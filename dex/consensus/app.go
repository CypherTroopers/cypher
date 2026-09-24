// Package consensus is a devnet-only application of the existing FHS protocol.
// Application methods run on one serialized event loop. The default execution
// is a money-free counter; optional deterministic execution runs only here.
package consensus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

var ErrUnavailable = hotstuff.ErrProposalDataUnavailable

const MaxRecords = 128

type Config struct {
	Domain    protocol.Domain
	Members   []*common.Cnode
	Index     int
	Secret    *bls.SecretKey
	DataDir   string
	CLXHeight uint64
	CLXHash   protocol.Hash
	MaxHeight uint64 // finite fixture limit, including finality child
	// StorageGenerations separates a finite absolute operating budget from the
	// unchanged 128-record hot window. It selects the new local WAL schema.
	StorageGenerations bool
	ArchiveBudgetBytes uint64
	Execution          Execution // nil retains the original money-free counter fixture
	Actions            func(height uint64) ([]byte, error)
	// ActionsWithParent selects from authenticated ingress using the exact
	// certified parent that will be executed. It receives an owned state copy.
	// Configure either this callback or Actions, never both.
	ActionsWithParent    func(parentState []byte, context ExecutionContext) ([]byte, error)
	BeforeVote           func(*hotstuff.PersistedVote) error
	RestoreVote          func(*hotstuff.PersistedVote) error
	OnFinalizedExecution func(height uint64, action, state []byte) error
	ObserveVote          func(ref []byte, vote *hotstuff.HotstuffMessage) error
}

type Record struct {
	Checkpoint protocol.Checkpoint
	Action     uint64
	Actions    []byte
	State      []byte
	Ref        []byte
	QC         *hotstuff.SignedState
	// History is derived from the actual certified parent, never ingress or a
	// local height cache. Schema 6 alone binds it into Checkpoint.DataRoot.
	History *protocol.HistoryFrontier `json:",omitempty"`
}

type Application struct {
	config         Config
	committee      *bftview.Committee
	keys           []*bls.PublicKey
	epoch          *checkpoint.Epoch
	manager        *hotstuff.HotstuffProtocolManager
	wal            *walStore
	disk           diskState
	selected       *hotstuff.SignedState
	builds         []*hotstuff.FHSProposalBuildRequest
	newView        bool
	send           func(string, *hotstuff.HotstuffMessage) error
	fatal          error
	closed         bool
	started        bool
	executionID    string
	genesisState   []byte
	genesisRoot    protocol.Hash
	notifiedHeight uint64
	archiveReplay  bool
	storageBlocked bool
	// Rebuilt exclusively by authenticated archive replay/rotation. Fixed-size
	// digests avoid retaining financial records or scanning old history per read.
	archiveDigests [MaxOperatingHeight + 1]protocol.Hash
}

func Open(c Config) (*Application, error) {
	if c.Actions != nil && c.ActionsWithParent != nil {
		return nil, errors.New("ambiguous DEX action sources")
	}
	if !c.Domain.Valid() || len(c.Members) != 7 || c.Index < 0 || c.Index >= 7 || c.Secret == nil || c.DataDir == "" || c.CLXHash == (protocol.Hash{}) || c.MaxHeight < 2 || c.MaxHeight > MaxOperatingHeight || !c.StorageGenerations && c.MaxHeight > MaxRecords {
		return nil, errors.New("invalid isolated counter fixture config")
	}
	if c.StorageGenerations {
		if c.ArchiveBudgetBytes == 0 {
			c.ArchiveBudgetBytes = DefaultArchiveBudgetBytes
		}
		if c.ArchiveBudgetBytes < minArchiveBudgetBytes || c.ArchiveBudgetBytes > maxArchiveBudgetBytes {
			return nil, errors.New("archive budget outside local bound")
		}
	} else if c.ArchiveBudgetBytes != 0 {
		return nil, errors.New("archive budget requires storage generations")
	}
	epoch, err := checkpoint.NewEpoch(c.Domain, 1, math.MaxUint64, c.Members)
	if err != nil {
		return nil, err
	}
	a := &Application{config: c, epoch: epoch, committee: &bftview.Committee{List: make([]*common.Cnode, 7)}}
	if err := a.initExecution(); err != nil {
		return nil, err
	}
	for i, m := range c.Members {
		n := *m
		a.committee.List[i] = &n
		key := new(bls.PublicKey)
		if err := key.DeserializeHexStr(n.Public); err != nil {
			return nil, err
		}
		a.keys = append(a.keys, key)
	}
	if !bytes.Equal(c.Secret.GetPublicKey().Serialize(), a.keys[c.Index].Serialize()) {
		return nil, errors.New("vote key not registered")
	}
	secret := new(bls.SecretKey)
	if err := secret.Deserialize(c.Secret.Serialize()); err != nil {
		return nil, err
	}
	a.config.Secret = secret
	a.config.Members = nil
	a.wal, err = openWAL(c.DataDir)
	if err != nil {
		return nil, err
	}
	a.wal.generational = c.StorageGenerations
	ok := false
	defer func() {
		if !ok {
			a.wal.close()
		}
	}()
	a.disk, err = a.wal.load(c.Domain, a.keys[c.Index].SerializeToHexStr())
	if err != nil {
		return nil, err
	}
	if err = a.bindExecutionWAL(); err != nil {
		return nil, err
	}
	if err = a.recover(); err != nil {
		return nil, err
	}
	if c.RestoreVote != nil {
		if err = c.RestoreVote(hotstuff.ClonePersistedVote(a.disk.Safety.LastVote)); err != nil {
			return nil, err
		}
	}
	if err = a.reconcileFinalizedExecution(); err != nil {
		return nil, err
	}
	a.selected = hotstuff.CloneSignedState(a.disk.Safety.HighestQC)
	a.manager = hotstuff.NewHotstuffProtocolManager(a, secret, a.keys[c.Index])
	if err = a.persist(); err != nil {
		return nil, err
	}
	ok = true
	return a, nil
}

func (a *Application) SetTransport(send func(string, *hotstuff.HotstuffMessage) error) { a.send = send }
func (a *Application) Close() error {
	if a.closed {
		return nil
	}
	a.closed = true
	return a.wal.close()
}
func (a *Application) check() error {
	if a.closed {
		return errors.New("DEX closed")
	}
	return a.fatal
}
func (a *Application) Start() error {
	if err := a.check(); err != nil {
		return err
	}
	a.started = true
	if a.disk.Outbox != nil {
		msg, err := a.manager.RebuildFHSQCBroadcast(a.disk.Outbox)
		if err != nil {
			return err
		}
		if errs := a.Broadcast(msg); len(errs) > 0 {
			return errors.Join(errs...)
		}
	}
	return a.manager.NewView()
}
func (a *Application) Handle(msg *hotstuff.HotstuffMessage) error {
	if err := a.check(); err != nil {
		return err
	}
	if err := validateDEXWire(msg); err != nil {
		return err
	}
	return a.manager.HandleMessage(msg)
}
func (a *Application) Timeout() error {
	if err := a.check(); err != nil {
		return err
	}
	return a.manager.LocalTimeout()
}

// Advance executes one queued build outside the protocol callback. It also emits
// new-view messages after QC publication has returned to the event loop.
func (a *Application) Advance() (bool, error) {
	if err := a.check(); err != nil {
		return false, err
	}
	if a.newView {
		a.newView = false
		return true, a.manager.NewView()
	}
	if len(a.builds) == 0 {
		return false, nil
	}
	r := a.builds[0]
	a.builds = a.builds[1:]
	record, err := a.build(r)
	result := &hotstuff.FHSProposalBuildResult{Key: r.Key, Err: err, ApplicationData: record}
	if err == nil {
		result.TProposal = record.Ref
		result.Extra, _ = encodeExtra(record)
	}
	return true, a.manager.HandleFHSProposalBuildResult(result)
}

func (a *Application) FinalizedHeight() uint64 {
	return a.disk.BaseHeight + uint64(len(a.disk.Finalized))
}
func (a *Application) CertifiedHeight() uint64 {
	if a.disk.Safety.HighestQC == nil {
		return 0
	}
	r, _ := types.DecodeHotstuffProposalRef(a.disk.Safety.HighestQC.State)
	if r == nil {
		return 0
	}
	return r.Number
}
func (a *Application) FinalizedCheckpoint(height uint64) (protocol.Checkpoint, []byte, error) {
	r, f, err := a.finalizedRecordAt(height)
	if err != nil {
		return protocol.Checkpoint{}, nil, err
	}
	return r.Checkpoint, append([]byte(nil), f.Proof...), nil
}
func (a *Application) Self() string             { return a.committee.List[a.config.Index].Address }
func (a *Application) ChainID() uint64          { return a.config.Domain.ChainID }
func (*Application) UseContextSignatures() bool { return true }
func (*Application) UseFHS2Chain() bool         { return true }
func (*Application) RequireMessageAuth() bool   { return true }
func (*Application) GetExtra() []byte           { return nil }
func (a *Application) GetPublicKey(hash common.Hash) ([]*bls.PublicKey, error) {
	if hash != common.Hash(a.config.Domain.EpochKey()) {
		return nil, errors.New("foreign DEX domain/epoch")
	}
	return a.keys, nil
}
func (a *Application) ResolveHotstuffCommittee(number uint64, hash common.Hash, _ bool) (*bftview.Committee, error) {
	if number != a.config.Domain.Epoch || hash != common.Hash(a.config.Domain.EpochKey()) {
		return nil, errors.New("unregistered DEX epoch")
	}
	return a.committee, nil
}
func (a *Application) FHSLeaderPublicKey(hash common.Hash, id string) (*bls.PublicKey, error) {
	keys, err := a.GetPublicKey(hash)
	if err != nil {
		return nil, err
	}
	for i, m := range a.committee.List {
		if m.Address == id {
			return keys[i], nil
		}
	}
	return nil, errors.New("unknown DEX leader")
}
func (a *Application) Write(to string, msg *hotstuff.HotstuffMessage) error {
	if err := a.check(); err != nil {
		return err
	}
	if a.send == nil {
		return errors.New("DEX transport unavailable")
	}
	// Ownership crosses the event loop boundary only as a fresh wire copy.
	b, err := rlp.EncodeToBytes(msg)
	if err != nil {
		return err
	}
	var copyMsg hotstuff.HotstuffMessage
	if err = rlp.DecodeBytes(b, &copyMsg); err != nil {
		return err
	}
	if copyMsg.Code == hotstuff.MsgVotePrepare && a.config.ObserveVote != nil {
		v := a.disk.Safety.LastVote
		if v == nil || v.ViewNumber != copyMsg.Number || v.ViewID != copyMsg.ViewId || v.LeaderID != to {
			return errors.New("own vote observer lacks durable proposal")
		}
		// The observer receives an independent copy and cannot mutate transport.
		var observed hotstuff.HotstuffMessage
		if err = rlp.DecodeBytes(b, &observed); err != nil {
			return err
		}
		if err = a.config.ObserveVote(append([]byte(nil), v.ProposalRef...), &observed); err != nil {
			return err
		}
	}
	return a.send(to, &copyMsg)
}
func (a *Application) Broadcast(msg *hotstuff.HotstuffMessage) []error {
	var errs []error
	for _, m := range a.committee.List {
		if err := a.Write(m.Address, msg); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}
func (a *Application) CurrentN() uint64 {
	n := uint64(0)
	if q := a.disk.Safety.HighestQC; q != nil {
		n = q.Number
	}
	if t := a.disk.Safety.HighestTC; t != nil && t.Statement.TimedOutView > n {
		n = t.Statement.TimedOutView
	}
	return n + 1
}
func (a *Application) CurrentState() ([]byte, string, uint64) {
	h, parent, _, _ := a.parent(a.selected)
	n := a.CurrentN()
	leader := (n - 1) % 7
	v := &bftview.View{TxNumber: h, TxHash: parent, KeyNumber: a.config.Domain.Epoch, KeyHash: common.Hash(a.config.Domain.EpochKey()), CommitteeHash: common.Hash(a.config.Domain.Committee), LeaderIndex: uint(leader), ViewNumber: n - 1}
	return v.EncodeConsensusToBytes(), a.committee.List[leader].Address, n
}
func (a *Application) ValidateView(state []byte) ([]byte, string, uint64, error) {
	current, leader, n := a.CurrentState()
	if !bytes.Equal(state, current) {
		return current, leader, n, hotstuff.ErrOldState
	}
	return current, leader, n, nil
}
func (a *Application) ValidateFHSContext(c *hotstuff.FHSViewContext) error {
	_, leader, n := a.CurrentState()
	if c == nil || c.ChainID != a.ChainID() || c.KeyNumber != a.config.Domain.Epoch || c.KeyHash != common.Hash(a.config.Domain.EpochKey()) || c.CommitteeHash != common.Hash(a.config.Domain.Committee) || c.TargetView != n || c.LeaderID != leader {
		return hotstuff.ErrInvalidLeaderView
	}
	return nil
}
func (*Application) OnNewView([]byte, [][]byte) error { return nil }
func (*Application) Propose(uint64, common.Hash, string) (error, []byte, []byte, []byte) {
	return errors.New("use bounded FHS build callback"), nil, nil, nil
}
func (*Application) OnViewDone(*hotstuff.SignedState) error {
	return errors.New("single QC cannot finalize DEX")
}
func (a *Application) HighestCertified() *hotstuff.SignedState {
	return hotstuff.CloneSignedState(a.disk.Safety.HighestQC)
}
func (a *Application) SelectedFHSProposalParent() *hotstuff.SignedState {
	return hotstuff.CloneSignedState(a.selected)
}
func (a *Application) SelectFHSProposalParent(q *hotstuff.SignedState) error {
	if q != nil {
		if err := a.verifyQC(q); err != nil {
			return err
		}
		if _, _, _, err := a.parent(q); err != nil {
			return err
		}
	}
	if err := a.extendsFinalized(q); err != nil {
		return err
	}
	a.selected = hotstuff.CloneSignedState(q)
	return nil
}
func (a *Application) HasValidatedFHSCertificate(q *hotstuff.SignedState) bool {
	if q == nil {
		return false
	}
	r, err := types.DecodeHotstuffProposalRef(q.State)
	if err != nil {
		return false
	}
	record := a.disk.Records[r.ProposalID().Hex()]
	return record != nil && record.QC != nil && hotstuff.SignedStateSemanticEqual(q, record.QC)
}
func (a *Application) ScheduleFHSProposalBuild(r *hotstuff.FHSProposalBuildRequest) error {
	if err := a.check(); err != nil {
		return err
	}
	if a.storageBlocked {
		return ErrStorageCapacity
	}
	if r == nil {
		return errors.New("nil DEX build request")
	}
	if len(a.builds) >= 1 {
		return errors.New("DEX build queue saturated")
	}
	h, _, _, err := a.parent(r.ParentQC)
	if err != nil {
		return err
	}
	if h >= a.config.MaxHeight {
		return errors.New("counter fixture height limit")
	}
	copyRequest := *r
	copyRequest.CurrentState = append([]byte(nil), r.CurrentState...)
	copyRequest.ParentQC = hotstuff.CloneSignedState(r.ParentQC)
	a.builds = append(a.builds, &copyRequest)
	return nil
}
func (a *Application) ApplyFHSProposalBuild(result *hotstuff.FHSProposalBuildResult) error {
	r, ok := result.ApplicationData.(*Record)
	if !ok || r == nil {
		return errors.New("missing DEX build result")
	}
	return a.storeRecord(r)
}
func (*Application) FinishFHSProposalBuild(*hotstuff.FHSProposalBuildResult) {}

func counterRoot(n uint64) protocol.Hash {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], n)
	return protocol.Digest("common-dex/counter/v1", b[:])
}
func (a *Application) genesisHash() common.Hash {
	k := a.config.Domain.EpochKey()
	if a.config.Execution != nil {
		return executionGenesisHash(k, a.executionID, a.genesisRoot)
	}
	return common.Hash(protocol.Digest("common-dex/counter-genesis/v1", k[:]))
}
func (a *Application) parent(q *hotstuff.SignedState) (uint64, common.Hash, uint64, error) {
	if q == nil {
		return 0, a.genesisHash(), 0, nil
	}
	ref, err := types.DecodeHotstuffProposalRef(q.State)
	if err != nil {
		return 0, common.Hash{}, 0, err
	}
	r := a.lookupRecord(ref)
	if r == nil || !bytes.Equal(r.Ref, q.State) {
		return 0, common.Hash{}, 0, ErrUnavailable
	}
	// The counter fixture's only action increments by exactly one. This relation
	// is checked against roots on every execution, including restart.
	return r.Checkpoint.LastBlock, ref.BlockHash, r.Checkpoint.LastBlock, nil
}
func (a *Application) makeCheckpoint(height uint64, parent common.Hash, counter uint64) protocol.Checkpoint {
	d := a.config.Domain
	var action [8]byte
	binary.BigEndian.PutUint64(action[:], 1)
	previous := protocol.Hash(parent)
	if height == 1 {
		previous = protocol.Hash{}
	}
	return protocol.Checkpoint{Version: d.Version, ProofMode: protocol.CommitteeSignatures, ChainID: d.ChainID, Genesis: d.Genesis, DEXID: d.DEXID, Epoch: d.Epoch, Committee: d.Committee, Sequence: height, Previous: previous, PreRoot: counterRoot(counter), PostRoot: counterRoot(counter + 1), FirstBlock: height, LastBlock: height, CLXHeight: a.config.CLXHeight, CLXHash: a.config.CLXHash, DataRoot: protocol.Digest("common-dex/counter-action/v1", action[:]), DataSchema: 1}
}
func encodeExtra(r *Record) ([]byte, error) {
	b, err := r.Checkpoint.Encode()
	if err != nil {
		return nil, err
	}
	if r.Checkpoint.DataSchema == ExecutionSchema || r.Checkpoint.DataSchema == NativeExecutionSchema || r.Checkpoint.DataSchema == RollingExecutionSchema || (r.Checkpoint.DataSchema == ContinuousExecutionSchema || r.Checkpoint.DataSchema == AncestryExecutionSchema) {
		envelope, err := EncodeExecutionAction(r.Actions)
		if err != nil {
			return nil, err
		}
		return append(b, envelope...), nil
	}
	var action [8]byte
	binary.BigEndian.PutUint64(action[:], r.Action)
	return append(b, action[:]...), nil
}
func (a *Application) build(req *hotstuff.FHSProposalBuildRequest) (*Record, error) {
	var action []byte
	if a.config.Execution != nil {
		if a.config.Actions == nil && a.config.ActionsWithParent == nil {
			return nil, errors.New("DEX action source unavailable")
		}
		h, _, _, err := a.parent(req.ParentQC)
		if err != nil {
			return nil, err
		}
		if a.config.ActionsWithParent != nil {
			state, pre, parentErr := a.executionParent(req.ParentQC)
			if parentErr != nil {
				return nil, parentErr
			}
			action, err = a.config.ActionsWithParent(state, a.executionContext(h+1, pre))
		} else {
			action, err = a.config.Actions(h + 1)
		}
		if err != nil {
			return nil, err
		}
	}
	return a.buildAction(req, action)
}
func (a *Application) buildAction(req *hotstuff.FHSProposalBuildRequest, action []byte) (*Record, error) {
	h, parent, counter, err := a.parent(req.ParentQC)
	if err != nil {
		return nil, err
	}
	if h >= a.config.MaxHeight || counter == math.MaxUint64 {
		return nil, errors.New("counter fixture limit")
	}
	c := a.makeCheckpoint(h+1, parent, counter)
	r := &Record{Action: 1}
	bodySize := uint64(8)
	if a.config.Execution != nil {
		var state []byte
		c, state, err = a.executeCheckpoint(h+1, parent, req.ParentQC, action)
		if err != nil {
			return nil, err
		}
		r.Action = 0
		r.Actions = append([]byte(nil), action...)
		r.State = state
		bodySize = uint64(6 + len(action))
	}
	if c.DataSchema == AncestryExecutionSchema {
		r.History, err = a.deriveHistory(req.ParentQC)
		if err != nil {
			return nil, err
		}
		root, historyErr := r.History.Root()
		if historyErr != nil {
			return nil, historyErr
		}
		c.DataRoot, err = protocol.HistoryDataRoot(c.DataRoot, root, r.History.Count)
		if err != nil {
			return nil, err
		}
	}
	hash, err := c.Hash()
	if err != nil {
		return nil, err
	}
	r.Checkpoint = c
	extra, _ := encodeExtra(r)
	ref := &types.HotstuffProposalRef{Version: types.HotstuffProposalRefVersion, ChainID: a.ChainID(), Number: h + 1, ViewNumber: req.Key.ViewNumber, ViewID: req.Key.ViewID, LeaderID: req.Key.LeaderID, BlockHash: common.Hash(hash), ParentHash: parent, StateRoot: common.Hash(c.PostRoot), BodyHash: common.Hash(c.DataRoot), BodySize: bodySize, ExtraHash: types.HotstuffProposalExtraHash(extra), ParentQCID: req.Key.ParentQCID, KeyHash: common.Hash(a.config.Domain.EpochKey()), Time: h + 1}
	r.Ref = ref.EncodeToBytes()
	return r, nil
}
func (a *Application) OnPropose(state, extra []byte, view uint64, parentQC *hotstuff.SignedState) error {
	if err := a.extendsFinalized(parentQC); err != nil {
		return err
	}
	if len(extra) < protocol.CheckpointSize || len(extra) > protocol.CheckpointSize+MaxActionBytes+6 {
		return errors.New("invalid counter record size")
	}
	c, err := protocol.DecodeCheckpoint(extra[:protocol.CheckpointSize])
	if err != nil {
		return err
	}
	r := &Record{Checkpoint: c, Ref: append([]byte(nil), state...)}
	if c.DataSchema == ExecutionSchema || c.DataSchema == NativeExecutionSchema || c.DataSchema == RollingExecutionSchema || c.DataSchema == ContinuousExecutionSchema || c.DataSchema == AncestryExecutionSchema {
		r.Actions, err = DecodeExecutionAction(extra[protocol.CheckpointSize:])
		if err != nil {
			return err
		}
	} else {
		if len(extra) != protocol.CheckpointSize+8 {
			return errors.New("invalid counter record size")
		}
		r.Action = binary.BigEndian.Uint64(extra[protocol.CheckpointSize:])
	}
	ref, err := types.DecodeHotstuffProposalRef(state)
	if err != nil {
		return err
	}
	if ref.ViewNumber != view {
		return errors.New("counter proposal view mismatch")
	}
	if err = a.validateRecordState(r, parentQC, false); err != nil {
		return err
	}
	return a.storeRecord(r)
}
func (a *Application) validateRecord(r *Record, parentQC *hotstuff.SignedState) error {
	return a.validateRecordState(r, parentQC, true)
}
func (a *Application) validateRecordState(r *Record, parentQC *hotstuff.SignedState, compareState bool) error {
	if r == nil || len(r.Ref) == 0 || len(r.Ref) > checkpoint.MaxRefBytes || len(r.State) > MaxStateBytes || len(r.Actions) > MaxActionBytes {
		return errors.New("invalid counter action")
	}
	if a.config.Execution == nil {
		if r.Action != 1 || r.Checkpoint.DataSchema != 1 || len(r.Actions) != 0 || len(r.State) != 0 {
			return errors.New("counter execution/schema mismatch")
		}
	} else if r.Action != 0 || r.Checkpoint.DataSchema != a.config.Execution.Schema() {
		return errors.New("generic execution/schema mismatch")
	}
	ref, err := types.DecodeHotstuffProposalRef(r.Ref)
	if err != nil {
		return err
	}
	if ref.ViewNumber == math.MaxUint64 {
		return errors.New("DEX view overflow")
	}
	h, _, counter, err := a.parent(parentQC)
	if err != nil {
		return err
	}
	if h >= a.config.MaxHeight || counter == math.MaxUint64 {
		return errors.New("counter limit")
	}
	var pid common.Hash
	if parentQC != nil {
		id, err := hotstuff.SignedStateID(parentQC)
		if err != nil {
			return err
		}
		pid = id.Hash()
	}
	req := &hotstuff.FHSProposalBuildRequest{Key: hotstuff.FHSProposalBuildKey{ViewNumber: ref.ViewNumber, ViewID: ref.ViewID, LeaderID: ref.LeaderID, ParentQCID: pid}, ParentQC: parentQC}
	want, err := a.buildAction(req, r.Actions)
	if err != nil {
		return err
	}
	if r.Checkpoint != want.Checkpoint {
		return errors.New("DEX execution/parent/root mismatch")
	}
	if compareState && !sameHistory(r.History, want.History) {
		return errors.New("DEX replay history mismatch")
	}
	if compareState && !bytes.Equal(r.State, want.State) {
		return errors.New("DEX replay state mismatch")
	}
	if !bytes.Equal(want.Ref, r.Ref) || ref.LeaderID != a.committee.List[(ref.ViewNumber-1)%7].Address {
		return errors.New("noncanonical counter metadata")
	}
	if parentQC != nil && ref.ViewNumber <= parentQC.Number {
		return errors.New("nonincreasing counter view")
	}
	if !compareState {
		r.State = append([]byte(nil), want.State...)
		r.History = cloneHistory(want.History)
	}
	return nil
}
func (a *Application) storeRecord(r *Record) error {
	if err := a.check(); err != nil {
		return err
	}
	_, err := r.Checkpoint.Hash()
	if err != nil {
		return err
	}
	ref, err := types.DecodeHotstuffProposalRef(r.Ref)
	if err != nil {
		return err
	}
	id := ref.ProposalID().Hex()
	if old := a.disk.Records[id]; old != nil {
		if !bytes.Equal(old.Ref, r.Ref) {
			return errors.New("conflicting counter proposal identity")
		}
		return nil
	}
	if a.storageBlocked {
		return ErrStorageCapacity
	}
	if len(a.disk.Records) >= MaxRecords {
		return errors.New("DEX retention bound reached")
	}
	copyRecord := *r
	copyRecord.Ref = append([]byte(nil), r.Ref...)
	copyRecord.Actions = append([]byte(nil), r.Actions...)
	copyRecord.State = append([]byte(nil), r.State...)
	copyRecord.QC = hotstuff.CloneSignedState(r.QC)
	copyRecord.History = cloneHistory(r.History)
	a.disk.Records[id] = &copyRecord
	return a.persist()
}

func (a *Application) verifyQC(q *hotstuff.SignedState) error {
	if q == nil || q.Number == math.MaxUint64 || len(q.State) > checkpoint.MaxRefBytes || len(q.Sign) == 0 || len(q.Sign) > 128 || len(q.LeaderID) > 128 {
		return errors.New("invalid QC bounds")
	}
	r, err := types.DecodeHotstuffProposalRef(q.State)
	if err != nil {
		return err
	}
	if r.ChainID != a.ChainID() || r.KeyHash != common.Hash(a.config.Domain.EpochKey()) || q.Number != r.ViewNumber || q.ViewID != r.ViewID || q.LeaderID != r.LeaderID || r.LeaderID != a.committee.List[(r.ViewNumber-1)%7].Address {
		return errors.New("foreign QC context")
	}
	if !hotstuff.VerifyFHSSignatureWithContext(q.Sign, q.Mask, q.State, a.keys, 5, a.ChainID(), hotstuff.MsgVotePrepare, q.ViewID, q.LeaderID) {
		return errors.New("invalid DEX QC signature")
	}
	return nil
}
func (a *Application) AdoptFHSHighQC(q *hotstuff.SignedState) error { return a.OnCertified(q) }
func (a *Application) OnCertified(q *hotstuff.SignedState) error {
	return a.certify(q, false)
}
func (a *Application) certify(q *hotstuff.SignedState, leaderOutbox bool) error {
	if err := a.check(); err != nil {
		return err
	}
	if err := a.verifyQC(q); err != nil {
		return err
	}
	ref, _ := types.DecodeHotstuffProposalRef(q.State)
	r := a.disk.Records[ref.ProposalID().Hex()]
	if r == nil || !bytes.Equal(r.Ref, q.State) {
		return ErrUnavailable
	}
	if ref.Number >= a.FinalizedHeight() {
		if err := a.extendsFinalized(q); err != nil {
			return err
		}
	}
	if old := a.disk.Safety.HighestQC; old != nil && old.Number == q.Number && !hotstuff.SignedStateSemanticEqual(old, q) {
		return errors.New("conflicting highest QC")
	}
	previousQC := r.QC
	r.QC = hotstuff.CloneSignedState(q)
	if err := a.commitAncestors(r); err != nil {
		r.QC = previousQC
		return err
	}
	if a.disk.Safety.HighestQC == nil || q.Number > a.disk.Safety.HighestQC.Number {
		a.disk.Safety.HighestQC = hotstuff.CloneSignedState(q)
		a.selected = hotstuff.CloneSignedState(q)
		a.newView = true
	}
	if t := a.disk.Safety.LastTimeoutVote; t != nil && t.TimedOutView <= q.Number {
		a.disk.Safety.LastTimeoutVote = nil
	}
	if t := a.disk.Safety.HighestTC; t != nil && t.Statement.TimedOutView <= q.Number {
		a.disk.Safety.HighestTC = nil
		a.disk.Safety.LastTimeoutView = 0
	}
	if leaderOutbox {
		a.disk.Outbox = hotstuff.CloneSignedState(q)
	}
	if err := a.persist(); err != nil {
		return err
	}
	return a.reconcileFinalizedExecution()
}
func (a *Application) commitAncestors(tip *Record) error {
	ref, _ := types.DecodeHotstuffProposalRef(tip.Ref)
	pq, err := a.parentQC(ref)
	if err != nil {
		return err
	}
	parent := a.recordForQC(pq)
	if parent == nil || parent.QC == nil || tip.QC.Number <= parent.QC.Number || tip.QC.Number-parent.QC.Number != 1 {
		return nil
	}
	if tip.Checkpoint.DataSchema == AncestryExecutionSchema {
		return a.commitHistoryAncestors(parent, tip)
	}
	path := []*hotstuff.SignedState{tip.QC}
	pending := []finalizedRecord{}
	for cursor := parent; cursor != nil && cursor.Checkpoint.LastBlock > a.FinalizedHeight(); {
		proof, err := checkpoint.EncodeProof(checkpoint.Proof{Target: cursor.QC, Descendants: path})
		if err != nil {
			return err
		}
		if _, err = a.epoch.Verify(cursor.Checkpoint, proof); err != nil {
			return err
		}
		hash, _ := cursor.Checkpoint.Hash()
		cursorRef, _ := types.DecodeHotstuffProposalRef(cursor.Ref)
		pending = append(pending, finalizedRecord{Key: cursorRef.ProposalID().Hex(), Hash: common.Hash(hash).Hex(), Proof: proof})
		cref, _ := types.DecodeHotstuffProposalRef(cursor.Ref)
		path = append([]*hotstuff.SignedState{cursor.QC}, path...)
		pqc, err := a.parentQC(cref)
		if err != nil {
			return err
		}
		cursor = a.recordForQC(pqc)
	}
	height := a.FinalizedHeight()
	var previous protocol.Hash
	if height > 0 {
		_, f, err := a.finalizedRecordAt(height)
		if err != nil {
			return err
		}
		previous = protocol.Hash(common.HexToHash(f.Hash))
	}
	for i := len(pending) - 1; i >= 0; i-- {
		r := a.disk.Records[pending[i].Key]
		if r.Checkpoint.LastBlock != height+1 {
			return errors.New("noncontiguous finalized counter state")
		}
		if r.Checkpoint.Previous != previous {
			return errors.New("conflicting finalized counter branch")
		}
		height++
		previous = protocol.Hash(common.HexToHash(pending[i].Hash))
	}
	for i := len(pending) - 1; i >= 0; i-- {
		a.disk.Finalized = append(a.disk.Finalized, pending[i])
	}
	return nil
}

// Each finalized record is already durable before an external subsystem may
// seal its corresponding state. The callback must be idempotent: a crash can
// occur after it succeeds but before any later application progress. Recover
// reconciles all final records, never speculative or merely certified records.
func (a *Application) reconcileFinalizedExecution() error {
	for a.notifiedHeight < a.FinalizedHeight() {
		height := a.notifiedHeight + 1
		r, _, err := a.finalizedRecordAt(height)
		if err != nil {
			a.fatal = err
			return a.fatal
		}
		if (r.Checkpoint.DataSchema == ExecutionSchema || r.Checkpoint.DataSchema == NativeExecutionSchema || r.Checkpoint.DataSchema == RollingExecutionSchema || (r.Checkpoint.DataSchema == ContinuousExecutionSchema || r.Checkpoint.DataSchema == AncestryExecutionSchema)) && a.config.OnFinalizedExecution != nil {
			if err := a.config.OnFinalizedExecution(height, append([]byte(nil), r.Actions...), append([]byte(nil), r.State...)); err != nil {
				a.fatal = fmt.Errorf("DEX finalized execution reconciliation: %w", err)
				return a.fatal
			}
		}
		a.notifiedHeight = height
	}
	return nil
}
func (a *Application) OnFHSLeaderCertifiedBeforeBroadcast(q *hotstuff.SignedState) error {
	if q == nil || q.LeaderID != a.Self() {
		return errors.New("foreign leader outbox")
	}
	return a.certify(q, true)
}
func (*Application) OnFHSLeaderCertifiedAfterBroadcast(*hotstuff.SignedState, bool) error { return nil }

func (a *Application) PersistFHSVote(v *hotstuff.PersistedVote) error {
	if err := a.check(); err != nil {
		return err
	}
	if v == nil {
		return errors.New("nil DEX vote")
	}
	r, err := types.DecodeHotstuffProposalRef(v.ProposalRef)
	if err != nil {
		return err
	}
	if r.ChainID != a.ChainID() || r.KeyHash != common.Hash(a.config.Domain.EpochKey()) || r.ViewNumber != v.ViewNumber || r.ViewID != v.ViewID || r.LeaderID != v.LeaderID || r.ProposalID() != v.ProposalID || hotstuff.StateDigest(v.ProposalRef) != v.ProposalRefHash {
		return errors.New("DEX vote metadata mismatch")
	}
	if record := a.disk.Records[r.ProposalID().Hex()]; record == nil || !bytes.Equal(record.Ref, v.ProposalRef) {
		return ErrUnavailable
	}
	if v.ViewNumber == math.MaxUint64 || v.ViewNumber < a.CurrentN() || a.disk.Safety.LastTimeoutVote != nil && v.ViewNumber <= a.disk.Safety.LastTimeoutVote.TimedOutView {
		return errors.New("DEX vote below safety watermark")
	}
	if old := a.disk.Safety.LastVote; old != nil {
		if v.ViewNumber < old.ViewNumber {
			return errors.New("stale DEX vote")
		}
		if v.ViewNumber == old.ViewNumber {
			if !bytes.Equal(v.ProposalRef, old.ProposalRef) {
				return errors.New("conflicting durable DEX vote")
			}
			return nil
		}
	}
	if a.config.BeforeVote != nil {
		if err := a.config.BeforeVote(hotstuff.ClonePersistedVote(v)); err != nil {
			return err
		}
	}
	a.disk.Safety.LastVote = hotstuff.ClonePersistedVote(v)
	return a.persist()
}
func (a *Application) HighestFHSTimeoutCertificate() *hotstuff.TimeoutCertificate {
	return hotstuff.CloneTimeoutCertificate(a.disk.Safety.HighestTC)
}
func (a *Application) PendingFHSTimeoutVote() (*hotstuff.TimeoutStatement, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	if a.disk.Safety.LastTimeoutVote == nil {
		return nil, nil
	}
	v := *a.disk.Safety.LastTimeoutVote
	return &v, nil
}
func (a *Application) validTimeout(s *hotstuff.TimeoutStatement) error {
	if s == nil || s.TimedOutView == math.MaxUint64 || s.ChainID != a.ChainID() || s.KeyNumber != a.config.Domain.Epoch || s.KeyHash != common.Hash(a.config.Domain.EpochKey()) || s.CommitteeHash != common.Hash(a.config.Domain.Committee) {
		return errors.New("foreign DEX timeout")
	}
	_, err := hotstuff.TimeoutStatementDigest(s)
	return err
}
func (a *Application) PersistFHSTimeoutVote(s *hotstuff.TimeoutStatement) error {
	if err := a.check(); err != nil {
		return err
	}
	if err := a.validTimeout(s); err != nil {
		return err
	}
	if s.TimedOutView < a.CurrentN() {
		return errors.New("stale DEX timeout")
	}
	if old := a.disk.Safety.LastTimeoutVote; old != nil {
		if s.TimedOutView < old.TimedOutView {
			return errors.New("stale DEX timeout")
		}
		if s.TimedOutView == old.TimedOutView {
			if *old != *s {
				return errors.New("conflicting DEX timeout")
			}
			return nil
		}
	}
	v := *s
	a.disk.Safety.LastTimeoutVote = &v
	return a.persist()
}
func (a *Application) AcceptFHSTimeoutCertificate(t *hotstuff.TimeoutCertificate) error {
	if err := a.check(); err != nil {
		return err
	}
	if t == nil {
		return errors.New("nil DEX TC")
	}
	if err := timeoutShape(t); err != nil {
		return err
	}
	if err := a.validTimeout(&t.Statement); err != nil {
		return err
	}
	if err := hotstuff.VerifyTimeoutCertificate(t, a.keys, 5); err != nil {
		return err
	}
	if t.Statement.TimedOutView < a.CurrentN() {
		return nil
	}
	a.disk.Safety.HighestTC = hotstuff.CloneTimeoutCertificate(t)
	a.disk.Safety.LastTimeoutView = t.Statement.TimedOutView
	if s := a.disk.Safety.LastTimeoutVote; s != nil && s.TimedOutView <= t.Statement.TimedOutView {
		a.disk.Safety.LastTimeoutVote = nil
	}
	return a.persist()
}

var _ hotstuff.HotStuffApplication = (*Application)(nil)
var _ hotstuff.FHSApplication = (*Application)(nil)
var _ hotstuff.CommitteeResolverApplication = (*Application)(nil)
var _ hotstuff.FHSProposalBuildApplication = (*Application)(nil)
