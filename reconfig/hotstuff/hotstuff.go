package hotstuff

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rlp"
	"github.com/zeebo/blake3"
)

const hotstuffSignatureDomain = "hotstuff-vote-v1"
const maxPendingNewViewIDs = 8
const maxPendingNewViewsPerID = 128
const hotstuffRecoveryInterval = 5 * time.Second
const finalizedRecoveryRetention = 2 * time.Minute
const maxFinalizedRecoveryViews = 16

var (
	ErrNewViewFail            = fmt.Errorf("hotstuff new view fail")
	ErrUnhandledMsg           = fmt.Errorf("hotstuff unhandled message")
	ErrViewTimeout            = fmt.Errorf("hotstuff view timeout")
	ErrQCVerification         = fmt.Errorf("hotstuff QC not valid")
	ErrInvalidReplica         = fmt.Errorf("hotstuff replica not valid")
	ErrInvalidVoteInfoMessage = fmt.Errorf("hotstuff voteInfo message not valid")
	ErrInsufficientQC         = fmt.Errorf("hotstuff QC insufficient")
	ErrInvalidHighQC          = fmt.Errorf("hotstuff highQC invalid")
	ErrInvalidPrepareQC       = fmt.Errorf("hotstuff prepareQC invalid")
	ErrInvalidPreCommitQC     = fmt.Errorf("hotstuff preCommitQC invalid")
	ErrInvalidCommitQC        = fmt.Errorf("hotstuff commitQC invalid")
	ErrInvalidProposal        = fmt.Errorf("hotstuff proposal invalid")
	ErrInvalidPublicKey       = fmt.Errorf("invalid public key for bls deserialize")
	ErrViewPhaseNotMatch      = fmt.Errorf("hotstuff view phase not match")
	ErrViewOldPhase           = fmt.Errorf("hotstuff old phase ")

	ErrMissingView       = fmt.Errorf("hotstuff view missing")
	ErrInvalidLeaderView = fmt.Errorf("hotstuff invalid leader view")
	ErrExistingView      = fmt.Errorf("hotstuff view existing")
	ErrViewIdNotMatch    = fmt.Errorf("hotstuff view id not match")

	ErrOldState    = fmt.Errorf("hotstuff view state too old")
	ErrFutureState = fmt.Errorf("hotstuff view state of future")
)

func hotstuffContextDigest(chainID uint64, msgCode uint32, viewID common.Hash, leaderID string, data []byte) []byte {
	stateHash := hotstuffDigest(data)
	payload, err := rlp.EncodeToBytes([]interface{}{
		[]byte(hotstuffSignatureDomain),
		chainID,
		msgCode,
		viewID,
		leaderID,
		stateHash,
	})
	if err != nil {
		fallback := hotstuffDigestHash([]byte(hotstuffSignatureDomain), stateHash, viewID[:], []byte(leaderID))
		out := make([]byte, len(fallback))
		copy(out, fallback[:])
		return out
	}
	return hotstuffDigest(payload)
}

func hotstuffDigest(data []byte) []byte {
	sum := blake3.Sum256(data)
	out := make([]byte, len(sum))
	copy(out, sum[:])
	return out
}

func hotstuffDigestHash(parts ...[]byte) common.Hash {
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	buf := make([]byte, 0, total)
	for _, p := range parts {
		if len(p) == 0 {
			continue
		}
		buf = append(buf, p...)
	}
	sum := blake3.Sum256(buf)
	var out common.Hash
	copy(out[:], sum[:])
	return out
}

func buildReplicaIndex(groupPublicKey []*bls.PublicKey) map[string]int {
	index := make(map[string]int, len(groupPublicKey))
	for i, p := range groupPublicKey {
		index[hex.EncodeToString(p.Serialize())] = i
	}
	return index
}

const (
	MsgNewView = iota
	MsgPrepare
	MsgVotePrepare
	MsgPreCommit
	MsgVotePreCommit
	MsgCommit
	MsgVoteCommit
	MsgDecide
	MsgQCBroadcast

	// pseudo messages
	MsgStartNewView // for handling new view from app
	MsgTryPropose
	MsgTimer
)

func ReadableMsgType(m uint32) string {
	switch {
	case m == MsgNewView:
		return "MsgNewView"
	case m == MsgPrepare:
		return "MsgPrepare"
	case m == MsgVotePrepare:
		return "MsgVotePrepare"
	case m == MsgPreCommit:
		return "MsgPreCommit"
	case m == MsgVotePreCommit:
		return "MsgVotePreCommit"
	case m == MsgCommit:
		return "MsgCommit"
	case m == MsgVoteCommit:
		return "MsgVoteCommit"
	case m == MsgDecide:
		return "MsgDecide"
	case m == MsgQCBroadcast:
		return "MsgQCBroadcast"
	case m == MsgStartNewView:
		return "MsgStartNewView"
	case m == MsgTryPropose:
		return "MsgTryPropose"

	default:
		return "unknown"
	}
}

const (
	PhasePrepare    = iota
	PhaseTryPropose // pseudo phase, used to describe the phase between onNewView and Propose successfully
	PhasePreCommit
	PhaseCommit
	PhaseDecide
	PhaseFinal
)

func readablePhase(code uint32) string {
	switch {
	case code == PhasePrepare:
		return "PhasePrepare"
	case code == PhaseTryPropose:
		return "PhasePropose"
	case code == PhasePreCommit:
		return "PhasePreCommit"
	case code == PhaseCommit:
		return "PhaseCommit"
	case code == PhaseDecide:
		return "PhaseDecide"
	case code == PhaseFinal:
		return "PhaseFinal"
	default:
		return "unknown"
	}
}

// Proposed K or T state with signature and mask, only for OnViewDone() interface
type SignedState struct {
	State    []byte
	Sign     []byte
	Mask     []byte
	ViewID   common.Hash
	LeaderID string
	Number   uint64
}

func CloneSignedState(in *SignedState) *SignedState {
	if in == nil {
		return nil
	}
	out := *in
	out.State = append([]byte(nil), in.State...)
	out.Sign = append([]byte(nil), in.Sign...)
	out.Mask = append([]byte(nil), in.Mask...)
	return &out
}

func EncodeSignedState(in *SignedState) ([]byte, error) {
	if in == nil {
		return nil, nil
	}
	return rlp.EncodeToBytes(in)
}

func DecodeSignedState(data []byte) (*SignedState, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var out SignedState
	if err := rlp.DecodeBytes(data, &out); err != nil {
		return nil, err
	}
	if len(out.State) == 0 || len(out.Sign) == 0 || len(out.Mask) == 0 || out.ViewID == (common.Hash{}) || out.LeaderID == "" || out.Number == 0 {
		return nil, ErrInvalidHighQC
	}
	return &out, nil
}

type HotStuffApplication interface {
	Self() string
	Write(string, *HotstuffMessage) error
	Broadcast(*HotstuffMessage) []error

	GetPublicKey(keyHash common.Hash) ([]*bls.PublicKey, error)

	OnNewView(currentState []byte, extra [][]byte) error
	OnPropose(state []byte, extra []byte, viewNumber uint64, parentQC *SignedState) error
	OnCertified(tSign *SignedState) error
	OnViewDone(tSign *SignedState) error
	HighestCertified() *SignedState

	ValidateView(currentState []byte) (expectedState []byte, expectedLeader string, expectedNumber uint64, err error)
	Propose(viewNumber uint64, viewID common.Hash, leaderID string) (e error, kState []byte, tState []byte, extra []byte)
	CurrentState() ([]byte, string, uint64)
	CurrentN() uint64
	GetExtra() []byte // only for new-view procedure
	ChainID() uint64
	UseContextSignatures() bool
	UseFHS2Chain() bool
}

type VoteInfo struct {
	Index      int // index in the group public keys
	PubKey     *bls.PublicKey
	KSign      bls.Sign
	TSign      bls.Sign
	ValidKSign bool
	ValidTSign bool
}

type QC struct {
	kSign *bls.Sign
	tSign *bls.Sign
	mask  []byte
}

type HotstuffMessage struct {
	Code   uint32
	Number uint64
	ViewId common.Hash
	Id     string
	PubKey []byte

	// The usage of these "DataX" if different per message
	DataA []byte
	DataB []byte
	DataC []byte

	DataD []byte
	DataE []byte
	DataF []byte
	DataG []byte // FHS parent certified state and QC

	ReceivedAt time.Time
}

type View struct {
	hash             common.Hash // hash on "currentState + leaderId", hence should be unique and equal for the same view and leader
	createdAt        time.Time
	number           uint64
	leaderId         string
	committeeKeyHash common.Hash
	phaseAsLeader    uint32
	phaseAsReplica   uint32
	currentState     []byte
	proposedKState   []byte
	proposedTState   []byte

	proposedKDigest   []byte
	proposedTDigest   []byte
	replicaIndex      map[string]int
	highVoteInfo      []*VoteInfo
	prepareVoteInfo   []*VoteInfo
	preCommitVoteInfo []*VoteInfo
	commitVoteInfo    []*VoteInfo
	qc                map[string]*QC
	leaderMsg         map[uint64]*HotstuffMessage // record messages from leader to replica: MsgPrepare, MsgPreCommit, MsgCommit, MsgDecide, MsgQCBroadcast
	replicaMsg        map[uint64]*HotstuffMessage // record messages from replica to leader: MsgVotePrepare

	groupPublicKey []*bls.PublicKey
	threshold      int
	cmLen          int

	extra [][]byte

	futureNewViewMsg []*HotstuffMessage

	waitingMoreVoteInfo   bool
	waitingMoreVoteInfoAt time.Time
	lastLeaderRecoveryAt  time.Time
	lastReplicaRecoveryAt time.Time
	certified             bool
}

func (v *View) hasKState() bool {
	return v.proposedKState != nil && len(v.proposedKState) > 0
}

func (v *View) hasTState() bool {
	return v.proposedTState != nil && len(v.proposedTState) > 0
}

type HotstuffProtocolManager struct {
	secretKey      *bls.SecretKey
	publicKey      *bls.PublicKey
	views          map[common.Hash]*View
	leaderView     *View
	app            HotStuffApplication
	unhandledMsg   map[common.Hash]*HotstuffMessage // messages which is not handled(which phase is ahead of local's)
	pendingNewView map[common.Hash]map[string]*HotstuffMessage
	finalized      map[common.Hash]*finalizedRecovery
}

type finalizedRecovery struct {
	number      uint64
	prepare     *HotstuffMessage
	qcBroadcast *HotstuffMessage
	decide      *HotstuffMessage
	finalizedAt time.Time
	lastSentAt  time.Time
}

func NewHotstuffProtocolManager(a HotStuffApplication, secretKey *bls.SecretKey, publicKey *bls.PublicKey) *HotstuffProtocolManager {
	manager := &HotstuffProtocolManager{
		secretKey:      secretKey,
		publicKey:      publicKey,
		app:            a,
		views:          make(map[common.Hash]*View),
		unhandledMsg:   make(map[common.Hash]*HotstuffMessage),
		pendingNewView: make(map[common.Hash]map[string]*HotstuffMessage),
		finalized:      make(map[common.Hash]*finalizedRecovery),
	}
	return manager
}

func CalcThreshold(size int) int {
	return (size + 1) * 2 / 3
}

func (hsm *HotstuffProtocolManager) UpdateKeyPair(sec *bls.SecretKey) {
	hsm.secretKey = sec
	hsm.publicKey = sec.GetPublicKey()
}

func (v *View) lookupReplica(pubKey *bls.PublicKey) int {
	if v.replicaIndex != nil {
		if index, ok := v.replicaIndex[hex.EncodeToString(pubKey.Serialize())]; ok {
			return index
		}
	}
	for i, p := range v.groupPublicKey {
		if p.IsEqual(pubKey) {
			return i
		}
	}
	return -1
}

func (v *View) msgToVoteInfo(m *HotstuffMessage) (error, *VoteInfo) {
	var qrum VoteInfo
	qrum.PubKey = bls.GetPublicKey(m.PubKey)
	if qrum.PubKey == nil {
		return ErrInvalidPublicKey, nil
	}
	/*
		if err := qrum.PubKey.Deserialize(m.PubKey); err != nil {
			return err, nil
		}
	*/
	if m.DataB != nil && len(m.DataB) > 0 {
		if err := qrum.KSign.Deserialize(m.DataB); err != nil {
			qrum.ValidKSign = false
		} else {
			qrum.ValidKSign = true
		}
	}

	if m.DataC != nil && len(m.DataC) > 0 {
		if err := qrum.TSign.Deserialize(m.DataC); err != nil {
			qrum.ValidTSign = false
		} else {
			qrum.ValidTSign = true
		}
	}

	if !qrum.ValidKSign && !qrum.ValidTSign {
		return ErrInvalidVoteInfoMessage, nil
	}

	index := v.lookupReplica(qrum.PubKey)
	if -1 == index {
		return ErrInvalidReplica, nil
	}
	qrum.Index = index

	return nil, &qrum
}

func (hsm *HotstuffProtocolManager) newMsg(code uint32, number uint64, viewId common.Hash, a []byte, b []byte, c []byte) *HotstuffMessage {
	msg := &HotstuffMessage{
		Code:   code,
		Number: number,
		ViewId: viewId,
		Id:     hsm.app.Self(),
	}

	if hsm.publicKey != nil {
		bPubKey := hsm.publicKey.Serialize()
		msg.PubKey = make([]byte, len(bPubKey))
		copy(msg.PubKey, bPubKey)
	}

	if a != nil && len(a) > 0 {
		msg.DataA = make([]byte, len(a))
		copy(msg.DataA, a)
	}

	if b != nil && len(b) > 0 {
		msg.DataB = make([]byte, len(b))
		copy(msg.DataB, b)
	}

	if c != nil && len(c) > 0 {
		msg.DataC = make([]byte, len(c))
		copy(msg.DataC, c)
	}

	return msg
}

func (hsm *HotstuffProtocolManager) newView() (*View, []byte, error) {
	currentState, leaderId, number := hsm.app.CurrentState()
	if leaderId == "" {
		return nil, nil, ErrNewViewFail
	}

	v := &View{
		phaseAsReplica:    PhasePrepare,
		number:            number,
		leaderId:          leaderId,
		highVoteInfo:      make([]*VoteInfo, 0),
		prepareVoteInfo:   make([]*VoteInfo, 0),
		preCommitVoteInfo: make([]*VoteInfo, 0),
		commitVoteInfo:    make([]*VoteInfo, 0),
		qc:                make(map[string]*QC),
		leaderMsg:         make(map[uint64]*HotstuffMessage),
		replicaMsg:        make(map[uint64]*HotstuffMessage),
		extra:             make([][]byte, 0),
		futureNewViewMsg:  make([]*HotstuffMessage, 0),
		createdAt:         time.Now(),
	}

	v.currentState = make([]byte, len(currentState))
	copy(v.currentState, currentState)

	v.hash = hotstuffDigestHash([]byte(v.leaderId), v.currentState)

	if err := hsm.initViewCommittee(v); err != nil {
		return nil, nil, err
	}

	return v, hsm.app.GetExtra(), nil
}

func (hsm *HotstuffProtocolManager) createView(asLeader bool, phase uint32, leaderId string, currentState []byte, number uint64) (*View, error) {
	v := &View{
		number:            number,
		leaderId:          leaderId,
		highVoteInfo:      make([]*VoteInfo, 0),
		prepareVoteInfo:   make([]*VoteInfo, 0),
		preCommitVoteInfo: make([]*VoteInfo, 0),
		commitVoteInfo:    make([]*VoteInfo, 0),
		qc:                make(map[string]*QC),
		leaderMsg:         make(map[uint64]*HotstuffMessage),
		replicaMsg:        make(map[uint64]*HotstuffMessage),
		extra:             make([][]byte, 0),
		futureNewViewMsg:  make([]*HotstuffMessage, 0),
		createdAt:         time.Now(),
	}

	if asLeader {
		v.phaseAsLeader = phase
	} else {
		v.phaseAsReplica = phase
	}

	v.currentState = make([]byte, len(currentState))
	copy(v.currentState, currentState)

	v.hash = hotstuffDigestHash([]byte(v.leaderId), v.currentState)

	if err := hsm.initViewCommittee(v); err != nil {
		return nil, err
	}

	return v, nil
}

// initViewCommittee snapshots the signer order identified by the view state.
// The snapshot must never be replaced with the latest committee: QC mask bits
// are positional and keep the meaning they had when the view was created.
func snapshotPublicKeys(groupPublicKey []*bls.PublicKey) ([]*bls.PublicKey, error) {
	if len(groupPublicKey) == 0 {
		return nil, fmt.Errorf("%w: empty committee", ErrInvalidPublicKey)
	}
	seen := make(map[string]struct{}, len(groupPublicKey))
	snapshot := make([]*bls.PublicKey, 0, len(groupPublicKey))
	for _, p := range groupPublicKey {
		if p == nil {
			return nil, fmt.Errorf("%w: nil committee key", ErrInvalidPublicKey)
		}
		encoded := hex.EncodeToString(p.Serialize())
		if _, exists := seen[encoded]; exists {
			return nil, fmt.Errorf("%w: duplicate committee key", ErrInvalidPublicKey)
		}
		seen[encoded] = struct{}{}
		snapshot = append(snapshot, p)
	}
	return snapshot, nil
}

func (hsm *HotstuffProtocolManager) initViewCommittee(v *View) error {
	if v == nil {
		return ErrMissingView
	}
	if len(v.groupPublicKey) > 0 {
		return nil
	}

	viewState := bftview.DecodeToView(v.currentState)
	if viewState == nil || viewState.KeyHash == (common.Hash{}) {
		return fmt.Errorf("%w: view has no committee key hash", ErrInvalidPublicKey)
	}
	groupPublicKey, err := hsm.app.GetPublicKey(viewState.KeyHash)
	if err != nil {
		return fmt.Errorf("%w: load committee %s: %v", ErrInvalidPublicKey, viewState.KeyHash, err)
	}
	v.groupPublicKey, err = snapshotPublicKeys(groupPublicKey)
	if err != nil {
		return fmt.Errorf("committee %s: %w", viewState.KeyHash, err)
	}
	v.committeeKeyHash = viewState.KeyHash
	v.cmLen = len(v.groupPublicKey)
	v.threshold = CalcThreshold(v.cmLen)
	v.replicaIndex = buildReplicaIndex(v.groupPublicKey)
	return nil
}

func (hsm *HotstuffProtocolManager) DumpView(v *View, asLeader bool) {
	/*
		log.Debug("Dump View ================", "viewID", v.hash)

		if asLeader {
			log.Debug("View phase", "asLeader", readablePhase(v.phaseAsLeader))
		} else {
			log.Debug("View phase", "asReplica", readablePhase(v.phaseAsLeader))
		}

		for i, p := range v.groupPublicKey {
			if i == 0 || i == 1 || i == (len(v.groupPublicKey)-1) {
				log.Debug("Public Key", "index", i, "key", hex.EncodeToString(p.Serialize()))
			}
		}

		log.Debug("Dump View End ================>>")
	*/
}

func (hsm *HotstuffProtocolManager) lockView(v *View) {
	for k, view := range hsm.views {
		if bytes.Equal(v.hash[:], view.hash[:]) {
			continue
		}

		// reserve views with future new view message
		if len(view.futureNewViewMsg) > 0 {
			continue
		}

		log.Debug("lockView remove view", "viewId", k)
		delete(hsm.views, k)
	}
}

func (hsm *HotstuffProtocolManager) viewDone(v *View, kSign []byte, tSign []byte, mask []byte, e error) error {
	if e != nil {
		log.Warn("view finished with error", "error", e, "ViewId", v.hash)
		return hsm.app.OnViewDone(nil)
	} else {
		elapsed := time.Now().Sub(v.createdAt).Nanoseconds() / 1000000

		log.Debug("view finished successfully", "ViewId", v.hash, "timeElapsed", elapsed)

		var tSignedState *SignedState
		if v.hasTState() {
			tSignedState = &SignedState{
				State:    v.proposedTState,
				Sign:     tSign,
				Mask:     mask,
				ViewID:   v.hash,
				LeaderID: v.leaderId,
				Number:   v.number,
			}
		}

		if err := hsm.app.OnViewDone(tSignedState); err != nil {
			log.Warn("view commit failed; keeping view retryable",
				"ViewId", v.hash,
				"number", v.number,
				"err", err)
			return err
		}
	}
	return nil
}

func (hsm *HotstuffProtocolManager) clearTimeoutView(curN uint64) error {
	now := time.Now()
	for _, v := range hsm.views {
		if v.number < curN {
			log.Debug("Remove timeout view", "viewId", v.hash, "phase", readablePhase(v.phaseAsReplica), "pas time", now.Sub(v.createdAt).Seconds())
			if v.phaseAsReplica < PhaseFinal {
				if err := hsm.viewDone(v, nil, nil, nil, ErrViewTimeout); err != nil {
					log.Warn("timeout view cleanup callback failed", "viewId", v.hash, "err", err)
				}
			}
			delete(hsm.views, v.hash)
		}
	}

	for k, m := range hsm.unhandledMsg {
		if m.Number < curN {
			log.Debug("Remove unhandled hotstuff message", "viewId", m.ViewId, "code", m.Code, "from", m.Id, "past time", now.Sub(m.ReceivedAt).Seconds())
			delete(hsm.unhandledMsg, k)
		}
	}

	return nil
}

func (hsm *HotstuffProtocolManager) discardStaleReplicaNewViews(number uint64, keep common.Hash) {
	for id, view := range hsm.views {
		if id == keep || view == nil || view.number != number {
			continue
		}
		if view.phaseAsReplica != PhasePrepare {
			continue
		}
		if _, ok := view.replicaMsg[MsgNewView]; !ok {
			continue
		}
		if len(view.leaderMsg) > 0 ||
			len(view.highVoteInfo) > 0 ||
			len(view.prepareVoteInfo) > 0 ||
			len(view.preCommitVoteInfo) > 0 ||
			len(view.commitVoteInfo) > 0 {
			continue
		}

		log.Debug("discard stale replica new-view",
			"number", number,
			"viewID", id,
			"keep", keep)
		delete(hsm.views, id)
	}
}

// for replica
func (hsm *HotstuffProtocolManager) NewView() error {
	v, extra, err := hsm.newView()
	if err != nil {
		return err
	}

	hsm.discardStaleReplicaNewViews(v.number, v.hash)
	if existing, exist := hsm.views[v.hash]; exist {
		v = existing
	} else {
		hsm.views[v.hash] = v
	}
	if v.replicaMsg == nil {
		v.replicaMsg = make(map[uint64]*HotstuffMessage)
	}

	sig := hsm.SignHashByMessage(MsgNewView, v.hash, v.leaderId, v.currentState)
	msg := hsm.newMsg(MsgNewView, v.number, v.hash, v.currentState, sig, extra)
	v.replicaMsg[MsgNewView] = msg
	v.lastReplicaRecoveryAt = time.Now()

	log.Debug("New View", "leader", v.leaderId, "ViewID", common.HexString(v.hash[:]))
	err = hsm.app.Write(v.leaderId, msg)
	if err != nil {
		hsm.clearTimeoutView(v.number) //clear old view
	}

	return err
}

func (hsm *HotstuffProtocolManager) aggregateQC(v *View, phase string, qrum []*VoteInfo) error {
	var kSign bls.Sign
	var tSign bls.Sign

	hasKSign := false
	hasTSign := false

	size := len(v.groupPublicKey) >> 3
	if len(v.groupPublicKey)&0x7 > 0 {
		size += 1
	}

	mask := make([]byte, size)
	for i, q := range qrum {
		if i == 0 {
			if q.ValidKSign {
				if err := kSign.Deserialize(q.KSign.Serialize()); err != nil {
					return err
				}
				hasKSign = true
			}

			if q.ValidTSign {
				if err := tSign.Deserialize(q.TSign.Serialize()); err != nil {
					return err
				}
				hasTSign = true
			}
		} else {
			if q.ValidKSign {
				kSign.Add(&q.KSign)
				hasKSign = true
			}

			if q.ValidTSign {
				tSign.Add(&q.TSign)
				hasTSign = true
			}
		}
		mask[q.Index>>3] |= 1 << uint64(q.Index%8)
	}

	v.qc[phase] = &QC{
		mask: mask,
	}

	if hasKSign {
		v.qc[phase].kSign = &kSign
	}

	if hasTSign {
		v.qc[phase].tSign = &tSign
	}

	return nil
}

func (hsm *HotstuffProtocolManager) lookupVoteInfo(pubKey *bls.PublicKey, voteInfo []*VoteInfo) bool {
	for _, q := range voteInfo {
		if q.PubKey.IsEqual(pubKey) {
			return true
		}
	}

	return false
}

func (hsm *HotstuffProtocolManager) rebroadcastPrepare(v *View, reason string) bool {
	if v == nil {
		return false
	}
	if v.phaseAsLeader != PhasePreCommit {
		return false
	}
	prepareMsg, ok := v.leaderMsg[MsgPrepare]
	if !ok || prepareMsg == nil {
		return false
	}

	log.Warn("HOTSTUFF PREPARE REBROADCAST",
		"reason", reason,
		"number", v.number,
		"viewID", v.hash,
		"votes", len(v.prepareVoteInfo),
		"threshold", v.threshold)

	hsm.app.Broadcast(prepareMsg)
	return true
}

func (hsm *HotstuffProtocolManager) cacheFinalizedRecovery(v *View, decide *HotstuffMessage) {
	if v == nil {
		return
	}
	entry := &finalizedRecovery{
		number:      v.number,
		decide:      decide,
		finalizedAt: time.Now(),
		lastSentAt:  time.Now(),
	}
	entry.prepare = v.leaderMsg[MsgPrepare]
	entry.qcBroadcast = v.leaderMsg[MsgQCBroadcast]
	if entry.qcBroadcast == nil && decide == nil {
		return
	}
	hsm.finalized[v.hash] = entry

	if len(hsm.finalized) <= maxFinalizedRecoveryViews {
		return
	}
	var oldestID common.Hash
	var oldest time.Time
	for id, candidate := range hsm.finalized {
		if candidate == nil || oldest.IsZero() || candidate.finalizedAt.Before(oldest) {
			oldestID = id
			if candidate != nil {
				oldest = candidate.finalizedAt
			}
		}
	}
	delete(hsm.finalized, oldestID)
}

// for leader
func (hsm *HotstuffProtocolManager) validateNewViewMsg(msg *HotstuffMessage) (*View, *VoteInfo, error) {
	if msg == nil {
		return nil, nil, ErrNewViewFail
	}
	decodedView := bftview.DecodeToView(msg.DataA)
	if decodedView == nil {
		return nil, nil, ErrNewViewFail
	}

	expectedState, _, expectedNumber, stateErr := hsm.app.ValidateView(msg.DataA)
	if stateErr != nil && stateErr != ErrFutureState {
		return nil, nil, stateErr
	}
	if stateErr == ErrFutureState {
		return nil, nil, stateErr
	}

	committee := bftview.LoadMember(decodedView.KeyNumber, decodedView.KeyHash, true)
	if committee == nil || committee.RlpHash() != decodedView.CommitteeHash || decodedView.LeaderIndex >= uint(len(committee.List)) {
		return nil, nil, ErrInvalidLeaderView
	}
	leader := committee.List[decodedView.LeaderIndex]
	if leader == nil {
		return nil, nil, ErrInvalidLeaderView
	}
	expectedLeader := bftview.GetNodeID(leader.Address, leader.Public)
	expectedMsgNumber := decodedView.TxNumber + 1
	if hsm.app.UseFHS2Chain() {
		expectedMsgNumber = decodedView.ViewNumber + 1
	}
	if expectedLeader == "" || expectedLeader != hsm.app.Self() || msg.Number != expectedMsgNumber {
		return nil, nil, ErrInvalidLeaderView
	}
	if stateErr == nil && (msg.Number != expectedNumber || !bytes.Equal(msg.DataA, expectedState)) {
		return nil, nil, ErrViewIdNotMatch
	}

	expectedViewID := hotstuffDigestHash([]byte(expectedLeader), msg.DataA)
	if msg.ViewId != expectedViewID {
		return nil, nil, ErrViewIdNotMatch
	}

	v, err := hsm.createView(true, PhasePrepare, expectedLeader, msg.DataA, msg.Number)
	if err != nil {
		return nil, nil, err
	}
	err, vote := v.msgToVoteInfo(msg)
	if err != nil {
		return nil, nil, err
	}
	if committee == nil || vote.Index < 0 || vote.Index >= len(committee.List) {
		return nil, nil, ErrInvalidReplica
	}
	replica := committee.List[vote.Index]
	if replica == nil || bftview.GetNodeID(replica.Address, replica.Public) != msg.Id {
		return nil, nil, ErrInvalidReplica
	}
	if !hsm.verifyVoteSignature(vote.KSign, vote.PubKey, MsgNewView, v.hash, v.leaderId, msg.DataA) {
		return nil, nil, ErrQCVerification
	}
	return v, vote, stateErr
}

func (hsm *HotstuffProtocolManager) queueFutureNewView(msg *HotstuffMessage, vote *VoteInfo) {
	if msg == nil {
		return
	}
	pending := hsm.pendingNewView[msg.ViewId]
	if pending == nil {
		if len(hsm.pendingNewView) >= maxPendingNewViewIDs {
			log.Warn("drop verified future new-view; pending view limit reached", "viewID", msg.ViewId, "limit", maxPendingNewViewIDs)
			return
		}
		pending = make(map[string]*HotstuffMessage)
		hsm.pendingNewView[msg.ViewId] = pending
	}
	if len(pending) >= maxPendingNewViewsPerID {
		log.Warn("drop future new-view; per-view limit reached",
			"viewID", msg.ViewId,
			"limit", maxPendingNewViewsPerID)
		return
	}

	key := msg.Id + ":" + hex.EncodeToString(msg.PubKey)
	if vote != nil && vote.PubKey != nil {
		key = hex.EncodeToString(vote.PubKey.Serialize())
	}
	if _, exists := pending[key]; !exists {
		pending[key] = msg
	}
}

func (hsm *HotstuffProtocolManager) acceptValidatedNewView(msg *HotstuffMessage, validatedView *View, vote *VoteInfo) error {
	if msg == nil || validatedView == nil || vote == nil {
		return ErrNewViewFail
	}

	v, exist := hsm.views[msg.ViewId]
	if !exist {
		v = validatedView
		log.Debug("create validated new view", "leader", v.leaderId, "viewID", v.hash)
		hsm.views[v.hash] = v
	}

	if hsm.lookupVoteInfo(vote.PubKey, v.highVoteInfo) {
		log.Warn("receive dup new-view message", "from", msg.Id, "viewId", msg.ViewId)
		return nil
	}

	if v.phaseAsLeader != PhasePrepare {
		if prepareMsg, ok := v.leaderMsg[MsgPrepare]; ok {
			log.Debug("send cached prepare to late replica", "replicaId", msg.Id)
			hsm.app.Write(msg.Id, prepareMsg)
		}
		return nil
	}

	v.highVoteInfo = append(v.highVoteInfo, vote)
	if len(msg.DataC) > 0 {
		extra := make([]byte, len(msg.DataC))
		copy(extra, msg.DataC)
		v.extra = append(v.extra, extra)
	}

	hsm.leaderView = v

	threshold := v.threshold
	if threshold > len(v.groupPublicKey) {
		threshold = len(v.groupPublicKey)
	}

	if len(v.highVoteInfo) < threshold {
		log.Info("handleNewViewMsg need more voteInfo", "threshold", v.threshold, "current", len(v.highVoteInfo))
		return ErrInsufficientQC
	}

	return hsm.activateLeaderView(v)
}

func (hsm *HotstuffProtocolManager) activateLeaderView(v *View) error {
	if v == nil {
		return ErrInvalidLeaderView
	}
	elapsed := time.Now().Sub(v.createdAt).Nanoseconds() / 1000000

	log.Debug("on new view", "ViewId", v.hash, "timeElapsed", elapsed)

	// notify app the new view only when leader has (n - f) votes
	if err := hsm.app.OnNewView(v.currentState, v.extra); err != nil {
		log.Debug("New view message failed verification", "error", err)
		v.lastLeaderRecoveryAt = time.Now()
		return err
	}

	v.phaseAsLeader = PhaseTryPropose
	v.lastLeaderRecoveryAt = time.Now()
	hsm.lockView(v)

	return hsm.TryPropose()
}

func (hsm *HotstuffProtocolManager) handleNewViewMsg(msg *HotstuffMessage) error {
	if msg == nil {
		return ErrNewViewFail
	}
	log.Info("handleNewViewMsg got new view message", "from", msg.Id, "viewId", msg.ViewId)

	validatedView, vote, err := hsm.validateNewViewMsg(msg)
	if err == ErrFutureState {
		hsm.queueFutureNewView(msg, vote)
		log.Info("queue verified future new-view", "from", msg.Id, "viewID", msg.ViewId)
		return err
	}
	if err != nil {
		log.Warn("reject new-view before storage", "from", msg.Id, "viewID", msg.ViewId, "err", err)
		return err
	}

	result := hsm.acceptValidatedNewView(msg, validatedView, vote)
	pending := hsm.pendingNewView[msg.ViewId]
	delete(hsm.pendingNewView, msg.ViewId)
	for _, futureMsg := range pending {
		futureView, futureVote, futureErr := hsm.validateNewViewMsg(futureMsg)
		if futureErr != nil {
			log.Warn("discard queued new-view after replay validation", "from", futureMsg.Id, "viewID", futureMsg.ViewId, "err", futureErr)
			continue
		}
		if err := hsm.acceptValidatedNewView(futureMsg, futureView, futureVote); err != nil && err != ErrInsufficientQC {
			result = err
		} else if err == nil {
			result = nil
		}
	}
	return result
}

func (hsm *HotstuffProtocolManager) TryPropose() error {
	v := hsm.leaderView
	if v == nil {
		return ErrInvalidLeaderView
	}

	if v.phaseAsLeader != PhaseTryPropose {
		log.Warn("TryPropose is not called on PhaseTryPropose stage, ignore", "viewId", v.hash, "phase", v.phaseAsLeader)
		return ErrViewPhaseNotMatch
	}

	err, kProposal, tProposal, extra := hsm.app.Propose(v.number, v.hash, v.leaderId)
	if err != nil {
		log.Warn("hotstuff application failed to propose", "viewId", v.hash, "number", v.number, "leader", v.leaderId, "err", err)
		return err
	}
	if len(kProposal) == 0 && len(tProposal) == 0 {
		log.Warn("hotstuff application returned empty proposal", "viewId", v.hash, "number", v.number, "leader", v.leaderId)
		return ErrInvalidProposal
	}

	if err := hsm.aggregateQC(v, "high", v.highVoteInfo); err != nil {
		log.Debug("aggregate high voteInfo failed")
		return err
	}

	msg := hsm.newMsg(MsgPrepare, v.number, v.hash, kProposal, tProposal, v.qc["high"].kSign.Serialize())
	msg.DataD = make([]byte, len(v.qc["high"].mask))
	copy(msg.DataD, v.qc["high"].mask)

	msg.DataE = make([]byte, len(v.currentState))
	copy(msg.DataE, v.currentState)

	if extra != nil && len(extra) > 0 {
		msg.DataF = make([]byte, len(extra))
		copy(msg.DataF, extra)
	}
	if hsm.app.UseFHS2Chain() {
		parentQC := hsm.app.HighestCertified()
		if parentQC != nil {
			if parentQC.Number >= v.number {
				return ErrInvalidHighQC
			}
			encodedQC, err := EncodeSignedState(parentQC)
			if err != nil {
				return err
			}
			msg.DataG = encodedQC
		}
	}

	if encoded, encErr := rlp.EncodeToBytes(msg); encErr == nil {
		log.Info("HOTSTUFF PREPARE SIZE",
			"number", v.number,
			"viewID", v.hash,
			"leader", v.leaderId,
			"kProposal", len(kProposal),
			"tProposal", len(tProposal),
			"extra", len(extra),
			"dataA", len(msg.DataA),
			"dataB", len(msg.DataB),
			"dataC", len(msg.DataC),
			"dataD", len(msg.DataD),
			"dataE", len(msg.DataE),
			"dataF", len(msg.DataF),
			"dataG", len(msg.DataG),
			"msgRLP", len(encoded))
	} else {
		log.Warn("HOTSTUFF PREPARE SIZE encode failed", "number", v.number, "viewID", v.hash, "err", encErr)
	}

	log.Debug("view broadcast Prepare msg", "viewID", v.hash, "number", v.number)

	if kProposal != nil && len(kProposal) > 0 {
		v.proposedKState = make([]byte, len(kProposal))
		copy(v.proposedKState, kProposal)
		v.proposedKDigest = hotstuffDigest(v.proposedKState)
	}

	if tProposal != nil && len(tProposal) > 0 {
		v.proposedTState = make([]byte, len(tProposal))
		copy(v.proposedTState, tProposal)
		v.proposedTDigest = hotstuffDigest(v.proposedTState)
	}

	v.leaderMsg[MsgPrepare] = msg
	v.phaseAsLeader = PhasePreCommit
	v.waitingMoreVoteInfo = true
	v.waitingMoreVoteInfoAt = time.Now()
	v.lastLeaderRecoveryAt = v.waitingMoreVoteInfoAt
	hsm.leaderView = nil

	// Broadcast after the leader state is fully prepared. This allows fast
	// VotePrepare responses to be handled safely.
	hsm.app.Broadcast(msg)

	hsm.DumpView(v, true)
	return nil
}

func VerifySignature(bSign []byte, bMask []byte, data []byte, groupPublicKey []*bls.PublicKey, threshold int) bool {
	return verifySignatureDigest(bSign, bMask, hotstuffDigest(data), groupPublicKey, threshold)
}

func VerifySignatureWithContext(bSign []byte, bMask []byte, data []byte, groupPublicKey []*bls.PublicKey, threshold int, chainID uint64, msgCode uint32, viewID common.Hash, leaderID string) bool {
	return verifySignatureDigest(bSign, bMask, hotstuffContextDigest(chainID, msgCode, viewID, leaderID, data), groupPublicKey, threshold)
}

func (hsm *HotstuffProtocolManager) verifyFHSParentQC(parentQC *SignedState, childViewNumber uint64) error {
	if parentQC == nil {
		return fmt.Errorf("%w: nil FHS parent QC", ErrInvalidHighQC)
	}
	if parentQC.Number >= childViewNumber {
		return fmt.Errorf("%w: parent view %d is not older than child view %d", ErrInvalidHighQC, parentQC.Number, childViewNumber)
	}

	parentRef, err := types.DecodeHotstuffProposalRef(parentQC.State)
	if err != nil {
		return fmt.Errorf("%w: decode parent proposal ref: %v", ErrInvalidHighQC, err)
	}
	if parentRef.ChainID != hsm.app.ChainID() ||
		parentRef.ViewNumber != parentQC.Number ||
		parentRef.ViewID != parentQC.ViewID ||
		parentRef.LeaderID != parentQC.LeaderID {
		return fmt.Errorf("%w: parent proposal/QC context mismatch", ErrInvalidHighQC)
	}

	parentKeys, err := hsm.app.GetPublicKey(parentRef.KeyHash)
	if err != nil {
		return fmt.Errorf("%w: load parent committee %s: %v", ErrInvalidHighQC, parentRef.KeyHash, err)
	}
	parentKeys, err = snapshotPublicKeys(parentKeys)
	if err != nil {
		return fmt.Errorf("%w: parent committee %s: %v", ErrInvalidHighQC, parentRef.KeyHash, err)
	}
	parentThreshold := CalcThreshold(len(parentKeys))
	if !hsm.verifyAggregatedSignature(parentQC.Sign, parentQC.Mask, MsgVotePrepare, parentQC.ViewID, parentQC.LeaderID, parentQC.State, parentKeys, parentThreshold) {
		return fmt.Errorf("%w: parent QC signature invalid for committee %s", ErrInvalidHighQC, parentRef.KeyHash)
	}
	return nil
}

func verifySignatureDigest(bSign []byte, bMask []byte, digest []byte, groupPublicKey []*bls.PublicKey, threshold int) bool {
	var sign bls.Sign
	if err := sign.Deserialize(bSign); err != nil {
		return false
	}
	if threshold <= 0 {
		return false
	}

	isFirst := true
	var pub bls.PublicKey

	signer := 0

loop:
	for i := range bMask {
		ii := i << 3
		for bit := 0; bit < 8; bit++ {
			if ii+bit >= len(groupPublicKey) {
				break loop
			}

			if bMask[i]&(1<<uint(bit)) != 0 {
				if isFirst {
					pub.Deserialize(groupPublicKey[ii+bit].Serialize())
					isFirst = false
				} else {
					pub.Add(groupPublicKey[ii+bit])
				}

				signer += 1
			}
		}
	}

	if signer < threshold || !sign.VerifyHash(&pub, digest) {
		log.Debug("Dump failed signature ================")
		log.Debug("signer", "is", signer, "threshold", threshold)
		log.Debug("Signature", "is ", hex.EncodeToString(bSign))
		log.Debug("Mask     ", "is ", hex.EncodeToString(bMask))
		log.Debug("Digest   ", "is ", hex.EncodeToString(digest))

		for i, p := range groupPublicKey {
			log.Debug("Public Key", "index", i, "key", hex.EncodeToString(p.Serialize()))
		}

		log.Debug("Dump failed signature end =================>>")
		return false
	}

	return true
}

func MaskToException(bMask []byte, groupPublicKey []*bls.PublicKey, beNewVer bool) []*bls.PublicKey {
	exception := make([]*bls.PublicKey, 0)
loop:
	for i := range bMask {
		ii := i << 3
		for bit := 0; bit < 8; bit++ {
			if ii+bit >= len(groupPublicKey) {
				break loop
			}
			if beNewVer {
				if bMask[i]&(1<<uint(bit)) == 0 {
					exception = append(exception, groupPublicKey[ii+bit])
				}
			} else {
				if bMask[i]&(1<<uint(bit)) != 0 {
					exception = append(exception, groupPublicKey[ii+bit])
				}
			}
		}
	}

	return exception
}

func MaskToExceptionIndexs(bMask []byte, cmLen int) []int {
	exception := make([]int, 0)
loop:
	for i := range bMask {
		ii := i << 3
		for bit := 0; bit < 8; bit++ {
			if ii+bit >= cmLen {
				break loop
			}
			if bMask[i]&(1<<uint(bit)) == 0 {
				exception = append(exception, ii+bit)
			}
		}
	}

	return exception
}

// for replica
func (hsm *HotstuffProtocolManager) handlePrepareMsg(m *HotstuffMessage) error {
	start := time.Now()
	expectedState, expectedLeader, expectedNumber, err := hsm.app.ValidateView(m.DataE)
	if err != nil {
		return err
	}

	expectedView := bftview.DecodeToView(expectedState)
	proposalView := bftview.DecodeToView(m.DataE)

	sameCanonicalView := expectedView.EqualConsensus(proposalView)

	// Do not reject only because NoDone differs.
	// In fixed keyblock mode, NoDone can flip locally before/after Prepare propagation.
	if expectedLeader == "" || expectedLeader != m.Id || expectedNumber != m.Number || !sameCanonicalView {
		log.Warn("handlePrepareMsg rejected non-canonical leader proposal",
			"from", m.Id,
			"expectedLeader", expectedLeader,
			"number", m.Number,
			"expectedNumber", expectedNumber,
			"stateEqual", bytes.Equal(expectedState, m.DataE),
			"expectedView", expectedView,
			"proposalView", proposalView)
		return ErrInvalidLeaderView
	}

	if !bytes.Equal(expectedState, m.DataE) {
		log.Warn("handlePrepareMsg accepted proposal with NoDone-only view mismatch",
			"from", m.Id,
			"number", m.Number,
			"expectedView", expectedView,
			"proposalView", proposalView)
	}

	v, exist := hsm.views[m.ViewId]
	if !exist {
		createdView, createErr := hsm.createView(false, PhasePrepare, expectedLeader, m.DataE, m.Number)
		if createErr != nil {
			log.Warn("handlePrepareMsg failed to load view committee", "viewId", m.ViewId, "err", createErr)
			return createErr
		}
		v = createdView
		hsm.views[v.hash] = v
		log.Debug("handlePrepareMsg create view", "viewId", m.ViewId)
	}

	if v.hash != m.ViewId || v.leaderId != expectedLeader {
		log.Warn("handlePrepareMsg rejected mismatched view/leader",
			"viewId", m.ViewId,
			"expectedLeader", expectedLeader,
			"viewLeader", v.leaderId)
		return ErrInvalidLeaderView
	}

	if v.phaseAsReplica != PhasePrepare {
		if voteMsg, ok := v.replicaMsg[MsgVotePrepare]; ok {
			log.Warn("handlePrepareMsg resend cached VotePrepare",
				"viewId", m.ViewId,
				"number", m.Number,
				"phase", readablePhase(v.phaseAsReplica),
				"to", m.Id)

			if err := hsm.app.Write(m.Id, voteMsg); err != nil {
				log.Warn("handlePrepareMsg failed to resend cached VotePrepare",
					"viewId", m.ViewId,
					"number", m.Number,
					"to", m.Id,
					"err", err)
				return err
			}

			return nil
		}

		log.Trace("handlePrepareMsg discard old-phase message",
			"viewId", hex.EncodeToString(m.ViewId[:]),
			"phase", readablePhase(v.phaseAsReplica))
		return ErrViewPhaseNotMatch
	}

	var state, extra []byte
	if len(m.DataB) > 0 {
		state = m.DataB
	}

	if len(m.DataF) > 0 {
		extra = m.DataF
	}

	// verify highQC in the prepare msg
	if !hsm.verifyAggregatedSignature(m.DataC, m.DataD, MsgNewView, v.hash, v.leaderId, m.DataE, v.groupPublicKey, v.threshold) {
		log.Debug("handlePrepareMsg failed to verify highQC", "viewId", m.ViewId)
		return ErrInvalidHighQC
	}

	var parentQC *SignedState
	if hsm.app.UseFHS2Chain() {
		var err error
		parentQC, err = DecodeSignedState(m.DataG)
		if err != nil {
			log.Debug("handlePrepareMsg failed to decode FHS parent QC", "viewId", m.ViewId, "err", err)
			return ErrInvalidHighQC
		}
		if parentQC != nil {
			if err := hsm.verifyFHSParentQC(parentQC, v.number); err != nil {
				log.Debug("handlePrepareMsg failed to verify FHS parent QC", "viewId", m.ViewId, "parentView", parentQC.Number, "err", err)
				return ErrInvalidHighQC
			}
		}
	}

	verifyStart := time.Now()
	if err := hsm.app.OnPropose(state, extra, v.number, parentQC); err != nil {
		log.Debug("handlePrepareMsg failed to verify proposed data", "viewId", m.ViewId, "number", m.Number, "elapsed", time.Since(verifyStart), "err", err)
		return ErrInvalidProposal
	}
	log.Info("HOTSTUFF PREPARE VERIFIED", "number", m.Number, "viewID", m.ViewId, "from", m.Id, "verifyElapsed", time.Since(verifyStart), "totalElapsed", time.Since(start), "stateBytes", len(state), "extraBytes", len(extra))
	hsm.lockView(v)

	kSign := []byte(nil)
	tSign := []byte(nil)

	if m.DataA != nil && len(m.DataA) > 0 {
		v.proposedKState = make([]byte, len(m.DataA))
		copy(v.proposedKState, m.DataA)
		v.proposedKDigest = hotstuffDigest(v.proposedKState)

		kSign = hsm.SignHashByMessage(MsgVotePrepare, v.hash, v.leaderId, v.proposedKState)
	}

	if m.DataB != nil && len(m.DataB) > 0 {
		v.proposedTState = make([]byte, len(m.DataB))
		copy(v.proposedTState, m.DataB)
		v.proposedTDigest = hotstuffDigest(v.proposedTState)

		tSign = hsm.SignHashByMessage(MsgVotePrepare, v.hash, v.leaderId, v.proposedTState)
	}

	msg := hsm.newMsg(MsgVotePrepare, v.number, v.hash, nil, kSign, tSign)

	// Cache VotePrepare so the replica can resend it if the leader retransmits Prepare.
	v.replicaMsg[MsgVotePrepare] = msg
	v.lastReplicaRecoveryAt = time.Now()

	log.Debug("handlePrepareMsg send VotePrepare msg", "viewID", v.hash, "number", v.number, "to", m.Id)
	if err := hsm.app.Write(m.Id, msg); err != nil {
		log.Warn("handlePrepareMsg failed to send VotePrepare msg", "viewID", v.hash, "number", v.number, "to", m.Id, "err", err)
		return err
	}

	v.phaseAsReplica = PhaseDecide
	log.Info("HOTSTUFF VOTEPREPARE SENT", "number", v.number, "viewID", v.hash, "to", m.Id, "totalElapsed", time.Since(start))

	return nil
}

func (hsm *HotstuffProtocolManager) createSignatureMsg(v *View, code uint32, phase string) *HotstuffMessage {
	bKSign := []byte(nil)
	bTSign := []byte(nil)
	if v.qc[phase].kSign != nil {
		bKSign = v.qc[phase].kSign.Serialize()
	}
	if v.qc[phase].tSign != nil {
		bTSign = v.qc[phase].tSign.Serialize()
	}

	// DataA: kSign, DataB: tSign, DataC: mask
	return hsm.newMsg(code, v.number, v.hash, bKSign, bTSign, v.qc[phase].mask)
}

func (hsm *HotstuffProtocolManager) broadcastPrepareQC(v *View) *HotstuffMessage {
	if v == nil || v.qc["prepare"] == nil {
		return nil
	}
	msg := hsm.createSignatureMsg(v, MsgQCBroadcast, "prepare")
	v.leaderMsg[MsgQCBroadcast] = msg

	log.Info("HOTSTUFF PREPARE QC BROADCAST",
		"number", v.number,
		"viewID", v.hash,
		"votes", len(v.prepareVoteInfo),
		"threshold", v.threshold)
	hsm.app.Broadcast(msg)
	return msg
}

func (hsm *HotstuffProtocolManager) verifyPrepareQCMessage(v *View, m *HotstuffMessage) error {
	if v == nil || m == nil {
		return ErrMissingView
	}
	if !v.hasKState() && !v.hasTState() {
		return ErrUnhandledMsg
	}
	if v.hasKState() && !hsm.verifyAggregatedSignature(m.DataA, m.DataC, MsgVotePrepare, v.hash, v.leaderId, v.proposedKState, v.groupPublicKey, v.threshold) {
		return ErrInvalidPrepareQC
	}
	if v.hasTState() && !hsm.verifyAggregatedSignature(m.DataB, m.DataC, MsgVotePrepare, v.hash, v.leaderId, v.proposedTState, v.groupPublicKey, v.threshold) {
		return ErrInvalidPrepareQC
	}
	return nil
}

func (hsm *HotstuffProtocolManager) certifyView(v *View, m *HotstuffMessage) error {
	if v == nil || m == nil {
		return ErrMissingView
	}
	if v.certified {
		return nil
	}
	if !v.hasTState() {
		return ErrInvalidProposal
	}
	certified := &SignedState{
		State:    append([]byte(nil), v.proposedTState...),
		Sign:     append([]byte(nil), m.DataB...),
		Mask:     append([]byte(nil), m.DataC...),
		ViewID:   v.hash,
		LeaderID: v.leaderId,
		Number:   v.number,
	}
	if err := hsm.app.OnCertified(certified); err != nil {
		return err
	}
	v.certified = true
	return nil
}

// for leader
func (hsm *HotstuffProtocolManager) handlePrepareVoteMsg(m *HotstuffMessage) error {
	v, exist := hsm.views[m.ViewId]
	if !exist {
		if finalized := hsm.finalized[m.ViewId]; finalized != nil {
			log.Warn("HOTSTUFF RECOVERY answer late vote from finalized cache",
				"number", finalized.number,
				"viewID", m.ViewId,
				"to", m.Id)
			if finalized.prepare != nil {
				_ = hsm.app.Write(m.Id, finalized.prepare)
			}
			if finalized.qcBroadcast != nil {
				_ = hsm.app.Write(m.Id, finalized.qcBroadcast)
			}
			if finalized.decide != nil {
				return hsm.app.Write(m.Id, finalized.decide)
			}
			return nil
		}
		log.Debug("handlePrepareVoteMsg found no matched view", "viewId", m.ViewId)
		return ErrMissingView
	}

	err, qrum := v.msgToVoteInfo(m)
	if err != nil {
		log.Debug("handlePrepareVoteMsg failed to convert msg to voteInfo", "error", err)
		return err
	}

	if v.hasKState() {
		if len(v.proposedKDigest) == 0 {
			v.proposedKDigest = hotstuffDigest(v.proposedKState)
		}
		if !qrum.ValidKSign || !hsm.verifyVoteSignature(qrum.KSign, qrum.PubKey, MsgVotePrepare, v.hash, v.leaderId, v.proposedKState) {
			log.Debug("handlePrepareVoteMsg failed to verify k-state signature", "viewId", m.ViewId)
			return ErrQCVerification
		}
	}

	if v.hasTState() {
		if len(v.proposedTDigest) == 0 {
			v.proposedTDigest = hotstuffDigest(v.proposedTState)
		}
		if !qrum.ValidTSign || !hsm.verifyVoteSignature(qrum.TSign, qrum.PubKey, MsgVotePrepare, v.hash, v.leaderId, v.proposedTState) {
			log.Debug("handlePrepareVoteMsg failed to verify t-state signature", "viewId", m.ViewId)
			hsm.DumpView(v, true)
			return ErrQCVerification
		}
	}

	if v.phaseAsLeader != PhasePreCommit {
		log.Trace("handlePrepareVoteMsg view phase not match", "viewID", hex.EncodeToString(v.hash[:]), "phase", readablePhase(v.phaseAsLeader), "shouldBe", readablePhase(PhasePreCommit))

		if decideMsg, ok := v.leaderMsg[MsgDecide]; ok {
			log.Debug("handlePrepareVoteMsg load Decide message and send to replica", "replicaId", m.Id)
			hsm.app.Write(m.Id, decideMsg)

			return nil
		}
		if qcMsg, ok := v.leaderMsg[MsgQCBroadcast]; ok {
			log.Debug("handlePrepareVoteMsg load PrepareQC message and send to replica", "replicaId", m.Id)
			return hsm.app.Write(m.Id, qcMsg)
		}

		return ErrViewPhaseNotMatch
	}
	pubKey := bls.GetPublicKey(m.PubKey)
	if pubKey == nil {
		log.Warn("prepare-vote message has invalid public key", "from", m.Id, "viewId", m.ViewId, "pubKey", hex.EncodeToString(m.PubKey))
		return nil
	}
	/*
		var pubKey bls.PublicKey
		if err := pubKey.Deserialize(m.PubKey); err != nil {
			log.Warn("prepare-vote message has invalid public key", "from", m.Id, "viewId", m.ViewId, "pubKey", hex.EncodeToString(m.PubKey))
			return nil
		}
	*/
	if hsm.lookupVoteInfo(pubKey, v.prepareVoteInfo) {
		if v.phaseAsLeader == PhasePreCommit && len(v.prepareVoteInfo) < v.threshold {
			v.waitingMoreVoteInfo = true
			if v.waitingMoreVoteInfoAt.IsZero() {
				v.waitingMoreVoteInfoAt = time.Now()
			}
		}
		log.Warn("discard dup prepare-vote message",
			"from", m.Id,
			"viewId", m.ViewId,
			"votes", len(v.prepareVoteInfo),
			"threshold", v.threshold)
		return nil
	}

	v.prepareVoteInfo = append(v.prepareVoteInfo, qrum)
	if len(v.prepareVoteInfo) < v.threshold {
		v.waitingMoreVoteInfo = true
		if v.waitingMoreVoteInfoAt.IsZero() {
			v.waitingMoreVoteInfoAt = time.Now()
		}
		log.Debug("handlePrepareVoteMsg need more voteInfo", "number", v.number, "threshold", v.threshold, "current", len(v.prepareVoteInfo))
		return ErrInsufficientQC
	}

	v.waitingMoreVoteInfo = false
	if err := hsm.aggregateQC(v, "prepare", v.prepareVoteInfo); err != nil {
		log.Debug("aggregate prepare voteInfo failed")
		return err
	}

	qcMsg := hsm.broadcastPrepareQC(v)
	if hsm.app.UseFHS2Chain() {
		v.phaseAsLeader = PhaseFinal
		if qcMsg != nil {
			v.leaderMsg[MsgQCBroadcast] = qcMsg
		}
		v.lastLeaderRecoveryAt = time.Now()
		hsm.cacheFinalizedRecovery(v, nil)
		return nil
	}
	msg := hsm.createSignatureMsg(v, MsgDecide, "prepare")

	log.Debug("handlePrepareVoteMsg broadcast Decide msg", "viewId", m.ViewId, "number", v.number)
	log.Info("HOTSTUFF DECIDE BROADCAST", "number", v.number, "viewID", m.ViewId, "votes", len(v.prepareVoteInfo), "threshold", v.threshold)
	hsm.app.Broadcast(msg)
	v.phaseAsLeader = PhaseFinal
	v.leaderMsg[MsgDecide] = msg
	if qcMsg != nil {
		v.leaderMsg[MsgQCBroadcast] = qcMsg
	}
	v.lastLeaderRecoveryAt = time.Now()
	hsm.cacheFinalizedRecovery(v, msg)

	return nil
}

// for replica
func (hsm *HotstuffProtocolManager) handleQCBroadcastMsg(m *HotstuffMessage) error {
	v, exist := hsm.views[m.ViewId]
	if !exist {
		return ErrUnhandledMsg
	}
	if err := hsm.verifyPrepareQCMessage(v, m); err != nil {
		return err
	}

	v.leaderMsg[MsgQCBroadcast] = m
	if hsm.app.UseFHS2Chain() {
		if err := hsm.certifyView(v, m); err != nil {
			return err
		}
		v.phaseAsReplica = PhaseFinal
	}
	log.Info("HOTSTUFF PREPARE QC VERIFIED",
		"number", m.Number,
		"viewID", m.ViewId,
		"from", m.Id,
		"maskBytes", len(m.DataC))
	return nil
}

// for replica
func (hsm *HotstuffProtocolManager) handleDecideMsg(m *HotstuffMessage) error {
	if hsm.app.UseFHS2Chain() {
		log.Warn("ignore MsgDecide in FHS 2-chain mode", "number", m.Number, "viewID", m.ViewId, "from", m.Id)
		return nil
	}
	start := time.Now()
	v, exist := hsm.views[m.ViewId]
	if !exist {
		//log.Debug("handleDecideMsg found no match view", "viewId", m.ViewId)
		return ErrMissingView
		//return ErrUnhandledMsg
	}

	//if v.phaseAsReplica < PhaseDecide {
	//	log.Debug("handleDecideMsg got future phase message", "viewId", hex.EncodeToString(m.ViewId[:]), "phase", readablePhase(v.phaseAsReplica))
	//	return ErrUnhandledMsg
	//}

	if v.phaseAsReplica > PhaseDecide {
		log.Trace("handleDecideMsg discard old phase message", "viewId", hex.EncodeToString(m.ViewId[:]), "phase", readablePhase(v.phaseAsReplica))
		return ErrViewOldPhase
	}

	if v.hasTState() {
		if !hsm.verifyAggregatedSignature(m.DataB, m.DataC, MsgVotePrepare, v.hash, v.leaderId, v.proposedTState, v.groupPublicKey, v.threshold) {
			log.Debug("handleDecideMsg failed to verify aggregated t-state signature", "viewId", m.ViewId)
			hsm.DumpView(v, false)
			return ErrInvalidPrepareQC
		}
	}

	log.Debug("handleDecideMsg view done", "viewId", m.ViewId, "number", m.Number)
	log.Info("HOTSTUFF DECIDE VERIFIED", "number", m.Number, "viewID", m.ViewId, "from", m.Id, "elapsed", time.Since(start))

	// execute the command. In proposal-ref mode, v.proposedTState is the
	// canonical ProposalRef bytes. The application is responsible for resolving
	// the sidecar body and committing a previously verified proposal when present.
	if err := hsm.viewDone(v, m.DataA, m.DataB, m.DataC, nil); err != nil {
		return err
	}
	v.phaseAsReplica = PhaseFinal

	// start new view
	//hsm.NewView()

	return nil
}

func (hsm *HotstuffProtocolManager) handleMessage(m *HotstuffMessage) error {
	switch {
	case m.Code == MsgTimer:
		return hsm.handleTimerMsg(m.Number)

	case m.Code == MsgNewView:
		return hsm.handleNewViewMsg(m)

	case m.Code == MsgPrepare:
		return hsm.handlePrepareMsg(m)
	case m.Code == MsgVotePrepare:
		return hsm.handlePrepareVoteMsg(m)
		/*
			case m.Code == MsgPreCommit:
				return hsm.handlePreCommitMsg(m)
			case m.Code == MsgVotePreCommit:
				return hsm.handlePreCommitVoteMsg(m)

			case m.Code == MsgCommit:
				return hsm.handleCommitMsg(m)
			case m.Code == MsgVoteCommit:
				return hsm.handleCommitVoteMsg(m)
		*/
	case m.Code == MsgDecide:
		return hsm.handleDecideMsg(m)
	case m.Code == MsgQCBroadcast:
		return hsm.handleQCBroadcastMsg(m)
	//empty message
	case m.Code == MsgStartNewView:
		log.Debug("handler handleStartNewView")
		return hsm.NewView()
	case m.Code == MsgTryPropose:
		log.Debug("handler MsgTryPropose")
		return hsm.TryPropose()

	default:
		log.Warn("unknown hotstuff message", "code", m.Code)
		return nil
	}
}

func (hsm *HotstuffProtocolManager) addToUnhandled(m *HotstuffMessage) {
	if m.Number < hsm.app.CurrentN() {
		return
	}
	bs, err := rlp.EncodeToBytes(m)
	if err != nil {
		log.Warn("failed to encode hotstuff message to bytes, discarded")
		return
	}
	m.ReceivedAt = time.Now() //??

	k := hotstuffDigestHash(bs)
	hsm.unhandledMsg[k] = m
}

func (hsm *HotstuffProtocolManager) HandleMessage(msg *HotstuffMessage) error {
	if msg.Code != MsgTimer {
		log.Debug("HandleMessage", "Number", msg.Number, "viewId", msg.ViewId, "code", ReadableMsgType(msg.Code), "from", msg.Id)
	}
	err := hsm.handleMessage(msg)
	if err == ErrUnhandledMsg {
		log.Debug("Add unhandled hotstuff message", "viewId", msg.ViewId, "code", msg.Code, "from", msg.Id)
		//fmt.Println("Add unhandled hotstuff message", "viewId", msg.ViewId, "code", msg.Code, "from", msg.Id)
		hsm.addToUnhandled(msg)
		return ErrUnhandledMsg
	}

	for k, m := range hsm.unhandledMsg {
		if e := hsm.handleMessage(m); e != ErrUnhandledMsg {
			log.Debug("Remove unhandled hotstuff message", "viewId", msg.ViewId, "code", msg.Code, "from", msg.Id)
			delete(hsm.unhandledMsg, k)
		}
	}

	return err
}

func (hsm *HotstuffProtocolManager) handleTimerMsg(curN uint64) error {
	now := time.Now()
	for _, v := range hsm.views {
		if v.number <= curN {
			continue
		}

		if now.Sub(v.lastReplicaRecoveryAt) >= hotstuffRecoveryInterval {
			switch v.phaseAsReplica {
			case PhasePrepare:
				if msg, ok := v.replicaMsg[MsgNewView]; ok && msg != nil {
					v.lastReplicaRecoveryAt = now
					log.Warn("HOTSTUFF RECOVERY resend NewView",
						"number", v.number,
						"viewID", v.hash,
						"to", v.leaderId)
					if err := hsm.app.Write(v.leaderId, msg); err != nil {
						log.Warn("HOTSTUFF RECOVERY NewView resend failed",
							"number", v.number,
							"viewID", v.hash,
							"to", v.leaderId,
							"err", err)
					}
				}
			case PhaseDecide:
				if msg, ok := v.replicaMsg[MsgVotePrepare]; ok && msg != nil {
					v.lastReplicaRecoveryAt = now
					log.Warn("HOTSTUFF RECOVERY resend VotePrepare",
						"number", v.number,
						"viewID", v.hash,
						"to", v.leaderId)
					if err := hsm.app.Write(v.leaderId, msg); err != nil {
						log.Warn("HOTSTUFF RECOVERY VotePrepare resend failed",
							"number", v.number,
							"viewID", v.hash,
							"to", v.leaderId,
							"err", err)
					}
				}
			}
		}

		if v.leaderId != hsm.app.Self() || now.Sub(v.lastLeaderRecoveryAt) < hotstuffRecoveryInterval {
			continue
		}

		switch v.phaseAsLeader {
		case PhasePrepare:
			threshold := v.threshold
			if threshold > len(v.groupPublicKey) {
				threshold = len(v.groupPublicKey)
			}
			if threshold <= 0 || len(v.highVoteInfo) < threshold {
				continue
			}
			v.lastLeaderRecoveryAt = now
			log.Warn("HOTSTUFF RECOVERY retry OnNewView",
				"number", v.number,
				"viewID", v.hash)
			if err := hsm.activateLeaderView(v); err != nil {
				log.Warn("HOTSTUFF RECOVERY OnNewView retry failed",
					"number", v.number,
					"viewID", v.hash,
					"err", err)
			}

		case PhaseTryPropose:
			v.lastLeaderRecoveryAt = now
			log.Warn("HOTSTUFF RECOVERY retry proposal",
				"number", v.number,
				"viewID", v.hash)
			hsm.leaderView = v
			if err := hsm.TryPropose(); err != nil {
				log.Warn("HOTSTUFF RECOVERY proposal retry failed",
					"number", v.number,
					"viewID", v.hash,
					"err", err)
			}

		case PhasePreCommit:
			if !v.waitingMoreVoteInfo {
				continue
			}
			elapsed := now.Sub(v.waitingMoreVoteInfoAt)
			if elapsed < params.CollectVoteInfoTimeout {
				continue
			}
			v.waitingMoreVoteInfoAt = now
			v.lastLeaderRecoveryAt = now

			if len(v.prepareVoteInfo) < v.threshold {
				hsm.rebroadcastPrepare(v, "collect-vote-timeout")
				continue
			}

			log.Debug("@@@handleTimerMsg", "curN", curN, "number", v.number, "elapsed(s)", elapsed)
			if err := hsm.aggregateQC(v, "prepare", v.prepareVoteInfo); err != nil {
				log.Debug("aggregate prepare voteInfo failed")
				continue
			}

			log.Debug("handleTimerMsg handlePrepareVoteMsg broadcast Decide msg", "number", v.number)
			v.waitingMoreVoteInfo = false
			qcMsg := hsm.broadcastPrepareQC(v)
			if hsm.app.UseFHS2Chain() {
				v.phaseAsLeader = PhaseFinal
				if qcMsg != nil {
					v.leaderMsg[MsgQCBroadcast] = qcMsg
				}
				hsm.cacheFinalizedRecovery(v, nil)
				continue
			}
			msg := hsm.createSignatureMsg(v, MsgDecide, "prepare")
			hsm.app.Broadcast(msg)
			v.phaseAsLeader = PhaseFinal
			v.leaderMsg[MsgDecide] = msg
			hsm.cacheFinalizedRecovery(v, msg)

		}
	}

	for id, finalized := range hsm.finalized {
		if finalized == nil || now.Sub(finalized.finalizedAt) > finalizedRecoveryRetention {
			delete(hsm.finalized, id)
			continue
		}
		if now.Sub(finalized.lastSentAt) < hotstuffRecoveryInterval {
			continue
		}
		finalized.lastSentAt = now
		if finalized.prepare != nil {
			log.Warn("HOTSTUFF RECOVERY rebroadcast retained Prepare",
				"number", finalized.number,
				"viewID", id)
			hsm.app.Broadcast(finalized.prepare)
		}
		if finalized.qcBroadcast != nil {
			log.Warn("HOTSTUFF RECOVERY rebroadcast retained PrepareQC",
				"number", finalized.number,
				"viewID", id)
			hsm.app.Broadcast(finalized.qcBroadcast)
		}
		if finalized.decide != nil {
			log.Warn("HOTSTUFF RECOVERY rebroadcast retained Decide",
				"number", finalized.number,
				"viewID", id)
			hsm.app.Broadcast(finalized.decide)
		}
	}

	return nil
}

func (hsm *HotstuffProtocolManager) SignHash(data []byte) []byte {
	sign := hsm.secretKey.SignHash(hotstuffDigest(data)).Serialize()
	log.Info("Signed hotstuff data!")
	return sign
}

func (hsm *HotstuffProtocolManager) SignHashWithContext(msgCode uint32, viewID common.Hash, leaderID string, data []byte) []byte {
	sign := hsm.secretKey.SignHash(hotstuffContextDigest(hsm.app.ChainID(), msgCode, viewID, leaderID, data)).Serialize()
	log.Info("Signed hotstuff data with context!")
	return sign
}

func (hsm *HotstuffProtocolManager) SignHashByMessage(msgCode uint32, viewID common.Hash, leaderID string, data []byte) []byte {
	if hsm.app.UseContextSignatures() {
		return hsm.SignHashWithContext(msgCode, viewID, leaderID, data)
	}
	return hsm.SignHash(data)
}

func (hsm *HotstuffProtocolManager) verifyVoteSignature(sig bls.Sign, pub *bls.PublicKey, msgCode uint32, viewID common.Hash, leaderID string, data []byte) bool {
	if hsm.app.UseContextSignatures() {
		return sig.VerifyHash(pub, hotstuffContextDigest(hsm.app.ChainID(), msgCode, viewID, leaderID, data))
	}
	return sig.VerifyHash(pub, hotstuffDigest(data))
}

func (hsm *HotstuffProtocolManager) verifyAggregatedSignature(bSign []byte, bMask []byte, msgCode uint32, viewID common.Hash, leaderID string, data []byte, groupPublicKey []*bls.PublicKey, threshold int) bool {
	if hsm.app.UseContextSignatures() {
		return VerifySignatureWithContext(bSign, bMask, data, groupPublicKey, threshold, hsm.app.ChainID(), msgCode, viewID, leaderID)
	}
	return VerifySignature(bSign, bMask, data, groupPublicKey, threshold)
}
