package hotstuff

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sync/atomic"
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
const maxUnhandledMessages = 256
const maxUnhandledPerSender = 16
const maxUnhandledBytes = 4 * 1024 * 1024
const maxUnhandledFutureViews = 16
const maxTimeoutStates = 32
const maxHotstuffControlBytes = MaxHotstuffControlBytes
const pendingMessageTTL = 2 * time.Minute
const hotstuffRecoveryInterval = 5 * time.Second
const finalizedRecoveryRetention = 2 * time.Minute
const maxFinalizedRecoveryViews = 16

var (
	ErrNewViewFail               = fmt.Errorf("hotstuff new view fail")
	ErrUnhandledMsg              = fmt.Errorf("hotstuff unhandled message")
	ErrViewTimeout               = fmt.Errorf("hotstuff view timeout")
	ErrQCVerification            = fmt.Errorf("hotstuff QC not valid")
	ErrInvalidReplica            = fmt.Errorf("hotstuff replica not valid")
	ErrInvalidVoteInfoMessage    = fmt.Errorf("hotstuff voteInfo message not valid")
	ErrInsufficientQC            = fmt.Errorf("hotstuff QC insufficient")
	ErrInvalidHighQC             = fmt.Errorf("hotstuff highQC invalid")
	ErrInvalidPrepareQC          = fmt.Errorf("hotstuff prepareQC invalid")
	ErrInvalidPreCommitQC        = fmt.Errorf("hotstuff preCommitQC invalid")
	ErrInvalidCommitQC           = fmt.Errorf("hotstuff commitQC invalid")
	ErrInvalidProposal           = fmt.Errorf("hotstuff proposal invalid")
	ErrProposalValidationPending = fmt.Errorf("hotstuff proposal validation pending")
	ErrInvalidPublicKey          = fmt.Errorf("invalid public key for bls deserialize")
	ErrViewPhaseNotMatch         = fmt.Errorf("hotstuff view phase not match")
	ErrViewOldPhase              = fmt.Errorf("hotstuff old phase ")

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
	MsgTimeout
	MsgTimeoutQC

	// pseudo messages
	MsgStartNewView // for handling new view from app
	MsgTryPropose
	MsgTimer
	MsgLocalTimeout
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
	case m == MsgTimeout:
		return "MsgTimeout"
	case m == MsgTimeoutQC:
		return "MsgTimeoutQC"
	case m == MsgStartNewView:
		return "MsgStartNewView"
	case m == MsgTryPropose:
		return "MsgTryPropose"
	case m == MsgLocalTimeout:
		return "MsgLocalTimeout"

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

// ProposalRecoveryApplication is an optional liveness hint for applications
// that can prove a proposal attempt had no publishable work for an unchanged
// input generation. It suppresses only the generic recovery retry; explicit
// NewTx, new-view, certificate and keyblock triggers still call TryPropose.
type ProposalRecoveryApplication interface {
	ProposalRecoveryReady(viewNumber uint64, viewID common.Hash, leaderID string) bool
}

// FHSProposalReadinessApplication exposes the canonical fields required by the
// local proposal retry gate without resolving a committee or emitting recovery
// traffic. CurrentState remains the authoritative view-construction callback;
// this snapshot is only a side-effect-free equality check for an already
// authenticated leader view. The encoded consensus state binds LeaderIndex and
// CommitteeHash, so an exact byte match preserves the original leader binding.
type FHSProposalReadinessApplication interface {
	FHSProposalReadinessSnapshot() (currentState []byte, viewNumber uint64, highest *SignedState)
}

// FHSLeaderCertificationApplication lets a production application durably
// adopt a leader-created QC before dissemination, while deferring any committee
// transition and two-chain commit until the QC has been sent to the committee
// that certified it.
type FHSLeaderCertificationApplication interface {
	OnFHSLeaderCertifiedBeforeBroadcast(*SignedState) error
	OnFHSLeaderCertifiedAfterBroadcast(*SignedState, bool) error
}

// FHSLeaderKeyApplication resolves the BLS key bound to a historical
// committee member address. It is used when a durable QC broadcast arrives
// after restart and the receiver no longer has the corresponding volatile
// View object.
type FHSLeaderKeyApplication interface {
	FHSLeaderPublicKey(keyHash common.Hash, leaderID string) (*bls.PublicKey, error)
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

	DataD   []byte
	DataE   []byte
	DataF   []byte
	DataG   []byte // FHS parent certified state and QC
	AuthSig []byte

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

	// Fair HotStuff keeps the common target-view context separate from
	// each replica's latest-QC report. This is required because honest
	// replicas can legitimately have different highest certificates during a
	// view change.
	fhsContext     *FHSViewContext
	fhsReports     map[uint32]*NewViewReport
	fhsReportSigns map[uint32]*bls.Sign
	fhsReportBytes int
	fhsAggregate   *AggregateQC
	fhsHighest     *SignedState
	fhsTimeout     *TimeoutCertificate
	fhsValidation  *FHSProposalValidationKey
	fhsBuild       *FHSProposalBuildKey
}

func (v *View) hasKState() bool {
	return v.proposedKState != nil && len(v.proposedKState) > 0
}

func (v *View) hasTState() bool {
	return v.proposedTState != nil && len(v.proposedTState) > 0
}

type HotstuffProtocolManager struct {
	secretKey          *bls.SecretKey
	publicKey          *bls.PublicKey
	views              map[common.Hash]*View
	leaderView         *View
	app                HotStuffApplication
	unhandledMsg       map[common.Hash]*HotstuffMessage // messages which is not handled(which phase is ahead of local's)
	unhandledSize      map[common.Hash]int
	unhandledBytes     int
	pendingNewView     map[common.Hash]map[string]*HotstuffMessage
	finalized          map[common.Hash]*finalizedRecovery
	timeoutVotes       map[common.Hash]map[int]*bls.Sign
	timeoutEchoed      map[common.Hash]bool
	timeoutQC          map[common.Hash]*TimeoutCertificate
	timeoutSeen        map[common.Hash]time.Time
	timeoutView        map[common.Hash]uint64
	validationSequence uint64
	pendingHighQC      *pendingFHSHighQCValidation
	epochReset         uint32
}

type pendingFHSHighQCValidation struct {
	key         FHSHighQCValidationKey
	qc          *SignedState
	messages    []*HotstuffMessage
	leaderViews map[common.Hash]struct{}
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
		unhandledSize:  make(map[common.Hash]int),
		pendingNewView: make(map[common.Hash]map[string]*HotstuffMessage),
		finalized:      make(map[common.Hash]*finalizedRecovery),
		timeoutVotes:   make(map[common.Hash]map[int]*bls.Sign),
		timeoutEchoed:  make(map[common.Hash]bool),
		timeoutQC:      make(map[common.Hash]*TimeoutCertificate),
		timeoutSeen:    make(map[common.Hash]time.Time),
		timeoutView:    make(map[common.Hash]uint64),
	}
	return manager
}

func CalcThreshold(size int) int {
	return (size + 1) * 2 / 3
}

func ValidateBFTCommitteeSize(size int) error {
	if size <= 0 || size > params.MaxFairHotstuffCommitteeSize || (size != 1 && (size-1)%3 != 0) {
		return fmt.Errorf("invalid BFT committee size %d: require n=3f+1 and n<=%d", size, params.MaxFairHotstuffCommitteeSize)
	}
	return nil
}

func (hsm *HotstuffProtocolManager) UpdateKeyPair(sec *bls.SecretKey) {
	hsm.secretKey = sec
	hsm.publicKey = sec.GetPublicKey()
}

// ScheduleFHSEpochReset requests a volatile protocol reset at a top-level
// HandleMessage boundary. Application callbacks run inside view processing, so
// clearing hsm.views synchronously from the callback would invalidate the View
// currently on the stack. The durable QC/WAL outbox is intentionally retained.
func (hsm *HotstuffProtocolManager) ScheduleFHSEpochReset() {
	if hsm == nil {
		return
	}
	atomic.StoreUint32(&hsm.epochReset, 1)
}

func (hsm *HotstuffProtocolManager) applyScheduledFHSEpochReset() bool {
	if hsm == nil || !atomic.CompareAndSwapUint32(&hsm.epochReset, 1, 0) {
		return false
	}
	hsm.views = make(map[common.Hash]*View)
	hsm.leaderView = nil
	hsm.unhandledMsg = make(map[common.Hash]*HotstuffMessage)
	hsm.unhandledSize = make(map[common.Hash]int)
	hsm.unhandledBytes = 0
	hsm.pendingNewView = make(map[common.Hash]map[string]*HotstuffMessage)
	hsm.finalized = make(map[common.Hash]*finalizedRecovery)
	hsm.timeoutVotes = make(map[common.Hash]map[int]*bls.Sign)
	hsm.timeoutEchoed = make(map[common.Hash]bool)
	hsm.timeoutQC = make(map[common.Hash]*TimeoutCertificate)
	hsm.timeoutSeen = make(map[common.Hash]time.Time)
	hsm.timeoutView = make(map[common.Hash]uint64)
	hsm.pendingHighQC = nil
	log.Info("reset Fair HotStuff volatile state for new key epoch")
	return true
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
	if err := ValidateBFTCommitteeSize(v.cmLen); err != nil {
		return err
	}
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
			hsm.removeUnhandled(k, m)
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
	if hsm.usesFHSProtocolV2() {
		return hsm.newFHSNewView()
	}
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
	if err := hsm.sealMessage(msg); err != nil {
		return err
	}
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
	if hsm.app.UseFHS2Chain() {
		if _, durable := hsm.app.(FHSLeaderCertificationApplication); durable {
			// The durable leader lifecycle fsyncs the QC before its first broadcast.
			// Its single persisted outbox owns retry and restart recovery, so retaining
			// the same QCBroadcast here would create a second timer-driven replay loop.
			return
		}
	}
	entry := &finalizedRecovery{
		number:      v.number,
		decide:      decide,
		finalizedAt: time.Now(),
		lastSentAt:  time.Now(),
	}
	// Before certification, resending Prepare is required to collect missing
	// votes. Once an FHS view has a QC, however, the self-contained QCBroadcast
	// is the recovery object. Retaining the older Prepare makes every receiver
	// with that QC reject its stale parent HighQC on each recovery tick, wasting
	// the bounded control queue and potentially starving current-view traffic.
	if !hsm.app.UseFHS2Chain() {
		entry.prepare = v.leaderMsg[MsgPrepare]
	}
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
	if hsm.usesFHSProtocolV2() {
		return hsm.validateFHSNewViewMsg(msg)
	}
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
	if err := hsm.verifyMessageAuth(msg, msg.Id, vote.PubKey); err != nil {
		return nil, nil, err
	}
	if !hsm.verifyVoteSignature(vote.KSign, vote.PubKey, MsgNewView, v.hash, v.leaderId, msg.DataA) {
		return nil, nil, ErrQCVerification
	}
	return v, vote, stateErr
}

func (hsm *HotstuffProtocolManager) queueFutureNewView(msg *HotstuffMessage, vote *VoteInfo) {
	if msg == nil || vote == nil || vote.PubKey == nil {
		return
	}
	if msg.Number > hsm.app.CurrentN()+maxPendingNewViewIDs {
		log.Warn("drop far-future new-view", "number", msg.Number, "current", hsm.app.CurrentN())
		return
	}
	encoded, err := rlp.EncodeToBytes(msg)
	if err != nil || len(encoded) > maxHotstuffControlBytes {
		return
	}
	now := time.Now()
	for id, entries := range hsm.pendingNewView {
		for key, pendingMsg := range entries {
			if pendingMsg == nil || (!pendingMsg.ReceivedAt.IsZero() && now.Sub(pendingMsg.ReceivedAt) > pendingMessageTTL) {
				delete(entries, key)
			}
		}
		if len(entries) == 0 {
			delete(hsm.pendingNewView, id)
		}
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
		msg.ReceivedAt = now
		pending[key] = msg
	}
}

func (hsm *HotstuffProtocolManager) acceptValidatedNewView(msg *HotstuffMessage, validatedView *View, vote *VoteInfo) error {
	if hsm.usesFHSProtocolV2() {
		return hsm.acceptFHSNewView(msg, validatedView, vote)
	}
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
	if hsm.usesFHSProtocolV2() {
		return hsm.activateFHSLeaderView(v)
	}
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
	if hsm.usesFHSProtocolV2() {
		return hsm.tryFHSPropose()
	}
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
	if err := hsm.sealMessage(msg); err != nil {
		return err
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

// CanTryPropose reports whether a local maintenance wake-up can make progress.
// It is intended for the serialized HotStuff control loop only. New-view
// activation invokes TryPropose directly, so polling before the leader has a
// quorum merely crowds authenticated network control traffic with local
// MsgTryPropose messages.
func (hsm *HotstuffProtocolManager) CanTryPropose() bool {
	if hsm == nil || hsm.leaderView == nil || hsm.leaderView.phaseAsLeader != PhaseTryPropose {
		return false
	}
	if !hsm.usesFHSProtocolV2() {
		return true
	}
	v := hsm.leaderView
	ctx := v.fhsContext
	if ctx == nil || v.fhsAggregate == nil || v.fhsBuild != nil || ctx.Validate() != nil ||
		ctx.ChainID != hsm.app.ChainID() || ctx.TargetView != v.number || ctx.LeaderID != v.leaderId ||
		ctx.ID() != v.hash || v.fhsAggregate.Context != *ctx {
		return false
	}
	var (
		state   []byte
		number  uint64
		highest *SignedState
	)
	if readiness, ok := hsm.app.(FHSProposalReadinessApplication); ok {
		state, number, highest = readiness.FHSProposalReadinessSnapshot()
	} else {
		var leaderID string
		state, leaderID, number = hsm.app.CurrentState()
		if leaderID != v.leaderId {
			return false
		}
		highest = hsm.selectedFHSProposalParent()
	}
	if number != v.number || !bytes.Equal(state, v.currentState) {
		return false
	}
	stateView := bftview.DecodeToView(state)
	if stateView == nil || stateView.KeyNumber != ctx.KeyNumber || stateView.KeyHash != ctx.KeyHash ||
		stateView.CommitteeHash != ctx.CommitteeHash {
		return false
	}
	return SignedStateSemanticEqual(highest, v.fhsHighest)
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
	if err := ValidateBFTCommitteeSize(len(parentKeys)); err != nil {
		return fmt.Errorf("%w: parent committee: %v", ErrInvalidHighQC, err)
	}
	parentThreshold := CalcThreshold(len(parentKeys))
	if !hsm.verifyAggregatedSignature(parentQC.Sign, parentQC.Mask, MsgVotePrepare, parentQC.ViewID, parentQC.LeaderID, parentQC.State, parentKeys, parentThreshold) {
		return fmt.Errorf("%w: parent QC signature invalid for committee %s", ErrInvalidHighQC, parentRef.KeyHash)
	}
	return nil
}

func verifySignatureDigest(bSign []byte, bMask []byte, digest []byte, groupPublicKey []*bls.PublicKey, threshold int) bool {
	if err := ValidateCanonicalSignerMask(bMask, len(groupPublicKey), threshold); err != nil {
		log.Debug("reject non-canonical signer mask", "err", err)
		return false
	}
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
	if hsm.usesFHSProtocolV2() {
		return hsm.handleFHSPrepareMsg(m)
	}
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
	proposalState := bftview.DecodeToView(v.currentState)
	if proposalState == nil || proposalState.LeaderIndex >= uint(len(v.groupPublicKey)) {
		return ErrInvalidLeaderView
	}
	if err := hsm.verifyMessageAuth(m, v.leaderId, v.groupPublicKey[proposalState.LeaderIndex]); err != nil {
		return err
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
	if err := hsm.sealMessage(msg); err != nil {
		return err
	}

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
	msg := hsm.newMsg(code, v.number, v.hash, bKSign, bTSign, v.qc[phase].mask)
	if code == MsgQCBroadcast && hsm.app.UseFHS2Chain() {
		// A receiver may have lost its volatile View during restart. Carry the
		// exact proposal reference certified by DataB/DataC so it can verify and
		// adopt the QC without trusting local cache state.
		msg.DataD = append([]byte(nil), v.proposedTState...)
	}
	if err := hsm.sealMessage(msg); err != nil {
		log.Error("failed to authenticate hotstuff QC message", "code", code, "err", err)
		return nil
	}
	return msg
}

// RebuildFHSQCBroadcast recreates the authenticated wire envelope for a
// leader QC kept in the durable restart outbox. The aggregate QC bytes and its
// semantic identity are unchanged; only the leader envelope signature is
// freshly sealed with the same configured consensus key.
func (hsm *HotstuffProtocolManager) RebuildFHSQCBroadcast(qc *SignedState) (*HotstuffMessage, error) {
	if qc == nil || !hsm.app.UseFHS2Chain() || qc.LeaderID != hsm.app.Self() {
		return nil, ErrInvalidPrepareQC
	}
	msg := hsm.newMsg(MsgQCBroadcast, qc.Number, qc.ViewID, nil, qc.Sign, qc.Mask)
	msg.DataD = append([]byte(nil), qc.State...)
	if err := hsm.sealMessage(msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func (hsm *HotstuffProtocolManager) broadcastPrepareQC(v *View) (*HotstuffMessage, error) {
	if v == nil || v.qc["prepare"] == nil {
		return nil, ErrMissingView
	}
	markRetryable := func() {
		v.waitingMoreVoteInfo = true
		v.waitingMoreVoteInfoAt = time.Now()
	}
	msg := hsm.createSignatureMsg(v, MsgQCBroadcast, "prepare")
	if msg == nil {
		markRetryable()
		return nil, fmt.Errorf("failed to authenticate prepare QC")
	}
	v.leaderMsg[MsgQCBroadcast] = msg
	var (
		certified *SignedState
		lifecycle FHSLeaderCertificationApplication
	)
	if hsm.app.UseFHS2Chain() {
		// The leader must durably adopt its own QC before any peer can observe
		// it. Otherwise a crash between broadcast and local self-delivery loses
		// the highest certificate and can violate restart safety.
		if hooks, ok := hsm.app.(FHSLeaderCertificationApplication); ok {
			lifecycle = hooks
			certified = hsm.certifiedState(v, msg)
			if certified == nil {
				delete(v.leaderMsg, MsgQCBroadcast)
				markRetryable()
				return nil, ErrInvalidProposal
			}
			// Before/After bracket every physical send attempt, not only the
			// first durable certification. The application uses this window to
			// suppress a concurrent durable-outbox replay. On a retry the QC is
			// already certified, but re-entering the idempotent Before hook is
			// still required before Broadcast exposes the same wire message.
			if err := lifecycle.OnFHSLeaderCertifiedBeforeBroadcast(certified); err != nil {
				delete(v.leaderMsg, MsgQCBroadcast)
				markRetryable()
				return nil, err
			}
			v.certified = true
		} else if err := hsm.certifyView(v, msg); err != nil {
			delete(v.leaderMsg, MsgQCBroadcast)
			markRetryable()
			return nil, err
		}
	}

	log.Info("HOTSTUFF PREPARE QC BROADCAST",
		"number", v.number,
		"viewID", v.hash,
		"votes", len(v.prepareVoteInfo),
		"threshold", v.threshold)
	broadcastSucceeded := len(hsm.app.Broadcast(msg)) == 0
	if lifecycle != nil {
		if err := lifecycle.OnFHSLeaderCertifiedAfterBroadcast(certified, broadcastSucceeded); err != nil {
			markRetryable()
			return msg, err
		}
	}
	return msg, nil
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
	certified := hsm.certifiedState(v, m)
	if certified == nil {
		return ErrInvalidProposal
	}
	if err := hsm.certifyFHSQC(certified, m); err != nil {
		return err
	}
	v.certified = true
	return nil
}

func (hsm *HotstuffProtocolManager) certifiedState(v *View, m *HotstuffMessage) *SignedState {
	if v == nil || m == nil || !v.hasTState() {
		return nil
	}
	return &SignedState{
		State:    append([]byte(nil), v.proposedTState...),
		Sign:     append([]byte(nil), m.DataB...),
		Mask:     append([]byte(nil), m.DataC...),
		ViewID:   v.hash,
		LeaderID: v.leaderId,
		Number:   v.number,
	}
}

// for leader
func (hsm *HotstuffProtocolManager) handlePrepareVoteMsg(m *HotstuffMessage) error {
	v, exist := hsm.views[m.ViewId]
	if !exist {
		log.Debug("handlePrepareVoteMsg found no matched view", "viewId", m.ViewId)
		return ErrMissingView
	}

	err, qrum := v.msgToVoteInfo(m)
	if err != nil {
		log.Debug("handlePrepareVoteMsg failed to convert msg to voteInfo", "error", err)
		return err
	}
	if hsm.requiresMessageAuth() {
		voteView := bftview.DecodeToView(v.currentState)
		committee := (*bftview.Committee)(nil)
		if voteView != nil {
			committee = bftview.LoadMember(voteView.KeyNumber, voteView.KeyHash, true)
		}
		if committee == nil || qrum.Index < 0 || qrum.Index >= len(committee.List) || committee.List[qrum.Index] == nil ||
			bftview.GetNodeID(committee.List[qrum.Index].Address, committee.List[qrum.Index].Public) != m.Id {
			return ErrInvalidReplica
		}
		if err := hsm.verifyMessageAuth(m, m.Id, qrum.PubKey); err != nil {
			return err
		}
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

	qcMsg, err := hsm.broadcastPrepareQC(v)
	if err != nil {
		return err
	}
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
	if msg == nil {
		return fmt.Errorf("failed to authenticate decide message")
	}

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
		if !hsm.app.UseFHS2Chain() {
			return ErrUnhandledMsg
		}
		return hsm.handleStandaloneFHSQCBroadcast(m)
	}
	if m.Number != v.number {
		return ErrViewIdNotMatch
	}
	if hsm.requiresMessageAuth() {
		qcView := bftview.DecodeToView(v.currentState)
		if qcView == nil || qcView.LeaderIndex >= uint(len(v.groupPublicKey)) {
			return ErrInvalidLeaderView
		}
		if err := hsm.verifyMessageAuth(m, v.leaderId, v.groupPublicKey[qcView.LeaderIndex]); err != nil {
			return err
		}
	}
	if hsm.app.UseFHS2Chain() && !bytes.Equal(m.DataD, v.proposedTState) {
		return ErrInvalidPrepareQC
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

// handleStandaloneFHSQCBroadcast verifies a self-contained QC after the
// receiver has lost the corresponding volatile View (for example, all nodes
// restarted after the leader fsynced the QC but before dissemination). No
// state is published until the historical committee, canonical signer mask,
// aggregate vote signature and authenticated leader envelope all verify.
func (hsm *HotstuffProtocolManager) handleStandaloneFHSQCBroadcast(m *HotstuffMessage) error {
	if m == nil || len(m.DataB) == 0 || len(m.DataC) == 0 || len(m.DataD) == 0 {
		return fmt.Errorf("%w: incomplete standalone FHS QC", ErrInvalidPrepareQC)
	}
	// DataA may contain the aggregate key-state vote when the original view
	// proposed a key block and a transaction block together. The independently
	// certified transaction proposal is carried by DataB/DataC/DataD, and the
	// authenticated envelope binds the optional DataA bytes as well. A replica
	// that lost the volatile View must therefore not reject an otherwise valid
	// transaction QC merely because the original leader retained the key vote.
	qc := &SignedState{
		State:    append([]byte(nil), m.DataD...),
		Sign:     append([]byte(nil), m.DataB...),
		Mask:     append([]byte(nil), m.DataC...),
		ViewID:   m.ViewId,
		LeaderID: m.Id,
		Number:   m.Number,
	}
	ref, err := types.DecodeHotstuffProposalRef(qc.State)
	if err != nil || ref.ChainID != hsm.app.ChainID() || ref.ViewNumber != qc.Number || ref.ViewID != qc.ViewID || ref.LeaderID != qc.LeaderID {
		return fmt.Errorf("%w: standalone proposal/QC context mismatch", ErrInvalidPrepareQC)
	}
	keys, err := hsm.app.GetPublicKey(ref.KeyHash)
	if err != nil {
		return err
	}
	threshold := CalcThreshold(len(keys))
	if err := ValidateCanonicalSignerMask(qc.Mask, len(keys), threshold); err != nil {
		return err
	}
	if !VerifyFHSSignatureWithContext(qc.Sign, qc.Mask, qc.State, keys, threshold, hsm.app.ChainID(), MsgVotePrepare, qc.ViewID, qc.LeaderID) {
		return fmt.Errorf("%w: standalone aggregate vote signature invalid", ErrInvalidPrepareQC)
	}
	if hsm.requiresMessageAuth() {
		resolver, ok := hsm.app.(FHSLeaderKeyApplication)
		if !ok {
			return ErrInvalidReplica
		}
		leaderKey, err := resolver.FHSLeaderPublicKey(ref.KeyHash, ref.LeaderID)
		if err != nil {
			return err
		}
		if err := hsm.verifyMessageAuth(m, ref.LeaderID, leaderKey); err != nil {
			return err
		}
	}
	if err := hsm.certifyFHSQC(qc, m); err != nil {
		return err
	}
	log.Info("HOTSTUFF STANDALONE PREPARE QC VERIFIED",
		"number", m.Number,
		"viewID", m.ViewId,
		"from", m.Id,
		"maskBytes", len(m.DataC))
	return nil
}

// for replica
func (hsm *HotstuffProtocolManager) handleDecideMsg(m *HotstuffMessage) error {
	if hsm.app.UseFHS2Chain() {
		log.Warn("reject MsgDecide in FHS 2-chain mode", "number", m.Number, "viewID", m.ViewId, "from", m.Id)
		return ErrViewPhaseNotMatch
	}
	start := time.Now()
	v, exist := hsm.views[m.ViewId]
	if !exist {
		//log.Debug("handleDecideMsg found no match view", "viewId", m.ViewId)
		return ErrMissingView
		//return ErrUnhandledMsg
	}
	if m.Number != v.number {
		return ErrViewIdNotMatch
	}
	if hsm.requiresMessageAuth() {
		decideView := bftview.DecodeToView(v.currentState)
		if decideView == nil || decideView.LeaderIndex >= uint(len(v.groupPublicKey)) {
			return ErrInvalidLeaderView
		}
		if err := hsm.verifyMessageAuth(m, v.leaderId, v.groupPublicKey[decideView.LeaderIndex]); err != nil {
			return err
		}
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
	case m.Code == MsgTimeout:
		if !hsm.usesFHSProtocolV2() {
			return ErrInvalidLeaderView
		}
		return hsm.handleTimeoutMsg(m)
	case m.Code == MsgTimeoutQC:
		if !hsm.usesFHSProtocolV2() {
			return ErrInvalidLeaderView
		}
		return hsm.handleTimeoutQCMsg(m)
	//empty message
	case m.Code == MsgStartNewView:
		log.Debug("handler handleStartNewView")
		return hsm.NewView()
	case m.Code == MsgTryPropose:
		log.Debug("handler MsgTryPropose")
		return hsm.TryPropose()
	case m.Code == MsgLocalTimeout:
		return hsm.LocalTimeout()

	default:
		log.Warn("unknown hotstuff message", "code", m.Code)
		return nil
	}
}

func (hsm *HotstuffProtocolManager) addToUnhandled(m *HotstuffMessage) {
	if m == nil || m.Code != MsgQCBroadcast {
		return
	}
	current := hsm.app.CurrentN()
	if m.Number < current || m.Number > current+maxUnhandledFutureViews {
		return
	}
	if hsm.requiresMessageAuth() {
		state, _, _ := hsm.app.CurrentState()
		view := bftview.DecodeToView(state)
		if view == nil {
			return
		}
		committee := bftview.LoadMember(view.KeyNumber, view.KeyHash, true)
		keys, err := hsm.app.GetPublicKey(view.KeyHash)
		if err != nil || committee == nil || len(keys) != len(committee.List) {
			return
		}
		index := -1
		for i := range committee.List {
			if committee.List[i] != nil && bftview.GetNodeID(committee.List[i].Address, committee.List[i].Public) == m.Id {
				index = i
				break
			}
		}
		if index < 0 || hsm.verifyMessageAuth(m, m.Id, keys[index]) != nil {
			return
		}
	}
	bs, err := rlp.EncodeToBytes(m)
	if err != nil || len(bs) > maxHotstuffControlBytes {
		log.Warn("failed to encode hotstuff message to bytes, discarded")
		return
	}
	now := time.Now()
	for key, pending := range hsm.unhandledMsg {
		if pending == nil || (!pending.ReceivedAt.IsZero() && now.Sub(pending.ReceivedAt) > pendingMessageTTL) || pending.Number < current {
			hsm.removeUnhandled(key, pending)
		}
	}
	perSender := 0
	for _, pending := range hsm.unhandledMsg {
		if pending != nil && pending.Id == m.Id {
			perSender++
		}
	}
	if perSender >= maxUnhandledPerSender {
		return
	}
	if len(hsm.unhandledMsg) >= maxUnhandledMessages || hsm.unhandledBytes+len(bs) > maxUnhandledBytes {
		if m.Code != MsgQCBroadcast || !hsm.evictUnhandledNonQC() {
			log.Warn("drop unhandled hotstuff message; queue limit reached", "count", len(hsm.unhandledMsg), "bytes", hsm.unhandledBytes)
			return
		}
	}
	canonical := *m
	canonical.ReceivedAt = time.Time{}
	canonicalBytes, err := rlp.EncodeToBytes(&canonical)
	if err != nil {
		return
	}
	k := hotstuffDigestHash(canonicalBytes)
	if _, exists := hsm.unhandledMsg[k]; exists {
		return
	}
	m.ReceivedAt = now
	hsm.unhandledMsg[k] = m
	hsm.unhandledSize[k] = len(bs)
	hsm.unhandledBytes += len(bs)
}

func (hsm *HotstuffProtocolManager) removeUnhandled(key common.Hash, msg *HotstuffMessage) {
	if size := hsm.unhandledSize[key]; size > 0 {
		hsm.unhandledBytes -= size
		if hsm.unhandledBytes < 0 {
			hsm.unhandledBytes = 0
		}
	}
	delete(hsm.unhandledSize, key)
	delete(hsm.unhandledMsg, key)
}

func (hsm *HotstuffProtocolManager) evictUnhandledNonQC() bool {
	var oldestKey common.Hash
	var oldestMsg *HotstuffMessage
	for key, candidate := range hsm.unhandledMsg {
		if candidate == nil || candidate.Code == MsgQCBroadcast {
			continue
		}
		if oldestMsg == nil || candidate.ReceivedAt.Before(oldestMsg.ReceivedAt) {
			oldestKey, oldestMsg = key, candidate
		}
	}
	if oldestMsg == nil {
		return false
	}
	hsm.removeUnhandled(oldestKey, oldestMsg)
	return true
}

func (hsm *HotstuffProtocolManager) HandleMessage(msg *HotstuffMessage) error {
	if msg == nil {
		return fmt.Errorf("nil hotstuff message")
	}
	// A reset scheduled outside the event loop (for example WAL recovery or
	// proof-aware full sync) must take effect before this message is evaluated.
	hsm.applyScheduledFHSEpochReset()
	if IsHotstuffWireCode(msg.Code) {
		if err := ValidateHotstuffWireMessage(msg); err != nil {
			return err
		}
	}
	if msg.Code != MsgTimer {
		log.Debug("HandleMessage", "Number", msg.Number, "viewId", msg.ViewId, "code", ReadableMsgType(msg.Code), "from", msg.Id)
	}
	err := hsm.handleMessage(msg)
	// An application callback may have committed a key epoch while handling the
	// message. Finish that stack frame, then discard every old-epoch recovery
	// object before replaying unhandled messages.
	if hsm.applyScheduledFHSEpochReset() {
		return err
	}
	if err == ErrUnhandledMsg {
		log.Debug("Add unhandled hotstuff message", "viewId", msg.ViewId, "code", msg.Code, "from", msg.Id)
		//fmt.Println("Add unhandled hotstuff message", "viewId", msg.ViewId, "code", msg.Code, "from", msg.Id)
		hsm.addToUnhandled(msg)
		return ErrUnhandledMsg
	}

	for k, m := range hsm.unhandledMsg {
		if m == nil || m.ViewId != msg.ViewId {
			continue
		}
		if e := hsm.handleMessage(m); e != ErrUnhandledMsg {
			log.Debug("Remove unhandled hotstuff message", "viewId", msg.ViewId, "code", msg.Code, "from", msg.Id)
			hsm.removeUnhandled(k, m)
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
			if recovery, ok := hsm.app.(ProposalRecoveryApplication); ok && !recovery.ProposalRecoveryReady(v.number, v.hash, v.leaderId) {
				// Avoid checking the same dormant input on every control-loop tick.
				// Work-producing events bypass this recovery path and wake immediately.
				v.lastLeaderRecoveryAt = now
				continue
			}
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
			qcMsg, err := hsm.broadcastPrepareQC(v)
			if err != nil {
				log.Warn("persist/broadcast PrepareQC failed", "number", v.number, "err", err)
				continue
			}
			if hsm.app.UseFHS2Chain() {
				v.phaseAsLeader = PhaseFinal
				if qcMsg != nil {
					v.leaderMsg[MsgQCBroadcast] = qcMsg
				}
				hsm.cacheFinalizedRecovery(v, nil)
				continue
			}
			msg := hsm.createSignatureMsg(v, MsgDecide, "prepare")
			if msg == nil {
				continue
			}
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
	if hsm.app.UseFHS2Chain() && msgCode == MsgVotePrepare {
		baseDigest := hotstuffContextDigest(hsm.app.ChainID(), msgCode, viewID, leaderID, data)
		digest, err := fhsSignerDigest(baseDigest, hsm.publicKey)
		if err != nil {
			log.Error("failed to build FHS signer digest", "err", err)
			return nil
		}
		signature := hsm.secretKey.SignHash(digest)
		if signature == nil {
			return nil
		}
		return signature.Serialize()
	}
	if hsm.app.UseContextSignatures() {
		return hsm.SignHashWithContext(msgCode, viewID, leaderID, data)
	}
	return hsm.SignHash(data)
}

func (hsm *HotstuffProtocolManager) verifyVoteSignature(sig bls.Sign, pub *bls.PublicKey, msgCode uint32, viewID common.Hash, leaderID string, data []byte) bool {
	if hsm.app.UseFHS2Chain() && msgCode == MsgVotePrepare {
		baseDigest := hotstuffContextDigest(hsm.app.ChainID(), msgCode, viewID, leaderID, data)
		digest, err := fhsSignerDigest(baseDigest, pub)
		return err == nil && sig.VerifyHash(pub, digest)
	}
	if hsm.app.UseContextSignatures() {
		return sig.VerifyHash(pub, hotstuffContextDigest(hsm.app.ChainID(), msgCode, viewID, leaderID, data))
	}
	return sig.VerifyHash(pub, hotstuffDigest(data))
}

func (hsm *HotstuffProtocolManager) verifyAggregatedSignature(bSign []byte, bMask []byte, msgCode uint32, viewID common.Hash, leaderID string, data []byte, groupPublicKey []*bls.PublicKey, threshold int) bool {
	if hsm.app.UseFHS2Chain() && msgCode == MsgVotePrepare {
		return VerifyFHSSignatureWithContext(bSign, bMask, data, groupPublicKey, threshold, hsm.app.ChainID(), msgCode, viewID, leaderID)
	}
	if hsm.app.UseContextSignatures() {
		return VerifySignatureWithContext(bSign, bMask, data, groupPublicKey, threshold, hsm.app.ChainID(), msgCode, viewID, leaderID)
	}
	return VerifySignature(bSign, bMask, data, groupPublicKey, threshold)
}
