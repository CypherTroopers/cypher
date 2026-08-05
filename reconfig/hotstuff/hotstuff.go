package hotstuff

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"bytes"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
)

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

// retryableMessageError marks an error that should keep the message in the
// pending queue. HandleMessage unwraps it before returning, so callers still
// receive the original application or transport error.
type retryableMessageError struct {
	err error
}

func (e *retryableMessageError) Error() string { return e.err.Error() }
func (e *retryableMessageError) Unwrap() error { return e.err }

func retryMessage(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := err.(*retryableMessageError); ok {
		return err
	}
	return &retryableMessageError{err: err}
}

func retryableCause(err error) (error, bool) {
	retryErr, ok := err.(*retryableMessageError)
	if !ok {
		return err, false
	}
	return retryErr.err, true
}

// isRecoverableApplicationError identifies application failures that can be
// resolved by starting the service or importing the missing ancestor. Some
// legacy application paths wrap these errors without %w, so retain the string
// checks until those callers all preserve the original error.
func isRecoverableApplicationError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrFutureState) ||
		errors.Is(err, types.ErrNotRunning) ||
		errors.Is(err, consensus.ErrUnknownAncestor) ||
		errors.Is(err, consensus.ErrPrunedAncestor) ||
		errors.Is(err, consensus.ErrFutureBlock) ||
		errors.Is(err, types.ErrUnknownAncestor) ||
		errors.Is(err, types.ErrPrunedAncestor) ||
		errors.Is(err, types.ErrFutureBlock) {
		return true
	}

	message := strings.ToLower(err.Error())
	return strings.Contains(message, types.ErrNotRunning.Error()) ||
		strings.Contains(message, types.ErrUnknownAncestor.Error()) ||
		strings.Contains(message, types.ErrPrunedAncestor.Error()) ||
		strings.Contains(message, types.ErrFutureBlock.Error())
}

func broadcastError(errs []error) error {
	var first error
	for _, err := range errs {
		if err == nil {
			// Broadcast is best-effort. A nil entry means at least one peer
			// accepted the message; lagging peers can recover through the
			// phase-specific unicast paths below.
			return nil
		}
		if first == nil {
			first = err
		}
	}
	return first
}

const (
	// A node that is one canonical block behind can receive the Decide for the
	// missing block and the NewView/Prepare for the following block. A window
	// of two therefore preserves the recovery path without buffering arbitrary
	// future heights.
	pendingFutureNumberWindow uint64 = 2
	maxPendingMessages               = 1024
	maxPendingPerSender              = 64
	pendingMessageTTL                = 5 * time.Minute
	pendingPruneInterval             = time.Second
	pendingRetryInterval             = time.Second
	// A finalized cache is independent of hsm.views because lockView removes
	// protocol views as later rounds are locked. Retain a small height window so
	// one-block-behind replicas can still request the decided proposal without
	// keeping arbitrary block payloads in memory.
	finalizedRecoveryNumberWindow uint64 = 2
	maxFinalizedRecoveryViews            = 4
)

const (
	MsgNewView = iota
	MsgPrepare
	MsgVotePrepare
	MsgPreCommit
	MsgVotePreCommit
	MsgCommit
	MsgVoteCommit
	MsgDecide

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
	State []byte
	Sign  []byte
	Mask  []byte
}

type HotStuffApplication interface {
	Self() string
	Write(string, *HotstuffMessage) error
	Broadcast(*HotstuffMessage) []error

	GetPublicKey() []*bls.PublicKey
	// ReplicaID resolves a committee public key to the transport identifier used
	// by Write. It binds signed recovery requests to their actual destination.
	ReplicaID(publicKey *bls.PublicKey) string

	OnNewView(currentState []byte, extra [][]byte) error
	// OnPropose receives the view state whose high QC was authenticated by the
	// Prepare handler. Applications must use prepareView, rather than mutable
	// local pacemaker state, for proposal checks that depend on the view.
	OnPropose(state []byte, extra []byte, prepareView []byte) error
	OnViewDone(tSign *SignedState) error

	CheckView(currentState []byte) error
	Propose() (e error, kState []byte, tState []byte, extra []byte)
	CurrentState() ([]byte, string, uint64)
	CurrentN() uint64
	GetExtra() []byte // only for new-view procedure
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

	ReceivedAt time.Time
}

type View struct {
	hash           common.Hash // hash on "currentState + leaderId", hence should be unique and equal for the same view and leader
	createdAt      time.Time
	number         uint64
	leaderId       string
	phaseAsLeader  uint32
	phaseAsReplica uint32
	currentState   []byte
	proposedKState []byte
	proposedTState []byte

	highVoteInfo      []*VoteInfo
	prepareVoteInfo   []*VoteInfo
	preCommitVoteInfo []*VoteInfo
	commitVoteInfo    []*VoteInfo
	qc                map[string]*QC
	leaderMsg         map[uint64]*HotstuffMessage // record messages from leader to replica: MsgPrepare, MsgPreCommit, MsgCommit, MsgDecide

	groupPublicKey []*bls.PublicKey
	threshold      int
	cmLen          int

	extra [][]byte

	futureNewViewMsg []*HotstuffMessage

	waitingMoreVoteInfo   bool
	waitingMoreVoteInfoAt time.Time
	lastBroadcastAttempt  time.Time
}

type finalizedRecoveryView struct {
	number         uint64
	leaderID       string
	currentState   []byte
	groupPublicKey []*bls.PublicKey
	memberIDs      []string
	prepare        *HotstuffMessage
	decide         *HotstuffMessage
	cachedAt       time.Time
	lastReplay     map[string]time.Time
}

func (v *View) hasKState() bool {
	return v.proposedKState != nil && len(v.proposedKState) > 0
}

func (v *View) hasTState() bool {
	return v.proposedTState != nil && len(v.proposedTState) > 0
}

type HotstuffProtocolManager struct {
	mu               sync.Mutex
	secretKey        *bls.SecretKey
	publicKey        *bls.PublicKey
	views            map[common.Hash]*View
	leaderView       *View
	app              HotStuffApplication
	unhandledMsg     map[common.Hash]*HotstuffMessage // messages which is not handled(which phase is ahead of local's)
	pendingBySender  map[common.Hash]int
	finalizedViews   map[common.Hash]*finalizedRecoveryView
	lastPendingPrune time.Time
	lastPendingRetry time.Time
}

func NewHotstuffProtocolManager(a HotStuffApplication, secretKey *bls.SecretKey, publicKey *bls.PublicKey) *HotstuffProtocolManager {
	manager := &HotstuffProtocolManager{
		secretKey:       secretKey,
		publicKey:       publicKey,
		app:             a,
		views:           make(map[common.Hash]*View),
		unhandledMsg:    make(map[common.Hash]*HotstuffMessage),
		pendingBySender: make(map[common.Hash]int),
		finalizedViews:  make(map[common.Hash]*finalizedRecoveryView),
	}
	return manager
}

func CalcThreshold(size int) int {
	return (size + 1) * 2 / 3
}

func (hsm *HotstuffProtocolManager) UpdateKeyPair(sec *bls.SecretKey) {
	hsm.mu.Lock()
	defer hsm.mu.Unlock()

	hsm.secretKey = sec
	hsm.publicKey = sec.GetPublicKey()
}

func (v *View) lookupReplica(pubKey *bls.PublicKey) int {
	for i, p := range v.groupPublicKey {
		if p.IsEqual(pubKey) {
			return i
		}
	}
	/*??
	log.Debug("lookupReplica miss replica's public key", "key", hex.EncodeToString(pubKey.Serialize()))

	log.Debug("lookupReplica start dumping committee members' public key ====================")
	for i, p := range v.groupPublicKey {
		log.Debug("Public Key", "index", i, "key", hex.EncodeToString(p.Serialize()))
	}
	log.Debug("lookupReplica finish dumping committee members' public key ====================")
	*/
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

func (hsm *HotstuffProtocolManager) newView() (*View, []byte) {
	currentState, leaderId, number := hsm.app.CurrentState()
	if leaderId == "" {
		return nil, nil
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
		extra:             make([][]byte, 0),
		futureNewViewMsg:  make([]*HotstuffMessage, 0),
		createdAt:         time.Now(),
	}

	v.currentState = make([]byte, len(currentState))
	copy(v.currentState, currentState)

	v.hash = crypto.Keccak256Hash([]byte(v.leaderId), v.currentState)

	groupPublicKey := hsm.app.GetPublicKey()
	v.groupPublicKey = make([]*bls.PublicKey, 0)
	for _, p := range groupPublicKey {
		v.groupPublicKey = append(v.groupPublicKey, p)
	}
	v.cmLen = len(groupPublicKey)
	v.threshold = CalcThreshold(v.cmLen)

	return v, hsm.app.GetExtra()
}

func (hsm *HotstuffProtocolManager) createView(asLeader bool, phase uint32, leaderId string, currentState []byte, number uint64) *View {
	v := &View{
		number:            number,
		leaderId:          leaderId,
		highVoteInfo:      make([]*VoteInfo, 0),
		prepareVoteInfo:   make([]*VoteInfo, 0),
		preCommitVoteInfo: make([]*VoteInfo, 0),
		commitVoteInfo:    make([]*VoteInfo, 0),
		qc:                make(map[string]*QC),
		leaderMsg:         make(map[uint64]*HotstuffMessage),
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

	v.hash = crypto.Keccak256Hash([]byte(v.leaderId), v.currentState)

	groupPublicKey := hsm.app.GetPublicKey()
	v.groupPublicKey = make([]*bls.PublicKey, 0)
	for _, p := range groupPublicKey {
		v.groupPublicKey = append(v.groupPublicKey, p)
	}
	v.cmLen = len(groupPublicKey)
	v.threshold = CalcThreshold(v.cmLen)

	return v
}

func (hsm *HotstuffProtocolManager) updateViewPublicKey(v *View) {
	groupPublicKey := hsm.app.GetPublicKey()
	v.groupPublicKey = make([]*bls.PublicKey, 0)
	for _, p := range groupPublicKey {
		v.groupPublicKey = append(v.groupPublicKey, p)
	}
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
		if appErr := hsm.app.OnViewDone(nil); appErr != nil {
			return appErr
		}
		return e
	}

	var tSignedState *SignedState
	if v.hasTState() {
		tSignedState = &SignedState{
			State: v.proposedTState,
			Sign:  tSign,
			Mask:  mask,
		}
	}

	if err := hsm.app.OnViewDone(tSignedState); err != nil {
		log.Warn("application failed to finish view", "error", err, "ViewId", v.hash)
		return err
	}

	elapsed := time.Now().Sub(v.createdAt).Nanoseconds() / 1000000
	log.Debug("view finished successfully", "ViewId", v.hash, "timeElapsed", elapsed)
	return nil
}

func (hsm *HotstuffProtocolManager) clearTimeoutView(curN uint64) error {
	now := time.Now()
	for _, v := range hsm.views {
		if v.number < curN {
			log.Debug("Remove timeout view", "viewId", v.hash, "phase", readablePhase(v.phaseAsReplica), "pas time", now.Sub(v.createdAt).Seconds())
			if v.phaseAsReplica < PhaseFinal {
				hsm.viewDone(v, nil, nil, nil, ErrViewTimeout)
			}
			delete(hsm.views, v.hash)
		}
	}

	for k, m := range hsm.unhandledMsg {
		if m.Number < curN && !hsm.isFinalizedRecoveryRequest(m, curN) {
			log.Debug("Remove unhandled hotstuff message", "viewId", m.ViewId, "code", m.Code, "from", m.Id, "past time", now.Sub(m.ReceivedAt).Seconds())
			hsm.removePending(k)
		}
	}

	return nil
}

// for replica
func (hsm *HotstuffProtocolManager) NewView() error {
	v, extra := hsm.newView()
	if v == nil {
		return ErrNewViewFail
	}

	if _, exist := hsm.views[v.hash]; !exist {
		hsm.views[v.hash] = v
	}

	sig := hsm.SignHash(v.currentState)
	msg := hsm.newMsg(MsgNewView, v.number, v.hash, v.currentState, sig, extra)

	log.Debug("New View", "leader", v.leaderId, "ViewID", common.HexString(v.hash[:]))
	err := hsm.app.Write(v.leaderId, msg)
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

// validateNewViewVote authenticates the state and sender of a NewView against
// an already-created view. In particular, this check does not consult the
// application's canonical height, so it is safe to use for a replica that is
// asking the leader to replay a view the leader has already decided.
func (hsm *HotstuffProtocolManager) validateNewViewVote(v *View, msg *HotstuffMessage) (*VoteInfo, error) {
	if v == nil || msg.Id == "" || v.leaderId != hsm.app.Self() ||
		v.number != msg.Number || v.hash != msg.ViewId ||
		!bytes.Equal(v.currentState, msg.DataA) ||
		msg.ViewId != crypto.Keccak256Hash([]byte(hsm.app.Self()), msg.DataA) {
		return nil, ErrViewIdNotMatch
	}

	err, vote := v.msgToVoteInfo(msg)
	if err != nil {
		return nil, err
	}
	if !vote.ValidKSign || !vote.KSign.VerifyHash(vote.PubKey, crypto.Keccak256(msg.DataA)) {
		return nil, ErrQCVerification
	}
	if memberID := hsm.app.ReplicaID(vote.PubKey); memberID == "" || memberID != msg.Id {
		return nil, ErrInvalidReplica
	}
	return vote, nil
}

func finalizedRecoveryTooOld(number, current uint64) bool {
	return current > number && current-number > finalizedRecoveryNumberWindow
}

func (hsm *HotstuffProtocolManager) pruneFinalizedViews(current uint64) {
	for viewID, cached := range hsm.finalizedViews {
		if cached == nil || finalizedRecoveryTooOld(cached.number, current) {
			delete(hsm.finalizedViews, viewID)
		}
	}
	for len(hsm.finalizedViews) > maxFinalizedRecoveryViews {
		hsm.evictOldestFinalizedView()
	}
}

func (hsm *HotstuffProtocolManager) evictOldestFinalizedView() {
	var (
		oldestID common.Hash
		oldest   *finalizedRecoveryView
	)
	for viewID, cached := range hsm.finalizedViews {
		if oldest == nil || cached.number < oldest.number ||
			(cached.number == oldest.number && cached.cachedAt.Before(oldest.cachedAt)) {
			oldestID, oldest = viewID, cached
		}
	}
	if oldest != nil {
		delete(hsm.finalizedViews, oldestID)
	}
}

// cacheFinalizedView snapshots everything required to recover a replica after
// lockView removes the active protocol view. The proposal messages and the
// committee identity mapping are cloned before the application inserts a
// KeyBlock and potentially changes the current committee.
func (hsm *HotstuffProtocolManager) cacheFinalizedView(v *View, decideMsg *HotstuffMessage) bool {
	if v == nil || decideMsg == nil || v.leaderId != hsm.app.Self() {
		return false
	}
	prepareMsg := v.leaderMsg[MsgPrepare]
	if prepareMsg == nil || prepareMsg.Code != MsgPrepare || decideMsg.Code != MsgDecide ||
		prepareMsg.ViewId != v.hash || decideMsg.ViewId != v.hash ||
		prepareMsg.Number != v.number || decideMsg.Number != v.number {
		return false
	}
	if hsm.finalizedViews == nil {
		hsm.finalizedViews = make(map[common.Hash]*finalizedRecoveryView)
	}
	if _, exists := hsm.finalizedViews[v.hash]; exists {
		return true
	}

	publicKeys := make([]*bls.PublicKey, 0, len(v.groupPublicKey))
	memberIDs := make([]string, 0, len(v.groupPublicKey))
	for _, publicKey := range v.groupPublicKey {
		if publicKey == nil {
			return false
		}
		cloned := bls.GetPublicKey(publicKey.Serialize())
		if cloned == nil {
			return false
		}
		memberID := hsm.app.ReplicaID(publicKey)
		if memberID == "" {
			return false
		}
		publicKeys = append(publicKeys, cloned)
		memberIDs = append(memberIDs, memberID)
	}
	if len(publicKeys) == 0 {
		return false
	}

	hsm.pruneFinalizedViews(v.number)
	if len(hsm.finalizedViews) >= maxFinalizedRecoveryViews {
		hsm.evictOldestFinalizedView()
	}
	hsm.finalizedViews[v.hash] = &finalizedRecoveryView{
		number:         v.number,
		leaderID:       v.leaderId,
		currentState:   common.CopyBytes(v.currentState),
		groupPublicKey: publicKeys,
		memberIDs:      memberIDs,
		prepare:        cloneHotstuffMessage(prepareMsg),
		decide:         cloneHotstuffMessage(decideMsg),
		cachedAt:       time.Now(),
		lastReplay:     make(map[string]time.Time),
	}
	return true
}

func validateFinalizedNewView(viewID common.Hash, cached *finalizedRecoveryView, msg *HotstuffMessage) error {
	if cached == nil || msg == nil || msg.Id == "" || cached.leaderID == "" ||
		cached.number != msg.Number || viewID != msg.ViewId ||
		!bytes.Equal(cached.currentState, msg.DataA) ||
		msg.ViewId != crypto.Keccak256Hash([]byte(cached.leaderID), msg.DataA) {
		return ErrViewIdNotMatch
	}
	publicKey := bls.GetPublicKey(msg.PubKey)
	if publicKey == nil {
		return ErrInvalidPublicKey
	}
	memberIndex := -1
	for index, member := range cached.groupPublicKey {
		if member != nil && member.IsEqual(publicKey) {
			memberIndex = index
			break
		}
	}
	if memberIndex < 0 || memberIndex >= len(cached.memberIDs) || cached.memberIDs[memberIndex] != msg.Id {
		return ErrInvalidReplica
	}
	var signature bls.Sign
	if err := signature.Deserialize(msg.DataB); err != nil {
		return ErrInvalidVoteInfoMessage
	}
	if !signature.VerifyHash(publicKey, crypto.Keccak256(msg.DataA)) {
		return ErrQCVerification
	}
	return nil
}

// recoverLateReplica services a signed NewView from the bounded finalized
// cache before CheckView can reject it as OldState. Prepare is sent first so a
// replica can reconstruct the proposal; its pending queue handles an
// independently delivered Decide.
func (hsm *HotstuffProtocolManager) recoverLateReplica(msg *HotstuffMessage) (bool, error) {
	hsm.pruneFinalizedViews(hsm.app.CurrentN())
	cached := hsm.finalizedViews[msg.ViewId]
	if cached == nil {
		return false, nil
	}
	if err := validateFinalizedNewView(msg.ViewId, cached, msg); err != nil {
		return true, err
	}
	if last := cached.lastReplay[msg.Id]; !last.IsZero() && time.Since(last) < pendingRetryInterval {
		return true, nil
	}

	log.Info("recover late replica from decided view", "replicaId", msg.Id, "viewId", msg.ViewId)
	if err := hsm.app.Write(msg.Id, cloneHotstuffMessage(cached.prepare)); err != nil {
		return true, retryMessage(err)
	}
	if err := hsm.app.Write(msg.Id, cloneHotstuffMessage(cached.decide)); err != nil {
		return true, retryMessage(err)
	}
	cached.lastReplay[msg.Id] = time.Now()
	return true, nil
}

// for leader
func (hsm *HotstuffProtocolManager) handleNewViewMsg(msg *HotstuffMessage) error {
	log.Info("handleNewViewMsg got new view message", "from", msg.Id, "viewId", msg.ViewId)
	// A decided leader is necessarily ahead of a replica that still reports the
	// preceding state. Authenticate that request against the cached view and
	// replay the certificate before the application's strict height comparison
	// can classify it as ErrOldState.
	if recovered, err := hsm.recoverLateReplica(msg); recovered {
		return err
	}

	err := hsm.app.CheckView(msg.DataA)
	if err != nil {
		if errors.Is(err, ErrOldState) {
			log.Warn("check new view failed, discard", "viewID", msg.ViewId)
			return err
		}
		if isRecoverableApplicationError(err) {
			log.Warn("new view is not ready locally", "viewID", msg.ViewId, "error", err)
			return retryMessage(err)
		}
		return err
	}

	v, exist := hsm.views[msg.ViewId]
	if !exist {
		v = hsm.createView(true, PhasePrepare, hsm.app.Self(), msg.DataA, msg.Number)
		if v.hash != msg.ViewId {
			log.Debug("handleNewViewMsg got new-view message with un-matched view id", "from", msg.Id, "viewId", msg.ViewId)
			return ErrViewIdNotMatch
		}
		log.Debug("create new view", "leader", v.leaderId, "viewID", v.hash)
		hsm.views[v.hash] = v
	}

	// OnNewView may already have succeeded while Propose or the Prepare
	// broadcast failed. In that case retry the staged proposal instead of
	// collecting or proposing a different value.
	if v.phaseAsLeader == PhaseTryPropose {
		hsm.leaderView = v
		return hsm.TryPropose()
	}

	hsm.updateViewPublicKey(v)
	qrum, err := hsm.validateNewViewVote(v, msg)
	if err != nil {
		log.Debug("New view message failed authentication", "error", err)
		return err
	}

	if v.phaseAsLeader != PhasePrepare {
		// this happens when leader receives more new-view messages than (2f + 1) threshold
		// the leader should write the Prepare message to these late replica too
		if prepareMsg, ok := v.leaderMsg[MsgPrepare]; ok {
			log.Debug("handleNewViewMsg load prepare message and send to replica", "replicaId", msg.Id)
			if err := hsm.app.Write(msg.Id, prepareMsg); err != nil {
				return retryMessage(err)
			}
		}
		return nil
	}

	if hsm.lookupVoteInfo(qrum.PubKey, v.highVoteInfo) {
		log.Warn("receive dup new-view meesage", "from", msg.Id, "viewId", msg.ViewId)
	} else {
		v.highVoteInfo = append(v.highVoteInfo, qrum)
		if len(v.currentState) != len(msg.DataA) {
			v.currentState = make([]byte, len(msg.DataA))
			copy(v.currentState, msg.DataA)
		}

		if len(msg.DataC) > 0 {
			extra := make([]byte, len(msg.DataC))
			copy(extra, msg.DataC)
			v.extra = append(v.extra, extra)
		}
	}

	threshold := v.threshold + 1
	if threshold > len(v.groupPublicKey) {
		threshold = len(v.groupPublicKey)
	}

	if len(v.highVoteInfo) < threshold {
		log.Info("handleNewViewMsg need more voteInfo", "threshold", v.threshold, "current", len(v.highVoteInfo))
		return ErrInsufficientQC
	}

	hsm.leaderView = v
	elapsed := time.Now().Sub(v.createdAt).Nanoseconds() / 1000000

	log.Debug("on new view", "ViewId", v.hash, "timeElapsed", elapsed)

	// notify app the new view only when leader has (n - f) votes
	if err := hsm.app.OnNewView(v.currentState, v.extra); err != nil {
		log.Debug("New view message failed verification", "error", err)
		if isRecoverableApplicationError(err) {
			return retryMessage(err)
		}
		return err
	}

	hsm.lockView(v)
	v.phaseAsLeader = PhaseTryPropose

	return hsm.TryPropose()
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
	if msg, ok := v.leaderMsg[MsgPrepare]; ok {
		return hsm.broadcastPrepare(v, msg)
	}

	err, kProposal, tProposal, extra := hsm.app.Propose()
	if err != nil {
		log.Warn("hotstuff application failed to propose")
		if isRecoverableApplicationError(err) {
			return retryMessage(err)
		}
		return err
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

	v.leaderMsg[MsgPrepare] = msg

	if kProposal != nil && len(kProposal) > 0 {
		v.proposedKState = make([]byte, len(kProposal))
		copy(v.proposedKState, kProposal)
	}

	if tProposal != nil && len(tProposal) > 0 {
		v.proposedTState = make([]byte, len(tProposal))
		copy(v.proposedTState, tProposal)
	}

	return hsm.broadcastPrepare(v, msg)
}

func (hsm *HotstuffProtocolManager) broadcastPrepare(v *View, msg *HotstuffMessage) error {
	log.Debug("view broadcast Prepare msg", "viewID", v.hash)
	now := time.Now()
	v.lastBroadcastAttempt = now
	hsm.lastPendingRetry = now
	if err := broadcastError(hsm.app.Broadcast(msg)); err != nil {
		log.Warn("view failed to broadcast Prepare msg", "viewID", v.hash, "error", err)
		return retryMessage(err)
	}

	v.phaseAsLeader = PhasePreCommit
	hsm.leaderView = nil
	hsm.DumpView(v, true)
	return nil
}

func VerifySignature(bSign []byte, bMask []byte, data []byte, groupPublicKey []*bls.PublicKey, threshold int) bool {
	var sign bls.Sign
	if err := sign.Deserialize(bSign); err != nil {
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

	if signer < threshold || !sign.VerifyHash(&pub, crypto.Keccak256(data)) {
		log.Debug("Dump failed signature ================")
		log.Debug("signer", "is", signer, "threshold", threshold)
		log.Debug("Signature", "is ", hex.EncodeToString(bSign))
		log.Debug("Mask     ", "is ", hex.EncodeToString(bMask))
		log.Debug("Data     ", "is ", hex.EncodeToString(data))

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
	if len(m.DataE) == 0 {
		return ErrInvalidProposal
	}
	if err := hsm.app.CheckView(m.DataE); err != nil {
		if isRecoverableApplicationError(err) {
			log.Debug("handlePrepareMsg waits for local chain", "viewId", m.ViewId, "error", err)
			return retryMessage(err)
		}
		return err
	}

	v, exist := hsm.views[m.ViewId]
	if !exist {
		v = hsm.createView(false, PhasePrepare, m.Id, m.DataE, m.Number)
		if v.hash != m.ViewId {
			return ErrViewIdNotMatch
		}
		hsm.views[v.hash] = v
		log.Debug("handlePrepareMsg create view", "viewId", m.ViewId)
	}

	if v.phaseAsReplica != PhasePrepare {
		log.Trace("handlePrepareMsg discard old-phase message", "viewId", hex.EncodeToString(m.ViewId[:]), "phase", readablePhase(v.phaseAsReplica))
		//fmt.Println("handlePrepareMsg discard old-phase message", "viewId", hex.EncodeToString(m.ViewId[:]), "phase", readablePhase(v.phaseAsReplica))
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
	if !VerifySignature(m.DataC, m.DataD, m.DataE, v.groupPublicKey, v.threshold) {
		log.Debug("handlePrepareMsg failed to verify highQC", "viewId", m.ViewId)
		return ErrInvalidHighQC
	}

	// DataE is safe to use as the proposal's view only after the high QC above
	// has authenticated it.
	if err := hsm.app.OnPropose(state, extra, m.DataE); err != nil {
		log.Debug("handlePrepareMsg failed to verify proposed data", "viewId", m.ViewId)
		if isRecoverableApplicationError(err) {
			return retryMessage(err)
		}
		return ErrInvalidProposal
	}

	kSign := []byte(nil)
	tSign := []byte(nil)

	if m.DataA != nil && len(m.DataA) > 0 {
		v.proposedKState = make([]byte, len(m.DataA))
		copy(v.proposedKState, m.DataA)

		kSign = hsm.SignHash(v.proposedKState)
	}

	if m.DataB != nil && len(m.DataB) > 0 {
		v.proposedTState = make([]byte, len(m.DataB))
		copy(v.proposedTState, m.DataB)

		tSign = hsm.SignHash(v.proposedTState)
	}

	msg := hsm.newMsg(MsgVotePrepare, v.number, v.hash, nil, kSign, tSign)

	log.Debug("handlePrepareMsg send VotePrepare msg", "viewID", v.hash)
	if err := hsm.app.Write(m.Id, msg); err != nil {
		log.Warn("handlePrepareMsg failed to send VotePrepare msg", "viewID", v.hash, "error", err)
		return retryMessage(err)
	}
	hsm.lockView(v)
	v.phaseAsReplica = PhaseDecide

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

	if v.hasKState() {
		if !qrum.ValidKSign || !qrum.KSign.VerifyHash(qrum.PubKey, crypto.Keccak256(v.proposedKState)) {
			log.Debug("handlePrepareVoteMsg failed to verify k-state signature", "viewId", m.ViewId)
			return ErrQCVerification
		}
	}

	if v.hasTState() {
		if !qrum.ValidTSign || !qrum.TSign.VerifyHash(qrum.PubKey, crypto.Keccak256(v.proposedTState)) {
			log.Debug("handlePrepareVoteMsg failed to verify t-state signature", "viewId", m.ViewId)
			hsm.DumpView(v, true)
			return ErrQCVerification
		}
	}
	if decideMsg, ok := v.leaderMsg[MsgDecide]; ok {
		if v.phaseAsLeader != PhaseFinal {
			return hsm.broadcastDecide(v, decideMsg)
		}
		log.Debug("handlePrepareVoteMsg send Decide to late replica", "replicaId", m.Id, "viewId", v.hash)
		if err := hsm.app.Write(m.Id, decideMsg); err != nil {
			return retryMessage(err)
		}
		return nil
	}

	if v.phaseAsLeader != PhasePreCommit {
		log.Trace("handlePrepareVoteMsg view phase not match", "viewID", hex.EncodeToString(v.hash[:]), "phase", readablePhase(v.phaseAsLeader), "shouldBe", readablePhase(PhasePreCommit))

		if preCommitMsg, ok := v.leaderMsg[MsgPreCommit]; ok {
			log.Debug("handlePrepareVoteMsg load PreCommit message and send to replica", "replicaId", m.Id)
			hsm.app.Write(m.Id, preCommitMsg)

			return nil
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
		log.Warn("discard dup prepare-vote message", "from", m.Id, "viewId", m.ViewId)
		return nil
	}

	v.prepareVoteInfo = append(v.prepareVoteInfo, qrum)
	if len(v.prepareVoteInfo) < v.threshold {
		log.Debug("handlePrepareVoteMsg need more voteInfo", "number", v.number, "threshold", v.threshold, "current", len(v.prepareVoteInfo))
		return ErrInsufficientQC
	}

	isTimeout := false
	if v.waitingMoreVoteInfo {
		elapsed := time.Now().Sub(v.waitingMoreVoteInfoAt)
		log.Debug("@@@handlePrepareVoteMsg collect sufficient votes", "viewId", m.ViewId, "number", v.number, "elapsed(s)", elapsed)
		if elapsed >= params.CollectVoteInfoTimeout {
			isTimeout = true
		}
	}

	if !isTimeout && len(v.prepareVoteInfo) < v.cmLen-1 {
		if !v.waitingMoreVoteInfo {
			v.waitingMoreVoteInfo = true
			v.waitingMoreVoteInfoAt = time.Now()
		}
		return nil
	}
	v.waitingMoreVoteInfo = false
	if err := hsm.aggregateQC(v, "prepare", v.prepareVoteInfo); err != nil {
		log.Debug("aggregate prepare voteInfo failed")
		return err
	}

	msg := hsm.createSignatureMsg(v, MsgDecide, "prepare")
	v.leaderMsg[MsgDecide] = msg

	return hsm.broadcastDecide(v, msg)
}

func (hsm *HotstuffProtocolManager) broadcastDecide(v *View, msg *HotstuffMessage) error {
	log.Debug("broadcast Decide msg", "viewId", v.hash, "number", v.number)
	if !hsm.cacheFinalizedView(v, msg) {
		log.Warn("unable to cache finalized view for late-replica recovery", "viewId", v.hash, "number", v.number)
	}
	now := time.Now()
	v.lastBroadcastAttempt = now
	hsm.lastPendingRetry = now
	if err := broadcastError(hsm.app.Broadcast(msg)); err != nil {
		log.Warn("failed to broadcast Decide msg", "viewId", v.hash, "number", v.number, "error", err)
		return retryMessage(err)
	}
	v.phaseAsLeader = PhaseFinal
	return nil
}

// for replica
func (hsm *HotstuffProtocolManager) handleDecideMsg(m *HotstuffMessage) error {
	v, exist := hsm.views[m.ViewId]
	if !exist {
		log.Debug("handleDecideMsg waits for matching Prepare", "viewId", m.ViewId)
		return retryMessage(ErrMissingView)
	}

	if v.phaseAsReplica < PhaseDecide {
		log.Debug("handleDecideMsg waits for Prepare", "viewId", hex.EncodeToString(m.ViewId[:]), "phase", readablePhase(v.phaseAsReplica))
		return retryMessage(ErrUnhandledMsg)
	}

	if v.phaseAsReplica > PhaseDecide {
		log.Trace("handleDecideMsg discard old phase message", "viewId", hex.EncodeToString(m.ViewId[:]), "phase", readablePhase(v.phaseAsReplica))
		return ErrViewOldPhase
	}

	if v.hasTState() {
		if !VerifySignature(m.DataB, m.DataC, v.proposedTState, v.groupPublicKey, v.threshold) {
			log.Debug("handleDecideMsg failed to verify aggregated t-state signature", "viewId", m.ViewId)
			hsm.DumpView(v, false)
			return ErrInvalidPrepareQC
		}
	}

	log.Debug("handleDecideMsg view done", "viewId", m.ViewId)

	// execute the command
	if err := hsm.viewDone(v, m.DataA, m.DataB, m.DataC, nil); err != nil {
		// Applying a valid Decide is idempotent. Keep it pending on every
		// application error so a stopped or catching-up node can retry it.
		return retryMessage(err)
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

func cloneHotstuffMessage(m *HotstuffMessage) *HotstuffMessage {
	clone := *m
	clone.PubKey = common.CopyBytes(m.PubKey)
	clone.DataA = common.CopyBytes(m.DataA)
	clone.DataB = common.CopyBytes(m.DataB)
	clone.DataC = common.CopyBytes(m.DataC)
	clone.DataD = common.CopyBytes(m.DataD)
	clone.DataE = common.CopyBytes(m.DataE)
	clone.DataF = common.CopyBytes(m.DataF)
	return &clone
}

func pendingMessageKey(m *HotstuffMessage) (common.Hash, error) {
	// ReceivedAt is queue metadata. The signed/QC payload remains part of the
	// identity: before Prepare arrives a Decide cannot be fully verified, and
	// an invalid earlier payload must not occupy the legitimate Decide's slot.
	identity := struct {
		Code   uint32
		Number uint64
		ViewId common.Hash
		Id     string
		PubKey []byte
		DataA  []byte
		DataB  []byte
		DataC  []byte
		DataD  []byte
		DataE  []byte
		DataF  []byte
	}{
		Code: m.Code, Number: m.Number, ViewId: m.ViewId, Id: m.Id, PubKey: m.PubKey,
		DataA: m.DataA, DataB: m.DataB, DataC: m.DataC,
		DataD: m.DataD, DataE: m.DataE, DataF: m.DataF,
	}
	bs, err := rlp.EncodeToBytes(&identity)
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash(bs), nil
}

func pendingSenderKey(m *HotstuffMessage) common.Hash {
	if len(m.PubKey) > 0 {
		return crypto.Keccak256Hash(m.PubKey)
	}
	return crypto.Keccak256Hash([]byte(m.Id))
}

func pendingNumberAllowed(m *HotstuffMessage, currentN uint64) bool {
	if m.Code > MsgDecide {
		return m.Code == MsgTryPropose
	}
	if m.Number < currentN {
		return false
	}
	return m.Number-currentN <= pendingFutureNumberWindow
}

func (hsm *HotstuffProtocolManager) isFinalizedRecoveryRequest(m *HotstuffMessage, currentN uint64) bool {
	if m == nil || m.Code != MsgNewView {
		return false
	}
	cached := hsm.finalizedViews[m.ViewId]
	return cached != nil && !finalizedRecoveryTooOld(cached.number, currentN) &&
		validateFinalizedNewView(m.ViewId, cached, m) == nil
}

func (hsm *HotstuffProtocolManager) pendingMessageAllowed(m *HotstuffMessage, currentN uint64) bool {
	return pendingNumberAllowed(m, currentN) || hsm.isFinalizedRecoveryRequest(m, currentN)
}

func pendingPublicKey(serialized []byte, group []*bls.PublicKey) *bls.PublicKey {
	if len(group) == 0 || len(serialized) == 0 {
		return nil
	}
	pubKey := bls.GetPublicKey(serialized)
	if pubKey == nil {
		return nil
	}
	for _, member := range group {
		if member != nil && member.IsEqual(pubKey) {
			return pubKey
		}
	}
	return nil
}

func verifyPendingSignature(signature []byte, state []byte, pubKey *bls.PublicKey) bool {
	if pubKey == nil || len(signature) == 0 {
		return false
	}
	var sign bls.Sign
	return sign.Deserialize(signature) == nil && sign.VerifyHash(pubKey, crypto.Keccak256(state))
}

// validPendingMessage performs checks that do not depend on importing the
// missing block. Full message validation still happens in handleMessage.
func (hsm *HotstuffProtocolManager) validPendingMessage(m *HotstuffMessage) bool {
	if m.Code == MsgTryPropose {
		return true
	}
	if m.Code > MsgDecide || m.Id == "" || m.ViewId == (common.Hash{}) {
		return false
	}
	if m.Code == MsgNewView {
		if cached := hsm.finalizedViews[m.ViewId]; cached != nil {
			return validateFinalizedNewView(m.ViewId, cached, m) == nil
		}
	}
	switch m.Code {
	case MsgNewView:
		if len(m.DataA) == 0 || len(m.DataB) == 0 ||
			m.ViewId != crypto.Keccak256Hash([]byte(hsm.app.Self()), m.DataA) {
			return false
		}
	case MsgPrepare:
		if len(m.DataE) == 0 || len(m.DataC) == 0 || len(m.DataD) == 0 ||
			m.ViewId != crypto.Keccak256Hash([]byte(m.Id), m.DataE) {
			return false
		}
	case MsgVotePrepare:
		if hsm.views[m.ViewId] == nil {
			return false
		}
	case MsgDecide:
		if v := hsm.views[m.ViewId]; v != nil && v.leaderId != "" && v.leaderId != m.Id {
			return false
		}
	default:
		return false
	}

	group := hsm.app.GetPublicKey()
	var sender *bls.PublicKey
	if len(group) > 0 {
		sender = pendingPublicKey(m.PubKey, group)
		if sender == nil {
			return false
		}
	}

	switch m.Code {
	case MsgNewView:
		return len(group) == 0 || verifyPendingSignature(m.DataB, m.DataA, sender)

	case MsgPrepare:
		return len(group) == 0 || VerifySignature(m.DataC, m.DataD, m.DataE, group, CalcThreshold(len(group)))

	case MsgVotePrepare:
		v := hsm.views[m.ViewId]
		if v == nil {
			return false
		}
		err, vote := v.msgToVoteInfo(m)
		if err != nil {
			return false
		}
		if v.hasKState() && (!vote.ValidKSign || !vote.KSign.VerifyHash(vote.PubKey, crypto.Keccak256(v.proposedKState))) {
			return false
		}
		if v.hasTState() && (!vote.ValidTSign || !vote.TSign.VerifyHash(vote.PubKey, crypto.Keccak256(v.proposedTState))) {
			return false
		}
		return true

	case MsgDecide:
		v := hsm.views[m.ViewId]
		if v == nil {
			// The Prepare may itself be pending, so its proposal is not yet
			// available for aggregate-signature verification.
			return true
		}
		if v.hasKState() && !VerifySignature(m.DataA, m.DataC, v.proposedKState, v.groupPublicKey, v.threshold) {
			return false
		}
		if v.hasTState() && !VerifySignature(m.DataB, m.DataC, v.proposedTState, v.groupPublicKey, v.threshold) {
			return false
		}
		return true
	}
	return false
}

func (hsm *HotstuffProtocolManager) prunePending(now time.Time, currentN uint64) {
	for key, msg := range hsm.unhandledMsg {
		finalizedRecovery := hsm.isFinalizedRecoveryRequest(msg, currentN)
		if !hsm.pendingMessageAllowed(msg, currentN) || msg.ReceivedAt.IsZero() ||
			(!finalizedRecovery && now.Sub(msg.ReceivedAt) > pendingMessageTTL) {
			hsm.removePending(key)
		}
	}
	hsm.lastPendingPrune = now
}

func (hsm *HotstuffProtocolManager) removePending(key common.Hash) {
	msg, exists := hsm.unhandledMsg[key]
	if !exists {
		return
	}
	delete(hsm.unhandledMsg, key)
	if hsm.pendingBySender == nil {
		return
	}
	sender := pendingSenderKey(msg)
	if hsm.pendingBySender[sender] <= 1 {
		delete(hsm.pendingBySender, sender)
	} else {
		hsm.pendingBySender[sender]--
	}
}

func (hsm *HotstuffProtocolManager) addToUnhandled(m *HotstuffMessage) {
	pending := cloneHotstuffMessage(m)
	currentN := hsm.app.CurrentN()
	if pending.Code == MsgTryPropose && pending.Number < currentN {
		// MsgTryPropose is normally an internal message without a number. Give
		// it the staged view's number so it survives until that view is stale.
		if hsm.leaderView != nil {
			pending.Number = hsm.leaderView.number
		} else {
			pending.Number = currentN
		}
	}
	if !hsm.pendingMessageAllowed(pending, currentN) {
		log.Debug("Discard out-of-window pending hotstuff message", "viewId", pending.ViewId, "code", pending.Code, "number", pending.Number, "current", currentN)
		return
	}
	pending.ReceivedAt = time.Now()

	k, err := pendingMessageKey(pending)
	if err != nil {
		log.Warn("failed to encode hotstuff message to bytes, discarded", "error", err)
		return
	}
	if _, exists := hsm.unhandledMsg[k]; exists {
		return
	}
	if hsm.lastPendingPrune.IsZero() {
		hsm.lastPendingPrune = pending.ReceivedAt
	} else if (len(hsm.unhandledMsg) >= maxPendingMessages && pending.ReceivedAt.Sub(hsm.lastPendingPrune) >= pendingPruneInterval) ||
		pending.ReceivedAt.Sub(hsm.lastPendingPrune) >= pendingMessageTTL {
		hsm.prunePending(pending.ReceivedAt, currentN)
	}
	if len(hsm.unhandledMsg) >= maxPendingMessages {
		log.Debug("pending hotstuff message limit reached", "limit", maxPendingMessages)
		return
	}

	sender := pendingSenderKey(pending)
	if hsm.pendingBySender[sender] >= maxPendingPerSender {
		log.Debug("pending hotstuff sender limit reached", "limit", maxPendingPerSender, "from", pending.Id)
		return
	}
	if !hsm.validPendingMessage(pending) {
		log.Debug("Discard invalid pending hotstuff message", "viewId", pending.ViewId, "code", pending.Code, "number", pending.Number)
		return
	}
	if hsm.pendingBySender == nil {
		hsm.pendingBySender = make(map[common.Hash]int)
	}
	wasEmpty := len(hsm.unhandledMsg) == 0
	hsm.unhandledMsg[k] = pending
	hsm.pendingBySender[sender]++
	if wasEmpty {
		hsm.lastPendingRetry = pending.ReceivedAt
	}
}

func (hsm *HotstuffProtocolManager) HandleMessage(msg *HotstuffMessage) error {
	hsm.mu.Lock()
	defer hsm.mu.Unlock()

	if msg.Code != MsgTimer {
		log.Debug("HandleMessage", "Number", msg.Number, "viewId", msg.ViewId, "code", ReadableMsgType(msg.Code), "from", msg.Id)
	}
	err := hsm.handleMessage(msg)
	if cause, retry := retryableCause(err); retry {
		log.Debug("Add pending hotstuff message", "viewId", msg.ViewId, "code", msg.Code, "from", msg.Id, "error", cause)
		hsm.addToUnhandled(msg)
		return cause
	}

	// A successfully handled Prepare directly unlocks a queued Decide. Other
	// transient application/transport errors retry from the timer, but at most
	// once per interval instead of scanning the queue every 100ms.
	if msg.Code == MsgPrepare && err == nil {
		hsm.retryPending(hsm.app.CurrentN())
	} else if msg.Code == MsgTimer && len(hsm.unhandledMsg) > 0 &&
		time.Since(hsm.lastPendingRetry) >= pendingRetryInterval {
		hsm.retryPending(hsm.app.CurrentN())
	}

	return err
}

type pendingMessage struct {
	key common.Hash
	msg *HotstuffMessage
}

// RetryPending retries messages retained while the local chain or HotStuff
// phase was behind. It is safe to call from the chain import path; processing
// is serialized with HandleMessage.
func (hsm *HotstuffProtocolManager) RetryPending(currentN uint64) error {
	hsm.mu.Lock()
	defer hsm.mu.Unlock()
	return hsm.retryPending(currentN)
}

func (hsm *HotstuffProtocolManager) retryPending(currentN uint64) error {
	hsm.lastPendingRetry = time.Now()
	if appN := hsm.app.CurrentN(); appN > currentN {
		currentN = appN
	}
	hsm.prunePending(time.Now(), currentN)

	pending := make([]pendingMessage, 0, len(hsm.unhandledMsg))
	for key, msg := range hsm.unhandledMsg {
		pending = append(pending, pendingMessage{key: key, msg: msg})
	}
	sort.SliceStable(pending, func(i, j int) bool {
		if pending[i].msg.Number != pending[j].msg.Number {
			return pending[i].msg.Number < pending[j].msg.Number
		}
		if pending[i].msg.Code != pending[j].msg.Code {
			return pending[i].msg.Code < pending[j].msg.Code
		}
		return pending[i].msg.ReceivedAt.Before(pending[j].msg.ReceivedAt)
	})

	var retryErr error
	for _, entry := range pending {
		msg := entry.msg
		// NewView/Prepare/Vote were authenticated before insertion and their
		// handlers verify them again when applicable. A Decide queued without a
		// view is the exception: validate its leader/QC once Prepare has supplied
		// the proposal, without redoing every BLS check on each timer retry.
		invalidDecide := msg.Code == MsgDecide && hsm.views[msg.ViewId] != nil && !hsm.validPendingMessage(msg)
		if !hsm.pendingMessageAllowed(msg, currentN) || invalidDecide {
			log.Debug("Remove stale or invalid pending hotstuff message", "viewId", msg.ViewId, "code", msg.Code, "number", msg.Number, "current", currentN)
			hsm.removePending(entry.key)
			continue
		}

		err := hsm.handleMessage(msg)
		cause, retry := retryableCause(err)
		if !retry && isRecoverableApplicationError(err) {
			cause, retry = err, true
		}
		if retry {
			retryErr = cause
			continue
		}

		log.Debug("Remove pending hotstuff message", "viewId", msg.ViewId, "code", msg.Code, "from", msg.Id, "result", err)
		hsm.removePending(entry.key)
	}
	return retryErr
}

func (hsm *HotstuffProtocolManager) handleTimerMsg(curN uint64) error {
	for _, v := range hsm.views {
		if v.number <= curN {
			continue
		}
		if decideMsg, ok := v.leaderMsg[MsgDecide]; ok && v.phaseAsLeader != PhaseFinal {
			if time.Since(v.lastBroadcastAttempt) < pendingRetryInterval {
				continue
			}
			if err := hsm.broadcastDecide(v, decideMsg); err != nil {
				continue
			}
		}
		if v.phaseAsLeader == PhaseFinal || !v.waitingMoreVoteInfo || len(v.prepareVoteInfo) < v.threshold {
			continue
		}
		elapsed := time.Now().Sub(v.waitingMoreVoteInfoAt)
		if elapsed < params.CollectVoteInfoTimeout {
			continue
		}

		log.Debug("@@@handleTimerMsg", "curN", curN, "number", v.number, "elapsed(s)", elapsed)
		if err := hsm.aggregateQC(v, "prepare", v.prepareVoteInfo); err != nil {
			log.Debug("aggregate prepare voteInfo failed")
			continue
		}

		log.Debug("handleTimerMsg handlePrepareVoteMsg broadcast Decide msg", "number", v.number)
		v.waitingMoreVoteInfo = false
		msg := hsm.createSignatureMsg(v, MsgDecide, "prepare")
		v.leaderMsg[MsgDecide] = msg
		if err := hsm.broadcastDecide(v, msg); err != nil {
			continue
		}
	}

	return nil
}

func (hsm *HotstuffProtocolManager) SignHash(data []byte) []byte {
	sign := hsm.secretKey.SignHash(crypto.Keccak256(data)).Serialize()
	log.Info("Signed hotstuff data!")
	return sign
}
