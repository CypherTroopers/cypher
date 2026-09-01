package hotstuff

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto/bls"
)

type recoveryTestApp struct {
	self                string
	writes              []*HotstuffMessage
	broadcasts          []*HotstuffMessage
	viewDone            func(*SignedState) error
	onCertified         func(*SignedState) error
	onNewView           func([]byte, [][]byte) error
	highest             *SignedState
	fhs                 bool
	publicKeys          []*bls.PublicKey
	publicKeysByHash    map[common.Hash][]*bls.PublicKey
	keyLookups          []common.Hash
	validateState       []byte
	validateLeader      string
	validateNumber      uint64
	certificationEvents []string
	broadcastErrors     []error
	broadcastSucceeded  []bool
	proposalCalls       int
	proposalRecovery    func(uint64, common.Hash, string) bool
}

// retryBroadcastWindowTestApp models the process-local replay-suppression
// window owned by the production FHS application. Every physical QC send must
// be bracketed by Before/After, including a retry after the first After hook
// fails. Broadcast checks the window from another goroutine so the regression
// also exercises the synchronization boundary under the race detector.
type retryBroadcastWindowTestApp struct {
	*recoveryTestApp

	mu                   sync.Mutex
	active               bool
	beforeCalls          int
	afterCalls           int
	unbracketedBroadcast int
}

func (a *retryBroadcastWindowTestApp) OnFHSLeaderCertifiedBeforeBroadcast(state *SignedState) error {
	a.mu.Lock()
	if a.active {
		a.unbracketedBroadcast++
	}
	a.active = true
	a.beforeCalls++
	a.certificationEvents = append(a.certificationEvents, "before")
	a.mu.Unlock()
	return a.OnCertified(state)
}

func (a *retryBroadcastWindowTestApp) Broadcast(msg *HotstuffMessage) []error {
	checked := make(chan bool, 1)
	go func() {
		a.mu.Lock()
		active := a.active
		a.mu.Unlock()
		checked <- active
	}()
	if !<-checked {
		a.mu.Lock()
		a.unbracketedBroadcast++
		a.mu.Unlock()
	}
	return a.recoveryTestApp.Broadcast(msg)
}

func (a *retryBroadcastWindowTestApp) OnFHSLeaderCertifiedAfterBroadcast(*SignedState, bool) error {
	a.mu.Lock()
	a.afterCalls++
	call := a.afterCalls
	a.certificationEvents = append(a.certificationEvents, "after")
	a.active = false
	a.mu.Unlock()
	if call == 1 {
		return errors.New("injected post-broadcast completion failure")
	}
	return nil
}

func (a *recoveryTestApp) Self() string { return a.self }
func (a *recoveryTestApp) Write(_ string, msg *HotstuffMessage) error {
	a.writes = append(a.writes, msg)
	return nil
}
func (a *recoveryTestApp) Broadcast(msg *HotstuffMessage) []error {
	a.certificationEvents = append(a.certificationEvents, "broadcast")
	a.broadcasts = append(a.broadcasts, msg)
	return a.broadcastErrors
}
func (a *recoveryTestApp) GetPublicKey(keyHash common.Hash) ([]*bls.PublicKey, error) {
	a.keyLookups = append(a.keyLookups, keyHash)
	if a.publicKeysByHash != nil {
		keys, ok := a.publicKeysByHash[keyHash]
		if !ok {
			return nil, errors.New("committee not found")
		}
		return keys, nil
	}
	if len(a.publicKeys) == 0 {
		return nil, errors.New("committee not found")
	}
	return a.publicKeys, nil
}
func (a *recoveryTestApp) OnNewView(state []byte, extra [][]byte) error {
	if a.onNewView != nil {
		return a.onNewView(state, extra)
	}
	return nil
}
func (a *recoveryTestApp) OnPropose([]byte, []byte, uint64, *SignedState) error { return nil }
func (a *recoveryTestApp) OnCertified(state *SignedState) error {
	if a.onCertified != nil {
		return a.onCertified(state)
	}
	return nil
}
func (a *recoveryTestApp) OnFHSLeaderCertifiedBeforeBroadcast(state *SignedState) error {
	a.certificationEvents = append(a.certificationEvents, "before")
	return a.OnCertified(state)
}
func (a *recoveryTestApp) OnFHSLeaderCertifiedAfterBroadcast(_ *SignedState, broadcastSucceeded bool) error {
	a.certificationEvents = append(a.certificationEvents, "after")
	a.broadcastSucceeded = append(a.broadcastSucceeded, broadcastSucceeded)
	return nil
}
func (a *recoveryTestApp) OnViewDone(state *SignedState) error {
	if a.viewDone != nil {
		return a.viewDone(state)
	}
	return nil
}
func (a *recoveryTestApp) ValidateView([]byte) ([]byte, string, uint64, error) {
	return a.validateState, a.validateLeader, a.validateNumber, nil
}
func (a *recoveryTestApp) HighestCertified() *SignedState { return CloneSignedState(a.highest) }
func (a *recoveryTestApp) Propose(uint64, common.Hash, string) (error, []byte, []byte, []byte) {
	a.proposalCalls++
	return nil, nil, nil, nil
}
func (a *recoveryTestApp) ProposalRecoveryReady(number uint64, viewID common.Hash, leaderID string) bool {
	if a.proposalRecovery != nil {
		return a.proposalRecovery(number, viewID, leaderID)
	}
	return true
}
func (a *recoveryTestApp) CurrentState() ([]byte, string, uint64) { return nil, "", 0 }
func (a *recoveryTestApp) CurrentN() uint64                       { return 0 }
func (a *recoveryTestApp) GetExtra() []byte                       { return nil }
func (a *recoveryTestApp) ChainID() uint64                        { return 1 }
func (a *recoveryTestApp) UseContextSignatures() bool             { return true }
func (a *recoveryTestApp) UseFHS2Chain() bool                     { return a.fhs }

type proposalReadinessSnapshotTestApp struct {
	*fhsFutureJumpApp
	currentStateCalls int
	snapshotCalls     int
}

func (a *proposalReadinessSnapshotTestApp) CurrentState() ([]byte, string, uint64) {
	a.currentStateCalls++
	return a.fhsFutureJumpApp.CurrentState()
}

func (a *proposalReadinessSnapshotTestApp) FHSProposalReadinessSnapshot() ([]byte, uint64, *SignedState) {
	a.snapshotCalls++
	state, _, number := a.fhsFutureJumpApp.CurrentState()
	return state, number, CloneSignedState(a.highest)
}

func TestCanTryProposeRequiresReadyLeaderView(t *testing.T) {
	legacy := NewHotstuffProtocolManager(&recoveryTestApp{}, nil, nil)
	if legacy.CanTryPropose() {
		t.Fatal("manager without a leader view reported proposal readiness")
	}
	legacy.leaderView = &View{phaseAsLeader: PhasePrepare}
	if legacy.CanTryPropose() {
		t.Fatal("prepare-phase leader view reported proposal readiness")
	}
	legacy.leaderView.phaseAsLeader = PhaseTryPropose
	if !legacy.CanTryPropose() {
		t.Fatal("ready legacy leader view did not report proposal readiness")
	}

	fhsApp := &proposalReadinessSnapshotTestApp{
		fhsFutureJumpApp: &fhsFutureJumpApp{
			recoveryTestApp: &recoveryTestApp{fhs: true},
			current:         7,
			keyNumber:       3,
			keyHash:         common.HexToHash("0x300"),
			committeeHash:   common.HexToHash("0x301"),
			leaderID:        "leader",
		},
	}
	fhs := NewHotstuffProtocolManager(fhsApp, nil, nil)
	state, leaderID, number := fhsApp.CurrentState()
	fhsApp.currentStateCalls = 0
	context, _, err := fhs.makeFHSContext(state, leaderID, number)
	if err != nil {
		t.Fatalf("make FHS context: %v", err)
	}
	fhs.leaderView = &View{
		phaseAsLeader: PhaseTryPropose,
		hash:          context.ID(),
		number:        number,
		leaderId:      leaderID,
		currentState:  append([]byte(nil), state...),
		fhsContext:    context,
	}
	if fhs.CanTryPropose() {
		t.Fatal("FHS leader view without an aggregate quorum reported proposal readiness")
	}
	fhs.leaderView.fhsAggregate = &AggregateQC{Context: *context}
	if !fhs.CanTryPropose() {
		t.Fatal("ready FHS leader view did not report proposal readiness")
	}
	fhs.leaderView.fhsBuild = &FHSProposalBuildKey{RequestID: 1}
	if fhs.CanTryPropose() {
		t.Fatal("FHS leader view with an active build reported proposal readiness")
	}
	fhs.leaderView.fhsBuild = nil

	fhsApp.current++
	if fhs.CanTryPropose() {
		t.Fatal("FHS leader view from an obsolete canonical state reported proposal readiness")
	}
	fhsApp.current--

	parent := &SignedState{
		State:    []byte("new canonical parent"),
		ViewID:   common.HexToHash("0x701"),
		LeaderID: "parent-leader",
		Number:   7,
	}
	fhsApp.highest = parent
	if fhs.CanTryPropose() {
		t.Fatal("FHS leader view with an obsolete highest certificate reported proposal readiness")
	}
	fhs.leaderView.fhsHighest = CloneSignedState(parent)
	if !fhs.CanTryPropose() {
		t.Fatal("FHS leader view matching canonical state and highest certificate did not report proposal readiness")
	}

	fhs.leaderView.fhsContext.TargetView++
	if fhs.CanTryPropose() {
		t.Fatal("FHS leader view inconsistent with its signed context reported proposal readiness")
	}
	if fhsApp.currentStateCalls != 0 {
		t.Fatalf("proposal readiness used side-effecting CurrentState %d times", fhsApp.currentStateCalls)
	}
	if fhsApp.snapshotCalls == 0 {
		t.Fatal("proposal readiness did not use the side-effect-free application snapshot")
	}
}

func TestRecoveryResendsReplicaMessages(t *testing.T) {
	app := &recoveryTestApp{self: "replica"}
	manager := NewHotstuffProtocolManager(app, nil, nil)
	viewID := common.HexToHash("0x1")
	newView := &HotstuffMessage{Code: MsgNewView, Number: 2, ViewId: viewID}
	vote := &HotstuffMessage{Code: MsgVotePrepare, Number: 2, ViewId: viewID}
	view := &View{
		hash:                  viewID,
		number:                2,
		leaderId:              "leader",
		phaseAsReplica:        PhasePrepare,
		replicaMsg:            map[uint64]*HotstuffMessage{MsgNewView: newView, MsgVotePrepare: vote},
		lastReplicaRecoveryAt: time.Now().Add(-hotstuffRecoveryInterval),
	}
	manager.views[viewID] = view

	if err := manager.handleTimerMsg(1); err != nil {
		t.Fatal(err)
	}
	if len(app.writes) != 1 || app.writes[0] != newView {
		t.Fatalf("NewView recovery writes = %v, want cached NewView", app.writes)
	}

	view.phaseAsReplica = PhaseDecide
	view.lastReplicaRecoveryAt = time.Now().Add(-hotstuffRecoveryInterval)
	if err := manager.handleTimerMsg(1); err != nil {
		t.Fatal(err)
	}
	if len(app.writes) != 2 || app.writes[1] != vote {
		t.Fatalf("VotePrepare recovery writes = %v, want cached vote", app.writes)
	}
}

func TestDiscardStaleReplicaNewViewsKeepsOnlyRetryableCanonicalView(t *testing.T) {
	app := &recoveryTestApp{self: "replica"}
	manager := NewHotstuffProtocolManager(app, nil, nil)
	number := uint64(5197)
	keepID := common.HexToHash("0x01")
	staleID := common.HexToHash("0x02")
	progressID := common.HexToHash("0x03")
	otherNumberID := common.HexToHash("0x04")

	manager.views[keepID] = &View{
		hash:           keepID,
		number:         number,
		phaseAsReplica: PhasePrepare,
		replicaMsg:     map[uint64]*HotstuffMessage{MsgNewView: {Code: MsgNewView, Number: number, ViewId: keepID}},
	}
	manager.views[staleID] = &View{
		hash:           staleID,
		number:         number,
		phaseAsReplica: PhasePrepare,
		replicaMsg:     map[uint64]*HotstuffMessage{MsgNewView: {Code: MsgNewView, Number: number, ViewId: staleID}},
	}
	manager.views[progressID] = &View{
		hash:            progressID,
		number:          number,
		phaseAsReplica:  PhasePrepare,
		replicaMsg:      map[uint64]*HotstuffMessage{MsgNewView: {Code: MsgNewView, Number: number, ViewId: progressID}},
		prepareVoteInfo: []*VoteInfo{{}},
	}
	manager.views[otherNumberID] = &View{
		hash:           otherNumberID,
		number:         number + 1,
		phaseAsReplica: PhasePrepare,
		replicaMsg:     map[uint64]*HotstuffMessage{MsgNewView: {Code: MsgNewView, Number: number + 1, ViewId: otherNumberID}},
	}

	manager.discardStaleReplicaNewViews(number, keepID)

	if _, ok := manager.views[staleID]; ok {
		t.Fatal("stale same-number NewView was not discarded")
	}
	if _, ok := manager.views[keepID]; !ok {
		t.Fatal("canonical NewView was discarded")
	}
	if _, ok := manager.views[progressID]; !ok {
		t.Fatal("view with progress was discarded")
	}
	if _, ok := manager.views[otherNumberID]; !ok {
		t.Fatal("different-number view was discarded")
	}
}

func TestRecoveryRebroadcastsFinalizedMessages(t *testing.T) {
	app := &recoveryTestApp{self: "leader"}
	manager := NewHotstuffProtocolManager(app, nil, nil)
	viewID := common.HexToHash("0x2")
	prepare := &HotstuffMessage{Code: MsgPrepare, Number: 2, ViewId: viewID}
	qcBroadcast := &HotstuffMessage{Code: MsgQCBroadcast, Number: 2, ViewId: viewID}
	decide := &HotstuffMessage{Code: MsgDecide, Number: 2, ViewId: viewID}
	manager.views[viewID] = &View{
		hash:                 viewID,
		number:               2,
		leaderId:             "leader",
		phaseAsLeader:        PhaseFinal,
		leaderMsg:            map[uint64]*HotstuffMessage{MsgPrepare: prepare, MsgQCBroadcast: qcBroadcast, MsgDecide: decide},
		lastLeaderRecoveryAt: time.Now().Add(-hotstuffRecoveryInterval),
	}
	manager.finalized[viewID] = &finalizedRecovery{
		number:      2,
		prepare:     prepare,
		qcBroadcast: qcBroadcast,
		decide:      decide,
		finalizedAt: time.Now(),
		lastSentAt:  time.Now().Add(-hotstuffRecoveryInterval),
	}

	if err := manager.handleTimerMsg(1); err != nil {
		t.Fatal(err)
	}
	if len(app.broadcasts) != 3 || app.broadcasts[0] != prepare || app.broadcasts[1] != qcBroadcast || app.broadcasts[2] != decide {
		t.Fatalf("final recovery broadcasts = %v, want Prepare then QCBroadcast then Decide", app.broadcasts)
	}
}

func TestFHSNonDurableFinalizedRecoveryRetainsOnlySelfContainedQC(t *testing.T) {
	base := &recoveryTestApp{self: "leader", fhs: true}
	// Embedding the base application behind the HotStuffApplication interface
	// deliberately hides its durable leader-certification hooks. This exercises
	// the fallback used by FHS applications without a durable QC outbox.
	app := struct{ HotStuffApplication }{HotStuffApplication: base}
	manager := NewHotstuffProtocolManager(&app, nil, nil)
	viewID := common.HexToHash("0xf102")
	prepare := &HotstuffMessage{Code: MsgPrepare, Number: 2, ViewId: viewID}
	qcBroadcast := &HotstuffMessage{Code: MsgQCBroadcast, Number: 2, ViewId: viewID}
	view := &View{
		hash:      viewID,
		number:    2,
		leaderMsg: map[uint64]*HotstuffMessage{MsgPrepare: prepare, MsgQCBroadcast: qcBroadcast},
	}

	manager.cacheFinalizedRecovery(view, nil)
	entry := manager.finalized[viewID]
	if entry == nil {
		t.Fatal("FHS finalized recovery entry was not cached")
	}
	if entry.prepare != nil {
		t.Fatal("FHS finalized recovery retained stale Prepare")
	}
	if entry.qcBroadcast != qcBroadcast {
		t.Fatal("FHS finalized recovery did not retain self-contained QCBroadcast")
	}

	entry.lastSentAt = time.Now().Add(-hotstuffRecoveryInterval)
	if err := manager.handleTimerMsg(1); err != nil {
		t.Fatal(err)
	}
	if len(base.broadcasts) != 1 || base.broadcasts[0] != qcBroadcast {
		t.Fatalf("FHS finalized recovery broadcasts = %v, want only QCBroadcast", base.broadcasts)
	}
}

func TestRecoveryRebroadcastsPrepareWhileCollectingVotes(t *testing.T) {
	app := &recoveryTestApp{self: "leader"}
	manager := NewHotstuffProtocolManager(app, nil, nil)
	viewID := common.HexToHash("0x5")
	prepare := &HotstuffMessage{Code: MsgPrepare, Number: 2, ViewId: viewID}
	manager.views[viewID] = &View{
		hash:                  viewID,
		number:                2,
		leaderId:              "leader",
		phaseAsLeader:         PhasePreCommit,
		threshold:             3,
		waitingMoreVoteInfo:   true,
		waitingMoreVoteInfoAt: time.Now().Add(-hotstuffRecoveryInterval),
		lastLeaderRecoveryAt:  time.Now().Add(-hotstuffRecoveryInterval),
		leaderMsg:             map[uint64]*HotstuffMessage{MsgPrepare: prepare},
	}

	if err := manager.handleTimerMsg(1); err != nil {
		t.Fatal(err)
	}
	if len(app.broadcasts) != 1 || app.broadcasts[0] != prepare {
		t.Fatalf("prepare recovery broadcasts = %v, want cached Prepare", app.broadcasts)
	}

	if err := manager.handleTimerMsg(1); err != nil {
		t.Fatal(err)
	}
	if len(app.broadcasts) != 1 {
		t.Fatalf("prepare recovery ignored interval; broadcasts = %d, want 1", len(app.broadcasts))
	}
}

func TestRecoveryRetriesProposal(t *testing.T) {
	app := &recoveryTestApp{self: "leader"}
	manager := NewHotstuffProtocolManager(app, nil, nil)
	viewID := common.HexToHash("0x3")
	view := &View{
		hash:                 viewID,
		number:               2,
		leaderId:             "leader",
		phaseAsLeader:        PhaseTryPropose,
		lastLeaderRecoveryAt: time.Now().Add(-hotstuffRecoveryInterval),
	}
	manager.views[viewID] = view

	if err := manager.handleTimerMsg(1); err != nil {
		t.Fatal(err)
	}
	if manager.leaderView != view {
		t.Fatal("proposal recovery did not restore the leader view")
	}
	if view.lastLeaderRecoveryAt.IsZero() {
		t.Fatal("proposal recovery did not advance its retry timestamp")
	}
	if app.proposalCalls != 1 {
		t.Fatalf("proposal recovery calls = %d, want 1", app.proposalCalls)
	}
}

func TestRecoveryQuiescesNoWorkUntilInputChanges(t *testing.T) {
	ready := false
	viewID := common.HexToHash("0x31")
	app := &recoveryTestApp{
		self: "leader",
		proposalRecovery: func(number uint64, gotViewID common.Hash, leaderID string) bool {
			if number != 2 || gotViewID != viewID || leaderID != "leader" {
				t.Fatalf("recovery context = %d/%s/%q, want 2/%s/leader", number, gotViewID, leaderID, viewID)
			}
			return ready
		},
	}
	manager := NewHotstuffProtocolManager(app, nil, nil)
	view := &View{
		hash:                 viewID,
		number:               2,
		leaderId:             "leader",
		phaseAsLeader:        PhaseTryPropose,
		lastLeaderRecoveryAt: time.Now().Add(-hotstuffRecoveryInterval),
	}
	manager.views[viewID] = view

	if err := manager.handleTimerMsg(1); err != nil {
		t.Fatal(err)
	}
	if app.proposalCalls != 0 {
		t.Fatalf("unchanged no-work input retried %d proposals", app.proposalCalls)
	}
	firstSuppression := view.lastLeaderRecoveryAt
	if firstSuppression.IsZero() {
		t.Fatal("suppressed recovery did not advance its bounded retry timestamp")
	}

	view.lastLeaderRecoveryAt = time.Now().Add(-hotstuffRecoveryInterval)
	if err := manager.handleTimerMsg(1); err != nil {
		t.Fatal(err)
	}
	if app.proposalCalls != 0 {
		t.Fatalf("second unchanged recovery retried %d proposals", app.proposalCalls)
	}

	ready = true
	view.lastLeaderRecoveryAt = time.Now().Add(-hotstuffRecoveryInterval)
	if err := manager.handleTimerMsg(1); err != nil {
		t.Fatal(err)
	}
	if app.proposalCalls != 1 {
		t.Fatalf("changed proposal input recovery calls = %d, want 1", app.proposalCalls)
	}
}

func TestFutureNewViewRequiresCommitteeValidationBeforeQueue(t *testing.T) {
	app := &recoveryTestApp{self: "leader"}
	manager := NewHotstuffProtocolManager(app, nil, nil)
	viewID := common.HexToHash("0x4")
	msg := &HotstuffMessage{
		Code:   MsgNewView,
		Number: 2,
		ViewId: viewID,
		Id:     "future-replica",
		PubKey: []byte{1, 2, 3},
	}

	manager.queueFutureNewView(msg, nil)
	pending := manager.pendingNewView[viewID]
	if len(pending) != 0 {
		t.Fatalf("unverified future NewView queue length = %d, want 0", len(pending))
	}
}

func TestQCBroadcastRejectsNumberViewMismatchBeforeVerification(t *testing.T) {
	manager := NewHotstuffProtocolManager(&recoveryTestApp{}, nil, nil)
	viewID := common.HexToHash("0x44")
	manager.views[viewID] = &View{hash: viewID, number: 2}
	err := manager.handleQCBroadcastMsg(&HotstuffMessage{Code: MsgQCBroadcast, Number: 3, ViewId: viewID})
	if !errors.Is(err, ErrViewIdNotMatch) {
		t.Fatalf("wrong-number QC error = %v, want %v", err, ErrViewIdNotMatch)
	}
}

func TestDecideCommitFailureRemainsRetryable(t *testing.T) {
	attempts := 0
	app := &recoveryTestApp{
		self: "replica",
		viewDone: func(*SignedState) error {
			attempts++
			if attempts == 1 {
				return errors.New("temporary commit failure")
			}
			return nil
		},
	}
	manager := NewHotstuffProtocolManager(app, nil, nil)
	viewID := common.HexToHash("0x6")
	view := &View{
		hash:           viewID,
		number:         2,
		leaderId:       "leader",
		phaseAsReplica: PhaseDecide,
	}
	manager.views[viewID] = view
	decide := &HotstuffMessage{Code: MsgDecide, Number: 2, ViewId: viewID, Id: "leader"}

	if err := manager.handleDecideMsg(decide); err == nil {
		t.Fatal("first commit unexpectedly succeeded")
	}
	if view.phaseAsReplica != PhaseDecide {
		t.Fatalf("phase after failed commit = %d, want PhaseDecide", view.phaseAsReplica)
	}
	if err := manager.handleDecideMsg(decide); err != nil {
		t.Fatalf("second commit failed: %v", err)
	}
	if view.phaseAsReplica != PhaseFinal {
		t.Fatalf("phase after successful retry = %d, want PhaseFinal", view.phaseAsReplica)
	}
}

func TestUnauthenticatedLateVoteCannotUseFinalizedRecoveryCache(t *testing.T) {
	app := &recoveryTestApp{self: "leader"}
	manager := NewHotstuffProtocolManager(app, nil, nil)
	viewID := common.HexToHash("0x7")
	prepare := &HotstuffMessage{Code: MsgPrepare, Number: 2, ViewId: viewID}
	qcBroadcast := &HotstuffMessage{Code: MsgQCBroadcast, Number: 2, ViewId: viewID}
	decide := &HotstuffMessage{Code: MsgDecide, Number: 2, ViewId: viewID}
	manager.finalized[viewID] = &finalizedRecovery{
		number:      2,
		prepare:     prepare,
		qcBroadcast: qcBroadcast,
		decide:      decide,
		finalizedAt: time.Now(),
	}

	vote := &HotstuffMessage{Code: MsgVotePrepare, Number: 2, ViewId: viewID, Id: "replica"}
	if err := manager.handlePrepareVoteMsg(vote); err != ErrMissingView {
		t.Fatalf("late unauthenticated vote error = %v, want %v", err, ErrMissingView)
	}
	if len(app.writes) != 0 {
		t.Fatalf("late unauthenticated vote triggered %d recovery writes", len(app.writes))
	}
}

func TestOnNewViewFailureRemainsRetryable(t *testing.T) {
	attempts := 0
	app := &recoveryTestApp{
		self: "leader",
		onNewView: func([]byte, [][]byte) error {
			attempts++
			if attempts == 1 {
				return errors.New("temporary view activation failure")
			}
			return nil
		},
	}
	manager := NewHotstuffProtocolManager(app, nil, nil)
	viewID := common.HexToHash("0x8")
	view := &View{
		hash:                 viewID,
		number:               2,
		leaderId:             "leader",
		phaseAsLeader:        PhasePrepare,
		threshold:            1,
		groupPublicKey:       []*bls.PublicKey{nil},
		highVoteInfo:         []*VoteInfo{{}},
		lastLeaderRecoveryAt: time.Now().Add(-hotstuffRecoveryInterval),
		leaderMsg:            make(map[uint64]*HotstuffMessage),
		qc:                   make(map[string]*QC),
	}
	manager.views[viewID] = view

	if err := manager.activateLeaderView(view); err == nil {
		t.Fatal("first OnNewView unexpectedly succeeded")
	}
	if view.phaseAsLeader != PhasePrepare {
		t.Fatalf("phase after failed OnNewView = %d, want PhasePrepare", view.phaseAsLeader)
	}

	view.lastLeaderRecoveryAt = time.Now().Add(-hotstuffRecoveryInterval)
	if err := manager.handleTimerMsg(1); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("OnNewView attempts = %d, want 2", attempts)
	}
	if view.phaseAsLeader != PhaseTryPropose {
		t.Fatalf("phase after OnNewView recovery = %d, want PhaseTryPropose", view.phaseAsLeader)
	}
}

func TestFHSPrepareQCCertifiesWithoutDecideCommit(t *testing.T) {
	certifiedCalls := 0
	decideCalls := 0
	app := &recoveryTestApp{
		self: "replica",
		fhs:  true,
		onCertified: func(state *SignedState) error {
			certifiedCalls++
			if state.Number != 9 || string(state.State) != "proposal-ref" {
				t.Fatalf("unexpected certified state: %+v", state)
			}
			return nil
		},
		viewDone: func(*SignedState) error {
			decideCalls++
			return nil
		},
	}
	manager := NewHotstuffProtocolManager(app, nil, nil)
	viewID := common.HexToHash("0x99")
	view := &View{
		hash:           viewID,
		number:         9,
		leaderId:       "leader",
		proposedTState: []byte("proposal-ref"),
		leaderMsg:      make(map[uint64]*HotstuffMessage),
	}
	manager.views[viewID] = view
	qc := &HotstuffMessage{
		Code:   MsgQCBroadcast,
		Number: 9,
		ViewId: viewID,
		DataB:  []byte("prepare-qc-signature"),
		DataC:  []byte{0x07},
	}

	if err := manager.certifyView(view, qc); err != nil {
		t.Fatal(err)
	}
	if certifiedCalls != 1 || !view.certified {
		t.Fatalf("certified calls = %d, certified = %t", certifiedCalls, view.certified)
	}
	if err := manager.handleDecideMsg(&HotstuffMessage{Code: MsgDecide, Number: 9, ViewId: viewID}); err != ErrViewPhaseNotMatch {
		t.Fatalf("FHS Decide error = %v, want %v", err, ErrViewPhaseNotMatch)
	}
	if decideCalls != 0 {
		t.Fatalf("same-view Decide committed %d times in FHS mode", decideCalls)
	}
}

func TestFHSLeaderBroadcastsPrepareQCWithoutDecide(t *testing.T) {
	var secret bls.SecretKey
	secret.SetByCSPRNG()
	public := secret.GetPublicKey()
	app := &recoveryTestApp{self: "leader", fhs: true, publicKeys: []*bls.PublicKey{public}}
	manager := NewHotstuffProtocolManager(app, &secret, public)
	viewID := common.HexToHash("0x100")
	state := []byte("proposal-ref")
	view := &View{
		hash:            viewID,
		number:          10,
		leaderId:        "leader",
		phaseAsLeader:   PhasePreCommit,
		proposedTState:  state,
		groupPublicKey:  []*bls.PublicKey{public},
		threshold:       1,
		replicaIndex:    buildReplicaIndex([]*bls.PublicKey{public}),
		prepareVoteInfo: make([]*VoteInfo, 0, 1),
		qc:              make(map[string]*QC),
		leaderMsg:       make(map[uint64]*HotstuffMessage),
	}
	manager.views[viewID] = view
	vote := &HotstuffMessage{
		Code:   MsgVotePrepare,
		Number: 10,
		ViewId: viewID,
		Id:     "leader",
		PubKey: public.Serialize(),
		DataC:  manager.SignHashByMessage(MsgVotePrepare, viewID, "leader", state),
	}

	if err := manager.handlePrepareVoteMsg(vote); err != nil {
		t.Fatal(err)
	}
	if view.phaseAsLeader != PhaseFinal {
		t.Fatalf("leader phase = %d, want PhaseFinal", view.phaseAsLeader)
	}
	if _, ok := view.leaderMsg[MsgQCBroadcast]; !ok {
		t.Fatal("leader did not retain Prepare QC broadcast")
	}
	if _, ok := view.leaderMsg[MsgDecide]; ok {
		t.Fatal("leader generated same-view MsgDecide in FHS mode")
	}
	if got := app.certificationEvents; len(got) < 3 || got[len(got)-3] != "before" || got[len(got)-2] != "broadcast" || got[len(got)-1] != "after" {
		t.Fatalf("leader QC lifecycle order = %v, want before/broadcast/after", got)
	}
	if len(app.broadcastSucceeded) != 1 || !app.broadcastSucceeded[0] {
		t.Fatalf("leader QC delivery result = %v, want [true]", app.broadcastSucceeded)
	}
	if len(manager.finalized) != 0 {
		t.Fatalf("durably persisted FHS QC retained %d duplicate volatile recovery entries", len(manager.finalized))
	}
	broadcastsAfterCertification := len(app.broadcasts)
	if err := manager.handleTimerMsg(view.number); err != nil {
		t.Fatal(err)
	}
	if len(app.broadcasts) != broadcastsAfterCertification {
		t.Fatalf("durably persisted FHS QC was redundantly rebroadcast by timer: before=%d after=%d",
			broadcastsAfterCertification, len(app.broadcasts))
	}
	for _, msg := range app.broadcasts {
		if msg.Code == MsgDecide {
			t.Fatal("leader broadcast same-view MsgDecide in FHS mode")
		}
	}
}

func TestFHSLeaderBroadcastDeliveryErrorsReachLifecycle(t *testing.T) {
	tests := []struct {
		name string
		errs []error
	}{
		{name: "partial committee failure", errs: []error{errors.New("peer unavailable")}},
		{name: "all committee sends fail", errs: []error{errors.New("peer one unavailable"), errors.New("peer two unavailable")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var secret bls.SecretKey
			secret.SetByCSPRNG()
			public := secret.GetPublicKey()
			app := &recoveryTestApp{
				self:            "leader",
				fhs:             true,
				publicKeys:      []*bls.PublicKey{public},
				broadcastErrors: test.errs,
			}
			manager := NewHotstuffProtocolManager(app, &secret, public)
			viewID := common.HexToHash("0x102")
			state := []byte("delivery-error-proposal-ref")
			view := &View{
				hash:            viewID,
				number:          12,
				leaderId:        "leader",
				phaseAsLeader:   PhasePreCommit,
				proposedTState:  state,
				groupPublicKey:  []*bls.PublicKey{public},
				threshold:       1,
				replicaIndex:    buildReplicaIndex([]*bls.PublicKey{public}),
				prepareVoteInfo: make([]*VoteInfo, 0, 1),
				qc:              make(map[string]*QC),
				leaderMsg:       make(map[uint64]*HotstuffMessage),
			}
			manager.views[viewID] = view
			vote := &HotstuffMessage{
				Code:   MsgVotePrepare,
				Number: view.number,
				ViewId: viewID,
				Id:     "leader",
				PubKey: public.Serialize(),
				DataC:  manager.SignHashByMessage(MsgVotePrepare, viewID, "leader", state),
			}

			if err := manager.handlePrepareVoteMsg(vote); err != nil {
				t.Fatalf("QC lifecycle stopped on delivery errors: %v", err)
			}
			if view.phaseAsLeader != PhaseFinal {
				t.Fatalf("leader phase = %d, want PhaseFinal", view.phaseAsLeader)
			}
			if len(app.broadcastSucceeded) != 1 || app.broadcastSucceeded[0] {
				t.Fatalf("leader QC delivery result = %v, want [false]", app.broadcastSucceeded)
			}
		})
	}
}

func TestFHSLeaderRetryBracketsEveryPhysicalQCBroadcast(t *testing.T) {
	var secret bls.SecretKey
	secret.SetByCSPRNG()
	public := secret.GetPublicKey()
	base := &recoveryTestApp{self: "leader", fhs: true, publicKeys: []*bls.PublicKey{public}}
	app := &retryBroadcastWindowTestApp{recoveryTestApp: base}
	manager := NewHotstuffProtocolManager(app, &secret, public)
	viewID := common.HexToHash("0x101")
	state := []byte("retry-proposal-ref")
	view := &View{
		hash:            viewID,
		number:          11,
		leaderId:        "leader",
		phaseAsLeader:   PhasePreCommit,
		proposedTState:  state,
		groupPublicKey:  []*bls.PublicKey{public},
		threshold:       1,
		replicaIndex:    buildReplicaIndex([]*bls.PublicKey{public}),
		prepareVoteInfo: make([]*VoteInfo, 0, 1),
		qc:              make(map[string]*QC),
		leaderMsg:       make(map[uint64]*HotstuffMessage),
	}
	manager.views[viewID] = view
	vote := &HotstuffMessage{
		Code:   MsgVotePrepare,
		Number: view.number,
		ViewId: viewID,
		Id:     "leader",
		PubKey: public.Serialize(),
		DataC:  manager.SignHashByMessage(MsgVotePrepare, viewID, "leader", state),
	}

	if err := manager.handlePrepareVoteMsg(vote); err == nil || err.Error() != "injected post-broadcast completion failure" {
		t.Fatalf("first QC broadcast error = %v, want injected completion failure", err)
	}
	if !view.certified {
		t.Fatal("durably certified view lost its retry watermark")
	}
	if _, err := manager.broadcastPrepareQC(view); err != nil {
		t.Fatalf("retry QC broadcast failed: %v", err)
	}

	app.mu.Lock()
	defer app.mu.Unlock()
	if app.beforeCalls != 2 || app.afterCalls != 2 || len(app.broadcasts) != 2 {
		t.Fatalf("QC retry lifecycle calls = before:%d broadcast:%d after:%d, want 2/2/2",
			app.beforeCalls, len(app.broadcasts), app.afterCalls)
	}
	if app.unbracketedBroadcast != 0 {
		t.Fatalf("observed %d physical QC broadcasts outside the replay-suppression window", app.unbracketedBroadcast)
	}
	if app.active {
		t.Fatal("retry completion left the replay-suppression window active")
	}
	want := []string{"before", "broadcast", "after", "before", "broadcast", "after"}
	if len(app.certificationEvents) != len(want) {
		t.Fatalf("QC retry lifecycle = %v, want %v", app.certificationEvents, want)
	}
	for index := range want {
		if app.certificationEvents[index] != want[index] {
			t.Fatalf("QC retry lifecycle = %v, want %v", app.certificationEvents, want)
		}
	}
}

func TestFHSEpochResetClearsOnlyVolatileProtocolState(t *testing.T) {
	app := &recoveryTestApp{}
	manager := NewHotstuffProtocolManager(app, nil, nil)
	viewID := common.HexToHash("0xe001")
	view := &View{hash: viewID, number: 29}
	manager.views[viewID] = view
	manager.leaderView = view
	msgID := common.HexToHash("0xe002")
	manager.unhandledMsg[msgID] = &HotstuffMessage{Code: MsgQCBroadcast, Number: 29}
	manager.unhandledSize[msgID] = 128
	manager.unhandledBytes = 128
	manager.pendingNewView[viewID] = map[string]*HotstuffMessage{"member": {Code: MsgNewView}}
	manager.finalized[viewID] = &finalizedRecovery{number: 29}
	manager.timeoutVotes[viewID] = map[int]*bls.Sign{0: {}}
	manager.timeoutEchoed[viewID] = true
	manager.timeoutQC[viewID] = &TimeoutCertificate{}
	manager.timeoutSeen[viewID] = time.Now()
	manager.timeoutView[viewID] = 29

	manager.ScheduleFHSEpochReset()
	if !manager.applyScheduledFHSEpochReset() {
		t.Fatal("scheduled epoch reset was not applied")
	}
	if len(manager.views) != 0 || manager.leaderView != nil || len(manager.unhandledMsg) != 0 ||
		len(manager.unhandledSize) != 0 || manager.unhandledBytes != 0 || len(manager.pendingNewView) != 0 ||
		len(manager.finalized) != 0 || len(manager.timeoutVotes) != 0 || len(manager.timeoutEchoed) != 0 ||
		len(manager.timeoutQC) != 0 || len(manager.timeoutSeen) != 0 || len(manager.timeoutView) != 0 {
		t.Fatal("epoch reset retained old volatile protocol state")
	}
	if manager.applyScheduledFHSEpochReset() {
		t.Fatal("epoch reset applied twice")
	}
}
