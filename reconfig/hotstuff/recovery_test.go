package hotstuff

import (
	"errors"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto/bls"
)

type recoveryTestApp struct {
	self        string
	writes      []*HotstuffMessage
	broadcasts  []*HotstuffMessage
	viewDone    func(*SignedState) error
	onCertified func(*SignedState) error
	onNewView   func([]byte, [][]byte) error
	highest     *SignedState
	fhs         bool
	publicKeys  []*bls.PublicKey
}

func (a *recoveryTestApp) Self() string { return a.self }
func (a *recoveryTestApp) Write(_ string, msg *HotstuffMessage) error {
	a.writes = append(a.writes, msg)
	return nil
}
func (a *recoveryTestApp) Broadcast(msg *HotstuffMessage) []error {
	a.broadcasts = append(a.broadcasts, msg)
	return nil
}
func (a *recoveryTestApp) GetPublicKey() []*bls.PublicKey { return a.publicKeys }
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
func (a *recoveryTestApp) OnViewDone(state *SignedState) error {
	if a.viewDone != nil {
		return a.viewDone(state)
	}
	return nil
}
func (a *recoveryTestApp) ValidateView([]byte) ([]byte, string, uint64, error) {
	return nil, "", 0, nil
}
func (a *recoveryTestApp) HighestCertified() *SignedState { return CloneSignedState(a.highest) }
func (a *recoveryTestApp) Propose(uint64, common.Hash, string) (error, []byte, []byte, []byte) {
	return nil, nil, nil, nil
}
func (a *recoveryTestApp) CurrentState() ([]byte, string, uint64) { return nil, "", 0 }
func (a *recoveryTestApp) CurrentN() uint64                       { return 0 }
func (a *recoveryTestApp) GetExtra() []byte                       { return nil }
func (a *recoveryTestApp) ChainID() uint64                        { return 1 }
func (a *recoveryTestApp) UseContextSignatures() bool             { return true }
func (a *recoveryTestApp) UseFHS2Chain() bool                     { return a.fhs }

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
}

func TestFutureNewViewQueuesBeforeCommitteeValidation(t *testing.T) {
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
	if len(pending) != 1 {
		t.Fatalf("future NewView queue length = %d, want 1", len(pending))
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

func TestLateVoteUsesFinalizedRecoveryCache(t *testing.T) {
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
	if err := manager.handlePrepareVoteMsg(vote); err != nil {
		t.Fatal(err)
	}
	if len(app.writes) != 3 || app.writes[0] != prepare || app.writes[1] != qcBroadcast || app.writes[2] != decide {
		t.Fatalf("late-vote recovery writes = %v, want Prepare then QCBroadcast then Decide", app.writes)
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
	if err := manager.handleDecideMsg(&HotstuffMessage{Code: MsgDecide, Number: 9, ViewId: viewID}); err != nil {
		t.Fatal(err)
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
	for _, msg := range app.broadcasts {
		if msg.Code == MsgDecide {
			t.Fatal("leader broadcast same-view MsgDecide in FHS mode")
		}
	}
}
