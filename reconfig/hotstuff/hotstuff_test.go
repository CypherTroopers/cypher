package hotstuff

import (
	"bytes"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/crypto/bls"
)

func TestMain(m *testing.M) {
	if err := bls.Init(bls.CurveFp254BNb); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

type testApplication struct {
	self       string
	currentN   uint64
	current    []byte
	leader     string
	publicKeys []*bls.PublicKey
	memberIDs  []string

	checkErr      error
	onNewViewErr  error
	onProposeErr  error
	onViewDoneErr error
	writeErr      error

	proposeK []byte
	proposeT []byte
	extra    []byte

	proposeCalls    int
	checkViewCalls  int
	onNewViewCalls  int
	onProposeCalls  int
	onProposeView   []byte
	onViewDoneCalls int
	writes          []*HotstuffMessage
	writeIDs        []string
	writeResult     []error
	broadcasts      []*HotstuffMessage
	broadcastResult [][]error
}

func (a *testApplication) Self() string { return a.self }

func (a *testApplication) Write(id string, msg *HotstuffMessage) error {
	a.writeIDs = append(a.writeIDs, id)
	a.writes = append(a.writes, cloneHotstuffMessage(msg))
	index := len(a.writes) - 1
	if index < len(a.writeResult) {
		return a.writeResult[index]
	}
	return a.writeErr
}

func (a *testApplication) Broadcast(msg *HotstuffMessage) []error {
	a.broadcasts = append(a.broadcasts, cloneHotstuffMessage(msg))
	index := len(a.broadcasts) - 1
	if index < len(a.broadcastResult) {
		return a.broadcastResult[index]
	}
	return nil
}

func (a *testApplication) GetPublicKey() []*bls.PublicKey { return a.publicKeys }

func (a *testApplication) ReplicaID(publicKey *bls.PublicKey) string {
	for index, member := range a.publicKeys {
		if member != nil && member.IsEqual(publicKey) {
			if index < len(a.memberIDs) {
				return a.memberIDs[index]
			}
			return "replica"
		}
	}
	return ""
}

func (a *testApplication) OnNewView([]byte, [][]byte) error {
	a.onNewViewCalls++
	return a.onNewViewErr
}

func (a *testApplication) OnPropose(_ []byte, _ []byte, prepareView []byte) error {
	a.onProposeCalls++
	a.onProposeView = append(a.onProposeView[:0], prepareView...)
	return a.onProposeErr
}

func (a *testApplication) OnViewDone(*SignedState) error {
	a.onViewDoneCalls++
	return a.onViewDoneErr
}

func (a *testApplication) CheckView([]byte) error {
	a.checkViewCalls++
	return a.checkErr
}

func (a *testApplication) Propose() (error, []byte, []byte, []byte) {
	a.proposeCalls++
	return nil, a.proposeK, a.proposeT, a.extra
}

func (a *testApplication) CurrentState() ([]byte, string, uint64) {
	return a.current, a.leader, a.currentN + 1
}

func (a *testApplication) CurrentN() uint64 { return a.currentN }
func (a *testApplication) GetExtra() []byte { return a.extra }

func newTestKey(t *testing.T) (*bls.SecretKey, *bls.PublicKey) {
	t.Helper()
	secret := new(bls.SecretKey)
	secret.SetByCSPRNG()
	return secret, secret.GetPublicKey()
}

func signedHash(t *testing.T, secret *bls.SecretKey, data []byte) bls.Sign {
	t.Helper()
	serialized := secret.SignHash(crypto.Keccak256(data)).Serialize()
	var sign bls.Sign
	if err := sign.Deserialize(serialized); err != nil {
		t.Fatal(err)
	}
	return sign
}

func TestPreparePassesOnlyAuthenticatedViewToApplication(t *testing.T) {
	secret, public := newTestKey(t)
	app := &testApplication{
		self:       "replica",
		currentN:   4,
		publicKeys: []*bls.PublicKey{public},
	}
	hsm := NewHotstuffProtocolManager(app, secret, public)
	prepareView := []byte("authenticated prepare view")
	viewID := crypto.Keccak256Hash([]byte("leader"), prepareView)
	prepare := &HotstuffMessage{
		Code: MsgPrepare, Number: 5, ViewId: viewID, Id: "leader",
		PubKey: public.Serialize(), DataB: []byte("tx proposal"), DataD: []byte{1}, DataE: prepareView,
	}

	prepare.DataC = secret.SignHash(crypto.Keccak256([]byte("different view"))).Serialize()
	if err := hsm.HandleMessage(prepare); !errors.Is(err, ErrInvalidHighQC) {
		t.Fatalf("Prepare with unauthenticated view error = %v, want %v", err, ErrInvalidHighQC)
	}
	if app.onProposeCalls != 0 {
		t.Fatalf("OnPropose called before view authentication: calls = %d", app.onProposeCalls)
	}

	prepare.DataC = secret.SignHash(crypto.Keccak256(prepareView)).Serialize()
	if err := hsm.HandleMessage(prepare); err != nil {
		t.Fatalf("Prepare with authenticated view error: %v", err)
	}
	if app.onProposeCalls != 1 {
		t.Fatalf("OnPropose calls = %d, want 1", app.onProposeCalls)
	}
	if !bytes.Equal(app.onProposeView, prepareView) {
		t.Fatalf("OnPropose view = %x, want authenticated DataE %x", app.onProposeView, prepareView)
	}
}

func TestDecideApplicationFailureRemainsRetryable(t *testing.T) {
	applyErr := errors.New("application is stopped")
	app := &testApplication{self: "replica", currentN: 9, onViewDoneErr: applyErr}
	hsm := NewHotstuffProtocolManager(app, nil, nil)
	v := hsm.createView(false, PhaseDecide, "leader", []byte("view-9"), 10)
	hsm.views[v.hash] = v
	decide := &HotstuffMessage{Code: MsgDecide, Number: 10, ViewId: v.hash, Id: "leader"}

	if err := hsm.HandleMessage(decide); !errors.Is(err, applyErr) {
		t.Fatalf("HandleMessage error = %v, want %v", err, applyErr)
	}
	if v.phaseAsReplica != PhaseDecide {
		t.Fatalf("phase = %s, want PhaseDecide", readablePhase(v.phaseAsReplica))
	}
	if len(hsm.unhandledMsg) != 1 {
		t.Fatalf("pending messages = %d, want 1", len(hsm.unhandledMsg))
	}
	if err := hsm.HandleMessage(&HotstuffMessage{Code: MsgTimer, Number: 9}); err != nil {
		t.Fatalf("timer error: %v", err)
	}
	if app.onViewDoneCalls != 1 {
		t.Fatalf("timer retried pending Decide: OnViewDone calls = %d, want 1", app.onViewDoneCalls)
	}
	if err := hsm.HandleMessage(decide); !errors.Is(err, applyErr) {
		t.Fatalf("repeated Decide error = %v, want %v", err, applyErr)
	}
	if v.phaseAsReplica != PhaseDecide || len(hsm.unhandledMsg) != 1 {
		t.Fatalf("repeated Decide changed phase or duplicated pending message")
	}

	app.onViewDoneErr = nil
	if err := hsm.RetryPending(9); err != nil {
		t.Fatalf("RetryPending error: %v", err)
	}
	if v.phaseAsReplica != PhaseFinal {
		t.Fatalf("phase = %s, want PhaseFinal", readablePhase(v.phaseAsReplica))
	}
	if len(hsm.unhandledMsg) != 0 {
		t.Fatalf("pending messages = %d, want 0", len(hsm.unhandledMsg))
	}
	if app.onViewDoneCalls != 3 {
		t.Fatalf("OnViewDone calls = %d, want 3", app.onViewDoneCalls)
	}
}

func TestRetryPendingProcessesPrepareBeforeOutOfOrderDecide(t *testing.T) {
	secret, public := newTestKey(t)
	app := &testApplication{
		self:       "replica",
		currentN:   9,
		publicKeys: []*bls.PublicKey{public},
		checkErr:   ErrFutureState,
	}
	hsm := NewHotstuffProtocolManager(app, secret, public)
	currentState := []byte("view-9")
	viewID := crypto.Keccak256Hash([]byte("leader"), currentState)
	highSign := secret.SignHash(crypto.Keccak256(currentState)).Serialize()
	prepare := &HotstuffMessage{
		Code: MsgPrepare, Number: 10, ViewId: viewID, Id: "leader",
		PubKey: public.Serialize(), DataB: []byte("tx proposal"),
		DataC: highSign, DataD: []byte{1}, DataE: currentState,
	}
	decide := &HotstuffMessage{
		Code: MsgDecide, Number: 10, ViewId: viewID, Id: "leader", PubKey: public.Serialize(),
		DataB: secret.SignHash(crypto.Keccak256(prepare.DataB)).Serialize(), DataC: []byte{1},
	}

	if err := hsm.HandleMessage(decide); !errors.Is(err, ErrMissingView) {
		t.Fatalf("Decide error = %v, want ErrMissingView", err)
	}
	if err := hsm.HandleMessage(prepare); !errors.Is(err, ErrFutureState) {
		t.Fatalf("Prepare error = %v, want ErrFutureState", err)
	}
	if len(hsm.unhandledMsg) != 2 {
		t.Fatalf("pending messages = %d, want 2", len(hsm.unhandledMsg))
	}

	app.checkErr = nil
	if err := hsm.RetryPending(9); err != nil {
		t.Fatalf("RetryPending error: %v", err)
	}
	v := hsm.views[viewID]
	if v == nil || v.phaseAsReplica != PhaseFinal {
		t.Fatalf("view phase = %v, want PhaseFinal", v)
	}
	if len(app.writes) != 1 || app.writes[0].Code != MsgVotePrepare {
		t.Fatalf("writes = %#v, want one VotePrepare", app.writes)
	}
	if app.onViewDoneCalls != 1 {
		t.Fatalf("OnViewDone calls = %d, want 1", app.onViewDoneCalls)
	}
	if len(hsm.unhandledMsg) != 0 {
		t.Fatalf("pending messages = %d, want 0", len(hsm.unhandledMsg))
	}
}

func TestPrepareRetriesUnknownAncestorAndVoteSendFailure(t *testing.T) {
	secret, public := newTestKey(t)
	syncErr := consensus.ErrUnknownAncestor
	sendErr := errors.New("send failed")
	app := &testApplication{
		self:         "replica",
		currentN:     4,
		publicKeys:   []*bls.PublicKey{public},
		onProposeErr: syncErr,
	}
	hsm := NewHotstuffProtocolManager(app, secret, public)
	currentState := []byte("view-4")
	viewID := crypto.Keccak256Hash([]byte("leader"), currentState)
	prepare := &HotstuffMessage{
		Code: MsgPrepare, Number: 5, ViewId: viewID, Id: "leader",
		PubKey: public.Serialize(), DataA: []byte("key proposal"),
		DataC: secret.SignHash(crypto.Keccak256(currentState)).Serialize(),
		DataD: []byte{1}, DataE: currentState,
	}

	if err := hsm.HandleMessage(prepare); !errors.Is(err, syncErr) {
		t.Fatalf("Prepare error = %v, want %v", err, syncErr)
	}
	v := hsm.views[viewID]
	if v == nil || v.phaseAsReplica != PhasePrepare {
		t.Fatalf("view phase after unknown ancestor = %v, want PhasePrepare", v)
	}

	app.onProposeErr = nil
	app.writeErr = sendErr
	if err := hsm.RetryPending(4); !errors.Is(err, sendErr) {
		t.Fatalf("RetryPending error = %v, want %v", err, sendErr)
	}
	if v.phaseAsReplica != PhasePrepare {
		t.Fatalf("phase after failed VotePrepare = %s, want PhasePrepare", readablePhase(v.phaseAsReplica))
	}

	app.writeErr = nil
	hsm.lastPendingRetry = time.Now().Add(-pendingRetryInterval)
	if err := hsm.HandleMessage(&HotstuffMessage{Code: MsgTimer, Number: 4}); err != nil {
		t.Fatalf("timer retry error: %v", err)
	}
	if v.phaseAsReplica != PhaseDecide {
		t.Fatalf("phase = %s, want PhaseDecide", readablePhase(v.phaseAsReplica))
	}
	if len(hsm.unhandledMsg) != 0 {
		t.Fatalf("pending messages = %d, want 0", len(hsm.unhandledMsg))
	}
}

func TestFutureNewViewIsRetriedAfterCatchUp(t *testing.T) {
	secret, public := newTestKey(t)
	currentState := []byte("view-12")
	app := &testApplication{
		self:            "leader",
		currentN:        11,
		current:         currentState,
		leader:          "leader",
		publicKeys:      []*bls.PublicKey{public},
		checkErr:        ErrFutureState,
		proposeT:        []byte("block-12"),
		broadcastResult: [][]error{{nil}},
	}
	hsm := NewHotstuffProtocolManager(app, secret, public)
	viewID := crypto.Keccak256Hash([]byte(app.self), currentState)
	msg := &HotstuffMessage{
		Code: MsgNewView, Number: 12, ViewId: viewID, Id: "replica",
		PubKey: public.Serialize(), DataA: currentState,
		DataB: secret.SignHash(crypto.Keccak256(currentState)).Serialize(),
	}

	if err := hsm.HandleMessage(msg); !errors.Is(err, ErrFutureState) {
		t.Fatalf("NewView error = %v, want ErrFutureState", err)
	}
	if len(hsm.views) != 0 {
		t.Fatalf("views created before catch-up = %d, want 0", len(hsm.views))
	}

	app.checkErr = nil
	if err := hsm.RetryPending(11); err != nil {
		t.Fatalf("RetryPending error: %v", err)
	}
	v := hsm.views[viewID]
	if v == nil || v.phaseAsLeader != PhasePreCommit {
		t.Fatalf("leader view = %v, want PhasePreCommit", v)
	}
	if app.onNewViewCalls != 1 || app.proposeCalls != 1 {
		t.Fatalf("OnNewView/Propose calls = %d/%d, want 1/1", app.onNewViewCalls, app.proposeCalls)
	}
	if len(app.broadcasts) != 1 || app.broadcasts[0].Code != MsgPrepare {
		t.Fatalf("broadcasts = %#v, want one Prepare", app.broadcasts)
	}
}

func finalizedRecoveryFixture(t *testing.T, app *testApplication, hsm *HotstuffProtocolManager, secret *bls.SecretKey, public *bls.PublicKey, state []byte, number uint64) (*View, *HotstuffMessage) {
	t.Helper()
	app.memberIDs = []string{"late-replica"}
	v := hsm.createView(true, PhaseFinal, app.self, state, number)
	v.leaderMsg[MsgPrepare] = &HotstuffMessage{
		Code: MsgPrepare, Number: v.number, ViewId: v.hash, Id: app.self,
		DataB: []byte("decided block"), DataE: state,
	}
	decide := &HotstuffMessage{Code: MsgDecide, Number: v.number, ViewId: v.hash, Id: app.self}
	v.leaderMsg[MsgDecide] = decide
	hsm.views[v.hash] = v
	if !hsm.cacheFinalizedView(v, decide) {
		t.Fatal("failed to cache finalized test view")
	}
	late := &HotstuffMessage{
		Code: MsgNewView, Number: v.number, ViewId: v.hash, Id: "late-replica",
		PubKey: public.Serialize(), DataA: state,
		DataB: secret.SignHash(crypto.Keccak256(state)).Serialize(),
	}
	return v, late
}

func TestOldStateNewViewReplaysFinalizedCacheAfterViewLock(t *testing.T) {
	secret, public := newTestKey(t)
	app := &testApplication{
		self: "leader", currentN: 43, publicKeys: []*bls.PublicKey{public}, checkErr: ErrOldState,
	}
	hsm := NewHotstuffProtocolManager(app, secret, public)
	v, late := finalizedRecoveryFixture(t, app, hsm, secret, public, []byte("view-41"), 42)
	next := hsm.createView(true, PhasePrepare, app.self, []byte("view-42"), 43)
	hsm.views[next.hash] = next
	hsm.lockView(next)
	if hsm.views[v.hash] != nil {
		t.Fatal("finalized protocol view survived lock; test did not exercise independent cache")
	}

	if err := hsm.HandleMessage(late); err != nil {
		t.Fatalf("late NewView error: %v", err)
	}
	if app.checkViewCalls != 0 {
		t.Fatalf("CheckView calls = %d, want recovery before OldState check", app.checkViewCalls)
	}
	if len(app.writes) != 2 || app.writes[0].Code != MsgPrepare || app.writes[1].Code != MsgDecide {
		t.Fatalf("writes = %#v, want cached Prepare followed by Decide", app.writes)
	}
	if app.writeIDs[0] != late.Id || app.writeIDs[1] != late.Id {
		t.Fatalf("write destinations = %v, want authenticated %q", app.writeIDs, late.Id)
	}
	if v.phaseAsLeader != PhaseFinal || app.onNewViewCalls != 0 || app.proposeCalls != 0 {
		t.Fatal("recovery mutated consensus phase or invoked proposal callbacks")
	}
}

func TestOldStateRecoveryRejectsUnauthenticatedOrSpoofedNewView(t *testing.T) {
	for _, test := range []struct {
		name      string
		mutate    func(*HotstuffMessage)
		wantError error
	}{
		{
			name: "invalid signature",
			mutate: func(msg *HotstuffMessage) {
				msg.DataB = []byte("not-a-signature")
			},
			wantError: ErrInvalidVoteInfoMessage,
		},
		{
			name: "spoofed destination",
			mutate: func(msg *HotstuffMessage) {
				msg.Id = "another-replica"
			},
			wantError: ErrInvalidReplica,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			secret, public := newTestKey(t)
			app := &testApplication{
				self: "leader", currentN: 43, publicKeys: []*bls.PublicKey{public}, checkErr: ErrOldState,
			}
			hsm := NewHotstuffProtocolManager(app, secret, public)
			_, late := finalizedRecoveryFixture(t, app, hsm, secret, public, []byte("view-41"), 42)
			test.mutate(late)

			if err := hsm.HandleMessage(late); !errors.Is(err, test.wantError) {
				t.Fatalf("NewView error = %v, want %v", err, test.wantError)
			}
			if len(app.writes) != 0 {
				t.Fatalf("invalid recovery wrote %d messages", len(app.writes))
			}
			if app.checkViewCalls != 0 {
				t.Fatalf("CheckView calls = %d, want authentication failure first", app.checkViewCalls)
			}
		})
	}
}

func TestOldStatePrepareOnlyViewIsNotRecovered(t *testing.T) {
	secret, public := newTestKey(t)
	app := &testApplication{
		self: "leader", currentN: 43, publicKeys: []*bls.PublicKey{public}, memberIDs: []string{"late-replica"}, checkErr: ErrOldState,
	}
	hsm := NewHotstuffProtocolManager(app, secret, public)
	state := []byte("view-41")
	v := hsm.createView(true, PhasePreCommit, app.self, state, 42)
	v.leaderMsg[MsgPrepare] = &HotstuffMessage{Code: MsgPrepare, Number: v.number, ViewId: v.hash, Id: app.self}
	hsm.views[v.hash] = v
	late := &HotstuffMessage{
		Code: MsgNewView, Number: v.number, ViewId: v.hash, Id: "late-replica",
		PubKey: public.Serialize(), DataA: state, DataB: secret.SignHash(crypto.Keccak256(state)).Serialize(),
	}

	if err := hsm.HandleMessage(late); !errors.Is(err, ErrOldState) {
		t.Fatalf("Prepare-only NewView error = %v, want ErrOldState", err)
	}
	if len(app.writes) != 0 {
		t.Fatalf("Prepare-only view wrote %d messages", len(app.writes))
	}
}

func TestFinalizedRecoverySendFailuresRemainPending(t *testing.T) {
	for _, test := range []struct {
		name        string
		writeResult []error
	}{
		{name: "Prepare send", writeResult: []error{errors.New("prepare send failed"), nil, nil}},
		{name: "Decide send", writeResult: []error{nil, errors.New("decide send failed"), nil, nil}},
	} {
		t.Run(test.name, func(t *testing.T) {
			secret, public := newTestKey(t)
			app := &testApplication{
				self: "leader", currentN: 43, publicKeys: []*bls.PublicKey{public},
				checkErr: ErrOldState, writeResult: test.writeResult,
			}
			hsm := NewHotstuffProtocolManager(app, secret, public)
			_, late := finalizedRecoveryFixture(t, app, hsm, secret, public, []byte("view-41"), 42)

			if err := hsm.HandleMessage(late); err == nil {
				t.Fatal("initial recovery unexpectedly succeeded")
			}
			if len(hsm.unhandledMsg) != 1 {
				t.Fatalf("pending messages = %d, want 1", len(hsm.unhandledMsg))
			}
			if err := hsm.RetryPending(app.currentN); err != nil {
				t.Fatalf("recovery retry error: %v", err)
			}
			if len(hsm.unhandledMsg) != 0 {
				t.Fatalf("pending messages after retry = %d, want 0", len(hsm.unhandledMsg))
			}
			last := app.writes[len(app.writes)-2:]
			if last[0].Code != MsgPrepare || last[1].Code != MsgDecide {
				t.Fatalf("retry writes = %#v, want Prepare then Decide", last)
			}
		})
	}
}

func TestFinalizedRecoveryCacheUsesSnapshotAndIsBounded(t *testing.T) {
	secret, public := newTestKey(t)
	app := &testApplication{self: "leader", currentN: 50, publicKeys: []*bls.PublicKey{public}, memberIDs: []string{"late-replica"}, checkErr: ErrOldState}
	hsm := NewHotstuffProtocolManager(app, secret, public)
	var firstID common.Hash
	for i := 0; i < maxFinalizedRecoveryViews+1; i++ {
		state := []byte{byte(i + 1)}
		v, _ := finalizedRecoveryFixture(t, app, hsm, secret, public, state, 50)
		if i == 0 {
			copy(firstID[:], v.hash[:])
		}
	}
	if len(hsm.finalizedViews) != maxFinalizedRecoveryViews {
		t.Fatalf("finalized cache size = %d, want %d", len(hsm.finalizedViews), maxFinalizedRecoveryViews)
	}
	if hsm.finalizedViews[firstID] != nil {
		t.Fatal("oldest finalized cache entry was not evicted")
	}

	state := []byte("committee snapshot")
	_, late := finalizedRecoveryFixture(t, app, hsm, secret, public, state, 50)
	_, replacement := newTestKey(t)
	app.publicKeys = []*bls.PublicKey{replacement}
	app.memberIDs = []string{"replacement"}
	if err := hsm.HandleMessage(late); err != nil {
		t.Fatalf("recovery with original committee snapshot failed: %v", err)
	}
	hsm.pruneFinalizedViews(50 + finalizedRecoveryNumberWindow + 1)
	if len(hsm.finalizedViews) != 0 {
		t.Fatalf("height-pruned cache size = %d, want 0", len(hsm.finalizedViews))
	}
}

func TestPrepareBroadcastRetriesStagedProposal(t *testing.T) {
	secret, public := newTestKey(t)
	sendErr := errors.New("broadcast failed")
	app := &testApplication{
		self:            "leader",
		currentN:        20,
		publicKeys:      []*bls.PublicKey{public},
		proposeT:        []byte("block-21"),
		broadcastResult: [][]error{{sendErr}, {nil}},
	}
	hsm := NewHotstuffProtocolManager(app, secret, public)
	v := hsm.createView(true, PhaseTryPropose, app.self, []byte("view-20"), 21)
	v.highVoteInfo = []*VoteInfo{{
		Index: 0, PubKey: public, KSign: signedHash(t, secret, v.currentState), ValidKSign: true,
	}}
	hsm.views[v.hash] = v
	hsm.leaderView = v

	if err := hsm.HandleMessage(&HotstuffMessage{Code: MsgTryPropose, Number: 21}); !errors.Is(err, sendErr) {
		t.Fatalf("TryPropose error = %v, want %v", err, sendErr)
	}
	if v.phaseAsLeader != PhaseTryPropose {
		t.Fatalf("phase = %s, want PhaseTryPropose", readablePhase(v.phaseAsLeader))
	}
	staged := v.leaderMsg[MsgPrepare]
	if staged == nil {
		t.Fatal("Prepare was not staged")
	}

	hsm.lastPendingRetry = time.Now().Add(-pendingRetryInterval)
	if err := hsm.HandleMessage(&HotstuffMessage{Code: MsgTimer, Number: 20}); err != nil {
		t.Fatalf("timer retry error: %v", err)
	}
	if v.phaseAsLeader != PhasePreCommit {
		t.Fatalf("phase = %s, want PhasePreCommit", readablePhase(v.phaseAsLeader))
	}
	if app.proposeCalls != 1 {
		t.Fatalf("Propose calls = %d, want 1", app.proposeCalls)
	}
	if len(app.broadcasts) != 2 || app.broadcasts[1].DataB == nil ||
		app.broadcasts[0].ViewId != app.broadcasts[1].ViewId {
		t.Fatalf("Prepare retry did not reuse staged proposal: %#v", app.broadcasts)
	}
}

func TestDecideBroadcastRetriesTotalFailureAndResendsToLateReplica(t *testing.T) {
	secret, public := newTestKey(t)
	sendErr := errors.New("one peer failed")
	app := &testApplication{
		self:            "leader",
		currentN:        30,
		publicKeys:      []*bls.PublicKey{public},
		broadcastResult: [][]error{{sendErr}, {nil, sendErr}},
	}
	hsm := NewHotstuffProtocolManager(app, secret, public)
	v := hsm.createView(true, PhasePreCommit, app.self, []byte("view-30"), 31)
	decide := &HotstuffMessage{Code: MsgDecide, Number: 31, ViewId: v.hash, Id: app.self}
	v.leaderMsg[MsgDecide] = decide
	hsm.views[v.hash] = v

	err := hsm.broadcastDecide(v, decide)
	if cause, retry := retryableCause(err); !retry || !errors.Is(cause, sendErr) {
		t.Fatalf("broadcastDecide error = %v, want retryable %v", err, sendErr)
	}
	if v.phaseAsLeader != PhasePreCommit {
		t.Fatalf("phase after total failure = %s, want PhasePreCommit", readablePhase(v.phaseAsLeader))
	}

	v.lastBroadcastAttempt = time.Now().Add(-pendingRetryInterval)
	if err := hsm.HandleMessage(&HotstuffMessage{Code: MsgTimer, Number: 30}); err != nil {
		t.Fatalf("timer Decide retry error: %v", err)
	}
	if v.phaseAsLeader != PhaseFinal {
		t.Fatalf("phase = %s, want PhaseFinal", readablePhase(v.phaseAsLeader))
	}

	vote := &HotstuffMessage{
		Code: MsgVotePrepare, Number: 31, ViewId: v.hash, Id: "late replica",
		PubKey: public.Serialize(), DataB: secret.SignHash(crypto.Keccak256([]byte("vote"))).Serialize(),
	}
	if err := hsm.handlePrepareVoteMsg(vote); err != nil {
		t.Fatalf("late VotePrepare error: %v", err)
	}
	if len(app.writes) != 1 || app.writes[0].Code != MsgDecide {
		t.Fatalf("writes = %#v, want one Decide", app.writes)
	}
}

func TestPendingHeightWindow(t *testing.T) {
	app := &testApplication{self: "replica", currentN: 100}
	hsm := NewHotstuffProtocolManager(app, nil, nil)

	for _, number := range []uint64{101, 102} {
		hsm.addToUnhandled(&HotstuffMessage{
			Code: MsgDecide, Number: number, ViewId: crypto.Keccak256Hash([]byte{byte(number)}), Id: "leader",
		})
	}
	hsm.addToUnhandled(&HotstuffMessage{
		Code: MsgDecide, Number: 103, ViewId: crypto.Keccak256Hash([]byte("too-far")), Id: "leader",
	})
	hsm.addToUnhandled(&HotstuffMessage{
		Code: MsgDecide, Number: 99, ViewId: crypto.Keccak256Hash([]byte("stale")), Id: "leader",
	})

	if len(hsm.unhandledMsg) != 2 {
		t.Fatalf("pending messages = %d, want the two in-window messages", len(hsm.unhandledMsg))
	}
}

func TestPendingLimits(t *testing.T) {
	app := &testApplication{self: "replica", currentN: 7}
	hsm := NewHotstuffProtocolManager(app, nil, nil)

	for i := 0; i < maxPendingPerSender+10; i++ {
		hsm.addToUnhandled(&HotstuffMessage{
			Code: MsgDecide, Number: 8,
			ViewId: crypto.Keccak256Hash([]byte{byte(i), byte(i >> 8)}),
			Id:     "one sender",
		})
	}
	if len(hsm.unhandledMsg) != maxPendingPerSender {
		t.Fatalf("per-sender pending messages = %d, want %d", len(hsm.unhandledMsg), maxPendingPerSender)
	}

	hsm = NewHotstuffProtocolManager(app, nil, nil)
	for i := 0; i < maxPendingMessages+25; i++ {
		hsm.addToUnhandled(&HotstuffMessage{
			Code: MsgDecide, Number: 8,
			ViewId: crypto.Keccak256Hash([]byte{byte(i), byte(i >> 8), 1}),
			Id:     "leader",
			PubKey: []byte{byte(i), byte(i >> 8), 2},
		})
	}
	if len(hsm.unhandledMsg) != maxPendingMessages {
		t.Fatalf("global pending messages = %d, want %d", len(hsm.unhandledMsg), maxPendingMessages)
	}
}

func TestPendingTTLAndExactDeduplication(t *testing.T) {
	app := &testApplication{self: "replica", currentN: 20}
	hsm := NewHotstuffProtocolManager(app, nil, nil)
	viewID := crypto.Keccak256Hash([]byte("view-21"))
	first := &HotstuffMessage{
		Code: MsgDecide, Number: 21, ViewId: viewID, Id: "leader", DataA: []byte("first"),
	}
	hsm.addToUnhandled(first)
	hsm.addToUnhandled(cloneHotstuffMessage(first))
	if len(hsm.unhandledMsg) != 1 {
		t.Fatalf("exact duplicate pending messages = %d, want 1", len(hsm.unhandledMsg))
	}
	differentPayload := cloneHotstuffMessage(first)
	differentPayload.DataA = []byte("changed payload")
	hsm.addToUnhandled(differentPayload)
	if len(hsm.unhandledMsg) != 2 {
		t.Fatalf("different signed payloads share a pending slot: messages = %d, want 2", len(hsm.unhandledMsg))
	}

	for _, msg := range hsm.unhandledMsg {
		msg.ReceivedAt = time.Now().Add(-pendingMessageTTL - time.Second)
	}

	if err := hsm.RetryPending(20); err != nil {
		t.Fatalf("RetryPending error: %v", err)
	}
	if len(hsm.unhandledMsg) != 0 {
		t.Fatalf("expired pending messages = %d, want 0", len(hsm.unhandledMsg))
	}
	if len(hsm.pendingBySender) != 0 {
		t.Fatalf("expired sender counters = %d, want 0", len(hsm.pendingBySender))
	}
}

func TestPendingRejectsNonCommitteePublicKey(t *testing.T) {
	_, member := newTestKey(t)
	_, outsider := newTestKey(t)
	app := &testApplication{self: "replica", currentN: 3, publicKeys: []*bls.PublicKey{member}}
	hsm := NewHotstuffProtocolManager(app, nil, nil)
	viewID := crypto.Keccak256Hash([]byte("view-4"))

	hsm.addToUnhandled(&HotstuffMessage{
		Code: MsgDecide, Number: 4, ViewId: viewID, Id: "leader", PubKey: outsider.Serialize(),
	})
	if len(hsm.unhandledMsg) != 0 {
		t.Fatal("message from a non-committee public key was retained")
	}
	hsm.addToUnhandled(&HotstuffMessage{
		Code: MsgDecide, Number: 4, ViewId: viewID, Id: "leader", PubKey: member.Serialize(),
	})
	if len(hsm.unhandledMsg) != 1 {
		t.Fatal("message from a committee public key was not retained")
	}
}
