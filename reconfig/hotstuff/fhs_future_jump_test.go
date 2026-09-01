package hotstuff

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rlp"
)

type fhsFutureJumpApp struct {
	*recoveryTestApp
	current       uint64
	keyNumber     uint64
	keyHash       common.Hash
	committeeHash common.Hash
	leaderID      string
	highestTC     *TimeoutCertificate
	acceptCalls   int
	adoptCalls    int
	adoptErr      error
	events        []string
}

func (a *fhsFutureJumpApp) CurrentN() uint64 { return a.current }

func (a *fhsFutureJumpApp) CurrentState() ([]byte, string, uint64) {
	state := (&bftview.View{
		TxNumber:      36,
		TxHash:        common.HexToHash("0x3600"),
		KeyNumber:     a.keyNumber,
		KeyHash:       a.keyHash,
		CommitteeHash: a.committeeHash,
		ViewNumber:    a.current,
	}).EncodeConsensusToBytes()
	return state, a.leaderID, a.current + 1
}

func (a *fhsFutureJumpApp) ValidateFHSContext(ctx *FHSViewContext) error {
	if ctx == nil || ctx.ChainID != a.ChainID() || ctx.TargetView != a.current+1 ||
		ctx.KeyNumber != a.keyNumber || ctx.KeyHash != a.keyHash || ctx.CommitteeHash != a.committeeHash ||
		ctx.LeaderID != a.leaderID {
		return ErrInvalidLeaderView
	}
	return nil
}

func (a *fhsFutureJumpApp) AdoptFHSHighQC(qc *SignedState) error {
	a.adoptCalls++
	a.events = append(a.events, "qc")
	if a.adoptErr != nil {
		return a.adoptErr
	}
	a.highest = CloneSignedState(qc)
	if qc != nil && qc.Number > a.current {
		a.current = qc.Number
	}
	return nil
}

func (a *fhsFutureJumpApp) HighestFHSTimeoutCertificate() *TimeoutCertificate {
	return CloneTimeoutCertificate(a.highestTC)
}

func (a *fhsFutureJumpApp) PersistFHSVote(*PersistedVote) error { return nil }

func (a *fhsFutureJumpApp) PersistFHSTimeoutVote(*TimeoutStatement) error { return nil }

func (a *fhsFutureJumpApp) AcceptFHSTimeoutCertificate(tc *TimeoutCertificate) error {
	a.acceptCalls++
	a.events = append(a.events, "tc")
	a.highestTC = CloneTimeoutCertificate(tc)
	if tc != nil && tc.Statement.TimedOutView > a.current {
		a.current = tc.Statement.TimedOutView
	}
	return nil
}

func (*fhsFutureJumpApp) RequireMessageAuth() bool { return true }

type fhsFutureJumpFixture struct {
	app       *fhsFutureJumpApp
	manager   *HotstuffProtocolManager
	secrets   []bls.SecretKey
	keys      []*bls.PublicKey
	committee *bftview.Committee
	memberIDs []string
}

type fhsAsyncValidationApp struct {
	*fhsFutureJumpApp
	scheduled        []*FHSProposalValidationRequest
	applied          []*FHSProposalValidationResult
	highScheduled    []*FHSHighQCValidationRequest
	highApplied      []*FHSHighQCValidationResult
	highEvents       []string
	highScheduleErr  error
	highApplyErr     error
	highApplyHook    func()
	persisted        []*PersistedVote
	persistErr       error
	validationEvents []string
	buildScheduled   []*FHSProposalBuildRequest
	buildApplied     []*FHSProposalBuildResult
	buildApplyErr    error
	buildEvents      []string
}

func (a *fhsAsyncValidationApp) ScheduleFHSProposalBuild(request *FHSProposalBuildRequest) error {
	if request == nil {
		return errors.New("nil proposal construction request")
	}
	copyRequest := *request
	copyRequest.CurrentState = append([]byte(nil), request.CurrentState...)
	copyRequest.ParentQC = CloneSignedState(request.ParentQC)
	a.buildScheduled = append(a.buildScheduled, &copyRequest)
	a.buildEvents = append(a.buildEvents, "schedule")
	return nil
}

func (a *fhsAsyncValidationApp) ApplyFHSProposalBuild(result *FHSProposalBuildResult) error {
	a.buildApplied = append(a.buildApplied, result)
	a.buildEvents = append(a.buildEvents, "apply")
	return a.buildApplyErr
}

func (a *fhsAsyncValidationApp) FinishFHSProposalBuild(*FHSProposalBuildResult) {}

func (a *fhsAsyncValidationApp) Broadcast(msg *HotstuffMessage) []error {
	a.buildEvents = append(a.buildEvents, "broadcast")
	return a.recoveryTestApp.Broadcast(msg)
}

func (a *fhsAsyncValidationApp) ScheduleFHSHighQCValidation(request *FHSHighQCValidationRequest) error {
	if request == nil || request.QC == nil {
		return errors.New("nil HighQC validation request")
	}
	if a.highScheduleErr != nil {
		return a.highScheduleErr
	}
	copyRequest := *request
	copyRequest.QC = CloneSignedState(request.QC)
	a.highScheduled = append(a.highScheduled, &copyRequest)
	return nil
}

func (a *fhsAsyncValidationApp) ApplyFHSHighQCValidation(result *FHSHighQCValidationResult) error {
	if result == nil {
		return errors.New("nil HighQC validation result")
	}
	a.highApplied = append(a.highApplied, result)
	a.highEvents = append(a.highEvents, "apply")
	for _, request := range a.highScheduled {
		if request != nil && request.Key == result.Key {
			if a.highApplyErr != nil {
				if a.highApplyHook != nil {
					a.highApplyHook()
				}
				return a.highApplyErr
			}
			a.highest = CloneSignedState(request.QC)
			if request.QC.Number > a.current {
				a.current = request.QC.Number
			}
			if a.highApplyHook != nil {
				a.highApplyHook()
			}
			return nil
		}
	}
	return ErrOldState
}

func (a *fhsAsyncValidationApp) FinishFHSHighQCValidation(*FHSHighQCValidationResult) {
	a.highEvents = append(a.highEvents, "finish")
}

func (a *fhsAsyncValidationApp) ScheduleFHSProposalValidation(request *FHSProposalValidationRequest) error {
	if request == nil {
		return errors.New("nil validation request")
	}
	copyRequest := *request
	copyRequest.ProposalRef = append([]byte(nil), request.ProposalRef...)
	copyRequest.Extra = append([]byte(nil), request.Extra...)
	copyRequest.ParentQC = CloneSignedState(request.ParentQC)
	a.scheduled = append(a.scheduled, &copyRequest)
	return nil
}

func (a *fhsAsyncValidationApp) ApplyFHSProposalValidation(result *FHSProposalValidationResult) error {
	a.validationEvents = append(a.validationEvents, "apply")
	a.applied = append(a.applied, result)
	return nil
}

func (a *fhsAsyncValidationApp) FinishFHSProposalValidation(*FHSProposalValidationResult) {
	a.validationEvents = append(a.validationEvents, "finish")
}

func (a *fhsAsyncValidationApp) PersistFHSVote(vote *PersistedVote) error {
	a.validationEvents = append(a.validationEvents, "persist")
	if vote != nil {
		copyVote := *vote
		copyVote.ProposalRef = append([]byte(nil), vote.ProposalRef...)
		a.persisted = append(a.persisted, &copyVote)
	}
	return a.persistErr
}

func (a *fhsAsyncValidationApp) Write(id string, msg *HotstuffMessage) error {
	a.validationEvents = append(a.validationEvents, "write")
	return a.recoveryTestApp.Write(id, msg)
}

type fhsAsyncValidationFixture struct {
	*fhsFutureJumpFixture
	async *fhsAsyncValidationApp
}

func newFHSAsyncValidationFixture(t *testing.T) *fhsAsyncValidationFixture {
	t.Helper()
	base := newFHSFutureJumpFixture(t, 11)
	async := &fhsAsyncValidationApp{fhsFutureJumpApp: base.app}
	base.manager = NewHotstuffProtocolManager(async, &base.secrets[3], base.keys[3])
	return &fhsAsyncValidationFixture{fhsFutureJumpFixture: base, async: async}
}

func (f *fhsAsyncValidationFixture) prepare(t *testing.T) (*types.HotstuffProposalRef, *HotstuffMessage) {
	t.Helper()
	state, leaderID, targetView := f.async.CurrentState()
	ctx, tc, err := f.manager.makeFHSContext(state, leaderID, targetView)
	if err != nil {
		t.Fatalf("make FHS Prepare context: %v", err)
	}
	if tc != nil {
		t.Fatal("unexpected timeout certificate in QC-entry fixture")
	}
	aggregate := aggregateNewViewReports(t, f.secrets, []int{0, 1, 2}, *ctx)
	encodedAggregate, err := EncodeAggregateQC(aggregate)
	if err != nil {
		t.Fatalf("encode FHS aggregate QC: %v", err)
	}
	extra := []byte("validated-extra")
	ref := &types.HotstuffProposalRef{
		Version:    types.HotstuffProposalRefVersion,
		ChainID:    f.async.ChainID(),
		Number:     37,
		ViewNumber: targetView,
		ViewID:     ctx.ID(),
		LeaderID:   leaderID,
		BlockHash:  common.HexToHash("0x3700"),
		ParentHash: common.HexToHash("0x3600"),
		BodyHash:   common.HexToHash("0x3701"),
		BodySize:   1,
		ExtraHash:  types.HotstuffProposalExtraHash(extra),
		KeyHash:    f.async.keyHash,
	}
	msg := &HotstuffMessage{
		Code:   MsgPrepare,
		Number: targetView,
		ViewId: ctx.ID(),
		Id:     leaderID,
		DataB:  ref.EncodeToBytes(),
		DataC:  encodedAggregate,
		DataF:  extra,
	}
	f.authenticate(t, 3, msg)
	return ref, msg
}

func (f *fhsAsyncValidationFixture) schedulePrepare(t *testing.T) (*types.HotstuffProposalRef, *FHSProposalValidationRequest) {
	t.Helper()
	ref, msg := f.prepare(t)
	if err := f.manager.handleFHSPrepareMsg(msg); !errors.Is(err, ErrProposalValidationPending) {
		t.Fatalf("schedule async FHS Prepare: got %v, want %v", err, ErrProposalValidationPending)
	}
	if len(f.async.scheduled) != 1 {
		t.Fatalf("validation schedule calls = %d, want 1", len(f.async.scheduled))
	}
	return ref, f.async.scheduled[0]
}

func (f *fhsAsyncValidationFixture) scheduleLeaderBuild(t *testing.T) (*View, *FHSProposalBuildRequest) {
	t.Helper()
	state, leaderID, targetView := f.async.CurrentState()
	ctx, tc, err := f.manager.makeFHSContext(state, leaderID, targetView)
	if err != nil {
		t.Fatal(err)
	}
	if tc != nil {
		t.Fatal("unexpected timeout certificate in leader construction fixture")
	}
	aggregate := aggregateNewViewReports(t, f.secrets, []int{0, 1, 2}, *ctx)
	v := &View{
		hash:           ctx.ID(),
		number:         targetView,
		leaderId:       leaderID,
		phaseAsLeader:  PhaseTryPropose,
		currentState:   append([]byte(nil), state...),
		leaderMsg:      make(map[uint64]*HotstuffMessage),
		fhsContext:     ctx,
		fhsAggregate:   aggregate,
		fhsReportSigns: make(map[uint32]*bls.Sign),
	}
	f.manager.views[v.hash] = v
	f.manager.leaderView = v
	if err := f.manager.tryFHSPropose(); !errors.Is(err, ErrProposalValidationPending) {
		t.Fatalf("schedule async FHS proposal construction: got %v, want %v", err, ErrProposalValidationPending)
	}
	if len(f.async.buildScheduled) != 1 {
		t.Fatalf("proposal construction schedule calls = %d, want 1", len(f.async.buildScheduled))
	}
	return v, f.async.buildScheduled[0]
}

func (f *fhsAsyncValidationFixture) proposalBuildResult(t *testing.T, request *FHSProposalBuildRequest) *FHSProposalBuildResult {
	t.Helper()
	extra := []byte("leader-build-extra")
	ref := &types.HotstuffProposalRef{
		Version: types.HotstuffProposalRefVersion, ChainID: f.async.ChainID(),
		Number: 37, ViewNumber: request.Key.ViewNumber, ViewID: request.Key.ViewID, LeaderID: request.Key.LeaderID,
		BlockHash: common.HexToHash("0x4700"), ParentHash: common.HexToHash("0x3600"),
		BodyHash: common.HexToHash("0x4701"), BodySize: 1,
		ExtraHash: types.HotstuffProposalExtraHash(extra), KeyHash: f.async.keyHash, ParentQCID: request.Key.ParentQCID,
	}
	return &FHSProposalBuildResult{Key: request.Key, TProposal: ref.EncodeToBytes(), Extra: extra, ApplicationData: "staged"}
}

func TestFHSAsyncLeaderBuildSealsBeforeApplyAndBroadcast(t *testing.T) {
	fixture := newFHSAsyncValidationFixture(t)
	v, request := fixture.scheduleLeaderBuild(t)
	if v.fhsBuild == nil || *v.fhsBuild != request.Key || len(fixture.async.buildApplied) != 0 || len(fixture.async.broadcasts) != 0 {
		t.Fatal("proposal construction scheduling published leader state")
	}

	result := fixture.proposalBuildResult(t, request)
	if err := fixture.manager.HandleFHSProposalBuildResult(result); err != nil {
		t.Fatalf("complete proposal construction: %v", err)
	}
	if len(fixture.async.buildEvents) != 3 || fixture.async.buildEvents[0] != "schedule" ||
		fixture.async.buildEvents[1] != "apply" || fixture.async.buildEvents[2] != "broadcast" {
		t.Fatalf("proposal construction order = %v, want [schedule apply broadcast]", fixture.async.buildEvents)
	}
	if v.phaseAsLeader != PhasePreCommit || fixture.manager.leaderView != nil || v.leaderMsg[MsgPrepare] == nil {
		t.Fatal("completed proposal construction did not publish exact Prepare state")
	}
	if err := ValidateHotstuffWireMessage(v.leaderMsg[MsgPrepare]); err != nil {
		t.Fatalf("published Prepare was not sealed/valid: %v", err)
	}
	if err := fixture.manager.HandleFHSProposalBuildResult(result); !errors.Is(err, ErrOldState) {
		t.Fatalf("duplicate construction result error = %v, want %v", err, ErrOldState)
	}
	if len(fixture.async.buildApplied) != 1 || len(fixture.async.broadcasts) != 1 {
		t.Fatal("duplicate construction result republished Apply or Prepare")
	}
}

func TestFHSAsyncLeaderBuildStaleResultHasNoSideEffects(t *testing.T) {
	fixture := newFHSAsyncValidationFixture(t)
	v, request := fixture.scheduleLeaderBuild(t)
	fixture.async.current++ // timeout-only view advance; block parent may be unchanged
	result := fixture.proposalBuildResult(t, request)
	if err := fixture.manager.HandleFHSProposalBuildResult(result); !errors.Is(err, ErrOldState) {
		t.Fatalf("stale construction result error = %v, want %v", err, ErrOldState)
	}
	if len(fixture.async.buildApplied) != 0 || len(fixture.async.broadcasts) != 0 || v.phaseAsLeader != PhaseTryPropose || v.leaderMsg[MsgPrepare] != nil {
		t.Fatal("stale construction result published application or Prepare state")
	}
}

func TestFHSLifecycleResetClearsAbandonedAsyncContinuations(t *testing.T) {
	fixture := newFHSAsyncValidationFixture(t)
	_, _ = fixture.scheduleLeaderBuild(t)
	fixture.manager.pendingHighQC = &pendingFHSHighQCValidation{key: FHSHighQCValidationKey{RequestID: 99}}
	fixture.manager.ScheduleFHSEpochReset()
	if !fixture.manager.applyScheduledFHSEpochReset() {
		t.Fatal("scheduled lifecycle reset was not applied")
	}
	if fixture.manager.leaderView != nil || fixture.manager.pendingHighQC != nil || len(fixture.manager.views) != 0 {
		t.Fatal("lifecycle reset retained abandoned build or HighQC continuation")
	}
}

func TestFHSAsyncLeaderBuildSealOrApplyFailureStaysRetryable(t *testing.T) {
	t.Run("seal failure", func(t *testing.T) {
		fixture := newFHSAsyncValidationFixture(t)
		v, request := fixture.scheduleLeaderBuild(t)
		fixture.manager.secretKey = nil
		if err := fixture.manager.HandleFHSProposalBuildResult(fixture.proposalBuildResult(t, request)); err == nil {
			t.Fatal("proposal construction seal failure was hidden")
		}
		if len(fixture.async.buildApplied) != 0 || len(fixture.async.broadcasts) != 0 || v.phaseAsLeader != PhaseTryPropose {
			t.Fatal("seal failure reached Apply or Broadcast")
		}
	})

	t.Run("apply failure", func(t *testing.T) {
		fixture := newFHSAsyncValidationFixture(t)
		v, request := fixture.scheduleLeaderBuild(t)
		fixture.async.buildApplyErr = errors.New("publication queue full")
		if err := fixture.manager.HandleFHSProposalBuildResult(fixture.proposalBuildResult(t, request)); err == nil {
			t.Fatal("proposal construction Apply failure was hidden")
		}
		if len(fixture.async.buildApplied) != 1 || len(fixture.async.broadcasts) != 0 || v.phaseAsLeader != PhaseTryPropose || v.leaderMsg[MsgPrepare] != nil {
			t.Fatal("Apply failure published Prepare or left the view non-retryable")
		}
	})
}

func TestFHSAsyncPrepareSchedulesWithoutPublishingVote(t *testing.T) {
	fixture := newFHSAsyncValidationFixture(t)
	ref, request := fixture.schedulePrepare(t)

	if request.Key.RequestID == 0 || request.Key.ProposalID != ref.ProposalID() ||
		request.Key.ViewNumber != ref.ViewNumber || request.Key.ViewID != ref.ViewID ||
		request.Key.LeaderID != ref.LeaderID {
		t.Fatalf("scheduled validation key = %#v, want exact proposal identity", request.Key)
	}
	if len(fixture.async.applied) != 0 || len(fixture.async.persisted) != 0 || len(fixture.async.writes) != 0 {
		t.Fatalf("schedule published side effects: apply=%d persist=%d write=%d",
			len(fixture.async.applied), len(fixture.async.persisted), len(fixture.async.writes))
	}
	view := fixture.manager.views[ref.ViewID]
	if view == nil || view.fhsValidation == nil || *view.fhsValidation != request.Key {
		t.Fatal("scheduled validation was not retained as the active request")
	}
	if vote := view.replicaMsg[MsgVotePrepare]; vote != nil {
		t.Fatal("VotePrepare was cached before async validation completed")
	}
	if view.phaseAsReplica != PhasePrepare {
		t.Fatalf("replica phase after schedule = %d, want PhasePrepare", view.phaseAsReplica)
	}
}

func TestFHSAsyncPrepareStaleResultsHaveNoSideEffects(t *testing.T) {
	t.Run("request token mismatch", func(t *testing.T) {
		fixture := newFHSAsyncValidationFixture(t)
		_, request := fixture.schedulePrepare(t)
		staleKey := request.Key
		staleKey.RequestID++

		err := fixture.manager.CompleteFHSProposalValidation(&FHSProposalValidationResult{Key: staleKey})
		if !errors.Is(err, ErrOldState) {
			t.Fatalf("mismatched request error = %v, want %v", err, ErrOldState)
		}
		assertNoAsyncValidationSideEffects(t, fixture)
	})

	t.Run("application state advanced", func(t *testing.T) {
		fixture := newFHSAsyncValidationFixture(t)
		_, request := fixture.schedulePrepare(t)
		fixture.async.current++

		err := fixture.manager.CompleteFHSProposalValidation(&FHSProposalValidationResult{Key: request.Key})
		if !errors.Is(err, ErrOldState) {
			t.Fatalf("stale application state error = %v, want %v", err, ErrOldState)
		}
		assertNoAsyncValidationSideEffects(t, fixture)
	})
}

func assertNoAsyncValidationSideEffects(t *testing.T, fixture *fhsAsyncValidationFixture) {
	t.Helper()
	if len(fixture.async.applied) != 0 || len(fixture.async.persisted) != 0 || len(fixture.async.writes) != 0 ||
		len(fixture.async.validationEvents) != 0 {
		t.Fatalf("stale result published side effects: apply=%d persist=%d write=%d events=%v",
			len(fixture.async.applied), len(fixture.async.persisted), len(fixture.async.writes), fixture.async.validationEvents)
	}
}

func TestFHSAsyncPrepareCompletesApplyWALWriteInOrder(t *testing.T) {
	fixture := newFHSAsyncValidationFixture(t)
	ref, request := fixture.schedulePrepare(t)
	result := &FHSProposalValidationResult{Key: request.Key, ApplicationData: "verified"}

	if err := fixture.manager.CompleteFHSProposalValidation(result); err != nil {
		t.Fatalf("complete async FHS Prepare: %v", err)
	}
	wantEvents := []string{"apply", "persist", "write", "finish"}
	if fmt.Sprint(fixture.async.validationEvents) != fmt.Sprint(wantEvents) {
		t.Fatalf("validation events = %v, want %v", fixture.async.validationEvents, wantEvents)
	}
	if len(fixture.async.applied) != 1 || fixture.async.applied[0] != result {
		t.Fatalf("validation apply calls = %d, want exact result once", len(fixture.async.applied))
	}
	if len(fixture.async.persisted) != 1 {
		t.Fatalf("vote WAL writes = %d, want 1", len(fixture.async.persisted))
	}
	persisted := fixture.async.persisted[0]
	if persisted.ViewNumber != ref.ViewNumber || persisted.ViewID != ref.ViewID || persisted.LeaderID != ref.LeaderID ||
		persisted.ProposalID != ref.ProposalID() || persisted.ProposalRefHash != StateDigest(persisted.ProposalRef) {
		t.Fatalf("persisted vote watermark = %#v, want exact proposal reference", persisted)
	}
	if len(fixture.async.writes) != 1 || fixture.async.writes[0].Code != MsgVotePrepare || len(fixture.async.writes[0].DataC) == 0 {
		t.Fatalf("published messages = %#v, want one signed VotePrepare", fixture.async.writes)
	}
	view := fixture.manager.views[ref.ViewID]
	if view == nil || view.phaseAsReplica != PhaseDecide || view.replicaMsg[MsgVotePrepare] != fixture.async.writes[0] {
		t.Fatal("completed VotePrepare was not cached before entering PhaseDecide")
	}
}

func TestFHSAsyncPrepareWALFailureCannotPublishVote(t *testing.T) {
	fixture := newFHSAsyncValidationFixture(t)
	ref, request := fixture.schedulePrepare(t)
	persistErr := errors.New("forced vote WAL failure")
	fixture.async.persistErr = persistErr

	err := fixture.manager.CompleteFHSProposalValidation(&FHSProposalValidationResult{Key: request.Key, ApplicationData: "verified"})
	if !errors.Is(err, persistErr) {
		t.Fatalf("WAL failure error = %v, want %v", err, persistErr)
	}
	wantEvents := []string{"apply", "persist", "finish"}
	if fmt.Sprint(fixture.async.validationEvents) != fmt.Sprint(wantEvents) {
		t.Fatalf("validation events = %v, want %v", fixture.async.validationEvents, wantEvents)
	}
	if len(fixture.async.persisted) != 1 || len(fixture.async.writes) != 0 {
		t.Fatalf("WAL failure side effects: persist=%d write=%d", len(fixture.async.persisted), len(fixture.async.writes))
	}
	view := fixture.manager.views[ref.ViewID]
	if view == nil || view.replicaMsg[MsgVotePrepare] != nil {
		t.Fatal("WAL failure cached a VotePrepare carrying a signature")
	}
	if view.phaseAsReplica != PhasePrepare {
		t.Fatalf("replica phase after WAL failure = %d, want PhasePrepare", view.phaseAsReplica)
	}
}

func TestFHSHighQCCatchupLatestRequestWinsAndStaleResultCannotApply(t *testing.T) {
	fixture := newFHSAsyncValidationFixture(t)
	makeQC := func(number uint64, marker byte) *SignedState {
		return &SignedState{
			State:    []byte{marker},
			ViewID:   common.BytesToHash([]byte{marker, 1}),
			LeaderID: fmt.Sprintf("leader-%d", marker),
			Number:   number,
		}
	}
	first := makeQC(12, 1)
	second := makeQC(13, 2)
	if err := fixture.manager.scheduleFHSHighQCCatchup(first, 13, nil, common.Hash{}); !errors.Is(err, ErrProposalValidationPending) {
		t.Fatalf("first HighQC schedule error = %v, want %v", err, ErrProposalValidationPending)
	}
	if err := fixture.manager.scheduleFHSHighQCCatchup(first, 13, nil, common.Hash{}); !errors.Is(err, ErrProposalValidationPending) {
		t.Fatalf("duplicate HighQC schedule error = %v, want %v", err, ErrProposalValidationPending)
	}
	if len(fixture.async.highScheduled) != 1 {
		t.Fatalf("duplicate HighQC scheduled %d workers, want 1", len(fixture.async.highScheduled))
	}
	firstKey := fixture.async.highScheduled[0].Key
	if err := fixture.manager.scheduleFHSHighQCCatchup(second, 14, nil, common.Hash{}); !errors.Is(err, ErrProposalValidationPending) {
		t.Fatalf("newer HighQC schedule error = %v, want %v", err, ErrProposalValidationPending)
	}
	if len(fixture.async.highScheduled) != 2 {
		t.Fatalf("newer HighQC schedules = %d, want 2", len(fixture.async.highScheduled))
	}
	secondKey := fixture.async.highScheduled[1].Key
	if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: firstKey, ApplicationData: "stale"}); !errors.Is(err, ErrOldState) {
		t.Fatalf("stale HighQC result error = %v, want %v", err, ErrOldState)
	}
	if len(fixture.async.highApplied) != 0 || fixture.async.adoptCalls != 0 {
		t.Fatalf("stale HighQC published state: async=%d sync=%d", len(fixture.async.highApplied), fixture.async.adoptCalls)
	}
	if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: secondKey, ApplicationData: "verified"}); err != nil {
		t.Fatalf("current HighQC result rejected: %v", err)
	}
	if len(fixture.async.highApplied) != 1 || !SignedStateSemanticEqual(fixture.async.highest, second) {
		t.Fatalf("current HighQC apply count=%d highest=%#v", len(fixture.async.highApplied), fixture.async.highest)
	}
	if got, want := fmt.Sprint(fixture.async.highEvents), fmt.Sprint([]string{"apply", "finish"}); got != want {
		t.Fatalf("HighQC publication events = %s, want %s", got, want)
	}
}

func TestFHSHighQCApplyOldStateImmediatelyReschedulesRetainedNewView(t *testing.T) {
	fixture := newFHSAsyncValidationFixture(t)
	qc := fixture.parentQC(t, 11, true)
	msg := fixture.newViewMessage(t, 12, nil, qc)
	if err := fixture.manager.HandleMessage(msg); !errors.Is(err, ErrProposalValidationPending) {
		t.Fatalf("initial NewView result = %v, want %v", err, ErrProposalValidationPending)
	}
	if len(fixture.async.highScheduled) != 1 {
		t.Fatalf("initial HighQC schedules = %d, want 1", len(fixture.async.highScheduled))
	}
	first := fixture.async.highScheduled[0]
	fixture.async.highApplyErr = fmt.Errorf("canonical base advanced: %w", ErrOldState)
	if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: first.Key}); !errors.Is(err, ErrOldState) {
		t.Fatalf("stale HighQC apply result = %v, want %v", err, ErrOldState)
	}
	if len(fixture.async.highScheduled) != 2 {
		t.Fatalf("stale HighQC apply schedules = %d, want immediate retry", len(fixture.async.highScheduled))
	}
	second := fixture.async.highScheduled[1]
	if second.Key == first.Key || fixture.manager.pendingHighQC == nil || fixture.manager.pendingHighQC.key != second.Key ||
		len(fixture.manager.pendingHighQC.messages) != 1 {
		t.Fatalf("retry did not retain exact continuation: first=%#v second=%#v pending=%#v", first.Key, second.Key, fixture.manager.pendingHighQC)
	}

	fixture.async.highApplyErr = nil
	if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: second.Key}); err != nil {
		t.Fatalf("fresh HighQC retry result: %v", err)
	}
	view := fixture.manager.views[msg.ViewId]
	if view == nil || len(view.fhsReports) != 1 || view.fhsReports[0] == nil {
		t.Fatalf("retained NewView was not accepted after retry: view=%#v", view)
	}
	if fixture.manager.pendingHighQC != nil {
		t.Fatalf("completed retry retained pending HighQC: %#v", fixture.manager.pendingHighQC)
	}
}

func TestFHSHighQCWorkerOldStateImmediatelyReschedulesRetainedNewView(t *testing.T) {
	fixture := newFHSAsyncValidationFixture(t)
	qc := fixture.parentQC(t, 11, true)
	msg := fixture.newViewMessage(t, 12, nil, qc)
	if err := fixture.manager.HandleMessage(msg); !errors.Is(err, ErrProposalValidationPending) {
		t.Fatalf("initial NewView result = %v, want %v", err, ErrProposalValidationPending)
	}
	first := fixture.async.highScheduled[0]
	workerErr := fmt.Errorf("staging base advanced: %w", ErrOldState)
	if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: first.Key, Err: workerErr}); !errors.Is(err, ErrOldState) {
		t.Fatalf("stale worker result = %v, want %v", err, ErrOldState)
	}
	if len(fixture.async.highApplied) != 0 || len(fixture.async.highScheduled) != 2 ||
		fixture.manager.pendingHighQC == nil || len(fixture.manager.pendingHighQC.messages) != 1 {
		t.Fatalf("stale worker retry state: applied=%d scheduled=%d pending=%#v",
			len(fixture.async.highApplied), len(fixture.async.highScheduled), fixture.manager.pendingHighQC)
	}
}

func TestFHSHighQCContinuationDeduplicatesSemanticSigner(t *testing.T) {
	pending := &pendingFHSHighQCValidation{leaderViews: make(map[common.Hash]struct{})}
	first := &HotstuffMessage{
		Code: MsgNewView, Number: 12, ViewId: common.HexToHash("0xc101"), Id: "member-0",
		PubKey: []byte{1}, DataA: []byte("first-proof"), AuthSig: []byte{2},
	}
	alternativeWire := cloneFHSPrepare(first)
	alternativeWire.DataA = []byte("same-view-alternative-certificate-encoding")
	alternativeWire.DataB = []byte("different-report-signature")
	alternativeWire.AuthSig = []byte("different-envelope-signature")
	if err := appendFHSHighQCContinuation(pending, first, common.Hash{}); err != nil {
		t.Fatal(err)
	}
	if err := appendFHSHighQCContinuation(pending, alternativeWire, common.Hash{}); err != nil {
		t.Fatal(err)
	}
	if len(pending.messages) != 1 || !sameFHSPrepare(pending.messages[0], first) {
		t.Fatalf("semantic duplicate retained or replaced first continuation: %#v", pending.messages)
	}

	differentSigner := cloneFHSPrepare(alternativeWire)
	differentSigner.Id = "member-1"
	if err := appendFHSHighQCContinuation(pending, differentSigner, common.Hash{}); err != nil {
		t.Fatal(err)
	}
	if len(pending.messages) != 2 {
		t.Fatalf("different signer continuation count = %d, want 2", len(pending.messages))
	}
}

func TestFHSHighQCContinuationReplacesOnlyStrictlyNewerSignerView(t *testing.T) {
	pending := &pendingFHSHighQCValidation{leaderViews: make(map[common.Hash]struct{})}
	first := &HotstuffMessage{Code: MsgNewView, Number: 12, ViewId: common.HexToHash("0xc201"), Id: "member-0", PubKey: []byte{1}}
	sameHeight := &HotstuffMessage{Code: MsgNewView, Number: 12, ViewId: common.HexToHash("0xffff"), Id: "member-0", PubKey: []byte{1}}
	newer := &HotstuffMessage{Code: MsgNewView, Number: 13, ViewId: common.HexToHash("0xc202"), Id: "member-0", PubKey: []byte{1}}
	older := &HotstuffMessage{Code: MsgNewView, Number: 11, ViewId: common.HexToHash("0xc200"), Id: "member-0", PubKey: []byte{1}}
	for _, msg := range []*HotstuffMessage{first, sameHeight, newer, older} {
		if err := appendFHSHighQCContinuation(pending, msg, common.Hash{}); err != nil {
			t.Fatal(err)
		}
	}
	if len(pending.messages) != 1 || pending.messages[0].Number != newer.Number || pending.messages[0].ViewId != newer.ViewId {
		t.Fatalf("signer slot did not retain strictly newest view: %#v", pending.messages)
	}
}

func TestFHSHighQCSameQCNewerCurrentViewCoalescesWorker(t *testing.T) {
	fixture := newFHSAsyncValidationFixture(t)
	qc := fixture.parentQC(t, 11, true)
	firstMsg := fixture.newViewMessageFrom(t, 0, 12, nil, qc)
	if err := fixture.manager.HandleMessage(firstMsg); !errors.Is(err, ErrProposalValidationPending) {
		t.Fatalf("initial NewView result = %v, want %v", err, ErrProposalValidationPending)
	}
	request := fixture.async.highScheduled[0]

	// Model an independently proven pacemaker advance while the same QC body is
	// still being validated. The newer view must replace the signer's retained
	// continuation without cancelling/restarting identical QC work.
	fixture.async.current = 12
	newerMsg := fixture.newViewMessageFrom(t, 0, 13, nil, qc)
	if err := fixture.manager.HandleMessage(newerMsg); !errors.Is(err, ErrProposalValidationPending) {
		t.Fatalf("newer same-QC NewView result = %v, want %v", err, ErrProposalValidationPending)
	}
	if len(fixture.async.highScheduled) != 1 || fixture.manager.pendingHighQC == nil ||
		fixture.manager.pendingHighQC.key != request.Key || len(fixture.manager.pendingHighQC.messages) != 1 ||
		fixture.manager.pendingHighQC.messages[0].Number != 13 {
		t.Fatalf("same QC restarted worker or retained stale view: scheduled=%d pending=%#v",
			len(fixture.async.highScheduled), fixture.manager.pendingHighQC)
	}
	if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: request.Key}); err != nil {
		t.Fatalf("coalesced HighQC result: %v", err)
	}
	view := fixture.manager.views[newerMsg.ViewId]
	if view == nil || len(view.fhsReports) != 1 || view.fhsReports[0] == nil {
		t.Fatalf("newer retained NewView was not replayed: %#v", view)
	}
}

func TestFHSNewViewCrossViewCannotChurnHighQCWorker(t *testing.T) {
	fixture := newFHSAsyncValidationFixture(t)
	qc := fixture.parentQC(t, 11, true)
	initial := fixture.newViewMessageFrom(t, 0, 12, nil, qc)
	if err := fixture.manager.HandleMessage(initial); !errors.Is(err, ErrProposalValidationPending) {
		t.Fatalf("initial NewView result = %v, want %v", err, ErrProposalValidationPending)
	}
	for target := uint64(13); target <= 19; target++ {
		msg := fixture.newViewMessageFrom(t, 0, target, nil, qc)
		if err := fixture.manager.HandleMessage(msg); !errors.Is(err, ErrFutureState) {
			t.Fatalf("unproven target %d result = %v, want %v", target, err, ErrFutureState)
		}
	}
	if len(fixture.async.highScheduled) != 1 || fixture.manager.pendingHighQC == nil ||
		len(fixture.manager.pendingHighQC.messages) != 1 || fixture.manager.pendingHighQC.messages[0].Number != 12 {
		t.Fatalf("cross-view input churned HighQC work: scheduled=%d pending=%#v",
			len(fixture.async.highScheduled), fixture.manager.pendingHighQC)
	}
}

func TestFHSNewViewImmediateParentQCMayScheduleFutureCatchup(t *testing.T) {
	fixture := newFHSAsyncValidationFixture(t)
	qc := fixture.parentQC(t, 12, true)
	msg := fixture.newViewMessageFrom(t, 0, 13, nil, qc)
	if err := fixture.manager.HandleMessage(msg); !errors.Is(err, ErrProposalValidationPending) {
		t.Fatalf("directly certified future target result = %v, want %v", err, ErrProposalValidationPending)
	}
	if len(fixture.async.highScheduled) != 1 || fixture.manager.pendingHighQC == nil || fixture.manager.pendingHighQC.key.TargetView != 13 {
		t.Fatalf("direct parent QC did not schedule bounded catch-up: scheduled=%d pending=%#v",
			len(fixture.async.highScheduled), fixture.manager.pendingHighQC)
	}
}

func TestFHSPrepareGatesFutureTargetBeforeHighQCSchedule(t *testing.T) {
	fixture := newFHSAsyncValidationFixture(t)
	qc := fixture.parentQC(t, 11, true)
	target := uint64(13)
	ctx := FHSViewContext{
		Version: fhsWireVersion, ChainID: fixture.async.ChainID(), TargetView: target,
		KeyNumber: fixture.async.keyNumber, KeyHash: fixture.async.keyHash,
		CommitteeHash: fixture.async.committeeHash, LeaderID: fixture.async.Self(), EntryKind: FHSViewFromQC,
	}
	aggregate := aggregateReportsWithHighQC(t, fixture.secrets, ctx, []*SignedState{qc, qc, qc})
	encodedAggregate, err := EncodeAggregateQC(aggregate)
	if err != nil {
		t.Fatal(err)
	}
	encodedQC, err := EncodeSignedState(qc)
	if err != nil {
		t.Fatal(err)
	}
	qcID, err := SignedStateID(qc)
	if err != nil {
		t.Fatal(err)
	}
	extra := []byte("future-prepare")
	ref := &types.HotstuffProposalRef{
		Version: types.HotstuffProposalRefVersion, ChainID: fixture.async.ChainID(), Number: 37,
		ViewNumber: target, ViewID: ctx.ID(), LeaderID: fixture.async.Self(), ParentQCID: qcID.Hash(),
		BlockHash: common.HexToHash("0x5700"), ParentHash: common.HexToHash("0x5600"),
		BodyHash: common.HexToHash("0x5701"), BodySize: 1, ExtraHash: types.HotstuffProposalExtraHash(extra), KeyHash: fixture.async.keyHash,
	}
	msg := &HotstuffMessage{
		Code: MsgPrepare, Number: target, ViewId: ctx.ID(), DataB: ref.EncodeToBytes(),
		DataC: encodedAggregate, DataF: extra, DataG: encodedQC,
	}
	fixture.authenticate(t, 3, msg)
	if err := fixture.manager.handleFHSPrepareMsg(msg); !errors.Is(err, ErrFutureState) {
		t.Fatalf("unproven future Prepare result = %v, want %v", err, ErrFutureState)
	}
	if len(fixture.async.highScheduled) != 0 || fixture.manager.pendingHighQC != nil {
		t.Fatalf("future Prepare scheduled HighQC before target gate: scheduled=%d pending=%#v",
			len(fixture.async.highScheduled), fixture.manager.pendingHighQC)
	}
}

func TestFHSPrepareWithoutHighestRetainedBehindActiveHighQC(t *testing.T) {
	fixture := newFHSAsyncValidationFixture(t)
	_, msg := fixture.prepare(t) // genesis-style aggregate has no HighestQC
	fixture.manager.pendingHighQC = &pendingFHSHighQCValidation{
		key:         FHSHighQCValidationKey{RequestID: 91, QCID: common.HexToHash("0x9100"), TargetView: msg.Number},
		qc:          fixture.parentQC(t, 10, true),
		leaderViews: make(map[common.Hash]struct{}),
	}
	if err := fixture.manager.handleFHSPrepareMsg(msg); !errors.Is(err, ErrProposalValidationPending) {
		t.Fatalf("Prepare behind active HighQC = %v, want %v", err, ErrProposalValidationPending)
	}
	if len(fixture.async.scheduled) != 0 || len(fixture.manager.pendingHighQC.messages) != 1 ||
		!sameFHSPrepare(fixture.manager.pendingHighQC.messages[0], msg) {
		t.Fatalf("Prepare was scheduled or lost instead of retained: scheduled=%d pending=%#v",
			len(fixture.async.scheduled), fixture.manager.pendingHighQC)
	}
}

func TestFHSHighQCContinuationAggregateBytesBounded(t *testing.T) {
	pending := &pendingFHSHighQCValidation{leaderViews: make(map[common.Hash]struct{})}
	payload := bytes.Repeat([]byte{0x5a}, MaxHotstuffControlBytes/3)
	used := 0
	for index := 0; index < maxPendingNewViewsPerID; index++ {
		msg := &HotstuffMessage{
			Code: MsgNewView, Number: 12, ViewId: common.HexToHash("0xc102"), Id: fmt.Sprintf("member-%d", index),
			PubKey: []byte{1}, DataA: payload, AuthSig: []byte{2},
		}
		if err := ValidateHotstuffWireMessage(msg); err != nil {
			t.Fatalf("fixture message %d exceeds its independent wire bound: %v", index, err)
		}
		encoded := cloneFHSPrepare(msg)
		encoded.ReceivedAt = time.Time{}
		wire, err := rlp.EncodeToBytes(encoded)
		if err != nil {
			t.Fatal(err)
		}
		before := len(pending.messages)
		err = appendFHSHighQCContinuation(pending, msg, common.Hash{})
		if len(wire) > maxFHSHighQCContinuationBytes-used {
			if err == nil {
				t.Fatal("aggregate continuation byte limit accepted overflowing message")
			}
			if len(pending.messages) != before {
				t.Fatal("overflowing continuation mutated pending messages")
			}
			return
		}
		if err != nil {
			t.Fatalf("continuation %d rejected below aggregate byte limit: %v", index, err)
		}
		used += len(wire)
	}
	t.Fatal("test did not reach aggregate continuation byte limit")
}

func TestFHSHighQCSupersedeTransfersBoundedNewViewContinuations(t *testing.T) {
	fixture := newFHSAsyncValidationFixture(t)
	older := fixture.parentQC(t, 10, true)
	newer := fixture.parentQC(t, 11, true)
	firstMsg := fixture.newViewMessageFrom(t, 0, 12, nil, older)
	secondMsg := fixture.newViewMessageFrom(t, 1, 12, nil, newer)
	if err := fixture.manager.HandleMessage(firstMsg); !errors.Is(err, ErrProposalValidationPending) {
		t.Fatalf("older NewView result = %v, want %v", err, ErrProposalValidationPending)
	}
	first := fixture.async.highScheduled[0]
	if err := fixture.manager.HandleMessage(secondMsg); !errors.Is(err, ErrProposalValidationPending) {
		t.Fatalf("newer NewView result = %v, want %v", err, ErrProposalValidationPending)
	}
	if len(fixture.async.highScheduled) != 2 || fixture.manager.pendingHighQC == nil ||
		len(fixture.manager.pendingHighQC.messages) != 2 {
		t.Fatalf("supersede lost continuations: scheduled=%d pending=%#v", len(fixture.async.highScheduled), fixture.manager.pendingHighQC)
	}
	second := fixture.async.highScheduled[1]
	if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: first.Key}); !errors.Is(err, ErrOldState) {
		t.Fatalf("superseded worker result = %v, want %v", err, ErrOldState)
	}
	if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: second.Key}); err != nil {
		t.Fatalf("newer HighQC result: %v", err)
	}
	view := fixture.manager.views[firstMsg.ViewId]
	if view == nil || len(view.fhsReports) != 2 || view.fhsReports[0] == nil || view.fhsReports[1] == nil {
		t.Fatalf("superseded continuations were not both revalidated: view=%#v", view)
	}
}

func TestFHSHighQCSupersedeScheduleOldStateRestoresLiveRequest(t *testing.T) {
	fixture := newFHSAsyncValidationFixture(t)
	older := fixture.parentQC(t, 10, true)
	newer := fixture.parentQC(t, 11, true)
	if err := fixture.manager.scheduleFHSHighQCCatchup(older, 20, nil, common.Hash{}); !errors.Is(err, ErrProposalValidationPending) {
		t.Fatalf("older HighQC schedule = %v, want %v", err, ErrProposalValidationPending)
	}
	previous := fixture.manager.pendingHighQC
	if previous == nil || len(fixture.async.highScheduled) != 1 {
		t.Fatalf("older HighQC was not retained: pending=%#v scheduled=%d", previous, len(fixture.async.highScheduled))
	}

	resume := fixture.newViewMessageFrom(t, 0, 12, nil, newer)
	fixture.async.highScheduleErr = fmt.Errorf("active target is newer: %w", ErrOldState)
	if err := fixture.manager.scheduleFHSHighQCCatchup(newer, 12, resume, common.Hash{}); !errors.Is(err, ErrProposalValidationPending) {
		t.Fatalf("rejected supersede = %v, want retained %v", err, ErrProposalValidationPending)
	}
	if fixture.manager.pendingHighQC != previous || len(fixture.async.highScheduled) != 1 ||
		len(previous.messages) != 1 || !sameFHSPrepare(previous.messages[0], resume) {
		t.Fatalf("schedule rejection lost live request or continuation: pending=%#v scheduled=%d messages=%d",
			fixture.manager.pendingHighQC, len(fixture.async.highScheduled), len(previous.messages))
	}

	fixture.async.highScheduleErr = nil
	if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: previous.key}); err != nil {
		t.Fatalf("older HighQC completion did not replay retained continuation: %v", err)
	}
	if len(fixture.async.highScheduled) != 2 || fixture.manager.pendingHighQC == nil ||
		fixture.manager.pendingHighQC.key.QCID == previous.key.QCID {
		t.Fatalf("retained continuation did not schedule newer HighQC: scheduled=%d pending=%#v",
			len(fixture.async.highScheduled), fixture.manager.pendingHighQC)
	}
}

func TestFHSHighQCSupersedePreservesExistingRequestAtContinuationLimit(t *testing.T) {
	fixture := newFHSAsyncValidationFixture(t)
	older := fixture.parentQC(t, 10, true)
	newer := fixture.parentQC(t, 11, true)
	if err := fixture.manager.scheduleFHSHighQCCatchup(older, 12, nil, common.Hash{}); !errors.Is(err, ErrProposalValidationPending) {
		t.Fatalf("older HighQC schedule = %v, want %v", err, ErrProposalValidationPending)
	}
	previous := fixture.manager.pendingHighQC
	for index := 0; index < maxPendingNewViewsPerID; index++ {
		previous.messages = append(previous.messages, &HotstuffMessage{Code: MsgNewView, Number: uint64(index + 1), Id: fmt.Sprintf("sender-%d", index)})
	}
	overflow := &HotstuffMessage{Code: MsgNewView, Number: 12, Id: "overflow"}
	if err := fixture.manager.scheduleFHSHighQCCatchup(newer, 12, overflow, common.Hash{}); err == nil {
		t.Fatal("supersede accepted a continuation above the bound")
	}
	if fixture.manager.pendingHighQC != previous || len(fixture.manager.pendingHighQC.messages) != maxPendingNewViewsPerID ||
		len(fixture.async.highScheduled) != 1 {
		t.Fatalf("bounded supersede replaced or mutated live request: pending=%#v scheduled=%d",
			fixture.manager.pendingHighQC, len(fixture.async.highScheduled))
	}
}

func TestFHSHighQCStaleApplyDoesNotReplayAcrossEpochReset(t *testing.T) {
	fixture := newFHSAsyncValidationFixture(t)
	qc := fixture.parentQC(t, 11, true)
	msg := fixture.newViewMessage(t, 12, nil, qc)
	if err := fixture.manager.HandleMessage(msg); !errors.Is(err, ErrProposalValidationPending) {
		t.Fatalf("initial NewView result = %v, want %v", err, ErrProposalValidationPending)
	}
	request := fixture.async.highScheduled[0]
	fixture.async.highApplyErr = ErrOldState
	fixture.async.highApplyHook = fixture.manager.ScheduleFHSEpochReset
	if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: request.Key}); !errors.Is(err, ErrOldState) {
		t.Fatalf("epoch-reset stale apply result = %v, want %v", err, ErrOldState)
	}
	if len(fixture.async.highScheduled) != 1 || fixture.manager.pendingHighQC != nil || len(fixture.manager.views) != 0 ||
		atomic.LoadUint32(&fixture.manager.epochReset) != 0 {
		t.Fatalf("stale apply replayed across epoch reset: scheduled=%d pending=%#v views=%d reset=%d",
			len(fixture.async.highScheduled), fixture.manager.pendingHighQC, len(fixture.manager.views), atomic.LoadUint32(&fixture.manager.epochReset))
	}
}

func TestFHSHighQCHardErrorsDiscardContinuationsWithoutRetry(t *testing.T) {
	t.Run("worker", func(t *testing.T) {
		fixture := newFHSAsyncValidationFixture(t)
		qc := fixture.parentQC(t, 11, true)
		msg := fixture.newViewMessage(t, 12, nil, qc)
		if err := fixture.manager.HandleMessage(msg); !errors.Is(err, ErrProposalValidationPending) {
			t.Fatalf("initial NewView result = %v, want %v", err, ErrProposalValidationPending)
		}
		request := fixture.async.highScheduled[0]
		hardErr := errors.New("invalid staged certificate")
		if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: request.Key, Err: hardErr}); !errors.Is(err, hardErr) {
			t.Fatalf("hard worker result = %v, want %v", err, hardErr)
		}
		if len(fixture.async.highScheduled) != 1 || fixture.manager.pendingHighQC != nil || len(fixture.manager.views) != 0 {
			t.Fatalf("hard worker error retried continuation: scheduled=%d pending=%#v views=%d",
				len(fixture.async.highScheduled), fixture.manager.pendingHighQC, len(fixture.manager.views))
		}
	})

	t.Run("apply", func(t *testing.T) {
		fixture := newFHSAsyncValidationFixture(t)
		qc := fixture.parentQC(t, 11, true)
		msg := fixture.newViewMessage(t, 12, nil, qc)
		if err := fixture.manager.HandleMessage(msg); !errors.Is(err, ErrProposalValidationPending) {
			t.Fatalf("initial NewView result = %v, want %v", err, ErrProposalValidationPending)
		}
		request := fixture.async.highScheduled[0]
		fixture.async.highApplyErr = errors.New("invalid publication")
		if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: request.Key}); !errors.Is(err, ErrInvalidHighQC) {
			t.Fatalf("hard apply result = %v, want %v", err, ErrInvalidHighQC)
		}
		if len(fixture.async.highScheduled) != 1 || fixture.manager.pendingHighQC != nil || len(fixture.manager.views) != 0 {
			t.Fatalf("hard apply error retried continuation: scheduled=%d pending=%#v views=%d",
				len(fixture.async.highScheduled), fixture.manager.pendingHighQC, len(fixture.manager.views))
		}
	})
}

func TestFHSHighQCApplyEpochResetCompletesExactCertificate(t *testing.T) {
	fixture := newFHSAsyncValidationFixture(t)
	qc := &SignedState{
		State:    []byte("epoch-transition-qc"),
		ViewID:   common.HexToHash("0xe901"),
		LeaderID: "epoch-transition-leader",
		Number:   12,
	}
	certified := 0
	fixture.async.recoveryTestApp.onCertified = func(got *SignedState) error {
		fixture.async.highEvents = append(fixture.async.highEvents, "certified")
		certified++
		if !SignedStateSemanticEqual(got, qc) {
			t.Fatalf("certified QC = %#v, want exact applied QC", got)
		}
		return nil
	}
	fixture.async.highApplyHook = fixture.manager.ScheduleFHSEpochReset

	staleViewID := common.HexToHash("0xe902")
	staleView := &View{hash: staleViewID}
	fixture.manager.views[staleViewID] = staleView
	fixture.manager.leaderView = staleView
	fixture.manager.pendingNewView[staleViewID] = map[string]*HotstuffMessage{"stale": {Code: MsgNewView}}
	fixture.manager.unhandledMsg[staleViewID] = &HotstuffMessage{Code: MsgPrepare}
	fixture.manager.unhandledSize[staleViewID] = 1
	if err := fixture.manager.scheduleFHSHighQCCatchup(qc, qc.Number+1, nil, staleViewID); !errors.Is(err, ErrProposalValidationPending) {
		t.Fatalf("schedule epoch-transition HighQC = %v, want %v", err, ErrProposalValidationPending)
	}
	request := fixture.async.highScheduled[0]
	if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{
		Key: request.Key, ApplicationData: "verified",
	}); err != nil {
		t.Fatalf("complete epoch-transition HighQC: %v", err)
	}

	if certified != 1 {
		t.Fatalf("OnCertified calls = %d, want exact applied QC once", certified)
	}
	if got, want := fmt.Sprint(fixture.async.highEvents), fmt.Sprint([]string{"apply", "certified", "finish"}); got != want {
		t.Fatalf("HighQC publication events = %s, want %s", got, want)
	}
	if len(fixture.async.highApplied) != 1 || !SignedStateSemanticEqual(fixture.async.highest, qc) {
		t.Fatalf("applied HighQC count=%d highest=%#v, want exact QC once", len(fixture.async.highApplied), fixture.async.highest)
	}
	if fixture.manager.pendingHighQC != nil || len(fixture.manager.views) != 0 || fixture.manager.leaderView != nil ||
		len(fixture.manager.pendingNewView) != 0 || len(fixture.manager.unhandledMsg) != 0 || atomic.LoadUint32(&fixture.manager.epochReset) != 0 {
		t.Fatalf("old-epoch volatile state survived reset: pending=%v views=%d leader=%v newViews=%d unhandled=%d",
			fixture.manager.pendingHighQC, len(fixture.manager.views), fixture.manager.leaderView,
			len(fixture.manager.pendingNewView), len(fixture.manager.unhandledMsg))
	}
	if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: request.Key}); !errors.Is(err, ErrOldState) {
		t.Fatalf("duplicate HighQC result error = %v, want %v", err, ErrOldState)
	}
	if certified != 1 || len(fixture.async.highApplied) != 1 {
		t.Fatalf("duplicate HighQC result repeated completion: certified=%d applied=%d", certified, len(fixture.async.highApplied))
	}
}

func TestFHSHighQCApplyEpochResetCertificationFailureFinishesPublication(t *testing.T) {
	fixture := newFHSAsyncValidationFixture(t)
	qc := &SignedState{
		State:    []byte("epoch-transition-qc-failure"),
		ViewID:   common.HexToHash("0xe911"),
		LeaderID: "epoch-transition-leader",
		Number:   12,
	}
	certificationErr := errors.New("forced certification completion failure")
	fixture.async.recoveryTestApp.onCertified = func(*SignedState) error { return certificationErr }
	fixture.async.highApplyHook = fixture.manager.ScheduleFHSEpochReset
	if err := fixture.manager.scheduleFHSHighQCCatchup(qc, qc.Number+1, nil, common.Hash{}); !errors.Is(err, ErrProposalValidationPending) {
		t.Fatalf("schedule epoch-transition HighQC = %v, want %v", err, ErrProposalValidationPending)
	}
	request := fixture.async.highScheduled[0]
	err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: request.Key})
	if !errors.Is(err, certificationErr) {
		t.Fatalf("certification completion error = %v, want %v", err, certificationErr)
	}
	if got, want := fmt.Sprint(fixture.async.highEvents), fmt.Sprint([]string{"apply", "finish"}); got != want {
		t.Fatalf("failed certification publication events = %s, want %s", got, want)
	}
	if fixture.manager.pendingHighQC != nil {
		t.Fatal("failed certification retained a reset-epoch HighQC continuation")
	}
}

func newFHSFutureJumpFixture(t *testing.T, current uint64) *fhsFutureJumpFixture {
	t.Helper()
	secrets, keys := makeTestCommittee(t, 4)
	committee := &bftview.Committee{List: make([]*common.Cnode, len(keys))}
	memberIDs := make([]string, len(keys))
	for index, key := range keys {
		committee.List[index] = &common.Cnode{
			Address:  fmt.Sprintf("127.0.0.1:%d", 7100+index),
			CoinBase: fmt.Sprintf("coinbase-%d", index),
			Public:   key.SerializeToHexStr(),
		}
		memberIDs[index] = bftview.GetNodeID(committee.List[index].Address, committee.List[index].Public)
	}
	db := rawdb.NewMemoryDatabase()
	bftview.SetCommitteeConfig(db, nil, nil)
	keyHash := common.HexToHash("0xf001")
	if !bftview.WriteCommittee(3, keyHash, committee) {
		t.Fatal("write future-jump committee")
	}
	app := &fhsFutureJumpApp{
		recoveryTestApp: &recoveryTestApp{
			self:             memberIDs[3],
			fhs:              true,
			publicKeysByHash: map[common.Hash][]*bls.PublicKey{keyHash: keys},
		},
		current:       current,
		keyNumber:     3,
		keyHash:       keyHash,
		committeeHash: committee.RlpHash(),
		leaderID:      memberIDs[3],
	}
	return &fhsFutureJumpFixture{
		app: app, manager: NewHotstuffProtocolManager(app, &secrets[3], keys[3]),
		secrets: secrets, keys: keys, committee: committee, memberIDs: memberIDs,
	}
}

func (f *fhsFutureJumpFixture) timeoutCertificate(t *testing.T, timedOutView uint64) *TimeoutCertificate {
	t.Helper()
	statement := &TimeoutStatement{
		Version:       fhsWireVersion,
		ChainID:       f.app.ChainID(),
		TimedOutView:  timedOutView,
		KeyNumber:     f.app.keyNumber,
		KeyHash:       f.app.keyHash,
		CommitteeHash: f.app.committeeHash,
	}
	digest, err := TimeoutStatementDigest(statement)
	if err != nil {
		t.Fatal(err)
	}
	votes := make(map[int]*bls.Sign)
	for index := 0; index < CalcThreshold(len(f.keys)); index++ {
		signerDigest, err := fhsSignerDigest(digest, f.keys[index])
		if err != nil {
			t.Fatal(err)
		}
		votes[index] = f.secrets[index].SignHash(signerDigest)
	}
	tc, err := buildTimeoutCertificate(statement, votes, len(f.keys))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyTimeoutCertificate(tc, f.keys, CalcThreshold(len(f.keys))); err != nil {
		t.Fatalf("invalid future-jump TC fixture: %v", err)
	}
	return tc
}

func (f *fhsFutureJumpFixture) authenticate(t *testing.T, sender int, msg *HotstuffMessage) {
	t.Helper()
	msg.Id = f.memberIDs[sender]
	msg.PubKey = append([]byte(nil), f.keys[sender].Serialize()...)
	digest, err := MessageAuthDigest(f.app.ChainID(), msg)
	if err != nil {
		t.Fatal(err)
	}
	signature := f.secrets[sender].SignHash(digest)
	if signature == nil {
		t.Fatal("sign future-jump message envelope")
	}
	msg.AuthSig = signature.Serialize()
}

func (f *fhsFutureJumpFixture) timeoutQCMessage(t *testing.T, tc *TimeoutCertificate) *HotstuffMessage {
	t.Helper()
	encoded, err := rlp.EncodeToBytes(&tc.Statement)
	if err != nil {
		t.Fatal(err)
	}
	msg := &HotstuffMessage{
		Code: MsgTimeoutQC, Number: tc.Statement.TimedOutView, ViewId: tc.Statement.ID(),
		DataA: encoded, DataB: append([]byte(nil), tc.Sign...), DataC: append([]byte(nil), tc.Mask...),
	}
	f.authenticate(t, 0, msg)
	return msg
}

func (f *fhsFutureJumpFixture) newViewMessage(t *testing.T, target uint64, tc *TimeoutCertificate, highQC *SignedState) *HotstuffMessage {
	return f.newViewMessageFrom(t, 0, target, tc, highQC)
}

func (f *fhsFutureJumpFixture) newViewMessageFrom(t *testing.T, sender int, target uint64, tc *TimeoutCertificate, highQC *SignedState) *HotstuffMessage {
	t.Helper()
	if sender < 0 || sender >= len(f.secrets) {
		t.Fatalf("new-view sender index %d out of range", sender)
	}
	ctx := FHSViewContext{
		Version:       fhsWireVersion,
		ChainID:       f.app.ChainID(),
		TargetView:    target,
		KeyNumber:     f.app.keyNumber,
		KeyHash:       f.app.keyHash,
		CommitteeHash: f.app.committeeHash,
		LeaderID:      f.app.Self(),
		EntryKind:     FHSViewFromQC,
	}
	if tc != nil {
		ctx.EntryKind = FHSViewFromTimeout
		ctx.EntryID = tc.Statement.ID()
	}
	report := &NewViewReport{Context: ctx, SignerIndex: uint32(sender), HighQC: CloneSignedState(highQC)}
	encodedReport, err := EncodeNewViewReport(report)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := NewViewReportDigest(report)
	if err != nil {
		t.Fatal(err)
	}
	reportSignature := f.secrets[sender].SignHash(digest)
	msg := &HotstuffMessage{
		Code: MsgNewView, Number: target, ViewId: ctx.ID(),
		DataA: encodedReport, DataB: reportSignature.Serialize(),
	}
	if tc != nil {
		msg.DataD, err = EncodeTimeoutCertificate(tc)
		if err != nil {
			t.Fatal(err)
		}
	}
	f.authenticate(t, sender, msg)
	return msg
}

func (f *fhsFutureJumpFixture) parentQC(t *testing.T, view uint64, valid bool) *SignedState {
	t.Helper()
	viewID := common.BigToHash(new(big.Int).SetUint64(view))
	ref := &types.HotstuffProposalRef{
		Version: types.HotstuffProposalRefVersion, ChainID: f.app.ChainID(),
		Number: 37, ViewNumber: view, ViewID: viewID, LeaderID: f.memberIDs[0],
		BlockHash: common.HexToHash("0x3700"), ParentHash: common.HexToHash("0x3600"),
		BodyHash: common.HexToHash("0x3701"), BodySize: 1,
		ExtraHash: types.HotstuffProposalExtraHash(nil), KeyHash: f.app.keyHash,
	}
	state := ref.EncodeToBytes()
	signature := aggregateContextSignatures(t, f.secrets, []int{0, 1, 2}, f.app.ChainID(), MsgVotePrepare, viewID, ref.LeaderID, state)
	if !valid {
		signature[0] ^= 0xff
	}
	return &SignedState{State: state, Sign: signature, Mask: []byte{0x07}, ViewID: viewID, LeaderID: ref.LeaderID, Number: view}
}

func assertNoFutureProofMutation(t *testing.T, fixture *fhsFutureJumpFixture, current uint64) {
	t.Helper()
	manager := fixture.manager
	if fixture.app.current != current || fixture.app.acceptCalls != 0 || fixture.app.adoptCalls != 0 {
		t.Fatalf("invalid future proof mutated application: current=%d accept=%d adopt=%d",
			fixture.app.current, fixture.app.acceptCalls, fixture.app.adoptCalls)
	}
	if len(manager.pendingNewView) != 0 || len(manager.views) != 0 || len(manager.timeoutVotes) != 0 ||
		len(manager.timeoutQC) != 0 || len(manager.timeoutSeen) != 0 || len(manager.timeoutView) != 0 {
		t.Fatalf("invalid future proof mutated volatile maps: pending=%d views=%d votes=%d qc=%d seen=%d timeoutViews=%d",
			len(manager.pendingNewView), len(manager.views), len(manager.timeoutVotes), len(manager.timeoutQC),
			len(manager.timeoutSeen), len(manager.timeoutView))
	}
}

func TestFarFutureTimeoutQCJumpsAfterFullVerification(t *testing.T) {
	fixture := newFHSFutureJumpFixture(t, 100)
	tc := fixture.timeoutCertificate(t, 130)
	if err := fixture.manager.handleTimeoutQCMsg(fixture.timeoutQCMessage(t, tc)); err != nil {
		t.Fatalf("valid far-future timeout QC rejected: %v", err)
	}
	if fixture.app.current != 130 || fixture.app.acceptCalls != 1 {
		t.Fatalf("far TC did not advance application: current=%d accepts=%d", fixture.app.current, fixture.app.acceptCalls)
	}
	if fixture.manager.timeoutQC[tc.Statement.ID()] == nil {
		t.Fatal("verified far TC was not retained for recovery")
	}
}

func TestFarSingleTimeoutVoteRemainsBoundToExactCurrentView(t *testing.T) {
	fixture := newFHSFutureJumpFixture(t, 100)
	tc := fixture.timeoutCertificate(t, 130)
	msg := fixture.timeoutQCMessage(t, tc)
	msg.Code = MsgTimeout
	fixture.authenticate(t, 0, msg)
	if err := fixture.manager.handleTimeoutMsg(msg); err == nil {
		t.Fatal("far single timeout vote was accepted")
	}
	assertNoFutureProofMutation(t, fixture, 100)
}

func TestStaleTimeoutQCIsQuietNoOp(t *testing.T) {
	fixture := newFHSFutureJumpFixture(t, 130)
	tc := fixture.timeoutCertificate(t, 129)
	msg := fixture.timeoutQCMessage(t, tc)
	msg.DataB[0] ^= 0xff // stale path must not spend BLS work or publish state
	if err := fixture.manager.handleTimeoutQCMsg(msg); !errors.Is(err, ErrOldState) {
		t.Fatalf("stale timeout QC error = %v, want %v", err, ErrOldState)
	}
	assertNoFutureProofMutation(t, fixture, 130)
}

func TestInvalidFarFutureProofsHaveNoSideEffects(t *testing.T) {
	t.Run("timeout certificate", func(t *testing.T) {
		fixture := newFHSFutureJumpFixture(t, 100)
		tc := fixture.timeoutCertificate(t, 130)
		msg := fixture.timeoutQCMessage(t, tc)
		msg.DataB[0] ^= 0xff
		fixture.authenticate(t, 0, msg)
		if err := fixture.manager.handleTimeoutQCMsg(msg); err == nil {
			t.Fatal("invalid far timeout QC was accepted")
		}
		assertNoFutureProofMutation(t, fixture, 100)
	})

	t.Run("new-view timeout proof", func(t *testing.T) {
		fixture := newFHSFutureJumpFixture(t, 100)
		tc := fixture.timeoutCertificate(t, 129)
		tc.Sign[0] ^= 0xff
		msg := fixture.newViewMessage(t, 130, tc, nil)
		if err := fixture.manager.handleNewViewMsg(msg); err == nil {
			t.Fatal("new-view with invalid far TC was accepted")
		}
		assertNoFutureProofMutation(t, fixture, 100)
	})

	t.Run("new-view high QC", func(t *testing.T) {
		fixture := newFHSFutureJumpFixture(t, 100)
		msg := fixture.newViewMessage(t, 130, nil, fixture.parentQC(t, 101, false))
		if err := fixture.manager.handleNewViewMsg(msg); err == nil {
			t.Fatal("new-view with invalid far high QC was accepted")
		}
		assertNoFutureProofMutation(t, fixture, 100)
	})
}

func TestFarNewViewAppliesVerifiedTCBeforeHighQCCatchup(t *testing.T) {
	fixture := newFHSFutureJumpFixture(t, 100)
	fixture.app.adoptErr = errors.New("proposal body not available")
	tc := fixture.timeoutCertificate(t, 129)
	msg := fixture.newViewMessage(t, 130, tc, fixture.parentQC(t, 101, true))
	if err := fixture.manager.handleNewViewMsg(msg); err == nil {
		t.Fatal("injected high-QC catch-up failure was hidden")
	}
	if fixture.app.current != 129 || fixture.app.acceptCalls != 1 || fixture.app.adoptCalls != 1 {
		t.Fatalf("verified TC was not retained before QC catch-up failure: current=%d accepts=%d adopts=%d",
			fixture.app.current, fixture.app.acceptCalls, fixture.app.adoptCalls)
	}
	if len(fixture.app.events) != 2 || fixture.app.events[0] != "tc" || fixture.app.events[1] != "qc" {
		t.Fatalf("future proof application order = %v, want [tc qc]", fixture.app.events)
	}
	if len(fixture.manager.pendingNewView) != 0 || len(fixture.manager.views) != 0 {
		t.Fatal("failed high-QC catch-up stored an unvalidated future NewView")
	}
}

func TestFarNewViewWithoutTCStaysOutsideBoundedQueue(t *testing.T) {
	fixture := newFHSFutureJumpFixture(t, 100)
	msg := fixture.newViewMessage(t, 130, nil, nil)
	if err := fixture.manager.handleNewViewMsg(msg); err != ErrFutureState {
		t.Fatalf("far proofless NewView error = %v, want %v", err, ErrFutureState)
	}
	assertNoFutureProofMutation(t, fixture, 100)
}
