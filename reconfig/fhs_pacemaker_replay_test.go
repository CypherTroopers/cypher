package reconfig

import (
	"encoding/json"
	"math/big"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

func ageFHSDeadline(t *testing.T, timer *paceMakerTimer) time.Time {
	t.Helper()
	before := time.Now().Add(-2 * paceMakerTimeoutForConfig(timer.config))
	timer.mu.Lock()
	timer.startTime = before
	timer.mu.Unlock()
	return before
}

func TestFHSCachedCertificationReplayPreservesDeadlineAndVote(t *testing.T) {
	s, qc, _ := testFHSLifecycleCertification(t)
	timer := s.pacetMakerTimer
	timer.service, timer.config = s, s.chainConfig
	s.currentView.ViewNumber = qc.Number
	ref, err := types.DecodeHotstuffProposalRef(qc.State)
	if err != nil {
		t.Fatal(err)
	}
	// This is the already-authenticated cache continuation invoked after the
	// protocol verifies a QC; proof authentication has separate regressions.
	s.fhsCertifiedByID = map[common.Hash]*fhsCertifiedProposal{ref.ProposalID(): {ref: ref, qc: qc, verified: &core.VerifiedProposal{}}}
	s.fhsStore = &fhsSafetyStore{loaded: true, state: hotstuff.NewFHSSafetyState()}
	s.fhsStore.state.LastVote = &hotstuff.PersistedVote{ViewNumber: qc.Number + 1, ProposalID: common.HexToHash("0xabc")}
	safety := hotstuff.CloneFHSSafetyState(s.fhsStore.state)
	if err = s.OnCertified(qc); err != nil {
		t.Fatal(err)
	}
	before := ageFHSDeadline(t, timer)
	for i := 0; i < 16; i++ {
		if err = s.OnCertified(hotstuff.CloneSignedState(qc)); err != nil {
			t.Fatal(err)
		}
	}
	after, stopped, _, _ := timer.get()
	if stopped || !after.Equal(before) || time.Since(after) <= paceMakerTimeoutForConfig(timer.config) {
		t.Fatal("duplicate authenticated QC postponed the expired deadline")
	}
	if !reflect.DeepEqual(safety, s.fhsStore.state) {
		t.Fatal("timer repair changed durable vote state")
	}
	// Explicit lifecycle stop/start grants a new full interval, then replays
	// of the same recovered QC cannot keep renewing it.
	if err = timer.stop(); err != nil {
		t.Fatal(err)
	}
	if err = timer.start(); err != nil {
		t.Fatal(err)
	}
	restarted, _, _, _ := timer.get()
	if !restarted.After(before) {
		t.Fatal("restart did not grant a fresh deadline")
	}
	if err = s.OnCertified(qc); err != nil {
		t.Fatal(err)
	}
	after, _, _, _ = timer.get()
	if !after.Equal(restarted) {
		t.Fatal("recovered QC postponed lifecycle deadline")
	}
	atomic.StoreInt32(&s.runningState, 0)
	timer.stop()
	if err = s.OnCertified(qc); err == nil {
		t.Fatal("stopped service accepted late continuation")
	}
	_, stopped, _, _ = timer.get()
	if !stopped {
		t.Fatal("late continuation restarted stopped timer")
	}
}

func TestFHSValidatedProposalRetryPreservesDeadline(t *testing.T) {
	s, result := proposalValidationPublicationFixture()
	s.chainConfig = &params.ChainConfig{ChainID: big.NewInt(1), FairHotstuff: true}
	output := result.ApplicationData.(*proposalValidationOutput)
	block := types.NewBlockWithHeader(&types.Header{ParentHash: output.ref.ParentHash, Number: big.NewInt(2), Difficulty: big.NewInt(1)})
	output.ref.Number, output.ref.BlockHash = 2, block.Hash()
	parentRef := *output.ref
	parentRef.Number, parentRef.ViewNumber, parentRef.BlockHash = 1, 1, output.ref.ParentHash
	parent := &hotstuff.SignedState{Number: 1, ViewID: parentRef.ViewID, LeaderID: parentRef.LeaderID, State: parentRef.EncodeToBytes()}
	parentID, err := hotstuff.SignedStateID(parent)
	if err != nil {
		t.Fatal(err)
	}
	output.ref.ParentQCID, output.parentQC = parentID.Hash(), parent
	output.verified.Block, output.verified.ParentNumber = block, 1
	output.verified.ProposalID = output.ref.ProposalID()
	output.validationGeneration = 0 // No asynchronous worker is running in this publication test.
	s.currentView.TxHash = output.ref.ParentHash
	s.fhsParentSelected = true
	s.fhsSelectedParent = &fhsCertifiedProposal{ref: &parentRef, qc: parent}
	if err = s.installHotstuffProposalValidation(output); err != nil {
		t.Fatal(err)
	}
	before := ageFHSDeadline(t, s.pacetMakerTimer)
	for i := 0; i < 16; i++ {
		if err = s.installHotstuffProposalValidation(output); err != nil {
			t.Fatal(err)
		}
	}
	after, _, _, _ := s.pacetMakerTimer.get()
	if !after.Equal(before) {
		t.Fatal("revalidated same-view proposal postponed deadline before vote safety check")
	}
	if err = s.pacetMakerTimer.startForFHSProgress(output.ref.ViewNumber, true); err != nil {
		t.Fatal(err)
	}
	certified, _, _, _ := s.pacetMakerTimer.get()
	if !certified.After(before) {
		t.Fatal("new certification did not get a full interval")
	}
	if err = s.installHotstuffProposalValidation(output); err != nil {
		t.Fatal(err)
	}
	after, _, _, _ = s.pacetMakerTimer.get()
	if !after.Equal(certified) {
		t.Fatal("proposal replay regressed certification progress")
	}
}

func TestFHSPacemakerProgressConcurrentAndNewViews(t *testing.T) {
	timer := &paceMakerTimer{beStop: true}
	if err := timer.startForFHSProgress(10, true); err != nil {
		t.Fatal(err)
	}
	before := ageFHSDeadline(t, timer)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 32; j++ {
				_ = timer.startForFHSProgress(10, true)
				_ = timer.startForFHSProgress(9, false)
				timer.get()
			}
		}()
	}
	wg.Wait()
	after, _, _, _ := timer.get()
	if !after.Equal(before) {
		t.Fatal("concurrent duplicate/lower progress extended deadline")
	}
	if err := timer.startForFHSProgress(11, false); err != nil {
		t.Fatal(err)
	}
	after, _, _, _ = timer.get()
	if !after.After(before) {
		t.Fatal("new view did not rearm")
	}
	if err := timer.startForFHSProgress(10, true); err != nil {
		t.Fatal(err)
	}
	stale, _, _, _ := timer.get()
	if !stale.Equal(after) {
		t.Fatal("late QC reset a later-view proposal deadline")
	}
}

func TestFHSPacemakerDuplicateProgressStillEmitsTimeout(t *testing.T) {
	for _, heartbeat := range []bool{true, false} {
		t.Run(map[bool]string{true: "healthy_heartbeat", false: "missing_heartbeat"}[heartbeat], func(t *testing.T) {
			timer, _, priority := newFHSPacemakerEventFixture(t)
			s := timer.service.(*Service)
			msg := &hotstuff.HotstuffMessage{Code: hotstuff.MsgQCBroadcast, Number: 1, ViewId: common.HexToHash("0x1234")}
			s.observeHotstuffProgress(msg)
			if err := timer.startForFHSProgress(msg.Number, true); err != nil {
				t.Fatal(err)
			}
			before := ageFHSDeadline(t, timer)
			s.muHotstuffProgress.Lock()
			s.hotstuffProgressAt = before
			s.muHotstuffProgress.Unlock()
			if !heartbeat {
				// No network worker is running in this fixture.
				for _, ack := range s.netService.ackMap {
					ack.ackTm = before
				}
			}
			for i := 0; i < 16; i++ {
				s.observeHotstuffProgress(msg)
				if err := timer.startForFHSProgress(msg.Number, true); err != nil {
					t.Fatal(err)
				}
			}
			if !s.HotstuffProgressTime().Equal(before) {
				t.Fatal("duplicate QC refreshed the auxiliary ACK progress timestamp")
			}
			done := make(chan struct{})
			go func() { defer close(done); timer.loopTimer() }()
			defer func() { timer.close(); <-done }()
			select {
			case msg := <-priority:
				if msg == nil || msg.hMsg == nil || msg.hMsg.Code != hotstuff.MsgLocalTimeout {
					t.Fatalf("duplicate-progress deadline emitted %v, want FHS local timeout", msg)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("duplicate QC progress suppressed the real timer loop timeout")
			}
		})
	}
}

func TestFHSConfiguredDeadlineReadOnlyReport(t *testing.T) {
	path := os.Getenv("CYPHER_FHS_DEADLINE_CONFIG")
	if path == "" {
		t.Skip("opt-in read-only current config report")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var g core.Genesis
	if err = json.Unmarshal(raw, &g); err != nil || g.Config == nil {
		t.Fatal("decode genesis config", err)
	}
	t.Logf("chainID=%s native=%t body=%s repair=%s execution=%s total=%s", g.Config.ChainID, g.Config.NativeParallelEnabled(), proposalBodyWaitTimeoutForConfig(g.Config, g.Config.EffectiveMaxBlockBytes()), proposalRepairWaitTimeoutForConfig(g.Config, int(g.Config.NativeParallel.MaxTransactionsPerBlock)), nativeExecutionLeaseForConfig(g.Config), paceMakerTimeoutForConfig(g.Config))
}
