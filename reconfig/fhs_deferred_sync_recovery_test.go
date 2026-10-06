package reconfig

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

// The receiver restarts with only A's durable safety records, while another
// quorum has finalized sibling B. InsertChain verifies and executes B's real
// child proof; only physical NewView delivery is captured by the fixture.
func deferredSyncRecoveryFixture(t *testing.T, beforeRestart ...func(*Service, *convergenceFixture)) (*Service, *fhsSyncResumeApplication, *hotstuff.PersistedVote, *types.Block, *fhsCertifiedProposal) {
	t.Helper()
	f := newConvergenceFixture(t)
	s := f.replicas[0]
	a := f.proposal(t, nil, 10, 'a')
	b := f.proposal(t, nil, 20, 'b')
	c := f.proposal(t, b, 21, 'c')
	vote := &hotstuff.PersistedVote{ViewNumber: a.ref.ViewNumber, ViewID: a.ref.ViewID, LeaderID: a.ref.LeaderID,
		ProposalID: a.ref.ProposalID(), ProposalRef: a.ref.EncodeToBytes(), ProposalRefHash: hotstuff.StateDigest(a.ref.EncodeToBytes())}
	if err := s.PersistFHSVote(vote); err != nil {
		t.Fatal(err)
	}
	if err := s.adoptFHSHighQC(a.qc, false, false); err != nil {
		t.Fatal(err)
	}
	if err := rawdb.DeleteFHSProposal(s.fhsStore.db, a.ref.ProposalID()); err != nil {
		t.Fatal(err)
	}
	for _, configure := range beforeRestart {
		configure(s, f)
	}
	resetBranchSafetyRuntime(s)
	if err := s.loadFHSWAL(); err != nil {
		t.Fatal(err)
	}
	if !s.hasDeferredFHSRecovery() {
		t.Fatal("missing proposal content did not gate restarted consensus")
	}
	s.netService.serverID = s.netService.serverAddress
	s.pacetMakerTimer = &paceMakerTimer{service: s, beStop: true}
	s.hotstuffMsgQ = &hotstuffMessageQueue{priorityInput: make(chan *hotstuffMsg, 4)}
	s.fhsRecoveryWake = make(chan struct{}, 1)
	s.muLifecycle.Lock()
	s.lifecycleGenerationLocked()
	s.muLifecycle.Unlock()
	atomic.StoreUint64(&s.proposalValidationGeneration, 1)
	atomic.StoreInt32(&s.runningState, 1)
	// Tests step the same control-loop callback without asynchronous retries.
	atomic.StoreInt32(&s.fhsRecoveryRetryQueued, 1)
	committee := bftview.LoadMember(0, s.kbc.CurrentBlock().Hash(), true)
	committeeDB := rawdb.NewMemoryDatabase()
	bftview.SetCommitteeConfig(committeeDB, s.kbc, nil)
	if !bftview.WriteCommittee(0, s.kbc.CurrentBlock().Hash(), committee) {
		t.Fatal("restore independent committee database")
	}
	bftview.SetServerInfo(s.Self(), f.public[0].SerializeToHexStr())
	t.Cleanup(func() {
		atomic.StoreInt32(&s.runningState, 0)
		bftview.SetServerInfo("", "")
		bftview.SetCommitteeConfig(nil, nil, nil)
		committeeDB.Close()
	})
	app := &fhsSyncResumeApplication{Service: s}
	s.protocolMng = hotstuff.NewHotstuffProtocolManager(app, &f.keys[0], f.public[0])
	s.bc.SetFHSFinalizedSyncLifecycle(s.beforeFHSFinalizedSyncKeyCommit,
		s.waitFHSValidationPublication, s.afterFHSFinalizedSyncCommit, s.finishFHSFinalizedSyncKeyCommit)
	block := b.verified.Block.WithSeal(b.verified.Block.Header())
	block.SetFHSSignature(b.qc.Sign, b.qc.Mask, b.qc.ViewID, b.qc.LeaderID, b.qc.Number, b.ref.ExtraHash, b.ref.ParentQCID)
	proof, err := core.EncodeFHSCommitProof(&core.FHSCommitProof{QCs: []*hotstuff.SignedState{c.qc}})
	if err != nil {
		t.Fatal(err)
	}
	if err := block.SetFHSFinalityProof(proof); err != nil {
		t.Fatal(err)
	}
	return s, app, vote, block, c
}

func TestFHSDeferredRecoveryResumesAfterCanonicalSiblingSync(t *testing.T) {
	s, app, vote, block, child := deferredSyncRecoveryFixture(t)
	if n, err := s.bc.InsertChain(types.Blocks{block}); err != nil || n != 1 {
		t.Fatalf("full sync rejected finalized sibling: count=%d err=%v", n, err)
	}
	if len(app.sent) != 0 {
		t.Fatal("sync callback sent consensus traffic while chainmu was held")
	}
	s.attemptDeferredFHSRecovery()
	if s.hasDeferredFHSRecovery() {
		t.Fatal("finalized sibling left restarted validator permanently gated")
	}
	if s.GetCurrentView().TxHash != block.Hash() || s.bc.CurrentBlock().Hash() != block.Hash() {
		t.Fatal("recovery did not use the independently finalized execution parent")
	}
	state, _ := reloadBranchSafetyState(t, s)
	if !persistedVotesEqual(state.LastVote, vote) {
		t.Fatal("canonical recovery erased the durable anti-equivocation vote")
	}
	conflict := hotstuff.ClonePersistedVote(vote)
	conflictRef := *child.ref
	conflictRef.ViewNumber, conflictRef.ViewID, conflictRef.LeaderID = vote.ViewNumber, vote.ViewID, vote.LeaderID
	conflict.ProposalRef = conflictRef.EncodeToBytes()
	conflict.ProposalID = conflictRef.ProposalID()
	conflict.ProposalRefHash = hotstuff.StateDigest(conflict.ProposalRef)
	if err := s.PersistFHSVote(conflict); err == nil || errors.Is(err, errFHSRecoveryPending) {
		t.Fatalf("resumed validator did not retain vote safety: %v", err)
	}
	_, stopped, _, _ := s.pacetMakerTimer.get()
	if stopped {
		t.Fatal("canonical recovery did not restart pacemaker")
	}
	select {
	case queued := <-s.hotstuffMsgQ.priorityInput:
		if err := s.protocolMng.HandleMessage(queued.hMsg); err != nil {
			t.Fatalf("resume NewView failed: %v", err)
		}
	default:
		t.Fatal("canonical recovery did not resume consensus messaging")
	}
	if len(app.sent) != 1 || app.sent[0].msg.Code != hotstuff.MsgNewView {
		t.Fatal("recovered validator did not emit a signed NewView")
	}
	keys, err := s.GetPublicKey(s.GetCurrentView().KeyHash)
	if err != nil {
		t.Fatal(err)
	}
	if err := hotstuff.VerifyMessageAuth(s.ChainID(), app.sent[0].msg, s.Self(), keys[0]); err != nil {
		t.Fatalf("resumed NewView has an invalid validator signature: %v", err)
	}
	report, err := hotstuff.DecodeNewViewReport(app.sent[0].msg.DataA)
	if err != nil || report.HighQC == nil || report.HighQC.Number != block.SignInfo().ViewNumber {
		t.Fatalf("resumed NewView did not advertise canonical safety watermark: %v", err)
	}
	if err := s.validateFHSProposalParent(child.ref, report.HighQC); err != nil {
		t.Fatalf("resumed validator rejected a child of the canonical parent: %v", err)
	}
	freshVote := &hotstuff.PersistedVote{ViewNumber: child.ref.ViewNumber, ViewID: child.ref.ViewID, LeaderID: child.ref.LeaderID,
		ProposalID: child.ref.ProposalID(), ProposalRef: child.ref.EncodeToBytes(), ProposalRefHash: hotstuff.StateDigest(child.ref.EncodeToBytes())}
	if err := s.PersistFHSVote(freshVote); err != nil {
		t.Fatalf("canonical recovery did not restore voting readiness: %v", err)
	}
}

func TestFHSDeferredRecoveryRejectsInvalidSyncProof(t *testing.T) {
	s, app, vote, block, child := deferredSyncRecoveryFixture(t)
	invalidQC := hotstuff.CloneSignedState(child.qc)
	invalidQC.Sign[0] ^= 1
	proof, err := core.EncodeFHSCommitProof(&core.FHSCommitProof{QCs: []*hotstuff.SignedState{invalidQC}})
	if err != nil {
		t.Fatal(err)
	}
	if err := block.SetFHSFinalityProof(proof); err != nil {
		t.Fatal(err)
	}
	if _, err := s.bc.InsertChain(types.Blocks{block}); err == nil {
		t.Fatal("invalid sibling finality proof was imported")
	}
	s.attemptDeferredFHSRecovery()
	if !s.hasDeferredFHSRecovery() || s.bc.CurrentBlockN() != 0 || len(app.sent) != 0 {
		t.Fatal("unverified sibling released the consensus recovery gate")
	}
	state, _ := reloadBranchSafetyState(t, s)
	if !persistedVotesEqual(state.LastVote, vote) {
		t.Fatal("rejected sync changed the anti-equivocation watermark")
	}
}

func TestFHSDeferredRecoveryWaitsForSyncRoutePublication(t *testing.T) {
	s, app, _, block, _ := deferredSyncRecoveryFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	s.bc.SetFHSFinalizedSyncLifecycle(s.beforeFHSFinalizedSyncKeyCommit, s.waitFHSValidationPublication,
		func(block *types.Block, ownQC, childQC *hotstuff.SignedState) error {
			close(entered)
			<-release
			return s.afterFHSFinalizedSyncCommit(block, ownQC, childQC)
		}, s.finishFHSFinalizedSyncKeyCommit)
	done := make(chan error, 1)
	go func() {
		_, err := s.bc.InsertChain(types.Blocks{block})
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("sync did not reach the canonical-to-runtime publication window")
	}
	if completed, err := s.completeCanonicalFHSRecovery(); err != nil || completed || !s.hasDeferredFHSRecovery() || len(app.sent) != 0 {
		t.Fatalf("canonical head alone bypassed incomplete sync publication: completed=%t err=%v", completed, err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	s.attemptDeferredFHSRecovery()
	if s.hasDeferredFHSRecovery() || s.GetCurrentView().TxHash != block.Hash() {
		t.Fatal("completed sync route was not resumed")
	}
}

func TestFHSDeferredRecoveryKeepsGateOnCanonicalWALFailure(t *testing.T) {
	s, app, vote, block, _ := deferredSyncRecoveryFixture(t)
	before, _ := reloadBranchSafetyState(t, s)
	s.fhsStore.db = &failingSyncStore{KeyValueStore: s.fhsStore.db}
	if _, err := s.bc.InsertChain(types.Blocks{block}); err == nil {
		t.Fatal("injected canonical watermark fsync failure was ignored")
	}
	if s.bc.CurrentBlock().Hash() != block.Hash() {
		t.Fatal("fixture did not reach the post-canonical WAL failure window")
	}
	s.attemptDeferredFHSRecovery()
	if !s.hasDeferredFHSRecovery() || len(app.sent) != 0 {
		t.Fatal("undurable canonical watermark released the recovery gate")
	}
	state, _ := reloadBranchSafetyState(t, s)
	if !persistedVotesEqual(state.LastVote, vote) || !hotstuff.SignedStateSemanticEqual(state.HighestQC, before.HighestQC) {
		t.Fatal("failed WAL reconciliation changed durable safety watermarks")
	}
}

func TestFHSDeferredRecoveryRetainsHigherTimeoutWatermarks(t *testing.T) {
	var pending hotstuff.TimeoutStatement
	var tc *hotstuff.TimeoutCertificate
	s, _, vote, block, _ := deferredSyncRecoveryFixture(t, func(s *Service, f *convergenceFixture) {
		current := s.GetCurrentView()
		statement := hotstuff.TimeoutStatement{Version: hotstuff.NewFHSSafetyState().Version,
			ChainID: s.ChainID(), TimedOutView: 30, KeyNumber: current.KeyNumber,
			KeyHash: current.KeyHash, CommitteeHash: current.CommitteeHash}
		tc = fhsEpochTestTC(t, statement, f.keys, f.public)
		if err := s.AcceptFHSTimeoutCertificate(tc); err != nil {
			t.Fatal(err)
		}
		pending = statement
		pending.TimedOutView++
		if err := s.PersistFHSTimeoutVote(&pending); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := s.bc.InsertChain(types.Blocks{block}); err != nil {
		t.Fatal(err)
	}
	s.attemptDeferredFHSRecovery()
	if s.hasDeferredFHSRecovery() || s.GetCurrentView().ViewNumber != tc.Statement.TimedOutView {
		t.Fatal("canonical recovery discarded the newer certified timeout view")
	}
	state, _ := reloadBranchSafetyState(t, s)
	if !persistedVotesEqual(state.LastVote, vote) || state.HighestTC == nil || state.HighestTC.Statement != tc.Statement ||
		state.LastTimeoutView != tc.Statement.TimedOutView || state.LastTimeoutVote == nil || *state.LastTimeoutVote != pending {
		t.Fatal("lower canonical QC erased newer durable timeout/vote watermarks")
	}
	select {
	case queued := <-s.hotstuffMsgQ.priorityInput:
		if queued.hMsg.Code != hotstuff.MsgLocalTimeout {
			t.Fatal("pending timeout recovery resumed ordinary NewView instead of its durable timeout")
		}
	default:
		t.Fatal("retained pending timeout was not resumed")
	}
}

func TestFHSDeferredRecoveryRejectsLateSupersededBodyResult(t *testing.T) {
	var donorBody *proposalBodyMsg
	var oldQC *hotstuff.SignedState
	s, _, _, block, _ := deferredSyncRecoveryFixture(t, func(s *Service, f *convergenceFixture) {
		oldQC = s.HighestCertified()
		ref, err := types.DecodeHotstuffProposalRef(oldQC.State)
		if err != nil {
			t.Fatal(err)
		}
		donorBody = cloneProposalBodyMsg(f.replicas[1].getProposalBody(ref.ProposalID()))
	})
	// DA completes, but the control loop has not yet consumed its executed
	// HighQC result when proof-aware full sync commits the competing branch.
	if err := s.storeProposalBody(donorBody); err != nil {
		t.Fatal(err)
	}
	s.proposalValidationJobs = make(chan *proposalValidationJob, 1)
	s.highQCValidationResults = make(chan *hotstuff.FHSHighQCValidationResult, 1)
	done := make(chan struct{})
	go func() {
		s.proposalValidationWorker()
		close(done)
	}()
	t.Cleanup(func() {
		s.cancelAllProposalValidations()
		close(s.proposalValidationJobs)
		<-done
	})
	if err := s.protocolMng.RecoverFHSHighQC(oldQC, oldQC.Number+1); !errors.Is(err, hotstuff.ErrProposalValidationPending) {
		t.Fatalf("deferred body worker was not scheduled: %v", err)
	}
	var result *hotstuff.FHSHighQCValidationResult
	select {
	case result = <-s.highQCValidationResults:
		if result.Err != nil {
			t.Fatalf("old branch body did not execute before sync: %v", result.Err)
		}
	case <-time.After(time.Second):
		t.Fatal("old body validation did not finish")
	}
	if _, err := s.bc.InsertChain(types.Blocks{block}); err != nil {
		t.Fatal(err)
	}
	s.attemptDeferredFHSRecovery()
	if s.hasDeferredFHSRecovery() {
		t.Fatal("canonical supersession did not complete recovery")
	}
	if err := s.protocolMng.HandleFHSHighQCValidationResult(result); !errors.Is(err, hotstuff.ErrOldState) {
		t.Fatalf("late superseded branch result was not rejected: %v", err)
	}
	if s.hasDeferredFHSRecovery() || s.GetCurrentView().TxHash != block.Hash() || s.bc.CurrentBlock().Hash() != block.Hash() ||
		s.HighestCertified().Number != block.SignInfo().ViewNumber {
		t.Fatal("late body result revived the abandoned branch or recovery gate")
	}
}
