package reconfig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/trie"
)

func testProposalValidationRequest(view uint64, discriminator byte) *hotstuff.FHSProposalValidationRequest {
	viewID := common.BytesToHash([]byte{discriminator, 1})
	ref := &types.HotstuffProposalRef{
		Version:    types.HotstuffProposalRefVersion,
		ChainID:    99,
		Number:     view,
		ViewNumber: view,
		ViewID:     viewID,
		LeaderID:   fmt.Sprintf("leader-%d", discriminator),
		BlockHash:  common.BytesToHash([]byte{discriminator, 2}),
		ParentHash: common.BytesToHash([]byte{discriminator, 3}),
		BodyHash:   common.BytesToHash([]byte{discriminator, 4}),
		BodySize:   1,
		ExtraHash:  types.HotstuffProposalExtraHash(nil),
		KeyHash:    common.BytesToHash([]byte{discriminator, 5}),
	}
	return &hotstuff.FHSProposalValidationRequest{
		Key: hotstuff.FHSProposalValidationKey{
			RequestID:  uint64(discriminator),
			ViewNumber: view,
			ViewID:     viewID,
			LeaderID:   ref.LeaderID,
			ProposalID: ref.ProposalID(),
		},
		ProposalRef: ref.EncodeToBytes(),
	}
}

func testProposalValidationService() *Service {
	return &Service{
		runningState:                 1,
		proposalValidationGeneration: 1,
		proposalValidationJobs:       make(chan *proposalValidationJob, proposalValidationQueueCapacity),
		proposalValidationResults:    make(chan *hotstuff.FHSProposalValidationResult, proposalValidationWorkers+1),
		highQCValidationResults:      make(chan *hotstuff.FHSHighQCValidationResult, proposalValidationWorkers+1),
		activeProposalValidations:    make(map[common.Hash]*proposalValidationControl),
		fhsCertifiedByHash:           make(map[common.Hash]*fhsCertifiedProposal),
	}
}

func testHighQCValidationRequest(number, target uint64, discriminator byte) *hotstuff.FHSHighQCValidationRequest {
	qc := &hotstuff.SignedState{
		State:    []byte{discriminator},
		ViewID:   common.BytesToHash([]byte{discriminator, 11}),
		LeaderID: fmt.Sprintf("leader-%d", discriminator),
		Number:   number,
	}
	id, _ := hotstuff.SignedStateID(qc)
	return &hotstuff.FHSHighQCValidationRequest{
		Key: hotstuff.FHSHighQCValidationKey{RequestID: uint64(discriminator), QCID: id.Hash(), TargetView: target},
		QC:  qc,
	}
}

func TestHotstuffControlLoopDoesNotCancelProposalFromUnverifiedNumber(t *testing.T) {
	source, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatal(err)
	}
	loopStart := bytes.Index(source, []byte("func (s *Service) handleHotStuffMsg()"))
	if loopStart < 0 {
		t.Fatal("could not locate serialized HotStuff message handler")
	}
	handleCall := bytes.Index(source[loopStart:], []byte("err := s.protocolMng.HandleMessage(msg.hMsg)"))
	if handleCall < 0 {
		t.Fatal("could not locate serialized HotStuff message handler")
	}
	beforeVerifiedHandle := source[loopStart : loopStart+handleCall]
	if bytes.Contains(beforeVerifiedHandle, []byte("cancelProposalValidationsBefore")) {
		t.Fatal("unverified HotStuff message number can cancel proposal validation before protocol verification")
	}
}

func TestHighQCValidationSchedulerReplacesQueuedStaleCatchup(t *testing.T) {
	service := testProposalValidationService()
	first := testHighQCValidationRequest(10, 11, 1)
	second := testHighQCValidationRequest(11, 12, 2)
	if err := service.ScheduleFHSHighQCValidation(first); err != nil {
		t.Fatal(err)
	}
	firstJob := <-service.proposalValidationJobs
	service.proposalValidationJobs <- firstJob
	if err := service.ScheduleFHSHighQCValidation(second); err != nil {
		t.Fatalf("new HighQC catch-up was dropped behind stale work: %v", err)
	}
	select {
	case <-firstJob.ctx.Done():
	default:
		t.Fatal("superseded HighQC catch-up was not cancelled")
	}
	current := <-service.proposalValidationJobs
	if current.highQCRequest == nil || current.highQCRequest.Key != second.Key || !service.isProposalValidationJobActive(current) {
		t.Fatalf("queued HighQC validation is not the current request")
	}
	if err := service.ScheduleFHSHighQCValidation(first); !errors.Is(err, hotstuff.ErrOldState) {
		t.Fatalf("older HighQC replaced current catch-up: got %v, want %v", err, hotstuff.ErrOldState)
	}
}

func TestHighQCValidationSurvivesTargetAdvanceAndProducesResult(t *testing.T) {
	service := testProposalValidationService()
	request := testHighQCValidationRequest(12, 13, 3)
	if err := service.ScheduleFHSHighQCValidation(request); err != nil {
		t.Fatal(err)
	}
	job := <-service.proposalValidationJobs
	// A lagging node at view 10 validates messages for view 11 while the QC
	// worker must catch it directly up to view 13. Routine active-view cleanup
	// must not cancel that manager-owned future jump.
	service.cancelInactiveProposalValidations(11)
	if !service.isProposalValidationJobActive(job) {
		t.Fatal("multi-view HighQC catch-up was cancelled at the intermediate view")
	}
	select {
	case <-job.ctx.Done():
		t.Fatal("multi-view HighQC context was cancelled at the intermediate view")
	default:
	}
	// A verified TC or other pacemaker proof may advance beyond the original
	// continuation target before body catch-up finishes. View cleanup does not
	// own the semantic QC worker and must not invalidate its eventual result.
	service.cancelInactiveProposalValidations(14)
	service.cancelProposalValidationsBefore(15)
	if !service.isProposalValidationJobActive(job) {
		t.Fatal("HighQC worker became inactive after the application passed its target view")
	}
	select {
	case <-job.ctx.Done():
		t.Fatal("HighQC worker was cancelled after the application passed its target view")
	default:
	}
	service.proposalValidationJobs <- job
	close(service.proposalValidationJobs)
	service.proposalValidationWorker()
	select {
	case result := <-service.highQCValidationResults:
		if result == nil || result.Key != request.Key {
			t.Fatalf("HighQC result = %#v, want key %#v", result, request.Key)
		}
	default:
		t.Fatal("surviving HighQC worker did not produce a result")
	}
}

func TestHighQCValidationIgnoresInvalidFarViewCleanup(t *testing.T) {
	service := testProposalValidationService()
	request := testHighQCValidationRequest(12, 13, 4)
	if err := service.ScheduleFHSHighQCValidation(request); err != nil {
		t.Fatal(err)
	}
	job := <-service.proposalValidationJobs
	invalidFarView := uint64(1) << 62
	// These are the cleanup calls surrounding HandleMessage in the serialized
	// control loop. An authenticated but invalid Number must not cancel the
	// manager-owned HighQC worker before or after message rejection.
	service.cancelProposalValidationsBefore(invalidFarView)
	service.cancelInactiveProposalValidations(invalidFarView)
	if !service.isProposalValidationJobActive(job) {
		t.Fatal("invalid far view cleanup removed active HighQC validation")
	}
	select {
	case <-job.ctx.Done():
		t.Fatal("invalid far view cleanup cancelled HighQC context")
	default:
	}
}

func TestSameHighQCDifferentTargetDoesNotRestartServiceWorker(t *testing.T) {
	service := testProposalValidationService()
	first := testHighQCValidationRequest(10, 11, 5)
	if err := service.ScheduleFHSHighQCValidation(first); err != nil {
		t.Fatal(err)
	}
	firstJob := <-service.proposalValidationJobs
	service.proposalValidationJobs <- firstJob
	advanced := &hotstuff.FHSHighQCValidationRequest{Key: first.Key, QC: hotstuff.CloneSignedState(first.QC)}
	advanced.Key.RequestID++
	advanced.Key.TargetView = 14
	if err := service.ScheduleFHSHighQCValidation(advanced); !errors.Is(err, hotstuff.ErrProposalValidationPending) {
		t.Fatalf("same semantic QC target advance = %v, want %v", err, hotstuff.ErrProposalValidationPending)
	}
	select {
	case <-firstJob.ctx.Done():
		t.Fatal("same semantic QC target advance cancelled existing worker")
	default:
	}
	queued := <-service.proposalValidationJobs
	if queued != firstJob || !service.isProposalValidationJobActive(firstJob) {
		t.Fatal("same semantic QC target advance replaced active job")
	}
}

func TestProposalValidationDoesNotCancelOrDrainActiveHighQC(t *testing.T) {
	service := testProposalValidationService()
	highQC := testHighQCValidationRequest(10, 11, 6)
	if err := service.ScheduleFHSHighQCValidation(highQC); err != nil {
		t.Fatal(err)
	}
	highQCJob := <-service.proposalValidationJobs
	service.proposalValidationJobs <- highQCJob
	proposal := testProposalValidationRequest(12, 7)
	if err := service.ScheduleFHSProposalValidation(proposal); !errors.Is(err, hotstuff.ErrProposalValidationPending) {
		t.Fatalf("proposal behind active HighQC = %v, want %v", err, hotstuff.ErrProposalValidationPending)
	}
	select {
	case <-highQCJob.ctx.Done():
		t.Fatal("proposal scheduling cancelled active HighQC")
	default:
	}
	queued := <-service.proposalValidationJobs
	if queued != highQCJob || !service.isProposalValidationJobActive(highQCJob) || len(service.activeProposalValidations) != 0 {
		t.Fatal("proposal scheduling drained or replaced active HighQC job")
	}
}

func TestAppliedHighQCAllowsRetainedProposalWithoutCancellingEitherJob(t *testing.T) {
	service := testProposalValidationService()
	highQC := testHighQCValidationRequest(10, 11, 8)
	if err := service.ScheduleFHSHighQCValidation(highQC); err != nil {
		t.Fatal(err)
	}
	highQCJob := <-service.proposalValidationJobs
	if !service.markHighQCValidationResultReady(highQC.Key, highQCJob.validationGeneration) ||
		!service.markHighQCValidationApplied(highQC.Key, highQCJob.validationGeneration) {
		t.Fatal("failed to model exact applied HighQC generation")
	}
	proposal := testProposalValidationRequest(11, 9)
	if err := service.ScheduleFHSProposalValidation(proposal); err != nil {
		t.Fatalf("retained Prepare was not scheduled during HighQC replay: %v", err)
	}
	proposalJob := <-service.proposalValidationJobs
	if proposalJob.request == nil || proposalJob.request.Key != proposal.Key || !service.isProposalValidationJobActive(proposalJob) {
		t.Fatalf("retained proposal job is not active: %#v", proposalJob)
	}
	if !service.isProposalValidationJobActive(highQCJob) {
		t.Fatal("proposal replay replaced applied HighQC before manager finish")
	}
	select {
	case <-highQCJob.ctx.Done():
		t.Fatal("proposal replay cancelled applied HighQC context")
	default:
	}
	service.finishHighQCValidation(highQC.Key)
	if !service.isProposalValidationJobActive(proposalJob) {
		t.Fatal("HighQC finish cancelled the concurrently scheduled proposal")
	}
}

func TestCompletedSameHighQCCanRescheduleStaleGeneration(t *testing.T) {
	service := testProposalValidationService()
	first := testHighQCValidationRequest(10, 11, 10)
	if err := service.ScheduleFHSHighQCValidation(first); err != nil {
		t.Fatal(err)
	}
	firstJob := <-service.proposalValidationJobs
	if !service.markHighQCValidationResultReady(first.Key, firstJob.validationGeneration) {
		t.Fatal("failed to mark completed HighQC generation")
	}
	retry := &hotstuff.FHSHighQCValidationRequest{Key: first.Key, QC: hotstuff.CloneSignedState(first.QC)}
	retry.Key.RequestID++
	if err := service.ScheduleFHSHighQCValidation(retry); err != nil {
		t.Fatalf("completed same-QC generation could not retry: %v", err)
	}
	select {
	case <-firstJob.ctx.Done():
	default:
		t.Fatal("completed HighQC generation was not retired after retry schedule succeeded")
	}
	retryJob := <-service.proposalValidationJobs
	if retryJob.highQCRequest == nil || retryJob.highQCRequest.Key != retry.Key || !service.isProposalValidationJobActive(retryJob) {
		t.Fatalf("same-QC retry is not active: %#v", retryJob)
	}
}

func TestProposalValidationSchedulerReplacesQueuedStaleView(t *testing.T) {
	if proposalValidationWorkers <= 1 || proposalValidationWorkers > 4 || proposalValidationQueueCapacity != 1 {
		t.Fatalf("validation bounds workers=%d queue=%d", proposalValidationWorkers, proposalValidationQueueCapacity)
	}
	service := testProposalValidationService()
	first := testProposalValidationRequest(10, 1)
	second := testProposalValidationRequest(11, 2)
	if err := service.ScheduleFHSProposalValidation(first); err != nil {
		t.Fatal(err)
	}
	firstJob := <-service.proposalValidationJobs
	service.proposalValidationJobs <- firstJob
	if err := service.ScheduleFHSProposalValidation(second); err != nil {
		t.Fatalf("current Prepare was dropped behind stale work: %v", err)
	}
	select {
	case <-firstJob.ctx.Done():
	default:
		t.Fatal("superseded validation was not cancelled")
	}
	current := <-service.proposalValidationJobs
	if current.request.Key != second.Key || !service.isProposalValidationJobActive(current) {
		t.Fatalf("queued validation = %#v, want active current view %#v", current.request.Key, second.Key)
	}
	if err := service.ScheduleFHSProposalValidation(first); !errors.Is(err, hotstuff.ErrOldState) {
		t.Fatalf("older Prepare replaced current work: got %v, want %v", err, hotstuff.ErrOldState)
	}
	if !service.isProposalValidationJobActive(current) {
		t.Fatal("rejected stale Prepare cancelled current validation")
	}
}

func TestProposalValidationCancellationFollowsActiveView(t *testing.T) {
	service := testProposalValidationService()
	request := testProposalValidationRequest(20, 3)
	if err := service.ScheduleFHSProposalValidation(request); err != nil {
		t.Fatal(err)
	}
	job := <-service.proposalValidationJobs
	service.cancelInactiveProposalValidations(request.Key.ViewNumber)
	if !service.isProposalValidationJobActive(job) {
		t.Fatal("active-view validation was cancelled")
	}
	service.cancelInactiveProposalValidations(request.Key.ViewNumber + 1)
	select {
	case <-job.ctx.Done():
	default:
		t.Fatal("validation from the previous view was not cancelled")
	}
	if service.isProposalValidationJobActive(job) {
		t.Fatal("cancelled validation remains active")
	}
	service.proposalValidationJobs <- job
	close(service.proposalValidationJobs)
	service.proposalValidationWorker()
	if len(service.proposalValidationResults) != 0 {
		t.Fatal("stale worker result entered the serialized control loop")
	}
}

func TestCanonicalCleanupPreservesActiveProposalAfterRejectedFarView(t *testing.T) {
	service := testProposalValidationService()
	request := testProposalValidationRequest(20, 11)
	service.currentView.ViewNumber = request.Key.ViewNumber - 1
	if err := service.ScheduleFHSProposalValidation(request); err != nil {
		t.Fatal(err)
	}
	job := <-service.proposalValidationJobs
	invalid := &hotstuff.HotstuffMessage{Number: uint64(1) << 62}
	if invalid.Number <= request.Key.ViewNumber {
		t.Fatal("invalid test message is not a far-future view")
	}

	// A rejected wire message must not influence cleanup. Only the canonical
	// current view observed after protocol verification may retire workers.
	service.cancelInactiveProposalValidations(service.GetCurrentView().ViewNumber + 1)
	if !service.isProposalValidationJobActive(job) {
		t.Fatal("canonical post-message cleanup removed the active proposal validation")
	}
	select {
	case <-job.ctx.Done():
		t.Fatal("canonical post-message cleanup cancelled the active proposal context")
	default:
	}
	service.proposalValidationJobs <- job
	close(service.proposalValidationJobs)
	service.proposalValidationWorker()
	select {
	case result := <-service.proposalValidationResults:
		if result == nil || result.Key != request.Key {
			t.Fatalf("proposal result = %#v, want key %#v", result, request.Key)
		}
	default:
		t.Fatal("active proposal worker did not publish its result")
	}
}

func TestProposalBodyWaitHonorsValidationCancellation(t *testing.T) {
	service := testProposalValidationService()
	service.proposalBodies = make(map[common.Hash]*proposalBodyMsg)
	request := testProposalValidationRequest(30, 4)
	ref, err := types.DecodeHotstuffProposalRef(request.ProposalRef)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	_, err = service.waitProposalBodyForValidation(ctx, ref, service.proposalValidationGeneration)
	if !errors.Is(err, hotstuff.ErrOldState) {
		t.Fatalf("cancelled body wait error = %v, want %v", err, hotstuff.ErrOldState)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("cancelled body wait took %s", elapsed)
	}
}

func TestProposalManifestAuthorityBindsLeaderOrActivePrepare(t *testing.T) {
	service := testProposalValidationService()
	body := &proposalBodyMsg{
		Type:            proposalBodyMsgManifest,
		ProposalID:      common.HexToHash("0x11"),
		ViewNumber:      12,
		ViewID:          common.HexToHash("0x12"),
		LeaderID:        "leader-address",
		From:            "leader-address",
		ProposalKeyHash: common.HexToHash("0x1010"),
		SenderKeyHash:   common.HexToHash("0x1010"),
	}
	if err := service.verifyProposalManifestAuthority(body); err == nil {
		t.Fatal("self-declared leader bypassed the unavailable deterministic route")
	}
	route := &FHSRoute{Enabled: true, ProposalView: body.ViewNumber, LeaderID: body.LeaderID}
	if !proposalManifestMatchesRoute(body, route) {
		t.Fatal("manifest did not match its deterministic route")
	}
	for _, mutate := range []func(){
		func() { route.ProposalView++ },
		func() { route.LeaderID = "other-leader" },
		func() { route.Enabled = false },
	} {
		copyRoute := *route
		mutate()
		if proposalManifestMatchesRoute(body, route) {
			t.Fatal("manifest matched a mutated deterministic route")
		}
		*route = copyRoute
	}

	body.From = "repair-peer"
	if err := service.verifyProposalManifestAuthority(body); err == nil {
		t.Fatal("non-leader allocated a manifest before its Prepare was active")
	}
	key := hotstuff.FHSProposalValidationKey{
		ViewNumber: body.ViewNumber,
		ViewID:     body.ViewID,
		LeaderID:   body.LeaderID,
		ProposalID: body.ProposalID,
	}
	service.activeProposalValidations[key.ViewID] = &proposalValidationControl{key: key, keyHash: body.SenderKeyHash, generation: 1}
	if err := service.verifyProposalManifestAuthority(body); err != nil {
		t.Fatalf("active Prepare repair manifest rejected: %v", err)
	}
	body.ProposalID = common.HexToHash("0x13")
	if err := service.verifyProposalManifestAuthority(body); err == nil {
		t.Fatal("repair peer allocated a manifest for a different proposal")
	}
}

func TestProposalManifestAuthorityAllowsOnlyVerifiedHighQCRepairSet(t *testing.T) {
	service := testProposalValidationService()
	request := testHighQCValidationRequest(20, 21, 9)
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	key := hotstuff.FHSProposalValidationKey{
		ViewNumber: 20,
		ViewID:     common.HexToHash("0x2001"),
		LeaderID:   "historical-leader",
		ProposalID: common.HexToHash("0x2002"),
	}
	keyHash := common.HexToHash("0x2005")
	service.activeHighQCValidation = &highQCValidationControl{
		key: request.Key, generation: 7, cancel: cancel,
		authorized: map[common.Hash]proposalBodyAuthority{key.ProposalID: {key: key, keyHash: keyHash}},
	}
	body := &proposalBodyMsg{
		Type: proposalBodyMsgManifest, ProposalID: key.ProposalID,
		ViewNumber: key.ViewNumber, ViewID: key.ViewID, LeaderID: key.LeaderID,
		From: "historical-repair-peer", ProposalKeyHash: keyHash, SenderKeyHash: keyHash,
	}
	if err := service.verifyProposalManifestAuthority(body); err != nil {
		t.Fatalf("verified HighQC repair manifest rejected: %v", err)
	}
	body.ProposalID = common.HexToHash("0x2003")
	if err := service.verifyProposalManifestAuthority(body); err == nil {
		t.Fatal("HighQC repair peer allocated a manifest outside the verified QC chain")
	}
	body.ProposalID = key.ProposalID
	body.ViewID = common.HexToHash("0x2004")
	if err := service.verifyProposalManifestAuthority(body); err == nil {
		t.Fatal("HighQC repair peer changed the certified proposal context")
	}
}

func TestIncompletePeerManifestCannotPoisonProposalCache(t *testing.T) {
	service := testProposalValidationService()
	service.proposalBodies = make(map[common.Hash]*proposalBodyMsg)
	service.verifiedProposalByID = make(map[common.Hash]*core.VerifiedProposal)
	candidate := &proposalBodyMsg{
		Type:       proposalBodyMsgManifest,
		ProposalID: common.HexToHash("0x21"),
		LeaderID:   "leader",
		From:       "repair-peer",
		Manifest:   []byte("unverified manifest"),
	}
	service.proposalBodies[candidate.ProposalID] = cloneProposalBodyMsg(candidate)
	service.discardIncompletePeerManifest(candidate)
	if service.proposalBodies[candidate.ProposalID] != nil {
		t.Fatal("incomplete non-leader manifest remained in the proposal cache")
	}

	leader := cloneProposalBodyMsg(candidate)
	leader.From = leader.LeaderID
	service.proposalBodies[leader.ProposalID] = leader
	service.discardIncompletePeerManifest(candidate)
	if service.proposalBodies[leader.ProposalID] == nil {
		t.Fatal("peer cleanup removed the leader's manifest")
	}

	complete := cloneProposalBodyMsg(candidate)
	complete.EncodedBlock = []byte{1}
	service.proposalBodies[complete.ProposalID] = complete
	service.discardIncompletePeerManifest(candidate)
	if service.proposalBodies[complete.ProposalID] == nil {
		t.Fatal("peer cleanup removed an already verified proposal body")
	}
}

func testProposalSidecar(t *testing.T) (*Service, *proposalBodyMsg) {
	t.Helper()
	service := &Service{
		chainConfig:          &params.ChainConfig{ChainID: big.NewInt(99)},
		proposalBodies:       make(map[common.Hash]*proposalBodyMsg),
		verifiedProposalByID: make(map[common.Hash]*core.VerifiedProposal),
		fhsCertifiedByID:     make(map[common.Hash]*fhsCertifiedProposal),
	}
	block := types.NewBlockWithHeader(&types.Header{
		ParentHash: common.HexToHash("0x01"),
		Number:     big.NewInt(1),
		Difficulty: big.NewInt(1),
		GasLimit:   1,
		KeyHash:    common.HexToHash("0x5151"),
	})
	encoded := block.EncodeToBytes()
	extra := []byte("application-proof")
	ref, err := types.NewHotstuffProposalRefWithProof(99, 7, common.HexToHash("0x07"), "leader", block, encoded, extra, common.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	return service, &proposalBodyMsg{
		Type:              proposalBodyMsgManifest,
		ProposalID:        ref.ProposalID(),
		BodyHash:          ref.BodyHash,
		BodySize:          ref.BodySize,
		Number:            ref.Number,
		ViewNumber:        ref.ViewNumber,
		ViewID:            ref.ViewID,
		LeaderID:          ref.LeaderID,
		From:              "member-0",
		ProposalKeyHash:   ref.KeyHash,
		EncodedBlock:      encoded,
		Extra:             extra,
		CreatedAtUnixNano: time.Now().Add(24 * time.Hour).UnixNano(),
	}
}

func TestProposalSidecarStoreBindsProofAndUsesLocalReceiveTime(t *testing.T) {
	service, body := testProposalSidecar(t)
	before := time.Now()
	if err := service.storeProposalBody(body); err != nil {
		t.Fatalf("valid proposal sidecar rejected: %v", err)
	}
	stored := service.getProposalBody(body.ProposalID)
	if stored == nil || time.Unix(0, stored.CreatedAtUnixNano).Before(before) || time.Unix(0, stored.CreatedAtUnixNano).After(time.Now().Add(time.Second)) {
		t.Fatal("proposal sidecar cache trusted the remote timestamp")
	}

	tampered := cloneProposalBodyMsg(body)
	tampered.Extra = []byte("different-proof")
	if err := service.storeProposalBody(tampered); err == nil {
		t.Fatal("same proposal ID accepted with a different application proof")
	}
}

func TestProposalSidecarWireRejectsAboveOsakaBlockLimit(t *testing.T) {
	body := &proposalBodyMsg{
		Type:       proposalBodyMsgManifest,
		ProposalID: common.HexToHash("0x01"),
		BodyHash:   common.HexToHash("0x02"),
		BodySize:   params.MaxBlockSize,
		Number:     1,
		ViewNumber: 1,
		ViewID:     common.HexToHash("0x03"),
		LeaderID:   "leader",
		From:       "member-0",
		AuthSig:    []byte{1},
		Manifest:   make([]byte, params.MaxBlockSize+1),
	}
	if err := validateProposalBodyWireShape(body); err == nil {
		t.Fatal("proposal sidecar above the Osaka block limit was accepted")
	}
}

func TestProposalManifestRepairReconstructsExactBody(t *testing.T) {
	service := &Service{
		chainConfig:          &params.ChainConfig{ChainID: big.NewInt(99)},
		proposalBodies:       make(map[common.Hash]*proposalBodyMsg),
		verifiedProposalByID: make(map[common.Hash]*core.VerifiedProposal),
		fhsCertifiedByID:     make(map[common.Hash]*fhsCertifiedProposal),
	}
	tx := testSignedProposalRepairTransaction(t)
	block := types.NewBlock(&types.Header{
		ParentHash: common.HexToHash("0x01"),
		Number:     big.NewInt(1),
		Difficulty: big.NewInt(1),
		GasLimit:   30_000_000,
	}, types.Transactions{tx}, nil, nil, new(trie.Trie))
	admission := &types.CommonTxAdmissionBatch{
		ChainID:     big.NewInt(99),
		GenesisHash: common.HexToHash("0x99"),
		Miner:       common.HexToAddress("0x42"),
		Timestamp:   1,
		TxHashes:    []common.Hash{tx.Hash()},
		Signature:   make([]byte, 65),
	}
	admission.TxRoot = types.DeriveCommonTxAdmissionTxRoot(admission.TxHashes)
	admission.AdmissionID = types.CommonTxAdmissionID(admission)
	reward := &types.CommonTxReward{TxHash: tx.Hash(), Approver: admission.Miner, ApproverReward: new(big.Int), Burn: new(big.Int)}
	block.SetCommonTxData([]*types.CommonTxAdmissionBatch{admission}, []types.CommonTxAdmissionRef{{}}, []*types.CommonTxReward{reward})
	encodedBlock := block.EncodeToBytes()
	extra := []byte("compact-proof")
	ref, err := types.NewHotstuffProposalRefWithProof(99, 7, common.HexToHash("0x07"), "leader", block, encodedBlock, extra, common.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := encodeProposalDataManifest(block)
	if err != nil {
		t.Fatal(err)
	}
	body := &proposalBodyMsg{
		Type:       proposalBodyMsgManifest,
		ProposalID: ref.ProposalID(),
		BodyHash:   ref.BodyHash,
		BodySize:   ref.BodySize,
		Number:     ref.Number,
		ViewNumber: ref.ViewNumber,
		ViewID:     ref.ViewID,
		LeaderID:   ref.LeaderID,
		From:       "leader-address",
		Manifest:   manifest,
		Extra:      extra,
		ParentQC:   nil,
		AuthSig:    []byte{1},
	}
	durableService := &Service{
		chainConfig:          service.chainConfig,
		proposalBodies:       make(map[common.Hash]*proposalBodyMsg),
		verifiedProposalByID: make(map[common.Hash]*core.VerifiedProposal),
		fhsCertifiedByID:     make(map[common.Hash]*fhsCertifiedProposal),
		resolveTxQUICTransaction: func(hash common.Hash) (*types.Transaction, error) {
			if hash == tx.Hash() {
				return tx, nil
			}
			return nil, nil
		},
	}
	if missing, err := durableService.storeProposalManifest(cloneProposalBodyMsg(body)); err != nil || len(missing) != 0 {
		t.Fatalf("durable ingress assembly missing=%v err=%v", missing, err)
	}
	if complete := durableService.getProposalBody(ref.ProposalID()); complete == nil || !bytes.Equal(complete.EncodedBlock, encodedBlock) {
		t.Fatal("durable ingress resolver did not reconstruct the proposal")
	}
	beforeManifest := service.proposalBodySnapshotForWait(ref.ProposalID())
	missing, err := service.storeProposalManifest(body)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-beforeManifest.wake:
	default:
		t.Fatal("manifest installation did not wake proposal waiters")
	}
	if len(missing) != 1 || missing[0] != tx.Hash() {
		t.Fatalf("missing = %v, want only %s", missing, tx.Hash())
	}
	if cached := service.getProposalBody(ref.ProposalID()); cached == nil || len(cached.EncodedBlock) != 0 {
		t.Fatal("manifest unexpectedly carried a full proposal body")
	}
	donorBody := cloneProposalBodyMsg(body)
	donorBody.EncodedBlock = encodedBlock
	repairHashes, repairBytes, err := service.proposalRepairTransactions(donorBody, missing)
	if err != nil {
		t.Fatal(err)
	}
	if len(repairHashes) != 1 || repairHashes[0] != tx.Hash() || len(repairBytes) != 1 {
		t.Fatalf("repair response hashes=%v transactions=%d", repairHashes, len(repairBytes))
	}
	beforeRepair := service.proposalBodySnapshotForWait(ref.ProposalID())
	remaining, err := service.mergeProposalRepair(&proposalBodyMsg{
		Type:             proposalBodyMsgRepairData,
		ProposalID:       ref.ProposalID(),
		BodyHash:         ref.BodyHash,
		BodySize:         ref.BodySize,
		Number:           ref.Number,
		ViewNumber:       ref.ViewNumber,
		ViewID:           ref.ViewID,
		LeaderID:         ref.LeaderID,
		MissingTxHashes:  repairHashes,
		TransactionBytes: repairBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("repair left %d missing transactions", remaining)
	}
	select {
	case <-beforeRepair.wake:
	default:
		t.Fatal("incremental repair did not wake proposal waiters")
	}
	complete := service.getProposalBody(ref.ProposalID())
	if complete == nil || !bytes.Equal(complete.EncodedBlock, encodedBlock) {
		t.Fatal("repair did not reconstruct the exact committed block encoding")
	}
	request := cloneProposalBodyEnvelope(complete)
	indexedBody, fromDurable, err := service.proposalBodyForRepairRequest(request)
	if err != nil || fromDurable || indexedBody == nil {
		t.Fatalf("indexed repair source unavailable: durable=%t body=%v err=%v", fromDurable, indexedBody != nil, err)
	}
	if len(indexedBody.EncodedBlock) != 0 || len(indexedBody.Manifest) != 0 || len(indexedBody.TransactionBytes) != 0 {
		t.Fatal("indexed repair source cloned a block-sized payload")
	}
	indexedHashes, indexedTransactions, err := service.proposalRepairTransactions(indexedBody, []common.Hash{tx.Hash()})
	if err != nil || len(indexedHashes) != 1 || len(indexedTransactions) != 1 {
		t.Fatalf("indexed repair lookup hashes=%d transactions=%d err=%v", len(indexedHashes), len(indexedTransactions), err)
	}
}

func TestProposalRepairCannotExportTransactionOutsideManifest(t *testing.T) {
	service, body := testProposalSidecar(t)
	block := types.DecodeToBlock(body.EncodedBlock)
	manifest, err := encodeProposalDataManifest(block)
	if err != nil {
		t.Fatal(err)
	}
	body.Manifest = manifest
	lookups := 0
	service.resolveTxQUICTransaction = func(common.Hash) (*types.Transaction, error) {
		lookups++
		return types.NewTransaction(0, common.HexToAddress("0x9999"), big.NewInt(1), 21_000, big.NewInt(1), nil), nil
	}
	hashes, txs, err := service.proposalRepairTransactions(body, []common.Hash{common.HexToHash("0xdead")})
	if err != nil {
		t.Fatal(err)
	}
	if len(hashes) != 0 || len(txs) != 0 || lookups != 0 {
		t.Fatalf("out-of-manifest repair hashes=%d txs=%d lookups=%d", len(hashes), len(txs), lookups)
	}
}

func TestProposalRepairLazilyIndexesRestoredBodyWithoutClone(t *testing.T) {
	service, body := testProposalSidecar(t)
	// Startup restoration installs already validated complete bodies directly
	// from the safety store; the transient donor index is intentionally rebuilt
	// on first use.
	service.proposalBodies[body.ProposalID] = cloneProposalBodyMsg(body)
	request := cloneProposalBodyEnvelope(body)
	indexed, fromDurable, err := service.proposalBodyForRepairRequest(request)
	if err != nil || fromDurable || indexed == nil {
		t.Fatalf("lazy restored-body index failed: durable=%t body=%v err=%v", fromDurable, indexed != nil, err)
	}
	if len(indexed.EncodedBlock) != 0 || len(indexed.Manifest) != 0 {
		t.Fatal("lazy restored-body lookup returned a block-sized payload copy")
	}
	service.muProposalBody.RLock()
	assembly := service.proposalAssemblies[body.ProposalID]
	service.muProposalBody.RUnlock()
	if assembly == nil || assembly.manifest == nil {
		t.Fatal("restored body did not publish its donor index")
	}
	manifest, err := service.proposalManifestForRepair(body.ProposalID, indexed)
	if err != nil || len(manifest) == 0 {
		t.Fatalf("indexed restored manifest unavailable: bytes=%d err=%v", len(manifest), err)
	}
}

func waitProposalAssemblyBuildWaiters(t *testing.T, service *Service, proposalID common.Hash, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		service.muProposalBody.RLock()
		build := service.proposalAssemblyBuilds[proposalID]
		got := 0
		if build != nil {
			got = build.waiters
		}
		service.muProposalBody.RUnlock()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("proposal assembly build did not reach %d waiters", want)
}

func TestProposalRepairRestoredBodyRebuildIsSingleflight(t *testing.T) {
	service, body := testProposalSidecar(t)
	service.proposalBodies[body.ProposalID] = cloneProposalBodyMsg(body)
	request := cloneProposalBodyEnvelope(body)
	var decodes atomic.Int32
	decodeStarted := make(chan struct{})
	releaseDecode := make(chan struct{})
	service.decodeProposalBodyForRepair = func(encoded []byte) *types.Block {
		if decodes.Add(1) == 1 {
			close(decodeStarted)
		}
		<-releaseDecode
		return types.DecodeToBlock(encoded)
	}
	const callers = 16
	start := make(chan struct{})
	results := make(chan error, callers)
	var ready sync.WaitGroup
	ready.Add(callers)
	for index := 0; index < callers; index++ {
		go func() {
			ready.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			indexed, _, err := service.proposalBodyForRepairRequestContext(ctx, request)
			if err == nil && (indexed == nil || len(indexed.EncodedBlock) != 0) {
				err = fmt.Errorf("singleflight returned invalid metadata-only body")
			}
			results <- err
		}()
	}
	ready.Wait()
	close(start)
	select {
	case <-decodeStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("donor index decode did not start")
	}
	waitProposalAssemblyBuildWaiters(t, service, body.ProposalID, callers)
	close(releaseDecode)
	for index := 0; index < callers; index++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if got := decodes.Load(); got != 1 {
		t.Fatalf("concurrent donor index decodes = %d, want 1", got)
	}
	service.muProposalBody.RLock()
	builds := len(service.proposalAssemblyBuilds)
	slots := len(service.proposalAssemblyBuildSlots)
	service.muProposalBody.RUnlock()
	if builds != 0 || slots != 0 {
		t.Fatalf("singleflight resources leaked: builds=%d slots=%d", builds, slots)
	}
}

func TestProposalRepairRestoredBodyRebuildWaitIsCancelable(t *testing.T) {
	service, body := testProposalSidecar(t)
	service.proposalBodies[body.ProposalID] = cloneProposalBodyMsg(body)
	request := cloneProposalBodyEnvelope(body)
	decodeStarted := make(chan struct{})
	releaseDecode := make(chan struct{})
	service.decodeProposalBodyForRepair = func(encoded []byte) *types.Block {
		close(decodeStarted)
		<-releaseDecode
		return types.DecodeToBlock(encoded)
	}
	ownerResult := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _, err := service.proposalBodyForRepairRequestContext(ctx, request)
		ownerResult <- err
	}()
	<-decodeStarted
	waitCtx, cancelWait := context.WithCancel(context.Background())
	waiterResult := make(chan error, 1)
	go func() {
		_, _, err := service.proposalBodyForRepairRequestContext(waitCtx, request)
		waiterResult <- err
	}()
	waitProposalAssemblyBuildWaiters(t, service, body.ProposalID, 2)
	cancelWait()
	select {
	case err := <-waiterResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled waiter error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled donor index waiter did not return")
	}
	close(releaseDecode)
	if err := <-ownerResult; err != nil {
		t.Fatalf("remaining build owner failed: %v", err)
	}
}

func TestProposalRepairRestoredBodyRebuildPanicReleasesSingleflight(t *testing.T) {
	service, body := testProposalSidecar(t)
	service.proposalBodies[body.ProposalID] = cloneProposalBodyMsg(body)
	request := cloneProposalBodyEnvelope(body)
	service.decodeProposalBodyForRepair = func([]byte) *types.Block { panic("decode-test") }
	if _, _, err := service.proposalBodyForRepairRequest(request); err == nil || !strings.Contains(err.Error(), "decode-test") {
		t.Fatalf("decode panic was not reported: %v", err)
	}
	service.muProposalBody.RLock()
	builds := len(service.proposalAssemblyBuilds)
	slots := len(service.proposalAssemblyBuildSlots)
	service.muProposalBody.RUnlock()
	if builds != 0 || slots != 0 {
		t.Fatalf("panic leaked singleflight resources: builds=%d slots=%d", builds, slots)
	}
	service.decodeProposalBodyForRepair = types.DecodeToBlock
	if indexed, _, err := service.proposalBodyForRepairRequest(request); err != nil || indexed == nil {
		t.Fatalf("singleflight did not recover after panic: body=%v err=%v", indexed != nil, err)
	}
}

func TestProposalWireNeverAcceptsFullBlockBody(t *testing.T) {
	_, body := testProposalSidecar(t)
	body.AuthSig = []byte{1}
	body.Manifest = []byte{1}
	if err := validateProposalBodyWireShape(body); err == nil {
		t.Fatal("wire proposal accepted a full block body")
	}
}

func TestProposalSidecarSignatureCoversAllProofFields(t *testing.T) {
	service, body := testProposalSidecar(t)
	repairTx := testSignedProposalRepairTransaction(t)
	encodedRepairTx, err := encodeProposalRepairTransaction(repairTx)
	if err != nil {
		t.Fatal(err)
	}
	body.TransactionBytes = [][]byte{encodedRepairTx}
	var secret bls.SecretKey
	secret.SetByCSPRNG()
	service.consensusSecret = &secret
	service.consensusPublic = secret.GetPublicKey()
	service.proposalBodySecret = new(bls.SecretKey)
	if err := service.proposalBodySecret.Deserialize(secret.Serialize()); err != nil {
		t.Fatal(err)
	}
	service.netService = &netService{serverID: body.From, serverAddress: body.From}
	service.currentView.KeyHash = common.HexToHash("0x5151")
	if err := service.sealProposalBody(body); err != nil {
		t.Fatal(err)
	}
	digest, err := proposalBodyAuthDigest(service.ChainID(), body)
	if err != nil {
		t.Fatal(err)
	}
	var signature bls.Sign
	if err := signature.Deserialize(body.AuthSig); err != nil || !signature.VerifyHash(service.consensusPublic, digest) {
		t.Fatal("valid proposal sidecar signature did not verify")
	}

	tampered := cloneProposalBodyMsg(body)
	tampered.ParentQC = []byte("different-parent-proof")
	tamperedDigest, err := proposalBodyAuthDigest(service.ChainID(), tampered)
	if err != nil {
		t.Fatal(err)
	}
	if signature.VerifyHash(service.consensusPublic, tamperedDigest) {
		t.Fatal("proposal sidecar signature did not bind ParentQC")
	}
	tampered = cloneProposalBodyMsg(body)
	tampered.SenderKeyHash = common.HexToHash("0x5252")
	tamperedDigest, err = proposalBodyAuthDigest(service.ChainID(), tampered)
	if err != nil {
		t.Fatal(err)
	}
	if signature.VerifyHash(service.consensusPublic, tamperedDigest) {
		t.Fatal("proposal sidecar signature did not bind SenderKeyHash")
	}
	tampered = cloneProposalBodyMsg(body)
	tampered.TransactionBytes[0][len(tampered.TransactionBytes[0])-1] ^= 1
	tamperedDigest, err = proposalBodyAuthDigest(service.ChainID(), tampered)
	if err != nil {
		t.Fatal(err)
	}
	if signature.VerifyHash(service.consensusPublic, tamperedDigest) {
		t.Fatal("proposal sidecar signature did not bind canonical transaction bytes")
	}
}

func TestConfigureConsensusIdentityRejectsMismatchedKeys(t *testing.T) {
	var secret, other bls.SecretKey
	secret.SetByCSPRNG()
	other.SetByCSPRNG()
	service := &Service{}
	service.protocolMng = hotstuff.NewHotstuffProtocolManager(service, nil, nil)
	config := &common.NodeConfig{Private: secret.SerializeToHexStr(), Public: secret.GetPublicKey().SerializeToHexStr()}
	if err := service.configureConsensusIdentity(config); err != nil {
		t.Fatalf("matching consensus identity rejected: %v", err)
	}
	config.Public = other.GetPublicKey().SerializeToHexStr()
	if err := service.configureConsensusIdentity(config); err == nil {
		t.Fatal("mismatched consensus private/public keys were accepted")
	}
}

func TestTxQUICReceiptIdentityInitializationAndConcurrentSigning(t *testing.T) {
	service := &Service{}
	service.protocolMng = hotstuff.NewHotstuffProtocolManager(service, nil, nil)
	backend := &ReconfigBackend{service: service}
	if _, err := backend.TxQUICReceiptPublicKey(); err == nil {
		t.Fatal("uninitialized receipt identity was exposed")
	}

	secret := new(bls.SecretKey)
	secret.SetByCSPRNG()
	config := &common.NodeConfig{Private: secret.SerializeToHexStr(), Public: secret.GetPublicKey().SerializeToHexStr()}
	if err := service.configureConsensusIdentity(config); err != nil {
		t.Fatal(err)
	}
	publicKey, err := backend.TxQUICReceiptPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	committee := []*common.Cnode{{Address: "validator-0", Public: secret.GetPublicKey().SerializeToHexStr()}}
	digest := sha256.Sum256([]byte("txquic-receipt-race-test"))

	const workers = 16
	var wait sync.WaitGroup
	errorsCh := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			service.txQUICReceiptSignMu.Lock()
			signatureBytes, err := service.signTxQUICReceiptLocked(digest[:], committee)
			service.txQUICReceiptSignMu.Unlock()
			if err != nil {
				errorsCh <- err
				return
			}
			public := bls.GetPublicKey(publicKey)
			var signature bls.Sign
			if public == nil || signature.Deserialize(signatureBytes) != nil || !signature.VerifyHash(public, digest[:]) {
				errorsCh <- fmt.Errorf("invalid concurrent receipt signature")
			}
		}()
	}
	wait.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Fatal(err)
	}
}
