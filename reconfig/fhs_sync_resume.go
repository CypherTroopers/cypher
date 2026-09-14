package reconfig

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

// One coalesced request covers the latest imported epoch. No sync callback
// waits for the control loop, lifecycle lock, or a physical network send.
type fhsSyncResumeRequest struct {
	generation           uint64
	validationGeneration uint64
	keyHash              common.Hash
	keyNumber            uint64
	ready                bool
	started              bool
	lastAttempt          time.Time
	previous             *fhsSyncResumeRequest
}

func (s *Service) beginFHSSyncResume(key *types.KeyBlock, generation uint64) {
	s.muFHSSyncResume.Lock()
	var previous *fhsSyncResumeRequest
	if pending := s.fhsSyncResume; pending != nil && pending.ready {
		copy := *pending
		copy.previous = nil // Never retain a chain of failed import attempts.
		previous = &copy
	}
	s.fhsSyncResume = &fhsSyncResumeRequest{
		generation: generation, validationGeneration: atomic.LoadUint64(&s.proposalValidationGeneration),
		keyHash: key.Hash(), keyNumber: key.NumberU64(), previous: previous,
	}
	s.fhsSyncResumePreparing = s.fhsSyncResume
	s.muFHSSyncResume.Unlock()
}

func (s *Service) finishFHSSyncResume(success bool) {
	s.muFHSSyncResume.Lock()
	// A rejected before-hook may not have invalidated anything. Its finish
	// must not cancel an earlier successfully published epoch's pending wake.
	if request := s.fhsSyncResumePreparing; request != nil {
		if success {
			request.ready = true
			request.previous = nil
		} else if s.fhsSyncResume == request {
			// Invalidation already reset the protocol, even if this later import
			// never became canonical. Preserve the previous successful epoch's
			// outstanding wake using the new worker generation, not the failed
			// epoch. The control loop rechecks its lifecycle and canonical route.
			s.fhsSyncResume = request.previous
			if s.fhsSyncResume != nil {
				s.fhsSyncResume.validationGeneration = atomic.LoadUint64(&s.proposalValidationGeneration)
				s.fhsSyncResume.lastAttempt = time.Time{}
			}
		}
		s.fhsSyncResumePreparing = nil
	}
	s.muFHSSyncResume.Unlock()
}

func (s *Service) fhsSyncResumeActive(request *fhsSyncResumeRequest) bool {
	if !s.lifecycleGenerationActiveLocked(request.generation) ||
		atomic.LoadUint64(&s.proposalValidationGeneration) != request.validationGeneration ||
		atomic.LoadInt32(&s.fhsEpochTransition) != 0 ||
		atomic.LoadInt32(&s.fhsValidationPublicationOwner) != int32(fhsValidationPublicationNone) ||
		s.hasDeferredFHSRecovery() {
		return false
	}
	view := s.GetCurrentView()
	if s.kbc == nil {
		return false
	}
	key := s.kbc.CurrentBlock()
	return key != nil && key.Hash() == request.keyHash && key.NumberU64() == request.keyNumber &&
		view.KeyHash == request.keyHash && view.KeyNumber == request.keyNumber
}

// processFHSSyncResume is one step on the protocol control loop. HandleMessage
// applies the final scheduled epoch reset before constructing the signed
// NewView. Keeping admission here avoids both a full local queue and a stale
// start-NewView dedup marker swallowing the only new-epoch wake.
func (s *Service) processFHSSyncResume() {
	s.muFHSSyncResume.Lock()
	request := s.fhsSyncResume
	if request == nil || !request.ready || time.Since(request.lastAttempt) < startNewViewDedupWindow {
		s.muFHSSyncResume.Unlock()
		return
	}
	if !s.lifecycleGenerationActiveLocked(request.generation) ||
		atomic.LoadUint64(&s.proposalValidationGeneration) != request.validationGeneration {
		s.fhsSyncResume = nil
		s.muFHSSyncResume.Unlock()
		return
	}
	s.muFHSSyncResume.Unlock()

	s.muLifecycle.Lock()
	if !s.fhsSyncResumeActive(request) || s.protocolMng == nil || bftview.IamMember() < 0 {
		s.muLifecycle.Unlock()
		return
	}
	s.muFHSSyncResume.Lock()
	if s.fhsSyncResume != request {
		s.muFHSSyncResume.Unlock()
		s.muLifecycle.Unlock()
		return
	}
	request.lastAttempt = time.Now()
	if !request.started && s.pacetMakerTimer != nil {
		if err := s.pacetMakerTimer.start(); err != nil {
			s.muFHSSyncResume.Unlock()
			s.muLifecycle.Unlock()
			return
		}
		request.started = true
	}
	s.muFHSSyncResume.Unlock()
	pending, replay, replayErr := s.preparePendingFHSQCBroadcastReplay()
	s.muLifecycle.Unlock()
	if replayErr != nil {
		log.Warn("Fair HotStuff synced epoch QC replay failed", "err", replayErr)
		return
	}
	s.broadcastPreparedFHSQCBroadcast(pending, replay)
	// Stop, another key import, or deferred recovery may have intervened while
	// transport was busy. Never reactivate their superseded request.
	if !s.fhsSyncResumeActive(request) {
		return
	}
	err := s.protocolMng.HandleMessage(&hotstuff.HotstuffMessage{
		Code: hotstuff.MsgStartNewView, Number: s.currentHotstuffBaseNumber(),
	})
	if err != nil {
		log.Debug("Fair HotStuff synced epoch resume will retry", "keyNumber", request.keyNumber, "err", err)
		return
	}
	s.muFHSSyncResume.Lock()
	if s.fhsSyncResume == request && s.fhsSyncResumeActive(request) {
		s.fhsSyncResume = nil
		log.Info("Fair HotStuff consensus resumed after key sync", "keyNumber", request.keyNumber, "keyHash", request.keyHash)
	}
	s.muFHSSyncResume.Unlock()
}

const fhsDeferredRecoveryRetryDelay = time.Second

type fhsValidationPublicationOwner int32

const (
	fhsValidationPublicationNone fhsValidationPublicationOwner = iota
	fhsValidationPublicationProposal
	fhsValidationPublicationHighQC
	fhsValidationPublicationSyncTransition
)

func (s *Service) acquireFHSValidationPublication(owner fhsValidationPublicationOwner) error {
	if s == nil || owner == fhsValidationPublicationNone {
		return fmt.Errorf("invalid FHS validation publication owner")
	}
	s.muFHSValidationPublication.Lock()
	if !atomic.CompareAndSwapInt32(&s.fhsValidationPublicationOwner,
		int32(fhsValidationPublicationNone), int32(owner)) {
		s.muFHSValidationPublication.Unlock()
		return fmt.Errorf("FHS validation publication ownership invariant failed")
	}
	return nil
}

var errFHSValidationPublicationBusy = core.ErrFHSFinalizedSyncPublicationBusy

// tryAcquireFHSValidationPublication is used only by proof-aware P2P sync,
// whose caller already holds BlockChain.chainmu. Waiting here would invert the
// live path's publication-barrier -> chainmu order and deadlock both commits.
// A failed try is deliberately retryable: InsertChain releases chainmu, after
// which the live HotStuff publication can finish. That owner may only be
// publishing a proposal vote and need not canonicalize the synced block, so
// InsertChain must retain and retry the exact downloaded batch itself.
func (s *Service) tryAcquireFHSValidationPublication(owner fhsValidationPublicationOwner) error {
	if s == nil || owner == fhsValidationPublicationNone {
		return fmt.Errorf("invalid FHS validation publication owner")
	}
	if !s.muFHSValidationPublication.TryLock() {
		return errFHSValidationPublicationBusy
	}
	if !atomic.CompareAndSwapInt32(&s.fhsValidationPublicationOwner,
		int32(fhsValidationPublicationNone), int32(owner)) {
		s.muFHSValidationPublication.Unlock()
		return fmt.Errorf("FHS validation publication ownership invariant failed")
	}
	return nil
}

// waitFHSValidationPublication waits for the current publication owner without
// holding BlockChain.chainmu. The sync importer calls this only after a failed
// TryLock attempt has unwound through InsertChain and released chainmu, so a
// live HighQC publication that is waiting to commit can make progress.
func (s *Service) waitFHSValidationPublication() {
	if s == nil {
		return
	}
	s.muFHSValidationPublication.Lock()
	s.muFHSValidationPublication.Unlock()
}

func (s *Service) releaseFHSValidationPublication(owner fhsValidationPublicationOwner) bool {
	if s == nil || owner == fhsValidationPublicationNone ||
		!atomic.CompareAndSwapInt32(&s.fhsValidationPublicationOwner, int32(owner), int32(fhsValidationPublicationNone)) {
		return false
	}
	s.muFHSValidationPublication.Unlock()
	return true
}

// beforeFHSFinalizedSyncKeyCommit rotates only committee-scoped timeout data
// after core has verified the complete direct-child finality proof, but before
// the synced key carrier becomes canonical. LastVote and HighestQC remain as
// global safety watermarks.
func (s *Service) beforeFHSFinalizedSyncKeyCommit(block *types.Block, childQC *hotstuff.SignedState) (bool, error) {
	// The barrier remains held until core invokes the paired finish callback.
	// This hook is called with BlockChain.chainmu held, so it must never wait
	// behind an Apply that owns this barrier and is itself waiting for chainmu.
	// Returning acquired=false tells core not to run the paired finish callback.
	if err := s.tryAcquireFHSValidationPublication(fhsValidationPublicationSyncTransition); err != nil {
		return false, err
	}
	if block == nil || block.BlockType() != types.Key_Block || childQC == nil {
		return true, fmt.Errorf("incomplete Fair HotStuff synced key transition")
	}
	keyBlock := types.DecodeToKeyBlock(block.KeyInfo())
	if keyBlock == nil {
		return true, fmt.Errorf("invalid Fair HotStuff synced key carrier")
	}
	current := s.kbc.CurrentBlock()
	if current == nil {
		return true, fmt.Errorf("missing canonical key head before Fair HotStuff sync transition")
	}
	if current.Hash() != keyBlock.Hash() || current.NumberU64() != keyBlock.NumberU64() {
		if keyBlock.NumberU64() != current.NumberU64()+1 || keyBlock.ParentHash() != current.Hash() {
			return true, fmt.Errorf("non-contiguous Fair HotStuff synced key transition: current=%d/%s next=%d/%s parent=%s",
				current.NumberU64(), current.Hash(), keyBlock.NumberU64(), keyBlock.Hash(), keyBlock.ParentHash())
		}
	}
	// Invalidate speculative work before the canonical key head can change. This
	// mutex is also the successful Apply-to-Broadcast publication barrier: if an
	// old-epoch Prepare is already being published, the sync commit waits for its
	// exact-committee broadcast; otherwise its worker/result can no longer apply.
	// Capture the lifecycle before invalidation: a concurrent Stop/Start must
	// not turn this old import into a request to activate the new service.
	atomic.CompareAndSwapUint64(&s.lifecycleGeneration, 0, 1)
	generation := atomic.LoadUint64(&s.lifecycleGeneration)
	s.invalidateProposalBuildsForEpochTransition()
	s.beginFHSSyncResume(keyBlock, generation)
	if err := s.rotateFHSEpochSafety(keyBlock.Hash()); err != nil {
		return true, err
	}
	return true, nil
}

func (s *Service) invalidateProposalBuildsForEpochTransition() {
	// The sync caller owns muFHSValidationPublication before entering here.
	// This is the global publication lock order used by HighQC continuation
	// paths that may subsequently schedule a proposal build.
	s.muProposalBuild.Lock()
	atomic.StoreInt32(&s.fhsEpochTransition, 1)
	atomic.AddUint64(&s.proposalValidationGeneration, 1)
	s.cancelAllProposalBuildsLocked()
	s.muProposalBuild.Unlock()
	s.cancelAllProposalValidations()
	if s.protocolMng != nil {
		s.protocolMng.ScheduleFHSEpochReset()
	}
}

func (s *Service) finishFHSFinalizedSyncKeyCommit(block *types.Block, outcome core.FHSFinalizedSyncKeyCommitOutcome) {
	if atomic.LoadInt32(&s.fhsValidationPublicationOwner) != int32(fhsValidationPublicationSyncTransition) {
		atomic.StoreInt32(&s.fhsEpochTransition, 1)
		s.setRunState(0)
		log.Error("Fair HotStuff synced key commit lost its validation publication barrier")
		return
	}
	defer func() {
		if !s.releaseFHSValidationPublication(fhsValidationPublicationSyncTransition) {
			atomic.StoreInt32(&s.fhsEpochTransition, 1)
			s.setRunState(0)
			log.Error("Fair HotStuff synced key commit failed to release its validation publication barrier")
		}
	}()
	switch outcome {
	case core.FHSFinalizedSyncPreCommitFailed, core.FHSFinalizedSyncCompleted:
		s.finishFHSSyncResume(outcome == core.FHSFinalizedSyncCompleted)
		s.muProposalBuild.Lock()
		atomic.StoreInt32(&s.fhsEpochTransition, 0)
		s.muProposalBuild.Unlock()
	case core.FHSFinalizedSyncCanonicalAfterFailed:
		// The canonical transaction/key heads have already moved and cannot be
		// rolled back here. Keep the epoch gate closed and stop consensus until
		// startup recovery reconciles the watermark and normalized view.
		s.setRunState(0)
		if block != nil {
			log.Error("Fair HotStuff synced key commit post-processing failed; consensus stopped",
				"number", block.NumberU64(), "hash", block.Hash())
		} else {
			log.Error("Fair HotStuff synced key commit post-processing failed; consensus stopped")
		}
	default:
		// Unknown lifecycle values are internal corruption. Fail closed using
		// the same stopped state while retaining the transition gate.
		s.setRunState(0)
		log.Error("Fair HotStuff synced key commit returned an unknown lifecycle outcome", "outcome", outcome)
	}
}

// afterFHSFinalizedSyncCommit runs after every proof-aware full-sync commit.
// First it advances the durable watermark to the exact canonical block's own
// QC. A key carrier additionally installs the common child-QC pacemaker base
// for the newly active epoch.
func (s *Service) afterFHSFinalizedSyncCommit(block *types.Block, ownQC, childQC *hotstuff.SignedState) error {
	if block == nil || ownQC == nil || childQC == nil {
		return fmt.Errorf("incomplete committed Fair HotStuff sync transition")
	}
	if err := s.reconcileFHSCanonicalQCWatermark(block, ownQC); err != nil {
		return fmt.Errorf("reconcile canonical Fair HotStuff QC watermark: %w", err)
	}
	// ProcInsertDone performs the same volatile reconciliation for a newly
	// inserted canonical block. Repeat it here because the proof-aware importer
	// can also backfill finality metadata onto an already-known canonical head,
	// a path which deliberately does not emit another insertion callback.
	if err := s.reconcileFHSCertifiedFrontier(block); err != nil {
		return fmt.Errorf("reconcile canonical Fair HotStuff runtime frontier: %w", err)
	}
	s.muProposalBody.RLock()
	frontier := s.fhsHighest
	var frontierRef *types.HotstuffProposalRef
	var frontierQCNumber uint64
	if frontier != nil && frontier.ref != nil && frontier.qc != nil {
		refCopy := *frontier.ref
		frontierRef = &refCopy
		frontierQCNumber = frontier.qc.Number
	}
	s.muProposalBody.RUnlock()
	// Publish the new canonical route before the downloader releases chainmu.
	// Restore the unique retained suffix as the proposal parent. Numeric
	// pacemaker progress is monotonic: a locally known higher TC is not discarded
	// merely because sync advanced block state.
	currentKey := s.kbc.CurrentBlock()
	if currentKey == nil {
		return fmt.Errorf("refresh canonical Fair HotStuff runtime route: missing key head")
	}
	routeNumber, routeHash, routeView := block.NumberU64(), block.Hash(), ownQC.Number
	if frontierRef != nil {
		routeNumber, routeHash = frontierRef.Number, frontierRef.BlockHash
		if frontierQCNumber > routeView {
			routeView = frontierQCNumber
		}
	}
	s.muCurrentView.Lock()
	s.currentView.TxNumber = routeNumber
	s.currentView.TxHash = routeHash
	s.currentView.KeyNumber = currentKey.NumberU64()
	s.currentView.KeyHash = currentKey.Hash()
	s.currentView.CommitteeHash = currentKey.CommitteeHash()
	if routeView > s.currentView.ViewNumber {
		s.currentView.ViewNumber = routeView
	}
	s.currentView.Round = 0
	s.currentView.NoDone = true
	if s.currentView.ViewNumber == ^uint64(0) {
		s.muCurrentView.Unlock()
		return fmt.Errorf("refresh canonical Fair HotStuff runtime route: view overflow")
	}
	committee, err := s.loadViewCommittee(&s.currentView, false)
	if err != nil {
		s.muCurrentView.Unlock()
		return fmt.Errorf("refresh canonical Fair HotStuff runtime route: %w", err)
	}
	leaderIndex, err := fairHotstuffLeaderIndex(
		s.chainConfig.FairHotstuffSeed,
		s.ChainID(),
		s.currentView.ViewNumber+1,
		s.currentView.CommitteeHash,
		len(committee.List),
	)
	if err != nil {
		s.muCurrentView.Unlock()
		return fmt.Errorf("refresh canonical Fair HotStuff runtime leader: %w", err)
	}
	s.currentView.LeaderIndex = leaderIndex
	s.waittingView.TxNumber = routeNumber
	s.waittingView.KeyNumber = currentKey.NumberU64()
	s.muCurrentView.Unlock()
	if block.BlockType() != types.Key_Block {
		s.wakeDeferredFHSRecoveryAfterSync(block)
		return nil
	}
	expected := types.DecodeToKeyBlock(block.KeyInfo())
	current := s.kbc.CurrentBlock()
	if expected == nil || current == nil || current.NumberU64() != expected.NumberU64() || current.Hash() != expected.Hash() {
		return fmt.Errorf("Fair HotStuff synced key head was not installed exactly")
	}
	if err := s.normalizeFHSEpochView(childQC, current); err != nil {
		return err
	}
	s.wakeDeferredFHSRecoveryAfterSync(block)
	return nil
}

func (s *Service) wakeDeferredFHSRecovery() {
	if s == nil || s.fhsRecoveryWake == nil {
		return
	}
	select {
	case s.fhsRecoveryWake <- struct{}{}:
	default:
	}
}

// Called only after the proof-aware importer has successfully published its
// WAL and runtime route, while it still holds chainmu. The control loop owns
// gate completion and consensus activation outside the importer.
func (s *Service) wakeDeferredFHSRecoveryAfterSync(block *types.Block) {
	if s == nil || s.fhsStore == nil || block == nil {
		return
	}
	s.fhsStore.safetyMu.Lock()
	if recovery := s.fhsStore.deferredRecovery; recovery != nil {
		recovery.CanonicalSyncHash = block.Hash()
	}
	s.fhsStore.safetyMu.Unlock()
	s.wakeDeferredFHSRecovery()
}

func (s *Service) retryDeferredFHSRecovery() {
	if s == nil || !s.hasDeferredFHSRecovery() || !atomic.CompareAndSwapInt32(&s.fhsRecoveryRetryQueued, 0, 1) {
		return
	}
	time.AfterFunc(fhsDeferredRecoveryRetryDelay, func() {
		atomic.StoreInt32(&s.fhsRecoveryRetryQueued, 0)
		if atomic.LoadInt32(&s.runningState) == 1 && s.hasDeferredFHSRecovery() {
			s.wakeDeferredFHSRecovery()
		}
	})
}

// attemptDeferredFHSRecovery runs only on the serialized HotStuff control
// loop. The network is live for authenticated DA repair, while all ordinary
// consensus messages and pacemaker activity remain gated.
func (s *Service) attemptDeferredFHSRecovery() {
	if s == nil || atomic.LoadInt32(&s.runningState) != 1 || s.fhsStore == nil {
		return
	}
	if completed, err := s.completeCanonicalFHSRecovery(); err != nil {
		log.Warn("Deferred FHS canonical recovery will retry", "err", err)
		s.retryDeferredFHSRecovery()
		return
	} else if completed {
		s.resumeAfterDeferredFHSRecovery()
		return
	}
	recovery := s.fhsStore.deferredRecoverySnapshot()
	if recovery == nil || recovery.HighestQC == nil {
		return
	}
	if s.HasValidatedFHSCertificate(recovery.HighestQC) {
		if err := s.commitFHS2ChainForCertified(recovery.HighestQC); err != nil {
			log.Warn("Deferred FHS recovery commit retry failed", "view", recovery.HighestQC.Number, "err", err)
			s.retryDeferredFHSRecovery()
			return
		}
		completed, err := s.completeDeferredFHSRecovery(recovery.HighestQC)
		if err != nil {
			log.Warn("Deferred FHS recovery completion retry failed", "view", recovery.HighestQC.Number, "err", err)
			s.retryDeferredFHSRecovery()
			return
		}
		if completed {
			s.resumeAfterDeferredFHSRecovery()
		}
		return
	}
	targetView := recovery.RecoveredView
	if targetView <= recovery.HighestQC.Number {
		targetView = recovery.HighestQC.Number + 1
	}
	err := s.protocolMng.RecoverFHSHighQC(recovery.HighestQC, targetView)
	if err == nil || err == hotstuff.ErrProposalValidationPending {
		return
	}
	log.Warn("Deferred FHS recovery scheduling failed", "view", recovery.HighestQC.Number, "err", err)
	s.retryDeferredFHSRecovery()
}

func (s *Service) resumeAfterDeferredFHSRecovery() {
	if s == nil {
		return
	}
	s.muLifecycle.Lock()
	if atomic.LoadInt32(&s.runningState) != 1 || s.hasDeferredFHSRecovery() {
		s.muLifecycle.Unlock()
		return
	}
	generation := s.lifecycleGenerationLocked()
	if bftview.IamMember() < 0 {
		log.Info("Fair HotStuff recovery completed for a non-committee node; stopping consensus service")
		s.setRunState(0)
		s.netService.StartStop(false)
		s.muLifecycle.Unlock()
		return
	}
	_ = s.pacetMakerTimer.start()
	current := s.currentHotstuffBaseNumber()
	pendingTimeout := s.hasPendingFHSTimeoutVote()
	s.muLifecycle.Unlock()
	s.resumeFHSConsensusMessagingForGeneration(generation, current, pendingTimeout)
}

// resumeFHSConsensusMessagingForGeneration keeps durable DB access and local
// consensus activation on the service lifecycle boundary, but sends the
// already-built replay message without holding that lock.
func (s *Service) resumeFHSConsensusMessagingForGeneration(generation, current uint64, pendingTimeout bool) {
	var (
		pendingReplay *hotstuff.SignedState
		replayMessage *hotstuff.HotstuffMessage
		replayErr     error
	)
	s.muLifecycle.Lock()
	if !s.lifecycleGenerationActiveLocked(generation) {
		s.muLifecycle.Unlock()
		return
	}
	pendingReplay, replayMessage, replayErr = s.preparePendingFHSQCBroadcastReplay()
	s.muLifecycle.Unlock()

	if replayErr != nil {
		log.Error("cannot replay durable FHS QC broadcast", "err", replayErr)
	} else {
		s.broadcastPreparedFHSQCBroadcast(pendingReplay, replayMessage)
	}

	s.muLifecycle.Lock()
	defer s.muLifecycle.Unlock()
	if !s.lifecycleGenerationActiveLocked(generation) {
		return
	}
	if pendingTimeout {
		s.enqueueFHSTimeout()
		return
	}
	s.sendNewViewMsgAfterReplay(current)
}
