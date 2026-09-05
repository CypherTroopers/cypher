package reconfig

import (
	"sync/atomic"
	"time"

	"github.com/cypherium/cypher/common"
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
