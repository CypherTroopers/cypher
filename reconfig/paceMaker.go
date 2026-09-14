// Copyright 2017 The cypherBFT Authors
// This file is part of the cypherBFT library.
//
// The cypherBFT library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The cypherBFT library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the cypherBFT library. If not, see <http://www.gnu.org/licenses/>.

package reconfig

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

var maxPaceMakerTime time.Time
var paceMakerPollInterval = 1 * time.Millisecond

const (
	// The native work envelope is denominated in EVM compute units. Pacemaker
	// deadlines must cover every block accepted by that envelope, otherwise a
	// busy but correct validator changes view while its execution worker is
	// still making progress. Version 1 defines a conservative reference machine
	// of 2^30 compute/s per worker and at most 64 useful DAG workers. These are
	// timeout-accounting constants, not a claim about measured hardware speed.
	nativeValidationComputePerSecond uint64 = 1 << 30
	nativeValidationParallelism      uint64 = 64
	nativePaceMakerExecutionMinimum         = 30 * time.Second
)

func nativeComputeLease(compute, perSecond uint64) time.Duration {
	if compute == 0 || perSecond == 0 {
		return 0
	}
	seconds := compute / perSecond
	if compute%perSecond != 0 {
		seconds++
	}
	maxSeconds := uint64(time.Duration(1<<63-1) / time.Second)
	if seconds > maxSeconds {
		return time.Duration(1<<63 - 1)
	}
	return time.Duration(seconds) * time.Second
}

// nativeExecutionLeaseForConfig derives the execution portion of the
// progress deadline from both limiting shapes of the signed dependency DAG:
// its longest serial path and its aggregate compute spread across workers.
func nativeExecutionLeaseForConfig(config *params.ChainConfig) time.Duration {
	if config == nil || !config.NativeParallelEnabled() {
		return 0
	}
	native := config.NativeParallel
	critical := nativeComputeLease(native.MaxCriticalPathCompute, nativeValidationComputePerSecond)
	aggregateRate := nativeValidationComputePerSecond * nativeValidationParallelism
	aggregate := nativeComputeLease(native.MaxComputePerBlock, aggregateRate)
	lease := critical
	if aggregate > lease {
		lease = aggregate
	}
	if lease < nativePaceMakerExecutionMinimum {
		lease = nativePaceMakerExecutionMinimum
	}
	return lease
}

func addDurationSaturating(left, right time.Duration) time.Duration {
	const maximum = time.Duration(1<<63 - 1)
	if right > 0 && left > maximum-right {
		return maximum
	}
	return left + right
}

// paceMakerTimeoutForConfig covers the complete configured proposal body,
// worst-case bounded repair schedule and a validation margin. AckTimeout still
// rotates a genuinely silent leader quickly; this longer progress deadline
// prevents the fixed legacy 30-second timer from changing view while a valid
// genesis-native 256 MiB proposal is being transferred and verified.
func paceMakerTimeoutForConfig(config *params.ChainConfig) time.Duration {
	timeout := params.PaceMakerTimeout
	if config == nil || !config.NativeParallelEnabled() {
		return timeout
	}
	body := proposalBodyWaitTimeoutForConfig(config, config.EffectiveMaxBlockBytes())
	repair := proposalRepairWaitTimeoutForConfig(config, int(config.NativeParallel.MaxTransactionsPerBlock))
	candidate := addDurationSaturating(body, repair)
	candidate = addDurationSaturating(candidate, nativeExecutionLeaseForConfig(config))
	if candidate > timeout {
		return candidate
	}
	return timeout
}

type paceMakerTimer struct {
	startTime        time.Time
	lastKeyTime      time.Time
	beStop           bool
	beClose          bool
	service          serviceI
	txPool           *core.TxPool
	candidatepool    *core.CandidatePool
	retryNumber      int
	lastKeyTriggerAt time.Time
	config           *params.ChainConfig
	kbc              *core.KeyBlockChain
	mu               sync.Mutex

	txsCh  chan core.NewTxsEvent
	txsSub event.Subscription
}

func newPaceMakerTimer(config *params.ChainConfig, s serviceI, backend *ReconfigBackend) *paceMakerTimer {
	maxPaceMakerTime = time.Now().AddDate(200, 0, 0) //200 years
	t := &paceMakerTimer{
		service:       s,
		txPool:        backend.TxPool(),
		candidatepool: backend.CandidatePool(),
		startTime:     maxPaceMakerTime,
		lastKeyTime:   time.Now(),
		beStop:        true,
		beClose:       false,
		config:        config,
	}

	t.txsCh = make(chan core.NewTxsEvent, 8192)
	t.txsSub = backend.TxPool().SubscribeNewTxsEvent(t.txsCh)
	go t.txsEventLoop()

	go t.loopTimer()
	return t
}

// Start for time counting of pacemake
func (t *paceMakerTimer) start() error {
	if t.service != nil && t.service.hasDeferredFHSRecovery() {
		return errFHSRecoveryPending
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.startTime = time.Now()

	t.beStop = false

	return nil
}

// Stop for time counting of pacemake
func (t *paceMakerTimer) stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.beStop = true
	t.retryNumber = 0
	t.startTime = maxPaceMakerTime
	return nil
}

// Close pacemake loop
func (t *paceMakerTimer) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.beClose = true
	if t.txsSub != nil {
		t.txsSub.Unsubscribe()
	}
}
func (t *paceMakerTimer) get() (time.Time, bool, bool, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.startTime, t.beStop, t.beClose, t.retryNumber
}

// Loop for status action
func (t *paceMakerTimer) loopTimer() {
	for {
		time.Sleep(paceMakerPollInterval)
		startTime, beStop, beClose, retryNumber := t.get()
		if beClose {
			return
		}

		if beStop || startTime == maxPaceMakerTime {
			continue
		}

		now := time.Now()
		fixedMode := t.config != nil && (t.config.FixedLeader || t.config.FixedCommittee) && !t.config.FairHotstuff
		leaderSilentFor := now.Sub(t.service.LeaderAckTime())
		progressSilentFor := now.Sub(t.service.HotstuffProgressTime())

		if fixedMode && bftview.IamMember() >= 0 {
			t.mu.Lock()
			lastKeyTime := t.lastKeyTime
			if now.Sub(lastKeyTime) >= params.KeyBlockMinInterval {
				// Fixed-mode keyblock view selection is owned by Service. Mutating
				// the leader here races with Service fallback selection and causes
				// the active leader to flap between primary and fallback.
				if t.lastKeyTriggerAt.IsZero() || now.Sub(t.lastKeyTriggerAt) >= 2*time.Second {
					t.lastKeyTriggerAt = now
					t.mu.Unlock()
					log.Warn("paceMakerTimer fixed mode keyblock trigger", "elapsed", now.Sub(lastKeyTime))
					continue
				}
				t.mu.Unlock()
				continue
			}
			t.mu.Unlock()

			// FixedLeader/FixedCommittee fallback must not be driven directly by this
			// local AckTimeout path. A local ack miss can differ per node and split
			// the committee into different LeaderIndex views. Keyblock fallback is
			// handled by the fixed-mode keyblock view logic in Service.
			continue
		}

		diff := now.Sub(startTime)
		if leaderSilentFor > params.AckTimeout && bftview.IamMember() >= 0 {
			if progressSilentFor <= params.AckTimeout {
				continue
			}
			log.Warn("paceMakerTimer Viewchange AckTimeout", "ackSilentFor", leaderSilentFor, "progressSilentFor", progressSilentFor)
			t.setNextLeader()
			t.service.ResetLeaderAckTime()
		} else if diff > paceMakerTimeoutForConfig(t.config) && bftview.IamMember() >= 0 { //timeout
			log.Warn("paceMakerTimer Viewchange PaceMakerTimeout Event is coming", "retryNumber", retryNumber)
			t.setNextLeader()
			t.retryNumber++
		}
	}
}

func (t *paceMakerTimer) triggerTryPropose() {
	curView := t.service.GetCurrentView()
	if !bftview.IamLeader(curView.LeaderIndex) {
		return
	}
	pending, _ := t.txPool.Stats()
	if pending == 0 {
		return
	}
	if svc, ok := t.service.(*Service); ok {
		svc.clearProposalNoWork()
		svc.triggerTryPropose(curView.TxNumber)
	}
}

func (t *paceMakerTimer) setNextLeader() {
	if t.config != nil && t.config.FairHotstuff {
		if service, ok := t.service.(*Service); ok && service.protocolMng != nil {
			service.enqueueFHSTimeout()
			t.start()
			return
		}
	}
	curView := t.service.GetCurrentView()
	t.service.setNextLeader()
	t.service.sendNewViewMsg(curView.TxNumber)
	t.start()
}

var m_totalTxs int
var m_tps10StartTm time.Time

// Event for new block done
func (t *paceMakerTimer) procBlockDone(curBlock *types.Block, curKeyBlock *types.KeyBlock, isKeyBlock bool) {
	if isKeyBlock {
		t.mu.Lock()
		t.lastKeyTime = time.Now()
		t.lastKeyTriggerAt = time.Time{}
		lastKeyTime := t.lastKeyTime
		t.mu.Unlock()
		log.Debug("paceMakerTimer keyblock done", "lastKeyTime", lastKeyTime)
	}
	if curBlock != nil {
		if t.config.EnabledTPS {
			txs := len(curBlock.Transactions())
			m_totalTxs += txs
			if txs > 0 {
				now := time.Now()
				if m_tps10StartTm.Equal(time.Time{}) {
					m_tps10StartTm = now
				} else if now.Sub(m_tps10StartTm).Seconds() > 10 {
					tps := float64(m_totalTxs) / now.Sub(m_tps10StartTm).Seconds()
					log.Debug("@TPS10", "txs/s", tps)
					m_totalTxs = 0
					m_tps10StartTm = now
				}
				tps := float64(txs) / now.Sub(t.startTime).Seconds()
				log.Debug("@TPS", "txs/s", tps)
			}
		}

		// 360-TX keyblock trigger removed.
		// KeyBlock generation is controlled by time-based fixed-mode KeyBlockMinInterval.

		//if curBlock.NumberU64()%20 == 0 {
		//log.Info("Goroutine", "num", runtime.NumGoroutine())
		//runtime.GC() //force gc
		//}

	}

	t.stop()
	if bftview.IamMember() >= 0 {
		t.start()
	}

}

func (t *paceMakerTimer) txsEventLoop() {
	for {
		select {
		case <-t.txsCh:
			t.mu.Lock()
			beStop := t.beStop
			beClose := t.beClose
			// Transactions make proposal work available, but do not prove that
			// consensus advanced. In FHS, a stalled leader can keep heartbeating
			// while transactions arrive, so retain the no-progress deadline.
			if !beStop && !beClose && (t.config == nil || !t.config.FairHotstuff) {
				t.startTime = time.Now()
			}
			t.mu.Unlock()

			if beClose {
				return
			}
			if beStop || bftview.IamMember() < 0 {
				continue
			}

			t.triggerTryPropose()

		case <-t.txsSub.Err():
			log.Info("txsEventLoop stopped")
			return
		}
	}
}

const (
	failedProposalRetry    = 20 * time.Millisecond
	fastBlockInterval      = 70 * time.Millisecond
	slowBlockInterval      = 1 * time.Second
	slowFallbackMinPending = 1
	// Adaptive slow-block cadence.
	// Heavy/deploy/data/dex transactions live in the slow lane.
	// When slow pending grows, slow blocks must be emitted faster to drain backlog.
	slowIntervalDrainPendingThreshold     = 512
	slowIntervalStrongPendingThreshold    = 2048
	slowIntervalEmergencyPendingThreshold = 8192
	slowBlockDrainInterval                = 250 * time.Millisecond
	slowBlockStrongDrainInterval          = 100 * time.Millisecond
	slowBlockEmergencyDrainInterval       = 70 * time.Millisecond
	// Phase 7A: lane pressure scheduler.
	// If slow lane backlog is much larger than fast lane, keep draining slow lane.
	// This avoids heavy/data/deploy transactions sitting behind fast native/small txs.
	slowPressureRatio         = 2
	slowPressureMinPending    = 512
	slowEmergencyForcePending = 8192
	startNewViewDedupWindow   = 2 * time.Second
)

// proposalWorkStamp identifies every cheap input that can turn a no-work
// proposal result into useful work. A Service retains at most one stamp. The
// Pool, candidate and speculative-exclusion revisions make the steady-state
// comparison O(1); parent, key, view and finality fields prevent the marker
// from surviving consensus progress. The nearest exclusion expiry provides a
// single time-driven wake without rescanning the exclusion map on every tick.
type proposalWorkStamp struct {
	fairHotstuff      bool
	poolRevision      uint64
	candidateRevision uint64
	proposedRevision  uint64
	proposedExpiry    time.Time
	parentNumber      uint64
	parentHash        common.Hash
	keyNumber         uint64
	keyHash           common.Hash
	view              bftview.View
	proposalView      uint64
	proposalViewID    common.Hash
	proposalLeaderID  string
	finality          bool
	keyblockReady     bool
	keyblockPending   bool
}

func (s *Service) captureProposalWorkStamp(now time.Time, proposalViewNumber uint64, proposalViewID common.Hash, leaderID string) (proposalWorkStamp, bool) {
	var stamp proposalWorkStamp
	if s == nil || s.txPool == nil || s.txService == nil || s.bc == nil || s.kbc == nil {
		return stamp, false
	}
	poolRevision := s.txPool.PendingRevision()
	proposedRevision, proposedExpiry, ok := s.txService.proposalExclusionState()
	if !ok {
		return stamp, false
	}
	candidateRevision := uint64(0)
	if s.keyService != nil && s.keyService.candidatepool != nil {
		candidateRevision = s.keyService.candidatepool.Revision()
	}
	view := s.GetCurrentView()
	parent := s.bc.CurrentBlock()
	if s.fairHotstuffEnabled() {
		if highest := s.highestFHSCertifiedProposal(); highest != nil && highest.Block != nil {
			parent = highest.Block
		}
	}
	keyBlock := s.kbc.CurrentBlock()
	if view == nil || parent == nil || keyBlock == nil {
		return stamp, false
	}
	if s.fairHotstuffEnabled() && (view.TxNumber != parent.NumberU64() || view.TxHash != parent.Hash()) {
		// An asynchronous certificate/view transition is between its publication
		// steps. Do not suppress anything from this mixed snapshot.
		return stamp, false
	}
	if s.fairHotstuffEnabled() && (view.KeyNumber != keyBlock.NumberU64() || view.KeyHash != keyBlock.Hash()) {
		return stamp, false
	}
	finality := s.needsFHSFinalityBlock()
	keyblockReady := s.fixedModeKeyblockIntervalElapsed(now)
	stamp = proposalWorkStamp{
		fairHotstuff:      s.fairHotstuffEnabled(),
		poolRevision:      poolRevision,
		candidateRevision: candidateRevision,
		proposedRevision:  proposedRevision,
		proposedExpiry:    proposedExpiry,
		parentNumber:      parent.NumberU64(),
		parentHash:        parent.Hash(),
		keyNumber:         keyBlock.NumberU64(),
		keyHash:           keyBlock.Hash(),
		view:              *view,
		proposalView:      proposalViewNumber,
		proposalViewID:    proposalViewID,
		proposalLeaderID:  leaderID,
		finality:          finality,
		keyblockReady:     keyblockReady,
		keyblockPending:   keyblockReady && s.keyService != nil && s.keyService.fixedModeEnabled() && !finality,
	}
	// Re-read the O(1) generation and consensus identities after the composite
	// snapshot. A concurrent change may cause an unnecessary retry, but can never
	// install a stale marker that suppresses new work.
	if poolRevision != s.txPool.PendingRevision() || !view.EqualAll(s.GetCurrentView()) {
		return proposalWorkStamp{}, false
	}
	currentProposedRevision, currentProposedExpiry, ok := s.txService.proposalExclusionState()
	if !ok || proposedRevision != currentProposedRevision || proposedExpiry != currentProposedExpiry {
		return proposalWorkStamp{}, false
	}
	if s.keyService != nil && s.keyService.candidatepool != nil && candidateRevision != s.keyService.candidatepool.Revision() {
		return proposalWorkStamp{}, false
	}
	currentParent := s.bc.CurrentBlock()
	if s.fairHotstuffEnabled() {
		if highest := s.highestFHSCertifiedProposal(); highest != nil && highest.Block != nil {
			currentParent = highest.Block
		}
	}
	currentKey := s.kbc.CurrentBlock()
	if currentParent == nil || currentKey == nil || currentParent.NumberU64() != stamp.parentNumber || currentParent.Hash() != stamp.parentHash ||
		currentKey.NumberU64() != stamp.keyNumber || currentKey.Hash() != stamp.keyHash {
		return proposalWorkStamp{}, false
	}
	return stamp, true
}

func (s *Service) rememberProposalNoWork(stamp proposalWorkStamp, valid bool) {
	if !valid {
		return
	}
	current, ok := s.captureProposalWorkStamp(time.Now(), stamp.proposalView, stamp.proposalViewID, stamp.proposalLeaderID)
	s.rememberProposalNoWorkIfCurrent(stamp, current, ok)
}

func (s *Service) rememberProposalNoWorkIfCurrent(stamp, current proposalWorkStamp, valid bool) bool {
	// Proposal view ID and leader live in the HotStuff recovery callback. The
	// current service view and all work-producing inputs are fixed by the stamp.
	// A ready fixed-mode keyblock is real work even when both transaction lanes
	// are empty. Its eligibility is interval-derived and remains pending across
	// local NoDone changes until the key carrier or its finality child advances.
	if !valid || current != stamp || stamp.keyblockPending {
		return false
	}
	s.muProposalNoWork.Lock()
	copy := stamp
	s.proposalNoWork = &copy
	s.muProposalNoWork.Unlock()
	return true
}

func (s *Service) clearProposalNoWork() {
	if s == nil {
		return
	}
	s.muProposalNoWork.Lock()
	s.proposalNoWork = nil
	s.muProposalNoWork.Unlock()
}

func (s *Service) proposalNoWorkUnchanged(now time.Time) bool {
	if s == nil {
		return false
	}
	s.muProposalNoWork.Lock()
	if s.proposalNoWork == nil {
		s.muProposalNoWork.Unlock()
		return false
	}
	remembered := *s.proposalNoWork
	s.muProposalNoWork.Unlock()

	if proposalNoWorkExpiryElapsed(remembered, now) {
		return s.proposalNoWorkMatchesCurrent(remembered, proposalWorkStamp{}, false)
	}
	current, ok := s.captureProposalWorkStamp(now, remembered.proposalView, remembered.proposalViewID, remembered.proposalLeaderID)
	return s.proposalNoWorkMatchesCurrent(remembered, current, ok)
}

func proposalNoWorkExpiryElapsed(stamp proposalWorkStamp, now time.Time) bool {
	return !stamp.proposedExpiry.IsZero() && now.After(stamp.proposedExpiry)
}

func (s *Service) proposalNoWorkMatchesCurrent(remembered, current proposalWorkStamp, valid bool) bool {
	s.muProposalNoWork.Lock()
	defer s.muProposalNoWork.Unlock()
	if s.proposalNoWork == nil || *s.proposalNoWork != remembered {
		return false
	}
	if valid && current == remembered {
		return true
	}
	s.proposalNoWork = nil
	return false
}

// ProposalRecoveryReady prevents HotStuff's generic five-second recovery loop
// from defeating an application-level no-work result. Ordinary transient
// failures never install the watermark and therefore remain retryable.
func (s *Service) ProposalRecoveryReady(viewNumber uint64, viewID common.Hash, leaderID string) bool {
	s.muProposalNoWork.Lock()
	remembered := s.proposalNoWork
	exactView := remembered != nil && remembered.proposalView == viewNumber && remembered.proposalViewID == viewID && remembered.proposalLeaderID == leaderID
	s.muProposalNoWork.Unlock()
	if !exactView {
		return true
	}
	if !s.proposalNoWorkUnchanged(time.Now()) {
		return true
	}
	return false
}

func (s *Service) scheduleProposalBuildRetry(key hotstuff.FHSProposalBuildKey) {
	go func() {
		time.Sleep(failedProposalRetry)
		if atomic.LoadInt32(&s.runningState) != 1 {
			return
		}
		state, leaderID, number := s.CurrentState()
		if number != key.ViewNumber || leaderID != key.LeaderID || hotstuff.StateDigest(state) != key.CurrentStateDigest || leaderID != s.Self() {
			return
		}
		s.triggerTryPropose(s.bc.CurrentBlockN())
	}()
}

func shouldRetryFHSProposalBuild(err error) bool {
	return err != nil && !errors.Is(err, hotstuff.ErrOldState) && !errors.Is(err, errProposalNoWork)
}

func (s *Service) triggerTryPropose(lastN uint64) {
	if atomic.LoadInt32(&s.runningState) != 1 {
		return
	}
	if s.fairHotstuffEnabled() {
		lastN = s.GetCurrentView().ViewNumber
	}
	if !atomic.CompareAndSwapInt32(&s.tryProposeQueued, 0, 1) {
		return
	}
	if !s.enqueueHotstuffPriority(&hotstuffMsg{
		sid:   nil,
		lastN: lastN,
		hMsg:  &hotstuff.HotstuffMessage{Code: hotstuff.MsgTryPropose},
	}) {
		atomic.StoreInt32(&s.tryProposeQueued, 0)
	}
}

func (s *Service) enqueueTimerPriority(curN uint64) {
	if s.fairHotstuffEnabled() {
		curN = s.GetCurrentView().ViewNumber
	}
	s.enqueueHotstuffPriority(&hotstuffMsg{
		sid:   nil,
		lastN: curN,
		hMsg:  &hotstuff.HotstuffMessage{Code: hotstuff.MsgTimer, Number: curN},
	})
}

func readableTxBlockType(blockType uint8) string {
	switch blockType {
	case types.FastTx_Block:
		return "fast"
	case types.SlowTx_Block:
		return "slow"
	case types.Key_Block:
		return "key"
	default:
		return "unknown"
	}
}

func (s *Service) shouldEmitFastBlock(now time.Time) bool {
	s.muProposalCadence.RLock()
	defer s.muProposalCadence.RUnlock()
	if s.lastFastBlockTime.IsZero() {
		return true
	}
	return now.Sub(s.lastFastBlockTime) >= fastBlockInterval
}

func adaptiveSlowBlockInterval(slowPending int) time.Duration {
	switch {
	case slowPending >= slowIntervalEmergencyPendingThreshold:
		return slowBlockEmergencyDrainInterval
	case slowPending >= slowIntervalStrongPendingThreshold:
		return slowBlockStrongDrainInterval
	case slowPending >= slowIntervalDrainPendingThreshold:
		return slowBlockDrainInterval
	default:
		return slowBlockInterval
	}
}

func (s *Service) shouldEmitSlowBlock(now time.Time, slowPending int) bool {
	s.muProposalCadence.RLock()
	defer s.muProposalCadence.RUnlock()
	if s.lastSlowBlockTime.IsZero() {
		return true
	}
	return now.Sub(s.lastSlowBlockTime) >= adaptiveSlowBlockInterval(slowPending)
}

func (s *Service) lanePendingCounts() (fastPending int, slowPending int) {
	if s.txPool == nil {
		return 0, 0
	}
	fastPending, slowPending, _ = s.txPool.PendingClassStats()
	return fastPending, slowPending
}

func slowLanePressureHigh(fastPending int, slowPending int) bool {
	if slowPending < slowPressureMinPending {
		return false
	}
	if fastPending <= 0 {
		return true
	}
	return slowPending >= fastPending*slowPressureRatio
}

func slowLaneEmergency(slowPending int) bool {
	return slowPending >= slowEmergencyForcePending
}

func (s *Service) chooseTxBlockType() uint8 {
	fastPending, slowPending := s.lanePendingCounts()
	now := time.Now()

	fastReady := fastPending > 0 && s.shouldEmitFastBlock(now)
	slowReady := slowPending > 0 && s.shouldEmitSlowBlock(now, slowPending)

	// Emergency slow backlog:
	// Do not allow fast lane to keep stealing proposal opportunities.
	// This still creates normal SlowTx_Block, so block verification compatibility is kept.
	if slowLaneEmergency(slowPending) {
		return types.SlowTx_Block
	}

	// Strong slow pressure:
	// Prefer slow if its adaptive interval is ready.
	if slowLanePressureHigh(fastPending, slowPending) && slowReady {
		return types.SlowTx_Block
	}

	// Normal cadence.
	switch {
	case fastReady:
		return types.FastTx_Block
	case slowReady:
		return types.SlowTx_Block
	case fastPending > 0 && !slowLanePressureHigh(fastPending, slowPending):
		return types.FastTx_Block
	case slowPending >= slowFallbackMinPending:
		return types.SlowTx_Block
	default:
		return types.FastTx_Block
	}
}

func (s *Service) observeHotstuffProgress(msg *hotstuff.HotstuffMessage) {
	if msg == nil {
		return
	}
	rank := uint8(0)
	switch msg.Code {
	case hotstuff.MsgPrepare:
		rank = 1
	case hotstuff.MsgVotePrepare:
		rank = 2
	case hotstuff.MsgQCBroadcast:
		rank = 3
	case hotstuff.MsgDecide:
		rank = 4
	case hotstuff.MsgTimeoutQC:
		rank = 1
	default:
		return
	}

	s.muHotstuffProgress.Lock()
	defer s.muHotstuffProgress.Unlock()
	if msg.Number > s.lastProgressN ||
		(msg.Number == s.lastProgressN && msg.ViewId != s.lastProgressViewID) ||
		(msg.Number == s.lastProgressN && msg.ViewId == s.lastProgressViewID && rank > s.lastProgressRank) {
		s.lastProgressN = msg.Number
		s.lastProgressViewID = msg.ViewId
		s.lastProgressRank = rank
		s.hotstuffProgressAt = time.Now()
	}
}

func (s *Service) HotstuffProgressTime() time.Time {
	s.muHotstuffProgress.Lock()
	defer s.muHotstuffProgress.Unlock()
	return s.hotstuffProgressAt
}

// Send new view when new block done
func (s *Service) sendNewViewMsg(curN uint64) {
	if s.hasDeferredFHSRecovery() {
		return
	}
	if s.fairHotstuffEnabled() {
		// A leader-created QC remains in a durable outbox until a higher QC
		// proves quorum dissemination. Replay it before every new-view attempt;
		// outbound coalescing prevents duplicate queue growth.
		s.replayPendingFHSQCBroadcast()
	}
	s.sendNewViewMsgAfterReplay(curN)
}

// sendNewViewMsgAfterReplay performs only the process-local NewView admission.
// Generation-aware QC completion calls this while holding muLifecycle, after
// any durable network replay has completed without that lock.
func (s *Service) sendNewViewMsgAfterReplay(curN uint64) {
	if s.hasDeferredFHSRecovery() {
		return
	}
	now := time.Now()
	curView := s.GetCurrentView()
	if s.fairHotstuffEnabled() {
		curN = curView.ViewNumber
	}
	viewHash := curView.ConsensusHash()

	s.muStartNewView.Lock()
	if curN == s.lastStartNewViewN &&
		viewHash == s.lastStartNewViewHash &&
		!s.lastStartNewViewAt.IsZero() &&
		now.Sub(s.lastStartNewViewAt) < startNewViewDedupWindow {
		s.muStartNewView.Unlock()
		log.Debug("suppress duplicate start-new-view",
			"curN", curN,
			"viewHash", viewHash,
			"since", now.Sub(s.lastStartNewViewAt))
		return
	}
	s.lastStartNewViewN = curN
	s.lastStartNewViewHash = viewHash
	s.lastStartNewViewAt = now
	s.muStartNewView.Unlock()

	if bftview.IamMember() >= 0 && (s.fairHotstuffEnabled() || curN >= s.bc.CurrentBlockN()) {
		s.enqueueHotstuffPriority(&hotstuffMsg{sid: nil, lastN: curN, hMsg: &hotstuff.HotstuffMessage{Code: hotstuff.MsgStartNewView, Number: curN}})
	}
}

func (s *Service) enqueueFHSTimeout() {
	if s.hasDeferredFHSRecovery() {
		return
	}
	s.enqueueHotstuffPriority(&hotstuffMsg{sid: nil, hMsg: &hotstuff.HotstuffMessage{Code: hotstuff.MsgLocalTimeout}})
}

// setNextLeader advances the leader after a proposal timeout.
func (s *Service) setNextLeader() {
	s.muCurrentView.Lock()
	defer s.muCurrentView.Unlock()

	switch {
	case s.fairHotstuffEnabled():
		// A failed proposal consumes its view while retaining the certified parent.
		s.currentView.ViewNumber++
		s.currentView.LeaderIndex = s.fairHotstuffLeaderIndexForCurrentLocked()
	case s.keyService != nil && s.keyService.fixedLeaderModeEnabled():
		primary := s.normalizeLeaderIndex(s.keyService.getPrimaryLeaderIndex())
		leaderIndex := s.normalizeLeaderIndex(s.keyService.getFallbackLeaderIndex(primary))
		s.currentView.LeaderIndex = leaderIndex
		s.keyService.setActiveLeader(leaderIndex)
	default:
		s.currentView.LeaderIndex = s.keyService.getNextLeaderIndex(s.currentView.LeaderIndex)
	}
	s.currentView.NoDone = true
	s.waittingView.TxNumber = s.currentView.TxNumber + 1
	s.waittingView.KeyNumber = s.currentView.KeyNumber + 1
	log.Info("setNextLeader", "index", s.currentView.LeaderIndex,
		"txNumber", s.currentView.TxNumber, "keyNumber", s.currentView.KeyNumber)
}

func (s *Service) LeaderAckTime() time.Time {
	mb := bftview.GetCurrentMember()
	if mb != nil {
		curView := s.GetCurrentView()
		if bftview.IamLeader(curView.LeaderIndex) {
			return time.Now()
		}
		leader := mb.List[curView.LeaderIndex]
		return s.netService.GetAckTime(leader.Address)
	}
	return time.Now()
}

func (s *Service) ResetLeaderAckTime() {
	mb := bftview.GetCurrentMember()
	if mb != nil {
		curView := s.GetCurrentView()
		leader := mb.List[curView.LeaderIndex]
		s.netService.ResetAckTime(leader.Address)
	}
}
