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
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

// Service coordinates consensus lifecycle, workers, and chain progress.
type Service struct {
	netService                  *netService
	bc                          *core.BlockChain
	txService                   *txService
	kbc                         *core.KeyBlockChain
	keyService                  *keyService
	txPool                      *core.TxPool
	removeFailedProposalTxs     func(types.Transactions)
	resolveTxQUICTransaction    func(common.Hash) (*types.Transaction, error)
	decodeProposalBodyForRepair func([]byte) *types.Block
	chainConfig                 *params.ChainConfig

	protocolMng *hotstuff.HotstuffProtocolManager

	lastCmInfoMap   map[common.Hash]*cachedCommitteeInfo
	muCommitteeInfo sync.Mutex
	currentView     bftview.View
	waittingView    bftview.View
	lastReqCmNumber uint64
	muCurrentView   sync.Mutex

	replicaView                  *bftview.View
	runningState                 int32
	muLifecycle                  sync.Mutex
	lifecycleGeneration          uint64
	proposalValidationGeneration uint64
	muProposalCadence            sync.RWMutex
	lastSlowBlockTime            time.Time
	lastFastBlockTime            time.Time
	lastCadenceWakeup            time.Time
	lastFixedKeyNewViewWakeup    time.Time
	fixedKeyViewStartedAt        time.Time
	fixedKeyViewTxNumber         uint64
	fixedKeyViewKeyNumber        uint64
	fixedKeyViewTxHash           common.Hash
	fixedKeyViewKeyHash          common.Hash
	lastCandidateRewardCheck     time.Time
	lastCandidateRewardReady     bool
	tryProposeQueued             int32
	muProposalNoWork             sync.Mutex
	proposalNoWork               *proposalWorkStamp
	muStartNewView               sync.Mutex
	lastStartNewViewN            uint64
	lastStartNewViewHash         common.Hash
	lastStartNewViewAt           time.Time
	pacetMakerTimer              *paceMakerTimer
	muHotstuffProgress           sync.Mutex
	hotstuffProgressAt           time.Time
	lastProgressN                uint64
	lastProgressViewID           common.Hash
	lastProgressRank             uint8

	muProposalBody             sync.RWMutex
	proposalBodies             map[common.Hash]*proposalBodyMsg
	proposalAssemblies         map[common.Hash]*proposalAssemblyState
	proposalAssemblyBuilds     map[common.Hash]*proposalAssemblyBuild
	proposalAssemblyBuildSlots chan struct{}
	proposalBodyWake           chan struct{}
	verifiedProposalByID       map[common.Hash]*core.VerifiedProposal
	fhsCertifiedByHash         map[common.Hash]*fhsCertifiedProposal
	fhsCertifiedByID           map[common.Hash]*fhsCertifiedProposal
	fhsHighest                 *fhsCertifiedProposal
	// fhsSelectedParent is the execution parent selected by a verified NewView
	// quorum. It may differ from the monotonically observed fhsHighest.
	fhsSelectedParent *fhsCertifiedProposal
	fhsParentSelected bool
	fhsStore          *fhsSafetyStore
	fhsContentWriter  *fhsContentWriter
	// These QC broadcast markers are deliberately memory-only. The active
	// marker brackets every physical send. The completed marker suppresses only
	// a matching durable-outbox replay for a short period after that send. A
	// restart loses both markers but retains the durable outbox, so crash
	// recovery still rebroadcasts immediately.
	muFHSQCBroadcast               sync.Mutex
	fhsActiveQCBroadcast           *hotstuff.SignedState
	fhsActiveQCBroadcastGeneration uint64
	fhsCompletedQCBroadcast        *hotstuff.SignedState
	fhsCompletedQCBroadcastExpiry  time.Time
	muConsensusIdentity            sync.RWMutex
	consensusPublic                *bls.PublicKey
	proposalBodySecret             *bls.SecretKey
	proposalBodySignMu             sync.Mutex
	txQUICReceiptSecret            *bls.SecretKey
	txQUICReceiptPublic            *bls.PublicKey
	txQUICReceiptSignMu            sync.Mutex

	hotstuffMsgQ              *hotstuffMessageQueue
	proposalValidationJobs    chan *proposalValidationJob
	proposalValidationResults chan *hotstuff.FHSProposalValidationResult
	highQCValidationResults   chan *hotstuff.FHSHighQCValidationResult
	fhsRecoveryWake           chan struct{}
	fhsRecoveryRetryQueued    int32
	muFHSSyncResume           sync.Mutex
	fhsSyncResume             *fhsSyncResumeRequest
	fhsSyncResumePreparing    *fhsSyncResumeRequest
	muProposalValidation      sync.Mutex
	activeProposalValidation  *proposalValidationControl
	activeHighQCValidation    *highQCValidationControl
	proposalValidationSeq     uint64
	// muFHSValidationPublication is transferred from a successful application
	// Apply callback to its manager Finish callback. It linearizes proposal
	// vote publication and HighQC installation against proof-aware key sync.
	// Lock order: muFHSValidationPublication -> muProposalBuild ->
	// muCurrentView -> txService.mu.
	muFHSValidationPublication      sync.Mutex
	fhsValidationPublicationOwner   int32
	activeProposalValidationPublish *hotstuff.FHSProposalValidationResult
	activeHighQCValidationPublish   *hotstuff.FHSHighQCValidationResult
	proposalBuildJobs               chan *proposalBuildJob
	proposalBuildResults            chan *hotstuff.FHSProposalBuildResult
	muProposalBuild                 sync.Mutex
	activeProposalBuild             *proposalBuildControl
	fhsEpochTransition              int32
	proposalBuildSeq                uint64
	proposalManifestSlots           chan struct{}
	proposalManifestJobs            chan *proposalManifestDispatch
	proposalFailedTxSlots           chan struct{}
	proposalFailedTxJobs            chan *proposalFailedTxCleanup
	feed1                           event.Feed
	msgCh1                          chan committeeMsg
	msgSub1                         event.Subscription // Subscription for msg event
}

var _ hotstuff.FHSProposalValidationApplication = (*Service)(nil)
var _ hotstuff.FHSHighQCValidationApplication = (*Service)(nil)
var _ hotstuff.FHSProposalBuildApplication = (*Service)(nil)

func newService(sName, sIp string, chainConfig *params.ChainConfig, backend *ReconfigBackend) *Service {
	s := new(Service)
	s.netService = newNetService(sName, sIp, chainConfig, backend, s)
	s.txService = newTxService(s, backend, chainConfig)
	s.keyService = newKeyService(s, backend, chainConfig)

	s.bc = backend.BlockChain()
	s.kbc = backend.KeyBlockChain()
	s.txPool = backend.TxPool()
	if s.txPool != nil {
		s.removeFailedProposalTxs = s.txPool.RemoveBatch
	}
	s.resolveTxQUICTransaction = backend.resolveTxQUICTransaction
	s.chainConfig = chainConfig
	var chainID uint64
	if chainConfig != nil && chainConfig.ChainID != nil {
		chainID = chainConfig.ChainID.Uint64()
	}
	var genesisHash common.Hash
	if s.bc != nil && s.bc.Genesis() != nil {
		genesisHash = s.bc.Genesis().Hash()
	}
	s.fhsStore = newFHSSafetyStoreForConfig(backend.ChainDb(), chainID, genesisHash, chainConfig)
	s.fhsContentWriter = newFHSContentWriterForConfig(chainConfig, s.persistFHSProposalData)

	s.lastCmInfoMap = make(map[common.Hash]*cachedCommitteeInfo)
	s.proposalBodies = make(map[common.Hash]*proposalBodyMsg)
	s.proposalAssemblies = make(map[common.Hash]*proposalAssemblyState)
	s.proposalAssemblyBuilds = make(map[common.Hash]*proposalAssemblyBuild)
	s.proposalAssemblyBuildSlots = make(chan struct{}, 1)
	s.proposalBodyWake = make(chan struct{})
	s.verifiedProposalByID = make(map[common.Hash]*core.VerifiedProposal)
	s.fhsCertifiedByHash = make(map[common.Hash]*fhsCertifiedProposal)
	s.fhsCertifiedByID = make(map[common.Hash]*fhsCertifiedProposal)

	s.msgCh1 = make(chan committeeMsg, 10)
	s.msgSub1 = s.feed1.Subscribe(s.msgCh1)
	s.hotstuffMsgQ = newHotstuffMessageQueue()
	s.proposalValidationJobs = make(chan *proposalValidationJob, proposalValidationQueueCapacity)
	s.proposalValidationResults = make(chan *hotstuff.FHSProposalValidationResult, proposalValidationWorkers+1)
	s.highQCValidationResults = make(chan *hotstuff.FHSHighQCValidationResult, proposalValidationWorkers+1)
	s.fhsRecoveryWake = make(chan struct{}, 1)
	s.proposalBuildJobs = make(chan *proposalBuildJob, proposalBuildQueueCapacity)
	s.proposalBuildResults = make(chan *hotstuff.FHSProposalBuildResult, proposalBuildWorkers+1)
	s.proposalManifestSlots = make(chan struct{}, proposalManifestDispatchCapacity)
	s.proposalManifestJobs = make(chan *proposalManifestDispatch, proposalManifestDispatchCapacity)
	s.proposalFailedTxSlots = make(chan struct{}, proposalFailedTxCleanupCapacity)
	s.proposalFailedTxJobs = make(chan *proposalFailedTxCleanup, proposalFailedTxCleanupCapacity)
	s.hotstuffProgressAt = time.Now()

	s.protocolMng = hotstuff.NewHotstuffProtocolManager(s, nil, nil)
	s.pacetMakerTimer = newPaceMakerTimer(chainConfig, s, backend)

	bftview.SetCommitteeConfig(backend.ChainDb(), backend.KeyBlockChain(), s)

	go s.handleHotStuffMsg()
	for worker := 0; worker < proposalValidationWorkers; worker++ {
		go s.proposalValidationWorker()
	}
	for worker := 0; worker < proposalBuildWorkers; worker++ {
		go s.proposalBuildWorker()
	}
	for worker := 0; worker < proposalManifestDispatchWorkers; worker++ {
		go s.proposalManifestDispatchWorker()
	}
	go s.proposalFailedTxCleanupWorker()
	go s.handleCommitteeMsg()
	go s.keyblockLivenessLoop()
	return s
}

func (s *Service) ChainID() uint64 {
	if s.chainConfig != nil && s.chainConfig.ChainID != nil {
		return s.chainConfig.ChainID.Uint64()
	}
	return 0
}

func (s *Service) UseContextSignatures() bool {
	return true
}

func (s *Service) RequireMessageAuth() bool {
	return true
}

func (s *Service) UseFHS2Chain() bool {
	return s.fairHotstuffEnabled()
}

var _ hotstuff.FHSProposalReadinessApplication = (*Service)(nil)

// Self call by hotstuff
func (s *Service) Self() string {
	return s.netService.serverID
}

// lifecycleGenerationLocked returns the currently active process-local service
// generation. The caller must hold muLifecycle. Zero is reserved for tests and
// direct marker helpers that do not participate in MinerStart/MinerStop.
func (s *Service) lifecycleGenerationLocked() uint64 {
	atomic.CompareAndSwapUint64(&s.lifecycleGeneration, 0, 1)
	return atomic.LoadUint64(&s.lifecycleGeneration)
}

// advanceLifecycleGenerationLocked invalidates every in-flight callback from a
// previous MinerStart/MinerStop boundary. The caller must hold muLifecycle.
func (s *Service) advanceLifecycleGenerationLocked() uint64 {
	generation := atomic.AddUint64(&s.lifecycleGeneration, 1)
	if generation == 0 {
		generation = atomic.AddUint64(&s.lifecycleGeneration, 1)
	}
	return generation
}

func (s *Service) lifecycleGenerationActiveLocked(generation uint64) bool {
	return generation != 0 && atomic.LoadUint64(&s.lifecycleGeneration) == generation && atomic.LoadInt32(&s.runningState) == 1
}

func (s *Service) lifecycleGenerationActive(generation uint64) bool {
	if s == nil {
		return false
	}
	s.muLifecycle.Lock()
	defer s.muLifecycle.Unlock()
	return s.lifecycleGenerationActiveLocked(generation)
}

func (s *Service) fairHotstuffEnabled() bool {
	return s.chainConfig != nil && s.chainConfig.FairHotstuff
}

func (s *Service) handleHotstuffPoolMaintenance(now time.Time) {
	if s.proposalNoWorkUnchanged(now) {
		return
	}
	fastPending, slowPending := s.lanePendingCounts()
	pendingTotal := 0
	if s.txPool != nil {
		pendingTotal, _ = s.txPool.Stats()
	}
	candidateRewardReady := s.fixedModeCandidateRewardReady(now)
	if s.fixedModeKeyblockIntervalElapsed(now) {
		s.wakeFixedModeKeyblock(now, "hotstuff-maintenance", candidateRewardReady, pendingTotal, fastPending, slowPending)
		return
	}
	s.repairFixedModeTxProposalViewIfPending(pendingTotal)
	if !bftview.IamLeader(s.GetCurrentView().LeaderIndex) {
		return
	}
	cadenceReady := candidateRewardReady || pendingTotal > 0 ||
		(fastPending > 0 && s.shouldEmitFastBlock(now)) ||
		(slowPending > 0 && s.shouldEmitSlowBlock(now, slowPending))
	if !cadenceReady || (!s.lastCadenceWakeup.IsZero() && now.Sub(s.lastCadenceWakeup) < 50*time.Millisecond) {
		return
	}
	s.lastCadenceWakeup = now
	// FHS new-view activation schedules the first proposal directly. Run this
	// side-effect-free canonical snapshot check only after cadence admits a
	// retry, and account for the attempt above even when the view is stale.
	if s.fairHotstuffEnabled() && (s.protocolMng == nil || !s.protocolMng.CanTryPropose()) {
		return
	}
	if pendingTotal > 0 && fastPending == 0 && slowPending == 0 {
		log.Warn("tx proposal liveness fallback wakeup",
			"pendingTotal", pendingTotal, "fastPending", fastPending, "slowPending", slowPending, "currentBlock", s.bc.CurrentBlockN())
	}
	if candidateRewardReady && pendingTotal == 0 {
		log.Warn("fixed-mode candidate reward new-view wakeup",
			"currentBlock", s.bc.CurrentBlockN(), "currentKey", s.kbc.CurrentBlockN(),
			"pendingTotal", pendingTotal, "fastPending", fastPending, "slowPending", slowPending)
	} else if candidateRewardReady {
		log.Warn("fixed-mode candidate reward delayed because txpool has pending txs",
			"currentBlock", s.bc.CurrentBlockN(), "currentKey", s.kbc.CurrentBlockN(),
			"pendingTotal", pendingTotal, "fastPending", fastPending, "slowPending", slowPending)
	}
	s.triggerTryPropose(s.bc.CurrentBlockN())
}

func (s *Service) handleHotStuffMsg() {
	poolTicker := time.NewTicker(25 * time.Millisecond)
	defer poolTicker.Stop()
	timerTicker := time.NewTicker(10 * time.Millisecond)
	defer timerTicker.Stop()

	for {
		// Only this loop owns the protocol manager. Sync callbacks merely record
		// a request while chainmu is held; the 10 ms ticker also retries it when
		// no other messages arrive.
		s.processFHSSyncResume()
		var data *hotstuffMsg
		select {
		case result := <-s.proposalBuildResults:
			if atomic.LoadInt32(&s.runningState) != 1 || s.hasDeferredFHSRecovery() {
				s.finishProposalBuild(result.Key)
				continue
			}
			err := s.protocolMng.HandleFHSProposalBuildResult(result)
			output, _ := result.ApplicationData.(*proposalBuildOutput)
			if errors.Is(err, errProposalNoWork) && output != nil {
				s.rememberProposalNoWork(output.workStamp, output.workStampValid)
			} else if !errors.Is(err, hotstuff.ErrOldState) {
				// Success and real failures both remain immediately actionable. Only
				// an accepted no-work result may quiesce this exact input generation.
				s.clearProposalNoWork()
			}
			if err != hotstuff.ErrOldState && result.Err != nil && output != nil && output.fixedMode && output.keyProposalAttempt {
				s.abortFixedModeKeyProposal("asynchronous proposal construction failed", result.Err)
			}
			s.finishProposalBuild(result.Key)
			if shouldRetryFHSProposalBuild(err) {
				log.Warn("FHS proposal construction completion rejected",
					"view", result.Key.ViewNumber, "viewID", result.Key.ViewID, "err", err)
				s.scheduleProposalBuildRetry(result.Key)
			}
			continue
		case result := <-s.proposalValidationResults:
			if atomic.LoadInt32(&s.runningState) != 1 || s.hasDeferredFHSRecovery() {
				s.finishProposalValidation(result.Key)
				continue
			}
			err := s.protocolMng.HandleFHSProposalValidationResult(result)
			s.finishProposalValidation(result.Key)
			s.cancelInactiveProposalValidations(s.GetCurrentView().ViewNumber + 1)
			if err == nil {
				s.observeHotstuffProgress(&hotstuff.HotstuffMessage{
					Code: hotstuff.MsgPrepare, Number: result.Key.ViewNumber, ViewId: result.Key.ViewID, Id: result.Key.LeaderID,
				})
			} else if err != hotstuff.ErrOldState {
				log.Warn("FHS proposal validation completion rejected",
					"view", result.Key.ViewNumber, "viewID", result.Key.ViewID,
					"proposalID", result.Key.ProposalID, "err", err)
			}
			continue
		case result := <-s.highQCValidationResults:
			recovering := s.hasDeferredFHSRecovery()
			if atomic.LoadInt32(&s.runningState) != 1 {
				s.finishHighQCValidation(result.Key)
				continue
			}
			err := s.protocolMng.HandleFHSHighQCValidationResult(result)
			s.finishHighQCValidation(result.Key)
			s.cancelInactiveProposalValidations(s.GetCurrentView().ViewNumber + 1)
			if err != nil && err != hotstuff.ErrOldState && err != hotstuff.ErrProposalValidationPending && err != hotstuff.ErrInsufficientQC {
				log.Warn("FHS HighQC validation completion rejected",
					"targetView", result.Key.TargetView, "qcID", result.Key.QCID, "err", err)
			}
			if recovering {
				if s.hasDeferredFHSRecovery() {
					s.retryDeferredFHSRecovery()
				} else {
					s.resumeAfterDeferredFHSRecovery()
				}
			}
			continue
		case <-s.fhsRecoveryWake:
			s.attemptDeferredFHSRecovery()
			continue
		case data = <-s.hotstuffMsgQ.next:
		case now := <-poolTicker.C:
			if atomic.LoadInt32(&s.runningState) == 1 && !s.hasDeferredFHSRecovery() {
				s.handleHotstuffPoolMaintenance(now)
			}
			continue
		case <-timerTicker.C:
			if atomic.LoadInt32(&s.runningState) == 1 && !s.hasDeferredFHSRecovery() {
				if err := s.protocolMng.HandleMessage(&hotstuff.HotstuffMessage{Code: hotstuff.MsgTimer, Number: s.currentHotstuffBaseNumber()}); err != nil {
					log.Warn("HotStuff recovery retry failed", "err", err)
				}
			}
			continue
		}
		msg := data
		if msg == nil || msg.hMsg == nil {
			log.Warn("handleHotStuffMsg received nil message")
			continue
		}
		msgCode := msg.hMsg.Code
		if msgCode == hotstuff.MsgTryPropose {
			atomic.StoreInt32(&s.tryProposeQueued, 0)
		}
		if atomic.LoadInt32(&s.runningState) != 1 {
			continue
		}
		if s.hasDeferredFHSRecovery() {
			continue
		}
		if err := s.validateHotstuffTransportSender(msg.sid, msg.hMsg); err != nil {
			log.Warn("drop hotstuff message after transport revalidation", "from", msg.hMsg.Id, "code", hotstuff.ReadableMsgType(msgCode), "err", err)
			continue
		}
		log.Debug("handleHotStuffMsg", "id", msg.hMsg.Id, "code", hotstuff.ReadableMsgType(msgCode), "ViewId", msg.hMsg.ViewId)

		var curN uint64
		if msgCode == hotstuff.MsgTryPropose || msgCode == hotstuff.MsgStartNewView {
			curN = s.currentHotstuffBaseNumber()
			if msg.lastN < curN {
				log.Debug("handleHotStuffMsg", "code", hotstuff.ReadableMsgType(msgCode), "lastN", msg.lastN, "curN", curN)
				continue
			}
		} else if msgCode == hotstuff.MsgPrepare && msg.sid != nil {
			curBlock := s.kbc.CurrentBlock()
			keyNumber := curBlock.NumberU64()
			keyHash := curBlock.Hash()
			msgAddress := msg.sid.Address.String()
			if bftview.LoadMember(keyNumber, keyHash, true) == nil && msgAddress != s.netService.serverAddress {
				log.Debug("request committee", "keynumber", keyNumber, "send to address", msgAddress)
				s.netService.SendRawData(msgAddress, &networkMsg{Cmsg: &committeeInfo{Committee: nil, KeyHash: keyHash, KeyNumber: keyNumber}})
			}
		}

		err := s.protocolMng.HandleMessage(msg.hMsg)
		// Cleanup is deliberately based on the canonical view after full protocol
		// verification. A transport-authenticated peer's raw Number is not proof
		// that the view advanced and must never cancel a valid proposal worker.
		s.cancelInactiveProposalValidations(s.GetCurrentView().ViewNumber + 1)
		if err == nil || (err == hotstuff.ErrInsufficientQC && msgCode != hotstuff.MsgTimeout) {
			s.observeHotstuffProgress(msg.hMsg)
		}
		if err != nil && err != hotstuff.ErrInsufficientQC && err != hotstuff.ErrUnhandledMsg && err != hotstuff.ErrOldState && err != hotstuff.ErrProposalValidationPending {
			log.Warn("HotStuff message rejected",
				"from", msg.hMsg.Id,
				"code", hotstuff.ReadableMsgType(msgCode),
				"number", msg.hMsg.Number,
				"viewID", msg.hMsg.ViewId,
				"err", err)
		}
		if err != nil && msgCode == hotstuff.MsgStartNewView {
			go func(curN uint64) {
				time.Sleep(failedProposalRetry)
				s.sendNewViewMsg(curN)
			}(curN)
		}
	}
}

func (s *Service) procBlockDone(block *types.Block) {
	s.clearProposalNoWork()
	if s.fairHotstuffEnabled() {
		if err := s.reconcileFHSCertifiedFrontier(block); err != nil {
			log.Error("stop Fair HotStuff after certified frontier reconciliation failure",
				"number", block.NumberU64(), "hash", block.Hash(), "err", err)
			s.setRunState(0)
			if s.pacetMakerTimer != nil {
				s.pacetMakerTimer.stop()
			}
			return
		}
	}
	var keyblock *types.KeyBlock
	beKeyBlock := false
	if block.BlockType() == types.Key_Block {
		keyblock = types.DecodeToKeyBlock(block.KeyInfo())
	}

	if keyblock != nil {
		beKeyBlock = true
		log.Info("@KeyBlockDone", "number", keyblock.NumberU64(), "T_number", keyblock.T_Number())
		s.updateCommittee(keyblock)
		s.saveCommittee(keyblock)
		if s.fairHotstuffEnabled() {
			nextCommittee := bftview.LoadMember(keyblock.NumberU64(), keyblock.Hash(), true)
			if nextCommittee == nil || nextCommittee.RlpHash() != keyblock.CommitteeHash() {
				log.Error("stop Fair HotStuff after missing next committee", "number", keyblock.NumberU64(), "hash", keyblock.Hash())
				s.setRunState(0)
				s.pacetMakerTimer.stop()
				return
			}
			peers, err := s.fhsPeerAuthorizationWithCertifiedCarriers(nextCommittee)
			if err != nil {
				log.Error("stop Fair HotStuff after invalid committee authorization update", "err", err)
				s.setRunState(0)
				s.pacetMakerTimer.stop()
				return
			}
			// A non-validator can import key blocks while its Fair HotStuff
			// service is intentionally stopped. Keep its committee/view state
			// current, but do not update an unconfigured consensus transport.
			if s.isRunning() {
				if err := s.netService.server.UpdatePeerAuthorization(peers); err != nil {
					log.Error("stop Fair HotStuff after peer authorization update failure", "err", err)
					s.setRunState(0)
					s.pacetMakerTimer.stop()
					return
				}
				s.netService.setAuthenticatedPeerKeys(peers)
			}
			s.muCurrentView.Lock()
			s.currentView.KeyNumber = keyblock.NumberU64()
			s.currentView.KeyHash = keyblock.Hash()
			s.currentView.CommitteeHash = keyblock.CommitteeHash()
			leaderIndex, leaderErr := fairHotstuffLeaderIndex(
				s.chainConfig.FairHotstuffSeed,
				s.ChainID(),
				s.currentView.ViewNumber+1,
				s.currentView.CommitteeHash,
				len(nextCommittee.List),
			)
			if leaderErr == nil {
				s.currentView.LeaderIndex = leaderIndex
			}
			s.muCurrentView.Unlock()
			if leaderErr != nil {
				log.Error("stop Fair HotStuff after next-committee leader election failure", "err", leaderErr)
				s.setRunState(0)
				s.pacetMakerTimer.stop()
				return
			}
		} else {
			s.updateCurrentView(block, keyblock, true)
		}
		s.muCurrentView.Lock()
		s.resetFixedModeKeyblockViewLocked()
		s.muCurrentView.Unlock()
		if s.keyService != nil && s.keyService.fixedLeaderModeEnabled() {
			s.keyService.setActiveLeader(0)
		}
		s.keyService.clearCandidate(keyblock)
	} else {
		log.Info("@TxBlockDone", "number", block.NumberU64(), "keyhash", block.KeyHash())
		s.updateCommittee(nil)
		if !s.fairHotstuffEnabled() {
			s.updateCurrentView(block, keyblock, false)
		}
		keyblock = s.kbc.CurrentBlock()
		//s.txPool.RemoveBatch(block.Transactions())
	}

	s.pacetMakerTimer.procBlockDone(block, keyblock, beKeyBlock)
	s.netService.procBlockDone(block.NumberU64(), keyblock.NumberU64())
	if beKeyBlock && keyblock != nil {
		s.kbc.PostBlock(keyblock)
	}
}

func (s *Service) configureConsensusIdentity(config *common.NodeConfig) error {
	if config == nil || config.Private == "" || config.Public == "" {
		return fmt.Errorf("missing consensus BLS identity")
	}
	secret := new(bls.SecretKey)
	if err := secret.DeserializeHexStr(config.Private); err != nil {
		return fmt.Errorf("invalid consensus BLS private key: %w", err)
	}
	public := secret.GetPublicKey()
	expected := bftview.StrToBlsPubKey(config.Public)
	if public == nil || expected == nil || !public.IsEqual(expected) {
		return fmt.Errorf("consensus BLS private/public key mismatch")
	}
	receiptSecret := new(bls.SecretKey)
	if err := receiptSecret.Deserialize(secret.Serialize()); err != nil {
		return fmt.Errorf("clone TxQUIC receipt BLS private key: %w", err)
	}
	receiptPublic := receiptSecret.GetPublicKey()
	if receiptPublic == nil || !receiptPublic.IsEqual(public) {
		return fmt.Errorf("TxQUIC receipt BLS key clone mismatch")
	}
	proposalBodySecret := new(bls.SecretKey)
	if err := proposalBodySecret.Deserialize(secret.Serialize()); err != nil {
		return fmt.Errorf("clone proposal sidecar BLS private key: %w", err)
	}
	proposalBodyPublic := proposalBodySecret.GetPublicKey()
	if proposalBodyPublic == nil || !proposalBodyPublic.IsEqual(public) {
		return fmt.Errorf("proposal sidecar BLS key clone mismatch")
	}
	s.muConsensusIdentity.Lock()
	s.consensusPublic = public
	s.proposalBodySecret = proposalBodySecret
	s.txQUICReceiptSecret = receiptSecret
	s.txQUICReceiptPublic = receiptPublic
	s.muConsensusIdentity.Unlock()
	s.protocolMng.UpdateKeyPair(secret)
	return nil
}

// call by miner.start
func (s *Service) start(config *common.NodeConfig) error {
	s.muLifecycle.Lock()
	lifecycleLocked := true
	defer func() {
		if lifecycleLocked {
			s.muLifecycle.Unlock()
		}
	}()
	if !s.isRunning() {
		generation := s.advanceLifecycleGenerationLocked()
		// MinerStop/MinerStart reuses this Service. Process-local replay suppression
		// must never survive that restart boundary; the durable outbox is authoritative.
		s.clearFHSQCBroadcastMarkers()
		if err := s.configureConsensusIdentity(config); err != nil {
			return err
		}
		bftview.SetServerInfo(s.netService.serverAddress, config.Public)
		if config.Coinbase != "" {
			bftview.SetServerCoinBase(common.HexToAddress(config.Coinbase))
		}
		if bftview.IamMember() >= 0 {
			s.updateCommittee(nil)
		}
		s.updateCurrentView(nil, nil, false)
		if err := s.loadFHSWAL(); err != nil {
			return fmt.Errorf("restore Fair HotStuff safety state: %w", err)
		}
		var deferredRecovery *fhsDeferredRecovery
		if s.fairHotstuffEnabled() && s.fhsStore != nil {
			deferredRecovery = s.fhsStore.deferredRecoverySnapshot()
		}
		if err := s.pruneFHSPersistenceAtCurrentHead(); err != nil {
			// GC is maintenance, not safety state. A corrupt stale record must not
			// prevent the validated WAL from bringing consensus back online.
			log.Warn("Failed to prune durable FHS recovery cache at startup", "err", err)
		}
		if s.fairHotstuffEnabled() {
			// WAL replay can complete a certified key-block parent and therefore
			// change the active committee. Determine the local role and configure
			// peer authentication only after that recovery is complete.
			isCommitteeMember := bftview.IamMember() >= 0
			if !isCommitteeMember {
				if deferredRecovery != nil {
					log.Warn("Fair HotStuff content recovery remains deferred for non-committee miner",
						"view", deferredRecovery.HighestQC.Number,
						"blockHash", deferredRecovery.HighestBlockHash)
				}
				log.Info("Fair HotStuff service remains stopped for non-committee miner",
					"address", s.netService.serverAddress,
					"coinbase", config.Coinbase)
				return nil
			}
			s.updateCommittee(nil)
			peers, err := s.fhsPeerAuthorizationWithCertifiedCarriers(bftview.GetCurrentMember())
			if err != nil {
				return err
			}
			if err := s.addDeferredFHSRecoveryPeers(peers, deferredRecovery); err != nil {
				return err
			}
			if err := s.netService.server.ConfigurePeerAuthentication(s.ChainID(), s.netService.serverAddress, config.Private, config.Public, peers); err != nil {
				return fmt.Errorf("configure authenticated QUIC transport: %w", err)
			}
			s.netService.setAuthenticatedPeerKeys(peers)
		}
		s.setRunState(1)
		s.netService.StartStop(true)
		if deferredRecovery != nil {
			_ = s.pacetMakerTimer.stop()
			s.wakeDeferredFHSRecovery()
			return nil
		}
		if bftview.IamMember() >= 0 {
			s.pacetMakerTimer.start()
			if s.fairHotstuffEnabled() {
				current := s.currentHotstuffBaseNumber()
				pendingTimeout := s.hasPendingFHSTimeoutVote()
				s.muLifecycle.Unlock()
				lifecycleLocked = false
				s.resumeFHSConsensusMessagingForGeneration(generation, current, pendingTimeout)
			} else {
				s.sendNewViewMsgAfterReplay(s.currentHotstuffBaseNumber())
			}
		}
	}
	return nil
}

func (s *Service) stop() {
	s.muLifecycle.Lock()
	defer s.muLifecycle.Unlock()
	s.advanceLifecycleGenerationLocked()
	if !s.isRunning() {
		s.clearFHSQCBroadcastMarkers()
		return
	}
	s.setRunState(0)
	s.clearFHSQCBroadcastMarkers()
	s.netService.StartStop(false)
	s.pacetMakerTimer.stop()
}

func (s *Service) isRunning() bool {
	return atomic.LoadInt32(&s.runningState) == 1
}

func (s *Service) setRunState(state int32) {
	s.muProposalBuild.Lock()
	changed := atomic.SwapInt32(&s.runningState, state) != state
	if changed {
		atomic.AddUint64(&s.proposalValidationGeneration, 1)
		if state != 1 {
			s.cancelAllProposalBuildsLocked()
		}
	}
	s.muProposalBuild.Unlock()
	if changed {
		s.clearProposalNoWork()
	}
	if changed && state != 1 {
		s.cancelAllProposalValidations()
		if s.protocolMng != nil {
			s.protocolMng.ScheduleFHSEpochReset()
		}
	}
}
