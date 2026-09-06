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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
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
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/rnet/network"
)

const failedProposalRetry = 20 * time.Millisecond
const fastBlockInterval = 70 * time.Millisecond
const slowBlockInterval = 1 * time.Second
const slowFallbackMinPending = 1

// Adaptive slow-block cadence.
// Heavy/deploy/data/dex transactions live in the slow lane.
// When slow pending grows, slow blocks must be emitted faster to drain backlog.
const slowIntervalDrainPendingThreshold = 512
const slowIntervalStrongPendingThreshold = 2048
const slowIntervalEmergencyPendingThreshold = 8192

const slowBlockDrainInterval = 250 * time.Millisecond
const slowBlockStrongDrainInterval = 100 * time.Millisecond
const slowBlockEmergencyDrainInterval = 70 * time.Millisecond

// Phase 7A: lane pressure scheduler.
// If slow lane backlog is much larger than fast lane, keep draining slow lane.
// This avoids heavy/data/deploy transactions sitting behind fast native/small txs.
const slowPressureRatio = 2
const slowPressureMinPending = 512
const slowEmergencyForcePending = 8192

const startNewViewDedupWindow = 2 * time.Second

// A leader keeps its durable QC dissemination outbox until a higher QC makes
// it obsolete. Suppress only the immediate same-process replay caused by the
// leader consuming its own just-sent QC. The marker is intentionally bounded
// and memory-only: ordinary delivery recovery resumes after the window, while
// a restart can replay the durable outbox immediately.
const fhsQCBroadcastReplaySuppressionWindow = 5 * time.Second
const fixedModeKeyblockWakeupInterval = 2 * time.Second
const fixedModeKeyblockWatchdogInterval = 250 * time.Millisecond
const fixedModeKeyblockViewRoundDuration = 2 * params.CollectVoteInfoTimeout

const proposalBodyCacheTTL = 2 * time.Minute
const proposalBodyWaitBaseTimeout = 2 * time.Second
const proposalBodyWaitMaxTimeout = 30 * time.Second
const proposalBodyWaitBytesPerSecond = 2 * 1024 * 1024
const proposalBodyRequestAfter = 250 * time.Millisecond
const proposalBodyRequestInterval = 250 * time.Millisecond
const proposalBodyControlMaxBytes = 512 * 1024
const proposalBodySidecarMaxBytes = int(params.MaxBlockSize)
const proposalRepairMaxHashes = 1024
const proposalRepairResponseReserve = 64 * 1024

// Native proposals may contain hundreds of thousands of transactions. Keep
// each authenticated repair message bounded, but pipeline a bounded number of
// disjoint windows per request interval instead of serialising all windows.
const proposalRepairNativeRequestBurst = 16

// Leave a bounded response/assembly window after the last distinct repair
// batch is scheduled; the batch schedule itself is accounted for separately.
const proposalRepairNetworkMargin = 2 * time.Second
const proposalBodyCacheMaxEntries = 64
const proposalBodyCacheMaxBytes = 8 * proposalBodySidecarMaxBytes
const proposalBodyAuthDomain = "cypher-fhs-proposal-data"

var errProposalAssemblySuperseded = errors.New("proposal assembly superseded")

// Two workers are deliberate: the active view can start while one superseded
// execution unwinds from the non-interruptible EVM. The latest-wins queue below
// retains only the newest waiting view, so repeated view changes cannot drop
// the current Prepare or create unbounded validation CPU/memory pressure.
const proposalValidationWorkers = 2
const proposalValidationQueueCapacity = 1

// Proposal construction uses a separate scheduler from validator execution.
// A superseded EVM run is not immediately interruptible, so two workers let the
// newest view start while one stale build unwinds. Only one latest waiting job
// is retained and publication is independently serialized on the HotStuff loop.
const proposalBuildWorkers = 2
const proposalBuildQueueCapacity = 1
const proposalManifestDispatchCapacity = 8
const proposalManifestDispatchWorkers = 4
const proposalFailedTxCleanupCapacity = 8
const fhsDeferredRecoveryRetryDelay = time.Second

const (
	proposalBodyMsgManifest uint32 = iota + 1
	proposalBodyMsgRepairRequest
	proposalBodyMsgRepairData
)

// proposalBodyCacheTTLForConfig keeps uncertified native proposal data through
// at least two complete pacemaker intervals. A proposal body can still be the
// only repair source while its current view validates, and the native deadline
// includes size-derived body transfer, repair and execution leases. Legacy
// networks retain their historical two-minute cache lifetime.
func proposalBodyCacheTTLForConfig(config *params.ChainConfig) time.Duration {
	ttl := proposalBodyCacheTTL
	if config == nil || !config.NativeParallelEnabled() {
		return ttl
	}
	paceMaker := paceMakerTimeoutForConfig(config)
	minimum := addDurationSaturating(paceMaker, paceMaker)
	if minimum > ttl {
		return minimum
	}
	return ttl
}

type committeeInfo struct {
	Committee *bftview.Committee
	KeyHash   common.Hash
	KeyNumber uint64
}

type bestCandidateInfo struct {
	Node      *common.Cnode
	KeyHash   common.Hash
	KeyNumber uint64
}

// FHSRoute is the authoritative transaction-ingress route for the next Fair
// HotStuff proposal view. ProposalView is the exact view used by the FHS leader
// election PRF; LeaderIndex is therefore never inferred from committee order.
//
// The route is intentionally expressed in rnet committee coordinates. The eth
// TxQUIC layer owns the rnet->TxQUIC port mapping and route caching.
type FHSRoute struct {
	Enabled       bool            `json:"enabled"`
	CurrentView   uint64          `json:"currentView"`
	ProposalView  uint64          `json:"proposalView"`
	TxNumber      uint64          `json:"txNumber"`
	TxHash        common.Hash     `json:"txHash"`
	KeyNumber     uint64          `json:"keyNumber"`
	KeyHash       common.Hash     `json:"keyHash"`
	CommitteeHash common.Hash     `json:"committeeHash"`
	LeaderIndex   uint            `json:"leaderIndex"`
	LeaderID      string          `json:"leaderId"`
	Leader        *common.Cnode   `json:"leader"`
	Committee     []*common.Cnode `json:"committee"`
}

type proposalBodyMsg struct {
	Type uint32

	ProposalID common.Hash
	BodyHash   common.Hash
	BodySize   uint64
	Number     uint64
	ViewNumber uint64
	ViewID     common.Hash
	LeaderID   string
	From       string
	// ProposalKeyHash identifies the committee generation committed by the
	// proposal itself; it can differ from SenderKeyHash while a lagging node
	// requests data across a key-block transition.
	ProposalKeyHash common.Hash
	// SenderKeyHash binds AuthSig to the exact committee generation that owns
	// From. Historical HighQC repair must not reinterpret a valid old/new member
	// key through whichever committee happens to be current locally.
	SenderKeyHash common.Hash

	EncodedBlock    []byte
	Manifest        []byte
	MissingTxHashes []common.Hash
	// TransactionBytes contains one canonical Transaction.MarshalBinary value
	// per MissingTxHashes entry. Keeping opaque bytes on the protobuf boundary
	// avoids reflecting over Transaction's intentionally private fields.
	TransactionBytes   [][]byte
	Extra              []byte
	ParentQC           []byte
	KeyActivationProof []byte
	// ManifestAuthSig is the original leader's signature over the immutable
	// manifest and proposal context. Repair donors preserve it while signing
	// their own transport envelope in AuthSig.
	ManifestAuthSig   []byte
	AuthSig           []byte
	CreatedAtUnixNano int64
}

// proposalDataManifest is the compact data-availability description sent for
// a proposal. Transaction bytes are deliberately absent: TxQUIC/P2P has
// already placed them in committee TxPools, and this manifest fixes their
// exact block order. A validator reconstructs the ordinary block encoding and
// still verifies the signed BodyHash and BodySize before executing it.
type proposalDataManifest struct {
	Header            *types.Header
	TransactionHashes []common.Hash
	// BlobSidecars are deep-copied and ordered one-for-one with BlobTxs in
	// TransactionHashes. They are part of the authenticated manifest and the
	// canonical proposal body commitment; ordinary transaction repair therefore
	// never has to fetch unauthenticated blob bytes from local node state.
	BlobSidecars             []*types.BlobTxSidecar
	Uncles                   []*types.Header
	CommonTxAdmissionBatches []*types.CommonTxAdmissionBatch
	CommonTxAdmissionRefs    []types.CommonTxAdmissionRef
	CommonTxRewards          []*types.CommonTxReward
}

// proposalAssemblyState is the verified, node-local index for one proposal
// manifest. It is never encoded on the wire. The manifest is decoded once,
// every hash has one deterministic position, and each repaired transaction is
// decoded once before being installed at that position. This turns repair from
// repeated O(manifest+repairs) work into O(repair chunk), while the final body
// commitment is still checked in full before publication.
//
// All fields are protected by Service.muProposalBody. Transaction pointers are
// immutable after installation, so a complete pointer slice may be copied and
// encoded after releasing the cache lock.
type proposalAssemblyState struct {
	manifest     *proposalDataManifest
	positions    map[common.Hash]int
	transactions types.Transactions
	missingCount int
	revision     uint64
	resolved     []common.Hash
	assembling   bool
	assemblyErr  error
	cacheWeight  int
}

type proposalAssemblyBuild struct {
	done    chan struct{}
	ctx     context.Context
	cancel  context.CancelFunc
	waiters int
	err     error
}

type fhsCertifiedProposal struct {
	ref      *types.HotstuffProposalRef
	verified *core.VerifiedProposal
	qc       *hotstuff.SignedState
	// Keep only authenticated metadata here. The encoded body and donor index
	// are evictable; verified.Block remains the source for reconstructing them
	// even if the asynchronous content writer has not reached disk yet.
	envelope       *proposalBodyMsg
	originalHeader *types.Header
}

type cachedCommitteeInfo struct {
	keyHash   common.Hash
	keyNumber uint64
	committee *bftview.Committee
	node      *common.Cnode
}

type committeeMsg struct {
	sid   *network.ServerIdentity
	cinfo *committeeInfo
	best  *bestCandidateInfo
}

type hotstuffMsg struct {
	sid   *network.ServerIdentity
	lastN uint64
	hMsg  *hotstuff.HotstuffMessage
}

type proposalValidationOutput struct {
	ref                  *types.HotstuffProposalRef
	verified             *core.VerifiedProposal
	extra                []byte
	parentQC             *hotstuff.SignedState
	serviceGeneration    uint64
	validationGeneration uint64
}

type fhsValidationPublicationOwner int32

const (
	fhsValidationPublicationNone fhsValidationPublicationOwner = iota
	fhsValidationPublicationProposal
	fhsValidationPublicationHighQC
	fhsValidationPublicationSyncTransition
)

type proposalValidationJob struct {
	request              *hotstuff.FHSProposalValidationRequest
	highQCRequest        *hotstuff.FHSHighQCValidationRequest
	parentVerified       *core.VerifiedProposal
	ctx                  context.Context
	cancel               context.CancelFunc
	serviceGeneration    uint64
	validationGeneration uint64
}

type proposalValidationControl struct {
	key        hotstuff.FHSProposalValidationKey
	keyHash    common.Hash
	generation uint64
	cancel     context.CancelFunc
}

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

type proposalBuildOutput struct {
	key                    hotstuff.FHSProposalBuildKey
	proposalRef            []byte
	extra                  []byte
	body                   *proposalBodyMsg
	manifest               *proposalBodyMsg
	destinations           []string
	txCandidate            *txProposalCandidate
	keyCandidate           *keyProposalCandidate
	keyBlock               *types.KeyBlock
	committee              *bftview.Committee
	blockType              uint8
	fixedMode              bool
	keyProposalAttempt     bool
	serviceGeneration      uint64
	constructionGeneration uint64
	publicationLocksHeld   bool
	workStamp              proposalWorkStamp
	workStampValid         bool
}

type stagedHotstuffProposal struct {
	proposalRef  []byte
	body         *proposalBodyMsg
	manifest     *proposalBodyMsg
	destinations []string
}

type proposalBuildJob struct {
	request                *hotstuff.FHSProposalBuildRequest
	ctx                    context.Context
	cancel                 context.CancelFunc
	serviceGeneration      uint64
	constructionGeneration uint64
}

type proposalBuildControl struct {
	key        hotstuff.FHSProposalBuildKey
	generation uint64
	cancel     context.CancelFunc
}

type proposalManifestDispatch struct {
	body              *proposalBodyMsg
	destinations      []string
	serviceGeneration uint64
}

type proposalFailedTxCleanup struct {
	txs               types.Transactions
	serviceGeneration uint64
}

type proposalBodyAuthority struct {
	key     hotstuff.FHSProposalValidationKey
	keyHash common.Hash
}

type highQCValidationControl struct {
	key         hotstuff.FHSHighQCValidationKey
	qcNumber    uint64
	generation  uint64
	resultReady bool
	applied     bool
	cancel      context.CancelFunc
	authorized  map[common.Hash]proposalBodyAuthority
}

type networkMsg struct {
	MsgFlag uint32
	Hmsg    *hotstuff.HotstuffMessage
	Cmsg    *committeeInfo
	Bmsg    *bestCandidateInfo
	Pmsg    *proposalBodyMsg

	queueSince    time.Time
	queueAttempts uint32
}

func (msg *networkMsg) NetworkClass() uint8 {
	if msg == nil {
		return network.NetClassBulkGossip
	}
	if msg.Hmsg != nil {
		return network.NetClassHotstuffControl
	}
	if msg.Pmsg != nil {
		switch msg.Pmsg.Type {
		case proposalBodyMsgRepairRequest:
			return network.NetClassProposalBodyControl
		case proposalBodyMsgManifest, proposalBodyMsgRepairData:
			payloadBytes := proposalBodyMsgPayloadBytes(msg.Pmsg)
			if payloadBytes <= proposalBodyControlMaxBytes {
				return network.NetClassProposalBodyControl
			}
			// The dedicated proposal-body QUIC class intentionally retains its
			// legacy 9 MiB packet cap. Genesis-native manifests can be larger, so
			// route only those bounded messages through the 257 MiB large-data
			// class. Both classes remain bulk-priority in the peer scheduler.
			if payloadBytes > proposalBodySidecarMaxBytes {
				return network.NetClassBulkGossip
			}
			return network.NetClassProposalBodyBulk
		default:
			return network.NetClassProposalBodyControl
		}
	}
	if msg.Cmsg != nil || msg.Bmsg != nil {
		return network.NetClassCommitteeControl
	}
	return network.NetClassBulkGossip
}

func (msg *networkMsg) GetCommittee() *bftview.Committee {
	var mb *bftview.Committee
	if msg.Cmsg != nil {
		mb = bftview.LoadMember(msg.Cmsg.KeyNumber, msg.Cmsg.KeyHash, true)
	} else if msg.Bmsg != nil {
		mb = bftview.LoadMember(msg.Bmsg.KeyNumber, msg.Bmsg.KeyHash, true)
	} else if msg.Hmsg != nil {
		mb = bftview.GetCurrentMember()
	} else if msg.Pmsg != nil {
		mb = bftview.GetCurrentMember()
	}
	return mb
}

// Service work for protcol
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
	lastProposeTime              time.Time
	lastSlowBlockTime            time.Time
	lastFastBlockTime            time.Time
	serviceStartTime             time.Time
	lastCadenceWakeup            time.Time
	lastFixedKeyNewViewWakeup    time.Time
	fixedKeyViewStartedAt        time.Time
	fixedKeyViewTxNumber         uint64
	fixedKeyViewKeyNumber        uint64
	fixedKeyViewTxHash           common.Hash
	fixedKeyViewKeyHash          common.Hash
	fixedKeyViewLeader           uint
	fixedKeyFallbackRound        uint
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
	consensusSecret                *bls.SecretKey
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
	activeProposalValidations map[common.Hash]*proposalValidationControl
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
	s.serviceStartTime = time.Now()
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
	s.activeProposalValidations = make(map[common.Hash]*proposalValidationControl)
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

// OnNewView --------------------------------------------------------------------------
func (s *Service) OnNewView(data []byte, extraes [][]byte) error { //buf is snapshot, //verify repla' block before newview
	view := bftview.DecodeToView(data)
	if view == nil {
		return fmt.Errorf("invalid new-view state")
	}
	log.Info("OnNewView..", "txNumber", view.TxNumber, "keyNumber", view.KeyNumber)

	s.muCurrentView.Lock()
	s.replicaView = view
	if view.EqualNoIndex(&s.currentView) {
		s.currentView.LeaderIndex = view.LeaderIndex
	}
	s.muCurrentView.Unlock()

	var bestCandidates []*types.Candidate
	for _, extraD := range extraes {
		if extraD == nil {
			continue
		}
		cand := types.DecodeToCandidate(extraD)
		if cand == nil {
			continue
		}
		bestCandidates = append(bestCandidates, cand)
	}
	s.keyService.setBestCandidate(bestCandidates)
	s.clearProposalNoWork()
	return nil
}

func (s *Service) CurrentN() uint64 {
	curView := s.GetCurrentView()
	if s.fairHotstuffEnabled() {
		return curView.ViewNumber + 1
	}
	return curView.TxNumber + 1
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

func (s *Service) loadViewCommittee(view *bftview.View, needIP bool) (*bftview.Committee, error) {
	if view == nil || view.KeyHash == (common.Hash{}) {
		return nil, fmt.Errorf("view has no committee key block")
	}
	keyblock := s.kbc.GetBlock(view.KeyHash, view.KeyNumber)
	if keyblock == nil {
		return nil, fmt.Errorf("unknown committee key block number=%d hash=%s", view.KeyNumber, view.KeyHash)
	}
	if keyblock.CommitteeHash() != view.CommitteeHash {
		return nil, fmt.Errorf("view committee hash mismatch: view=%s keyblock=%s", view.CommitteeHash, keyblock.CommitteeHash())
	}
	committee := bftview.LoadMember(view.KeyNumber, view.KeyHash, needIP)
	if committee == nil {
		return nil, fmt.Errorf("committee unavailable for key block number=%d hash=%s", view.KeyNumber, view.KeyHash)
	}
	if committee.RlpHash() != keyblock.CommitteeHash() {
		return nil, fmt.Errorf("stored committee hash mismatch for key block %s", view.KeyHash)
	}
	return committee, nil
}

// resolveExactFHSCommittee resolves a committee only from an exact key-block
// commitment. The normal path uses the key chain. During an epoch handoff a
// lagging replica may have installed the certified key carrier while the QC
// for its direct child was dropped by transport backpressure. In that gap the
// first new-epoch manifest carries the missing child QC. Once that old-epoch
// QC is verified against the locally certified carrier, it is a complete
// two-chain activation proof for authenticating the new committee.
//
// The generic path below accepts either an installed child certificate or an
// activation proof retained in an already authenticated proposal manifest.
// The initial manifest is handled by resolveExactFHSCommitteeWithActivation.
// Merely receiving/validating a carrier, or finding an arbitrary committee DB
// entry, remains insufficient.
func (s *Service) resolveExactFHSCommittee(keyHash common.Hash, needIP bool) (*types.KeyBlock, *bftview.Committee, bool, error) {
	return s.resolveExactFHSCommitteeWithActivation(keyHash, needIP, nil)
}

func (s *Service) resolveExactFHSCommitteeWithActivation(keyHash common.Hash, needIP bool, activationQC []byte, finalityProof ...[]byte) (*types.KeyBlock, *bftview.Committee, bool, error) {
	if s == nil || s.kbc == nil || keyHash == (common.Hash{}) {
		return nil, nil, false, fmt.Errorf("missing FHS committee generation")
	}
	if keyBlock := s.kbc.GetBlockByHash(keyHash); keyBlock != nil {
		canonical := s.kbc.GetBlockByNumber(keyBlock.NumberU64())
		if canonical != nil && canonical.Hash() == keyHash {
			committee := bftview.LoadMember(keyBlock.NumberU64(), keyHash, needIP)
			if committee == nil || len(committee.List) == 0 {
				return nil, nil, false, fmt.Errorf("committee unavailable for key block %s", keyHash)
			}
			if committee.RlpHash() != keyBlock.CommitteeHash() {
				return nil, nil, false, fmt.Errorf("committee commitment mismatch for key block %s", keyHash)
			}
			return keyBlock, committee, false, nil
		}
	}

	keyBlock, err := s.certifiedUncommittedFHSKeyBlock(keyHash, activationQC, finalityProof...)
	if err != nil {
		return nil, nil, false, err
	}
	committee := bftview.LoadMember(keyBlock.NumberU64(), keyHash, needIP)
	if committee == nil || len(committee.List) == 0 {
		return nil, nil, false, fmt.Errorf("certified uncommitted committee unavailable for key block %s", keyHash)
	}
	if committee.RlpHash() != keyBlock.CommitteeHash() {
		return nil, nil, false, fmt.Errorf("certified uncommitted committee commitment mismatch for key block %s", keyHash)
	}
	return keyBlock, committee, true, nil
}

type certifiedFHSKeyCarrier struct {
	keyBlock *types.KeyBlock
	ref      *types.HotstuffProposalRef
	qc       *hotstuff.SignedState
}

func (s *Service) certifiedUncommittedFHSKeyBlock(keyHash common.Hash, encodedActivationQC []byte, encodedFinalityProof ...[]byte) (*types.KeyBlock, error) {
	if s == nil || keyHash == (common.Hash{}) {
		return nil, fmt.Errorf("invalid certified FHS key generation")
	}
	s.muProposalBody.RLock()
	var (
		carriers         []*certifiedFHSKeyCarrier
		activationProofs [][]byte
		finalityProofs   [][]byte
	)
	// A block may have certificates in multiple views. Keep each exact QC
	// candidate: the activation proof binds ParentQCID, not just BlockHash.
	for _, record := range s.fhsCertifiedByID {
		if record == nil || record.verified == nil || record.verified.Block == nil || record.verified.Block.BlockType() != types.Key_Block {
			continue
		}
		candidate := types.DecodeToKeyBlock(record.verified.Block.KeyInfo())
		if candidate == nil || candidate.Hash() != keyHash {
			continue
		}
		artifact := &fhsHighQCValidationItem{ref: record.ref, qc: record.qc, verified: record.verified}
		if err := validateStagedFHSCertificateArtifact(artifact); err != nil {
			s.muProposalBody.RUnlock()
			return nil, fmt.Errorf("invalid certified key carrier for %s: %w", keyHash, err)
		}
		if record.verified.Block.KeyHash() != candidate.ParentHash() ||
			record.verified.Block.NumberU64() == 0 || candidate.T_Number() != record.verified.Block.NumberU64()-1 {
			s.muProposalBody.RUnlock()
			return nil, fmt.Errorf("certified key carrier commitment mismatch for %s", keyHash)
		}
		refCopy := *record.ref
		carriers = append(carriers, &certifiedFHSKeyCarrier{
			keyBlock: candidate, ref: &refCopy, qc: hotstuff.CloneSignedState(record.qc),
		})
	}
	if len(carriers) == 0 {
		s.muProposalBody.RUnlock()
		return nil, fmt.Errorf("committee %s is unavailable from the key chain and certified pipeline", keyHash)
	}
	for _, proof := range encodedFinalityProof {
		if len(proof) > 0 {
			finalityProofs = append(finalityProofs, append([]byte(nil), proof...))
		}
	}
	if len(encodedActivationQC) > 0 {
		activationProofs = append(activationProofs, append([]byte(nil), encodedActivationQC...))
	}
	for _, child := range s.fhsCertifiedByID {
		if child == nil || child.ref == nil || child.qc == nil {
			continue
		}
		encoded, err := hotstuff.EncodeSignedState(child.qc)
		if err == nil {
			activationProofs = append(activationProofs, encoded)
		}
	}
	// Only authenticated manifests reach proposalBodies. Retaining the proof
	// bridges manifest -> Prepare ordering without publishing certificates or
	// unverified application state on behalf of the incoming manifest.
	if len(encodedActivationQC) == 0 {
		for _, record := range s.fhsCertifiedByID {
			if record == nil {
				continue
			}
			if body := record.envelope; body != nil && body.ProposalKeyHash == keyHash && len(body.ParentQC) > 0 {
				activationProofs = append(activationProofs, append([]byte(nil), body.ParentQC...))
				if len(body.KeyActivationProof) > 0 {
					finalityProofs = append(finalityProofs, append([]byte(nil), body.KeyActivationProof...))
				}
			}
		}
		for _, body := range s.proposalBodies {
			if body != nil && body.ProposalKeyHash == keyHash && len(body.ParentQC) > 0 {
				activationProofs = append(activationProofs, append([]byte(nil), body.ParentQC...))
				if len(body.KeyActivationProof) > 0 {
					finalityProofs = append(finalityProofs, append([]byte(nil), body.KeyActivationProof...))
				}
			}
		}
	}
	s.muProposalBody.RUnlock()

	for _, carrier := range carriers {
		verifiedCarrierRef, err := s.verifyFHSQCCryptographic(carrier.qc)
		if err != nil || verifiedCarrierRef == nil || verifiedCarrierRef.ProposalID() != carrier.ref.ProposalID() {
			continue
		}
		for _, encoded := range finalityProofs {
			if _, err := s.verifyFHSKeyActivationFinality(carrier, encoded); err == nil {
				return carrier.keyBlock, nil
			}
		}
		for _, encoded := range activationProofs {
			activationQC, err := hotstuff.DecodeSignedState(encoded)
			if err != nil || activationQC == nil {
				continue
			}
			// Check epoch before signature resolution to avoid recursively
			// trying to activate this same unknown signer generation.
			ref, err := types.DecodeHotstuffProposalRef(activationQC.State)
			if err != nil || ref.KeyHash != carrier.keyBlock.ParentHash() {
				continue
			}
			if _, err := s.verifyCertifiedFHSKeyActivation(carrier, activationQC); err == nil {
				return carrier.keyBlock, nil
			}
		}
	}
	return nil, fmt.Errorf("certified key block %s has no verified consecutive-view activation proof", keyHash)
}

func (s *Service) verifyCertifiedFHSKeyActivation(carrier *certifiedFHSKeyCarrier, activationQC *hotstuff.SignedState) (*types.HotstuffProposalRef, error) {
	if carrier == nil || carrier.keyBlock == nil || carrier.ref == nil || carrier.qc == nil || activationQC == nil {
		return nil, fmt.Errorf("incomplete certified key activation proof")
	}
	activationRef, err := s.verifyFHSQCCryptographic(activationQC)
	if err != nil {
		return nil, fmt.Errorf("verify certified key activation QC: %w", err)
	}
	carrierQCID, err := hotstuff.SignedStateID(carrier.qc)
	if err != nil {
		return nil, fmt.Errorf("derive certified key carrier QC id: %w", err)
	}
	if activationRef.ParentHash != carrier.ref.BlockHash || activationRef.Number != carrier.ref.Number+1 ||
		activationRef.ViewNumber <= carrier.ref.ViewNumber || activationRef.ViewNumber-carrier.ref.ViewNumber != 1 || activationRef.KeyHash != carrier.keyBlock.ParentHash() ||
		activationRef.ParentQCID != carrierQCID.Hash() {
		return nil, fmt.Errorf("certified key activation QC is not the carrier's direct old-epoch child")
	}
	return activationRef, nil
}

// CurrentState call by hotstuff
func (s *Service) CurrentState() ([]byte, string, uint64) { //recv by onnewview
	curView := s.GetCurrentView()
	leaderID := ""
	mb, committeeErr := s.loadViewCommittee(curView, true)
	committeeSize := 0
	if mb != nil {
		committeeSize = len(mb.List)
	}
	if mb != nil && curView.LeaderIndex < uint(len(mb.List)) && mb.List[curView.LeaderIndex] != nil {
		leader := mb.List[curView.LeaderIndex]
		log.Info("CurrentState.NextLeader", "index", curView.LeaderIndex, "ip", leader.Address)
		leaderID = bftview.GetNodeID(leader.Address, leader.Public)
	} else {
		log.Error("CurrentState.NextLeader: invalid committee or leader index",
			"index", curView.LeaderIndex,
			"committeeSize", committeeSize,
			"err", committeeErr)
		s.Committee_Request(curView.KeyNumber, curView.KeyHash)
	}

	log.Info("CurrentState", "TxNumber", curView.TxNumber, "KeyNumber", curView.KeyNumber, "LeaderIndex", curView.LeaderIndex, "NoDone", curView.NoDone)

	number := curView.TxNumber + 1
	if s.fairHotstuffEnabled() {
		number = curView.ViewNumber + 1
	}
	return curView.EncodeConsensusToBytes(), leaderID, number
}

// FHSProposalReadinessSnapshot returns only immutable/copy-on-read consensus
// identity for the local retry gate. Unlike CurrentState it never loads a
// committee, logs, requests committee data, or performs network work.
func (s *Service) FHSProposalReadinessSnapshot() ([]byte, uint64, *hotstuff.SignedState) {
	s.muCurrentView.Lock()
	current := s.currentView
	s.muCurrentView.Unlock()
	return current.EncodeConsensusToBytes(), current.ViewNumber + 1, s.SelectedFHSProposalParent()
}

var _ hotstuff.FHSProposalReadinessApplication = (*Service)(nil)

// GetExtra call by hotstuff
func (s *Service) GetExtra() []byte {
	best := s.keyService.getBestCandidate(true)
	if best == nil {
		return nil
	}
	return best.EncodeToBytes()
}

// GetPublicKey resolves the exact historical signer order for a key block.
func (s *Service) GetPublicKey(keyHash common.Hash) ([]*bls.PublicKey, error) {
	if keyHash == (common.Hash{}) {
		return nil, fmt.Errorf("empty committee key block hash")
	}
	_, committee, _, err := s.resolveExactFHSCommittee(keyHash, false)
	if err != nil {
		return nil, err
	}
	publicKeys := committee.ToBlsPublicKeys(keyHash)
	if len(publicKeys) == 0 || len(publicKeys) != len(committee.List) {
		return nil, fmt.Errorf("invalid committee public keys for key block %s", keyHash)
	}
	return append([]*bls.PublicKey(nil), publicKeys...), nil
}

// FHSLeaderPublicKey resolves the exact historical address-to-BLS-key binding
// used to authenticate a self-contained QC broadcast after volatile views have
// been lost. Looking up by key hash prevents a later committee from
// reinterpreting an older certificate.
func (s *Service) FHSLeaderPublicKey(keyHash common.Hash, leaderID string) (*bls.PublicKey, error) {
	_, resolved, _, err := s.resolveExactFHSCommittee(keyHash, false)
	if err != nil {
		return nil, err
	}
	for _, node := range resolved.List {
		if node != nil && node.Address == leaderID {
			public := bftview.StrToBlsPubKey(node.Public)
			if public == nil {
				return nil, fmt.Errorf("invalid BLS key for historical leader %s", leaderID)
			}
			return public, nil
		}
	}
	return nil, fmt.Errorf("leader %s is not in historical committee %s", leaderID, keyHash)
}

// Self call by hotstuff
func (s *Service) Self() string {
	return s.netService.serverID
}

// CheckView call by hotstuff
func (s *Service) CheckView(data []byte) error {
	_, _, _, err := s.ValidateView(data)
	return err
}

func validateViewAgainstSnapshot(data []byte, current bftview.View, useFHS2Chain bool) ([]byte, uint64, error) {
	view := bftview.DecodeToView(data)
	if view == nil {
		return nil, 0, fmt.Errorf("invalid hotstuff view encoding")
	}

	expectedState := current.EncodeConsensusToBytes()
	expectedNumber := current.TxNumber + 1
	if useFHS2Chain {
		expectedNumber = current.ViewNumber + 1
		if view.ViewNumber < current.ViewNumber {
			return expectedState, expectedNumber, hotstuff.ErrOldState
		}
		if view.ViewNumber > current.ViewNumber {
			return expectedState, expectedNumber, hotstuff.ErrFutureState
		}
	}
	if view.KeyNumber < current.KeyNumber ||
		(view.KeyNumber == current.KeyNumber && view.TxNumber < current.TxNumber) {
		return expectedState, expectedNumber, hotstuff.ErrOldState
	}
	if view.KeyNumber > current.KeyNumber ||
		(view.KeyNumber == current.KeyNumber && view.TxNumber > current.TxNumber) {
		return expectedState, expectedNumber, hotstuff.ErrFutureState
	}
	return expectedState, expectedNumber, nil
}

// ValidateView returns validation and the expected state from one currentView
// snapshot. Reading the blockchain height first and currentView afterwards can
// observe a block between insertion and procBlockDone, incorrectly turning a
// future NewView into a mismatched current view and permanently dropping it.
func (s *Service) ValidateView(data []byte) ([]byte, string, uint64, error) {
	if !s.isRunning() {
		return nil, "", 0, types.ErrNotRunning
	}
	view := bftview.DecodeToView(data)
	if view == nil {
		return nil, "", 0, fmt.Errorf("invalid hotstuff view encoding")
	}

	s.muCurrentView.Lock()
	current := s.currentView
	s.muCurrentView.Unlock()

	log.Debug("ValidateView..",
		"txNumber", view.TxNumber,
		"keyNumber", view.KeyNumber,
		"local key number", current.KeyNumber,
		"tx number", current.TxNumber)

	expectedState, expectedNumber, err := validateViewAgainstSnapshot(data, current, s.fairHotstuffEnabled())
	if err != nil {
		return expectedState, "", expectedNumber, err
	}
	committee, err := s.loadViewCommittee(&current, true)
	if err != nil {
		return expectedState, "", expectedNumber, err
	}
	if current.LeaderIndex >= uint(len(committee.List)) || committee.List[current.LeaderIndex] == nil {
		return expectedState, "", expectedNumber, fmt.Errorf("invalid leader index %d for committee %s", current.LeaderIndex, current.KeyHash)
	}
	leader := committee.List[current.LeaderIndex]
	leaderID := bftview.GetNodeID(leader.Address, leader.Public)
	if leaderID == "" {
		return expectedState, "", expectedNumber, fmt.Errorf("empty leader id for committee %s", current.KeyHash)
	}
	return expectedState, leaderID, expectedNumber, nil
}

func cloneProposalBodyMsg(in *proposalBodyMsg) *proposalBodyMsg {
	if in == nil {
		return nil
	}
	out := *in
	out.EncodedBlock = append([]byte(nil), in.EncodedBlock...)
	out.Manifest = append([]byte(nil), in.Manifest...)
	out.MissingTxHashes = append([]common.Hash(nil), in.MissingTxHashes...)
	out.TransactionBytes = make([][]byte, len(in.TransactionBytes))
	for index := range in.TransactionBytes {
		out.TransactionBytes[index] = append([]byte(nil), in.TransactionBytes[index]...)
	}
	out.Extra = append([]byte(nil), in.Extra...)
	out.ParentQC = append([]byte(nil), in.ParentQC...)
	out.KeyActivationProof = append([]byte(nil), in.KeyActivationProof...)
	out.ManifestAuthSig = append([]byte(nil), in.ManifestAuthSig...)
	out.AuthSig = append([]byte(nil), in.AuthSig...)
	return &out
}

// cloneProposalBodyEnvelope copies authenticated proposal metadata and proof
// fields without first copying any potentially block-sized data payload. The
// caller explicitly attaches the one payload representation it needs.
func cloneProposalBodyEnvelope(in *proposalBodyMsg) *proposalBodyMsg {
	if in == nil {
		return nil
	}
	out := *in
	out.EncodedBlock = nil
	out.Manifest = nil
	out.MissingTxHashes = nil
	out.TransactionBytes = nil
	out.Extra = append([]byte(nil), in.Extra...)
	out.ParentQC = append([]byte(nil), in.ParentQC...)
	out.KeyActivationProof = append([]byte(nil), in.KeyActivationProof...)
	out.ManifestAuthSig = append([]byte(nil), in.ManifestAuthSig...)
	out.AuthSig = append([]byte(nil), in.AuthSig...)
	return &out
}

func (s *Service) proposalBodyWakeLocked() <-chan struct{} {
	if s.proposalBodyWake == nil {
		s.proposalBodyWake = make(chan struct{})
	}
	return s.proposalBodyWake
}

func (s *Service) signalProposalBodyUpdateLocked() {
	if s.proposalBodyWake == nil {
		s.proposalBodyWake = make(chan struct{})
		return
	}
	close(s.proposalBodyWake)
	s.proposalBodyWake = make(chan struct{})
}

func (s *Service) evictProposalBodyLocked(proposalID common.Hash) {
	delete(s.proposalBodies, proposalID)
	delete(s.proposalAssemblies, proposalID)
	if build := s.proposalAssemblyBuilds[proposalID]; build != nil && build.cancel != nil {
		build.cancel()
	}
	if s.fhsCertifiedByID[proposalID] == nil {
		delete(s.verifiedProposalByID, proposalID)
	}
	s.signalProposalBodyUpdateLocked()
}

func (s *Service) deleteProposalBodyLocked(proposalID common.Hash) {
	s.evictProposalBodyLocked(proposalID)
	delete(s.verifiedProposalByID, proposalID)
}

func encodeProposalDataManifest(block *types.Block) ([]byte, error) {
	return encodeProposalDataManifestForConfig(nil, block)
}

func proposalDataManifestForBlock(block *types.Block) (*proposalDataManifest, error) {
	if block == nil {
		return nil, fmt.Errorf("nil proposal block")
	}
	txs := block.Transactions()
	hashes := make([]common.Hash, len(txs))
	for index, tx := range txs {
		if tx == nil {
			return nil, fmt.Errorf("nil proposal transaction %d", index)
		}
		hashes[index] = tx.Hash()
	}
	return &proposalDataManifest{
		Header:                   block.Header(),
		TransactionHashes:        hashes,
		BlobSidecars:             block.BlobSidecars(),
		Uncles:                   block.Uncles(),
		CommonTxAdmissionBatches: block.CommonTxAdmissionBatches(),
		CommonTxAdmissionRefs:    block.CommonTxAdmissionRefs(),
		CommonTxRewards:          block.CommonTxRewards(),
	}, nil
}

func encodeProposalDataManifestForConfig(config *params.ChainConfig, block *types.Block) ([]byte, error) {
	manifest, err := proposalDataManifestForBlock(block)
	if err != nil {
		return nil, err
	}
	encoded, err := rlp.EncodeToBytes(manifest)
	if err != nil {
		return nil, err
	}
	limit := proposalBodyLimitForConfig(config)
	if len(encoded) == 0 || len(encoded) > limit {
		return nil, fmt.Errorf("proposal manifest too large: bytes=%d limit=%d", len(encoded), limit)
	}
	return encoded, nil
}

func decodeProposalDataManifest(encoded []byte) (*proposalDataManifest, error) {
	return decodeProposalDataManifestForConfig(nil, encoded)
}

func decodeProposalDataManifestForConfig(config *params.ChainConfig, encoded []byte) (*proposalDataManifest, error) {
	if len(encoded) == 0 || len(encoded) > proposalBodyLimitForConfig(config) {
		return nil, fmt.Errorf("invalid proposal manifest size: %d", len(encoded))
	}
	var manifest proposalDataManifest
	if err := rlp.DecodeBytes(encoded, &manifest); err != nil {
		return nil, fmt.Errorf("decode proposal manifest: %w", err)
	}
	limits := params.FairHotstuffWorkLimitsForConfig(config)
	if isEVMOnlyProposalMode(config) {
		limits = params.FairHotstuffEVMWorkLimitsForConfig(config)
	}
	if uint64(len(manifest.TransactionHashes)) > limits.Transactions {
		return nil, fmt.Errorf("proposal manifest transaction count %d exceeds limit %d", len(manifest.TransactionHashes), limits.Transactions)
	}
	if uint64(len(manifest.CommonTxAdmissionBatches)) > limits.CommonTxAdmissionBatches {
		return nil, fmt.Errorf("proposal manifest admission batch count %d exceeds limit %d", len(manifest.CommonTxAdmissionBatches), limits.CommonTxAdmissionBatches)
	}
	if uint64(len(manifest.CommonTxAdmissionRefs)) > limits.CommonTxAdmissionRefs {
		return nil, fmt.Errorf("proposal manifest admission reference count %d exceeds limit %d", len(manifest.CommonTxAdmissionRefs), limits.CommonTxAdmissionRefs)
	}
	if uint64(len(manifest.CommonTxRewards)) > limits.CommonTxRewards {
		return nil, fmt.Errorf("proposal manifest reward count %d exceeds limit %d", len(manifest.CommonTxRewards), limits.CommonTxRewards)
	}
	if manifest.Header == nil || manifest.Header.Number == nil || manifest.Header.Number.Sign() <= 0 || manifest.Header.Difficulty == nil {
		return nil, fmt.Errorf("proposal manifest has invalid header")
	}
	if err := validateProposalManifestBlobSidecars(config, &manifest); err != nil {
		return nil, err
	}
	seen := make(map[common.Hash]struct{}, len(manifest.TransactionHashes))
	for index, hash := range manifest.TransactionHashes {
		if hash == (common.Hash{}) {
			return nil, fmt.Errorf("proposal manifest transaction %d has an empty hash", index)
		}
		if _, duplicate := seen[hash]; duplicate {
			return nil, fmt.Errorf("proposal manifest repeats transaction %s", hash)
		}
		seen[hash] = struct{}{}
	}
	for index, uncle := range manifest.Uncles {
		if uncle == nil {
			return nil, fmt.Errorf("proposal manifest uncle %d is nil", index)
		}
	}
	for index, batch := range manifest.CommonTxAdmissionBatches {
		if batch == nil {
			return nil, fmt.Errorf("proposal manifest admission batch %d is nil", index)
		}
	}
	if len(manifest.CommonTxAdmissionRefs) != len(manifest.TransactionHashes) {
		return nil, fmt.Errorf("proposal manifest admission reference count %d does not match transaction count %d", len(manifest.CommonTxAdmissionRefs), len(manifest.TransactionHashes))
	}
	for index, reward := range manifest.CommonTxRewards {
		if reward == nil {
			return nil, fmt.Errorf("proposal manifest reward %d is nil", index)
		}
	}
	return &manifest, nil
}

func validateProposalManifestBlobSidecars(config *params.ChainConfig, manifest *proposalDataManifest) error {
	if manifest == nil || manifest.Header == nil {
		return fmt.Errorf("proposal manifest has no blob-sidecar header context")
	}
	if len(manifest.BlobSidecars) > len(manifest.TransactionHashes) {
		return fmt.Errorf("proposal manifest blob sidecar count %d exceeds transaction count %d", len(manifest.BlobSidecars), len(manifest.TransactionHashes))
	}
	if len(manifest.BlobSidecars) > 0 && config != nil && !config.IsCancun(manifest.Header.Number, manifest.Header.Time) {
		return fmt.Errorf("proposal manifest carries blob sidecars before Cancun")
	}
	maxPerTransaction := params.MaxBlobsPerTransaction(config, manifest.Header.Time)
	if maxPerTransaction == 0 {
		maxPerTransaction = params.BlobTxMaxBlobs
	}
	expectedVersion := types.BlobSidecarVersion0
	if config != nil && config.IsOsaka(manifest.Header.Number, manifest.Header.Time) {
		expectedVersion = types.BlobSidecarVersion1
	}
	maxBlockBlobGas := params.MaxBlobGasPerBlock(nil)
	if config != nil {
		maxBlockBlobGas = params.MaxBlobGasPerBlock(config.ActiveBlobConfig(manifest.Header.Time))
	}
	var totalBlobs uint64
	for index, sidecar := range manifest.BlobSidecars {
		if sidecar == nil {
			return fmt.Errorf("proposal manifest blob sidecar %d is nil", index)
		}
		blobCount := len(sidecar.Blobs)
		if blobCount == 0 {
			return fmt.Errorf("proposal manifest blob sidecar %d has no blobs", index)
		}
		if err := sidecar.ValidateVersion(expectedVersion); err != nil {
			return fmt.Errorf("proposal manifest blob sidecar %d: %w", index, err)
		}
		if maxPerTransaction > 0 && blobCount > maxPerTransaction {
			return fmt.Errorf("proposal manifest blob sidecar %d has %d blobs, limit %d", index, blobCount, maxPerTransaction)
		}
		const eip4844BlobBytes = 4096 * 32
		for blobIndex, blob := range sidecar.Blobs {
			if len(blob) != eip4844BlobBytes {
				return fmt.Errorf("proposal manifest blob sidecar %d blob %d has %d bytes, want %d", index, blobIndex, len(blob), eip4844BlobBytes)
			}
		}
		if uint64(blobCount) > (^uint64(0) - totalBlobs) {
			return fmt.Errorf("proposal manifest blob count overflows")
		}
		totalBlobs += uint64(blobCount)
	}
	if totalBlobs > ^uint64(0)/params.BlobTxBlobGasPerBlob {
		return fmt.Errorf("proposal manifest blob gas overflows")
	}
	blobGasUsed := totalBlobs * params.BlobTxBlobGasPerBlob
	if blobGasUsed != manifest.Header.BlobGasUsed {
		return fmt.Errorf("proposal manifest blob gas mismatch: sidecars=%d header=%d", blobGasUsed, manifest.Header.BlobGasUsed)
	}
	if blobGasUsed > maxBlockBlobGas {
		return fmt.Errorf("proposal manifest blob gas %d exceeds block limit %d", blobGasUsed, maxBlockBlobGas)
	}
	return nil
}

const proposalAssemblyBytesPerTransaction = 112
const proposalAssemblyBytesPerRepairedTransaction = 160

func proposalAssemblyBaseWeight(payloadBytes, transactions int) int {
	return saturatingAddInt(payloadBytes, saturatingMulInt(transactions, proposalAssemblyBytesPerTransaction))
}

func proposalAssemblyTransactionWeight(tx *types.Transaction) int {
	if tx == nil {
		return 0
	}
	return saturatingAddInt(int(tx.Size()), proposalAssemblyBytesPerRepairedTransaction)
}

func proposalManifestBlobSidecarWeight(sidecars []*types.BlobTxSidecar) int {
	weight := 0
	for _, sidecar := range sidecars {
		if sidecar == nil {
			continue
		}
		weight = saturatingAddInt(weight, 128)
		for _, blob := range sidecar.Blobs {
			weight = saturatingAddInt(weight, len(blob))
		}
		weight = saturatingAddInt(weight, saturatingMulInt(len(sidecar.Commitments)+len(sidecar.Proofs), 48))
	}
	return weight
}

func proposalExecutionEnvelope(tx *types.Transaction) *types.Transaction {
	if tx != nil && tx.Type() == types.BlobTxType && tx.BlobSidecar() != nil {
		return tx.WithBlobSidecar(nil)
	}
	return tx
}

func newCompleteProposalAssembly(block *types.Block, encodedBytes int) (*proposalAssemblyState, error) {
	manifest, err := proposalDataManifestForBlock(block)
	if err != nil {
		return nil, err
	}
	txs := block.Transactions()
	state := &proposalAssemblyState{
		manifest:     manifest,
		positions:    make(map[common.Hash]int, len(txs)),
		transactions: make(types.Transactions, len(txs)),
		revision:     1,
		cacheWeight: saturatingAddInt(
			proposalAssemblyBaseWeight(encodedBytes, len(txs)),
			proposalManifestBlobSidecarWeight(manifest.BlobSidecars),
		),
	}
	for index, tx := range txs {
		if tx == nil || !tx.IsInitialized() {
			return nil, fmt.Errorf("proposal transaction %d is not initialized", index)
		}
		hash := tx.Hash()
		if _, duplicate := state.positions[hash]; duplicate {
			return nil, fmt.Errorf("proposal repeats transaction %s", hash)
		}
		state.transactions[index] = proposalExecutionEnvelope(tx)
		state.positions[hash] = index
	}
	return state, nil
}

func (s *Service) newPendingProposalAssembly(manifest *proposalDataManifest, encodedBytes int) (*proposalAssemblyState, error) {
	if manifest == nil {
		return nil, fmt.Errorf("nil proposal manifest")
	}
	state := &proposalAssemblyState{
		manifest:     manifest,
		positions:    make(map[common.Hash]int, len(manifest.TransactionHashes)),
		transactions: make(types.Transactions, len(manifest.TransactionHashes)),
		missingCount: len(manifest.TransactionHashes),
		revision:     1,
		cacheWeight: saturatingAddInt(
			proposalAssemblyBaseWeight(encodedBytes, len(manifest.TransactionHashes)),
			proposalManifestBlobSidecarWeight(manifest.BlobSidecars),
		),
	}
	for index, hash := range manifest.TransactionHashes {
		if _, duplicate := state.positions[hash]; duplicate {
			return nil, fmt.Errorf("proposal manifest repeats transaction %s", hash)
		}
		state.positions[hash] = index
		tx, err := s.resolveProposalTransaction(hash)
		if err != nil {
			return nil, err
		}
		if tx == nil {
			continue
		}
		tx = proposalExecutionEnvelope(tx)
		state.transactions[index] = tx
		state.missingCount--
		state.cacheWeight = saturatingAddInt(state.cacheWeight, proposalAssemblyTransactionWeight(tx))
	}
	return state, nil
}

func (s *Service) resolveProposalTransaction(hash common.Hash) (*types.Transaction, error) {
	var tx *types.Transaction
	if s.txPool != nil {
		tx = s.txPool.Get(hash)
	}
	if tx == nil && s.resolveTxQUICTransaction != nil {
		var err error
		tx, err = s.resolveTxQUICTransaction(hash)
		if err != nil {
			return nil, fmt.Errorf("resolve durable proposal transaction %s: %w", hash, err)
		}
	}
	if tx == nil {
		return nil, nil
	}
	if !tx.IsInitialized() {
		return nil, fmt.Errorf("proposal transaction lookup returned an uninitialized transaction for %s", hash)
	}
	if tx.Hash() != hash {
		return nil, fmt.Errorf("proposal transaction lookup mismatch for %s", hash)
	}
	return tx, nil
}

func proposalAssemblyMissingHashes(state *proposalAssemblyState) []common.Hash {
	if state == nil || state.manifest == nil || state.missingCount == 0 {
		return nil
	}
	missing := make([]common.Hash, 0, state.missingCount)
	for index, hash := range state.manifest.TransactionHashes {
		if state.transactions[index] == nil {
			missing = append(missing, hash)
		}
	}
	return missing
}

func proposalBodyMsgPayloadBytes(body *proposalBodyMsg) int {
	if body == nil {
		return 0
	}
	total := len(body.From) + len(body.LeaderID) + len(body.EncodedBlock) + len(body.Manifest) +
		len(body.Extra) + len(body.ParentQC) + len(body.KeyActivationProof) + len(body.ManifestAuthSig) + len(body.AuthSig) + len(body.MissingTxHashes)*common.HashLength
	for _, encoded := range body.TransactionBytes {
		total += len(encoded)
	}
	return total
}

func encodeProposalRepairTransaction(tx *types.Transaction) ([]byte, error) {
	return encodeProposalRepairTransactionForConfig(nil, tx)
}

func encodeProposalRepairTransactionForConfig(config *params.ChainConfig, tx *types.Transaction) ([]byte, error) {
	if tx == nil || !tx.IsInitialized() {
		return nil, fmt.Errorf("proposal repair transaction is not initialized")
	}
	encoded, err := tx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("encode proposal repair transaction: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > proposalRepairPayloadLimitForConfig(config) {
		return nil, fmt.Errorf("invalid proposal repair transaction size %d", len(encoded))
	}
	return encoded, nil
}

func decodeCanonicalProposalRepairTransaction(encoded []byte) (*types.Transaction, error) {
	return decodeCanonicalProposalRepairTransactionForConfig(nil, encoded)
}

func decodeCanonicalProposalRepairTransactionForConfig(config *params.ChainConfig, encoded []byte) (*types.Transaction, error) {
	if len(encoded) == 0 || len(encoded) > proposalRepairPayloadLimitForConfig(config) {
		return nil, fmt.Errorf("invalid proposal repair transaction size %d", len(encoded))
	}
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(encoded); err != nil {
		return nil, fmt.Errorf("decode proposal repair transaction: %w", err)
	}
	if !tx.IsInitialized() {
		return nil, fmt.Errorf("decoded proposal repair transaction is not initialized")
	}
	canonical, err := tx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("re-encode proposal repair transaction: %w", err)
	}
	if !bytes.Equal(canonical, encoded) {
		return nil, fmt.Errorf("proposal repair transaction is not canonically encoded")
	}
	return tx, nil
}

func decodeProposalRepairTransactions(hashes []common.Hash, encodedTransactions [][]byte) (types.Transactions, error) {
	return decodeProposalRepairTransactionsForConfig(nil, hashes, encodedTransactions)
}

func decodeProposalRepairTransactionsForConfig(config *params.ChainConfig, hashes []common.Hash, encodedTransactions [][]byte) (types.Transactions, error) {
	if len(encodedTransactions) == 0 || len(encodedTransactions) != len(hashes) || len(encodedTransactions) > proposalRepairMaxHashes {
		return nil, fmt.Errorf("invalid proposal repair transaction count")
	}
	limit := proposalRepairPayloadLimitForConfig(config)
	total := len(hashes) * common.HashLength
	if total > limit {
		return nil, fmt.Errorf("proposal repair transactions exceed %d bytes", limit)
	}
	txs := make(types.Transactions, len(encodedTransactions))
	seen := make(map[common.Hash]struct{}, len(hashes))
	for index, encoded := range encodedTransactions {
		hash := hashes[index]
		if hash == (common.Hash{}) {
			return nil, fmt.Errorf("proposal repair transaction %d has an empty hash", index)
		}
		if _, duplicate := seen[hash]; duplicate {
			return nil, fmt.Errorf("proposal repair repeats transaction %s", hash)
		}
		seen[hash] = struct{}{}
		if len(encoded) > limit-total {
			return nil, fmt.Errorf("proposal repair transactions exceed %d bytes", limit)
		}
		total += len(encoded)
		tx, err := decodeCanonicalProposalRepairTransactionForConfig(config, encoded)
		if err != nil {
			return nil, fmt.Errorf("proposal repair transaction %d: %w", index, err)
		}
		if tx.Hash() != hash {
			return nil, fmt.Errorf("proposal repair transaction %d does not match its hash", index)
		}
		txs[index] = tx
	}
	return txs, nil
}

func proposalBodyParentQCID(encoded []byte) (common.Hash, error) {
	qc, err := hotstuff.DecodeSignedState(encoded)
	if err != nil || qc == nil {
		return common.Hash{}, err
	}
	id, err := hotstuff.SignedStateID(qc)
	if err != nil {
		return common.Hash{}, err
	}
	return id.Hash(), nil
}

func proposalBodyAuthDigest(chainID uint64, body *proposalBodyMsg) ([]byte, error) {
	if chainID == 0 || body == nil || body.From == "" || body.ProposalID == (common.Hash{}) {
		return nil, fmt.Errorf("invalid proposal sidecar authentication context")
	}
	encodedTransactions, err := rlp.EncodeToBytes(body.TransactionBytes)
	if err != nil {
		return nil, err
	}
	payload, err := rlp.EncodeToBytes([]interface{}{
		[]byte(proposalBodyAuthDomain), chainID, body.Type, body.ProposalID, body.BodyHash,
		body.BodySize, body.Number, body.ViewNumber, body.ViewID, body.LeaderID, body.From,
		body.ProposalKeyHash, body.SenderKeyHash,
		sha256.Sum256(body.EncodedBlock), sha256.Sum256(body.Manifest), body.MissingTxHashes,
		sha256.Sum256(encodedTransactions), sha256.Sum256(body.Extra), sha256.Sum256(body.ParentQC), sha256.Sum256(body.KeyActivationProof),
		sha256.Sum256(body.ManifestAuthSig),
	})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	return digest[:], nil
}

func validateProposalBodyWireShape(body *proposalBodyMsg) error {
	return validateProposalBodyWireShapeForConfig(nil, body)
}

func validateProposalBodyWireShapeForConfig(config *params.ChainConfig, body *proposalBodyMsg) error {
	if body == nil || body.From == "" || len(body.From) > 512 || len(body.AuthSig) == 0 || len(body.AuthSig) > 256 {
		return fmt.Errorf("invalid proposal sidecar identity fields")
	}
	if len(body.ManifestAuthSig) > 256 {
		return fmt.Errorf("proposal manifest signature exceeds size limit")
	}
	if body.ProposalID == (common.Hash{}) || body.BodyHash == (common.Hash{}) || body.BodySize == 0 ||
		body.ProposalKeyHash == (common.Hash{}) || body.SenderKeyHash == (common.Hash{}) ||
		body.Number == 0 || body.ViewNumber == 0 || body.ViewID == (common.Hash{}) || body.LeaderID == "" {
		return fmt.Errorf("incomplete proposal data context")
	}
	if body.BodySize > uint64(proposalBodyLimitForConfig(config)) {
		return fmt.Errorf("proposal body size %d exceeds configured limit", body.BodySize)
	}
	if len(body.EncodedBlock) != 0 {
		return fmt.Errorf("full proposal body is forbidden on the wire")
	}
	if len(body.KeyActivationProof) > types.MaxFHSFinalityProofSize {
		return fmt.Errorf("proposal key activation proof exceeds %d bytes", types.MaxFHSFinalityProofSize)
	}
	if len(body.Extra)+len(body.ParentQC) > proposalBodyControlMaxBytes {
		return fmt.Errorf("proposal sidecar proof exceeds %d bytes", proposalBodyControlMaxBytes)
	}
	switch body.Type {
	case proposalBodyMsgManifest:
		if len(body.Manifest) == 0 || len(body.Manifest) > proposalBodyLimitForConfig(config) ||
			len(body.MissingTxHashes) != 0 || len(body.TransactionBytes) != 0 {
			return fmt.Errorf("invalid proposal manifest payload")
		}
		if _, err := decodeProposalDataManifestForConfig(config, body.Manifest); err != nil {
			return err
		}
	case proposalBodyMsgRepairRequest:
		if len(body.Manifest) != 0 || len(body.TransactionBytes) != 0 || len(body.Extra) != 0 || len(body.ParentQC) != 0 || len(body.KeyActivationProof) != 0 ||
			len(body.MissingTxHashes) > proposalRepairMaxHashes {
			return fmt.Errorf("invalid proposal repair request")
		}
		seen := make(map[common.Hash]struct{}, len(body.MissingTxHashes))
		for _, hash := range body.MissingTxHashes {
			if hash == (common.Hash{}) {
				return fmt.Errorf("proposal repair request contains an empty hash")
			}
			if _, duplicate := seen[hash]; duplicate {
				return fmt.Errorf("proposal repair request repeats transaction %s", hash)
			}
			seen[hash] = struct{}{}
		}
	case proposalBodyMsgRepairData:
		if len(body.Manifest) != 0 || len(body.Extra) != 0 || len(body.ParentQC) != 0 || len(body.KeyActivationProof) != 0 ||
			len(body.TransactionBytes) == 0 || len(body.TransactionBytes) != len(body.MissingTxHashes) ||
			len(body.TransactionBytes) > proposalRepairMaxHashes || proposalBodyMsgPayloadBytes(body) > proposalRepairPayloadLimitForConfig(config) {
			return fmt.Errorf("invalid proposal repair payload")
		}
		if _, err := decodeProposalRepairTransactionsForConfig(config, body.MissingTxHashes, body.TransactionBytes); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown proposal sidecar message type")
	}
	return nil
}

func (s *Service) sealProposalBody(body *proposalBodyMsg) error {
	if body == nil {
		return fmt.Errorf("proposal sidecar signing key is unavailable")
	}
	s.proposalBodySignMu.Lock()
	defer s.proposalBodySignMu.Unlock()
	s.muConsensusIdentity.RLock()
	secret, public := s.proposalBodySecret, s.consensusPublic
	s.muConsensusIdentity.RUnlock()
	if secret == nil || public == nil {
		return fmt.Errorf("proposal sidecar signing key is unavailable")
	}
	body.From = s.Self()
	current := s.GetCurrentView()
	if current == nil || current.KeyHash == (common.Hash{}) {
		return fmt.Errorf("proposal sidecar committee generation is unavailable")
	}
	body.SenderKeyHash = current.KeyHash
	// A historical proposal donor signs under that proposal's committee when
	// possible. Repair requests may legitimately be sent by a lagging member
	// outside the proposal's later committee, in which case the sender's current
	// generation remains the authenticated identity.
	if body.ProposalKeyHash != (common.Hash{}) && s.kbc != nil {
		if _, err := s.proposalBodySenderKey(body.ProposalKeyHash, body.From); err == nil {
			body.SenderKeyHash = body.ProposalKeyHash
		}
	}
	if body.Type == proposalBodyMsgManifest && body.From == body.LeaderID && len(body.Manifest) > 0 {
		if err := signProposalManifest(s.ChainID(), body, secret); err != nil {
			return err
		}
	}
	digest, err := proposalBodyAuthDigest(s.ChainID(), body)
	if err != nil {
		return err
	}
	signature := secret.SignHash(digest)
	if signature == nil {
		return fmt.Errorf("failed to sign proposal sidecar")
	}
	body.AuthSig = append(body.AuthSig[:0], signature.Serialize()...)
	return nil
}

func (s *Service) proposalBodySenderKey(keyHash common.Hash, from string) (*bls.PublicKey, error) {
	if s == nil || s.kbc == nil || keyHash == (common.Hash{}) || from == "" {
		return nil, fmt.Errorf("proposal sidecar committee identity is incomplete")
	}
	_, resolved, _, err := s.resolveExactFHSCommittee(keyHash, false)
	if err != nil {
		return nil, fmt.Errorf("proposal sidecar committee %s is unavailable: %w", keyHash, err)
	}
	for _, node := range resolved.List {
		if node != nil && node.Address == from {
			public := bftview.StrToBlsPubKey(node.Public)
			if public == nil {
				return nil, fmt.Errorf("proposal sidecar sender has an invalid committee key")
			}
			return public, nil
		}
	}
	return nil, fmt.Errorf("proposal sidecar sender is not in committee %s", keyHash)
}

func (s *Service) proposalBodySenderKeyForMessage(body *proposalBodyMsg) (*bls.PublicKey, error) {
	if body == nil {
		return nil, fmt.Errorf("proposal sidecar committee identity is incomplete")
	}
	public, ordinaryErr := s.proposalBodySenderKey(body.SenderKeyHash, body.From)
	if ordinaryErr == nil {
		return public, nil
	}
	// The first manifest after a key handoff can arrive before this replica has
	// received the old committee's direct-child QCBroadcast. Authenticate that
	// one message using its self-contained activation QC. All later message
	// types use the generic resolver, which can recover the same proof from the
	// authenticated manifest cache.
	if body.Type != proposalBodyMsgManifest || body.ProposalKeyHash == (common.Hash{}) ||
		body.ProposalKeyHash != body.SenderKeyHash || len(body.ParentQC) == 0 {
		return nil, ordinaryErr
	}
	_, committee, certifiedUncommitted, err := s.resolveExactFHSCommitteeWithActivation(
		body.SenderKeyHash, false, body.ParentQC, body.KeyActivationProof,
	)
	if err != nil || !certifiedUncommitted {
		return nil, ordinaryErr
	}
	for _, node := range committee.List {
		if node != nil && node.Address == body.From {
			public := bftview.StrToBlsPubKey(node.Public)
			if public == nil {
				return nil, fmt.Errorf("proposal sidecar sender has an invalid activated committee key")
			}
			return public, nil
		}
	}
	return nil, fmt.Errorf("proposal sidecar sender is not in activated committee %s", body.SenderKeyHash)
}

func (s *Service) verifyProposalBodySender(si *network.ServerIdentity, body *proposalBodyMsg) error {
	if si == nil || body == nil || body.From == "" || si.Address.String() != body.From {
		return fmt.Errorf("proposal sidecar transport identity mismatch")
	}
	public, err := s.proposalBodySenderKeyForMessage(body)
	if err != nil {
		return err
	}
	digest, err := proposalBodyAuthDigest(s.ChainID(), body)
	if err != nil {
		return err
	}
	var signature bls.Sign
	if len(body.AuthSig) == 0 || signature.Deserialize(body.AuthSig) != nil || !signature.VerifyHash(public, digest) {
		return fmt.Errorf("invalid proposal sidecar signature")
	}
	return nil
}

// verifyProposalManifestAuthority prevents any committee member from filling
// the shared manifest cache with proposals it doesn't lead. A non-leader may
// return a manifest only after the serialized HotStuff loop has accepted the
// exact Prepare and registered its validation key; this is the repair path for
// a leader manifest that was lost in transit.
func (s *Service) verifyProposalManifestAuthority(body *proposalBodyMsg) error {
	if s == nil || body == nil || body.Type != proposalBodyMsgManifest {
		return fmt.Errorf("invalid proposal manifest authority context")
	}
	s.muProposalValidation.Lock()
	for _, active := range s.activeProposalValidations {
		if active == nil {
			continue
		}
		key := active.key
		if key.ViewNumber == body.ViewNumber && key.ViewID == body.ViewID && key.LeaderID == body.LeaderID && key.ProposalID == body.ProposalID &&
			active.keyHash == body.ProposalKeyHash && active.keyHash == body.SenderKeyHash {
			s.muProposalValidation.Unlock()
			return nil
		}
	}
	if active := s.activeHighQCValidation; active != nil {
		if authority, ok := active.authorized[body.ProposalID]; ok &&
			authority.key.ViewNumber == body.ViewNumber && authority.key.ViewID == body.ViewID &&
			authority.key.LeaderID == body.LeaderID && authority.keyHash == body.ProposalKeyHash &&
			authority.keyHash == body.SenderKeyHash {
			s.muProposalValidation.Unlock()
			return nil
		}
	}
	s.muProposalValidation.Unlock()

	// A manifest is intentionally distributed before its Prepare, so the
	// serialized validation registry cannot authorize the first copy. Bind
	// that path to the route derived from the current consensus view. Merely
	// setting From == LeaderID is not authority: any Byzantine committee
	// member could otherwise allocate and evict shared manifest-cache entries.
	if body.From != body.LeaderID {
		return fmt.Errorf("proposal manifest sender is neither the route leader nor an active Prepare repair peer")
	}
	route, routeErr := s.CurrentFHSRoute()
	if routeErr == nil && proposalManifestMatchesRoute(body, route) &&
		body.ProposalKeyHash == route.KeyHash && body.SenderKeyHash == route.KeyHash {
		return nil
	}
	if err := s.verifyCertifiedTransitionManifestAuthority(body); err != nil {
		if routeErr != nil {
			return fmt.Errorf("resolve proposal manifest route: %v; certified transition: %w", routeErr, err)
		}
		return fmt.Errorf("proposal manifest does not match the current deterministic leader route: %w", err)
	}
	return nil
}

func proposalManifestMatchesRoute(body *proposalBodyMsg, route *FHSRoute) bool {
	return body != nil && route != nil && route.Enabled &&
		body.Type == proposalBodyMsgManifest && body.From == body.LeaderID &&
		body.ViewNumber == route.ProposalView && body.LeaderID == route.LeaderID
}

// verifyCertifiedTransitionManifestAuthority handles only the narrow interval
// in which this replica has installed a certified key carrier but has not yet
// received the consecutive pair that finalized it. The first new-epoch manifest
// supplies the terminal old-committee QC and, for an ancestor commit, the complete
// activation path. Exact parent linkage and a deterministic new-committee leader
// are required before the bounded manifest cache changes.
func (s *Service) verifyCertifiedTransitionManifestAuthority(body *proposalBodyMsg) error {
	if s == nil || s.chainConfig == nil || body == nil || body.From != body.LeaderID || body.ProposalKeyHash == (common.Hash{}) ||
		body.ProposalKeyHash != body.SenderKeyHash {
		return fmt.Errorf("invalid certified-transition manifest identity")
	}
	keyBlock, committee, certifiedUncommitted, err := s.resolveExactFHSCommitteeWithActivation(
		body.ProposalKeyHash, true, body.ParentQC, body.KeyActivationProof,
	)
	if err != nil {
		return err
	}
	if !certifiedUncommitted {
		return fmt.Errorf("manifest key committee is already canonical but is not the current route")
	}
	current := s.GetCurrentView()
	if current == nil || current.KeyHash != keyBlock.ParentHash() {
		return fmt.Errorf("manifest does not activate directly from the local key epoch")
	}
	leaderIndex, err := fairHotstuffLeaderIndex(
		s.chainConfig.FairHotstuffSeed, s.ChainID(), body.ViewNumber,
		keyBlock.CommitteeHash(), len(committee.List),
	)
	if err != nil {
		return err
	}
	if leaderIndex >= uint(len(committee.List)) || committee.List[leaderIndex] == nil {
		return fmt.Errorf("certified-transition leader index is invalid")
	}
	leader := committee.List[leaderIndex]
	expectedLeader := bftview.GetNodeID(leader.Address, leader.Public)
	if expectedLeader == "" || body.LeaderID != expectedLeader || body.From != expectedLeader {
		return fmt.Errorf("manifest sender is not the certified-transition deterministic leader")
	}

	manifest, err := decodeProposalDataManifestForConfig(s.chainConfig, body.Manifest)
	if err != nil {
		return err
	}
	if manifest.Header == nil || manifest.Header.Number == nil || manifest.Header.Number.Uint64() != body.Number ||
		manifest.Header.KeyHash != body.ProposalKeyHash {
		return fmt.Errorf("manifest header does not match its certified-transition context")
	}
	parentQC, err := hotstuff.DecodeSignedState(body.ParentQC)
	if err != nil || parentQC == nil {
		return fmt.Errorf("certified-transition manifest has no valid parent QC")
	}
	parentRef, err := s.verifyFHSQCCryptographic(parentQC)
	if err != nil {
		return fmt.Errorf("verify certified-transition parent QC: %w", err)
	}
	if len(body.KeyActivationProof) > 0 {
		proof, err := core.DecodeFHSCommitProofBytes(body.KeyActivationProof)
		if err != nil || !hotstuff.SignedStateSemanticEqual(proof.QCs[len(proof.QCs)-1], parentQC) {
			return fmt.Errorf("certified-transition parent QC is not the activation proof's terminal certificate")
		}
	}
	if parentRef.BlockHash != manifest.Header.ParentHash ||
		parentRef.KeyHash != keyBlock.ParentHash() || parentRef.Number == ^uint64(0) ||
		parentRef.ViewNumber == ^uint64(0) || body.Number != parentRef.Number+1 ||
		body.ViewNumber != parentRef.ViewNumber+1 {
		return fmt.Errorf("manifest does not extend its verified activation parent")
	}
	return nil
}

// discardIncompletePeerManifest removes only an exact failed peer candidate.
// Authenticated relays with missing transactions remain cached for repair;
// the leader's manifest signature prevents another peer from poisoning them.
func (s *Service) discardIncompletePeerManifest(candidate *proposalBodyMsg) {
	if s == nil || candidate == nil || candidate.From == candidate.LeaderID {
		return
	}
	s.muProposalBody.Lock()
	existing := s.proposalBodies[candidate.ProposalID]
	if existing != nil && len(existing.EncodedBlock) == 0 && existing.From == candidate.From &&
		bytes.Equal(existing.Manifest, candidate.Manifest) {
		s.deleteProposalBodyLocked(candidate.ProposalID)
	}
	s.muProposalBody.Unlock()
}

func (s *Service) proposalBodyCacheUsageLocked() (int, int) {
	bytesUsed := 0
	for _, body := range s.proposalBodies {
		if body != nil {
			bytesUsed = saturatingAddInt(bytesUsed, proposalBodyMsgPayloadBytes(body))
		}
	}
	return len(s.proposalBodies), bytesUsed
}

func (s *Service) proposalAssemblyCacheUsageLocked() int {
	bytesUsed := 0
	for proposalID, assembly := range s.proposalAssemblies {
		if assembly == nil || s.proposalBodies[proposalID] == nil {
			continue
		}
		bytesUsed = saturatingAddInt(bytesUsed, assembly.cacheWeight)
	}
	return bytesUsed
}

// dropOldestCompleteProposalAssemblyExceptLocked releases only a rebuildable
// donor index. The authenticated encoded body and certified chain record stay
// cached, so index pressure cannot break the two-chain suffix needed for
// finality or restart repair.
func (s *Service) dropOldestCompleteProposalAssemblyExceptLocked(except common.Hash) bool {
	var (
		oldestID common.Hash
		oldestAt int64
		found    bool
	)
	for proposalID, assembly := range s.proposalAssemblies {
		body := s.proposalBodies[proposalID]
		if proposalID == except || assembly == nil || body == nil || len(body.EncodedBlock) == 0 {
			continue
		}
		if !found || body.CreatedAtUnixNano < oldestAt {
			oldestID, oldestAt, found = proposalID, body.CreatedAtUnixNano, true
		}
	}
	if !found {
		return false
	}
	delete(s.proposalAssemblies, oldestID)
	return true
}

func (s *Service) ensureProposalAssemblyCapacityLocked(proposalID common.Hash, replacementWeight int) bool {
	if replacementWeight < 0 {
		return false
	}
	oldWeight := 0
	if old := s.proposalAssemblies[proposalID]; old != nil {
		oldWeight = old.cacheWeight
	}
	growth := replacementWeight - oldWeight
	if growth < 0 {
		growth = 0
	}
	limit := proposalBodyCacheLimitForConfig(s.chainConfig)
	for !fitsIntBudget(s.proposalAssemblyCacheUsageLocked(), growth, limit) {
		if s.dropOldestCompleteProposalAssemblyExceptLocked(proposalID) {
			continue
		}
		if !s.evictOldestProposalBodyExceptLocked(proposalID) {
			return false
		}
	}
	return true
}

func (s *Service) evictOldestProposalBodyLocked() bool {
	return s.evictOldestProposalBodyExceptLocked(common.Hash{})
}

func (s *Service) evictOldestProposalBodyExceptLocked(except common.Hash) bool {
	var oldestID common.Hash
	var oldest *proposalBodyMsg
	found := false
	for id, body := range s.proposalBodies {
		if id == except {
			continue
		}
		if body == nil {
			oldestID, found = id, true
			break
		}
		if oldest == nil || body.CreatedAtUnixNano < oldest.CreatedAtUnixNano {
			oldestID, oldest, found = id, body, true
		}
	}
	if !found {
		return false
	}
	s.evictProposalBodyLocked(oldestID)
	return true
}

func (s *Service) updateProposalBodyProof(proposalID common.Hash, extra []byte, parentQC *hotstuff.SignedState) error {
	if proposalID == (common.Hash{}) {
		return fmt.Errorf("empty proposal id")
	}
	encodedParent, err := hotstuff.EncodeSignedState(parentQC)
	if err != nil {
		return err
	}
	s.muProposalBody.Lock()
	if body := s.proposalBodies[proposalID]; body != nil {
		if !bytes.Equal(body.Extra, extra) || !bytes.Equal(body.ParentQC, encodedParent) {
			s.muProposalBody.Unlock()
			return fmt.Errorf("proposal sidecar proof differs from its signed proposal reference")
		}
	}
	s.muProposalBody.Unlock()
	return nil
}

func (s *Service) purgeExpiredProposalCachesLocked(now time.Time) {
	ttl := proposalBodyCacheTTLForConfig(s.chainConfig)
	for id, body := range s.proposalBodies {
		if body == nil || (body.CreatedAtUnixNano > 0 && now.Sub(time.Unix(0, body.CreatedAtUnixNano)) > ttl) {
			s.evictProposalBodyLocked(id)
		}
	}
}

func (s *Service) purgeExpiredProposalCaches(now time.Time) {
	s.muProposalBody.Lock()
	s.purgeExpiredProposalCachesLocked(now)
	s.muProposalBody.Unlock()
}

func (s *Service) storeProposalBody(body *proposalBodyMsg) error {
	return s.storeProposalBodyWithOwnership(body, false, nil)
}

// storeProposalBodyWithOwnership may take ownership of EncodedBlock only for
// freshly reconstructed, function-local bytes. Network, staging and test
// callers retain defensive-copy semantics through storeProposalBody.
func (s *Service) storeProposalBodyWithOwnership(body *proposalBodyMsg, ownEncodedBlock bool, expectedAssembly *proposalAssemblyState) error {
	if body == nil {
		return fmt.Errorf("nil proposal body")
	}
	if body.ProposalID == (common.Hash{}) {
		return fmt.Errorf("proposal body missing proposal id")
	}
	if body.BodyHash == (common.Hash{}) {
		return fmt.Errorf("proposal body missing body hash")
	}
	if body.BodySize == 0 || body.BodySize != uint64(len(body.EncodedBlock)) {
		return fmt.Errorf("proposal body size mismatch: declared=%d actual=%d", body.BodySize, len(body.EncodedBlock))
	}
	if len(body.EncodedBlock) == 0 {
		return fmt.Errorf("proposal body missing encoded block")
	}
	bodyLimit := proposalBodyLimitForConfig(s.chainConfig)
	if len(body.EncodedBlock) > bodyLimit {
		return fmt.Errorf("proposal body too large: bytes=%d limit=%d", len(body.EncodedBlock), bodyLimit)
	}
	if got := types.HotstuffProposalBodyHash(body.EncodedBlock); got != body.BodyHash {
		return fmt.Errorf("proposal body hash mismatch: have %s want %s", got, body.BodyHash)
	}
	if body.Number == 0 || body.ViewNumber == 0 || body.ViewID == (common.Hash{}) || body.LeaderID == "" {
		return fmt.Errorf("proposal sidecar has incomplete proposal context")
	}
	block := types.DecodeToBlock(body.EncodedBlock)
	if block == nil {
		return fmt.Errorf("proposal sidecar contains an invalid block")
	}
	assembly, err := newCompleteProposalAssembly(block, len(body.EncodedBlock))
	if err != nil {
		return err
	}
	parentQCID, err := proposalBodyParentQCID(body.ParentQC)
	if err != nil {
		return fmt.Errorf("proposal sidecar parent QC: %w", err)
	}
	ref, err := types.NewHotstuffProposalRefWithProof(s.ChainID(), body.ViewNumber, body.ViewID, body.LeaderID, block, body.EncodedBlock, body.Extra, parentQCID)
	if err != nil {
		return err
	}
	if ref.ProposalID() != body.ProposalID || ref.Number != body.Number || ref.BodyHash != body.BodyHash || ref.KeyHash != body.ProposalKeyHash {
		return fmt.Errorf("proposal sidecar does not match its proposal ID")
	}
	var cpy *proposalBodyMsg
	if ownEncodedBlock {
		cpy = cloneProposalBodyEnvelope(body)
		cpy.EncodedBlock = body.EncodedBlock
	} else {
		cpy = cloneProposalBodyMsg(body)
	}
	cpy.Type = proposalBodyMsgManifest
	cpy.Manifest = nil
	cpy.MissingTxHashes = nil
	cpy.TransactionBytes = nil
	if cpy.From == "" {
		cpy.From = s.Self()
	}
	// Never trust remote wall-clock values for TTL or eviction decisions.
	cpy.CreatedAtUnixNano = time.Now().UnixNano()

	s.muProposalBody.Lock()
	if s.proposalAssemblies == nil {
		s.proposalAssemblies = make(map[common.Hash]*proposalAssemblyState)
	}
	s.purgeExpiredProposalCachesLocked(time.Now())
	if expectedAssembly != nil {
		pending := s.proposalBodies[cpy.ProposalID]
		if s.proposalAssemblies[cpy.ProposalID] != expectedAssembly || pending == nil || len(pending.EncodedBlock) > 0 {
			s.muProposalBody.Unlock()
			return errProposalAssemblySuperseded
		}
	}
	if !s.ensureProposalAssemblyCapacityLocked(cpy.ProposalID, assembly.cacheWeight) {
		s.muProposalBody.Unlock()
		return fmt.Errorf("proposal assembly cache capacity exhausted")
	}
	var cached *proposalBodyMsg
	if existing := s.proposalBodies[cpy.ProposalID]; existing != nil {
		if existing.BodyHash != cpy.BodyHash || existing.BodySize != cpy.BodySize ||
			existing.ProposalKeyHash != cpy.ProposalKeyHash || !bytes.Equal(existing.Extra, cpy.Extra) ||
			!bytes.Equal(existing.ParentQC, cpy.ParentQC) || !bytes.Equal(existing.KeyActivationProof, cpy.KeyActivationProof) {
			s.muProposalBody.Unlock()
			return fmt.Errorf("conflicting proposal sidecar for %s", cpy.ProposalID)
		}
		if len(existing.EncodedBlock) == 0 {
			existingBytes := proposalBodyMsgPayloadBytes(existing)
			replacementBytes := proposalBodyMsgPayloadBytes(cpy)
			growth := replacementBytes - existingBytes
			if growth < 0 {
				growth = 0
			}
			for {
				_, bytesUsed := s.proposalBodyCacheUsageLocked()
				if fitsIntBudget(bytesUsed, growth, proposalBodyCacheLimitForConfig(s.chainConfig)) {
					break
				}
				if !s.evictOldestProposalBodyExceptLocked(cpy.ProposalID) {
					s.muProposalBody.Unlock()
					return fmt.Errorf("proposal sidecar cache capacity exhausted")
				}
			}
			s.proposalBodies[cpy.ProposalID] = cpy
			s.proposalAssemblies[cpy.ProposalID] = assembly
			cached = cpy
		} else {
			if !bytes.Equal(existing.EncodedBlock, cpy.EncodedBlock) {
				s.muProposalBody.Unlock()
				return fmt.Errorf("conflicting proposal sidecar for %s", cpy.ProposalID)
			}
			if s.proposalAssemblies[cpy.ProposalID] == nil {
				s.proposalAssemblies[cpy.ProposalID] = assembly
			}
			cached = existing
		}
	} else {
		entryBytes := proposalBodyMsgPayloadBytes(cpy)
		for {
			entries, bytesUsed := s.proposalBodyCacheUsageLocked()
			if entries < proposalBodyCacheMaxEntries && fitsIntBudget(bytesUsed, entryBytes, proposalBodyCacheLimitForConfig(s.chainConfig)) {
				break
			}
			if !s.evictOldestProposalBodyLocked() {
				s.muProposalBody.Unlock()
				return fmt.Errorf("proposal sidecar cache capacity exhausted")
			}
		}
		s.proposalBodies[cpy.ProposalID] = cpy
		s.proposalAssemblies[cpy.ProposalID] = assembly
		cached = cpy
	}
	s.signalProposalBodyUpdateLocked()
	s.muProposalBody.Unlock()

	// Cache publication is the validation boundary. The fixed single writer is
	// best effort and bounded: queue pressure or a disk failure cannot put an
	// 8 MiB write back on the Vote path. Missing content remains recoverable by
	// ProposalID/BodyHash after restart.
	if s.fhsContentWriter != nil {
		if !s.fhsContentWriter.enqueue(ref, cached) {
			log.Warn("FHS proposal content persistence queue is full; retaining repairable cache entry",
				"proposalID", ref.ProposalID(), "bodyHash", ref.BodyHash, "bytes", ref.BodySize)
		}
		return nil
	}
	// Isolated tests and lightweight Service fixtures do not own a lifecycle
	// writer; preserve deterministic synchronous persistence for those callers.
	if err := s.persistFHSProposalData(ref, cached); err != nil {
		return fmt.Errorf("persist proposal data: %w", err)
	}
	return nil
}

func (s *Service) storeProposalManifest(body *proposalBodyMsg) ([]common.Hash, error) {
	if body == nil || body.Type != proposalBodyMsgManifest || len(body.Manifest) == 0 {
		return nil, fmt.Errorf("invalid proposal manifest")
	}
	if body.BodySize == 0 || body.BodySize > uint64(proposalBodyLimitForConfig(s.chainConfig)) {
		return nil, fmt.Errorf("invalid proposal body size %d", body.BodySize)
	}
	manifest, err := decodeProposalDataManifestForConfig(s.chainConfig, body.Manifest)
	if err != nil {
		return nil, err
	}
	if manifest.Header.Number.Uint64() != body.Number {
		return nil, fmt.Errorf("proposal manifest block number mismatch")
	}
	if manifest.Header.KeyHash != body.ProposalKeyHash {
		return nil, fmt.Errorf("proposal manifest committee generation mismatch")
	}
	if manifest.Header.UncleHash != types.CalcUncleHash(manifest.Uncles) {
		return nil, fmt.Errorf("proposal manifest uncle root mismatch")
	}
	if manifest.Header.CommonTxAdmissionRoot != types.DeriveCommonTxAdmissionRoot(manifest.CommonTxAdmissionBatches, manifest.CommonTxAdmissionRefs) ||
		manifest.Header.CommonTxRewardRoot != types.DeriveCommonTxRewardRoot(manifest.CommonTxRewards) {
		return nil, fmt.Errorf("proposal manifest common transaction root mismatch")
	}
	if _, err := proposalBodyParentQCID(body.ParentQC); err != nil {
		return nil, fmt.Errorf("proposal manifest parent QC: %w", err)
	}
	assembly, err := s.newPendingProposalAssembly(manifest, len(body.Manifest))
	if err != nil {
		return nil, err
	}
	cpy := cloneProposalBodyMsg(body)
	cpy.EncodedBlock = nil
	cpy.MissingTxHashes = nil
	cpy.TransactionBytes = nil
	cpy.CreatedAtUnixNano = time.Now().UnixNano()

	s.muProposalBody.Lock()
	if s.proposalAssemblies == nil {
		s.proposalAssemblies = make(map[common.Hash]*proposalAssemblyState)
	}
	s.purgeExpiredProposalCachesLocked(time.Now())
	if !s.ensureProposalAssemblyCapacityLocked(cpy.ProposalID, assembly.cacheWeight) {
		s.muProposalBody.Unlock()
		return nil, fmt.Errorf("proposal assembly cache capacity exhausted")
	}
	if existing := s.proposalBodies[cpy.ProposalID]; existing != nil {
		if existing.BodyHash != cpy.BodyHash || existing.BodySize != cpy.BodySize || existing.Number != cpy.Number ||
			existing.ViewNumber != cpy.ViewNumber || existing.ViewID != cpy.ViewID || existing.LeaderID != cpy.LeaderID ||
			existing.ProposalKeyHash != cpy.ProposalKeyHash ||
			!bytes.Equal(existing.Extra, cpy.Extra) || !bytes.Equal(existing.ParentQC, cpy.ParentQC) || !bytes.Equal(existing.KeyActivationProof, cpy.KeyActivationProof) {
			s.muProposalBody.Unlock()
			return nil, fmt.Errorf("conflicting proposal manifest for %s", cpy.ProposalID)
		}
		if len(existing.EncodedBlock) > 0 {
			s.muProposalBody.Unlock()
			return nil, nil
		}
		if !bytes.Equal(existing.Manifest, cpy.Manifest) {
			s.muProposalBody.Unlock()
			return nil, fmt.Errorf("conflicting proposal manifest for %s", cpy.ProposalID)
		}
		if s.proposalAssemblies[cpy.ProposalID] == nil {
			s.proposalAssemblies[cpy.ProposalID] = assembly
			s.signalProposalBodyUpdateLocked()
		}
		s.muProposalBody.Unlock()
		if _, err := s.assembleProposalBody(cpy.ProposalID); err != nil {
			return nil, err
		}
		return s.proposalMissingHashes(cpy.ProposalID), nil
	}
	entryBytes := proposalBodyMsgPayloadBytes(cpy)
	for {
		entries, bytesUsed := s.proposalBodyCacheUsageLocked()
		if entries < proposalBodyCacheMaxEntries && fitsIntBudget(bytesUsed, entryBytes, proposalBodyCacheLimitForConfig(s.chainConfig)) {
			break
		}
		if !s.evictOldestProposalBodyLocked() {
			s.muProposalBody.Unlock()
			return nil, fmt.Errorf("proposal manifest cache capacity exhausted")
		}
	}
	s.proposalBodies[cpy.ProposalID] = cpy
	s.proposalAssemblies[cpy.ProposalID] = assembly
	s.signalProposalBodyUpdateLocked()
	s.muProposalBody.Unlock()
	if _, err := s.assembleProposalBody(cpy.ProposalID); err != nil {
		return nil, err
	}
	return s.proposalMissingHashes(cpy.ProposalID), nil
}

func (s *Service) mergeProposalRepair(body *proposalBodyMsg) (int, error) {
	if body == nil || body.Type != proposalBodyMsgRepairData {
		return 0, fmt.Errorf("invalid proposal repair")
	}
	txs, err := decodeProposalRepairTransactionsForConfig(s.chainConfig, body.MissingTxHashes, body.TransactionBytes)
	if err != nil {
		return 0, err
	}
	s.muProposalBody.Lock()
	existing := s.proposalBodies[body.ProposalID]
	if existing == nil || len(existing.Manifest) == 0 || len(existing.EncodedBlock) > 0 {
		s.muProposalBody.Unlock()
		return 0, fmt.Errorf("proposal repair has no pending manifest")
	}
	if existing.BodyHash != body.BodyHash || existing.BodySize != body.BodySize || existing.Number != body.Number ||
		existing.ViewNumber != body.ViewNumber || existing.ViewID != body.ViewID || existing.LeaderID != body.LeaderID ||
		existing.ProposalKeyHash != body.ProposalKeyHash {
		s.muProposalBody.Unlock()
		return 0, fmt.Errorf("proposal repair context mismatch")
	}
	assembly := s.proposalAssemblies[body.ProposalID]
	if assembly == nil || assembly.manifest == nil {
		s.muProposalBody.Unlock()
		return 0, fmt.Errorf("proposal repair has no verified manifest index")
	}
	positions := make([]int, len(txs))
	for index, hash := range body.MissingTxHashes {
		position, ok := assembly.positions[hash]
		if !ok {
			s.muProposalBody.Unlock()
			return 0, fmt.Errorf("proposal repair transaction %s is outside the manifest", hash)
		}
		positions[index] = position
	}
	additionalBytes := 0
	assemblyGrowth := 0
	additions := make([][]byte, 0, len(body.TransactionBytes))
	newlyResolved := make([]common.Hash, 0, len(body.TransactionBytes))
	newPositions := make([]int, 0, len(body.TransactionBytes))
	newTransactions := make(types.Transactions, 0, len(body.TransactionBytes))
	for index := range txs {
		position := positions[index]
		if assembly.transactions[position] != nil {
			continue
		}
		newPositions = append(newPositions, position)
		newTransactions = append(newTransactions, proposalExecutionEnvelope(txs[index]))
		newlyResolved = append(newlyResolved, body.MissingTxHashes[index])
		additions = append(additions, append([]byte(nil), body.TransactionBytes[index]...))
		additionalBytes = saturatingAddInt(additionalBytes, len(body.TransactionBytes[index]))
		assemblyGrowth = saturatingAddInt(assemblyGrowth,
			saturatingAddInt(len(body.TransactionBytes[index]), proposalAssemblyBytesPerRepairedTransaction))
	}
	for {
		_, bytesUsed := s.proposalBodyCacheUsageLocked()
		if fitsIntBudget(bytesUsed, additionalBytes, proposalBodyCacheLimitForConfig(s.chainConfig)) {
			break
		}
		if !s.evictOldestProposalBodyExceptLocked(body.ProposalID) {
			s.muProposalBody.Unlock()
			return 0, fmt.Errorf("proposal repair exceeds cache capacity")
		}
	}
	replacementWeight := saturatingAddInt(assembly.cacheWeight, assemblyGrowth)
	if !s.ensureProposalAssemblyCapacityLocked(body.ProposalID, replacementWeight) {
		s.muProposalBody.Unlock()
		return 0, fmt.Errorf("proposal repair exceeds assembly cache capacity")
	}
	for index, position := range newPositions {
		assembly.transactions[position] = newTransactions[index]
		assembly.missingCount--
	}
	existing.TransactionBytes = append(existing.TransactionBytes, additions...)
	existing.CreatedAtUnixNano = time.Now().UnixNano()
	assembly.resolved = append(assembly.resolved, newlyResolved...)
	assembly.cacheWeight = replacementWeight
	assembly.revision++
	s.signalProposalBodyUpdateLocked()
	s.muProposalBody.Unlock()
	return s.assembleProposalBody(body.ProposalID)
}

func (s *Service) proposalMissingHashes(proposalID common.Hash) []common.Hash {
	s.muProposalBody.RLock()
	missing := proposalAssemblyMissingHashes(s.proposalAssemblies[proposalID])
	s.muProposalBody.RUnlock()
	return missing
}

func (s *Service) finishProposalAssemblyError(proposalID common.Hash, state *proposalAssemblyState, err error) (int, error) {
	s.muProposalBody.Lock()
	if current := s.proposalAssemblies[proposalID]; current == state {
		current.assembling = false
		current.assemblyErr = err
		current.revision++
		s.signalProposalBodyUpdateLocked()
	}
	s.muProposalBody.Unlock()
	return 0, err
}

func reconstructProposalBlock(manifest *proposalDataManifest, txs types.Transactions) (*types.Block, error) {
	if manifest == nil || manifest.Header == nil {
		return nil, fmt.Errorf("proposal manifest is incomplete")
	}
	block, err := types.NewBlockWithHeader(manifest.Header).WithBodyAndBlobSidecars(txs, manifest.Uncles, manifest.BlobSidecars)
	if err != nil {
		return nil, fmt.Errorf("reconstruct proposal blob sidecars: %w", err)
	}
	block.SetCommonTxData(manifest.CommonTxAdmissionBatches, manifest.CommonTxAdmissionRefs, manifest.CommonTxRewards)
	return block, nil
}

func (s *Service) assembleProposalBody(proposalID common.Hash) (int, error) {
	s.muProposalBody.Lock()
	body := s.proposalBodies[proposalID]
	state := s.proposalAssemblies[proposalID]
	if body == nil || len(body.EncodedBlock) > 0 {
		s.muProposalBody.Unlock()
		return 0, nil
	}
	if state == nil || state.manifest == nil {
		s.muProposalBody.Unlock()
		return 0, fmt.Errorf("proposal has no verified manifest index")
	}
	if state.assemblyErr != nil {
		err := state.assemblyErr
		s.muProposalBody.Unlock()
		return 0, err
	}
	if state.missingCount > 0 || state.assembling {
		remaining := state.missingCount
		s.muProposalBody.Unlock()
		return remaining, nil
	}
	state.assembling = true
	manifest := state.manifest
	txs := append(types.Transactions(nil), state.transactions...)
	complete := cloneProposalBodyEnvelope(body)
	s.muProposalBody.Unlock()

	block, err := reconstructProposalBlock(manifest, txs)
	if err != nil {
		return s.finishProposalAssemblyError(proposalID, state, err)
	}
	encodedBlock := block.EncodeToBytes()
	if uint64(len(encodedBlock)) != complete.BodySize {
		return s.finishProposalAssemblyError(proposalID, state, fmt.Errorf("reconstructed proposal body size mismatch: have=%d want=%d", len(encodedBlock), complete.BodySize))
	}
	if hash := types.HotstuffProposalBodyHash(encodedBlock); hash != complete.BodyHash {
		return s.finishProposalAssemblyError(proposalID, state, fmt.Errorf("reconstructed proposal body hash mismatch: have=%s want=%s", hash, complete.BodyHash))
	}
	parentQCID, err := proposalBodyParentQCID(complete.ParentQC)
	if err != nil {
		return s.finishProposalAssemblyError(proposalID, state, err)
	}
	ref, err := types.NewHotstuffProposalRefWithProof(s.ChainID(), complete.ViewNumber, complete.ViewID, complete.LeaderID, block, encodedBlock, complete.Extra, parentQCID)
	if err != nil {
		return s.finishProposalAssemblyError(proposalID, state, err)
	}
	if ref.ProposalID() != complete.ProposalID || ref.Number != complete.Number || ref.BodyHash != complete.BodyHash ||
		ref.BodySize != complete.BodySize || ref.KeyHash != complete.ProposalKeyHash {
		return s.finishProposalAssemblyError(proposalID, state, fmt.Errorf("reconstructed proposal does not match its signed reference"))
	}
	complete.EncodedBlock = encodedBlock
	if err := s.storeProposalBodyWithOwnership(complete, true, state); err != nil {
		if errors.Is(err, errProposalAssemblySuperseded) {
			return 0, nil
		}
		return s.finishProposalAssemblyError(proposalID, state, err)
	}
	return 0, nil
}

func (s *Service) getProposalBody(proposalID common.Hash) *proposalBodyMsg {
	s.muProposalBody.RLock()
	body := cloneProposalBodyMsg(s.proposalBodies[proposalID])
	s.muProposalBody.RUnlock()
	return body
}

type proposalBodyWaitSnapshot struct {
	body         *proposalBodyMsg
	missingCount int
	assemblyErr  error
	hasManifest  bool
	assembling   bool
	wake         <-chan struct{}
}

// proposalBodySnapshotForWait copies a block-sized payload only after assembly
// has completed. Pending waits observe constant-size state plus a close/reopen
// notification channel, so unrelated timer ticks never clone the manifest or
// accumulated repair bytes.
func (s *Service) proposalBodySnapshotForWait(proposalID common.Hash) proposalBodyWaitSnapshot {
	s.muProposalBody.Lock()
	wake := s.proposalBodyWakeLocked()
	body := s.proposalBodies[proposalID]
	if body != nil && len(body.EncodedBlock) > 0 {
		s.muProposalBody.Unlock()
		// Completed cache entries are immutable. Retain the pointer across the
		// copy so a 256 MiB handoff does not monopolize the global proposal lock.
		complete := cloneProposalBodyMsg(body)
		return proposalBodyWaitSnapshot{body: complete, wake: wake}
	}
	snapshot := proposalBodyWaitSnapshot{wake: wake}
	if assembly := s.proposalAssemblies[proposalID]; assembly != nil {
		snapshot.missingCount = assembly.missingCount
		snapshot.assemblyErr = assembly.assemblyErr
		snapshot.hasManifest = assembly.manifest != nil
		snapshot.assembling = assembly.assembling
	}
	s.muProposalBody.Unlock()
	return snapshot
}

func (s *Service) resolveProposalAssemblyWindow(proposalID common.Hash, hashes []common.Hash) ([]common.Hash, error) {
	if len(hashes) == 0 {
		return nil, nil
	}
	resolved := make(map[common.Hash]*types.Transaction, len(hashes))
	for _, hash := range hashes {
		tx, err := s.resolveProposalTransaction(hash)
		if err != nil {
			return nil, err
		}
		if tx != nil {
			resolved[hash] = proposalExecutionEnvelope(tx)
		}
	}
	if len(resolved) > 0 {
		s.muProposalBody.Lock()
		state := s.proposalAssemblies[proposalID]
		changed := false
		if state != nil && state.manifest != nil && state.assemblyErr == nil {
			newlyResolved := make(map[common.Hash]*types.Transaction, len(resolved))
			for hash, tx := range resolved {
				position, ok := state.positions[hash]
				if !ok || state.transactions[position] != nil {
					continue
				}
				newlyResolved[hash] = tx
			}
			growth := 0
			for _, tx := range newlyResolved {
				growth = saturatingAddInt(growth, proposalAssemblyTransactionWeight(tx))
			}
			if len(newlyResolved) > 0 && s.ensureProposalAssemblyCapacityLocked(proposalID, saturatingAddInt(state.cacheWeight, growth)) {
				for hash, tx := range newlyResolved {
					position := state.positions[hash]
					state.transactions[position] = tx
					state.missingCount--
					state.resolved = append(state.resolved, hash)
				}
				state.cacheWeight = saturatingAddInt(state.cacheWeight, growth)
				changed = true
				state.revision++
				s.signalProposalBodyUpdateLocked()
			}
		}
		s.muProposalBody.Unlock()
		if changed {
			if _, err := s.assembleProposalBody(proposalID); err != nil {
				return nil, err
			}
		}
	}
	unresolved := make([]common.Hash, 0, len(hashes))
	s.muProposalBody.RLock()
	state := s.proposalAssemblies[proposalID]
	for _, hash := range hashes {
		position, ok := -1, false
		if state != nil {
			position, ok = state.positions[hash]
		}
		if !ok || state.transactions[position] == nil {
			unresolved = append(unresolved, hash)
		}
	}
	s.muProposalBody.RUnlock()
	return unresolved, nil
}

func (s *Service) storeVerifiedProposal(proposalID common.Hash, verified *core.VerifiedProposal) {
	if proposalID == (common.Hash{}) || verified == nil {
		return
	}
	s.muProposalBody.Lock()
	defer s.muProposalBody.Unlock()
	s.purgeExpiredProposalCachesLocked(time.Now())
	s.verifiedProposalByID[proposalID] = verified
}

func (s *Service) getVerifiedProposal(proposalID common.Hash) *core.VerifiedProposal {
	s.muProposalBody.RLock()
	verified := s.verifiedProposalByID[proposalID]
	s.muProposalBody.RUnlock()
	return verified
}

func (s *Service) deleteProposalCaches(proposalID common.Hash) {
	s.muProposalBody.Lock()
	s.deleteProposalBodyLocked(proposalID)
	s.muProposalBody.Unlock()
}

func signedStateEqual(a, b *hotstuff.SignedState) bool {
	return hotstuff.SignedStateSemanticEqual(a, b)
}

func (s *Service) HighestCertified() *hotstuff.SignedState {
	s.muProposalBody.RLock()
	var qc *hotstuff.SignedState
	if s.fhsHighest != nil {
		qc = hotstuff.CloneSignedState(s.fhsHighest.qc)
	}
	s.muProposalBody.RUnlock()
	if s.fhsStore != nil {
		state, _, err := s.fhsStore.snapshot()
		if err == nil && state != nil && state.HighestQC != nil && (qc == nil || state.HighestQC.Number > qc.Number) {
			qc = hotstuff.CloneSignedState(state.HighestQC)
		}
	}
	return qc
}

// fhsCertifiedFrontierAboveCanonical returns the only in-memory certificate
// that is allowed to act as an execution base. A proof-aware block import can
// advance the canonical chain while an asynchronous HighQC worker still sees
// the old certified cache. Such a record is historical state, not a parent
// overlay: feeding it back to ValidateBlockForHotstuff would replay an already
// canonical block against the current StateDB.
func fhsCertifiedFrontierAboveCanonical(highest *fhsCertifiedProposal, canonicalNumber uint64) *fhsCertifiedProposal {
	if highest == nil || highest.ref == nil || highest.ref.Number <= canonicalNumber {
		return nil
	}
	return highest
}

// Reconciliation retains certified branches rooted at the committed head and
// selects the greatest observed view. Multiple uncommitted siblings are legal;
// a fork below the canonical head is not an execution base.
func (s *Service) reconcileFHSCertifiedFrontierLocked(canonical *types.Block) error {
	if s == nil || canonical == nil {
		return fmt.Errorf("cannot reconcile FHS certified frontier without canonical head")
	}
	if s.fhsCertifiedByHash == nil {
		s.fhsCertifiedByHash = make(map[common.Hash]*fhsCertifiedProposal)
	}
	if s.fhsCertifiedByID == nil {
		s.fhsCertifiedByID = make(map[common.Hash]*fhsCertifiedProposal)
	}
	kept := make(map[common.Hash]struct{})
	views := make(map[uint64]*hotstuff.SignedState)
	var frontier *fhsCertifiedProposal
	for id, record := range s.fhsCertifiedByID {
		if record == nil || record.ref == nil || record.ref.Number <= canonical.NumberU64() {
			continue
		}
		if record.ref.ProposalID() != id {
			return fmt.Errorf("FHS certified cache key mismatch for %s", id)
		}
		if err := validateStagedFHSCertificateArtifact(&fhsHighQCValidationItem{ref: record.ref, qc: record.qc, verified: record.verified}); err != nil {
			return err
		}
		cursor := record
		anchored := false
		for depth := 0; depth <= fhsMaxCertifiedChainDepth; depth++ {
			if cursor.ref.ParentHash == canonical.Hash() {
				anchored = cursor.ref.Number == canonical.NumberU64()+1
				break
			}
			parent := fhsCertifiedParent(s.fhsCertifiedByID, cursor)
			if parent == nil || parent.ref == nil || parent.qc == nil || parent.ref.Number <= canonical.NumberU64() {
				break
			}
			if parent.ref.Number+1 != cursor.ref.Number || parent.qc.Number >= cursor.qc.Number {
				return fmt.Errorf("invalid FHS certified ancestry")
			}
			cursor = parent
		}
		if !anchored {
			continue
		}
		if previous := views[record.qc.Number]; previous != nil && !hotstuff.SignedStateSemanticEqual(previous, record.qc) {
			return fmt.Errorf("conflicting FHS certificates at view %d", record.qc.Number)
		}
		views[record.qc.Number] = record.qc
		kept[id] = struct{}{}
		if frontier == nil || record.qc.Number > frontier.qc.Number {
			frontier = record
		}
	}
	s.fhsCertifiedByHash = make(map[common.Hash]*fhsCertifiedProposal)
	for id, record := range s.fhsCertifiedByID {
		if _, ok := kept[id]; ok {
			s.cacheFHSCertificateLocked(record)
			continue
		}
		delete(s.fhsCertifiedByID, id)
		if record != nil && record.ref != nil {
			s.deleteProposalBodyLocked(record.ref.ProposalID())
		}
	}
	s.fhsHighest = frontier
	if selected := s.fhsSelectedParent; selected != nil {
		if _, ok := kept[selected.ref.ProposalID()]; !ok {
			s.fhsSelectedParent, s.fhsParentSelected = nil, false
		}
	}
	return nil
}

func (s *Service) reconcileFHSCertifiedFrontier(canonical *types.Block) error {
	s.muProposalBody.Lock()
	defer s.muProposalBody.Unlock()
	return s.reconcileFHSCertifiedFrontierLocked(canonical)
}

func (s *Service) highestFHSCertifiedProposal() *core.VerifiedProposal {
	s.muProposalBody.RLock()
	defer s.muProposalBody.RUnlock()
	parent := s.fhsHighest
	if s.fhsParentSelected {
		parent = s.fhsSelectedParent
	}
	if parent == nil || (s.bc != nil && parent.ref.Number <= s.bc.CurrentBlockN()) {
		return nil
	}
	return parent.verified
}

func fhsProposalParentNumber(canonical uint64, highest *core.VerifiedProposal) uint64 {
	if highest != nil && highest.Block != nil && highest.Block.NumberU64() > canonical {
		return highest.Block.NumberU64()
	}
	return canonical
}

func (s *Service) getFHSCertifiedVerified(hash common.Hash) *core.VerifiedProposal {
	s.muProposalBody.RLock()
	defer s.muProposalBody.RUnlock()
	if certified := s.fhsCertifiedByHash[hash]; certified != nil {
		return certified.verified
	}
	return nil
}

// snapshotFHSCertifiedVerified is called by the serialized HotStuff loop when
// dispatching a worker. The private StateDB copy prevents a later 2-chain
// commit from consuming the mutable parent state while child validation is in
// flight. The receiving worker exclusively owns this snapshot and transfers its
// state to execution rather than making another copy.
func (s *Service) snapshotFHSCertifiedVerified(hash common.Hash) *core.VerifiedProposal {
	s.muProposalBody.RLock()
	defer s.muProposalBody.RUnlock()
	certified := s.fhsCertifiedByHash[hash]
	if certified == nil || certified.verified == nil {
		return nil
	}
	snapshot := *certified.verified
	if certified.verified.StateDB != nil {
		snapshot.StateDB = certified.verified.StateDB.Copy()
	}
	return &snapshot
}

func (s *Service) validateFHSProposalParent(ref *types.HotstuffProposalRef, parentQC *hotstuff.SignedState) error {
	if ref == nil {
		return fmt.Errorf("nil FHS proposal ref")
	}
	current := s.GetCurrentView()
	if ref.ParentHash != current.TxHash {
		return fmt.Errorf("FHS proposal does not extend selected execution parent")
	}
	selected := s.SelectedFHSProposalParent()
	if !hotstuff.SignedStateSemanticEqual(parentQC, selected) {
		return fmt.Errorf("FHS proposal parent differs from verified quorum selection")
	}
	if parentQC == nil {
		canonical := s.bc.CurrentBlock()
		if ref.ParentHash != canonical.Hash() || ref.Number != canonical.NumberU64()+1 {
			return fmt.Errorf("first FHS proposal must extend canonical head")
		}
		return nil
	}
	parentRef, err := types.DecodeHotstuffProposalRef(parentQC.State)
	if err != nil {
		return err
	}
	if parentRef.BlockHash != ref.ParentHash || ref.Number != parentRef.Number+1 || ref.ViewNumber <= parentRef.ViewNumber {
		return fmt.Errorf("FHS proposal does not directly extend its certified quorum parent")
	}
	return nil
}

func (s *Service) OnCertified(cert *hotstuff.SignedState) error {
	if s == nil {
		return types.ErrNotRunning
	}
	s.muLifecycle.Lock()
	if atomic.LoadInt32(&s.runningState) != 1 {
		s.muLifecycle.Unlock()
		return types.ErrNotRunning
	}
	generation := s.lifecycleGenerationLocked()

	// Async HighQC completion replays the authenticated QCBroadcast after Apply
	// has already installed and committed this exact QC. Keep that continuation
	// on the control loop small; it only advances the pacemaker/outbound NewView
	// and must not enter body retrieval or historical EVM execution again.
	if s.HasValidatedFHSCertificate(cert) {
		s.muLifecycle.Unlock()
		return s.finishFHSCertificationForGeneration(cert, generation)
	}
	// Replica path: the originating leader owns the durable dissemination
	// outbox. A receiver persists/adopts the QC, but must not claim it as a
	// locally replayable leader broadcast. Keep adoption inside the lifecycle
	// boundary so Backend.Stop cannot close its DB underneath the callback.
	if err := s.adoptFHSHighQC(cert, false, false); err != nil {
		s.muLifecycle.Unlock()
		return err
	}
	s.muLifecycle.Unlock()
	return s.finishFHSCertificationForGeneration(cert, generation)
}

func (s *Service) beginFHSQCBroadcast(cert *hotstuff.SignedState) error {
	return s.beginFHSQCBroadcastForGeneration(cert, 0)
}

func (s *Service) beginFHSQCBroadcastForGeneration(cert *hotstuff.SignedState, generation uint64) error {
	if s == nil || cert == nil {
		return fmt.Errorf("cannot begin an empty FHS certification broadcast")
	}
	s.muFHSQCBroadcast.Lock()
	defer s.muFHSQCBroadcast.Unlock()
	if s.fhsActiveQCBroadcast != nil {
		if !hotstuff.SignedStateSemanticEqual(s.fhsActiveQCBroadcast, cert) {
			return fmt.Errorf("another FHS certification broadcast is already active")
		}
		if s.fhsActiveQCBroadcastGeneration != generation {
			return fmt.Errorf("FHS certification broadcast belongs to another service generation")
		}
		return nil
	}
	// A direct protocol retry must not be blocked by the post-send replay
	// suppression marker. Only replayPendingFHSQCBroadcast consults that marker.
	s.fhsActiveQCBroadcast = hotstuff.CloneSignedState(cert)
	s.fhsActiveQCBroadcastGeneration = generation
	return nil
}

// abortFHSQCBroadcast clears an active attempt which did not achieve complete
// committee queue admission. It must not create a post-send suppression marker.
func (s *Service) abortFHSQCBroadcast(cert *hotstuff.SignedState) error {
	if s == nil || cert == nil {
		return fmt.Errorf("cannot abort an empty FHS certification broadcast")
	}
	s.muFHSQCBroadcast.Lock()
	defer s.muFHSQCBroadcast.Unlock()
	if s.fhsActiveQCBroadcast == nil {
		return nil
	}
	if !hotstuff.SignedStateSemanticEqual(s.fhsActiveQCBroadcast, cert) {
		return fmt.Errorf("FHS certification broadcast abort mismatch")
	}
	s.fhsActiveQCBroadcast = nil
	s.fhsActiveQCBroadcastGeneration = 0
	return nil
}

// completeFHSQCBroadcast records that the physical broadcast happened.
// The completed marker is a single bounded entry and is never persisted.
func (s *Service) completeFHSQCBroadcast(cert *hotstuff.SignedState, now time.Time) error {
	if s == nil || cert == nil {
		return fmt.Errorf("cannot complete an empty FHS certification broadcast")
	}
	s.muFHSQCBroadcast.Lock()
	defer s.muFHSQCBroadcast.Unlock()
	if s.fhsActiveQCBroadcast == nil {
		return fmt.Errorf("cannot complete an FHS certification broadcast that is not active")
	}
	if !hotstuff.SignedStateSemanticEqual(s.fhsActiveQCBroadcast, cert) {
		return fmt.Errorf("FHS certification broadcast completion mismatch")
	}
	s.fhsActiveQCBroadcast = nil
	s.fhsActiveQCBroadcastGeneration = 0
	s.fhsCompletedQCBroadcast = hotstuff.CloneSignedState(cert)
	s.fhsCompletedQCBroadcastExpiry = now.Add(fhsQCBroadcastReplaySuppressionWindow)
	return nil
}

func (s *Service) fhsQCBroadcastReplaySuppressed(cert *hotstuff.SignedState, now time.Time) bool {
	if s == nil || cert == nil {
		return false
	}
	s.muFHSQCBroadcast.Lock()
	defer s.muFHSQCBroadcast.Unlock()
	if hotstuff.SignedStateSemanticEqual(s.fhsActiveQCBroadcast, cert) {
		return true
	}
	if s.fhsCompletedQCBroadcast == nil {
		return false
	}
	if !now.Before(s.fhsCompletedQCBroadcastExpiry) {
		s.fhsCompletedQCBroadcast = nil
		s.fhsCompletedQCBroadcastExpiry = time.Time{}
		return false
	}
	return hotstuff.SignedStateSemanticEqual(s.fhsCompletedQCBroadcast, cert)
}

func (s *Service) fhsQCBroadcastActive(cert *hotstuff.SignedState) bool {
	_, active := s.fhsQCBroadcastActiveGeneration(cert)
	return active
}

func (s *Service) fhsQCBroadcastActiveGeneration(cert *hotstuff.SignedState) (uint64, bool) {
	if s == nil || cert == nil {
		return 0, false
	}
	s.muFHSQCBroadcast.Lock()
	defer s.muFHSQCBroadcast.Unlock()
	if !hotstuff.SignedStateSemanticEqual(s.fhsActiveQCBroadcast, cert) {
		return 0, false
	}
	return s.fhsActiveQCBroadcastGeneration, true
}

func (s *Service) clearFHSQCBroadcastMarkers() {
	if s == nil {
		return
	}
	s.muFHSQCBroadcast.Lock()
	s.fhsActiveQCBroadcast = nil
	s.fhsActiveQCBroadcastGeneration = 0
	s.fhsCompletedQCBroadcast = nil
	s.fhsCompletedQCBroadcastExpiry = time.Time{}
	s.muFHSQCBroadcast.Unlock()
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

func (s *Service) OnFHSLeaderCertifiedBeforeBroadcast(cert *hotstuff.SignedState) (err error) {
	if s == nil {
		return fmt.Errorf("cannot begin an FHS certification broadcast on a nil service")
	}
	s.muLifecycle.Lock()
	defer s.muLifecycle.Unlock()
	if atomic.LoadInt32(&s.runningState) != 1 {
		return types.ErrNotRunning
	}
	generation := s.lifecycleGenerationLocked()
	if err := s.beginFHSQCBroadcastForGeneration(cert, generation); err != nil {
		return err
	}
	ready := false
	defer func() {
		if !ready {
			if cleanupErr := s.abortFHSQCBroadcast(cert); cleanupErr != nil {
				log.Error("failed to clear aborted FHS certification broadcast", "number", cert.Number, "err", cleanupErr)
			}
		}
	}()
	if err := s.adoptFHSHighQC(cert, false, true); err != nil {
		return err
	}
	if err := s.refreshFHSCertifiedCommitteePeerAuthorization(); err != nil {
		return err
	}
	activeGeneration, active := s.fhsQCBroadcastActiveGeneration(cert)
	generationCurrent := s.lifecycleGenerationActiveLocked(generation) && active && activeGeneration == generation
	if !generationCurrent {
		return types.ErrNotRunning
	}
	ready = true
	return nil
}

func (s *Service) OnFHSLeaderCertifiedAfterBroadcast(cert *hotstuff.SignedState, broadcastSucceeded bool) (err error) {
	// Before has bracketed this physical send attempt, including retries. Mark
	// a successful queue admission completed even when canonical adoption below
	// fails. If any committee delivery was rejected, clear the active marker
	// before finishing so sendNewViewMsg can immediately replay the durable outbox.
	// Calling After without a successful Before is rejected rather than pretending
	// that a send occurred.
	generation, active := s.fhsQCBroadcastActiveGeneration(cert)
	if !active || generation == 0 {
		return fmt.Errorf("cannot complete an FHS certification broadcast that is not active")
	}
	if !s.lifecycleGenerationActive(generation) {
		return types.ErrNotRunning
	}
	if !broadcastSucceeded {
		if err := s.abortFHSQCBroadcast(cert); err != nil {
			return err
		}
		return s.finishFHSCertificationForGeneration(cert, generation)
	}
	defer func() {
		if cleanupErr := s.completeFHSQCBroadcast(cert, time.Now()); cleanupErr != nil {
			if err == nil {
				err = cleanupErr
			} else {
				log.Error("failed to clear completed FHS certification broadcast", "number", cert.Number, "err", cleanupErr)
			}
		}
	}()
	return s.finishFHSCertificationForGeneration(cert, generation)
}

func (s *Service) finishFHSCertification(cert *hotstuff.SignedState) error {
	if s == nil {
		return types.ErrNotRunning
	}
	s.muLifecycle.Lock()
	if atomic.LoadInt32(&s.runningState) != 1 {
		s.muLifecycle.Unlock()
		return types.ErrNotRunning
	}
	generation := s.lifecycleGenerationLocked()
	s.muLifecycle.Unlock()
	return s.finishFHSCertificationForGeneration(cert, generation)
}

func (s *Service) finishFHSCertificationState(cert *hotstuff.SignedState) error {
	if err := s.refreshFHSCertifiedCommitteePeerAuthorization(); err != nil {
		return fmt.Errorf("authorize certified FHS committee handoff peers: %w", err)
	}
	if err := s.commitFHS2ChainForCertified(cert); err != nil {
		return err
	}
	return nil
}

func (s *Service) finishFHSCertificationForGeneration(cert *hotstuff.SignedState, generation uint64) error {
	var (
		pendingReplay *hotstuff.SignedState
		replayMessage *hotstuff.HotstuffMessage
		replayErr     error
	)

	// Keep every local persistence and activation step inside the MinerStop
	// boundary. Preparing a durable replay can read the safety DB, so it belongs
	// here too; only the already-built network message is sent after unlocking.
	s.muLifecycle.Lock()
	if !s.lifecycleGenerationActiveLocked(generation) {
		s.muLifecycle.Unlock()
		return types.ErrNotRunning
	}
	if err := s.finishFHSCertificationState(cert); err != nil {
		s.muLifecycle.Unlock()
		return err
	}
	// Canonical insertion invokes ProcInsertDone synchronously. Reconciliation
	// may stop this service without taking muLifecycle, so fail closed before
	// rearming the pacemaker even though the outer lifecycle lock is still held.
	if !s.lifecycleGenerationActiveLocked(generation) {
		s.muLifecycle.Unlock()
		return types.ErrNotRunning
	}
	_ = s.pacetMakerTimer.start()
	if s.fairHotstuffEnabled() && !s.hasDeferredFHSRecovery() {
		pendingReplay, replayMessage, replayErr = s.preparePendingFHSQCBroadcastReplay()
	}
	s.muLifecycle.Unlock()

	// A physical send may wait on bounded transport backpressure. Do not make
	// MinerStop wait for it. No database or consensus state is touched here.
	if replayErr != nil {
		log.Error("cannot replay durable FHS QC broadcast", "err", replayErr)
	} else {
		s.broadcastPreparedFHSQCBroadcast(pendingReplay, replayMessage)
	}

	// Stop, or a Stop/Start pair, may have happened while the prepared message
	// was sent. Revalidate the exact generation before admitting NewView.
	s.muLifecycle.Lock()
	defer s.muLifecycle.Unlock()
	if !s.lifecycleGenerationActiveLocked(generation) {
		return types.ErrNotRunning
	}
	s.sendNewViewMsgAfterReplay(cert.Number)
	return nil
}

func (s *Service) needsFHSFinalityBlock() bool {
	if !s.fairHotstuffEnabled() {
		return false
	}
	currentKeyHash := common.Hash{}
	if currentKey := s.kbc.CurrentBlock(); currentKey != nil {
		currentKeyHash = currentKey.Hash()
	}
	s.muProposalBody.RLock()
	defer s.muProposalBody.RUnlock()
	return fhsNeedsFinalityBlock(s.fhsExecutionBranchLocked(), currentKeyHash, s.isCanonicalFHSBlock)
}

// fhsNeedsFinalityBlock reports whether the certified frontier still needs a
// child proposal before it can reach 2-chain finality. An empty transaction
// block normally does not justify producing another empty block. The exception
// is an empty block certified under the previous key epoch: after its parent
// key block commits, one child under the new key is required to finish the
// handoff. Once that child is certified, its KeyHash matches currentKeyHash and
// the empty chain stops growing.
func fhsNeedsFinalityBlock(certifiedByHash map[common.Hash]*fhsCertifiedProposal, currentKeyHash common.Hash, isCommitted func(*types.Block) bool) bool {
	for _, certified := range certifiedByHash {
		if certified == nil || certified.verified == nil || certified.verified.Block == nil {
			continue
		}
		block := certified.verified.Block
		if isCommitted != nil && isCommitted(block) {
			continue
		}
		if block.BlockType() == types.Key_Block || len(block.Transactions()) > 0 || block.KeyHash() != currentKeyHash {
			return true
		}
	}
	return false
}

func (s *Service) isCanonicalFHSBlock(block *types.Block) bool {
	if block == nil {
		return false
	}
	hash := block.Hash()
	number := block.NumberU64()
	return s.bc.GetCanonicalHash(number) == hash && s.bc.HasBlockAndState(hash, number)
}

func fhsHasUncommittedKeyBlock(certifiedByHash map[common.Hash]*fhsCertifiedProposal, isCommitted func(*types.Block) bool) bool {
	return fhsHasConflictingUncommittedKeyBlock(certifiedByHash, nil, isCommitted)
}

func fhsHasConflictingUncommittedKeyBlock(certifiedByHash map[common.Hash]*fhsCertifiedProposal, candidate *types.Block, isCommitted func(*types.Block) bool) bool {
	for _, certified := range certifiedByHash {
		if certified == nil || certified.verified == nil || certified.verified.Block == nil {
			continue
		}
		block := certified.verified.Block
		if block.BlockType() == types.Key_Block && !isCommitted(block) && (candidate == nil || candidate.Hash() != block.Hash()) {
			return true
		}
	}
	return false
}

func (s *Service) hasConflictingUncommittedFHSKeyBlock(candidate *types.Block) bool {
	if !s.fairHotstuffEnabled() || candidate == nil || candidate.BlockType() != types.Key_Block {
		return false
	}
	s.muProposalBody.RLock()
	defer s.muProposalBody.RUnlock()
	return fhsHasConflictingUncommittedKeyBlock(s.fhsExecutionBranchLocked(), candidate, s.isCanonicalFHSBlock)
}

// hasUncommittedFHSKeyBlock reports whether the certified pipeline already
// contains a key-block transition which has not reached 2-chain finality yet.
// Building another key block on the still-canonical key head would create a
// competing key block at the same height and make historical QC verification
// depend on which sibling happened to be installed last.
func (s *Service) hasUncommittedFHSKeyBlock() bool {
	if !s.fairHotstuffEnabled() {
		return false
	}
	s.muProposalBody.RLock()
	defer s.muProposalBody.RUnlock()
	return fhsHasUncommittedKeyBlock(s.fhsExecutionBranchLocked(), s.isCanonicalFHSBlock)
}

func fhs2ChainCommitTarget(certificates map[common.Hash]*fhsCertifiedProposal, tip *fhsCertifiedProposal) *fhsCertifiedProposal {
	if tip == nil || tip.ref == nil || tip.qc == nil {
		return nil
	}
	parent := fhsCertifiedParent(certificates, tip)
	if parent == nil || parent.ref == nil || parent.qc == nil || parent.ref.BlockHash != tip.ref.ParentHash {
		return nil
	}
	if tip.ref.Number != parent.ref.Number+1 || tip.qc.Number <= parent.qc.Number || tip.qc.Number-parent.qc.Number != 1 {
		return nil
	}
	return parent
}

// preflightFHSCommitStep validates one independently finalizable parent/child
// pair before any epoch-local WAL or pacemaker state is changed. Callers run it
// immediately before each sequential commit so a preceding key carrier can
// advance the effective key head for the next step in a recovered prefix.
func (s *Service) preflightFHSCommitStep(target *fhsCertifiedProposal, proof *core.FHSCommitProof) (*types.KeyBlock, error) {
	if target == nil || target.ref == nil || target.verified == nil || target.verified.Block == nil || proof == nil || len(proof.QCs) == 0 {
		return nil, fmt.Errorf("incomplete FHS 2-chain commit proof")
	}
	block := target.verified.Block
	if err := s.bc.VerifyFHSCommitProof(block, proof); err != nil {
		return nil, fmt.Errorf("invalid Fair HotStuff 2-chain commit proof: %w", err)
	}
	if block.BlockType() != types.Key_Block {
		return nil, nil
	}
	keyBlock := types.DecodeToKeyBlock(block.KeyInfo())
	if keyBlock == nil || block.NumberU64() == 0 {
		return nil, fmt.Errorf("invalid FHS key-block transition %s", target.ref.BlockHash)
	}
	if block.KeyHash() != keyBlock.ParentHash() {
		return nil, fmt.Errorf("FHS key-block carrier key hash mismatch: block=%s keyHash=%s keyParent=%s", block.Hash(), block.KeyHash(), keyBlock.ParentHash())
	}
	if err := verifyKeyBlockCarrierParent(keyBlock, block.NumberU64()-1); err != nil {
		return nil, fmt.Errorf("invalid FHS key-block carrier: %w", err)
	}
	currentKey := s.kbc.CurrentBlock()
	if currentKey != nil && currentKey.Hash() == keyBlock.Hash() {
		// A proof-aware sync/import may have atomically committed this exact
		// carrier after the service built its certified-prefix snapshot. Treat
		// the transition as idempotent only when the transaction target is also
		// the exact canonical block; a key-only match is not sufficient.
		if s.bc.GetCanonicalHash(block.NumberU64()) != block.Hash() || !s.bc.HasBlockAndState(block.Hash(), block.NumberU64()) {
			return nil, fmt.Errorf("FHS key transition is current without its canonical carrier: key=%s carrier=%s", keyBlock.Hash(), block.Hash())
		}
	} else if err := s.kbc.ValidateKeyBlockForCanonicalInsert(keyBlock); err != nil {
		return nil, fmt.Errorf("invalid FHS canonical key transition: %w", err)
	}
	return keyBlock, nil
}

func (s *Service) commitFHS2ChainForCertified(qc *hotstuff.SignedState) error {
	if qc == nil {
		return fmt.Errorf("nil certified FHS state")
	}
	ref, err := types.DecodeHotstuffProposalRef(qc.State)
	if err != nil {
		return err
	}
	s.muProposalBody.RLock()
	tip := s.fhsCertifiedByID[ref.ProposalID()]
	target := fhs2ChainCommitTarget(s.fhsCertifiedByID, tip)
	if target == nil {
		s.muProposalBody.RUnlock()
		return nil
	}

	type commitStep struct {
		target *fhsCertifiedProposal
		proof  *core.FHSCommitProof
	}
	currentHash := s.bc.CurrentBlock().Hash()
	chain := make([]commitStep, 0, 2)
	path := []*hotstuff.SignedState{tip.qc}
	for cursor := target; cursor != nil && cursor.ref.BlockHash != currentHash; cursor = fhsCertifiedParent(s.fhsCertifiedByID, cursor) {
		chain = append(chain, commitStep{target: cursor, proof: &core.FHSCommitProof{QCs: append([]*hotstuff.SignedState(nil), path...)}})
		if cursor.ref.ParentHash == currentHash {
			break
		}
		if fhsCertifiedParent(s.fhsCertifiedByID, cursor) == nil {
			s.muProposalBody.RUnlock()
			return fmt.Errorf("FHS commit prefix missing certified ancestor %s", cursor.ref.ParentHash)
		}
		path = append([]*hotstuff.SignedState{cursor.qc}, path...)
	}
	s.muProposalBody.RUnlock()

	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	for _, step := range chain {
		certified := step.target
		keyBlock, err := s.preflightFHSCommitStep(certified, step.proof)
		if err != nil {
			return err
		}
		if keyBlock != nil {
			if err := s.rotateFHSEpochSafety(keyBlock.Hash()); err != nil {
				return fmt.Errorf("rotate FHS epoch safety before key-block commit: %w", err)
			}
			// The timeout proof was committee-specific and has just been rotated
			// out of WAL. Normalize immediately, even if the canonical DB write
			// below transiently fails, so replicas do not retain different local
			// old-epoch TC heights while retrying the same common proof.
			if err := s.normalizeFHSEpochView(qc, s.kbc.CurrentBlock()); err != nil {
				return fmt.Errorf("prepare FHS epoch view normalization: %w", err)
			}
		}
		if err := s.txService.decideFHSVerifiedProposal(certified.ref, certified.verified, certified.qc, step.proof); err != nil {
			return err
		}
		if keyBlock != nil {
			// The key head and committee are now canonical. Apply the same QC base
			// to that exact new key context before any later commit step can fail.
			if err := s.normalizeFHSEpochView(qc, s.kbc.CurrentBlock()); err != nil {
				return fmt.Errorf("complete FHS epoch view normalization: %w", err)
			}
		}
		proposalID := certified.ref.ProposalID()
		s.muProposalBody.Lock()
		delete(s.fhsCertifiedByHash, certified.ref.BlockHash)
		delete(s.fhsCertifiedByID, proposalID)
		s.deleteProposalBodyLocked(proposalID)
		s.muProposalBody.Unlock()
		log.Info("FHS 2-CHAIN COMMIT",
			"number", certified.ref.Number,
			"view", certified.qc.Number,
			"hash", certified.ref.BlockHash,
			"trigger", tip.ref.BlockHash,
			"triggerView", tip.qc.Number)
	}
	canonical := s.bc.CurrentBlock()
	if err := s.reconcileFHSCertifiedFrontier(canonical); err != nil {
		return err
	}
	s.muProposalBody.RLock()
	parent := s.fhsHighest
	if s.fhsParentSelected {
		parent = s.fhsSelectedParent
	}
	s.muProposalBody.RUnlock()
	return s.publishFHSExecutionParent(parent, canonical)
}

// normalizeFHSEpochView gives every replica the same numeric pacemaker base
// after a key epoch transition. A replica may have observed a valid higher TC
// from the old epoch while another replica missed it; retaining those local
// maxima would split their NewView target numbers. The child QC that finalized
// the transition is common proof, so its view is the deterministic new base.
// LastVote remains durable and still rejects a conflicting same-view proposal;
// replicas with a higher old-epoch vote advance together through new-epoch TCs.
func (s *Service) normalizeFHSEpochView(qc *hotstuff.SignedState, keyBlock *types.KeyBlock) error {
	if qc == nil || keyBlock == nil {
		return fmt.Errorf("missing FHS epoch normalization proof")
	}
	ref, err := types.DecodeHotstuffProposalRef(qc.State)
	if err != nil {
		return err
	}
	if ref.ChainID != s.ChainID() || ref.ViewNumber != qc.Number || ref.ViewID != qc.ViewID || ref.LeaderID != qc.LeaderID {
		return fmt.Errorf("FHS epoch normalization QC context mismatch")
	}
	s.muCurrentView.Lock()
	s.currentView.TxNumber = ref.Number
	s.currentView.TxHash = ref.BlockHash
	s.currentView.KeyNumber = keyBlock.NumberU64()
	s.currentView.KeyHash = keyBlock.Hash()
	s.currentView.CommitteeHash = keyBlock.CommitteeHash()
	s.currentView.ViewNumber = qc.Number
	s.currentView.Round = 0
	s.currentView.NoDone = true
	s.currentView.LeaderIndex = s.fairHotstuffLeaderIndexForCurrentLocked()
	s.waittingView.TxNumber = ref.Number
	s.waittingView.KeyNumber = keyBlock.NumberU64()
	s.muCurrentView.Unlock()
	if s.protocolMng != nil {
		s.protocolMng.ScheduleFHSEpochReset()
	}
	return nil
}

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

func (s *Service) stageHotstuffProposal(viewNumber uint64, viewID common.Hash, leaderID string, encodedBlock, extra []byte, parentQC *hotstuff.SignedState) (*stagedHotstuffProposal, error) {
	if len(encodedBlock) == 0 {
		return nil, fmt.Errorf("empty encoded block proposal")
	}
	bodyLimit := proposalBodyLimitForConfig(s.chainConfig)
	if len(encodedBlock) > bodyLimit {
		return nil, fmt.Errorf("encoded block proposal too large: bytes=%d limit=%d", len(encodedBlock), bodyLimit)
	}
	block := types.DecodeToBlock(encodedBlock)
	if block == nil {
		return nil, fmt.Errorf("failed to decode encoded block proposal")
	}
	if s.fairHotstuffEnabled() {
		current := s.GetCurrentView()
		if viewNumber != current.ViewNumber+1 {
			return nil, fmt.Errorf("FHS proposal view mismatch: have %d want %d", viewNumber, current.ViewNumber+1)
		}
		if block.ParentHash() != current.TxHash {
			return nil, fmt.Errorf("FHS proposal does not extend highest certified block: parent=%s highest=%s", block.ParentHash(), current.TxHash)
		}
	}
	var parentQCID common.Hash
	if parentQC != nil {
		id, err := hotstuff.SignedStateID(parentQC)
		if err != nil {
			return nil, err
		}
		parentQCID = id.Hash()
	}
	encodedParentQC, err := hotstuff.EncodeSignedState(parentQC)
	if err != nil {
		return nil, err
	}
	ref, err := types.NewHotstuffProposalRefWithProof(s.ChainID(), viewNumber, viewID, leaderID, block, encodedBlock, extra, parentQCID)
	if err != nil {
		return nil, err
	}
	proposalID := ref.ProposalID()
	body := &proposalBodyMsg{
		Type:               proposalBodyMsgManifest,
		ProposalID:         proposalID,
		BodyHash:           ref.BodyHash,
		BodySize:           ref.BodySize,
		Number:             ref.Number,
		ViewNumber:         ref.ViewNumber,
		ViewID:             ref.ViewID,
		LeaderID:           ref.LeaderID,
		From:               s.Self(),
		ProposalKeyHash:    ref.KeyHash,
		EncodedBlock:       encodedBlock,
		Extra:              append([]byte(nil), extra...),
		ParentQC:           encodedParentQC,
		KeyActivationProof: s.canonicalFHSKeyActivationProof(ref.KeyHash),
		CreatedAtUnixNano:  time.Now().UnixNano(),
	}
	manifest, err := encodeProposalDataManifestForConfig(s.chainConfig, block)
	if err != nil {
		return nil, err
	}
	refBytes := ref.EncodeToBytes()
	if len(refBytes) == 0 {
		return nil, fmt.Errorf("failed to encode hotstuff proposal ref")
	}
	log.Info("HOTSTUFF PROPOSAL REF",
		"number", ref.Number,
		"viewID", ref.ViewID,
		"proposalID", proposalID,
		"blockHash", ref.BlockHash,
		"bodyHash", ref.BodyHash,
		"bodySize", ref.BodySize,
		"refBytes", len(refBytes))
	wireBody := cloneProposalBodyEnvelope(body)
	wireBody.Type = proposalBodyMsgManifest
	wireBody.From = s.Self()
	wireBody.Manifest = append([]byte(nil), manifest...)
	if err := s.sealProposalBody(wireBody); err != nil {
		return nil, fmt.Errorf("sign proposal manifest: %w", err)
	}
	// Attach the relayable leader proof before caching and queuing durable
	// content, so a donor that retains this body can serve the same proof after
	// its original leader becomes unavailable, including after a donor restart.
	body.ManifestAuthSig = append([]byte(nil), wireBody.ManifestAuthSig...)
	if err := s.storeProposalBody(body); err != nil {
		return nil, err
	}
	_, committee, _, err := s.resolveExactFHSCommittee(ref.KeyHash, true)
	if err != nil || committee == nil || len(committee.List) == 0 {
		return nil, fmt.Errorf("proposal committee unavailable %s: %w", ref.KeyHash, err)
	}
	destinations := make([]string, 0, len(committee.List)-1)
	for _, node := range committee.List {
		if node == nil || node.Address == "" || IsSelf(node.Address) {
			continue
		}
		destinations = append(destinations, node.Address)
	}
	return &stagedHotstuffProposal{
		proposalRef:  refBytes,
		body:         body,
		manifest:     wireBody,
		destinations: destinations,
	}, nil
}

func (s *Service) prepareHotstuffProposal(viewNumber uint64, viewID common.Hash, leaderID string, encodedBlock, extra []byte) ([]byte, error) {
	staged, err := s.stageHotstuffProposal(viewNumber, viewID, leaderID, encodedBlock, extra, s.SelectedFHSProposalParent())
	if err != nil {
		return nil, err
	}
	s.broadcastProposalManifestToCommittee(staged.body, staged.manifest.Manifest)
	return staged.proposalRef, nil
}

func (s *Service) broadcastProposalManifestToCommittee(body *proposalBodyMsg, manifest []byte) {
	if body == nil {
		return
	}
	_, mb, _, err := s.resolveExactFHSCommittee(body.ProposalKeyHash, true)
	if err != nil || mb == nil {
		log.Warn("HOTSTUFF PROPOSAL BODY broadcast skipped; missing committee", "number", body.Number, "proposalID", body.ProposalID, "err", err)
		return
	}
	wireBody := cloneProposalBodyEnvelope(body)
	if wireBody != nil {
		wireBody.Type = proposalBodyMsgManifest
		wireBody.From = s.Self()
		wireBody.Manifest = append([]byte(nil), manifest...)
	}
	if err := s.sealProposalBody(wireBody); err != nil {
		log.Warn("HOTSTUFF PROPOSAL BODY signing failed", "number", body.Number, "err", err)
		return
	}
	for _, node := range mb.List {
		if node == nil || node.Address == "" || IsSelf(node.Address) {
			continue
		}
		log.Info("HOTSTUFF PROPOSAL MANIFEST SEND",
			"to", node.Address,
			"number", body.Number,
			"proposalID", body.ProposalID,
			"bodyHash", body.BodyHash,
			"manifestBytes", len(wireBody.Manifest),
			"bodyBytes", body.BodySize)
		if err := s.netService.SendRawData(node.Address, &networkMsg{Pmsg: wireBody}); err != nil {
			log.Warn("HOTSTUFF PROPOSAL BODY send failed", "to", node.Address, "number", body.Number, "proposalID", body.ProposalID, "err", err)
		}
	}
}

func (s *Service) proposalRepairTarget(ref *types.HotstuffProposalRef, attempt uint64) *common.Cnode {
	if s == nil || s.kbc == nil || ref == nil || ref.KeyHash == (common.Hash{}) {
		return nil
	}
	// Repair follows the committee generation committed by the certified
	// proposal, not the receiver's current committee. A catch-up chain may cross
	// a key-block transition before the local application publishes that view.
	_, mb, _, err := s.resolveExactFHSCommittee(ref.KeyHash, true)
	if err != nil || mb == nil || len(mb.List) == 0 {
		return nil
	}
	if attempt == 0 {
		if leader, _ := mb.Get(ref.LeaderID, bftview.ID); leader != nil && leader.Address != "" && !IsSelf(leader.Address) {
			return leader
		}
	}
	proposalID := ref.ProposalID()
	seed := binary.BigEndian.Uint64(proposalID[:8]) + attempt
	committeeSize := uint64(len(mb.List))
	base := seed % committeeSize
	for offset := 0; offset < len(mb.List); offset++ {
		index := int((base + uint64(offset)) % committeeSize)
		node := mb.List[index]
		if node != nil && node.Address != "" && !IsSelf(node.Address) {
			return node
		}
	}
	return nil
}

// proposalRepairRequestTracker keeps one waiter's outstanding repair requests
// disjoint until every currently missing transaction has been covered. Only
// then does it begin another pass, so a delayed response cannot pin retries to
// the first proposalRepairMaxHashes entries forever.
type proposalRepairRequestTracker struct {
	requested                map[common.Hash]struct{}
	outstanding              [][]common.Hash
	assemblyState            *proposalAssemblyState
	assemblyRequested        map[common.Hash][]common.Hash
	assemblyResolutionCursor int
	retry                    []common.Hash
	cursor                   int
}

// releaseAnsweredWindows makes the unreturned part of a byte-capped response
// immediately requestable again. A donor sends at most one response per request;
// observing that any hash in an outstanding window is no longer missing therefore
// proves that the response for that window arrived. Without this step a 1 MiB
// response to a 1024-hash request can strand the remaining hashes until the
// tracker has walked the entire manifest.
func (tracker *proposalRepairRequestTracker) releaseAnsweredWindows(missing []common.Hash) {
	if tracker == nil || len(tracker.outstanding) == 0 {
		return
	}
	stillMissing := make(map[common.Hash]struct{}, len(missing))
	for _, hash := range missing {
		stillMissing[hash] = struct{}{}
	}
	retained := tracker.outstanding[:0]
	for _, window := range tracker.outstanding {
		answered := false
		for _, hash := range window {
			if _, present := stillMissing[hash]; !present {
				answered = true
				break
			}
		}
		if !answered {
			retained = append(retained, window)
			continue
		}
		for _, hash := range window {
			delete(tracker.requested, hash)
		}
	}
	for index := len(retained); index < len(tracker.outstanding); index++ {
		tracker.outstanding[index] = nil
	}
	tracker.outstanding = retained
}

func (tracker *proposalRepairRequestTracker) nextWindow(missing []common.Hash) []common.Hash {
	if len(missing) == 0 {
		return nil
	}
	if tracker.requested == nil {
		tracker.requested = make(map[common.Hash]struct{}, len(missing))
	}
	tracker.releaseAnsweredWindows(missing)
	windowCapacity := len(missing)
	if windowCapacity > proposalRepairMaxHashes {
		windowCapacity = proposalRepairMaxHashes
	}
	next := make([]common.Hash, 0, windowCapacity)
	appendUnrequested := func() {
		for _, hash := range missing {
			if _, requested := tracker.requested[hash]; requested {
				continue
			}
			tracker.requested[hash] = struct{}{}
			next = append(next, hash)
			if len(next) == proposalRepairMaxHashes {
				return
			}
		}
	}
	appendUnrequested()
	if len(next) == 0 {
		clear(tracker.requested)
		tracker.outstanding = nil
		appendUnrequested()
	}
	if len(next) > 0 {
		tracker.outstanding = append(tracker.outstanding, append([]common.Hash(nil), next...))
	}
	return next
}

func proposalAssemblyHashMissing(state *proposalAssemblyState, hash common.Hash) bool {
	if state == nil {
		return false
	}
	position, ok := state.positions[hash]
	return ok && state.transactions[position] == nil
}

func (tracker *proposalRepairRequestTracker) releaseResolvedAssemblyWindows(state *proposalAssemblyState) {
	if tracker == nil || state == nil || tracker.assemblyResolutionCursor >= len(state.resolved) {
		return
	}
	for _, resolved := range state.resolved[tracker.assemblyResolutionCursor:] {
		window := tracker.assemblyRequested[resolved]
		if len(window) == 0 {
			continue
		}
		for _, hash := range window {
			delete(tracker.assemblyRequested, hash)
			if proposalAssemblyHashMissing(state, hash) {
				tracker.retry = append(tracker.retry, hash)
			}
		}
	}
	tracker.assemblyResolutionCursor = len(state.resolved)
}

// nextAssemblyWindow walks the immutable manifest order with a cursor. Unlike
// nextWindow's compatibility slice API, it neither materializes the complete
// missing set nor rescans from index zero for every repair request.
func (tracker *proposalRepairRequestTracker) nextAssemblyWindow(state *proposalAssemblyState) []common.Hash {
	if tracker == nil || state == nil || state.manifest == nil || state.missingCount == 0 {
		return nil
	}
	if tracker.assemblyState != state {
		tracker.assemblyState = state
		tracker.assemblyRequested = nil
		tracker.assemblyResolutionCursor = len(state.resolved)
		tracker.retry = nil
		tracker.cursor = 0
	}
	if tracker.assemblyRequested == nil {
		tracker.assemblyRequested = make(map[common.Hash][]common.Hash)
	}
	tracker.releaseResolvedAssemblyWindows(state)
	next := make([]common.Hash, 0, proposalRepairMaxHashes)
	appendHash := func(hash common.Hash) {
		if len(next) == proposalRepairMaxHashes || !proposalAssemblyHashMissing(state, hash) {
			return
		}
		if _, requested := tracker.assemblyRequested[hash]; requested {
			return
		}
		next = append(next, hash)
	}
	for len(tracker.retry) > 0 && len(next) < proposalRepairMaxHashes {
		hash := tracker.retry[0]
		tracker.retry[0] = common.Hash{}
		tracker.retry = tracker.retry[1:]
		appendHash(hash)
	}
	for tracker.cursor < len(state.manifest.TransactionHashes) && len(next) < proposalRepairMaxHashes {
		hash := state.manifest.TransactionHashes[tracker.cursor]
		tracker.cursor++
		appendHash(hash)
	}
	if len(next) == 0 {
		// Every missing hash is either in-flight or the first pass has ended.
		// Start a bounded retry pass; delayed responses remain safe because
		// repair data is idempotently installed by manifest position.
		clear(tracker.assemblyRequested)
		tracker.retry = nil
		tracker.cursor = 0
		for tracker.cursor < len(state.manifest.TransactionHashes) && len(next) < proposalRepairMaxHashes {
			hash := state.manifest.TransactionHashes[tracker.cursor]
			tracker.cursor++
			appendHash(hash)
		}
	}
	if len(next) > 0 {
		window := append([]common.Hash(nil), next...)
		for _, hash := range window {
			tracker.assemblyRequested[hash] = window
		}
	}
	return next
}

func (s *Service) nextProposalRepairWindow(proposalID common.Hash, tracker *proposalRepairRequestTracker) []common.Hash {
	s.muProposalBody.RLock()
	window := tracker.nextAssemblyWindow(s.proposalAssemblies[proposalID])
	s.muProposalBody.RUnlock()
	return window
}

func proposalRepairRequestBurstForConfig(config *params.ChainConfig) uint64 {
	if config != nil && config.NativeParallelEnabled() {
		return proposalRepairNativeRequestBurst
	}
	return 1
}

func (s *Service) sendProposalRepairRequest(ref *types.HotstuffProposalRef, missing []common.Hash, attempt uint64) {
	if ref == nil {
		return
	}
	if len(missing) > proposalRepairMaxHashes {
		missing = missing[:proposalRepairMaxHashes]
	}
	req := &proposalBodyMsg{
		Type:              proposalBodyMsgRepairRequest,
		ProposalID:        ref.ProposalID(),
		BodyHash:          ref.BodyHash,
		BodySize:          ref.BodySize,
		Number:            ref.Number,
		ViewNumber:        ref.ViewNumber,
		ViewID:            ref.ViewID,
		LeaderID:          ref.LeaderID,
		From:              s.Self(),
		ProposalKeyHash:   ref.KeyHash,
		MissingTxHashes:   append([]common.Hash(nil), missing...),
		CreatedAtUnixNano: time.Now().UnixNano(),
	}
	if err := s.sealProposalBody(req); err != nil {
		log.Warn("HOTSTUFF PROPOSAL BODY REQUEST signing failed", "number", ref.Number, "err", err)
		return
	}

	node := s.proposalRepairTarget(ref, attempt)
	if node == nil {
		return
	}
	log.Info("HOTSTUFF PROPOSAL REPAIR REQUEST",
		"to", node.Address,
		"number", ref.Number,
		"proposalID", req.ProposalID,
		"missing", len(req.MissingTxHashes),
		"attempt", attempt)
	if err := s.netService.SendRawData(node.Address, &networkMsg{Pmsg: req}); err != nil {
		log.Warn("HOTSTUFF PROPOSAL REPAIR request failed", "to", node.Address, "number", ref.Number, "proposalID", req.ProposalID, "err", err)
	}
}

func (s *Service) waitProposalBody(ref *types.HotstuffProposalRef) (*proposalBodyMsg, error) {
	return s.waitProposalBodyForValidation(context.Background(), ref, 0)
}

func (s *Service) waitProposalBodyForGeneration(ref *types.HotstuffProposalRef, generation uint64) (*proposalBodyMsg, error) {
	return s.waitProposalBodyForValidation(context.Background(), ref, generation)
}

func (s *Service) waitProposalBodyForValidation(ctx context.Context, ref *types.HotstuffProposalRef, serviceGeneration uint64) (*proposalBodyMsg, error) {
	if ref == nil {
		return nil, fmt.Errorf("nil proposal ref")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	proposalID := ref.ProposalID()
	start := time.Now()
	// Once a proposal reference has been accepted for the current view, its
	// size-derived body/repair deadline is immutable. A keyblock interval may
	// influence selection of the next view, but must not truncate an in-flight
	// 256 MiB proposal to one second and make a valid block untransportable.
	deadline := start.Add(proposalBodyWaitTimeoutForConfig(s.chainConfig, ref.BodySize))
	nextRequestAt := time.Now().Add(proposalBodyRequestAfter)
	var requestAttempt uint64
	var repairStartedAt time.Time
	var repairRequests proposalRepairRequestTracker
	var checkedDurable bool
	for {
		if err := ctx.Err(); err != nil {
			return nil, hotstuff.ErrOldState
		}
		if serviceGeneration != 0 && (atomic.LoadInt32(&s.runningState) != 1 || atomic.LoadUint64(&s.proposalValidationGeneration) != serviceGeneration) {
			return nil, hotstuff.ErrOldState
		}
		snapshot := s.proposalBodySnapshotForWait(proposalID)
		if snapshot.assemblyErr != nil {
			return nil, snapshot.assemblyErr
		}
		if snapshot.body == nil {
			body, found, err := s.reconstructFHSCertifiedBody(proposalID)
			if err != nil {
				return nil, err
			}
			if !found && !checkedDurable && s.fhsStore != nil && s.fhsStore.db != nil {
				checkedDurable = true
				_, body, _, err = s.readFHSDurableProposalBody(proposalID)
				if err != nil {
					return nil, err
				}
			}
			snapshot.body = body
		}
		if snapshot.body != nil {
			if snapshot.body.BodyHash != ref.BodyHash {
				return nil, fmt.Errorf("proposal body hash mismatch for %s: have %s want %s", proposalID, snapshot.body.BodyHash, ref.BodyHash)
			}
			if uint64(len(snapshot.body.EncodedBlock)) != ref.BodySize {
				return nil, fmt.Errorf("proposal body size mismatch for %s: have %d want %d", proposalID, len(snapshot.body.EncodedBlock), ref.BodySize)
			}
			return snapshot.body, nil
		}
		now := time.Now()
		if snapshot.missingCount > 0 {
			if repairStartedAt.IsZero() {
				repairStartedAt = now
			}
			repairDeadline := repairStartedAt.Add(proposalRepairWaitTimeoutForPayload(s.chainConfig, snapshot.missingCount, ref.BodySize))
			if repairDeadline.After(deadline) {
				deadline = repairDeadline
			}
		}
		if !now.Before(nextRequestAt) {
			if snapshot.hasManifest && snapshot.missingCount > 0 {
				burst := proposalRepairRequestBurstForConfig(s.chainConfig)
				for sent := uint64(0); sent < burst; sent++ {
					window := s.nextProposalRepairWindow(proposalID, &repairRequests)
					if len(window) == 0 {
						break
					}
					unresolved, err := s.resolveProposalAssemblyWindow(proposalID, window)
					if err != nil {
						return nil, err
					}
					if len(unresolved) == 0 {
						continue
					}
					s.sendProposalRepairRequest(ref, unresolved, requestAttempt)
					requestAttempt++
				}
			} else if !snapshot.hasManifest && !snapshot.assembling {
				// An empty hash list requests the authenticated manifest itself.
				s.sendProposalRepairRequest(ref, nil, requestAttempt)
				requestAttempt++
			}
			nextRequestAt = now.Add(proposalBodyRequestInterval)
			// Sending or local resolution may have completed the proposal and
			// replaced the wake channel. Refresh state before blocking.
			continue
		}
		if now.After(deadline) {
			return nil, fmt.Errorf("%w: proposal body timeout: number=%d proposalID=%s bodyHash=%s", hotstuff.ErrProposalDataUnavailable, ref.Number, proposalID, ref.BodyHash)
		}
		wakeAt := nextRequestAt
		if deadline.Before(wakeAt) {
			wakeAt = deadline
		}
		wait := time.Until(wakeAt)
		if wait < 0 {
			wait = 0
		}
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-snapshot.wake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return nil, hotstuff.ErrOldState
		}
	}
}

func proposalBodyWaitTimeout(bodySize uint64) time.Duration {
	return proposalBodyWaitTimeoutForConfig(nil, bodySize)
}

func proposalBodyWaitTimeoutForConfig(config *params.ChainConfig, bodySize uint64) time.Duration {
	timeout := proposalBodyWaitBaseTimeout
	if config != nil && config.NativeParallelEnabled() {
		if limit := uint64(proposalBodyLimitForConfig(config)); bodySize > limit {
			bodySize = limit
		}
	}
	if bodySize > 0 {
		transfer := time.Duration(bodySize) * time.Second / proposalBodyWaitBytesPerSecond
		timeout += transfer
	}
	maxTimeout := proposalBodyWaitMaxTimeout
	if config != nil && config.NativeParallelEnabled() {
		configuredTransfer := time.Duration(config.EffectiveMaxBlockBytes()) * time.Second / proposalBodyWaitBytesPerSecond
		if configuredTransfer > time.Duration(^uint64(0)>>1)-proposalBodyWaitBaseTimeout {
			maxTimeout = time.Duration(^uint64(0) >> 1)
		} else if candidate := proposalBodyWaitBaseTimeout + configuredTransfer; candidate > maxTimeout {
			maxTimeout = candidate
		}
	}
	if timeout > maxTimeout {
		return maxTimeout
	}
	return timeout
}

func proposalRepairWaitTimeout(missingCount int) time.Duration {
	return proposalRepairWaitTimeoutForConfig(nil, missingCount)
}

func proposalRepairWaitTimeoutForConfig(config *params.ChainConfig, missingCount int) time.Duration {
	recoveryBytes := uint64(0)
	if config != nil && config.NativeParallelEnabled() {
		recoveryBytes = config.EffectiveMaxBlockBytes()
	}
	return proposalRepairWaitTimeoutForPayload(config, missingCount, recoveryBytes)
}

// proposalRepairWaitTimeoutForPayload covers both the request-window schedule
// and the bytes which may need to be recovered. The count schedule alone is not
// sufficient: a single 1024-hash request can yield only one maximum-size
// transaction because repair responses are deliberately capped near 1 MiB.
func proposalRepairWaitTimeoutForPayload(config *params.ChainConfig, missingCount int, recoveryBytes uint64) time.Duration {
	if missingCount <= 0 {
		return 0
	}
	count := uint64(missingCount)
	if limit := params.FairHotstuffWorkLimitsForConfig(config).Transactions; count > limit {
		count = limit
	}
	if count == 0 {
		return 0
	}
	batchSize := uint64(proposalRepairMaxHashes)
	batches := (count + batchSize - 1) / batchSize
	burst := proposalRepairRequestBurstForConfig(config)
	rounds := (batches + burst - 1) / burst
	timeout := proposalBodyRequestAfter + time.Duration(rounds-1)*proposalBodyRequestInterval + proposalRepairNetworkMargin
	maxTimeout := proposalBodyWaitMaxTimeout
	if config != nil && config.NativeParallelEnabled() {
		maxBatches := (config.NativeParallel.MaxTransactionsPerBlock + batchSize - 1) / batchSize
		if maxBatches > 0 {
			maxRounds := (maxBatches + burst - 1) / burst
			configured := proposalBodyRequestAfter + time.Duration(maxRounds-1)*proposalBodyRequestInterval + proposalRepairNetworkMargin
			if configured > maxTimeout {
				maxTimeout = configured
			}
		}
		transferTimeout := proposalBodyWaitTimeoutForConfig(config, recoveryBytes)
		if transferTimeout > timeout {
			timeout = transferTimeout
		}
		configuredTransfer := proposalBodyWaitTimeoutForConfig(config, config.EffectiveMaxBlockBytes())
		if configuredTransfer > maxTimeout {
			maxTimeout = configuredTransfer
		}
	}
	if timeout > maxTimeout {
		return maxTimeout
	}
	return timeout
}

func (s *Service) proposalRepairTransactions(body *proposalBodyMsg, requested []common.Hash) ([]common.Hash, [][]byte, error) {
	if body == nil || len(requested) == 0 {
		return nil, nil, nil
	}
	available := make(map[common.Hash]*types.Transaction, len(requested))
	allowed := make(map[common.Hash]struct{}, len(requested))
	indexed := false
	// An explicit payload is a standalone/durable repair source (and is used by
	// focused validation tests). Metadata-only bodies returned by
	// proposalBodyForRepairRequest select the cached incremental index.
	useCachedIndex := len(body.EncodedBlock) == 0 && len(body.Manifest) == 0 && len(body.TransactionBytes) == 0
	s.muProposalBody.RLock()
	if useCachedIndex {
		if cached := s.proposalBodies[body.ProposalID]; cached != nil && cached.BodyHash == body.BodyHash &&
			cached.BodySize == body.BodySize && cached.Number == body.Number && cached.ViewNumber == body.ViewNumber &&
			cached.ViewID == body.ViewID && cached.LeaderID == body.LeaderID && cached.ProposalKeyHash == body.ProposalKeyHash {
			if state := s.proposalAssemblies[body.ProposalID]; state != nil {
				indexed = true
				for _, hash := range requested {
					position, ok := state.positions[hash]
					if !ok {
						continue
					}
					allowed[hash] = struct{}{}
					if tx := state.transactions[position]; tx != nil {
						available[hash] = tx
					}
				}
			}
		}
	}
	s.muProposalBody.RUnlock()
	if !indexed {
		if useCachedIndex {
			// The hot index can be evicted between selecting this repair source
			// and reading it. Certified artifacts/durable content remain usable.
			fallback, found, err := s.localFHSProposalBody(body.ProposalID)
			if err != nil {
				return nil, nil, err
			}
			if found {
				if !proposalBodyRepairContextMatches(fallback, body) {
					return nil, nil, fmt.Errorf("proposal repair fallback context mismatch")
				}
				body = fallback
			}
		}
		available = make(map[common.Hash]*types.Transaction, len(body.TransactionBytes))
		allowed = make(map[common.Hash]struct{})
		for index, encoded := range body.TransactionBytes {
			tx, err := decodeCanonicalProposalRepairTransactionForConfig(s.chainConfig, encoded)
			if err != nil {
				return nil, nil, fmt.Errorf("cached proposal repair transaction %d: %w", index, err)
			}
			hash := tx.Hash()
			if _, duplicate := available[hash]; duplicate {
				return nil, nil, fmt.Errorf("cached proposal repair repeats transaction %s", hash)
			}
			available[hash] = tx
		}
		if len(body.Manifest) > 0 {
			if manifest, err := decodeProposalDataManifestForConfig(s.chainConfig, body.Manifest); err == nil {
				allowed = make(map[common.Hash]struct{}, len(manifest.TransactionHashes))
				for _, hash := range manifest.TransactionHashes {
					allowed[hash] = struct{}{}
				}
			}
		}
		if len(body.EncodedBlock) > 0 {
			if block := types.DecodeToBlock(body.EncodedBlock); block != nil {
				allowed = make(map[common.Hash]struct{}, len(block.Transactions()))
				for index, tx := range block.Transactions() {
					if tx == nil || !tx.IsInitialized() {
						return nil, nil, fmt.Errorf("proposal repair block transaction %d is not initialized", index)
					}
					hash := tx.Hash()
					available[hash] = tx
					allowed[hash] = struct{}{}
				}
			}
		}
	}
	if len(allowed) == 0 {
		return nil, nil, nil
	}
	hashes := make([]common.Hash, 0, len(requested))
	encodedTransactions := make([][]byte, 0, len(requested))
	seen := make(map[common.Hash]struct{}, len(requested))
	payloadBytes := 0
	for _, hash := range requested {
		if _, included := allowed[hash]; !included {
			continue
		}
		if _, duplicate := seen[hash]; duplicate {
			continue
		}
		seen[hash] = struct{}{}
		tx := available[hash]
		if tx == nil && s.txPool != nil {
			tx = s.txPool.Get(hash)
		}
		if tx == nil && s.resolveTxQUICTransaction != nil {
			var err error
			tx, err = s.resolveTxQUICTransaction(hash)
			if err != nil {
				return nil, nil, fmt.Errorf("resolve durable repair transaction %s: %w", hash, err)
			}
		}
		if tx == nil {
			continue
		}
		encoded, err := encodeProposalRepairTransactionForConfig(s.chainConfig, tx)
		if err != nil {
			return nil, nil, fmt.Errorf("encode repair transaction %s: %w", hash, err)
		}
		if tx.Hash() != hash {
			continue
		}
		nextBytes := len(encoded) + common.HashLength
		payloadLimit := proposalRepairPayloadLimitForConfig(s.chainConfig) - proposalRepairResponseReserve
		if len(encodedTransactions) > 0 && !fitsIntBudget(payloadBytes, nextBytes, payloadLimit) {
			break
		}
		if nextBytes > payloadLimit {
			continue
		}
		hashes = append(hashes, hash)
		encodedTransactions = append(encodedTransactions, encoded)
		payloadBytes += nextBytes
	}
	return hashes, encodedTransactions, nil
}

func (s *Service) proposalManifestForRepair(proposalID common.Hash, fallback *proposalBodyMsg) ([]byte, error) {
	if fallback != nil && len(fallback.Manifest) > 0 {
		return append([]byte(nil), fallback.Manifest...), nil
	}
	s.muProposalBody.RLock()
	var manifest *proposalDataManifest
	if state := s.proposalAssemblies[proposalID]; state != nil {
		manifest = state.manifest
	}
	s.muProposalBody.RUnlock()
	if manifest == nil {
		if fallback != nil && len(fallback.EncodedBlock) == 0 {
			body, found, err := s.localFHSProposalBody(proposalID)
			if err != nil {
				return nil, err
			}
			if found {
				if !proposalBodyRepairContextMatches(body, fallback) {
					return nil, fmt.Errorf("proposal manifest fallback context mismatch")
				}
				fallback = body
			}
		}
		if fallback == nil || len(fallback.EncodedBlock) == 0 {
			return nil, fmt.Errorf("proposal manifest is unavailable")
		}
		block := types.DecodeToBlock(fallback.EncodedBlock)
		return encodeProposalDataManifestForConfig(s.chainConfig, block)
	}
	encoded, err := rlp.EncodeToBytes(manifest)
	if err != nil {
		return nil, err
	}
	limit := proposalBodyLimitForConfig(s.chainConfig)
	if len(encoded) == 0 || len(encoded) > limit {
		return nil, fmt.Errorf("proposal manifest too large: bytes=%d limit=%d", len(encoded), limit)
	}
	return encoded, nil
}

func proposalBodyRepairContextMatches(body, request *proposalBodyMsg) bool {
	return body != nil && request != nil && body.ProposalID == request.ProposalID && body.BodyHash == request.BodyHash &&
		body.BodySize == request.BodySize && body.Number == request.Number && body.ViewNumber == request.ViewNumber &&
		body.ViewID == request.ViewID && body.LeaderID == request.LeaderID && body.ProposalKeyHash == request.ProposalKeyHash
}

func (s *Service) releaseProposalAssemblyBuildWaiter(build *proposalAssemblyBuild) {
	if build == nil {
		return
	}
	s.muProposalBody.Lock()
	if build.waiters > 0 {
		build.waiters--
	}
	if build.waiters == 0 && build.cancel != nil {
		build.cancel()
	}
	s.muProposalBody.Unlock()
}

func (s *Service) finishProposalAssemblyBuild(proposalID common.Hash, build *proposalAssemblyBuild, buildErr error) {
	s.muProposalBody.Lock()
	build.err = buildErr
	if s.proposalAssemblyBuilds[proposalID] == build {
		delete(s.proposalAssemblyBuilds, proposalID)
	}
	if build.cancel != nil {
		build.cancel()
	}
	close(build.done)
	s.muProposalBody.Unlock()
}

func (s *Service) runProposalAssemblyBuild(proposalID common.Hash, cached *proposalBodyMsg, build *proposalAssemblyBuild, slots chan struct{}) {
	var buildErr error
	defer func() {
		if recovered := recover(); recovered != nil {
			buildErr = fmt.Errorf("proposal donor index rebuild panic: %v", recovered)
		}
		s.finishProposalAssemblyBuild(proposalID, build, buildErr)
	}()
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	case <-build.ctx.Done():
		buildErr = build.ctx.Err()
		return
	}
	s.muProposalBody.RLock()
	current := s.proposalBodies[proposalID]
	alreadyBuilt := s.proposalAssemblies[proposalID] != nil
	decoder := s.decodeProposalBodyForRepair
	s.muProposalBody.RUnlock()
	if alreadyBuilt {
		return
	}
	if current != cached {
		buildErr = errProposalAssemblySuperseded
		return
	}
	if decoder == nil {
		decoder = types.DecodeToBlock
	}
	block := decoder(cached.EncodedBlock)
	if block == nil {
		buildErr = fmt.Errorf("cached proposal repair body is invalid")
		return
	}
	assembly, err := newCompleteProposalAssembly(block, len(cached.EncodedBlock))
	if err != nil {
		buildErr = err
		return
	}
	if err := build.ctx.Err(); err != nil {
		buildErr = err
		return
	}
	s.muProposalBody.Lock()
	defer s.muProposalBody.Unlock()
	if s.proposalBodies[proposalID] != cached {
		buildErr = errProposalAssemblySuperseded
		return
	}
	if s.proposalAssemblies[proposalID] != nil {
		return
	}
	if s.proposalAssemblies == nil {
		s.proposalAssemblies = make(map[common.Hash]*proposalAssemblyState)
	}
	if !s.ensureProposalAssemblyCapacityLocked(proposalID, assembly.cacheWeight) {
		buildErr = fmt.Errorf("proposal assembly cache capacity exhausted")
		return
	}
	s.proposalAssemblies[proposalID] = assembly
}

func (s *Service) ensureProposalRepairAssembly(ctx context.Context, request *proposalBodyMsg, cached *proposalBodyMsg) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.muProposalBody.Lock()
	if s.proposalBodies[request.ProposalID] != cached {
		s.muProposalBody.Unlock()
		return errProposalAssemblySuperseded
	}
	if s.proposalAssemblies[request.ProposalID] != nil {
		s.muProposalBody.Unlock()
		return nil
	}
	if s.proposalAssemblyBuilds == nil {
		s.proposalAssemblyBuilds = make(map[common.Hash]*proposalAssemblyBuild)
	}
	if s.proposalAssemblyBuildSlots == nil {
		s.proposalAssemblyBuildSlots = make(chan struct{}, 1)
	}
	build := s.proposalAssemblyBuilds[request.ProposalID]
	if build == nil {
		timeout := proposalBodyWaitTimeoutForConfig(s.chainConfig, request.BodySize)
		buildCtx, cancel := context.WithTimeout(context.Background(), timeout)
		build = &proposalAssemblyBuild{done: make(chan struct{}), ctx: buildCtx, cancel: cancel}
		s.proposalAssemblyBuilds[request.ProposalID] = build
		go s.runProposalAssemblyBuild(request.ProposalID, cached, build, s.proposalAssemblyBuildSlots)
	}
	build.waiters++
	done := build.done
	s.muProposalBody.Unlock()
	defer s.releaseProposalAssemblyBuildWaiter(build)
	select {
	case <-done:
		return build.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// proposalBodyForRepairRequest first checks the volatile hot cache, then falls
// back to the content-addressed recovery store. A restarted validator may have
// certified proposal data on disk without having repopulated proposalBodies;
// it must still be able to act as a DA repair donor. The durable loader fully
// revalidates the ProposalRef and body/proof commitments before this exact
// request context is matched.
func (s *Service) proposalBodyForRepairRequest(request *proposalBodyMsg) (*proposalBodyMsg, bool, error) {
	if request == nil || request.ProposalID == (common.Hash{}) {
		return nil, false, fmt.Errorf("invalid proposal repair request")
	}
	timeout := proposalBodyWaitTimeoutForConfig(s.chainConfig, request.BodySize)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return s.proposalBodyForRepairRequestContext(ctx, request)
}

func (s *Service) proposalBodyForRepairRequestContext(ctx context.Context, request *proposalBodyMsg) (*proposalBodyMsg, bool, error) {
	if request == nil || request.ProposalID == (common.Hash{}) {
		return nil, false, fmt.Errorf("invalid proposal repair request")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		s.muProposalBody.RLock()
		cached := s.proposalBodies[request.ProposalID]
		indexed := cached != nil && s.proposalAssemblies[request.ProposalID] != nil
		s.muProposalBody.RUnlock()
		if cached != nil {
			if !proposalBodyRepairContextMatches(cached, request) {
				return nil, false, fmt.Errorf("proposal repair request context mismatch")
			}
			if indexed {
				// The cached assembly index is the repair payload source. Copy only
				// authenticated metadata instead of a 256 MiB block.
				return cloneProposalBodyEnvelope(cached), false, nil
			}
			if len(cached.EncodedBlock) > 0 {
				if err := s.ensureProposalRepairAssembly(ctx, request, cached); err != nil {
					if errors.Is(err, errProposalAssemblySuperseded) {
						continue
					}
					return nil, false, err
				}
				continue
			}
			// Incomplete pre-index fixtures retain the compatibility fallback.
			// Authenticated manifests normally install their index atomically.
			return cloneProposalBodyMsg(cached), false, nil
		}
		durableBody, found, err := s.localFHSProposalBody(request.ProposalID)
		if err != nil {
			return nil, true, err
		}
		if !found || durableBody == nil {
			return nil, false, nil
		}
		if !proposalBodyRepairContextMatches(durableBody, request) {
			return nil, true, fmt.Errorf("proposal repair request context mismatch")
		}
		return durableBody, true, nil
	}
}

func (s *Service) handleProposalBodyMsg(si *network.ServerIdentity, msg *proposalBodyMsg) {
	if msg == nil {
		return
	}
	if err := validateProposalBodyWireShapeForConfig(s.chainConfig, msg); err != nil {
		log.Warn("HOTSTUFF PROPOSAL BODY malformed", "from", msg.From, "number", msg.Number, "err", err)
		return
	}
	if err := s.verifyProposalBodySender(si, msg); err != nil {
		log.Warn("HOTSTUFF PROPOSAL BODY sender rejected", "from", msg.From, "number", msg.Number, "proposalID", msg.ProposalID, "err", err)
		return
	}
	if msg.Type == proposalBodyMsgManifest {
		if err := s.verifyProposalManifestAuthority(msg); err != nil {
			log.Warn("HOTSTUFF PROPOSAL MANIFEST authority rejected", "from", msg.From, "leader", msg.LeaderID, "number", msg.Number, "proposalID", msg.ProposalID, "err", err)
			return
		}
		if err := s.verifyProposalManifestSignature(msg); err != nil {
			log.Warn("HOTSTUFF PROPOSAL MANIFEST leader signature rejected", "from", msg.From, "number", msg.Number, "proposalID", msg.ProposalID, "err", err)
			return
		}
	}
	switch msg.Type {
	case proposalBodyMsgManifest:
		missing, err := s.storeProposalManifest(msg)
		if err != nil {
			s.discardIncompletePeerManifest(msg)
			log.Warn("HOTSTUFF PROPOSAL MANIFEST rejected", "from", msg.From, "number", msg.Number, "proposalID", msg.ProposalID, "err", err)
			return
		}
		log.Info("HOTSTUFF PROPOSAL MANIFEST stored", "from", msg.From, "number", msg.Number, "proposalID", msg.ProposalID,
			"manifestBytes", len(msg.Manifest), "missing", len(missing), "bodyBytes", msg.BodySize)
	case proposalBodyMsgRepairRequest:
		body, fromDurable, err := s.proposalBodyForRepairRequest(msg)
		if err != nil {
			log.Warn("HOTSTUFF PROPOSAL REPAIR request rejected", "from", msg.From, "number", msg.Number,
				"proposalID", msg.ProposalID, "durable", fromDurable, "err", err)
			return
		}
		if body == nil {
			log.Debug("HOTSTUFF PROPOSAL REPAIR request miss", "from", msg.From, "number", msg.Number, "proposalID", msg.ProposalID)
			return
		}
		if si == nil {
			return
		}
		address := si.Address.String()
		if address == "" {
			return
		}
		if len(msg.MissingTxHashes) == 0 {
			manifest, err := s.proposalManifestForRepair(body.ProposalID, body)
			if err != nil {
				log.Warn("HOTSTUFF PROPOSAL MANIFEST response assembly failed", "to", address, "proposalID", body.ProposalID, "err", err)
				return
			}
			response := cloneProposalBodyEnvelope(body)
			response.Type = proposalBodyMsgManifest
			response.From = s.Self()
			response.Manifest = manifest
			if err := s.sealProposalBody(response); err != nil {
				log.Warn("HOTSTUFF PROPOSAL MANIFEST RESPONSE signing failed", "to", address, "number", body.Number, "err", err)
				return
			}
			if err := s.netService.SendRawData(address, &networkMsg{Pmsg: response}); err != nil {
				log.Warn("HOTSTUFF PROPOSAL MANIFEST response failed", "to", address, "number", body.Number, "proposalID", body.ProposalID, "err", err)
			}
			return
		}
		hashes, encodedTransactions, err := s.proposalRepairTransactions(body, msg.MissingTxHashes)
		if err != nil {
			log.Warn("HOTSTUFF PROPOSAL REPAIR lookup failed", "to", address, "proposalID", body.ProposalID, "err", err)
			return
		}
		if len(encodedTransactions) == 0 {
			return
		}
		response := &proposalBodyMsg{
			Type:              proposalBodyMsgRepairData,
			ProposalID:        body.ProposalID,
			BodyHash:          body.BodyHash,
			BodySize:          body.BodySize,
			Number:            body.Number,
			ViewNumber:        body.ViewNumber,
			ViewID:            body.ViewID,
			LeaderID:          body.LeaderID,
			From:              s.Self(),
			ProposalKeyHash:   body.ProposalKeyHash,
			MissingTxHashes:   hashes,
			TransactionBytes:  encodedTransactions,
			CreatedAtUnixNano: time.Now().UnixNano(),
		}
		if err := s.sealProposalBody(response); err != nil {
			log.Warn("HOTSTUFF PROPOSAL REPAIR RESPONSE signing failed", "to", address, "number", body.Number, "err", err)
			return
		}
		if err := validateProposalBodyWireShapeForConfig(s.chainConfig, response); err != nil {
			log.Warn("HOTSTUFF PROPOSAL REPAIR RESPONSE invalid", "to", address, "number", body.Number, "err", err)
			return
		}
		if err := s.netService.SendRawData(address, &networkMsg{Pmsg: response}); err != nil {
			log.Warn("HOTSTUFF PROPOSAL REPAIR response failed", "to", address, "number", body.Number, "proposalID", body.ProposalID, "err", err)
		}
	case proposalBodyMsgRepairData:
		remaining, err := s.mergeProposalRepair(msg)
		if err != nil {
			log.Warn("HOTSTUFF PROPOSAL REPAIR rejected", "from", msg.From, "number", msg.Number, "proposalID", msg.ProposalID, "err", err)
			return
		}
		log.Info("HOTSTUFF PROPOSAL REPAIR stored", "from", msg.From, "number", msg.Number, "proposalID", msg.ProposalID,
			"transactions", len(msg.TransactionBytes), "remaining", remaining)
	default:
		log.Warn("HOTSTUFF PROPOSAL BODY unknown type", "type", msg.Type, "number", msg.Number, "proposalID", msg.ProposalID)
	}
}

// OnPropose is retained for non-FHS callers. Production FHS nodes schedule the
// same validation on the bounded worker pool below and install its result on
// the serialized HotStuff control loop.
func (s *Service) OnPropose(state []byte, extra []byte, viewNumber uint64, parentQC *hotstuff.SignedState) error {
	output, err := s.validateHotstuffProposalApplication(context.Background(), state, extra, viewNumber, parentQC, nil, 0, 0)
	if err != nil {
		return err
	}
	return s.installHotstuffProposalValidation(output)
}

func (s *Service) validateHotstuffProposalApplication(ctx context.Context, state []byte, extra []byte, viewNumber uint64, parentQC *hotstuff.SignedState, parentVerified *core.VerifiedProposal, serviceGeneration, validationGeneration uint64) (*proposalValidationOutput, error) {
	if !s.isRunning() {
		return nil, types.ErrNotRunning
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, hotstuff.ErrOldState
	}
	if len(state) == 0 {
		err := fmt.Errorf("empty hotstuff proposal ref")
		log.Error("OnPropose", "error", err)
		return nil, err
	}

	ref, err := types.DecodeHotstuffProposalRef(state)
	if err != nil {
		log.Error("OnPropose decode proposal ref", "err", err)
		return nil, err
	}
	if ref.ChainID != s.ChainID() {
		return nil, fmt.Errorf("hotstuff proposal chain id mismatch: have %d want %d", ref.ChainID, s.ChainID())
	}
	if ref.ViewNumber != viewNumber {
		return nil, fmt.Errorf("hotstuff proposal view number mismatch: have %d want %d", ref.ViewNumber, viewNumber)
	}
	if s.fairHotstuffEnabled() {
		if ref.ExtraHash != types.HotstuffProposalExtraHash(extra) {
			return nil, fmt.Errorf("hotstuff proposal extra proof is not bound to the signed reference")
		}
		var parentQCID common.Hash
		if parentQC != nil {
			id, err := hotstuff.SignedStateID(parentQC)
			if err != nil {
				return nil, err
			}
			parentQCID = id.Hash()
		}
		if ref.ParentQCID != parentQCID {
			return nil, fmt.Errorf("hotstuff proposal parent QC is not bound to the signed reference")
		}
		if err := s.validateFHSProposalParent(ref, parentQC); err != nil {
			return nil, err
		}
	}
	proposalID := ref.ProposalID()
	log.Info("OnPropose",
		"number", ref.Number,
		"proposalID", proposalID,
		"blockHash", ref.BlockHash,
		"bodyHash", ref.BodyHash,
		"bodySize", ref.BodySize)

	body, err := s.waitProposalBodyForValidation(ctx, ref, serviceGeneration)
	if err != nil {
		log.Error("OnPropose wait proposal body", "number", ref.Number, "proposalID", proposalID, "err", err)
		return nil, err
	}
	block := types.DecodeToBlock(body.EncodedBlock)
	if block == nil {
		err := fmt.Errorf("DecodeToBlock(proposal body) error")
		log.Error("OnPropose", "proposalID", proposalID, "error", err)
		return nil, err
	}
	if err := ref.VerifyAgainstBlock(block, body.EncodedBlock); err != nil {
		log.Error("OnPropose proposal ref mismatch", "number", ref.Number, "proposalID", proposalID, "err", err)
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, hotstuff.ErrOldState
	}

	var verified *core.VerifiedProposal
	if parentVerified != nil {
		// Only ScheduleFHSProposalValidation supplies a non-nil parent here;
		// snapshotFHSCertifiedVerified has already isolated it from the cache.
		// An empty parent may legitimately have no execution state. Preserve
		// the existing StateAt fallback; there is no mutable state to transfer.
		if parentVerified.StateDB == nil {
			verified, err = s.txService.verifyHotstuffProposalWithParent(ref, block, extra, parentVerified)
		} else {
			verified, err = s.txService.verifyHotstuffProposalWithOwnedParent(ref, block, extra, parentVerified)
		}
	} else {
		verified, err = s.txService.verifyHotstuffProposal(ref, block, extra)
	}
	if err != nil {
		log.Error("verify hotstuff proposal", "number", block.NumberU64(), "proposalID", proposalID, "err", err)
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, hotstuff.ErrOldState
	}
	if block.BlockType() == types.Key_Block {
		kblock := types.DecodeToKeyBlock(block.KeyInfo())
		if kblock == nil {
			return nil, fmt.Errorf("Block's extra (keyblock) is error format!")
		}
		if s.hasConflictingUncommittedFHSKeyBlock(block) {
			return nil, fmt.Errorf("reject competing key block while a certified key transition is uncommitted: proposal=%s", block.Hash())
		}
		if block.NumberU64() == 0 {
			return nil, fmt.Errorf("key block carrier cannot be transaction genesis")
		}
	}
	return &proposalValidationOutput{
		ref:                  ref,
		verified:             verified,
		extra:                append([]byte(nil), extra...),
		parentQC:             hotstuff.CloneSignedState(parentQC),
		serviceGeneration:    serviceGeneration,
		validationGeneration: validationGeneration,
	}, nil
}

func (s *Service) installHotstuffProposalValidation(output *proposalValidationOutput) error {
	if output == nil || output.ref == nil || output.verified == nil || output.verified.ProposalID != output.ref.ProposalID() {
		return fmt.Errorf("invalid hotstuff proposal validation output")
	}
	if output.serviceGeneration != 0 && (atomic.LoadInt32(&s.runningState) != 1 || atomic.LoadUint64(&s.proposalValidationGeneration) != output.serviceGeneration) {
		return hotstuff.ErrOldState
	}
	if atomic.LoadInt32(&s.fhsEpochTransition) != 0 {
		return hotstuff.ErrOldState
	}
	if output.validationGeneration != 0 && !s.isProposalValidationOutputActive(output) {
		return hotstuff.ErrOldState
	}
	if err := output.verified.SanityCheck(); err != nil || output.verified.BlockHash() != output.ref.BlockHash ||
		output.verified.ViewNumber != output.ref.ViewNumber || output.verified.ViewID != output.ref.ViewID || output.verified.LeaderID != output.ref.LeaderID ||
		output.verified.ParentHash != output.ref.ParentHash {
		return fmt.Errorf("invalid verified proposal artifact: %v", err)
	}
	if output.ref.ExtraHash != types.HotstuffProposalExtraHash(output.extra) {
		return fmt.Errorf("validated proposal extra commitment changed")
	}
	var parentQCID common.Hash
	if output.parentQC != nil {
		id, err := hotstuff.SignedStateID(output.parentQC)
		if err != nil {
			return err
		}
		parentQCID = id.Hash()
	}
	if output.ref.ParentQCID != parentQCID {
		return fmt.Errorf("validated proposal parent QC commitment changed")
	}
	if s.fairHotstuffEnabled() {
		if err := s.validateFHSProposalParent(output.ref, output.parentQC); err != nil {
			return err
		}
	}
	if output.verified.Block != nil && output.verified.Block.BlockType() == types.Key_Block {
		block := output.verified.Block
		kblock := types.DecodeToKeyBlock(block.KeyInfo())
		if kblock == nil || block.NumberU64() == 0 || s.hasConflictingUncommittedFHSKeyBlock(block) {
			return fmt.Errorf("validated key block is no longer admissible")
		}
		if err := s.keyService.verifyKeyBlock(kblock, types.DecodeToCandidate(output.extra), block.NumberU64()-1); err != nil {
			return err
		}
	}
	if err := s.updateProposalBodyProof(output.ref.ProposalID(), output.extra, output.parentQC); err != nil {
		return err
	}
	s.storeVerifiedProposal(output.ref.ProposalID(), output.verified)
	s.pacetMakerTimer.start()
	return nil
}

func (s *Service) ScheduleFHSProposalValidation(request *hotstuff.FHSProposalValidationRequest) error {
	if request == nil || request.Key.ProposalID == (common.Hash{}) || len(request.ProposalRef) == 0 || s.proposalValidationJobs == nil {
		return fmt.Errorf("invalid FHS proposal validation request")
	}
	cloned := &hotstuff.FHSProposalValidationRequest{
		Key:         request.Key,
		ProposalRef: append([]byte(nil), request.ProposalRef...),
		Extra:       append([]byte(nil), request.Extra...),
		ParentQC:    hotstuff.CloneSignedState(request.ParentQC),
	}
	ref, err := types.DecodeHotstuffProposalRef(cloned.ProposalRef)
	if err != nil || ref.ProposalID() != cloned.Key.ProposalID {
		return fmt.Errorf("invalid FHS proposal validation reference")
	}
	serviceGeneration := atomic.LoadUint64(&s.proposalValidationGeneration)
	if atomic.LoadInt32(&s.runningState) != 1 || serviceGeneration == 0 {
		return types.ErrNotRunning
	}
	if atomic.LoadInt32(&s.fhsEpochTransition) != 0 {
		return hotstuff.ErrOldState
	}
	parentVerified := s.snapshotFHSCertifiedVerified(ref.ParentHash)

	s.muProposalValidation.Lock()
	defer s.muProposalValidation.Unlock()
	if atomic.LoadInt32(&s.runningState) != 1 || atomic.LoadUint64(&s.proposalValidationGeneration) != serviceGeneration {
		return types.ErrNotRunning
	}
	if atomic.LoadInt32(&s.fhsEpochTransition) != 0 {
		return hotstuff.ErrOldState
	}
	// A manager-owned HighQC worker must outlive ordinary view cleanup. The
	// Prepare that depends on it is already retained as a manager continuation;
	// reject this direct scheduling attempt without cancelling or draining the
	// shared queue, then let the HighQC result replay the exact Prepare.
	activeHighQC := s.activeHighQCValidation
	if active := activeHighQC; active != nil && !active.applied {
		return hotstuff.ErrProposalValidationPending
	}
	for _, active := range s.activeProposalValidations {
		if active != nil && active.key.ViewNumber > cloned.Key.ViewNumber {
			return hotstuff.ErrOldState
		}
		if active != nil && active.key == cloned.Key {
			return nil
		}
	}
	for viewID, active := range s.activeProposalValidations {
		if active != nil && active.cancel != nil {
			active.cancel()
		}
		delete(s.activeProposalValidations, viewID)
	}
	for {
		select {
		case stale := <-s.proposalValidationJobs:
			if stale != nil && stale.highQCRequest != nil {
				// An applied HighQC normally has no queued worker, but preserve the
				// manager-owned job if result publication and queue observation race.
				select {
				case s.proposalValidationJobs <- stale:
					return hotstuff.ErrProposalValidationPending
				default:
					return fmt.Errorf("FHS proposal scheduler could not preserve HighQC work")
				}
			}
			if stale != nil && stale.cancel != nil {
				stale.cancel()
			}
		default:
			goto queueDrained
		}
	}

queueDrained:
	s.proposalValidationSeq++
	if s.proposalValidationSeq == 0 {
		s.proposalValidationSeq++
	}
	validationGeneration := s.proposalValidationSeq
	ctx, cancel := context.WithCancel(context.Background())
	job := &proposalValidationJob{
		request:              cloned,
		parentVerified:       parentVerified,
		ctx:                  ctx,
		cancel:               cancel,
		serviceGeneration:    serviceGeneration,
		validationGeneration: validationGeneration,
	}
	s.activeProposalValidations[cloned.Key.ViewID] = &proposalValidationControl{
		key:        cloned.Key,
		keyHash:    ref.KeyHash,
		generation: validationGeneration,
		cancel:     cancel,
	}
	select {
	case s.proposalValidationJobs <- job:
		return nil
	default:
		delete(s.activeProposalValidations, cloned.Key.ViewID)
		cancel()
		return fmt.Errorf("FHS proposal validation scheduler invariant failed")
	}
}

func (s *Service) ScheduleFHSHighQCValidation(request *hotstuff.FHSHighQCValidationRequest) error {
	if request == nil || request.QC == nil || request.Key.RequestID == 0 || request.Key.QCID == (common.Hash{}) ||
		request.Key.TargetView == 0 || s.proposalValidationJobs == nil {
		return fmt.Errorf("invalid FHS HighQC validation request")
	}
	id, err := hotstuff.SignedStateID(request.QC)
	if err != nil || id.Hash() != request.Key.QCID || request.Key.TargetView <= request.QC.Number {
		return fmt.Errorf("invalid FHS HighQC validation identity")
	}
	cloned := &hotstuff.FHSHighQCValidationRequest{Key: request.Key, QC: hotstuff.CloneSignedState(request.QC)}
	serviceGeneration := atomic.LoadUint64(&s.proposalValidationGeneration)
	if atomic.LoadInt32(&s.runningState) != 1 || serviceGeneration == 0 {
		return types.ErrNotRunning
	}
	if atomic.LoadInt32(&s.fhsEpochTransition) != 0 {
		return hotstuff.ErrOldState
	}

	s.muProposalValidation.Lock()
	defer s.muProposalValidation.Unlock()
	if atomic.LoadInt32(&s.runningState) != 1 || atomic.LoadUint64(&s.proposalValidationGeneration) != serviceGeneration {
		return types.ErrNotRunning
	}
	if atomic.LoadInt32(&s.fhsEpochTransition) != 0 {
		return hotstuff.ErrOldState
	}
	// Preflight semantic certificate order before touching the running worker.
	// TargetView is only continuation metadata and must never make the same QC
	// cancel/restart identical body and EVM validation work.
	previousHighQC := s.activeHighQCValidation
	if active := previousHighQC; active != nil {
		if active.key == cloned.Key {
			return nil
		}
		if active.key.QCID == cloned.Key.QCID {
			if !active.resultReady {
				return hotstuff.ErrProposalValidationPending
			}
		} else if active.qcNumber >= cloned.QC.Number && !cloned.Key.SelectProposalParent && !active.applied {
			return hotstuff.ErrOldState
		}
	}
	for _, active := range s.activeProposalValidations {
		if active != nil && active.key.ViewNumber > cloned.Key.TargetView {
			return hotstuff.ErrOldState
		}
	}
	// Temporarily remove queued jobs without cancelling them. The new semantic
	// QC must be enqueued successfully before any manager-owned work is stopped.
	var displaced []*proposalValidationJob
	for {
		select {
		case stale := <-s.proposalValidationJobs:
			if stale != nil {
				displaced = append(displaced, stale)
			}
		default:
			goto highQCQueueDrained
		}
	}

highQCQueueDrained:
	s.proposalValidationSeq++
	if s.proposalValidationSeq == 0 {
		s.proposalValidationSeq++
	}
	validationGeneration := s.proposalValidationSeq
	ctx, cancel := context.WithCancel(context.Background())
	job := &proposalValidationJob{
		highQCRequest:        cloned,
		ctx:                  ctx,
		cancel:               cancel,
		serviceGeneration:    serviceGeneration,
		validationGeneration: validationGeneration,
	}
	newControl := &highQCValidationControl{
		key: cloned.Key, qcNumber: cloned.QC.Number, generation: validationGeneration, cancel: cancel,
		authorized: make(map[common.Hash]proposalBodyAuthority),
	}
	select {
	case s.proposalValidationJobs <- job:
		// Publication into the bounded queue is the replacement linearization
		// point. Only now may the previous semantic QC and proposal jobs stop.
		s.activeHighQCValidation = newControl
		if previousHighQC != nil && previousHighQC.cancel != nil {
			previousHighQC.cancel()
		}
		for viewID, active := range s.activeProposalValidations {
			if active != nil && active.cancel != nil {
				active.cancel()
			}
			delete(s.activeProposalValidations, viewID)
		}
		for _, stale := range displaced {
			if stale.cancel != nil {
				stale.cancel()
			}
		}
		return nil
	default:
		cancel()
		for _, stale := range displaced {
			select {
			case s.proposalValidationJobs <- stale:
			default:
				return fmt.Errorf("FHS HighQC validation scheduler could not restore displaced work")
			}
		}
		// The old registry and queued work remain authoritative. ErrOldState is
		// the manager contract that restores its previous pending request.
		return hotstuff.ErrOldState
	}
}

func (s *Service) isProposalValidationJobActive(job *proposalValidationJob) bool {
	if s == nil || job == nil || job.ctx == nil || job.ctx.Err() != nil ||
		atomic.LoadInt32(&s.runningState) != 1 || atomic.LoadUint64(&s.proposalValidationGeneration) != job.serviceGeneration {
		return false
	}
	s.muProposalValidation.Lock()
	defer s.muProposalValidation.Unlock()
	if job.highQCRequest != nil {
		active := s.activeHighQCValidation
		return active != nil && active.key == job.highQCRequest.Key && active.generation == job.validationGeneration
	}
	if job.request == nil {
		return false
	}
	active := s.activeProposalValidations[job.request.Key.ViewID]
	return active != nil && active.key == job.request.Key && active.generation == job.validationGeneration
}

func (s *Service) markHighQCValidationResultReady(key hotstuff.FHSHighQCValidationKey, generation uint64) bool {
	if s == nil || generation == 0 {
		return false
	}
	s.muProposalValidation.Lock()
	defer s.muProposalValidation.Unlock()
	active := s.activeHighQCValidation
	if active == nil || active.key != key || active.generation != generation {
		return false
	}
	active.resultReady = true
	return true
}

func (s *Service) markHighQCValidationApplied(key hotstuff.FHSHighQCValidationKey, generation uint64) bool {
	if s == nil || generation == 0 {
		return false
	}
	s.muProposalValidation.Lock()
	defer s.muProposalValidation.Unlock()
	active := s.activeHighQCValidation
	if active == nil || active.key != key || active.generation != generation || !active.resultReady {
		return false
	}
	active.applied = true
	return true
}

func (s *Service) isProposalValidationOutputActive(output *proposalValidationOutput) bool {
	if s == nil || output == nil || output.ref == nil {
		return false
	}
	s.muProposalValidation.Lock()
	defer s.muProposalValidation.Unlock()
	active := s.activeProposalValidations[output.ref.ViewID]
	return active != nil && active.generation == output.validationGeneration &&
		active.key.ViewNumber == output.ref.ViewNumber && active.key.ViewID == output.ref.ViewID &&
		active.key.LeaderID == output.ref.LeaderID && active.key.ProposalID == output.ref.ProposalID()
}

func (s *Service) isHighQCValidationOutputActive(output *fhsHighQCValidationOutput) bool {
	if s == nil || output == nil {
		return false
	}
	s.muProposalValidation.Lock()
	defer s.muProposalValidation.Unlock()
	active := s.activeHighQCValidation
	return active != nil && active.key == output.key && active.generation == output.validationGeneration
}

func (s *Service) authorizeHighQCProposalBody(key hotstuff.FHSHighQCValidationKey, generation uint64, ref *types.HotstuffProposalRef) error {
	if s == nil || ref == nil || key.RequestID == 0 || generation == 0 {
		return hotstuff.ErrOldState
	}
	s.muProposalValidation.Lock()
	active := s.activeHighQCValidation
	if active == nil || active.key != key || active.generation != generation {
		s.muProposalValidation.Unlock()
		return hotstuff.ErrOldState
	}
	active.authorized[ref.ProposalID()] = proposalBodyAuthority{
		key: hotstuff.FHSProposalValidationKey{
			ViewNumber: ref.ViewNumber,
			ViewID:     ref.ViewID,
			LeaderID:   ref.LeaderID,
			ProposalID: ref.ProposalID(),
		},
		keyHash: ref.KeyHash,
	}
	s.muProposalValidation.Unlock()
	if err := s.extendDeferredFHSRecoveryPeers(ref.KeyHash); err != nil {
		return fmt.Errorf("authorize deferred FHS repair committee: %w", err)
	}
	return nil
}

// activeHighQCProposalBodyIDs snapshots the cryptographically verified repair
// set without exposing the validation registry. Durable proposal GC treats
// these entries as temporarily live until the exact HighQC worker completes;
// otherwise a catch-up longer than the ordinary unsolicited cache budget can
// collect its own oldest bodies before the serialized install begins.
func (s *Service) activeHighQCProposalBodyIDs() map[common.Hash]struct{} {
	protected := make(map[common.Hash]struct{})
	if s == nil {
		return protected
	}
	s.muProposalValidation.Lock()
	if active := s.activeHighQCValidation; active != nil {
		for proposalID := range active.authorized {
			protected[proposalID] = struct{}{}
		}
	}
	s.muProposalValidation.Unlock()
	return protected
}

func (s *Service) finishProposalValidation(key hotstuff.FHSProposalValidationKey) {
	if s == nil {
		return
	}
	s.muProposalValidation.Lock()
	defer s.muProposalValidation.Unlock()
	active := s.activeProposalValidations[key.ViewID]
	if active == nil || active.key != key {
		return
	}
	if active.cancel != nil {
		active.cancel()
	}
	delete(s.activeProposalValidations, key.ViewID)
}

func (s *Service) finishHighQCValidation(key hotstuff.FHSHighQCValidationKey) {
	if s == nil {
		return
	}
	s.muProposalValidation.Lock()
	defer s.muProposalValidation.Unlock()
	active := s.activeHighQCValidation
	if active == nil || active.key != key {
		return
	}
	if active.cancel != nil {
		active.cancel()
	}
	s.activeHighQCValidation = nil
}

func (s *Service) cancelInactiveProposalValidations(activeView uint64) {
	if s == nil {
		return
	}
	s.muProposalValidation.Lock()
	defer s.muProposalValidation.Unlock()
	for viewID, active := range s.activeProposalValidations {
		if active != nil && active.key.ViewNumber == activeView {
			continue
		}
		if active != nil && active.cancel != nil {
			active.cancel()
		}
		delete(s.activeProposalValidations, viewID)
	}
	// HighQC work is owned by the manager's semantic QC continuation, not by an
	// individual active view. It ends only on semantic replacement, completion,
	// epoch transition or shutdown.
}

func (s *Service) cancelProposalValidationsBefore(viewNumber uint64) {
	if s == nil || viewNumber == 0 {
		return
	}
	s.muProposalValidation.Lock()
	defer s.muProposalValidation.Unlock()
	for viewID, active := range s.activeProposalValidations {
		if active != nil && active.key.ViewNumber >= viewNumber {
			continue
		}
		if active != nil && active.cancel != nil {
			active.cancel()
		}
		delete(s.activeProposalValidations, viewID)
	}
}

func (s *Service) cancelAllProposalValidations() {
	if s == nil {
		return
	}
	s.muProposalValidation.Lock()
	defer s.muProposalValidation.Unlock()
	for viewID, active := range s.activeProposalValidations {
		if active != nil && active.cancel != nil {
			active.cancel()
		}
		delete(s.activeProposalValidations, viewID)
	}
	if active := s.activeHighQCValidation; active != nil {
		if active.cancel != nil {
			active.cancel()
		}
		s.activeHighQCValidation = nil
	}
	for {
		select {
		case stale := <-s.proposalValidationJobs:
			if stale != nil && stale.cancel != nil {
				stale.cancel()
			}
		default:
			return
		}
	}
}

func (s *Service) proposalValidationWorker() {
	for job := range s.proposalValidationJobs {
		if !s.isProposalValidationJobActive(job) {
			continue
		}
		if request := job.highQCRequest; request != nil {
			output, err := s.stageFHSHighQC(job.ctx, request.Key, request.QC, job.serviceGeneration, job.validationGeneration)
			if !s.isProposalValidationJobActive(job) {
				continue
			}
			result := &hotstuff.FHSHighQCValidationResult{Key: request.Key, Err: err, ApplicationData: output}
			if !s.markHighQCValidationResultReady(request.Key, job.validationGeneration) {
				continue
			}
			select {
			case s.highQCValidationResults <- result:
			case <-job.ctx.Done():
			}
			continue
		}
		request := job.request
		output, err := s.validateHotstuffProposalApplication(job.ctx, request.ProposalRef, request.Extra, request.Key.ViewNumber, request.ParentQC, job.parentVerified, job.serviceGeneration, job.validationGeneration)
		if !s.isProposalValidationJobActive(job) {
			continue
		}
		result := &hotstuff.FHSProposalValidationResult{Key: request.Key, Err: err, ApplicationData: output}
		select {
		case s.proposalValidationResults <- result:
		case <-job.ctx.Done():
		}
	}
}

func (s *Service) ApplyFHSProposalValidation(result *hotstuff.FHSProposalValidationResult) error {
	if result == nil || result.Err != nil {
		return fmt.Errorf("invalid FHS proposal validation result")
	}
	output, ok := result.ApplicationData.(*proposalValidationOutput)
	if !ok || output == nil || output.ref == nil || output.ref.ViewNumber != result.Key.ViewNumber ||
		output.ref.ViewID != result.Key.ViewID || output.ref.LeaderID != result.Key.LeaderID || output.ref.ProposalID() != result.Key.ProposalID {
		return fmt.Errorf("FHS proposal validation result context mismatch")
	}
	if err := s.acquireFHSValidationPublication(fhsValidationPublicationProposal); err != nil {
		return err
	}
	transferred := false
	defer func() {
		if !transferred {
			s.releaseFHSValidationPublication(fhsValidationPublicationProposal)
		}
	}()
	if err := s.installHotstuffProposalValidation(output); err != nil {
		return err
	}
	s.activeProposalValidationPublish = result
	transferred = true
	return nil
}

// FinishFHSProposalValidation releases the publication barrier only after the
// manager has durably persisted, signed and sent (or rejected) the vote.
func (s *Service) FinishFHSProposalValidation(result *hotstuff.FHSProposalValidationResult) {
	if s == nil || result == nil ||
		atomic.LoadInt32(&s.fhsValidationPublicationOwner) != int32(fhsValidationPublicationProposal) ||
		s.activeProposalValidationPublish != result {
		return
	}
	s.activeProposalValidationPublish = nil
	if !s.releaseFHSValidationPublication(fhsValidationPublicationProposal) {
		atomic.StoreInt32(&s.fhsEpochTransition, 1)
		s.setRunState(0)
		log.Error("Fair HotStuff proposal validation failed to release its publication barrier")
	}
}

func (s *Service) ApplyFHSHighQCValidation(result *hotstuff.FHSHighQCValidationResult) error {
	if result == nil || result.Err != nil {
		return fmt.Errorf("invalid FHS HighQC validation result")
	}
	output, ok := result.ApplicationData.(*fhsHighQCValidationOutput)
	if !ok || output == nil || output.key != result.Key {
		return fmt.Errorf("FHS HighQC validation result context mismatch")
	}
	if err := s.acquireFHSValidationPublication(fhsValidationPublicationHighQC); err != nil {
		return err
	}
	transferred := false
	defer func() {
		if !transferred {
			s.releaseFHSValidationPublication(fhsValidationPublicationHighQC)
		}
	}()
	if output.serviceGeneration != 0 && (atomic.LoadInt32(&s.runningState) != 1 ||
		atomic.LoadUint64(&s.proposalValidationGeneration) != output.serviceGeneration) {
		return hotstuff.ErrOldState
	}
	if atomic.LoadInt32(&s.fhsEpochTransition) != 0 {
		return hotstuff.ErrOldState
	}
	if output.validationGeneration != 0 && !s.isHighQCValidationOutputActive(output) {
		return hotstuff.ErrOldState
	}
	if err := s.installStagedFHSHighQC(output, false, false); err != nil {
		return err
	}
	if err := s.commitFHS2ChainForCertified(output.targetQC); err != nil {
		return err
	}
	if _, err := s.completeDeferredFHSRecovery(output.targetQC); err != nil {
		return err
	}
	if output.validationGeneration != 0 && !s.markHighQCValidationApplied(result.Key, output.validationGeneration) {
		return hotstuff.ErrOldState
	}
	s.activeHighQCValidationPublish = result
	transferred = true
	return nil
}

// FinishFHSHighQCValidation retains the same barrier through manager state
// cleanup and exact continuation replay, not merely through application install.
func (s *Service) FinishFHSHighQCValidation(result *hotstuff.FHSHighQCValidationResult) {
	if s == nil || result == nil ||
		atomic.LoadInt32(&s.fhsValidationPublicationOwner) != int32(fhsValidationPublicationHighQC) ||
		s.activeHighQCValidationPublish != result {
		return
	}
	s.activeHighQCValidationPublish = nil
	if !s.releaseFHSValidationPublication(fhsValidationPublicationHighQC) {
		atomic.StoreInt32(&s.fhsEpochTransition, 1)
		s.setRunState(0)
		log.Error("Fair HotStuff HighQC validation failed to release its publication barrier")
	}
}

func (s *Service) ScheduleFHSProposalBuild(request *hotstuff.FHSProposalBuildRequest) error {
	if request == nil || request.Key.RequestID == 0 || request.Key.ViewNumber == 0 || request.Key.ViewID == (common.Hash{}) ||
		request.Key.LeaderID == "" || len(request.CurrentState) == 0 || s.proposalBuildJobs == nil {
		return fmt.Errorf("invalid FHS proposal construction request")
	}
	cloned := &hotstuff.FHSProposalBuildRequest{
		Key:          request.Key,
		CurrentState: append([]byte(nil), request.CurrentState...),
		ParentQC:     hotstuff.CloneSignedState(request.ParentQC),
	}
	if hotstuff.StateDigest(cloned.CurrentState) != cloned.Key.CurrentStateDigest {
		return fmt.Errorf("FHS proposal construction state mismatch")
	}
	var parentQCID common.Hash
	if cloned.ParentQC != nil {
		id, err := hotstuff.SignedStateID(cloned.ParentQC)
		if err != nil {
			return err
		}
		parentQCID = id.Hash()
	}
	if parentQCID != cloned.Key.ParentQCID {
		return fmt.Errorf("FHS proposal construction parent QC mismatch")
	}
	serviceGeneration := atomic.LoadUint64(&s.proposalValidationGeneration)
	if atomic.LoadInt32(&s.runningState) != 1 || serviceGeneration == 0 {
		return types.ErrNotRunning
	}

	s.muProposalBuild.Lock()
	defer s.muProposalBuild.Unlock()
	if atomic.LoadInt32(&s.runningState) != 1 || atomic.LoadUint64(&s.proposalValidationGeneration) != serviceGeneration {
		return types.ErrNotRunning
	}
	if atomic.LoadInt32(&s.fhsEpochTransition) != 0 {
		return hotstuff.ErrOldState
	}
	if active := s.activeProposalBuild; active != nil {
		if active.key == cloned.Key {
			return nil
		}
		if active.key.ViewNumber > cloned.Key.ViewNumber {
			return hotstuff.ErrOldState
		}
		if active.cancel != nil {
			active.cancel()
		}
		s.activeProposalBuild = nil
	}
	for {
		select {
		case stale := <-s.proposalBuildJobs:
			if stale != nil && stale.cancel != nil {
				stale.cancel()
			}
		default:
			goto proposalBuildQueueDrained
		}
	}

proposalBuildQueueDrained:
	s.proposalBuildSeq++
	if s.proposalBuildSeq == 0 {
		s.proposalBuildSeq++
	}
	constructionGeneration := s.proposalBuildSeq
	ctx, cancel := context.WithCancel(context.Background())
	job := &proposalBuildJob{
		request:                cloned,
		ctx:                    ctx,
		cancel:                 cancel,
		serviceGeneration:      serviceGeneration,
		constructionGeneration: constructionGeneration,
	}
	s.activeProposalBuild = &proposalBuildControl{key: cloned.Key, generation: constructionGeneration, cancel: cancel}
	select {
	case s.proposalBuildJobs <- job:
		return nil
	default:
		s.activeProposalBuild = nil
		cancel()
		return fmt.Errorf("FHS proposal construction scheduler invariant failed")
	}
}

func (s *Service) isProposalBuildJobActive(job *proposalBuildJob) bool {
	if s == nil || job == nil || job.request == nil || job.ctx == nil || job.ctx.Err() != nil ||
		atomic.LoadInt32(&s.runningState) != 1 || atomic.LoadUint64(&s.proposalValidationGeneration) != job.serviceGeneration {
		return false
	}
	s.muProposalBuild.Lock()
	defer s.muProposalBuild.Unlock()
	active := s.activeProposalBuild
	return active != nil && active.key == job.request.Key && active.generation == job.constructionGeneration
}

func (s *Service) proposalBuildWorker() {
	for job := range s.proposalBuildJobs {
		if !s.isProposalBuildJobActive(job) {
			continue
		}
		output, err := s.stageFHSProposalBuild(job)
		if !s.isProposalBuildJobActive(job) {
			continue
		}
		result := &hotstuff.FHSProposalBuildResult{Key: job.request.Key, Err: err, ApplicationData: output}
		if output != nil {
			result.TProposal = append([]byte(nil), output.proposalRef...)
			result.Extra = append([]byte(nil), output.extra...)
		}
		select {
		case s.proposalBuildResults <- result:
		case <-job.ctx.Done():
		}
	}
}

// keyProposalPlan derives proposal eligibility from the canonical key-block interval.
// Fixed mode deliberately ignores NoDone: it is local recovery state and may be
// reset by an otherwise valid TC/QC transition while the key-block slot is due.
func keyProposalPlan(fixedMode bool, leaderIndex uint, noDone, intervalElapsed bool) (attempt, isDone bool) {
	if fixedMode {
		return intervalElapsed, true
	}
	return leaderIndex > 0 && intervalElapsed, !noDone
}

func (s *Service) stageFHSProposalBuild(job *proposalBuildJob) (*proposalBuildOutput, error) {
	request := job.request
	output := &proposalBuildOutput{
		key:                    request.Key,
		serviceGeneration:      job.serviceGeneration,
		constructionGeneration: job.constructionGeneration,
	}
	if !s.isProposalBuildJobActive(job) {
		return output, hotstuff.ErrOldState
	}
	state, leaderID, number := s.CurrentState()
	if number != request.Key.ViewNumber || leaderID != request.Key.LeaderID || !bytes.Equal(state, request.CurrentState) {
		return output, hotstuff.ErrOldState
	}

	s.muCurrentView.Lock()
	leaderIndex := s.currentView.LeaderIndex
	noDone := s.currentView.NoDone
	replicaMatches := s.replicaView != nil && s.replicaView.EqualConsensus(&s.currentView)
	s.muCurrentView.Unlock()
	if !replicaMatches || !bftview.IamLeader(leaderIndex) {
		return output, hotstuff.ErrOldState
	}

	fixedMode := s.keyService.config != nil && (s.keyService.config.FixedLeader || s.keyService.config.FixedCommittee)
	keyBlockIntervalElapsed := true
	if curKeyblock := s.kbc.CurrentBlock(); curKeyblock != nil {
		keyBlockIntervalElapsed = time.Since(time.Unix(int64(curKeyblock.Time()), 0)) >= params.KeyBlockMinInterval
	}
	keyProposalAttempt, keyProposalIsDone := keyProposalPlan(fixedMode, leaderIndex, noDone, keyBlockIntervalElapsed)
	if keyProposalAttempt && s.hasUncommittedFHSKeyBlock() {
		keyProposalAttempt = false
	}
	output.fixedMode = fixedMode
	output.keyProposalAttempt = keyProposalAttempt

	if output.keyProposalAttempt {
		txParentNumber := fhsProposalParentNumber(s.bc.CurrentBlockN(), s.highestFHSCertifiedProposal())
		keyblock, committee, bestCandidate, err := s.keyService.tryProposalChangeCommittee(leaderIndex, keyProposalIsDone, txParentNumber)
		if err != nil || keyblock == nil || committee == nil {
			if err == nil {
				err = fmt.Errorf("incomplete key block proposal")
			}
			return output, err
		}
		if bestCandidate != nil {
			output.extra = bestCandidate.EncodeToBytes()
		}
		candidate, err := s.txService.buildProposalNewKeyBlock(keyblock)
		if err != nil {
			return output, err
		}
		staged, err := s.stageHotstuffProposal(request.Key.ViewNumber, request.Key.ViewID, request.Key.LeaderID,
			candidate.encoded, output.extra, request.ParentQC)
		if err != nil {
			return output, err
		}
		output.proposalRef = staged.proposalRef
		output.body = staged.body
		output.manifest = staged.manifest
		output.destinations = staged.destinations
		output.keyCandidate = candidate
		output.keyBlock = keyblock
		output.committee = committee
		output.blockType = types.Key_Block
		return output, nil
	}

	output.workStamp, output.workStampValid = s.captureProposalWorkStamp(
		time.Now(), request.Key.ViewNumber, request.Key.ViewID, request.Key.LeaderID,
	)
	blockType := s.chooseTxBlockType()
	candidate, err := s.txService.buildProposalNewBlock(blockType)
	if err != nil {
		primaryErr := err
		fallbackType := uint8(types.FastTx_Block)
		if blockType == types.FastTx_Block {
			fallbackType = types.SlowTx_Block
		}
		fallbackCandidate, fallbackErr := s.txService.buildProposalNewBlock(fallbackType)
		if fallbackErr == nil {
			candidate = fallbackCandidate
			err = nil
			blockType = fallbackType
		} else {
			err = proposalLaneBuildError(primaryErr, fallbackErr)
		}
	}
	if err != nil {
		return output, err
	}
	staged, err := s.stageHotstuffProposal(request.Key.ViewNumber, request.Key.ViewID, request.Key.LeaderID,
		candidate.encoded, nil, request.ParentQC)
	if err != nil {
		return output, err
	}
	output.proposalRef = staged.proposalRef
	output.body = staged.body
	output.manifest = staged.manifest
	output.destinations = staged.destinations
	output.txCandidate = candidate
	output.blockType = blockType
	return output, nil
}

func (s *Service) reserveProposalManifestDispatch() error {
	select {
	case s.proposalManifestSlots <- struct{}{}:
		return nil
	default:
		return fmt.Errorf("proposal manifest dispatch queue saturated")
	}
}

func (s *Service) releaseProposalManifestDispatch() {
	select {
	case <-s.proposalManifestSlots:
	default:
		panic("proposal manifest dispatch reservation underflow")
	}
}

func (s *Service) reserveProposalFailedTxCleanup() error {
	select {
	case s.proposalFailedTxSlots <- struct{}{}:
		return nil
	default:
		return fmt.Errorf("proposal failed-TX cleanup queue saturated")
	}
}

func (s *Service) releaseProposalFailedTxCleanup() {
	select {
	case <-s.proposalFailedTxSlots:
	default:
		panic("proposal failed-TX cleanup reservation underflow")
	}
}

func (s *Service) proposalManifestDispatchWorker() {
	for job := range s.proposalManifestJobs {
		if job != nil && job.body != nil && atomic.LoadInt32(&s.runningState) == 1 &&
			atomic.LoadUint64(&s.proposalValidationGeneration) == job.serviceGeneration {
			for _, address := range job.destinations {
				if atomic.LoadInt32(&s.runningState) != 1 || atomic.LoadUint64(&s.proposalValidationGeneration) != job.serviceGeneration {
					break
				}
				if err := s.netService.SendRawData(address, &networkMsg{Pmsg: job.body}); err != nil {
					log.Warn("HOTSTUFF PROPOSAL MANIFEST dispatch failed", "to", address,
						"number", job.body.Number, "proposalID", job.body.ProposalID, "err", err)
				}
			}
		}
		s.releaseProposalManifestDispatch()
	}
}

func (s *Service) proposalFailedTxCleanupWorker() {
	for job := range s.proposalFailedTxJobs {
		if job != nil && len(job.txs) > 0 && s.removeFailedProposalTxs != nil && atomic.LoadInt32(&s.runningState) == 1 &&
			atomic.LoadUint64(&s.proposalValidationGeneration) == job.serviceGeneration {
			s.removeFailedProposalTxs(job.txs)
			log.Warn("Removed failed proposal txs from txpool", "count", len(job.txs))
		}
		s.releaseProposalFailedTxCleanup()
	}
}

// proposalBuildRouteMatchesLocked requires muCurrentView. It binds the manager
// request to the exact service route and to the block/key generation captured by
// the worker. Apply keeps this lock until candidate publication completes, so a
// timeout-only route change cannot slip between this check and install.
func (s *Service) proposalBuildRouteMatchesLocked(output *proposalBuildOutput) bool {
	if output == nil || output.key.ViewNumber != s.currentView.ViewNumber+1 ||
		hotstuff.StateDigest(s.currentView.EncodeConsensusToBytes()) != output.key.CurrentStateDigest ||
		s.replicaView == nil || !s.replicaView.EqualConsensus(&s.currentView) {
		return false
	}
	committee, err := s.loadViewCommittee(&s.currentView, true)
	if err != nil || s.currentView.LeaderIndex >= uint(len(committee.List)) || committee.List[s.currentView.LeaderIndex] == nil {
		return false
	}
	leader := committee.List[s.currentView.LeaderIndex]
	if bftview.GetNodeID(leader.Address, leader.Public) != output.key.LeaderID || output.key.LeaderID != s.Self() {
		return false
	}
	var generation proposalGeneration
	switch {
	case output.txCandidate != nil && output.keyCandidate == nil:
		generation = output.txCandidate.generation
	case output.keyCandidate != nil && output.txCandidate == nil:
		generation = output.keyCandidate.generation
	default:
		return false
	}
	return generation.parentHash == s.currentView.TxHash && generation.parentNumber == s.currentView.TxNumber &&
		generation.keyHash == s.currentView.KeyHash && generation.keyNumber == s.currentView.KeyNumber
}

func (s *Service) ApplyFHSProposalBuild(result *hotstuff.FHSProposalBuildResult) error {
	if result == nil || result.Err != nil {
		return fmt.Errorf("invalid FHS proposal construction result")
	}
	output, ok := result.ApplicationData.(*proposalBuildOutput)
	if !ok || output == nil || output.key != result.Key || !bytes.Equal(output.proposalRef, result.TProposal) ||
		!bytes.Equal(output.extra, result.Extra) || output.manifest == nil || output.body == nil {
		return fmt.Errorf("FHS proposal construction result context mismatch")
	}
	s.muProposalBuild.Lock()
	buildLockTransferred := false
	defer func() {
		if !buildLockTransferred {
			s.muProposalBuild.Unlock()
		}
	}()
	active := s.activeProposalBuild
	activeMatch := active != nil && active.key == result.Key && active.generation == output.constructionGeneration
	if !activeMatch || atomic.LoadInt32(&s.runningState) != 1 ||
		atomic.LoadUint64(&s.proposalValidationGeneration) != output.serviceGeneration {
		return hotstuff.ErrOldState
	}
	if err := s.reserveProposalManifestDispatch(); err != nil {
		return err
	}
	manifestReserved := true
	defer func() {
		if manifestReserved {
			s.releaseProposalManifestDispatch()
		}
	}()
	cleanupReserved := false
	if output.txCandidate != nil && len(output.txCandidate.failedTxes) > 0 {
		if err := s.reserveProposalFailedTxCleanup(); err != nil {
			return err
		}
		cleanupReserved = true
		defer func() {
			if cleanupReserved {
				s.releaseProposalFailedTxCleanup()
			}
		}()
	}

	// Lock order is muProposalBuild -> muCurrentView -> txService.mu. No
	// txService publication path acquires muCurrentView while holding txService.mu.
	s.muCurrentView.Lock()
	currentViewLockTransferred := false
	defer func() {
		if !currentViewLockTransferred {
			s.muCurrentView.Unlock()
		}
	}()
	if !s.proposalBuildRouteMatchesLocked(output) || atomic.LoadInt32(&s.runningState) != 1 ||
		atomic.LoadUint64(&s.proposalValidationGeneration) != output.serviceGeneration {
		return hotstuff.ErrOldState
	}

	switch {
	case output.txCandidate != nil && output.keyCandidate == nil:
		if err := s.txService.installProposalCandidate(output.txCandidate, nil); err != nil {
			return err
		}
	case output.keyCandidate != nil && output.txCandidate == nil && output.keyBlock != nil && output.committee != nil:
		if err := s.txService.installKeyProposalCandidate(output.keyCandidate, func() error {
			if output.committee.RlpHash() != output.keyBlock.CommitteeHash() {
				return fmt.Errorf("key proposal committee commitment changed")
			}
			// A proposed (not committed) committee must be available for proposal
			// verification/recovery, but Committee_OnStored only adjusts live peer
			// connections for an already-canonical key block. Defer that callback to
			// the normal commit/verification path.
			if !output.committee.StoreWithoutCallback(output.keyBlock) {
				return fmt.Errorf("failed to persist proposed committee for key block %d/%s", output.keyBlock.NumberU64(), output.keyBlock.Hash())
			}
			return nil
		}); err != nil {
			return err
		}
	default:
		return fmt.Errorf("FHS proposal construction result has ambiguous candidate")
	}

	s.proposalManifestJobs <- &proposalManifestDispatch{
		body:              cloneProposalBodyMsg(output.manifest),
		destinations:      append([]string(nil), output.destinations...),
		serviceGeneration: output.serviceGeneration,
	}
	manifestReserved = false
	if cleanupReserved {
		s.proposalFailedTxJobs <- &proposalFailedTxCleanup{
			txs:               append(types.Transactions(nil), output.txCandidate.failedTxes...),
			serviceGeneration: output.serviceGeneration,
		}
		cleanupReserved = false
	}
	now := time.Now()
	s.muProposalCadence.Lock()
	s.lastProposeTime = now
	if output.blockType == types.SlowTx_Block {
		s.lastSlowBlockTime = now
	} else if output.blockType == types.FastTx_Block {
		s.lastFastBlockTime = now
	}
	s.muProposalCadence.Unlock()
	output.publicationLocksHeld = true
	currentViewLockTransferred = true
	buildLockTransferred = true
	return nil
}

// FinishFHSProposalBuild releases the publication barrier after the manager has
// cached, phase-transitioned and submitted the sealed Prepare. Apply transfers
// these locks only on success, and the manager defers this callback immediately,
// so Stop cannot linearize in the Apply-to-Broadcast gap.
func (s *Service) FinishFHSProposalBuild(result *hotstuff.FHSProposalBuildResult) {
	if result == nil {
		return
	}
	output, _ := result.ApplicationData.(*proposalBuildOutput)
	if output == nil || !output.publicationLocksHeld {
		return
	}
	output.publicationLocksHeld = false
	s.muCurrentView.Unlock()
	s.muProposalBuild.Unlock()
}

func (s *Service) finishProposalBuild(key hotstuff.FHSProposalBuildKey) {
	s.muProposalBuild.Lock()
	defer s.muProposalBuild.Unlock()
	active := s.activeProposalBuild
	if active == nil || active.key != key {
		return
	}
	if active.cancel != nil {
		active.cancel()
	}
	s.activeProposalBuild = nil
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

func (s *Service) cancelAllProposalBuilds() {
	s.muProposalBuild.Lock()
	defer s.muProposalBuild.Unlock()
	s.cancelAllProposalBuildsLocked()
}

// cancelAllProposalBuildsLocked requires muProposalBuild.
func (s *Service) cancelAllProposalBuildsLocked() {
	if active := s.activeProposalBuild; active != nil {
		if active.cancel != nil {
			active.cancel()
		}
		s.activeProposalBuild = nil
	}
	for {
		select {
		case stale := <-s.proposalBuildJobs:
			if stale != nil && stale.cancel != nil {
				stale.cancel()
			}
		default:
			return
		}
	}
}

// Propose call by hotstuff
func (s *Service) Propose(viewNumber uint64, viewID common.Hash, leaderID string) (e error, kState []byte, tState []byte, extra []byte) { //buf recv by onpropose, onviewdown
	if s.fairHotstuffEnabled() {
		return fmt.Errorf("Fair HotStuff proposal construction is asynchronous"), nil, nil, nil
	}
	log.Debug("Propose..", "number", s.GetCurrentView().TxNumber)

	proposeOK := false
	defer func() {
		if proposeOK {
			s.muProposalCadence.Lock()
			s.lastProposeTime = time.Now()
			s.muProposalCadence.Unlock()
		} else if !errors.Is(e, errProposalNoWork) {
			go func() {
				time.Sleep(failedProposalRetry)
				curView := s.GetCurrentView()
				if bftview.IamLeader(curView.LeaderIndex) {
					s.triggerTryPropose(s.bc.CurrentBlockN())
				}
			}()
		}
	}()

	if !s.isRunning() {
		err := fmt.Errorf("not running for propose")
		return err, nil, nil, nil
	}

	s.muCurrentView.Lock()
	leaderIndex := s.currentView.LeaderIndex
	noDone := s.currentView.NoDone
	if !s.replicaView.EqualConsensus(&s.currentView) {
		log.Error("Propose", "replica view not equal to local current view txNumber", s.currentView.TxNumber, "keyNumber", s.currentView.KeyNumber, "LeaderIndex", leaderIndex, "NoDone",
			s.currentView.NoDone, "replica txNumber", s.replicaView.TxNumber, "keyNumber", s.replicaView.KeyNumber, "LeaderIndex", s.replicaView.LeaderIndex, "NoDone", s.replicaView.NoDone)
		s.muCurrentView.Unlock()
		return fmt.Errorf("replica view not equal to local current view"), nil, nil, nil
	}
	if !bftview.IamLeader(leaderIndex) {
		//proposeOK = true
		err := fmt.Errorf("not leader for propose")
		log.Error("Propose", "leaderIndex", leaderIndex, "error", err)
		s.muCurrentView.Unlock()
		return err, nil, nil, nil
	}
	s.muCurrentView.Unlock()

	fixedMode := s.keyService.config != nil && (s.keyService.config.FixedLeader || s.keyService.config.FixedCommittee)
	keyBlockIntervalElapsed := true
	if curKeyblock := s.kbc.CurrentBlock(); curKeyblock != nil {
		lastKeyTime := time.Unix(int64(curKeyblock.Time()), 0)
		keyBlockIntervalElapsed = time.Since(lastKeyTime) >= params.KeyBlockMinInterval
		legacyKeyProposalSelected := leaderIndex > 0
		if fixedMode {
			legacyKeyProposalSelected = !noDone
		}
		if legacyKeyProposalSelected && !keyBlockIntervalElapsed {
			log.Debug("Propose keyblock suppressed by minimum interval",
				"elapsed", time.Since(lastKeyTime),
				"minimum", params.KeyBlockMinInterval,
				"lastKeyTime", lastKeyTime)
		}
	}

	keyProposalAttempt, keyProposalIsDone := keyProposalPlan(fixedMode, leaderIndex, noDone, keyBlockIntervalElapsed)
	if keyProposalAttempt && s.hasUncommittedFHSKeyBlock() {
		keyProposalAttempt = false
		log.Info("FHS keyblock proposal suppressed until certified keyblock finalizes",
			"currentTx", s.bc.CurrentBlockN(),
			"currentKey", s.kbc.CurrentBlockN())
	}

	if keyProposalAttempt {
		txParentNumber := fhsProposalParentNumber(s.bc.CurrentBlockN(), s.highestFHSCertifiedProposal())
		keyblock, mb, bestCandi, err := s.keyService.tryProposalChangeCommittee(leaderIndex, keyProposalIsDone, txParentNumber)
		if err == nil && keyblock != nil && mb != nil {
			if bestCandi != nil {
				extra = bestCandi.EncodeToBytes()
			}
			data, err := s.txService.tryProposalNewKeyBlock(keyblock)
			if err != nil {
				log.Warn("tryProposalNewKeyBlock", "error", err)
				if fixedMode {
					s.abortFixedModeKeyProposal("assemble failed", err)
				}
				return err, nil, nil, nil
			}
			proposalRef, err := s.prepareHotstuffProposal(viewNumber, viewID, leaderID, data, extra)
			if err != nil {
				log.Warn("prepare keyblock hotstuff proposal", "error", err)
				if fixedMode {
					s.abortFixedModeKeyProposal("prepare proposal failed", err)
				}
				return err, nil, nil, nil
			}
			if !mb.Store(keyblock) {
				return fmt.Errorf("failed to persist proposed committee for key block %d/%s", keyblock.NumberU64(), keyblock.Hash()), nil, nil, nil
			}
			proposeOK = true
			return nil, nil, proposalRef, extra
		} else {
			log.Error("tryProposalChangeCommittee failed", "error", err)
			if fixedMode {
				s.abortFixedModeKeyProposal("change committee failed", err)
			}
			return fmt.Errorf("tryProposalChangeCommittee failed"), nil, nil, nil
		}
	}
	workStamp, workStampValid := s.captureProposalWorkStamp(time.Now(), viewNumber, viewID, leaderID)
	blockType := s.chooseTxBlockType()
	data, err := s.txService.tryProposalNewBlock(blockType)
	if err != nil {
		primaryErr := err
		fallbackType := uint8(types.FastTx_Block)
		if blockType == types.FastTx_Block {
			fallbackType = types.SlowTx_Block
		}
		if !errors.Is(primaryErr, errProposalNoWork) {
			log.Warn("Primary tx block proposal failed, trying fallback lane",
				"primary", readableTxBlockType(blockType),
				"fallback", readableTxBlockType(fallbackType),
				"err", primaryErr)
		}
		fallbackData, fallbackErr := s.txService.tryProposalNewBlock(fallbackType)
		if fallbackErr == nil {
			data = fallbackData
			err = nil
			blockType = fallbackType
		} else {
			err = proposalLaneBuildError(primaryErr, fallbackErr)
		}
	}
	if err != nil {
		if errors.Is(err, errProposalNoWork) {
			s.rememberProposalNoWork(workStamp, workStampValid)
		} else {
			s.clearProposalNoWork()
			log.Warn("tryProposalNewBlock", "error", err)
		}
		return err, nil, nil, nil
	}
	proposalRef, err := s.prepareHotstuffProposal(viewNumber, viewID, leaderID, data, nil)
	if err != nil {
		s.clearProposalNoWork()
		log.Warn("prepare txblock hotstuff proposal", "error", err)
		return err, nil, nil, nil
	}
	now := time.Now()
	s.muProposalCadence.Lock()
	if blockType == types.SlowTx_Block {
		s.lastSlowBlockTime = now
	} else if blockType == types.FastTx_Block {
		s.lastFastBlockTime = now
	}
	s.muProposalCadence.Unlock()
	s.clearProposalNoWork()
	proposeOK = true
	return nil, nil, proposalRef, nil
}

func (s *Service) abortFixedModeKeyProposal(reason string, err error) {
	s.muCurrentView.Lock()
	defer s.muCurrentView.Unlock()

	if s.keyService == nil || !s.keyService.fixedModeEnabled() || s.currentView.NoDone {
		return
	}
	log.Warn("fixed-mode keyblock proposal aborted; returning to tx proposal view",
		"reason", reason,
		"err", err,
		"txNumber", s.currentView.TxNumber,
		"keyNumber", s.currentView.KeyNumber,
		"leaderIndex", s.currentView.LeaderIndex)
	s.currentView.NoDone = true
	// A failed fixed-mode keyblock proposal should not leave the service waiting
	// for a keyblock that was never committed. Reset the waiting watermark so the
	// next successful tx/key block can advance the view normally.
	s.waittingView.TxNumber = s.currentView.TxNumber
	s.waittingView.KeyNumber = s.currentView.KeyNumber
}

func (s *Service) fixedModeKeyblockIntervalElapsed(now time.Time) bool {
	if s.keyService == nil || !s.keyService.fixedModeEnabled() {
		return false
	}
	curKeyBlock := s.kbc.CurrentBlock()
	if curKeyBlock == nil {
		return false
	}
	lastKeyTime := time.Unix(int64(curKeyBlock.Time()), 0)
	return now.Sub(lastKeyTime) >= params.KeyBlockMinInterval
}

func (s *Service) fixedModeCandidateRewardReady(now time.Time) bool {
	if s.keyService == nil || !s.keyService.fixedModeEnabled() {
		return false
	}
	curKeyBlock := s.kbc.CurrentBlock()
	if curKeyBlock == nil {
		return false
	}

	lastKeyTime := time.Unix(int64(curKeyBlock.Time()), 0)
	elapsed := now.Sub(lastKeyTime)
	if elapsed < params.KeyBlockMinInterval {
		return false
	}

	// handleHotStuffMsg wakes every 1ms. Refreshing CandidatePool on every idle
	// loop floods logs and can burn CPU while the keyblock view is waiting.
	if !s.lastCandidateRewardCheck.IsZero() && now.Sub(s.lastCandidateRewardCheck) < 2*time.Second {
		return s.lastCandidateRewardReady
	}

	s.lastCandidateRewardCheck = now
	s.lastCandidateRewardReady = s.getBestCandidate(true) != nil
	return s.lastCandidateRewardReady
}

func (s *Service) repairFixedModeTxProposalViewIfPending(pendingTotal int) {
	if pendingTotal <= 0 || s.keyService == nil || !s.keyService.fixedModeEnabled() {
		return
	}
	curKeyBlock := s.kbc.CurrentBlock()
	if curKeyBlock == nil {
		return
	}

	now := time.Now()
	lastKeyTime := time.Unix(int64(curKeyBlock.Time()), 0)
	elapsed := now.Sub(lastKeyTime)

	// If keyblock interval has elapsed, do not interfere with normal keyblock proposal.
	if elapsed >= params.KeyBlockMinInterval {
		return
	}

	// Do not repair immediately after a tx block proposal was generated.
	// The proposal may still be in HotStuff consensus. Touching currentView /
	// waittingView while a tx block is in-flight can make the next view wait
	// for the wrong watermark.
	s.muProposalCadence.RLock()
	lastTxProposal := s.lastFastBlockTime
	if s.lastSlowBlockTime.After(lastTxProposal) {
		lastTxProposal = s.lastSlowBlockTime
	}
	s.muProposalCadence.RUnlock()
	if !lastTxProposal.IsZero() && now.Sub(lastTxProposal) < 2*time.Second {
		s.muCurrentView.Lock()
		txNumber := s.currentView.TxNumber
		keyNumber := s.currentView.KeyNumber
		leaderIndex := s.currentView.LeaderIndex
		noDone := s.currentView.NoDone
		s.muCurrentView.Unlock()

		log.Debug("skip fixed-mode tx proposal view repair; recent tx proposal in flight",
			"pendingTotal", pendingTotal,
			"sinceLastTxProposal", now.Sub(lastTxProposal),
			"elapsed", elapsed,
			"minimum", params.KeyBlockMinInterval,
			"txNumber", txNumber,
			"keyNumber", keyNumber,
			"leaderIndex", leaderIndex,
			"noDone", noDone)

		return
	}

	s.muCurrentView.Lock()
	defer s.muCurrentView.Unlock()

	if !s.currentView.NoDone {
		leaderIndex := s.keyService.getPrimaryLeaderIndex()
		if s.fairHotstuffEnabled() {
			leaderIndex = s.fairHotstuffLeaderIndexForCurrentLocked()
		}
		if mb := bftview.GetCurrentMember(); mb != nil && len(mb.List) > 0 && leaderIndex >= uint(len(mb.List)) {
			leaderIndex = 0
		}

		log.Warn("fixed-mode pending txs while keyblock interval not elapsed; forcing tx proposal view",
			"pendingTotal", pendingTotal,
			"elapsed", elapsed,
			"minimum", params.KeyBlockMinInterval,
			"txNumber", s.currentView.TxNumber,
			"keyNumber", s.currentView.KeyNumber,
			"oldLeaderIndex", s.currentView.LeaderIndex,
			"newLeaderIndex", leaderIndex)

		s.currentView.NoDone = true
		s.currentView.LeaderIndex = leaderIndex
		s.waittingView.TxNumber = s.currentView.TxNumber
		s.waittingView.KeyNumber = s.currentView.KeyNumber
	}
}

func (s *Service) normalizeLeaderIndex(index uint) uint {
	mb := bftview.GetCurrentMember()
	if mb == nil || len(mb.List) == 0 {
		return 0
	}
	if index >= uint(len(mb.List)) {
		return 0
	}
	return index
}

func (s *Service) fairHotstuffEnabled() bool {
	return s.chainConfig != nil && s.chainConfig.FairHotstuff
}

// refreshFHSRouteBaseLocked bootstraps/repairs the route view from canonical
// chain state without discarding a validator's newer certified/timeout view.
// This is important for common RPC nodes: they instantiate reconfig but do not
// run the validator pacemaker, so currentView must still be usable as a routing
// authority before miner.start is ever called on that node.
func (s *Service) refreshFHSRouteBaseLocked() error {
	if s == nil || !s.fairHotstuffEnabled() || s.bc == nil || s.kbc == nil {
		return fmt.Errorf("Fair HotStuff route is unavailable")
	}
	curBlock := s.bc.CurrentBlock()
	curKeyBlock := s.kbc.CurrentBlock()
	if curBlock == nil || curKeyBlock == nil {
		return fmt.Errorf("Fair HotStuff canonical heads are unavailable")
	}

	passive := atomic.LoadInt32(&s.runningState) == 0
	needsTxRefresh := s.currentView.TxHash == (common.Hash{}) || s.currentView.TxNumber < curBlock.NumberU64()
	if passive && s.currentView.TxNumber == curBlock.NumberU64() && s.currentView.TxHash != curBlock.Hash() {
		needsTxRefresh = true
	}
	needsKeyRefresh := s.currentView.KeyHash == (common.Hash{}) || s.currentView.KeyNumber < curKeyBlock.NumberU64()
	if passive && s.currentView.KeyNumber == curKeyBlock.NumberU64() && s.currentView.KeyHash != curKeyBlock.Hash() {
		needsKeyRefresh = true
	}

	routeBaseChanged := false
	if needsTxRefresh {
		s.currentView.TxNumber = curBlock.NumberU64()
		s.currentView.TxHash = curBlock.Hash()
		s.currentView.Round = 0
		s.currentView.NoDone = true

		canonicalView := curBlock.NumberU64()
		if signInfo := curBlock.SignInfo(); signInfo != nil && signInfo.ViewNumber > canonicalView {
			canonicalView = signInfo.ViewNumber
		}
		// A running validator may already know a newer TC/QC view than the
		// canonical head. Never move that pacemaker backwards. Passive/common
		// nodes, however, must advance to every newly imported canonical view.
		if canonicalView > s.currentView.ViewNumber {
			s.currentView.ViewNumber = canonicalView
		}
		routeBaseChanged = true
	}
	if needsKeyRefresh {
		s.currentView.KeyNumber = curKeyBlock.NumberU64()
		s.currentView.KeyHash = curKeyBlock.Hash()
		s.currentView.CommitteeHash = curKeyBlock.CommitteeHash()
		s.currentView.Round = 0
		s.currentView.NoDone = true
		routeBaseChanged = true
	}
	if s.currentView.CommitteeHash == (common.Hash{}) && s.currentView.KeyHash == curKeyBlock.Hash() {
		s.currentView.CommitteeHash = curKeyBlock.CommitteeHash()
		routeBaseChanged = true
	}

	// Common RPC nodes do not run the FHS pacemaker. Whenever canonical chain
	// import moves their route base, maintain currentView.LeaderIndex exactly as
	// a validator would: leader(currentView.ViewNumber+1, seed, committeeHash).
	// CurrentFHSRoute then reads this field as the sole leader authority.
	if routeBaseChanged {
		if s.currentView.ViewNumber == ^uint64(0) {
			return fmt.Errorf("Fair HotStuff proposal view overflow")
		}
		committee, err := s.loadViewCommittee(&s.currentView, false)
		if err != nil {
			return err
		}
		if committee == nil || len(committee.List) == 0 || committee.RlpHash() != s.currentView.CommitteeHash {
			return fmt.Errorf("Fair HotStuff route committee is unavailable")
		}
		leaderIndex, err := fairHotstuffLeaderIndex(
			s.chainConfig.FairHotstuffSeed,
			s.ChainID(),
			s.currentView.ViewNumber+1,
			s.currentView.CommitteeHash,
			len(committee.List),
		)
		if err != nil {
			return err
		}
		s.currentView.LeaderIndex = leaderIndex
	}
	return nil
}

// CurrentFHSRoute returns the single authoritative route for the next proposal
// view. The leader is always derived from
//
//	ProposalView + FairHotstuffSeed + CommitteeHash
//
// and currentView.LeaderIndex is repaired to that deterministic result before
// the route is published. fixedCommittee only freezes committee membership; it
// never selects committee index 0 as the Fair HotStuff leader.
func (s *Service) CurrentFHSRoute() (*FHSRoute, error) {
	if s == nil || !s.fairHotstuffEnabled() {
		return nil, fmt.Errorf("Fair HotStuff is not enabled")
	}

	// Committee/view transitions can race this read. Retry against a fresh
	// snapshot rather than combining a committee from one epoch with another
	// epoch's proposal view.
	for attempt := 0; attempt < 4; attempt++ {
		s.muCurrentView.Lock()
		if err := s.refreshFHSRouteBaseLocked(); err != nil {
			s.muCurrentView.Unlock()
			return nil, err
		}
		view := s.currentView
		s.muCurrentView.Unlock()

		if view.ViewNumber == ^uint64(0) {
			return nil, fmt.Errorf("Fair HotStuff proposal view overflow")
		}
		proposalView := view.ViewNumber + 1
		committee, err := s.loadViewCommittee(&view, true)
		if err != nil {
			return nil, err
		}
		if committee == nil || len(committee.List) == 0 || committee.RlpHash() != view.CommitteeHash {
			return nil, fmt.Errorf("Fair HotStuff route committee is unavailable")
		}

		// currentView.LeaderIndex is the single authoritative leader selector.
		// Recompute only as an invariant check; never infer a replacement from
		// committee ordering and never silently route to index 0.
		expectedIndex, err := fairHotstuffLeaderIndex(
			s.chainConfig.FairHotstuffSeed,
			s.ChainID(),
			proposalView,
			view.CommitteeHash,
			len(committee.List),
		)
		if err != nil {
			return nil, err
		}
		if view.LeaderIndex != expectedIndex {
			return nil, fmt.Errorf("Fair HotStuff leader invariant mismatch: proposalView=%d currentView.LeaderIndex=%d deterministic=%d", proposalView, view.LeaderIndex, expectedIndex)
		}
		if view.LeaderIndex >= uint(len(committee.List)) || committee.List[view.LeaderIndex] == nil {
			return nil, fmt.Errorf("Fair HotStuff leader index %d is outside committee", view.LeaderIndex)
		}

		s.muCurrentView.Lock()
		// If a QC/TC or key transition moved the view while the committee was
		// resolved, restart with the new authoritative state.
		if s.currentView.ViewNumber != view.ViewNumber ||
			s.currentView.KeyNumber != view.KeyNumber ||
			s.currentView.KeyHash != view.KeyHash ||
			s.currentView.CommitteeHash != view.CommitteeHash ||
			s.currentView.LeaderIndex != view.LeaderIndex {
			s.muCurrentView.Unlock()
			continue
		}
		s.muCurrentView.Unlock()

		leader := committee.List[view.LeaderIndex]
		leaderCopy := *leader
		leaderID := bftview.GetNodeID(leader.Address, leader.Public)
		if leaderID == "" {
			return nil, fmt.Errorf("Fair HotStuff leader identity is empty")
		}
		committeeCopy := make([]*common.Cnode, len(committee.List))
		for index, member := range committee.List {
			if member == nil {
				return nil, fmt.Errorf("Fair HotStuff committee member %d is nil", index)
			}
			memberCopy := *member
			committeeCopy[index] = &memberCopy
		}
		return &FHSRoute{
			Enabled:       true,
			CurrentView:   view.ViewNumber,
			ProposalView:  proposalView,
			TxNumber:      view.TxNumber,
			TxHash:        view.TxHash,
			KeyNumber:     view.KeyNumber,
			KeyHash:       view.KeyHash,
			CommitteeHash: view.CommitteeHash,
			LeaderIndex:   view.LeaderIndex,
			LeaderID:      leaderID,
			Leader:        &leaderCopy,
			Committee:     committeeCopy,
		}, nil
	}
	return nil, fmt.Errorf("Fair HotStuff route changed repeatedly while resolving")
}

// CurrentFHSRoute exposes the service route to subsystems (notably TxQUIC)
// without exporting the Service field from ReconfigBackend.
func (backend *ReconfigBackend) CurrentFHSRoute() (*FHSRoute, error) {
	if backend == nil || backend.service == nil {
		return nil, fmt.Errorf("reconfig service is unavailable")
	}
	return backend.service.CurrentFHSRoute()
}

// TxQUICReceiptPublicKey returns the validator identity that signs durable
// ingress acknowledgements. It is the same BLS identity committed in the FHS
// committee, not a replaceable TLS certificate key.
func (backend *ReconfigBackend) TxQUICReceiptPublicKey() ([]byte, error) {
	if backend == nil || backend.service == nil {
		return nil, fmt.Errorf("Fair HotStuff receipt identity is unavailable")
	}
	return backend.service.txQUICReceiptPublicKey()
}

// PoWResultTLSPublicKey returns the consensus BLS identity used to authenticate
// the fixed-mode PoW result listener.
func (backend *ReconfigBackend) PoWResultTLSPublicKey() ([]byte, error) {
	if backend == nil || backend.service == nil {
		return nil, fmt.Errorf("PoW result TLS identity is unavailable")
	}
	return backend.service.txQUICReceiptPublicKey()
}

func (s *Service) txQUICReceiptPublicKey() ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("Fair HotStuff receipt identity is unavailable")
	}
	s.muConsensusIdentity.RLock()
	secret, public := s.txQUICReceiptSecret, s.txQUICReceiptPublic
	s.muConsensusIdentity.RUnlock()
	if secret == nil || public == nil {
		return nil, fmt.Errorf("Fair HotStuff receipt identity is unavailable")
	}
	derived := secret.GetPublicKey()
	if derived == nil || !derived.IsEqual(public) {
		return nil, fmt.Errorf("Fair HotStuff receipt key pair is inconsistent")
	}
	return append([]byte(nil), public.Serialize()...), nil
}

// SignTxQUICReceipt signs one domain-separated TxQUIC acknowledgement digest
// only while this node's BLS key is a member of the exact canonical committee
// generation carried by the packet and acknowledgement.
func (backend *ReconfigBackend) SignTxQUICReceipt(keyNumber uint64, committeeHash common.Hash, digest []byte) ([]byte, error) {
	if backend == nil || backend.service == nil {
		return nil, fmt.Errorf("Fair HotStuff receipt signer is unavailable")
	}
	return backend.service.signTxQUICReceiptForGeneration(keyNumber, committeeHash, digest)
}

// SignPoWResultTLS signs a PoW-result transport certificate digest while the
// local consensus identity belongs to the canonical committee. Unlike a
// TxQUIC receipt, the TLS host identity is the validator's long-lived BLS key,
// so this check works for both legacy and Fair HotStuff fixed committees.
func (backend *ReconfigBackend) SignPoWResultTLS(generation common.Hash, digest []byte) ([]byte, error) {
	if backend == nil || backend.service == nil {
		return nil, fmt.Errorf("PoW result TLS signer is unavailable")
	}
	return backend.service.signPoWResultTLS(generation, digest)
}

func (s *Service) signPoWResultTLS(generation common.Hash, digest []byte) ([]byte, error) {
	if s == nil || generation == (common.Hash{}) || s.kbc == nil {
		return nil, fmt.Errorf("PoW result TLS signer is unavailable")
	}
	// The BLS implementation is not safe for concurrent use. Share the receipt
	// signer serialization because both protocols use the isolated receipt key.
	s.txQUICReceiptSignMu.Lock()
	defer s.txQUICReceiptSignMu.Unlock()
	keyBlock := s.kbc.CurrentBlock()
	if keyBlock == nil || keyBlock.Hash() != generation {
		return nil, fmt.Errorf("PoW result TLS keyblock generation changed before signing")
	}
	committee := bftview.GetCurrentMember()
	if committee == nil || len(committee.List) == 0 {
		return nil, fmt.Errorf("canonical PoW result committee is unavailable")
	}
	signature, err := s.signTxQUICReceiptLocked(digest, committee.List)
	if err != nil {
		return nil, err
	}
	keyBlock = s.kbc.CurrentBlock()
	if keyBlock == nil || keyBlock.Hash() != generation {
		return nil, fmt.Errorf("PoW result TLS keyblock generation changed while signing")
	}
	return signature, nil
}

func (s *Service) signTxQUICReceiptForGeneration(keyNumber uint64, committeeHash common.Hash, digest []byte) ([]byte, error) {
	if s == nil || committeeHash == (common.Hash{}) {
		return nil, fmt.Errorf("invalid Fair HotStuff receipt generation")
	}
	// Serialize the non-thread-safe BLS secret before taking the view lock. ACK
	// bursts then wait without blocking HotStuff view/QC transitions.
	s.txQUICReceiptSignMu.Lock()
	defer s.txQUICReceiptSignMu.Unlock()
	// Hold the authoritative view lock through the short membership check and
	// BLS operation. A key-block transition cannot move the committee between
	// validation and signing.
	s.muCurrentView.Lock()
	defer s.muCurrentView.Unlock()
	if err := s.refreshFHSRouteBaseLocked(); err != nil {
		return nil, err
	}
	view := s.currentView
	if view.KeyNumber != keyNumber || view.CommitteeHash != committeeHash {
		return nil, fmt.Errorf("Fair HotStuff committee changed before TxQUIC receipt signing")
	}
	committee, err := s.loadViewCommittee(&view, true)
	if err != nil {
		return nil, err
	}
	if committee == nil || len(committee.List) == 0 || committee.RlpHash() != committeeHash {
		return nil, fmt.Errorf("Fair HotStuff receipt committee is unavailable")
	}
	return s.signTxQUICReceiptLocked(digest, committee.List)
}

func (s *Service) signTxQUICReceiptLocked(digest []byte, committee []*common.Cnode) ([]byte, error) {
	publicKey, err := s.txQUICReceiptPublicKey()
	if err != nil {
		return nil, err
	}
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("invalid TxQUIC receipt digest length")
	}
	authorized := false
	for _, member := range committee {
		if member == nil {
			continue
		}
		candidate := bls.GetPublicKey(common.FromHex(member.Public))
		if candidate != nil && bytes.Equal(candidate.Serialize(), publicKey) {
			authorized = true
			break
		}
	}
	if !authorized {
		return nil, fmt.Errorf("local TxQUIC receipt signer is outside the active committee")
	}
	s.muConsensusIdentity.RLock()
	secret := s.txQUICReceiptSecret
	s.muConsensusIdentity.RUnlock()
	if secret == nil {
		return nil, fmt.Errorf("Fair HotStuff receipt signing key is unavailable")
	}
	signature := secret.SignHash(digest)
	if signature == nil {
		return nil, fmt.Errorf("failed to sign TxQUIC receipt")
	}
	return append([]byte(nil), signature.Serialize()...), nil
}

func (s *Service) fairHotstuffLeaderIndexForTargetLocked(targetView uint64, committeeHash common.Hash) uint {
	if s.chainConfig == nil || s.chainConfig.FairHotstuffSeed == (common.Hash{}) || targetView == 0 ||
		committeeHash == (common.Hash{}) || committeeHash != s.currentView.CommitteeHash {
		return 0
	}
	// Resolve the committee from the same historical key block whose hash is in
	// the PRF input. The mutable global current committee can switch before the
	// view fields do, which would otherwise combine an old hash with a new size.
	view := s.currentView
	committee, err := s.loadViewCommittee(&view, false)
	if err != nil || committee == nil || len(committee.List) == 0 || committee.RlpHash() != committeeHash {
		return 0
	}
	index, err := fairHotstuffLeaderIndex(s.chainConfig.FairHotstuffSeed, s.ChainID(), targetView, committeeHash, len(committee.List))
	if err != nil {
		return 0
	}
	return index
}

func fairHotstuffLeaderIndex(seed common.Hash, chainID, targetView uint64, committeeHash common.Hash, committeeSize int) (uint, error) {
	if seed == (common.Hash{}) || chainID == 0 || targetView == 0 || committeeHash == (common.Hash{}) || committeeSize <= 0 {
		return 0, fmt.Errorf("invalid Fair HotStuff leader election input")
	}
	n := uint64(committeeSize)
	// Rejection sampling avoids the modulo bias that would otherwise make the
	// first (2^64 mod n) committee indices slightly more likely.
	cutoff := -n % n
	for counter := uint64(0); ; counter++ {
		h := sha256.New()
		h.Write([]byte("cypher-fhs-leader-v2"))
		h.Write(seed[:])
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], chainID)
		h.Write(encoded[:])
		binary.BigEndian.PutUint64(encoded[:], targetView)
		h.Write(encoded[:])
		h.Write(committeeHash[:])
		binary.BigEndian.PutUint64(encoded[:], counter)
		h.Write(encoded[:])
		sum := h.Sum(nil)
		candidate := binary.BigEndian.Uint64(sum[:8])
		if candidate >= cutoff {
			return uint(candidate % n), nil
		}
	}
}

func (s *Service) fairHotstuffLeaderIndexFromBlockLocked(block *types.Block) uint {
	// The block and its QC are deliberately not entropy sources. A Byzantine
	// leader can choose the block contents and the 2f+1 signer subset.
	return s.fairHotstuffLeaderIndexForTargetLocked(s.currentView.ViewNumber+1, s.currentView.CommitteeHash)
}

func (s *Service) fairHotstuffLeaderIndexForCurrentLocked() uint {
	return s.fairHotstuffLeaderIndexForTargetLocked(s.currentView.ViewNumber+1, s.currentView.CommitteeHash)
}

func (s *Service) leaderAckRecent(index uint) bool {
	mb := bftview.GetCurrentMember()
	if mb == nil || len(mb.List) == 0 || index >= uint(len(mb.List)) {
		return false
	}

	node := mb.List[index]
	if node == nil || node.Address == "" {
		return false
	}
	if IsSelf(node.Address) {
		return true
	}

	ack := s.netService.GetAckTime(node.Address)
	if ack.IsZero() {
		return false
	}
	return time.Since(ack) <= params.AckTimeout
}

func (s *Service) resetFixedModeKeyblockViewLocked() {
	s.fixedKeyViewStartedAt = time.Time{}
	s.fixedKeyViewTxNumber = 0
	s.fixedKeyViewKeyNumber = 0
	s.fixedKeyViewTxHash = common.Hash{}
	s.fixedKeyViewKeyHash = common.Hash{}
	s.fixedKeyViewLeader = 0
	s.fixedKeyFallbackRound = 0
}

func (s *Service) fixedModeKeyblockViewStateChangedLocked() bool {
	return s.fixedKeyViewStartedAt.IsZero() ||
		s.fixedKeyViewTxNumber != s.currentView.TxNumber ||
		s.fixedKeyViewKeyNumber != s.currentView.KeyNumber ||
		s.fixedKeyViewTxHash != s.currentView.TxHash ||
		s.fixedKeyViewKeyHash != s.currentView.KeyHash
}

func (s *Service) fixedModeKeyblockViewStart(now time.Time) time.Time {
	start := now
	if block := s.bc.CurrentBlock(); block != nil {
		start = time.Unix(int64(block.Time()), 0)
	}
	return fixedModeKeyblockViewStartFromHeads(now, start, s.kbc.CurrentBlock())
}

func fixedModeKeyblockViewStartFromHeads(now, start time.Time, keyBlock *types.KeyBlock) time.Time {
	if keyBlock != nil {
		if keyBlock.IsZeroTimeGenesis() {
			return now
		}
		keyReadyAt := time.Unix(int64(keyBlock.Time()), 0).Add(params.KeyBlockMinInterval)
		if keyReadyAt.After(start) {
			start = keyReadyAt
		}
	}
	if start.After(now) {
		return now
	}
	return start
}

func fixedModeKeyblockLeader(primary uint) (leader uint, fallbackRound uint) {
	return primary, 0
}

func (s *Service) prepareFixedModeKeyblockView(now time.Time) (oldView bftview.View, curView bftview.View, fallbackRound uint, viewAge time.Duration) {
	s.muCurrentView.Lock()
	defer s.muCurrentView.Unlock()

	oldView = s.currentView

	primary := uint(0)
	if s.fairHotstuffEnabled() {
		primary = s.fairHotstuffLeaderIndexForCurrentLocked()
	} else if s.keyService != nil {
		primary = s.keyService.getPrimaryLeaderIndex()
	}
	primary = s.normalizeLeaderIndex(primary)

	if s.fixedModeKeyblockViewStateChangedLocked() {
		// Derive the timeout origin from committed chain data. Local ACK times and
		// process start times are not consensus state and previously split nodes
		// between the primary and fallback leaders for the same view.
		s.fixedKeyViewStartedAt = s.fixedModeKeyblockViewStart(now)
		s.fixedKeyViewTxNumber = s.currentView.TxNumber
		s.fixedKeyViewKeyNumber = s.currentView.KeyNumber
		s.fixedKeyViewTxHash = s.currentView.TxHash
		s.fixedKeyViewKeyHash = s.currentView.KeyHash
		s.fixedKeyViewLeader = primary
		s.fixedKeyFallbackRound = 0
		if s.keyService != nil {
			s.keyService.setActiveLeader(primary)
		}
	}

	viewAge = now.Sub(s.fixedKeyViewStartedAt)
	if viewAge < 0 {
		viewAge = 0
	}
	nextRound := uint64(0)
	if fixedModeKeyblockViewRoundDuration > 0 {
		nextRound = uint64(viewAge / fixedModeKeyblockViewRoundDuration)
	}
	if s.fixedKeyViewLeader != primary {
		log.Info("fixed-mode keyblock restoring deterministic primary leader",
			"from", s.fixedKeyViewLeader,
			"to", primary,
			"viewAge", viewAge)
	}
	// Local heartbeat/ACK observations are not consensus state. Using them to
	// select a fallback split healthy nodes across different LeaderIndex values.
	// With protocol-level retransmission, a live primary self-recovers without a
	// leader change. A future down-node fallback must be quorum-certified.
	s.fixedKeyViewLeader, s.fixedKeyFallbackRound = fixedModeKeyblockLeader(primary)
	if s.keyService != nil {
		s.keyService.setActiveLeader(primary)
	}

	s.currentView.LeaderIndex = s.normalizeLeaderIndex(s.fixedKeyViewLeader)
	s.currentView.NoDone = false
	if s.currentView.Round != nextRound {
		log.Warn("fixed-mode keyblock advancing recovery round",
			"oldRound", s.currentView.Round,
			"round", nextRound,
			"viewAge", viewAge,
			"roundDuration", fixedModeKeyblockViewRoundDuration,
			"currentBlock", s.bc.CurrentBlockN(),
			"currentKey", s.kbc.CurrentBlockN())
		s.currentView.Round = nextRound
	}
	s.waittingView.TxNumber = s.currentView.TxNumber + 1
	s.waittingView.KeyNumber = s.currentView.KeyNumber + 1

	curView = s.currentView
	fallbackRound = s.fixedKeyFallbackRound
	return oldView, curView, fallbackRound, viewAge
}

func (s *Service) enqueueHotstuffPriority(msg *hotstuffMsg) bool {
	if s == nil || s.hotstuffMsgQ == nil || msg == nil {
		return false
	}
	if !s.hotstuffMsgQ.pushPriority(msg) {
		code := uint32(0)
		if msg.hMsg != nil {
			code = msg.hMsg.Code
		}
		log.Debug("drop hotstuff priority message after bounded queue backpressure", "code", hotstuff.ReadableMsgType(code))
		return false
	}
	return true
}

func (s *Service) enqueueHotstuff(msg *hotstuffMsg) {
	if s == nil || s.hotstuffMsgQ == nil || msg == nil {
		return
	}
	if !s.hotstuffMsgQ.push(msg) {
		code := uint32(0)
		if msg.hMsg != nil {
			code = msg.hMsg.Code
		}
		log.Debug("drop hotstuff network message after bounded queue backpressure", "code", hotstuff.ReadableMsgType(code))
	}
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

func (s *Service) wakeFixedModeKeyblock(now time.Time, reason string, candidateRewardReady bool, pendingTotal, fastPending, slowPending int) bool {
	if atomic.LoadInt32(&s.runningState) != 1 || bftview.IamMember() < 0 {
		return false
	}
	if !s.fixedModeKeyblockIntervalElapsed(now) {
		return false
	}
	s.clearProposalNoWork()

	s.muCurrentView.Lock()
	if !s.lastFixedKeyNewViewWakeup.IsZero() && now.Sub(s.lastFixedKeyNewViewWakeup) < fixedModeKeyblockWakeupInterval {
		s.muCurrentView.Unlock()
		return true
	}
	s.lastFixedKeyNewViewWakeup = now
	s.muCurrentView.Unlock()

	oldView, curView, fallbackRound, viewAge := s.prepareFixedModeKeyblockView(now)
	log.Warn("fixed-mode keyblock start-new-view wakeup",
		"reason", reason,
		"currentBlock", s.bc.CurrentBlockN(),
		"currentKey", s.kbc.CurrentBlockN(),
		"oldLeaderIndex", oldView.LeaderIndex,
		"oldNoDone", oldView.NoDone,
		"leaderIndex", curView.LeaderIndex,
		"noDone", curView.NoDone,
		"round", curView.Round,
		"fallbackRound", fallbackRound,
		"viewAge", viewAge,
		"isLeader", bftview.IamLeader(curView.LeaderIndex),
		"candidateReady", candidateRewardReady,
		"pendingTotal", pendingTotal,
		"fastPending", fastPending,
		"slowPending", slowPending)

	curN := s.bc.CurrentBlockN()
	s.sendNewViewMsg(curN)
	s.enqueueTimerPriority(curN)
	return true
}

func (s *Service) keyblockLivenessLoop() {
	ticker := time.NewTicker(fixedModeKeyblockWatchdogInterval)
	defer ticker.Stop()
	for now := range ticker.C {
		if atomic.LoadInt32(&s.runningState) != 1 || bftview.IamMember() < 0 {
			continue
		}
		if !s.fixedModeKeyblockIntervalElapsed(now) {
			continue
		}
		if s.proposalNoWorkUnchanged(now) {
			continue
		}
		fastPending, slowPending := s.lanePendingCounts()
		pendingTotal := 0
		if s.txPool != nil {
			pendingTotal, _ = s.txPool.Stats()
		}
		s.purgeExpiredProposalCaches(now)
		s.wakeFixedModeKeyblock(now, "watchdog", false, pendingTotal, fastPending, slowPending)
	}
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

// OnViewDone call by hotstuff
func (s *Service) OnViewDone(tSign *hotstuff.SignedState) error {
	if !s.isRunning() {
		return types.ErrNotRunning
	}
	if tSign == nil {
		log.Warn("OnViewDone nil!")
		return nil
	}
	if s.fairHotstuffEnabled() {
		return fmt.Errorf("MsgDecide commit is disabled in FHS 2-chain mode")
	}
	ref, err := types.DecodeHotstuffProposalRef(tSign.State)
	if err != nil {
		log.Error("OnViewDone decode proposal ref", "err", err)
		return err
	}
	proposalID := ref.ProposalID()
	verified := s.getVerifiedProposal(proposalID)
	if verified == nil {
		log.Warn("OnViewDone verified proposal cache miss; revalidating before commit", "number", ref.Number, "proposalID", proposalID)
		body, err := s.waitProposalBody(ref)
		if err != nil {
			return err
		}
		block := types.DecodeToBlock(body.EncodedBlock)
		if block == nil {
			return fmt.Errorf("DecodeToBlock(proposal body) error")
		}
		if err := ref.VerifyAgainstBlock(block, body.EncodedBlock); err != nil {
			return err
		}
		verified, err = s.txService.verifyHotstuffProposal(ref, block, nil)
		if err != nil {
			return err
		}
	}
	if err := s.txService.decideVerifiedProposal(ref, verified, tSign.Sign, tSign.Mask, tSign.Number, tSign.ViewID, tSign.LeaderID); err != nil {
		return err
	}
	s.deleteProposalCaches(proposalID)
	return nil
}

// Write call by hotstuff------------------------------------------------------------------------------------------------
func (s *Service) Write(id string, data *hotstuff.HotstuffMessage) error {
	if atomic.LoadInt32(&s.runningState) != 1 {
		return types.ErrNotRunning
	}
	log.Info("Write", "to id", id, "code", hotstuff.ReadableMsgType(data.Code), "ViewId", data.ViewId)

	if id == s.Self() {
		if !s.enqueueHotstuffPriority(&hotstuffMsg{sid: nil, hMsg: cloneHotstuffMessage(data)}) {
			return fmt.Errorf("local HotStuff priority queue is full")
		}
		return nil
	}

	mb := bftview.GetCurrentMember()
	if mb == nil {
		return fmt.Errorf("can't find current committee,id %s", id)
	}
	node, _ := mb.Get(id, bftview.ID)
	if node == nil || len(node.Address) < 7 { //1.1.1.1
		err := fmt.Errorf("can't find id %s in current committee", id)
		log.Error("Couldn't send", "err", err)
		return err
	}

	if err := s.netService.SendRawData(node.Address, &networkMsg{Hmsg: data}); err != nil {
		return err
	}
	return nil
}

// Broadcast call by hotstuff
func (s *Service) Broadcast(data *hotstuff.HotstuffMessage) []error {
	if atomic.LoadInt32(&s.runningState) != 1 {
		return []error{types.ErrNotRunning}
	}
	if data == nil {
		return []error{fmt.Errorf("nil hotstuff message")}
	}
	log.Debug("Broadcast", "code", hotstuff.ReadableMsgType(data.Code), "ViewId", data.ViewId)
	log.Info("HOTSTUFF BROADCAST",
		"code", hotstuff.ReadableMsgType(data.Code),
		"number", data.Number,
		"viewID", data.ViewId,
		"dataA", len(data.DataA),
		"dataB", len(data.DataB),
		"dataC", len(data.DataC),
		"dataD", len(data.DataD),
		"dataE", len(data.DataE),
		"dataF", len(data.DataF),
		"dataG", len(data.DataG))

	// Local delivery is retained for protocol correctness. Leader self-vote
	// optimization belongs in hotstuff.go and must preserve quorum accounting.
	s.enqueueHotstuffPriority(&hotstuffMsg{sid: nil, hMsg: cloneHotstuffMessage(data)})

	// Production rule: HotStuff control messages use direct committee delivery.
	// Large proposal bodies are distributed as proposalBodyMsg sidecars, not in
	// MsgPrepare.DataB.
	switch data.Code {
	case hotstuff.MsgPrepare, hotstuff.MsgQCBroadcast, hotstuff.MsgDecide, hotstuff.MsgTimeout, hotstuff.MsgTimeoutQC:
		return s.broadcastHotstuffToCommittee(data)
	default:
		s.netService.broadcast("", &networkMsg{Hmsg: data})
		return nil
	}
}

func (s *Service) broadcastHotstuffToCommittee(data *hotstuff.HotstuffMessage) []error {
	mb, err := s.hotstuffBroadcastCommittee(data)
	if err != nil {
		return []error{err}
	}
	if mb == nil {
		return []error{fmt.Errorf("can't find current committee")}
	}
	var errs []error
	for _, node := range mb.List {
		if node == nil || node.Address == "" || IsSelf(node.Address) {
			continue
		}
		log.Info("HOTSTUFF DIRECT SEND",
			"to", node.Address,
			"code", hotstuff.ReadableMsgType(data.Code),
			"number", data.Number,
			"viewID", data.ViewId,
			"dataB", len(data.DataB))
		if err := s.netService.SendRawData(node.Address, &networkMsg{Hmsg: data}); err != nil {
			errs = append(errs, err)
			log.Warn("HOTSTUFF DIRECT SEND failed", "to", node.Address, "number", data.Number, "err", err)
		}
	}
	return errs
}

// hotstuffBroadcastCommittee pins Prepare delivery to the committee generation
// committed by its proposal reference. A concurrent finalized-sync key change
// must never redirect an old-epoch Prepare to the newly current committee.
func (s *Service) hotstuffBroadcastCommittee(data *hotstuff.HotstuffMessage) (*bftview.Committee, error) {
	if data == nil {
		return nil, fmt.Errorf("nil hotstuff broadcast")
	}
	if data.Code == hotstuff.MsgQCBroadcast && s.fairHotstuffEnabled() {
		return s.fhsQCBroadcastCommittee(data)
	}
	if data.Code != hotstuff.MsgPrepare {
		return bftview.GetCurrentMember(), nil
	}
	ref, err := types.DecodeHotstuffProposalRef(data.DataB)
	if err != nil || ref == nil {
		return nil, fmt.Errorf("decode Prepare proposal committee: %w", err)
	}
	if s.kbc == nil || ref.KeyHash == (common.Hash{}) {
		return nil, fmt.Errorf("missing Prepare proposal committee %s", ref.KeyHash)
	}
	_, committee, _, err := s.resolveExactFHSCommittee(ref.KeyHash, true)
	if err != nil || committee == nil || len(committee.List) == 0 {
		return nil, fmt.Errorf("can't find Prepare committee %s: %w", ref.KeyHash, err)
	}
	return committee, nil
}

func (s *Service) networkMsgAck(si *network.ServerIdentity, msg *networkMsg) {
	if msg == nil {
		return
	}
	if msg.Pmsg != nil {
		s.handleProposalBodyMsg(si, msg.Pmsg)
		return
	}
	if msg.Hmsg != nil {
		if err := hotstuff.ValidateHotstuffWireMessage(msg.Hmsg); err != nil {
			log.Warn("reject malformed hotstuff wire message", "code", hotstuff.ReadableMsgType(msg.Hmsg.Code), "err", err)
			return
		}
		if err := s.validateHotstuffTransportSender(si, msg.Hmsg); err != nil {
			log.Warn("reject unauthenticated hotstuff transport sender", "from", msg.Hmsg.Id, "code", hotstuff.ReadableMsgType(msg.Hmsg.Code), "err", err)
			return
		}
		s.enqueueHotstuff(&hotstuffMsg{sid: si, hMsg: msg.Hmsg})
		return
	}
	s.feed1.Send(committeeMsg{sid: si, cinfo: msg.Cmsg, best: msg.Bmsg})
}

func (s *Service) validateHotstuffTransportSender(si *network.ServerIdentity, msg *hotstuff.HotstuffMessage) error {
	if msg == nil {
		return fmt.Errorf("nil hotstuff message")
	}
	if si == nil {
		if hotstuff.IsHotstuffWireCode(msg.Code) && msg.Id != s.Self() {
			return fmt.Errorf("local hotstuff origin %q is not self", msg.Id)
		}
		return nil
	}
	if !hotstuff.IsHotstuffWireCode(msg.Code) {
		return fmt.Errorf("remote pseudo hotstuff message")
	}
	if si.Address.String() == "" || si.Address.String() != msg.Id {
		return fmt.Errorf("transport identity %q does not match envelope %q", si.Address.String(), msg.Id)
	}
	return nil
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

// -------------------------------------------------------------------------------------------------------------------------
func (s *Service) syncCommittee(mb *bftview.Committee, keyblock *types.KeyBlock) {
	if !keyblock.HasNewNode() {
		return
	}

	in := mb.In()
	s.netService.SendRawData(in.Address, &networkMsg{Cmsg: &committeeInfo{Committee: mb, KeyHash: keyblock.Hash(), KeyNumber: keyblock.NumberU64()}})

	msg := &bestCandidateInfo{Node: in, KeyHash: keyblock.Hash(), KeyNumber: keyblock.NumberU64()}
	//s.netService.broadcast("", &networkMsg{Bmsg: msg})
	for i, r := range mb.List {
		if i == 0 || IsSelf(r.Address) {
			continue
		}
		log.Debug("syncBestCandidate", "send to", r.Address)
		s.netService.SendRawData(r.Address, &networkMsg{Bmsg: msg})
	}
}

func (s *Service) storeCommitteeInCache(cmInfo *committeeInfo, best *bestCandidateInfo) {
	s.muCommitteeInfo.Lock()
	defer s.muCommitteeInfo.Unlock()
	var (
		keyHash   common.Hash
		keyNumber uint64
		committee *bftview.Committee
		node      *common.Cnode
	)
	if cmInfo != nil {
		keyHash = cmInfo.KeyHash
		keyNumber = cmInfo.KeyNumber
		committee = cmInfo.Committee
	} else if best != nil {
		keyHash = best.KeyHash
		keyNumber = best.KeyNumber
		node = best.Node
	}

	ac, ok := s.lastCmInfoMap[keyHash]
	if ok {
		if cmInfo != nil {
			ac.committee = cmInfo.Committee
		}
		if best != nil {
			ac.node = best.Node
		}
		return
	}
	//clear prev map
	maxNumber := s.kbc.CurrentBlockN()
	for hash, ac := range s.lastCmInfoMap {
		if ac.keyNumber < maxNumber-9 {
			delete(s.lastCmInfoMap, hash)
		}
	}
	log.Info("@@storeCommitteeInCache", "key number", keyNumber)

	s.lastCmInfoMap[keyHash] = &cachedCommitteeInfo{keyHash: keyHash, keyNumber: keyNumber, committee: committee, node: node}
}

// handle committee sync message
func (s *Service) handleCommitteeMsg() {
	for {
		select {
		case msg := <-s.msgCh1:
			if msg.best != nil {
				if bftview.LoadMember(msg.best.KeyNumber, msg.best.KeyHash, true) != nil {
					continue
				}
				log.Info("bestCandidate", "best KeyNumber", msg.best.KeyNumber)
				s.storeCommitteeInCache(nil, msg.best)
				continue
			}
			cInfo := msg.cinfo
			if cInfo == nil {
				continue
			}
			if cInfo.Committee == nil {
				mb := bftview.LoadMember(cInfo.KeyNumber, cInfo.KeyHash, true)
				if mb == nil {
					continue
				}
				msgAddress := msg.sid.Address.String()
				log.Debug("committeeInfo answer", "number", cInfo.KeyNumber, "adddress", msgAddress)
				r, _ := mb.Get(msgAddress, bftview.Address)
				if r != nil {
					log.Debug("committeeInfo answer..ok", "number", cInfo.KeyNumber)
					s.netService.SendRawData(msgAddress, &networkMsg{Cmsg: &committeeInfo{Committee: mb, KeyHash: cInfo.KeyHash, KeyNumber: cInfo.KeyNumber}})
				}
				continue
			}

			if bftview.LoadMember(cInfo.KeyNumber, cInfo.KeyHash, true) != nil {
				continue
			}
			log.Debug("committeeInfo", "number", cInfo.KeyNumber, "adddress", msg.sid.Address)
			keyblock := s.kbc.GetBlock(cInfo.KeyHash, cInfo.KeyNumber)
			if keyblock != nil {
				cInfo.Committee.Store(keyblock)
			} else {
				s.storeCommitteeInCache(cInfo, nil)
			}

		case <-s.msgSub1.Err():
			log.Error("handleHotStuffMsg Feed error")
			return
		}
	}
}

// Save committee by keyblock
func (s *Service) saveCommittee(curKeyBlock *types.KeyBlock) {
	mb := bftview.LoadMember(curKeyBlock.NumberU64(), curKeyBlock.Hash(), false)
	if mb != nil {
		return
	}

	var newNode *common.Cnode
	if curKeyBlock.BlockType() == types.PowReconfig || curKeyBlock.BlockType() == types.PacePowReconfig {
		newNode = &common.Cnode{
			CoinBase: curKeyBlock.InAddress(),
			Public:   curKeyBlock.InPubKey(),
		}
	}

	mb, _ = bftview.GetCommittee(newNode, curKeyBlock, false)
	mb.StoreWithoutCallback(curKeyBlock)
}

// Update committee by keyblock
func (s *Service) updateCommittee(keyBlock *types.KeyBlock) bool {
	bStore := false
	curKeyBlock := keyBlock
	if bftview.IamMember() < 0 {
		return false
	}
	if curKeyBlock == nil {
		curKeyBlock = s.kbc.CurrentBlock()
	}
	mb := bftview.LoadMember(curKeyBlock.NumberU64(), curKeyBlock.Hash(), true)
	if mb != nil {
		return bStore
	}

	s.muCommitteeInfo.Lock()
	ac, ok := s.lastCmInfoMap[curKeyBlock.Hash()]
	if ok {
		if ac.committee != nil {
			mb = ac.committee
		} else if ac.node != nil {
			mb, _ = bftview.GetCommittee(ac.node, curKeyBlock, true)
		}
	}
	s.muCommitteeInfo.Unlock()

	if mb == nil && !curKeyBlock.HasNewNode() {
		mb, _ = bftview.GetCommittee(nil, curKeyBlock, true)
	}

	if mb != nil {
		bStore = mb.Store(curKeyBlock)
	} else {
		log.Info("updateCommittee can't found committee", "txNumber", s.bc.CurrentBlockN(), "keyNumber", curKeyBlock.NumberU64())
	}
	return bStore
}

func (s *Service) Committee_OnStored(keyblock *types.KeyBlock, mb *bftview.Committee) {
	log.Debug("store committee", "keyNumber", keyblock.NumberU64(), "ip0", mb.List[0].Address, "ipn", mb.List[len(mb.List)-1].Address)
	if keyblock.HasNewNode() && keyblock.NumberU64() == s.kbc.CurrentBlockN() {
		s.netService.AdjustConnect(keyblock.OutAddress(1))
	}
}

// Request committee for keyblock
func (s *Service) Committee_Request(kNumber uint64, hash common.Hash) {
	if kNumber <= s.lastReqCmNumber || !bftview.IamMemberByNumber(kNumber, hash) {
		return
	}

	log.Debug("Committee_Request", "keynumber", kNumber)

	var parentMb *bftview.Committee
	for i := 1; i < 10; i++ {
		keyblock := s.kbc.GetBlockByNumber(kNumber - uint64(i))
		if keyblock == nil {
			return
		}
		mb := bftview.LoadMember(keyblock.NumberU64(), keyblock.Hash(), true)
		if mb != nil {
			parentMb = mb
			break
		}
	}
	if parentMb == nil {
		return
	}

	for _, node := range parentMb.List {
		if IsSelf(node.Address) {
			continue
		}
		s.netService.SendRawData(node.Address, &networkMsg{Cmsg: &committeeInfo{Committee: nil, KeyHash: hash, KeyNumber: kNumber}})
	}
	s.lastReqCmNumber = kNumber
}

// Update current view data
func (s *Service) updateCurrentView(curBlock *types.Block, curKeyBlock *types.KeyBlock, fromKeyBlock bool) { //call by keyblock done
	s.muCurrentView.Lock()

	if curBlock == nil {
		curBlock = s.bc.CurrentBlock()
	}
	if curKeyBlock == nil {
		curKeyBlock = s.kbc.CurrentBlock()
	}

	s.currentView.TxNumber = curBlock.NumberU64()
	s.currentView.TxHash = curBlock.Hash()
	s.currentView.KeyNumber = curKeyBlock.NumberU64()
	s.currentView.KeyHash = curKeyBlock.Hash()
	s.currentView.CommitteeHash = curKeyBlock.CommitteeHash()
	s.currentView.Round = 0

	if s.fairHotstuffEnabled() {
		viewNumber := curBlock.NumberU64()
		if signInfo := curBlock.SignInfo(); signInfo != nil && signInfo.ViewNumber > viewNumber {
			viewNumber = signInfo.ViewNumber
		}
		s.currentView.ViewNumber = viewNumber
		s.currentView.LeaderIndex = s.fairHotstuffLeaderIndexFromBlockLocked(curBlock)
		s.currentView.NoDone = true
	} else if fromKeyBlock || curBlock.NumberU64() > curKeyBlock.T_Number() {
		s.currentView.LeaderIndex = 0
		s.currentView.NoDone = true
	}
	log.Debug("updateCurrentView", "TxNumber", s.currentView.TxNumber, "KeyNumber", s.currentView.KeyNumber, "LeaderIndex", s.currentView.LeaderIndex, "NoDone", s.currentView.NoDone, "Round", s.currentView.Round)
	sendNewView := false
	newViewNumber := s.currentView.TxNumber
	if fromKeyBlock || (s.currentView.TxNumber >= s.waittingView.TxNumber && s.currentView.KeyNumber >= s.waittingView.KeyNumber) || curBlock.BlockType() == types.Key_Block {
		sendNewView = true
		s.waittingView.KeyNumber = s.currentView.KeyNumber
		s.waittingView.TxNumber = s.currentView.TxNumber
	}
	s.muCurrentView.Unlock()

	// sendNewViewMsg snapshots currentView through GetCurrentView, so it must run
	// after releasing muCurrentView.
	if sendNewView && atomic.LoadInt32(&s.runningState) == 1 {
		s.sendNewViewMsg(newViewNumber)
	}
}

func (s *Service) GetCurrentView() *bftview.View {
	s.muCurrentView.Lock()
	defer s.muCurrentView.Unlock()

	v := s.currentView
	return &v
}

func (s *Service) currentHotstuffBaseNumber() uint64 {
	if s.fairHotstuffEnabled() {
		return s.GetCurrentView().ViewNumber
	}
	return s.bc.CurrentBlockN()
}

func (s *Service) getBestCandidate(refresh bool) *types.Candidate {
	return s.keyService.getBestCandidate(refresh)
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

// Set next leader by prescribed rules
func (s *Service) setNextLeader(isDone bool) {
	s.muCurrentView.Lock()
	defer s.muCurrentView.Unlock()

	if s.fairHotstuffEnabled() {
		if !isDone {
			// The failed proposal view is consumed even though the certified parent
			// remains unchanged. The next proposal therefore gets a fresh view number.
			s.currentView.ViewNumber++
		}
		s.currentView.LeaderIndex = s.fairHotstuffLeaderIndexForCurrentLocked()
		s.currentView.NoDone = !isDone

		log.Info("setNextLeader fair hotstuff",
			"isDone", isDone,
			"index", s.currentView.LeaderIndex,
			"txNumber", s.currentView.TxNumber,
			"keyNumber", s.currentView.KeyNumber)

		s.waittingView.TxNumber = s.currentView.TxNumber + 1
		s.waittingView.KeyNumber = s.currentView.KeyNumber + 1
		return
	}

	fixedLeaderMode := s.keyService != nil && s.keyService.fixedLeaderModeEnabled()
	if fixedLeaderMode {
		primary := s.normalizeLeaderIndex(s.keyService.getPrimaryLeaderIndex())
		leaderIndex := primary
		if !isDone {
			leaderIndex = s.normalizeLeaderIndex(s.keyService.getFallbackLeaderIndex(primary))
		}

		s.currentView.LeaderIndex = leaderIndex
		s.currentView.NoDone = !isDone
		s.keyService.setActiveLeader(leaderIndex)

		log.Info("setNextLeader fixed mode",
			"isDone", isDone,
			"primary", primary,
			"index", s.currentView.LeaderIndex)

		s.waittingView.TxNumber = s.currentView.TxNumber + 1
		s.waittingView.KeyNumber = s.currentView.KeyNumber + 1
		return
	}

	if isDone {
		s.currentView.LeaderIndex = s.keyService.getNextLeaderIndex(0)
	} else {
		s.currentView.LeaderIndex = s.keyService.getNextLeaderIndex(s.currentView.LeaderIndex)
	}
	s.currentView.NoDone = !isDone
	log.Info("setNextLeader", "isDone", isDone, "index", s.currentView.LeaderIndex)

	s.waittingView.TxNumber = s.currentView.TxNumber + 1
	s.waittingView.KeyNumber = s.currentView.KeyNumber + 1
}

func (s *Service) shouldRestorePrimaryLeader() bool {
	if s.keyService == nil || !s.keyService.fixedLeaderModeEnabled() {
		return false
	}
	primary := s.normalizeLeaderIndex(s.keyService.getPrimaryLeaderIndex())
	return s.leaderAckRecent(primary)
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
	s.consensusSecret = secret
	s.consensusPublic = public
	s.proposalBodySecret = proposalBodySecret
	s.txQUICReceiptSecret = receiptSecret
	s.txQUICReceiptPublic = receiptPublic
	s.muConsensusIdentity.Unlock()
	s.protocolMng.UpdateKeyPair(secret)
	return nil
}

func activeFHSAuthorizedPeers(committee *bftview.Committee) (map[string][]byte, error) {
	if committee == nil {
		return nil, fmt.Errorf("active Fair HotStuff committee is unavailable")
	}
	if err := hotstuff.ValidateBFTCommitteeSize(len(committee.List)); err != nil {
		return nil, err
	}
	peers := make(map[string][]byte, len(committee.List))
	for index, node := range committee.List {
		if node == nil || node.Address == "" || node.Public == "" {
			return nil, fmt.Errorf("active Fair HotStuff committee member %d is incomplete", index)
		}
		public := bftview.StrToBlsPubKey(node.Public)
		if public == nil {
			return nil, fmt.Errorf("active Fair HotStuff committee member %d has an invalid BLS key", index)
		}
		if _, duplicate := peers[node.Address]; duplicate {
			return nil, fmt.Errorf("active Fair HotStuff committee has duplicate address %q", node.Address)
		}
		peers[node.Address] = public.Serialize()
	}
	return peers, nil
}

// fhsPeerAuthorizationWithCertifiedCarriers widens only the transport-level
// allow-list during a key handoff. The pending committee obtains no consensus
// authority here: proposal sidecars still require a verified activation QC,
// and HotStuff messages remain bound to their exact committee/view proofs.
// This union merely lets a newly added member deliver that self-contained
// proof. The previous canonical generation and durable QC generations remain
// reachable until their delivery/recovery references expire.
func (s *Service) fhsPeerAuthorizationWithCertifiedCarriers(active *bftview.Committee) (map[string][]byte, error) {
	peers, err := activeFHSAuthorizedPeers(active)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, fmt.Errorf("missing FHS service")
	}

	if err := s.addFHSQCDeliveryPeers(peers); err != nil {
		return nil, err
	}

	s.muProposalBody.RLock()
	carriers := make([]*certifiedFHSKeyCarrier, 0, 1)
	for _, record := range s.fhsCertifiedByHash {
		if record == nil || record.verified == nil || record.verified.Block == nil || record.verified.Block.BlockType() != types.Key_Block {
			continue
		}
		candidate := types.DecodeToKeyBlock(record.verified.Block.KeyInfo())
		artifact := &fhsHighQCValidationItem{ref: record.ref, qc: record.qc, verified: record.verified}
		if candidate == nil || validateStagedFHSCertificateArtifact(artifact) != nil ||
			record.verified.Block.KeyHash() != candidate.ParentHash() || record.verified.Block.NumberU64() == 0 ||
			candidate.T_Number() != record.verified.Block.NumberU64()-1 {
			s.muProposalBody.RUnlock()
			return nil, fmt.Errorf("invalid certified FHS key carrier in peer authorization pipeline")
		}
		refCopy := *record.ref
		carriers = append(carriers, &certifiedFHSKeyCarrier{
			keyBlock: candidate,
			ref:      &refCopy,
			qc:       hotstuff.CloneSignedState(record.qc),
		})
	}
	s.muProposalBody.RUnlock()

	for _, carrier := range carriers {
		verifiedRef, err := s.verifyFHSQCCryptographic(carrier.qc)
		if err != nil {
			return nil, fmt.Errorf("verify certified FHS key carrier for peer authorization: %w", err)
		}
		if verifiedRef == nil || verifiedRef.ProposalID() != carrier.ref.ProposalID() {
			return nil, fmt.Errorf("certified FHS key carrier peer authorization context mismatch")
		}
		committee := bftview.LoadMember(carrier.keyBlock.NumberU64(), carrier.keyBlock.Hash(), true)
		if committee == nil || len(committee.List) == 0 || committee.RlpHash() != carrier.keyBlock.CommitteeHash() {
			return nil, fmt.Errorf("certified FHS key carrier committee commitment mismatch")
		}
		generationPeers, err := activeFHSAuthorizedPeers(committee)
		if err != nil {
			return nil, err
		}
		for address, publicKey := range generationPeers {
			if existing := peers[address]; len(existing) > 0 && !bytes.Equal(existing, publicKey) {
				return nil, fmt.Errorf("conflicting FHS peer key for %q across committee handoff", address)
			}
			peers[address] = append([]byte(nil), publicKey...)
		}
	}
	return peers, nil
}

func (s *Service) refreshFHSCertifiedCommitteePeerAuthorization() error {
	if s == nil || !s.fairHotstuffEnabled() || !s.isRunning() || s.netService == nil || s.netService.server == nil {
		return nil
	}
	peers, err := s.fhsPeerAuthorizationWithCertifiedCarriers(bftview.GetCurrentMember())
	if err != nil {
		return err
	}
	if err := s.netService.server.UpdatePeerAuthorization(peers); err != nil {
		return err
	}
	s.netService.setAuthenticatedPeerKeys(peers)
	return nil
}

func (s *Service) addFHSCommitteePeers(peers map[string][]byte, keyHash common.Hash) error {
	if s == nil || s.kbc == nil || peers == nil || keyHash == (common.Hash{}) {
		return fmt.Errorf("missing FHS committee generation")
	}
	_, committee, _, err := s.resolveExactFHSCommittee(keyHash, true)
	if err != nil {
		return fmt.Errorf("load FHS committee %s: %w", keyHash, err)
	}
	generationPeers, err := activeFHSAuthorizedPeers(committee)
	if err != nil {
		return fmt.Errorf("load FHS committee %s: %w", keyHash, err)
	}
	for address, publicKey := range generationPeers {
		if existing := peers[address]; len(existing) > 0 && !bytes.Equal(existing, publicKey) {
			return fmt.Errorf("conflicting FHS peer key for %q across committee generations", address)
		}
		peers[address] = append([]byte(nil), publicKey...)
	}
	return nil
}

func (s *Service) addDeferredFHSRecoveryPeers(peers map[string][]byte, recovery *fhsDeferredRecovery) error {
	if recovery == nil {
		return nil
	}
	if s == nil || s.kbc == nil || recovery.HighestQC == nil {
		return fmt.Errorf("missing deferred FHS recovery committee")
	}
	ref, err := types.DecodeHotstuffProposalRef(recovery.HighestQC.State)
	if err != nil || ref == nil || ref.KeyHash == (common.Hash{}) {
		return fmt.Errorf("decode deferred FHS recovery committee: %w", err)
	}
	return s.addFHSCommitteePeers(peers, ref.KeyHash)
}

// extendDeferredFHSRecoveryPeers admits an older proposal generation only
// after its QC has been cryptographically verified and authorized by the
// active HighQC worker. This is needed when a repaired parent crosses more
// than one key-block boundary; completion narrows the transport back to the
// current committee before the consensus gate opens.
func (s *Service) extendDeferredFHSRecoveryPeers(keyHash common.Hash) error {
	if s == nil || !s.hasDeferredFHSRecovery() || s.netService == nil || s.netService.server == nil {
		return nil
	}
	peers, err := s.fhsPeerAuthorizationWithCertifiedCarriers(bftview.GetCurrentMember())
	if err != nil {
		return err
	}
	if err := s.addDeferredFHSRecoveryPeers(peers, s.fhsStore.deferredRecoverySnapshot()); err != nil {
		return err
	}
	if err := s.addFHSCommitteePeers(peers, keyHash); err != nil {
		return err
	}
	if err := s.netService.server.UpdatePeerAuthorization(peers); err != nil {
		return err
	}
	s.netService.setAuthenticatedPeerKeys(peers)
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

// fhsConsensusResumeTarget keeps restart/deferred-recovery message selection
// in one place. sendNewViewMsg owns the normal-path durable QC replay; a
// pending timeout resumes without NewView and therefore needs one explicit
// replay before the timeout vote is queued.
type fhsConsensusResumeTarget interface {
	replayPendingFHSQCBroadcast()
	sendNewViewMsg(uint64)
	enqueueFHSTimeout()
}

func resumeFHSConsensusMessaging(target fhsConsensusResumeTarget, current uint64, pendingTimeout bool) {
	if pendingTimeout {
		target.replayPendingFHSQCBroadcast()
		target.enqueueFHSTimeout()
		return
	}
	target.sendNewViewMsg(current)
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

func (s *Service) printAllStatus() {
	s.netService.GetNetBlocks(nil)
	for addr, a := range s.netService.ackStatusSnapshot() {
		si := network.NewServerIdentity(addr)
		log.Info("ackInfo", "addr", addr, "id", si.ID)
		log.Info("ackInfo", "ackTm", a.ackTm, "sendTm", a.sendTm, "isSending", a.isSending)
	}
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

func (s *Service) Exceptions(blockNumber int64) []string {
	block := s.bc.GetBlockByNumber(uint64(blockNumber))
	if block == nil {
		return nil
	}
	cm := s.kbc.GetCommitteeByHash(block.KeyHash())
	if cm == nil {
		return nil
	}
	indexs := hotstuff.MaskToExceptionIndexs(block.SignInfo().Exceptions, len(cm))
	if indexs == nil {
		return nil
	}
	var exs []string
	for _, i := range indexs {
		exs = append(exs, cm[i].CoinBase)
	}
	return exs
}

func (s *Service) TakePartInBlocks(address common.Address, checkKeyNumber int64) []string {
	coinbase := strings.ToLower(address.String())
	coinbase = coinbase[2:] //del 0x
	if checkKeyNumber < 0 || uint64(checkKeyNumber) > s.kbc.CurrentBlockN() {
		return nil
	}

	keyNumber := uint64(checkKeyNumber)
	keyblock := s.kbc.GetBlockByNumber(keyNumber)
	if keyblock == nil {
		return nil
	}
	c := bftview.LoadMember(keyNumber, keyblock.Hash(), false)
	if c == nil {
		return nil
	}
	isMember := false
	memberI := 0
	for i, r := range c.List {
		ss := strings.ToLower(r.CoinBase)
		if strings.HasPrefix(ss, "0x") {
			ss = ss[2:]
		}
		if ss == coinbase {
			isMember = true
			memberI = i
			break
		}
	}
	if !isMember {
		return nil
	}
	var takePartInNumberList []string

	fromN := keyblock.T_Number() + 1
	toN := uint64(0)
	if keyNumber == s.kbc.CurrentBlockN() {
		toN = s.bc.CurrentBlockN()
	} else {
		nextkeyblock := s.kbc.GetBlockByNumber(keyNumber + 1)
		toN = nextkeyblock.T_Number()
	}
	if toN < fromN {
		return nil
	}
	n := len(c.List)
	for i := fromN; i <= toN; i++ {
		block := s.bc.GetBlockByNumber(i)
		if block == nil {
			return nil
		}
		indexs := hotstuff.MaskToExceptionIndexs(block.SignInfo().Exceptions, n)
		if indexs == nil {
			takePartInNumberList = append(takePartInNumberList, strconv.FormatInt(int64(i), 10))
			continue
		}
		isException := false
		for _, j := range indexs {
			if j == memberI {
				isException = true
				break
			}
		}
		if !isException {
			takePartInNumberList = append(takePartInNumberList, strconv.FormatInt(int64(i), 10))
		}
	}

	return takePartInNumberList
}

func (s *Service) SwitchOK() bool {
	fromN := int(s.kbc.CurrentBlockN() - uint64(bftview.GetServerCommitteeLen()/3+1))
	if fromN <= 0 {
		return true
	}
	keyblock := s.kbc.GetBlockByNumber(uint64(fromN))
	if s.bc.CurrentBlockN()-keyblock.T_Number() > 0 {
		return true
	}
	return false
}
