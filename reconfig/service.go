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
	"crypto/sha256"
	"encoding/binary"
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
const hotstuffIdleSleep = 1 * time.Millisecond
const tryProposeDebounce = time.Second
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
const fixedModeKeyblockWakeupInterval = 2 * time.Second
const fixedModeKeyblockWatchdogInterval = 250 * time.Millisecond
const fixedModeKeyblockViewRoundDuration = 2 * params.CollectVoteInfoTimeout

const proposalBodyCacheTTL = 2 * time.Minute
const proposalBodyWaitBaseTimeout = 2 * time.Second
const proposalBodyWaitMaxTimeout = 30 * time.Second
const proposalBodyWaitBytesPerSecond = 2 * 1024 * 1024
const proposalBodyRequestAfter = 250 * time.Millisecond
const proposalBodyRequestInterval = 250 * time.Millisecond
const proposalBodyPollInterval = 5 * time.Millisecond
const proposalBodyControlMaxBytes = 512 * 1024
const proposalBodySidecarMaxBytes = 256 * 1024 * 1024
const proposalBodyCacheMaxEntries = 64
const proposalBodyCacheMaxBytes = 512 * 1024 * 1024
const proposalBodyAuthDomain = "cypher-fhs-proposal-sidecar-v1"
const proposalBodyKeyblockLivenessTimeout = time.Second

const (
	proposalBodyMsgData uint32 = iota + 1
	proposalBodyMsgRequest
)

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

type proposalBodyMsg struct {
	Type uint32

	ProposalID common.Hash
	BodyHash   common.Hash
	Number     uint64
	ViewNumber uint64
	ViewID     common.Hash
	LeaderID   string
	From       string

	EncodedBlock      []byte
	Extra             []byte
	ParentQC          []byte
	AuthSig           []byte
	CreatedAtUnixNano int64
}

type fhsCertifiedProposal struct {
	ref      *types.HotstuffProposalRef
	verified *core.VerifiedProposal
	qc       *hotstuff.SignedState
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
		case proposalBodyMsgRequest:
			return network.NetClassProposalBodyControl
		case proposalBodyMsgData:
			if len(msg.Pmsg.EncodedBlock) <= proposalBodyControlMaxBytes {
				return network.NetClassProposalBodyControl
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
	netService  *netService
	bc          *core.BlockChain
	txService   *txService
	kbc         *core.KeyBlockChain
	keyService  *keyService
	txPool      *core.TxPool
	chainConfig *params.ChainConfig

	protocolMng *hotstuff.HotstuffProtocolManager

	lastCmInfoMap   map[common.Hash]*cachedCommitteeInfo
	muCommitteeInfo sync.Mutex
	currentView     bftview.View
	waittingView    bftview.View
	lastReqCmNumber uint64
	muCurrentView   sync.Mutex

	replicaView               *bftview.View
	runningState              int32
	lastProposeTime           time.Time
	lastSlowBlockTime         time.Time
	lastFastBlockTime         time.Time
	serviceStartTime          time.Time
	lastCadenceWakeup         time.Time
	lastFixedKeyNewViewWakeup time.Time
	fixedKeyViewStartedAt     time.Time
	fixedKeyViewTxNumber      uint64
	fixedKeyViewKeyNumber     uint64
	fixedKeyViewTxHash        common.Hash
	fixedKeyViewKeyHash       common.Hash
	fixedKeyViewLeader        uint
	fixedKeyFallbackRound     uint
	lastCandidateRewardCheck  time.Time
	lastCandidateRewardReady  bool
	tryProposeQueuedAt        int64
	muStartNewView            sync.Mutex
	lastStartNewViewN         uint64
	lastStartNewViewHash      common.Hash
	lastStartNewViewAt        time.Time
	pacetMakerTimer           *paceMakerTimer
	muHotstuffProgress        sync.Mutex
	hotstuffProgressAt        time.Time
	lastProgressN             uint64
	lastProgressViewID        common.Hash
	lastProgressRank          uint8

	muProposalBody       sync.RWMutex
	proposalBodies       map[common.Hash]*proposalBodyMsg
	verifiedProposalByID map[common.Hash]*core.VerifiedProposal
	fhsCertifiedByHash   map[common.Hash]*fhsCertifiedProposal
	fhsCertifiedByID     map[common.Hash]*fhsCertifiedProposal
	fhsHighest           *fhsCertifiedProposal
	fhsStore             *fhsSafetyStore
	consensusSecret      *bls.SecretKey
	consensusPublic      *bls.PublicKey

	hotstuffMsgQ *hotstuffMessageQueue
	feed1        event.Feed
	msgCh1       chan committeeMsg
	msgSub1      event.Subscription // Subscription for msg event
}

func newService(sName, sIp string, chainConfig *params.ChainConfig, backend *ReconfigBackend) *Service {
	s := new(Service)
	s.serviceStartTime = time.Now()
	s.netService = newNetService(sName, sIp, chainConfig, backend, s)
	s.txService = newTxService(s, backend, chainConfig)
	s.keyService = newKeyService(s, backend, chainConfig)

	s.bc = backend.BlockChain()
	s.kbc = backend.KeyBlockChain()
	s.txPool = backend.TxPool()
	s.chainConfig = chainConfig
	var chainID uint64
	if chainConfig != nil && chainConfig.ChainID != nil {
		chainID = chainConfig.ChainID.Uint64()
	}
	var genesisHash common.Hash
	if s.bc != nil && s.bc.Genesis() != nil {
		genesisHash = s.bc.Genesis().Hash()
	}
	s.fhsStore = newFHSSafetyStore(backend.ChainDb(), chainID, genesisHash)

	s.lastCmInfoMap = make(map[common.Hash]*cachedCommitteeInfo)
	s.proposalBodies = make(map[common.Hash]*proposalBodyMsg)
	s.verifiedProposalByID = make(map[common.Hash]*core.VerifiedProposal)
	s.fhsCertifiedByHash = make(map[common.Hash]*fhsCertifiedProposal)
	s.fhsCertifiedByID = make(map[common.Hash]*fhsCertifiedProposal)

	s.msgCh1 = make(chan committeeMsg, 10)
	s.msgSub1 = s.feed1.Subscribe(s.msgCh1)
	s.hotstuffMsgQ = newHotstuffMessageQueue()
	s.hotstuffProgressAt = time.Now()

	s.protocolMng = hotstuff.NewHotstuffProtocolManager(s, nil, nil)
	s.pacetMakerTimer = newPaceMakerTimer(chainConfig, s, backend)

	bftview.SetCommitteeConfig(backend.ChainDb(), backend.KeyBlockChain(), s)

	go s.handleHotStuffMsg()
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
	keyblock := s.kbc.GetBlockByHash(keyHash)
	if keyblock == nil {
		return nil, fmt.Errorf("unknown committee key block %s", keyHash)
	}
	committee := bftview.LoadMember(keyblock.NumberU64(), keyHash, false)
	if committee == nil {
		return nil, fmt.Errorf("missing committee for key block %s", keyHash)
	}
	if committee.RlpHash() != keyblock.CommitteeHash() {
		return nil, fmt.Errorf("committee hash mismatch for key block %s", keyHash)
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
	committee := s.kbc.GetCommitteeByHash(keyHash)
	if len(committee) == 0 {
		return nil, fmt.Errorf("missing historical committee for key hash %s", keyHash)
	}
	for _, node := range committee {
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
	if len(in.EncodedBlock) > 0 {
		out.EncodedBlock = make([]byte, len(in.EncodedBlock))
		copy(out.EncodedBlock, in.EncodedBlock)
	}
	out.Extra = append([]byte(nil), in.Extra...)
	out.ParentQC = append([]byte(nil), in.ParentQC...)
	out.AuthSig = append([]byte(nil), in.AuthSig...)
	return &out
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
	payload, err := rlp.EncodeToBytes([]interface{}{
		[]byte(proposalBodyAuthDomain), chainID, body.Type, body.ProposalID, body.BodyHash,
		body.Number, body.ViewNumber, body.ViewID, body.LeaderID, body.From,
		sha256.Sum256(body.EncodedBlock), sha256.Sum256(body.Extra), sha256.Sum256(body.ParentQC),
	})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	return digest[:], nil
}

func validateProposalBodyWireShape(body *proposalBodyMsg) error {
	if body == nil || body.From == "" || len(body.From) > 512 || len(body.AuthSig) == 0 || len(body.AuthSig) > 256 {
		return fmt.Errorf("invalid proposal sidecar identity fields")
	}
	if len(body.Extra)+len(body.ParentQC) > proposalBodyControlMaxBytes {
		return fmt.Errorf("proposal sidecar proof exceeds %d bytes", proposalBodyControlMaxBytes)
	}
	switch body.Type {
	case proposalBodyMsgData:
		if len(body.EncodedBlock) == 0 || len(body.EncodedBlock) > proposalBodySidecarMaxBytes {
			return fmt.Errorf("invalid proposal sidecar body size")
		}
	case proposalBodyMsgRequest:
		if len(body.EncodedBlock) != 0 || len(body.Extra) != 0 || len(body.ParentQC) != 0 {
			return fmt.Errorf("proposal sidecar request contains a data payload")
		}
	default:
		return fmt.Errorf("unknown proposal sidecar message type")
	}
	return nil
}

func (s *Service) sealProposalBody(body *proposalBodyMsg) error {
	if body == nil || s.consensusSecret == nil || s.consensusPublic == nil {
		return fmt.Errorf("proposal sidecar signing key is unavailable")
	}
	body.From = s.Self()
	digest, err := proposalBodyAuthDigest(s.ChainID(), body)
	if err != nil {
		return err
	}
	signature := s.consensusSecret.SignHash(digest)
	if signature == nil {
		return fmt.Errorf("failed to sign proposal sidecar")
	}
	body.AuthSig = append(body.AuthSig[:0], signature.Serialize()...)
	return nil
}

func (s *Service) proposalBodySenderKey(from string) (*bls.PublicKey, error) {
	current := s.GetCurrentView()
	committee, err := s.loadViewCommittee(current, true)
	if err != nil {
		return nil, err
	}
	keys, err := s.GetPublicKey(current.KeyHash)
	if err != nil || len(keys) != len(committee.List) {
		return nil, fmt.Errorf("proposal sidecar committee keys unavailable")
	}
	for index, node := range committee.List {
		if node != nil && node.Address == from && keys[index] != nil {
			return keys[index], nil
		}
	}
	return nil, fmt.Errorf("proposal sidecar sender is not in the active committee")
}

func (s *Service) verifyProposalBodySender(si *network.ServerIdentity, body *proposalBodyMsg) error {
	if si == nil || body == nil || body.From == "" || si.Address.String() != body.From {
		return fmt.Errorf("proposal sidecar transport identity mismatch")
	}
	public, err := s.proposalBodySenderKey(body.From)
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

func (s *Service) proposalBodyCacheUsageLocked() (int, int) {
	bytesUsed := 0
	for _, body := range s.proposalBodies {
		if body != nil {
			bytesUsed += len(body.EncodedBlock) + len(body.Extra) + len(body.ParentQC) + len(body.AuthSig)
		}
	}
	return len(s.proposalBodies), bytesUsed
}

func (s *Service) evictOldestProposalBodyLocked() bool {
	var oldestID common.Hash
	var oldest *proposalBodyMsg
	found := false
	for id, body := range s.proposalBodies {
		if body == nil {
			oldestID, found = id, true
			break
		}
		if _, certified := s.fhsCertifiedByID[id]; certified {
			continue
		}
		if oldest == nil || body.CreatedAtUnixNano < oldest.CreatedAtUnixNano {
			oldestID, oldest, found = id, body, true
		}
	}
	if !found {
		return false
	}
	delete(s.proposalBodies, oldestID)
	delete(s.verifiedProposalByID, oldestID)
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
	for id, body := range s.proposalBodies {
		if body == nil || (body.CreatedAtUnixNano > 0 && now.Sub(time.Unix(0, body.CreatedAtUnixNano)) > proposalBodyCacheTTL) {
			if _, certified := s.fhsCertifiedByID[id]; certified {
				continue
			}
			delete(s.proposalBodies, id)
			delete(s.verifiedProposalByID, id)
		}
	}
}

func (s *Service) purgeExpiredProposalCaches(now time.Time) {
	s.muProposalBody.Lock()
	s.purgeExpiredProposalCachesLocked(now)
	s.muProposalBody.Unlock()
}

func (s *Service) storeProposalBody(body *proposalBodyMsg) error {
	if body == nil {
		return fmt.Errorf("nil proposal body")
	}
	if body.ProposalID == (common.Hash{}) {
		return fmt.Errorf("proposal body missing proposal id")
	}
	if body.BodyHash == (common.Hash{}) {
		return fmt.Errorf("proposal body missing body hash")
	}
	if len(body.EncodedBlock) == 0 {
		return fmt.Errorf("proposal body missing encoded block")
	}
	if len(body.EncodedBlock) > proposalBodySidecarMaxBytes {
		return fmt.Errorf("proposal body too large: bytes=%d limit=%d", len(body.EncodedBlock), proposalBodySidecarMaxBytes)
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
	parentQCID, err := proposalBodyParentQCID(body.ParentQC)
	if err != nil {
		return fmt.Errorf("proposal sidecar parent QC: %w", err)
	}
	ref, err := types.NewHotstuffProposalRefWithProof(s.ChainID(), body.ViewNumber, body.ViewID, body.LeaderID, block, body.EncodedBlock, body.Extra, parentQCID)
	if err != nil {
		return err
	}
	if ref.ProposalID() != body.ProposalID || ref.Number != body.Number || ref.BodyHash != body.BodyHash {
		return fmt.Errorf("proposal sidecar does not match its proposal ID")
	}
	cpy := cloneProposalBodyMsg(body)
	cpy.Type = proposalBodyMsgData
	if cpy.From == "" {
		cpy.From = s.Self()
	}
	// Never trust remote wall-clock values for TTL or eviction decisions.
	cpy.CreatedAtUnixNano = time.Now().UnixNano()

	s.muProposalBody.Lock()
	defer s.muProposalBody.Unlock()
	s.purgeExpiredProposalCachesLocked(time.Now())
	if existing := s.proposalBodies[cpy.ProposalID]; existing != nil {
		if existing.BodyHash != cpy.BodyHash || !bytes.Equal(existing.EncodedBlock, cpy.EncodedBlock) ||
			!bytes.Equal(existing.Extra, cpy.Extra) || !bytes.Equal(existing.ParentQC, cpy.ParentQC) {
			return fmt.Errorf("conflicting proposal sidecar for %s", cpy.ProposalID)
		}
		return nil
	}
	entryBytes := len(cpy.EncodedBlock) + len(cpy.Extra) + len(cpy.ParentQC) + len(cpy.AuthSig)
	for {
		entries, bytesUsed := s.proposalBodyCacheUsageLocked()
		if entries < proposalBodyCacheMaxEntries && bytesUsed+entryBytes <= proposalBodyCacheMaxBytes {
			break
		}
		if !s.evictOldestProposalBodyLocked() {
			return fmt.Errorf("proposal sidecar cache capacity exhausted")
		}
	}
	s.proposalBodies[cpy.ProposalID] = cpy
	return nil
}

func (s *Service) getProposalBody(proposalID common.Hash) *proposalBodyMsg {
	s.muProposalBody.RLock()
	body := cloneProposalBodyMsg(s.proposalBodies[proposalID])
	s.muProposalBody.RUnlock()
	return body
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
	delete(s.proposalBodies, proposalID)
	delete(s.verifiedProposalByID, proposalID)
	s.muProposalBody.Unlock()
}

func signedStateEqual(a, b *hotstuff.SignedState) bool {
	return hotstuff.SignedStateSemanticEqual(a, b)
}

func (s *Service) HighestCertified() *hotstuff.SignedState {
	s.muProposalBody.RLock()
	defer s.muProposalBody.RUnlock()
	if s.fhsHighest == nil {
		return nil
	}
	return hotstuff.CloneSignedState(s.fhsHighest.qc)
}

func (s *Service) highestFHSCertifiedProposal() *core.VerifiedProposal {
	s.muProposalBody.RLock()
	defer s.muProposalBody.RUnlock()
	if s.fhsHighest == nil {
		return nil
	}
	return s.fhsHighest.verified
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

func (s *Service) validateFHSProposalParent(ref *types.HotstuffProposalRef, parentQC *hotstuff.SignedState) error {
	if ref == nil {
		return fmt.Errorf("nil FHS proposal ref")
	}
	current := s.GetCurrentView()
	if ref.ParentHash != current.TxHash {
		return fmt.Errorf("FHS proposal parent is not highest certified block: have %s want %s", ref.ParentHash, current.TxHash)
	}

	s.muProposalBody.RLock()
	highest := s.fhsHighest
	s.muProposalBody.RUnlock()
	if highest == nil {
		if parentQC != nil {
			return fmt.Errorf("unexpected FHS parent QC without a locally certified parent")
		}
		if ref.ParentHash != s.bc.CurrentBlock().Hash() {
			return fmt.Errorf("first FHS proposal must extend canonical head: have %s want %s", ref.ParentHash, s.bc.CurrentBlock().Hash())
		}
		return nil
	}
	if parentQC == nil {
		return fmt.Errorf("FHS proposal missing highest parent QC")
	}
	if !signedStateEqual(parentQC, highest.qc) {
		return fmt.Errorf("FHS proposal parent QC is not the highest certified QC")
	}
	parentRef, err := types.DecodeHotstuffProposalRef(parentQC.State)
	if err != nil {
		return fmt.Errorf("invalid FHS parent proposal ref: %w", err)
	}
	if parentRef.BlockHash != ref.ParentHash || parentRef.BlockHash != highest.ref.BlockHash {
		return fmt.Errorf("FHS proposal does not extend QC-certified parent")
	}
	if ref.Number != parentRef.Number+1 {
		return fmt.Errorf("FHS proposal block height is not contiguous: have %d parent %d", ref.Number, parentRef.Number)
	}
	if ref.ViewNumber <= parentRef.ViewNumber {
		return fmt.Errorf("FHS proposal view is not newer: have %d parent %d", ref.ViewNumber, parentRef.ViewNumber)
	}
	return nil
}

func (s *Service) OnCertified(cert *hotstuff.SignedState) error {
	// Replica path: the originating leader owns the durable dissemination
	// outbox. A receiver persists/adopts the QC, but must not claim it as a
	// locally replayable leader broadcast.
	if err := s.adoptFHSHighQC(cert, false, false); err != nil {
		return err
	}
	return s.finishFHSCertification(cert)
}

func (s *Service) OnFHSLeaderCertifiedBeforeBroadcast(cert *hotstuff.SignedState) error {
	return s.adoptFHSHighQC(cert, false, true)
}

func (s *Service) OnFHSLeaderCertifiedAfterBroadcast(cert *hotstuff.SignedState) error {
	return s.finishFHSCertification(cert)
}

func (s *Service) finishFHSCertification(cert *hotstuff.SignedState) error {
	if err := s.commitFHS2ChainForCertified(cert); err != nil {
		return err
	}
	s.pacetMakerTimer.start()
	s.sendNewViewMsg(cert.Number)
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
	return fhsNeedsFinalityBlock(s.fhsCertifiedByHash, currentKeyHash, s.isCanonicalFHSBlock)
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
	return fhsHasConflictingUncommittedKeyBlock(s.fhsCertifiedByHash, candidate, s.isCanonicalFHSBlock)
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
	return fhsHasUncommittedKeyBlock(s.fhsCertifiedByHash, s.isCanonicalFHSBlock)
}

func fhs2ChainCommitTarget(certifiedByHash map[common.Hash]*fhsCertifiedProposal, tip *fhsCertifiedProposal) *fhsCertifiedProposal {
	if tip == nil || tip.ref == nil || tip.qc == nil {
		return nil
	}
	parent := certifiedByHash[tip.ref.ParentHash]
	if parent == nil || parent.ref == nil || parent.qc == nil || parent.ref.BlockHash != tip.ref.ParentHash {
		return nil
	}
	if tip.ref.Number != parent.ref.Number+1 || tip.qc.Number <= parent.qc.Number {
		return nil
	}
	return parent
}

// preflightFHSCommitStep validates one independently finalizable parent/child
// pair before any epoch-local WAL or pacemaker state is changed. Callers run it
// immediately before each sequential commit so a preceding key carrier can
// advance the effective key head for the next step in a recovered prefix.
func (s *Service) preflightFHSCommitStep(target, child *fhsCertifiedProposal) (*types.KeyBlock, error) {
	if target == nil || target.ref == nil || target.verified == nil || target.verified.Block == nil || child == nil || child.qc == nil {
		return nil, fmt.Errorf("incomplete FHS 2-chain commit proof")
	}
	block := target.verified.Block
	if err := s.bc.VerifyFHS2ChainCommitProof(block, child.qc); err != nil {
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
	tip := s.fhsCertifiedByHash[ref.BlockHash]
	target := fhs2ChainCommitTarget(s.fhsCertifiedByHash, tip)
	if target == nil {
		s.muProposalBody.RUnlock()
		return nil
	}

	type commitStep struct {
		target *fhsCertifiedProposal
		child  *fhsCertifiedProposal
	}
	currentHash := s.bc.CurrentBlock().Hash()
	chain := make([]commitStep, 0, 2)
	child := tip
	for cursor := target; cursor != nil && cursor.ref.BlockHash != currentHash; cursor = s.fhsCertifiedByHash[cursor.ref.ParentHash] {
		chain = append(chain, commitStep{target: cursor, child: child})
		if cursor.ref.ParentHash == currentHash {
			break
		}
		if s.fhsCertifiedByHash[cursor.ref.ParentHash] == nil {
			s.muProposalBody.RUnlock()
			return fmt.Errorf("FHS commit prefix missing certified ancestor %s", cursor.ref.ParentHash)
		}
		child = cursor
	}
	s.muProposalBody.RUnlock()

	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	for _, step := range chain {
		certified := step.target
		keyBlock, err := s.preflightFHSCommitStep(certified, step.child)
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
		if err := s.txService.decideFHSVerifiedProposal(certified.ref, certified.verified, certified.qc, step.child.qc); err != nil {
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
		delete(s.proposalBodies, proposalID)
		delete(s.verifiedProposalByID, proposalID)
		s.muProposalBody.Unlock()
		log.Info("FHS 2-CHAIN COMMIT",
			"number", certified.ref.Number,
			"view", certified.qc.Number,
			"hash", certified.ref.BlockHash,
			"trigger", tip.ref.BlockHash,
			"triggerView", tip.qc.Number)
	}
	return nil
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

// beforeFHSFinalizedSyncKeyCommit rotates only committee-scoped timeout data
// after core has verified the complete direct-child finality proof, but before
// the synced key carrier becomes canonical. LastVote and HighestQC remain as
// global safety watermarks.
func (s *Service) beforeFHSFinalizedSyncKeyCommit(block *types.Block, childQC *hotstuff.SignedState) error {
	if block == nil || block.BlockType() != types.Key_Block || childQC == nil {
		return fmt.Errorf("incomplete Fair HotStuff synced key transition")
	}
	keyBlock := types.DecodeToKeyBlock(block.KeyInfo())
	if keyBlock == nil {
		return fmt.Errorf("invalid Fair HotStuff synced key carrier")
	}
	current := s.kbc.CurrentBlock()
	if current == nil {
		return fmt.Errorf("missing canonical key head before Fair HotStuff sync transition")
	}
	if current.Hash() != keyBlock.Hash() || current.NumberU64() != keyBlock.NumberU64() {
		if keyBlock.NumberU64() != current.NumberU64()+1 || keyBlock.ParentHash() != current.Hash() {
			return fmt.Errorf("non-contiguous Fair HotStuff synced key transition: current=%d/%s next=%d/%s parent=%s",
				current.NumberU64(), current.Hash(), keyBlock.NumberU64(), keyBlock.Hash(), keyBlock.ParentHash())
		}
	}
	return s.rotateFHSEpochSafety(keyBlock.Hash())
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
	if block.BlockType() != types.Key_Block {
		return nil
	}
	expected := types.DecodeToKeyBlock(block.KeyInfo())
	current := s.kbc.CurrentBlock()
	if expected == nil || current == nil || current.NumberU64() != expected.NumberU64() || current.Hash() != expected.Hash() {
		return fmt.Errorf("Fair HotStuff synced key head was not installed exactly")
	}
	return s.normalizeFHSEpochView(childQC, current)
}

func (s *Service) prepareHotstuffProposal(viewNumber uint64, viewID common.Hash, leaderID string, encodedBlock, extra []byte) ([]byte, error) {
	if len(encodedBlock) == 0 {
		return nil, fmt.Errorf("empty encoded block proposal")
	}
	if len(encodedBlock) > proposalBodySidecarMaxBytes {
		return nil, fmt.Errorf("encoded block proposal too large: bytes=%d limit=%d", len(encodedBlock), proposalBodySidecarMaxBytes)
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
	parentQC := s.HighestCertified()
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
		Type:              proposalBodyMsgData,
		ProposalID:        proposalID,
		BodyHash:          ref.BodyHash,
		Number:            ref.Number,
		ViewNumber:        ref.ViewNumber,
		ViewID:            ref.ViewID,
		LeaderID:          ref.LeaderID,
		From:              s.Self(),
		EncodedBlock:      encodedBlock,
		Extra:             append([]byte(nil), extra...),
		ParentQC:          encodedParentQC,
		CreatedAtUnixNano: time.Now().UnixNano(),
	}
	if err := s.storeProposalBody(body); err != nil {
		return nil, err
	}
	s.broadcastProposalBodyToCommittee(body)
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
	return refBytes, nil
}

func (s *Service) broadcastProposalBodyToCommittee(body *proposalBodyMsg) {
	if body == nil {
		return
	}
	mb := bftview.GetCurrentMember()
	if mb == nil {
		log.Warn("HOTSTUFF PROPOSAL BODY broadcast skipped; missing committee", "number", body.Number, "proposalID", body.ProposalID)
		return
	}
	wireBody := cloneProposalBodyMsg(body)
	if wireBody != nil {
		wireBody.From = s.Self()
	}
	if err := s.sealProposalBody(wireBody); err != nil {
		log.Warn("HOTSTUFF PROPOSAL BODY signing failed", "number", body.Number, "err", err)
		return
	}
	for _, node := range mb.List {
		if node == nil || node.Address == "" || IsSelf(node.Address) {
			continue
		}
		log.Info("HOTSTUFF PROPOSAL BODY SEND",
			"to", node.Address,
			"number", body.Number,
			"proposalID", body.ProposalID,
			"bodyHash", body.BodyHash,
			"bytes", len(body.EncodedBlock))
		if err := s.netService.SendRawData(node.Address, &networkMsg{Pmsg: wireBody}); err != nil {
			log.Warn("HOTSTUFF PROPOSAL BODY send failed", "to", node.Address, "number", body.Number, "proposalID", body.ProposalID, "err", err)
		}
	}
}

func (s *Service) sendProposalBodyRequest(ref *types.HotstuffProposalRef) {
	if ref == nil {
		return
	}
	req := &proposalBodyMsg{
		Type:              proposalBodyMsgRequest,
		ProposalID:        ref.ProposalID(),
		BodyHash:          ref.BodyHash,
		Number:            ref.Number,
		ViewNumber:        ref.ViewNumber,
		ViewID:            ref.ViewID,
		LeaderID:          ref.LeaderID,
		From:              s.Self(),
		CreatedAtUnixNano: time.Now().UnixNano(),
	}
	if err := s.sealProposalBody(req); err != nil {
		log.Warn("HOTSTUFF PROPOSAL BODY REQUEST signing failed", "number", ref.Number, "err", err)
		return
	}

	mb := bftview.GetCurrentMember()
	if mb == nil {
		return
	}
	for _, node := range mb.List {
		if node == nil || node.Address == "" || IsSelf(node.Address) {
			continue
		}
		log.Info("HOTSTUFF PROPOSAL BODY REQUEST",
			"to", node.Address,
			"number", ref.Number,
			"proposalID", req.ProposalID,
			"bodyHash", req.BodyHash)
		if err := s.netService.SendRawData(node.Address, &networkMsg{Pmsg: req}); err != nil {
			log.Warn("HOTSTUFF PROPOSAL BODY request failed", "to", node.Address, "number", ref.Number, "proposalID", req.ProposalID, "err", err)
		}
	}
}

func (s *Service) waitProposalBody(ref *types.HotstuffProposalRef) (*proposalBodyMsg, error) {
	if ref == nil {
		return nil, fmt.Errorf("nil proposal ref")
	}
	proposalID := ref.ProposalID()
	start := time.Now()
	deadline := start.Add(proposalBodyWaitTimeout(ref.BodySize))
	shortenedForKeyblock := false
	if s.fixedModeKeyblockIntervalElapsed(start) && start.Add(proposalBodyKeyblockLivenessTimeout).Before(deadline) {
		deadline = start.Add(proposalBodyKeyblockLivenessTimeout)
		shortenedForKeyblock = true
	}
	nextRequestAt := time.Now().Add(proposalBodyRequestAfter)
	for {
		body := s.getProposalBody(proposalID)
		if body != nil {
			if body.BodyHash != ref.BodyHash {
				return nil, fmt.Errorf("proposal body hash mismatch for %s: have %s want %s", proposalID, body.BodyHash, ref.BodyHash)
			}
			if uint64(len(body.EncodedBlock)) != ref.BodySize {
				return nil, fmt.Errorf("proposal body size mismatch for %s: have %d want %d", proposalID, len(body.EncodedBlock), ref.BodySize)
			}
			return body, nil
		}
		now := time.Now()
		if !shortenedForKeyblock && s.fixedModeKeyblockIntervalElapsed(now) {
			keyblockDeadline := now.Add(proposalBodyKeyblockLivenessTimeout)
			if keyblockDeadline.Before(deadline) {
				deadline = keyblockDeadline
				shortenedForKeyblock = true
				log.Warn("HOTSTUFF PROPOSAL BODY wait shortened for keyblock liveness",
					"number", ref.Number,
					"proposalID", proposalID,
					"bodyHash", ref.BodyHash,
					"bodySize", ref.BodySize,
					"deadline", deadline.Sub(now))
			}
		}
		if !now.Before(nextRequestAt) {
			s.sendProposalBodyRequest(ref)
			nextRequestAt = now.Add(proposalBodyRequestInterval)
		}
		if now.After(deadline) {
			return nil, fmt.Errorf("proposal body timeout: number=%d proposalID=%s bodyHash=%s", ref.Number, proposalID, ref.BodyHash)
		}
		time.Sleep(proposalBodyPollInterval)
	}
}

func proposalBodyWaitTimeout(bodySize uint64) time.Duration {
	timeout := proposalBodyWaitBaseTimeout
	if bodySize > 0 {
		transfer := time.Duration(bodySize) * time.Second / proposalBodyWaitBytesPerSecond
		timeout += transfer
	}
	if timeout > proposalBodyWaitMaxTimeout {
		return proposalBodyWaitMaxTimeout
	}
	return timeout
}

func (s *Service) handleProposalBodyMsg(si *network.ServerIdentity, msg *proposalBodyMsg) {
	if msg == nil {
		return
	}
	if err := validateProposalBodyWireShape(msg); err != nil {
		log.Warn("HOTSTUFF PROPOSAL BODY malformed", "from", msg.From, "number", msg.Number, "err", err)
		return
	}
	if err := s.verifyProposalBodySender(si, msg); err != nil {
		log.Warn("HOTSTUFF PROPOSAL BODY sender rejected", "from", msg.From, "number", msg.Number, "proposalID", msg.ProposalID, "err", err)
		return
	}
	switch msg.Type {
	case proposalBodyMsgData:
		if err := s.storeProposalBody(msg); err != nil {
			log.Warn("HOTSTUFF PROPOSAL BODY rejected", "from", msg.From, "number", msg.Number, "proposalID", msg.ProposalID, "err", err)
			return
		}
		log.Info("HOTSTUFF PROPOSAL BODY stored", "from", msg.From, "number", msg.Number, "proposalID", msg.ProposalID, "bytes", len(msg.EncodedBlock))
	case proposalBodyMsgRequest:
		body := s.getProposalBody(msg.ProposalID)
		if body == nil {
			log.Debug("HOTSTUFF PROPOSAL BODY request miss", "from", msg.From, "number", msg.Number, "proposalID", msg.ProposalID)
			return
		}
		if si == nil {
			return
		}
		address := si.Address.String()
		if address == "" {
			return
		}
		cpy := cloneProposalBodyMsg(body)
		if cpy != nil {
			cpy.From = s.Self()
		}
		if err := s.sealProposalBody(cpy); err != nil {
			log.Warn("HOTSTUFF PROPOSAL BODY RESPONSE signing failed", "to", address, "number", body.Number, "err", err)
			return
		}
		log.Info("HOTSTUFF PROPOSAL BODY RESPONSE", "to", address, "number", body.Number, "proposalID", body.ProposalID, "bytes", len(body.EncodedBlock))
		if err := s.netService.SendRawData(address, &networkMsg{Pmsg: cpy}); err != nil {
			log.Warn("HOTSTUFF PROPOSAL BODY response failed", "to", address, "number", body.Number, "proposalID", body.ProposalID, "err", err)
		}
	default:
		log.Warn("HOTSTUFF PROPOSAL BODY unknown type", "type", msg.Type, "number", msg.Number, "proposalID", msg.ProposalID)
	}
}

// OnPropose call by hotstuff
func (s *Service) OnPropose(state []byte, extra []byte, viewNumber uint64, parentQC *hotstuff.SignedState) error { // verify new proposal ref and full sidecar body before voting
	log.Debug("OnPropose..")
	if !s.isRunning() {
		return types.ErrNotRunning
	}
	if len(state) == 0 {
		err := fmt.Errorf("empty hotstuff proposal ref")
		log.Error("OnPropose", "error", err)
		return err
	}

	ref, err := types.DecodeHotstuffProposalRef(state)
	if err != nil {
		log.Error("OnPropose decode proposal ref", "err", err)
		return err
	}
	if ref.ChainID != s.ChainID() {
		return fmt.Errorf("hotstuff proposal chain id mismatch: have %d want %d", ref.ChainID, s.ChainID())
	}
	if ref.ViewNumber != viewNumber {
		return fmt.Errorf("hotstuff proposal view number mismatch: have %d want %d", ref.ViewNumber, viewNumber)
	}
	if s.fairHotstuffEnabled() {
		if ref.ExtraHash != types.HotstuffProposalExtraHash(extra) {
			return fmt.Errorf("hotstuff proposal extra proof is not bound to the signed reference")
		}
		var parentQCID common.Hash
		if parentQC != nil {
			id, err := hotstuff.SignedStateID(parentQC)
			if err != nil {
				return err
			}
			parentQCID = id.Hash()
		}
		if ref.ParentQCID != parentQCID {
			return fmt.Errorf("hotstuff proposal parent QC is not bound to the signed reference")
		}
		if err := s.validateFHSProposalParent(ref, parentQC); err != nil {
			return err
		}
	}
	proposalID := ref.ProposalID()
	log.Info("OnPropose",
		"number", ref.Number,
		"proposalID", proposalID,
		"blockHash", ref.BlockHash,
		"bodyHash", ref.BodyHash,
		"bodySize", ref.BodySize)

	body, err := s.waitProposalBody(ref)
	if err != nil {
		log.Error("OnPropose wait proposal body", "number", ref.Number, "proposalID", proposalID, "err", err)
		return err
	}
	block := types.DecodeToBlock(body.EncodedBlock)
	if block == nil {
		err := fmt.Errorf("DecodeToBlock(proposal body) error")
		log.Error("OnPropose", "proposalID", proposalID, "error", err)
		return err
	}
	if err := ref.VerifyAgainstBlock(block, body.EncodedBlock); err != nil {
		log.Error("OnPropose proposal ref mismatch", "number", ref.Number, "proposalID", proposalID, "err", err)
		return err
	}

	verified, err := s.txService.verifyHotstuffProposal(ref, block, extra)
	if err != nil {
		log.Error("verify hotstuff proposal", "number", block.NumberU64(), "proposalID", proposalID, "err", err)
		return err
	}
	if err := s.updateProposalBodyProof(proposalID, extra, parentQC); err != nil {
		return err
	}
	if block.BlockType() == types.Key_Block {
		kblock := types.DecodeToKeyBlock(block.KeyInfo())
		if kblock == nil {
			return fmt.Errorf("Block's extra (keyblock) is error format!")
		}
		if s.hasConflictingUncommittedFHSKeyBlock(block) {
			return fmt.Errorf("reject competing key block while a certified key transition is uncommitted: proposal=%s", block.Hash())
		}
		if block.NumberU64() == 0 {
			return fmt.Errorf("key block carrier cannot be transaction genesis")
		}
		if err := s.keyService.verifyKeyBlock(kblock, types.DecodeToCandidate(extra), block.NumberU64()-1); err != nil {
			log.Error("verify keyblock", "number", kblock.NumberU64(), "proposalID", proposalID, "err", err)
			return err
		}
	}
	s.storeVerifiedProposal(proposalID, verified)
	s.pacetMakerTimer.start()
	return nil
}

// Propose call by hotstuff
func (s *Service) Propose(viewNumber uint64, viewID common.Hash, leaderID string) (e error, kState []byte, tState []byte, extra []byte) { //buf recv by onpropose, onviewdown
	log.Debug("Propose..", "number", s.GetCurrentView().TxNumber)

	proposeOK := false
	defer func() {
		if !proposeOK {
			go func() {
				time.Sleep(failedProposalRetry)
				curView := s.GetCurrentView()
				if bftview.IamLeader(curView.LeaderIndex) {
					s.triggerTryPropose(s.bc.CurrentBlockN())
				}
			}()
		} else {
			s.lastProposeTime = time.Now()
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
	keyProposal := leaderIndex > 0
	if fixedMode {
		// In fixed mode, a fallback leader may be selected from local ack/progress
		// observations. Do not let that alone force the service into the keyblock
		// proposal path; otherwise a transient fallback view can starve tx block
		// proposals. Fixed mode keyblocks should only be proposed after an explicit
		// keyblock trigger has marked the current view as not done.
		keyProposal = !noDone
	}
	keyBlockIntervalElapsed := true
	if curKeyblock := s.kbc.CurrentBlock(); curKeyblock != nil {
		lastKeyTime := time.Unix(int64(curKeyblock.Time()), 0)
		keyBlockIntervalElapsed = time.Since(lastKeyTime) >= params.KeyBlockMinInterval
		if keyProposal && !keyBlockIntervalElapsed {
			log.Debug("Propose keyblock suppressed by minimum interval",
				"elapsed", time.Since(lastKeyTime),
				"minimum", params.KeyBlockMinInterval,
				"lastKeyTime", lastKeyTime)
		}
	}

	if fixedMode && !keyProposal && keyBlockIntervalElapsed && s.getBestCandidate(true) != nil {
		keyProposal = true
		log.Warn("fixed-mode candidate reward keyblock proposal forced",
			"noDone", noDone,
			"leaderIndex", leaderIndex,
			"currentTx", s.bc.CurrentBlockN(),
			"currentKey", s.kbc.CurrentBlockN())
	}
	if keyProposal && s.hasUncommittedFHSKeyBlock() {
		keyProposal = false
		log.Info("FHS keyblock proposal suppressed until certified keyblock finalizes",
			"currentTx", s.bc.CurrentBlockN(),
			"currentKey", s.kbc.CurrentBlockN())
	}

	if keyProposal && keyBlockIntervalElapsed {
		txParentNumber := fhsProposalParentNumber(s.bc.CurrentBlockN(), s.highestFHSCertifiedProposal())
		keyblock, mb, bestCandi, err := s.keyService.tryProposalChangeCommittee(leaderIndex, !noDone, txParentNumber)
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
	blockType := s.chooseTxBlockType()
	data, err := s.txService.tryProposalNewBlock(blockType)
	if err != nil {
		fallbackType := uint8(types.FastTx_Block)
		if blockType == types.FastTx_Block {
			fallbackType = types.SlowTx_Block
		}
		log.Warn("Primary tx block proposal failed, trying fallback lane",
			"primary", readableTxBlockType(blockType),
			"fallback", readableTxBlockType(fallbackType),
			"err", err)
		data, err = s.txService.tryProposalNewBlock(fallbackType)
		if err == nil {
			blockType = fallbackType
		}
	}
	if err != nil {
		log.Warn("tryProposalNewBlock", "error", err)
		return err, nil, nil, nil
	}
	proposalRef, err := s.prepareHotstuffProposal(viewNumber, viewID, leaderID, data, nil)
	if err != nil {
		log.Warn("prepare txblock hotstuff proposal", "error", err)
		return err, nil, nil, nil
	}
	now := time.Now()
	if blockType == types.SlowTx_Block {
		s.lastSlowBlockTime = now
	} else if blockType == types.FastTx_Block {
		s.lastFastBlockTime = now
	}
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
	lastTxProposal := s.lastFastBlockTime
	if s.lastSlowBlockTime.After(lastTxProposal) {
		lastTxProposal = s.lastSlowBlockTime
	}
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
	if keyBlock := s.kbc.CurrentBlock(); keyBlock != nil {
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

func (s *Service) enqueueHotstuffPriority(msg *hotstuffMsg) {
	if s == nil || s.hotstuffMsgQ == nil || msg == nil {
		return
	}
	if !s.hotstuffMsgQ.pushPriority(msg) {
		code := uint32(0)
		if msg.hMsg != nil {
			code = msg.hMsg.Code
		}
		log.Debug("drop hotstuff priority message after bounded queue backpressure", "code", hotstuff.ReadableMsgType(code))
	}
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
	now := time.Now().UnixNano()
	prev := atomic.LoadInt64(&s.tryProposeQueuedAt)
	if prev != 0 && time.Duration(now-prev) < tryProposeDebounce {
		return
	}
	atomic.StoreInt64(&s.tryProposeQueuedAt, now)
	s.enqueueHotstuffPriority(&hotstuffMsg{
		sid:   nil,
		lastN: lastN,
		hMsg:  &hotstuff.HotstuffMessage{Code: hotstuff.MsgTryPropose},
	})
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
	log.Info("Write", "to id", id, "code", hotstuff.ReadableMsgType(data.Code), "ViewId", data.ViewId)

	if id == s.Self() {
		s.enqueueHotstuffPriority(&hotstuffMsg{sid: nil, hMsg: cloneHotstuffMessage(data)})
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
	mb := bftview.GetCurrentMember()
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

func (s *Service) handleHotStuffMsg() {
	for {
		data := s.hotstuffMsgQ.pop()
		if data == nil {
			time.Sleep(hotstuffIdleSleep)
			now := time.Now()

			fastPending, slowPending := s.lanePendingCounts()
			pendingTotal := 0
			if s.txPool != nil {
				pendingTotal, _ = s.txPool.Stats()
			}
			candidateRewardReady := s.fixedModeCandidateRewardReady(now)
			keyblockIntervalElapsed := s.fixedModeKeyblockIntervalElapsed(now)

			// Fixed-mode keyblock liveness:
			// This must run on every committee member, not only the leader.
			// Every member must first switch to the same keyblock view (NoDone=false)
			// before sending MsgNewView. If only the leader flips NoDone, replicas vote
			// for a different view hash and the leader never reaches the new-view quorum.
			if keyblockIntervalElapsed {
				s.wakeFixedModeKeyblock(now, "hotstuff-idle", candidateRewardReady, pendingTotal, fastPending, slowPending)

				// Keyblock interval has priority over tx/candidate liveness wakeups.
				// Let MsgStartNewView drive HotStuff to PhaseTryPropose instead of
				// enqueueing MsgTryPropose against a stale or nil leader view.
				s.protocolMng.HandleMessage(&hotstuff.HotstuffMessage{Code: hotstuff.MsgTimer, Number: s.currentHotstuffBaseNumber()})
				continue
			}

			// Fixed-mode liveness repair must run before IamLeader check.
			// If currentView is stuck in keyblock-wait state, IamLeader may be false
			// or tx proposal may be suppressed until the next 10-minute keyblock.
			s.repairFixedModeTxProposalViewIfPending(pendingTotal)

			if bftview.IamLeader(s.GetCurrentView().LeaderIndex) {
				cadenceReady := false

				if candidateRewardReady {
					// Candidate-only liveness:
					// If txpool is empty but a common-miner PoW candidate is ready
					// after KeyBlockMinInterval, wake keyblock proposal.
					cadenceReady = true
				} else if pendingTotal > 0 {
					// Strong liveness fallback:
					// If txpool has pending txs, always wake proposal periodically.
					cadenceReady = true

					if fastPending == 0 && slowPending == 0 {
						log.Warn("tx proposal liveness fallback wakeup",
							"pendingTotal", pendingTotal,
							"fastPending", fastPending,
							"slowPending", slowPending,
							"currentBlock", s.bc.CurrentBlockN())
					}
				} else {
					cadenceReady = (fastPending > 0 && s.shouldEmitFastBlock(now)) ||
						(slowPending > 0 && s.shouldEmitSlowBlock(now, slowPending))
				}

				if cadenceReady {
					if s.lastCadenceWakeup.IsZero() || now.Sub(s.lastCadenceWakeup) >= 50*time.Millisecond {
						s.lastCadenceWakeup = now
						if candidateRewardReady && pendingTotal == 0 {
							log.Warn("fixed-mode candidate reward new-view wakeup",
								"currentBlock", s.bc.CurrentBlockN(),
								"currentKey", s.kbc.CurrentBlockN(),
								"pendingTotal", pendingTotal,
								"fastPending", fastPending,
								"slowPending", slowPending)
							s.triggerTryPropose(s.bc.CurrentBlockN())
						} else {
							if candidateRewardReady && pendingTotal > 0 {
								log.Warn("fixed-mode candidate reward delayed because txpool has pending txs",
									"currentBlock", s.bc.CurrentBlockN(),
									"currentKey", s.kbc.CurrentBlockN(),
									"pendingTotal", pendingTotal,
									"fastPending", fastPending,
									"slowPending", slowPending)
							}
							s.triggerTryPropose(s.bc.CurrentBlockN())
						}
					}
				}
			}
			s.protocolMng.HandleMessage(&hotstuff.HotstuffMessage{Code: hotstuff.MsgTimer, Number: s.currentHotstuffBaseNumber()})
			continue
		}
		msg := data
		if msg == nil || msg.hMsg == nil {
			log.Warn("handleHotStuffMsg received nil message")
			continue
		}
		msgCode := msg.hMsg.Code
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
		if err == nil || (err == hotstuff.ErrInsufficientQC && msgCode != hotstuff.MsgTimeout) {
			s.observeHotstuffProgress(msg.hMsg)
		}
		if err != nil && err != hotstuff.ErrInsufficientQC && err != hotstuff.ErrUnhandledMsg && err != hotstuff.ErrOldState {
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
	if sendNewView {
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
	now := time.Now()
	curView := s.GetCurrentView()
	if s.fairHotstuffEnabled() {
		curN = curView.ViewNumber
		// A leader-created QC remains in a durable outbox until a higher QC
		// proves quorum dissemination. Replay it before every new-view attempt;
		// outbound coalescing prevents duplicate queue growth.
		s.replayPendingFHSQCBroadcast()
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
			peers, err := activeFHSAuthorizedPeers(nextCommittee)
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
	s.consensusSecret = secret
	s.consensusPublic = public
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

// call by miner.start
func (s *Service) start(config *common.NodeConfig) error {
	if !s.isRunning() {
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
		if s.fairHotstuffEnabled() {
			// WAL replay can complete a certified key-block parent and therefore
			// change the active committee. Determine the local role and configure
			// peer authentication only after that recovery is complete.
			isCommitteeMember := bftview.IamMember() >= 0
			if !isCommitteeMember {
				log.Info("Fair HotStuff service remains stopped for non-committee miner",
					"address", s.netService.serverAddress,
					"coinbase", config.Coinbase)
				return nil
			}
			s.updateCommittee(nil)
			peers, err := activeFHSAuthorizedPeers(bftview.GetCurrentMember())
			if err != nil {
				return err
			}
			if err := s.netService.server.ConfigurePeerAuthentication(s.ChainID(), s.netService.serverAddress, config.Private, config.Public, peers); err != nil {
				return fmt.Errorf("configure authenticated QUIC transport: %w", err)
			}
			s.netService.setAuthenticatedPeerKeys(peers)
		}
		s.setRunState(1)
		s.netService.StartStop(true)
		s.replayPendingFHSQCBroadcast()
		if bftview.IamMember() >= 0 {
			s.pacetMakerTimer.start()
			if s.fairHotstuffEnabled() && s.hasPendingFHSTimeoutVote() {
				s.enqueueFHSTimeout()
			} else {
				s.sendNewViewMsg(s.currentHotstuffBaseNumber())
			}
		}
	}
	return nil
}

func (s *Service) stop() {
	if s.isRunning() {
		s.netService.StartStop(false)
		s.pacetMakerTimer.stop()
		s.setRunState(0)
	}
}

func (s *Service) isRunning() bool {
	log.Info("service isRunning check")
	return atomic.LoadInt32(&s.runningState) == 1
}

func (s *Service) printAllStatus() {
	s.netService.GetNetBlocks(nil)
	for addr, a := range s.netService.ackMap {
		si := network.NewServerIdentity(addr)
		log.Info("ackInfo", "addr", addr, "id", si.ID)
		if a != nil {
			log.Info("ackInfo", "ackTm", a.ackTm, "sendTm", a.sendTm, "isSending", *a.isSending)
		}
	}
}

func (s *Service) setRunState(state int32) {
	atomic.StoreInt32(&s.runningState, state)
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
