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

const proposalBodyCacheTTL = 2 * time.Minute
const proposalBodyWaitBaseTimeout = 2 * time.Second
const proposalBodyWaitMaxTimeout = 30 * time.Second
const proposalBodyWaitBytesPerSecond = 2 * 1024 * 1024
const proposalBodyRequestAfter = 250 * time.Millisecond
const proposalBodyRequestInterval = 250 * time.Millisecond
const proposalBodyPollInterval = 5 * time.Millisecond
const proposalBodySidecarMaxBytes = 256 * 1024 * 1024

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
	ViewID     common.Hash
	LeaderID   string
	From       string

	EncodedBlock      []byte
	CreatedAtUnixNano int64
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

	s.lastCmInfoMap = make(map[common.Hash]*cachedCommitteeInfo)
	s.proposalBodies = make(map[common.Hash]*proposalBodyMsg)
	s.verifiedProposalByID = make(map[common.Hash]*core.VerifiedProposal)

	s.msgCh1 = make(chan committeeMsg, 10)
	s.msgSub1 = s.feed1.Subscribe(s.msgCh1)
	s.hotstuffMsgQ = newHotstuffMessageQueue()
	s.hotstuffProgressAt = time.Now()

	s.protocolMng = hotstuff.NewHotstuffProtocolManager(s, nil, nil)
	s.pacetMakerTimer = newPaceMakerTimer(chainConfig, s, backend)

	bftview.SetCommitteeConfig(backend.ChainDb(), backend.KeyBlockChain(), s)

	go s.handleHotStuffMsg()
	go s.handleCommitteeMsg()
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

// CurrentState call by hotstuff
func (s *Service) CurrentState() ([]byte, string, uint64) { //recv by onnewview
	curView := s.GetCurrentView()
	leaderID := ""
	mb := bftview.GetCurrentMember()
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
			"committeeSize", committeeSize)
		s.Committee_Request(curView.KeyNumber, curView.KeyHash)
	}

	log.Info("CurrentState", "TxNumber", curView.TxNumber, "KeyNumber", curView.KeyNumber, "LeaderIndex", curView.LeaderIndex, "NoDone", curView.NoDone)

	return curView.EncodeConsensusToBytes(), leaderID, curView.TxNumber + 1
}

// GetExtra call by hotstuff
func (s *Service) GetExtra() []byte {
	best := s.keyService.getBestCandidate(true)
	if best == nil {
		return nil
	}
	return best.EncodeToBytes()
}

// GetPublicKey call by hotstuff
func (s *Service) GetPublicKey() []*bls.PublicKey {
	keyblock := s.kbc.CurrentBlock()
	keyNumber := keyblock.NumberU64()
	c := bftview.LoadMember(keyNumber, keyblock.Hash(), false)
	if c == nil {
		return nil
	}
	return c.ToBlsPublicKeys(keyblock.Hash())
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

func validateViewAgainstSnapshot(data []byte, current bftview.View) ([]byte, uint64, error) {
	view := bftview.DecodeToView(data)
	if view == nil {
		return nil, 0, fmt.Errorf("invalid hotstuff view encoding")
	}

	expectedState := current.EncodeConsensusToBytes()
	expectedNumber := current.TxNumber + 1
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

	leaderID := ""
	committee := bftview.GetCurrentMember()
	if committee != nil && current.LeaderIndex < uint(len(committee.List)) {
		leader := committee.List[current.LeaderIndex]
		if leader != nil {
			leaderID = bftview.GetNodeID(leader.Address, leader.Public)
		}
	}

	log.Debug("ValidateView..",
		"txNumber", view.TxNumber,
		"keyNumber", view.KeyNumber,
		"local key number", current.KeyNumber,
		"tx number", current.TxNumber)

	expectedState, expectedNumber, err := validateViewAgainstSnapshot(data, current)
	return expectedState, leaderID, expectedNumber, err
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
	return &out
}

func (s *Service) purgeExpiredProposalCachesLocked(now time.Time) {
	for id, body := range s.proposalBodies {
		if body == nil || (body.CreatedAtUnixNano > 0 && now.Sub(time.Unix(0, body.CreatedAtUnixNano)) > proposalBodyCacheTTL) {
			delete(s.proposalBodies, id)
			delete(s.verifiedProposalByID, id)
		}
	}
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
	cpy := cloneProposalBodyMsg(body)
	cpy.Type = proposalBodyMsgData
	if cpy.From == "" {
		cpy.From = s.Self()
	}
	if cpy.CreatedAtUnixNano == 0 {
		cpy.CreatedAtUnixNano = time.Now().UnixNano()
	}

	s.muProposalBody.Lock()
	defer s.muProposalBody.Unlock()
	s.purgeExpiredProposalCachesLocked(time.Now())
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

func (s *Service) prepareHotstuffProposal(viewID common.Hash, leaderID string, encodedBlock []byte) ([]byte, error) {
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
	ref, err := types.NewHotstuffProposalRef(s.ChainID(), viewID, leaderID, block, encodedBlock)
	if err != nil {
		return nil, err
	}
	proposalID := ref.ProposalID()
	body := &proposalBodyMsg{
		Type:              proposalBodyMsgData,
		ProposalID:        proposalID,
		BodyHash:          ref.BodyHash,
		Number:            ref.Number,
		ViewID:            ref.ViewID,
		LeaderID:          ref.LeaderID,
		From:              s.Self(),
		EncodedBlock:      encodedBlock,
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
	for _, node := range mb.List {
		if node == nil || node.Address == "" || IsSelf(node.Address) {
			continue
		}
		cpy := cloneProposalBodyMsg(body)
		if cpy != nil {
			cpy.From = s.Self()
		}
		log.Info("HOTSTUFF PROPOSAL BODY SEND",
			"to", node.Address,
			"number", body.Number,
			"proposalID", body.ProposalID,
			"bodyHash", body.BodyHash,
			"bytes", len(body.EncodedBlock))
		if err := s.netService.SendRawData(node.Address, &networkMsg{Pmsg: cpy}); err != nil {
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
		ViewID:            ref.ViewID,
		LeaderID:          ref.LeaderID,
		From:              s.Self(),
		CreatedAtUnixNano: time.Now().UnixNano(),
	}

	mb := bftview.GetCurrentMember()
	if mb == nil {
		return
	}
	for _, node := range mb.List {
		if node == nil || node.Address == "" || IsSelf(node.Address) {
			continue
		}
		if ref.LeaderID != "" {
			nodeID := bftview.GetNodeID(node.Address, node.Public)
			if nodeID != ref.LeaderID {
				continue
			}
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
	deadline := time.Now().Add(proposalBodyWaitTimeout(ref.BodySize))
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
		log.Info("HOTSTUFF PROPOSAL BODY RESPONSE", "to", address, "number", body.Number, "proposalID", body.ProposalID, "bytes", len(body.EncodedBlock))
		if err := s.netService.SendRawData(address, &networkMsg{Pmsg: cpy}); err != nil {
			log.Warn("HOTSTUFF PROPOSAL BODY response failed", "to", address, "number", body.Number, "proposalID", body.ProposalID, "err", err)
		}
	default:
		log.Warn("HOTSTUFF PROPOSAL BODY unknown type", "type", msg.Type, "number", msg.Number, "proposalID", msg.ProposalID)
	}
}

// OnPropose call by hotstuff
func (s *Service) OnPropose(state []byte, extra []byte) error { // verify new proposal ref and full sidecar body before voting
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
	if block.BlockType() == types.Key_Block {
		kblock := types.DecodeToKeyBlock(block.KeyInfo())
		if kblock == nil {
			return fmt.Errorf("Block's extra (keyblock) is error format!")
		}
		if err := s.keyService.verifyKeyBlock(kblock, types.DecodeToCandidate(extra)); err != nil {
			log.Error("verify keyblock", "number", kblock.NumberU64(), "proposalID", proposalID, "err", err)
			return err
		}
	}
	s.storeVerifiedProposal(proposalID, verified)
	s.pacetMakerTimer.start()
	return nil
}

// Propose call by hotstuff
func (s *Service) Propose(viewID common.Hash, leaderID string) (e error, kState []byte, tState []byte, extra []byte) { //buf recv by onpropose, onviewdown
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

	if keyProposal && keyBlockIntervalElapsed {
		keyblock, mb, bestCandi, err := s.keyService.tryProposalChangeCommittee(leaderIndex, !noDone)
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
			proposalRef, err := s.prepareHotstuffProposal(viewID, leaderID, data)
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
	proposalRef, err := s.prepareHotstuffProposal(viewID, leaderID, data)
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
	if s.keyService != nil {
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
	s.waittingView.TxNumber = s.currentView.TxNumber + 1
	s.waittingView.KeyNumber = s.currentView.KeyNumber + 1

	curView = s.currentView
	fallbackRound = s.fixedKeyFallbackRound
	return oldView, curView, fallbackRound, viewAge
}

func (s *Service) triggerTryPropose(lastN uint64) {
	if atomic.LoadInt32(&s.runningState) != 1 {
		return
	}
	now := time.Now().UnixNano()
	prev := atomic.LoadInt64(&s.tryProposeQueuedAt)
	if prev != 0 && time.Duration(now-prev) < tryProposeDebounce {
		return
	}
	atomic.StoreInt64(&s.tryProposeQueuedAt, now)
	s.hotstuffMsgQ.push(&hotstuffMsg{
		sid:   nil,
		lastN: lastN,
		hMsg:  &hotstuff.HotstuffMessage{Code: hotstuff.MsgTryPropose},
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
	if err := s.txService.decideVerifiedProposal(ref, verified, tSign.Sign, tSign.Mask, tSign.ViewID, tSign.LeaderID); err != nil {
		return err
	}
	s.deleteProposalCaches(proposalID)
	return nil
}

// Write call by hotstuff------------------------------------------------------------------------------------------------
func (s *Service) Write(id string, data *hotstuff.HotstuffMessage) error {
	log.Info("Write", "to id", id, "code", hotstuff.ReadableMsgType(data.Code), "ViewId", data.ViewId)

	if id == s.Self() {
		s.hotstuffMsgQ.push(&hotstuffMsg{sid: nil, hMsg: data})
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
		"dataF", len(data.DataF))

	// Local delivery is retained for protocol correctness. Leader self-vote
	// optimization belongs in hotstuff.go and must preserve quorum accounting.
	s.hotstuffMsgQ.push(&hotstuffMsg{sid: nil, hMsg: data})

	// Production rule: HotStuff control messages use direct committee delivery.
	// Large proposal bodies are distributed as proposalBodyMsg sidecars, not in
	// MsgPrepare.DataB.
	switch data.Code {
	case hotstuff.MsgPrepare, hotstuff.MsgDecide:
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
		s.hotstuffMsgQ.push(&hotstuffMsg{sid: si, hMsg: msg.Hmsg})
		return
	}
	s.feed1.Send(committeeMsg{sid: si, cinfo: msg.Cmsg, best: msg.Bmsg})
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
				if s.lastFixedKeyNewViewWakeup.IsZero() || now.Sub(s.lastFixedKeyNewViewWakeup) >= 2*time.Second {
					s.lastFixedKeyNewViewWakeup = now
					oldView, curView, fallbackRound, viewAge := s.prepareFixedModeKeyblockView(now)
					log.Warn("fixed-mode keyblock start-new-view wakeup",
						"currentBlock", s.bc.CurrentBlockN(),
						"currentKey", s.kbc.CurrentBlockN(),
						"oldLeaderIndex", oldView.LeaderIndex,
						"oldNoDone", oldView.NoDone,
						"leaderIndex", curView.LeaderIndex,
						"noDone", curView.NoDone,
						"fallbackRound", fallbackRound,
						"viewAge", viewAge,
						"isLeader", bftview.IamLeader(curView.LeaderIndex),
						"candidateReady", candidateRewardReady,
						"pendingTotal", pendingTotal,
						"fastPending", fastPending,
						"slowPending", slowPending)
					s.sendNewViewMsg(s.bc.CurrentBlockN())
				}

				// Keyblock interval has priority over tx/candidate liveness wakeups.
				// Let MsgStartNewView drive HotStuff to PhaseTryPropose instead of
				// enqueueing MsgTryPropose against a stale or nil leader view.
				s.protocolMng.HandleMessage(&hotstuff.HotstuffMessage{Code: hotstuff.MsgTimer, Number: s.bc.CurrentBlockN()})
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
			s.protocolMng.HandleMessage(&hotstuff.HotstuffMessage{Code: hotstuff.MsgTimer, Number: s.bc.CurrentBlockN()})
			continue
		}
		msg := data
		if msg == nil || msg.hMsg == nil {
			log.Warn("handleHotStuffMsg received nil message")
			continue
		}
		msgCode := msg.hMsg.Code
		log.Debug("handleHotStuffMsg", "id", msg.hMsg.Id, "code", hotstuff.ReadableMsgType(msgCode), "ViewId", msg.hMsg.ViewId)

		var curN uint64
		if msgCode == hotstuff.MsgTryPropose || msgCode == hotstuff.MsgStartNewView {
			curN = s.bc.CurrentBlockN()
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
		if err == nil || err == hotstuff.ErrInsufficientQC {
			s.observeHotstuffProgress(msg.hMsg)
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
	case hotstuff.MsgDecide:
		rank = 3
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

	if fromKeyBlock || curBlock.NumberU64() > curKeyBlock.T_Number() {
		s.currentView.LeaderIndex = 0
		s.currentView.NoDone = true
	}
	log.Debug("updateCurrentView", "TxNumber", s.currentView.TxNumber, "KeyNumber", s.currentView.KeyNumber, "LeaderIndex", s.currentView.LeaderIndex, "NoDone", s.currentView.NoDone)
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

func (s *Service) getBestCandidate(refresh bool) *types.Candidate {
	return s.keyService.getBestCandidate(refresh)
}

// Send new view when new block done
func (s *Service) sendNewViewMsg(curN uint64) {
	now := time.Now()
	curView := s.GetCurrentView()
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

	if bftview.IamMember() >= 0 && curN >= s.bc.CurrentBlockN() {
		s.hotstuffMsgQ.push(&hotstuffMsg{sid: nil, lastN: curN, hMsg: &hotstuff.HotstuffMessage{Code: hotstuff.MsgStartNewView, Number: curN}})
	}
}

// Set next leader by prescribed rules
func (s *Service) setNextLeader(isDone bool) {
	s.muCurrentView.Lock()
	defer s.muCurrentView.Unlock()

	fixedMode := s.keyService != nil && s.keyService.fixedModeEnabled()
	if fixedMode {
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
	if s.keyService == nil {
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
		s.updateCurrentView(block, keyblock, true)
		s.muCurrentView.Lock()
		s.resetFixedModeKeyblockViewLocked()
		s.muCurrentView.Unlock()
		if s.keyService != nil && s.keyService.fixedModeEnabled() {
			s.keyService.setActiveLeader(0)
		}
		s.keyService.clearCandidate(keyblock)
	} else {
		log.Info("@TxBlockDone", "number", block.NumberU64(), "keyhash", block.KeyHash())
		s.updateCommittee(nil)
		s.updateCurrentView(block, keyblock, false)
		keyblock = s.kbc.CurrentBlock()
		//s.txPool.RemoveBatch(block.Transactions())
	}

	s.pacetMakerTimer.procBlockDone(block, keyblock, beKeyBlock)
	s.netService.procBlockDone(block.NumberU64(), keyblock.NumberU64())
	if beKeyBlock && keyblock != nil {
		s.kbc.PostBlock(keyblock)
	}
}

// call by miner.start
func (s *Service) start(config *common.NodeConfig) {
	if !s.isRunning() {
		s.protocolMng.UpdateKeyPair(bftview.StrToBlsPrivKey(config.Private))
		bftview.SetServerInfo(s.netService.serverAddress, config.Public)
		if config.Coinbase != "" {
			bftview.SetServerCoinBase(common.HexToAddress(config.Coinbase))
		}
		s.netService.StartStop(true)
		if bftview.IamMember() >= 0 {
			s.updateCommittee(nil)
			s.pacetMakerTimer.start()
		}
		s.updateCurrentView(nil, nil, false)
		s.setRunState(1)
	}
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
