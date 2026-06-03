package reconfig

import (
	"fmt"
	"sync"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rnet/network"
)

const (
	commonApprovalVoteTimeout     = 500 * time.Millisecond
	commonApprovalResponseTimeout = 2 * time.Second
)

const (
	commonApprovalRequest uint8 = iota + 1
	commonApprovalVote
	commonApprovalResponse
)

type commonApprovalViewData struct {
	Domain        string
	ChainID       uint64
	BlockHash     common.Hash
	BlockNumber   uint64
	KeyHash       common.Hash
	CommitteeHash common.Hash
}

type commonApprovalMsg struct {
	Type             uint8
	ValidatorAddress string
	BlockData        []byte
	ViewID           common.Hash
	LeaderID         string
	CommitteeHash    common.Hash
	SignerIndex      int
	Signature        []byte
	Mask             []byte
	Error            string
}

type commonApprovalLeaderSession struct {
	viewID           common.Hash
	leaderID         string
	validatorAddress string
	block            *types.Block
	votes            map[int][]byte
	done             chan *commonApprovalMsg
}

var commonApprovalRuntime = struct {
	sync.Mutex
	responses map[common.Hash]chan *commonApprovalMsg
	sessions  map[common.Hash]*commonApprovalLeaderSession
}{
	responses: make(map[common.Hash]chan *commonApprovalMsg),
	sessions:  make(map[common.Hash]*commonApprovalLeaderSession),
}

func (s *Service) commonApprovalViewID(block *types.Block, committeeHash common.Hash) common.Hash {
	chainID := uint64(0)
	if s.chainConfig != nil && s.chainConfig.ChainID != nil {
		chainID = s.chainConfig.ChainID.Uint64()
	}
	data := commonApprovalViewData{
		Domain:        "cypher-common-approval-v1",
		ChainID:       chainID,
		BlockHash:     block.Hash(),
		BlockNumber:   block.NumberU64(),
		KeyHash:       block.KeyHash(),
		CommitteeHash: committeeHash,
	}
	return rlpHash(data)
}

func (s *Service) attachCommonApprovalToEncodedBlock(data []byte) ([]byte, error) {
	if data == nil || s.chainConfig == nil || !s.chainConfig.CommonApprovalEnabled {
		return data, nil
	}
	block := types.DecodeToBlock(data)
	if block == nil {
		return nil, fmt.Errorf("common approval failed: cannot decode proposed block")
	}
	if err := s.attachCommonApproval(block); err != nil {
		return nil, err
	}
	return block.EncodeToBytes(), nil
}

// attachCommonApproval asks the active common-approval leader to approve the tx
// block. The common leader validates the tx block, collects votes from the active
// common committee and returns a CommonApprovalQC. Validator HotStuff then
// finalizes only the tx block carrying that QC.
func (s *Service) attachCommonApproval(block *types.Block) error {
	if !core.CommonApprovalRequired(s.chainConfig, block) {
		return nil
	}
	return s.requestCommonApproval(block)
}

func (s *Service) requestCommonApproval(block *types.Block) error {
	if err := core.ValidateCommonApprovalCommittee(s.chainConfig); err != nil {
		return err
	}
	nodes := core.OrderedCommonCommittee(s.chainConfig)
	if len(nodes) == 0 || nodes[0] == nil || nodes[0].Address == "" {
		return fmt.Errorf("common approval failed: active common leader is empty")
	}

	leader := nodes[0]
	committeeHash := core.CommonApprovalCommitteeHash(s.chainConfig)
	leaderID := bftview.GetNodeID(leader.Address, leader.Public)
	viewID := s.commonApprovalViewID(block, committeeHash)
	payload := block.CopyNoSignInfo().EncodeToBytes()
	if payload == nil {
		return types.ErrEncodeRLP
	}

	respCh := make(chan *commonApprovalMsg, 1)
	commonApprovalRuntime.Lock()
	commonApprovalRuntime.responses[viewID] = respCh
	commonApprovalRuntime.Unlock()
	defer func() {
		commonApprovalRuntime.Lock()
		delete(commonApprovalRuntime.responses, viewID)
		commonApprovalRuntime.Unlock()
	}()

	req := &commonApprovalMsg{
		Type:             commonApprovalRequest,
		ValidatorAddress: s.netService.serverAddress,
		BlockData:        block.EncodeToBytes(),
		ViewID:           viewID,
		LeaderID:         leaderID,
		CommitteeHash:    committeeHash,
	}
	log.Info("common approval request", "view", viewID.Hex(), "leader", leader.Address, "block", block.NumberU64())

	if s.isSelfAddress(leader.Address) {
		go s.handleCommonApprovalMsg(req)
	} else {
		s.sendCommonApprovalRaw(leader.Address, req)
	}

	select {
	case resp := <-respCh:
		if resp == nil {
			return fmt.Errorf("common approval failed: empty response")
		}
		if resp.Error != "" {
			return fmt.Errorf("common approval failed: %s", resp.Error)
		}
		if resp.CommitteeHash != committeeHash || resp.ViewID != viewID || resp.LeaderID != leaderID {
			return fmt.Errorf("common approval failed: response context mismatch")
		}
		block.SetCommonApproval(resp.Signature, resp.Mask, resp.ViewID, resp.LeaderID, resp.CommitteeHash)
		if err := core.VerifyCommonApproval(s.chainConfig, block); err != nil {
			return err
		}
		log.Info("common approval attached", "view", viewID.Hex(), "block", block.NumberU64())
		return nil
	case <-time.After(commonApprovalResponseTimeout):
		return fmt.Errorf("common approval timeout waiting for common leader %s", leader.Address)
	}
}

func (s *Service) commonApprovalMsgAck(si *network.ServerIdentity, msg *commonApprovalMsg) {
	if msg == nil {
		return
	}
	s.handleCommonApprovalMsg(msg)
}

func (s *Service) handleCommonApprovalMsg(msg *commonApprovalMsg) {
	if msg == nil {
		return
	}
	switch msg.Type {
	case commonApprovalRequest:
		go s.routeCommonApprovalRequest(msg)
	case commonApprovalVote:
		s.handleCommonApprovalVote(msg)
	case commonApprovalResponse:
		s.handleCommonApprovalResponse(msg)
	default:
		log.Warn("unknown common approval message", "type", msg.Type)
	}
}

func (s *Service) routeCommonApprovalRequest(req *commonApprovalMsg) {
	if s.isCommonApprovalLeader(req.LeaderID) {
		s.handleCommonApprovalRequest(req)
		return
	}
	s.handleCommonApprovalVoteRequest(req)
}

func (s *Service) handleCommonApprovalRequest(req *commonApprovalMsg) {
	if req == nil {
		return
	}
	block := types.DecodeToBlock(req.BlockData)
	if block == nil {
		s.sendCommonApprovalResponse(req, nil, nil, "cannot decode tx block")
		return
	}
	if !s.isCommonApprovalLeader(req.LeaderID) {
		s.sendCommonApprovalResponse(req, nil, nil, "receiver is not active common leader")
		return
	}
	if req.CommitteeHash != core.CommonApprovalCommitteeHash(s.chainConfig) {
		s.sendCommonApprovalResponse(req, nil, nil, "common committee hash mismatch")
		return
	}
	if req.ViewID != s.commonApprovalViewID(block, req.CommitteeHash) {
		s.sendCommonApprovalResponse(req, nil, nil, "common approval view mismatch")
		return
	}
	if req.ValidatorAddress == "" {
		s.sendCommonApprovalResponse(req, nil, nil, "validator address is empty")
		return
	}
	if err := s.txService.verifyTxBlock(block); err != nil {
		s.sendCommonApprovalResponse(req, nil, nil, err.Error())
		return
	}

	sig, index, err := s.signCommonApproval(block, req.ViewID, req.LeaderID, req.CommitteeHash)
	if err != nil {
		s.sendCommonApprovalResponse(req, nil, nil, err.Error())
		return
	}
	session := &commonApprovalLeaderSession{
		viewID:           req.ViewID,
		leaderID:         req.LeaderID,
		validatorAddress: req.ValidatorAddress,
		block:            block,
		votes:            map[int][]byte{index: sig},
		done:             make(chan *commonApprovalMsg, 1),
	}

	commonApprovalRuntime.Lock()
	commonApprovalRuntime.sessions[req.ViewID] = session
	commonApprovalRuntime.Unlock()
	defer func() {
		commonApprovalRuntime.Lock()
		delete(commonApprovalRuntime.sessions, req.ViewID)
		commonApprovalRuntime.Unlock()
	}()

	s.broadcastCommonApprovalVoteRequest(req)
	commonApprovalRuntime.Lock()
	resp := s.tryBuildCommonApprovalResponse(session)
	commonApprovalRuntime.Unlock()
	if resp != nil {
		s.deliverCommonApprovalResponse(resp)
		return
	}

	select {
	case resp := <-session.done:
		s.deliverCommonApprovalResponse(resp)
	case <-time.After(commonApprovalVoteTimeout):
		commonApprovalRuntime.Lock()
		resp := s.tryBuildCommonApprovalResponse(session)
		commonApprovalRuntime.Unlock()
		if resp != nil {
			s.deliverCommonApprovalResponse(resp)
			return
		}
		s.sendCommonApprovalResponse(req, nil, nil, "common committee threshold not reached")
	}
}

func (s *Service) broadcastCommonApprovalVoteRequest(req *commonApprovalMsg) {
	nodes := core.OrderedCommonCommittee(s.chainConfig)
	for _, node := range nodes {
		if node == nil || node.Address == "" || s.isSelfAddress(node.Address) {
			continue
		}
		s.sendCommonApprovalRaw(node.Address, req)
	}
}

func (s *Service) handleCommonApprovalVoteRequest(req *commonApprovalMsg) {
	if req == nil {
		return
	}
	block := types.DecodeToBlock(req.BlockData)
	if block == nil {
		return
	}
	if err := s.txService.verifyTxBlock(block); err != nil {
		log.Warn("common approval vote rejected", "view", req.ViewID.Hex(), "err", err)
		return
	}
	sig, index, err := s.signCommonApproval(block, req.ViewID, req.LeaderID, req.CommitteeHash)
	if err != nil {
		log.Warn("common approval vote sign failed", "view", req.ViewID.Hex(), "err", err)
		return
	}
	vote := &commonApprovalMsg{
		Type:          commonApprovalVote,
		ViewID:        req.ViewID,
		LeaderID:      req.LeaderID,
		CommitteeHash: req.CommitteeHash,
		SignerIndex:   index,
		Signature:     sig,
	}
	leaderAddr := ""
	if nodes := core.OrderedCommonCommittee(s.chainConfig); len(nodes) > 0 && nodes[0] != nil {
		leaderAddr = nodes[0].Address
	}
	if leaderAddr == "" {
		return
	}
	if s.isSelfAddress(leaderAddr) {
		s.handleCommonApprovalVote(vote)
	} else {
		s.sendCommonApprovalRaw(leaderAddr, vote)
	}
}

func (s *Service) handleCommonApprovalVote(vote *commonApprovalMsg) {
	if vote == nil {
		return
	}
	commonApprovalRuntime.Lock()
	session := commonApprovalRuntime.sessions[vote.ViewID]
	var resp *commonApprovalMsg
	if session != nil && s.verifyCommonApprovalVote(session, vote) {
		if session.votes == nil {
			session.votes = make(map[int][]byte)
		}
		session.votes[vote.SignerIndex] = vote.Signature
		resp = s.tryBuildCommonApprovalResponse(session)
	}
	commonApprovalRuntime.Unlock()
	if session == nil || resp == nil {
		return
	}
	select {
	case session.done <- resp:
	default:
	}
}

func (s *Service) handleCommonApprovalResponse(resp *commonApprovalMsg) {
	if resp == nil {
		return
	}
	commonApprovalRuntime.Lock()
	pending := commonApprovalRuntime.responses[resp.ViewID]
	commonApprovalRuntime.Unlock()
	if pending == nil {
		return
	}
	select {
	case pending <- resp:
	default:
	}
}

func (s *Service) signCommonApproval(block *types.Block, viewID common.Hash, leaderID string, committeeHash common.Hash) ([]byte, int, error) {
	if block == nil {
		return nil, -1, fmt.Errorf("nil block")
	}
	if committeeHash != core.CommonApprovalCommitteeHash(s.chainConfig) {
		return nil, -1, fmt.Errorf("common committee hash mismatch")
	}
	if viewID != s.commonApprovalViewID(block, committeeHash) {
		return nil, -1, fmt.Errorf("common approval view mismatch")
	}
	nodes := core.OrderedCommonCommittee(s.chainConfig)
	selfPub := bftview.GetServerInfo(bftview.PublicKey)
	if selfPub == "" {
		return nil, -1, fmt.Errorf("local BLS public key is empty")
	}
	selfIndex := -1
	for i, node := range nodes {
		if node != nil && node.Public == selfPub {
			selfIndex = i
			break
		}
	}
	if selfIndex < 0 {
		return nil, -1, fmt.Errorf("local node is not in active commonCommittee")
	}
	payload := block.CopyNoSignInfo().EncodeToBytes()
	if payload == nil {
		return nil, -1, types.ErrEncodeRLP
	}
	return s.protocolMng.SignHashByMessage(hotstuff.MsgVotePrepare, viewID, leaderID, payload), selfIndex, nil
}

func (s *Service) verifyCommonApprovalVote(session *commonApprovalLeaderSession, vote *commonApprovalMsg) bool {
	if session == nil || vote == nil || vote.Signature == nil {
		return false
	}
	nodes := core.OrderedCommonCommittee(s.chainConfig)
	if vote.SignerIndex < 0 || vote.SignerIndex >= len(nodes) {
		return false
	}
	payload := session.block.CopyNoSignInfo().EncodeToBytes()
	if payload == nil {
		return false
	}
	mask := make([]byte, (len(nodes)+7)/8)
	mask[vote.SignerIndex/8] |= 1 << uint(vote.SignerIndex%8)
	pubs, err := core.CommonApprovalPublicKeys(nodes)
	if err != nil {
		log.Warn("common approval public key load failed", "err", err)
		return false
	}
	chainID := uint64(0)
	if s.chainConfig != nil && s.chainConfig.ChainID != nil {
		chainID = s.chainConfig.ChainID.Uint64()
	}
	return hotstuff.VerifySignatureWithContext(vote.Signature, mask, payload, pubs, 1, chainID, hotstuff.MsgVotePrepare, session.viewID, session.leaderID)
}

func (s *Service) tryBuildCommonApprovalResponse(session *commonApprovalLeaderSession) *commonApprovalMsg {
	if session == nil {
		return nil
	}
	nodes := core.OrderedCommonCommittee(s.chainConfig)
	threshold := core.CommonApprovalThreshold(s.chainConfig, len(nodes))
	if len(session.votes) < threshold {
		return nil
	}
	sig, mask, err := aggregateCommonApprovalSignatures(session.votes, len(nodes))
	if err != nil {
		log.Warn("common approval aggregate failed", "err", err)
		return nil
	}
	return &commonApprovalMsg{
		Type:             commonApprovalResponse,
		ValidatorAddress: session.validatorAddress,
		BlockData:        session.block.EncodeToBytes(),
		ViewID:           session.viewID,
		LeaderID:         session.leaderID,
		CommitteeHash:    core.CommonApprovalCommitteeHash(s.chainConfig),
		Signature:        sig,
		Mask:             mask,
	}
}

func aggregateCommonApprovalSignatures(votes map[int][]byte, committeeSize int) ([]byte, []byte, error) {
	if committeeSize <= 0 || len(votes) == 0 {
		return nil, nil, fmt.Errorf("empty common approval vote set")
	}
	mask := make([]byte, (committeeSize+7)/8)
	var agg bls.Sign
	first := true
	for index, raw := range votes {
		if index < 0 || index >= committeeSize {
			return nil, nil, fmt.Errorf("common approval vote index %d out of range", index)
		}
		var sig bls.Sign
		if err := sig.Deserialize(raw); err != nil {
			return nil, nil, err
		}
		if first {
			if err := agg.Deserialize(sig.Serialize()); err != nil {
				return nil, nil, err
			}
			first = false
		} else {
			agg.Add(&sig)
		}
		mask[index/8] |= 1 << uint(index%8)
	}
	return agg.Serialize(), mask, nil
}

func (s *Service) sendCommonApprovalResponse(req *commonApprovalMsg, sig []byte, mask []byte, errText string) {
	if req == nil {
		return
	}
	resp := &commonApprovalMsg{
		Type:             commonApprovalResponse,
		ValidatorAddress: req.ValidatorAddress,
		BlockData:        req.BlockData,
		ViewID:           req.ViewID,
		LeaderID:         req.LeaderID,
		CommitteeHash:    req.CommitteeHash,
		Signature:        sig,
		Mask:             mask,
		Error:            errText,
	}
	s.deliverCommonApprovalResponse(resp)
}

func (s *Service) deliverCommonApprovalResponse(resp *commonApprovalMsg) {
	if resp == nil {
		return
	}
	if resp.ValidatorAddress == "" || s.isSelfAddress(resp.ValidatorAddress) {
		s.handleCommonApprovalResponse(resp)
		return
	}
	s.sendCommonApprovalRaw(resp.ValidatorAddress, resp)
}

func (s *Service) isCommonApprovalLeader(leaderID string) bool {
	nodes := core.OrderedCommonCommittee(s.chainConfig)
	if len(nodes) == 0 || nodes[0] == nil {
		return false
	}
	selfPub := bftview.GetServerInfo(bftview.PublicKey)
	return nodes[0].Public == selfPub && bftview.GetNodeID(nodes[0].Address, nodes[0].Public) == leaderID
}

func (s *Service) sendCommonApprovalRaw(address string, msg *commonApprovalMsg) error {
	if address == "" || msg == nil {
		return nil
	}
	if s.isSelfAddress(address) {
		s.handleCommonApprovalMsg(msg)
		return nil
	}
	si := network.NewServerIdentity(address)
	return s.netService.SendRaw(si, msg, false)
}

func (s *Service) isSelfAddress(address string) bool {
	return address == s.netService.serverAddress || IsSelf(address)
}
