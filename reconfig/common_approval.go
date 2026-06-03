package reconfig

import (
	"fmt"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
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

type pendingCommonApprovalResponse struct {
	ch chan *commonApprovalMsg
}

type commonApprovalLeaderSession struct {
	viewID           common.Hash
	leaderID         string
	validatorAddress string
	block            *types.Block
	votes            map[int][]byte
	done             chan *commonApprovalMsg
}

func (s *Service) initCommonApprovalState() {
	s.commonApprovalResponses = make(map[common.Hash]*pendingCommonApprovalResponse)
	s.commonApprovalSessions = make(map[common.Hash]*commonApprovalLeaderSession)
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

// attachCommonApproval asks the common-approval HotStuff leader to approve the
// tx block. The common leader validates the tx block, collects votes from the
// active common committee and returns a CommonApprovalQC. Validator HotStuff then
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
	if len(nodes) == 0 || nodes[0] == nil {
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
	s.commonApprovalMu.Lock()
	s.commonApprovalResponses[viewID] = &pendingCommonApprovalResponse{ch: respCh}
	s.commonApprovalMu.Unlock()
	defer func() {
		s.commonApprovalMu.Lock()
		delete(s.commonApprovalResponses, viewID)
		s.commonApprovalMu.Unlock()
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

	if IsSelf(leader.Address) {
		go s.handleCommonApprovalMsg(nil, req)
	} else {
		s.netService.SendRawData(leader.Address, &networkMsg{Amsg: req})
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

func (s *Service) handleCommonApprovalMsg(si interface{}, msg *commonApprovalMsg) {
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

	s.commonApprovalMu.Lock()
	s.commonApprovalSessions[req.ViewID] = session
	s.commonApprovalMu.Unlock()
	defer func() {
		s.commonApprovalMu.Lock()
		delete(s.commonApprovalSessions, req.ViewID)
		s.commonApprovalMu.Unlock()
	}()

	s.broadcastCommonApprovalVoteRequest(req)
	s.commonApprovalMu.Lock()
	resp := s.tryBuildCommonApprovalResponse(session)
	s.commonApprovalMu.Unlock()
	if resp != nil {
		s.deliverCommonApprovalResponse(resp)
		return
	}

	select {
	case resp := <-session.done:
		s.deliverCommonApprovalResponse(resp)
	case <-time.After(commonApprovalVoteTimeout):
		s.commonApprovalMu.Lock()
		resp := s.tryBuildCommonApprovalResponse(session)
		s.commonApprovalMu.Unlock()
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
		if node == nil || node.Address == "" || IsSelf(node.Address) {
			continue
		}
		s.netService.SendRawData(node.Address, &networkMsg{Amsg: req})
	}
}

func (s *Service) handleCommonApprovalVote(vote *commonApprovalMsg) {
	if vote == nil {
		return
	}
	s.commonApprovalMu.Lock()
	session := s.commonApprovalSessions[vote.ViewID]
	var resp *commonApprovalMsg
	if session != nil {
		if session.votes == nil {
			session.votes = make(map[int][]byte)
		}
		if vote.Signature != nil && vote.SignerIndex >= 0 {
			session.votes[vote.SignerIndex] = vote.Signature
		}
		resp = s.tryBuildCommonApprovalResponse(session)
	}
	s.commonApprovalMu.Unlock()
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
	s.commonApprovalMu.Lock()
	pending := s.commonApprovalResponses[resp.ViewID]
	s.commonApprovalMu.Unlock()
	if pending == nil {
		return
	}
	select {
	case pending.ch <- resp:
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

func (s *Service) tryBuildCommonApprovalResponse(session *commonApprovalLeaderSession) *commonApprovalMsg {
	if session == nil {
		return nil
	}
	nodes := core.OrderedCommonCommittee(s.chainConfig)
	threshold := core.CommonApprovalThreshold(s.chainConfig, len(nodes))
	if len(session.votes) < threshold {
		return nil
	}
	sig, mask, err := hotstuff.AggregateIndexedSignatures(session.votes, len(nodes))
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
	if resp.ValidatorAddress == "" || IsSelf(resp.ValidatorAddress) {
		s.handleCommonApprovalResponse(resp)
		return
	}
	s.netService.SendRawData(resp.ValidatorAddress, &networkMsg{Amsg: resp})
}

func (s *Service) isCommonApprovalLeader(leaderID string) bool {
	nodes := core.OrderedCommonCommittee(s.chainConfig)
	if len(nodes) == 0 || nodes[0] == nil {
		return false
	}
	selfPub := bftview.GetServerInfo(bftview.PublicKey)
	return nodes[0].Public == selfPub && bftview.GetNodeID(nodes[0].Address, nodes[0].Public) == leaderID
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
	if IsSelf(leaderAddr) {
		s.handleCommonApprovalVote(vote)
	} else {
		s.netService.SendRawData(leaderAddr, &networkMsg{Amsg: vote})
	}
}

func (s *Service) routeCommonApprovalRequest(msg *commonApprovalMsg) {
	if msg == nil {
		return
	}
	if s.isCommonApprovalLeader(msg.LeaderID) {
		s.handleCommonApprovalRequest(msg)
		return
	}
	s.handleCommonApprovalVoteRequest(msg)
}
