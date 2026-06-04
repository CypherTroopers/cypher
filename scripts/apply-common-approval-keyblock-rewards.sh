#!/usr/bin/env bash
set -euo pipefail

KEYBLOCK_GO="reconfig/keyblock.go"
TXBLOCK_GO="reconfig/txblock.go"
CONSENSUS_GO="consensus/colossusX/consensus.go"
COMMON_APPROVAL_GO="reconfig/common_approval.go"
BLOCK_VALIDATOR_GO="core/block_validator.go"

if [[ ! -f "$KEYBLOCK_GO" || ! -f "$TXBLOCK_GO" || ! -f "$CONSENSUS_GO" || ! -f "$COMMON_APPROVAL_GO" || ! -f "$BLOCK_VALIDATOR_GO" ]]; then
  echo "Run this script from repository root" >&2
  exit 1
fi

python3 - <<'PY'
from pathlib import Path

keyblock = Path("reconfig/keyblock.go")
text = keyblock.read_text()

# Verify reward summary and ActiveCommonCommittee structure on received self-proposed keyblocks.
old = '''	if err := verifyKeyBlockMinInterval(keyblock, curKeyblock); err != nil {
			return err
		}
		if err := keyS.verifyCommonApprovalRewardSummary(keyblock, curKeyblock.T_Number()+1, keyblock.T_Number()); err != nil {
			return err
		}
		return nil
	}'''
new = '''	if err := verifyKeyBlockMinInterval(keyblock, curKeyblock); err != nil {
			return err
		}
		if err := keyS.verifyCommonApprovalRewardSummary(keyblock, curKeyblock.T_Number()+1, keyblock.T_Number()); err != nil {
			return err
		}
		if err := keyS.verifyActiveCommonCommitteeSummary(keyblock); err != nil {
			return err
		}
		return nil
	}'''
if old in text and new not in text:
    text = text.replace(old, new, 1)
else:
    old = '''	if err := verifyKeyBlockMinInterval(keyblock, curKeyblock); err != nil {
			return err
		}
		return nil
	}'''
    new = '''	if err := verifyKeyBlockMinInterval(keyblock, curKeyblock); err != nil {
			return err
		}
		if err := keyS.verifyCommonApprovalRewardSummary(keyblock, curKeyblock.T_Number()+1, keyblock.T_Number()); err != nil {
			return err
		}
		if err := keyS.verifyActiveCommonCommitteeSummary(keyblock); err != nil {
			return err
		}
		return nil
	}'''
    if old in text and new not in text:
        text = text.replace(old, new, 1)

old = '''	if !keyblock.TypeCheck(kbc.CurrentBlock().T_Number()) {
		return fmt.Errorf("verifyKeyBlock, check failed, current keynumber:%d,keyblock T_Number:%d", kbc.CurrentBlockN(), keyblock.T_Number())
	}
	if err := keyS.verifyCommonApprovalRewardSummary(keyblock, curKeyblock.T_Number()+1, keyblock.T_Number()); err != nil {
		return err
	}

	keyType := keyblock.BlockType()'''
new = '''	if !keyblock.TypeCheck(kbc.CurrentBlock().T_Number()) {
		return fmt.Errorf("verifyKeyBlock, check failed, current keynumber:%d,keyblock T_Number:%d", kbc.CurrentBlockN(), keyblock.T_Number())
	}
	if err := keyS.verifyCommonApprovalRewardSummary(keyblock, curKeyblock.T_Number()+1, keyblock.T_Number()); err != nil {
		return err
	}
	if err := keyS.verifyActiveCommonCommitteeSummary(keyblock); err != nil {
		return err
	}

	keyType := keyblock.BlockType()'''
if old in text and new not in text:
    text = text.replace(old, new, 1)
else:
    old = '''	if !keyblock.TypeCheck(kbc.CurrentBlock().T_Number()) {
		return fmt.Errorf("verifyKeyBlock, check failed, current keynumber:%d,keyblock T_Number:%d", kbc.CurrentBlockN(), keyblock.T_Number())
	}

	keyType := keyblock.BlockType()'''
    new = '''	if !keyblock.TypeCheck(kbc.CurrentBlock().T_Number()) {
		return fmt.Errorf("verifyKeyBlock, check failed, current keynumber:%d,keyblock T_Number:%d", kbc.CurrentBlockN(), keyblock.T_Number())
	}
	if err := keyS.verifyCommonApprovalRewardSummary(keyblock, curKeyblock.T_Number()+1, keyblock.T_Number()); err != nil {
		return err
	}
	if err := keyS.verifyActiveCommonCommitteeSummary(keyblock); err != nil {
		return err
	}

	keyType := keyblock.BlockType()'''
    if old in text and new not in text:
        text = text.replace(old, new, 1)

# Attach reward summary and ActiveCommonCommittee when proposing a KeyBlock.
old = '''	keyblock := types.NewKeyBlock(header)
	keyblock = keyblock.WithBody(mb.In().Public, mb.In().CoinBase, outerPublic, outerCoinBase, mb.Leader().Public, mb.Leader().CoinBase)
	if rewards, err := keyS.buildCommonApprovalRewardSummary(curKeyBlock.T_Number()+1, header.T_Number); err != nil {
		return nil, nil, nil, err
	} else {
		keyblock.SetCommonApprovalRewards(rewards)
		log.Info("common approval reward summary attached", "keyBlock", header.Number.Uint64(), "fromTx", curKeyBlock.T_Number()+1, "toTx", header.T_Number, "rewards", rewards)
	}
	log.Info("tryProposalChangeCommittee", "committeeHash", header.CommitteeHash, "leader", keyblock.LeaderPubKey(), "outerCoinBase", outerCoinBase)'''
new = '''	keyblock := types.NewKeyBlock(header)
	keyblock = keyblock.WithBody(mb.In().Public, mb.In().CoinBase, outerPublic, outerCoinBase, mb.Leader().Public, mb.Leader().CoinBase)
	if rewards, err := keyS.buildCommonApprovalRewardSummary(curKeyBlock.T_Number()+1, header.T_Number); err != nil {
		return nil, nil, nil, err
	} else {
		keyblock.SetCommonApprovalRewards(rewards)
		log.Info("common approval reward summary attached", "keyBlock", header.Number.Uint64(), "fromTx", curKeyBlock.T_Number()+1, "toTx", header.T_Number, "rewards", rewards)
	}
	if activeCommonCommittee, err := keyS.buildActiveCommonCommitteeSummary(); err != nil {
		return nil, nil, nil, err
	} else {
		keyblock.SetActiveCommonCommittee(activeCommonCommittee)
		log.Info("active common committee summary attached", "keyBlock", header.Number.Uint64(), "members", activeCommonCommittee)
	}
	log.Info("tryProposalChangeCommittee", "committeeHash", header.CommitteeHash, "leader", keyblock.LeaderPubKey(), "outerCoinBase", outerCoinBase)'''
if old in text and new not in text:
    text = text.replace(old, new, 1)
else:
    old = '''	keyblock := types.NewKeyBlock(header)
	keyblock = keyblock.WithBody(mb.In().Public, mb.In().CoinBase, outerPublic, outerCoinBase, mb.Leader().Public, mb.Leader().CoinBase)
	log.Info("tryProposalChangeCommittee", "committeeHash", header.CommitteeHash, "leader", keyblock.LeaderPubKey(), "outerCoinBase", outerCoinBase)'''
    new = '''	keyblock := types.NewKeyBlock(header)
	keyblock = keyblock.WithBody(mb.In().Public, mb.In().CoinBase, outerPublic, outerCoinBase, mb.Leader().Public, mb.Leader().CoinBase)
	if rewards, err := keyS.buildCommonApprovalRewardSummary(curKeyBlock.T_Number()+1, header.T_Number); err != nil {
		return nil, nil, nil, err
	} else {
		keyblock.SetCommonApprovalRewards(rewards)
		log.Info("common approval reward summary attached", "keyBlock", header.Number.Uint64(), "fromTx", curKeyBlock.T_Number()+1, "toTx", header.T_Number, "rewards", rewards)
	}
	if activeCommonCommittee, err := keyS.buildActiveCommonCommitteeSummary(); err != nil {
		return nil, nil, nil, err
	} else {
		keyblock.SetActiveCommonCommittee(activeCommonCommittee)
		log.Info("active common committee summary attached", "keyBlock", header.Number.Uint64(), "members", activeCommonCommittee)
	}
	log.Info("tryProposalChangeCommittee", "committeeHash", header.CommitteeHash, "leader", keyblock.LeaderPubKey(), "outerCoinBase", outerCoinBase)'''
    if old in text and new not in text:
        text = text.replace(old, new, 1)

keyblock.write_text(text)

# The Key_Block tx-block proposal path builds its root manually, without going
# through consensus.FinalizeAndAssemble. It must therefore apply exactly the same
# CommonApproval signer reward as validators apply during verification.
txblock = Path("reconfig/txblock.go")
text = txblock.read_text()
old = '''	colossusX.AccumulateRewards(txS.bc.Config(), work.publicState, header, nil)
	colossusX.ApplyKeyblockPowReward(work.publicState, keyblock)
	header.Root = work.publicState.IntermediateRoot(false)'''
new = '''	colossusX.AccumulateRewards(txS.bc.Config(), work.publicState, header, nil)
	colossusX.ApplyKeyblockPowReward(work.publicState, keyblock)
	colossusX.ApplyCommonApprovalSignerRewards(work.publicState, keyblock)
	header.Root = work.publicState.IntermediateRoot(false)'''
if old in text and new not in text:
    text = text.replace(old, new, 1)
txblock.write_text(text)

consensus = Path("consensus/colossusX/consensus.go")
text = consensus.read_text()

# Keep ApplyKeyblockPowRewardByKeyInfo limited to legacy/common PoW reward only.
# It is used from existing paths and should not hide CommonApproval reward side effects.
unsafe_func = '''	keyblock := types.DecodeToKeyBlock(keyInfo)
	ApplyKeyblockPowReward(state, keyblock)
	ApplyCommonApprovalSignerRewards(state, keyblock)
}'''
safe_func = '''	keyblock := types.DecodeToKeyBlock(keyInfo)
	ApplyKeyblockPowReward(state, keyblock)
}'''
text = text.replace(unsafe_func, safe_func)

# Validators/importers verify Key_Block tx-blocks through consensus finalization.
# Match the proposal path above by applying CommonApproval signer rewards only in
# the explicit Key_Block branches.
old = '''	if header.BlockType == types.Key_Block {
		ApplyKeyblockPowRewardByKeyInfo(state, header.KeyInfo)
	}'''
new = '''	if header.BlockType == types.Key_Block {
		ApplyKeyblockPowRewardByKeyInfo(state, header.KeyInfo)
		keyblock := types.DecodeToKeyBlock(header.KeyInfo)
		ApplyCommonApprovalSignerRewards(state, keyblock)
	}'''
if old in text and new not in text:
    text = text.replace(old, new, 2)

consensus.write_text(text)

common_approval = Path("reconfig/common_approval.go")
text = common_approval.read_text()

# requestCommonApproval: all leader selection and committee hash must come from the KeyBlock attached to block.KeyHash().
text = text.replace('''func (s *Service) requestCommonApproval(block *types.Block) error {
	if err := core.ValidateCommonApprovalCommittee(s.chainConfig); err != nil {
		return err
	}
	nodes := core.OrderedCommonCommittee(s.chainConfig)
	if len(nodes) == 0 {
		return fmt.Errorf("common approval failed: active common committee is empty")
	}
	committeeHash := core.CommonApprovalCommitteeHash(s.chainConfig)''', '''func (s *Service) requestCommonApproval(block *types.Block) error {
	if err := s.validateCommonApprovalCommitteeForBlock(block); err != nil {
		return err
	}
	nodes := s.orderedCommonCommitteeForBlock(block)
	if len(nodes) == 0 {
		return fmt.Errorf("common approval failed: active common committee is empty")
	}
	committeeHash := s.commonApprovalCommitteeHashForBlock(block)''')

text = text.replace('''			block.SetCommonApproval(resp.Signature, resp.Mask, resp.ViewID, resp.LeaderID, resp.CommitteeHash)
			if err := core.VerifyCommonApproval(s.chainConfig, block); err != nil {
				return err
			}''', '''			block.SetCommonApproval(resp.Signature, resp.Mask, resp.ViewID, resp.LeaderID, resp.CommitteeHash)
			if err := s.verifyCommonApprovalForBlock(block); err != nil {
				return err
			}''')

text = text.replace('''func (s *Service) routeCommonApprovalRequest(req *commonApprovalMsg) {
	if s.isCommonApprovalLeader(req.LeaderID) {
		s.handleCommonApprovalRequest(req)
		return
	}
	s.handleCommonApprovalVoteRequest(req)
}''', '''func (s *Service) routeCommonApprovalRequest(req *commonApprovalMsg) {
	if req == nil {
		return
	}
	block := types.DecodeToBlock(req.BlockData)
	if block != nil && s.isCommonApprovalLeaderForBlock(block, req.LeaderID) {
		s.handleCommonApprovalRequest(req)
		return
	}
	s.handleCommonApprovalVoteRequest(req)
}''')

text = text.replace('''	if !s.isCommonApprovalLeader(req.LeaderID) {
		s.sendCommonApprovalResponse(req, nil, nil, "receiver is not active common leader")
		return
	}
	if req.CommitteeHash != core.CommonApprovalCommitteeHash(s.chainConfig) {
		s.sendCommonApprovalResponse(req, nil, nil, "common committee hash mismatch")
		return
	}''', '''	if !s.isCommonApprovalLeaderForBlock(block, req.LeaderID) {
		s.sendCommonApprovalResponse(req, nil, nil, "receiver is not active common leader")
		return
	}
	if req.CommitteeHash != s.commonApprovalCommitteeHashForBlock(block) {
		s.sendCommonApprovalResponse(req, nil, nil, "common committee hash mismatch")
		return
	}''')

text = text.replace('''func (s *Service) broadcastCommonApprovalVoteRequest(req *commonApprovalMsg) {
	nodes := core.OrderedCommonCommittee(s.chainConfig)
	for _, node := range nodes {''', '''func (s *Service) broadcastCommonApprovalVoteRequest(req *commonApprovalMsg) {
	if req == nil {
		return
	}
	block := types.DecodeToBlock(req.BlockData)
	if block == nil {
		return
	}
	nodes := s.orderedCommonCommitteeForBlock(block)
	for _, node := range nodes {''')

text = text.replace('''	if committeeHash != core.CommonApprovalCommitteeHash(s.chainConfig) {
		return nil, -1, fmt.Errorf("common committee hash mismatch")
	}
	if viewID != s.commonApprovalViewID(block, committeeHash) {
		return nil, -1, fmt.Errorf("common approval view mismatch")
	}
	nodes := core.OrderedCommonCommittee(s.chainConfig)''', '''	if committeeHash != s.commonApprovalCommitteeHashForBlock(block) {
		return nil, -1, fmt.Errorf("common committee hash mismatch")
	}
	if viewID != s.commonApprovalViewID(block, committeeHash) {
		return nil, -1, fmt.Errorf("common approval view mismatch")
	}
	nodes := s.orderedCommonCommitteeForBlock(block)''')

text = text.replace('''	nodes := core.OrderedCommonCommittee(s.chainConfig)
	index := int(vote.SignerIndex)''', '''	nodes := s.orderedCommonCommitteeForBlock(session.block)
	index := int(vote.SignerIndex)''')

text = text.replace('''func (s *Service) commonApprovalSessionThreshold(session *commonApprovalLeaderSession) int {
	nodes := core.OrderedCommonCommittee(s.chainConfig)''', '''func (s *Service) commonApprovalSessionThreshold(session *commonApprovalLeaderSession) int {
	nodes := s.orderedCommonCommitteeForBlock(session.block)''')

text = text.replace('''	nodes := core.OrderedCommonCommittee(s.chainConfig)
	threshold := s.commonApprovalSessionThreshold(session)''', '''	nodes := s.orderedCommonCommitteeForBlock(session.block)
	threshold := s.commonApprovalSessionThreshold(session)''')

text = text.replace('''		CommitteeHash:    core.CommonApprovalCommitteeHash(s.chainConfig),''', '''		CommitteeHash:    s.commonApprovalCommitteeHashForBlock(session.block),''')

text = text.replace('''func (s *Service) commonApprovalLeaderAddress(leaderID string) string {
	if leaderID == "" {
		return ""
	}
	nodes := core.OrderedCommonCommittee(s.chainConfig)
	for _, node := range nodes {
		if node == nil || node.Address == "" || node.Public == "" {
			continue
		}
		if bftview.GetNodeID(node.Address, node.Public) == leaderID {
			return node.Address
		}
	}
	return ""
}

func (s *Service) isCommonApprovalLeader(leaderID string) bool {
	if leaderID == "" {
		return false
	}
	selfPub := bftview.GetServerInfo(bftview.PublicKey)
	if selfPub == "" {
		return false
	}
	nodes := core.OrderedCommonCommittee(s.chainConfig)
	for _, node := range nodes {
		if node == nil || node.Public != selfPub {
			continue
		}
		if bftview.GetNodeID(node.Address, node.Public) == leaderID {
			return true
		}
	}
	return false
}''', '''func (s *Service) commonApprovalLeaderAddressForBlock(block *types.Block, leaderID string) string {
	if leaderID == "" {
		return ""
	}
	nodes := s.orderedCommonCommitteeForBlock(block)
	for _, node := range nodes {
		if node == nil || node.Address == "" || node.Public == "" {
			continue
		}
		if bftview.GetNodeID(node.Address, node.Public) == leaderID {
			return node.Address
		}
	}
	return ""
}

func (s *Service) commonApprovalLeaderAddress(leaderID string) string {
	return s.commonApprovalLeaderAddressForBlock(nil, leaderID)
}

func (s *Service) isCommonApprovalLeaderForBlock(block *types.Block, leaderID string) bool {
	if leaderID == "" {
		return false
	}
	selfPub := bftview.GetServerInfo(bftview.PublicKey)
	if selfPub == "" {
		return false
	}
	nodes := s.orderedCommonCommitteeForBlock(block)
	for _, node := range nodes {
		if node == nil || node.Public != selfPub {
			continue
		}
		if bftview.GetNodeID(node.Address, node.Public) == leaderID {
			return true
		}
	}
	return false
}

func (s *Service) isCommonApprovalLeader(leaderID string) bool {
	return s.isCommonApprovalLeaderForBlock(nil, leaderID)
}''')

text = text.replace('''	leaderAddr := s.commonApprovalLeaderAddress(req.LeaderID)''', '''	leaderAddr := s.commonApprovalLeaderAddressForBlock(block, req.LeaderID)''')

common_approval.write_text(text)

block_validator = Path("core/block_validator.go")
text = block_validator.read_text()
text = text.replace('''	if err := VerifyCommonApproval(v.config, block); err != nil {
		return err
	}''', '''	keyblock := v.bc.keyBlockChain.GetBlockByHash(block.KeyHash())
	if err := VerifyCommonApprovalForKeyBlock(v.config, block, keyblock); err != nil {
		return err
	}''')
block_validator.write_text(text)
PY

gofmt -w "$KEYBLOCK_GO" "$TXBLOCK_GO" "$CONSENSUS_GO" "$COMMON_APPROVAL_GO" "$BLOCK_VALIDATOR_GO" reconfig/common_approval_committee.go reconfig/common_approval_rewards.go reconfig/active_common_committee.go consensus/colossusX/rewards.go core/types/keyblock.go core/common_approval.go

echo "CommonApproval KeyBlock reward summary, payout, active committee summary, and runtime committee switching applied."
