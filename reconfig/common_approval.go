package reconfig

import (
	"fmt"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

type commonApprovalViewData struct {
	Domain        string
	ChainID       uint64
	BlockHash     common.Hash
	BlockNumber   uint64
	KeyHash       common.Hash
	CommitteeHash common.Hash
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

// attachCommonApproval is the minimum viable common-set implementation. With a
// one-node commonCommittee and threshold=1, the common member can attach a valid
// CommonApproval QC locally. The fields and verifier are intentionally compatible
// with a future full Common HotStuff service that aggregates multiple common-node
// votes before validator HotStuff finality.
func (s *Service) attachCommonApproval(block *types.Block) error {
	if !core.CommonApprovalRequired(s.chainConfig, block) {
		return nil
	}
	if err := core.ValidateCommonApprovalCommittee(s.chainConfig); err != nil {
		return err
	}
	nodes := core.OrderedCommonCommittee(s.chainConfig)

	selfPub := bftview.GetServerInfo(bftview.PublicKey)
	if selfPub == "" {
		return fmt.Errorf("common approval failed: local BLS public key is empty")
	}
	selfIndex := -1
	var selfNode *common.Cnode
	for i, node := range nodes {
		if node != nil && node.Public == selfPub {
			selfIndex = i
			selfNode = node
			break
		}
	}
	if selfIndex < 0 || selfNode == nil {
		return fmt.Errorf("common approval failed: local node is not in active commonCommittee")
	}

	payload := block.CopyNoSignInfo().EncodeToBytes()
	if payload == nil {
		return types.ErrEncodeRLP
	}
	committeeHash := core.CommonApprovalCommitteeHash(s.chainConfig)
	viewID := s.commonApprovalViewID(block, committeeHash)
	leaderID := bftview.GetNodeID(selfNode.Address, selfNode.Public)
	sig := s.protocolMng.SignHashByMessage(hotstuff.MsgVotePrepare, viewID, leaderID, payload)
	mask := make([]byte, (len(nodes)+7)/8)
	mask[selfIndex/8] |= 1 << uint(selfIndex%8)

	block.SetCommonApproval(sig, mask, viewID, leaderID, committeeHash)
	return nil
}
