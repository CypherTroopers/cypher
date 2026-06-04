package reconfig

import (
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/log"
)

func (s *Service) commonApprovalKeyBlock(block *types.Block) *types.KeyBlock {
	if s == nil || s.kbc == nil || block == nil {
		return nil
	}
	keyblock := s.kbc.GetBlockByHash(block.KeyHash())
	if keyblock == nil {
		log.Warn("common approval keyblock not found; using config fallback", "keyHash", block.KeyHash())
	}
	return keyblock
}

func (s *Service) orderedCommonCommitteeForBlock(block *types.Block) []*common.Cnode {
	return core.OrderedCommonCommitteeForKeyBlock(s.chainConfig, s.commonApprovalKeyBlock(block))
}

func (s *Service) commonApprovalCommitteeHashForBlock(block *types.Block) common.Hash {
	return core.CommonApprovalCommitteeHashForKeyBlock(s.chainConfig, s.commonApprovalKeyBlock(block))
}

func (s *Service) validateCommonApprovalCommitteeForBlock(block *types.Block) error {
	return core.ValidateCommonApprovalCommitteeForKeyBlock(s.chainConfig, s.commonApprovalKeyBlock(block))
}

func (s *Service) verifyCommonApprovalForBlock(block *types.Block) error {
	return core.VerifyCommonApprovalForKeyBlock(s.chainConfig, block, s.commonApprovalKeyBlock(block))
}
