package reconfig

import (
	"fmt"

	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/log"
)

func (keyS *keyService) buildCommonApprovalRewardSummary(fromN, toN uint64) ([]types.CommonApprovalReward, error) {
	if keyS == nil || keyS.config == nil || !keyS.config.CommonApprovalEnabled || keyS.bc == nil {
		return nil, nil
	}
	if fromN > toN {
		return nil, nil
	}

	nodes := core.OrderedCommonCommittee(keyS.config)
	if len(nodes) == 0 {
		return nil, nil
	}
	committeeHash := core.CommonApprovalCommitteeHash(keyS.config)
	counts := make(map[string]uint64)

	for n := fromN; n <= toN; n++ {
		block := keyS.bc.GetBlockByNumber(n)
		if block == nil {
			return nil, fmt.Errorf("common approval reward summary failed: tx block %d not found", n)
		}
		if !core.CommonApprovalRequired(keyS.config, block) {
			continue
		}
		si := block.SignInfo()
		if si == nil || len(si.CommonApprovalSignature) == 0 || len(si.CommonApprovalExceptions) == 0 {
			continue
		}
		if si.CommonApprovalCommitteeHash != committeeHash {
			log.Warn("skip common approval reward summary: committee hash mismatch",
				"block", block.NumberU64(),
				"have", si.CommonApprovalCommitteeHash.Hex(),
				"want", committeeHash.Hex())
			continue
		}
		mask := si.CommonApprovalExceptions
		for i, node := range nodes {
			if node == nil || node.CoinBase == "" {
				continue
			}
			if len(mask) <= i/8 {
				continue
			}
			if (mask[i/8] & (1 << uint(i%8))) == 0 {
				continue
			}
			counts[node.CoinBase]++
		}
	}

	rewards := make([]types.CommonApprovalReward, 0, len(counts))
	for _, node := range nodes {
		if node == nil || node.CoinBase == "" {
			continue
		}
		count := counts[node.CoinBase]
		if count == 0 {
			continue
		}
		rewards = append(rewards, types.CommonApprovalReward{
			CoinBase:       node.CoinBase,
			SignedTxBlocks: count,
		})
	}
	return rewards, nil
}

func (keyS *keyService) verifyCommonApprovalRewardSummary(keyblock *types.KeyBlock, fromN, toN uint64) error {
	if keyS == nil || keyS.config == nil || !keyS.config.CommonApprovalEnabled || keyblock == nil {
		return nil
	}
	expected, err := keyS.buildCommonApprovalRewardSummary(fromN, toN)
	if err != nil {
		return err
	}
	actual := keyblock.CommonApprovalRewards()
	if !sameCommonApprovalRewards(actual, expected) {
		return fmt.Errorf("keyblock common approval reward summary mismatch: have=%v want=%v", actual, expected)
	}
	return nil
}

func sameCommonApprovalRewards(a, b []types.CommonApprovalReward) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].CoinBase != b[i].CoinBase || a[i].SignedTxBlocks != b[i].SignedTxBlocks {
			return false
		}
	}
	return true
}
