package reconfig

import (
	"fmt"

	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
)

func (keyS *keyService) buildCommonApprovalRewardSummary(fromN, toN uint64) ([]types.CommonApprovalReward, error) {
	if keyS == nil || keyS.config == nil || !keyS.config.CommonApprovalEnabled || keyS.bc == nil {
		return nil, nil
	}
	if fromN > toN {
		return nil, nil
	}

	counts := make(map[string]uint64)
	orderedCoinBases := make([]string, 0)
	seenCoinBases := make(map[string]struct{})

	for n := fromN; n <= toN; n++ {
		block := keyS.bc.GetBlockByNumber(n)
		if block == nil {
			return nil, fmt.Errorf("common approval reward summary failed: tx block %d not found", n)
		}
		if !core.CommonApprovalRequired(keyS.config, block) {
			continue
		}

		var keyblock *types.KeyBlock
		if keyS.kbc != nil {
			keyblock = keyS.kbc.GetBlockByHash(block.KeyHash())
		}
		rewards := commonApprovalRewardsForBlock(keyS.config, block, keyblock)
		if rewards == nil {
			nodes := core.OrderedCommonCommitteeForKeyBlock(keyS.config, keyblock)
			committeeHash := core.CommonApprovalCommitteeHashFromNodes(nodes)
			si := block.SignInfo()
			if si != nil && len(si.CommonApprovalSignature) > 0 && len(si.CommonApprovalExceptions) > 0 && si.CommonApprovalCommitteeHash != committeeHash {
				log.Warn("skip common approval reward summary: committee hash mismatch",
					"block", block.NumberU64(),
					"keyHash", block.KeyHash(),
					"have", si.CommonApprovalCommitteeHash.Hex(),
					"want", committeeHash.Hex())
			}
			continue
		}
		for _, reward := range rewards {
			if _, ok := seenCoinBases[reward.CoinBase]; !ok {
				orderedCoinBases = append(orderedCoinBases, reward.CoinBase)
				seenCoinBases[reward.CoinBase] = struct{}{}
			}
			counts[reward.CoinBase] += reward.SignedTxBlocks
		}
	}

	rewards := make([]types.CommonApprovalReward, 0, len(counts))
	for _, coinBase := range orderedCoinBases {
		rewards = append(rewards, types.CommonApprovalReward{
			CoinBase:       coinBase,
			SignedTxBlocks: counts[coinBase],
		})
	}
	return rewards, nil
}

// commonApprovalRewardsForBlock resolves signer mask indexes against the active
// common committee recorded in the KeyBlock referenced by the tx block. The
// config committee is only a compatibility fallback for old KeyBlocks without
// an ActiveCommonCommittee snapshot.
func commonApprovalRewardsForBlock(config *params.ChainConfig, block *types.Block, keyblock *types.KeyBlock) []types.CommonApprovalReward {
	if !core.CommonApprovalRequired(config, block) {
		return nil
	}
	si := block.SignInfo()
	if si == nil || len(si.CommonApprovalSignature) == 0 || len(si.CommonApprovalExceptions) == 0 {
		return nil
	}
	nodes := core.OrderedCommonCommitteeForKeyBlock(config, keyblock)
	if len(nodes) == 0 || si.CommonApprovalCommitteeHash != core.CommonApprovalCommitteeHashFromNodes(nodes) {
		return nil
	}

	rewards := make([]types.CommonApprovalReward, 0, len(nodes))
	for i, node := range nodes {
		if node == nil || node.CoinBase == "" || len(si.CommonApprovalExceptions) <= i/8 {
			continue
		}
		if (si.CommonApprovalExceptions[i/8] & (1 << uint(i%8))) == 0 {
			continue
		}
		rewards = append(rewards, types.CommonApprovalReward{
			CoinBase:       node.CoinBase,
			SignedTxBlocks: 1,
		})
	}
	return rewards
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
