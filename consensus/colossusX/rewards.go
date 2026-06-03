package colossusX

import (
	"math/big"
	"sort"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
)

const (
	commonApprovalRewardBootstrapIndex    = 0
	commonApprovalRewardMaxCommitteeSize = 7
)

var (
	// CommonApprovalSignerReward is paid only to commonCommittee members whose
	// CommonApproval mask bit is set for a finalized tx block.
	// No signature means no reward.
	CommonApprovalSignerReward = new(big.Int).Mul(big.NewInt(1000), big.NewInt(params.Ether))
)

// ApplyCommonApprovalKeyblockRewards settles CommonApproval signer rewards in
// the KeyBlock block itself. It scans the tx blocks in the just-closed keyHash
// period and pays only the members whose CommonApproval mask bit is set.
//
// Reward rule:
//   - mask bit 1: signer receives CommonApprovalSignerReward for that tx block.
//   - mask bit 0: no signature, no reward.
func ApplyCommonApprovalKeyblockRewards(bc types.ChainReader, state vm.StateDB, header *types.Header) {
	if bc == nil || state == nil || header == nil || header.Number == nil || header.Number.Sign() == 0 {
		return
	}
	config := bc.Config()
	if config == nil || !config.CommonApprovalEnabled || header.BlockType != types.Key_Block {
		return
	}

	parent := bc.GetBlock(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		log.Error("ApplyCommonApprovalKeyblockRewards", "not found parent block", header.ParentHash)
		return
	}

	settledKeyHash := parent.KeyHash()
	nodes := orderedCommonApprovalRewardCommittee(config)
	if len(nodes) == 0 {
		return
	}
	committeeHash := (&bftview.Committee{List: nodes}).RlpHash()
	counts := make(map[common.Address]uint64)

	for block := parent; block != nil && block.KeyHash() == settledKeyHash; {
		collectCommonApprovalRewardCounts(block, nodes, committeeHash, counts)
		if block.NumberU64() == 0 {
			break
		}
		block = bc.GetBlock(block.ParentHash(), block.NumberU64()-1)
	}

	for addr, count := range counts {
		if count == 0 {
			continue
		}
		amount := new(big.Int).Mul(new(big.Int).SetUint64(count), CommonApprovalSignerReward)
		state.AddBalance(addr, amount)
		log.Info("common approval signer reward settled",
			"keyBlock", header.Number.Uint64(),
			"settledKeyHash", settledKeyHash,
			"coinbase", addr,
			"signedTxBlocks", count,
			"amount", amount)
	}
}

func collectCommonApprovalRewardCounts(block *types.Block, nodes []*common.Cnode, committeeHash common.Hash, counts map[common.Address]uint64) {
	if block == nil || counts == nil || block.BlockType() == types.Key_Block {
		return
	}
	signInfo := block.SignInfo()
	if signInfo == nil || len(signInfo.CommonApprovalSignature) == 0 || len(signInfo.CommonApprovalExceptions) == 0 {
		return
	}
	if signInfo.CommonApprovalCommitteeHash != committeeHash {
		log.Warn("skip common approval reward: committee hash mismatch",
			"block", block.NumberU64(),
			"have", signInfo.CommonApprovalCommitteeHash.Hex(),
			"want", committeeHash.Hex())
		return
	}
	for i, node := range nodes {
		if node == nil || node.CoinBase == "" {
			continue
		}
		if len(signInfo.CommonApprovalExceptions) <= i/8 {
			continue
		}
		if (signInfo.CommonApprovalExceptions[i/8] & (1 << uint(i%8))) == 0 {
			continue
		}
		counts[common.HexToAddress(node.CoinBase)]++
	}
}

func orderedCommonApprovalRewardCommittee(config *params.ChainConfig) []*common.Cnode {
	if config == nil || len(config.CommonCommittee) == 0 {
		return nil
	}

	nodes := make([]*common.Cnode, 0, len(config.CommonCommittee))
	included := make(map[int]struct{})

	if node, ok := config.CommonCommittee[commonApprovalRewardBootstrapIndex]; ok {
		n := node
		nodes = append(nodes, &n)
		included[commonApprovalRewardBootstrapIndex] = struct{}{}
	}

	keys := make([]int, 0, len(config.CommonCommittee))
	for k := range config.CommonCommittee {
		if _, ok := included[k]; ok {
			continue
		}
		keys = append(keys, k)
	}
	sort.Ints(keys)

	for _, k := range keys {
		if len(nodes) >= commonApprovalRewardMaxCommitteeSize {
			break
		}
		n := config.CommonCommittee[k]
		nodes = append(nodes, &n)
	}
	return nodes
}
