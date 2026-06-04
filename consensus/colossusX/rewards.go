package colossusX

import (
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
)

var (
	// CommonApprovalSignerReward is paid only to commonCommittee members whose
	// CommonApproval mask bit was set in finalized tx blocks and was summarized
	// into the following KeyBlock. No signature means no reward.
	CommonApprovalSignerReward = new(big.Int).Mul(big.NewInt(1000), big.NewInt(params.Ether))
)

// ApplyKeyblockPowRewardByKeyInfo credits KeyBlock-related rewards from the
// KeyBlock embedded in the tx block's KeyInfo.
//
// This is the single KeyBlock reward path for:
//   - Common PoW / outAddress reward
//   - CommonApproval signer rewards summarized into the KeyBlock
func ApplyKeyblockPowRewardByKeyInfo(state vm.StateDB, keyInfo []byte) {
	if state == nil || len(keyInfo) == 0 {
		return
	}
	keyblock := types.DecodeToKeyBlock(keyInfo)
	ApplyKeyblockPowReward(state, keyblock)
	ApplyCommonApprovalSignerRewards(state, keyblock)
}

// ApplyKeyblockPowReward credits CommonNodePowReward to keyblock outAddress.
func ApplyKeyblockPowReward(state vm.StateDB, keyblock *types.KeyBlock) {
	if state == nil || keyblock == nil {
		return
	}
	submitter := stringsTrimRewardPrefix(keyblock.OutAddress(0))
	if submitter == "" {
		return
	}
	state.AddBalance(common.HexToAddress(submitter), new(big.Int).Set(CommonNodePowReward))
}

// ApplyCommonApprovalSignerRewards credits CommonApprovalSignerReward only to
// signers listed in the KeyBlock's CommonApprovalRewards summary.
//
// The summary is generated before the KeyBlock proposal by scanning finalized tx
// blocks from the previous KeyBlock period. Finalization must only read this
// summary; it must not traverse tx-chain parents from a KeyBlock header.
func ApplyCommonApprovalSignerRewards(state vm.StateDB, keyblock *types.KeyBlock) {
	if state == nil || keyblock == nil {
		return
	}
	for _, reward := range keyblock.CommonApprovalRewards() {
		if reward.CoinBase == "" || reward.SignedTxBlocks == 0 {
			continue
		}
		amount := new(big.Int).Mul(new(big.Int).SetUint64(reward.SignedTxBlocks), CommonApprovalSignerReward)
		addr := common.HexToAddress(reward.CoinBase)
		state.AddBalance(addr, amount)
		log.Info("common approval signer reward settled",
			"keyBlock", keyblock.NumberU64(),
			"coinbase", addr,
			"signedTxBlocks", reward.SignedTxBlocks,
			"amount", amount)
	}
}

func stringsTrimRewardPrefix(addr string) string {
	if addr == "" {
		return ""
	}
	if addr[0] == '*' {
		return addr[1:]
	}
	return addr
}
