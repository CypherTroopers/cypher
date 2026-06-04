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
