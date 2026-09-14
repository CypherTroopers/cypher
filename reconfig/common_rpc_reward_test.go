package reconfig

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

func TestBuildCommonTxRewardsRequiresRecipient(t *testing.T) {
	operator, recipient := common.Address{1}, common.Address{2}
	tx := types.NewTransaction(0, common.Address{3}, new(big.Int), 21000, big.NewInt(9), nil)
	valid := types.CommonTxAdmissionBatch{
		Version: types.CommonRPCVersionV2, Miner: operator,
		RewardRecipient: recipient, TxHashes: []common.Hash{tx.Hash()},
	}
	for _, test := range []struct {
		name   string
		mutate func(*types.CommonTxAdmissionBatch)
	}{
		{"missing version", func(a *types.CommonTxAdmissionBatch) { a.Version = 0 }},
		{"legacy version", func(a *types.CommonTxAdmissionBatch) { a.Version = 1 }},
		{"unknown version", func(a *types.CommonTxAdmissionBatch) { a.Version = 3 }},
		{"missing recipient", func(a *types.CommonTxAdmissionBatch) { a.RewardRecipient = common.Address{} }},
		{"recipient equals signer", func(a *types.CommonTxAdmissionBatch) { a.RewardRecipient = operator }},
	} {
		t.Run(test.name, func(t *testing.T) {
			admission := valid
			test.mutate(&admission)
			if rewards, err := buildCommonTxRewards(types.Transactions{tx}, types.Receipts{{GasUsed: 37}}, []*types.CommonTxAdmissionBatch{&admission}, []types.CommonTxAdmissionRef{{}}, nil); err == nil || len(rewards) != 0 {
				t.Fatal("proposer constructed rewards from an admission without the mandatory recipient format")
			}
		})
	}
	for _, status := range []uint64{types.ReceiptStatusFailed, types.ReceiptStatusSuccessful} {
		rewards, err := buildCommonTxRewards(types.Transactions{tx}, types.Receipts{{GasUsed: 37, Status: status}}, []*types.CommonTxAdmissionBatch{&valid}, []types.CommonTxAdmissionRef{{}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(rewards) != 1 {
			t.Fatal("missing reward for a canonical admission")
		}
		reward := rewards[0]
		if reward.Version != types.CommonRPCVersionV2 || reward.Approver != operator || reward.RewardRecipient != recipient {
			t.Fatal("proposer lost the distinct signer and recipient")
		}
		if reward.ApproverReward.Cmp(big.NewInt(66)) != 0 || reward.Burn.Cmp(big.NewInt(267)) != 0 {
			t.Fatal("proposer changed the fee split or failed-receipt reward rule")
		}
	}
}
