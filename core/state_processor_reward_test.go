package core

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

func TestCommonRPCRewardIsAppliedOnlyAfterTransactionExecution(t *testing.T) {
	approver := common.HexToAddress("0x1000000000000000000000000000000000000001")
	tx := types.NewTransaction(0, common.HexToAddress("0x2000000000000000000000000000000000000002"), new(big.Int), params.TxGas, big.NewInt(params.FixedTransferGasPricePerGas), nil)
	actualFee := new(big.Int).Mul(new(big.Int).SetUint64(params.TxGas), big.NewInt(params.FixedTransferGasPricePerGas))
	wantReward := new(big.Int).Div(new(big.Int).Set(actualFee), big.NewInt(5))
	reward := &types.CommonTxReward{
		TxHash: tx.Hash(), Approver: approver,
		ApproverReward: new(big.Int).Set(wantReward),
		Burn:           new(big.Int).Sub(actualFee, wantReward),
	}
	statedb := newModernTestState(t)
	if err := validateCommonRPCReward(reward, approver, tx, params.TxGas, big.NewInt(params.FixedBaseFeePerGas)); err != nil {
		t.Fatal(err)
	}
	if got := statedb.GetBalance(approver); got.Sign() != 0 {
		t.Fatalf("validation mutated approver balance before all tx execution: %v", got)
	}
	applyCommonRPCRewards(statedb, []*types.CommonTxReward{reward})
	if got := statedb.GetBalance(approver); got.Cmp(wantReward) != 0 {
		t.Fatalf("settled approver reward = %v, want %v", got, wantReward)
	}
}
