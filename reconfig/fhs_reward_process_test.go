package reconfig

import (
	"math/big"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

// This isolates the actual seven-validator proposal, authenticated QUIC,
// verification, import and finality path from local RPC policy tests.
func TestFHSProcessRecoveryRewardFinality(t *testing.T) {
	children, _ := newFHSRecoveryProcesses(t, true)
	for _, child := range children {
		child.call(t, fhsProcessCommand{Op: "gate", Gate: fhsProcessGate{Healed: true}})
		child.call(t, fhsProcessCommand{Op: "start"})
		child.call(t, fhsProcessCommand{Op: "workload", Workload: true})
	}
	statuses := waitFHSProcesses(t, children, 90*time.Second, func(statuses []fhsProcessReport) bool {
		for _, s := range statuses {
			if s.Height < 3 || s.RewardAmount == nil {
				return false
			}
		}
		return true
	})
	requireFHSCanonicalAgreement(t, children, statuses, 3)
	var root common.Hash
	for i, s := range statuses {
		if s.RewardApprover == (common.Address{}) || s.RewardRecipient != common.HexToAddress("0xb123") || s.RewardApprover == s.RewardRecipient {
			t.Fatalf("validator %d lost A/B identity", i)
		}
		if s.RewardReceiptStatus != types.ReceiptStatusSuccessful || s.RewardReceiptGas != params.TxGas {
			t.Fatalf("validator %d receipt mismatch", i)
		}
		actualFee := new(big.Int).Mul(new(big.Int).SetUint64(s.RewardReceiptGas), big.NewInt(params.FixedBaseFeePerGas*2))
		wantReward := new(big.Int).Div(new(big.Int).Set(actualFee), big.NewInt(5))
		if s.RewardAmount.Cmp(wantReward) != 0 || s.RewardBurn.Cmp(new(big.Int).Sub(actualFee, wantReward)) != 0 {
			t.Fatalf("validator %d fee split mismatch", i)
		}
		if s.RewardApproverBalance == nil || s.RewardApproverBalance.Cmp(big.NewInt(77)) != 0 {
			t.Fatalf("validator %d paid Common TX reward to A", i)
		}
		if s.RewardRecipientBalance == nil || s.RewardRecipientBalance.Cmp(new(big.Int).Add(big.NewInt(123), wantReward)) != 0 {
			t.Fatalf("validator %d did not pay directly to keyless B", i)
		}
		if root == (common.Hash{}) {
			root = s.RewardStateRoot
		}
		if root == (common.Hash{}) || s.RewardStateRoot != root {
			t.Fatalf("validator %d state root mismatch", i)
		}
	}
	t.Log("Seven independent validators finalized matching mandatory-recipient receipts/state roots; B (no key) received exactly floor(actualFee/5), A retained its 77-unit initial balance")
}
