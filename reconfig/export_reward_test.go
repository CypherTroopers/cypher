package reconfig

import (
	"crypto/ecdsa"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/rpc"
)

// Test-only bridge avoids a production reconfig -> eth import cycle. The
// external test package installs actual eth TxQUIC endpoints in every child.
var FHSRewardIngressFactory func(*ReconfigBackend, string, string) (func() error, func(), error)
var FHSRewardReceiptEndpoint func(*ReconfigBackend) string

func FHSRewardSetTransactionResolver(backend *ReconfigBackend, resolve func(common.Hash) (*types.Transaction, error)) {
	backend.resolveTxQUICTransaction = resolve
}

type FHSRewardNetworkFixture struct {
	Genesis                *core.Genesis
	KeyBlock               *types.KeyBlock
	Committee              []*common.Cnode
	SenderKey, OperatorKey *ecdsa.PrivateKey
	RewardRecipient        common.Address
	Transactions           types.Transactions
}

type fhsNetworkReceipt struct {
	CommonTxApprover        common.Address  `json:"commonTxApprover"`
	CommonTxRewardRecipient common.Address  `json:"commonTxRewardRecipient"`
	CommonTxApproverReward  *hexutil.Big    `json:"commonTxApproverReward"`
	GasUsed                 hexutil.Uint64  `json:"gasUsed"`
	EffectiveGasPrice       *hexutil.Big    `json:"effectiveGasPrice"`
	Status                  hexutil.Uint64  `json:"status"`
	ContractAddress         *common.Address `json:"contractAddress"`
	BlockHash               common.Hash     `json:"blockHash"`
}

func RunFHSRewardNetworkTest(t *testing.T, startCommon func(*testing.T, *FHSRewardNetworkFixture) func(*types.Transaction) error) {
	t.Helper()
	children, _, fixture := newFHSRecoveryProcessFixture(t, true, true)
	for _, child := range children {
		child.call(t, fhsProcessCommand{Op: "gate", Gate: fhsProcessGate{Healed: true}})
		child.call(t, fhsProcessCommand{Op: "start"})
	}
	submit := startCommon(t, fixture)
	for index, tx := range fixture.Transactions {
		if err := submit(tx); err != nil {
			t.Fatalf("public HTTP raw transaction %d: %v", index, err)
		}
		waitFHSProcesses(t, children, 60*time.Second, func(statuses []fhsProcessReport) bool {
			for _, s := range statuses {
				if s.Certified < uint64(index+1) {
					return false
				}
			}
			return true
		})
	}
	statuses := waitFHSProcesses(t, children, 90*time.Second, func(statuses []fhsProcessReport) bool {
		for _, s := range statuses {
			if s.Height < 3 || s.RewardAmount == nil || s.FinalizedFixtureTxs < 4 {
				return false
			}
		}
		return true
	})
	requireFHSCanonicalAgreement(t, children, statuses, 3)
	var root common.Hash
	expectedReceipts := make(map[common.Hash]fhsNetworkReceipt)
	for index, s := range statuses {
		if s.Submitted != 0 {
			t.Fatal("fixture directly injected a transaction, bypassing network ingress")
		}
		if s.CanonicalFirstTx != fixture.Transactions[0].Hash() || s.RewardApprover != crypto.PubkeyToAddress(fixture.OperatorKey.PublicKey) || s.RewardRecipient != fixture.RewardRecipient {
			t.Fatalf("validator %d lost externally submitted TX/A/B", index)
		}
		if s.RewardApproverBalance == nil || s.RewardApproverBalance.Cmp(big.NewInt(77)) != 0 || s.RewardRecipientBalance == nil || s.RewardRecipientBalance.Cmp(new(big.Int).Add(big.NewInt(123), s.RewardAmount)) != 0 {
			t.Fatalf("validator %d did not credit reward directly to B", index)
		}
		if s.RewardReceiptStatus != types.ReceiptStatusSuccessful || s.RewardReceiptGas != 21000 {
			t.Fatalf("validator %d receipt mismatch", index)
		}
		client, err := rpc.DialHTTP(s.ReceiptEndpoint)
		if err != nil {
			t.Fatal(err)
		}
		for nonce := 0; nonce < 4; nonce++ {
			var receipt fhsNetworkReceipt
			hash := fixture.Transactions[nonce].Hash()
			if err := client.Call(&receipt, "eth_getTransactionReceipt", hash); err != nil {
				client.Close()
				t.Fatalf("validator %d TX%d public receipt: %v", index, nonce, err)
			}
			if receipt.CommonTxApprover != s.RewardApprover || receipt.CommonTxRewardRecipient != s.RewardRecipient || receipt.CommonTxApproverReward == nil || receipt.EffectiveGasPrice == nil {
				client.Close()
				t.Fatalf("validator %d TX%d HTTP receipt lost A/B/reward", index, nonce)
			}
			fee := new(big.Int).Mul(new(big.Int).SetUint64(uint64(receipt.GasUsed)), (*big.Int)(receipt.EffectiveGasPrice))
			if (*big.Int)(receipt.CommonTxApproverReward).Cmp(new(big.Int).Div(fee, big.NewInt(5))) != 0 {
				client.Close()
				t.Fatalf("validator %d TX%d HTTP receipt fee split mismatch", index, nonce)
			}
			wantStatus := uint64(types.ReceiptStatusSuccessful)
			if nonce == 3 {
				wantStatus = types.ReceiptStatusFailed
			}
			if uint64(receipt.Status) != wantStatus {
				client.Close()
				t.Fatalf("validator %d TX%d receipt status=%d", index, nonce, receipt.Status)
			}
			if nonce == 1 {
				want := crypto.CreateAddress(crypto.PubkeyToAddress(fixture.SenderKey.PublicKey), 1)
				if receipt.ContractAddress == nil || *receipt.ContractAddress != want {
					client.Close()
					t.Fatal("deployment receipt lost contract address")
				}
			}
			if want, exists := expectedReceipts[hash]; exists {
				if !reflect.DeepEqual(receipt, want) {
					client.Close()
					t.Fatalf("validator %d TX%d HTTP receipt differs", index, nonce)
				}
			} else {
				expectedReceipts[hash] = receipt
			}
		}
		client.Close()
		if root == (common.Hash{}) {
			root = s.RewardStateRoot
		}
		if s.RewardStateRoot != root {
			t.Fatalf("validator %d state root mismatch", index)
		}
	}
	t.Log("HTTP raw transfer/deployment/successful and reverted contract calls -> Common admission/WAL/outbox -> authenticated TxQUIC -> seven FHS validators -> finality: matching HTTP receipts/state roots and direct keyless-B payout")
}
