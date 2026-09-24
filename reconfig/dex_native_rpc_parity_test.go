package reconfig_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/settlement"
	"github.com/cypherium/cypher/internal/ethapi"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig"
	"github.com/cypherium/cypher/rpc"
)

// nativeProbeRPCParity uses the ordinary HTTP eth APIs and private IPC debug
// APIs after the Common has imported genuine committee-finalized blocks. It
// neither submits a transaction nor modifies the canonical StateDB. The fixture
// must include one successful ordinary EOA transfer for legacy trace parity.
func nativeProbeRPCParity(t *testing.T, fixture *reconfig.FHSRewardNetworkFixture, commonNode *nativeCommonNode, finalizedFundingTX *types.Transaction) {
	t.Helper()
	chain := commonNode.Service.BlockChain()
	head := chain.CurrentBlock()
	if head.NumberU64() == 0 || finalizedFundingTX == nil || finalizedFundingTX.To() == nil || *finalizedFundingTX.To() != params.DEXSettlementAddress {
		t.Fatal("RPC parity requires a finalized native funding transaction")
	}
	sender, err := types.Sender(types.NewEIP155Signer(fixture.Genesis.Config.ChainID), finalizedFundingTX)
	if err != nil {
		t.Fatal(err)
	}
	ipc, err := rpc.DialIPC(context.Background(), commonNode.Stack.IPCEndpoint())
	if err != nil {
		t.Fatal(err)
	}
	defer ipc.Close()
	ref := rpc.BlockNumberOrHashWithHash(head.Hash(), true)
	fake := common.HexToAddress("0xfacade000000000000000000000000000000dead")
	type accountState struct {
		Balance *big.Int
		Nonce   uint64
		Code    []byte
	}
	type canonicalState struct {
		Hash, Root common.Hash
		Status     settlement.Status
		Buckets    map[settlement.Bucket]protocol.Amount
		Surplus    protocol.Amount
		Accounts   map[common.Address]accountState
		Entries    []protocol.InboxEntry
	}
	observe := func() canonicalState {
		t.Helper()
		block := chain.CurrentBlock()
		st, err := chain.StateAt(block.Root())
		if err != nil {
			t.Fatal(err)
		}
		status, buckets, surplus, err := settlement.NativeStatus(st, params.DEXSettlementAddress)
		if err != nil {
			t.Fatal(err)
		}
		out := canonicalState{Hash: block.Hash(), Root: block.Root(), Status: status, Buckets: buckets, Surplus: surplus, Accounts: make(map[common.Address]accountState)}
		for _, address := range []common.Address{sender, fake, params.DEXSettlementAddress, fixture.RewardRecipient} {
			out.Accounts[address] = accountState{new(big.Int).Set(st.GetBalance(address)), st.GetNonce(address), common.CopyBytes(st.GetCode(address))}
		}
		for i := uint64(0); i < status.Deposits; i++ {
			entry, err := settlement.ReadNativeEntry(st, params.DEXSettlementAddress, i)
			if err != nil {
				t.Fatal(err)
			}
			out.Entries = append(out.Entries, entry)
		}
		if err := st.Error(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	before := observe()
	if before.Accounts[fake].Balance.Sign() != 0 || before.Accounts[sender].Balance.Cmp(big.NewInt(1)) < 0 {
		t.Fatal("RPC simulation fixture funding/empty sender assumption")
	}
	assertUnchanged := func(label string) {
		t.Helper()
		if after := observe(); !reflect.DeepEqual(after, before) {
			t.Fatalf("%s modified canonical native state", label)
		}
	}
	var receipt *nativeReceipt
	if err := commonNode.Client.Call(&receipt, "eth_getTransactionReceipt", finalizedFundingTX.Hash()); err != nil || receipt == nil || uint64(receipt.Status) != types.ReceiptStatusSuccessful || len(receipt.Logs) != 1 {
		t.Fatal("ordinary RPC native receipt", receipt, err)
	}
	data, err := (protocol.NativeCall{Operation: protocol.NativeDeposit}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	// One native atom is sufficient: there is no conversion or simulated token.
	args := map[string]interface{}{"from": sender, "to": params.DEXSettlementAddress, "value": (*hexutil.Big)(big.NewInt(1)), "gas": hexutil.Uint64(500000), "nonce": hexutil.Uint64(before.Accounts[sender].Nonce), "data": hexutil.Bytes(data)}
	var output hexutil.Bytes
	if err := commonNode.Client.Call(&output, "eth_call", args, ref); err != nil {
		t.Fatal("native eth_call", err)
	}
	entry, err := protocol.DecodeInboxEntry(output)
	amount, _ := protocol.AmountFromBig(big.NewInt(1))
	wantPayload, payloadErr := protocol.NativeFundingPayloadHash([20]byte(sender), [20]byte(sender), amount, 0, protocol.InboxTrader, data)
	if err != nil || payloadErr != nil || len(output) != protocol.InboxEntrySize || entry.Sender != [20]byte(sender) || entry.Owner != [20]byte(sender) || entry.Nonce != before.Accounts[sender].Nonce || entry.Index != before.Status.Deposits || entry.Amount.Big().Cmp(big.NewInt(1)) != 0 || entry.PayloadHash != wantPayload || entry.Bucket != protocol.InboxTrader {
		t.Fatal("native eth_call stable entry mismatch", entry, err)
	}
	assertUnchanged("eth_call")
	var estimate hexutil.Uint64
	if err := commonNode.Client.Call(&estimate, "eth_estimateGas", args); err != nil {
		t.Fatal("native eth_estimateGas", err)
	}
	if uint64(estimate) <= params.TxGas || estimate != receipt.GasUsed {
		t.Fatalf("native estimated gas %d differs from canonical funding receipt %d", estimate, receipt.GasUsed)
	}
	args["gas"] = estimate
	if err := commonNode.Client.Call(&output, "eth_call", args, ref); err != nil {
		t.Fatal("estimated native gas cannot execute", err)
	}
	args["gas"] = estimate - 1
	if err := commonNode.Client.Call(&output, "eth_call", args, ref); err == nil {
		t.Fatal("native eth_call admitted less than estimated gas")
	}
	args["gas"] = hexutil.Uint64(500000)
	assertUnchanged("eth_estimateGas/gas boundary")
	args["from"], args["nonce"] = fake, hexutil.Uint64(0)
	for _, method := range []string{"eth_call", "eth_estimateGas"} {
		var err error
		if method == "eth_call" {
			err = commonNode.Client.Call(&output, method, args, ref)
		} else {
			err = commonNode.Client.Call(&estimate, method, args)
		}
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "insufficient") {
			t.Fatalf("%s unfunded synthetic sender not rejected: %v", method, err)
		}
	}
	// Explicit override success is a simulation. It cannot credit the fake
	// account or create an inbox entry in the canonical state.
	override := map[common.Address]interface{}{fake: map[string]interface{}{"balance": (*hexutil.Big)(big.NewInt(1))}}
	if err := commonNode.Client.Call(&output, "eth_call", args, ref, override); err != nil {
		t.Fatal("explicit balance override simulation", err)
	}
	entry, err = protocol.DecodeInboxEntry(output)
	if err != nil || entry.Owner != [20]byte(fake) || entry.Amount.Big().Cmp(big.NewInt(1)) != 0 {
		t.Fatal("override simulation result", entry, err)
	}
	assertUnchanged("synthetic sender and explicit override")
	var trace ethapi.ExecutionResult
	if err := ipc.Call(&trace, "debug_traceTransaction", finalizedFundingTX.Hash(), map[string]interface{}{}); err != nil {
		t.Fatal("native debug_traceTransaction", err)
	}
	returned, err := hex.DecodeString(trace.ReturnValue)
	if err != nil || trace.Failed || trace.Gas != uint64(receipt.GasUsed) || len(returned) != protocol.InboxEntrySize || !bytes.Equal(returned, receipt.Logs[0].Data) {
		t.Fatal("native trace/receipt/return parity", trace, err)
	}
	assertUnchanged("native debug_traceTransaction")
	var ordinary *types.Transaction
	for height := uint64(1); height <= head.NumberU64() && ordinary == nil; height++ {
		for _, tx := range chain.GetBlockByNumber(height).Transactions() {
			if tx.To() != nil && *tx.To() != params.DEXSettlementAddress && len(tx.Data()) == 0 && tx.Gas() == params.TxGas {
				ordinary = tx
				break
			}
		}
	}
	if ordinary == nil {
		t.Fatal("legacy RPC trace parity requires a finalized ordinary EOA transaction")
	}
	trace = ethapi.ExecutionResult{}
	if err := ipc.Call(&trace, "debug_traceTransaction", ordinary.Hash(), map[string]interface{}{}); err != nil || trace.Failed || trace.Gas != params.TxGas || trace.ReturnValue != "" {
		t.Fatal("ordinary transaction trace regressed", trace, err)
	}
	assertUnchanged("ordinary debug_traceTransaction")
	t.Logf("NATIVE_RPC_PARITY head=%s eth_call_return=%d estimate=%d native_trace_gas=%d ordinary_trace_gas=%d fake_from=insufficient explicit_override=simulation canonical_state=unchanged", head.Hash().Hex(), protocol.InboxEntrySize, receipt.GasUsed, receipt.GasUsed, trace.Gas)
}
