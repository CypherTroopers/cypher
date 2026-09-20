package eth

import (
	"context"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/internal/ethapi"
	"github.com/cypherium/cypher/params"
)

type blockscoutTestEngine struct{ consensus.Engine }

func (blockscoutTestEngine) Author(h *types.Header) (common.Address, error) { return h.Coinbase, nil }

type blockscoutTestChain struct{}

func (blockscoutTestChain) Engine() consensus.Engine                    { return blockscoutTestEngine{} }
func (blockscoutTestChain) GetHeader(common.Hash, uint64) *types.Header { return nil }

func TestBlockscoutTraceExecution(t *testing.T) {
	for _, mode := range []string{"legacy", "dynamic", "return", "revert", "custom-js"} {
		t.Run(mode, func(t *testing.T) {
			id := big.NewInt(10101919)
			cfg := &params.ChainConfig{ChainID: id, HomesteadBlock: big.NewInt(0), EIP150Block: big.NewInt(0), EIP155Block: big.NewInt(0), EIP158Block: big.NewInt(0), ByzantiumBlock: big.NewInt(0), ConstantinopleBlock: big.NewInt(0), PetersburgBlock: big.NewInt(0), IstanbulBlock: big.NewInt(0)}
			cfg.SetModernForkConfig(&params.ModernForkConfig{BerlinBlock: big.NewInt(0), LondonBlock: big.NewInt(0)})
			db := rawdb.NewMemoryDatabase()
			defer db.Close()
			st, err := state.New(common.Hash{}, state.NewDatabase(db), nil)
			if err != nil {
				t.Fatal(err)
			}
			key, err := crypto.GenerateKey()
			if err != nil {
				t.Fatal(err)
			}
			from := crypto.PubkeyToAddress(key.PublicKey)
			to := common.HexToAddress("0x0000000000000000000000000000000000001234")
			st.SetBalance(from, new(big.Int).Exp(big.NewInt(10), big.NewInt(22), nil))
			st.SetBalance(to, big.NewInt(1))
			gas := uint64(21000)
			switch mode {
			case "return":
				st.SetCode(to, common.FromHex("0x602a60005260206000f3"))
				gas = 100000
			case "revert":
				st.SetCode(to, common.FromHex("0x60006000fd"))
				gas = 100000
			}
			tx := types.NewTransaction(0, to, big.NewInt(10), gas, big.NewInt(1000000000), nil)
			var signer types.Signer = types.NewEIP155Signer(id)
			if mode == "dynamic" {
				tx = types.NewTx(&types.DynamicFeeTx{ChainID: id, To: &to, Gas: gas, GasFeeCap: big.NewInt(2000000000), GasTipCap: big.NewInt(200000000), Value: big.NewInt(10)})
				signer = types.NewLondonSigner(id)
			}
			tx, err = types.SignTx(tx, signer, key)
			if err != nil {
				t.Fatal(err)
			}
			block := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1), Time: 1, GasLimit: 30000000, BaseFee: big.NewInt(800000000)}).WithBody([]*types.Transaction{tx}, nil)
			tracer := "callTracer"
			traceConfig := &TraceConfig{Tracer: &tracer}
			if mode == "return" || mode == "revert" {
				traceConfig = &TraceConfig{}
			}
			if mode == "custom-js" {
				tracer = `{step:function(){},fault:function(){},result:function(ctx,db){return {gasUsed:ctx.gasUsed,nonce:db.getNonce(ctx.from)};}}`
			}
			used := uint64(0)
			result, receipt, err := blockscoutApplyTrace(context.Background(), cfg, blockscoutTestChain{}, block, st, new(core.GasPool).AddGas(block.GasLimit()), &used, 0, traceConfig)
			if err != nil {
				t.Fatal(err)
			}
			if receipt == nil || used != receipt.GasUsed || st.GetNonce(from) != 1 {
				t.Fatal("receipt or post-state mismatch")
			}
			if mode == "return" || mode == "revert" {
				execution, ok := result.(*ethapi.ExecutionResult)
				if !ok {
					t.Fatalf("unexpected result %T", result)
				}
				if mode == "return" && (execution.Failed || execution.ReturnValue != "000000000000000000000000000000000000000000000000000000000000002a") {
					t.Fatalf("wrong return: %+v", execution)
				}
				if mode == "revert" && (!execution.Failed || receipt.Status != types.ReceiptStatusFailed) {
					t.Fatal("revert not recorded")
				}
				return
			}
			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			var call map[string]interface{}
			if err := json.Unmarshal(encoded, &call); err != nil {
				t.Fatal(err)
			}
			if mode == "custom-js" {
				if call["gasUsed"] != float64(21000) || call["nonce"] != float64(1) {
					t.Fatalf("JS context/DB wrapper mismatch: %v", call)
				}
			} else {
				if call["gasUsed"] != "0x5208" || call["gas"] != "0x5208" {
					t.Fatalf("wrong root gas: %v", call)
				}
				if call["from"] != from.Hex() && call["from"] != common.Bytes2Hex(from[:]) && call["from"] != "0x"+common.Bytes2Hex(from[:]) {
					t.Fatalf("wrong sender: %v", call["from"])
				}
			}
		})
	}
}
func TestBlockscoutTraceHashEnvelope(t *testing.T) {
	hash := common.HexToHash("0x1234")
	encoded, err := json.Marshal(&txTraceResult{TxHash: hash, Result: []interface{}{}})
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	if result["txHash"] != hash.Hex() {
		t.Fatalf("missing txHash: %s", encoded)
	}
}
