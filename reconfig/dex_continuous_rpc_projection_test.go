package reconfig_test

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/internal/ethapi"
)

func TestContinuousRPCProjectionCanonicalAndIncompleteHeader(t *testing.T) {
	for _, gas := range []uint64{0, 21000} {
		header := &types.Header{Number: big.NewInt(754), Difficulty: big.NewInt(1), BaseFee: big.NewInt(1), ParentHash: common.Hash{31: 1}, Root: common.Hash{31: 2}, TxHash: common.Hash{31: 3}, ReceiptHash: common.Hash{31: 4}, CommonTxAdmissionRoot: common.Hash{31: 5}, CommonTxRewardRoot: common.Hash{31: 6}, GasUsed: gas, GasLimit: 30000000, Extra: []byte{}}
		want := types.NewBlockWithHeader(header)
		raw, err := json.Marshal(ethapi.RPCMarshalHeader(header))
		if err != nil {
			t.Fatal(err)
		}
		var got *continuousRPCBlock
		if err = json.Unmarshal(raw, &got); err != nil || got.matchCanonical(want) != nil {
			t.Fatal("real RPC projection rejected", err)
		}
		var incomplete types.Header
		if err = json.Unmarshal(raw, &incomplete); err != nil {
			t.Fatal(err)
		}
		if incomplete.Hash() == header.Hash() || incomplete.Root != header.Root || incomplete.GasUsed != header.GasUsed || incomplete.CommonTxAdmissionRoot != (common.Hash{}) || incomplete.CommonTxRewardRoot != (common.Hash{}) {
			t.Fatal("did not reproduce lossy RPC Header hash reconstruction")
		}
		t.Logf("gas=%d explicitHash=%s reconstructedHash=%s rootAndGasMatch=true", gas, got.Hash.Hex(), incomplete.Hash().Hex())
		fields := []string{"hash", "number", "parentHash", "stateRoot", "transactionsRoot", "receiptsRoot", "gasUsed"}
		for _, field := range fields {
			for _, mutation := range []string{"missing", "null", "modified"} {
				t.Run(field+"/"+mutation, func(t *testing.T) {
					var modified map[string]json.RawMessage
					if err := json.Unmarshal(raw, &modified); err != nil {
						t.Fatal(err)
					}
					switch mutation {
					case "missing":
						delete(modified, field)
					case "null":
						modified[field] = json.RawMessage("null")
					case "modified":
						value := any(common.Hash{31: 99})
						if field == "number" || field == "gasUsed" {
							value = "0x63"
						}
						modified[field], _ = json.Marshal(value)
					}
					bad, err := json.Marshal(modified)
					if err != nil {
						t.Fatal(err)
					}
					var rejected *continuousRPCBlock
					if err = json.Unmarshal(bad, &rejected); err != nil {
						t.Fatal(err)
					}
					if rejected.matchCanonical(want) == nil {
						t.Fatal("invalid projection accepted")
					}
				})
			}
		}
		var absent *continuousRPCBlock
		if err = json.Unmarshal([]byte("null"), &absent); err != nil || absent.matchCanonical(want) == nil {
			t.Fatal("null RPC block accepted", err)
		}
	}
}
