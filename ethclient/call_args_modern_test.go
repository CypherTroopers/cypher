package ethclient

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/cypherium/cypher"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core/types"
)

func TestToCallArgIncludesModernEVMFields(t *testing.T) {
	to := common.HexToAddress("0x1000000000000000000000000000000000000001")
	accessList := types.AccessList{{Address: to, StorageKeys: []common.Hash{{1}}}}
	blobHashes := []common.Hash{{types.BlobCommitmentVersionKZG}}
	authList := []types.SetCodeAuthorization{{
		ChainID: big.NewInt(1), Address: to, Nonce: 2,
		V: new(big.Int), R: big.NewInt(1), S: big.NewInt(1),
	}}
	msg := cypher.CallMsg{
		From: common.HexToAddress("0x2000000000000000000000000000000000000002"),
		To:   &to, Gas: 100_000, GasFeeCap: big.NewInt(20), GasTipCap: big.NewInt(2),
		Value: big.NewInt(3), Data: []byte{0xde, 0xad}, AccessList: accessList,
		BlobGasFeeCap: big.NewInt(4), BlobHashes: blobHashes, AuthorizationList: authList,
	}
	arg, ok := toCallArg(msg).(map[string]interface{})
	if !ok {
		t.Fatalf("call argument type = %T", toCallArg(msg))
	}
	if _, exists := arg["data"]; exists {
		t.Fatal("call argument used deprecated data instead of input")
	}
	if input, ok := arg["input"].(hexutil.Bytes); !ok || !bytes.Equal(input, msg.Data) {
		t.Fatalf("input = %#v, want %x", arg["input"], msg.Data)
	}
	for field, want := range map[string]*big.Int{
		"maxFeePerGas":         msg.GasFeeCap,
		"maxPriorityFeePerGas": msg.GasTipCap,
		"maxFeePerBlobGas":     msg.BlobGasFeeCap,
	} {
		got, ok := arg[field].(*hexutil.Big)
		if !ok || got.ToInt().Cmp(want) != 0 {
			t.Fatalf("%s = %#v, want %v", field, arg[field], want)
		}
	}
	if got, ok := arg["accessList"].(types.AccessList); !ok || len(got) != 1 {
		t.Fatalf("accessList = %#v", arg["accessList"])
	}
	if got, ok := arg["blobVersionedHashes"].([]common.Hash); !ok || len(got) != 1 || got[0] != blobHashes[0] {
		t.Fatalf("blobVersionedHashes = %#v", arg["blobVersionedHashes"])
	}
	if got, ok := arg["authorizationList"].([]types.SetCodeAuthorization); !ok || len(got) != 1 || got[0].Nonce != 2 {
		t.Fatalf("authorizationList = %#v", arg["authorizationList"])
	}
}
