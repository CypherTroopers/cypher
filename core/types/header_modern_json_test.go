package types

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
)

func TestHeaderJSONPreservesModernFields(t *testing.T) {
	original := &Header{
		Difficulty:       big.NewInt(1),
		Number:           big.NewInt(2),
		Extra:            []byte{},
		WithdrawalsHash:  common.HexToHash("0x01"),
		BlobGasUsed:      2,
		ExcessBlobGas:    3,
		ParentBeaconRoot: common.HexToHash("0x04"),
		RequestsHash:     common.HexToHash("0x05"),
	}
	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Header
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.WithdrawalsHash != original.WithdrawalsHash ||
		decoded.BlobGasUsed != original.BlobGasUsed ||
		decoded.ExcessBlobGas != original.ExcessBlobGas ||
		decoded.ParentBeaconRoot != original.ParentBeaconRoot ||
		decoded.RequestsHash != original.RequestsHash {
		t.Fatalf("modern fields changed across JSON round trip: got %#v", decoded)
	}
}
