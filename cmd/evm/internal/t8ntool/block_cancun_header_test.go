package t8ntool

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
)

func TestB11RToBlockCopiesCancunHeaderFields(t *testing.T) {
	blobGasUsed := uint64(0x20000)
	excessBlobGas := uint64(0x40000)
	parentBeaconRoot := common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")
	withdrawalsRoot := common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222")
	requestsHash := common.HexToHash("0x3333333333333333333333333333333333333333333333333333333333333333")
	input := &bbInput{Header: &blockHeaderInput{
		Number:                big.NewInt(7),
		Difficulty:            big.NewInt(1),
		GasLimit:              0x100000,
		GasUsed:               0x5208,
		Time:                  0x1234,
		BaseFee:               big.NewInt(1000000000),
		BlobGasUsed:           &blobGasUsed,
		ExcessBlobGas:         &excessBlobGas,
		ParentBeaconBlockRoot: &parentBeaconRoot,
		WithdrawalsHash:       &withdrawalsRoot,
		RequestsHash:          &requestsHash,
	}}
	block, err := input.ToBlock()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	header := block.Header()
	if header.Number.Cmp(big.NewInt(7)) != 0 {
		t.Fatalf("number mismatch: %v", header.Number)
	}
	if header.BaseFee.Cmp(big.NewInt(1000000000)) != 0 {
		t.Fatalf("baseFee mismatch: %v", header.BaseFee)
	}
	if header.BlobGasUsed != blobGasUsed {
		t.Fatalf("blobGasUsed mismatch: %d", header.BlobGasUsed)
	}
	if header.ExcessBlobGas != excessBlobGas {
		t.Fatalf("excessBlobGas mismatch: %d", header.ExcessBlobGas)
	}
	if header.ParentBeaconRoot != parentBeaconRoot {
		t.Fatalf("parentBeaconRoot mismatch")
	}
	if header.WithdrawalsHash != withdrawalsRoot {
		t.Fatalf("withdrawalsRoot mismatch")
	}
	if header.RequestsHash != requestsHash {
		t.Fatalf("requestsHash mismatch")
	}
}
