package core

import (
	"math/big"
	"strings"
	"testing"

	"github.com/cypherium/cypher/core/types"
)

func TestEVMValidateStateRejectsActualReceiptBytes(t *testing.T) {
	config := evmOnlyNativeConfig()
	config.NativeParallel.MaxReceiptBytesPerBlock = 100
	receipts := types.Receipts{{Status: types.ReceiptStatusSuccessful}}
	header := &types.Header{Number: big.NewInt(0), Bloom: types.CreateBloom(receipts)}
	block := types.NewBlockWithHeader(header)
	validator := &BlockValidator{config: config}
	if err := validator.ValidateState(block, newModernTestState(t), receipts, 0); err == nil || !strings.Contains(err.Error(), "receipt bytes") {
		t.Fatalf("expected actual receipt byte rejection, got %v", err)
	}
}

func TestEVMValidateStateRejectsNilReceiptBeforeBloom(t *testing.T) {
	config := evmOnlyNativeConfig()
	header := &types.Header{Number: big.NewInt(0)}
	block := types.NewBlockWithHeader(header)
	validator := &BlockValidator{config: config}
	if err := validator.ValidateState(block, newModernTestState(t), types.Receipts{nil}, 0); err == nil || !strings.Contains(err.Error(), "receipt 0 is nil") {
		t.Fatalf("nil receipt error = %v", err)
	}
}
