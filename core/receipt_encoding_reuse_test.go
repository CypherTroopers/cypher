package core

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/trie"
)

func TestRLPStringEnvelopeSizeMatchesEncoder(t *testing.T) {
	for _, size := range []int{0, 1, 2, 55, 56, 255, 256, 4096} {
		payload := make([]byte, size)
		if size == 1 {
			payload[0] = 0x01
		}
		encoded, err := rlp.EncodeToBytes(payload)
		if err != nil {
			t.Fatalf("encode size %d: %v", size, err)
		}
		if got := rlpStringEnvelopeSize(payload); got != uint64(len(encoded)) {
			t.Fatalf("payload %d envelope = %d, want %d", size, got, len(encoded))
		}
	}
}

func TestEVMReceiptReusedEncodingPreservesListSize(t *testing.T) {
	receipts := types.Receipts{
		{Type: types.LegacyTxType, Status: types.ReceiptStatusSuccessful},
		{Type: types.AccessListTxType, Status: types.ReceiptStatusFailed},
		{Type: types.DynamicFeeTxType, Status: types.ReceiptStatusSuccessful},
		{Type: types.BlobTxType, Status: types.ReceiptStatusFailed},
		{Type: types.SetCodeTxType, Status: types.ReceiptStatusSuccessful, Logs: []*types.Log{{Data: make([]byte, 1024)}}},
	}
	var oldContent, reusedContent uint64
	for index, receipt := range receipts {
		wrapped, err := rlp.EncodeToBytes(receipt)
		if err != nil {
			t.Fatalf("encode wrapped receipt %d: %v", index, err)
		}
		leaf, err := receipt.MarshalBinary()
		if err != nil {
			t.Fatalf("encode receipt leaf %d: %v", index, err)
		}
		oldContent += uint64(len(wrapped))
		if receipt.Type == types.LegacyTxType {
			reusedContent += uint64(len(leaf))
		} else {
			reusedContent += rlpStringEnvelopeSize(leaf)
		}
	}
	if oldContent != reusedContent || rlp.ListSize(oldContent) != rlp.ListSize(reusedContent) {
		t.Fatalf("receipt list size changed: old=%d reused=%d", oldContent, reusedContent)
	}
}

func TestEVMValidateStateMixedReceiptBatches(t *testing.T) {
	config := evmOnlyNativeConfig()
	receipts := make(types.Receipts, 257)
	for index := range receipts {
		receiptType := uint8(index % (types.SetCodeTxType + 1))
		receipts[index] = &types.Receipt{Type: receiptType, Status: types.ReceiptStatusSuccessful}
	}
	statedb := newModernTestState(t)
	header := &types.Header{
		Number:      big.NewInt(0),
		Bloom:       types.CreateBloom(receipts),
		ReceiptHash: types.DeriveSha(receipts, new(trie.Trie)),
		Root:        statedb.IntermediateRoot(config.IsEIP158(big.NewInt(0))),
	}
	block := types.NewBlockWithHeader(header)
	validator := &BlockValidator{config: config}
	if err := validator.ValidateState(block, statedb, receipts, 0); err != nil {
		t.Fatalf("mixed typed receipt validation failed: %v", err)
	}
}
