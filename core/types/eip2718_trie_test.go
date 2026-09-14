package types

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
)

func testDynamicFeeTransaction() *Transaction {
	to := common.HexToAddress("0x1234")
	return NewTx(&DynamicFeeTx{
		ChainID: big.NewInt(1), Nonce: 7,
		GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2), Gas: 21000,
		To: &to, Value: big.NewInt(3), Data: []byte{4}, AccessList: AccessList{},
		V: big.NewInt(0), R: big.NewInt(1), S: big.NewInt(1),
	})
}

func testTypedTransactions() []*Transaction {
	to := common.HexToAddress("0x1234")
	return []*Transaction{
		NewTx(&AccessListTx{
			ChainID: big.NewInt(1), Nonce: 7, GasPrice: big.NewInt(2), Gas: 21000,
			To: &to, Value: big.NewInt(3), Data: []byte{4}, AccessList: AccessList{},
			V: big.NewInt(0), R: big.NewInt(1), S: big.NewInt(1),
		}),
		testDynamicFeeTransaction(),
		NewTx(&BlobTx{
			ChainID: big.NewInt(1), Nonce: 7, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2), Gas: 21000,
			To: to, Value: big.NewInt(3), Data: []byte{4}, AccessList: AccessList{}, BlobFeeCap: big.NewInt(1),
			V: big.NewInt(0), R: big.NewInt(1), S: big.NewInt(1),
		}),
		NewTx(&SetCodeTx{
			ChainID: big.NewInt(1), Nonce: 7, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2), Gas: 21000,
			To: to, Value: big.NewInt(3), Data: []byte{4}, AccessList: AccessList{}, AuthList: []SetCodeAuthorization{},
			V: big.NewInt(0), R: big.NewInt(1), S: big.NewInt(1),
		}),
		NewTx(&NativeTxV1{
			ChainID: big.NewInt(1), RecentBlockHash: testHash(5), RecentBlockNumber: 7, ValidUntil: 14,
			Payer: testAddress(1), To: testAddress(2), Value: big.NewInt(3), Data: []byte{4},
			MaxFeePerCompute: big.NewInt(2), PriorityFeePerCompute: big.NewInt(1), ComputeLimit: 21_000,
			MemoryLimit: 1024, LogLimit: 1024, OutputLimit: 1024,
			Accesses: []NativeAccess{
				{Resource: NativeResource{Kind: NativeResourceAccount, Address: testAddress(1)}, Mode: NativeAccessWrite},
				{Resource: NativeResource{Kind: NativeResourceAccount, Address: testAddress(2)}, Mode: NativeAccessWrite},
			},
			V: big.NewInt(0), R: big.NewInt(1), S: big.NewInt(1),
		}),
	}
}

func testConsensusReceipt(typ uint8) *Receipt {
	return &Receipt{
		Type: typ, Status: ReceiptStatusSuccessful, CumulativeGasUsed: 21000,
		Bloom: Bloom{}, Logs: []*Log{},
	}
}

func TestEIP2718TransactionTrieLeafUsesRawTypedEnvelope(t *testing.T) {
	for _, typed := range testTypedTransactions() {
		want, err := typed.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if got := (Transactions{typed}).GetRlp(0); !bytes.Equal(got, want) {
			t.Fatalf("type-%d transaction trie leaf = %x, want raw envelope %x", typed.Type(), got, want)
		}
		embedded, err := rlp.EncodeToBytes(typed)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(embedded, want) {
			t.Fatalf("type-%d block-body transaction unexpectedly equals raw trie envelope", typed.Type())
		}
	}

	legacy := NewTransaction(0, common.HexToAddress("0x01"), big.NewInt(1), 21000, big.NewInt(1), nil)
	legacyWant, err := legacy.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if got := (Transactions{legacy}).GetRlp(0); !bytes.Equal(got, legacyWant) {
		t.Fatalf("legacy transaction trie leaf changed: have %x want %x", got, legacyWant)
	}
}

func TestEIP2718ReceiptTrieLeafAndEmbeddedRoundTrip(t *testing.T) {
	for _, typ := range []uint8{AccessListTxType, DynamicFeeTxType, BlobTxType, SetCodeTxType, NativeTxType} {
		receipt := testConsensusReceipt(typ)
		payload, err := rlp.EncodeToBytes(receipt.consensusEncoding())
		if err != nil {
			t.Fatal(err)
		}
		want := append([]byte{typ}, payload...)
		if got := (Receipts{receipt}).GetRlp(0); !bytes.Equal(got, want) {
			t.Fatalf("type-%d receipt trie leaf = %x, want %x", typ, got, want)
		}
		embedded, err := rlp.EncodeToBytes(receipt)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(embedded, want) {
			t.Fatalf("type-%d receipt-list encoding omitted the required RLP string wrapper", typ)
		}
		var decoded Receipt
		if err := rlp.DecodeBytes(embedded, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Type != typ || decoded.Status != receipt.Status || decoded.CumulativeGasUsed != receipt.CumulativeGasUsed {
			t.Fatalf("type-%d receipt round trip mismatch: %#v", typ, decoded)
		}
	}

	legacy := testConsensusReceipt(LegacyTxType)
	legacyPayload, err := rlp.EncodeToBytes(legacy.consensusEncoding())
	if err != nil {
		t.Fatal(err)
	}
	if got := (Receipts{legacy}).GetRlp(0); !bytes.Equal(got, legacyPayload) {
		t.Fatalf("legacy receipt trie leaf changed: have %x want %x", got, legacyPayload)
	}
}

func TestEIP2718ReceiptRejectsUnknownTypeAndTrailingPayload(t *testing.T) {
	payload, err := testConsensusReceipt(DynamicFeeTxType).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var decoded Receipt
	if err := decoded.UnmarshalBinary(append(payload, 0x80)); err == nil {
		t.Fatal("typed receipt with trailing RLP was accepted")
	}
	payload[0] = 0x7f
	if err := decoded.UnmarshalBinary(payload); err == nil {
		t.Fatal("unknown typed receipt was accepted")
	}
}

func TestReceiptDeriveFieldsRestoresTransactionType(t *testing.T) {
	tx := testDynamicFeeTransaction()
	receipt := testConsensusReceipt(LegacyTxType)
	if err := (Receipts{receipt}).DeriveFields(params.AllcolossusXProtocolChanges, common.Hash{}, 1, Transactions{tx}); err != nil {
		t.Fatal(err)
	}
	if receipt.Type != DynamicFeeTxType {
		t.Fatalf("derived receipt type = %d, want %d", receipt.Type, DynamicFeeTxType)
	}
}
