package types

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/rlp"
)

func testAddress(n byte) common.Address {
	var addr common.Address
	addr[19] = n
	return addr
}

func TestTypedTransactionRejectsOversizedIntegerFields(t *testing.T) {
	overflow := new(big.Int).Lsh(big.NewInt(1), 256)
	to := testAddress(1)
	inner := &SetCodeTx{
		ChainID:   big.NewInt(1),
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1),
		To:        to,
		Value:     big.NewInt(0),
		AuthList: []SetCodeAuthorization{{
			ChainID: overflow,
			Address: to,
			V:       big.NewInt(0),
			R:       big.NewInt(1),
			S:       big.NewInt(1),
		}},
		V: big.NewInt(0), R: big.NewInt(1), S: big.NewInt(1),
	}
	if _, err := NewTx(inner).MarshalBinary(); err == nil {
		t.Fatal("expected oversized authorization chainId to be rejected on encode")
	}
	payload, err := rlp.EncodeToBytes(inner)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Transaction
	if err := decoded.UnmarshalBinary(append([]byte{SetCodeTxType}, payload...)); err == nil {
		t.Fatal("expected oversized authorization chainId to be rejected on decode")
	}
}

func TestTypedTransactionRejectsTrailingPayload(t *testing.T) {
	to := testAddress(1)
	tx := NewTx(&DynamicFeeTx{
		ChainID: big.NewInt(1), GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(1),
		Gas: 21_000, To: &to, Value: big.NewInt(0), V: big.NewInt(0), R: big.NewInt(1), S: big.NewInt(1),
	})
	encoded, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, 0x80) // A second, ignored RLP value.
	var decoded Transaction
	if err := decoded.UnmarshalBinary(encoded); err == nil {
		t.Fatal("typed transaction with trailing RLP was accepted")
	}
}

func testHash(n byte) common.Hash {
	var hash common.Hash
	hash[31] = n
	return hash
}

func assertTxTypeRoundTrip(t *testing.T, tx *Transaction, want uint8) {
	t.Helper()
	enc, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}
	var dec Transaction
	if err := dec.UnmarshalBinary(enc); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}
	if got := dec.Type(); got != want {
		t.Fatalf("binary tx type mismatch: got %d want %d", got, want)
	}

	blob, err := json.Marshal(tx)
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}
	var fromJSON Transaction
	if err := json.Unmarshal(blob, &fromJSON); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v\njson=%s", err, blob)
	}
	if got := fromJSON.Type(); got != want {
		t.Fatalf("json tx type mismatch: got %d want %d", got, want)
	}
}

func TestTypedTransactionRoundTrip(t *testing.T) {
	to := testAddress(1)
	accessList := AccessList{
		{
			Address:     testAddress(2),
			StorageKeys: []common.Hash{testHash(3)},
		},
	}

	assertTxTypeRoundTrip(t, &Transaction{data: &AccessListTx{
		ChainID:    big.NewInt(12367),
		Nonce:      1,
		GasPrice:   big.NewInt(1000),
		Gas:        21000,
		To:         &to,
		Value:      big.NewInt(1),
		Data:       []byte{0x01, 0x02},
		AccessList: accessList,
		V:          big.NewInt(0),
		R:          big.NewInt(1),
		S:          big.NewInt(1),
	}}, AccessListTxType)

	assertTxTypeRoundTrip(t, &Transaction{data: &DynamicFeeTx{
		ChainID:    big.NewInt(12367),
		Nonce:      2,
		GasTipCap:  big.NewInt(10),
		GasFeeCap:  big.NewInt(100),
		Gas:        50000,
		To:         &to,
		Value:      big.NewInt(2),
		Data:       []byte{0x03, 0x04},
		AccessList: accessList,
		V:          big.NewInt(0),
		R:          big.NewInt(1),
		S:          big.NewInt(1),
	}}, DynamicFeeTxType)

	assertTxTypeRoundTrip(t, &Transaction{data: &BlobTx{
		ChainID:    big.NewInt(12367),
		Nonce:      3,
		GasTipCap:  big.NewInt(10),
		GasFeeCap:  big.NewInt(100),
		Gas:        80000,
		To:         to,
		Value:      big.NewInt(3),
		Data:       []byte{0x05, 0x06},
		AccessList: accessList,
		BlobFeeCap: big.NewInt(7),
		BlobHashes: []common.Hash{testHash(4)},
		V:          big.NewInt(0),
		R:          big.NewInt(1),
		S:          big.NewInt(1),
	}}, BlobTxType)

	assertTxTypeRoundTrip(t, &Transaction{data: &SetCodeTx{
		ChainID:    big.NewInt(12367),
		Nonce:      4,
		GasTipCap:  big.NewInt(10),
		GasFeeCap:  big.NewInt(100),
		Gas:        90000,
		To:         to,
		Value:      big.NewInt(4),
		Data:       []byte{0x07, 0x08},
		AccessList: accessList,
		AuthList: []SetCodeAuthorization{{
			ChainID: big.NewInt(12367),
			Address: testAddress(5),
			Nonce:   1,
			V:       big.NewInt(0),
			R:       big.NewInt(1),
			S:       big.NewInt(1),
		}},
		V: big.NewInt(0),
		R: big.NewInt(1),
		S: big.NewInt(1),
	}}, SetCodeTxType)
}

func TestTypedTransactionHashUsesRawEnvelope(t *testing.T) {
	to := testAddress(1)
	accessList := AccessList{
		{
			Address:     testAddress(2),
			StorageKeys: []common.Hash{testHash(3)},
		},
	}

	txs := []*Transaction{
		{data: &AccessListTx{
			ChainID:    big.NewInt(1236789),
			Nonce:      1,
			GasPrice:   big.NewInt(1000),
			Gas:        21000,
			To:         &to,
			Value:      big.NewInt(1),
			Data:       []byte{0x01, 0x02},
			AccessList: accessList,
			V:          big.NewInt(0),
			R:          big.NewInt(1),
			S:          big.NewInt(1),
		}},
		{data: &DynamicFeeTx{
			ChainID:    big.NewInt(1236789),
			Nonce:      2,
			GasTipCap:  big.NewInt(10),
			GasFeeCap:  big.NewInt(100),
			Gas:        50000,
			To:         &to,
			Value:      big.NewInt(2),
			Data:       []byte{0x03, 0x04},
			AccessList: accessList,
			V:          big.NewInt(0),
			R:          big.NewInt(1),
			S:          big.NewInt(1),
		}},
	}

	for _, tx := range txs {
		enc, err := tx.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary failed: %v", err)
		}
		want := crypto.Keccak256Hash(enc)
		if got := tx.Hash(); got != want {
			t.Fatalf("typed tx hash mismatch: got %s want %s", got.Hex(), want.Hex())
		}
	}
}
