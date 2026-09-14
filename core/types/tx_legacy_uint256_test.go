package types

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/rlp"
)

func legacyUint256TestTransaction() *Transaction {
	to := common.HexToAddress("0x1234567890123456789012345678901234567890")
	return NewTx(&LegacyTx{
		AccountNonce: 1,
		Price:        big.NewInt(2),
		GasLimit:     21_000,
		Recipient:    &to,
		Amount:       big.NewInt(3),
		Payload:      []byte{0x01, 0x02},
		V:            big.NewInt(27),
		R:            big.NewInt(1),
		S:            big.NewInt(2),
	})
}

func TestLegacyTransactionAcceptsUint256Boundary(t *testing.T) {
	maximum := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	tx := legacyUint256TestTransaction()
	inner := tx.legacyData()
	inner.Price.Set(maximum)
	inner.Amount.Set(maximum)
	inner.V.Set(maximum)
	inner.R.Set(maximum)
	inner.S.Set(maximum)

	wire, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("256-bit legacy transaction was rejected: %v", err)
	}
	var decoded Transaction
	if err := decoded.UnmarshalBinary(wire); err != nil {
		t.Fatalf("256-bit legacy transaction failed binary round trip: %v", err)
	}
	price := decoded.GasPrice()
	value := decoded.Value()
	v, r, s := decoded.RawSignatureValues()
	for name, field := range map[string]*big.Int{
		"gasPrice": price,
		"value":    value,
		"v":        v,
		"r":        r,
		"s":        s,
	} {
		if field.Cmp(maximum) != 0 {
			t.Fatalf("%s changed across round trip: have %x want %x", name, field, maximum)
		}
	}

	embedded, err := rlp.EncodeToBytes(tx)
	if err != nil {
		t.Fatalf("256-bit legacy transaction failed embedded RLP encoding: %v", err)
	}
	var fromEmbedded Transaction
	if err := rlp.DecodeBytes(embedded, &fromEmbedded); err != nil {
		t.Fatalf("256-bit legacy transaction failed embedded RLP decoding: %v", err)
	}
	if fromEmbedded.GasPrice().Cmp(maximum) != 0 {
		t.Fatal("embedded RLP round trip changed 256-bit gasPrice")
	}
}

func TestLegacyTransactionRejectsOutOfRangeIntegersBeforeEncodingHashAndSigning(t *testing.T) {
	overflow := new(big.Int).Lsh(big.NewInt(1), 256)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*LegacyTx)
	}{
		{"gasPrice", func(tx *LegacyTx) { tx.Price.Set(overflow) }},
		{"value", func(tx *LegacyTx) { tx.Amount.Set(overflow) }},
		{"v", func(tx *LegacyTx) { tx.V.Set(overflow) }},
		{"r", func(tx *LegacyTx) { tx.R.Set(overflow) }},
		{"s", func(tx *LegacyTx) { tx.S.Set(overflow) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tx := legacyUint256TestTransaction()
			test.mutate(tx.legacyData())
			if err := tx.ValidateIntegerBounds(); !errors.Is(err, ErrTxIntegerOutOfRange) {
				t.Fatalf("ValidateIntegerBounds error = %v, want %v", err, ErrTxIntegerOutOfRange)
			}
			if _, err := tx.MarshalBinary(); !errors.Is(err, ErrTxIntegerOutOfRange) {
				t.Fatalf("MarshalBinary error = %v, want %v", err, ErrTxIntegerOutOfRange)
			}
			if _, err := rlp.EncodeToBytes(tx); !errors.Is(err, ErrTxIntegerOutOfRange) {
				t.Fatalf("EncodeRLP error = %v, want %v", err, ErrTxIntegerOutOfRange)
			}
			if _, err := tx.MarshalJSON(); !errors.Is(err, ErrTxIntegerOutOfRange) {
				t.Fatalf("MarshalJSON error = %v, want %v", err, ErrTxIntegerOutOfRange)
			}
			if hash := tx.Hash(); hash != (common.Hash{}) {
				t.Fatalf("invalid legacy transaction produced hash %s", hash)
			}
			if _, err := SignTx(tx, NewEIP155Signer(big.NewInt(1)), key); !errors.Is(err, ErrTxIntegerOutOfRange) {
				t.Fatalf("SignTx error = %v, want %v", err, ErrTxIntegerOutOfRange)
			}
		})
	}
}

func TestLegacyTransactionRejectsNegativeIntegers(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*LegacyTx)
	}{
		{"gasPrice", func(tx *LegacyTx) { tx.Price.SetInt64(-1) }},
		{"value", func(tx *LegacyTx) { tx.Amount.SetInt64(-1) }},
		{"v", func(tx *LegacyTx) { tx.V.SetInt64(-1) }},
		{"r", func(tx *LegacyTx) { tx.R.SetInt64(-1) }},
		{"s", func(tx *LegacyTx) { tx.S.SetInt64(-1) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx := legacyUint256TestTransaction()
			test.mutate(tx.legacyData())
			if _, err := tx.MarshalBinary(); !errors.Is(err, ErrTxIntegerOutOfRange) {
				t.Fatalf("negative legacy integer error = %v, want %v", err, ErrTxIntegerOutOfRange)
			}
		})
	}
}

func TestLegacySigningRejectsSignatureValuesOutsideUint256(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	// EIP-155 doubles the chain ID when deriving V. This chain ID therefore
	// produces a 257-bit V even though every field in the unsigned transaction
	// is otherwise valid.
	chainID := new(big.Int).Lsh(big.NewInt(1), 255)
	if _, err := SignTx(legacyUint256TestTransaction(), NewEIP155Signer(chainID), key); !errors.Is(err, ErrTxIntegerOutOfRange) {
		t.Fatalf("SignTx error = %v, want %v", err, ErrTxIntegerOutOfRange)
	}
}

type legacyRawIntegerTransaction struct {
	AccountNonce uint64
	Price        rlp.RawValue
	GasLimit     uint64
	Recipient    *common.Address `rlp:"nil"`
	Amount       rlp.RawValue
	Payload      []byte
	V            rlp.RawValue
	R            rlp.RawValue
	S            rlp.RawValue
}

func rawLegacyInteger(t *testing.T, value []byte) rlp.RawValue {
	t.Helper()
	raw, err := rlp.EncodeToBytes(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func baseLegacyRawIntegerTransaction(t *testing.T) *legacyRawIntegerTransaction {
	t.Helper()
	to := common.HexToAddress("0x1234567890123456789012345678901234567890")
	zero := rawLegacyInteger(t, nil)
	one := rawLegacyInteger(t, []byte{1})
	return &legacyRawIntegerTransaction{
		AccountNonce: 1,
		Price:        one,
		GasLimit:     21_000,
		Recipient:    &to,
		Amount:       zero,
		V:            one,
		R:            one,
		S:            one,
	}
}

func TestLegacyTransactionRejects257BitRawIntegers(t *testing.T) {
	overflow := rawLegacyInteger(t, append([]byte{1}, make([]byte, 32)...))
	for _, test := range []struct {
		name   string
		mutate func(*legacyRawIntegerTransaction)
	}{
		{"gasPrice", func(tx *legacyRawIntegerTransaction) { tx.Price = overflow }},
		{"value", func(tx *legacyRawIntegerTransaction) { tx.Amount = overflow }},
		{"v", func(tx *legacyRawIntegerTransaction) { tx.V = overflow }},
		{"r", func(tx *legacyRawIntegerTransaction) { tx.R = overflow }},
		{"s", func(tx *legacyRawIntegerTransaction) { tx.S = overflow }},
	} {
		t.Run(test.name, func(t *testing.T) {
			rawTx := baseLegacyRawIntegerTransaction(t)
			test.mutate(rawTx)
			wire, err := rlp.EncodeToBytes(rawTx)
			if err != nil {
				t.Fatal(err)
			}
			var decoded Transaction
			if err := decoded.UnmarshalBinary(wire); !errors.Is(err, ErrTxIntegerOutOfRange) {
				t.Fatalf("257-bit raw %s error = %v, want %v", test.name, err, ErrTxIntegerOutOfRange)
			}
		})
	}
}

func TestLegacyTransactionRejectsOversizedRawFeeAndSignature(t *testing.T) {
	// Keep the complete raw transaction below the configured 1 MiB transaction
	// ceiling while making the attacked integer large enough to catch any
	// accidental unbounded big.Int decoding.
	oversized := rawLegacyInteger(t, bytes.Repeat([]byte{0xff}, (1<<20)-1024))
	for _, test := range []struct {
		name   string
		mutate func(*legacyRawIntegerTransaction)
	}{
		{"gasPrice", func(tx *legacyRawIntegerTransaction) { tx.Price = oversized }},
		{"signatureR", func(tx *legacyRawIntegerTransaction) { tx.R = oversized }},
	} {
		t.Run(test.name, func(t *testing.T) {
			rawTx := baseLegacyRawIntegerTransaction(t)
			test.mutate(rawTx)
			wire, err := rlp.EncodeToBytes(rawTx)
			if err != nil {
				t.Fatal(err)
			}
			if len(wire) >= 1<<20 {
				t.Fatalf("test transaction size = %d, want below 1 MiB", len(wire))
			}

			var binaryDecoded Transaction
			if err := binaryDecoded.UnmarshalBinary(wire); !errors.Is(err, ErrTxIntegerOutOfRange) {
				t.Fatalf("UnmarshalBinary error = %v, want %v", err, ErrTxIntegerOutOfRange)
			}
			var rlpDecoded Transaction
			if err := rlp.DecodeBytes(wire, &rlpDecoded); !errors.Is(err, ErrTxIntegerOutOfRange) {
				t.Fatalf("DecodeRLP error = %v, want %v", err, ErrTxIntegerOutOfRange)
			}
		})
	}
}

func TestTypedTransactionsRemainCanonicalAfterLegacyIntegerGuard(t *testing.T) {
	to := common.HexToAddress("0x1234567890123456789012345678901234567890")
	tests := []*Transaction{
		NewTx(&AccessListTx{ChainID: big.NewInt(1), GasPrice: big.NewInt(2), Gas: 21_000, To: &to, Value: big.NewInt(3), V: big.NewInt(0), R: big.NewInt(1), S: big.NewInt(2)}),
		NewTx(&DynamicFeeTx{ChainID: big.NewInt(1), GasTipCap: big.NewInt(2), GasFeeCap: big.NewInt(3), Gas: 21_000, To: &to, Value: big.NewInt(4), V: big.NewInt(0), R: big.NewInt(1), S: big.NewInt(2)}),
		NewTx(&BlobTx{ChainID: big.NewInt(1), GasTipCap: big.NewInt(2), GasFeeCap: big.NewInt(3), Gas: 21_000, To: to, Value: big.NewInt(4), BlobFeeCap: big.NewInt(5), V: big.NewInt(0), R: big.NewInt(1), S: big.NewInt(2)}),
		NewTx(&SetCodeTx{ChainID: big.NewInt(1), GasTipCap: big.NewInt(2), GasFeeCap: big.NewInt(3), Gas: 21_000, To: to, Value: big.NewInt(4), V: big.NewInt(0), R: big.NewInt(1), S: big.NewInt(2)}),
	}
	for index, tx := range tests {
		wantType := uint8(index + 1)
		if err := tx.ValidateIntegerBounds(); err != nil {
			t.Fatalf("type %d integer validation failed: %v", wantType, err)
		}
		wire, err := tx.MarshalBinary()
		if err != nil {
			t.Fatalf("type %d marshal failed: %v", wantType, err)
		}
		var decoded Transaction
		if err := decoded.UnmarshalBinary(wire); err != nil {
			t.Fatalf("type %d unmarshal failed: %v", wantType, err)
		}
		roundTrip, err := decoded.MarshalBinary()
		if err != nil {
			t.Fatalf("type %d re-marshal failed: %v", wantType, err)
		}
		if decoded.Type() != wantType || !bytes.Equal(roundTrip, wire) {
			t.Fatalf("type %d canonical envelope changed", wantType)
		}
		if got, want := tx.Hash(), crypto.Keccak256Hash(wire); got != want {
			t.Fatalf("type %d hash = %s, want %s", wantType, got, want)
		}
	}
}
