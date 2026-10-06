package types

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto"
)

func TestTypedTransactionJSONYParity(t *testing.T) {
	to := common.HexToAddress("0x1234")
	tests := []struct {
		name string
		tx   *Transaction
	}{
		{"access-list", NewTx(&AccessListTx{ChainID: big.NewInt(1), To: &to, Value: new(big.Int), GasPrice: big.NewInt(1), V: new(big.Int), R: new(big.Int), S: new(big.Int)})},
		{"dynamic-fee", NewTx(&DynamicFeeTx{ChainID: big.NewInt(1), To: &to, Value: new(big.Int), GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2), V: new(big.Int), R: new(big.Int), S: new(big.Int)})},
		{"blob", NewTx(&BlobTx{ChainID: big.NewInt(1), To: to, Value: new(big.Int), GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2), BlobFeeCap: big.NewInt(1), V: new(big.Int), R: new(big.Int), S: new(big.Int)})},
		{"set-code", NewTx(&SetCodeTx{ChainID: big.NewInt(1), To: to, Value: new(big.Int), GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2), V: new(big.Int), R: new(big.Int), S: new(big.Int)})},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := json.Marshal(test.tx)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatal(err)
			}
			if string(fields["yParity"]) != `"0x0"` {
				t.Fatalf("yParity = %s, want 0x0", fields["yParity"])
			}
			if string(fields["accessList"]) != `[]` {
				t.Fatalf("accessList = %s, want []", fields["accessList"])
			}

			// yParity is the canonical field, so decoding must not require the
			// deprecated v alias.
			delete(fields, "v")
			yParityOnly, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			var decoded Transaction
			if err := json.Unmarshal(yParityOnly, &decoded); err != nil {
				t.Fatalf("yParity-only JSON rejected: %v", err)
			}
			if decoded.V().Sign() != 0 {
				t.Fatalf("decoded parity = %v, want 0", decoded.V())
			}

			fields["v"] = json.RawMessage(`"0x1"`)
			mismatch, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(mismatch, new(Transaction)); err == nil {
				t.Fatal("mismatched v and yParity accepted")
			}

			delete(fields, "v")
			fields["yParity"] = json.RawMessage(`"0x2"`)
			invalidParity, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(invalidParity, new(Transaction)); err == nil {
				t.Fatal("out-of-range yParity accepted")
			}

			delete(fields, "yParity")
			missingParity, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(missingParity, new(Transaction)); err == nil {
				t.Fatal("typed transaction without yParity or v accepted")
			}
		})
	}
}

func TestSignedTypedTransactionJSONYParityRoundTrip(t *testing.T) {
	chainID := big.NewInt(1)
	to := common.HexToAddress("0x1234")
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	unsigned := NewTx(&DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     7,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(2),
		Gas:       21_000,
		To:        &to,
		Value:     big.NewInt(3),
	})
	signed, err := SignTx(unsigned, NewPragueSigner(chainID), key)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "v")
	yParityOnly, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Transaction
	if err := json.Unmarshal(yParityOnly, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Hash() != signed.Hash() {
		t.Fatalf("signed typed transaction hash changed: have %s want %s", decoded.Hash(), signed.Hash())
	}
	if _, err := Sender(NewPragueSigner(chainID), &decoded); err != nil {
		t.Fatalf("decoded signed transaction cannot recover sender: %v", err)
	}
}

func TestLegacyTransactionJSONOmitsYParity(t *testing.T) {
	tx := NewTransaction(0, common.HexToAddress("0x1234"), new(big.Int), 21_000, big.NewInt(1), nil)
	encoded, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if _, exists := fields["yParity"]; exists {
		t.Fatal("legacy transaction unexpectedly contains yParity")
	}
	if _, exists := fields["accessList"]; exists {
		t.Fatal("legacy transaction unexpectedly contains accessList")
	}
}
