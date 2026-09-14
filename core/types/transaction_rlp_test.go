package types

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
)

type legacyTxData struct {
	AccountNonce uint64
	Price        *big.Int
	GasLimit     uint64
	Recipient    *common.Address
	Amount       *big.Int
	Payload      []byte
	V            *big.Int
	R            *big.Int
	S            *big.Int
}

func TestDecodeLegacyRLPTransaction(t *testing.T) {
	to := common.HexToAddress("0x1111111111111111111111111111111111111111")
	legacy := legacyTxData{
		AccountNonce: 7,
		Price:        big.NewInt(1_000_000_000),
		GasLimit:     21_000,
		Recipient:    &to,
		Amount:       big.NewInt(12345),
		Payload:      nil,
		V:            big.NewInt(27),
		R:            big.NewInt(1),
		S:            big.NewInt(2),
	}

	blob, err := rlp.EncodeToBytes(&legacy)
	if err != nil {
		t.Fatalf("failed to encode legacy tx: %v", err)
	}

	var tx Transaction
	if err := rlp.DecodeBytes(blob, &tx); err != nil {
		t.Fatalf("failed to decode legacy tx: %v", err)
	}

	if tx.RouteHint() != TxRouteAuto {
		t.Fatalf("unexpected route hint %d", tx.RouteHint())
	}
	if tx.Nonce() != legacy.AccountNonce {
		t.Fatalf("unexpected nonce %d", tx.Nonce())
	}
}

func TestRouteHintDoesNotAffectRLPHash(t *testing.T) {
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	tx := NewTransaction(3, to, big.NewInt(99), 21_000, big.NewInt(1), nil)
	withHint := tx.WithRouteHint(TxRouteFast)

	if tx.Hash() != withHint.Hash() {
		t.Fatalf("route hint should not affect transaction hash")
	}
}

func TestRouteHintJSONRoundTrip(t *testing.T) {
	to := common.HexToAddress("0x3333333333333333333333333333333333333333")
	tx := NewTransaction(4, to, big.NewInt(11), 21_000, big.NewInt(2), []byte{0x1, 0x2}).WithRouteHint(TxRouteSlow)

	raw, err := tx.MarshalJSON()
	if err != nil {
		t.Fatalf("failed to marshal tx: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("failed to decode json payload: %v", err)
	}
	if got, ok := payload["routeHint"].(float64); !ok || got != float64(TxRouteSlow) {
		t.Fatalf("unexpected routeHint in json: %v", payload["routeHint"])
	}

	var dec Transaction
	if err := dec.UnmarshalJSON(raw); err != nil {
		t.Fatalf("failed to unmarshal tx: %v", err)
	}
	if dec.RouteHint() != TxRouteSlow {
		t.Fatalf("unexpected route hint %d", dec.RouteHint())
	}
	if dec.Hash() != tx.Hash() {
		t.Fatalf("json roundtrip changed tx hash")
	}
}

func TestTransactionsByPriceAndNonceRecomputesSignerForCurrentHead(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	chainID := big.NewInt(1337)
	config := *params.TestChainConfig
	config.ChainID = new(big.Int).Set(chainID)
	config.EIP155Block = big.NewInt(10)

	to := common.HexToAddress("0x4444444444444444444444444444444444444444")
	sign := func(tx *Transaction, signer Signer) *Transaction {
		signed, signErr := SignTx(tx, signer, key)
		if signErr != nil {
			t.Fatal(signErr)
		}
		return signed
	}
	transactions := Transactions{
		sign(NewTransaction(0, to, big.NewInt(1), 21_000, big.NewInt(3), nil), HomesteadSigner{}),
		sign(NewTransaction(1, to, big.NewInt(1), 21_000, big.NewInt(3), nil), NewEIP155Signer(chainID)),
		sign(NewTransaction(2, to, big.NewInt(1), 21_000, big.NewInt(3), nil), NewEIP155Signer(chainID)),
	}
	from := crypto.PubkeyToAddress(key.PublicKey)
	ordered := NewTransactionsByPriceAndNonce(&config, big.NewInt(9), map[common.Address]Transactions{
		from: transactions,
	})

	for wantNonce := uint64(0); wantNonce < uint64(len(transactions)); wantNonce++ {
		tx := ordered.Peek()
		if tx == nil {
			t.Fatalf("head is nil, want nonce %d", wantNonce)
		}
		if tx.Nonce() != wantNonce {
			t.Fatalf("head nonce = %d, want %d", tx.Nonce(), wantNonce)
		}
		ordered.Shift()
	}
	if tx := ordered.Peek(); tx != nil {
		t.Fatalf("unexpected transaction after account tail: nonce %d", tx.Nonce())
	}
}

func TestTransactionsByPriceAndNonceCopyHasIndependentCursor(t *testing.T) {
	chainID := big.NewInt(1337)
	config := *params.TestChainConfig
	config.ChainID = new(big.Int).Set(chainID)
	config.EIP155Block = big.NewInt(0)
	to := common.HexToAddress("0x5555555555555555555555555555555555555555")
	accounts := make(map[common.Address]Transactions)
	for account := 0; account < 2; account++ {
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		transactions := make(Transactions, 2)
		for nonce := range transactions {
			unsigned := NewTransaction(uint64(nonce), to, new(big.Int), params.TxGas, big.NewInt(int64(10-account)), nil)
			transactions[nonce], err = SignTx(unsigned, NewEIP155Signer(chainID), key)
			if err != nil {
				t.Fatal(err)
			}
		}
		accounts[crypto.PubkeyToAddress(key.PublicKey)] = transactions
	}
	original := NewTransactionsByPriceAndNonce(&config, big.NewInt(1), accounts)
	clone := original.Copy()
	first := original.Peek()
	if first == nil || clone.Peek() != first {
		t.Fatal("copied cursor did not preserve the original head")
	}
	clone.Shift()
	clone.Pop()
	if original.Peek() != first {
		t.Fatal("mutating copied cursor consumed the original head")
	}
	original.Shift()
	if clone.Peek() == original.Peek() {
		t.Fatal("cursor mutations unexpectedly shared heap state")
	}
}
