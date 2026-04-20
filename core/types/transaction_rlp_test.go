package types

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
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
