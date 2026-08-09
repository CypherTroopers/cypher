package types

import (
	"bytes"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto"
)

func TestDelegationHelpers(t *testing.T) {
	address := common.HexToAddress("0x1122334455667788990011223344556677889900")
	delegation := AddressToDelegation(address)
	if len(delegation) != 23 {
		t.Fatalf("delegation length = %d, want 23", len(delegation))
	}
	if !bytes.Equal(delegation[:3], []byte{0xef, 0x01, 0x00}) {
		t.Fatalf("delegation prefix = %x", delegation[:3])
	}
	parsed, ok := ParseDelegation(delegation)
	if !ok || parsed != address {
		t.Fatalf("parsed delegation = (%s, %t), want (%s, true)", parsed, ok, address)
	}

	for _, invalid := range [][]byte{
		nil,
		DelegationPrefix,
		append(append([]byte{}, delegation...), 0),
		append([]byte{0xef, 0x01, 0x01}, delegation[3:]...),
		delegation[:len(delegation)-1],
	} {
		if address, ok := ParseDelegation(invalid); ok {
			t.Fatalf("accepted invalid delegation %x as %s", invalid, address)
		}
	}

	// AddressToDelegation must not return storage backed by the exported prefix.
	delegation[0] = 0
	if DelegationPrefix[0] != 0xef {
		t.Fatalf("AddressToDelegation aliased DelegationPrefix")
	}
}

func TestSetCodeAuthorizationSignAndRecover(t *testing.T) {
	key, err := crypto.HexToECDSA("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	auth := SetCodeAuthorization{
		ChainID: big.NewInt(1),
		Address: common.HexToAddress("0x1122334455667788990011223344556677889900"),
		Nonce:   7,
	}

	// rlp([1, address, 7]) = 0xd7 || 0x01 || 0x94 || address || 0x07.
	raw := []byte{0x05, 0xd7, 0x01, 0x94}
	raw = append(raw, auth.Address[:]...)
	raw = append(raw, 0x07)
	if got, want := auth.SigHash(), crypto.Keccak256Hash(raw); got != want {
		t.Fatalf("authorization sighash = %s, want %s", got, want)
	}

	signed, err := SignSetCode(key, auth)
	if err != nil {
		t.Fatal(err)
	}
	if signed.V == nil || signed.R == nil || signed.S == nil {
		t.Fatal("SignSetCode returned nil signature values")
	}
	if signed.V.Uint64() > 1 {
		t.Fatalf("signature y parity = %d", signed.V.Uint64())
	}
	authority, err := signed.Authority()
	if err != nil {
		t.Fatal(err)
	}
	if want := crypto.PubkeyToAddress(key.PublicKey); authority != want {
		t.Fatalf("authority = %s, want %s", authority, want)
	}

	// The signed result must not alias the unsigned authorization's big.Int.
	signed.ChainID.SetUint64(2)
	if auth.ChainID.Uint64() != 1 {
		t.Fatalf("SignSetCode aliased input ChainID")
	}
}

func TestSetCodeAuthorizationRejectsNonCanonicalSignatures(t *testing.T) {
	key, err := crypto.HexToECDSA("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignSetCode(key, SetCodeAuthorization{
		ChainID: big.NewInt(1),
		Address: common.Address{0x42},
		Nonce:   3,
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []SetCodeAuthorization{
		{ChainID: signed.ChainID, Address: signed.Address, Nonce: signed.Nonce, V: big.NewInt(2), R: signed.R, S: signed.S},
		{ChainID: signed.ChainID, Address: signed.Address, Nonce: signed.Nonce, V: signed.V, R: new(big.Int), S: signed.S},
		{ChainID: signed.ChainID, Address: signed.Address, Nonce: signed.Nonce, V: signed.V, R: signed.R, S: new(big.Int).Sub(crypto.S256().Params().N, signed.S)},
		{ChainID: signed.ChainID, Address: signed.Address, Nonce: signed.Nonce, V: nil, R: signed.R, S: signed.S},
	}
	for i := range tests {
		if authority, err := tests[i].Authority(); err == nil {
			t.Fatalf("invalid signature %d recovered %s", i, authority)
		}
	}
}

func TestSetCodeTransactionAuthorizationAccessors(t *testing.T) {
	key1, err := crypto.HexToECDSA("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	key2, err := crypto.HexToECDSA("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	if err != nil {
		t.Fatal(err)
	}
	auth1, err := SignSetCode(key1, SetCodeAuthorization{ChainID: big.NewInt(1), Address: common.Address{1}, Nonce: 0})
	if err != nil {
		t.Fatal(err)
	}
	auth2, err := SignSetCode(key2, SetCodeAuthorization{ChainID: big.NewInt(1), Address: common.Address{2}, Nonce: 0})
	if err != nil {
		t.Fatal(err)
	}
	invalid := auth1
	invalid.V = big.NewInt(2)
	tx := &Transaction{data: &SetCodeTx{AuthList: []SetCodeAuthorization{auth1, auth1, invalid, auth2}}}

	copied := tx.SetCodeAuthorizations()
	if len(copied) != 4 {
		t.Fatalf("authorization count = %d, want 4", len(copied))
	}
	copied[0].ChainID.SetUint64(99)
	copied[0].R.SetUint64(0)
	original := tx.data.(*SetCodeTx).AuthList[0]
	if original.ChainID.Uint64() != 1 || original.R.Sign() == 0 {
		t.Fatal("SetCodeAuthorizations returned aliased big.Int fields")
	}

	got := tx.SetCodeAuthorities()
	want := []common.Address{crypto.PubkeyToAddress(key1.PublicKey), crypto.PubkeyToAddress(key2.PublicKey)}
	if len(got) != len(want) {
		t.Fatalf("authority count = %d, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("authority %d = %s, want %s", i, got[i], want[i])
		}
	}

	if (&Transaction{}).SetCodeAuthorizations() != nil || (&Transaction{}).SetCodeAuthorities() != nil {
		t.Fatal("non-set-code transaction returned authorizations")
	}
}

func TestSetCodeAsMessagePreservesTypeAndAuthorizations(t *testing.T) {
	key, err := crypto.HexToECDSA("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	auth, err := SignSetCode(key, SetCodeAuthorization{
		ChainID: big.NewInt(1),
		Address: common.HexToAddress("0x1234"),
		Nonce:   7,
	})
	if err != nil {
		t.Fatal(err)
	}
	tx := NewTx(&SetCodeTx{
		ChainID:   big.NewInt(1),
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1),
		Gas:       100_000,
		To:        common.HexToAddress("0xabcd"),
		Value:     new(big.Int),
		AuthList:  []SetCodeAuthorization{auth},
	})
	tx, err = SignTx(tx, NewPragueSigner(big.NewInt(1)), key)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := tx.AsMessage(NewPragueSigner(big.NewInt(1)))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type() != SetCodeTxType {
		t.Fatalf("message type = %d, want %d", msg.Type(), SetCodeTxType)
	}
	got := msg.SetCodeAuthorizations()
	if len(got) != 1 || got[0].Address != auth.Address || got[0].Nonce != auth.Nonce {
		t.Fatalf("message authorizations = %#v, want %#v", got, []SetCodeAuthorization{auth})
	}
	got[0].ChainID.SetUint64(99)
	if msg.SetCodeAuthorizations()[0].ChainID.Uint64() != 1 {
		t.Fatal("message authorization accessor returned aliased data")
	}
}

func TestSetCodeTransactionJSONRoundTripPreservesAuthority(t *testing.T) {
	authorityKey, err := crypto.HexToECDSA("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	if err != nil {
		t.Fatal(err)
	}
	txKey, err := crypto.HexToECDSA("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	auth, err := SignSetCode(authorityKey, SetCodeAuthorization{
		ChainID: big.NewInt(1),
		Address: common.HexToAddress("0x7702"),
		Nonce:   3,
	})
	if err != nil {
		t.Fatal(err)
	}
	tx := NewTx(&SetCodeTx{
		ChainID:   big.NewInt(1),
		Nonce:     9,
		GasTipCap: big.NewInt(2),
		GasFeeCap: big.NewInt(10),
		Gas:       100_000,
		To:        common.HexToAddress("0x1234"),
		Value:     new(big.Int),
		AuthList:  []SetCodeAuthorization{auth},
	})
	tx, err = SignTx(tx, NewPragueSigner(big.NewInt(1)), txKey)
	if err != nil {
		t.Fatal(err)
	}
	wantHash := tx.Hash()
	wantAuthority := crypto.PubkeyToAddress(authorityKey.PublicKey)

	encoded, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		AuthorizationList []map[string]interface{} `json:"authorizationList"`
	}
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	if len(wire.AuthorizationList) != 1 {
		t.Fatalf("authorizationList length = %d, want 1: %s", len(wire.AuthorizationList), encoded)
	}
	for _, field := range []string{"chainId", "address", "nonce", "yParity", "r", "s"} {
		if _, ok := wire.AuthorizationList[0][field]; !ok {
			t.Fatalf("authorization JSON missing %q: %s", field, encoded)
		}
	}

	var decoded Transaction
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	got := decoded.SetCodeAuthorizations()
	if len(got) != 1 {
		t.Fatalf("decoded authorization count = %d, want 1", len(got))
	}
	gotAuthority, err := got[0].Authority()
	if err != nil {
		t.Fatalf("decoded authorization signature is invalid: %v", err)
	}
	if gotAuthority != wantAuthority {
		t.Fatalf("decoded authority = %s, want %s", gotAuthority, wantAuthority)
	}
	if decoded.Hash() != wantHash {
		t.Fatalf("transaction hash changed across JSON: got %s, want %s", decoded.Hash(), wantHash)
	}
}
