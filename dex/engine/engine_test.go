package engine

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/dex/protocol"
)

func fixture(t *testing.T) (*Engine, *State, []*ecdsa.PrivateKey) {
	t.Helper()
	keys := make([]*ecdsa.PrivateKey, 4)
	for i := range keys {
		raw := make([]byte, 32)
		raw[31] = byte(i + 41)
		var err error
		keys[i], err = crypto.ToECDSA(raw)
		if err != nil {
			t.Fatal(err)
		}
	}
	d := protocol.Domain{Version: 1, ChainID: 10101919, Genesis: protocol.Hash{1}, DEXID: protocol.Hash{2}, Epoch: 1, Committee: protocol.Hash{3}}
	config := Config{Domain: d, Custody: [20]byte{19: 240}, Oracle: [20]byte(crypto.PubkeyToAddress(keys[0].PublicKey)), Support: "20000000000000000000", Insurance: "5000000000000000000", CLXHeight: 0, CLXHash: d.Genesis}
	for i := 1; i <= 2; i++ {
		config.Deposits = append(config.Deposits, protocol.Deposit{Version: 1, Domain: d, Custody: config.Custody, ID: uint64(i - 1), Owner: [20]byte(crypto.PubkeyToAddress(keys[i].PublicKey)), Amount: Amount("100000000000000000000"), CLXHash: d.Genesis})
	}
	e, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	s, err := e.Genesis()
	if err != nil {
		t.Fatal(err)
	}
	return e, s, keys
}
func command(e *Engine, s *State, key *ecdsa.PrivateKey, kind uint8) Action {
	owner := [20]byte(crypto.PubkeyToAddress(key.PublicKey))
	nonce := uint64(1)
	if account := s.Accounts[id(owner)]; account != nil {
		nonce = account.Nonce + 1
	}
	return Action{Version: 1, Epoch: e.config.Domain.EpochKey(), Kind: kind, Owner: owner, Nonce: nonce}
}
func apply(t *testing.T, e *Engine, s *State, key *ecdsa.PrivateKey, a Action) (*State, Delta) {
	t.Helper()
	raw, err := Sign(a, key)
	if err != nil {
		t.Fatal(err)
	}
	out, d, err := e.Apply(s, raw, s.Height+1)
	if err != nil {
		t.Fatalf("height %d kind %d: %v", s.Height+1, a.Kind, err)
	}
	return out, d
}
func bootstrap(t *testing.T) (*Engine, *State, []*ecdsa.PrivateKey) {
	e, s, k := fixture(t)
	for i := 1; i <= 2; i++ {
		a := command(e, s, k[i], Credit)
		a.DepositID = uint64(i - 1)
		s, _ = apply(t, e, s, k[i], a)
	}
	a := command(e, s, k[0], Oracle)
	a.Price = Amount("100000000000000000000")
	a.FeedSequence = 1
	a.FundingRate = 100
	a.ValidUntil = 100
	s, _ = apply(t, e, s, k[0], a)
	return e, s, k
}
func order(e *Engine, s *State, key *ecdsa.PrivateKey, oid uint64, side int8, p string, q uint64) Action {
	a := command(e, s, key, Place)
	a.OrderID = oid
	a.Side = side
	a.Price = Amount(p)
	a.Quantity = q
	return a
}

func TestIndependentActionCodecs(t *testing.T) {
	raw, err := os.ReadFile("../testdata/engine.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Codec []struct{ Encoded, Hash string }
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for i, v := range vectors.Codec {
		b, err := hex.DecodeString(v.Encoded)
		if err != nil {
			t.Fatal(err)
		}
		var a Action
		if err := binary.Read(bytes.NewReader(b), binary.BigEndian, &a); err != nil {
			t.Fatal(err)
		}
		got, err := a.Encode()
		if err != nil {
			t.Fatalf("%d %v", i, err)
		}
		h := protocol.Digest("common-dex/action/v1", got)
		if !bytes.Equal(got, b) || hex.EncodeToString(h[:]) != v.Hash {
			t.Fatal("independent codec mismatch")
		}
	}
}
func TestTradeFundingWithdrawIndependentTrace(t *testing.T) {
	e, s, k := bootstrap(t)
	s, _ = apply(t, e, s, k[2], order(e, s, k[2], 1, -1, s.Mark, 100000000))
	s, _ = apply(t, e, s, k[1], order(e, s, k[1], 1, 1, s.Mark, 100000000))
	for s.Height < 9 {
		s, _ = apply(t, e, s, k[0], command(e, s, k[0], Noop))
	}
	s, _ = apply(t, e, s, k[0], command(e, s, k[0], Funding))
	a := command(e, s, k[0], Oracle)
	a.Price = Amount("110000000000000000000")
	a.FeedSequence = 2
	a.FundingRate = 100
	a.ValidUntil = 100
	s, _ = apply(t, e, s, k[0], a)
	s, _ = apply(t, e, s, k[1], order(e, s, k[1], 2, -1, s.Mark, 100000000))
	s, _ = apply(t, e, s, k[2], order(e, s, k[2], 2, 1, s.Mark, 100000000))
	data, _ := os.ReadFile("../testdata/engine.json")
	var expected struct{ Trace map[string]string }
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatal(err)
	}
	alice, bob := id([20]byte(crypto.PubkeyToAddress(k[1].PublicKey))), id([20]byte(crypto.PubkeyToAddress(k[2].PublicKey)))
	if s.Accounts[alice].Cash != expected.Trace["alice_cash_before_withdraw"] || s.Accounts[bob].Cash != expected.Trace["bob_cash"] || s.Fees != expected.Trace["fees"] || s.Dust != expected.Trace["funding_dust"] {
		t.Fatalf("trace mismatch: %+v Alice=%+v Bob=%+v", s, s.Accounts[alice], s.Accounts[bob])
	}
	w := command(e, s, k[1], Withdraw)
	w.Amount = Amount(expected.Trace["withdrawal"])
	w.Recipient = [20]byte(crypto.PubkeyToAddress(k[3].PublicKey))
	s, d := apply(t, e, s, k[1], w)
	if s.Accounts[alice].Cash != expected.Trace["alice_cash_after_withdraw"] || len(d.Withdrawals) != 1 || d.Withdrawals[0].Amount != w.Amount {
		t.Fatal("withdraw reserve mismatch")
	}
	encoded, _ := s.Encode()
	restored, err := e.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	aRoot, _ := s.Root()
	bRoot, _ := restored.Root()
	if aRoot != bRoot {
		t.Fatal("root replay mismatch")
	}
}
func rejected(t *testing.T, e *Engine, s *State, key *ecdsa.PrivateKey, a Action) {
	t.Helper()
	before, _ := s.Encode()
	raw, err := Sign(a, key)
	if err == nil {
		_, _, err = e.Apply(s, raw, s.Height+1)
	}
	if err == nil {
		t.Fatalf("accepted action kind=%d", a.Kind)
	}
	after, _ := s.Encode()
	if !bytes.Equal(before, after) {
		t.Fatal("rejection mutated parent")
	}
}
func TestReplayStaleMarginSelfTradeAndAtomicAmend(t *testing.T) {
	e, s, k := bootstrap(t)
	a := order(e, s, k[1], 1, 1, s.Mark, 100000000)
	s, _ = apply(t, e, s, k[1], a)
	rejected(t, e, s, k[1], a)
	self := order(e, s, k[1], 2, -1, s.Mark, 100000000)
	rejected(t, e, s, k[1], self)
	amend := command(e, s, k[1], Amend)
	amend.OrderID = 1
	amend.Side = 1
	amend.Quantity = 10000000000
	amend.Price = Amount(s.Mark)
	rejected(t, e, s, k[1], amend)
	post := order(e, s, k[2], 1, -1, s.Mark, 100000000)
	post.Flags = PostOnly
	rejected(t, e, s, k[2], post)
	reduce := order(e, s, k[2], 1, -1, s.Mark, 100000000)
	reduce.Flags = ReduceOnly
	rejected(t, e, s, k[2], reduce)
	bad := command(e, s, k[2], Credit)
	bad.DepositID = 0
	rejected(t, e, s, k[2], bad)
	s.ValidUntil = s.Height // authenticated snapshot fixture at freshness boundary
	rejected(t, e, s, k[2], order(e, s, k[2], 1, -1, s.Mark, 100000000))
	cancel := command(e, s, k[1], Cancel)
	cancel.OrderID = 1
	s, _ = apply(t, e, s, k[1], cancel)
	if len(s.Orders) != 0 {
		t.Fatal("stale cancel")
	}
}
func TestSignaturesAndBounds(t *testing.T) {
	e, s, k := bootstrap(t)
	a := command(e, s, k[0], Noop)
	raw, err := Sign(a, k[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []func([]byte) []byte{func(b []byte) []byte { return b[:len(b)-1] }, func(b []byte) []byte { b[20] ^= 1; return b }, func(b []byte) []byte { b[len(b)-1] = 27; return b }, func(b []byte) []byte {
		n := new(big.Int).Sub(crypto.S256().Params().N, new(big.Int).SetBytes(b[ActionSize+32:ActionSize+64]))
		n.FillBytes(b[ActionSize+32 : ActionSize+64])
		return b
	}} {
		bad := mutation(append([]byte(nil), raw...))
		if _, err := Decode(bad); err == nil {
			t.Fatal("accepted malformed signature/action")
		}
	}
	foreign := a
	foreign.Epoch[0] ^= 1
	rejected(t, e, s, k[0], foreign)
	noncanonical, _ := s.Encode()
	noncanonical = append(noncanonical, ' ')
	if _, err := e.Decode(noncanonical); err == nil {
		t.Fatal("noncanonical state")
	}
}

func TestLiquidationActualBookAndInsuranceExhaustion(t *testing.T) {
	for _, price := range []string{"80000000000000000000", "1000000000000000000"} {
		t.Run(price, func(t *testing.T) {
			e, s, k := bootstrap(t)
			s, _ = apply(t, e, s, k[2], order(e, s, k[2], 1, -1, s.Mark, 500000000))
			s, _ = apply(t, e, s, k[1], order(e, s, k[1], 1, 1, s.Mark, 500000000))
			a := command(e, s, k[0], Oracle)
			a.Price = Amount(price)
			a.FeedSequence = 2
			a.ValidUntil = 100
			s, _ = apply(t, e, s, k[0], a)
			liq := command(e, s, k[0], Liquidate)
			liq.Target = [20]byte(crypto.PubkeyToAddress(k[1].PublicKey))
			// No liquidity means no imaginary close and no insurance spending.
			s, d := apply(t, e, s, k[0], liq)
			if position(s.Accounts[id(liq.Target)]) != 500000000 || d.InsuranceUsed != "0" {
				t.Fatal("invented liquidity")
			}
			bid := order(e, s, k[2], 2, 1, price, 500000000)
			bid.Flags = ReduceOnly
			s, _ = apply(t, e, s, k[2], bid)
			liq = command(e, s, k[0], Liquidate)
			liq.Target = [20]byte(crypto.PubkeyToAddress(k[1].PublicKey))
			s, d = apply(t, e, s, k[0], liq)
			if position(s.Accounts[id(liq.Target)]) != 0 || number(d.InsuranceUsed).Sign() <= 0 {
				t.Fatal("liquidation did not close and consume insurance")
			}
			if price == "1000000000000000000" {
				if !s.Frozen || s.Insurance != "0" || number(s.Accounts[id(liq.Target)].Cash).Sign() >= 0 {
					t.Fatal("uncovered debt not frozen")
				}
				w := command(e, s, k[2], Withdraw)
				w.Amount = Amount("1")
				w.Recipient = [20]byte(crypto.PubkeyToAddress(k[2].PublicKey))
				rejected(t, e, s, k[2], w)
			} else if s.Frozen || s.Accounts[id(liq.Target)].Cash != "0" {
				t.Fatal("covered liquidation state")
			}
		})
	}
}

func TestPartialPriceTimeIOCAndRestingMarginRecheck(t *testing.T) {
	e, s, k := bootstrap(t)
	s, _ = apply(t, e, s, k[2], order(e, s, k[2], 1, -1, "101000000000000000000", 100000000))
	s, _ = apply(t, e, s, k[2], order(e, s, k[2], 2, -1, "100000000000000000000", 100000000))
	a := order(e, s, k[1], 1, 1, "101000000000000000000", 150000000)
	a.Flags = IOC
	s, _ = apply(t, e, s, k[1], a)
	if len(s.Orders) != 1 || s.Orders[0].ID != 1 || s.Orders[0].Quantity != 50000000 {
		t.Fatal("price priority or partial fill incorrect")
	}
	alice := s.Accounts[id(a.Owner)]
	if len(alice.Lots) != 2 || alice.Lots[0].Entry != "100000000000000000000" || alice.Lots[1].Quantity != 50000000 {
		t.Fatal("FIFO fills")
	}
	w := command(e, s, k[1], Withdraw)
	w.Amount = Amount("1")
	w.Recipient = a.Owner
	rejected(t, e, s, k[1], w)
	// Increase mark enough that the short maker's old margin is invalid.
	oracle := command(e, s, k[0], Oracle)
	oracle.Price = Amount("300000000000000000000")
	oracle.FeedSequence = 2
	oracle.ValidUntil = 100
	s, _ = apply(t, e, s, k[0], oracle)
	a = order(e, s, k[1], 2, 1, "101000000000000000000", 100000000)
	a.Flags = IOC
	s, _ = apply(t, e, s, k[1], a)
	if len(s.Orders) != 0 || position(s.Accounts[id(a.Owner)]) != 150000000 {
		t.Fatal("resting order bypassed updated risk")
	}
}

func TestPendingFundingCannotEscapeAfterStaleFeed(t *testing.T) {
	e, s, k := bootstrap(t)
	s, _ = apply(t, e, s, k[2], order(e, s, k[2], 1, -1, s.Mark, 100000000))
	s, _ = apply(t, e, s, k[1], order(e, s, k[1], 1, 1, s.Mark, 100000000))
	s, _ = apply(t, e, s, k[2], order(e, s, k[2], 2, -1, s.Mark, 100000))
	s.ValidUntil = 9
	for s.Height < 10 {
		s, _ = apply(t, e, s, k[0], command(e, s, k[0], Noop))
	}
	if s.PendingFunding != 10 {
		t.Fatal("due funding was silently skipped")
	}
	cancel := command(e, s, k[2], Cancel)
	cancel.OrderID = 2
	s, _ = apply(t, e, s, k[2], cancel)
	oracle := command(e, s, k[0], Oracle)
	oracle.Price = Amount("110000000000000000000")
	oracle.FeedSequence = 2
	oracle.FundingRate = 100
	oracle.ValidUntil = 100
	s, _ = apply(t, e, s, k[0], oracle)
	closing := order(e, s, k[1], 2, -1, s.Mark, 100000000)
	closing.Flags = ReduceOnly
	rejected(t, e, s, k[1], closing)
	alice := id([20]byte(crypto.PubkeyToAddress(k[1].PublicKey)))
	bob := id([20]byte(crypto.PubkeyToAddress(k[2].PublicKey)))
	oldA, oldB := s.Accounts[alice].Cash, s.Accounts[bob].Cash
	s, _ = apply(t, e, s, k[0], command(e, s, k[0], Funding))
	data, _ := os.ReadFile("../testdata/engine.json")
	var expected struct {
		Resume struct {
			Height      uint64 `json:"resume_height"`
			Long, Short string
		} `json:"-"`
		Funding map[string]interface{} `json:"funding_resume"`
	}
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatal(err)
	}
	if s.LastFunding != uint64(expected.Funding["resume_height"].(float64)) || s.PendingFunding != 0 || sub(s.Accounts[alice].Cash, oldA) != expected.Funding["long_delta"].(string) || sub(s.Accounts[bob].Cash, oldB) != expected.Funding["short_delta"].(string) {
		t.Fatal("independent pending funding recovery mismatch")
	}
}
