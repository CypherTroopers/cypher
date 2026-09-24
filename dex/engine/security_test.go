package engine

import (
	"bytes"
	"testing"

	"github.com/cypherium/cypher/crypto"
)

func TestLiquidationTickCollarNeverRoundsAgainstVictim(t *testing.T) {
	for _, tc := range []struct {
		mark, bid string
		fills     bool
	}{
		{"2000", "1000", false}, // A 50% worse bid is outside the 5% collar.
		{"1000", "1000", true},  // The minimum valid tick must remain liquidatable.
	} {
		t.Run(tc.mark, func(t *testing.T) {
			e, s, k := bootstrap(t)
			s, _ = apply(t, e, s, k[2], order(e, s, k[2], 1, -1, s.Mark, 500000000))
			s, _ = apply(t, e, s, k[1], order(e, s, k[1], 1, 1, s.Mark, 500000000))
			o := command(e, s, k[0], Oracle)
			o.Price = Amount(tc.mark)
			o.FeedSequence = 2
			o.ValidUntil = 100
			s, _ = apply(t, e, s, k[0], o)
			bid := order(e, s, k[2], 2, 1, tc.bid, 500000000)
			bid.Flags = ReduceOnly
			s, _ = apply(t, e, s, k[2], bid)
			liq := command(e, s, k[0], Liquidate)
			liq.Target = [20]byte(crypto.PubkeyToAddress(k[1].PublicKey))
			parent, _ := s.Encode()
			out, d := apply(t, e, s, k[0], liq)
			after, _ := s.Encode()
			if !bytes.Equal(parent, after) {
				t.Fatal("liquidation mutated input")
			}
			closed := position(out.Accounts[id(liq.Target)]) == 0
			if closed != tc.fills {
				t.Fatalf("collar fill=%v, want %v", closed, tc.fills)
			}
			if !tc.fills && d.InsuranceUsed != "0" {
				t.Fatal("unfilled liquidation spent insurance")
			}
		})
	}
}

func TestEngineRejectsMismatchedDepositAnchorHeight(t *testing.T) {
	e, _, _ := fixture(t)
	c := e.config
	c.CLXHeight++ // The hash authenticates one exact height, not any lower one.
	if _, err := New(c); err == nil {
		t.Fatal("same hash accepted at a different inclusion height")
	}
}

func TestApplyRejectsAbsentParent(t *testing.T) {
	e, _, _ := fixture(t)
	if _, _, err := e.Apply(nil, nil, 1); err == nil {
		t.Fatal("nil parent accepted")
	}
}
