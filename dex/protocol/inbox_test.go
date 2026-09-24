package protocol

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestIndependentInboxGoldenAndMutation(t *testing.T) {
	raw, err := os.ReadFile("../testdata/inbox.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		EntrySize    int    `json:"entry_size"`
		CountSlot    string `json:"count_slot"`
		MarketOracle string `json:"market_oracle"`
		MarketSeed   string `json:"market_seed"`
		Entries      []struct {
			Encoded, Hash, Slot string
			SourceID            string `json:"source_id"`
		}
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	count := InboxCountStorageKey()
	if v.EntrySize != InboxEntrySize || hex.EncodeToString(count[:]) != v.CountSlot {
		t.Fatal("inbox metadata golden")
	}
	var oracle [20]byte
	ob, _ := hex.DecodeString(v.MarketOracle)
	copy(oracle[:], ob)
	seed, err := NativeMarketSeed(oracle)
	if err != nil || hex.EncodeToString(seed[:]) != v.MarketSeed {
		t.Fatal("market seed golden", err)
	}
	if _, err := NativeMarketSeed([20]byte{}); err == nil {
		t.Fatal("zero native oracle")
	}
	for _, entry := range v.Entries {
		b, _ := hex.DecodeString(entry.Encoded)
		e, err := DecodeInboxEntry(b)
		if err != nil {
			t.Fatal(err)
		}
		h, _ := e.Hash()
		source, _ := e.SourceID()
		slot := InboxEntryStorageKey(e.Index)
		if hex.EncodeToString(h[:]) != entry.Hash || hex.EncodeToString(source[:]) != entry.SourceID || hex.EncodeToString(slot[:]) != entry.Slot {
			t.Fatal("independent inbox vector mismatch")
		}
		for _, mutate := range []func(*InboxEntry){func(x *InboxEntry) { x.Sender[0] ^= 1 }, func(x *InboxEntry) { x.Nonce++ }, func(x *InboxEntry) { x.ActionIndex++ }, func(x *InboxEntry) { x.PayloadHash[0] ^= 1 }, func(x *InboxEntry) { x.Owner[0] ^= 1 }, func(x *InboxEntry) { x.Custody[0] ^= 1 }, func(x *InboxEntry) { x.Amount[31] ^= 1 }} {
			x := e
			mutate(&x)
			changed, _ := x.Hash()
			if changed == h {
				t.Fatal("unbound entry mutation")
			}
		}
		for _, bad := range [][]byte{b[:len(b)-1], append(append([]byte(nil), b...), 0)} {
			if _, err := DecodeInboxEntry(bad); err == nil {
				t.Fatal("noncanonical entry accepted")
			}
		}
		x := e
		x.Version = 1
		if _, err = x.Encode(); err == nil {
			t.Fatal("legacy entry accepted")
		}
		x = e
		x.Asset = 1
		if _, err = x.Encode(); err == nil {
			t.Fatal("wrapped/foreign asset accepted")
		}
	}
}
