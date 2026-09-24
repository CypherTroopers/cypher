package relay

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/dex/clxevidence"
)

// These vectors test canonical interpretation after MPT authentication. They do
// not create a trusted anchor from unauthenticated RPC words.
func TestDecodeAuthenticatedAnchorWordsV1V2Golden(t *testing.T) {
	raw, err := os.ReadFile("../testdata/key_renewal.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Legacy  struct{ Encoded, ID string } `json:"legacy_anchor"`
		Anchors []struct{ Encoded, ID string }
	}
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	decode := func(encoded string) clxevidence.Anchor {
		b, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		a, err := clxevidence.DecodeAnchor(b)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	words := func(a clxevidence.Anchor) []common.Hash {
		b, err := a.Encode()
		if err != nil {
			t.Fatal(err)
		}
		out := make([]common.Hash, 11)
		for i := range b {
			out[i/32][i%32] = b[i]
		}
		id, err := a.ID()
		if err != nil {
			t.Fatal(err)
		}
		out[9], out[10] = common.Hash(id), common.Hash{1}
		return out
	}
	g := decode(vectors.Legacy.Encoded)
	g.Height = 0
	cases := append([]struct{ Encoded, ID string }{vectors.Legacy}, vectors.Anchors...)
	for i, c := range cases {
		a := decode(c.Encoded)
		w := words(a)
		if hex.EncodeToString(w[9][:]) != c.ID {
			t.Fatal("independent golden anchor ID", i)
		}
		got, found, err := decodeStoredAnchor(w, g, a.Height)
		if err != nil || !found || got != a {
			t.Fatal("canonical authenticated storage", i, err)
		}
		for _, name := range []string{"short", "extra", "partial-id", "partial-data", "missing-evidence", "wrong-id", "padding", "unknown-version", "height", "chain", "genesis", "dex", "custody", "epoch"} {
			t.Run(c.ID[:8]+"/"+name, func(t *testing.T) {
				w := words(a)
				expectHeight := a.Height
				switch name {
				case "short":
					w = w[:10]
				case "extra":
					w = append(w, common.Hash{})
				case "partial-id":
					w[9] = common.Hash{}
				case "partial-data":
					w = make([]common.Hash, 11)
					w[8][0] = 1
				case "missing-evidence":
					w[10] = common.Hash{}
				case "wrong-id":
					w[9][0] ^= 1
				case "padding":
					w[8][31] = 1
				case "unknown-version":
					w[0][1] = 3
				case "height":
					expectHeight++
				case "epoch":
					// Codec rejects non-fixture epochs before ID matching.
					w[7][13] = 2
				default:
					bad := a
					switch name {
					case "chain":
						bad.ChainID++
					case "genesis":
						bad.Genesis[0] ^= 1
					case "dex":
						bad.DEXID[0] ^= 1
					case "custody":
						bad.Custody[0] ^= 1
					}
					w = words(bad)
				}
				if _, found, err := decodeStoredAnchor(w, g, expectHeight); err == nil || found {
					t.Fatal("accepted altered authenticated storage interpretation")
				}
			})
		}
		changed := a
		changed.SourceKeyHash[0] ^= 1
		changed.SourceCommittee[0] ^= 1
		_, found, err = decodeStoredAnchor(words(changed), g, a.Height)
		if a.Version == 1 && (err == nil || found) {
			t.Fatal("legacy static key/committee changed")
		}
		if a.Version == 2 && (err != nil || !found) {
			t.Fatal("v2 authenticated native record rejected after key/order update", err)
		}
	}
	if _, found, err := decodeStoredAnchor(make([]common.Hash, 11), g, 1); err != nil || found {
		t.Fatal("authenticated absence", err)
	}
}
