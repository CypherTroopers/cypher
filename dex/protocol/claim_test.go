package protocol

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestIndependentClaimGolden(t *testing.T) {
	raw, err := os.ReadFile("../testdata/claims.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Leaves []struct{ Encoded, Hash, Nullifier string }
		Root   string
	}
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	if len(golden.Leaves) != 2 {
		t.Fatal("missing claims")
	}
	var hashes []Hash
	var claims []Claim
	for _, v := range golden.Leaves {
		b, err := hex.DecodeString(v.Encoded)
		if err != nil {
			t.Fatal(err)
		}
		c, err := DecodeClaim(b)
		if err != nil {
			t.Fatal(err)
		}
		h, err := c.Hash()
		if err != nil || hex.EncodeToString(h[:]) != v.Hash {
			t.Fatal("claim hash mismatch", err)
		}
		n, err := c.Nullifier()
		if err != nil || hex.EncodeToString(n[:]) != v.Nullifier {
			t.Fatal("nullifier mismatch", err)
		}
		b, err = c.Encode()
		if err != nil || hex.EncodeToString(b) != v.Encoded {
			t.Fatal("codec mismatch", err)
		}
		claims = append(claims, c)
		hashes = append(hashes, h)
	}
	root := MerkleParent(hashes[0], hashes[1])
	if hex.EncodeToString(root[:]) != golden.Root {
		t.Fatal("tree hash mismatch")
	}
	for i := range claims {
		if err := VerifyInclusion(root, hashes[i], uint32(i), []Hash{hashes[1-i]}); err != nil {
			t.Fatal(err)
		}
		mutations := []Claim{claims[i], claims[i], claims[i], claims[i], claims[i], claims[i]}
		mutations[0].Owner[0] ^= 1
		mutations[1].Recipient[0] ^= 1
		mutations[2].Amount[31] ^= 1
		mutations[3].Domain.DEXID[0] ^= 1
		mutations[4].Sequence++
		mutations[5].Domain.Epoch++
		for j, m := range mutations {
			h, err := m.Hash()
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyInclusion(root, h, uint32(i), []Hash{hashes[1-i]}); err == nil {
				t.Fatalf("mutated field %d included", j)
			}
		}
		original, _ := claims[i].Nullifier()
		for _, j := range []int{0, 1, 2, 4, 5} {
			n, _ := mutations[j].Nullifier()
			if n != original {
				t.Fatalf("duplicate ID can split nullifier through mutation %d", j)
			}
		}
		other, _ := mutations[3].Nullifier()
		if other == original {
			t.Fatal("foreign DEX reused nullifier")
		}
	}
	if err := VerifyInclusion(root, hashes[0], 2, []Hash{hashes[1]}); err == nil {
		t.Fatal("unused index bits accepted")
	}
	if err := VerifyInclusion(root, hashes[0], 0, make([]Hash, 33)); err == nil {
		t.Fatal("unbounded proof accepted")
	}
	if err := VerifyInclusion(hashes[0], hashes[0], 0, nil); err != nil {
		t.Fatal("single-leaf proof", err)
	}
	if _, err := DecodeClaim(append(raw, 0)); err == nil {
		t.Fatal("invalid length accepted")
	}
	bad := claims[0]
	bad.Asset = 1
	if _, err := bad.Hash(); err == nil {
		t.Fatal("wrapped/other asset accepted")
	}
}
