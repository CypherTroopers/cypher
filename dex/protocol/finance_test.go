package protocol

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestIndependentFinanceGolden(t *testing.T) {
	raw, err := os.ReadFile("../testdata/finance.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Summaries, Deposits []struct{ Encoded, Hash string }
		Trees               []struct {
			Count int
			Root  string
			Paths [][]string
		}
	}
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Summaries) != 2 || len(vectors.Deposits) != 3 || len(vectors.Trees) != 4 {
		t.Fatal("missing independent vectors")
	}
	for _, v := range vectors.Summaries {
		b, _ := hex.DecodeString(v.Encoded)
		f, err := DecodeFinanceSummary(b)
		if err != nil {
			t.Fatal(err)
		}
		h, err := f.Hash()
		if err != nil || hex.EncodeToString(h[:]) != v.Hash {
			t.Fatal("finance hash", err)
		}
		round, _ := f.Encode()
		if !reflect.DeepEqual(round, b) {
			t.Fatal("finance codec")
		}
		if _, err := DecodeFinanceSummary(append(b, 0)); err == nil {
			t.Fatal("finance trailing bytes")
		}
		f.DepositTotal[0] = 1
		if f.Validate() == nil {
			t.Fatal("finance overflow")
		}
	}
	var deposits []Deposit
	var leaves []Hash
	for _, v := range vectors.Deposits {
		b, _ := hex.DecodeString(v.Encoded)
		d, err := DecodeDeposit(b)
		if err != nil {
			t.Fatal(err)
		}
		h, err := d.Hash()
		if err != nil || hex.EncodeToString(h[:]) != v.Hash {
			t.Fatal("deposit hash", err)
		}
		round, _ := d.Encode()
		if !reflect.DeepEqual(round, b) {
			t.Fatal("deposit codec")
		}
		deposits = append(deposits, d)
		leaves = append(leaves, h)
		if _, err := DecodeDeposit(append(b, 0)); err == nil {
			t.Fatal("deposit trailing bytes")
		}
	}
	for _, v := range vectors.Trees {
		root, paths, err := BuildCountedTree(leaves[:v.Count])
		if err != nil || hex.EncodeToString(root[:]) != v.Root {
			t.Fatal("count root", err)
		}
		for i, p := range paths {
			if len(p) != len(v.Paths[i]) {
				t.Fatal("path depth")
			}
			for j, h := range p {
				if hex.EncodeToString(h[:]) != v.Paths[i][j] {
					t.Fatal("path sibling")
				}
			}
			if err := VerifyCountedInclusion(root, leaves[i], uint32(i), uint32(v.Count), p); err != nil {
				t.Fatal(err)
			}
		}
	}
	expected, _, _ := BuildCountedTree(leaves)
	actual, err := DepositInboxRoot(deposits)
	if err != nil || actual != expected {
		t.Fatal("inbox root")
	}
	deposits[1].ID++
	if _, err := DepositInboxRoot(deposits); err == nil {
		t.Fatal("deposit gap accepted")
	}
	root, paths, _ := BuildCountedTree(leaves)
	if VerifyCountedInclusion(root, leaves[0], 0, 4, paths[0]) == nil {
		t.Fatal("count mutation accepted")
	}
	if VerifyCountedInclusion(root, leaves[0], 3, 3, paths[0]) == nil {
		t.Fatal("padded leaf accepted")
	}
	badPadding := append([]Hash(nil), paths[2]...)
	badPadding[0] = Hash{77}
	badBase := MerkleParent(badPadding[1], MerkleParent(leaves[2], badPadding[0]))
	if VerifyCountedInclusion(countedRoot(3, badBase), leaves[2], 2, 3, badPadding) == nil {
		t.Fatal("noncanonical padding admitted by a matching root")
	}
	if _, _, err := BuildCountedTree(make([]Hash, 1025)); err == nil {
		t.Fatal("unbounded tree")
	}
}
