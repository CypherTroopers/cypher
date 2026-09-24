package protocol

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func historyTestID(n uint64) Hash {
	var h Hash
	binary.BigEndian.PutUint64(h[24:], n)
	return h
}

// Independently generated with Python hashlib and a complete 4096-leaf tree,
// rather than the Go frontier's incremental algorithm.
func TestHistoryIndependentGolden(t *testing.T) {
	vectors := []struct {
		count      int
		root, data string
	}{
		{0, "2d9d2e4a5d2618f5964ecb7537a905605458385cc1c2ed84b824f444c6ed27c3", "4aebd38a3387a45979e14a436923cea711d2765934e93710c684210803613e4a"},
		{1, "1746dd8bbc2f0003dafd17d3a164b66548944543ca1dde02ad9c47748309347e", "46ec832e5f82187bcb0a4948ecf5293b60303312dbcf4fe3860223e23e8d1e7a"},
		{3, "870e77875c85f231b6988044a7756ed06b79bc7e16a34308a95074f984fbc245", "f04ccbf272047d15584d3d71ec507b076f9e43a7025c2632f8be743c215a502e"},
		{4095, "c0887b8280303d4d0773b2c5ffd48c5ba5a666c0780672ee26f093e971b80f8e", "cb9e564e6da34eb7aeecf69566ebb0845f14ff07d5aa0b9fdd1ce2320e60cf5a"},
	}
	for _, v := range vectors {
		var frontier HistoryFrontier
		ids := make([]Hash, v.count)
		for i := range ids {
			ids[i] = historyTestID(uint64(i + 1))
			if err := frontier.AppendQCID(ids[i]); err != nil {
				t.Fatal(err)
			}
		}
		root, err := frontier.Root()
		if err != nil || hex.EncodeToString(root[:]) != v.root {
			t.Fatalf("count%d root%x err%v", v.count, root, err)
		}
		data, err := HistoryDataRoot(historyTestID(17), root, uint64(v.count))
		if err != nil || hex.EncodeToString(data[:]) != v.data {
			t.Fatalf("count%d data%x err%v", v.count, data, err)
		}
		if v.count == 0 {
			continue
		}
		for _, index := range []uint64{0, uint64(v.count / 2), uint64(v.count - 1)} {
			path, err := BuildHistoryProof(ids, index)
			if err != nil {
				t.Fatal(err)
			}
			if err = VerifyHistoryInclusion(root, ids[index], index, uint64(v.count), path); err != nil {
				t.Fatal(err)
			}
			path[0][0] ^= 1
			if VerifyHistoryInclusion(root, ids[index], index, uint64(v.count), path) == nil {
				t.Fatal("modified path accepted")
			}
		}
	}
}

func TestHistoryBoundsAndCanonicalFrontier(t *testing.T) {
	var f HistoryFrontier
	f.Branch[3] = historyTestID(1)
	if _, err := f.Root(); err == nil {
		t.Fatal("unused branch accepted")
	}
	f = HistoryFrontier{Count: 1}
	if _, err := f.Root(); err == nil {
		t.Fatal("missing live branch accepted")
	}
	f = HistoryFrontier{}
	if f.AppendQCID(Hash{}) == nil {
		t.Fatal("zero QC accepted")
	}
	for i := 1; i <= MaxHistoryCount; i++ {
		if err := f.AppendQCID(historyTestID(uint64(i))); err != nil {
			t.Fatal(err)
		}
	}
	before := f
	if f.AppendQCID(historyTestID(4096)) == nil || f != before {
		t.Fatal("capacity changed frontier")
	}
	for _, count := range []uint64{0, 4096, ^uint64(0)} {
		if _, err := HistoryProofRoot(historyTestID(1), 0, count, make([]Hash, 12)); err == nil {
			t.Fatal("count accepted", count)
		}
	}
	if _, err := HistoryProofRoot(historyTestID(1), 1, 1, make([]Hash, 12)); err == nil {
		t.Fatal("index accepted")
	}
	if _, err := HistoryProofRoot(historyTestID(1), 0, 1, make([]Hash, 13)); err == nil {
		t.Fatal("depth accepted")
	}
}
