package protocol

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestIndependentCheckpointGolden(t *testing.T) {
	data, err := os.ReadFile("../testdata/checkpoint.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Vectors []struct {
			Name, Encoded, Hash string
			EpochKey            string `json:"epoch_key"`
		}
	}
	if err := json.Unmarshal(data, &golden); err != nil {
		t.Fatal(err)
	}
	if len(golden.Vectors) != 2 {
		t.Fatal("missing golden vectors")
	}
	for _, v := range golden.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			raw, err := hex.DecodeString(v.Encoded)
			if err != nil {
				t.Fatal(err)
			}
			c, err := DecodeCheckpoint(raw)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := c.Encode()
			if err != nil || !bytes.Equal(raw, encoded) {
				t.Fatalf("canonical roundtrip: %v", err)
			}
			h, err := c.Hash()
			if err != nil || hex.EncodeToString(h[:]) != v.Hash {
				t.Fatalf("hash mismatch: %x %v", h, err)
			}
			epoch := c.Domain().EpochKey()
			if hex.EncodeToString(epoch[:]) != v.EpochKey {
				t.Fatalf("epoch mismatch: %x", epoch)
			}
			if c.ChainID != 10101919 || c.FirstBlock != 1 || c.LastBlock != 3 || c.InboxStart != 0 || c.InboxEnd != 2 {
				t.Fatal("field order mismatch")
			}
			for _, bad := range [][]byte{nil, raw[:len(raw)-1], append(append([]byte(nil), raw...), 0)} {
				if _, err := DecodeCheckpoint(bad); err == nil {
					t.Fatal("accepted noncanonical length")
				}
			}
			for _, offset := range []int{0, 2, len(raw) - 1} {
				bad := append([]byte(nil), raw...)
				bad[offset] = 255
				if _, err := DecodeCheckpoint(bad); err == nil {
					t.Fatalf("accepted unsupported mode at %d", offset)
				}
			}
		})
	}
}

func TestEveryDomainComponentSeparatesEpoch(t *testing.T) {
	d := Domain{Version: 1, ChainID: 1, Genesis: Hash{1}, DEXID: Hash{2}, Epoch: 1, Committee: Hash{3}}
	want := d.EpochKey()
	variants := []Domain{d, d, d, d, d, d}
	variants[0].Version++
	variants[1].ChainID++
	variants[2].Genesis[0]++
	variants[3].DEXID[0]++
	variants[4].Epoch++
	variants[5].Committee[0]++
	for i, v := range variants {
		if v.EpochKey() == want {
			t.Fatalf("domain component %d omitted", i)
		}
	}
}

func FuzzDecodeCheckpoint(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, CheckpointSize))
	data, err := os.ReadFile("../testdata/checkpoint.json")
	if err != nil {
		f.Fatal(err)
	}
	var golden struct{ Vectors []struct{ Encoded string } }
	if err := json.Unmarshal(data, &golden); err != nil {
		f.Fatal(err)
	}
	for _, v := range golden.Vectors {
		b, err := hex.DecodeString(v.Encoded)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := DecodeCheckpoint(data)
		if err != nil {
			return
		}
		encoded, err := c.Encode()
		if err != nil || !bytes.Equal(encoded, data) {
			t.Fatal("accepted noncanonical encoding")
		}
	})
}
