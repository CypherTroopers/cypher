package types

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"math"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
)

func TestHeaderJSONPreservesModernFields(t *testing.T) {
	original := &Header{
		Difficulty:       big.NewInt(1),
		Number:           big.NewInt(2),
		Extra:            []byte{},
		WithdrawalsHash:  common.HexToHash("0x01"),
		BlobGasUsed:      2,
		ExcessBlobGas:    3,
		ParentBeaconRoot: common.HexToHash("0x04"),
		RequestsHash:     common.HexToHash("0x05"),
	}
	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Header
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.WithdrawalsHash != original.WithdrawalsHash ||
		decoded.BlobGasUsed != original.BlobGasUsed ||
		decoded.ExcessBlobGas != original.ExcessBlobGas ||
		decoded.ParentBeaconRoot != original.ParentBeaconRoot ||
		decoded.RequestsHash != original.RequestsHash {
		t.Fatalf("modern fields changed across JSON round trip: got %#v", decoded)
	}
}

func TestHeaderFHSSlotEnvelope(t *testing.T) {
	for _, slot := range []uint64{0, 1, 2, 3, 4, 1_700_000_000*4 + 3, math.MaxUint64} {
		header := &Header{Extra: []byte("old extra")}
		header.SetFHSSlot(slot)
		if header.Time != slot/4 || len(header.Extra) != 12 || !bytes.Equal(header.Extra[:4], []byte{'F', 'H', 'S', 1}) || binary.BigEndian.Uint64(header.Extra[4:]) != slot {
			t.Fatalf("slot %d has noncanonical encoding: time %d extra %x", slot, header.Time, header.Extra)
		}
		if got, err := header.FHSSlot(); err != nil || got != slot {
			t.Fatalf("slot %d decoded as %d: %v", slot, got, err)
		}
		copied := CopyHeader(header)
		copied.Extra[11] ^= 1
		if binary.BigEndian.Uint64(header.Extra[4:]) != slot {
			t.Fatalf("copy mutated original slot %d", slot)
		}
	}

	var missing *Header
	if _, err := missing.FHSSlot(); err == nil {
		t.Fatal("nil header accepted as a slot header")
	}
	valid := new(Header)
	valid.SetFHSSlot(1_700_000_000 * 4)
	for _, test := range []struct {
		name   string
		mutate func(*Header)
	}{
		{"missing", func(h *Header) { h.Extra = nil }},
		{"short", func(h *Header) { h.Extra = h.Extra[:11] }},
		{"long", func(h *Header) { h.Extra = append(h.Extra, 0) }},
		{"marker", func(h *Header) { h.Extra[0] ^= 1 }},
		{"version", func(h *Header) { h.Extra[3]++ }},
		{"seconds", func(h *Header) { h.Time++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			header := CopyHeader(valid)
			test.mutate(header)
			if _, err := header.FHSSlot(); err == nil {
				t.Fatalf("malformed slot header accepted: time %d extra %x", header.Time, header.Extra)
			}
		})
	}
}

func TestHeaderJSONFHSSlotAndKeyInfoRoundTrip(t *testing.T) {
	original := &Header{
		Difficulty:            big.NewInt(1),
		Number:                big.NewInt(2),
		BaseFee:               big.NewInt(800_000_000),
		BlockType:             Key_Block,
		KeyInfo:               []byte{0x01, 0x02, 0x03},
		CommonTxAdmissionRoot: common.HexToHash("0x04"),
		CommonTxRewardRoot:    common.HexToHash("0x05"),
	}
	original.SetFHSSlot(1_700_000_000*4 + 2)
	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Header
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Hash() != original.Hash() || !bytes.Equal(decoded.KeyInfo, original.KeyInfo) || !bytes.Equal(decoded.Extra, original.Extra) {
		t.Fatal("header JSON changed hash-covered slot or key info")
	}
	if got, err := decoded.FHSSlot(); err != nil || got != 1_700_000_000*4+2 {
		t.Fatalf("JSON slot = %d: %v", got, err)
	}

	// Older JSON omitted keyInfo. Reusing a receiver must not retain key data
	// from an earlier key carrier after decoding an ordinary legacy header.
	legacy := CopyHeader(original)
	legacy.KeyInfo = nil
	encoded, err = json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.KeyInfo) != 0 || decoded.Hash() != legacy.Hash() {
		t.Fatal("legacy header JSON retained stale key info")
	}
}
