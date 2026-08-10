// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package ccse

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestEncoderPrimitiveVector(t *testing.T) {
	encoded, err := Marshal(1024, func(e *Encoder) {
		e.Bool(true)
		e.Bool(false)
		e.Uint32(0x01020304)
		e.Uint64(0x0102030405060708)
		e.Int64(-2)
		e.Bytes([]byte{0xaa, 0xbb})
		e.String("CPH")
		e.OptionalString(false, "")
		e.OptionalString(true, "")
	})
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString("0100010203040102030405060708fffffffffffffffe00000002aabb00000003435048000100000000")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("primitive vector mismatch\n got %x\nwant %x", encoded, want)
	}
}

func TestEncoderPresenceIsDistinctFromDefault(t *testing.T) {
	absent, err := Marshal(64, func(e *Encoder) { e.OptionalString(false, "") })
	if err != nil {
		t.Fatal(err)
	}
	present, err := Marshal(64, func(e *Encoder) { e.OptionalString(true, "") })
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(absent, present) {
		t.Fatal("absent and present-empty projections are identical")
	}
	if _, err := Marshal(64, func(e *Encoder) { e.OptionalString(false, "hidden") }); !errors.Is(err, ErrNonCanonicalAbsent) {
		t.Fatalf("absent retained value: got %v", err)
	}
}

func TestEncoderRejectsInvalidUnicode(t *testing.T) {
	if UnicodeNormalizationVersion != "15.0.0" {
		t.Fatalf("Unicode normalization tables = %s, want 15.0.0", UnicodeNormalizationVersion)
	}
	tests := []struct {
		name  string
		value string
		want  error
	}{
		{name: "invalid UTF-8", value: string([]byte{0xff}), want: ErrInvalidUTF8},
		{name: "non-NFC", value: "e\u0301", want: ErrNonNFCString},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Marshal(64, func(e *Encoder) { e.String(test.value) })
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
	if _, err := Marshal(64, func(e *Encoder) { e.String("é") }); err != nil {
		t.Fatalf("NFC string rejected: %v", err)
	}
}

func TestEncoderSetOrderAndListOrder(t *testing.T) {
	setA, err := Marshal(1024, func(e *Encoder) { e.StringSet([]string{"miner", "agent", "buyer"}) })
	if err != nil {
		t.Fatal(err)
	}
	setB, err := Marshal(1024, func(e *Encoder) { e.StringSet([]string{"buyer", "miner", "agent"}) })
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(setA, setB) {
		t.Fatalf("set permutation changed encoding\n%x\n%x", setA, setB)
	}
	if _, err := Marshal(1024, func(e *Encoder) { e.StringSet([]string{"agent", "agent"}) }); !errors.Is(err, ErrDuplicateSetValue) {
		t.Fatalf("duplicate set member: got %v", err)
	}

	first := [][]byte{{1}, {2}}
	second := [][]byte{{2}, {1}}
	listA, err := Marshal(1024, func(e *Encoder) { e.EncodedList(first) })
	if err != nil {
		t.Fatal(err)
	}
	listB, err := Marshal(1024, func(e *Encoder) { e.EncodedList(second) })
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(listA, listB) {
		t.Fatal("ordered-list permutation did not change encoding")
	}
}

func TestEncoderBounds(t *testing.T) {
	if _, err := Marshal(-1, func(e *Encoder) { e.String("x") }); !errors.Is(err, ErrInvalidLimits) {
		t.Fatalf("negative limit: got %v", err)
	}
	if _, err := Marshal(4, func(e *Encoder) { e.String("x") }); !errors.Is(err, ErrProjectionTooLarge) {
		t.Fatalf("oversize projection: got %v", err)
	}
	if _, err := Marshal(32, func(e *Encoder) { e.FixedBytes([]byte{1}, 2) }); err == nil {
		t.Fatal("wrong fixed width was accepted")
	}
}

func FuzzEncoderString(f *testing.F) {
	f.Add("CPH")
	f.Add("é")
	f.Add("e\u0301")
	f.Add(string([]byte{0xff}))
	f.Fuzz(func(t *testing.T, value string) {
		encoded, err := Marshal(4096, func(e *Encoder) { e.String(value) })
		if err == nil && len(encoded) < 4 {
			t.Fatalf("accepted string lacks length prefix: %x", encoded)
		}
	})
}
