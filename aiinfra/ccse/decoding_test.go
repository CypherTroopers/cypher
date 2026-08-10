// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package ccse

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"testing"
)

func TestDecoderPrimitiveRoundTrip(t *testing.T) {
	fixed := []byte{0xde, 0xad, 0xbe, 0xef}
	optionalBytes := []byte{0xaa, 0xbb}
	encoded, err := Marshal(1024, func(out *Encoder) {
		out.Bool(true)
		out.Bool(false)
		out.Uint32(0x01020304)
		out.Uint64(0x0102030405060708)
		out.Int64(-2)
		out.Bytes([]byte{0x10, 0x20, 0x30})
		out.FixedBytes(fixed, len(fixed))
		out.String("é")
		out.OptionalString(false, "")
		out.OptionalString(true, "")
		out.OptionalBytes(true, optionalBytes)
		out.OptionalFixedBytes(false, nil, 4)
		out.OptionalFixedBytes(true, fixed, len(fixed))
		out.Bool(true)
		out.Int64(math.MinInt64)
	})
	if err != nil {
		t.Fatal(err)
	}

	decoder := NewDecoder(encoded, len(encoded))
	assertBool(t, decoder, true)
	assertBool(t, decoder, false)
	if value, err := decoder.Uint32(); err != nil || value != 0x01020304 {
		t.Fatalf("uint32 = %#x, %v", value, err)
	}
	if value, err := decoder.Uint64(); err != nil || value != 0x0102030405060708 {
		t.Fatalf("uint64 = %#x, %v", value, err)
	}
	if value, err := decoder.Int64(); err != nil || value != -2 {
		t.Fatalf("int64 = %d, %v", value, err)
	}
	if value, err := decoder.Bytes(3); err != nil || !bytes.Equal(value, []byte{0x10, 0x20, 0x30}) {
		t.Fatalf("bytes = %x, %v", value, err)
	}
	if value, err := decoder.FixedBytes(len(fixed)); err != nil || !bytes.Equal(value, fixed) {
		t.Fatalf("fixed bytes = %x, %v", value, err)
	}
	if value, err := decoder.String(2); err != nil || value != "é" {
		t.Fatalf("string = %q, %v", value, err)
	}
	if present, value, err := decoder.OptionalString(16); err != nil || present || value != "" {
		t.Fatalf("absent string = (%t, %q), %v", present, value, err)
	}
	if present, value, err := decoder.OptionalString(16); err != nil || !present || value != "" {
		t.Fatalf("present empty string = (%t, %q), %v", present, value, err)
	}
	if present, value, err := decoder.OptionalBytes(2); err != nil || !present || !bytes.Equal(value, optionalBytes) {
		t.Fatalf("optional bytes = (%t, %x), %v", present, value, err)
	}
	if present, value, err := decoder.OptionalFixedBytes(4); err != nil || present || value != nil {
		t.Fatalf("absent fixed bytes = (%t, %x), %v", present, value, err)
	}
	if present, value, err := decoder.OptionalFixedBytes(4); err != nil || !present || !bytes.Equal(value, fixed) {
		t.Fatalf("present fixed bytes = (%t, %x), %v", present, value, err)
	}
	if present, err := decoder.Presence(); err != nil || !present {
		t.Fatalf("presence = %t, %v", present, err)
	}
	if value, err := decoder.Int64(); err != nil || value != math.MinInt64 {
		t.Fatalf("minimum int64 = %d, %v", value, err)
	}
	if !decoder.EOF() {
		t.Fatal("decoder did not report exact EOF")
	}
	if err := decoder.Finish(); err != nil {
		t.Fatalf("finish: %v", err)
	}
}

func TestUnmarshalRequiresExactConsumption(t *testing.T) {
	encoded, err := Marshal(16, func(out *Encoder) {
		out.Bool(true)
		out.Uint32(7)
	})
	if err != nil {
		t.Fatal(err)
	}
	var decoded bool
	if err := Unmarshal(encoded, len(encoded), func(in *Decoder) error {
		var err error
		decoded, err = in.Bool()
		if err != nil {
			return err
		}
		value, err := in.Uint32()
		if err != nil {
			return err
		}
		if value != 7 {
			t.Fatalf("uint32 = %d", value)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !decoded {
		t.Fatal("boolean was not decoded")
	}

	if err := Unmarshal(encoded, len(encoded), func(in *Decoder) error {
		_, err := in.Bool()
		return err
	}); !errors.Is(err, ErrTrailingData) {
		t.Fatalf("partial decode = %v", err)
	}
	if err := Unmarshal([]byte{2}, 1, func(in *Decoder) error {
		_, _ = in.Bool() // Finish must retain an ignored primitive error.
		return nil
	}); !errors.Is(err, ErrInvalidBoolean) {
		t.Fatalf("ignored primitive error = %v", err)
	}
	if err := Unmarshal(nil, 1, nil); err == nil {
		t.Fatal("nil decoder projection was accepted")
	}
}

func TestDecoderConstructorBoundsAndNilReceiver(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		limit int
		want  error
	}{
		{name: "negative", limit: -1, want: ErrInvalidLimits},
		{name: "default limit", input: []byte{0}, limit: 0, want: nil},
		{name: "one over explicit", input: []byte{0, 1}, limit: 1, want: ErrProjectionTooLarge},
		{name: "exact explicit", input: []byte{1}, limit: 1, want: nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decoder := NewDecoder(test.input, test.limit)
			if test.want != nil {
				if err := decoder.Finish(); !errors.Is(err, test.want) {
					t.Fatalf("finish = %v, want %v", err, test.want)
				}
				return
			}
			if len(test.input) == 1 {
				if _, err := decoder.Bool(); err != nil {
					t.Fatal(err)
				}
			}
			if err := decoder.Finish(); err != nil {
				t.Fatal(err)
			}
		})
	}

	var decoder *Decoder
	if _, err := decoder.Bool(); !errors.Is(err, ErrInvalidDecoder) {
		t.Fatalf("nil Bool = %v", err)
	}
	if _, err := decoder.Bytes(1); !errors.Is(err, ErrInvalidDecoder) {
		t.Fatalf("nil Bytes = %v", err)
	}
	if err := decoder.Finish(); !errors.Is(err, ErrInvalidDecoder) {
		t.Fatalf("nil Finish = %v", err)
	}
	if decoder.EOF() {
		t.Fatal("nil decoder reported EOF")
	}
}

func TestDecoderRejectsInvalidBooleanAndRetainsFirstError(t *testing.T) {
	decoder := NewDecoder([]byte{2, 1}, 2)
	if _, err := decoder.Bool(); !errors.Is(err, ErrInvalidBoolean) {
		t.Fatalf("invalid boolean = %v", err)
	}
	if _, err := decoder.Bool(); !errors.Is(err, ErrInvalidBoolean) {
		t.Fatalf("read after invalid boolean = %v", err)
	}
	if err := decoder.Finish(); !errors.Is(err, ErrInvalidBoolean) {
		t.Fatalf("finish after invalid boolean = %v", err)
	}
}

func TestDecoderRejectsTruncation(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		read  func(*Decoder) error
	}{
		{name: "bool", read: func(d *Decoder) error { _, err := d.Bool(); return err }},
		{name: "uint32", input: []byte{1, 2, 3}, read: func(d *Decoder) error { _, err := d.Uint32(); return err }},
		{name: "uint64", input: make([]byte, 7), read: func(d *Decoder) error { _, err := d.Uint64(); return err }},
		{name: "int64", input: make([]byte, 7), read: func(d *Decoder) error { _, err := d.Int64(); return err }},
		{name: "bytes length", input: []byte{0, 0, 0}, read: func(d *Decoder) error { _, err := d.Bytes(8); return err }},
		{name: "bytes value", input: []byte{0, 0, 0, 2, 1}, read: func(d *Decoder) error { _, err := d.Bytes(8); return err }},
		{name: "list count", input: []byte{0, 0, 0}, read: func(d *Decoder) error {
			return d.ValidatedList(4, 8, func(_ int, child *Decoder) error { _, err := child.Bool(); return err })
		}},
		{name: "list frames", input: []byte{0, 0, 0, 2, 0, 0, 0, 0}, read: func(d *Decoder) error {
			return d.ValidatedList(2, 8, func(_ int, child *Decoder) error { _, err := child.Bool(); return err })
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decoder := NewDecoder(test.input, 64)
			if err := test.read(decoder); !errors.Is(err, ErrTruncatedProjection) {
				t.Fatalf("got %v, want %v", err, ErrTruncatedProjection)
			}
		})
	}
}

func TestDecoderBytesFixedWidthAndLengthBounds(t *testing.T) {
	if _, err := NewDecoder(framedBytes([]byte{1, 2}), 6).Bytes(1); !errors.Is(err, ErrProjectionTooLarge) {
		t.Fatalf("oversize bytes = %v", err)
	}
	if _, err := NewDecoder([]byte{0xff, 0xff, 0xff, 0xff}, 4).Bytes(0); !errors.Is(err, ErrProjectionTooLarge) {
		t.Fatalf("u32 maximum length = %v", err)
	}
	if _, err := NewDecoder(framedBytes([]byte{1}), 5).FixedBytes(2); !errors.Is(err, ErrInvalidFixedWidth) {
		t.Fatalf("wrong fixed width = %v", err)
	}
	if _, err := NewDecoder(framedBytes([]byte{1}), 5).FixedBytes(-1); !errors.Is(err, ErrInvalidLimits) {
		t.Fatalf("negative fixed width = %v", err)
	}
	if _, err := NewDecoder(framedBytes(nil), 4).Bytes(-1); !errors.Is(err, ErrInvalidLimits) {
		t.Fatalf("negative value limit = %v", err)
	}

	decoder := NewDecoder(framedBytes([]byte{1, 2}), 6)
	value, err := decoder.FixedBytes(2)
	if err != nil || !bytes.Equal(value, []byte{1, 2}) {
		t.Fatalf("fixed bytes = %x, %v", value, err)
	}
	if err := decoder.Finish(); err != nil {
		t.Fatal(err)
	}
}

func TestDecoderRejectsInvalidUnicode(t *testing.T) {
	if UnicodeNormalizationVersion != "15.0.0" {
		t.Fatalf("Unicode normalization tables = %s, want 15.0.0", UnicodeNormalizationVersion)
	}
	tests := []struct {
		name  string
		value []byte
		limit int
		want  error
	}{
		{name: "invalid UTF-8", value: []byte{0xff}, limit: 8, want: ErrInvalidUTF8},
		{name: "non-NFC", value: []byte("e\u0301"), limit: 8, want: ErrNonNFCString},
		{name: "oversize", value: []byte("CPH"), limit: 2, want: ErrProjectionTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decoder := NewDecoder(framedBytes(test.value), 64)
			if _, err := decoder.String(test.limit); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}

	decoder := NewDecoder(framedBytes([]byte("é")), 64)
	if value, err := decoder.String(2); err != nil || value != "é" {
		t.Fatalf("NFC string = %q, %v", value, err)
	}
	if err := decoder.Finish(); err != nil {
		t.Fatal(err)
	}
}

func TestDecoderPresenceAndHiddenTrailingValue(t *testing.T) {
	decoder := NewDecoder(append([]byte{0}, framedBytes([]byte("hidden"))...), 64)
	present, value, err := decoder.OptionalString(16)
	if err != nil || present || value != "" {
		t.Fatalf("optional string = (%t, %q), %v", present, value, err)
	}
	if err := decoder.Finish(); !errors.Is(err, ErrTrailingData) {
		t.Fatalf("hidden absent value = %v", err)
	}

	if _, _, err := NewDecoder([]byte{2}, 1).OptionalBytes(8); !errors.Is(err, ErrInvalidBoolean) {
		t.Fatalf("invalid optional presence = %v", err)
	}
	if _, _, err := NewDecoder([]byte{1, 0, 0, 0, 1, 0xff}, 6).OptionalFixedBytes(2); !errors.Is(err, ErrInvalidFixedWidth) {
		t.Fatalf("optional fixed width = %v", err)
	}
}

func TestDecoderValidatedListBoundsOrderAndCopies(t *testing.T) {
	want := [][]byte{{2}, {1, 0}, nil}
	elements, err := encodeByteElements(want)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Marshal(128, func(out *Encoder) { out.EncodedList(elements) })
	if err != nil {
		t.Fatal(err)
	}
	decoder := NewDecoder(encoded, len(encoded))
	values := make([][]byte, 0, len(want))
	if err := decoder.ValidatedList(3, 6, collectByteElements(&values, 2)); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(values, want) {
		t.Fatalf("list = %v, want %v", values, want)
	}
	if err := decoder.Finish(); err != nil {
		t.Fatal(err)
	}

	if err := NewDecoder(encoded, len(encoded)).ValidatedList(2, 6, collectByteElements(new([][]byte), 2)); !errors.Is(err, ErrTooManyElements) {
		t.Fatalf("item bound = %v", err)
	}
	if err := NewDecoder(encoded, len(encoded)).ValidatedList(3, 5, collectByteElements(new([][]byte), 2)); !errors.Is(err, ErrProjectionTooLarge) {
		t.Fatalf("element bound = %v", err)
	}
	if err := NewDecoder(encoded, len(encoded)).ValidatedList(-1, 6, collectByteElements(new([][]byte), 2)); !errors.Is(err, ErrInvalidLimits) {
		t.Fatalf("negative item bound = %v", err)
	}
	if err := NewDecoder(encoded, len(encoded)).ValidatedList(3, -1, collectByteElements(new([][]byte), 2)); !errors.Is(err, ErrInvalidLimits) {
		t.Fatalf("negative element bound = %v", err)
	}
	if err := NewDecoder(encoded, len(encoded)).ValidatedList(maxCollectionElements+1, 6, collectByteElements(new([][]byte), 2)); !errors.Is(err, ErrInvalidLimits) {
		t.Fatalf("package ceiling overflow = %v", err)
	}
	if err := NewDecoder([]byte{0xff, 0xff, 0xff, 0xff}, 4).ValidatedList(0, 0, collectByteElements(new([][]byte), 2)); !errors.Is(err, ErrTooManyElements) {
		t.Fatalf("u32 maximum count = %v", err)
	}
	if err := NewDecoder(encoded, len(encoded)).ValidatedList(3, 6, nil); !errors.Is(err, ErrElementDecoderRequired) {
		t.Fatalf("nil element decoder = %v", err)
	}

	values[0][0] = 0xff
	second := make([][]byte, 0, len(want))
	if err := NewDecoder(encoded, len(encoded)).ValidatedList(3, 6, collectByteElements(&second, 2)); err != nil {
		t.Fatal(err)
	}
	if second[0][0] != 2 {
		t.Fatal("returned list element aliases encoded input or another decode")
	}
}

func TestDecoderValidatedSetRequiresStrictRawCanonicalOrder(t *testing.T) {
	input := [][]byte{{2}, {1, 0}, {1}}
	elements, err := encodeByteElements(input)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Marshal(128, func(out *Encoder) { out.EncodedSet(elements) })
	if err != nil {
		t.Fatal(err)
	}
	decoder := NewDecoder(encoded, len(encoded))
	values := make([][]byte, 0, len(input))
	if err := decoder.ValidatedSet(3, 6, collectByteElements(&values, 2)); err != nil {
		t.Fatal(err)
	}
	want := [][]byte{{1}, {2}, {1, 0}}
	if !reflect.DeepEqual(values, want) {
		t.Fatalf("set = %v, want raw lexical order %v", values, want)
	}
	if err := decoder.Finish(); err != nil {
		t.Fatal(err)
	}

	unsortedElements, err := encodeByteElements([][]byte{{2}, {1}})
	if err != nil {
		t.Fatal(err)
	}
	unsorted, err := Marshal(64, func(out *Encoder) { out.EncodedList(unsortedElements) })
	if err != nil {
		t.Fatal(err)
	}
	if err := NewDecoder(unsorted, len(unsorted)).ValidatedSet(2, 5, collectByteElements(new([][]byte), 1)); !errors.Is(err, ErrNonCanonicalSetOrder) {
		t.Fatalf("unsorted set = %v", err)
	}

	duplicateElements, err := encodeByteElements([][]byte{{1}, {1}})
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := Marshal(64, func(out *Encoder) { out.EncodedList(duplicateElements) })
	if err != nil {
		t.Fatal(err)
	}
	if err := NewDecoder(duplicate, len(duplicate)).ValidatedSet(2, 5, collectByteElements(new([][]byte), 1)); !errors.Is(err, ErrDuplicateSetValue) {
		t.Fatalf("duplicate set = %v", err)
	}
}

func TestDecoderValidatedCollectionsRejectInvalidInnerElements(t *testing.T) {
	customErr := errors.New("schema semantic rejection")
	tests := []struct {
		name    string
		element []byte
		decode  func(int, *Decoder) error
		want    error
	}{
		{name: "empty required structure", element: nil, decode: func(_ int, child *Decoder) error { _, err := child.Uint32(); return err }, want: ErrTruncatedProjection},
		{name: "incomplete inner length", element: []byte{0, 0, 0}, decode: func(_ int, child *Decoder) error { _, err := child.Bytes(8); return err }, want: ErrTruncatedProjection},
		{name: "inner trailing byte", element: append(framedBytes([]byte{1}), 0), decode: func(_ int, child *Decoder) error { _, err := child.Bytes(1); return err }, want: ErrTrailingData},
		{name: "callback consumes nothing", element: []byte{1}, decode: func(_ int, _ *Decoder) error { return nil }, want: ErrTrailingData},
		{name: "ignored child error", element: []byte{2}, decode: func(_ int, child *Decoder) error { _, _ = child.Bool(); return nil }, want: ErrInvalidBoolean},
		{name: "invalid inner UTF-8", element: framedBytes([]byte{0xff}), decode: func(_ int, child *Decoder) error { _, err := child.String(8); return err }, want: ErrInvalidUTF8},
		{name: "non-NFC inner string", element: framedBytes([]byte("e\u0301")), decode: func(_ int, child *Decoder) error { _, err := child.String(8); return err }, want: ErrNonNFCString},
		{name: "callback semantic error", element: framedBytes([]byte{1}), decode: func(_ int, child *Decoder) error {
			_, err := child.Bytes(1)
			if err != nil {
				return err
			}
			return customErr
		}, want: customErr},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := Marshal(128, func(out *Encoder) { out.EncodedList([][]byte{test.element}) })
			if err != nil {
				t.Fatal(err)
			}
			decoder := NewDecoder(encoded, len(encoded))
			err = decoder.ValidatedList(1, 64, test.decode)
			if !errors.Is(err, test.want) {
				t.Fatalf("validated list = %v, want %v", err, test.want)
			}
			if finishErr := decoder.Finish(); !errors.Is(finishErr, test.want) {
				t.Fatalf("Finish lost retained child error: %v, want %v", finishErr, test.want)
			}
		})
	}

	encoded, err := Marshal(64, func(out *Encoder) { out.EncodedSet([][]byte{framedBytes([]byte{0xff})}) })
	if err != nil {
		t.Fatal(err)
	}
	if err := NewDecoder(encoded, len(encoded)).ValidatedSet(1, 8, func(_ int, child *Decoder) error {
		_, err := child.String(1)
		return err
	}); !errors.Is(err, ErrInvalidUTF8) {
		t.Fatalf("validated set accepted invalid inner string: %v", err)
	}
}

func TestDecoderStringSetValidatesTypedElements(t *testing.T) {
	encoded, err := Marshal(128, func(out *Encoder) { out.StringSet([]string{"miner", "é", "agent", "a"}) })
	if err != nil {
		t.Fatal(err)
	}
	decoder := NewDecoder(encoded, len(encoded))
	values, err := decoder.StringSet(4, 5)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a", "é", "agent", "miner"}
	if !reflect.DeepEqual(values, want) {
		t.Fatalf("string set = %q, want %q", values, want)
	}
	if err := decoder.Finish(); err != nil {
		t.Fatal(err)
	}

	if _, err := NewDecoder(encoded, len(encoded)).StringSet(4, 4); !errors.Is(err, ErrProjectionTooLarge) {
		t.Fatalf("string element bound = %v", err)
	}
	if _, err := NewDecoder(encoded, len(encoded)).StringSet(4, -1); !errors.Is(err, ErrInvalidLimits) {
		t.Fatalf("negative string bound = %v", err)
	}
	maxInt := int(^uint(0) >> 1)
	if _, err := NewDecoder(encoded, len(encoded)).StringSet(4, maxInt); !errors.Is(err, ErrInvalidLimits) {
		t.Fatalf("overflowing string bound = %v", err)
	}

	for _, test := range []struct {
		name    string
		element []byte
		want    error
	}{
		{name: "invalid UTF-8", element: framedBytes([]byte{0xff}), want: ErrInvalidUTF8},
		{name: "non-NFC", element: framedBytes([]byte("e\u0301")), want: ErrNonNFCString},
		{name: "inner trailing", element: append(framedBytes([]byte("a")), 0), want: ErrTrailingData},
	} {
		t.Run(test.name, func(t *testing.T) {
			outer, err := Marshal(64, func(out *Encoder) { out.EncodedSet([][]byte{test.element}) })
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewDecoder(outer, len(outer)).StringSet(1, 8); !errors.Is(err, test.want) {
				t.Fatalf("StringSet = %v, want %v", err, test.want)
			}
		})
	}

	stringA := framedBytes([]byte("a"))
	stringB := framedBytes([]byte("b"))
	for _, test := range []struct {
		name     string
		elements [][]byte
		want     error
	}{
		{name: "duplicate", elements: [][]byte{stringA, stringA}, want: ErrDuplicateSetValue},
		{name: "noncanonical order", elements: [][]byte{stringB, stringA}, want: ErrNonCanonicalSetOrder},
	} {
		t.Run(test.name, func(t *testing.T) {
			outer, err := Marshal(64, func(out *Encoder) { out.EncodedList(test.elements) })
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewDecoder(outer, len(outer)).StringSet(2, 1); !errors.Is(err, test.want) {
				t.Fatalf("StringSet = %v, want %v", err, test.want)
			}
		})
	}

	values[0] = "mutated"
	second, err := NewDecoder(encoded, len(encoded)).StringSet(4, 5)
	if err != nil {
		t.Fatal(err)
	}
	if second[0] != "a" {
		t.Fatal("returned string set aliases decoder state")
	}
}

func TestDecoderCopiesInputAndReturnedValues(t *testing.T) {
	encoded := framedBytes([]byte{0xaa, 0xbb})
	decoder := NewDecoder(encoded, len(encoded))
	encoded[4] = 0xff
	value, err := decoder.Bytes(2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(value, []byte{0xaa, 0xbb}) {
		t.Fatalf("caller mutation changed decoder input: %x", value)
	}
	value[0] = 0
	if decoder.input[4] != 0xaa {
		t.Fatal("returned bytes alias decoder storage")
	}
	if err := decoder.Finish(); err != nil {
		t.Fatal(err)
	}
}

func TestDecoderFinishRejectsTrailingDataAndReadsAfterFinish(t *testing.T) {
	decoder := NewDecoder([]byte{1, 0}, 2)
	assertBool(t, decoder, true)
	if decoder.EOF() {
		t.Fatal("decoder reported EOF with trailing data")
	}
	if err := decoder.Finish(); !errors.Is(err, ErrTrailingData) {
		t.Fatalf("finish with trailing data = %v", err)
	}
	if _, err := decoder.Bool(); !errors.Is(err, ErrTrailingData) {
		t.Fatalf("read after failed finish = %v", err)
	}

	exact := NewDecoder(nil, 1)
	if !exact.EOF() {
		t.Fatal("empty decoder did not report EOF")
	}
	if err := exact.Finish(); err != nil {
		t.Fatal(err)
	}
	if err := exact.Finish(); err != nil {
		t.Fatalf("second finish = %v", err)
	}
	if _, err := exact.Bool(); !errors.Is(err, ErrDecoderFinished) {
		t.Fatalf("read after successful finish = %v", err)
	}
}

func FuzzDecoderEncoderRoundTrip(f *testing.F) {
	f.Add(true, uint32(0x01020304), uint64(0x0102030405060708), int64(-2), "é", []byte{1, 2, 3})
	f.Add(false, uint32(0), uint64(0), int64(math.MinInt64), "", []byte{})
	f.Add(true, ^uint32(0), ^uint64(0), int64(math.MaxInt64), "e\u0301", []byte{0xff})
	f.Fuzz(func(t *testing.T, present bool, u32 uint32, u64 uint64, i64 int64, text string, blob []byte) {
		if len(text) > 512 || len(blob) > 512 {
			return
		}
		optionalText := ""
		if present {
			optionalText = text
		}
		list := [][]byte{append([]byte(nil), blob...), []byte(text)}
		listElements, err := encodeByteElements(list)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := Marshal(4096, func(out *Encoder) {
			out.Bool(present)
			out.Uint32(u32)
			out.Uint64(u64)
			out.Int64(i64)
			out.String(text)
			out.Bytes(blob)
			out.OptionalString(present, optionalText)
			out.EncodedList(listElements)
		})
		if err != nil {
			return
		}

		decoder := NewDecoder(encoded, 4096)
		decodedBool, err := decoder.Bool()
		if err != nil {
			t.Fatal(err)
		}
		decodedU32, err := decoder.Uint32()
		if err != nil {
			t.Fatal(err)
		}
		decodedU64, err := decoder.Uint64()
		if err != nil {
			t.Fatal(err)
		}
		decodedI64, err := decoder.Int64()
		if err != nil {
			t.Fatal(err)
		}
		decodedText, err := decoder.String(512)
		if err != nil {
			t.Fatal(err)
		}
		decodedBlob, err := decoder.Bytes(512)
		if err != nil {
			t.Fatal(err)
		}
		decodedPresent, decodedOptional, err := decoder.OptionalString(512)
		if err != nil {
			t.Fatal(err)
		}
		decodedList := make([][]byte, 0, len(list))
		if err := decoder.ValidatedList(2, 516, collectByteElements(&decodedList, 512)); err != nil {
			t.Fatal(err)
		}
		if err := decoder.Finish(); err != nil {
			t.Fatal(err)
		}
		if decodedBool != present || decodedU32 != u32 || decodedU64 != u64 || decodedI64 != i64 ||
			decodedText != text || !bytes.Equal(decodedBlob, blob) || decodedPresent != present ||
			decodedOptional != optionalText || !equalByteSlices(decodedList, list) {
			t.Fatal("decoded values differ from encoded values")
		}

		decodedListElements, err := encodeByteElements(decodedList)
		if err != nil {
			t.Fatal(err)
		}
		reencoded, err := Marshal(4096, func(out *Encoder) {
			out.Bool(decodedBool)
			out.Uint32(decodedU32)
			out.Uint64(decodedU64)
			out.Int64(decodedI64)
			out.String(decodedText)
			out.Bytes(decodedBlob)
			out.OptionalString(decodedPresent, decodedOptional)
			out.EncodedList(decodedListElements)
		})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(reencoded, encoded) {
			t.Fatalf("roundtrip changed bytes\n got %x\nwant %x", reencoded, encoded)
		}
	})
}

func FuzzDecoderRejectsMalformedWithoutUnboundedWork(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{2})
	f.Add([]byte{0, 0, 0, 1, 0, 0, 0, 0})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 4096 {
			input = input[:4096]
		}
		decoder := NewDecoder(input, 4096)
		values := make([][]byte, 0)
		parseErr := decoder.ValidatedSet(64, 256, collectByteElements(&values, 252))
		finishErr := decoder.Finish()
		if parseErr != nil {
			if finishErr == nil || !errors.Is(finishErr, parseErr) {
				t.Fatalf("Finish lost retained parse error: parse=%v finish=%v", parseErr, finishErr)
			}
			return
		}
		if finishErr != nil {
			if !errors.Is(finishErr, ErrTrailingData) {
				t.Fatalf("unexpected Finish error after collection parse: %v", finishErr)
			}
			return
		}
		if len(values) > 64 {
			t.Fatalf("decoded %d values above bound", len(values))
		}
		for _, value := range values {
			if len(value) > 252 {
				t.Fatalf("decoded element length %d above bound", len(value))
			}
		}
	})
}

func assertBool(t *testing.T, decoder *Decoder, want bool) {
	t.Helper()
	value, err := decoder.Bool()
	if err != nil || value != want {
		t.Fatalf("bool = %t, %v; want %t", value, err, want)
	}
}

func framedBytes(value []byte) []byte {
	encoded := make([]byte, 4+len(value))
	binary.BigEndian.PutUint32(encoded, uint32(len(value)))
	copy(encoded[4:], value)
	return encoded
}

func equalByteSlices(left, right [][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !bytes.Equal(left[index], right[index]) {
			return false
		}
	}
	return true
}

func encodeByteElements(values [][]byte) ([][]byte, error) {
	elements := make([][]byte, len(values))
	for index, value := range values {
		encoded, err := Marshal(4+len(value), func(out *Encoder) { out.Bytes(value) })
		if err != nil {
			return nil, err
		}
		elements[index] = encoded
	}
	return elements, nil
}

func collectByteElements(values *[][]byte, maxValueBytes int) func(int, *Decoder) error {
	return func(_ int, child *Decoder) error {
		value, err := child.Bytes(maxValueBytes)
		if err != nil {
			return err
		}
		*values = append(*values, value)
		return nil
	}
}
