// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package ccse

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

var (
	ErrInvalidDecoder         = errors.New("ccse: invalid decoder")
	ErrDecoderFinished        = errors.New("ccse: decoder is already finished")
	ErrTruncatedProjection    = errors.New("ccse: truncated canonical projection")
	ErrTrailingData           = errors.New("ccse: trailing canonical projection data")
	ErrInvalidBoolean         = errors.New("ccse: canonical boolean is not zero or one")
	ErrInvalidFixedWidth      = errors.New("ccse: invalid fixed byte width")
	ErrNonCanonicalSetOrder   = errors.New("ccse: set elements are not in canonical order")
	ErrElementDecoderRequired = errors.New("ccse: collection element decoder is required")
)

// Decoder reads one schema-ordered CCSE projection. It intentionally exposes
// no map, float, reflection, host-width integer, or implicit normalization
// operation. A schema decoder must call Finish after consuming its final field.
//
// Decoder owns a copy of input and every byte slice it returns is detached.
// It retains the first error so a failed parse cannot be resumed under a
// different interpretation.
type Decoder struct {
	input    []byte
	offset   int
	maxBytes uint64
	err      error
	finished bool
}

// NewDecoder creates a decoder whose complete input is bounded by maxBytes.
// Zero selects DefaultMaxProjectionSize. A negative limit or oversized input
// creates a fail-closed decoder whose methods return the retained error.
func NewDecoder(input []byte, maxBytes int) *Decoder {
	d := &Decoder{}
	if maxBytes < 0 {
		d.err = ErrInvalidLimits
		return d
	}
	if maxBytes == 0 {
		maxBytes = DefaultMaxProjectionSize
	}
	d.maxBytes = uint64(maxBytes)
	if uint64(len(input)) > d.maxBytes {
		d.err = ErrProjectionTooLarge
		return d
	}
	d.input = append([]byte(nil), input...)
	return d
}

// Unmarshal applies a schema-specific decoder and requires it to consume the
// complete projection. It is the decode-side counterpart of Marshal. A typed
// decoder may capture its result in the closure, while Unmarshal guarantees
// that a forgotten Finish call cannot admit trailing bytes.
func Unmarshal(input []byte, maxBytes int, decode func(*Decoder) error) error {
	if decode == nil {
		return errors.New("ccse: nil decoder projection")
	}
	d := NewDecoder(input, maxBytes)
	if d.err != nil {
		return d.err
	}
	if err := decode(d); err != nil {
		return d.fail(err)
	}
	return d.Finish()
}

// Bool reads a canonical boolean. Values other than exactly 0 and 1 are
// rejected rather than treated as truthy.
func (d *Decoder) Bool() (bool, error) {
	raw, err := d.read(1)
	if err != nil {
		return false, err
	}
	switch raw[0] {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, d.fail(fmt.Errorf("%w: 0x%02x", ErrInvalidBoolean, raw[0]))
	}
}

// Presence reads the canonical one-byte presence discriminator used by an
// optional field. When it returns false the schema decoder must not consume an
// optional value.
func (d *Decoder) Presence() (bool, error) {
	return d.Bool()
}

// Uint32 reads one unsigned 32-bit big-endian integer.
func (d *Decoder) Uint32() (uint32, error) {
	raw, err := d.read(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(raw), nil
}

// Uint64 reads one unsigned 64-bit big-endian integer.
func (d *Decoder) Uint64() (uint64, error) {
	raw, err := d.read(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(raw), nil
}

// Int64 reads one signed 64-bit two's-complement big-endian integer.
func (d *Decoder) Int64() (int64, error) {
	value, err := d.Uint64()
	return int64(value), err
}

// Bytes reads a u32 length followed by the exact bytes. maxValueBytes bounds
// the value excluding its four-byte length prefix; zero uses the decoder's
// complete-input bound. The returned slice never aliases decoder or caller
// storage.
func (d *Decoder) Bytes(maxValueBytes int) ([]byte, error) {
	return d.bytes(maxValueBytes, -1)
}

// FixedBytes reads the normal CCSE byte-string framing and additionally
// requires its declared value length to equal width exactly.
func (d *Decoder) FixedBytes(width int) ([]byte, error) {
	if width < 0 {
		return nil, d.fail(ErrInvalidLimits)
	}
	return d.bytes(width, width)
}

// String reads a length-prefixed string and rejects invalid UTF-8 and strings
// that are not already NFC according to the Unicode version fixed by CCSE-v1.
// It never silently normalizes. maxValueBytes excludes the length prefix.
func (d *Decoder) String(maxValueBytes int) (string, error) {
	value, err := d.Bytes(maxValueBytes)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(value) {
		return "", d.fail(ErrInvalidUTF8)
	}
	text := string(value)
	if !norm.NFC.IsNormalString(text) {
		return "", d.fail(ErrNonNFCString)
	}
	return text, nil
}

// OptionalBytes reads presence followed by a byte string when present.
func (d *Decoder) OptionalBytes(maxValueBytes int) (bool, []byte, error) {
	if _, err := d.valueLimit(maxValueBytes); err != nil {
		return false, nil, err
	}
	present, err := d.Presence()
	if err != nil || !present {
		return present, nil, err
	}
	value, err := d.Bytes(maxValueBytes)
	if err != nil {
		return false, nil, err
	}
	return true, value, nil
}

// OptionalFixedBytes reads presence followed by an exactly sized CCSE byte
// string when present.
func (d *Decoder) OptionalFixedBytes(width int) (bool, []byte, error) {
	if width < 0 {
		return false, nil, d.fail(ErrInvalidLimits)
	}
	present, err := d.Presence()
	if err != nil || !present {
		return present, nil, err
	}
	value, err := d.FixedBytes(width)
	if err != nil {
		return false, nil, err
	}
	return true, value, nil
}

// OptionalString reads presence followed by a canonical string when present.
func (d *Decoder) OptionalString(maxValueBytes int) (bool, string, error) {
	if _, err := d.valueLimit(maxValueBytes); err != nil {
		return false, "", err
	}
	present, err := d.Presence()
	if err != nil || !present {
		return present, "", err
	}
	value, err := d.String(maxValueBytes)
	if err != nil {
		return false, "", err
	}
	return true, value, nil
}

// ValidatedList reads a count and independently length-framed canonical
// elements in their declared order. decodeElement must consume each element's
// schema through its child Decoder. ValidatedList always calls Finish on every
// child and rejects an ignored child error, incomplete structure, or trailing
// element data. Raw framing-only element bytes are deliberately not exposed.
//
// maxItems and maxElementBytes are checked before their corresponding
// allocations; zero selects the package collection ceiling and complete-input
// bound respectively. A callback may capture typed, detached values returned
// by the child decoder.
func (d *Decoder) ValidatedList(maxItems, maxElementBytes int, decodeElement func(int, *Decoder) error) error {
	return d.validatedCollection(maxItems, maxElementBytes, false, decodeElement)
}

// ValidatedSet applies the same mandatory child validation as ValidatedList
// and additionally requires raw canonical element encodings to be in strictly
// increasing lexicographic order. Equal adjacent encodings are duplicates;
// descending encodings are noncanonical. Input is never sorted or deduplicated.
func (d *Decoder) ValidatedSet(maxItems, maxElementBytes int, decodeElement func(int, *Decoder) error) error {
	return d.validatedCollection(maxItems, maxElementBytes, true, decodeElement)
}

// StringSet decodes a CCSE set whose elements are canonical strings. The
// returned order is the signed raw-canonical set order, not locale or Go string
// order. maxStringBytes bounds each UTF-8 value excluding its inner length
// prefix; zero uses the decoder input bound. The returned slice is detached.
func (d *Decoder) StringSet(maxItems, maxStringBytes int) ([]string, error) {
	if maxStringBytes < 0 {
		return nil, d.fail(ErrInvalidLimits)
	}
	maxElementBytes := 0
	if maxStringBytes > 0 {
		maxInt := int(^uint(0) >> 1)
		if maxStringBytes > maxInt-4 {
			return nil, d.fail(ErrInvalidLimits)
		}
		maxElementBytes = 4 + maxStringBytes
	}
	values := make([]string, 0)
	err := d.ValidatedSet(maxItems, maxElementBytes, func(_ int, child *Decoder) error {
		value, err := child.String(maxStringBytes)
		if err != nil {
			return err
		}
		values = append(values, value)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return values, nil
}

// EOF reports whether the complete input has been consumed without an error.
// Schema decoders must still call Finish so trailing data becomes a retained
// parse error rather than a boolean branch that can be forgotten.
func (d *Decoder) EOF() bool {
	return d != nil && d.err == nil && d.offset == len(d.input)
}

// Finish returns the first retained parse error, or succeeds only after the
// complete input has been consumed exactly. Its result must be checked on every
// manual decode path; EOF alone is not validation because a failed decoder can
// be physically at the end of its input. Finish is idempotent after success.
// Reads after a successful Finish fail closed.
func (d *Decoder) Finish() error {
	if d == nil {
		return ErrInvalidDecoder
	}
	if d.err != nil {
		return d.err
	}
	if d.finished {
		return nil
	}
	if d.offset != len(d.input) {
		return d.fail(fmt.Errorf("%w: %d bytes remain", ErrTrailingData, len(d.input)-d.offset))
	}
	d.finished = true
	return nil
}

func (d *Decoder) bytes(maxValueBytes, exactWidth int) ([]byte, error) {
	limit, err := d.valueLimit(maxValueBytes)
	if err != nil {
		return nil, err
	}
	rawLength, err := d.read(4)
	if err != nil {
		return nil, err
	}
	length := uint64(binary.BigEndian.Uint32(rawLength))
	if exactWidth >= 0 && length != uint64(exactWidth) {
		return nil, d.fail(fmt.Errorf("%w: encoded width is %d, want %d", ErrInvalidFixedWidth, length, exactWidth))
	}
	if length > limit {
		return nil, d.fail(fmt.Errorf("%w: value length %d exceeds %d", ErrProjectionTooLarge, length, limit))
	}
	if length > uint64(len(d.input)-d.offset) {
		return nil, d.fail(fmt.Errorf("%w: need %d bytes at offset %d", ErrTruncatedProjection, length, d.offset))
	}
	start := d.offset
	d.offset += int(length)
	return append([]byte(nil), d.input[start:d.offset]...), nil
}

func (d *Decoder) collectionCount(maxItems int) (int, error) {
	if maxItems < 0 {
		return 0, d.fail(ErrInvalidLimits)
	}
	if maxItems == 0 {
		maxItems = maxCollectionElements
	}
	if maxItems > maxCollectionElements {
		return 0, d.fail(ErrInvalidLimits)
	}
	countValue, err := d.Uint32()
	if err != nil {
		return 0, err
	}
	count := uint64(countValue)
	if count > uint64(maxItems) {
		return 0, d.fail(fmt.Errorf("%w: count %d exceeds %d", ErrTooManyElements, count, maxItems))
	}
	// Every framed element needs at least its four-byte length prefix. Check
	// this before converting count to int or allocating the result slice.
	if count > uint64(len(d.input)-d.offset)/4 {
		return 0, d.fail(fmt.Errorf("%w: %d element frames do not fit", ErrTruncatedProjection, count))
	}
	return int(count), nil
}

func (d *Decoder) validatedCollection(maxItems, maxElementBytes int, requireSetOrder bool, decodeElement func(int, *Decoder) error) error {
	if decodeElement == nil {
		return d.fail(ErrElementDecoderRequired)
	}
	if maxItems < 0 || maxItems > maxCollectionElements || maxElementBytes < 0 {
		return d.fail(ErrInvalidLimits)
	}
	count, err := d.collectionCount(maxItems)
	if err != nil {
		return err
	}
	var previous []byte
	for index := 0; index < count; index++ {
		element, err := d.Bytes(maxElementBytes)
		if err != nil {
			return err
		}
		if requireSetOrder && index > 0 {
			switch comparison := bytes.Compare(previous, element); {
			case comparison == 0:
				return d.fail(ErrDuplicateSetValue)
			case comparison > 0:
				return d.fail(ErrNonCanonicalSetOrder)
			}
		}
		previous = element

		childLimit := len(element)
		if childLimit == 0 {
			childLimit = 1
		}
		child := NewDecoder(element, childLimit)
		callbackErr := decodeElement(index, child)
		retainedChildErr := child.err
		finishErr := child.Finish()
		switch {
		case retainedChildErr != nil:
			return d.fail(fmt.Errorf("ccse: collection element %d: %w", index, retainedChildErr))
		case callbackErr != nil:
			return d.fail(fmt.Errorf("ccse: collection element %d: %w", index, callbackErr))
		case finishErr != nil:
			return d.fail(fmt.Errorf("ccse: collection element %d: %w", index, finishErr))
		}
	}
	return nil
}

func (d *Decoder) valueLimit(maxValueBytes int) (uint64, error) {
	if d == nil {
		return 0, ErrInvalidDecoder
	}
	if maxValueBytes < 0 {
		return 0, d.fail(ErrInvalidLimits)
	}
	if maxValueBytes == 0 {
		return d.maxBytes, nil
	}
	return uint64(maxValueBytes), nil
}

func (d *Decoder) read(width int) ([]byte, error) {
	if d == nil {
		return nil, ErrInvalidDecoder
	}
	if d.err != nil {
		return nil, d.err
	}
	if d.finished {
		return nil, d.fail(ErrDecoderFinished)
	}
	if width < 0 {
		return nil, d.fail(ErrInvalidLimits)
	}
	if width > len(d.input)-d.offset {
		return nil, d.fail(fmt.Errorf("%w: need %d bytes at offset %d", ErrTruncatedProjection, width, d.offset))
	}
	start := d.offset
	d.offset += width
	return d.input[start:d.offset], nil
}

func (d *Decoder) fail(err error) error {
	if d == nil {
		return ErrInvalidDecoder
	}
	if d.err == nil {
		d.err = err
	}
	return d.err
}
