// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package ccse

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	// DefaultMaxProjectionSize bounds an individual canonical domain, envelope,
	// or payload projection. Message-specific schemas SHOULD set a lower bound.
	DefaultMaxProjectionSize = 8 << 20
	maxCollectionElements    = 1 << 20

	// UnicodeNormalizationVersion fixes the UCD tables used for CCSE-v1 NFC
	// validation. Every language implementation must use this version and pass
	// the shared vectors before it can claim conformance.
	UnicodeNormalizationVersion = norm.Version
)

var (
	ErrProjectionTooLarge = errors.New("ccse: canonical projection exceeds size limit")
	ErrInvalidUTF8        = errors.New("ccse: string is not valid UTF-8")
	ErrNonNFCString       = errors.New("ccse: string is not NFC normalized")
	ErrNonCanonicalAbsent = errors.New("ccse: absent optional field retains a value")
	ErrDuplicateSetValue  = errors.New("ccse: duplicate canonical set value")
	ErrTooManyElements    = errors.New("ccse: collection exceeds element limit")
)

// Encoder writes schema-ordered CCSE fields. It intentionally exposes no map,
// float, reflection, or host-width integer operation.
//
// Encoder retains the first error. Projection functions may therefore call
// methods sequentially and return Bytes at the end without branching after
// each field.
type Encoder struct {
	buf      bytes.Buffer
	err      error
	maxBytes uint64
}

// NewEncoder creates an encoder bounded by maxBytes. Zero selects
// DefaultMaxProjectionSize; a negative security limit fails closed.
func NewEncoder(maxBytes int) *Encoder {
	if maxBytes < 0 {
		return &Encoder{err: ErrInvalidLimits}
	}
	if maxBytes == 0 {
		maxBytes = DefaultMaxProjectionSize
	}
	return &Encoder{maxBytes: uint64(maxBytes)}
}

// Marshal applies a schema-specific projection and returns a detached byte
// slice. The projection must write fields in the order fixed by its schema.
func Marshal(maxBytes int, project func(*Encoder)) ([]byte, error) {
	if project == nil {
		return nil, errors.New("ccse: nil projection")
	}
	e := NewEncoder(maxBytes)
	project(e)
	return e.Result()
}

// Bool writes a canonical boolean as exactly one byte.
func (e *Encoder) Bool(value bool) {
	if value {
		e.raw([]byte{1})
	} else {
		e.raw([]byte{0})
	}
}

// Uint32 writes an unsigned 32-bit integer in big-endian order.
func (e *Encoder) Uint32(value uint32) {
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], value)
	e.raw(out[:])
}

// Uint64 writes an unsigned 64-bit integer in big-endian order.
func (e *Encoder) Uint64(value uint64) {
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], value)
	e.raw(out[:])
}

// Int64 writes a signed 64-bit integer as its fixed-width two's-complement
// representation in big-endian order. CCSE UTC timestamps use this operation.
func (e *Encoder) Int64(value int64) {
	e.Uint64(uint64(value))
}

// FixedBytes enforces a schema-fixed width and then writes the value with the
// same 32-bit length prefix required for every CCSE byte string.
func (e *Encoder) FixedBytes(value []byte, width int) {
	if e.err != nil {
		return
	}
	if width < 0 || len(value) != width {
		e.err = fmt.Errorf("ccse: fixed byte width is %d, want %d", len(value), width)
		return
	}
	e.Bytes(value)
}

// Bytes writes a 32-bit length followed by the exact bytes.
func (e *Encoder) Bytes(value []byte) {
	if e.err != nil {
		return
	}
	if uint64(len(value)) > math.MaxUint32 {
		e.err = ErrProjectionTooLarge
		return
	}
	e.Uint32(uint32(len(value)))
	e.raw(value)
}

// String writes a valid NFC UTF-8 string as length-prefixed bytes. CCSE does
// not silently normalize because doing so would let two accepted inputs have
// the same authorization bytes while downstream business logic sees different
// original text.
func (e *Encoder) String(value string) {
	if e.err != nil {
		return
	}
	if !utf8.ValidString(value) {
		e.err = ErrInvalidUTF8
		return
	}
	if !norm.NFC.IsNormalString(value) {
		e.err = ErrNonNFCString
		return
	}
	e.Bytes([]byte(value))
}

// OptionalString encodes presence separately from the scalar default.
func (e *Encoder) OptionalString(present bool, value string) {
	if !present && value != "" {
		e.err = ErrNonCanonicalAbsent
		return
	}
	e.Bool(present)
	if present {
		e.String(value)
	}
}

// OptionalBytes encodes presence separately from an empty byte string.
func (e *Encoder) OptionalBytes(present bool, value []byte) {
	if !present && len(value) != 0 {
		e.err = ErrNonCanonicalAbsent
		return
	}
	e.Bool(present)
	if present {
		e.Bytes(value)
	}
}

// OptionalFixedBytes encodes presence separately from an all-zero fixed value.
func (e *Encoder) OptionalFixedBytes(present bool, value []byte, width int) {
	if !present && len(value) != 0 {
		e.err = ErrNonCanonicalAbsent
		return
	}
	e.Bool(present)
	if present {
		e.FixedBytes(value, width)
	}
}

// EncodedList writes already-canonical elements in their declared order. Each
// element is independently length-framed so concatenation cannot be ambiguous.
func (e *Encoder) EncodedList(values [][]byte) {
	if e.err != nil {
		return
	}
	if len(values) > maxCollectionElements || uint64(len(values)) > math.MaxUint32 {
		e.err = ErrTooManyElements
		return
	}
	e.Uint32(uint32(len(values)))
	for _, value := range values {
		e.Bytes(value)
	}
}

// EncodedSet writes already-canonical elements sorted lexicographically by
// their encoded bytes. Duplicate canonical values are rejected.
func (e *Encoder) EncodedSet(values [][]byte) {
	if e.err != nil {
		return
	}
	if len(values) > maxCollectionElements || uint64(len(values)) > math.MaxUint32 {
		e.err = ErrTooManyElements
		return
	}
	if !e.collectionFits(values) {
		e.err = ErrProjectionTooLarge
		return
	}
	ordered := make([][]byte, len(values))
	for i, value := range values {
		ordered[i] = append([]byte(nil), value...)
	}
	sort.Slice(ordered, func(i, j int) bool { return bytes.Compare(ordered[i], ordered[j]) < 0 })
	for i := 1; i < len(ordered); i++ {
		if bytes.Equal(ordered[i-1], ordered[i]) {
			e.err = ErrDuplicateSetValue
			return
		}
	}
	e.EncodedList(ordered)
}

// StringSet applies the canonical string encoding to each member and then
// writes the declared set in encoded-byte order.
func (e *Encoder) StringSet(values []string) {
	if e.err != nil {
		return
	}
	if len(values) > maxCollectionElements {
		e.err = ErrTooManyElements
		return
	}
	total := uint64(4)
	for _, value := range values {
		// Each set member is an outer bytes(element) containing the canonical
		// string bytes(length || UTF-8).
		total += uint64(4 + 4 + len(value))
		if total > e.maxBytes {
			e.err = ErrProjectionTooLarge
			return
		}
	}
	encoded := make([][]byte, 0, len(values))
	for _, value := range values {
		item, err := Marshal(int(e.maxBytes), func(sub *Encoder) { sub.String(value) })
		if err != nil {
			e.err = err
			return
		}
		encoded = append(encoded, item)
	}
	e.EncodedSet(encoded)
}

// Result returns a detached copy of the canonical projection.
func (e *Encoder) Result() ([]byte, error) {
	if e.err != nil {
		return nil, e.err
	}
	return append([]byte(nil), e.buf.Bytes()...), nil
}

func (e *Encoder) raw(value []byte) {
	if e.err != nil {
		return
	}
	if uint64(len(value)) > e.maxBytes || uint64(e.buf.Len()) > e.maxBytes-uint64(len(value)) {
		e.err = ErrProjectionTooLarge
		return
	}
	_, e.err = e.buf.Write(value)
}

func (e *Encoder) collectionFits(values [][]byte) bool {
	total := uint64(4)
	for _, value := range values {
		if uint64(len(value)) > math.MaxUint32 {
			return false
		}
		total += uint64(4 + len(value))
		if total > e.maxBytes {
			return false
		}
	}
	return true
}
