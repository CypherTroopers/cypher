// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package strictproto

import (
	"fmt"
	"unicode/utf8"

	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	wireVarint  = uint64(0)
	wireFixed64 = uint64(1)
	wireBytes   = uint64(2)
	wireStart   = uint64(3)
	wireEnd     = uint64(4)
	wireFixed32 = uint64(5)

	maxFieldNumber   = uint64(1<<29 - 1)
	maxUint32Value   = uint64(1<<32 - 1)
	maxInt32Value    = uint64(1<<31 - 1)
	minInt32Encoding = ^uint64(0) - uint64(1<<31) + 1
)

type scanState struct {
	limits      Limits
	totalFields int
}

// Preflight validates raw Protobuf bytes without allocating values from the
// input. Its small bookkeeping allocations are bounded by descriptors and
// MaxDepth, while input-controlled work is bounded by Limits.
func Preflight(data []byte, descriptor protoreflect.MessageDescriptor, limits Limits) error {
	if err := limits.validateFor(descriptor); err != nil {
		return err
	}
	rootLimit := limits.messageBytes(descriptor)
	if len(data) > rootLimit {
		return fmt.Errorf("%w: root has %d bytes, limit %d", ErrMessageTooLarge, len(data), rootLimit)
	}
	owned := append([]byte(nil), data...)
	return preflightOwned(owned, descriptor, limits)
}

// preflightOwned requires an immutable, caller-owned byte slice and limits
// already bound to descriptor. Unmarshal uses it so preflight and decode see
// the exact same snapshot without making two copies.
func preflightOwned(data []byte, descriptor protoreflect.MessageDescriptor, limits Limits) error {
	state := scanState{limits: limits}
	return state.scanMessage(data, descriptor, 1)
}

func (s *scanState) scanMessage(data []byte, descriptor protoreflect.MessageDescriptor, depth int) error {
	if depth > s.limits.MaxDepth {
		return fmt.Errorf("%w: %s at depth %d", ErrDepthExceeded, descriptor.FullName(), depth)
	}
	if descriptor.IsPlaceholder() || descriptor.IsMapEntry() || descriptor.Syntax() != protoreflect.Proto3 || descriptor.ExtensionRanges().Len() != 0 {
		return fmt.Errorf("%w: message %s is not a supported proto3 descriptor", ErrInvalidDescriptor, descriptor.FullName())
	}
	if len(data) > s.limits.messageBytes(descriptor) {
		return fmt.Errorf("%w: %s has %d bytes", ErrMessageTooLarge, descriptor.FullName(), len(data))
	}

	fields := descriptor.Fields()
	for index := 0; index < fields.Len(); index++ {
		field := fields.Get(index)
		if field.IsMap() || field.Kind() == protoreflect.GroupKind || field.IsPlaceholder() || field.IsWeak() {
			return fmt.Errorf("%w: field %s", ErrInvalidDescriptor, field.FullName())
		}
	}
	seen := make([]bool, fields.Len())
	fieldBytes := make([]int, fields.Len())
	repeatedItems := make([]int, fields.Len())
	oneofs := descriptor.Oneofs()
	oneofSeen := make([]bool, oneofs.Len())

	for offset := 0; offset < len(data); {
		tag, tagBytes, err := consumeMinimalVarint(data[offset:])
		if err != nil {
			return fmt.Errorf("%s tag at offset %d: %w", descriptor.FullName(), offset, err)
		}
		number := tag >> 3
		wireType := tag & 7
		if number == 0 || number > maxFieldNumber {
			return fmt.Errorf("%w: %s field number %d at offset %d", ErrWireType, descriptor.FullName(), number, offset)
		}
		if wireType == wireStart || wireType == wireEnd {
			return fmt.Errorf("%w: %s field %d at offset %d", ErrGroup, descriptor.FullName(), number, offset)
		}
		if wireType > wireFixed32 {
			return fmt.Errorf("%w: %s field %d has wire type %d", ErrWireType, descriptor.FullName(), number, wireType)
		}

		field := fields.ByNumber(protoreflect.FieldNumber(number))
		if field == nil || field.IsExtension() || field.IsWeak() {
			return fmt.Errorf("%w: %s field %d at offset %d", ErrUnknownField, descriptor.FullName(), number, offset)
		}
		if field.IsMap() || field.Kind() == protoreflect.GroupKind || field.IsPlaceholder() || field.IsWeak() {
			return fmt.Errorf("%w: field %s", ErrInvalidDescriptor, field.FullName())
		}
		index := field.Index()
		if index < 0 || index >= fields.Len() {
			return fmt.Errorf("%w: field %s has invalid descriptor index", ErrInvalidDescriptor, field.FullName())
		}

		packed := field.IsList() && isPackable(field.Kind()) && wireType == wireBytes
		expectedWire, ok := kindWireType(field.Kind())
		if !ok || (!packed && wireType != expectedWire) {
			return fmt.Errorf("%w: field %s has wire type %d, want %d", ErrWireType, field.FullName(), wireType, expectedWire)
		}
		if field.Cardinality() != protoreflect.Repeated {
			if seen[index] {
				return fmt.Errorf("%w: field %s", ErrDuplicateField, field.FullName())
			}
			seen[index] = true
		}
		if oneof := field.ContainingOneof(); oneof != nil {
			oneofIndex := oneof.Index()
			if oneofIndex < 0 || oneofIndex >= oneofs.Len() {
				return fmt.Errorf("%w: oneof %s has invalid descriptor index", ErrInvalidDescriptor, oneof.FullName())
			}
			if oneofSeen[oneofIndex] {
				return fmt.Errorf("%w: oneof %s", ErrOneofConflict, oneof.FullName())
			}
			oneofSeen[oneofIndex] = true
		}
		if s.totalFields >= s.limits.MaxTotalFields {
			return fmt.Errorf("%w: field %s", ErrTooManyFields, field.FullName())
		}
		s.totalFields++

		valueOffset := offset + tagBytes
		if packed {
			payload, consumed, err := consumeBytes(data[valueOffset:])
			if err != nil {
				return fmt.Errorf("field %s at offset %d: %w", field.FullName(), valueOffset, err)
			}
			if err := addFieldBytes(fieldBytes, index, len(payload), s.limits.fieldBytes(field), field); err != nil {
				return err
			}
			remainingItems := s.limits.repeatedItems(field) - repeatedItems[index]
			count, err := scanPacked(payload, field, remainingItems)
			if err != nil {
				return err
			}
			if err := addRepeatedItems(repeatedItems, index, count, s.limits.repeatedItems(field), field); err != nil {
				return err
			}
			offset = valueOffset + consumed
			continue
		}

		if field.Cardinality() == protoreflect.Repeated {
			if err := addRepeatedItems(repeatedItems, index, 1, s.limits.repeatedItems(field), field); err != nil {
				return err
			}
		}
		consumed, valueBytes, payload, err := consumeFieldValue(data[valueOffset:], wireType)
		if err != nil {
			return fmt.Errorf("field %s at offset %d: %w", field.FullName(), valueOffset, err)
		}
		if err := addFieldBytes(fieldBytes, index, valueBytes, s.limits.fieldBytes(field), field); err != nil {
			return err
		}
		if err := validateValue(field, wireType, payload); err != nil {
			return err
		}
		if field.Kind() == protoreflect.MessageKind {
			messageDescriptor := field.Message()
			if messageDescriptor == nil || messageDescriptor.IsPlaceholder() {
				return fmt.Errorf("%w: message field %s has no linked descriptor", ErrInvalidDescriptor, field.FullName())
			}
			if err := s.scanMessage(payload, messageDescriptor, depth+1); err != nil {
				return fmt.Errorf("field %s: %w", field.FullName(), err)
			}
		}
		offset = valueOffset + consumed
	}
	return nil
}

func addFieldBytes(totals []int, index, amount, limit int, field protoreflect.FieldDescriptor) error {
	if amount < 0 || totals[index] > limit-amount {
		return fmt.Errorf("%w: field %s exceeds %d bytes", ErrFieldTooLarge, field.FullName(), limit)
	}
	totals[index] += amount
	return nil
}

func addRepeatedItems(totals []int, index, amount, limit int, field protoreflect.FieldDescriptor) error {
	if amount < 0 || totals[index] > limit-amount {
		return fmt.Errorf("%w: field %s exceeds %d items", ErrTooManyRepeatedItems, field.FullName(), limit)
	}
	totals[index] += amount
	return nil
}

func consumeFieldValue(data []byte, wireType uint64) (consumed int, valueBytes int, payload []byte, err error) {
	switch wireType {
	case wireVarint:
		_, size, varintErr := consumeMinimalVarint(data)
		if varintErr != nil {
			return 0, 0, nil, varintErr
		}
		return size, size, data[:size], nil
	case wireFixed64:
		if len(data) < 8 {
			return 0, 0, nil, ErrTruncated
		}
		return 8, 8, data[:8], nil
	case wireBytes:
		value, size, bytesErr := consumeBytes(data)
		if bytesErr != nil {
			return 0, 0, nil, bytesErr
		}
		return size, len(value), value, nil
	case wireFixed32:
		if len(data) < 4 {
			return 0, 0, nil, ErrTruncated
		}
		return 4, 4, data[:4], nil
	default:
		return 0, 0, nil, ErrWireType
	}
}

func consumeBytes(data []byte) ([]byte, int, error) {
	length, prefixBytes, err := consumeMinimalVarint(data)
	if err != nil {
		return nil, 0, err
	}
	remaining := data[prefixBytes:]
	if length > uint64(len(remaining)) {
		return nil, 0, ErrTruncated
	}
	valueLength := int(length)
	return remaining[:valueLength], prefixBytes + valueLength, nil
}

func consumeMinimalVarint(data []byte) (uint64, int, error) {
	var value uint64
	for index := 0; index < 10; index++ {
		if index >= len(data) {
			return 0, 0, ErrTruncated
		}
		current := data[index]
		if index == 9 && current > 1 {
			return 0, 0, ErrVarintOverflow
		}
		value |= uint64(current&0x7f) << (7 * index)
		if current&0x80 == 0 {
			size := index + 1
			if minimalVarintSize(value) != size {
				return 0, 0, ErrNonMinimalVarint
			}
			return value, size, nil
		}
	}
	return 0, 0, ErrVarintOverflow
}

func minimalVarintSize(value uint64) int {
	size := 1
	for value >= 0x80 {
		value >>= 7
		size++
	}
	return size
}

func kindWireType(kind protoreflect.Kind) (uint64, bool) {
	switch kind {
	case protoreflect.BoolKind, protoreflect.EnumKind,
		protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Uint32Kind,
		protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Uint64Kind:
		return wireVarint, true
	case protoreflect.Fixed64Kind, protoreflect.Sfixed64Kind, protoreflect.DoubleKind:
		return wireFixed64, true
	case protoreflect.StringKind, protoreflect.BytesKind, protoreflect.MessageKind:
		return wireBytes, true
	case protoreflect.Fixed32Kind, protoreflect.Sfixed32Kind, protoreflect.FloatKind:
		return wireFixed32, true
	default:
		return 0, false
	}
}

func isPackable(kind protoreflect.Kind) bool {
	_, ok := kindWireType(kind)
	return ok && kind != protoreflect.StringKind && kind != protoreflect.BytesKind && kind != protoreflect.MessageKind
}

func scanPacked(payload []byte, field protoreflect.FieldDescriptor, maxItems int) (int, error) {
	wireType, ok := kindWireType(field.Kind())
	if !ok || wireType == wireBytes {
		return 0, fmt.Errorf("%w: field %s is not packable", ErrMalformedPacked, field.FullName())
	}
	switch wireType {
	case wireVarint:
		count := 0
		for offset := 0; offset < len(payload); {
			if count >= maxItems {
				return 0, fmt.Errorf("%w: field %s exceeds %d items", ErrTooManyRepeatedItems, field.FullName(), maxItems)
			}
			_, size, err := consumeMinimalVarint(payload[offset:])
			if err != nil {
				return 0, fmt.Errorf("%w: field %s element %d: %w", ErrMalformedPacked, field.FullName(), count, err)
			}
			if err := validateValue(field, wireVarint, payload[offset:offset+size]); err != nil {
				return 0, err
			}
			offset += size
			count++
		}
		return count, nil
	case wireFixed32:
		if len(payload)%4 != 0 {
			return 0, fmt.Errorf("%w: field %s fixed32 payload has %d bytes", ErrMalformedPacked, field.FullName(), len(payload))
		}
		count := len(payload) / 4
		if count > maxItems {
			return 0, fmt.Errorf("%w: field %s exceeds %d items", ErrTooManyRepeatedItems, field.FullName(), maxItems)
		}
		return count, nil
	case wireFixed64:
		if len(payload)%8 != 0 {
			return 0, fmt.Errorf("%w: field %s fixed64 payload has %d bytes", ErrMalformedPacked, field.FullName(), len(payload))
		}
		count := len(payload) / 8
		if count > maxItems {
			return 0, fmt.Errorf("%w: field %s exceeds %d items", ErrTooManyRepeatedItems, field.FullName(), maxItems)
		}
		return count, nil
	default:
		return 0, fmt.Errorf("%w: field %s", ErrMalformedPacked, field.FullName())
	}
}

func validateValue(field protoreflect.FieldDescriptor, wireType uint64, payload []byte) error {
	switch field.Kind() {
	case protoreflect.StringKind:
		if !utf8.Valid(payload) {
			return fmt.Errorf("%w: field %s", ErrInvalidUTF8, field.FullName())
		}
	case protoreflect.BoolKind, protoreflect.EnumKind, protoreflect.Int32Kind,
		protoreflect.Sint32Kind, protoreflect.Uint32Kind,
		protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Uint64Kind:
		if wireType != wireVarint {
			return fmt.Errorf("%w: field %s", ErrWireType, field.FullName())
		}
		value, size, err := consumeMinimalVarint(payload)
		if err != nil || size != len(payload) {
			if err == nil {
				err = ErrInvalidValue
			}
			return fmt.Errorf("field %s: %w", field.FullName(), err)
		}
		switch field.Kind() {
		case protoreflect.BoolKind:
			if value > 1 {
				return fmt.Errorf("%w: bool field %s has value %d", ErrInvalidValue, field.FullName(), value)
			}
		case protoreflect.Uint32Kind, protoreflect.Sint32Kind:
			if value > maxUint32Value {
				return fmt.Errorf("%w: 32-bit field %s overflows", ErrInvalidValue, field.FullName())
			}
		case protoreflect.Int32Kind:
			if _, ok := decodeInt32(value); !ok {
				return fmt.Errorf("%w: int32 field %s overflows", ErrInvalidValue, field.FullName())
			}
		case protoreflect.EnumKind:
			number, ok := decodeInt32(value)
			if !ok {
				return fmt.Errorf("%w: enum field %s overflows", ErrInvalidValue, field.FullName())
			}
			enum := field.Enum()
			if enum == nil || enum.IsPlaceholder() {
				return fmt.Errorf("%w: enum field %s has no linked descriptor", ErrInvalidDescriptor, field.FullName())
			}
			if enum.Values().ByNumber(protoreflect.EnumNumber(number)) == nil {
				return fmt.Errorf("%w: field %s has number %d", ErrUnknownEnum, field.FullName(), number)
			}
		}
	}
	return nil
}

func decodeInt32(value uint64) (int32, bool) {
	if value <= maxInt32Value {
		return int32(value), true
	}
	if value >= minInt32Encoding {
		return int32(uint32(value)), true
	}
	return 0, false
}
