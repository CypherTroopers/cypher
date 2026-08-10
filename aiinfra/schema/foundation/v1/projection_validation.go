// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package foundationv1

import (
	"errors"
	"fmt"

	"github.com/cypherium/cypher/aiinfra/ccse"
)

var (
	ErrInvalidEnumValue = errors.New("aiinfra foundation: invalid enum value")
	ErrFieldLimit       = errors.New("aiinfra foundation: registry field limit exceeded")
)

// OptionalFixedBytes16 preserves absence independently from an all-zero ID.
type OptionalFixedBytes16 struct {
	Present bool
	Value   [16]byte
}

// OptionalFixedBytes32 preserves absence independently from an all-zero digest.
type OptionalFixedBytes32 struct {
	Present bool
	Value   [32]byte
}

func validateRequiredStringField(name, value string, maxEncodedBytes int) error {
	if value == "" {
		return fmt.Errorf("%w: %s is empty", ErrInvalidProjectionValue, name)
	}
	if _, err := ccse.Marshal(maxEncodedBytes, func(out *ccse.Encoder) { out.String(value) }); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrFieldLimit, name, err)
	}
	return nil
}

func validateOptionalStringField(name string, value OptionalString, maxEncodedBytes int, allowPresentEmpty bool) error {
	if !value.Present && value.Value != "" {
		return fmt.Errorf("%w: %s carries hidden value", ccse.ErrNonCanonicalAbsent, name)
	}
	if value.Present && !allowPresentEmpty && value.Value == "" {
		return fmt.Errorf("%w: present %s is empty", ErrInvalidProjectionValue, name)
	}
	if _, err := ccse.Marshal(maxEncodedBytes, func(out *ccse.Encoder) { out.OptionalString(value.Present, value.Value) }); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrFieldLimit, name, err)
	}
	return nil
}

func canonicalStringSetField(name string, values []string, maxItems, maxEncodedBytes int, required bool) ([][]byte, error) {
	if required && len(values) == 0 {
		return nil, fmt.Errorf("%w: %s is empty", ErrInvalidProjectionValue, name)
	}
	if len(values) > maxItems {
		return nil, fmt.Errorf("%w: %s has %d items, max %d", ErrFieldLimit, name, len(values), maxItems)
	}
	elements := make([][]byte, 0, len(values))
	for index, value := range values {
		if value == "" {
			return nil, fmt.Errorf("%w: %s[%d] is empty", ErrInvalidProjectionValue, name, index)
		}
		encoded, err := ccse.Marshal(maxEncodedBytes, func(out *ccse.Encoder) { out.String(value) })
		if err != nil {
			return nil, fmt.Errorf("%w: %s[%d]: %w", ErrFieldLimit, name, index, err)
		}
		elements = append(elements, encoded)
	}
	if _, err := ccse.Marshal(maxEncodedBytes, func(out *ccse.Encoder) { out.EncodedSet(elements) }); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrFieldLimit, name, err)
	}
	return elements, nil
}

func canonicalDigestSetField(name string, values [][32]byte, maxItems, maxEncodedBytes int, required bool) ([][]byte, error) {
	if required && len(values) == 0 {
		return nil, fmt.Errorf("%w: %s is empty", ErrInvalidProjectionValue, name)
	}
	if len(values) > maxItems {
		return nil, fmt.Errorf("%w: %s has %d items, max %d", ErrFieldLimit, name, len(values), maxItems)
	}
	for index, value := range values {
		if isZero32(value) {
			return nil, fmt.Errorf("%w: %s[%d] is zero", ErrInvalidProjectionValue, name, index)
		}
	}
	elements, err := canonicalDigestSet(values)
	if err != nil {
		return nil, err
	}
	if _, err := ccse.Marshal(maxEncodedBytes, func(out *ccse.Encoder) { out.EncodedSet(elements) }); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrFieldLimit, name, err)
	}
	return elements, nil
}

func canonicalMessageSetField(name string, elements [][]byte, maxItems, maxEncodedBytes int, required bool) ([][]byte, error) {
	if required && len(elements) == 0 {
		return nil, fmt.Errorf("%w: %s is empty", ErrInvalidProjectionValue, name)
	}
	if len(elements) > maxItems {
		return nil, fmt.Errorf("%w: %s has %d items, max %d", ErrFieldLimit, name, len(elements), maxItems)
	}
	if _, err := ccse.Marshal(maxEncodedBytes, func(out *ccse.Encoder) { out.EncodedSet(elements) }); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrFieldLimit, name, err)
	}
	return elements, nil
}

func canonicalUint32SetField(name string, values []uint32, maxItems, maxEncodedBytes int, required bool) ([][]byte, error) {
	if required && len(values) == 0 {
		return nil, fmt.Errorf("%w: %s is empty", ErrInvalidProjectionValue, name)
	}
	if len(values) > maxItems {
		return nil, fmt.Errorf("%w: %s has %d items, max %d", ErrFieldLimit, name, len(values), maxItems)
	}
	elements, err := encodeUint32Set(values)
	if err != nil {
		return nil, err
	}
	if _, err := ccse.Marshal(maxEncodedBytes, func(out *ccse.Encoder) { out.EncodedSet(elements) }); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrFieldLimit, name, err)
	}
	return elements, nil
}

func validateRequiredFixed16(name string, value [16]byte) error {
	if isZero16(value) {
		return fmt.Errorf("%w: %s is zero", ErrInvalidProjectionValue, name)
	}
	return nil
}

func validateRequiredFixed32(name string, value [32]byte) error {
	if isZero32(value) {
		return fmt.Errorf("%w: %s is zero", ErrInvalidProjectionValue, name)
	}
	return nil
}

func validateOptionalFixed16(name string, value OptionalFixedBytes16) error {
	if !value.Present && !isZero16(value.Value) {
		return fmt.Errorf("%w: %s carries hidden value", ccse.ErrNonCanonicalAbsent, name)
	}
	if value.Present && isZero16(value.Value) {
		return fmt.Errorf("%w: present %s is zero", ErrInvalidProjectionValue, name)
	}
	return nil
}

func validateOptionalFixed32(name string, value OptionalFixedBytes32) error {
	if !value.Present && !isZero32(value.Value) {
		return fmt.Errorf("%w: %s carries hidden value", ccse.ErrNonCanonicalAbsent, name)
	}
	if value.Present && isZero32(value.Value) {
		return fmt.Errorf("%w: present %s is zero", ErrInvalidProjectionValue, name)
	}
	return nil
}

func validateRequiredTimeRange(name string, start, end int64) error {
	if start < 0 || end <= start {
		return fmt.Errorf("%w: %s", ErrInvalidTimeRange, name)
	}
	return nil
}

func validateEnumRange(name string, value, minimum, maximum uint32) error {
	if value < minimum || value > maximum {
		return fmt.Errorf("%w: %s=%d", ErrInvalidEnumValue, name, value)
	}
	return nil
}

func validatePositive(name string, value uint64) error {
	if value == 0 {
		return fmt.Errorf("%w: %s is zero", ErrInvalidProjectionValue, name)
	}
	return nil
}

func validateTimestamp(name string, value int64) error {
	if value < 0 {
		return fmt.Errorf("%w: %s is negative", ErrInvalidTimeRange, name)
	}
	return nil
}

func encodeOptionalFixed16(out *ccse.Encoder, value OptionalFixedBytes16) {
	if !value.Present {
		out.OptionalFixedBytes(false, nil, len(value.Value))
		return
	}
	out.OptionalFixedBytes(true, value.Value[:], len(value.Value))
}

func encodeOptionalFixed32(out *ccse.Encoder, value OptionalFixedBytes32) {
	if !value.Present {
		out.OptionalFixedBytes(false, nil, len(value.Value))
		return
	}
	out.OptionalFixedBytes(true, value.Value[:], len(value.Value))
}
