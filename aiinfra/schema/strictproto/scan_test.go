// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package strictproto

import (
	"bytes"
	"errors"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

func TestPreflightAcceptsOrderIndependentPackedAndUnpackedValues(t *testing.T) {
	descriptor := strictTestDescriptor(t)
	child := wireVarintField(1, 7)
	packedNumbers := protowire.AppendVarint(nil, 1)
	packedNumbers = protowire.AppendVarint(packedNumbers, 2)
	packedFlags := []byte{0, 1}
	packedModes := []byte{0, 1}
	packedFixed32 := protowire.AppendFixed32(nil, 11)
	packedFixed32 = protowire.AppendFixed32(packedFixed32, 22)
	packedFixed64 := protowire.AppendFixed64(nil, 33)
	packedSigned := []byte{1, 2}

	data := appendFields(
		wireBytesField(11, []byte("hello, 世界")),
		wireBytesField(1, packedNumbers),
		wireVarintField(1, 3),
		wireBytesField(2, packedFlags),
		wireVarintField(2, 1),
		wireBytesField(3, packedModes),
		wireVarintField(3, 1),
		wireBytesField(4, packedFixed32),
		wireBytesField(5, packedSigned),
		wireBytesField(6, child),
		wireBytesField(7, child),
		wireBytesField(7, nil),
		wireBytesField(8, nil),
		wireVarintField(9, 42),
		wireBytesField(12, []byte{1, 2, 3}),
		wireVarintField(13, ^uint64(0)),
		wireBytesField(14, packedFixed64),
		wireBytesField(15, []byte{4, 5}),
		wireVarintField(15, 6),
	)
	if err := Preflight(data, descriptor, testLimits()); err != nil {
		t.Fatal(err)
	}
}

func TestPreflightRejectsMalformedOrAmbiguousWire(t *testing.T) {
	descriptor := strictTestDescriptor(t)
	child := wireVarintField(1, 1)
	overflow := append(bytes.Repeat([]byte{0x80}, 9), 0x02)
	truncatedVarint := []byte{0x80}

	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"unknown root field", wireVarintField(99, 1), ErrUnknownField},
		{"unknown nested field", wireBytesField(6, wireVarintField(2, 1)), ErrUnknownField},
		{"wire type mismatch", wireFixed32Field(1, 1), ErrWireType},
		{"start group", protowire.AppendTag(nil, 6, protowire.StartGroupType), ErrGroup},
		{"end group", protowire.AppendTag(nil, 6, protowire.EndGroupType), ErrGroup},
		{"duplicate singular nested", appendFields(wireBytesField(6, child), wireBytesField(6, child)), ErrDuplicateField},
		{"duplicate optional", appendFields(wireBytesField(8, nil), wireBytesField(8, []byte("x"))), ErrDuplicateField},
		{"oneof conflict", appendFields(wireVarintField(9, 1), wireBytesField(10, []byte("x"))), ErrOneofConflict},
		{"oneof duplicate", appendFields(wireVarintField(9, 1), wireVarintField(9, 2)), ErrDuplicateField},
		{"nested duplicate", wireBytesField(6, appendFields(child, child)), ErrDuplicateField},
		{"invalid bool", wireVarintField(2, 2), ErrInvalidValue},
		{"uint32 overflow", wireVarintField(1, maxUint32Value+1), ErrInvalidValue},
		{"int32 overflow", wireVarintField(13, maxInt32Value+1), ErrInvalidValue},
		{"unknown enum", wireVarintField(3, 2), ErrUnknownEnum},
		{"invalid UTF-8", wireBytesField(11, []byte{0xff}), ErrInvalidUTF8},
		{"truncated fixed32", append(protowire.AppendTag(nil, 4, protowire.Fixed32Type), 1, 2, 3), ErrTruncated},
		{"truncated payload", appendFields(protowire.AppendTag(nil, 11, protowire.BytesType), []byte{2, 'x'}), ErrTruncated},
		{"zero field number", []byte{0}, ErrWireType},
		{"invalid wire type", []byte{0x0e}, ErrWireType},
		{"truncated tag", truncatedVarint, ErrTruncated},
		{"overflow tag", overflow, ErrVarintOverflow},
		{"truncated value", append(protowire.AppendTag(nil, 1, protowire.VarintType), truncatedVarint...), ErrTruncated},
		{"overflow value", append(protowire.AppendTag(nil, 1, protowire.VarintType), overflow...), ErrVarintOverflow},
		{"overflow length", append(protowire.AppendTag(nil, 11, protowire.BytesType), overflow...), ErrVarintOverflow},
		{"non-minimal tag", []byte{0x88, 0x00, 0x01}, ErrNonMinimalVarint},
		{"non-minimal value", []byte{0x08, 0x81, 0x00}, ErrNonMinimalVarint},
		{"non-minimal length", []byte{0x5a, 0x81, 0x00, 'x'}, ErrNonMinimalVarint},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := Preflight(test.data, descriptor, testLimits())
			if !errors.Is(err, test.want) {
				t.Fatalf("Preflight() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestPreflightInspectsPackedScalarPayloads(t *testing.T) {
	descriptor := strictTestDescriptor(t)
	overflow := protowire.AppendVarint(nil, maxUint32Value+1)
	tests := []struct {
		name  string
		field protowire.Number
		body  []byte
		want  error
	}{
		{"invalid bool", 2, []byte{0, 2}, ErrInvalidValue},
		{"unknown enum", 3, []byte{0, 2}, ErrUnknownEnum},
		{"uint32 overflow", 1, overflow, ErrInvalidValue},
		{"non-minimal varint", 1, []byte{0x81, 0x00}, ErrNonMinimalVarint},
		{"truncated varint", 1, []byte{0x80}, ErrTruncated},
		{"fixed32 misalignment", 4, make([]byte, 5), ErrMalformedPacked},
		{"fixed64 misalignment", 14, make([]byte, 9), ErrMalformedPacked},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := Preflight(wireBytesField(test.field, test.body), descriptor, testLimits())
			if !errors.Is(err, test.want) {
				t.Fatalf("Preflight() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestPreflightEnforcesAllResourceBounds(t *testing.T) {
	descriptor := strictTestDescriptor(t)
	childField := descriptor.Fields().ByName("child")
	blobField := descriptor.Fields().ByName("blob")
	numbersField := descriptor.Fields().ByName("numbers")
	child := wireVarintField(1, 128)
	threeNumbers := appendFields(wireVarintField(1, 1), wireVarintField(1, 2), wireVarintField(1, 3))

	tests := []struct {
		name   string
		data   []byte
		mutate func(*Limits)
		want   error
	}{
		{
			name: "root message bytes", data: wireBytesField(12, []byte{1, 2, 3}), want: ErrMessageTooLarge,
			mutate: func(l *Limits) { l.MaxMessageBytes = 4 },
		},
		{
			name: "field bytes", data: wireBytesField(12, []byte{1, 2, 3}), want: ErrFieldTooLarge,
			mutate: func(l *Limits) { l.MaxFieldBytes = 2 },
		},
		{
			name: "cumulative field bytes", data: threeNumbers, want: ErrFieldTooLarge,
			mutate: func(l *Limits) { l.MaxFieldBytes = 2 },
		},
		{
			name: "total fields", data: appendFields(wireVarintField(1, 1), wireVarintField(2, 1)), want: ErrTooManyFields,
			mutate: func(l *Limits) { l.MaxTotalFields = 1 },
		},
		{
			name: "unpacked repeated count", data: threeNumbers, want: ErrTooManyRepeatedItems,
			mutate: func(l *Limits) { l.MaxRepeatedItems = 2 },
		},
		{
			name: "packed repeated count", data: wireBytesField(1, []byte{1, 2, 3}), want: ErrTooManyRepeatedItems,
			mutate: func(l *Limits) { l.MaxRepeatedItems = 2 },
		},
		{
			name: "depth", data: wireBytesField(6, child), want: ErrDepthExceeded,
			mutate: func(l *Limits) { l.MaxDepth = 1 },
		},
		{
			name: "message override", data: wireBytesField(6, child), want: ErrMessageTooLarge,
			mutate: func(l *Limits) {
				*l = l.WithMessageByteLimit(childField.Message().FullName(), 2)
			},
		},
		{
			name: "field override", data: wireBytesField(12, []byte{1, 2, 3}), want: ErrFieldTooLarge,
			mutate: func(l *Limits) {
				*l = l.WithFieldByteLimit(blobField.FullName(), 2)
			},
		},
		{
			name: "repeated override", data: threeNumbers, want: ErrTooManyRepeatedItems,
			mutate: func(l *Limits) {
				*l = l.WithRepeatedItemLimit(numbersField.FullName(), 2)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			limits := testLimits()
			test.mutate(&limits)
			err := Preflight(test.data, descriptor, limits)
			if !errors.Is(err, test.want) {
				t.Fatalf("Preflight() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestLimitsRejectInvalidOrWideningValues(t *testing.T) {
	descriptor := strictTestDescriptor(t)
	field := descriptor.Fields().ByName("blob")
	tests := []Limits{
		{},
		func() Limits { value := testLimits(); value.MaxDepth = 0; return value }(),
		func() Limits {
			value := testLimits()
			value = value.WithFieldByteLimit(field.FullName(), value.MaxFieldBytes+1)
			return value
		}(),
		func() Limits {
			value := testLimits()
			value = value.WithFieldByteLimit("not a full name", 1)
			return value
		}(),
		func() Limits {
			value := testLimits()
			value = value.WithMessageByteLimit(field.FullName(), 1)
			return value
		}(),
		func() Limits {
			value := testLimits()
			value = value.WithRepeatedItemLimit(field.FullName(), 1)
			return value
		}(),
	}
	for index, limits := range tests {
		if err := Preflight(nil, descriptor, limits); !errors.Is(err, ErrInvalidLimits) {
			t.Fatalf("case %d error = %v", index, err)
		}
	}
}

func TestLimitOverridesAreCopyOnWrite(t *testing.T) {
	descriptor := strictTestDescriptor(t)
	field := descriptor.Fields().ByName("blob")
	base := testLimits().WithFieldByteLimit(field.FullName(), 2)
	widenedCopy := base.WithFieldByteLimit(field.FullName(), 3)
	data := wireBytesField(12, []byte{1, 2, 3})
	if err := Preflight(data, descriptor, base); !errors.Is(err, ErrFieldTooLarge) {
		t.Fatalf("base error = %v", err)
	}
	if err := Preflight(data, descriptor, widenedCopy); err != nil {
		t.Fatalf("copy unexpectedly inherited base map mutation: %v", err)
	}
}
