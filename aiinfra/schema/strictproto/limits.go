// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package strictproto

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/reflect/protoreflect"
)

var (
	ErrInvalidLimits         = errors.New("strict protobuf: invalid limits")
	ErrInvalidDescriptor     = errors.New("strict protobuf: invalid or unsupported descriptor")
	ErrDescriptorMismatch    = errors.New("strict protobuf: descriptor mismatch")
	ErrNilTarget             = errors.New("strict protobuf: nil unmarshal target")
	ErrMessageTooLarge       = errors.New("strict protobuf: message byte limit exceeded")
	ErrFieldTooLarge         = errors.New("strict protobuf: field byte limit exceeded")
	ErrTooManyFields         = errors.New("strict protobuf: total field limit exceeded")
	ErrTooManyRepeatedItems  = errors.New("strict protobuf: repeated item limit exceeded")
	ErrDepthExceeded         = errors.New("strict protobuf: nesting depth exceeded")
	ErrUnknownField          = errors.New("strict protobuf: unknown field")
	ErrUnknownEnum           = errors.New("strict protobuf: unknown enum number")
	ErrWireType              = errors.New("strict protobuf: wire type mismatch")
	ErrGroup                 = errors.New("strict protobuf: groups are forbidden")
	ErrDuplicateField        = errors.New("strict protobuf: duplicate singular field")
	ErrOneofConflict         = errors.New("strict protobuf: duplicate or conflicting oneof")
	ErrInvalidValue          = errors.New("strict protobuf: invalid scalar value")
	ErrInvalidUTF8           = errors.New("strict protobuf: invalid UTF-8 string")
	ErrTruncated             = errors.New("strict protobuf: truncated wire value")
	ErrVarintOverflow        = errors.New("strict protobuf: varint overflow")
	ErrNonMinimalVarint      = errors.New("strict protobuf: non-minimal varint")
	ErrMalformedPacked       = errors.New("strict protobuf: malformed packed field")
	ErrUnknownAfterUnmarshal = errors.New("strict protobuf: unknown fields after unmarshal")
	ErrNilRepeatedMessage    = errors.New("strict protobuf: nil repeated message")
)

// Limits bounds work and allocations performed while validating one wire
// message. All five global limits are mandatory and strictly positive.
//
// Per-descriptor limits are installed with the With*Limit methods. Their maps
// are deliberately private and copy-on-write: a Limits value can therefore be
// retained by a production receiver without exposing mutable map aliases.
//
// MaxFieldBytes counts cumulative wire-value bytes for one field in one
// message instance. Tags and length prefixes are covered by MaxMessageBytes.
// MaxTotalFields counts wire field occurrences across the complete message
// tree. The root message is at depth one.
type Limits struct {
	MaxMessageBytes    int
	MaxFieldBytes      int
	MaxTotalFields     int
	MaxDepth           int
	MaxRepeatedItems   int
	messageByteLimits  map[protoreflect.FullName]int
	fieldByteLimits    map[protoreflect.FullName]int
	repeatedItemLimits map[protoreflect.FullName]int
}

// WithMessageByteLimit returns an independent Limits value with a narrower
// limit for one reachable message descriptor. Invalid, widening, misspelled,
// or unreachable names are rejected when the limits are bound to a root
// descriptor by Preflight or Unmarshal.
func (l Limits) WithMessageByteLimit(name protoreflect.FullName, value int) Limits {
	l.messageByteLimits = cloneOverrideWith(l.messageByteLimits, name, value)
	return l
}

// WithFieldByteLimit returns an independent Limits value with a narrower
// cumulative byte limit for one reachable field descriptor.
func (l Limits) WithFieldByteLimit(name protoreflect.FullName, value int) Limits {
	l.fieldByteLimits = cloneOverrideWith(l.fieldByteLimits, name, value)
	return l
}

// WithRepeatedItemLimit returns an independent Limits value with a narrower
// item limit for one reachable repeated field descriptor.
func (l Limits) WithRepeatedItemLimit(name protoreflect.FullName, value int) Limits {
	l.repeatedItemLimits = cloneOverrideWith(l.repeatedItemLimits, name, value)
	return l
}

func cloneOverrideWith(source map[protoreflect.FullName]int, name protoreflect.FullName, value int) map[protoreflect.FullName]int {
	cloned := make(map[protoreflect.FullName]int, len(source)+1)
	for existingName, existingValue := range source {
		cloned[existingName] = existingValue
	}
	cloned[name] = value
	return cloned
}

// Validate checks that all limits fail closed and that overrides only narrow
// the corresponding global bound.
func (l Limits) Validate() error {
	if l.MaxMessageBytes <= 0 || l.MaxFieldBytes <= 0 || l.MaxTotalFields <= 0 || l.MaxDepth <= 0 || l.MaxRepeatedItems <= 0 {
		return fmt.Errorf("%w: every global limit must be positive", ErrInvalidLimits)
	}
	if err := validateOverrides("message bytes", l.messageByteLimits, l.MaxMessageBytes); err != nil {
		return err
	}
	if err := validateOverrides("field bytes", l.fieldByteLimits, l.MaxFieldBytes); err != nil {
		return err
	}
	if err := validateOverrides("repeated items", l.repeatedItemLimits, l.MaxRepeatedItems); err != nil {
		return err
	}
	return nil
}

// validateFor binds override names to the exact descriptor graph. This turns
// typos and message/field-category mistakes into errors instead of silently
// falling back to a wider global limit.
func (l Limits) validateFor(root protoreflect.MessageDescriptor) error {
	if err := l.Validate(); err != nil {
		return err
	}
	if root == nil || root.IsPlaceholder() {
		return fmt.Errorf("%w: missing root message descriptor", ErrInvalidDescriptor)
	}
	messages := make(map[protoreflect.FullName]struct{})
	fields := make(map[protoreflect.FullName]protoreflect.FieldDescriptor)
	var visit func(protoreflect.MessageDescriptor) error
	visit = func(message protoreflect.MessageDescriptor) error {
		if message == nil || message.IsPlaceholder() {
			return fmt.Errorf("%w: missing reachable message descriptor", ErrInvalidDescriptor)
		}
		if _, seen := messages[message.FullName()]; seen {
			return nil
		}
		messages[message.FullName()] = struct{}{}
		declared := message.Fields()
		for index := 0; index < declared.Len(); index++ {
			field := declared.Get(index)
			fields[field.FullName()] = field
			if field.Kind() == protoreflect.MessageKind {
				if err := visit(field.Message()); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := visit(root); err != nil {
		return err
	}
	for name := range l.messageByteLimits {
		if _, ok := messages[name]; !ok {
			return fmt.Errorf("%w: message byte override %q is not reachable from %s", ErrInvalidLimits, name, root.FullName())
		}
	}
	for name := range l.fieldByteLimits {
		if _, ok := fields[name]; !ok {
			return fmt.Errorf("%w: field byte override %q is not reachable from %s", ErrInvalidLimits, name, root.FullName())
		}
	}
	for name := range l.repeatedItemLimits {
		field, ok := fields[name]
		if !ok || !field.IsList() {
			return fmt.Errorf("%w: repeated item override %q is not a reachable repeated field of %s", ErrInvalidLimits, name, root.FullName())
		}
	}
	return nil
}

func validateOverrides(label string, overrides map[protoreflect.FullName]int, global int) error {
	for name, value := range overrides {
		if !name.IsValid() || value <= 0 || value > global {
			return fmt.Errorf("%w: %s override %q=%d outside 1..%d", ErrInvalidLimits, label, name, value, global)
		}
	}
	return nil
}

func (l Limits) messageBytes(descriptor protoreflect.MessageDescriptor) int {
	if value, ok := l.messageByteLimits[descriptor.FullName()]; ok {
		return value
	}
	return l.MaxMessageBytes
}

func (l Limits) fieldBytes(descriptor protoreflect.FieldDescriptor) int {
	if value, ok := l.fieldByteLimits[descriptor.FullName()]; ok {
		return value
	}
	return l.MaxFieldBytes
}

func (l Limits) repeatedItems(descriptor protoreflect.FieldDescriptor) int {
	if value, ok := l.repeatedItemLimits[descriptor.FullName()]; ok {
		return value
	}
	return l.MaxRepeatedItems
}
