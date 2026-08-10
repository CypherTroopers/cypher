// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package strictproto

import (
	"fmt"
	"reflect"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Unmarshal preflights data against expected before permitting the Protobuf
// runtime to allocate decoded values. Target must implement exactly expected;
// matching by full name alone is deliberately insufficient.
//
// A preflight failure leaves target untouched. Once decoding starts, any
// runtime or reflection validation failure resets target so callers cannot use
// a partially validated message.
func Unmarshal(data []byte, target proto.Message, expected protoreflect.MessageDescriptor, limits Limits) error {
	if expected == nil {
		return fmt.Errorf("%w: target=<unknown> expected=<nil>", ErrDescriptorMismatch)
	}
	if err := limits.validateFor(expected); err != nil {
		return err
	}
	// Reject before allocating, then take exactly one bounded snapshot. Both
	// the structural scan and runtime decoder consume this owned copy, so a
	// caller buffer pool or a ProtoReflect hook cannot change wire history in
	// the interval between validation and interpretation.
	rootLimit := limits.messageBytes(expected)
	if len(data) > rootLimit {
		return fmt.Errorf("%w: root has %d bytes, limit %d", ErrMessageTooLarge, len(data), rootLimit)
	}
	owned := append([]byte(nil), data...)
	if isNilMessage(target) {
		return ErrNilTarget
	}
	message := target.ProtoReflect()
	if !message.IsValid() {
		return ErrNilTarget
	}
	if expected == nil || message.Descriptor() != expected {
		return fmt.Errorf("%w: target=%s expected=%v", ErrDescriptorMismatch, message.Descriptor().FullName(), descriptorName(expected))
	}
	if err := preflightOwned(owned, expected, limits); err != nil {
		return err
	}

	proto.Reset(target)
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(owned, target); err != nil {
		proto.Reset(target)
		return fmt.Errorf("strict protobuf: runtime unmarshal: %w", err)
	}
	if err := validateDecoded(target.ProtoReflect(), expected); err != nil {
		proto.Reset(target)
		return err
	}
	return nil
}

func isNilMessage(message proto.Message) bool {
	if message == nil {
		return true
	}
	value := reflect.ValueOf(message)
	return value.Kind() == reflect.Pointer && value.IsNil()
}

func descriptorName(descriptor protoreflect.MessageDescriptor) any {
	if descriptor == nil {
		return "<nil>"
	}
	return descriptor.FullName()
}

func validateDecoded(message protoreflect.Message, expected protoreflect.MessageDescriptor) error {
	if !message.IsValid() {
		return ErrNilTarget
	}
	if expected == nil || message.Descriptor() != expected {
		return fmt.Errorf("%w: decoded=%s expected=%v", ErrDescriptorMismatch, message.Descriptor().FullName(), descriptorName(expected))
	}
	if len(message.GetUnknown()) != 0 {
		return fmt.Errorf("%w: message %s", ErrUnknownAfterUnmarshal, expected.FullName())
	}

	var rangeErr error
	message.Range(func(field protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
		declared := expected.Fields().ByNumber(field.Number())
		if declared == nil || declared != field {
			rangeErr = fmt.Errorf("%w: populated field %s", ErrDescriptorMismatch, field.FullName())
			return false
		}
		return true
	})
	if rangeErr != nil {
		return rangeErr
	}

	fields := expected.Fields()
	for index := 0; index < fields.Len(); index++ {
		field := fields.Get(index)
		if field.IsMap() || field.Kind() == protoreflect.GroupKind || field.IsPlaceholder() || field.IsWeak() {
			return fmt.Errorf("%w: field %s", ErrInvalidDescriptor, field.FullName())
		}
		if field.IsList() {
			list := message.Get(field).List()
			for item := 0; item < list.Len(); item++ {
				value := list.Get(item)
				if err := validateReflectedValue(value, field, true); err != nil {
					return fmt.Errorf("field %s item %d: %w", field.FullName(), item, err)
				}
			}
			continue
		}
		if field.Kind() == protoreflect.MessageKind {
			if !message.Has(field) {
				continue
			}
			if err := validateReflectedValue(message.Get(field), field, false); err != nil {
				return fmt.Errorf("field %s: %w", field.FullName(), err)
			}
			continue
		}
		if field.HasPresence() && !message.Has(field) {
			continue
		}
		if err := validateReflectedValue(message.Get(field), field, false); err != nil {
			return fmt.Errorf("field %s: %w", field.FullName(), err)
		}
	}
	return nil
}

func validateReflectedValue(value protoreflect.Value, field protoreflect.FieldDescriptor, repeated bool) error {
	switch field.Kind() {
	case protoreflect.MessageKind:
		nested := value.Message()
		if !nested.IsValid() {
			if repeated {
				return ErrNilRepeatedMessage
			}
			return ErrNilTarget
		}
		expected := field.Message()
		if expected == nil || nested.Descriptor() != expected {
			return fmt.Errorf("%w: nested=%s expected=%v", ErrDescriptorMismatch, nested.Descriptor().FullName(), descriptorName(expected))
		}
		return validateDecoded(nested, expected)
	case protoreflect.EnumKind:
		enum := field.Enum()
		if enum == nil || enum.IsPlaceholder() {
			return fmt.Errorf("%w: enum field %s", ErrInvalidDescriptor, field.FullName())
		}
		number := value.Enum()
		if enum.Values().ByNumber(number) == nil {
			return fmt.Errorf("%w: field %s has number %d", ErrUnknownEnum, field.FullName(), number)
		}
	case protoreflect.StringKind:
		if !utf8.ValidString(value.String()) {
			return fmt.Errorf("%w: field %s", ErrInvalidUTF8, field.FullName())
		}
	}
	return nil
}
