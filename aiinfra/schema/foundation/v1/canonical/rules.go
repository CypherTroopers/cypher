// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package canonical

import (
	"fmt"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

type projectionRules struct {
	name   string
	limits schema.Limits
	fields []schema.Field
}

func newProjectionRules(name string, limits schema.Limits, fields []schema.Field) (projectionRules, error) {
	if name == "" || limits.MaxPayloadBytes <= 0 || limits.MaxFields != len(fields) || limits.MaxCollectionItems <= 0 || limits.MaxNestingDepth <= 0 {
		return projectionRules{}, fmt.Errorf("%w: invalid rules for %s", ErrCatalogMismatch, name)
	}
	cloned := append([]schema.Field(nil), fields...)
	for index, field := range cloned {
		if field.Order != index+1 || field.Name == "" || field.MaxEncodedBytes <= 0 || field.MaxEncodedBytes > limits.MaxPayloadBytes ||
			field.MaxItems <= 0 || field.MaxItems > limits.MaxCollectionItems || field.Critical == nil {
			return projectionRules{}, fmt.Errorf("%w: invalid field %s[%d]", ErrCatalogMismatch, name, index)
		}
		if (field.Collection == "scalar" && field.MaxItems != 1) || (field.Collection != "scalar" && field.Collection != "set" && field.Collection != "ordered_list") {
			return projectionRules{}, fmt.Errorf("%w: invalid collection rules for %s.%s", ErrCatalogMismatch, name, field.Name)
		}
	}
	return projectionRules{name: name, limits: limits, fields: cloned}, nil
}

type projectionDecoder struct {
	in    *ccse.Decoder
	rules projectionRules
	next  int
	err   error
}

func newProjectionDecoder(in *ccse.Decoder, rules projectionRules) *projectionDecoder {
	return &projectionDecoder{in: in, rules: rules}
}

func (d *projectionDecoder) String(order int, name string) string {
	field, ok := d.field(order, name, "string", "required", "scalar")
	if !ok {
		return ""
	}
	limit, err := scalarValueLimit(field, 4)
	if err != nil {
		d.record(err)
		return ""
	}
	value, err := d.in.String(limit)
	d.record(err)
	return value
}

func (d *projectionDecoder) OptionalString(order int, name string) foundationv1.OptionalString {
	field, ok := d.field(order, name, "string", "optional", "scalar")
	if !ok {
		return foundationv1.OptionalString{}
	}
	limit, err := scalarValueLimit(field, 5)
	if err != nil {
		d.record(err)
		return foundationv1.OptionalString{}
	}
	present, value, err := d.in.OptionalString(limit)
	d.record(err)
	return foundationv1.OptionalString{Present: present, Value: value}
}

func (d *projectionDecoder) Bool(order int, name string) bool {
	if !d.fixedScalar(order, name, "bool", 1) {
		return false
	}
	value, err := d.in.Bool()
	d.record(err)
	return value
}

func (d *projectionDecoder) Uint32(order int, name string) uint32 {
	if !d.fixedScalar(order, name, "uint32", 4) {
		return 0
	}
	value, err := d.in.Uint32()
	d.record(err)
	return value
}

func (d *projectionDecoder) Uint64(order int, name string) uint64 {
	if !d.fixedScalar(order, name, "uint64", 8) {
		return 0
	}
	value, err := d.in.Uint64()
	d.record(err)
	return value
}

func (d *projectionDecoder) Int64(order int, name string) int64 {
	if !d.fixedScalar(order, name, "int64", 8) {
		return 0
	}
	value, err := d.in.Int64()
	d.record(err)
	return value
}

func (d *projectionDecoder) OptionalInt64(order int, name string) foundationv1.OptionalInt64 {
	field, ok := d.field(order, name, "int64", "optional", "scalar")
	if !ok || field.MaxEncodedBytes != 9 {
		if ok {
			d.record(fmt.Errorf("%w: %s.%s optional int64 width", ErrCatalogMismatch, d.rules.name, name))
		}
		return foundationv1.OptionalInt64{}
	}
	present, err := d.in.Presence()
	if err != nil || !present {
		d.record(err)
		return foundationv1.OptionalInt64{Present: present}
	}
	value, err := d.in.Int64()
	d.record(err)
	return foundationv1.OptionalInt64{Present: true, Value: value}
}

func (d *projectionDecoder) OptionalUint64(order int, name string) foundationv1.OptionalUint64 {
	field, ok := d.field(order, name, "uint64", "optional", "scalar")
	if !ok || field.MaxEncodedBytes != 9 {
		if ok {
			d.record(fmt.Errorf("%w: %s.%s optional uint64 width", ErrCatalogMismatch, d.rules.name, name))
		}
		return foundationv1.OptionalUint64{}
	}
	present, err := d.in.Presence()
	if err != nil || !present {
		d.record(err)
		return foundationv1.OptionalUint64{Present: present}
	}
	value, err := d.in.Uint64()
	d.record(err)
	return foundationv1.OptionalUint64{Present: true, Value: value}
}

func (d *projectionDecoder) OptionalUint32(order int, name string) foundationv1.OptionalUint32 {
	field, ok := d.field(order, name, "uint32", "optional", "scalar")
	if !ok || field.MaxEncodedBytes != 5 {
		if ok {
			d.record(fmt.Errorf("%w: %s.%s optional uint32 width", ErrCatalogMismatch, d.rules.name, name))
		}
		return foundationv1.OptionalUint32{}
	}
	present, err := d.in.Presence()
	if err != nil || !present {
		d.record(err)
		return foundationv1.OptionalUint32{Present: present}
	}
	value, err := d.in.Uint32()
	d.record(err)
	return foundationv1.OptionalUint32{Present: true, Value: value}
}

func (d *projectionDecoder) Enum(order int, name string, minimum, maximum uint32) uint32 {
	field, ok := d.field(order, name, "enum_uint32", "required", "scalar")
	if !ok || field.MaxEncodedBytes != 4 {
		if ok {
			d.record(fmt.Errorf("%w: %s.%s enum width", ErrCatalogMismatch, d.rules.name, name))
		}
		return 0
	}
	value, err := d.in.Uint32()
	d.record(err)
	if err == nil && (value < minimum || value > maximum) {
		d.record(fmt.Errorf("%w: %s=%d", foundationv1.ErrInvalidEnumValue, name, value))
	}
	return value
}

func (d *projectionDecoder) Fixed16(order int, name string) [16]byte {
	field, ok := d.field(order, name, "fixed_bytes_16", "required", "scalar")
	if !ok || field.MaxEncodedBytes != 20 {
		if ok {
			d.record(fmt.Errorf("%w: %s.%s fixed16 width", ErrCatalogMismatch, d.rules.name, name))
		}
		return [16]byte{}
	}
	value, err := d.in.FixedBytes(16)
	d.record(err)
	var out [16]byte
	copy(out[:], value)
	return out
}

func (d *projectionDecoder) Fixed32(order int, name string) [32]byte {
	field, ok := d.field(order, name, "fixed_bytes_32", "required", "scalar")
	if !ok || field.MaxEncodedBytes != 36 {
		if ok {
			d.record(fmt.Errorf("%w: %s.%s fixed32 width", ErrCatalogMismatch, d.rules.name, name))
		}
		return [32]byte{}
	}
	value, err := d.in.FixedBytes(32)
	d.record(err)
	var out [32]byte
	copy(out[:], value)
	return out
}

func (d *projectionDecoder) OptionalFixed16(order int, name string) foundationv1.OptionalFixedBytes16 {
	field, ok := d.field(order, name, "fixed_bytes_16", "optional", "scalar")
	if !ok || field.MaxEncodedBytes != 21 {
		if ok {
			d.record(fmt.Errorf("%w: %s.%s optional fixed16 width", ErrCatalogMismatch, d.rules.name, name))
		}
		return foundationv1.OptionalFixedBytes16{}
	}
	present, value, err := d.in.OptionalFixedBytes(16)
	d.record(err)
	var out [16]byte
	copy(out[:], value)
	return foundationv1.OptionalFixedBytes16{Present: present, Value: out}
}

func (d *projectionDecoder) OptionalFixed32(order int, name string) foundationv1.OptionalFixedBytes32 {
	field, ok := d.field(order, name, "fixed_bytes_32", "optional", "scalar")
	if !ok || field.MaxEncodedBytes != 37 {
		if ok {
			d.record(fmt.Errorf("%w: %s.%s optional fixed32 width", ErrCatalogMismatch, d.rules.name, name))
		}
		return foundationv1.OptionalFixedBytes32{}
	}
	present, value, err := d.in.OptionalFixedBytes(32)
	d.record(err)
	var out [32]byte
	copy(out[:], value)
	return foundationv1.OptionalFixedBytes32{Present: present, Value: out}
}

func (d *projectionDecoder) StringSet(order int, name string) []string {
	field, ok := d.field(order, name, "string", "required", "set")
	if !ok {
		return nil
	}
	if field.MaxEncodedBytes < 12 {
		d.record(fmt.Errorf("%w: %s.%s string set bound", ErrCatalogMismatch, d.rules.name, name))
		return nil
	}
	values, err := d.in.StringSet(field.MaxItems, field.MaxEncodedBytes-12)
	if err == nil {
		_, err = ccse.Marshal(field.MaxEncodedBytes, func(out *ccse.Encoder) { out.StringSet(values) })
	}
	d.record(err)
	return values
}

func (d *projectionDecoder) Fixed32Set(order int, name string) [][32]byte {
	field, ok := d.field(order, name, "fixed_bytes_32", "required", "set")
	if !ok {
		return nil
	}
	values := make([][32]byte, 0)
	elements := make([][]byte, 0)
	err := d.in.ValidatedSet(field.MaxItems, 36, func(_ int, child *ccse.Decoder) error {
		value, err := child.FixedBytes(32)
		if err != nil {
			return err
		}
		var fixed [32]byte
		copy(fixed[:], value)
		values = append(values, fixed)
		encoded, err := ccse.Marshal(36, func(out *ccse.Encoder) { out.FixedBytes(fixed[:], 32) })
		if err != nil {
			return err
		}
		elements = append(elements, encoded)
		return nil
	})
	if err == nil {
		_, err = ccse.Marshal(field.MaxEncodedBytes, func(out *ccse.Encoder) { out.EncodedSet(elements) })
	}
	d.record(err)
	if err != nil {
		return nil
	}
	return values
}

func (d *projectionDecoder) Uint32Set(order int, name string) []uint32 {
	field, ok := d.field(order, name, "uint32", "required", "set")
	if !ok {
		return nil
	}
	values := make([]uint32, 0)
	elements := make([][]byte, 0)
	err := d.in.ValidatedSet(field.MaxItems, 4, func(_ int, child *ccse.Decoder) error {
		value, err := child.Uint32()
		if err != nil {
			return err
		}
		values = append(values, value)
		encoded, err := ccse.Marshal(4, func(out *ccse.Encoder) { out.Uint32(value) })
		if err != nil {
			return err
		}
		elements = append(elements, encoded)
		return nil
	})
	if err == nil {
		_, err = ccse.Marshal(field.MaxEncodedBytes, func(out *ccse.Encoder) { out.EncodedSet(elements) })
	}
	d.record(err)
	if err != nil {
		return nil
	}
	return values
}

func (d *projectionDecoder) InlineMessage(order int, name, target string) bool {
	field, ok := d.field(order, name, "message", "required", "scalar")
	if !ok {
		return false
	}
	if field.MessageType != target {
		d.record(fmt.Errorf("%w: %s.%s message target", ErrCatalogMismatch, d.rules.name, name))
		return false
	}
	return true
}

func (d *projectionDecoder) MessageSet(order int, name, target string) (schema.Field, bool) {
	field, ok := d.field(order, name, "message", "required", "set")
	if !ok {
		return schema.Field{}, false
	}
	if field.MessageType != target {
		d.record(fmt.Errorf("%w: %s.%s message target", ErrCatalogMismatch, d.rules.name, name))
		return schema.Field{}, false
	}
	return field, true
}

func (d *projectionDecoder) FinishFields() error {
	if d.err != nil {
		return d.err
	}
	if d.next != len(d.rules.fields) {
		return fmt.Errorf("%w: %s decoded %d of %d fields", ErrCatalogMismatch, d.rules.name, d.next, len(d.rules.fields))
	}
	return nil
}

func (d *projectionDecoder) fixedScalar(order int, name, fieldType string, width int) bool {
	field, ok := d.field(order, name, fieldType, "required", "scalar")
	if !ok {
		return false
	}
	if field.MaxEncodedBytes != width {
		d.record(fmt.Errorf("%w: %s.%s width", ErrCatalogMismatch, d.rules.name, name))
		return false
	}
	return true
}

func (d *projectionDecoder) field(order int, name, fieldType, presence, collection string) (schema.Field, bool) {
	if d.err != nil {
		return schema.Field{}, false
	}
	if order != d.next+1 || order <= 0 || order > len(d.rules.fields) {
		d.record(fmt.Errorf("%w: %s field order %d", ErrCatalogMismatch, d.rules.name, order))
		return schema.Field{}, false
	}
	field := d.rules.fields[order-1]
	if field.Order != order || field.Name != name || field.Type != fieldType || field.Presence != presence || field.Collection != collection {
		d.record(fmt.Errorf("%w: %s field %d %s", ErrCatalogMismatch, d.rules.name, order, name))
		return schema.Field{}, false
	}
	d.next = order
	return field, true
}

func (d *projectionDecoder) record(err error) {
	if err != nil && d.err == nil {
		d.err = err
	}
}

func scalarValueLimit(field schema.Field, framingBytes int) (int, error) {
	if field.MaxEncodedBytes < framingBytes {
		return 0, fmt.Errorf("%w: field %s byte bound", ErrCatalogMismatch, field.Name)
	}
	return field.MaxEncodedBytes - framingBytes, nil
}

func enforceMessageSetBound(field schema.Field, elements [][]byte) error {
	_, err := ccse.Marshal(field.MaxEncodedBytes, func(out *ccse.Encoder) { out.EncodedSet(elements) })
	if err != nil {
		return fmt.Errorf("%w: %s: %w", foundationv1.ErrFieldLimit, field.Name, err)
	}
	return nil
}
