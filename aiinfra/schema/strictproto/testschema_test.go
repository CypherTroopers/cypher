// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package strictproto

import (
	"sync"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

var (
	testDescriptorOnce sync.Once
	testDescriptor     protoreflect.MessageDescriptor
	testDescriptorErr  error
)

func strictTestDescriptor(t testing.TB) protoreflect.MessageDescriptor {
	t.Helper()
	testDescriptorOnce.Do(func() {
		optional := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
		repeated := descriptorpb.FieldDescriptorProto_LABEL_REPEATED
		uint32Type := descriptorpb.FieldDescriptorProto_TYPE_UINT32
		boolType := descriptorpb.FieldDescriptorProto_TYPE_BOOL
		enumType := descriptorpb.FieldDescriptorProto_TYPE_ENUM
		fixed32Type := descriptorpb.FieldDescriptorProto_TYPE_FIXED32
		sint32Type := descriptorpb.FieldDescriptorProto_TYPE_SINT32
		messageType := descriptorpb.FieldDescriptorProto_TYPE_MESSAGE
		stringType := descriptorpb.FieldDescriptorProto_TYPE_STRING
		uint64Type := descriptorpb.FieldDescriptorProto_TYPE_UINT64
		bytesType := descriptorpb.FieldDescriptorProto_TYPE_BYTES
		int32Type := descriptorpb.FieldDescriptorProto_TYPE_INT32
		fixed64Type := descriptorpb.FieldDescriptorProto_TYPE_FIXED64

		file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
			Name:    proto.String("strict/test.proto"),
			Package: proto.String("strict.test"),
			Syntax:  proto.String("proto3"),
			EnumType: []*descriptorpb.EnumDescriptorProto{{
				Name: proto.String("Mode"),
				Value: []*descriptorpb.EnumValueDescriptorProto{
					{Name: proto.String("MODE_UNSPECIFIED"), Number: proto.Int32(0)},
					{Name: proto.String("MODE_ON"), Number: proto.Int32(1)},
				},
			}},
			MessageType: []*descriptorpb.DescriptorProto{
				{
					Name: proto.String("Child"),
					Field: []*descriptorpb.FieldDescriptorProto{{
						Name: proto.String("value"), Number: proto.Int32(1), Label: &optional, Type: &uint32Type,
					}},
				},
				{
					Name: proto.String("Root"),
					OneofDecl: []*descriptorpb.OneofDescriptorProto{
						{Name: proto.String("choice")},
						{Name: proto.String("_note")},
					},
					Field: []*descriptorpb.FieldDescriptorProto{
						{Name: proto.String("numbers"), Number: proto.Int32(1), Label: &repeated, Type: &uint32Type, Options: &descriptorpb.FieldOptions{Packed: proto.Bool(true)}},
						{Name: proto.String("flags"), Number: proto.Int32(2), Label: &repeated, Type: &boolType, Options: &descriptorpb.FieldOptions{Packed: proto.Bool(true)}},
						{Name: proto.String("modes"), Number: proto.Int32(3), Label: &repeated, Type: &enumType, TypeName: proto.String(".strict.test.Mode"), Options: &descriptorpb.FieldOptions{Packed: proto.Bool(true)}},
						{Name: proto.String("fixeds"), Number: proto.Int32(4), Label: &repeated, Type: &fixed32Type, Options: &descriptorpb.FieldOptions{Packed: proto.Bool(true)}},
						{Name: proto.String("signed"), Number: proto.Int32(5), Label: &repeated, Type: &sint32Type, Options: &descriptorpb.FieldOptions{Packed: proto.Bool(true)}},
						{Name: proto.String("child"), Number: proto.Int32(6), Label: &optional, Type: &messageType, TypeName: proto.String(".strict.test.Child")},
						{Name: proto.String("children"), Number: proto.Int32(7), Label: &repeated, Type: &messageType, TypeName: proto.String(".strict.test.Child")},
						{Name: proto.String("note"), Number: proto.Int32(8), Label: &optional, Type: &stringType, OneofIndex: proto.Int32(1), Proto3Optional: proto.Bool(true)},
						{Name: proto.String("sequence"), Number: proto.Int32(9), Label: &optional, Type: &uint64Type, OneofIndex: proto.Int32(0)},
						{Name: proto.String("token"), Number: proto.Int32(10), Label: &optional, Type: &stringType, OneofIndex: proto.Int32(0)},
						{Name: proto.String("text"), Number: proto.Int32(11), Label: &optional, Type: &stringType},
						{Name: proto.String("blob"), Number: proto.Int32(12), Label: &optional, Type: &bytesType},
						{Name: proto.String("int_value"), Number: proto.Int32(13), Label: &optional, Type: &int32Type},
						{Name: proto.String("fixed64s"), Number: proto.Int32(14), Label: &repeated, Type: &fixed64Type, Options: &descriptorpb.FieldOptions{Packed: proto.Bool(true)}},
						{Name: proto.String("unpacked_numbers"), Number: proto.Int32(15), Label: &repeated, Type: &uint32Type, Options: &descriptorpb.FieldOptions{Packed: proto.Bool(false)}},
					},
				},
			},
		}, nil)
		if err != nil {
			testDescriptorErr = err
			return
		}
		testDescriptor = file.Messages().ByName("Root")
		if testDescriptor == nil {
			testDescriptorErr = ErrInvalidDescriptor
		}
	})
	if testDescriptorErr != nil {
		t.Fatal(testDescriptorErr)
	}
	return testDescriptor
}

func testLimits() Limits {
	return Limits{
		MaxMessageBytes:  4096,
		MaxFieldBytes:    2048,
		MaxTotalFields:   128,
		MaxDepth:         8,
		MaxRepeatedItems: 64,
	}
}

func wireVarintField(number protowire.Number, value uint64) []byte {
	out := protowire.AppendTag(nil, number, protowire.VarintType)
	return protowire.AppendVarint(out, value)
}

func wireBytesField(number protowire.Number, value []byte) []byte {
	out := protowire.AppendTag(nil, number, protowire.BytesType)
	out = protowire.AppendVarint(out, uint64(len(value)))
	return append(out, value...)
}

func wireFixed32Field(number protowire.Number, value uint32) []byte {
	out := protowire.AppendTag(nil, number, protowire.Fixed32Type)
	return protowire.AppendFixed32(out, value)
}

func appendFields(fields ...[]byte) []byte {
	var out []byte
	for _, field := range fields {
		out = append(out, field...)
	}
	return out
}
