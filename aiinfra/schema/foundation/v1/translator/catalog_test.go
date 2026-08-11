// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package translator

import (
	"errors"
	"strings"
	"testing"

	"github.com/cypherium/cypher/aiinfra/schema"
	commonv1 "github.com/cypherium/cypher/aiinfra/schema/common/v1"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
	transportv1 "github.com/cypherium/cypher/aiinfra/schema/transport/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestGeneratedTransportDescriptorMatchesPinnedCatalog(t *testing.T) {
	registry, err := schema.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	root := (&transportv1.SignedFoundationRecord{}).ProtoReflect().Descriptor()
	if _, err := validateTransportDescriptor(root, registry); err != nil {
		t.Fatal(err)
	}
}

func TestDynamicTransportDescriptorDriftFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*descriptorpb.FileDescriptorProto, *descriptorpb.FileDescriptorProto, *descriptorpb.FileDescriptorProto)
	}{
		{
			name: "enum field target",
			mutate: func(_ *descriptorpb.FileDescriptorProto, foundation, _ *descriptorpb.FileDescriptorProto) {
				field := descriptorField(t, descriptorMessage(t, foundation, "ProviderIdentity"), "state")
				field.TypeName = proto.String(".cph.aiinfra.foundation.v1.EvidenceStatus")
			},
		},
		{
			name: "enum value name",
			mutate: func(_ *descriptorpb.FileDescriptorProto, foundation, _ *descriptorpb.FileDescriptorProto) {
				descriptorEnum(t, foundation, "IdentityState").Value[2].Name = proto.String("IDENTITY_STATE_ENABLED")
			},
		},
		{
			name: "enum value number",
			mutate: func(_ *descriptorpb.FileDescriptorProto, foundation, _ *descriptorpb.FileDescriptorProto) {
				descriptorEnum(t, foundation, "IdentityState").Value[6].Number = proto.Int32(7)
			},
		},
		{
			name: "enum value added",
			mutate: func(_ *descriptorpb.FileDescriptorProto, foundation, _ *descriptorpb.FileDescriptorProto) {
				enum := descriptorEnum(t, foundation, "IdentityState")
				enum.Value = append(enum.Value, &descriptorpb.EnumValueDescriptorProto{
					Name: proto.String("IDENTITY_STATE_ARCHIVED"), Number: proto.Int32(7),
				})
			},
		},
		{
			name: "field number swap",
			mutate: func(_ *descriptorpb.FileDescriptorProto, foundation, _ *descriptorpb.FileDescriptorProto) {
				message := descriptorMessage(t, foundation, "ProviderIdentity")
				first := descriptorField(t, message, "provider_id")
				second := descriptorField(t, message, "organization_identity_uri")
				first.Number, second.Number = second.Number, first.Number
			},
		},
		{
			name: "message field target",
			mutate: func(_ *descriptorpb.FileDescriptorProto, foundation, _ *descriptorpb.FileDescriptorProto) {
				field := descriptorField(t, descriptorMessage(t, foundation, "ProviderIdentity"), "metadata")
				field.TypeName = proto.String(".cph.aiinfra.common.v1.ProtocolVersion")
			},
		},
		{
			name: "real oneof",
			mutate: func(_ *descriptorpb.FileDescriptorProto, foundation, _ *descriptorpb.FileDescriptorProto) {
				message := descriptorMessage(t, foundation, "ProviderIdentity")
				for _, field := range message.Field {
					if field.OneofIndex != nil {
						field.OneofIndex = proto.Int32(field.GetOneofIndex() + 1)
					}
				}
				message.OneofDecl = append([]*descriptorpb.OneofDescriptorProto{{Name: proto.String("drift")}}, message.OneofDecl...)
				descriptorField(t, message, "provider_id").OneofIndex = proto.Int32(0)
			},
		},
		{
			name: "reserved range",
			mutate: func(_ *descriptorpb.FileDescriptorProto, foundation, _ *descriptorpb.FileDescriptorProto) {
				message := descriptorMessage(t, foundation, "ProviderIdentity")
				message.ReservedRange = append(message.ReservedRange, &descriptorpb.DescriptorProto_ReservedRange{
					Start: proto.Int32(100), End: proto.Int32(101),
				})
			},
		},
	}

	registry, err := schema.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := dynamicTransportRoot(t, test.mutate)
			if _, err := validateTransportDescriptor(root, registry); !errors.Is(err, ErrCatalogMismatch) {
				t.Fatalf("got %v, want errors.Is(_, %v)", err, ErrCatalogMismatch)
			}
		})
	}
}

func TestReachableMessageExtensionRangesFailClosed(t *testing.T) {
	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name:    proto.String("extension_range.proto"),
		Package: proto.String("cph.aiinfra.test"),
		Syntax:  proto.String("proto2"),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("Extended"),
			ExtensionRange: []*descriptorpb.DescriptorProto_ExtensionRange{{
				Start: proto.Int32(100), End: proto.Int32(200),
			}},
		}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = validateReachableMessageShape(file.Messages().Get(0))
	if !errors.Is(err, ErrCatalogMismatch) || !strings.Contains(err.Error(), "extension ranges") {
		t.Fatalf("got %v, want explicit extension-range catalog failure", err)
	}
}

func dynamicTransportRoot(t *testing.T, mutate func(*descriptorpb.FileDescriptorProto, *descriptorpb.FileDescriptorProto, *descriptorpb.FileDescriptorProto)) protoreflect.MessageDescriptor {
	t.Helper()
	common := proto.Clone(protodesc.ToFileDescriptorProto(commonv1.File_common_v1_common_proto)).(*descriptorpb.FileDescriptorProto)
	foundation := proto.Clone(protodesc.ToFileDescriptorProto(foundationv1.File_foundation_v1_foundation_proto)).(*descriptorpb.FileDescriptorProto)
	transport := proto.Clone(protodesc.ToFileDescriptorProto(transportv1.File_transport_v1_foundation_transport_proto)).(*descriptorpb.FileDescriptorProto)
	mutate(common, foundation, transport)
	files, err := protodesc.NewFiles(&descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{common, foundation, transport}})
	if err != nil {
		t.Fatalf("build dynamic descriptors: %v", err)
	}
	descriptor, err := files.FindDescriptorByName("cph.aiinfra.transport.v1.SignedFoundationRecord")
	if err != nil {
		t.Fatal(err)
	}
	root, ok := descriptor.(protoreflect.MessageDescriptor)
	if !ok {
		t.Fatalf("root has type %T", descriptor)
	}
	return root
}

func descriptorMessage(t *testing.T, file *descriptorpb.FileDescriptorProto, name string) *descriptorpb.DescriptorProto {
	t.Helper()
	for _, message := range file.MessageType {
		if message.GetName() == name {
			return message
		}
	}
	t.Fatalf("message %s not found", name)
	return nil
}

func descriptorField(t *testing.T, message *descriptorpb.DescriptorProto, name string) *descriptorpb.FieldDescriptorProto {
	t.Helper()
	for _, field := range message.Field {
		if field.GetName() == name {
			return field
		}
	}
	t.Fatalf("field %s.%s not found", message.GetName(), name)
	return nil
}

func descriptorEnum(t *testing.T, file *descriptorpb.FileDescriptorProto, name string) *descriptorpb.EnumDescriptorProto {
	t.Helper()
	for _, enum := range file.EnumType {
		if enum.GetName() == name {
			return enum
		}
	}
	t.Fatalf("enum %s not found", name)
	return nil
}
