// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package strictproto

import (
	"errors"
	"testing"

	commonv1 "github.com/cypherium/cypher/aiinfra/schema/common/v1"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

type protoReflectHookMessage struct {
	message protoreflect.Message
	hook    func(int)
	calls   int
}

func (m *protoReflectHookMessage) ProtoReflect() protoreflect.Message {
	m.calls++
	if m.hook != nil {
		m.hook(m.calls)
	}
	return m.message
}

func TestUnmarshalDynamicMessageAfterPreflight(t *testing.T) {
	descriptor := strictTestDescriptor(t)
	child := wireVarintField(1, 7)
	data := appendFields(
		wireBytesField(11, []byte("ready")),
		wireBytesField(1, []byte{1, 2}),
		wireVarintField(1, 3),
		wireBytesField(6, child),
		wireBytesField(7, child),
		wireBytesField(8, nil),
		wireVarintField(9, 0),
	)
	target := dynamicpb.NewMessage(descriptor)
	if err := Unmarshal(data, target, descriptor, testLimits()); err != nil {
		t.Fatal(err)
	}
	if got := target.Get(descriptor.Fields().ByName("numbers")).List().Len(); got != 3 {
		t.Fatalf("numbers length = %d, want 3", got)
	}
	if !target.Has(descriptor.Fields().ByName("note")) {
		t.Fatal("present-empty proto3 optional note lost presence")
	}
	sequence := descriptor.Fields().ByName("sequence")
	if target.WhichOneof(sequence.ContainingOneof()) != sequence {
		t.Fatal("present-zero oneof sequence lost presence")
	}
}

func TestUnmarshalGeneratedOptionalOneofAndNestedMessages(t *testing.T) {
	empty := ""
	domain := &commonv1.TransportSigningDomain{
		TenantOrganization: &empty,
		ReplayGuard:        &commonv1.TransportSigningDomain_Sequence{Sequence: 0},
	}
	data, err := proto.Marshal(domain)
	if err != nil {
		t.Fatal(err)
	}
	target := new(commonv1.TransportSigningDomain)
	descriptor := domain.ProtoReflect().Descriptor()
	if err := Unmarshal(data, target, descriptor, testLimits()); err != nil {
		t.Fatal(err)
	}
	if target.TenantOrganization == nil || target.GetSequence() != 0 {
		t.Fatal("optional or oneof presence was not preserved")
	}
	if _, ok := target.ReplayGuard.(*commonv1.TransportSigningDomain_Sequence); !ok {
		t.Fatalf("replay guard type = %T", target.ReplayGuard)
	}

	provider := &foundationv1.ProviderIdentity{
		Metadata: &commonv1.RecordMetadata{
			SchemaVersion: &commonv1.SchemaVersion{Major: 1},
		},
	}
	data, err = proto.Marshal(provider)
	if err != nil {
		t.Fatal(err)
	}
	providerTarget := new(foundationv1.ProviderIdentity)
	if err := Unmarshal(data, providerTarget, provider.ProtoReflect().Descriptor(), testLimits()); err != nil {
		t.Fatal(err)
	}
	if providerTarget.Metadata == nil || providerTarget.Metadata.SchemaVersion == nil || providerTarget.Metadata.SchemaVersion.Major != 1 {
		t.Fatal("nested generated message did not round-trip")
	}
}

func TestUnmarshalRejectsNilOrMismatchedTarget(t *testing.T) {
	descriptor := strictTestDescriptor(t)
	var typedNil *commonv1.SchemaVersion
	if err := Unmarshal(nil, typedNil, descriptor, testLimits()); !errors.Is(err, ErrNilTarget) {
		t.Fatalf("typed nil error = %v", err)
	}
	target := new(commonv1.SchemaVersion)
	if err := Unmarshal(nil, target, descriptor, testLimits()); !errors.Is(err, ErrDescriptorMismatch) {
		t.Fatalf("descriptor mismatch error = %v", err)
	}
	if err := Unmarshal(nil, target, nil, testLimits()); !errors.Is(err, ErrDescriptorMismatch) {
		t.Fatalf("nil descriptor error = %v", err)
	}
}

func TestPreflightFailureLeavesTargetUntouched(t *testing.T) {
	descriptor := strictTestDescriptor(t)
	target := dynamicpb.NewMessage(descriptor)
	textField := descriptor.Fields().ByName("text")
	target.Set(textField, protoreflect.ValueOfString("existing"))
	if err := Unmarshal(wireVarintField(99, 1), target, descriptor, testLimits()); !errors.Is(err, ErrUnknownField) {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got := target.Get(textField).String(); got != "existing" {
		t.Fatalf("target changed after preflight failure: %q", got)
	}
}

func TestUnmarshalUsesOneOwnedSnapshotAcrossPreflightAndDecode(t *testing.T) {
	descriptor := strictTestDescriptor(t)
	original := appendFields(wireBytesField(11, []byte("a")), wireBytesField(12, []byte("b")))
	duplicateText := appendFields(wireBytesField(11, []byte("a")), wireBytesField(11, []byte("b")))
	if len(original) != len(duplicateText) {
		t.Fatal("test mutation must preserve wire length")
	}
	targetMessage := dynamicpb.NewMessage(descriptor)
	target := &protoReflectHookMessage{
		message: targetMessage.ProtoReflect(),
		hook: func(call int) {
			if call == 2 {
				copy(original, duplicateText)
			}
		},
	}
	if err := Unmarshal(original, target, descriptor, testLimits()); err != nil {
		t.Fatal(err)
	}
	if got := targetMessage.Get(descriptor.Fields().ByName("text")).String(); got != "a" {
		t.Fatalf("decoded text = %q, want snapshot value a", got)
	}
	if got := targetMessage.Get(descriptor.Fields().ByName("blob")).Bytes(); string(got) != "b" {
		t.Fatalf("decoded blob = %q, want snapshot value b", got)
	}
	if string(original) != string(duplicateText) {
		t.Fatal("mutation hook did not run")
	}
}

func TestReflectionValidationRejectsUnknownEnumNilAndInvalidUTF8AtAllDepths(t *testing.T) {
	rootUnknown := new(commonv1.SchemaVersion)
	rootUnknown.ProtoReflect().SetUnknown(wireVarintField(99, 1))
	if err := validateDecoded(rootUnknown.ProtoReflect(), rootUnknown.ProtoReflect().Descriptor()); !errors.Is(err, ErrUnknownAfterUnmarshal) {
		t.Fatalf("root unknown error = %v", err)
	}

	nestedUnknown := &foundationv1.ProviderIdentity{Metadata: new(commonv1.RecordMetadata)}
	nestedUnknown.Metadata.ProtoReflect().SetUnknown(wireVarintField(99, 1))
	if err := validateDecoded(nestedUnknown.ProtoReflect(), nestedUnknown.ProtoReflect().Descriptor()); !errors.Is(err, ErrUnknownAfterUnmarshal) {
		t.Fatalf("nested unknown error = %v", err)
	}

	unknownEnum := &foundationv1.KeyLifecycle{State: foundationv1.KeyLifecycleState(99)}
	if err := validateDecoded(unknownEnum.ProtoReflect(), unknownEnum.ProtoReflect().Descriptor()); !errors.Is(err, ErrUnknownEnum) {
		t.Fatalf("unknown enum error = %v", err)
	}

	nilRepeated := &foundationv1.EvidenceRecord{Observations: []*foundationv1.MetricObservation{nil}}
	if err := validateDecoded(nilRepeated.ProtoReflect(), nilRepeated.ProtoReflect().Descriptor()); !errors.Is(err, ErrNilRepeatedMessage) {
		t.Fatalf("nil repeated message error = %v", err)
	}

	invalidUTF8 := &foundationv1.MetricCriterion{MetricId: string([]byte{0xff})}
	if err := validateDecoded(invalidUTF8.ProtoReflect(), invalidUTF8.ProtoReflect().Descriptor()); !errors.Is(err, ErrInvalidUTF8) {
		t.Fatalf("invalid UTF-8 error = %v", err)
	}
}

func TestReflectionValidationRequiresExactDescriptor(t *testing.T) {
	descriptor := strictTestDescriptor(t)
	message := new(commonv1.SchemaVersion)
	if err := validateDecoded(message.ProtoReflect(), descriptor); !errors.Is(err, ErrDescriptorMismatch) {
		t.Fatalf("validateDecoded() error = %v", err)
	}
}
