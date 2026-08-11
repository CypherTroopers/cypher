// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package schema_test

import (
	"crypto/sha256"
	_ "embed"
	"fmt"
	"sort"
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

//go:embed descriptor/current.binpb
var currentDescriptorImage []byte

//go:embed descriptor/baseline-v1.binpb
var compatibilityBaseline []byte

const compatibilityBaselineSHA256 = "6aff2b5c3321eefc7439fab7e65a6ace41f943cbddf6a1de85dd5a296fb7d3a2"
const currentDescriptorSHA256 = "bf90801eec8ad89ad865f671f9e4b7d736560a9f4eb01189b48b87a804c1151a"

var transportOnlyMessages = map[protoreflect.FullName]protoreflect.FullName{
	"cph.aiinfra.common.v1.ProtocolVersion":           "cph.aiinfra.common.v1",
	"cph.aiinfra.common.v1.TransportSigningDomain":    "cph.aiinfra.common.v1",
	"cph.aiinfra.common.v1.TransportExtension":        "cph.aiinfra.common.v1",
	"cph.aiinfra.common.v1.TransportEnvelope":         "cph.aiinfra.common.v1",
	"cph.aiinfra.transport.v1.SignedFoundationRecord": "cph.aiinfra.transport.v1",
}

type enumContract struct {
	zeroName protoreflect.Name
	maximum  protoreflect.EnumNumber
}

var enumContracts = map[protoreflect.FullName]enumContract{
	"cph.aiinfra.common.v1.SignatureAlgorithm": {
		zeroName: "SIGNATURE_ALGORITHM_UNSPECIFIED",
		maximum:  3,
	},
	"cph.aiinfra.common.v1.PrincipalKind": {
		zeroName: "PRINCIPAL_KIND_UNSPECIFIED",
		maximum:  9,
	},
	"cph.aiinfra.foundation.v1.IdentityState": {
		zeroName: "IDENTITY_STATE_UNSPECIFIED",
		maximum:  6,
	},
	"cph.aiinfra.foundation.v1.KeyLifecycleState": {
		zeroName: "KEY_LIFECYCLE_STATE_UNSPECIFIED",
		maximum:  5,
	},
	"cph.aiinfra.foundation.v1.PolicyBundleState": {
		zeroName: "POLICY_BUNDLE_STATE_UNSPECIFIED",
		maximum:  6,
	},
	"cph.aiinfra.foundation.v1.AuditOutcome": {
		zeroName: "AUDIT_OUTCOME_UNSPECIFIED",
		maximum:  4,
	},
	"cph.aiinfra.foundation.v1.EvidenceLevel": {
		zeroName: "EVIDENCE_LEVEL_UNSPECIFIED",
		maximum:  7,
	},
	"cph.aiinfra.foundation.v1.EvidenceStatus": {
		zeroName: "EVIDENCE_STATUS_UNSPECIFIED",
		maximum:  5,
	},
	"cph.aiinfra.foundation.v1.ComparisonOperator": {
		zeroName: "COMPARISON_OPERATOR_UNSPECIFIED",
		maximum:  6,
	},
	"cph.aiinfra.foundation.v1.ConfidenceMethod": {
		zeroName: "CONFIDENCE_METHOD_UNSPECIFIED",
		maximum:  5,
	},
	"cph.aiinfra.foundation.v1.TransferEvidenceKind": {
		zeroName: "TRANSFER_EVIDENCE_KIND_UNSPECIFIED",
		maximum:  7,
	},
}

func TestDescriptorImageMatchesGeneratedSources(t *testing.T) {
	sum := sha256.Sum256(currentDescriptorImage)
	if got := fmt.Sprintf("%x", sum); got != currentDescriptorSHA256 {
		t.Fatalf("current descriptor SHA-256=%s, want %s", got, currentDescriptorSHA256)
	}
	image := decodeDescriptorSet(t, "current descriptor", currentDescriptorImage)
	byName := make(map[string]*descriptorpb.FileDescriptorProto, len(image.File))
	for _, file := range image.File {
		if _, duplicate := byName[file.GetName()]; duplicate {
			t.Fatalf("descriptor image contains duplicate file %q", file.GetName())
		}
		byName[file.GetName()] = file
	}

	generated := []protoreflect.FileDescriptor{
		commonv1.File_common_v1_common_proto,
		foundationv1.File_foundation_v1_foundation_proto,
		transportv1.File_transport_v1_foundation_transport_proto,
	}
	if len(byName) != len(generated) {
		t.Fatalf("descriptor image contains %d files, generated source exposes %d", len(byName), len(generated))
	}
	for _, file := range generated {
		got, ok := byName[file.Path()]
		if !ok {
			t.Fatalf("descriptor image is missing generated file %q", file.Path())
		}
		want := protodesc.ToFileDescriptorProto(file)
		got.SourceCodeInfo = nil
		want.SourceCodeInfo = nil
		if !proto.Equal(got, want) {
			t.Fatalf("checked descriptor for %q does not match generated Go source", file.Path())
		}
	}
}

func TestFoundationTransportWrapperContract(t *testing.T) {
	message := transportv1.File_transport_v1_foundation_transport_proto.Messages().ByName("SignedFoundationRecord")
	if message == nil {
		t.Fatal("generated descriptor is missing SignedFoundationRecord")
	}
	if got := message.Fields().Len(); got != 16 {
		t.Fatalf("SignedFoundationRecord fields=%d, want 16", got)
	}
	for _, contract := range []struct {
		number protoreflect.FieldNumber
		name   protoreflect.Name
		target protoreflect.FullName
	}{
		{1, "signing_domain", "cph.aiinfra.common.v1.TransportSigningDomain"},
		{2, "envelope", "cph.aiinfra.common.v1.TransportEnvelope"},
	} {
		field := message.Fields().ByNumber(contract.number)
		if field == nil || field.Name() != contract.name || field.Kind() != protoreflect.MessageKind || field.Message().FullName() != contract.target || field.ContainingOneof() != nil {
			t.Fatalf("SignedFoundationRecord field %d does not match the fixed %s contract", contract.number, contract.name)
		}
	}
	ranges := message.ReservedRanges()
	if ranges.Len() != 1 {
		t.Fatalf("SignedFoundationRecord reserved ranges=%d, want 1", ranges.Len())
	}
	reserved := ranges.Get(0)
	if reserved[0] != 3 || reserved[1] != 16 {
		t.Fatalf("SignedFoundationRecord reserved range=%v, want [3,16)", reserved)
	}
	payload := message.Oneofs().ByName("payload")
	if payload == nil || payload.IsSynthetic() || payload.Fields().Len() != 14 {
		t.Fatalf("SignedFoundationRecord payload oneof is missing, synthetic, or not 14-way")
	}
	payloads := []struct {
		number protoreflect.FieldNumber
		name   protoreflect.Name
		target protoreflect.FullName
	}{
		{16, "provider_identity", "cph.aiinfra.foundation.v1.ProviderIdentity"},
		{17, "agent_identity", "cph.aiinfra.foundation.v1.AgentIdentity"},
		{18, "host_identity", "cph.aiinfra.foundation.v1.HostIdentity"},
		{19, "device_identity", "cph.aiinfra.foundation.v1.DeviceIdentity"},
		{20, "miner_identity", "cph.aiinfra.foundation.v1.MinerIdentity"},
		{21, "runner_identity", "cph.aiinfra.foundation.v1.RunnerIdentity"},
		{22, "buyer_identity", "cph.aiinfra.foundation.v1.BuyerIdentity"},
		{23, "service_identity", "cph.aiinfra.foundation.v1.ServiceIdentity"},
		{24, "key_lifecycle", "cph.aiinfra.foundation.v1.KeyLifecycle"},
		{25, "policy_bundle", "cph.aiinfra.foundation.v1.PolicyBundle"},
		{26, "audit_event", "cph.aiinfra.foundation.v1.AuditEvent"},
		{27, "evidence_record", "cph.aiinfra.foundation.v1.EvidenceRecord"},
		{28, "experiment_plan", "cph.aiinfra.foundation.v1.ExperimentPlan"},
		{29, "ownership_transfer_authorization", "cph.aiinfra.foundation.v1.OwnershipTransferAuthorization"},
	}
	for _, contract := range payloads {
		field := message.Fields().ByNumber(contract.number)
		if field == nil || field.Name() != contract.name || field.Kind() != protoreflect.MessageKind || field.Message().FullName() != contract.target || field.ContainingOneof() != payload {
			t.Fatalf("SignedFoundationRecord payload field %d does not match the fixed %s contract", contract.number, contract.name)
		}
	}
}

func TestCompatibilityBaselineIsValidDescriptorSet(t *testing.T) {
	sum := sha256.Sum256(compatibilityBaseline)
	if got := fmt.Sprintf("%x", sum); got != compatibilityBaselineSHA256 {
		t.Fatalf("compatibility baseline SHA-256=%s, want %s", got, compatibilityBaselineSHA256)
	}
	baseline := decodeDescriptorSet(t, "compatibility baseline", compatibilityBaseline)
	if len(baseline.File) != 2 {
		t.Fatalf("compatibility baseline contains %d files, want 2", len(baseline.File))
	}
	if _, err := protodesc.NewFiles(baseline); err != nil {
		t.Fatalf("compatibility baseline cannot be linked: %v", err)
	}
}

func TestDescriptorRegistryAlignment(t *testing.T) {
	registry, err := schema.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	image := decodeDescriptorSet(t, "current descriptor", currentDescriptorImage)
	files, err := protodesc.NewFiles(image)
	if err != nil {
		t.Fatalf("link current descriptor: %v", err)
	}

	registered := make(map[protoreflect.FullName]schema.Projection, len(registry.Structures)+len(registry.Messages))
	for _, structure := range registry.Structures {
		registered[protoreflect.FullName(structure.Name)] = structure
	}
	for _, message := range registry.Messages {
		if message.UnknownFieldPolicy != "reject" {
			t.Fatalf("%s unknown_field_policy = %q, want reject", message.Name, message.UnknownFieldPolicy)
		}
		registered[protoreflect.FullName(message.Name)] = schema.Projection{
			Name:   message.Name,
			Limits: message.Limits,
			Fields: message.Fields,
		}
	}

	seenRegistered := make(map[protoreflect.FullName]bool, len(registered))
	seenTransport := make(map[protoreflect.FullName]bool, len(transportOnlyMessages))
	seenEnums := make(map[protoreflect.FullName]bool, len(enumContracts))
	files.RangeFiles(func(file protoreflect.FileDescriptor) bool {
		if file.Syntax() != protoreflect.Proto3 {
			t.Fatalf("%s syntax=%s, want proto3", file.Path(), file.Syntax())
		}
		validateEnums(t, file.Enums(), seenEnums)
		validateMessages(t, file, file.Messages(), registered, seenRegistered, seenTransport, seenEnums)
		return true
	})

	requireAllNamesSeen(t, "registered signing projection", registered, seenRegistered)
	requireAllNamesSeen(t, "transport-only message", transportOnlyMessages, seenTransport)
	requireAllNamesSeen(t, "enum contract", enumContracts, seenEnums)
}

func decodeDescriptorSet(t *testing.T, label string, data []byte) *descriptorpb.FileDescriptorSet {
	t.Helper()
	if len(data) == 0 {
		t.Fatalf("%s is empty", label)
	}
	var files descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(data, &files); err != nil {
		t.Fatalf("decode %s: %v", label, err)
	}
	return &files
}

func validateProjectionDescriptor(t *testing.T, projection schema.Projection, message protoreflect.MessageDescriptor) {
	t.Helper()
	fields := message.Fields()
	if fields.Len() != len(projection.Fields) {
		t.Fatalf("%s descriptor fields=%d registry fields=%d", projection.Name, fields.Len(), len(projection.Fields))
	}
	if fields.Len() != projection.Limits.MaxFields {
		t.Fatalf("%s descriptor fields=%d registry max_fields=%d", projection.Name, fields.Len(), projection.Limits.MaxFields)
	}
	for index, registeredField := range projection.Fields {
		field := fields.Get(index)
		if registeredField.Order != index+1 || field.Number() != protoreflect.FieldNumber(registeredField.Order) {
			t.Fatalf("%s field[%d] number/order mismatch: descriptor=%d registry=%d", projection.Name, index, field.Number(), registeredField.Order)
		}
		if string(field.Name()) != registeredField.Name {
			t.Fatalf("%s field %d name mismatch: descriptor=%q registry=%q", projection.Name, registeredField.Order, field.Name(), registeredField.Name)
		}
		validateFieldCollection(t, projection.Name, registeredField, field)
		validateFieldPresence(t, projection.Name, registeredField, field)
		validateFieldKind(t, projection.Name, registeredField, field)
	}
}

func validateFieldCollection(t *testing.T, messageName string, registered schema.Field, field protoreflect.FieldDescriptor) {
	t.Helper()
	if field.IsMap() {
		t.Fatalf("%s.%s uses a forbidden map field", messageName, registered.Name)
	}
	switch registered.Collection {
	case "scalar":
		if field.Cardinality() == protoreflect.Repeated {
			t.Fatalf("%s.%s is repeated but registry collection is scalar", messageName, registered.Name)
		}
	case "set", "ordered_list":
		if field.Cardinality() != protoreflect.Repeated {
			t.Fatalf("%s.%s is not repeated but registry collection is %s", messageName, registered.Name, registered.Collection)
		}
	default:
		t.Fatalf("%s.%s has unknown registry collection %q", messageName, registered.Name, registered.Collection)
	}
}

func TestDescriptorCollectionVocabularyIncludesOrderedList(t *testing.T) {
	message := foundationv1.File_foundation_v1_foundation_proto.Messages().ByName("ExperimentPlan")
	if message == nil {
		t.Fatal("generated descriptor is missing ExperimentPlan")
	}
	field := message.Fields().ByName("criteria")
	if field == nil || field.Cardinality() != protoreflect.Repeated {
		t.Fatal("generated descriptor is missing repeated ExperimentPlan.criteria")
	}
	validateFieldCollection(t, string(message.FullName()), schema.Field{
		Name:       string(field.Name()),
		Collection: "ordered_list",
	}, field)
}

func validateFieldPresence(t *testing.T, messageName string, registered schema.Field, field protoreflect.FieldDescriptor) {
	t.Helper()
	oneof := field.ContainingOneof()
	switch registered.Presence {
	case "optional":
		if !field.HasOptionalKeyword() || oneof == nil || !oneof.IsSynthetic() {
			t.Fatalf("%s.%s must be a proto3 optional field", messageName, registered.Name)
		}
	case "required":
		if field.HasOptionalKeyword() {
			t.Fatalf("%s.%s is proto3 optional but registry presence is required", messageName, registered.Name)
		}
		if oneof != nil {
			t.Fatalf("%s.%s is in oneof %s but registry has no oneof", messageName, registered.Name, oneof.Name())
		}
	default:
		t.Fatalf("%s.%s has unknown registry presence %q", messageName, registered.Name, registered.Presence)
	}
}

func validateFieldKind(t *testing.T, messageName string, registered schema.Field, field protoreflect.FieldDescriptor) {
	t.Helper()
	wantKind := map[string]protoreflect.Kind{
		"bool":           protoreflect.BoolKind,
		"uint32":         protoreflect.Uint32Kind,
		"uint64":         protoreflect.Uint64Kind,
		"int64":          protoreflect.Int64Kind,
		"enum_uint32":    protoreflect.EnumKind,
		"string":         protoreflect.StringKind,
		"bytes":          protoreflect.BytesKind,
		"fixed_bytes_16": protoreflect.BytesKind,
		"fixed_bytes_32": protoreflect.BytesKind,
		"fixed_bytes_64": protoreflect.BytesKind,
		"message":        protoreflect.MessageKind,
	}[registered.Type]
	if wantKind == 0 || field.Kind() != wantKind {
		t.Fatalf("%s.%s kind mismatch: descriptor=%s registry=%s", messageName, registered.Name, field.Kind(), registered.Type)
	}
	if registered.Type == "message" {
		if field.Message() == nil || string(field.Message().FullName()) != registered.MessageType {
			t.Fatalf("%s.%s message target mismatch: descriptor=%v registry=%s", messageName, registered.Name, field.Message(), registered.MessageType)
		}
	}
	if registered.Type == "enum_uint32" {
		if field.Enum() == nil {
			t.Fatalf("%s.%s has no enum descriptor", messageName, registered.Name)
		}
		if _, ok := enumContracts[field.Enum().FullName()]; !ok {
			t.Fatalf("%s.%s uses enum %s without a pinned allowed range", messageName, registered.Name, field.Enum().FullName())
		}
	}
}

func validateNoForbiddenTransportKinds(t *testing.T, message protoreflect.MessageDescriptor) {
	t.Helper()
	fields := message.Fields()
	for index := 0; index < fields.Len(); index++ {
		field := fields.Get(index)
		if field.IsMap() {
			t.Fatalf("%s.%s uses a forbidden map field", message.FullName(), field.Name())
		}
		switch field.Kind() {
		case protoreflect.FloatKind, protoreflect.DoubleKind:
			t.Fatalf("%s.%s uses forbidden floating point kind %s", message.FullName(), field.Name(), field.Kind())
		}
	}
}

func validateMessages(
	t *testing.T,
	file protoreflect.FileDescriptor,
	messages protoreflect.MessageDescriptors,
	registered map[protoreflect.FullName]schema.Projection,
	seenRegistered map[protoreflect.FullName]bool,
	seenTransport map[protoreflect.FullName]bool,
	seenEnums map[protoreflect.FullName]bool,
) {
	t.Helper()
	for index := 0; index < messages.Len(); index++ {
		message := messages.Get(index)
		validateNoForbiddenTransportKinds(t, message)
		name := message.FullName()
		projection, isRegistered := registered[name]
		expectedPackage, isTransportOnly := transportOnlyMessages[name]
		switch {
		case isRegistered && isTransportOnly:
			t.Fatalf("%s is both a signing projection and transport-only", name)
		case isRegistered:
			validateProjectionDescriptor(t, projection, message)
			seenRegistered[name] = true
		case isTransportOnly:
			if file.Package() != expectedPackage {
				t.Fatalf("transport-only message %s is in package %s, want %s", name, file.Package(), expectedPackage)
			}
			seenTransport[name] = true
		default:
			t.Fatalf("descriptor message %s is neither registered nor explicitly transport-only", name)
		}
		validateEnums(t, message.Enums(), seenEnums)
		validateMessages(t, file, message.Messages(), registered, seenRegistered, seenTransport, seenEnums)
	}
}

func validateEnums(t *testing.T, enums protoreflect.EnumDescriptors, seen map[protoreflect.FullName]bool) {
	t.Helper()
	for enumIndex := 0; enumIndex < enums.Len(); enumIndex++ {
		enum := enums.Get(enumIndex)
		contract, ok := enumContracts[enum.FullName()]
		if !ok {
			t.Fatalf("enum %s has no pinned contract", enum.FullName())
		}
		values := enum.Values()
		if values.Len() != int(contract.maximum)+1 {
			t.Fatalf("enum %s has %d values, want contiguous range 0..%d", enum.FullName(), values.Len(), contract.maximum)
		}
		for number := protoreflect.EnumNumber(0); number <= contract.maximum; number++ {
			value := values.ByNumber(number)
			if value == nil {
				t.Fatalf("enum %s is missing allowed value %d", enum.FullName(), number)
			}
		}
		zero := values.ByNumber(0)
		if zero == nil || zero.Name() != contract.zeroName || !strings.HasSuffix(string(zero.Name()), "_UNSPECIFIED") {
			t.Fatalf("enum %s zero sentinel=%v, want %s", enum.FullName(), zero, contract.zeroName)
		}
		seen[enum.FullName()] = true
	}
}

func requireAllNamesSeen[T any](t *testing.T, label string, expected map[protoreflect.FullName]T, seen map[protoreflect.FullName]bool) {
	t.Helper()
	missing := make([]string, 0)
	for name := range expected {
		if !seen[name] {
			missing = append(missing, string(name))
		}
	}
	if len(missing) != 0 {
		sort.Strings(missing)
		t.Fatalf("descriptor is missing %s(s): %s", label, fmt.Sprint(missing))
	}
}
