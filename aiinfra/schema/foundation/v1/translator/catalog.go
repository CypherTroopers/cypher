// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package translator

import (
	"fmt"

	"github.com/cypherium/cypher/aiinfra/schema"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type transportField struct {
	number   protoreflect.FieldNumber
	name     protoreflect.Name
	kind     protoreflect.Kind
	list     bool
	optional bool
	oneof    protoreflect.Name
	message  protoreflect.FullName
}

type enumValueContract struct {
	name   protoreflect.Name
	number protoreflect.EnumNumber
}

type enumContract struct {
	name   protoreflect.FullName
	values []enumValueContract
}

// reviewedEnums pins every enum reachable from SignedFoundationRecord by its
// fully-qualified name and complete ordered name:number table. Merely checking
// protoreflect.EnumKind is insufficient: all protobuf enums have the same wire
// type, so a descriptor could otherwise redirect a security-relevant field to
// a different enum without changing strict wire preflight behavior.
var reviewedEnums = [...]enumContract{
	{"cph.aiinfra.common.v1.SignatureAlgorithm", []enumValueContract{
		{"SIGNATURE_ALGORITHM_UNSPECIFIED", 0},
		{"SIGNATURE_ALGORITHM_ED25519", 1},
		{"SIGNATURE_ALGORITHM_P256_SHA256", 2},
		{"SIGNATURE_ALGORITHM_EIP712", 3},
	}},
	{"cph.aiinfra.common.v1.PrincipalKind", []enumValueContract{
		{"PRINCIPAL_KIND_UNSPECIFIED", 0},
		{"PRINCIPAL_KIND_PROVIDER", 1},
		{"PRINCIPAL_KIND_AGENT", 2},
		{"PRINCIPAL_KIND_HOST", 3},
		{"PRINCIPAL_KIND_DEVICE", 4},
		{"PRINCIPAL_KIND_MINER", 5},
		{"PRINCIPAL_KIND_RUNNER", 6},
		{"PRINCIPAL_KIND_BUYER", 7},
		{"PRINCIPAL_KIND_SERVICE", 8},
		{"PRINCIPAL_KIND_HUMAN_USER", 9},
	}},
	{"cph.aiinfra.foundation.v1.IdentityState", []enumValueContract{
		{"IDENTITY_STATE_UNSPECIFIED", 0},
		{"IDENTITY_STATE_PENDING", 1},
		{"IDENTITY_STATE_ACTIVE", 2},
		{"IDENTITY_STATE_SUSPENDED", 3},
		{"IDENTITY_STATE_REVOKED", 4},
		{"IDENTITY_STATE_TRANSFERRED", 5},
		{"IDENTITY_STATE_EXPIRED", 6},
	}},
	{"cph.aiinfra.foundation.v1.KeyLifecycleState", []enumValueContract{
		{"KEY_LIFECYCLE_STATE_UNSPECIFIED", 0},
		{"KEY_LIFECYCLE_STATE_PREACTIVE", 1},
		{"KEY_LIFECYCLE_STATE_ACTIVE", 2},
		{"KEY_LIFECYCLE_STATE_RETIRING", 3},
		{"KEY_LIFECYCLE_STATE_REVOKED", 4},
		{"KEY_LIFECYCLE_STATE_EXPIRED", 5},
	}},
	{"cph.aiinfra.foundation.v1.PolicyBundleState", []enumValueContract{
		{"POLICY_BUNDLE_STATE_UNSPECIFIED", 0},
		{"POLICY_BUNDLE_STATE_DRAFT", 1},
		{"POLICY_BUNDLE_STATE_APPROVED_DELAYED", 2},
		{"POLICY_BUNDLE_STATE_ACTIVE", 3},
		{"POLICY_BUNDLE_STATE_ROLLED_BACK", 4},
		{"POLICY_BUNDLE_STATE_REVOKED", 5},
		{"POLICY_BUNDLE_STATE_EXPIRED", 6},
	}},
	{"cph.aiinfra.foundation.v1.AuditOutcome", []enumValueContract{
		{"AUDIT_OUTCOME_UNSPECIFIED", 0},
		{"AUDIT_OUTCOME_SUCCEEDED", 1},
		{"AUDIT_OUTCOME_REJECTED", 2},
		{"AUDIT_OUTCOME_FAILED", 3},
		{"AUDIT_OUTCOME_TIMED_OUT", 4},
	}},
	{"cph.aiinfra.foundation.v1.EvidenceLevel", []enumValueContract{
		{"EVIDENCE_LEVEL_UNSPECIFIED", 0},
		{"EVIDENCE_LEVEL_CONCEPT", 1},
		{"EVIDENCE_LEVEL_DESIGNED", 2},
		{"EVIDENCE_LEVEL_IMPLEMENTED", 3},
		{"EVIDENCE_LEVEL_LAB_VALIDATED", 4},
		{"EVIDENCE_LEVEL_PILOT_VALIDATED", 5},
		{"EVIDENCE_LEVEL_PRODUCTION_READY", 6},
		{"EVIDENCE_LEVEL_COMMERCIAL_SCALE_VALIDATED", 7},
	}},
	{"cph.aiinfra.foundation.v1.EvidenceStatus", []enumValueContract{
		{"EVIDENCE_STATUS_UNSPECIFIED", 0},
		{"EVIDENCE_STATUS_PENDING", 1},
		{"EVIDENCE_STATUS_PASSED", 2},
		{"EVIDENCE_STATUS_FAILED", 3},
		{"EVIDENCE_STATUS_EXPIRED", 4},
		{"EVIDENCE_STATUS_INVALIDATED", 5},
	}},
	{"cph.aiinfra.foundation.v1.ComparisonOperator", []enumValueContract{
		{"COMPARISON_OPERATOR_UNSPECIFIED", 0},
		{"COMPARISON_OPERATOR_LESS_THAN", 1},
		{"COMPARISON_OPERATOR_LESS_THAN_OR_EQUAL", 2},
		{"COMPARISON_OPERATOR_EQUAL", 3},
		{"COMPARISON_OPERATOR_GREATER_THAN_OR_EQUAL", 4},
		{"COMPARISON_OPERATOR_GREATER_THAN", 5},
		{"COMPARISON_OPERATOR_WITHIN_INCLUSIVE_RANGE", 6},
	}},
	{"cph.aiinfra.foundation.v1.ConfidenceMethod", []enumValueContract{
		{"CONFIDENCE_METHOD_UNSPECIFIED", 0},
		{"CONFIDENCE_METHOD_EXACT", 1},
		{"CONFIDENCE_METHOD_BOOTSTRAP", 2},
		{"CONFIDENCE_METHOD_BINOMIAL", 3},
		{"CONFIDENCE_METHOD_STUDENT_T", 4},
		{"CONFIDENCE_METHOD_NONPARAMETRIC", 5},
	}},
	{"cph.aiinfra.foundation.v1.TransferEvidenceKind", []enumValueContract{
		{"TRANSFER_EVIDENCE_KIND_UNSPECIFIED", 0},
		{"TRANSFER_EVIDENCE_KIND_OLD_PROVIDER_AUTHORITY", 1},
		{"TRANSFER_EVIDENCE_KIND_NEW_PROVIDER_AUTHORITY", 2},
		{"TRANSFER_EVIDENCE_KIND_HOST_SANITATION_ATTESTATION", 3},
		{"TRANSFER_EVIDENCE_KIND_DEVICE_SANITATION_ATTESTATION", 4},
		{"TRANSFER_EVIDENCE_KIND_DESCENDANT_IDENTITY_CLOSURE", 5},
		{"TRANSFER_EVIDENCE_KIND_LEASE_OFFER_WORKLOAD_CLOSURE", 6},
		{"TRANSFER_EVIDENCE_KIND_NEW_ATTESTATION_READINESS", 7},
	}},
}

var reviewedEnumFields = map[protoreflect.FullName]protoreflect.FullName{
	"cph.aiinfra.common.v1.TransportSigningDomain.signature_algorithm":      "cph.aiinfra.common.v1.SignatureAlgorithm",
	"cph.aiinfra.common.v1.TransportEnvelope.signature_algorithm":           "cph.aiinfra.common.v1.SignatureAlgorithm",
	"cph.aiinfra.foundation.v1.ProviderIdentity.state":                      "cph.aiinfra.foundation.v1.IdentityState",
	"cph.aiinfra.foundation.v1.AgentIdentity.state":                         "cph.aiinfra.foundation.v1.IdentityState",
	"cph.aiinfra.foundation.v1.HostIdentity.state":                          "cph.aiinfra.foundation.v1.IdentityState",
	"cph.aiinfra.foundation.v1.DeviceIdentity.state":                        "cph.aiinfra.foundation.v1.IdentityState",
	"cph.aiinfra.foundation.v1.MinerIdentity.state":                         "cph.aiinfra.foundation.v1.IdentityState",
	"cph.aiinfra.foundation.v1.RunnerIdentity.state":                        "cph.aiinfra.foundation.v1.IdentityState",
	"cph.aiinfra.foundation.v1.BuyerIdentity.state":                         "cph.aiinfra.foundation.v1.IdentityState",
	"cph.aiinfra.foundation.v1.ServiceIdentity.state":                       "cph.aiinfra.foundation.v1.IdentityState",
	"cph.aiinfra.foundation.v1.KeyLifecycle.subject_kind":                   "cph.aiinfra.common.v1.PrincipalKind",
	"cph.aiinfra.foundation.v1.KeyLifecycle.algorithm":                      "cph.aiinfra.common.v1.SignatureAlgorithm",
	"cph.aiinfra.foundation.v1.KeyLifecycle.state":                          "cph.aiinfra.foundation.v1.KeyLifecycleState",
	"cph.aiinfra.foundation.v1.PolicyBundle.state":                          "cph.aiinfra.foundation.v1.PolicyBundleState",
	"cph.aiinfra.foundation.v1.AuditEvent.outcome":                          "cph.aiinfra.foundation.v1.AuditOutcome",
	"cph.aiinfra.foundation.v1.MetricCriterion.comparison":                  "cph.aiinfra.foundation.v1.ComparisonOperator",
	"cph.aiinfra.foundation.v1.EvidenceRecord.achieved_level":               "cph.aiinfra.foundation.v1.EvidenceLevel",
	"cph.aiinfra.foundation.v1.EvidenceRecord.status":                       "cph.aiinfra.foundation.v1.EvidenceStatus",
	"cph.aiinfra.foundation.v1.ExperimentPlan.confidence_method":            "cph.aiinfra.foundation.v1.ConfidenceMethod",
	"cph.aiinfra.foundation.v1.ExperimentPlan.target_level":                 "cph.aiinfra.foundation.v1.EvidenceLevel",
	"cph.aiinfra.foundation.v1.TransferEvidenceCommitment.evidence_kind":    "cph.aiinfra.foundation.v1.TransferEvidenceKind",
	"cph.aiinfra.foundation.v1.OwnershipTransferAuthorization.subject_kind": "cph.aiinfra.common.v1.PrincipalKind",
}

func validateTransportDescriptor(root protoreflect.MessageDescriptor, registry schema.Registry) (map[protoreflect.FullName]protoreflect.MessageDescriptor, error) {
	if root == nil || root.FullName() != "cph.aiinfra.transport.v1.SignedFoundationRecord" {
		return nil, fmt.Errorf("%w: transport root descriptor", ErrCatalogMismatch)
	}
	reachable := make(map[protoreflect.FullName]protoreflect.MessageDescriptor)
	reachableEnums := make(map[protoreflect.FullName]protoreflect.EnumDescriptor)
	seenEnumFields := make(map[protoreflect.FullName]struct{})
	var visit func(protoreflect.MessageDescriptor) error
	visit = func(message protoreflect.MessageDescriptor) error {
		if err := validateReachableMessageShape(message); err != nil {
			return err
		}
		if message.FullName() != root.FullName() && (message.ReservedRanges().Len() != 0 || message.ReservedNames().Len() != 0) {
			return fmt.Errorf("%w: invalid descriptor %v", ErrCatalogMismatch, descriptorName(message))
		}
		if _, exists := reachable[message.FullName()]; exists {
			return nil
		}
		reachable[message.FullName()] = message
		fields := message.Fields()
		for index := 0; index < fields.Len(); index++ {
			field := fields.Get(index)
			if field.IsMap() || field.Kind() == protoreflect.GroupKind || field.IsPlaceholder() || field.IsWeak() {
				return fmt.Errorf("%w: unsupported field %s", ErrCatalogMismatch, field.FullName())
			}
			if field.Kind() == protoreflect.EnumKind {
				enum := field.Enum()
				expected, pinned := reviewedEnumFields[field.FullName()]
				if enum == nil || enum.IsPlaceholder() || !pinned || enum.FullName() != expected {
					return fmt.Errorf("%w: enum target for %s", ErrCatalogMismatch, field.FullName())
				}
				reachableEnums[enum.FullName()] = enum
				seenEnumFields[field.FullName()] = struct{}{}
			}
			if field.Kind() == protoreflect.MessageKind {
				if err := visit(field.Message()); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := visit(root); err != nil {
		return nil, err
	}
	if len(seenEnumFields) != len(reviewedEnumFields) {
		return nil, fmt.Errorf("%w: enum field cardinality", ErrCatalogMismatch)
	}
	if err := validateReachableEnums(reachableEnums); err != nil {
		return nil, err
	}

	rootFields := []transportField{
		{1, "signing_domain", protoreflect.MessageKind, false, false, "", "cph.aiinfra.common.v1.TransportSigningDomain"},
		{2, "envelope", protoreflect.MessageKind, false, false, "", "cph.aiinfra.common.v1.TransportEnvelope"},
	}
	for index, expected := range reviewedMessages {
		rootFields = append(rootFields, transportField{
			number: protoreflect.FieldNumber(16 + index), name: protoreflect.Name(payloadFieldName(expected.id)),
			kind: protoreflect.MessageKind, oneof: "payload", message: expected.name,
		})
	}
	if err := validateExactDescriptor(root, rootFields, []protoreflect.Name{"payload"}); err != nil {
		return nil, err
	}
	if root.ReservedRanges().Len() != 1 || root.ReservedRanges().Get(0)[0] != 3 || root.ReservedRanges().Get(0)[1] != 16 || root.ReservedNames().Len() != 0 {
		return nil, fmt.Errorf("%w: wrapper reserved range", ErrCatalogMismatch)
	}

	if err := validateExactDescriptor(reachable["cph.aiinfra.common.v1.SchemaVersion"], []transportField{
		{1, "major", protoreflect.Uint32Kind, false, false, "", ""},
		{2, "minor", protoreflect.Uint32Kind, false, false, "", ""},
	}, nil); err != nil {
		return nil, err
	}
	if err := validateExactDescriptor(reachable["cph.aiinfra.common.v1.ProtocolVersion"], []transportField{
		{1, "major", protoreflect.Uint32Kind, false, false, "", ""},
		{2, "minor", protoreflect.Uint32Kind, false, false, "", ""},
	}, nil); err != nil {
		return nil, err
	}
	if err := validateExactDescriptor(reachable["cph.aiinfra.common.v1.TransportSigningDomain"], domainTransportFields(), []protoreflect.Name{"replay_guard"}); err != nil {
		return nil, err
	}
	if err := validateExactDescriptor(reachable["cph.aiinfra.common.v1.TransportEnvelope"], envelopeTransportFields(), []protoreflect.Name{"replay_guard"}); err != nil {
		return nil, err
	}
	if err := validateExactDescriptor(reachable["cph.aiinfra.common.v1.TransportExtension"], []transportField{
		{1, "extension_id", protoreflect.Uint32Kind, false, false, "", ""},
		{2, "critical", protoreflect.BoolKind, false, false, "", ""},
		{3, "value", protoreflect.BytesKind, false, false, "", ""},
	}, nil); err != nil {
		return nil, err
	}

	for _, message := range registry.Messages {
		descriptor := reachable[protoreflect.FullName(message.Name)]
		if err := validateProjectionDescriptor(descriptor, message.Fields); err != nil {
			return nil, err
		}
	}
	for _, structure := range registry.Structures {
		descriptor := reachable[protoreflect.FullName(structure.Name)]
		if err := validateProjectionDescriptor(descriptor, structure.Fields); err != nil {
			return nil, err
		}
	}
	return reachable, nil
}

func domainTransportFields() []transportField {
	return []transportField{
		{1, "purpose", protoreflect.StringKind, false, false, "", ""},
		{2, "sender_identity", protoreflect.StringKind, false, false, "", ""},
		{3, "audience", protoreflect.StringKind, true, false, "", ""},
		{4, "tenant_organization", protoreflect.StringKind, false, true, "_tenant_organization", ""},
		{5, "provider_organization", protoreflect.StringKind, false, true, "_provider_organization", ""},
		{6, "chain_id_uint256_be", protoreflect.BytesKind, false, false, "", ""},
		{7, "genesis_hash_sha256", protoreflect.BytesKind, false, false, "", ""},
		{8, "environment", protoreflect.StringKind, false, false, "", ""},
		{9, "protocol_version", protoreflect.MessageKind, false, false, "", "cph.aiinfra.common.v1.ProtocolVersion"},
		{10, "schema_version", protoreflect.MessageKind, false, false, "", "cph.aiinfra.common.v1.SchemaVersion"},
		{number: 11, name: "signature_algorithm", kind: protoreflect.EnumKind},
		{12, "signature_key_id", protoreflect.StringKind, false, false, "", ""},
		{13, "issued_at_unix_nano", protoreflect.Int64Kind, false, false, "", ""},
		{14, "expires_at_unix_nano", protoreflect.Int64Kind, false, false, "", ""},
		{15, "sequence", protoreflect.Uint64Kind, false, false, "replay_guard", ""},
		{16, "expected_generation", protoreflect.Uint64Kind, false, false, "replay_guard", ""},
		{17, "replay_domain_id", protoreflect.StringKind, false, false, "", ""},
	}
}

func envelopeTransportFields() []transportField {
	return []transportField{
		{1, "protocol_version", protoreflect.MessageKind, false, false, "", "cph.aiinfra.common.v1.ProtocolVersion"},
		{2, "schema_version", protoreflect.MessageKind, false, false, "", "cph.aiinfra.common.v1.SchemaVersion"},
		{3, "message_id", protoreflect.BytesKind, false, false, "", ""},
		{4, "correlation_id", protoreflect.BytesKind, false, false, "", ""},
		{5, "causation_id", protoreflect.BytesKind, false, true, "_causation_id", ""},
		{6, "sender_identity", protoreflect.StringKind, false, false, "", ""},
		{7, "chain_id_uint256_be", protoreflect.BytesKind, false, false, "", ""},
		{8, "environment", protoreflect.StringKind, false, false, "", ""},
		{9, "issued_at_unix_nano", protoreflect.Int64Kind, false, false, "", ""},
		{10, "expires_at_unix_nano", protoreflect.Int64Kind, false, false, "", ""},
		{11, "sequence", protoreflect.Uint64Kind, false, false, "replay_guard", ""},
		{12, "expected_generation", protoreflect.Uint64Kind, false, false, "replay_guard", ""},
		{13, "payload_digest_sha256", protoreflect.BytesKind, false, false, "", ""},
		{number: 14, name: "signature_algorithm", kind: protoreflect.EnumKind},
		{15, "signature_key_id", protoreflect.StringKind, false, false, "", ""},
		{16, "extensions", protoreflect.MessageKind, true, false, "", "cph.aiinfra.common.v1.TransportExtension"},
		{17, "signature", protoreflect.BytesKind, false, false, "", ""},
	}
}

func validateExactDescriptor(descriptor protoreflect.MessageDescriptor, expected []transportField, realOneofs []protoreflect.Name) error {
	if descriptor == nil || descriptor.IsPlaceholder() || descriptor.Fields().Len() != len(expected) {
		return fmt.Errorf("%w: descriptor %v field count", ErrCatalogMismatch, descriptorName(descriptor))
	}
	for _, rule := range expected {
		field := descriptor.Fields().ByNumber(rule.number)
		if field == nil || field.Name() != rule.name || field.Kind() != rule.kind || field.IsList() != rule.list ||
			field.HasOptionalKeyword() != rule.optional || field.Cardinality() != expectedCardinality(rule.list) ||
			field.HasPresence() != expectedPresence(rule.kind, rule.optional, rule.oneof, rule.list) || field.IsPacked() != expectedPacked(rule.kind, rule.list) ||
			field.HasDefault() {
			return fmt.Errorf("%w: descriptor %s field %d", ErrCatalogMismatch, descriptor.FullName(), rule.number)
		}
		oneof := protoreflect.Name("")
		if field.ContainingOneof() != nil {
			oneof = field.ContainingOneof().Name()
		}
		if oneof != rule.oneof {
			return fmt.Errorf("%w: descriptor %s field %s oneof", ErrCatalogMismatch, descriptor.FullName(), field.Name())
		}
		if rule.message != "" && (field.Message() == nil || field.Message().FullName() != rule.message) {
			return fmt.Errorf("%w: descriptor %s field %s target", ErrCatalogMismatch, descriptor.FullName(), field.Name())
		}
	}
	expectedOneofs := make(map[protoreflect.Name]bool)
	for _, rule := range expected {
		if rule.oneof != "" {
			expectedOneofs[rule.oneof] = rule.optional
		}
	}
	if descriptor.Oneofs().Len() != len(expectedOneofs) {
		return fmt.Errorf("%w: descriptor %s total oneof count", ErrCatalogMismatch, descriptor.FullName())
	}
	actualReal := make([]protoreflect.Name, 0, descriptor.Oneofs().Len())
	for index := 0; index < descriptor.Oneofs().Len(); index++ {
		oneof := descriptor.Oneofs().Get(index)
		synthetic, ok := expectedOneofs[oneof.Name()]
		if !ok || oneof.IsSynthetic() != synthetic {
			return fmt.Errorf("%w: descriptor %s oneof %s shape", ErrCatalogMismatch, descriptor.FullName(), oneof.Name())
		}
		if !oneof.IsSynthetic() {
			actualReal = append(actualReal, oneof.Name())
		}
	}
	if len(actualReal) != len(realOneofs) {
		return fmt.Errorf("%w: descriptor %s oneof count", ErrCatalogMismatch, descriptor.FullName())
	}
	for index := range realOneofs {
		if actualReal[index] != realOneofs[index] {
			return fmt.Errorf("%w: descriptor %s oneof %d", ErrCatalogMismatch, descriptor.FullName(), index)
		}
	}
	return nil
}

func validateProjectionDescriptor(descriptor protoreflect.MessageDescriptor, rules []schema.Field) error {
	if descriptor == nil || descriptor.IsPlaceholder() || descriptor.Fields().Len() != len(rules) {
		return fmt.Errorf("%w: projection descriptor %v", ErrCatalogMismatch, descriptorName(descriptor))
	}
	optionalCount := 0
	for index, rule := range rules {
		field := descriptor.Fields().ByNumber(protoreflect.FieldNumber(index + 1))
		if field == nil || string(field.Name()) != rule.Name || field.IsMap() || field.IsList() != (rule.Collection != "scalar") ||
			field.HasOptionalKeyword() != (rule.Presence == "optional") || !registryKindMatches(field.Kind(), rule.Type) ||
			field.Cardinality() != expectedCardinality(rule.Collection != "scalar") ||
			field.HasPresence() != expectedPresence(field.Kind(), rule.Presence == "optional", "", rule.Collection != "scalar") ||
			field.IsPacked() != expectedPacked(field.Kind(), rule.Collection != "scalar") || field.HasDefault() {
			return fmt.Errorf("%w: projection %s field %d (%s)", ErrCatalogMismatch, descriptor.FullName(), index+1, rule.Name)
		}
		oneof := field.ContainingOneof()
		if rule.Presence == "optional" {
			optionalCount++
			if oneof == nil || !oneof.IsSynthetic() || oneof.Name() != protoreflect.Name("_"+rule.Name) {
				return fmt.Errorf("%w: projection %s field %s optional oneof", ErrCatalogMismatch, descriptor.FullName(), rule.Name)
			}
		} else if oneof != nil {
			return fmt.Errorf("%w: projection %s field %s unexpected oneof", ErrCatalogMismatch, descriptor.FullName(), rule.Name)
		}
		if rule.Type == "message" && (field.Message() == nil || string(field.Message().FullName()) != rule.MessageType) {
			return fmt.Errorf("%w: projection %s field %s target", ErrCatalogMismatch, descriptor.FullName(), rule.Name)
		}
		if rule.Type == "enum_uint32" {
			expected, ok := reviewedEnumFields[field.FullName()]
			if !ok || field.Enum() == nil || field.Enum().FullName() != expected {
				return fmt.Errorf("%w: projection %s field %s enum target", ErrCatalogMismatch, descriptor.FullName(), rule.Name)
			}
		}
	}
	if descriptor.Oneofs().Len() != optionalCount {
		return fmt.Errorf("%w: projection %s total oneof count", ErrCatalogMismatch, descriptor.FullName())
	}
	for index := 0; index < descriptor.Oneofs().Len(); index++ {
		if !descriptor.Oneofs().Get(index).IsSynthetic() {
			return fmt.Errorf("%w: projection %s real oneof", ErrCatalogMismatch, descriptor.FullName())
		}
	}
	return nil
}

func validateReachableMessageShape(message protoreflect.MessageDescriptor) error {
	if message == nil || message.IsPlaceholder() || message.IsMapEntry() {
		return fmt.Errorf("%w: invalid descriptor %v", ErrCatalogMismatch, descriptorName(message))
	}
	if message.ExtensionRanges().Len() != 0 {
		return fmt.Errorf("%w: descriptor %s extension ranges", ErrCatalogMismatch, message.FullName())
	}
	if message.Syntax() != protoreflect.Proto3 {
		return fmt.Errorf("%w: descriptor %s syntax", ErrCatalogMismatch, message.FullName())
	}
	return nil
}

func validateReachableEnums(reachable map[protoreflect.FullName]protoreflect.EnumDescriptor) error {
	if len(reachable) != len(reviewedEnums) {
		return fmt.Errorf("%w: reachable enum cardinality", ErrCatalogMismatch)
	}
	for _, contract := range reviewedEnums {
		descriptor := reachable[contract.name]
		if descriptor == nil || descriptor.IsPlaceholder() || descriptor.FullName() != contract.name ||
			descriptor.Syntax() != protoreflect.Proto3 || descriptor.Values().Len() != len(contract.values) ||
			descriptor.ReservedRanges().Len() != 0 || descriptor.ReservedNames().Len() != 0 {
			return fmt.Errorf("%w: enum descriptor %s", ErrCatalogMismatch, contract.name)
		}
		for index, expected := range contract.values {
			value := descriptor.Values().Get(index)
			if value.Name() != expected.name || value.Number() != expected.number {
				return fmt.Errorf("%w: enum %s value %d", ErrCatalogMismatch, contract.name, index)
			}
		}
	}
	return nil
}

func expectedCardinality(list bool) protoreflect.Cardinality {
	if list {
		return protoreflect.Repeated
	}
	return protoreflect.Optional
}

func expectedPresence(kind protoreflect.Kind, optional bool, oneof protoreflect.Name, list bool) bool {
	return !list && (kind == protoreflect.MessageKind || optional || oneof != "")
}

func expectedPacked(kind protoreflect.Kind, list bool) bool {
	if !list {
		return false
	}
	switch kind {
	case protoreflect.BoolKind, protoreflect.EnumKind,
		protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind,
		protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind,
		protoreflect.Uint32Kind, protoreflect.Fixed32Kind,
		protoreflect.Uint64Kind, protoreflect.Fixed64Kind,
		protoreflect.FloatKind, protoreflect.DoubleKind:
		return true
	default:
		return false
	}
}

func registryKindMatches(kind protoreflect.Kind, registryType string) bool {
	switch registryType {
	case "bool":
		return kind == protoreflect.BoolKind
	case "uint32":
		return kind == protoreflect.Uint32Kind
	case "enum_uint32":
		return kind == protoreflect.EnumKind
	case "uint64":
		return kind == protoreflect.Uint64Kind
	case "int64":
		return kind == protoreflect.Int64Kind
	case "string":
		return kind == protoreflect.StringKind
	case "bytes", "fixed_bytes_16", "fixed_bytes_32", "fixed_bytes_64":
		return kind == protoreflect.BytesKind
	case "message":
		return kind == protoreflect.MessageKind
	default:
		return false
	}
}

func descriptorName(descriptor protoreflect.MessageDescriptor) protoreflect.FullName {
	if descriptor == nil {
		return "<nil>"
	}
	return descriptor.FullName()
}
