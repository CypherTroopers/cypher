// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

// Package translator converts the strictly validated Protobuf transport for a
// foundation authorization into its transport-independent CCSE record. The
// returned record is deliberately named unverified: callers MUST pass it to a
// fully configured ccse.Verifier before causing any state change.
package translator

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/schema"
	commonv1 "github.com/cypherium/cypher/aiinfra/schema/common/v1"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
	"github.com/cypherium/cypher/aiinfra/schema/foundation/v1/canonical"
	"github.com/cypherium/cypher/aiinfra/schema/strictproto"
	transportv1 "github.com/cypherium/cypher/aiinfra/schema/transport/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	expectedRegistrySHA256 = "5a4faaee3e51629aed73edbb17047a865b223add9aece7dbe90f27fbfd4a30eb"
	maxTransportBytes      = 640 << 10
	maxTransportFields     = 4096
	maxTransportDepth      = 7
	maxTransportItems      = 1024
	maxSignatureBytes      = 128
)

var (
	ErrCatalogMismatch      = errors.New("aiinfra foundation translator: catalog mismatch")
	ErrMissingRequiredField = errors.New("aiinfra foundation translator: missing required field")
	ErrInvalidFixedLength   = errors.New("aiinfra foundation translator: invalid fixed-width field")
	ErrInvalidPurpose       = errors.New("aiinfra foundation translator: invalid signing purpose")
	ErrInvalidSchemaVersion = errors.New("aiinfra foundation translator: invalid schema version")
	ErrInvalidPayload       = errors.New("aiinfra foundation translator: invalid payload selection")
	ErrExtensionPolicy      = errors.New("aiinfra foundation translator: signed extensions are not registered")
	ErrInvalidSignatureSize = errors.New("aiinfra foundation translator: invalid signature size")
)

var schemaV1 = ccse.Version{Major: 1, Minor: 0}

type signingProjection interface {
	CanonicalBytes() ([]byte, error)
	MessageTypeID() uint32
}

type catalogMessage struct {
	id       uint32
	name     protoreflect.FullName
	purpose  string
	maxBytes int
}

var reviewedMessages = [...]catalogMessage{
	{schema.MessageTypeProviderIdentity, "cph.aiinfra.foundation.v1.ProviderIdentity", "identity.provider.bind", 32768},
	{schema.MessageTypeAgentIdentity, "cph.aiinfra.foundation.v1.AgentIdentity", "identity.agent.bind", 24576},
	{schema.MessageTypeHostIdentity, "cph.aiinfra.foundation.v1.HostIdentity", "identity.host.bind", 24576},
	{schema.MessageTypeDeviceIdentity, "cph.aiinfra.foundation.v1.DeviceIdentity", "identity.device.bind", 24576},
	{schema.MessageTypeMinerIdentity, "cph.aiinfra.foundation.v1.MinerIdentity", "identity.miner.bind", 32768},
	{schema.MessageTypeRunnerIdentity, "cph.aiinfra.foundation.v1.RunnerIdentity", "identity.runner.bind", 28672},
	{schema.MessageTypeBuyerIdentity, "cph.aiinfra.foundation.v1.BuyerIdentity", "identity.buyer.bind", 24576},
	{schema.MessageTypeServiceIdentity, "cph.aiinfra.foundation.v1.ServiceIdentity", "identity.service.bind", 24576},
	{schema.MessageTypeKeyLifecycle, "cph.aiinfra.foundation.v1.KeyLifecycle", "identity.key.lifecycle", 32768},
	{schema.MessageTypePolicyBundle, "cph.aiinfra.foundation.v1.PolicyBundle", "governance.policy.bundle", 49152},
	{schema.MessageTypeAuditEvent, "cph.aiinfra.foundation.v1.AuditEvent", "audit.event.append", 65536},
	{schema.MessageTypeEvidenceRecord, "cph.aiinfra.foundation.v1.EvidenceRecord", "evidence.record.release", 262144},
	{schema.MessageTypeExperimentPlan, "cph.aiinfra.foundation.v1.ExperimentPlan", "evidence.experiment.plan.freeze", 262144},
	{schema.MessageTypeOwnershipTransferAuthorization, "cph.aiinfra.foundation.v1.OwnershipTransferAuthorization", "identity.ownership.transfer.authorize", 196608},
}

type transportProfile struct {
	limits    strictproto.Limits
	messages  map[uint32]schema.Message
	canonical *canonical.Validator
}

var (
	profileOnce sync.Once
	profile     transportProfile
	profileErr  error
)

// TranslateUnverified strictly decodes one transport wrapper and returns a
// detached CCSE record that has NOT had its signature, key status, time,
// replay state, or receiver policy verified. The function validates the exact
// transport shape, reconstructs the canonical payload, checks its supplied
// digest and all duplicate domain/envelope bindings, and preserves the
// transport-supplied digest and signature without replacing either value.
func TranslateUnverified(wire []byte) (*ccse.Record, error) {
	configured, err := loadTransportProfile()
	if err != nil {
		return nil, err
	}
	var wrapper transportv1.SignedFoundationRecord
	descriptor := wrapper.ProtoReflect().Descriptor()
	if err := strictproto.Unmarshal(wire, &wrapper, descriptor, configured.limits); err != nil {
		return nil, fmt.Errorf("aiinfra foundation translator: strict decode: %w", err)
	}
	if wrapper.SigningDomain == nil {
		return nil, missing("signing_domain")
	}
	if wrapper.Envelope == nil {
		return nil, missing("envelope")
	}

	messageTypeID, err := selectedMessageTypeID(&wrapper)
	if err != nil {
		return nil, err
	}
	registered, ok := configured.messages[messageTypeID]
	if !ok {
		return nil, fmt.Errorf("%w: message type %d", ErrCatalogMismatch, messageTypeID)
	}

	domain, err := translateDomain(wrapper.SigningDomain)
	if err != nil {
		return nil, err
	}
	envelope, err := translateEnvelope(wrapper.Envelope)
	if err != nil {
		return nil, err
	}
	if domain.Purpose != registered.Purpose {
		return nil, fmt.Errorf("%w: type %d has %q, want %q", ErrInvalidPurpose, messageTypeID, domain.Purpose, registered.Purpose)
	}
	if domain.SchemaVersion != schemaV1 || envelope.SchemaVersion != schemaV1 {
		return nil, fmt.Errorf("%w: domain=%d.%d envelope=%d.%d", ErrInvalidSchemaVersion,
			domain.SchemaVersion.Major, domain.SchemaVersion.Minor,
			envelope.SchemaVersion.Major, envelope.SchemaVersion.Minor)
	}
	if len(envelope.Extensions) != 0 {
		for _, extension := range envelope.Extensions {
			if extension.Critical {
				return nil, fmt.Errorf("%w: %w: extension %d", ErrExtensionPolicy, ccse.ErrUnknownCriticalExtension, extension.ID)
			}
		}
		return nil, fmt.Errorf("%w: %w", ErrExtensionPolicy, ccse.ErrUnknownExtension)
	}
	if len(wrapper.Envelope.Signature) == 0 || len(wrapper.Envelope.Signature) > maxSignatureBytes {
		return nil, fmt.Errorf("%w: got %d, want 1..%d", ErrInvalidSignatureSize, len(wrapper.Envelope.Signature), maxSignatureBytes)
	}
	// Reject malformed or cross-bound headers before walking, projecting, or
	// hashing the potentially much larger payload. The supplied payload digest
	// is deliberately excluded from this pass and remains untouched for the
	// authoritative comparison after canonical payload reconstruction.
	if err := validateHeaderBeforePayload(messageTypeID, domain, envelope); err != nil {
		return nil, err
	}

	translatedMessageTypeID, projection, err := translatePayload(&wrapper)
	if err != nil {
		return nil, err
	}
	if projection == nil || translatedMessageTypeID != messageTypeID || projection.MessageTypeID() != messageTypeID {
		return nil, fmt.Errorf("%w: projection type does not match oneof", ErrInvalidPayload)
	}
	payload, err := projection.CanonicalBytes()
	if err != nil {
		return nil, fmt.Errorf("%w: canonical projection: %w", ErrInvalidPayload, err)
	}
	if _, err := configured.canonical.Decode(messageTypeID, schemaV1, payload); err != nil {
		return nil, fmt.Errorf("%w: independent canonical decode: %w", ErrInvalidPayload, err)
	}
	digest := sha256.Sum256(payload)
	if !bytes.Equal(digest[:], envelope.PayloadDigest[:]) {
		return nil, ccse.ErrPayloadDigestMismatch
	}

	// Do not construct the final record with ccse.NewRecord: it intentionally
	// overwrites the supplied payload digest. A receiver must distinguish an
	// authentic supplied digest from a locally repaired one.
	record := &ccse.Record{
		MessageTypeID: messageTypeID,
		SchemaVersion: schemaV1,
		Domain:        cloneDomain(domain),
		Envelope:      cloneEnvelope(envelope),
		Payload:       append([]byte(nil), payload...),
		Signature:     append([]byte(nil), wrapper.Envelope.Signature...),
	}
	limits := ccse.DefaultLimits()
	limits.MaxPayloadBytes = registered.Limits.MaxPayloadBytes
	limits.MaxSignatureBytes = maxSignatureBytes
	if _, err := record.Preimage(limits); err != nil {
		return nil, fmt.Errorf("aiinfra foundation translator: invalid CCSE binding: %w", err)
	}
	return record, nil
}

func validateHeaderBeforePayload(messageTypeID uint32, domain ccse.Domain, envelope ccse.Envelope) error {
	if domain.ProtocolVersion != envelope.ProtocolVersion ||
		domain.SchemaVersion != envelope.SchemaVersion ||
		domain.SenderIdentity != envelope.SenderIdentity ||
		domain.ChainID != envelope.ChainID ||
		domain.Environment != envelope.Environment ||
		domain.IssuedAtUnixNano != envelope.IssuedAtUnixNano ||
		domain.ExpiresAtUnixNano != envelope.ExpiresAtUnixNano ||
		domain.CounterKind != envelope.CounterKind ||
		domain.Counter != envelope.Counter ||
		domain.SignatureAlgorithm != envelope.SignatureAlgorithm ||
		domain.SignatureKeyID != envelope.SignatureKeyID {
		return ccse.ErrDomainEnvelopeMismatch
	}

	// NewRecord operates on detached values and replaces only its private
	// envelope copy's digest with SHA-256(empty). This reuses the normative CCSE
	// domain/envelope validation without repairing or otherwise changing the
	// transport-supplied digest that TranslateUnverified later preserves.
	if _, err := ccse.NewRecord(messageTypeID, schemaV1, domain, envelope, nil); err != nil {
		return fmt.Errorf("aiinfra foundation translator: invalid CCSE header: %w", err)
	}
	return nil
}

func loadTransportProfile() (transportProfile, error) {
	profileOnce.Do(func() {
		profile, profileErr = buildTransportProfile()
	})
	return profile, profileErr
}

func buildTransportProfile() (transportProfile, error) {
	canonicalValidator, err := canonical.NewValidator()
	if err != nil {
		return transportProfile{}, fmt.Errorf("%w: canonical validator: %v", ErrCatalogMismatch, err)
	}
	registry, err := schema.LoadDefault()
	if err != nil {
		return transportProfile{}, fmt.Errorf("%w: load registry: %v", ErrCatalogMismatch, err)
	}
	digest, err := registry.SHA256Hex()
	if err != nil || digest != expectedRegistrySHA256 {
		return transportProfile{}, fmt.Errorf("%w: registry SHA-256 %q", ErrCatalogMismatch, digest)
	}
	if len(registry.Messages) != len(reviewedMessages) || len(registry.Structures) != 7 {
		return transportProfile{}, fmt.Errorf("%w: registry cardinality", ErrCatalogMismatch)
	}

	root := (&transportv1.SignedFoundationRecord{}).ProtoReflect().Descriptor()
	reachable, err := validateTransportDescriptor(root, registry)
	if err != nil {
		return transportProfile{}, err
	}

	limits := strictproto.Limits{
		MaxMessageBytes:  maxTransportBytes,
		MaxFieldBytes:    262144,
		MaxTotalFields:   maxTransportFields,
		MaxDepth:         maxTransportDepth,
		MaxRepeatedItems: maxTransportItems,
	}
	limits = limits.WithMessageByteLimit(root.FullName(), maxTransportBytes)
	limits = limits.WithMessageByteLimit("cph.aiinfra.common.v1.TransportSigningDomain", 64<<10)
	limits = limits.WithMessageByteLimit("cph.aiinfra.common.v1.TransportEnvelope", 256<<10)
	limits = limits.WithMessageByteLimit("cph.aiinfra.common.v1.TransportExtension", 4<<10)
	limits = limits.WithMessageByteLimit("cph.aiinfra.common.v1.ProtocolVersion", 12)

	messages := make(map[uint32]schema.Message, len(reviewedMessages))
	for index, expected := range reviewedMessages {
		registered, ok := registry.LookupMessage(expected.id)
		if !ok || registered.Name != string(expected.name) || registered.Purpose != expected.purpose ||
			registered.SchemaVersion != (schema.Version{Major: 1, Minor: 0}) ||
			registered.UnknownFieldPolicy != "reject" || registered.Limits.MaxPayloadBytes != expected.maxBytes ||
			registry.Messages[index].MessageTypeID != expected.id {
			return transportProfile{}, fmt.Errorf("%w: message %d", ErrCatalogMismatch, expected.id)
		}
		messages[expected.id] = registered
		limits = installProjectionLimits(limits, reachable[expected.name], registered.Limits, registered.Fields)
	}
	for _, structure := range registry.Structures {
		descriptor := reachable[protoreflect.FullName(structure.Name)]
		limits = installProjectionLimits(limits, descriptor, structure.Limits, structure.Fields)
	}
	// SchemaVersion uses fixed-width CCSE u32s but Protobuf uint32 varints may
	// occupy five bytes each plus tags. The semantic translator still fixes the
	// authorization schema to 1.0.
	limits = limits.WithMessageByteLimit("cph.aiinfra.common.v1.SchemaVersion", 12)

	limits = installTransportLimits(limits)
	if err := limits.Validate(); err != nil {
		return transportProfile{}, fmt.Errorf("%w: invalid strict limits: %v", ErrCatalogMismatch, err)
	}
	return transportProfile{limits: limits, messages: messages, canonical: canonicalValidator}, nil
}

func installProjectionLimits(limits strictproto.Limits, descriptor protoreflect.MessageDescriptor, projectionLimits schema.Limits, fields []schema.Field) strictproto.Limits {
	limits = limits.WithMessageByteLimit(descriptor.FullName(), projectionLimits.MaxPayloadBytes)
	for _, rule := range fields {
		field := descriptor.Fields().ByName(protoreflect.Name(rule.Name))
		limits = limits.WithFieldByteLimit(field.FullName(), protobufFieldLimit(field, rule.MaxEncodedBytes))
		if field.IsList() {
			limits = limits.WithRepeatedItemLimit(field.FullName(), rule.MaxItems)
		}
	}
	return limits
}

func protobufFieldLimit(field protoreflect.FieldDescriptor, registryBound int) int {
	minimum := 1
	switch field.Kind() {
	case protoreflect.BoolKind:
		minimum = 1
	case protoreflect.EnumKind, protoreflect.Uint32Kind, protoreflect.Int32Kind:
		minimum = 5
	case protoreflect.Uint64Kind, protoreflect.Int64Kind:
		minimum = 10
	}
	if registryBound < minimum {
		return minimum
	}
	return registryBound
}

func installTransportLimits(limits strictproto.Limits) strictproto.Limits {
	messageLimits := map[protoreflect.FullName]int{
		"cph.aiinfra.common.v1.TransportSigningDomain": 64 << 10,
		"cph.aiinfra.common.v1.TransportEnvelope":      256 << 10,
		"cph.aiinfra.common.v1.TransportExtension":     4 << 10,
		"cph.aiinfra.common.v1.ProtocolVersion":        12,
	}
	for name, value := range messageLimits {
		limits = limits.WithMessageByteLimit(name, value)
	}
	fieldLimits := map[protoreflect.FullName]int{
		"cph.aiinfra.transport.v1.SignedFoundationRecord.signing_domain":     64 << 10,
		"cph.aiinfra.transport.v1.SignedFoundationRecord.envelope":           256 << 10,
		"cph.aiinfra.common.v1.TransportSigningDomain.purpose":               128,
		"cph.aiinfra.common.v1.TransportSigningDomain.sender_identity":       1024,
		"cph.aiinfra.common.v1.TransportSigningDomain.audience":              32 << 10,
		"cph.aiinfra.common.v1.TransportSigningDomain.tenant_organization":   1024,
		"cph.aiinfra.common.v1.TransportSigningDomain.provider_organization": 1024,
		"cph.aiinfra.common.v1.TransportSigningDomain.chain_id_uint256_be":   32,
		"cph.aiinfra.common.v1.TransportSigningDomain.genesis_hash_sha256":   32,
		"cph.aiinfra.common.v1.TransportSigningDomain.environment":           128,
		"cph.aiinfra.common.v1.TransportSigningDomain.signature_key_id":      256,
		"cph.aiinfra.common.v1.TransportSigningDomain.replay_domain_id":      256,
		"cph.aiinfra.common.v1.TransportEnvelope.message_id":                 16,
		"cph.aiinfra.common.v1.TransportEnvelope.correlation_id":             16,
		"cph.aiinfra.common.v1.TransportEnvelope.causation_id":               16,
		"cph.aiinfra.common.v1.TransportEnvelope.sender_identity":            1024,
		"cph.aiinfra.common.v1.TransportEnvelope.chain_id_uint256_be":        32,
		"cph.aiinfra.common.v1.TransportEnvelope.environment":                128,
		"cph.aiinfra.common.v1.TransportEnvelope.payload_digest_sha256":      32,
		"cph.aiinfra.common.v1.TransportEnvelope.signature_key_id":           256,
		"cph.aiinfra.common.v1.TransportEnvelope.extensions":                 64 << 10,
		"cph.aiinfra.common.v1.TransportEnvelope.signature":                  maxSignatureBytes,
		"cph.aiinfra.common.v1.TransportExtension.value":                     4 << 10,
	}
	for _, expected := range reviewedMessages {
		fieldLimits["cph.aiinfra.transport.v1.SignedFoundationRecord."+payloadFieldName(expected.id)] = expected.maxBytes
	}
	for name, value := range fieldLimits {
		limits = limits.WithFieldByteLimit(name, value)
	}
	limits = limits.WithRepeatedItemLimit("cph.aiinfra.common.v1.TransportSigningDomain.audience", 64)
	limits = limits.WithRepeatedItemLimit("cph.aiinfra.common.v1.TransportEnvelope.extensions", 64)
	return limits
}

func payloadFieldName(messageTypeID uint32) protoreflect.FullName {
	names := [...]string{
		"provider_identity", "agent_identity", "host_identity", "device_identity", "miner_identity",
		"runner_identity", "buyer_identity", "service_identity", "key_lifecycle", "policy_bundle",
		"audit_event", "evidence_record", "experiment_plan", "ownership_transfer_authorization",
	}
	index := int(messageTypeID - schema.MessageTypeProviderIdentity)
	if index < 0 || index >= len(names) {
		return "invalid"
	}
	return protoreflect.FullName(names[index])
}

func translateDomain(input *commonv1.TransportSigningDomain) (ccse.Domain, error) {
	protocolVersion, err := protocolVersion(input.ProtocolVersion, "signing_domain.protocol_version")
	if err != nil {
		return ccse.Domain{}, err
	}
	schemaVersion, err := requiredSchemaV1(input.SchemaVersion, "signing_domain.schema_version")
	if err != nil {
		return ccse.Domain{}, err
	}
	chainID, err := fixed32(input.ChainIdUint256Be, "signing_domain.chain_id_uint256_be")
	if err != nil {
		return ccse.Domain{}, err
	}
	genesisHash, err := fixed32(input.GenesisHashSha256, "signing_domain.genesis_hash_sha256")
	if err != nil {
		return ccse.Domain{}, err
	}
	counterKind, counter, err := domainReplay(input)
	if err != nil {
		return ccse.Domain{}, err
	}
	algorithm, err := signatureAlgorithm(input.SignatureAlgorithm, "signing_domain.signature_algorithm")
	if err != nil {
		return ccse.Domain{}, err
	}
	return ccse.Domain{
		Purpose:              input.Purpose,
		SenderIdentity:       input.SenderIdentity,
		Audience:             append([]string(nil), input.Audience...),
		TenantOrganization:   optionalString(input.TenantOrganization),
		ProviderOrganization: optionalString(input.ProviderOrganization),
		ChainID:              chainID,
		GenesisHash:          genesisHash,
		Environment:          input.Environment,
		ProtocolVersion:      protocolVersion,
		SchemaVersion:        schemaVersion,
		SignatureAlgorithm:   algorithm,
		SignatureKeyID:       input.SignatureKeyId,
		IssuedAtUnixNano:     input.IssuedAtUnixNano,
		ExpiresAtUnixNano:    input.ExpiresAtUnixNano,
		CounterKind:          counterKind,
		Counter:              counter,
		ReplayDomainID:       input.ReplayDomainId,
	}, nil
}

func translateEnvelope(input *commonv1.TransportEnvelope) (ccse.Envelope, error) {
	protocolVersion, err := protocolVersion(input.ProtocolVersion, "envelope.protocol_version")
	if err != nil {
		return ccse.Envelope{}, err
	}
	schemaVersion, err := requiredSchemaV1(input.SchemaVersion, "envelope.schema_version")
	if err != nil {
		return ccse.Envelope{}, err
	}
	messageID, err := fixed16(input.MessageId, "envelope.message_id")
	if err != nil {
		return ccse.Envelope{}, err
	}
	correlationID, err := fixed16(input.CorrelationId, "envelope.correlation_id")
	if err != nil {
		return ccse.Envelope{}, err
	}
	causationID, err := optionalFixed16(input.CausationId, "envelope.causation_id")
	if err != nil {
		return ccse.Envelope{}, err
	}
	chainID, err := fixed32(input.ChainIdUint256Be, "envelope.chain_id_uint256_be")
	if err != nil {
		return ccse.Envelope{}, err
	}
	payloadDigest, err := fixed32(input.PayloadDigestSha256, "envelope.payload_digest_sha256")
	if err != nil {
		return ccse.Envelope{}, err
	}
	counterKind, counter, err := envelopeReplay(input)
	if err != nil {
		return ccse.Envelope{}, err
	}
	algorithm, err := signatureAlgorithm(input.SignatureAlgorithm, "envelope.signature_algorithm")
	if err != nil {
		return ccse.Envelope{}, err
	}
	extensions, err := translateExtensions(input.Extensions)
	if err != nil {
		return ccse.Envelope{}, err
	}
	return ccse.Envelope{
		ProtocolVersion:    protocolVersion,
		SchemaVersion:      schemaVersion,
		MessageID:          messageID,
		CorrelationID:      correlationID,
		CausationID:        causationID,
		SenderIdentity:     input.SenderIdentity,
		ChainID:            chainID,
		Environment:        input.Environment,
		IssuedAtUnixNano:   input.IssuedAtUnixNano,
		ExpiresAtUnixNano:  input.ExpiresAtUnixNano,
		CounterKind:        counterKind,
		Counter:            counter,
		PayloadDigest:      payloadDigest,
		SignatureAlgorithm: algorithm,
		SignatureKeyID:     input.SignatureKeyId,
		Extensions:         extensions,
	}, nil
}

func translateExtensions(input []*commonv1.TransportExtension) ([]ccse.Extension, error) {
	out := make([]ccse.Extension, 0, len(input))
	seen := make(map[uint32]struct{}, len(input))
	for index, extension := range input {
		if extension == nil {
			return nil, missing(fmt.Sprintf("envelope.extensions[%d]", index))
		}
		if extension.ExtensionId == 0 {
			return nil, ccse.ErrInvalidExtension
		}
		if _, duplicate := seen[extension.ExtensionId]; duplicate {
			return nil, ccse.ErrDuplicateExtension
		}
		seen[extension.ExtensionId] = struct{}{}
		out = append(out, ccse.Extension{ID: extension.ExtensionId, Critical: extension.Critical, Value: append([]byte(nil), extension.Value...)})
	}
	return out, nil
}

func domainReplay(input *commonv1.TransportSigningDomain) (ccse.CounterKind, uint64, error) {
	switch replay := input.ReplayGuard.(type) {
	case *commonv1.TransportSigningDomain_Sequence:
		return ccse.CounterSequence, replay.Sequence, nil
	case *commonv1.TransportSigningDomain_ExpectedGeneration:
		return ccse.CounterExpectedGeneration, replay.ExpectedGeneration, nil
	default:
		return ccse.CounterUnspecified, 0, missing("signing_domain.replay_guard")
	}
}

func envelopeReplay(input *commonv1.TransportEnvelope) (ccse.CounterKind, uint64, error) {
	switch replay := input.ReplayGuard.(type) {
	case *commonv1.TransportEnvelope_Sequence:
		return ccse.CounterSequence, replay.Sequence, nil
	case *commonv1.TransportEnvelope_ExpectedGeneration:
		return ccse.CounterExpectedGeneration, replay.ExpectedGeneration, nil
	default:
		return ccse.CounterUnspecified, 0, missing("envelope.replay_guard")
	}
}

func missing(name string) error {
	return fmt.Errorf("%w: %s", ErrMissingRequiredField, name)
}

func optionalString(value *string) ccse.OptionalString {
	if value == nil {
		return ccse.OptionalString{}
	}
	return ccse.OptionalString{Present: true, Value: *value}
}

func protocolVersion(value *commonv1.ProtocolVersion, name string) (ccse.Version, error) {
	if value == nil {
		return ccse.Version{}, missing(name)
	}
	if value.Major == 0 {
		return ccse.Version{}, fmt.Errorf("%w: %s.major is zero", ErrInvalidSchemaVersion, name)
	}
	return ccse.Version{Major: value.Major, Minor: value.Minor}, nil
}

func requiredSchemaV1(value *commonv1.SchemaVersion, name string) (ccse.Version, error) {
	if value == nil {
		return ccse.Version{}, missing(name)
	}
	if value.Major != 1 || value.Minor != 0 {
		return ccse.Version{}, fmt.Errorf("%w: %s=%d.%d", ErrInvalidSchemaVersion, name, value.Major, value.Minor)
	}
	return schemaV1, nil
}

func signatureAlgorithm(value commonv1.SignatureAlgorithm, name string) (ccse.SignatureAlgorithmID, error) {
	// This boundary recognizes catalog-pinned algorithm identifiers but does
	// not claim cryptographic support. ccse.Verifier remains fail-closed: its
	// generic verification path accepts signatures only for Ed25519 and returns
	// ccse.ErrUnsupportedAlgorithm for P-256 and EIP-712 until a policy-scoped
	// verifier adapter is explicitly implemented.
	switch value {
	case commonv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519,
		commonv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_P256_SHA256,
		commonv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_EIP712:
		return ccse.SignatureAlgorithmID(value), nil
	default:
		return ccse.SignatureAlgorithmUnspecified, fmt.Errorf("%w: %s=%d", ErrMissingRequiredField, name, value)
	}
}

func fixed16(value []byte, name string) ([16]byte, error) {
	var out [16]byte
	if len(value) != len(out) {
		return out, fmt.Errorf("%w: %s has %d bytes, want %d", ErrInvalidFixedLength, name, len(value), len(out))
	}
	copy(out[:], value)
	return out, nil
}

func fixed32(value []byte, name string) ([32]byte, error) {
	var out [32]byte
	if len(value) != len(out) {
		return out, fmt.Errorf("%w: %s has %d bytes, want %d", ErrInvalidFixedLength, name, len(value), len(out))
	}
	copy(out[:], value)
	return out, nil
}

func optionalFixed16(value []byte, name string) (ccse.OptionalMessageID, error) {
	if value == nil {
		return ccse.OptionalMessageID{}, nil
	}
	fixed, err := fixed16(value, name)
	if err != nil {
		return ccse.OptionalMessageID{}, err
	}
	return ccse.OptionalMessageID{Present: true, Value: fixed}, nil
}

func cloneDomain(value ccse.Domain) ccse.Domain {
	value.Audience = append([]string(nil), value.Audience...)
	return value
}

func cloneEnvelope(value ccse.Envelope) ccse.Envelope {
	value.Extensions = append([]ccse.Extension(nil), value.Extensions...)
	for index := range value.Extensions {
		value.Extensions[index].Value = append([]byte(nil), value.Extensions[index].Value...)
	}
	return value
}

// Keep the projection package tied into the production translator build even
// when a future refactor moves all concrete uses into generated switch files.
var _ signingProjection = foundationv1.ProviderIdentitySigningProjection{}
