// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

// Package canonical independently decodes and validates the CCSE-v1 payloads
// registered for the foundation schema. It never decodes or consults Protobuf
// transport bytes.
package canonical

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/schema"
)

const expectedRegistrySHA256 = "d432c225de9f5747feaad2fd7971834d3a389f7e37e155a0761685e61acb779e"

var (
	ErrValidatorNotInitialized    = errors.New("aiinfra foundation canonical: validator is not initialized")
	ErrCatalogMismatch            = errors.New("aiinfra foundation canonical: registry catalog mismatch")
	ErrUnknownMessageType         = errors.New("aiinfra foundation canonical: unknown message type")
	ErrUnsupportedSchemaVersion   = errors.New("aiinfra foundation canonical: unsupported schema version")
	ErrDecodedMessageTypeMismatch = errors.New("aiinfra foundation canonical: decoded message type mismatch")
)

// Payload is one of the thirteen registered foundation signing projections.
// Implementations are values decoded from CCSE bytes, never Protobuf messages.
type Payload interface {
	MessageTypeID() uint32
	CanonicalBytes() ([]byte, error)
}

type decodePayloadFunc func(*Validator, *ccse.Decoder, projectionRules) (Payload, error)

type catalogEntry struct {
	version ccse.Version
	purpose string
	rules   projectionRules
	decode  decodePayloadFunc
}

type nestedCatalog struct {
	schemaVersion     projectionRules
	recordMetadata    projectionRules
	metricCriterion   projectionRules
	metricObservation projectionRules
}

// Validator is immutable after construction and safe for concurrent use.
// Its catalog is accepted only when the embedded registry has the reviewed
// SHA-256 and the exact thirteen message identities fixed below.
type Validator struct {
	entries map[uint32]catalogEntry
	nested  nestedCatalog
}

var _ ccse.SchemaValidator = (*Validator)(nil)

type expectedMessage struct {
	id       uint32
	name     string
	purpose  string
	maxBytes int
	decode   decodePayloadFunc
}

var expectedMessages = [...]expectedMessage{
	{schema.MessageTypeProviderIdentity, "cph.aiinfra.foundation.v1.ProviderIdentity", "identity.provider.bind", 32768, decodeProviderIdentity},
	{schema.MessageTypeAgentIdentity, "cph.aiinfra.foundation.v1.AgentIdentity", "identity.agent.bind", 24576, decodeAgentIdentity},
	{schema.MessageTypeHostIdentity, "cph.aiinfra.foundation.v1.HostIdentity", "identity.host.bind", 24576, decodeHostIdentity},
	{schema.MessageTypeDeviceIdentity, "cph.aiinfra.foundation.v1.DeviceIdentity", "identity.device.bind", 24576, decodeDeviceIdentity},
	{schema.MessageTypeMinerIdentity, "cph.aiinfra.foundation.v1.MinerIdentity", "identity.miner.bind", 32768, decodeMinerIdentity},
	{schema.MessageTypeRunnerIdentity, "cph.aiinfra.foundation.v1.RunnerIdentity", "identity.runner.bind", 28672, decodeRunnerIdentity},
	{schema.MessageTypeBuyerIdentity, "cph.aiinfra.foundation.v1.BuyerIdentity", "identity.buyer.bind", 24576, decodeBuyerIdentity},
	{schema.MessageTypeServiceIdentity, "cph.aiinfra.foundation.v1.ServiceIdentity", "identity.service.bind", 24576, decodeServiceIdentity},
	{schema.MessageTypeKeyLifecycle, "cph.aiinfra.foundation.v1.KeyLifecycle", "identity.key.lifecycle", 32768, decodeKeyLifecycle},
	{schema.MessageTypePolicyBundle, "cph.aiinfra.foundation.v1.PolicyBundle", "governance.policy.bundle", 49152, decodePolicyBundle},
	{schema.MessageTypeAuditEvent, "cph.aiinfra.foundation.v1.AuditEvent", "audit.event.append", 65536, decodeAuditEvent},
	{schema.MessageTypeEvidenceRecord, "cph.aiinfra.foundation.v1.EvidenceRecord", "evidence.record.release", 262144, decodeEvidenceRecord},
	{schema.MessageTypeExperimentPlan, "cph.aiinfra.foundation.v1.ExperimentPlan", "evidence.experiment.plan.freeze", 262144, decodeExperimentPlan},
}

// NewValidator loads and freezes the embedded production registry. It fails
// closed if any registry byte, registered message identity, version, purpose,
// unknown-field policy, payload bound, or required nested projection differs.
func NewValidator() (*Validator, error) {
	registry, err := schema.LoadDefault()
	if err != nil {
		return nil, fmt.Errorf("%w: load registry: %v", ErrCatalogMismatch, err)
	}
	digest, err := registry.SHA256Hex()
	if err != nil {
		return nil, fmt.Errorf("%w: hash registry: %v", ErrCatalogMismatch, err)
	}
	if digest != expectedRegistrySHA256 {
		return nil, fmt.Errorf("%w: registry SHA-256 %s", ErrCatalogMismatch, digest)
	}
	if len(registry.Messages) != len(expectedMessages) {
		return nil, fmt.Errorf("%w: message count %d", ErrCatalogMismatch, len(registry.Messages))
	}

	validator := &Validator{entries: make(map[uint32]catalogEntry, len(expectedMessages))}
	for _, expected := range expectedMessages {
		message, ok := registry.LookupMessage(expected.id)
		if !ok || message.Name != expected.name || message.Purpose != expected.purpose ||
			message.SchemaVersion != (schema.Version{Major: 1, Minor: 0}) ||
			message.UnknownFieldPolicy != "reject" || message.Limits.MaxPayloadBytes != expected.maxBytes {
			return nil, fmt.Errorf("%w: message %d", ErrCatalogMismatch, expected.id)
		}
		rules, err := newProjectionRules(message.Name, message.Limits, message.Fields)
		if err != nil {
			return nil, err
		}
		validator.entries[expected.id] = catalogEntry{
			version: ccse.Version{Major: 1, Minor: 0},
			purpose: expected.purpose,
			rules:   rules,
			decode:  expected.decode,
		}
	}

	nestedExpected := []struct {
		name     string
		maxBytes int
		target   *projectionRules
	}{
		{"cph.aiinfra.common.v1.SchemaVersion", 8, &validator.nested.schemaVersion},
		{"cph.aiinfra.common.v1.RecordMetadata", 8192, &validator.nested.recordMetadata},
		{"cph.aiinfra.foundation.v1.MetricCriterion", 1024, &validator.nested.metricCriterion},
		{"cph.aiinfra.foundation.v1.MetricObservation", 1024, &validator.nested.metricObservation},
	}
	if len(registry.Structures) != len(nestedExpected) {
		return nil, fmt.Errorf("%w: nested projection count %d", ErrCatalogMismatch, len(registry.Structures))
	}
	for _, expected := range nestedExpected {
		projection, ok := lookupProjection(registry.Structures, expected.name)
		if !ok || projection.Limits.MaxPayloadBytes != expected.maxBytes {
			return nil, fmt.Errorf("%w: nested projection %s", ErrCatalogMismatch, expected.name)
		}
		rules, err := newProjectionRules(projection.Name, projection.Limits, projection.Fields)
		if err != nil {
			return nil, err
		}
		*expected.target = rules
	}
	return validator, nil
}

// Decode parses one exact registered CCSE payload, enforces its typed schema
// and semantic invariants, re-encodes it through the authoritative signing
// projection, and requires byte-for-byte equality with input.
func (v *Validator) Decode(messageTypeID uint32, version ccse.Version, input []byte) (Payload, error) {
	entry, err := v.entry(messageTypeID, version)
	if err != nil {
		return nil, err
	}
	if len(input) > entry.rules.limits.MaxPayloadBytes {
		return nil, canonicalError(ccse.ErrProjectionTooLarge)
	}
	candidate := append([]byte(nil), input...)
	var decoded Payload
	err = ccse.Unmarshal(candidate, entry.rules.limits.MaxPayloadBytes, func(in *ccse.Decoder) error {
		var decodeErr error
		decoded, decodeErr = entry.decode(v, in, entry.rules)
		return decodeErr
	})
	if err != nil {
		return nil, canonicalError(err)
	}
	if decoded == nil || decoded.MessageTypeID() != messageTypeID {
		return nil, canonicalError(ErrDecodedMessageTypeMismatch)
	}
	reencoded, err := decoded.CanonicalBytes()
	if err != nil {
		return nil, canonicalError(err)
	}
	if !bytes.Equal(reencoded, candidate) {
		return nil, canonicalError(errors.New("canonical re-encoding differs from input"))
	}
	return decoded, nil
}

// ValidateCanonicalPayload implements ccse.SchemaValidator.
func (v *Validator) ValidateCanonicalPayload(_ context.Context, messageTypeID uint32, version ccse.Version, input []byte) error {
	_, err := v.Decode(messageTypeID, version, input)
	return err
}

// ValidateExtensions rejects every signed extension for the exact thirteen
// v1.0 types. The current registry defines no signed extension, so a sender's
// critical=false flag cannot make an extension acceptable.
func (v *Validator) ValidateExtensions(_ context.Context, messageTypeID uint32, version ccse.Version, extensions []ccse.Extension) error {
	if _, err := v.entry(messageTypeID, version); err != nil {
		return err
	}
	for _, extension := range extensions {
		if extension.Critical {
			return ccse.ErrUnknownCriticalExtension
		}
	}
	if len(extensions) != 0 {
		return ccse.ErrUnknownExtension
	}
	return nil
}

func (v *Validator) entry(messageTypeID uint32, version ccse.Version) (catalogEntry, error) {
	if v == nil || len(v.entries) == 0 {
		return catalogEntry{}, ErrValidatorNotInitialized
	}
	entry, ok := v.entries[messageTypeID]
	if !ok {
		return catalogEntry{}, fmt.Errorf("%w: %d", ErrUnknownMessageType, messageTypeID)
	}
	if version != entry.version {
		return catalogEntry{}, fmt.Errorf("%w: %d.%d", ErrUnsupportedSchemaVersion, version.Major, version.Minor)
	}
	return entry, nil
}

func lookupProjection(values []schema.Projection, name string) (schema.Projection, bool) {
	for _, value := range values {
		if value.Name == name {
			return value, true
		}
	}
	return schema.Projection{}, false
}

func canonicalError(err error) error {
	if err == nil || errors.Is(err, ccse.ErrNonCanonicalPayload) {
		return err
	}
	return fmt.Errorf("%w: %w", ccse.ErrNonCanonicalPayload, err)
}
