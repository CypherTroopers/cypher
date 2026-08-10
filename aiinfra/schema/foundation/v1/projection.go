// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

// Package foundationv1 contains explicit CCSE signing projections for the
// foundation transport messages. Generated Protobuf messages will remain a
// separate representation and must be validated and translated into these
// types before signing.
package foundationv1

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/schema"
)

const (
	providerIdentityMaxPayload = 32768
	keyLifecycleMaxPayload     = 32768
	experimentPlanMaxPayload   = 262144
	recordMetadataMaxPayload   = 8192
	metricCriterionMaxPayload  = 1024
)

var (
	ErrInvalidProjectionValue = errors.New("aiinfra foundation: invalid signing projection value")
	ErrInvalidRational        = errors.New("aiinfra foundation: rational denominator must be positive")
	ErrInvalidTimeRange       = errors.New("aiinfra foundation: invalid time range")

	schemaVersionSigningFields = [...]string{
		"major", "minor",
	}
	recordMetadataSigningFields = [...]string{
		"schema_version", "record_id", "created_at_unix_nano", "integrity_digest_sha256",
		"home_region", "writer_epoch", "state_version", "idempotency_key", "policy_digests_sha256",
	}
	providerIdentitySigningFields = [...]string{
		"metadata", "provider_id", "organization_identity_uri", "payout_identity", "jurisdictions",
		"policy_digests_sha256", "stake_reference", "ownership_generation", "valid_from_unix_nano",
		"valid_until_unix_nano", "state",
	}
	keyLifecycleSigningFields = [...]string{
		"metadata", "key_id", "subject_identity", "subject_kind", "algorithm", "state",
		"not_before_unix_nano", "not_after_unix_nano", "revoked_at_unix_nano",
		"rotation_predecessor_key_id", "allowed_message_type_ids",
		"authorization_policy_digest_sha256", "transition_reason_code",
	}
	metricCriterionSigningFields = [...]string{
		"metric_id", "comparison", "threshold_numerator", "threshold_denominator",
		"upper_threshold_numerator", "upper_threshold_denominator", "unit",
		"percentile_basis_points", "minimum_metric_sample_size",
	}
	experimentPlanSigningFields = [...]string{
		"metadata", "experiment_plan_id", "capability_id", "component", "owner_identity",
		"software_version", "hardware_scope", "workload_scope", "region_scope",
		"collection_not_before_unix_nano", "observation_window_nanos", "minimum_sample_size",
		"confidence_level_basis_points", "confidence_method", "criteria", "revalidation_triggers",
		"expires_at_unix_nano", "experiment_policy_digest_sha256", "target_level",
		"frozen_at_unix_nano", "approving_identities",
	}
)

// OptionalString preserves absence independently from an empty string.
type OptionalString struct {
	Present bool
	Value   string
}

// OptionalInt64 preserves absence independently from numeric zero.
type OptionalInt64 struct {
	Present bool
	Value   int64
}

// OptionalUint64 preserves absence independently from numeric zero.
type OptionalUint64 struct {
	Present bool
	Value   uint64
}

// OptionalUint32 preserves absence independently from numeric zero.
type OptionalUint32 struct {
	Present bool
	Value   uint32
}

// SchemaVersionSigningProjection is the nested schema-version projection.
type SchemaVersionSigningProjection struct {
	Major uint32
	Minor uint32
}

// RecordMetadataSigningProjection is the common immutable-record prefix.
type RecordMetadataSigningProjection struct {
	SchemaVersion       SchemaVersionSigningProjection
	RecordID            string
	CreatedAtUnixNano   int64
	IntegrityDigest     [32]byte
	HomeRegion          string
	WriterEpoch         uint64
	StateVersion        uint64
	IdempotencyKey      [16]byte
	PolicyDigestsSHA256 [][32]byte
}

// ProviderIdentitySigningProjection corresponds exactly to registry message
// type FOUNDATION_PROVIDER_IDENTITY_V1 (0x00010001).
type ProviderIdentitySigningProjection struct {
	Metadata             RecordMetadataSigningProjection
	ProviderID           string
	OrganizationIdentity string
	PayoutIdentity       string
	Jurisdictions        []string
	PolicyDigestsSHA256  [][32]byte
	StakeReference       OptionalString
	OwnershipGeneration  uint64
	ValidFromUnixNano    int64
	ValidUntilUnixNano   int64
	State                uint32
}

// KeyLifecycleSigningProjection corresponds exactly to registry message type
// FOUNDATION_KEY_LIFECYCLE_V1 (0x00010009).
type KeyLifecycleSigningProjection struct {
	Metadata                        RecordMetadataSigningProjection
	KeyID                           string
	SubjectIdentity                 string
	SubjectKind                     uint32
	Algorithm                       uint32
	State                           uint32
	NotBeforeUnixNano               int64
	NotAfterUnixNano                int64
	RevokedAtUnixNano               OptionalInt64
	RotationPredecessorKeyID        OptionalString
	AllowedMessageTypeIDs           []uint32
	AuthorizationPolicyDigestSHA256 [32]byte
	TransitionReasonCode            OptionalString
}

// MetricCriterionSigningProjection uses exact rational thresholds; it never
// converts through floating point.
type MetricCriterionSigningProjection struct {
	MetricID                  string
	Comparison                uint32
	ThresholdNumerator        int64
	ThresholdDenominator      uint64
	UpperThresholdNumerator   OptionalInt64
	UpperThresholdDenominator OptionalUint64
	Unit                      string
	PercentileBasisPoints     OptionalUint32
	MinimumMetricSampleSize   uint64
}

// ExperimentPlanSigningProjection freezes numerical thresholds, observation
// scope, sample size, confidence, expiry, and approval before collection.
type ExperimentPlanSigningProjection struct {
	Metadata                     RecordMetadataSigningProjection
	ExperimentPlanID             string
	CapabilityID                 string
	Component                    string
	OwnerIdentity                string
	SoftwareVersion              string
	HardwareScope                []string
	WorkloadScope                []string
	RegionScope                  []string
	CollectionNotBeforeUnixNano  int64
	ObservationWindowNanos       uint64
	MinimumSampleSize            uint64
	ConfidenceLevelBasisPoints   uint32
	ConfidenceMethod             uint32
	Criteria                     []MetricCriterionSigningProjection
	RevalidationTriggers         []string
	ExpiresAtUnixNano            int64
	ExperimentPolicyDigestSHA256 [32]byte
	TargetLevel                  uint32
	FrozenAtUnixNano             int64
	ApprovingIdentities          []string
}

// CanonicalBytes emits the ordered payload projection fixed by registry.json.
func (p ProviderIdentitySigningProjection) CanonicalBytes() ([]byte, error) {
	metadata, err := p.Metadata.prepare()
	if err != nil {
		return nil, err
	}
	for _, field := range []struct {
		name  string
		value string
		max   int
	}{
		{"provider_id", p.ProviderID, 256}, {"organization_identity_uri", p.OrganizationIdentity, 1024},
		{"payout_identity", p.PayoutIdentity, 256},
	} {
		if err := validateRequiredStringField(field.name, field.value, field.max); err != nil {
			return nil, err
		}
	}
	jurisdictions, err := canonicalStringSetField("jurisdictions", p.Jurisdictions, 32, 4096, true)
	if err != nil {
		return nil, err
	}
	policyDigests, err := canonicalDigestSetField("policy_digests_sha256", p.PolicyDigestsSHA256, 64, 2564, true)
	if err != nil {
		return nil, err
	}
	if err := validateOptionalStringField("stake_reference", p.StakeReference, 513, true); err != nil {
		return nil, err
	}
	if err := validateIdentityLifecycle(p.OwnershipGeneration, p.ValidFromUnixNano, p.ValidUntilUnixNano, p.State); err != nil {
		return nil, err
	}
	return ccse.Marshal(providerIdentityMaxPayload, func(out *ccse.Encoder) {
		metadata.encode(out)
		out.String(p.ProviderID)
		out.String(p.OrganizationIdentity)
		out.String(p.PayoutIdentity)
		out.EncodedSet(jurisdictions)
		out.EncodedSet(policyDigests)
		out.OptionalString(p.StakeReference.Present, p.StakeReference.Value)
		out.Uint64(p.OwnershipGeneration)
		out.Int64(p.ValidFromUnixNano)
		out.Int64(p.ValidUntilUnixNano)
		out.Uint32(p.State)
	})
}

// MessageTypeID returns the fixed production registry identifier.
func (ProviderIdentitySigningProjection) MessageTypeID() uint32 {
	return schema.MessageTypeProviderIdentity
}

// SigningFieldNames returns an immutable copy of the registry signing order.
func (ProviderIdentitySigningProjection) SigningFieldNames() []string {
	return copyFieldNames(providerIdentitySigningFields[:])
}

// CanonicalBytes emits the ordered payload projection fixed by registry.json.
func (p KeyLifecycleSigningProjection) CanonicalBytes() ([]byte, error) {
	metadata, err := p.Metadata.prepare()
	if err != nil {
		return nil, err
	}
	allowed, err := canonicalUint32SetField("allowed_message_type_ids", p.AllowedMessageTypeIDs, 256, 2052, true)
	if err != nil {
		return nil, err
	}
	if err := validateRequiredStringField("key_id", p.KeyID, 256); err != nil {
		return nil, err
	}
	if err := validateRequiredStringField("subject_identity", p.SubjectIdentity, 1024); err != nil {
		return nil, err
	}
	if err := validateEnumRange("subject_kind", p.SubjectKind, 1, 9); err != nil {
		return nil, err
	}
	if err := validateEnumRange("algorithm", p.Algorithm, 1, 3); err != nil {
		return nil, err
	}
	if err := validateEnumRange("state", p.State, 1, 5); err != nil {
		return nil, err
	}
	if err := validateRequiredFixed32("authorization_policy_digest_sha256", p.AuthorizationPolicyDigestSHA256); err != nil {
		return nil, err
	}
	for _, messageTypeID := range p.AllowedMessageTypeIDs {
		if messageTypeID < schema.ProductionMessageIDFloor {
			return nil, fmt.Errorf("%w: non-production allowed message type %d", ErrInvalidProjectionValue, messageTypeID)
		}
	}
	if p.NotBeforeUnixNano < 0 || p.NotAfterUnixNano <= p.NotBeforeUnixNano {
		return nil, ErrInvalidTimeRange
	}
	if err := validateOptionalInt64("revoked_at_unix_nano", p.RevokedAtUnixNano); err != nil {
		return nil, err
	}
	if p.RevokedAtUnixNano.Present && (p.RevokedAtUnixNano.Value < p.NotBeforeUnixNano || p.RevokedAtUnixNano.Value > p.NotAfterUnixNano) {
		return nil, fmt.Errorf("%w: revoked_at_unix_nano outside key lifetime", ErrInvalidTimeRange)
	}
	if (p.State == 4) != p.RevokedAtUnixNano.Present {
		return nil, fmt.Errorf("%w: revoked state/timestamp mismatch", ErrInvalidProjectionValue)
	}
	if err := validateOptionalStringField("rotation_predecessor_key_id", p.RotationPredecessorKeyID, 257, false); err != nil {
		return nil, err
	}
	if err := validateOptionalStringField("transition_reason_code", p.TransitionReasonCode, 257, true); err != nil {
		return nil, err
	}
	return ccse.Marshal(keyLifecycleMaxPayload, func(out *ccse.Encoder) {
		metadata.encode(out)
		out.String(p.KeyID)
		out.String(p.SubjectIdentity)
		out.Uint32(p.SubjectKind)
		out.Uint32(p.Algorithm)
		out.Uint32(p.State)
		out.Int64(p.NotBeforeUnixNano)
		out.Int64(p.NotAfterUnixNano)
		out.Bool(p.RevokedAtUnixNano.Present)
		if p.RevokedAtUnixNano.Present {
			out.Int64(p.RevokedAtUnixNano.Value)
		}
		out.OptionalString(p.RotationPredecessorKeyID.Present, p.RotationPredecessorKeyID.Value)
		out.EncodedSet(allowed)
		out.FixedBytes(p.AuthorizationPolicyDigestSHA256[:], len(p.AuthorizationPolicyDigestSHA256))
		out.OptionalString(p.TransitionReasonCode.Present, p.TransitionReasonCode.Value)
	})
}

// MessageTypeID returns the fixed production registry identifier.
func (KeyLifecycleSigningProjection) MessageTypeID() uint32 {
	return schema.MessageTypeKeyLifecycle
}

// SigningFieldNames returns an immutable copy of the registry signing order.
func (KeyLifecycleSigningProjection) SigningFieldNames() []string {
	return copyFieldNames(keyLifecycleSigningFields[:])
}

// CanonicalBytes emits the ordered nested projection fixed by registry.json.
func (p MetricCriterionSigningProjection) CanonicalBytes() ([]byte, error) {
	if err := validateRequiredStringField("metric_id", p.MetricID, 128); err != nil {
		return nil, err
	}
	if err := validateEnumRange("comparison", p.Comparison, 1, 6); err != nil {
		return nil, err
	}
	if err := validateRequiredStringField("unit", p.Unit, 64); err != nil {
		return nil, err
	}
	if p.MinimumMetricSampleSize == 0 {
		return nil, ErrInvalidProjectionValue
	}
	if err := validateOptionalInt64("upper_threshold_numerator", p.UpperThresholdNumerator); err != nil {
		return nil, err
	}
	if err := validateOptionalUint64("upper_threshold_denominator", p.UpperThresholdDenominator); err != nil {
		return nil, err
	}
	if err := validateOptionalUint32("percentile_basis_points", p.PercentileBasisPoints); err != nil {
		return nil, err
	}
	if p.ThresholdDenominator == 0 || (p.UpperThresholdDenominator.Present && p.UpperThresholdDenominator.Value == 0) {
		return nil, ErrInvalidRational
	}
	if p.UpperThresholdNumerator.Present != p.UpperThresholdDenominator.Present {
		return nil, fmt.Errorf("%w: upper threshold presence differs", ErrInvalidProjectionValue)
	}
	if (p.Comparison == 6) != p.UpperThresholdNumerator.Present {
		return nil, fmt.Errorf("%w: range comparison/upper threshold mismatch", ErrInvalidProjectionValue)
	}
	if p.UpperThresholdNumerator.Present && rationalGreater(
		p.ThresholdNumerator,
		p.ThresholdDenominator,
		p.UpperThresholdNumerator.Value,
		p.UpperThresholdDenominator.Value,
	) {
		return nil, fmt.Errorf("%w: lower threshold exceeds upper threshold", ErrInvalidRational)
	}
	if p.PercentileBasisPoints.Present && (p.PercentileBasisPoints.Value == 0 || p.PercentileBasisPoints.Value > 10000) {
		return nil, fmt.Errorf("%w: percentile basis points", ErrInvalidProjectionValue)
	}
	return ccse.Marshal(metricCriterionMaxPayload, func(out *ccse.Encoder) {
		out.String(p.MetricID)
		out.Uint32(p.Comparison)
		out.Int64(p.ThresholdNumerator)
		out.Uint64(p.ThresholdDenominator)
		out.Bool(p.UpperThresholdNumerator.Present)
		if p.UpperThresholdNumerator.Present {
			out.Int64(p.UpperThresholdNumerator.Value)
		}
		out.Bool(p.UpperThresholdDenominator.Present)
		if p.UpperThresholdDenominator.Present {
			out.Uint64(p.UpperThresholdDenominator.Value)
		}
		out.String(p.Unit)
		out.Bool(p.PercentileBasisPoints.Present)
		if p.PercentileBasisPoints.Present {
			out.Uint32(p.PercentileBasisPoints.Value)
		}
		out.Uint64(p.MinimumMetricSampleSize)
	})
}

// CanonicalBytes emits the ordered payload projection fixed by registry.json.
func (p ExperimentPlanSigningProjection) CanonicalBytes() ([]byte, error) {
	metadata, err := p.Metadata.prepare()
	if err != nil {
		return nil, err
	}
	criteria := make([][]byte, 0, len(p.Criteria))
	metricIDs := make(map[string]struct{}, len(p.Criteria))
	for index, criterion := range p.Criteria {
		if _, duplicate := metricIDs[criterion.MetricID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate criterion metric_id %q", ErrInvalidProjectionValue, criterion.MetricID)
		}
		metricIDs[criterion.MetricID] = struct{}{}
		encoded, err := criterion.CanonicalBytes()
		if err != nil {
			return nil, fmt.Errorf("criterion %d: %w", index, err)
		}
		criteria = append(criteria, encoded)
	}
	criteria, err = canonicalMessageSetField("criteria", criteria, 64, 67584, true)
	if err != nil {
		return nil, err
	}
	for _, field := range []struct {
		name  string
		value string
		max   int
	}{
		{"experiment_plan_id", p.ExperimentPlanID, 256}, {"capability_id", p.CapabilityID, 256},
		{"component", p.Component, 256}, {"owner_identity", p.OwnerIdentity, 1024}, {"software_version", p.SoftwareVersion, 256},
	} {
		if err := validateRequiredStringField(field.name, field.value, field.max); err != nil {
			return nil, err
		}
	}
	hardware, err := canonicalStringSetField("hardware_scope", p.HardwareScope, 128, 33792, true)
	if err != nil {
		return nil, err
	}
	workloads, err := canonicalStringSetField("workload_scope", p.WorkloadScope, 128, 33792, true)
	if err != nil {
		return nil, err
	}
	regions, err := canonicalStringSetField("region_scope", p.RegionScope, 64, 8448, true)
	if err != nil {
		return nil, err
	}
	triggers, err := canonicalStringSetField("revalidation_triggers", p.RevalidationTriggers, 128, 33792, true)
	if err != nil {
		return nil, err
	}
	approvers, err := canonicalStringSetField("approving_identities", p.ApprovingIdentities, 64, 17408, true)
	if err != nil {
		return nil, err
	}
	if p.CollectionNotBeforeUnixNano < 0 || p.FrozenAtUnixNano < 0 || p.ExpiresAtUnixNano <= p.CollectionNotBeforeUnixNano || p.FrozenAtUnixNano > p.CollectionNotBeforeUnixNano {
		return nil, ErrInvalidTimeRange
	}
	if p.ObservationWindowNanos == 0 || p.MinimumSampleSize == 0 || p.ConfidenceLevelBasisPoints == 0 || p.ConfidenceLevelBasisPoints > 10000 {
		return nil, ErrInvalidProjectionValue
	}
	if err := validateEnumRange("confidence_method", p.ConfidenceMethod, 1, 5); err != nil {
		return nil, err
	}
	if err := validateEnumRange("target_level", p.TargetLevel, 1, 7); err != nil {
		return nil, err
	}
	if isZero32(p.ExperimentPolicyDigestSHA256) {
		return nil, fmt.Errorf("%w: zero experiment policy digest", ErrInvalidProjectionValue)
	}
	return ccse.Marshal(experimentPlanMaxPayload, func(out *ccse.Encoder) {
		metadata.encode(out)
		out.String(p.ExperimentPlanID)
		out.String(p.CapabilityID)
		out.String(p.Component)
		out.String(p.OwnerIdentity)
		out.String(p.SoftwareVersion)
		out.EncodedSet(hardware)
		out.EncodedSet(workloads)
		out.EncodedSet(regions)
		out.Int64(p.CollectionNotBeforeUnixNano)
		out.Uint64(p.ObservationWindowNanos)
		out.Uint64(p.MinimumSampleSize)
		out.Uint32(p.ConfidenceLevelBasisPoints)
		out.Uint32(p.ConfidenceMethod)
		out.EncodedSet(criteria)
		out.EncodedSet(triggers)
		out.Int64(p.ExpiresAtUnixNano)
		out.FixedBytes(p.ExperimentPolicyDigestSHA256[:], len(p.ExperimentPolicyDigestSHA256))
		out.Uint32(p.TargetLevel)
		out.Int64(p.FrozenAtUnixNano)
		out.EncodedSet(approvers)
	})
}

// MessageTypeID returns the fixed production registry identifier.
func (ExperimentPlanSigningProjection) MessageTypeID() uint32 {
	return schema.MessageTypeExperimentPlan
}

// SigningFieldNames returns an immutable copy of the registry signing order.
func (ExperimentPlanSigningProjection) SigningFieldNames() []string {
	return copyFieldNames(experimentPlanSigningFields[:])
}

// SigningFieldNames returns an immutable copy of the nested registry signing order.
func (SchemaVersionSigningProjection) SigningFieldNames() []string {
	return copyFieldNames(schemaVersionSigningFields[:])
}

// SigningFieldNames returns an immutable copy of the nested registry signing order.
func (RecordMetadataSigningProjection) SigningFieldNames() []string {
	return copyFieldNames(recordMetadataSigningFields[:])
}

// SigningFieldNames returns an immutable copy of the nested registry signing order.
func (MetricCriterionSigningProjection) SigningFieldNames() []string {
	return copyFieldNames(metricCriterionSigningFields[:])
}

func (p RecordMetadataSigningProjection) canonicalBytes() ([]byte, error) {
	prepared, err := p.prepare()
	if err != nil {
		return nil, err
	}
	return ccse.Marshal(recordMetadataMaxPayload, prepared.encode)
}

type preparedRecordMetadata struct {
	value         RecordMetadataSigningProjection
	policyDigests [][]byte
}

func (p RecordMetadataSigningProjection) prepare() (preparedRecordMetadata, error) {
	if p.SchemaVersion.Major == 0 || p.CreatedAtUnixNano < 0 || p.WriterEpoch == 0 || p.StateVersion == 0 || isZero16(p.IdempotencyKey) || isZero32(p.IntegrityDigest) {
		return preparedRecordMetadata{}, ErrInvalidProjectionValue
	}
	if err := validateRequiredStringField("metadata.record_id", p.RecordID, 256); err != nil {
		return preparedRecordMetadata{}, err
	}
	if err := validateRequiredStringField("metadata.home_region", p.HomeRegion, 128); err != nil {
		return preparedRecordMetadata{}, err
	}
	policyDigests, err := canonicalDigestSetField("metadata.policy_digests_sha256", p.PolicyDigestsSHA256, 64, 2564, true)
	if err != nil {
		return preparedRecordMetadata{}, err
	}
	prepared := preparedRecordMetadata{value: p, policyDigests: policyDigests}
	if _, err := ccse.Marshal(recordMetadataMaxPayload, prepared.encode); err != nil {
		return preparedRecordMetadata{}, err
	}
	return prepared, nil
}

func (p preparedRecordMetadata) encode(out *ccse.Encoder) {
	out.Uint32(p.value.SchemaVersion.Major)
	out.Uint32(p.value.SchemaVersion.Minor)
	out.String(p.value.RecordID)
	out.Int64(p.value.CreatedAtUnixNano)
	out.FixedBytes(p.value.IntegrityDigest[:], len(p.value.IntegrityDigest))
	out.String(p.value.HomeRegion)
	out.Uint64(p.value.WriterEpoch)
	out.Uint64(p.value.StateVersion)
	out.FixedBytes(p.value.IdempotencyKey[:], len(p.value.IdempotencyKey))
	out.EncodedSet(p.policyDigests)
}

func canonicalDigestSet(values [][32]byte) ([][]byte, error) {
	encoded := make([][]byte, len(values))
	for index := range values {
		item, err := ccse.Marshal(4+len(values[index]), func(out *ccse.Encoder) {
			out.FixedBytes(values[index][:], len(values[index]))
		})
		if err != nil {
			return nil, err
		}
		encoded[index] = item
	}
	return encoded, nil
}

func encodeUint32Set(values []uint32) ([][]byte, error) {
	encoded := make([][]byte, 0, len(values))
	for _, value := range values {
		item, err := ccse.Marshal(4, func(out *ccse.Encoder) { out.Uint32(value) })
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, item)
	}
	return encoded, nil
}

func isZero16(value [16]byte) bool {
	return value == [16]byte{}
}

func isZero32(value [32]byte) bool {
	return value == [32]byte{}
}

func validateOptionalInt64(name string, value OptionalInt64) error {
	if !value.Present && value.Value != 0 {
		return fmt.Errorf("%w: %s carries hidden value", ccse.ErrNonCanonicalAbsent, name)
	}
	return nil
}

func validateOptionalUint64(name string, value OptionalUint64) error {
	if !value.Present && value.Value != 0 {
		return fmt.Errorf("%w: %s carries hidden value", ccse.ErrNonCanonicalAbsent, name)
	}
	return nil
}

func validateOptionalUint32(name string, value OptionalUint32) error {
	if !value.Present && value.Value != 0 {
		return fmt.Errorf("%w: %s carries hidden value", ccse.ErrNonCanonicalAbsent, name)
	}
	return nil
}

func rationalGreater(leftNumerator int64, leftDenominator uint64, rightNumerator int64, rightDenominator uint64) bool {
	left := new(big.Int).Mul(big.NewInt(leftNumerator), new(big.Int).SetUint64(rightDenominator))
	right := new(big.Int).Mul(big.NewInt(rightNumerator), new(big.Int).SetUint64(leftDenominator))
	return left.Cmp(right) > 0
}
