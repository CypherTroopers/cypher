// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package foundationv1

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/schema"
)

func TestProviderProjectionPresenceAndSetSemantics(t *testing.T) {
	first := validProviderProjection()
	first.Jurisdictions = []string{"DE", "US"}
	first.PolicyDigestsSHA256 = [][32]byte{digest32(0x22), digest32(0x11)}
	second := first
	second.Jurisdictions = []string{"US", "DE"}
	second.PolicyDigestsSHA256 = [][32]byte{digest32(0x11), digest32(0x22)}

	firstBytes, err := first.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := second.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("declared set permutation changed provider projection")
	}

	presentEmpty := first
	presentEmpty.StakeReference = OptionalString{Present: true, Value: ""}
	presentBytes, err := presentEmpty.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstBytes, presentBytes) {
		t.Fatal("absent stake reference and present-empty reference encoded identically")
	}
	if first.MessageTypeID() != schema.MessageTypeProviderIdentity {
		t.Fatalf("provider message type = %d", first.MessageTypeID())
	}
}

func TestProviderProjectionRejectsDuplicateSetMember(t *testing.T) {
	provider := validProviderProjection()
	provider.Jurisdictions = []string{"DE", "DE"}
	if _, err := provider.CanonicalBytes(); !errors.Is(err, ccse.ErrDuplicateSetValue) {
		t.Fatalf("duplicate jurisdiction error = %v", err)
	}
}

func TestKeyLifecycleProjectionSetAndPresence(t *testing.T) {
	first := validKeyLifecycleProjection()
	first.AllowedMessageTypeIDs = []uint32{schema.MessageTypeExperimentPlan, schema.MessageTypeProviderIdentity}
	second := first
	second.AllowedMessageTypeIDs = []uint32{schema.MessageTypeProviderIdentity, schema.MessageTypeExperimentPlan}

	firstBytes, err := first.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := second.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("allowed message type set permutation changed projection")
	}

	revoked := first
	revoked.State = 4
	revoked.RevokedAtUnixNano = OptionalInt64{Present: true, Value: first.NotBeforeUnixNano}
	revokedBytes, err := revoked.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstBytes, revokedBytes) {
		t.Fatal("absent revoked_at and present timestamp encoded identically")
	}
	if first.MessageTypeID() != schema.MessageTypeKeyLifecycle {
		t.Fatalf("key lifecycle message type = %d", first.MessageTypeID())
	}

	invalid := first
	invalid.AllowedMessageTypeIDs = []uint32{100}
	if _, err := invalid.CanonicalBytes(); !errors.Is(err, ErrInvalidProjectionValue) {
		t.Fatalf("test-only authorization error = %v", err)
	}
}

func TestExperimentPlanProjectionCriterionSet(t *testing.T) {
	first := validExperimentPlanProjection()
	first.Criteria = []MetricCriterionSigningProjection{criterion("readiness.p99", 5), criterion("invalid_results", 0)}
	second := first
	second.Criteria = []MetricCriterionSigningProjection{criterion("invalid_results", 0), criterion("readiness.p99", 5)}
	second.HardwareScope = []string{"gpu:nvidia:h200", "gpu:amd:max395"}
	first.HardwareScope = []string{"gpu:amd:max395", "gpu:nvidia:h200"}

	firstBytes, err := first.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := second.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("criterion or hardware set permutation changed experiment projection")
	}
	if first.MessageTypeID() != schema.MessageTypeExperimentPlan {
		t.Fatalf("experiment plan message type = %d", first.MessageTypeID())
	}

	duplicate := first
	duplicate.Criteria = []MetricCriterionSigningProjection{criterion("readiness.p99", 5), criterion("readiness.p99", 5)}
	if _, err := duplicate.CanonicalBytes(); !errors.Is(err, ErrInvalidProjectionValue) {
		t.Fatalf("duplicate criterion error = %v", err)
	}
}

func TestMetricCriterionRequiresExactValidRational(t *testing.T) {
	invalid := criterion("readiness.p99", 5)
	invalid.ThresholdDenominator = 0
	if _, err := invalid.CanonicalBytes(); !errors.Is(err, ErrInvalidRational) {
		t.Fatalf("zero denominator error = %v", err)
	}
	invalid = criterion("readiness.p99", 5)
	invalid.UpperThresholdNumerator = OptionalInt64{Present: true, Value: 1}
	if _, err := invalid.CanonicalBytes(); !errors.Is(err, ErrInvalidProjectionValue) {
		t.Fatalf("unpaired upper threshold error = %v", err)
	}
	invalid = criterion("readiness.p99", 5)
	invalid.PercentileBasisPoints = OptionalUint32{Present: true, Value: 0}
	if _, err := invalid.CanonicalBytes(); !errors.Is(err, ErrInvalidProjectionValue) {
		t.Fatalf("zero present percentile error = %v", err)
	}
	invalid = criterion("temperature.range", 5)
	invalid.Comparison = 6
	invalid.UpperThresholdNumerator = OptionalInt64{Present: true, Value: 4}
	invalid.UpperThresholdDenominator = OptionalUint64{Present: true, Value: 1}
	if _, err := invalid.CanonicalBytes(); !errors.Is(err, ErrInvalidRational) {
		t.Fatalf("descending rational range error = %v", err)
	}
}

func TestOptionalNumericRejectsHiddenNonzeroValues(t *testing.T) {
	tests := []struct {
		name   string
		encode func() error
	}{
		{
			name: "int64",
			encode: func() error {
				key := validKeyLifecycleProjection()
				key.RevokedAtUnixNano = OptionalInt64{Present: false, Value: key.NotBeforeUnixNano}
				_, err := key.CanonicalBytes()
				return err
			},
		},
		{
			name: "uint64",
			encode: func() error {
				value := criterion("readiness.p99", 5)
				value.UpperThresholdDenominator = OptionalUint64{Present: false, Value: 1}
				_, err := value.CanonicalBytes()
				return err
			},
		},
		{
			name: "uint32",
			encode: func() error {
				value := criterion("readiness.p99", 5)
				value.PercentileBasisPoints = OptionalUint32{Present: false, Value: 9500}
				_, err := value.CanonicalBytes()
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.encode(); !errors.Is(err, ccse.ErrNonCanonicalAbsent) {
				t.Fatalf("hidden optional error = %v", err)
			}
		})
	}
}

func TestPresentOptionalTimeMustBeWithinKeyLifetime(t *testing.T) {
	key := validKeyLifecycleProjection()
	key.RevokedAtUnixNano = OptionalInt64{Present: true, Value: key.NotAfterUnixNano + 1}
	if _, err := key.CanonicalBytes(); !errors.Is(err, ErrInvalidTimeRange) {
		t.Fatalf("out-of-lifetime revocation error = %v", err)
	}
}

func TestPresentZeroRationalNumeratorIsDistinct(t *testing.T) {
	present := criterion("temperature.range", 0)
	present.Comparison = 6
	present.UpperThresholdNumerator = OptionalInt64{Present: true, Value: 0}
	present.UpperThresholdDenominator = OptionalUint64{Present: true, Value: 1}
	presentBytes, err := present.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(presentBytes) == 0 {
		t.Fatal("present zero numerator produced empty encoding")
	}
}

func TestFixedDigestSetUsesInnerAndOuterLengthFrames(t *testing.T) {
	elements, err := canonicalDigestSet([][32]byte{digest32(0xaa)})
	if err != nil {
		t.Fatal(err)
	}
	if len(elements) != 1 || len(elements[0]) != 36 || binary.BigEndian.Uint32(elements[0][:4]) != 32 {
		t.Fatalf("canonical fixed digest element = %x", elements)
	}
	encoded, err := ccse.Marshal(64, func(out *ccse.Encoder) { out.EncodedSet(elements) })
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != 44 || binary.BigEndian.Uint32(encoded[:4]) != 1 || binary.BigEndian.Uint32(encoded[4:8]) != 36 || binary.BigEndian.Uint32(encoded[8:12]) != 32 {
		t.Fatalf("fixed digest set framing = %x", encoded)
	}
}

func validMetadata() RecordMetadataSigningProjection {
	return RecordMetadataSigningProjection{
		SchemaVersion:       SchemaVersionSigningProjection{Major: 1},
		RecordID:            "record-01",
		CreatedAtUnixNano:   1_800_000_000_000_000_000,
		IntegrityDigest:     digest32(0xa1),
		HomeRegion:          "eu-central-1",
		WriterEpoch:         1,
		StateVersion:        1,
		IdempotencyKey:      id16(0xb1),
		PolicyDigestsSHA256: [][32]byte{digest32(0xc1)},
	}
}

func validProviderProjection() ProviderIdentitySigningProjection {
	return ProviderIdentitySigningProjection{
		Metadata:             validMetadata(),
		ProviderID:           "provider-01",
		OrganizationIdentity: "spiffe://cph.example/provider/01",
		PayoutIdentity:       "cph:0x0000000000000000000000000000000000000001",
		Jurisdictions:        []string{"DE"},
		PolicyDigestsSHA256:  [][32]byte{digest32(0xd1)},
		OwnershipGeneration:  1,
		ValidFromUnixNano:    1_800_000_000_000_000_000,
		ValidUntilUnixNano:   1_800_086_400_000_000_000,
		State:                2,
	}
}

func validKeyLifecycleProjection() KeyLifecycleSigningProjection {
	return KeyLifecycleSigningProjection{
		Metadata:                        validMetadata(),
		KeyID:                           "key-01",
		SubjectIdentity:                 "spiffe://cph.example/service/scheduler",
		SubjectKind:                     8,
		Algorithm:                       1,
		State:                           2,
		NotBeforeUnixNano:               1_800_000_000_000_000_000,
		NotAfterUnixNano:                1_800_086_400_000_000_000,
		AllowedMessageTypeIDs:           []uint32{schema.MessageTypeExperimentPlan},
		AuthorizationPolicyDigestSHA256: digest32(0xe1),
	}
}

func validExperimentPlanProjection() ExperimentPlanSigningProjection {
	return ExperimentPlanSigningProjection{
		Metadata:                     validMetadata(),
		ExperimentPlanID:             "plan-01",
		CapabilityID:                 "CAP-PREEMPT-01",
		Component:                    "provider-agent",
		OwnerIdentity:                "spiffe://cph.example/service/evidence",
		SoftwareVersion:              "CPH-AIIE-0.2+implementation.1",
		HardwareScope:                []string{"gpu:amd:max395"},
		WorkloadScope:                []string{"mining:colossus-x-v1"},
		RegionScope:                  []string{"eu-central-1"},
		CollectionNotBeforeUnixNano:  1_800_000_100_000_000_000,
		ObservationWindowNanos:       86_400_000_000_000,
		MinimumSampleSize:            100,
		ConfidenceLevelBasisPoints:   9500,
		ConfidenceMethod:             2,
		Criteria:                     []MetricCriterionSigningProjection{criterion("readiness.p99", 5)},
		RevalidationTriggers:         []string{"software-major-change"},
		ExpiresAtUnixNano:            1_900_000_000_000_000_000,
		ExperimentPolicyDigestSHA256: digest32(0xf1),
		TargetLevel:                  4,
		FrozenAtUnixNano:             1_800_000_000_000_000_000,
		ApprovingIdentities:          []string{"spiffe://cph.example/user/reviewer-01"},
	}
}

func criterion(id string, threshold int64) MetricCriterionSigningProjection {
	return MetricCriterionSigningProjection{
		MetricID:                id,
		Comparison:              2,
		ThresholdNumerator:      threshold,
		ThresholdDenominator:    1,
		Unit:                    "seconds",
		MinimumMetricSampleSize: 100,
	}
}

func digest32(fill byte) (out [32]byte) {
	for index := range out {
		out[index] = fill
	}
	return out
}

func id16(fill byte) (out [16]byte) {
	for index := range out {
		out[index] = fill
	}
	return out
}
