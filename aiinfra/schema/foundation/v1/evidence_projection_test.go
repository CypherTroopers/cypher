// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package foundationv1

import (
	"bytes"
	"errors"
	"testing"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/schema"
)

func TestEvidenceProjectionPositive(t *testing.T) {
	encoded, err := validEvidenceRecord().CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) == 0 {
		t.Fatal("empty evidence projection")
	}
	if (EvidenceRecordSigningProjection{}).MessageTypeID() != schema.MessageTypeEvidenceRecord {
		t.Fatal("evidence message type mismatch")
	}
}

func TestEvidenceOneFieldMutationFailsClosed(t *testing.T) {
	evidence := validEvidenceRecord()
	evidence.EvidenceID = ""
	if _, err := evidence.CanonicalBytes(); err == nil {
		t.Fatal("empty evidence_id accepted")
	}
}

func TestMetricObservationRationalValidation(t *testing.T) {
	observation := validMetricObservation("readiness.p99", true)
	if _, err := observation.CanonicalBytes(); err != nil {
		t.Fatal(err)
	}
	observation.ObservedDenominator = 0
	if _, err := observation.CanonicalBytes(); !errors.Is(err, ErrInvalidRational) {
		t.Fatalf("zero observed denominator error = %v", err)
	}
	observation = validMetricObservation("readiness.p99", true)
	observation.ObservedNumerator = 20
	if _, err := observation.CanonicalBytes(); !errors.Is(err, ErrInvalidRational) {
		t.Fatalf("observation outside interval error = %v", err)
	}
}

func TestEvidenceSemanticAndCollectionValidation(t *testing.T) {
	evidence := validEvidenceRecord()
	evidence.Status = 2
	evidence.Observations[0].CriterionPassed = false
	if _, err := evidence.CanonicalBytes(); !errors.Is(err, ErrInvalidProjectionValue) {
		t.Fatalf("inconsistent PASSED status error = %v", err)
	}

	evidence = validEvidenceRecord()
	second := validMetricObservation("readiness.p99", true)
	second.ObservedNumerator = 9
	evidence.Observations = append(evidence.Observations, second)
	if _, err := evidence.CanonicalBytes(); !errors.Is(err, ErrInvalidProjectionValue) {
		t.Fatalf("duplicate metric ID error = %v", err)
	}

	evidence = validEvidenceRecord()
	evidence.HardwareScope = []string{"gpu:amd:max395", "gpu:amd:max395"}
	if _, err := evidence.CanonicalBytes(); !errors.Is(err, ccse.ErrDuplicateSetValue) {
		t.Fatalf("duplicate hardware scope error = %v", err)
	}

	evidence = validEvidenceRecord()
	evidence.Observations = make([]MetricObservationSigningProjection, 65)
	for index := range evidence.Observations {
		evidence.Observations[index] = validMetricObservation("metric-"+string(rune('A'+index)), true)
	}
	if _, err := evidence.CanonicalBytes(); !errors.Is(err, ErrFieldLimit) {
		t.Fatalf("observation count error = %v", err)
	}

	evidence = validEvidenceRecord()
	evidence.Status = 99
	if _, err := evidence.CanonicalBytes(); !errors.Is(err, ErrInvalidEnumValue) {
		t.Fatalf("unknown evidence status error = %v", err)
	}
}

func TestEvidenceSetsAndObservationSetAreCanonical(t *testing.T) {
	first := validEvidenceRecord()
	first.HardwareScope = []string{"gpu:nvidia:h200", "gpu:amd:max395"}
	first.Observations = []MetricObservationSigningProjection{
		validMetricObservation("readiness.p99", true),
		validMetricObservation("invalid-results", true),
	}
	second := first
	second.HardwareScope = []string{"gpu:amd:max395", "gpu:nvidia:h200"}
	second.Observations = []MetricObservationSigningProjection{
		validMetricObservation("invalid-results", true),
		validMetricObservation("readiness.p99", true),
	}
	firstBytes, err := first.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := second.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("declared evidence set permutation changed projection")
	}
}

func validMetricObservation(metricID string, passed bool) MetricObservationSigningProjection {
	return MetricObservationSigningProjection{
		MetricID:                   metricID,
		ObservedNumerator:          5,
		ObservedDenominator:        1,
		SampleSize:                 100,
		ConfidenceLowerNumerator:   4,
		ConfidenceLowerDenominator: 1,
		ConfidenceUpperNumerator:   6,
		ConfidenceUpperDenominator: 1,
		CriterionPassed:            passed,
	}
}

func validEvidenceRecord() EvidenceRecordSigningProjection {
	return EvidenceRecordSigningProjection{
		Metadata:                      validMetadata(),
		EvidenceID:                    "evidence-01",
		ExperimentPlanID:              "plan-01",
		CapabilityID:                  "CAP-PREEMPT-01",
		Component:                     "provider-agent",
		OwnerIdentity:                 "spiffe://cph.example/service/evidence",
		SoftwareVersion:               "CPH-AIIE-0.2+implementation.1",
		HardwareScope:                 []string{"gpu:amd:max395"},
		WorkloadScope:                 []string{"mining:colossus-x-v1"},
		RegionScope:                   []string{"eu-central-1"},
		TestStartedAtUnixNano:         1_799_000_000_000_000_000,
		TestEndedAtUnixNano:           1_799_500_000_000_000_000,
		SampleSize:                    100,
		EvidenceArtifactDigestsSHA256: [][32]byte{digest32(0x71)},
		Observations:                  []MetricObservationSigningProjection{validMetricObservation("readiness.p99", true)},
		ApprovingRole:                 "evidence-reviewer",
		ApprovingIdentities:           []string{"spiffe://cph.example/user/reviewer-01"},
		ApprovedAtUnixNano:            1_799_600_000_000_000_000,
		ExpiresAtUnixNano:             1_900_000_000_000_000_000,
		RevalidationTriggers:          []string{"software-major-change"},
		AchievedLevel:                 4,
		Status:                        2,
	}
}
