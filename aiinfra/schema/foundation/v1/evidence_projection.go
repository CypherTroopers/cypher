// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package foundationv1

import (
	"fmt"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/schema"
)

const (
	metricObservationMaxPayload = 1024
	evidenceRecordMaxPayload    = 262144
)

var (
	metricObservationSigningFields = [...]string{
		"metric_id", "observed_numerator", "observed_denominator", "sample_size",
		"confidence_lower_numerator", "confidence_lower_denominator",
		"confidence_upper_numerator", "confidence_upper_denominator", "criterion_passed",
	}
	evidenceRecordSigningFields = [...]string{
		"metadata", "evidence_id", "experiment_plan_id", "capability_id", "component", "owner_identity",
		"software_version", "hardware_scope", "workload_scope", "region_scope", "test_started_at_unix_nano",
		"test_ended_at_unix_nano", "sample_size", "evidence_artifact_digests_sha256", "observations",
		"approving_role", "approving_identities", "approved_at_unix_nano", "expires_at_unix_nano",
		"revalidation_triggers", "achieved_level", "status",
	}
)

type MetricObservationSigningProjection struct {
	MetricID                   string
	ObservedNumerator          int64
	ObservedDenominator        uint64
	SampleSize                 uint64
	ConfidenceLowerNumerator   int64
	ConfidenceLowerDenominator uint64
	ConfidenceUpperNumerator   int64
	ConfidenceUpperDenominator uint64
	CriterionPassed            bool
}

type EvidenceRecordSigningProjection struct {
	Metadata                      RecordMetadataSigningProjection
	EvidenceID                    string
	ExperimentPlanID              string
	CapabilityID                  string
	Component                     string
	OwnerIdentity                 string
	SoftwareVersion               string
	HardwareScope                 []string
	WorkloadScope                 []string
	RegionScope                   []string
	TestStartedAtUnixNano         int64
	TestEndedAtUnixNano           int64
	SampleSize                    uint64
	EvidenceArtifactDigestsSHA256 [][32]byte
	Observations                  []MetricObservationSigningProjection
	ApprovingRole                 string
	ApprovingIdentities           []string
	ApprovedAtUnixNano            int64
	ExpiresAtUnixNano             int64
	RevalidationTriggers          []string
	AchievedLevel                 uint32
	Status                        uint32
}

func (p MetricObservationSigningProjection) CanonicalBytes() ([]byte, error) {
	if err := validateRequiredStringField("metric_id", p.MetricID, 128); err != nil {
		return nil, err
	}
	if p.ObservedDenominator == 0 || p.ConfidenceLowerDenominator == 0 || p.ConfidenceUpperDenominator == 0 {
		return nil, ErrInvalidRational
	}
	if p.SampleSize == 0 {
		return nil, fmt.Errorf("%w: sample_size is zero", ErrInvalidProjectionValue)
	}
	if rationalGreater(p.ConfidenceLowerNumerator, p.ConfidenceLowerDenominator, p.ConfidenceUpperNumerator, p.ConfidenceUpperDenominator) {
		return nil, fmt.Errorf("%w: descending confidence interval", ErrInvalidRational)
	}
	if rationalGreater(p.ConfidenceLowerNumerator, p.ConfidenceLowerDenominator, p.ObservedNumerator, p.ObservedDenominator) ||
		rationalGreater(p.ObservedNumerator, p.ObservedDenominator, p.ConfidenceUpperNumerator, p.ConfidenceUpperDenominator) {
		return nil, fmt.Errorf("%w: observation outside confidence interval", ErrInvalidRational)
	}
	return ccse.Marshal(metricObservationMaxPayload, func(out *ccse.Encoder) {
		out.String(p.MetricID)
		out.Int64(p.ObservedNumerator)
		out.Uint64(p.ObservedDenominator)
		out.Uint64(p.SampleSize)
		out.Int64(p.ConfidenceLowerNumerator)
		out.Uint64(p.ConfidenceLowerDenominator)
		out.Int64(p.ConfidenceUpperNumerator)
		out.Uint64(p.ConfidenceUpperDenominator)
		out.Bool(p.CriterionPassed)
	})
}

func (MetricObservationSigningProjection) SigningFieldNames() []string {
	return copyFieldNames(metricObservationSigningFields[:])
}

func (p EvidenceRecordSigningProjection) CanonicalBytes() ([]byte, error) {
	metadata, err := p.Metadata.prepare()
	if err != nil {
		return nil, err
	}
	for _, field := range []struct {
		name  string
		value string
		max   int
	}{
		{"evidence_id", p.EvidenceID, 256}, {"experiment_plan_id", p.ExperimentPlanID, 256},
		{"capability_id", p.CapabilityID, 256}, {"component", p.Component, 256},
		{"owner_identity", p.OwnerIdentity, 1024}, {"software_version", p.SoftwareVersion, 256},
		{"approving_role", p.ApprovingRole, 128},
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
	if err := validateRequiredTimeRange("evidence test window", p.TestStartedAtUnixNano, p.TestEndedAtUnixNano); err != nil {
		return nil, err
	}
	if p.SampleSize == 0 {
		return nil, fmt.Errorf("%w: sample_size is zero", ErrInvalidProjectionValue)
	}
	artifacts, err := canonicalDigestSetField("evidence_artifact_digests_sha256", p.EvidenceArtifactDigestsSHA256, 256, 10244, true)
	if err != nil {
		return nil, err
	}
	observationBodies := make([][]byte, 0, len(p.Observations))
	metricIDs := make(map[string]struct{}, len(p.Observations))
	allCriteriaPassed := true
	anyCriterionFailed := false
	for index, observation := range p.Observations {
		if _, duplicate := metricIDs[observation.MetricID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate observation metric_id %q", ErrInvalidProjectionValue, observation.MetricID)
		}
		metricIDs[observation.MetricID] = struct{}{}
		if observation.SampleSize > p.SampleSize {
			return nil, fmt.Errorf("%w: observations[%d].sample_size exceeds record", ErrInvalidProjectionValue, index)
		}
		body, err := observation.CanonicalBytes()
		if err != nil {
			return nil, fmt.Errorf("observations[%d]: %w", index, err)
		}
		observationBodies = append(observationBodies, body)
		allCriteriaPassed = allCriteriaPassed && observation.CriterionPassed
		anyCriterionFailed = anyCriterionFailed || !observation.CriterionPassed
	}
	observations, err := canonicalMessageSetField("observations", observationBodies, 64, 67584, true)
	if err != nil {
		return nil, err
	}
	approvers, err := canonicalStringSetField("approving_identities", p.ApprovingIdentities, 64, 17408, true)
	if err != nil {
		return nil, err
	}
	if p.ApprovedAtUnixNano < p.TestEndedAtUnixNano || p.ExpiresAtUnixNano <= p.ApprovedAtUnixNano {
		return nil, fmt.Errorf("%w: evidence approval/expiry", ErrInvalidTimeRange)
	}
	if p.Metadata.CreatedAtUnixNano < p.ApprovedAtUnixNano {
		return nil, fmt.Errorf("%w: evidence approved after record creation", ErrInvalidTimeRange)
	}
	triggers, err := canonicalStringSetField("revalidation_triggers", p.RevalidationTriggers, 128, 33792, true)
	if err != nil {
		return nil, err
	}
	if err := validateEnumRange("achieved_level", p.AchievedLevel, 1, 7); err != nil {
		return nil, err
	}
	if err := validateEnumRange("status", p.Status, 1, 5); err != nil {
		return nil, err
	}
	if p.Status == 2 && !allCriteriaPassed {
		return nil, fmt.Errorf("%w: PASSED evidence has a failed criterion", ErrInvalidProjectionValue)
	}
	if p.Status == 3 && !anyCriterionFailed {
		return nil, fmt.Errorf("%w: FAILED evidence has no failed criterion", ErrInvalidProjectionValue)
	}
	return ccse.Marshal(evidenceRecordMaxPayload, func(out *ccse.Encoder) {
		metadata.encode(out)
		out.String(p.EvidenceID)
		out.String(p.ExperimentPlanID)
		out.String(p.CapabilityID)
		out.String(p.Component)
		out.String(p.OwnerIdentity)
		out.String(p.SoftwareVersion)
		out.EncodedSet(hardware)
		out.EncodedSet(workloads)
		out.EncodedSet(regions)
		out.Int64(p.TestStartedAtUnixNano)
		out.Int64(p.TestEndedAtUnixNano)
		out.Uint64(p.SampleSize)
		out.EncodedSet(artifacts)
		out.EncodedSet(observations)
		out.String(p.ApprovingRole)
		out.EncodedSet(approvers)
		out.Int64(p.ApprovedAtUnixNano)
		out.Int64(p.ExpiresAtUnixNano)
		out.EncodedSet(triggers)
		out.Uint32(p.AchievedLevel)
		out.Uint32(p.Status)
	})
}

func (EvidenceRecordSigningProjection) MessageTypeID() uint32 {
	return schema.MessageTypeEvidenceRecord
}
func (EvidenceRecordSigningProjection) SigningFieldNames() []string {
	return copyFieldNames(evidenceRecordSigningFields[:])
}
