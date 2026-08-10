// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package canonical

import (
	"github.com/cypherium/cypher/aiinfra/ccse"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

func decodeEvidenceRecord(v *Validator, in *ccse.Decoder, rules projectionRules) (Payload, error) {
	decoder := newProjectionDecoder(in, rules)
	metadata, _ := decodeMetadataField(v, decoder)
	value := foundationv1.EvidenceRecordSigningProjection{
		Metadata:                      metadata,
		EvidenceID:                    decoder.String(2, "evidence_id"),
		ExperimentPlanID:              decoder.String(3, "experiment_plan_id"),
		CapabilityID:                  decoder.String(4, "capability_id"),
		Component:                     decoder.String(5, "component"),
		OwnerIdentity:                 decoder.String(6, "owner_identity"),
		SoftwareVersion:               decoder.String(7, "software_version"),
		HardwareScope:                 decoder.StringSet(8, "hardware_scope"),
		WorkloadScope:                 decoder.StringSet(9, "workload_scope"),
		RegionScope:                   decoder.StringSet(10, "region_scope"),
		TestStartedAtUnixNano:         decoder.Int64(11, "test_started_at_unix_nano"),
		TestEndedAtUnixNano:           decoder.Int64(12, "test_ended_at_unix_nano"),
		SampleSize:                    decoder.Uint64(13, "sample_size"),
		EvidenceArtifactDigestsSHA256: decoder.Fixed32Set(14, "evidence_artifact_digests_sha256"),
	}
	value.Observations = decodeObservationSet(v, decoder, 15, "observations")
	value.ApprovingRole = decoder.String(16, "approving_role")
	value.ApprovingIdentities = decoder.StringSet(17, "approving_identities")
	value.ApprovedAtUnixNano = decoder.Int64(18, "approved_at_unix_nano")
	value.ExpiresAtUnixNano = decoder.Int64(19, "expires_at_unix_nano")
	value.RevalidationTriggers = decoder.StringSet(20, "revalidation_triggers")
	value.AchievedLevel = decoder.Enum(21, "achieved_level", 1, 7)
	value.Status = decoder.Enum(22, "status", 1, 5)
	if err := decoder.FinishFields(); err != nil {
		return nil, err
	}
	return value, nil
}

func decodeExperimentPlan(v *Validator, in *ccse.Decoder, rules projectionRules) (Payload, error) {
	decoder := newProjectionDecoder(in, rules)
	metadata, _ := decodeMetadataField(v, decoder)
	value := foundationv1.ExperimentPlanSigningProjection{
		Metadata:                    metadata,
		ExperimentPlanID:            decoder.String(2, "experiment_plan_id"),
		CapabilityID:                decoder.String(3, "capability_id"),
		Component:                   decoder.String(4, "component"),
		OwnerIdentity:               decoder.String(5, "owner_identity"),
		SoftwareVersion:             decoder.String(6, "software_version"),
		HardwareScope:               decoder.StringSet(7, "hardware_scope"),
		WorkloadScope:               decoder.StringSet(8, "workload_scope"),
		RegionScope:                 decoder.StringSet(9, "region_scope"),
		CollectionNotBeforeUnixNano: decoder.Int64(10, "collection_not_before_unix_nano"),
		ObservationWindowNanos:      decoder.Uint64(11, "observation_window_nanos"),
		MinimumSampleSize:           decoder.Uint64(12, "minimum_sample_size"),
		ConfidenceLevelBasisPoints:  decoder.Uint32(13, "confidence_level_basis_points"),
		ConfidenceMethod:            decoder.Enum(14, "confidence_method", 1, 5),
	}
	value.Criteria = decodeCriterionSet(v, decoder, 15, "criteria")
	value.RevalidationTriggers = decoder.StringSet(16, "revalidation_triggers")
	value.ExpiresAtUnixNano = decoder.Int64(17, "expires_at_unix_nano")
	value.ExperimentPolicyDigestSHA256 = decoder.Fixed32(18, "experiment_policy_digest_sha256")
	value.TargetLevel = decoder.Enum(19, "target_level", 1, 7)
	value.FrozenAtUnixNano = decoder.Int64(20, "frozen_at_unix_nano")
	value.ApprovingIdentities = decoder.StringSet(21, "approving_identities")
	if err := decoder.FinishFields(); err != nil {
		return nil, err
	}
	return value, nil
}

func decodeObservationSet(v *Validator, decoder *projectionDecoder, order int, name string) []foundationv1.MetricObservationSigningProjection {
	field, ok := decoder.MessageSet(order, name, metricObservationType)
	if !ok {
		return nil
	}
	values := make([]foundationv1.MetricObservationSigningProjection, 0)
	canonicalElements := make([][]byte, 0)
	err := decoder.in.ValidatedSet(field.MaxItems, v.nested.metricObservation.limits.MaxPayloadBytes, func(_ int, child *ccse.Decoder) error {
		value, err := decodeMetricObservation(child, v.nested.metricObservation)
		if err != nil {
			return err
		}
		canonical, err := value.CanonicalBytes()
		if err != nil {
			return err
		}
		values = append(values, value)
		canonicalElements = append(canonicalElements, canonical)
		return nil
	})
	if err == nil {
		err = enforceMessageSetBound(field, canonicalElements)
	}
	decoder.record(err)
	if err != nil {
		return nil
	}
	return values
}

func decodeCriterionSet(v *Validator, decoder *projectionDecoder, order int, name string) []foundationv1.MetricCriterionSigningProjection {
	field, ok := decoder.MessageSet(order, name, metricCriterionType)
	if !ok {
		return nil
	}
	values := make([]foundationv1.MetricCriterionSigningProjection, 0)
	canonicalElements := make([][]byte, 0)
	err := decoder.in.ValidatedSet(field.MaxItems, v.nested.metricCriterion.limits.MaxPayloadBytes, func(_ int, child *ccse.Decoder) error {
		value, err := decodeMetricCriterion(child, v.nested.metricCriterion)
		if err != nil {
			return err
		}
		canonical, err := value.CanonicalBytes()
		if err != nil {
			return err
		}
		values = append(values, value)
		canonicalElements = append(canonicalElements, canonical)
		return nil
	})
	if err == nil {
		err = enforceMessageSetBound(field, canonicalElements)
	}
	decoder.record(err)
	if err != nil {
		return nil
	}
	return values
}
