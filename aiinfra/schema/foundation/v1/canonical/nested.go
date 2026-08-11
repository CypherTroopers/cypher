// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package canonical

import (
	"github.com/cypherium/cypher/aiinfra/ccse"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

const (
	schemaVersionType     = "cph.aiinfra.common.v1.SchemaVersion"
	recordMetadataType    = "cph.aiinfra.common.v1.RecordMetadata"
	metricCriterionType   = "cph.aiinfra.foundation.v1.MetricCriterion"
	metricObservationType = "cph.aiinfra.foundation.v1.MetricObservation"
	keyClosureType        = "cph.aiinfra.foundation.v1.KeyClosure"
	transferEvidenceType  = "cph.aiinfra.foundation.v1.TransferEvidenceCommitment"
	transferAuthorityType = "cph.aiinfra.foundation.v1.TransferAuthority"
)

func decodeSchemaVersion(in *ccse.Decoder, rules projectionRules) (foundationv1.SchemaVersionSigningProjection, error) {
	decoder := newProjectionDecoder(in, rules)
	value := foundationv1.SchemaVersionSigningProjection{
		Major: decoder.Uint32(1, "major"),
		Minor: decoder.Uint32(2, "minor"),
	}
	return value, decoder.FinishFields()
}

func decodeRecordMetadata(v *Validator, in *ccse.Decoder, rules projectionRules) (foundationv1.RecordMetadataSigningProjection, error) {
	decoder := newProjectionDecoder(in, rules)
	if !decoder.InlineMessage(1, "schema_version", schemaVersionType) {
		return foundationv1.RecordMetadataSigningProjection{}, decoder.FinishFields()
	}
	version, versionErr := decodeSchemaVersion(in, v.nested.schemaVersion)
	decoder.record(versionErr)
	value := foundationv1.RecordMetadataSigningProjection{
		SchemaVersion:       version,
		RecordID:            decoder.String(2, "record_id"),
		CreatedAtUnixNano:   decoder.Int64(3, "created_at_unix_nano"),
		IntegrityDigest:     decoder.Fixed32(4, "integrity_digest_sha256"),
		HomeRegion:          decoder.String(5, "home_region"),
		WriterEpoch:         decoder.Uint64(6, "writer_epoch"),
		StateVersion:        decoder.Uint64(7, "state_version"),
		IdempotencyKey:      decoder.Fixed16(8, "idempotency_key"),
		PolicyDigestsSHA256: decoder.Fixed32Set(9, "policy_digests_sha256"),
	}
	if err := decoder.FinishFields(); err != nil {
		return foundationv1.RecordMetadataSigningProjection{}, err
	}
	return value, nil
}

func decodeMetricCriterion(in *ccse.Decoder, rules projectionRules) (foundationv1.MetricCriterionSigningProjection, error) {
	decoder := newProjectionDecoder(in, rules)
	value := foundationv1.MetricCriterionSigningProjection{
		MetricID:                  decoder.String(1, "metric_id"),
		Comparison:                decoder.Enum(2, "comparison", 1, 6),
		ThresholdNumerator:        decoder.Int64(3, "threshold_numerator"),
		ThresholdDenominator:      decoder.Uint64(4, "threshold_denominator"),
		UpperThresholdNumerator:   decoder.OptionalInt64(5, "upper_threshold_numerator"),
		UpperThresholdDenominator: decoder.OptionalUint64(6, "upper_threshold_denominator"),
		Unit:                      decoder.String(7, "unit"),
		PercentileBasisPoints:     decoder.OptionalUint32(8, "percentile_basis_points"),
		MinimumMetricSampleSize:   decoder.Uint64(9, "minimum_metric_sample_size"),
	}
	if err := decoder.FinishFields(); err != nil {
		return foundationv1.MetricCriterionSigningProjection{}, err
	}
	canonical, err := value.CanonicalBytes()
	if err != nil {
		return foundationv1.MetricCriterionSigningProjection{}, err
	}
	if len(canonical) > rules.limits.MaxPayloadBytes {
		return foundationv1.MetricCriterionSigningProjection{}, ccse.ErrProjectionTooLarge
	}
	return value, nil
}

func decodeMetricObservation(in *ccse.Decoder, rules projectionRules) (foundationv1.MetricObservationSigningProjection, error) {
	decoder := newProjectionDecoder(in, rules)
	value := foundationv1.MetricObservationSigningProjection{
		MetricID:                   decoder.String(1, "metric_id"),
		ObservedNumerator:          decoder.Int64(2, "observed_numerator"),
		ObservedDenominator:        decoder.Uint64(3, "observed_denominator"),
		SampleSize:                 decoder.Uint64(4, "sample_size"),
		ConfidenceLowerNumerator:   decoder.Int64(5, "confidence_lower_numerator"),
		ConfidenceLowerDenominator: decoder.Uint64(6, "confidence_lower_denominator"),
		ConfidenceUpperNumerator:   decoder.Int64(7, "confidence_upper_numerator"),
		ConfidenceUpperDenominator: decoder.Uint64(8, "confidence_upper_denominator"),
		CriterionPassed:            decoder.Bool(9, "criterion_passed"),
	}
	if err := decoder.FinishFields(); err != nil {
		return foundationv1.MetricObservationSigningProjection{}, err
	}
	canonical, err := value.CanonicalBytes()
	if err != nil {
		return foundationv1.MetricObservationSigningProjection{}, err
	}
	if len(canonical) > rules.limits.MaxPayloadBytes {
		return foundationv1.MetricObservationSigningProjection{}, ccse.ErrProjectionTooLarge
	}
	return value, nil
}

func decodeMetadataField(v *Validator, decoder *projectionDecoder) (foundationv1.RecordMetadataSigningProjection, error) {
	if !decoder.InlineMessage(1, "metadata", recordMetadataType) {
		return foundationv1.RecordMetadataSigningProjection{}, decoder.FinishFields()
	}
	value, err := decodeRecordMetadata(v, decoder.in, v.nested.recordMetadata)
	decoder.record(err)
	return value, err
}
