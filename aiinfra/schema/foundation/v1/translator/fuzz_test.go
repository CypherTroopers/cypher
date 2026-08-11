// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package translator

import (
	"testing"

	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

func FuzzTranslateUnverified(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x08, 0x00})
	f.Add([]byte{0x1b})
	// Seed every oneof arm with a fully valid authorization so the mutator can
	// reach semantic translation and digest binding rather than exercising only
	// early strict-wire rejection paths.
	for _, projection := range validProjections() {
		f.Add(marshalWrapper(f, validWrapper(f, projection)))
	}

	// Add multi-item deep branches separately. These make the nested evidence
	// observation and experiment criterion loops part of the initial corpus.
	evidence := validProjections()[11].(foundationv1.EvidenceRecordSigningProjection)
	evidence.Observations = append(evidence.Observations, foundationv1.MetricObservationSigningProjection{
		MetricID: "throughput", ObservedNumerator: 10, ObservedDenominator: 1, SampleSize: 50,
		ConfidenceLowerNumerator: 9, ConfidenceLowerDenominator: 1,
		ConfidenceUpperNumerator: 11, ConfidenceUpperDenominator: 1, CriterionPassed: true,
	})
	f.Add(marshalWrapper(f, validWrapper(f, evidence)))

	experiment := validProjections()[12].(foundationv1.ExperimentPlanSigningProjection)
	experiment.Criteria = append(experiment.Criteria, foundationv1.MetricCriterionSigningProjection{
		MetricID: "throughput", Comparison: 5, ThresholdNumerator: 9, ThresholdDenominator: 1,
		Unit: "items_per_second", MinimumMetricSampleSize: 50,
	})
	f.Add(marshalWrapper(f, validWrapper(f, experiment)))

	transfer := validProjections()[13].(foundationv1.OwnershipTransferAuthorizationSigningProjection)
	transfer.EvidenceCommitments = append(transfer.EvidenceCommitments,
		foundationv1.TransferEvidenceCommitmentSigningProjection{
			EvidenceKind:           foundationv1.TransferEvidenceOldProviderAuthority,
			CCSERecordDigestSHA256: digest32(0x7f),
		})
	f.Add(marshalWrapper(f, validWrapper(f, transfer)))

	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > maxTransportBytes+1 {
			t.Skip()
		}
		_, _ = TranslateUnverified(wire)
	})
}
