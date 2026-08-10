// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package canonical

import (
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

func validPayloads() []Payload {
	metadata := validMetadata()
	return []Payload{
		foundationv1.ProviderIdentitySigningProjection{
			Metadata: metadata, ProviderID: "provider-01", OrganizationIdentity: "spiffe://cph.example/provider/01",
			PayoutIdentity: "cph:0x0000000000000000000000000000000000000001", Jurisdictions: []string{"DE"},
			PolicyDigestsSHA256: [][32]byte{digest32(0x31)}, StakeReference: foundationv1.OptionalString{Present: true, Value: "stake-01"},
			OwnershipGeneration: 1, ValidFromUnixNano: 1_800_000_000_000_000_000,
			ValidUntilUnixNano: 1_800_086_400_000_000_000, State: 2,
		},
		foundationv1.AgentIdentitySigningProjection{
			Metadata: metadata, AgentID: "agent-01", ProviderID: "provider-01", HostID: "host-01",
			SPIFFEID: "spiffe://cph.example/agent/01", KeyID: "key-agent-01", OwnershipGeneration: 1,
			ValidFromUnixNano: 1_800_000_000_000_000_000, ValidUntilUnixNano: 1_800_086_400_000_000_000, State: 2,
		},
		foundationv1.HostIdentitySigningProjection{
			Metadata: metadata, HostID: "host-01", ProviderID: "provider-01", ProviderSiteID: "site-01",
			AttestationIdentity: "attestation:host:01", KeyID: "key-host-01", OwnershipGeneration: 1,
			ValidFromUnixNano: 1_800_000_000_000_000_000, ValidUntilUnixNano: 1_800_086_400_000_000_000, State: 2,
		},
		foundationv1.DeviceIdentitySigningProjection{
			Metadata: metadata, DeviceID: "device-01", ProviderID: "provider-01", HostID: "host-01",
			VendorSerialDigestSHA256: digest32(0x32), AttestationIdentity: "attestation:device:01", KeyID: "key-device-01",
			OwnershipGeneration: 1, ValidFromUnixNano: 1_800_000_000_000_000_000,
			ValidUntilUnixNano: 1_800_086_400_000_000_000, State: 2,
		},
		foundationv1.MinerIdentitySigningProjection{
			Metadata: metadata, MinerID: "miner-01", ProviderID: "provider-01", AgentID: "agent-01",
			DeviceIDs: []string{"device-01"}, PayoutIdentity: "cph:0x0000000000000000000000000000000000000001",
			KeyID: "key-miner-01", BindingGeneration: 1, ValidFromUnixNano: 1_800_000_000_000_000_000,
			ValidUntilUnixNano: 1_800_086_400_000_000_000, State: 2,
		},
		foundationv1.RunnerIdentitySigningProjection{
			Metadata: metadata, RunnerAttemptID: "runner-attempt-01", ProviderID: "provider-01", AgentID: "agent-01",
			LeaseID: "lease-01", JobID: "job-01", AttemptID: "attempt-01", WorkloadIdentity: "spiffe://cph.example/runner/attempt-01",
			KeyID: "key-runner-01", ValidFromUnixNano: 1_800_000_000_000_000_000,
			ValidUntilUnixNano: 1_800_003_600_000_000_000, State: 2,
		},
		foundationv1.BuyerIdentitySigningProjection{
			Metadata: metadata, BuyerID: "buyer-01", OrganizationIdentityURI: "spiffe://cph.example/buyer/01",
			BillingIdentity: "billing-01", KeyID: "key-buyer-01", AuthorizationGeneration: 1,
			ValidFromUnixNano: 1_800_000_000_000_000_000, ValidUntilUnixNano: 1_800_086_400_000_000_000, State: 2,
		},
		foundationv1.ServiceIdentitySigningProjection{
			Metadata: metadata, ServiceID: "service-01", ServiceName: "lease-service",
			SPIFFEID: "spiffe://cph.example/service/lease", DeploymentEnvironment: "testnet", KeyID: "key-service-01",
			CredentialGeneration: 1, ValidFromUnixNano: 1_800_000_000_000_000_000,
			ValidUntilUnixNano: 1_800_086_400_000_000_000, State: 2,
		},
		foundationv1.KeyLifecycleSigningProjection{
			Metadata: metadata, KeyID: "key-01", SubjectIdentity: "spiffe://cph.example/service/scheduler",
			SubjectKind: 8, Algorithm: 1, State: 2, NotBeforeUnixNano: 1_800_000_000_000_000_000,
			NotAfterUnixNano:                1_800_086_400_000_000_000,
			RotationPredecessorKeyID:        foundationv1.OptionalString{Present: true, Value: "key-00"},
			AllowedMessageTypeIDs:           []uint32{schema.MessageTypeExperimentPlan},
			AuthorizationPolicyDigestSHA256: digest32(0x33),
			TransitionReasonCode:            foundationv1.OptionalString{Present: true, Value: "scheduled-rotation"},
		},
		foundationv1.PolicyBundleSigningProjection{
			Metadata: metadata, PolicyBundleID: "policy-01", PolicyKind: "provider-eligibility",
			PolicyVersion: foundationv1.SchemaVersionSigningProjection{Major: 1}, Sequence: 1,
			ApprovedAtUnixNano: 1_799_999_000_000_000_000, EffectiveAtUnixNano: 1_800_000_000_000_000_000,
			ExpiresAtUnixNano: 1_900_000_000_000_000_000, PolicyDocumentDigestSHA256: digest32(0x34),
			PolicyDocumentMediaType: "application/json", ApproverIdentities: []string{"spiffe://cph.example/user/approver-01"},
			ApproverKeyIDs: []string{"key-approver-01"}, MinimumApprovals: 1, Emergency: true,
			BreakGlassExpiresAtUnixNano: foundationv1.OptionalInt64{Present: true, Value: 1_850_000_000_000_000_000}, State: 3,
		},
		foundationv1.AuditEventSigningProjection{
			Metadata: metadata, AuditEventID: "audit-01", EventType: "PolicyActivated",
			ActorIdentity: "spiffe://cph.example/service/policy-registry", ActorKeyID: "key-policy-registry-01",
			SubjectIDs: []string{"policy-01"}, CauseCode: "scheduled-activation", CorrelationID: id16(0x35),
			CausationID:        foundationv1.OptionalFixedBytes16{Present: true, Value: id16(0x36)},
			OccurredAtUnixNano: 1_800_000_000_000_000_000, Outcome: 1,
			AppliedPolicyDigestsSHA256: [][32]byte{digest32(0x37)}, EvidenceDigestsSHA256: [][32]byte{digest32(0x38)},
			RedactedDetailsDigestSHA256: foundationv1.OptionalFixedBytes32{Present: true, Value: digest32(0x39)},
			PreviousEventDigestSHA256:   digest32(0x3a), AuditSequence: 1,
		},
		validEvidenceRecord(metadata),
		validExperimentPlan(metadata),
	}
}

func validMetadata() foundationv1.RecordMetadataSigningProjection {
	return foundationv1.RecordMetadataSigningProjection{
		SchemaVersion:       foundationv1.SchemaVersionSigningProjection{Major: 1},
		RecordID:            "record-01",
		CreatedAtUnixNano:   1_800_000_000_000_000_000,
		IntegrityDigest:     digest32(0x21),
		HomeRegion:          "eu-central-1",
		WriterEpoch:         1,
		StateVersion:        1,
		IdempotencyKey:      id16(0x22),
		PolicyDigestsSHA256: [][32]byte{digest32(0x23)},
	}
}

func validCriterion(metricID string) foundationv1.MetricCriterionSigningProjection {
	return foundationv1.MetricCriterionSigningProjection{
		MetricID: metricID, Comparison: 6, ThresholdNumerator: 4, ThresholdDenominator: 1,
		UpperThresholdNumerator:   foundationv1.OptionalInt64{Present: true, Value: 6},
		UpperThresholdDenominator: foundationv1.OptionalUint64{Present: true, Value: 1},
		Unit:                      "seconds", PercentileBasisPoints: foundationv1.OptionalUint32{Present: true, Value: 9500},
		MinimumMetricSampleSize: 100,
	}
}

func validObservation(metricID string, passed bool) foundationv1.MetricObservationSigningProjection {
	return foundationv1.MetricObservationSigningProjection{
		MetricID: metricID, ObservedNumerator: 5, ObservedDenominator: 1, SampleSize: 100,
		ConfidenceLowerNumerator: 4, ConfidenceLowerDenominator: 1,
		ConfidenceUpperNumerator: 6, ConfidenceUpperDenominator: 1, CriterionPassed: passed,
	}
}

func validEvidenceRecord(metadata foundationv1.RecordMetadataSigningProjection) foundationv1.EvidenceRecordSigningProjection {
	return foundationv1.EvidenceRecordSigningProjection{
		Metadata: metadata, EvidenceID: "evidence-01", ExperimentPlanID: "plan-01", CapabilityID: "CAP-PREEMPT-01",
		Component: "provider-agent", OwnerIdentity: "spiffe://cph.example/service/evidence",
		SoftwareVersion: "CPH-AIIE-0.2+implementation.1", HardwareScope: []string{"gpu:amd:max395"},
		WorkloadScope: []string{"mining:colossus-x-v1"}, RegionScope: []string{"eu-central-1"},
		TestStartedAtUnixNano: 1_799_000_000_000_000_000, TestEndedAtUnixNano: 1_799_500_000_000_000_000,
		SampleSize: 100, EvidenceArtifactDigestsSHA256: [][32]byte{digest32(0x41)},
		Observations:  []foundationv1.MetricObservationSigningProjection{validObservation("readiness.p99", true)},
		ApprovingRole: "evidence-reviewer", ApprovingIdentities: []string{"spiffe://cph.example/user/reviewer-01"},
		ApprovedAtUnixNano: 1_799_600_000_000_000_000, ExpiresAtUnixNano: 1_900_000_000_000_000_000,
		RevalidationTriggers: []string{"software-major-change"}, AchievedLevel: 4, Status: 2,
	}
}

func validExperimentPlan(metadata foundationv1.RecordMetadataSigningProjection) foundationv1.ExperimentPlanSigningProjection {
	return foundationv1.ExperimentPlanSigningProjection{
		Metadata: metadata, ExperimentPlanID: "plan-01", CapabilityID: "CAP-PREEMPT-01", Component: "provider-agent",
		OwnerIdentity: "spiffe://cph.example/service/evidence", SoftwareVersion: "CPH-AIIE-0.2+implementation.1",
		HardwareScope: []string{"gpu:amd:max395"}, WorkloadScope: []string{"mining:colossus-x-v1"},
		RegionScope: []string{"eu-central-1"}, CollectionNotBeforeUnixNano: 1_800_000_100_000_000_000,
		ObservationWindowNanos: 86_400_000_000_000, MinimumSampleSize: 100, ConfidenceLevelBasisPoints: 9500,
		ConfidenceMethod: 2, Criteria: []foundationv1.MetricCriterionSigningProjection{validCriterion("readiness.p99")},
		RevalidationTriggers: []string{"software-major-change"}, ExpiresAtUnixNano: 1_900_000_000_000_000_000,
		ExperimentPolicyDigestSHA256: digest32(0x42), TargetLevel: 4, FrozenAtUnixNano: 1_800_000_000_000_000_000,
		ApprovingIdentities: []string{"spiffe://cph.example/user/reviewer-01"},
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
