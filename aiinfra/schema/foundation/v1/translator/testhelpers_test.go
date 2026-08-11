// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package translator

import (
	"testing"

	commonv1 "github.com/cypherium/cypher/aiinfra/schema/common/v1"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
	transportv1 "github.com/cypherium/cypher/aiinfra/schema/transport/v1"
	"google.golang.org/protobuf/encoding/protowire"
)

func setProtoArm(wrapper *transportv1.SignedFoundationRecord, projection signingProjection) {
	switch p := projection.(type) {
	case foundationv1.ProviderIdentitySigningProjection:
		stake := optionalStringPointer(p.StakeReference)
		wrapper.Payload = &transportv1.SignedFoundationRecord_ProviderIdentity{ProviderIdentity: &foundationv1.ProviderIdentity{Metadata: metadataProto(p.Metadata), ProviderId: p.ProviderID, OrganizationIdentityUri: p.OrganizationIdentity, PayoutIdentity: p.PayoutIdentity, Jurisdictions: append([]string(nil), p.Jurisdictions...), PolicyDigestsSha256: digestSetBytes(p.PolicyDigestsSHA256), StakeReference: stake, OwnershipGeneration: p.OwnershipGeneration, ValidFromUnixNano: p.ValidFromUnixNano, ValidUntilUnixNano: p.ValidUntilUnixNano, State: foundationv1.IdentityState(p.State)}}
	case foundationv1.AgentIdentitySigningProjection:
		wrapper.Payload = &transportv1.SignedFoundationRecord_AgentIdentity{AgentIdentity: &foundationv1.AgentIdentity{Metadata: metadataProto(p.Metadata), AgentId: p.AgentID, ProviderId: p.ProviderID, HostId: p.HostID, SpiffeId: p.SPIFFEID, KeyId: p.KeyID, OwnershipGeneration: p.OwnershipGeneration, ValidFromUnixNano: p.ValidFromUnixNano, ValidUntilUnixNano: p.ValidUntilUnixNano, State: foundationv1.IdentityState(p.State)}}
	case foundationv1.HostIdentitySigningProjection:
		wrapper.Payload = &transportv1.SignedFoundationRecord_HostIdentity{HostIdentity: &foundationv1.HostIdentity{Metadata: metadataProto(p.Metadata), HostId: p.HostID, ProviderId: p.ProviderID, ProviderSiteId: p.ProviderSiteID, AttestationIdentity: p.AttestationIdentity, KeyId: p.KeyID, OwnershipGeneration: p.OwnershipGeneration, ValidFromUnixNano: p.ValidFromUnixNano, ValidUntilUnixNano: p.ValidUntilUnixNano, State: foundationv1.IdentityState(p.State)}}
	case foundationv1.DeviceIdentitySigningProjection:
		wrapper.Payload = &transportv1.SignedFoundationRecord_DeviceIdentity{DeviceIdentity: &foundationv1.DeviceIdentity{Metadata: metadataProto(p.Metadata), DeviceId: p.DeviceID, ProviderId: p.ProviderID, HostId: p.HostID, VendorSerialDigestSha256: fixed32Bytes(p.VendorSerialDigestSHA256), AttestationIdentity: p.AttestationIdentity, KeyId: p.KeyID, OwnershipGeneration: p.OwnershipGeneration, ValidFromUnixNano: p.ValidFromUnixNano, ValidUntilUnixNano: p.ValidUntilUnixNano, State: foundationv1.IdentityState(p.State)}}
	case foundationv1.MinerIdentitySigningProjection:
		wrapper.Payload = &transportv1.SignedFoundationRecord_MinerIdentity{MinerIdentity: &foundationv1.MinerIdentity{Metadata: metadataProto(p.Metadata), MinerId: p.MinerID, ProviderId: p.ProviderID, AgentId: p.AgentID, DeviceIds: append([]string(nil), p.DeviceIDs...), PayoutIdentity: p.PayoutIdentity, KeyId: p.KeyID, BindingGeneration: p.BindingGeneration, ValidFromUnixNano: p.ValidFromUnixNano, ValidUntilUnixNano: p.ValidUntilUnixNano, State: foundationv1.IdentityState(p.State)}}
	case foundationv1.RunnerIdentitySigningProjection:
		wrapper.Payload = &transportv1.SignedFoundationRecord_RunnerIdentity{RunnerIdentity: &foundationv1.RunnerIdentity{Metadata: metadataProto(p.Metadata), RunnerAttemptId: p.RunnerAttemptID, ProviderId: p.ProviderID, AgentId: p.AgentID, LeaseId: p.LeaseID, JobId: p.JobID, AttemptId: p.AttemptID, WorkloadIdentity: p.WorkloadIdentity, KeyId: p.KeyID, ValidFromUnixNano: p.ValidFromUnixNano, ValidUntilUnixNano: p.ValidUntilUnixNano, State: foundationv1.IdentityState(p.State)}}
	case foundationv1.BuyerIdentitySigningProjection:
		wrapper.Payload = &transportv1.SignedFoundationRecord_BuyerIdentity{BuyerIdentity: &foundationv1.BuyerIdentity{Metadata: metadataProto(p.Metadata), BuyerId: p.BuyerID, OrganizationIdentityUri: p.OrganizationIdentityURI, BillingIdentity: p.BillingIdentity, KeyId: p.KeyID, AuthorizationGeneration: p.AuthorizationGeneration, ValidFromUnixNano: p.ValidFromUnixNano, ValidUntilUnixNano: p.ValidUntilUnixNano, State: foundationv1.IdentityState(p.State)}}
	case foundationv1.ServiceIdentitySigningProjection:
		wrapper.Payload = &transportv1.SignedFoundationRecord_ServiceIdentity{ServiceIdentity: &foundationv1.ServiceIdentity{Metadata: metadataProto(p.Metadata), ServiceId: p.ServiceID, ServiceName: p.ServiceName, SpiffeId: p.SPIFFEID, DeploymentEnvironment: p.DeploymentEnvironment, KeyId: p.KeyID, CredentialGeneration: p.CredentialGeneration, ValidFromUnixNano: p.ValidFromUnixNano, ValidUntilUnixNano: p.ValidUntilUnixNano, State: foundationv1.IdentityState(p.State)}}
	case foundationv1.KeyLifecycleSigningProjection:
		wrapper.Payload = &transportv1.SignedFoundationRecord_KeyLifecycle{KeyLifecycle: &foundationv1.KeyLifecycle{Metadata: metadataProto(p.Metadata), KeyId: p.KeyID, SubjectIdentity: p.SubjectIdentity, SubjectKind: commonv1.PrincipalKind(p.SubjectKind), Algorithm: commonv1.SignatureAlgorithm(p.Algorithm), State: foundationv1.KeyLifecycleState(p.State), NotBeforeUnixNano: p.NotBeforeUnixNano, NotAfterUnixNano: p.NotAfterUnixNano, RevokedAtUnixNano: optionalInt64Pointer(p.RevokedAtUnixNano), RotationPredecessorKeyId: optionalStringPointer(p.RotationPredecessorKeyID), AllowedMessageTypeIds: append([]uint32(nil), p.AllowedMessageTypeIDs...), AuthorizationPolicyDigestSha256: fixed32Bytes(p.AuthorizationPolicyDigestSHA256), TransitionReasonCode: optionalStringPointer(p.TransitionReasonCode)}}
	case foundationv1.PolicyBundleSigningProjection:
		wrapper.Payload = &transportv1.SignedFoundationRecord_PolicyBundle{PolicyBundle: &foundationv1.PolicyBundle{Metadata: metadataProto(p.Metadata), PolicyBundleId: p.PolicyBundleID, PolicyKind: p.PolicyKind, PolicyVersion: &commonv1.SchemaVersion{Major: p.PolicyVersion.Major, Minor: p.PolicyVersion.Minor}, Sequence: p.Sequence, PredecessorDigestSha256: optionalFixed32Bytes(p.PredecessorDigestSHA256), ApprovedAtUnixNano: p.ApprovedAtUnixNano, EffectiveAtUnixNano: p.EffectiveAtUnixNano, ExpiresAtUnixNano: p.ExpiresAtUnixNano, PolicyDocumentDigestSha256: fixed32Bytes(p.PolicyDocumentDigestSHA256), PolicyDocumentMediaType: p.PolicyDocumentMediaType, ApproverIdentities: append([]string(nil), p.ApproverIdentities...), ApproverKeyIds: append([]string(nil), p.ApproverKeyIDs...), MinimumApprovals: p.MinimumApprovals, Emergency: p.Emergency, RollbackTargetDigestSha256: optionalFixed32Bytes(p.RollbackTargetDigestSHA256), BreakGlassExpiresAtUnixNano: optionalInt64Pointer(p.BreakGlassExpiresAtUnixNano), State: foundationv1.PolicyBundleState(p.State)}}
	case foundationv1.AuditEventSigningProjection:
		wrapper.Payload = &transportv1.SignedFoundationRecord_AuditEvent{AuditEvent: &foundationv1.AuditEvent{Metadata: metadataProto(p.Metadata), AuditEventId: p.AuditEventID, EventType: p.EventType, ActorIdentity: p.ActorIdentity, ActorKeyId: p.ActorKeyID, SubjectIds: append([]string(nil), p.SubjectIDs...), CauseCode: p.CauseCode, CorrelationId: fixed16Bytes(p.CorrelationID), CausationId: optionalFixed16Bytes(p.CausationID), OccurredAtUnixNano: p.OccurredAtUnixNano, Outcome: foundationv1.AuditOutcome(p.Outcome), AppliedPolicyDigestsSha256: digestSetBytes(p.AppliedPolicyDigestsSHA256), EvidenceDigestsSha256: digestSetBytes(p.EvidenceDigestsSHA256), RedactedDetailsDigestSha256: optionalFixed32Bytes(p.RedactedDetailsDigestSHA256), PreviousEventDigestSha256: fixed32Bytes(p.PreviousEventDigestSHA256), AuditSequence: p.AuditSequence}}
	case foundationv1.EvidenceRecordSigningProjection:
		observations := make([]*foundationv1.MetricObservation, 0, len(p.Observations))
		for _, item := range p.Observations {
			observations = append(observations, &foundationv1.MetricObservation{MetricId: item.MetricID, ObservedNumerator: item.ObservedNumerator, ObservedDenominator: item.ObservedDenominator, SampleSize: item.SampleSize, ConfidenceLowerNumerator: item.ConfidenceLowerNumerator, ConfidenceLowerDenominator: item.ConfidenceLowerDenominator, ConfidenceUpperNumerator: item.ConfidenceUpperNumerator, ConfidenceUpperDenominator: item.ConfidenceUpperDenominator, CriterionPassed: item.CriterionPassed})
		}
		wrapper.Payload = &transportv1.SignedFoundationRecord_EvidenceRecord{EvidenceRecord: &foundationv1.EvidenceRecord{Metadata: metadataProto(p.Metadata), EvidenceId: p.EvidenceID, ExperimentPlanId: p.ExperimentPlanID, CapabilityId: p.CapabilityID, Component: p.Component, OwnerIdentity: p.OwnerIdentity, SoftwareVersion: p.SoftwareVersion, HardwareScope: append([]string(nil), p.HardwareScope...), WorkloadScope: append([]string(nil), p.WorkloadScope...), RegionScope: append([]string(nil), p.RegionScope...), TestStartedAtUnixNano: p.TestStartedAtUnixNano, TestEndedAtUnixNano: p.TestEndedAtUnixNano, SampleSize: p.SampleSize, EvidenceArtifactDigestsSha256: digestSetBytes(p.EvidenceArtifactDigestsSHA256), Observations: observations, ApprovingRole: p.ApprovingRole, ApprovingIdentities: append([]string(nil), p.ApprovingIdentities...), ApprovedAtUnixNano: p.ApprovedAtUnixNano, ExpiresAtUnixNano: p.ExpiresAtUnixNano, RevalidationTriggers: append([]string(nil), p.RevalidationTriggers...), AchievedLevel: foundationv1.EvidenceLevel(p.AchievedLevel), Status: foundationv1.EvidenceStatus(p.Status)}}
	case foundationv1.ExperimentPlanSigningProjection:
		criteria := make([]*foundationv1.MetricCriterion, 0, len(p.Criteria))
		for _, item := range p.Criteria {
			criteria = append(criteria, &foundationv1.MetricCriterion{MetricId: item.MetricID, Comparison: foundationv1.ComparisonOperator(item.Comparison), ThresholdNumerator: item.ThresholdNumerator, ThresholdDenominator: item.ThresholdDenominator, UpperThresholdNumerator: optionalInt64Pointer(item.UpperThresholdNumerator), UpperThresholdDenominator: optionalUint64Pointer(item.UpperThresholdDenominator), Unit: item.Unit, PercentileBasisPoints: optionalUint32Pointer(item.PercentileBasisPoints), MinimumMetricSampleSize: item.MinimumMetricSampleSize})
		}
		wrapper.Payload = &transportv1.SignedFoundationRecord_ExperimentPlan{ExperimentPlan: &foundationv1.ExperimentPlan{Metadata: metadataProto(p.Metadata), ExperimentPlanId: p.ExperimentPlanID, CapabilityId: p.CapabilityID, Component: p.Component, OwnerIdentity: p.OwnerIdentity, SoftwareVersion: p.SoftwareVersion, HardwareScope: append([]string(nil), p.HardwareScope...), WorkloadScope: append([]string(nil), p.WorkloadScope...), RegionScope: append([]string(nil), p.RegionScope...), CollectionNotBeforeUnixNano: p.CollectionNotBeforeUnixNano, ObservationWindowNanos: p.ObservationWindowNanos, MinimumSampleSize: p.MinimumSampleSize, ConfidenceLevelBasisPoints: p.ConfidenceLevelBasisPoints, ConfidenceMethod: foundationv1.ConfidenceMethod(p.ConfidenceMethod), Criteria: criteria, RevalidationTriggers: append([]string(nil), p.RevalidationTriggers...), ExpiresAtUnixNano: p.ExpiresAtUnixNano, ExperimentPolicyDigestSha256: fixed32Bytes(p.ExperimentPolicyDigestSHA256), TargetLevel: foundationv1.EvidenceLevel(p.TargetLevel), FrozenAtUnixNano: p.FrozenAtUnixNano, ApprovingIdentities: append([]string(nil), p.ApprovingIdentities...)}}
	case foundationv1.OwnershipTransferAuthorizationSigningProjection:
		closures := make([]*foundationv1.KeyClosure, 0, len(p.OldKeyClosures))
		for _, item := range p.OldKeyClosures {
			closures = append(closures, &foundationv1.KeyClosure{KeyId: item.KeyID, TerminalKeyLifecyclePayloadDigestSha256: fixed32Bytes(item.TerminalKeyLifecyclePayloadDigestSHA256)})
		}
		evidence := make([]*foundationv1.TransferEvidenceCommitment, 0, len(p.EvidenceCommitments))
		for _, item := range p.EvidenceCommitments {
			evidence = append(evidence, &foundationv1.TransferEvidenceCommitment{EvidenceKind: foundationv1.TransferEvidenceKind(item.EvidenceKind), CcseRecordDigestSha256: fixed32Bytes(item.CCSERecordDigestSHA256)})
		}
		oldAuthorities := make([]*foundationv1.TransferAuthority, 0, len(p.OldAuthorities))
		for _, item := range p.OldAuthorities {
			oldAuthorities = append(oldAuthorities, &foundationv1.TransferAuthority{Identity: item.Identity, KeyId: item.KeyID})
		}
		newAuthorities := make([]*foundationv1.TransferAuthority, 0, len(p.NewAuthorities))
		for _, item := range p.NewAuthorities {
			newAuthorities = append(newAuthorities, &foundationv1.TransferAuthority{Identity: item.Identity, KeyId: item.KeyID})
		}
		wrapper.Payload = &transportv1.SignedFoundationRecord_OwnershipTransferAuthorization{OwnershipTransferAuthorization: &foundationv1.OwnershipTransferAuthorization{Metadata: metadataProto(p.Metadata), TransferAuthorizationId: p.TransferAuthorizationID, SubjectKind: commonv1.PrincipalKind(p.SubjectKind), PreviousEntityId: p.PreviousEntityID, NextEntityId: p.NextEntityID, PreviousPrincipalIdentity: p.PreviousPrincipalIdentity, NextPrincipalIdentity: p.NextPrincipalIdentity, PreviousProviderId: p.PreviousProviderID, NextProviderId: p.NextProviderID, ExpectedGeneration: p.ExpectedGeneration, NextGeneration: p.NextGeneration, PreviousTerminalIdentityPayloadDigestSha256: fixed32Bytes(p.PreviousTerminalIdentityPayloadDigestSHA256), NextPendingIdentityPayloadDigestSha256: fixed32Bytes(p.NextPendingIdentityPayloadDigestSHA256), OldKeyClosures: closures, NewKeyId: p.NewKeyID, EvidenceCommitments: evidence, EffectiveAtUnixNano: p.EffectiveAtUnixNano, ExpiresAtUnixNano: p.ExpiresAtUnixNano, OldAuthorities: oldAuthorities, NewAuthorities: newAuthorities}}
	default:
		panic("unknown projection")
	}
}

func metadataProto(p foundationv1.RecordMetadataSigningProjection) *commonv1.RecordMetadata {
	return &commonv1.RecordMetadata{SchemaVersion: &commonv1.SchemaVersion{Major: p.SchemaVersion.Major, Minor: p.SchemaVersion.Minor}, RecordId: p.RecordID, CreatedAtUnixNano: p.CreatedAtUnixNano, IntegrityDigestSha256: fixed32Bytes(p.IntegrityDigest), HomeRegion: p.HomeRegion, WriterEpoch: p.WriterEpoch, StateVersion: p.StateVersion, IdempotencyKey: fixed16Bytes(p.IdempotencyKey), PolicyDigestsSha256: digestSetBytes(p.PolicyDigestsSHA256)}
}

func fixed16Bytes(value [16]byte) []byte { return append([]byte(nil), value[:]...) }
func fixed32Bytes(value [32]byte) []byte { return append([]byte(nil), value[:]...) }

func digestSetBytes(values [][32]byte) [][]byte {
	out := make([][]byte, 0, len(values))
	for _, value := range values {
		out = append(out, fixed32Bytes(value))
	}
	return out
}

func optionalStringPointer(value foundationv1.OptionalString) *string {
	if !value.Present {
		return nil
	}
	copy := value.Value
	return &copy
}
func optionalInt64Pointer(value foundationv1.OptionalInt64) *int64 {
	if !value.Present {
		return nil
	}
	copy := value.Value
	return &copy
}
func optionalUint64Pointer(value foundationv1.OptionalUint64) *uint64 {
	if !value.Present {
		return nil
	}
	copy := value.Value
	return &copy
}
func optionalUint32Pointer(value foundationv1.OptionalUint32) *uint32 {
	if !value.Present {
		return nil
	}
	copy := value.Value
	return &copy
}
func optionalFixed16Bytes(value foundationv1.OptionalFixedBytes16) []byte {
	if !value.Present {
		return nil
	}
	return fixed16Bytes(value.Value)
}
func optionalFixed32Bytes(value foundationv1.OptionalFixedBytes32) []byte {
	if !value.Present {
		return nil
	}
	return fixed32Bytes(value.Value)
}

func wireField(t *testing.T, wire []byte, target protowire.Number) []byte {
	t.Helper()
	for len(wire) != 0 {
		number, wireType, tagSize := protowire.ConsumeTag(wire)
		if tagSize < 0 {
			t.Fatalf("bad test wire tag: %v", protowire.ParseError(tagSize))
		}
		valueSize := protowire.ConsumeFieldValue(number, wireType, wire[tagSize:])
		if valueSize < 0 {
			t.Fatalf("bad test wire value: %v", protowire.ParseError(valueSize))
		}
		field := wire[:tagSize+valueSize]
		if number == target {
			return append([]byte(nil), field...)
		}
		wire = wire[tagSize+valueSize:]
	}
	t.Fatalf("field %d not found", target)
	return nil
}
