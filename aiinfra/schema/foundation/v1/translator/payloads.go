// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package translator

import (
	"fmt"

	"github.com/cypherium/cypher/aiinfra/schema"
	commonv1 "github.com/cypherium/cypher/aiinfra/schema/common/v1"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
	transportv1 "github.com/cypherium/cypher/aiinfra/schema/transport/v1"
)

func selectedMessageTypeID(wrapper *transportv1.SignedFoundationRecord) (uint32, error) {
	switch wrapper.Payload.(type) {
	case *transportv1.SignedFoundationRecord_ProviderIdentity:
		return schema.MessageTypeProviderIdentity, nil
	case *transportv1.SignedFoundationRecord_AgentIdentity:
		return schema.MessageTypeAgentIdentity, nil
	case *transportv1.SignedFoundationRecord_HostIdentity:
		return schema.MessageTypeHostIdentity, nil
	case *transportv1.SignedFoundationRecord_DeviceIdentity:
		return schema.MessageTypeDeviceIdentity, nil
	case *transportv1.SignedFoundationRecord_MinerIdentity:
		return schema.MessageTypeMinerIdentity, nil
	case *transportv1.SignedFoundationRecord_RunnerIdentity:
		return schema.MessageTypeRunnerIdentity, nil
	case *transportv1.SignedFoundationRecord_BuyerIdentity:
		return schema.MessageTypeBuyerIdentity, nil
	case *transportv1.SignedFoundationRecord_ServiceIdentity:
		return schema.MessageTypeServiceIdentity, nil
	case *transportv1.SignedFoundationRecord_KeyLifecycle:
		return schema.MessageTypeKeyLifecycle, nil
	case *transportv1.SignedFoundationRecord_PolicyBundle:
		return schema.MessageTypePolicyBundle, nil
	case *transportv1.SignedFoundationRecord_AuditEvent:
		return schema.MessageTypeAuditEvent, nil
	case *transportv1.SignedFoundationRecord_EvidenceRecord:
		return schema.MessageTypeEvidenceRecord, nil
	case *transportv1.SignedFoundationRecord_ExperimentPlan:
		return schema.MessageTypeExperimentPlan, nil
	case *transportv1.SignedFoundationRecord_OwnershipTransferAuthorization:
		return schema.MessageTypeOwnershipTransferAuthorization, nil
	default:
		return 0, missing("payload")
	}
}

func translatePayload(wrapper *transportv1.SignedFoundationRecord) (uint32, signingProjection, error) {
	switch selected := wrapper.Payload.(type) {
	case *transportv1.SignedFoundationRecord_ProviderIdentity:
		projection, err := providerIdentity(selected.ProviderIdentity)
		return messageType(projection, err)
	case *transportv1.SignedFoundationRecord_AgentIdentity:
		projection, err := agentIdentity(selected.AgentIdentity)
		return messageType(projection, err)
	case *transportv1.SignedFoundationRecord_HostIdentity:
		projection, err := hostIdentity(selected.HostIdentity)
		return messageType(projection, err)
	case *transportv1.SignedFoundationRecord_DeviceIdentity:
		projection, err := deviceIdentity(selected.DeviceIdentity)
		return messageType(projection, err)
	case *transportv1.SignedFoundationRecord_MinerIdentity:
		projection, err := minerIdentity(selected.MinerIdentity)
		return messageType(projection, err)
	case *transportv1.SignedFoundationRecord_RunnerIdentity:
		projection, err := runnerIdentity(selected.RunnerIdentity)
		return messageType(projection, err)
	case *transportv1.SignedFoundationRecord_BuyerIdentity:
		projection, err := buyerIdentity(selected.BuyerIdentity)
		return messageType(projection, err)
	case *transportv1.SignedFoundationRecord_ServiceIdentity:
		projection, err := serviceIdentity(selected.ServiceIdentity)
		return messageType(projection, err)
	case *transportv1.SignedFoundationRecord_KeyLifecycle:
		projection, err := keyLifecycle(selected.KeyLifecycle)
		return messageType(projection, err)
	case *transportv1.SignedFoundationRecord_PolicyBundle:
		projection, err := policyBundle(selected.PolicyBundle)
		return messageType(projection, err)
	case *transportv1.SignedFoundationRecord_AuditEvent:
		projection, err := auditEvent(selected.AuditEvent)
		return messageType(projection, err)
	case *transportv1.SignedFoundationRecord_EvidenceRecord:
		projection, err := evidenceRecord(selected.EvidenceRecord)
		return messageType(projection, err)
	case *transportv1.SignedFoundationRecord_ExperimentPlan:
		projection, err := experimentPlan(selected.ExperimentPlan)
		return messageType(projection, err)
	case *transportv1.SignedFoundationRecord_OwnershipTransferAuthorization:
		projection, err := ownershipTransferAuthorization(selected.OwnershipTransferAuthorization)
		return messageType(projection, err)
	default:
		return 0, nil, missing("payload")
	}
}

func messageType[T signingProjection](projection T, err error) (uint32, signingProjection, error) {
	if err != nil {
		return 0, nil, err
	}
	return projection.MessageTypeID(), projection, nil
}

func providerIdentity(input *foundationv1.ProviderIdentity) (foundationv1.ProviderIdentitySigningProjection, error) {
	if input == nil {
		return foundationv1.ProviderIdentitySigningProjection{}, missing("provider_identity")
	}
	metadata, err := recordMetadata(input.Metadata)
	if err != nil {
		return foundationv1.ProviderIdentitySigningProjection{}, err
	}
	policyDigests, err := fixed32Set(input.PolicyDigestsSha256, "provider_identity.policy_digests_sha256")
	if err != nil {
		return foundationv1.ProviderIdentitySigningProjection{}, err
	}
	return foundationv1.ProviderIdentitySigningProjection{
		Metadata:             metadata,
		ProviderID:           input.ProviderId,
		OrganizationIdentity: input.OrganizationIdentityUri,
		PayoutIdentity:       input.PayoutIdentity,
		Jurisdictions:        append([]string(nil), input.Jurisdictions...),
		PolicyDigestsSHA256:  policyDigests,
		StakeReference:       optionalProjectionString(input.StakeReference),
		OwnershipGeneration:  input.OwnershipGeneration,
		ValidFromUnixNano:    input.ValidFromUnixNano,
		ValidUntilUnixNano:   input.ValidUntilUnixNano,
		State:                uint32(input.State),
	}, nil
}

func agentIdentity(input *foundationv1.AgentIdentity) (foundationv1.AgentIdentitySigningProjection, error) {
	if input == nil {
		return foundationv1.AgentIdentitySigningProjection{}, missing("agent_identity")
	}
	metadata, err := recordMetadata(input.Metadata)
	if err != nil {
		return foundationv1.AgentIdentitySigningProjection{}, err
	}
	return foundationv1.AgentIdentitySigningProjection{
		Metadata: metadata, AgentID: input.AgentId, ProviderID: input.ProviderId, HostID: input.HostId,
		SPIFFEID: input.SpiffeId, KeyID: input.KeyId, OwnershipGeneration: input.OwnershipGeneration,
		ValidFromUnixNano: input.ValidFromUnixNano, ValidUntilUnixNano: input.ValidUntilUnixNano, State: uint32(input.State),
	}, nil
}

func hostIdentity(input *foundationv1.HostIdentity) (foundationv1.HostIdentitySigningProjection, error) {
	if input == nil {
		return foundationv1.HostIdentitySigningProjection{}, missing("host_identity")
	}
	metadata, err := recordMetadata(input.Metadata)
	if err != nil {
		return foundationv1.HostIdentitySigningProjection{}, err
	}
	return foundationv1.HostIdentitySigningProjection{
		Metadata: metadata, HostID: input.HostId, ProviderID: input.ProviderId, ProviderSiteID: input.ProviderSiteId,
		AttestationIdentity: input.AttestationIdentity, KeyID: input.KeyId, OwnershipGeneration: input.OwnershipGeneration,
		ValidFromUnixNano: input.ValidFromUnixNano, ValidUntilUnixNano: input.ValidUntilUnixNano, State: uint32(input.State),
	}, nil
}

func deviceIdentity(input *foundationv1.DeviceIdentity) (foundationv1.DeviceIdentitySigningProjection, error) {
	if input == nil {
		return foundationv1.DeviceIdentitySigningProjection{}, missing("device_identity")
	}
	metadata, err := recordMetadata(input.Metadata)
	if err != nil {
		return foundationv1.DeviceIdentitySigningProjection{}, err
	}
	serial, err := fixed32(input.VendorSerialDigestSha256, "device_identity.vendor_serial_digest_sha256")
	if err != nil {
		return foundationv1.DeviceIdentitySigningProjection{}, err
	}
	return foundationv1.DeviceIdentitySigningProjection{
		Metadata: metadata, DeviceID: input.DeviceId, ProviderID: input.ProviderId, HostID: input.HostId,
		VendorSerialDigestSHA256: serial, AttestationIdentity: input.AttestationIdentity, KeyID: input.KeyId,
		OwnershipGeneration: input.OwnershipGeneration, ValidFromUnixNano: input.ValidFromUnixNano,
		ValidUntilUnixNano: input.ValidUntilUnixNano, State: uint32(input.State),
	}, nil
}

func minerIdentity(input *foundationv1.MinerIdentity) (foundationv1.MinerIdentitySigningProjection, error) {
	if input == nil {
		return foundationv1.MinerIdentitySigningProjection{}, missing("miner_identity")
	}
	metadata, err := recordMetadata(input.Metadata)
	if err != nil {
		return foundationv1.MinerIdentitySigningProjection{}, err
	}
	return foundationv1.MinerIdentitySigningProjection{
		Metadata: metadata, MinerID: input.MinerId, ProviderID: input.ProviderId, AgentID: input.AgentId,
		DeviceIDs: append([]string(nil), input.DeviceIds...), PayoutIdentity: input.PayoutIdentity, KeyID: input.KeyId,
		BindingGeneration: input.BindingGeneration, ValidFromUnixNano: input.ValidFromUnixNano,
		ValidUntilUnixNano: input.ValidUntilUnixNano, State: uint32(input.State),
	}, nil
}

func runnerIdentity(input *foundationv1.RunnerIdentity) (foundationv1.RunnerIdentitySigningProjection, error) {
	if input == nil {
		return foundationv1.RunnerIdentitySigningProjection{}, missing("runner_identity")
	}
	metadata, err := recordMetadata(input.Metadata)
	if err != nil {
		return foundationv1.RunnerIdentitySigningProjection{}, err
	}
	return foundationv1.RunnerIdentitySigningProjection{
		Metadata: metadata, RunnerAttemptID: input.RunnerAttemptId, ProviderID: input.ProviderId, AgentID: input.AgentId,
		LeaseID: input.LeaseId, JobID: input.JobId, AttemptID: input.AttemptId, WorkloadIdentity: input.WorkloadIdentity,
		KeyID: input.KeyId, ValidFromUnixNano: input.ValidFromUnixNano, ValidUntilUnixNano: input.ValidUntilUnixNano,
		State: uint32(input.State),
	}, nil
}

func buyerIdentity(input *foundationv1.BuyerIdentity) (foundationv1.BuyerIdentitySigningProjection, error) {
	if input == nil {
		return foundationv1.BuyerIdentitySigningProjection{}, missing("buyer_identity")
	}
	metadata, err := recordMetadata(input.Metadata)
	if err != nil {
		return foundationv1.BuyerIdentitySigningProjection{}, err
	}
	return foundationv1.BuyerIdentitySigningProjection{
		Metadata: metadata, BuyerID: input.BuyerId, OrganizationIdentityURI: input.OrganizationIdentityUri,
		BillingIdentity: input.BillingIdentity, KeyID: input.KeyId, AuthorizationGeneration: input.AuthorizationGeneration,
		ValidFromUnixNano: input.ValidFromUnixNano, ValidUntilUnixNano: input.ValidUntilUnixNano, State: uint32(input.State),
	}, nil
}

func serviceIdentity(input *foundationv1.ServiceIdentity) (foundationv1.ServiceIdentitySigningProjection, error) {
	if input == nil {
		return foundationv1.ServiceIdentitySigningProjection{}, missing("service_identity")
	}
	metadata, err := recordMetadata(input.Metadata)
	if err != nil {
		return foundationv1.ServiceIdentitySigningProjection{}, err
	}
	return foundationv1.ServiceIdentitySigningProjection{
		Metadata: metadata, ServiceID: input.ServiceId, ServiceName: input.ServiceName, SPIFFEID: input.SpiffeId,
		DeploymentEnvironment: input.DeploymentEnvironment, KeyID: input.KeyId, CredentialGeneration: input.CredentialGeneration,
		ValidFromUnixNano: input.ValidFromUnixNano, ValidUntilUnixNano: input.ValidUntilUnixNano, State: uint32(input.State),
	}, nil
}

func keyLifecycle(input *foundationv1.KeyLifecycle) (foundationv1.KeyLifecycleSigningProjection, error) {
	if input == nil {
		return foundationv1.KeyLifecycleSigningProjection{}, missing("key_lifecycle")
	}
	metadata, err := recordMetadata(input.Metadata)
	if err != nil {
		return foundationv1.KeyLifecycleSigningProjection{}, err
	}
	authorizationDigest, err := fixed32(input.AuthorizationPolicyDigestSha256, "key_lifecycle.authorization_policy_digest_sha256")
	if err != nil {
		return foundationv1.KeyLifecycleSigningProjection{}, err
	}
	return foundationv1.KeyLifecycleSigningProjection{
		Metadata: metadata, KeyID: input.KeyId, SubjectIdentity: input.SubjectIdentity, SubjectKind: uint32(input.SubjectKind),
		Algorithm: uint32(input.Algorithm), State: uint32(input.State), NotBeforeUnixNano: input.NotBeforeUnixNano,
		NotAfterUnixNano: input.NotAfterUnixNano, RevokedAtUnixNano: optionalProjectionInt64(input.RevokedAtUnixNano),
		RotationPredecessorKeyID:        optionalProjectionString(input.RotationPredecessorKeyId),
		AllowedMessageTypeIDs:           append([]uint32(nil), input.AllowedMessageTypeIds...),
		AuthorizationPolicyDigestSHA256: authorizationDigest,
		TransitionReasonCode:            optionalProjectionString(input.TransitionReasonCode),
	}, nil
}

func policyBundle(input *foundationv1.PolicyBundle) (foundationv1.PolicyBundleSigningProjection, error) {
	if input == nil {
		return foundationv1.PolicyBundleSigningProjection{}, missing("policy_bundle")
	}
	metadata, err := recordMetadata(input.Metadata)
	if err != nil {
		return foundationv1.PolicyBundleSigningProjection{}, err
	}
	policyVersion, err := projectionSchemaVersion(input.PolicyVersion, "policy_bundle.policy_version", false)
	if err != nil {
		return foundationv1.PolicyBundleSigningProjection{}, err
	}
	predecessor, err := optionalProjectionFixed32(input.PredecessorDigestSha256, "policy_bundle.predecessor_digest_sha256")
	if err != nil {
		return foundationv1.PolicyBundleSigningProjection{}, err
	}
	documentDigest, err := fixed32(input.PolicyDocumentDigestSha256, "policy_bundle.policy_document_digest_sha256")
	if err != nil {
		return foundationv1.PolicyBundleSigningProjection{}, err
	}
	rollback, err := optionalProjectionFixed32(input.RollbackTargetDigestSha256, "policy_bundle.rollback_target_digest_sha256")
	if err != nil {
		return foundationv1.PolicyBundleSigningProjection{}, err
	}
	return foundationv1.PolicyBundleSigningProjection{
		Metadata: metadata, PolicyBundleID: input.PolicyBundleId, PolicyKind: input.PolicyKind, PolicyVersion: policyVersion,
		Sequence: input.Sequence, PredecessorDigestSHA256: predecessor, ApprovedAtUnixNano: input.ApprovedAtUnixNano,
		EffectiveAtUnixNano: input.EffectiveAtUnixNano, ExpiresAtUnixNano: input.ExpiresAtUnixNano,
		PolicyDocumentDigestSHA256: documentDigest, PolicyDocumentMediaType: input.PolicyDocumentMediaType,
		ApproverIdentities: append([]string(nil), input.ApproverIdentities...), ApproverKeyIDs: append([]string(nil), input.ApproverKeyIds...),
		MinimumApprovals: input.MinimumApprovals, Emergency: input.Emergency, RollbackTargetDigestSHA256: rollback,
		BreakGlassExpiresAtUnixNano: optionalProjectionInt64(input.BreakGlassExpiresAtUnixNano), State: uint32(input.State),
	}, nil
}

func auditEvent(input *foundationv1.AuditEvent) (foundationv1.AuditEventSigningProjection, error) {
	if input == nil {
		return foundationv1.AuditEventSigningProjection{}, missing("audit_event")
	}
	metadata, err := recordMetadata(input.Metadata)
	if err != nil {
		return foundationv1.AuditEventSigningProjection{}, err
	}
	correlationID, err := fixed16(input.CorrelationId, "audit_event.correlation_id")
	if err != nil {
		return foundationv1.AuditEventSigningProjection{}, err
	}
	causationID, err := optionalProjectionFixed16(input.CausationId, "audit_event.causation_id")
	if err != nil {
		return foundationv1.AuditEventSigningProjection{}, err
	}
	policies, err := fixed32Set(input.AppliedPolicyDigestsSha256, "audit_event.applied_policy_digests_sha256")
	if err != nil {
		return foundationv1.AuditEventSigningProjection{}, err
	}
	evidence, err := fixed32Set(input.EvidenceDigestsSha256, "audit_event.evidence_digests_sha256")
	if err != nil {
		return foundationv1.AuditEventSigningProjection{}, err
	}
	redacted, err := optionalProjectionFixed32(input.RedactedDetailsDigestSha256, "audit_event.redacted_details_digest_sha256")
	if err != nil {
		return foundationv1.AuditEventSigningProjection{}, err
	}
	previous, err := fixed32(input.PreviousEventDigestSha256, "audit_event.previous_event_digest_sha256")
	if err != nil {
		return foundationv1.AuditEventSigningProjection{}, err
	}
	return foundationv1.AuditEventSigningProjection{
		Metadata: metadata, AuditEventID: input.AuditEventId, EventType: input.EventType, ActorIdentity: input.ActorIdentity,
		ActorKeyID: input.ActorKeyId, SubjectIDs: append([]string(nil), input.SubjectIds...), CauseCode: input.CauseCode,
		CorrelationID: correlationID, CausationID: causationID, OccurredAtUnixNano: input.OccurredAtUnixNano,
		Outcome: uint32(input.Outcome), AppliedPolicyDigestsSHA256: policies, EvidenceDigestsSHA256: evidence,
		RedactedDetailsDigestSHA256: redacted, PreviousEventDigestSHA256: previous, AuditSequence: input.AuditSequence,
	}, nil
}

func evidenceRecord(input *foundationv1.EvidenceRecord) (foundationv1.EvidenceRecordSigningProjection, error) {
	if input == nil {
		return foundationv1.EvidenceRecordSigningProjection{}, missing("evidence_record")
	}
	metadata, err := recordMetadata(input.Metadata)
	if err != nil {
		return foundationv1.EvidenceRecordSigningProjection{}, err
	}
	artifacts, err := fixed32Set(input.EvidenceArtifactDigestsSha256, "evidence_record.evidence_artifact_digests_sha256")
	if err != nil {
		return foundationv1.EvidenceRecordSigningProjection{}, err
	}
	observations := make([]foundationv1.MetricObservationSigningProjection, 0, len(input.Observations))
	for index, observation := range input.Observations {
		translated, translateErr := metricObservation(observation, fmt.Sprintf("evidence_record.observations[%d]", index))
		if translateErr != nil {
			return foundationv1.EvidenceRecordSigningProjection{}, translateErr
		}
		observations = append(observations, translated)
	}
	return foundationv1.EvidenceRecordSigningProjection{
		Metadata: metadata, EvidenceID: input.EvidenceId, ExperimentPlanID: input.ExperimentPlanId,
		CapabilityID: input.CapabilityId, Component: input.Component, OwnerIdentity: input.OwnerIdentity,
		SoftwareVersion: input.SoftwareVersion, HardwareScope: append([]string(nil), input.HardwareScope...),
		WorkloadScope: append([]string(nil), input.WorkloadScope...), RegionScope: append([]string(nil), input.RegionScope...),
		TestStartedAtUnixNano: input.TestStartedAtUnixNano, TestEndedAtUnixNano: input.TestEndedAtUnixNano,
		SampleSize: input.SampleSize, EvidenceArtifactDigestsSHA256: artifacts, Observations: observations,
		ApprovingRole: input.ApprovingRole, ApprovingIdentities: append([]string(nil), input.ApprovingIdentities...),
		ApprovedAtUnixNano: input.ApprovedAtUnixNano, ExpiresAtUnixNano: input.ExpiresAtUnixNano,
		RevalidationTriggers: append([]string(nil), input.RevalidationTriggers...), AchievedLevel: uint32(input.AchievedLevel),
		Status: uint32(input.Status),
	}, nil
}

func experimentPlan(input *foundationv1.ExperimentPlan) (foundationv1.ExperimentPlanSigningProjection, error) {
	if input == nil {
		return foundationv1.ExperimentPlanSigningProjection{}, missing("experiment_plan")
	}
	metadata, err := recordMetadata(input.Metadata)
	if err != nil {
		return foundationv1.ExperimentPlanSigningProjection{}, err
	}
	criteria := make([]foundationv1.MetricCriterionSigningProjection, 0, len(input.Criteria))
	for index, criterion := range input.Criteria {
		translated, translateErr := metricCriterion(criterion, fmt.Sprintf("experiment_plan.criteria[%d]", index))
		if translateErr != nil {
			return foundationv1.ExperimentPlanSigningProjection{}, translateErr
		}
		criteria = append(criteria, translated)
	}
	policyDigest, err := fixed32(input.ExperimentPolicyDigestSha256, "experiment_plan.experiment_policy_digest_sha256")
	if err != nil {
		return foundationv1.ExperimentPlanSigningProjection{}, err
	}
	return foundationv1.ExperimentPlanSigningProjection{
		Metadata: metadata, ExperimentPlanID: input.ExperimentPlanId, CapabilityID: input.CapabilityId,
		Component: input.Component, OwnerIdentity: input.OwnerIdentity, SoftwareVersion: input.SoftwareVersion,
		HardwareScope: append([]string(nil), input.HardwareScope...), WorkloadScope: append([]string(nil), input.WorkloadScope...),
		RegionScope: append([]string(nil), input.RegionScope...), CollectionNotBeforeUnixNano: input.CollectionNotBeforeUnixNano,
		ObservationWindowNanos: input.ObservationWindowNanos, MinimumSampleSize: input.MinimumSampleSize,
		ConfidenceLevelBasisPoints: input.ConfidenceLevelBasisPoints, ConfidenceMethod: uint32(input.ConfidenceMethod),
		Criteria: criteria, RevalidationTriggers: append([]string(nil), input.RevalidationTriggers...),
		ExpiresAtUnixNano: input.ExpiresAtUnixNano, ExperimentPolicyDigestSHA256: policyDigest,
		TargetLevel: uint32(input.TargetLevel), FrozenAtUnixNano: input.FrozenAtUnixNano,
		ApprovingIdentities: append([]string(nil), input.ApprovingIdentities...),
	}, nil
}

func ownershipTransferAuthorization(input *foundationv1.OwnershipTransferAuthorization) (foundationv1.OwnershipTransferAuthorizationSigningProjection, error) {
	if input == nil {
		return foundationv1.OwnershipTransferAuthorizationSigningProjection{}, missing("ownership_transfer_authorization")
	}
	metadata, err := recordMetadata(input.Metadata)
	if err != nil {
		return foundationv1.OwnershipTransferAuthorizationSigningProjection{}, err
	}
	previousTerminalDigest, err := fixed32(input.PreviousTerminalIdentityPayloadDigestSha256, "ownership_transfer_authorization.previous_terminal_identity_payload_digest_sha256")
	if err != nil {
		return foundationv1.OwnershipTransferAuthorizationSigningProjection{}, err
	}
	nextPendingDigest, err := fixed32(input.NextPendingIdentityPayloadDigestSha256, "ownership_transfer_authorization.next_pending_identity_payload_digest_sha256")
	if err != nil {
		return foundationv1.OwnershipTransferAuthorizationSigningProjection{}, err
	}
	closures := make([]foundationv1.KeyClosureSigningProjection, 0, len(input.OldKeyClosures))
	for index, value := range input.OldKeyClosures {
		if value == nil {
			return foundationv1.OwnershipTransferAuthorizationSigningProjection{}, missing(fmt.Sprintf("ownership_transfer_authorization.old_key_closures[%d]", index))
		}
		digest, err := fixed32(value.TerminalKeyLifecyclePayloadDigestSha256, fmt.Sprintf("ownership_transfer_authorization.old_key_closures[%d].terminal_key_lifecycle_payload_digest_sha256", index))
		if err != nil {
			return foundationv1.OwnershipTransferAuthorizationSigningProjection{}, err
		}
		closures = append(closures, foundationv1.KeyClosureSigningProjection{KeyID: value.KeyId, TerminalKeyLifecyclePayloadDigestSHA256: digest})
	}
	evidence := make([]foundationv1.TransferEvidenceCommitmentSigningProjection, 0, len(input.EvidenceCommitments))
	for index, value := range input.EvidenceCommitments {
		if value == nil {
			return foundationv1.OwnershipTransferAuthorizationSigningProjection{}, missing(fmt.Sprintf("ownership_transfer_authorization.evidence_commitments[%d]", index))
		}
		digest, err := fixed32(value.CcseRecordDigestSha256, fmt.Sprintf("ownership_transfer_authorization.evidence_commitments[%d].ccse_record_digest_sha256", index))
		if err != nil {
			return foundationv1.OwnershipTransferAuthorizationSigningProjection{}, err
		}
		evidence = append(evidence, foundationv1.TransferEvidenceCommitmentSigningProjection{EvidenceKind: uint32(value.EvidenceKind), CCSERecordDigestSHA256: digest})
	}
	oldAuthorities, err := transferAuthorities(input.OldAuthorities, "ownership_transfer_authorization.old_authorities")
	if err != nil {
		return foundationv1.OwnershipTransferAuthorizationSigningProjection{}, err
	}
	newAuthorities, err := transferAuthorities(input.NewAuthorities, "ownership_transfer_authorization.new_authorities")
	if err != nil {
		return foundationv1.OwnershipTransferAuthorizationSigningProjection{}, err
	}
	return foundationv1.OwnershipTransferAuthorizationSigningProjection{
		Metadata: metadata, TransferAuthorizationID: input.TransferAuthorizationId, SubjectKind: uint32(input.SubjectKind),
		PreviousEntityID: input.PreviousEntityId, NextEntityID: input.NextEntityId,
		PreviousPrincipalIdentity: input.PreviousPrincipalIdentity, NextPrincipalIdentity: input.NextPrincipalIdentity,
		PreviousProviderID: input.PreviousProviderId, NextProviderID: input.NextProviderId,
		ExpectedGeneration: input.ExpectedGeneration, NextGeneration: input.NextGeneration,
		PreviousTerminalIdentityPayloadDigestSHA256: previousTerminalDigest,
		NextPendingIdentityPayloadDigestSHA256:      nextPendingDigest, OldKeyClosures: closures, NewKeyID: input.NewKeyId,
		EvidenceCommitments: evidence, EffectiveAtUnixNano: input.EffectiveAtUnixNano, ExpiresAtUnixNano: input.ExpiresAtUnixNano,
		OldAuthorities: oldAuthorities, NewAuthorities: newAuthorities,
	}, nil
}

func transferAuthorities(input []*foundationv1.TransferAuthority, name string) ([]foundationv1.TransferAuthoritySigningProjection, error) {
	out := make([]foundationv1.TransferAuthoritySigningProjection, 0, len(input))
	for index, value := range input {
		if value == nil {
			return nil, missing(fmt.Sprintf("%s[%d]", name, index))
		}
		out = append(out, foundationv1.TransferAuthoritySigningProjection{Identity: value.Identity, KeyID: value.KeyId})
	}
	return out, nil
}

func recordMetadata(input *commonv1.RecordMetadata) (foundationv1.RecordMetadataSigningProjection, error) {
	if input == nil {
		return foundationv1.RecordMetadataSigningProjection{}, missing("payload.metadata")
	}
	version, err := projectionSchemaVersion(input.SchemaVersion, "payload.metadata.schema_version", true)
	if err != nil {
		return foundationv1.RecordMetadataSigningProjection{}, err
	}
	integrity, err := fixed32(input.IntegrityDigestSha256, "payload.metadata.integrity_digest_sha256")
	if err != nil {
		return foundationv1.RecordMetadataSigningProjection{}, err
	}
	idempotency, err := fixed16(input.IdempotencyKey, "payload.metadata.idempotency_key")
	if err != nil {
		return foundationv1.RecordMetadataSigningProjection{}, err
	}
	policies, err := fixed32Set(input.PolicyDigestsSha256, "payload.metadata.policy_digests_sha256")
	if err != nil {
		return foundationv1.RecordMetadataSigningProjection{}, err
	}
	return foundationv1.RecordMetadataSigningProjection{
		SchemaVersion: version, RecordID: input.RecordId, CreatedAtUnixNano: input.CreatedAtUnixNano,
		IntegrityDigest: integrity, HomeRegion: input.HomeRegion, WriterEpoch: input.WriterEpoch,
		StateVersion: input.StateVersion, IdempotencyKey: idempotency, PolicyDigestsSHA256: policies,
	}, nil
}

func metricCriterion(input *foundationv1.MetricCriterion, name string) (foundationv1.MetricCriterionSigningProjection, error) {
	if input == nil {
		return foundationv1.MetricCriterionSigningProjection{}, missing(name)
	}
	return foundationv1.MetricCriterionSigningProjection{
		MetricID: input.MetricId, Comparison: uint32(input.Comparison), ThresholdNumerator: input.ThresholdNumerator,
		ThresholdDenominator: input.ThresholdDenominator, UpperThresholdNumerator: optionalProjectionInt64(input.UpperThresholdNumerator),
		UpperThresholdDenominator: optionalProjectionUint64(input.UpperThresholdDenominator), Unit: input.Unit,
		PercentileBasisPoints: optionalProjectionUint32(input.PercentileBasisPoints), MinimumMetricSampleSize: input.MinimumMetricSampleSize,
	}, nil
}

func metricObservation(input *foundationv1.MetricObservation, name string) (foundationv1.MetricObservationSigningProjection, error) {
	if input == nil {
		return foundationv1.MetricObservationSigningProjection{}, missing(name)
	}
	return foundationv1.MetricObservationSigningProjection{
		MetricID: input.MetricId, ObservedNumerator: input.ObservedNumerator, ObservedDenominator: input.ObservedDenominator,
		SampleSize: input.SampleSize, ConfidenceLowerNumerator: input.ConfidenceLowerNumerator,
		ConfidenceLowerDenominator: input.ConfidenceLowerDenominator, ConfidenceUpperNumerator: input.ConfidenceUpperNumerator,
		ConfidenceUpperDenominator: input.ConfidenceUpperDenominator, CriterionPassed: input.CriterionPassed,
	}, nil
}

func projectionSchemaVersion(input *commonv1.SchemaVersion, name string, requireV1 bool) (foundationv1.SchemaVersionSigningProjection, error) {
	if input == nil {
		return foundationv1.SchemaVersionSigningProjection{}, missing(name)
	}
	if input.Major == 0 || (requireV1 && (input.Major != 1 || input.Minor != 0)) {
		return foundationv1.SchemaVersionSigningProjection{}, fmt.Errorf("%w: %s=%d.%d", ErrInvalidSchemaVersion, name, input.Major, input.Minor)
	}
	return foundationv1.SchemaVersionSigningProjection{Major: input.Major, Minor: input.Minor}, nil
}

func optionalProjectionString(input *string) foundationv1.OptionalString {
	if input == nil {
		return foundationv1.OptionalString{}
	}
	return foundationv1.OptionalString{Present: true, Value: *input}
}

func optionalProjectionInt64(input *int64) foundationv1.OptionalInt64 {
	if input == nil {
		return foundationv1.OptionalInt64{}
	}
	return foundationv1.OptionalInt64{Present: true, Value: *input}
}

func optionalProjectionUint64(input *uint64) foundationv1.OptionalUint64 {
	if input == nil {
		return foundationv1.OptionalUint64{}
	}
	return foundationv1.OptionalUint64{Present: true, Value: *input}
}

func optionalProjectionUint32(input *uint32) foundationv1.OptionalUint32 {
	if input == nil {
		return foundationv1.OptionalUint32{}
	}
	return foundationv1.OptionalUint32{Present: true, Value: *input}
}

func optionalProjectionFixed16(input []byte, name string) (foundationv1.OptionalFixedBytes16, error) {
	if input == nil {
		return foundationv1.OptionalFixedBytes16{}, nil
	}
	value, err := fixed16(input, name)
	if err != nil {
		return foundationv1.OptionalFixedBytes16{}, err
	}
	return foundationv1.OptionalFixedBytes16{Present: true, Value: value}, nil
}

func optionalProjectionFixed32(input []byte, name string) (foundationv1.OptionalFixedBytes32, error) {
	if input == nil {
		return foundationv1.OptionalFixedBytes32{}, nil
	}
	value, err := fixed32(input, name)
	if err != nil {
		return foundationv1.OptionalFixedBytes32{}, err
	}
	return foundationv1.OptionalFixedBytes32{Present: true, Value: value}, nil
}

func fixed32Set(input [][]byte, name string) ([][32]byte, error) {
	out := make([][32]byte, 0, len(input))
	for index, item := range input {
		value, err := fixed32(item, fmt.Sprintf("%s[%d]", name, index))
		if err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, nil
}
