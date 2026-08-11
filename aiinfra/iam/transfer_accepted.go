// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"bytes"
	"context"
	"fmt"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

type acceptedTransferValidation struct {
	Snapshot                AcceptedOwnershipTransferSnapshot
	Legacy                  OwnershipTransferSnapshot
	Dependencies            []SnapshotPrecondition
	AuthorityValidFromNano  int64
	AuthorityValidUntilNano int64
}

func (p *Planner) resolveAcceptedTransfer(ctx context.Context, evidence [32]byte,
	at int64) (acceptedTransferValidation, error) {
	if evidence == ([32]byte{}) || at < 0 {
		return acceptedTransferValidation{}, ErrTransferAuthorizationRequired
	}
	raw, found, err := p.view.LookupAcceptedOwnershipTransfer(ctx, evidence)
	if err != nil {
		return acceptedTransferValidation{}, fmt.Errorf("aiinfra iam: lookup accepted ownership transfer: %w", err)
	}
	if !found || preflightAcceptedTransfer(raw) != nil {
		return acceptedTransferValidation{}, ErrTransferAuthorizationRequired
	}
	snapshot := cloneAcceptedTransfer(raw)
	digest, err := acceptedTransferDigest(snapshot)
	if err != nil || digest != snapshot.SnapshotDigest || snapshot.TransferEvidenceDigest != evidence ||
		snapshot.AcceptedAtUnixNano > at || at < snapshot.Projection.EffectiveAtUnixNano ||
		at >= snapshot.Projection.ExpiresAtUnixNano ||
		snapshot.AcceptedAtUnixNano < snapshot.Profile.Activation.ValidFromUnixNano ||
		snapshot.AcceptedAtUnixNano >= snapshot.Profile.Activation.ValidUntilUnixNano {
		return acceptedTransferValidation{}, ErrTransferAuthorizationRequired
	}
	historicalProfile, err := p.profile.OwnershipTransferProfileAt(ctx,
		OwnershipTransferProfileHistoryRequest{ProfileID: snapshot.Profile.ProfileID,
			ProfileVersion: snapshot.Profile.ProfileVersion, SubjectKind: snapshot.Projection.SubjectKind,
			ProfileDigest:            snapshot.ProfileDigest,
			ActivationVersion:        snapshot.Profile.Activation.ActivationVersion,
			ActivationSnapshotDigest: snapshot.Profile.Activation.SnapshotDigest})
	historicalProfile, historicalDigest, historyErr := normalizeTransferProfile(
		historicalProfile, snapshot.Projection)
	if err != nil || historyErr != nil || historicalDigest != snapshot.ProfileDigest ||
		!sameTransferProfile(historicalProfile, snapshot.Profile) {
		return acceptedTransferValidation{}, ErrTransferAuthorizationRequired
	}
	auditEventID, err := idempotency.JoinedAuditEventID(snapshotBinding(snapshot))
	if err != nil {
		return acceptedTransferValidation{}, ErrTransferAuthorizationRequired
	}
	if _, err := p.transferCollectionIdentifierClaims(ctx, snapshot.Projection,
		snapshot.FixedEvidence, auditEventID, false); err != nil {
		return acceptedTransferValidation{}, ErrTransferAuthorizationRequired
	}
	// Profile activation is an acceptance-time fence. Once the authorization
	// row is durably accepted, cutover uses the retained activation evidence
	// and must not be stranded by a later profile-row retirement.
	dependencies := []SnapshotPrecondition{snapshot.Precondition()}
	historicalDependencies, err := p.revalidateAcceptedTransferSignatures(ctx, snapshot)
	if err != nil {
		return acceptedTransferValidation{}, err
	}
	dependencies = append(dependencies, historicalDependencies...)
	authorityValidFrom := snapshot.Projection.EffectiveAtUnixNano
	authorityValidUntil := snapshot.Projection.ExpiresAtUnixNano
	for _, requirement := range snapshot.Profile.NewAuthorities {
		approval, found := transferAdmissionByAuthority(snapshot.Approvals, requirement)
		if !found {
			return acceptedTransferValidation{}, ErrTransferAuthorizationRequired
		}
		current, currentErr := p.validateCurrentTransferAuthority(ctx, requirement,
			approval.Signed.record.Domain.IssuedAtUnixNano, at)
		if currentErr != nil {
			return acceptedTransferValidation{}, currentErr
		}
		dependencies = append(dependencies, current.Dependencies...)
		authorityValidFrom = maximumInt64(authorityValidFrom, current.ValidFromUnixNano)
		authorityValidUntil = minimumInt64(authorityValidUntil, current.ValidUntilUnixNano)
	}
	dependencies, err = canonicalPreconditions(dependencies)
	if err != nil {
		return acceptedTransferValidation{}, err
	}
	legacy := OwnershipTransferSnapshot{
		PreviousEntity: EntityRef{Kind: EntityIdentity, PrincipalKind: snapshot.Projection.SubjectKind,
			ID: snapshot.Projection.PreviousEntityID},
		NextEntity: EntityRef{Kind: EntityIdentity, PrincipalKind: snapshot.Projection.SubjectKind,
			ID: snapshot.Projection.NextEntityID},
		PreviousPrincipal:   snapshot.Projection.PreviousPrincipalIdentity,
		NextPrincipal:       snapshot.Projection.NextPrincipalIdentity,
		PreviousGeneration:  snapshot.Projection.ExpectedGeneration,
		NextGeneration:      snapshot.Projection.NextGeneration,
		CompletedAtUnixNano: snapshot.Projection.EffectiveAtUnixNano,
		EvidenceDigest:      evidence,
	}
	if at < authorityValidFrom || at >= authorityValidUntil {
		return acceptedTransferValidation{}, ErrTransferAuthorizationRequired
	}
	return acceptedTransferValidation{Snapshot: snapshot, Legacy: legacy, Dependencies: dependencies,
		AuthorityValidFromNano: authorityValidFrom, AuthorityValidUntilNano: authorityValidUntil}, nil
}

func (p *Planner) revalidateAcceptedTransferSignatures(ctx context.Context,
	snapshot AcceptedOwnershipTransferSnapshot) ([]SnapshotPrecondition, error) {
	dependencies := make([]SnapshotPrecondition, 0, len(snapshot.Approvals)+len(snapshot.FixedEvidence.EvidenceRecords))
	for _, approval := range snapshot.Approvals {
		dependency, approvalErr := p.revalidateRetainedTransferApproval(ctx, snapshot, approval)
		if approvalErr != nil {
			return nil, approvalErr
		}
		dependencies = append(dependencies, dependency)
	}
	commitments := make(map[[32]byte]uint32, len(snapshot.Projection.EvidenceCommitments))
	for _, commitment := range snapshot.Projection.EvidenceCommitments {
		commitments[commitment.CCSERecordDigestSHA256] = commitment.EvidenceKind
	}
	for _, retained := range snapshot.FixedEvidence.EvidenceRecords {
		kind, ok := commitments[retained.digest]
		if !ok {
			return nil, ErrTransferAuthorizationRequired
		}
		dependency, evidenceErr := p.revalidateRetainedTransferEvidence(ctx, snapshot,
			retained, kind)
		if evidenceErr != nil {
			return nil, evidenceErr
		}
		dependencies = append(dependencies, dependency)
	}
	return canonicalPreconditions(dependencies)
}

func (p *Planner) revalidateRetainedTransferApproval(ctx context.Context,
	snapshot AcceptedOwnershipTransferSnapshot,
	approval OwnershipTransferAuthorityAdmission) (SnapshotPrecondition, error) {
	authorization, err := authorizationFromSignedRecord(approval.Signed.record)
	if err != nil || authorization.recordDigest != approval.Signed.digest {
		return SnapshotPrecondition{}, ErrAuthorizationMismatch
	}
	receiver := cloneReceiverProfile(approval.Receiver)
	if validateReceiverProfile(receiver) != nil ||
		approval.AdmissionProfileDigest != snapshot.ProfileDigest ||
		approval.AdmissionActivationDigest != snapshot.Profile.Activation.SnapshotDigest {
		return SnapshotPrecondition{}, ErrAuthorizationMismatch
	}
	fingerprint, err := transferAuthorityAdmissionFingerprint(approval)
	if err != nil || fingerprint != approval.Fingerprint {
		return SnapshotPrecondition{}, ErrAuthorizationMismatch
	}
	requirement, oldSide, found := transferAuthorityRequirement(snapshot.Profile,
		authorization.senderIdentity, authorization.signatureKeyID)
	previous := EntityRef{Kind: EntityIdentity, PrincipalKind: snapshot.Projection.SubjectKind,
		ID: snapshot.Projection.PreviousEntityID}
	if !found || approval.Authority != requirement || approval.OldSide != oldSide ||
		!authorization.providerOrganization.Present ||
		authorization.providerOrganization.Value != requirement.OrganizationID ||
		!bytes.Equal(authorization.payload, snapshot.CanonicalPayload) ||
		validateRetainedAuthorizationDomain(authorization, receiver, previous,
			schema.MessageTypeOwnershipTransferAuthorization,
			snapshot.Projection.ExpectedGeneration, snapshot.Projection.Metadata.CreatedAtUnixNano,
			approval.ValidatedAtUnixNano) != nil {
		return SnapshotPrecondition{}, ErrAuthorizationMismatch
	}
	material, err := validateMaterialSnapshot(approval.Historical.Material)
	if err != nil || material.KeyID != requirement.KeyID ||
		material.SubjectIdentity != requirement.Identity || material.TargetIdentity.Kind != EntityIdentity ||
		material.EnrollmentDomain.EnrollmentDomainID != receiver.EnrollmentDomainID ||
		material.EnrollmentDomain.Environment != authorization.environment ||
		material.EnrollmentDomain.GenesisHash != authorization.genesisHash {
		return SnapshotPrecondition{}, ErrAuthorizationMismatch
	}
	lifecycle, err := normalizeViewLifecycle(approval.Historical.Lifecycle)
	if err != nil || lifecycle.KeyID != requirement.KeyID ||
		lifecycle.SubjectIdentity != requirement.Identity || (lifecycle.State != 2 && lifecycle.State != 3) ||
		lifecycle.RevokedAtUnixNano != 0 ||
		lifecycle.AuthorizationPolicyDigestSHA256 != requirement.AuthorizationPolicyDigestSHA256 ||
		authorization.issuedAtUnixNano < lifecycle.NotBeforeUnixNano ||
		authorization.expiresAtUnixNano > lifecycle.NotAfterUnixNano ||
		!containsUint32(lifecycle.AllowedMessageTypeIDs, schema.MessageTypeOwnershipTransferAuthorization) {
		return SnapshotPrecondition{}, ErrAuthorizationMismatch
	}
	identity, err := normalizeViewIdentity(approval.Historical.Identity)
	if err != nil || !sameEntityRef(identity.Ref, material.TargetIdentity) || identity.State != 2 ||
		identity.PrincipalIdentity != requirement.Identity || identity.KeyID != requirement.KeyID ||
		identity.CreatedAtUnixNano > authorization.issuedAtUnixNano ||
		authorization.issuedAtUnixNano < identity.ValidFromUnixNano ||
		authorization.expiresAtUnixNano > identity.ValidUntilUnixNano ||
		verifyAuthorizationWithMaterial(authorization, material.Algorithm,
			material.CanonicalPublicKey, material.KeyID) != nil {
		return SnapshotPrecondition{}, ErrAuthorizationMismatch
	}
	authoritative, err := p.resolveHistoricalTransferAuthority(ctx, requirement, authorization, receiver)
	if err != nil || !sameHistoricalAuthorization(authoritative, approval.Historical) {
		return SnapshotPrecondition{}, ErrAuthorizationMismatch
	}
	return materialPrecondition(material), nil
}

func sameHistoricalAuthorization(left, right HistoricalKeyAuthorizationSnapshot) bool {
	leftBytes, leftErr := canonicalHistoricalAuthorization(left)
	rightBytes, rightErr := canonicalHistoricalAuthorization(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func validateRetainedAuthorizationDomain(authorization VerifiedAuthorization,
	receiver ReceiverProfile, replayEntity EntityRef, messageTypeID uint32,
	expectedGeneration uint64, createdAt, validatedAt int64) error {
	expectedReplay, err := DeriveEntityReplayDomainID(receiver.ReplayDomainID, replayEntity)
	providerMismatch := receiver.ProviderOrganization != authorization.providerOrganization
	if messageTypeID == schema.MessageTypeOwnershipTransferAuthorization {
		providerMismatch = receiver.ProviderOrganization.Present &&
			receiver.ProviderOrganization != authorization.providerOrganization
	}
	if err != nil || validateAudienceSet(authorization.audience) != nil ||
		authorization.messageTypeID != messageTypeID ||
		authorization.schemaVersion != (ccse.Version{Major: 1}) || authorization.messageID == ([16]byte{}) ||
		createdAt < 0 || createdAt > authorization.issuedAtUnixNano ||
		authorization.issuedAtUnixNano > validatedAt || validatedAt >= authorization.expiresAtUnixNano ||
		authorization.expiresAtUnixNano-authorization.issuedAtUnixNano > receiver.MaxValidityWindowNanos ||
		receiver.ProtocolVersion != authorization.protocolVersion || receiver.SchemaVersion != authorization.schemaVersion ||
		receiver.Purpose != authorization.purpose || !sameStringSet(receiver.Audience, authorization.audience) ||
		receiver.TenantOrganization != authorization.tenantOrganization ||
		providerMismatch ||
		receiver.Environment != authorization.environment || receiver.ChainID != authorization.chainID ||
		receiver.GenesisHash != authorization.genesisHash || expectedReplay != authorization.replayDomainID ||
		receiver.CounterKind != ccse.CounterExpectedGeneration ||
		authorization.counterKind != ccse.CounterExpectedGeneration || authorization.counter != expectedGeneration {
		return ErrAuthorizationMismatch
	}
	return nil
}

func (p *Planner) revalidateRetainedTransferEvidence(ctx context.Context,
	snapshot AcceptedOwnershipTransferSnapshot, retained RetainedVerifiedRecord,
	evidenceKind uint32) (SnapshotPrecondition, error) {
	admission, found := transferEvidenceAdmissionByDigest(snapshot.FixedEvidence.EvidenceAdmissions,
		retained.digest)
	if !found || admission.EvidenceKind != evidenceKind ||
		admission.ProfileDigest != snapshot.ProfileDigest ||
		admission.ActivationDigest != snapshot.Profile.Activation.SnapshotDigest {
		return SnapshotPrecondition{}, ErrTransferAuthorizationRequired
	}
	decision, err := transferEvidencePolicyDecisionDigest(snapshot.Projection,
		snapshot.TransferEvidenceDigest, admission)
	if err != nil || decision != admission.PolicyDecisionDigest {
		return SnapshotPrecondition{}, ErrTransferAuthorizationRequired
	}
	fingerprint, err := transferEvidenceAdmissionFingerprint(admission)
	if err != nil || fingerprint != admission.Fingerprint {
		return SnapshotPrecondition{}, ErrTransferAuthorizationRequired
	}
	authorization, err := authorizationFromSignedRecord(retained.record)
	if err != nil || authorization.recordDigest != retained.digest ||
		authorization.messageTypeID != schema.MessageTypeEvidenceRecord {
		return SnapshotPrecondition{}, ErrAuthorizationMismatch
	}
	validator, err := foundationCanonicalValidator()
	if err != nil {
		return SnapshotPrecondition{}, err
	}
	decoded, err := validator.Decode(schema.MessageTypeEvidenceRecord,
		ccse.Version{Major: 1}, authorization.payload)
	projection, ok := decoded.(foundationv1.EvidenceRecordSigningProjection)
	if err != nil || !ok || projection.EvidenceID == "" {
		return SnapshotPrecondition{}, ErrAuthorizationMismatch
	}
	receiver := cloneReceiverProfile(admission.Receiver)
	if validateReceiverProfile(receiver) != nil ||
		validateRetainedAuthorizationDomain(authorization, receiver,
			EntityRef{Kind: EntityIdentity, PrincipalKind: 8, ID: projection.EvidenceID},
			schema.MessageTypeEvidenceRecord, projection.Metadata.StateVersion,
			projection.Metadata.CreatedAtUnixNano, snapshot.AcceptedAtUnixNano) != nil {
		return SnapshotPrecondition{}, ErrAuthorizationMismatch
	}
	authoritative, err := p.resolveHistoricalEvidenceAuthorization(ctx, authorization, receiver)
	if err != nil || !sameHistoricalAuthorization(authoritative, admission.Historical) {
		return SnapshotPrecondition{}, ErrAuthorizationMismatch
	}
	return materialPrecondition(authoritative.Material), nil
}

func transferEvidenceAdmissionByDigest(values []OwnershipTransferEvidenceAdmission,
	digest [32]byte) (OwnershipTransferEvidenceAdmission, bool) {
	for _, value := range values {
		if value.RecordDigest == digest {
			return cloneTransferEvidenceAdmission(value), true
		}
	}
	return OwnershipTransferEvidenceAdmission{}, false
}

func snapshotBinding(snapshot AcceptedOwnershipTransferSnapshot) idempotency.Binding {
	return idempotency.Binding{Key: snapshot.Projection.Metadata.IdempotencyKey,
		Domain:        idempotency.OperationIAMOwnershipTransfer,
		OwnerID:       snapshot.Projection.TransferAuthorizationID,
		RequestDigest: snapshot.TransferEvidenceDigest}
}

func preflightAcceptedTransfer(snapshot AcceptedOwnershipTransferSnapshot) error {
	return preflightTransferSnapshot(snapshot.Profile, snapshot.Approvals,
		snapshot.FixedEvidence, snapshot.CanonicalPayload)
}

func transferAdmissionByAuthority(approvals []OwnershipTransferAuthorityAdmission,
	requirement OwnershipTransferAuthorityRequirement) (OwnershipTransferAuthorityAdmission, bool) {
	for _, approval := range approvals {
		if approval.Authority == requirement {
			return cloneTransferAdmission(approval), true
		}
	}
	return OwnershipTransferAuthorityAdmission{}, false
}

type acceptedTransferOverlayView struct {
	View
	digest [32]byte
	legacy OwnershipTransferSnapshot
}

func (view *acceptedTransferOverlayView) LookupOwnershipTransfer(ctx context.Context,
	digest [32]byte) (OwnershipTransferSnapshot, bool, error) {
	if digest == view.digest {
		return view.legacy, true, nil
	}
	return view.View.LookupOwnershipTransfer(ctx, digest)
}

func acceptedTransferMatchesKeyEnrollment(validation acceptedTransferValidation,
	command KeyEnrollmentCommand) bool {
	projection := validation.Snapshot.Projection
	return command.Material.TransferEvidenceDigest == validation.Snapshot.TransferEvidenceDigest &&
		command.Lifecycle.TransferEvidenceDigest == validation.Snapshot.TransferEvidenceDigest &&
		command.Material.ClaimedKeyID == projection.NewKeyID &&
		command.Material.SubjectKind == projection.SubjectKind &&
		command.Material.SubjectIdentity == projection.NextPrincipalIdentity &&
		sameEntityRef(command.Material.TargetIdentity, validation.Legacy.NextEntity)
}

func acceptedTransferMatchesIdentity(validation acceptedTransferValidation,
	identity IdentitySnapshot) bool {
	snapshot := validation.Snapshot
	digest := sha256Bytes(identity.CanonicalPayload)
	switch {
	case digest == snapshot.Projection.PreviousTerminalIdentityPayloadDigestSHA256:
		return bytes.Equal(identity.CanonicalPayload, snapshot.FixedEvidence.PreviousTerminalIdentity.CanonicalPayload)
	case digest == snapshot.Projection.NextPendingIdentityPayloadDigestSHA256:
		return bytes.Equal(identity.CanonicalPayload, snapshot.FixedEvidence.NextPendingIdentity.CanonicalPayload)
	default:
		return false
	}
}

func acceptedTransferMatchesLifecycle(validation acceptedTransferValidation,
	lifecycle KeyLifecycleSnapshot) bool {
	for _, expected := range validation.Snapshot.FixedEvidence.KeyClosureSnapshots {
		if lifecycle.KeyID == expected.KeyID && bytes.Equal(lifecycle.CanonicalPayload, expected.CanonicalPayload) {
			return true
		}
	}
	return false
}

func appendAcceptedTransferDependencies(cas CASIntent,
	validation acceptedTransferValidation) (CASIntent, error) {
	cas.Dependencies = append(cas.Dependencies, validation.Dependencies...)
	dependencies, err := canonicalPreconditions(cas.Dependencies)
	if err != nil {
		return CASIntent{}, err
	}
	cas.Dependencies = dependencies
	return cas, nil
}

func appendAcceptedTransferAuditEvidence(audit AuditIntent,
	validation acceptedTransferValidation) (AuditIntent, error) {
	source := auditSourceEvidence{Present: audit.hasSourceAuthorization, ActorKeyID: audit.actorKeyID,
		Record: cloneCCSERecord(audit.sourceAuthorizationRecord), Digest: audit.sourceAuthorizationDigest,
		CausationID: audit.sourceCausationID}
	evidence := append(audit.EvidenceDigestsSHA256(), validation.Snapshot.SnapshotDigest,
		validation.Snapshot.ProfileDigest)
	evidence = uniqueDigests(evidence)
	return newAuditIntent(audit.auditEventID, audit.eventType, audit.actorIdentity, audit.subjectIDs,
		audit.causeCode, audit.correlationID, audit.causationID, audit.messageID, audit.idempotencyKey,
		audit.expectedAuditIdempotencyKey, source, audit.occurredAtUnixNano,
		audit.policyDigestsSHA256, evidence)
}

func bindAcceptedTransferMutation(mutation MutationPlan, audit AuditIntent,
	validation acceptedTransferValidation) (PendingMutationPlan, error) {
	cas, err := appendAcceptedTransferDependencies(mutation.CAS(), validation)
	if err != nil {
		return PendingMutationPlan{}, err
	}
	window := planWindow{EvaluatedAtUnixNano: mutation.EvaluatedAtUnixNano(),
		CommitNotBeforeUnixNano: maximumInt64(mutation.CommitNotBeforeUnixNano(),
			validation.AuthorityValidFromNano),
		CommitNotAfterUnixNano: minimumInt64(mutation.CommitNotAfterUnixNano(),
			validation.AuthorityValidUntilNano)}
	if window.CommitNotBeforeUnixNano >= window.CommitNotAfterUnixNano {
		return PendingMutationPlan{}, ErrInvalidCommitWindow
	}
	switch mutation.Kind() {
	case MutationAppendIdentity:
		value, ok := mutation.Identity()
		if !ok {
			return PendingMutationPlan{}, ErrPendingPlanInvalid
		}
		mutation, err = newIdentityPlan(cas, value, window)
	case MutationAppendKeyLifecycle:
		value, ok := mutation.KeyLifecycle()
		if !ok {
			return PendingMutationPlan{}, ErrPendingPlanInvalid
		}
		mutation, err = newLifecyclePlan(cas, value, window)
	default:
		return PendingMutationPlan{}, ErrPendingPlanInvalid
	}
	if err != nil {
		return PendingMutationPlan{}, err
	}
	audit, err = appendAcceptedTransferAuditEvidence(audit, validation)
	if err != nil {
		return PendingMutationPlan{}, err
	}
	return newPendingMutationPlan(mutation, audit)
}

func bindAcceptedKeyEnrollment(plan PendingKeyEnrollmentPlan,
	validation acceptedTransferValidation) (PendingKeyEnrollmentPlan, error) {
	materialCAS, err := appendAcceptedTransferDependencies(plan.material.CAS(), validation)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	lifecycleCAS, err := appendAcceptedTransferDependencies(plan.lifecycle.CAS(), validation)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	commitNotBefore := maximumInt64(plan.commitNotBeforeUnixNano,
		validation.AuthorityValidFromNano)
	commitNotAfter := minimumInt64(plan.commitNotAfterUnixNano,
		validation.AuthorityValidUntilNano)
	if commitNotBefore >= commitNotAfter {
		return PendingKeyEnrollmentPlan{}, ErrInvalidCommitWindow
	}
	material, materialOK := plan.material.KeyMaterial()
	lifecycle, lifecycleOK := plan.lifecycle.KeyLifecycle()
	if !materialOK || !lifecycleOK {
		return PendingKeyEnrollmentPlan{}, ErrPendingPlanInvalid
	}
	window := planWindow{EvaluatedAtUnixNano: plan.evaluatedAtUnixNano,
		CommitNotBeforeUnixNano: commitNotBefore, CommitNotAfterUnixNano: commitNotAfter}
	materialPlan, err := newMaterialPlan(materialCAS, material, window)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	lifecyclePlan, err := newLifecyclePlan(lifecycleCAS, lifecycle, window)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	audit, err := appendAcceptedTransferAuditEvidence(plan.audit, validation)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	mutationDigest, err := keyEnrollmentMutationCoreDigest(materialPlan, lifecyclePlan)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	core := pendingCoreEvidenceDigest(mutationDigest, audit.Digest())
	parent, joined, err := pendingIdempotencyBindings(plan.admission.idempotencyReservations)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	reservations, err := pendingIdempotencyClaimsBound(parent, joined, audit.Digest(), core)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	completion, err := pendingCompletionClaims(reservations)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	admission, err := newPendingAdmissionIntent(plan.admission.identifierReservations, reservations,
		core, plan.evaluatedAtUnixNano, commitNotBefore, commitNotAfter)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	result := PendingKeyEnrollmentPlan{material: materialPlan, lifecycle: lifecyclePlan, audit: audit,
		evaluatedAtUnixNano: plan.evaluatedAtUnixNano, commitNotBeforeUnixNano: commitNotBefore,
		commitNotAfterUnixNano: commitNotAfter, admission: admission,
		idempotencyCompletion: completion}
	result.digest, err = keyEnrollmentPlanDigest(result)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	if err := result.VerifyDigest(); err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	return result, nil
}

func transferOverlayPlanner(planner *Planner, validation acceptedTransferValidation) *Planner {
	copy := *planner
	copy.view = &acceptedTransferOverlayView{View: planner.view,
		digest: validation.Snapshot.TransferEvidenceDigest, legacy: validation.Legacy}
	return &copy
}

func collectingSnapshot(binding idempotency.Binding, version uint64, progress [32]byte) idempotency.Snapshot {
	return idempotency.Snapshot{Binding: binding, State: idempotency.StateCollecting,
		Version: version, ProgressDigest: progress}
}
