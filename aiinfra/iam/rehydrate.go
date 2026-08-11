// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

// RevalidateDurablePending upgrades inert decoded storage bytes into an
// in-process capability only after rechecking their signed semantic source,
// current COLLECTING X/Y pair, admitted global IDs, writer lease and mutation
// state through this Planner's authoritative View/Profile. Hash self-
// consistency alone is intentionally insufficient.
func (p *Planner) RevalidateDurablePending(ctx context.Context,
	decoded DecodedDurablePendingEnvelope, atUnixNano int64) (DurablePendingEnvelope, error) {
	if err := p.ready(); err != nil {
		return DurablePendingEnvelope{}, err
	}
	if err := ctx.Err(); err != nil {
		return DurablePendingEnvelope{}, err
	}
	if atUnixNano < 0 || len(decoded.encoded) == 0 ||
		domainDigest(durablePendingEnvelopeDigestDomain, decoded.encoded) != decoded.digest {
		return DurablePendingEnvelope{}, ErrPendingPlanInvalid
	}
	envelope, err := decodeDurablePendingEnvelope(decoded.encoded)
	if err != nil || envelope.kind != decoded.kind || envelope.digest != decoded.digest {
		return DurablePendingEnvelope{}, ErrPendingPlanInvalid
	}
	// Kind 4 is written only by the terminal audited-final transaction. It is
	// never an OPEN pending admission and therefore never reissues a commit
	// capability. Reload verifies the completed X/Y/member outcome and returns
	// the stored result even after the reconciliation's signing window.
	if envelope.kind == DurablePendingReconciliation {
		if err := p.revalidateReconciliation(ctx, *envelope.reconciliation, atUnixNano); err != nil {
			return DurablePendingEnvelope{}, err
		}
		return DurablePendingEnvelope{}, ErrPendingPlanInvalid
	}
	evaluatedAt, commitNotBefore, commitNotAfter, err := durableEnvelopeFullWindow(envelope)
	if err != nil || atUnixNano < commitNotBefore || atUnixNano >= commitNotAfter || evaluatedAt > atUnixNano {
		return DurablePendingEnvelope{}, ErrInvalidCommitWindow
	}

	switch envelope.kind {
	case DurablePendingMutation:
		err = p.revalidatePendingMutation(ctx, *envelope.mutation, atUnixNano, decoded.encoded)
	case DurablePendingKeyEnrollment:
		err = p.revalidatePendingEnrollment(ctx, *envelope.enrollment, atUnixNano, decoded.encoded)
	case DurablePendingOwnershipTransferCollection:
		err = p.revalidateTransferCollection(ctx, *envelope.transfer, atUnixNano)
	case DurablePendingOwnershipTransferCutover:
		err = p.revalidateAcceptedCutover(ctx, *envelope.cutover, atUnixNano, decoded.encoded)
	default:
		err = ErrPendingPlanInvalid
	}
	if err != nil {
		return DurablePendingEnvelope{}, err
	}
	envelope.capability = true
	return envelope, nil
}

// PlanReconciliationFromDecoded is the terminal-only recovery path for an
// admitted cutover whose success window has closed. It never returns a
// success-capable DurablePendingEnvelope. Instead it rechecks the exact stored
// X/Y/member/global admission, reconstructs the original plan at its trusted
// admission time, and emits only a no-business-write reconciliation plan.
func (p *Planner) PlanReconciliationFromDecoded(ctx context.Context,
	decoded DecodedDurablePendingEnvelope,
	command PendingReconciliationCommand) (PendingReconciliationPlan, error) {
	if err := p.ready(); err != nil {
		return PendingReconciliationPlan{}, err
	}
	if err := ctx.Err(); err != nil {
		return PendingReconciliationPlan{}, err
	}
	if command.EvaluatedAtUnixNano < 0 || len(decoded.encoded) == 0 ||
		domainDigest(durablePendingEnvelopeDigestDomain, decoded.encoded) != decoded.digest {
		return PendingReconciliationPlan{}, ErrPendingPlanInvalid
	}
	envelope, err := decodeDurablePendingEnvelope(decoded.encoded)
	if err != nil || envelope.kind != decoded.kind || envelope.digest != decoded.digest {
		return PendingReconciliationPlan{}, ErrPendingPlanInvalid
	}
	switch envelope.kind {
	case DurablePendingMutation:
		if envelope.mutation == nil || command.EvaluatedAtUnixNano < envelope.mutation.CommitNotAfterUnixNano() {
			return PendingReconciliationPlan{}, ErrInvalidCommitWindow
		}
		if err := p.revalidatePendingMutation(ctx, *envelope.mutation,
			envelope.mutation.EvaluatedAtUnixNano(), decoded.encoded); err != nil {
			return PendingReconciliationPlan{}, err
		}
		envelope.capability = true
		return envelope.mutation.PlanReconciliation(command)
	case DurablePendingKeyEnrollment:
		if envelope.enrollment == nil || command.EvaluatedAtUnixNano < envelope.enrollment.CommitNotAfterUnixNano() {
			return PendingReconciliationPlan{}, ErrInvalidCommitWindow
		}
		if err := p.revalidatePendingEnrollment(ctx, *envelope.enrollment,
			envelope.enrollment.EvaluatedAtUnixNano(), decoded.encoded); err != nil {
			return PendingReconciliationPlan{}, err
		}
		envelope.capability = true
		return envelope.enrollment.PlanReconciliation(command)
	case DurablePendingOwnershipTransferCollection:
		if envelope.transfer == nil || command.EvaluatedAtUnixNano < envelope.transfer.CommitNotAfterUnixNano() {
			return PendingReconciliationPlan{}, ErrInvalidCommitWindow
		}
		if err := p.revalidateStoredTransferCollection(ctx, *envelope.transfer); err != nil {
			return PendingReconciliationPlan{}, err
		}
		envelope.capability = true
		return reconcileTransferCollection(*envelope.transfer, command, decoded.encoded)
	case DurablePendingOwnershipTransferCutover:
		if envelope.cutover == nil || command.EvaluatedAtUnixNano < envelope.cutover.CommitNotAfterUnixNano() {
			return PendingReconciliationPlan{}, ErrInvalidCommitWindow
		}
		// Terminal recovery intentionally does not reuse the success-resume path.
		// A changed business row, consumed/expired challenge, retired writer lease,
		// or rotated current authority can be the reason the cutover missed its
		// deadline. Requiring those current conditions here would strand the
		// admitted X/Y/member rows forever. Recheck only immutable admission and
		// historical authorization evidence before producing a no-write failure.
		if err := p.revalidateAcceptedCutoverForReconciliation(ctx, *envelope.cutover,
			decoded.encoded); err != nil {
			return PendingReconciliationPlan{}, err
		}
		envelope.capability = true
		return envelope.PlanReconciliation(command)
	default:
		return PendingReconciliationPlan{}, ErrPendingPlanInvalid
	}
}

// revalidateAcceptedCutoverForReconciliation proves that a stored cutover was
// genuinely admitted without requiring the success pre-state to remain true.
// It is deliberately narrower than revalidateAcceptedCutover: no current
// business row, challenge, writer lease, or new-authority ACTIVE check occurs
// on this terminal-only path.
func (p *Planner) revalidateAcceptedCutoverForReconciliation(ctx context.Context,
	plan PendingOwnershipTransferCutoverPlan, original []byte) error {
	if plan.VerifyDigest() != nil || len(original) == 0 {
		return ErrPendingPlanInvalid
	}
	if err := p.validateStoredCutoverAdmission(ctx, plan); err != nil {
		return err
	}
	raw, found, err := p.view.LookupAcceptedOwnershipTransfer(ctx,
		plan.accepted.TransferEvidenceDigest)
	if err != nil || !found || preflightAcceptedTransfer(raw) != nil {
		return ErrTransferAuthorizationRequired
	}
	stored := cloneAcceptedTransfer(raw)
	storedDigest, err := acceptedTransferDigest(stored)
	if err != nil || storedDigest != stored.SnapshotDigest ||
		stored.SnapshotDigest != plan.accepted.SnapshotDigest ||
		stored.TransferEvidenceDigest != plan.accepted.TransferEvidenceDigest ||
		stored.AcceptedAtUnixNano > plan.evaluatedAtUnixNano ||
		stored.AcceptedAtUnixNano < stored.Profile.Activation.ValidFromUnixNano ||
		stored.AcceptedAtUnixNano >= stored.Profile.Activation.ValidUntilUnixNano ||
		stored.AcceptedAtUnixNano < stored.Projection.EffectiveAtUnixNano ||
		stored.AcceptedAtUnixNano >= stored.Projection.ExpiresAtUnixNano {
		return ErrTransferAuthorizationRequired
	}
	historicalProfile, err := p.profile.OwnershipTransferProfileAt(ctx,
		OwnershipTransferProfileHistoryRequest{ProfileID: stored.Profile.ProfileID,
			ProfileVersion: stored.Profile.ProfileVersion, SubjectKind: stored.Projection.SubjectKind,
			ProfileDigest:            stored.ProfileDigest,
			ActivationVersion:        stored.Profile.Activation.ActivationVersion,
			ActivationSnapshotDigest: stored.Profile.Activation.SnapshotDigest})
	historicalProfile, historicalDigest, historyErr := normalizeTransferProfile(
		historicalProfile, stored.Projection)
	if err != nil || historyErr != nil || historicalDigest != stored.ProfileDigest ||
		!sameTransferProfile(historicalProfile, stored.Profile) {
		return ErrTransferAuthorizationRequired
	}
	historicalDependencies, err := p.revalidateAcceptedTransferSignatures(ctx, stored)
	if err != nil {
		return err
	}
	if err := p.revalidateHistoricalAcceptanceEvidencePolicy(ctx, stored.Projection,
		stored.TransferEvidenceDigest, OwnershipTransferApprovalCollectionSnapshot{
			CanonicalPayload: stored.CanonicalPayload, TransferEvidenceDigest: stored.TransferEvidenceDigest,
			Profile: stored.Profile, ProfileDigest: stored.ProfileDigest, Approvals: stored.Approvals,
			FixedEvidence: stored.FixedEvidence}, stored.AcceptedAtUnixNano); err != nil {
		return err
	}
	for _, dependency := range append(historicalDependencies, stored.Precondition()) {
		if !containsSnapshotPrecondition(plan.dependencies, dependency) {
			return ErrPendingPlanInvalid
		}
	}
	if err := p.revalidateHistoricalCutoverSources(ctx, plan); err != nil {
		return err
	}
	derived, err := durableEnvelopeForAcceptedCutover(plan)
	if err != nil || !bytes.Equal(derived.encoded, original) {
		return ErrPendingPlanInvalid
	}
	return nil
}

func containsSnapshotPrecondition(values []SnapshotPrecondition, expected SnapshotPrecondition) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

// revalidateHistoricalCutoverSources independently verifies every signed
// component record against immutable material and the lifecycle/identity rows
// that were active at admission. It does not consult their current heads.
func (p *Planner) revalidateHistoricalCutoverSources(ctx context.Context,
	plan PendingOwnershipTransferCutoverPlan) error {
	for _, step := range plan.steps {
		if step.Kind == CutoverCreateNextKeyMaterial {
			continue
		}
		record, found := cutoverAuthorizationRecord(plan, step.Mutation.CAS().AuthorizationDigest)
		if !found {
			return ErrAuthorizationMismatch
		}
		authorization, err := authorizationFromSignedRecord(record)
		if err != nil || authorization.issuedAtUnixNano > plan.evaluatedAtUnixNano ||
			plan.evaluatedAtUnixNano >= authorization.expiresAtUnixNano {
			return ErrAuthorizationMismatch
		}
		var messageTypeID uint32
		var payload []byte
		switch step.Mutation.Kind() {
		case MutationAppendIdentity:
			identity, ok := step.Mutation.Identity()
			if !ok {
				return ErrPendingPlanInvalid
			}
			messageTypeID, payload = identity.MessageTypeID, identity.CanonicalPayload
		case MutationAppendKeyLifecycle:
			lifecycle, ok := step.Mutation.KeyLifecycle()
			if !ok {
				return ErrPendingPlanInvalid
			}
			messageTypeID, payload = schema.MessageTypeKeyLifecycle, lifecycle.CanonicalPayload
		default:
			return ErrPendingPlanInvalid
		}
		if authorization.messageTypeID != messageTypeID || !bytes.Equal(authorization.payload, payload) {
			return ErrAuthorizationMismatch
		}
		material, materialFound, lookupErr := p.view.LookupKeyMaterial(ctx,
			authorization.signatureKeyID)
		if lookupErr != nil || !materialFound {
			return ErrKeyMaterialUnknown
		}
		material, err = validateMaterialSnapshot(material)
		if err != nil || material.KeyID != authorization.signatureKeyID ||
			material.SubjectIdentity != authorization.senderIdentity {
			return ErrAuthorizationMismatch
		}
		lifecycle, lifecycleFound, lookupErr := p.view.LookupKeyLifecycleAt(ctx,
			material.KeyID, plan.evaluatedAtUnixNano)
		if lookupErr != nil || !lifecycleFound {
			return ErrLifecycleUnknown
		}
		lifecycle, err = normalizeViewLifecycle(lifecycle)
		if err != nil || lifecycle.KeyID != material.KeyID ||
			lifecycle.SubjectIdentity != material.SubjectIdentity ||
			lifecycle.SubjectKind != material.SubjectKind || lifecycle.Algorithm != material.Algorithm ||
			(lifecycle.State != 2 && lifecycle.State != 3) || lifecycle.RevokedAtUnixNano != 0 ||
			authorization.issuedAtUnixNano < lifecycle.NotBeforeUnixNano ||
			authorization.expiresAtUnixNano > lifecycle.NotAfterUnixNano ||
			plan.evaluatedAtUnixNano < lifecycle.NotBeforeUnixNano ||
			plan.evaluatedAtUnixNano >= lifecycle.NotAfterUnixNano ||
			!containsUint32(lifecycle.AllowedMessageTypeIDs, messageTypeID) {
			return ErrAuthorizationMismatch
		}
		identity, identityFound, lookupErr := p.view.LookupIdentityAt(ctx,
			material.TargetIdentity, plan.evaluatedAtUnixNano)
		if lookupErr != nil || !identityFound {
			return ErrIdentityUnknown
		}
		identity, err = normalizeViewIdentity(identity)
		if err != nil || !sameEntityRef(identity.Ref, material.TargetIdentity) || identity.State != 2 ||
			identity.PrincipalIdentity != material.SubjectIdentity || identity.KeyID != material.KeyID ||
			identity.CreatedAtUnixNano > authorization.issuedAtUnixNano ||
			authorization.issuedAtUnixNano < identity.ValidFromUnixNano ||
			authorization.expiresAtUnixNano > identity.ValidUntilUnixNano ||
			plan.evaluatedAtUnixNano < identity.ValidFromUnixNano ||
			plan.evaluatedAtUnixNano >= identity.ValidUntilUnixNano ||
			verifyAuthorizationWithMaterial(authorization, material.Algorithm,
				material.CanonicalPublicKey, material.KeyID) != nil {
			return ErrAuthorizationMismatch
		}
		for _, dependency := range []SnapshotPrecondition{
			lifecyclePrecondition(lifecycle), identityPrecondition(identity),
		} {
			if !containsSnapshotPrecondition(plan.dependencies, dependency) {
				return ErrPendingPlanInvalid
			}
		}
	}
	return nil
}

func (p *Planner) revalidateStoredTransferCollection(ctx context.Context,
	plan OwnershipTransferApprovalCollectionPlan) error {
	if plan.VerifyDigest() != nil || len(plan.next.Approvals) == 0 {
		return ErrPendingPlanInvalid
	}
	stored, found, err := p.view.SnapshotOwnershipTransferApprovalCollection(ctx, plan.next.Binding.Key)
	if err != nil || !found || preflightTransferCollection(stored) != nil {
		return ErrTransferCollectionMismatch
	}
	stored = cloneTransferCollection(stored)
	storedDigest, err := transferCollectionDigest(stored)
	if err != nil || storedDigest != stored.ProgressDigest || stored.ProgressDigest != plan.next.ProgressDigest ||
		stored.Version != plan.next.Version || !sameTransferCollectionSnapshot(stored, plan.next) {
		return ErrTransferCollectionMismatch
	}
	joinedBinding, err := idempotency.JoinedAuditBinding(plan.next.Binding)
	if err != nil {
		return ErrPendingPlanInvalid
	}
	parent, parentFound, joined, joinedFound, err := p.view.SnapshotBusinessIdempotencyPair(
		ctx, plan.next.Binding.Key, joinedBinding.Key)
	if err != nil || !parentFound || !joinedFound ||
		parent != (idempotency.Snapshot{Binding: plan.next.Binding, State: idempotency.StateCollecting,
			Version: plan.next.Version, ProgressDigest: plan.next.ProgressDigest}) {
		return ErrPendingPlanInvalid
	}
	expectedJoined := plan.joinedAuditSnapshot
	if plan.disposition == OwnershipTransferCollectionAppend {
		parentDigest, digestErr := idempotency.BindingDigest(plan.next.Binding)
		if digestErr != nil {
			return digestErr
		}
		expectedJoined = idempotency.Snapshot{Binding: joinedBinding, State: idempotency.StateCollecting,
			Version: 1, ProgressDigest: parentDigest}
	}
	if joined != expectedJoined {
		return ErrPendingPlanInvalid
	}
	for _, claim := range plan.identifierClaims {
		snapshot, found, lookupErr := p.view.LookupGlobalID(ctx, claim.Identifier)
		if lookupErr != nil || !found || snapshot.Identifier != claim.Identifier ||
			snapshot.Owner != claim.Owner || snapshot.Version != claim.NextVersion {
			return ErrPendingPlanInvalid
		}
	}
	projection, _, _, err := normalizeOwnershipTransferPayload(plan.next.CanonicalPayload)
	if err != nil {
		return err
	}
	historicalProfile, err := p.profile.OwnershipTransferProfileAt(ctx,
		OwnershipTransferProfileHistoryRequest{ProfileID: plan.next.Profile.ProfileID,
			ProfileVersion: plan.next.Profile.ProfileVersion, SubjectKind: projection.SubjectKind,
			ProfileDigest:            plan.next.ProfileDigest,
			ActivationVersion:        plan.next.Profile.Activation.ActivationVersion,
			ActivationSnapshotDigest: plan.next.Profile.Activation.SnapshotDigest})
	historicalProfile, profileDigest, profileErr := normalizeTransferProfile(historicalProfile, projection)
	if err != nil || profileErr != nil || profileDigest != plan.next.ProfileDigest ||
		!sameTransferProfile(historicalProfile, plan.next.Profile) {
		return ErrTransferAuthorizationRequired
	}
	candidate := AcceptedOwnershipTransferSnapshot{Projection: projection,
		CanonicalPayload:       append([]byte(nil), plan.next.CanonicalPayload...),
		TransferEvidenceDigest: plan.next.TransferEvidenceDigest,
		Profile:                cloneTransferProfile(plan.next.Profile), ProfileDigest: plan.next.ProfileDigest,
		Approvals:          cloneTransferCollection(plan.next).Approvals,
		FixedEvidence:      cloneTransferFixedEvidence(plan.next.FixedEvidence),
		AcceptedAtUnixNano: plan.evaluatedAtUnixNano, StateVersion: plan.next.Version,
		WriterEpoch: plan.next.WriterEpoch}
	if _, err := p.revalidateAcceptedTransferSignatures(ctx, candidate); err != nil {
		return err
	}
	if err := p.revalidateHistoricalAcceptanceEvidencePolicy(ctx, projection,
		plan.next.TransferEvidenceDigest, plan.next, plan.evaluatedAtUnixNano); err != nil {
		return err
	}
	entity := EntityRef{Kind: EntityOwnershipTransfer, PrincipalKind: projection.SubjectKind,
		ID: projection.TransferAuthorizationID}
	lease, leaseFound, err := p.view.LookupWriterLease(ctx, entity)
	if err != nil || !leaseFound || lease.Entity != entity || lease.HomeRegion != plan.next.HomeRegion ||
		lease.WriterEpoch != plan.authorizedWriterEpoch || lease.EvidenceDigest != plan.writerEvidenceDigest ||
		plan.evaluatedAtUnixNano < lease.ValidFromUnixNano || plan.evaluatedAtUnixNano >= lease.ValidUntilUnixNano {
		return ErrWriterFenceMismatch
	}
	return nil
}

func (p *Planner) revalidateHistoricalAcceptanceEvidencePolicy(ctx context.Context,
	projection foundationv1.OwnershipTransferAuthorizationSigningProjection,
	transferDigest [32]byte, collection OwnershipTransferApprovalCollectionSnapshot,
	validatedAt int64) error {
	commitments := make(map[[32]byte]uint32, len(projection.EvidenceCommitments))
	for _, commitment := range projection.EvidenceCommitments {
		if _, duplicate := commitments[commitment.CCSERecordDigestSHA256]; duplicate {
			return ErrTransferAuthorizationRequired
		}
		commitments[commitment.CCSERecordDigestSHA256] = commitment.EvidenceKind
	}
	if len(commitments) != len(collection.FixedEvidence.EvidenceRecords) ||
		len(collection.FixedEvidence.EvidenceAdmissions) != len(collection.FixedEvidence.EvidenceRecords) {
		return ErrTransferAuthorizationRequired
	}
	for _, retained := range collection.FixedEvidence.EvidenceRecords {
		kind, found := commitments[retained.digest]
		admission, admissionFound := transferEvidenceAdmissionByDigest(
			collection.FixedEvidence.EvidenceAdmissions, retained.digest)
		if !found || !admissionFound || admission.EvidenceKind != kind ||
			admission.ValidatedAtUnixNano < collection.Profile.Activation.ValidFromUnixNano ||
			admission.ValidatedAtUnixNano >= collection.Profile.Activation.ValidUntilUnixNano ||
			admission.ValidatedAtUnixNano > validatedAt ||
			admission.ProfileDigest != collection.ProfileDigest ||
			admission.ActivationDigest != collection.Profile.Activation.SnapshotDigest {
			return ErrTransferAuthorizationRequired
		}
		decision, err := transferEvidencePolicyDecisionDigest(projection, transferDigest, admission)
		if err != nil || decision != admission.PolicyDecisionDigest {
			return ErrTransferAuthorizationRequired
		}
		request := OwnershipTransferEvidenceRequest{
			TransferAuthorizationID: projection.TransferAuthorizationID,
			TransferEvidenceDigest:  transferDigest,
			Profile:                 cloneTransferProfile(collection.Profile),
			ProfileDigest:           collection.ProfileDigest,
			Activation:              collection.Profile.Activation,
			EvidenceKind:            kind,
			Record:                  retained.Record(),
			RecordDigest:            retained.digest,
			EvaluatedAtUnixNano:     admission.ValidatedAtUnixNano,
		}
		if err := p.profile.ValidateOwnershipTransferEvidenceAt(ctx,
			OwnershipTransferEvidenceHistoryRequest{EvidenceRequest: request,
				PolicyDecisionDigest: decision}); err != nil {
			return fmt.Errorf("aiinfra iam: historical transfer evidence policy: %w", err)
		}
	}
	return nil
}

func sameTransferCollectionSnapshot(left, right OwnershipTransferApprovalCollectionSnapshot) bool {
	leftBytes, leftErr := jsonMarshalCanonical(left)
	rightBytes, rightErr := jsonMarshalCanonical(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func durableEnvelopeFullWindow(envelope DurablePendingEnvelope) (int64, int64, int64, error) {
	switch envelope.kind {
	case DurablePendingMutation:
		return envelope.mutation.EvaluatedAtUnixNano(), envelope.mutation.CommitNotBeforeUnixNano(),
			envelope.mutation.CommitNotAfterUnixNano(), nil
	case DurablePendingKeyEnrollment:
		return envelope.enrollment.EvaluatedAtUnixNano(), envelope.enrollment.CommitNotBeforeUnixNano(),
			envelope.enrollment.CommitNotAfterUnixNano(), nil
	case DurablePendingOwnershipTransferCollection:
		return envelope.transfer.EvaluatedAtUnixNano(), envelope.transfer.CommitNotBeforeUnixNano(),
			envelope.transfer.CommitNotAfterUnixNano(), nil
	case DurablePendingReconciliation:
		return envelope.reconciliation.EvaluatedAtUnixNano(), envelope.reconciliation.CommitNotBeforeUnixNano(),
			envelope.reconciliation.CommitNotAfterUnixNano(), nil
	case DurablePendingOwnershipTransferCutover:
		return envelope.cutover.EvaluatedAtUnixNano(), envelope.cutover.CommitNotBeforeUnixNano(),
			envelope.cutover.CommitNotAfterUnixNano(), nil
	case DurablePendingOwnershipTransferAcceptance:
		return envelope.acceptance.EvaluatedAtUnixNano(), envelope.acceptance.CommitNotBeforeUnixNano(),
			envelope.acceptance.CommitNotAfterUnixNano(), nil
	default:
		return 0, 0, 0, ErrPendingPlanInvalid
	}
}

func (p *Planner) revalidateAcceptedCutover(ctx context.Context,
	plan PendingOwnershipTransferCutoverPlan, at int64, original []byte) error {
	if plan.VerifyDigest() != nil || at < plan.commitNotBeforeUnixNano || at >= plan.commitNotAfterUnixNano {
		return ErrPendingPlanInvalid
	}
	if err := p.validateStoredCutoverAdmission(ctx, plan); err != nil {
		return err
	}
	accepted, err := p.resolveAcceptedTransfer(ctx, plan.accepted.TransferEvidenceDigest, at)
	if err != nil || accepted.Snapshot.SnapshotDigest != plan.accepted.SnapshotDigest {
		return ErrTransferAuthorizationRequired
	}
	for _, step := range plan.steps {
		if err := p.revalidateCutoverMutationState(ctx, step.Mutation, at); err != nil {
			return err
		}
		if step.Kind == CutoverCreateNextKeyMaterial {
			continue
		}
		record, found := cutoverAuthorizationRecord(plan, step.Mutation.CAS().AuthorizationDigest)
		if !found {
			return ErrAuthorizationMismatch
		}
		authorization, err := authorizationFromSignedRecord(record)
		if err != nil || p.revalidateAuthorizationAt(ctx, authorization, step.Mutation, at) != nil {
			return ErrAuthorizationMismatch
		}
	}
	command, pool, err := cutoverResumeInputs(plan)
	if err != nil {
		return err
	}
	resume := *p
	resume.view = newCutoverResumeView(p.view, plan.admission, plan.memberAdmission)
	rebuilt, err := resume.planOwnershipTransferCutoverWithEvidence(ctx, command, accepted, pool)
	if err != nil || rebuilt.VerifyDigest() != nil || rebuilt.Digest() != plan.Digest() {
		return ErrPendingPlanInvalid
	}
	rebuiltEnvelope, err := durableEnvelopeForAcceptedCutover(rebuilt)
	if err != nil || !bytes.Equal(rebuiltEnvelope.encoded, original) {
		return ErrPendingPlanInvalid
	}
	return nil
}

func (p *Planner) validateStoredCutoverAdmission(ctx context.Context,
	plan PendingOwnershipTransferCutoverPlan) error {
	parent, joined, err := pendingIdempotencyBindings(plan.admission.idempotencyReservations)
	if err != nil {
		return err
	}
	decision, err := idempotency.PrecheckJoined(ctx, p.view, parent)
	if err != nil || decision.Kind() != idempotency.ContinueCollection ||
		decision.ParentSnapshot().Binding != parent || decision.AuditSnapshot().Binding != joined {
		return ErrPendingPlanInvalid
	}
	for _, claim := range plan.admission.idempotencyReservations {
		expected := idempotency.Snapshot{Binding: claim.Binding, State: claim.NextState,
			Version: claim.NextVersion, ProgressDigest: claim.NextProgressDigest}
		actual := decision.ParentSnapshot()
		if claim.Binding == joined {
			actual = decision.AuditSnapshot()
		}
		if actual != expected {
			return ErrPendingPlanInvalid
		}
	}
	compound, ok := p.view.(idempotency.CompoundMemberView)
	if !ok {
		return ErrViewRequired
	}
	for _, claim := range plan.memberAdmission {
		member, err := idempotency.PrecheckCompoundMemberForParent(ctx, compound, parent, claim.Binding)
		expected := idempotency.CompoundMemberSnapshot{Binding: claim.Binding,
			ParentBinding: claim.ParentBinding, State: claim.NextState,
			Version: claim.NextVersion, ProgressDigest: claim.ProgressDigest}
		if err != nil || member.Kind() != idempotency.ContinueCollection || member.Snapshot() != expected {
			return ErrPendingPlanInvalid
		}
	}
	for _, reservation := range plan.admission.identifierReservations {
		snapshot, found, lookupErr := p.view.LookupGlobalID(ctx, reservation.Identifier)
		if lookupErr != nil || !found || reservation.Mode != globalid.ReserveNew ||
			snapshot.Identifier != reservation.Identifier || snapshot.Owner != reservation.Owner ||
			snapshot.Version != reservation.NextVersion {
			return ErrPendingPlanInvalid
		}
	}
	return nil
}

func cutoverResumeInputs(plan PendingOwnershipTransferCutoverPlan) (
	OwnershipTransferCutoverCommand, *cutoverEvidencePool, error) {
	if plan.VerifyDigest() != nil || len(plan.steps) < 5 || len(plan.evidence) != 3 {
		return OwnershipTransferCutoverCommand{}, nil, ErrPendingPlanInvalid
	}
	closureCount := len(plan.accepted.FixedEvidence.KeyClosureSnapshots)
	if closureCount < 1 || len(plan.steps) != closureCount+4 {
		return OwnershipTransferCutoverCommand{}, nil, ErrPendingPlanInvalid
	}
	command := OwnershipTransferCutoverCommand{TransferEvidenceDigest: plan.accepted.TransferEvidenceDigest,
		EvaluatedAtUnixNano:    plan.evaluatedAtUnixNano,
		KeyClosureWriterFences: make([]WriterFence, closureCount)}
	for index := 0; index < closureCount; index++ {
		step := plan.steps[index]
		lifecycle, ok := step.Mutation.KeyLifecycle()
		record, found := cutoverAuthorizationRecord(plan, step.Mutation.CAS().AuthorizationDigest)
		authorization, authErr := authorizationFromSignedRecord(record)
		if !ok || !found || authErr != nil || step.Kind != CutoverClosePreviousKey {
			return OwnershipTransferCutoverCommand{}, nil, ErrPendingPlanInvalid
		}
		command.KeyClosureWriterFences[index] = writerFenceFromCAS(step.Mutation.CAS(),
			authorization.senderIdentity, lifecycle.HomeRegion)
	}

	previousStep := plan.steps[closureCount]
	previous, ok := previousStep.Mutation.Identity()
	previousRecord, found := cutoverAuthorizationRecord(plan,
		previousStep.Mutation.CAS().AuthorizationDigest)
	previousAuthorization, authErr := authorizationFromSignedRecord(previousRecord)
	previousProjection, projectionErr := decodeIdentitySnapshotProjection(previous)
	if !ok || !found || authErr != nil || projectionErr != nil ||
		previousStep.Kind != CutoverTerminalPreviousIdentity {
		return OwnershipTransferCutoverCommand{}, nil, ErrPendingPlanInvalid
	}
	command.PreviousTerminalIdentity = IdentityCommand{Projection: previousProjection,
		ActorIdentity: previousAuthorization.senderIdentity, EvaluatedAtUnixNano: plan.evaluatedAtUnixNano,
		CorrelationID: previousAuthorization.correlationID, CausationID: previousAuthorization.causationID,
		CauseCode: "ownership-transfer-cutover", Authorization: previousAuthorization,
		TransferEvidenceDigest: plan.accepted.TransferEvidenceDigest,
		Fence: writerFenceFromCAS(previousStep.Mutation.CAS(), previousAuthorization.senderIdentity,
			previous.HomeRegion)}

	materialStep, lifecycleStep := plan.steps[closureCount+1], plan.steps[closureCount+2]
	material, materialOK := materialStep.Mutation.KeyMaterial()
	lifecycle, lifecycleOK := lifecycleStep.Mutation.KeyLifecycle()
	lifecycleRecord, lifecycleRecordFound := cutoverAuthorizationRecord(plan,
		lifecycleStep.Mutation.CAS().AuthorizationDigest)
	lifecycleAuthorization, lifecycleAuthErr := authorizationFromSignedRecord(lifecycleRecord)
	lifecycleProjection, lifecycleProjectionErr := decodeLifecycleSnapshotProjection(lifecycle)
	if !materialOK || !lifecycleOK || !lifecycleRecordFound || lifecycleAuthErr != nil ||
		lifecycleProjectionErr != nil || materialStep.Kind != CutoverCreateNextKeyMaterial ||
		lifecycleStep.Kind != CutoverCreateNextKeyLifecycle {
		return OwnershipTransferCutoverCommand{}, nil, ErrPendingPlanInvalid
	}
	command.NewKeyEnrollment = KeyEnrollmentCommand{Material: KeyMaterialCommand{
		Algorithm: material.Algorithm, CanonicalPublicKey: append([]byte(nil), material.CanonicalPublicKey...),
		ClaimedKeyID: material.KeyID, SubjectIdentity: material.SubjectIdentity,
		SubjectKind: material.SubjectKind, TargetIdentity: material.TargetIdentity,
		TransferEvidenceDigest: material.TransferEvidenceDigest, EnrollmentDomain: material.EnrollmentDomain,
		Challenge: material.ProofChallenge, ChallengeExpiresAtUnixNano: material.ProofExpiresAtUnixNano,
		ProofSignature:                    append([]byte(nil), material.ProofSignature...),
		EnrollmentAuthorityIdentity:       material.EnrollmentAuthorityIdentity,
		EnrollmentAuthorityEvidenceDigest: material.ChallengeEvidenceDigest,
		EnrollmentPolicyDigestsSHA256:     cloneDigests(material.EnrollmentPolicyDigestsSHA256),
		EvaluatedAtUnixNano:               plan.evaluatedAtUnixNano, CorrelationID: lifecycleAuthorization.correlationID,
		IdempotencyKey: material.IdempotencyKey, CauseCode: "ownership-transfer-cutover",
		Fence: writerFenceFromCAS(materialStep.Mutation.CAS(), material.WriterIdentity, material.HomeRegion)},
		Lifecycle: KeyLifecycleCommand{Projection: lifecycleProjection,
			ActorIdentity: lifecycleAuthorization.senderIdentity, EvaluatedAtUnixNano: plan.evaluatedAtUnixNano,
			CorrelationID: lifecycleAuthorization.correlationID, CausationID: lifecycleAuthorization.causationID,
			CauseCode: "ownership-transfer-cutover", Authorization: lifecycleAuthorization,
			TransferEvidenceDigest: plan.accepted.TransferEvidenceDigest,
			Fence: writerFenceFromCAS(lifecycleStep.Mutation.CAS(), lifecycleAuthorization.senderIdentity,
				lifecycle.HomeRegion)}}

	nextStep := plan.steps[closureCount+3]
	next, ok := nextStep.Mutation.Identity()
	nextRecord, found := cutoverAuthorizationRecord(plan, nextStep.Mutation.CAS().AuthorizationDigest)
	nextAuthorization, authErr := authorizationFromSignedRecord(nextRecord)
	nextProjection, projectionErr := decodeIdentitySnapshotProjection(next)
	if !ok || !found || authErr != nil || projectionErr != nil || nextStep.Kind != CutoverCreateNextIdentity {
		return OwnershipTransferCutoverCommand{}, nil, ErrPendingPlanInvalid
	}
	command.NextPendingIdentity = IdentityCommand{Projection: nextProjection,
		ActorIdentity: nextAuthorization.senderIdentity, EvaluatedAtUnixNano: plan.evaluatedAtUnixNano,
		CorrelationID: nextAuthorization.correlationID, CausationID: nextAuthorization.causationID,
		CauseCode: "ownership-transfer-cutover", Authorization: nextAuthorization,
		TransferEvidenceDigest: plan.accepted.TransferEvidenceDigest,
		Fence:                  writerFenceFromCAS(nextStep.Mutation.CAS(), nextAuthorization.senderIdentity, next.HomeRegion)}

	pool := &cutoverEvidencePool{values: make(map[[32]byte]RetainedVerifiedRecord, len(plan.evidence))}
	for _, retained := range plan.evidence {
		if _, err := canonicalRetainedRecord(retained); err != nil {
			return OwnershipTransferCutoverCommand{}, nil, ErrPendingPlanInvalid
		}
		if _, duplicate := pool.values[retained.digest]; duplicate {
			return OwnershipTransferCutoverCommand{}, nil, ErrPendingPlanInvalid
		}
		pool.values[retained.digest] = RetainedVerifiedRecord{
			record: cloneCCSERecord(retained.record), digest: retained.digest}
	}
	return command, pool, nil
}

func cutoverAuthorizationRecord(plan PendingOwnershipTransferCutoverPlan,
	digest [32]byte) (ccse.Record, bool) {
	for _, retained := range plan.evidence {
		if retained.digest == digest {
			return cloneCCSERecord(retained.record), true
		}
	}
	for _, retained := range plan.accepted.FixedEvidence.KeyClosureRecords {
		if retained.digest == digest {
			return cloneCCSERecord(retained.record), true
		}
	}
	return ccse.Record{}, false
}

func (p *Planner) revalidateCutoverMutationState(ctx context.Context, plan MutationPlan, at int64) error {
	cas := plan.CAS()
	lease, found, err := p.view.LookupWriterLease(ctx, cas.Entity)
	if err != nil || !found || lease.Entity != cas.Entity || lease.WriterEpoch != cas.AuthorizedWriterEpoch ||
		lease.EvidenceDigest != cas.WriterEvidenceDigest || at < lease.ValidFromUnixNano ||
		at >= lease.ValidUntilUnixNano {
		return ErrWriterFenceMismatch
	}
	switch cas.Entity.Kind {
	case EntityKeyMaterial:
		current, exists, lookupErr := p.view.LookupKeyMaterial(ctx, cas.Entity.ID)
		if lookupErr != nil || exists != !cas.ExpectedAbsent {
			return ErrViewInconsistent
		}
		if exists && (current.StateVersion != cas.ExpectedStateVersion ||
			current.WriterEpoch != cas.ExpectedEntityWriterEpoch) {
			return ErrViewInconsistent
		}
		if cas.ConsumeChallenge {
			challenge, challengeFound, challengeErr := p.view.LookupProofChallenge(ctx, cas.Challenge)
			if challengeErr != nil || !challengeFound || challenge.Consumed ||
				challenge.EvidenceDigest != cas.ChallengeEvidenceDigest || at >= challenge.ExpiresAtUnixNano {
				return ErrInvalidProofOfPossession
			}
		}
	case EntityIdentity:
		current, exists, lookupErr := p.view.LookupIdentity(ctx, cas.Entity)
		if lookupErr != nil || exists != !cas.ExpectedAbsent {
			return ErrViewInconsistent
		}
		if exists {
			current, lookupErr = normalizeViewIdentity(current)
			if lookupErr != nil || current.StateVersion != cas.ExpectedStateVersion ||
				current.WriterEpoch != cas.ExpectedEntityWriterEpoch {
				return ErrViewInconsistent
			}
		}
	case EntityKeyLifecycle:
		current, exists, lookupErr := p.view.LookupKeyLifecycle(ctx, cas.Entity.ID)
		if lookupErr != nil || exists != !cas.ExpectedAbsent {
			return ErrViewInconsistent
		}
		if exists {
			current, lookupErr = normalizeViewLifecycle(current)
			if lookupErr != nil || current.StateVersion != cas.ExpectedStateVersion ||
				current.WriterEpoch != cas.ExpectedEntityWriterEpoch {
				return ErrViewInconsistent
			}
		}
	default:
		return ErrPendingPlanInvalid
	}
	return nil
}

func authorizationFromSignedRecord(record ccse.Record) (VerifiedAuthorization, error) {
	digest, err := record.Digest(ccse.DefaultLimits())
	if err != nil || len(record.Signature) != 64 {
		return VerifiedAuthorization{}, ErrAuthorizationMismatch
	}
	domain, envelope := record.Domain, record.Envelope
	return VerifiedAuthorization{
		messageTypeID: record.MessageTypeID, schemaVersion: record.SchemaVersion,
		senderIdentity: domain.SenderIdentity, signatureKeyID: envelope.SignatureKeyID,
		payload: append([]byte(nil), record.Payload...), recordDigest: digest,
		messageID: envelope.MessageID, correlationID: envelope.CorrelationID,
		causationID: envelope.CausationID, issuedAtUnixNano: envelope.IssuedAtUnixNano,
		expiresAtUnixNano: envelope.ExpiresAtUnixNano, protocolVersion: domain.ProtocolVersion,
		purpose: domain.Purpose, audience: append([]string(nil), domain.Audience...),
		tenantOrganization: domain.TenantOrganization, providerOrganization: domain.ProviderOrganization,
		environment: domain.Environment, chainID: domain.ChainID, genesisHash: domain.GenesisHash,
		replayDomainID: domain.ReplayDomainID, counterKind: domain.CounterKind, counter: domain.Counter,
		sourceRecord: cloneCCSERecord(record), hasSourceRecord: true,
	}, nil
}

func (p *Planner) revalidatePendingMutation(ctx context.Context, pending PendingMutationPlan,
	at int64, original []byte) error {
	if pending.VerifyDigest() != nil || pending.audit.hasSourceAuthorization == false {
		return ErrPendingPlanInvalid
	}
	if err := p.revalidateAdmissionState(ctx, pending.admission, pending.mutation.CAS(), at); err != nil {
		return err
	}
	authorization, err := authorizationFromSignedRecord(pending.audit.sourceAuthorizationRecord)
	if err != nil {
		return err
	}
	resume := *p
	resume.view = newPendingResumeView(p.view, pending.admission)
	var rebuilt PendingMutationPlan
	switch pending.mutation.Kind() {
	case MutationAppendIdentity:
		snapshot, ok := pending.mutation.Identity()
		if !ok {
			return ErrPendingPlanInvalid
		}
		projection, err := decodeIdentitySnapshotProjection(snapshot)
		if err != nil {
			return err
		}
		command := IdentityCommand{Projection: projection, ActorIdentity: pending.audit.ActorIdentity(),
			EvaluatedAtUnixNano: pending.mutation.EvaluatedAtUnixNano(), CorrelationID: pending.audit.CorrelationID(),
			CausationID: authorization.CausationID(), CauseCode: pending.audit.CauseCode(),
			Fence:         writerFenceFromMutation(pending.mutation, pending.audit.ActorIdentity(), snapshot.HomeRegion),
			Authorization: authorization, TransferEvidenceDigest: pending.mutation.CAS().TransferEvidenceDigest}
		rebuilt, err = resume.PlanIdentity(ctx, command)
		if err != nil {
			return err
		}
	case MutationAppendKeyLifecycle:
		snapshot, ok := pending.mutation.KeyLifecycle()
		if !ok {
			return ErrPendingPlanInvalid
		}
		projection, err := decodeLifecycleSnapshotProjection(snapshot)
		if err != nil {
			return err
		}
		command := KeyLifecycleCommand{Projection: projection, ActorIdentity: pending.audit.ActorIdentity(),
			EvaluatedAtUnixNano: pending.mutation.EvaluatedAtUnixNano(), CorrelationID: pending.audit.CorrelationID(),
			CausationID: authorization.CausationID(), CauseCode: pending.audit.CauseCode(),
			Fence:         writerFenceFromMutation(pending.mutation, pending.audit.ActorIdentity(), snapshot.HomeRegion),
			Authorization: authorization, TransferEvidenceDigest: pending.mutation.CAS().TransferEvidenceDigest}
		rebuilt, err = resume.PlanKeyLifecycle(ctx, command)
		if err != nil {
			return err
		}
	default:
		return ErrPendingPlanInvalid
	}
	rebuiltEnvelope, err := rebuilt.DurableEnvelope()
	if err != nil || !bytes.Equal(rebuiltEnvelope.encoded, original) {
		return ErrPendingPlanInvalid
	}
	return p.revalidateAuthorizationAt(ctx, authorization, pending.mutation, at)
}

func (p *Planner) revalidatePendingEnrollment(ctx context.Context, pending PendingKeyEnrollmentPlan,
	at int64, original []byte) error {
	if pending.VerifyDigest() != nil || !pending.audit.hasSourceAuthorization {
		return ErrPendingPlanInvalid
	}
	for _, cas := range pending.CASIntents() {
		if err := p.revalidateAdmissionState(ctx, pending.admission, cas, at); err != nil {
			return err
		}
	}
	material, materialOK := pending.KeyMaterial()
	lifecycle, lifecycleOK := pending.KeyLifecycle()
	if !materialOK || !lifecycleOK {
		return ErrPendingPlanInvalid
	}
	authorization, err := authorizationFromSignedRecord(pending.audit.sourceAuthorizationRecord)
	if err != nil {
		return err
	}
	lifecycleProjection, err := decodeLifecycleSnapshotProjection(lifecycle)
	if err != nil {
		return err
	}
	materialCAS, lifecycleCAS := pending.material.CAS(), pending.lifecycle.CAS()
	materialCommand := KeyMaterialCommand{Algorithm: material.Algorithm,
		CanonicalPublicKey: material.CanonicalPublicKey, ClaimedKeyID: material.KeyID,
		SubjectIdentity: material.SubjectIdentity, SubjectKind: material.SubjectKind,
		TargetIdentity: material.TargetIdentity, TransferEvidenceDigest: material.TransferEvidenceDigest,
		EnrollmentDomain: material.EnrollmentDomain, Challenge: material.ProofChallenge,
		ChallengeExpiresAtUnixNano: material.ProofExpiresAtUnixNano, ProofSignature: material.ProofSignature,
		EnrollmentAuthorityIdentity:       material.EnrollmentAuthorityIdentity,
		EnrollmentAuthorityEvidenceDigest: material.ChallengeEvidenceDigest,
		EnrollmentPolicyDigestsSHA256:     material.EnrollmentPolicyDigestsSHA256,
		EvaluatedAtUnixNano:               pending.EvaluatedAtUnixNano(), CorrelationID: pending.audit.CorrelationID(),
		IdempotencyKey: material.IdempotencyKey, CauseCode: pending.audit.CauseCode(),
		Fence: writerFenceFromCAS(materialCAS, material.WriterIdentity, material.HomeRegion)}
	lifecycleCommand := KeyLifecycleCommand{Projection: lifecycleProjection,
		ActorIdentity: pending.audit.ActorIdentity(), EvaluatedAtUnixNano: pending.EvaluatedAtUnixNano(),
		CorrelationID: pending.audit.CorrelationID(), CausationID: authorization.CausationID(),
		CauseCode:     pending.audit.CauseCode(),
		Fence:         writerFenceFromCAS(lifecycleCAS, pending.audit.ActorIdentity(), lifecycle.HomeRegion),
		Authorization: authorization, TransferEvidenceDigest: lifecycleCAS.TransferEvidenceDigest}
	resume := *p
	resume.view = newPendingResumeView(p.view, pending.admission)
	rebuilt, err := resume.PlanKeyEnrollment(ctx, KeyEnrollmentCommand{Material: materialCommand, Lifecycle: lifecycleCommand})
	if err != nil {
		return err
	}
	rebuiltEnvelope, err := rebuilt.DurableEnvelope()
	if err != nil || !bytes.Equal(rebuiltEnvelope.encoded, original) {
		return ErrPendingPlanInvalid
	}
	return p.revalidateAuthorizationAt(ctx, authorization, pending.lifecycle, at)
}

func decodeIdentitySnapshotProjection(snapshot IdentitySnapshot) (any, error) {
	validator, err := foundationCanonicalValidator()
	if err != nil {
		return nil, err
	}
	projection, err := validator.Decode(snapshot.MessageTypeID, ccse.Version{Major: 1}, snapshot.CanonicalPayload)
	if err != nil {
		return nil, ErrPendingPlanInvalid
	}
	normalized, err := NormalizeIdentity(projection)
	if err != nil || !equalIdentitySnapshots(normalized, snapshot) {
		return nil, ErrPendingPlanInvalid
	}
	return projection, nil
}

func decodeLifecycleSnapshotProjection(snapshot KeyLifecycleSnapshot) (any, error) {
	validator, err := foundationCanonicalValidator()
	if err != nil {
		return nil, err
	}
	projection, err := validator.Decode(schema.MessageTypeKeyLifecycle, ccse.Version{Major: 1}, snapshot.CanonicalPayload)
	if err != nil {
		return nil, ErrPendingPlanInvalid
	}
	normalized, err := NormalizeKeyLifecycle(projection)
	if err != nil || !equalLifecycleSnapshots(normalized, snapshot) {
		return nil, ErrPendingPlanInvalid
	}
	return projection, nil
}

func equalIdentitySnapshots(left, right IdentitySnapshot) bool {
	leftBytes, leftErr := jsonMarshalCanonical(left)
	rightBytes, rightErr := jsonMarshalCanonical(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func equalLifecycleSnapshots(left, right KeyLifecycleSnapshot) bool {
	leftBytes, leftErr := jsonMarshalCanonical(left)
	rightBytes, rightErr := jsonMarshalCanonical(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func jsonMarshalCanonical(value any) ([]byte, error) {
	return json.Marshal(value)
}

func writerFenceFromMutation(plan MutationPlan, writer, home string) WriterFence {
	return writerFenceFromCAS(plan.CAS(), writer, home)
}

func writerFenceFromCAS(cas CASIntent, writer, home string) WriterFence {
	return WriterFence{Entity: cas.Entity, WriterIdentity: writer, HomeRegion: home,
		WriterEpoch: cas.AuthorizedWriterEpoch, ExpectedStateVersion: cas.ExpectedStateVersion,
		EvidenceDigest: cas.WriterEvidenceDigest}
}

func (p *Planner) revalidateAuthorizationAt(ctx context.Context, authorization VerifiedAuthorization,
	mutation MutationPlan, at int64) error {
	var payload []byte
	var createdAt int64
	var messageType uint32
	switch mutation.Kind() {
	case MutationAppendIdentity:
		value, ok := mutation.Identity()
		if !ok {
			return ErrPendingPlanInvalid
		}
		payload, createdAt, messageType = value.CanonicalPayload, value.CreatedAtUnixNano, value.MessageTypeID
	case MutationAppendKeyLifecycle:
		value, ok := mutation.KeyLifecycle()
		if !ok {
			return ErrPendingPlanInvalid
		}
		payload, createdAt, messageType = value.CanonicalPayload, value.CreatedAtUnixNano, authorization.messageTypeID
	default:
		return ErrPendingPlanInvalid
	}
	_, err := p.validateVerifiedAuthorization(ctx, authorization, messageType, payload, createdAt,
		authorization.senderIdentity, authorization.correlationID, authorization.causationID,
		mutation.CAS().Entity, at, mutation.CAS().ExpectedStateVersion)
	return err
}

func (p *Planner) revalidateAdmissionState(ctx context.Context, admission PendingAdmissionIntent,
	cas CASIntent, at int64) error {
	if err := verifyPendingAdmissionIntent(admission); err != nil {
		return err
	}
	parent, joined, err := pendingIdempotencyBindings(admission.idempotencyReservations)
	if err != nil {
		return err
	}
	parentSnapshot, parentFound, joinedSnapshot, joinedFound, err :=
		p.view.SnapshotBusinessIdempotencyPair(ctx, parent.Key, joined.Key)
	if err != nil || !parentFound || !joinedFound {
		return ErrPendingPlanInvalid
	}
	for _, claim := range admission.idempotencyReservations {
		expected := idempotency.Snapshot{Binding: claim.Binding, State: claim.NextState,
			Version: claim.NextVersion, ProgressDigest: claim.NextProgressDigest}
		actual := parentSnapshot
		if claim.Binding == joined {
			actual = joinedSnapshot
		}
		if actual != expected {
			return ErrPendingPlanInvalid
		}
	}
	for _, reservation := range admission.identifierReservations {
		snapshot, found, lookupErr := p.view.LookupGlobalID(ctx, reservation.Identifier)
		if lookupErr != nil || !found || reservation.Mode != globalid.ReserveNew ||
			snapshot.Identifier != reservation.Identifier || snapshot.Owner != reservation.Owner ||
			snapshot.Version != reservation.NextVersion {
			return ErrPendingPlanInvalid
		}
	}
	lease, found, err := p.view.LookupWriterLease(ctx, cas.Entity)
	if err != nil || !found || lease.Entity != cas.Entity || lease.WriterEpoch != cas.AuthorizedWriterEpoch ||
		lease.EvidenceDigest != cas.WriterEvidenceDigest || at < lease.ValidFromUnixNano || at >= lease.ValidUntilUnixNano {
		return ErrWriterFenceMismatch
	}
	return nil
}

type pendingResumeView struct {
	View
	hiddenGlobal map[string]struct{}
	parentKey    [16]byte
	joinedKey    [16]byte
}

type cutoverResumeView struct {
	*pendingResumeView
	hiddenMembers map[[ccse.MessageIDSize]byte]struct{}
}

func newCutoverResumeView(view View, admission PendingAdmissionIntent,
	members []idempotency.CompoundMemberClaim) *cutoverResumeView {
	result := &cutoverResumeView{pendingResumeView: newPendingResumeView(view, admission),
		hiddenMembers: make(map[[ccse.MessageIDSize]byte]struct{}, len(members))}
	for _, claim := range members {
		result.hiddenMembers[claim.Binding.Key] = struct{}{}
	}
	return result
}

func (view *cutoverResumeView) SnapshotCompoundMemberState(ctx context.Context,
	key [ccse.MessageIDSize]byte) (idempotency.CompoundMemberSnapshot, bool,
	idempotency.Snapshot, bool, idempotency.Snapshot, bool, error) {
	if _, hidden := view.hiddenMembers[key]; hidden {
		return idempotency.CompoundMemberSnapshot{}, false, idempotency.Snapshot{}, false,
			idempotency.Snapshot{}, false, nil
	}
	compound, ok := view.View.(idempotency.CompoundMemberView)
	if !ok {
		return idempotency.CompoundMemberSnapshot{}, false, idempotency.Snapshot{}, false,
			idempotency.Snapshot{}, false, ErrViewRequired
	}
	return compound.SnapshotCompoundMemberState(ctx, key)
}

func (view *cutoverResumeView) LookupBusinessIdempotency(ctx context.Context,
	key [ccse.MessageIDSize]byte) (idempotency.Snapshot, bool, error) {
	if _, hidden := view.hiddenMembers[key]; hidden {
		return idempotency.Snapshot{}, false, nil
	}
	return view.pendingResumeView.LookupBusinessIdempotency(ctx, key)
}

func (view *cutoverResumeView) SnapshotBusinessIdempotencyPair(ctx context.Context,
	parent, joined [ccse.MessageIDSize]byte) (idempotency.Snapshot, bool,
	idempotency.Snapshot, bool, error) {
	if _, hidden := view.hiddenMembers[parent]; hidden {
		return idempotency.Snapshot{}, false, idempotency.Snapshot{}, false, nil
	}
	return view.pendingResumeView.SnapshotBusinessIdempotencyPair(ctx, parent, joined)
}

func newPendingResumeView(view View, admission PendingAdmissionIntent) *pendingResumeView {
	result := &pendingResumeView{View: view, hiddenGlobal: make(map[string]struct{})}
	for _, claim := range admission.identifierReservations {
		result.hiddenGlobal[claim.Identifier] = struct{}{}
	}
	parent, joined, _ := pendingIdempotencyBindings(admission.idempotencyReservations)
	result.parentKey, result.joinedKey = parent.Key, joined.Key
	return result
}

func (view *pendingResumeView) LookupGlobalID(ctx context.Context, id string) (globalid.Snapshot, bool, error) {
	if _, hidden := view.hiddenGlobal[id]; hidden {
		return globalid.Snapshot{}, false, nil
	}
	return view.View.LookupGlobalID(ctx, id)
}

func (view *pendingResumeView) LookupBusinessIdempotency(ctx context.Context,
	key [16]byte) (idempotency.Snapshot, bool, error) {
	if key == view.parentKey || key == view.joinedKey {
		return idempotency.Snapshot{}, false, nil
	}
	return view.View.LookupBusinessIdempotency(ctx, key)
}

func (view *pendingResumeView) SnapshotBusinessIdempotencyPair(ctx context.Context,
	parent, joined [16]byte) (idempotency.Snapshot, bool, idempotency.Snapshot, bool, error) {
	if parent == view.parentKey {
		return idempotency.Snapshot{}, false, idempotency.Snapshot{}, false, nil
	}
	return view.View.SnapshotBusinessIdempotencyPair(ctx, parent, joined)
}

func (p *Planner) revalidateTransferCollection(context.Context,
	OwnershipTransferApprovalCollectionPlan, int64) error {
	return fmt.Errorf("%w: ownership-transfer recovery requires profile activation", ErrPendingPlanInvalid)
}

func (p *Planner) revalidateReconciliation(ctx context.Context,
	plan PendingReconciliationPlan, at int64) error {
	if at < 0 || plan.VerifyDigest() != nil || plan.failureOutcomeDigest == ([32]byte{}) {
		return ErrPendingPlanInvalid
	}
	parent, joined, err := pendingCompletionBindings(plan.idempotencyCompletion)
	if err != nil {
		return ErrPendingPlanInvalid
	}
	decision, err := idempotency.PrecheckJoined(ctx, p.view, parent)
	if err != nil || decision.Kind() != idempotency.DuplicateCompleted ||
		decision.OutcomeDigest() != plan.failureOutcomeDigest {
		return ErrPendingPlanInvalid
	}
	for _, claim := range plan.idempotencyCompletion {
		expected := idempotency.Snapshot{Binding: claim.Binding, State: claim.NextState,
			Version: claim.NextVersion, ProgressDigest: claim.NextProgressDigest,
			OutcomeDigest: plan.failureOutcomeDigest}
		actual := decision.ParentSnapshot()
		if claim.Binding == joined {
			actual = decision.AuditSnapshot()
		}
		if actual != expected {
			return ErrPendingPlanInvalid
		}
	}
	if len(plan.compoundMemberCompletion) != 0 {
		compound, ok := p.view.(idempotency.CompoundMemberView)
		if !ok {
			return ErrViewRequired
		}
		for _, claim := range plan.compoundMemberCompletion {
			member, memberErr := idempotency.PrecheckCompoundMemberForParent(ctx,
				compound, parent, claim.Binding)
			expected := idempotency.CompoundMemberSnapshot{Binding: claim.Binding,
				ParentBinding: claim.ParentBinding, State: claim.NextState,
				Version: claim.NextVersion, ProgressDigest: claim.ProgressDigest,
				OutcomeDigest: plan.failureOutcomeDigest}
			if memberErr != nil || member.Kind() != idempotency.DuplicateCompleted ||
				member.OutcomeDigest() != plan.failureOutcomeDigest || member.Snapshot() != expected {
				return ErrPendingPlanInvalid
			}
		}
	}
	for _, assertion := range plan.identifierTombstones {
		snapshot, found, lookupErr := p.view.LookupGlobalID(ctx, assertion.Identifier)
		if lookupErr != nil || !found || assertion.Mode != globalid.AssertExisting ||
			snapshot.Identifier != assertion.Identifier || snapshot.Owner != assertion.Owner ||
			snapshot.Version != assertion.ExpectedVersion {
			return ErrPendingPlanInvalid
		}
	}
	return IdempotencyCompletedError{Outcome: plan.failureOutcomeDigest}
}
