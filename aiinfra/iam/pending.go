// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"bytes"
	"fmt"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
)

const (
	pendingCoreEvidenceDomain = "CPH-AIIE-IAM-PENDING-CORE-EVIDENCE-V1\x00"
	pendingAdmissionDomain    = "CPH-AIIE-IAM-PENDING-ADMISSION-V1\x00"
	pendingFinalPlanDomain    = "CPH-AIIE-IAM-PENDING-FINAL-PLAN-V1\x00"
	pendingAdmissionMaxBytes  = 6 << 20
)

func pendingCoreEvidenceDigest(mutationDigest, auditDigest [32]byte) [32]byte {
	encoded, _ := ccse.Marshal(80, func(out *ccse.Encoder) {
		out.FixedBytes(mutationDigest[:], 32)
		out.FixedBytes(auditDigest[:], 32)
	})
	return domainDigest(pendingCoreEvidenceDomain, encoded)
}

func joinedAuditEventReservation(parent idempotency.Binding, eventID string) (globalid.Claim, error) {
	expectedEventID, err := idempotency.JoinedAuditEventID(parent)
	if err != nil || eventID == "" || eventID != expectedEventID {
		return globalid.Claim{}, ErrPendingPlanInvalid
	}
	claim, err := globalid.Reserve(eventID, globalid.Owner{
		Domain: globalid.OwnerGovernanceAuditEvent,
		ID:     eventID,
	})
	if err != nil {
		return globalid.Claim{}, fmt.Errorf("%w: joined audit event reservation: %v", ErrGlobalIdentifier, err)
	}
	return claim, nil
}

func joinedAuditEventAssertion(reservation globalid.Claim) (globalid.Claim, error) {
	if reservation.Mode != globalid.ReserveNew ||
		reservation.Owner.Domain != globalid.OwnerGovernanceAuditEvent ||
		reservation.Identifier != reservation.Owner.ID {
		return globalid.Claim{}, ErrPendingPlanInvalid
	}
	claim, err := globalid.Assert(reservation.Identifier, globalid.Snapshot{
		Identifier: reservation.Identifier,
		Owner:      reservation.Owner,
		Version:    reservation.NextVersion,
	}, reservation.Owner)
	if err != nil {
		return globalid.Claim{}, ErrPendingPlanInvalid
	}
	return claim, nil
}

func containsGlobalClaim(claims []globalid.Claim, expected globalid.Claim) bool {
	for _, claim := range claims {
		if claim == expected {
			return true
		}
	}
	return false
}

func verifyJoinedAuditEventClaims(parent idempotency.Binding, audit AuditIntent,
	reservations, final []globalid.Claim) error {
	reservation, err := joinedAuditEventReservation(parent, audit.AuditEventID())
	if err != nil || !containsGlobalClaim(reservations, reservation) {
		return ErrPendingPlanInvalid
	}
	assertion, err := joinedAuditEventAssertion(reservation)
	if err != nil || !containsGlobalClaim(final, assertion) {
		return ErrPendingPlanInvalid
	}
	return nil
}

func stageGlobalIdentifierClaims(claims []globalid.Claim) (finalClaims,
	reservations []globalid.Claim, err error) {
	for _, claim := range claims {
		if err := claim.Validate(); err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrGlobalIdentifier, err)
		}
		if claim.Mode != globalid.ReserveNew {
			finalClaims = append(finalClaims, claim)
			continue
		}
		reservations = append(reservations, claim)
		assertion, assertErr := globalid.Assert(claim.Identifier, globalid.Snapshot{
			Identifier: claim.Identifier, Owner: claim.Owner, Version: claim.NextVersion}, claim.Owner)
		if assertErr != nil {
			return nil, nil, fmt.Errorf("%w: staged assertion: %v", ErrGlobalIdentifier, assertErr)
		}
		finalClaims = append(finalClaims, assertion)
	}
	if len(reservations) == 0 {
		return nil, nil, fmt.Errorf("%w: pending admission has no immutable identifier reservation", ErrPendingPlanInvalid)
	}
	finalClaims, err = normalizeGlobalClaims(finalClaims)
	if err != nil {
		return nil, nil, err
	}
	reservations, err = normalizeGlobalClaims(reservations)
	return finalClaims, reservations, err
}

func pendingIdempotencyBindings(claims []idempotency.Claim) (parent,
	joined idempotency.Binding, err error) {
	normalized, err := idempotency.NormalizeClaims(claims)
	if err != nil || len(normalized) != 2 {
		return parent, joined, ErrPendingPlanInvalid
	}
	for _, claim := range normalized {
		if claim.Mode != idempotency.ReserveCollection {
			return parent, joined, ErrPendingPlanInvalid
		}
		if claim.Binding.Domain == idempotency.OperationJoinedAudit {
			joined = claim.Binding
		} else {
			parent = claim.Binding
		}
	}
	if parent == (idempotency.Binding{}) || joined == (idempotency.Binding{}) {
		return parent, joined, ErrPendingPlanInvalid
	}
	expected, err := idempotency.JoinedAuditBinding(parent)
	if err != nil || expected != joined {
		return parent, joined, ErrPendingPlanInvalid
	}
	return parent, joined, nil
}

func pendingCompletionBindings(claims []idempotency.Claim) (parent,
	joined idempotency.Binding, err error) {
	normalized, err := idempotency.NormalizeClaims(claims)
	if err != nil || len(normalized) != 2 {
		return parent, joined, ErrPendingPlanInvalid
	}
	for _, claim := range normalized {
		if claim.Mode != idempotency.CompleteCollection {
			return parent, joined, ErrPendingPlanInvalid
		}
		if claim.Binding.Domain == idempotency.OperationJoinedAudit {
			joined = claim.Binding
		} else {
			parent = claim.Binding
		}
	}
	if parent == (idempotency.Binding{}) || joined == (idempotency.Binding{}) {
		return parent, joined, ErrPendingPlanInvalid
	}
	expected, err := idempotency.JoinedAuditBinding(parent)
	if err != nil || expected != joined {
		return parent, joined, ErrPendingPlanInvalid
	}
	return parent, joined, nil
}

func pendingIdempotencyClaimsBound(parent, joined idempotency.Binding, auditIntentDigest,
	coreEvidenceDigest [32]byte) ([]idempotency.Claim, error) {
	parentDigest, err := idempotency.BindingDigest(parent)
	if err != nil {
		return nil, err
	}
	if expected, joinErr := idempotency.JoinedAuditBinding(parent); joinErr != nil || expected != joined ||
		coreEvidenceDigest == ([32]byte{}) {
		return nil, ErrPendingPlanInvalid
	}
	encoded, err := ccse.Marshal(160, func(out *ccse.Encoder) {
		out.FixedBytes(parentDigest[:], 32)
		out.FixedBytes(auditIntentDigest[:], 32)
		out.FixedBytes(coreEvidenceDigest[:], 32)
	})
	if err != nil {
		return nil, err
	}
	mutationProgress := domainDigest(pendingMutationProgressDomain, encoded)
	mutationClaim, err := idempotency.NewReserveCollection(parent, mutationProgress)
	if err != nil {
		return nil, err
	}
	auditClaim, err := idempotency.NewReserveCollection(joined, parentDigest)
	if err != nil {
		return nil, err
	}
	return idempotency.NormalizeClaims([]idempotency.Claim{mutationClaim, auditClaim})
}

func pendingCompletionClaims(reservations []idempotency.Claim) ([]idempotency.Claim, error) {
	result := make([]idempotency.Claim, 0, len(reservations))
	for _, reservation := range reservations {
		if reservation.Mode != idempotency.ReserveCollection {
			return nil, ErrPendingPlanInvalid
		}
		snapshot := idempotency.Snapshot{Binding: reservation.Binding, State: reservation.NextState,
			Version: reservation.NextVersion, ProgressDigest: reservation.NextProgressDigest}
		claim, err := idempotency.NewCompleteCollection(snapshot)
		if err != nil {
			return nil, err
		}
		result = append(result, claim)
	}
	return idempotency.NormalizeClaims(result)
}

func newPendingAdmissionIntent(identifierReservations []globalid.Claim,
	idempotencyReservations []idempotency.Claim, core [32]byte,
	evaluatedAt, commitNotBefore, commitNotAfter int64) (PendingAdmissionIntent, error) {
	globalBytes, err := globalid.CanonicalBytes(identifierReservations)
	if err != nil {
		return PendingAdmissionIntent{}, err
	}
	idempotencyBytes, err := idempotency.CanonicalBytes(idempotencyReservations)
	if err != nil {
		return PendingAdmissionIntent{}, err
	}
	if core == ([32]byte{}) || evaluatedAt < 0 || commitNotBefore < 0 ||
		commitNotBefore > evaluatedAt || commitNotAfter <= evaluatedAt {
		return PendingAdmissionIntent{}, ErrPendingPlanInvalid
	}
	encoded, err := ccse.Marshal(pendingAdmissionMaxBytes, func(out *ccse.Encoder) {
		out.FixedBytes(core[:], 32)
		out.Int64(evaluatedAt)
		out.Int64(commitNotBefore)
		out.Int64(commitNotAfter)
		out.Bytes(globalBytes)
		out.Bytes(idempotencyBytes)
	})
	if err != nil {
		return PendingAdmissionIntent{}, err
	}
	return PendingAdmissionIntent{identifierReservations: append([]globalid.Claim(nil), identifierReservations...),
		idempotencyReservations: append([]idempotency.Claim(nil), idempotencyReservations...),
		coreEvidenceDigest:      core, evaluatedAtUnixNano: evaluatedAt,
		commitNotBeforeUnixNano: commitNotBefore, commitNotAfterUnixNano: commitNotAfter,
		digest: domainDigest(pendingAdmissionDomain, encoded)}, nil
}

func verifyPendingAdmissionIntent(intent PendingAdmissionIntent) error {
	derived, err := newPendingAdmissionIntent(intent.identifierReservations,
		intent.idempotencyReservations, intent.coreEvidenceDigest, intent.evaluatedAtUnixNano,
		intent.commitNotBeforeUnixNano, intent.commitNotAfterUnixNano)
	if err != nil || derived.digest != intent.digest {
		return ErrPendingPlanInvalid
	}
	return nil
}

func rebuildMutationPlan(plan MutationPlan, cas CASIntent) (MutationPlan, error) {
	window := planWindow{EvaluatedAtUnixNano: plan.EvaluatedAtUnixNano(),
		CommitNotBeforeUnixNano: plan.CommitNotBeforeUnixNano(),
		CommitNotAfterUnixNano:  plan.CommitNotAfterUnixNano()}
	switch plan.Kind() {
	case MutationCreateKeyMaterial:
		value, ok := plan.KeyMaterial()
		if !ok {
			return MutationPlan{}, ErrPendingPlanInvalid
		}
		return newMaterialPlan(cas, value, window)
	case MutationAppendIdentity:
		value, ok := plan.Identity()
		if !ok {
			return MutationPlan{}, ErrPendingPlanInvalid
		}
		return newIdentityPlan(cas, value, window)
	case MutationAppendKeyLifecycle:
		value, ok := plan.KeyLifecycle()
		if !ok {
			return MutationPlan{}, ErrPendingPlanInvalid
		}
		return newLifecyclePlan(cas, value, window)
	default:
		return MutationPlan{}, ErrPendingPlanInvalid
	}
}

func finalPendingDigest(core, admission [32]byte, completions []idempotency.Claim) ([32]byte, error) {
	var zero [32]byte
	completionBytes, err := idempotency.CanonicalBytes(completions)
	if err != nil {
		return zero, err
	}
	encoded, err := ccse.Marshal(1<<20, func(out *ccse.Encoder) {
		out.FixedBytes(core[:], 32)
		out.FixedBytes(admission[:], 32)
		out.Bytes(completionBytes)
	})
	if err != nil {
		return zero, err
	}
	return domainDigest(pendingFinalPlanDomain, encoded), nil
}

func stagedReservationsMatchFinalClaims(reservations, final []globalid.Claim) bool {
	for _, claim := range final {
		if claim.Mode == globalid.ReserveNew {
			return false
		}
	}
	for _, reservation := range reservations {
		if reservation.Mode != globalid.ReserveNew {
			return false
		}
		matched := false
		for _, claim := range final {
			if claim.Identifier == reservation.Identifier && claim.Mode == globalid.AssertExisting &&
				claim.ExpectedOwner == reservation.Owner && claim.Owner == reservation.Owner &&
				claim.ExpectedVersion == reservation.NextVersion && claim.NextVersion == reservation.NextVersion {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func sameIdempotencyClaims(left, right []idempotency.Claim) bool {
	if len(left) == 0 || len(right) == 0 {
		return len(left) == 0 && len(right) == 0
	}
	leftBytes, leftErr := idempotency.CanonicalBytes(left)
	rightBytes, rightErr := idempotency.CanonicalBytes(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}
