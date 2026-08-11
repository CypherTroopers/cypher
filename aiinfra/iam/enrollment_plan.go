// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	"github.com/cypherium/cypher/aiinfra/schema"
)

const (
	keyEnrollmentRequestDomain = "CPH-AIIE-IAM-KEY-ENROLLMENT-REQUEST-V1\x00"
	keyEnrollmentPlanDomain    = "CPH-AIIE-IAM-KEY-ENROLLMENT-PLAN-V1\x00"
)

// PendingKeyEnrollmentPlan binds creation of immutable KeyMaterial, its first
// signed PREACTIVE KeyLifecycle record, challenge consumption, global-ID and
// business-idempotency claims, and one exact AuditIntent. It remains
// non-committable until the WS0.2b coordinator joins a separately keyed,
// Governance/Audit-validated event and audit-head CAS.
type PendingKeyEnrollmentPlan struct {
	material                MutationPlan
	lifecycle               MutationPlan
	audit                   AuditIntent
	evaluatedAtUnixNano     int64
	commitNotBeforeUnixNano int64
	commitNotAfterUnixNano  int64
	admission               PendingAdmissionIntent
	idempotencyCompletion   []idempotency.Claim
	digest                  [32]byte
}

func (p PendingKeyEnrollmentPlan) Digest() [32]byte         { return p.digest }
func (PendingKeyEnrollmentPlan) CommitReady() bool          { return false }
func (p PendingKeyEnrollmentPlan) AuditIntent() AuditIntent { return p.audit }
func (p PendingKeyEnrollmentPlan) AdmissionIntent() PendingAdmissionIntent {
	return p.admission.detached()
}
func (p PendingKeyEnrollmentPlan) IdempotencyCompletionClaims() []idempotency.Claim {
	return append([]idempotency.Claim(nil), p.idempotencyCompletion...)
}
func (p PendingKeyEnrollmentPlan) EvaluatedAtUnixNano() int64 { return p.evaluatedAtUnixNano }
func (p PendingKeyEnrollmentPlan) CommitNotBeforeUnixNano() int64 {
	return p.commitNotBeforeUnixNano
}
func (p PendingKeyEnrollmentPlan) CommitNotAfterUnixNano() int64 {
	return p.commitNotAfterUnixNano
}
func (p PendingKeyEnrollmentPlan) KeyMaterial() (KeyMaterialSnapshot, bool) {
	return p.material.KeyMaterial()
}
func (p PendingKeyEnrollmentPlan) KeyLifecycle() (KeyLifecycleSnapshot, bool) {
	return p.lifecycle.KeyLifecycle()
}
func (p PendingKeyEnrollmentPlan) CASIntents() []CASIntent {
	return []CASIntent{p.material.CAS(), p.lifecycle.CAS()}
}
func (p PendingKeyEnrollmentPlan) VerifyDigest() error { return verifyPendingKeyEnrollmentPlan(p) }
func (p PendingKeyEnrollmentPlan) RequiredTransferAuthorization() (digest [32]byte, required bool) {
	digest = p.material.CAS().TransferEvidenceDigest
	return digest, digest != ([32]byte{})
}

// PlanKeyEnrollment is the only public first-registration operation. A
// standalone material phase has no exported planner and an initial lifecycle
// passed to PlanKeyLifecycle fails closed.
func (p *Planner) PlanKeyEnrollment(ctx context.Context, command KeyEnrollmentCommand) (PendingKeyEnrollmentPlan, error) {
	materialTransfer := command.Material.TransferEvidenceDigest
	lifecycleTransfer := command.Lifecycle.TransferEvidenceDigest
	if materialTransfer == ([32]byte{}) && lifecycleTransfer == ([32]byte{}) {
		return p.planKeyEnrollment(ctx, command, false)
	}
	// An accepted transfer authorizes one atomic cutover; it never authorizes
	// the successor key to be enrolled as an independently auditable mutation.
	// PlanOwnershipTransferCutover is the sole public consumer of nonzero
	// transfer evidence and invokes the private compound helpers below.
	return PendingKeyEnrollmentPlan{}, ErrTransferAuthorizationRequired
}

func (p *Planner) planKeyEnrollment(ctx context.Context, command KeyEnrollmentCommand,
	allowUnverifiedTransfer bool) (PendingKeyEnrollmentPlan, error) {
	if (command.Material.TransferEvidenceDigest != ([32]byte{}) ||
		command.Lifecycle.TransferEvidenceDigest != ([32]byte{})) && !allowUnverifiedTransfer {
		return PendingKeyEnrollmentPlan{}, ErrTransferAuthorizationRequired
	}
	if err := p.ready(); err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	lifecycle, err := NormalizeKeyLifecycle(command.Lifecycle.Projection)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	if lifecycle.State != 1 || lifecycle.StateVersion != 1 || lifecycle.HasRevokedAt ||
		lifecycle.IdempotencyKey != command.Material.IdempotencyKey ||
		command.Material.TransferEvidenceDigest != command.Lifecycle.TransferEvidenceDigest ||
		command.Material.EvaluatedAtUnixNano != command.Lifecycle.EvaluatedAtUnixNano ||
		command.Material.CorrelationID != command.Lifecycle.CorrelationID ||
		command.Material.CauseCode != command.Lifecycle.CauseCode {
		return PendingKeyEnrollmentPlan{}, ErrAuthorizationMismatch
	}
	if command.Lifecycle.ActorIdentity == "" ||
		command.Lifecycle.ActorIdentity != command.Lifecycle.Fence.WriterIdentity ||
		command.Lifecycle.Fence.ExpectedStateVersion != 0 {
		return PendingKeyEnrollmentPlan{}, ErrAuthorizationMismatch
	}
	if err := validateOperationFields(command.Lifecycle.ActorIdentity, command.Lifecycle.CauseCode,
		command.Lifecycle.CorrelationID, command.Lifecycle.EvaluatedAtUnixNano); err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	// Authenticate the exact canonical PREACTIVE record before looking up its
	// business-idempotency pair, preventing outcome probing with an unsigned or
	// cross-domain projection. Target mutation state is intentionally deferred.
	if _, err := p.validateVerifiedAuthorization(ctx, command.Lifecycle.Authorization,
		schema.MessageTypeKeyLifecycle, lifecycle.CanonicalPayload, lifecycle.CreatedAtUnixNano,
		command.Lifecycle.ActorIdentity, command.Lifecycle.CorrelationID, command.Lifecycle.CausationID,
		EntityRef{Kind: EntityKeyLifecycle, PrincipalKind: lifecycle.SubjectKind, ID: lifecycle.KeyID},
		command.Lifecycle.EvaluatedAtUnixNano, 0); err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	canonicalKey, err := CanonicalPublicKey(command.Material.Algorithm, command.Material.CanonicalPublicKey)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	keyID, err := DeriveKeyID(command.Material.Algorithm, canonicalKey)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	if keyID != command.Material.ClaimedKeyID || lifecycle.KeyID != keyID ||
		lifecycle.SubjectIdentity != command.Material.SubjectIdentity ||
		lifecycle.SubjectKind != command.Material.SubjectKind || lifecycle.Algorithm != command.Material.Algorithm {
		return PendingKeyEnrollmentPlan{}, ErrKeyMaterialMismatch
	}
	materialDigest, err := keyMaterialRequestDigest(command.Material, canonicalKey, keyID)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	lifecycleDigest := sha256.Sum256(lifecycle.CanonicalPayload)
	requestProjection, err := ccse.Marshal(256, func(out *ccse.Encoder) {
		out.FixedBytes(materialDigest[:], 32)
		out.FixedBytes(lifecycleDigest[:], 32)
	})
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	requestDigest := domainDigest(keyEnrollmentRequestDomain, requestProjection)
	binding := mutationIdempotencyBinding(lifecycle.IdempotencyKey, idempotency.OperationIAMKeyEnrollment,
		keyID, requestDigest)
	joinedAuditBinding, err := p.precheckPendingIdempotency(ctx, binding)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	auditEventID, err := idempotency.JoinedAuditEventID(binding)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, ErrPendingPlanInvalid
	}

	materialPlan, materialAudit, err := p.planKeyMaterial(ctx, command.Material)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	material, ok := materialPlan.KeyMaterial()
	if !ok {
		return PendingKeyEnrollmentPlan{}, ErrPendingPlanInvalid
	}
	overlay, err := newEnrollmentOverlayView(p.view, material, materialPlan.CAS().IdentifierClaims)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	overlayPlanner := *p
	overlayPlanner.view = overlay
	lifecyclePlan, lifecycleAudit, err := overlayPlanner.planKeyLifecycle(ctx, command.Lifecycle, true,
		allowUnverifiedTransfer)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}

	materialCAS := materialPlan.CAS()
	lifecycleSnapshot, ok := lifecyclePlan.KeyLifecycle()
	if !ok {
		return PendingKeyEnrollmentPlan{}, ErrPendingPlanInvalid
	}
	lifecycleCAS := lifecyclePlan.CAS()
	lifecycleCAS.IdentifierClaims = retainRecordClaims(lifecycleCAS.IdentifierClaims)
	lifecycleCAS.Dependencies = removePlannedMaterialDependency(lifecycleCAS.Dependencies, material)

	subjects := uniqueStrings(append(materialAudit.SubjectIDs(), lifecycleAudit.SubjectIDs()...))
	policies := uniqueDigests(append(materialAudit.PolicyDigestsSHA256(), lifecycleAudit.PolicyDigestsSHA256()...))
	evidence := uniqueDigests(append(materialAudit.EvidenceDigestsSHA256(), lifecycleAudit.EvidenceDigestsSHA256()...))
	source, err := auditSourceFromAuthorization(command.Lifecycle.Authorization)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	audit, err := newAuditIntent(auditEventID, "iam.key_enrolled", command.Lifecycle.ActorIdentity, subjects,
		command.Lifecycle.CauseCode, command.Lifecycle.CorrelationID,
		directAuditCausation(command.Lifecycle.Authorization.messageID),
		command.Lifecycle.Authorization.messageID, lifecycle.IdempotencyKey, joinedAuditBinding.Key, source,
		command.Lifecycle.EvaluatedAtUnixNano, policies, evidence)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	auditEventReservation, err := joinedAuditEventReservation(binding, audit.AuditEventID())
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	materialCAS.IdentifierClaims = append(materialCAS.IdentifierClaims, auditEventReservation)
	materialCAS.IdentifierClaims, err = normalizeGlobalClaims(materialCAS.IdentifierClaims)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	materialFinalIdentifiers, materialReservations, err := stageGlobalIdentifierClaims(materialCAS.IdentifierClaims)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	lifecycleFinalIdentifiers, lifecycleReservations, err := stageGlobalIdentifierClaims(lifecycleCAS.IdentifierClaims)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	materialCAS.IdentifierClaims = materialFinalIdentifiers
	materialCAS.IdempotencyClaims = nil
	materialPlan, err = newMaterialPlan(materialCAS, material, planWindow{
		EvaluatedAtUnixNano:     materialPlan.EvaluatedAtUnixNano(),
		CommitNotBeforeUnixNano: materialPlan.CommitNotBeforeUnixNano(),
		CommitNotAfterUnixNano:  materialPlan.CommitNotAfterUnixNano(),
	})
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	lifecycleCAS.IdentifierClaims = lifecycleFinalIdentifiers
	lifecycleCAS.IdempotencyClaims = nil
	lifecyclePlan, err = newLifecyclePlan(lifecycleCAS, lifecycleSnapshot, planWindow{
		EvaluatedAtUnixNano:     lifecyclePlan.EvaluatedAtUnixNano(),
		CommitNotBeforeUnixNano: lifecyclePlan.CommitNotBeforeUnixNano(),
		CommitNotAfterUnixNano:  lifecyclePlan.CommitNotAfterUnixNano(),
	})
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	compositeMutationDigest, err := keyEnrollmentMutationCoreDigest(materialPlan, lifecyclePlan)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	core := pendingCoreEvidenceDigest(compositeMutationDigest, audit.Digest())
	idempotencyReservations, err := pendingIdempotencyClaimsBound(binding, joinedAuditBinding, audit.Digest(), core)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	completion, err := pendingCompletionClaims(idempotencyReservations)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	identifierReservations, err := normalizeGlobalClaims(append(materialReservations, lifecycleReservations...))
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	result := PendingKeyEnrollmentPlan{material: materialPlan, lifecycle: lifecyclePlan, audit: audit,
		evaluatedAtUnixNano:     command.Lifecycle.EvaluatedAtUnixNano,
		commitNotBeforeUnixNano: maximumInt64(materialPlan.CommitNotBeforeUnixNano(), lifecyclePlan.CommitNotBeforeUnixNano()),
		commitNotAfterUnixNano:  minimumInt64(materialPlan.CommitNotAfterUnixNano(), lifecyclePlan.CommitNotAfterUnixNano()),
		idempotencyCompletion:   completion}
	if result.commitNotBeforeUnixNano >= result.commitNotAfterUnixNano {
		return PendingKeyEnrollmentPlan{}, ErrInvalidCommitWindow
	}
	result.admission, err = newPendingAdmissionIntent(identifierReservations, idempotencyReservations,
		core, result.evaluatedAtUnixNano, result.commitNotBeforeUnixNano, result.commitNotAfterUnixNano)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	result.digest, err = keyEnrollmentPlanDigest(result)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	if err := result.VerifyDigest(); err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	return result, nil
}

type enrollmentOverlayView struct {
	View
	material KeyMaterialSnapshot
	globals  map[string]globalid.Snapshot
}

func newEnrollmentOverlayView(base View, material KeyMaterialSnapshot,
	claims []globalid.Claim) (*enrollmentOverlayView, error) {
	overlay := &enrollmentOverlayView{View: base, material: cloneKeyMaterial(material),
		globals: make(map[string]globalid.Snapshot, len(claims))}
	for _, claim := range claims {
		if err := claim.Validate(); err != nil {
			return nil, ErrGlobalIdentifier
		}
		overlay.globals[claim.Identifier] = globalid.Snapshot{Identifier: claim.Identifier,
			Owner: claim.Owner, Version: claim.NextVersion}
	}
	return overlay, nil
}

func (view *enrollmentOverlayView) LookupKeyMaterial(ctx context.Context, keyID string) (KeyMaterialSnapshot, bool, error) {
	if keyID == view.material.KeyID {
		return cloneKeyMaterial(view.material), true, nil
	}
	return view.View.LookupKeyMaterial(ctx, keyID)
}

func (view *enrollmentOverlayView) LookupGlobalID(ctx context.Context, identifier string) (globalid.Snapshot, bool, error) {
	if snapshot, ok := view.globals[identifier]; ok {
		return snapshot, true, nil
	}
	return view.View.LookupGlobalID(ctx, identifier)
}

func retainRecordClaims(claims []globalid.Claim) []globalid.Claim {
	result := make([]globalid.Claim, 0, len(claims))
	for _, claim := range claims {
		if claim.Owner.Domain == globalid.OwnerCanonicalRecord {
			result = append(result, claim)
		}
	}
	return result
}

func removePlannedMaterialDependency(dependencies []SnapshotPrecondition,
	material KeyMaterialSnapshot) []SnapshotPrecondition {
	result := make([]SnapshotPrecondition, 0, len(dependencies))
	for _, dependency := range dependencies {
		if dependency.Entity.Kind == EntityKeyMaterial && dependency.Entity.ID == material.KeyID {
			continue
		}
		result = append(result, dependency)
	}
	return result
}

func uniqueStrings(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return append([]string(nil), result...)
}

func uniqueDigests(values [][32]byte) [][32]byte {
	sort.Slice(values, func(i, j int) bool {
		for index := 0; index < 32; index++ {
			if values[i][index] != values[j][index] {
				return values[i][index] < values[j][index]
			}
		}
		return false
	})
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return append([][32]byte(nil), result...)
}

func keyEnrollmentPlanDigest(plan PendingKeyEnrollmentPlan) ([32]byte, error) {
	var zero [32]byte
	completionBytes, err := idempotency.CanonicalBytes(plan.idempotencyCompletion)
	if err != nil {
		return zero, fmt.Errorf("%w: enrollment completion claims: %v", ErrPendingPlanInvalid, err)
	}
	compositeMutationDigest, err := keyEnrollmentMutationCoreDigest(plan.material, plan.lifecycle)
	if err != nil {
		return zero, err
	}
	auditDigest := plan.audit.Digest()
	admissionDigest := plan.admission.Digest()
	encoded, err := ccse.Marshal(1<<20, func(out *ccse.Encoder) {
		out.FixedBytes(compositeMutationDigest[:], 32)
		out.FixedBytes(auditDigest[:], 32)
		out.FixedBytes(admissionDigest[:], 32)
		out.Int64(plan.evaluatedAtUnixNano)
		out.Int64(plan.commitNotBeforeUnixNano)
		out.Int64(plan.commitNotAfterUnixNano)
		out.Bytes(completionBytes)
	})
	if err != nil {
		return zero, err
	}
	return domainDigest(keyEnrollmentPlanDomain, encoded), nil
}

func keyEnrollmentMutationCoreDigest(material, lifecycle MutationPlan) ([32]byte, error) {
	var zero [32]byte
	if material.Kind() != MutationCreateKeyMaterial || lifecycle.Kind() != MutationAppendKeyLifecycle {
		return zero, ErrPendingPlanInvalid
	}
	materialDigest, lifecycleDigest := material.Digest(), lifecycle.Digest()
	encoded, err := ccse.Marshal(128, func(out *ccse.Encoder) {
		out.FixedBytes(materialDigest[:], 32)
		out.FixedBytes(lifecycleDigest[:], 32)
	})
	if err != nil {
		return zero, err
	}
	return domainDigest(keyEnrollmentPlanDomain+"MUTATION-CORE\x00", encoded), nil
}

func verifyPendingKeyEnrollmentPlan(plan PendingKeyEnrollmentPlan) error {
	if verifyMutationPlan(plan.material) != nil || verifyMutationPlan(plan.lifecycle) != nil || verifyAuditIntent(plan.audit) != nil ||
		plan.evaluatedAtUnixNano < 0 || plan.commitNotBeforeUnixNano < 0 ||
		plan.commitNotBeforeUnixNano >= plan.commitNotAfterUnixNano ||
		plan.audit.IdempotencyKey() == ([16]byte{}) || plan.audit.ExpectedAuditIdempotencyKey() == ([16]byte{}) ||
		plan.audit.IdempotencyKey() == plan.audit.ExpectedAuditIdempotencyKey() {
		return ErrPendingPlanInvalid
	}
	materialCAS, lifecycleCAS := plan.material.CAS(), plan.lifecycle.CAS()
	if len(materialCAS.IdempotencyClaims) != 0 || len(lifecycleCAS.IdempotencyClaims) != 0 ||
		verifyPendingAdmissionIntent(plan.admission) != nil ||
		plan.admission.EvaluatedAtUnixNano() != plan.evaluatedAtUnixNano ||
		plan.admission.CommitNotBeforeUnixNano() != plan.commitNotBeforeUnixNano ||
		plan.admission.CommitNotAfterUnixNano() != plan.commitNotAfterUnixNano {
		return ErrPendingPlanInvalid
	}
	compositeMutationDigest, err := keyEnrollmentMutationCoreDigest(plan.material, plan.lifecycle)
	if err != nil {
		return ErrPendingPlanInvalid
	}
	core := pendingCoreEvidenceDigest(compositeMutationDigest, plan.audit.Digest())
	if core != plan.admission.CoreEvidenceDigest() {
		return ErrPendingPlanInvalid
	}
	finalIdentifiers := append(materialCAS.IdentifierClaims, lifecycleCAS.IdentifierClaims...)
	if !stagedReservationsMatchFinalClaims(plan.admission.identifierReservations, finalIdentifiers) {
		return ErrPendingPlanInvalid
	}
	parent, joined, err := pendingIdempotencyBindings(plan.admission.idempotencyReservations)
	if err != nil || plan.audit.IdempotencyKey() != parent.Key ||
		plan.audit.ExpectedAuditIdempotencyKey() != joined.Key {
		return ErrPendingPlanInvalid
	}
	if err := verifyJoinedAuditEventClaims(parent, plan.audit,
		plan.admission.identifierReservations, finalIdentifiers); err != nil {
		return err
	}
	expectedCompletion, err := pendingCompletionClaims(plan.admission.idempotencyReservations)
	if err != nil || !sameIdempotencyClaims(expectedCompletion, plan.idempotencyCompletion) {
		return ErrPendingPlanInvalid
	}
	digest, err := keyEnrollmentPlanDigest(plan)
	if err != nil || digest != plan.digest {
		return ErrPendingPlanInvalid
	}
	return nil
}
