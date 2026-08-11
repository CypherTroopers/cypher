// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"bytes"
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
	ownershipTransferCutoverCoreDomain           = "CPH-AIIE-IAM-OWNERSHIP-TRANSFER-CUTOVER-CORE-V1\x00"
	ownershipTransferCutoverMemberDomain         = "CPH-AIIE-IAM-OWNERSHIP-TRANSFER-CUTOVER-MEMBER-V1\x00"
	ownershipTransferCutoverPlanDomain           = "CPH-AIIE-IAM-OWNERSHIP-TRANSFER-CUTOVER-PLAN-V1\x00"
	ownershipTransferCutoverStepEvidenceDomain   = "CPH-AIIE-IAM-OWNERSHIP-TRANSFER-CUTOVER-STEP-EVIDENCE-V1\x00"
	ownershipTransferCutoverRecordEvidenceDomain = "CPH-AIIE-IAM-OWNERSHIP-TRANSFER-CUTOVER-RECORD-EVIDENCE-V1\x00"
)

// OwnershipTransferCutoverStepKind fixes the only legal execution order. A
// durable adapter applies all steps in one SERIALIZABLE transaction and may
// observe a dependency on an earlier step only inside that same transaction.
type OwnershipTransferCutoverStepKind uint8

const (
	CutoverClosePreviousKey OwnershipTransferCutoverStepKind = iota + 1
	CutoverTerminalPreviousIdentity
	CutoverCreateNextKeyMaterial
	CutoverCreateNextKeyLifecycle
	CutoverCreateNextIdentity
)

// OwnershipTransferCutoverCommand supplies the signed preimages which are not
// part of the accepted authorization row. Key-closure signed records are
// already retained by AcceptedOwnershipTransferSnapshot; only their current
// writer fences are supplied here. Every command timestamp and transfer digest
// must equal the outer values.
type OwnershipTransferCutoverCommand struct {
	TransferEvidenceDigest   [32]byte
	PreviousTerminalIdentity IdentityCommand
	KeyClosureWriterFences   []WriterFence
	NewKeyEnrollment         KeyEnrollmentCommand
	NextPendingIdentity      IdentityCommand
	AuthenticatedEvidence    []ccse.AuthenticatedEvidenceRecord
	EvaluatedAtUnixNano      int64
}

// OwnershipTransferCutoverStep is one detached write in the fixed compound
// order. It is not independently committable.
type OwnershipTransferCutoverStep struct {
	Kind                OwnershipTransferCutoverStepKind
	Mutation            MutationPlan
	PlannedPredecessors []SnapshotPrecondition
}

func cloneCutoverStep(source OwnershipTransferCutoverStep) OwnershipTransferCutoverStep {
	result := source
	result.Mutation = cloneMutationPlan(source.Mutation)
	result.PlannedPredecessors = append([]SnapshotPrecondition(nil), source.PlannedPredecessors...)
	return result
}

// PendingOwnershipTransferCutoverPlan is one noncommittable atomic write set.
// Authorization acceptance remains a separate completed operation; this plan
// either commits every state row below together with its canonical audit or
// changes no business state at all.
type PendingOwnershipTransferCutoverPlan struct {
	accepted                AcceptedOwnershipTransferSnapshot
	steps                   []OwnershipTransferCutoverStep
	dependencies            []SnapshotPrecondition
	evidence                []RetainedVerifiedRecord
	audit                   AuditIntent
	evaluatedAtUnixNano     int64
	commitNotBeforeUnixNano int64
	commitNotAfterUnixNano  int64
	admission               PendingAdmissionIntent
	idempotencyCompletion   []idempotency.Claim
	memberAdmission         []idempotency.CompoundMemberClaim
	memberCompletion        []idempotency.CompoundMemberClaim
	identifierAssertions    []globalid.Claim
	digest                  [32]byte
}

func clonePendingOwnershipTransferCutoverPlan(source PendingOwnershipTransferCutoverPlan) (
	result PendingOwnershipTransferCutoverPlan) {
	result = source
	result.accepted = cloneAcceptedTransfer(source.accepted)
	result.steps = make([]OwnershipTransferCutoverStep, len(source.steps))
	for index := range source.steps {
		result.steps[index] = cloneCutoverStep(source.steps[index])
	}
	result.dependencies = append([]SnapshotPrecondition(nil), source.dependencies...)
	result.evidence = cloneRetainedRecords(source.evidence)
	result.audit = cloneAuditIntent(source.audit)
	result.admission = source.admission.detached()
	result.idempotencyCompletion = append([]idempotency.Claim(nil), source.idempotencyCompletion...)
	result.memberAdmission = append([]idempotency.CompoundMemberClaim(nil), source.memberAdmission...)
	result.memberCompletion = append([]idempotency.CompoundMemberClaim(nil), source.memberCompletion...)
	result.identifierAssertions = append([]globalid.Claim(nil), source.identifierAssertions...)
	return result
}

func (PendingOwnershipTransferCutoverPlan) CommitReady() bool     { return false }
func (plan PendingOwnershipTransferCutoverPlan) Digest() [32]byte { return plan.digest }
func (plan PendingOwnershipTransferCutoverPlan) AcceptedTransfer() AcceptedOwnershipTransferSnapshot {
	return cloneAcceptedTransfer(plan.accepted)
}
func (plan PendingOwnershipTransferCutoverPlan) Steps() []OwnershipTransferCutoverStep {
	result := make([]OwnershipTransferCutoverStep, len(plan.steps))
	for index := range plan.steps {
		result[index] = cloneCutoverStep(plan.steps[index])
	}
	return result
}
func (plan PendingOwnershipTransferCutoverPlan) Dependencies() []SnapshotPrecondition {
	return append([]SnapshotPrecondition(nil), plan.dependencies...)
}
func (plan PendingOwnershipTransferCutoverPlan) EvidenceRecords() []RetainedVerifiedRecord {
	return cloneRetainedRecords(plan.evidence)
}
func (plan PendingOwnershipTransferCutoverPlan) AuditIntent() AuditIntent {
	return cloneAuditIntent(plan.audit)
}
func (plan PendingOwnershipTransferCutoverPlan) EvaluatedAtUnixNano() int64 {
	return plan.evaluatedAtUnixNano
}
func (plan PendingOwnershipTransferCutoverPlan) CommitNotBeforeUnixNano() int64 {
	return plan.commitNotBeforeUnixNano
}
func (plan PendingOwnershipTransferCutoverPlan) CommitNotAfterUnixNano() int64 {
	return plan.commitNotAfterUnixNano
}
func (plan PendingOwnershipTransferCutoverPlan) AdmissionIntent() PendingAdmissionIntent {
	return plan.admission.detached()
}
func (plan PendingOwnershipTransferCutoverPlan) IdempotencyCompletionClaims() []idempotency.Claim {
	return append([]idempotency.Claim(nil), plan.idempotencyCompletion...)
}
func (plan PendingOwnershipTransferCutoverPlan) CompoundMemberAdmissionClaims() []idempotency.CompoundMemberClaim {
	return append([]idempotency.CompoundMemberClaim(nil), plan.memberAdmission...)
}
func (plan PendingOwnershipTransferCutoverPlan) CompoundMemberCompletionClaims() []idempotency.CompoundMemberClaim {
	return append([]idempotency.CompoundMemberClaim(nil), plan.memberCompletion...)
}
func (plan PendingOwnershipTransferCutoverPlan) IdentifierAssertions() []globalid.Claim {
	return append([]globalid.Claim(nil), plan.identifierAssertions...)
}
func (plan PendingOwnershipTransferCutoverPlan) VerifyDigest() error {
	return verifyOwnershipTransferCutoverPlan(plan)
}

func cloneMutationPlan(source MutationPlan) MutationPlan {
	result := source
	result.cas = cloneCASIntent(source.cas)
	if source.material != nil {
		value := cloneKeyMaterial(*source.material)
		result.material = &value
	}
	if source.identity != nil {
		value := cloneIdentity(*source.identity)
		result.identity = &value
	}
	if source.lifecycle != nil {
		value := cloneLifecycle(*source.lifecycle)
		result.lifecycle = &value
	}
	return result
}

// PlanOwnershipTransferCutover is retained as an explicit fail-closed API
// boundary. A cutover admission may only be constructed together with the
// quorum-collection acceptance transaction, or reissued from its durably
// revalidated pending envelope.
func (p *Planner) PlanOwnershipTransferCutover(ctx context.Context,
	command OwnershipTransferCutoverCommand) (PendingOwnershipTransferCutoverPlan, error) {
	_ = ctx
	_ = command
	return PendingOwnershipTransferCutoverPlan{}, ErrTransferAuthorizationRequired
}

type ownershipTransferCutoverCandidateToken struct{}

func (p *Planner) planOwnershipTransferCutoverCandidate(ctx context.Context,
	command OwnershipTransferCutoverCommand, _ ownershipTransferCutoverCandidateToken) (
	PendingOwnershipTransferCutoverPlan, error) {
	if err := p.ready(); err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	if command.TransferEvidenceDigest == ([32]byte{}) || command.EvaluatedAtUnixNano < 0 ||
		len(command.KeyClosureWriterFences) > 256 {
		return PendingOwnershipTransferCutoverPlan{}, ErrTransferAuthorizationRequired
	}
	accepted, err := p.resolveAcceptedTransfer(ctx, command.TransferEvidenceDigest,
		command.EvaluatedAtUnixNano)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	if err := validateCutoverCommandEnvelope(command, accepted); err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	evidencePool, err := newCutoverEvidencePool(command.AuthenticatedEvidence)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	return p.planOwnershipTransferCutoverWithEvidence(ctx, command, accepted, evidencePool)
}

func (p *Planner) planOwnershipTransferCutoverWithEvidence(ctx context.Context,
	command OwnershipTransferCutoverCommand, accepted acceptedTransferValidation,
	evidencePool *cutoverEvidencePool) (PendingOwnershipTransferCutoverPlan, error) {
	cutoverBinding, err := idempotency.OwnershipTransferCutoverBinding(snapshotBinding(accepted.Snapshot))
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, ErrPendingPlanInvalid
	}
	joinedBinding, err := p.precheckPendingIdempotency(ctx, cutoverBinding)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	auditEventID, err := idempotency.JoinedAuditEventID(cutoverBinding)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, ErrPendingPlanInvalid
	}

	overlay := newCutoverOverlayView(p.view, accepted)
	worker := *p
	worker.view = overlay
	steps := make([]OwnershipTransferCutoverStep, 0,
		len(accepted.Snapshot.FixedEvidence.KeyClosureSnapshots)+4)
	members := make([]cutoverMember, 0, len(accepted.Snapshot.FixedEvidence.KeyClosureSnapshots)+3)
	evidence := make([]RetainedVerifiedRecord, 0,
		3)

	fences, err := indexCutoverClosureFences(command.KeyClosureWriterFences,
		accepted.Snapshot.FixedEvidence.KeyClosureSnapshots)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	for _, expected := range accepted.Snapshot.FixedEvidence.KeyClosureSnapshots {
		record, found := retainedClosureRecord(accepted.Snapshot.FixedEvidence, expected)
		if !found {
			return PendingOwnershipTransferCutoverPlan{}, ErrTransferAuthorizationRequired
		}
		// Closure records are already retained in the accepted authorization and
		// committed by its SnapshotDigest. Reuse that owned preimage instead of
		// requiring and retaining a second AuthenticatedEvidence copy.
		authorization, err := authorizationFromSignedRecord(record.record)
		if err != nil || authorization.recordDigest != record.digest {
			return PendingOwnershipTransferCutoverPlan{}, ErrTransferAuthorizationRequired
		}
		projection, err := decodeLifecycleSnapshotProjection(expected)
		if err != nil {
			return PendingOwnershipTransferCutoverPlan{}, err
		}
		memberCommand := KeyLifecycleCommand{Projection: projection,
			ActorIdentity: authorization.senderIdentity, EvaluatedAtUnixNano: command.EvaluatedAtUnixNano,
			CorrelationID: authorization.correlationID, CausationID: authorization.causationID,
			CauseCode: "ownership-transfer-cutover", Fence: fences[expected.KeyID],
			Authorization: authorization, TransferEvidenceDigest: command.TransferEvidenceDigest}
		mutation, _, err := worker.planKeyLifecycle(ctx, memberCommand, false, true)
		if err != nil {
			return PendingOwnershipTransferCutoverPlan{}, err
		}
		binding, err := cutoverMemberBinding(mutation.CAS().IdempotencyClaims)
		if err != nil {
			return PendingOwnershipTransferCutoverPlan{}, err
		}
		mutation, err = stripCutoverChildClaims(mutation)
		if err != nil {
			return PendingOwnershipTransferCutoverPlan{}, err
		}
		steps = append(steps, OwnershipTransferCutoverStep{Kind: CutoverClosePreviousKey, Mutation: mutation})
		members = append(members, cutoverMember{Binding: binding, MutationDigest: mutation.Digest()})
		overlay.putLifecycle(expected)
	}

	previousEvidence, found := evidencePool.takePayload(
		accepted.Snapshot.FixedEvidence.PreviousTerminalIdentity.MessageTypeID,
		accepted.Snapshot.FixedEvidence.PreviousTerminalIdentity.CanonicalPayload)
	if !found {
		return PendingOwnershipTransferCutoverPlan{}, ErrTransferAuthorizationRequired
	}
	previousAuthorization, err := authorizationFromSignedRecord(previousEvidence.record)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	command.PreviousTerminalIdentity = bindCutoverIdentityAuthorization(
		command.PreviousTerminalIdentity, previousAuthorization)
	previousMutation, _, err := worker.planIdentity(ctx, command.PreviousTerminalIdentity, true)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	previousBinding, err := cutoverMemberBinding(previousMutation.CAS().IdempotencyClaims)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	previousMutation, err = stripCutoverChildClaims(previousMutation)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	steps = append(steps, OwnershipTransferCutoverStep{Kind: CutoverTerminalPreviousIdentity,
		Mutation: previousMutation})
	members = append(members, cutoverMember{Binding: previousBinding, MutationDigest: previousMutation.Digest()})
	evidence = append(evidence, previousEvidence)
	overlay.putIdentity(accepted.Snapshot.FixedEvidence.PreviousTerminalIdentity)

	requestedLifecycle, err := NormalizeKeyLifecycle(command.NewKeyEnrollment.Lifecycle.Projection)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	enrollmentEvidence, found := evidencePool.takePayload(schema.MessageTypeKeyLifecycle,
		requestedLifecycle.CanonicalPayload)
	if !found {
		return PendingOwnershipTransferCutoverPlan{}, ErrTransferAuthorizationRequired
	}
	enrollmentAuthorization, err := authorizationFromSignedRecord(enrollmentEvidence.record)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	command.NewKeyEnrollment.Lifecycle = bindCutoverLifecycleAuthorization(
		command.NewKeyEnrollment.Lifecycle, enrollmentAuthorization)
	enrollment, err := worker.planKeyEnrollment(ctx, command.NewKeyEnrollment, true)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	enrollmentParent, _, err := pendingIdempotencyBindings(enrollment.admission.idempotencyReservations)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	materialPlan, lifecyclePlan, reservations, err := cutoverEnrollmentMutations(enrollment)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	steps = append(steps,
		OwnershipTransferCutoverStep{Kind: CutoverCreateNextKeyMaterial, Mutation: materialPlan},
		OwnershipTransferCutoverStep{Kind: CutoverCreateNextKeyLifecycle, Mutation: lifecyclePlan})
	enrollmentDigest, err := keyEnrollmentMutationCoreDigest(materialPlan, lifecyclePlan)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	members = append(members, cutoverMember{Binding: enrollmentParent, MutationDigest: enrollmentDigest})
	evidence = append(evidence, enrollmentEvidence)
	material, materialOK := materialPlan.KeyMaterial()
	lifecycle, lifecycleOK := lifecyclePlan.KeyLifecycle()
	if !materialOK || !lifecycleOK {
		return PendingOwnershipTransferCutoverPlan{}, ErrPendingPlanInvalid
	}
	overlay.putMaterial(material)
	overlay.putLifecycle(lifecycle)

	nextEvidence, found := evidencePool.takePayload(
		accepted.Snapshot.FixedEvidence.NextPendingIdentity.MessageTypeID,
		accepted.Snapshot.FixedEvidence.NextPendingIdentity.CanonicalPayload)
	if !found {
		return PendingOwnershipTransferCutoverPlan{}, ErrTransferAuthorizationRequired
	}
	nextAuthorization, err := authorizationFromSignedRecord(nextEvidence.record)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	command.NextPendingIdentity = bindCutoverIdentityAuthorization(
		command.NextPendingIdentity, nextAuthorization)
	nextMutation, _, err := worker.planIdentity(ctx, command.NextPendingIdentity, true)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	nextBinding, err := cutoverMemberBinding(nextMutation.CAS().IdempotencyClaims)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	nextMutation, err = stripCutoverChildClaims(nextMutation)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	steps = append(steps, OwnershipTransferCutoverStep{Kind: CutoverCreateNextIdentity, Mutation: nextMutation})
	members = append(members, cutoverMember{Binding: nextBinding, MutationDigest: nextMutation.Digest()})
	evidence = append(evidence, nextEvidence)

	window, err := intersectCutoverWindow(command.EvaluatedAtUnixNano, accepted, steps)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	for index := range steps {
		steps[index].Mutation, err = rebuildCutoverMutationWindow(steps[index].Mutation, window)
		if err != nil {
			return PendingOwnershipTransferCutoverPlan{}, err
		}
	}
	steps, preStateDependencies, err := partitionCutoverDependencies(steps, accepted.Dependencies)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	// Window rebinding changes mutation digests; rebuild the member association
	// in the same fixed order (enrollment is the only two-step member).
	members, err = rebindCutoverMemberDigests(members, steps)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	if !evidencePool.empty() {
		return PendingOwnershipTransferCutoverPlan{}, ErrTransferAuthorizationRequired
	}
	evidence, err = normalizeCutoverEvidence(evidence)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	audit, err := newOwnershipTransferCutoverAudit(cutoverBinding, joinedBinding, auditEventID,
		accepted, steps, evidence, command.EvaluatedAtUnixNano)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	members, err = validateCutoverMembers(ctx, p.view, members, cutoverBinding)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}

	identifierAssertions, identifierReservations, err := stageCutoverIdentifiers(steps, reservations,
		cutoverBinding, auditEventID)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	core, err := ownershipTransferCutoverCoreDigest(accepted.Snapshot, steps,
		preStateDependencies, evidence, audit)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	idempotencyReservations, memberReservations, err := cutoverIdempotencyReservations(
		cutoverBinding, joinedBinding, members, audit.Digest(), core)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	completion, err := pendingCompletionClaims(idempotencyReservations)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	memberCompletion, err := cutoverMemberCompletionClaims(memberReservations)
	if err != nil || idempotency.ValidateDisjointClaimKeys(idempotencyReservations, memberReservations) != nil ||
		idempotency.ValidateDisjointClaimKeys(completion, memberCompletion) != nil {
		return PendingOwnershipTransferCutoverPlan{}, ErrPendingPlanInvalid
	}
	admission, err := newPendingAdmissionIntent(identifierReservations, idempotencyReservations,
		core, window.EvaluatedAtUnixNano, window.CommitNotBeforeUnixNano, window.CommitNotAfterUnixNano)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	plan := PendingOwnershipTransferCutoverPlan{accepted: cloneAcceptedTransfer(accepted.Snapshot),
		steps: steps, dependencies: preStateDependencies,
		evidence: evidence, audit: audit, evaluatedAtUnixNano: window.EvaluatedAtUnixNano,
		commitNotBeforeUnixNano: window.CommitNotBeforeUnixNano,
		commitNotAfterUnixNano:  window.CommitNotAfterUnixNano, admission: admission,
		idempotencyCompletion: completion, memberAdmission: memberReservations,
		memberCompletion: memberCompletion, identifierAssertions: identifierAssertions}
	plan.digest, err = ownershipTransferCutoverPlanDigest(plan)
	if err != nil || plan.VerifyDigest() != nil {
		return PendingOwnershipTransferCutoverPlan{}, ErrPendingPlanInvalid
	}
	return plan, nil
}

type cutoverMember struct {
	Binding        idempotency.Binding
	MutationDigest [32]byte
}

func validateCutoverCommandEnvelope(command OwnershipTransferCutoverCommand,
	accepted acceptedTransferValidation) error {
	digest := command.TransferEvidenceDigest
	if command.PreviousTerminalIdentity.TransferEvidenceDigest != digest ||
		command.NextPendingIdentity.TransferEvidenceDigest != digest ||
		command.NewKeyEnrollment.Material.TransferEvidenceDigest != digest ||
		command.NewKeyEnrollment.Lifecycle.TransferEvidenceDigest != digest ||
		command.PreviousTerminalIdentity.EvaluatedAtUnixNano != command.EvaluatedAtUnixNano ||
		command.NextPendingIdentity.EvaluatedAtUnixNano != command.EvaluatedAtUnixNano ||
		command.NewKeyEnrollment.Material.EvaluatedAtUnixNano != command.EvaluatedAtUnixNano ||
		command.NewKeyEnrollment.Lifecycle.EvaluatedAtUnixNano != command.EvaluatedAtUnixNano {
		return ErrTransferAuthorizationRequired
	}
	previous, err := NormalizeIdentity(command.PreviousTerminalIdentity.Projection)
	if err != nil || !acceptedTransferMatchesIdentity(accepted, previous) ||
		!bytes.Equal(previous.CanonicalPayload,
			accepted.Snapshot.FixedEvidence.PreviousTerminalIdentity.CanonicalPayload) {
		return ErrTransferAuthorizationRequired
	}
	next, err := NormalizeIdentity(command.NextPendingIdentity.Projection)
	if err != nil || !acceptedTransferMatchesIdentity(accepted, next) ||
		!bytes.Equal(next.CanonicalPayload,
			accepted.Snapshot.FixedEvidence.NextPendingIdentity.CanonicalPayload) ||
		!acceptedTransferMatchesKeyEnrollment(accepted, command.NewKeyEnrollment) {
		return ErrTransferAuthorizationRequired
	}
	return nil
}

func indexCutoverClosureFences(fences []WriterFence,
	closures []KeyLifecycleSnapshot) (map[string]WriterFence, error) {
	if len(fences) != len(closures) {
		return nil, ErrTransferAuthorizationRequired
	}
	expected := make(map[string]struct{}, len(closures))
	for _, closure := range closures {
		if closure.KeyID == "" {
			return nil, ErrTransferAuthorizationRequired
		}
		expected[closure.KeyID] = struct{}{}
	}
	result := make(map[string]WriterFence, len(fences))
	for _, fence := range fences {
		if _, ok := expected[fence.Entity.ID]; !ok || fence.Entity.Kind != EntityKeyLifecycle ||
			fence.Entity.ID == "" {
			return nil, ErrTransferAuthorizationRequired
		}
		if _, duplicate := result[fence.Entity.ID]; duplicate {
			return nil, ErrTransferAuthorizationRequired
		}
		result[fence.Entity.ID] = fence
	}
	return result, nil
}

func retainedClosureRecord(fixed OwnershipTransferFixedEvidence,
	expected KeyLifecycleSnapshot) (RetainedVerifiedRecord, bool) {
	for _, retained := range fixed.KeyClosureRecords {
		if bytes.Equal(retained.record.Payload, expected.CanonicalPayload) {
			return RetainedVerifiedRecord{record: cloneCCSERecord(retained.record), digest: retained.digest}, true
		}
	}
	return RetainedVerifiedRecord{}, false
}

func cutoverMemberBinding(claims []idempotency.Claim) (idempotency.Binding, error) {
	parent, _, err := pendingIdempotencyBindings(claims)
	return parent, err
}

func stripCutoverChildClaims(plan MutationPlan) (MutationPlan, error) {
	cas := plan.CAS()
	cas.IdempotencyClaims = nil
	return rebuildMutationPlan(plan, cas)
}

func cutoverEnrollmentMutations(plan PendingKeyEnrollmentPlan) (MutationPlan, MutationPlan,
	[]globalid.Claim, error) {
	if err := plan.VerifyDigest(); err != nil {
		return MutationPlan{}, MutationPlan{}, nil, err
	}
	material := cloneMutationPlan(plan.material)
	lifecycle := cloneMutationPlan(plan.lifecycle)
	materialCAS := material.CAS()
	// The child key-enrollment audit EventID is intentionally absent: the
	// cutover has one umbrella canonical audit. Its other staged reservations
	// (notably the new PREACTIVE RecordID) remain permanent.
	filtered := materialCAS.IdentifierClaims[:0]
	for _, claim := range materialCAS.IdentifierClaims {
		if claim.Owner.Domain != globalid.OwnerGovernanceAuditEvent {
			filtered = append(filtered, claim)
		}
	}
	materialCAS.IdentifierClaims = append([]globalid.Claim(nil), filtered...)
	var err error
	material, err = rebuildMutationPlan(material, materialCAS)
	if err != nil {
		return MutationPlan{}, MutationPlan{}, nil, err
	}
	reservations := make([]globalid.Claim, 0, len(plan.admission.identifierReservations))
	for _, claim := range plan.admission.identifierReservations {
		if claim.Owner.Domain != globalid.OwnerGovernanceAuditEvent {
			reservations = append(reservations, claim)
		}
	}
	if len(reservations) == 0 {
		return MutationPlan{}, MutationPlan{}, nil, ErrPendingPlanInvalid
	}
	reservations, err = normalizeGlobalClaims(reservations)
	return material, lifecycle, reservations, err
}

type cutoverEvidencePool struct {
	values map[[32]byte]RetainedVerifiedRecord
}

func newCutoverEvidencePool(values []ccse.AuthenticatedEvidenceRecord) (*cutoverEvidencePool, error) {
	if len(values) != 3 {
		return nil, ErrTransferAuthorizationRequired
	}
	var aggregate uint64
	for _, value := range values {
		switch value.MessageTypeID() {
		case schema.MessageTypeAgentIdentity, schema.MessageTypeHostIdentity,
			schema.MessageTypeDeviceIdentity, schema.MessageTypeKeyLifecycle:
		default:
			return nil, ErrTransferAuthorizationRequired
		}
		size, sizeErr := value.PreflightSize(transferVerifiedRecordLimits(32768))
		if value.SchemaVersion() != (ccse.Version{Major: 1}) || sizeErr != nil || size == 0 ||
			size > maxTransferCompoundInputBytes || aggregate > maxTransferCompoundInputBytes-size {
			return nil, ErrTransferAuthorizationRequired
		}
		aggregate += size
	}
	pool := &cutoverEvidencePool{values: make(map[[32]byte]RetainedVerifiedRecord, len(values))}
	for _, value := range values {
		record := value.Record()
		digest, err := record.Digest(ccse.DefaultLimits())
		if err != nil || digest == ([32]byte{}) || digest != value.Digest() ||
			record.MessageTypeID != value.MessageTypeID() || record.SchemaVersion != value.SchemaVersion() {
			return nil, ErrTransferAuthorizationRequired
		}
		if _, err := canonicalSignedAuthorizationEvidence(record); err != nil {
			return nil, ErrTransferAuthorizationRequired
		}
		if _, duplicate := pool.values[digest]; duplicate {
			return nil, ErrTransferAuthorizationRequired
		}
		pool.values[digest] = RetainedVerifiedRecord{record: record, digest: digest}
	}
	return pool, nil
}

func (pool *cutoverEvidencePool) takePayload(messageTypeID uint32,
	payload []byte) (RetainedVerifiedRecord, bool) {
	var match RetainedVerifiedRecord
	var digest [32]byte
	found := false
	for candidateDigest, value := range pool.values {
		if value.record.MessageTypeID != messageTypeID || !bytes.Equal(value.record.Payload, payload) {
			continue
		}
		if found {
			return RetainedVerifiedRecord{}, false
		}
		match, digest, found = value, candidateDigest, true
	}
	if found {
		delete(pool.values, digest)
	}
	return match, found
}

func (pool *cutoverEvidencePool) empty() bool { return len(pool.values) == 0 }

func bindCutoverIdentityAuthorization(command IdentityCommand,
	authorization VerifiedAuthorization) IdentityCommand {
	command.Authorization = authorization
	command.ActorIdentity = authorization.senderIdentity
	command.CorrelationID = authorization.correlationID
	command.CausationID = authorization.causationID
	return command
}

func bindCutoverLifecycleAuthorization(command KeyLifecycleCommand,
	authorization VerifiedAuthorization) KeyLifecycleCommand {
	command.Authorization = authorization
	command.ActorIdentity = authorization.senderIdentity
	command.CorrelationID = authorization.correlationID
	command.CausationID = authorization.causationID
	return command
}

func normalizeCutoverEvidence(values []RetainedVerifiedRecord) ([]RetainedVerifiedRecord, error) {
	if len(values) != 3 {
		return nil, ErrPendingPlanInvalid
	}
	result := cloneRetainedRecords(values)
	for _, value := range result {
		if _, err := canonicalRetainedRecord(value); err != nil {
			return nil, ErrPendingPlanInvalid
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return bytes.Compare(result[i].digest[:], result[j].digest[:]) < 0
	})
	for index := 1; index < len(result); index++ {
		if result[index-1].digest == result[index].digest {
			return nil, ErrPendingPlanInvalid
		}
	}
	return result, nil
}

func validateCutoverMembers(ctx context.Context, view View, members []cutoverMember,
	cutover idempotency.Binding) ([]cutoverMember, error) {
	compoundView, ok := view.(idempotency.CompoundMemberView)
	if !ok {
		return nil, ErrViewRequired
	}
	result := append([]cutoverMember(nil), members...)
	for index := range result {
		decision, precheckErr := idempotency.PrecheckCompoundMemberForParent(ctx,
			compoundView, cutover, result[index].Binding)
		if precheckErr != nil || decision.Kind() != idempotency.Proceed {
			return nil, ErrPendingPlanInvalid
		}
	}
	return result, nil
}

func intersectCutoverWindow(at int64, accepted acceptedTransferValidation,
	steps []OwnershipTransferCutoverStep) (planWindow, error) {
	starts := []int64{accepted.AuthorityValidFromNano, accepted.Snapshot.Projection.EffectiveAtUnixNano}
	ends := []int64{accepted.AuthorityValidUntilNano, accepted.Snapshot.Projection.ExpiresAtUnixNano}
	for _, step := range steps {
		if step.Mutation.EvaluatedAtUnixNano() != at {
			return planWindow{}, ErrInvalidCommitWindow
		}
		starts = append(starts, step.Mutation.CommitNotBeforeUnixNano())
		ends = append(ends, step.Mutation.CommitNotAfterUnixNano())
	}
	window := planWindow{EvaluatedAtUnixNano: at, CommitNotBeforeUnixNano: at,
		CommitNotAfterUnixNano: accepted.Snapshot.Projection.ExpiresAtUnixNano}
	for _, value := range starts {
		window.CommitNotBeforeUnixNano = maximumInt64(window.CommitNotBeforeUnixNano, value)
	}
	for _, value := range ends {
		window.CommitNotAfterUnixNano = minimumInt64(window.CommitNotAfterUnixNano, value)
	}
	if window.CommitNotBeforeUnixNano > at || window.CommitNotAfterUnixNano <= at {
		return planWindow{}, ErrInvalidCommitWindow
	}
	return window, nil
}

func rebuildCutoverMutationWindow(plan MutationPlan, window planWindow) (MutationPlan, error) {
	cas := plan.CAS()
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

// partitionCutoverDependencies separates immutable pre-state assertions from
// edges which intentionally name an output of an earlier step. An executor
// checks every pre-state dependency before its first write, then applies steps
// in order and checks only PlannedPredecessors between writes.
func partitionCutoverDependencies(steps []OwnershipTransferCutoverStep,
	base []SnapshotPrecondition) ([]OwnershipTransferCutoverStep, []SnapshotPrecondition, error) {
	preState := append([]SnapshotPrecondition(nil), base...)
	outputs := make(map[EntityRef]SnapshotPrecondition, len(steps))
	result := make([]OwnershipTransferCutoverStep, len(steps))
	for index, step := range steps {
		result[index] = cloneCutoverStep(step)
		cas := step.Mutation.CAS()
		planned := make([]SnapshotPrecondition, 0, len(cas.Dependencies))
		for _, dependency := range cas.Dependencies {
			if output, found := outputs[dependency.Entity]; found && output == dependency {
				planned = append(planned, dependency)
			} else {
				preState = append(preState, dependency)
			}
		}
		var err error
		planned, err = canonicalPreconditions(planned)
		if err != nil {
			return nil, nil, err
		}
		result[index].PlannedPredecessors = planned
		cas.Dependencies = nil
		result[index].Mutation, err = rebuildMutationPlan(step.Mutation, cas)
		if err != nil {
			return nil, nil, err
		}
		output, err := cutoverMutationOutputPrecondition(result[index].Mutation)
		if err != nil {
			return nil, nil, err
		}
		if _, duplicate := outputs[output.Entity]; duplicate {
			return nil, nil, ErrPendingPlanInvalid
		}
		outputs[output.Entity] = output
	}
	var err error
	preState, err = canonicalPreconditions(preState)
	if err != nil || len(preState) == 0 {
		return nil, nil, ErrPendingPlanInvalid
	}
	return result, preState, nil
}

func cutoverMutationOutputPrecondition(plan MutationPlan) (SnapshotPrecondition, error) {
	switch plan.Kind() {
	case MutationCreateKeyMaterial:
		value, ok := plan.KeyMaterial()
		if !ok {
			return SnapshotPrecondition{}, ErrPendingPlanInvalid
		}
		return materialPrecondition(value), nil
	case MutationAppendIdentity:
		value, ok := plan.Identity()
		if !ok {
			return SnapshotPrecondition{}, ErrPendingPlanInvalid
		}
		return identityPrecondition(value), nil
	case MutationAppendKeyLifecycle:
		value, ok := plan.KeyLifecycle()
		if !ok {
			return SnapshotPrecondition{}, ErrPendingPlanInvalid
		}
		return lifecyclePrecondition(value), nil
	default:
		return SnapshotPrecondition{}, ErrPendingPlanInvalid
	}
}

func rebindCutoverMemberDigests(members []cutoverMember,
	steps []OwnershipTransferCutoverStep) ([]cutoverMember, error) {
	closureCount := len(steps) - 4
	if closureCount < 1 || len(members) != closureCount+3 ||
		len(steps) != closureCount+4 {
		return nil, ErrPendingPlanInvalid
	}
	result := append([]cutoverMember(nil), members...)
	for index := 0; index < closureCount; index++ {
		result[index].MutationDigest = steps[index].Mutation.Digest()
	}
	result[closureCount].MutationDigest = steps[closureCount].Mutation.Digest()
	enrollmentDigest, err := keyEnrollmentMutationCoreDigest(steps[closureCount+1].Mutation,
		steps[closureCount+2].Mutation)
	if err != nil {
		return nil, err
	}
	result[closureCount+1].MutationDigest = enrollmentDigest
	result[closureCount+2].MutationDigest = steps[closureCount+3].Mutation.Digest()
	return result, nil
}

type cutoverOverlayView struct {
	View
	transferDigest [32]byte
	legacy         OwnershipTransferSnapshot
	identities     map[EntityRef]IdentitySnapshot
	materials      map[string]KeyMaterialSnapshot
	lifecycles     map[string]KeyLifecycleSnapshot
}

func newCutoverOverlayView(base View, accepted acceptedTransferValidation) *cutoverOverlayView {
	return &cutoverOverlayView{View: base, transferDigest: accepted.Snapshot.TransferEvidenceDigest,
		legacy: accepted.Legacy, identities: make(map[EntityRef]IdentitySnapshot),
		materials: make(map[string]KeyMaterialSnapshot), lifecycles: make(map[string]KeyLifecycleSnapshot)}
}

func (view *cutoverOverlayView) putIdentity(snapshot IdentitySnapshot) {
	view.identities[snapshot.Ref] = cloneIdentity(snapshot)
}
func (view *cutoverOverlayView) putMaterial(snapshot KeyMaterialSnapshot) {
	view.materials[snapshot.KeyID] = cloneKeyMaterial(snapshot)
}
func (view *cutoverOverlayView) putLifecycle(snapshot KeyLifecycleSnapshot) {
	view.lifecycles[snapshot.KeyID] = cloneLifecycle(snapshot)
}

func (view *cutoverOverlayView) LookupIdentity(ctx context.Context,
	ref EntityRef) (IdentitySnapshot, bool, error) {
	if snapshot, ok := view.identities[ref]; ok {
		return cloneIdentity(snapshot), true, nil
	}
	return view.View.LookupIdentity(ctx, ref)
}

func (view *cutoverOverlayView) LookupIdentityByPrincipal(ctx context.Context, kind uint32,
	principal string) (IdentitySnapshot, bool, error) {
	// A persistent Host/Device principal continues to resolve to the planned
	// terminal old identity until the final principal-index transfer step.
	for _, snapshot := range view.identities {
		if snapshot.Ref.PrincipalKind == kind && snapshot.PrincipalIdentity == principal {
			return cloneIdentity(snapshot), true, nil
		}
	}
	return view.View.LookupIdentityByPrincipal(ctx, kind, principal)
}

func (view *cutoverOverlayView) LookupKeyMaterial(ctx context.Context,
	keyID string) (KeyMaterialSnapshot, bool, error) {
	if snapshot, ok := view.materials[keyID]; ok {
		return cloneKeyMaterial(snapshot), true, nil
	}
	return view.View.LookupKeyMaterial(ctx, keyID)
}

func (view *cutoverOverlayView) LookupKeyLifecycle(ctx context.Context,
	keyID string) (KeyLifecycleSnapshot, bool, error) {
	if snapshot, ok := view.lifecycles[keyID]; ok {
		return cloneLifecycle(snapshot), true, nil
	}
	return view.View.LookupKeyLifecycle(ctx, keyID)
}

func (view *cutoverOverlayView) LookupSubjectKeyLifecycles(ctx context.Context,
	kind uint32, principal string) ([]KeyLifecycleSnapshot, error) {
	base, err := view.View.LookupSubjectKeyLifecycles(ctx, kind, principal)
	if err != nil {
		return nil, err
	}
	byKey := make(map[string]KeyLifecycleSnapshot, len(base)+len(view.lifecycles))
	for _, snapshot := range base {
		byKey[snapshot.KeyID] = cloneLifecycle(snapshot)
	}
	for keyID, snapshot := range view.lifecycles {
		if snapshot.SubjectKind == kind && snapshot.SubjectIdentity == principal {
			byKey[keyID] = cloneLifecycle(snapshot)
		}
	}
	result := make([]KeyLifecycleSnapshot, 0, len(byKey))
	for _, snapshot := range byKey {
		result = append(result, snapshot)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].KeyID < result[j].KeyID })
	return result, nil
}

func (view *cutoverOverlayView) LookupOwnershipTransfer(ctx context.Context,
	digest [32]byte) (OwnershipTransferSnapshot, bool, error) {
	if digest == view.transferDigest {
		return view.legacy, true, nil
	}
	return view.View.LookupOwnershipTransfer(ctx, digest)
}

func stageCutoverIdentifiers(steps []OwnershipTransferCutoverStep,
	enrollmentReservations []globalid.Claim, parent idempotency.Binding,
	auditEventID string) ([]globalid.Claim, []globalid.Claim, error) {
	reservations := append([]globalid.Claim(nil), enrollmentReservations...)
	auditReservation, err := joinedAuditEventReservation(parent, auditEventID)
	if err != nil {
		return nil, nil, err
	}
	reservations = append(reservations, auditReservation)
	reservations, err = normalizeGlobalClaims(reservations)
	if err != nil {
		return nil, nil, err
	}
	// Every staged non-audit reservation must already appear as the exact final
	// assertion in one ordered mutation CAS.
	for _, reservation := range enrollmentReservations {
		assertion, assertionErr := joinedIdentifierAssertion(reservation)
		if assertionErr != nil || !cutoverStepsContainIdentifier(steps, assertion) {
			return nil, nil, ErrPendingPlanInvalid
		}
	}
	auditAssertion, err := joinedIdentifierAssertion(auditReservation)
	if err != nil {
		return nil, nil, err
	}
	return []globalid.Claim{auditAssertion}, reservations, nil
}

func joinedIdentifierAssertion(reservation globalid.Claim) (globalid.Claim, error) {
	if reservation.Mode != globalid.ReserveNew {
		return globalid.Claim{}, ErrPendingPlanInvalid
	}
	claim, err := globalid.Assert(reservation.Identifier, globalid.Snapshot{
		Identifier: reservation.Identifier, Owner: reservation.Owner,
		Version: reservation.NextVersion}, reservation.Owner)
	if err != nil {
		return globalid.Claim{}, ErrPendingPlanInvalid
	}
	return claim, nil
}

func cutoverStepsContainIdentifier(steps []OwnershipTransferCutoverStep,
	expected globalid.Claim) bool {
	for _, step := range steps {
		for _, claim := range step.Mutation.CAS().IdentifierClaims {
			if claim == expected {
				return true
			}
		}
	}
	return false
}

func cutoverIdempotencyReservations(parent, joined idempotency.Binding,
	members []cutoverMember, auditDigest, core [32]byte) ([]idempotency.Claim,
	[]idempotency.CompoundMemberClaim, error) {
	umbrella, err := pendingIdempotencyClaimsBound(parent, joined, auditDigest, core)
	if err != nil {
		return nil, nil, err
	}
	memberClaims := make([]idempotency.CompoundMemberClaim, 0, len(members))
	for _, member := range members {
		if member.Binding == parent || member.Binding == joined || member.MutationDigest == ([32]byte{}) {
			return nil, nil, ErrPendingPlanInvalid
		}
		bindingDigest, digestErr := idempotency.BindingDigest(member.Binding)
		if digestErr != nil {
			return nil, nil, digestErr
		}
		encoded, encodeErr := ccse.Marshal(128, func(out *ccse.Encoder) {
			out.FixedBytes(bindingDigest[:], 32)
			out.FixedBytes(member.MutationDigest[:], 32)
			out.FixedBytes(core[:], 32)
		})
		if encodeErr != nil {
			return nil, nil, encodeErr
		}
		claim, claimErr := idempotency.NewReserveCompoundMember(parent, member.Binding,
			domainDigest(ownershipTransferCutoverMemberDomain, encoded))
		if claimErr != nil {
			return nil, nil, claimErr
		}
		memberClaims = append(memberClaims, claim)
	}
	memberClaims, err = idempotency.NormalizeCompoundMemberClaims(memberClaims)
	if err != nil || len(memberClaims) != len(members) ||
		idempotency.ValidateDisjointClaimKeys(umbrella, memberClaims) != nil {
		return nil, nil, ErrPendingPlanInvalid
	}
	return umbrella, memberClaims, nil
}

func cutoverMemberCompletionClaims(reservations []idempotency.CompoundMemberClaim) (
	[]idempotency.CompoundMemberClaim, error) {
	result := make([]idempotency.CompoundMemberClaim, 0, len(reservations))
	for _, reservation := range reservations {
		if reservation.Mode != idempotency.ReserveCompoundMember {
			return nil, ErrPendingPlanInvalid
		}
		claim, err := idempotency.NewCompleteCompoundMember(idempotency.CompoundMemberSnapshot{
			Binding: reservation.Binding, ParentBinding: reservation.ParentBinding,
			State: reservation.NextState, Version: reservation.NextVersion,
			ProgressDigest: reservation.ProgressDigest})
		if err != nil {
			return nil, err
		}
		result = append(result, claim)
	}
	return idempotency.NormalizeCompoundMemberClaims(result)
}

func newOwnershipTransferCutoverAudit(parent, joined idempotency.Binding, eventID string,
	accepted acceptedTransferValidation, steps []OwnershipTransferCutoverStep,
	evidenceRecords []RetainedVerifiedRecord, at int64) (AuditIntent, error) {
	coordinator, ok := transferCoordinator(accepted.Snapshot.Profile)
	if !ok {
		return AuditIntent{}, ErrTransferAuthorizationRequired
	}
	approval, ok := coordinatorApproval(accepted.Snapshot.Profile, accepted.Snapshot.Approvals)
	if !ok || approval.Authority != coordinator {
		return AuditIntent{}, ErrTransferAuthorizationRequired
	}
	record := approval.Signed.record
	source := auditSourceEvidence{Present: true, ActorKeyID: coordinator.KeyID,
		Record: cloneCCSERecord(record), Digest: approval.Signed.digest,
		CausationID: record.Envelope.CausationID}
	subjects := []string{accepted.Snapshot.Projection.TransferAuthorizationID,
		accepted.Snapshot.Projection.PreviousEntityID, accepted.Snapshot.Projection.NextEntityID,
		accepted.Snapshot.Projection.PreviousPrincipalIdentity,
		accepted.Snapshot.Projection.NextPrincipalIdentity,
		accepted.Snapshot.Projection.NewKeyID}
	policies := append(cloneDigests(accepted.Snapshot.Projection.Metadata.PolicyDigestsSHA256),
		accepted.Snapshot.Profile.PolicyDigest)
	evidence := [][32]byte{accepted.Snapshot.TransferEvidenceDigest,
		accepted.Snapshot.SnapshotDigest, accepted.Snapshot.ProfileDigest}
	for _, step := range steps {
		if material, ok := step.Mutation.KeyMaterial(); ok {
			policies = append(policies, material.EnrollmentPolicyDigestsSHA256...)
		}
		if identity, ok := step.Mutation.Identity(); ok {
			policies = append(policies, identity.PolicyDigestsSHA256...)
		}
		if lifecycle, ok := step.Mutation.KeyLifecycle(); ok {
			policies = append(policies, lifecycle.PolicyDigestsSHA256...)
		}
	}
	stepBytes, err := canonicalCutoverSteps(steps)
	if err != nil {
		return AuditIntent{}, err
	}
	evidenceBytes, err := canonicalCutoverEvidence(evidenceRecords)
	if err != nil {
		return AuditIntent{}, err
	}
	evidence = append(evidence,
		domainDigest(ownershipTransferCutoverStepEvidenceDomain, stepBytes),
		domainDigest(ownershipTransferCutoverRecordEvidenceDomain, evidenceBytes))
	return newAuditIntent(eventID, "iam.ownership_transfer.cutover", coordinator.Identity,
		uniqueStrings(subjects), "ownership-transfer-cutover", record.Envelope.CorrelationID,
		directAuditCausation(record.Envelope.MessageID), record.Envelope.MessageID,
		parent.Key, joined.Key, source, at, uniqueDigests(policies), uniqueDigests(evidence))
}

func ownershipTransferCutoverCoreDigest(accepted AcceptedOwnershipTransferSnapshot,
	steps []OwnershipTransferCutoverStep, dependencies []SnapshotPrecondition,
	evidenceRecords []RetainedVerifiedRecord,
	audit AuditIntent) ([32]byte, error) {
	var zero [32]byte
	acceptedDigest, err := acceptedTransferDigest(accepted)
	if err != nil || acceptedDigest != accepted.SnapshotDigest {
		return zero, ErrPendingPlanInvalid
	}
	stepBytes, err := canonicalCutoverSteps(steps)
	if err != nil {
		return zero, err
	}
	evidenceBytes, err := canonicalCutoverEvidence(evidenceRecords)
	if err != nil {
		return zero, err
	}
	if err := verifyAuditIntent(audit); err != nil {
		return zero, err
	}
	dependencyBytes, err := canonicalSnapshotPreconditions(dependencies)
	if err != nil || len(dependencies) == 0 {
		return zero, ErrPendingPlanInvalid
	}
	encoded, err := ccse.Marshal(16<<20, func(out *ccse.Encoder) {
		out.FixedBytes(accepted.TransferEvidenceDigest[:], 32)
		out.FixedBytes(accepted.SnapshotDigest[:], 32)
		out.Bytes(stepBytes)
		out.Bytes(dependencyBytes)
		out.Bytes(evidenceBytes)
		auditDigest := audit.Digest()
		out.FixedBytes(auditDigest[:], 32)
	})
	if err != nil {
		return zero, err
	}
	return domainDigest(ownershipTransferCutoverCoreDomain, encoded), nil
}

func canonicalCutoverSteps(steps []OwnershipTransferCutoverStep) ([]byte, error) {
	if len(steps) < 5 || len(steps) > 260 {
		return nil, ErrPendingPlanInvalid
	}
	elements := make([][]byte, len(steps))
	for index, step := range steps {
		if err := verifyMutationPlan(step.Mutation); err != nil {
			return nil, err
		}
		predecessors, err := canonicalSnapshotPreconditions(step.PlannedPredecessors)
		if err != nil {
			return nil, err
		}
		elements[index], err = ccse.Marshal(64<<10, func(out *ccse.Encoder) {
			out.Uint32(uint32(step.Kind))
			digest := step.Mutation.Digest()
			out.FixedBytes(digest[:], 32)
			out.Bytes(predecessors)
		})
		if err != nil {
			return nil, err
		}
	}
	return ccse.Marshal(1<<20, func(out *ccse.Encoder) { out.EncodedList(elements) })
}

func canonicalCutoverEvidence(values []RetainedVerifiedRecord) ([]byte, error) {
	normalized, err := normalizeCutoverEvidence(values)
	if err != nil {
		return nil, err
	}
	elements := make([][]byte, len(normalized))
	for index, retained := range normalized {
		record, recordErr := canonicalRetainedRecord(retained)
		if recordErr != nil {
			return nil, recordErr
		}
		elements[index], err = ccse.Marshal(2<<20, func(out *ccse.Encoder) {
			out.FixedBytes(retained.digest[:], 32)
			out.Bytes(record)
		})
		if err != nil {
			return nil, err
		}
	}
	return ccse.Marshal(16<<20, func(out *ccse.Encoder) { out.EncodedSet(elements) })
}

func ownershipTransferCutoverPlanDigest(plan PendingOwnershipTransferCutoverPlan) ([32]byte, error) {
	var zero [32]byte
	core, err := ownershipTransferCutoverCoreDigest(plan.accepted, plan.steps, plan.dependencies,
		plan.evidence, plan.audit)
	if err != nil {
		return zero, err
	}
	completion, err := idempotency.CanonicalBytes(plan.idempotencyCompletion)
	if err != nil {
		return zero, err
	}
	identifiers, err := globalid.CanonicalBytes(plan.identifierAssertions)
	if err != nil {
		return zero, err
	}
	memberAdmission, err := idempotency.CompoundMemberCanonicalBytes(plan.memberAdmission)
	if err != nil {
		return zero, err
	}
	memberCompletion, err := idempotency.CompoundMemberCanonicalBytes(plan.memberCompletion)
	if err != nil {
		return zero, err
	}
	encoded, err := ccse.Marshal(4<<20, func(out *ccse.Encoder) {
		out.FixedBytes(core[:], 32)
		admissionDigest := plan.admission.Digest()
		out.FixedBytes(admissionDigest[:], 32)
		out.Bytes(completion)
		out.Bytes(memberAdmission)
		out.Bytes(memberCompletion)
		out.Bytes(identifiers)
		out.Int64(plan.evaluatedAtUnixNano)
		out.Int64(plan.commitNotBeforeUnixNano)
		out.Int64(plan.commitNotAfterUnixNano)
	})
	if err != nil {
		return zero, err
	}
	return domainDigest(ownershipTransferCutoverPlanDomain, encoded), nil
}

func verifyOwnershipTransferCutoverPlan(plan PendingOwnershipTransferCutoverPlan) error {
	if preflightAcceptedTransfer(plan.accepted) != nil || plan.accepted.SnapshotDigest == ([32]byte{}) ||
		verifyPendingAdmissionIntent(plan.admission) != nil || verifyAuditIntent(plan.audit) != nil ||
		plan.evaluatedAtUnixNano < 0 || plan.commitNotBeforeUnixNano < 0 ||
		plan.commitNotBeforeUnixNano > plan.evaluatedAtUnixNano ||
		plan.commitNotAfterUnixNano <= plan.evaluatedAtUnixNano {
		return fmt.Errorf("%w: invalid cutover component/window", ErrPendingPlanInvalid)
	}
	acceptedDigest, err := acceptedTransferDigest(plan.accepted)
	if err != nil || acceptedDigest != plan.accepted.SnapshotDigest ||
		plan.evaluatedAtUnixNano < plan.accepted.Projection.EffectiveAtUnixNano ||
		plan.evaluatedAtUnixNano >= plan.accepted.Projection.ExpiresAtUnixNano {
		return fmt.Errorf("%w: invalid accepted cutover authority", ErrPendingPlanInvalid)
	}
	closureCount := len(plan.accepted.FixedEvidence.KeyClosureSnapshots)
	if closureCount < 1 || len(plan.steps) != closureCount+4 || len(plan.evidence) != 3 {
		return fmt.Errorf("%w: invalid cutover step/evidence shape", ErrPendingPlanInvalid)
	}
	for index, step := range plan.steps {
		expectedKind := CutoverClosePreviousKey
		switch index {
		case closureCount:
			expectedKind = CutoverTerminalPreviousIdentity
		case closureCount + 1:
			expectedKind = CutoverCreateNextKeyMaterial
		case closureCount + 2:
			expectedKind = CutoverCreateNextKeyLifecycle
		case closureCount + 3:
			expectedKind = CutoverCreateNextIdentity
		}
		if step.Kind != expectedKind || verifyMutationPlan(step.Mutation) != nil ||
			step.Mutation.EvaluatedAtUnixNano() != plan.evaluatedAtUnixNano ||
			step.Mutation.CommitNotBeforeUnixNano() != plan.commitNotBeforeUnixNano ||
			step.Mutation.CommitNotAfterUnixNano() != plan.commitNotAfterUnixNano ||
			step.Mutation.CAS().TransferEvidenceDigest != plan.accepted.TransferEvidenceDigest ||
			len(step.Mutation.CAS().IdempotencyClaims) != 0 ||
			len(step.Mutation.CAS().Dependencies) != 0 {
			return fmt.Errorf("%w: invalid cutover step %d", ErrPendingPlanInvalid, index)
		}
	}
	if err := verifyCutoverDependencyPhases(plan.steps, plan.dependencies); err != nil {
		return err
	}
	if err := verifyCutoverWriteValues(plan); err != nil {
		return fmt.Errorf("%w: cutover write/evidence mismatch", err)
	}
	normalizedEvidence, err := normalizeCutoverEvidence(plan.evidence)
	if err != nil || !sameCutoverEvidence(normalizedEvidence, plan.evidence) {
		return fmt.Errorf("%w: invalid cutover retained evidence", ErrPendingPlanInvalid)
	}
	parent, joined, err := pendingIdempotencyBindings(plan.admission.idempotencyReservations)
	if err != nil || parent.Domain != idempotency.OperationIAMOwnershipTransferCutover ||
		plan.audit.IdempotencyKey() != parent.Key || plan.audit.ExpectedAuditIdempotencyKey() != joined.Key ||
		parent != mustCutoverBinding(plan.accepted) {
		return fmt.Errorf("%w: invalid cutover parent binding", ErrPendingPlanInvalid)
	}
	expectedAudit, err := newOwnershipTransferCutoverAudit(parent, joined,
		plan.audit.AuditEventID(), acceptedTransferValidation{Snapshot: plan.accepted},
		plan.steps, plan.evidence, plan.evaluatedAtUnixNano)
	if err != nil || expectedAudit.Digest() != plan.audit.Digest() {
		return fmt.Errorf("%w: invalid cutover audit", ErrPendingPlanInvalid)
	}
	if err := verifyJoinedAuditEventClaims(parent, plan.audit,
		plan.admission.identifierReservations, plan.identifierAssertions); err != nil {
		return err
	}
	if !cutoverReservationsMatchFinal(plan) {
		return fmt.Errorf("%w: cutover reservations do not match writes", ErrPendingPlanInvalid)
	}
	completion, err := pendingCompletionClaims(plan.admission.idempotencyReservations)
	if err != nil || !sameIdempotencyClaims(completion, plan.idempotencyCompletion) {
		return fmt.Errorf("%w: invalid cutover completion", ErrPendingPlanInvalid)
	}
	core, err := ownershipTransferCutoverCoreDigest(plan.accepted, plan.steps, plan.dependencies,
		plan.evidence, plan.audit)
	if err != nil || core != plan.admission.CoreEvidenceDigest() ||
		plan.admission.EvaluatedAtUnixNano() != plan.evaluatedAtUnixNano ||
		plan.admission.CommitNotBeforeUnixNano() != plan.commitNotBeforeUnixNano ||
		plan.admission.CommitNotAfterUnixNano() != plan.commitNotAfterUnixNano {
		return fmt.Errorf("%w: invalid cutover core", ErrPendingPlanInvalid)
	}
	members, err := deriveCutoverMembers(plan.steps)
	if err != nil || len(members) != closureCount+3 {
		return fmt.Errorf("%w: invalid cutover member derivation", ErrPendingPlanInvalid)
	}
	expectedReservations, expectedMemberAdmission, err := cutoverIdempotencyReservations(
		parent, joined, members, plan.audit.Digest(), core)
	if err != nil || !sameIdempotencyClaims(expectedReservations,
		plan.admission.idempotencyReservations) ||
		!sameCompoundMemberClaims(expectedMemberAdmission, plan.memberAdmission) {
		return fmt.Errorf("%w: invalid cutover member reservation", ErrPendingPlanInvalid)
	}
	expectedMemberCompletion, err := cutoverMemberCompletionClaims(expectedMemberAdmission)
	if err != nil || !sameCompoundMemberClaims(expectedMemberCompletion, plan.memberCompletion) ||
		idempotency.ValidateDisjointClaimKeys(plan.admission.idempotencyReservations,
			plan.memberAdmission) != nil ||
		idempotency.ValidateDisjointClaimKeys(plan.idempotencyCompletion,
			plan.memberCompletion) != nil {
		return fmt.Errorf("%w: invalid cutover member completion", ErrPendingPlanInvalid)
	}
	digest, err := ownershipTransferCutoverPlanDigest(plan)
	if err != nil || digest != plan.digest {
		return fmt.Errorf("%w: cutover digest mismatch", ErrPendingPlanInvalid)
	}
	return nil
}

func mustCutoverBinding(snapshot AcceptedOwnershipTransferSnapshot) idempotency.Binding {
	binding, err := idempotency.OwnershipTransferCutoverBinding(snapshotBinding(snapshot))
	if err != nil {
		return idempotency.Binding{}
	}
	return binding
}

// deriveCutoverMembers reconstructs every child business binding exclusively
// from the detached write values. This prevents a caller from swapping a
// member alias while retaining a self-consistent compound-claim digest.
func deriveCutoverMembers(steps []OwnershipTransferCutoverStep) ([]cutoverMember, error) {
	closureCount := len(steps) - 4
	if closureCount < 1 || len(steps) != closureCount+4 {
		return nil, ErrPendingPlanInvalid
	}
	result := make([]cutoverMember, 0, closureCount+3)
	for index := 0; index < closureCount; index++ {
		lifecycle, ok := steps[index].Mutation.KeyLifecycle()
		if !ok {
			return nil, ErrPendingPlanInvalid
		}
		result = append(result, cutoverMember{Binding: mutationIdempotencyBinding(
			lifecycle.IdempotencyKey, idempotency.OperationIAMKeyLifecycle, lifecycle.KeyID,
			sha256.Sum256(lifecycle.CanonicalPayload)), MutationDigest: steps[index].Mutation.Digest()})
	}
	previous, ok := steps[closureCount].Mutation.Identity()
	if !ok {
		return nil, ErrPendingPlanInvalid
	}
	result = append(result, cutoverMember{Binding: mutationIdempotencyBinding(
		previous.IdempotencyKey, idempotency.OperationIAMIdentity, previous.Ref.ID,
		sha256.Sum256(previous.CanonicalPayload)), MutationDigest: steps[closureCount].Mutation.Digest()})

	material, materialOK := steps[closureCount+1].Mutation.KeyMaterial()
	lifecycle, lifecycleOK := steps[closureCount+2].Mutation.KeyLifecycle()
	if !materialOK || !lifecycleOK || material.KeyID != lifecycle.KeyID ||
		material.IdempotencyKey != lifecycle.IdempotencyKey {
		return nil, ErrPendingPlanInvalid
	}
	materialRequest := KeyMaterialCommand{Algorithm: material.Algorithm,
		CanonicalPublicKey: append([]byte(nil), material.CanonicalPublicKey...),
		ClaimedKeyID:       material.KeyID, SubjectIdentity: material.SubjectIdentity,
		SubjectKind: material.SubjectKind, TargetIdentity: material.TargetIdentity,
		TransferEvidenceDigest: material.TransferEvidenceDigest,
		EnrollmentDomain:       material.EnrollmentDomain, Challenge: material.ProofChallenge,
		ChallengeExpiresAtUnixNano:        material.ProofExpiresAtUnixNano,
		ProofSignature:                    append([]byte(nil), material.ProofSignature...),
		EnrollmentAuthorityIdentity:       material.EnrollmentAuthorityIdentity,
		EnrollmentAuthorityEvidenceDigest: material.ChallengeEvidenceDigest,
		EnrollmentPolicyDigestsSHA256:     cloneDigests(material.EnrollmentPolicyDigestsSHA256),
		IdempotencyKey:                    material.IdempotencyKey}
	materialDigest, err := keyMaterialRequestDigest(materialRequest,
		material.CanonicalPublicKey, material.KeyID)
	if err != nil {
		return nil, err
	}
	lifecycleDigest := sha256.Sum256(lifecycle.CanonicalPayload)
	requestProjection, err := ccse.Marshal(256, func(out *ccse.Encoder) {
		out.FixedBytes(materialDigest[:], 32)
		out.FixedBytes(lifecycleDigest[:], 32)
	})
	if err != nil {
		return nil, err
	}
	enrollmentDigest, err := keyEnrollmentMutationCoreDigest(steps[closureCount+1].Mutation,
		steps[closureCount+2].Mutation)
	if err != nil {
		return nil, err
	}
	result = append(result, cutoverMember{Binding: mutationIdempotencyBinding(
		lifecycle.IdempotencyKey, idempotency.OperationIAMKeyEnrollment, lifecycle.KeyID,
		domainDigest(keyEnrollmentRequestDomain, requestProjection)), MutationDigest: enrollmentDigest})

	next, ok := steps[closureCount+3].Mutation.Identity()
	if !ok {
		return nil, ErrPendingPlanInvalid
	}
	result = append(result, cutoverMember{Binding: mutationIdempotencyBinding(
		next.IdempotencyKey, idempotency.OperationIAMIdentity, next.Ref.ID,
		sha256.Sum256(next.CanonicalPayload)), MutationDigest: steps[closureCount+3].Mutation.Digest()})
	return result, nil
}

func sameCompoundMemberClaims(left, right []idempotency.CompoundMemberClaim) bool {
	if len(left) == 0 || len(right) == 0 {
		return len(left) == 0 && len(right) == 0
	}
	normalizedLeft, leftErr := idempotency.NormalizeCompoundMemberClaims(left)
	normalizedRight, rightErr := idempotency.NormalizeCompoundMemberClaims(right)
	if leftErr != nil || rightErr != nil || len(normalizedLeft) != len(normalizedRight) {
		return false
	}
	for index := range normalizedLeft {
		if normalizedLeft[index] != normalizedRight[index] {
			return false
		}
	}
	return true
}

func verifyCutoverDependencyPhases(steps []OwnershipTransferCutoverStep,
	preState []SnapshotPrecondition) error {
	normalized, err := canonicalPreconditions(preState)
	if err != nil || len(normalized) != len(preState) {
		return ErrPendingPlanInvalid
	}
	for index := range normalized {
		if normalized[index] != preState[index] {
			return ErrPendingPlanInvalid
		}
	}
	outputs := make(map[EntityRef]SnapshotPrecondition, len(steps))
	for _, step := range steps {
		planned, err := canonicalPreconditions(step.PlannedPredecessors)
		if err != nil || len(planned) != len(step.PlannedPredecessors) {
			return ErrPendingPlanInvalid
		}
		for index, dependency := range planned {
			if dependency != step.PlannedPredecessors[index] {
				return ErrPendingPlanInvalid
			}
			if output, found := outputs[dependency.Entity]; !found || output != dependency {
				return ErrPendingPlanInvalid
			}
		}
		output, err := cutoverMutationOutputPrecondition(step.Mutation)
		if err != nil {
			return err
		}
		if _, duplicate := outputs[output.Entity]; duplicate {
			return ErrPendingPlanInvalid
		}
		outputs[output.Entity] = output
	}
	return nil
}

func verifyCutoverWriteValues(plan PendingOwnershipTransferCutoverPlan) error {
	closureCount := len(plan.accepted.FixedEvidence.KeyClosureSnapshots)
	for index := 0; index < closureCount; index++ {
		value, ok := plan.steps[index].Mutation.KeyLifecycle()
		if !ok || !equalLifecycleSnapshots(value,
			plan.accepted.FixedEvidence.KeyClosureSnapshots[index]) {
			return ErrPendingPlanInvalid
		}
	}
	previous, ok := plan.steps[closureCount].Mutation.Identity()
	if !ok || !equalIdentitySnapshots(previous,
		plan.accepted.FixedEvidence.PreviousTerminalIdentity) {
		return ErrPendingPlanInvalid
	}
	material, materialOK := plan.steps[closureCount+1].Mutation.KeyMaterial()
	lifecycle, lifecycleOK := plan.steps[closureCount+2].Mutation.KeyLifecycle()
	next, nextOK := plan.steps[closureCount+3].Mutation.Identity()
	if !materialOK || !lifecycleOK || !nextOK ||
		material.KeyID != plan.accepted.Projection.NewKeyID ||
		material.TransferEvidenceDigest != plan.accepted.TransferEvidenceDigest ||
		material.SubjectIdentity != plan.accepted.Projection.NextPrincipalIdentity ||
		material.SubjectKind != plan.accepted.Projection.SubjectKind ||
		material.TargetIdentity != (EntityRef{Kind: EntityIdentity,
			PrincipalKind: plan.accepted.Projection.SubjectKind,
			ID:            plan.accepted.Projection.NextEntityID}) ||
		lifecycle.KeyID != material.KeyID || lifecycle.State != 1 || lifecycle.StateVersion != 1 ||
		!equalIdentitySnapshots(next, plan.accepted.FixedEvidence.NextPendingIdentity) {
		return ErrPendingPlanInvalid
	}
	expectedAuthorization := make(map[[32]byte]struct{}, closureCount+3)
	for _, step := range plan.steps {
		digest := step.Mutation.CAS().AuthorizationDigest
		if step.Kind == CutoverCreateNextKeyMaterial {
			if digest != ([32]byte{}) {
				return ErrPendingPlanInvalid
			}
			continue
		}
		if digest == ([32]byte{}) {
			return ErrPendingPlanInvalid
		}
		expectedAuthorization[digest] = struct{}{}
	}
	availableAuthorization := make(map[[32]byte]struct{}, closureCount+3)
	for _, closure := range plan.accepted.FixedEvidence.KeyClosureRecords {
		availableAuthorization[closure.digest] = struct{}{}
	}
	for _, evidence := range plan.evidence {
		availableAuthorization[evidence.digest] = struct{}{}
	}
	if len(plan.evidence) != 3 || len(availableAuthorization) != len(expectedAuthorization) {
		return ErrPendingPlanInvalid
	}
	for digest := range availableAuthorization {
		if _, ok := expectedAuthorization[digest]; !ok {
			return ErrPendingPlanInvalid
		}
	}
	return nil
}

func cutoverReservationsMatchFinal(plan PendingOwnershipTransferCutoverPlan) bool {
	for _, reservation := range plan.admission.identifierReservations {
		assertion, err := joinedIdentifierAssertion(reservation)
		if err != nil {
			return false
		}
		found := false
		for _, claim := range plan.identifierAssertions {
			if claim == assertion {
				found = true
				break
			}
		}
		if !found {
			found = cutoverStepsContainIdentifier(plan.steps, assertion)
		}
		if !found {
			return false
		}
	}
	return true
}

func sameCutoverEvidence(left, right []RetainedVerifiedRecord) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		leftRecord, leftErr := canonicalRetainedRecord(left[index])
		rightRecord, rightErr := canonicalRetainedRecord(right[index])
		if leftErr != nil || rightErr != nil || !bytes.Equal(leftRecord, rightRecord) {
			return false
		}
	}
	return true
}
