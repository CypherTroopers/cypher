// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"fmt"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	"github.com/cypherium/cypher/aiinfra/replayresult"
)

const (
	pendingReconciliationPlanDomain             = "CPH-AIIE-IAM-PENDING-RECONCILIATION-PLAN-V1\x00"
	pendingReconciliationFreshRequirementDomain = "CPH-AIIE-IAM-PENDING-RECONCILIATION-FRESH-REQUIREMENT-V1\x00"
	transferCollectionFailureIntentDomain       = "CPH-AIIE-IAM-TRANSFER-COLLECTION-FAILURE-INTENT-V1\x00"
)

type PendingDisposition uint8

const (
	PendingDispositionExpired PendingDisposition = iota + 1
	PendingDispositionFailed
)

// PendingReconciliationCommand carries a trusted transaction-time evaluation
// and immutable failure/clock evidence. FAILED remains noncommittable until
// WS0.2b verifies the referenced operational failure evidence; EXPIRED is
// independently gated by the original CommitNotAfter fence.
type PendingReconciliationCommand struct {
	Disposition         PendingDisposition
	EvaluatedAtUnixNano int64
	Evidence            PendingReconciliationEvidence
}

// ReconciliationAuditRequirement is consumed by the sole canonical Audit
// Writer. It intentionally is not an AuditIntent: the writer must create and
// validate a new signed failure event/head CAS while retaining the original
// authorization as source evidence.
type ReconciliationAuditRequirement struct {
	auditEventID              string
	eventType                 string
	logicalActorIdentity      string
	logicalActorKeyID         string
	correlationID             [16]byte
	causationID               ccse.OptionalMessageID
	auditIdempotencyKey       [16]byte
	sourceAuthorizationDigest [32]byte
	sourceAuthorizationRecord ccse.Record
	hasSourceAuthorization    bool
	originalAuditIntentDigest [32]byte
	policyDigestsSHA256       [][32]byte
	subjectIDs                []string
	causeCode                 string
	occurredAtUnixNano        int64
	freshRequirementDigest    [32]byte
}

func (requirement ReconciliationAuditRequirement) AuditEventID() string {
	return requirement.auditEventID
}
func (requirement ReconciliationAuditRequirement) EventType() string { return requirement.eventType }
func (requirement ReconciliationAuditRequirement) LogicalActorIdentity() string {
	return requirement.logicalActorIdentity
}
func (requirement ReconciliationAuditRequirement) LogicalActorKeyID() string {
	return requirement.logicalActorKeyID
}
func (requirement ReconciliationAuditRequirement) CorrelationID() [16]byte {
	return requirement.correlationID
}
func (requirement ReconciliationAuditRequirement) CausationID() ccse.OptionalMessageID {
	return requirement.causationID
}
func (requirement ReconciliationAuditRequirement) AuditIdempotencyKey() [16]byte {
	return requirement.auditIdempotencyKey
}
func (requirement ReconciliationAuditRequirement) SourceAuthorizationDigest() [32]byte {
	return requirement.sourceAuthorizationDigest
}
func (requirement ReconciliationAuditRequirement) SourceAuthorizationRecord() (ccse.Record, bool) {
	if !requirement.hasSourceAuthorization {
		return ccse.Record{}, false
	}
	return cloneCCSERecord(requirement.sourceAuthorizationRecord), true
}
func (requirement ReconciliationAuditRequirement) OriginalAuditIntentDigest() [32]byte {
	return requirement.originalAuditIntentDigest
}
func (requirement ReconciliationAuditRequirement) PolicyDigestsSHA256() [][32]byte {
	return cloneDigests(requirement.policyDigestsSHA256)
}
func (requirement ReconciliationAuditRequirement) SubjectIDs() []string {
	return append([]string(nil), requirement.subjectIDs...)
}
func (requirement ReconciliationAuditRequirement) CauseCode() string { return requirement.causeCode }
func (requirement ReconciliationAuditRequirement) OccurredAtUnixNano() int64 {
	return requirement.occurredAtUnixNano
}
func (requirement ReconciliationAuditRequirement) FreshRequirementDigest() [32]byte {
	return requirement.freshRequirementDigest
}
func (requirement ReconciliationAuditRequirement) HistoricalCausationRecord() (ccse.Record, bool) {
	return requirement.SourceAuthorizationRecord()
}
func (requirement ReconciliationAuditRequirement) HistoricalCausationDigest() [32]byte {
	return requirement.sourceAuthorizationDigest
}

// FreshReconcilerAuthorityRequired declares that the original source is only
// historical causation. Governance must authorize the newly signed AuditEvent
// with the current Audit Writer key/profile/lease at transaction time.
func (ReconciliationAuditRequirement) FreshReconcilerAuthorityRequired() bool { return true }

// PendingReconciliationPlan closes both X/Y rows to one exact failure outcome
// while asserting that every admitted global identifier remains a permanent
// final-owner tombstone. It is still noncommittable until the canonical Audit
// Writer result and audit-head CAS are joined.
type PendingReconciliationPlan struct {
	originalPendingEnvelope  []byte
	originalEnvelopeDigest   [32]byte
	pendingDigest            [32]byte
	disposition              PendingDisposition
	evaluatedAtUnixNano      int64
	commitNotBeforeUnixNano  int64
	commitNotAfterUnixNano   int64
	failureEvidenceDigest    [32]byte
	failureEvidence          PendingReconciliationEvidence
	failureResult            replayresult.Result
	failureOutcomeDigest     [32]byte
	idempotencyCompletion    []idempotency.Claim
	compoundMemberCompletion []idempotency.CompoundMemberClaim
	identifierTombstones     []globalid.Claim
	audit                    ReconciliationAuditRequirement
	digest                   [32]byte
}

func (plan PendingReconciliationPlan) Digest() [32]byte { return plan.digest }
func (PendingReconciliationPlan) CommitReady() bool     { return false }
func (plan PendingReconciliationPlan) Disposition() PendingDisposition {
	return plan.disposition
}
func (plan PendingReconciliationPlan) EvaluatedAtUnixNano() int64 {
	return plan.evaluatedAtUnixNano
}
func (plan PendingReconciliationPlan) CommitNotBeforeUnixNano() int64 {
	return plan.commitNotBeforeUnixNano
}
func (plan PendingReconciliationPlan) CommitNotAfterUnixNano() int64 {
	return plan.commitNotAfterUnixNano
}
func (plan PendingReconciliationPlan) FailureOutcomeDigest() [32]byte {
	return plan.failureOutcomeDigest
}
func (plan PendingReconciliationPlan) FailureEvidence() PendingReconciliationEvidence {
	return clonePendingReconciliationEvidence(plan.failureEvidence)
}
func (plan PendingReconciliationPlan) FailureResult() replayresult.Result { return plan.failureResult }
func (plan PendingReconciliationPlan) OriginalPendingEnvelopeBytes() []byte {
	return append([]byte(nil), plan.originalPendingEnvelope...)
}
func (plan PendingReconciliationPlan) OriginalPendingEnvelopeDigest() [32]byte {
	return plan.originalEnvelopeDigest
}
func (plan PendingReconciliationPlan) IdempotencyCompletionClaims() []idempotency.Claim {
	return append([]idempotency.Claim(nil), plan.idempotencyCompletion...)
}
func (plan PendingReconciliationPlan) CompoundMemberCompletionClaims() []idempotency.CompoundMemberClaim {
	return append([]idempotency.CompoundMemberClaim(nil), plan.compoundMemberCompletion...)
}
func (plan PendingReconciliationPlan) IdentifierTombstoneAssertions() []globalid.Claim {
	return append([]globalid.Claim(nil), plan.identifierTombstones...)
}
func (plan PendingReconciliationPlan) AuditRequirement() ReconciliationAuditRequirement {
	result := plan.audit
	result.sourceAuthorizationRecord = cloneCCSERecord(plan.audit.sourceAuthorizationRecord)
	result.policyDigestsSHA256 = cloneDigests(plan.audit.policyDigestsSHA256)
	result.subjectIDs = append([]string(nil), plan.audit.subjectIDs...)
	return result
}
func (plan PendingReconciliationPlan) VerifyDigest() error {
	derived, err := newPendingReconciliationPlan(plan.pendingDigest, plan.disposition,
		plan.evaluatedAtUnixNano, plan.commitNotBeforeUnixNano, plan.failureEvidence,
		plan.idempotencyCompletion, plan.compoundMemberCompletion, plan.identifierTombstones, plan.audit,
		plan.originalPendingEnvelope)
	if err != nil || derived.digest != plan.digest || derived.failureOutcomeDigest != plan.failureOutcomeDigest {
		return ErrPendingPlanInvalid
	}
	return nil
}

func (plan PendingMutationPlan) PlanReconciliation(command PendingReconciliationCommand) (PendingReconciliationPlan, error) {
	if err := plan.VerifyDigest(); err != nil {
		return PendingReconciliationPlan{}, err
	}
	envelope, err := plan.DurableEnvelope()
	if err != nil {
		return PendingReconciliationPlan{}, err
	}
	return reconcilePending(plan.digest, plan.admission, plan.idempotencyCompletion, plan.audit,
		nil, command, envelope.Bytes())
}

func (plan PendingKeyEnrollmentPlan) PlanReconciliation(command PendingReconciliationCommand) (PendingReconciliationPlan, error) {
	if err := plan.VerifyDigest(); err != nil {
		return PendingReconciliationPlan{}, err
	}
	envelope, err := plan.DurableEnvelope()
	if err != nil {
		return PendingReconciliationPlan{}, err
	}
	return reconcilePending(plan.digest, plan.admission, plan.idempotencyCompletion, plan.audit,
		nil, command, envelope.Bytes())
}

func (plan OwnershipTransferApprovalCollectionPlan) PlanReconciliation(
	command PendingReconciliationCommand) (PendingReconciliationPlan, error) {
	if err := plan.VerifyDigest(); err != nil {
		return PendingReconciliationPlan{}, err
	}
	envelope, err := plan.DurableEnvelope()
	if err != nil {
		return PendingReconciliationPlan{}, err
	}
	return reconcileTransferCollection(plan, command, envelope.Bytes())
}

func reconcileTransferCollection(plan OwnershipTransferApprovalCollectionPlan,
	command PendingReconciliationCommand, originalEnvelope []byte) (PendingReconciliationPlan, error) {
	if command.EvaluatedAtUnixNano < plan.CommitNotAfterUnixNano() || command.Evidence.Verify() != nil ||
		command.Evidence.Disposition() != command.Disposition ||
		command.Evidence.AuditOccurredAtUnixNano() != command.EvaluatedAtUnixNano ||
		command.Evidence.OriginalCommitNotAfterUnixNano() != plan.CommitNotAfterUnixNano() ||
		(command.Disposition != PendingDispositionExpired && command.Disposition != PendingDispositionFailed) {
		return PendingReconciliationPlan{}, ErrInvalidCommitWindow
	}
	parent := idempotency.Snapshot{Binding: plan.next.Binding, State: idempotency.StateCollecting,
		Version: plan.next.Version, ProgressDigest: plan.next.ProgressDigest}
	joinedBinding, err := idempotency.JoinedAuditBinding(plan.next.Binding)
	if err != nil {
		return PendingReconciliationPlan{}, ErrPendingPlanInvalid
	}
	joined := plan.joinedAuditSnapshot
	if plan.disposition == OwnershipTransferCollectionAppend {
		parentDigest, digestErr := idempotency.BindingDigest(plan.next.Binding)
		if digestErr != nil {
			return PendingReconciliationPlan{}, digestErr
		}
		joined = idempotency.Snapshot{Binding: joinedBinding, State: idempotency.StateCollecting,
			Version: 1, ProgressDigest: parentDigest}
	}
	parentCompletion, err := idempotency.NewCompleteCollection(parent)
	if err != nil {
		return PendingReconciliationPlan{}, err
	}
	joinedCompletion, err := idempotency.NewCompleteCollection(joined)
	if err != nil {
		return PendingReconciliationPlan{}, err
	}
	completion, err := idempotency.NormalizeClaims([]idempotency.Claim{parentCompletion, joinedCompletion})
	if err != nil {
		return PendingReconciliationPlan{}, err
	}
	tombstones, err := terminalIdentifierAssertions(plan.identifierClaims)
	if err != nil {
		return PendingReconciliationPlan{}, err
	}
	projection, _, _, err := normalizeOwnershipTransferPayload(plan.next.CanonicalPayload)
	if err != nil || len(plan.next.Approvals) == 0 {
		return PendingReconciliationPlan{}, ErrPendingPlanInvalid
	}
	source := plan.next.Approvals[0]
	if coordinator, ok := transferCoordinator(plan.next.Profile); ok {
		if coordinatorAdmission, found := transferAdmissionByAuthority(plan.next.Approvals, coordinator); found {
			source = coordinatorAdmission
		}
	}
	authorization, err := authorizationFromSignedRecord(source.Signed.record)
	if err != nil || authorization.recordDigest != source.Signed.digest {
		return PendingReconciliationPlan{}, ErrAuthorizationMismatch
	}
	eventID, err := idempotency.JoinedAuditEventID(plan.next.Binding)
	if err != nil {
		return PendingReconciliationPlan{}, err
	}
	intentBytes, err := ccse.Marshal(160, func(out *ccse.Encoder) {
		out.FixedBytes(plan.digest[:], 32)
		out.FixedBytes(plan.next.ProgressDigest[:], 32)
		out.FixedBytes(plan.next.ProfileDigest[:], 32)
	})
	if err != nil {
		return PendingReconciliationPlan{}, err
	}
	eventType := "iam.ownership-transfer.collection.failed"
	if command.Disposition == PendingDispositionExpired {
		eventType = "iam.ownership-transfer.collection.expired"
	}
	requirement := ReconciliationAuditRequirement{auditEventID: eventID, eventType: eventType,
		logicalActorIdentity: authorization.senderIdentity, logicalActorKeyID: authorization.signatureKeyID,
		correlationID: authorization.correlationID, causationID: directAuditCausation(authorization.messageID),
		auditIdempotencyKey: joinedBinding.Key, sourceAuthorizationDigest: authorization.recordDigest,
		sourceAuthorizationRecord: cloneCCSERecord(authorization.sourceRecord), hasSourceAuthorization: true,
		originalAuditIntentDigest: domainDigest(transferCollectionFailureIntentDomain, intentBytes),
		policyDigestsSHA256:       cloneDigests(projection.Metadata.PolicyDigestsSHA256),
		subjectIDs: uniqueStrings([]string{projection.TransferAuthorizationID,
			projection.PreviousEntityID, projection.NextEntityID,
			projection.PreviousPrincipalIdentity, projection.NextPrincipalIdentity}),
		causeCode:          reconciliationCauseCode(command.Disposition),
		occurredAtUnixNano: command.EvaluatedAtUnixNano}
	return newPendingReconciliationPlan(plan.digest, command.Disposition,
		command.EvaluatedAtUnixNano, plan.CommitNotAfterUnixNano(), command.Evidence,
		completion, nil, tombstones, requirement, originalEnvelope)
}

func terminalIdentifierAssertions(claims []globalid.Claim) ([]globalid.Claim, error) {
	result := make([]globalid.Claim, 0, len(claims))
	for _, claim := range claims {
		if claim.Mode != globalid.ReserveNew && claim.Mode != globalid.AssertExisting {
			return nil, ErrPendingPlanInvalid
		}
		assertion, err := globalid.Assert(claim.Identifier, globalid.Snapshot{
			Identifier: claim.Identifier, Owner: claim.Owner, Version: claim.NextVersion}, claim.Owner)
		if err != nil {
			return nil, ErrPendingPlanInvalid
		}
		result = append(result, assertion)
	}
	return normalizeGlobalClaims(result)
}

// PlanReconciliation is intentionally exposed on a capability-bearing durable
// envelope for ownership-transfer cutovers. A raw cutover plan cannot create
// its standalone durable envelope; only RevalidateDurablePending can issue the
// capability after checking the already-admitted X/Y/member/global state.
func (envelope DurablePendingEnvelope) PlanReconciliation(
	command PendingReconciliationCommand) (PendingReconciliationPlan, error) {
	if !envelope.capability || envelope.kind != DurablePendingOwnershipTransferCutover ||
		envelope.cutover == nil || envelope.VerifyDigest() != nil {
		return PendingReconciliationPlan{}, ErrPendingPlanInvalid
	}
	plan := envelope.cutover
	return reconcilePending(plan.digest, plan.admission, plan.idempotencyCompletion, plan.audit,
		plan.memberCompletion, command, envelope.Bytes())
}

func reconcilePending(pendingDigest [32]byte, admission PendingAdmissionIntent,
	completion []idempotency.Claim, source AuditIntent,
	memberCompletion []idempotency.CompoundMemberClaim, command PendingReconciliationCommand,
	originalEnvelope []byte) (PendingReconciliationPlan, error) {
	if command.EvaluatedAtUnixNano < 0 || command.Evidence.Verify() != nil ||
		command.Evidence.Disposition() != command.Disposition ||
		command.Evidence.AuditOccurredAtUnixNano() != command.EvaluatedAtUnixNano ||
		command.Evidence.OriginalCommitNotAfterUnixNano() != admission.CommitNotAfterUnixNano() {
		return PendingReconciliationPlan{}, ErrInvalidInput
	}
	switch command.Disposition {
	case PendingDispositionExpired:
		if command.EvaluatedAtUnixNano < admission.CommitNotAfterUnixNano() {
			return PendingReconciliationPlan{}, ErrInvalidCommitWindow
		}
	case PendingDispositionFailed:
		// FAILED and EXPIRED share the same post-deadline terminalization fence.
		// Before that point the original pending operation remains resumable and
		// must not be closed by an out-of-band failure report.
		if command.EvaluatedAtUnixNano < admission.CommitNotAfterUnixNano() {
			return PendingReconciliationPlan{}, ErrInvalidCommitWindow
		}
	default:
		return PendingReconciliationPlan{}, ErrInvalidInput
	}
	tombstones := make([]globalid.Claim, 0, len(admission.identifierReservations))
	for _, reservation := range admission.identifierReservations {
		assertion, err := globalid.Assert(reservation.Identifier, globalid.Snapshot{
			Identifier: reservation.Identifier, Owner: reservation.Owner, Version: reservation.NextVersion}, reservation.Owner)
		if err != nil {
			return PendingReconciliationPlan{}, fmt.Errorf("%w: identifier tombstone: %v", ErrPendingPlanInvalid, err)
		}
		tombstones = append(tombstones, assertion)
	}
	var eventType string
	if command.Disposition == PendingDispositionExpired {
		eventType = "iam.pending.expired"
	} else {
		eventType = "iam.pending.failed"
	}
	requirement := ReconciliationAuditRequirement{auditEventID: source.AuditEventID(), eventType: eventType,
		logicalActorIdentity: source.ActorIdentity(), logicalActorKeyID: source.ActorKeyID(),
		correlationID: source.CorrelationID(), causationID: source.CausationID(),
		auditIdempotencyKey:       source.ExpectedAuditIdempotencyKey(),
		sourceAuthorizationDigest: source.SourceAuthorizationDigest(),
		originalAuditIntentDigest: source.Digest(), subjectIDs: source.SubjectIDs(),
		causeCode: reconciliationCauseCode(command.Disposition), occurredAtUnixNano: command.EvaluatedAtUnixNano}
	requirement.sourceAuthorizationRecord, requirement.hasSourceAuthorization = source.SourceAuthorizationRecord()
	requirement.policyDigestsSHA256 = source.PolicyDigestsSHA256()
	return newPendingReconciliationPlan(pendingDigest, command.Disposition,
		command.EvaluatedAtUnixNano, admission.CommitNotAfterUnixNano(), command.Evidence,
		completion, memberCompletion, tombstones, requirement, originalEnvelope)
}

func newPendingReconciliationPlan(pendingDigest [32]byte, disposition PendingDisposition,
	evaluatedAt, notBefore int64, failureEvidence PendingReconciliationEvidence, completion []idempotency.Claim,
	memberCompletion []idempotency.CompoundMemberClaim, tombstones []globalid.Claim,
	audit ReconciliationAuditRequirement,
	originalEnvelope []byte) (PendingReconciliationPlan, error) {
	original, err := decodeDurablePendingEnvelope(originalEnvelope)
	if err != nil || original.PendingDigest() != pendingDigest ||
		(original.Kind() != DurablePendingMutation && original.Kind() != DurablePendingKeyEnrollment &&
			original.Kind() != DurablePendingOwnershipTransferCollection &&
			original.Kind() != DurablePendingOwnershipTransferCutover) {
		return PendingReconciliationPlan{}, fmt.Errorf("%w: original envelope", ErrPendingPlanInvalid)
	}
	originalEvaluatedAt, originalCommitNotAfter, ok := durableEnvelopeWindow(original)
	if !ok || originalCommitNotAfter <= originalEvaluatedAt {
		return PendingReconciliationPlan{}, fmt.Errorf("%w: original window", ErrPendingPlanInvalid)
	}
	maxLatency := originalCommitNotAfter - originalEvaluatedAt
	if evaluatedAt > int64(^uint64(0)>>1)-maxLatency {
		return PendingReconciliationPlan{}, ErrInvalidCommitWindow
	}
	commitNotAfter := evaluatedAt + maxLatency
	if commitNotAfter <= evaluatedAt {
		return PendingReconciliationPlan{}, ErrInvalidCommitWindow
	}
	originalEnvelopeDigest := original.Digest()
	completionBytes, err := idempotency.CanonicalBytes(completion)
	if err != nil {
		return PendingReconciliationPlan{}, err
	}
	var memberCompletionBytes []byte
	if len(memberCompletion) != 0 {
		memberCompletion, err = idempotency.NormalizeCompoundMemberClaims(memberCompletion)
		if err != nil || idempotency.ValidateDisjointClaimKeys(completion, memberCompletion) != nil {
			return PendingReconciliationPlan{}, fmt.Errorf("%w: member completions", ErrPendingPlanInvalid)
		}
		memberCompletionBytes, err = idempotency.CompoundMemberCanonicalBytes(memberCompletion)
		if err != nil {
			return PendingReconciliationPlan{}, err
		}
	}
	if original.Kind() == DurablePendingOwnershipTransferCutover {
		if original.cutover == nil || len(memberCompletion) == 0 ||
			!sameCompoundMemberClaims(memberCompletion, original.cutover.memberCompletion) {
			return PendingReconciliationPlan{}, fmt.Errorf("%w: cutover member completions", ErrPendingPlanInvalid)
		}
	} else if len(memberCompletion) != 0 {
		return PendingReconciliationPlan{}, fmt.Errorf("%w: unexpected member completions", ErrPendingPlanInvalid)
	}
	tombstoneBytes, err := globalid.CanonicalBytes(tombstones)
	if err != nil {
		return PendingReconciliationPlan{}, err
	}
	if pendingDigest == ([32]byte{}) || failureEvidence.Verify() != nil ||
		failureEvidence.FinalClockRequirement().Verify() != nil ||
		failureEvidence.FinalClockRequirement().PendingDigest() != pendingDigest ||
		failureEvidence.FinalClockRequirement().OriginalCommitNotAfterUnixNano() != notBefore ||
		failureEvidence.FinalClockRequirement().AuditOccurredAtUnixNano() != evaluatedAt ||
		failureEvidence.Disposition() != disposition ||
		failureEvidence.AuditOccurredAtUnixNano() != evaluatedAt ||
		failureEvidence.OriginalCommitNotAfterUnixNano() != notBefore ||
		(disposition != PendingDispositionExpired && disposition != PendingDispositionFailed) ||
		evaluatedAt < 0 || notBefore <= 0 || audit.auditEventID == "" || audit.eventType == "" ||
		audit.auditIdempotencyKey == ([16]byte{}) || audit.originalAuditIntentDigest == ([32]byte{}) {
		return PendingReconciliationPlan{}, fmt.Errorf("%w: reconciliation components", ErrPendingPlanInvalid)
	}
	policies, err := canonicalDigests(audit.policyDigestsSHA256)
	if err != nil || len(policies) == 0 {
		return PendingReconciliationPlan{}, fmt.Errorf("%w: reconciliation policies", ErrPendingPlanInvalid)
	}
	audit.policyDigestsSHA256 = policies
	audit.subjectIDs, err = canonicalStrings(audit.subjectIDs)
	if err != nil || len(audit.subjectIDs) == 0 || audit.causeCode == "" || audit.occurredAtUnixNano != evaluatedAt {
		return PendingReconciliationPlan{}, fmt.Errorf("%w: reconciliation audit tuple", ErrPendingPlanInvalid)
	}
	policyElements, err := encodedDigestSet(policies)
	if err != nil {
		return PendingReconciliationPlan{}, err
	}
	if disposition == PendingDispositionExpired && evaluatedAt < notBefore {
		return PendingReconciliationPlan{}, ErrInvalidCommitWindow
	}
	parent, joined, err := pendingCompletionBindings(completion)
	if err != nil || audit.auditIdempotencyKey != joined.Key {
		return PendingReconciliationPlan{}, fmt.Errorf("%w: completion bindings", ErrPendingPlanInvalid)
	}
	reservation, err := joinedAuditEventReservation(parent, audit.auditEventID)
	if err != nil {
		return PendingReconciliationPlan{}, err
	}
	eventAssertion, err := joinedAuditEventAssertion(reservation)
	if err != nil || !containsGlobalClaim(tombstones, eventAssertion) {
		return PendingReconciliationPlan{}, fmt.Errorf("%w: audit event tombstone", ErrPendingPlanInvalid)
	}
	if audit.hasSourceAuthorization {
		recordDigest, digestErr := audit.sourceAuthorizationRecord.Digest(ccse.DefaultLimits())
		if digestErr != nil || recordDigest != audit.sourceAuthorizationDigest ||
			audit.sourceAuthorizationRecord.Domain.SenderIdentity != audit.logicalActorIdentity ||
			audit.sourceAuthorizationRecord.Envelope.SignatureKeyID != audit.logicalActorKeyID ||
			audit.sourceAuthorizationRecord.Envelope.CorrelationID != audit.correlationID ||
			!audit.causationID.Present || audit.causationID.Value != audit.sourceAuthorizationRecord.Envelope.MessageID {
			return PendingReconciliationPlan{}, fmt.Errorf("%w: historical audit source", ErrPendingPlanInvalid)
		}
	}
	failureResult, err := newPendingReconciliationResult(pendingDigest, failureEvidence)
	if err != nil {
		return PendingReconciliationPlan{}, fmt.Errorf("%w: failure result: %v", ErrPendingPlanInvalid, err)
	}
	outcome := failureResult.Digest()
	freshProjection, err := ccse.Marshal(512<<10, func(out *ccse.Encoder) {
		out.FixedBytes(pendingDigest[:], 32)
		out.Uint32(uint32(disposition))
		out.Int64(evaluatedAt)
		out.Int64(notBefore)
		out.Int64(commitNotAfter)
		evidenceDigest := failureEvidence.Digest()
		out.FixedBytes(evidenceDigest[:], 32)
		out.FixedBytes(outcome[:], 32)
		out.String(audit.auditEventID)
		out.String(audit.eventType)
		out.String(audit.causeCode)
		out.Int64(audit.occurredAtUnixNano)
		out.FixedBytes(audit.originalAuditIntentDigest[:], 32)
	})
	if err != nil {
		return PendingReconciliationPlan{}, err
	}
	audit.freshRequirementDigest = domainDigest(pendingReconciliationFreshRequirementDomain, freshProjection)
	for _, claim := range memberCompletion {
		if idempotency.ValidateCompoundMemberOutcome(claim, outcome) != nil {
			return PendingReconciliationPlan{}, ErrPendingPlanInvalid
		}
	}
	sourceBytes := []byte(nil)
	if audit.hasSourceAuthorization {
		sourceBytes, err = canonicalSignedAuthorizationEvidence(audit.sourceAuthorizationRecord)
		if err != nil {
			return PendingReconciliationPlan{}, err
		}
	}
	failureEvidenceDigest := failureEvidence.Digest()
	failureEvidenceBytes := failureEvidence.CanonicalBytes()
	failureResultPayload := failureResult.Payload()
	encoded, err := ccse.Marshal(2<<20, func(out *ccse.Encoder) {
		out.FixedBytes(originalEnvelopeDigest[:], 32)
		out.Bytes(originalEnvelope)
		out.FixedBytes(pendingDigest[:], 32)
		out.Uint32(uint32(disposition))
		out.Int64(evaluatedAt)
		out.Int64(notBefore)
		out.Int64(commitNotAfter)
		out.FixedBytes(failureEvidenceDigest[:], 32)
		out.Bytes(failureEvidenceBytes)
		out.String(failureResult.ContentType())
		out.Bytes(failureResultPayload)
		out.FixedBytes(outcome[:], 32)
		out.Bytes(completionBytes)
		out.Bytes(memberCompletionBytes)
		out.Bytes(tombstoneBytes)
		out.String(audit.auditEventID)
		out.String(audit.eventType)
		out.String(audit.logicalActorIdentity)
		out.String(audit.logicalActorKeyID)
		out.FixedBytes(audit.correlationID[:], 16)
		out.Bool(audit.causationID.Present)
		if audit.causationID.Present {
			out.FixedBytes(audit.causationID.Value[:], 16)
		}
		out.FixedBytes(audit.auditIdempotencyKey[:], 16)
		out.FixedBytes(audit.sourceAuthorizationDigest[:], 32)
		out.FixedBytes(audit.originalAuditIntentDigest[:], 32)
		out.String(audit.causeCode)
		out.Int64(audit.occurredAtUnixNano)
		out.Uint32(uint32(len(audit.subjectIDs)))
		for _, subject := range audit.subjectIDs {
			out.String(subject)
		}
		out.FixedBytes(audit.freshRequirementDigest[:], 32)
		out.EncodedSet(policyElements)
		out.Bool(audit.hasSourceAuthorization)
		if audit.hasSourceAuthorization {
			out.Bytes(sourceBytes)
		}
	})
	if err != nil {
		return PendingReconciliationPlan{}, err
	}
	return PendingReconciliationPlan{originalPendingEnvelope: append([]byte(nil), originalEnvelope...),
		originalEnvelopeDigest: originalEnvelopeDigest,
		pendingDigest:          pendingDigest, disposition: disposition,
		evaluatedAtUnixNano: evaluatedAt, commitNotBeforeUnixNano: notBefore,
		commitNotAfterUnixNano: commitNotAfter,
		failureEvidenceDigest:  failureEvidenceDigest,
		failureEvidence:        clonePendingReconciliationEvidence(failureEvidence),
		failureResult:          failureResult, failureOutcomeDigest: outcome,
		idempotencyCompletion:    append([]idempotency.Claim(nil), completion...),
		compoundMemberCompletion: append([]idempotency.CompoundMemberClaim(nil), memberCompletion...),
		identifierTombstones:     append([]globalid.Claim(nil), tombstones...), audit: audit,
		digest: domainDigest(pendingReconciliationPlanDomain, encoded)}, nil
}

func reconciliationCauseCode(disposition PendingDisposition) string {
	if disposition == PendingDispositionExpired {
		return "iam-operation-deadline-exceeded"
	}
	return "iam-operation-failed"
}

func durableEnvelopeWindow(envelope DurablePendingEnvelope) (int64, int64, bool) {
	switch envelope.Kind() {
	case DurablePendingMutation:
		if envelope.mutation == nil {
			return 0, 0, false
		}
		return envelope.mutation.EvaluatedAtUnixNano(), envelope.mutation.CommitNotAfterUnixNano(), true
	case DurablePendingKeyEnrollment:
		if envelope.enrollment == nil {
			return 0, 0, false
		}
		return envelope.enrollment.EvaluatedAtUnixNano(), envelope.enrollment.CommitNotAfterUnixNano(), true
	case DurablePendingOwnershipTransferCollection:
		if envelope.transfer == nil {
			return 0, 0, false
		}
		return envelope.transfer.EvaluatedAtUnixNano(), envelope.transfer.CommitNotAfterUnixNano(), true
	case DurablePendingOwnershipTransferCutover:
		if envelope.cutover == nil {
			return 0, 0, false
		}
		return envelope.cutover.EvaluatedAtUnixNano(), envelope.cutover.CommitNotAfterUnixNano(), true
	default:
		return 0, 0, false
	}
}
