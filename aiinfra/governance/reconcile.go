// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"sort"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

// ReconcilePolicyOperation closes a stranded X/Y COLLECTING pair without
// changing policy-registry state. It appends the exact signed FAILED/TIMED_OUT
// audit event and completes both idempotency rows in one commit-ready plan.
func (p *Planner) ReconcilePolicyOperation(ctx context.Context, command PolicyReconcileCommand) (MutationPlan, error) {
	if p == nil || p.canonical == nil || command.AtUnixNano < 0 ||
		(command.Outcome != 3 && command.Outcome != 4) || command.Binding.Domain != idempotency.OperationGovernancePolicy {
		return MutationPlan{}, ErrInvalidCommand
	}
	decision, err := idempotency.PrecheckJoined(ctx, p.idempotency, command.Binding)
	if err != nil {
		return MutationPlan{}, err
	}
	if decision.Kind() == idempotency.DuplicateCompleted {
		return MutationPlan{}, DuplicateCompletedError{OutcomeDigestSHA256: decision.OutcomeDigest()}
	}
	if decision.Kind() != idempotency.ContinueCollection {
		return MutationPlan{}, ErrApprovalCollection
	}
	joinedBinding, err := idempotency.JoinedAuditBinding(command.Binding)
	if err != nil || !validJoinedAuditReservation(decision.AuditSnapshot(), joinedBinding) {
		return MutationPlan{}, ErrApprovalCollection
	}
	approvals, err := p.loadPolicyApprovalCollectionForReconcile(ctx, command.Binding, decision.ParentSnapshot())
	if err != nil {
		return MutationPlan{}, err
	}
	bundle := approvals[0].bundle
	deadline, err := p.policyReconciliationDeadline(ctx, approvals)
	if err != nil {
		return MutationPlan{}, err
	}
	if deadline == math.MaxInt64 || command.AtUnixNano < deadline {
		return MutationPlan{}, fmt.Errorf("%w: policy operation is still within its authorization window", ErrInvalidCommand)
	}
	document, err := p.documents.ResolvePolicyDocument(ctx, bundle.PolicyDocumentDigestSHA256)
	if err != nil || !preflightPolicyDocumentSnapshot(document) {
		return MutationPlan{}, ErrSnapshotInconsistent
	}
	document = clonePolicyDocumentSnapshot(document)
	if validatePolicyDocument(document, bundle.PolicyDocumentDigestSHA256, bundle.PolicyDocumentMediaType) != nil {
		return MutationPlan{}, ErrSnapshotInconsistent
	}

	recordDigests := approvalRecordDigests(approvals)
	sources := append([][ccse.DigestSize]byte(nil), recordDigests...)
	sources = uniqueSortedDigests(append(sources, command.Binding.RequestDigest, bundle.PolicyDocumentDigestSHA256))
	transactionEvidence := make(map[[ccse.DigestSize]byte]DurableEvidence, len(sources))
	approvalEvidence := make([]SignedEvidence, 0, len(approvals))
	for _, approval := range approvals {
		evidence := newSignedEvidence(approval.record)
		approvalEvidence = append(approvalEvidence, evidence)
		if _, collision := transactionEvidence[approval.record.digest]; collision {
			return MutationPlan{}, ErrAuditEvidence
		}
		transactionEvidence[approval.record.digest] = newSignedDurableEvidence(
			approval.record, approval.admissionKey.AuthorizationPolicyDigestSHA256, approval.admissionProfileDigest,
		)
	}
	sort.Slice(approvalEvidence, func(i, j int) bool {
		return bytes.Compare(approvalEvidence[i].recordDigest[:], approvalEvidence[j].recordDigest[:]) < 0
	})
	payloadEvidence := newContentEvidence(command.Binding.RequestDigest, approvals[0].record.record.Payload)
	if existing, collision := transactionEvidence[command.Binding.RequestDigest]; collision &&
		(existing.kind != payloadEvidence.kind || !bytes.Equal(existing.content, payloadEvidence.content)) {
		return MutationPlan{}, ErrAuditEvidence
	}
	transactionEvidence[command.Binding.RequestDigest] = payloadEvidence
	documentEvidence := newContentEvidence(bundle.PolicyDocumentDigestSHA256, document.CanonicalDocument)
	if existing, collision := transactionEvidence[bundle.PolicyDocumentDigestSHA256]; collision &&
		(existing.kind != documentEvidence.kind || !bytes.Equal(existing.content, documentEvidence.content)) {
		return MutationPlan{}, ErrAuditEvidence
	}
	transactionEvidence[bundle.PolicyDocumentDigestSHA256] = documentEvidence
	eventID, err := idempotency.JoinedAuditEventID(command.Binding)
	if err != nil {
		return MutationPlan{}, ErrInvalidCommand
	}
	var terminalTemplate DurablePendingTerminalTemplate
	hasLegacy := false
	for _, approval := range approvals {
		hasLegacy = hasLegacy || approval.legacyAdmission
	}
	// Legacy V1 collection rows predate the canonical kind-7 pending envelope.
	// Completing X/Y without an exact pending predecessor would violate the
	// durable storage invariant, and synthesizing one from retained votes would
	// manufacture state. Such rows require an explicit offline migration.
	if hasLegacy {
		return MutationPlan{}, ErrApprovalCollection
	}
	terminalTemplate, err = p.buildPolicyApprovalTerminalTemplate(ctx, command.Binding,
		decision.ParentSnapshot(), policyApprovalEntriesFromApprovals(approvals), eventID)
	if err != nil {
		return MutationPlan{}, err
	}
	cause := "policy-mutation-failed"
	eventType := "PolicyMutationFailed"
	if command.Outcome == 4 {
		cause = "policy-operation-deadline-exceeded"
		eventType = "PolicyMutationTimedOut"
	}
	intentValue := AuditIntentSnapshot{
		Required: true, StreamID: p.profile.AuditReplayDomainID, EventType: eventType, AuditEventID: eventID,
		ActorIdentity: p.profile.AuditWriterIdentity, ActorKeyID: p.profile.AuditWriterKeyID,
		SubjectIDs: uniqueSortedStrings([]string{bundle.PolicyBundleID, bundle.Metadata.RecordID}), CauseCode: cause,
		OccurredAtUnixNano: command.AtUnixNano, Outcome: command.Outcome, IdempotencyKey: joinedBinding.Key,
		CorrelationID:              approvals[0].record.record.Envelope.CorrelationID,
		CausationID:                approvals[0].record.record.Envelope.CausationID,
		AppliedPolicyDigestsSHA256: uniqueSortedDigests(append(append([][ccse.DigestSize]byte(nil), bundle.Metadata.PolicyDigestsSHA256...), p.profileDigest)),
		EvidenceDigestsSHA256:      sources, Emergency: bundle.Emergency,
	}
	if bundle.BreakGlassExpiresAtUnixNano.Present {
		intentValue.BreakGlassExpiresAtUnixNano = bundle.BreakGlassExpiresAtUnixNano.Value
		if scopes, decodeErr := decodeBreakGlassDocument(document, bundle.PolicyDocumentDigestSHA256, bundle.PolicyDocumentMediaType, bundle.PolicyKind); decodeErr == nil {
			intentValue.BreakGlassScopes = uniqueSortedStrings(scopes)
		}
	}
	expectedIntent, err := newAuditIntent(intentValue)
	if err != nil {
		return MutationPlan{}, err
	}
	auditPlan, actualIntent, err := p.planAuditAppend(ctx, AuditAppendCommand{
		AtUnixNano: command.AtUnixNano, Event: command.AuditEvent, SourceRecordDigestsSHA256: sources,
	}, transactionEvidence, ptrIdempotencySnapshot(decision.AuditSnapshot()), &command.Binding,
		policyPendingEvidenceLinksFromDigests(command.Binding.Key, decision.ParentSnapshot().Version, recordDigests))
	if err != nil {
		return MutationPlan{}, err
	}
	if !auditIntentSatisfiesPending(actualIntent.Snapshot(), expectedIntent.Snapshot()) {
		return MutationPlan{}, ErrAuditRequired
	}
	audit := auditPlan.Snapshot()
	if audit.IdempotencyOutcome != command.Outcome || len(audit.IdempotencyClaims) != 1 {
		return MutationPlan{}, ErrAuditRequired
	}
	completeParent, err := idempotency.NewCompleteCollection(decision.ParentSnapshot())
	if err != nil {
		return MutationPlan{}, ErrApprovalCollection
	}
	claims, err := idempotency.NormalizeClaims(append([]idempotency.Claim{completeParent}, audit.IdempotencyClaims...))
	if err != nil {
		return MutationPlan{}, ErrApprovalCollection
	}
	identifierClaims, err := p.policyAdmissionIdentifierClaims(ctx, bundle, command.Binding.RequestDigest, eventID, idempotency.ContinueCollection)
	if err != nil {
		return MutationPlan{}, err
	}
	identifierClaims, err = globalid.NormalizeClaims(append(identifierClaims, audit.IdentifierClaims...))
	if err != nil {
		return MutationPlan{}, ErrPolicyConflict
	}
	audit.Kind = MutationPolicyAbort
	audit.PolicyBundleID = bundle.PolicyBundleID
	audit.PolicyRecordID = bundle.Metadata.RecordID
	audit.PolicyKind = bundle.PolicyKind
	audit.PolicySequence = bundle.Sequence
	audit.PolicyBundleDigestSHA256 = command.Binding.RequestDigest
	audit.PolicyDocumentDigestSHA256 = bundle.PolicyDocumentDigestSHA256
	audit.PolicyDocumentEvidence = append([]byte(nil), document.CanonicalDocument...)
	audit.PolicyIdempotencySnapshot = decision.ParentSnapshot()
	audit.DurablePolicyApprovalTerminalTemplate = terminalTemplate
	audit.JoinedAuditIdempotencySnapshot = decision.AuditSnapshot()
	audit.ApprovalRecordDigestsSHA256 = recordDigests
	audit.ApprovalEvidence = approvalEvidence
	audit.ApprovalAdmissionEvidence = approvalAdmissionEvidence(approvals)
	audit.ApprovalKeyPreconditions = make([]KeyStatePrecondition, len(approvals))
	for index := range approvals {
		audit.ApprovalKeyPreconditions[index] = keyPrecondition(approvals[index].admissionKey)
	}
	keyReadSet := append([]KeyStatePrecondition(nil), audit.AuditSourceKeyPreconditions...)
	keyReadSet = append(keyReadSet, audit.ApprovalKeyPreconditions...)
	keyReadSet = append(keyReadSet, audit.AuditWriterKeyPrecondition)
	audit.CanonicalKeyStateAssertions, err = p.canonicalKeyStateAssertions(ctx, keyReadSet)
	if err != nil {
		return MutationPlan{}, fmt.Errorf("%w: canonical key read set", err)
	}
	audit.PolicyBundleOwnerDigestSHA256 = policyBundleOwnerDigest(bundle.PolicyKind, bundle.PolicyBundleID)
	audit.IdentifierClaims = identifierClaims
	audit.IdempotencyClaims = claims
	audit.IdempotencyOutcome = command.Outcome
	return newMutationPlan(audit)
}

func ptrIdempotencySnapshot(value idempotency.Snapshot) *idempotency.Snapshot { return &value }

func (p *Planner) loadPolicyApprovalCollectionForReconcile(ctx context.Context, binding idempotency.Binding,
	snapshot idempotency.Snapshot) ([]policyApproval, error) {
	if snapshot.Validate() != nil || snapshot.State != idempotency.StateCollecting || snapshot.Binding != binding {
		return nil, ErrApprovalCollection
	}
	raw, err := p.collections.SnapshotPolicyApprovalCollection(ctx, binding.Key)
	if err != nil || len(raw) == 0 || len(raw) > maxApprovals || snapshot.Version < uint64(len(raw)) {
		return nil, ErrApprovalCollection
	}
	approvals := make([]policyApproval, 0, len(raw))
	var collectionProfileDigest [ccse.DigestSize]byte
	var collectionActivation GovernanceProfileActivationSnapshot
	hasLegacyAdmission := false
	for index := range raw {
		approval, _, decodeErr := p.validatePolicyApprovalAdmission(ctx, raw[index])
		if decodeErr != nil {
			return nil, fmt.Errorf("reconcile approval %d: %w", index, decodeErr)
		}
		profileDigest := approval.admissionProfileDigest
		if index == 0 {
			collectionProfileDigest = profileDigest
		} else if profileDigest != collectionProfileDigest {
			// A single canonical operation cannot change its authorization
			// profile while signatures are being collected. Callers must start
			// a fresh bundle/idempotency operation after profile migration.
			return nil, ErrApprovalCollection
		}
		if !approval.legacyAdmission {
			if collectionActivation == (GovernanceProfileActivationSnapshot{}) {
				collectionActivation = approval.admissionActivation
			} else if approval.admissionActivation != collectionActivation {
				return nil, ErrApprovalCollection
			}
		} else {
			hasLegacyAdmission = true
		}
		// Reconciliation never reinterprets the retained vote under current
		// IAM roles/quorum. validatePolicyApprovalAdmission already verified
		// its complete signature, identity ownership, key lifecycle and
		// profile-at-issuance fingerprint.
		approval.key = cloneKeySnapshot(approval.admissionKey)
		approvals = append(approvals, approval)
	}
	if err := validatePolicyApprovalCollectionShape(binding, approvals); err != nil {
		return nil, err
	}
	progress, err := approvalCollectionDigest(binding, approvals)
	if err != nil {
		return nil, ErrApprovalCollection
	}
	if progress != snapshot.ProgressDigest {
		if !hasLegacyAdmission {
			return nil, ErrApprovalCollection
		}
		legacyProgress, legacyErr := legacyApprovalCollectionDigest(binding, approvals)
		if legacyErr != nil || legacyProgress != snapshot.ProgressDigest {
			return nil, ErrApprovalCollection
		}
	}
	return approvals, contextErr(ctx)
}

// decodePolicyApprovalForReconcile deliberately does not use p.profile. A
// stranded collection may outlive a governance-profile migration; using the
// current profile would either reinterpret old authorization or make the
// mandatory terminal audit impossible. The catalog timeline selects the
// immutable profile that was authoritative when this signature was issued.
func (p *Planner) decodePolicyApprovalForReconcile(ctx context.Context, input SignedRecord) (policyApproval, Profile, [ccse.DigestSize]byte, error) {
	if input.Record == nil || input.Record.Domain.IssuedAtUnixNano < 0 {
		return policyApproval{}, Profile{}, [ccse.DigestSize]byte{}, ErrInvalidSignedRecord
	}
	issuedAt := input.Record.Domain.IssuedAtUnixNano
	activation, active, err := p.profiles.ActiveGovernanceProfile(ctx, issuedAt)
	if err != nil {
		return policyApproval{}, Profile{}, [ccse.DigestSize]byte{}, fmt.Errorf("resolve reconciliation profile: %w", err)
	}
	if !active || !validGovernanceProfileActivation(activation, issuedAt) {
		return policyApproval{}, Profile{}, [ccse.DigestSize]byte{}, ErrApprovalCollection
	}
	profileDigest := activation.GovernanceProfileDigestSHA256
	profile, err := p.resolveHistoricalProfile(ctx, profileDigest, issuedAt)
	if err != nil {
		return policyApproval{}, Profile{}, [ccse.DigestSize]byte{}, err
	}
	signed, err := p.validateHistoricalSignedPolicyRecord(ctx, input, profile)
	if err != nil {
		return policyApproval{}, Profile{}, [ccse.DigestSize]byte{}, err
	}
	decoded, err := p.canonical.Decode(schema.MessageTypePolicyBundle, profile.SchemaVersion, signed.record.Payload)
	if err != nil {
		return policyApproval{}, Profile{}, [ccse.DigestSize]byte{}, ErrInvalidSignedRecord
	}
	bundle, ok := decoded.(foundationv1.PolicyBundleSigningProjection)
	if !ok {
		return policyApproval{}, Profile{}, [ccse.DigestSize]byte{}, ErrInvalidSignedRecord
	}
	identity := signed.record.Domain.SenderIdentity
	keyID := signed.record.Domain.SignatureKeyID
	if bundle.Metadata.CreatedAtUnixNano > issuedAt || len(bundle.ApproverIdentities) == 0 ||
		len(bundle.ApproverIdentities) != len(bundle.ApproverKeyIDs) || len(bundle.ApproverIdentities) > maxApprovals ||
		hasDuplicateStrings(bundle.ApproverIdentities) || hasDuplicateStrings(bundle.ApproverKeyIDs) ||
		!containsString(bundle.ApproverIdentities, identity) || !containsString(bundle.ApproverKeyIDs, keyID) ||
		bundle.MinimumApprovals == 0 || bundle.MinimumApprovals > uint32(len(bundle.ApproverIdentities)) ||
		!containsDigest(bundle.Metadata.PolicyDigestsSHA256, profileDigest) {
		return policyApproval{}, Profile{}, [ccse.DigestSize]byte{}, ErrApprovalSetMismatch
	}
	return policyApproval{record: signed, bundle: bundle}, profile, profileDigest, nil
}

func (p *Planner) policyReconciliationDeadline(ctx context.Context, approvals []policyApproval) (int64, error) {
	if len(approvals) == 0 {
		return math.MaxInt64, ErrApprovalCollection
	}
	deadline := approvals[0].bundle.ExpiresAtUnixNano
	if approvals[0].bundle.State == PolicyStateApprovedDelayed {
		deadline = minimumInt64(deadline, approvals[0].bundle.EffectiveAtUnixNano)
	}
	if approvals[0].bundle.Emergency && approvals[0].bundle.BreakGlassExpiresAtUnixNano.Present {
		deadline = minimumInt64(deadline, approvals[0].bundle.BreakGlassExpiresAtUnixNano.Value)
	}
	for _, approval := range approvals {
		deadline = minimumInt64(deadline, approval.record.record.Domain.ExpiresAtUnixNano)
		if approval.legacyAdmission {
			issuedActivation, activeAtIssue, err := p.profiles.ActiveGovernanceProfile(ctx, approval.record.record.Domain.IssuedAtUnixNano)
			if err != nil {
				return 0, fmt.Errorf("aiinfra governance: resolve reconciliation activation: %w", err)
			}
			admissionActivation, activeAtAdmission, err := p.profiles.ActiveGovernanceProfile(ctx, approval.admissionValidatedAt)
			if err != nil {
				return 0, fmt.Errorf("aiinfra governance: resolve reconciliation admission activation: %w", err)
			}
			if !activeAtIssue || !activeAtAdmission ||
				!validGovernanceProfileActivation(issuedActivation, approval.record.record.Domain.IssuedAtUnixNano) ||
				!validGovernanceProfileActivation(admissionActivation, approval.admissionValidatedAt) ||
				issuedActivation.GovernanceProfileDigestSHA256 != approval.admissionProfileDigest ||
				admissionActivation.GovernanceProfileDigestSHA256 != approval.admissionProfileDigest {
				return 0, ErrApprovalCollection
			}
			deadline = minimumInt64(deadline, issuedActivation.ValidUntilUnixNano)
			deadline = minimumInt64(deadline, admissionActivation.ValidUntilUnixNano)
			continue
		}
		deadline = minimumInt64(deadline, approval.admissionActivation.ValidUntilUnixNano)
	}
	return deadline, nil
}
