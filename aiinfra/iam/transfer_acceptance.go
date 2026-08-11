// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"bytes"
	"context"
	"fmt"
	"reflect"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

const (
	transferAcceptancePlanDomain                 = "CPH-AIIE-IAM-OWNERSHIP-TRANSFER-ACCEPTANCE-PLAN-V1\x00"
	transferAcceptanceMemberSetDomain            = "CPH-AIIE-IAM-OWNERSHIP-TRANSFER-ACCEPTANCE-MEMBER-SET-V1\x00"
	transferAcceptanceGlobalReservationSetDomain = "CPH-AIIE-IAM-OWNERSHIP-TRANSFER-ACCEPTANCE-GLOBAL-RESERVATION-SET-V1\x00"
)

// OwnershipTransferAcceptanceCommand closes a quorum-complete durable
// collection and stages the complete future cutover in the same audited
// transaction. The approval-ingestion API never constructs Accepted state.
type OwnershipTransferAcceptanceCommand struct {
	CollectionKey       [16]byte
	Cutover             OwnershipTransferCutoverCommand
	EvaluatedAtUnixNano int64
	Fence               WriterFence
}

// PendingOwnershipTransferAcceptancePlan is the only acceptance capability.
// It is still noncommittable until joined with the canonical Governance audit
// fragment. Applying it writes Accepted + the cutover Pending envelope and
// reserves cutover X/Y, all compound members and future global identifiers.
type PendingOwnershipTransferAcceptancePlan struct {
	collection                    OwnershipTransferApprovalCollectionSnapshot
	expectedCollectionVersion     uint64
	expectedCollectionProgress    [32]byte
	expectedCollectionHomeRegion  string
	expectedCollectionWriterEpoch uint64
	authorizedWriterEpoch         uint64
	writerEvidenceDigest          [32]byte
	writerFence                   WriterFence
	accepted                      AcceptedOwnershipTransferSnapshot
	cutover                       PendingOwnershipTransferCutoverPlan
	transferCompletion            []idempotency.Claim
	identifierAssertions          []globalid.Claim
	dependencies                  []SnapshotPrecondition
	audit                         AuditIntent
	evaluatedAtUnixNano           int64
	commitNotBeforeUnixNano       int64
	commitNotAfterUnixNano        int64
	digest                        [32]byte
}

func clonePendingOwnershipTransferAcceptancePlan(source PendingOwnershipTransferAcceptancePlan) (
	result PendingOwnershipTransferAcceptancePlan) {
	result = source
	result.collection = cloneTransferCollection(source.collection)
	result.accepted = cloneAcceptedTransfer(source.accepted)
	result.cutover = clonePendingOwnershipTransferCutoverPlan(source.cutover)
	result.transferCompletion = append([]idempotency.Claim(nil), source.transferCompletion...)
	result.identifierAssertions = append([]globalid.Claim(nil), source.identifierAssertions...)
	result.dependencies = append([]SnapshotPrecondition(nil), source.dependencies...)
	result.audit = cloneAuditIntent(source.audit)
	return result
}

func (PendingOwnershipTransferAcceptancePlan) CommitReady() bool     { return false }
func (plan PendingOwnershipTransferAcceptancePlan) Digest() [32]byte { return plan.digest }
func (plan PendingOwnershipTransferAcceptancePlan) Collection() OwnershipTransferApprovalCollectionSnapshot {
	return cloneTransferCollection(plan.collection)
}
func (plan PendingOwnershipTransferAcceptancePlan) AcceptedTransfer() AcceptedOwnershipTransferSnapshot {
	return cloneAcceptedTransfer(plan.accepted)
}

// CutoverDigest binds the nested admission without exposing an independently
// persistable cutover capability. The full pending bytes are emitted only by
// the acceptance durable envelope.
func (plan PendingOwnershipTransferAcceptancePlan) CutoverDigest() [32]byte {
	return plan.cutover.Digest()
}
func (plan PendingOwnershipTransferAcceptancePlan) TransferCompletionClaims() []idempotency.Claim {
	return append([]idempotency.Claim(nil), plan.transferCompletion...)
}
func (plan PendingOwnershipTransferAcceptancePlan) WriterFence() WriterFence {
	return plan.writerFence
}
func (plan PendingOwnershipTransferAcceptancePlan) IdentifierAssertions() []globalid.Claim {
	return append([]globalid.Claim(nil), plan.identifierAssertions...)
}
func (plan PendingOwnershipTransferAcceptancePlan) Dependencies() []SnapshotPrecondition {
	return append([]SnapshotPrecondition(nil), plan.dependencies...)
}
func (plan PendingOwnershipTransferAcceptancePlan) AuditIntent() AuditIntent {
	return cloneAuditIntent(plan.audit)
}
func (plan PendingOwnershipTransferAcceptancePlan) EvaluatedAtUnixNano() int64 {
	return plan.evaluatedAtUnixNano
}
func (plan PendingOwnershipTransferAcceptancePlan) CommitNotBeforeUnixNano() int64 {
	return plan.commitNotBeforeUnixNano
}
func (plan PendingOwnershipTransferAcceptancePlan) CommitNotAfterUnixNano() int64 {
	return plan.commitNotAfterUnixNano
}
func (plan PendingOwnershipTransferAcceptancePlan) VerifyDigest() error {
	return verifyOwnershipTransferAcceptancePlan(plan)
}

type candidateAcceptedTransferView struct {
	View
	snapshot AcceptedOwnershipTransferSnapshot
}

func (view *candidateAcceptedTransferView) LookupAcceptedOwnershipTransfer(ctx context.Context,
	digest [32]byte) (AcceptedOwnershipTransferSnapshot, bool, error) {
	if digest == view.snapshot.TransferEvidenceDigest {
		return cloneAcceptedTransfer(view.snapshot), true, nil
	}
	return view.View.LookupAcceptedOwnershipTransfer(ctx, digest)
}

func (view *candidateAcceptedTransferView) SnapshotCompoundMemberState(ctx context.Context,
	key [16]byte) (idempotency.CompoundMemberSnapshot, bool, idempotency.Snapshot, bool,
	idempotency.Snapshot, bool, error) {
	compound, ok := view.View.(idempotency.CompoundMemberView)
	if !ok {
		return idempotency.CompoundMemberSnapshot{}, false, idempotency.Snapshot{}, false,
			idempotency.Snapshot{}, false, ErrViewRequired
	}
	return compound.SnapshotCompoundMemberState(ctx, key)
}

// PlanOwnershipTransferAcceptance loads the authoritative quorum collection;
// caller-constructed Accepted snapshots are never accepted as authority.
func (p *Planner) PlanOwnershipTransferAcceptance(ctx context.Context,
	command OwnershipTransferAcceptanceCommand) (PendingOwnershipTransferAcceptancePlan, error) {
	if err := p.ready(); err != nil {
		return PendingOwnershipTransferAcceptancePlan{}, err
	}
	if command.CollectionKey == ([16]byte{}) || command.EvaluatedAtUnixNano < 0 ||
		command.Cutover.EvaluatedAtUnixNano != command.EvaluatedAtUnixNano {
		return PendingOwnershipTransferAcceptancePlan{}, ErrTransferAuthorizationRequired
	}
	raw, found, err := p.view.SnapshotOwnershipTransferApprovalCollection(ctx, command.CollectionKey)
	if err != nil || !found || preflightTransferAcceptanceInput(raw, command.Cutover) != nil {
		return PendingOwnershipTransferAcceptancePlan{}, ErrTransferCollectionMismatch
	}
	collection := cloneTransferCollection(raw)
	progress, err := transferCollectionDigest(collection)
	if err != nil || progress != collection.ProgressDigest || collection.Binding.Key != command.CollectionKey {
		return PendingOwnershipTransferAcceptancePlan{}, ErrTransferCollectionMismatch
	}
	projection, canonical, transferDigest, err := normalizeOwnershipTransferPayload(collection.CanonicalPayload)
	if err != nil || transferDigest != collection.TransferEvidenceDigest ||
		!transferQuorumSatisfied(collection.Profile, collection.ProfileDigest, collection.Approvals) {
		return PendingOwnershipTransferAcceptancePlan{}, ErrTransferAuthorizationRequired
	}
	if command.Cutover.TransferEvidenceDigest != transferDigest ||
		command.EvaluatedAtUnixNano < collection.Profile.Activation.ValidFromUnixNano ||
		command.EvaluatedAtUnixNano >= collection.Profile.Activation.ValidUntilUnixNano {
		return PendingOwnershipTransferAcceptancePlan{}, ErrTransferAuthorizationRequired
	}
	entity := EntityRef{Kind: EntityOwnershipTransfer, PrincipalKind: projection.SubjectKind,
		ID: projection.TransferAuthorizationID}
	if command.Fence.ExpectedStateVersion != collection.Version ||
		command.Fence.WriterEpoch < collection.WriterEpoch ||
		(command.Fence.HomeRegion != collection.HomeRegion && command.Fence.WriterEpoch <= collection.WriterEpoch) {
		return PendingOwnershipTransferAcceptancePlan{}, ErrWriterFenceMismatch
	}
	lease, err := p.validateFence(ctx, entity, command.Fence, command.EvaluatedAtUnixNano,
		command.Fence.HomeRegion, command.Fence.WriterEpoch)
	if err != nil {
		return PendingOwnershipTransferAcceptancePlan{}, err
	}
	if err := p.profile.ValidateAuthority(ctx, AuthorityRequest{Mutation: MutationCollectOwnershipTransfer,
		Entity: entity, ActorIdentity: command.Fence.WriterIdentity,
		EvaluatedAtUnixNano: command.EvaluatedAtUnixNano,
		PolicyDigestsSHA256: cloneDigests(projection.Metadata.PolicyDigestsSHA256)}); err != nil {
		return PendingOwnershipTransferAcceptancePlan{}, fmt.Errorf("aiinfra iam: transfer acceptance authority: %w", err)
	}
	refreshed, err := p.refreshTransferApprovals(ctx, collection.Approvals,
		collection.ProfileDigest, collection.Profile.Activation.SnapshotDigest,
		command.EvaluatedAtUnixNano)
	if err != nil {
		return PendingOwnershipTransferAcceptancePlan{}, err
	}
	// The accepted authorization retains the exact immutable collection
	// admissions. Acceptance-time ACTIVE assertions are transaction
	// dependencies, not a rewrite of the already committed approval evidence.
	accepted := AcceptedOwnershipTransferSnapshot{Projection: cloneTransferProjection(projection),
		CanonicalPayload: canonical, TransferEvidenceDigest: transferDigest,
		Profile: cloneTransferProfile(collection.Profile), ProfileDigest: collection.ProfileDigest,
		Approvals:          cloneTransferCollection(collection).Approvals,
		FixedEvidence:      cloneTransferFixedEvidence(collection.FixedEvidence),
		AcceptedAtUnixNano: command.EvaluatedAtUnixNano, StateVersion: collection.Version,
		WriterEpoch: command.Fence.WriterEpoch}
	accepted.SnapshotDigest, err = acceptedTransferDigest(accepted)
	if err != nil {
		return PendingOwnershipTransferAcceptancePlan{}, err
	}
	if existing, exists, lookupErr := p.view.LookupAcceptedOwnershipTransfer(ctx, transferDigest); lookupErr != nil || exists || existing.SnapshotDigest != ([32]byte{}) {
		return PendingOwnershipTransferAcceptancePlan{}, ErrTransferCollectionMismatch
	}

	decision, err := idempotency.PrecheckJoined(ctx, p.view, collection.Binding)
	if err != nil || decision.Kind() != idempotency.ContinueCollection {
		return PendingOwnershipTransferAcceptancePlan{}, ErrPendingPlanInvalid
	}
	parentSnapshot, auditSnapshot := decision.ParentSnapshot(), decision.AuditSnapshot()
	if parentSnapshot.Binding != collection.Binding || parentSnapshot.State != idempotency.StateCollecting ||
		parentSnapshot.Version != collection.Version || parentSnapshot.ProgressDigest != collection.ProgressDigest {
		return PendingOwnershipTransferAcceptancePlan{}, ErrPendingPlanInvalid
	}
	parentCompletion, err := idempotency.NewCompleteCollection(parentSnapshot)
	if err != nil {
		return PendingOwnershipTransferAcceptancePlan{}, err
	}
	auditCompletion, err := idempotency.NewCompleteCollection(auditSnapshot)
	if err != nil {
		return PendingOwnershipTransferAcceptancePlan{}, err
	}
	transferCompletion, err := idempotency.NormalizeClaims([]idempotency.Claim{parentCompletion, auditCompletion})
	if err != nil {
		return PendingOwnershipTransferAcceptancePlan{}, err
	}

	candidateView := &candidateAcceptedTransferView{View: p.view, snapshot: accepted}
	cutoverPlanner := *p
	cutoverPlanner.view = candidateView
	cutover, err := cutoverPlanner.planOwnershipTransferCutoverCandidate(ctx, command.Cutover,
		ownershipTransferCutoverCandidateToken{})
	if err != nil {
		return PendingOwnershipTransferAcceptancePlan{}, err
	}
	// The candidate path independently re-verifies every retained approval and
	// evidence signature against authoritative historical IAM state. Only after
	// that succeeds may untrusted stored EvidenceRecords reach the frozen policy
	// callback.
	if err := p.revalidateAcceptanceEvidencePolicy(ctx, projection, transferDigest,
		collection, command.EvaluatedAtUnixNano); err != nil {
		return PendingOwnershipTransferAcceptancePlan{}, err
	}
	coordinator, ok := transferCoordinator(collection.Profile)
	if !ok {
		return PendingOwnershipTransferAcceptancePlan{}, ErrTransferAuthorizationRequired
	}
	eventID, err := idempotency.JoinedAuditEventID(collection.Binding)
	if err != nil {
		return PendingOwnershipTransferAcceptancePlan{}, err
	}
	identifierAssertions, err := p.transferCollectionIdentifierClaims(ctx, projection,
		collection.FixedEvidence, eventID, false)
	if err != nil {
		return PendingOwnershipTransferAcceptancePlan{}, err
	}
	baseAudit, err := newOwnershipTransferAuditIntent(collection.Binding,
		auditSnapshot.Binding, eventID, accepted, coordinator, command.EvaluatedAtUnixNano)
	if err != nil {
		return PendingOwnershipTransferAcceptancePlan{}, err
	}
	audit, err := bindAcceptanceAuditToCutover(*baseAudit, cutover)
	if err != nil {
		return PendingOwnershipTransferAcceptancePlan{}, err
	}
	if err := validateAcceptanceIdempotencyDisjoint(transferCompletion, cutover); err != nil {
		return PendingOwnershipTransferAcceptancePlan{}, err
	}
	dependencies, err := transferCollectionDependencies(refreshed, collection.FixedEvidence,
		collection.Profile, projection.SubjectKind)
	if err != nil {
		return PendingOwnershipTransferAcceptancePlan{}, err
	}
	acceptedPrecondition := accepted.Precondition()
	for _, dependency := range cutover.Dependencies() {
		// The Accepted row is created by this transaction. Its existing-row
		// assertion belongs to the later cutover finalization; every other
		// historical/current authority fence must already hold at admission.
		if dependency == acceptedPrecondition {
			continue
		}
		conflictsWithCurrentFence := false
		for _, current := range dependencies {
			if current.Entity == dependency.Entity {
				// Acceptance locks the authoritative current row. A retained
				// historical proof may name an older version of that same
				// semantic entity; it is rechecked again from history at cutover.
				conflictsWithCurrentFence = true
				break
			}
		}
		if conflictsWithCurrentFence {
			continue
		}
		dependencies = append(dependencies, dependency)
	}
	dependencies, err = canonicalPreconditions(dependencies)
	if err != nil {
		return PendingOwnershipTransferAcceptancePlan{}, err
	}
	receiver, err := p.profile.ReceiverProfile(ctx, schema.MessageTypeOwnershipTransferAuthorization)
	if err != nil || validateReceiverProfile(receiver) != nil {
		return PendingOwnershipTransferAcceptancePlan{}, ErrAuthorizationMismatch
	}
	starts, ends := transferCollectionTimeBounds(collection, lease)
	ends = append(ends, cutover.CommitNotAfterUnixNano())
	window, err := newPlanWindow(receiver, command.EvaluatedAtUnixNano, starts, ends)
	if err != nil {
		return PendingOwnershipTransferAcceptancePlan{}, err
	}
	plan := PendingOwnershipTransferAcceptancePlan{collection: collection,
		expectedCollectionVersion: collection.Version, expectedCollectionProgress: collection.ProgressDigest,
		expectedCollectionHomeRegion:  collection.HomeRegion,
		expectedCollectionWriterEpoch: collection.WriterEpoch,
		authorizedWriterEpoch:         command.Fence.WriterEpoch, writerEvidenceDigest: command.Fence.EvidenceDigest,
		writerFence: command.Fence,
		accepted:    accepted, cutover: cutover, transferCompletion: transferCompletion,
		identifierAssertions: identifierAssertions,
		dependencies:         dependencies, audit: audit, evaluatedAtUnixNano: command.EvaluatedAtUnixNano,
		commitNotBeforeUnixNano: window.CommitNotBeforeUnixNano,
		commitNotAfterUnixNano:  window.CommitNotAfterUnixNano}
	plan.digest, err = ownershipTransferAcceptancePlanDigest(plan)
	if err != nil || plan.VerifyDigest() != nil {
		return PendingOwnershipTransferAcceptancePlan{}, ErrPendingPlanInvalid
	}
	return plan, nil
}

func (p *Planner) revalidateAcceptanceEvidencePolicy(ctx context.Context,
	projection foundationv1.OwnershipTransferAuthorizationSigningProjection, transferDigest [32]byte,
	collection OwnershipTransferApprovalCollectionSnapshot, at int64) error {
	commitments := make(map[[32]byte]uint32, len(projection.EvidenceCommitments))
	for _, commitment := range projection.EvidenceCommitments {
		commitments[commitment.CCSERecordDigestSHA256] = commitment.EvidenceKind
	}
	if len(commitments) != len(collection.FixedEvidence.EvidenceRecords) {
		return ErrTransferAuthorizationRequired
	}
	for _, retained := range collection.FixedEvidence.EvidenceRecords {
		kind, found := commitments[retained.digest]
		if !found {
			return ErrTransferAuthorizationRequired
		}
		if err := p.profile.ValidateOwnershipTransferEvidence(ctx, OwnershipTransferEvidenceRequest{
			TransferAuthorizationID: projection.TransferAuthorizationID,
			TransferEvidenceDigest:  transferDigest, Profile: cloneTransferProfile(collection.Profile),
			ProfileDigest: collection.ProfileDigest, Activation: collection.Profile.Activation,
			EvidenceKind: kind, Record: retained.Record(), RecordDigest: retained.digest,
			EvaluatedAtUnixNano: at,
		}); err != nil {
			return fmt.Errorf("aiinfra iam: transfer acceptance evidence policy: %w", err)
		}
	}
	return nil
}

func bindAcceptanceAuditToCutover(base AuditIntent,
	cutover PendingOwnershipTransferCutoverPlan) (AuditIntent, error) {
	memberBytes, err := idempotency.CompoundMemberCanonicalBytes(cutover.memberAdmission)
	if err != nil {
		return AuditIntent{}, err
	}
	globalBytes, err := globalid.CanonicalBytes(cutover.admission.identifierReservations)
	if err != nil {
		return AuditIntent{}, err
	}
	evidence := append(base.EvidenceDigestsSHA256(), cutover.Digest(), cutover.admission.Digest(),
		cutover.admission.CoreEvidenceDigest(), domainDigest(transferAcceptanceMemberSetDomain, memberBytes),
		domainDigest(transferAcceptanceGlobalReservationSetDomain, globalBytes))
	source := auditSourceEvidence{Present: base.hasSourceAuthorization, ActorKeyID: base.actorKeyID,
		Record: cloneCCSERecord(base.sourceAuthorizationRecord), Digest: base.sourceAuthorizationDigest,
		CausationID: base.sourceCausationID}
	return newAuditIntent(base.auditEventID, base.eventType, base.actorIdentity, base.subjectIDs,
		base.causeCode, base.correlationID, base.causationID, base.messageID,
		base.idempotencyKey, base.expectedAuditIdempotencyKey, source, base.occurredAtUnixNano,
		base.policyDigestsSHA256, evidence)
}

func ownershipTransferAcceptancePlanDigest(plan PendingOwnershipTransferAcceptancePlan) ([32]byte, error) {
	var zero [32]byte
	if plan.cutover.VerifyDigest() != nil || verifyAuditIntent(plan.audit) != nil {
		return zero, ErrPendingPlanInvalid
	}
	completion, err := idempotency.CanonicalBytes(plan.transferCompletion)
	if err != nil {
		return zero, err
	}
	dependencies, err := canonicalSnapshotPreconditions(plan.dependencies)
	if err != nil {
		return zero, err
	}
	identifiers, err := globalid.CanonicalBytes(plan.identifierAssertions)
	if err != nil {
		return zero, err
	}
	encoded, err := ccse.Marshal(2<<20, func(out *ccse.Encoder) {
		bindingDigest, _ := idempotency.BindingDigest(plan.collection.Binding)
		out.FixedBytes(bindingDigest[:], 32)
		out.Uint64(plan.expectedCollectionVersion)
		out.FixedBytes(plan.expectedCollectionProgress[:], 32)
		out.String(plan.expectedCollectionHomeRegion)
		out.Uint64(plan.expectedCollectionWriterEpoch)
		out.Uint64(plan.authorizedWriterEpoch)
		out.FixedBytes(plan.writerEvidenceDigest[:], 32)
		out.Uint32(uint32(plan.writerFence.Entity.Kind))
		out.Uint32(plan.writerFence.Entity.PrincipalKind)
		out.String(plan.writerFence.Entity.ID)
		out.String(plan.writerFence.WriterIdentity)
		out.String(plan.writerFence.HomeRegion)
		out.Uint64(plan.writerFence.WriterEpoch)
		out.Uint64(plan.writerFence.ExpectedStateVersion)
		out.FixedBytes(plan.writerFence.EvidenceDigest[:], 32)
		out.FixedBytes(plan.accepted.SnapshotDigest[:], 32)
		cutoverDigest := plan.cutover.Digest()
		out.FixedBytes(cutoverDigest[:], 32)
		out.Bytes(completion)
		out.Bytes(identifiers)
		out.Bytes(dependencies)
		auditDigest := plan.audit.Digest()
		out.FixedBytes(auditDigest[:], 32)
		out.Int64(plan.evaluatedAtUnixNano)
		out.Int64(plan.commitNotBeforeUnixNano)
		out.Int64(plan.commitNotAfterUnixNano)
	})
	if err != nil {
		return zero, err
	}
	return domainDigest(transferAcceptancePlanDomain, encoded), nil
}

func verifyOwnershipTransferAcceptancePlan(plan PendingOwnershipTransferAcceptancePlan) error {
	progress, progressErr := transferCollectionDigest(plan.collection)
	acceptedDigest, acceptedErr := acceptedTransferDigest(plan.accepted)
	if preflightTransferCollection(plan.collection) != nil || preflightAcceptedTransfer(plan.accepted) != nil ||
		progressErr != nil || progress != plan.collection.ProgressDigest ||
		acceptedErr != nil || acceptedDigest != plan.accepted.SnapshotDigest ||
		plan.cutover.VerifyDigest() != nil || verifyAuditIntent(plan.audit) != nil {
		return fmt.Errorf("%w: invalid acceptance component digest", ErrPendingPlanInvalid)
	}
	if plan.collection.Binding.Key == ([16]byte{}) ||
		snapshotBinding(plan.accepted) != plan.collection.Binding ||
		!acceptedTransferDerivedFromCollection(plan.accepted, plan.collection) ||
		plan.accepted.TransferEvidenceDigest != plan.collection.TransferEvidenceDigest ||
		!reflect.DeepEqual(cloneAcceptedTransfer(plan.cutover.accepted), cloneAcceptedTransfer(plan.accepted)) {
		return fmt.Errorf("%w: collection/accepted/cutover binding mismatch", ErrPendingPlanInvalid)
	}
	if plan.expectedCollectionVersion != plan.collection.Version ||
		plan.expectedCollectionProgress != plan.collection.ProgressDigest ||
		plan.expectedCollectionHomeRegion != plan.collection.HomeRegion ||
		plan.expectedCollectionWriterEpoch != plan.collection.WriterEpoch ||
		plan.authorizedWriterEpoch < plan.expectedCollectionWriterEpoch ||
		(plan.writerFence.HomeRegion != plan.expectedCollectionHomeRegion &&
			plan.authorizedWriterEpoch <= plan.expectedCollectionWriterEpoch) ||
		plan.writerFence.ExpectedStateVersion != plan.expectedCollectionVersion ||
		plan.writerFence.WriterEpoch != plan.authorizedWriterEpoch ||
		plan.writerFence.EvidenceDigest != plan.writerEvidenceDigest ||
		plan.writerFence.Entity != (EntityRef{Kind: EntityOwnershipTransfer,
			PrincipalKind: plan.accepted.Projection.SubjectKind,
			ID:            plan.accepted.Projection.TransferAuthorizationID}) ||
		plan.writerFence.WriterIdentity == "" || plan.writerFence.HomeRegion == "" ||
		plan.writerEvidenceDigest == ([32]byte{}) {
		return fmt.Errorf("%w: collection writer fence mismatch", ErrPendingPlanInvalid)
	}
	if plan.evaluatedAtUnixNano < 0 ||
		plan.accepted.AcceptedAtUnixNano != plan.evaluatedAtUnixNano ||
		plan.accepted.WriterEpoch != plan.authorizedWriterEpoch ||
		plan.cutover.EvaluatedAtUnixNano() != plan.evaluatedAtUnixNano ||
		plan.commitNotBeforeUnixNano > plan.evaluatedAtUnixNano ||
		plan.commitNotAfterUnixNano <= plan.evaluatedAtUnixNano ||
		plan.commitNotAfterUnixNano > plan.cutover.CommitNotAfterUnixNano() {
		return fmt.Errorf("%w: acceptance/cutover time relation mismatch", ErrPendingPlanInvalid)
	}
	parent := idempotency.Snapshot{Binding: plan.collection.Binding, State: idempotency.StateCollecting,
		Version: plan.collection.Version, ProgressDigest: plan.collection.ProgressDigest}
	joined, err := idempotency.JoinedAuditBinding(plan.collection.Binding)
	if err != nil {
		return ErrPendingPlanInvalid
	}
	parentCompletion, err := idempotency.NewCompleteCollection(parent)
	if err != nil {
		return ErrPendingPlanInvalid
	}
	parentDigest, err := idempotency.BindingDigest(plan.collection.Binding)
	if err != nil {
		return ErrPendingPlanInvalid
	}
	auditSnapshot := idempotency.Snapshot{Binding: joined, State: idempotency.StateCollecting,
		Version: 1, ProgressDigest: parentDigest}
	auditCompletion, err := idempotency.NewCompleteCollection(auditSnapshot)
	if err != nil {
		return ErrPendingPlanInvalid
	}
	expectedCompletion, err := idempotency.NormalizeClaims([]idempotency.Claim{parentCompletion, auditCompletion})
	if err != nil || !sameIdempotencyClaims(expectedCompletion, plan.transferCompletion) ||
		validateAcceptanceIdempotencyDisjoint(plan.transferCompletion, plan.cutover) != nil {
		return ErrPendingPlanInvalid
	}
	eventID, err := idempotency.JoinedAuditEventID(plan.collection.Binding)
	if err != nil || eventID != plan.audit.AuditEventID() ||
		verifyTransferIdentifierClaims(plan.collection, OwnershipTransferCollectionReplace,
			plan.identifierAssertions) != nil {
		return ErrPendingPlanInvalid
	}
	if !acceptanceDependenciesContainCutover(plan) {
		return ErrPendingPlanInvalid
	}
	expectedAudit, err := newOwnershipTransferAuditIntent(plan.collection.Binding,
		joined, plan.audit.AuditEventID(), plan.accepted,
		mustTransferCoordinator(plan.accepted.Profile), plan.evaluatedAtUnixNano)
	if err == nil {
		expectedAuditValue, bindErr := bindAcceptanceAuditToCutover(*expectedAudit, plan.cutover)
		err = bindErr
		expectedAudit = &expectedAuditValue
	}
	if err != nil || expectedAudit.Digest() != plan.audit.Digest() {
		return ErrPendingPlanInvalid
	}
	digest, err := ownershipTransferAcceptancePlanDigest(plan)
	if err != nil || digest != plan.digest {
		return ErrPendingPlanInvalid
	}
	return nil
}

func acceptanceDependenciesContainCutover(plan PendingOwnershipTransferAcceptancePlan) bool {
	acceptedPrecondition := plan.accepted.Precondition()
	for _, expected := range plan.cutover.Dependencies() {
		if expected == acceptedPrecondition {
			continue
		}
		found := false
		for _, actual := range plan.dependencies {
			if actual == expected || actual.Entity == expected.Entity {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func acceptedTransferDerivedFromCollection(accepted AcceptedOwnershipTransferSnapshot,
	collection OwnershipTransferApprovalCollectionSnapshot) bool {
	projection, canonical, digest, err := normalizeOwnershipTransferPayload(collection.CanonicalPayload)
	if err != nil || digest != collection.TransferEvidenceDigest ||
		!reflect.DeepEqual(accepted.Projection, projection) ||
		!bytes.Equal(accepted.CanonicalPayload, canonical) ||
		accepted.TransferEvidenceDigest != collection.TransferEvidenceDigest ||
		accepted.ProfileDigest != collection.ProfileDigest ||
		!sameTransferProfile(accepted.Profile, collection.Profile) ||
		!sameTransferFixedEvidence(accepted.FixedEvidence, collection.FixedEvidence) ||
		accepted.StateVersion != collection.Version {
		return false
	}
	acceptedApprovals, acceptedErr := canonicalTransferAdmissions(accepted.Approvals)
	collectionApprovals, collectionErr := canonicalTransferAdmissions(collection.Approvals)
	return acceptedErr == nil && collectionErr == nil && bytes.Equal(acceptedApprovals, collectionApprovals)
}

func validateAcceptanceIdempotencyDisjoint(completion []idempotency.Claim,
	cutover PendingOwnershipTransferCutoverPlan) error {
	ordinary := append([]idempotency.Claim(nil), completion...)
	ordinary = append(ordinary, cutover.admission.idempotencyReservations...)
	if _, err := idempotency.NormalizeClaims(ordinary); err != nil {
		return ErrPendingPlanInvalid
	}
	if err := idempotency.ValidateDisjointClaimKeys(ordinary, cutover.memberAdmission); err != nil {
		return ErrPendingPlanInvalid
	}
	return nil
}

func mustTransferCoordinator(profile OwnershipTransferProfile) OwnershipTransferAuthorityRequirement {
	value, _ := transferCoordinator(profile)
	return value
}
