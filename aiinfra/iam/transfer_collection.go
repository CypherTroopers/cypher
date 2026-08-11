// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

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

const (
	transferApprovalSetAuditDomain = "CPH-AIIE-IAM-OWNERSHIP-TRANSFER-AUDIT-APPROVAL-SET-V1\x00"
	transferFixedAuditDomain       = "CPH-AIIE-IAM-OWNERSHIP-TRANSFER-AUDIT-FIXED-EVIDENCE-V1\x00"
	maxTransferCompoundInputBytes  = uint64(12 << 20)
)

// PlanOwnershipTransferApproval validates and stages one signature over the
// canonical ownership-transfer authorization. The result is deliberately not
// commit-ready: an adapter may persist its COLLECTING admission, but quorum
// acceptance still has to be joined to the canonical Governance AuditEvent,
// audit-head CAS and both X/Y idempotency completions.
func (p *Planner) PlanOwnershipTransferApproval(ctx context.Context,
	command OwnershipTransferApprovalIngestionCommand) (OwnershipTransferApprovalCollectionPlan, error) {
	if err := p.ready(); err != nil {
		return OwnershipTransferApprovalCollectionPlan{}, err
	}
	if err := ctx.Err(); err != nil {
		return OwnershipTransferApprovalCollectionPlan{}, err
	}
	if command.EvaluatedAtUnixNano < 0 {
		return OwnershipTransferApprovalCollectionPlan{}, ErrTransferAuthorizationRequired
	}
	if err := preflightOwnershipTransferCommand(command); err != nil {
		return OwnershipTransferApprovalCollectionPlan{}, ErrTransferAuthorizationRequired
	}

	projection, canonicalPayload, transferDigest, err := normalizeOwnershipTransferPayload(command.Approval.Payload())
	if err != nil {
		return OwnershipTransferApprovalCollectionPlan{}, err
	}
	profileValue, err := p.profile.OwnershipTransferProfile(ctx, transferProfileRequest(projection))
	if err != nil {
		return OwnershipTransferApprovalCollectionPlan{}, fmt.Errorf("aiinfra iam: ownership-transfer profile: %w", err)
	}
	profile, profileDigest, err := normalizeTransferProfile(profileValue, projection)
	if err != nil {
		return OwnershipTransferApprovalCollectionPlan{}, err
	}
	if command.EvaluatedAtUnixNano < profile.Activation.ValidFromUnixNano ||
		command.EvaluatedAtUnixNano >= profile.Activation.ValidUntilUnixNano {
		return OwnershipTransferApprovalCollectionPlan{}, ErrTransferAuthorizationRequired
	}
	if _, ok := transferCoordinator(profile); !ok {
		return OwnershipTransferApprovalCollectionPlan{}, ErrTransferAuthorizationRequired
	}
	entity := EntityRef{Kind: EntityOwnershipTransfer, PrincipalKind: projection.SubjectKind,
		ID: projection.TransferAuthorizationID}
	if command.Fence.WriterIdentity == "" {
		return OwnershipTransferApprovalCollectionPlan{}, ErrWriterFenceMismatch
	}
	if err := p.profile.ValidateAuthority(ctx, AuthorityRequest{Mutation: MutationCollectOwnershipTransfer,
		Entity: entity, ActorIdentity: command.Fence.WriterIdentity,
		EvaluatedAtUnixNano: command.EvaluatedAtUnixNano,
		PolicyDigestsSHA256: cloneDigests(projection.Metadata.PolicyDigestsSHA256)}); err != nil {
		return OwnershipTransferApprovalCollectionPlan{}, fmt.Errorf("aiinfra iam: transfer collection authority: %w", err)
	}

	// This exact signed approval and every digest-committed fixed input are
	// validated before the joined-idempotency lookup. A caller cannot probe a
	// known business key using an unrelated or unsigned payload.
	admission, err := p.validateTransferAuthorityAdmission(ctx, command.Approval, projection,
		canonicalPayload, profile, profileDigest, command.EvaluatedAtUnixNano)
	if err != nil {
		return OwnershipTransferApprovalCollectionPlan{}, err
	}
	fixed, err := p.validateTransferFixedEvidence(ctx, projection, transferDigest, profile, profileDigest,
		command.PreviousTerminalIdentityPayload, command.NextPendingIdentityPayload,
		command.KeyClosureRecords, command.EvidenceRecords, command.EvaluatedAtUnixNano)
	if err != nil {
		return OwnershipTransferApprovalCollectionPlan{}, err
	}

	binding := idempotency.Binding{Key: projection.Metadata.IdempotencyKey,
		Domain:  idempotency.OperationIAMOwnershipTransfer,
		OwnerID: projection.TransferAuthorizationID, RequestDigest: transferDigest}
	if err := binding.Validate(); err != nil {
		return OwnershipTransferApprovalCollectionPlan{}, ErrTransferAuthorizationRequired
	}
	joinedBinding, err := idempotency.JoinedAuditBinding(binding)
	if err != nil {
		return OwnershipTransferApprovalCollectionPlan{}, ErrPendingPlanInvalid
	}
	auditEventID, err := idempotency.JoinedAuditEventID(binding)
	if err != nil {
		return OwnershipTransferApprovalCollectionPlan{}, ErrPendingPlanInvalid
	}
	decision, err := idempotency.PrecheckJoined(ctx, p.view, binding)
	if err != nil {
		return OwnershipTransferApprovalCollectionPlan{}, fmt.Errorf("aiinfra iam: transfer idempotency precheck: %w", err)
	}
	if decision.Kind() == idempotency.DuplicateCompleted {
		if err := p.validateCompletedTransferRetry(ctx, transferDigest, profileDigest, admission); err != nil {
			return OwnershipTransferApprovalCollectionPlan{}, err
		}
		return OwnershipTransferApprovalCollectionPlan{}, IdempotencyCompletedError{Outcome: decision.OutcomeDigest()}
	}

	next := OwnershipTransferApprovalCollectionSnapshot{Binding: binding,
		CanonicalPayload: canonicalPayload, TransferEvidenceDigest: transferDigest,
		Profile: profile, ProfileDigest: profileDigest, FixedEvidence: fixed,
		HomeRegion: command.Fence.HomeRegion, WriterEpoch: command.Fence.WriterEpoch}
	plan := OwnershipTransferApprovalCollectionPlan{evaluatedAtUnixNano: command.EvaluatedAtUnixNano,
		authorizedWriterEpoch: command.Fence.WriterEpoch, writerEvidenceDigest: command.Fence.EvidenceDigest}
	var parentSnapshot, auditSnapshot idempotency.Snapshot
	switch decision.Kind() {
	case idempotency.Proceed:
		if command.Fence.ExpectedStateVersion != 0 {
			return OwnershipTransferApprovalCollectionPlan{}, ErrWriterFenceMismatch
		}
		if command.Fence.HomeRegion != projection.Metadata.HomeRegion ||
			command.Fence.WriterEpoch != projection.Metadata.WriterEpoch {
			return OwnershipTransferApprovalCollectionPlan{}, ErrWriterFenceMismatch
		}
		if stored, found, lookupErr := p.view.SnapshotOwnershipTransferApprovalCollection(ctx, binding.Key); lookupErr != nil {
			return OwnershipTransferApprovalCollectionPlan{}, fmt.Errorf("aiinfra iam: transfer collection lookup: %w", lookupErr)
		} else if found || !zeroTransferCollection(stored) {
			return OwnershipTransferApprovalCollectionPlan{}, ErrTransferCollectionMismatch
		}
		plan.disposition = OwnershipTransferCollectionAppend
		next.Version = 1
		next.Approvals = []OwnershipTransferAuthorityAdmission{admission}
	case idempotency.ContinueCollection:
		parentSnapshot, auditSnapshot = decision.ParentSnapshot(), decision.AuditSnapshot()
		stored, found, lookupErr := p.view.SnapshotOwnershipTransferApprovalCollection(ctx, binding.Key)
		if lookupErr != nil {
			return OwnershipTransferApprovalCollectionPlan{}, fmt.Errorf("aiinfra iam: transfer collection lookup: %w", lookupErr)
		}
		if !found {
			return OwnershipTransferApprovalCollectionPlan{}, ErrTransferCollectionMismatch
		}
		if preflightTransferCollection(stored) != nil {
			return OwnershipTransferApprovalCollectionPlan{}, ErrTransferAuthorizationRequired
		}
		stored = cloneTransferCollection(stored)
		storedDigest, digestErr := transferCollectionDigest(stored)
		if digestErr != nil || storedDigest != stored.ProgressDigest || stored.Binding != binding ||
			stored.Version != parentSnapshot.Version || stored.ProgressDigest != parentSnapshot.ProgressDigest ||
			stored.Version == math.MaxUint64 || !bytes.Equal(stored.CanonicalPayload, canonicalPayload) ||
			stored.TransferEvidenceDigest != transferDigest || stored.ProfileDigest != profileDigest ||
			!sameTransferProfile(stored.Profile, profile) || !sameTransferFixedEvidence(stored.FixedEvidence, fixed) {
			return OwnershipTransferApprovalCollectionPlan{}, ErrTransferCollectionMismatch
		}
		if command.Fence.ExpectedStateVersion != stored.Version || command.Fence.WriterEpoch < stored.WriterEpoch ||
			(command.Fence.HomeRegion != stored.HomeRegion && command.Fence.WriterEpoch <= stored.WriterEpoch) {
			return OwnershipTransferApprovalCollectionPlan{}, ErrWriterFenceMismatch
		}
		merged, mergeErr := mergeTransferApproval(stored.Approvals, admission)
		if mergeErr != nil {
			return OwnershipTransferApprovalCollectionPlan{}, mergeErr
		}
		next.Version = stored.Version + 1
		next.Approvals = merged
		plan.disposition = OwnershipTransferCollectionReplace
		plan.expectedVersion = stored.Version
		plan.expectedProgressDigest = stored.ProgressDigest
		plan.expectedHomeRegion = stored.HomeRegion
		plan.expectedWriterEpoch = stored.WriterEpoch
		plan.joinedAuditSnapshot = auditSnapshot
	default:
		return OwnershipTransferApprovalCollectionPlan{}, ErrViewInconsistent
	}

	lease, err := p.validateFence(ctx, entity, command.Fence, command.EvaluatedAtUnixNano,
		command.Fence.HomeRegion, command.Fence.WriterEpoch)
	if err != nil {
		return OwnershipTransferApprovalCollectionPlan{}, err
	}
	// Revalidate every collected authority against current ACTIVE IAM state.
	// This is essential at quorum: an approval cannot complete acceptance after
	// its old or new authority was suspended, revoked, expired or rotated.
	next.Approvals, err = p.refreshTransferApprovals(ctx, next.Approvals, profileDigest,
		profile.Activation.SnapshotDigest,
		command.EvaluatedAtUnixNano)
	if err != nil {
		return OwnershipTransferApprovalCollectionPlan{}, err
	}
	if !sameTransferCorrelation(next.Approvals) {
		return OwnershipTransferApprovalCollectionPlan{}, ErrTransferAuthorizationRequired
	}
	next.ProgressDigest, err = transferCollectionDigest(next)
	if err != nil {
		return OwnershipTransferApprovalCollectionPlan{}, err
	}

	if decision.Kind() == idempotency.Proceed {
		parentClaim, claimErr := idempotency.NewReserveCollection(binding, next.ProgressDigest)
		if claimErr != nil {
			return OwnershipTransferApprovalCollectionPlan{}, claimErr
		}
		parentDigest, digestErr := idempotency.BindingDigest(binding)
		if digestErr != nil {
			return OwnershipTransferApprovalCollectionPlan{}, digestErr
		}
		auditClaim, claimErr := idempotency.NewReserveCollection(joinedBinding, parentDigest)
		if claimErr != nil {
			return OwnershipTransferApprovalCollectionPlan{}, claimErr
		}
		plan.idempotencyClaims, err = idempotency.NormalizeClaims([]idempotency.Claim{parentClaim, auditClaim})
		if err != nil {
			return OwnershipTransferApprovalCollectionPlan{}, err
		}
	} else {
		advance, claimErr := idempotency.NewAdvanceCollection(parentSnapshot, next.ProgressDigest)
		if claimErr != nil {
			return OwnershipTransferApprovalCollectionPlan{}, claimErr
		}
		plan.idempotencyClaims = []idempotency.Claim{advance}
	}
	plan.identifierClaims, err = p.transferCollectionIdentifierClaims(ctx, projection, fixed,
		auditEventID, decision.Kind() == idempotency.Proceed)
	if err != nil {
		return OwnershipTransferApprovalCollectionPlan{}, err
	}
	plan.dependencies, err = transferCollectionDependencies(next.Approvals, fixed,
		profile, projection.SubjectKind)
	if err != nil {
		return OwnershipTransferApprovalCollectionPlan{}, err
	}

	receiver, err := p.profile.ReceiverProfile(ctx, schema.MessageTypeOwnershipTransferAuthorization)
	if err != nil || validateReceiverProfile(receiver) != nil {
		return OwnershipTransferApprovalCollectionPlan{}, ErrAuthorizationMismatch
	}
	starts, ends := transferCollectionTimeBounds(next, lease)
	window, err := newPlanWindow(receiver, command.EvaluatedAtUnixNano, starts, ends)
	if err != nil {
		return OwnershipTransferApprovalCollectionPlan{}, err
	}
	plan.commitNotBeforeUnixNano = window.CommitNotBeforeUnixNano
	plan.commitNotAfterUnixNano = window.CommitNotAfterUnixNano
	plan.next = next
	plan.quorumSatisfied = transferQuorumSatisfied(profile, profileDigest, next.Approvals)
	plan.digest, err = ownershipTransferCollectionPlanDigest(plan)
	if err != nil {
		return OwnershipTransferApprovalCollectionPlan{}, err
	}
	if err := plan.VerifyDigest(); err != nil {
		return OwnershipTransferApprovalCollectionPlan{}, err
	}
	return plan, nil
}

// preflightOwnershipTransferCommand accounts for the complete compound input
// before the first VerifiedRecord getter or caller-owned payload copy. Per-
// record receiver limits remain in force in the deeper semantic validators;
// this aggregate fence prevents many individually-valid records from causing
// an unbounded retained-evidence allocation.
func preflightOwnershipTransferCommand(command OwnershipTransferApprovalIngestionCommand) error {
	if len(command.PreviousTerminalIdentityPayload) == 0 || len(command.PreviousTerminalIdentityPayload) > 196608 ||
		len(command.NextPendingIdentityPayload) == 0 || len(command.NextPendingIdentityPayload) > 196608 ||
		len(command.KeyClosureRecords) == 0 || len(command.KeyClosureRecords) > 256 ||
		len(command.EvidenceRecords) == 0 || len(command.EvidenceRecords) > 64 {
		return ErrTransferAuthorizationRequired
	}
	total := uint64(len(command.PreviousTerminalIdentityPayload)) + uint64(len(command.NextPendingIdentityPayload))
	add := func(record ccse.VerifiedRecord, messageTypeID uint32, payloadLimit int) error {
		if record.MessageTypeID() != messageTypeID || record.SchemaVersion() != (ccse.Version{Major: 1}) ||
			record.Digest() == ([32]byte{}) {
			return ErrTransferAuthorizationRequired
		}
		size, err := record.PreflightSize(transferVerifiedRecordLimits(payloadLimit))
		if err != nil || size > maxTransferCompoundInputBytes || total > maxTransferCompoundInputBytes-size {
			return ErrTransferAuthorizationRequired
		}
		total += size
		return nil
	}
	if total > maxTransferCompoundInputBytes ||
		add(command.Approval, schema.MessageTypeOwnershipTransferAuthorization, 196608) != nil {
		return ErrTransferAuthorizationRequired
	}
	for _, record := range command.KeyClosureRecords {
		if add(record, schema.MessageTypeKeyLifecycle, 32768) != nil {
			return ErrTransferAuthorizationRequired
		}
	}
	for _, record := range command.EvidenceRecords {
		if add(record, schema.MessageTypeEvidenceRecord, 262144) != nil {
			return ErrTransferAuthorizationRequired
		}
	}
	return nil
}

func transferCoordinator(profile OwnershipTransferProfile) (OwnershipTransferAuthorityRequirement, bool) {
	for _, value := range profile.NewAuthorities {
		if value.Coordinator {
			return value, true
		}
	}
	return OwnershipTransferAuthorityRequirement{}, false
}

func mergeTransferApproval(existing []OwnershipTransferAuthorityAdmission,
	next OwnershipTransferAuthorityAdmission) ([]OwnershipTransferAuthorityAdmission, error) {
	result := append([]OwnershipTransferAuthorityAdmission(nil), existing...)
	for index := range result {
		result[index] = cloneTransferAdmission(result[index])
		if result[index].Authority != next.Authority {
			continue
		}
		if result[index].Signed.digest == next.Signed.digest {
			return nil, ErrTransferApprovalDuplicate
		}
		// CounterExpectedGeneration is one immutable vote per authority and
		// previous-entity generation. A fresh MessageID at the same generation
		// cannot be replay-authorized, so replacement would create an unreachable
		// semantic path. Expired collections are reconciled and restarted with a
		// new transfer authorization after the failed outcome is audited.
		return nil, ErrTransferAuthorizationRequired
	}
	result = append(result, cloneTransferAdmission(next))
	if len(result) > maxTransferAuthorities {
		return nil, ErrTransferAuthorizationRequired
	}
	sortTransferAdmissions(result)
	return result, nil
}

func sortTransferAdmissions(values []OwnershipTransferAuthorityAdmission) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].Authority.Identity != values[j].Authority.Identity {
			return values[i].Authority.Identity < values[j].Authority.Identity
		}
		return values[i].Authority.KeyID < values[j].Authority.KeyID
	})
}

func (p *Planner) refreshTransferApprovals(ctx context.Context,
	approvals []OwnershipTransferAuthorityAdmission, profileDigest, activationDigest [32]byte,
	at int64) ([]OwnershipTransferAuthorityAdmission, error) {
	result := make([]OwnershipTransferAuthorityAdmission, len(approvals))
	for index := range approvals {
		result[index] = cloneTransferAdmission(approvals[index])
		record := result[index].Signed.record
		if record.Domain.IssuedAtUnixNano > at || at >= record.Domain.ExpiresAtUnixNano ||
			result[index].AdmissionProfileDigest != profileDigest ||
			result[index].AdmissionActivationDigest != activationDigest {
			return nil, ErrTransferAuthorizationRequired
		}
		current, err := p.validateCurrentTransferAuthority(ctx, result[index].Authority,
			record.Domain.IssuedAtUnixNano, at)
		if err != nil {
			return nil, err
		}
		result[index].CurrentPreconditions = current.Dependencies
		result[index].ValidatedAtUnixNano = at
		result[index].Fingerprint, err = transferAuthorityAdmissionFingerprint(result[index])
		if err != nil {
			return nil, err
		}
	}
	sortTransferAdmissions(result)
	return result, nil
}

func sameTransferCorrelation(approvals []OwnershipTransferAuthorityAdmission) bool {
	if len(approvals) == 0 {
		return false
	}
	correlation := approvals[0].Signed.record.Envelope.CorrelationID
	if correlation == ([16]byte{}) {
		return false
	}
	for _, approval := range approvals[1:] {
		if approval.Signed.record.Envelope.CorrelationID != correlation {
			return false
		}
	}
	return true
}

func transferCollectionDependencies(approvals []OwnershipTransferAuthorityAdmission,
	fixed OwnershipTransferFixedEvidence, profile OwnershipTransferProfile,
	subjectKind uint32) ([]SnapshotPrecondition, error) {
	values := []SnapshotPrecondition{fixed.PreviousIdentityCAS,
		profile.Activation.Precondition(profile.ProfileID, subjectKind)}
	values = append(values, fixed.ClosurePreconditions...)
	values = append(values, fixed.EvidencePreconditions...)
	for _, approval := range approvals {
		values = append(values, approval.CurrentPreconditions...)
	}
	return canonicalPreconditions(values)
}

func transferCollectionTimeBounds(snapshot OwnershipTransferApprovalCollectionSnapshot,
	lease WriterLeaseSnapshot) ([]int64, []int64) {
	starts := []int64{lease.ValidFromUnixNano, snapshot.Profile.Activation.ValidFromUnixNano}
	ends := []int64{lease.ValidUntilUnixNano, snapshot.Profile.Activation.ValidUntilUnixNano}
	_, _, projectionDigest, err := normalizeOwnershipTransferPayload(snapshot.CanonicalPayload)
	if err == nil && projectionDigest == snapshot.TransferEvidenceDigest {
		projection, _, _, _ := normalizeOwnershipTransferPayload(snapshot.CanonicalPayload)
		ends = append(ends, projection.ExpiresAtUnixNano)
	}
	for _, approval := range snapshot.Approvals {
		starts = append(starts, approval.Signed.record.Domain.IssuedAtUnixNano,
			approval.Historical.Lifecycle.NotBeforeUnixNano,
			approval.Historical.Identity.ValidFromUnixNano)
		ends = append(ends, approval.Signed.record.Domain.ExpiresAtUnixNano,
			approval.Historical.Lifecycle.NotAfterUnixNano,
			approval.Historical.Identity.ValidUntilUnixNano)
	}
	for _, record := range append(cloneRetainedRecords(snapshot.FixedEvidence.KeyClosureRecords),
		cloneRetainedRecords(snapshot.FixedEvidence.EvidenceRecords)...) {
		starts = append(starts, record.record.Domain.IssuedAtUnixNano)
		ends = append(ends, record.record.Domain.ExpiresAtUnixNano)
	}
	return starts, ends
}

func zeroTransferCollection(snapshot OwnershipTransferApprovalCollectionSnapshot) bool {
	return snapshot.Binding == (idempotency.Binding{}) && snapshot.Version == 0 &&
		snapshot.ProgressDigest == ([32]byte{}) && len(snapshot.CanonicalPayload) == 0 &&
		snapshot.TransferEvidenceDigest == ([32]byte{}) && snapshot.ProfileDigest == ([32]byte{}) &&
		len(snapshot.Approvals) == 0 && snapshot.HomeRegion == "" && snapshot.WriterEpoch == 0
}

func (p *Planner) transferCollectionIdentifierClaims(ctx context.Context,
	projection foundationv1.OwnershipTransferAuthorizationSigningProjection,
	fixed OwnershipTransferFixedEvidence, auditEventID string, reserve bool) ([]globalid.Claim, error) {
	oldRef := EntityRef{Kind: EntityIdentity, PrincipalKind: projection.SubjectKind, ID: projection.PreviousEntityID}
	newRef := EntityRef{Kind: EntityIdentity, PrincipalKind: projection.SubjectKind, ID: projection.NextEntityID}
	canonicalOwner := globalid.Owner{Domain: globalid.OwnerCanonicalRecord, ID: projection.TransferAuthorizationID}
	auditOwner := globalid.Owner{Domain: globalid.OwnerGovernanceAuditEvent, ID: auditEventID}
	oldOwner, newOwner := identityGlobalOwner(oldRef), identityGlobalOwner(newRef)
	type requested struct {
		id      string
		owner   globalid.Owner
		reserve bool
	}
	requests := []requested{
		{projection.TransferAuthorizationID, canonicalOwner, reserve},
		{projection.Metadata.RecordID, canonicalOwner, reserve},
		{auditEventID, auditOwner, reserve},
		{projection.PreviousEntityID, oldOwner, false},
		{projection.PreviousPrincipalIdentity, oldOwner, false},
		{projection.NextEntityID, newOwner, reserve},
		{projection.NewKeyID, keyGlobalOwner(projection.NewKeyID), reserve},
		{fixed.PreviousTerminalIdentity.RecordID,
			recordGlobalOwner(oldRef, fixed.PreviousTerminalIdentity.RecordID), reserve},
		{fixed.NextPendingIdentity.RecordID,
			recordGlobalOwner(newRef, fixed.NextPendingIdentity.RecordID), reserve},
	}
	if projection.SubjectKind == 2 {
		requests = append(requests, requested{projection.NextPrincipalIdentity, newOwner, reserve})
	} else {
		requests = append(requests, requested{projection.NextPrincipalIdentity, oldOwner, false})
	}
	for _, lifecycle := range fixed.KeyClosureSnapshots {
		closureRef := EntityRef{Kind: EntityKeyLifecycle, PrincipalKind: lifecycle.SubjectKind, ID: lifecycle.KeyID}
		requests = append(requests, requested{lifecycle.RecordID,
			recordGlobalOwner(closureRef, lifecycle.RecordID), reserve})
	}
	claims := make([]globalid.Claim, 0, len(requests))
	for _, request := range requests {
		var claim globalid.Claim
		var err error
		if request.reserve {
			claim, err = p.reserveGlobalID(ctx, request.id, request.owner)
		} else {
			claim, err = p.assertGlobalID(ctx, request.id, request.owner)
		}
		if err != nil {
			return nil, err
		}
		claims = append(claims, claim)
	}
	for _, record := range fixed.EvidenceRecords {
		recordID, expectedOwner, recordErr := retainedEvidenceRecordGlobalOwner(record)
		if recordErr != nil {
			return nil, recordErr
		}
		snapshot, found, lookupErr := p.view.LookupGlobalID(ctx, recordID)
		if lookupErr != nil {
			return nil, fmt.Errorf("aiinfra iam: lookup transfer evidence record identifier: %w", lookupErr)
		}
		if !found {
			return nil, ErrGlobalIdentifier
		}
		claim, claimErr := globalid.Assert(recordID, snapshot, expectedOwner)
		if claimErr != nil {
			return nil, ErrGlobalIdentifier
		}
		claims = append(claims, claim)
	}
	return normalizeGlobalClaims(claims)
}

func newOwnershipTransferAuditIntent(parent, joined idempotency.Binding, eventID string,
	accepted AcceptedOwnershipTransferSnapshot, coordinator OwnershipTransferAuthorityRequirement,
	at int64) (*AuditIntent, error) {
	approval, ok := coordinatorApproval(accepted.Profile, accepted.Approvals)
	if !ok || approval.Authority != coordinator {
		return nil, ErrTransferAuthorizationRequired
	}
	record := approval.Signed.record
	source := auditSourceEvidence{Present: true, ActorKeyID: coordinator.KeyID,
		Record: cloneCCSERecord(record), Digest: approval.Signed.digest,
		CausationID: record.Envelope.CausationID}
	approvalBytes, err := canonicalTransferAdmissions(accepted.Approvals)
	if err != nil {
		return nil, err
	}
	fixedBytes, err := canonicalTransferFixedEvidence(accepted.FixedEvidence)
	if err != nil {
		return nil, err
	}
	approvalSetDigest := domainDigest(transferApprovalSetAuditDomain, approvalBytes)
	fixedDigest := domainDigest(transferFixedAuditDomain, fixedBytes)
	policies := uniqueDigests(append(cloneDigests(accepted.Projection.Metadata.PolicyDigestsSHA256),
		accepted.Profile.PolicyDigest))
	evidence := uniqueDigests([][32]byte{accepted.TransferEvidenceDigest, accepted.ProfileDigest,
		accepted.SnapshotDigest, approvalSetDigest, fixedDigest})
	subjects := []string{accepted.Projection.TransferAuthorizationID,
		accepted.Projection.PreviousEntityID, accepted.Projection.NextEntityID,
		accepted.Projection.PreviousPrincipalIdentity, accepted.Projection.NextPrincipalIdentity,
		accepted.Projection.PreviousProviderID, accepted.Projection.NextProviderID,
		accepted.Projection.NewKeyID}
	intent, err := newAuditIntent(eventID, "iam.ownership_transfer.accepted", coordinator.Identity,
		subjects, "ownership-transfer-authorized", record.Envelope.CorrelationID,
		directAuditCausation(record.Envelope.MessageID), record.Envelope.MessageID,
		parent.Key, joined.Key, source, at, policies, evidence)
	if err != nil {
		return nil, err
	}
	return &intent, nil
}

func (p *Planner) validateCompletedTransferRetry(ctx context.Context, transferDigest,
	profileDigest [32]byte, approval OwnershipTransferAuthorityAdmission) error {
	accepted, found, err := p.view.LookupAcceptedOwnershipTransfer(ctx, transferDigest)
	if err != nil || !found {
		return ErrTransferCollectionMismatch
	}
	accepted = cloneAcceptedTransfer(accepted)
	digest, err := acceptedTransferDigest(accepted)
	if err != nil || digest != accepted.SnapshotDigest || accepted.ProfileDigest != profileDigest {
		return ErrTransferCollectionMismatch
	}
	for _, stored := range accepted.Approvals {
		if stored.Authority == approval.Authority && stored.Signed.digest == approval.Signed.digest {
			return nil
		}
	}
	return ErrTransferAuthorizationRequired
}
