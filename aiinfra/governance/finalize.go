// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	"github.com/cypherium/cypher/aiinfra/schema"
)

// FinalizePolicyMutation joins an approved policy mutation to the exact signed
// AuditEvent and audit-head CAS. Only the returned CommitReady plan may be
// applied, and the policy/head/EventID CAS operations must share one durable
// transaction.
func (p *Planner) FinalizePolicyMutation(ctx context.Context, pending PendingPolicyPlan, command PolicyFinalizeCommand) (MutationPlan, error) {
	if p == nil {
		return MutationPlan{}, ErrInvalidConfiguration
	}
	if err := pending.VerifyDigest(); err != nil {
		return MutationPlan{}, fmt.Errorf("%w: pending policy plan", err)
	}
	policy := pending.policy.Snapshot()
	expectedIntent := pending.audit.Snapshot()
	if policy.CommitReady || policy.Kind < MutationPolicyPublish || policy.Kind > MutationPolicyExpire ||
		policy.GovernanceProfileDigestSHA256 != p.profileDigest ||
		!expectedIntent.Required || !digestSetContainsAll(policy.AuditSourceDigestsSHA256, policy.ApprovalRecordDigestsSHA256) ||
		!equalDigestSets(policy.AuditSourceDigestsSHA256, expectedIntent.EvidenceDigestsSHA256) {
		return MutationPlan{}, ErrInvalidCommand
	}
	joinedAuditBinding, err := idempotency.JoinedAuditBinding(policy.PolicyIdempotencySnapshot.Binding)
	if err != nil || expectedIntent.IdempotencyKey != joinedAuditBinding.Key || joinedAuditBinding.Key == policy.PolicyIdempotencySnapshot.Binding.Key ||
		!validJoinedAuditReservation(policy.JoinedAuditIdempotencySnapshot, joinedAuditBinding) {
		return MutationPlan{}, ErrInvalidCommand
	}
	joinedEventID, err := idempotency.JoinedAuditEventID(policy.PolicyIdempotencySnapshot.Binding)
	if err != nil || expectedIntent.AuditEventID != joinedEventID ||
		!containsIdentifierClaim(policy.IdentifierClaims, joinedEventID, globalid.Owner{Domain: globalid.OwnerGovernanceAuditEvent, ID: joinedEventID}) {
		return MutationPlan{}, ErrInvalidCommand
	}
	if err := p.revalidatePendingPolicy(ctx, policy, command.AtUnixNano); err != nil {
		return MutationPlan{}, err
	}
	transactionEvidence, err := policyTransactionEvidence(policy)
	if err != nil {
		return MutationPlan{}, err
	}
	auditPlan, actualIntent, err := p.planAuditAppend(ctx, AuditAppendCommand{
		AtUnixNano: command.AtUnixNano, Event: command.AuditEvent,
		SourceRecordDigestsSHA256: append([][32]byte(nil), policy.AuditSourceDigestsSHA256...),
	}, transactionEvidence, &policy.JoinedAuditIdempotencySnapshot, &policy.PolicyIdempotencySnapshot.Binding,
		policyPendingEvidenceLinks(policy))
	if err != nil {
		return MutationPlan{}, err
	}
	actual := actualIntent.Snapshot()
	if !auditIntentSatisfiesPending(actual, expectedIntent) {
		return MutationPlan{}, ErrAuditRequired
	}
	audit := auditPlan.Snapshot()
	if !audit.CommitReady || audit.Kind != MutationAuditAppend || len(audit.IdempotencyClaims) != 1 ||
		!equalDigestSets(audit.AuditSourceDigestsSHA256, policy.AuditSourceDigestsSHA256) ||
		audit.GovernanceProfileActivation != policy.GovernanceProfileActivation {
		return MutationPlan{}, ErrAuditRequired
	}

	policy.CommitReady = true
	policy.EvaluatedAtUnixNano = command.AtUnixNano
	policy.CommitNotBeforeUnixNano = maximumInt64(policy.CommitNotBeforeUnixNano, audit.CommitNotBeforeUnixNano)
	policy.CommitNotAfterUnixNano = minimumInt64(policy.CommitNotAfterUnixNano, audit.CommitNotAfterUnixNano)
	if policy.CommitNotAfterUnixNano <= policy.CommitNotBeforeUnixNano {
		return MutationPlan{}, ErrPolicyExpired
	}
	policy.AuditStreamID = audit.AuditStreamID
	policy.AuditEventID = audit.AuditEventID
	policy.AuditRecordID = audit.AuditRecordID
	policy.AuditSourceEvidence = append([]DurableEvidence(nil), audit.AuditSourceEvidence...)
	for index := range policy.AuditSourceEvidence {
		policy.AuditSourceEvidence[index] = cloneDurableEvidence(policy.AuditSourceEvidence[index])
	}
	policy.AuditSourceStorageCapabilities = cloneDurableEvidenceStorageCapabilities(audit.AuditSourceStorageCapabilities)
	policy.AuditSourceKeyPreconditions = append([]KeyStatePrecondition(nil), audit.AuditSourceKeyPreconditions...)
	policy.ExpectedAuditEventAbsent = audit.ExpectedAuditEventAbsent
	policy.DeploymentAnchorSHA256 = audit.DeploymentAnchorSHA256
	policy.ExpectedAuditSequence = audit.ExpectedAuditSequence
	policy.ExpectedAuditHeadDigest = audit.ExpectedAuditHeadDigest
	policy.ExpectedAuditHeadHomeRegion = audit.ExpectedAuditHeadHomeRegion
	policy.AuthorizedAuditHomeRegion = audit.AuthorizedAuditHomeRegion
	policy.ExpectedAuditHeadWriterIdentity = audit.ExpectedAuditHeadWriterIdentity
	policy.AuthorizedAuditWriterIdentity = audit.AuthorizedAuditWriterIdentity
	policy.ExpectedAuditHeadWriterEpoch = audit.ExpectedAuditHeadWriterEpoch
	policy.AuthorizedAuditWriterEpoch = audit.AuthorizedAuditWriterEpoch
	policy.ExpectedAuditHeadGovernanceProfileDigestSHA256 = audit.ExpectedAuditHeadGovernanceProfileDigestSHA256
	policy.AuthorizedAuditGovernanceProfileDigestSHA256 = audit.AuthorizedAuditGovernanceProfileDigestSHA256
	policy.ExpectedAuditWriterLeaseEvidenceDigestSHA256 = audit.ExpectedAuditWriterLeaseEvidenceDigestSHA256
	policy.ExpectedAuditWriterLeaseNotBeforeUnixNano = audit.ExpectedAuditWriterLeaseNotBeforeUnixNano
	policy.ExpectedAuditWriterLeaseNotAfterUnixNano = audit.ExpectedAuditWriterLeaseNotAfterUnixNano
	policy.NextAuditSequence = audit.NextAuditSequence
	policy.NextAuditRecordDigestSHA256 = audit.NextAuditRecordDigestSHA256
	policy.AuditEventEvidence = audit.AuditEventEvidence
	policy.AuditWriterKeyPrecondition = audit.AuditWriterKeyPrecondition
	keyReadSet := append([]KeyStatePrecondition(nil), policy.AuditSourceKeyPreconditions...)
	keyReadSet = append(keyReadSet, policy.ApprovalKeyPreconditions...)
	keyReadSet = append(keyReadSet, policy.AuditWriterKeyPrecondition)
	policy.CanonicalKeyStateAssertions, err = p.canonicalKeyStateAssertions(ctx, keyReadSet)
	if err != nil {
		return MutationPlan{}, fmt.Errorf("%w: canonical key read set", err)
	}
	policy.CanonicalAuditAppend = cloneCanonicalAuditAppendCapability(audit.CanonicalAuditAppend)
	policy.CanonicalAuditWriterLeaseAssertion = cloneCanonicalAuditWriterLeaseAssertion(audit.CanonicalAuditWriterLeaseAssertion)
	policy.CanonicalStateAssertions = cloneCanonicalStateAssertions(audit.CanonicalStateAssertions)
	policy.IdempotencyOutcome = audit.IdempotencyOutcome
	policy.IdentifierClaims, err = globalid.NormalizeClaims(append(append([]globalid.Claim(nil), policy.IdentifierClaims...), audit.IdentifierClaims...))
	if err != nil {
		return MutationPlan{}, ErrPolicyConflict
	}
	completeCollection, err := idempotency.NewCompleteCollection(policy.PolicyIdempotencySnapshot)
	if err != nil {
		return MutationPlan{}, ErrApprovalCollection
	}
	policy.IdempotencyClaims, err = idempotency.NormalizeClaims(append([]idempotency.Claim{completeCollection}, audit.IdempotencyClaims...))
	if err != nil {
		return MutationPlan{}, fmt.Errorf("%w: compound idempotency claims: %v", ErrInvalidCommand, err)
	}
	policyMutation, err := p.canonicalPolicyMutation(ctx, policy)
	if err != nil {
		return MutationPlan{}, fmt.Errorf("%w: canonical policy registry mutation", err)
	}
	policy.CanonicalStateMutations = []CanonicalStateMutation{policyMutation}
	return newMutationPlan(policy)
}

func containsIdentifierClaim(claims []globalid.Claim, identifier string, owner globalid.Owner) bool {
	for _, claim := range claims {
		if claim.Identifier == identifier && claim.Owner == owner {
			return true
		}
	}
	return false
}

func policyTransactionEvidence(policy MutationPlanSnapshot) (map[[ccse.DigestSize]byte]DurableEvidence, error) {
	if len(policy.PolicyDocumentEvidence) == 0 || len(policy.PolicyDocumentEvidence) > maxPolicyDocumentBytes ||
		sha256.Sum256(policy.PolicyDocumentEvidence) != policy.PolicyDocumentDigestSHA256 {
		return nil, ErrAuditEvidence
	}
	result := map[[ccse.DigestSize]byte]DurableEvidence{
		policy.PolicyDocumentDigestSHA256: newContentEvidence(policy.PolicyDocumentDigestSHA256, policy.PolicyDocumentEvidence),
	}
	authorizationByRecord := make(map[[ccse.DigestSize]byte][ccse.DigestSize]byte, len(policy.ApprovalAdmissionEvidence))
	profileByRecord := make(map[[ccse.DigestSize]byte][ccse.DigestSize]byte, len(policy.ApprovalAdmissionEvidence))
	for _, admission := range policy.ApprovalAdmissionEvidence {
		authorization := admission.AdmissionKey.AuthorizationPolicyDigestSHA256
		if isZeroDigest(admission.RecordDigestSHA256) || isZeroDigest(authorization) ||
			isZeroDigest(admission.GovernanceProfileDigestSHA256) {
			return nil, ErrAuditEvidence
		}
		if _, duplicate := authorizationByRecord[admission.RecordDigestSHA256]; duplicate {
			return nil, ErrAuditEvidence
		}
		authorizationByRecord[admission.RecordDigestSHA256] = authorization
		profileByRecord[admission.RecordDigestSHA256] = admission.GovernanceProfileDigestSHA256
	}
	for _, retained := range policy.ApprovalEvidence {
		record := retained.Record()
		if !preflightRawRecord(record, maxPayloadBytesFor(schema.MessageTypePolicyBundle)) {
			return nil, ErrInvalidSignedRecord
		}
		digest, err := record.Digest(ccse.DefaultLimits())
		if err != nil || digest != retained.RecordDigest() {
			return nil, ErrInvalidSignedRecord
		}
		if _, collision := result[digest]; collision {
			return nil, ErrAuditEvidence
		}
		authorization, admitted := authorizationByRecord[digest]
		if !admitted {
			return nil, ErrAuditEvidence
		}
		result[digest] = DurableEvidence{
			kind: EvidenceSignedCCSERecord, digest: digest, signed: cloneSignedEvidence(retained),
			authorizationPolicyDigests: uniqueSortedDigests([][ccse.DigestSize]byte{authorization, profileByRecord[digest]}),
		}
		payloadDigest := sha256.Sum256(record.Payload)
		payloadEvidence := newContentEvidence(payloadDigest, record.Payload)
		if existing, collision := result[payloadDigest]; collision {
			if existing.kind != payloadEvidence.kind || existing.digest != payloadEvidence.digest ||
				!bytes.Equal(existing.content, payloadEvidence.content) {
				return nil, ErrAuditEvidence
			}
		} else {
			result[payloadDigest] = payloadEvidence
		}
	}
	if len(authorizationByRecord) != len(policy.ApprovalEvidence) {
		return nil, ErrAuditEvidence
	}
	if len(result) != len(policy.AuditSourceDigestsSHA256) {
		return nil, ErrAuditEvidence
	}
	for _, source := range policy.AuditSourceDigestsSHA256 {
		if _, exists := result[source]; !exists {
			return nil, ErrAuditEvidence
		}
	}
	return result, nil
}

func policyPendingEvidenceLinks(policy MutationPlanSnapshot) map[[ccse.DigestSize]byte]durableEvidencePendingLink {
	return policyPendingEvidenceLinksFromDigests(policy.PolicyIdempotencySnapshot.Binding.Key,
		policy.PolicyIdempotencySnapshot.Version, policy.ApprovalRecordDigestsSHA256)
}

func policyPendingEvidenceLinksFromDigests(key [ccse.MessageIDSize]byte, revision uint64,
	digests [][ccse.DigestSize]byte) map[[ccse.DigestSize]byte]durableEvidencePendingLink {
	if key == ([ccse.MessageIDSize]byte{}) || revision == 0 || len(digests) == 0 {
		return nil
	}
	result := make(map[[ccse.DigestSize]byte]durableEvidencePendingLink, len(digests))
	for _, digest := range digests {
		result[digest] = durableEvidencePendingLink{pendingKey: key, pendingRevision: revision}
	}
	return result
}

func (p *Planner) revalidatePendingPolicy(ctx context.Context, policy MutationPlanSnapshot, at int64) error {
	if at < 0 || len(policy.ApprovalEvidence) == 0 || len(policy.ApprovalEvidence) != len(policy.ApprovalKeyPreconditions) {
		return ErrInvalidCommand
	}
	if at < policy.EvaluatedAtUnixNano || at < policy.CommitNotBeforeUnixNano || policy.CommitNotAfterUnixNano <= at {
		return ErrPolicyExpired
	}
	switch policy.Kind {
	case MutationPolicyPublish:
		if at >= policy.EffectiveAtUnixNano || at >= policy.ExpiresAtUnixNano {
			return ErrActivationDelay
		}
	case MutationPolicyActivate:
		if at < policy.EffectiveAtUnixNano || at >= policy.ExpiresAtUnixNano ||
			(policy.Emergency && policy.BreakGlassExpiresAtUnixNano <= at) {
			return ErrPolicyExpired
		}
	case MutationPolicyRollback:
		if at < policy.EffectiveAtUnixNano || at >= policy.ExpiresAtUnixNano {
			return ErrPolicyExpired
		}
	case MutationPolicyRevoke:
		if at < policy.ApprovedAtUnixNano || at >= policy.ExpiresAtUnixNano {
			return ErrInvalidCommand
		}
	case MutationPolicyExpire:
		if at < policy.ExpiresAtUnixNano {
			return ErrPolicyExpired
		}
	default:
		return ErrInvalidCommand
	}
	expectedBinding := idempotency.Binding{
		Key: policy.PolicyIdempotencySnapshot.Binding.Key, Domain: idempotency.OperationGovernancePolicy,
		OwnerID: hex.EncodeToString(policy.PolicyBundleOwnerDigestSHA256[:]), RequestDigest: policy.PolicyBundleDigestSHA256,
	}
	if policy.PolicyIdempotencySnapshot.Validate() != nil || policy.PolicyIdempotencySnapshot.State != idempotency.StateCollecting ||
		policy.PolicyIdempotencySnapshot.Binding != expectedBinding {
		return ErrApprovalCollection
	}
	decision, err := idempotency.PrecheckJoined(ctx, p.idempotency, expectedBinding)
	if err != nil {
		return err
	}
	if decision.Kind() == idempotency.DuplicateCompleted {
		return DuplicateCompletedError{OutcomeDigestSHA256: decision.OutcomeDigest()}
	}
	if decision.Kind() != idempotency.ContinueCollection || decision.ParentSnapshot() != policy.PolicyIdempotencySnapshot ||
		decision.AuditSnapshot() != policy.JoinedAuditIdempotencySnapshot {
		return ErrApprovalCollection
	}
	joinedBinding, err := idempotency.JoinedAuditBinding(expectedBinding)
	if err != nil || !validJoinedAuditReservation(policy.JoinedAuditIdempotencySnapshot, joinedBinding) {
		return ErrApprovalCollection
	}
	collected, err := p.loadPolicyApprovalCollection(ctx, expectedBinding, decision.ParentSnapshot(), at)
	if err != nil {
		return err
	}
	if !approvalEvidenceSetMatchesRetained(collected, policy.ApprovalEvidence) {
		return ErrApprovalCollection
	}

	preconditions := make(map[string]KeyStatePrecondition, len(policy.ApprovalKeyPreconditions))
	for _, expected := range policy.ApprovalKeyPreconditions {
		if expected.KeyID == "" || expected.StateVersion == 0 || expected.WriterEpoch == 0 || isZeroDigest(expected.SnapshotDigestSHA256) ||
			expected.IdentityStateVersion == 0 || expected.IdentityWriterEpoch == 0 || isZeroDigest(expected.IdentitySnapshotDigestSHA256) ||
			isZeroDigest(expected.AuthorizationSnapshotDigestSHA256) {
			return ErrInvalidCommand
		}
		if _, duplicate := preconditions[expected.KeyID]; duplicate {
			return ErrInvalidCommand
		}
		preconditions[expected.KeyID] = expected
	}
	seen := make(map[string]struct{}, len(policy.ApprovalEvidence))
	for _, retained := range policy.ApprovalEvidence {
		record := retained.Record()
		if !preflightRawRecord(record, maxPayloadBytesFor(schema.MessageTypePolicyBundle)) {
			return ErrInvalidSignedRecord
		}
		digest, err := record.Digest(ccse.DefaultLimits())
		if err != nil || digest != retained.RecordDigest() {
			return ErrInvalidSignedRecord
		}
		if record.MessageTypeID != schema.MessageTypePolicyBundle || record.SchemaVersion != p.profile.SchemaVersion ||
			record.Domain.Purpose != policyPurpose || record.Domain.ProtocolVersion != p.profile.ProtocolVersion ||
			!equalStringSets(record.Domain.Audience, p.profile.Audience) || record.Domain.TenantOrganization != p.profile.TenantOrganization ||
			record.Domain.ProviderOrganization != p.profile.ProviderOrganization || record.Domain.Environment != p.profile.Environment ||
			record.Envelope.Environment != p.profile.Environment || record.Domain.ChainID != p.profile.ChainID ||
			record.Envelope.ChainID != p.profile.ChainID || record.Domain.GenesisHash != p.profile.GenesisHash ||
			record.Domain.ReplayDomainID != p.profile.PolicyReplayDomainID || record.Domain.CounterKind != ccse.CounterSequence ||
			record.Envelope.CounterKind != ccse.CounterSequence || record.Domain.IssuedAtUnixNano > at ||
			record.Domain.ExpiresAtUnixNano <= at || record.Domain.ExpiresAtUnixNano-record.Domain.IssuedAtUnixNano > p.profile.MaxRecordValidityNanos {
			return ErrWrongRecordContext
		}
		payloadDigest := sha256.Sum256(record.Payload)
		if payloadDigest != policy.PolicyBundleDigestSHA256 || payloadDigest != record.Envelope.PayloadDigest {
			return ErrApprovalPayloadMismatch
		}
		if _, err := p.canonical.Decode(schema.MessageTypePolicyBundle, p.profile.SchemaVersion, record.Payload); err != nil {
			return err
		}
		snapshot := signedRecordSnapshot{record: cloneCCSERecord(record), digest: digest}
		key, err := p.authorizeKey(ctx, snapshot, schema.MessageTypePolicyBundle, at)
		if err != nil {
			return err
		}
		expected, ok := preconditions[key.KeyID]
		if !ok || expected != keyPrecondition(key) {
			return ErrKeyNotActive
		}
		if _, duplicate := seen[key.KeyID]; duplicate {
			return ErrDuplicateApprover
		}
		seen[key.KeyID] = struct{}{}
	}
	if len(seen) != len(preconditions) {
		return ErrInvalidCommand
	}

	registry, err := p.policies.SnapshotPolicy(ctx, policy.PolicyKind)
	if err != nil {
		return fmt.Errorf("aiinfra governance: snapshot policy at finalize: %w", err)
	}
	if !p.preflightPolicyRegistrySnapshot(registry) {
		return ErrSnapshotInconsistent
	}
	registry = clonePolicyRegistrySnapshot(registry)
	if err := p.validatePolicyRegistrySnapshot(ctx, policy.PolicyKind, registry); err != nil {
		return err
	}
	profileActivation, err := p.validatePolicyWriterFence(ctx, registry, at)
	if err != nil {
		return err
	}
	if registry.HeadPresent != policy.ExpectedPolicyHeadPresent || registry.Head.Sequence != policy.ExpectedPolicyHeadSequence ||
		registry.Head.BundleDigestSHA256 != policy.ExpectedPolicyHeadDigest || registry.Head.HomeRegion != policy.ExpectedPolicyHeadHomeRegion ||
		registry.AuthorizedHomeRegion != policy.AuthorizedPolicyHomeRegion ||
		registry.GovernanceProfileDigestSHA256 != policy.GovernanceProfileDigestSHA256 ||
		registry.Head.WriterEpoch != policy.ExpectedPolicyHeadWriterEpoch ||
		registry.AuthorizedWriterEpoch != policy.AuthorizedPolicyWriterEpoch ||
		registry.WriterLeaseEvidenceDigestSHA256 != policy.ExpectedPolicyWriterLeaseEvidenceDigestSHA256 ||
		registry.WriterLeaseNotBeforeUnixNano != policy.ExpectedPolicyWriterLeaseNotBeforeUnixNano ||
		registry.WriterLeaseNotAfterUnixNano != policy.ExpectedPolicyWriterLeaseNotAfterUnixNano ||
		profileActivation != policy.GovernanceProfileActivation {
		return ErrPolicyConflict
	}
	if policy.Kind == MutationPolicyRollback {
		var target *PolicyRecordSnapshot
		for index := range registry.Records {
			if registry.Records[index].BundleDigestSHA256 == policy.RollbackTargetDigestSHA256 {
				copyRecord := registry.Records[index]
				target = &copyRecord
			}
		}
		if target == nil || target.State != PolicyStateActive || target.Emergency || target.ExpiresAtUnixNano <= at {
			return ErrRollbackTarget
		}
		for _, record := range registry.Records {
			if record.Sequence > target.Sequence && record.PolicyBundleID == target.PolicyBundleID &&
				(record.State == PolicyStateRolledBack || record.State == PolicyStateRevoked || record.State == PolicyStateExpired) {
				return ErrRollbackTarget
			}
		}
	}
	if err := p.validateIdentifierClaims(ctx, policy.IdentifierClaims); err != nil {
		return err
	}
	return contextErr(ctx)
}

func (p *Planner) validateIdentifierClaims(ctx context.Context, claims []globalid.Claim) error {
	if len(claims) == 0 {
		return ErrInvalidCommand
	}
	normalized, err := globalid.NormalizeClaims(claims)
	if err != nil || len(normalized) != len(claims) {
		return ErrInvalidCommand
	}
	for _, claim := range normalized {
		current, exists, err := p.ids.LookupGlobalID(ctx, claim.Identifier)
		if err != nil {
			return fmt.Errorf("aiinfra governance: lookup global identifier: %w", err)
		}
		switch claim.Mode {
		case globalid.ReserveNew:
			if exists || current != (globalid.Snapshot{}) {
				return ErrPolicyConflict
			}
		case globalid.AssertExisting:
			if !exists || current.Identifier != claim.Identifier || current.Owner != claim.ExpectedOwner ||
				current.Version != claim.ExpectedVersion || claim.Owner != current.Owner || claim.NextVersion != current.Version {
				return ErrPolicyConflict
			}
		default:
			return ErrInvalidCommand
		}
	}
	return nil
}

func auditIntentSatisfiesPending(actual, expected AuditIntentSnapshot) bool {
	expectedApplied := append([][32]byte(nil), expected.AppliedPolicyDigestsSHA256...)
	if isZeroDigest(actual.WriterAuthorizationPolicyDigestSHA256) {
		return false
	}
	expectedApplied = uniqueSortedDigests(append(expectedApplied, actual.WriterAuthorizationPolicyDigestSHA256))
	return actual.Required && expected.Required && actual.StreamID == expected.StreamID && actual.EventType == expected.EventType &&
		actual.AuditEventID == expected.AuditEventID && expected.AuditEventID != "" &&
		actual.ActorIdentity == expected.ActorIdentity && actual.ActorKeyID == expected.ActorKeyID && expected.ActorKeyID != "" &&
		equalStringSets(actual.SubjectIDs, expected.SubjectIDs) &&
		actual.CauseCode == expected.CauseCode && actual.OccurredAtUnixNano == expected.OccurredAtUnixNano &&
		actual.Outcome == expected.Outcome && (expected.Outcome == 1 || expected.Outcome == 3 || expected.Outcome == 4) &&
		actual.IdempotencyKey == expected.IdempotencyKey &&
		actual.IdempotencyKey != ([ccse.MessageIDSize]byte{}) && actual.CorrelationID == expected.CorrelationID &&
		actual.CausationID == expected.CausationID &&
		equalDigestSets(actual.AppliedPolicyDigestsSHA256, expectedApplied) &&
		equalDigestSets(actual.EvidenceDigestsSHA256, expected.EvidenceDigestsSHA256) &&
		actual.Emergency == expected.Emergency && actual.BreakGlassExpiresAtUnixNano == expected.BreakGlassExpiresAtUnixNano &&
		equalStringSetsAllowEmpty(actual.BreakGlassScopes, expected.BreakGlassScopes)
}

func equalDigestSets(left, right [][32]byte) bool {
	if len(left) != len(right) || hasDuplicateDigests(left) || hasDuplicateDigests(right) {
		return false
	}
	for _, value := range left {
		if !containsDigest(right, value) {
			return false
		}
	}
	return true
}

func digestSetContainsAll(haystack, needles [][32]byte) bool {
	if hasDuplicateDigests(haystack) || hasDuplicateDigests(needles) {
		return false
	}
	for _, value := range needles {
		if !containsDigest(haystack, value) {
			return false
		}
	}
	return true
}
