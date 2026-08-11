// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
	"github.com/cypherium/cypher/aiinfra/schema/foundation/v1/canonical"
)

const (
	policyPurpose = "governance.policy.bundle"
	auditPurpose  = "audit.event.append"
	maxApprovals  = 64
)

// Planner is immutable after construction and safe for concurrent use when its
// read-only views are safe for concurrent use.
type Planner struct {
	iam           IAMView
	policies      PolicyView
	profiles      GovernanceProfileCatalog
	collections   ApprovalCollectionView
	ids           globalid.View
	idempotency   idempotency.JoinedView
	documents     PolicyDocumentView
	evidence      EvidenceView
	audit         AuditView
	profile       Profile
	profileDigest [ccse.DigestSize]byte
	canonical     *canonical.Validator
}

// NewPlanner validates and freezes all policy slices. It performs no external
// read or write and does not retain aliases into profile.
func NewPlanner(iam IAMView, policies PolicyView, profiles GovernanceProfileCatalog, collections ApprovalCollectionView, ids globalid.View, idempotencyView idempotency.JoinedView,
	documents PolicyDocumentView, evidence EvidenceView, audit AuditView, profile Profile) (*Planner, error) {
	if iam == nil || policies == nil || profiles == nil || collections == nil || ids == nil || idempotencyView == nil || documents == nil || evidence == nil || audit == nil {
		return nil, fmt.Errorf("%w: every read-only view is required", ErrInvalidConfiguration)
	}
	if !preflightProfile(profile) {
		return nil, ErrInvalidConfiguration
	}
	profile = cloneProfile(profile)
	if err := validateProfile(profile); err != nil {
		return nil, err
	}
	profileDigest, err := digestGovernanceProfile(profile)
	if err != nil {
		return nil, fmt.Errorf("%w: profile digest: %v", ErrInvalidConfiguration, err)
	}
	validator, err := canonical.NewValidator()
	if err != nil {
		return nil, fmt.Errorf("%w: canonical registry: %v", ErrInvalidConfiguration, err)
	}
	return &Planner{iam: iam, policies: policies, profiles: profiles, collections: collections, ids: ids, idempotency: idempotencyView,
		documents: documents, evidence: evidence, audit: audit, profile: profile, profileDigest: profileDigest, canonical: validator}, nil
}

// PlanPolicyApproval validates the entire multi-signature approval set and
// returns a non-committable plan. FinalizePolicyMutation must bind the exact
// intent to a signed AuditEvent and current audit-head CAS.
func (p *Planner) PlanPolicyApproval(ctx context.Context, command PolicyApprovalCommand) (PendingPolicyPlan, error) {
	policy, audit, err := p.planPolicyApproval(ctx, command)
	if err != nil {
		return PendingPolicyPlan{}, err
	}
	pending := PendingPolicyPlan{policy: policy, audit: audit}
	pending.digest = digestPendingPolicyPlan(policy.Digest(), audit.Digest())
	return pending, nil
}

func (p *Planner) planPolicyApproval(ctx context.Context, command PolicyApprovalCommand) (MutationPlan, AuditIntent, error) {
	if p == nil || p.canonical == nil {
		return MutationPlan{}, AuditIntent{}, ErrInvalidConfiguration
	}
	if err := contextErr(ctx); err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	if command.AtUnixNano < 0 || len(command.Approvals) == 0 || len(command.Approvals) > maxApprovals {
		return MutationPlan{}, AuditIntent{}, ErrInvalidCommand
	}
	approvals := make([]policyApproval, 0, len(command.Approvals))
	var canonicalPayload []byte
	var payloadDigest [ccse.DigestSize]byte
	var correlationID [ccse.MessageIDSize]byte
	var causationID ccse.OptionalMessageID

	for index := range command.Approvals {
		snapshot, err := p.validateSignedRecord(ctx, command.Approvals[index], schema.MessageTypePolicyBundle, policyPurpose, p.profile.PolicyReplayDomainID, command.AtUnixNano)
		if err != nil {
			return MutationPlan{}, AuditIntent{}, fmt.Errorf("approval %d: %w", index, err)
		}
		decoded, err := p.canonical.Decode(schema.MessageTypePolicyBundle, p.profile.SchemaVersion, snapshot.record.Payload)
		if err != nil {
			return MutationPlan{}, AuditIntent{}, fmt.Errorf("approval %d: %w", index, err)
		}
		bundle, ok := decoded.(foundationv1.PolicyBundleSigningProjection)
		if !ok {
			return MutationPlan{}, AuditIntent{}, ErrInvalidSignedRecord
		}
		if index == 0 {
			canonicalPayload = append([]byte(nil), snapshot.record.Payload...)
			payloadDigest = snapshot.record.Envelope.PayloadDigest
			correlationID = snapshot.record.Envelope.CorrelationID
			causationID = snapshot.record.Envelope.CausationID
		} else if !bytes.Equal(canonicalPayload, snapshot.record.Payload) || payloadDigest != snapshot.record.Envelope.PayloadDigest {
			return MutationPlan{}, AuditIntent{}, fmt.Errorf("approval %d: %w", index, ErrApprovalPayloadMismatch)
		} else if correlationID != snapshot.record.Envelope.CorrelationID {
			return MutationPlan{}, AuditIntent{}, fmt.Errorf("approval %d: %w: correlation differs", index, ErrApprovalSetMismatch)
		} else if causationID != snapshot.record.Envelope.CausationID {
			return MutationPlan{}, AuditIntent{}, fmt.Errorf("approval %d: %w: causation differs", index, ErrApprovalSetMismatch)
		}
		approvals = append(approvals, policyApproval{record: snapshot, bundle: bundle})
	}

	bundle := approvals[0].bundle
	idempotencyBinding := policyIdempotencyBinding(bundle, payloadDigest)
	idempotencyDecision, err := idempotency.PrecheckJoined(ctx, p.idempotency, idempotencyBinding)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	if idempotencyDecision.Kind() == idempotency.DuplicateCompleted {
		return MutationPlan{}, AuditIntent{}, DuplicateCompletedError{OutcomeDigestSHA256: idempotencyDecision.OutcomeDigest()}
	}
	if idempotencyDecision.Kind() != idempotency.ContinueCollection ||
		idempotencyDecision.ParentSnapshot().State != idempotency.StateCollecting {
		return MutationPlan{}, AuditIntent{}, ErrApprovalCollection
	}
	joinedAuditBinding, err := idempotency.JoinedAuditBinding(idempotencyBinding)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, ErrInvalidCommand
	}
	if !validJoinedAuditReservation(idempotencyDecision.AuditSnapshot(), joinedAuditBinding) {
		return MutationPlan{}, AuditIntent{}, ErrApprovalCollection
	}
	for index := range approvals {
		key, authorizeErr := p.authorizeKey(ctx, approvals[index].record, schema.MessageTypePolicyBundle, command.AtUnixNano)
		if authorizeErr != nil {
			return MutationPlan{}, AuditIntent{}, fmt.Errorf("approval %d: %w", index, authorizeErr)
		}
		approvals[index].key = key
	}
	if bundle.Sequence > uint64(p.profile.MaxPolicyRecords) {
		return MutationPlan{}, AuditIntent{}, ErrPolicySequence
	}
	if bundle.ApprovedAtUnixNano > command.AtUnixNano {
		return MutationPlan{}, AuditIntent{}, fmt.Errorf("%w: approval time is in the future", ErrInvalidCommand)
	}
	if (bundle.State == PolicyStateApprovedDelayed || bundle.State == PolicyStateActive || bundle.State == PolicyStateRolledBack || bundle.State == PolicyStateRevoked) &&
		bundle.ExpiresAtUnixNano <= command.AtUnixNano {
		return MutationPlan{}, AuditIntent{}, ErrPolicyExpired
	}

	identities := make([]string, 0, len(approvals))
	keyIDs := make([]string, 0, len(approvals))
	recordDigests := make([][ccse.DigestSize]byte, 0, len(approvals))
	keys := make([]GovernanceKeySnapshot, 0, len(approvals))
	for _, item := range approvals {
		if bundle.Metadata.CreatedAtUnixNano > item.record.record.Domain.IssuedAtUnixNano {
			return MutationPlan{}, AuditIntent{}, fmt.Errorf("%w: policy created after approval signature", ErrInvalidCommand)
		}
		identities = append(identities, item.record.record.Domain.SenderIdentity)
		keyIDs = append(keyIDs, item.record.record.Domain.SignatureKeyID)
		recordDigests = append(recordDigests, item.record.digest)
		keys = append(keys, cloneKeySnapshot(item.key))
	}
	if hasDuplicateStrings(identities) || hasDuplicateStrings(keyIDs) || hasDuplicateDigests(recordDigests) {
		return MutationPlan{}, AuditIntent{}, ErrDuplicateApprover
	}
	if !equalStringSets(identities, bundle.ApproverIdentities) || !equalStringSets(keyIDs, bundle.ApproverKeyIDs) {
		return MutationPlan{}, AuditIntent{}, ErrApprovalSetMismatch
	}
	if bundle.MinimumApprovals < p.profile.MinimumApprovals || uint32(len(approvals)) < bundle.MinimumApprovals {
		return MutationPlan{}, AuditIntent{}, ErrApprovalQuorum
	}
	organizations := make([]string, 0, len(keys))
	for _, key := range keys {
		organizations = append(organizations, key.OrganizationIdentity)
	}
	if uint32(distinctStringCount(organizations)) < p.profile.MinimumDistinctApprovalOrganizations {
		return MutationPlan{}, AuditIntent{}, ErrRoleSeparation
	}
	if !rolesHaveDistinctAssignment(keys, p.profile.RequiredApprovalRoles) {
		return MutationPlan{}, AuditIntent{}, ErrRoleSeparation
	}
	for _, key := range keys {
		if !containsDigest(bundle.Metadata.PolicyDigestsSHA256, key.AuthorizationPolicyDigestSHA256) {
			return MutationPlan{}, AuditIntent{}, fmt.Errorf("%w: key %q authorization policy is not committed by metadata", ErrKeyNotAuthorized, key.KeyID)
		}
	}
	authorizationDigests := make([][ccse.DigestSize]byte, 0, len(keys))
	for _, key := range keys {
		authorizationDigests = append(authorizationDigests, key.AuthorizationPolicyDigestSHA256)
	}
	authorizationDigests = append(authorizationDigests, p.profileDigest)
	authorizationDigests = uniqueSortedDigests(authorizationDigests)
	if !equalDigestSets(bundle.Metadata.PolicyDigestsSHA256, authorizationDigests) {
		return MutationPlan{}, AuditIntent{}, fmt.Errorf("%w: metadata authorization policy set differs", ErrKeyNotAuthorized)
	}
	collectedApprovals, err := p.validatePolicyApprovalCollection(ctx, idempotencyBinding, idempotencyDecision.ParentSnapshot(), approvals, command.AtUnixNano)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}

	registry, err := p.policies.SnapshotPolicy(ctx, bundle.PolicyKind)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, fmt.Errorf("aiinfra governance: snapshot policy: %w", err)
	}
	if !p.preflightPolicyRegistrySnapshot(registry) {
		return MutationPlan{}, AuditIntent{}, ErrSnapshotInconsistent
	}
	registry = clonePolicyRegistrySnapshot(registry)
	if err := contextErr(ctx); err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	if err := p.validatePolicyRegistrySnapshot(ctx, bundle.PolicyKind, registry); err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	profileActivation, err := p.validatePolicyWriterFence(ctx, registry, command.AtUnixNano)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	if bundle.Metadata.HomeRegion != p.profile.PolicyHomeRegion || bundle.Metadata.HomeRegion != registry.AuthorizedHomeRegion ||
		bundle.Metadata.WriterEpoch != registry.AuthorizedWriterEpoch || bundle.Metadata.StateVersion != bundle.Sequence ||
		bundle.Metadata.CreatedAtUnixNano > command.AtUnixNano || !validPolicyCreatedAtForState(bundle.State, bundle.Metadata.CreatedAtUnixNano,
		bundle.ApprovedAtUnixNano, bundle.EffectiveAtUnixNano, bundle.ExpiresAtUnixNano) {
		return MutationPlan{}, AuditIntent{}, ErrPolicyConflict
	}
	if err := validateSequenceAndPredecessor(bundle, registry); err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	if err := validateNoPolicyConflict(bundle, payloadDigest, registry); err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}

	action, err := p.policyAction(bundle, command.AtUnixNano)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	if !bundle.Emergency && bundle.EffectiveAtUnixNano-bundle.ApprovedAtUnixNano < p.profile.MinActivationDelayNanos {
		return MutationPlan{}, AuditIntent{}, ErrActivationDelay
	}
	document, resolveErr := p.documents.ResolvePolicyDocument(ctx, bundle.PolicyDocumentDigestSHA256)
	if resolveErr != nil {
		return MutationPlan{}, AuditIntent{}, fmt.Errorf("aiinfra governance: resolve policy document: %w", resolveErr)
	}
	if !preflightPolicyDocumentSnapshot(document) {
		if bundle.Emergency {
			return MutationPlan{}, AuditIntent{}, ErrBreakGlassScope
		}
		return MutationPlan{}, AuditIntent{}, ErrSnapshotInconsistent
	}
	document = clonePolicyDocumentSnapshot(document)
	if validatePolicyDocument(document, bundle.PolicyDocumentDigestSHA256, bundle.PolicyDocumentMediaType) != nil {
		if bundle.Emergency {
			return MutationPlan{}, AuditIntent{}, ErrBreakGlassScope
		}
		return MutationPlan{}, AuditIntent{}, ErrSnapshotInconsistent
	}

	var scopes []string
	if bundle.Emergency {
		if bundle.MinimumApprovals < p.profile.BreakGlassMinimumApprovals || len(approvals) < 2 {
			return MutationPlan{}, AuditIntent{}, ErrBreakGlassDualControl
		}
		if !rolesHaveDistinctAssignment(keys, p.profile.BreakGlassRequiredRoles) {
			return MutationPlan{}, AuditIntent{}, ErrBreakGlassDualControl
		}
		if uint32(distinctStringCount(organizations)) < p.profile.BreakGlassMinimumDistinctOrganizations {
			return MutationPlan{}, AuditIntent{}, ErrBreakGlassDualControl
		}
		if !bundle.BreakGlassExpiresAtUnixNano.Present ||
			(action == MutationPolicyActivate && bundle.BreakGlassExpiresAtUnixNano.Value <= command.AtUnixNano) ||
			bundle.BreakGlassExpiresAtUnixNano.Value != bundle.ExpiresAtUnixNano ||
			bundle.BreakGlassExpiresAtUnixNano.Value-bundle.EffectiveAtUnixNano > p.profile.MaxBreakGlassDurationNanos {
			return MutationPlan{}, AuditIntent{}, ErrBreakGlassExpiry
		}
		derivedScopes, decodeErr := decodeBreakGlassDocument(document, bundle.PolicyDocumentDigestSHA256, bundle.PolicyDocumentMediaType, bundle.PolicyKind)
		if decodeErr != nil {
			return MutationPlan{}, AuditIntent{}, decodeErr
		}
		scopes, err = validateBreakGlassScopes(derivedScopes, p.profile.AllowedBreakGlassScopes)
		if err != nil {
			return MutationPlan{}, AuditIntent{}, err
		}
	}
	if err := validateProposedPolicyTransition(bundle, scopes, registry); err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	if bundle.Metadata.RecordID == bundle.PolicyBundleID {
		return MutationPlan{}, AuditIntent{}, ErrInvalidCommand
	}
	ownerDigest := policyBundleOwnerDigest(bundle.PolicyKind, bundle.PolicyBundleID)
	policyOwner := globalid.Owner{Domain: globalid.OwnerGovernancePolicyBundle, ID: hex.EncodeToString(ownerDigest[:])}
	ownerSnapshot, ownerExists, err := p.ids.LookupGlobalID(ctx, bundle.PolicyBundleID)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, fmt.Errorf("aiinfra governance: lookup policy bundle ID: %w", err)
	}
	newLifecycle := bundle.State == PolicyStateApprovedDelayed || (bundle.State == PolicyStateActive && bundle.Emergency)
	if newLifecycle {
		for _, historical := range registry.Records {
			if historical.PolicyBundleID == bundle.PolicyBundleID {
				return MutationPlan{}, AuditIntent{}, ErrPolicyConflict
			}
		}
	}
	if !ownerExists {
		return MutationPlan{}, AuditIntent{}, ErrPolicyConflict
	}
	bundleClaim, assertErr := globalid.Assert(bundle.PolicyBundleID, ownerSnapshot, policyOwner)
	if assertErr != nil {
		return MutationPlan{}, AuditIntent{}, ErrPolicyConflict
	}
	recordOwner, recordExists, err := p.ids.LookupGlobalID(ctx, bundle.Metadata.RecordID)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, fmt.Errorf("aiinfra governance: lookup policy record ID: %w", err)
	}
	if !recordExists {
		return MutationPlan{}, AuditIntent{}, ErrPolicyConflict
	}
	recordClaim, assertErr := globalid.Assert(bundle.Metadata.RecordID, recordOwner, globalid.Owner{
		Domain: globalid.OwnerCanonicalRecord, ID: hex.EncodeToString(payloadDigest[:]),
	})
	if assertErr != nil {
		return MutationPlan{}, AuditIntent{}, ErrPolicyConflict
	}
	eventID, err := idempotency.JoinedAuditEventID(idempotencyBinding)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, ErrInvalidCommand
	}
	eventOwner, eventExists, err := p.ids.LookupGlobalID(ctx, eventID)
	if err != nil || !eventExists {
		return MutationPlan{}, AuditIntent{}, ErrPolicyConflict
	}
	eventClaim, assertErr := globalid.Assert(eventID, eventOwner, globalid.Owner{Domain: globalid.OwnerGovernanceAuditEvent, ID: eventID})
	if assertErr != nil {
		return MutationPlan{}, AuditIntent{}, ErrPolicyConflict
	}
	if bundle.State == PolicyStateApprovedDelayed || (bundle.State == PolicyStateActive && bundle.Emergency) {
		for index := range approvals {
			if approvals[index].record.record.Domain.IssuedAtUnixNano > bundle.ApprovedAtUnixNano {
				return MutationPlan{}, AuditIntent{}, fmt.Errorf("approval %d: %w: new revision signature issued after approved_at", index, ErrInvalidCommand)
			}
		}
	}

	if bundle.RollbackTargetDigestSHA256.Present != (bundle.State == PolicyStateRolledBack) {
		return MutationPlan{}, AuditIntent{}, ErrRollbackTarget
	}
	rollbackTargetDeadline := int64(math.MaxInt64)
	if bundle.RollbackTargetDigestSHA256.Present {
		var rollbackErr error
		rollbackTargetDeadline, rollbackErr = validateRollbackTarget(bundle, payloadDigest, registry, command.AtUnixNano)
		if rollbackErr != nil {
			return MutationPlan{}, AuditIntent{}, rollbackErr
		}
	}

	sortDigests(recordDigests)
	approvalEvidence := make([]SignedEvidence, 0, len(approvals))
	for _, item := range approvals {
		approvalEvidence = append(approvalEvidence, newSignedEvidence(item.record))
	}
	sort.Slice(approvalEvidence, func(i, j int) bool {
		return bytes.Compare(approvalEvidence[i].recordDigest[:], approvalEvidence[j].recordDigest[:]) < 0
	})
	keyPreconditions := make([]KeyStatePrecondition, 0, len(keys))
	for _, key := range keys {
		keyPreconditions = append(keyPreconditions, keyPrecondition(key))
	}
	sort.Slice(keyPreconditions, func(i, j int) bool { return keyPreconditions[i].KeyID < keyPreconditions[j].KeyID })
	evidence := append([][ccse.DigestSize]byte(nil), recordDigests...)
	evidence = append(evidence, payloadDigest, bundle.PolicyDocumentDigestSHA256)
	evidence = uniqueSortedDigests(evidence)
	applied := uniqueSortedDigests(append([][ccse.DigestSize]byte(nil), bundle.Metadata.PolicyDigestsSHA256...))
	subjects := uniqueSortedStrings([]string{bundle.PolicyBundleID, bundle.Metadata.RecordID})
	commitDeadline := int64(math.MaxInt64)
	for _, item := range approvals {
		commitDeadline = minimumInt64(commitDeadline, item.record.record.Domain.ExpiresAtUnixNano)
		commitDeadline = minimumInt64(commitDeadline, item.key.NotAfterUnixNano)
	}
	if action == MutationPolicyPublish || action == MutationPolicyActivate || action == MutationPolicyRollback || action == MutationPolicyRevoke {
		commitDeadline = minimumInt64(commitDeadline, bundle.ExpiresAtUnixNano)
	}
	if action == MutationPolicyRollback {
		commitDeadline = minimumInt64(commitDeadline, rollbackTargetDeadline)
	}
	commitDeadline = minimumInt64(commitDeadline, registry.WriterLeaseNotAfterUnixNano)
	commitDeadline = minimumInt64(commitDeadline, profileActivation.ValidUntilUnixNano)
	if action == MutationPolicyPublish {
		commitDeadline = minimumInt64(commitDeadline, bundle.EffectiveAtUnixNano)
	}
	if bundle.Emergency && action == MutationPolicyActivate {
		commitDeadline = minimumInt64(commitDeadline, bundle.BreakGlassExpiresAtUnixNano.Value)
	}
	latencyDeadline, ok := addPositiveNanos(command.AtUnixNano, p.profile.MaxPlanCommitLatencyNanos)
	if !ok {
		return MutationPlan{}, AuditIntent{}, ErrInvalidCommand
	}
	commitDeadline = minimumInt64(commitDeadline, latencyDeadline)
	commitNotBefore := maximumInt64(subtractFloorZero(command.AtUnixNano, p.profile.MaxClockSkewNanos), actionNotBefore(action, bundle))
	commitNotBefore = maximumInt64(commitNotBefore, profileActivation.ValidFromUnixNano)
	if commitDeadline <= commitNotBefore {
		return MutationPlan{}, AuditIntent{}, ErrPolicyExpired
	}
	identifierClaims, err := globalid.NormalizeClaims([]globalid.Claim{bundleClaim, recordClaim, eventClaim})
	if err != nil {
		return MutationPlan{}, AuditIntent{}, ErrPolicyConflict
	}
	planValue := MutationPlanSnapshot{
		EvaluatedAtUnixNano:                           command.AtUnixNano,
		CommitNotBeforeUnixNano:                       commitNotBefore,
		CommitNotAfterUnixNano:                        commitDeadline,
		GovernanceProfileDigestSHA256:                 p.profileDigest,
		GovernanceProfileActivation:                   profileActivation,
		Kind:                                          action,
		PolicyBundleID:                                bundle.PolicyBundleID,
		PolicyRecordID:                                bundle.Metadata.RecordID,
		PolicyKind:                                    bundle.PolicyKind,
		PolicySequence:                                bundle.Sequence,
		PolicyBundleDigestSHA256:                      payloadDigest,
		PolicyDocumentDigestSHA256:                    bundle.PolicyDocumentDigestSHA256,
		PolicyDocumentEvidence:                        append([]byte(nil), document.CanonicalDocument...),
		PolicyIdempotencySnapshot:                     idempotencyDecision.ParentSnapshot(),
		JoinedAuditIdempotencySnapshot:                idempotencyDecision.AuditSnapshot(),
		ExpectedPolicyHeadPresent:                     registry.HeadPresent,
		ExpectedPolicyHeadSequence:                    registry.Head.Sequence,
		ExpectedPolicyHeadDigest:                      registry.Head.BundleDigestSHA256,
		ExpectedPolicyHeadHomeRegion:                  registry.Head.HomeRegion,
		AuthorizedPolicyHomeRegion:                    registry.AuthorizedHomeRegion,
		ExpectedPolicyHeadWriterEpoch:                 registry.Head.WriterEpoch,
		AuthorizedPolicyWriterEpoch:                   registry.AuthorizedWriterEpoch,
		ExpectedPolicyWriterLeaseEvidenceDigestSHA256: registry.WriterLeaseEvidenceDigestSHA256,
		ExpectedPolicyWriterLeaseNotBeforeUnixNano:    registry.WriterLeaseNotBeforeUnixNano,
		ExpectedPolicyWriterLeaseNotAfterUnixNano:     registry.WriterLeaseNotAfterUnixNano,
		RollbackTargetPresent:                         bundle.RollbackTargetDigestSHA256.Present,
		RollbackTargetDigestSHA256:                    bundle.RollbackTargetDigestSHA256.Value,
		ApprovedAtUnixNano:                            bundle.ApprovedAtUnixNano,
		EffectiveAtUnixNano:                           bundle.EffectiveAtUnixNano,
		ExpiresAtUnixNano:                             bundle.ExpiresAtUnixNano,
		Emergency:                                     bundle.Emergency,
		BreakGlassScopes:                              append([]string(nil), scopes...),
		ApprovalRecordDigestsSHA256:                   append([][ccse.DigestSize]byte(nil), recordDigests...),
		AuditSourceDigestsSHA256:                      append([][ccse.DigestSize]byte(nil), evidence...),
		ApprovalEvidence:                              approvalEvidence,
		ApprovalAdmissionEvidence:                     approvalAdmissionEvidence(collectedApprovals),
		ApprovalKeyPreconditions:                      keyPreconditions,
		ExpectedPolicyBundleIDAbsent:                  false,
		PolicyBundleOwnerDigestSHA256:                 ownerDigest,
		ExpectedPolicyRecordIDAbsent:                  false,
		IdentifierClaims:                              identifierClaims,
	}
	if bundle.BreakGlassExpiresAtUnixNano.Present {
		planValue.BreakGlassExpiresAtUnixNano = bundle.BreakGlassExpiresAtUnixNano.Value
	}
	intentValue := AuditIntentSnapshot{
		Required:                   true,
		StreamID:                   p.profile.AuditReplayDomainID,
		EventType:                  eventTypeForAction(action),
		AuditEventID:               eventID,
		ActorIdentity:              p.profile.AuditWriterIdentity,
		ActorKeyID:                 p.profile.AuditWriterKeyID,
		SubjectIDs:                 subjects,
		CauseCode:                  causeForAction(action, bundle.Emergency),
		OccurredAtUnixNano:         command.AtUnixNano,
		Outcome:                    1,
		IdempotencyKey:             joinedAuditBinding.Key,
		CorrelationID:              correlationID,
		CausationID:                causationID,
		AppliedPolicyDigestsSHA256: applied,
		EvidenceDigestsSHA256:      evidence,
		Emergency:                  bundle.Emergency,
		BreakGlassScopes:           append([]string(nil), scopes...),
	}
	if bundle.BreakGlassExpiresAtUnixNano.Present {
		intentValue.BreakGlassExpiresAtUnixNano = bundle.BreakGlassExpiresAtUnixNano.Value
	}
	plan, err := newMutationPlan(planValue)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	intent, err := newAuditIntent(intentValue)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	return plan, intent, nil
}

func (p *Planner) policyAction(bundle foundationv1.PolicyBundleSigningProjection, at int64) (MutationKind, error) {
	switch bundle.State {
	case PolicyStateApprovedDelayed:
		if bundle.EffectiveAtUnixNano <= at {
			return 0, fmt.Errorf("%w: delayed state is already effective", ErrActivationDelay)
		}
		return MutationPolicyPublish, nil
	case PolicyStateActive:
		if bundle.EffectiveAtUnixNano > at {
			return 0, ErrActivationDelay
		}
		return MutationPolicyActivate, nil
	case PolicyStateRolledBack:
		if bundle.EffectiveAtUnixNano > at {
			return 0, ErrActivationDelay
		}
		return MutationPolicyRollback, nil
	case PolicyStateRevoked:
		if bundle.ApprovedAtUnixNano > at || bundle.ExpiresAtUnixNano <= at {
			return 0, ErrPolicyExpired
		}
		return MutationPolicyRevoke, nil
	case PolicyStateExpired:
		if bundle.ExpiresAtUnixNano > at {
			return 0, ErrPolicyExpired
		}
		return MutationPolicyExpire, nil
	default:
		return 0, fmt.Errorf("%w: policy state %d cannot mutate the registry", ErrInvalidCommand, bundle.State)
	}
}

func eventTypeForAction(action MutationKind) string {
	switch action {
	case MutationPolicyPublish:
		return "PolicyPublishedDelayed"
	case MutationPolicyActivate:
		return "PolicyActivated"
	case MutationPolicyRollback:
		return "PolicyRolledBack"
	case MutationPolicyRevoke:
		return "PolicyRevoked"
	case MutationPolicyExpire:
		return "PolicyExpired"
	default:
		return "PolicyMutationRejected"
	}
}

func causeForAction(action MutationKind, emergency bool) string {
	if emergency {
		return "break-glass-dual-control"
	}
	switch action {
	case MutationPolicyRollback:
		return "approved-rollback"
	case MutationPolicyRevoke:
		return "approved-revocation"
	case MutationPolicyExpire:
		return "scheduled-expiry"
	default:
		return "approved-change-control"
	}
}

func validateProfile(profile Profile) error {
	if profile.ProtocolVersion.Major == 0 || profile.SchemaVersion != (ccse.Version{Major: 1, Minor: 0}) ||
		len(profile.Audience) == 0 || profile.Environment == "" || isZeroDigest(profile.ChainID) || isZeroDigest(profile.GenesisHash) ||
		profile.PolicyReplayDomainID == "" || profile.AuditReplayDomainID == "" || profile.PolicyReplayDomainID == profile.AuditReplayDomainID ||
		profile.AuditWriterIdentity == "" || profile.AuditWriterKeyID == "" || profile.AuditWriterRole == "" ||
		profile.PolicyHomeRegion == "" || profile.AuditHomeRegion == "" ||
		profile.EnrollmentDomainID == "" || isZeroDigest(profile.AuditDeploymentAnchorSHA256) ||
		profile.MinimumApprovals == 0 || profile.MinimumDistinctApprovalOrganizations == 0 ||
		profile.MinimumDistinctApprovalOrganizations > profile.MinimumApprovals || profile.BreakGlassMinimumApprovals < 2 ||
		profile.BreakGlassMinimumApprovals < profile.MinimumApprovals || profile.MinActivationDelayNanos <= 0 ||
		profile.BreakGlassMinimumDistinctOrganizations < 2 ||
		profile.BreakGlassMinimumDistinctOrganizations > profile.BreakGlassMinimumApprovals ||
		profile.MaxBreakGlassDurationNanos <= 0 || profile.MaxRecordValidityNanos <= 0 || profile.MaxClockSkewNanos < 0 ||
		profile.MaxPlanCommitLatencyNanos <= 0 || profile.MaxPolicyRecords <= 0 ||
		len(profile.RequiredApprovalRoles) == 0 || len(profile.BreakGlassRequiredRoles) < 2 || len(profile.AllowedBreakGlassScopes) == 0 {
		return ErrInvalidConfiguration
	}
	if (!profile.TenantOrganization.Present && profile.TenantOrganization.Value != "") ||
		(!profile.ProviderOrganization.Present && profile.ProviderOrganization.Value != "") ||
		hasDuplicateStrings(profile.Audience) || hasDuplicateStrings(profile.RequiredApprovalRoles) ||
		hasDuplicateStrings(profile.BreakGlassRequiredRoles) || hasDuplicateStrings(profile.AllowedBreakGlassScopes) ||
		containsEmpty(profile.Audience) || containsEmpty(profile.RequiredApprovalRoles) || containsEmpty(profile.BreakGlassRequiredRoles) || containsEmpty(profile.AllowedBreakGlassScopes) {
		return ErrInvalidConfiguration
	}
	return nil
}

func preflightProfile(profile Profile) bool {
	if len(profile.Audience) == 0 || len(profile.Audience) > 64 || len(profile.RequiredApprovalRoles) == 0 || len(profile.RequiredApprovalRoles) > 64 ||
		len(profile.BreakGlassRequiredRoles) < 2 || len(profile.BreakGlassRequiredRoles) > 64 ||
		len(profile.AllowedBreakGlassScopes) == 0 || len(profile.AllowedBreakGlassScopes) > 64 ||
		profile.MaxPolicyRecords <= 0 || profile.MaxPolicyRecords > 4096 || profile.MinimumApprovals > maxApprovals ||
		profile.MinimumDistinctApprovalOrganizations > maxApprovals || profile.BreakGlassMinimumApprovals > maxApprovals ||
		profile.BreakGlassMinimumDistinctOrganizations > maxApprovals {
		return false
	}
	total := 0
	values := []string{
		profile.Environment, profile.PolicyReplayDomainID, profile.AuditReplayDomainID, profile.AuditWriterIdentity, profile.AuditWriterKeyID, profile.AuditWriterRole,
		profile.PolicyHomeRegion, profile.AuditHomeRegion, profile.EnrollmentDomainID,
		profile.TenantOrganization.Value, profile.ProviderOrganization.Value,
	}
	values = append(values, profile.Audience...)
	values = append(values, profile.RequiredApprovalRoles...)
	values = append(values, profile.BreakGlassRequiredRoles...)
	values = append(values, profile.AllowedBreakGlassScopes...)
	for _, value := range values {
		if !boundedSizeAdd(&total, len(value), 64<<10) {
			return false
		}
	}
	return true
}

func (p *Planner) preflightPolicyRegistrySnapshot(snapshot PolicyRegistrySnapshot) bool {
	const (
		maxHistoryRecords         = 4096
		maxHistoryApprovalRecords = 8192
		maxHistoryBytes           = 256 << 20
	)
	approvalCount := len(snapshot.Head.ApprovalEvidence)
	if len(snapshot.Records) > maxHistoryRecords || len(snapshot.Head.BreakGlassScopes) > 64 ||
		len(snapshot.Head.ApproverIdentities) > 64 || len(snapshot.Head.ApproverKeyIDs) > 64 ||
		len(snapshot.Head.ApprovalEvidence) > maxApprovals ||
		len(snapshot.Head.CanonicalPayload) > maxPayloadBytesFor(schema.MessageTypePolicyBundle) {
		return false
	}
	for _, record := range snapshot.Records {
		if len(record.ApprovalEvidence) > maxApprovals || approvalCount > maxHistoryApprovalRecords-len(record.ApprovalEvidence) {
			return false
		}
		approvalCount += len(record.ApprovalEvidence)
	}
	total := 0
	headValues := []string{snapshot.Head.RecordID, snapshot.Head.HomeRegion, snapshot.Head.PolicyBundleID,
		snapshot.Head.PolicyKind, snapshot.Head.PolicyDocumentMediaType, snapshot.AuthorizedHomeRegion}
	if !boundedSizeAdd(&total, len(snapshot.Head.CanonicalPayload), maxHistoryBytes) {
		return false
	}
	for _, value := range headValues {
		if !boundedSizeAdd(&total, len(value), maxHistoryBytes) {
			return false
		}
	}
	for _, value := range append(append([]string(nil), snapshot.Head.ApproverIdentities...), snapshot.Head.ApproverKeyIDs...) {
		if !boundedSizeAdd(&total, len(value), maxHistoryBytes) {
			return false
		}
	}
	for _, scope := range snapshot.Head.BreakGlassScopes {
		if !boundedSizeAdd(&total, len(scope), maxHistoryBytes) {
			return false
		}
	}
	for _, evidence := range snapshot.Head.ApprovalEvidence {
		if !preflightHistoricalApprovalEvidence(evidence, &total, maxHistoryBytes) {
			return false
		}
	}
	for _, record := range snapshot.Records {
		if len(record.BreakGlassScopes) > 64 || len(record.ApproverIdentities) > 64 || len(record.ApproverKeyIDs) > 64 ||
			len(record.ApprovalEvidence) == 0 || len(record.ApprovalEvidence) > maxApprovals ||
			len(record.CanonicalPayload) == 0 || len(record.CanonicalPayload) > maxPayloadBytesFor(schema.MessageTypePolicyBundle) ||
			!boundedSizeAdd(&total, len(record.CanonicalPayload), maxHistoryBytes) {
			return false
		}
		for _, value := range []string{record.RecordID, record.HomeRegion, record.PolicyBundleID, record.PolicyKind, record.PolicyDocumentMediaType} {
			if !boundedSizeAdd(&total, len(value), maxHistoryBytes) {
				return false
			}
		}
		for _, value := range append(append([]string(nil), record.ApproverIdentities...), record.ApproverKeyIDs...) {
			if !boundedSizeAdd(&total, len(value), maxHistoryBytes) {
				return false
			}
		}
		for _, scope := range record.BreakGlassScopes {
			if !boundedSizeAdd(&total, len(scope), maxHistoryBytes) {
				return false
			}
		}
		for _, evidence := range record.ApprovalEvidence {
			if !preflightHistoricalApprovalEvidence(evidence, &total, maxHistoryBytes) {
				return false
			}
		}
	}
	return true
}

func preflightHistoricalApprovalEvidence(evidence HistoricalPolicyApprovalEvidence, total *int, limit int) bool {
	record := evidence.Signed.Record
	if !preflightRawRecord(record, maxPayloadBytesFor(schema.MessageTypePolicyBundle)) || !preflightKeySnapshot(evidence.Key) {
		return false
	}
	// Historical evidence retains both the transport record and the immutable
	// verifier snapshot. Account for both representations before any allocating
	// getter is called; a verifier constructed with wider limits must not bypass
	// this receiver's per-record or aggregate budget.
	limits := ccse.DefaultLimits()
	limits.MaxPayloadBytes = maxPayloadBytesFor(schema.MessageTypePolicyBundle)
	verifiedSize, err := evidence.Signed.Verified.PreflightSize(limits)
	if err != nil || verifiedSize > uint64(limit) || !boundedSizeAdd(total, int(verifiedSize), limit) {
		return false
	}
	for _, size := range []int{len(record.Payload), len(record.Signature), len(evidence.Key.PublicKey), 4 * len(evidence.Key.AllowedMessageTypeIDs)} {
		if !boundedSizeAdd(total, size, limit) {
			return false
		}
	}
	values := []string{
		record.Domain.Purpose, record.Domain.SenderIdentity, record.Domain.TenantOrganization.Value,
		record.Domain.ProviderOrganization.Value, record.Domain.Environment, record.Domain.SignatureKeyID,
		record.Domain.ReplayDomainID, record.Envelope.SenderIdentity, record.Envelope.Environment,
		record.Envelope.SignatureKeyID, evidence.Key.KeyID, evidence.Key.SubjectIdentity,
		evidence.Key.TargetIdentityID, evidence.Key.OrganizationIdentity, evidence.Key.EnrollmentDomainID, evidence.Key.EnrollmentEnvironment,
	}
	values = append(values, record.Domain.Audience...)
	values = append(values, evidence.Key.Roles...)
	for _, value := range values {
		if !boundedSizeAdd(total, len(value), limit) {
			return false
		}
	}
	for _, extension := range record.Envelope.Extensions {
		if !boundedSizeAdd(total, len(extension.Value), limit) {
			return false
		}
	}
	return true
}

func preflightPolicyDocumentSnapshot(snapshot PolicyDocumentSnapshot) bool {
	return len(snapshot.MediaType) > 0 && len(snapshot.MediaType) <= 128 &&
		len(snapshot.CanonicalDocument) > 0 && len(snapshot.CanonicalDocument) <= maxPolicyDocumentBytes
}

func cloneProfile(profile Profile) Profile {
	profile.Audience = append([]string(nil), profile.Audience...)
	profile.RequiredApprovalRoles = append([]string(nil), profile.RequiredApprovalRoles...)
	profile.BreakGlassRequiredRoles = append([]string(nil), profile.BreakGlassRequiredRoles...)
	profile.AllowedBreakGlassScopes = append([]string(nil), profile.AllowedBreakGlassScopes...)
	return profile
}

func validateSequenceAndPredecessor(bundle foundationv1.PolicyBundleSigningProjection, registry PolicyRegistrySnapshot) error {
	if !registry.HeadPresent {
		if bundle.Sequence != 1 {
			return ErrPolicySequence
		}
		if bundle.PredecessorDigestSHA256.Present {
			return ErrPolicyPredecessor
		}
		return nil
	}
	if registry.Head.Sequence == math.MaxUint64 || bundle.Sequence != registry.Head.Sequence+1 {
		return ErrPolicySequence
	}
	if !bundle.PredecessorDigestSHA256.Present || bundle.PredecessorDigestSHA256.Value != registry.Head.BundleDigestSHA256 {
		return ErrPolicyPredecessor
	}
	return nil
}

func validateNoPolicyConflict(bundle foundationv1.PolicyBundleSigningProjection, digest [ccse.DigestSize]byte, registry PolicyRegistrySnapshot) error {
	for _, record := range registry.Records {
		if record.BundleDigestSHA256 == digest {
			return ErrPolicyConflict
		}
		if record.Sequence == bundle.Sequence {
			return ErrPolicyConflict
		}
	}
	return nil
}

func validateProposedPolicyTransition(bundle foundationv1.PolicyBundleSigningProjection, scopes []string, registry PolicyRegistrySnapshot) error {
	if !registry.HeadPresent {
		if (!bundle.Emergency && bundle.State == PolicyStateApprovedDelayed) ||
			(bundle.Emergency && bundle.State == PolicyStateActive) {
			return nil
		}
		return fmt.Errorf("%w: initial normal policy must be delayed; direct active requires break-glass", ErrPolicyConflict)
	}
	head := registry.Head
	switch bundle.State {
	case PolicyStateApprovedDelayed:
		if bundle.Emergency || (head.State != PolicyStateActive && head.State != PolicyStateRolledBack &&
			head.State != PolicyStateRevoked && head.State != PolicyStateExpired) {
			return ErrPolicyConflict
		}
		return nil
	case PolicyStateActive:
		if bundle.Emergency {
			// Break-glass is the one explicit direct-active exception. It is a
			// new, short-lived revision and need not reuse the prior document,
			// but it cannot splice around an already delayed transition.
			if head.State == PolicyStateApprovedDelayed {
				return ErrPolicyConflict
			}
			return nil
		}
		if head.State != PolicyStateApprovedDelayed || !policyRecordMatchesBundle(head, bundle, scopes) {
			return ErrPolicyConflict
		}
		return nil
	case PolicyStateRolledBack:
		if head.State != PolicyStateActive || !policyRecordMatchesBundle(head, bundle, scopes) {
			return ErrPolicyConflict
		}
		return nil
	case PolicyStateRevoked, PolicyStateExpired:
		if (head.State != PolicyStateApprovedDelayed && head.State != PolicyStateActive) ||
			!policyRecordMatchesBundle(head, bundle, scopes) {
			return ErrPolicyConflict
		}
		return nil
	default:
		return ErrPolicyConflict
	}
}

func policyRecordMatchesBundle(record PolicyRecordSnapshot, bundle foundationv1.PolicyBundleSigningProjection, scopes []string) bool {
	breakGlassExpiry := int64(0)
	if bundle.BreakGlassExpiresAtUnixNano.Present {
		breakGlassExpiry = bundle.BreakGlassExpiresAtUnixNano.Value
	}
	return record.PolicyBundleID == bundle.PolicyBundleID && record.PolicyKind == bundle.PolicyKind &&
		record.PolicyVersion == (ccse.Version{Major: bundle.PolicyVersion.Major, Minor: bundle.PolicyVersion.Minor}) &&
		record.ApprovedAtUnixNano == bundle.ApprovedAtUnixNano && record.EffectiveAtUnixNano == bundle.EffectiveAtUnixNano &&
		record.ExpiresAtUnixNano == bundle.ExpiresAtUnixNano && record.PolicyDocumentDigestSHA256 == bundle.PolicyDocumentDigestSHA256 &&
		record.PolicyDocumentMediaType == bundle.PolicyDocumentMediaType &&
		equalStringSets(record.ApproverIdentities, bundle.ApproverIdentities) && equalStringSets(record.ApproverKeyIDs, bundle.ApproverKeyIDs) &&
		record.MinimumApprovals == bundle.MinimumApprovals && record.Emergency == bundle.Emergency &&
		record.BreakGlassExpiresAtUnixNano == breakGlassExpiry &&
		equalStringSetsAllowEmpty(record.BreakGlassScopes, scopes)
}

func validateRollbackTarget(bundle foundationv1.PolicyBundleSigningProjection, bundleDigest [ccse.DigestSize]byte, registry PolicyRegistrySnapshot, at int64) (int64, error) {
	target := bundle.RollbackTargetDigestSHA256.Value
	if target == bundleDigest || isZeroDigest(target) {
		return 0, ErrRollbackTarget
	}
	var selected *PolicyRecordSnapshot
	for index := range registry.Records {
		record := registry.Records[index]
		if record.BundleDigestSHA256 == target {
			if record.PolicyKind != bundle.PolicyKind || record.Sequence >= bundle.Sequence || record.State != PolicyStateActive || record.Emergency ||
				record.ExpiresAtUnixNano <= at {
				return 0, ErrRollbackTarget
			}
			copyRecord := record
			selected = &copyRecord
		}
	}
	if selected == nil {
		return 0, ErrRollbackTarget
	}
	for _, record := range registry.Records {
		if record.Sequence > selected.Sequence && record.PolicyBundleID == selected.PolicyBundleID &&
			(record.State == PolicyStateRolledBack || record.State == PolicyStateRevoked || record.State == PolicyStateExpired) {
			return 0, ErrRollbackTarget
		}
	}
	return selected.ExpiresAtUnixNano, nil
}

func (p *Planner) validatePolicyRegistrySnapshot(ctx context.Context, policyKind string, snapshot PolicyRegistrySnapshot) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if snapshot.AuthorizedHomeRegion != p.profile.PolicyHomeRegion || snapshot.AuthorizedWriterEpoch == 0 ||
		snapshot.GovernanceProfileDigestSHA256 != p.profileDigest ||
		isZeroDigest(snapshot.WriterLeaseEvidenceDigestSHA256) || snapshot.WriterLeaseNotBeforeUnixNano < 0 ||
		snapshot.WriterLeaseNotAfterUnixNano <= snapshot.WriterLeaseNotBeforeUnixNano {
		return ErrSnapshotInconsistent
	}
	if !snapshot.HeadPresent {
		if !isZeroPolicyRecord(snapshot.Head) || len(snapshot.Records) != 0 {
			return ErrSnapshotInconsistent
		}
		return nil
	}
	if snapshot.Head.PolicyKind != policyKind || snapshot.Head.Sequence == 0 || snapshot.Head.Sequence > 4096 ||
		uint64(len(snapshot.Records)) != snapshot.Head.Sequence {
		return ErrSnapshotInconsistent
	}
	seenDigests := make(map[[ccse.DigestSize]byte]PolicyRecordSnapshot, len(snapshot.Records))
	bySequence := make(map[uint64]PolicyRecordSnapshot, len(snapshot.Records))
	seenRecordIDs := make(map[string]struct{}, len(snapshot.Records))
	for _, record := range snapshot.Records {
		acceptance := record.AcceptanceEvidence
		if acceptance.HomeRegion != record.HomeRegion || acceptance.WriterEpoch != record.WriterEpoch ||
			acceptance.GovernanceProfileDigestSHA256 != record.GovernanceProfileDigestSHA256 ||
			acceptance.GovernanceProfileActivation.GovernanceProfileDigestSHA256 != record.GovernanceProfileDigestSHA256 ||
			!validGovernanceProfileActivation(acceptance.GovernanceProfileActivation, acceptance.AcceptedAtUnixNano) ||
			isZeroDigest(acceptance.WriterLeaseEvidenceDigestSHA256) ||
			acceptance.WriterLeaseNotBeforeUnixNano < 0 ||
			acceptance.WriterLeaseNotAfterUnixNano <= acceptance.WriterLeaseNotBeforeUnixNano ||
			acceptance.AcceptedAtUnixNano < acceptance.WriterLeaseNotBeforeUnixNano ||
			acceptance.AcceptedAtUnixNano >= acceptance.WriterLeaseNotAfterUnixNano ||
			acceptance.AcceptedAtUnixNano < record.ApprovedAtUnixNano ||
			!validHistoricalAcceptanceTime(record, acceptance.AcceptedAtUnixNano) ||
			isZeroDigest(acceptance.MutationPlanDigestSHA256) || isZeroDigest(acceptance.DurableResultDigestSHA256) {
			return ErrSnapshotInconsistent
		}
		historicalProfile, profileErr := p.resolveHistoricalProfileActivation(ctx, acceptance.GovernanceProfileActivation, acceptance.AcceptedAtUnixNano)
		if profileErr != nil {
			return profileErr
		}
		decoded, decodeErr := p.canonical.Decode(schema.MessageTypePolicyBundle, historicalProfile.SchemaVersion, record.CanonicalPayload)
		projection, projectionOK := decoded.(foundationv1.PolicyBundleSigningProjection)
		if decodeErr != nil || !projectionOK || sha256.Sum256(record.CanonicalPayload) != record.BundleDigestSHA256 ||
			!policyRecordMatchesProjection(record, projection) ||
			!containsDigest(projection.Metadata.PolicyDigestsSHA256, record.GovernanceProfileDigestSHA256) {
			return ErrSnapshotInconsistent
		}
		if err := p.validateHistoricalPolicyApprovals(ctx, record, projection, historicalProfile); err != nil {
			return err
		}
		recordOwner := globalid.Owner{Domain: globalid.OwnerCanonicalRecord, ID: hex.EncodeToString(record.BundleDigestSHA256[:])}
		recordIDSnapshot, recordIDExists, lookupErr := p.ids.LookupGlobalID(ctx, record.RecordID)
		if lookupErr != nil {
			return fmt.Errorf("aiinfra governance: lookup historical policy record ID: %w", lookupErr)
		}
		if !recordIDExists {
			return ErrSnapshotInconsistent
		}
		if _, assertErr := globalid.Assert(record.RecordID, recordIDSnapshot, recordOwner); assertErr != nil {
			return ErrSnapshotInconsistent
		}
		bundleOwnerDigest := policyBundleOwnerDigest(record.PolicyKind, record.PolicyBundleID)
		bundleOwner := globalid.Owner{Domain: globalid.OwnerGovernancePolicyBundle, ID: hex.EncodeToString(bundleOwnerDigest[:])}
		bundleIDSnapshot, bundleIDExists, lookupErr := p.ids.LookupGlobalID(ctx, record.PolicyBundleID)
		if lookupErr != nil {
			return fmt.Errorf("aiinfra governance: lookup historical policy bundle ID: %w", lookupErr)
		}
		if !bundleIDExists {
			return ErrSnapshotInconsistent
		}
		if _, assertErr := globalid.Assert(record.PolicyBundleID, bundleIDSnapshot, bundleOwner); assertErr != nil {
			return ErrSnapshotInconsistent
		}
		document, resolveErr := p.documents.ResolvePolicyDocument(ctx, record.PolicyDocumentDigestSHA256)
		if resolveErr != nil || !preflightPolicyDocumentSnapshot(document) {
			return ErrSnapshotInconsistent
		}
		document = clonePolicyDocumentSnapshot(document)
		if validatePolicyDocument(document, record.PolicyDocumentDigestSHA256, record.PolicyDocumentMediaType) != nil {
			return ErrSnapshotInconsistent
		}
		if record.Emergency {
			derivedScopes, decodeErr := decodeBreakGlassDocument(document, record.PolicyDocumentDigestSHA256, record.PolicyDocumentMediaType, record.PolicyKind)
			validatedScopes, scopeErr := validateBreakGlassScopes(derivedScopes, historicalProfile.AllowedBreakGlassScopes)
			if decodeErr != nil || scopeErr != nil || !equalStringSets(validatedScopes, record.BreakGlassScopes) {
				return ErrSnapshotInconsistent
			}
		}
		if record.RecordID == "" || record.RecordID == record.PolicyBundleID || record.PolicyBundleID == "" ||
			record.HomeRegion == "" || record.WriterEpoch == 0 || record.WriterEpoch > snapshot.AuthorizedWriterEpoch ||
			record.StateVersion != record.Sequence ||
			record.PolicyKind != policyKind || record.PolicyVersion.Major == 0 || record.Sequence == 0 ||
			record.Sequence > uint64(historicalProfile.MaxPolicyRecords) || isZeroDigest(record.GovernanceProfileDigestSHA256) ||
			isZeroDigest(record.BundleDigestSHA256) || isZeroDigest(record.PolicyDocumentDigestSHA256) || record.PolicyDocumentMediaType == "" ||
			record.EffectiveAtUnixNano < 0 || record.ExpiresAtUnixNano <= record.EffectiveAtUnixNano ||
			record.ApprovedAtUnixNano < 0 || record.EffectiveAtUnixNano < record.ApprovedAtUnixNano ||
			(!record.Emergency && record.EffectiveAtUnixNano-record.ApprovedAtUnixNano < historicalProfile.MinActivationDelayNanos) ||
			!validPolicyCreatedAtForState(record.State, projection.Metadata.CreatedAtUnixNano, record.ApprovedAtUnixNano, record.EffectiveAtUnixNano, record.ExpiresAtUnixNano) ||
			len(record.ApproverIdentities) == 0 || len(record.ApproverIdentities) != len(record.ApproverKeyIDs) ||
			record.MinimumApprovals == 0 || int(record.MinimumApprovals) > len(record.ApproverIdentities) ||
			hasDuplicateStrings(record.ApproverIdentities) || hasDuplicateStrings(record.ApproverKeyIDs) ||
			record.State < PolicyStateApprovedDelayed || record.State > 6 || hasDuplicateStrings(record.BreakGlassScopes) || containsEmpty(record.BreakGlassScopes) ||
			record.Emergency != (len(record.BreakGlassScopes) != 0) ||
			(record.Emergency && (record.BreakGlassExpiresAtUnixNano <= record.EffectiveAtUnixNano ||
				record.BreakGlassExpiresAtUnixNano != record.ExpiresAtUnixNano ||
				record.BreakGlassExpiresAtUnixNano-record.EffectiveAtUnixNano > historicalProfile.MaxBreakGlassDurationNanos)) ||
			(!record.Emergency && record.BreakGlassExpiresAtUnixNano != 0) ||
			record.RollbackTargetPresent != (record.State == PolicyStateRolledBack) ||
			(!record.PredecessorPresent && !isZeroDigest(record.PredecessorDigestSHA256)) ||
			(!record.RollbackTargetPresent && !isZeroDigest(record.RollbackTargetDigestSHA256)) {
			return ErrSnapshotInconsistent
		}
		if _, exists := seenDigests[record.BundleDigestSHA256]; exists {
			return ErrSnapshotInconsistent
		}
		seenDigests[record.BundleDigestSHA256] = record
		if _, exists := seenRecordIDs[record.RecordID]; exists {
			return ErrSnapshotInconsistent
		}
		seenRecordIDs[record.RecordID] = struct{}{}
		if _, exists := bySequence[record.Sequence]; exists {
			return ErrSnapshotInconsistent
		}
		bySequence[record.Sequence] = record
	}
	var priorDigest [ccse.DigestSize]byte
	acceptedDigests := make(map[[ccse.DigestSize]byte]PolicyRecordSnapshot, len(snapshot.Records))
	seenBundleIDs := make(map[string]struct{}, len(snapshot.Records))
	history := make([]PolicyRecordSnapshot, 0, len(snapshot.Records))
	var previous *PolicyRecordSnapshot
	var priorWriterEpoch uint64
	var priorHomeRegion string
	for sequence := uint64(1); sequence <= snapshot.Head.Sequence; sequence++ {
		record, exists := bySequence[sequence]
		if !exists {
			return ErrSnapshotInconsistent
		}
		if sequence == 1 {
			if record.PredecessorPresent || !isZeroDigest(record.PredecessorDigestSHA256) {
				return ErrSnapshotInconsistent
			}
		} else if !record.PredecessorPresent || record.PredecessorDigestSHA256 != priorDigest {
			return ErrSnapshotInconsistent
		}
		if record.WriterEpoch < priorWriterEpoch || (record.WriterEpoch == priorWriterEpoch && priorHomeRegion != "" && record.HomeRegion != priorHomeRegion) {
			return ErrSnapshotInconsistent
		}
		if record.RollbackTargetPresent {
			target, exists := acceptedDigests[record.RollbackTargetDigestSHA256]
			if !exists || target.State != PolicyStateActive || target.Emergency ||
				target.ExpiresAtUnixNano <= record.AcceptanceEvidence.AcceptedAtUnixNano {
				return ErrSnapshotInconsistent
			}
			for _, prior := range history {
				if prior.Sequence > target.Sequence && prior.PolicyBundleID == target.PolicyBundleID &&
					(prior.State == PolicyStateRolledBack || prior.State == PolicyStateRevoked || prior.State == PolicyStateExpired) {
					return ErrSnapshotInconsistent
				}
			}
		}
		if !validHistoricalPolicyTransition(previous, record) {
			return ErrSnapshotInconsistent
		}
		startsLifecycle := previous == nil || record.State == PolicyStateApprovedDelayed ||
			(record.State == PolicyStateActive && record.Emergency)
		if startsLifecycle {
			if _, reused := seenBundleIDs[record.PolicyBundleID]; reused {
				return ErrSnapshotInconsistent
			}
			seenBundleIDs[record.PolicyBundleID] = struct{}{}
		}
		acceptedDigests[record.BundleDigestSHA256] = record
		history = append(history, record)
		priorDigest = record.BundleDigestSHA256
		priorWriterEpoch = record.WriterEpoch
		priorHomeRegion = record.HomeRegion
		current := record
		previous = &current
	}
	if !equalPolicyRecords(snapshot.Head, bySequence[snapshot.Head.Sequence]) || snapshot.Head.WriterEpoch > snapshot.AuthorizedWriterEpoch ||
		(snapshot.Head.WriterEpoch == snapshot.AuthorizedWriterEpoch && snapshot.Head.HomeRegion != snapshot.AuthorizedHomeRegion) {
		return ErrSnapshotInconsistent
	}
	return nil
}

func validHistoricalAcceptanceTime(record PolicyRecordSnapshot, acceptedAt int64) bool {
	switch record.State {
	case PolicyStateApprovedDelayed:
		return acceptedAt < record.EffectiveAtUnixNano && acceptedAt < record.ExpiresAtUnixNano
	case PolicyStateActive, PolicyStateRolledBack:
		if acceptedAt < record.EffectiveAtUnixNano || acceptedAt >= record.ExpiresAtUnixNano {
			return false
		}
		return !record.Emergency || acceptedAt < record.BreakGlassExpiresAtUnixNano
	case PolicyStateRevoked:
		return acceptedAt >= record.ApprovedAtUnixNano && acceptedAt < record.ExpiresAtUnixNano
	case PolicyStateExpired:
		return acceptedAt >= record.ExpiresAtUnixNano
	default:
		return false
	}
}

func (p *Planner) validatePolicyWriterFence(ctx context.Context, snapshot PolicyRegistrySnapshot, at int64) (GovernanceProfileActivationSnapshot, error) {
	if snapshot.AuthorizedHomeRegion != p.profile.PolicyHomeRegion || snapshot.AuthorizedWriterEpoch == 0 ||
		snapshot.GovernanceProfileDigestSHA256 != p.profileDigest ||
		isZeroDigest(snapshot.WriterLeaseEvidenceDigestSHA256) || snapshot.WriterLeaseNotBeforeUnixNano < 0 ||
		snapshot.WriterLeaseNotAfterUnixNano <= snapshot.WriterLeaseNotBeforeUnixNano ||
		at < snapshot.WriterLeaseNotBeforeUnixNano || at >= snapshot.WriterLeaseNotAfterUnixNano {
		return GovernanceProfileActivationSnapshot{}, ErrPolicyConflict
	}
	activation, active, err := p.profiles.ActiveGovernanceProfile(ctx, at)
	if err != nil {
		return GovernanceProfileActivationSnapshot{}, fmt.Errorf("aiinfra governance: resolve active profile: %w", err)
	}
	if !active || !validGovernanceProfileActivation(activation, at) || activation.GovernanceProfileDigestSHA256 != p.profileDigest {
		return GovernanceProfileActivationSnapshot{}, ErrPolicyConflict
	}
	return activation, nil
}

func isZeroPolicyRecord(record PolicyRecordSnapshot) bool {
	return isZeroDigest(record.BundleDigestSHA256) && len(record.CanonicalPayload) == 0 && record.RecordID == "" && record.HomeRegion == "" && record.WriterEpoch == 0 &&
		isZeroDigest(record.GovernanceProfileDigestSHA256) &&
		record.StateVersion == 0 && record.PolicyBundleID == "" && record.PolicyKind == "" &&
		record.PolicyVersion == (ccse.Version{}) && record.Sequence == 0 &&
		!record.PredecessorPresent && isZeroDigest(record.PredecessorDigestSHA256) &&
		!record.RollbackTargetPresent && isZeroDigest(record.RollbackTargetDigestSHA256) && record.State == 0 &&
		record.ApprovedAtUnixNano == 0 && record.EffectiveAtUnixNano == 0 && record.ExpiresAtUnixNano == 0 &&
		isZeroDigest(record.PolicyDocumentDigestSHA256) && record.PolicyDocumentMediaType == "" &&
		len(record.ApproverIdentities) == 0 && len(record.ApproverKeyIDs) == 0 && record.MinimumApprovals == 0 &&
		!record.Emergency && record.BreakGlassExpiresAtUnixNano == 0 && len(record.BreakGlassScopes) == 0 &&
		len(record.ApprovalEvidence) == 0 && record.AcceptanceEvidence == (PolicyAcceptanceEvidenceSnapshot{})
}

func equalPolicyRecords(left, right PolicyRecordSnapshot) bool {
	return left.BundleDigestSHA256 == right.BundleDigestSHA256 && bytes.Equal(left.CanonicalPayload, right.CanonicalPayload) &&
		left.GovernanceProfileDigestSHA256 == right.GovernanceProfileDigestSHA256 &&
		left.RecordID == right.RecordID && left.HomeRegion == right.HomeRegion &&
		left.WriterEpoch == right.WriterEpoch && left.StateVersion == right.StateVersion && left.PolicyBundleID == right.PolicyBundleID &&
		left.PolicyKind == right.PolicyKind && left.PolicyVersion == right.PolicyVersion && left.Sequence == right.Sequence &&
		left.PredecessorPresent == right.PredecessorPresent && left.PredecessorDigestSHA256 == right.PredecessorDigestSHA256 &&
		left.RollbackTargetPresent == right.RollbackTargetPresent && left.RollbackTargetDigestSHA256 == right.RollbackTargetDigestSHA256 &&
		left.State == right.State && left.ApprovedAtUnixNano == right.ApprovedAtUnixNano &&
		left.EffectiveAtUnixNano == right.EffectiveAtUnixNano && left.ExpiresAtUnixNano == right.ExpiresAtUnixNano &&
		left.PolicyDocumentDigestSHA256 == right.PolicyDocumentDigestSHA256 && left.PolicyDocumentMediaType == right.PolicyDocumentMediaType &&
		equalStringSets(left.ApproverIdentities, right.ApproverIdentities) && equalStringSets(left.ApproverKeyIDs, right.ApproverKeyIDs) &&
		left.MinimumApprovals == right.MinimumApprovals && left.Emergency == right.Emergency &&
		left.BreakGlassExpiresAtUnixNano == right.BreakGlassExpiresAtUnixNano && equalStringSetsAllowEmpty(left.BreakGlassScopes, right.BreakGlassScopes) &&
		historicalApprovalEvidenceEqual(left.ApprovalEvidence, right.ApprovalEvidence) && left.AcceptanceEvidence == right.AcceptanceEvidence
}

func validHistoricalPolicyTransition(previous *PolicyRecordSnapshot, current PolicyRecordSnapshot) bool {
	if previous == nil {
		return (!current.Emergency && current.State == PolicyStateApprovedDelayed) ||
			(current.Emergency && current.State == PolicyStateActive)
	}
	switch current.State {
	case PolicyStateApprovedDelayed:
		return !current.Emergency && (previous.State == PolicyStateActive || previous.State == PolicyStateRolledBack ||
			previous.State == PolicyStateRevoked || previous.State == PolicyStateExpired)
	case PolicyStateActive:
		if current.Emergency {
			return previous.State != PolicyStateApprovedDelayed
		}
		return previous.State == PolicyStateApprovedDelayed && policyRecordInvariantsEqual(*previous, current)
	case PolicyStateRolledBack:
		return previous.State == PolicyStateActive && policyRecordInvariantsEqual(*previous, current)
	case PolicyStateRevoked, PolicyStateExpired:
		return (previous.State == PolicyStateApprovedDelayed || previous.State == PolicyStateActive) &&
			policyRecordInvariantsEqual(*previous, current)
	default:
		return false
	}
}

func policyRecordInvariantsEqual(left, right PolicyRecordSnapshot) bool {
	return left.PolicyBundleID == right.PolicyBundleID && left.PolicyKind == right.PolicyKind && left.PolicyVersion == right.PolicyVersion &&
		left.ApprovedAtUnixNano == right.ApprovedAtUnixNano && left.EffectiveAtUnixNano == right.EffectiveAtUnixNano &&
		left.ExpiresAtUnixNano == right.ExpiresAtUnixNano && left.PolicyDocumentDigestSHA256 == right.PolicyDocumentDigestSHA256 &&
		left.PolicyDocumentMediaType == right.PolicyDocumentMediaType && equalStringSets(left.ApproverIdentities, right.ApproverIdentities) &&
		equalStringSets(left.ApproverKeyIDs, right.ApproverKeyIDs) && left.MinimumApprovals == right.MinimumApprovals &&
		left.Emergency == right.Emergency && left.BreakGlassExpiresAtUnixNano == right.BreakGlassExpiresAtUnixNano &&
		equalStringSetsAllowEmpty(left.BreakGlassScopes, right.BreakGlassScopes)
}

func policyRecordMatchesProjection(record PolicyRecordSnapshot, bundle foundationv1.PolicyBundleSigningProjection) bool {
	breakGlassExpiry := int64(0)
	if bundle.BreakGlassExpiresAtUnixNano.Present {
		breakGlassExpiry = bundle.BreakGlassExpiresAtUnixNano.Value
	}
	return record.RecordID == bundle.Metadata.RecordID && record.HomeRegion == bundle.Metadata.HomeRegion &&
		record.WriterEpoch == bundle.Metadata.WriterEpoch && record.StateVersion == bundle.Metadata.StateVersion &&
		record.PolicyBundleID == bundle.PolicyBundleID && record.PolicyKind == bundle.PolicyKind &&
		record.PolicyVersion == (ccse.Version{Major: bundle.PolicyVersion.Major, Minor: bundle.PolicyVersion.Minor}) &&
		record.Sequence == bundle.Sequence && record.PredecessorPresent == bundle.PredecessorDigestSHA256.Present &&
		record.PredecessorDigestSHA256 == bundle.PredecessorDigestSHA256.Value &&
		record.RollbackTargetPresent == bundle.RollbackTargetDigestSHA256.Present &&
		record.RollbackTargetDigestSHA256 == bundle.RollbackTargetDigestSHA256.Value && record.State == bundle.State &&
		record.ApprovedAtUnixNano == bundle.ApprovedAtUnixNano && record.EffectiveAtUnixNano == bundle.EffectiveAtUnixNano &&
		record.ExpiresAtUnixNano == bundle.ExpiresAtUnixNano && record.PolicyDocumentDigestSHA256 == bundle.PolicyDocumentDigestSHA256 &&
		record.PolicyDocumentMediaType == bundle.PolicyDocumentMediaType && equalStringSets(record.ApproverIdentities, bundle.ApproverIdentities) &&
		equalStringSets(record.ApproverKeyIDs, bundle.ApproverKeyIDs) && record.MinimumApprovals == bundle.MinimumApprovals &&
		record.Emergency == bundle.Emergency && record.BreakGlassExpiresAtUnixNano == breakGlassExpiry
}

func validPolicyCreatedAtForState(state uint32, createdAt, approvedAt, effectiveAt, expiresAt int64) bool {
	if createdAt < approvedAt {
		return false
	}
	switch state {
	case PolicyStateApprovedDelayed:
		return createdAt < effectiveAt
	case PolicyStateActive, PolicyStateRolledBack:
		return createdAt >= effectiveAt && createdAt < expiresAt
	case PolicyStateRevoked:
		return createdAt < expiresAt
	case PolicyStateExpired:
		return createdAt >= expiresAt
	default:
		return false
	}
}

func equalStringSetsAllowEmpty(left, right []string) bool {
	if len(left) == 0 && len(right) == 0 {
		return true
	}
	return equalStringSets(left, right)
}

func validateBreakGlassScopes(scopes, allowed []string) ([]string, error) {
	if len(scopes) == 0 || hasDuplicateStrings(scopes) || containsEmpty(scopes) {
		return nil, ErrBreakGlassScope
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, scope := range allowed {
		allowedSet[scope] = struct{}{}
	}
	result := append([]string(nil), scopes...)
	for _, scope := range result {
		if _, ok := allowedSet[scope]; !ok {
			return nil, fmt.Errorf("%w: %q", ErrBreakGlassScope, scope)
		}
	}
	sort.Strings(result)
	return result, nil
}

func rolesHaveDistinctAssignment(keys []GovernanceKeySnapshot, requiredRoles []string) bool {
	if len(requiredRoles) == 0 {
		return true
	}
	roles := append([]string(nil), requiredRoles...)
	sort.Strings(roles)
	keyOrder := make([]int, len(keys))
	for index := range keyOrder {
		keyOrder[index] = index
	}
	sort.Slice(keyOrder, func(i, j int) bool { return keys[keyOrder[i]].SubjectIdentity < keys[keyOrder[j]].SubjectIdentity })
	assigned := make([]int, len(keys))
	for index := range assigned {
		assigned[index] = -1
	}
	var match func(int, []bool) bool
	match = func(roleIndex int, visited []bool) bool {
		for _, keyIndex := range keyOrder {
			if visited[keyIndex] || !containsString(keys[keyIndex].Roles, roles[roleIndex]) {
				continue
			}
			visited[keyIndex] = true
			if assigned[keyIndex] == -1 || match(assigned[keyIndex], visited) {
				assigned[keyIndex] = roleIndex
				return true
			}
		}
		return false
	}
	for roleIndex := range roles {
		if !match(roleIndex, make([]bool, len(keys))) {
			return false
		}
	}
	return true
}

func containsMessageType(values []uint32, target uint32) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsDigest(values [][ccse.DigestSize]byte, target [ccse.DigestSize]byte) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsEmpty(values []string) bool {
	return containsString(values, "")
}

func distinctStringCount(values []string) int {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	return len(seen)
}

func hasDuplicateStrings(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func hasDuplicateDigests(values [][ccse.DigestSize]byte) bool {
	seen := make(map[[ccse.DigestSize]byte]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func equalStringSets(left, right []string) bool {
	if len(left) != len(right) || hasDuplicateStrings(left) || hasDuplicateStrings(right) {
		return false
	}
	l := append([]string(nil), left...)
	r := append([]string(nil), right...)
	sort.Strings(l)
	sort.Strings(r)
	for index := range l {
		if l[index] != r[index] {
			return false
		}
	}
	return true
}

func sortDigests(values [][ccse.DigestSize]byte) {
	sort.Slice(values, func(i, j int) bool { return bytes.Compare(values[i][:], values[j][:]) < 0 })
}

func uniqueSortedDigests(values [][ccse.DigestSize]byte) [][ccse.DigestSize]byte {
	copyValues := append([][ccse.DigestSize]byte(nil), values...)
	sortDigests(copyValues)
	result := copyValues[:0]
	for _, value := range copyValues {
		if isZeroDigest(value) || (len(result) > 0 && result[len(result)-1] == value) {
			continue
		}
		result = append(result, value)
	}
	return append([][ccse.DigestSize]byte(nil), result...)
}

func uniqueSortedStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	out := result[:0]
	for _, value := range result {
		if value == "" || (len(out) > 0 && out[len(out)-1] == value) {
			continue
		}
		out = append(out, value)
	}
	return append([]string(nil), out...)
}

func isZeroDigest(value [ccse.DigestSize]byte) bool { return value == [ccse.DigestSize]byte{} }

func minimumInt64(left, right int64) int64 {
	if right < left {
		return right
	}
	return left
}

func maximumInt64(left, right int64) int64 {
	if right > left {
		return right
	}
	return left
}

func subtractFloorZero(value, delta int64) int64 {
	if delta >= value {
		return 0
	}
	return value - delta
}

func addPositiveNanos(value, delta int64) (int64, bool) {
	if value < 0 || delta <= 0 || value > math.MaxInt64-delta {
		return 0, false
	}
	return value + delta, true
}

func actionNotBefore(action MutationKind, bundle foundationv1.PolicyBundleSigningProjection) int64 {
	switch action {
	case MutationPolicyPublish:
		return bundle.ApprovedAtUnixNano
	case MutationPolicyActivate, MutationPolicyRollback:
		return bundle.EffectiveAtUnixNano
	case MutationPolicyRevoke:
		return bundle.ApprovedAtUnixNano
	case MutationPolicyExpire:
		return bundle.ExpiresAtUnixNano
	default:
		return math.MaxInt64
	}
}

func policyBundleOwnerDigest(policyKind, bundleID string) [ccse.DigestSize]byte {
	preimage := make([]byte, 0, len(policyKind)+len(bundleID)+48)
	preimage = append(preimage, "CPH-AIIE-POLICY-BUNDLE-OWNER-V1\x00"...)
	preimage = append(preimage, policyKind...)
	preimage = append(preimage, 0)
	preimage = append(preimage, bundleID...)
	return sha256.Sum256(preimage)
}

func contextErr(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidCommand
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func clonePolicyRegistrySnapshot(snapshot PolicyRegistrySnapshot) PolicyRegistrySnapshot {
	snapshot.Head.CanonicalPayload = append([]byte(nil), snapshot.Head.CanonicalPayload...)
	snapshot.Head.ApproverIdentities = append([]string(nil), snapshot.Head.ApproverIdentities...)
	snapshot.Head.ApproverKeyIDs = append([]string(nil), snapshot.Head.ApproverKeyIDs...)
	snapshot.Head.BreakGlassScopes = append([]string(nil), snapshot.Head.BreakGlassScopes...)
	snapshot.Head.ApprovalEvidence = cloneHistoricalPolicyApprovalEvidence(snapshot.Head.ApprovalEvidence)
	snapshot.Records = append([]PolicyRecordSnapshot(nil), snapshot.Records...)
	for index := range snapshot.Records {
		snapshot.Records[index].CanonicalPayload = append([]byte(nil), snapshot.Records[index].CanonicalPayload...)
		snapshot.Records[index].ApproverIdentities = append([]string(nil), snapshot.Records[index].ApproverIdentities...)
		snapshot.Records[index].ApproverKeyIDs = append([]string(nil), snapshot.Records[index].ApproverKeyIDs...)
		snapshot.Records[index].BreakGlassScopes = append([]string(nil), snapshot.Records[index].BreakGlassScopes...)
		snapshot.Records[index].ApprovalEvidence = cloneHistoricalPolicyApprovalEvidence(snapshot.Records[index].ApprovalEvidence)
	}
	return snapshot
}

func cloneHistoricalPolicyApprovalEvidence(input []HistoricalPolicyApprovalEvidence) []HistoricalPolicyApprovalEvidence {
	result := make([]HistoricalPolicyApprovalEvidence, 0, len(input))
	for _, evidence := range input {
		copyRecord := cloneCCSERecord(evidence.Signed.Record)
		result = append(result, HistoricalPolicyApprovalEvidence{
			Signed: SignedRecord{Record: &copyRecord, Verified: evidence.Signed.Verified},
			Key:    cloneKeySnapshot(evidence.Key), GovernanceProfileActivation: evidence.GovernanceProfileActivation,
		})
	}
	return result
}

func clonePolicyDocumentSnapshot(snapshot PolicyDocumentSnapshot) PolicyDocumentSnapshot {
	snapshot.CanonicalDocument = append([]byte(nil), snapshot.CanonicalDocument...)
	return snapshot
}

func cloneKeySnapshot(snapshot GovernanceKeySnapshot) GovernanceKeySnapshot {
	snapshot.PublicKey = append([]byte(nil), snapshot.PublicKey...)
	snapshot.AllowedMessageTypeIDs = append([]uint32(nil), snapshot.AllowedMessageTypeIDs...)
	snapshot.Roles = append([]string(nil), snapshot.Roles...)
	return snapshot
}

func keyPrecondition(snapshot GovernanceKeySnapshot) KeyStatePrecondition {
	return KeyStatePrecondition{
		KeyID: snapshot.KeyID, StateVersion: snapshot.StateVersion, WriterEpoch: snapshot.WriterEpoch,
		SnapshotDigestSHA256: snapshot.SnapshotDigestSHA256,
		IdentityStateVersion: snapshot.IdentityStateVersion, IdentityWriterEpoch: snapshot.IdentityWriterEpoch,
		IdentitySnapshotDigestSHA256:      snapshot.IdentitySnapshotDigestSHA256,
		AuthorizationSnapshotDigestSHA256: digestGovernanceAuthorizationSnapshot(snapshot),
	}
}

func validKeyStatePrecondition(value KeyStatePrecondition) bool {
	return value.KeyID != "" && value.StateVersion != 0 && value.WriterEpoch != 0 &&
		!isZeroDigest(value.SnapshotDigestSHA256) && value.IdentityStateVersion != 0 &&
		value.IdentityWriterEpoch != 0 && !isZeroDigest(value.IdentitySnapshotDigestSHA256) &&
		!isZeroDigest(value.AuthorizationSnapshotDigestSHA256)
}
