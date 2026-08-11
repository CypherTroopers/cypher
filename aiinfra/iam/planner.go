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
	mutationPlanDomain = "CPH-AIIE-IAM-MUTATION-PLAN-V1\x00"
	auditIntentDomain  = "CPH-AIIE-IAM-AUDIT-INTENT-V1\x00"
	pendingPlanDomain  = "CPH-AIIE-IAM-PENDING-PLAN-V1\x00"
)

// Planner holds detached, validated registry state and injected read-only
// authority boundaries. It is safe for concurrent use when View and Profile
// satisfy their own read-only concurrency contracts.
type Planner struct {
	view     View
	profile  Profile
	registry schema.Registry
}

// NewPlanner validates and deep-copies the registry through its canonical JSON
// representation, preventing later caller mutation from changing decisions.
func NewPlanner(view View, profile Profile, registry schema.Registry) (*Planner, error) {
	if view == nil {
		return nil, ErrViewRequired
	}
	if profile == nil {
		return nil, ErrProfileRequired
	}
	canonical, err := registry.CanonicalJSON()
	if err != nil {
		return nil, fmt.Errorf("aiinfra iam: registry: %w", err)
	}
	detached, err := schema.Parse(canonical)
	if err != nil {
		return nil, fmt.Errorf("aiinfra iam: registry copy: %w", err)
	}
	return &Planner{view: view, profile: profile, registry: detached}, nil
}

// NewDefaultPlanner uses the embedded, reviewed production registry.
func NewDefaultPlanner(view View, profile Profile) (*Planner, error) {
	registry, err := schema.LoadDefault()
	if err != nil {
		return nil, err
	}
	return NewPlanner(view, profile, registry)
}

// planKeyMaterial is an internal phase of compound key enrollment. Standalone
// unsigned material registration is intentionally not exported.
func (p *Planner) planKeyMaterial(ctx context.Context, command KeyMaterialCommand) (MutationPlan, AuditIntent, error) {
	if err := p.ready(); err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	if err := validateOperationFields(command.SubjectIdentity, command.CauseCode, command.CorrelationID, command.EvaluatedAtUnixNano); err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	receiver, err := p.profile.ReceiverProfile(ctx, schema.MessageTypeKeyLifecycle)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, fmt.Errorf("aiinfra iam: enrollment receiver profile: %w", err)
	}
	if err := validateReceiverProfile(receiver); err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	if command.EnrollmentDomain.EnrollmentDomainID != receiver.EnrollmentDomainID ||
		command.EnrollmentDomain.Environment != receiver.Environment ||
		command.EnrollmentDomain.GenesisHash != receiver.GenesisHash {
		return MutationPlan{}, AuditIntent{}, ErrKeyMaterialMismatch
	}
	canonical, err := CanonicalPublicKey(command.Algorithm, command.CanonicalPublicKey)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	derived, err := DeriveKeyID(command.Algorithm, canonical)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	if command.ClaimedKeyID == "" || command.ClaimedKeyID != derived {
		return MutationPlan{}, AuditIntent{}, ErrKeyIDMismatch
	}
	if command.SubjectKind < 1 || command.SubjectKind > 8 {
		return MutationPlan{}, AuditIntent{}, ErrInvalidInput
	}
	if err := validateTargetIdentity(command.TargetIdentity, command.SubjectKind); err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	requestDigest, err := keyMaterialRequestDigest(command, canonical, derived)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	idempotencyBinding := mutationIdempotencyBinding(command.IdempotencyKey,
		idempotency.OperationIAMKeyEnrollment, derived, requestDigest)
	joinedAuditBinding, err := p.precheckPendingIdempotency(ctx, idempotencyBinding)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	auditEventID, err := idempotency.JoinedAuditEventID(idempotencyBinding)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, ErrPendingPlanInvalid
	}
	challenge := command.Challenge
	challengeState, found, err := p.view.LookupProofChallenge(ctx, challenge)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, fmt.Errorf("aiinfra iam: lookup proof challenge: %w", err)
	}
	if !found {
		return MutationPlan{}, AuditIntent{}, ErrProofChallengeUnknown
	}
	if err := validateChallenge(command, challengeState); err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	enrollmentPolicies, err := canonicalDigests(command.EnrollmentPolicyDigestsSHA256)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	proofDigest, err := VerifyProofOfPossession(command.Algorithm, canonical, derived, command.SubjectIdentity,
		command.SubjectKind, command.TargetIdentity, command.TransferEvidenceDigest, command.EnrollmentDomain, challenge,
		command.ChallengeExpiresAtUnixNano, command.ProofSignature)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	if _, exists, err := p.view.LookupKeyMaterial(ctx, derived); err != nil {
		return MutationPlan{}, AuditIntent{}, fmt.Errorf("aiinfra iam: lookup key material: %w", err)
	} else if exists {
		// Exact repeats are handled by the outer atomic replay store. Re-entering
		// semantic planning with any existing ID is a global reuse attempt.
		return MutationPlan{}, AuditIntent{}, ErrKeyMaterialExists
	}
	entity := EntityRef{Kind: EntityKeyMaterial, PrincipalKind: command.SubjectKind, ID: derived}
	if command.Fence.ExpectedStateVersion != 0 {
		return MutationPlan{}, AuditIntent{}, ErrStateVersionConflict
	}
	leaseState, err := p.validateFence(ctx, entity, command.Fence, command.EvaluatedAtUnixNano, command.Fence.HomeRegion, command.Fence.WriterEpoch)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	identifierClaims, principalClaimMode, transferDependency, err := p.keyMaterialIdentifierClaims(ctx, entity,
		command.TargetIdentity, command.SubjectIdentity, command.TransferEvidenceDigest, command.EvaluatedAtUnixNano)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	enrollmentAuthority := EnrollmentAuthorityRequest{Entity: entity, TargetIdentity: command.TargetIdentity,
		TransferEvidenceDigest: command.TransferEvidenceDigest, ActorIdentity: command.Fence.WriterIdentity,
		SubjectIdentity: command.SubjectIdentity, SubjectKind: command.SubjectKind, Algorithm: command.Algorithm,
		EnrollmentDomain: command.EnrollmentDomain, Challenge: command.Challenge,
		ChallengeIssuerIdentity: command.EnrollmentAuthorityIdentity,
		ChallengeEvidenceDigest: command.EnrollmentAuthorityEvidenceDigest,
		PolicyDigestsSHA256:     cloneDigests(enrollmentPolicies), PrincipalClaimMode: principalClaimMode,
		EvaluatedAtUnixNano: command.EvaluatedAtUnixNano}
	if err := p.profile.ValidateEnrollmentAuthority(ctx, enrollmentAuthority); err != nil {
		return MutationPlan{}, AuditIntent{}, fmt.Errorf("aiinfra iam: enrollment authority: %w", err)
	}
	authority := AuthorityRequest{Mutation: MutationCreateKeyMaterial, Entity: entity,
		ActorIdentity: command.Fence.WriterIdentity, EvaluatedAtUnixNano: command.EvaluatedAtUnixNano,
		PolicyDigestsSHA256: cloneDigests(enrollmentPolicies)}
	if err := p.profile.ValidateAuthority(ctx, authority); err != nil {
		return MutationPlan{}, AuditIntent{}, fmt.Errorf("aiinfra iam: key material authority: %w", err)
	}
	material := KeyMaterialSnapshot{
		KeyID: derived, Algorithm: command.Algorithm, CanonicalPublicKey: canonical,
		SubjectIdentity: command.SubjectIdentity, SubjectKind: command.SubjectKind,
		TargetIdentity:         command.TargetIdentity,
		TransferEvidenceDigest: command.TransferEvidenceDigest,
		EnrollmentDomain:       command.EnrollmentDomain,
		ProofChallenge:         challenge, ProofExpiresAtUnixNano: command.ChallengeExpiresAtUnixNano,
		ProofSignature: append([]byte(nil), command.ProofSignature...), ProofDigest: proofDigest,
		ChallengeEvidenceDigest:       challengeState.EvidenceDigest,
		EnrollmentAuthorityIdentity:   command.EnrollmentAuthorityIdentity,
		EnrollmentPolicyDigestsSHA256: cloneDigests(enrollmentPolicies),
		WriterIdentity:                command.Fence.WriterIdentity, HomeRegion: command.Fence.HomeRegion,
		WriterEpoch: command.Fence.WriterEpoch, StateVersion: 1, IdempotencyKey: command.IdempotencyKey,
	}
	material.EnrollmentBindingDigest, err = enrollmentBindingDigest(material)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	cas := CASIntent{Entity: entity, ExpectedAbsent: true, ExpectedEntityWriterEpoch: 0,
		AuthorizedWriterEpoch: command.Fence.WriterEpoch,
		ConsumeChallenge:      true, Challenge: challenge, ChallengeEvidenceDigest: challengeState.EvidenceDigest,
		WriterEvidenceDigest: command.Fence.EvidenceDigest, IdentifierClaims: identifierClaims,
		TransferEvidenceDigest: command.TransferEvidenceDigest}
	if transferDependency.Entity.Kind != 0 {
		cas.Dependencies = []SnapshotPrecondition{transferDependency}
	}
	window, err := newPlanWindow(receiver, command.EvaluatedAtUnixNano,
		[]int64{leaseState.ValidFromUnixNano}, []int64{leaseState.ValidUntilUnixNano, challengeState.ExpiresAtUnixNano})
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	evidence := [][32]byte{command.Fence.EvidenceDigest, challengeState.EvidenceDigest, proofDigest}
	if command.TransferEvidenceDigest != ([32]byte{}) {
		evidence = append(evidence, command.TransferEvidenceDigest)
	}
	audit, err := newAuditIntent(auditEventID, "iam.key_material.registered", command.Fence.WriterIdentity,
		[]string{derived, command.SubjectIdentity, command.TargetIdentity.ID}, command.CauseCode, command.CorrelationID,
		ccse.OptionalMessageID{}, [16]byte{}, command.IdempotencyKey, joinedAuditBinding.Key,
		auditSourceEvidence{}, command.EvaluatedAtUnixNano, enrollmentPolicies,
		evidence)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	cas.IdempotencyClaims, err = pendingIdempotencyClaims(idempotencyBinding, joinedAuditBinding, audit.Digest())
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	plan, err := newMaterialPlan(cas, material, window)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	return plan, audit, nil
}

// PlanIdentity validates an append-only v1 identity state record and returns a
// mandatory-audit pending plan.
func (p *Planner) PlanIdentity(ctx context.Context, command IdentityCommand) (PendingMutationPlan, error) {
	if command.TransferEvidenceDigest == ([32]byte{}) {
		mutation, audit, err := p.planIdentity(ctx, command, false)
		if err != nil {
			return PendingMutationPlan{}, err
		}
		return newPendingMutationPlan(mutation, audit)
	}
	return PendingMutationPlan{}, ErrTransferAuthorizationRequired
}

func (p *Planner) planIdentity(ctx context.Context, command IdentityCommand,
	allowUnverifiedTransfer bool) (MutationPlan, AuditIntent, error) {
	if command.TransferEvidenceDigest != ([32]byte{}) && !allowUnverifiedTransfer {
		return MutationPlan{}, AuditIntent{}, ErrTransferAuthorizationRequired
	}
	if err := p.ready(); err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	next, err := NormalizeIdentity(command.Projection)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	if command.ActorIdentity == "" || command.ActorIdentity != command.Fence.WriterIdentity {
		return MutationPlan{}, AuditIntent{}, ErrWriterFenceMismatch
	}
	if err := validateOperationFields(command.ActorIdentity, command.CauseCode, command.CorrelationID, command.EvaluatedAtUnixNano); err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	authorization, err := p.validateVerifiedAuthorization(ctx, command.Authorization, next.MessageTypeID,
		next.CanonicalPayload, next.CreatedAtUnixNano, command.ActorIdentity, command.CorrelationID, command.CausationID,
		next.Ref, command.EvaluatedAtUnixNano, command.Fence.ExpectedStateVersion)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	requestDigest := sha256.Sum256(next.CanonicalPayload)
	idempotencyBinding := mutationIdempotencyBinding(next.IdempotencyKey,
		idempotency.OperationIAMIdentity, next.Ref.ID, requestDigest)
	joinedAuditBinding, err := p.precheckPendingIdempotency(ctx, idempotencyBinding)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	auditEventID, err := idempotency.JoinedAuditEventID(idempotencyBinding)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, ErrPendingPlanInvalid
	}
	stored, found, err := p.view.LookupIdentity(ctx, next.Ref)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, fmt.Errorf("aiinfra iam: lookup identity: %w", err)
	}
	var previous *IdentitySnapshot
	var successorDependencies []SnapshotPrecondition
	if found {
		current, err := normalizeViewIdentity(stored)
		if err != nil {
			return MutationPlan{}, AuditIntent{}, err
		}
		if !sameEntityRef(current.Ref, next.Ref) {
			return MutationPlan{}, AuditIntent{}, ErrIdentityConflict
		}
		if terminalIdentityState(current.State) {
			return MutationPlan{}, AuditIntent{}, ErrTerminalIdentity
		}
		if err := checkedNextVersion(current.StateVersion, next.StateVersion); err != nil {
			return MutationPlan{}, AuditIntent{}, err
		}
		successorDependencies, err = p.validateIdentityRecordSuccessor(ctx, current, next)
		if err != nil {
			return MutationPlan{}, AuditIntent{}, err
		}
		if next.WriterEpoch < current.WriterEpoch || (next.HomeRegion != current.HomeRegion && next.WriterEpoch <= current.WriterEpoch) {
			return MutationPlan{}, AuditIntent{}, ErrWriterFenceMismatch
		}
		copy := cloneIdentity(current)
		previous = &copy
	} else if next.StateVersion != 1 {
		return MutationPlan{}, AuditIntent{}, ErrStateVersionConflict
	}
	expectedVersion := uint64(0)
	if previous != nil {
		expectedVersion = previous.StateVersion
	}
	if err := validateIdentityTransitionBaseline(previous, next, command.TransferEvidenceDigest,
		command.EvaluatedAtUnixNano); err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	if command.Fence.ExpectedStateVersion != expectedVersion {
		return MutationPlan{}, AuditIntent{}, ErrStateVersionConflict
	}
	leaseState, err := p.validateFence(ctx, next.Ref, command.Fence, command.EvaluatedAtUnixNano, next.HomeRegion, next.WriterEpoch)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	transfer, err := p.validateOwnershipTransfer(ctx, next, found, command.TransferEvidenceDigest, command.EvaluatedAtUnixNano)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	principalIndex, err := p.validatePrincipalIndex(ctx, next, found, transfer.Evidence)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	dependencies, err := p.validateIdentityGraph(ctx, next)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	keyValidation, err := p.validateIdentityKey(ctx, next, command.EvaluatedAtUnixNano,
		command.Authorization.environment, command.Authorization.genesisHash)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	if previous == nil && keyValidation.TransferEvidenceDigest != command.TransferEvidenceDigest {
		return MutationPlan{}, AuditIntent{}, ErrIdentityConflict
	}
	terminalDependencies, subjectKeySetDigest, err := p.validateTerminalSubjectKeys(ctx, next, command.EvaluatedAtUnixNano)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	dependencies = append(dependencies, successorDependencies...)
	dependencies = append(dependencies, keyValidation.Dependencies...)
	dependencies = append(dependencies, terminalDependencies...)
	dependencies = append(dependencies, transfer.Dependencies...)
	dependencies = append(dependencies, authorization.Dependencies...)
	dependencies, err = canonicalPreconditions(dependencies)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	transition := IdentityTransitionRequest{Next: cloneIdentity(next)}
	if previous != nil {
		copy := cloneIdentity(*previous)
		transition.Previous = &copy
	}
	if err := p.profile.ValidateIdentityTransition(ctx, transition); err != nil {
		return MutationPlan{}, AuditIntent{}, fmt.Errorf("aiinfra iam: identity transition policy: %w", err)
	}
	authority := AuthorityRequest{Mutation: MutationAppendIdentity, Entity: next.Ref,
		ActorIdentity: command.ActorIdentity, EvaluatedAtUnixNano: command.EvaluatedAtUnixNano,
		PolicyDigestsSHA256: cloneDigests(next.PolicyDigestsSHA256)}
	if err := p.profile.ValidateAuthority(ctx, authority); err != nil {
		return MutationPlan{}, AuditIntent{}, fmt.Errorf("aiinfra iam: identity authority: %w", err)
	}
	cas := CASIntent{Entity: next.Ref, ExpectedAbsent: previous == nil,
		ExpectedStateVersion: expectedVersion, AuthorizedWriterEpoch: command.Fence.WriterEpoch,
		WriterEvidenceDigest: command.Fence.EvidenceDigest, Dependencies: dependencies,
		TransferEvidenceDigest: command.TransferEvidenceDigest, AuthorizationDigest: command.Authorization.recordDigest,
		PrincipalIndex:      principalIndex,
		SubjectKeySetDigest: subjectKeySetDigest}
	if previous != nil {
		cas.ExpectedEntityWriterEpoch = previous.WriterEpoch
	}
	cas.EnrollmentEvidenceDigest = keyValidation.EnrollmentEvidenceDigest
	cas.IdentifierClaims, err = p.identityIdentifierClaims(ctx, next, previous, principalIndex, transfer.Evidence,
		keyValidation.EnrollmentEvidenceDigest)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	windowStarts := []int64{leaseState.ValidFromUnixNano, authorization.NotBeforeUnixNano}
	windowEnds := []int64{leaseState.ValidUntilUnixNano, authorization.NotAfterUnixNano}
	switch next.State {
	case 1:
		windowEnds = append(windowEnds, next.ValidUntilUnixNano)
		if keyValidation.NotAfterUnixNano > 0 {
			windowEnds = append(windowEnds, keyValidation.NotAfterUnixNano)
		}
	case 2, 3:
		windowStarts = append(windowStarts, next.ValidFromUnixNano)
		windowEnds = append(windowEnds, next.ValidUntilUnixNano)
		if keyValidation.NotBeforeUnixNano > 0 {
			windowStarts = append(windowStarts, keyValidation.NotBeforeUnixNano)
			windowEnds = append(windowEnds, keyValidation.NotAfterUnixNano)
		}
	case 6:
		windowStarts = append(windowStarts, next.ValidUntilUnixNano)
	}
	window, err := newPlanWindow(authorization.Receiver, command.EvaluatedAtUnixNano, windowStarts, windowEnds)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	subjects := []string{next.Ref.ID, next.PrincipalIdentity, next.RecordID}
	if next.KeyID != "" {
		subjects = append(subjects, next.KeyID)
	}
	evidence := [][32]byte{command.Fence.EvidenceDigest, command.Authorization.recordDigest}
	if command.TransferEvidenceDigest != ([32]byte{}) {
		evidence = append(evidence, command.TransferEvidenceDigest)
	}
	source, err := auditSourceFromAuthorization(command.Authorization)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	audit, err := newAuditIntent(auditEventID, "iam.identity.appended", command.ActorIdentity, subjects,
		command.CauseCode, command.CorrelationID, directAuditCausation(command.Authorization.messageID),
		command.Authorization.messageID, next.IdempotencyKey, joinedAuditBinding.Key, source,
		command.EvaluatedAtUnixNano,
		next.PolicyDigestsSHA256, evidence)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	cas.IdempotencyClaims, err = pendingIdempotencyClaims(idempotencyBinding, joinedAuditBinding, audit.Digest())
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	plan, err := newIdentityPlan(cas, next, window)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	return plan, audit, nil
}

// PlanKeyLifecycle validates a transition of an existing lifecycle. Initial
// PREACTIVE creation is available only through signed compound key enrollment.
func (p *Planner) PlanKeyLifecycle(ctx context.Context, command KeyLifecycleCommand) (PendingMutationPlan, error) {
	if command.TransferEvidenceDigest == ([32]byte{}) {
		mutation, audit, err := p.planKeyLifecycle(ctx, command, false, false)
		if err != nil {
			return PendingMutationPlan{}, err
		}
		return newPendingMutationPlan(mutation, audit)
	}
	return PendingMutationPlan{}, ErrTransferAuthorizationRequired
}

func (p *Planner) planKeyLifecycle(ctx context.Context, command KeyLifecycleCommand,
	allowInitialPreactive, allowUnverifiedTransfer bool) (MutationPlan, AuditIntent, error) {
	if command.TransferEvidenceDigest != ([32]byte{}) && !allowUnverifiedTransfer {
		return MutationPlan{}, AuditIntent{}, ErrTransferAuthorizationRequired
	}
	if err := p.ready(); err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	next, err := NormalizeKeyLifecycle(command.Projection)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	if command.ActorIdentity == "" || command.ActorIdentity != command.Fence.WriterIdentity {
		return MutationPlan{}, AuditIntent{}, ErrWriterFenceMismatch
	}
	if err := validateOperationFields(command.ActorIdentity, command.CauseCode, command.CorrelationID, command.EvaluatedAtUnixNano); err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	authorization, err := p.validateVerifiedAuthorization(ctx, command.Authorization, schema.MessageTypeKeyLifecycle,
		next.CanonicalPayload, next.CreatedAtUnixNano, command.ActorIdentity, command.CorrelationID, command.CausationID,
		EntityRef{Kind: EntityKeyLifecycle, PrincipalKind: next.SubjectKind, ID: next.KeyID},
		command.EvaluatedAtUnixNano, command.Fence.ExpectedStateVersion)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	requestDigest := sha256.Sum256(next.CanonicalPayload)
	idempotencyBinding := mutationIdempotencyBinding(next.IdempotencyKey,
		idempotency.OperationIAMKeyLifecycle, next.KeyID, requestDigest)
	joinedAuditBinding, err := p.precheckPendingIdempotency(ctx, idempotencyBinding)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	auditEventID, err := idempotency.JoinedAuditEventID(idempotencyBinding)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, ErrPendingPlanInvalid
	}
	material, found, err := p.view.LookupKeyMaterial(ctx, next.KeyID)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, fmt.Errorf("aiinfra iam: lookup key material: %w", err)
	}
	if !found {
		return MutationPlan{}, AuditIntent{}, ErrKeyMaterialUnknown
	}
	material, err = validateMaterialSnapshot(material)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	if material.KeyID != next.KeyID || material.SubjectIdentity != next.SubjectIdentity || material.SubjectKind != next.SubjectKind || material.Algorithm != next.Algorithm {
		return MutationPlan{}, AuditIntent{}, ErrKeyMaterialMismatch
	}
	if next.Algorithm != ccse.SignatureAlgorithmEd25519 {
		return MutationPlan{}, AuditIntent{}, ErrUnsupportedAlgorithm
	}
	if err := p.validateAllowedMessageTypes(ctx, next); err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	entity := EntityRef{Kind: EntityKeyLifecycle, PrincipalKind: next.SubjectKind, ID: next.KeyID}
	stored, exists, err := p.view.LookupKeyLifecycle(ctx, next.KeyID)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, fmt.Errorf("aiinfra iam: lookup key lifecycle: %w", err)
	}
	if !exists && !allowInitialPreactive {
		return MutationPlan{}, AuditIntent{}, ErrLifecycleUnknown
	}
	expectedVersion := uint64(0)
	var predecessorDependency SnapshotPrecondition
	if exists {
		current, err := normalizeViewLifecycle(stored)
		if err != nil {
			return MutationPlan{}, AuditIntent{}, err
		}
		if current.KeyID != next.KeyID {
			return MutationPlan{}, AuditIntent{}, ErrViewInconsistent
		}
		if terminalLifecycleState(current.State) {
			return MutationPlan{}, AuditIntent{}, ErrTerminalLifecycle
		}
		if err := checkedNextVersion(current.StateVersion, next.StateVersion); err != nil {
			return MutationPlan{}, AuditIntent{}, err
		}
		if current.ImmutableBindingDigest != next.ImmutableBindingDigest {
			return MutationPlan{}, AuditIntent{}, ErrKeyMaterialMismatch
		}
		if next.WriterEpoch < current.WriterEpoch || (next.HomeRegion != current.HomeRegion && next.WriterEpoch <= current.WriterEpoch) {
			return MutationPlan{}, AuditIntent{}, ErrWriterFenceMismatch
		}
		if err := validateLifecycleTransition(current, next, command.EvaluatedAtUnixNano); err != nil {
			return MutationPlan{}, AuditIntent{}, err
		}
		if next.HasRotationPredecessor {
			successor, found, lookupErr := p.view.LookupRotationSuccessor(ctx, next.RotationPredecessorKeyID)
			if lookupErr != nil {
				return MutationPlan{}, AuditIntent{}, fmt.Errorf("aiinfra iam: lookup retained rotation successor: %w", lookupErr)
			}
			if !found {
				return MutationPlan{}, AuditIntent{}, ErrViewInconsistent
			}
			successor, lookupErr = normalizeViewLifecycle(successor)
			if lookupErr != nil || successor.KeyID != next.KeyID ||
				successor.RotationPredecessorKeyID != next.RotationPredecessorKeyID {
				return MutationPlan{}, AuditIntent{}, ErrViewInconsistent
			}
		}
		expectedVersion = current.StateVersion
	} else {
		if next.StateVersion != 1 {
			return MutationPlan{}, AuditIntent{}, ErrStateVersionConflict
		}
		if next.State != 1 {
			return MutationPlan{}, AuditIntent{}, fmt.Errorf("%w: first lifecycle must be PREACTIVE", ErrInvalidTransition)
		}
		if command.EvaluatedAtUnixNano >= next.NotAfterUnixNano {
			return MutationPlan{}, AuditIntent{}, fmt.Errorf("%w: PREACTIVE lifecycle already expired", ErrInvalidTransition)
		}
		if next.HasRevokedAt {
			return MutationPlan{}, AuditIntent{}, ErrInvalidTransition
		}
		if material.TransferEvidenceDigest != command.TransferEvidenceDigest {
			return MutationPlan{}, AuditIntent{}, ErrIdentityConflict
		}
		predecessorDependency, err = p.validatePredecessorChain(ctx, next)
		if err != nil {
			return MutationPlan{}, AuditIntent{}, err
		}
	}
	if command.Fence.ExpectedStateVersion != expectedVersion {
		return MutationPlan{}, AuditIntent{}, ErrStateVersionConflict
	}
	if material.EnrollmentDomain.EnrollmentDomainID != authorization.Receiver.EnrollmentDomainID ||
		material.EnrollmentDomain.Environment != command.Authorization.environment ||
		material.EnrollmentDomain.GenesisHash != command.Authorization.genesisHash {
		return MutationPlan{}, AuditIntent{}, ErrKeyMaterialMismatch
	}
	subjectDependency, subjectAbsent, err := p.validateLifecycleSubject(ctx, next, material.TargetIdentity,
		exists, command.TransferEvidenceDigest, command.EvaluatedAtUnixNano)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	dependencies := []SnapshotPrecondition{materialPrecondition(material)}
	dependencies = append(dependencies, authorization.Dependencies...)
	if subjectDependency.Entity.Kind != 0 {
		dependencies = append(dependencies, subjectDependency)
	}
	if predecessorDependency.Entity.Kind != 0 {
		dependencies = append(dependencies, predecessorDependency)
	}
	dependencies, err = canonicalPreconditions(dependencies)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	leaseState, err := p.validateFence(ctx, entity, command.Fence, command.EvaluatedAtUnixNano, next.HomeRegion, next.WriterEpoch)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	authority := AuthorityRequest{Mutation: MutationAppendKeyLifecycle, Entity: entity,
		ActorIdentity: command.ActorIdentity, EvaluatedAtUnixNano: command.EvaluatedAtUnixNano,
		PolicyDigestsSHA256: cloneDigests(next.PolicyDigestsSHA256)}
	if err := p.profile.ValidateAuthority(ctx, authority); err != nil {
		return MutationPlan{}, AuditIntent{}, fmt.Errorf("aiinfra iam: lifecycle authority: %w", err)
	}
	cas := CASIntent{Entity: entity, ExpectedAbsent: !exists,
		ExpectedStateVersion: expectedVersion, AuthorizedWriterEpoch: command.Fence.WriterEpoch,
		WriterEvidenceDigest: command.Fence.EvidenceDigest, Dependencies: dependencies,
		RotationPredecessorKeyID: next.RotationPredecessorKeyID,
		AuthorizationDigest:      command.Authorization.recordDigest, ExpectedSubjectAbsent: subjectAbsent,
		SubjectKind: next.SubjectKind, SubjectIdentity: next.SubjectIdentity,
		TransferEvidenceDigest: command.TransferEvidenceDigest}
	if exists {
		cas.ExpectedEntityWriterEpoch = stored.WriterEpoch
	}
	if next.HasRotationPredecessor {
		if exists {
			cas.PredecessorIndexMode = PredecessorAssertExisting
		} else {
			cas.PredecessorIndexMode = PredecessorReserveNew
		}
	}
	cas.IdentifierClaims, err = p.lifecycleIdentifierClaims(ctx, next, material.TargetIdentity,
		subjectDependency, subjectAbsent,
		command.TransferEvidenceDigest != ([32]byte{}) && terminalLifecycleState(next.State))
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	windowStarts := []int64{leaseState.ValidFromUnixNano, authorization.NotBeforeUnixNano}
	windowEnds := []int64{leaseState.ValidUntilUnixNano, authorization.NotAfterUnixNano}
	switch next.State {
	case 1:
		windowEnds = append(windowEnds, next.NotAfterUnixNano)
	case 2, 3:
		windowStarts = append(windowStarts, next.NotBeforeUnixNano)
		windowEnds = append(windowEnds, next.NotAfterUnixNano)
	case 5:
		windowStarts = append(windowStarts, next.NotAfterUnixNano)
	}
	window, err := newPlanWindow(authorization.Receiver, command.EvaluatedAtUnixNano, windowStarts, windowEnds)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	subjects := []string{next.KeyID, next.SubjectIdentity, next.RecordID}
	if next.HasRotationPredecessor {
		subjects = append(subjects, next.RotationPredecessorKeyID)
	}
	evidence := [][32]byte{command.Fence.EvidenceDigest, command.Authorization.recordDigest}
	if command.TransferEvidenceDigest != ([32]byte{}) {
		evidence = append(evidence, command.TransferEvidenceDigest)
	}
	source, err := auditSourceFromAuthorization(command.Authorization)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	audit, err := newAuditIntent(auditEventID, "iam.key_lifecycle.appended", command.ActorIdentity, subjects,
		command.CauseCode, command.CorrelationID, directAuditCausation(command.Authorization.messageID),
		command.Authorization.messageID, next.IdempotencyKey, joinedAuditBinding.Key, source,
		command.EvaluatedAtUnixNano,
		next.PolicyDigestsSHA256, evidence)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	cas.IdempotencyClaims, err = pendingIdempotencyClaims(idempotencyBinding, joinedAuditBinding, audit.Digest())
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	plan, err := newLifecyclePlan(cas, next, window)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	return plan, audit, nil
}

func (p *Planner) ready() error {
	if p == nil || p.view == nil {
		return ErrViewRequired
	}
	if p.profile == nil {
		return ErrProfileRequired
	}
	return nil
}

func (p *Planner) validateAllowedMessageTypes(ctx context.Context, lifecycle KeyLifecycleSnapshot) error {
	for _, id := range lifecycle.AllowedMessageTypeIDs {
		if _, ok := p.registry.LookupMessage(id); !ok {
			return fmt.Errorf("%w: %d", ErrUnknownMessageType, id)
		}
	}
	request := AllowedMessageTypesRequest{
		SubjectIdentity: lifecycle.SubjectIdentity, SubjectKind: lifecycle.SubjectKind,
		KeyID: lifecycle.KeyID, MessageTypeIDs: append([]uint32(nil), lifecycle.AllowedMessageTypeIDs...),
		AuthorizationPolicyDigestSHA256: lifecycle.AuthorizationPolicyDigestSHA256,
	}
	if err := p.profile.ValidateAllowedMessageTypes(ctx, request); err != nil {
		return fmt.Errorf("aiinfra iam: allowed message type policy: %w", err)
	}
	return nil
}

func (p *Planner) validatePredecessorChain(ctx context.Context, lifecycle KeyLifecycleSnapshot) (SnapshotPrecondition, error) {
	if !lifecycle.HasRotationPredecessor {
		return SnapshotPrecondition{}, nil
	}
	if lifecycle.RotationPredecessorKeyID == lifecycle.KeyID {
		return SnapshotPrecondition{}, ErrPredecessorCycle
	}
	if successor, found, err := p.view.LookupRotationSuccessor(ctx, lifecycle.RotationPredecessorKeyID); err != nil {
		return SnapshotPrecondition{}, fmt.Errorf("aiinfra iam: lookup rotation successor: %w", err)
	} else if found {
		successor, normalizeErr := normalizeViewLifecycle(successor)
		if normalizeErr != nil {
			return SnapshotPrecondition{}, normalizeErr
		}
		if !successor.HasRotationPredecessor || successor.RotationPredecessorKeyID != lifecycle.RotationPredecessorKeyID {
			return SnapshotPrecondition{}, ErrViewInconsistent
		}
		return SnapshotPrecondition{}, ErrInvalidPredecessor
	}
	seen := map[string]struct{}{lifecycle.KeyID: {}}
	cursor := lifecycle.RotationPredecessorKeyID
	var direct SnapshotPrecondition
	for depth := 0; depth < maxPredecessorDepth; depth++ {
		if _, duplicate := seen[cursor]; duplicate {
			return SnapshotPrecondition{}, ErrPredecessorCycle
		}
		seen[cursor] = struct{}{}
		item, found, err := p.view.LookupKeyLifecycle(ctx, cursor)
		if err != nil {
			return SnapshotPrecondition{}, fmt.Errorf("aiinfra iam: lookup predecessor %q: %w", cursor, err)
		}
		if !found {
			return SnapshotPrecondition{}, fmt.Errorf("%w: unknown key %q", ErrInvalidPredecessor, cursor)
		}
		item, err = normalizeViewLifecycle(item)
		if err != nil {
			return SnapshotPrecondition{}, err
		}
		if item.KeyID != cursor || item.SubjectIdentity != lifecycle.SubjectIdentity || item.SubjectKind != lifecycle.SubjectKind {
			return SnapshotPrecondition{}, ErrInvalidPredecessor
		}
		if depth == 0 {
			direct = lifecyclePrecondition(item)
		}
		if !item.HasRotationPredecessor {
			return direct, nil
		}
		cursor = item.RotationPredecessorKeyID
	}
	return SnapshotPrecondition{}, ErrLookupLimit
}

func (p *Planner) validateFence(ctx context.Context, entity EntityRef, supplied WriterFence, at int64, homeRegion string, writerEpoch uint64) (WriterLeaseSnapshot, error) {
	if !sameEntityRef(entity, supplied.Entity) || supplied.WriterIdentity == "" || supplied.HomeRegion == "" ||
		supplied.WriterEpoch == 0 || supplied.EvidenceDigest == ([32]byte{}) || at < 0 {
		return WriterLeaseSnapshot{}, ErrWriterFenceMismatch
	}
	lease, found, err := p.view.LookupWriterLease(ctx, entity)
	if err != nil {
		return WriterLeaseSnapshot{}, fmt.Errorf("aiinfra iam: lookup writer lease: %w", err)
	}
	if !found {
		return WriterLeaseSnapshot{}, ErrWriterFenceUnknown
	}
	if !sameEntityRef(lease.Entity, entity) || lease.WriterIdentity != supplied.WriterIdentity ||
		lease.HomeRegion != supplied.HomeRegion || lease.WriterEpoch != supplied.WriterEpoch ||
		lease.EvidenceDigest != supplied.EvidenceDigest || homeRegion != supplied.HomeRegion || writerEpoch != supplied.WriterEpoch {
		return WriterLeaseSnapshot{}, ErrWriterFenceMismatch
	}
	if lease.ValidFromUnixNano < 0 || lease.ValidUntilUnixNano <= lease.ValidFromUnixNano || at < lease.ValidFromUnixNano || at >= lease.ValidUntilUnixNano {
		return WriterLeaseSnapshot{}, ErrWriterFenceExpired
	}
	return lease, nil
}

func validateChallenge(command KeyMaterialCommand, state ProofChallengeSnapshot) error {
	if len(command.EnrollmentPolicyDigestsSHA256) == 0 || len(command.EnrollmentPolicyDigestsSHA256) > 64 ||
		len(state.PolicyDigestsSHA256) == 0 || len(state.PolicyDigestsSHA256) > 64 {
		return ErrInvalidProofOfPossession
	}
	if err := validateTargetIdentity(command.TargetIdentity, command.SubjectKind); err != nil {
		return ErrInvalidProofOfPossession
	}
	if _, err := ccse.Marshal(4096, func(out *ccse.Encoder) {
		out.String(state.SubjectIdentity)
		out.String(state.IssuerIdentity)
	}); err != nil {
		return ErrInvalidProofOfPossession
	}
	commandPolicies, err := canonicalDigests(command.EnrollmentPolicyDigestsSHA256)
	if err != nil {
		return ErrInvalidProofOfPossession
	}
	statePolicies, err := canonicalDigests(state.PolicyDigestsSHA256)
	if err != nil || !equalDigestSlices(commandPolicies, statePolicies) {
		return ErrInvalidProofOfPossession
	}
	if state.Challenge != command.Challenge || state.SubjectIdentity != command.SubjectIdentity || state.SubjectKind != command.SubjectKind ||
		!sameEntityRef(state.TargetIdentity, command.TargetIdentity) ||
		state.TransferEvidenceDigest != command.TransferEvidenceDigest || state.Domain != command.EnrollmentDomain ||
		state.ExpiresAtUnixNano != command.ChallengeExpiresAtUnixNano || state.EvidenceDigest == ([32]byte{}) ||
		state.IssuerIdentity == "" || state.IssuerIdentity != command.EnrollmentAuthorityIdentity ||
		state.EvidenceDigest != command.EnrollmentAuthorityEvidenceDigest {
		return ErrInvalidProofOfPossession
	}
	if state.Consumed {
		return ErrProofChallengeConsumed
	}
	if command.EvaluatedAtUnixNano < 0 || command.EvaluatedAtUnixNano >= state.ExpiresAtUnixNano {
		return ErrProofChallengeExpired
	}
	return nil
}

func equalDigestSlices(left, right [][32]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validateOperationFields(actor, cause string, correlation [16]byte, at int64) error {
	if actor == "" || cause == "" || correlation == ([16]byte{}) || at < 0 {
		return ErrInvalidInput
	}
	for _, value := range []string{actor, cause} {
		if _, err := ccse.Marshal(2048, func(out *ccse.Encoder) { out.String(value) }); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidInput, err)
		}
	}
	return nil
}

func newMaterialPlan(cas CASIntent, material KeyMaterialSnapshot, window planWindow) (MutationPlan, error) {
	material = cloneKeyMaterial(material)
	policyElements, err := encodedDigestSet(material.EnrollmentPolicyDigestsSHA256)
	if err != nil {
		return MutationPlan{}, err
	}
	digest, err := planDigest(MutationCreateKeyMaterial, cas, window, func(out *ccse.Encoder) {
		out.String(material.KeyID)
		out.Uint32(uint32(material.Algorithm))
		out.Bytes(material.CanonicalPublicKey)
		out.String(material.SubjectIdentity)
		out.Uint32(material.SubjectKind)
		out.Uint32(uint32(material.TargetIdentity.Kind))
		out.Uint32(material.TargetIdentity.PrincipalKind)
		out.String(material.TargetIdentity.ID)
		out.FixedBytes(material.TransferEvidenceDigest[:], 32)
		out.String(material.EnrollmentDomain.EnrollmentDomainID)
		out.String(material.EnrollmentDomain.Environment)
		out.FixedBytes(material.EnrollmentDomain.GenesisHash[:], 32)
		out.FixedBytes(material.ProofChallenge[:], 32)
		out.Int64(material.ProofExpiresAtUnixNano)
		out.Bytes(material.ProofSignature)
		out.FixedBytes(material.ProofDigest[:], 32)
		out.FixedBytes(material.ChallengeEvidenceDigest[:], 32)
		out.String(material.EnrollmentAuthorityIdentity)
		out.EncodedSet(policyElements)
		out.FixedBytes(material.EnrollmentBindingDigest[:], 32)
		out.String(material.WriterIdentity)
		out.String(material.HomeRegion)
		out.Uint64(material.WriterEpoch)
		out.Uint64(material.StateVersion)
		out.FixedBytes(material.IdempotencyKey[:], 16)
	})
	if err != nil {
		return MutationPlan{}, err
	}
	return MutationPlan{kind: MutationCreateKeyMaterial, cas: cas, material: &material,
		evaluatedAtUnixNano: window.EvaluatedAtUnixNano, commitNotBeforeUnixNano: window.CommitNotBeforeUnixNano,
		commitNotAfterUnixNano: window.CommitNotAfterUnixNano, digest: digest}, nil
}

func newIdentityPlan(cas CASIntent, identity IdentitySnapshot, window planWindow) (MutationPlan, error) {
	identity = cloneIdentity(identity)
	digest, err := planDigest(MutationAppendIdentity, cas, window, func(out *ccse.Encoder) { out.Bytes(identity.CanonicalPayload) })
	if err != nil {
		return MutationPlan{}, err
	}
	return MutationPlan{kind: MutationAppendIdentity, cas: cas, identity: &identity,
		evaluatedAtUnixNano: window.EvaluatedAtUnixNano, commitNotBeforeUnixNano: window.CommitNotBeforeUnixNano,
		commitNotAfterUnixNano: window.CommitNotAfterUnixNano, digest: digest}, nil
}

func newLifecyclePlan(cas CASIntent, lifecycle KeyLifecycleSnapshot, window planWindow) (MutationPlan, error) {
	lifecycle = cloneLifecycle(lifecycle)
	digest, err := planDigest(MutationAppendKeyLifecycle, cas, window, func(out *ccse.Encoder) { out.Bytes(lifecycle.CanonicalPayload) })
	if err != nil {
		return MutationPlan{}, err
	}
	return MutationPlan{kind: MutationAppendKeyLifecycle, cas: cas, lifecycle: &lifecycle,
		evaluatedAtUnixNano: window.EvaluatedAtUnixNano, commitNotBeforeUnixNano: window.CommitNotBeforeUnixNano,
		commitNotAfterUnixNano: window.CommitNotAfterUnixNano, digest: digest}, nil
}

func planDigest(kind MutationKind, cas CASIntent, window planWindow, body func(*ccse.Encoder)) ([32]byte, error) {
	var zero [32]byte
	if window.EvaluatedAtUnixNano < 0 || window.CommitNotBeforeUnixNano < 0 ||
		window.CommitNotBeforeUnixNano > window.EvaluatedAtUnixNano ||
		window.CommitNotAfterUnixNano <= window.EvaluatedAtUnixNano {
		return zero, ErrInvalidCommitWindow
	}
	dependencies, err := canonicalPreconditions(cas.Dependencies)
	if err != nil {
		return zero, err
	}
	identifierClaims, err := globalid.CanonicalBytes(cas.IdentifierClaims)
	if err != nil {
		return zero, fmt.Errorf("%w: global identifier claims: %v", ErrPendingPlanInvalid, err)
	}
	var idempotencyClaims []byte
	if len(cas.IdempotencyClaims) != 0 {
		idempotencyClaims, err = idempotency.CanonicalBytes(cas.IdempotencyClaims)
		if err != nil {
			return zero, fmt.Errorf("%w: idempotency claims: %v", ErrPendingPlanInvalid, err)
		}
	}
	dependencyElements := make([][]byte, len(dependencies))
	for index, dependency := range dependencies {
		dependencyElements[index], err = ccse.Marshal(2048, func(out *ccse.Encoder) {
			encodeEntity(out, dependency.Entity)
			out.Uint64(dependency.ExpectedStateVersion)
			out.Uint64(dependency.ExpectedWriterEpoch)
			out.Uint32(dependency.ExpectedState)
			out.FixedBytes(dependency.ExpectedSnapshotDigest[:], 32)
		})
		if err != nil {
			return zero, err
		}
	}
	encoded, err := ccse.Marshal(65536, func(out *ccse.Encoder) {
		out.Uint32(uint32(kind))
		out.Int64(window.EvaluatedAtUnixNano)
		out.Int64(window.CommitNotBeforeUnixNano)
		out.Int64(window.CommitNotAfterUnixNano)
		encodeEntity(out, cas.Entity)
		out.Bool(cas.ExpectedAbsent)
		out.Uint64(cas.ExpectedStateVersion)
		out.Uint64(cas.ExpectedEntityWriterEpoch)
		out.Uint64(cas.AuthorizedWriterEpoch)
		out.FixedBytes(cas.WriterEvidenceDigest[:], 32)
		out.EncodedList(dependencyElements)
		out.Bool(cas.ConsumeChallenge)
		if cas.ConsumeChallenge {
			out.FixedBytes(cas.Challenge[:], 32)
			out.FixedBytes(cas.ChallengeEvidenceDigest[:], 32)
		}
		out.Uint32(uint32(cas.PredecessorIndexMode))
		if cas.PredecessorIndexMode != 0 {
			out.String(cas.RotationPredecessorKeyID)
		}
		out.FixedBytes(cas.TransferEvidenceDigest[:], 32)
		out.FixedBytes(cas.EnrollmentEvidenceDigest[:], 32)
		out.FixedBytes(cas.AuthorizationDigest[:], 32)
		out.Uint32(uint32(cas.PrincipalIndex.Mode))
		if cas.PrincipalIndex.Mode != 0 {
			out.Uint32(cas.PrincipalIndex.PrincipalKind)
			out.String(cas.PrincipalIndex.PrincipalIdentity)
			encodeEntity(out, cas.PrincipalIndex.ExpectedOwner)
			encodeEntity(out, cas.PrincipalIndex.NextOwner)
			out.Uint64(cas.PrincipalIndex.ExpectedStateVersion)
			out.Uint64(cas.PrincipalIndex.ExpectedEntityWriterEpoch)
			out.Uint32(cas.PrincipalIndex.ExpectedState)
			out.FixedBytes(cas.PrincipalIndex.TransferEvidenceDigest[:], 32)
		}
		out.Bytes(identifierClaims)
		out.Bool(cas.ExpectedSubjectAbsent)
		if cas.ExpectedSubjectAbsent {
			out.Uint32(cas.SubjectKind)
			out.String(cas.SubjectIdentity)
		}
		out.FixedBytes(cas.SubjectKeySetDigest[:], 32)
		out.Bytes(idempotencyClaims)
		body(out)
	})
	if err != nil {
		return zero, err
	}
	return domainDigest(mutationPlanDomain, encoded), nil
}

func newAuditIntent(auditEventID, eventType, actor string, subjects []string, cause string, correlation [16]byte,
	causation ccse.OptionalMessageID, messageID, idempotencyKey, expectedAuditIdempotencyKey [16]byte,
	source auditSourceEvidence, occurred int64, policies, evidence [][32]byte) (AuditIntent, error) {
	subjects, err := canonicalStrings(subjects)
	if err != nil {
		return AuditIntent{}, err
	}
	policies, err = canonicalDigests(policies)
	if err != nil {
		return AuditIntent{}, err
	}
	evidence, err = canonicalDigests(evidence)
	if err != nil {
		return AuditIntent{}, err
	}
	subjectElements, err := encodedStringSet(subjects)
	if err != nil {
		return AuditIntent{}, err
	}
	policyElements, err := encodedDigestSet(policies)
	if err != nil {
		return AuditIntent{}, err
	}
	evidenceElements, err := encodedDigestSet(evidence)
	if err != nil {
		return AuditIntent{}, err
	}
	var sourceBytes []byte
	if source.Present {
		digest, digestErr := source.Record.Digest(ccse.DefaultLimits())
		if digestErr != nil || digest != source.Digest || source.Digest == ([32]byte{}) ||
			source.ActorKeyID == "" || source.Record.Domain.SenderIdentity != actor ||
			source.Record.Envelope.SignatureKeyID != source.ActorKeyID ||
			source.Record.Envelope.MessageID != messageID || source.Record.Envelope.CorrelationID != correlation ||
			source.Record.Envelope.CausationID != source.CausationID || !causation.Present ||
			causation.Value != messageID {
			return AuditIntent{}, ErrAuthorizationMismatch
		}
		sourceBytes, err = canonicalSignedAuthorizationEvidence(source.Record)
		if err != nil {
			return AuditIntent{}, err
		}
	} else if source.ActorKeyID != "" || source.Digest != ([32]byte{}) ||
		source.CausationID.Present || source.CausationID.Value != ([16]byte{}) {
		return AuditIntent{}, ErrPendingPlanInvalid
	}
	if auditEventID == "" {
		return AuditIntent{}, ErrPendingPlanInvalid
	}
	encoded, err := ccse.Marshal(2<<20, func(out *ccse.Encoder) {
		out.String(auditEventID)
		out.String(eventType)
		out.String(actor)
		out.String(source.ActorKeyID)
		out.EncodedSet(subjectElements)
		out.String(cause)
		out.FixedBytes(correlation[:], 16)
		out.Bool(causation.Present)
		if causation.Present {
			out.FixedBytes(causation.Value[:], 16)
		}
		out.FixedBytes(messageID[:], 16)
		out.FixedBytes(idempotencyKey[:], 16)
		out.FixedBytes(expectedAuditIdempotencyKey[:], 16)
		out.Bool(source.Present)
		if source.Present {
			out.FixedBytes(source.Digest[:], 32)
			out.Bool(source.CausationID.Present)
			if source.CausationID.Present {
				out.FixedBytes(source.CausationID.Value[:], 16)
			}
			out.Bytes(sourceBytes)
		}
		out.Int64(occurred)
		out.EncodedSet(policyElements)
		out.EncodedSet(evidenceElements)
	})
	if err != nil {
		return AuditIntent{}, err
	}
	digest := domainDigest(auditIntentDomain, encoded)
	return AuditIntent{auditEventID: auditEventID, eventType: eventType, actorIdentity: actor, actorKeyID: source.ActorKeyID,
		subjectIDs: subjects, causeCode: cause,
		correlationID: correlation, causationID: causation, messageID: messageID, idempotencyKey: idempotencyKey,
		expectedAuditIdempotencyKey: expectedAuditIdempotencyKey,
		sourceAuthorizationRecord:   cloneCCSERecord(source.Record), hasSourceAuthorization: source.Present,
		sourceAuthorizationDigest: source.Digest, sourceCausationID: source.CausationID,
		occurredAtUnixNano: occurred, policyDigestsSHA256: policies,
		evidenceDigestsSHA256: evidence, digest: digest}, nil
}

func newPendingMutationPlan(mutation MutationPlan, audit AuditIntent) (PendingMutationPlan, error) {
	if err := verifyMutationPlan(mutation); err != nil {
		return PendingMutationPlan{}, err
	}
	if err := verifyAuditIntent(audit); err != nil {
		return PendingMutationPlan{}, err
	}
	cas := mutation.CAS()
	parent, joined, err := pendingIdempotencyBindings(cas.IdempotencyClaims)
	if err != nil || audit.IdempotencyKey() != parent.Key ||
		audit.ExpectedAuditIdempotencyKey() != joined.Key {
		return PendingMutationPlan{}, ErrPendingPlanInvalid
	}
	auditEventReservation, err := joinedAuditEventReservation(parent, audit.AuditEventID())
	if err != nil {
		return PendingMutationPlan{}, err
	}
	cas.IdentifierClaims = append(cas.IdentifierClaims, auditEventReservation)
	cas.IdentifierClaims, err = normalizeGlobalClaims(cas.IdentifierClaims)
	if err != nil {
		return PendingMutationPlan{}, err
	}
	finalIdentifiers, reservations, err := stageGlobalIdentifierClaims(cas.IdentifierClaims)
	if err != nil {
		return PendingMutationPlan{}, err
	}
	cas.IdentifierClaims = finalIdentifiers
	cas.IdempotencyClaims = nil
	mutation, err = rebuildMutationPlan(mutation, cas)
	if err != nil {
		return PendingMutationPlan{}, err
	}
	core := pendingCoreEvidenceDigest(mutation.Digest(), audit.Digest())
	idempotencyReservations, err := pendingIdempotencyClaimsBound(parent, joined, audit.Digest(), core)
	if err != nil {
		return PendingMutationPlan{}, err
	}
	completion, err := pendingCompletionClaims(idempotencyReservations)
	if err != nil {
		return PendingMutationPlan{}, err
	}
	admission, err := newPendingAdmissionIntent(reservations, idempotencyReservations,
		core, mutation.EvaluatedAtUnixNano(), mutation.CommitNotBeforeUnixNano(),
		mutation.CommitNotAfterUnixNano())
	if err != nil {
		return PendingMutationPlan{}, err
	}
	digest, err := finalPendingDigest(core, admission.Digest(), completion)
	if err != nil {
		return PendingMutationPlan{}, err
	}
	result := PendingMutationPlan{mutation: mutation, audit: audit, admission: admission,
		idempotencyCompletion: completion, digest: digest}
	if err := verifyPendingMutationPlan(result); err != nil {
		return PendingMutationPlan{}, err
	}
	return result, nil
}

func verifyPendingMutationPlan(pending PendingMutationPlan) error {
	if err := verifyMutationPlan(pending.mutation); err != nil {
		return err
	}
	if err := verifyAuditIntent(pending.audit); err != nil {
		return err
	}
	if len(pending.mutation.CAS().IdempotencyClaims) != 0 ||
		verifyPendingAdmissionIntent(pending.admission) != nil {
		return ErrPendingPlanInvalid
	}
	core := pendingCoreEvidenceDigest(pending.mutation.Digest(), pending.audit.Digest())
	if core != pending.admission.CoreEvidenceDigest() ||
		pending.admission.EvaluatedAtUnixNano() != pending.mutation.EvaluatedAtUnixNano() ||
		pending.admission.CommitNotBeforeUnixNano() != pending.mutation.CommitNotBeforeUnixNano() ||
		pending.admission.CommitNotAfterUnixNano() != pending.mutation.CommitNotAfterUnixNano() ||
		!stagedReservationsMatchFinalClaims(pending.admission.identifierReservations,
			pending.mutation.CAS().IdentifierClaims) {
		return ErrPendingPlanInvalid
	}
	parent, joined, err := pendingIdempotencyBindings(pending.admission.idempotencyReservations)
	if err != nil || pending.audit.IdempotencyKey() != parent.Key ||
		pending.audit.ExpectedAuditIdempotencyKey() != joined.Key {
		return ErrPendingPlanInvalid
	}
	if err := verifyJoinedAuditEventClaims(parent, pending.audit,
		pending.admission.identifierReservations, pending.mutation.CAS().IdentifierClaims); err != nil {
		return err
	}
	expectedCompletion, err := pendingCompletionClaims(pending.admission.idempotencyReservations)
	if err != nil || !sameIdempotencyClaims(expectedCompletion, pending.idempotencyCompletion) {
		return ErrPendingPlanInvalid
	}
	digest, err := finalPendingDigest(core, pending.admission.Digest(), pending.idempotencyCompletion)
	if err != nil || pending.digest != digest {
		return ErrPendingPlanInvalid
	}
	return nil
}

func verifyMutationPlan(plan MutationPlan) error {
	window := planWindow{EvaluatedAtUnixNano: plan.evaluatedAtUnixNano,
		CommitNotBeforeUnixNano: plan.commitNotBeforeUnixNano, CommitNotAfterUnixNano: plan.commitNotAfterUnixNano}
	var (
		digest [32]byte
		err    error
	)
	switch plan.kind {
	case MutationCreateKeyMaterial:
		if plan.material == nil || plan.identity != nil || plan.lifecycle != nil {
			return ErrPendingPlanInvalid
		}
		material := plan.material
		policyElements, policyErr := encodedDigestSet(material.EnrollmentPolicyDigestsSHA256)
		if policyErr != nil {
			return policyErr
		}
		digest, err = planDigest(plan.kind, plan.cas, window, func(out *ccse.Encoder) {
			out.String(material.KeyID)
			out.Uint32(uint32(material.Algorithm))
			out.Bytes(material.CanonicalPublicKey)
			out.String(material.SubjectIdentity)
			out.Uint32(material.SubjectKind)
			out.Uint32(uint32(material.TargetIdentity.Kind))
			out.Uint32(material.TargetIdentity.PrincipalKind)
			out.String(material.TargetIdentity.ID)
			out.FixedBytes(material.TransferEvidenceDigest[:], 32)
			out.String(material.EnrollmentDomain.EnrollmentDomainID)
			out.String(material.EnrollmentDomain.Environment)
			out.FixedBytes(material.EnrollmentDomain.GenesisHash[:], 32)
			out.FixedBytes(material.ProofChallenge[:], 32)
			out.Int64(material.ProofExpiresAtUnixNano)
			out.Bytes(material.ProofSignature)
			out.FixedBytes(material.ProofDigest[:], 32)
			out.FixedBytes(material.ChallengeEvidenceDigest[:], 32)
			out.String(material.EnrollmentAuthorityIdentity)
			out.EncodedSet(policyElements)
			out.FixedBytes(material.EnrollmentBindingDigest[:], 32)
			out.String(material.WriterIdentity)
			out.String(material.HomeRegion)
			out.Uint64(material.WriterEpoch)
			out.Uint64(material.StateVersion)
			out.FixedBytes(material.IdempotencyKey[:], 16)
		})
	case MutationAppendIdentity:
		if plan.identity == nil || plan.material != nil || plan.lifecycle != nil {
			return ErrPendingPlanInvalid
		}
		digest, err = planDigest(plan.kind, plan.cas, window, func(out *ccse.Encoder) { out.Bytes(plan.identity.CanonicalPayload) })
	case MutationAppendKeyLifecycle:
		if plan.lifecycle == nil || plan.material != nil || plan.identity != nil {
			return ErrPendingPlanInvalid
		}
		digest, err = planDigest(plan.kind, plan.cas, window, func(out *ccse.Encoder) { out.Bytes(plan.lifecycle.CanonicalPayload) })
	default:
		return ErrPendingPlanInvalid
	}
	if err != nil {
		return err
	}
	if digest != plan.digest {
		return ErrPendingPlanInvalid
	}
	return nil
}

func verifyAuditIntent(intent AuditIntent) error {
	source := auditSourceEvidence{Present: intent.hasSourceAuthorization, ActorKeyID: intent.actorKeyID,
		Record: cloneCCSERecord(intent.sourceAuthorizationRecord), Digest: intent.sourceAuthorizationDigest,
		CausationID: intent.sourceCausationID}
	derived, err := newAuditIntent(intent.auditEventID, intent.eventType, intent.actorIdentity, intent.subjectIDs, intent.causeCode,
		intent.correlationID, intent.causationID, intent.messageID, intent.idempotencyKey,
		intent.expectedAuditIdempotencyKey, source, intent.occurredAtUnixNano,
		intent.policyDigestsSHA256, intent.evidenceDigestsSHA256)
	if err != nil {
		return err
	}
	if derived.digest != intent.digest {
		return ErrPendingPlanInvalid
	}
	return nil
}

func pendingDigest(mutation, audit [32]byte) [32]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte(pendingPlanDomain))
	_, _ = hash.Write(mutation[:])
	_, _ = hash.Write(audit[:])
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func encodeEntity(out *ccse.Encoder, entity EntityRef) {
	out.Uint32(uint32(entity.Kind))
	out.Uint32(entity.PrincipalKind)
	out.String(entity.ID)
}

func domainDigest(domain string, encoded []byte) [32]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write(encoded)
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func canonicalStrings(values []string) ([]string, error) {
	copy := append([]string(nil), values...)
	sort.Strings(copy)
	result := copy[:0]
	for _, value := range copy {
		if value == "" {
			return nil, ErrInvalidInput
		}
		if len(result) == 0 || value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result, nil
}

func canonicalDigests(values [][32]byte) ([][32]byte, error) {
	copy := cloneDigests(values)
	sort.Slice(copy, func(i, j int) bool { return bytes.Compare(copy[i][:], copy[j][:]) < 0 })
	for i, value := range copy {
		if value == ([32]byte{}) {
			return nil, ErrInvalidInput
		}
		if i > 0 && value == copy[i-1] {
			return nil, fmt.Errorf("%w: duplicate digest", ErrInvalidInput)
		}
	}
	return copy, nil
}
