// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"context"
	"fmt"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/idempotency"
)

const keyMaterialRequestDomain = "CPH-AIIE-IAM-KEY-MATERIAL-REQUEST-V1\x00"
const pendingMutationProgressDomain = "CPH-AIIE-IAM-PENDING-MUTATION-PROGRESS-V1\x00"

func (p *Planner) precheckPendingIdempotency(ctx context.Context,
	binding idempotency.Binding) (idempotency.Binding, error) {
	// Only ordinary IAM child operations may have been consumed as aliases by
	// an ownership-transfer cutover. The cutover umbrella itself is a normal
	// joined X/Y pair and must never be routed through the member state machine.
	if compoundView, ok := p.view.(idempotency.CompoundMemberView); ok &&
		idempotency.IsCompoundMemberDomain(binding.Domain) {
		member, memberErr := idempotency.PrecheckCompoundMember(ctx, compoundView, binding)
		if memberErr != nil {
			return idempotency.Binding{}, fmt.Errorf("aiinfra iam: compound-member precheck: %w", memberErr)
		}
		switch member.Kind() {
		case idempotency.DuplicateCompleted:
			return idempotency.Binding{}, IdempotencyCompletedError{Outcome: member.OutcomeDigest()}
		case idempotency.ContinueCollection:
			return idempotency.Binding{}, ErrIdempotencyInProgress
		case idempotency.Proceed:
		default:
			return idempotency.Binding{}, ErrViewInconsistent
		}
	}
	joined, err := idempotency.JoinedAuditBinding(binding)
	if err != nil {
		return idempotency.Binding{}, fmt.Errorf("aiinfra iam: joined audit binding: %w", err)
	}
	eventID, err := idempotency.JoinedAuditEventID(binding)
	if err != nil {
		return idempotency.Binding{}, fmt.Errorf("aiinfra iam: joined audit event id: %w", err)
	}
	decision, err := idempotency.PrecheckJoined(ctx, p.view, binding)
	if err != nil {
		return idempotency.Binding{}, fmt.Errorf("aiinfra iam: joined idempotency precheck: %w", err)
	}
	switch decision.Kind() {
	case idempotency.Proceed:
	case idempotency.DuplicateCompleted:
		return idempotency.Binding{}, IdempotencyCompletedError{Outcome: decision.OutcomeDigest()}
	case idempotency.ContinueCollection:
		return idempotency.Binding{}, IdempotencyCollectingError{
			Parent: decision.ParentSnapshot(), Audit: decision.AuditSnapshot(),
			JoinedAuditEventID: eventID}
	default:
		return idempotency.Binding{}, ErrViewInconsistent
	}
	return joined, nil
}

func pendingIdempotencyClaims(parent, joined idempotency.Binding,
	auditIntentDigest [32]byte) ([]idempotency.Claim, error) {
	parentDigest, err := idempotency.BindingDigest(parent)
	if err != nil {
		return nil, err
	}
	if expected, err := idempotency.JoinedAuditBinding(parent); err != nil || expected != joined {
		return nil, ErrPendingPlanInvalid
	}
	encoded, err := ccse.Marshal(128, func(out *ccse.Encoder) {
		out.FixedBytes(parentDigest[:], 32)
		out.FixedBytes(auditIntentDigest[:], 32)
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

func mutationIdempotencyBinding(key [16]byte, domain idempotency.OperationDomain,
	ownerID string, requestDigest [32]byte) idempotency.Binding {
	return idempotency.Binding{Key: key, Domain: domain, OwnerID: ownerID, RequestDigest: requestDigest}
}

func keyMaterialRequestDigest(command KeyMaterialCommand, canonicalPublicKey []byte,
	keyID string) ([32]byte, error) {
	var zero [32]byte
	policies, err := canonicalDigests(command.EnrollmentPolicyDigestsSHA256)
	if err != nil {
		return zero, err
	}
	policyElements, err := encodedDigestSet(policies)
	if err != nil {
		return zero, err
	}
	encoded, err := ccse.Marshal(65536, func(out *ccse.Encoder) {
		out.String(keyID)
		out.Uint32(uint32(command.Algorithm))
		out.Bytes(canonicalPublicKey)
		out.String(command.SubjectIdentity)
		out.Uint32(command.SubjectKind)
		encodeEntity(out, command.TargetIdentity)
		out.FixedBytes(command.TransferEvidenceDigest[:], 32)
		out.String(command.EnrollmentDomain.EnrollmentDomainID)
		out.String(command.EnrollmentDomain.Environment)
		out.FixedBytes(command.EnrollmentDomain.GenesisHash[:], 32)
		out.FixedBytes(command.Challenge[:], 32)
		out.Int64(command.ChallengeExpiresAtUnixNano)
		out.Bytes(command.ProofSignature)
		out.String(command.EnrollmentAuthorityIdentity)
		out.FixedBytes(command.EnrollmentAuthorityEvidenceDigest[:], 32)
		out.EncodedSet(policyElements)
	})
	if err != nil {
		return zero, fmt.Errorf("%w: key material idempotency projection: %v", ErrInvalidInput, err)
	}
	return domainDigest(keyMaterialRequestDomain, encoded), nil
}
