// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"bytes"
	"context"
	"fmt"
	"sort"

	"github.com/cypherium/cypher/aiinfra/globalid"
)

func identityGlobalOwner(ref EntityRef) globalid.Owner {
	return globalid.Owner{Domain: globalid.OwnerIAMIdentity,
		ID: fmt.Sprintf("iam-identity-v1:%d:%d:%s", ref.PrincipalKind, len(ref.ID), ref.ID)}
}

func keyGlobalOwner(keyID string) globalid.Owner {
	return globalid.Owner{Domain: globalid.OwnerIAMKey, ID: keyID}
}

func recordGlobalOwner(ref EntityRef, recordID string) globalid.Owner {
	return globalid.Owner{Domain: globalid.OwnerCanonicalRecord,
		ID: fmt.Sprintf("iam-record-v1:%d:%d:%d:%s:%d:%s", ref.Kind, ref.PrincipalKind,
			len(ref.ID), ref.ID, len(recordID), recordID)}
}

func (p *Planner) reserveGlobalID(ctx context.Context, identifier string, owner globalid.Owner) (globalid.Claim, error) {
	_, found, err := p.view.LookupGlobalID(ctx, identifier)
	if err != nil {
		return globalid.Claim{}, fmt.Errorf("aiinfra iam: lookup global identifier %q: %w", identifier, err)
	}
	if found {
		return globalid.Claim{}, fmt.Errorf("%w: %q already exists", ErrGlobalIdentifier, identifier)
	}
	claim, err := globalid.Reserve(identifier, owner)
	if err != nil {
		return globalid.Claim{}, fmt.Errorf("%w: reserve %q: %v", ErrGlobalIdentifier, identifier, err)
	}
	return claim, nil
}

func (p *Planner) assertGlobalID(ctx context.Context, identifier string, owner globalid.Owner) (globalid.Claim, error) {
	snapshot, found, err := p.view.LookupGlobalID(ctx, identifier)
	if err != nil {
		return globalid.Claim{}, fmt.Errorf("aiinfra iam: lookup global identifier %q: %w", identifier, err)
	}
	if !found {
		return globalid.Claim{}, fmt.Errorf("%w: %q is absent", ErrGlobalIdentifier, identifier)
	}
	claim, err := globalid.Assert(identifier, snapshot, owner)
	if err != nil {
		return globalid.Claim{}, fmt.Errorf("%w: assert %q: %v", ErrGlobalIdentifier, identifier, err)
	}
	return claim, nil
}

func (p *Planner) transferGlobalID(ctx context.Context, identifier string, expected, next globalid.Owner,
	evidence [32]byte) (globalid.Claim, error) {
	snapshot, found, err := p.view.LookupGlobalID(ctx, identifier)
	if err != nil {
		return globalid.Claim{}, fmt.Errorf("aiinfra iam: lookup global identifier %q: %w", identifier, err)
	}
	if !found || snapshot.Owner != expected {
		return globalid.Claim{}, fmt.Errorf("%w: transfer source %q", ErrGlobalIdentifier, identifier)
	}
	claim, err := globalid.Transfer(identifier, snapshot, next, evidence)
	if err != nil {
		return globalid.Claim{}, fmt.Errorf("%w: transfer %q: %v", ErrGlobalIdentifier, identifier, err)
	}
	return claim, nil
}

func normalizeGlobalClaims(claims []globalid.Claim) ([]globalid.Claim, error) {
	normalized, err := globalid.NormalizeClaims(claims)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGlobalIdentifier, err)
	}
	return normalized, nil
}

// normalizeAggregatedGlobalClaims is used only when independently bounded
// semantic sub-plans are joined. A 256-key cutover can repeat the same exact
// principal/key assertions in many steps, so its raw concatenation can exceed
// globalid.MaxClaims even though the unique transaction claim set cannot.
// Validate before deduplicating and reject different claims for one identifier;
// the ordinary normalizer then enforces the public bound on the unique set.
func normalizeAggregatedGlobalClaims(claims []globalid.Claim) ([]globalid.Claim, error) {
	if len(claims) == 0 || len(claims) > globalid.MaxClaims*4 {
		return nil, fmt.Errorf("%w: aggregated claim count", ErrGlobalIdentifier)
	}
	owned := append([]globalid.Claim(nil), claims...)
	for index := range owned {
		if err := owned[index].Validate(); err != nil {
			return nil, fmt.Errorf("%w: aggregated claim %d: %v", ErrGlobalIdentifier, index, err)
		}
	}
	sort.Slice(owned, func(i, j int) bool {
		return bytes.Compare([]byte(owned[i].Identifier), []byte(owned[j].Identifier)) < 0
	})
	unique := owned[:0]
	for _, claim := range owned {
		if len(unique) == 0 || unique[len(unique)-1].Identifier != claim.Identifier {
			unique = append(unique, claim)
			continue
		}
		if unique[len(unique)-1] != claim {
			return nil, fmt.Errorf("%w: conflicting aggregated identifier %q",
				ErrGlobalIdentifier, claim.Identifier)
		}
	}
	return normalizeGlobalClaims(unique)
}

func (p *Planner) keyMaterialIdentifierClaims(ctx context.Context, entity, target EntityRef,
	principal string, transferDigest [32]byte, at int64) ([]globalid.Claim, globalid.ClaimMode,
	SnapshotPrecondition, error) {
	var claim globalid.Claim
	var err error
	if transferDigest == ([32]byte{}) {
		claim, err = p.reserveGlobalID(ctx, entity.ID, keyGlobalOwner(entity.ID))
	} else {
		claim, err = p.reserveOrAssertFutureIdentityID(ctx, entity.ID, keyGlobalOwner(entity.ID))
	}
	if err != nil {
		return nil, 0, SnapshotPrecondition{}, err
	}
	claims := []globalid.Claim{claim}
	identity, found, err := p.view.LookupIdentityByPrincipal(ctx, entity.PrincipalKind, principal)
	if err != nil {
		return nil, 0, SnapshotPrecondition{}, fmt.Errorf("aiinfra iam: lookup enrollment principal: %w", err)
	}
	targetSnapshot, targetFound, err := p.view.LookupIdentity(ctx, target)
	if err != nil {
		return nil, 0, SnapshotPrecondition{}, fmt.Errorf("aiinfra iam: lookup enrollment target: %w", err)
	}
	if targetFound {
		targetSnapshot, err = normalizeViewIdentity(targetSnapshot)
		if err != nil {
			return nil, 0, SnapshotPrecondition{}, err
		}
	}
	if found {
		identity, err = normalizeViewIdentity(identity)
		if err != nil {
			return nil, 0, SnapshotPrecondition{}, err
		}
	}
	owner := identityGlobalOwner(target)
	var dependency SnapshotPrecondition
	if transferDigest == ([32]byte{}) {
		if found != targetFound || (found && (!sameEntityRef(identity.Ref, target) ||
			!sameEntityRef(targetSnapshot.Ref, target) || identity.PrincipalIdentity != principal ||
			targetSnapshot.PrincipalIdentity != principal)) {
			return nil, 0, SnapshotPrecondition{}, ErrIdentityConflict
		}
		var principalClaim globalid.Claim
		if found {
			principalClaim, err = p.assertGlobalID(ctx, principal, owner)
		} else {
			principalClaim, err = p.reserveOrAssertFutureIdentityID(ctx, principal, owner)
		}
		if err != nil {
			return nil, 0, SnapshotPrecondition{}, err
		}
		claims = append(claims, principalClaim)
		if target.ID != principal {
			targetClaim, targetErr := p.reserveOrAssertFutureIdentityID(ctx, target.ID, owner)
			if targetErr != nil {
				return nil, 0, SnapshotPrecondition{}, targetErr
			}
			claims = append(claims, targetClaim)
		}
		claims, err = normalizeGlobalClaims(claims)
		return claims, principalClaim.Mode, dependency, err
	}

	// A transfer enrollment is staged before the successor identity exists.
	// Resolve the signed transfer by PreviousEntity rather than attempting to
	// discover it through NextPrincipal: Agent principals must rotate, while a
	// Host/Device attestation principal may intentionally remain unchanged.
	if targetFound || (entity.PrincipalKind != 2 && entity.PrincipalKind != 3 && entity.PrincipalKind != 4) {
		return nil, 0, SnapshotPrecondition{}, ErrIdentityConflict
	}
	evidence, evidenceFound, lookupErr := p.view.LookupOwnershipTransfer(ctx, transferDigest)
	if lookupErr != nil {
		return nil, 0, SnapshotPrecondition{}, fmt.Errorf("aiinfra iam: lookup enrollment transfer: %w", lookupErr)
	}
	if !evidenceFound || evidence.EvidenceDigest != transferDigest ||
		!sameEntityRef(evidence.NextEntity, target) || evidence.NextPrincipal != principal ||
		evidence.PreviousEntity.Kind != EntityIdentity ||
		evidence.PreviousEntity.PrincipalKind != entity.PrincipalKind ||
		evidence.PreviousEntity.ID == target.ID || evidence.PreviousGeneration == ^uint64(0) ||
		evidence.NextGeneration != evidence.PreviousGeneration+1 ||
		evidence.CompletedAtUnixNano < 0 || evidence.CompletedAtUnixNano > at ||
		(entity.PrincipalKind == 2 && evidence.PreviousPrincipal == evidence.NextPrincipal) {
		return nil, 0, SnapshotPrecondition{}, ErrIdentityConflict
	}
	previous, previousFound, lookupErr := p.view.LookupIdentity(ctx, evidence.PreviousEntity)
	if lookupErr != nil {
		return nil, 0, SnapshotPrecondition{}, fmt.Errorf("aiinfra iam: lookup previous enrollment identity: %w", lookupErr)
	}
	if !previousFound {
		return nil, 0, SnapshotPrecondition{}, ErrIdentityUnknown
	}
	previous, err = normalizeViewIdentity(previous)
	if err != nil {
		return nil, 0, SnapshotPrecondition{}, err
	}
	if previous.State != 5 || previous.Generation != evidence.PreviousGeneration ||
		previous.PrincipalIdentity != evidence.PreviousPrincipal {
		return nil, 0, SnapshotPrecondition{}, ErrIdentityConflict
	}
	if evidence.PreviousPrincipal == principal {
		if !found || !sameEntityRef(identity.Ref, previous.Ref) || identity.State != 5 {
			return nil, 0, SnapshotPrecondition{}, ErrIdentityConflict
		}
	} else if found {
		return nil, 0, SnapshotPrecondition{}, ErrIdentityConflict
	}
	dependency = identityPrecondition(previous)
	previousOwner := identityGlobalOwner(previous.Ref)
	oldPrincipalClaim, err := p.assertGlobalID(ctx, evidence.PreviousPrincipal, previousOwner)
	if err != nil {
		return nil, 0, SnapshotPrecondition{}, err
	}
	claims = append(claims, oldPrincipalClaim)
	var principalClaim globalid.Claim
	if evidence.PreviousPrincipal == principal {
		principalClaim = oldPrincipalClaim
	} else {
		principalClaim, err = p.reserveOrAssertFutureIdentityID(ctx, principal, owner)
		if err != nil {
			return nil, 0, SnapshotPrecondition{}, err
		}
		claims = append(claims, principalClaim)
	}
	if target.ID != principal {
		targetClaim, targetErr := p.reserveOrAssertFutureIdentityID(ctx, target.ID, owner)
		if targetErr != nil {
			return nil, 0, SnapshotPrecondition{}, targetErr
		}
		claims = append(claims, targetClaim)
	} else if evidence.PreviousPrincipal == principal {
		// A persistent principal cannot simultaneously retain the old owner and
		// reserve the successor entity identifier before final cutover.
		return nil, 0, SnapshotPrecondition{}, ErrGlobalIdentifier
	}
	claims, err = normalizeGlobalClaims(claims)
	return claims, principalClaim.Mode, dependency, err
}

func (p *Planner) reserveOrAssertFutureIdentityID(ctx context.Context, identifier string,
	owner globalid.Owner) (globalid.Claim, error) {
	snapshot, found, err := p.view.LookupGlobalID(ctx, identifier)
	if err != nil {
		return globalid.Claim{}, fmt.Errorf("aiinfra iam: lookup future identity identifier %q: %w", identifier, err)
	}
	if !found {
		return p.reserveGlobalID(ctx, identifier, owner)
	}
	claim, err := globalid.Assert(identifier, snapshot, owner)
	if err != nil {
		return globalid.Claim{}, fmt.Errorf("%w: future identity identifier %q: %v", ErrGlobalIdentifier, identifier, err)
	}
	return claim, nil
}

func (p *Planner) identityIdentifierClaims(ctx context.Context, next IdentitySnapshot, previous *IdentitySnapshot,
	principal PrincipalIndexIntent, transfer *OwnershipTransferSnapshot,
	enrollmentEvidence [32]byte) ([]globalid.Claim, error) {
	claims := make([]globalid.Claim, 0, 4)
	owner := identityGlobalOwner(next.Ref)
	var claim globalid.Claim
	var err error
	if previous != nil {
		claim, err = p.assertGlobalID(ctx, next.Ref.ID, owner)
		if err != nil {
			return nil, err
		}
		claims = append(claims, claim)
		claim, err = p.assertGlobalID(ctx, principal.PrincipalIdentity, owner)
		if err != nil {
			return nil, err
		}
		claims = append(claims, claim)
	} else if principal.Mode == globalid.TransferExisting {
		if next.KeyID == "" {
			claim, err = p.reserveGlobalID(ctx, next.Ref.ID, owner)
		} else {
			claim, err = p.assertGlobalID(ctx, next.Ref.ID, owner)
		}
		if err != nil {
			return nil, err
		}
		claims = append(claims, claim)
		claim, err = p.transferGlobalID(ctx, principal.PrincipalIdentity,
			identityGlobalOwner(principal.ExpectedOwner), owner, principal.TransferEvidenceDigest)
		if err != nil {
			return nil, err
		}
		claims = append(claims, claim)
	} else if next.KeyID != "" {
		if enrollmentEvidence == ([32]byte{}) {
			return nil, ErrGlobalIdentifier
		}
		claim, err = p.assertGlobalID(ctx, principal.PrincipalIdentity, owner)
		if err != nil {
			return nil, err
		}
		claims = append(claims, claim)
		if next.Ref.ID != next.PrincipalIdentity {
			claim, err = p.assertGlobalID(ctx, next.Ref.ID, owner)
			if err != nil {
				return nil, err
			}
			claims = append(claims, claim)
		}
	} else {
		claim, err = p.reserveGlobalID(ctx, next.Ref.ID, owner)
		if err != nil {
			return nil, err
		}
		claims = append(claims, claim)
		claim, err = p.reserveGlobalID(ctx, principal.PrincipalIdentity, owner)
		if err != nil {
			return nil, err
		}
		claims = append(claims, claim)
	}
	if transfer != nil && transfer.PreviousPrincipal != transfer.NextPrincipal {
		claim, err = p.assertGlobalID(ctx, transfer.PreviousPrincipal,
			identityGlobalOwner(transfer.PreviousEntity))
		if err != nil {
			return nil, err
		}
		claims = append(claims, claim)
	}

	recordOwner := recordGlobalOwner(next.Ref, next.RecordID)
	var record globalid.Claim
	if transfer != nil {
		record, err = p.reserveOrAssertFutureIdentityID(ctx, next.RecordID, recordOwner)
	} else {
		record, err = p.reserveGlobalID(ctx, next.RecordID, recordOwner)
	}
	if err != nil {
		return nil, err
	}
	claims = append(claims, record)
	return normalizeGlobalClaims(claims)
}

func (p *Planner) lifecycleIdentifierClaims(ctx context.Context, next KeyLifecycleSnapshot,
	targetIdentity EntityRef, subject SnapshotPrecondition, subjectAbsent, recordPreReserved bool) ([]globalid.Claim, error) {
	claims := make([]globalid.Claim, 0, 4)
	keyClaim, err := p.assertGlobalID(ctx, next.KeyID, keyGlobalOwner(next.KeyID))
	if err != nil {
		return nil, err
	}
	claims = append(claims, keyClaim)
	recordOwner := recordGlobalOwner(EntityRef{Kind: EntityKeyLifecycle, PrincipalKind: next.SubjectKind, ID: next.KeyID}, next.RecordID)
	var record globalid.Claim
	if recordPreReserved {
		record, err = p.assertGlobalID(ctx, next.RecordID, recordOwner)
	} else {
		record, err = p.reserveGlobalID(ctx, next.RecordID, recordOwner)
	}
	if err != nil {
		return nil, err
	}
	claims = append(claims, record)
	if subjectAbsent {
		owner := identityGlobalOwner(targetIdentity)
		claim, claimErr := p.assertGlobalID(ctx, next.SubjectIdentity, owner)
		if claimErr != nil {
			return nil, claimErr
		}
		claims = append(claims, claim)
		if targetIdentity.ID != next.SubjectIdentity {
			claim, claimErr = p.assertGlobalID(ctx, targetIdentity.ID, owner)
			if claimErr != nil {
				return nil, claimErr
			}
			claims = append(claims, claim)
		}
	} else if subject.Entity.Kind == EntityIdentity {
		claim, claimErr := p.assertGlobalID(ctx, next.SubjectIdentity, identityGlobalOwner(subject.Entity))
		if claimErr != nil {
			return nil, claimErr
		}
		claims = append(claims, claim)
	}
	if !subjectAbsent && targetIdentity.ID != next.SubjectIdentity {
		claim, claimErr := p.assertGlobalID(ctx, targetIdentity.ID, identityGlobalOwner(targetIdentity))
		if claimErr != nil {
			return nil, claimErr
		}
		claims = append(claims, claim)
	}
	return normalizeGlobalClaims(claims)
}
