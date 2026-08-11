// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"context"
	"fmt"
	"sort"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/schema"
)

const (
	resolvedLifecycleSnapshotDomain = "CPH-AIIE-IAM-RESOLVED-LIFECYCLE-SNAPSHOT-V1\x00"
	resolvedIdentitySnapshotDomain  = "CPH-AIIE-IAM-RESOLVED-IDENTITY-SNAPSHOT-V1\x00"
)

// KeySnapshotResolver pins one detached schema registry for its whole
// lifetime. Historical lifecycle decisions therefore cannot change because a
// process-global/default registry is upgraded between calls.
type KeySnapshotResolver struct {
	view     View
	registry schema.Registry
}

func NewKeySnapshotResolver(view View, registry schema.Registry) (*KeySnapshotResolver, error) {
	if view == nil {
		return nil, ErrViewRequired
	}
	canonical, err := registry.CanonicalJSON()
	if err != nil {
		return nil, fmt.Errorf("aiinfra iam: resolver registry: %w", err)
	}
	detached, err := schema.Parse(canonical)
	if err != nil {
		return nil, fmt.Errorf("aiinfra iam: resolver registry copy: %w", err)
	}
	return &KeySnapshotResolver{view: view, registry: detached}, nil
}

func NewDefaultKeySnapshotResolver(view View) (*KeySnapshotResolver, error) {
	registry, err := schema.LoadDefault()
	if err != nil {
		return nil, err
	}
	return NewKeySnapshotResolver(view, registry)
}

// ResolveKeySnapshot composes immutable material and lifecycle state without
// applying a caller-specific role or time policy. Governance must still add
// exact enrollment-domain, role, separation and operation-time checks.
func (resolver *KeySnapshotResolver) ResolveKeySnapshot(ctx context.Context, keyID string) (ResolvedKeySnapshot, error) {
	if resolver == nil {
		return ResolvedKeySnapshot{}, ErrViewRequired
	}
	return resolveKeySnapshot(ctx, resolver.view, resolver.registry, keyID)
}

func resolveKeySnapshot(ctx context.Context, view View, registry schema.Registry, keyID string) (ResolvedKeySnapshot, error) {
	if view == nil {
		return ResolvedKeySnapshot{}, ErrViewRequired
	}
	material, found, err := view.LookupKeyMaterial(ctx, keyID)
	if err != nil {
		return ResolvedKeySnapshot{}, fmt.Errorf("aiinfra iam: lookup key material: %w", err)
	}
	if !found {
		return ResolvedKeySnapshot{}, ErrKeyMaterialUnknown
	}
	material, err = validateMaterialSnapshot(material)
	if err != nil {
		return ResolvedKeySnapshot{}, err
	}
	keyIdentifier, keyFound, err := view.LookupGlobalID(ctx, material.KeyID)
	if err != nil {
		return ResolvedKeySnapshot{}, fmt.Errorf("aiinfra iam: lookup key global identifier: %w", err)
	}
	if !keyFound {
		return ResolvedKeySnapshot{}, ErrGlobalIdentifier
	}
	if _, err := globalid.Assert(material.KeyID, keyIdentifier, keyGlobalOwner(material.KeyID)); err != nil {
		return ResolvedKeySnapshot{}, ErrGlobalIdentifier
	}
	lifecycle, found, err := view.LookupKeyLifecycle(ctx, keyID)
	if err != nil {
		return ResolvedKeySnapshot{}, fmt.Errorf("aiinfra iam: lookup key lifecycle: %w", err)
	}
	if !found {
		return ResolvedKeySnapshot{}, ErrLifecycleUnknown
	}
	lifecycle, err = normalizeViewLifecycle(lifecycle)
	if err != nil {
		return ResolvedKeySnapshot{}, err
	}
	if lifecycle.KeyID != material.KeyID || lifecycle.SubjectIdentity != material.SubjectIdentity ||
		lifecycle.SubjectKind != material.SubjectKind || lifecycle.Algorithm != material.Algorithm {
		return ResolvedKeySnapshot{}, ErrKeyMaterialMismatch
	}
	identity, found, err := view.LookupIdentityByPrincipal(ctx, material.SubjectKind, material.SubjectIdentity)
	if err != nil {
		return ResolvedKeySnapshot{}, fmt.Errorf("aiinfra iam: lookup key subject identity: %w", err)
	}
	if !found {
		return ResolvedKeySnapshot{}, ErrIdentityUnknown
	}
	identity, err = normalizeViewIdentity(identity)
	if err != nil {
		return ResolvedKeySnapshot{}, err
	}
	if !sameEntityRef(identity.Ref, material.TargetIdentity) || identity.PrincipalIdentity != material.SubjectIdentity ||
		identity.State != 2 || identity.KeyID != material.KeyID ||
		lifecycle.NotBeforeUnixNano < identity.ValidFromUnixNano || lifecycle.NotAfterUnixNano > identity.ValidUntilUnixNano {
		return ResolvedKeySnapshot{}, ErrIdentityConflict
	}
	owner := identityGlobalOwner(identity.Ref)
	for _, identifier := range []string{identity.Ref.ID, identity.PrincipalIdentity} {
		snapshot, globalFound, lookupErr := view.LookupGlobalID(ctx, identifier)
		if lookupErr != nil {
			return ResolvedKeySnapshot{}, fmt.Errorf("aiinfra iam: lookup key subject global identifier: %w", lookupErr)
		}
		if !globalFound {
			return ResolvedKeySnapshot{}, ErrGlobalIdentifier
		}
		if _, assertErr := globalid.Assert(identifier, snapshot, owner); assertErr != nil {
			return ResolvedKeySnapshot{}, ErrGlobalIdentifier
		}
	}
	for _, id := range lifecycle.AllowedMessageTypeIDs {
		if _, ok := registry.LookupMessage(id); !ok {
			return ResolvedKeySnapshot{}, fmt.Errorf("%w: %d", ErrUnknownMessageType, id)
		}
	}
	allowed := append([]uint32(nil), lifecycle.AllowedMessageTypeIDs...)
	sort.Slice(allowed, func(i, j int) bool { return allowed[i] < allowed[j] })
	snapshotDigest := domainDigest(resolvedLifecycleSnapshotDomain, lifecycle.CanonicalPayload)
	identityDigest := domainDigest(resolvedIdentitySnapshotDomain, identity.CanonicalPayload)
	return ResolvedKeySnapshot{
		KeyID: keyID, SubjectIdentity: material.SubjectIdentity, SubjectKind: material.SubjectKind,
		Algorithm: material.Algorithm, PublicKey: append([]byte(nil), material.CanonicalPublicKey...),
		EnrollmentDomain: material.EnrollmentDomain, TargetIdentity: material.TargetIdentity,
		State: lifecycle.State, StateVersion: lifecycle.StateVersion, WriterEpoch: lifecycle.WriterEpoch,
		SnapshotDigest: snapshotDigest, NotBeforeUnixNano: lifecycle.NotBeforeUnixNano,
		NotAfterUnixNano: lifecycle.NotAfterUnixNano, RevokedAtUnixNano: lifecycle.RevokedAtUnixNano,
		AllowedMessageTypeIDs:           allowed,
		AuthorizationPolicyDigestSHA256: lifecycle.AuthorizationPolicyDigestSHA256,
		IdentityStateVersion:            identity.StateVersion, IdentityWriterEpoch: identity.WriterEpoch,
		IdentitySnapshotDigest:     identityDigest,
		IdentityValidFromUnixNano:  identity.ValidFromUnixNano,
		IdentityValidUntilUnixNano: identity.ValidUntilUnixNano,
	}, nil
}

func validateMaterialSnapshot(material KeyMaterialSnapshot) (KeyMaterialSnapshot, error) {
	if len(material.CanonicalPublicKey) != 32 || len(material.ProofSignature) != 64 ||
		len(material.EnrollmentPolicyDigestsSHA256) == 0 || len(material.EnrollmentPolicyDigestsSHA256) > 64 {
		return KeyMaterialSnapshot{}, ErrViewInconsistent
	}
	material = cloneKeyMaterial(material)
	policies, err := canonicalDigests(material.EnrollmentPolicyDigestsSHA256)
	if err != nil {
		return KeyMaterialSnapshot{}, ErrViewInconsistent
	}
	material.EnrollmentPolicyDigestsSHA256 = policies
	if material.KeyID == "" || material.SubjectIdentity == "" || material.SubjectKind < 1 || material.SubjectKind > 8 ||
		material.EnrollmentDomain.EnrollmentDomainID == "" || material.EnrollmentDomain.Environment == "" ||
		material.EnrollmentDomain.GenesisHash == ([32]byte{}) ||
		material.EnrollmentAuthorityIdentity == "" ||
		material.WriterIdentity == "" || material.HomeRegion == "" || material.WriterEpoch == 0 || material.StateVersion != 1 ||
		material.IdempotencyKey == ([16]byte{}) ||
		material.ProofChallenge == ([32]byte{}) || material.ProofExpiresAtUnixNano <= 0 ||
		material.ProofDigest == ([32]byte{}) || material.ChallengeEvidenceDigest == ([32]byte{}) ||
		material.EnrollmentBindingDigest == ([32]byte{}) {
		return KeyMaterialSnapshot{}, ErrViewInconsistent
	}
	if err := validateTargetIdentity(material.TargetIdentity, material.SubjectKind); err != nil {
		return KeyMaterialSnapshot{}, ErrViewInconsistent
	}
	if err := ValidateKeyID(material.KeyID, material.Algorithm, material.CanonicalPublicKey); err != nil {
		return KeyMaterialSnapshot{}, fmt.Errorf("%w: %v", ErrViewInconsistent, err)
	}
	digest, err := VerifyProofOfPossession(material.Algorithm, material.CanonicalPublicKey, material.KeyID,
		material.SubjectIdentity, material.SubjectKind, material.TargetIdentity, material.TransferEvidenceDigest,
		material.EnrollmentDomain, material.ProofChallenge,
		material.ProofExpiresAtUnixNano, material.ProofSignature)
	if err != nil || digest != material.ProofDigest {
		return KeyMaterialSnapshot{}, ErrViewInconsistent
	}
	binding, err := enrollmentBindingDigest(material)
	if err != nil || binding != material.EnrollmentBindingDigest {
		return KeyMaterialSnapshot{}, ErrViewInconsistent
	}
	return material, nil
}

// VerificationKeyResolver adapts deployment-scoped IAM snapshots to
// ccse.KeyResolver. It cannot be constructed without the exact enrollment
// deployment anchor; a package literal cannot bypass that comparison.
type VerificationKeyResolver struct {
	keys           *KeySnapshotResolver
	expectedDomain EnrollmentDomain
}

func NewVerificationKeyResolver(view View, expectedDomain EnrollmentDomain) (*VerificationKeyResolver, error) {
	registry, err := schema.LoadDefault()
	if err != nil {
		return nil, err
	}
	return NewVerificationKeyResolverWithRegistry(view, expectedDomain, registry)
}

func NewVerificationKeyResolverWithRegistry(view View, expectedDomain EnrollmentDomain, registry schema.Registry) (*VerificationKeyResolver, error) {
	if view == nil {
		return nil, ErrViewRequired
	}
	if err := validateEnrollmentDomain(expectedDomain); err != nil {
		return nil, err
	}
	keys, err := NewKeySnapshotResolver(view, registry)
	if err != nil {
		return nil, err
	}
	return &VerificationKeyResolver{keys: keys, expectedDomain: expectedDomain}, nil
}

func (resolver *VerificationKeyResolver) ResolveKey(ctx context.Context, keyID string) (ccse.KeyRecord, error) {
	if resolver == nil || resolver.keys == nil {
		return ccse.KeyRecord{}, ErrViewRequired
	}
	resolved, err := resolver.keys.ResolveKeySnapshot(ctx, keyID)
	if err != nil {
		if err == ErrKeyMaterialUnknown || err == ErrLifecycleUnknown {
			return ccse.KeyRecord{}, ccse.ErrUnknownKey
		}
		return ccse.KeyRecord{}, err
	}
	if resolved.EnrollmentDomain != resolver.expectedDomain {
		return ccse.KeyRecord{}, ErrKeyMaterialMismatch
	}
	switch resolved.State {
	case 1, 5:
		return ccse.KeyRecord{}, ccse.ErrKeyNotActive
	case 2, 3, 4:
	default:
		return ccse.KeyRecord{}, ccse.ErrKeyNotActive
	}
	return ccse.KeyRecord{
		KeyID: resolved.KeyID, SubjectIdentity: resolved.SubjectIdentity, Algorithm: resolved.Algorithm,
		PublicKey: append([]byte(nil), resolved.PublicKey...), NotBeforeUnixNano: resolved.NotBeforeUnixNano,
		NotAfterUnixNano: resolved.NotAfterUnixNano, RevokedAtUnixNano: resolved.RevokedAtUnixNano,
		AllowedMessageTypes: append([]uint32(nil), resolved.AllowedMessageTypeIDs...),
	}, nil
}
