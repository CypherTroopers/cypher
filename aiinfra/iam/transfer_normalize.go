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
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

const (
	transferProfileDigestDomain     = "CPH-AIIE-IAM-OWNERSHIP-TRANSFER-PROFILE-V1\x00"
	transferProfileActivationDomain = "CPH-AIIE-IAM-OWNERSHIP-TRANSFER-PROFILE-ACTIVATION-V1\x00"
	transferAdmissionDigestDomain   = "CPH-AIIE-IAM-OWNERSHIP-TRANSFER-AUTHORITY-ADMISSION-V1\x00"
)

func transferVerifiedRecordLimits(maxPayload int) ccse.Limits {
	return ccse.Limits{MaxDomainBytes: 64 << 10, MaxEnvelopeBytes: 64 << 10,
		MaxPayloadBytes: maxPayload, MaxSignatureBytes: 64}
}

func normalizeOwnershipTransferPayload(payload []byte) (foundationv1.OwnershipTransferAuthorizationSigningProjection,
	[]byte, [32]byte, error) {
	var zero [32]byte
	if len(payload) == 0 || len(payload) > 196608 {
		return foundationv1.OwnershipTransferAuthorizationSigningProjection{}, nil, zero, ErrTransferAuthorizationRequired
	}
	validator, err := foundationCanonicalValidator()
	if err != nil {
		return foundationv1.OwnershipTransferAuthorizationSigningProjection{}, nil, zero, err
	}
	decoded, err := validator.Decode(schema.MessageTypeOwnershipTransferAuthorization,
		ccse.Version{Major: 1}, payload)
	if err != nil {
		return foundationv1.OwnershipTransferAuthorizationSigningProjection{}, nil, zero,
			fmt.Errorf("%w: decode transfer payload: %v", ErrTransferAuthorizationRequired, err)
	}
	projection, ok := decoded.(foundationv1.OwnershipTransferAuthorizationSigningProjection)
	if !ok {
		return foundationv1.OwnershipTransferAuthorizationSigningProjection{}, nil, zero, ErrTransferAuthorizationRequired
	}
	canonical, err := projection.CanonicalBytes()
	if err != nil || !bytes.Equal(canonical, payload) || projection.Metadata.StateVersion != 1 {
		return foundationv1.OwnershipTransferAuthorizationSigningProjection{}, nil, zero, ErrTransferAuthorizationRequired
	}
	return cloneTransferProjection(projection), append([]byte(nil), canonical...), sha256.Sum256(canonical), nil
}

func transferProfileRequest(projection foundationv1.OwnershipTransferAuthorizationSigningProjection) OwnershipTransferProfileRequest {
	return OwnershipTransferProfileRequest{
		TransferAuthorizationID: projection.TransferAuthorizationID,
		SubjectKind:             projection.SubjectKind,
		PreviousEntity: EntityRef{Kind: EntityIdentity, PrincipalKind: projection.SubjectKind,
			ID: projection.PreviousEntityID},
		NextEntity: EntityRef{Kind: EntityIdentity, PrincipalKind: projection.SubjectKind,
			ID: projection.NextEntityID},
		PreviousPrincipal:   projection.PreviousPrincipalIdentity,
		NextPrincipal:       projection.NextPrincipalIdentity,
		PreviousProviderID:  projection.PreviousProviderID,
		NextProviderID:      projection.NextProviderID,
		ExpectedGeneration:  projection.ExpectedGeneration,
		NextGeneration:      projection.NextGeneration,
		EffectiveAtUnixNano: projection.EffectiveAtUnixNano,
		ExpiresAtUnixNano:   projection.ExpiresAtUnixNano,
	}
}

func normalizeTransferProfile(profile OwnershipTransferProfile,
	projection foundationv1.OwnershipTransferAuthorizationSigningProjection) (OwnershipTransferProfile, [32]byte, error) {
	var zero [32]byte
	if profile.ProfileID == "" || profile.ProfileVersion == 0 || profile.PolicyDigest == zero ||
		profile.RecordIntegrityDigestSHA256 == zero ||
		profile.RecordIntegrityDigestSHA256 != projection.Metadata.IntegrityDigest ||
		len(profile.OldAuthorities) == 0 || len(profile.OldAuthorities) > 32 ||
		len(profile.NewAuthorities) == 0 || len(profile.NewAuthorities) > 32 ||
		len(profile.OldAuthorities)+len(profile.NewAuthorities) > maxTransferAuthorities {
		return OwnershipTransferProfile{}, zero, ErrTransferAuthorizationRequired
	}
	profile = cloneTransferProfile(profile)
	sortTransferRequirements(profile.OldAuthorities)
	sortTransferRequirements(profile.NewAuthorities)
	oldPairs := transferProjectionAuthorities(projection.OldAuthorities)
	newPairs := transferProjectionAuthorities(projection.NewAuthorities)
	if !requirementsMatchPairs(profile.OldAuthorities, oldPairs) ||
		!requirementsMatchPairs(profile.NewAuthorities, newPairs) {
		return OwnershipTransferProfile{}, zero, ErrTransferAuthorizationRequired
	}
	identities := make(map[string]struct{}, len(profile.OldAuthorities)+len(profile.NewAuthorities))
	keys := make(map[string]struct{}, len(identities))
	oldOrganizations := make(map[string]struct{})
	coordinators := 0
	validate := func(values []OwnershipTransferAuthorityRequirement, provider string, old bool) error {
		for _, value := range values {
			if value.Identity == "" || value.KeyID == "" || value.ProviderID != provider ||
				value.OrganizationID == "" || value.Role == "" ||
				value.AuthorizationPolicyDigestSHA256 == zero {
				return ErrTransferAuthorizationRequired
			}
			if _, duplicate := identities[value.Identity]; duplicate {
				return ErrTransferAuthorizationRequired
			}
			if _, duplicate := keys[value.KeyID]; duplicate {
				return ErrTransferAuthorizationRequired
			}
			identities[value.Identity] = struct{}{}
			keys[value.KeyID] = struct{}{}
			if old {
				if value.Coordinator {
					return ErrTransferAuthorizationRequired
				}
				oldOrganizations[value.OrganizationID] = struct{}{}
			} else {
				if _, overlaps := oldOrganizations[value.OrganizationID]; overlaps {
					return ErrTransferAuthorizationRequired
				}
				if value.Coordinator {
					coordinators++
				}
			}
		}
		return nil
	}
	if err := validate(profile.OldAuthorities, projection.PreviousProviderID, true); err != nil {
		return OwnershipTransferProfile{}, zero, err
	}
	if err := validate(profile.NewAuthorities, projection.NextProviderID, false); err != nil || coordinators != 1 {
		return OwnershipTransferProfile{}, zero, ErrTransferAuthorizationRequired
	}
	expectedPolicies := [][32]byte{profile.PolicyDigest}
	for _, requirement := range profile.OldAuthorities {
		expectedPolicies = append(expectedPolicies, requirement.AuthorizationPolicyDigestSHA256)
	}
	for _, requirement := range profile.NewAuthorities {
		expectedPolicies = append(expectedPolicies, requirement.AuthorizationPolicyDigestSHA256)
	}
	expectedPolicies = uniqueDigests(expectedPolicies)
	actualPolicies, err := canonicalDigests(projection.Metadata.PolicyDigestsSHA256)
	if err != nil || !equalDigestSlices(expectedPolicies, actualPolicies) {
		return OwnershipTransferProfile{}, zero, ErrTransferAuthorizationRequired
	}
	encoded, err := encodeTransferProfilePolicy(profile)
	if err != nil {
		return OwnershipTransferProfile{}, zero, ErrTransferAuthorizationRequired
	}
	profileDigest := domainDigest(transferProfileDigestDomain, encoded)
	activationDigest, activationErr := transferProfileActivationDigest(profile.ProfileID,
		profile.ProfileVersion, profile.Activation)
	if activationErr != nil || profile.Activation.ProfileDigest != profileDigest ||
		profile.Activation.SnapshotDigest != activationDigest {
		return OwnershipTransferProfile{}, zero, ErrTransferAuthorizationRequired
	}
	return profile, profileDigest, nil
}

func transferProfileActivationDigest(profileID string, profileVersion uint64,
	activation OwnershipTransferProfileActivation) ([32]byte, error) {
	var zero [32]byte
	if profileID == "" || profileVersion == 0 || activation.ProfileDigest == zero ||
		activation.ActivationVersion == 0 || activation.ValidFromUnixNano < 0 ||
		activation.ValidUntilUnixNano <= activation.ValidFromUnixNano || activation.EvidenceDigest == zero ||
		activation.StateVersion == 0 || activation.WriterEpoch == 0 {
		return zero, ErrTransferAuthorizationRequired
	}
	encoded, err := ccse.Marshal(512, func(out *ccse.Encoder) {
		out.String(profileID)
		out.Uint64(profileVersion)
		out.FixedBytes(activation.ProfileDigest[:], 32)
		out.Uint64(activation.ActivationVersion)
		out.Int64(activation.ValidFromUnixNano)
		out.Int64(activation.ValidUntilUnixNano)
		out.FixedBytes(activation.EvidenceDigest[:], 32)
		out.Uint64(activation.StateVersion)
		out.Uint64(activation.WriterEpoch)
	})
	if err != nil {
		return zero, ErrTransferAuthorizationRequired
	}
	return domainDigest(transferProfileActivationDomain, encoded), nil
}

func sortTransferRequirements(values []OwnershipTransferAuthorityRequirement) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].Identity != values[j].Identity {
			return values[i].Identity < values[j].Identity
		}
		return values[i].KeyID < values[j].KeyID
	})
}

func transferProjectionAuthorities(values []foundationv1.TransferAuthoritySigningProjection) []foundationv1.TransferAuthoritySigningProjection {
	result := append([]foundationv1.TransferAuthoritySigningProjection(nil), values...)
	sort.Slice(result, func(i, j int) bool {
		if result[i].Identity != result[j].Identity {
			return result[i].Identity < result[j].Identity
		}
		return result[i].KeyID < result[j].KeyID
	})
	return result
}

func requirementsMatchPairs(requirements []OwnershipTransferAuthorityRequirement,
	pairs []foundationv1.TransferAuthoritySigningProjection) bool {
	if len(requirements) != len(pairs) {
		return false
	}
	for index := range requirements {
		if requirements[index].Identity != pairs[index].Identity || requirements[index].KeyID != pairs[index].KeyID {
			return false
		}
	}
	return true
}

func encodeTransferRequirements(values []OwnershipTransferAuthorityRequirement) ([][]byte, error) {
	elements := make([][]byte, len(values))
	var err error
	for index, value := range values {
		elements[index], err = ccse.Marshal(8192, func(out *ccse.Encoder) {
			out.String(value.Identity)
			out.String(value.KeyID)
			out.String(value.ProviderID)
			out.String(value.OrganizationID)
			out.String(value.Role)
			out.FixedBytes(value.AuthorizationPolicyDigestSHA256[:], 32)
			out.Bool(value.Coordinator)
		})
		if err != nil {
			return nil, ErrTransferAuthorizationRequired
		}
	}
	return elements, nil
}

func retainedVerifiedRecord(verified ccse.VerifiedRecord) (RetainedVerifiedRecord, error) {
	record := verified.Record()
	if record.MessageTypeID == 0 || verified.Digest() == ([32]byte{}) ||
		record.MessageTypeID != verified.MessageTypeID() || record.SchemaVersion != verified.SchemaVersion() {
		return RetainedVerifiedRecord{}, ErrTransferAuthorizationRequired
	}
	digest, err := record.Digest(ccse.DefaultLimits())
	if err != nil || digest != verified.Digest() {
		return RetainedVerifiedRecord{}, ErrTransferAuthorizationRequired
	}
	if _, err := canonicalSignedAuthorizationEvidence(record); err != nil {
		return RetainedVerifiedRecord{}, ErrTransferAuthorizationRequired
	}
	return RetainedVerifiedRecord{record: cloneCCSERecord(record), digest: digest}, nil
}

func (p *Planner) validateTransferAuthorityAdmission(ctx context.Context,
	verified ccse.VerifiedRecord, projection foundationv1.OwnershipTransferAuthorizationSigningProjection,
	canonical []byte, profile OwnershipTransferProfile, profileDigest [32]byte,
	at int64) (OwnershipTransferAuthorityAdmission, error) {
	authorization := AuthorizationFromVerifiedRecord(verified)
	if _, _, err := validateAuthorizationSourceRecord(authorization); err != nil {
		return OwnershipTransferAuthorityAdmission{}, err
	}
	if authorization.messageTypeID != schema.MessageTypeOwnershipTransferAuthorization ||
		authorization.schemaVersion != (ccse.Version{Major: 1}) ||
		!bytes.Equal(authorization.payload, canonical) || authorization.messageID == ([16]byte{}) ||
		projection.Metadata.CreatedAtUnixNano > authorization.issuedAtUnixNano ||
		authorization.issuedAtUnixNano > at || at >= authorization.expiresAtUnixNano ||
		authorization.counterKind != ccse.CounterExpectedGeneration || authorization.counter != projection.ExpectedGeneration {
		return OwnershipTransferAuthorityAdmission{}, ErrTransferAuthorizationRequired
	}
	receiver, err := p.profile.ReceiverProfile(ctx, schema.MessageTypeOwnershipTransferAuthorization)
	if err != nil || validateReceiverProfile(receiver) != nil || validateAudienceSet(authorization.audience) != nil {
		return OwnershipTransferAuthorityAdmission{}, ErrAuthorizationMismatch
	}
	// The counter is the previous identity's ownership generation. Scoping by
	// TransferAuthorizationID would allow competing transfer IDs for the same
	// entity/generation to each consume an independent replay namespace.
	replayEntity := EntityRef{Kind: EntityIdentity, PrincipalKind: projection.SubjectKind,
		ID: projection.PreviousEntityID}
	expectedReplayDomain, err := DeriveEntityReplayDomainID(receiver.ReplayDomainID, replayEntity)
	if err != nil {
		return OwnershipTransferAuthorityAdmission{}, ErrAuthorizationMismatch
	}
	if receiver.ProtocolVersion != authorization.protocolVersion || receiver.SchemaVersion != authorization.schemaVersion ||
		receiver.Purpose != authorization.purpose || !sameStringSet(receiver.Audience, authorization.audience) ||
		receiver.TenantOrganization != authorization.tenantOrganization ||
		(receiver.ProviderOrganization.Present && receiver.ProviderOrganization != authorization.providerOrganization) ||
		receiver.Environment != authorization.environment || receiver.ChainID != authorization.chainID ||
		receiver.GenesisHash != authorization.genesisHash || expectedReplayDomain != authorization.replayDomainID ||
		receiver.CounterKind != ccse.CounterExpectedGeneration || receiver.EnrollmentDomainID == "" ||
		authorization.expiresAtUnixNano-authorization.issuedAtUnixNano > receiver.MaxValidityWindowNanos {
		return OwnershipTransferAuthorityAdmission{}, ErrAuthorizationMismatch
	}
	requirement, oldSide, found := transferAuthorityRequirement(profile, authorization.senderIdentity,
		authorization.signatureKeyID)
	if !found || !authorization.providerOrganization.Present ||
		authorization.providerOrganization.Value != requirement.OrganizationID {
		return OwnershipTransferAuthorityAdmission{}, ErrTransferAuthorizationRequired
	}
	historical, err := p.resolveHistoricalTransferAuthority(ctx, requirement, authorization, receiver)
	if err != nil {
		return OwnershipTransferAuthorityAdmission{}, err
	}
	if err := verifyAuthorizationWithMaterial(authorization, historical.Material.Algorithm,
		historical.Material.CanonicalPublicKey, historical.Material.KeyID); err != nil {
		return OwnershipTransferAuthorityAdmission{}, err
	}
	current, err := p.validateCurrentTransferAuthority(ctx, requirement, authorization.issuedAtUnixNano, at)
	if err != nil {
		return OwnershipTransferAuthorityAdmission{}, err
	}
	retained, err := retainedVerifiedRecord(verified)
	if err != nil {
		return OwnershipTransferAuthorityAdmission{}, err
	}
	admission := OwnershipTransferAuthorityAdmission{Authority: requirement, OldSide: oldSide,
		Signed: retained, Historical: historical, CurrentPreconditions: current.Dependencies,
		Receiver:                  cloneReceiverProfile(receiver),
		AdmissionProfileDigest:    profileDigest,
		AdmissionActivationDigest: profile.Activation.SnapshotDigest, ValidatedAtUnixNano: at}
	admission.Fingerprint, err = transferAuthorityAdmissionFingerprint(admission)
	if err != nil {
		return OwnershipTransferAuthorityAdmission{}, err
	}
	return admission, nil
}

func transferAuthorityRequirement(profile OwnershipTransferProfile, identity, keyID string) (
	OwnershipTransferAuthorityRequirement, bool, bool) {
	for _, requirement := range profile.OldAuthorities {
		if requirement.Identity == identity && requirement.KeyID == keyID {
			return requirement, true, true
		}
	}
	for _, requirement := range profile.NewAuthorities {
		if requirement.Identity == identity && requirement.KeyID == keyID {
			return requirement, false, true
		}
	}
	return OwnershipTransferAuthorityRequirement{}, false, false
}

func (p *Planner) resolveHistoricalTransferAuthority(ctx context.Context,
	requirement OwnershipTransferAuthorityRequirement, authorization VerifiedAuthorization,
	receiver ReceiverProfile) (HistoricalKeyAuthorizationSnapshot, error) {
	material, found, err := p.view.LookupKeyMaterial(ctx, requirement.KeyID)
	if err != nil || !found {
		return HistoricalKeyAuthorizationSnapshot{}, ErrKeyMaterialUnknown
	}
	material, err = validateMaterialSnapshot(material)
	if err != nil || material.SubjectIdentity != requirement.Identity ||
		material.EnrollmentDomain.EnrollmentDomainID != receiver.EnrollmentDomainID ||
		material.EnrollmentDomain.Environment != authorization.environment ||
		material.EnrollmentDomain.GenesisHash != authorization.genesisHash {
		return HistoricalKeyAuthorizationSnapshot{}, ErrAuthorizationMismatch
	}
	lifecycle, found, err := p.view.LookupKeyLifecycleAt(ctx, requirement.KeyID, authorization.issuedAtUnixNano)
	if err != nil || !found {
		return HistoricalKeyAuthorizationSnapshot{}, ErrLifecycleUnknown
	}
	lifecycle, err = normalizeViewLifecycle(lifecycle)
	if err != nil || lifecycle.KeyID != requirement.KeyID || lifecycle.SubjectIdentity != requirement.Identity ||
		(lifecycle.State != 2 && lifecycle.State != 3) || lifecycle.RevokedAtUnixNano != 0 ||
		lifecycle.AuthorizationPolicyDigestSHA256 != requirement.AuthorizationPolicyDigestSHA256 ||
		authorization.issuedAtUnixNano < lifecycle.NotBeforeUnixNano ||
		authorization.expiresAtUnixNano > lifecycle.NotAfterUnixNano ||
		!containsUint32(lifecycle.AllowedMessageTypeIDs, schema.MessageTypeOwnershipTransferAuthorization) {
		return HistoricalKeyAuthorizationSnapshot{}, ErrAuthorizationMismatch
	}
	identity, found, err := p.view.LookupIdentityAt(ctx, material.TargetIdentity, authorization.issuedAtUnixNano)
	if err != nil || !found {
		return HistoricalKeyAuthorizationSnapshot{}, ErrIdentityUnknown
	}
	identity, err = normalizeViewIdentity(identity)
	if err != nil || !sameEntityRef(identity.Ref, material.TargetIdentity) || identity.State != 2 ||
		identity.PrincipalIdentity != requirement.Identity || identity.KeyID != requirement.KeyID ||
		identity.CreatedAtUnixNano > authorization.issuedAtUnixNano ||
		authorization.issuedAtUnixNano < identity.ValidFromUnixNano || authorization.expiresAtUnixNano > identity.ValidUntilUnixNano {
		return HistoricalKeyAuthorizationSnapshot{}, ErrAuthorizationMismatch
	}
	return HistoricalKeyAuthorizationSnapshot{Material: material, Lifecycle: lifecycle, Identity: identity}, nil
}

func (p *Planner) resolveHistoricalEvidenceAuthorization(ctx context.Context,
	authorization VerifiedAuthorization, receiver ReceiverProfile) (HistoricalKeyAuthorizationSnapshot, error) {
	material, found, err := p.view.LookupKeyMaterial(ctx, authorization.signatureKeyID)
	if err != nil || !found {
		return HistoricalKeyAuthorizationSnapshot{}, ErrKeyMaterialUnknown
	}
	material, err = validateMaterialSnapshot(material)
	if err != nil || material.SubjectIdentity != authorization.senderIdentity ||
		material.EnrollmentDomain.EnrollmentDomainID != receiver.EnrollmentDomainID ||
		material.EnrollmentDomain.Environment != authorization.environment ||
		material.EnrollmentDomain.GenesisHash != authorization.genesisHash {
		return HistoricalKeyAuthorizationSnapshot{}, ErrAuthorizationMismatch
	}
	lifecycle, found, err := p.view.LookupKeyLifecycleAt(ctx, material.KeyID,
		authorization.issuedAtUnixNano)
	if err != nil || !found {
		return HistoricalKeyAuthorizationSnapshot{}, ErrLifecycleUnknown
	}
	lifecycle, err = normalizeViewLifecycle(lifecycle)
	if err != nil || lifecycle.KeyID != material.KeyID ||
		lifecycle.SubjectIdentity != material.SubjectIdentity || lifecycle.SubjectKind != material.SubjectKind ||
		lifecycle.Algorithm != material.Algorithm || (lifecycle.State != 2 && lifecycle.State != 3) ||
		lifecycle.RevokedAtUnixNano != 0 || authorization.issuedAtUnixNano < lifecycle.NotBeforeUnixNano ||
		authorization.expiresAtUnixNano > lifecycle.NotAfterUnixNano ||
		!containsUint32(lifecycle.AllowedMessageTypeIDs, schema.MessageTypeEvidenceRecord) {
		return HistoricalKeyAuthorizationSnapshot{}, ErrAuthorizationMismatch
	}
	identity, found, err := p.view.LookupIdentityAt(ctx, material.TargetIdentity,
		authorization.issuedAtUnixNano)
	if err != nil || !found {
		return HistoricalKeyAuthorizationSnapshot{}, ErrIdentityUnknown
	}
	identity, err = normalizeViewIdentity(identity)
	if err != nil || !sameEntityRef(identity.Ref, material.TargetIdentity) || identity.State != 2 ||
		identity.PrincipalIdentity != material.SubjectIdentity || identity.KeyID != material.KeyID ||
		identity.CreatedAtUnixNano > authorization.issuedAtUnixNano ||
		authorization.issuedAtUnixNano < identity.ValidFromUnixNano ||
		authorization.expiresAtUnixNano > identity.ValidUntilUnixNano ||
		verifyAuthorizationWithMaterial(authorization, material.Algorithm,
			material.CanonicalPublicKey, material.KeyID) != nil {
		return HistoricalKeyAuthorizationSnapshot{}, ErrAuthorizationMismatch
	}
	return HistoricalKeyAuthorizationSnapshot{Material: material, Lifecycle: lifecycle, Identity: identity}, nil
}

type currentTransferAuthorityValidation struct {
	Dependencies       []SnapshotPrecondition
	ValidFromUnixNano  int64
	ValidUntilUnixNano int64
}

func (p *Planner) validateCurrentTransferAuthority(ctx context.Context,
	requirement OwnershipTransferAuthorityRequirement, issuedAt, at int64) (currentTransferAuthorityValidation, error) {
	resolved, err := resolveKeySnapshot(ctx, p.view, p.registry, requirement.KeyID)
	if err != nil || resolved.SubjectIdentity != requirement.Identity || resolved.State != 2 ||
		resolved.RevokedAtUnixNano != 0 || issuedAt < resolved.NotBeforeUnixNano ||
		at < resolved.NotBeforeUnixNano || at >= resolved.NotAfterUnixNano ||
		at < resolved.IdentityValidFromUnixNano || at >= resolved.IdentityValidUntilUnixNano ||
		resolved.AuthorizationPolicyDigestSHA256 != requirement.AuthorizationPolicyDigestSHA256 ||
		!containsUint32(resolved.AllowedMessageTypeIDs, schema.MessageTypeOwnershipTransferAuthorization) {
		return currentTransferAuthorityValidation{}, ErrAuthorizationMismatch
	}
	dependencies, err := canonicalPreconditions([]SnapshotPrecondition{
		{Entity: EntityRef{Kind: EntityKeyLifecycle, PrincipalKind: resolved.SubjectKind, ID: resolved.KeyID},
			ExpectedStateVersion: resolved.StateVersion, ExpectedWriterEpoch: resolved.WriterEpoch,
			ExpectedState: resolved.State, ExpectedSnapshotDigest: resolved.SnapshotDigest},
		{Entity: resolved.TargetIdentity, ExpectedStateVersion: resolved.IdentityStateVersion,
			ExpectedWriterEpoch: resolved.IdentityWriterEpoch, ExpectedState: 2,
			ExpectedSnapshotDigest: resolved.IdentitySnapshotDigest},
	})
	if err != nil {
		return currentTransferAuthorityValidation{}, err
	}
	return currentTransferAuthorityValidation{Dependencies: dependencies,
		ValidFromUnixNano:  maximumInt64(resolved.NotBeforeUnixNano, resolved.IdentityValidFromUnixNano),
		ValidUntilUnixNano: minimumInt64(resolved.NotAfterUnixNano, resolved.IdentityValidUntilUnixNano)}, nil
}

func (p *Planner) validateTransferFixedEvidence(ctx context.Context,
	projection foundationv1.OwnershipTransferAuthorizationSigningProjection, transferDigest [32]byte,
	profile OwnershipTransferProfile, profileDigest [32]byte,
	previousTerminalPayload, nextPendingPayload []byte,
	closureRecords, evidenceRecords []ccse.VerifiedRecord, at int64) (OwnershipTransferFixedEvidence, error) {
	if len(closureRecords) != len(projection.OldKeyClosures) ||
		len(evidenceRecords) != len(projection.EvidenceCommitments) {
		return OwnershipTransferFixedEvidence{}, ErrTransferAuthorizationRequired
	}
	closures := make(map[[32]byte]foundationv1.KeyClosureSigningProjection, len(projection.OldKeyClosures))
	for _, closure := range projection.OldKeyClosures {
		closures[closure.TerminalKeyLifecyclePayloadDigestSHA256] = closure
	}
	previousTerminal, err := normalizeTransferIdentityPayload(previousTerminalPayload, projection.SubjectKind)
	if err != nil || sha256.Sum256(previousTerminal.CanonicalPayload) != projection.PreviousTerminalIdentityPayloadDigestSHA256 {
		return OwnershipTransferFixedEvidence{}, ErrTransferAuthorizationRequired
	}
	nextPending, err := normalizeTransferIdentityPayload(nextPendingPayload, projection.SubjectKind)
	if err != nil || sha256.Sum256(nextPending.CanonicalPayload) != projection.NextPendingIdentityPayloadDigestSHA256 {
		return OwnershipTransferFixedEvidence{}, ErrTransferAuthorizationRequired
	}
	previousRef := EntityRef{Kind: EntityIdentity, PrincipalKind: projection.SubjectKind, ID: projection.PreviousEntityID}
	nextRef := EntityRef{Kind: EntityIdentity, PrincipalKind: projection.SubjectKind, ID: projection.NextEntityID}
	currentPrevious, found, lookupErr := p.view.LookupIdentity(ctx, previousRef)
	if lookupErr != nil || !found {
		return OwnershipTransferFixedEvidence{}, ErrIdentityUnknown
	}
	currentPrevious, err = normalizeViewIdentity(currentPrevious)
	if err != nil || (currentPrevious.State != 2 && currentPrevious.State != 3) ||
		currentPrevious.PrincipalIdentity != projection.PreviousPrincipalIdentity ||
		currentPrevious.Bindings.ProviderID != projection.PreviousProviderID ||
		currentPrevious.Generation != projection.ExpectedGeneration ||
		!sameEntityRef(previousTerminal.Ref, previousRef) || previousTerminal.State != 5 ||
		previousTerminal.PrincipalIdentity != projection.PreviousPrincipalIdentity ||
		previousTerminal.Bindings.ProviderID != projection.PreviousProviderID ||
		previousTerminal.Generation != projection.ExpectedGeneration ||
		previousTerminal.ImmutableBindingDigest != currentPrevious.ImmutableBindingDigest ||
		previousTerminal.ValidFromUnixNano != currentPrevious.ValidFromUnixNano ||
		previousTerminal.ValidUntilUnixNano != currentPrevious.ValidUntilUnixNano ||
		checkedNextVersion(currentPrevious.StateVersion, previousTerminal.StateVersion) != nil ||
		!sameEntityRef(nextPending.Ref, nextRef) || nextPending.State != 1 || nextPending.StateVersion != 1 ||
		nextPending.PrincipalIdentity != projection.NextPrincipalIdentity ||
		nextPending.Bindings.ProviderID != projection.NextProviderID ||
		nextPending.Generation != projection.NextGeneration || nextPending.KeyID != projection.NewKeyID ||
		nextPending.ValidFromUnixNano > projection.EffectiveAtUnixNano ||
		projection.EffectiveAtUnixNano >= nextPending.ValidUntilUnixNano {
		return OwnershipTransferFixedEvidence{}, ErrTransferAuthorizationRequired
	}
	result := OwnershipTransferFixedEvidence{PreviousTerminalIdentity: previousTerminal,
		NextPendingIdentity: nextPending, PreviousIdentityCAS: identityPrecondition(currentPrevious)}
	for _, verified := range closureRecords {
		if verified.MessageTypeID() != schema.MessageTypeKeyLifecycle ||
			verified.SchemaVersion() != (ccse.Version{Major: 1}) || verified.Digest() == ([32]byte{}) ||
			verified.ValidateLimits(transferVerifiedRecordLimits(32768)) != nil {
			return OwnershipTransferFixedEvidence{}, ErrTransferAuthorizationRequired
		}
		retained, err := retainedVerifiedRecord(verified)
		if err != nil || verified.MessageTypeID() != schema.MessageTypeKeyLifecycle {
			return OwnershipTransferFixedEvidence{}, ErrTransferAuthorizationRequired
		}
		payload := verified.Payload()
		closure, ok := closures[sha256.Sum256(payload)]
		if !ok {
			return OwnershipTransferFixedEvidence{}, ErrTransferAuthorizationRequired
		}
		delete(closures, closure.TerminalKeyLifecyclePayloadDigestSHA256)
		validator, validatorErr := foundationCanonicalValidator()
		if validatorErr != nil {
			return OwnershipTransferFixedEvidence{}, validatorErr
		}
		decoded, decodeErr := validator.Decode(schema.MessageTypeKeyLifecycle, ccse.Version{Major: 1}, payload)
		if decodeErr != nil {
			return OwnershipTransferFixedEvidence{}, ErrTransferAuthorizationRequired
		}
		lifecycle, normalizeErr := NormalizeKeyLifecycle(decoded)
		if normalizeErr != nil || lifecycle.KeyID != closure.KeyID || !terminalLifecycleState(lifecycle.State) ||
			lifecycle.SubjectKind != projection.SubjectKind || lifecycle.SubjectIdentity != projection.PreviousPrincipalIdentity {
			return OwnershipTransferFixedEvidence{}, ErrTransferAuthorizationRequired
		}
		current, found, lookupErr := p.view.LookupKeyLifecycle(ctx, closure.KeyID)
		if lookupErr != nil || !found {
			return OwnershipTransferFixedEvidence{}, ErrLifecycleUnknown
		}
		current, normalizeErr = normalizeViewLifecycle(current)
		if normalizeErr != nil || terminalLifecycleState(current.State) ||
			checkedNextVersion(current.StateVersion, lifecycle.StateVersion) != nil ||
			current.ImmutableBindingDigest != lifecycle.ImmutableBindingDigest {
			return OwnershipTransferFixedEvidence{}, ErrTransferAuthorizationRequired
		}
		closureAt := lifecycle.NotAfterUnixNano
		if lifecycle.State == 4 {
			if !lifecycle.HasRevokedAt {
				return OwnershipTransferFixedEvidence{}, ErrTransferAuthorizationRequired
			}
			closureAt = lifecycle.RevokedAtUnixNano
		}
		if closureAt < projection.EffectiveAtUnixNano || closureAt >= projection.ExpiresAtUnixNano ||
			validateLifecycleTransition(current, lifecycle, closureAt) != nil {
			return OwnershipTransferFixedEvidence{}, ErrTransferAuthorizationRequired
		}
		authorization := AuthorizationFromVerifiedRecord(verified)
		authorized, authorizationErr := p.validateVerifiedAuthorization(ctx, authorization,
			schema.MessageTypeKeyLifecycle, lifecycle.CanonicalPayload, lifecycle.CreatedAtUnixNano,
			authorization.senderIdentity, authorization.correlationID, authorization.causationID,
			EntityRef{Kind: EntityKeyLifecycle, PrincipalKind: lifecycle.SubjectKind, ID: lifecycle.KeyID},
			at, current.StateVersion)
		if authorizationErr != nil {
			return OwnershipTransferFixedEvidence{}, authorizationErr
		}
		result.KeyClosureRecords = append(result.KeyClosureRecords, retained)
		result.KeyClosureSnapshots = append(result.KeyClosureSnapshots, lifecycle)
		result.ClosurePreconditions = append(result.ClosurePreconditions, lifecyclePrecondition(current))
		result.ClosurePreconditions = append(result.ClosurePreconditions, authorized.Dependencies...)
	}
	if len(closures) != 0 {
		return OwnershipTransferFixedEvidence{}, ErrTransferAuthorizationRequired
	}
	commitments := make(map[[32]byte]uint32, len(projection.EvidenceCommitments))
	for _, commitment := range projection.EvidenceCommitments {
		if _, duplicate := commitments[commitment.CCSERecordDigestSHA256]; duplicate {
			return OwnershipTransferFixedEvidence{}, ErrTransferAuthorizationRequired
		}
		commitments[commitment.CCSERecordDigestSHA256] = commitment.EvidenceKind
	}
	for _, verified := range evidenceRecords {
		if verified.MessageTypeID() != schema.MessageTypeEvidenceRecord ||
			verified.SchemaVersion() != (ccse.Version{Major: 1}) || verified.Digest() == ([32]byte{}) ||
			verified.ValidateLimits(transferVerifiedRecordLimits(262144)) != nil {
			return OwnershipTransferFixedEvidence{}, ErrTransferAuthorizationRequired
		}
		payload := verified.Payload()
		validator, validatorErr := foundationCanonicalValidator()
		if validatorErr != nil {
			return OwnershipTransferFixedEvidence{}, validatorErr
		}
		decoded, decodeErr := validator.Decode(schema.MessageTypeEvidenceRecord,
			ccse.Version{Major: 1}, payload)
		evidenceProjection, projectionOK := decoded.(foundationv1.EvidenceRecordSigningProjection)
		if decodeErr != nil || !projectionOK || evidenceProjection.EvidenceID == "" {
			return OwnershipTransferFixedEvidence{}, ErrTransferAuthorizationRequired
		}
		authorization := AuthorizationFromVerifiedRecord(verified)
		authorized, authorizationErr := p.validateVerifiedAuthorization(ctx, authorization,
			schema.MessageTypeEvidenceRecord, payload, evidenceProjection.Metadata.CreatedAtUnixNano,
			authorization.senderIdentity, authorization.correlationID, authorization.causationID,
			EntityRef{Kind: EntityIdentity, PrincipalKind: 8, ID: evidenceProjection.EvidenceID},
			at, evidenceProjection.Metadata.StateVersion)
		if authorizationErr != nil {
			return OwnershipTransferFixedEvidence{}, authorizationErr
		}
		retained, err := retainedVerifiedRecord(verified)
		if err != nil || verified.MessageTypeID() != schema.MessageTypeEvidenceRecord {
			return OwnershipTransferFixedEvidence{}, ErrTransferAuthorizationRequired
		}
		if verified.Domain().IssuedAtUnixNano > at || at >= verified.Domain().ExpiresAtUnixNano {
			return OwnershipTransferFixedEvidence{}, ErrTransferAuthorizationRequired
		}
		kind, ok := commitments[retained.digest]
		if !ok {
			return OwnershipTransferFixedEvidence{}, ErrTransferAuthorizationRequired
		}
		delete(commitments, retained.digest)
		if err := p.profile.ValidateOwnershipTransferEvidence(ctx, OwnershipTransferEvidenceRequest{
			TransferAuthorizationID: projection.TransferAuthorizationID,
			TransferEvidenceDigest:  transferDigest, Profile: cloneTransferProfile(profile),
			ProfileDigest: profileDigest, Activation: profile.Activation, EvidenceKind: kind,
			Record: retained.Record(), RecordDigest: retained.digest, EvaluatedAtUnixNano: at,
		}); err != nil {
			return OwnershipTransferFixedEvidence{}, fmt.Errorf("aiinfra iam: transfer evidence policy: %w", err)
		}
		historical, historicalErr := p.resolveHistoricalEvidenceAuthorization(ctx,
			authorization, authorized.Receiver)
		if historicalErr != nil {
			return OwnershipTransferFixedEvidence{}, historicalErr
		}
		admission := OwnershipTransferEvidenceAdmission{RecordDigest: retained.digest,
			EvidenceKind: kind, Historical: historical, Receiver: cloneReceiverProfile(authorized.Receiver),
			ProfileDigest: profileDigest, ActivationDigest: profile.Activation.SnapshotDigest,
			ValidatedAtUnixNano: at}
		admission.PolicyDecisionDigest, err = transferEvidencePolicyDecisionDigest(projection,
			transferDigest, admission)
		if err != nil {
			return OwnershipTransferFixedEvidence{}, err
		}
		admission.Fingerprint, err = transferEvidenceAdmissionFingerprint(admission)
		if err != nil {
			return OwnershipTransferFixedEvidence{}, err
		}
		result.EvidenceRecords = append(result.EvidenceRecords, retained)
		result.EvidenceAdmissions = append(result.EvidenceAdmissions, admission)
		result.EvidencePreconditions = append(result.EvidencePreconditions, authorized.Dependencies...)
	}
	if len(commitments) != 0 {
		return OwnershipTransferFixedEvidence{}, ErrTransferAuthorizationRequired
	}
	sort.Slice(result.KeyClosureRecords, func(i, j int) bool {
		return bytes.Compare(result.KeyClosureRecords[i].digest[:], result.KeyClosureRecords[j].digest[:]) < 0
	})
	sort.Slice(result.KeyClosureSnapshots, func(i, j int) bool {
		return result.KeyClosureSnapshots[i].KeyID < result.KeyClosureSnapshots[j].KeyID
	})
	sort.Slice(result.EvidenceRecords, func(i, j int) bool {
		return bytes.Compare(result.EvidenceRecords[i].digest[:], result.EvidenceRecords[j].digest[:]) < 0
	})
	sort.Slice(result.EvidenceAdmissions, func(i, j int) bool {
		return bytes.Compare(result.EvidenceAdmissions[i].RecordDigest[:],
			result.EvidenceAdmissions[j].RecordDigest[:]) < 0
	})
	result.ClosurePreconditions, err = canonicalPreconditions(result.ClosurePreconditions)
	if err != nil {
		return OwnershipTransferFixedEvidence{}, err
	}
	result.EvidencePreconditions, err = canonicalPreconditions(result.EvidencePreconditions)
	if err != nil {
		return OwnershipTransferFixedEvidence{}, err
	}
	return result, nil
}

func normalizeTransferIdentityPayload(payload []byte, subjectKind uint32) (IdentitySnapshot, error) {
	if subjectKind < 2 || subjectKind > 4 || len(payload) == 0 || len(payload) > 32768 {
		return IdentitySnapshot{}, ErrTransferAuthorizationRequired
	}
	validator, err := foundationCanonicalValidator()
	if err != nil {
		return IdentitySnapshot{}, err
	}
	messageTypeID := schema.MessageTypeProviderIdentity + subjectKind - 1
	decoded, err := validator.Decode(messageTypeID, ccse.Version{Major: 1}, payload)
	if err != nil {
		return IdentitySnapshot{}, ErrTransferAuthorizationRequired
	}
	snapshot, err := NormalizeIdentity(decoded)
	if err != nil || snapshot.MessageTypeID != messageTypeID || !bytes.Equal(snapshot.CanonicalPayload, payload) {
		return IdentitySnapshot{}, ErrTransferAuthorizationRequired
	}
	return snapshot, nil
}

func retainedEvidenceRecordGlobalOwner(record RetainedVerifiedRecord) (string, globalid.Owner, error) {
	validator, err := foundationCanonicalValidator()
	if err != nil {
		return "", globalid.Owner{}, err
	}
	decoded, err := validator.Decode(record.record.MessageTypeID, record.record.SchemaVersion,
		record.record.Payload)
	if err != nil {
		return "", globalid.Owner{}, ErrTransferAuthorizationRequired
	}
	value, ok := decoded.(foundationv1.EvidenceRecordSigningProjection)
	if !ok || value.Metadata.RecordID == "" || value.EvidenceID == "" {
		return "", globalid.Owner{}, ErrTransferAuthorizationRequired
	}
	return value.Metadata.RecordID,
		globalid.Owner{Domain: globalid.OwnerCanonicalRecord, ID: value.EvidenceID}, nil
}
