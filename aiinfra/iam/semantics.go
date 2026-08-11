// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"sort"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
)

type authorizationValidation struct {
	Dependencies      []SnapshotPrecondition
	Receiver          ReceiverProfile
	NotBeforeUnixNano int64
	NotAfterUnixNano  int64
}

func (p *Planner) validateVerifiedAuthorization(ctx context.Context, authorization VerifiedAuthorization,
	messageTypeID uint32, payload []byte, recordCreatedAt int64, actor string, correlation [16]byte,
	causation ccse.OptionalMessageID, replayEntity EntityRef, at int64,
	expectedGeneration uint64) (authorizationValidation, error) {
	receiver, err := p.profile.ReceiverProfile(ctx, messageTypeID)
	if err != nil {
		return authorizationValidation{}, fmt.Errorf("aiinfra iam: receiver profile: %w", err)
	}
	if err := validateReceiverProfile(receiver); err != nil {
		return authorizationValidation{}, err
	}
	expectedReplayDomain, err := DeriveEntityReplayDomainID(receiver.ReplayDomainID, replayEntity)
	if err != nil {
		return authorizationValidation{}, err
	}
	if _, _, err := validateAuthorizationSourceRecord(authorization); err != nil {
		return authorizationValidation{}, err
	}
	if err := validateAudienceSet(authorization.audience); err != nil {
		return authorizationValidation{}, ErrAuthorizationMismatch
	}
	if authorization.messageTypeID != messageTypeID || authorization.schemaVersion != (ccse.Version{Major: 1}) ||
		authorization.senderIdentity != actor || authorization.signatureKeyID == "" ||
		!bytes.Equal(authorization.payload, payload) || authorization.recordDigest == ([32]byte{}) ||
		authorization.messageID == ([16]byte{}) || authorization.correlationID != correlation ||
		authorization.causationID != causation || recordCreatedAt < 0 || recordCreatedAt > authorization.issuedAtUnixNano ||
		authorization.issuedAtUnixNano > at || at >= authorization.expiresAtUnixNano ||
		receiver.MaxClockSkewNanos < 0 || receiver.MaxValidityWindowNanos <= 0 ||
		authorization.expiresAtUnixNano-authorization.issuedAtUnixNano > receiver.MaxValidityWindowNanos ||
		receiver.ProtocolVersion != authorization.protocolVersion || receiver.SchemaVersion != authorization.schemaVersion ||
		receiver.Purpose != authorization.purpose || !sameStringSet(receiver.Audience, authorization.audience) ||
		receiver.TenantOrganization != authorization.tenantOrganization || receiver.ProviderOrganization != authorization.providerOrganization ||
		receiver.Environment != authorization.environment || receiver.ChainID != authorization.chainID ||
		receiver.GenesisHash != authorization.genesisHash || expectedReplayDomain != authorization.replayDomainID ||
		receiver.EnrollmentDomainID == "" || receiver.CounterKind != ccse.CounterExpectedGeneration ||
		receiver.CounterKind != authorization.counterKind {
		return authorizationValidation{}, ErrAuthorizationMismatch
	}
	if authorization.counterKind == ccse.CounterExpectedGeneration && authorization.counter != expectedGeneration {
		return authorizationValidation{}, ErrAuthorizationMismatch
	}
	dependencies, keyNotBefore, keyNotAfter, err := p.validateAuthorizationKey(ctx, authorization, receiver, at)
	if err != nil {
		return authorizationValidation{}, err
	}
	return authorizationValidation{Dependencies: dependencies, Receiver: receiver,
		NotBeforeUnixNano: maximumInt64(authorization.issuedAtUnixNano, keyNotBefore),
		NotAfterUnixNano:  minimumInt64(authorization.expiresAtUnixNano, keyNotAfter)}, nil
}

func validateReceiverProfile(receiver ReceiverProfile) error {
	if receiver.ProtocolVersion.Major == 0 || receiver.SchemaVersion != (ccse.Version{Major: 1}) ||
		receiver.ChainID == ([32]byte{}) || receiver.GenesisHash == ([32]byte{}) ||
		receiver.MaxClockSkewNanos < 0 || receiver.MaxValidityWindowNanos <= 0 || receiver.MaxPlanCommitLatencyNanos <= 0 ||
		receiver.MaxClockSkewNanos > receiver.MaxValidityWindowNanos ||
		receiver.MaxPlanCommitLatencyNanos > receiver.MaxValidityWindowNanos {
		return ErrAuthorizationMismatch
	}
	if err := validateAudienceSet(receiver.Audience); err != nil {
		return ErrAuthorizationMismatch
	}
	for _, value := range []struct {
		text string
		max  int
	}{
		{receiver.Purpose, 260}, {receiver.Environment, 132}, {receiver.ReplayDomainID, 1028}, {receiver.EnrollmentDomainID, 1028},
	} {
		if value.text == "" {
			return ErrAuthorizationMismatch
		}
		if _, err := ccse.Marshal(value.max, func(out *ccse.Encoder) { out.String(value.text) }); err != nil {
			return ErrAuthorizationMismatch
		}
	}
	for _, optional := range []ccse.OptionalString{receiver.TenantOrganization, receiver.ProviderOrganization} {
		if !optional.Present && optional.Value != "" {
			return ErrAuthorizationMismatch
		}
		if _, err := ccse.Marshal(1029, func(out *ccse.Encoder) { out.OptionalString(optional.Present, optional.Value) }); err != nil {
			return ErrAuthorizationMismatch
		}
	}
	return nil
}

func validateAudienceSet(values []string) error {
	if len(values) == 0 || len(values) > 64 {
		return ErrAuthorizationMismatch
	}
	encodedValues := make([][]byte, len(values))
	for index, value := range values {
		encoded, err := ccse.Marshal(1028, func(out *ccse.Encoder) { out.String(value) })
		if err != nil || len(encoded) > 1028 || value == "" {
			return ErrAuthorizationMismatch
		}
		encodedValues[index] = encoded
	}
	if _, err := ccse.Marshal(65536, func(out *ccse.Encoder) { out.EncodedSet(encodedValues) }); err != nil {
		return ErrAuthorizationMismatch
	}
	return nil
}

func sameStringSet(left, right []string) bool {
	left = append([]string(nil), left...)
	right = append([]string(nil), right...)
	sort.Strings(left)
	sort.Strings(right)
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] || (i > 0 && left[i] == left[i-1]) {
			return false
		}
	}
	return true
}

func (p *Planner) validateAuthorizationKey(ctx context.Context, authorization VerifiedAuthorization,
	receiver ReceiverProfile, at int64) ([]SnapshotPrecondition, int64, int64, error) {
	resolved, err := resolveKeySnapshot(ctx, p.view, p.registry, authorization.signatureKeyID)
	if err != nil {
		return nil, 0, 0, err
	}
	if resolved.SubjectIdentity != authorization.senderIdentity || (resolved.State != 2 && resolved.State != 3) ||
		resolved.EnrollmentDomain.EnrollmentDomainID != receiver.EnrollmentDomainID ||
		resolved.EnrollmentDomain.Environment != authorization.environment || resolved.EnrollmentDomain.GenesisHash != authorization.genesisHash ||
		authorization.issuedAtUnixNano < resolved.NotBeforeUnixNano || authorization.expiresAtUnixNano > resolved.NotAfterUnixNano ||
		at < resolved.NotBeforeUnixNano || at >= resolved.NotAfterUnixNano || resolved.RevokedAtUnixNano != 0 ||
		!containsUint32(resolved.AllowedMessageTypeIDs, authorization.messageTypeID) {
		return nil, 0, 0, ErrAuthorizationMismatch
	}
	if err := verifyAuthorizationWithMaterial(authorization, resolved.Algorithm,
		resolved.PublicKey, resolved.KeyID); err != nil {
		return nil, 0, 0, err
	}
	lifecycle, found, err := p.view.LookupKeyLifecycle(ctx, authorization.signatureKeyID)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("aiinfra iam: lookup authorization lifecycle: %w", err)
	}
	if !found {
		return nil, 0, 0, ErrLifecycleUnknown
	}
	lifecycle, err = normalizeViewLifecycle(lifecycle)
	if err != nil {
		return nil, 0, 0, err
	}
	lifecycleDependency := SnapshotPrecondition{
		Entity:               EntityRef{Kind: EntityKeyLifecycle, PrincipalKind: lifecycle.SubjectKind, ID: lifecycle.KeyID},
		ExpectedStateVersion: lifecycle.StateVersion, ExpectedWriterEpoch: lifecycle.WriterEpoch,
		ExpectedState: lifecycle.State, ExpectedSnapshotDigest: resolved.SnapshotDigest,
	}
	identityDependency := SnapshotPrecondition{Entity: resolved.TargetIdentity,
		ExpectedStateVersion: resolved.IdentityStateVersion, ExpectedWriterEpoch: resolved.IdentityWriterEpoch,
		ExpectedState: 2, ExpectedSnapshotDigest: resolved.IdentitySnapshotDigest}
	dependencies, err := canonicalPreconditions([]SnapshotPrecondition{lifecycleDependency, identityDependency})
	if err != nil {
		return nil, 0, 0, err
	}
	return dependencies, resolved.NotBeforeUnixNano, resolved.NotAfterUnixNano, nil
}

func verifyAuthorizationWithMaterial(authorization VerifiedAuthorization,
	algorithm ccse.SignatureAlgorithmID, publicKey []byte, keyID string) error {
	if algorithm != ccse.SignatureAlgorithmEd25519 || len(publicKey) != ed25519.PublicKeySize ||
		len(authorization.sourceRecord.Signature) != ed25519.SignatureSize ||
		authorization.recordDigest == ([32]byte{}) || authorization.signatureKeyID != keyID {
		return ErrAuthorizationMismatch
	}
	if err := ValidateKeyID(keyID, algorithm, publicKey); err != nil ||
		!ed25519.Verify(ed25519.PublicKey(publicKey), authorization.recordDigest[:],
			authorization.sourceRecord.Signature) {
		return ErrAuthorizationMismatch
	}
	return nil
}

func containsUint32(values []uint32, target uint32) bool {
	index := sort.Search(len(values), func(i int) bool { return values[i] >= target })
	return index < len(values) && values[index] == target
}

func (p *Planner) validateIdentityGraph(ctx context.Context, identity IdentitySnapshot) ([]SnapshotPrecondition, error) {
	var parents []EntityRef
	switch identity.Ref.PrincipalKind {
	case 1, 7, 8:
	case 2:
		parents = []EntityRef{{Kind: EntityIdentity, PrincipalKind: 1, ID: identity.Bindings.ProviderID}, {Kind: EntityIdentity, PrincipalKind: 3, ID: identity.Bindings.HostID}}
	case 3:
		parents = []EntityRef{{Kind: EntityIdentity, PrincipalKind: 1, ID: identity.Bindings.ProviderID}}
	case 4:
		parents = []EntityRef{{Kind: EntityIdentity, PrincipalKind: 1, ID: identity.Bindings.ProviderID}, {Kind: EntityIdentity, PrincipalKind: 3, ID: identity.Bindings.HostID}}
	case 5:
		parents = []EntityRef{{Kind: EntityIdentity, PrincipalKind: 1, ID: identity.Bindings.ProviderID}, {Kind: EntityIdentity, PrincipalKind: 2, ID: identity.Bindings.AgentID}}
		for _, deviceID := range identity.Bindings.DeviceIDs {
			parents = append(parents, EntityRef{Kind: EntityIdentity, PrincipalKind: 4, ID: deviceID})
		}
	case 6:
		parents = []EntityRef{{Kind: EntityIdentity, PrincipalKind: 1, ID: identity.Bindings.ProviderID}, {Kind: EntityIdentity, PrincipalKind: 2, ID: identity.Bindings.AgentID}}
	default:
		return nil, ErrInvalidInput
	}
	dependencies := make([]SnapshotPrecondition, 0, len(parents))
	parentStates := make(map[EntityRef]IdentitySnapshot, len(parents))
	for _, ref := range parents {
		if ref.ID == "" {
			return nil, ErrIdentityConflict
		}
		parent, found, err := p.view.LookupIdentity(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("aiinfra iam: lookup parent identity: %w", err)
		}
		if !found {
			return nil, fmt.Errorf("%w: parent %d/%q", ErrIdentityUnknown, ref.PrincipalKind, ref.ID)
		}
		parent, err = normalizeViewIdentity(parent)
		if err != nil {
			return nil, err
		}
		if !sameEntityRef(parent.Ref, ref) {
			return nil, ErrViewInconsistent
		}
		if !terminalIdentityState(identity.State) {
			if parent.State != 2 || identity.ValidFromUnixNano < parent.ValidFromUnixNano || identity.ValidUntilUnixNano > parent.ValidUntilUnixNano {
				return nil, ErrIdentityConflict
			}
		}
		parentStates[ref] = parent
		dependencies = append(dependencies, identityPrecondition(parent))
	}
	providerRef := EntityRef{Kind: EntityIdentity, PrincipalKind: 1, ID: identity.Bindings.ProviderID}
	if provider, ok := parentStates[providerRef]; ok {
		switch identity.Ref.PrincipalKind {
		case 2, 3, 4:
			if identity.Generation != provider.Generation {
				return nil, ErrIdentityConflict
			}
		}
	}
	if identity.Ref.PrincipalKind == 2 || identity.Ref.PrincipalKind == 4 {
		host := parentStates[EntityRef{Kind: EntityIdentity, PrincipalKind: 3, ID: identity.Bindings.HostID}]
		if host.Bindings.ProviderID != identity.Bindings.ProviderID || host.Generation != identity.Generation {
			return nil, ErrIdentityConflict
		}
	}
	if identity.Ref.PrincipalKind == 5 || identity.Ref.PrincipalKind == 6 {
		agent := parentStates[EntityRef{Kind: EntityIdentity, PrincipalKind: 2, ID: identity.Bindings.AgentID}]
		if agent.Bindings.ProviderID != identity.Bindings.ProviderID {
			return nil, ErrIdentityConflict
		}
	}
	if identity.Ref.PrincipalKind == 5 {
		agent := parentStates[EntityRef{Kind: EntityIdentity, PrincipalKind: 2, ID: identity.Bindings.AgentID}]
		for _, deviceID := range identity.Bindings.DeviceIDs {
			device := parentStates[EntityRef{Kind: EntityIdentity, PrincipalKind: 4, ID: deviceID}]
			if device.Bindings.ProviderID != identity.Bindings.ProviderID ||
				device.Bindings.HostID == "" || device.Bindings.HostID != agent.Bindings.HostID {
				return nil, ErrIdentityConflict
			}
		}
	}
	return canonicalPreconditions(dependencies)
}

func identityPrecondition(identity IdentitySnapshot) SnapshotPrecondition {
	return SnapshotPrecondition{Entity: identity.Ref, ExpectedStateVersion: identity.StateVersion,
		ExpectedWriterEpoch: identity.WriterEpoch, ExpectedState: identity.State,
		ExpectedSnapshotDigest: domainDigest(resolvedIdentitySnapshotDomain, identity.CanonicalPayload)}
}

func lifecyclePrecondition(lifecycle KeyLifecycleSnapshot) SnapshotPrecondition {
	return SnapshotPrecondition{Entity: EntityRef{Kind: EntityKeyLifecycle, PrincipalKind: lifecycle.SubjectKind, ID: lifecycle.KeyID},
		ExpectedStateVersion: lifecycle.StateVersion, ExpectedWriterEpoch: lifecycle.WriterEpoch, ExpectedState: lifecycle.State,
		ExpectedSnapshotDigest: domainDigest(resolvedLifecycleSnapshotDomain, lifecycle.CanonicalPayload)}
}

func materialPrecondition(material KeyMaterialSnapshot) SnapshotPrecondition {
	return SnapshotPrecondition{Entity: EntityRef{Kind: EntityKeyMaterial, PrincipalKind: material.SubjectKind, ID: material.KeyID},
		ExpectedStateVersion: material.StateVersion, ExpectedWriterEpoch: material.WriterEpoch,
		ExpectedSnapshotDigest: material.EnrollmentBindingDigest}
}

func (p *Planner) validatePrincipalIndex(ctx context.Context, identity IdentitySnapshot, entityExists bool, transfer *OwnershipTransferSnapshot) (PrincipalIndexIntent, error) {
	indexed, found, err := p.view.LookupIdentityByPrincipal(ctx, identity.Ref.PrincipalKind, identity.PrincipalIdentity)
	if err != nil {
		return PrincipalIndexIntent{}, fmt.Errorf("aiinfra iam: lookup principal identity: %w", err)
	}
	if !found {
		if entityExists {
			return PrincipalIndexIntent{}, ErrViewInconsistent
		}
		if transfer != nil && transfer.PreviousPrincipal == transfer.NextPrincipal {
			return PrincipalIndexIntent{}, ErrViewInconsistent
		}
		return PrincipalIndexIntent{Mode: globalid.ReserveNew, PrincipalKind: identity.Ref.PrincipalKind,
			PrincipalIdentity: identity.PrincipalIdentity, NextOwner: identity.Ref}, nil
	}
	indexed, err = normalizeViewIdentity(indexed)
	if err != nil {
		return PrincipalIndexIntent{}, err
	}
	if indexed.PrincipalIdentity != identity.PrincipalIdentity {
		return PrincipalIndexIntent{}, ErrIdentityConflict
	}
	if sameEntityRef(indexed.Ref, identity.Ref) {
		if !entityExists {
			return PrincipalIndexIntent{}, ErrViewInconsistent
		}
		return PrincipalIndexIntent{Mode: globalid.AssertExisting, PrincipalKind: identity.Ref.PrincipalKind,
			PrincipalIdentity: identity.PrincipalIdentity, ExpectedOwner: identity.Ref, NextOwner: identity.Ref,
			ExpectedStateVersion: indexed.StateVersion, ExpectedEntityWriterEpoch: indexed.WriterEpoch,
			ExpectedState: indexed.State}, nil
	}
	if transfer == nil || (identity.Ref.PrincipalKind != 3 && identity.Ref.PrincipalKind != 4) ||
		transfer.PreviousPrincipal != transfer.NextPrincipal || !sameEntityRef(indexed.Ref, transfer.PreviousEntity) ||
		indexed.State != 5 || indexed.StateVersion == 0 || indexed.WriterEpoch == 0 {
		return PrincipalIndexIntent{}, ErrIdentityConflict
	}
	return PrincipalIndexIntent{Mode: globalid.TransferExisting, PrincipalKind: identity.Ref.PrincipalKind,
		PrincipalIdentity: identity.PrincipalIdentity, ExpectedOwner: indexed.Ref, NextOwner: identity.Ref,
		ExpectedStateVersion: indexed.StateVersion, ExpectedEntityWriterEpoch: indexed.WriterEpoch,
		ExpectedState: indexed.State, TransferEvidenceDigest: transfer.EvidenceDigest}, nil
}

func (p *Planner) validateLifecycleSubject(ctx context.Context, lifecycle KeyLifecycleSnapshot,
	targetIdentity EntityRef, lifecycleExists bool, transferDigest [32]byte,
	at int64) (SnapshotPrecondition, bool, error) {
	if err := validateTargetIdentity(targetIdentity, lifecycle.SubjectKind); err != nil {
		return SnapshotPrecondition{}, false, ErrKeyMaterialMismatch
	}
	identity, found, err := p.view.LookupIdentityByPrincipal(ctx, lifecycle.SubjectKind, lifecycle.SubjectIdentity)
	if err != nil {
		return SnapshotPrecondition{}, false, fmt.Errorf("aiinfra iam: lookup lifecycle subject: %w", err)
	}
	if !found {
		bootstrapCreate := !lifecycleExists && lifecycle.State == 1
		bootstrapClosure := lifecycleExists && (lifecycle.State == 4 || lifecycle.State == 5)
		if !bootstrapCreate && !bootstrapClosure {
			return SnapshotPrecondition{}, false, ErrIdentityUnknown
		}
		if transferDigest != ([32]byte{}) {
			// A rotated Agent principal is necessarily absent while its PREACTIVE
			// successor key is staged. Bind that absence and the exact terminal
			// previous identity named by the transfer evidence.
			if !bootstrapCreate || lifecycle.SubjectKind != 2 {
				return SnapshotPrecondition{}, false, ErrIdentityConflict
			}
			evidence, evidenceFound, lookupErr := p.view.LookupOwnershipTransfer(ctx, transferDigest)
			if lookupErr != nil {
				return SnapshotPrecondition{}, false, fmt.Errorf("aiinfra iam: lookup lifecycle transfer: %w", lookupErr)
			}
			if !evidenceFound || evidence.EvidenceDigest != transferDigest ||
				!sameEntityRef(evidence.NextEntity, targetIdentity) ||
				evidence.NextPrincipal != lifecycle.SubjectIdentity ||
				evidence.PreviousEntity.Kind != EntityIdentity ||
				evidence.PreviousEntity.PrincipalKind != lifecycle.SubjectKind ||
				evidence.PreviousPrincipal == evidence.NextPrincipal ||
				evidence.PreviousGeneration == ^uint64(0) ||
				evidence.NextGeneration != evidence.PreviousGeneration+1 ||
				evidence.CompletedAtUnixNano < 0 || evidence.CompletedAtUnixNano > at {
				return SnapshotPrecondition{}, false, ErrIdentityConflict
			}
			previous, previousFound, previousErr := p.view.LookupIdentity(ctx, evidence.PreviousEntity)
			if previousErr != nil {
				return SnapshotPrecondition{}, false, fmt.Errorf("aiinfra iam: lookup previous lifecycle identity: %w", previousErr)
			}
			if !previousFound {
				return SnapshotPrecondition{}, false, ErrIdentityUnknown
			}
			previous, previousErr = normalizeViewIdentity(previous)
			if previousErr != nil {
				return SnapshotPrecondition{}, false, previousErr
			}
			if previous.State != 5 || previous.Generation != evidence.PreviousGeneration ||
				previous.PrincipalIdentity != evidence.PreviousPrincipal {
				return SnapshotPrecondition{}, false, ErrIdentityConflict
			}
			return identityPrecondition(previous), true, nil
		}
		// PREACTIVE material may be enrolled before the PENDING identity record.
		// It must also remain revocable/expirable if enrollment is abandoned;
		// exact principal absence is carried into every such commit CAS.
		return SnapshotPrecondition{}, true, nil
	}
	identity, err = normalizeViewIdentity(identity)
	if err != nil {
		return SnapshotPrecondition{}, false, err
	}
	if identity.Ref.PrincipalKind != lifecycle.SubjectKind || identity.PrincipalIdentity != lifecycle.SubjectIdentity {
		return SnapshotPrecondition{}, false, ErrIdentityConflict
	}
	if lifecycleExists && terminalLifecycleState(lifecycle.State) && transferDigest != ([32]byte{}) {
		evidence, evidenceFound, lookupErr := p.view.LookupOwnershipTransfer(ctx, transferDigest)
		if lookupErr != nil {
			return SnapshotPrecondition{}, false, fmt.Errorf("aiinfra iam: lookup lifecycle closure transfer: %w", lookupErr)
		}
		if !evidenceFound || evidence.EvidenceDigest != transferDigest ||
			!sameEntityRef(evidence.PreviousEntity, identity.Ref) ||
			evidence.PreviousPrincipal != identity.PrincipalIdentity ||
			evidence.PreviousGeneration != identity.Generation ||
			evidence.CompletedAtUnixNano < 0 || evidence.CompletedAtUnixNano > at ||
			!sameEntityRef(targetIdentity, identity.Ref) {
			return SnapshotPrecondition{}, false, ErrIdentityConflict
		}
		return identityPrecondition(identity), false, nil
	}
	if terminalIdentityState(identity.State) {
		// Host/Device TPM or vendor attestation principals may survive an
		// ownership transfer. A PREACTIVE successor key is staged against the
		// exact transfer evidence before the new PENDING identity atomically
		// moves the principal index.
		if identity.State != 5 || lifecycleExists || lifecycle.State != 1 ||
			(lifecycle.SubjectKind != 3 && lifecycle.SubjectKind != 4) || transferDigest == ([32]byte{}) {
			return SnapshotPrecondition{}, false, ErrIdentityConflict
		}
		evidence, found, lookupErr := p.view.LookupOwnershipTransfer(ctx, transferDigest)
		if lookupErr != nil {
			return SnapshotPrecondition{}, false, fmt.Errorf("aiinfra iam: lookup lifecycle transfer: %w", lookupErr)
		}
		if !found || evidence.EvidenceDigest != transferDigest || !sameEntityRef(evidence.PreviousEntity, identity.Ref) ||
			evidence.PreviousPrincipal != lifecycle.SubjectIdentity || evidence.NextPrincipal != lifecycle.SubjectIdentity ||
			evidence.NextEntity.Kind != EntityIdentity || evidence.NextEntity.PrincipalKind != lifecycle.SubjectKind ||
			evidence.NextEntity.ID == identity.Ref.ID || evidence.PreviousGeneration != identity.Generation ||
			evidence.PreviousGeneration == ^uint64(0) || evidence.NextGeneration != evidence.PreviousGeneration+1 ||
			!sameEntityRef(evidence.NextEntity, targetIdentity) ||
			evidence.CompletedAtUnixNano < 0 || evidence.CompletedAtUnixNano > at {
			return SnapshotPrecondition{}, false, ErrIdentityConflict
		}
		return identityPrecondition(identity), false, nil
	}
	if !sameEntityRef(identity.Ref, targetIdentity) || transferDigest != ([32]byte{}) ||
		lifecycle.NotBeforeUnixNano < identity.ValidFromUnixNano ||
		lifecycle.NotAfterUnixNano > identity.ValidUntilUnixNano {
		return SnapshotPrecondition{}, false, ErrIdentityConflict
	}
	return identityPrecondition(identity), false, nil
}

type identityKeyValidation struct {
	Dependencies             []SnapshotPrecondition
	NotBeforeUnixNano        int64
	NotAfterUnixNano         int64
	EnrollmentEvidenceDigest [32]byte
	TransferEvidenceDigest   [32]byte
}

func (p *Planner) validateIdentityKey(ctx context.Context, identity IdentitySnapshot, at int64, environment string, genesisHash [32]byte) (identityKeyValidation, error) {
	if identity.KeyID == "" {
		return identityKeyValidation{}, nil
	}
	material, found, err := p.view.LookupKeyMaterial(ctx, identity.KeyID)
	if err != nil {
		return identityKeyValidation{}, fmt.Errorf("aiinfra iam: lookup identity key material: %w", err)
	}
	if !found {
		return identityKeyValidation{}, ErrKeyMaterialUnknown
	}
	material, err = validateMaterialSnapshot(material)
	if err != nil {
		return identityKeyValidation{}, err
	}
	if material.SubjectIdentity != identity.PrincipalIdentity || material.SubjectKind != identity.Ref.PrincipalKind {
		return identityKeyValidation{}, ErrKeyMaterialMismatch
	}
	if !sameEntityRef(material.TargetIdentity, identity.Ref) {
		return identityKeyValidation{}, ErrKeyMaterialMismatch
	}
	receiver, err := p.profile.ReceiverProfile(ctx, identity.MessageTypeID)
	if err != nil {
		return identityKeyValidation{}, fmt.Errorf("aiinfra iam: target key receiver profile: %w", err)
	}
	if err := validateReceiverProfile(receiver); err != nil {
		return identityKeyValidation{}, err
	}
	if material.EnrollmentDomain.EnrollmentDomainID != receiver.EnrollmentDomainID ||
		material.EnrollmentDomain.Environment != environment || material.EnrollmentDomain.GenesisHash != genesisHash {
		return identityKeyValidation{}, ErrKeyMaterialMismatch
	}
	dependencies := []SnapshotPrecondition{materialPrecondition(material)}
	lifecycle, found, err := p.view.LookupKeyLifecycle(ctx, identity.KeyID)
	if err != nil {
		return identityKeyValidation{}, fmt.Errorf("aiinfra iam: lookup identity key lifecycle: %w", err)
	}
	if !found {
		return identityKeyValidation{}, ErrLifecycleUnknown
	}
	lifecycle, err = normalizeViewLifecycle(lifecycle)
	if err != nil {
		return identityKeyValidation{}, err
	}
	if lifecycle.SubjectIdentity != identity.PrincipalIdentity || lifecycle.SubjectKind != identity.Ref.PrincipalKind || lifecycle.Algorithm != material.Algorithm {
		return identityKeyValidation{}, ErrKeyMaterialMismatch
	}
	if lifecycle.NotBeforeUnixNano < identity.ValidFromUnixNano || lifecycle.NotAfterUnixNano > identity.ValidUntilUnixNano ||
		!containsUint32(lifecycle.AllowedMessageTypeIDs, identity.MessageTypeID) {
		return identityKeyValidation{}, ErrLifecycleUnknown
	}
	if identity.State == 2 && (lifecycle.State != 2 || at < lifecycle.NotBeforeUnixNano || at >= lifecycle.NotAfterUnixNano || lifecycle.RevokedAtUnixNano != 0) {
		return identityKeyValidation{}, ErrLifecycleUnknown
	}
	if identity.State == 1 && lifecycle.State != 1 && lifecycle.State != 2 {
		return identityKeyValidation{}, ErrLifecycleUnknown
	}
	if identity.State == 3 && ((lifecycle.State != 2 && lifecycle.State != 3) || at < lifecycle.NotBeforeUnixNano ||
		at >= lifecycle.NotAfterUnixNano || lifecycle.RevokedAtUnixNano != 0) {
		return identityKeyValidation{}, ErrLifecycleUnknown
	}
	return identityKeyValidation{Dependencies: append(dependencies, lifecyclePrecondition(lifecycle)),
		NotBeforeUnixNano: lifecycle.NotBeforeUnixNano, NotAfterUnixNano: lifecycle.NotAfterUnixNano,
		EnrollmentEvidenceDigest: material.EnrollmentBindingDigest,
		TransferEvidenceDigest:   material.TransferEvidenceDigest}, nil
}

func validateIdentityTransitionBaseline(previous *IdentitySnapshot, next IdentitySnapshot,
	transferEvidence [32]byte, at int64) error {
	if at < 0 || next.ValidFromUnixNano < 0 || next.ValidUntilUnixNano <= next.ValidFromUnixNano {
		return ErrInvalidTransition
	}
	if previous == nil {
		if next.State != 1 {
			return fmt.Errorf("%w: first identity state must be PENDING", ErrInvalidTransition)
		}
		switch next.Ref.PrincipalKind {
		case 1, 2, 3, 4:
			firstEnrollment := next.Generation == 1 && transferEvidence == ([32]byte{})
			transferEnrollment := next.Generation > 1 && transferEvidence != ([32]byte{})
			if !firstEnrollment && !transferEnrollment {
				return ErrIdentityConflict
			}
		case 5, 7, 8:
			if next.Generation != 1 || transferEvidence != ([32]byte{}) {
				return ErrIdentityConflict
			}
		case 6:
			if next.Generation != 0 || transferEvidence != ([32]byte{}) {
				return ErrIdentityConflict
			}
		default:
			return ErrInvalidInput
		}
	} else {
		valid := (previous.State == 1 && (next.State == 2 || next.State == 4 || next.State == 6)) ||
			(previous.State == 2 && (next.State == 3 || next.State == 4 || next.State == 5 || next.State == 6)) ||
			(previous.State == 3 && (next.State == 2 || next.State == 4 || next.State == 5 || next.State == 6))
		if !valid {
			return fmt.Errorf("%w: identity %d -> %d", ErrInvalidTransition, previous.State, next.State)
		}
	}
	switch next.State {
	case 1:
		if at >= next.ValidUntilUnixNano {
			return fmt.Errorf("%w: pending identity expired", ErrInvalidTransition)
		}
	case 2, 3:
		if at < next.ValidFromUnixNano || at >= next.ValidUntilUnixNano {
			return fmt.Errorf("%w: nonterminal identity outside validity", ErrInvalidTransition)
		}
	case 4, 5:
		// Revocation and ownership transfer may close an already expired
		// identity; their key/evidence closure is validated separately.
	case 6:
		if at < next.ValidUntilUnixNano {
			return fmt.Errorf("%w: identity expiry before valid_until", ErrInvalidTransition)
		}
	default:
		return ErrInvalidTransition
	}
	return nil
}

func (p *Planner) validateIdentityRecordSuccessor(ctx context.Context, previous, next IdentitySnapshot) ([]SnapshotPrecondition, error) {
	if previous.ValidFromUnixNano != next.ValidFromUnixNano || previous.ValidUntilUnixNano != next.ValidUntilUnixNano {
		return nil, ErrIdentityConflict
	}
	if previous.ImmutableBindingDigest != next.ImmutableBindingDigest {
		// Miner binding changes are a generation-fenced operation performed
		// only while resuming from SUSPENDED. All other v1 static identity
		// bindings remain immutable for one entity ID.
		if next.Ref.PrincipalKind != 5 || previous.State != 3 || next.State != 2 ||
			previous.Generation == ^uint64(0) || next.Generation != previous.Generation+1 ||
			previous.KeyID != next.KeyID {
			return nil, ErrIdentityConflict
		}
		return nil, nil
	}
	if previous.KeyID == next.KeyID {
		if previous.Generation != next.Generation {
			return nil, ErrIdentityConflict
		}
		return nil, nil
	}
	if previous.KeyID == "" || next.KeyID == "" {
		return nil, ErrIdentityConflict
	}
	switch next.Ref.PrincipalKind {
	case 7, 8:
		if previous.Generation == ^uint64(0) || next.Generation != previous.Generation+1 {
			return nil, ErrIdentityConflict
		}
	default:
		if next.Generation != previous.Generation {
			return nil, ErrIdentityConflict
		}
	}
	nextLifecycle, found, err := p.view.LookupKeyLifecycle(ctx, next.KeyID)
	if err != nil {
		return nil, fmt.Errorf("aiinfra iam: lookup rotated key: %w", err)
	}
	if !found {
		return nil, ErrLifecycleUnknown
	}
	nextLifecycle, err = normalizeViewLifecycle(nextLifecycle)
	if err != nil {
		return nil, err
	}
	if !nextLifecycle.HasRotationPredecessor || nextLifecycle.RotationPredecessorKeyID != previous.KeyID ||
		nextLifecycle.SubjectIdentity != next.PrincipalIdentity || nextLifecycle.SubjectKind != next.Ref.PrincipalKind {
		return nil, ErrInvalidPredecessor
	}
	previousLifecycle, found, err := p.view.LookupKeyLifecycle(ctx, previous.KeyID)
	if err != nil {
		return nil, fmt.Errorf("aiinfra iam: lookup previous identity key: %w", err)
	}
	if !found {
		return nil, ErrLifecycleUnknown
	}
	previousLifecycle, err = normalizeViewLifecycle(previousLifecycle)
	if err != nil {
		return nil, err
	}
	if previousLifecycle.SubjectIdentity != previous.PrincipalIdentity || previousLifecycle.SubjectKind != previous.Ref.PrincipalKind {
		return nil, ErrInvalidPredecessor
	}
	return []SnapshotPrecondition{lifecyclePrecondition(previousLifecycle), lifecyclePrecondition(nextLifecycle)}, nil
}

func (p *Planner) validateTerminalSubjectKeys(ctx context.Context, identity IdentitySnapshot, at int64) ([]SnapshotPrecondition, [32]byte, error) {
	if !terminalIdentityState(identity.State) {
		return nil, [32]byte{}, nil
	}
	items, err := p.view.LookupSubjectKeyLifecycles(ctx, identity.Ref.PrincipalKind, identity.PrincipalIdentity)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("aiinfra iam: lookup subject keys: %w", err)
	}
	if len(items) > 256 {
		return nil, [32]byte{}, ErrLookupLimit
	}
	dependencies := make([]SnapshotPrecondition, 0, len(items))
	foundOwn := identity.KeyID == ""
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		item, err = normalizeViewLifecycle(item)
		if err != nil {
			return nil, [32]byte{}, err
		}
		if item.SubjectKind != identity.Ref.PrincipalKind || item.SubjectIdentity != identity.PrincipalIdentity {
			return nil, [32]byte{}, ErrViewInconsistent
		}
		if _, duplicate := seen[item.KeyID]; duplicate {
			return nil, [32]byte{}, ErrViewInconsistent
		}
		seen[item.KeyID] = struct{}{}
		if item.KeyID == identity.KeyID {
			foundOwn = true
		}
		if !((item.State == 4 && item.HasRevokedAt && item.RevokedAtUnixNano <= at) || (item.State == 5 && at >= item.NotAfterUnixNano)) {
			return nil, [32]byte{}, ErrTerminalIdentity
		}
		dependencies = append(dependencies, lifecyclePrecondition(item))
	}
	if !foundOwn {
		return nil, [32]byte{}, ErrViewInconsistent
	}
	dependencies, err = canonicalPreconditions(dependencies)
	if err != nil {
		return nil, [32]byte{}, err
	}
	elements := make([][]byte, len(dependencies))
	for index, dependency := range dependencies {
		elements[index], err = ccse.Marshal(2048, func(item *ccse.Encoder) {
			encodeEntity(item, dependency.Entity)
			item.Uint64(dependency.ExpectedStateVersion)
			item.Uint64(dependency.ExpectedWriterEpoch)
			item.Uint32(dependency.ExpectedState)
		})
		if err != nil {
			return nil, [32]byte{}, err
		}
	}
	encoded, err := ccse.Marshal(32768, func(out *ccse.Encoder) {
		out.Uint32(identity.Ref.PrincipalKind)
		out.String(identity.PrincipalIdentity)
		out.EncodedList(elements)
	})
	if err != nil {
		return nil, [32]byte{}, err
	}
	return dependencies, domainDigest("CPH-AIIE-IAM-SUBJECT-KEY-SET-V1\x00", encoded), nil
}

type ownershipTransferValidation struct {
	Dependencies []SnapshotPrecondition
	Evidence     *OwnershipTransferSnapshot
}

func (p *Planner) validateOwnershipTransfer(ctx context.Context, identity IdentitySnapshot, entityExists bool, evidenceDigest [32]byte, at int64) (ownershipTransferValidation, error) {
	// Only the v1 ownership_generation identities use cross-entity transfer.
	if identity.Ref.PrincipalKind < 1 || identity.Ref.PrincipalKind > 4 {
		if evidenceDigest != ([32]byte{}) {
			return ownershipTransferValidation{}, ErrIdentityConflict
		}
		return ownershipTransferValidation{}, nil
	}
	if entityExists {
		if evidenceDigest == ([32]byte{}) {
			return ownershipTransferValidation{}, nil
		}
		if identity.State != 5 {
			return ownershipTransferValidation{}, ErrIdentityConflict
		}
		evidence, found, err := p.view.LookupOwnershipTransfer(ctx, evidenceDigest)
		if err != nil {
			return ownershipTransferValidation{}, fmt.Errorf("aiinfra iam: lookup identity closure transfer: %w", err)
		}
		if !found || evidence.EvidenceDigest != evidenceDigest ||
			!sameEntityRef(evidence.PreviousEntity, identity.Ref) ||
			evidence.PreviousPrincipal != identity.PrincipalIdentity ||
			evidence.PreviousGeneration != identity.Generation ||
			evidence.CompletedAtUnixNano < 0 || evidence.CompletedAtUnixNano > at {
			return ownershipTransferValidation{}, ErrIdentityConflict
		}
		current, found, err := p.view.LookupIdentity(ctx, identity.Ref)
		if err != nil || !found {
			return ownershipTransferValidation{}, ErrIdentityUnknown
		}
		current, err = normalizeViewIdentity(current)
		if err != nil || terminalIdentityState(current.State) || current.Generation != evidence.PreviousGeneration ||
			current.PrincipalIdentity != evidence.PreviousPrincipal {
			return ownershipTransferValidation{}, ErrIdentityConflict
		}
		copy := evidence
		return ownershipTransferValidation{Dependencies: []SnapshotPrecondition{identityPrecondition(current)}, Evidence: &copy}, nil
	}
	if identity.Generation == 1 {
		if evidenceDigest != ([32]byte{}) {
			return ownershipTransferValidation{}, ErrIdentityConflict
		}
		return ownershipTransferValidation{}, nil
	}
	if identity.Generation < 2 || evidenceDigest == ([32]byte{}) {
		return ownershipTransferValidation{}, ErrIdentityConflict
	}
	evidence, found, err := p.view.LookupOwnershipTransfer(ctx, evidenceDigest)
	if err != nil {
		return ownershipTransferValidation{}, fmt.Errorf("aiinfra iam: lookup ownership transfer: %w", err)
	}
	if !found || evidence.EvidenceDigest != evidenceDigest || !sameEntityRef(evidence.NextEntity, identity.Ref) ||
		evidence.NextPrincipal != identity.PrincipalIdentity || evidence.NextGeneration != identity.Generation ||
		evidence.PreviousEntity.Kind != EntityIdentity || evidence.PreviousEntity.PrincipalKind != identity.Ref.PrincipalKind ||
		evidence.PreviousEntity.ID == identity.Ref.ID || evidence.PreviousGeneration == ^uint64(0) ||
		evidence.NextGeneration != evidence.PreviousGeneration+1 || evidence.CompletedAtUnixNano < 0 || evidence.CompletedAtUnixNano > at ||
		((identity.Ref.PrincipalKind == 1 || identity.Ref.PrincipalKind == 2) && evidence.PreviousPrincipal == evidence.NextPrincipal) {
		return ownershipTransferValidation{}, ErrIdentityConflict
	}
	previous, found, err := p.view.LookupIdentity(ctx, evidence.PreviousEntity)
	if err != nil {
		return ownershipTransferValidation{}, fmt.Errorf("aiinfra iam: lookup transferred identity: %w", err)
	}
	if !found {
		return ownershipTransferValidation{}, ErrIdentityUnknown
	}
	previous, err = normalizeViewIdentity(previous)
	if err != nil {
		return ownershipTransferValidation{}, err
	}
	if previous.State != 5 || previous.Generation != evidence.PreviousGeneration || previous.PrincipalIdentity != evidence.PreviousPrincipal {
		return ownershipTransferValidation{}, ErrIdentityConflict
	}
	copy := evidence
	return ownershipTransferValidation{Dependencies: []SnapshotPrecondition{identityPrecondition(previous)}, Evidence: &copy}, nil
}

func canonicalPreconditions(values []SnapshotPrecondition) ([]SnapshotPrecondition, error) {
	result := append([]SnapshotPrecondition(nil), values...)
	sort.Slice(result, func(i, j int) bool {
		left, right := result[i].Entity, result[j].Entity
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		if left.PrincipalKind != right.PrincipalKind {
			return left.PrincipalKind < right.PrincipalKind
		}
		return left.ID < right.ID
	})
	output := result[:0]
	for _, item := range result {
		if len(output) > 0 && sameEntityRef(output[len(output)-1].Entity, item.Entity) {
			if output[len(output)-1] != item {
				return nil, ErrViewInconsistent
			}
			continue
		}
		output = append(output, item)
	}
	return output, nil
}
