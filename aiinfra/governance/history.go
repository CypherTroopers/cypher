// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"sort"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

const historicalApprovalEvidenceDigestDomain = "CPH-AIIE-GOVERNANCE-HISTORICAL-APPROVAL-EVIDENCE-V1\x00"

func (p *Planner) resolveHistoricalProfile(ctx context.Context, digest [ccse.DigestSize]byte, acceptedAt int64) (Profile, error) {
	if isZeroDigest(digest) {
		return Profile{}, ErrSnapshotInconsistent
	}
	activation, active, err := p.profiles.ActiveGovernanceProfile(ctx, acceptedAt)
	if err != nil {
		return Profile{}, fmt.Errorf("aiinfra governance: resolve active historical profile: %w", err)
	}
	if !active || !validGovernanceProfileActivation(activation, acceptedAt) || activation.GovernanceProfileDigestSHA256 != digest {
		return Profile{}, ErrSnapshotInconsistent
	}
	profile, found, err := p.profiles.ResolveGovernanceProfile(ctx, digest)
	if err != nil {
		return Profile{}, fmt.Errorf("aiinfra governance: resolve historical profile: %w", err)
	}
	if !found || !preflightProfile(profile) {
		return Profile{}, ErrSnapshotInconsistent
	}
	profile = cloneProfile(profile)
	if err := validateProfile(profile); err != nil {
		return Profile{}, ErrSnapshotInconsistent
	}
	computed, err := digestGovernanceProfile(profile)
	if err != nil || computed != digest {
		return Profile{}, ErrSnapshotInconsistent
	}
	return profile, nil
}

func (p *Planner) resolveHistoricalProfileActivation(ctx context.Context, expected GovernanceProfileActivationSnapshot, at int64) (Profile, error) {
	if !validGovernanceProfileActivation(expected, at) {
		return Profile{}, ErrSnapshotInconsistent
	}
	actual, active, err := p.profiles.ActiveGovernanceProfile(ctx, at)
	if err != nil {
		return Profile{}, fmt.Errorf("aiinfra governance: resolve exact historical activation: %w", err)
	}
	if !active || actual != expected {
		return Profile{}, ErrSnapshotInconsistent
	}
	profile, found, err := p.profiles.ResolveGovernanceProfile(ctx, expected.GovernanceProfileDigestSHA256)
	if err != nil {
		return Profile{}, fmt.Errorf("aiinfra governance: resolve exact historical profile: %w", err)
	}
	if !found || !preflightProfile(profile) {
		return Profile{}, ErrSnapshotInconsistent
	}
	profile = cloneProfile(profile)
	computed, digestErr := digestGovernanceProfile(profile)
	if validateProfile(profile) != nil || digestErr != nil || computed != expected.GovernanceProfileDigestSHA256 {
		return Profile{}, ErrSnapshotInconsistent
	}
	return profile, nil
}

func (p *Planner) validateHistoricalPolicyApprovals(ctx context.Context, record PolicyRecordSnapshot,
	projection foundationv1.PolicyBundleSigningProjection, profile Profile) error {
	if len(record.ApprovalEvidence) == 0 || len(record.ApprovalEvidence) > maxApprovals ||
		len(record.ApprovalEvidence) != len(record.ApproverIdentities) ||
		uint32(len(record.ApprovalEvidence)) < record.MinimumApprovals || record.MinimumApprovals < profile.MinimumApprovals {
		return ErrSnapshotInconsistent
	}
	identities := make([]string, 0, len(record.ApprovalEvidence))
	keyIDs := make([]string, 0, len(record.ApprovalEvidence))
	recordDigests := make([][ccse.DigestSize]byte, 0, len(record.ApprovalEvidence))
	keys := make([]GovernanceKeySnapshot, 0, len(record.ApprovalEvidence))
	authorizationDigests := make([][ccse.DigestSize]byte, 0, len(record.ApprovalEvidence)+1)
	var correlation [ccse.MessageIDSize]byte
	var causation ccse.OptionalMessageID
	for index, retained := range record.ApprovalEvidence {
		if retained.Signed.Record == nil || retained.GovernanceProfileActivation != record.AcceptanceEvidence.GovernanceProfileActivation ||
			!validGovernanceProfileActivation(retained.GovernanceProfileActivation, retained.Signed.Record.Domain.IssuedAtUnixNano) {
			return ErrSnapshotInconsistent
		}
		signed, err := p.validateHistoricalSignedPolicyRecord(ctx, retained.Signed, profile)
		if err != nil || !bytes.Equal(signed.record.Payload, record.CanonicalPayload) ||
			signed.record.Envelope.PayloadDigest != record.BundleDigestSHA256 ||
			projection.Metadata.CreatedAtUnixNano > signed.record.Domain.IssuedAtUnixNano ||
			record.AcceptanceEvidence.AcceptedAtUnixNano < signed.record.Domain.IssuedAtUnixNano ||
			record.AcceptanceEvidence.AcceptedAtUnixNano >= signed.record.Domain.ExpiresAtUnixNano {
			return ErrSnapshotInconsistent
		}
		issuedActivation, activeAtIssue, timelineErr := p.profiles.ActiveGovernanceProfile(ctx, signed.record.Domain.IssuedAtUnixNano)
		if timelineErr != nil || !activeAtIssue || issuedActivation != retained.GovernanceProfileActivation ||
			issuedActivation.GovernanceProfileDigestSHA256 != record.GovernanceProfileDigestSHA256 {
			return ErrSnapshotInconsistent
		}
		if (record.State == PolicyStateApprovedDelayed || (record.State == PolicyStateActive && record.Emergency)) &&
			signed.record.Domain.IssuedAtUnixNano > record.ApprovedAtUnixNano {
			return ErrSnapshotInconsistent
		}
		key, err := authorizeHistoricalPolicyKey(signed, retained.Key, profile)
		if err != nil {
			return ErrSnapshotInconsistent
		}
		authoritative, found, historyErr := p.iam.ResolveGovernanceKeyAt(
			ctx, key.KeyID, record.AcceptanceEvidence.AcceptedAtUnixNano)
		if historyErr != nil || !found || !preflightKeySnapshot(authoritative) ||
			!exactGovernanceKeySnapshot(key, authoritative) {
			return ErrSnapshotInconsistent
		}
		if index == 0 {
			correlation = signed.record.Envelope.CorrelationID
			causation = signed.record.Envelope.CausationID
		} else if correlation != signed.record.Envelope.CorrelationID || causation != signed.record.Envelope.CausationID {
			return ErrSnapshotInconsistent
		}
		identities = append(identities, signed.record.Domain.SenderIdentity)
		keyIDs = append(keyIDs, signed.record.Domain.SignatureKeyID)
		recordDigests = append(recordDigests, signed.digest)
		keys = append(keys, key)
		authorizationDigests = append(authorizationDigests, key.AuthorizationPolicyDigestSHA256)
	}
	if hasDuplicateStrings(identities) || hasDuplicateStrings(keyIDs) || hasDuplicateDigests(recordDigests) ||
		!equalStringSets(identities, record.ApproverIdentities) || !equalStringSets(keyIDs, record.ApproverKeyIDs) {
		return ErrSnapshotInconsistent
	}
	organizations := make([]string, 0, len(keys))
	for _, key := range keys {
		organizations = append(organizations, key.OrganizationIdentity)
	}
	if uint32(distinctStringCount(organizations)) < profile.MinimumDistinctApprovalOrganizations ||
		!rolesHaveDistinctAssignment(keys, profile.RequiredApprovalRoles) {
		return ErrSnapshotInconsistent
	}
	if record.Emergency && (record.MinimumApprovals < profile.BreakGlassMinimumApprovals ||
		uint32(distinctStringCount(organizations)) < profile.BreakGlassMinimumDistinctOrganizations ||
		!rolesHaveDistinctAssignment(keys, profile.BreakGlassRequiredRoles)) {
		return ErrSnapshotInconsistent
	}
	authorizationDigests = uniqueSortedDigests(append(authorizationDigests, record.GovernanceProfileDigestSHA256))
	if !equalDigestSets(projection.Metadata.PolicyDigestsSHA256, authorizationDigests) {
		return ErrSnapshotInconsistent
	}
	return contextErr(ctx)
}

func validGovernanceProfileActivation(snapshot GovernanceProfileActivationSnapshot, at int64) bool {
	return !isZeroDigest(snapshot.GovernanceProfileDigestSHA256) && snapshot.Version != 0 &&
		!isZeroDigest(snapshot.EvidenceDigestSHA256) && snapshot.ValidFromUnixNano >= 0 &&
		snapshot.ValidUntilUnixNano > snapshot.ValidFromUnixNano && at >= snapshot.ValidFromUnixNano && at < snapshot.ValidUntilUnixNano
}

func (p *Planner) validateHistoricalSignedPolicyRecord(ctx context.Context, input SignedRecord, profile Profile) (signedRecordSnapshot, error) {
	snapshot, err := bindHistoricalSignedRecord(input, maxPayloadBytesFor(schema.MessageTypePolicyBundle))
	if err != nil {
		return signedRecordSnapshot{}, ErrInvalidSignedRecord
	}
	record := snapshot.record
	if record.MessageTypeID != schema.MessageTypePolicyBundle || record.SchemaVersion != profile.SchemaVersion ||
		record.Domain.Purpose != policyPurpose || record.Domain.ProtocolVersion != profile.ProtocolVersion ||
		record.Envelope.ProtocolVersion != profile.ProtocolVersion || !equalStringSets(record.Domain.Audience, profile.Audience) ||
		record.Domain.TenantOrganization != profile.TenantOrganization || record.Domain.ProviderOrganization != profile.ProviderOrganization ||
		record.Domain.Environment != profile.Environment || record.Envelope.Environment != profile.Environment ||
		record.Domain.ChainID != profile.ChainID || record.Envelope.ChainID != profile.ChainID ||
		record.Domain.GenesisHash != profile.GenesisHash || record.Domain.ReplayDomainID != profile.PolicyReplayDomainID ||
		record.Domain.CounterKind != ccse.CounterSequence || record.Envelope.CounterKind != ccse.CounterSequence ||
		record.Domain.IssuedAtUnixNano < 0 || record.Domain.ExpiresAtUnixNano <= record.Domain.IssuedAtUnixNano ||
		record.Domain.ExpiresAtUnixNano-record.Domain.IssuedAtUnixNano > profile.MaxRecordValidityNanos {
		return signedRecordSnapshot{}, ErrWrongRecordContext
	}
	if err := p.canonical.ValidateExtensions(ctx, schema.MessageTypePolicyBundle, profile.SchemaVersion, record.Envelope.Extensions); err != nil ||
		sha256.Sum256(record.Payload) != record.Envelope.PayloadDigest {
		return signedRecordSnapshot{}, ErrInvalidSignedRecord
	}
	if _, err := p.canonical.Decode(schema.MessageTypePolicyBundle, profile.SchemaVersion, record.Payload); err != nil {
		return signedRecordSnapshot{}, ErrInvalidSignedRecord
	}
	return snapshot, nil
}

func authorizeHistoricalPolicyKey(signed signedRecordSnapshot, input GovernanceKeySnapshot, profile Profile) (GovernanceKeySnapshot, error) {
	if !preflightKeySnapshot(input) {
		return GovernanceKeySnapshot{}, ErrSnapshotInconsistent
	}
	key := cloneKeySnapshot(input)
	if key.KeyID == "" || key.KeyID != signed.record.Domain.SignatureKeyID || key.KeyID != signed.record.Envelope.SignatureKeyID ||
		key.SubjectIdentity == "" || key.SubjectIdentity != signed.record.Domain.SenderIdentity ||
		key.SubjectIdentity != signed.record.Envelope.SenderIdentity || key.TargetIdentityKind != 1 ||
		key.TargetPrincipalKind < 1 || key.TargetPrincipalKind > 8 || key.TargetIdentityID == "" || key.OrganizationIdentity == "" ||
		key.EnrollmentDomainID != profile.EnrollmentDomainID || key.EnrollmentEnvironment != profile.Environment ||
		key.EnrollmentGenesisHash != profile.GenesisHash || key.LifecycleState != KeyLifecycleStateActive || key.RevokedAtUnixNano != 0 ||
		key.NotBeforeUnixNano < 0 || key.NotAfterUnixNano <= key.NotBeforeUnixNano ||
		signed.record.Domain.IssuedAtUnixNano < key.NotBeforeUnixNano || signed.record.Domain.ExpiresAtUnixNano > key.NotAfterUnixNano ||
		!containsMessageType(key.AllowedMessageTypeIDs, schema.MessageTypePolicyBundle) ||
		isZeroDigest(key.AuthorizationPolicyDigestSHA256) || key.StateVersion == 0 || key.WriterEpoch == 0 ||
		isZeroDigest(key.SnapshotDigestSHA256) || key.IdentityStateVersion == 0 || key.IdentityWriterEpoch == 0 ||
		isZeroDigest(key.IdentitySnapshotDigestSHA256) || hasDuplicateUint32(key.AllowedMessageTypeIDs) ||
		hasDuplicateStrings(key.Roles) || containsEmpty(key.Roles) || key.Algorithm != signed.record.Domain.SignatureAlgorithm ||
		key.Algorithm != signed.record.Envelope.SignatureAlgorithm {
		return GovernanceKeySnapshot{}, ErrKeyNotAuthorized
	}
	if key.Algorithm != ccse.SignatureAlgorithmEd25519 || len(key.PublicKey) != ed25519.PublicKeySize ||
		len(signed.record.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(ed25519.PublicKey(key.PublicKey), signed.digest[:], signed.record.Signature) {
		return GovernanceKeySnapshot{}, ErrInvalidSignature
	}
	return key, nil
}

func historicalApprovalEvidenceEqual(left, right []HistoricalPolicyApprovalEvidence) bool {
	if len(left) != len(right) {
		return false
	}
	leftDigests, err := historicalApprovalEvidenceDigests(left)
	if err != nil {
		return false
	}
	rightDigests, err := historicalApprovalEvidenceDigests(right)
	if err != nil || len(leftDigests) != len(rightDigests) {
		return false
	}
	for index := range leftDigests {
		if leftDigests[index] != rightDigests[index] {
			return false
		}
	}
	return true
}

func historicalApprovalEvidenceDigests(input []HistoricalPolicyApprovalEvidence) ([][ccse.DigestSize]byte, error) {
	result := make([][ccse.DigestSize]byte, 0, len(input))
	for _, retained := range input {
		if retained.Signed.Record == nil || !preflightRawRecord(retained.Signed.Record, maxPayloadBytesFor(schema.MessageTypePolicyBundle)) ||
			!preflightKeySnapshot(retained.Key) {
			return nil, ErrSnapshotInconsistent
		}
		snapshot, err := bindHistoricalSignedRecord(retained.Signed, maxPayloadBytesFor(schema.MessageTypePolicyBundle))
		if err != nil {
			return nil, err
		}
		w := newDigestWriter(historicalApprovalEvidenceDigestDomain)
		w.evidence(newSignedEvidence(snapshot))
		w.digest(digestGovernanceAuthorizationSnapshot(retained.Key))
		w.profileActivation(retained.GovernanceProfileActivation)
		value, err := w.sum()
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	sortDigests(result)
	return result, nil
}

func sortedHistoricalOrganizations(keys []GovernanceKeySnapshot) []string {
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key.OrganizationIdentity)
	}
	sort.Strings(result)
	return result
}
