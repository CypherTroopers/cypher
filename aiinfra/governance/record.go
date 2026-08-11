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
)

type signedRecordSnapshot struct {
	record ccse.Record
	digest [ccse.DigestSize]byte
}

func (p *Planner) validateEvidenceSignedRecord(ctx context.Context, input SignedRecord, at int64) (signedRecordSnapshot, GovernanceKeySnapshot, error) {
	const maxEvidencePayloadBytes = 1 << 20
	snapshot, err := bindVerifiedSignedRecord(input, maxEvidencePayloadBytes)
	if err != nil {
		return signedRecordSnapshot{}, GovernanceKeySnapshot{}, ErrInvalidSignedRecord
	}
	record := snapshot.record
	if record.MessageTypeID == 0 || record.SchemaVersion != p.profile.SchemaVersion ||
		record.Domain.ProtocolVersion != p.profile.ProtocolVersion || record.Envelope.ProtocolVersion != p.profile.ProtocolVersion ||
		record.Domain.TenantOrganization != p.profile.TenantOrganization ||
		record.Domain.ProviderOrganization != p.profile.ProviderOrganization ||
		record.Domain.Environment != p.profile.Environment || record.Envelope.Environment != p.profile.Environment ||
		record.Domain.ChainID != p.profile.ChainID || record.Envelope.ChainID != p.profile.ChainID ||
		record.Domain.GenesisHash != p.profile.GenesisHash || record.Domain.Purpose == "" || record.Domain.ReplayDomainID == "" ||
		record.Domain.CounterKind != ccse.CounterSequence || record.Envelope.CounterKind != ccse.CounterSequence ||
		record.Domain.IssuedAtUnixNano > at || record.Domain.ExpiresAtUnixNano <= at ||
		record.Domain.ExpiresAtUnixNano-record.Domain.IssuedAtUnixNano > p.profile.MaxRecordValidityNanos {
		return signedRecordSnapshot{}, GovernanceKeySnapshot{}, ErrWrongRecordContext
	}
	if err := p.canonical.ValidateExtensions(ctx, record.MessageTypeID, record.SchemaVersion, record.Envelope.Extensions); err != nil {
		return signedRecordSnapshot{}, GovernanceKeySnapshot{}, ErrInvalidSignedRecord
	}
	if sha256.Sum256(record.Payload) != record.Envelope.PayloadDigest {
		return signedRecordSnapshot{}, GovernanceKeySnapshot{}, ccse.ErrPayloadDigestMismatch
	}
	if _, err := p.canonical.Decode(record.MessageTypeID, record.SchemaVersion, record.Payload); err != nil {
		return signedRecordSnapshot{}, GovernanceKeySnapshot{}, ErrInvalidSignedRecord
	}
	key, err := p.authorizeKey(ctx, snapshot, record.MessageTypeID, at)
	if err != nil {
		return signedRecordSnapshot{}, GovernanceKeySnapshot{}, err
	}
	return snapshot, key, nil
}

func (p *Planner) validateSignedRecord(ctx context.Context, input SignedRecord, messageTypeID uint32, purpose, replayDomain string, at int64) (signedRecordSnapshot, error) {
	if input.Record == nil {
		return signedRecordSnapshot{}, ErrInvalidSignedRecord
	}
	maxPayloadBytes := maxPayloadBytesFor(messageTypeID)
	if maxPayloadBytes == 0 {
		return signedRecordSnapshot{}, ErrInvalidSignedRecord
	}
	snapshot, err := bindVerifiedSignedRecord(input, maxPayloadBytes)
	if err != nil {
		return signedRecordSnapshot{}, fmt.Errorf("%w: %v", ErrInvalidSignedRecord, err)
	}
	record := snapshot.record
	if record.MessageTypeID != messageTypeID || record.SchemaVersion != p.profile.SchemaVersion || record.Domain.Purpose != purpose ||
		record.Domain.ProtocolVersion != p.profile.ProtocolVersion || record.Envelope.ProtocolVersion != p.profile.ProtocolVersion ||
		!equalStringSets(record.Domain.Audience, p.profile.Audience) || record.Domain.TenantOrganization != p.profile.TenantOrganization ||
		record.Domain.ProviderOrganization != p.profile.ProviderOrganization || record.Domain.Environment != p.profile.Environment ||
		record.Envelope.Environment != p.profile.Environment || record.Domain.ChainID != p.profile.ChainID ||
		record.Envelope.ChainID != p.profile.ChainID || record.Domain.GenesisHash != p.profile.GenesisHash ||
		record.Domain.ReplayDomainID != replayDomain || record.Domain.CounterKind != ccse.CounterSequence ||
		record.Envelope.CounterKind != ccse.CounterSequence {
		return signedRecordSnapshot{}, ErrWrongRecordContext
	}
	if at < 0 || record.Domain.IssuedAtUnixNano > at || record.Domain.ExpiresAtUnixNano <= at ||
		record.Domain.ExpiresAtUnixNano-record.Domain.IssuedAtUnixNano > p.profile.MaxRecordValidityNanos {
		return signedRecordSnapshot{}, fmt.Errorf("%w: record is not currently valid", ErrWrongRecordContext)
	}
	if err := p.canonical.ValidateExtensions(ctx, messageTypeID, p.profile.SchemaVersion, record.Envelope.Extensions); err != nil {
		return signedRecordSnapshot{}, fmt.Errorf("%w: %v", ErrInvalidSignedRecord, err)
	}
	payloadDigest := sha256.Sum256(record.Payload)
	if payloadDigest != record.Envelope.PayloadDigest {
		return signedRecordSnapshot{}, ccse.ErrPayloadDigestMismatch
	}
	return snapshot, nil
}

// bindVerifiedSignedRecord performs the cheap scalar binding first, then
// bounds both representations before making any detached compound copy. The
// raw record is copied exactly once and that same copy is hashed and compared
// with the immutable verifier snapshot, including the detached signature.
func bindVerifiedSignedRecord(input SignedRecord, maxPayloadBytes int) (signedRecordSnapshot, error) {
	if input.Record == nil || maxPayloadBytes <= 0 {
		return signedRecordSnapshot{}, ErrInvalidSignedRecord
	}
	raw := input.Record
	verifiedMessageType := input.Verified.MessageTypeID()
	verifiedSchemaVersion := input.Verified.SchemaVersion()
	verifiedDigest := input.Verified.Digest()
	if verifiedMessageType != raw.MessageTypeID || verifiedSchemaVersion != raw.SchemaVersion || isZeroDigest(verifiedDigest) {
		return signedRecordSnapshot{}, ErrInvalidSignedRecord
	}
	limits := ccse.DefaultLimits()
	if maxPayloadBytes < limits.MaxPayloadBytes {
		limits.MaxPayloadBytes = maxPayloadBytes
	}
	if !preflightRawRecord(raw, maxPayloadBytes) || input.Verified.ValidateLimits(limits) != nil {
		return signedRecordSnapshot{}, ErrInvalidSignedRecord
	}
	record := cloneCCSERecord(raw)
	digest, err := record.Digest(limits)
	if err != nil || digest != verifiedDigest {
		return signedRecordSnapshot{}, ErrInvalidSignedRecord
	}
	verifiedDomain := input.Verified.Domain()
	verifiedEnvelope := input.Verified.Envelope()
	verifiedPayload := input.Verified.Payload()
	verifiedSignature := input.Verified.Signature()
	if len(verifiedPayload) > maxPayloadBytes || len(verifiedDomain.Audience) > 64 || len(verifiedEnvelope.Extensions) > 64 ||
		!equalDomains(record.Domain, verifiedDomain) || !equalEnvelopes(record.Envelope, verifiedEnvelope) ||
		!bytes.Equal(record.Payload, verifiedPayload) || !bytes.Equal(record.Signature, verifiedSignature) {
		return signedRecordSnapshot{}, ErrInvalidSignedRecord
	}
	return signedRecordSnapshot{record: record, digest: digest}, nil
}

// bindHistoricalSignedRecord is the restart-safe counterpart of
// bindVerifiedSignedRecord. Live ingress must still carry the opaque
// ccse.VerifiedRecord produced by the replay-owning verifier. Durable history,
// however, retains the complete signed record and re-authenticates it against
// an authoritative historical IAM snapshot; replaying it merely to recreate a
// VerifiedRecord would be both incorrect and unavailable after restart.
//
// A nonzero VerifiedRecord is never ignored: if one is supplied, its complete
// byte-for-byte binding remains mandatory. Only the literal zero value selects
// the raw historical path.
func bindHistoricalSignedRecord(input SignedRecord, maxPayloadBytes int) (signedRecordSnapshot, error) {
	if input.Verified.MessageTypeID() != 0 || input.Verified.SchemaVersion() != (ccse.Version{}) ||
		input.Verified.Digest() != ([ccse.DigestSize]byte{}) {
		return bindVerifiedSignedRecord(input, maxPayloadBytes)
	}
	if input.Record == nil || maxPayloadBytes <= 0 || !preflightRawRecord(input.Record, maxPayloadBytes) {
		return signedRecordSnapshot{}, ErrInvalidSignedRecord
	}
	limits := ccse.DefaultLimits()
	if maxPayloadBytes < limits.MaxPayloadBytes {
		limits.MaxPayloadBytes = maxPayloadBytes
	}
	record := cloneCCSERecord(input.Record)
	digest, err := record.Digest(limits)
	if err != nil || isZeroDigest(digest) {
		return signedRecordSnapshot{}, ErrInvalidSignedRecord
	}
	return signedRecordSnapshot{record: record, digest: digest}, nil
}

func exactGovernanceKeySnapshot(left, right GovernanceKeySnapshot) bool {
	return left.KeyID == right.KeyID && left.SubjectIdentity == right.SubjectIdentity &&
		left.TargetIdentityKind == right.TargetIdentityKind && left.TargetPrincipalKind == right.TargetPrincipalKind &&
		left.TargetIdentityID == right.TargetIdentityID && left.OrganizationIdentity == right.OrganizationIdentity &&
		left.Algorithm == right.Algorithm && bytes.Equal(left.PublicKey, right.PublicKey) &&
		left.LifecycleState == right.LifecycleState && left.NotBeforeUnixNano == right.NotBeforeUnixNano &&
		left.NotAfterUnixNano == right.NotAfterUnixNano && left.RevokedAtUnixNano == right.RevokedAtUnixNano &&
		equalUint32Sets(left.AllowedMessageTypeIDs, right.AllowedMessageTypeIDs) &&
		equalStringSets(left.Roles, right.Roles) &&
		left.AuthorizationPolicyDigestSHA256 == right.AuthorizationPolicyDigestSHA256 &&
		left.StateVersion == right.StateVersion && left.WriterEpoch == right.WriterEpoch &&
		left.SnapshotDigestSHA256 == right.SnapshotDigestSHA256 &&
		left.IdentityStateVersion == right.IdentityStateVersion &&
		left.IdentityWriterEpoch == right.IdentityWriterEpoch &&
		left.IdentitySnapshotDigestSHA256 == right.IdentitySnapshotDigestSHA256 &&
		left.EnrollmentDomainID == right.EnrollmentDomainID &&
		left.EnrollmentEnvironment == right.EnrollmentEnvironment &&
		left.EnrollmentGenesisHash == right.EnrollmentGenesisHash
}

func equalUint32Sets(left, right []uint32) bool {
	if len(left) != len(right) || hasDuplicateUint32(left) || hasDuplicateUint32(right) {
		return false
	}
	for _, value := range left {
		if !containsMessageType(right, value) {
			return false
		}
	}
	return true
}

func (p *Planner) authorizeKey(ctx context.Context, signed signedRecordSnapshot, messageTypeID uint32, at int64) (GovernanceKeySnapshot, error) {
	keyID := signed.record.Domain.SignatureKeyID
	key, err := p.iam.ResolveGovernanceKey(ctx, keyID)
	if err != nil {
		return GovernanceKeySnapshot{}, fmt.Errorf("%w: %v", ErrUnknownGovernanceKey, err)
	}
	if !preflightKeySnapshot(key) {
		return GovernanceKeySnapshot{}, ErrSnapshotInconsistent
	}
	key = cloneKeySnapshot(key)
	if key.KeyID == "" || key.KeyID != keyID || key.KeyID != signed.record.Envelope.SignatureKeyID {
		return GovernanceKeySnapshot{}, ErrUnknownGovernanceKey
	}
	if key.SubjectIdentity == "" || key.SubjectIdentity != signed.record.Domain.SenderIdentity ||
		key.SubjectIdentity != signed.record.Envelope.SenderIdentity {
		return GovernanceKeySnapshot{}, ErrKeyOwnership
	}
	if key.TargetIdentityKind != 1 || key.TargetPrincipalKind < 1 || key.TargetPrincipalKind > 8 ||
		key.TargetIdentityID == "" || key.OrganizationIdentity == "" {
		return GovernanceKeySnapshot{}, ErrSnapshotInconsistent
	}
	if key.EnrollmentDomainID != p.profile.EnrollmentDomainID || key.EnrollmentEnvironment != p.profile.Environment ||
		key.EnrollmentGenesisHash != p.profile.GenesisHash {
		return GovernanceKeySnapshot{}, ErrKeyNotAuthorized
	}
	if key.RevokedAtUnixNano < 0 {
		return GovernanceKeySnapshot{}, ErrSnapshotInconsistent
	}
	// Revocation is permanent for authorization: a signature retained from
	// before the revocation cannot activate a new policy afterward.
	if key.RevokedAtUnixNano != 0 {
		return GovernanceKeySnapshot{}, ErrKeyRevoked
	}
	if key.NotBeforeUnixNano < 0 || key.NotAfterUnixNano <= key.NotBeforeUnixNano || at < key.NotBeforeUnixNano ||
		signed.record.Domain.IssuedAtUnixNano < key.NotBeforeUnixNano {
		return GovernanceKeySnapshot{}, ErrKeyNotActive
	}
	if at >= key.NotAfterUnixNano || signed.record.Domain.ExpiresAtUnixNano > key.NotAfterUnixNano {
		return GovernanceKeySnapshot{}, ErrKeyExpired
	}
	if key.LifecycleState != KeyLifecycleStateActive {
		return GovernanceKeySnapshot{}, ErrKeyNotActive
	}
	if !containsMessageType(key.AllowedMessageTypeIDs, messageTypeID) || isZeroDigest(key.AuthorizationPolicyDigestSHA256) {
		return GovernanceKeySnapshot{}, ErrKeyNotAuthorized
	}
	if key.StateVersion == 0 || key.WriterEpoch == 0 || isZeroDigest(key.SnapshotDigestSHA256) ||
		key.IdentityStateVersion == 0 || key.IdentityWriterEpoch == 0 || isZeroDigest(key.IdentitySnapshotDigestSHA256) {
		return GovernanceKeySnapshot{}, ErrSnapshotInconsistent
	}
	if hasDuplicateUint32(key.AllowedMessageTypeIDs) || hasDuplicateStrings(key.Roles) || containsEmpty(key.Roles) {
		return GovernanceKeySnapshot{}, ErrSnapshotInconsistent
	}
	if key.Algorithm != signed.record.Domain.SignatureAlgorithm || key.Algorithm != signed.record.Envelope.SignatureAlgorithm {
		return GovernanceKeySnapshot{}, ErrKeyNotAuthorized
	}
	switch key.Algorithm {
	case ccse.SignatureAlgorithmEd25519:
		if len(key.PublicKey) != ed25519.PublicKeySize || len(signed.record.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(ed25519.PublicKey(key.PublicKey), signed.digest[:], signed.record.Signature) {
			return GovernanceKeySnapshot{}, ErrInvalidSignature
		}
	default:
		return GovernanceKeySnapshot{}, fmt.Errorf("%w: unsupported algorithm %d", ErrKeyNotAuthorized, key.Algorithm)
	}
	return cloneKeySnapshot(key), nil
}

func cloneCCSERecord(input *ccse.Record) ccse.Record {
	copyRecord := *input
	copyRecord.Domain.Audience = append([]string(nil), input.Domain.Audience...)
	copyRecord.Envelope.Extensions = cloneExtensions(input.Envelope.Extensions)
	copyRecord.Payload = append([]byte(nil), input.Payload...)
	copyRecord.Signature = append([]byte(nil), input.Signature...)
	return copyRecord
}

func cloneExtensions(input []ccse.Extension) []ccse.Extension {
	result := make([]ccse.Extension, len(input))
	for index := range input {
		result[index] = input[index]
		result[index].Value = append([]byte(nil), input[index].Value...)
	}
	return result
}

func equalDomains(left, right ccse.Domain) bool {
	return left.Purpose == right.Purpose && left.SenderIdentity == right.SenderIdentity &&
		equalStringSets(left.Audience, right.Audience) && left.TenantOrganization == right.TenantOrganization &&
		left.ProviderOrganization == right.ProviderOrganization && left.ChainID == right.ChainID &&
		left.GenesisHash == right.GenesisHash && left.Environment == right.Environment &&
		left.ProtocolVersion == right.ProtocolVersion && left.SchemaVersion == right.SchemaVersion &&
		left.SignatureAlgorithm == right.SignatureAlgorithm && left.SignatureKeyID == right.SignatureKeyID &&
		left.IssuedAtUnixNano == right.IssuedAtUnixNano && left.ExpiresAtUnixNano == right.ExpiresAtUnixNano &&
		left.CounterKind == right.CounterKind && left.Counter == right.Counter && left.ReplayDomainID == right.ReplayDomainID
}

func equalEnvelopes(left, right ccse.Envelope) bool {
	leftExtensions := canonicalExtensionCopy(left.Extensions)
	rightExtensions := canonicalExtensionCopy(right.Extensions)
	if left.ProtocolVersion != right.ProtocolVersion || left.SchemaVersion != right.SchemaVersion ||
		left.MessageID != right.MessageID || left.CorrelationID != right.CorrelationID || left.CausationID != right.CausationID ||
		left.SenderIdentity != right.SenderIdentity || left.ChainID != right.ChainID || left.Environment != right.Environment ||
		left.IssuedAtUnixNano != right.IssuedAtUnixNano || left.ExpiresAtUnixNano != right.ExpiresAtUnixNano ||
		left.CounterKind != right.CounterKind || left.Counter != right.Counter || left.PayloadDigest != right.PayloadDigest ||
		left.SignatureAlgorithm != right.SignatureAlgorithm || left.SignatureKeyID != right.SignatureKeyID ||
		len(leftExtensions) != len(rightExtensions) {
		return false
	}
	for index := range leftExtensions {
		if leftExtensions[index].ID != rightExtensions[index].ID || leftExtensions[index].Critical != rightExtensions[index].Critical ||
			!bytes.Equal(leftExtensions[index].Value, rightExtensions[index].Value) {
			return false
		}
	}
	return true
}

func canonicalExtensionCopy(input []ccse.Extension) []ccse.Extension {
	result := cloneExtensions(input)
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func hasDuplicateUint32(values []uint32) bool {
	seen := make(map[uint32]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func maxPayloadBytesFor(messageTypeID uint32) int {
	switch messageTypeID {
	case 0x0001000a: // FOUNDATION_POLICY_BUNDLE_V1
		return 49152
	case 0x0001000b: // FOUNDATION_AUDIT_EVENT_V1
		return 65536
	default:
		return 0
	}
}

// preflightRawRecord touches only lengths and scalar headers. It bounds every
// attacker-controlled slice before cloneCCSERecord allocates a detached copy.
// As with ccse.Verifier, callers transfer read ownership for the call and must
// not concurrently mutate the record.
func preflightRawRecord(record *ccse.Record, maxPayloadBytes int) bool {
	if record == nil || maxPayloadBytes <= 0 || len(record.Payload) > maxPayloadBytes ||
		len(record.Signature) == 0 || len(record.Signature) > ccse.DefaultLimits().MaxSignatureBytes ||
		len(record.Domain.Audience) == 0 || len(record.Domain.Audience) > 64 || len(record.Envelope.Extensions) > 64 {
		return false
	}
	domainLimit := ccse.DefaultLimits().MaxDomainBytes
	domainSize := 256
	for _, value := range []string{
		record.Domain.Purpose, record.Domain.SenderIdentity, record.Domain.TenantOrganization.Value,
		record.Domain.ProviderOrganization.Value, record.Domain.Environment, record.Domain.SignatureKeyID,
		record.Domain.ReplayDomainID,
	} {
		if !boundedSizeAdd(&domainSize, len(value), domainLimit) {
			return false
		}
	}
	for _, audience := range record.Domain.Audience {
		if !boundedSizeAdd(&domainSize, len(audience)+4, domainLimit) {
			return false
		}
	}
	envelopeLimit := ccse.DefaultLimits().MaxEnvelopeBytes
	envelopeSize := 256
	for _, value := range []string{record.Envelope.SenderIdentity, record.Envelope.Environment, record.Envelope.SignatureKeyID} {
		if !boundedSizeAdd(&envelopeSize, len(value), envelopeLimit) {
			return false
		}
	}
	for _, extension := range record.Envelope.Extensions {
		if !boundedSizeAdd(&envelopeSize, len(extension.Value)+16, envelopeLimit) {
			return false
		}
	}
	return true
}

func boundedSizeAdd(total *int, value, limit int) bool {
	if total == nil || value < 0 || limit < 0 || *total < 0 || *total > limit || value > limit-*total {
		return false
	}
	*total += value
	return true
}

func preflightKeySnapshot(key GovernanceKeySnapshot) bool {
	if len(key.PublicKey) > 4096 || len(key.AllowedMessageTypeIDs) == 0 || len(key.AllowedMessageTypeIDs) > 256 ||
		len(key.Roles) == 0 || len(key.Roles) > 64 {
		return false
	}
	total := 0
	for _, value := range append(append([]string{key.KeyID, key.SubjectIdentity, key.TargetIdentityID, key.OrganizationIdentity, key.EnrollmentDomainID, key.EnrollmentEnvironment}, key.Roles...), "") {
		if !boundedSizeAdd(&total, len(value), 32<<10) {
			return false
		}
	}
	return true
}
