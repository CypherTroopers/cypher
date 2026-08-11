// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package foundationv1

import (
	"fmt"
	"math"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/schema"
)

const (
	ownershipTransferAuthorizationMaxPayload = 196608
	keyClosureMaxPayload                     = 512
	transferEvidenceCommitmentMaxPayload     = 64
	transferAuthorityMaxPayload              = 1536

	TransferEvidenceOldProviderAuthority        = uint32(1)
	TransferEvidenceNewProviderAuthority        = uint32(2)
	TransferEvidenceHostSanitationAttestation   = uint32(3)
	TransferEvidenceDeviceSanitationAttestation = uint32(4)
	TransferEvidenceDescendantIdentityClosure   = uint32(5)
	TransferEvidenceLeaseOfferWorkloadClosure   = uint32(6)
	TransferEvidenceNewAttestationReadiness     = uint32(7)
)

var ownershipTransferAuthorizationSigningFields = [...]string{
	"metadata", "transfer_authorization_id", "subject_kind", "previous_entity_id", "next_entity_id",
	"previous_principal_identity", "next_principal_identity", "previous_provider_id", "next_provider_id",
	"expected_generation", "next_generation", "previous_terminal_identity_payload_digest_sha256",
	"next_pending_identity_payload_digest_sha256", "old_key_closures", "new_key_id", "evidence_commitments",
	"effective_at_unix_nano", "expires_at_unix_nano", "old_authorities", "new_authorities",
}

var keyClosureSigningFields = [...]string{
	"key_id", "terminal_key_lifecycle_payload_digest_sha256",
}

var transferEvidenceCommitmentSigningFields = [...]string{
	"evidence_kind", "ccse_record_digest_sha256",
}

var transferAuthoritySigningFields = [...]string{
	"identity", "key_id",
}

// KeyClosureSigningProjection commits one old key to its terminal
// KeyLifecycle payload. The complete signed lifecycle record remains external
// evidence and must be retained by the receiver.
type KeyClosureSigningProjection struct {
	KeyID                                   string
	TerminalKeyLifecyclePayloadDigestSHA256 [32]byte
}

// TransferEvidenceCommitmentSigningProjection binds one typed, complete CCSE
// evidence record without embedding it or introducing a digest cycle.
type TransferEvidenceCommitmentSigningProjection struct {
	EvidenceKind           uint32
	CCSERecordDigestSHA256 [32]byte
}

// TransferAuthoritySigningProjection is an exact authority identity/key pair.
// Frozen IAM policy, rather than this payload, determines the required sets.
type TransferAuthoritySigningProjection struct {
	Identity string
	KeyID    string
}

// OwnershipTransferAuthorizationSigningProjection is the canonical signed
// authorization for an Agent, Host, or Device ownership transfer.
type OwnershipTransferAuthorizationSigningProjection struct {
	Metadata                                    RecordMetadataSigningProjection
	TransferAuthorizationID                     string
	SubjectKind                                 uint32
	PreviousEntityID                            string
	NextEntityID                                string
	PreviousPrincipalIdentity                   string
	NextPrincipalIdentity                       string
	PreviousProviderID                          string
	NextProviderID                              string
	ExpectedGeneration                          uint64
	NextGeneration                              uint64
	PreviousTerminalIdentityPayloadDigestSHA256 [32]byte
	NextPendingIdentityPayloadDigestSHA256      [32]byte
	OldKeyClosures                              []KeyClosureSigningProjection
	NewKeyID                                    string
	EvidenceCommitments                         []TransferEvidenceCommitmentSigningProjection
	EffectiveAtUnixNano                         int64
	ExpiresAtUnixNano                           int64
	OldAuthorities                              []TransferAuthoritySigningProjection
	NewAuthorities                              []TransferAuthoritySigningProjection
}

func (p KeyClosureSigningProjection) CanonicalBytes() ([]byte, error) {
	if err := validateRequiredStringField("key_closure.key_id", p.KeyID, 256); err != nil {
		return nil, err
	}
	if err := validateRequiredFixed32("key_closure.terminal_key_lifecycle_payload_digest_sha256", p.TerminalKeyLifecyclePayloadDigestSHA256); err != nil {
		return nil, err
	}
	return ccse.Marshal(keyClosureMaxPayload, func(out *ccse.Encoder) {
		out.String(p.KeyID)
		out.FixedBytes(p.TerminalKeyLifecyclePayloadDigestSHA256[:], 32)
	})
}

func (KeyClosureSigningProjection) SigningFieldNames() []string {
	return copyFieldNames(keyClosureSigningFields[:])
}

func (p TransferEvidenceCommitmentSigningProjection) CanonicalBytes() ([]byte, error) {
	if err := validateEnumRange("transfer_evidence_commitment.evidence_kind", p.EvidenceKind, TransferEvidenceOldProviderAuthority, TransferEvidenceNewAttestationReadiness); err != nil {
		return nil, err
	}
	if err := validateRequiredFixed32("transfer_evidence_commitment.ccse_record_digest_sha256", p.CCSERecordDigestSHA256); err != nil {
		return nil, err
	}
	return ccse.Marshal(transferEvidenceCommitmentMaxPayload, func(out *ccse.Encoder) {
		out.Uint32(p.EvidenceKind)
		out.FixedBytes(p.CCSERecordDigestSHA256[:], 32)
	})
}

func (TransferEvidenceCommitmentSigningProjection) SigningFieldNames() []string {
	return copyFieldNames(transferEvidenceCommitmentSigningFields[:])
}

func (p TransferAuthoritySigningProjection) CanonicalBytes() ([]byte, error) {
	if err := validateRequiredStringField("transfer_authority.identity", p.Identity, 1024); err != nil {
		return nil, err
	}
	if err := validateRequiredStringField("transfer_authority.key_id", p.KeyID, 256); err != nil {
		return nil, err
	}
	return ccse.Marshal(transferAuthorityMaxPayload, func(out *ccse.Encoder) {
		out.String(p.Identity)
		out.String(p.KeyID)
	})
}

func (TransferAuthoritySigningProjection) SigningFieldNames() []string {
	return copyFieldNames(transferAuthoritySigningFields[:])
}

// CanonicalBytes emits the ordered payload projection fixed by registry.json.
func (p OwnershipTransferAuthorizationSigningProjection) CanonicalBytes() ([]byte, error) {
	metadata, err := p.Metadata.prepare()
	if err != nil {
		return nil, err
	}
	for _, field := range []struct {
		name  string
		value string
		max   int
	}{
		{"transfer_authorization_id", p.TransferAuthorizationID, 256},
		{"previous_entity_id", p.PreviousEntityID, 256},
		{"next_entity_id", p.NextEntityID, 256},
		{"previous_principal_identity", p.PreviousPrincipalIdentity, 1024},
		{"next_principal_identity", p.NextPrincipalIdentity, 1024},
		{"previous_provider_id", p.PreviousProviderID, 256},
		{"next_provider_id", p.NextProviderID, 256},
		{"new_key_id", p.NewKeyID, 256},
	} {
		if err := validateRequiredStringField(field.name, field.value, field.max); err != nil {
			return nil, err
		}
	}
	if p.SubjectKind < 2 || p.SubjectKind > 4 {
		return nil, fmt.Errorf("%w: subject_kind=%d", ErrInvalidEnumValue, p.SubjectKind)
	}
	if p.PreviousEntityID == p.NextEntityID || p.PreviousProviderID == p.NextProviderID {
		return nil, fmt.Errorf("%w: transfer endpoints must differ", ErrInvalidProjectionValue)
	}
	if p.SubjectKind == 2 && p.PreviousPrincipalIdentity == p.NextPrincipalIdentity {
		return nil, fmt.Errorf("%w: agent principals must differ", ErrInvalidProjectionValue)
	}
	if (p.SubjectKind == 3 || p.SubjectKind == 4) && p.PreviousPrincipalIdentity != p.NextPrincipalIdentity {
		return nil, fmt.Errorf("%w: host/device principal must be preserved", ErrInvalidProjectionValue)
	}
	if p.ExpectedGeneration == 0 || p.ExpectedGeneration == math.MaxUint64 || p.NextGeneration != p.ExpectedGeneration+1 {
		return nil, fmt.Errorf("%w: ownership generation must advance exactly once", ErrInvalidProjectionValue)
	}
	if err := validateRequiredFixed32("previous_terminal_identity_payload_digest_sha256", p.PreviousTerminalIdentityPayloadDigestSHA256); err != nil {
		return nil, err
	}
	if err := validateRequiredFixed32("next_pending_identity_payload_digest_sha256", p.NextPendingIdentityPayloadDigestSHA256); err != nil {
		return nil, err
	}
	if p.PreviousTerminalIdentityPayloadDigestSHA256 == p.NextPendingIdentityPayloadDigestSHA256 {
		return nil, fmt.Errorf("%w: terminal and pending identity digests are equal", ErrInvalidProjectionValue)
	}
	if err := validateRequiredTimeRange("ownership transfer authorization", p.EffectiveAtUnixNano, p.ExpiresAtUnixNano); err != nil {
		return nil, err
	}
	if p.Metadata.CreatedAtUnixNano > p.EffectiveAtUnixNano {
		return nil, fmt.Errorf("%w: transfer effective before record creation", ErrInvalidTimeRange)
	}

	closures, oldKeys, err := canonicalKeyClosures(p.OldKeyClosures)
	if err != nil {
		return nil, err
	}
	if _, exists := oldKeys[p.NewKeyID]; exists {
		return nil, fmt.Errorf("%w: new_key_id is an old closed key", ErrInvalidProjectionValue)
	}
	evidence, err := canonicalTransferEvidence(p.SubjectKind, p.EvidenceCommitments)
	if err != nil {
		return nil, err
	}
	oldAuthorities, newAuthorities, err := canonicalTransferAuthorities(p.OldAuthorities, p.NewAuthorities)
	if err != nil {
		return nil, err
	}

	return ccse.Marshal(ownershipTransferAuthorizationMaxPayload, func(out *ccse.Encoder) {
		metadata.encode(out)
		out.String(p.TransferAuthorizationID)
		out.Uint32(p.SubjectKind)
		out.String(p.PreviousEntityID)
		out.String(p.NextEntityID)
		out.String(p.PreviousPrincipalIdentity)
		out.String(p.NextPrincipalIdentity)
		out.String(p.PreviousProviderID)
		out.String(p.NextProviderID)
		out.Uint64(p.ExpectedGeneration)
		out.Uint64(p.NextGeneration)
		out.FixedBytes(p.PreviousTerminalIdentityPayloadDigestSHA256[:], 32)
		out.FixedBytes(p.NextPendingIdentityPayloadDigestSHA256[:], 32)
		out.EncodedSet(closures)
		out.String(p.NewKeyID)
		out.EncodedSet(evidence)
		out.Int64(p.EffectiveAtUnixNano)
		out.Int64(p.ExpiresAtUnixNano)
		out.EncodedSet(oldAuthorities)
		out.EncodedSet(newAuthorities)
	})
}

func canonicalKeyClosures(values []KeyClosureSigningProjection) ([][]byte, map[string]struct{}, error) {
	if len(values) == 0 || len(values) > 256 {
		return nil, nil, fmt.Errorf("%w: old_key_closures count", ErrInvalidProjectionValue)
	}
	elements := make([][]byte, 0, len(values))
	keys := make(map[string]struct{}, len(values))
	for index, value := range values {
		if _, duplicate := keys[value.KeyID]; duplicate {
			return nil, nil, fmt.Errorf("%w: duplicate old key %q", ErrInvalidProjectionValue, value.KeyID)
		}
		keys[value.KeyID] = struct{}{}
		encoded, err := value.CanonicalBytes()
		if err != nil {
			return nil, nil, fmt.Errorf("old_key_closures[%d]: %w", index, err)
		}
		elements = append(elements, encoded)
	}
	canonical, err := canonicalMessageSetField("old_key_closures", elements, 256, 77824, true)
	return canonical, keys, err
}

func canonicalTransferEvidence(subjectKind uint32, values []TransferEvidenceCommitmentSigningProjection) ([][]byte, error) {
	if len(values) == 0 || len(values) > 64 {
		return nil, fmt.Errorf("%w: evidence_commitments count", ErrInvalidProjectionValue)
	}
	elements := make([][]byte, 0, len(values))
	kinds := make(map[uint32]struct{}, 7)
	for index, value := range values {
		kinds[value.EvidenceKind] = struct{}{}
		encoded, err := value.CanonicalBytes()
		if err != nil {
			return nil, fmt.Errorf("evidence_commitments[%d]: %w", index, err)
		}
		elements = append(elements, encoded)
	}
	required := []uint32{TransferEvidenceOldProviderAuthority, TransferEvidenceNewProviderAuthority}
	allowed := map[uint32]struct{}{
		TransferEvidenceOldProviderAuthority: {},
		TransferEvidenceNewProviderAuthority: {},
	}
	switch subjectKind {
	case 2:
		required = append(required, TransferEvidenceDescendantIdentityClosure, TransferEvidenceLeaseOfferWorkloadClosure)
		allowed[TransferEvidenceDescendantIdentityClosure] = struct{}{}
		allowed[TransferEvidenceLeaseOfferWorkloadClosure] = struct{}{}
	case 3:
		required = append(required, TransferEvidenceHostSanitationAttestation, TransferEvidenceNewAttestationReadiness)
		allowed[TransferEvidenceHostSanitationAttestation] = struct{}{}
		allowed[TransferEvidenceNewAttestationReadiness] = struct{}{}
	case 4:
		required = append(required, TransferEvidenceDeviceSanitationAttestation, TransferEvidenceNewAttestationReadiness)
		allowed[TransferEvidenceDeviceSanitationAttestation] = struct{}{}
		allowed[TransferEvidenceNewAttestationReadiness] = struct{}{}
	}
	for kind := range kinds {
		if _, ok := allowed[kind]; !ok {
			return nil, fmt.Errorf("%w: evidence kind %d is not applicable to subject", ErrInvalidProjectionValue, kind)
		}
	}
	for _, kind := range required {
		if _, present := kinds[kind]; !present {
			return nil, fmt.Errorf("%w: required evidence kind %d is absent", ErrInvalidProjectionValue, kind)
		}
	}
	return canonicalMessageSetField("evidence_commitments", elements, 64, 4608, true)
}

func canonicalTransferAuthorities(oldValues, newValues []TransferAuthoritySigningProjection) ([][]byte, [][]byte, error) {
	if len(oldValues) == 0 || len(oldValues) > 32 || len(newValues) == 0 || len(newValues) > 32 {
		return nil, nil, fmt.Errorf("%w: authority set count", ErrInvalidProjectionValue)
	}
	identities := make(map[string]struct{}, len(oldValues)+len(newValues))
	keys := make(map[string]struct{}, len(oldValues)+len(newValues))
	encode := func(name string, values []TransferAuthoritySigningProjection) ([][]byte, error) {
		elements := make([][]byte, 0, len(values))
		for index, value := range values {
			if _, duplicate := identities[value.Identity]; duplicate {
				return nil, fmt.Errorf("%w: duplicate authority identity %q", ErrInvalidProjectionValue, value.Identity)
			}
			if _, duplicate := keys[value.KeyID]; duplicate {
				return nil, fmt.Errorf("%w: duplicate authority key %q", ErrInvalidProjectionValue, value.KeyID)
			}
			identities[value.Identity] = struct{}{}
			keys[value.KeyID] = struct{}{}
			encoded, err := value.CanonicalBytes()
			if err != nil {
				return nil, fmt.Errorf("%s[%d]: %w", name, index, err)
			}
			elements = append(elements, encoded)
		}
		return canonicalMessageSetField(name, elements, 32, 50176, true)
	}
	oldEncoded, err := encode("old_authorities", oldValues)
	if err != nil {
		return nil, nil, err
	}
	newEncoded, err := encode("new_authorities", newValues)
	if err != nil {
		return nil, nil, err
	}
	return oldEncoded, newEncoded, nil
}

func (OwnershipTransferAuthorizationSigningProjection) MessageTypeID() uint32 {
	return schema.MessageTypeOwnershipTransferAuthorization
}

func (OwnershipTransferAuthorizationSigningProjection) SigningFieldNames() []string {
	return copyFieldNames(ownershipTransferAuthorizationSigningFields[:])
}
