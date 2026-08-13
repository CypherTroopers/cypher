// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

const (
	canonicalIAMSidecarMaxBytes        = 4096
	canonicalIAMProofChallengeMaxBytes = 16 << 10
	canonicalIAMMaterialMaxBytes       = 128 << 10
	canonicalIAMAcceptedMaxBytes       = 8 << 20
)

// CanonicalPrincipalIdentityIndexState is the complete reversible value of a
// principal-identity-index.v1 row. Version is deliberately absent: v1 does
// not commit the independently incremented canonical-state row version into
// this value.
type CanonicalPrincipalIdentityIndexState struct {
	PrincipalKind                uint32
	PrincipalIdentity            string
	Owner                        EntityRef
	IdentityStateVersion         uint64
	IdentityWriterEpoch          uint64
	IdentityState                uint32
	TransferEvidenceDigestSHA256 [sha256.Size]byte
}

// CanonicalRotationPredecessorIndexState is the complete reversible value of
// a rotation-predecessor-index.v1 row.
type CanonicalRotationPredecessorIndexState struct {
	PredecessorKeyID string
	SuccessorKeyID   string
}

// CanonicalSubjectKeySetState is the complete value actually retained by a
// subject-key-set.v1 row. The v1 encoding commits only the key-set digest, not
// its members, so this type must not be treated as a reconstructed key list.
type CanonicalSubjectKeySetState struct {
	SubjectKind        uint32
	PrincipalIdentity  string
	KeySetDigestSHA256 [sha256.Size]byte
}

// RehydratesMembers reports the intentional v1 limitation.
func (CanonicalSubjectKeySetState) RehydratesMembers() bool { return false }

// CanonicalIdentityState is the identity.v1 value that can be proven from one
// row. Several frozen identity schemas intentionally share an identical field
// layout, while the row omits MessageTypeID/principal kind. Candidate schemas
// are therefore retained without choosing one. SemanticSnapshot succeeds only
// when the payload shape itself identifies exactly one schema.
type CanonicalIdentityState struct {
	candidates       []IdentitySnapshot
	canonicalPayload []byte
}

func (value CanonicalIdentityState) CandidateMessageTypeIDs() []uint32 {
	result := make([]uint32, len(value.candidates))
	for index := range value.candidates {
		result[index] = value.candidates[index].MessageTypeID
	}
	return result
}
func (value CanonicalIdentityState) CanonicalPayload() []byte {
	return append([]byte(nil), value.canonicalPayload...)
}
func (value CanonicalIdentityState) RehydratesSemanticSnapshot() bool {
	return len(value.candidates) == 1
}
func (value CanonicalIdentityState) SemanticSnapshot() (IdentitySnapshot, error) {
	if len(value.candidates) != 1 {
		return IdentitySnapshot{}, ErrCanonicalStateUnrehydratable
	}
	return cloneIdentity(value.candidates[0]), nil
}

// CanonicalAcceptedOwnershipTransferState is the bounded, structurally decoded
// projection that accepted-ownership-transfer.v1 actually retains. It verifies
// framing, retained record type/payload hashes and the outer row commitments;
// it does not authenticate embedded signatures, fingerprints, frozen profile
// or activation evidence because v1 omitted their required preimages/keys. It
// is intentionally not AcceptedOwnershipTransferSnapshot and is safe only for
// storage diagnostics, never as LookupAcceptedOwnershipTransfer authority.
type CanonicalAcceptedOwnershipTransferState struct {
	projection                     foundationv1.OwnershipTransferAuthorizationSigningProjection
	canonicalPayload               []byte
	transferEvidenceDigestSHA256   [sha256.Size]byte
	profileDigestSHA256            [sha256.Size]byte
	activationSnapshotDigestSHA256 [sha256.Size]byte
	approvalCount                  int
	closureCount                   int
	evidenceCount                  int
	acceptedAtUnixNano             int64
	stateVersion                   uint64
	writerEpoch                    uint64
}

func (value CanonicalAcceptedOwnershipTransferState) Projection() foundationv1.OwnershipTransferAuthorizationSigningProjection {
	return cloneTransferProjection(value.projection)
}
func (value CanonicalAcceptedOwnershipTransferState) CanonicalPayload() []byte {
	return append([]byte(nil), value.canonicalPayload...)
}
func (value CanonicalAcceptedOwnershipTransferState) TransferEvidenceDigestSHA256() [sha256.Size]byte {
	return value.transferEvidenceDigestSHA256
}
func (value CanonicalAcceptedOwnershipTransferState) ProfileDigestSHA256() [sha256.Size]byte {
	return value.profileDigestSHA256
}
func (value CanonicalAcceptedOwnershipTransferState) ActivationSnapshotDigestSHA256() [sha256.Size]byte {
	return value.activationSnapshotDigestSHA256
}
func (value CanonicalAcceptedOwnershipTransferState) ApprovalCount() int { return value.approvalCount }
func (value CanonicalAcceptedOwnershipTransferState) ClosureCount() int  { return value.closureCount }
func (value CanonicalAcceptedOwnershipTransferState) EvidenceCount() int { return value.evidenceCount }
func (value CanonicalAcceptedOwnershipTransferState) AcceptedAtUnixNano() int64 {
	return value.acceptedAtUnixNano
}
func (value CanonicalAcceptedOwnershipTransferState) StateVersion() uint64 { return value.stateVersion }
func (value CanonicalAcceptedOwnershipTransferState) WriterEpoch() uint64  { return value.writerEpoch }

// RehydratesSemanticSnapshot is always false for v1. A future version must
// persist the frozen profile and every admission preimage before an adapter can
// implement LookupAcceptedOwnershipTransfer from canonical state alone.
func (CanonicalAcceptedOwnershipTransferState) RehydratesSemanticSnapshot() bool { return false }

// SemanticSnapshot fails closed instead of synthesizing fields that v1 did
// not retain.
func (CanonicalAcceptedOwnershipTransferState) SemanticSnapshot() (AcceptedOwnershipTransferSnapshot, error) {
	return AcceptedOwnershipTransferSnapshot{}, ErrCanonicalStateUnrehydratable
}

// DecodedCanonicalIAMState is a closed, detached result of validating one IAM
// canonical-state row. Exactly one typed getter succeeds.
type DecodedCanonicalIAMState struct {
	record      CanonicalStateRecord
	material    *KeyMaterialSnapshot
	identity    *CanonicalIdentityState
	lifecycle   *KeyLifecycleSnapshot
	lease       *WriterLeaseSnapshot
	challenge   *ProofChallengeSnapshot
	principal   *CanonicalPrincipalIdentityIndexState
	predecessor *CanonicalRotationPredecessorIndexState
	subjectKeys *CanonicalSubjectKeySetState
	accepted    *CanonicalAcceptedOwnershipTransferState
}

func (value DecodedCanonicalIAMState) Kind() string { return value.record.Kind }
func (value DecodedCanonicalIAMState) Record() CanonicalStateRecord {
	return cloneCanonicalStateRecord(value.record)
}
func (value DecodedCanonicalIAMState) KeyMaterial() (KeyMaterialSnapshot, bool) {
	if value.material == nil {
		return KeyMaterialSnapshot{}, false
	}
	return cloneKeyMaterial(*value.material), true
}
func (value DecodedCanonicalIAMState) Identity() (CanonicalIdentityState, bool) {
	if value.identity == nil {
		return CanonicalIdentityState{}, false
	}
	result := CanonicalIdentityState{canonicalPayload: append([]byte(nil), value.identity.canonicalPayload...)}
	result.candidates = make([]IdentitySnapshot, len(value.identity.candidates))
	for index := range value.identity.candidates {
		result.candidates[index] = cloneIdentity(value.identity.candidates[index])
	}
	return result, true
}
func (value DecodedCanonicalIAMState) KeyLifecycle() (KeyLifecycleSnapshot, bool) {
	if value.lifecycle == nil {
		return KeyLifecycleSnapshot{}, false
	}
	return cloneLifecycle(*value.lifecycle), true
}
func (value DecodedCanonicalIAMState) WriterLease() (WriterLeaseSnapshot, bool) {
	if value.lease == nil {
		return WriterLeaseSnapshot{}, false
	}
	return *value.lease, true
}
func (value DecodedCanonicalIAMState) ProofChallenge() (ProofChallengeSnapshot, bool) {
	if value.challenge == nil {
		return ProofChallengeSnapshot{}, false
	}
	result := *value.challenge
	result.PolicyDigestsSHA256 = cloneDigests(value.challenge.PolicyDigestsSHA256)
	return result, true
}
func (value DecodedCanonicalIAMState) PrincipalIdentityIndex() (CanonicalPrincipalIdentityIndexState, bool) {
	if value.principal == nil {
		return CanonicalPrincipalIdentityIndexState{}, false
	}
	return *value.principal, true
}
func (value DecodedCanonicalIAMState) RotationPredecessorIndex() (CanonicalRotationPredecessorIndexState, bool) {
	if value.predecessor == nil {
		return CanonicalRotationPredecessorIndexState{}, false
	}
	return *value.predecessor, true
}
func (value DecodedCanonicalIAMState) SubjectKeySet() (CanonicalSubjectKeySetState, bool) {
	if value.subjectKeys == nil {
		return CanonicalSubjectKeySetState{}, false
	}
	return *value.subjectKeys, true
}
func (value DecodedCanonicalIAMState) AcceptedOwnershipTransfer() (CanonicalAcceptedOwnershipTransferState, bool) {
	if value.accepted == nil {
		return CanonicalAcceptedOwnershipTransferState{}, false
	}
	result := *value.accepted
	result.projection = cloneTransferProjection(value.accepted.projection)
	result.canonicalPayload = append([]byte(nil), value.accepted.canonicalPayload...)
	return result, true
}

// DecodeCanonicalIAMStateRecord is the IAM-owned read boundary for a raw
// canonical-state row. It performs a bounded schema decode, canonical
// re-encode byte comparison, and exact row namespace/kind/content-type,
// ObjectID, codec digest, terminal, validity and derivable version checks.
// Unsupported IAM kinds fail closed.
func DecodeCanonicalIAMStateRecord(record CanonicalStateRecord) (DecodedCanonicalIAMState, error) {
	if !validCanonicalStateRecord(record) {
		return DecodedCanonicalIAMState{}, canonicalStateDecodeError(record.Kind, "invalid row envelope")
	}
	if err := validateCanonicalIAMStateKindSize(record.Kind, len(record.CanonicalState)); err != nil {
		return DecodedCanonicalIAMState{}, canonicalStateDecodeError(record.Kind, err.Error())
	}
	var result DecodedCanonicalIAMState
	var err error
	switch record.Kind {
	case CanonicalStateKindIAMKeyMaterial:
		var value KeyMaterialSnapshot
		value, err = decodeCanonicalKeyMaterial(record.CanonicalState)
		if err == nil {
			err = verifyDecodedCanonicalRow(record, record.Kind, value.KeyID, value.StateVersion, true,
				value.EnrollmentBindingDigest, true)
			result.material = &value
		}
	case CanonicalStateKindIAMIdentity:
		var candidates []IdentitySnapshot
		candidates, err = decodeCanonicalIdentityCandidates(record.CanonicalState)
		if err == nil {
			matching := make([]IdentitySnapshot, 0, len(candidates))
			for _, candidate := range candidates {
				if verifyDecodedCanonicalRow(record, record.Kind, candidate.Ref.ID, candidate.StateVersion, true,
					domainDigest(resolvedIdentitySnapshotDomain, candidate.CanonicalPayload),
					terminalIdentityState(candidate.State)) == nil {
					matching = append(matching, candidate)
				}
			}
			if len(matching) == 0 {
				err = fmt.Errorf("row metadata matches no decoded identity schema")
			} else {
				value := CanonicalIdentityState{candidates: matching,
					canonicalPayload: append([]byte(nil), record.CanonicalState...)}
				result.identity = &value
			}
		}
	case CanonicalStateKindIAMKeyLifecycle:
		var value KeyLifecycleSnapshot
		value, err = decodeCanonicalLifecycle(record.CanonicalState)
		if err == nil {
			err = verifyDecodedCanonicalRow(record, record.Kind, value.KeyID, value.StateVersion, true,
				domainDigest(resolvedLifecycleSnapshotDomain, value.CanonicalPayload), terminalLifecycleState(value.State))
			result.lifecycle = &value
		}
	case CanonicalStateKindIAMWriterLease:
		var value WriterLeaseSnapshot
		value, err = decodeCanonicalWriterLease(record.CanonicalState)
		if err == nil {
			err = verifyDecodedCanonicalRow(record, record.Kind, canonicalEntityObjectID(value.Entity),
				value.WriterEpoch, true, domainDigest(iamWriterLeaseStateDomain, record.CanonicalState), false)
			result.lease = &value
		}
	case CanonicalStateKindIAMProofChallenge:
		var value ProofChallengeSnapshot
		value, err = decodeCanonicalProofChallenge(record.CanonicalState)
		if err == nil {
			version := uint64(1)
			if value.Consumed {
				version = 2
			}
			err = verifyDecodedCanonicalRow(record, record.Kind, hex.EncodeToString(value.Challenge[:]),
				version, true, domainDigest(iamProofChallengeStateDomain, record.CanonicalState), value.Consumed)
			result.challenge = &value
		}
	case CanonicalStateKindIAMPrincipalIdentityIndex:
		var value CanonicalPrincipalIdentityIndexState
		value, err = decodeCanonicalPrincipalIndex(record.CanonicalState)
		if err == nil {
			err = verifyDecodedCanonicalRow(record, record.Kind,
				principalIndexObjectID(value.PrincipalKind, value.PrincipalIdentity), 0, false,
				domainDigest(iamPrincipalIndexStateDomain, record.CanonicalState), false)
			result.principal = &value
		}
	case CanonicalStateKindIAMRotationPredecessorIndex:
		var value CanonicalRotationPredecessorIndexState
		value, err = decodeCanonicalPredecessorIndex(record.CanonicalState)
		if err == nil {
			err = verifyDecodedCanonicalRow(record, record.Kind, value.PredecessorKeyID, 1, true,
				domainDigest(iamPredecessorIndexStateDomain, record.CanonicalState), true)
			result.predecessor = &value
		}
	case CanonicalStateKindIAMSubjectKeySet:
		var value CanonicalSubjectKeySetState
		value, err = decodeCanonicalSubjectKeySet(record.CanonicalState)
		if err == nil {
			err = verifyDecodedCanonicalRow(record, record.Kind,
				principalIndexObjectID(value.SubjectKind, value.PrincipalIdentity), 0, false,
				value.KeySetDigestSHA256, false)
			result.subjectKeys = &value
		}
	case CanonicalStateKindIAMAcceptedOwnershipTransfer:
		var value CanonicalAcceptedOwnershipTransferState
		value, err = decodeCanonicalAcceptedTransfer(record.CanonicalState)
		if err == nil {
			err = verifyDecodedCanonicalRow(record, record.Kind, value.projection.TransferAuthorizationID,
				value.stateVersion, true, domainDigest(acceptedTransferDigestDomain, record.CanonicalState), true)
			result.accepted = &value
		}
	case CanonicalStateKindIAMTransferProfileActivation:
		err = fmt.Errorf("v1 profile-activation rows have no reversible persisted state codec")
	default:
		err = fmt.Errorf("unsupported IAM canonical state kind")
	}
	if err != nil {
		return DecodedCanonicalIAMState{}, canonicalStateDecodeError(record.Kind, err.Error())
	}
	result.record = cloneCanonicalStateRecord(record)
	return result, nil
}

func validateCanonicalIAMStateKindSize(kind string, size int) error {
	maximum := 0
	switch kind {
	case CanonicalStateKindIAMKeyMaterial:
		maximum = canonicalIAMMaterialMaxBytes
	case CanonicalStateKindIAMIdentity, CanonicalStateKindIAMKeyLifecycle:
		maximum = 32768
	case CanonicalStateKindIAMAcceptedOwnershipTransfer:
		maximum = canonicalIAMAcceptedMaxBytes
	case CanonicalStateKindIAMProofChallenge:
		maximum = canonicalIAMProofChallengeMaxBytes
	case CanonicalStateKindIAMPrincipalIdentityIndex,
		CanonicalStateKindIAMRotationPredecessorIndex,
		CanonicalStateKindIAMSubjectKeySet,
		CanonicalStateKindIAMWriterLease:
		maximum = canonicalIAMSidecarMaxBytes
	case CanonicalStateKindIAMTransferProfileActivation:
		return fmt.Errorf("v1 profile-activation rows have no reversible persisted state codec")
	default:
		return fmt.Errorf("unsupported IAM canonical state kind")
	}
	if size <= 0 || size > maximum {
		return fmt.Errorf("canonical state length %d exceeds kind limit %d", size, maximum)
	}
	return nil
}

func canonicalStateDecodeError(kind, detail string) error {
	if kind == "" {
		kind = "<empty>"
	}
	return fmt.Errorf("%w: %s: %s", ErrCanonicalStateInvalid, kind, detail)
}

func verifyDecodedCanonicalRow(record CanonicalStateRecord, kind, objectID string,
	version uint64, exactVersion bool, digest [sha256.Size]byte, terminal bool) error {
	contentType, ok := canonicalStateSpec(kind)
	if !ok || record.Namespace != CanonicalStateNamespaceIAM || record.Kind != kind ||
		record.ContentType != contentType || record.ObjectID != objectID ||
		(exactVersion && record.Version != version) || (!exactVersion && record.Version == 0) ||
		record.StateDigestSHA256 != digest || record.Terminal != terminal ||
		record.HasValidityWindow || record.ValidFromUnixNano != 0 || record.ValidUntilUnixNano != 0 {
		return fmt.Errorf("row metadata does not match decoded state")
	}
	return nil
}

func decodeCanonicalKeyMaterial(encoded []byte) (KeyMaterialSnapshot, error) {
	var value KeyMaterialSnapshot
	err := ccse.Unmarshal(encoded, canonicalIAMMaterialMaxBytes, func(in *ccse.Decoder) error {
		var err error
		if value.KeyID, err = in.String(canonicalIAMMaterialMaxBytes); err != nil {
			return err
		}
		algorithm, err := in.Uint32()
		if err != nil {
			return err
		}
		value.Algorithm = ccse.SignatureAlgorithmID(algorithm)
		if value.CanonicalPublicKey, err = in.Bytes(canonicalIAMMaterialMaxBytes); err != nil {
			return err
		}
		if value.SubjectIdentity, err = in.String(canonicalIAMMaterialMaxBytes); err != nil {
			return err
		}
		if value.SubjectKind, err = in.Uint32(); err != nil {
			return err
		}
		if value.TargetIdentity, err = decodeCanonicalEntity(in, canonicalIAMMaterialMaxBytes); err != nil {
			return err
		}
		if value.TransferEvidenceDigest, err = decodeCanonicalDigest(in); err != nil {
			return err
		}
		if value.EnrollmentDomain.EnrollmentDomainID, err = in.String(canonicalIAMMaterialMaxBytes); err != nil {
			return err
		}
		if value.EnrollmentDomain.Environment, err = in.String(canonicalIAMMaterialMaxBytes); err != nil {
			return err
		}
		if value.EnrollmentDomain.GenesisHash, err = decodeCanonicalDigest(in); err != nil {
			return err
		}
		if value.ProofChallenge, err = decodeCanonicalDigest(in); err != nil {
			return err
		}
		if value.ProofExpiresAtUnixNano, err = in.Int64(); err != nil {
			return err
		}
		if value.ProofSignature, err = in.Bytes(canonicalIAMMaterialMaxBytes); err != nil {
			return err
		}
		if value.ProofDigest, err = decodeCanonicalDigest(in); err != nil {
			return err
		}
		if value.ChallengeEvidenceDigest, err = decodeCanonicalDigest(in); err != nil {
			return err
		}
		if value.EnrollmentAuthorityIdentity, err = in.String(canonicalIAMMaterialMaxBytes); err != nil {
			return err
		}
		if err = in.ValidatedSet(64, 64, func(_ int, child *ccse.Decoder) error {
			digest, digestErr := decodeCanonicalDigest(child)
			if digestErr == nil {
				value.EnrollmentPolicyDigestsSHA256 = append(value.EnrollmentPolicyDigestsSHA256, digest)
			}
			return digestErr
		}); err != nil {
			return err
		}
		if value.EnrollmentBindingDigest, err = decodeCanonicalDigest(in); err != nil {
			return err
		}
		if value.WriterIdentity, err = in.String(canonicalIAMMaterialMaxBytes); err != nil {
			return err
		}
		if value.HomeRegion, err = in.String(canonicalIAMMaterialMaxBytes); err != nil {
			return err
		}
		if value.WriterEpoch, err = in.Uint64(); err != nil {
			return err
		}
		if value.StateVersion, err = in.Uint64(); err != nil {
			return err
		}
		value.IdempotencyKey, err = decodeCanonicalFixed16(in)
		return err
	})
	if err != nil {
		return KeyMaterialSnapshot{}, err
	}
	normalized, err := validateMaterialSnapshot(value)
	if err != nil {
		return KeyMaterialSnapshot{}, err
	}
	reencoded, err := canonicalMaterialSnapshot(normalized)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return KeyMaterialSnapshot{}, fmt.Errorf("noncanonical key-material encoding")
	}
	return normalized, nil
}

func decodeCanonicalIdentityCandidates(encoded []byte) ([]IdentitySnapshot, error) {
	validator, err := foundationCanonicalValidator()
	if err != nil {
		return nil, err
	}
	messageTypes := [...]uint32{
		schema.MessageTypeProviderIdentity,
		schema.MessageTypeAgentIdentity,
		schema.MessageTypeHostIdentity,
		schema.MessageTypeDeviceIdentity,
		schema.MessageTypeMinerIdentity,
		schema.MessageTypeRunnerIdentity,
		schema.MessageTypeBuyerIdentity,
		schema.MessageTypeServiceIdentity,
	}
	result := make([]IdentitySnapshot, 0, len(messageTypes))
	for _, messageTypeID := range messageTypes {
		projection, decodeErr := validator.Decode(messageTypeID, ccse.Version{Major: 1}, encoded)
		if decodeErr != nil {
			continue
		}
		snapshot, normalizeErr := NormalizeIdentity(projection)
		if normalizeErr != nil || !bytes.Equal(snapshot.CanonicalPayload, encoded) {
			continue
		}
		snapshot, normalizeErr = normalizeViewIdentity(snapshot)
		if normalizeErr != nil {
			continue
		}
		result = append(result, snapshot)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("identity payload matched no v1 schema")
	}
	return result, nil
}

func decodeCanonicalIdentityForRef(encoded []byte, expected EntityRef) (IdentitySnapshot, error) {
	candidates, err := decodeCanonicalIdentityCandidates(encoded)
	if err != nil {
		return IdentitySnapshot{}, err
	}
	var result IdentitySnapshot
	matches := 0
	for _, candidate := range candidates {
		if candidate.Ref == expected {
			result = candidate
			matches++
		}
	}
	if matches != 1 {
		return IdentitySnapshot{}, fmt.Errorf("identity payload matched %d schemas for expected entity", matches)
	}
	return result, nil
}

func decodeCanonicalLifecycle(encoded []byte) (KeyLifecycleSnapshot, error) {
	validator, err := foundationCanonicalValidator()
	if err != nil {
		return KeyLifecycleSnapshot{}, err
	}
	projection, err := validator.Decode(schema.MessageTypeKeyLifecycle, ccse.Version{Major: 1}, encoded)
	if err != nil {
		return KeyLifecycleSnapshot{}, err
	}
	result, err := NormalizeKeyLifecycle(projection)
	if err != nil || !bytes.Equal(result.CanonicalPayload, encoded) {
		return KeyLifecycleSnapshot{}, fmt.Errorf("noncanonical lifecycle encoding")
	}
	return normalizeViewLifecycle(result)
}

func decodeCanonicalWriterLease(encoded []byte) (WriterLeaseSnapshot, error) {
	var value WriterLeaseSnapshot
	err := ccse.Unmarshal(encoded, canonicalIAMSidecarMaxBytes, func(in *ccse.Decoder) error {
		var err error
		if value.Entity, err = decodeCanonicalEntity(in, canonicalIAMSidecarMaxBytes); err != nil {
			return err
		}
		if value.WriterIdentity, err = in.String(canonicalIAMSidecarMaxBytes); err != nil {
			return err
		}
		if value.HomeRegion, err = in.String(canonicalIAMSidecarMaxBytes); err != nil {
			return err
		}
		if value.WriterEpoch, err = in.Uint64(); err != nil {
			return err
		}
		if value.ValidFromUnixNano, err = in.Int64(); err != nil {
			return err
		}
		if value.ValidUntilUnixNano, err = in.Int64(); err != nil {
			return err
		}
		value.EvidenceDigest, err = decodeCanonicalDigest(in)
		return err
	})
	if err != nil {
		return WriterLeaseSnapshot{}, err
	}
	reencoded, err := canonicalWriterLeaseState(value)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return WriterLeaseSnapshot{}, fmt.Errorf("noncanonical writer-lease encoding")
	}
	return value, nil
}

func decodeCanonicalProofChallenge(encoded []byte) (ProofChallengeSnapshot, error) {
	var value ProofChallengeSnapshot
	err := ccse.Unmarshal(encoded, canonicalIAMProofChallengeMaxBytes, func(in *ccse.Decoder) error {
		var err error
		if value.Challenge, err = decodeCanonicalDigest(in); err != nil {
			return err
		}
		if value.SubjectIdentity, err = in.String(canonicalIAMProofChallengeMaxBytes); err != nil {
			return err
		}
		if value.SubjectKind, err = in.Uint32(); err != nil {
			return err
		}
		if value.TargetIdentity, err = decodeCanonicalEntity(in, canonicalIAMProofChallengeMaxBytes); err != nil {
			return err
		}
		if value.TransferEvidenceDigest, err = decodeCanonicalDigest(in); err != nil {
			return err
		}
		if value.Domain.EnrollmentDomainID, err = in.String(canonicalIAMProofChallengeMaxBytes); err != nil {
			return err
		}
		if value.Domain.Environment, err = in.String(canonicalIAMProofChallengeMaxBytes); err != nil {
			return err
		}
		if value.Domain.GenesisHash, err = decodeCanonicalDigest(in); err != nil {
			return err
		}
		if value.ExpiresAtUnixNano, err = in.Int64(); err != nil {
			return err
		}
		if value.Consumed, err = in.Bool(); err != nil {
			return err
		}
		if value.IssuerIdentity, err = in.String(canonicalIAMProofChallengeMaxBytes); err != nil {
			return err
		}
		count, err := in.Uint32()
		if err != nil {
			return err
		}
		// The outer 16 KiB codec is the primary bound. This explicit ceiling
		// prevents count-controlled work before any fixed-width reads.
		if count > 512 {
			return fmt.Errorf("proof policy count exceeds codec bound")
		}
		value.PolicyDigestsSHA256 = make([][sha256.Size]byte, 0, count)
		for index := uint32(0); index < count; index++ {
			digest, digestErr := decodeCanonicalDigest(in)
			if digestErr != nil {
				return digestErr
			}
			value.PolicyDigestsSHA256 = append(value.PolicyDigestsSHA256, digest)
		}
		value.EvidenceDigest, err = decodeCanonicalDigest(in)
		return err
	})
	if err != nil {
		return ProofChallengeSnapshot{}, err
	}
	if value.SubjectKind < 1 || value.SubjectKind > 8 ||
		value.TargetIdentity != (EntityRef{Kind: EntityIdentity, PrincipalKind: value.SubjectKind,
			ID: value.TargetIdentity.ID}) || value.TargetIdentity.ID == "" ||
		value.Domain.EnrollmentDomainID == "" || value.Domain.Environment == "" ||
		value.Domain.GenesisHash == ([sha256.Size]byte{}) ||
		len(value.PolicyDigestsSHA256) == 0 || len(value.PolicyDigestsSHA256) > 64 {
		return ProofChallengeSnapshot{}, fmt.Errorf("invalid proof-challenge semantics")
	}
	reencoded, err := canonicalProofChallengeState(value)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return ProofChallengeSnapshot{}, fmt.Errorf("noncanonical proof-challenge encoding")
	}
	return value, nil
}

func decodeCanonicalPrincipalIndex(encoded []byte) (CanonicalPrincipalIdentityIndexState, error) {
	var value CanonicalPrincipalIdentityIndexState
	err := ccse.Unmarshal(encoded, canonicalIAMSidecarMaxBytes, func(in *ccse.Decoder) error {
		var err error
		if value.PrincipalKind, err = in.Uint32(); err != nil {
			return err
		}
		if value.PrincipalIdentity, err = in.String(canonicalIAMSidecarMaxBytes); err != nil {
			return err
		}
		if value.Owner, err = decodeCanonicalEntity(in, canonicalIAMSidecarMaxBytes); err != nil {
			return err
		}
		if value.IdentityStateVersion, err = in.Uint64(); err != nil {
			return err
		}
		if value.IdentityWriterEpoch, err = in.Uint64(); err != nil {
			return err
		}
		if value.IdentityState, err = in.Uint32(); err != nil {
			return err
		}
		value.TransferEvidenceDigestSHA256, err = decodeCanonicalDigest(in)
		return err
	})
	if err != nil {
		return CanonicalPrincipalIdentityIndexState{}, err
	}
	reencoded, err := canonicalPrincipalIndexState(value.PrincipalKind, value.PrincipalIdentity,
		value.Owner, value.IdentityStateVersion, value.IdentityWriterEpoch, value.IdentityState,
		value.TransferEvidenceDigestSHA256)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return CanonicalPrincipalIdentityIndexState{}, fmt.Errorf("noncanonical principal-index encoding")
	}
	return value, nil
}

func decodeCanonicalPredecessorIndex(encoded []byte) (CanonicalRotationPredecessorIndexState, error) {
	var value CanonicalRotationPredecessorIndexState
	err := ccse.Unmarshal(encoded, canonicalIAMSidecarMaxBytes, func(in *ccse.Decoder) error {
		var err error
		if value.PredecessorKeyID, err = in.String(canonicalIAMSidecarMaxBytes); err != nil {
			return err
		}
		value.SuccessorKeyID, err = in.String(canonicalIAMSidecarMaxBytes)
		return err
	})
	if err != nil {
		return CanonicalRotationPredecessorIndexState{}, err
	}
	reencoded, err := canonicalPredecessorIndexState(value.PredecessorKeyID, value.SuccessorKeyID)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return CanonicalRotationPredecessorIndexState{}, fmt.Errorf("noncanonical predecessor-index encoding")
	}
	return value, nil
}

func decodeCanonicalSubjectKeySet(encoded []byte) (CanonicalSubjectKeySetState, error) {
	var value CanonicalSubjectKeySetState
	err := ccse.Unmarshal(encoded, canonicalIAMSidecarMaxBytes, func(in *ccse.Decoder) error {
		var err error
		if value.SubjectKind, err = in.Uint32(); err != nil {
			return err
		}
		if value.PrincipalIdentity, err = in.String(canonicalIAMSidecarMaxBytes); err != nil {
			return err
		}
		value.KeySetDigestSHA256, err = decodeCanonicalDigest(in)
		return err
	})
	if err != nil {
		return CanonicalSubjectKeySetState{}, err
	}
	reencoded, err := canonicalSubjectKeySetState(value.SubjectKind, value.PrincipalIdentity,
		value.KeySetDigestSHA256)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return CanonicalSubjectKeySetState{}, fmt.Errorf("noncanonical subject-key-set encoding")
	}
	return value, nil
}

func decodeCanonicalAcceptedTransfer(encoded []byte) (CanonicalAcceptedOwnershipTransferState, error) {
	var value CanonicalAcceptedOwnershipTransferState
	var approvals, fixed []byte
	err := ccse.Unmarshal(encoded, canonicalIAMAcceptedMaxBytes, func(in *ccse.Decoder) error {
		var err error
		if value.canonicalPayload, err = in.Bytes(196608); err != nil {
			return err
		}
		if value.transferEvidenceDigestSHA256, err = decodeCanonicalDigest(in); err != nil {
			return err
		}
		if value.profileDigestSHA256, err = decodeCanonicalDigest(in); err != nil {
			return err
		}
		if value.activationSnapshotDigestSHA256, err = decodeCanonicalDigest(in); err != nil {
			return err
		}
		if approvals, err = in.Bytes(4 << 20); err != nil {
			return err
		}
		if fixed, err = in.Bytes(4 << 20); err != nil {
			return err
		}
		if value.acceptedAtUnixNano, err = in.Int64(); err != nil {
			return err
		}
		if value.stateVersion, err = in.Uint64(); err != nil {
			return err
		}
		value.writerEpoch, err = in.Uint64()
		return err
	})
	if err != nil {
		return CanonicalAcceptedOwnershipTransferState{}, err
	}
	projection, canonical, transferDigest, err := normalizeOwnershipTransferPayload(value.canonicalPayload)
	if err != nil || !bytes.Equal(canonical, value.canonicalPayload) ||
		transferDigest != value.transferEvidenceDigestSHA256 ||
		value.profileDigestSHA256 == ([sha256.Size]byte{}) ||
		value.activationSnapshotDigestSHA256 == ([sha256.Size]byte{}) ||
		value.acceptedAtUnixNano < projection.Metadata.CreatedAtUnixNano ||
		value.acceptedAtUnixNano >= projection.ExpiresAtUnixNano ||
		value.stateVersion == 0 || value.writerEpoch == 0 {
		return CanonicalAcceptedOwnershipTransferState{}, fmt.Errorf("invalid accepted-transfer commitments")
	}
	value.projection = projection
	approvalMetadata, err := validateOpaqueTransferAdmissions(approvals, projection)
	if err != nil {
		return CanonicalAcceptedOwnershipTransferState{}, err
	}
	fixedMetadata, err := validateOpaqueTransferFixedEvidence(fixed, projection)
	if err != nil {
		return CanonicalAcceptedOwnershipTransferState{}, err
	}
	value.approvalCount = approvalMetadata.count
	value.closureCount = fixedMetadata.closureCount
	value.evidenceCount = fixedMetadata.evidenceCount
	reencoded, err := ccse.Marshal(canonicalIAMAcceptedMaxBytes, func(out *ccse.Encoder) {
		out.Bytes(value.canonicalPayload)
		out.FixedBytes(value.transferEvidenceDigestSHA256[:], sha256.Size)
		out.FixedBytes(value.profileDigestSHA256[:], sha256.Size)
		out.FixedBytes(value.activationSnapshotDigestSHA256[:], sha256.Size)
		out.Bytes(approvals)
		out.Bytes(fixed)
		out.Int64(value.acceptedAtUnixNano)
		out.Uint64(value.stateVersion)
		out.Uint64(value.writerEpoch)
	})
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return CanonicalAcceptedOwnershipTransferState{}, fmt.Errorf("noncanonical accepted-transfer encoding")
	}
	return value, nil
}

type opaqueTransferAdmissions struct{ count int }

func validateOpaqueTransferAdmissions(encoded []byte,
	projection foundationv1.OwnershipTransferAuthorizationSigningProjection) (opaqueTransferAdmissions, error) {
	type authorityKey struct {
		identity string
		keyID    string
	}
	declared := make(map[authorityKey]bool, len(projection.OldAuthorities)+len(projection.NewAuthorities))
	for _, authority := range projection.OldAuthorities {
		declared[authorityKey{identity: authority.Identity, keyID: authority.KeyID}] = true
	}
	for _, authority := range projection.NewAuthorities {
		declared[authorityKey{identity: authority.Identity, keyID: authority.KeyID}] = false
	}
	if len(declared) != len(projection.OldAuthorities)+len(projection.NewAuthorities) {
		return opaqueTransferAdmissions{}, fmt.Errorf("transfer payload contains duplicate authorities")
	}
	count := 0
	identities := make(map[string]struct{})
	transferPayload, err := projection.CanonicalBytes()
	if err != nil {
		return opaqueTransferAdmissions{}, fmt.Errorf("invalid transfer payload")
	}
	transferPayloadDigest := sha256.Sum256(transferPayload)
	err = ccse.Unmarshal(encoded, 4<<20, func(in *ccse.Decoder) error {
		return in.ValidatedSet(maxTransferAuthorities, 2<<20, func(_ int, child *ccse.Decoder) error {
			identity, err := child.String(1024)
			if err != nil {
				return err
			}
			keyID, err := child.String(256)
			if err != nil {
				return err
			}
			oldSide, err := child.Bool()
			if err != nil {
				return err
			}
			fingerprint, err := decodeCanonicalDigest(child)
			if err != nil {
				return err
			}
			retained, err := child.Bytes(2 << 20)
			if err != nil {
				return err
			}
			if identity == "" || keyID == "" || fingerprint == ([sha256.Size]byte{}) {
				return fmt.Errorf("empty transfer admission field")
			}
			expectedSide, found := declared[authorityKey{identity: identity, keyID: keyID}]
			if !found || expectedSide != oldSide {
				return fmt.Errorf("admission is not declared by transfer payload")
			}
			if _, duplicate := identities[identity]; duplicate {
				return fmt.Errorf("duplicate transfer admission identity")
			}
			identities[identity] = struct{}{}
			record, decodeErr := decodeOpaqueRetainedRecord(retained)
			if decodeErr != nil {
				return decodeErr
			}
			if record.messageTypeID != schema.MessageTypeOwnershipTransferAuthorization ||
				record.schemaVersion != (ccse.Version{Major: 1}) ||
				record.payloadDigest != transferPayloadDigest {
				return fmt.Errorf("invalid transfer admission record type or payload")
			}
			count++
			return nil
		})
	})
	if err != nil || count == 0 || count != len(declared) {
		return opaqueTransferAdmissions{}, fmt.Errorf("invalid transfer admissions: %v", err)
	}
	return opaqueTransferAdmissions{count: count}, nil
}

type opaqueTransferFixedEvidence struct {
	closureCount  int
	evidenceCount int
}

func validateOpaqueTransferFixedEvidence(encoded []byte,
	projection foundationv1.OwnershipTransferAuthorizationSigningProjection) (opaqueTransferFixedEvidence, error) {
	var previousRaw, nextRaw, identityCASRaw, closuresRaw, lifecycleRaw []byte
	var evidenceRaw, admissionsRaw, closureCASRaw, evidenceCASRaw []byte
	err := ccse.Unmarshal(encoded, 4<<20, func(in *ccse.Decoder) error {
		values := []*[]byte{&previousRaw, &nextRaw, &identityCASRaw, &closuresRaw, &lifecycleRaw,
			&evidenceRaw, &admissionsRaw, &closureCASRaw, &evidenceCASRaw}
		for _, target := range values {
			value, readErr := in.Bytes(4 << 20)
			if readErr != nil {
				return readErr
			}
			*target = value
		}
		return nil
	})
	if err != nil {
		return opaqueTransferFixedEvidence{}, err
	}
	previousRef := EntityRef{Kind: EntityIdentity, PrincipalKind: projection.SubjectKind, ID: projection.PreviousEntityID}
	previous, err := decodeCanonicalIdentityForRef(previousRaw, previousRef)
	if err != nil || sha256.Sum256(previousRaw) != projection.PreviousTerminalIdentityPayloadDigestSHA256 ||
		previous.Ref != previousRef ||
		previous.PrincipalIdentity != projection.PreviousPrincipalIdentity || previous.State != 5 ||
		previous.Generation != projection.ExpectedGeneration || previous.Bindings.ProviderID != projection.PreviousProviderID {
		return opaqueTransferFixedEvidence{}, fmt.Errorf("invalid previous transfer identity")
	}
	nextRef := EntityRef{Kind: EntityIdentity, PrincipalKind: projection.SubjectKind, ID: projection.NextEntityID}
	next, err := decodeCanonicalIdentityForRef(nextRaw, nextRef)
	if err != nil || sha256.Sum256(nextRaw) != projection.NextPendingIdentityPayloadDigestSHA256 ||
		next.Ref != nextRef ||
		next.PrincipalIdentity != projection.NextPrincipalIdentity || next.State != 1 || next.StateVersion != 1 ||
		next.Generation != projection.NextGeneration || next.Bindings.ProviderID != projection.NextProviderID ||
		next.KeyID != projection.NewKeyID || next.ValidFromUnixNano > projection.EffectiveAtUnixNano ||
		projection.EffectiveAtUnixNano >= next.ValidUntilUnixNano {
		return opaqueTransferFixedEvidence{}, fmt.Errorf("invalid next transfer identity")
	}
	identityCAS, err := decodeCanonicalSnapshotPreconditions(identityCASRaw, 1)
	if err != nil || len(identityCAS) != 1 || identityCAS[0].Entity != previous.Ref ||
		identityCAS[0].ExpectedStateVersion == 0 || identityCAS[0].ExpectedStateVersion+1 != previous.StateVersion ||
		(identityCAS[0].ExpectedState != 2 && identityCAS[0].ExpectedState != 3) ||
		identityCAS[0].ExpectedSnapshotDigest == ([sha256.Size]byte{}) {
		return opaqueTransferFixedEvidence{}, fmt.Errorf("invalid previous identity CAS")
	}
	closureRecords, err := decodeOpaqueRetainedRecordSet(closuresRaw, 256, true)
	if err != nil {
		return opaqueTransferFixedEvidence{}, err
	}
	closures, err := decodeCanonicalLifecycleSet(lifecycleRaw, 256)
	if err != nil || len(closures) != len(closureRecords) || len(closures) != len(projection.OldKeyClosures) {
		return opaqueTransferFixedEvidence{}, fmt.Errorf("invalid transfer closure set")
	}
	closureCAS, err := decodeCanonicalSnapshotPreconditions(closureCASRaw, maxTransferClosurePreconditions)
	if err != nil {
		return opaqueTransferFixedEvidence{}, err
	}
	closureCommitments := make(map[string][sha256.Size]byte, len(projection.OldKeyClosures))
	for _, commitment := range projection.OldKeyClosures {
		closureCommitments[commitment.KeyID] = commitment.TerminalKeyLifecyclePayloadDigestSHA256
	}
	if len(closureCommitments) != len(projection.OldKeyClosures) {
		return opaqueTransferFixedEvidence{}, fmt.Errorf("duplicate or unmatched closure commitments")
	}
	closureRecordSet := make(map[[sha256.Size]byte]struct{}, len(closureRecords))
	for _, record := range closureRecords {
		if record.messageTypeID != schema.MessageTypeKeyLifecycle ||
			record.schemaVersion != (ccse.Version{Major: 1}) {
			return opaqueTransferFixedEvidence{}, fmt.Errorf("invalid closure record type")
		}
		closureRecordSet[record.payloadDigest] = struct{}{}
	}
	for _, lifecycle := range closures {
		digest, found := closureCommitments[lifecycle.KeyID]
		if _, recordFound := closureRecordSet[digest]; !found || !recordFound ||
			sha256.Sum256(lifecycle.CanonicalPayload) != digest ||
			!terminalLifecycleState(lifecycle.State) || lifecycle.SubjectKind != projection.SubjectKind ||
			lifecycle.SubjectIdentity != projection.PreviousPrincipalIdentity ||
			!hasMatchingClosureCAS(closureCAS, lifecycle) {
			return opaqueTransferFixedEvidence{}, fmt.Errorf("closure does not match transfer payload")
		}
	}
	evidenceRecords, err := decodeOpaqueRetainedRecordSet(evidenceRaw, 64, true)
	if err != nil {
		return opaqueTransferFixedEvidence{}, err
	}
	for _, record := range evidenceRecords {
		if record.messageTypeID != schema.MessageTypeEvidenceRecord ||
			record.schemaVersion != (ccse.Version{Major: 1}) {
			return opaqueTransferFixedEvidence{}, fmt.Errorf("invalid evidence record type")
		}
	}
	evidenceAdmissions, err := decodeOpaqueEvidenceAdmissions(admissionsRaw)
	if err != nil || len(evidenceAdmissions) != len(evidenceRecords) ||
		len(evidenceAdmissions) != len(projection.EvidenceCommitments) {
		return opaqueTransferFixedEvidence{}, fmt.Errorf("invalid transfer evidence set")
	}
	commitments := make(map[[sha256.Size]byte]uint32, len(projection.EvidenceCommitments))
	for _, commitment := range projection.EvidenceCommitments {
		commitments[commitment.CCSERecordDigestSHA256] = commitment.EvidenceKind
	}
	if len(commitments) != len(projection.EvidenceCommitments) {
		return opaqueTransferFixedEvidence{}, fmt.Errorf("duplicate evidence commitments")
	}
	records := make(map[[sha256.Size]byte]struct{}, len(evidenceRecords))
	for _, record := range evidenceRecords {
		records[record.recordDigest] = struct{}{}
	}
	for digest, kind := range evidenceAdmissions {
		if expectedKind, found := commitments[digest]; !found || expectedKind != kind {
			return opaqueTransferFixedEvidence{}, fmt.Errorf("evidence admission commitment mismatch")
		}
		if _, found := records[digest]; !found {
			return opaqueTransferFixedEvidence{}, fmt.Errorf("evidence admission lacks retained record")
		}
	}
	if _, err = decodeCanonicalSnapshotPreconditions(evidenceCASRaw, maxTransferEvidencePreconditions); err != nil {
		return opaqueTransferFixedEvidence{}, err
	}
	return opaqueTransferFixedEvidence{closureCount: len(closures), evidenceCount: len(evidenceRecords)}, nil
}

func hasMatchingClosureCAS(values []SnapshotPrecondition, lifecycle KeyLifecycleSnapshot) bool {
	for _, value := range values {
		if value.Entity == (EntityRef{Kind: EntityKeyLifecycle, PrincipalKind: lifecycle.SubjectKind, ID: lifecycle.KeyID}) &&
			value.ExpectedStateVersion > 0 && value.ExpectedStateVersion+1 == lifecycle.StateVersion &&
			value.ExpectedState != 4 && value.ExpectedState != 5 {
			return true
		}
	}
	return false
}

func decodeCanonicalLifecycleSet(encoded []byte, max int) ([]KeyLifecycleSnapshot, error) {
	values := make([]KeyLifecycleSnapshot, 0)
	canonical := make([][]byte, 0)
	err := ccse.Unmarshal(encoded, 4<<20, func(in *ccse.Decoder) error {
		return in.ValidatedSet(max, 32768, func(_ int, child *ccse.Decoder) error {
			projection, decodeErr := decodeCanonicalLifecycleProjection(child)
			if decodeErr != nil {
				return decodeErr
			}
			raw, encodeErr := projection.CanonicalBytes()
			if encodeErr != nil {
				return encodeErr
			}
			snapshot, normalizeErr := NormalizeKeyLifecycle(projection)
			if normalizeErr != nil {
				return normalizeErr
			}
			canonical = append(canonical, raw)
			values = append(values, snapshot)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	reencoded, err := ccse.Marshal(4<<20, func(out *ccse.Encoder) { out.EncodedSet(canonical) })
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return nil, fmt.Errorf("noncanonical lifecycle set")
	}
	return values, nil
}

// decodeCanonicalLifecycleProjection follows the public Foundation v1 signing
// order. The authoritative CanonicalBytes method below is still the source of
// truth: callers accept the result only when the complete enclosing set
// re-encodes byte-for-byte.
func decodeCanonicalLifecycleProjection(in *ccse.Decoder) (foundationv1.KeyLifecycleSigningProjection, error) {
	metadata, err := decodeCanonicalRecordMetadata(in)
	if err != nil {
		return foundationv1.KeyLifecycleSigningProjection{}, err
	}
	value := foundationv1.KeyLifecycleSigningProjection{Metadata: metadata}
	if value.KeyID, err = in.String(256); err != nil {
		return foundationv1.KeyLifecycleSigningProjection{}, err
	}
	if value.SubjectIdentity, err = in.String(1024); err != nil {
		return foundationv1.KeyLifecycleSigningProjection{}, err
	}
	if value.SubjectKind, err = in.Uint32(); err != nil {
		return foundationv1.KeyLifecycleSigningProjection{}, err
	}
	if value.Algorithm, err = in.Uint32(); err != nil {
		return foundationv1.KeyLifecycleSigningProjection{}, err
	}
	if value.State, err = in.Uint32(); err != nil {
		return foundationv1.KeyLifecycleSigningProjection{}, err
	}
	if value.NotBeforeUnixNano, err = in.Int64(); err != nil {
		return foundationv1.KeyLifecycleSigningProjection{}, err
	}
	if value.NotAfterUnixNano, err = in.Int64(); err != nil {
		return foundationv1.KeyLifecycleSigningProjection{}, err
	}
	if value.RevokedAtUnixNano.Present, err = in.Presence(); err != nil {
		return foundationv1.KeyLifecycleSigningProjection{}, err
	}
	if value.RevokedAtUnixNano.Present {
		if value.RevokedAtUnixNano.Value, err = in.Int64(); err != nil {
			return foundationv1.KeyLifecycleSigningProjection{}, err
		}
	}
	if value.RotationPredecessorKeyID.Present, value.RotationPredecessorKeyID.Value, err = in.OptionalString(256); err != nil {
		return foundationv1.KeyLifecycleSigningProjection{}, err
	}
	if err = in.ValidatedSet(256, 4, func(_ int, child *ccse.Decoder) error {
		messageTypeID, decodeErr := child.Uint32()
		if decodeErr == nil {
			value.AllowedMessageTypeIDs = append(value.AllowedMessageTypeIDs, messageTypeID)
		}
		return decodeErr
	}); err != nil {
		return foundationv1.KeyLifecycleSigningProjection{}, err
	}
	if value.AuthorizationPolicyDigestSHA256, err = decodeCanonicalDigest(in); err != nil {
		return foundationv1.KeyLifecycleSigningProjection{}, err
	}
	if value.TransitionReasonCode.Present, value.TransitionReasonCode.Value, err = in.OptionalString(256); err != nil {
		return foundationv1.KeyLifecycleSigningProjection{}, err
	}
	return value, nil
}

func decodeCanonicalRecordMetadata(in *ccse.Decoder) (foundationv1.RecordMetadataSigningProjection, error) {
	var value foundationv1.RecordMetadataSigningProjection
	var err error
	if value.SchemaVersion.Major, err = in.Uint32(); err != nil {
		return foundationv1.RecordMetadataSigningProjection{}, err
	}
	if value.SchemaVersion.Minor, err = in.Uint32(); err != nil {
		return foundationv1.RecordMetadataSigningProjection{}, err
	}
	if value.RecordID, err = in.String(256); err != nil {
		return foundationv1.RecordMetadataSigningProjection{}, err
	}
	if value.CreatedAtUnixNano, err = in.Int64(); err != nil {
		return foundationv1.RecordMetadataSigningProjection{}, err
	}
	if value.IntegrityDigest, err = decodeCanonicalDigest(in); err != nil {
		return foundationv1.RecordMetadataSigningProjection{}, err
	}
	if value.HomeRegion, err = in.String(128); err != nil {
		return foundationv1.RecordMetadataSigningProjection{}, err
	}
	if value.WriterEpoch, err = in.Uint64(); err != nil {
		return foundationv1.RecordMetadataSigningProjection{}, err
	}
	if value.StateVersion, err = in.Uint64(); err != nil {
		return foundationv1.RecordMetadataSigningProjection{}, err
	}
	if value.IdempotencyKey, err = decodeCanonicalFixed16(in); err != nil {
		return foundationv1.RecordMetadataSigningProjection{}, err
	}
	if err = in.ValidatedSet(64, 64, func(_ int, child *ccse.Decoder) error {
		digest, decodeErr := decodeCanonicalDigest(child)
		if decodeErr == nil {
			value.PolicyDigestsSHA256 = append(value.PolicyDigestsSHA256, digest)
		}
		return decodeErr
	}); err != nil {
		return foundationv1.RecordMetadataSigningProjection{}, err
	}
	return value, nil
}

func decodeCanonicalSnapshotPreconditions(encoded []byte, max int) ([]SnapshotPrecondition, error) {
	values := make([]SnapshotPrecondition, 0)
	err := ccse.Unmarshal(encoded, 512<<10, func(in *ccse.Decoder) error {
		return in.ValidatedList(max, 2048, func(_ int, child *ccse.Decoder) error {
			var value SnapshotPrecondition
			var err error
			if value.Entity, err = decodeCanonicalEntity(child, 2048); err != nil {
				return err
			}
			if value.ExpectedStateVersion, err = child.Uint64(); err != nil {
				return err
			}
			if value.ExpectedWriterEpoch, err = child.Uint64(); err != nil {
				return err
			}
			if value.ExpectedState, err = child.Uint32(); err != nil {
				return err
			}
			if value.ExpectedSnapshotDigest, err = decodeCanonicalDigest(child); err != nil {
				return err
			}
			values = append(values, value)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	reencoded, err := canonicalSnapshotPreconditions(values)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return nil, fmt.Errorf("noncanonical snapshot preconditions")
	}
	return values, nil
}

type opaqueRetainedRecord struct {
	messageTypeID uint32
	schemaVersion ccse.Version
	recordDigest  [sha256.Size]byte
	payloadDigest [sha256.Size]byte
}

func decodeOpaqueRetainedRecordSet(encoded []byte, max int, requireNonempty bool) ([]opaqueRetainedRecord, error) {
	records := make([]opaqueRetainedRecord, 0)
	err := ccse.Unmarshal(encoded, 4<<20, func(in *ccse.Decoder) error {
		return in.ValidatedSet(max, 2<<20, func(_ int, child *ccse.Decoder) error {
			record, err := decodeOpaqueRetainedRecordDecoder(child)
			if err == nil {
				records = append(records, record)
			}
			return err
		})
	})
	if err != nil || (requireNonempty && len(records) == 0) {
		return nil, fmt.Errorf("invalid retained record set: %v", err)
	}
	return records, nil
}

func decodeOpaqueRetainedRecord(encoded []byte) (opaqueRetainedRecord, error) {
	var record opaqueRetainedRecord
	err := ccse.Unmarshal(encoded, 2<<20, func(in *ccse.Decoder) error {
		var decodeErr error
		record, decodeErr = decodeOpaqueRetainedRecordDecoder(in)
		return decodeErr
	})
	return record, err
}

func decodeOpaqueRetainedRecordDecoder(in *ccse.Decoder) (opaqueRetainedRecord, error) {
	digest, err := decodeCanonicalDigest(in)
	if err != nil {
		return opaqueRetainedRecord{}, err
	}
	signed, err := in.Bytes(2 << 20)
	if err != nil {
		return opaqueRetainedRecord{}, err
	}
	var preimage, signature []byte
	err = ccse.Unmarshal(signed, 2<<20, func(signedIn *ccse.Decoder) error {
		var decodeErr error
		if preimage, decodeErr = signedIn.Bytes(2 << 20); decodeErr != nil {
			return decodeErr
		}
		signature, decodeErr = signedIn.Bytes(ed25519.SignatureSize)
		return decodeErr
	})
	if err != nil || len(signature) != ed25519.SignatureSize || sha256.Sum256(preimage) != digest ||
		digest == ([sha256.Size]byte{}) {
		return opaqueRetainedRecord{}, fmt.Errorf("invalid retained signed record")
	}
	messageTypeID, schemaVersion, payloadDigest, err := canonicalCCSEPreimageHeader(preimage)
	if err != nil {
		return opaqueRetainedRecord{}, err
	}
	return opaqueRetainedRecord{messageTypeID: messageTypeID, schemaVersion: schemaVersion,
		recordDigest: digest, payloadDigest: payloadDigest}, nil
}

func canonicalCCSEPreimageHeader(preimage []byte) (uint32, ccse.Version, [sha256.Size]byte, error) {
	const preamble = "CPH-AIIE-CCSE-V1\x00"
	if len(preimage) < len(preamble)+12+4 || string(preimage[:len(preamble)]) != preamble {
		return 0, ccse.Version{}, [sha256.Size]byte{}, fmt.Errorf("invalid CCSE preimage prefix")
	}
	offset := len(preamble)
	readUint32 := func() (uint32, error) {
		if offset > len(preimage)-4 {
			return 0, fmt.Errorf("truncated CCSE preimage")
		}
		value := uint32(preimage[offset])<<24 | uint32(preimage[offset+1])<<16 |
			uint32(preimage[offset+2])<<8 | uint32(preimage[offset+3])
		offset += 4
		return value, nil
	}
	messageTypeID, err := readUint32()
	if err != nil {
		return 0, ccse.Version{}, [sha256.Size]byte{}, err
	}
	major, err := readUint32()
	if err != nil {
		return 0, ccse.Version{}, [sha256.Size]byte{}, err
	}
	minor, err := readUint32()
	if err != nil || messageTypeID == 0 || major == 0 {
		return 0, ccse.Version{}, [sha256.Size]byte{}, fmt.Errorf("invalid CCSE preimage header")
	}
	schemaVersion := ccse.Version{Major: major, Minor: minor}
	readUint64 := func() (uint64, error) {
		if offset > len(preimage)-8 {
			return 0, fmt.Errorf("truncated CCSE preimage")
		}
		var value uint64
		for index := 0; index < 8; index++ {
			value = value<<8 | uint64(preimage[offset+index])
		}
		offset += 8
		return value, nil
	}
	domainLength, err := readUint32()
	if err != nil || uint64(domainLength) > uint64(len(preimage)-offset) {
		return 0, ccse.Version{}, [sha256.Size]byte{}, fmt.Errorf("invalid CCSE domain length")
	}
	offset += int(domainLength)
	envelopeLength, err := readUint64()
	if err != nil || envelopeLength > uint64(len(preimage)-offset) {
		return 0, ccse.Version{}, [sha256.Size]byte{}, fmt.Errorf("invalid CCSE envelope length")
	}
	offset += int(envelopeLength)
	payloadLength, err := readUint64()
	if err != nil || payloadLength > uint64(len(preimage)-offset) ||
		payloadLength != uint64(len(preimage)-offset) {
		return 0, ccse.Version{}, [sha256.Size]byte{}, fmt.Errorf("invalid CCSE payload length")
	}
	return messageTypeID, schemaVersion, sha256.Sum256(preimage[offset:]), nil
}

func decodeOpaqueEvidenceAdmissions(encoded []byte) (map[[sha256.Size]byte]uint32, error) {
	values := make(map[[sha256.Size]byte]uint32)
	err := ccse.Unmarshal(encoded, 128<<10, func(in *ccse.Decoder) error {
		return in.ValidatedSet(64, 1024, func(_ int, child *ccse.Decoder) error {
			digest, err := decodeCanonicalDigest(child)
			if err != nil {
				return err
			}
			kind, err := child.Uint32()
			if err != nil {
				return err
			}
			fingerprint, err := decodeCanonicalDigest(child)
			if err != nil {
				return err
			}
			if digest == ([sha256.Size]byte{}) || kind == 0 || fingerprint == ([sha256.Size]byte{}) {
				return fmt.Errorf("invalid evidence admission")
			}
			if _, duplicate := values[digest]; duplicate {
				return fmt.Errorf("duplicate evidence admission")
			}
			values[digest] = kind
			return nil
		})
	})
	return values, err
}

func decodeCanonicalEntity(in *ccse.Decoder, maxStringBytes int) (EntityRef, error) {
	kind, err := in.Uint32()
	if err != nil {
		return EntityRef{}, err
	}
	principalKind, err := in.Uint32()
	if err != nil {
		return EntityRef{}, err
	}
	id, err := in.String(maxStringBytes)
	if err != nil {
		return EntityRef{}, err
	}
	if kind > uint32(^EntityKind(0)) {
		return EntityRef{}, fmt.Errorf("entity kind overflows")
	}
	return EntityRef{Kind: EntityKind(kind), PrincipalKind: principalKind, ID: id}, nil
}

func decodeCanonicalDigest(in *ccse.Decoder) ([sha256.Size]byte, error) {
	encoded, err := in.FixedBytes(sha256.Size)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	var result [sha256.Size]byte
	copy(result[:], encoded)
	return result, nil
}

func decodeCanonicalFixed16(in *ccse.Decoder) ([16]byte, error) {
	encoded, err := in.FixedBytes(16)
	if err != nil {
		return [16]byte{}, err
	}
	var result [16]byte
	copy(result[:], encoded)
	return result, nil
}
