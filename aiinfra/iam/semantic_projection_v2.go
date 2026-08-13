// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"

	"github.com/cypherium/cypher/aiinfra/ccse"
)

const (
	// SemanticProjectionCodecV2 is the lossless companion codec for IAM
	// canonical-state rows.  It is deliberately separate from the frozen v1
	// row encoding: v1 remains useful as a signed/CAS commitment, while this
	// projection retains every preimage required to rebuild an IAM View after
	// restart.  For the one frozen profile-activation row whose v1 codec is
	// opaque, v2 instead commits SHA-256 of the exact associated v1 bytes and the
	// database enforces one-to-one same-row linkage.
	SemanticProjectionCodecV2 = "cph.aiinfra.iam.semantic-projection.v2"
	semanticProjectionV2Max   = 64 << 20
)

// SemanticProjectionV2 is a storage-neutral, immutable projection attached to
// one exact canonical-state history row.  Storage must key it by all of
// Kind/ObjectID/Version/StateDigestSHA256 and write it in the same UoW as that
// row; it is not a second independently mutable head.
type SemanticProjectionV2 struct {
	Kind               string
	ObjectID           string
	Version            uint64
	StateDigestSHA256  [sha256.Size]byte
	Canonical          []byte
	DigestSHA256       [sha256.Size]byte
	LookupDigestSHA256 [sha256.Size]byte
	HasLookupDigest    bool
}

func (value SemanticProjectionV2) Codec() string             { return SemanticProjectionCodecV2 }
func (value SemanticProjectionV2) Bytes() []byte             { return bytes.Clone(value.Canonical) }
func (value SemanticProjectionV2) Digest() [sha256.Size]byte { return value.DigestSHA256 }
func (value SemanticProjectionV2) LookupDigest() ([sha256.Size]byte, bool) {
	return value.LookupDigestSHA256, value.HasLookupDigest
}

// DecodedSemanticProjectionV2 is a detached closed union.  Exactly one getter
// succeeds.  Decoding always validates the semantic snapshot, derives the
// frozen v1 canonical row again, and byte-compares the input by re-encoding.
type DecodedSemanticProjectionV2 struct {
	projection      SemanticProjectionV2
	material        *KeyMaterialSnapshot
	identity        *IdentitySnapshot
	lifecycle       *KeyLifecycleSnapshot
	accepted        *AcceptedOwnershipTransferSnapshot
	subjectKeys     []SnapshotPrecondition
	subjectKind     uint32
	subjectIdentity string
	transferProfile *OwnershipTransferProfile
}

func (value DecodedSemanticProjectionV2) Projection() SemanticProjectionV2 {
	result := value.projection
	result.Canonical = bytes.Clone(result.Canonical)
	return result
}
func (value DecodedSemanticProjectionV2) KeyMaterial() (KeyMaterialSnapshot, bool) {
	if value.material == nil {
		return KeyMaterialSnapshot{}, false
	}
	return cloneKeyMaterial(*value.material), true
}
func (value DecodedSemanticProjectionV2) Identity() (IdentitySnapshot, bool) {
	if value.identity == nil {
		return IdentitySnapshot{}, false
	}
	return cloneIdentity(*value.identity), true
}
func (value DecodedSemanticProjectionV2) KeyLifecycle() (KeyLifecycleSnapshot, bool) {
	if value.lifecycle == nil {
		return KeyLifecycleSnapshot{}, false
	}
	return cloneLifecycle(*value.lifecycle), true
}
func (value DecodedSemanticProjectionV2) AcceptedOwnershipTransfer() (AcceptedOwnershipTransferSnapshot, bool) {
	if value.accepted == nil {
		return AcceptedOwnershipTransferSnapshot{}, false
	}
	return cloneAcceptedTransfer(*value.accepted), true
}
func (value DecodedSemanticProjectionV2) SubjectKeyMembers() ([]SnapshotPrecondition, bool) {
	if value.subjectKeys == nil {
		return nil, false
	}
	return append([]SnapshotPrecondition(nil), value.subjectKeys...), true
}
func (value DecodedSemanticProjectionV2) SubjectKeySet() (uint32, string, []SnapshotPrecondition, bool) {
	if value.subjectKeys == nil {
		return 0, "", nil, false
	}
	return value.subjectKind, value.subjectIdentity,
		append([]SnapshotPrecondition(nil), value.subjectKeys...), true
}
func (value DecodedSemanticProjectionV2) OwnershipTransferProfile() (OwnershipTransferProfile, bool) {
	if value.transferProfile == nil {
		return OwnershipTransferProfile{}, false
	}
	return cloneTransferProfile(*value.transferProfile), true
}

type iamSubjectKeySetProjectionV2Wire struct {
	SubjectKind       uint32                 `json:"subject_kind"`
	PrincipalIdentity string                 `json:"principal_identity"`
	Members           []SnapshotPrecondition `json:"members"`
}

type iamSemanticProjectionV2Wire struct {
	Version                 uint32                            `json:"version"`
	Kind                    string                            `json:"kind"`
	Material                *KeyMaterialSnapshot              `json:"material,omitempty"`
	Identity                *IdentitySnapshot                 `json:"identity,omitempty"`
	Lifecycle               *KeyLifecycleSnapshot             `json:"lifecycle,omitempty"`
	Accepted                *durableAcceptedTransferWire      `json:"accepted,omitempty"`
	SubjectKeys             *iamSubjectKeySetProjectionV2Wire `json:"subject_keys,omitempty"`
	TransferProfile         *OwnershipTransferProfile         `json:"transfer_profile,omitempty"`
	OpaqueCanonicalV1SHA256 *[sha256.Size]byte                `json:"opaque_canonical_v1_sha256,omitempty"`
}

// BuildSemanticProjectionsV2 closes the production write path: every lossy
// core v1 mutation in fragment's already-bound canonical bundle receives one
// lossless v2 companion.  Reversible sidecars remain decoded from their v1
// rows and therefore intentionally do not receive a duplicate projection.
func BuildSemanticProjectionsV2(fragment IAMExecutionFragment) ([]SemanticProjectionV2, error) {
	if fragment.VerifyDigest() != nil || fragment.canonicalState == nil ||
		fragment.canonicalState.VerifyForExecution(fragment) != nil {
		return nil, ErrPendingPlanInvalid
	}
	type source struct {
		kind    string
		id      string
		version uint64
		wire    iamSemanticProjectionV2Wire
	}
	sources := make([]source, 0, len(fragment.mutations)+len(fragment.cutoverWrites)+1)
	addWrite := func(write IAMMutationWrite) error {
		var item source
		switch write.Kind {
		case MutationCreateKeyMaterial:
			if write.Material == nil {
				return ErrPendingPlanInvalid
			}
			value, err := validateMaterialSnapshot(*write.Material)
			if err != nil {
				return err
			}
			item = source{CanonicalStateKindIAMKeyMaterial, value.KeyID, value.StateVersion,
				iamSemanticProjectionV2Wire{Version: 2, Kind: CanonicalStateKindIAMKeyMaterial, Material: &value}}
		case MutationAppendIdentity:
			if write.Identity == nil {
				return ErrPendingPlanInvalid
			}
			value, err := normalizeViewIdentity(*write.Identity)
			if err != nil {
				return err
			}
			item = source{CanonicalStateKindIAMIdentity, value.Ref.ID, value.StateVersion,
				iamSemanticProjectionV2Wire{Version: 2, Kind: CanonicalStateKindIAMIdentity, Identity: &value}}
		case MutationAppendKeyLifecycle:
			if write.Lifecycle == nil {
				return ErrPendingPlanInvalid
			}
			value, err := normalizeViewLifecycle(*write.Lifecycle)
			if err != nil {
				return err
			}
			item = source{CanonicalStateKindIAMKeyLifecycle, value.KeyID, value.StateVersion,
				iamSemanticProjectionV2Wire{Version: 2, Kind: CanonicalStateKindIAMKeyLifecycle, Lifecycle: &value}}
		default:
			return ErrPendingPlanInvalid
		}
		sources = append(sources, item)
		return nil
	}
	for _, write := range fragment.mutations {
		if err := addWrite(write); err != nil {
			return nil, err
		}
	}
	for _, step := range fragment.cutoverWrites {
		if err := addWrite(step.Write); err != nil {
			return nil, err
		}
	}
	if fragment.acceptedTransfer != nil {
		accepted := cloneAcceptedTransfer(fragment.acceptedTransfer.Next)
		if digest, err := acceptedTransferDigest(accepted); err != nil || digest != accepted.SnapshotDigest {
			return nil, ErrPendingPlanInvalid
		}
		wire := acceptedToWire(accepted)
		sources = append(sources, source{CanonicalStateKindIAMAcceptedOwnershipTransfer,
			accepted.Projection.TransferAuthorizationID, accepted.StateVersion,
			iamSemanticProjectionV2Wire{Version: 2,
				Kind: CanonicalStateKindIAMAcceptedOwnershipTransfer, Accepted: wire}})
	}

	used := make([]bool, len(sources))
	result := make([]SemanticProjectionV2, 0, len(sources))
	for _, mutation := range fragment.canonicalState.mutations {
		next := mutation.next
		if !semanticProjectionV2Required(next.Kind) {
			continue
		}
		if !semanticCoreProjectionV2Required(next.Kind) {
			if mutation.semanticV2 == nil {
				return nil, ErrPendingPlanInvalid
			}
			decoded, decodeErr := decodeSemanticProjectionV2(next.Kind, next.ObjectID, next.Version,
				next.StateDigestSHA256, next.CanonicalState, mutation.semanticV2.Canonical)
			if decodeErr != nil || decoded.Projection().Digest() != mutation.semanticV2.Digest() {
				return nil, ErrPendingPlanInvalid
			}
			result = append(result, decoded.Projection())
			continue
		}
		selected := -1
		for index := range sources {
			if !used[index] && sources[index].kind == next.Kind && sources[index].id == next.ObjectID &&
				sources[index].version == next.Version {
				if selected != -1 {
					return nil, ErrPendingPlanInvalid
				}
				selected = index
			}
		}
		if selected == -1 {
			return nil, ErrPendingPlanInvalid
		}
		encoded, err := marshalIAMSemanticProjectionV2(sources[selected].wire)
		if err != nil {
			return nil, err
		}
		projection, err := decodeSemanticProjectionV2(next.Kind, next.ObjectID, next.Version,
			next.StateDigestSHA256, next.CanonicalState, encoded)
		if err != nil {
			return nil, err
		}
		used[selected] = true
		result = append(result, projection.projection)
	}
	for _, consumed := range used {
		if !consumed {
			return nil, ErrPendingPlanInvalid
		}
	}
	return result, nil
}

func semanticCoreProjectionV2Required(kind string) bool {
	switch kind {
	case CanonicalStateKindIAMKeyMaterial, CanonicalStateKindIAMIdentity,
		CanonicalStateKindIAMKeyLifecycle, CanonicalStateKindIAMAcceptedOwnershipTransfer:
		return true
	default:
		return false
	}
}

func semanticProjectionV2Required(kind string) bool {
	return semanticCoreProjectionV2Required(kind) ||
		kind == CanonicalStateKindIAMSubjectKeySet ||
		kind == CanonicalStateKindIAMTransferProfileActivation
}

// NewKeyMaterialSemanticProjectionV2 builds a standalone lossless companion
// for audited bootstrap/migration writers and storage acceptance tests. It is
// the same strict codec used by BuildSemanticProjectionsV2 and immediately
// decodes against the supplied frozen v1 row before returning.
func NewKeyMaterialSemanticProjectionV2(record CanonicalStateRecord,
	material KeyMaterialSnapshot) (SemanticProjectionV2, error) {
	material, err := validateMaterialSnapshot(material)
	if err != nil || record.Kind != CanonicalStateKindIAMKeyMaterial ||
		record.ObjectID != material.KeyID || record.Version != material.StateVersion ||
		record.StateDigestSHA256 != material.EnrollmentBindingDigest {
		return SemanticProjectionV2{}, ErrCanonicalStateInvalid
	}
	wire := iamSemanticProjectionV2Wire{Version: 2, Kind: record.Kind, Material: &material}
	encoded, err := marshalIAMSemanticProjectionV2(wire)
	if err != nil {
		return SemanticProjectionV2{}, err
	}
	decoded, err := decodeSemanticProjectionV2(record.Kind, record.ObjectID, record.Version,
		record.StateDigestSHA256, record.CanonicalState, encoded)
	if err != nil {
		return SemanticProjectionV2{}, err
	}
	return decoded.projection, nil
}

// CanonicalKeyMaterialStateV1 returns the frozen exact v1 row bytes and
// semantic digest after validating a detached material snapshot. It is
// intended for explicit audited bootstrap writers; ordinary mutation flows
// obtain these bytes through CanonicalIAMStateView.
func CanonicalKeyMaterialStateV1(material KeyMaterialSnapshot) ([]byte, [sha256.Size]byte, error) {
	material, err := validateMaterialSnapshot(material)
	if err != nil {
		return nil, [sha256.Size]byte{}, ErrCanonicalStateInvalid
	}
	canonical, err := canonicalMaterialSnapshot(material)
	if err != nil {
		return nil, [sha256.Size]byte{}, ErrCanonicalStateInvalid
	}
	return canonical, material.EnrollmentBindingDigest, nil
}

// NewSubjectKeySetSemanticProjectionV2 preserves the exact member
// preconditions whose v1 digest was stored without its preimage.  The member
// set is canonicalized and its v1 digest is rederived before a companion can
// be attached.
func NewSubjectKeySetSemanticProjectionV2(record CanonicalStateRecord,
	subjectKind uint32, principal string, members []SnapshotPrecondition) (SemanticProjectionV2, error) {
	members, digest, err := canonicalSubjectKeySetMembersV2(subjectKind, principal, members)
	if err != nil || record.Kind != CanonicalStateKindIAMSubjectKeySet ||
		record.ObjectID != principalIndexObjectID(subjectKind, principal) ||
		record.StateDigestSHA256 != digest {
		return SemanticProjectionV2{}, ErrCanonicalStateInvalid
	}
	wire := iamSemanticProjectionV2Wire{Version: 2, Kind: record.Kind,
		SubjectKeys: &iamSubjectKeySetProjectionV2Wire{SubjectKind: subjectKind,
			PrincipalIdentity: principal, Members: members}}
	encoded, err := marshalIAMSemanticProjectionV2(wire)
	if err != nil {
		return SemanticProjectionV2{}, err
	}
	decoded, err := decodeSemanticProjectionV2(record.Kind, record.ObjectID, record.Version,
		record.StateDigestSHA256, record.CanonicalState, encoded)
	if err != nil {
		return SemanticProjectionV2{}, err
	}
	return decoded.projection, nil
}

// NewOwnershipTransferProfileSemanticProjectionV2 retains the immutable
// policy preimage omitted by ownership-transfer-profile-activation.v1.
func NewOwnershipTransferProfileSemanticProjectionV2(record CanonicalStateRecord,
	profile OwnershipTransferProfile) (SemanticProjectionV2, error) {
	profile, err := validateStandaloneTransferProfileV2(profile)
	if err != nil || record.Kind != CanonicalStateKindIAMTransferProfileActivation ||
		record.ObjectID != profile.ProfileID || record.Version != profile.Activation.StateVersion ||
		record.StateDigestSHA256 != profile.Activation.SnapshotDigest || !record.HasValidityWindow ||
		record.ValidFromUnixNano != profile.Activation.ValidFromUnixNano ||
		record.ValidUntilUnixNano != profile.Activation.ValidUntilUnixNano {
		return SemanticProjectionV2{}, ErrCanonicalStateInvalid
	}
	canonicalDigest := sha256.Sum256(record.CanonicalState)
	wire := iamSemanticProjectionV2Wire{Version: 2, Kind: record.Kind, TransferProfile: &profile,
		OpaqueCanonicalV1SHA256: &canonicalDigest}
	encoded, err := marshalIAMSemanticProjectionV2(wire)
	if err != nil {
		return SemanticProjectionV2{}, err
	}
	decoded, err := decodeSemanticProjectionV2(record.Kind, record.ObjectID, record.Version,
		record.StateDigestSHA256, record.CanonicalState, encoded)
	if err != nil {
		return SemanticProjectionV2{}, err
	}
	return decoded.projection, nil
}

func marshalIAMSemanticProjectionV2(wire iamSemanticProjectionV2Wire) ([]byte, error) {
	encoded, err := json.Marshal(wire)
	if err != nil || len(encoded) == 0 || len(encoded) > semanticProjectionV2Max {
		return nil, ErrCanonicalStateInvalid
	}
	return encoded, nil
}

// DecodeSemanticProjectionV2 verifies a projection against its exact frozen
// v1 row commitment.  v1-only rows never enter this function through a
// fallback; callers must return ErrCanonicalStateUnrehydratable when the
// companion is absent.
func DecodeSemanticProjectionV2(kind, objectID string, version uint64,
	stateDigest [sha256.Size]byte, canonicalV1, input []byte) (DecodedSemanticProjectionV2, error) {
	return decodeSemanticProjectionV2(kind, objectID, version, stateDigest, canonicalV1, input)
}

func decodeSemanticProjectionV2(kind, objectID string, version uint64,
	stateDigest [sha256.Size]byte, canonicalV1, input []byte) (DecodedSemanticProjectionV2, error) {
	if !semanticProjectionV2Required(kind) || objectID == "" || len(objectID) > 1024 || version == 0 ||
		stateDigest == ([sha256.Size]byte{}) || len(canonicalV1) == 0 || len(canonicalV1) > iamCanonicalStateMaxBytes ||
		len(input) == 0 || len(input) > semanticProjectionV2Max {
		return DecodedSemanticProjectionV2{}, ErrCanonicalStateInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	var wire iamSemanticProjectionV2Wire
	if err := decoder.Decode(&wire); err != nil {
		return DecodedSemanticProjectionV2{}, ErrCanonicalStateInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return DecodedSemanticProjectionV2{}, ErrCanonicalStateInvalid
	}
	if wire.Version != 2 || wire.Kind != kind {
		return DecodedSemanticProjectionV2{}, ErrCanonicalStateInvalid
	}
	reencoded, err := marshalIAMSemanticProjectionV2(wire)
	if err != nil || !bytes.Equal(reencoded, input) {
		return DecodedSemanticProjectionV2{}, ErrCanonicalStateInvalid
	}
	result := DecodedSemanticProjectionV2{}
	switch kind {
	case CanonicalStateKindIAMKeyMaterial:
		if wire.Material == nil || semanticV2WirePointers(wire) != 1 {
			return DecodedSemanticProjectionV2{}, ErrCanonicalStateInvalid
		}
		value, validateErr := validateMaterialSnapshot(*wire.Material)
		derived, canonicalErr := canonicalMaterialSnapshot(value)
		if validateErr != nil || canonicalErr != nil || value.KeyID != objectID || value.StateVersion != version ||
			value.EnrollmentBindingDigest != stateDigest || !bytes.Equal(derived, canonicalV1) {
			return DecodedSemanticProjectionV2{}, ErrCanonicalStateInvalid
		}
		result.material = &value
	case CanonicalStateKindIAMIdentity:
		if wire.Identity == nil || semanticV2WirePointers(wire) != 1 {
			return DecodedSemanticProjectionV2{}, ErrCanonicalStateInvalid
		}
		value, validateErr := normalizeViewIdentity(*wire.Identity)
		if validateErr != nil || value.Ref.ID != objectID || value.StateVersion != version ||
			domainDigest(resolvedIdentitySnapshotDomain, value.CanonicalPayload) != stateDigest ||
			!bytes.Equal(value.CanonicalPayload, canonicalV1) {
			return DecodedSemanticProjectionV2{}, ErrCanonicalStateInvalid
		}
		result.identity = &value
	case CanonicalStateKindIAMKeyLifecycle:
		if wire.Lifecycle == nil || semanticV2WirePointers(wire) != 1 {
			return DecodedSemanticProjectionV2{}, ErrCanonicalStateInvalid
		}
		value, validateErr := normalizeViewLifecycle(*wire.Lifecycle)
		if validateErr != nil || value.KeyID != objectID || value.StateVersion != version ||
			domainDigest(resolvedLifecycleSnapshotDomain, value.CanonicalPayload) != stateDigest ||
			!bytes.Equal(value.CanonicalPayload, canonicalV1) {
			return DecodedSemanticProjectionV2{}, ErrCanonicalStateInvalid
		}
		result.lifecycle = &value
	case CanonicalStateKindIAMAcceptedOwnershipTransfer:
		if wire.Accepted == nil || semanticV2WirePointers(wire) != 1 {
			return DecodedSemanticProjectionV2{}, ErrCanonicalStateInvalid
		}
		value, validateErr := acceptedFromWire(*wire.Accepted)
		derived, digest, canonicalErr := canonicalAcceptedTransferState(value)
		if validateErr != nil || canonicalErr != nil || value.Projection.TransferAuthorizationID != objectID ||
			value.StateVersion != version || digest != stateDigest || value.SnapshotDigest != stateDigest ||
			!bytes.Equal(derived, canonicalV1) {
			return DecodedSemanticProjectionV2{}, ErrCanonicalStateInvalid
		}
		result.accepted = &value
	case CanonicalStateKindIAMSubjectKeySet:
		if wire.SubjectKeys == nil || semanticV2WirePointers(wire) != 1 {
			return DecodedSemanticProjectionV2{}, ErrCanonicalStateInvalid
		}
		members, digest, memberErr := canonicalSubjectKeySetMembersV2(wire.SubjectKeys.SubjectKind,
			wire.SubjectKeys.PrincipalIdentity, wire.SubjectKeys.Members)
		v1, v1Err := canonicalSubjectKeySetState(wire.SubjectKeys.SubjectKind,
			wire.SubjectKeys.PrincipalIdentity, digest)
		if memberErr != nil || v1Err != nil || objectID != principalIndexObjectID(
			wire.SubjectKeys.SubjectKind, wire.SubjectKeys.PrincipalIdentity) || digest != stateDigest ||
			!bytes.Equal(v1, canonicalV1) {
			return DecodedSemanticProjectionV2{}, ErrCanonicalStateInvalid
		}
		result.subjectKeys = members
		result.subjectKind = wire.SubjectKeys.SubjectKind
		result.subjectIdentity = wire.SubjectKeys.PrincipalIdentity
	case CanonicalStateKindIAMTransferProfileActivation:
		if wire.TransferProfile == nil || wire.OpaqueCanonicalV1SHA256 == nil ||
			semanticV2WirePointers(wire) != 1 {
			return DecodedSemanticProjectionV2{}, ErrCanonicalStateInvalid
		}
		profile, profileErr := validateStandaloneTransferProfileV2(*wire.TransferProfile)
		if profileErr != nil || objectID != profile.ProfileID || version != profile.Activation.StateVersion ||
			stateDigest != profile.Activation.SnapshotDigest ||
			*wire.OpaqueCanonicalV1SHA256 != sha256.Sum256(canonicalV1) {
			return DecodedSemanticProjectionV2{}, ErrCanonicalStateInvalid
		}
		result.transferProfile = &profile
	default:
		return DecodedSemanticProjectionV2{}, fmt.Errorf("%w: unsupported semantic projection", ErrCanonicalStateInvalid)
	}
	if kind != CanonicalStateKindIAMTransferProfileActivation && wire.OpaqueCanonicalV1SHA256 != nil {
		return DecodedSemanticProjectionV2{}, ErrCanonicalStateInvalid
	}
	result.projection = SemanticProjectionV2{Kind: kind, ObjectID: objectID, Version: version,
		StateDigestSHA256: stateDigest, Canonical: bytes.Clone(input), DigestSHA256: sha256.Sum256(input)}
	if result.accepted != nil {
		result.projection.LookupDigestSHA256 = result.accepted.TransferEvidenceDigest
		result.projection.HasLookupDigest = true
	}
	return result, nil
}

// OwnershipTransferSnapshot returns the legacy lookup projection derived from
// a fully validated accepted-transfer v2 snapshot.
func (value DecodedSemanticProjectionV2) OwnershipTransferSnapshot() (OwnershipTransferSnapshot, bool) {
	if value.accepted == nil {
		return OwnershipTransferSnapshot{}, false
	}
	snapshot := value.accepted
	return OwnershipTransferSnapshot{
		PreviousEntity: EntityRef{Kind: EntityIdentity, PrincipalKind: snapshot.Projection.SubjectKind,
			ID: snapshot.Projection.PreviousEntityID},
		NextEntity: EntityRef{Kind: EntityIdentity, PrincipalKind: snapshot.Projection.SubjectKind,
			ID: snapshot.Projection.NextEntityID},
		PreviousPrincipal:   snapshot.Projection.PreviousPrincipalIdentity,
		NextPrincipal:       snapshot.Projection.NextPrincipalIdentity,
		PreviousGeneration:  snapshot.Projection.ExpectedGeneration,
		NextGeneration:      snapshot.Projection.NextGeneration,
		CompletedAtUnixNano: snapshot.Projection.EffectiveAtUnixNano,
		EvidenceDigest:      snapshot.TransferEvidenceDigest,
	}, true
}

func semanticV2WirePointers(wire iamSemanticProjectionV2Wire) int {
	count := 0
	for _, present := range []bool{wire.Material != nil, wire.Identity != nil, wire.Lifecycle != nil,
		wire.Accepted != nil, wire.SubjectKeys != nil, wire.TransferProfile != nil} {
		if present {
			count++
		}
	}
	return count
}

func canonicalSubjectKeySetMembersV2(kind uint32, principal string,
	input []SnapshotPrecondition) ([]SnapshotPrecondition, [sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if kind < 1 || kind > 8 || principal == "" || len(input) > 256 {
		return nil, zero, ErrCanonicalStateInvalid
	}
	members, err := canonicalPreconditions(input)
	if err != nil {
		return nil, zero, ErrCanonicalStateInvalid
	}
	elements := make([][]byte, len(members))
	for index, member := range members {
		if member.Entity.Kind != EntityKeyLifecycle || member.Entity.PrincipalKind != kind ||
			member.Entity.ID == "" || member.ExpectedStateVersion == 0 || member.ExpectedWriterEpoch == 0 ||
			member.ExpectedState == 0 || member.ExpectedSnapshotDigest == zero {
			return nil, zero, ErrCanonicalStateInvalid
		}
		elements[index], err = ccse.Marshal(2048, func(out *ccse.Encoder) {
			encodeEntity(out, member.Entity)
			out.Uint64(member.ExpectedStateVersion)
			out.Uint64(member.ExpectedWriterEpoch)
			out.Uint32(member.ExpectedState)
		})
		if err != nil {
			return nil, zero, ErrCanonicalStateInvalid
		}
	}
	encoded, err := ccse.Marshal(32768, func(out *ccse.Encoder) {
		out.Uint32(kind)
		out.String(principal)
		out.EncodedList(elements)
	})
	if err != nil {
		return nil, zero, ErrCanonicalStateInvalid
	}
	return members, domainDigest("CPH-AIIE-IAM-SUBJECT-KEY-SET-V1\x00", encoded), nil
}

func validateStandaloneTransferProfileV2(input OwnershipTransferProfile) (OwnershipTransferProfile, error) {
	zero := [sha256.Size]byte{}
	if input.ProfileID == "" || input.ProfileVersion == 0 || input.PolicyDigest == zero ||
		input.RecordIntegrityDigestSHA256 == zero || len(input.OldAuthorities) == 0 ||
		len(input.NewAuthorities) == 0 || len(input.OldAuthorities)+len(input.NewAuthorities) > maxTransferAuthorities {
		return OwnershipTransferProfile{}, ErrCanonicalStateInvalid
	}
	profile := cloneTransferProfile(input)
	sortTransferRequirements(profile.OldAuthorities)
	sortTransferRequirements(profile.NewAuthorities)
	seenIdentities, seenKeys, oldOrganizations := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	coordinators := 0
	for side, values := range [][]OwnershipTransferAuthorityRequirement{profile.OldAuthorities, profile.NewAuthorities} {
		for _, value := range values {
			if value.Identity == "" || value.KeyID == "" || value.ProviderID == "" || value.OrganizationID == "" ||
				value.Role == "" || value.AuthorizationPolicyDigestSHA256 == zero {
				return OwnershipTransferProfile{}, ErrCanonicalStateInvalid
			}
			if _, exists := seenIdentities[value.Identity]; exists {
				return OwnershipTransferProfile{}, ErrCanonicalStateInvalid
			}
			if _, exists := seenKeys[value.KeyID]; exists {
				return OwnershipTransferProfile{}, ErrCanonicalStateInvalid
			}
			seenIdentities[value.Identity], seenKeys[value.KeyID] = struct{}{}, struct{}{}
			if side == 0 {
				if value.Coordinator {
					return OwnershipTransferProfile{}, ErrCanonicalStateInvalid
				}
				oldOrganizations[value.OrganizationID] = struct{}{}
			} else {
				if _, overlap := oldOrganizations[value.OrganizationID]; overlap {
					return OwnershipTransferProfile{}, ErrCanonicalStateInvalid
				}
				if value.Coordinator {
					coordinators++
				}
			}
		}
	}
	policy, err := encodeTransferProfilePolicy(profile)
	if err != nil || coordinators != 1 || domainDigest(transferProfileDigestDomain, policy) != profile.Activation.ProfileDigest {
		return OwnershipTransferProfile{}, ErrCanonicalStateInvalid
	}
	activation, err := transferProfileActivationDigest(profile.ProfileID, profile.ProfileVersion, profile.Activation)
	if err != nil || activation != profile.Activation.SnapshotDigest {
		return OwnershipTransferProfile{}, ErrCanonicalStateInvalid
	}
	return profile, nil
}
