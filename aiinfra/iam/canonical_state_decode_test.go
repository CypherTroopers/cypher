// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"testing"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

func canonicalDecodeTestRecord(kind, objectID string, version uint64, digest [sha256.Size]byte,
	canonical []byte, terminal bool) CanonicalStateRecord {
	contentType, _ := canonicalStateSpec(kind)
	return CanonicalStateRecord{Namespace: CanonicalStateNamespaceIAM, Kind: kind,
		ObjectID: objectID, Version: version, StateDigestSHA256: digest, ContentType: contentType,
		CanonicalState: append([]byte(nil), canonical...), Terminal: terminal,
		AuditEventID: "audit:test:canonical-state-decode"}
}

func TestDecodeCanonicalIAMStateRecordReversibleKinds(t *testing.T) {
	material := materialSnapshot(t, 0x31, "spiffe://cph.example/agent/decode", 2)
	materialCanonical, err := canonicalMaterialSnapshot(material)
	if err != nil {
		t.Fatal(err)
	}
	materialRecord := canonicalDecodeTestRecord(CanonicalStateKindIAMKeyMaterial, material.KeyID,
		material.StateVersion, material.EnrollmentBindingDigest, materialCanonical, true)

	identity, err := NormalizeIdentity(agentProjection(material, 2, 3, 7))
	if err != nil {
		t.Fatal(err)
	}
	identityRecord := canonicalDecodeTestRecord(CanonicalStateKindIAMIdentity, identity.Ref.ID,
		identity.StateVersion, domainDigest(resolvedIdentitySnapshotDomain, identity.CanonicalPayload),
		identity.CanonicalPayload, false)

	lifecycle := lifecycleSnapshot(t, material, 4, 3, 7)
	lifecycleRecord := canonicalDecodeTestRecord(CanonicalStateKindIAMKeyLifecycle, lifecycle.KeyID,
		lifecycle.StateVersion, domainDigest(resolvedLifecycleSnapshotDomain, lifecycle.CanonicalPayload),
		lifecycle.CanonicalPayload, true)

	lease := lease(identity.Ref, "spiffe://cph.example/service/iam-writer", 9, 0x41)
	leaseCanonical, err := canonicalWriterLeaseState(lease)
	if err != nil {
		t.Fatal(err)
	}
	leaseRecord := canonicalDecodeTestRecord(CanonicalStateKindIAMWriterLease,
		canonicalEntityObjectID(lease.Entity), lease.WriterEpoch,
		domainDigest(iamWriterLeaseStateDomain, leaseCanonical), leaseCanonical, false)

	challenge := ProofChallengeSnapshot{Challenge: digest(0x42), SubjectIdentity: material.SubjectIdentity,
		SubjectKind: material.SubjectKind, TargetIdentity: material.TargetIdentity,
		Domain: material.EnrollmentDomain, ExpiresAtUnixNano: testNow + 100,
		IssuerIdentity:      "spiffe://cph.example/service/enroller",
		PolicyDigestsSHA256: [][32]byte{digest(0x43), digest(0x44)}, EvidenceDigest: digest(0x45)}
	challengeCanonical, err := canonicalProofChallengeState(challenge)
	if err != nil {
		t.Fatal(err)
	}
	challengeRecord := canonicalDecodeTestRecord(CanonicalStateKindIAMProofChallenge,
		bytesToHex(challenge.Challenge[:]), 1, domainDigest(iamProofChallengeStateDomain, challengeCanonical),
		challengeCanonical, false)

	principalCanonical, err := canonicalPrincipalIndexState(identity.Ref.PrincipalKind,
		identity.PrincipalIdentity, identity.Ref, identity.StateVersion, identity.WriterEpoch,
		identity.State, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	principalRecord := canonicalDecodeTestRecord(CanonicalStateKindIAMPrincipalIdentityIndex,
		principalIndexObjectID(identity.Ref.PrincipalKind, identity.PrincipalIdentity), 17,
		domainDigest(iamPrincipalIndexStateDomain, principalCanonical), principalCanonical, false)

	predecessorCanonical, err := canonicalPredecessorIndexState("cph-key:old", "cph-key:new")
	if err != nil {
		t.Fatal(err)
	}
	predecessorRecord := canonicalDecodeTestRecord(CanonicalStateKindIAMRotationPredecessorIndex,
		"cph-key:old", 1, domainDigest(iamPredecessorIndexStateDomain, predecessorCanonical),
		predecessorCanonical, true)

	setDigest := digest(0x46)
	subjectCanonical, err := canonicalSubjectKeySetState(identity.Ref.PrincipalKind,
		identity.PrincipalIdentity, setDigest)
	if err != nil {
		t.Fatal(err)
	}
	subjectRecord := canonicalDecodeTestRecord(CanonicalStateKindIAMSubjectKeySet,
		principalIndexObjectID(identity.Ref.PrincipalKind, identity.PrincipalIdentity), 23,
		setDigest, subjectCanonical, false)

	tests := []struct {
		name   string
		record CanonicalStateRecord
		assert func(testing.TB, DecodedCanonicalIAMState)
	}{
		{"key-material", materialRecord, func(t testing.TB, decoded DecodedCanonicalIAMState) {
			value, ok := decoded.KeyMaterial()
			if !ok || value.KeyID != material.KeyID {
				t.Fatal("key material getter mismatch")
			}
			value.CanonicalPublicKey[0] ^= 0xff
			again, _ := decoded.KeyMaterial()
			if bytes.Equal(value.CanonicalPublicKey, again.CanonicalPublicKey) {
				t.Fatal("key material getter aliases decoded state")
			}
		}},
		{"identity", identityRecord, func(t testing.TB, decoded DecodedCanonicalIAMState) {
			value, ok := decoded.Identity()
			if !ok || len(value.CandidateMessageTypeIDs()) != 3 || value.RehydratesSemanticSnapshot() {
				t.Fatal("identity getter mismatch")
			}
			if _, err := value.SemanticSnapshot(); !errors.Is(err, ErrCanonicalStateUnrehydratable) {
				t.Fatalf("ambiguous identity SemanticSnapshot error = %v", err)
			}
		}},
		{"lifecycle", lifecycleRecord, func(t testing.TB, decoded DecodedCanonicalIAMState) {
			value, ok := decoded.KeyLifecycle()
			if !ok || value.KeyID != lifecycle.KeyID || value.State != lifecycle.State {
				t.Fatal("lifecycle getter mismatch")
			}
		}},
		{"writer-lease", leaseRecord, func(t testing.TB, decoded DecodedCanonicalIAMState) {
			value, ok := decoded.WriterLease()
			if !ok || value != lease {
				t.Fatal("writer lease getter mismatch")
			}
		}},
		{"proof-challenge", challengeRecord, func(t testing.TB, decoded DecodedCanonicalIAMState) {
			value, ok := decoded.ProofChallenge()
			if !ok || value.Challenge != challenge.Challenge || len(value.PolicyDigestsSHA256) != 2 {
				t.Fatal("proof challenge getter mismatch")
			}
		}},
		{"principal-index", principalRecord, func(t testing.TB, decoded DecodedCanonicalIAMState) {
			value, ok := decoded.PrincipalIdentityIndex()
			if !ok || value.Owner != identity.Ref || value.IdentityStateVersion != identity.StateVersion {
				t.Fatal("principal index getter mismatch")
			}
		}},
		{"predecessor-index", predecessorRecord, func(t testing.TB, decoded DecodedCanonicalIAMState) {
			value, ok := decoded.RotationPredecessorIndex()
			if !ok || value.PredecessorKeyID != "cph-key:old" || value.SuccessorKeyID != "cph-key:new" {
				t.Fatal("predecessor index getter mismatch")
			}
		}},
		{"subject-key-set", subjectRecord, func(t testing.TB, decoded DecodedCanonicalIAMState) {
			value, ok := decoded.SubjectKeySet()
			if !ok || value.KeySetDigestSHA256 != setDigest || value.RehydratesMembers() {
				t.Fatal("subject key-set getter mismatch")
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decoded, decodeErr := DecodeCanonicalIAMStateRecord(test.record)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			if decoded.Kind() != test.record.Kind || decoded.Record().StateDigestSHA256 != test.record.StateDigestSHA256 {
				t.Fatal("decoded record mismatch")
			}
			test.assert(t, decoded)
		})
	}
}

func TestDecodeCanonicalIAMAcceptedTransferIsVerifiedButOpaque(t *testing.T) {
	_, _, accepted := acceptedTransferFixture(t)
	canonical, digest, err := canonicalAcceptedTransferState(accepted)
	if err != nil {
		t.Fatal(err)
	}
	record := canonicalDecodeTestRecord(CanonicalStateKindIAMAcceptedOwnershipTransfer,
		accepted.Projection.TransferAuthorizationID, accepted.StateVersion, digest, canonical, true)
	decoded, err := DecodeCanonicalIAMStateRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	value, ok := decoded.AcceptedOwnershipTransfer()
	if !ok || value.Projection().TransferAuthorizationID != accepted.Projection.TransferAuthorizationID ||
		value.TransferEvidenceDigestSHA256() != accepted.TransferEvidenceDigest ||
		value.StateVersion() != accepted.StateVersion || value.WriterEpoch() != accepted.WriterEpoch ||
		value.ApprovalCount() != len(accepted.Approvals) ||
		value.ClosureCount() != len(accepted.FixedEvidence.KeyClosureSnapshots) ||
		value.EvidenceCount() != len(accepted.FixedEvidence.EvidenceRecords) {
		t.Fatal("accepted transfer opaque projection mismatch")
	}
	if value.RehydratesSemanticSnapshot() {
		t.Fatal("v1 accepted transfer unexpectedly claims semantic rehydration")
	}
	if _, err := value.SemanticSnapshot(); !errors.Is(err, ErrCanonicalStateUnrehydratable) {
		t.Fatalf("SemanticSnapshot error = %v", err)
	}
}

func TestDecodeCanonicalIAMAcceptedTransferRejectsSelfConsistentInnerTampering(t *testing.T) {
	_, _, accepted := acceptedTransferFixture(t)
	canonical, digest, err := canonicalAcceptedTransferState(accepted)
	if err != nil {
		t.Fatal(err)
	}
	record := canonicalDecodeTestRecord(CanonicalStateKindIAMAcceptedOwnershipTransfer,
		accepted.Projection.TransferAuthorizationID, accepted.StateVersion, digest, canonical, true)

	t.Run("partial-authority-set", func(t *testing.T) {
		parts := decodeAcceptedWireParts(t, canonical)
		approvals := decodeRawCCSECollection(t, parts.approvals)
		if len(approvals) < 2 {
			t.Fatal("fixture requires at least two approvals")
		}
		parts.approvals = encodeRawCCSESet(t, approvals[1:])
		requireAcceptedWireRejected(t, record, parts.encode(t))
	})

	t.Run("zero-approval-fingerprint", func(t *testing.T) {
		parts := decodeAcceptedWireParts(t, canonical)
		approvals := decodeRawCCSECollection(t, parts.approvals)
		approvals[0] = mutateApprovalElement(t, approvals[0], false, true)
		parts.approvals = encodeRawCCSESet(t, approvals)
		requireAcceptedWireRejected(t, record, parts.encode(t))
	})

	t.Run("wrong-approval-record-type", func(t *testing.T) {
		parts := decodeAcceptedWireParts(t, canonical)
		approvals := decodeRawCCSECollection(t, parts.approvals)
		approvals[0] = mutateApprovalElement(t, approvals[0], true, false)
		parts.approvals = encodeRawCCSESet(t, approvals)
		requireAcceptedWireRejected(t, record, parts.encode(t))
	})

	t.Run("wrong-evidence-record-type", func(t *testing.T) {
		parts := decodeAcceptedWireParts(t, canonical)
		fixed := decodeFixedEvidenceWireParts(t, parts.fixed)
		evidence := decodeRawCCSECollection(t, fixed[5])
		if len(evidence) == 0 {
			t.Fatal("fixture requires retained evidence")
		}
		evidence[0] = mutateRetainedRecordType(t, evidence[0], schema.MessageTypeAuditEvent)
		fixed[5] = encodeRawCCSESet(t, evidence)
		parts.fixed = encodeFixedEvidenceWireParts(t, fixed)
		requireAcceptedWireRejected(t, record, parts.encode(t))
	})

	t.Run("wrong-closure-record-type", func(t *testing.T) {
		parts := decodeAcceptedWireParts(t, canonical)
		fixed := decodeFixedEvidenceWireParts(t, parts.fixed)
		closures := decodeRawCCSECollection(t, fixed[3])
		if len(closures) == 0 {
			t.Fatal("fixture requires retained closure")
		}
		closures[0] = mutateRetainedRecordType(t, closures[0], schema.MessageTypeAuditEvent)
		fixed[3] = encodeRawCCSESet(t, closures)
		parts.fixed = encodeFixedEvidenceWireParts(t, fixed)
		requireAcceptedWireRejected(t, record, parts.encode(t))
	})
}

type acceptedWireParts struct {
	payload                                   []byte
	transferDigest, profileDigest, activation [sha256.Size]byte
	approvals, fixed                          []byte
	acceptedAt                                int64
	stateVersion, writerEpoch                 uint64
}

func decodeAcceptedWireParts(t testing.TB, encoded []byte) acceptedWireParts {
	t.Helper()
	var value acceptedWireParts
	err := ccse.Unmarshal(encoded, canonicalIAMAcceptedMaxBytes, func(in *ccse.Decoder) error {
		var err error
		if value.payload, err = in.Bytes(196608); err != nil {
			return err
		}
		if value.transferDigest, err = decodeCanonicalDigest(in); err != nil {
			return err
		}
		if value.profileDigest, err = decodeCanonicalDigest(in); err != nil {
			return err
		}
		if value.activation, err = decodeCanonicalDigest(in); err != nil {
			return err
		}
		if value.approvals, err = in.Bytes(4 << 20); err != nil {
			return err
		}
		if value.fixed, err = in.Bytes(4 << 20); err != nil {
			return err
		}
		if value.acceptedAt, err = in.Int64(); err != nil {
			return err
		}
		if value.stateVersion, err = in.Uint64(); err != nil {
			return err
		}
		value.writerEpoch, err = in.Uint64()
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func (value acceptedWireParts) encode(t testing.TB) []byte {
	t.Helper()
	encoded, err := ccse.Marshal(canonicalIAMAcceptedMaxBytes, func(out *ccse.Encoder) {
		out.Bytes(value.payload)
		out.FixedBytes(value.transferDigest[:], sha256.Size)
		out.FixedBytes(value.profileDigest[:], sha256.Size)
		out.FixedBytes(value.activation[:], sha256.Size)
		out.Bytes(value.approvals)
		out.Bytes(value.fixed)
		out.Int64(value.acceptedAt)
		out.Uint64(value.stateVersion)
		out.Uint64(value.writerEpoch)
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func requireAcceptedWireRejected(t testing.TB, original CanonicalStateRecord, canonical []byte) {
	t.Helper()
	candidate := cloneCanonicalStateRecord(original)
	candidate.CanonicalState = append([]byte(nil), canonical...)
	candidate.StateDigestSHA256 = domainDigest(acceptedTransferDigestDomain, canonical)
	if _, err := DecodeCanonicalIAMStateRecord(candidate); !errors.Is(err, ErrCanonicalStateInvalid) {
		t.Fatalf("tampered accepted row error = %v", err)
	}
}

func decodeRawCCSECollection(t testing.TB, encoded []byte) [][]byte {
	t.Helper()
	if len(encoded) < 4 {
		t.Fatal("truncated CCSE collection")
	}
	count := int(binary.BigEndian.Uint32(encoded[:4]))
	offset := 4
	values := make([][]byte, 0, count)
	for index := 0; index < count; index++ {
		if offset > len(encoded)-4 {
			t.Fatal("truncated CCSE collection element length")
		}
		length := int(binary.BigEndian.Uint32(encoded[offset : offset+4]))
		offset += 4
		if length < 0 || offset > len(encoded)-length {
			t.Fatal("truncated CCSE collection element")
		}
		values = append(values, append([]byte(nil), encoded[offset:offset+length]...))
		offset += length
	}
	if offset != len(encoded) {
		t.Fatal("trailing CCSE collection bytes")
	}
	return values
}

func encodeRawCCSESet(t testing.TB, values [][]byte) []byte {
	t.Helper()
	encoded, err := ccse.Marshal(4<<20, func(out *ccse.Encoder) { out.EncodedSet(values) })
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mutateApprovalElement(t testing.TB, encoded []byte, mutateRecordType, zeroFingerprint bool) []byte {
	t.Helper()
	var identity, keyID string
	var oldSide bool
	var fingerprint [sha256.Size]byte
	var retained []byte
	err := ccse.Unmarshal(encoded, 2<<20, func(in *ccse.Decoder) error {
		var err error
		if identity, err = in.String(1024); err != nil {
			return err
		}
		if keyID, err = in.String(256); err != nil {
			return err
		}
		if oldSide, err = in.Bool(); err != nil {
			return err
		}
		if fingerprint, err = decodeCanonicalDigest(in); err != nil {
			return err
		}
		retained, err = in.Bytes(2 << 20)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if mutateRecordType {
		retained = mutateRetainedRecordType(t, retained, schema.MessageTypeAuditEvent)
	}
	if zeroFingerprint {
		fingerprint = [sha256.Size]byte{}
	}
	result, err := ccse.Marshal(2<<20, func(out *ccse.Encoder) {
		out.String(identity)
		out.String(keyID)
		out.Bool(oldSide)
		out.FixedBytes(fingerprint[:], sha256.Size)
		out.Bytes(retained)
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func mutateRetainedRecordType(t testing.TB, encoded []byte, messageTypeID uint32) []byte {
	t.Helper()
	var signed []byte
	err := ccse.Unmarshal(encoded, 2<<20, func(in *ccse.Decoder) error {
		if _, err := decodeCanonicalDigest(in); err != nil {
			return err
		}
		var readErr error
		signed, readErr = in.Bytes(2 << 20)
		return readErr
	})
	if err != nil {
		t.Fatal(err)
	}
	var preimage, signature []byte
	err = ccse.Unmarshal(signed, 2<<20, func(in *ccse.Decoder) error {
		var readErr error
		if preimage, readErr = in.Bytes(2 << 20); readErr != nil {
			return readErr
		}
		signature, readErr = in.Bytes(128)
		return readErr
	})
	if err != nil {
		t.Fatal(err)
	}
	const preamble = "CPH-AIIE-CCSE-V1\x00"
	if len(preimage) < len(preamble)+4 || string(preimage[:len(preamble)]) != preamble {
		t.Fatal("invalid retained preimage fixture")
	}
	binary.BigEndian.PutUint32(preimage[len(preamble):len(preamble)+4], messageTypeID)
	digest := sha256.Sum256(preimage)
	signed, err = ccse.Marshal(2<<20, func(out *ccse.Encoder) {
		out.Bytes(preimage)
		out.Bytes(signature)
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := ccse.Marshal(2<<20, func(out *ccse.Encoder) {
		out.FixedBytes(digest[:], sha256.Size)
		out.Bytes(signed)
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func decodeFixedEvidenceWireParts(t testing.TB, encoded []byte) [9][]byte {
	t.Helper()
	var values [9][]byte
	err := ccse.Unmarshal(encoded, 4<<20, func(in *ccse.Decoder) error {
		for index := range values {
			value, err := in.Bytes(4 << 20)
			if err != nil {
				return err
			}
			values[index] = value
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return values
}

func encodeFixedEvidenceWireParts(t testing.TB, values [9][]byte) []byte {
	t.Helper()
	encoded, err := ccse.Marshal(4<<20, func(out *ccse.Encoder) {
		for _, value := range values {
			out.Bytes(value)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestDecodeCanonicalIAMStateRecordRejectsRowAndCodecTampering(t *testing.T) {
	canonical, err := canonicalPredecessorIndexState("old", "new")
	if err != nil {
		t.Fatal(err)
	}
	record := canonicalDecodeTestRecord(CanonicalStateKindIAMRotationPredecessorIndex, "old", 1,
		domainDigest(iamPredecessorIndexStateDomain, canonical), canonical, true)
	mutations := []struct {
		name   string
		mutate func(*CanonicalStateRecord)
	}{
		{"namespace", func(value *CanonicalStateRecord) { value.Namespace++ }},
		{"kind", func(value *CanonicalStateRecord) { value.Kind = CanonicalStateKindIAMSubjectKeySet }},
		{"content-type", func(value *CanonicalStateRecord) { value.ContentType += "; forged" }},
		{"object-id", func(value *CanonicalStateRecord) { value.ObjectID = "other" }},
		{"version", func(value *CanonicalStateRecord) { value.Version++ }},
		{"digest", func(value *CanonicalStateRecord) { value.StateDigestSHA256[0] ^= 1 }},
		{"terminal", func(value *CanonicalStateRecord) { value.Terminal = false }},
		{"trailing-state", func(value *CanonicalStateRecord) { value.CanonicalState = append(value.CanonicalState, 0) }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			candidate := cloneCanonicalStateRecord(record)
			mutation.mutate(&candidate)
			if _, decodeErr := DecodeCanonicalIAMStateRecord(candidate); !errors.Is(decodeErr, ErrCanonicalStateInvalid) {
				t.Fatalf("error = %v", decodeErr)
			}
		})
	}
}

func TestDecodeCanonicalIAMStateRecordRejectsUnspecifiedV1ProfileActivationCodec(t *testing.T) {
	canonical := []byte{1}
	record := canonicalDecodeTestRecord(CanonicalStateKindIAMTransferProfileActivation, "profile-1", 1,
		sha256.Sum256(canonical), canonical, false)
	record.HasValidityWindow = true
	record.ValidFromUnixNano = 1
	record.ValidUntilUnixNano = 2
	if _, err := DecodeCanonicalIAMStateRecord(record); !errors.Is(err, ErrCanonicalStateInvalid) {
		t.Fatalf("error = %v", err)
	}
}

func TestCanonicalIAMStateKindSizeLimits(t *testing.T) {
	tests := []struct {
		kind string
		max  int
	}{
		{CanonicalStateKindIAMKeyMaterial, canonicalIAMMaterialMaxBytes},
		{CanonicalStateKindIAMIdentity, 32768},
		{CanonicalStateKindIAMKeyLifecycle, 32768},
		{CanonicalStateKindIAMAcceptedOwnershipTransfer, canonicalIAMAcceptedMaxBytes},
		{CanonicalStateKindIAMProofChallenge, canonicalIAMProofChallengeMaxBytes},
		{CanonicalStateKindIAMPrincipalIdentityIndex, canonicalIAMSidecarMaxBytes},
		{CanonicalStateKindIAMRotationPredecessorIndex, canonicalIAMSidecarMaxBytes},
		{CanonicalStateKindIAMSubjectKeySet, canonicalIAMSidecarMaxBytes},
		{CanonicalStateKindIAMWriterLease, canonicalIAMSidecarMaxBytes},
	}
	for _, test := range tests {
		t.Run(test.kind, func(t *testing.T) {
			if err := validateCanonicalIAMStateKindSize(test.kind, test.max); err != nil {
				t.Fatalf("exact max rejected: %v", err)
			}
			if err := validateCanonicalIAMStateKindSize(test.kind, test.max+1); err == nil {
				t.Fatal("max+1 accepted")
			}
		})
	}
}

func TestCanonicalAcceptedTransferPreconditionDecodeLimitsMatchProductionPreflight(t *testing.T) {
	for _, test := range []struct {
		name string
		max  int
	}{
		{"closure", maxTransferClosurePreconditions},
		{"evidence", maxTransferEvidencePreconditions},
	} {
		t.Run(test.name, func(t *testing.T) {
			values := make([]SnapshotPrecondition, test.max+1)
			for index := range values {
				values[index] = SnapshotPrecondition{
					Entity: EntityRef{Kind: EntityKeyLifecycle, PrincipalKind: 2,
						ID: fmt.Sprintf("key-%06d", index)},
					ExpectedStateVersion: 1, ExpectedWriterEpoch: 1, ExpectedState: 2,
					ExpectedSnapshotDigest: digest(byte(index%255 + 1)),
				}
			}
			exact, err := canonicalSnapshotPreconditions(values[:test.max])
			if err != nil {
				t.Fatal(err)
			}
			if decoded, err := decodeCanonicalSnapshotPreconditions(exact, test.max); err != nil ||
				len(decoded) != test.max {
				t.Fatalf("exact max decode len=%d error=%v", len(decoded), err)
			}
			over, err := canonicalSnapshotPreconditions(values)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeCanonicalSnapshotPreconditions(over, test.max); err == nil {
				t.Fatal("max+1 preconditions accepted")
			}
		})
	}
}

func TestDecodeCanonicalIAMIdentityUniqueAndAmbiguousShapes(t *testing.T) {
	providerProjection := foundationv1.ProviderIdentitySigningProjection{
		Metadata: metadata(1, 7, 0x70), ProviderID: "provider-decode",
		OrganizationIdentity: "spiffe://cph.example/provider/decode",
		PayoutIdentity:       "cph:provider-decode", Jurisdictions: []string{"DE"},
		PolicyDigestsSHA256: [][32]byte{digest(0x71)}, OwnershipGeneration: 1,
		ValidFromUnixNano: testNotBefore, ValidUntilUnixNano: testNotAfter, State: 2,
	}
	provider, err := NormalizeIdentity(providerProjection)
	if err != nil {
		t.Fatal(err)
	}
	providerRecord := canonicalDecodeTestRecord(CanonicalStateKindIAMIdentity, provider.Ref.ID,
		provider.StateVersion, domainDigest(resolvedIdentitySnapshotDomain, provider.CanonicalPayload),
		provider.CanonicalPayload, terminalIdentityState(provider.State))
	decoded, err := DecodeCanonicalIAMStateRecord(providerRecord)
	if err != nil {
		t.Fatal(err)
	}
	providerState, ok := decoded.Identity()
	if !ok || !providerState.RehydratesSemanticSnapshot() {
		t.Fatal("unique provider payload did not rehydrate")
	}
	providerSnapshot, err := providerState.SemanticSnapshot()
	if err != nil || providerSnapshot.MessageTypeID != schema.MessageTypeProviderIdentity {
		t.Fatalf("provider snapshot = %#v, error = %v", providerSnapshot, err)
	}

	material := materialSnapshot(t, 0x71, "spiffe://cph.example/identity/ambiguous", 2)
	agent, err := NormalizeIdentity(agentProjection(material, 2, 1, 7))
	if err != nil {
		t.Fatal(err)
	}
	agentRecord := canonicalDecodeTestRecord(CanonicalStateKindIAMIdentity, agent.Ref.ID,
		agent.StateVersion, domainDigest(resolvedIdentitySnapshotDomain, agent.CanonicalPayload),
		agent.CanonicalPayload, terminalIdentityState(agent.State))
	decoded, err = DecodeCanonicalIAMStateRecord(agentRecord)
	if err != nil {
		t.Fatal(err)
	}
	ambiguous, ok := decoded.Identity()
	if !ok || ambiguous.RehydratesSemanticSnapshot() {
		t.Fatal("ambiguous identity unexpectedly rehydrated")
	}
	got := ambiguous.CandidateMessageTypeIDs()
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	want := []uint32{schema.MessageTypeAgentIdentity, schema.MessageTypeHostIdentity,
		schema.MessageTypeServiceIdentity}
	if !equalUint32s(got, want) {
		t.Fatalf("candidate message types = %v, want %v", got, want)
	}
}

func equalUint32s(left, right []uint32) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func FuzzDecodeCanonicalIAMStateRecord(f *testing.F) {
	canonical, err := canonicalPredecessorIndexState("old", "new")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(uint8(0), []byte{})
	f.Add(uint8(6), canonical)
	kinds := [...]string{
		CanonicalStateKindIAMKeyMaterial,
		CanonicalStateKindIAMIdentity,
		CanonicalStateKindIAMKeyLifecycle,
		CanonicalStateKindIAMAcceptedOwnershipTransfer,
		CanonicalStateKindIAMProofChallenge,
		CanonicalStateKindIAMPrincipalIdentityIndex,
		CanonicalStateKindIAMRotationPredecessorIndex,
		CanonicalStateKindIAMSubjectKeySet,
		CanonicalStateKindIAMWriterLease,
	}
	f.Fuzz(func(t *testing.T, selector uint8, state []byte) {
		kind := kinds[int(selector)%len(kinds)]
		contentType, _ := canonicalStateSpec(kind)
		digest := sha256.Sum256(append([]byte("fuzz-state:"), state...))
		if kind == CanonicalStateKindIAMRotationPredecessorIndex {
			digest = domainDigest(iamPredecessorIndexStateDomain, state)
		}
		record := CanonicalStateRecord{Namespace: CanonicalStateNamespaceIAM, Kind: kind,
			ObjectID: "old", Version: 1, StateDigestSHA256: digest, ContentType: contentType,
			CanonicalState: append([]byte(nil), state...), Terminal: kind == CanonicalStateKindIAMRotationPredecessorIndex,
			AuditEventID: "audit:fuzz"}
		decoded, decodeErr := DecodeCanonicalIAMStateRecord(record)
		if decodeErr == nil {
			if _, secondErr := DecodeCanonicalIAMStateRecord(decoded.Record()); secondErr != nil {
				t.Fatalf("successful decode is not stable: %v", secondErr)
			}
		}
	})
}

func bytesToHex(value []byte) string {
	const digits = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, item := range value {
		result[index*2] = digits[item>>4]
		result[index*2+1] = digits[item&0x0f]
	}
	return string(result)
}
