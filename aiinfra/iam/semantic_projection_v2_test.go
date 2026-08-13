// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

func TestKeyMaterialSemanticProjectionV2RoundTripAndExactRebind(t *testing.T) {
	material := materialSnapshot(t, 0x91, "spiffe://cph.example/agent/semantic-v2", 2)
	canonical, stateDigest, err := CanonicalKeyMaterialStateV1(material)
	if err != nil {
		t.Fatal(err)
	}
	record := canonicalDecodeTestRecord(CanonicalStateKindIAMKeyMaterial, material.KeyID,
		material.StateVersion, stateDigest, canonical, true)
	projection, err := NewKeyMaterialSemanticProjectionV2(record, material)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSemanticProjectionV2(record.Kind, record.ObjectID, record.Version,
		record.StateDigestSHA256, record.CanonicalState, projection.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	restored, ok := decoded.KeyMaterial()
	if !ok || restored.KeyID != material.KeyID ||
		!bytes.Equal(restored.CanonicalPublicKey, material.CanonicalPublicKey) ||
		decoded.Projection().Digest() != projection.Digest() {
		t.Fatal("key material semantic projection did not round-trip exactly")
	}

	tests := map[string]func() (CanonicalStateRecord, []byte){
		"canonical-v1": func() (CanonicalStateRecord, []byte) {
			changed := record
			changed.CanonicalState = bytes.Clone(record.CanonicalState)
			changed.CanonicalState[len(changed.CanonicalState)-1] ^= 1
			return changed, projection.Bytes()
		},
		"state-digest": func() (CanonicalStateRecord, []byte) {
			changed := record
			changed.StateDigestSHA256[0] ^= 1
			return changed, projection.Bytes()
		},
		"unknown-json-field": func() (CanonicalStateRecord, []byte) {
			input := projection.Bytes()
			input[len(input)-1] = ','
			input = append(input, []byte(`"unknown":true}`)...)
			return record, input
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed, input := mutate()
			if _, decodeErr := DecodeSemanticProjectionV2(changed.Kind, changed.ObjectID,
				changed.Version, changed.StateDigestSHA256, changed.CanonicalState, input); !errors.Is(decodeErr, ErrCanonicalStateInvalid) {
				t.Fatalf("tampered projection accepted: %v", decodeErr)
			}
		})
	}
}

func TestSubjectKeySetSemanticProjectionV2RetainsExactBoundedMembers(t *testing.T) {
	material := materialSnapshot(t, 0x92, "spiffe://cph.example/agent/subject-set", 2)
	lifecycle := lifecycleSnapshot(t, material, 4, 3, 7)
	members := []SnapshotPrecondition{lifecyclePrecondition(lifecycle)}
	canonicalMembers, digest, err := canonicalSubjectKeySetMembersV2(lifecycle.SubjectKind,
		lifecycle.SubjectIdentity, members)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalSubjectKeySetState(lifecycle.SubjectKind,
		lifecycle.SubjectIdentity, digest)
	if err != nil {
		t.Fatal(err)
	}
	record := canonicalDecodeTestRecord(CanonicalStateKindIAMSubjectKeySet,
		principalIndexObjectID(lifecycle.SubjectKind, lifecycle.SubjectIdentity), 1, digest, canonical, false)
	projection, err := NewSubjectKeySetSemanticProjectionV2(record, lifecycle.SubjectKind,
		lifecycle.SubjectIdentity, members)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSemanticProjectionV2(record.Kind, record.ObjectID, record.Version,
		record.StateDigestSHA256, record.CanonicalState, projection.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	kind, principal, restored, ok := decoded.SubjectKeySet()
	if !ok || kind != lifecycle.SubjectKind || principal != lifecycle.SubjectIdentity ||
		!sameSnapshotPreconditions(restored, canonicalMembers) {
		t.Fatal("subject-key-set member preimages did not round-trip")
	}

	var wire iamSemanticProjectionV2Wire
	if err := json.Unmarshal(projection.Bytes(), &wire); err != nil {
		t.Fatal(err)
	}
	wire.SubjectKeys.Members[0].ExpectedWriterEpoch++
	selfConsistentTamper, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeSemanticProjectionV2(record.Kind, record.ObjectID, record.Version,
		record.StateDigestSHA256, record.CanonicalState, selfConsistentTamper); !errors.Is(err, ErrCanonicalStateInvalid) {
		t.Fatalf("member preimage tamper accepted: %v", err)
	}

	overflow := make([]SnapshotPrecondition, 257)
	for index := range overflow {
		overflow[index] = members[0]
		overflow[index].Entity.ID = fmt.Sprintf("cph-key:overflow-%03d", index)
		overflow[index].ExpectedSnapshotDigest[0] = byte(index + 1)
	}
	if _, err := NewSubjectKeySetSemanticProjectionV2(record, lifecycle.SubjectKind,
		lifecycle.SubjectIdentity, overflow); !errors.Is(err, ErrCanonicalStateInvalid) {
		t.Fatalf("257 subject members accepted: %v", err)
	}
}

func TestSemanticProjectionV2RejectsOversizeBeforeDecode(t *testing.T) {
	input := make([]byte, semanticProjectionV2Max+1)
	if _, err := DecodeSemanticProjectionV2(CanonicalStateKindIAMKeyMaterial, "cph-key:oversize", 1,
		digest(0xa1), []byte{1}, input); !errors.Is(err, ErrCanonicalStateInvalid) {
		t.Fatalf("oversize projection accepted: %v", err)
	}
}
