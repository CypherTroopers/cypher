// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/cypherium/cypher/aiinfra/ccse"
)

func TestDurablePolicyApprovalCollectionRoundTripAndRehydrate(t *testing.T) {
	fixture := newGovernanceFixture(t)
	policy := fixture.normalPolicy()
	fixture.policyCommand(t, policy)
	payload, err := policy.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	binding := policyIdempotencyBinding(policy, sha256.Sum256(payload))
	snapshot := fixture.idempotency.snapshots[binding.Key]
	entries := fixture.collections.collections[binding.Key]

	encoded, err := EncodePolicyApprovalCollection(binding, snapshot.Version, snapshot.ProgressDigest, entries)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	reversed := append([]PolicyApprovalCollectionEntry(nil), entries...)
	reversed[0], reversed[1] = reversed[1], reversed[0]
	encodedReversed, err := EncodePolicyApprovalCollection(binding, snapshot.Version, snapshot.ProgressDigest, reversed)
	if err != nil || !bytes.Equal(encoded.Bytes(), encodedReversed.Bytes()) || encoded.Digest() != encodedReversed.Digest() {
		t.Fatalf("codec is not deterministic: err=%v", err)
	}
	decoded, err := DecodePolicyApprovalCollection(encoded.Bytes())
	if err != nil || decoded.Digest() != encoded.Digest() || decoded.Binding() != binding ||
		decoded.Revision() != snapshot.Version || decoded.ProgressDigest() != snapshot.ProgressDigest ||
		len(decoded.EvidenceDigests()) != len(entries) {
		t.Fatalf("decode: value=%+v err=%v", decoded, err)
	}
	capability, err := fixture.planner.RehydratePolicyApprovalCollection(context.Background(), decoded)
	if err != nil {
		t.Fatalf("rehydrate: %v", err)
	}
	got := capability.Entries()
	if capability.CommitReady() || len(got) != len(entries) || got[0].Signed.Verified.MessageTypeID() != 0 ||
		got[0].Signed.Verified.Digest() != ([ccse.DigestSize]byte{}) {
		t.Fatalf("bad rehydrated capability")
	}
	got[0].Signed.Record.Payload[0] ^= 0xff
	if bytes.Equal(got[0].Signed.Record.Payload, capability.Entries()[0].Signed.Record.Payload) {
		t.Fatal("rehydrated entries alias caller storage")
	}
}

func TestDurablePolicyApprovalCollectionTamperFailsClosed(t *testing.T) {
	fixture := newGovernanceFixture(t)
	policy := fixture.normalPolicy()
	fixture.policyCommand(t, policy)
	payload, err := policy.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	binding := policyIdempotencyBinding(policy, sha256.Sum256(payload))
	snapshot := fixture.idempotency.snapshots[binding.Key]
	entries := fixture.collections.collections[binding.Key]
	encoded, err := EncodePolicyApprovalCollection(binding, snapshot.Version, snapshot.ProgressDigest, entries)
	if err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func([]byte) []byte{
		"version":  func(input []byte) []byte { input[3]++; return input },
		"content":  func(input []byte) []byte { input[len(input)/2] ^= 0x80; return input },
		"trailing": func(input []byte) []byte { return append(input, 0) },
	} {
		t.Run(name, func(t *testing.T) {
			input := mutate(encoded.Bytes())
			if _, err := DecodePolicyApprovalCollection(input); !errors.Is(err, ErrApprovalCollection) {
				t.Fatalf("tamper error = %v", err)
			}
		})
	}

	forged := clonePolicyApprovalCollectionEntries(entries)
	forged[0].AdmissionKey.Roles = append(forged[0].AdmissionKey.Roles, "forged.role")
	// Keep the envelope internally self-consistent to prove that rehydration,
	// not merely parsing, performs the authoritative historical IAM check.
	approval, _, err := fixture.planner.validatePolicyApprovalAdmission(context.Background(), entries[0])
	if err != nil {
		t.Fatal(err)
	}
	approval.admissionKey = cloneKeySnapshot(forged[0].AdmissionKey)
	approval.admissionFingerprint, err = policyApprovalAdmissionFingerprint(approval)
	if err != nil {
		t.Fatal(err)
	}
	forged[0].AdmissionFingerprintSHA256 = approval.admissionFingerprint
	forgedEnvelope, err := EncodePolicyApprovalCollection(binding, snapshot.Version, snapshot.ProgressDigest, forged)
	if err != nil {
		t.Fatalf("encode self-consistent forgery: %v", err)
	}
	if _, err := fixture.planner.RehydratePolicyApprovalCollection(context.Background(), forgedEnvelope); !errors.Is(err, ErrApprovalCollection) {
		t.Fatalf("authoritative IAM substitution error = %v", err)
	}
}

func TestDurablePolicyApprovalCollectionBoundsBeforeAggregateEncode(t *testing.T) {
	fixture := newGovernanceFixture(t)
	policy := fixture.normalPolicy()
	fixture.policyCommand(t, policy)
	payload, err := policy.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	binding := policyIdempotencyBinding(policy, sha256.Sum256(payload))
	snapshot := fixture.idempotency.snapshots[binding.Key]
	entry := fixture.collections.collections[binding.Key][0]
	tooMany := make([]PolicyApprovalCollectionEntry, maxApprovals+1)
	for index := range tooMany {
		tooMany[index] = entry
	}
	if _, err := EncodePolicyApprovalCollection(binding, uint64(len(tooMany)), snapshot.ProgressDigest, tooMany); !errors.Is(err, ErrApprovalCollection) {
		t.Fatalf("aggregate bound error = %v", err)
	}
}
