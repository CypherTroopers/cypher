// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/cypherium/cypher/aiinfra/ccse"
)

func TestKeyIDAndProofOfPossession(t *testing.T) {
	public, private := testKey(0x21)
	keyID, err := DeriveKeyID(ccse.SignatureAlgorithmEd25519, public)
	if err != nil {
		t.Fatal(err)
	}
	const expected = "cph-key-v1:sha256:9bb63de08cc85e272226905b136de6064045a38c43d16615ef88af1964ad40fb"
	if keyID != expected {
		t.Fatalf("key id = %q, want %q", keyID, expected)
	}
	challenge := digest(0x22)
	expires := testNow + 99
	domain := testEnrollmentDomain()
	target := EntityRef{Kind: EntityIdentity, PrincipalKind: 2, ID: "agent-01"}
	proof, err := ProofOfPossessionDigest(keyID, "spiffe://cph.example/agent/01", 2, target, [32]byte{}, domain, challenge, expires)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(proof[:]), "b58a5c8ed1375b30e665077708151da397511d4e27f42d4f0a4e5d1a2fee0398"; got != want {
		t.Fatalf("proof digest = %s, want %s", got, want)
	}
	signature := ed25519.Sign(private, proof[:])
	verified, err := VerifyProofOfPossession(ccse.SignatureAlgorithmEd25519, public, keyID,
		"spiffe://cph.example/agent/01", 2, target, [32]byte{}, domain, challenge, expires, signature)
	if err != nil || verified != proof {
		t.Fatalf("verify = %x, %v", verified, err)
	}

	mutations := []func(){
		func() { signature[0] ^= 1 },
		func() { challenge[0] ^= 1 },
	}
	for i, mutate := range mutations {
		badSignature := append([]byte(nil), signature...)
		badChallenge := challenge
		if i == 0 {
			badSignature[0] ^= 1
		} else {
			badChallenge[0] ^= 1
		}
		if _, err := VerifyProofOfPossession(ccse.SignatureAlgorithmEd25519, public, keyID,
			"spiffe://cph.example/agent/01", 2, target, [32]byte{}, domain, badChallenge, expires, badSignature); err == nil {
			t.Fatalf("mutation %d accepted", i)
		}
		_ = mutate
	}
	badTarget := target
	badTarget.ID = "agent-02"
	if _, err := VerifyProofOfPossession(ccse.SignatureAlgorithmEd25519, public, keyID,
		"spiffe://cph.example/agent/01", 2, badTarget, [32]byte{}, domain, challenge, expires, signature); err == nil {
		t.Fatal("target identity substitution accepted")
	}
	if _, err := VerifyProofOfPossession(ccse.SignatureAlgorithmEd25519, public, keyID,
		"spiffe://cph.example/agent/01", 2, target, digest(0x23), domain, challenge, expires, signature); err == nil {
		t.Fatal("transfer evidence substitution accepted")
	}
	if _, err := DeriveKeyID(ccse.SignatureAlgorithmP256SHA256, public); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("P256 error = %v", err)
	}
	if _, err := CanonicalPublicKey(ccse.SignatureAlgorithmEd25519, public[:31]); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("short key error = %v", err)
	}
}

func TestPlanKeyMaterialDeterministicDetachedAndNoReuse(t *testing.T) {
	view := newMemoryView()
	profile := &allowProfile{}
	planner := testPlanner(t, view, profile)
	public, private := testKey(0x31)
	keyID, _ := DeriveKeyID(ccse.SignatureAlgorithmEd25519, public)
	challenge := digest(0x32)
	expires := testNow + 1_000
	domain := testEnrollmentDomain()
	target := EntityRef{Kind: EntityIdentity, PrincipalKind: 2, ID: "agent-31"}
	proofDigest, _ := ProofOfPossessionDigest(keyID, "spiffe://cph.example/agent/31", 2, target, [32]byte{}, domain, challenge, expires)
	signature := ed25519.Sign(private, proofDigest[:])
	ref := EntityRef{Kind: EntityKeyMaterial, PrincipalKind: 2, ID: keyID}
	view.challenges[challenge] = ProofChallengeSnapshot{Challenge: challenge, SubjectIdentity: "spiffe://cph.example/agent/31", SubjectKind: 2,
		TargetIdentity: target,
		Domain:         domain, ExpiresAtUnixNano: expires, IssuerIdentity: "spiffe://cph.example/service/enroller",
		PolicyDigestsSHA256: [][32]byte{digest(0x36)}, EvidenceDigest: digest(0x33)}
	view.leases[ref] = lease(ref, "spiffe://cph.example/service/iam-writer", 7, 0x34)
	command := KeyMaterialCommand{Algorithm: ccse.SignatureAlgorithmEd25519, CanonicalPublicKey: public,
		ClaimedKeyID: keyID, SubjectIdentity: "spiffe://cph.example/agent/31", SubjectKind: 2,
		TargetIdentity:   target,
		EnrollmentDomain: domain,
		Challenge:        challenge, ChallengeExpiresAtUnixNano: expires, ProofSignature: signature,
		EnrollmentAuthorityIdentity:       "spiffe://cph.example/service/enroller",
		EnrollmentAuthorityEvidenceDigest: digest(0x33), EnrollmentPolicyDigestsSHA256: [][32]byte{digest(0x36)},
		EvaluatedAtUnixNano: testNow, CorrelationID: id16(0x35), IdempotencyKey: id16(0x37), CauseCode: "bootstrap",
		Fence: fence(ref, "spiffe://cph.example/service/iam-writer", 7, 0, 0x34)}
	originalPublic := append([]byte(nil), public...)
	originalSignature := append([]byte(nil), signature...)
	first, err := planKeyMaterialForTest(planner, context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	second, err := planKeyMaterialForTest(planner, context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest() != second.Digest() || first.AuditIntent().Digest() != second.AuditIntent().Digest() {
		t.Fatal("plan is not deterministic")
	}
	material, ok := first.KeyMaterial()
	if !ok {
		t.Fatal("missing material")
	}
	material.CanonicalPublicKey[0] ^= 1
	material.ProofSignature[0] ^= 1
	again, _ := first.KeyMaterial()
	if bytes.Equal(material.CanonicalPublicKey, again.CanonicalPublicKey) || bytes.Equal(material.ProofSignature, again.ProofSignature) {
		t.Fatal("plan aliases getter result")
	}
	command.CanonicalPublicKey[0] ^= 1
	command.ProofSignature[0] ^= 1
	stored, _ := first.KeyMaterial()
	if stored.KeyID != keyID || !bytes.Equal(stored.CanonicalPublicKey, originalPublic) {
		t.Fatal("plan aliases command")
	}

	view.materials[keyID] = stored
	_, err = planKeyMaterialForTest(planner, context.Background(), KeyMaterialCommand{
		Algorithm: ccse.SignatureAlgorithmEd25519, CanonicalPublicKey: originalPublic, ClaimedKeyID: keyID,
		SubjectIdentity: "spiffe://cph.example/agent/other", SubjectKind: 2, Challenge: challenge,
		TargetIdentity:   target,
		EnrollmentDomain: domain, ChallengeExpiresAtUnixNano: expires, ProofSignature: originalSignature, EvaluatedAtUnixNano: testNow,
		EnrollmentAuthorityIdentity:       command.EnrollmentAuthorityIdentity,
		EnrollmentAuthorityEvidenceDigest: command.EnrollmentAuthorityEvidenceDigest,
		EnrollmentPolicyDigestsSHA256:     command.EnrollmentPolicyDigestsSHA256,
		CorrelationID:                     id16(1), IdempotencyKey: id16(2), CauseCode: "reuse", Fence: command.Fence,
	})
	requireErrorIs(t, err, ErrInvalidProofOfPossession)
	// The exact-material/exact-subject case reaches the global existence fence.
	command.CanonicalPublicKey = originalPublic
	command.ProofSignature = originalSignature
	_, err = planKeyMaterialForTest(planner, context.Background(), command)
	requireErrorIs(t, err, ErrKeyMaterialExists)
}

func TestPlanKeyMaterialRejectsChallengeAndFenceDrift(t *testing.T) {
	view := newMemoryView()
	planner := testPlanner(t, view, &allowProfile{})
	material := materialSnapshot(t, 0x41, "spiffe://cph.example/agent/41", 2)
	ref := EntityRef{Kind: EntityKeyMaterial, PrincipalKind: 2, ID: material.KeyID}
	view.challenges[material.ProofChallenge] = ProofChallengeSnapshot{Challenge: material.ProofChallenge,
		SubjectIdentity: material.SubjectIdentity, SubjectKind: material.SubjectKind,
		TargetIdentity:    material.TargetIdentity,
		Domain:            material.EnrollmentDomain,
		ExpiresAtUnixNano: material.ProofExpiresAtUnixNano, Consumed: true,
		IssuerIdentity:      material.EnrollmentAuthorityIdentity,
		PolicyDigestsSHA256: material.EnrollmentPolicyDigestsSHA256, EvidenceDigest: material.ChallengeEvidenceDigest}
	view.leases[ref] = lease(ref, material.WriterIdentity, 7, 0x44)
	command := KeyMaterialCommand{Algorithm: material.Algorithm, CanonicalPublicKey: material.CanonicalPublicKey,
		ClaimedKeyID: material.KeyID, SubjectIdentity: material.SubjectIdentity, SubjectKind: material.SubjectKind,
		TargetIdentity:   material.TargetIdentity,
		EnrollmentDomain: material.EnrollmentDomain,
		Challenge:        material.ProofChallenge, ChallengeExpiresAtUnixNano: material.ProofExpiresAtUnixNano,
		EnrollmentAuthorityIdentity:       material.EnrollmentAuthorityIdentity,
		EnrollmentAuthorityEvidenceDigest: material.ChallengeEvidenceDigest,
		EnrollmentPolicyDigestsSHA256:     material.EnrollmentPolicyDigestsSHA256,
		ProofSignature:                    material.ProofSignature, EvaluatedAtUnixNano: testNow, CorrelationID: id16(4), IdempotencyKey: material.IdempotencyKey, CauseCode: "bootstrap",
		Fence: fence(ref, material.WriterIdentity, 7, 0, 0x44)}
	_, err := planKeyMaterialForTest(planner, context.Background(), command)
	requireErrorIs(t, err, ErrProofChallengeConsumed)
	state := view.challenges[material.ProofChallenge]
	state.Consumed = false
	view.challenges[material.ProofChallenge] = state
	command.Fence.EvidenceDigest[0] ^= 1
	_, err = planKeyMaterialForTest(planner, context.Background(), command)
	requireErrorIs(t, err, ErrWriterFenceMismatch)
}
