// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"errors"
	"testing"

	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

func transferProfileFixture() (foundationv1.OwnershipTransferAuthorizationSigningProjection, OwnershipTransferProfile) {
	sharedAuthorityPolicy := digest(0xa2)
	profilePolicy := digest(0xa1)
	projection := foundationv1.OwnershipTransferAuthorizationSigningProjection{
		Metadata: metadata(1, 7, 0xa0), TransferAuthorizationID: "transfer-agent-01",
		SubjectKind: 2, PreviousEntityID: "agent-old-01", NextEntityID: "agent-new-01",
		PreviousPrincipalIdentity: "spiffe://cph.example/old/agent-01",
		NextPrincipalIdentity:     "spiffe://cph.example/new/agent-01",
		PreviousProviderID:        "provider-old", NextProviderID: "provider-new",
		ExpectedGeneration: 1, NextGeneration: 2,
		PreviousTerminalIdentityPayloadDigestSHA256: digest(0xa3),
		NextPendingIdentityPayloadDigestSHA256:      digest(0xa4),
		OldKeyClosures: []foundationv1.KeyClosureSigningProjection{{KeyID: "old-key-01",
			TerminalKeyLifecyclePayloadDigestSHA256: digest(0xa5)}},
		NewKeyID: "new-key-01",
		EvidenceCommitments: []foundationv1.TransferEvidenceCommitmentSigningProjection{
			{EvidenceKind: foundationv1.TransferEvidenceOldProviderAuthority, CCSERecordDigestSHA256: digest(0xb1)},
			{EvidenceKind: foundationv1.TransferEvidenceNewProviderAuthority, CCSERecordDigestSHA256: digest(0xb2)},
			{EvidenceKind: foundationv1.TransferEvidenceDescendantIdentityClosure, CCSERecordDigestSHA256: digest(0xb3)},
			{EvidenceKind: foundationv1.TransferEvidenceLeaseOfferWorkloadClosure, CCSERecordDigestSHA256: digest(0xb4)},
		},
		EffectiveAtUnixNano: testNow + 10, ExpiresAtUnixNano: testNow + 1_000,
		OldAuthorities: []foundationv1.TransferAuthoritySigningProjection{{Identity: "spiffe://cph.example/old/admin", KeyID: "old-authority-key"}},
		NewAuthorities: []foundationv1.TransferAuthoritySigningProjection{{Identity: "spiffe://cph.example/new/admin", KeyID: "new-authority-key"}},
	}
	projection.Metadata.RecordID = "transfer-agent-01-record"
	projection.Metadata.PolicyDigestsSHA256 = [][32]byte{profilePolicy, sharedAuthorityPolicy}
	profile := OwnershipTransferProfile{ProfileID: "transfer-profile-v1", ProfileVersion: 1,
		PolicyDigest: profilePolicy, RecordIntegrityDigestSHA256: projection.Metadata.IntegrityDigest,
		OldAuthorities: []OwnershipTransferAuthorityRequirement{{Identity: projection.OldAuthorities[0].Identity,
			KeyID: projection.OldAuthorities[0].KeyID, ProviderID: projection.PreviousProviderID,
			OrganizationID: "org-old", Role: "transfer-old",
			AuthorizationPolicyDigestSHA256: sharedAuthorityPolicy}},
		NewAuthorities: []OwnershipTransferAuthorityRequirement{{Identity: projection.NewAuthorities[0].Identity,
			KeyID: projection.NewAuthorities[0].KeyID, ProviderID: projection.NextProviderID,
			OrganizationID: "org-new", Role: "transfer-coordinator",
			AuthorizationPolicyDigestSHA256: sharedAuthorityPolicy, Coordinator: true}},
	}
	return projection, activatedTestTransferProfile(profile)
}

func TestNormalizeTransferProfileBindsExactPoliciesAndIntegrity(t *testing.T) {
	projection, profile := transferProfileFixture()
	payload, err := projection.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	normalized, _, _, err := normalizeOwnershipTransferPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := normalizeTransferProfile(profile, normalized); err != nil {
		t.Fatalf("shared authority policy should deduplicate: %v", err)
	}

	for name, mutate := range map[string]func(*foundationv1.OwnershipTransferAuthorizationSigningProjection, *OwnershipTransferProfile){
		"omit": func(value *foundationv1.OwnershipTransferAuthorizationSigningProjection, _ *OwnershipTransferProfile) {
			value.Metadata.PolicyDigestsSHA256 = value.Metadata.PolicyDigestsSHA256[:1]
		},
		"extra": func(value *foundationv1.OwnershipTransferAuthorizationSigningProjection, _ *OwnershipTransferProfile) {
			value.Metadata.PolicyDigestsSHA256 = append(value.Metadata.PolicyDigestsSHA256, digest(0xfe))
		},
		"mutated": func(value *foundationv1.OwnershipTransferAuthorizationSigningProjection, _ *OwnershipTransferProfile) {
			value.Metadata.PolicyDigestsSHA256[1][0] ^= 1
		},
		"integrity": func(_ *foundationv1.OwnershipTransferAuthorizationSigningProjection, value *OwnershipTransferProfile) {
			value.RecordIntegrityDigestSHA256[0] ^= 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate, candidateProfile := projection, cloneTransferProfile(profile)
			candidate.Metadata.PolicyDigestsSHA256 = cloneDigests(projection.Metadata.PolicyDigestsSHA256)
			mutate(&candidate, &candidateProfile)
			canonical, canonicalErr := candidate.CanonicalBytes()
			if canonicalErr != nil {
				t.Fatal(canonicalErr)
			}
			decoded, _, _, decodeErr := normalizeOwnershipTransferPayload(canonical)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			if _, _, profileErr := normalizeTransferProfile(candidateProfile, decoded); !errors.Is(profileErr, ErrTransferAuthorizationRequired) {
				t.Fatalf("profile mismatch = %v", profileErr)
			}
		})
	}
}

func TestOwnershipTransferMetadataStateVersionIsInitial(t *testing.T) {
	projection, _ := transferProfileFixture()
	projection.Metadata.StateVersion = 2
	payload, err := projection.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := normalizeOwnershipTransferPayload(payload); !errors.Is(err, ErrTransferAuthorizationRequired) {
		t.Fatalf("noninitial transfer metadata accepted: %v", err)
	}
}
