// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package foundationv1

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"testing"

	"github.com/cypherium/cypher/aiinfra/ccse"
)

func TestOwnershipTransferOldKeyClosureBoundary(t *testing.T) {
	value := validAgentOwnershipTransfer()
	value.OldKeyClosures = make([]KeyClosureSigningProjection, 256)
	for index := range value.OldKeyClosures {
		value.OldKeyClosures[index] = KeyClosureSigningProjection{
			KeyID:                                   fmt.Sprintf("old-key-%03d", index),
			TerminalKeyLifecyclePayloadDigestSHA256: digest32(byte(index%255 + 1)),
		}
	}
	if _, err := value.CanonicalBytes(); err != nil {
		t.Fatalf("256 old key closures rejected: %v", err)
	}

	value.OldKeyClosures = append(value.OldKeyClosures, KeyClosureSigningProjection{
		KeyID: "old-key-256", TerminalKeyLifecyclePayloadDigestSHA256: digest32(0xff),
	})
	if _, err := value.CanonicalBytes(); !errors.Is(err, ErrInvalidProjectionValue) {
		t.Fatalf("257 old key closures error = %v", err)
	}
}

func TestOwnershipTransferEvidenceMultiplicityAndCanonicalOrder(t *testing.T) {
	first := validAgentOwnershipTransfer()
	first.EvidenceCommitments = append(first.EvidenceCommitments,
		TransferEvidenceCommitmentSigningProjection{EvidenceKind: TransferEvidenceOldProviderAuthority, CCSERecordDigestSHA256: digest32(0xe1)})
	second := validAgentOwnershipTransfer()
	second.EvidenceCommitments = []TransferEvidenceCommitmentSigningProjection{
		first.EvidenceCommitments[4], first.EvidenceCommitments[3], first.EvidenceCommitments[2],
		first.EvidenceCommitments[1], first.EvidenceCommitments[0],
	}
	firstBytes, err := first.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := second.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("same-kind distinct evidence or input order changed canonical bytes")
	}

	duplicate := validAgentOwnershipTransfer()
	duplicate.EvidenceCommitments = append(duplicate.EvidenceCommitments, duplicate.EvidenceCommitments[0])
	if _, err := duplicate.CanonicalBytes(); !errors.Is(err, ccse.ErrDuplicateSetValue) {
		t.Fatalf("exact (kind,digest) duplicate error = %v", err)
	}
}

func TestOwnershipTransferRequiredEvidenceBySubject(t *testing.T) {
	agent := validAgentOwnershipTransfer()
	if _, err := agent.CanonicalBytes(); err != nil {
		t.Fatalf("valid agent: %v", err)
	}

	host := validAgentOwnershipTransfer()
	host.SubjectKind = 3
	host.NextPrincipalIdentity = host.PreviousPrincipalIdentity
	host.EvidenceCommitments = []TransferEvidenceCommitmentSigningProjection{
		{EvidenceKind: TransferEvidenceOldProviderAuthority, CCSERecordDigestSHA256: digest32(0xd1)},
		{EvidenceKind: TransferEvidenceNewProviderAuthority, CCSERecordDigestSHA256: digest32(0xd2)},
		{EvidenceKind: TransferEvidenceHostSanitationAttestation, CCSERecordDigestSHA256: digest32(0xd3)},
		{EvidenceKind: TransferEvidenceNewAttestationReadiness, CCSERecordDigestSHA256: digest32(0xd4)},
	}
	if _, err := host.CanonicalBytes(); err != nil {
		t.Fatalf("valid host: %v", err)
	}

	device := host
	device.SubjectKind = 4
	device.EvidenceCommitments = []TransferEvidenceCommitmentSigningProjection{
		{EvidenceKind: TransferEvidenceOldProviderAuthority, CCSERecordDigestSHA256: digest32(0xc1)},
		{EvidenceKind: TransferEvidenceNewProviderAuthority, CCSERecordDigestSHA256: digest32(0xc2)},
		{EvidenceKind: TransferEvidenceDeviceSanitationAttestation, CCSERecordDigestSHA256: digest32(0xc3)},
		{EvidenceKind: TransferEvidenceNewAttestationReadiness, CCSERecordDigestSHA256: digest32(0xc4)},
	}
	if _, err := device.CanonicalBytes(); err != nil {
		t.Fatalf("valid device: %v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*OwnershipTransferAuthorizationSigningProjection)
	}{
		{"missing old provider authority", func(p *OwnershipTransferAuthorizationSigningProjection) {
			p.EvidenceCommitments = p.EvidenceCommitments[1:]
		}},
		{"agent missing graph closure", func(p *OwnershipTransferAuthorizationSigningProjection) {
			p.EvidenceCommitments = p.EvidenceCommitments[:3]
		}},
		{"agent irrelevant sanitation", func(p *OwnershipTransferAuthorizationSigningProjection) {
			p.EvidenceCommitments = append(p.EvidenceCommitments, TransferEvidenceCommitmentSigningProjection{EvidenceKind: TransferEvidenceHostSanitationAttestation, CCSERecordDigestSHA256: digest32(0xaa)})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := validAgentOwnershipTransfer()
			test.mutate(&value)
			if _, err := value.CanonicalBytes(); !errors.Is(err, ErrInvalidProjectionValue) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	host.EvidenceCommitments = host.EvidenceCommitments[:3]
	if _, err := host.CanonicalBytes(); !errors.Is(err, ErrInvalidProjectionValue) {
		t.Fatalf("host without readiness error = %v", err)
	}
	device.EvidenceCommitments = device.EvidenceCommitments[:3]
	if _, err := device.CanonicalBytes(); !errors.Is(err, ErrInvalidProjectionValue) {
		t.Fatalf("device without readiness error = %v", err)
	}
}

func TestOwnershipTransferRejectsAmbiguousStateTransitions(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*OwnershipTransferAuthorizationSigningProjection)
	}{
		{"unsupported subject", func(p *OwnershipTransferAuthorizationSigningProjection) { p.SubjectKind = 1 }},
		{"same entity", func(p *OwnershipTransferAuthorizationSigningProjection) { p.NextEntityID = p.PreviousEntityID }},
		{"same provider", func(p *OwnershipTransferAuthorizationSigningProjection) { p.NextProviderID = p.PreviousProviderID }},
		{"agent same principal", func(p *OwnershipTransferAuthorizationSigningProjection) {
			p.NextPrincipalIdentity = p.PreviousPrincipalIdentity
		}},
		{"generation zero", func(p *OwnershipTransferAuthorizationSigningProjection) {
			p.ExpectedGeneration = 0
			p.NextGeneration = 1
		}},
		{"generation overflow", func(p *OwnershipTransferAuthorizationSigningProjection) {
			p.ExpectedGeneration = math.MaxUint64
			p.NextGeneration = 0
		}},
		{"generation skip", func(p *OwnershipTransferAuthorizationSigningProjection) { p.NextGeneration++ }},
		{"same identity digests", func(p *OwnershipTransferAuthorizationSigningProjection) {
			p.NextPendingIdentityPayloadDigestSHA256 = p.PreviousTerminalIdentityPayloadDigestSHA256
		}},
		{"empty half-open interval", func(p *OwnershipTransferAuthorizationSigningProjection) { p.ExpiresAtUnixNano = p.EffectiveAtUnixNano }},
		{"created after effective", func(p *OwnershipTransferAuthorizationSigningProjection) {
			p.EffectiveAtUnixNano = p.Metadata.CreatedAtUnixNano - 1
		}},
		{"new key already closed", func(p *OwnershipTransferAuthorizationSigningProjection) { p.NewKeyID = p.OldKeyClosures[0].KeyID }},
		{"duplicate closure key", func(p *OwnershipTransferAuthorizationSigningProjection) {
			p.OldKeyClosures = append(p.OldKeyClosures, KeyClosureSigningProjection{KeyID: p.OldKeyClosures[0].KeyID, TerminalKeyLifecyclePayloadDigestSHA256: digest32(0xee)})
		}},
		{"authority identity reused across sets", func(p *OwnershipTransferAuthorizationSigningProjection) {
			p.NewAuthorities[0].Identity = p.OldAuthorities[0].Identity
		}},
		{"authority key reused across sets", func(p *OwnershipTransferAuthorizationSigningProjection) {
			p.NewAuthorities[0].KeyID = p.OldAuthorities[0].KeyID
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := validAgentOwnershipTransfer()
			test.mutate(&value)
			if _, err := value.CanonicalBytes(); err == nil {
				t.Fatal("accepted invalid ownership transfer")
			}
		})
	}
}

func validAgentOwnershipTransfer() OwnershipTransferAuthorizationSigningProjection {
	return OwnershipTransferAuthorizationSigningProjection{
		Metadata: validMetadata(), TransferAuthorizationID: "transfer-01", SubjectKind: 2,
		PreviousEntityID: "agent-old", NextEntityID: "agent-new", PreviousPrincipalIdentity: "principal-old",
		NextPrincipalIdentity: "principal-new", PreviousProviderID: "provider-old", NextProviderID: "provider-new",
		ExpectedGeneration: 4, NextGeneration: 5, PreviousTerminalIdentityPayloadDigestSHA256: digest32(0xb1),
		NextPendingIdentityPayloadDigestSHA256: digest32(0xb2),
		OldKeyClosures:                         []KeyClosureSigningProjection{{KeyID: "key-old", TerminalKeyLifecyclePayloadDigestSHA256: digest32(0xb3)}},
		NewKeyID:                               "key-new",
		EvidenceCommitments: []TransferEvidenceCommitmentSigningProjection{
			{EvidenceKind: TransferEvidenceOldProviderAuthority, CCSERecordDigestSHA256: digest32(0xb4)},
			{EvidenceKind: TransferEvidenceNewProviderAuthority, CCSERecordDigestSHA256: digest32(0xb5)},
			{EvidenceKind: TransferEvidenceDescendantIdentityClosure, CCSERecordDigestSHA256: digest32(0xb6)},
			{EvidenceKind: TransferEvidenceLeaseOfferWorkloadClosure, CCSERecordDigestSHA256: digest32(0xb7)},
		},
		EffectiveAtUnixNano: 1_800_000_000_000_000_000, ExpiresAtUnixNano: 1_800_003_600_000_000_000,
		OldAuthorities: []TransferAuthoritySigningProjection{{Identity: "authority-old", KeyID: "authority-key-old"}},
		NewAuthorities: []TransferAuthoritySigningProjection{{Identity: "authority-new", KeyID: "authority-key-new"}},
	}
}
