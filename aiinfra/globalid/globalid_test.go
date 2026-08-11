// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package globalid

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

func TestClaimsCanonicalAndGloballyUnnamespaced(t *testing.T) {
	recordOwner := Owner{Domain: OwnerCanonicalRecord, ID: "record-1"}
	identityOwner := Owner{Domain: OwnerIAMIdentity, ID: "identity-1"}
	record, err := Reserve("record-1", recordOwner)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := Reserve("identity-1", identityOwner)
	if err != nil {
		t.Fatal(err)
	}
	first, err := Digest([]Claim{record, identity, identity})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Digest([]Claim{identity, record})
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("claim permutation or identical duplicate changed digest")
	}

	conflict, err := Reserve("identity-1", Owner{Domain: OwnerGovernancePolicyBundle, ID: "policy-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NormalizeClaims([]Claim{identity, conflict}); !errors.Is(err, ErrConflictingClaim) {
		t.Fatalf("cross-domain reuse error = %v", err)
	}
}

func TestAssertAndTransferBindVersionOwnerAndEvidence(t *testing.T) {
	oldOwner := Owner{Domain: OwnerIAMIdentity, ID: "device-binding-1"}
	newOwner := Owner{Domain: OwnerIAMIdentity, ID: "device-binding-2"}
	snapshot := Snapshot{Identifier: "spiffe://example/device/7", Owner: oldOwner, Version: 4}

	assertion, err := Assert(snapshot.Identifier, snapshot, oldOwner)
	if err != nil {
		t.Fatal(err)
	}
	if assertion.ExpectedVersion != 4 || assertion.NextVersion != 4 || assertion.ExpectedOwner != oldOwner {
		t.Fatalf("assertion = %#v", assertion)
	}

	evidence := sha256.Sum256([]byte("signed ownership transfer"))
	transfer, err := Transfer(snapshot.Identifier, snapshot, newOwner, evidence)
	if err != nil {
		t.Fatal(err)
	}
	if transfer.ExpectedVersion != 4 || transfer.NextVersion != 5 || transfer.ExpectedOwner != oldOwner || transfer.Owner != newOwner {
		t.Fatalf("transfer = %#v", transfer)
	}
	if _, err := Transfer(snapshot.Identifier, snapshot, newOwner, [32]byte{}); !errors.Is(err, ErrInvalidClaim) {
		t.Fatalf("zero-evidence transfer error = %v", err)
	}
	if _, err := Transfer(snapshot.Identifier, snapshot, Owner{Domain: OwnerIAMKey, ID: "key-1"}, evidence); !errors.Is(err, ErrInvalidClaim) {
		t.Fatalf("cross-domain transfer error = %v", err)
	}
}

func TestOnlyIAMIdentityOwnershipCanTransfer(t *testing.T) {
	evidence := sha256.Sum256([]byte("transfer evidence"))
	tests := []struct {
		identifier string
		owner      Owner
		next       Owner
	}{
		{IAMKeyIDPrefix + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Owner{Domain: OwnerIAMKey, ID: IAMKeyIDPrefix + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
			Owner{Domain: OwnerIAMKey, ID: IAMKeyIDPrefix + "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}},
		{"record-id", Owner{Domain: OwnerCanonicalRecord, ID: "owner-before"}, Owner{Domain: OwnerCanonicalRecord, ID: "owner-after"}},
		{"policy-id", Owner{Domain: OwnerGovernancePolicyBundle, ID: "owner-before"}, Owner{Domain: OwnerGovernancePolicyBundle, ID: "owner-after"}},
		{JoinedAuditEventIDPrefix + "0123456789abcdef0123456789abcdef",
			Owner{Domain: OwnerGovernanceAuditEvent, ID: JoinedAuditEventIDPrefix + "0123456789abcdef0123456789abcdef"},
			Owner{Domain: OwnerGovernanceAuditEvent, ID: JoinedAuditEventIDPrefix + "abcdef0123456789abcdef0123456789"}},
	}
	for _, test := range tests {
		snapshot := Snapshot{Identifier: test.identifier, Owner: test.owner, Version: 1}
		_, err := Transfer(snapshot.Identifier, snapshot, test.next, evidence)
		if !errors.Is(err, ErrInvalidClaim) {
			t.Fatalf("domain %q transfer error = %v", test.owner.Domain, err)
		}
	}
}

func TestMachineDerivedIdentifierNamespacesCannotBeSquatted(t *testing.T) {
	if IAMKeyIDPrefix != "cph-key-v1:sha256:" || JoinedAuditEventIDPrefix != "cph-audit-v1:" {
		t.Fatalf("durable identifier prefix drift: key=%q audit=%q", IAMKeyIDPrefix, JoinedAuditEventIDPrefix)
	}
	keyID := IAMKeyIDPrefix + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	auditID := JoinedAuditEventIDPrefix + "0123456789abcdef0123456789abcdef"
	for _, test := range []struct {
		name       string
		identifier string
		owner      Owner
		wantError  bool
	}{
		{"key owner", keyID, Owner{Domain: OwnerIAMKey, ID: keyID}, false},
		{"key namespace squat", keyID, Owner{Domain: OwnerIAMIdentity, ID: "identity-1"}, true},
		{"key owner malformed ID", "ordinary-key-id", Owner{Domain: OwnerIAMKey, ID: "ordinary-key-id"}, true},
		{"key suffix too short", IAMKeyIDPrefix + "ab", Owner{Domain: OwnerIAMKey, ID: IAMKeyIDPrefix + "ab"}, true},
		{"key suffix uppercase", IAMKeyIDPrefix + "ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789", Owner{Domain: OwnerIAMKey, ID: IAMKeyIDPrefix + "ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}, true},
		{"audit owner", auditID, Owner{Domain: OwnerGovernanceAuditEvent, ID: auditID}, false},
		{"audit namespace squat", auditID, Owner{Domain: OwnerCanonicalRecord, ID: "record-1"}, true},
		{"audit owner mismatch", auditID, Owner{Domain: OwnerGovernanceAuditEvent, ID: auditID + "-other"}, true},
		{"audit suffix too short", JoinedAuditEventIDPrefix + "ab", Owner{Domain: OwnerGovernanceAuditEvent, ID: JoinedAuditEventIDPrefix + "ab"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := Reserve(test.identifier, test.owner)
			if (err != nil) != test.wantError {
				t.Fatalf("error=%v wantError=%v", err, test.wantError)
			}
		})
	}
}

func TestClaimsRejectUnknownDomainsInvalidTextAndVersionDrift(t *testing.T) {
	cases := []Claim{
		{Identifier: "id", Mode: ReserveNew, Owner: Owner{Domain: "unregistered", ID: "id"}, NextVersion: 1},
		{Identifier: "bad\nidentifier", Mode: ReserveNew, Owner: Owner{Domain: OwnerIAMIdentity, ID: "id"}, NextVersion: 1},
		{Identifier: "e\u0301", Mode: ReserveNew, Owner: Owner{Domain: OwnerIAMIdentity, ID: "id"}, NextVersion: 1},
		{Identifier: "id", Mode: AssertExisting, ExpectedOwner: Owner{Domain: OwnerIAMIdentity, ID: "id"}, Owner: Owner{Domain: OwnerIAMIdentity, ID: "id"}, ExpectedVersion: 2, NextVersion: 3},
	}
	for index, claim := range cases {
		if err := claim.Validate(); !errors.Is(err, ErrInvalidClaim) {
			t.Fatalf("case %d error = %v", index, err)
		}
	}
}

func TestKnownOwnerDomainCatalogIsStableAndDetached(t *testing.T) {
	got := KnownOwnerDomains()
	want := []struct {
		domain  OwnerDomain
		literal string
	}{
		{OwnerIAMIdentity, "cph.aiinfra.iam.identity.v1"},
		{OwnerIAMKey, "cph.aiinfra.iam.key.v1"},
		{OwnerCanonicalRecord, "cph.aiinfra.canonical.record.v1"},
		{OwnerGovernancePolicyBundle, "cph.aiinfra.governance.policy-bundle.v1"},
		{OwnerGovernanceAuditEvent, "cph.aiinfra.governance.audit-event.v1"},
	}
	if len(got) != len(want) {
		t.Fatalf("domains = %v", got)
	}
	for index := range want {
		if string(want[index].domain) != want[index].literal {
			t.Fatalf("constant %d = %q, want durable literal %q", index, want[index].domain, want[index].literal)
		}
		if got[index] != want[index].domain {
			t.Fatalf("domain %d = %q, want %q", index, got[index], want[index].domain)
		}
	}
	got[0] = "mutated"
	if KnownOwnerDomains()[0] != want[0].domain {
		t.Fatal("owner domain catalog aliases caller slice")
	}
}

func TestMaximumClaimCountSupportsV1OwnershipTransfer(t *testing.T) {
	// 330 is the largest current producer shape: 256 future terminal key
	// records, 64 retained evidence assertions and ten transfer/base IDs.
	claims := make([]Claim, 330)
	for index := range claims {
		identifier := fmt.Sprintf("ownership-transfer-id-%03d", index)
		claim, err := Reserve(identifier, Owner{Domain: OwnerIAMIdentity, ID: identifier})
		if err != nil {
			t.Fatal(err)
		}
		claims[index] = claim
	}
	if _, err := CanonicalBytes(claims); err != nil {
		t.Fatalf("330-claim v1 transfer rejected: %v", err)
	}

	overLimit := make([]Claim, MaxClaims+1)
	for index := range overLimit {
		identifier := fmt.Sprintf("over-limit-id-%03d", index)
		claim, err := Reserve(identifier, Owner{Domain: OwnerIAMIdentity, ID: identifier})
		if err != nil {
			t.Fatal(err)
		}
		overLimit[index] = claim
	}
	if _, err := CanonicalBytes(overLimit); !errors.Is(err, ErrInvalidClaim) {
		t.Fatalf("%d-claim input error=%v", len(overLimit), err)
	}
}

func TestClaimDigestGolden(t *testing.T) {
	record, err := Reserve("record-1", Owner{Domain: OwnerCanonicalRecord, ID: "record-1"})
	if err != nil {
		t.Fatal(err)
	}
	identityOwner := Owner{Domain: OwnerIAMIdentity, ID: "identity-1"}
	identitySnapshot := Snapshot{Identifier: "identity-1", Owner: identityOwner, Version: 7}
	identity, err := Assert(identitySnapshot.Identifier, identitySnapshot, identityOwner)
	if err != nil {
		t.Fatal(err)
	}
	transferSnapshot := Snapshot{
		Identifier: "spiffe://example/device/7",
		Owner:      Owner{Domain: OwnerIAMIdentity, ID: "device-binding-1"},
		Version:    4,
	}
	transfer, err := Transfer(
		transferSnapshot.Identifier,
		transferSnapshot,
		Owner{Domain: OwnerIAMIdentity, ID: "device-binding-2"},
		sha256.Sum256([]byte("signed ownership transfer")),
	)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := Digest([]Claim{transfer, record, identity})
	if err != nil {
		t.Fatal(err)
	}
	const want = "09ba00aa0182fffacfad228083520c4e7a5f83a609503503606ee0107bf44f02"
	if got := hex.EncodeToString(digest[:]); got != want {
		t.Fatalf("global ID claim digest drift: got=%s want=%s", got, want)
	}
}

func FuzzClaimCanonicalization(f *testing.F) {
	f.Add("record-1", "record-1", uint8(ReserveNew), uint64(0))
	f.Add("spiffe://example/device/7", "device-binding-1", uint8(AssertExisting), uint64(4))
	f.Fuzz(func(t *testing.T, identifier, ownerID string, rawMode uint8, version uint64) {
		mode := ClaimMode(rawMode%3 + 1)
		owner := Owner{Domain: OwnerIAMIdentity, ID: ownerID}
		claim := Claim{Identifier: identifier, Mode: mode, Owner: owner}
		switch mode {
		case ReserveNew:
			claim.NextVersion = 1
		case AssertExisting:
			claim.ExpectedOwner = owner
			claim.ExpectedVersion = version
			claim.NextVersion = version
		case TransferExisting:
			claim.ExpectedOwner = Owner{Domain: OwnerIAMIdentity, ID: ownerID + "-old"}
			claim.ExpectedVersion = version
			if version != ^uint64(0) {
				claim.NextVersion = version + 1
			}
			claim.TransferEvidenceDigest = sha256.Sum256([]byte("fuzz-evidence"))
		}
		canonical, err := CanonicalBytes([]Claim{claim, claim})
		if err != nil {
			return
		}
		normalized, err := NormalizeClaims([]Claim{claim})
		if err != nil {
			t.Fatal(err)
		}
		again, err := CanonicalBytes(normalized)
		if err != nil {
			t.Fatal(err)
		}
		if string(canonical) != string(again) {
			t.Fatal("canonicalization is not idempotent")
		}
	})
}
