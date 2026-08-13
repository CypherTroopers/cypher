// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
)

func semanticCatalogTestDigest(value byte) (result [sha256.Size]byte) {
	for index := range result {
		result[index] = value
	}
	return result
}

func TestSignedGovernanceSemanticCatalogVerifiesAndResolvesExactArtifact(t *testing.T) {
	seed := semanticCatalogTestDigest(0x31)
	private := ed25519.NewKeyFromSeed(seed[:])
	public := private.Public().(ed25519.PublicKey)
	chain, genesis := semanticCatalogTestDigest(0x41), semanticCatalogTestDigest(0x42)
	document := semanticCatalogTestDigest(0x61)
	wire := signedGovernanceCatalogWire{Version: 1, IssuerIdentity: "spiffe://cph.test/catalog",
		KeyID: "catalog-key-1", Environment: "test", ChainID: chain, GenesisHash: genesis,
		ValidFromUnixNano: 100, ValidUntilUnixNano: 500,
		Assignments: []signedGovernanceAssignmentWire{{KeyID: "key-a", ValidFromUnixNano: 100,
			ValidUntilUnixNano: 500, OrganizationIdentity: "spiffe://cph.test/org/a",
			Roles:                                 []string{"governance.proposer", "governance.reviewer"},
			AuthorizationSnapshotDigestSHA256:     semanticCatalogTestDigest(0x51),
			GovernanceProfileDigestSHA256:         semanticCatalogTestDigest(0x52),
			ProfileActivationVersion:              3,
			ProfileActivationSnapshotDigestSHA256: semanticCatalogTestDigest(0x53)}},
		Documents: []signedGovernanceDocumentWire{{DigestSHA256: document, MediaType: "application/json"}}}
	canonical, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(append([]byte(governanceSemanticCatalogSignatureDomain), canonical...))
	signature := ed25519.Sign(private, digest[:])
	trust := GovernanceSemanticCatalogTrust{IssuerIdentity: wire.IssuerIdentity, KeyID: wire.KeyID,
		Environment: wire.Environment, ChainID: chain, GenesisHash: genesis,
		PublicKey: append([]byte(nil), public...)}
	catalog, err := NewSignedGovernanceSemanticCatalog(canonical, signature, trust, 200)
	if err != nil {
		t.Fatal(err)
	}
	assignment, found, err := catalog.ResolveGovernanceAuthorizationAt(context.Background(), "key-a", 250)
	if err != nil || !found || assignment.KeyID != "key-a" ||
		assignment.AuthorizationSnapshotDigestSHA256 != wire.Assignments[0].AuthorizationSnapshotDigestSHA256 {
		t.Fatalf("assignment=%+v found=%t err=%v", assignment, found, err)
	}
	assignment.Roles[0] = "mutated"
	again, _, _ := catalog.ResolveGovernanceAuthorizationAt(context.Background(), "key-a", 250)
	if again.Roles[0] == "mutated" {
		t.Fatal("catalog returned aliased roles")
	}
	media, found, err := catalog.ResolveGovernanceDocumentMediaTypeAt(context.Background(), document, 250)
	if err != nil || !found || media != "application/json" {
		t.Fatalf("media=%q found=%t err=%v", media, found, err)
	}
	if _, found, _ := catalog.ResolveGovernanceAuthorizationAt(context.Background(), "key-a", 500); found {
		t.Fatal("expired catalog assignment resolved")
	}

	tampered := append([]byte(nil), canonical...)
	tampered[len(tampered)-2] ^= 1
	if _, err := NewSignedGovernanceSemanticCatalog(tampered, signature, trust, 200); !errors.Is(err, ErrCanonicalInvalid) {
		t.Fatalf("tampered artifact accepted: %v", err)
	}
	wrongTrust := trust
	wrongTrust.Environment = "production"
	if _, err := NewSignedGovernanceSemanticCatalog(canonical, signature, wrongTrust, 200); !errors.Is(err, ErrCanonicalInvalid) {
		t.Fatalf("wrong environment trust accepted: %v", err)
	}
}
