// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"io"
	"sort"
)

const governanceSemanticCatalogSignatureDomain = "CPH-AIIE-GOVERNANCE-SEMANTIC-CATALOG-V1\x00"

// GovernanceSemanticCatalogTrust is the deployment root used to verify one
// immutable detached-signed catalog artifact. Key bytes are copied by the
// constructor and are never returned.
type GovernanceSemanticCatalogTrust struct {
	IssuerIdentity string
	KeyID          string
	Environment    string
	ChainID        [sha256.Size]byte
	GenesisHash    [sha256.Size]byte
	PublicKey      []byte
}

type signedGovernanceAssignmentWire struct {
	KeyID                                 string            `json:"key_id"`
	ValidFromUnixNano                     int64             `json:"valid_from_unix_nano"`
	ValidUntilUnixNano                    int64             `json:"valid_until_unix_nano"`
	OrganizationIdentity                  string            `json:"organization_identity"`
	Roles                                 []string          `json:"roles"`
	AuthorizationSnapshotDigestSHA256     [sha256.Size]byte `json:"authorization_snapshot_digest_sha256"`
	GovernanceProfileDigestSHA256         [sha256.Size]byte `json:"governance_profile_digest_sha256"`
	ProfileActivationVersion              uint64            `json:"profile_activation_version"`
	ProfileActivationSnapshotDigestSHA256 [sha256.Size]byte `json:"profile_activation_snapshot_digest_sha256"`
}

type signedGovernanceDocumentWire struct {
	DigestSHA256 [sha256.Size]byte `json:"digest_sha256"`
	MediaType    string            `json:"media_type"`
}

type signedGovernanceCatalogWire struct {
	Version            uint32                           `json:"version"`
	IssuerIdentity     string                           `json:"issuer_identity"`
	KeyID              string                           `json:"key_id"`
	Environment        string                           `json:"environment"`
	ChainID            [sha256.Size]byte                `json:"chain_id"`
	GenesisHash        [sha256.Size]byte                `json:"genesis_hash"`
	ValidFromUnixNano  int64                            `json:"valid_from_unix_nano"`
	ValidUntilUnixNano int64                            `json:"valid_until_unix_nano"`
	Assignments        []signedGovernanceAssignmentWire `json:"assignments"`
	Documents          []signedGovernanceDocumentWire   `json:"documents"`
}

// SignedGovernanceSemanticCatalog is a concrete immutable root-trust adapter
// for the two facts absent from frozen PostgreSQL v1 rows: key role/org
// assignments and document media types. The artifact is strict canonical JSON
// authenticated by a detached Ed25519 signature.
type SignedGovernanceSemanticCatalog struct {
	wire       signedGovernanceCatalogWire
	digest     [sha256.Size]byte
	verifiedAt int64
}

func NewSignedGovernanceSemanticCatalog(canonical, signature []byte,
	trust GovernanceSemanticCatalogTrust, verifiedAtUnixNano int64) (*SignedGovernanceSemanticCatalog, error) {
	if len(canonical) == 0 || len(canonical) > 16<<20 || len(signature) != ed25519.SignatureSize ||
		len(trust.PublicKey) != ed25519.PublicKeySize || trust.IssuerIdentity == "" ||
		trust.KeyID == "" || trust.Environment == "" || trust.ChainID == ([sha256.Size]byte{}) ||
		trust.GenesisHash == ([sha256.Size]byte{}) || verifiedAtUnixNano < 0 {
		return nil, ErrCanonicalInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	var wire signedGovernanceCatalogWire
	if decoder.Decode(&wire) != nil {
		return nil, ErrCanonicalInvalid
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, ErrCanonicalInvalid
	}
	reencoded, err := json.Marshal(wire)
	digest := sha256.Sum256(append([]byte(governanceSemanticCatalogSignatureDomain), canonical...))
	if err != nil || !bytes.Equal(reencoded, canonical) ||
		!ed25519.Verify(ed25519.PublicKey(trust.PublicKey), digest[:], signature) ||
		wire.Version != 1 || wire.IssuerIdentity != trust.IssuerIdentity || wire.KeyID != trust.KeyID ||
		wire.Environment != trust.Environment || wire.ChainID != trust.ChainID ||
		wire.GenesisHash != trust.GenesisHash || wire.ValidFromUnixNano < 0 ||
		wire.ValidUntilUnixNano <= wire.ValidFromUnixNano || verifiedAtUnixNano < wire.ValidFromUnixNano ||
		verifiedAtUnixNano >= wire.ValidUntilUnixNano || len(wire.Assignments) == 0 ||
		len(wire.Assignments) > 4096 || len(wire.Documents) > 4096 {
		return nil, ErrCanonicalInvalid
	}
	for index := range wire.Assignments {
		value := &wire.Assignments[index]
		if value.KeyID == "" || value.OrganizationIdentity == "" || len(value.Roles) == 0 ||
			len(value.Roles) > 64 || value.ValidFromUnixNano < wire.ValidFromUnixNano ||
			value.ValidUntilUnixNano <= value.ValidFromUnixNano ||
			value.ValidUntilUnixNano > wire.ValidUntilUnixNano ||
			value.AuthorizationSnapshotDigestSHA256 == ([sha256.Size]byte{}) ||
			value.GovernanceProfileDigestSHA256 == ([sha256.Size]byte{}) ||
			value.ProfileActivationVersion == 0 ||
			value.ProfileActivationSnapshotDigestSHA256 == ([sha256.Size]byte{}) ||
			!sortedUniqueNonemptyStrings(value.Roles) {
			return nil, ErrCanonicalInvalid
		}
		if index > 0 {
			previous := wire.Assignments[index-1]
			if previous.KeyID > value.KeyID || (previous.KeyID == value.KeyID &&
				(previous.ValidFromUnixNano >= value.ValidFromUnixNano ||
					previous.ValidUntilUnixNano > value.ValidFromUnixNano)) {
				return nil, ErrCanonicalInvalid
			}
		}
	}
	for index := range wire.Documents {
		value := wire.Documents[index]
		if value.DigestSHA256 == ([sha256.Size]byte{}) || value.MediaType == "" || len(value.MediaType) > 255 ||
			(index > 0 && bytes.Compare(wire.Documents[index-1].DigestSHA256[:], value.DigestSHA256[:]) >= 0) {
			return nil, ErrCanonicalInvalid
		}
	}
	return &SignedGovernanceSemanticCatalog{wire: wire, digest: digest,
		verifiedAt: verifiedAtUnixNano}, nil
}

func sortedUniqueNonemptyStrings(values []string) bool {
	if !sort.StringsAreSorted(values) {
		return false
	}
	for index, value := range values {
		if value == "" || len(value) > 255 || (index > 0 && values[index-1] == value) {
			return false
		}
	}
	return true
}

func (catalog *SignedGovernanceSemanticCatalog) ArtifactDigestSHA256() [sha256.Size]byte {
	if catalog == nil {
		return [sha256.Size]byte{}
	}
	return catalog.digest
}

func (catalog *SignedGovernanceSemanticCatalog) ResolveGovernanceAuthorization(_ context.Context,
	keyID string) (GovernanceAuthorizationAssignment, bool, error) {
	if catalog == nil {
		return GovernanceAuthorizationAssignment{}, false, ErrCanonicalInvalid
	}
	return catalog.ResolveGovernanceAuthorizationAt(context.Background(), keyID, catalog.verifiedAt)
}

func (catalog *SignedGovernanceSemanticCatalog) ResolveGovernanceAuthorizationAt(_ context.Context,
	keyID string, at int64) (GovernanceAuthorizationAssignment, bool, error) {
	if catalog == nil || keyID == "" || at < catalog.wire.ValidFromUnixNano || at >= catalog.wire.ValidUntilUnixNano {
		return GovernanceAuthorizationAssignment{}, false, nil
	}
	var selected *signedGovernanceAssignmentWire
	for index := range catalog.wire.Assignments {
		value := &catalog.wire.Assignments[index]
		if value.KeyID == keyID && at >= value.ValidFromUnixNano && at < value.ValidUntilUnixNano {
			if selected != nil {
				return GovernanceAuthorizationAssignment{}, false, ErrCanonicalStateCorrupt
			}
			selected = value
		}
	}
	if selected == nil {
		return GovernanceAuthorizationAssignment{}, false, nil
	}
	return GovernanceAuthorizationAssignment{KeyID: selected.KeyID,
		OrganizationIdentity: selected.OrganizationIdentity, Roles: append([]string(nil), selected.Roles...),
		AuthorizationSnapshotDigestSHA256:     selected.AuthorizationSnapshotDigestSHA256,
		GovernanceProfileDigestSHA256:         selected.GovernanceProfileDigestSHA256,
		ProfileActivationVersion:              selected.ProfileActivationVersion,
		ProfileActivationSnapshotDigestSHA256: selected.ProfileActivationSnapshotDigestSHA256}, true, nil
}

func (catalog *SignedGovernanceSemanticCatalog) ResolveGovernanceDocumentMediaType(_ context.Context,
	digest [sha256.Size]byte) (string, bool, error) {
	return catalog.ResolveGovernanceDocumentMediaTypeAt(context.Background(), digest, catalog.verifiedAt)
}

func (catalog *SignedGovernanceSemanticCatalog) ResolveGovernanceDocumentMediaTypeAt(_ context.Context,
	digest [sha256.Size]byte, at int64) (string, bool, error) {
	if catalog == nil || digest == ([sha256.Size]byte{}) ||
		at < catalog.wire.ValidFromUnixNano || at >= catalog.wire.ValidUntilUnixNano {
		return "", false, nil
	}
	index := sort.Search(len(catalog.wire.Documents), func(index int) bool {
		return bytes.Compare(catalog.wire.Documents[index].DigestSHA256[:], digest[:]) >= 0
	})
	if index == len(catalog.wire.Documents) || catalog.wire.Documents[index].DigestSHA256 != digest {
		return "", false, nil
	}
	return catalog.wire.Documents[index].MediaType, true, nil
}

var (
	_ GovernanceAuthorizationCatalog = (*SignedGovernanceSemanticCatalog)(nil)
	_ GovernanceDocumentMediaCatalog = (*SignedGovernanceSemanticCatalog)(nil)
)
