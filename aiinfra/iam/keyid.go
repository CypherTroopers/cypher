// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/cypherium/cypher/aiinfra/ccse"
)

// CanonicalPublicKey validates and detaches a production public key. WS0.2a
// promotes only raw 32-byte Ed25519 keys; registered future identifiers remain
// fail-closed until a separately reviewed canonicalization adapter exists.
func CanonicalPublicKey(algorithm ccse.SignatureAlgorithmID, publicKey []byte) ([]byte, error) {
	if algorithm != ccse.SignatureAlgorithmEd25519 {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedAlgorithm, algorithm)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: Ed25519 public key length %d", ErrInvalidInput, len(publicKey))
	}
	return append([]byte(nil), publicKey...), nil
}

// DeriveKeyID returns the globally content-addressed key identifier:
//
//	SHA256("CPH-AIIE-KEY-ID-V1\0" || uint32BE(algorithm) ||
//	       uint32BE(len(canonical_public_key)) || canonical_public_key)
//
// rendered as cph-key-v1:sha256:<lower-case 64 hex digits>. Subject identity
// is deliberately excluded and is bound exactly once by KeyMaterialSnapshot.
func DeriveKeyID(algorithm ccse.SignatureAlgorithmID, publicKey []byte) (string, error) {
	canonical, err := CanonicalPublicKey(algorithm, publicKey)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(KeyIDDomain))
	var word [4]byte
	binary.BigEndian.PutUint32(word[:], uint32(algorithm))
	_, _ = hash.Write(word[:])
	binary.BigEndian.PutUint32(word[:], uint32(len(canonical)))
	_, _ = hash.Write(word[:])
	_, _ = hash.Write(canonical)
	return KeyIDPrefix + hex.EncodeToString(hash.Sum(nil)), nil
}

// ValidateKeyID enforces the exact lowercase display form and content binding.
func ValidateKeyID(keyID string, algorithm ccse.SignatureAlgorithmID, publicKey []byte) error {
	if len(keyID) != len(KeyIDPrefix)+sha256.Size*2 || !strings.HasPrefix(keyID, KeyIDPrefix) {
		return ErrKeyIDMismatch
	}
	hexPart := strings.TrimPrefix(keyID, KeyIDPrefix)
	if strings.ToLower(hexPart) != hexPart {
		return ErrKeyIDMismatch
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		return ErrKeyIDMismatch
	}
	expected, err := DeriveKeyID(algorithm, publicKey)
	if err != nil {
		return err
	}
	if keyID != expected {
		return ErrKeyIDMismatch
	}
	return nil
}

// ProofOfPossessionDigest constructs the digest signed by the registering key:
//
//	SHA256("CPH-AIIE-KEY-POP-V1\0" ||
//	       len32(key_id) || key_id ||
//	       len32(subject_identity) || subject_identity ||
//	       uint32BE(subject_kind) ||
//	       uint32BE(target_entity_kind) || uint32BE(target_principal_kind) ||
//	       len32(target_entity_id) || target_entity_id ||
//	       len32(32) || transfer_evidence_digest ||
//	       len32(enrollment_domain_id) || enrollment_domain_id ||
//	       len32(environment) || environment ||
//	       len32(32) || genesis_hash ||
//	       len32(32) || challenge || int64BE(challenge_expires_at_unix_nano))
//
// The literal domain tag is unframed; all variable data is CCSE framed.
func ProofOfPossessionDigest(keyID, subjectIdentity string, subjectKind uint32, targetIdentity EntityRef,
	transferEvidenceDigest [32]byte, domain EnrollmentDomain, challenge [32]byte,
	expiresAtUnixNano int64) ([32]byte, error) {
	var zero [32]byte
	encoded, err := proofOfPossessionPreimage(keyID, subjectIdentity, subjectKind, targetIdentity,
		transferEvidenceDigest, domain, challenge, expiresAtUnixNano)
	if err != nil {
		return zero, err
	}
	return domainDigest(ProofDomain, encoded), nil
}

func proofOfPossessionPreimage(keyID, subjectIdentity string, subjectKind uint32,
	targetIdentity EntityRef, transferEvidenceDigest [32]byte, domain EnrollmentDomain,
	challenge [32]byte, expiresAtUnixNano int64) ([]byte, error) {
	var zero [32]byte
	if keyID == "" || subjectIdentity == "" || subjectKind < 1 || subjectKind > 8 ||
		challenge == zero || expiresAtUnixNano <= 0 {
		return nil, ErrInvalidInput
	}
	if err := validateTargetIdentity(targetIdentity, subjectKind); err != nil {
		return nil, err
	}
	if err := validateEnrollmentDomain(domain); err != nil {
		return nil, err
	}
	encoded, err := ccse.Marshal(2048, func(out *ccse.Encoder) {
		out.String(keyID)
		out.String(subjectIdentity)
		out.Uint32(subjectKind)
		out.Uint32(uint32(targetIdentity.Kind))
		out.Uint32(targetIdentity.PrincipalKind)
		out.String(targetIdentity.ID)
		out.FixedBytes(transferEvidenceDigest[:], 32)
		out.String(domain.EnrollmentDomainID)
		out.String(domain.Environment)
		out.FixedBytes(domain.GenesisHash[:], len(domain.GenesisHash))
		out.FixedBytes(challenge[:], len(challenge))
		out.Int64(expiresAtUnixNano)
	})
	if err != nil {
		return nil, fmt.Errorf("%w: proof projection: %v", ErrInvalidInput, err)
	}
	return encoded, nil
}

func validateTargetIdentity(target EntityRef, subjectKind uint32) error {
	if target.Kind != EntityIdentity || target.PrincipalKind != subjectKind || target.ID == "" {
		return ErrInvalidInput
	}
	if _, err := ccse.Marshal(2048, func(out *ccse.Encoder) {
		out.Uint32(uint32(target.Kind))
		out.Uint32(target.PrincipalKind)
		out.String(target.ID)
	}); err != nil {
		return fmt.Errorf("%w: target identity: %v", ErrInvalidInput, err)
	}
	return nil
}

func validateEnrollmentDomain(domain EnrollmentDomain) error {
	if domain.EnrollmentDomainID == "" || domain.Environment == "" || domain.GenesisHash == ([32]byte{}) {
		return ErrInvalidInput
	}
	if _, err := ccse.Marshal(1280, func(out *ccse.Encoder) {
		out.String(domain.EnrollmentDomainID)
		out.String(domain.Environment)
		out.FixedBytes(domain.GenesisHash[:], 32)
	}); err != nil {
		return fmt.Errorf("%w: enrollment domain: %v", ErrInvalidInput, err)
	}
	return nil
}

// VerifyProofOfPossession validates the exact 64-byte Ed25519 signature over
// ProofOfPossessionDigest. Challenge freshness and one-use admission are
// authoritative View checks performed by PlanKeyMaterial.
func VerifyProofOfPossession(algorithm ccse.SignatureAlgorithmID, publicKey []byte, keyID, subjectIdentity string,
	subjectKind uint32, targetIdentity EntityRef, transferEvidenceDigest [32]byte,
	domain EnrollmentDomain, challenge [32]byte,
	expiresAtUnixNano int64, signature []byte) ([32]byte, error) {
	var zero [32]byte
	canonical, err := CanonicalPublicKey(algorithm, publicKey)
	if err != nil {
		return zero, err
	}
	if err := ValidateKeyID(keyID, algorithm, canonical); err != nil {
		return zero, err
	}
	if len(signature) != ed25519.SignatureSize {
		return zero, ErrInvalidProofOfPossession
	}
	digest, err := ProofOfPossessionDigest(keyID, subjectIdentity, subjectKind, targetIdentity,
		transferEvidenceDigest, domain, challenge, expiresAtUnixNano)
	if err != nil {
		return zero, err
	}
	if !ed25519.Verify(ed25519.PublicKey(canonical), digest[:], signature) {
		return zero, ErrInvalidProofOfPossession
	}
	return digest, nil
}
