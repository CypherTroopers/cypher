// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package ccse

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

const ccseV1Preamble = "CPH-AIIE-CCSE-V1\x00"

// Limits bound work before a receiver hashes or verifies untrusted data.
type Limits struct {
	MaxDomainBytes    int
	MaxEnvelopeBytes  int
	MaxPayloadBytes   int
	MaxSignatureBytes int
}

var ErrInvalidLimits = errors.New("ccse: invalid verification limits")

// DefaultLimits returns conservative control-plane bounds. A new value is
// returned on every call so one component cannot mutate process-wide policy.
// Individual message types SHOULD reduce MaxPayloadBytes further.
func DefaultLimits() Limits {
	return Limits{
		MaxDomainBytes:    64 << 10,
		MaxEnvelopeBytes:  256 << 10,
		MaxPayloadBytes:   1 << 20,
		MaxSignatureBytes: 128,
	}
}

// Record contains the transport-independent fields needed to reconstruct a
// CCSE-v1 authorization. Payload is a schema-specific canonical projection,
// never the Protobuf wire bytes.
type Record struct {
	MessageTypeID uint32
	SchemaVersion Version
	Domain        Domain
	Envelope      Envelope
	Payload       []byte
	Signature     []byte
}

// NewRecord constructs an unsigned record and binds the payload digest into the
// envelope. Payload is copied so subsequent caller mutation cannot change the
// authorization bytes.
func NewRecord(messageTypeID uint32, schemaVersion Version, domain Domain, envelope Envelope, canonicalPayload []byte) (*Record, error) {
	envelope.PayloadDigest = sha256.Sum256(canonicalPayload)
	record := &Record{
		MessageTypeID: messageTypeID,
		SchemaVersion: schemaVersion,
		Domain:        cloneDomain(domain),
		Envelope:      cloneEnvelope(envelope),
		Payload:       append([]byte(nil), canonicalPayload...),
	}
	canonicalizeRecordSets(record)
	if _, err := record.Preimage(DefaultLimits()); err != nil {
		return nil, err
	}
	return record, nil
}

// Preimage returns the exact CCSE-v1 byte string specified by Master
// Architecture §10.1.
func (r *Record) Preimage(limits Limits) ([]byte, error) {
	if r == nil || r.MessageTypeID == 0 || r.SchemaVersion.Major == 0 {
		return nil, ErrInvalidRecord
	}
	var err error
	limits, err = normalizeLimits(limits)
	if err != nil {
		return nil, err
	}
	if len(r.Payload) > limits.MaxPayloadBytes {
		return nil, ErrProjectionTooLarge
	}
	if r.SchemaVersion != r.Domain.SchemaVersion || r.SchemaVersion != r.Envelope.SchemaVersion {
		return nil, ErrDomainEnvelopeMismatch
	}
	if err := validateBinding(r.Domain, r.Envelope, r.Payload); err != nil {
		return nil, err
	}
	domainBytes, err := r.Domain.canonicalBytes(limits.MaxDomainBytes)
	if err != nil {
		return nil, err
	}
	envelopeBytes, err := r.Envelope.canonicalBytes(limits.MaxEnvelopeBytes)
	if err != nil {
		return nil, err
	}
	if uint64(len(domainBytes)) > math.MaxUint32 {
		return nil, ErrProjectionTooLarge
	}
	total := uint64(len(ccseV1Preamble)) + 12 + 4 + uint64(len(domainBytes)) + 8 + uint64(len(envelopeBytes)) + 8 + uint64(len(r.Payload))
	if total > uint64(math.MaxInt) {
		return nil, ErrProjectionTooLarge
	}
	out := make([]byte, 0, int(total))
	out = append(out, ccseV1Preamble...)
	out = binary.BigEndian.AppendUint32(out, r.MessageTypeID)
	out = binary.BigEndian.AppendUint32(out, r.SchemaVersion.Major)
	out = binary.BigEndian.AppendUint32(out, r.SchemaVersion.Minor)
	out = binary.BigEndian.AppendUint32(out, uint32(len(domainBytes)))
	out = append(out, domainBytes...)
	out = binary.BigEndian.AppendUint64(out, uint64(len(envelopeBytes)))
	out = append(out, envelopeBytes...)
	out = binary.BigEndian.AppendUint64(out, uint64(len(r.Payload)))
	out = append(out, r.Payload...)
	return out, nil
}

// Digest hashes the complete canonical preimage with SHA-256.
func (r *Record) Digest(limits Limits) ([DigestSize]byte, error) {
	preimage, err := r.Preimage(limits)
	if err != nil {
		return [DigestSize]byte{}, err
	}
	return sha256.Sum256(preimage), nil
}

// SignEd25519 signs SHA-256(CCSE preimage). The key identifier and algorithm
// identifier are already bound inside the signed domain and envelope.
func (r *Record) SignEd25519(privateKey ed25519.PrivateKey, limits Limits) error {
	if r == nil {
		return ErrInvalidRecord
	}
	if r.Domain.SignatureAlgorithm != SignatureAlgorithmEd25519 || r.Envelope.SignatureAlgorithm != SignatureAlgorithmEd25519 {
		return ErrUnsupportedAlgorithm
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("%w: invalid Ed25519 private key size", ErrInvalidRecord)
	}
	canonicalizeRecordSets(r)
	digest, err := r.Digest(limits)
	if err != nil {
		return err
	}
	r.Signature = ed25519.Sign(privateKey, digest[:])
	return nil
}

func verifyEd25519(record *Record, publicKey ed25519.PublicKey, limits Limits) error {
	if len(publicKey) != ed25519.PublicKeySize || len(record.Signature) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}
	digest, err := record.Digest(limits)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, digest[:], record.Signature) {
		return ErrInvalidSignature
	}
	return nil
}

func normalizeLimits(limits Limits) (Limits, error) {
	if limits.MaxDomainBytes < 0 || limits.MaxEnvelopeBytes < 0 || limits.MaxPayloadBytes < 0 || limits.MaxSignatureBytes < 0 {
		return Limits{}, ErrInvalidLimits
	}
	defaults := DefaultLimits()
	if limits.MaxDomainBytes == 0 {
		limits.MaxDomainBytes = defaults.MaxDomainBytes
	}
	if limits.MaxEnvelopeBytes == 0 {
		limits.MaxEnvelopeBytes = defaults.MaxEnvelopeBytes
	}
	if limits.MaxPayloadBytes == 0 {
		limits.MaxPayloadBytes = defaults.MaxPayloadBytes
	}
	if limits.MaxSignatureBytes == 0 {
		limits.MaxSignatureBytes = defaults.MaxSignatureBytes
	}
	return limits, nil
}

func validateSignatureSize(record *Record, limits Limits) error {
	if record == nil {
		return ErrInvalidRecord
	}
	var err error
	limits, err = normalizeLimits(limits)
	if err != nil {
		return err
	}
	if len(record.Signature) == 0 {
		return errors.Join(ErrInvalidSignature, errors.New("missing signature"))
	}
	if len(record.Signature) > limits.MaxSignatureBytes {
		return ErrProjectionTooLarge
	}
	return nil
}

// preflightUntrustedRecord bounds every variable-size field before Verify
// clones, sorts, normalizes or hashes attacker-controlled input.
func preflightUntrustedRecord(record *Record, limits Limits) error {
	if record == nil {
		return ErrInvalidRecord
	}
	var err error
	limits, err = normalizeLimits(limits)
	if err != nil {
		return err
	}
	if err := validateSignatureSize(record, limits); err != nil {
		return err
	}
	if len(record.Payload) > limits.MaxPayloadBytes || len(record.Domain.Audience) > maxAudience || len(record.Envelope.Extensions) > maxExtensions {
		return ErrProjectionTooLarge
	}
	domainSize := uint64(0)
	add := func(size uint64) bool {
		if size > uint64(limits.MaxDomainBytes) || domainSize > uint64(limits.MaxDomainBytes)-size {
			return false
		}
		domainSize += size
		return true
	}
	addString := func(value string) bool { return add(4 + uint64(len(value))) }
	if !addString(record.Domain.Purpose) || !addString(record.Domain.SenderIdentity) || !add(4) {
		return ErrProjectionTooLarge
	}
	for _, audience := range record.Domain.Audience {
		if !add(4) || !addString(audience) {
			return ErrProjectionTooLarge
		}
	}
	if !add(1) || !addStringIfPresent(record.Domain.TenantOrganization.Present, record.Domain.TenantOrganization.Value, addString) ||
		!add(1) || !addStringIfPresent(record.Domain.ProviderOrganization.Present, record.Domain.ProviderOrganization.Value, addString) ||
		!add(36+36) || !addString(record.Domain.Environment) || !add(8+8+4) || !addString(record.Domain.SignatureKeyID) ||
		!add(8+8+4+8) || !addString(record.Domain.ReplayDomainID) {
		return ErrProjectionTooLarge
	}

	envelopeSize := uint64(16 + 20 + 20 + 1 + 36 + 16 + 4 + 8 + 36 + 4 + 4)
	if record.Envelope.CausationID.Present {
		envelopeSize += 20
	}
	addEnvelope := func(size uint64) bool {
		if size > uint64(limits.MaxEnvelopeBytes) || envelopeSize > uint64(limits.MaxEnvelopeBytes)-size {
			return false
		}
		envelopeSize += size
		return true
	}
	if !addEnvelope(4+uint64(len(record.Envelope.SenderIdentity))) ||
		!addEnvelope(4+uint64(len(record.Envelope.Environment))) ||
		!addEnvelope(4+uint64(len(record.Envelope.SignatureKeyID))) {
		return ErrProjectionTooLarge
	}
	for _, extension := range record.Envelope.Extensions {
		// outer len32 + id + critical + value len32 + value
		if !addEnvelope(4 + 4 + 1 + 4 + uint64(len(extension.Value))) {
			return ErrProjectionTooLarge
		}
	}
	return nil
}

func addStringIfPresent(present bool, value string, add func(string) bool) bool {
	if !present {
		// Hidden values are rejected canonically later, but they must still be
		// bounded before the snapshot copy.
		return len(value) == 0 || add(value)
	}
	return add(value)
}
