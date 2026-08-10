// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package ccse

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
)

const (
	DigestSize    = sha256.Size
	MessageIDSize = 16
	maxAudience   = 64
	maxExtensions = 64
)

// SignatureAlgorithmID is committed inside both the domain and envelope.
type SignatureAlgorithmID uint32

const (
	SignatureAlgorithmUnspecified SignatureAlgorithmID = 0
	SignatureAlgorithmEd25519     SignatureAlgorithmID = 1
	SignatureAlgorithmP256SHA256  SignatureAlgorithmID = 2
	SignatureAlgorithmEIP712      SignatureAlgorithmID = 3
)

// CounterKind distinguishes a per-replay-domain sequence from an optimistic
// concurrency generation. A signed operation cannot ambiguously use both.
type CounterKind uint32

const (
	CounterUnspecified        CounterKind = 0
	CounterSequence           CounterKind = 1
	CounterExpectedGeneration CounterKind = 2
)

// Version is a two-component protocol or schema version.
type Version struct {
	Major uint32
	Minor uint32
}

// OptionalString preserves the distinction between an absent field and a
// present empty string.
type OptionalString struct {
	Present bool
	Value   string
}

// OptionalMessageID preserves the distinction between no causation and a
// present nonzero identifier.
type OptionalMessageID struct {
	Present bool
	Value   [MessageIDSize]byte
}

// Extension is the signed escape hatch for explicitly registered additive
// fields. CCSE-v1 rejects every signed extension absent from the exact schema
// registry, regardless of sender-selected criticality. Unknown transport fields
// may be ignored only outside the signing projection under registry policy.
type Extension struct {
	ID       uint32
	Critical bool
	Value    []byte
}

// Domain binds an authorization to its purpose, identities, deployment,
// protocol, key, validity window, and replay scope. Audience is a declared set.
// ChainID is the canonical unsigned 256-bit big-endian chain identifier.
type Domain struct {
	Purpose              string
	SenderIdentity       string
	Audience             []string
	TenantOrganization   OptionalString
	ProviderOrganization OptionalString
	ChainID              [32]byte
	GenesisHash          [DigestSize]byte
	Environment          string
	ProtocolVersion      Version
	SchemaVersion        Version
	SignatureAlgorithm   SignatureAlgorithmID
	SignatureKeyID       string
	IssuedAtUnixNano     int64
	ExpiresAtUnixNano    int64
	CounterKind          CounterKind
	Counter              uint64
	ReplayDomainID       string
}

// Envelope is the transport-independent state-changing operation envelope.
// PayloadDigest is SHA-256 over the canonical payload projection.
type Envelope struct {
	ProtocolVersion    Version
	SchemaVersion      Version
	MessageID          [MessageIDSize]byte
	CorrelationID      [MessageIDSize]byte
	CausationID        OptionalMessageID
	SenderIdentity     string
	ChainID            [32]byte
	Environment        string
	IssuedAtUnixNano   int64
	ExpiresAtUnixNano  int64
	CounterKind        CounterKind
	Counter            uint64
	PayloadDigest      [DigestSize]byte
	SignatureAlgorithm SignatureAlgorithmID
	SignatureKeyID     string
	Extensions         []Extension
}

var (
	ErrInvalidRecord              = errors.New("ccse: invalid signed record")
	ErrDomainEnvelopeMismatch     = errors.New("ccse: domain and envelope mismatch")
	ErrUnsupportedAlgorithm       = errors.New("ccse: unsupported signature algorithm")
	ErrInvalidSignature           = errors.New("ccse: invalid signature")
	ErrPayloadDigestMismatch      = errors.New("ccse: payload digest mismatch")
	ErrDuplicateExtension         = errors.New("ccse: duplicate extension identifier")
	ErrInvalidExtension           = errors.New("ccse: invalid extension")
	ErrInvalidValidityWindow      = errors.New("ccse: invalid validity window")
	ErrInvalidCounterKind         = errors.New("ccse: invalid counter kind")
	ErrEmptyRequiredDomainField   = errors.New("ccse: empty required domain field")
	ErrEmptyRequiredEnvelopeField = errors.New("ccse: empty required envelope field")
)

func (v Version) encode(e *Encoder) {
	e.Uint32(v.Major)
	e.Uint32(v.Minor)
}

func (d Domain) canonicalBytes(maxBytes int) ([]byte, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	return Marshal(maxBytes, func(e *Encoder) {
		e.String(d.Purpose)
		e.String(d.SenderIdentity)
		e.StringSet(d.Audience)
		e.OptionalString(d.TenantOrganization.Present, d.TenantOrganization.Value)
		e.OptionalString(d.ProviderOrganization.Present, d.ProviderOrganization.Value)
		e.FixedBytes(d.ChainID[:], len(d.ChainID))
		e.FixedBytes(d.GenesisHash[:], len(d.GenesisHash))
		e.String(d.Environment)
		d.ProtocolVersion.encode(e)
		d.SchemaVersion.encode(e)
		e.Uint32(uint32(d.SignatureAlgorithm))
		e.String(d.SignatureKeyID)
		e.Int64(d.IssuedAtUnixNano)
		e.Int64(d.ExpiresAtUnixNano)
		e.Uint32(uint32(d.CounterKind))
		e.Uint64(d.Counter)
		e.String(d.ReplayDomainID)
	})
}

func (d Domain) validate() error {
	if d.Purpose == "" || d.SenderIdentity == "" || len(d.Audience) == 0 || d.Environment == "" || d.SignatureKeyID == "" || d.ReplayDomainID == "" {
		return ErrEmptyRequiredDomainField
	}
	if isZeroDigest(d.ChainID) || isZeroDigest(d.GenesisHash) {
		return fmt.Errorf("%w: zero chain ID or genesis hash", ErrEmptyRequiredDomainField)
	}
	if len(d.Audience) > maxAudience {
		return ErrTooManyElements
	}
	if (!d.TenantOrganization.Present && d.TenantOrganization.Value != "") || (!d.ProviderOrganization.Present && d.ProviderOrganization.Value != "") {
		return ErrNonCanonicalAbsent
	}
	if d.ProtocolVersion.Major == 0 || d.SchemaVersion.Major == 0 {
		return fmt.Errorf("%w: zero major version", ErrInvalidRecord)
	}
	if d.SignatureAlgorithm == SignatureAlgorithmUnspecified {
		return fmt.Errorf("%w: unspecified algorithm", ErrInvalidRecord)
	}
	if d.CounterKind != CounterSequence && d.CounterKind != CounterExpectedGeneration {
		return ErrInvalidCounterKind
	}
	if d.IssuedAtUnixNano < 0 || d.ExpiresAtUnixNano <= d.IssuedAtUnixNano {
		return ErrInvalidValidityWindow
	}
	return nil
}

func (e Envelope) canonicalBytes(maxBytes int) ([]byte, error) {
	if err := e.validate(); err != nil {
		return nil, err
	}
	extensions, err := canonicalExtensions(e.Extensions, maxBytes)
	if err != nil {
		return nil, err
	}
	return Marshal(maxBytes, func(out *Encoder) {
		e.ProtocolVersion.encode(out)
		e.SchemaVersion.encode(out)
		out.FixedBytes(e.MessageID[:], len(e.MessageID))
		out.FixedBytes(e.CorrelationID[:], len(e.CorrelationID))
		out.Bool(e.CausationID.Present)
		if e.CausationID.Present {
			out.FixedBytes(e.CausationID.Value[:], len(e.CausationID.Value))
		}
		out.String(e.SenderIdentity)
		out.FixedBytes(e.ChainID[:], len(e.ChainID))
		out.String(e.Environment)
		out.Int64(e.IssuedAtUnixNano)
		out.Int64(e.ExpiresAtUnixNano)
		out.Uint32(uint32(e.CounterKind))
		out.Uint64(e.Counter)
		out.FixedBytes(e.PayloadDigest[:], len(e.PayloadDigest))
		out.Uint32(uint32(e.SignatureAlgorithm))
		out.String(e.SignatureKeyID)
		out.EncodedList(extensions)
	})
}

func (e Envelope) validate() error {
	if e.SenderIdentity == "" || e.Environment == "" || e.SignatureKeyID == "" {
		return ErrEmptyRequiredEnvelopeField
	}
	if isZeroDigest(e.ChainID) {
		return fmt.Errorf("%w: zero chain ID", ErrEmptyRequiredEnvelopeField)
	}
	if isZeroMessageID(e.MessageID) || isZeroMessageID(e.CorrelationID) {
		return fmt.Errorf("%w: zero message or correlation identifier", ErrInvalidRecord)
	}
	if (!e.CausationID.Present && !isZeroMessageID(e.CausationID.Value)) || (e.CausationID.Present && isZeroMessageID(e.CausationID.Value)) {
		return ErrNonCanonicalAbsent
	}
	if len(e.Extensions) > maxExtensions {
		return ErrTooManyElements
	}
	if e.ProtocolVersion.Major == 0 || e.SchemaVersion.Major == 0 {
		return fmt.Errorf("%w: zero major version", ErrInvalidRecord)
	}
	if e.SignatureAlgorithm == SignatureAlgorithmUnspecified {
		return fmt.Errorf("%w: unspecified algorithm", ErrInvalidRecord)
	}
	if e.CounterKind != CounterSequence && e.CounterKind != CounterExpectedGeneration {
		return ErrInvalidCounterKind
	}
	if e.IssuedAtUnixNano < 0 || e.ExpiresAtUnixNano <= e.IssuedAtUnixNano {
		return ErrInvalidValidityWindow
	}
	return validateExtensions(e.Extensions, DefaultMaxProjectionSize)
}

func validateExtensions(extensions []Extension, maxBytes int) error {
	if maxBytes <= 0 {
		return ErrProjectionTooLarge
	}
	seen := make(map[uint32]struct{}, len(extensions))
	total := uint64(4)
	for _, extension := range extensions {
		if extension.ID == 0 {
			return ErrInvalidExtension
		}
		if _, exists := seen[extension.ID]; exists {
			return ErrDuplicateExtension
		}
		seen[extension.ID] = struct{}{}
		// EncodedList adds a length prefix around the extension, whose own
		// projection is u32 ID, bool critical, and len32(value).
		total += uint64(4 + 4 + 1 + 4 + len(extension.Value))
		if total > uint64(maxBytes) {
			return ErrProjectionTooLarge
		}
	}
	return nil
}

func canonicalExtensions(extensions []Extension, maxBytes int) ([][]byte, error) {
	if err := validateExtensions(extensions, maxBytes); err != nil {
		return nil, err
	}
	ordered := append([]Extension(nil), extensions...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	encoded := make([][]byte, 0, len(ordered))
	for i, extension := range ordered {
		if extension.ID == 0 {
			return nil, ErrInvalidExtension
		}
		if i > 0 && ordered[i-1].ID == extension.ID {
			return nil, ErrDuplicateExtension
		}
		item, err := Marshal(maxBytes, func(e *Encoder) {
			e.Uint32(extension.ID)
			e.Bool(extension.Critical)
			e.Bytes(extension.Value)
		})
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, item)
	}
	return encoded, nil
}

func validateBinding(domain Domain, envelope Envelope, payload []byte) error {
	if domain.ProtocolVersion != envelope.ProtocolVersion ||
		domain.SchemaVersion != envelope.SchemaVersion ||
		domain.SenderIdentity != envelope.SenderIdentity ||
		domain.ChainID != envelope.ChainID ||
		domain.Environment != envelope.Environment ||
		domain.IssuedAtUnixNano != envelope.IssuedAtUnixNano ||
		domain.ExpiresAtUnixNano != envelope.ExpiresAtUnixNano ||
		domain.CounterKind != envelope.CounterKind ||
		domain.Counter != envelope.Counter ||
		domain.SignatureAlgorithm != envelope.SignatureAlgorithm ||
		domain.SignatureKeyID != envelope.SignatureKeyID {
		return ErrDomainEnvelopeMismatch
	}
	digest := sha256.Sum256(payload)
	if !bytes.Equal(digest[:], envelope.PayloadDigest[:]) {
		return ErrPayloadDigestMismatch
	}
	return nil
}

func isZeroMessageID(id [MessageIDSize]byte) bool {
	return id == [MessageIDSize]byte{}
}

func isZeroDigest[T ~[32]byte](value T) bool {
	return value == T{}
}
