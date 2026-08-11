// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"

	"github.com/cypherium/cypher/aiinfra/ccse"
)

// auditSourceEvidence retains the complete detached signed authorization that
// directly caused an IAM transition. The canonical Audit Writer is a distinct
// signer; it must be able to reverify this logical actor evidence during the
// WS0.2b compound finalization.
type auditSourceEvidence struct {
	Present     bool
	ActorKeyID  string
	Record      ccse.Record
	Digest      [32]byte
	CausationID ccse.OptionalMessageID
}

func auditSourceFromAuthorization(authorization VerifiedAuthorization) (auditSourceEvidence, error) {
	record, encoded, err := validateAuthorizationSourceRecord(authorization)
	if err != nil {
		return auditSourceEvidence{}, err
	}
	_ = encoded // Recomputed by newAuditIntent and verifyAuditIntent.
	return auditSourceEvidence{Present: true, ActorKeyID: authorization.signatureKeyID,
		Record: record, Digest: authorization.recordDigest,
		CausationID: authorization.causationID}, nil
}

func validateAuthorizationSourceRecord(authorization VerifiedAuthorization) (ccse.Record, []byte, error) {
	if !authorization.hasSourceRecord {
		return ccse.Record{}, nil, ErrAuthorizationMismatch
	}
	record := cloneCCSERecord(authorization.sourceRecord)
	domain, envelope := record.Domain, record.Envelope
	payloadDigest := sha256.Sum256(record.Payload)
	if record.MessageTypeID != authorization.messageTypeID || record.SchemaVersion != authorization.schemaVersion ||
		!bytes.Equal(record.Payload, authorization.payload) ||
		domain.ProtocolVersion != authorization.protocolVersion || domain.SchemaVersion != authorization.schemaVersion ||
		domain.Purpose != authorization.purpose || domain.SenderIdentity != authorization.senderIdentity ||
		!sameStringSet(domain.Audience, authorization.audience) ||
		domain.TenantOrganization != authorization.tenantOrganization ||
		domain.ProviderOrganization != authorization.providerOrganization ||
		domain.Environment != authorization.environment || domain.ChainID != authorization.chainID ||
		domain.GenesisHash != authorization.genesisHash || domain.ReplayDomainID != authorization.replayDomainID ||
		domain.CounterKind != authorization.counterKind || domain.Counter != authorization.counter ||
		domain.IssuedAtUnixNano != authorization.issuedAtUnixNano ||
		domain.ExpiresAtUnixNano != authorization.expiresAtUnixNano ||
		domain.SignatureAlgorithm != ccse.SignatureAlgorithmEd25519 ||
		domain.SignatureKeyID != authorization.signatureKeyID ||
		envelope.ProtocolVersion != authorization.protocolVersion ||
		envelope.SchemaVersion != authorization.schemaVersion || envelope.MessageID != authorization.messageID ||
		envelope.CorrelationID != authorization.correlationID || envelope.CausationID != authorization.causationID ||
		envelope.SenderIdentity != authorization.senderIdentity || envelope.ChainID != authorization.chainID ||
		envelope.Environment != authorization.environment || envelope.IssuedAtUnixNano != authorization.issuedAtUnixNano ||
		envelope.ExpiresAtUnixNano != authorization.expiresAtUnixNano ||
		envelope.CounterKind != authorization.counterKind || envelope.Counter != authorization.counter ||
		envelope.PayloadDigest != payloadDigest || envelope.SignatureAlgorithm != ccse.SignatureAlgorithmEd25519 ||
		envelope.SignatureKeyID != authorization.signatureKeyID || len(record.Signature) != ed25519.SignatureSize {
		return ccse.Record{}, nil, ErrAuthorizationMismatch
	}
	digest, err := record.Digest(ccse.DefaultLimits())
	if err != nil || digest != authorization.recordDigest {
		return ccse.Record{}, nil, ErrAuthorizationMismatch
	}
	encoded, err := canonicalSignedAuthorizationEvidence(record)
	if err != nil {
		return ccse.Record{}, nil, ErrAuthorizationMismatch
	}
	return record, encoded, nil
}

func canonicalSignedAuthorizationEvidence(record ccse.Record) ([]byte, error) {
	preimage, err := record.Preimage(ccse.DefaultLimits())
	if err != nil || len(record.Signature) != ed25519.SignatureSize {
		return nil, ErrAuthorizationMismatch
	}
	return ccse.Marshal(2<<20, func(out *ccse.Encoder) {
		out.Bytes(preimage)
		out.Bytes(record.Signature)
	})
}

func directAuditCausation(messageID [16]byte) ccse.OptionalMessageID {
	return ccse.OptionalMessageID{Present: true, Value: messageID}
}
