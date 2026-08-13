// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"sort"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	"github.com/cypherium/cypher/aiinfra/schema"
)

const (
	// DurablePolicyApprovalCollectionCodec is the semantic codec identifier
	// reserved by storage pending kind 7.
	DurablePolicyApprovalCollectionCodec        = "cph.aiinfra.governance.policy-approval-collection.v1"
	DurablePolicyApprovalCollectionCodecVersion = uint32(1)

	durablePolicyApprovalCollectionDigestDomain = "CPH-AIIE-GOVERNANCE-DURABLE-POLICY-APPROVAL-COLLECTION-V1\x00"
	durablePolicyApprovalCollectionMaxBytes     = 8 << 20
	durablePolicyApprovalEntryMaxBytes          = 128 << 10
	durablePolicyApprovalStringMaxBytes         = 64 << 10
)

// DecodedPolicyApprovalCollection is inert, owned storage data. Canonical
// decoding proves byte integrity and closed-union shape only; it does not make
// a stored IAM key snapshot authoritative. RehydratePolicyApprovalCollection
// performs the historical IAM/profile lookups and returns the capability type.
type DecodedPolicyApprovalCollection struct {
	encoded  []byte
	digest   [ccse.DigestSize]byte
	binding  idempotency.Binding
	revision uint64
	progress [ccse.DigestSize]byte
	entries  []PolicyApprovalCollectionEntry
}

func (value DecodedPolicyApprovalCollection) Codec() string {
	return DurablePolicyApprovalCollectionCodec
}
func (value DecodedPolicyApprovalCollection) CodecVersion() uint32 {
	return DurablePolicyApprovalCollectionCodecVersion
}
func (value DecodedPolicyApprovalCollection) Bytes() []byte {
	return append([]byte(nil), value.encoded...)
}
func (value DecodedPolicyApprovalCollection) Digest() [ccse.DigestSize]byte { return value.digest }
func (value DecodedPolicyApprovalCollection) Binding() idempotency.Binding  { return value.binding }
func (value DecodedPolicyApprovalCollection) Revision() uint64              { return value.revision }
func (value DecodedPolicyApprovalCollection) ProgressDigest() [ccse.DigestSize]byte {
	return value.progress
}
func (value DecodedPolicyApprovalCollection) EvidenceDigests() [][ccse.DigestSize]byte {
	return durablePolicyApprovalEvidenceDigests(value.entries)
}
// Entries returns detached inert admission evidence. Authority is granted
// only after Planner.RehydratePolicyApprovalCollection re-resolves every IAM
// key and profile timeline; this getter exposes no execution capability.
func (value DecodedPolicyApprovalCollection) Entries() []PolicyApprovalCollectionEntry {
	return clonePolicyApprovalCollectionEntries(value.entries)
}

// RehydratedPolicyApprovalCollection is issued only after every raw signed
// record has been rehashed, Ed25519-verified, and matched exactly with the
// authoritative IAM key and governance-profile timelines. It intentionally
// remains non-committable; the storage coordinator must still CAS its exact
// revision/progress tuple in the AuditEvent-owned transaction.
type RehydratedPolicyApprovalCollection struct {
	decoded DecodedPolicyApprovalCollection
}

func (value RehydratedPolicyApprovalCollection) CommitReady() bool { return false }
func (value RehydratedPolicyApprovalCollection) Codec() string {
	return DurablePolicyApprovalCollectionCodec
}
func (value RehydratedPolicyApprovalCollection) CodecVersion() uint32 {
	return DurablePolicyApprovalCollectionCodecVersion
}
func (value RehydratedPolicyApprovalCollection) Bytes() []byte { return value.decoded.Bytes() }
func (value RehydratedPolicyApprovalCollection) Digest() [ccse.DigestSize]byte {
	return value.decoded.digest
}
func (value RehydratedPolicyApprovalCollection) Binding() idempotency.Binding {
	return value.decoded.binding
}
func (value RehydratedPolicyApprovalCollection) Revision() uint64 { return value.decoded.revision }
func (value RehydratedPolicyApprovalCollection) ProgressDigest() [ccse.DigestSize]byte {
	return value.decoded.progress
}
func (value RehydratedPolicyApprovalCollection) EvidenceDigests() [][ccse.DigestSize]byte {
	return value.decoded.EvidenceDigests()
}
func (value RehydratedPolicyApprovalCollection) Entries() []PolicyApprovalCollectionEntry {
	return clonePolicyApprovalCollectionEntries(value.decoded.entries)
}

// EncodePolicyApprovalCollection produces the sole deterministic kind-7
// envelope. The result is deliberately inert: callers cannot turn a
// self-consistent, attacker-authored key snapshot into an authorization
// capability without Planner.RehydratePolicyApprovalCollection.
func EncodePolicyApprovalCollection(binding idempotency.Binding, revision uint64,
	progress [ccse.DigestSize]byte, entries []PolicyApprovalCollectionEntry) (DecodedPolicyApprovalCollection, error) {
	encoded, normalized, err := marshalPolicyApprovalCollection(binding, revision, progress, entries)
	if err != nil {
		return DecodedPolicyApprovalCollection{}, err
	}
	return DecodedPolicyApprovalCollection{
		encoded: encoded, digest: durablePolicyApprovalCollectionDigest(encoded), binding: binding,
		revision: revision, progress: progress, entries: normalized,
	}, nil
}

// DecodePolicyApprovalCollection rejects unknown versions, noncanonical set
// order, duplicates, trailing bytes, oversized aggregates, and any byte stream
// that does not reproduce exactly under the v1 encoder.
func DecodePolicyApprovalCollection(input []byte) (DecodedPolicyApprovalCollection, error) {
	if len(input) == 0 || len(input) > durablePolicyApprovalCollectionMaxBytes {
		return DecodedPolicyApprovalCollection{}, ErrApprovalCollection
	}
	var (
		binding  idempotency.Binding
		revision uint64
		progress [ccse.DigestSize]byte
		entries  []PolicyApprovalCollectionEntry
	)
	err := ccse.Unmarshal(input, durablePolicyApprovalCollectionMaxBytes, func(in *ccse.Decoder) error {
		version, err := in.Uint32()
		if err != nil || version != DurablePolicyApprovalCollectionCodecVersion {
			return ErrApprovalCollection
		}
		codec, err := in.String(255)
		if err != nil || codec != DurablePolicyApprovalCollectionCodec {
			return ErrApprovalCollection
		}
		key, err := in.FixedBytes(ccse.MessageIDSize)
		if err != nil {
			return err
		}
		copy(binding.Key[:], key)
		domain, err := in.String(128)
		if err != nil {
			return err
		}
		binding.Domain = idempotency.OperationDomain(domain)
		binding.OwnerID, err = in.String(durablePolicyApprovalStringMaxBytes)
		if err != nil {
			return err
		}
		requestDigest, err := in.FixedBytes(ccse.DigestSize)
		if err != nil {
			return err
		}
		copy(binding.RequestDigest[:], requestDigest)
		revision, err = in.Uint64()
		if err != nil {
			return err
		}
		progressBytes, err := in.FixedBytes(ccse.DigestSize)
		if err != nil {
			return err
		}
		copy(progress[:], progressBytes)
		entries = make([]PolicyApprovalCollectionEntry, 0, maxApprovals)
		return in.ValidatedSet(maxApprovals, durablePolicyApprovalEntryMaxBytes, func(_ int, child *ccse.Decoder) error {
			entry, decodeErr := decodeDurablePolicyApprovalEntry(child)
			if decodeErr != nil {
				return decodeErr
			}
			entries = append(entries, entry)
			return nil
		})
	})
	if err != nil || binding.Validate() != nil || revision == 0 || isZeroDigest(progress) || len(entries) == 0 ||
		revision < uint64(len(entries)) {
		return DecodedPolicyApprovalCollection{}, ErrApprovalCollection
	}
	reencoded, normalized, err := marshalPolicyApprovalCollection(binding, revision, progress, entries)
	if err != nil || !bytes.Equal(reencoded, input) {
		return DecodedPolicyApprovalCollection{}, ErrApprovalCollection
	}
	return DecodedPolicyApprovalCollection{
		encoded: append([]byte(nil), input...), digest: durablePolicyApprovalCollectionDigest(input),
		binding: binding, revision: revision, progress: progress, entries: normalized,
	}, nil
}

// RehydratePolicyApprovalCollection is the trust transition for a kind-7
// envelope. In particular, it never tries to reconstruct ccse.VerifiedRecord:
// historical raw records are rehashed and re-signed, then their retained key
// snapshots are compared with ResolveGovernanceKeyAt byte-for-byte.
func (p *Planner) RehydratePolicyApprovalCollection(ctx context.Context,
	decoded DecodedPolicyApprovalCollection) (RehydratedPolicyApprovalCollection, error) {
	if p == nil || p.canonical == nil || len(decoded.encoded) == 0 ||
		durablePolicyApprovalCollectionDigest(decoded.encoded) != decoded.digest {
		return RehydratedPolicyApprovalCollection{}, ErrApprovalCollection
	}
	reparsed, err := DecodePolicyApprovalCollection(decoded.encoded)
	if err != nil || reparsed.digest != decoded.digest || reparsed.binding != decoded.binding ||
		reparsed.revision != decoded.revision || reparsed.progress != decoded.progress {
		return RehydratedPolicyApprovalCollection{}, ErrApprovalCollection
	}
	approvals := make([]policyApproval, 0, len(reparsed.entries))
	for index := range reparsed.entries {
		approval, _, validateErr := p.validatePolicyApprovalAdmission(ctx, reparsed.entries[index])
		if validateErr != nil {
			return RehydratedPolicyApprovalCollection{}, fmt.Errorf("rehydrate approval %d: %w", index, ErrApprovalCollection)
		}
		if approval.legacyAdmission {
			// Kind 7 is the V2 codec. A legacy row remains readable through the
			// old view for terminal reconciliation, but cannot be laundered into a
			// V2 durable capability.
			return RehydratedPolicyApprovalCollection{}, ErrApprovalCollection
		}
		approvals = append(approvals, approval)
	}
	if err := validatePolicyApprovalCollectionShape(reparsed.binding, approvals); err != nil {
		return RehydratedPolicyApprovalCollection{}, ErrApprovalCollection
	}
	progress, err := approvalCollectionDigest(reparsed.binding, approvals)
	if err != nil || progress != reparsed.progress || reparsed.revision < uint64(len(approvals)) {
		return RehydratedPolicyApprovalCollection{}, ErrApprovalCollection
	}
	if err := contextErr(ctx); err != nil {
		return RehydratedPolicyApprovalCollection{}, err
	}
	return RehydratedPolicyApprovalCollection{decoded: reparsed}, nil
}

func marshalPolicyApprovalCollection(binding idempotency.Binding, revision uint64,
	progress [ccse.DigestSize]byte, entries []PolicyApprovalCollectionEntry) ([]byte, []PolicyApprovalCollectionEntry, error) {
	if binding.Validate() != nil || revision == 0 || isZeroDigest(progress) || len(entries) == 0 ||
		len(entries) > maxApprovals || revision < uint64(len(entries)) {
		return nil, nil, ErrApprovalCollection
	}
	encodedEntries := make([][]byte, 0, len(entries))
	normalized := make([]PolicyApprovalCollectionEntry, 0, len(entries))
	for index := range entries {
		entryBytes, entry, err := marshalDurablePolicyApprovalEntry(entries[index])
		if err != nil {
			return nil, nil, fmt.Errorf("approval entry %d: %w", index, ErrApprovalCollection)
		}
		encodedEntries = append(encodedEntries, entryBytes)
		normalized = append(normalized, entry)
	}
	sort.Slice(normalized, func(i, j int) bool {
		left, _ := marshalDurablePolicyApprovalEntryBytes(normalized[i])
		right, _ := marshalDurablePolicyApprovalEntryBytes(normalized[j])
		return bytes.Compare(left, right) < 0
	})
	encoded, err := ccse.Marshal(durablePolicyApprovalCollectionMaxBytes, func(out *ccse.Encoder) {
		out.Uint32(DurablePolicyApprovalCollectionCodecVersion)
		out.String(DurablePolicyApprovalCollectionCodec)
		out.FixedBytes(binding.Key[:], ccse.MessageIDSize)
		out.String(string(binding.Domain))
		out.String(binding.OwnerID)
		out.FixedBytes(binding.RequestDigest[:], ccse.DigestSize)
		out.Uint64(revision)
		out.FixedBytes(progress[:], ccse.DigestSize)
		out.EncodedSet(encodedEntries)
	})
	if err != nil {
		return nil, nil, ErrApprovalCollection
	}
	return encoded, normalized, nil
}

func marshalDurablePolicyApprovalEntry(input PolicyApprovalCollectionEntry) ([]byte, PolicyApprovalCollectionEntry, error) {
	if input.Signed.Record == nil || !preflightRawRecord(input.Signed.Record, maxPayloadBytesFor(schema.MessageTypePolicyBundle)) ||
		!preflightKeySnapshot(input.AdmissionKey) || isZeroDigest(input.GovernanceProfileDigestSHA256) ||
		!validGovernanceProfileActivation(input.GovernanceProfileActivation, input.ValidatedAtUnixNano) ||
		input.GovernanceProfileActivation.GovernanceProfileDigestSHA256 != input.GovernanceProfileDigestSHA256 ||
		input.ValidatedAtUnixNano < 0 || isZeroDigest(input.AdmissionFingerprintSHA256) {
		return nil, PolicyApprovalCollectionEntry{}, ErrApprovalCollection
	}
	signed, err := bindHistoricalSignedRecord(input.Signed, maxPayloadBytesFor(schema.MessageTypePolicyBundle))
	if err != nil {
		return nil, PolicyApprovalCollectionEntry{}, ErrApprovalCollection
	}
	entry := PolicyApprovalCollectionEntry{
		Signed: SignedRecord{Record: ptrCCSERecord(signed.record)}, AdmissionKey: cloneKeySnapshot(input.AdmissionKey),
		GovernanceProfileDigestSHA256: input.GovernanceProfileDigestSHA256,
		GovernanceProfileActivation:   input.GovernanceProfileActivation,
		ValidatedAtUnixNano:           input.ValidatedAtUnixNano,
		AdmissionFingerprintSHA256:    input.AdmissionFingerprintSHA256,
	}
	encoded, err := marshalDurablePolicyApprovalEntryBytes(entry)
	if err != nil || len(encoded) > durablePolicyApprovalEntryMaxBytes {
		return nil, PolicyApprovalCollectionEntry{}, ErrApprovalCollection
	}
	return encoded, entry, nil
}

func marshalDurablePolicyApprovalEntryBytes(entry PolicyApprovalCollectionEntry) ([]byte, error) {
	record := entry.Signed.Record
	digest, err := record.Digest(ccse.DefaultLimits())
	if err != nil {
		return nil, err
	}
	return ccse.Marshal(durablePolicyApprovalEntryMaxBytes, func(out *ccse.Encoder) {
		encodeDurableCCSERecord(out, *record)
		out.FixedBytes(digest[:], ccse.DigestSize)
		encodeDurableGovernanceKey(out, entry.AdmissionKey)
		out.FixedBytes(entry.GovernanceProfileDigestSHA256[:], ccse.DigestSize)
		encodeDurableProfileActivation(out, entry.GovernanceProfileActivation)
		out.Int64(entry.ValidatedAtUnixNano)
		out.FixedBytes(entry.AdmissionFingerprintSHA256[:], ccse.DigestSize)
	})
}

func decodeDurablePolicyApprovalEntry(in *ccse.Decoder) (PolicyApprovalCollectionEntry, error) {
	record, err := decodeDurableCCSERecord(in)
	if err != nil {
		return PolicyApprovalCollectionEntry{}, err
	}
	digestBytes, err := in.FixedBytes(ccse.DigestSize)
	if err != nil {
		return PolicyApprovalCollectionEntry{}, err
	}
	var expectedDigest [ccse.DigestSize]byte
	copy(expectedDigest[:], digestBytes)
	actualDigest, err := record.Digest(ccse.DefaultLimits())
	if err != nil || actualDigest != expectedDigest {
		return PolicyApprovalCollectionEntry{}, ErrApprovalCollection
	}
	key, err := decodeDurableGovernanceKey(in)
	if err != nil {
		return PolicyApprovalCollectionEntry{}, err
	}
	profileBytes, err := in.FixedBytes(ccse.DigestSize)
	if err != nil {
		return PolicyApprovalCollectionEntry{}, err
	}
	var profileDigest [ccse.DigestSize]byte
	copy(profileDigest[:], profileBytes)
	activation, err := decodeDurableProfileActivation(in)
	if err != nil {
		return PolicyApprovalCollectionEntry{}, err
	}
	validatedAt, err := in.Int64()
	if err != nil {
		return PolicyApprovalCollectionEntry{}, err
	}
	fingerprintBytes, err := in.FixedBytes(ccse.DigestSize)
	if err != nil {
		return PolicyApprovalCollectionEntry{}, err
	}
	var fingerprint [ccse.DigestSize]byte
	copy(fingerprint[:], fingerprintBytes)
	if !preflightRawRecord(&record, maxPayloadBytesFor(schema.MessageTypePolicyBundle)) || !preflightKeySnapshot(key) ||
		isZeroDigest(profileDigest) || activation.GovernanceProfileDigestSHA256 != profileDigest ||
		!validGovernanceProfileActivation(activation, validatedAt) || isZeroDigest(fingerprint) {
		return PolicyApprovalCollectionEntry{}, ErrApprovalCollection
	}
	return PolicyApprovalCollectionEntry{
		Signed: SignedRecord{Record: ptrCCSERecord(record)}, AdmissionKey: key,
		GovernanceProfileDigestSHA256: profileDigest, GovernanceProfileActivation: activation,
		ValidatedAtUnixNano: validatedAt, AdmissionFingerprintSHA256: fingerprint,
	}, nil
}

func encodeDurableCCSERecord(out *ccse.Encoder, record ccse.Record) {
	out.Uint32(record.MessageTypeID)
	encodeDurableVersion(out, record.SchemaVersion)
	domain := record.Domain
	out.String(domain.Purpose)
	out.String(domain.SenderIdentity)
	out.StringSet(domain.Audience)
	out.OptionalString(domain.TenantOrganization.Present, domain.TenantOrganization.Value)
	out.OptionalString(domain.ProviderOrganization.Present, domain.ProviderOrganization.Value)
	out.FixedBytes(domain.ChainID[:], ccse.DigestSize)
	out.FixedBytes(domain.GenesisHash[:], ccse.DigestSize)
	out.String(domain.Environment)
	encodeDurableVersion(out, domain.ProtocolVersion)
	encodeDurableVersion(out, domain.SchemaVersion)
	out.Uint32(uint32(domain.SignatureAlgorithm))
	out.String(domain.SignatureKeyID)
	out.Int64(domain.IssuedAtUnixNano)
	out.Int64(domain.ExpiresAtUnixNano)
	out.Uint32(uint32(domain.CounterKind))
	out.Uint64(domain.Counter)
	out.String(domain.ReplayDomainID)
	envelope := record.Envelope
	encodeDurableVersion(out, envelope.ProtocolVersion)
	encodeDurableVersion(out, envelope.SchemaVersion)
	out.FixedBytes(envelope.MessageID[:], ccse.MessageIDSize)
	out.FixedBytes(envelope.CorrelationID[:], ccse.MessageIDSize)
	out.Bool(envelope.CausationID.Present)
	if envelope.CausationID.Present {
		out.FixedBytes(envelope.CausationID.Value[:], ccse.MessageIDSize)
	}
	out.String(envelope.SenderIdentity)
	out.FixedBytes(envelope.ChainID[:], ccse.DigestSize)
	out.String(envelope.Environment)
	out.Int64(envelope.IssuedAtUnixNano)
	out.Int64(envelope.ExpiresAtUnixNano)
	out.Uint32(uint32(envelope.CounterKind))
	out.Uint64(envelope.Counter)
	out.FixedBytes(envelope.PayloadDigest[:], ccse.DigestSize)
	out.Uint32(uint32(envelope.SignatureAlgorithm))
	out.String(envelope.SignatureKeyID)
	extensions := make([][]byte, 0, len(envelope.Extensions))
	for _, extension := range envelope.Extensions {
		encoded, err := ccse.Marshal(ccse.DefaultLimits().MaxEnvelopeBytes, func(child *ccse.Encoder) {
			child.Uint32(extension.ID)
			child.Bool(extension.Critical)
			child.Bytes(extension.Value)
		})
		if err != nil {
			// Propagate through the parent encoder without a panic. An invalid
			// extension will also make Record.Digest fail before this helper.
			out.Bytes(make([]byte, durablePolicyApprovalCollectionMaxBytes+1))
			return
		}
		extensions = append(extensions, encoded)
	}
	out.EncodedSet(extensions)
	out.Bytes(record.Payload)
	out.Bytes(record.Signature)
}

func decodeDurableCCSERecord(in *ccse.Decoder) (ccse.Record, error) {
	var record ccse.Record
	var err error
	record.MessageTypeID, err = in.Uint32()
	if err != nil {
		return ccse.Record{}, err
	}
	if record.SchemaVersion, err = decodeDurableVersion(in); err != nil {
		return ccse.Record{}, err
	}
	domain := &record.Domain
	if domain.Purpose, err = in.String(durablePolicyApprovalStringMaxBytes); err != nil {
		return ccse.Record{}, err
	}
	if domain.SenderIdentity, err = in.String(durablePolicyApprovalStringMaxBytes); err != nil {
		return ccse.Record{}, err
	}
	if domain.Audience, err = in.StringSet(64, durablePolicyApprovalStringMaxBytes); err != nil {
		return ccse.Record{}, err
	}
	if domain.TenantOrganization.Present, domain.TenantOrganization.Value, err = in.OptionalString(durablePolicyApprovalStringMaxBytes); err != nil {
		return ccse.Record{}, err
	}
	if domain.ProviderOrganization.Present, domain.ProviderOrganization.Value, err = in.OptionalString(durablePolicyApprovalStringMaxBytes); err != nil {
		return ccse.Record{}, err
	}
	if err = decodeFixed32(in, &domain.ChainID); err != nil {
		return ccse.Record{}, err
	}
	if err = decodeFixed32(in, &domain.GenesisHash); err != nil {
		return ccse.Record{}, err
	}
	if domain.Environment, err = in.String(durablePolicyApprovalStringMaxBytes); err != nil {
		return ccse.Record{}, err
	}
	if domain.ProtocolVersion, err = decodeDurableVersion(in); err != nil {
		return ccse.Record{}, err
	}
	if domain.SchemaVersion, err = decodeDurableVersion(in); err != nil {
		return ccse.Record{}, err
	}
	algorithm, err := in.Uint32()
	if err != nil {
		return ccse.Record{}, err
	}
	domain.SignatureAlgorithm = ccse.SignatureAlgorithmID(algorithm)
	if domain.SignatureKeyID, err = in.String(durablePolicyApprovalStringMaxBytes); err != nil {
		return ccse.Record{}, err
	}
	if domain.IssuedAtUnixNano, err = in.Int64(); err != nil {
		return ccse.Record{}, err
	}
	if domain.ExpiresAtUnixNano, err = in.Int64(); err != nil {
		return ccse.Record{}, err
	}
	counterKind, err := in.Uint32()
	if err != nil {
		return ccse.Record{}, err
	}
	domain.CounterKind = ccse.CounterKind(counterKind)
	if domain.Counter, err = in.Uint64(); err != nil {
		return ccse.Record{}, err
	}
	if domain.ReplayDomainID, err = in.String(durablePolicyApprovalStringMaxBytes); err != nil {
		return ccse.Record{}, err
	}
	envelope := &record.Envelope
	if envelope.ProtocolVersion, err = decodeDurableVersion(in); err != nil {
		return ccse.Record{}, err
	}
	if envelope.SchemaVersion, err = decodeDurableVersion(in); err != nil {
		return ccse.Record{}, err
	}
	if err = decodeFixed16(in, &envelope.MessageID); err != nil {
		return ccse.Record{}, err
	}
	if err = decodeFixed16(in, &envelope.CorrelationID); err != nil {
		return ccse.Record{}, err
	}
	if envelope.CausationID.Present, err = in.Bool(); err != nil {
		return ccse.Record{}, err
	}
	if envelope.CausationID.Present {
		if err = decodeFixed16(in, &envelope.CausationID.Value); err != nil {
			return ccse.Record{}, err
		}
	}
	if envelope.SenderIdentity, err = in.String(durablePolicyApprovalStringMaxBytes); err != nil {
		return ccse.Record{}, err
	}
	if err = decodeFixed32(in, &envelope.ChainID); err != nil {
		return ccse.Record{}, err
	}
	if envelope.Environment, err = in.String(durablePolicyApprovalStringMaxBytes); err != nil {
		return ccse.Record{}, err
	}
	if envelope.IssuedAtUnixNano, err = in.Int64(); err != nil {
		return ccse.Record{}, err
	}
	if envelope.ExpiresAtUnixNano, err = in.Int64(); err != nil {
		return ccse.Record{}, err
	}
	counterKind, err = in.Uint32()
	if err != nil {
		return ccse.Record{}, err
	}
	envelope.CounterKind = ccse.CounterKind(counterKind)
	if envelope.Counter, err = in.Uint64(); err != nil {
		return ccse.Record{}, err
	}
	if err = decodeFixed32(in, &envelope.PayloadDigest); err != nil {
		return ccse.Record{}, err
	}
	algorithm, err = in.Uint32()
	if err != nil {
		return ccse.Record{}, err
	}
	envelope.SignatureAlgorithm = ccse.SignatureAlgorithmID(algorithm)
	if envelope.SignatureKeyID, err = in.String(durablePolicyApprovalStringMaxBytes); err != nil {
		return ccse.Record{}, err
	}
	envelope.Extensions = make([]ccse.Extension, 0, 64)
	if err = in.ValidatedSet(64, ccse.DefaultLimits().MaxEnvelopeBytes, func(_ int, child *ccse.Decoder) error {
		extension := ccse.Extension{}
		var childErr error
		if extension.ID, childErr = child.Uint32(); childErr != nil {
			return childErr
		}
		if extension.Critical, childErr = child.Bool(); childErr != nil {
			return childErr
		}
		if extension.Value, childErr = child.Bytes(ccse.DefaultLimits().MaxEnvelopeBytes); childErr != nil {
			return childErr
		}
		envelope.Extensions = append(envelope.Extensions, extension)
		return nil
	}); err != nil {
		return ccse.Record{}, err
	}
	if record.Payload, err = in.Bytes(maxPayloadBytesFor(schema.MessageTypePolicyBundle)); err != nil {
		return ccse.Record{}, err
	}
	if record.Signature, err = in.Bytes(ccse.DefaultLimits().MaxSignatureBytes); err != nil {
		return ccse.Record{}, err
	}
	return record, nil
}

func encodeDurableGovernanceKey(out *ccse.Encoder, key GovernanceKeySnapshot) {
	out.String(key.KeyID)
	out.String(key.SubjectIdentity)
	out.Uint32(key.TargetIdentityKind)
	out.Uint32(key.TargetPrincipalKind)
	out.String(key.TargetIdentityID)
	out.String(key.OrganizationIdentity)
	out.Uint32(uint32(key.Algorithm))
	out.Bytes(key.PublicKey)
	out.Uint32(key.LifecycleState)
	out.Int64(key.NotBeforeUnixNano)
	out.Int64(key.NotAfterUnixNano)
	out.Int64(key.RevokedAtUnixNano)
	allowed := make([][]byte, 0, len(key.AllowedMessageTypeIDs))
	for _, value := range key.AllowedMessageTypeIDs {
		encoded, _ := ccse.Marshal(8, func(child *ccse.Encoder) { child.Uint32(value) })
		allowed = append(allowed, encoded)
	}
	out.EncodedSet(allowed)
	out.StringSet(key.Roles)
	out.FixedBytes(key.AuthorizationPolicyDigestSHA256[:], ccse.DigestSize)
	out.Uint64(key.KeyMaterialStateVersion)
	out.FixedBytes(key.KeyMaterialStateDigestSHA256[:], ccse.DigestSize)
	out.Uint64(key.StateVersion)
	out.Uint64(key.WriterEpoch)
	out.FixedBytes(key.SnapshotDigestSHA256[:], ccse.DigestSize)
	out.Uint64(key.IdentityStateVersion)
	out.Uint64(key.IdentityWriterEpoch)
	out.FixedBytes(key.IdentitySnapshotDigestSHA256[:], ccse.DigestSize)
	out.String(key.EnrollmentDomainID)
	out.String(key.EnrollmentEnvironment)
	out.FixedBytes(key.EnrollmentGenesisHash[:], ccse.DigestSize)
}

func decodeDurableGovernanceKey(in *ccse.Decoder) (GovernanceKeySnapshot, error) {
	var key GovernanceKeySnapshot
	var err error
	if key.KeyID, err = in.String(durablePolicyApprovalStringMaxBytes); err != nil {
		return key, err
	}
	if key.SubjectIdentity, err = in.String(durablePolicyApprovalStringMaxBytes); err != nil {
		return key, err
	}
	if key.TargetIdentityKind, err = in.Uint32(); err != nil {
		return key, err
	}
	if key.TargetPrincipalKind, err = in.Uint32(); err != nil {
		return key, err
	}
	if key.TargetIdentityID, err = in.String(durablePolicyApprovalStringMaxBytes); err != nil {
		return key, err
	}
	if key.OrganizationIdentity, err = in.String(durablePolicyApprovalStringMaxBytes); err != nil {
		return key, err
	}
	algorithm, err := in.Uint32()
	if err != nil {
		return key, err
	}
	key.Algorithm = ccse.SignatureAlgorithmID(algorithm)
	if key.PublicKey, err = in.Bytes(256); err != nil {
		return key, err
	}
	if key.LifecycleState, err = in.Uint32(); err != nil {
		return key, err
	}
	if key.NotBeforeUnixNano, err = in.Int64(); err != nil {
		return key, err
	}
	if key.NotAfterUnixNano, err = in.Int64(); err != nil {
		return key, err
	}
	if key.RevokedAtUnixNano, err = in.Int64(); err != nil {
		return key, err
	}
	key.AllowedMessageTypeIDs = make([]uint32, 0, 64)
	if err = in.ValidatedSet(64, 8, func(_ int, child *ccse.Decoder) error {
		value, childErr := child.Uint32()
		if childErr == nil {
			key.AllowedMessageTypeIDs = append(key.AllowedMessageTypeIDs, value)
		}
		return childErr
	}); err != nil {
		return key, err
	}
	if key.Roles, err = in.StringSet(64, durablePolicyApprovalStringMaxBytes); err != nil {
		return key, err
	}
	if err = decodeFixed32(in, &key.AuthorizationPolicyDigestSHA256); err != nil {
		return key, err
	}
	if key.KeyMaterialStateVersion, err = in.Uint64(); err != nil {
		return key, err
	}
	if err = decodeFixed32(in, &key.KeyMaterialStateDigestSHA256); err != nil {
		return key, err
	}
	if key.StateVersion, err = in.Uint64(); err != nil {
		return key, err
	}
	if key.WriterEpoch, err = in.Uint64(); err != nil {
		return key, err
	}
	if err = decodeFixed32(in, &key.SnapshotDigestSHA256); err != nil {
		return key, err
	}
	if key.IdentityStateVersion, err = in.Uint64(); err != nil {
		return key, err
	}
	if key.IdentityWriterEpoch, err = in.Uint64(); err != nil {
		return key, err
	}
	if err = decodeFixed32(in, &key.IdentitySnapshotDigestSHA256); err != nil {
		return key, err
	}
	if key.EnrollmentDomainID, err = in.String(durablePolicyApprovalStringMaxBytes); err != nil {
		return key, err
	}
	if key.EnrollmentEnvironment, err = in.String(durablePolicyApprovalStringMaxBytes); err != nil {
		return key, err
	}
	if err = decodeFixed32(in, &key.EnrollmentGenesisHash); err != nil {
		return key, err
	}
	return key, nil
}

func encodeDurableProfileActivation(out *ccse.Encoder, value GovernanceProfileActivationSnapshot) {
	out.FixedBytes(value.GovernanceProfileDigestSHA256[:], ccse.DigestSize)
	out.Uint64(value.Version)
	out.Int64(value.ValidFromUnixNano)
	out.Int64(value.ValidUntilUnixNano)
	out.FixedBytes(value.EvidenceDigestSHA256[:], ccse.DigestSize)
}

func decodeDurableProfileActivation(in *ccse.Decoder) (GovernanceProfileActivationSnapshot, error) {
	var value GovernanceProfileActivationSnapshot
	if err := decodeFixed32(in, &value.GovernanceProfileDigestSHA256); err != nil {
		return value, err
	}
	var err error
	if value.Version, err = in.Uint64(); err != nil {
		return value, err
	}
	if value.ValidFromUnixNano, err = in.Int64(); err != nil {
		return value, err
	}
	if value.ValidUntilUnixNano, err = in.Int64(); err != nil {
		return value, err
	}
	if err = decodeFixed32(in, &value.EvidenceDigestSHA256); err != nil {
		return value, err
	}
	return value, nil
}

func encodeDurableVersion(out *ccse.Encoder, value ccse.Version) {
	out.Uint32(value.Major)
	out.Uint32(value.Minor)
}

func decodeDurableVersion(in *ccse.Decoder) (ccse.Version, error) {
	major, err := in.Uint32()
	if err != nil {
		return ccse.Version{}, err
	}
	minor, err := in.Uint32()
	return ccse.Version{Major: major, Minor: minor}, err
}

func decodeFixed16(in *ccse.Decoder, output *[ccse.MessageIDSize]byte) error {
	value, err := in.FixedBytes(ccse.MessageIDSize)
	if err == nil {
		copy(output[:], value)
	}
	return err
}

func decodeFixed32(in *ccse.Decoder, output *[ccse.DigestSize]byte) error {
	value, err := in.FixedBytes(ccse.DigestSize)
	if err == nil {
		copy(output[:], value)
	}
	return err
}

func durablePolicyApprovalCollectionDigest(input []byte) [ccse.DigestSize]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(durablePolicyApprovalCollectionDigestDomain))
	_, _ = h.Write(input)
	var result [ccse.DigestSize]byte
	copy(result[:], h.Sum(nil))
	return result
}

func durablePolicyApprovalEvidenceDigests(entries []PolicyApprovalCollectionEntry) [][ccse.DigestSize]byte {
	result := make([][ccse.DigestSize]byte, 0, len(entries))
	for _, entry := range entries {
		if entry.Signed.Record == nil {
			return nil
		}
		digest, err := entry.Signed.Record.Digest(ccse.DefaultLimits())
		if err != nil || isZeroDigest(digest) {
			return nil
		}
		result = append(result, digest)
	}
	sortDigests(result)
	return result
}

func clonePolicyApprovalCollectionEntries(input []PolicyApprovalCollectionEntry) []PolicyApprovalCollectionEntry {
	result := make([]PolicyApprovalCollectionEntry, 0, len(input))
	for _, entry := range input {
		if entry.Signed.Record == nil {
			return nil
		}
		record := cloneCCSERecord(entry.Signed.Record)
		result = append(result, PolicyApprovalCollectionEntry{
			Signed: SignedRecord{Record: &record}, AdmissionKey: cloneKeySnapshot(entry.AdmissionKey),
			GovernanceProfileDigestSHA256: entry.GovernanceProfileDigestSHA256,
			GovernanceProfileActivation:   entry.GovernanceProfileActivation,
			ValidatedAtUnixNano:           entry.ValidatedAtUnixNano,
			AdmissionFingerprintSHA256:    entry.AdmissionFingerprintSHA256,
		})
	}
	return result
}

func ptrCCSERecord(value ccse.Record) *ccse.Record {
	copy := cloneCCSERecord(&value)
	return &copy
}
