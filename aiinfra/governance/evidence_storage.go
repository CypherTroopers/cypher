// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"unicode/utf8"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/iam"
)

const (
	durableEvidenceStorageCodecVersion = uint32(1)

	durableSignedCCSEStorageCodec = "cph.aiinfra.governance.signed-ccse-evidence.v1"
	durableSemanticStorageCodec   = "cph.aiinfra.governance.semantic-receipt-evidence.v1"

	durableEvidenceStorageCapabilityDigestDomain = "CPH-AIIE-GOVERNANCE-DURABLE-EVIDENCE-STORAGE-CAPABILITY-V2\x00"
	durableEvidenceStorageMaxBytes               = 64 << 20
	durableEvidenceStorageMaxEventIDBytes        = 1024
)

// newDurableEvidenceStorageCapability closes the conversion from a semantic
// Governance evidence capability to its storage representation. In
// particular, a caller never guesses how a signed record or semantic receipt
// is serialized from the public DurableEvidence getters.
func newDurableEvidenceStorageCapability(evidence DurableEvidence,
	expectedAuditEventID string) (DurableEvidenceStorageCapability, error) {
	return newDurableEvidenceStorageCapabilityWithPersistence(evidence, expectedAuditEventID,
		DurableEvidenceStorageReserveNew, [ccse.MessageIDSize]byte{}, 0, false)
}

func newDurableEvidenceStorageCapabilityWithPersistence(evidence DurableEvidence,
	expectedAuditEventID string, disposition DurableEvidenceStorageDisposition,
	pendingKey [ccse.MessageIDSize]byte, pendingRevision uint64,
	hasPendingLink bool) (DurableEvidenceStorageCapability, error) {
	if !validDurableEvidenceStorageText(expectedAuditEventID, durableEvidenceStorageMaxEventIDBytes) ||
		isZeroDigest(evidence.digest) || !validDurableEvidencePersistence(disposition, pendingKey, pendingRevision, hasPendingLink) {
		return DurableEvidenceStorageCapability{}, ErrAuditEvidence
	}
	var (
		kind        DurableEvidenceStorageKind
		contentType string
		canonical   []byte
		err         error
	)
	switch evidence.kind {
	case EvidenceContentSHA256:
		if len(evidence.content) == 0 || len(evidence.content) > durableEvidenceStorageMaxBytes ||
			sha256.Sum256(evidence.content) != evidence.digest || evidence.semanticDomain != "" ||
			evidence.signed.record.MessageTypeID != 0 || len(evidence.authorizationPolicyDigests) != 0 ||
			evidence.keyPreconditionPresent || evidence.keyPrecondition != (KeyStatePrecondition{}) ||
			evidence.authorizationNotAfter != 0 {
			return DurableEvidenceStorageCapability{}, ErrAuditEvidence
		}
		kind = DurableEvidenceStorageContentSHA256
		contentType = DurableEvidenceContentSHA256ContentType
		canonical = append([]byte(nil), evidence.content...)
	case EvidenceSignedCCSERecord:
		kind = DurableEvidenceStorageSignedCCSE
		contentType = DurableEvidenceSignedCCSEContentType
		canonical, err = marshalDurableSignedCCSEEvidence(evidence)
	case EvidenceSemanticReceipt:
		kind = DurableEvidenceStorageSemantic
		contentType = DurableEvidenceSemanticContentType
		canonical, err = marshalDurableSemanticEvidence(evidence)
	default:
		return DurableEvidenceStorageCapability{}, ErrAuditEvidence
	}
	if err != nil || len(canonical) == 0 || len(canonical) > durableEvidenceStorageMaxBytes {
		return DurableEvidenceStorageCapability{}, ErrAuditEvidence
	}
	result := DurableEvidenceStorageCapability{
		evidenceDigest: evidence.digest, kind: kind, contentType: contentType,
		canonicalContent: append([]byte(nil), canonical...), expectedAuditEventID: expectedAuditEventID,
		auditAssertionEventID: expectedAuditEventID,
		disposition:           disposition, hasPendingLink: hasPendingLink, pendingKey: pendingKey, pendingRevision: pendingRevision,
	}
	result.digest, err = digestDurableEvidenceStorageCapability(result)
	if err != nil {
		return DurableEvidenceStorageCapability{}, err
	}
	return result, nil
}

func newDurableEvidenceStorageCapabilities(evidence []DurableEvidence,
	expectedAuditEventID string) ([]DurableEvidenceStorageCapability, error) {
	return newDurableEvidenceStorageCapabilitiesForAudit(evidence, expectedAuditEventID, nil)
}

type durableEvidencePendingLink struct {
	pendingKey      [ccse.MessageIDSize]byte
	pendingRevision uint64
	iamExisting     *durableEvidenceIAMExistingProof
}

// durableEvidenceIAMExistingProof retains IAM's opaque, independently
// verified persistence capability and the exact evidence member selected from
// it. Governance never reconstructs IAM's durable codec or trusts a caller
// supplied digest-to-row map.
type durableEvidenceIAMExistingProof struct {
	request     iam.JoinedAuditRequest
	persistence iam.IAMPendingPersistenceCapability
	evidence    iam.IAMPersistenceEvidenceCapability
}

func newDurableEvidenceStorageCapabilitiesForAudit(evidence []DurableEvidence,
	expectedAuditEventID string,
	existing map[[ccse.DigestSize]byte]durableEvidencePendingLink) ([]DurableEvidenceStorageCapability, error) {
	if len(evidence) == 0 || len(evidence) > 128 {
		return nil, ErrAuditEvidence
	}
	result := make([]DurableEvidenceStorageCapability, len(evidence))
	for index := range evidence {
		disposition := DurableEvidenceStorageReserveNew
		var key [ccse.MessageIDSize]byte
		var revision uint64
		hasPending := false
		if existing != nil {
			if link, found := existing[evidence[index].digest]; found {
				disposition, key, revision, hasPending = DurableEvidenceStorageAssertExisting,
					link.pendingKey, link.pendingRevision, true
				if link.iamExisting != nil {
					capability, err := newIAMExistingEvidenceStorageCapability(evidence[index],
						expectedAuditEventID, link)
					if err != nil {
						return nil, ErrAuditEvidence
					}
					result[index] = capability
					continue
				}
			}
		}
		capability, err := newDurableEvidenceStorageCapabilityWithPersistence(evidence[index], expectedAuditEventID,
			disposition, key, revision, hasPending)
		if err != nil {
			return nil, ErrAuditEvidence
		}
		result[index] = capability
	}
	return result, nil
}

func newIAMExistingEvidenceStorageCapability(evidence DurableEvidence, expectedAuditEventID string,
	link durableEvidencePendingLink) (DurableEvidenceStorageCapability, error) {
	if link.iamExisting == nil || evidence.kind != EvidenceSignedCCSERecord ||
		evidence.signed.recordDigest != evidence.digest ||
		!validDurableEvidenceStorageText(expectedAuditEventID, durableEvidenceStorageMaxEventIDBytes) {
		return DurableEvidenceStorageCapability{}, ErrAuditEvidence
	}
	record := link.iamExisting.evidence.Record()
	result := DurableEvidenceStorageCapability{
		evidenceDigest: evidence.digest, kind: DurableEvidenceStorageKind(record.Kind),
		contentType: record.ContentType, canonicalContent: append([]byte(nil), record.CanonicalContent...),
		expectedAuditEventID: record.ExpectedAuditEventID, auditAssertionEventID: expectedAuditEventID,
		disposition:    DurableEvidenceStorageAssertExisting,
		hasPendingLink: true, pendingKey: link.pendingKey, pendingRevision: link.pendingRevision,
		iamExistingProof: &durableEvidenceIAMExistingProof{
			request: link.iamExisting.request, persistence: link.iamExisting.persistence,
			evidence: link.iamExisting.evidence,
		},
	}
	var err error
	result.digest, err = digestDurableEvidenceStorageCapability(result)
	if err != nil {
		return DurableEvidenceStorageCapability{}, ErrAuditEvidence
	}
	return result, nil
}

func iamPendingEvidenceLinks(request iam.JoinedAuditRequest, sourceDigest [ccse.DigestSize]byte,
	expectedAuditEventID string) (map[[ccse.DigestSize]byte]durableEvidencePendingLink, error) {
	if request.VerifyDigest() != nil || isZeroDigest(sourceDigest) ||
		!validDurableEvidenceStorageText(expectedAuditEventID, durableEvidenceStorageMaxEventIDBytes) {
		return nil, ErrAuditEvidence
	}
	persistence, ok := request.PendingPersistenceCapability()
	if !ok || persistence.VerifyFor(request) != nil {
		return nil, ErrAuditEvidence
	}
	execution, ok := request.ExecutionFragment()
	if !ok || execution.VerifyDigest() != nil {
		return nil, ErrAuditEvidence
	}
	executionPersistence, ok := execution.PendingPersistenceCapability()
	if !ok || executionPersistence.VerifyDigest() != nil ||
		executionPersistence.Digest() != persistence.Digest() {
		return nil, ErrAuditEvidence
	}
	source := persistence.Source()
	expected := request.ParentExpectedSnapshot()
	if source.PendingKey != request.ParentBinding().Key || source.PendingKey != expected.Binding.Key ||
		source.Revision != expected.Version || source.Status != iam.IAMPendingStatusOpen ||
		source.ExpectedAuditEventID != expectedAuditEventID ||
		!containsDigest(source.EvidenceDigestsSHA256, sourceDigest) {
		return nil, ErrAuditEvidence
	}
	selected, found := persistence.EvidenceByDigest(sourceDigest)
	if !found || selected.VerifyDigest() != nil {
		return nil, ErrAuditEvidence
	}
	record := selected.Record()
	if record.Kind != iam.IAMEvidenceSignedCCSERecord ||
		record.ContentType != iam.IAMEvidenceContentTypeSignedCCSERecord ||
		!validDurableEvidenceStorageText(record.ExpectedAuditEventID, durableEvidenceStorageMaxEventIDBytes) {
		return nil, ErrAuditEvidence
	}
	return map[[ccse.DigestSize]byte]durableEvidencePendingLink{
		sourceDigest: {pendingKey: source.PendingKey, pendingRevision: source.Revision,
			iamExisting: &durableEvidenceIAMExistingProof{request: request,
				persistence: persistence, evidence: selected}},
	}, nil
}

func marshalDurableSignedCCSEEvidence(evidence DurableEvidence) ([]byte, error) {
	if evidence.kind != EvidenceSignedCCSERecord || len(evidence.content) != 0 || evidence.semanticDomain != "" ||
		evidence.signed.record.MessageTypeID == 0 || evidence.signed.recordDigest != evidence.digest ||
		len(evidence.signed.record.Signature) != ed25519.SignatureSize {
		return nil, ErrAuditEvidence
	}
	preimage, err := evidence.signed.record.Preimage(ccse.DefaultLimits())
	if err != nil || sha256.Sum256(preimage) != evidence.digest {
		return nil, ErrAuditEvidence
	}
	return ccse.Marshal(durableEvidenceStorageMaxBytes, func(out *ccse.Encoder) {
		out.Uint32(durableEvidenceStorageCodecVersion)
		out.String(durableSignedCCSEStorageCodec)
		out.Bytes(preimage)
		out.FixedBytes(evidence.signed.record.Signature, ed25519.SignatureSize)
	})
}

func marshalDurableSemanticEvidence(evidence DurableEvidence) ([]byte, error) {
	if evidence.kind != EvidenceSemanticReceipt || evidence.semanticDomain != iamAuditEvidenceReceiptDomain ||
		len(evidence.content) == 0 || len(evidence.content) > durableEvidenceStorageMaxBytes ||
		domainSeparatedContentDigest(iamAuditEvidenceBundleDigestDomain, evidence.content) != evidence.digest ||
		evidence.signed.record.MessageTypeID != 0 || len(evidence.authorizationPolicyDigests) != 0 ||
		evidence.keyPreconditionPresent || evidence.keyPrecondition != (KeyStatePrecondition{}) ||
		evidence.authorizationNotAfter != 0 {
		return nil, ErrAuditEvidence
	}
	return ccse.Marshal(durableEvidenceStorageMaxBytes, func(out *ccse.Encoder) {
		out.Uint32(durableEvidenceStorageCodecVersion)
		out.String(durableSemanticStorageCodec)
		out.String(evidence.semanticDomain)
		out.Bytes(evidence.content)
	})
}

func validateDurableSignedCCSEStorageContent(content []byte,
	expectedDigest [ccse.DigestSize]byte) error {
	var preimage []byte
	err := ccse.Unmarshal(content, durableEvidenceStorageMaxBytes, func(in *ccse.Decoder) error {
		version, err := in.Uint32()
		if err != nil || version != durableEvidenceStorageCodecVersion {
			return ErrAuditEvidence
		}
		codec, err := in.String(255)
		if err != nil || codec != durableSignedCCSEStorageCodec {
			return ErrAuditEvidence
		}
		preimage, err = in.Bytes(ccse.DefaultLimits().MaxDomainBytes + ccse.DefaultLimits().MaxEnvelopeBytes +
			ccse.DefaultLimits().MaxPayloadBytes + 64)
		if err != nil || len(preimage) == 0 {
			return ErrAuditEvidence
		}
		signature, err := in.FixedBytes(ed25519.SignatureSize)
		if err != nil || len(signature) != ed25519.SignatureSize {
			return ErrAuditEvidence
		}
		return nil
	})
	if err != nil || sha256.Sum256(preimage) != expectedDigest {
		return ErrAuditEvidence
	}
	return nil
}

func validateDurableSemanticStorageContent(content []byte,
	expectedDigest [ccse.DigestSize]byte) error {
	var domain string
	var receipt []byte
	err := ccse.Unmarshal(content, durableEvidenceStorageMaxBytes, func(in *ccse.Decoder) error {
		version, err := in.Uint32()
		if err != nil || version != durableEvidenceStorageCodecVersion {
			return ErrAuditEvidence
		}
		codec, err := in.String(255)
		if err != nil || codec != durableSemanticStorageCodec {
			return ErrAuditEvidence
		}
		domain, err = in.String(255)
		if err != nil || domain != iamAuditEvidenceReceiptDomain {
			return ErrAuditEvidence
		}
		receipt, err = in.Bytes(durableEvidenceStorageMaxBytes)
		if err != nil || len(receipt) == 0 {
			return ErrAuditEvidence
		}
		return nil
	})
	if err != nil || domainSeparatedContentDigest(iamAuditEvidenceBundleDigestDomain, receipt) != expectedDigest {
		return ErrAuditEvidence
	}
	return nil
}

// DecodeDurableEvidenceSnapshot is the inert inverse of the closed storage
// codecs. It grants no authorization: signed evidence carries no reconstructed
// VerifiedRecord and is re-authorized by Planner against IAM on use.
func DecodeDurableEvidenceSnapshot(kind uint8, contentType string,
	expectedDigest [ccse.DigestSize]byte, content []byte) (EvidenceSnapshot, error) {
	if isZeroDigest(expectedDigest) || len(content) == 0 || len(content) > durableEvidenceStorageMaxBytes {
		return EvidenceSnapshot{}, ErrAuditEvidence
	}
	switch DurableEvidenceStorageKind(kind) {
	case DurableEvidenceStorageContentSHA256:
		if contentType != DurableEvidenceContentSHA256ContentType || sha256.Sum256(content) != expectedDigest {
			return EvidenceSnapshot{}, ErrAuditEvidence
		}
		return EvidenceSnapshot{Kind: EvidenceContentSHA256, DigestSHA256: expectedDigest,
			Content: append([]byte(nil), content...)}, nil
	case DurableEvidenceStorageSignedCCSE:
		if contentType != DurableEvidenceSignedCCSEContentType {
			return EvidenceSnapshot{}, ErrAuditEvidence
		}
		var preimage, signature []byte
		err := ccse.Unmarshal(content, durableEvidenceStorageMaxBytes, func(in *ccse.Decoder) error {
			version, err := in.Uint32()
			if err != nil || version != durableEvidenceStorageCodecVersion {
				return ErrAuditEvidence
			}
			codec, err := in.String(255)
			if err != nil || codec != durableSignedCCSEStorageCodec {
				return ErrAuditEvidence
			}
			preimage, err = in.Bytes(ccse.DefaultLimits().MaxDomainBytes + ccse.DefaultLimits().MaxEnvelopeBytes +
				ccse.DefaultLimits().MaxPayloadBytes + 128)
			if err != nil {
				return err
			}
			signature, err = in.FixedBytes(ed25519.SignatureSize)
			return err
		})
		if err != nil || sha256.Sum256(preimage) != expectedDigest {
			return EvidenceSnapshot{}, ErrAuditEvidence
		}
		record, err := ccse.ParseRecordPreimage(preimage, signature, ccse.DefaultLimits())
		if err != nil {
			return EvidenceSnapshot{}, ErrAuditEvidence
		}
		return EvidenceSnapshot{Kind: EvidenceSignedCCSERecord, DigestSHA256: expectedDigest,
			Signed: SignedRecord{Record: &record}}, nil
	case DurableEvidenceStorageSemantic:
		if contentType != DurableEvidenceSemanticContentType {
			return EvidenceSnapshot{}, ErrAuditEvidence
		}
		var domain string
		var receipt []byte
		err := ccse.Unmarshal(content, durableEvidenceStorageMaxBytes, func(in *ccse.Decoder) error {
			version, err := in.Uint32()
			if err != nil || version != durableEvidenceStorageCodecVersion {
				return ErrAuditEvidence
			}
			codec, err := in.String(255)
			if err != nil || codec != durableSemanticStorageCodec {
				return ErrAuditEvidence
			}
			if domain, err = in.String(255); err != nil {
				return err
			}
			receipt, err = in.Bytes(durableEvidenceStorageMaxBytes)
			return err
		})
		if err != nil || domain != iamAuditEvidenceReceiptDomain ||
			domainSeparatedContentDigest(iamAuditEvidenceBundleDigestDomain, receipt) != expectedDigest {
			return EvidenceSnapshot{}, ErrAuditEvidence
		}
		return EvidenceSnapshot{Kind: EvidenceSemanticReceipt, DigestSHA256: expectedDigest,
			Content: append([]byte(nil), receipt...)}, nil
	default:
		return EvidenceSnapshot{}, ErrAuditEvidence
	}
}

func digestDurableEvidenceStorageCapability(value DurableEvidenceStorageCapability) ([ccse.DigestSize]byte, error) {
	if isZeroDigest(value.evidenceDigest) ||
		!validDurableEvidenceStorageText(value.expectedAuditEventID, durableEvidenceStorageMaxEventIDBytes) ||
		!validDurableEvidenceStorageText(value.auditAssertionEventID, durableEvidenceStorageMaxEventIDBytes) ||
		len(value.canonicalContent) == 0 ||
		len(value.canonicalContent) > durableEvidenceStorageMaxBytes ||
		!validDurableEvidencePersistence(value.disposition, value.pendingKey, value.pendingRevision, value.hasPendingLink) {
		return [ccse.DigestSize]byte{}, ErrAuditEvidence
	}
	switch value.kind {
	case DurableEvidenceStorageContentSHA256:
		if value.iamExistingProof != nil || value.contentType != DurableEvidenceContentSHA256ContentType ||
			sha256.Sum256(value.canonicalContent) != value.evidenceDigest {
			return [ccse.DigestSize]byte{}, ErrAuditEvidence
		}
	case DurableEvidenceStorageSignedCCSE:
		if value.iamExistingProof == nil {
			if value.contentType != DurableEvidenceSignedCCSEContentType ||
				validateDurableSignedCCSEStorageContent(value.canonicalContent, value.evidenceDigest) != nil {
				return [ccse.DigestSize]byte{}, ErrAuditEvidence
			}
		} else if !validIAMExistingEvidenceProof(value) {
			return [ccse.DigestSize]byte{}, ErrAuditEvidence
		}
	case DurableEvidenceStorageSemantic:
		if value.iamExistingProof != nil || value.contentType != DurableEvidenceSemanticContentType ||
			validateDurableSemanticStorageContent(value.canonicalContent, value.evidenceDigest) != nil {
			return [ccse.DigestSize]byte{}, ErrAuditEvidence
		}
	default:
		return [ccse.DigestSize]byte{}, ErrAuditEvidence
	}
	w := newDigestWriter(durableEvidenceStorageCapabilityDigestDomain)
	w.digest(value.evidenceDigest)
	w.uint8(uint8(value.kind))
	w.string(value.contentType)
	w.bytes(value.canonicalContent)
	w.string(value.expectedAuditEventID)
	w.string(value.auditAssertionEventID)
	w.uint8(uint8(value.disposition))
	w.bool(value.hasPendingLink)
	w.bytes(value.pendingKey[:])
	w.uint64(value.pendingRevision)
	w.bool(value.iamExistingProof != nil)
	if value.iamExistingProof != nil {
		w.digest(value.iamExistingProof.request.Digest())
		w.digest(value.iamExistingProof.persistence.Digest())
		w.digest(value.iamExistingProof.evidence.Digest())
	}
	return w.sum()
}

func validIAMExistingEvidenceProof(value DurableEvidenceStorageCapability) bool {
	proof := value.iamExistingProof
	if proof == nil || value.kind != DurableEvidenceStorageSignedCCSE ||
		value.disposition != DurableEvidenceStorageAssertExisting || !value.hasPendingLink ||
		proof.request.VerifyDigest() != nil || proof.persistence.VerifyFor(proof.request) != nil ||
		proof.evidence.VerifyDigest() != nil {
		return false
	}
	source := proof.persistence.Source()
	if source.PendingKey != value.pendingKey || source.Revision != value.pendingRevision ||
		source.Status != iam.IAMPendingStatusOpen || source.ExpectedAuditEventID != value.auditAssertionEventID ||
		proof.request.JoinedAuditEventID() != value.auditAssertionEventID ||
		!containsDigest(source.EvidenceDigestsSHA256, value.evidenceDigest) {
		return false
	}
	record := proof.evidence.Record()
	if record.DigestSHA256 != value.evidenceDigest || record.Kind != iam.IAMEvidenceSignedCCSERecord ||
		record.ContentType != iam.IAMEvidenceContentTypeSignedCCSERecord ||
		DurableEvidenceStorageKind(record.Kind) != value.kind || record.ContentType != value.contentType ||
		!bytes.Equal(record.CanonicalContent, value.canonicalContent) ||
		record.ExpectedAuditEventID != value.expectedAuditEventID {
		return false
	}
	found := false
	for _, candidate := range proof.persistence.Evidence() {
		if candidate.VerifyDigest() != nil {
			return false
		}
		candidateRecord := candidate.Record()
		if candidate.Digest() == proof.evidence.Digest() && equalIAMPersistenceEvidenceRecords(candidateRecord, record) {
			if found {
				return false
			}
			found = true
		}
	}
	return found
}

func equalIAMPersistenceEvidenceRecords(left, right iam.IAMPersistenceEvidenceRecord) bool {
	return left.DigestSHA256 == right.DigestSHA256 && left.Kind == right.Kind &&
		left.ContentType == right.ContentType && bytes.Equal(left.CanonicalContent, right.CanonicalContent) &&
		left.ExpectedAuditEventID == right.ExpectedAuditEventID
}

func validDurableEvidencePersistence(disposition DurableEvidenceStorageDisposition,
	pendingKey [ccse.MessageIDSize]byte, pendingRevision uint64, hasPendingLink bool) bool {
	if disposition != DurableEvidenceStorageReserveNew && disposition != DurableEvidenceStorageAssertExisting {
		return false
	}
	if hasPendingLink {
		return disposition == DurableEvidenceStorageAssertExisting &&
			pendingKey != ([ccse.MessageIDSize]byte{}) && pendingRevision != 0
	}
	return pendingKey == ([ccse.MessageIDSize]byte{}) && pendingRevision == 0
}

func validDurableEvidenceStorageText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) &&
		strings.TrimSpace(value) == value && strings.IndexByte(value, 0) < 0
}

func cloneDurableEvidenceStorageCapabilities(input []DurableEvidenceStorageCapability) []DurableEvidenceStorageCapability {
	result := make([]DurableEvidenceStorageCapability, len(input))
	for index := range input {
		result[index] = input[index]
		result[index].canonicalContent = append([]byte(nil), input[index].canonicalContent...)
		if input[index].iamExistingProof != nil {
			copy := *input[index].iamExistingProof
			result[index].iamExistingProof = &copy
		}
	}
	return result
}

func equalDurableEvidenceStorageCapabilities(left, right DurableEvidenceStorageCapability) bool {
	return left.evidenceDigest == right.evidenceDigest && left.kind == right.kind &&
		left.contentType == right.contentType && bytes.Equal(left.canonicalContent, right.canonicalContent) &&
		left.expectedAuditEventID == right.expectedAuditEventID &&
		left.auditAssertionEventID == right.auditAssertionEventID && left.disposition == right.disposition &&
		left.hasPendingLink == right.hasPendingLink && left.pendingKey == right.pendingKey &&
		left.pendingRevision == right.pendingRevision && equalIAMExistingProofs(left.iamExistingProof, right.iamExistingProof) &&
		left.digest == right.digest
}

func equalIAMExistingProofs(left, right *durableEvidenceIAMExistingProof) bool {
	if (left == nil) != (right == nil) {
		return false
	}
	return left == nil || (left.request.Digest() == right.request.Digest() &&
		left.persistence.Digest() == right.persistence.Digest() &&
		left.evidence.Digest() == right.evidence.Digest())
}
