// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"bytes"
	"context"
	"crypto/sha256"
	"sort"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
)

const iamCollectionAdvanceCapabilityDomain = "CPH-AIIE-IAM-COLLECTION-ADVANCE-CAPABILITY-V1\x00"

// IAMCollectionAdvanceCapability is the complete storage-neutral capability
// for one kind-3 approval append after revision 1. It binds the exact OPEN
// predecessor, its linked evidence, the newly ingested outer CCSE record, the
// next same-kind OPEN revision, evidence dispositions, X advance/Y assertion,
// global assertions and the complete canonical read set.
type IAMCollectionAdvanceCapability struct {
	source            IAMPendingStoredRevision
	sourceEvidence    []IAMPersistenceEvidenceCapability
	next              IAMPendingRevision
	evidence          []IAMEvidenceStorageCapability
	state             IAMPendingAdmissionStateCapability
	advanceClaims     []idempotency.Claim
	joinedExpected    idempotency.Snapshot
	identifierClaims  []globalid.Claim
	outerRecord       ccse.Record
	outerRecordDigest [sha256.Size]byte
	auditEventID      string
	pendingDigest     [sha256.Size]byte
	envelopeDigest    [sha256.Size]byte
	digest            [sha256.Size]byte
}

func (value IAMCollectionAdvanceCapability) Source() IAMPendingStoredRevision {
	return cloneIAMPendingStoredRevision(value.source)
}
func (value IAMCollectionAdvanceCapability) SourceEvidence() []IAMPersistenceEvidenceCapability {
	result := make([]IAMPersistenceEvidenceCapability, len(value.sourceEvidence))
	for index := range value.sourceEvidence {
		result[index] = IAMPersistenceEvidenceCapability{
			record: cloneIAMPersistenceEvidenceRecord(value.sourceEvidence[index].record),
			digest: value.sourceEvidence[index].digest}
	}
	return result
}
func (value IAMCollectionAdvanceCapability) NextRevision() IAMPendingRevision {
	return IAMPendingRevision{record: cloneIAMPendingRevisionRecord(value.next.record),
		digest: value.next.digest}
}
func (value IAMCollectionAdvanceCapability) EvidenceStorageCapabilities() []IAMEvidenceStorageCapability {
	result := make([]IAMEvidenceStorageCapability, len(value.evidence))
	for index := range value.evidence {
		result[index] = cloneIAMEvidenceStorageCapability(value.evidence[index])
	}
	return result
}
func (value IAMCollectionAdvanceCapability) CanonicalStateReads() IAMPendingAdmissionStateCapability {
	return cloneIAMPendingAdmissionStateCapability(value.state)
}
func (value IAMCollectionAdvanceCapability) IdempotencyAdvanceClaims() []idempotency.Claim {
	return append([]idempotency.Claim(nil), value.advanceClaims...)
}
func (value IAMCollectionAdvanceCapability) JoinedExpectedSnapshot() idempotency.Snapshot {
	return value.joinedExpected
}
func (value IAMCollectionAdvanceCapability) IdentifierClaims() []globalid.Claim {
	return append([]globalid.Claim(nil), value.identifierClaims...)
}
func (value IAMCollectionAdvanceCapability) OuterRecord() (ccse.Record, bool) {
	if value.outerRecordDigest == ([sha256.Size]byte{}) {
		return ccse.Record{}, false
	}
	return cloneCCSERecord(value.outerRecord), true
}
func (value IAMCollectionAdvanceCapability) OuterRecordDigest() [sha256.Size]byte {
	return value.outerRecordDigest
}
func (value IAMCollectionAdvanceCapability) AuditEventID() string { return value.auditEventID }
func (value IAMCollectionAdvanceCapability) PendingDigest() [sha256.Size]byte {
	return value.pendingDigest
}
func (value IAMCollectionAdvanceCapability) DurableEnvelopeDigest() [sha256.Size]byte {
	return value.envelopeDigest
}
func (value IAMCollectionAdvanceCapability) Digest() [sha256.Size]byte { return value.digest }
func (value IAMCollectionAdvanceCapability) VerifyDigest() error {
	digest, err := digestIAMCollectionAdvanceCapability(value)
	if err != nil || digest != value.digest {
		return ErrPendingPlanInvalid
	}
	return nil
}
func (value IAMCollectionAdvanceCapability) VerifyOuter(outer ccse.VerifiedRecord) error {
	if value.VerifyDigest() != nil || outer.Digest() != value.outerRecordDigest ||
		!sameCCSERecord(value.outerRecord, outer.Record()) {
		return ErrAuthorizationMismatch
	}
	return nil
}
func (value IAMCollectionAdvanceCapability) VerifyFor(envelope DurablePendingEnvelope) error {
	if value.VerifyDigest() != nil || !envelope.capability || envelope.VerifyDigest() != nil ||
		envelope.Kind() != DurablePendingOwnershipTransferCollection ||
		value.pendingDigest != envelope.PendingDigest() || value.envelopeDigest != envelope.Digest() {
		return ErrPendingPlanInvalid
	}
	plan, ok := envelope.OwnershipTransferCollectionPlan()
	if !ok || plan.Disposition() != OwnershipTransferCollectionReplace ||
		plan.Digest() != value.pendingDigest || value.auditEventID == "" ||
		!sameIdempotencyClaims(plan.IdempotencyClaims(), value.advanceClaims) ||
		!sameGlobalClaims(plan.IdentifierClaims(), value.identifierClaims) {
		return ErrPendingPlanInvalid
	}
	joined, present := plan.JoinedAuditSnapshot()
	if !present || joined != value.joinedExpected ||
		verifyCollectionAdvanceState(value.state, envelope, value.auditEventID) != nil {
		return ErrPendingPlanInvalid
	}
	outer, outerDigest, err := collectionAdvanceOuter(value.source, plan)
	if err != nil || outerDigest != value.outerRecordDigest || !sameCCSERecord(outer, value.outerRecord) {
		return ErrPendingPlanInvalid
	}
	if validateCollectionAdvanceSource(value.source, value.sourceEvidence, plan,
		value.auditEventID) != nil {
		return ErrPendingPlanInvalid
	}
	metadata := collectionAdvanceEvidenceMetadata(plan, value.outerRecord, value.outerRecordDigest,
		value.auditEventID)
	expectedRecords, err := pendingAdmissionEvidenceRecords(envelope, value.state.digest, metadata)
	if err != nil {
		return ErrPendingPlanInvalid
	}
	combined, err := combineCollectionAdvanceEvidence(value.sourceEvidence, expectedRecords)
	if err != nil || !sameCollectionAdvanceEvidenceActions(value.evidence, combined,
		value.source, value.auditEventID) {
		return ErrPendingPlanInvalid
	}
	next := value.next.Record()
	if next.PendingKey != plan.next.Binding.Key || next.ExpectedKind != DurablePendingOwnershipTransferCollection ||
		next.Kind != DurablePendingOwnershipTransferCollection || next.Revision != value.source.Revision+1 ||
		next.PreviousEnvelopeDigestSHA256 != value.source.EnvelopeDigestSHA256 ||
		!bytes.Equal(next.PreviousCanonicalEnvelope, value.source.CanonicalEnvelope) ||
		next.PreviousCommitNotBeforeUnixNano != value.source.CommitNotBeforeUnixNano ||
		next.PreviousCommitNotAfterUnixNano != value.source.CommitNotAfterUnixNano ||
		next.EnvelopeDigestSHA256 != envelope.Digest() ||
		!bytes.Equal(next.CanonicalEnvelope, envelope.encoded) ||
		!equalDigestSlices(next.EvidenceDigestsSHA256, admissionEvidenceDigests(combined)) ||
		next.Status != IAMPendingStatusOpen || next.CommitNotBeforeUnixNano != plan.CommitNotBeforeUnixNano() ||
		next.CommitNotAfterUnixNano != plan.CommitNotAfterUnixNano() ||
		next.ExpectedAuditEventID != value.auditEventID {
		return ErrPendingPlanInvalid
	}
	return nil
}

// BindCollectionAdvanceCapability validates and freezes one same-kind OPEN
// collection revision. It is intentionally separate from first admission so
// an adapter cannot reinterpret an absent-row insert as an update or vice
// versa.
func (p *Planner) BindCollectionAdvanceCapability(ctx context.Context,
	envelope DurablePendingEnvelope) (IAMCollectionAdvanceCapability, error) {
	if err := p.ready(); err != nil {
		return IAMCollectionAdvanceCapability{}, err
	}
	if err := ctx.Err(); err != nil {
		return IAMCollectionAdvanceCapability{}, err
	}
	if !envelope.capability || envelope.VerifyDigest() != nil ||
		envelope.Kind() != DurablePendingOwnershipTransferCollection {
		return IAMCollectionAdvanceCapability{}, ErrPendingPlanInvalid
	}
	plan, ok := envelope.OwnershipTransferCollectionPlan()
	if !ok || plan.Disposition() != OwnershipTransferCollectionReplace || plan.expectedVersion == 0 {
		return IAMCollectionAdvanceCapability{}, ErrPendingPlanInvalid
	}
	eventID, err := idempotency.JoinedAuditEventID(plan.next.Binding)
	if err != nil {
		return IAMCollectionAdvanceCapability{}, ErrPendingPlanInvalid
	}
	persistenceView, ok := p.view.(IAMPendingPersistenceView)
	if !ok {
		return IAMCollectionAdvanceCapability{}, ErrViewRequired
	}
	evidenceView, ok := p.view.(IAMPendingAdmissionEvidenceView)
	if !ok {
		return IAMCollectionAdvanceCapability{}, ErrViewRequired
	}
	canonicalView, ok := p.view.(CanonicalIAMStateView)
	if !ok {
		return IAMCollectionAdvanceCapability{}, ErrViewRequired
	}
	sidecarView, ok := p.view.(CanonicalIAMSidecarStateView)
	if !ok {
		return IAMCollectionAdvanceCapability{}, ErrViewRequired
	}
	source, sourceRecords, found, err := persistenceView.SnapshotIAMPendingPersistence(ctx,
		plan.next.Binding.Key, plan.expectedVersion, nil)
	if err != nil {
		return IAMCollectionAdvanceCapability{}, err
	}
	if !found {
		return IAMCollectionAdvanceCapability{}, ErrViewInconsistent
	}
	sourceEvidence, err := validateIAMPersistenceEvidence(sourceRecords,
		source.EvidenceDigestsSHA256)
	if err != nil || validateCollectionAdvanceSource(source, sourceEvidence, plan, eventID) != nil {
		return IAMCollectionAdvanceCapability{}, ErrViewInconsistent
	}
	outer, outerDigest, err := collectionAdvanceOuter(source, plan)
	if err != nil {
		return IAMCollectionAdvanceCapability{}, err
	}
	state, err := p.bindOwnershipTransferCollectionState(ctx, envelope, eventID,
		canonicalView, sidecarView)
	if err != nil || verifyCollectionAdvanceState(state, envelope, eventID) != nil {
		return IAMCollectionAdvanceCapability{}, ErrPendingPlanInvalid
	}
	metadata := collectionAdvanceEvidenceMetadata(plan, outer, outerDigest, eventID)
	expectedRecords, err := pendingAdmissionEvidenceRecords(envelope, state.digest, metadata)
	if err != nil {
		return IAMCollectionAdvanceCapability{}, err
	}
	combined, err := combineCollectionAdvanceEvidence(sourceEvidence, expectedRecords)
	if err != nil {
		return IAMCollectionAdvanceCapability{}, err
	}
	sourceByDigest := make(map[[sha256.Size]byte]IAMPersistenceEvidenceCapability,
		len(sourceEvidence))
	for _, evidence := range sourceEvidence {
		sourceByDigest[evidence.record.DigestSHA256] = evidence
	}
	actions := make([]IAMEvidenceStorageCapability, len(combined))
	for index, record := range combined {
		if _, linked := sourceByDigest[record.DigestSHA256]; linked {
			action, actionErr := newLinkedIAMEvidenceStorageAssertion(record, source, eventID)
			if actionErr != nil {
				return IAMCollectionAdvanceCapability{}, actionErr
			}
			actions[index] = action
			continue
		}
		stored, exists, lookupErr := evidenceView.LookupIAMPendingAdmissionEvidence(ctx,
			record.DigestSHA256)
		if lookupErr != nil {
			return IAMCollectionAdvanceCapability{}, lookupErr
		}
		if exists {
			if !equalIAMPersistenceEvidenceRecords(stored, record) {
				return IAMCollectionAdvanceCapability{}, ErrViewInconsistent
			}
		} else if nonzeroIAMPersistenceEvidenceRecord(stored) {
			return IAMCollectionAdvanceCapability{}, ErrViewInconsistent
		}
		disposition := IAMEvidenceStorageReserveNew
		if exists {
			disposition = IAMEvidenceStorageAssertExisting
		}
		action, actionErr := newIAMEvidenceStorageAction(record, disposition, eventID)
		if actionErr != nil {
			return IAMCollectionAdvanceCapability{}, actionErr
		}
		actions[index] = action
	}
	next, err := newIAMPendingRevision(IAMPendingRevisionRecord{
		PendingKey: plan.next.Binding.Key, ExpectedKind: DurablePendingOwnershipTransferCollection,
		Kind: DurablePendingOwnershipTransferCollection, Codec: durablePendingCodec,
		CodecVersion: durablePendingCodecVersion, Revision: source.Revision + 1,
		PreviousEnvelopeDigestSHA256:    source.EnvelopeDigestSHA256,
		PreviousCanonicalEnvelope:       append([]byte(nil), source.CanonicalEnvelope...),
		PreviousCommitNotBeforeUnixNano: source.CommitNotBeforeUnixNano,
		PreviousCommitNotAfterUnixNano:  source.CommitNotAfterUnixNano,
		EnvelopeDigestSHA256:            envelope.Digest(), CanonicalEnvelope: envelope.Bytes(),
		EvidenceDigestsSHA256: admissionEvidenceDigests(combined), Status: IAMPendingStatusOpen,
		CommitNotBeforeUnixNano: plan.CommitNotBeforeUnixNano(),
		CommitNotAfterUnixNano:  plan.CommitNotAfterUnixNano(), ExpectedAuditEventID: eventID,
	})
	if err != nil {
		return IAMCollectionAdvanceCapability{}, err
	}
	joined, present := plan.JoinedAuditSnapshot()
	if !present {
		return IAMCollectionAdvanceCapability{}, ErrPendingPlanInvalid
	}
	capability := IAMCollectionAdvanceCapability{source: cloneIAMPendingStoredRevision(source),
		sourceEvidence: sourceEvidence, next: next, evidence: actions, state: state,
		advanceClaims: plan.IdempotencyClaims(), joinedExpected: joined,
		identifierClaims: plan.IdentifierClaims(), outerRecord: cloneCCSERecord(outer),
		outerRecordDigest: outerDigest, auditEventID: eventID, pendingDigest: plan.Digest(),
		envelopeDigest: envelope.Digest()}
	capability.digest, err = digestIAMCollectionAdvanceCapability(capability)
	if err != nil || capability.VerifyFor(envelope) != nil {
		return IAMCollectionAdvanceCapability{}, ErrPendingPlanInvalid
	}
	return capability, nil
}

func validateCollectionAdvanceSource(source IAMPendingStoredRevision,
	evidence []IAMPersistenceEvidenceCapability, next OwnershipTransferApprovalCollectionPlan,
	eventID string) error {
	if !validIAMPendingStoredRevision(source) || source.Kind != DurablePendingOwnershipTransferCollection ||
		source.PendingKey != next.next.Binding.Key || source.Revision != next.expectedVersion ||
		source.ExpectedAuditEventID != eventID || len(evidence) != len(source.EvidenceDigestsSHA256) {
		return ErrViewInconsistent
	}
	decoded, err := decodeDurablePendingEnvelope(source.CanonicalEnvelope)
	if err != nil || decoded.Kind() != DurablePendingOwnershipTransferCollection || decoded.transfer == nil ||
		decoded.Digest() != source.EnvelopeDigestSHA256 {
		return ErrViewInconsistent
	}
	previous := decoded.transfer
	_, notBefore, notAfter, err := durableEnvelopeFullWindow(decoded)
	if err != nil || notBefore != source.CommitNotBeforeUnixNano ||
		notAfter != source.CommitNotAfterUnixNano || previous.next.Binding != next.next.Binding ||
		previous.next.Version != next.expectedVersion ||
		previous.next.ProgressDigest != next.expectedProgressDigest ||
		previous.next.HomeRegion != next.expectedHomeRegion ||
		previous.next.WriterEpoch != next.expectedWriterEpoch ||
		!sameTransferCollectionFixedFields(previous.next, next.next) {
		return ErrViewInconsistent
	}
	for index, digest := range source.EvidenceDigestsSHA256 {
		if evidence[index].VerifyDigest() != nil || evidence[index].record.DigestSHA256 != digest ||
			evidence[index].record.ExpectedAuditEventID != eventID {
			return ErrViewInconsistent
		}
	}
	if validateCollectionAdvanceSourceEvidence(source, evidence, decoded, eventID) != nil {
		return ErrViewInconsistent
	}
	return nil
}

type pendingAdmissionReceiptSnapshot struct {
	kind                    DurablePendingKind
	pendingDigest           [sha256.Size]byte
	envelopeDigest          [sha256.Size]byte
	envelopeLength          uint64
	semanticAdmissionDigest [sha256.Size]byte
	stateDigest             [sha256.Size]byte
	auditEventID            string
	commitNotBefore         int64
	commitNotAfter          int64
	idempotencyBytes        []byte
	identifierBytes         []byte
	signedDigests           [][sha256.Size]byte
}

func validateCollectionAdvanceSourceEvidence(source IAMPendingStoredRevision,
	evidence []IAMPersistenceEvidenceCapability, decoded DurablePendingEnvelope,
	eventID string) error {
	if decoded.transfer == nil || decoded.Kind() != DurablePendingOwnershipTransferCollection {
		return ErrViewInconsistent
	}
	// Internal decoding is inert. This local copy is used only to derive the
	// exact signed preimages already checked against the current collection;
	// it is never returned as an authorization capability.
	sourceEnvelope := decoded
	sourceEnvelope.capability = true
	expectedSigned, err := pendingAdmissionSignedRecords(sourceEnvelope, eventID)
	if err != nil {
		return ErrViewInconsistent
	}
	signedByDigest := make(map[[sha256.Size]byte]IAMPersistenceEvidenceRecord,
		len(expectedSigned))
	for _, record := range expectedSigned {
		signedByDigest[record.DigestSHA256] = record
	}
	receiptCount, currentReceiptCount := 0, 0
	for _, capability := range evidence {
		record := capability.record
		if expected, found := signedByDigest[record.DigestSHA256]; found {
			if !equalIAMPersistenceEvidenceRecords(record, expected) {
				return ErrViewInconsistent
			}
			delete(signedByDigest, record.DigestSHA256)
			continue
		}
		if record.Kind != IAMEvidenceSemanticReceipt ||
			record.ContentType != IAMPendingAdmissionEvidenceContentType {
			return ErrViewInconsistent
		}
		receipt, parseErr := decodePendingAdmissionReceipt(record.CanonicalContent)
		if parseErr != nil || receipt.kind != DurablePendingOwnershipTransferCollection ||
			receipt.auditEventID != eventID || receipt.pendingDigest == ([sha256.Size]byte{}) ||
			receipt.envelopeDigest == ([sha256.Size]byte{}) || receipt.envelopeLength == 0 ||
			receipt.semanticAdmissionDigest == ([sha256.Size]byte{}) ||
			receipt.stateDigest == ([sha256.Size]byte{}) || receipt.commitNotBefore <= 0 ||
			receipt.commitNotAfter <= receipt.commitNotBefore ||
			len(receipt.idempotencyBytes) == 0 || len(receipt.identifierBytes) == 0 ||
			len(receipt.signedDigests) == 0 || !canonicalDigestList(receipt.signedDigests) {
			return ErrViewInconsistent
		}
		receiptCount++
		if pendingAdmissionReceiptMatchesSource(receipt, source, *decoded.transfer,
			expectedSigned) {
			currentReceiptCount++
		}
	}
	if source.Revision > iamMaxPendingEvidenceRecords || len(signedByDigest) != 0 ||
		receiptCount != int(source.Revision) ||
		currentReceiptCount != 1 || len(evidence) != len(expectedSigned)+receiptCount {
		return ErrViewInconsistent
	}
	return nil
}

func decodePendingAdmissionReceipt(encoded []byte) (pendingAdmissionReceiptSnapshot, error) {
	var result pendingAdmissionReceiptSnapshot
	err := ccse.Unmarshal(encoded, iamPendingAdmissionReceiptMaxBytes, func(in *ccse.Decoder) error {
		kind, err := in.Uint32()
		if err != nil {
			return err
		}
		result.kind = DurablePendingKind(kind)
		value, err := in.FixedBytes(sha256.Size)
		if err != nil {
			return err
		}
		copy(result.pendingDigest[:], value)
		value, err = in.FixedBytes(sha256.Size)
		if err != nil {
			return err
		}
		copy(result.envelopeDigest[:], value)
		if result.envelopeLength, err = in.Uint64(); err != nil {
			return err
		}
		value, err = in.FixedBytes(sha256.Size)
		if err != nil {
			return err
		}
		copy(result.semanticAdmissionDigest[:], value)
		value, err = in.FixedBytes(sha256.Size)
		if err != nil {
			return err
		}
		copy(result.stateDigest[:], value)
		if result.auditEventID, err = in.String(1024); err != nil {
			return err
		}
		if result.commitNotBefore, err = in.Int64(); err != nil {
			return err
		}
		if result.commitNotAfter, err = in.Int64(); err != nil {
			return err
		}
		if result.idempotencyBytes, err = in.Bytes(idempotency.MaxCanonicalClaimBytes); err != nil {
			return err
		}
		if result.identifierBytes, err = in.Bytes(globalid.MaxCanonicalBytes); err != nil {
			return err
		}
		count, err := in.Uint32()
		if err != nil || count > iamMaxPendingEvidenceRecords {
			return ErrPendingPlanInvalid
		}
		result.signedDigests = make([][sha256.Size]byte, count)
		for index := range result.signedDigests {
			value, err = in.FixedBytes(sha256.Size)
			if err != nil {
				return err
			}
			copy(result.signedDigests[index][:], value)
		}
		return nil
	})
	if err != nil {
		return pendingAdmissionReceiptSnapshot{}, err
	}
	return result, nil
}

func pendingAdmissionReceiptMatchesSource(receipt pendingAdmissionReceiptSnapshot,
	source IAMPendingStoredRevision, plan OwnershipTransferApprovalCollectionPlan,
	signed []IAMPersistenceEvidenceRecord) bool {
	idempotencyBytes, err := idempotency.CanonicalBytes(plan.IdempotencyClaims())
	if err != nil {
		return false
	}
	identifierBytes, err := globalid.CanonicalBytes(plan.IdentifierClaims())
	if err != nil {
		return false
	}
	signedDigests := make([][sha256.Size]byte, len(signed))
	for index := range signed {
		signedDigests[index] = signed[index].DigestSHA256
	}
	return receipt.pendingDigest == plan.Digest() &&
		receipt.envelopeDigest == source.EnvelopeDigestSHA256 &&
		receipt.envelopeLength == uint64(len(source.CanonicalEnvelope)) &&
		receipt.semanticAdmissionDigest == plan.Digest() &&
		receipt.auditEventID == source.ExpectedAuditEventID &&
		receipt.commitNotBefore == source.CommitNotBeforeUnixNano &&
		receipt.commitNotAfter == source.CommitNotAfterUnixNano &&
		bytes.Equal(receipt.idempotencyBytes, idempotencyBytes) &&
		bytes.Equal(receipt.identifierBytes, identifierBytes) &&
		equalDigestSlices(receipt.signedDigests, signedDigests)
}

func sameTransferCollectionFixedFields(left, right OwnershipTransferApprovalCollectionSnapshot) bool {
	return left.Binding == right.Binding && bytes.Equal(left.CanonicalPayload, right.CanonicalPayload) &&
		left.TransferEvidenceDigest == right.TransferEvidenceDigest &&
		left.ProfileDigest == right.ProfileDigest && sameTransferProfile(left.Profile, right.Profile) &&
		sameTransferFixedEvidence(left.FixedEvidence, right.FixedEvidence) &&
		left.HomeRegion == right.HomeRegion
}

func collectionAdvanceOuter(source IAMPendingStoredRevision,
	next OwnershipTransferApprovalCollectionPlan) (ccse.Record, [sha256.Size]byte, error) {
	decoded, err := decodeDurablePendingEnvelope(source.CanonicalEnvelope)
	if err != nil || decoded.transfer == nil {
		return ccse.Record{}, [sha256.Size]byte{}, ErrViewInconsistent
	}
	previousAuthorities := make(map[OwnershipTransferAuthorityRequirement][sha256.Size]byte,
		len(decoded.transfer.next.Approvals))
	for _, approval := range decoded.transfer.next.Approvals {
		if approval.Signed.Digest() == ([sha256.Size]byte{}) {
			return ccse.Record{}, [sha256.Size]byte{}, ErrViewInconsistent
		}
		previousAuthorities[approval.Authority] = approval.Signed.Digest()
	}
	var outer RetainedVerifiedRecord
	for _, approval := range next.next.Approvals {
		if digest, existed := previousAuthorities[approval.Authority]; existed {
			if digest != approval.Signed.Digest() {
				return ccse.Record{}, [sha256.Size]byte{}, ErrViewInconsistent
			}
			delete(previousAuthorities, approval.Authority)
			continue
		}
		if outer.digest != ([sha256.Size]byte{}) {
			return ccse.Record{}, [sha256.Size]byte{}, ErrPendingPlanInvalid
		}
		outer = approval.Signed
	}
	if len(previousAuthorities) != 0 || outer.digest == ([sha256.Size]byte{}) ||
		len(next.next.Approvals) != len(decoded.transfer.next.Approvals)+1 {
		return ccse.Record{}, [sha256.Size]byte{}, ErrPendingPlanInvalid
	}
	record := outer.Record()
	digest, err := record.Digest(ccse.DefaultLimits())
	if err != nil || digest != outer.Digest() {
		return ccse.Record{}, [sha256.Size]byte{}, ErrPendingPlanInvalid
	}
	return record, digest, nil
}

func collectionAdvanceEvidenceMetadata(plan OwnershipTransferApprovalCollectionPlan,
	outer ccse.Record, outerDigest [sha256.Size]byte,
	eventID string) pendingAdmissionMetadataValue {
	return pendingAdmissionMetadataValue{pendingKey: plan.next.Binding.Key, auditEventID: eventID,
		semanticAdmissionDigest: plan.Digest(), idempotencyReservations: plan.IdempotencyClaims(),
		identifierClaims: plan.IdentifierClaims(), outerRecord: cloneCCSERecord(outer),
		outerRecordDigest: outerDigest, commitNotBefore: plan.CommitNotBeforeUnixNano(),
		commitNotAfter: plan.CommitNotAfterUnixNano()}
}

func combineCollectionAdvanceEvidence(source []IAMPersistenceEvidenceCapability,
	next []IAMPersistenceEvidenceRecord) ([]IAMPersistenceEvidenceRecord, error) {
	values := make(map[[sha256.Size]byte]IAMPersistenceEvidenceRecord, len(source)+len(next))
	for _, evidence := range source {
		if evidence.VerifyDigest() != nil {
			return nil, ErrPendingPlanInvalid
		}
		values[evidence.record.DigestSHA256] = cloneIAMPersistenceEvidenceRecord(evidence.record)
	}
	for _, record := range next {
		if previous, found := values[record.DigestSHA256]; found &&
			!equalIAMPersistenceEvidenceRecords(previous, record) {
			return nil, ErrViewInconsistent
		}
		values[record.DigestSHA256] = cloneIAMPersistenceEvidenceRecord(record)
	}
	if len(values) == 0 || len(values) > iamMaxPendingEvidenceRecords {
		return nil, ErrPendingPlanInvalid
	}
	result := make([]IAMPersistenceEvidenceRecord, 0, len(values))
	for _, record := range values {
		result = append(result, record)
	}
	sort.Slice(result, func(i, j int) bool {
		return bytes.Compare(result[i].DigestSHA256[:], result[j].DigestSHA256[:]) < 0
	})
	return result, nil
}

func newLinkedIAMEvidenceStorageAssertion(record IAMPersistenceEvidenceRecord,
	source IAMPendingStoredRevision, eventID string) (IAMEvidenceStorageCapability, error) {
	result, err := newIAMEvidenceStorageAction(record, IAMEvidenceStorageAssertExisting, eventID)
	if err != nil {
		return IAMEvidenceStorageCapability{}, err
	}
	result.pendingKey = source.PendingKey
	result.pendingRevision = source.Revision
	result.hasPendingLink = true
	result.digest, err = digestIAMEvidenceStorageCapability(result)
	if err != nil || result.VerifyDigest() != nil {
		return IAMEvidenceStorageCapability{}, ErrPendingPlanInvalid
	}
	return result, nil
}

func verifyCollectionAdvanceState(value IAMPendingAdmissionStateCapability,
	envelope DurablePendingEnvelope, eventID string) error {
	if value.VerifyDigest() != nil || value.auditEventID != eventID {
		return ErrPendingPlanInvalid
	}
	coverage, err := pendingAdmissionCoverageDigest(envelope)
	if err != nil || coverage != value.coverageDigest {
		return ErrPendingPlanInvalid
	}
	expected, err := pendingAdmissionExpectedReadKeys(envelope)
	if err != nil || len(expected) != len(value.assertions)+len(value.absences) {
		return ErrPendingPlanInvalid
	}
	for _, assertion := range value.assertions {
		key := canonicalStateRecordKey(assertion.record)
		present, found := expected[key]
		if !found || !present {
			return ErrPendingPlanInvalid
		}
		delete(expected, key)
	}
	for _, absence := range value.absences {
		key := canonicalStateKeyString(absence.namespace, absence.kind, absence.objectID)
		present, found := expected[key]
		if !found || present {
			return ErrPendingPlanInvalid
		}
		delete(expected, key)
	}
	if len(expected) != 0 {
		return ErrPendingPlanInvalid
	}
	return nil
}

func sameCollectionAdvanceEvidenceActions(actions []IAMEvidenceStorageCapability,
	records []IAMPersistenceEvidenceRecord, source IAMPendingStoredRevision,
	eventID string) bool {
	if len(actions) != len(records) {
		return false
	}
	sourceDigests := make(map[[sha256.Size]byte]struct{}, len(source.EvidenceDigestsSHA256))
	for _, digest := range source.EvidenceDigestsSHA256 {
		sourceDigests[digest] = struct{}{}
	}
	for index := range actions {
		if actions[index].VerifyDigest() != nil || actions[index].auditAssertionEventID != eventID ||
			!equalIAMPersistenceEvidenceRecords(actions[index].evidence.record, records[index]) {
			return false
		}
		_, linked := sourceDigests[records[index].DigestSHA256]
		if linked != actions[index].hasPendingLink ||
			(linked && (actions[index].disposition != IAMEvidenceStorageAssertExisting ||
				actions[index].pendingKey != source.PendingKey ||
				actions[index].pendingRevision != source.Revision)) ||
			(!linked && (actions[index].disposition != IAMEvidenceStorageReserveNew &&
				actions[index].disposition != IAMEvidenceStorageAssertExisting)) {
			return false
		}
	}
	return true
}

func digestIAMCollectionAdvanceCapability(value IAMCollectionAdvanceCapability) ([sha256.Size]byte, error) {
	if !validIAMPendingStoredRevision(value.source) || value.next.VerifyDigest() != nil ||
		value.state.VerifyDigest() != nil || value.auditEventID == "" ||
		value.outerRecordDigest == ([sha256.Size]byte{}) || value.pendingDigest == ([sha256.Size]byte{}) ||
		value.envelopeDigest == ([sha256.Size]byte{}) || len(value.evidence) == 0 {
		return [sha256.Size]byte{}, ErrPendingPlanInvalid
	}
	sourceDigest, err := digestIAMPendingStoredRevisionSnapshot(value.source)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	sourceEvidenceDigests := make([][sha256.Size]byte, len(value.sourceEvidence))
	for index := range value.sourceEvidence {
		if value.sourceEvidence[index].VerifyDigest() != nil {
			return [sha256.Size]byte{}, ErrPendingPlanInvalid
		}
		sourceEvidenceDigests[index] = value.sourceEvidence[index].Digest()
	}
	actionDigests := make([][sha256.Size]byte, len(value.evidence))
	for index := range value.evidence {
		if value.evidence[index].VerifyDigest() != nil {
			return [sha256.Size]byte{}, ErrPendingPlanInvalid
		}
		actionDigests[index] = value.evidence[index].Digest()
	}
	advance, err := idempotency.CanonicalBytes(value.advanceClaims)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	joined, err := canonicalIdempotencySnapshot(value.joinedExpected)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	identifiers, err := globalid.CanonicalBytes(value.identifierClaims)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	outerCanonical, err := canonicalSignedAuthorizationEvidence(value.outerRecord)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	actualOuter, err := value.outerRecord.Digest(ccse.DefaultLimits())
	if err != nil || actualOuter != value.outerRecordDigest {
		return [sha256.Size]byte{}, ErrPendingPlanInvalid
	}
	nextDigest, stateDigest := value.next.Digest(), value.state.Digest()
	advanceDigest := domainDigest(iamCollectionAdvanceCapabilityDomain+"IDEMPOTENCY\x00", advance)
	joinedDigest := domainDigest(iamCollectionAdvanceCapabilityDomain+"JOINED\x00", joined)
	identifierDigest := domainDigest(iamCollectionAdvanceCapabilityDomain+"IDENTIFIERS\x00",
		identifiers)
	outerCanonicalDigest := domainDigest(iamCollectionAdvanceCapabilityDomain+"OUTER-RECORD\x00",
		outerCanonical)
	encoded, err := ccse.Marshal(64<<10, func(out *ccse.Encoder) {
		out.FixedBytes(sourceDigest[:], sha256.Size)
		out.Uint32(uint32(len(sourceEvidenceDigests)))
		for _, digest := range sourceEvidenceDigests {
			out.FixedBytes(digest[:], sha256.Size)
		}
		out.FixedBytes(nextDigest[:], sha256.Size)
		out.Uint32(uint32(len(actionDigests)))
		for _, digest := range actionDigests {
			out.FixedBytes(digest[:], sha256.Size)
		}
		out.FixedBytes(stateDigest[:], sha256.Size)
		out.FixedBytes(advanceDigest[:], sha256.Size)
		out.Uint64(uint64(len(advance)))
		out.FixedBytes(joinedDigest[:], sha256.Size)
		out.Uint64(uint64(len(joined)))
		out.FixedBytes(identifierDigest[:], sha256.Size)
		out.Uint64(uint64(len(identifiers)))
		out.FixedBytes(value.outerRecordDigest[:], sha256.Size)
		out.FixedBytes(outerCanonicalDigest[:], sha256.Size)
		out.Uint64(uint64(len(outerCanonical)))
		out.String(value.auditEventID)
		out.FixedBytes(value.pendingDigest[:], sha256.Size)
		out.FixedBytes(value.envelopeDigest[:], sha256.Size)
	})
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return domainDigest(iamCollectionAdvanceCapabilityDomain, encoded), nil
}

func digestIAMPendingStoredRevisionSnapshot(value IAMPendingStoredRevision) ([sha256.Size]byte, error) {
	if !validIAMPendingStoredRevision(value) {
		return [sha256.Size]byte{}, ErrPendingPlanInvalid
	}
	encoded, err := ccse.Marshal(64<<10, func(out *ccse.Encoder) {
		out.FixedBytes(value.PendingKey[:], ccse.MessageIDSize)
		out.Uint32(uint32(value.Kind))
		out.String(value.Codec)
		out.Uint32(value.CodecVersion)
		out.Uint64(value.Revision)
		out.FixedBytes(value.PreviousEnvelopeDigestSHA256[:], sha256.Size)
		out.FixedBytes(value.EnvelopeDigestSHA256[:], sha256.Size)
		out.Uint64(uint64(len(value.CanonicalEnvelope)))
		out.Uint32(uint32(len(value.EvidenceDigestsSHA256)))
		for _, digest := range value.EvidenceDigestsSHA256 {
			out.FixedBytes(digest[:], sha256.Size)
		}
		out.Uint32(uint32(value.Status))
		out.Int64(value.CommitNotBeforeUnixNano)
		out.Int64(value.CommitNotAfterUnixNano)
		out.FixedBytes(value.TerminalOutcomeDigestSHA256[:], sha256.Size)
		out.String(value.ExpectedAuditEventID)
	})
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return domainDigest(iamCollectionAdvanceCapabilityDomain+"SOURCE\x00", encoded), nil
}
