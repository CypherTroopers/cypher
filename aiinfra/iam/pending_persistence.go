// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"bytes"
	"context"
	"crypto/sha256"
	"sort"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	"github.com/cypherium/cypher/aiinfra/replayresult"
)

const (
	IAMPendingStatusOpen     uint8 = 1
	IAMPendingStatusTerminal uint8 = 2

	IAMEvidenceContentSHA256       uint8 = 1
	IAMEvidenceSignedCCSERecord    uint8 = 2
	IAMEvidenceAuthenticatedRecord uint8 = 3
	IAMEvidenceSemanticReceipt     uint8 = 4

	IAMEvidenceStorageReserveNew     uint8 = 1
	IAMEvidenceStorageAssertExisting uint8 = 2

	IAMEvidenceContentTypeSignedCCSERecord = "application/cph.aiinfra.ccse.signed-record.v1"

	iamPendingPersistenceDomain      = "CPH-AIIE-IAM-PENDING-PERSISTENCE-CAPABILITY-V1\x00"
	iamPendingTerminalTemplateDomain = "CPH-AIIE-IAM-PENDING-TERMINAL-TEMPLATE-V1\x00"
)

// IAMPendingStoredRevision is the exact storage-neutral OPEN head snapshot
// returned by the transaction-backed persistence view.
type IAMPendingStoredRevision struct {
	PendingKey                   [ccse.MessageIDSize]byte
	Kind                         DurablePendingKind
	Codec                        string
	CodecVersion                 uint32
	Revision                     uint64
	PreviousEnvelopeDigestSHA256 [sha256.Size]byte
	EnvelopeDigestSHA256         [sha256.Size]byte
	CanonicalEnvelope            []byte
	EvidenceDigestsSHA256        [][sha256.Size]byte
	Status                       uint8
	CommitNotBeforeUnixNano      int64
	CommitNotAfterUnixNano       int64
	TerminalOutcomeDigestSHA256  [sha256.Size]byte
	ExpectedAuditEventID         string
}

// IAMPersistenceEvidenceRecord is one full, bounded preimage retained by the
// OPEN pending revision. Kind values match the closed PostgreSQL catalog.
type IAMPersistenceEvidenceRecord struct {
	DigestSHA256         [sha256.Size]byte
	Kind                 uint8
	ContentType          string
	CanonicalContent     []byte
	ExpectedAuditEventID string
}

// IAMPendingPersistenceView is a fail-closed optional extension. Its method
// reads an optimistic pre-sign snapshot of the exact OPEN pending revision,
// every evidence row linked to it, and the explicitly requested current
// evidence preimages. The final coordinator later byte-compares/CAS-applies
// this capability in its own SERIALIZABLE UoW.
type IAMPendingPersistenceView interface {
	SnapshotIAMPendingPersistence(context.Context, [ccse.MessageIDSize]byte, uint64,
		[][sha256.Size]byte) (
		IAMPendingStoredRevision, []IAMPersistenceEvidenceRecord, bool, error)
}

// IAMPendingRevision is an owned exact write capability. For version-one
// creation Previous* is empty. For an update it carries the complete locked
// predecessor and its byte-exact CAS values.
type IAMPendingRevision struct {
	record IAMPendingRevisionRecord
	digest [sha256.Size]byte
}

type IAMPendingRevisionRecord struct {
	PendingKey                      [ccse.MessageIDSize]byte
	ExpectedKind                    DurablePendingKind
	Kind                            DurablePendingKind
	Codec                           string
	CodecVersion                    uint32
	Revision                        uint64
	PreviousEnvelopeDigestSHA256    [sha256.Size]byte
	PreviousCanonicalEnvelope       []byte
	PreviousCommitNotBeforeUnixNano int64
	PreviousCommitNotAfterUnixNano  int64
	EnvelopeDigestSHA256            [sha256.Size]byte
	CanonicalEnvelope               []byte
	EvidenceDigestsSHA256           [][sha256.Size]byte
	Status                          uint8
	CommitNotBeforeUnixNano         int64
	CommitNotAfterUnixNano          int64
	TerminalOutcomeDigestSHA256     [sha256.Size]byte
	ExpectedAuditEventID            string
}

func (value IAMPendingRevision) Record() IAMPendingRevisionRecord {
	return cloneIAMPendingRevisionRecord(value.record)
}
func (value IAMPendingRevision) Digest() [sha256.Size]byte { return value.digest }
func (value IAMPendingRevision) VerifyDigest() error {
	digest, err := digestIAMPendingRevisionRecord(value.record)
	if err != nil || digest != value.digest {
		return ErrPendingPlanInvalid
	}
	return nil
}

type IAMPersistenceEvidenceCapability struct {
	record IAMPersistenceEvidenceRecord
	digest [sha256.Size]byte
}

// IAMEvidenceStorageCapability is the exact coordinator action for one
// immutable evidence row. Existing source-linked rows are asserted against
// their exact OPEN pending revision; current failure evidence is reserved as
// a new row before the terminal revision links it.
type IAMEvidenceStorageCapability struct {
	evidence              IAMPersistenceEvidenceCapability
	disposition           uint8
	pendingKey            [ccse.MessageIDSize]byte
	pendingRevision       uint64
	hasPendingLink        bool
	auditAssertionEventID string
	digest                [sha256.Size]byte
}

func (value IAMEvidenceStorageCapability) Evidence() IAMPersistenceEvidenceCapability {
	return IAMPersistenceEvidenceCapability{record: cloneIAMPersistenceEvidenceRecord(value.evidence.record),
		digest: value.evidence.digest}
}
func (value IAMEvidenceStorageCapability) Disposition() uint8 { return value.disposition }
func (value IAMEvidenceStorageCapability) PendingLink() ([ccse.MessageIDSize]byte, uint64, bool) {
	return value.pendingKey, value.pendingRevision, value.hasPendingLink
}
func (value IAMEvidenceStorageCapability) AuditAssertionEventID() string {
	return value.auditAssertionEventID
}
func (value IAMEvidenceStorageCapability) Digest() [sha256.Size]byte { return value.digest }
func (value IAMEvidenceStorageCapability) VerifyDigest() error {
	digest, err := digestIAMEvidenceStorageCapability(value)
	if err != nil || digest != value.digest {
		return ErrPendingPlanInvalid
	}
	return nil
}

func (value IAMPersistenceEvidenceCapability) Record() IAMPersistenceEvidenceRecord {
	return cloneIAMPersistenceEvidenceRecord(value.record)
}
func (value IAMPersistenceEvidenceCapability) Digest() [sha256.Size]byte { return value.digest }
func (value IAMPersistenceEvidenceCapability) VerifyDigest() error {
	digest, err := digestIAMPersistenceEvidenceRecord(value.record)
	if err != nil || digest != value.digest {
		return ErrPendingPlanInvalid
	}
	return nil
}

// IAMPendingPersistenceCapability binds the exact locked predecessor and its
// complete evidence preimages. TerminalRevisions is the only conversion to
// storage writes and requires the exact typed replay result.
type IAMPendingPersistenceCapability struct {
	source               IAMPendingStoredRevision
	evidence             []IAMPersistenceEvidenceCapability
	auditEventID         string
	kind                 DurablePendingKind
	nextEnvelope         []byte
	nextEnvelopeDigest   [sha256.Size]byte
	nestedEnvelope       []byte
	nestedEnvelopeDigest [sha256.Size]byte
	digest               [sha256.Size]byte
}

func (value IAMPendingPersistenceCapability) Source() IAMPendingStoredRevision {
	return cloneIAMPendingStoredRevision(value.source)
}
func (value IAMPendingPersistenceCapability) Evidence() []IAMPersistenceEvidenceCapability {
	result := make([]IAMPersistenceEvidenceCapability, len(value.evidence))
	for index := range value.evidence {
		result[index] = IAMPersistenceEvidenceCapability{
			record: cloneIAMPersistenceEvidenceRecord(value.evidence[index].record),
			digest: value.evidence[index].digest}
	}
	return result
}
func (value IAMPendingPersistenceCapability) EvidenceByDigest(digest [sha256.Size]byte) (
	IAMPersistenceEvidenceCapability, bool) {
	for _, evidence := range value.evidence {
		if evidence.record.DigestSHA256 == digest && evidence.VerifyDigest() == nil {
			return IAMPersistenceEvidenceCapability{
				record: cloneIAMPersistenceEvidenceRecord(evidence.record), digest: evidence.digest}, true
		}
	}
	return IAMPersistenceEvidenceCapability{}, false
}
func (value IAMPendingPersistenceCapability) EvidenceStorageCapabilities() []IAMEvidenceStorageCapability {
	result := make([]IAMEvidenceStorageCapability, 0, len(value.evidence))
	source := make(map[[sha256.Size]byte]struct{}, len(value.source.EvidenceDigestsSHA256))
	for _, digest := range value.source.EvidenceDigestsSHA256 {
		source[digest] = struct{}{}
	}
	for _, evidence := range value.evidence {
		capability := IAMEvidenceStorageCapability{evidence: IAMPersistenceEvidenceCapability{
			record: cloneIAMPersistenceEvidenceRecord(evidence.record), digest: evidence.digest},
			disposition: IAMEvidenceStorageReserveNew, auditAssertionEventID: value.auditEventID}
		if _, exists := source[evidence.record.DigestSHA256]; exists {
			capability.disposition = IAMEvidenceStorageAssertExisting
			capability.pendingKey = value.source.PendingKey
			capability.pendingRevision = value.source.Revision
			capability.hasPendingLink = true
		}
		capability.digest, _ = digestIAMEvidenceStorageCapability(capability)
		result = append(result, capability)
	}
	return result
}
func (value IAMPendingPersistenceCapability) Digest() [sha256.Size]byte { return value.digest }
func (value IAMPendingPersistenceCapability) VerifyDigest() error {
	digest, err := digestIAMPendingPersistenceCapability(value)
	if err != nil || digest != value.digest {
		return ErrPendingPlanInvalid
	}
	return nil
}
func (value IAMPendingPersistenceCapability) VerifyFor(request JoinedAuditRequest) error {
	if request.VerifyDigest() != nil || request.persistence == nil ||
		request.persistence.digest != value.digest || value.VerifyDigest() != nil ||
		value.source.PendingKey != request.parentBinding.Key ||
		value.source.Revision != request.parentExpected.Version ||
		value.auditEventID != request.auditEventID {
		return ErrPendingPlanInvalid
	}
	return verifyIAMPersistenceEvidenceForRequest(value, request)
}

func verifyIAMPersistenceEvidenceForRequest(value IAMPendingPersistenceCapability,
	request JoinedAuditRequest) error {
	for _, reference := range pendingPersistenceEvidenceReferences(request) {
		if _, ok := value.EvidenceByDigest(reference.Digest); !ok {
			return ErrPendingPlanInvalid
		}
	}
	var sources []AuditIntent
	if request.audit != nil {
		sources = append(sources, cloneAuditIntent(*request.audit))
	} else if request.reconciliation != nil {
		sourceRecord, hasSource := request.reconciliation.SourceAuthorizationRecord()
		if !hasSource {
			return ErrPendingPlanInvalid
		}
		sourceDigest := request.reconciliation.SourceAuthorizationDigest()
		sourceEvidence, found := value.EvidenceByDigest(sourceDigest)
		canonical, err := canonicalSignedAuthorizationEvidence(sourceRecord)
		if !found || sourceEvidence.record.Kind != IAMEvidenceSignedCCSERecord ||
			sourceEvidence.record.ContentType != IAMEvidenceContentTypeSignedCCSERecord ||
			err != nil || !bytes.Equal(canonical, sourceEvidence.record.CanonicalContent) {
			return ErrPendingPlanInvalid
		}
	}
	if request.Kind() == DurablePendingOwnershipTransferAcceptance && request.envelope.acceptance != nil {
		sources = append(sources, request.envelope.acceptance.cutover.AuditIntent())
	}
	for _, source := range sources {
		sourceRecord, hasSource := source.SourceAuthorizationRecord()
		sourceDigest := source.SourceAuthorizationDigest()
		sourceEvidence, found := value.EvidenceByDigest(sourceDigest)
		canonical, err := canonicalSignedAuthorizationEvidence(sourceRecord)
		if !hasSource || !found || sourceEvidence.record.Kind != IAMEvidenceSignedCCSERecord ||
			sourceEvidence.record.ContentType != IAMEvidenceContentTypeSignedCCSERecord ||
			err != nil || !bytes.Equal(canonical, sourceEvidence.record.CanonicalContent) {
			return ErrPendingPlanInvalid
		}
	}
	return nil
}

func pendingPersistenceEvidenceReferences(request JoinedAuditRequest) []ContentAddressedEvidenceReference {
	values := append([]ContentAddressedEvidenceReference(nil), request.evidenceReferences...)
	if request.Kind() == DurablePendingOwnershipTransferAcceptance && request.envelope.acceptance != nil {
		values = append(values, auditEvidenceReferences(request.envelope.acceptance.cutover.AuditIntent())...)
	}
	result := make([]ContentAddressedEvidenceReference, 0, len(values))
	seen := make(map[[sha256.Size]byte]struct{}, len(values))
	for _, value := range values {
		if value.Digest == ([sha256.Size]byte{}) {
			continue
		}
		if _, duplicate := seen[value.Digest]; duplicate {
			continue
		}
		seen[value.Digest] = struct{}{}
		result = append(result, value)
	}
	return result
}

// IAMPendingTerminalTemplate freezes every IAM-owned pending revision field
// except the outer joined-audit result digest. The coordinator validates and
// stores its own success replay result, then supplies only that digest to
// Finalize. IAM never creates a competing success result codec.
type IAMPendingTerminalTemplate struct {
	records            []IAMPendingRevisionRecord
	requestDigest      [sha256.Size]byte
	executionDigest    [sha256.Size]byte
	capabilityDigest   [sha256.Size]byte
	expectedOutcome    uint32
	innerFailureDigest [sha256.Size]byte
	digest             [sha256.Size]byte
}

func (value IAMPendingTerminalTemplate) Digest() [sha256.Size]byte { return value.digest }
func (value IAMPendingTerminalTemplate) VerifyFor(request JoinedAuditRequest) error {
	if request.VerifyDigest() != nil || request.execution == nil || request.persistence == nil ||
		value.requestDigest != request.digest || value.executionDigest != request.execution.Digest() ||
		value.capabilityDigest != request.persistence.digest ||
		value.expectedOutcome != request.ExpectedOutcome() {
		return ErrPendingPlanInvalid
	}
	if value.expectedOutcome == 1 {
		if value.innerFailureDigest != ([sha256.Size]byte{}) {
			return ErrPendingPlanInvalid
		}
	} else {
		failure, ok := request.FailureResult()
		if !ok || (value.expectedOutcome != 3 && value.expectedOutcome != 4) ||
			failure.Digest() != value.innerFailureDigest {
			return ErrPendingPlanInvalid
		}
	}
	digest, err := digestIAMPendingTerminalTemplate(value.records, value.requestDigest,
		value.executionDigest, value.capabilityDigest, value.expectedOutcome,
		value.innerFailureDigest)
	if err != nil || digest != value.digest {
		return ErrPendingPlanInvalid
	}
	return nil
}

// Finalize supplies the already-validated outer coordinator result digest.
// For FAILED/TIMED_OUT the outer result must be distinct from, and retain,
// IAM's strict inner failure result plus the final UoW clock receipt.
func (value IAMPendingTerminalTemplate) Finalize(request JoinedAuditRequest,
	joinedOutcomeDigest [sha256.Size]byte) ([]IAMPendingRevision, error) {
	if value.VerifyFor(request) != nil || joinedOutcomeDigest == ([sha256.Size]byte{}) ||
		(value.innerFailureDigest != ([sha256.Size]byte{}) && joinedOutcomeDigest == value.innerFailureDigest) {
		return nil, ErrPendingPlanInvalid
	}
	result := make([]IAMPendingRevision, len(value.records))
	for index := range value.records {
		record := cloneIAMPendingRevisionRecord(value.records[index])
		if record.Status == IAMPendingStatusTerminal {
			record.TerminalOutcomeDigestSHA256 = joinedOutcomeDigest
		}
		capability, err := newIAMPendingRevision(record)
		if err != nil {
			return nil, err
		}
		result[index] = capability
	}
	return result, nil
}

// BindPendingPersistenceCapability validates the exact stored predecessor and
// evidence through the optional transaction view and binds an owned copy into
// both request and execution digests.
func (p *Planner) BindPendingPersistenceCapability(ctx context.Context,
	request JoinedAuditRequest) (JoinedAuditRequest, error) {
	if err := p.ready(); err != nil {
		return JoinedAuditRequest{}, err
	}
	if request.VerifyDigest() != nil || request.persistence != nil || request.execution == nil {
		return JoinedAuditRequest{}, ErrPendingPlanInvalid
	}
	view, ok := p.view.(IAMPendingPersistenceView)
	if !ok {
		return JoinedAuditRequest{}, ErrViewRequired
	}
	references := pendingPersistenceEvidenceReferences(request)
	requiredEvidence := make([][sha256.Size]byte, len(references))
	for index := range references {
		requiredEvidence[index] = references[index].Digest
	}
	source, records, found, err := view.SnapshotIAMPendingPersistence(ctx,
		request.parentBinding.Key, request.parentExpected.Version, requiredEvidence)
	if err != nil {
		return JoinedAuditRequest{}, err
	}
	capability, err := newIAMPendingPersistenceCapability(request, source, records, found)
	if err != nil {
		return JoinedAuditRequest{}, err
	}
	request.persistence = &capability
	request.stateCommitment, err = joinedAuditStateCommitment(request)
	if err != nil {
		return JoinedAuditRequest{}, ErrPendingPlanInvalid
	}
	execution, err := executionFragmentFromRequest(request)
	if err != nil {
		return JoinedAuditRequest{}, ErrPendingPlanInvalid
	}
	request.execution = &execution
	request.digest, err = joinedAuditRequestDigest(request)
	if err != nil || request.VerifyDigest() != nil {
		return JoinedAuditRequest{}, ErrPendingPlanInvalid
	}
	return request, nil
}

func newIAMPendingPersistenceCapability(request JoinedAuditRequest, source IAMPendingStoredRevision,
	records []IAMPersistenceEvidenceRecord, found bool) (IAMPendingPersistenceCapability, error) {
	if !found || !validIAMPendingStoredRevision(source) || source.PendingKey != request.parentBinding.Key ||
		source.Revision != request.parentExpected.Version || source.ExpectedAuditEventID != request.auditEventID {
		return IAMPendingPersistenceCapability{}, ErrViewInconsistent
	}
	expectedSourceKind := request.Kind()
	expectedSourceEnvelope := request.envelope.encoded
	expectedSourceDigest := request.envelope.digest
	if request.Kind() == DurablePendingReconciliation {
		expectedSourceEnvelope = request.envelope.reconciliation.originalPendingEnvelope
		expectedSourceDigest = request.envelope.reconciliation.originalEnvelopeDigest
		decoded, err := DecodeDurablePendingEnvelope(expectedSourceEnvelope)
		if err != nil {
			return IAMPendingPersistenceCapability{}, ErrPendingPlanInvalid
		}
		expectedSourceKind = decoded.Kind()
	} else if request.Kind() == DurablePendingOwnershipTransferAcceptance {
		expectedSourceKind = DurablePendingOwnershipTransferCollection
		decoded, err := decodeDurablePendingEnvelope(source.CanonicalEnvelope)
		if err != nil || decoded.transfer == nil || request.envelope.acceptance == nil ||
			decoded.transfer.next.Binding != request.envelope.acceptance.collection.Binding ||
			decoded.transfer.next.Version != request.envelope.acceptance.collection.Version ||
			decoded.transfer.next.ProgressDigest != request.envelope.acceptance.collection.ProgressDigest {
			return IAMPendingPersistenceCapability{}, ErrViewInconsistent
		}
		expectedSourceEnvelope = source.CanonicalEnvelope
		expectedSourceDigest = source.EnvelopeDigestSHA256
	}
	if source.Kind != expectedSourceKind || source.EnvelopeDigestSHA256 != expectedSourceDigest ||
		!bytes.Equal(source.CanonicalEnvelope, expectedSourceEnvelope) {
		return IAMPendingPersistenceCapability{}, ErrViewInconsistent
	}
	decodedSource, err := decodeDurablePendingEnvelope(expectedSourceEnvelope)
	if err != nil {
		return IAMPendingPersistenceCapability{}, ErrPendingPlanInvalid
	}
	_, expectedNotBefore, expectedNotAfter, err := durableEnvelopeFullWindow(decodedSource)
	if err != nil || source.CommitNotBeforeUnixNano != expectedNotBefore ||
		source.CommitNotAfterUnixNano != expectedNotAfter {
		return IAMPendingPersistenceCapability{}, ErrViewInconsistent
	}
	requiredEvidence := append([][sha256.Size]byte(nil), source.EvidenceDigestsSHA256...)
	for _, reference := range pendingPersistenceEvidenceReferences(request) {
		requiredEvidence = append(requiredEvidence, reference.Digest)
	}
	requiredEvidence = uniqueDigests(requiredEvidence)
	evidence, err := validateIAMPersistenceEvidence(records, requiredEvidence)
	if err != nil {
		return IAMPendingPersistenceCapability{}, err
	}
	capability := IAMPendingPersistenceCapability{source: cloneIAMPendingStoredRevision(source),
		evidence: evidence, auditEventID: request.auditEventID, kind: request.Kind(),
		nextEnvelope: request.envelope.Bytes(), nextEnvelopeDigest: request.envelope.Digest(),
	}
	if request.Kind() == DurablePendingReconciliation {
		failureEvidence := request.envelope.reconciliation.failureEvidence
		failureRecord := IAMPersistenceEvidenceRecord{DigestSHA256: failureEvidence.Digest(),
			Kind: IAMEvidenceSemanticReceipt, ContentType: failureEvidence.ContentType(),
			CanonicalContent: failureEvidence.CanonicalBytes(), ExpectedAuditEventID: request.auditEventID}
		if _, found := capability.EvidenceByDigest(failureRecord.DigestSHA256); !found {
			failureCapabilityDigest, digestErr := digestIAMPersistenceEvidenceRecord(failureRecord)
			if digestErr != nil || len(capability.evidence) >= 64 {
				return IAMPendingPersistenceCapability{}, ErrPendingPlanInvalid
			}
			capability.evidence = append(capability.evidence, IAMPersistenceEvidenceCapability{
				record: failureRecord, digest: failureCapabilityDigest})
			sort.Slice(capability.evidence, func(i, j int) bool {
				return bytes.Compare(capability.evidence[i].record.DigestSHA256[:],
					capability.evidence[j].record.DigestSHA256[:]) < 0
			})
		}
	}
	if request.Kind() == DurablePendingOwnershipTransferAcceptance {
		fragment := request.execution
		capability.nestedEnvelope = fragment.PendingEnvelopeBytes()
		capability.nestedEnvelopeDigest, _ = fragment.NestedDurableEnvelopeDigest()
	}
	capability.digest, err = digestIAMPendingPersistenceCapability(capability)
	if err != nil {
		return IAMPendingPersistenceCapability{}, err
	}
	if verifyIAMPersistenceEvidenceForRequest(capability, request) != nil {
		return IAMPendingPersistenceCapability{}, ErrViewInconsistent
	}
	return capability, nil
}

// TerminalTemplate returns one same-kind terminal template, or for ephemeral
// kind 6 the ordered pair: terminal kind 3 then new OPEN kind 5. Both success
// and reconciliation are finalized only with the coordinator's outer joined
// result digest.
func (value IAMPendingPersistenceCapability) TerminalTemplate(
	request JoinedAuditRequest) (IAMPendingTerminalTemplate, error) {
	if value.VerifyDigest() != nil || request.VerifyDigest() != nil || request.execution == nil ||
		request.persistence == nil || request.persistence.digest != value.digest ||
		request.auditEventID != value.auditEventID {
		return IAMPendingTerminalTemplate{}, ErrPendingPlanInvalid
	}
	expectedOutcome := request.ExpectedOutcome()
	var innerFailureDigest [sha256.Size]byte
	if expectedOutcome != 1 {
		failure, ok := request.FailureResult()
		if !ok || (expectedOutcome != 3 && expectedOutcome != 4) {
			return IAMPendingTerminalTemplate{}, ErrPendingPlanInvalid
		}
		snapshot, err := DecodePendingReconciliationResult(failure)
		requirement, ok := request.ReconciliationFinalClockRequirement()
		if err != nil || !ok || snapshot.PendingDigest() != requirement.PendingDigest() ||
			snapshot.FinalClockRequirement() != requirement {
			return IAMPendingTerminalTemplate{}, ErrPendingPlanInvalid
		}
		innerFailureDigest = failure.Digest()
	}
	records, err := value.terminalRevisionRecords(request, [sha256.Size]byte{})
	if err != nil {
		return IAMPendingTerminalTemplate{}, err
	}
	template := IAMPendingTerminalTemplate{records: records, requestDigest: request.digest,
		executionDigest: request.execution.Digest(), capabilityDigest: value.digest,
		expectedOutcome: expectedOutcome, innerFailureDigest: innerFailureDigest}
	template.digest, err = digestIAMPendingTerminalTemplate(records, template.requestDigest,
		template.executionDigest, template.capabilityDigest, template.expectedOutcome,
		template.innerFailureDigest)
	if err != nil || template.VerifyFor(request) != nil {
		return IAMPendingTerminalTemplate{}, ErrPendingPlanInvalid
	}
	return template, nil
}

// SuccessTerminalTemplate is a compatibility-narrowed success constructor.
func (value IAMPendingPersistenceCapability) SuccessTerminalTemplate(
	request JoinedAuditRequest) (IAMPendingTerminalTemplate, error) {
	if request.ExpectedOutcome() != 1 {
		return IAMPendingTerminalTemplate{}, ErrPendingPlanInvalid
	}
	return value.TerminalTemplate(request)
}

// FailureTerminalTemplate validates and binds IAM's strict inner failure
// result but leaves the authoritative outer result digest for Finalize.
func (value IAMPendingPersistenceCapability) FailureTerminalTemplate(
	request JoinedAuditRequest) (IAMPendingTerminalTemplate, error) {
	if request.ExpectedOutcome() != 3 && request.ExpectedOutcome() != 4 {
		return IAMPendingTerminalTemplate{}, ErrPendingPlanInvalid
	}
	return value.TerminalTemplate(request)
}

// TerminalRevisions is retained fail-closed for source compatibility. A raw
// IAM failure result is not the authoritative final UoW result; callers must
// use FailureTerminalTemplate and Finalize with the outer joined digest.
func (value IAMPendingPersistenceCapability) TerminalRevisions(request JoinedAuditRequest,
	result replayresult.Result) ([]IAMPendingRevision, error) {
	return nil, ErrPendingPlanInvalid
}

func (value IAMPendingPersistenceCapability) terminalRevisionRecords(request JoinedAuditRequest,
	outcome [sha256.Size]byte) ([]IAMPendingRevisionRecord, error) {
	terminal := IAMPendingRevisionRecord{PendingKey: value.source.PendingKey,
		ExpectedKind: value.source.Kind, Kind: value.source.Kind, Codec: value.source.Codec,
		CodecVersion: value.source.CodecVersion, Revision: value.source.Revision + 1,
		PreviousEnvelopeDigestSHA256:    value.source.EnvelopeDigestSHA256,
		PreviousCanonicalEnvelope:       append([]byte(nil), value.source.CanonicalEnvelope...),
		PreviousCommitNotBeforeUnixNano: value.source.CommitNotBeforeUnixNano,
		PreviousCommitNotAfterUnixNano:  value.source.CommitNotAfterUnixNano,
		EnvelopeDigestSHA256:            value.source.EnvelopeDigestSHA256,
		CanonicalEnvelope:               append([]byte(nil), value.source.CanonicalEnvelope...),
		EvidenceDigestsSHA256:           append([][sha256.Size]byte(nil), value.source.EvidenceDigestsSHA256...),
		Status:                          IAMPendingStatusTerminal, CommitNotBeforeUnixNano: value.source.CommitNotBeforeUnixNano,
		CommitNotAfterUnixNano:      value.source.CommitNotAfterUnixNano,
		TerminalOutcomeDigestSHA256: outcome, ExpectedAuditEventID: value.auditEventID}
	if request.Kind() == DurablePendingReconciliation {
		terminal.Kind = DurablePendingReconciliation
		terminal.PreviousCommitNotBeforeUnixNano = 0
		terminal.PreviousCommitNotAfterUnixNano = 0
		terminal.EnvelopeDigestSHA256 = value.nextEnvelopeDigest
		terminal.CanonicalEnvelope = append([]byte(nil), value.nextEnvelope...)
		terminal.CommitNotBeforeUnixNano = request.commitNotBeforeUnixNano
		terminal.CommitNotAfterUnixNano = request.commitNotAfterUnixNano
		terminal.EvidenceDigestsSHA256 = value.allEvidenceDigests()
	} else if request.Kind() == DurablePendingOwnershipTransferAcceptance {
		childBinding := mustCutoverBinding(request.envelope.acceptance.cutover.accepted)
		if childBinding.Domain != idempotency.OperationIAMOwnershipTransferCutover ||
			childBinding.Key == ([ccse.MessageIDSize]byte{}) {
			return nil, ErrPendingPlanInvalid
		}
		child := IAMPendingRevisionRecord{PendingKey: childBinding.Key,
			Kind: DurablePendingOwnershipTransferCutover, Codec: durablePendingCodec,
			CodecVersion: durablePendingCodecVersion, Revision: 1,
			EnvelopeDigestSHA256:    value.nestedEnvelopeDigest,
			CanonicalEnvelope:       append([]byte(nil), value.nestedEnvelope...),
			EvidenceDigestsSHA256:   value.allEvidenceDigests(),
			Status:                  IAMPendingStatusOpen,
			CommitNotBeforeUnixNano: request.envelope.acceptance.cutover.CommitNotBeforeUnixNano(),
			CommitNotAfterUnixNano:  request.envelope.acceptance.cutover.CommitNotAfterUnixNano(),
			ExpectedAuditEventID:    request.envelope.acceptance.cutover.audit.AuditEventID()}
		return []IAMPendingRevisionRecord{terminal, child}, nil
	}
	return []IAMPendingRevisionRecord{terminal}, nil
}

func (value IAMPendingPersistenceCapability) allEvidenceDigests() [][sha256.Size]byte {
	result := make([][sha256.Size]byte, len(value.evidence))
	for index := range value.evidence {
		result[index] = value.evidence[index].record.DigestSHA256
	}
	return result
}

func newIAMPendingRevision(record IAMPendingRevisionRecord) (IAMPendingRevision, error) {
	record = cloneIAMPendingRevisionRecord(record)
	digest, err := digestIAMPendingRevisionRecord(record)
	if err != nil {
		return IAMPendingRevision{}, err
	}
	return IAMPendingRevision{record: record, digest: digest}, nil
}

func digestIAMPendingTerminalTemplate(records []IAMPendingRevisionRecord,
	requestDigest, executionDigest, capabilityDigest [sha256.Size]byte, expectedOutcome uint32,
	innerFailureDigest [sha256.Size]byte) ([sha256.Size]byte, error) {
	if len(records) == 0 || len(records) > 2 || requestDigest == ([sha256.Size]byte{}) ||
		executionDigest == ([sha256.Size]byte{}) || capabilityDigest == ([sha256.Size]byte{}) ||
		(expectedOutcome != 1 && expectedOutcome != 3 && expectedOutcome != 4) ||
		(expectedOutcome == 1) != (innerFailureDigest == ([sha256.Size]byte{})) {
		return [sha256.Size]byte{}, ErrPendingPlanInvalid
	}
	recordDigests := make([][sha256.Size]byte, len(records))
	for index := range records {
		record := cloneIAMPendingRevisionRecord(records[index])
		if record.Status == IAMPendingStatusTerminal {
			if record.TerminalOutcomeDigestSHA256 != ([sha256.Size]byte{}) {
				return [sha256.Size]byte{}, ErrPendingPlanInvalid
			}
			// A fixed nonzero placeholder validates and commits every template
			// field while keeping the coordinator-owned outcome slot explicit.
			record.TerminalOutcomeDigestSHA256[0] = 1
		}
		digest, err := digestIAMPendingRevisionRecord(record)
		if err != nil {
			return [sha256.Size]byte{}, err
		}
		recordDigests[index] = digest
	}
	encoded, err := ccse.Marshal(512, func(out *ccse.Encoder) {
		out.FixedBytes(requestDigest[:], sha256.Size)
		out.FixedBytes(executionDigest[:], sha256.Size)
		out.FixedBytes(capabilityDigest[:], sha256.Size)
		out.Uint32(expectedOutcome)
		out.FixedBytes(innerFailureDigest[:], sha256.Size)
		out.Uint32(uint32(len(recordDigests)))
		for _, digest := range recordDigests {
			out.FixedBytes(digest[:], sha256.Size)
		}
	})
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return domainDigest(iamPendingTerminalTemplateDomain, encoded), nil
}

func validIAMPendingStoredRevision(value IAMPendingStoredRevision) bool {
	if value.PendingKey == ([ccse.MessageIDSize]byte{}) || value.Kind < DurablePendingMutation ||
		value.Kind > DurablePendingOwnershipTransferCutover || value.Codec != durablePendingCodec ||
		value.CodecVersion != durablePendingCodecVersion || value.Revision == 0 ||
		value.EnvelopeDigestSHA256 == ([sha256.Size]byte{}) || len(value.CanonicalEnvelope) == 0 ||
		domainDigest(durablePendingEnvelopeDigestDomain, value.CanonicalEnvelope) != value.EnvelopeDigestSHA256 ||
		value.Status != IAMPendingStatusOpen || value.CommitNotBeforeUnixNano <= 0 ||
		value.CommitNotAfterUnixNano <= value.CommitNotBeforeUnixNano ||
		value.TerminalOutcomeDigestSHA256 != ([sha256.Size]byte{}) || value.ExpectedAuditEventID == "" {
		return false
	}
	if (value.Revision == 1) != (value.PreviousEnvelopeDigestSHA256 == ([sha256.Size]byte{})) {
		return false
	}
	return canonicalDigestList(value.EvidenceDigestsSHA256)
}

func validateIAMPersistenceEvidence(records []IAMPersistenceEvidenceRecord,
	digests [][sha256.Size]byte) ([]IAMPersistenceEvidenceCapability, error) {
	if len(records) != len(digests) || len(records) > iamMaxPendingEvidenceRecords {
		return nil, ErrViewInconsistent
	}
	expected := make(map[[sha256.Size]byte]struct{}, len(digests))
	for _, digest := range digests {
		expected[digest] = struct{}{}
	}
	result := make([]IAMPersistenceEvidenceCapability, len(records))
	for index, record := range records {
		digest, err := digestIAMPersistenceEvidenceRecord(record)
		if err != nil {
			return nil, ErrViewInconsistent
		}
		result[index] = IAMPersistenceEvidenceCapability{
			record: cloneIAMPersistenceEvidenceRecord(record), digest: digest}
		delete(expected, record.DigestSHA256)
	}
	if len(expected) != 0 {
		return nil, ErrViewInconsistent
	}
	sort.Slice(result, func(i, j int) bool {
		return bytes.Compare(result[i].record.DigestSHA256[:], result[j].record.DigestSHA256[:]) < 0
	})
	for index := 1; index < len(result); index++ {
		if result[index-1].record.DigestSHA256 == result[index].record.DigestSHA256 {
			return nil, ErrViewInconsistent
		}
	}
	return result, nil
}

func digestIAMPersistenceEvidenceRecord(record IAMPersistenceEvidenceRecord) ([sha256.Size]byte, error) {
	if record.DigestSHA256 == ([sha256.Size]byte{}) || record.Kind < IAMEvidenceContentSHA256 ||
		record.Kind > IAMEvidenceSemanticReceipt || record.ContentType == "" ||
		len(record.CanonicalContent) == 0 || len(record.CanonicalContent) > 64<<20 ||
		record.ExpectedAuditEventID == "" {
		return [sha256.Size]byte{}, ErrPendingPlanInvalid
	}
	if record.Kind == IAMEvidenceContentSHA256 && sha256.Sum256(record.CanonicalContent) != record.DigestSHA256 {
		return [sha256.Size]byte{}, ErrPendingPlanInvalid
	}
	if record.Kind == IAMEvidenceSignedCCSERecord &&
		!validCanonicalFailurePreimage(record.CanonicalContent, record.DigestSHA256) {
		return [sha256.Size]byte{}, ErrPendingPlanInvalid
	}
	if record.Kind == IAMEvidenceSemanticReceipt &&
		record.ContentType == IAMPendingAdmissionEvidenceContentType &&
		domainDigest(iamPendingAdmissionEvidenceDomain, record.CanonicalContent) != record.DigestSHA256 {
		return [sha256.Size]byte{}, ErrPendingPlanInvalid
	}
	contentDigest := domainDigest(iamPendingPersistenceDomain+"EVIDENCE-CONTENT\x00",
		record.CanonicalContent)
	encoded, err := ccse.Marshal(4096, func(out *ccse.Encoder) {
		out.FixedBytes(record.DigestSHA256[:], sha256.Size)
		out.Uint32(uint32(record.Kind))
		out.String(record.ContentType)
		out.FixedBytes(contentDigest[:], sha256.Size)
		out.Uint64(uint64(len(record.CanonicalContent)))
		out.String(record.ExpectedAuditEventID)
	})
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return domainDigest(iamPendingPersistenceDomain+"EVIDENCE\x00", encoded), nil
}

func digestIAMEvidenceStorageCapability(value IAMEvidenceStorageCapability) ([sha256.Size]byte, error) {
	if value.evidence.VerifyDigest() != nil || value.auditAssertionEventID == "" ||
		(value.disposition != IAMEvidenceStorageReserveNew &&
			value.disposition != IAMEvidenceStorageAssertExisting) ||
		(value.disposition == IAMEvidenceStorageReserveNew &&
			(value.hasPendingLink || value.pendingKey != ([ccse.MessageIDSize]byte{}) || value.pendingRevision != 0)) ||
		(value.disposition == IAMEvidenceStorageAssertExisting && value.hasPendingLink &&
			(value.pendingKey == ([ccse.MessageIDSize]byte{}) || value.pendingRevision == 0)) ||
		(value.disposition == IAMEvidenceStorageAssertExisting && !value.hasPendingLink &&
			(value.pendingKey != ([ccse.MessageIDSize]byte{}) || value.pendingRevision != 0)) {
		return [sha256.Size]byte{}, ErrPendingPlanInvalid
	}
	evidenceDigest := value.evidence.Digest()
	encoded, err := ccse.Marshal(4096, func(out *ccse.Encoder) {
		out.FixedBytes(evidenceDigest[:], sha256.Size)
		out.Uint32(uint32(value.disposition))
		out.Bool(value.hasPendingLink)
		out.FixedBytes(value.pendingKey[:], ccse.MessageIDSize)
		out.Uint64(value.pendingRevision)
		out.String(value.auditAssertionEventID)
	})
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return domainDigest(iamPendingPersistenceDomain+"STORAGE-EVIDENCE\x00", encoded), nil
}

func digestIAMPendingPersistenceCapability(value IAMPendingPersistenceCapability) ([sha256.Size]byte, error) {
	if !validIAMPendingStoredRevision(value.source) || value.auditEventID == "" ||
		value.kind == 0 || value.nextEnvelopeDigest == ([sha256.Size]byte{}) ||
		domainDigest(durablePendingEnvelopeDigestDomain, value.nextEnvelope) != value.nextEnvelopeDigest {
		return [sha256.Size]byte{}, ErrPendingPlanInvalid
	}
	evidenceDigests := make([][sha256.Size]byte, len(value.evidence))
	for index := range value.evidence {
		if value.evidence[index].VerifyDigest() != nil {
			return [sha256.Size]byte{}, ErrPendingPlanInvalid
		}
		evidenceDigests[index] = value.evidence[index].Digest()
	}
	encoded, err := ccse.Marshal(1<<20, func(out *ccse.Encoder) {
		out.FixedBytes(value.source.PendingKey[:], ccse.MessageIDSize)
		out.Uint32(uint32(value.source.Kind))
		out.Uint64(value.source.Revision)
		out.FixedBytes(value.source.PreviousEnvelopeDigestSHA256[:], sha256.Size)
		out.FixedBytes(value.source.EnvelopeDigestSHA256[:], sha256.Size)
		out.Uint64(uint64(len(value.source.CanonicalEnvelope)))
		out.Uint32(uint32(len(value.source.EvidenceDigestsSHA256)))
		for _, digest := range value.source.EvidenceDigestsSHA256 {
			out.FixedBytes(digest[:], sha256.Size)
		}
		out.Uint32(uint32(value.source.Status))
		out.Int64(value.source.CommitNotBeforeUnixNano)
		out.Int64(value.source.CommitNotAfterUnixNano)
		out.String(value.source.ExpectedAuditEventID)
		out.Uint32(uint32(value.kind))
		out.FixedBytes(value.nextEnvelopeDigest[:], sha256.Size)
		out.Uint64(uint64(len(value.nextEnvelope)))
		out.FixedBytes(value.nestedEnvelopeDigest[:], sha256.Size)
		out.Uint64(uint64(len(value.nestedEnvelope)))
		out.String(value.auditEventID)
		out.Uint32(uint32(len(evidenceDigests)))
		for _, digest := range evidenceDigests {
			out.FixedBytes(digest[:], sha256.Size)
		}
	})
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return domainDigest(iamPendingPersistenceDomain, encoded), nil
}

func digestIAMPendingRevisionRecord(record IAMPendingRevisionRecord) ([sha256.Size]byte, error) {
	if record.PendingKey == ([ccse.MessageIDSize]byte{}) || record.Kind < DurablePendingMutation ||
		record.Kind > DurablePendingOwnershipTransferCutover || record.Codec != durablePendingCodec ||
		record.CodecVersion != durablePendingCodecVersion || record.Revision == 0 ||
		record.EnvelopeDigestSHA256 == ([sha256.Size]byte{}) || len(record.CanonicalEnvelope) == 0 ||
		domainDigest(durablePendingEnvelopeDigestDomain, record.CanonicalEnvelope) != record.EnvelopeDigestSHA256 ||
		record.CommitNotBeforeUnixNano <= 0 || record.CommitNotAfterUnixNano < record.CommitNotBeforeUnixNano ||
		record.ExpectedAuditEventID == "" || !canonicalDigestList(record.EvidenceDigestsSHA256) {
		return [sha256.Size]byte{}, ErrPendingPlanInvalid
	}
	if record.Revision == 1 {
		if record.ExpectedKind != 0 || record.PreviousEnvelopeDigestSHA256 != ([sha256.Size]byte{}) ||
			len(record.PreviousCanonicalEnvelope) != 0 || record.PreviousCommitNotBeforeUnixNano != 0 ||
			record.PreviousCommitNotAfterUnixNano != 0 || record.Status != IAMPendingStatusOpen ||
			record.TerminalOutcomeDigestSHA256 != ([sha256.Size]byte{}) {
			return [sha256.Size]byte{}, ErrPendingPlanInvalid
		}
	} else {
		if record.ExpectedKind == 0 || record.PreviousEnvelopeDigestSHA256 == ([sha256.Size]byte{}) ||
			len(record.PreviousCanonicalEnvelope) == 0 ||
			domainDigest(durablePendingEnvelopeDigestDomain, record.PreviousCanonicalEnvelope) !=
				record.PreviousEnvelopeDigestSHA256 {
			return [sha256.Size]byte{}, ErrPendingPlanInvalid
		}
		switch record.Status {
		case IAMPendingStatusOpen:
			if record.ExpectedKind != record.Kind || record.TerminalOutcomeDigestSHA256 != ([sha256.Size]byte{}) ||
				record.PreviousCommitNotBeforeUnixNano <= 0 ||
				record.PreviousCommitNotAfterUnixNano < record.PreviousCommitNotBeforeUnixNano {
				return [sha256.Size]byte{}, ErrPendingPlanInvalid
			}
		case IAMPendingStatusTerminal:
			if record.TerminalOutcomeDigestSHA256 == ([sha256.Size]byte{}) {
				return [sha256.Size]byte{}, ErrPendingPlanInvalid
			}
		default:
			return [sha256.Size]byte{}, ErrPendingPlanInvalid
		}
	}
	encoded, err := ccse.Marshal(64<<10, func(out *ccse.Encoder) {
		out.FixedBytes(record.PendingKey[:], ccse.MessageIDSize)
		out.Uint32(uint32(record.ExpectedKind))
		out.Uint32(uint32(record.Kind))
		out.String(record.Codec)
		out.Uint32(record.CodecVersion)
		out.Uint64(record.Revision)
		out.FixedBytes(record.PreviousEnvelopeDigestSHA256[:], sha256.Size)
		out.Uint64(uint64(len(record.PreviousCanonicalEnvelope)))
		out.Int64(record.PreviousCommitNotBeforeUnixNano)
		out.Int64(record.PreviousCommitNotAfterUnixNano)
		out.FixedBytes(record.EnvelopeDigestSHA256[:], sha256.Size)
		out.Uint64(uint64(len(record.CanonicalEnvelope)))
		out.Uint32(uint32(len(record.EvidenceDigestsSHA256)))
		for _, digest := range record.EvidenceDigestsSHA256 {
			out.FixedBytes(digest[:], sha256.Size)
		}
		out.Uint32(uint32(record.Status))
		out.Int64(record.CommitNotBeforeUnixNano)
		out.Int64(record.CommitNotAfterUnixNano)
		out.FixedBytes(record.TerminalOutcomeDigestSHA256[:], sha256.Size)
		out.String(record.ExpectedAuditEventID)
	})
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return domainDigest(iamPendingPersistenceDomain+"REVISION\x00", encoded), nil
}

func canonicalDigestList(values [][sha256.Size]byte) bool {
	if len(values) > iamMaxPendingEvidenceRecords {
		return false
	}
	for index, value := range values {
		if value == ([sha256.Size]byte{}) ||
			(index > 0 && bytes.Compare(values[index-1][:], value[:]) >= 0) {
			return false
		}
	}
	return true
}

func cloneIAMPendingStoredRevision(value IAMPendingStoredRevision) IAMPendingStoredRevision {
	value.CanonicalEnvelope = append([]byte(nil), value.CanonicalEnvelope...)
	value.EvidenceDigestsSHA256 = append([][sha256.Size]byte(nil), value.EvidenceDigestsSHA256...)
	return value
}

func cloneIAMPersistenceEvidenceRecord(value IAMPersistenceEvidenceRecord) IAMPersistenceEvidenceRecord {
	value.CanonicalContent = append([]byte(nil), value.CanonicalContent...)
	return value
}

func cloneIAMPendingRevisionRecord(value IAMPendingRevisionRecord) IAMPendingRevisionRecord {
	value.PreviousCanonicalEnvelope = append([]byte(nil), value.PreviousCanonicalEnvelope...)
	value.CanonicalEnvelope = append([]byte(nil), value.CanonicalEnvelope...)
	value.EvidenceDigestsSHA256 = append([][sha256.Size]byte(nil), value.EvidenceDigestsSHA256...)
	return value
}

func cloneIAMPendingPersistenceCapability(value IAMPendingPersistenceCapability) IAMPendingPersistenceCapability {
	value.source = cloneIAMPendingStoredRevision(value.source)
	value.nextEnvelope = append([]byte(nil), value.nextEnvelope...)
	value.nestedEnvelope = append([]byte(nil), value.nestedEnvelope...)
	value.evidence = value.Evidence()
	return value
}
