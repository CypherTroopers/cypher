// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
)

const (
	IAMPendingAdmissionEvidenceContentType = "application/cph.aiinfra.iam.pending-admission-evidence.v1"

	iamPendingAdmissionCapabilityDomain = "CPH-AIIE-IAM-PENDING-ADMISSION-CAPABILITY-V1\x00"
	iamPendingAdmissionEvidenceDomain   = "CPH-AIIE-IAM-PENDING-ADMISSION-EVIDENCE-V1\x00"
	iamPendingAdmissionStateDomain      = "CPH-AIIE-IAM-PENDING-ADMISSION-STATE-V1\x00"
	iamPendingAdmissionCoverageDomain   = "CPH-AIIE-IAM-PENDING-ADMISSION-COVERAGE-V1\x00"
	iamMaxPendingEvidenceRecords        = 512
	iamPendingAdmissionReceiptMaxBytes  = idempotency.MaxCanonicalClaimBytes + globalid.MaxCanonicalBytes + 1<<20
)

// IAMPendingAdmissionEvidenceView is the optimistic pre-sign evidence probe.
// IAM constructs the expected full preimage first; the view may only report
// whether that exact content-addressed row already exists. A found row with
// different bytes fails closed instead of changing the storage disposition.
type IAMPendingAdmissionEvidenceView interface {
	LookupIAMPendingAdmissionEvidence(context.Context, [sha256.Size]byte) (
		IAMPersistenceEvidenceRecord, bool, error)
}

// IAMPendingAdmissionStateCapability contains only authoritative reads. It
// intentionally exposes no CanonicalStateMutation: admission reserves the
// pending/X/Y/global rows but must not apply the later audited business write.
type IAMPendingAdmissionStateCapability struct {
	assertions     []CanonicalStateAssertion
	absences       []CanonicalStateAbsence
	auditEventID   string
	coverageDigest [sha256.Size]byte
	digest         [sha256.Size]byte
}

func (value IAMPendingAdmissionStateCapability) Assertions() []CanonicalStateAssertion {
	return cloneCanonicalStateAssertions(value.assertions)
}
func (value IAMPendingAdmissionStateCapability) Absences() []CanonicalStateAbsence {
	return append([]CanonicalStateAbsence(nil), value.absences...)
}
func (value IAMPendingAdmissionStateCapability) AuditEventID() string { return value.auditEventID }
func (value IAMPendingAdmissionStateCapability) CoverageDigest() [sha256.Size]byte {
	return value.coverageDigest
}
func (value IAMPendingAdmissionStateCapability) Digest() [sha256.Size]byte { return value.digest }
func (value IAMPendingAdmissionStateCapability) VerifyDigest() error {
	digest, err := digestIAMPendingAdmissionState(value.assertions, value.absences,
		value.auditEventID, value.coverageDigest)
	if err != nil || digest != value.digest {
		return ErrPendingPlanInvalid
	}
	return nil
}
func (value IAMPendingAdmissionStateCapability) VerifyFor(envelope DurablePendingEnvelope) error {
	eventID, err := pendingAdmissionAuditEventID(envelope)
	if err != nil || value.VerifyDigest() != nil || eventID != value.auditEventID {
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
		assertionExpected, found := expected[key]
		if !found || !assertionExpected {
			return ErrPendingPlanInvalid
		}
		delete(expected, key)
	}
	for _, absence := range value.absences {
		key := canonicalStateKeyString(absence.namespace, absence.kind, absence.objectID)
		assertionExpected, found := expected[key]
		if !found || assertionExpected {
			return ErrPendingPlanInvalid
		}
		delete(expected, key)
	}
	if len(expected) != 0 {
		return ErrPendingPlanInvalid
	}
	return nil
}

// IAMPendingAdmissionCapability is the complete storage-neutral first-OPEN
// capability for IAM pending kinds 1, 2 and 3. It freezes the exact revision,
// evidence insert/assert decisions, X/Y and global claims, and all semantic
// state reads needed by the optimistic plan. VerifyFor is its fail-closed
// completeness marker.
type IAMPendingAdmissionCapability struct {
	revision                IAMPendingRevision
	evidence                []IAMEvidenceStorageCapability
	state                   IAMPendingAdmissionStateCapability
	idempotencyReservations []idempotency.Claim
	identifierClaims        []globalid.Claim
	outerRecord             ccse.Record
	outerRecordDigest       [sha256.Size]byte
	auditEventID            string
	pendingDigest           [sha256.Size]byte
	envelopeDigest          [sha256.Size]byte
	semanticAdmissionDigest [sha256.Size]byte
	digest                  [sha256.Size]byte
}

func (value IAMPendingAdmissionCapability) PendingRevision() IAMPendingRevision {
	return IAMPendingRevision{record: cloneIAMPendingRevisionRecord(value.revision.record),
		digest: value.revision.digest}
}
func (value IAMPendingAdmissionCapability) EvidenceStorageCapabilities() []IAMEvidenceStorageCapability {
	result := make([]IAMEvidenceStorageCapability, len(value.evidence))
	for index := range value.evidence {
		result[index] = cloneIAMEvidenceStorageCapability(value.evidence[index])
	}
	return result
}
func (value IAMPendingAdmissionCapability) CanonicalStateReads() IAMPendingAdmissionStateCapability {
	return cloneIAMPendingAdmissionStateCapability(value.state)
}
func (value IAMPendingAdmissionCapability) IdempotencyReservations() []idempotency.Claim {
	return append([]idempotency.Claim(nil), value.idempotencyReservations...)
}
func (value IAMPendingAdmissionCapability) IdentifierClaims() []globalid.Claim {
	return append([]globalid.Claim(nil), value.identifierClaims...)
}
func (value IAMPendingAdmissionCapability) OuterRecord() (ccse.Record, bool) {
	if value.outerRecordDigest == ([sha256.Size]byte{}) {
		return ccse.Record{}, false
	}
	return cloneCCSERecord(value.outerRecord), true
}
func (value IAMPendingAdmissionCapability) OuterRecordDigest() [sha256.Size]byte {
	return value.outerRecordDigest
}
func (value IAMPendingAdmissionCapability) AuditEventID() string { return value.auditEventID }
func (value IAMPendingAdmissionCapability) PendingDigest() [sha256.Size]byte {
	return value.pendingDigest
}
func (value IAMPendingAdmissionCapability) DurableEnvelopeDigest() [sha256.Size]byte {
	return value.envelopeDigest
}
func (value IAMPendingAdmissionCapability) Digest() [sha256.Size]byte { return value.digest }
func (value IAMPendingAdmissionCapability) VerifyDigest() error {
	digest, err := digestIAMPendingAdmissionCapability(value)
	if err != nil || digest != value.digest {
		return ErrPendingPlanInvalid
	}
	return nil
}

// VerifyOuter is the adapter boundary for the replay-verified outer record.
// It compares the complete signed record, not merely caller-supplied metadata.
func (value IAMPendingAdmissionCapability) VerifyOuter(outer ccse.VerifiedRecord) error {
	if value.VerifyDigest() != nil || outer.Digest() != value.outerRecordDigest ||
		!sameCCSERecord(value.outerRecord, outer.Record()) {
		return ErrAuthorizationMismatch
	}
	return nil
}

func (value IAMPendingAdmissionCapability) VerifyFor(envelope DurablePendingEnvelope) error {
	metadata, err := pendingAdmissionMetadata(envelope)
	if err != nil || value.VerifyDigest() != nil || value.state.VerifyFor(envelope) != nil ||
		value.auditEventID != metadata.auditEventID || value.pendingDigest != envelope.PendingDigest() ||
		value.envelopeDigest != envelope.Digest() ||
		value.semanticAdmissionDigest != metadata.semanticAdmissionDigest ||
		value.outerRecordDigest != metadata.outerRecordDigest ||
		!sameCCSERecord(value.outerRecord, metadata.outerRecord) ||
		!sameIdempotencyClaims(value.idempotencyReservations, metadata.idempotencyReservations) ||
		!sameGlobalClaims(value.identifierClaims, metadata.identifierClaims) {
		return ErrPendingPlanInvalid
	}
	record := value.revision.Record()
	if record.PendingKey != metadata.pendingKey || record.Kind != envelope.Kind() || record.Revision != 1 ||
		record.EnvelopeDigestSHA256 != envelope.Digest() || !bytes.Equal(record.CanonicalEnvelope, envelope.encoded) ||
		record.ExpectedAuditEventID != metadata.auditEventID ||
		record.CommitNotBeforeUnixNano != metadata.commitNotBefore ||
		record.CommitNotAfterUnixNano != metadata.commitNotAfter {
		return ErrPendingPlanInvalid
	}
	expected, err := pendingAdmissionEvidenceRecords(envelope, value.state.digest, metadata)
	if err != nil || !sameAdmissionEvidenceActions(value.evidence, expected, metadata.auditEventID) {
		return ErrPendingPlanInvalid
	}
	digests := admissionEvidenceDigests(expected)
	if !equalDigestSlices(record.EvidenceDigestsSHA256, digests) {
		return ErrPendingPlanInvalid
	}
	return nil
}

// BindPendingAdmissionCapability mints an initial OPEN revision. Collection
// continuation is deliberately excluded: it requires an exact predecessor
// revision capability rather than the absent-row CAS encoded here.
func (p *Planner) BindPendingAdmissionCapability(ctx context.Context,
	envelope DurablePendingEnvelope) (IAMPendingAdmissionCapability, error) {
	if err := p.ready(); err != nil {
		return IAMPendingAdmissionCapability{}, err
	}
	if err := ctx.Err(); err != nil {
		return IAMPendingAdmissionCapability{}, err
	}
	metadata, err := pendingAdmissionMetadata(envelope)
	if err != nil {
		return IAMPendingAdmissionCapability{}, err
	}
	evidenceView, ok := p.view.(IAMPendingAdmissionEvidenceView)
	if !ok {
		return IAMPendingAdmissionCapability{}, ErrViewRequired
	}
	state, err := p.bindPendingAdmissionState(ctx, envelope, metadata.auditEventID)
	if err != nil {
		return IAMPendingAdmissionCapability{}, err
	}
	records, err := pendingAdmissionEvidenceRecords(envelope, state.digest, metadata)
	if err != nil {
		return IAMPendingAdmissionCapability{}, err
	}
	actions := make([]IAMEvidenceStorageCapability, len(records))
	for index, expected := range records {
		stored, found, lookupErr := evidenceView.LookupIAMPendingAdmissionEvidence(ctx,
			expected.DigestSHA256)
		if lookupErr != nil {
			return IAMPendingAdmissionCapability{}, lookupErr
		}
		if found {
			if !equalIAMPersistenceEvidenceRecords(stored, expected) {
				return IAMPendingAdmissionCapability{}, ErrViewInconsistent
			}
		} else if nonzeroIAMPersistenceEvidenceRecord(stored) {
			return IAMPendingAdmissionCapability{}, ErrViewInconsistent
		}
		action, actionErr := newIAMEvidenceStorageAction(expected,
			IAMEvidenceStorageReserveNew, metadata.auditEventID)
		if found {
			action, actionErr = newIAMEvidenceStorageAction(expected,
				IAMEvidenceStorageAssertExisting, metadata.auditEventID)
		}
		if actionErr != nil {
			return IAMPendingAdmissionCapability{}, actionErr
		}
		actions[index] = action
	}
	evidenceDigests := admissionEvidenceDigests(records)
	revision, err := newIAMPendingRevision(IAMPendingRevisionRecord{
		PendingKey: metadata.pendingKey, Kind: envelope.Kind(), Codec: durablePendingCodec,
		CodecVersion: durablePendingCodecVersion, Revision: 1,
		EnvelopeDigestSHA256: envelope.Digest(), CanonicalEnvelope: envelope.Bytes(),
		EvidenceDigestsSHA256: evidenceDigests, Status: IAMPendingStatusOpen,
		CommitNotBeforeUnixNano: metadata.commitNotBefore,
		CommitNotAfterUnixNano:  metadata.commitNotAfter,
		ExpectedAuditEventID:    metadata.auditEventID,
	})
	if err != nil {
		return IAMPendingAdmissionCapability{}, err
	}
	capability := IAMPendingAdmissionCapability{revision: revision, evidence: actions,
		state: state, idempotencyReservations: metadata.idempotencyReservations,
		identifierClaims: metadata.identifierClaims, outerRecord: cloneCCSERecord(metadata.outerRecord),
		outerRecordDigest: metadata.outerRecordDigest, auditEventID: metadata.auditEventID,
		pendingDigest: envelope.PendingDigest(), envelopeDigest: envelope.Digest(),
		semanticAdmissionDigest: metadata.semanticAdmissionDigest}
	capability.digest, err = digestIAMPendingAdmissionCapability(capability)
	if err != nil || capability.VerifyFor(envelope) != nil {
		return IAMPendingAdmissionCapability{}, ErrPendingPlanInvalid
	}
	return capability, nil
}

type pendingAdmissionMetadataValue struct {
	pendingKey              [ccse.MessageIDSize]byte
	auditEventID            string
	semanticAdmissionDigest [sha256.Size]byte
	idempotencyReservations []idempotency.Claim
	identifierClaims        []globalid.Claim
	outerRecord             ccse.Record
	outerRecordDigest       [sha256.Size]byte
	commitNotBefore         int64
	commitNotAfter          int64
}

func pendingAdmissionMetadata(envelope DurablePendingEnvelope) (pendingAdmissionMetadataValue, error) {
	if !envelope.capability || envelope.VerifyDigest() != nil {
		return pendingAdmissionMetadataValue{}, ErrPendingPlanInvalid
	}
	var result pendingAdmissionMetadataValue
	switch envelope.Kind() {
	case DurablePendingMutation:
		plan, ok := envelope.PendingMutationPlan()
		if !ok {
			return result, ErrPendingPlanInvalid
		}
		admission := plan.AdmissionIntent()
		result.semanticAdmissionDigest = admission.Digest()
		result.idempotencyReservations = admission.IdempotencyReservations()
		result.identifierClaims = admission.IdentifierReservations()
		result.auditEventID = plan.AuditIntent().AuditEventID()
		result.outerRecord, _ = plan.AuditIntent().SourceAuthorizationRecord()
		result.outerRecordDigest = plan.AuditIntent().SourceAuthorizationDigest()
		result.commitNotBefore, result.commitNotAfter = admission.CommitNotBeforeUnixNano(),
			admission.CommitNotAfterUnixNano()
	case DurablePendingKeyEnrollment:
		plan, ok := envelope.PendingKeyEnrollmentPlan()
		if !ok {
			return result, ErrPendingPlanInvalid
		}
		admission := plan.AdmissionIntent()
		result.semanticAdmissionDigest = admission.Digest()
		result.idempotencyReservations = admission.IdempotencyReservations()
		result.identifierClaims = admission.IdentifierReservations()
		result.auditEventID = plan.AuditIntent().AuditEventID()
		result.outerRecord, _ = plan.AuditIntent().SourceAuthorizationRecord()
		result.outerRecordDigest = plan.AuditIntent().SourceAuthorizationDigest()
		result.commitNotBefore, result.commitNotAfter = admission.CommitNotBeforeUnixNano(),
			admission.CommitNotAfterUnixNano()
	case DurablePendingOwnershipTransferCollection:
		plan, ok := envelope.OwnershipTransferCollectionPlan()
		if !ok || plan.Disposition() != OwnershipTransferCollectionAppend {
			return result, ErrPendingPlanInvalid
		}
		result.semanticAdmissionDigest = plan.Digest()
		result.idempotencyReservations = plan.IdempotencyClaims()
		result.identifierClaims = plan.IdentifierClaims()
		result.commitNotBefore, result.commitNotAfter = plan.CommitNotBeforeUnixNano(),
			plan.CommitNotAfterUnixNano()
		joined, err := idempotency.JoinedAuditEventID(plan.next.Binding)
		if err != nil {
			return result, ErrPendingPlanInvalid
		}
		result.auditEventID = joined
		if len(plan.next.Approvals) != 1 {
			return result, ErrPendingPlanInvalid
		}
		result.outerRecord = plan.next.Approvals[0].Signed.Record()
		result.outerRecordDigest = plan.next.Approvals[0].Signed.Digest()
	default:
		return result, ErrPendingPlanInvalid
	}
	parent, _, err := pendingIdempotencyBindings(result.idempotencyReservations)
	if err != nil || result.semanticAdmissionDigest == ([sha256.Size]byte{}) ||
		result.auditEventID == "" || result.outerRecordDigest == ([sha256.Size]byte{}) ||
		result.commitNotBefore <= 0 ||
		result.commitNotAfter <= result.commitNotBefore {
		return pendingAdmissionMetadataValue{}, ErrPendingPlanInvalid
	}
	result.pendingKey = parent.Key
	result.idempotencyReservations, err = idempotency.NormalizeClaims(result.idempotencyReservations)
	if err != nil {
		return pendingAdmissionMetadataValue{}, ErrPendingPlanInvalid
	}
	result.identifierClaims, err = normalizeGlobalClaims(result.identifierClaims)
	if err != nil {
		return pendingAdmissionMetadataValue{}, ErrPendingPlanInvalid
	}
	actualOuterDigest, err := result.outerRecord.Digest(ccse.DefaultLimits())
	if err != nil || actualOuterDigest != result.outerRecordDigest {
		return pendingAdmissionMetadataValue{}, ErrPendingPlanInvalid
	}
	return result, nil
}

func pendingAdmissionAuditEventID(envelope DurablePendingEnvelope) (string, error) {
	metadata, err := pendingAdmissionMetadata(envelope)
	return metadata.auditEventID, err
}

func (p *Planner) bindPendingAdmissionState(ctx context.Context, envelope DurablePendingEnvelope,
	auditEventID string) (IAMPendingAdmissionStateCapability, error) {
	view, ok := p.view.(CanonicalIAMStateView)
	if !ok {
		return IAMPendingAdmissionStateCapability{}, ErrViewRequired
	}
	sidecarView, ok := p.view.(CanonicalIAMSidecarStateView)
	if !ok {
		return IAMPendingAdmissionStateCapability{}, ErrViewRequired
	}
	var assertions []CanonicalStateAssertion
	var absences []CanonicalStateAbsence
	switch envelope.Kind() {
	case DurablePendingMutation, DurablePendingKeyEnrollment:
		request, err := envelope.JoinedAuditRequest()
		if err != nil || request.execution == nil {
			return IAMPendingAdmissionStateCapability{}, ErrPendingPlanInvalid
		}
		full, err := buildIAMCanonicalStateBundle(ctx, p.view, view,
			*request.execution, auditEventID)
		if err != nil {
			return IAMPendingAdmissionStateCapability{}, err
		}
		assertions, absences, err = canonicalAdmissionReads(full)
		if err != nil {
			return IAMPendingAdmissionStateCapability{}, err
		}
	case DurablePendingOwnershipTransferCollection:
		result, err := p.bindOwnershipTransferCollectionState(ctx, envelope, auditEventID,
			view, sidecarView)
		if err != nil || result.VerifyFor(envelope) != nil {
			return IAMPendingAdmissionStateCapability{}, ErrPendingPlanInvalid
		}
		return result, nil
	default:
		return IAMPendingAdmissionStateCapability{}, ErrPendingPlanInvalid
	}
	assertions, absences, err := normalizeCanonicalAdmissionReads(assertions, absences)
	if err != nil {
		return IAMPendingAdmissionStateCapability{}, err
	}
	coverage, err := pendingAdmissionCoverageDigest(envelope)
	if err != nil {
		return IAMPendingAdmissionStateCapability{}, err
	}
	result := IAMPendingAdmissionStateCapability{assertions: assertions, absences: absences,
		auditEventID: auditEventID, coverageDigest: coverage}
	result.digest, err = digestIAMPendingAdmissionState(assertions, absences, auditEventID, coverage)
	if err != nil || result.VerifyFor(envelope) != nil {
		return IAMPendingAdmissionStateCapability{}, ErrPendingPlanInvalid
	}
	return result, nil
}

func (p *Planner) bindOwnershipTransferCollectionState(ctx context.Context,
	envelope DurablePendingEnvelope, auditEventID string, view CanonicalIAMStateView,
	sidecarView CanonicalIAMSidecarStateView) (IAMPendingAdmissionStateCapability, error) {
	plan, ok := envelope.OwnershipTransferCollectionPlan()
	if !ok {
		return IAMPendingAdmissionStateCapability{}, ErrPendingPlanInvalid
	}
	assertions := make([]CanonicalStateAssertion, 0, len(plan.dependencies)+1)
	for _, dependency := range plan.Dependencies() {
		record, found, err := view.CanonicalIAMStateAssertion(ctx, dependency, auditEventID)
		if err != nil {
			return IAMPendingAdmissionStateCapability{}, err
		}
		if !found || !canonicalStateRecordMatchesPrecondition(record, dependency) {
			return IAMPendingAdmissionStateCapability{}, ErrViewInconsistent
		}
		assertion, err := newCanonicalStateAssertion(record)
		if err != nil {
			return IAMPendingAdmissionStateCapability{}, ErrViewInconsistent
		}
		assertions = append(assertions, assertion)
	}
	projection, _, _, err := normalizeOwnershipTransferPayload(plan.next.CanonicalPayload)
	if err != nil {
		return IAMPendingAdmissionStateCapability{}, ErrPendingPlanInvalid
	}
	request, err := canonicalWriterLeaseSidecarRequest(ctx, p.view, WriterFence{
		Entity: EntityRef{Kind: EntityOwnershipTransfer, PrincipalKind: projection.SubjectKind,
			ID: projection.TransferAuthorizationID},
		WriterIdentity: plan.authorizedWriterIdentity, HomeRegion: plan.authorizedWriterHomeRegion,
		WriterEpoch: plan.authorizedWriterEpoch, EvidenceDigest: plan.writerEvidenceDigest,
	}, auditEventID)
	if err != nil {
		return IAMPendingAdmissionStateCapability{}, err
	}
	assertion, _, _, kind, err := bindCanonicalSidecar(ctx, sidecarView, request,
		make(map[string]CanonicalStateRecord))
	if err != nil || kind != 1 {
		return IAMPendingAdmissionStateCapability{}, ErrViewInconsistent
	}
	assertions = append(assertions, assertion)
	assertions, absences, err := normalizeCanonicalAdmissionReads(assertions, nil)
	if err != nil {
		return IAMPendingAdmissionStateCapability{}, err
	}
	coverage, err := pendingAdmissionCoverageDigest(envelope)
	if err != nil {
		return IAMPendingAdmissionStateCapability{}, err
	}
	result := IAMPendingAdmissionStateCapability{assertions: assertions, absences: absences,
		auditEventID: auditEventID, coverageDigest: coverage}
	result.digest, err = digestIAMPendingAdmissionState(assertions, absences, auditEventID, coverage)
	if err != nil || result.VerifyDigest() != nil {
		return IAMPendingAdmissionStateCapability{}, ErrPendingPlanInvalid
	}
	return result, nil
}

func canonicalAdmissionReads(full IAMCanonicalStateBundle) ([]CanonicalStateAssertion,
	[]CanonicalStateAbsence, error) {
	if full.VerifyDigest() != nil {
		return nil, nil, ErrPendingPlanInvalid
	}
	assertions := full.Assertions()
	absences := full.Absences()
	seen := make(map[string]struct{}, len(assertions)+len(absences)+len(full.mutations))
	for _, assertion := range assertions {
		seen[canonicalStateRecordKey(assertion.record)] = struct{}{}
	}
	for _, absence := range absences {
		seen[canonicalStateKeyString(absence.namespace, absence.kind, absence.objectID)] = struct{}{}
	}
	for _, mutation := range full.mutations {
		key := canonicalStateRecordKey(mutation.next)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		if mutation.expected != nil {
			assertion, err := newCanonicalStateAssertion(*mutation.expected)
			if err != nil {
				return nil, nil, err
			}
			assertions = append(assertions, assertion)
		} else {
			absence, err := newCanonicalStateAbsence(mutation.next.Namespace,
				mutation.next.Kind, mutation.next.ObjectID)
			if err != nil {
				return nil, nil, err
			}
			absences = append(absences, absence)
		}
	}
	return normalizeCanonicalAdmissionReads(assertions, absences)
}

func normalizeCanonicalAdmissionReads(assertions []CanonicalStateAssertion,
	absences []CanonicalStateAbsence) ([]CanonicalStateAssertion, []CanonicalStateAbsence, error) {
	assertions = cloneCanonicalStateAssertions(assertions)
	absences = append([]CanonicalStateAbsence(nil), absences...)
	sort.Slice(assertions, func(i, j int) bool {
		return canonicalStateRecordKey(assertions[i].record) < canonicalStateRecordKey(assertions[j].record)
	})
	for index, assertion := range assertions {
		if assertion.VerifyDigest() != nil || (index > 0 &&
			canonicalStateRecordKey(assertion.record) == canonicalStateRecordKey(assertions[index-1].record)) {
			return nil, nil, ErrPendingPlanInvalid
		}
	}
	sort.Slice(absences, func(i, j int) bool {
		return canonicalStateKeyString(absences[i].namespace, absences[i].kind, absences[i].objectID) <
			canonicalStateKeyString(absences[j].namespace, absences[j].kind, absences[j].objectID)
	})
	for index, absence := range absences {
		key := canonicalStateKeyString(absence.namespace, absence.kind, absence.objectID)
		if absence.VerifyDigest() != nil || (index > 0 && key == canonicalStateKeyString(
			absences[index-1].namespace, absences[index-1].kind, absences[index-1].objectID)) {
			return nil, nil, ErrPendingPlanInvalid
		}
		position := sort.Search(len(assertions), func(i int) bool {
			return canonicalStateRecordKey(assertions[i].record) >= key
		})
		if position < len(assertions) && canonicalStateRecordKey(assertions[position].record) == key {
			return nil, nil, ErrPendingPlanInvalid
		}
	}
	if len(assertions)+len(absences) == 0 || len(assertions)+len(absences) > iamCanonicalStateMaxAssertions {
		return nil, nil, ErrPendingPlanInvalid
	}
	return assertions, absences, nil
}

func pendingAdmissionCoverageDigest(envelope DurablePendingEnvelope) ([sha256.Size]byte, error) {
	if !envelope.capability || envelope.VerifyDigest() != nil {
		return [sha256.Size]byte{}, ErrPendingPlanInvalid
	}
	var semantic [sha256.Size]byte
	switch envelope.Kind() {
	case DurablePendingMutation, DurablePendingKeyEnrollment:
		request, err := envelope.JoinedAuditRequest()
		if err != nil || request.execution == nil {
			return [sha256.Size]byte{}, ErrPendingPlanInvalid
		}
		semantic, err = canonicalStateCoverageDigest(*request.execution)
		if err != nil {
			return [sha256.Size]byte{}, err
		}
	case DurablePendingOwnershipTransferCollection:
		plan, ok := envelope.OwnershipTransferCollectionPlan()
		if !ok {
			return [sha256.Size]byte{}, ErrPendingPlanInvalid
		}
		dependencies, err := canonicalSnapshotPreconditions(plan.Dependencies())
		if err != nil {
			return [sha256.Size]byte{}, err
		}
		planDigest := plan.Digest()
		encoded, err := ccse.Marshal(8<<20, func(out *ccse.Encoder) {
			out.FixedBytes(planDigest[:], sha256.Size)
			out.Bytes(dependencies)
			out.String(plan.authorizedWriterIdentity)
			out.String(plan.authorizedWriterHomeRegion)
			out.Uint64(plan.authorizedWriterEpoch)
			out.FixedBytes(plan.writerEvidenceDigest[:], sha256.Size)
		})
		if err != nil {
			return [sha256.Size]byte{}, err
		}
		semantic = domainDigest(iamPendingAdmissionCoverageDomain+"COLLECTION\x00", encoded)
	default:
		return [sha256.Size]byte{}, ErrPendingPlanInvalid
	}
	pendingDigest, envelopeDigest := envelope.PendingDigest(), envelope.Digest()
	encoded, err := ccse.Marshal(256, func(out *ccse.Encoder) {
		out.Uint32(uint32(envelope.Kind()))
		out.FixedBytes(pendingDigest[:], sha256.Size)
		out.FixedBytes(envelopeDigest[:], sha256.Size)
		out.FixedBytes(semantic[:], sha256.Size)
	})
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return domainDigest(iamPendingAdmissionCoverageDomain, encoded), nil
}

// pendingAdmissionExpectedReadKeys derives the complete pre-state key set
// without consulting the view. Values are true for present-row assertions and
// false for absent-row predicates. When ordered semantic steps touch one key
// more than once, only its first pre-state observation belongs to admission.
func pendingAdmissionExpectedReadKeys(envelope DurablePendingEnvelope) (map[string]bool, error) {
	result := make(map[string]bool)
	add := func(kind, objectID string, present bool) error {
		if _, ok := canonicalStateSpec(kind); !ok || objectID == "" {
			return ErrPendingPlanInvalid
		}
		key := canonicalStateKeyString(CanonicalStateNamespaceIAM, kind, objectID)
		if _, exists := result[key]; !exists {
			result[key] = present
		}
		return nil
	}
	addDependency := func(dependency SnapshotPrecondition) error {
		kind, ok := canonicalStateKindForEntity(dependency.Entity)
		if !ok {
			return ErrPendingPlanInvalid
		}
		return add(kind, dependency.Entity.ID, true)
	}
	addCAS := func(cas CASIntent) error {
		for _, dependency := range cas.Dependencies {
			if err := addDependency(dependency); err != nil {
				return err
			}
		}
		kind, ok := canonicalStateKindForEntity(cas.Entity)
		if !ok || add(kind, cas.Entity.ID, !cas.ExpectedAbsent) != nil ||
			add(CanonicalStateKindIAMWriterLease, canonicalEntityObjectID(cas.Entity), true) != nil {
			return ErrPendingPlanInvalid
		}
		if cas.ConsumeChallenge {
			if err := add(CanonicalStateKindIAMProofChallenge,
				hex.EncodeToString(cas.Challenge[:]), true); err != nil {
				return err
			}
		}
		if cas.PrincipalIndex.Mode != 0 {
			if err := add(CanonicalStateKindIAMPrincipalIdentityIndex,
				principalIndexObjectID(cas.PrincipalIndex.PrincipalKind,
					cas.PrincipalIndex.PrincipalIdentity),
				cas.PrincipalIndex.Mode != globalid.ReserveNew); err != nil {
				return err
			}
		}
		if cas.PredecessorIndexMode != 0 {
			if err := add(CanonicalStateKindIAMRotationPredecessorIndex,
				cas.RotationPredecessorKeyID,
				cas.PredecessorIndexMode == PredecessorAssertExisting); err != nil {
				return err
			}
		}
		if cas.SubjectKeySetDigest != ([sha256.Size]byte{}) {
			if err := add(CanonicalStateKindIAMSubjectKeySet,
				principalIndexObjectID(cas.Entity.PrincipalKind, cas.SubjectIdentity), true); err != nil {
				return err
			}
		}
		if cas.ExpectedSubjectAbsent {
			if err := add(CanonicalStateKindIAMPrincipalIdentityIndex,
				principalIndexObjectID(cas.SubjectKind, cas.SubjectIdentity), false); err != nil {
				return err
			}
		}
		return nil
	}
	switch envelope.Kind() {
	case DurablePendingMutation:
		plan, ok := envelope.PendingMutationPlan()
		if !ok || addCAS(plan.CAS()) != nil {
			return nil, ErrPendingPlanInvalid
		}
	case DurablePendingKeyEnrollment:
		plan, ok := envelope.PendingKeyEnrollmentPlan()
		if !ok {
			return nil, ErrPendingPlanInvalid
		}
		for _, cas := range plan.CASIntents() {
			if err := addCAS(cas); err != nil {
				return nil, err
			}
		}
	case DurablePendingOwnershipTransferCollection:
		plan, ok := envelope.OwnershipTransferCollectionPlan()
		if !ok {
			return nil, ErrPendingPlanInvalid
		}
		for _, dependency := range plan.Dependencies() {
			if err := addDependency(dependency); err != nil {
				return nil, err
			}
		}
		projection, _, _, err := normalizeOwnershipTransferPayload(plan.next.CanonicalPayload)
		if err != nil {
			return nil, ErrPendingPlanInvalid
		}
		entity := EntityRef{Kind: EntityOwnershipTransfer, PrincipalKind: projection.SubjectKind,
			ID: projection.TransferAuthorizationID}
		if err := add(CanonicalStateKindIAMWriterLease, canonicalEntityObjectID(entity), true); err != nil {
			return nil, err
		}
	default:
		return nil, ErrPendingPlanInvalid
	}
	if len(result) == 0 || len(result) > iamCanonicalStateMaxAssertions {
		return nil, ErrPendingPlanInvalid
	}
	return result, nil
}

func pendingAdmissionEvidenceRecords(envelope DurablePendingEnvelope, stateDigest [sha256.Size]byte,
	metadata pendingAdmissionMetadataValue) ([]IAMPersistenceEvidenceRecord, error) {
	if stateDigest == ([sha256.Size]byte{}) {
		return nil, ErrPendingPlanInvalid
	}
	signed, err := pendingAdmissionSignedRecords(envelope, metadata.auditEventID)
	if err != nil {
		return nil, err
	}
	idempotencyBytes, err := idempotency.CanonicalBytes(metadata.idempotencyReservations)
	if err != nil {
		return nil, err
	}
	identifierBytes, err := globalid.CanonicalBytes(metadata.identifierClaims)
	if err != nil {
		return nil, err
	}
	signedDigests := make([][sha256.Size]byte, len(signed))
	for index := range signed {
		signedDigests[index] = signed[index].DigestSHA256
	}
	pendingDigest, envelopeDigest := envelope.PendingDigest(), envelope.Digest()
	receiptBytes, err := ccse.Marshal(iamPendingAdmissionReceiptMaxBytes, func(out *ccse.Encoder) {
		out.Uint32(uint32(envelope.Kind()))
		out.FixedBytes(pendingDigest[:], sha256.Size)
		out.FixedBytes(envelopeDigest[:], sha256.Size)
		out.Uint64(uint64(len(envelope.encoded)))
		out.FixedBytes(metadata.semanticAdmissionDigest[:], sha256.Size)
		out.FixedBytes(stateDigest[:], sha256.Size)
		out.String(metadata.auditEventID)
		out.Int64(metadata.commitNotBefore)
		out.Int64(metadata.commitNotAfter)
		out.Bytes(idempotencyBytes)
		out.Bytes(identifierBytes)
		out.Uint32(uint32(len(signedDigests)))
		for _, digest := range signedDigests {
			out.FixedBytes(digest[:], sha256.Size)
		}
	})
	if err != nil {
		return nil, err
	}
	receipt := IAMPersistenceEvidenceRecord{
		DigestSHA256: domainDigest(iamPendingAdmissionEvidenceDomain, receiptBytes),
		Kind:         IAMEvidenceSemanticReceipt, ContentType: IAMPendingAdmissionEvidenceContentType,
		CanonicalContent: receiptBytes, ExpectedAuditEventID: metadata.auditEventID,
	}
	result := append(signed, receipt)
	sort.Slice(result, func(i, j int) bool {
		return bytes.Compare(result[i].DigestSHA256[:], result[j].DigestSHA256[:]) < 0
	})
	if len(result) == 0 || len(result) > iamMaxPendingEvidenceRecords {
		return nil, ErrPendingPlanInvalid
	}
	for index := range result {
		if _, err := digestIAMPersistenceEvidenceRecord(result[index]); err != nil ||
			(index > 0 && result[index-1].DigestSHA256 == result[index].DigestSHA256) {
			return nil, ErrPendingPlanInvalid
		}
	}
	return result, nil
}

func pendingAdmissionSignedRecords(envelope DurablePendingEnvelope,
	auditEventID string) ([]IAMPersistenceEvidenceRecord, error) {
	var records []ccse.Record
	switch envelope.Kind() {
	case DurablePendingMutation:
		plan, _ := envelope.PendingMutationPlan()
		record, ok := plan.AuditIntent().SourceAuthorizationRecord()
		if !ok {
			return nil, ErrPendingPlanInvalid
		}
		records = append(records, record)
	case DurablePendingKeyEnrollment:
		plan, _ := envelope.PendingKeyEnrollmentPlan()
		record, ok := plan.AuditIntent().SourceAuthorizationRecord()
		if !ok {
			return nil, ErrPendingPlanInvalid
		}
		records = append(records, record)
	case DurablePendingOwnershipTransferCollection:
		plan, _ := envelope.OwnershipTransferCollectionPlan()
		for _, approval := range plan.next.Approvals {
			records = append(records, approval.Signed.Record())
		}
		for _, retained := range plan.next.FixedEvidence.KeyClosureRecords {
			records = append(records, retained.Record())
		}
		for _, retained := range plan.next.FixedEvidence.EvidenceRecords {
			records = append(records, retained.Record())
		}
	default:
		return nil, ErrPendingPlanInvalid
	}
	result := make([]IAMPersistenceEvidenceRecord, 0, len(records))
	seen := make(map[[sha256.Size]byte][]byte, len(records))
	for _, record := range records {
		digest, err := record.Digest(ccse.DefaultLimits())
		if err != nil || digest == ([sha256.Size]byte{}) {
			return nil, ErrPendingPlanInvalid
		}
		canonical, err := canonicalSignedAuthorizationEvidence(record)
		if err != nil {
			return nil, ErrPendingPlanInvalid
		}
		if previous, duplicate := seen[digest]; duplicate {
			if !bytes.Equal(previous, canonical) {
				return nil, ErrPendingPlanInvalid
			}
			continue
		}
		seen[digest] = append([]byte(nil), canonical...)
		result = append(result, IAMPersistenceEvidenceRecord{DigestSHA256: digest,
			Kind: IAMEvidenceSignedCCSERecord, ContentType: IAMEvidenceContentTypeSignedCCSERecord,
			CanonicalContent: canonical, ExpectedAuditEventID: auditEventID})
	}
	sort.Slice(result, func(i, j int) bool {
		return bytes.Compare(result[i].DigestSHA256[:], result[j].DigestSHA256[:]) < 0
	})
	return result, nil
}

func newIAMEvidenceStorageAction(record IAMPersistenceEvidenceRecord, disposition uint8,
	auditEventID string) (IAMEvidenceStorageCapability, error) {
	digest, err := digestIAMPersistenceEvidenceRecord(record)
	if err != nil {
		return IAMEvidenceStorageCapability{}, err
	}
	result := IAMEvidenceStorageCapability{evidence: IAMPersistenceEvidenceCapability{
		record: cloneIAMPersistenceEvidenceRecord(record), digest: digest},
		disposition: disposition, auditAssertionEventID: auditEventID}
	result.digest, err = digestIAMEvidenceStorageCapability(result)
	if err != nil || result.VerifyDigest() != nil {
		return IAMEvidenceStorageCapability{}, ErrPendingPlanInvalid
	}
	return result, nil
}

func digestIAMPendingAdmissionState(assertions []CanonicalStateAssertion,
	absences []CanonicalStateAbsence, auditEventID string,
	coverage [sha256.Size]byte) ([sha256.Size]byte, error) {
	assertions, absences, err := normalizeCanonicalAdmissionReads(assertions, absences)
	if err != nil || auditEventID == "" || coverage == ([sha256.Size]byte{}) {
		return [sha256.Size]byte{}, ErrPendingPlanInvalid
	}
	encoded, err := ccse.Marshal(128<<10, func(out *ccse.Encoder) {
		out.String(auditEventID)
		out.FixedBytes(coverage[:], sha256.Size)
		out.Uint32(uint32(len(assertions)))
		for _, assertion := range assertions {
			out.FixedBytes(assertion.digest[:], sha256.Size)
		}
		out.Uint32(uint32(len(absences)))
		for _, absence := range absences {
			out.FixedBytes(absence.digest[:], sha256.Size)
		}
	})
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return domainDigest(iamPendingAdmissionStateDomain, encoded), nil
}

func digestIAMPendingAdmissionCapability(value IAMPendingAdmissionCapability) ([sha256.Size]byte, error) {
	if value.revision.VerifyDigest() != nil || value.state.VerifyDigest() != nil ||
		value.auditEventID == "" || value.pendingDigest == ([sha256.Size]byte{}) ||
		value.envelopeDigest == ([sha256.Size]byte{}) ||
		value.semanticAdmissionDigest == ([sha256.Size]byte{}) ||
		value.outerRecordDigest == ([sha256.Size]byte{}) || len(value.evidence) == 0 ||
		len(value.evidence) > iamMaxPendingEvidenceRecords {
		return [sha256.Size]byte{}, ErrPendingPlanInvalid
	}
	idempotencyBytes, err := idempotency.CanonicalBytes(value.idempotencyReservations)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	identifierBytes, err := globalid.CanonicalBytes(value.identifierClaims)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	actualOuterDigest, err := value.outerRecord.Digest(ccse.DefaultLimits())
	if err != nil || actualOuterDigest != value.outerRecordDigest {
		return [sha256.Size]byte{}, ErrPendingPlanInvalid
	}
	outerCanonical, err := canonicalSignedAuthorizationEvidence(value.outerRecord)
	if err != nil {
		return [sha256.Size]byte{}, ErrPendingPlanInvalid
	}
	actionDigests := make([][sha256.Size]byte, len(value.evidence))
	for index := range value.evidence {
		if value.evidence[index].VerifyDigest() != nil ||
			value.evidence[index].AuditAssertionEventID() != value.auditEventID {
			return [sha256.Size]byte{}, ErrPendingPlanInvalid
		}
		actionDigests[index] = value.evidence[index].digest
	}
	revisionDigest, stateDigest := value.revision.Digest(), value.state.Digest()
	idempotencyDigest := domainDigest(iamPendingAdmissionCapabilityDomain+"IDEMPOTENCY\x00",
		idempotencyBytes)
	identifierDigest := domainDigest(iamPendingAdmissionCapabilityDomain+"IDENTIFIERS\x00",
		identifierBytes)
	outerCanonicalDigest := domainDigest(iamPendingAdmissionCapabilityDomain+"OUTER-RECORD\x00",
		outerCanonical)
	encoded, err := ccse.Marshal(64<<10, func(out *ccse.Encoder) {
		out.FixedBytes(revisionDigest[:], sha256.Size)
		out.FixedBytes(stateDigest[:], sha256.Size)
		out.FixedBytes(value.pendingDigest[:], sha256.Size)
		out.FixedBytes(value.envelopeDigest[:], sha256.Size)
		out.FixedBytes(value.semanticAdmissionDigest[:], sha256.Size)
		out.FixedBytes(value.outerRecordDigest[:], sha256.Size)
		out.FixedBytes(outerCanonicalDigest[:], sha256.Size)
		out.Uint64(uint64(len(outerCanonical)))
		out.String(value.auditEventID)
		out.FixedBytes(idempotencyDigest[:], sha256.Size)
		out.Uint64(uint64(len(idempotencyBytes)))
		out.FixedBytes(identifierDigest[:], sha256.Size)
		out.Uint64(uint64(len(identifierBytes)))
		out.Uint32(uint32(len(actionDigests)))
		for _, digest := range actionDigests {
			out.FixedBytes(digest[:], sha256.Size)
		}
	})
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return domainDigest(iamPendingAdmissionCapabilityDomain, encoded), nil
}

func admissionEvidenceDigests(records []IAMPersistenceEvidenceRecord) [][sha256.Size]byte {
	result := make([][sha256.Size]byte, len(records))
	for index := range records {
		result[index] = records[index].DigestSHA256
	}
	sort.Slice(result, func(i, j int) bool { return bytes.Compare(result[i][:], result[j][:]) < 0 })
	return result
}

func sameAdmissionEvidenceActions(actions []IAMEvidenceStorageCapability,
	records []IAMPersistenceEvidenceRecord, eventID string) bool {
	if len(actions) != len(records) {
		return false
	}
	for index := range actions {
		if actions[index].VerifyDigest() != nil || actions[index].auditAssertionEventID != eventID ||
			(actions[index].disposition != IAMEvidenceStorageReserveNew &&
				actions[index].disposition != IAMEvidenceStorageAssertExisting) ||
			actions[index].hasPendingLink ||
			!equalIAMPersistenceEvidenceRecords(actions[index].evidence.record, records[index]) {
			return false
		}
	}
	return true
}

func equalIAMPersistenceEvidenceRecords(left, right IAMPersistenceEvidenceRecord) bool {
	return left.DigestSHA256 == right.DigestSHA256 && left.Kind == right.Kind &&
		left.ContentType == right.ContentType && bytes.Equal(left.CanonicalContent, right.CanonicalContent) &&
		left.ExpectedAuditEventID == right.ExpectedAuditEventID
}

func nonzeroIAMPersistenceEvidenceRecord(value IAMPersistenceEvidenceRecord) bool {
	return value.DigestSHA256 != ([sha256.Size]byte{}) || value.Kind != 0 || value.ContentType != "" ||
		len(value.CanonicalContent) != 0 || value.ExpectedAuditEventID != ""
}

func cloneIAMEvidenceStorageCapability(value IAMEvidenceStorageCapability) IAMEvidenceStorageCapability {
	value.evidence = IAMPersistenceEvidenceCapability{
		record: cloneIAMPersistenceEvidenceRecord(value.evidence.record), digest: value.evidence.digest}
	return value
}

func cloneIAMPendingAdmissionStateCapability(value IAMPendingAdmissionStateCapability) IAMPendingAdmissionStateCapability {
	value.assertions = cloneCanonicalStateAssertions(value.assertions)
	value.absences = append([]CanonicalStateAbsence(nil), value.absences...)
	return value
}

func sameGlobalClaims(left, right []globalid.Claim) bool {
	leftBytes, leftErr := globalid.CanonicalBytes(left)
	rightBytes, rightErr := globalid.CanonicalBytes(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func sameCCSERecord(left, right ccse.Record) bool {
	leftDigest, leftErr := left.Digest(ccse.DefaultLimits())
	rightDigest, rightErr := right.Digest(ccse.DefaultLimits())
	if leftErr != nil || rightErr != nil || leftDigest != rightDigest {
		return false
	}
	leftCanonical, leftErr := canonicalSignedAuthorizationEvidence(left)
	rightCanonical, rightErr := canonicalSignedAuthorizationEvidence(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftCanonical, rightCanonical)
}
