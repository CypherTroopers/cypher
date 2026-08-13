// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/replayresult"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

const (
	pendingReconciliationEvidenceDomain = "CPH-AIIE-IAM-PENDING-RECONCILIATION-EVIDENCE-V1\x00"

	// PendingReconciliationResultContentType is the closed durable replay
	// result type for FAILED/TIMED_OUT IAM pending operations.
	PendingReconciliationResultContentType = "application/vnd.cph.aiinfra.iam.reconciliation-result.v1+ccse"
	// MaxPendingReconciliationResultPayloadBytes is the exact public payload
	// bound accepted and produced by IAM's strict failure-result codec. Outer
	// joined-result codecs must reserve at least this many bytes for the inner
	// result or reject the operation before signing.
	MaxPendingReconciliationResultPayloadBytes = replayresult.MaxPayloadBytes

	pendingReconciliationClockDomain                 = "CPH-AIIE-IAM-PENDING-RECONCILIATION-CLOCK-V1\x00"
	pendingReconciliationFinalClockRequirementDomain = "CPH-AIIE-IAM-RECONCILIATION-FINAL-CLOCK-REQUIREMENT-V1\x00"

	pendingReconciliationExpiredEvidenceContentType = "application/vnd.cph.aiinfra.iam.expired-clock.v1+ccse"
	pendingReconciliationFailedEvidenceContentType  = "application/vnd.cph.aiinfra.iam.signed-failure.v1+ccse"
)

type pendingReconciliationEvidenceKind uint8

const (
	pendingReconciliationExpiredClockEvidence pendingReconciliationEvidenceKind = iota + 1
	pendingReconciliationSignedFailureEvidence
)

// ReconciliationTransactionClockSnapshot is a final-UoW database receipt.
// It is never retained by a pre-sign IAM request. Coordinators may construct
// it after opening their final UoW and validate it against the request's
// ReconciliationFinalClockRequirement.
type ReconciliationTransactionClockSnapshot struct {
	TransactionID                  string
	ObservedAtUnixNano             int64
	PendingDigest                  [32]byte
	OriginalCommitNotAfterUnixNano int64
	SnapshotDigest                 [32]byte
}

// ReconciliationFinalClockRequirement is the pre-sign, transaction-neutral
// clock constraint. The final coordinator obtains xid/clock_timestamp from
// its active UoW, checks ObservedAt >= AuditOccurredAt, and binds that fresh
// receipt into the coordinator-owned joined result. An xid must never be
// embedded in the IAM request before its outer AuditEvent is signed.
type ReconciliationFinalClockRequirement struct {
	pendingDigest                  [32]byte
	originalCommitNotAfterUnixNano int64
	auditOccurredAtUnixNano        int64
	digest                         [32]byte
}

func (value ReconciliationFinalClockRequirement) PendingDigest() [32]byte {
	return value.pendingDigest
}
func (value ReconciliationFinalClockRequirement) OriginalCommitNotAfterUnixNano() int64 {
	return value.originalCommitNotAfterUnixNano
}
func (value ReconciliationFinalClockRequirement) AuditOccurredAtUnixNano() int64 {
	return value.auditOccurredAtUnixNano
}
func (value ReconciliationFinalClockRequirement) Digest() [32]byte { return value.digest }
func (value ReconciliationFinalClockRequirement) Verify() error {
	rebuilt, err := newReconciliationFinalClockRequirement(value.pendingDigest,
		value.originalCommitNotAfterUnixNano, value.auditOccurredAtUnixNano)
	if err != nil || rebuilt != value {
		return ErrPendingPlanInvalid
	}
	return nil
}

// ValidateObservation checks a fresh final-UoW receipt without retaining its
// transaction identity in this pre-sign capability.
func (value ReconciliationFinalClockRequirement) ValidateObservation(
	snapshot ReconciliationTransactionClockSnapshot) error {
	if value.Verify() != nil || verifyReconciliationClock(snapshot) != nil ||
		snapshot.PendingDigest != value.pendingDigest ||
		snapshot.OriginalCommitNotAfterUnixNano != value.originalCommitNotAfterUnixNano ||
		snapshot.ObservedAtUnixNano < value.auditOccurredAtUnixNano {
		return ErrInvalidCommitWindow
	}
	return nil
}

func newReconciliationFinalClockRequirement(pendingDigest [32]byte, deadline,
	auditOccurredAt int64) (ReconciliationFinalClockRequirement, error) {
	if pendingDigest == ([32]byte{}) || deadline <= 0 || auditOccurredAt < deadline {
		return ReconciliationFinalClockRequirement{}, ErrInvalidCommitWindow
	}
	encoded, err := ccse.Marshal(64, func(out *ccse.Encoder) {
		out.FixedBytes(pendingDigest[:], 32)
		out.Int64(deadline)
		out.Int64(auditOccurredAt)
	})
	if err != nil {
		return ReconciliationFinalClockRequirement{}, err
	}
	return ReconciliationFinalClockRequirement{pendingDigest: pendingDigest,
		originalCommitNotAfterUnixNano: deadline, auditOccurredAtUnixNano: auditOccurredAt,
		digest: domainDigest(pendingReconciliationFinalClockRequirementDomain, encoded)}, nil
}

// ReconciliationTransactionClockView is retained for adapter compatibility.
// IAM planning deliberately does not require it; the final coordinator owns
// the UoW receipt and validates it after outer AuditEvent signing.
type ReconciliationTransactionClockView interface {
	SnapshotReconciliationTransactionClock(context.Context, [32]byte, int64) (ReconciliationTransactionClockSnapshot, error)
}

// NewReconciliationTransactionClockSnapshot is an adapter helper, not an
// authorization constructor. Planner accepts its result only when returned by
// its already-trusted transaction-bound View.
func NewReconciliationTransactionClockSnapshot(transactionID string, observedAt int64,
	pendingDigest [32]byte, originalDeadline int64) (ReconciliationTransactionClockSnapshot, error) {
	if transactionID == "" || len(transactionID) > 256 || observedAt < originalDeadline ||
		originalDeadline <= 0 || pendingDigest == ([32]byte{}) {
		return ReconciliationTransactionClockSnapshot{}, ErrInvalidInput
	}
	encoded, err := ccse.Marshal(512, func(out *ccse.Encoder) {
		out.String(transactionID)
		out.Int64(observedAt)
		out.FixedBytes(pendingDigest[:], 32)
		out.Int64(originalDeadline)
	})
	if err != nil {
		return ReconciliationTransactionClockSnapshot{}, err
	}
	return ReconciliationTransactionClockSnapshot{TransactionID: transactionID,
		ObservedAtUnixNano: observedAt, PendingDigest: pendingDigest,
		OriginalCommitNotAfterUnixNano: originalDeadline,
		SnapshotDigest:                 domainDigest(pendingReconciliationClockDomain, encoded)}, nil
}

func verifyReconciliationClock(snapshot ReconciliationTransactionClockSnapshot) error {
	rebuilt, err := NewReconciliationTransactionClockSnapshot(snapshot.TransactionID,
		snapshot.ObservedAtUnixNano, snapshot.PendingDigest, snapshot.OriginalCommitNotAfterUnixNano)
	if err != nil || rebuilt != snapshot {
		return ErrPendingPlanInvalid
	}
	return nil
}

// PendingReconciliationEvidence is an owned, bounded failure/clock preimage.
// Its private fields prevent a digest-only caller assertion.  The canonical
// bytes bind the original admitted deadline as well as the observation time,
// so an EXPIRED decision cannot be moved to another pending window.
type PendingReconciliationEvidence struct {
	kind                           pendingReconciliationEvidenceKind
	disposition                    PendingDisposition
	auditOccurredAtUnixNano        int64
	originalCommitNotAfterUnixNano int64
	contentType                    string
	payload                        []byte
	failureRecord                  ccse.Record
	failureRecordDigest            [32]byte
	finalClock                     ReconciliationFinalClockRequirement
	canonical                      []byte
	digest                         [32]byte
}

func newPendingReconciliationEvidence(kind pendingReconciliationEvidenceKind,
	disposition PendingDisposition, pendingDigest [32]byte, originalDeadline,
	auditOccurredAtUnixNano int64, failureRecord ccse.Record) (PendingReconciliationEvidence, error) {
	finalClock, err := newReconciliationFinalClockRequirement(pendingDigest,
		originalDeadline, auditOccurredAtUnixNano)
	if err != nil ||
		(kind == pendingReconciliationExpiredClockEvidence) != (disposition == PendingDispositionExpired) ||
		(kind == pendingReconciliationSignedFailureEvidence) != (disposition == PendingDispositionFailed) {
		return PendingReconciliationEvidence{}, ErrInvalidInput
	}
	contentType := pendingReconciliationExpiredEvidenceContentType
	failureBytes := []byte(nil)
	failureDigest := [32]byte{}
	if kind == pendingReconciliationSignedFailureEvidence {
		contentType = pendingReconciliationFailedEvidenceContentType
		var err error
		failureDigest, err = failureRecord.Digest(ccse.DefaultLimits())
		if err != nil || failureDigest == ([32]byte{}) ||
			failureRecord.MessageTypeID != schema.MessageTypeEvidenceRecord ||
			failureRecord.SchemaVersion != (ccse.Version{Major: 1}) {
			return PendingReconciliationEvidence{}, ErrInvalidInput
		}
		failureBytes, err = canonicalSignedAuthorizationEvidence(failureRecord)
		if err != nil {
			return PendingReconciliationEvidence{}, err
		}
	} else if failureRecord.MessageTypeID != 0 || len(failureRecord.Payload) != 0 || len(failureRecord.Signature) != 0 {
		return PendingReconciliationEvidence{}, ErrInvalidInput
	}
	canonical, err := ccse.Marshal(1<<20, func(out *ccse.Encoder) {
		out.Uint32(1)
		out.Uint32(uint32(kind))
		out.Uint32(uint32(disposition))
		out.Int64(auditOccurredAtUnixNano)
		out.FixedBytes(pendingDigest[:], 32)
		out.Int64(originalDeadline)
		out.FixedBytes(finalClock.digest[:], 32)
		out.String(contentType)
		out.FixedBytes(failureDigest[:], 32)
		out.Bytes(failureBytes)
	})
	if err != nil {
		return PendingReconciliationEvidence{}, err
	}
	return PendingReconciliationEvidence{kind: kind, disposition: disposition,
		auditOccurredAtUnixNano:        auditOccurredAtUnixNano,
		originalCommitNotAfterUnixNano: originalDeadline,
		contentType:                    contentType, payload: append([]byte(nil), canonical...),
		failureRecord: cloneCCSERecord(failureRecord), failureRecordDigest: failureDigest,
		finalClock: finalClock,
		canonical:  canonical, digest: domainDigest(pendingReconciliationEvidenceDomain, canonical)}, nil
}

func (evidence PendingReconciliationEvidence) Disposition() PendingDisposition {
	return evidence.disposition
}

// AuditOccurredAtUnixNano is the already-signed outer AuditEvent time. It is
// The later database observation is not retained here; it is validated by
// ReconciliationFinalClockRequirement.ValidateObservation.
func (evidence PendingReconciliationEvidence) AuditOccurredAtUnixNano() int64 {
	return evidence.auditOccurredAtUnixNano
}
func (evidence PendingReconciliationEvidence) ObservedAtUnixNano() int64 {
	return evidence.auditOccurredAtUnixNano
}
func (evidence PendingReconciliationEvidence) OriginalCommitNotAfterUnixNano() int64 {
	return evidence.originalCommitNotAfterUnixNano
}
func (evidence PendingReconciliationEvidence) FailureCode() string {
	if evidence.disposition == PendingDispositionExpired {
		return "commit-deadline-expired"
	}
	return "signed-operational-failure"
}
func (evidence PendingReconciliationEvidence) ContentType() string { return evidence.contentType }
func (evidence PendingReconciliationEvidence) Payload() []byte {
	return append([]byte(nil), evidence.payload...)
}
func (evidence PendingReconciliationEvidence) CanonicalBytes() []byte {
	return append([]byte(nil), evidence.canonical...)
}
func (evidence PendingReconciliationEvidence) Digest() [32]byte { return evidence.digest }

// TransactionClockSnapshot is retained only for source compatibility and no
// longer exposes a pre-final transaction identity. Use FinalClockRequirement.
func (evidence PendingReconciliationEvidence) TransactionClockSnapshot() ReconciliationTransactionClockSnapshot {
	return ReconciliationTransactionClockSnapshot{}
}
func (evidence PendingReconciliationEvidence) FinalClockRequirement() ReconciliationFinalClockRequirement {
	return evidence.finalClock
}
func (evidence PendingReconciliationEvidence) SignedFailureRecord() (ccse.Record, [32]byte, bool) {
	if evidence.kind != pendingReconciliationSignedFailureEvidence {
		return ccse.Record{}, [32]byte{}, false
	}
	return cloneCCSERecord(evidence.failureRecord), evidence.failureRecordDigest, true
}

func (evidence PendingReconciliationEvidence) Verify() error {
	rebuilt, err := newPendingReconciliationEvidence(evidence.kind, evidence.disposition,
		evidence.finalClock.PendingDigest(), evidence.originalCommitNotAfterUnixNano,
		evidence.auditOccurredAtUnixNano, evidence.failureRecord)
	if err != nil || rebuilt.digest != evidence.digest ||
		!bytes.Equal(rebuilt.canonical, evidence.canonical) ||
		!bytes.Equal(rebuilt.payload, evidence.payload) {
		return fmt.Errorf("%w: reconciliation evidence", ErrPendingPlanInvalid)
	}
	return nil
}

func clonePendingReconciliationEvidence(evidence PendingReconciliationEvidence) PendingReconciliationEvidence {
	evidence.payload = append([]byte(nil), evidence.payload...)
	evidence.canonical = append([]byte(nil), evidence.canonical...)
	evidence.failureRecord = cloneCCSERecord(evidence.failureRecord)
	return evidence
}

// PreparePendingReconciliationEvidence retains the legacy transaction-neutral
// default where the signed occurrence is the original deadline. New
// outer-signing flows use PreparePendingReconciliationEvidenceAt with the
// already-reserved AuditEvent occurrence time.
func (p *Planner) PreparePendingReconciliationEvidence(ctx context.Context,
	decoded DecodedDurablePendingEnvelope, disposition PendingDisposition,
	failure ccse.AuthenticatedEvidenceRecord) (PendingReconciliationEvidence, error) {
	envelope, err := decodeDurablePendingEnvelope(decoded.encoded)
	if err != nil || envelope.Digest() != decoded.digest {
		return PendingReconciliationEvidence{}, ErrPendingPlanInvalid
	}
	_, deadline, ok := durableEnvelopeWindow(envelope)
	if !ok {
		return PendingReconciliationEvidence{}, ErrPendingPlanInvalid
	}
	return p.preparePendingReconciliationEvidence(ctx, decoded, disposition, failure, deadline)
}

// PreparePendingReconciliationEvidenceAt binds an already-signed outer audit
// occurrence time to a transaction-neutral final-clock requirement. The
// final UoW must later prove a database observation at or after this time.
func (p *Planner) PreparePendingReconciliationEvidenceAt(ctx context.Context,
	decoded DecodedDurablePendingEnvelope, disposition PendingDisposition,
	failure ccse.AuthenticatedEvidenceRecord, auditOccurredAtUnixNano int64) (
	PendingReconciliationEvidence, error) {
	return p.preparePendingReconciliationEvidence(ctx, decoded, disposition, failure,
		auditOccurredAtUnixNano)
}

func (p *Planner) preparePendingReconciliationEvidence(ctx context.Context,
	decoded DecodedDurablePendingEnvelope, disposition PendingDisposition,
	failure ccse.AuthenticatedEvidenceRecord, auditOccurredAt int64) (
	PendingReconciliationEvidence, error) {
	if err := p.ready(); err != nil {
		return PendingReconciliationEvidence{}, err
	}
	if err := ctx.Err(); err != nil {
		return PendingReconciliationEvidence{}, err
	}
	envelope, err := decodeDurablePendingEnvelope(decoded.encoded)
	if err != nil || envelope.Digest() != decoded.digest || envelope.Kind() != decoded.kind ||
		envelope.Kind() == DurablePendingReconciliation || envelope.Kind() == DurablePendingOwnershipTransferAcceptance {
		return PendingReconciliationEvidence{}, ErrPendingPlanInvalid
	}
	_, deadline, ok := durableEnvelopeWindow(envelope)
	if !ok || auditOccurredAt < deadline {
		return PendingReconciliationEvidence{}, ErrInvalidCommitWindow
	}
	switch disposition {
	case PendingDispositionExpired:
		return newPendingReconciliationEvidence(pendingReconciliationExpiredClockEvidence,
			disposition, envelope.PendingDigest(), deadline, auditOccurredAt, ccse.Record{})
	case PendingDispositionFailed:
		if failure.MessageTypeID() != schema.MessageTypeEvidenceRecord ||
			failure.SchemaVersion() != (ccse.Version{Major: 1}) ||
			failure.ValidateLimits(transferVerifiedRecordLimits(262144)) != nil {
			return PendingReconciliationEvidence{}, ErrAuthorizationMismatch
		}
		record := failure.Record()
		if err := p.validateReconciliationFailureRecord(ctx, record, envelope.PendingDigest(),
			auditOccurredAt); err != nil {
			return PendingReconciliationEvidence{}, err
		}
		return newPendingReconciliationEvidence(pendingReconciliationSignedFailureEvidence,
			disposition, envelope.PendingDigest(), deadline, auditOccurredAt, record)
	default:
		return PendingReconciliationEvidence{}, ErrInvalidInput
	}
}

func (p *Planner) validateReconciliationFailureRecord(ctx context.Context, record ccse.Record,
	pendingDigest [32]byte, auditOccurredAtUnixNano int64) error {
	authorization, err := authorizationFromSignedRecord(record)
	if err != nil || authorization.messageTypeID != schema.MessageTypeEvidenceRecord ||
		authorization.schemaVersion != (ccse.Version{Major: 1}) {
		return ErrAuthorizationMismatch
	}
	validator, err := foundationCanonicalValidator()
	if err != nil {
		return err
	}
	decoded, err := validator.Decode(schema.MessageTypeEvidenceRecord,
		ccse.Version{Major: 1}, authorization.payload)
	projection, ok := decoded.(foundationv1.EvidenceRecordSigningProjection)
	if err != nil || !ok || projection.Component != "iam.pending.reconciliation" ||
		projection.Status != uint32(foundationv1.EvidenceStatus_EVIDENCE_STATUS_FAILED) ||
		projection.TestEndedAtUnixNano > auditOccurredAtUnixNano ||
		!containsDigest(projection.EvidenceArtifactDigestsSHA256, pendingDigest) {
		return ErrAuthorizationMismatch
	}
	receiver, err := p.profile.ReceiverProfile(ctx, schema.MessageTypeEvidenceRecord)
	if err != nil || validateReceiverProfile(receiver) != nil ||
		validateRetainedAuthorizationDomain(authorization, receiver,
			EntityRef{Kind: EntityIdentity, PrincipalKind: 8, ID: projection.EvidenceID},
			schema.MessageTypeEvidenceRecord, projection.Metadata.StateVersion,
			projection.Metadata.CreatedAtUnixNano, auditOccurredAtUnixNano) != nil {
		return ErrAuthorizationMismatch
	}
	if _, err := p.resolveHistoricalEvidenceAuthorization(ctx, authorization, receiver); err != nil {
		return ErrAuthorizationMismatch
	}
	return nil
}

func containsDigest(values [][32]byte, target [32]byte) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func newPendingReconciliationResult(pendingDigest [32]byte,
	evidence PendingReconciliationEvidence) (replayresult.Result, error) {
	if pendingDigest == ([32]byte{}) || evidence.Verify() != nil {
		return replayresult.Result{}, ErrPendingPlanInvalid
	}
	canonicalEvidence := evidence.CanonicalBytes()
	payload, err := ccse.Marshal(MaxPendingReconciliationResultPayloadBytes, func(out *ccse.Encoder) {
		out.Uint32(1)
		out.FixedBytes(pendingDigest[:], 32)
		evidenceDigest := evidence.Digest()
		out.FixedBytes(evidenceDigest[:], 32)
		out.Bytes(canonicalEvidence)
	})
	if err != nil {
		return replayresult.Result{}, err
	}
	result, err := replayresult.New(PendingReconciliationResultContentType, payload)
	if err != nil || result.Verify() != nil {
		return replayresult.Result{}, ErrPendingPlanInvalid
	}
	return result, nil
}

// PendingReconciliationResultSnapshot is an inert, alias-safe interpretation
// of a durable FAILED/TIMED_OUT replay result. It deliberately grants no IAM
// write capability; duplicate and restore paths use it only to revalidate the
// closed content type and exact terminal evidence tuple.
type PendingReconciliationResultSnapshot struct {
	result                  replayresult.Result
	pendingDigest           [32]byte
	evidenceDigest          [32]byte
	disposition             PendingDisposition
	auditOccurredAtUnixNano int64
	finalClock              ReconciliationFinalClockRequirement
	failureRecordDigest     [32]byte
	canonicalEvidence       []byte
}

func (snapshot PendingReconciliationResultSnapshot) Digest() [32]byte {
	return snapshot.result.Digest()
}
func (snapshot PendingReconciliationResultSnapshot) PendingDigest() [32]byte {
	return snapshot.pendingDigest
}
func (snapshot PendingReconciliationResultSnapshot) EvidenceDigest() [32]byte {
	return snapshot.evidenceDigest
}
func (snapshot PendingReconciliationResultSnapshot) Disposition() PendingDisposition {
	return snapshot.disposition
}
func (snapshot PendingReconciliationResultSnapshot) AuditOccurredAtUnixNano() int64 {
	return snapshot.auditOccurredAtUnixNano
}
func (snapshot PendingReconciliationResultSnapshot) FinalClockRequirement() ReconciliationFinalClockRequirement {
	return snapshot.finalClock
}
func (snapshot PendingReconciliationResultSnapshot) FailureRecordDigest() ([32]byte, bool) {
	return snapshot.failureRecordDigest,
		snapshot.disposition == PendingDispositionFailed && snapshot.failureRecordDigest != ([32]byte{})
}
func (snapshot PendingReconciliationResultSnapshot) CanonicalEvidenceBytes() []byte {
	return append([]byte(nil), snapshot.canonicalEvidence...)
}
func (snapshot PendingReconciliationResultSnapshot) Verify() error {
	rebuilt, err := DecodePendingReconciliationResult(snapshot.result)
	if err != nil || rebuilt.pendingDigest != snapshot.pendingDigest ||
		rebuilt.evidenceDigest != snapshot.evidenceDigest || rebuilt.disposition != snapshot.disposition ||
		rebuilt.auditOccurredAtUnixNano != snapshot.auditOccurredAtUnixNano || rebuilt.finalClock != snapshot.finalClock ||
		rebuilt.failureRecordDigest != snapshot.failureRecordDigest ||
		!bytes.Equal(rebuilt.canonicalEvidence, snapshot.canonicalEvidence) {
		return ErrPendingPlanInvalid
	}
	return nil
}

// DecodePendingReconciliationResult strictly decodes the IAM-owned failure
// replay result. It rejects wrong media types, noncanonical/trailing payloads,
// invalid final-clock requirements, and failure evidence whose retained signed preimage
// does not match its record digest.
func DecodePendingReconciliationResult(result replayresult.Result) (
	PendingReconciliationResultSnapshot, error) {
	if result.Verify() != nil || result.ContentType() != PendingReconciliationResultContentType ||
		len(result.Payload()) > MaxPendingReconciliationResultPayloadBytes {
		return PendingReconciliationResultSnapshot{}, ErrPendingPlanInvalid
	}
	payload := result.Payload()
	var (
		version           uint32
		pendingDigest     [32]byte
		evidenceDigest    [32]byte
		canonicalEvidence []byte
	)
	err := ccse.Unmarshal(payload, MaxPendingReconciliationResultPayloadBytes, func(in *ccse.Decoder) error {
		var decodeErr error
		if version, decodeErr = in.Uint32(); decodeErr != nil {
			return decodeErr
		}
		pendingBytes, decodeErr := in.FixedBytes(sha256.Size)
		if decodeErr != nil {
			return decodeErr
		}
		copy(pendingDigest[:], pendingBytes)
		evidenceBytes, decodeErr := in.FixedBytes(sha256.Size)
		if decodeErr != nil {
			return decodeErr
		}
		copy(evidenceDigest[:], evidenceBytes)
		canonicalEvidence, decodeErr = in.Bytes(1 << 20)
		return decodeErr
	})
	if err != nil || version != 1 || pendingDigest == ([32]byte{}) ||
		evidenceDigest == ([32]byte{}) || len(canonicalEvidence) == 0 ||
		domainDigest(pendingReconciliationEvidenceDomain, canonicalEvidence) != evidenceDigest {
		return PendingReconciliationResultSnapshot{}, ErrPendingPlanInvalid
	}

	var (
		evidenceVersion  uint32
		kind             uint32
		dispositionRaw   uint32
		auditOccurredAt  int64
		evidencePending  [32]byte
		deadline         int64
		finalClockDigest [32]byte
		contentType      string
		failureDigest    [32]byte
		failureBytes     []byte
	)
	err = ccse.Unmarshal(canonicalEvidence, 1<<20, func(in *ccse.Decoder) error {
		var decodeErr error
		if evidenceVersion, decodeErr = in.Uint32(); decodeErr != nil {
			return decodeErr
		}
		if kind, decodeErr = in.Uint32(); decodeErr != nil {
			return decodeErr
		}
		if dispositionRaw, decodeErr = in.Uint32(); decodeErr != nil {
			return decodeErr
		}
		if auditOccurredAt, decodeErr = in.Int64(); decodeErr != nil {
			return decodeErr
		}
		value, decodeErr := in.FixedBytes(sha256.Size)
		if decodeErr != nil {
			return decodeErr
		}
		copy(evidencePending[:], value)
		if deadline, decodeErr = in.Int64(); decodeErr != nil {
			return decodeErr
		}
		value, decodeErr = in.FixedBytes(sha256.Size)
		if decodeErr != nil {
			return decodeErr
		}
		copy(finalClockDigest[:], value)
		if contentType, decodeErr = in.String(255); decodeErr != nil {
			return decodeErr
		}
		value, decodeErr = in.FixedBytes(sha256.Size)
		if decodeErr != nil {
			return decodeErr
		}
		copy(failureDigest[:], value)
		failureBytes, decodeErr = in.Bytes(1 << 20)
		return decodeErr
	})
	finalClock, clockErr := newReconciliationFinalClockRequirement(evidencePending, deadline,
		auditOccurredAt)
	disposition := PendingDisposition(dispositionRaw)
	if err != nil || evidenceVersion != 1 || evidencePending != pendingDigest ||
		clockErr != nil || finalClock.Digest() != finalClockDigest {
		return PendingReconciliationResultSnapshot{}, ErrPendingPlanInvalid
	}
	switch disposition {
	case PendingDispositionExpired:
		if pendingReconciliationEvidenceKind(kind) != pendingReconciliationExpiredClockEvidence ||
			contentType != pendingReconciliationExpiredEvidenceContentType ||
			failureDigest != ([32]byte{}) || len(failureBytes) != 0 {
			return PendingReconciliationResultSnapshot{}, ErrPendingPlanInvalid
		}
	case PendingDispositionFailed:
		if pendingReconciliationEvidenceKind(kind) != pendingReconciliationSignedFailureEvidence ||
			contentType != pendingReconciliationFailedEvidenceContentType ||
			failureDigest == ([32]byte{}) || !validCanonicalFailurePreimage(failureBytes, failureDigest) {
			return PendingReconciliationResultSnapshot{}, ErrPendingPlanInvalid
		}
	default:
		return PendingReconciliationResultSnapshot{}, ErrPendingPlanInvalid
	}
	reencoded, marshalErr := ccse.Marshal(MaxPendingReconciliationResultPayloadBytes, func(out *ccse.Encoder) {
		out.Uint32(version)
		out.FixedBytes(pendingDigest[:], sha256.Size)
		out.FixedBytes(evidenceDigest[:], sha256.Size)
		out.Bytes(canonicalEvidence)
	})
	if marshalErr != nil || !bytes.Equal(reencoded, payload) {
		return PendingReconciliationResultSnapshot{}, ErrPendingPlanInvalid
	}
	owned, resultErr := replayresult.New(result.ContentType(), payload)
	if resultErr != nil || owned.Digest() != result.Digest() {
		return PendingReconciliationResultSnapshot{}, ErrPendingPlanInvalid
	}
	return PendingReconciliationResultSnapshot{result: owned, pendingDigest: pendingDigest,
		evidenceDigest: evidenceDigest, disposition: disposition,
		auditOccurredAtUnixNano: auditOccurredAt, finalClock: finalClock,
		failureRecordDigest: failureDigest,
		canonicalEvidence:   append([]byte(nil), canonicalEvidence...)}, nil
}

func validCanonicalFailurePreimage(encoded []byte, expectedDigest [32]byte) bool {
	var preimage, signature []byte
	err := ccse.Unmarshal(encoded, 2<<20, func(in *ccse.Decoder) error {
		var decodeErr error
		if preimage, decodeErr = in.Bytes(2 << 20); decodeErr != nil {
			return decodeErr
		}
		signature, decodeErr = in.Bytes(ed25519.SignatureSize)
		return decodeErr
	})
	return err == nil && len(preimage) != 0 && len(signature) == ed25519.SignatureSize &&
		sha256.Sum256(preimage) == expectedDigest
}
