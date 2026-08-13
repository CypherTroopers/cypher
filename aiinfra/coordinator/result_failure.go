// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package coordinator

import (
	"bytes"
	"crypto/sha256"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/governance"
	"github.com/cypherium/cypher/aiinfra/iam"
	"github.com/cypherium/cypher/aiinfra/replayresult"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

const (
	// AuditedFailureResultContentType is the only durable result stored for a
	// joined FAILED/TIMED_OUT operation. The IAM result is retained as an inner
	// semantic preimage; the outer digest additionally binds the final UoW
	// clock, signed AuditEvent and Governance fragment.
	AuditedFailureResultContentType = "application/vnd.cph.aiinfra.joined-audit-failure.v1+ccse"

	auditedFailureResultVersion = uint32(1)
	// Keep the nested IAM result boundary byte-exact with the semantic codec.
	// A smaller composition-layer cap would admit and sign a valid IAM failure
	// only to strand it at finalization.
	auditedFailureInnerMaxBytes = iam.MaxPendingReconciliationResultPayloadBytes
)

type auditedFailureProjection struct {
	requestDigest          [sha256.Size]byte
	pendingDigest          [sha256.Size]byte
	envelopeDigest         [sha256.Size]byte
	stateDigest            [sha256.Size]byte
	executionDigest        [sha256.Size]byte
	governanceDigest       [sha256.Size]byte
	auditEventID           string
	auditRecordDigest      [sha256.Size]byte
	auditPayloadDigest     [sha256.Size]byte
	auditSequence          uint64
	auditOutcome           uint32
	evaluatedAtUnixNano    int64
	commitNotBefore        int64
	commitNotAfter         int64
	evidenceBundleDigest   [sha256.Size]byte
	innerContentType       string
	innerPayload           []byte
	innerDigest            [sha256.Size]byte
	clockPendingDigest     [sha256.Size]byte
	clockDeadline          int64
	clockAuditOccurredAt   int64
	clockRequirementDigest [sha256.Size]byte
	transactionID          string
	transactionObservedAt  int64
}

// AuditedFailureSnapshot is an inert duplicate/restore projection. It does
// not recreate any IAM, Governance, pending or transaction capability.
type AuditedFailureSnapshot struct {
	projection   auditedFailureProjection
	resultDigest [sha256.Size]byte
}

func (value AuditedFailureSnapshot) RequestDigest() [sha256.Size]byte {
	return value.projection.requestDigest
}
func (value AuditedFailureSnapshot) PendingDigest() [sha256.Size]byte {
	return value.projection.pendingDigest
}
func (value AuditedFailureSnapshot) DurableEnvelopeDigest() [sha256.Size]byte {
	return value.projection.envelopeDigest
}
func (value AuditedFailureSnapshot) StateAndGlobalCASDigest() [sha256.Size]byte {
	return value.projection.stateDigest
}
func (value AuditedFailureSnapshot) ExecutionFragmentDigest() [sha256.Size]byte {
	return value.projection.executionDigest
}
func (value AuditedFailureSnapshot) GovernanceFragmentDigest() [sha256.Size]byte {
	return value.projection.governanceDigest
}
func (value AuditedFailureSnapshot) AuditEventID() string { return value.projection.auditEventID }
func (value AuditedFailureSnapshot) AuditRecordDigest() [sha256.Size]byte {
	return value.projection.auditRecordDigest
}
func (value AuditedFailureSnapshot) AuditPayloadDigest() [sha256.Size]byte {
	return value.projection.auditPayloadDigest
}
func (value AuditedFailureSnapshot) AuditSequence() uint64 { return value.projection.auditSequence }
func (value AuditedFailureSnapshot) AuditOutcome() uint32  { return value.projection.auditOutcome }
func (value AuditedFailureSnapshot) EvaluatedAtUnixNano() int64 {
	return value.projection.evaluatedAtUnixNano
}
func (value AuditedFailureSnapshot) CommitNotBeforeUnixNano() int64 {
	return value.projection.commitNotBefore
}
func (value AuditedFailureSnapshot) CommitNotAfterUnixNano() int64 {
	return value.projection.commitNotAfter
}
func (value AuditedFailureSnapshot) EvidenceBundleDigest() [sha256.Size]byte {
	return value.projection.evidenceBundleDigest
}
func (value AuditedFailureSnapshot) InnerFailureResult() (replayresult.Result, error) {
	return replayresult.New(value.projection.innerContentType, value.projection.innerPayload)
}
func (value AuditedFailureSnapshot) InnerFailureDigest() [sha256.Size]byte {
	return value.projection.innerDigest
}
func (value AuditedFailureSnapshot) ClockRequirementDigest() [sha256.Size]byte {
	return value.projection.clockRequirementDigest
}
func (value AuditedFailureSnapshot) OriginalCommitNotAfterUnixNano() int64 {
	return value.projection.clockDeadline
}
func (value AuditedFailureSnapshot) AuditOccurredAtUnixNano() int64 {
	return value.projection.clockAuditOccurredAt
}
func (value AuditedFailureSnapshot) TransactionID() string { return value.projection.transactionID }
func (value AuditedFailureSnapshot) TransactionObservedAtUnixNano() int64 {
	return value.projection.transactionObservedAt
}
func (value AuditedFailureSnapshot) ResultDigest() [sha256.Size]byte { return value.resultDigest }

// DecodeAuditedFailureResult validates the coordinator-owned wrapper and the
// complete nested IAM failure result before exposing an inert projection.
func DecodeAuditedFailureResult(result replayresult.Result) (AuditedFailureSnapshot, error) {
	var zero AuditedFailureSnapshot
	if result.Verify() != nil || result.ContentType() != AuditedFailureResultContentType {
		return zero, ErrInvalidCompoundResult
	}
	payload := result.Payload()
	projection, err := decodeAuditedFailureProjection(payload)
	if err != nil {
		return zero, err
	}
	rebuilt, err := encodeAuditedFailureProjection(projection)
	if err != nil || !bytes.Equal(rebuilt, payload) {
		return zero, ErrInvalidCompoundResult
	}
	return AuditedFailureSnapshot{projection: cloneAuditedFailureProjection(projection),
		resultDigest: result.Digest()}, nil
}

func auditedFailurePayload(request iam.JoinedAuditRequest, execution iam.IAMExecutionFragment,
	fragment governance.JoinedAuditFragment, view governance.JoinedAuditFragmentSnapshot,
	record ccse.Record, event foundationv1.AuditEventSigningProjection, inner replayresult.Result,
	transactionID string, transactionAt int64) ([]byte, error) {
	bundle, ok := request.AuditEvidenceBundle()
	requestClock, requestClockOK := request.ReconciliationFinalClockRequirement()
	executionClock, executionClockOK := execution.ReconciliationFinalClockRequirement()
	if !ok || bundle.VerifyFor(request) != nil ||
		bundle.Digest() != view.IAMAuditEvidenceBundleDigestSHA256 ||
		!requestClockOK || !executionClockOK || requestClock.Digest() != executionClock.Digest() ||
		inner.Verify() != nil {
		return nil, ErrInvalidCompoundResult
	}
	recordDigest, err := record.Digest(ccse.DefaultLimits())
	if err != nil {
		return nil, ErrInvalidCompoundResult
	}
	return encodeAuditedFailureProjection(auditedFailureProjection{
		requestDigest: request.Digest(), pendingDigest: request.PendingDigest(),
		envelopeDigest: request.DurableEnvelopeDigest(), stateDigest: request.StateAndGlobalCASCommitment(),
		executionDigest: execution.Digest(), governanceDigest: fragment.Digest(),
		auditEventID: event.AuditEventID, auditRecordDigest: recordDigest,
		auditPayloadDigest: record.Envelope.PayloadDigest, auditSequence: event.AuditSequence,
		auditOutcome: event.Outcome, evaluatedAtUnixNano: view.EvaluatedAtUnixNano,
		commitNotBefore: view.CommitNotBeforeUnixNano, commitNotAfter: view.CommitNotAfterUnixNano,
		evidenceBundleDigest: bundle.Digest(), innerContentType: inner.ContentType(),
		innerPayload: inner.Payload(), innerDigest: inner.Digest(),
		clockPendingDigest:     requestClock.PendingDigest(),
		clockDeadline:          requestClock.OriginalCommitNotAfterUnixNano(),
		clockAuditOccurredAt:   requestClock.AuditOccurredAtUnixNano(),
		clockRequirementDigest: requestClock.Digest(), transactionID: transactionID,
		transactionObservedAt: transactionAt,
	})
}

func encodeAuditedFailureProjection(value auditedFailureProjection) ([]byte, error) {
	if value.requestDigest == ([sha256.Size]byte{}) || value.pendingDigest == ([sha256.Size]byte{}) ||
		value.envelopeDigest == ([sha256.Size]byte{}) || value.stateDigest == ([sha256.Size]byte{}) ||
		value.executionDigest == ([sha256.Size]byte{}) || value.governanceDigest == ([sha256.Size]byte{}) ||
		value.auditEventID == "" || value.auditRecordDigest == ([sha256.Size]byte{}) ||
		value.auditPayloadDigest == ([sha256.Size]byte{}) || value.auditSequence == 0 ||
		(value.auditOutcome != 3 && value.auditOutcome != 4) || value.evaluatedAtUnixNano < 0 ||
		value.commitNotBefore < 0 || value.commitNotBefore > value.evaluatedAtUnixNano ||
		value.commitNotAfter <= value.evaluatedAtUnixNano || value.evidenceBundleDigest == ([sha256.Size]byte{}) ||
		value.innerContentType != iam.PendingReconciliationResultContentType || len(value.innerPayload) == 0 ||
		len(value.innerPayload) > auditedFailureInnerMaxBytes ||
		value.innerDigest == ([sha256.Size]byte{}) || value.clockPendingDigest == ([sha256.Size]byte{}) ||
		value.clockPendingDigest != value.pendingDigest ||
		value.clockDeadline <= 0 || value.clockAuditOccurredAt < value.clockDeadline ||
		value.clockAuditOccurredAt != value.evaluatedAtUnixNano ||
		value.clockRequirementDigest == ([sha256.Size]byte{}) || !validTransactionID(value.transactionID) ||
		value.transactionObservedAt < value.clockAuditOccurredAt ||
		value.transactionObservedAt < value.commitNotBefore || value.transactionObservedAt >= value.commitNotAfter {
		return nil, ErrInvalidCompoundResult
	}
	inner, err := replayresult.New(value.innerContentType, value.innerPayload)
	if err != nil || inner.Verify() != nil || inner.Digest() != value.innerDigest {
		return nil, ErrInvalidCompoundResult
	}
	snapshot, err := iam.DecodePendingReconciliationResult(inner)
	if err != nil || snapshot.Verify() != nil || snapshot.PendingDigest() != value.clockPendingDigest ||
		snapshot.AuditOccurredAtUnixNano() != value.clockAuditOccurredAt {
		return nil, ErrInvalidCompoundResult
	}
	requirement := snapshot.FinalClockRequirement()
	if requirement.Verify() != nil || requirement.Digest() != value.clockRequirementDigest ||
		requirement.PendingDigest() != value.clockPendingDigest ||
		requirement.OriginalCommitNotAfterUnixNano() != value.clockDeadline ||
		requirement.AuditOccurredAtUnixNano() != value.clockAuditOccurredAt ||
		(value.auditOutcome == 4) != (snapshot.Disposition() == iam.PendingDispositionExpired) ||
		(value.auditOutcome == 3) != (snapshot.Disposition() == iam.PendingDispositionFailed) {
		return nil, ErrInvalidCompoundResult
	}
	return ccse.Marshal(replayresult.MaxPayloadBytes, func(out *ccse.Encoder) {
		out.Uint32(auditedFailureResultVersion)
		out.FixedBytes(value.requestDigest[:], sha256.Size)
		out.FixedBytes(value.pendingDigest[:], sha256.Size)
		out.FixedBytes(value.envelopeDigest[:], sha256.Size)
		out.FixedBytes(value.stateDigest[:], sha256.Size)
		out.FixedBytes(value.executionDigest[:], sha256.Size)
		out.FixedBytes(value.governanceDigest[:], sha256.Size)
		out.String(value.auditEventID)
		out.FixedBytes(value.auditRecordDigest[:], sha256.Size)
		out.FixedBytes(value.auditPayloadDigest[:], sha256.Size)
		out.Uint64(value.auditSequence)
		out.Uint32(value.auditOutcome)
		out.Int64(value.evaluatedAtUnixNano)
		out.Int64(value.commitNotBefore)
		out.Int64(value.commitNotAfter)
		out.FixedBytes(value.evidenceBundleDigest[:], sha256.Size)
		out.String(value.innerContentType)
		out.Bytes(value.innerPayload)
		out.FixedBytes(value.innerDigest[:], sha256.Size)
		out.FixedBytes(value.clockPendingDigest[:], sha256.Size)
		out.Int64(value.clockDeadline)
		out.Int64(value.clockAuditOccurredAt)
		out.FixedBytes(value.clockRequirementDigest[:], sha256.Size)
		out.String(value.transactionID)
		out.Int64(value.transactionObservedAt)
	})
}

func decodeAuditedFailureProjection(input []byte) (auditedFailureProjection, error) {
	var value auditedFailureProjection
	err := ccse.Unmarshal(input, replayresult.MaxPayloadBytes, func(in *ccse.Decoder) error {
		version, err := in.Uint32()
		if err != nil || version != auditedFailureResultVersion {
			return ErrInvalidCompoundResult
		}
		for _, target := range []*[sha256.Size]byte{&value.requestDigest, &value.pendingDigest,
			&value.envelopeDigest, &value.stateDigest, &value.executionDigest, &value.governanceDigest} {
			if err := decodeSuccessDigest(in, target); err != nil {
				return err
			}
		}
		value.auditEventID, err = in.String(1024)
		if err != nil {
			return ErrInvalidCompoundResult
		}
		if err := decodeSuccessDigest(in, &value.auditRecordDigest); err != nil {
			return err
		}
		if err := decodeSuccessDigest(in, &value.auditPayloadDigest); err != nil {
			return err
		}
		value.auditSequence, err = in.Uint64()
		if err != nil {
			return ErrInvalidCompoundResult
		}
		value.auditOutcome, err = in.Uint32()
		if err != nil {
			return ErrInvalidCompoundResult
		}
		value.evaluatedAtUnixNano, err = in.Int64()
		if err != nil {
			return ErrInvalidCompoundResult
		}
		value.commitNotBefore, err = in.Int64()
		if err != nil {
			return ErrInvalidCompoundResult
		}
		value.commitNotAfter, err = in.Int64()
		if err != nil {
			return ErrInvalidCompoundResult
		}
		if err := decodeSuccessDigest(in, &value.evidenceBundleDigest); err != nil {
			return err
		}
		value.innerContentType, err = in.String(replayresult.MaxContentTypeBytes)
		if err != nil {
			return ErrInvalidCompoundResult
		}
		value.innerPayload, err = in.Bytes(replayresult.MaxPayloadBytes)
		if err != nil {
			return ErrInvalidCompoundResult
		}
		if err := decodeSuccessDigest(in, &value.innerDigest); err != nil {
			return err
		}
		if err := decodeSuccessDigest(in, &value.clockPendingDigest); err != nil {
			return err
		}
		value.clockDeadline, err = in.Int64()
		if err != nil {
			return ErrInvalidCompoundResult
		}
		value.clockAuditOccurredAt, err = in.Int64()
		if err != nil {
			return ErrInvalidCompoundResult
		}
		if err := decodeSuccessDigest(in, &value.clockRequirementDigest); err != nil {
			return err
		}
		value.transactionID, err = in.String(20)
		if err != nil {
			return ErrInvalidCompoundResult
		}
		value.transactionObservedAt, err = in.Int64()
		return err
	})
	if err != nil {
		return auditedFailureProjection{}, ErrInvalidCompoundResult
	}
	if _, err := encodeAuditedFailureProjection(value); err != nil {
		return auditedFailureProjection{}, ErrInvalidCompoundResult
	}
	return cloneAuditedFailureProjection(value), nil
}

func cloneAuditedFailureProjection(value auditedFailureProjection) auditedFailureProjection {
	value.innerPayload = append([]byte(nil), value.innerPayload...)
	return value
}
