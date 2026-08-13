// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

// Package coordinator joins the non-committable IAM and Governance semantic
// fragments at the one replay-owned serializable transaction boundary.
package coordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"strconv"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/governance"
	"github.com/cypherium/cypher/aiinfra/iam"
	"github.com/cypherium/cypher/aiinfra/replayresult"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
	foundationcanonical "github.com/cypherium/cypher/aiinfra/schema/foundation/v1/canonical"
	"github.com/cypherium/cypher/aiinfra/storage/postgres"
)

const (
	// AuditedSuccessResultContentType is the closed durable result returned by
	// a successful IAM/Governance joined operation.
	AuditedSuccessResultContentType = "application/vnd.cph.aiinfra.joined-audit-success.v1+ccse"

	auditedSuccessResultVersion  uint32 = 1
	auditedSuccessResultMaxBytes        = 16 << 10
)

var ErrInvalidCompoundResult = errors.New("aiinfra coordinator: invalid joined-audit result")

// AuditedResult is an immutable result capability. For successful operations
// its payload commits the exact IAM request/execution/state commitments, the
// Governance fragment, and the outer signed AuditEvent. Reconciliation wraps
// IAM's exact failure preimage in a coordinator-owned result which also binds
// the final database xid/clock; that wrapper digest is the one outcome shared
// by X/Y/member/pending rows and the authoritative UoW.
type AuditedResult struct {
	result             replayresult.Result
	requestDigest      [sha256.Size]byte
	governanceDigest   [sha256.Size]byte
	auditRecordDigest  [sha256.Size]byte
	auditPayloadDigest [sha256.Size]byte
	transactionID      string
	transactionAt      int64
	success            bool
}

// AuditedSuccessSnapshot is the decoded, immutable projection of a durable
// successful joined result. It is intentionally read-only: duplicate replay
// and restore paths can inspect the exact operation commitments without
// reconstructing an IAM or Governance capability from stored bytes.
type AuditedSuccessSnapshot struct {
	projection   auditedSuccessProjection
	resultDigest [sha256.Size]byte
}

func (snapshot AuditedSuccessSnapshot) Kind() iam.DurablePendingKind {
	return snapshot.projection.kind
}
func (snapshot AuditedSuccessSnapshot) RequestDigest() [sha256.Size]byte {
	return snapshot.projection.requestDigest
}
func (snapshot AuditedSuccessSnapshot) PendingDigest() [sha256.Size]byte {
	return snapshot.projection.pendingDigest
}
func (snapshot AuditedSuccessSnapshot) DurableEnvelopeDigest() [sha256.Size]byte {
	return snapshot.projection.envelopeDigest
}
func (snapshot AuditedSuccessSnapshot) StateAndGlobalCASDigest() [sha256.Size]byte {
	return snapshot.projection.stateDigest
}
func (snapshot AuditedSuccessSnapshot) ExecutionFragmentDigest() [sha256.Size]byte {
	return snapshot.projection.executionDigest
}
func (snapshot AuditedSuccessSnapshot) GovernanceFragmentDigest() [sha256.Size]byte {
	return snapshot.projection.governanceDigest
}
func (snapshot AuditedSuccessSnapshot) AuditEventID() string {
	return snapshot.projection.auditEventID
}
func (snapshot AuditedSuccessSnapshot) AuditRecordDigest() [sha256.Size]byte {
	return snapshot.projection.auditRecordDigest
}
func (snapshot AuditedSuccessSnapshot) AuditPayloadDigest() [sha256.Size]byte {
	return snapshot.projection.auditPayloadDigest
}
func (snapshot AuditedSuccessSnapshot) AuditSequence() uint64 {
	return snapshot.projection.auditSequence
}
func (snapshot AuditedSuccessSnapshot) EvaluatedAtUnixNano() int64 {
	return snapshot.projection.evaluatedAtUnixNano
}
func (snapshot AuditedSuccessSnapshot) CommitNotBeforeUnixNano() int64 {
	return snapshot.projection.commitNotBefore
}
func (snapshot AuditedSuccessSnapshot) CommitNotAfterUnixNano() int64 {
	return snapshot.projection.commitNotAfter
}
func (snapshot AuditedSuccessSnapshot) EvidenceBundleDigest() [sha256.Size]byte {
	return snapshot.projection.evidenceBundleDigest
}
func (snapshot AuditedSuccessSnapshot) TransactionID() string {
	return snapshot.projection.transactionID
}
func (snapshot AuditedSuccessSnapshot) TransactionObservedAtUnixNano() int64 {
	return snapshot.projection.transactionObservedAt
}
func (snapshot AuditedSuccessSnapshot) ResultDigest() [sha256.Size]byte {
	return snapshot.resultDigest
}

// DecodeAuditedSuccessResult validates a durable result retrieved after an
// exact replay duplicate or backup/restore. It requires the closed content
// type, canonical field order, complete input consumption, and byte-for-byte
// re-encoding before returning any semantic value.
func DecodeAuditedSuccessResult(result replayresult.Result) (AuditedSuccessSnapshot, error) {
	var zero AuditedSuccessSnapshot
	if result.Verify() != nil || result.ContentType() != AuditedSuccessResultContentType {
		return zero, ErrInvalidCompoundResult
	}
	payload := result.Payload()
	projection, err := decodeAuditedSuccessProjection(payload)
	if err != nil {
		return zero, err
	}
	rebuilt, err := encodeAuditedSuccessProjection(projection)
	if err != nil || !bytes.Equal(rebuilt, payload) {
		return zero, ErrInvalidCompoundResult
	}
	return AuditedSuccessSnapshot{projection: projection, resultDigest: result.Digest()}, nil
}

type auditedSuccessProjection struct {
	kind                  iam.DurablePendingKind
	requestDigest         [sha256.Size]byte
	pendingDigest         [sha256.Size]byte
	envelopeDigest        [sha256.Size]byte
	stateDigest           [sha256.Size]byte
	executionDigest       [sha256.Size]byte
	governanceDigest      [sha256.Size]byte
	auditEventID          string
	auditRecordDigest     [sha256.Size]byte
	auditPayloadDigest    [sha256.Size]byte
	auditSequence         uint64
	auditOutcome          uint32
	evaluatedAtUnixNano   int64
	commitNotBefore       int64
	commitNotAfter        int64
	evidenceBundleDigest  [sha256.Size]byte
	transactionID         string
	transactionObservedAt int64
}

func (result AuditedResult) ContentType() string { return result.result.ContentType() }
func (result AuditedResult) Payload() []byte     { return result.result.Payload() }
func (result AuditedResult) Digest() [sha256.Size]byte {
	return result.result.Digest()
}
func (result AuditedResult) Successful() bool { return result.success }

// Completion returns the byte-exact no-external-effect completion accepted by
// the replay transaction. It is available only for a valid result capability.
func (result AuditedResult) Completion() (postgres.DurableCompletion, error) {
	if result.result.Verify() != nil || result.transactionID == "" {
		return postgres.DurableCompletion{}, ErrInvalidCompoundResult
	}
	return postgres.DurableCompletion{ContentType: result.result.ContentType(),
		Payload: result.result.Payload(), ExternalEffects: postgres.NoExternalEffects}, nil
}

// VerifyFor reconstructs every relation used by the audited-final executor. It prevents
// a retained result capability from being paired with a different request,
// Governance fragment, or re-signature of the same unsigned AuditEvent.
func (result AuditedResult) VerifyFor(request iam.JoinedAuditRequest,
	fragment governance.JoinedAuditFragment, outer ccse.VerifiedRecord) error {
	rebuilt, err := newAuditedResult(request, fragment, outer, result.transactionID, result.transactionAt)
	if err != nil || result.result.Verify() != nil || rebuilt.result.Verify() != nil ||
		result.result.Digest() != rebuilt.result.Digest() ||
		result.result.ContentType() != rebuilt.result.ContentType() ||
		!bytes.Equal(result.result.Payload(), rebuilt.result.Payload()) ||
		result.requestDigest != rebuilt.requestDigest ||
		result.governanceDigest != rebuilt.governanceDigest ||
		result.auditRecordDigest != rebuilt.auditRecordDigest ||
		result.auditPayloadDigest != rebuilt.auditPayloadDigest ||
		result.transactionID != rebuilt.transactionID || result.transactionAt != rebuilt.transactionAt ||
		result.success != rebuilt.success {
		return ErrInvalidCompoundResult
	}
	return nil
}

// buildAuditedResult is the internal result constructor for the joined boundary.
// It proves that outer is the exact immutable record which opened uow, reads
// that UoW's cached database clock and xid8, builds the semantic result, derives
// the evidence assertion count from the Governance capability, and binds the
// typed receipt before returning. The UoW must be in its pre-result planning
// phase; callers cannot choose a different result or evidence count later.
func buildAuditedResult(ctx context.Context, uow *postgres.CanonicalUOW,
	request iam.JoinedAuditRequest, fragment governance.JoinedAuditFragment,
	outer ccse.VerifiedRecord) (AuditedResult, error) {
	if uow == nil {
		return AuditedResult{}, ErrTransactionBoundaryRequired
	}
	execution, ok := request.ExecutionFragment()
	if !ok || requireStorageBoundRequest(request, execution) != nil {
		return AuditedResult{}, ErrInvalidCompoundResult
	}
	if err := uow.AssertOuterVerifiedRecord(ctx, outer); err != nil {
		return AuditedResult{}, err
	}
	clock, err := uow.SnapshotTransactionClock(ctx)
	if err != nil {
		return AuditedResult{}, err
	}
	result, err := newAuditedResult(request, fragment, outer,
		clock.TransactionID(), clock.ObservedAtUnixNano())
	if err != nil {
		return AuditedResult{}, err
	}
	evidenceCount := len(fragment.Snapshot().AuditSourceStorageCapabilities)
	if evidenceCount <= 0 || evidenceCount > int(^uint16(0)) {
		return AuditedResult{}, ErrInvalidCompoundResult
	}
	receipt, err := postgres.NewAuditedFinalUOWReceipt(result.ContentType(), result.Payload(),
		request.JoinedAuditEventID(), uint16(evidenceCount))
	if err != nil || receipt.ResultDigest() != result.Digest() {
		return AuditedResult{}, ErrInvalidCompoundResult
	}
	if err := uow.BindResult(ctx, receipt); err != nil {
		return AuditedResult{}, err
	}
	return result, nil
}

// requireStorageBoundRequest prevents the result phase from enabling writes
// for a semantic request which has not first been rebound to the exact pending
// row and complete canonical-state snapshot read by the transaction adapter.
// Reconciliation deliberately has no business-state mutation bundle: it
// closes the admitted pending/idempotency rows using historical evidence.
func requireStorageBoundRequest(request iam.JoinedAuditRequest,
	execution iam.IAMExecutionFragment) error {
	requestPersistence, requestHasPersistence := request.PendingPersistenceCapability()
	executionPersistence, executionHasPersistence := execution.PendingPersistenceCapability()
	if !requestHasPersistence || !executionHasPersistence ||
		requestPersistence.VerifyDigest() != nil || executionPersistence.VerifyDigest() != nil ||
		requestPersistence.Digest() != executionPersistence.Digest() {
		return ErrInvalidCompoundResult
	}
	requestState, requestHasState := request.CanonicalStateBundle()
	executionState, executionHasState := execution.CanonicalStateBundle()
	if request.Kind() == iam.DurablePendingReconciliation {
		if requestHasState || executionHasState {
			return ErrInvalidCompoundResult
		}
		return nil
	}
	if !requestHasState || !executionHasState || requestState.VerifyDigest() != nil ||
		executionState.VerifyDigest() != nil || requestState.VerifyForExecution(execution) != nil ||
		executionState.VerifyForExecution(execution) != nil || requestState.Digest() != executionState.Digest() ||
		requestState.AuditEventID() != request.JoinedAuditEventID() ||
		executionState.AuditEventID() != request.JoinedAuditEventID() ||
		len(requestState.Assertions())+len(requestState.Absences())+len(requestState.Mutations()) == 0 {
		return ErrInvalidCompoundResult
	}
	return nil
}

func newAuditedResult(request iam.JoinedAuditRequest,
	fragment governance.JoinedAuditFragment, outer ccse.VerifiedRecord,
	transactionID string, transactionAt int64) (AuditedResult, error) {
	var zero AuditedResult
	if request.CommitReady() || fragment.CommitReady() || request.VerifyDigest() != nil ||
		fragment.VerifyDigest() != nil || outer.MessageTypeID() != schema.MessageTypeAuditEvent ||
		outer.SchemaVersion() != (ccse.Version{Major: 1}) {
		return zero, ErrInvalidCompoundResult
	}
	execution, ok := request.ExecutionFragment()
	if !ok || execution.CommitReady() || execution.VerifyDigest() != nil {
		return zero, ErrInvalidCompoundResult
	}
	view := fragment.Snapshot()
	if err := bindSemanticFragments(request, execution, view); err != nil {
		return zero, err
	}
	if !validTransactionID(transactionID) || transactionAt < view.CommitNotBeforeUnixNano ||
		transactionAt >= view.CommitNotAfterUnixNano {
		return zero, ErrInvalidCompoundResult
	}
	record, event, err := bindOuterAuditEvent(outer, view)
	if err != nil {
		return zero, err
	}

	result := AuditedResult{
		requestDigest: request.Digest(), governanceDigest: fragment.Digest(),
		auditRecordDigest: outer.Digest(), auditPayloadDigest: record.Envelope.PayloadDigest,
		transactionID: transactionID, transactionAt: transactionAt,
		success: request.ExpectedOutcome() == 1,
	}
	if failure, failed := request.FailureResult(); failed {
		failureDigest, present := request.FailureOutcomeDigest()
		if !present || result.success || failure.Verify() != nil || failure.Digest() != failureDigest ||
			executionFailureMismatch(execution, failureDigest, failure) ||
			bindReconciliationTransaction(request, execution, transactionID, transactionAt) != nil {
			return zero, ErrInvalidCompoundResult
		}
		payload, payloadErr := auditedFailurePayload(request, execution, fragment, view, record,
			event, failure, transactionID, transactionAt)
		if payloadErr != nil {
			return zero, payloadErr
		}
		result.result, err = replayresult.New(AuditedFailureResultContentType, payload)
		if err != nil || result.result.Verify() != nil {
			return zero, ErrInvalidCompoundResult
		}
		return result, nil
	}
	if !result.success {
		return zero, ErrInvalidCompoundResult
	}
	payload, err := auditedSuccessPayload(request, execution, fragment, view, record, event,
		transactionID, transactionAt)
	if err != nil {
		return zero, err
	}
	result.result, err = replayresult.New(AuditedSuccessResultContentType, payload)
	if err != nil || result.result.Verify() != nil {
		return zero, ErrInvalidCompoundResult
	}
	return result, nil
}

func bindReconciliationTransaction(request iam.JoinedAuditRequest,
	execution iam.IAMExecutionFragment, transactionID string, transactionAt int64) error {
	requestClock, requestOK := request.ReconciliationFinalClockRequirement()
	executionClock, executionOK := execution.ReconciliationFinalClockRequirement()
	if !requestOK || !executionOK || requestClock.Digest() != executionClock.Digest() ||
		requestClock.PendingDigest() != executionClock.PendingDigest() ||
		requestClock.OriginalCommitNotAfterUnixNano() != executionClock.OriginalCommitNotAfterUnixNano() ||
		requestClock.AuditOccurredAtUnixNano() != executionClock.AuditOccurredAtUnixNano() ||
		request.EvaluatedAtUnixNano() != requestClock.AuditOccurredAtUnixNano() {
		return ErrInvalidCompoundResult
	}
	snapshot, err := iam.NewReconciliationTransactionClockSnapshot(transactionID, transactionAt,
		requestClock.PendingDigest(), requestClock.OriginalCommitNotAfterUnixNano())
	if err != nil || requestClock.ValidateObservation(snapshot) != nil ||
		executionClock.ValidateObservation(snapshot) != nil {
		return ErrInvalidCompoundResult
	}
	return nil
}

func executionFailureMismatch(execution iam.IAMExecutionFragment, expected [sha256.Size]byte,
	failure replayresult.Result) bool {
	digest, ok := execution.FailureOutcomeDigest()
	if !ok || digest != expected {
		return true
	}
	actual, ok := execution.FailureResult()
	return !ok || actual.Verify() != nil || actual.Digest() != failure.Digest() ||
		actual.ContentType() != failure.ContentType() || !bytes.Equal(actual.Payload(), failure.Payload())
}

func bindSemanticFragments(request iam.JoinedAuditRequest, execution iam.IAMExecutionFragment,
	view governance.JoinedAuditFragmentSnapshot) error {
	if view.CommitReady || view.IAMRequestDigestSHA256 != request.Digest() ||
		view.IAMPendingDigestSHA256 != request.PendingDigest() ||
		view.IAMDurableEnvelopeDigestSHA256 != request.DurableEnvelopeDigest() ||
		view.IAMStateAndGlobalCASDigestSHA256 != request.StateAndGlobalCASCommitment() ||
		view.IAMExecutionFragmentDigestSHA256 != execution.Digest() ||
		view.ParentBinding != request.ParentBinding() ||
		view.ExpectedParentSnapshot != request.ParentExpectedSnapshot() ||
		view.JoinedBinding != request.JoinedBinding() ||
		view.ExpectedJoinedSnapshot != request.JoinedExpectedSnapshot() ||
		view.JoinedAuditEventID != request.JoinedAuditEventID() ||
		view.ExpectedOutcome != request.ExpectedOutcome() ||
		view.AuditEventIdentifierClaim != request.JoinedAuditEventIdentifierAssertion() ||
		view.EvaluatedAtUnixNano != request.EvaluatedAtUnixNano() ||
		view.CommitNotBeforeUnixNano < request.CommitNotBeforeUnixNano() ||
		view.CommitNotAfterUnixNano > request.CommitNotAfterUnixNano() ||
		view.CommitNotAfterUnixNano <= view.CommitNotBeforeUnixNano {
		return ErrInvalidCompoundResult
	}
	return nil
}

func bindOuterAuditEvent(outer ccse.VerifiedRecord,
	view governance.JoinedAuditFragmentSnapshot) (ccse.Record, foundationv1.AuditEventSigningProjection, error) {
	var emptyRecord ccse.Record
	var emptyEvent foundationv1.AuditEventSigningProjection
	if outer.ValidateLimits(ccse.DefaultLimits()) != nil || outer.Digest() == ([sha256.Size]byte{}) ||
		outer.MessageTypeID() != schema.MessageTypeAuditEvent || outer.SchemaVersion() != (ccse.Version{Major: 1}) {
		return emptyRecord, emptyEvent, ErrInvalidCompoundResult
	}
	record := outer.Record()
	digest, err := record.Digest(ccse.DefaultLimits())
	if err != nil || digest != outer.Digest() || digest != view.NextAuditRecordDigestSHA256 ||
		sha256.Sum256(record.Payload) != record.Envelope.PayloadDigest ||
		record.Domain.ReplayDomainID != view.AuditStreamID ||
		record.Domain.SenderIdentity != view.AuthorizedAuditWriterIdentity ||
		record.Envelope.SenderIdentity != view.AuthorizedAuditWriterIdentity ||
		record.Domain.Counter != view.NextAuditSequence || record.Envelope.Counter != view.NextAuditSequence ||
		record.Domain.CounterKind != ccse.CounterSequence || record.Envelope.CounterKind != ccse.CounterSequence {
		return emptyRecord, emptyEvent, ErrInvalidCompoundResult
	}
	retained := view.AuditEventEvidence.Record()
	if retained == nil || view.AuditEventEvidence.RecordDigest() != digest || !reflect.DeepEqual(*retained, record) {
		return emptyRecord, emptyEvent, ErrInvalidCompoundResult
	}
	validator, err := foundationcanonical.NewValidator()
	if err != nil {
		return emptyRecord, emptyEvent, ErrInvalidCompoundResult
	}
	decoded, err := validator.Decode(schema.MessageTypeAuditEvent, ccse.Version{Major: 1}, record.Payload)
	event, ok := decoded.(foundationv1.AuditEventSigningProjection)
	if err != nil || !ok || event.AuditEventID != view.JoinedAuditEventID ||
		event.Metadata.RecordID != event.AuditEventID || event.AuditSequence != view.NextAuditSequence ||
		event.Outcome != view.ExpectedOutcome || event.OccurredAtUnixNano != view.CanonicalAuditIntent.OccurredAtUnixNano ||
		event.PreviousEventDigestSHA256 != expectedPreviousDigest(view) {
		return emptyRecord, emptyEvent, ErrInvalidCompoundResult
	}
	return record, event, nil
}

func expectedPreviousDigest(view governance.JoinedAuditFragmentSnapshot) [sha256.Size]byte {
	if view.ExpectedAuditSequence == 0 {
		return view.DeploymentAnchorSHA256
	}
	return view.ExpectedAuditHeadDigestSHA256
}

func auditedSuccessPayload(request iam.JoinedAuditRequest, execution iam.IAMExecutionFragment,
	fragment governance.JoinedAuditFragment, view governance.JoinedAuditFragmentSnapshot,
	record ccse.Record, event foundationv1.AuditEventSigningProjection,
	transactionID string, transactionAt int64) ([]byte, error) {
	bundle, ok := request.AuditEvidenceBundle()
	if !ok || bundle.VerifyFor(request) != nil ||
		bundle.Digest() != view.IAMAuditEvidenceBundleDigestSHA256 {
		return nil, ErrInvalidCompoundResult
	}
	requestDigest := request.Digest()
	recordDigest, err := record.Digest(ccse.DefaultLimits())
	if err != nil {
		return nil, ErrInvalidCompoundResult
	}
	return encodeAuditedSuccessProjection(auditedSuccessProjection{
		kind: request.Kind(), requestDigest: requestDigest, pendingDigest: request.PendingDigest(),
		envelopeDigest: request.DurableEnvelopeDigest(), stateDigest: request.StateAndGlobalCASCommitment(),
		executionDigest: execution.Digest(), governanceDigest: fragment.Digest(), auditEventID: event.AuditEventID,
		auditRecordDigest: recordDigest, auditPayloadDigest: record.Envelope.PayloadDigest,
		auditSequence: event.AuditSequence, auditOutcome: event.Outcome,
		evaluatedAtUnixNano: view.EvaluatedAtUnixNano, commitNotBefore: view.CommitNotBeforeUnixNano,
		commitNotAfter: view.CommitNotAfterUnixNano, evidenceBundleDigest: bundle.Digest(),
		transactionID: transactionID, transactionObservedAt: transactionAt,
	})
}

func encodeAuditedSuccessProjection(value auditedSuccessProjection) ([]byte, error) {
	if !isSuccessfulPendingKind(value.kind) || value.requestDigest == ([sha256.Size]byte{}) ||
		value.pendingDigest == ([sha256.Size]byte{}) || value.envelopeDigest == ([sha256.Size]byte{}) ||
		value.stateDigest == ([sha256.Size]byte{}) || value.executionDigest == ([sha256.Size]byte{}) ||
		value.governanceDigest == ([sha256.Size]byte{}) || value.auditEventID == "" ||
		value.auditRecordDigest == ([sha256.Size]byte{}) || value.auditPayloadDigest == ([sha256.Size]byte{}) ||
		value.auditSequence == 0 || value.auditOutcome != 1 || value.evaluatedAtUnixNano < 0 ||
		value.commitNotBefore < 0 || value.commitNotBefore > value.evaluatedAtUnixNano ||
		value.commitNotAfter <= value.evaluatedAtUnixNano || value.evidenceBundleDigest == ([sha256.Size]byte{}) {
		return nil, ErrInvalidCompoundResult
	}
	if !validTransactionID(value.transactionID) ||
		value.transactionObservedAt < value.commitNotBefore ||
		value.transactionObservedAt >= value.commitNotAfter {
		return nil, ErrInvalidCompoundResult
	}
	return ccse.Marshal(auditedSuccessResultMaxBytes, func(out *ccse.Encoder) {
		out.Uint32(auditedSuccessResultVersion)
		out.Uint32(uint32(value.kind))
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
		out.String(value.transactionID)
		out.Int64(value.transactionObservedAt)
	})
}

func decodeAuditedSuccessProjection(input []byte) (auditedSuccessProjection, error) {
	var value auditedSuccessProjection
	err := ccse.Unmarshal(input, auditedSuccessResultMaxBytes, func(in *ccse.Decoder) error {
		version, err := in.Uint32()
		if err != nil || version != auditedSuccessResultVersion {
			return ErrInvalidCompoundResult
		}
		kind, err := in.Uint32()
		if err != nil {
			return ErrInvalidCompoundResult
		}
		value.kind = iam.DurablePendingKind(kind)
		if err := decodeSuccessDigest(in, &value.requestDigest); err != nil {
			return err
		}
		if err := decodeSuccessDigest(in, &value.pendingDigest); err != nil {
			return err
		}
		if err := decodeSuccessDigest(in, &value.envelopeDigest); err != nil {
			return err
		}
		if err := decodeSuccessDigest(in, &value.stateDigest); err != nil {
			return err
		}
		if err := decodeSuccessDigest(in, &value.executionDigest); err != nil {
			return err
		}
		if err := decodeSuccessDigest(in, &value.governanceDigest); err != nil {
			return err
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
		value.transactionID, err = in.String(20)
		if err != nil {
			return ErrInvalidCompoundResult
		}
		value.transactionObservedAt, err = in.Int64()
		return err
	})
	if err != nil {
		return auditedSuccessProjection{}, ErrInvalidCompoundResult
	}
	if _, err := encodeAuditedSuccessProjection(value); err != nil {
		return auditedSuccessProjection{}, ErrInvalidCompoundResult
	}
	return value, nil
}

func validTransactionID(value string) bool {
	parsed, err := strconv.ParseUint(value, 10, 64)
	return err == nil && parsed != 0 && strconv.FormatUint(parsed, 10) == value
}

func decodeSuccessDigest(in *ccse.Decoder, target *[sha256.Size]byte) error {
	if in == nil || target == nil {
		return ErrInvalidCompoundResult
	}
	raw, err := in.FixedBytes(sha256.Size)
	if err != nil {
		return ErrInvalidCompoundResult
	}
	copy(target[:], raw)
	return nil
}

func isSuccessfulPendingKind(kind iam.DurablePendingKind) bool {
	switch kind {
	case iam.DurablePendingMutation, iam.DurablePendingKeyEnrollment,
		iam.DurablePendingOwnershipTransferCollection,
		iam.DurablePendingOwnershipTransferCutover,
		iam.DurablePendingOwnershipTransferAcceptance:
		return true
	default:
		return false
	}
}
