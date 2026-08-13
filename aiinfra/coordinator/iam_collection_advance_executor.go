// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package coordinator

import (
	"bytes"
	"context"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/iam"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	"github.com/cypherium/cypher/aiinfra/storage/postgres"
)

// NewIAMCollectionAdvanceHandler is the canonical kind-3 continuation path.
// It can only replace an exact locked OPEN predecessor. The parent X row is
// advanced while its immutable joined Y row is byte-asserted in the same
// transaction; no caller can reinterpret this capability as first admission.
func NewIAMCollectionAdvanceHandler(envelope iam.DurablePendingEnvelope,
	capability iam.IAMCollectionAdvanceCapability) (ccse.ReplayHandler, error) {
	if envelope.CommitReady() || envelope.VerifyDigest() != nil ||
		envelope.Kind() != iam.DurablePendingOwnershipTransferCollection ||
		capability.VerifyFor(envelope) != nil {
		return nil, ErrInvalidCompoundResult
	}
	outerRecord, present := capability.OuterRecord()
	if !present || capability.OuterRecordDigest() == ([ccse.DigestSize]byte{}) {
		return nil, ErrInvalidCompoundResult
	}
	outerDigest, err := outerRecord.Digest(ccse.DefaultLimits())
	if err != nil || outerDigest != capability.OuterRecordDigest() {
		return nil, ErrInvalidCompoundResult
	}
	source := capability.Source()
	next, err := mapIAMPendingRevision(capability.NextRevision())
	if err != nil || source.Kind != iam.DurablePendingOwnershipTransferCollection ||
		next.ExpectedKind != postgres.DurablePendingOwnershipTransferCollection ||
		next.Kind != postgres.DurablePendingOwnershipTransferCollection ||
		next.Status != postgres.DurablePendingOpen || next.Revision != source.Revision+1 ||
		next.PreviousEnvelopeDigest != source.EnvelopeDigestSHA256 ||
		!bytes.Equal(next.PreviousCanonicalEnvelope, source.CanonicalEnvelope) ||
		next.PreviousCommitNotBeforeUnixNano != source.CommitNotBeforeUnixNano ||
		next.PreviousCommitNotAfterUnixNano != source.CommitNotAfterUnixNano ||
		next.EnvelopeDigest != envelope.Digest() || !bytes.Equal(next.CanonicalEnvelope, envelope.Bytes()) ||
		next.ExpectedAuditEventID != capability.AuditEventID() {
		return nil, ErrInvalidCompoundResult
	}
	state := capability.CanonicalStateReads()
	if state.VerifyFor(envelope) != nil || len(state.Assertions())+len(state.Absences()) >
		postgres.MaxCanonicalStateAssertions {
		return nil, ErrInvalidCompoundResult
	}
	advance, parentExpected, joinedExpected, err := validateCollectionAdvanceIdempotency(capability)
	if err != nil || len(capability.IdentifierClaims()) == 0 ||
		preflightIAMCollectionAdvanceWriteBudget(capability, next) != nil {
		return nil, ErrInvalidCompoundResult
	}

	return func(ctx context.Context, outer ccse.VerifiedRecord) ([ccse.DigestSize]byte, error) {
		if capability.VerifyOuter(outer) != nil ||
			!exactIAMAdmissionOuter(outer, outerRecord, capability.OuterRecordDigest()) {
			return [ccse.DigestSize]byte{}, ErrInvalidCompoundResult
		}
		uow, err := postgres.OpenCanonicalUOW(ctx, outer, postgres.CanonicalAdmission, "", 0)
		if err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := uow.AssertOuterVerifiedRecord(ctx, outer); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		clock, err := uow.SnapshotTransactionClock(ctx)
		if err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		result, err := newIAMCollectionAdvanceResult(iamCollectionAdvanceResultProjection{
			pendingDigest: capability.PendingDigest(), envelopeDigest: envelope.Digest(),
			capabilityDigest: capability.Digest(), stateReadDigest: state.Digest(),
			nextRevisionDigest:   capability.NextRevision().Digest(),
			sourceEnvelopeDigest: source.EnvelopeDigestSHA256,
			outerRecordDigest:    outer.Digest(), outerPayloadDigest: outer.Envelope().PayloadDigest,
			auditEventID: capability.AuditEventID(), sourceRevision: source.Revision,
			nextRevision:                    next.Revision,
			previousCommitNotBeforeUnixNano: source.CommitNotBeforeUnixNano,
			previousCommitNotAfterUnixNano:  source.CommitNotAfterUnixNano,
			commitNotBeforeUnixNano:         next.CommitNotBeforeUnixNano,
			commitNotAfterUnixNano:          next.CommitNotAfterUnixNano,
			transactionID:                   clock.TransactionID(), transactionObservedAtUnixNano: clock.ObservedAtUnixNano(),
		})
		if err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		receipt, err := postgres.NewAdmissionUOWReceipt(result.ContentType(), result.Payload())
		if err != nil || receipt.ResultDigest() != result.Digest() {
			return [ccse.DigestSize]byte{}, ErrInvalidCompoundResult
		}
		if err := uow.BindResult(ctx, receipt); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := assertIAMPendingStoredSource(ctx, uow, source); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := assertIAMAdmissionState(ctx, uow, state); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := assertCollectionAdvanceIdempotency(ctx, uow, parentExpected, joinedExpected); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := uow.ApplyBusinessIdempotency(ctx, postgres.BusinessIdempotencyMutation{
			ExpectedAuditEventID: capability.AuditEventID(), Claims: []idempotency.Claim{advance},
		}); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := uow.ApplyGlobalClaims(ctx, postgres.GlobalClaimMutation{
			AuditEventID: capability.AuditEventID(), Claims: capability.IdentifierClaims(),
		}); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := applyIAMCollectionAdvanceEvidence(ctx, uow, capability); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := uow.ApplyDurablePendingRevision(ctx, next); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := uow.AssertCommitDeadline(ctx, next.CommitNotAfterUnixNano); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		transaction, ok := postgres.Transaction(ctx)
		if !ok {
			return [ccse.DigestSize]byte{}, ErrTransactionBoundaryRequired
		}
		completion, err := result.Completion()
		if err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		digest, err := transaction.Complete(ctx, completion)
		if err != nil || digest != result.Digest() {
			return [ccse.DigestSize]byte{}, ErrInvalidCompoundResult
		}
		return digest, nil
	}, nil
}

func validateCollectionAdvanceIdempotency(capability iam.IAMCollectionAdvanceCapability) (
	idempotency.Claim, idempotency.Snapshot, idempotency.Snapshot, error) {
	claims, err := idempotency.NormalizeClaims(capability.IdempotencyAdvanceClaims())
	joined := capability.JoinedExpectedSnapshot()
	if err != nil || len(claims) != 1 || claims[0].Mode != idempotency.AdvanceCollection ||
		joined.Validate() != nil || joined.State != idempotency.StateCollecting || joined.Version != 1 ||
		joined.OutcomeDigest != ([ccse.DigestSize]byte{}) {
		return idempotency.Claim{}, idempotency.Snapshot{}, idempotency.Snapshot{}, ErrInvalidCompoundResult
	}
	claim := claims[0]
	parent := idempotency.Snapshot{Binding: claim.Binding, State: claim.ExpectedState,
		Version: claim.ExpectedVersion, ProgressDigest: claim.ExpectedProgressDigest}
	joinedBinding, err := idempotency.JoinedAuditBinding(claim.Binding)
	parentDigest, digestErr := idempotency.BindingDigest(claim.Binding)
	if err != nil || digestErr != nil || parent.Validate() != nil || joined.Binding != joinedBinding ||
		joined.ProgressDigest != parentDigest {
		return idempotency.Claim{}, idempotency.Snapshot{}, idempotency.Snapshot{}, ErrInvalidCompoundResult
	}
	return claim, parent, joined, nil
}

func assertCollectionAdvanceIdempotency(ctx context.Context, uow *postgres.CanonicalUOW,
	parentExpected, joinedExpected idempotency.Snapshot) error {
	if uow == nil {
		return ErrInvalidCompoundResult
	}
	parent, parentFound, joined, joinedFound, err := uow.SnapshotBusinessIdempotencyPair(ctx,
		parentExpected.Binding.Key, joinedExpected.Binding.Key)
	if err != nil {
		return err
	}
	if !parentFound || !joinedFound || parent != parentExpected || joined != joinedExpected {
		return ErrInvalidCompoundResult
	}
	return nil
}

func applyIAMCollectionAdvanceEvidence(ctx context.Context, uow *postgres.CanonicalUOW,
	capability iam.IAMCollectionAdvanceCapability) error {
	if uow == nil || capability.VerifyDigest() != nil {
		return ErrInvalidCompoundResult
	}
	source := capability.Source()
	linked := make(map[[ccse.DigestSize]byte]struct{}, len(source.EvidenceDigestsSHA256))
	for _, digest := range source.EvidenceDigestsSHA256 {
		linked[digest] = struct{}{}
	}
	values := capability.EvidenceStorageCapabilities()
	if len(values) == 0 {
		return ErrInvalidCompoundResult
	}
	for _, value := range values {
		if value.VerifyDigest() != nil || value.AuditAssertionEventID() != capability.AuditEventID() {
			return ErrInvalidCompoundResult
		}
		evidence := value.Evidence()
		if evidence.VerifyDigest() != nil {
			return ErrInvalidCompoundResult
		}
		record := evidence.Record()
		kind := postgres.DurableEvidenceKind(record.Kind)
		if kind < postgres.DurableEvidenceContentSHA256 || kind > postgres.DurableEvidenceSemanticReceipt {
			return ErrInvalidCompoundResult
		}
		pendingKey, revision, hasLink := value.PendingLink()
		_, wasLinked := linked[record.DigestSHA256]
		if hasLink != wasLinked ||
			(hasLink && (pendingKey != source.PendingKey || revision != source.Revision ||
				value.Disposition() != iam.IAMEvidenceStorageAssertExisting)) ||
			(!hasLink && (pendingKey != ([ccse.MessageIDSize]byte{}) || revision != 0)) {
			return ErrInvalidCompoundResult
		}
		mapped := postgres.DurableEvidenceRecord{Digest: record.DigestSHA256, Kind: kind,
			ContentType: record.ContentType, CanonicalContent: append([]byte(nil), record.CanonicalContent...),
			ExpectedAuditEventID: record.ExpectedAuditEventID}
		switch value.Disposition() {
		case iam.IAMEvidenceStorageReserveNew:
			if hasLink || record.ExpectedAuditEventID != capability.AuditEventID() {
				return ErrInvalidCompoundResult
			}
			if err := uow.ReserveDurableEvidence(ctx, mapped); err != nil {
				return err
			}
		case iam.IAMEvidenceStorageAssertExisting:
			if err := uow.AssertDurableEvidenceContent(ctx, mapped); err != nil {
				return err
			}
		default:
			return ErrInvalidCompoundResult
		}
	}
	return nil
}

func preflightIAMCollectionAdvanceWriteBudget(capability iam.IAMCollectionAdvanceCapability,
	next postgres.DurablePendingRevision) error {
	var total uint64
	for _, value := range capability.EvidenceStorageCapabilities() {
		if value.VerifyDigest() != nil {
			return ErrInvalidCompoundResult
		}
		if value.Disposition() == iam.IAMEvidenceStorageReserveNew {
			evidence := value.Evidence()
			if evidence.VerifyDigest() != nil ||
				addCanonicalWriteBytes(&total, len(evidence.Record().CanonicalContent)) != nil {
				return ErrInvalidCompoundResult
			}
		}
	}
	return addCanonicalWriteBytes(&total, len(next.CanonicalEnvelope))
}
