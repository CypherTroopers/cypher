// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package coordinator

import (
	"bytes"
	"context"
	"reflect"
	"sort"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/iam"
	"github.com/cypherium/cypher/aiinfra/storage/postgres"
)

// NewIAMAdmissionHandler is the only canonical first-OPEN path for IAM
// pending kinds 1..3. It persists no business mutation: it byte-asserts the
// optimistic semantic read set, reserves X/Y and global identifiers, retains
// the complete evidence preimages and stores revision one under the replay
// transaction of the exact signed source record.
func NewIAMAdmissionHandler(envelope iam.DurablePendingEnvelope,
	capability iam.IAMPendingAdmissionCapability) (ccse.ReplayHandler, error) {
	if envelope.CommitReady() || envelope.VerifyDigest() != nil || capability.VerifyFor(envelope) != nil ||
		envelope.Kind() < iam.DurablePendingMutation ||
		envelope.Kind() > iam.DurablePendingOwnershipTransferCollection {
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
	revision, err := mapIAMPendingRevision(capability.PendingRevision())
	if err != nil || revision.Revision != 1 || revision.ExpectedKind != 0 ||
		revision.Status != postgres.DurablePendingOpen || revision.Kind != postgres.DurablePendingKind(envelope.Kind()) ||
		revision.EnvelopeDigest != envelope.Digest() || !bytes.Equal(revision.CanonicalEnvelope, envelope.Bytes()) ||
		revision.ExpectedAuditEventID != capability.AuditEventID() {
		return nil, ErrInvalidCompoundResult
	}
	state := capability.CanonicalStateReads()
	if state.VerifyFor(envelope) != nil || state.AuditEventID() != capability.AuditEventID() ||
		len(state.Assertions())+len(state.Absences()) > postgres.MaxCanonicalStateAssertions {
		return nil, ErrInvalidCompoundResult
	}
	if len(capability.IdempotencyReservations()) == 0 || len(capability.IdentifierClaims()) == 0 ||
		preflightIAMAdmissionWriteBudget(capability, revision) != nil {
		return nil, ErrInvalidCompoundResult
	}

	return func(ctx context.Context, outer ccse.VerifiedRecord) ([ccse.DigestSize]byte, error) {
		if !exactIAMAdmissionOuter(outer, outerRecord, capability.OuterRecordDigest()) {
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
		result, err := newIAMAdmissionResult(iamAdmissionResultProjection{
			kind: envelope.Kind(), pendingDigest: capability.PendingDigest(), envelopeDigest: envelope.Digest(),
			capabilityDigest: capability.Digest(), stateReadDigest: state.Digest(),
			revisionDigest: capability.PendingRevision().Digest(), outerRecordDigest: outer.Digest(),
			outerPayloadDigest: outer.Envelope().PayloadDigest, auditEventID: capability.AuditEventID(),
			commitNotBeforeUnixNano: revision.CommitNotBeforeUnixNano,
			commitNotAfterUnixNano:  revision.CommitNotAfterUnixNano,
			transactionID:           clock.TransactionID(), transactionObservedAtNano: clock.ObservedAtUnixNano(),
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
		if err := assertIAMAdmissionState(ctx, uow, state); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := uow.ApplyBusinessIdempotency(ctx, postgres.BusinessIdempotencyMutation{
			ExpectedAuditEventID: capability.AuditEventID(), Claims: capability.IdempotencyReservations(),
		}); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := uow.ApplyGlobalClaims(ctx, postgres.GlobalClaimMutation{
			AuditEventID: capability.AuditEventID(), Claims: capability.IdentifierClaims(),
		}); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := applyIAMAdmissionEvidence(ctx, uow, capability); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := uow.ApplyDurablePendingRevision(ctx, revision); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := uow.AssertCommitDeadline(ctx, revision.CommitNotAfterUnixNano); err != nil {
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

func exactIAMAdmissionOuter(verified ccse.VerifiedRecord, expected ccse.Record,
	digest [ccse.DigestSize]byte) bool {
	actualDigest, err := expected.Digest(ccse.DefaultLimits())
	return err == nil && actualDigest == digest && verified.Digest() == digest &&
		reflect.DeepEqual(expected, verified.Record())
}

func assertIAMAdmissionState(ctx context.Context, uow *postgres.CanonicalUOW,
	state iam.IAMPendingAdmissionStateCapability) error {
	if uow == nil || state.VerifyDigest() != nil {
		return ErrInvalidCompoundResult
	}
	for _, assertion := range state.Assertions() {
		record, err := mapIAMStateAssertion(assertion)
		if err != nil {
			return err
		}
		if err := uow.AssertCanonicalState(ctx, record); err != nil {
			return err
		}
	}
	for _, absence := range state.Absences() {
		namespace, kind, objectID, err := mapIAMStateAbsence(absence)
		if err != nil {
			return err
		}
		if err := uow.AssertCanonicalStateAbsent(ctx, namespace, kind, objectID); err != nil {
			return err
		}
	}
	return nil
}

func applyIAMAdmissionEvidence(ctx context.Context, uow *postgres.CanonicalUOW,
	capability iam.IAMPendingAdmissionCapability) error {
	if uow == nil || capability.VerifyDigest() != nil {
		return ErrInvalidCompoundResult
	}
	values := capability.EvidenceStorageCapabilities()
	if len(values) == 0 {
		return ErrInvalidCompoundResult
	}
	sort.Slice(values, func(i, j int) bool {
		left := values[i].Evidence().Record().DigestSHA256
		right := values[j].Evidence().Record().DigestSHA256
		return bytes.Compare(left[:], right[:]) < 0
	})
	var prior [ccse.DigestSize]byte
	for index, value := range values {
		if value.VerifyDigest() != nil || value.AuditAssertionEventID() != capability.AuditEventID() {
			return ErrInvalidCompoundResult
		}
		if key, revision, linked := value.PendingLink(); linked || revision != 0 || key != ([ccse.MessageIDSize]byte{}) {
			return ErrInvalidCompoundResult
		}
		evidence := value.Evidence()
		if evidence.VerifyDigest() != nil {
			return ErrInvalidCompoundResult
		}
		record := evidence.Record()
		if index > 0 && bytes.Compare(prior[:], record.DigestSHA256[:]) >= 0 {
			return ErrInvalidCompoundResult
		}
		prior = record.DigestSHA256
		mapped := postgres.DurableEvidenceRecord{Digest: record.DigestSHA256,
			Kind: postgres.DurableEvidenceKind(record.Kind), ContentType: record.ContentType,
			CanonicalContent:     append([]byte(nil), record.CanonicalContent...),
			ExpectedAuditEventID: record.ExpectedAuditEventID}
		switch value.Disposition() {
		case iam.IAMEvidenceStorageReserveNew:
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

func preflightIAMAdmissionWriteBudget(capability iam.IAMPendingAdmissionCapability,
	revision postgres.DurablePendingRevision) error {
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
	return addCanonicalWriteBytes(&total, len(revision.CanonicalEnvelope))
}
