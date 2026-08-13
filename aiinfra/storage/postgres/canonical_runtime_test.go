// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
)

func newBoundCanonicalUnit(t *testing.T, receipt CanonicalUOWReceipt) (context.Context,
	atomicTxView, *transactionState, *unitDriver, *CanonicalUOW) {
	t.Helper()
	entry, verified := verifiedReplayInput(t)
	if receipt.kind == CanonicalAuditedFinal {
		entry, verified = verifiedAuditReplayInput(t, receipt.auditEventID)
	}
	ctx, transaction, state, driverInstance := newUnitTransactionForEntry(t, nil, entry)
	uow, err := BindCanonicalUOW(ctx, verified, receipt)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, transaction, state, driverInstance, uow
}

func exactCompletion(receipt CanonicalUOWReceipt) DurableCompletion {
	return DurableCompletion{ContentType: receipt.ResultContentType(), Payload: receipt.ResultPayload(),
		ExternalEffects: NoExternalEffects}
}

func exactOuterAuditRecord(uow *CanonicalUOW, eventID string, _ byte) AuditEventRecord {
	audit := uow.bound.outerAudit
	return AuditEventRecord{EventID: eventID, StreamID: audit.streamID, Sequence: audit.sequence,
		EventDigest: uow.bound.outerPayloadDigest, RecordDigest: uow.bound.outerRecordDigest,
		CanonicalEvent: bytes.Clone(uow.bound.outerCanonicalPayload), OccurredAtUnixNano: audit.occurredAtUnixNano,
		Head: AuditHeadCAS{DeploymentAnchorDigest: audit.previousDigest,
			AuthorizedWriterIdentity: audit.writerIdentity, AuthorizedHomeRegion: audit.homeRegion,
			AuthorizedWriterEpoch: audit.writerEpoch, AuthorizedGovernanceProfileDigest: [sha256.Size]byte{2},
			WriterLeaseEvidenceDigest:    [sha256.Size]byte{3},
			WriterLeaseNotBeforeUnixNano: audit.occurredAtUnixNano - 1,
			WriterLeaseNotAfterUnixNano:  audit.occurredAtUnixNano + 1}}
}

func setUnitQuery(driverInstance *unitDriver, query string, columns []string, values [][]driver.Value) {
	driverInstance.mu.Lock()
	defer driverInstance.mu.Unlock()
	if driverInstance.queryResponses == nil {
		driverInstance.queryResponses = make(map[string]unitQueryResponse)
	}
	driverInstance.queryResponses[strings.TrimSpace(query)] = unitQueryResponse{columns: columns, values: values}
}

func TestCanonicalReceiptOwnsResultAndAdmissionCompletesByteExactly(t *testing.T) {
	payload := []byte("admitted")
	receipt, err := NewAdmissionUOWReceipt("application/cph.admission", payload)
	if err != nil {
		t.Fatal(err)
	}
	payload[0] = 'X'
	if got := string(receipt.ResultPayload()); got != "admitted" {
		t.Fatalf("owned payload = %q", got)
	}
	detached := receipt.ResultPayload()
	detached[0] = 'Y'
	if got := string(receipt.ResultPayload()); got != "admitted" {
		t.Fatalf("getter aliases receipt: %q", got)
	}
	ctx, transaction, state, _, _ := newBoundCanonicalUnit(t, receipt)
	digest, err := transaction.Complete(ctx, exactCompletion(receipt))
	if err != nil {
		t.Fatal(err)
	}
	if digest != receipt.ResultDigest() {
		t.Fatal("completion digest differs from bound receipt")
	}
	if err := state.finish(digest); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalBindRejectsWrongContextMismatchAndDuplicate(t *testing.T) {
	receipt, err := NewAdmissionUOWReceipt("application/cph.admission", []byte("ok"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BindCanonicalUOW(context.Background(), ccse.VerifiedRecord{}, receipt); !errors.Is(err, ErrCanonicalUOWRequired) {
		t.Fatalf("unbound context error = %v", err)
	}

	entry, verified := verifiedReplayInput(t)
	ctx, _, state, _ := newUnitTransactionForEntry(t, nil, entry)
	if _, err := BindCanonicalUOW(ctx, ccse.VerifiedRecord{}, receipt); !errors.Is(err, ErrCanonicalUOWMismatch) {
		t.Fatalf("mismatched verified record error = %v", err)
	}
	if state.poisoned == nil {
		t.Fatal("mismatched bind did not poison the transaction")
	}

	ctx, _, _, _, uow := newBoundCanonicalUnit(t, receipt)
	if uow == nil {
		t.Fatal("nil canonical capability")
	}
	if _, err := BindCanonicalUOW(ctx, verified, receipt); !errors.Is(err, ErrCanonicalUOWDuplicate) {
		t.Fatalf("duplicate bind error = %v", err)
	}
}

func TestCanonicalPlanningOpenClockThenBindResult(t *testing.T) {
	receipt, err := NewAdmissionUOWReceipt("application/cph.admission", []byte("planned"))
	if err != nil {
		t.Fatal(err)
	}
	entry, verified := verifiedReplayInput(t)
	ctx, transaction, state, driverInstance := newUnitTransactionForEntry(t, nil, entry)
	uow, err := OpenCanonicalUOW(ctx, verified, CanonicalAdmission, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	driverInstance.mu.Lock()
	beforePlanning := len(driverInstance.executions)
	driverInstance.mu.Unlock()
	if beforePlanning != 0 {
		t.Fatalf("planning open issued %d writes", beforePlanning)
	}
	setUnitQuery(driverInstance, selectGlobalHeadForUpdateSQL,
		[]string{"owner_domain", "owner_id", "version"}, [][]driver.Value{{
			string(globalid.OwnerIAMIdentity), "identity-1", "1",
		}})
	globalSnapshot, found, err := uow.LookupGlobalID(ctx, "identity-1")
	if err != nil || !found || globalSnapshot.Owner.ID != "identity-1" {
		t.Fatalf("pre-bind transaction read=%+v found=%t err=%v", globalSnapshot, found, err)
	}
	setUnitQuery(driverInstance, snapshotCanonicalTransactionClockSQL,
		[]string{"pg_current_xact_id", "observed_at_unix_nano"},
		[][]driver.Value{{"4294967300", int64(1_800_000_000_000_000_000)}})
	if _, err := uow.SnapshotTransactionClock(ctx); err != nil {
		t.Fatal(err)
	}
	if err := uow.BindResult(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	digest, err := transaction.Complete(ctx, exactCompletion(receipt))
	if err != nil {
		t.Fatal(err)
	}
	if err := state.finish(digest); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalFinalCommitDeadlineUsesFreshDatabaseClock(t *testing.T) {
	receipt, err := NewAuditedFinalUOWReceipt("application/cph.final", []byte("final"),
		"event-deadline", 1)
	if err != nil {
		t.Fatal(err)
	}
	newUOW := func(t *testing.T) (context.Context, *CanonicalUOW, *transactionState, *unitDriver) {
		t.Helper()
		entry, verified := verifiedAuditReplayInput(t, "event-deadline")
		ctx, _, state, driverInstance := newUnitTransactionForEntry(t, nil, entry)
		uow, openErr := OpenCanonicalUOW(ctx, verified, CanonicalAuditedFinal,
			"event-deadline", 1)
		if openErr != nil {
			t.Fatal(openErr)
		}
		setUnitQuery(driverInstance, snapshotCanonicalTransactionClockSQL,
			[]string{"pg_current_xact_id", "observed_at_unix_nano"},
			[][]driver.Value{{"4294967300", int64(100)}})
		if _, clockErr := uow.SnapshotTransactionClock(ctx); clockErr != nil {
			t.Fatal(clockErr)
		}
		if bindErr := uow.BindResult(ctx, receipt); bindErr != nil {
			t.Fatal(bindErr)
		}
		return ctx, uow, state, driverInstance
	}

	ctx, uow, state, driverInstance := newUOW(t)
	setUnitQuery(driverInstance, assertCanonicalCommitDeadlineSQL,
		[]string{"pg_current_xact_id", "observed_at_unix_nano"},
		[][]driver.Value{{"4294967300", int64(199)}})
	if err := uow.AssertCommitDeadline(ctx, 200); err != nil {
		t.Fatalf("fresh pre-deadline observation: %v", err)
	}
	setUnitQuery(driverInstance, assertCanonicalCommitDeadlineSQL,
		[]string{"pg_current_xact_id", "observed_at_unix_nano"},
		[][]driver.Value{{"4294967300", int64(199)}})
	if err := assertCanonicalCommitDeadlineBeforeCommit(ctx, state); err != nil {
		t.Fatalf("final pre-commit observation: %v", err)
	}
	setUnitQuery(driverInstance, assertCanonicalCommitDeadlineSQL,
		[]string{"pg_current_xact_id", "observed_at_unix_nano"},
		[][]driver.Value{{"4294967300", int64(200)}})
	if err := assertCanonicalCommitDeadlineBeforeCommit(ctx, state); !errors.Is(err, ErrCanonicalUOWMismatch) {
		t.Fatalf("final half-open deadline error = %v", err)
	}

	ctx, uow, _, driverInstance = newUOW(t)
	setUnitQuery(driverInstance, assertCanonicalCommitDeadlineSQL,
		[]string{"pg_current_xact_id", "observed_at_unix_nano"},
		[][]driver.Value{{"4294967300", int64(200)}})
	if err := uow.AssertCommitDeadline(ctx, 200); !errors.Is(err, ErrCanonicalUOWMismatch) {
		t.Fatalf("half-open deadline error = %v", err)
	}

	ctx, uow, _, driverInstance = newUOW(t)
	setUnitQuery(driverInstance, assertCanonicalCommitDeadlineSQL,
		[]string{"pg_current_xact_id", "observed_at_unix_nano"},
		[][]driver.Value{{"4294967301", int64(150)}})
	if err := uow.AssertCommitDeadline(ctx, 200); !errors.Is(err, ErrCanonicalUOWMismatch) {
		t.Fatalf("foreign xid error = %v", err)
	}
}

func TestCanonicalAdmissionUsesSameFreshCommitDeadlineFence(t *testing.T) {
	receipt, err := NewAdmissionUOWReceipt("application/cph.admission", []byte("admitted"))
	if err != nil {
		t.Fatal(err)
	}
	entry, verified := verifiedReplayInput(t)
	ctx, _, state, driverInstance := newUnitTransactionForEntry(t, nil, entry)
	uow, err := OpenCanonicalUOW(ctx, verified, CanonicalAdmission, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	setUnitQuery(driverInstance, snapshotCanonicalTransactionClockSQL,
		[]string{"pg_current_xact_id", "observed_at_unix_nano"},
		[][]driver.Value{{"4294967300", int64(100)}})
	if _, err := uow.SnapshotTransactionClock(ctx); err != nil {
		t.Fatal(err)
	}
	if err := uow.BindResult(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	setUnitQuery(driverInstance, assertCanonicalCommitDeadlineSQL,
		[]string{"pg_current_xact_id", "observed_at_unix_nano"},
		[][]driver.Value{{"4294967300", int64(199)}})
	if err := uow.AssertCommitDeadline(ctx, 200); err != nil {
		t.Fatalf("admission deadline: %v", err)
	}
	if err := assertCanonicalCommitDeadlineBeforeCommit(ctx, state); err != nil {
		t.Fatalf("admission final deadline: %v", err)
	}
}

func TestCanonicalPlanningRejectsPreBindWriteAndCompletion(t *testing.T) {
	entry, verified := verifiedReplayInput(t)
	ctx, transaction, _, driverInstance := newUnitTransactionForEntry(t, nil, entry)
	uow, err := OpenCanonicalUOW(ctx, verified, CanonicalAdmission, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	err = uow.ReserveDurableEvidence(ctx, DurableEvidenceRecord{Digest: [sha256.Size]byte{1},
		Kind: DurableEvidenceContentSHA256, ContentType: "application/cph.evidence",
		CanonicalContent: []byte("evidence"), ExpectedAuditEventID: "future-event"})
	if !errors.Is(err, ErrCanonicalUOWPhase) {
		t.Fatalf("pre-bind write error = %v", err)
	}
	driverInstance.mu.Lock()
	executions := len(driverInstance.executions)
	driverInstance.mu.Unlock()
	if executions != 0 {
		t.Fatalf("pre-bind write issued %d SQL writes", executions)
	}
	if _, err := transaction.Complete(ctx, DurableCompletion{ContentType: "application/cph.admission",
		Payload: []byte("planned"), ExternalEffects: NoExternalEffects}); !errors.Is(err, ErrTransactionPoisoned) {
		t.Fatalf("completion after pre-bind write error = %v", err)
	}

	ctx, transaction, _, _ = newUnitTransactionForEntry(t, nil, entry)
	uow, err = OpenCanonicalUOW(ctx, verified, CanonicalAdmission, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Complete(ctx, DurableCompletion{ContentType: "application/cph.admission",
		Payload: []byte("planned"), ExternalEffects: NoExternalEffects}); !errors.Is(err, ErrCanonicalUOWPhase) {
		t.Fatalf("completion before result bind error = %v", err)
	}
}

func TestCanonicalPlanningResultBindIsContextAndIntentExactOneShot(t *testing.T) {
	receipt, err := NewAuditedFinalUOWReceipt("application/cph.final", []byte("final"),
		"event-one", 1)
	if err != nil {
		t.Fatal(err)
	}
	entry, verified := verifiedAuditReplayInput(t, "event-one")
	ctx, _, _, _ := newUnitTransactionForEntry(t, nil, entry)
	uow, err := OpenCanonicalUOW(ctx, verified, CanonicalAuditedFinal, "event-one", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := uow.BindResult(context.Background(), receipt); !errors.Is(err, ErrCanonicalUOWRequired) {
		t.Fatalf("foreign-context result bind error = %v", err)
	}

	ctx, _, _, _ = newUnitTransactionForEntry(t, nil, entry)
	uow, err = OpenCanonicalUOW(ctx, verified, CanonicalAuditedFinal, "event-one", 1)
	if err != nil {
		t.Fatal(err)
	}
	mismatch, err := NewAuditedFinalUOWReceipt("application/cph.final", []byte("final"),
		"event-two", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := uow.BindResult(ctx, mismatch); !errors.Is(err, ErrCanonicalUOWMismatch) {
		t.Fatalf("mismatched planning intent error = %v", err)
	}

	ctx, _, _, _ = newUnitTransactionForEntry(t, nil, entry)
	uow, err = OpenCanonicalUOW(ctx, verified, CanonicalAuditedFinal, "event-one", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := uow.BindResult(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	if err := uow.BindResult(ctx, receipt); !errors.Is(err, ErrCanonicalUOWDuplicate) {
		t.Fatalf("duplicate result bind error = %v", err)
	}

	ctx, _, _, _ = newUnitTransactionForEntry(t, nil, entry)
	if _, err := OpenCanonicalUOW(ctx, verified, CanonicalAuditedFinal, "event-one", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCanonicalUOW(ctx, verified, CanonicalAuditedFinal, "event-one", 1); !errors.Is(err, ErrCanonicalUOWDuplicate) {
		t.Fatalf("duplicate planning open error = %v", err)
	}
}

func TestCanonicalPlanningOuterVerifiedRecordAssertionIsPreBindAndExact(t *testing.T) {
	receipt, err := NewAuditedFinalUOWReceipt("application/cph.final", []byte("final"),
		"event-one", 1)
	if err != nil {
		t.Fatal(err)
	}
	entry, outer := verifiedAuditReplayInput(t, "event-one")
	ctx, _, _, _ := newUnitTransactionForEntry(t, nil, entry)
	uow, err := OpenCanonicalUOW(ctx, outer, CanonicalAuditedFinal, "event-one", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := uow.AssertOuterVerifiedRecord(ctx, outer); err != nil {
		t.Fatalf("exact pre-bind outer assertion: %v", err)
	}
	detachedSignature := outer.Signature()
	detachedSignature[0] ^= 1
	if bytes.Equal(detachedSignature, uow.bound.outerSignature) {
		t.Fatal("open UoW retained caller-aliased signature bytes")
	}
	if err := uow.BindResult(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	if err := uow.AssertOuterVerifiedRecord(ctx, outer); !errors.Is(err, ErrCanonicalUOWPhase) {
		t.Fatalf("post-bind outer assertion error = %v", err)
	}

	ctx, _, state, driverInstance := newUnitTransactionForEntry(t, nil, entry)
	uow, err = OpenCanonicalUOW(ctx, outer, CanonicalAuditedFinal, "event-one", 1)
	if err != nil {
		t.Fatal(err)
	}
	_, detached := verifiedAuditReplayInputWithCause(t, "event-one", "detached-cause")
	if err := uow.AssertOuterVerifiedRecord(ctx, detached); !errors.Is(err, ErrCanonicalUOWMismatch) {
		t.Fatalf("different signed outer with same EventID error = %v", err)
	}
	if state.poisoned == nil {
		t.Fatal("different signed outer did not poison transaction")
	}
	driverInstance.mu.Lock()
	executions := len(driverInstance.executions)
	driverInstance.mu.Unlock()
	if executions != 0 {
		t.Fatalf("outer assertion issued %d SQL statements", executions)
	}

	ctx, _, _, _ = newUnitTransactionForEntry(t, nil, entry)
	uow, err = OpenCanonicalUOW(ctx, outer, CanonicalAuditedFinal, "event-one", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := uow.AssertOuterVerifiedRecord(context.Background(), outer); !errors.Is(err, ErrCanonicalUOWRequired) {
		t.Fatalf("foreign-context outer assertion error = %v", err)
	}
}

func TestCanonicalPlanningRejectsAuditEventAdmissionDowngrade(t *testing.T) {
	entry, verified := verifiedAuditReplayInput(t, "event-one")
	ctx, transaction, state, driverInstance := newUnitTransactionForEntry(t, nil, entry)
	if _, err := OpenCanonicalUOW(ctx, verified, CanonicalAdmission, "", 0); !errors.Is(err, ErrCanonicalUOWMismatch) {
		t.Fatalf("AuditEvent admission downgrade error = %v", err)
	}
	if state.poisoned == nil {
		t.Fatal("AuditEvent admission downgrade did not poison transaction")
	}
	driverInstance.mu.Lock()
	executions := len(driverInstance.executions)
	driverInstance.mu.Unlock()
	if executions != 0 {
		t.Fatalf("AuditEvent admission downgrade issued %d SQL statements", executions)
	}
	if _, err := transaction.Complete(ctx, DurableCompletion{
		ContentType: "application/cph.admission", Payload: []byte("downgraded"),
		ExternalEffects: NoExternalEffects,
	}); !errors.Is(err, ErrTransactionPoisoned) {
		t.Fatalf("completion after AuditEvent admission downgrade error = %v", err)
	}
}

func TestAdmissionForbidsAuditEventAndPoisonsCompletion(t *testing.T) {
	receipt, err := NewAdmissionUOWReceipt("application/cph.admission", []byte("ok"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, transaction, _, _, uow := newBoundCanonicalUnit(t, receipt)
	err = uow.AppendAuditEvent(ctx, AuditEventRecord{EventID: "event-1"})
	if !errors.Is(err, ErrCanonicalUOWPhase) {
		t.Fatalf("Admission AppendAuditEvent error = %v", err)
	}
	if _, err := transaction.Complete(ctx, exactCompletion(receipt)); !errors.Is(err, ErrTransactionPoisoned) {
		t.Fatalf("completion after phase violation error = %v", err)
	}
}

func TestAuditedFinalRequiresAndAcceptsExactAuditGlobalEvidenceCoupling(t *testing.T) {
	receipt, err := NewAuditedFinalUOWReceipt("application/cph.final", []byte("final"), "event-final", 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, transaction, state, driverInstance, uow := newBoundCanonicalUnit(t, receipt)
	if _, err := transaction.Complete(ctx, exactCompletion(receipt)); !errors.Is(err, ErrCanonicalUOWPhase) {
		t.Fatalf("incomplete audited-final completion error = %v", err)
	}
	if state.poisoned == nil {
		t.Fatal("premature completion did not poison transaction")
	}

	// Use a fresh transaction for the complete positive path.
	ctx, transaction, state, driverInstance, uow = newBoundCanonicalUnit(t, receipt)
	claim, err := globalid.Reserve("event-final", globalid.Owner{
		Domain: globalid.OwnerGovernanceAuditEvent, ID: "event-final"})
	if err != nil {
		t.Fatal(err)
	}
	if err := uow.ApplyGlobalClaims(ctx, GlobalClaimMutation{AuditEventID: "event-final",
		Claims: []globalid.Claim{claim}}); err != nil {
		t.Fatal(err)
	}
	if err := uow.AppendAuditEvent(ctx, exactOuterAuditRecord(uow, "event-final", 1)); err != nil {
		t.Fatal(err)
	}
	evidence := DurableEvidenceRecord{Digest: [sha256.Size]byte{3},
		Kind: DurableEvidenceAuthenticatedRecord, ContentType: "application/cph.ccse-record",
		CanonicalContent: []byte("signed-source"), ExpectedAuditEventID: "event-final"}
	setUnitQuery(driverInstance, selectDurableEvidenceForUpdateSQL,
		[]string{"evidence_kind", "content_type", "canonical_content", "audit_event_id"}, nil)
	if err := uow.ReserveDurableEvidence(ctx, evidence); err != nil {
		t.Fatal(err)
	}
	if err := uow.AssertDurableEvidence(ctx, []EvidenceAssertion{{EvidenceDigest: evidence.Digest}}); err != nil {
		t.Fatal(err)
	}
	digest, err := transaction.Complete(ctx, exactCompletion(receipt))
	if err != nil {
		t.Fatal(err)
	}
	if err := state.finish(digest); err != nil {
		t.Fatal(err)
	}
}

func TestAdmissionWriterPersistsJoinedCollectionAndPendingRevision(t *testing.T) {
	receipt, err := NewAdmissionUOWReceipt("application/cph.admission", []byte("collecting"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, transaction, state, _, uow := newBoundCanonicalUnit(t, receipt)
	eventID := "future-event"
	parent := idempotency.Binding{Key: [ccse.MessageIDSize]byte{1},
		Domain: idempotency.OperationIAMIdentity, OwnerID: "identity-1",
		RequestDigest: [sha256.Size]byte{1}}
	joined, err := idempotency.JoinedAuditBinding(parent)
	if err != nil {
		t.Fatal(err)
	}
	parentClaim, err := idempotency.NewReserveCollection(parent, [sha256.Size]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	parentDigest, err := idempotency.BindingDigest(parent)
	if err != nil {
		t.Fatal(err)
	}
	joinedClaim, err := idempotency.NewReserveCollection(joined, parentDigest)
	if err != nil {
		t.Fatal(err)
	}
	if err := uow.ApplyBusinessIdempotency(ctx, BusinessIdempotencyMutation{
		ExpectedAuditEventID: eventID, Claims: []idempotency.Claim{joinedClaim, parentClaim},
	}); err != nil {
		t.Fatal(err)
	}
	globalClaim, err := globalid.Reserve(eventID, globalid.Owner{
		Domain: globalid.OwnerGovernanceAuditEvent, ID: eventID})
	if err != nil {
		t.Fatal(err)
	}
	if err := uow.ApplyGlobalClaims(ctx, GlobalClaimMutation{AuditEventID: eventID,
		Claims: []globalid.Claim{globalClaim}}); err != nil {
		t.Fatal(err)
	}
	if err := uow.ApplyDurablePendingRevision(ctx, DurablePendingRevision{
		PendingKey: parent.Key, Kind: DurablePendingMutation, Codec: DurablePendingIAMCodec,
		CodecVersion: 1, Revision: 1, EnvelopeDigest: [sha256.Size]byte{4},
		CanonicalEnvelope: []byte("canonical-envelope"), Status: DurablePendingOpen,
		CommitNotBeforeUnixNano: 1, CommitNotAfterUnixNano: 2,
		ExpectedAuditEventID: eventID,
	}); err != nil {
		t.Fatal(err)
	}
	digest, err := transaction.Complete(ctx, exactCompletion(receipt))
	if err != nil {
		t.Fatal(err)
	}
	if err := state.finish(digest); err != nil {
		t.Fatal(err)
	}
}

func TestAuditedAcceptanceCompletesParentAndCreatesDistinctFutureChild(t *testing.T) {
	receipt, err := NewAuditedFinalUOWReceipt("application/cph.acceptance", []byte("accepted"),
		"acceptance-event", 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, transaction, state, driverInstance, uow := newBoundCanonicalUnit(t, receipt)

	// First Apply closes the pre-existing transfer X/Y with the outer result.
	parent := idempotency.Binding{Key: [ccse.MessageIDSize]byte{1},
		Domain: idempotency.OperationIAMOwnershipTransfer, OwnerID: "transfer-1",
		RequestDigest: [sha256.Size]byte{1}}
	parentProgress := [sha256.Size]byte{2}
	parentSnapshot := idempotency.Snapshot{Binding: parent, State: idempotency.StateCollecting,
		Version: 3, ProgressDigest: parentProgress}
	parentComplete, err := idempotency.NewCompleteCollection(parentSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	joined, err := idempotency.JoinedAuditBinding(parent)
	if err != nil {
		t.Fatal(err)
	}
	parentDigest, err := idempotency.BindingDigest(parent)
	if err != nil {
		t.Fatal(err)
	}
	joinedComplete, err := idempotency.NewCompleteCollection(idempotency.Snapshot{
		Binding: joined, State: idempotency.StateCollecting, Version: 1, ProgressDigest: parentDigest})
	if err != nil {
		t.Fatal(err)
	}
	if err := uow.ApplyBusinessIdempotency(ctx, BusinessIdempotencyMutation{
		ExpectedAuditEventID: "acceptance-event", OutcomeDigest: receipt.ResultDigest(),
		Claims: []idempotency.Claim{parentComplete, joinedComplete},
	}); err != nil {
		t.Fatal(err)
	}

	// A separate Apply reserves the zero-outcome future cutover X/Y/member.
	child := idempotency.Binding{Key: [ccse.MessageIDSize]byte{3},
		Domain: idempotency.OperationIAMOwnershipTransferCutover, OwnerID: "transfer-1",
		RequestDigest: [sha256.Size]byte{3}}
	childJoined, err := idempotency.JoinedAuditBinding(child)
	if err != nil {
		t.Fatal(err)
	}
	childProgress := [sha256.Size]byte{4}
	childReserve, err := idempotency.NewReserveCollection(child, childProgress)
	if err != nil {
		t.Fatal(err)
	}
	childDigest, err := idempotency.BindingDigest(child)
	if err != nil {
		t.Fatal(err)
	}
	childJoinedReserve, err := idempotency.NewReserveCollection(childJoined, childDigest)
	if err != nil {
		t.Fatal(err)
	}
	member := idempotency.Binding{Key: [ccse.MessageIDSize]byte{5},
		Domain: idempotency.OperationIAMIdentity, OwnerID: "identity-child",
		RequestDigest: [sha256.Size]byte{5}}
	memberReserve, err := idempotency.NewReserveCompoundMember(child, member, [sha256.Size]byte{6})
	if err != nil {
		t.Fatal(err)
	}
	if err := uow.ApplyBusinessIdempotency(ctx, BusinessIdempotencyMutation{
		ExpectedAuditEventID: "future-cutover-event",
		Claims:               []idempotency.Claim{childReserve, childJoinedReserve},
		CompoundMembers:      []idempotency.CompoundMemberClaim{memberReserve},
	}); err != nil {
		t.Fatal(err)
	}

	actualClaim, err := globalid.Reserve("acceptance-event", globalid.Owner{
		Domain: globalid.OwnerGovernanceAuditEvent, ID: "acceptance-event"})
	if err != nil {
		t.Fatal(err)
	}
	if err := uow.ApplyGlobalClaims(ctx, GlobalClaimMutation{AuditEventID: "acceptance-event",
		Claims: []globalid.Claim{actualClaim}}); err != nil {
		t.Fatal(err)
	}
	futureClaim, err := globalid.Reserve("future-cutover-event", globalid.Owner{
		Domain: globalid.OwnerGovernanceAuditEvent, ID: "future-cutover-event"})
	if err != nil {
		t.Fatal(err)
	}
	if err := uow.ApplyGlobalClaims(ctx, GlobalClaimMutation{AuditEventID: "future-cutover-event",
		Claims: []globalid.Claim{futureClaim}}); err != nil {
		t.Fatal(err)
	}

	if err := uow.ApplyDurablePendingRevision(ctx, DurablePendingRevision{
		PendingKey: parent.Key, ExpectedKind: DurablePendingOwnershipTransferCollection,
		Kind:  DurablePendingOwnershipTransferCollection,
		Codec: DurablePendingIAMCodec, CodecVersion: 1, Revision: 2,
		PreviousEnvelopeDigest: [sha256.Size]byte{7}, PreviousCanonicalEnvelope: []byte("open-collection"),
		EnvelopeDigest: [sha256.Size]byte{7}, CanonicalEnvelope: []byte("open-collection"),
		Status:                          DurablePendingTerminal,
		EvidenceDigests:                 [][sha256.Size]byte{{12}},
		PreviousCommitNotBeforeUnixNano: 1, PreviousCommitNotAfterUnixNano: 2,
		CommitNotBeforeUnixNano: 1, CommitNotAfterUnixNano: 2,
		TerminalOutcomeDigest: receipt.ResultDigest(), ExpectedAuditEventID: "acceptance-event",
	}); err != nil {
		t.Fatal(err)
	}
	if err := uow.ApplyDurablePendingRevision(ctx, DurablePendingRevision{
		PendingKey: child.Key, Kind: DurablePendingOwnershipTransferCutover,
		Codec: DurablePendingIAMCodec, CodecVersion: 1, Revision: 1,
		EnvelopeDigest: [sha256.Size]byte{9}, CanonicalEnvelope: []byte("future-cutover"),
		Status: DurablePendingOpen, CommitNotBeforeUnixNano: 2, CommitNotAfterUnixNano: 3,
		ExpectedAuditEventID: "future-cutover-event",
	}); err != nil {
		t.Fatal(err)
	}
	if err := uow.AppendAuditEvent(ctx, exactOuterAuditRecord(uow, "acceptance-event", 10)); err != nil {
		t.Fatal(err)
	}
	evidence := DurableEvidenceRecord{Digest: [sha256.Size]byte{12},
		Kind: DurableEvidenceSemanticReceipt, ContentType: "application/cph.acceptance-evidence",
		CanonicalContent: []byte("verified-acceptance"), ExpectedAuditEventID: "acceptance-event"}
	setUnitQuery(driverInstance, selectDurableEvidenceForUpdateSQL,
		[]string{"evidence_kind", "content_type", "canonical_content", "audit_event_id"}, nil)
	if err := uow.ReserveDurableEvidence(ctx, evidence); err != nil {
		t.Fatal(err)
	}
	if err := uow.AssertDurableEvidence(ctx, []EvidenceAssertion{{EvidenceDigest: evidence.Digest,
		HasPending: true, PendingKey: parent.Key, PendingRevision: 2}}); err != nil {
		t.Fatal(err)
	}
	digest, err := transaction.Complete(ctx, exactCompletion(receipt))
	if err != nil {
		t.Fatal(err)
	}
	if err := state.finish(digest); err != nil {
		t.Fatal(err)
	}
}

func TestPendingKindSixIsRejectedBeforeSQLAndPoisons(t *testing.T) {
	receipt, err := NewAdmissionUOWReceipt("application/cph.admission", []byte("collecting"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, transaction, _, driverInstance, uow := newBoundCanonicalUnit(t, receipt)
	driverInstance.mu.Lock()
	before := len(driverInstance.executions)
	driverInstance.mu.Unlock()
	err = uow.ApplyDurablePendingRevision(ctx, DurablePendingRevision{
		PendingKey: [ccse.MessageIDSize]byte{1}, Kind: DurablePendingKind(6), Codec: "invalid",
		CodecVersion: 1, Revision: 1, EnvelopeDigest: [sha256.Size]byte{1},
		CanonicalEnvelope: []byte("invalid-kind-six"), Status: DurablePendingOpen,
		CommitNotBeforeUnixNano: 1, CommitNotAfterUnixNano: 1, ExpectedAuditEventID: "future-event",
	})
	if !errors.Is(err, ErrCanonicalInvalid) {
		t.Fatalf("kind 6 error = %v", err)
	}
	driverInstance.mu.Lock()
	after := len(driverInstance.executions)
	driverInstance.mu.Unlock()
	if after != before {
		t.Fatalf("invalid kind issued SQL: before=%d after=%d", before, after)
	}
	if _, err := transaction.Complete(ctx, exactCompletion(receipt)); !errors.Is(err, ErrTransactionPoisoned) {
		t.Fatalf("completion after invalid kind error = %v", err)
	}
}

func TestCanonicalCASZeroRowsPoisonsTransaction(t *testing.T) {
	receipt, err := NewAdmissionUOWReceipt("application/cph.admission", []byte("collecting"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, transaction, _, driverInstance, uow := newBoundCanonicalUnit(t, receipt)
	driverInstance.mu.Lock()
	driverInstance.rowsAffected = map[string]int64{strings.TrimSpace(insertGlobalHeadSQL): 0}
	driverInstance.mu.Unlock()
	claim, err := globalid.Reserve("future-event", globalid.Owner{
		Domain: globalid.OwnerGovernanceAuditEvent, ID: "future-event"})
	if err != nil {
		t.Fatal(err)
	}
	err = uow.ApplyGlobalClaims(ctx, GlobalClaimMutation{AuditEventID: "future-event",
		Claims: []globalid.Claim{claim}})
	if !errors.Is(err, ErrCanonicalCASMismatch) {
		t.Fatalf("zero-row CAS error = %v", err)
	}
	if _, err := transaction.Complete(ctx, exactCompletion(receipt)); !errors.Is(err, ErrTransactionPoisoned) {
		t.Fatalf("completion after CAS failure error = %v", err)
	}
}

func TestDurableEvidenceDigestCollisionPoisonsWithoutUpdate(t *testing.T) {
	receipt, err := NewAdmissionUOWReceipt("application/cph.admission", []byte("evidence"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, transaction, _, driverInstance, uow := newBoundCanonicalUnit(t, receipt)
	digest := [sha256.Size]byte{1}
	setUnitQuery(driverInstance, selectDurableEvidenceForUpdateSQL,
		[]string{"evidence_kind", "content_type", "canonical_content", "audit_event_id"},
		[][]driver.Value{{int64(DurableEvidenceSignedCCSERecord), "application/cph.ccse",
			[]byte("original"), "future-event"}})
	err = uow.AssertDurableEvidenceContent(ctx, DurableEvidenceRecord{Digest: digest,
		Kind: DurableEvidenceSignedCCSERecord, ContentType: "application/cph.ccse",
		CanonicalContent: []byte("different"), ExpectedAuditEventID: "future-event"})
	if !errors.Is(err, ErrCanonicalStateCorrupt) {
		t.Fatalf("digest collision error = %v", err)
	}
	if _, err := transaction.Complete(ctx, exactCompletion(receipt)); !errors.Is(err, ErrTransactionPoisoned) {
		t.Fatalf("completion after evidence collision error = %v", err)
	}
}

func TestActualGlobalAssertionRequiresExactAuditAttribution(t *testing.T) {
	receipt, err := NewAuditedFinalUOWReceipt("application/cph.final", []byte("final"), "actual-event", 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, _, _, _, uow := newBoundCanonicalUnit(t, receipt)
	claim, err := globalid.Reserve("actual-event", globalid.Owner{
		Domain: globalid.OwnerGovernanceAuditEvent, ID: "actual-event"})
	if err != nil {
		t.Fatal(err)
	}
	if err := uow.ApplyGlobalClaims(ctx, GlobalClaimMutation{AuditEventID: "different-future-event",
		Claims: []globalid.Claim{claim}}); err != nil {
		t.Fatal(err)
	}
	if uow.bound.globalEventAsserted {
		t.Fatal("claim attributed to another future event satisfied the actual-event assertion")
	}
}

func TestAuditEventDigestIsExactOuterPayloadDigest(t *testing.T) {
	receipt, err := NewAuditedFinalUOWReceipt("application/cph.final", []byte("final"),
		"actual-event", 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, transaction, _, driverInstance, uow := newBoundCanonicalUnit(t, receipt)
	event := exactOuterAuditRecord(uow, "actual-event", 0)
	event.EventDigest[0] ^= 1
	driverInstance.mu.Lock()
	before := len(driverInstance.executions)
	driverInstance.mu.Unlock()
	if err := uow.AppendAuditEvent(ctx, event); !errors.Is(err, ErrCanonicalUOWPhase) {
		t.Fatalf("mismatched payload digest error = %v", err)
	}
	driverInstance.mu.Lock()
	after := len(driverInstance.executions)
	driverInstance.mu.Unlock()
	if after != before {
		t.Fatalf("invalid AuditEvent issued SQL: before=%d after=%d", before, after)
	}
	if _, err := transaction.Complete(ctx, exactCompletion(receipt)); !errors.Is(err, ErrTransactionPoisoned) {
		t.Fatalf("completion after mismatched payload digest error = %v", err)
	}
}

func TestAuthoritativeUOWStoresOuterPayloadDigestOnlyForAuditedFinal(t *testing.T) {
	admission, err := NewAdmissionUOWReceipt("application/cph.admission", []byte("admitted"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, admissionDriver, _ := newBoundCanonicalUnit(t, admission)
	admissionDriver.mu.Lock()
	admissionArgs := append([]driver.NamedValue(nil), admissionDriver.executionArgs[0]...)
	admissionDriver.mu.Unlock()
	if len(admissionArgs) != 9 || admissionArgs[8].Value != nil {
		t.Fatalf("Admission authoritative UoW args = %#v", admissionArgs)
	}

	audited, err := NewAuditedFinalUOWReceipt("application/cph.final", []byte("final"),
		"actual-event", 1)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, auditedDriver, uow := newBoundCanonicalUnit(t, audited)
	auditedDriver.mu.Lock()
	auditedArgs := append([]driver.NamedValue(nil), auditedDriver.executionArgs[0]...)
	auditedDriver.mu.Unlock()
	if len(auditedArgs) != 9 ||
		!bytes.Equal(auditedArgs[8].Value.([]byte), uow.bound.outerPayloadDigest[:]) {
		t.Fatalf("AuditedFinal authoritative UoW args = %#v", auditedArgs)
	}
}

func TestSnapshotTransactionClockUsesExactCanonicalTransaction(t *testing.T) {
	receipt, err := NewAdmissionUOWReceipt("application/cph.admission", []byte("clock"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, _, _, driverInstance, uow := newBoundCanonicalUnit(t, receipt)
	const observed int64 = 1_800_000_000_123_456_000
	setUnitQuery(driverInstance, snapshotCanonicalTransactionClockSQL,
		[]string{"pg_current_xact_id", "observed_at_unix_nano"},
		[][]driver.Value{{"4294967300", observed}})
	snapshot, err := uow.SnapshotTransactionClock(ctx)
	if err != nil || snapshot.TransactionID() != "4294967300" ||
		snapshot.ObservedAtUnixNano() != observed {
		t.Fatalf("transaction clock=%+v err=%v", snapshot, err)
	}
	// Once observed, the transaction clock is an immutable capability value.
	// A later database response must neither replace it nor be consulted.
	driverInstance.mu.Lock()
	driverInstance.queryResponses[strings.TrimSpace(snapshotCanonicalTransactionClockSQL)] =
		unitQueryResponse{err: errors.New("cached transaction clock was queried again")}
	driverInstance.mu.Unlock()
	cached, err := uow.SnapshotTransactionClock(ctx)
	if err != nil || cached != snapshot {
		t.Fatalf("cached transaction clock=%+v err=%v, want %+v", cached, err, snapshot)
	}
	detached := snapshot
	detached.transactionID = "detached"
	detached.observedAtUnixNano++
	if snapshot.TransactionID() != "4294967300" || snapshot.ObservedAtUnixNano() != observed {
		t.Fatal("transaction clock value was not immutable across copies")
	}
	if !strings.Contains(snapshotCanonicalTransactionClockSQL, "pg_current_xact_id()::text") ||
		!strings.Contains(snapshotCanonicalTransactionClockSQL, "clock_timestamp()") {
		t.Fatal("transaction clock SQL is not database/xid bound")
	}

	otherCtx, _, _, otherDriver, otherUOW := newBoundCanonicalUnit(t, receipt)
	const otherObserved int64 = observed + 1
	setUnitQuery(otherDriver, snapshotCanonicalTransactionClockSQL,
		[]string{"pg_current_xact_id", "observed_at_unix_nano"},
		[][]driver.Value{{"4294967301", otherObserved}})
	other, err := otherUOW.SnapshotTransactionClock(otherCtx)
	if err != nil || other.TransactionID() != "4294967301" ||
		other.ObservedAtUnixNano() != otherObserved || other == snapshot {
		t.Fatalf("other UoW transaction clock=%+v err=%v", other, err)
	}
}

func TestSnapshotTransactionClockRejectsMalformedDatabaseValues(t *testing.T) {
	for _, test := range []struct {
		name   string
		values [][]driver.Value
		err    error
	}{
		{name: "zero xid", values: [][]driver.Value{{"0", int64(1)}}},
		{name: "noncanonical xid", values: [][]driver.Value{{"01", int64(1)}}},
		{name: "negative observation", values: [][]driver.Value{{"1", int64(-1)}}},
		{name: "query failure", err: errors.New("clock unavailable")},
	} {
		t.Run(test.name, func(t *testing.T) {
			receipt, err := NewAdmissionUOWReceipt("application/cph.admission", []byte("clock"))
			if err != nil {
				t.Fatal(err)
			}
			ctx, transaction, _, driverInstance, uow := newBoundCanonicalUnit(t, receipt)
			driverInstance.mu.Lock()
			if driverInstance.queryResponses == nil {
				driverInstance.queryResponses = make(map[string]unitQueryResponse)
			}
			driverInstance.queryResponses[strings.TrimSpace(snapshotCanonicalTransactionClockSQL)] =
				unitQueryResponse{columns: []string{"pg_current_xact_id", "observed_at_unix_nano"},
					values: test.values, err: test.err}
			driverInstance.mu.Unlock()
			if _, err := uow.SnapshotTransactionClock(ctx); !errors.Is(err, ErrCanonicalStateCorrupt) {
				t.Fatalf("malformed transaction clock error = %v", err)
			}
			if _, err := transaction.Complete(ctx, exactCompletion(receipt)); !errors.Is(err, ErrTransactionPoisoned) {
				t.Fatalf("completion after malformed clock error = %v", err)
			}
		})
	}
}

func TestAuditedBindAndAppendRejectDetachedSignedPayloadTuple(t *testing.T) {
	receipt, err := NewAuditedFinalUOWReceipt("application/cph.final", []byte("final"),
		"receipt-event", 1)
	if err != nil {
		t.Fatal(err)
	}
	entry, verified := verifiedAuditReplayInput(t, "signed-event")
	ctx, _, state, driverInstance := newUnitTransactionForEntry(t, nil, entry)
	if _, err := BindCanonicalUOW(ctx, verified, receipt); !errors.Is(err, ErrCanonicalUOWMismatch) {
		t.Fatalf("signed/receipt EventID mismatch error = %v", err)
	}
	if state.poisoned == nil {
		t.Fatal("signed/receipt EventID mismatch did not poison transaction")
	}
	driverInstance.mu.Lock()
	executions := len(driverInstance.executions)
	driverInstance.mu.Unlock()
	if executions != 0 {
		t.Fatalf("mismatched audited bind issued %d SQL statements", executions)
	}

	for _, test := range []struct {
		name   string
		mutate func(*AuditEventRecord)
	}{
		{"EventID", func(event *AuditEventRecord) { event.EventID = "detached-event" }},
		{"stream", func(event *AuditEventRecord) { event.StreamID = "detached-stream" }},
		{"sequence", func(event *AuditEventRecord) { event.Sequence++ }},
		{"occurred", func(event *AuditEventRecord) { event.OccurredAtUnixNano++ }},
		{"first-link anchor", func(event *AuditEventRecord) { event.Head.DeploymentAnchorDigest[0] ^= 1 }},
		{"writer", func(event *AuditEventRecord) { event.Head.AuthorizedWriterIdentity = "spiffe://detached/writer" }},
		{"home region", func(event *AuditEventRecord) { event.Head.AuthorizedHomeRegion = "detached-region" }},
		{"writer epoch", func(event *AuditEventRecord) { event.Head.AuthorizedWriterEpoch++ }},
		{"record digest", func(event *AuditEventRecord) { event.RecordDigest[0] ^= 1 }},
		{"canonical payload", func(event *AuditEventRecord) { event.CanonicalEvent[0] ^= 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, _, _, driverInstance, uow := newBoundCanonicalUnit(t, receipt)
			event := exactOuterAuditRecord(uow, "receipt-event", 0)
			test.mutate(&event)
			driverInstance.mu.Lock()
			before := len(driverInstance.executions)
			driverInstance.mu.Unlock()
			if err := uow.AppendAuditEvent(ctx, event); !errors.Is(err, ErrCanonicalUOWPhase) {
				t.Fatalf("detached tuple error = %v", err)
			}
			driverInstance.mu.Lock()
			after := len(driverInstance.executions)
			driverInstance.mu.Unlock()
			if after != before {
				t.Fatalf("detached tuple issued SQL: before=%d after=%d", before, after)
			}
		})
	}
}

func TestCanonicalByteBudgetIsSharedAcrossEvidencePendingAndState(t *testing.T) {
	receipt, err := NewAdmissionUOWReceipt("application/cph.admission", []byte("budget"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, _, _, driverInstance, uow := newBoundCanonicalUnit(t, receipt)
	uow.bound.canonicalBytes = v2MaxUOWCanonicalBytes - 2
	setUnitQuery(driverInstance, selectDurableEvidenceForUpdateSQL,
		[]string{"evidence_kind", "content_type", "canonical_content", "audit_event_id"}, nil)
	if err := uow.ReserveDurableEvidence(ctx, DurableEvidenceRecord{
		Digest: [sha256.Size]byte{1}, Kind: DurableEvidenceContentSHA256,
		ContentType: "application/cph.evidence", CanonicalContent: []byte{1},
		ExpectedAuditEventID: "future-event",
	}); err != nil {
		t.Fatal(err)
	}
	if uow.bound.canonicalBytes != v2MaxUOWCanonicalBytes-1 {
		t.Fatalf("shared budget after evidence = %d", uow.bound.canonicalBytes)
	}
	err = uow.ApplyDurablePendingRevision(ctx, DurablePendingRevision{
		PendingKey: [ccse.MessageIDSize]byte{1}, Kind: DurablePendingMutation,
		Codec: DurablePendingIAMCodec, CodecVersion: 1, Revision: 1,
		EnvelopeDigest: [sha256.Size]byte{2}, CanonicalEnvelope: []byte{1, 2},
		Status: DurablePendingOpen, CommitNotBeforeUnixNano: 1,
		CommitNotAfterUnixNano: 2, ExpectedAuditEventID: "future-event",
	})
	if !errors.Is(err, ErrCanonicalInvalid) {
		t.Fatalf("cross-category budget error = %v", err)
	}

	finalReceipt, err := NewAuditedFinalUOWReceipt("application/cph.final", []byte("final"),
		"actual-event", 1)
	if err != nil {
		t.Fatal(err)
	}
	finalCtx, _, _, _, finalUOW := newBoundCanonicalUnit(t, finalReceipt)
	finalUOW.bound.canonicalBytes = v2MaxUOWCanonicalBytes - 1
	err = finalUOW.ApplyCanonicalStates(finalCtx, []CanonicalStateMutation{{Next: CanonicalStateRecord{
		Namespace: CanonicalStateIAM, Kind: CanonicalStateIAMIdentity, ObjectID: "identity-1",
		Version: 1, StateDigest: [sha256.Size]byte{3},
		ContentType: CanonicalStateIAMIdentityContentType, CanonicalState: []byte{1, 2},
		AuditEventID: "actual-event",
	}}})
	if !errors.Is(err, ErrCanonicalInvalid) {
		t.Fatalf("state shared budget error = %v", err)
	}
}

func TestCanonicalStateMutationsPermitOnlyExactOrderedSameKeyChains(t *testing.T) {
	receipt, err := NewAuditedFinalUOWReceipt("application/cph.final", []byte("final"),
		"chain-event", 1)
	if err != nil {
		t.Fatal(err)
	}
	expected := CanonicalStateRecord{Namespace: CanonicalStateIAM,
		Kind: CanonicalStateIAMPrincipalIdentityIndex, ObjectID: "principal-1", Version: 1,
		StateDigest: [sha256.Size]byte{1}, ContentType: CanonicalStateIAMPrincipalIdentityIndexContentType,
		CanonicalState: []byte("old-owner"), AuditEventID: "old-event"}
	intermediate := expected
	intermediate.Version = 2
	intermediate.StateDigest = [sha256.Size]byte{2}
	intermediate.CanonicalState = []byte("terminal-owner")
	intermediate.AuditEventID = "chain-event"
	next := intermediate
	next.Version = 3
	next.StateDigest = [sha256.Size]byte{3}
	next.CanonicalState = []byte("new-owner")

	chain := []CanonicalStateMutation{{Expected: &expected, Next: intermediate},
		{Expected: &intermediate, Next: next}}
	prepared, err := prepareCanonicalStateMutations(receipt, chain)
	if err != nil || len(prepared) != 2 ||
		!equalCanonicalStateRecords(*prepared[1].Expected, prepared[0].Next) {
		t.Fatalf("valid ordered chain=%+v err=%v", prepared, err)
	}
	broken := append([]CanonicalStateMutation(nil), chain...)
	broken[1].Expected = &expected
	if _, err := prepareCanonicalStateMutations(receipt, broken); !errors.Is(err, ErrCanonicalInvalid) {
		t.Fatalf("unchained duplicate error = %v", err)
	}

	ctx, _, _, driverInstance, uow := newBoundCanonicalUnit(t, receipt)
	if err := uow.ApplyCanonicalStates(ctx, chain); err != nil {
		t.Fatal(err)
	}
	third := next
	third.Version = 4
	third.StateDigest = [sha256.Size]byte{4}
	third.CanonicalState = []byte("settled-owner")
	if err := uow.ApplyCanonicalStates(ctx,
		[]CanonicalStateMutation{{Expected: &next, Next: third}}); err != nil {
		t.Fatalf("cross-call ordered continuation: %v", err)
	}
	driverInstance.mu.Lock()
	executions := append([]string(nil), driverInstance.executions...)
	driverInstance.mu.Unlock()
	updates, histories := 0, 0
	for _, execution := range executions {
		switch execution {
		case strings.TrimSpace(updateCanonicalStateHeadSQL):
			updates++
		case strings.TrimSpace(insertCanonicalStateHistorySQL):
			histories++
		}
	}
	if updates != 3 || histories != 3 || uow.bound.canonicalStateWrites != 3 ||
		!equalCanonicalStateRecords(uow.bound.canonicalStateHeads[canonicalStateRecordKey(third)], third) {
		t.Fatalf("ordered chain writes updates=%d histories=%d count=%d head=%+v", updates, histories,
			uow.bound.canonicalStateWrites, uow.bound.canonicalStateHeads[canonicalStateRecordKey(third)])
	}
}

func TestReconciliationPendingCASBindsExactOldKindRevisionAndDigest(t *testing.T) {
	receipt, err := NewAuditedFinalUOWReceipt("application/cph.failure", []byte("failed"),
		"failure-event", 1)
	if err != nil {
		t.Fatal(err)
	}
	previous := [sha256.Size]byte{1}
	revision := DurablePendingRevision{
		PendingKey: [ccse.MessageIDSize]byte{1}, ExpectedKind: DurablePendingOwnershipTransferCollection,
		Kind: DurablePendingReconciliation, Codec: DurablePendingIAMCodec, CodecVersion: 1,
		Revision: 2, PreviousEnvelopeDigest: previous, PreviousCanonicalEnvelope: []byte("open"),
		EnvelopeDigest:    [sha256.Size]byte{2},
		CanonicalEnvelope: []byte("failure"), Status: DurablePendingTerminal,
		CommitNotBeforeUnixNano: 1, CommitNotAfterUnixNano: 2,
		TerminalOutcomeDigest: receipt.ResultDigest(), ExpectedAuditEventID: "failure-event",
	}
	if _, err := preparePendingRevision(receipt, revision); err != nil {
		t.Fatalf("valid reconciliation rejected: %v", err)
	}
	invalid := revision
	invalid.ExpectedKind = DurablePendingGovernancePolicyApprovalCollection
	if _, err := preparePendingRevision(receipt, invalid); !errors.Is(err, ErrCanonicalUOWPhase) {
		t.Fatalf("invalid reconciliation source error = %v", err)
	}

	ctx, _, _, driverInstance, uow := newBoundCanonicalUnit(t, receipt)
	driverInstance.mu.Lock()
	driverInstance.rowsAffected = map[string]int64{strings.TrimSpace(updatePendingHeadSQL): 0}
	driverInstance.mu.Unlock()
	if err := uow.ApplyDurablePendingRevision(ctx, revision); !errors.Is(err, ErrCanonicalCASMismatch) {
		t.Fatalf("old-head mismatch error = %v", err)
	}
	driverInstance.mu.Lock()
	executions := append([]string(nil), driverInstance.executions...)
	args := append([]driver.NamedValue(nil), driverInstance.executionArgs[len(driverInstance.executionArgs)-1]...)
	driverInstance.mu.Unlock()
	if executions[len(executions)-1] != strings.TrimSpace(updatePendingHeadSQL) || len(args) != 25 ||
		args[16].Value != "1" || !bytes.Equal(args[17].Value.([]byte), previous[:]) ||
		args[18].Value != int64(DurablePendingOwnershipTransferCollection) ||
		!bytes.Equal(args[21].Value.([]byte), []byte("open")) || args[22].Value != false ||
		args[23].Value != int64(0) || args[24].Value != int64(0) {
		t.Fatalf("pending exact-CAS arguments = %#v", args)
	}
}

func TestOpenPendingAdvanceBindsExactPreviousWindow(t *testing.T) {
	receipt, err := NewAdmissionUOWReceipt("application/cph.admission", []byte("advance"))
	if err != nil {
		t.Fatal(err)
	}
	previous := [sha256.Size]byte{1}
	revision := DurablePendingRevision{
		PendingKey: [ccse.MessageIDSize]byte{1}, ExpectedKind: DurablePendingOwnershipTransferCollection,
		Kind: DurablePendingOwnershipTransferCollection, Codec: DurablePendingIAMCodec, CodecVersion: 1,
		Revision: 2, PreviousEnvelopeDigest: previous, PreviousCanonicalEnvelope: []byte("open-v1"),
		PreviousCommitNotBeforeUnixNano: 10, PreviousCommitNotAfterUnixNano: 20,
		EnvelopeDigest: [sha256.Size]byte{2}, CanonicalEnvelope: []byte("open-v2"),
		Status: DurablePendingOpen, CommitNotBeforeUnixNano: 11, CommitNotAfterUnixNano: 19,
		ExpectedAuditEventID: "future-event",
	}
	if _, err := preparePendingRevision(receipt, revision); err != nil {
		t.Fatalf("valid OPEN advance rejected: %v", err)
	}
	missingWindow := revision
	missingWindow.PreviousCommitNotBeforeUnixNano = 0
	missingWindow.PreviousCommitNotAfterUnixNano = 0
	if _, err := preparePendingRevision(receipt, missingWindow); !errors.Is(err, ErrCanonicalInvalid) {
		t.Fatalf("missing predecessor window error = %v", err)
	}

	ctx, _, _, driverInstance, uow := newBoundCanonicalUnit(t, receipt)
	if err := uow.ApplyDurablePendingRevision(ctx, revision); err != nil {
		t.Fatal(err)
	}
	driverInstance.mu.Lock()
	var updateArgs []driver.NamedValue
	for index, execution := range driverInstance.executions {
		if execution == strings.TrimSpace(updatePendingHeadSQL) {
			updateArgs = append([]driver.NamedValue(nil), driverInstance.executionArgs[index]...)
			break
		}
	}
	driverInstance.mu.Unlock()
	if len(updateArgs) != 25 || updateArgs[22].Value != true ||
		updateArgs[23].Value != int64(10) || updateArgs[24].Value != int64(20) {
		t.Fatalf("OPEN predecessor-window CAS args = %#v", updateArgs)
	}
}

func TestSuccessfulTerminalPreservesOpenSemanticEnvelope(t *testing.T) {
	receipt, err := NewAuditedFinalUOWReceipt("application/cph.success", []byte("done"),
		"success-event", 1)
	if err != nil {
		t.Fatal(err)
	}
	digest := [sha256.Size]byte{1}
	revision := DurablePendingRevision{
		PendingKey: [ccse.MessageIDSize]byte{1}, ExpectedKind: DurablePendingMutation,
		Kind: DurablePendingMutation, Codec: DurablePendingIAMCodec, CodecVersion: 1,
		Revision: 2, PreviousEnvelopeDigest: digest, PreviousCanonicalEnvelope: []byte("open-envelope"),
		EnvelopeDigest: digest, CanonicalEnvelope: []byte("open-envelope"),
		Status:                          DurablePendingTerminal,
		PreviousCommitNotBeforeUnixNano: 1, PreviousCommitNotAfterUnixNano: 2,
		CommitNotBeforeUnixNano: 1, CommitNotAfterUnixNano: 2,
		TerminalOutcomeDigest: receipt.ResultDigest(), ExpectedAuditEventID: "success-event",
	}
	prepared, err := preparePendingRevision(receipt, revision)
	if err != nil || prepared.EnvelopeDigest != prepared.PreviousEnvelopeDigest ||
		!bytes.Equal(prepared.CanonicalEnvelope, prepared.PreviousCanonicalEnvelope) {
		t.Fatalf("prepared lifecycle terminal=%+v err=%v", prepared, err)
	}
	changedDigest := revision
	changedDigest.EnvelopeDigest[0] ^= 1
	if _, err := preparePendingRevision(receipt, changedDigest); !errors.Is(err, ErrCanonicalInvalid) {
		t.Fatalf("changed terminal digest error = %v", err)
	}
	changedEnvelope := revision
	changedEnvelope.CanonicalEnvelope = []byte("invented-terminal-envelope")
	if _, err := preparePendingRevision(receipt, changedEnvelope); !errors.Is(err, ErrCanonicalInvalid) {
		t.Fatalf("changed terminal envelope error = %v", err)
	}
	missingCASBytes := revision
	missingCASBytes.PreviousCanonicalEnvelope = nil
	if _, err := preparePendingRevision(receipt, missingCASBytes); !errors.Is(err, ErrCanonicalInvalid) {
		t.Fatalf("missing exact prior envelope error = %v", err)
	}
	changedWindow := revision
	changedWindow.CommitNotAfterUnixNano++
	if _, err := preparePendingRevision(receipt, changedWindow); !errors.Is(err, ErrCanonicalInvalid) {
		t.Fatalf("changed lifecycle terminal window error = %v", err)
	}

	ctx, _, _, driverInstance, uow := newBoundCanonicalUnit(t, receipt)
	if err := uow.ApplyDurablePendingRevision(ctx, revision); err != nil {
		t.Fatal(err)
	}
	driverInstance.mu.Lock()
	var updateArgs []driver.NamedValue
	for index, execution := range driverInstance.executions {
		if execution == strings.TrimSpace(updatePendingHeadSQL) {
			updateArgs = append([]driver.NamedValue(nil), driverInstance.executionArgs[index]...)
			break
		}
	}
	driverInstance.mu.Unlock()
	if len(updateArgs) != 25 || updateArgs[22].Value != true ||
		updateArgs[23].Value != int64(1) || updateArgs[24].Value != int64(2) {
		t.Fatalf("lifecycle terminal exact-window CAS args = %#v", updateArgs)
	}
}

func TestCanonicalStateHistoryAndGovernanceTimelineAreExactAndOwned(t *testing.T) {
	receipt, err := NewAdmissionUOWReceipt("application/cph.admission", []byte("read"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, _, _, driverInstance, uow := newBoundCanonicalUnit(t, receipt)
	digest := [sha256.Size]byte{1}
	canonical := []byte("activation")
	setUnitQuery(driverInstance, selectCanonicalStateVersionSQL,
		[]string{"state_digest", "content_type", "canonical_state", "terminal",
			"valid_from_unix_nano", "valid_until_unix_nano", "audit_event_id"},
		[][]driver.Value{{digest[:], CanonicalStateGovernanceProfileActivationContentType,
			canonical, false, int64(10), int64(20), "activation-event"}})
	record, found, err := uow.LoadCanonicalStateVersion(ctx, CanonicalStateGovernance,
		CanonicalStateGovernanceProfileActivation, "profile-1", 1)
	if err != nil || !found || record.ValidFromUnixNano != 10 || record.ValidUntilUnixNano != 20 {
		t.Fatalf("history record=%+v found=%t err=%v", record, found, err)
	}
	record.CanonicalState[0] = 'X'
	if canonical[0] == 'X' {
		t.Fatal("history result aliases driver bytes")
	}

	setUnitQuery(driverInstance, selectActiveGovernanceProfileStateSQL,
		[]string{"object_id", "version", "state_digest", "content_type", "canonical_state",
			"terminal", "valid_from_unix_nano", "valid_until_unix_nano", "audit_event_id"},
		[][]driver.Value{{"profile-1", "1", digest[:],
			CanonicalStateGovernanceProfileActivationContentType, canonical, false,
			int64(10), int64(20), "activation-event"}})
	record, found, err = uow.LoadActiveGovernanceProfileState(ctx, 10)
	if err != nil || !found || record.ObjectID != "profile-1" || record.Version != 1 {
		t.Fatalf("active record=%+v found=%t err=%v", record, found, err)
	}

	ctx, _, _, driverInstance, uow = newBoundCanonicalUnit(t, receipt)
	setUnitQuery(driverInstance, selectActiveGovernanceProfileStateSQL,
		[]string{"object_id", "version", "state_digest", "content_type", "canonical_state",
			"terminal", "valid_from_unix_nano", "valid_until_unix_nano", "audit_event_id"},
		[][]driver.Value{
			{"profile-1", "1", digest[:], CanonicalStateGovernanceProfileActivationContentType,
				canonical, false, int64(10), int64(20), "activation-event"},
			{"profile-2", "1", []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				CanonicalStateGovernanceProfileActivationContentType, []byte("overlap"), false,
				int64(10), int64(20), "other-event"},
		})
	if _, _, err := uow.LoadActiveGovernanceProfileState(ctx, 15); !errors.Is(err, ErrCanonicalStateCorrupt) {
		t.Fatalf("ambiguous active timeline error = %v", err)
	}
}

func TestAssertDurablePendingOpenRequiresCompleteSnapshot(t *testing.T) {
	receipt, err := NewAdmissionUOWReceipt("application/cph.admission", []byte("read"))
	if err != nil {
		t.Fatal(err)
	}
	key := [ccse.MessageIDSize]byte{1}
	previous, current := [sha256.Size]byte{2}, [sha256.Size]byte{3}
	evidenceA, evidenceB := [sha256.Size]byte{4}, [sha256.Size]byte{5}
	base := DurablePendingRevision{PendingKey: key, Kind: DurablePendingOwnershipTransferCutover,
		Codec: DurablePendingIAMCodec, CodecVersion: 1, Revision: 2,
		PreviousEnvelopeDigest: previous, EnvelopeDigest: current,
		CanonicalEnvelope: []byte("exact-open-envelope"),
		EvidenceDigests:   [][sha256.Size]byte{evidenceA, evidenceB}, Status: DurablePendingOpen,
		CommitNotBeforeUnixNano: 10, CommitNotAfterUnixNano: 20,
		ExpectedAuditEventID: "future-event"}
	for _, test := range []struct {
		name   string
		mutate func(*DurablePendingRevision)
		ok     bool
	}{
		{name: "exact", ok: true},
		{name: "previous digest", mutate: func(value *DurablePendingRevision) {
			value.PreviousEnvelopeDigest = [sha256.Size]byte{9}
		}},
		{name: "window", mutate: func(value *DurablePendingRevision) {
			value.CommitNotAfterUnixNano++
		}},
		{name: "evidence set", mutate: func(value *DurablePendingRevision) {
			value.EvidenceDigests[1] = [sha256.Size]byte{6}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, _, _, driverInstance, uow := newBoundCanonicalUnit(t, receipt)
			setUnitQuery(driverInstance, selectPendingHeadForUpdateSQL,
				[]string{"pending_kind", "codec", "codec_version", "revision", "previous_envelope_digest",
					"envelope_digest", "canonical_envelope", "evidence_count", "status",
					"commit_not_before_unix_nano", "commit_not_after_unix_nano", "terminal_outcome_digest",
					"audit_event_id"}, [][]driver.Value{{int64(base.Kind), base.Codec, int64(base.CodecVersion), "2",
					base.PreviousEnvelopeDigest[:], base.EnvelopeDigest[:], base.CanonicalEnvelope, int64(2),
					int64(base.Status), base.CommitNotBeforeUnixNano, base.CommitNotAfterUnixNano, nil,
					base.ExpectedAuditEventID}})
			setUnitQuery(driverInstance, selectPendingEvidenceForUpdateSQL,
				[]string{"evidence_ordinal", "evidence_digest"}, [][]driver.Value{
					{int64(1), evidenceA[:]}, {int64(2), evidenceB[:]},
				})
			expected := base
			expected.CanonicalEnvelope = append([]byte(nil), base.CanonicalEnvelope...)
			expected.EvidenceDigests = append([][sha256.Size]byte(nil), base.EvidenceDigests...)
			if test.mutate != nil {
				test.mutate(&expected)
			}
			err := uow.AssertDurablePendingOpen(ctx, expected)
			if test.ok && err != nil {
				t.Fatal(err)
			}
			if !test.ok && !errors.Is(err, ErrCanonicalCASMismatch) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestReconciliationReloadRequiresExactImmutableSourceRevision(t *testing.T) {
	receipt, err := NewAdmissionUOWReceipt("application/cph.admission", []byte("read"))
	if err != nil {
		t.Fatal(err)
	}
	key := [ccse.MessageIDSize]byte{1}
	previous, current, outcome := [sha256.Size]byte{2}, [sha256.Size]byte{3}, [sha256.Size]byte{4}
	for _, test := range []struct {
		name       string
		sourceKind DurablePendingKind
		sourceHash [sha256.Size]byte
		wantError  bool
	}{
		{name: "exact", sourceKind: DurablePendingOwnershipTransferCutover, sourceHash: previous},
		{name: "wrong kind", sourceKind: DurablePendingGovernancePolicyApprovalCollection, sourceHash: previous, wantError: true},
		{name: "wrong digest", sourceKind: DurablePendingOwnershipTransferCutover, sourceHash: [sha256.Size]byte{9}, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, _, _, driverInstance, uow := newBoundCanonicalUnit(t, receipt)
			setUnitQuery(driverInstance, selectPendingHeadForUpdateSQL,
				[]string{"pending_kind", "codec", "codec_version", "revision", "previous_envelope_digest",
					"envelope_digest", "canonical_envelope", "evidence_count", "status",
					"commit_not_before_unix_nano", "commit_not_after_unix_nano", "terminal_outcome_digest",
					"audit_event_id"}, [][]driver.Value{{int64(DurablePendingReconciliation),
					DurablePendingIAMCodec, int64(1), "2", previous[:], current[:], []byte("failure"),
					int64(0), int64(DurablePendingTerminal), int64(1), int64(2), outcome[:], "failure-event"}})
			setUnitQuery(driverInstance, selectPendingEvidenceForUpdateSQL,
				[]string{"evidence_ordinal", "evidence_digest"}, nil)
			setUnitQuery(driverInstance, selectTerminalSourceRevisionSQL,
				[]string{"pending_kind", "codec", "codec_version", "status", "terminal_outcome_digest",
					"envelope_digest", "canonical_envelope", "commit_not_before_unix_nano",
					"commit_not_after_unix_nano", "audit_event_id"}, [][]driver.Value{{int64(test.sourceKind),
					DurablePendingIAMCodec, int64(1), int64(DurablePendingOpen), nil,
					test.sourceHash[:], []byte("open"), int64(1), int64(2), "failure-event"}})
			loaded, found, err := uow.LoadDurablePending(ctx, key)
			if test.wantError {
				if !errors.Is(err, ErrCanonicalStateCorrupt) || found || loaded.PendingKey != ([ccse.MessageIDSize]byte{}) {
					t.Fatalf("loaded=%+v found=%t err=%v", loaded, found, err)
				}
				return
			}
			if err != nil || !found || loaded.Kind != DurablePendingReconciliation ||
				loaded.PreviousEnvelopeDigest != previous {
				t.Fatalf("loaded=%+v found=%t err=%v", loaded, found, err)
			}
		})
	}
}

func TestLifecycleTerminalReloadRequiresExactImmutableSourceWindow(t *testing.T) {
	receipt, err := NewAdmissionUOWReceipt("application/cph.admission", []byte("read"))
	if err != nil {
		t.Fatal(err)
	}
	key := [ccse.MessageIDSize]byte{1}
	digest, outcome := [sha256.Size]byte{2}, [sha256.Size]byte{4}
	for _, test := range []struct {
		name            string
		sourceNotBefore int64
		sourceNotAfter  int64
		wantError       bool
	}{
		{name: "exact", sourceNotBefore: 10, sourceNotAfter: 20},
		{name: "changed not-before", sourceNotBefore: 11, sourceNotAfter: 20, wantError: true},
		{name: "changed not-after", sourceNotBefore: 10, sourceNotAfter: 21, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, _, _, driverInstance, uow := newBoundCanonicalUnit(t, receipt)
			setUnitQuery(driverInstance, selectPendingHeadForUpdateSQL,
				[]string{"pending_kind", "codec", "codec_version", "revision", "previous_envelope_digest",
					"envelope_digest", "canonical_envelope", "evidence_count", "status",
					"commit_not_before_unix_nano", "commit_not_after_unix_nano", "terminal_outcome_digest",
					"audit_event_id"}, [][]driver.Value{{int64(DurablePendingMutation),
					DurablePendingIAMCodec, int64(1), "2", digest[:], digest[:], []byte("open"),
					int64(0), int64(DurablePendingTerminal), int64(10), int64(20), outcome[:], "success-event"}})
			setUnitQuery(driverInstance, selectPendingEvidenceForUpdateSQL,
				[]string{"evidence_ordinal", "evidence_digest"}, nil)
			setUnitQuery(driverInstance, selectTerminalSourceRevisionSQL,
				[]string{"pending_kind", "codec", "codec_version", "status", "terminal_outcome_digest",
					"envelope_digest", "canonical_envelope", "commit_not_before_unix_nano",
					"commit_not_after_unix_nano", "audit_event_id"}, [][]driver.Value{{int64(DurablePendingMutation),
					DurablePendingIAMCodec, int64(1), int64(DurablePendingOpen), nil, digest[:], []byte("open"),
					test.sourceNotBefore, test.sourceNotAfter, "success-event"}})
			loaded, found, err := uow.LoadDurablePending(ctx, key)
			if test.wantError {
				if !errors.Is(err, ErrCanonicalStateCorrupt) || found {
					t.Fatalf("loaded=%+v found=%t err=%v", loaded, found, err)
				}
				return
			}
			if err != nil || !found || loaded.CommitNotBeforeUnixNano != 10 ||
				loaded.CommitNotAfterUnixNano != 20 {
				t.Fatalf("loaded=%+v found=%t err=%v", loaded, found, err)
			}
		})
	}
}

func TestCanonicalViewsUseLockedRowsAndReturnOwnedSnapshots(t *testing.T) {
	receipt, err := NewAdmissionUOWReceipt("application/cph.admission", []byte("read"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, _, _, driverInstance, uow := newBoundCanonicalUnit(t, receipt)

	setUnitQuery(driverInstance, selectGlobalHeadForUpdateSQL,
		[]string{"owner_domain", "owner_id", "version"}, [][]driver.Value{{
			string(globalid.OwnerIAMIdentity), "identity-1", "1",
		}})
	globalSnapshot, found, err := uow.LookupGlobalID(ctx, "identity-1")
	if err != nil || !found || globalSnapshot.Version != 1 {
		t.Fatalf("global snapshot=%+v found=%t err=%v", globalSnapshot, found, err)
	}

	binding := idempotency.Binding{Key: [ccse.MessageIDSize]byte{9},
		Domain: idempotency.OperationGovernanceAudit, OwnerID: "audit-owner",
		RequestDigest: [sha256.Size]byte{8}}
	bindingDigest, err := idempotency.BindingDigest(binding)
	if err != nil {
		t.Fatal(err)
	}
	outcome := [sha256.Size]byte{7}
	setUnitQuery(driverInstance, selectBusinessHeadForUpdateSQL,
		[]string{"row_kind", "operation_domain", "owner_id", "request_digest", "binding_digest",
			"parent_key", "parent_operation_domain", "parent_owner_id", "parent_request_digest",
			"state", "version", "progress_digest", "outcome_digest"}, [][]driver.Value{{
			int64(1), string(binding.Domain), binding.OwnerID, binding.RequestDigest[:], bindingDigest[:],
			nil, nil, nil, nil, int64(idempotency.StateCompleted), "1", nil, outcome[:],
		}})
	businessSnapshot, found, err := uow.LookupBusinessIdempotency(ctx, binding.Key)
	if err != nil || !found || businessSnapshot != (idempotency.Snapshot{Binding: binding,
		State: idempotency.StateCompleted, Version: 1, OutcomeDigest: outcome}) {
		t.Fatalf("business snapshot=%+v found=%t err=%v", businessSnapshot, found, err)
	}

	previous, envelopeDigest := [sha256.Size]byte{1}, [sha256.Size]byte{2}
	evidenceA, evidenceB := [sha256.Size]byte{3}, [sha256.Size]byte{4}
	setUnitQuery(driverInstance, selectPendingHeadForUpdateSQL,
		[]string{"pending_kind", "codec", "codec_version", "revision", "previous_envelope_digest",
			"envelope_digest", "canonical_envelope", "evidence_count", "status",
			"commit_not_before_unix_nano", "commit_not_after_unix_nano", "terminal_outcome_digest",
			"audit_event_id"}, [][]driver.Value{{int64(DurablePendingMutation), DurablePendingIAMCodec, int64(1), "2",
			previous[:], envelopeDigest[:], []byte("owned-envelope"), int64(2), int64(DurablePendingOpen),
			int64(1), int64(2), nil, "future-event"}})
	setUnitQuery(driverInstance, selectPendingEvidenceForUpdateSQL,
		[]string{"evidence_ordinal", "evidence_digest"}, [][]driver.Value{
			{int64(1), evidenceA[:]}, {int64(2), evidenceB[:]},
		})
	pending, found, err := uow.LoadDurablePending(ctx, binding.Key)
	if err != nil || !found || pending.Revision != 2 ||
		!bytes.Equal(pending.CanonicalEnvelope, []byte("owned-envelope")) || len(pending.EvidenceDigests) != 2 {
		t.Fatalf("pending=%+v found=%t err=%v", pending, found, err)
	}
	pending.CanonicalEnvelope[0] = 'X'
	if bytes.Equal(pending.CanonicalEnvelope, []byte("owned-envelope")) {
		t.Fatal("test failed to mutate returned detached envelope")
	}

	evidenceContent := []byte("owned-evidence")
	setUnitQuery(driverInstance, selectDurableEvidenceForUpdateSQL,
		[]string{"evidence_kind", "content_type", "canonical_content", "audit_event_id"},
		[][]driver.Value{{int64(DurableEvidenceSignedCCSERecord), "application/cph.ccse", evidenceContent, "future-event"}})
	evidence, found, err := uow.LoadDurableEvidence(ctx, evidenceA)
	if err != nil || !found || !bytes.Equal(evidence.CanonicalContent, evidenceContent) {
		t.Fatalf("evidence=%+v found=%t err=%v", evidence, found, err)
	}
	evidence.CanonicalContent[0] = 'X'
	if evidenceContent[0] == 'X' {
		t.Fatal("evidence result aliases fake-driver source")
	}
}

func TestAuditViewsReturnCompleteTransactionBoundSnapshot(t *testing.T) {
	receipt, err := NewAdmissionUOWReceipt("application/cph.admission", []byte("read"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, _, _, driverInstance, uow := newBoundCanonicalUnit(t, receipt)
	anchor, last, profile, lease := [sha256.Size]byte{1}, [sha256.Size]byte{2},
		[sha256.Size]byte{3}, [sha256.Size]byte{4}
	setUnitQuery(driverInstance, selectAuditHeadForUpdateSQL,
		[]string{"deployment_anchor_digest", "highest_sequence", "latest_record_digest",
			"audit_event_id", "head_writer_identity", "authorized_writer_identity",
			"home_region", "authorized_home_region", "writer_epoch", "authorized_writer_epoch",
			"head_governance_profile_digest", "authorized_governance_profile_digest",
			"writer_lease_evidence_digest", "writer_lease_not_before_unix_nano",
			"writer_lease_not_after_unix_nano"}, [][]driver.Value{{anchor[:], "7", last[:],
			"event-7", "writer", "writer", "region", "region", "9", "9",
			profile[:], profile[:], lease[:], int64(10), int64(20)}})
	head, found, err := uow.LoadAuditHead(ctx, "stream")
	if err != nil || !found || head.StreamID != "stream" || head.Sequence != 7 ||
		head.DeploymentAnchorDigest != anchor || head.LastRecordDigest != last ||
		head.HeadWriterIdentity != "writer" || head.AuthorizedWriterIdentity != "writer" ||
		head.HomeRegion != "region" || head.AuthorizedHomeRegion != "region" ||
		head.WriterEpoch != 9 || head.AuthorizedWriterEpoch != 9 ||
		head.HeadGovernanceProfileDigest != profile ||
		head.AuthorizedGovernanceProfileDigest != profile ||
		head.WriterLeaseEvidenceDigest != lease || head.WriterLeaseNotBeforeUnixNano != 10 ||
		head.WriterLeaseNotAfterUnixNano != 20 {
		t.Fatalf("audit head=%+v found=%t err=%v", head, found, err)
	}
	setUnitQuery(driverInstance, selectAuditEventForUpdateSQL,
		[]string{"stream_id", "audit_sequence", "record_digest"},
		[][]driver.Value{{"stream", "7", last[:]}})
	event, found, err := uow.LoadAuditEvent(ctx, "event-7")
	if err != nil || !found || event.EventID != "event-7" || event.StreamID != "stream" ||
		event.Sequence != 7 || event.RecordDigest != last {
		t.Fatalf("audit event=%+v found=%t err=%v", event, found, err)
	}
}

func TestPrepareCompoundMemberRequiresExactUmbrellaXY(t *testing.T) {
	parent := idempotency.Binding{Key: [ccse.MessageIDSize]byte{1},
		Domain: idempotency.OperationIAMOwnershipTransferCutover, OwnerID: "transfer-1",
		RequestDigest: [sha256.Size]byte{1}}
	member := idempotency.Binding{Key: [ccse.MessageIDSize]byte{2},
		Domain: idempotency.OperationIAMIdentity, OwnerID: "identity-1",
		RequestDigest: [sha256.Size]byte{2}}
	parentClaim, err := idempotency.NewReserveCollection(parent, [sha256.Size]byte{3})
	if err != nil {
		t.Fatal(err)
	}
	joined, err := idempotency.JoinedAuditBinding(parent)
	if err != nil {
		t.Fatal(err)
	}
	parentDigest, err := idempotency.BindingDigest(parent)
	if err != nil {
		t.Fatal(err)
	}
	joinedClaim, err := idempotency.NewReserveCollection(joined, parentDigest)
	if err != nil {
		t.Fatal(err)
	}
	memberClaim, err := idempotency.NewReserveCompoundMember(parent, member, [sha256.Size]byte{4})
	if err != nil {
		t.Fatal(err)
	}
	writes, err := prepareBusinessWrites(BusinessIdempotencyMutation{ExpectedAuditEventID: "future-event",
		Claims:          []idempotency.Claim{joinedClaim, parentClaim},
		CompoundMembers: []idempotency.CompoundMemberClaim{memberClaim}})
	if err != nil || len(writes) != 3 {
		t.Fatalf("prepared writes=%+v err=%v", writes, err)
	}
	kinds := map[int16]int{}
	for _, write := range writes {
		kinds[write.rowKind]++
	}
	if kinds[1] != 1 || kinds[2] != 1 || kinds[3] != 1 {
		t.Fatalf("row kinds = %v", kinds)
	}
	if _, err := prepareBusinessWrites(BusinessIdempotencyMutation{ExpectedAuditEventID: "future-event",
		Claims:          []idempotency.Claim{parentClaim},
		CompoundMembers: []idempotency.CompoundMemberClaim{memberClaim}}); !errors.Is(err, ErrCanonicalInvalid) {
		t.Fatalf("orphan compound member error = %v", err)
	}
}
