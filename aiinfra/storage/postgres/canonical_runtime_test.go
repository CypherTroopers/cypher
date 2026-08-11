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

func exactOuterAuditRecord(uow *CanonicalUOW, eventID string, eventDigest byte) AuditEventRecord {
	return AuditEventRecord{EventID: eventID, StreamID: "audit-stream", Sequence: 1,
		EventDigest: [sha256.Size]byte{eventDigest}, RecordDigest: uow.bound.outerRecordDigest,
		CanonicalEvent: bytes.Clone(uow.bound.outerCanonicalPayload), OccurredAtUnixNano: 1,
		Head: AuditHeadCAS{DeploymentAnchorDigest: [sha256.Size]byte{1},
			AuthorizedWriterIdentity: "spiffe://test/audit-writer", AuthorizedHomeRegion: "test-region",
			AuthorizedWriterEpoch: 1, AuthorizedGovernanceProfileDigest: [sha256.Size]byte{2},
			WriterLeaseEvidenceDigest: [sha256.Size]byte{3}, WriterLeaseNotBeforeUnixNano: 0,
			WriterLeaseNotAfterUnixNano: 2}}
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
		Kind: DurablePendingOwnershipTransferCollection,
		Codec: DurablePendingIAMCodec, CodecVersion: 1, Revision: 2,
		PreviousEnvelopeDigest: [sha256.Size]byte{7}, EnvelopeDigest: [sha256.Size]byte{8},
		CanonicalEnvelope: []byte("terminal-collection"), Status: DurablePendingTerminal,
		EvidenceDigests:         [][sha256.Size]byte{{12}},
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
