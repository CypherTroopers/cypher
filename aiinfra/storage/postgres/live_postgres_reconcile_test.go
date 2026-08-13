// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

// TestLivePostgresAuditedReconciliationAfterDeadline exercises the storage
// half of expired IAM reconciliation against a real PostgreSQL server. The
// workflow is random and retained in the disposable database so that catalog
// and evidence inspection can follow a successful run.
func TestLivePostgresAuditedReconciliationAfterDeadline(t *testing.T) {
	if os.Getenv(livePostgresDisposableEnv) != "YES" {
		t.Skip("set CPH_AIIE_POSTGRES_DISPOSABLE=YES to run the live PostgreSQL acceptance test")
	}
	ownerDSN, runtimeDSN := os.Getenv(livePostgresOwnerDSNEnv), os.Getenv(livePostgresRuntimeDSNEnv)
	if ownerDSN == "" || runtimeDSN == "" {
		t.Fatal("live PostgreSQL acceptance requires both owner and runtime DSNs")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	ownerDB := openLivePostgres(t, ctx, ownerDSN, "reconciliation owner")
	runtimeDB := openLivePostgres(t, ctx, runtimeDSN, "reconciliation runtime")
	if err := MigrateReplayStore(ctx, ownerDB); err != nil {
		t.Fatalf("owner migration: %v", err)
	}
	var runtimeRole string
	if err := runtimeDB.QueryRowContext(ctx, "SELECT current_user").Scan(&runtimeRole); err != nil {
		t.Fatal("read reconciliation runtime role")
	}
	if err := grantLivePostgresRuntimeACL(ctx, ownerDB, runtimeRole); err != nil {
		t.Fatalf("install exact runtime ACL: %v", err)
	}
	if err := VerifyReplayStore(ctx, runtimeDB); err != nil {
		t.Fatalf("runtime verification: %v", err)
	}
	store, err := NewReplayStore(ctx, runtimeDB)
	if err != nil {
		t.Fatalf("construct runtime replay store: %v", err)
	}

	nonce := livePostgresNonce(t)
	suffix := fmt.Sprintf("%x", nonce[:])
	parent := idempotency.Binding{
		Key:           nonce,
		Domain:        idempotency.OperationIAMIdentity,
		OwnerID:       "live-reconciliation-identity-" + suffix,
		RequestDigest: liveReconciliationDigest("request/" + suffix),
	}
	joined, err := idempotency.JoinedAuditBinding(parent)
	if err != nil {
		t.Fatal(err)
	}
	eventID, err := idempotency.JoinedAuditEventID(parent)
	if err != nil {
		t.Fatal(err)
	}
	eventOwner := globalid.Owner{Domain: globalid.OwnerGovernanceAuditEvent, ID: eventID}
	parentProgress := liveReconciliationDigest("progress/" + suffix)
	parentClaim, err := idempotency.NewReserveCollection(parent, parentProgress)
	if err != nil {
		t.Fatal(err)
	}
	parentBindingDigest, err := idempotency.BindingDigest(parent)
	if err != nil {
		t.Fatal(err)
	}
	joinedClaim, err := idempotency.NewReserveCollection(joined, parentBindingDigest)
	if err != nil {
		t.Fatal(err)
	}
	eventClaim, err := globalid.Reserve(eventID, eventOwner)
	if err != nil {
		t.Fatal(err)
	}

	sourceEvidence := []DurableEvidenceRecord{
		liveReconciliationEvidence("source-authorization/"+suffix, eventID),
		liveReconciliationEvidence("source-policy/"+suffix, eventID),
	}
	sort.Slice(sourceEvidence, func(i, j int) bool {
		return bytes.Compare(sourceEvidence[i].Digest[:], sourceEvidence[j].Digest[:]) < 0
	})
	sourceEvidenceDigests := []([sha256.Size]byte){sourceEvidence[0].Digest, sourceEvidence[1].Digest}
	sourceEnvelope := []byte("canonical-live-reconciliation-source-v1/" + suffix)
	sourceEnvelopeDigest := sha256.Sum256(sourceEnvelope)
	admissionEntry, admissionVerified := livePostgresVerifiedInput(t, livePostgresNonce(t))
	admissionReceipt, err := NewAdmissionUOWReceipt(
		"application/cph.aiinfra.live-reconciliation-admission.v1",
		[]byte("live-reconciliation-admitted/"+suffix))
	if err != nil {
		t.Fatal(err)
	}

	var sourceRevision DurablePendingRevision
	admission, err := store.Execute(ctx, admissionEntry, admissionVerified,
		func(txCtx context.Context, exact ccse.VerifiedRecord) ([sha256.Size]byte, error) {
			transaction, ok := Transaction(txCtx)
			if !ok {
				return [sha256.Size]byte{}, ErrTransactionRequired
			}
			uow, openErr := OpenCanonicalUOW(txCtx, exact, CanonicalAdmission, "", 0)
			if openErr != nil {
				return [sha256.Size]byte{}, openErr
			}
			if assertErr := uow.AssertOuterVerifiedRecord(txCtx, exact); assertErr != nil {
				return [sha256.Size]byte{}, assertErr
			}
			clock, clockErr := uow.SnapshotTransactionClock(txCtx)
			if clockErr != nil {
				return [sha256.Size]byte{}, clockErr
			}
			if bindErr := uow.BindResult(txCtx, admissionReceipt); bindErr != nil {
				return [sha256.Size]byte{}, bindErr
			}
			if applyErr := uow.ApplyBusinessIdempotency(txCtx, BusinessIdempotencyMutation{
				ExpectedAuditEventID: eventID,
				Claims:               []idempotency.Claim{parentClaim, joinedClaim},
			}); applyErr != nil {
				return [sha256.Size]byte{}, applyErr
			}
			if applyErr := uow.ApplyGlobalClaims(txCtx, GlobalClaimMutation{
				AuditEventID: eventID, Claims: []globalid.Claim{eventClaim},
			}); applyErr != nil {
				return [sha256.Size]byte{}, applyErr
			}
			for _, evidence := range sourceEvidence {
				if reserveErr := uow.ReserveDurableEvidence(txCtx, evidence); reserveErr != nil {
					return [sha256.Size]byte{}, reserveErr
				}
			}
			sourceRevision = DurablePendingRevision{
				PendingKey:              parent.Key,
				Kind:                    DurablePendingMutation,
				Codec:                   DurablePendingIAMCodec,
				CodecVersion:            1,
				Revision:                1,
				EnvelopeDigest:          sourceEnvelopeDigest,
				CanonicalEnvelope:       bytes.Clone(sourceEnvelope),
				EvidenceDigests:         append([][sha256.Size]byte(nil), sourceEvidenceDigests...),
				Status:                  DurablePendingOpen,
				CommitNotBeforeUnixNano: clock.ObservedAtUnixNano() - int64(time.Second),
				CommitNotAfterUnixNano:  clock.ObservedAtUnixNano() + int64(3*time.Second),
				ExpectedAuditEventID:    eventID,
			}
			if applyErr := uow.ApplyDurablePendingRevision(txCtx, sourceRevision); applyErr != nil {
				return [sha256.Size]byte{}, applyErr
			}
			if deadlineErr := uow.AssertCommitDeadline(txCtx,
				sourceRevision.CommitNotAfterUnixNano); deadlineErr != nil {
				return [sha256.Size]byte{}, deadlineErr
			}
			return transaction.Complete(txCtx, livePostgresCompletion(admissionReceipt))
		})
	if err != nil {
		t.Fatalf("commit reconciliation source admission: %v", err)
	}
	if admission.Status != ccse.ReplayApplied || admission.OutcomeDigest != admissionReceipt.ResultDigest() {
		t.Fatalf("source admission decision=%+v", admission)
	}

	auditOccurredAt := waitForLiveReconciliationDeadline(t, ctx, runtimeDB,
		sourceRevision.CommitNotAfterUnixNano)
	if auditOccurredAt < sourceRevision.CommitNotAfterUnixNano {
		t.Fatal("database clock did not cross the admitted half-open deadline")
	}
	reconciliationEvidence := liveReconciliationEvidence(fmt.Sprintf(
		"expired-clock/source=%x/deadline=%d/observed=%d/%s",
		sourceRevision.EnvelopeDigest, sourceRevision.CommitNotAfterUnixNano, auditOccurredAt, suffix), eventID)
	terminalEvidenceDigests := append([][sha256.Size]byte(nil), sourceEvidenceDigests...)
	terminalEvidenceDigests = append(terminalEvidenceDigests, reconciliationEvidence.Digest)
	sort.Slice(terminalEvidenceDigests, func(i, j int) bool {
		return bytes.Compare(terminalEvidenceDigests[i][:], terminalEvidenceDigests[j][:]) < 0
	})
	reconciliationEnvelope := []byte(fmt.Sprintf(
		"canonical-live-reconciliation-terminal-v1/source=%x/deadline=%d/evidence=%x/%s",
		sourceRevision.EnvelopeDigest, sourceRevision.CommitNotAfterUnixNano,
		reconciliationEvidence.Digest, suffix))
	reconciliationEnvelopeDigest := sha256.Sum256(reconciliationEnvelope)

	auditNonce := livePostgresNonce(t)
	auditStream := "cph.test.postgres-live-reconciliation.audit." + suffix
	correlationDigest := sha256.Sum256(append([]byte("live-reconciliation-correlation:"), nonce[:]...))
	var correlationID [ccse.MessageIDSize]byte
	copy(correlationID[:], correlationDigest[:ccse.MessageIDSize])
	policyDigest := liveReconciliationDigest("audit-policy/" + suffix)
	deploymentAnchor := liveReconciliationDigest("audit-anchor/" + suffix)
	profileDigest := liveReconciliationDigest("audit-profile/" + suffix)
	leaseDigest := liveReconciliationDigest("audit-writer-lease/" + suffix)
	auditProjection := foundationv1.AuditEventSigningProjection{
		Metadata: foundationv1.RecordMetadataSigningProjection{
			SchemaVersion:       foundationv1.SchemaVersionSigningProjection{Major: 1},
			RecordID:            eventID,
			CreatedAtUnixNano:   auditOccurredAt,
			IntegrityDigest:     liveReconciliationDigest("audit-integrity/" + suffix),
			HomeRegion:          "live-reconciliation-region",
			WriterEpoch:         1,
			StateVersion:        1,
			IdempotencyKey:      joined.Key,
			PolicyDigestsSHA256: [][sha256.Size]byte{policyDigest},
		},
		AuditEventID:               eventID,
		EventType:                  "IAMPendingReconciled",
		ActorIdentity:              "spiffe://test/postgres-live-reconciler",
		ActorKeyID:                 "live-postgres-reconciler-key",
		SubjectIDs:                 []string{parent.OwnerID},
		CauseCode:                  "commit-deadline-expired",
		CorrelationID:              correlationID,
		OccurredAtUnixNano:         auditOccurredAt,
		Outcome:                    4,
		AppliedPolicyDigestsSHA256: [][sha256.Size]byte{policyDigest},
		EvidenceDigestsSHA256:      append([][sha256.Size]byte(nil), terminalEvidenceDigests...),
		PreviousEventDigestSHA256:  deploymentAnchor,
		AuditSequence:              1,
	}
	auditPayload, err := auditProjection.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	finalEntry, finalVerified := liveReconciliationAuditInput(t, auditNonce, auditStream,
		correlationID, auditOccurredAt, auditPayload)
	finalPayload := []byte(fmt.Sprintf("live-reconciliation-result-v1/source=%x/observed=%d/%s",
		sourceRevision.EnvelopeDigest, auditOccurredAt, suffix))
	finalReceipt, err := NewAuditedFinalUOWReceipt(
		"application/cph.aiinfra.live-reconciliation-result.v1", finalPayload, eventID,
		uint16(len(terminalEvidenceDigests)))
	if err != nil {
		t.Fatal(err)
	}

	finalDecision, err := store.Execute(ctx, finalEntry, finalVerified,
		func(txCtx context.Context, exact ccse.VerifiedRecord) ([sha256.Size]byte, error) {
			transaction, ok := Transaction(txCtx)
			if !ok {
				return [sha256.Size]byte{}, ErrTransactionRequired
			}
			uow, openErr := OpenCanonicalUOW(txCtx, exact, CanonicalAuditedFinal,
				eventID, uint16(len(terminalEvidenceDigests)))
			if openErr != nil {
				return [sha256.Size]byte{}, openErr
			}
			if assertErr := uow.AssertOuterVerifiedRecord(txCtx, exact); assertErr != nil {
				return [sha256.Size]byte{}, assertErr
			}
			clock, clockErr := uow.SnapshotTransactionClock(txCtx)
			if clockErr != nil {
				return [sha256.Size]byte{}, clockErr
			}
			if clock.ObservedAtUnixNano() < sourceRevision.CommitNotAfterUnixNano ||
				clock.ObservedAtUnixNano() < auditProjection.OccurredAtUnixNano {
				return [sha256.Size]byte{}, fmt.Errorf("reconciliation transaction clock precedes expiry")
			}
			parentSnapshot, parentFound, joinedSnapshot, joinedFound, snapshotErr :=
				uow.SnapshotBusinessIdempotencyPair(txCtx, parent.Key, joined.Key)
			if snapshotErr != nil {
				return [sha256.Size]byte{}, snapshotErr
			}
			if !parentFound || !joinedFound || parentSnapshot.State != idempotency.StateCollecting ||
				joinedSnapshot.State != idempotency.StateCollecting || parentSnapshot.Version != 1 ||
				joinedSnapshot.Version != 1 || parentSnapshot.ProgressDigest != parentProgress ||
				joinedSnapshot.ProgressDigest != parentBindingDigest {
				return [sha256.Size]byte{}, fmt.Errorf("reconciliation source X/Y differs")
			}
			globalSnapshot, globalFound, lookupErr := uow.LookupGlobalID(txCtx, eventID)
			if lookupErr != nil {
				return [sha256.Size]byte{}, lookupErr
			}
			if !globalFound || globalSnapshot.Owner != eventOwner || globalSnapshot.Version != 1 {
				return [sha256.Size]byte{}, fmt.Errorf("reconciliation source global identifier differs")
			}
			loadedSource, pendingFound, loadErr := uow.LoadDurablePending(txCtx, parent.Key)
			if loadErr != nil {
				return [sha256.Size]byte{}, loadErr
			}
			if !pendingFound || !equalLiveReconciliationPending(loadedSource, sourceRevision) {
				return [sha256.Size]byte{}, fmt.Errorf("reconciliation source pending differs")
			}
			if assertErr := uow.AssertDurablePendingOpen(txCtx, loadedSource); assertErr != nil {
				return [sha256.Size]byte{}, assertErr
			}
			for _, expected := range sourceEvidence {
				loaded, found, evidenceErr := uow.LoadDurableEvidence(txCtx, expected.Digest)
				if evidenceErr != nil {
					return [sha256.Size]byte{}, evidenceErr
				}
				if !found || !equalLiveReconciliationEvidence(loaded, expected) {
					return [sha256.Size]byte{}, fmt.Errorf("reconciliation source evidence differs")
				}
				if assertErr := uow.AssertDurableEvidenceContent(txCtx, loaded); assertErr != nil {
					return [sha256.Size]byte{}, assertErr
				}
			}
			if bindErr := uow.BindResult(txCtx, finalReceipt); bindErr != nil {
				return [sha256.Size]byte{}, bindErr
			}
			parentComplete, completeErr := idempotency.NewCompleteCollection(parentSnapshot)
			if completeErr != nil {
				return [sha256.Size]byte{}, completeErr
			}
			joinedComplete, completeErr := idempotency.NewCompleteCollection(joinedSnapshot)
			if completeErr != nil {
				return [sha256.Size]byte{}, completeErr
			}
			if applyErr := uow.ApplyBusinessIdempotency(txCtx, BusinessIdempotencyMutation{
				ExpectedAuditEventID: eventID,
				OutcomeDigest:        finalReceipt.ResultDigest(),
				Claims:               []idempotency.Claim{parentComplete, joinedComplete},
			}); applyErr != nil {
				return [sha256.Size]byte{}, applyErr
			}
			globalAssert, assertErr := globalid.Assert(eventID, globalSnapshot, eventOwner)
			if assertErr != nil {
				return [sha256.Size]byte{}, assertErr
			}
			if applyErr := uow.ApplyGlobalClaims(txCtx, GlobalClaimMutation{
				AuditEventID: eventID, Claims: []globalid.Claim{globalAssert},
			}); applyErr != nil {
				return [sha256.Size]byte{}, applyErr
			}
			if reserveErr := uow.ReserveDurableEvidence(txCtx, reconciliationEvidence); reserveErr != nil {
				return [sha256.Size]byte{}, reserveErr
			}
			terminal := DurablePendingRevision{
				PendingKey:                parent.Key,
				ExpectedKind:              DurablePendingMutation,
				Kind:                      DurablePendingReconciliation,
				Codec:                     DurablePendingIAMCodec,
				CodecVersion:              1,
				Revision:                  2,
				PreviousEnvelopeDigest:    sourceRevision.EnvelopeDigest,
				PreviousCanonicalEnvelope: bytes.Clone(sourceRevision.CanonicalEnvelope),
				EnvelopeDigest:            reconciliationEnvelopeDigest,
				CanonicalEnvelope:         bytes.Clone(reconciliationEnvelope),
				EvidenceDigests:           append([][sha256.Size]byte(nil), terminalEvidenceDigests...),
				Status:                    DurablePendingTerminal,
				CommitNotBeforeUnixNano:   sourceRevision.CommitNotAfterUnixNano,
				CommitNotAfterUnixNano:    auditProjection.OccurredAtUnixNano + int64(5*time.Minute),
				TerminalOutcomeDigest:     finalReceipt.ResultDigest(),
				ExpectedAuditEventID:      eventID,
			}
			if applyErr := uow.ApplyDurablePendingRevision(txCtx, terminal); applyErr != nil {
				return [sha256.Size]byte{}, applyErr
			}
			envelope := exact.Envelope()
			audit := AuditEventRecord{
				EventID:            eventID,
				StreamID:           auditStream,
				Sequence:           1,
				EventDigest:        envelope.PayloadDigest,
				RecordDigest:       exact.Digest(),
				CanonicalEvent:     exact.Payload(),
				OccurredAtUnixNano: auditProjection.OccurredAtUnixNano,
				Head: AuditHeadCAS{
					DeploymentAnchorDigest:            deploymentAnchor,
					AuthorizedWriterIdentity:          exact.Domain().SenderIdentity,
					AuthorizedHomeRegion:              auditProjection.Metadata.HomeRegion,
					AuthorizedWriterEpoch:             auditProjection.Metadata.WriterEpoch,
					AuthorizedGovernanceProfileDigest: profileDigest,
					WriterLeaseEvidenceDigest:         leaseDigest,
					WriterLeaseNotBeforeUnixNano:      auditProjection.OccurredAtUnixNano - int64(time.Minute),
					WriterLeaseNotAfterUnixNano:       auditProjection.OccurredAtUnixNano + int64(10*time.Minute),
				},
			}
			if appendErr := uow.AppendAuditEvent(txCtx, audit); appendErr != nil {
				return [sha256.Size]byte{}, appendErr
			}
			assertions := make([]EvidenceAssertion, len(terminalEvidenceDigests))
			for index, digest := range terminalEvidenceDigests {
				assertions[index] = EvidenceAssertion{EvidenceDigest: digest, HasPending: true,
					PendingKey: parent.Key, PendingRevision: 2}
			}
			if assertErr := uow.AssertDurableEvidence(txCtx, assertions); assertErr != nil {
				return [sha256.Size]byte{}, assertErr
			}
			if deadlineErr := uow.AssertCommitDeadline(txCtx,
				terminal.CommitNotAfterUnixNano); deadlineErr != nil {
				return [sha256.Size]byte{}, deadlineErr
			}
			return transaction.Complete(txCtx, livePostgresCompletion(finalReceipt))
		})
	if err != nil {
		t.Fatalf("commit audited reconciliation: %v", err)
	}
	if finalDecision.Status != ccse.ReplayApplied ||
		finalDecision.OutcomeDigest != finalReceipt.ResultDigest() {
		t.Fatalf("audited reconciliation decision=%+v", finalDecision)
	}

	durableResult, err := store.LoadDurableResult(ctx, finalEntry, finalReceipt.ResultDigest())
	if err != nil {
		t.Fatalf("load reconciliation result: %v", err)
	}
	if durableResult.ContentType != finalReceipt.ResultContentType() ||
		!bytes.Equal(durableResult.Payload, finalReceipt.ResultPayload()) ||
		DurableResultDigest(durableResult.ContentType, durableResult.Payload) != finalReceipt.ResultDigest() {
		t.Fatal("reconciliation durable result bytes or digest differ")
	}
	duplicateCalled := false
	duplicate, err := store.Execute(ctx, finalEntry, finalVerified,
		func(context.Context, ccse.VerifiedRecord) ([sha256.Size]byte, error) {
			duplicateCalled = true
			return [sha256.Size]byte{}, errors.New("reconciliation duplicate handler invoked")
		})
	if err != nil {
		t.Fatalf("reconciliation duplicate: %v", err)
	}
	if duplicateCalled || duplicate.Status != ccse.ReplayDuplicateCompleted ||
		duplicate.OutcomeDigest != finalReceipt.ResultDigest() {
		t.Fatalf("reconciliation duplicate=%+v handler_called=%t", duplicate, duplicateCalled)
	}

	reloadEntry, reloadVerified := livePostgresVerifiedInput(t, livePostgresNonce(t))
	reloadReceipt, err := NewAdmissionUOWReceipt(
		"application/cph.aiinfra.live-reconciliation-reload.v1",
		[]byte("live-reconciliation-reloaded/"+suffix))
	if err != nil {
		t.Fatal(err)
	}
	reload, err := store.Execute(ctx, reloadEntry, reloadVerified,
		func(txCtx context.Context, exact ccse.VerifiedRecord) ([sha256.Size]byte, error) {
			transaction, ok := Transaction(txCtx)
			if !ok {
				return [sha256.Size]byte{}, ErrTransactionRequired
			}
			uow, bindErr := BindCanonicalUOW(txCtx, exact, reloadReceipt)
			if bindErr != nil {
				return [sha256.Size]byte{}, bindErr
			}
			parentSnapshot, parentFound, joinedSnapshot, joinedFound, snapshotErr :=
				uow.SnapshotBusinessIdempotencyPair(txCtx, parent.Key, joined.Key)
			if snapshotErr != nil {
				return [sha256.Size]byte{}, snapshotErr
			}
			if !parentFound || !joinedFound || parentSnapshot.State != idempotency.StateCompleted ||
				joinedSnapshot.State != idempotency.StateCompleted ||
				parentSnapshot.OutcomeDigest != finalReceipt.ResultDigest() ||
				joinedSnapshot.OutcomeDigest != finalReceipt.ResultDigest() {
				return [sha256.Size]byte{}, fmt.Errorf("reloaded terminal X/Y differs")
			}
			pending, found, loadErr := uow.LoadDurablePending(txCtx, parent.Key)
			if loadErr != nil {
				return [sha256.Size]byte{}, loadErr
			}
			if !found || pending.Kind != DurablePendingReconciliation || pending.Revision != 2 ||
				pending.PreviousEnvelopeDigest != sourceRevision.EnvelopeDigest ||
				pending.EnvelopeDigest != reconciliationEnvelopeDigest ||
				!bytes.Equal(pending.CanonicalEnvelope, reconciliationEnvelope) ||
				pending.Status != DurablePendingTerminal ||
				pending.TerminalOutcomeDigest != finalReceipt.ResultDigest() ||
				!equalLiveReconciliationDigests(pending.EvidenceDigests, terminalEvidenceDigests) {
				return [sha256.Size]byte{}, fmt.Errorf("reloaded kind-4 terminal differs")
			}
			for _, expected := range append(sourceEvidence, reconciliationEvidence) {
				loaded, evidenceFound, evidenceErr := uow.LoadDurableEvidence(txCtx, expected.Digest)
				if evidenceErr != nil {
					return [sha256.Size]byte{}, evidenceErr
				}
				if !evidenceFound || !equalLiveReconciliationEvidence(loaded, expected) {
					return [sha256.Size]byte{}, fmt.Errorf("reloaded reconciliation evidence differs")
				}
			}
			globalSnapshot, globalFound, lookupErr := uow.LookupGlobalID(txCtx, eventID)
			if lookupErr != nil {
				return [sha256.Size]byte{}, lookupErr
			}
			if !globalFound || globalSnapshot.Owner != eventOwner || globalSnapshot.Version != 1 {
				return [sha256.Size]byte{}, fmt.Errorf("reloaded reconciliation global identifier differs")
			}
			auditEvent, eventFound, auditErr := uow.LoadAuditEvent(txCtx, eventID)
			if auditErr != nil {
				return [sha256.Size]byte{}, auditErr
			}
			if !eventFound || auditEvent.StreamID != auditStream || auditEvent.Sequence != 1 ||
				auditEvent.RecordDigest != finalVerified.Digest() {
				return [sha256.Size]byte{}, fmt.Errorf("reloaded reconciliation AuditEvent differs")
			}
			auditHead, headFound, headErr := uow.LoadAuditHead(txCtx, auditStream)
			if headErr != nil {
				return [sha256.Size]byte{}, headErr
			}
			if !headFound || auditHead.Sequence != 1 || auditHead.AuditEventID != eventID ||
				auditHead.LastRecordDigest != finalVerified.Digest() {
				return [sha256.Size]byte{}, fmt.Errorf("reloaded reconciliation audit head differs")
			}
			return transaction.Complete(txCtx, livePostgresCompletion(reloadReceipt))
		})
	if err != nil {
		t.Fatalf("reload reconciled workflow: %v", err)
	}
	if reload.Status != ccse.ReplayApplied || reload.OutcomeDigest != reloadReceipt.ResultDigest() {
		t.Fatalf("reconciliation reload decision=%+v", reload)
	}

	assertLiveReconciliationRows(t, ctx, runtimeDB, parent.Key, eventID,
		finalEntry, len(terminalEvidenceDigests))
}

func liveReconciliationDigest(value string) [sha256.Size]byte {
	return sha256.Sum256([]byte(value))
}

func liveReconciliationEvidence(value, eventID string) DurableEvidenceRecord {
	canonical := []byte(value)
	return DurableEvidenceRecord{Digest: sha256.Sum256(canonical),
		Kind: DurableEvidenceSemanticReceipt, ContentType: "application/cph.aiinfra.live-evidence.v1",
		CanonicalContent: canonical, ExpectedAuditEventID: eventID}
}

func waitForLiveReconciliationDeadline(t *testing.T, ctx context.Context, database *sql.DB,
	deadline int64) int64 {
	t.Helper()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		var observed int64
		if err := database.QueryRowContext(ctx, `
			SELECT (EXTRACT(EPOCH FROM observed_at) * 1000000000)::bigint
			FROM (SELECT pg_catalog.clock_timestamp() AS observed_at) observation`).Scan(&observed); err != nil {
			t.Fatalf("observe PostgreSQL reconciliation deadline: %v", err)
		}
		if observed >= deadline {
			return observed
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for PostgreSQL reconciliation deadline: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}

func liveReconciliationAuditInput(t *testing.T, nonce [ccse.MessageIDSize]byte,
	replayDomain string, correlationID [ccse.MessageIDSize]byte, issuedAtUnixNano int64,
	payload []byte) (ccse.ReplayEntry, ccse.VerifiedRecord) {
	t.Helper()
	protocolVersion, schemaVersion := ccse.Version{Major: 1}, ccse.Version{Major: 1}
	issuedAt := time.Unix(0, issuedAtUnixNano).UTC()
	expiresAt := issuedAt.Add(15 * time.Minute)
	suffix := fmt.Sprintf("%x", nonce[:])
	seed := sha256.Sum256(append([]byte("cph-live-reconciliation-audit-key:"), nonce[:]...))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	chainID := liveReconciliationDigest("chain/" + suffix)
	genesisHash := liveReconciliationDigest("genesis/" + suffix)
	domain := ccse.Domain{
		Purpose:            "cph.test.postgres-live-reconciliation",
		SenderIdentity:     "spiffe://test/postgres-live-reconciler/" + suffix,
		Audience:           []string{"cph.test.receiver"},
		ChainID:            chainID,
		GenesisHash:        genesisHash,
		Environment:        "test",
		ProtocolVersion:    protocolVersion,
		SchemaVersion:      schemaVersion,
		SignatureAlgorithm: ccse.SignatureAlgorithmEd25519,
		SignatureKeyID:     "live-reconciliation-key-" + suffix,
		IssuedAtUnixNano:   issuedAt.UnixNano(),
		ExpiresAtUnixNano:  expiresAt.UnixNano(),
		CounterKind:        ccse.CounterSequence,
		Counter:            1,
		ReplayDomainID:     replayDomain,
	}
	envelope := ccse.Envelope{
		ProtocolVersion:    protocolVersion,
		SchemaVersion:      schemaVersion,
		MessageID:          nonce,
		CorrelationID:      correlationID,
		SenderIdentity:     domain.SenderIdentity,
		ChainID:            chainID,
		Environment:        domain.Environment,
		IssuedAtUnixNano:   domain.IssuedAtUnixNano,
		ExpiresAtUnixNano:  domain.ExpiresAtUnixNano,
		CounterKind:        domain.CounterKind,
		Counter:            domain.Counter,
		SignatureAlgorithm: domain.SignatureAlgorithm,
		SignatureKeyID:     domain.SignatureKeyID,
	}
	record, err := ccse.NewRecord(schema.MessageTypeAuditEvent, schemaVersion, domain, envelope, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := record.SignEd25519(privateKey, ccse.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	keys := ccse.NewMemoryKeyRegistry()
	if err := keys.Add(ccse.KeyRecord{
		KeyID:               domain.SignatureKeyID,
		SubjectIdentity:     domain.SenderIdentity,
		Algorithm:           ccse.SignatureAlgorithmEd25519,
		PublicKey:           publicKey,
		NotBeforeUnixNano:   issuedAt.Add(-time.Minute).UnixNano(),
		NotAfterUnixNano:    expiresAt.Add(time.Minute).UnixNano(),
		AllowedMessageTypes: []uint32{schema.MessageTypeAuditEvent},
	}); err != nil {
		t.Fatal(err)
	}
	capture := new(captureReplayStore)
	verifier := ccse.Verifier{
		Expectations: ccse.Expectations{
			MessageTypeID:     schema.MessageTypeAuditEvent,
			SchemaVersion:     schemaVersion,
			ProtocolVersion:   protocolVersion,
			Purpose:           domain.Purpose,
			SenderIdentity:    ccse.OptionalString{Present: true, Value: domain.SenderIdentity},
			Audience:          domain.Audience,
			Environment:       domain.Environment,
			ChainID:           chainID,
			GenesisHash:       genesisHash,
			ReplayDomainID:    domain.ReplayDomainID,
			CounterKind:       domain.CounterKind,
			MaxValidityWindow: 20 * time.Minute,
		},
		Limits: ccse.DefaultLimits(),
		Clock:  ccse.ClockFunc(func() time.Time { return issuedAt.Add(time.Second) }),
		Keys:   keys,
		Replay: capture,
		Schema: ccse.SchemaValidatorFuncs{
			Payload:    func(context.Context, uint32, ccse.Version, []byte) error { return nil },
			Extensions: func(context.Context, uint32, ccse.Version, []ccse.Extension) error { return nil },
		},
		Handle: func(context.Context, ccse.VerifiedRecord) ([sha256.Size]byte, error) {
			return [sha256.Size]byte{1}, nil
		},
	}
	if _, err := verifier.Verify(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	return capture.entry, capture.verified
}

func equalLiveReconciliationEvidence(actual, expected DurableEvidenceRecord) bool {
	return actual.Digest == expected.Digest && actual.Kind == expected.Kind &&
		actual.ContentType == expected.ContentType &&
		bytes.Equal(actual.CanonicalContent, expected.CanonicalContent) &&
		actual.ExpectedAuditEventID == expected.ExpectedAuditEventID
}

func equalLiveReconciliationPending(actual, expected DurablePendingRevision) bool {
	return actual.PendingKey == expected.PendingKey && actual.Kind == expected.Kind &&
		actual.Codec == expected.Codec && actual.CodecVersion == expected.CodecVersion &&
		actual.Revision == expected.Revision &&
		actual.PreviousEnvelopeDigest == expected.PreviousEnvelopeDigest &&
		actual.EnvelopeDigest == expected.EnvelopeDigest &&
		bytes.Equal(actual.CanonicalEnvelope, expected.CanonicalEnvelope) &&
		equalLiveReconciliationDigests(actual.EvidenceDigests, expected.EvidenceDigests) &&
		actual.Status == expected.Status &&
		actual.CommitNotBeforeUnixNano == expected.CommitNotBeforeUnixNano &&
		actual.CommitNotAfterUnixNano == expected.CommitNotAfterUnixNano &&
		actual.TerminalOutcomeDigest == expected.TerminalOutcomeDigest &&
		actual.ExpectedAuditEventID == expected.ExpectedAuditEventID
}

func equalLiveReconciliationDigests(actual, expected [][sha256.Size]byte) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range actual {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}

func assertLiveReconciliationRows(t *testing.T, ctx context.Context, database *sql.DB,
	pendingKey [ccse.MessageIDSize]byte, eventID string, finalEntry ccse.ReplayEntry,
	evidenceCount int) {
	t.Helper()
	rows, err := database.QueryContext(ctx, `
		SELECT revision::text, pending_kind, status
		FROM cph_aiinfra.durable_pending_revision
		WHERE pending_key = $1
		ORDER BY revision`, pendingKey[:])
	if err != nil {
		t.Fatalf("query retained reconciliation revisions: %v", err)
	}
	defer rows.Close()
	type revision struct {
		number string
		kind   int16
		status int16
	}
	var revisions []revision
	for rows.Next() {
		var value revision
		if err := rows.Scan(&value.number, &value.kind, &value.status); err != nil {
			t.Fatalf("scan retained reconciliation revision: %v", err)
		}
		revisions = append(revisions, value)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read retained reconciliation revisions: %v", err)
	}
	if len(revisions) != 2 || revisions[0] != (revision{"1", int16(DurablePendingMutation), int16(DurablePendingOpen)}) ||
		revisions[1] != (revision{"2", int16(DurablePendingReconciliation), int16(DurablePendingTerminal)}) {
		t.Fatalf("retained reconciliation revisions=%+v", revisions)
	}
	scope, err := replayScopeDigest(finalEntry)
	if err != nil {
		t.Fatal(err)
	}
	var assertions int
	if err := database.QueryRowContext(ctx, `
		SELECT count(*)
		FROM cph_aiinfra.durable_evidence_assertion
		WHERE uow_scope_sha256 = $1 AND uow_message_id = $2
			AND pending_key = $3 AND pending_revision = 2 AND audit_event_id = $4`,
		scope[:], finalEntry.MessageID[:], pendingKey[:], eventID).Scan(&assertions); err != nil {
		t.Fatalf("query retained reconciliation evidence assertions: %v", err)
	}
	if assertions != evidenceCount {
		t.Fatalf("retained reconciliation evidence assertions=%d want=%d", assertions, evidenceCount)
	}
}
