// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/iam"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	livePostgresDisposableEnv = "CPH_AIIE_POSTGRES_DISPOSABLE"
	livePostgresOwnerDSNEnv   = "CPH_AIIE_POSTGRES_OWNER_DSN"
	livePostgresRuntimeDSNEnv = "CPH_AIIE_POSTGRES_RUNTIME_DSN"
)

// TestLivePostgresCanonicalAdmissionAndReload is intentionally opt-in. Its
// database must be disposable: the test installs migrations, changes direct
// grants for the supplied runtime role, and retains authoritative evidence.
func TestLivePostgresCanonicalAdmissionAndReload(t *testing.T) {
	if os.Getenv(livePostgresDisposableEnv) != "YES" {
		t.Skip("set CPH_AIIE_POSTGRES_DISPOSABLE=YES to run the live PostgreSQL acceptance test")
	}
	ownerDSN, runtimeDSN := os.Getenv(livePostgresOwnerDSNEnv), os.Getenv(livePostgresRuntimeDSNEnv)
	if ownerDSN == "" || runtimeDSN == "" {
		t.Fatal("live PostgreSQL acceptance requires both owner and runtime DSNs")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ownerDB := openLivePostgres(t, ctx, ownerDSN, "owner")
	runtimeDB := openLivePostgres(t, ctx, runtimeDSN, "runtime")

	if err := MigrateReplayStore(ctx, ownerDB); err != nil {
		t.Fatalf("first owner migration: %v", err)
	}
	if err := MigrateReplayStore(ctx, ownerDB); err != nil {
		t.Fatalf("idempotent owner migration: %v", err)
	}
	assertLivePostgresConstraintTamperRejected(t, ctx, ownerDB)
	assertLivePostgresOutboxFunctionTamperRejected(t, ctx, ownerDB)
	var ownerRole, runtimeRole string
	if err := ownerDB.QueryRowContext(ctx, "SELECT current_user").Scan(&ownerRole); err != nil {
		t.Fatal("read owner role")
	}
	if err := runtimeDB.QueryRowContext(ctx, "SELECT current_user").Scan(&runtimeRole); err != nil {
		t.Fatal("read runtime role")
	}
	if ownerRole == "" || runtimeRole == "" || ownerRole == runtimeRole {
		t.Fatal("owner and runtime connections must use distinct direct-login roles")
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
	entry, verified := livePostgresVerifiedInput(t, nonce)
	suffix := hex.EncodeToString(nonce[:])
	eventID := globalid.JoinedAuditEventIDPrefix + suffix
	parent := idempotency.Binding{
		Key:           nonce,
		Domain:        idempotency.OperationIAMIdentity,
		OwnerID:       "live-identity-" + suffix,
		RequestDigest: sha256.Sum256(append([]byte("live-request:"), nonce[:]...)),
	}
	joined, err := idempotency.JoinedAuditBinding(parent)
	if err != nil {
		t.Fatal(err)
	}
	progress := sha256.Sum256(append([]byte("live-progress:"), nonce[:]...))
	parentClaim, err := idempotency.NewReserveCollection(parent, progress)
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
	eventClaim, err := globalid.Reserve(eventID, globalid.Owner{
		Domain: globalid.OwnerGovernanceAuditEvent,
		ID:     eventID,
	})
	if err != nil {
		t.Fatal(err)
	}
	eventOwner := globalid.Owner{Domain: globalid.OwnerGovernanceAuditEvent, ID: eventID}
	evidenceContent := append([]byte("live-evidence:"), nonce[:]...)
	evidenceDigest := sha256.Sum256(evidenceContent)
	evidence := DurableEvidenceRecord{
		Digest:               evidenceDigest,
		Kind:                 DurableEvidenceSemanticReceipt,
		ContentType:          "application/cph.aiinfra.live-evidence.v1",
		CanonicalContent:     evidenceContent,
		ExpectedAuditEventID: eventID,
	}
	pendingEnvelope := append([]byte("live-pending-envelope:"), nonce[:]...)
	pendingDigest := sha256.Sum256(pendingEnvelope)
	pending := DurablePendingRevision{
		PendingKey:              parent.Key,
		Kind:                    DurablePendingMutation,
		Codec:                   DurablePendingIAMCodec,
		CodecVersion:            1,
		Revision:                1,
		EnvelopeDigest:          pendingDigest,
		CanonicalEnvelope:       pendingEnvelope,
		EvidenceDigests:         [][sha256.Size]byte{evidenceDigest},
		Status:                  DurablePendingOpen,
		CommitNotBeforeUnixNano: 1_800_000_000_000_000_000,
		CommitNotAfterUnixNano:  1_800_000_300_000_000_000,
		ExpectedAuditEventID:    eventID,
	}
	receipt, err := NewAdmissionUOWReceipt("application/cph.aiinfra.live-admission.v1",
		append([]byte("live-admitted:"), nonce[:]...))
	if err != nil {
		t.Fatal(err)
	}

	handlerCalls := 0
	decision, err := store.Execute(ctx, entry, verified,
		func(txCtx context.Context, exact ccse.VerifiedRecord) ([sha256.Size]byte, error) {
			handlerCalls++
			uow, bindErr := BindCanonicalUOW(txCtx, exact, receipt)
			if bindErr != nil {
				return [sha256.Size]byte{}, bindErr
			}
			if applyErr := uow.ApplyBusinessIdempotency(txCtx, BusinessIdempotencyMutation{
				ExpectedAuditEventID: eventID,
				Claims:               []idempotency.Claim{parentClaim, joinedClaim},
			}); applyErr != nil {
				return [sha256.Size]byte{}, applyErr
			}
			if applyErr := uow.ApplyGlobalClaims(txCtx, GlobalClaimMutation{
				AuditEventID: eventID,
				Claims:       []globalid.Claim{eventClaim},
			}); applyErr != nil {
				return [sha256.Size]byte{}, applyErr
			}
			if applyErr := uow.ReserveDurableEvidence(txCtx, evidence); applyErr != nil {
				return [sha256.Size]byte{}, applyErr
			}
			if applyErr := uow.ApplyDurablePendingRevision(txCtx, pending); applyErr != nil {
				return [sha256.Size]byte{}, applyErr
			}
			transaction, ok := Transaction(txCtx)
			if !ok {
				return [sha256.Size]byte{}, ErrTransactionRequired
			}
			return transaction.Complete(txCtx, livePostgresCompletion(receipt))
		})
	if err != nil {
		t.Fatalf("commit canonical admission: %v", err)
	}
	if decision.Status != ccse.ReplayApplied || decision.OutcomeDigest != receipt.ResultDigest() || handlerCalls != 1 {
		t.Fatalf("admission decision=%+v handler_calls=%d", decision, handlerCalls)
	}
	loadedResult, err := store.LoadDurableResult(ctx, entry, decision.OutcomeDigest)
	if err != nil {
		t.Fatalf("load durable result: %v", err)
	}
	if loadedResult.ContentType != receipt.ResultContentType() ||
		!bytes.Equal(loadedResult.Payload, receipt.ResultPayload()) {
		t.Fatal("loaded durable result differs from the admission receipt")
	}

	duplicateCalled := false
	duplicate, err := store.Execute(ctx, entry, verified,
		func(context.Context, ccse.VerifiedRecord) ([sha256.Size]byte, error) {
			duplicateCalled = true
			return [sha256.Size]byte{}, fmt.Errorf("duplicate handler was invoked")
		})
	if err != nil {
		t.Fatalf("exact redelivery: %v", err)
	}
	if duplicateCalled || duplicate.Status != ccse.ReplayDuplicateCompleted ||
		duplicate.OutcomeDigest != receipt.ResultDigest() {
		t.Fatalf("duplicate decision=%+v handler_called=%t", duplicate, duplicateCalled)
	}

	advanceNonce := livePostgresNonce(t)
	advanceEntry, advanceVerified := livePostgresVerifiedInput(t, advanceNonce)
	advanceReceipt, err := NewAdmissionUOWReceipt("application/cph.aiinfra.live-advance.v1",
		append([]byte("live-advanced:"), advanceNonce[:]...))
	if err != nil {
		t.Fatal(err)
	}
	progress2 := sha256.Sum256(append([]byte("live-progress-v2:"), nonce[:]...))
	pendingEnvelope2 := append([]byte("live-pending-envelope-v2:"), nonce[:]...)
	pendingDigest2 := sha256.Sum256(pendingEnvelope2)
	var pending2 DurablePendingRevision
	advance, err := store.Execute(ctx, advanceEntry, advanceVerified,
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
			if _, clockErr := uow.SnapshotTransactionClock(txCtx); clockErr != nil {
				return [sha256.Size]byte{}, clockErr
			}
			actualPending, found, loadErr := uow.LoadDurablePending(txCtx, parent.Key)
			if loadErr != nil {
				return [sha256.Size]byte{}, loadErr
			}
			if !found || !equalLivePostgresPending(actualPending, pending) {
				return [sha256.Size]byte{}, fmt.Errorf("reloaded pending revision differs")
			}
			if assertErr := uow.AssertDurablePendingOpen(txCtx, actualPending); assertErr != nil {
				return [sha256.Size]byte{}, assertErr
			}
			actualParent, parentFound, actualJoined, joinedFound, snapshotErr :=
				uow.SnapshotBusinessIdempotencyPair(txCtx, parent.Key, joined.Key)
			if snapshotErr != nil {
				return [sha256.Size]byte{}, snapshotErr
			}
			wantParent := idempotency.Snapshot{Binding: parent, State: idempotency.StateCollecting,
				Version: 1, ProgressDigest: progress}
			wantJoined := idempotency.Snapshot{Binding: joined, State: idempotency.StateCollecting,
				Version: 1, ProgressDigest: parentDigest}
			if !parentFound || !joinedFound || actualParent != wantParent || actualJoined != wantJoined {
				return [sha256.Size]byte{}, fmt.Errorf("reloaded business pair differs")
			}
			actualGlobal, globalFound, lookupErr := uow.LookupGlobalID(txCtx, eventID)
			if lookupErr != nil {
				return [sha256.Size]byte{}, lookupErr
			}
			wantGlobal := globalid.Snapshot{Identifier: eventID,
				Owner: globalid.Owner{Domain: globalid.OwnerGovernanceAuditEvent, ID: eventID}, Version: 1}
			if !globalFound || actualGlobal != wantGlobal {
				return [sha256.Size]byte{}, fmt.Errorf("reloaded global identifier differs")
			}
			actualEvidence, evidenceFound, loadErr := uow.LoadDurableEvidence(txCtx, evidenceDigest)
			if loadErr != nil || !evidenceFound {
				return [sha256.Size]byte{}, fmt.Errorf("reload durable evidence: found=%t err=%v", evidenceFound, loadErr)
			}
			if assertErr := uow.AssertDurableEvidenceContent(txCtx, actualEvidence); assertErr != nil {
				return [sha256.Size]byte{}, assertErr
			}
			if bindErr := uow.BindResult(txCtx, advanceReceipt); bindErr != nil {
				return [sha256.Size]byte{}, bindErr
			}
			advanceParent, claimErr := idempotency.NewAdvanceCollection(actualParent, progress2)
			if claimErr != nil {
				return [sha256.Size]byte{}, claimErr
			}
			if applyErr := uow.ApplyBusinessIdempotency(txCtx, BusinessIdempotencyMutation{
				ExpectedAuditEventID: eventID,
				Claims:               []idempotency.Claim{advanceParent},
			}); applyErr != nil {
				return [sha256.Size]byte{}, applyErr
			}
			globalAssert, claimErr := globalid.Assert(eventID, actualGlobal, eventOwner)
			if claimErr != nil {
				return [sha256.Size]byte{}, claimErr
			}
			if applyErr := uow.ApplyGlobalClaims(txCtx, GlobalClaimMutation{
				AuditEventID: eventID,
				Claims:       []globalid.Claim{globalAssert},
			}); applyErr != nil {
				return [sha256.Size]byte{}, applyErr
			}
			pending2 = DurablePendingRevision{
				PendingKey:                      parent.Key,
				ExpectedKind:                    actualPending.Kind,
				Kind:                            actualPending.Kind,
				Codec:                           actualPending.Codec,
				CodecVersion:                    actualPending.CodecVersion,
				Revision:                        2,
				PreviousEnvelopeDigest:          actualPending.EnvelopeDigest,
				PreviousCanonicalEnvelope:       actualPending.CanonicalEnvelope,
				PreviousCommitNotBeforeUnixNano: actualPending.CommitNotBeforeUnixNano,
				PreviousCommitNotAfterUnixNano:  actualPending.CommitNotAfterUnixNano,
				EnvelopeDigest:                  pendingDigest2,
				CanonicalEnvelope:               pendingEnvelope2,
				EvidenceDigests:                 actualPending.EvidenceDigests,
				Status:                          DurablePendingOpen,
				CommitNotBeforeUnixNano:         actualPending.CommitNotBeforeUnixNano + 1,
				CommitNotAfterUnixNano:          actualPending.CommitNotAfterUnixNano,
				ExpectedAuditEventID:            eventID,
			}
			if applyErr := uow.ApplyDurablePendingRevision(txCtx, pending2); applyErr != nil {
				return [sha256.Size]byte{}, applyErr
			}
			if deadlineErr := uow.AssertCommitDeadline(txCtx, pending2.CommitNotAfterUnixNano); deadlineErr != nil {
				return [sha256.Size]byte{}, deadlineErr
			}
			return transaction.Complete(txCtx, livePostgresCompletion(advanceReceipt))
		})
	if err != nil {
		t.Fatalf("commit canonical advance: %v", err)
	}
	if advance.Status != ccse.ReplayApplied || advance.OutcomeDigest != advanceReceipt.ResultDigest() {
		t.Fatalf("advance decision=%+v", advance)
	}

	finalNonce := livePostgresNonce(t)
	auditStream := "cph.test.postgres-live.audit." + hex.EncodeToString(finalNonce[:])
	auditIssuedAt := livePostgresIssuedAt().Add(2 * time.Millisecond)
	auditPolicyDigest := sha256.Sum256(append([]byte("live-audit-policy:"), nonce[:]...))
	auditAnchorDigest := sha256.Sum256(append([]byte("live-audit-anchor:"), nonce[:]...))
	auditProfileDigest := sha256.Sum256(append([]byte("live-audit-profile:"), nonce[:]...))
	auditLeaseDigest := sha256.Sum256(append([]byte("live-audit-lease:"), nonce[:]...))
	auditProjection := foundationv1.AuditEventSigningProjection{
		Metadata: foundationv1.RecordMetadataSigningProjection{
			SchemaVersion:       foundationv1.SchemaVersionSigningProjection{Major: 1},
			RecordID:            eventID,
			CreatedAtUnixNano:   auditIssuedAt.UnixNano(),
			IntegrityDigest:     sha256.Sum256(append([]byte("live-audit-integrity:"), nonce[:]...)),
			HomeRegion:          "live-test-region",
			WriterEpoch:         1,
			StateVersion:        1,
			IdempotencyKey:      parent.Key,
			PolicyDigestsSHA256: [][sha256.Size]byte{auditPolicyDigest},
		},
		AuditEventID:               eventID,
		EventType:                  "LiveStorageAcceptance",
		ActorIdentity:              "live-test-actor",
		ActorKeyID:                 "live-test-actor-key",
		SubjectIDs:                 []string{parent.OwnerID},
		CauseCode:                  "storage-real-acceptance",
		CorrelationID:              livePostgresCorrelationID(finalNonce),
		OccurredAtUnixNano:         auditIssuedAt.UnixNano(),
		Outcome:                    1,
		AppliedPolicyDigestsSHA256: [][sha256.Size]byte{auditPolicyDigest},
		EvidenceDigestsSHA256:      [][sha256.Size]byte{evidenceDigest},
		PreviousEventDigestSHA256:  auditAnchorDigest,
		AuditSequence:              1,
	}
	auditPayload, err := auditProjection.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	finalEntry, finalVerified := livePostgresVerifiedInputFor(t, finalNonce,
		schema.MessageTypeAuditEvent, auditPayload, auditStream, auditIssuedAt)
	finalReceipt, err := NewAuditedFinalUOWReceipt("application/cph.aiinfra.live-final.v1",
		append([]byte("live-terminal:"), nonce[:]...), eventID, 1)
	if err != nil {
		t.Fatal(err)
	}
	semanticMaterial, semanticState, semanticProjection := livePostgresSemanticMaterial(t,
		finalNonce, eventID)
	finalDecision, err := store.Execute(ctx, finalEntry, finalVerified,
		func(txCtx context.Context, exact ccse.VerifiedRecord) ([sha256.Size]byte, error) {
			transaction, ok := Transaction(txCtx)
			if !ok {
				return [sha256.Size]byte{}, ErrTransactionRequired
			}
			uow, openErr := OpenCanonicalUOW(txCtx, exact, CanonicalAuditedFinal, eventID, 1)
			if openErr != nil {
				return [sha256.Size]byte{}, openErr
			}
			if assertErr := uow.AssertOuterVerifiedRecord(txCtx, exact); assertErr != nil {
				return [sha256.Size]byte{}, assertErr
			}
			if _, clockErr := uow.SnapshotTransactionClock(txCtx); clockErr != nil {
				return [sha256.Size]byte{}, clockErr
			}
			actualParent, parentFound, actualJoined, joinedFound, snapshotErr :=
				uow.SnapshotBusinessIdempotencyPair(txCtx, parent.Key, joined.Key)
			if snapshotErr != nil || !parentFound || !joinedFound ||
				actualParent.Version != 2 || actualJoined.Version != 1 {
				return [sha256.Size]byte{}, fmt.Errorf("reload final business pair: parent=%t joined=%t err=%v",
					parentFound, joinedFound, snapshotErr)
			}
			actualGlobal, globalFound, lookupErr := uow.LookupGlobalID(txCtx, eventID)
			if lookupErr != nil || !globalFound {
				return [sha256.Size]byte{}, fmt.Errorf("reload final global: found=%t err=%v", globalFound, lookupErr)
			}
			actualEvidence, evidenceFound, loadErr := uow.LoadDurableEvidence(txCtx, evidenceDigest)
			if loadErr != nil || !evidenceFound {
				return [sha256.Size]byte{}, fmt.Errorf("reload final evidence: found=%t err=%v", evidenceFound, loadErr)
			}
			actualPending, pendingFound, loadErr := uow.LoadDurablePending(txCtx, parent.Key)
			if loadErr != nil || !pendingFound || !equalLivePostgresPending(actualPending, pending2) {
				return [sha256.Size]byte{}, fmt.Errorf("reload final pending: found=%t err=%v", pendingFound, loadErr)
			}
			if assertErr := uow.AssertDurablePendingOpen(txCtx, actualPending); assertErr != nil {
				return [sha256.Size]byte{}, assertErr
			}
			if assertErr := uow.AssertDurableEvidenceContent(txCtx, actualEvidence); assertErr != nil {
				return [sha256.Size]byte{}, assertErr
			}
			if bindErr := uow.BindResult(txCtx, finalReceipt); bindErr != nil {
				return [sha256.Size]byte{}, bindErr
			}
			if applyErr := uow.ApplyCanonicalStates(txCtx, []CanonicalStateMutation{{
				Next: semanticState,
			}}); applyErr != nil {
				return [sha256.Size]byte{}, applyErr
			}
			if attachErr := uow.AttachSemanticProjection(txCtx, SemanticProjectionRecord{
				State: semanticState, Codec: semanticProjection.Codec(),
				ProjectionDigest:    semanticProjection.Digest(),
				CanonicalProjection: semanticProjection.Bytes(),
			}); attachErr != nil {
				return [sha256.Size]byte{}, attachErr
			}
			parentComplete, claimErr := idempotency.NewCompleteCollection(actualParent)
			if claimErr != nil {
				return [sha256.Size]byte{}, claimErr
			}
			joinedComplete, claimErr := idempotency.NewCompleteCollection(actualJoined)
			if claimErr != nil {
				return [sha256.Size]byte{}, claimErr
			}
			if applyErr := uow.ApplyBusinessIdempotency(txCtx, BusinessIdempotencyMutation{
				ExpectedAuditEventID: eventID,
				OutcomeDigest:        finalReceipt.ResultDigest(),
				Claims:               []idempotency.Claim{parentComplete, joinedComplete},
			}); applyErr != nil {
				return [sha256.Size]byte{}, applyErr
			}
			globalAssert, claimErr := globalid.Assert(eventID, actualGlobal, eventOwner)
			if claimErr != nil {
				return [sha256.Size]byte{}, claimErr
			}
			if applyErr := uow.ApplyGlobalClaims(txCtx, GlobalClaimMutation{
				AuditEventID: eventID,
				Claims:       []globalid.Claim{globalAssert},
			}); applyErr != nil {
				return [sha256.Size]byte{}, applyErr
			}
			terminal := DurablePendingRevision{
				PendingKey:                      parent.Key,
				ExpectedKind:                    actualPending.Kind,
				Kind:                            actualPending.Kind,
				Codec:                           actualPending.Codec,
				CodecVersion:                    actualPending.CodecVersion,
				Revision:                        3,
				PreviousEnvelopeDigest:          actualPending.EnvelopeDigest,
				PreviousCanonicalEnvelope:       actualPending.CanonicalEnvelope,
				PreviousCommitNotBeforeUnixNano: actualPending.CommitNotBeforeUnixNano,
				PreviousCommitNotAfterUnixNano:  actualPending.CommitNotAfterUnixNano,
				EnvelopeDigest:                  actualPending.EnvelopeDigest,
				CanonicalEnvelope:               actualPending.CanonicalEnvelope,
				EvidenceDigests:                 actualPending.EvidenceDigests,
				Status:                          DurablePendingTerminal,
				CommitNotBeforeUnixNano:         actualPending.CommitNotBeforeUnixNano,
				CommitNotAfterUnixNano:          actualPending.CommitNotAfterUnixNano,
				TerminalOutcomeDigest:           finalReceipt.ResultDigest(),
				ExpectedAuditEventID:            eventID,
			}
			if applyErr := uow.ApplyDurablePendingRevision(txCtx, terminal); applyErr != nil {
				return [sha256.Size]byte{}, applyErr
			}
			envelope := exact.Envelope()
			if appendErr := uow.AppendAuditEvent(txCtx, AuditEventRecord{
				EventID:            eventID,
				StreamID:           auditStream,
				Sequence:           1,
				EventDigest:        envelope.PayloadDigest,
				RecordDigest:       exact.Digest(),
				CanonicalEvent:     exact.Payload(),
				OccurredAtUnixNano: auditProjection.OccurredAtUnixNano,
				Head: AuditHeadCAS{
					DeploymentAnchorDigest:            auditAnchorDigest,
					AuthorizedWriterIdentity:          exact.Domain().SenderIdentity,
					AuthorizedHomeRegion:              auditProjection.Metadata.HomeRegion,
					AuthorizedWriterEpoch:             auditProjection.Metadata.WriterEpoch,
					AuthorizedGovernanceProfileDigest: auditProfileDigest,
					WriterLeaseEvidenceDigest:         auditLeaseDigest,
					WriterLeaseNotBeforeUnixNano:      auditProjection.OccurredAtUnixNano - int64(time.Minute),
					WriterLeaseNotAfterUnixNano:       auditProjection.OccurredAtUnixNano + int64(10*time.Minute),
				},
			}); appendErr != nil {
				return [sha256.Size]byte{}, appendErr
			}
			if assertErr := uow.AssertDurableEvidence(txCtx, []EvidenceAssertion{{
				EvidenceDigest:  evidenceDigest,
				HasPending:      true,
				PendingKey:      parent.Key,
				PendingRevision: 3,
			}}); assertErr != nil {
				return [sha256.Size]byte{}, assertErr
			}
			if deadlineErr := uow.AssertCommitDeadline(txCtx, terminal.CommitNotAfterUnixNano); deadlineErr != nil {
				return [sha256.Size]byte{}, deadlineErr
			}
			return transaction.Complete(txCtx, livePostgresCompletion(finalReceipt))
		})
	if err != nil {
		t.Fatalf("commit audited final: %v", err)
	}
	if finalDecision.Status != ccse.ReplayApplied ||
		finalDecision.OutcomeDigest != finalReceipt.ResultDigest() {
		t.Fatalf("audited final decision=%+v", finalDecision)
	}
	// A different replay transaction proves that the process-local material
	// snapshot is not being reused: the production adapter must load the frozen
	// row and its v2 companion from PostgreSQL and strictly rehydrate it.
	reloadNonce := livePostgresNonce(t)
	reloadEntry, reloadVerified := livePostgresVerifiedInput(t, reloadNonce)
	reloadReceipt, err := NewAdmissionUOWReceipt("application/cph.aiinfra.live-semantic-reload.v1",
		append([]byte("live-semantic-reloaded:"), reloadNonce[:]...))
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Execute(ctx, reloadEntry, reloadVerified,
		func(txCtx context.Context, exact ccse.VerifiedRecord) ([sha256.Size]byte, error) {
			uow, openErr := OpenCanonicalUOW(txCtx, exact, CanonicalAdmission, "", 0)
			if openErr != nil {
				return [sha256.Size]byte{}, openErr
			}
			adapter, adapterErr := NewProductionSemanticAdapter(uow, livePostgresIAMPolicy{})
			if adapterErr != nil {
				return [sha256.Size]byte{}, adapterErr
			}
			restored, found, lookupErr := adapter.LookupKeyMaterial(txCtx, semanticMaterial.KeyID)
			if lookupErr != nil || !found || restored.EnrollmentBindingDigest != semanticMaterial.EnrollmentBindingDigest ||
				!bytes.Equal(restored.CanonicalPublicKey, semanticMaterial.CanonicalPublicKey) {
				return [sha256.Size]byte{}, fmt.Errorf("semantic reload: found=%t err=%v", found, lookupErr)
			}
			if bindErr := uow.BindResult(txCtx, reloadReceipt); bindErr != nil {
				return [sha256.Size]byte{}, bindErr
			}
			transaction, ok := Transaction(txCtx)
			if !ok {
				return [sha256.Size]byte{}, ErrTransactionRequired
			}
			return transaction.Complete(txCtx, livePostgresCompletion(reloadReceipt))
		})
	if err != nil {
		t.Fatalf("production semantic adapter reload: %v", err)
	}

	finalDuplicateCalled := false
	finalDuplicate, err := store.Execute(ctx, finalEntry, finalVerified,
		func(context.Context, ccse.VerifiedRecord) ([sha256.Size]byte, error) {
			finalDuplicateCalled = true
			return [sha256.Size]byte{}, errors.New("audited-final duplicate handler was invoked")
		})
	if err != nil {
		t.Fatalf("exact audited-final redelivery: %v", err)
	}
	if finalDuplicateCalled || finalDuplicate.Status != ccse.ReplayDuplicateCompleted ||
		finalDuplicate.OutcomeDigest != finalReceipt.ResultDigest() {
		t.Fatalf("audited-final duplicate decision=%+v handler_called=%t",
			finalDuplicate, finalDuplicateCalled)
	}
	finalResult, err := store.LoadDurableResult(ctx, finalEntry, finalReceipt.ResultDigest())
	if err != nil {
		t.Fatalf("load audited-final result: %v", err)
	}
	if finalResult.ContentType != finalReceipt.ResultContentType() ||
		!bytes.Equal(finalResult.Payload, finalReceipt.ResultPayload()) {
		t.Fatal("loaded audited-final result differs from its receipt")
	}

	terminalReloadNonce := livePostgresNonce(t)
	terminalReloadEntry, terminalReloadVerified := livePostgresVerifiedInput(t, terminalReloadNonce)
	terminalReloadReceipt, err := NewAdmissionUOWReceipt("application/cph.aiinfra.live-terminal-reload.v1",
		append([]byte("live-terminal-reloaded:"), terminalReloadNonce[:]...))
	if err != nil {
		t.Fatal(err)
	}
	terminalReload, err := store.Execute(ctx, terminalReloadEntry, terminalReloadVerified,
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
			actualParent, parentFound, actualJoined, joinedFound, snapshotErr :=
				uow.SnapshotBusinessIdempotencyPair(txCtx, parent.Key, joined.Key)
			if snapshotErr != nil || !parentFound || !joinedFound ||
				actualParent.State != idempotency.StateCompleted ||
				actualJoined.State != idempotency.StateCompleted ||
				actualParent.OutcomeDigest != finalReceipt.ResultDigest() ||
				actualJoined.OutcomeDigest != finalReceipt.ResultDigest() {
				return [sha256.Size]byte{}, fmt.Errorf("terminal business pair differs")
			}
			actualPending, pendingFound, loadErr := uow.LoadDurablePending(txCtx, parent.Key)
			if loadErr != nil || !pendingFound || actualPending.Revision != 3 ||
				actualPending.Status != DurablePendingTerminal ||
				actualPending.TerminalOutcomeDigest != finalReceipt.ResultDigest() {
				return [sha256.Size]byte{}, fmt.Errorf("terminal pending differs")
			}
			actualEvidence, evidenceFound, loadErr := uow.LoadDurableEvidence(txCtx, evidenceDigest)
			if loadErr != nil || !evidenceFound ||
				!bytes.Equal(actualEvidence.CanonicalContent, evidenceContent) {
				return [sha256.Size]byte{}, fmt.Errorf("terminal evidence differs")
			}
			actualGlobal, globalFound, lookupErr := uow.LookupGlobalID(txCtx, eventID)
			if lookupErr != nil || !globalFound || actualGlobal.Owner != eventOwner || actualGlobal.Version != 1 {
				return [sha256.Size]byte{}, fmt.Errorf("terminal global identifier differs")
			}
			auditEvent, eventFound, auditErr := uow.LoadAuditEvent(txCtx, eventID)
			if auditErr != nil || !eventFound || auditEvent.StreamID != auditStream ||
				auditEvent.Sequence != 1 || auditEvent.RecordDigest != finalVerified.Digest() {
				return [sha256.Size]byte{}, fmt.Errorf("terminal AuditEvent differs")
			}
			auditHead, headFound, auditErr := uow.LoadAuditHead(txCtx, auditStream)
			if auditErr != nil || !headFound || auditHead.Sequence != 1 ||
				auditHead.AuditEventID != eventID || auditHead.LastRecordDigest != finalVerified.Digest() {
				return [sha256.Size]byte{}, fmt.Errorf("terminal audit head differs")
			}
			if bindErr := uow.BindResult(txCtx, terminalReloadReceipt); bindErr != nil {
				return [sha256.Size]byte{}, bindErr
			}
			if deadlineErr := uow.AssertCommitDeadline(txCtx,
				clock.ObservedAtUnixNano()+int64(time.Minute)); deadlineErr != nil {
				return [sha256.Size]byte{}, deadlineErr
			}
			return transaction.Complete(txCtx, livePostgresCompletion(terminalReloadReceipt))
		})
	if err != nil {
		t.Fatalf("commit terminal reload: %v", err)
	}
	if terminalReload.Status != ccse.ReplayApplied ||
		terminalReload.OutcomeDigest != terminalReloadReceipt.ResultDigest() {
		t.Fatalf("terminal reload decision=%+v", terminalReload)
	}
}

func assertLivePostgresOutboxFunctionTamperRejected(t *testing.T, ctx context.Context,
	ownerDB *sql.DB) {
	t.Helper()
	tx, err := ownerDB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		t.Fatalf("begin outbox-function tamper transaction: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		ALTER FUNCTION cph_aiinfra.claim_outbox_delivery(BYTEA, BYTEA, BIGINT, INTEGER)
		SECURITY INVOKER`); err != nil {
		t.Fatalf("tamper outbox function security identity: %v", err)
	}
	if err := verifyReplaySchemaShape(ctx, tx); !errors.Is(err, ErrSchemaShapeMismatch) {
		t.Fatalf("tampered outbox function verification error=%v, want ErrSchemaShapeMismatch", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback outbox-function tamper: %v", err)
	}

	restored, err := ownerDB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: true})
	if err != nil {
		t.Fatalf("begin restored outbox-function verification: %v", err)
	}
	defer func() { _ = restored.Rollback() }()
	if err := verifyReplaySchemaShape(ctx, restored); err != nil {
		t.Fatalf("verify outbox function after tamper rollback: %v", err)
	}
	if err := restored.Commit(); err != nil {
		t.Fatalf("commit restored outbox-function verification: %v", err)
	}
}

func openLivePostgres(t *testing.T, ctx context.Context, dsn, identity string) *sql.DB {
	t.Helper()
	database, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open %s PostgreSQL connection", identity)
	}
	database.SetMaxOpenConns(2)
	database.SetMaxIdleConns(2)
	t.Cleanup(func() { _ = database.Close() })
	if err := database.PingContext(ctx); err != nil {
		t.Fatalf("connect to %s PostgreSQL", identity)
	}
	return database
}

func assertLivePostgresConstraintTamperRejected(t *testing.T, ctx context.Context, ownerDB *sql.DB) {
	t.Helper()
	tx, err := ownerDB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		t.Fatalf("begin catalog tamper transaction: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "SET LOCAL search_path = pg_catalog"); err != nil {
		t.Fatalf("constrain catalog tamper search path: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `
		ALTER TABLE cph_aiinfra.authoritative_uow
		DROP CONSTRAINT authoritative_uow_scope_length`); err != nil {
		t.Fatalf("drop sealed constraint in rollback transaction: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `
		ALTER TABLE cph_aiinfra.authoritative_uow
		ADD CONSTRAINT authoritative_uow_scope_length
		CHECK ((octet_length(scope_sha256) = 32) OR TRUE)`); err != nil {
		t.Fatalf("replace sealed constraint in rollback transaction: %v", err)
	}
	if err := verifyReplaySchemaShape(ctx, tx); !errors.Is(err, ErrSchemaShapeMismatch) {
		t.Fatalf("tampered constraint verification error=%v, want ErrSchemaShapeMismatch", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback catalog tamper: %v", err)
	}

	restored, err := ownerDB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: true})
	if err != nil {
		t.Fatalf("begin restored catalog verification: %v", err)
	}
	defer func() { _ = restored.Rollback() }()
	if _, err := restored.ExecContext(ctx, "SET LOCAL search_path = pg_catalog"); err != nil {
		t.Fatalf("constrain restored verification search path: %v", err)
	}
	if err := verifyReplaySchemaShape(ctx, restored); err != nil {
		t.Fatalf("verify schema after catalog tamper rollback: %v", err)
	}
	if err := restored.Commit(); err != nil {
		t.Fatalf("commit restored catalog verification: %v", err)
	}
}

func grantLivePostgresRuntimeACL(ctx context.Context, ownerDB *sql.DB, runtimeRole string) error {
	if runtimeRole == "" {
		return fmt.Errorf("runtime role is empty")
	}
	role := pgx.Identifier{runtimeRole}.Sanitize()
	tx, err := ownerDB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "REVOKE ALL PRIVILEGES ON SCHEMA cph_aiinfra FROM "+role); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "GRANT USAGE ON SCHEMA cph_aiinfra TO "+role); err != nil {
		return err
	}

	tables := make([]string, 0, len(replayColumnContract))
	for table := range replayColumnContract {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	for _, table := range tables {
		qualified := pgx.Identifier{"cph_aiinfra", table}.Sanitize()
		if _, err := tx.ExecContext(ctx, "REVOKE ALL PRIVILEGES ON TABLE "+qualified+" FROM "+role); err != nil {
			return err
		}
		var privileges []string
		if runtimeTableReadContract(table) {
			privileges = append(privileges, "SELECT")
		}
		insert, update := runtimeTableWriteContract(table)
		if insert {
			privileges = append(privileges, "INSERT")
		}
		if update {
			privileges = append(privileges, "UPDATE")
		}
		if len(privileges) != 0 {
			if _, err := tx.ExecContext(ctx, "GRANT "+strings.Join(privileges, ", ")+" ON TABLE "+qualified+" TO "+role); err != nil {
				return err
			}
		}
	}

	bodies, err := migrationFunctionBodies()
	if err != nil {
		return err
	}
	functions := make([]string, 0, len(bodies))
	for function := range bodies {
		functions = append(functions, function)
	}
	sort.Strings(functions)
	for _, function := range functions {
		qualified := migrationFunctionPrivilegeIdentity(function)
		if _, err := tx.ExecContext(ctx, "REVOKE ALL PRIVILEGES ON FUNCTION "+qualified+" FROM "+role); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "GRANT EXECUTE ON FUNCTION "+qualified+" TO "+role); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func livePostgresNonce(t *testing.T) [ccse.MessageIDSize]byte {
	t.Helper()
	var nonce [ccse.MessageIDSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal("generate live PostgreSQL nonce")
	}
	if nonce == ([ccse.MessageIDSize]byte{}) {
		nonce[0] = 1
	}
	return nonce
}

func livePostgresVerifiedInput(t *testing.T,
	nonce [ccse.MessageIDSize]byte) (ccse.ReplayEntry, ccse.VerifiedRecord) {
	t.Helper()
	suffix := hex.EncodeToString(nonce[:])
	return livePostgresVerifiedInputFor(t, nonce, schema.MessageTypeEvidenceRecord,
		append([]byte("live-postgres-record:"), nonce[:]...),
		"cph.test.postgres-live."+suffix, livePostgresIssuedAt())
}

func livePostgresVerifiedInputFor(t *testing.T, nonce [ccse.MessageIDSize]byte,
	messageTypeID uint32, payload []byte, replayDomain string,
	issuedAt time.Time) (ccse.ReplayEntry, ccse.VerifiedRecord) {
	t.Helper()
	protocolVersion, schemaVersion := ccse.Version{Major: 1}, ccse.Version{Major: 1}
	expiresAt := issuedAt.Add(5 * time.Minute)
	suffix := hex.EncodeToString(nonce[:])
	seed := sha256.Sum256(append([]byte("cph-live-postgres-key:"), nonce[:]...))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	chainID, genesisHash := [sha256.Size]byte{31: 1}, [sha256.Size]byte{0: 2}
	domain := ccse.Domain{
		Purpose:            "cph.test.postgres-live",
		SenderIdentity:     "spiffe://test/postgres-live/" + suffix,
		Audience:           []string{"cph.test.receiver"},
		ChainID:            chainID,
		GenesisHash:        genesisHash,
		Environment:        "test",
		ProtocolVersion:    protocolVersion,
		SchemaVersion:      schemaVersion,
		SignatureAlgorithm: ccse.SignatureAlgorithmEd25519,
		SignatureKeyID:     "live-key-" + suffix,
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
		CorrelationID:      livePostgresCorrelationID(nonce),
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
	record, err := ccse.NewRecord(messageTypeID, schemaVersion, domain, envelope, payload)
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
		NotBeforeUnixNano:   issuedAt.Add(-time.Hour).UnixNano(),
		NotAfterUnixNano:    expiresAt.Add(time.Hour).UnixNano(),
		AllowedMessageTypes: []uint32{messageTypeID},
	}); err != nil {
		t.Fatal(err)
	}
	capture := new(captureReplayStore)
	verifier := ccse.Verifier{
		Expectations: ccse.Expectations{
			MessageTypeID:     messageTypeID,
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
			MaxValidityWindow: 10 * time.Minute,
		},
		Limits: ccse.DefaultLimits(),
		Clock:  ccse.ClockFunc(func() time.Time { return issuedAt.Add(time.Minute) }),
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

func livePostgresIssuedAt() time.Time {
	return time.Unix(1_800_000_000, 0).UTC()
}

func livePostgresCorrelationID(nonce [ccse.MessageIDSize]byte) [ccse.MessageIDSize]byte {
	digest := sha256.Sum256(append([]byte("cph-live-correlation:"), nonce[:]...))
	var correlationID [ccse.MessageIDSize]byte
	copy(correlationID[:], digest[:ccse.MessageIDSize])
	return correlationID
}

func livePostgresCompletion(receipt CanonicalUOWReceipt) DurableCompletion {
	return DurableCompletion{
		ContentType:     receipt.ResultContentType(),
		Payload:         receipt.ResultPayload(),
		ExternalEffects: NoExternalEffects,
	}
}

func livePostgresSemanticMaterial(t testing.TB, nonce [ccse.MessageIDSize]byte,
	eventID string) (iam.KeyMaterialSnapshot, CanonicalStateRecord, iam.SemanticProjectionV2) {
	t.Helper()
	seed := sha256.Sum256(append([]byte("live-semantic-material:"), nonce[:]...))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)
	keyID, err := iam.DeriveKeyID(ccse.SignatureAlgorithmEd25519, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	subject := "spiffe://test/postgres-live/semantic/" + hex.EncodeToString(nonce[:])
	target := iam.EntityRef{Kind: iam.EntityIdentity, PrincipalKind: 2, ID: subject}
	domain := iam.EnrollmentDomain{EnrollmentDomainID: "cph.test.postgres-live.enrollment",
		Environment: "test", GenesisHash: sha256.Sum256([]byte("live-semantic-genesis"))}
	challenge := sha256.Sum256(append([]byte("live-semantic-challenge:"), nonce[:]...))
	expiresAt := livePostgresIssuedAt().Add(time.Hour).UnixNano()
	proof, err := iam.ProofOfPossessionDigest(keyID, subject, 2, target, [sha256.Size]byte{},
		domain, challenge, expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	idempotencyKey := nonce
	if idempotencyKey == ([ccse.MessageIDSize]byte{}) {
		idempotencyKey[0] = 1
	}
	material := iam.KeyMaterialSnapshot{KeyID: keyID, Algorithm: ccse.SignatureAlgorithmEd25519,
		CanonicalPublicKey: publicKey, SubjectIdentity: subject, SubjectKind: 2,
		TargetIdentity: target, EnrollmentDomain: domain, ProofChallenge: challenge,
		ProofExpiresAtUnixNano: expiresAt, ProofSignature: ed25519.Sign(privateKey, proof[:]),
		ProofDigest: proof, ChallengeEvidenceDigest: sha256.Sum256([]byte("live-semantic-evidence")),
		EnrollmentAuthorityIdentity:   "spiffe://test/postgres-live/enroller",
		EnrollmentPolicyDigestsSHA256: [][sha256.Size]byte{sha256.Sum256([]byte("live-semantic-policy"))},
		WriterIdentity:                "spiffe://test/postgres-live/iam-writer", HomeRegion: "live-test-region",
		WriterEpoch: 1, StateVersion: 1, IdempotencyKey: idempotencyKey}
	material.EnrollmentBindingDigest, err = iam.KeyMaterialEnrollmentBindingDigest(material)
	if err != nil {
		t.Fatal(err)
	}
	canonical, digest, err := iam.CanonicalKeyMaterialStateV1(material)
	if err != nil {
		t.Fatal(err)
	}
	state := CanonicalStateRecord{Namespace: CanonicalStateIAM, Kind: CanonicalStateIAMKeyMaterial,
		ObjectID: keyID, Version: 1, StateDigest: digest,
		ContentType: CanonicalStateIAMKeyMaterialContentType, CanonicalState: canonical,
		Terminal: true, AuditEventID: eventID}
	projection, err := iam.NewKeyMaterialSemanticProjectionV2(toIAMState(state), material)
	if err != nil {
		t.Fatal(err)
	}
	return material, state, projection
}

type livePostgresIAMPolicy struct{}

func (livePostgresIAMPolicy) ValidateAuthority(context.Context, iam.AuthorityRequest) error {
	return nil
}
func (livePostgresIAMPolicy) ValidateEnrollmentAuthority(context.Context, iam.EnrollmentAuthorityRequest) error {
	return nil
}
func (livePostgresIAMPolicy) ValidateIdentityTransition(context.Context, iam.IdentityTransitionRequest) error {
	return nil
}
func (livePostgresIAMPolicy) ValidateAllowedMessageTypes(context.Context, iam.AllowedMessageTypesRequest) error {
	return nil
}
func (livePostgresIAMPolicy) OwnershipTransferProfile(context.Context, iam.OwnershipTransferProfileRequest) (iam.OwnershipTransferProfile, error) {
	return iam.OwnershipTransferProfile{}, errors.New("unused live policy method")
}
func (livePostgresIAMPolicy) OwnershipTransferProfileAt(context.Context, iam.OwnershipTransferProfileHistoryRequest) (iam.OwnershipTransferProfile, error) {
	return iam.OwnershipTransferProfile{}, errors.New("unused live policy method")
}
func (livePostgresIAMPolicy) ValidateOwnershipTransferEvidence(context.Context, iam.OwnershipTransferEvidenceRequest) error {
	return errors.New("unused live policy method")
}
func (livePostgresIAMPolicy) ValidateOwnershipTransferEvidenceAt(context.Context, iam.OwnershipTransferEvidenceHistoryRequest) error {
	return errors.New("unused live policy method")
}
func (livePostgresIAMPolicy) ReceiverProfile(context.Context, uint32) (iam.ReceiverProfile, error) {
	return iam.ReceiverProfile{}, errors.New("unused live policy method")
}

func equalLivePostgresPending(actual, expected DurablePendingRevision) bool {
	return actual.PendingKey == expected.PendingKey && actual.Kind == expected.Kind &&
		actual.Codec == expected.Codec &&
		actual.CodecVersion == expected.CodecVersion && actual.Revision == expected.Revision &&
		actual.PreviousEnvelopeDigest == expected.PreviousEnvelopeDigest &&
		actual.EnvelopeDigest == expected.EnvelopeDigest &&
		bytes.Equal(actual.CanonicalEnvelope, expected.CanonicalEnvelope) &&
		equalLivePostgresDigests(actual.EvidenceDigests, expected.EvidenceDigests) &&
		actual.Status == expected.Status &&
		actual.CommitNotBeforeUnixNano == expected.CommitNotBeforeUnixNano &&
		actual.CommitNotAfterUnixNano == expected.CommitNotAfterUnixNano &&
		actual.TerminalOutcomeDigest == expected.TerminalOutcomeDigest &&
		actual.ExpectedAuditEventID == expected.ExpectedAuditEventID
}

func equalLivePostgresDigests(actual, expected [][sha256.Size]byte) bool {
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
