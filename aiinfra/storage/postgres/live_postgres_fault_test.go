// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestLivePostgresFaultRollbackAndConcurrentRedelivery is intentionally
// opt-in. It retains successful random replay rows, but never deletes,
// truncates, or reuses existing authoritative rows. Every failure case is
// required to leave no row bearing its random test identifiers.
func TestLivePostgresFaultRollbackAndConcurrentRedelivery(t *testing.T) {
	if os.Getenv(livePostgresDisposableEnv) != "YES" {
		t.Skip("set CPH_AIIE_POSTGRES_DISPOSABLE=YES to run the live PostgreSQL acceptance test")
	}
	ownerDSN, runtimeDSN := os.Getenv(livePostgresOwnerDSNEnv), os.Getenv(livePostgresRuntimeDSNEnv)
	if ownerDSN == "" || runtimeDSN == "" {
		t.Fatal("live PostgreSQL acceptance requires both owner and runtime DSNs")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	ownerDB := openLivePostgres(t, ctx, ownerDSN, "fault-test owner")
	runtimeDB := openLivePostgres(t, ctx, runtimeDSN, "fault-test runtime")
	if err := MigrateReplayStore(ctx, ownerDB); err != nil {
		t.Fatalf("owner migration: %v", err)
	}
	var runtimeRole string
	if err := runtimeDB.QueryRowContext(ctx, "SELECT current_user").Scan(&runtimeRole); err != nil {
		t.Fatal("read fault-test runtime role")
	}
	if err := grantLivePostgresRuntimeACL(ctx, ownerDB, runtimeRole); err != nil {
		t.Fatalf("install exact runtime ACL: %v", err)
	}
	store, err := NewReplayStore(ctx, runtimeDB)
	if err != nil {
		t.Fatalf("construct fault-test replay store: %v", err)
	}

	t.Run("handler error rolls back every authoritative row", func(t *testing.T) {
		testLivePostgresHandlerErrorRollback(t, ctx, runtimeDB, store)
	})
	t.Run("deferred constraint commit failure rolls back", func(t *testing.T) {
		testLivePostgresDeferredConstraintRollback(t, ctx, ownerDB)
	})
	t.Run("concurrent redelivery invokes handler at most once", func(t *testing.T) {
		testLivePostgresConcurrentRedelivery(t, ctx, store)
	})
	t.Run("database execution fence rejects overlap and redelivery recovers", func(t *testing.T) {
		testLivePostgresExecutionFenceRedelivery(t, ctx, ownerDB, store)
	})
	t.Run("real serialization conflict retries a fresh transaction", func(t *testing.T) {
		testLivePostgresSerializationRetry(t, ctx, ownerDB, runtimeDB, runtimeRole)
	})
}

func testLivePostgresSerializationRetry(t *testing.T, ctx context.Context,
	ownerDB, runtimeDB *sql.DB, runtimeRole string) {
	t.Helper()
	nonce := livePostgresNonce(t)
	suffix := hex.EncodeToString(nonce[:])
	tableIdentifier := "cph_aiinfra_ssi_" + suffix
	qualifiedTable := pgx.Identifier{"public", tableIdentifier}.Sanitize()
	role := pgx.Identifier{runtimeRole}.Sanitize()
	if _, err := ownerDB.ExecContext(ctx, "CREATE TABLE "+qualifiedTable+
		" (id BIGINT PRIMARY KEY, value BIGINT NOT NULL)"); err != nil {
		t.Fatalf("create serialization acceptance table: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = ownerDB.ExecContext(cleanupCtx, "DROP TABLE "+qualifiedTable)
	})
	if _, err := ownerDB.ExecContext(ctx, "INSERT INTO "+qualifiedTable+" (id, value) VALUES (1, 0)"); err != nil {
		t.Fatalf("seed serialization acceptance row: %v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, "GRANT SELECT, UPDATE ON TABLE "+qualifiedTable+" TO "+role); err != nil {
		t.Fatalf("grant serialization acceptance table: %v", err)
	}
	selectSQL := "SELECT value FROM " + qualifiedTable + " WHERE id = 1"
	updateSQL := "UPDATE " + qualifiedTable + " SET value = value + 1 WHERE id = 1"
	store, err := NewReplayStore(ctx, runtimeDB,
		WithAllowedStatements(
			AllowedStatement{SQL: selectSQL, Access: StatementQuery},
			AllowedStatement{SQL: updateSQL, Access: StatementExec},
		),
		WithSerializationRetryPolicy(3, time.Millisecond, 5*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("construct serialization-retry store: %v", err)
	}
	entry, verified := livePostgresVerifiedInput(t, nonce)
	receipt, err := NewAdmissionUOWReceipt("application/cph.aiinfra.live-serialization.v1",
		[]byte("live-serialization-result/"+suffix))
	if err != nil {
		t.Fatal(err)
	}
	firstRead := make(chan struct{})
	concurrentCommitted := make(chan error, 1)
	go func() {
		select {
		case <-firstRead:
		case <-ctx.Done():
			concurrentCommitted <- ctx.Err()
			return
		}
		_, updateErr := ownerDB.ExecContext(ctx,
			"UPDATE "+qualifiedTable+" SET value = value + 1 WHERE id = 1")
		concurrentCommitted <- updateErr
	}()
	handlerCalls := 0
	serializationObserved := false
	decision, err := store.Execute(ctx, entry, verified,
		func(txCtx context.Context, exact ccse.VerifiedRecord) ([sha256.Size]byte, error) {
			handlerCalls++
			transaction, ok := Transaction(txCtx)
			if !ok {
				return [sha256.Size]byte{}, ErrTransactionRequired
			}
			var value int64
			row := transaction.QueryRowContext(txCtx, selectSQL)
			if scanErr := row.Scan(&value); scanErr != nil {
				return [sha256.Size]byte{}, scanErr
			}
			if handlerCalls == 1 {
				close(firstRead)
				if concurrentErr := <-concurrentCommitted; concurrentErr != nil {
					return [sha256.Size]byte{}, concurrentErr
				}
			}
			result, updateErr := transaction.ExecContext(txCtx, updateSQL)
			if updateErr != nil {
				var pgErr *pgconn.PgError
				serializationObserved = errors.As(updateErr, &pgErr) && pgErr.Code == "40001"
				return [sha256.Size]byte{}, updateErr
			}
			if _, rowsErr := result.RowsAffected(); rowsErr != nil {
				return [sha256.Size]byte{}, rowsErr
			}
			if _, bindErr := BindCanonicalUOW(txCtx, exact, receipt); bindErr != nil {
				return [sha256.Size]byte{}, bindErr
			}
			return transaction.Complete(txCtx, livePostgresCompletion(receipt))
		})
	if err != nil {
		t.Fatalf("execute across real serialization conflict: %v", err)
	}
	if !serializationObserved || handlerCalls != 2 || decision.Status != ccse.ReplayApplied ||
		decision.OutcomeDigest != receipt.ResultDigest() {
		t.Fatalf("serialization_observed=%t handler_calls=%d decision=%+v",
			serializationObserved, handlerCalls, decision)
	}
	var finalValue int64
	if err := ownerDB.QueryRowContext(ctx, "SELECT value FROM "+qualifiedTable+" WHERE id = 1").Scan(&finalValue); err != nil {
		t.Fatalf("read serialization acceptance row: %v", err)
	}
	if finalValue != 2 {
		t.Fatalf("serialization acceptance value=%d, want 2", finalValue)
	}
}

func testLivePostgresHandlerErrorRollback(t *testing.T, ctx context.Context,
	runtimeDB *sql.DB, store *ReplayStore) {
	t.Helper()
	nonce := livePostgresNonce(t)
	entry, verified := livePostgresVerifiedInput(t, nonce)
	scope, err := replayScopeDigest(entry)
	if err != nil {
		t.Fatal(err)
	}
	suffix := hex.EncodeToString(nonce[:])
	eventID := globalid.JoinedAuditEventIDPrefix + suffix
	parent := idempotency.Binding{
		Key:           nonce,
		Domain:        idempotency.OperationIAMIdentity,
		OwnerID:       "live-fault-identity-" + suffix,
		RequestDigest: livePostgresFaultDigest("request/" + suffix),
	}
	joined, err := idempotency.JoinedAuditBinding(parent)
	if err != nil {
		t.Fatal(err)
	}
	parentClaim, err := idempotency.NewReserveCollection(parent,
		livePostgresFaultDigest("progress/"+suffix))
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
	evidenceContent := []byte("live-fault-evidence/" + suffix)
	evidenceDigest := sha256.Sum256(evidenceContent)
	evidence := DurableEvidenceRecord{
		Digest:               evidenceDigest,
		Kind:                 DurableEvidenceSemanticReceipt,
		ContentType:          "application/cph.aiinfra.live-fault-evidence.v1",
		CanonicalContent:     evidenceContent,
		ExpectedAuditEventID: eventID,
	}
	pendingEnvelope := []byte("live-fault-pending/" + suffix)
	pending := DurablePendingRevision{
		PendingKey:              parent.Key,
		Kind:                    DurablePendingMutation,
		Codec:                   DurablePendingIAMCodec,
		CodecVersion:            1,
		Revision:                1,
		EnvelopeDigest:          sha256.Sum256(pendingEnvelope),
		CanonicalEnvelope:       pendingEnvelope,
		EvidenceDigests:         [][sha256.Size]byte{evidenceDigest},
		Status:                  DurablePendingOpen,
		CommitNotBeforeUnixNano: 1_800_000_000_000_000_000,
		CommitNotAfterUnixNano:  1_800_000_300_000_000_000,
		ExpectedAuditEventID:    eventID,
	}
	receipt, err := NewAdmissionUOWReceipt("application/cph.aiinfra.live-fault-result.v1",
		[]byte("live-fault-result/"+suffix))
	if err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("injected live handler failure after completion")
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
			outcome, completeErr := transaction.Complete(txCtx, livePostgresCompletion(receipt))
			if completeErr != nil {
				return [sha256.Size]byte{}, completeErr
			}
			return outcome, wantErr
		})
	if !errors.Is(err, wantErr) {
		t.Fatalf("handler failure=%v, want injected error", err)
	}
	if decision != (ccse.ReplayDecision{}) || handlerCalls != 1 {
		t.Fatalf("failed decision=%+v handler_calls=%d", decision, handlerCalls)
	}

	checks := []livePostgresCountCheck{
		{"replay head", `SELECT count(*) FROM cph_aiinfra.ccse_replay_head WHERE scope_sha256 = $1`, []any{scope[:]}},
		{"replay inbox", `SELECT count(*) FROM cph_aiinfra.ccse_replay_inbox WHERE scope_sha256 = $1 AND message_id = $2`, []any{scope[:], entry.MessageID[:]}},
		{"durable result", `SELECT count(*) FROM cph_aiinfra.ccse_durable_result WHERE scope_sha256 = $1 AND message_id = $2`, []any{scope[:], entry.MessageID[:]}},
		{"authoritative UoW", `SELECT count(*) FROM cph_aiinfra.authoritative_uow WHERE scope_sha256 = $1 AND message_id = $2`, []any{scope[:], entry.MessageID[:]}},
		{"business head", `SELECT count(*) FROM cph_aiinfra.business_idempotency_head WHERE idempotency_key IN ($1, $2)`, []any{parent.Key[:], joined.Key[:]}},
		{"business history", `SELECT count(*) FROM cph_aiinfra.business_idempotency_history WHERE idempotency_key IN ($1, $2)`, []any{parent.Key[:], joined.Key[:]}},
		{"global head", `SELECT count(*) FROM cph_aiinfra.global_identifier_head WHERE identifier = $1`, []any{eventID}},
		{"global history", `SELECT count(*) FROM cph_aiinfra.global_identifier_history WHERE identifier = $1`, []any{eventID}},
		{"global claim", `SELECT count(*) FROM cph_aiinfra.global_identifier_claim WHERE identifier = $1`, []any{eventID}},
		{"durable evidence", `SELECT count(*) FROM cph_aiinfra.durable_evidence WHERE evidence_digest = $1`, []any{evidenceDigest[:]}},
		{"pending head", `SELECT count(*) FROM cph_aiinfra.durable_pending_head WHERE pending_key = $1`, []any{parent.Key[:]}},
		{"pending revision", `SELECT count(*) FROM cph_aiinfra.durable_pending_revision WHERE pending_key = $1`, []any{parent.Key[:]}},
		{"pending evidence", `SELECT count(*) FROM cph_aiinfra.durable_pending_evidence WHERE pending_key = $1`, []any{parent.Key[:]}},
	}
	for _, check := range checks {
		assertLivePostgresCount(t, ctx, runtimeDB, check, 0)
	}
	if _, err := store.LoadDurableResult(ctx, entry, receipt.ResultDigest()); !errors.Is(err, ErrDurableResultMissing) {
		t.Fatalf("load rolled-back durable result error=%v, want ErrDurableResultMissing", err)
	}
}

func testLivePostgresDeferredConstraintRollback(t *testing.T, ctx context.Context,
	ownerDB *sql.DB) {
	t.Helper()
	scopeNonce := livePostgresNonce(t)
	scope := livePostgresFaultDigest("deferred-scope/" + hex.EncodeToString(scopeNonce[:]))
	messageID := livePostgresNonce(t)
	outcome := livePostgresFaultDigest("deferred-outcome/" + hex.EncodeToString(messageID[:]))
	tx, err := ownerDB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		t.Fatalf("begin deferred-constraint transaction: %v", err)
	}
	deferredRolledBack := false
	defer func() {
		if !deferredRolledBack {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.ExecContext(ctx, "SET LOCAL search_path = pg_catalog"); err != nil {
		t.Fatalf("constrain deferred-constraint search path: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO cph_aiinfra.authoritative_uow
			(scope_sha256, message_id, uow_kind, outcome_digest,
			 result_content_type, result_payload, evidence_assertion_count,
			 audit_event_id, outer_payload_digest, transaction_id)
		VALUES ($1, $2, 1, $3, $4, $5, 0, NULL, NULL, pg_current_xact_id())`,
		scope[:], messageID[:], outcome[:],
		"application/cph.aiinfra.live-deferred-failure.v1", []byte("must-roll-back")); err != nil {
		t.Fatalf("stage row protected by deferred constraints: %v", err)
	}
	commitErr := tx.Commit()
	if commitErr == nil {
		deferredRolledBack = true
		t.Fatal("commit accepted an authoritative UoW without its replay result")
	}
	var pgErr *pgconn.PgError
	if !errors.As(commitErr, &pgErr) || (pgErr.Code != "23503" && pgErr.Code != "23514") {
		t.Fatalf("deferred constraint commit error=%v, want SQLSTATE 23503 or 23514", commitErr)
	}
	deferredRolledBack = true
	assertLivePostgresCount(t, ctx, ownerDB, livePostgresCountCheck{
		name:  "deferred authoritative UoW",
		query: `SELECT count(*) FROM cph_aiinfra.authoritative_uow WHERE scope_sha256 = $1 AND message_id = $2`,
		args:  []any{scope[:], messageID[:]},
	}, 0)
}

func testLivePostgresConcurrentRedelivery(t *testing.T, ctx context.Context,
	store *ReplayStore) {
	t.Helper()
	nonce := livePostgresNonce(t)
	entry, verified := livePostgresVerifiedInput(t, nonce)
	receipt, err := NewAdmissionUOWReceipt("application/cph.aiinfra.live-concurrent.v1",
		[]byte("live-concurrent-result/"+hex.EncodeToString(nonce[:])))
	if err != nil {
		t.Fatal(err)
	}
	type executionResult struct {
		decision ccse.ReplayDecision
		err      error
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan executionResult, 1)
	var handlerCalls atomic.Int32
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	go func() {
		decision, executeErr := store.Execute(ctx, entry, verified,
			func(txCtx context.Context, exact ccse.VerifiedRecord) ([sha256.Size]byte, error) {
				handlerCalls.Add(1)
				close(entered)
				select {
				case <-release:
				case <-txCtx.Done():
					return [sha256.Size]byte{}, txCtx.Err()
				}
				_, bindErr := BindCanonicalUOW(txCtx, exact, receipt)
				if bindErr != nil {
					return [sha256.Size]byte{}, bindErr
				}
				transaction, ok := Transaction(txCtx)
				if !ok {
					return [sha256.Size]byte{}, ErrTransactionRequired
				}
				return transaction.Complete(txCtx, livePostgresCompletion(receipt))
			})
		firstDone <- executionResult{decision: decision, err: executeErr}
	}()

	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatalf("first concurrent handler did not start: %v", ctx.Err())
	}
	concurrentHandlerCalled := false
	concurrent, concurrentErr := store.Execute(ctx, entry, verified,
		func(context.Context, ccse.VerifiedRecord) ([sha256.Size]byte, error) {
			concurrentHandlerCalled = true
			return [sha256.Size]byte{}, errors.New("concurrent handler unexpectedly invoked")
		})
	if !errors.Is(concurrentErr, ErrUnitOfWorkActive) ||
		!errors.Is(concurrentErr, ccse.ErrReplayReentrant) {
		t.Fatalf("concurrent delivery error=%v, want active/reentrant rejection", concurrentErr)
	}
	if concurrent != (ccse.ReplayDecision{}) || concurrentHandlerCalled {
		t.Fatalf("concurrent decision=%+v handler_called=%t", concurrent, concurrentHandlerCalled)
	}
	close(release)
	released = true
	var first executionResult
	select {
	case first = <-firstDone:
	case <-ctx.Done():
		t.Fatalf("first concurrent execution did not finish: %v", ctx.Err())
	}
	if first.err != nil || first.decision.Status != ccse.ReplayApplied ||
		first.decision.OutcomeDigest != receipt.ResultDigest() {
		t.Fatalf("first concurrent execution decision=%+v err=%v", first.decision, first.err)
	}

	retryHandlerCalled := false
	retry, err := store.Execute(ctx, entry, verified,
		func(context.Context, ccse.VerifiedRecord) ([sha256.Size]byte, error) {
			retryHandlerCalled = true
			return [sha256.Size]byte{}, errors.New("completed redelivery handler unexpectedly invoked")
		})
	if err != nil {
		t.Fatalf("retry concurrent redelivery: %v", err)
	}
	if retryHandlerCalled || retry.Status != ccse.ReplayDuplicateCompleted ||
		retry.OutcomeDigest != first.decision.OutcomeDigest || handlerCalls.Load() != 1 {
		t.Fatalf("retry=%+v retry_handler=%t handler_calls=%d",
			retry, retryHandlerCalled, handlerCalls.Load())
	}
	loaded, err := store.LoadDurableResult(ctx, entry, retry.OutcomeDigest)
	if err != nil {
		t.Fatalf("load concurrent durable result: %v", err)
	}
	if loaded.ContentType != receipt.ResultContentType() ||
		!bytes.Equal(loaded.Payload, receipt.ResultPayload()) {
		t.Fatal("concurrent redelivery recovered a different durable result")
	}
}

func testLivePostgresExecutionFenceRedelivery(t *testing.T, ctx context.Context,
	ownerDB *sql.DB, store *ReplayStore) {
	t.Helper()
	nonce := livePostgresNonce(t)
	entry, verified := livePostgresVerifiedInput(t, nonce)
	scope, err := replayScopeDigest(entry)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := NewAdmissionUOWReceipt("application/cph.aiinfra.live-fence.v1",
		[]byte("live-fence-result/"+hex.EncodeToString(nonce[:])))
	if err != nil {
		t.Fatal(err)
	}
	locker, err := ownerDB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		t.Fatalf("begin execution-fence holder: %v", err)
	}
	locked := true
	defer func() {
		if locked {
			_ = locker.Rollback()
		}
	}()
	var version int64
	if err := locker.QueryRowContext(ctx, `
		SELECT version
		FROM cph_aiinfra.schema_migration
		WHERE version = $1
		FOR UPDATE`, executionFenceVersion).Scan(&version); err != nil {
		t.Fatalf("hold database execution fence: %v", err)
	}
	if version != executionFenceVersion {
		t.Fatalf("locked execution-fence version=%d", version)
	}
	handlerCalled := false
	decision, err := store.Execute(ctx, entry, verified,
		func(context.Context, ccse.VerifiedRecord) ([sha256.Size]byte, error) {
			handlerCalled = true
			return [sha256.Size]byte{}, errors.New("fenced handler unexpectedly invoked")
		})
	if !errors.Is(err, ErrUnitOfWorkActive) {
		t.Fatalf("database-fenced execution error=%v, want ErrUnitOfWorkActive", err)
	}
	if decision != (ccse.ReplayDecision{}) || handlerCalled {
		t.Fatalf("database-fenced decision=%+v handler_called=%t", decision, handlerCalled)
	}
	for _, check := range []livePostgresCountCheck{
		{"database-fenced replay head", `SELECT count(*) FROM cph_aiinfra.ccse_replay_head WHERE scope_sha256 = $1`, []any{scope[:]}},
		{"database-fenced replay inbox", `SELECT count(*) FROM cph_aiinfra.ccse_replay_inbox WHERE scope_sha256 = $1 AND message_id = $2`, []any{scope[:], entry.MessageID[:]}},
		{"database-fenced durable result", `SELECT count(*) FROM cph_aiinfra.ccse_durable_result WHERE scope_sha256 = $1 AND message_id = $2`, []any{scope[:], entry.MessageID[:]}},
		{"database-fenced authoritative UoW", `SELECT count(*) FROM cph_aiinfra.authoritative_uow WHERE scope_sha256 = $1 AND message_id = $2`, []any{scope[:], entry.MessageID[:]}},
	} {
		assertLivePostgresCount(t, ctx, ownerDB, check, 0)
	}
	if err := locker.Rollback(); err != nil {
		t.Fatalf("release database execution fence: %v", err)
	}
	locked = false

	handlerCalls := 0
	applied, err := store.Execute(ctx, entry, verified,
		func(txCtx context.Context, exact ccse.VerifiedRecord) ([sha256.Size]byte, error) {
			handlerCalls++
			if _, bindErr := BindCanonicalUOW(txCtx, exact, receipt); bindErr != nil {
				return [sha256.Size]byte{}, bindErr
			}
			transaction, ok := Transaction(txCtx)
			if !ok {
				return [sha256.Size]byte{}, ErrTransactionRequired
			}
			return transaction.Complete(txCtx, livePostgresCompletion(receipt))
		})
	if err != nil || applied.Status != ccse.ReplayApplied ||
		applied.OutcomeDigest != receipt.ResultDigest() || handlerCalls != 1 {
		t.Fatalf("post-fence execution decision=%+v handler_calls=%d err=%v",
			applied, handlerCalls, err)
	}
	duplicateCalled := false
	duplicate, err := store.Execute(ctx, entry, verified,
		func(context.Context, ccse.VerifiedRecord) ([sha256.Size]byte, error) {
			duplicateCalled = true
			return [sha256.Size]byte{}, errors.New("post-fence duplicate handler unexpectedly invoked")
		})
	if err != nil || duplicate.Status != ccse.ReplayDuplicateCompleted ||
		duplicate.OutcomeDigest != applied.OutcomeDigest || duplicateCalled {
		t.Fatalf("post-fence duplicate=%+v handler_called=%t err=%v",
			duplicate, duplicateCalled, err)
	}
}

type livePostgresCountCheck struct {
	name  string
	query string
	args  []any
}

func assertLivePostgresCount(t *testing.T, ctx context.Context, database *sql.DB,
	check livePostgresCountCheck, want int64) {
	t.Helper()
	var count int64
	if err := database.QueryRowContext(ctx, check.query, check.args...).Scan(&count); err != nil {
		t.Fatalf("count %s: %v", check.name, err)
	}
	if count != want {
		t.Fatalf("%s row count=%d, want %d", check.name, count, want)
	}
}

func livePostgresFaultDigest(value string) [sha256.Size]byte {
	return sha256.Sum256([]byte("CPH-AIIE-LIVE-POSTGRES-FAULT-V1\x00" + value))
}
