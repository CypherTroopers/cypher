// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestLivePostgresOutboxRedeliveryAndDeduplication exercises the real
// database-clock lease protocol. It models the unavoidable crash window after
// a remote publication succeeds but before its PostgreSQL acknowledgement:
// the next worker receives the same deduplication key and the idempotent
// publisher applies the logical effect only once.
func TestLivePostgresOutboxRedeliveryAndDeduplication(t *testing.T) {
	if os.Getenv(livePostgresDisposableEnv) != "YES" {
		t.Skip("set CPH_AIIE_POSTGRES_DISPOSABLE=YES to run the live PostgreSQL outbox test")
	}
	ownerDSN, runtimeDSN := os.Getenv(livePostgresOwnerDSNEnv), os.Getenv(livePostgresRuntimeDSNEnv)
	if ownerDSN == "" || runtimeDSN == "" {
		t.Fatal("live PostgreSQL outbox test requires both owner and runtime DSNs")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	ownerDB := openLivePostgres(t, ctx, ownerDSN, "outbox-test owner")
	runtimeDB := openLivePostgres(t, ctx, runtimeDSN, "outbox-test runtime")
	if err := MigrateReplayStore(ctx, ownerDB); err != nil {
		t.Fatalf("outbox-test owner migration: %v", err)
	}
	var runtimeRole string
	if err := runtimeDB.QueryRowContext(ctx, "SELECT current_user").Scan(&runtimeRole); err != nil {
		t.Fatal("read outbox-test runtime role")
	}
	if err := grantLivePostgresRuntimeACL(ctx, ownerDB, runtimeRole); err != nil {
		t.Fatalf("install outbox-test runtime ACL: %v", err)
	}
	store, err := NewReplayStore(ctx, runtimeDB)
	if err != nil {
		t.Fatalf("construct outbox-test replay store: %v", err)
	}
	publisher := newLivePostgresIdempotentPublisher()
	t.Run("delivery table is closed behind fenced functions", func(t *testing.T) {
		assertLivePostgresOutboxTableCapabilityClosed(t, ctx, runtimeDB)
	})

	t.Run("publish-then-crash redelivers one logical effect", func(t *testing.T) {
		nonce := livePostgresNonce(t)
		entry, verified := livePostgresVerifiedInput(t, nonce)
		intent := OutboxIntent{
			EventID: nonce, Destination: "cph.live.outbox",
			DeduplicationKey: fmt.Sprintf("crash-%x", nonce[:]),
			ContentType:      "application/cph.aiinfra.live-outbox.v1",
			Payload:          append([]byte("crash-redelivery/"), nonce[:]...),
		}
		applyLivePostgresOutboxIntent(t, ctx, store, entry, verified, intent)
		crashed, err := NewOutboxDispatcher(ctx, runtimeDB, "worker-crashed", publisher,
			WithOutboxBatchSize(1), WithOutboxLeaseDuration(time.Second),
			WithOutboxRetryBackoff(time.Millisecond, time.Second))
		if err != nil {
			t.Fatal(err)
		}
		claim, found, err := crashed.claim(ctx)
		if err != nil || !found {
			t.Fatalf("claim crash-window intent: found=%t err=%v", found, err)
		}
		if err := publisher.Publish(ctx, claim.publication()); err != nil {
			t.Fatalf("first crash-window publication: %v", err)
		}
		fakeToken := claim.leaseToken
		fakeToken[0] ^= 0xff
		if fakeToken == ([ccse.MessageIDSize]byte{}) {
			fakeToken[0] = 1
		}
		claimWorker := outboxWorkerDigest("worker-crashed")
		_, err = runtimeDB.ExecContext(ctx,
			"SELECT cph_aiinfra.acknowledge_outbox_delivery($1, $2, $3)",
			claim.eventID[:], claimWorker[:], fakeToken[:])
		assertLivePostgresOutboxSQLState(t, err, "55000", "forged lease-token acknowledgement")
		forgedWorker := outboxWorkerDigest("worker-forged")
		_, err = runtimeDB.ExecContext(ctx,
			"SELECT cph_aiinfra.acknowledge_outbox_delivery($1, $2, $3)",
			claim.eventID[:], forgedWorker[:], claim.leaseToken[:])
		assertLivePostgresOutboxSQLState(t, err, "55000", "forged worker acknowledgement")
		failureDigest := sha256.Sum256([]byte("forged rejection"))
		_, err = runtimeDB.ExecContext(ctx,
			"SELECT cph_aiinfra.reject_outbox_delivery($1, $2, $3, $4, $5)",
			claim.eventID[:], claimWorker[:], fakeToken[:], int64(time.Second/time.Microsecond),
			failureDigest[:])
		assertLivePostgresOutboxSQLState(t, err, "55000", "forged lease-token rejection")
		// Deliberately omit acknowledge: this is the process-loss boundary.
		awaitLivePostgresOutboxReady(t, ctx, ownerDB, intent.EventID)
		recovery, err := NewOutboxDispatcher(ctx, runtimeDB, "worker-recovery", publisher,
			WithOutboxBatchSize(1), WithOutboxLeaseDuration(time.Second),
			WithOutboxRetryBackoff(time.Millisecond, time.Second))
		if err != nil {
			t.Fatal(err)
		}
		report, err := recovery.DispatchBatch(ctx)
		if err != nil {
			t.Fatalf("recover crash-window delivery: %v", err)
		}
		if report != (OutboxDispatchReport{Claimed: 1, Delivered: 1}) {
			t.Fatalf("recovery report=%+v", report)
		}
		calls, effects := publisher.counts(intent)
		if calls != 2 || effects != 1 {
			t.Fatalf("crash-window publisher calls=%d logical_effects=%d", calls, effects)
		}
		assertLivePostgresOutboxState(t, ctx, ownerDB, intent.EventID, 2, true)
		assertLivePostgresOutboxDuplicate(t, ctx, store, entry, verified)
		assertLivePostgresOutboxIntentImmutable(t, ctx, ownerDB, intent)
	})

	t.Run("publisher failure is nacked then redelivered", func(t *testing.T) {
		nonce := livePostgresNonce(t)
		entry, verified := livePostgresVerifiedInput(t, nonce)
		intent := OutboxIntent{
			EventID: nonce, Destination: "cph.live.outbox",
			DeduplicationKey: fmt.Sprintf("failure-%x", nonce[:]),
			ContentType:      "application/cph.aiinfra.live-outbox.v1",
			Payload:          append([]byte("failure-redelivery/"), nonce[:]...),
		}
		applyLivePostgresOutboxIntent(t, ctx, store, entry, verified, intent)
		publisher.failNext(intent)
		dispatcher, err := NewOutboxDispatcher(ctx, runtimeDB, "worker-retry", publisher,
			WithOutboxBatchSize(1), WithOutboxLeaseDuration(time.Second),
			WithOutboxRetryBackoff(time.Millisecond, time.Second))
		if err != nil {
			t.Fatal(err)
		}
		report, err := dispatcher.DispatchBatch(ctx)
		if err == nil || report != (OutboxDispatchReport{Claimed: 1, Failed: 1}) {
			t.Fatalf("failed publication report=%+v err=%v", report, err)
		}
		awaitLivePostgresOutboxReady(t, ctx, ownerDB, intent.EventID)
		report, err = dispatcher.DispatchBatch(ctx)
		if err != nil || report != (OutboxDispatchReport{Claimed: 1, Delivered: 1}) {
			t.Fatalf("redelivery report=%+v err=%v", report, err)
		}
		calls, effects := publisher.counts(intent)
		if calls != 2 || effects != 1 {
			t.Fatalf("retry publisher calls=%d logical_effects=%d", calls, effects)
		}
		assertLivePostgresOutboxState(t, ctx, ownerDB, intent.EventID, 2, true)
	})

	t.Run("multiple workers skip a locked delivery row", func(t *testing.T) {
		firstNonce, secondNonce := livePostgresNonce(t), livePostgresNonce(t)
		firstEntry, firstVerified := livePostgresVerifiedInput(t, firstNonce)
		secondEntry, secondVerified := livePostgresVerifiedInput(t, secondNonce)
		first := OutboxIntent{
			EventID: firstNonce, Destination: "cph.live.outbox",
			DeduplicationKey: fmt.Sprintf("worker-a-%x", firstNonce[:]),
			ContentType:      "application/cph.aiinfra.live-outbox.v1",
			Payload:          append([]byte("worker-a/"), firstNonce[:]...),
		}
		second := OutboxIntent{
			EventID: secondNonce, Destination: "cph.live.outbox",
			DeduplicationKey: fmt.Sprintf("worker-b-%x", secondNonce[:]),
			ContentType:      "application/cph.aiinfra.live-outbox.v1",
			Payload:          append([]byte("worker-b/"), secondNonce[:]...),
		}
		applyLivePostgresOutboxIntent(t, ctx, store, firstEntry, firstVerified, first)
		applyLivePostgresOutboxIntent(t, ctx, store, secondEntry, secondVerified, second)
		if _, err := ownerDB.ExecContext(ctx, `
			INSERT INTO cph_aiinfra.ccse_outbox_delivery (event_id)
			VALUES ($1) ON CONFLICT (event_id) DO NOTHING`, first.EventID[:]); err != nil {
			t.Fatalf("initialize first multi-worker delivery row: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
		if _, err := ownerDB.ExecContext(ctx, `
			INSERT INTO cph_aiinfra.ccse_outbox_delivery (event_id)
			VALUES ($1) ON CONFLICT (event_id) DO NOTHING`, second.EventID[:]); err != nil {
			t.Fatalf("initialize second multi-worker delivery row: %v", err)
		}
		locker, err := ownerDB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
		if err != nil {
			t.Fatal(err)
		}
		locked := true
		defer func() {
			if locked {
				_ = locker.Rollback()
			}
		}()
		var lockedID []byte
		if err := locker.QueryRowContext(ctx, `
			SELECT event_id FROM cph_aiinfra.ccse_outbox_delivery
			WHERE event_id = $1 FOR UPDATE`, first.EventID[:]).Scan(&lockedID); err != nil {
			t.Fatalf("lock first worker delivery row: %v", err)
		}
		workerB, err := NewOutboxDispatcher(ctx, runtimeDB, "worker-b", publisher,
			WithOutboxBatchSize(1), WithOutboxLeaseDuration(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		report, err := workerB.DispatchBatch(ctx)
		if err != nil || report != (OutboxDispatchReport{Claimed: 1, Delivered: 1}) {
			t.Fatalf("worker B SKIP LOCKED report=%+v err=%v", report, err)
		}
		calls, effects := publisher.counts(second)
		if calls != 1 || effects != 1 {
			t.Fatalf("worker B published wrong unlocked intent calls=%d effects=%d", calls, effects)
		}
		if err := locker.Rollback(); err != nil {
			t.Fatal(err)
		}
		locked = false
		workerA, err := NewOutboxDispatcher(ctx, runtimeDB, "worker-a", publisher,
			WithOutboxBatchSize(1), WithOutboxLeaseDuration(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		report, err = workerA.DispatchBatch(ctx)
		if err != nil || report != (OutboxDispatchReport{Claimed: 1, Delivered: 1}) {
			t.Fatalf("worker A after unlock report=%+v err=%v", report, err)
		}
		calls, effects = publisher.counts(first)
		if calls != 1 || effects != 1 {
			t.Fatalf("worker A publish calls=%d effects=%d", calls, effects)
		}
	})
}

func assertLivePostgresOutboxTableCapabilityClosed(t *testing.T, ctx context.Context,
	runtimeDB *sql.DB) {
	t.Helper()
	var rows int64
	err := runtimeDB.QueryRowContext(ctx,
		"SELECT count(*) FROM cph_aiinfra.ccse_outbox_delivery").Scan(&rows)
	assertLivePostgresOutboxSQLState(t, err, "42501", "direct delivery SELECT")
	_, err = runtimeDB.ExecContext(ctx, `
		INSERT INTO cph_aiinfra.ccse_outbox_delivery (event_id) VALUES ($1)`,
		[]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	assertLivePostgresOutboxSQLState(t, err, "42501", "direct delivery INSERT")
	_, err = runtimeDB.ExecContext(ctx, `
		UPDATE cph_aiinfra.ccse_outbox_delivery SET delivered_at = clock_timestamp()`)
	assertLivePostgresOutboxSQLState(t, err, "42501", "direct delivery UPDATE")
}

func assertLivePostgresOutboxSQLState(t *testing.T, err error, code, operation string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s unexpectedly succeeded", operation)
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Fatalf("%s error=%v, want SQLSTATE %s", operation, err, code)
	}
}

func applyLivePostgresOutboxIntent(t *testing.T, ctx context.Context, store *ReplayStore,
	entry ccse.ReplayEntry, verified ccse.VerifiedRecord, intent OutboxIntent) {
	t.Helper()
	handlerCalls := 0
	decision, err := store.Execute(ctx, entry, verified,
		func(txCtx context.Context, _ ccse.VerifiedRecord) ([sha256.Size]byte, error) {
			handlerCalls++
			transaction, ok := Transaction(txCtx)
			if !ok {
				return [sha256.Size]byte{}, ErrTransactionRequired
			}
			return transaction.Complete(txCtx, DurableCompletion{
				ContentType:     "application/cph.aiinfra.live-outbox-result.v1",
				Payload:         append([]byte("outbox-result/"), intent.EventID[:]...),
				ExternalEffects: ExternalEffectsViaOutbox,
				Outbox:          []OutboxIntent{intent},
			})
		})
	if err != nil || decision.Status != ccse.ReplayApplied || handlerCalls != 1 {
		t.Fatalf("apply outbox intent decision=%+v handler_calls=%d err=%v",
			decision, handlerCalls, err)
	}
}

func assertLivePostgresOutboxDuplicate(t *testing.T, ctx context.Context, store *ReplayStore,
	entry ccse.ReplayEntry, verified ccse.VerifiedRecord) {
	t.Helper()
	handlerCalled := false
	decision, err := store.Execute(ctx, entry, verified,
		func(context.Context, ccse.VerifiedRecord) ([sha256.Size]byte, error) {
			handlerCalled = true
			return [sha256.Size]byte{}, errors.New("outbox duplicate invoked handler")
		})
	if err != nil || handlerCalled || decision.Status != ccse.ReplayDuplicateCompleted {
		t.Fatalf("outbox duplicate decision=%+v handler_called=%t err=%v",
			decision, handlerCalled, err)
	}
}

func awaitLivePostgresOutboxReady(t *testing.T, ctx context.Context, database *sql.DB,
	eventID [ccse.MessageIDSize]byte) {
	t.Helper()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		var ready bool
		err := database.QueryRowContext(ctx, `
			SELECT delivered_at IS NULL
			   AND next_attempt_at <= clock_timestamp()
			   AND (lease_until IS NULL OR lease_until <= clock_timestamp())
			FROM cph_aiinfra.ccse_outbox_delivery
			WHERE event_id = $1`, eventID[:]).Scan(&ready)
		if err != nil {
			t.Fatalf("inspect outbox readiness: %v", err)
		}
		if ready {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for outbox database-clock deadline: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}

func assertLivePostgresOutboxState(t *testing.T, ctx context.Context, database *sql.DB,
	eventID [ccse.MessageIDSize]byte, wantAttempts int64, wantDelivered bool) {
	t.Helper()
	var attempts int64
	var delivered bool
	if err := database.QueryRowContext(ctx, `
		SELECT attempt_count, delivered_at IS NOT NULL
		FROM cph_aiinfra.ccse_outbox_delivery WHERE event_id = $1`, eventID[:]).
		Scan(&attempts, &delivered); err != nil {
		t.Fatalf("read outbox delivery state: %v", err)
	}
	if attempts != wantAttempts || delivered != wantDelivered {
		t.Fatalf("outbox attempts=%d delivered=%t, want %d/%t",
			attempts, delivered, wantAttempts, wantDelivered)
	}
}

func assertLivePostgresOutboxIntentImmutable(t *testing.T, ctx context.Context,
	ownerDB *sql.DB, intent OutboxIntent) {
	t.Helper()
	_, err := ownerDB.ExecContext(ctx, `
		UPDATE cph_aiinfra.ccse_outbox_intent
		SET payload = $2, payload_digest = $3
		WHERE event_id = $1`, intent.EventID[:], []byte("tampered"), sha256Digest([]byte("tampered")))
	if err == nil {
		t.Fatal("immutable outbox intent accepted payload tamper")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55000" {
		t.Fatalf("immutable outbox tamper error=%v, want SQLSTATE 55000", err)
	}
	var storedPayload, storedDigest []byte
	if err := ownerDB.QueryRowContext(ctx, `
		SELECT payload, payload_digest FROM cph_aiinfra.ccse_outbox_intent
		WHERE event_id = $1`, intent.EventID[:]).Scan(&storedPayload, &storedDigest); err != nil {
		t.Fatalf("reload immutable outbox intent: %v", err)
	}
	digest := sha256.Sum256(intent.Payload)
	if !bytes.Equal(storedPayload, intent.Payload) || !bytes.Equal(storedDigest, digest[:]) {
		t.Fatal("failed tamper changed immutable outbox intent")
	}
}

type livePostgresIdempotentPublisher struct {
	mu       sync.Mutex
	calls    map[string]int
	effects  map[string][sha256.Size]byte
	failures map[string]int
}

func newLivePostgresIdempotentPublisher() *livePostgresIdempotentPublisher {
	return &livePostgresIdempotentPublisher{
		calls: make(map[string]int), effects: make(map[string][sha256.Size]byte),
		failures: make(map[string]int),
	}
}

func (publisher *livePostgresIdempotentPublisher) Publish(_ context.Context,
	publication OutboxPublication) error {
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	key := publication.Destination + "\x00" + publication.DeduplicationKey
	publisher.calls[key]++
	if publisher.failures[key] > 0 {
		publisher.failures[key]--
		return errors.New("injected remote publication failure")
	}
	digest := sha256.Sum256(publication.Payload)
	if prior, exists := publisher.effects[key]; exists {
		if prior != digest {
			return errors.New("deduplication key reused with different payload")
		}
		return nil
	}
	publisher.effects[key] = digest
	return nil
}

func (publisher *livePostgresIdempotentPublisher) failNext(intent OutboxIntent) {
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	publisher.failures[intent.Destination+"\x00"+intent.DeduplicationKey]++
}

func (publisher *livePostgresIdempotentPublisher) counts(intent OutboxIntent) (int, int) {
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	key := intent.Destination + "\x00" + intent.DeduplicationKey
	effects := 0
	if digest, ok := publisher.effects[key]; ok && bytes.Equal(digest[:], sha256Digest(intent.Payload)) {
		effects = 1
	}
	return publisher.calls[key], effects
}

func sha256Digest(payload []byte) []byte {
	digest := sha256.Sum256(payload)
	return digest[:]
}
