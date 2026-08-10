// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/aiinfra/ccse"
)

var testDriverSequence atomic.Uint64

type unitDriver struct {
	mu          sync.Mutex
	executions  []string
	replayEntry *ccse.ReplayEntry
	durable     *DurableResult
	durableHash [32]byte
	commits     int
	rollbacks   int
	sessionRole string
	resultError error
}

func (driverInstance *unitDriver) Open(string) (driver.Conn, error) {
	return &unitConn{driver: driverInstance}, nil
}

type unitConn struct{ driver *unitDriver }

func (connection *unitConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare is not supported")
}
func (connection *unitConn) Close() error { return nil }
func (connection *unitConn) Begin() (driver.Tx, error) {
	return &unitTx{driver: connection.driver}, nil
}
func (connection *unitConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return &unitTx{driver: connection.driver}, nil
}
func (connection *unitConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	connection.driver.mu.Lock()
	connection.driver.executions = append(connection.driver.executions, strings.TrimSpace(query))
	resultError := connection.driver.resultError
	connection.driver.mu.Unlock()
	if strings.Contains(query, "business.") && resultError != nil {
		return unitResult{err: resultError}, nil
	}
	return driver.RowsAffected(1), nil
}

type unitResult struct{ err error }

func (result unitResult) LastInsertId() (int64, error) { return 0, result.err }
func (result unitResult) RowsAffected() (int64, error) { return 0, result.err }
func (connection *unitConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	connection.driver.mu.Lock()
	replayEntry := connection.driver.replayEntry
	durable := connection.driver.durable
	durableHash := connection.driver.durableHash
	sessionRole := connection.driver.sessionRole
	connection.driver.mu.Unlock()
	if strings.Contains(query, "current_setting('session_replication_role')") {
		if sessionRole == "" {
			sessionRole = "origin"
		}
		return &unitRows{columns: []string{"current_setting"}, values: [][]driver.Value{{sessionRole}}}, nil
	}
	if replayEntry != nil {
		switch {
		case strings.Contains(query, "FROM cph_aiinfra.ccse_durable_result result"):
			rows := &unitRows{columns: []string{"result_digest", "content_type", "payload"}}
			if durable != nil {
				rows.values = [][]driver.Value{{durableHash[:], durable.ContentType, durable.Payload}}
			}
			return rows, nil
		case strings.Contains(query, "FROM cph_aiinfra.ccse_replay_head") && strings.Contains(query, "FOR UPDATE"):
			return &unitRows{
				columns: []string{"counter_kind", "replay_domain_id", "sender_identity", "environment", "chain_id", "genesis_hash"},
				values: [][]driver.Value{{
					int64(replayEntry.CounterKind), replayEntry.ReplayDomainID, replayEntry.SenderIdentity,
					replayEntry.Environment, replayEntry.ChainID[:], replayEntry.GenesisHash[:],
				}},
			}, nil
		case strings.Contains(query, "FROM cph_aiinfra.ccse_replay_inbox"):
			return &unitRows{columns: []string{
				"message_type_id", "schema_major", "schema_minor", "record_digest", "sequence", "expires_at_unix_nano", "outcome_digest",
			}}, nil
		case strings.Contains(query, "SELECT highest_sequence"):
			return &unitRows{columns: []string{"highest_sequence"}, values: [][]driver.Value{{nil}}}, nil
		}
	}
	if strings.Contains(query, "empty_business") {
		return &unitRows{columns: []string{"value"}}, nil
	}
	return &unitRows{columns: []string{"value"}, values: [][]driver.Value{{int64(1)}}}, nil
}

type unitTx struct{ driver *unitDriver }

func (transaction *unitTx) Commit() error {
	transaction.driver.mu.Lock()
	transaction.driver.commits++
	transaction.driver.mu.Unlock()
	return nil
}
func (transaction *unitTx) Rollback() error {
	transaction.driver.mu.Lock()
	transaction.driver.rollbacks++
	transaction.driver.mu.Unlock()
	return nil
}

type unitRows struct {
	columns []string
	values  [][]driver.Value
	index   int
}

func (rows *unitRows) Columns() []string { return rows.columns }
func (rows *unitRows) Close() error      { return nil }
func (rows *unitRows) Next(destination []driver.Value) error {
	if rows.index >= len(rows.values) {
		return io.EOF
	}
	copy(destination, rows.values[rows.index])
	rows.index++
	return nil
}

func newUnitTransaction(t *testing.T, statements map[string]StatementAccess) (context.Context, atomicTxView, *transactionState, *unitDriver) {
	t.Helper()
	database, driverInstance := newUnitDatabase(t)
	tx, err := database.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	store := &ReplayStore{db: database, statements: statements}
	state := &transactionState{store: store, tx: tx, entry: testReplayEntry()}
	ctx := context.WithValue(context.Background(), replayTransactionContextKey{}, replayTransactionContext{store: store, state: state})
	transaction, ok := Transaction(ctx)
	if !ok {
		t.Fatal("Transaction returned false")
	}
	return ctx, transaction.(atomicTxView), state, driverInstance
}

func newUnitDatabase(t *testing.T) (*sql.DB, *unitDriver) {
	t.Helper()
	driverInstance := &unitDriver{}
	name := fmt.Sprintf("cph-aiinfra-postgres-unit-%d", testDriverSequence.Add(1))
	sql.Register(name, driverInstance)
	database, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database, driverInstance
}

func TestUnitOfWorkRequiresDurableCompletionAndMatchingDigest(t *testing.T) {
	ctx, transaction, state, driverInstance := newUnitTransaction(t, nil)
	if err := state.finish([32]byte{1}); !errors.Is(err, ErrCompletionRequired) {
		t.Fatalf("finish without completion error = %v", err)
	}
	completion := DurableCompletion{
		ContentType:     "application/cph.test+json",
		Payload:         []byte(`{"ok":true}`),
		ExternalEffects: NoExternalEffects,
	}
	digest, err := transaction.Complete(ctx, completion)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.finish([32]byte{9}); !errors.Is(err, ErrOutcomeMismatch) {
		t.Fatalf("mismatched digest error = %v", err)
	}
	if err := state.finish(digest); err != nil {
		t.Fatal(err)
	}
	driverInstance.mu.Lock()
	defer driverInstance.mu.Unlock()
	if len(driverInstance.executions) != 1 || !strings.Contains(driverInstance.executions[0], "ccse_durable_result") {
		t.Fatalf("executions = %#v", driverInstance.executions)
	}
}

func TestUnitOfWorkPersistsEveryOutboxIntentBeforeSealing(t *testing.T) {
	ctx, transaction, state, driverInstance := newUnitTransaction(t, nil)
	completion := DurableCompletion{
		ContentType:     "application/cph.test+json",
		Payload:         []byte(`{"ok":true}`),
		ExternalEffects: ExternalEffectsViaOutbox,
		Outbox: []OutboxIntent{
			{EventID: [16]byte{1}, Destination: "cph.test", DeduplicationKey: "one", ContentType: "application/cph.event", Payload: []byte("one")},
			{EventID: [16]byte{2}, Destination: "cph.test", DeduplicationKey: "two", ContentType: "application/cph.event", Payload: []byte("two")},
		},
	}
	digest, err := transaction.Complete(ctx, completion)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.finish(digest); err != nil {
		t.Fatal(err)
	}
	driverInstance.mu.Lock()
	defer driverInstance.mu.Unlock()
	if len(driverInstance.executions) != 3 {
		t.Fatalf("execution count = %d, want durable result + 2 outbox rows", len(driverInstance.executions))
	}
}

func TestUnitOfWorkRejectsOpenRowsAndUnlistedSQL(t *testing.T) {
	query := "SELECT value FROM business.job"
	ctx, transaction, state, _ := newUnitTransaction(t, map[string]StatementAccess{query: StatementQuery})
	rows, err := transaction.QueryContext(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	completion := DurableCompletion{ContentType: "application/cph.test", ExternalEffects: NoExternalEffects}
	if _, err := transaction.Complete(ctx, completion); !errors.Is(err, ErrRowsStillOpen) {
		t.Fatalf("completion with open rows error = %v", err)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if err := state.finish([32]byte{1}); !errors.Is(err, ErrTransactionPoisoned) {
		t.Fatalf("ignored open-row error = %v", err)
	}

	ctx, transaction, state, _ = newUnitTransaction(t, nil)
	if _, err := transaction.ExecContext(ctx, "COMMIT"); !errors.Is(err, ErrStatementNotAllowed) {
		t.Fatalf("unlisted statement error = %v", err)
	}
	if err := state.finish([32]byte{1}); !errors.Is(err, ErrTransactionPoisoned) {
		t.Fatalf("ignored SQL policy error = %v", err)
	}
}

func TestUnitOfWorkPoisonsDeferredResultInspectionError(t *testing.T) {
	query := "UPDATE business.job SET state = $1 WHERE id = $2"
	ctx, transaction, _, driverInstance := newUnitTransaction(t, map[string]StatementAccess{query: StatementExec})
	driverInstance.resultError = errors.New("rows affected unavailable")
	result, err := transaction.ExecContext(ctx, query, "done", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := result.RowsAffected(); err == nil {
		t.Fatal("RowsAffected unexpectedly succeeded")
	}
	if _, err := transaction.Complete(ctx, DurableCompletion{
		ContentType:     "application/cph.test",
		ExternalEffects: NoExternalEffects,
	}); !errors.Is(err, ErrTransactionPoisoned) {
		t.Fatalf("Complete error = %v, want %v", err, ErrTransactionPoisoned)
	}
}

func TestUnitOfWorkChecksSessionRoleAtCompletion(t *testing.T) {
	ctx, transaction, _, driverInstance := newUnitTransaction(t, nil)
	driverInstance.sessionRole = "replica"
	if _, err := transaction.Complete(ctx, DurableCompletion{
		ContentType:     "application/cph.test",
		ExternalEffects: NoExternalEffects,
	}); !errors.Is(err, ErrUnsafeSessionRole) {
		t.Fatalf("Complete error = %v, want %v", err, ErrUnsafeSessionRole)
	}
}

func TestQueryRowNoRowsMayBeHandledBeforeCompletion(t *testing.T) {
	query := "SELECT value FROM empty_business"
	ctx, transaction, state, _ := newUnitTransaction(t, map[string]StatementAccess{query: StatementQuery})
	var value int64
	row := transaction.QueryRowContext(ctx, query)
	if err := row.Scan(&value); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("Scan error = %v", err)
	}
	if err := row.AcceptNoRows(); err != nil {
		t.Fatal(err)
	}
	digest, err := transaction.Complete(ctx, DurableCompletion{ContentType: "application/cph.test", ExternalEffects: NoExternalEffects})
	if err != nil {
		t.Fatal(err)
	}
	if err := state.finish(digest); err != nil {
		t.Fatal(err)
	}
}

func TestQueryRowNoRowsMustBeAcknowledged(t *testing.T) {
	query := "SELECT value FROM empty_business"
	ctx, transaction, _, _ := newUnitTransaction(t, map[string]StatementAccess{query: StatementQuery})
	var value int64
	if err := transaction.QueryRowContext(ctx, query).Scan(&value); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("Scan error = %v", err)
	}
	if _, err := transaction.Complete(ctx, DurableCompletion{
		ContentType:     "application/cph.test",
		ExternalEffects: NoExternalEffects,
	}); !errors.Is(err, ErrNoRowsUnacknowledged) {
		t.Fatalf("Complete error = %v, want %v", err, ErrNoRowsUnacknowledged)
	}
}

func TestQueryRowsMayBeClosedOrExhaustedBeforeCompletion(t *testing.T) {
	query := "SELECT value FROM business.job"
	for _, test := range []struct {
		name    string
		consume func(*testing.T, Rows)
	}{
		{
			name: "closed",
			consume: func(t *testing.T, rows Rows) {
				t.Helper()
				if err := rows.Close(); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "exhausted",
			consume: func(t *testing.T, rows Rows) {
				t.Helper()
				var value int64
				if !rows.Next() {
					t.Fatal("query returned no row")
				}
				if err := rows.Scan(&value); err != nil {
					t.Fatal(err)
				}
				if value != 1 {
					t.Fatalf("value = %d, want 1", value)
				}
				if rows.Next() {
					t.Fatal("query returned an unexpected second row")
				}
				if err := rows.Err(); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, transaction, state, _ := newUnitTransaction(t, map[string]StatementAccess{query: StatementQuery})
			rows, err := transaction.QueryContext(ctx, query)
			if err != nil {
				t.Fatal(err)
			}
			test.consume(t, rows)
			digest, err := transaction.Complete(ctx, DurableCompletion{
				ContentType:     "application/cph.test",
				ExternalEffects: NoExternalEffects,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := state.finish(digest); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type captureReplayStore struct {
	entry    ccse.ReplayEntry
	verified ccse.VerifiedRecord
}

func (store *captureReplayStore) Execute(_ context.Context, entry ccse.ReplayEntry, verified ccse.VerifiedRecord, _ ccse.ReplayHandler) (ccse.ReplayDecision, error) {
	store.entry = entry
	store.verified = verified
	return ccse.ReplayDecision{Status: ccse.ReplayApplied, OutcomeDigest: [32]byte{1}}, nil
}

func verifiedReplayInput(t *testing.T) (ccse.ReplayEntry, ccse.VerifiedRecord) {
	t.Helper()
	const messageTypeID uint32 = 65537
	protocolVersion := ccse.Version{Major: 1}
	schemaVersion := ccse.Version{Major: 1}
	issuedAt := time.Unix(1_800_000_000, 0).UTC()
	expiresAt := issuedAt.Add(5 * time.Minute)
	seed := [ed25519.SeedSize]byte{1, 2, 3, 4}
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	chainID := [32]byte{31: 1}
	genesisHash := [32]byte{0: 2}
	domain := ccse.Domain{
		Purpose:            "cph.test.postgres-uow",
		SenderIdentity:     "spiffe://test/service/one",
		Audience:           []string{"cph.test.receiver"},
		ChainID:            chainID,
		GenesisHash:        genesisHash,
		Environment:        "test",
		ProtocolVersion:    protocolVersion,
		SchemaVersion:      schemaVersion,
		SignatureAlgorithm: ccse.SignatureAlgorithmEd25519,
		SignatureKeyID:     "test-key-1",
		IssuedAtUnixNano:   issuedAt.UnixNano(),
		ExpiresAtUnixNano:  expiresAt.UnixNano(),
		CounterKind:        ccse.CounterSequence,
		Counter:            1,
		ReplayDomainID:     "cph.test.postgres-uow",
	}
	envelope := ccse.Envelope{
		ProtocolVersion:    protocolVersion,
		SchemaVersion:      schemaVersion,
		MessageID:          [16]byte{1},
		CorrelationID:      [16]byte{2},
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
	record, err := ccse.NewRecord(messageTypeID, schemaVersion, domain, envelope, []byte{0, 0, 0, 1})
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
		Handle: func(context.Context, ccse.VerifiedRecord) ([32]byte, error) { return [32]byte{1}, nil },
	}
	if _, err := verifier.Verify(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	return capture.entry, capture.verified
}

func TestReplayStoreExecuteCommitsOnlyACompletedUnitOfWork(t *testing.T) {
	entry, verified := verifiedReplayInput(t)
	database, driverInstance := newUnitDatabase(t)
	driverInstance.replayEntry = &entry
	store := &ReplayStore{db: database, statements: make(map[string]StatementAccess)}
	decision, err := store.Execute(context.Background(), entry, verified, func(ctx context.Context, _ ccse.VerifiedRecord) ([32]byte, error) {
		transaction, ok := Transaction(ctx)
		if !ok {
			t.Fatal("handler did not receive the unit of work")
		}
		return transaction.Complete(ctx, DurableCompletion{
			ContentType:     "application/cph.test",
			Payload:         []byte("result"),
			ExternalEffects: NoExternalEffects,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Status != ccse.ReplayApplied || decision.OutcomeDigest == [32]byte{} {
		t.Fatalf("decision = %+v", decision)
	}
	driverInstance.mu.Lock()
	defer driverInstance.mu.Unlock()
	if driverInstance.commits != 1 || driverInstance.rollbacks != 0 {
		t.Fatalf("commits=%d rollbacks=%d", driverInstance.commits, driverInstance.rollbacks)
	}
	wantFragments := []string{
		"SET LOCAL search_path = pg_catalog",
		"ccse_replay_head",
		"ccse_durable_result",
		"ccse_replay_inbox",
		"highest_sequence",
	}
	joined := strings.Join(driverInstance.executions, "\n")
	for _, fragment := range wantFragments {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("execution log lacks %q: %s", fragment, joined)
		}
	}
}

func TestReplayStoreExecuteRollsBackHandlerWithoutDurableCompletion(t *testing.T) {
	entry, verified := verifiedReplayInput(t)
	database, driverInstance := newUnitDatabase(t)
	driverInstance.replayEntry = &entry
	store := &ReplayStore{db: database, statements: make(map[string]StatementAccess)}
	_, err := store.Execute(context.Background(), entry, verified, func(ctx context.Context, _ ccse.VerifiedRecord) ([32]byte, error) {
		if _, ok := Transaction(ctx); !ok {
			t.Fatal("handler did not receive the unit of work")
		}
		return [32]byte{1}, nil
	})
	if !errors.Is(err, ErrCompletionRequired) {
		t.Fatalf("Execute error = %v", err)
	}
	driverInstance.mu.Lock()
	defer driverInstance.mu.Unlock()
	if driverInstance.commits != 0 || driverInstance.rollbacks != 1 {
		t.Fatalf("commits=%d rollbacks=%d", driverInstance.commits, driverInstance.rollbacks)
	}
}

func TestReplayStoreRejectsBackgroundNestedExecute(t *testing.T) {
	entry, verified := verifiedReplayInput(t)
	database, driverInstance := newUnitDatabase(t)
	driverInstance.replayEntry = &entry
	store := &ReplayStore{db: database, statements: make(map[string]StatementAccess)}
	decision, err := store.Execute(context.Background(), entry, verified, func(ctx context.Context, _ ccse.VerifiedRecord) ([32]byte, error) {
		_, nestedErr := store.Execute(context.Background(), entry, verified, func(context.Context, ccse.VerifiedRecord) ([32]byte, error) {
			return [32]byte{1}, nil
		})
		if !errors.Is(nestedErr, ccse.ErrReplayReentrant) || !errors.Is(nestedErr, ErrUnitOfWorkActive) {
			t.Fatalf("nested Execute error = %v", nestedErr)
		}
		transaction, ok := Transaction(ctx)
		if !ok {
			t.Fatal("handler did not receive the unit of work")
		}
		return transaction.Complete(ctx, DurableCompletion{
			ContentType:     "application/cph.test",
			ExternalEffects: NoExternalEffects,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Status != ccse.ReplayApplied {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestReplayStoreSingleFlightGuardIsGoroutineSafe(t *testing.T) {
	entry, verified := verifiedReplayInput(t)
	database, driverInstance := newUnitDatabase(t)
	driverInstance.replayEntry = &entry
	store := &ReplayStore{db: database, statements: make(map[string]StatementAccess)}
	entered := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		_, err := store.Execute(context.Background(), entry, verified, func(ctx context.Context, _ ccse.VerifiedRecord) ([32]byte, error) {
			close(entered)
			<-release
			transaction, ok := Transaction(ctx)
			if !ok {
				return [32]byte{}, ErrTransactionRequired
			}
			return transaction.Complete(ctx, DurableCompletion{
				ContentType:     "application/cph.test",
				ExternalEffects: NoExternalEffects,
			})
		})
		finished <- err
	}()
	<-entered
	_, overlapErr := store.Execute(context.Background(), entry, verified, func(context.Context, ccse.VerifiedRecord) ([32]byte, error) {
		return [32]byte{1}, nil
	})
	if !errors.Is(overlapErr, ccse.ErrReplayReentrant) || !errors.Is(overlapErr, ErrUnitOfWorkActive) {
		t.Fatalf("overlapping Execute error = %v", overlapErr)
	}
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}

func TestReplayStoreRejectsReplicaSessionRole(t *testing.T) {
	entry, verified := verifiedReplayInput(t)
	database, driverInstance := newUnitDatabase(t)
	driverInstance.replayEntry = &entry
	driverInstance.sessionRole = "replica"
	store := &ReplayStore{db: database, statements: make(map[string]StatementAccess)}
	_, err := store.Execute(context.Background(), entry, verified, func(context.Context, ccse.VerifiedRecord) ([32]byte, error) {
		t.Fatal("unsafe session reached handler")
		return [32]byte{}, nil
	})
	if !errors.Is(err, ErrUnsafeSessionRole) {
		t.Fatalf("Execute error = %v, want %v", err, ErrUnsafeSessionRole)
	}
}

func TestLoadDurableResultRehashesExactReplayResult(t *testing.T) {
	entry, _ := verifiedReplayInput(t)
	database, driverInstance := newUnitDatabase(t)
	driverInstance.replayEntry = &entry
	store := &ReplayStore{db: database, statements: make(map[string]StatementAccess)}
	stored := &DurableResult{ContentType: "application/cph.test", Payload: []byte("result")}
	expected := DurableResultDigest(stored.ContentType, stored.Payload)
	driverInstance.durable = stored
	driverInstance.durableHash = expected
	result, err := store.LoadDurableResult(context.Background(), entry, expected)
	if err != nil {
		t.Fatal(err)
	}
	if result.ContentType != stored.ContentType || string(result.Payload) != string(stored.Payload) {
		t.Fatalf("result = %+v", result)
	}
	stored.Payload[0] ^= 1
	if result.Payload[0] == stored.Payload[0] {
		t.Fatal("LoadDurableResult returned driver-owned payload bytes")
	}
	if _, err := store.LoadDurableResult(context.Background(), entry, expected); !errors.Is(err, ErrDurableResultCorrupt) {
		t.Fatalf("corrupt result error = %v", err)
	}
}
