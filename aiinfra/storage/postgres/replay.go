// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

// Package postgres contains PostgreSQL authoritative-state adapters for the
// CPH AI Infrastructure Extension. It is not imported by the validator binary.
package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"

	"github.com/cypherium/cypher/aiinfra/ccse"
)

var (
	ErrReplayEntryMismatch  = errors.New("aiinfra postgres: replay entry does not match verified record")
	ErrReplayScopeCollision = errors.New("aiinfra postgres: replay scope digest collision")
	ErrTransactionRequired  = errors.New("aiinfra postgres: handler did not claim the authoritative transaction")
	ErrStatementNotAllowed  = errors.New("aiinfra postgres: SQL statement is not in the immutable allowlist")
	ErrTransactionSealed    = errors.New("aiinfra postgres: authoritative transaction is already sealed")
	ErrTransactionPoisoned  = errors.New("aiinfra postgres: authoritative transaction observed an ignored error")
	ErrCompletionRequired   = errors.New("aiinfra postgres: durable result and effect disposition are required")
	ErrCompletionDuplicate  = errors.New("aiinfra postgres: durable completion was already recorded")
	ErrOutcomeMismatch      = errors.New("aiinfra postgres: handler outcome digest does not match the durable result")
	ErrInvalidCompletion    = errors.New("aiinfra postgres: invalid durable completion")
	ErrRowsStillOpen        = errors.New("aiinfra postgres: query rows must be consumed or closed before completion")
	ErrDurableResultMissing = errors.New("aiinfra postgres: durable result is missing")
	ErrDurableResultCorrupt = errors.New("aiinfra postgres: durable result does not match its committed digest")
	ErrUnitOfWorkActive     = errors.New("aiinfra postgres: another unit of work is active on this store")
	ErrUnsafeSessionRole    = errors.New("aiinfra postgres: session_replication_role is not origin")
	ErrNoRowsUnacknowledged = errors.New("aiinfra postgres: sql.ErrNoRows must be acknowledged explicitly")
	ErrRowAlreadyConsumed   = errors.New("aiinfra postgres: query row was already consumed")
)

const (
	replayScopeMagic         = "CPH-AIIE-CCSE-REPLAY-SCOPE-V1\x00"
	durableResultMagic       = "CPH-AIIE-DURABLE-RESULT-V1\x00"
	maxDurablePayloadBytes   = 1 << 20
	maxContentTypeBytes      = 255
	maxDestinationBytes      = 255
	maxDeduplicationKeyBytes = 1024
	maxOutboxIntents         = 256
	maxOutboxPayloadBytes    = 4 << 20
)

// StatementAccess fixes how an allowlisted statement may be used. The SQL text
// is compared byte-for-byte after trimming leading and trailing whitespace;
// runtime SQL assembled from untrusted input is therefore never authorized.
type StatementAccess uint8

const (
	StatementExec StatementAccess = 1 << iota
	StatementQuery
)

// AllowedStatement is a deployment-time SQL capability. A service should keep
// this catalog in source control beside the code that owns the corresponding
// canonical state transition.
type AllowedStatement struct {
	SQL    string
	Access StatementAccess
}

// StoreOption configures immutable ReplayStore policy.
type StoreOption func(*storeConfig) error

type storeConfig struct {
	statements map[string]StatementAccess
}

// WithAllowedStatements adds exact business-state SQL to the transaction
// capability set. Transaction-control, DDL, session, COPY, listener and
// cph_aiinfra-internal statements are rejected even when listed.
func WithAllowedStatements(statements ...AllowedStatement) StoreOption {
	frozen := append([]AllowedStatement(nil), statements...)
	return func(config *storeConfig) error {
		for _, statement := range frozen {
			query := strings.TrimSpace(statement.SQL)
			if query == "" || (statement.Access != StatementExec && statement.Access != StatementQuery) {
				return fmt.Errorf("%w: malformed statement capability", ErrStatementNotAllowed)
			}
			if err := validateBusinessSQL(query, statement.Access); err != nil {
				return err
			}
			if prior, exists := config.statements[query]; exists && prior != statement.Access {
				return fmt.Errorf("%w: conflicting access for statement", ErrStatementNotAllowed)
			}
			config.statements[query] = statement.Access
		}
		return nil
	}
}

// ReplayStore implements ccse.ReplayStore with one PostgreSQL serializable
// transaction. The handler obtains that transaction through Transaction and
// must write its business state, durable result, and outbox before returning.
type ReplayStore struct {
	db            BeginTxer
	statements    map[string]StatementAccess
	executeActive atomic.Bool
}

// NewReplayStore verifies the exact schema and least-privilege runtime role,
// then creates a durable replay adapter with a closed-by-default SQL capability
// set. Construction fails closed if migration or role policy is incomplete.
func NewReplayStore(ctx context.Context, db BeginTxer, options ...StoreOption) (*ReplayStore, error) {
	if db == nil {
		return nil, ErrDatabaseRequired
	}
	config := storeConfig{statements: make(map[string]StatementAccess)}
	for _, option := range options {
		if option == nil {
			return nil, fmt.Errorf("%w: nil store option", ErrStatementNotAllowed)
		}
		if err := option(&config); err != nil {
			return nil, err
		}
	}
	if err := VerifyReplayStore(ctx, db); err != nil {
		return nil, err
	}
	statements := cloneStatementPolicy(config.statements)
	return &ReplayStore{db: db, statements: statements}, nil
}

func cloneStatementPolicy(source map[string]StatementAccess) map[string]StatementAccess {
	clone := make(map[string]StatementAccess, len(source))
	for query, access := range source {
		clone[query] = access
	}
	return clone
}

type replayTransactionContextKey struct{}

type replayTransactionContext struct {
	store *ReplayStore
	state *transactionState
}

// AtomicTx deliberately omits Commit, Rollback and Prepare. ReplayStore alone
// owns the boundary. Business SQL must be registered at construction time and
// Complete must durably bind the result and external-effect disposition.
type AtomicTx interface {
	ExecContext(context.Context, string, ...interface{}) (Result, error)
	QueryContext(context.Context, string, ...interface{}) (Rows, error)
	QueryRowContext(context.Context, string, ...interface{}) RowScanner
	Complete(context.Context, DurableCompletion) ([sha256.Size]byte, error)
}

// Rows is the guarded streaming-query surface. Errors and closure are observed
// by the unit of work; Complete fails while any Rows or Row remains open.
type Rows interface {
	Next() bool
	Scan(...interface{}) error
	Err() error
	Close() error
}

// Result prevents database/sql driver errors discovered after ExecContext from
// escaping the unit-of-work poison state.
type Result interface {
	LastInsertId() (int64, error)
	RowsAffected() (int64, error)
}

// RowScanner requires sql.ErrNoRows to be acknowledged explicitly. A caller
// that expects an optional row must call AcceptNoRows after Scan returns
// sql.ErrNoRows; otherwise the open row prevents completion.
type RowScanner interface {
	Scan(...interface{}) error
	AcceptNoRows() error
}

// ExternalEffectDisposition makes the handler explicitly state whether the
// operation has no external effect or whether every effect is represented by a
// durable outbox intent.
type ExternalEffectDisposition uint8

const (
	NoExternalEffects ExternalEffectDisposition = iota + 1
	ExternalEffectsViaOutbox
)

// DurableCompletion is the result committed with the replay inbox entry.
// Payload is copied into PostgreSQL and its domain-separated digest is returned
// by Complete. ContentType is a stable application media type, not user input.
type DurableCompletion struct {
	ContentType     string
	Payload         []byte
	ExternalEffects ExternalEffectDisposition
	Outbox          []OutboxIntent
}

// DurableResult is the response payload recovered for either an applied
// request or an exact completed redelivery. Returned payload bytes are owned by
// the caller.
type DurableResult struct {
	ContentType string
	Payload     []byte
}

// OutboxIntent is an immutable, deduplicated external publication intent.
// EventID is globally unique; Destination and DeduplicationKey jointly prevent
// a logical effect from being enqueued twice.
type OutboxIntent struct {
	EventID          [ccse.MessageIDSize]byte
	Destination      string
	DeduplicationKey string
	ContentType      string
	Payload          []byte
}

type transactionState struct {
	mu        sync.Mutex
	store     *ReplayStore
	tx        *sql.Tx
	scope     [sha256.Size]byte
	entry     ccse.ReplayEntry
	claimed   bool
	completed bool
	sealed    bool
	poisoned  error
	outcome   [sha256.Size]byte
	openRows  uint64
	noRows    uint64
}

type atomicTxView struct {
	state *transactionState
}

func (view atomicTxView) ExecContext(ctx context.Context, query string, args ...interface{}) (Result, error) {
	state, err := view.lockForStatement(ctx, query, StatementExec)
	if err != nil {
		return nil, err
	}
	defer state.mu.Unlock()
	result, err := state.tx.ExecContext(ctx, strings.TrimSpace(query), args...)
	if err != nil {
		state.poisoned = err
		return nil, err
	}
	return &guardedResult{state: state, result: result}, nil
}

type guardedResult struct {
	state  *transactionState
	result sql.Result
	mu     sync.Mutex
}

func (result *guardedResult) LastInsertId() (int64, error) {
	result.mu.Lock()
	defer result.mu.Unlock()
	value, err := result.result.LastInsertId()
	result.observe(err)
	return value, err
}

func (result *guardedResult) RowsAffected() (int64, error) {
	result.mu.Lock()
	defer result.mu.Unlock()
	value, err := result.result.RowsAffected()
	result.observe(err)
	return value, err
}

func (result *guardedResult) observe(err error) {
	if err == nil {
		return
	}
	result.state.mu.Lock()
	if result.state.poisoned == nil {
		result.state.poisoned = err
	}
	result.state.mu.Unlock()
}

func (view atomicTxView) QueryContext(ctx context.Context, query string, args ...interface{}) (Rows, error) {
	state, err := view.lockForStatement(ctx, query, StatementQuery)
	if err != nil {
		return nil, err
	}
	defer state.mu.Unlock()
	rows, err := state.tx.QueryContext(ctx, strings.TrimSpace(query), args...)
	if err != nil {
		state.poisoned = err
		return nil, err
	}
	state.openRows++
	return &guardedRows{state: state, rows: rows}, nil
}

func (view atomicTxView) QueryRowContext(ctx context.Context, query string, args ...interface{}) RowScanner {
	state, err := view.lockForStatement(ctx, query, StatementQuery)
	if err != nil {
		return errorRow{err: err}
	}
	defer state.mu.Unlock()
	state.openRows++
	return &guardedRow{state: state, row: state.tx.QueryRowContext(ctx, strings.TrimSpace(query), args...)}
}

func (view atomicTxView) lockForStatement(ctx context.Context, query string, access StatementAccess) (*transactionState, error) {
	state := view.state
	if state == nil || !contextOwnsTransaction(ctx, state) {
		if state != nil {
			state.mu.Lock()
			if state.poisoned == nil {
				state.poisoned = ErrTransactionRequired
			}
			state.mu.Unlock()
		}
		return nil, ErrTransactionRequired
	}
	state.mu.Lock()
	if state.sealed {
		state.poisoned = ErrTransactionSealed
		state.mu.Unlock()
		return nil, ErrTransactionSealed
	}
	if state.poisoned != nil {
		state.mu.Unlock()
		return nil, fmt.Errorf("%w: %v", ErrTransactionPoisoned, state.poisoned)
	}
	if state.openRows != 0 {
		if state.noRows != 0 {
			state.poisoned = ErrNoRowsUnacknowledged
		} else {
			state.poisoned = ErrRowsStillOpen
		}
		state.mu.Unlock()
		return nil, state.poisoned
	}
	query = strings.TrimSpace(query)
	allowed := state.store.statements[query]
	if allowed&access == 0 {
		err := fmt.Errorf("%w: sha256=%x", ErrStatementNotAllowed, sha256.Sum256([]byte(query)))
		state.poisoned = err
		state.mu.Unlock()
		return nil, err
	}
	return state, nil
}

type errorRow struct{ err error }

func (row errorRow) Scan(...interface{}) error { return row.err }
func (row errorRow) AcceptNoRows() error       { return row.err }

type guardedRow struct {
	state          *transactionState
	row            *sql.Row
	scanned        bool
	awaitingNoRows bool
	mu             sync.Mutex
}

func (row *guardedRow) Scan(dest ...interface{}) error {
	row.mu.Lock()
	defer row.mu.Unlock()
	if row.scanned {
		row.poison(ErrRowAlreadyConsumed)
		return ErrRowAlreadyConsumed
	}
	row.scanned = true
	err := row.row.Scan(dest...)
	row.state.mu.Lock()
	if errors.Is(err, sql.ErrNoRows) {
		row.awaitingNoRows = true
		row.state.noRows++
	} else {
		if err != nil && row.state.poisoned == nil {
			row.state.poisoned = err
		}
		if row.state.openRows > 0 {
			row.state.openRows--
		}
	}
	row.state.mu.Unlock()
	return err
}

func (row *guardedRow) AcceptNoRows() error {
	row.mu.Lock()
	defer row.mu.Unlock()
	if !row.scanned || !row.awaitingNoRows {
		row.poison(ErrNoRowsUnacknowledged)
		return ErrNoRowsUnacknowledged
	}
	row.state.mu.Lock()
	if row.state.openRows > 0 {
		row.state.openRows--
	}
	if row.state.noRows > 0 {
		row.state.noRows--
	}
	row.state.mu.Unlock()
	row.awaitingNoRows = false
	return nil
}

func (row *guardedRow) poison(err error) {
	row.state.mu.Lock()
	if row.state.poisoned == nil {
		row.state.poisoned = err
	}
	row.state.mu.Unlock()
}

type guardedRows struct {
	state *transactionState
	rows  *sql.Rows
	once  sync.Once
	mu    sync.Mutex
}

func (rows *guardedRows) Next() bool {
	rows.mu.Lock()
	defer rows.mu.Unlock()
	next := rows.rows.Next()
	if !next {
		rows.observeAndClose(rows.rows.Err())
	}
	return next
}

func (rows *guardedRows) Scan(dest ...interface{}) error {
	rows.mu.Lock()
	defer rows.mu.Unlock()
	err := rows.rows.Scan(dest...)
	if err != nil {
		rows.state.mu.Lock()
		if rows.state.poisoned == nil {
			rows.state.poisoned = err
		}
		rows.state.mu.Unlock()
	}
	return err
}

func (rows *guardedRows) Err() error {
	rows.mu.Lock()
	defer rows.mu.Unlock()
	err := rows.rows.Err()
	if err != nil {
		rows.state.mu.Lock()
		if rows.state.poisoned == nil {
			rows.state.poisoned = err
		}
		rows.state.mu.Unlock()
	}
	return err
}

func (rows *guardedRows) Close() error {
	rows.mu.Lock()
	defer rows.mu.Unlock()
	err := rows.rows.Close()
	observed := err
	if observed == nil {
		observed = rows.rows.Err()
	}
	rows.observeAndClose(observed)
	return err
}

func (rows *guardedRows) observeAndClose(err error) {
	rows.once.Do(func() {
		rows.state.mu.Lock()
		if err != nil && rows.state.poisoned == nil {
			rows.state.poisoned = err
		}
		if rows.state.openRows > 0 {
			rows.state.openRows--
		}
		rows.state.mu.Unlock()
	})
}

func (view atomicTxView) Complete(ctx context.Context, completion DurableCompletion) ([sha256.Size]byte, error) {
	state := view.state
	if state == nil || !contextOwnsTransaction(ctx, state) {
		if state != nil {
			state.mu.Lock()
			if state.poisoned == nil {
				state.poisoned = ErrTransactionRequired
			}
			state.mu.Unlock()
		}
		return [sha256.Size]byte{}, ErrTransactionRequired
	}
	if err := validateCompletion(completion); err != nil {
		state.mu.Lock()
		if state.poisoned == nil {
			state.poisoned = err
		}
		state.mu.Unlock()
		return [sha256.Size]byte{}, err
	}

	state.mu.Lock()
	defer state.mu.Unlock()
	if state.sealed || state.completed {
		state.poisoned = ErrCompletionDuplicate
		return [sha256.Size]byte{}, ErrCompletionDuplicate
	}
	if state.poisoned != nil {
		return [sha256.Size]byte{}, fmt.Errorf("%w: %v", ErrTransactionPoisoned, state.poisoned)
	}
	if state.openRows != 0 {
		if state.noRows != 0 {
			state.poisoned = ErrNoRowsUnacknowledged
		} else {
			state.poisoned = ErrRowsStillOpen
		}
		return [sha256.Size]byte{}, state.poisoned
	}
	if err := assertSessionReplicationOrigin(ctx, state.tx); err != nil {
		state.poisoned = err
		return [sha256.Size]byte{}, err
	}
	outcome := DurableResultDigest(completion.ContentType, completion.Payload)
	if _, err := state.tx.ExecContext(ctx, `
		INSERT INTO cph_aiinfra.ccse_durable_result
			(scope_sha256, message_id, result_digest, content_type, payload, external_effect_mode)
		VALUES ($1, $2, $3, $4, $5, $6)`, state.scope[:], state.entry.MessageID[:], outcome[:],
		completion.ContentType, completion.Payload, int16(completion.ExternalEffects)); err != nil {
		state.poisoned = err
		return [sha256.Size]byte{}, fmt.Errorf("aiinfra postgres: insert durable result: %w", err)
	}
	for _, intent := range completion.Outbox {
		payloadDigest := sha256.Sum256(intent.Payload)
		if _, err := state.tx.ExecContext(ctx, `
			INSERT INTO cph_aiinfra.ccse_outbox_intent
				(event_id, scope_sha256, message_id, destination, deduplication_key,
				 content_type, payload, payload_digest)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, intent.EventID[:], state.scope[:],
			state.entry.MessageID[:], intent.Destination, intent.DeduplicationKey,
			intent.ContentType, intent.Payload, payloadDigest[:]); err != nil {
			state.poisoned = err
			return [sha256.Size]byte{}, fmt.Errorf("aiinfra postgres: insert outbox intent: %w", err)
		}
	}
	if err := assertSessionReplicationOrigin(ctx, state.tx); err != nil {
		state.poisoned = err
		return [sha256.Size]byte{}, err
	}
	state.completed = true
	state.sealed = true
	state.outcome = outcome
	return outcome, nil
}

// Transaction returns the authoritative PostgreSQL transaction owned by the
// current ReplayStore.Execute call. A handler must fail closed if it expected a
// transaction and this function returns false.
func Transaction(ctx context.Context) (AtomicTx, bool) {
	active, ok := ctx.Value(replayTransactionContextKey{}).(replayTransactionContext)
	if !ok || active.state == nil || active.store == nil || active.state.store != active.store || active.state.tx == nil {
		return nil, false
	}
	active.state.mu.Lock()
	if active.state.sealed || active.state.poisoned != nil {
		active.state.mu.Unlock()
		return nil, false
	}
	active.state.claimed = true
	active.state.mu.Unlock()
	return atomicTxView{state: active.state}, true
}

// Execute implements ccse.ReplayStore. It never retries a transaction
// internally: a serialization failure aborts every effect and the caller may
// safely redeliver the same signed message.
func (s *ReplayStore) Execute(ctx context.Context, entry ccse.ReplayEntry, verified ccse.VerifiedRecord, apply ccse.ReplayHandler) (ccse.ReplayDecision, error) {
	if s == nil || s.db == nil {
		return ccse.ReplayDecision{}, ErrDatabaseRequired
	}
	if !s.executeActive.CompareAndSwap(false, true) {
		return ccse.ReplayDecision{}, fmt.Errorf("%w: %w", ccse.ErrReplayReentrant, ErrUnitOfWorkActive)
	}
	defer s.executeActive.Store(false)
	if apply == nil {
		return ccse.ReplayDecision{}, ccse.ErrReplayHandlerRequired
	}
	if _, nested := activeTransaction(ctx); nested {
		// A nested independent commit could survive an outer rollback. Services
		// that need composition must do it inside the one transaction instead.
		return ccse.ReplayDecision{}, ccse.ErrReplayReentrant
	}
	if err := entry.Validate(); err != nil {
		return ccse.ReplayDecision{}, err
	}
	if err := matchVerifiedRecord(entry, verified); err != nil {
		return ccse.ReplayDecision{}, err
	}
	scopeDigest, err := replayScopeDigest(entry)
	if err != nil {
		return ccse.ReplayDecision{}, err
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return ccse.ReplayDecision{}, fmt.Errorf("aiinfra postgres: begin replay transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "SET LOCAL search_path = pg_catalog"); err != nil {
		return ccse.ReplayDecision{}, fmt.Errorf("aiinfra postgres: constrain replay search path: %w", err)
	}
	if err := assertSessionReplicationOrigin(ctx, tx); err != nil {
		return ccse.ReplayDecision{}, err
	}

	if err := lockReplayScope(ctx, tx, scopeDigest, entry); err != nil {
		return ccse.ReplayDecision{}, err
	}
	prior, found, err := readReplayMessage(ctx, tx, scopeDigest, entry.MessageID)
	if err != nil {
		return ccse.ReplayDecision{}, err
	}
	if found {
		if prior.matches(entry) {
			return ccse.ReplayDecision{
				Status:        ccse.ReplayDuplicateCompleted,
				OutcomeDigest: prior.outcomeDigest,
			}, nil
		}
		return ccse.ReplayDecision{}, ccse.ErrMessageIDConflict
	}

	highest, hasHighest, err := readHighestSequence(ctx, tx, scopeDigest)
	if err != nil {
		return ccse.ReplayDecision{}, err
	}
	if hasHighest && entry.Sequence <= highest {
		return ccse.ReplayDecision{}, ccse.ErrReplaySequence
	}

	state := &transactionState{store: s, tx: tx, scope: scopeDigest, entry: entry}
	txCtx := context.WithValue(ctx, replayTransactionContextKey{}, replayTransactionContext{store: s, state: state})
	outcomeDigest, err := apply(txCtx, verified)
	if err != nil {
		return ccse.ReplayDecision{}, err
	}
	if err := state.finish(outcomeDigest); err != nil {
		return ccse.ReplayDecision{}, err
	}
	if err := assertSessionReplicationOrigin(ctx, tx); err != nil {
		return ccse.ReplayDecision{}, err
	}
	if err := insertReplayMessage(ctx, tx, scopeDigest, entry, outcomeDigest); err != nil {
		return ccse.ReplayDecision{}, err
	}
	if err := updateHighestSequence(ctx, tx, scopeDigest, entry.Sequence); err != nil {
		return ccse.ReplayDecision{}, err
	}
	if err := assertSessionReplicationOrigin(ctx, tx); err != nil {
		return ccse.ReplayDecision{}, err
	}
	if err := tx.Commit(); err != nil {
		return ccse.ReplayDecision{}, fmt.Errorf("aiinfra postgres: commit replay transaction: %w", err)
	}
	return ccse.ReplayDecision{Status: ccse.ReplayApplied, OutcomeDigest: outcomeDigest}, nil
}

// LoadDurableResult retrieves and rehashes the exact result bound to a replay
// decision. It never returns a payload on a missing inbox join, digest mismatch,
// oversized row or malformed content type.
func (s *ReplayStore) LoadDurableResult(ctx context.Context, entry ccse.ReplayEntry, expected [sha256.Size]byte) (DurableResult, error) {
	if s == nil || s.db == nil {
		return DurableResult{}, ErrDatabaseRequired
	}
	if err := entry.Validate(); err != nil {
		return DurableResult{}, err
	}
	if isZeroDigest(expected) {
		return DurableResult{}, ccse.ErrInvalidOutcomeDigest
	}
	scopeDigest, err := replayScopeDigest(entry)
	if err != nil {
		return DurableResult{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: true})
	if err != nil {
		return DurableResult{}, fmt.Errorf("aiinfra postgres: begin durable-result read: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "SET LOCAL search_path = pg_catalog"); err != nil {
		return DurableResult{}, fmt.Errorf("aiinfra postgres: constrain result-read search path: %w", err)
	}
	var storedDigest []byte
	var result DurableResult
	sequence := encodeSequence(entry.Sequence)
	err = tx.QueryRowContext(ctx, `
		SELECT result.result_digest, result.content_type, result.payload
		FROM cph_aiinfra.ccse_durable_result result
		JOIN cph_aiinfra.ccse_replay_inbox inbox
		  ON inbox.scope_sha256 = result.scope_sha256
		 AND inbox.message_id = result.message_id
		 AND inbox.outcome_digest = result.result_digest
		WHERE result.scope_sha256 = $1 AND result.message_id = $2
		  AND result.result_digest = $3
		  AND inbox.counter_kind = $4 AND inbox.message_type_id = $5
		  AND inbox.schema_major = $6 AND inbox.schema_minor = $7
		  AND inbox.record_digest = $8 AND inbox.sequence = $9
		  AND inbox.expires_at_unix_nano = $10`, scopeDigest[:], entry.MessageID[:], expected[:],
		int16(entry.CounterKind), int64(entry.MessageTypeID), int64(entry.SchemaVersion.Major), int64(entry.SchemaVersion.Minor),
		entry.Digest[:], sequence[:], entry.ExpiresAt,
	).Scan(&storedDigest, &result.ContentType, &result.Payload)
	if errors.Is(err, sql.ErrNoRows) {
		return DurableResult{}, ErrDurableResultMissing
	}
	if err != nil {
		return DurableResult{}, fmt.Errorf("aiinfra postgres: read durable result: %w", err)
	}
	if len(storedDigest) != sha256.Size || len(result.Payload) > maxDurablePayloadBytes ||
		validateStableText("result content type", result.ContentType, maxContentTypeBytes) != nil ||
		!bytes.Equal(storedDigest, expected[:]) || DurableResultDigest(result.ContentType, result.Payload) != expected {
		return DurableResult{}, ErrDurableResultCorrupt
	}
	if err := tx.Commit(); err != nil {
		return DurableResult{}, fmt.Errorf("aiinfra postgres: commit durable-result read: %w", err)
	}
	result.Payload = append([]byte(nil), result.Payload...)
	return result, nil
}

func activeTransaction(ctx context.Context) (*transactionState, bool) {
	active, ok := ctx.Value(replayTransactionContextKey{}).(replayTransactionContext)
	if !ok || active.store == nil || active.state == nil || active.state.tx == nil {
		return nil, false
	}
	return active.state, true
}

func contextOwnsTransaction(ctx context.Context, state *transactionState) bool {
	active, ok := activeTransaction(ctx)
	return ok && active == state
}

func (state *transactionState) finish(returned [sha256.Size]byte) error {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.poisoned != nil {
		return fmt.Errorf("%w: %v", ErrTransactionPoisoned, state.poisoned)
	}
	if !state.claimed {
		return ErrTransactionRequired
	}
	if state.openRows != 0 {
		if state.noRows != 0 {
			return ErrNoRowsUnacknowledged
		}
		return ErrRowsStillOpen
	}
	if !state.completed {
		return ErrCompletionRequired
	}
	if isZeroDigest(returned) {
		return ccse.ErrInvalidOutcomeDigest
	}
	if returned != state.outcome {
		return ErrOutcomeMismatch
	}
	return nil
}

// DurableResultDigest is the digest returned by Complete and persisted in the
// replay inbox. It binds the media type and exact payload bytes.
func DurableResultDigest(contentType string, payload []byte) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte(durableResultMagic))
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(contentType)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write([]byte(contentType))
	binary.BigEndian.PutUint32(length[:], uint32(len(payload)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write(payload)
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func validateCompletion(completion DurableCompletion) error {
	if err := validateStableText("result content type", completion.ContentType, maxContentTypeBytes); err != nil {
		return err
	}
	if len(completion.Payload) > maxDurablePayloadBytes {
		return fmt.Errorf("%w: result payload exceeds %d bytes", ErrInvalidCompletion, maxDurablePayloadBytes)
	}
	switch completion.ExternalEffects {
	case NoExternalEffects:
		if len(completion.Outbox) != 0 {
			return fmt.Errorf("%w: no-effect completion contains outbox intents", ErrInvalidCompletion)
		}
	case ExternalEffectsViaOutbox:
		if len(completion.Outbox) == 0 {
			return fmt.Errorf("%w: outbox effect mode requires at least one intent", ErrInvalidCompletion)
		}
	default:
		return fmt.Errorf("%w: external-effect disposition is required", ErrInvalidCompletion)
	}
	if len(completion.Outbox) > maxOutboxIntents {
		return fmt.Errorf("%w: outbox contains more than %d intents", ErrInvalidCompletion, maxOutboxIntents)
	}
	seen := make(map[[ccse.MessageIDSize]byte]struct{}, len(completion.Outbox))
	seenDeduplicationKeys := make(map[string]struct{}, len(completion.Outbox))
	totalPayloadBytes := 0
	for _, intent := range completion.Outbox {
		if intent.EventID == [ccse.MessageIDSize]byte{} {
			return fmt.Errorf("%w: zero outbox event ID", ErrInvalidCompletion)
		}
		if _, duplicate := seen[intent.EventID]; duplicate {
			return fmt.Errorf("%w: duplicate outbox event ID", ErrInvalidCompletion)
		}
		seen[intent.EventID] = struct{}{}
		if err := validateStableText("outbox destination", intent.Destination, maxDestinationBytes); err != nil {
			return err
		}
		if err := validateStableText("outbox deduplication key", intent.DeduplicationKey, maxDeduplicationKeyBytes); err != nil {
			return err
		}
		if err := validateStableText("outbox content type", intent.ContentType, maxContentTypeBytes); err != nil {
			return err
		}
		if len(intent.Payload) > maxDurablePayloadBytes {
			return fmt.Errorf("%w: outbox payload exceeds %d bytes", ErrInvalidCompletion, maxDurablePayloadBytes)
		}
		deduplicationIdentity := intent.Destination + "\x00" + intent.DeduplicationKey
		if _, duplicate := seenDeduplicationKeys[deduplicationIdentity]; duplicate {
			return fmt.Errorf("%w: duplicate destination and deduplication key", ErrInvalidCompletion)
		}
		seenDeduplicationKeys[deduplicationIdentity] = struct{}{}
		totalPayloadBytes += len(intent.Payload)
		if totalPayloadBytes > maxOutboxPayloadBytes {
			return fmt.Errorf("%w: total outbox payload exceeds %d bytes", ErrInvalidCompletion, maxOutboxPayloadBytes)
		}
	}
	return nil
}

func validateStableText(field, value string, maximum int) error {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value || strings.IndexByte(value, 0) >= 0 {
		return fmt.Errorf("%w: invalid %s", ErrInvalidCompletion, field)
	}
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return fmt.Errorf("%w: %s must use visible ASCII", ErrInvalidCompletion, field)
		}
	}
	return nil
}

func matchVerifiedRecord(entry ccse.ReplayEntry, verified ccse.VerifiedRecord) error {
	domain := verified.Domain()
	envelope := verified.Envelope()
	if verified.MessageTypeID() != entry.MessageTypeID ||
		verified.SchemaVersion() != entry.SchemaVersion ||
		domain.CounterKind != entry.CounterKind ||
		domain.ReplayDomainID != entry.ReplayDomainID ||
		domain.SenderIdentity != entry.SenderIdentity ||
		domain.Environment != entry.Environment ||
		domain.ChainID != entry.ChainID ||
		domain.GenesisHash != entry.GenesisHash ||
		envelope.MessageID != entry.MessageID ||
		envelope.Counter != entry.Sequence ||
		envelope.ExpiresAtUnixNano != entry.ExpiresAt ||
		verified.Digest() != entry.Digest {
		return ErrReplayEntryMismatch
	}
	return nil
}

func replayScopeDigest(entry ccse.ReplayEntry) ([sha256.Size]byte, error) {
	projection, err := ccse.Marshal(256<<10, func(out *ccse.Encoder) {
		out.Uint32(uint32(entry.CounterKind))
		out.String(entry.ReplayDomainID)
		out.String(entry.SenderIdentity)
		out.String(entry.Environment)
		out.FixedBytes(entry.ChainID[:], len(entry.ChainID))
		out.FixedBytes(entry.GenesisHash[:], len(entry.GenesisHash))
	})
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("aiinfra postgres: encode replay scope: %w", err)
	}
	preimage := make([]byte, 0, len(replayScopeMagic)+len(projection))
	preimage = append(preimage, replayScopeMagic...)
	preimage = append(preimage, projection...)
	return sha256.Sum256(preimage), nil
}

func lockReplayScope(ctx context.Context, tx *sql.Tx, scopeDigest [sha256.Size]byte, entry ccse.ReplayEntry) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO cph_aiinfra.ccse_replay_head
			(scope_sha256, counter_kind, replay_domain_id, sender_identity, environment, chain_id, genesis_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (scope_sha256) DO NOTHING`,
		scopeDigest[:], int16(entry.CounterKind), entry.ReplayDomainID, entry.SenderIdentity,
		entry.Environment, entry.ChainID[:], entry.GenesisHash[:],
	); err != nil {
		return fmt.Errorf("aiinfra postgres: create replay scope: %w", err)
	}
	var (
		counterKind                       int16
		replayDomain, sender, environment string
		chainID, genesisHash              []byte
	)
	if err := tx.QueryRowContext(ctx, `
		SELECT counter_kind, replay_domain_id, sender_identity, environment, chain_id, genesis_hash
		FROM cph_aiinfra.ccse_replay_head
		WHERE scope_sha256=$1
		FOR UPDATE`, scopeDigest[:],
	).Scan(&counterKind, &replayDomain, &sender, &environment, &chainID, &genesisHash); err != nil {
		return fmt.Errorf("aiinfra postgres: lock replay scope: %w", err)
	}
	if counterKind != int16(entry.CounterKind) || replayDomain != entry.ReplayDomainID ||
		sender != entry.SenderIdentity || environment != entry.Environment ||
		!bytes.Equal(chainID, entry.ChainID[:]) || !bytes.Equal(genesisHash, entry.GenesisHash[:]) {
		return ErrReplayScopeCollision
	}
	return nil
}

type replayMessage struct {
	counterKind   ccse.CounterKind
	messageTypeID uint32
	schemaVersion ccse.Version
	digest        [sha256.Size]byte
	sequence      uint64
	expiresAt     int64
	outcomeDigest [sha256.Size]byte
}

func (m replayMessage) matches(entry ccse.ReplayEntry) bool {
	return m.counterKind == entry.CounterKind && m.messageTypeID == entry.MessageTypeID && m.schemaVersion == entry.SchemaVersion &&
		m.digest == entry.Digest && m.sequence == entry.Sequence && m.expiresAt == entry.ExpiresAt
}

func readReplayMessage(ctx context.Context, tx *sql.Tx, scopeDigest [sha256.Size]byte, messageID [ccse.MessageIDSize]byte) (replayMessage, bool, error) {
	var (
		counterKind, messageTypeID int64
		schemaMajor, schemaMinor   int64
		digest, sequence, outcome  []byte
		value                      replayMessage
	)
	err := tx.QueryRowContext(ctx, `
		SELECT counter_kind, message_type_id, schema_major, schema_minor, record_digest, sequence,
		       expires_at_unix_nano, outcome_digest
		FROM cph_aiinfra.ccse_replay_inbox
		WHERE scope_sha256=$1 AND message_id=$2`, scopeDigest[:], messageID[:],
	).Scan(&counterKind, &messageTypeID, &schemaMajor, &schemaMinor, &digest, &sequence, &value.expiresAt, &outcome)
	if errors.Is(err, sql.ErrNoRows) {
		return replayMessage{}, false, nil
	}
	if err != nil {
		return replayMessage{}, false, fmt.Errorf("aiinfra postgres: read replay inbox: %w", err)
	}
	if (counterKind != int64(ccse.CounterSequence) && counterKind != int64(ccse.CounterExpectedGeneration)) ||
		messageTypeID <= 0 || messageTypeID > int64(^uint32(0)) ||
		schemaMajor <= 0 || schemaMajor > int64(^uint32(0)) ||
		schemaMinor < 0 || schemaMinor > int64(^uint32(0)) ||
		len(digest) != sha256.Size || len(sequence) != 8 || len(outcome) != sha256.Size {
		return replayMessage{}, false, fmt.Errorf("aiinfra postgres: invalid durable replay row")
	}
	value.counterKind = ccse.CounterKind(counterKind)
	value.messageTypeID = uint32(messageTypeID)
	value.schemaVersion = ccse.Version{Major: uint32(schemaMajor), Minor: uint32(schemaMinor)}
	copy(value.digest[:], digest)
	value.sequence = binary.BigEndian.Uint64(sequence)
	copy(value.outcomeDigest[:], outcome)
	return value, true, nil
}

func readHighestSequence(ctx context.Context, tx *sql.Tx, scopeDigest [sha256.Size]byte) (uint64, bool, error) {
	var encoded []byte
	if err := tx.QueryRowContext(ctx,
		"SELECT highest_sequence FROM cph_aiinfra.ccse_replay_head WHERE scope_sha256=$1",
		scopeDigest[:],
	).Scan(&encoded); err != nil {
		return 0, false, fmt.Errorf("aiinfra postgres: read replay sequence: %w", err)
	}
	if encoded == nil {
		return 0, false, nil
	}
	if len(encoded) != 8 {
		return 0, false, fmt.Errorf("aiinfra postgres: invalid durable replay sequence")
	}
	return binary.BigEndian.Uint64(encoded), true, nil
}

func insertReplayMessage(ctx context.Context, tx *sql.Tx, scopeDigest [sha256.Size]byte, entry ccse.ReplayEntry, outcome [sha256.Size]byte) error {
	sequence := encodeSequence(entry.Sequence)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO cph_aiinfra.ccse_replay_inbox
			(scope_sha256, message_id, counter_kind, message_type_id, schema_major, schema_minor,
			 record_digest, sequence, expires_at_unix_nano, outcome_digest)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		scopeDigest[:], entry.MessageID[:], int16(entry.CounterKind), int64(entry.MessageTypeID),
		int64(entry.SchemaVersion.Major), int64(entry.SchemaVersion.Minor), entry.Digest[:],
		sequence[:], entry.ExpiresAt, outcome[:],
	); err != nil {
		return fmt.Errorf("aiinfra postgres: insert replay inbox: %w", err)
	}
	return nil
}

func updateHighestSequence(ctx context.Context, tx *sql.Tx, scopeDigest [sha256.Size]byte, sequence uint64) error {
	encoded := encodeSequence(sequence)
	result, err := tx.ExecContext(ctx, `
		UPDATE cph_aiinfra.ccse_replay_head
		SET highest_sequence=$2, updated_at=clock_timestamp()
		WHERE scope_sha256=$1`, scopeDigest[:], encoded[:])
	if err != nil {
		return fmt.Errorf("aiinfra postgres: update replay sequence: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("aiinfra postgres: inspect replay sequence update: %w", err)
	}
	if rows != 1 {
		return fmt.Errorf("aiinfra postgres: replay scope disappeared during transaction")
	}
	return nil
}

func encodeSequence(sequence uint64) [8]byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], sequence)
	return encoded
}

func isZeroDigest(digest [sha256.Size]byte) bool {
	return digest == [sha256.Size]byte{}
}

func assertSessionReplicationOrigin(ctx context.Context, tx *sql.Tx) error {
	var role string
	if err := tx.QueryRowContext(ctx,
		"SELECT pg_catalog.current_setting('session_replication_role')",
	).Scan(&role); err != nil {
		return fmt.Errorf("%w: inspect session_replication_role: %v", ErrUnsafeSessionRole, err)
	}
	if role != "origin" {
		return fmt.Errorf("%w: got %q", ErrUnsafeSessionRole, role)
	}
	return nil
}
