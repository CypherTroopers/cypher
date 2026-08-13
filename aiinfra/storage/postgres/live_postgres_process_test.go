// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

const (
	livePostgresAdminDSNEnv          = "CPH_AIIE_POSTGRES_ADMIN_DSN"
	livePostgresProcessHelperModeEnv = "CPH_AIIE_POSTGRES_PROCESS_HELPER_MODE"
	livePostgresProcessNonceEnv      = "CPH_AIIE_POSTGRES_PROCESS_NONCE"

	livePostgresHelperBackendWait = "backend-wait"
	livePostgresHelperProcessWait = "process-wait"
	livePostgresHelperCommitWait  = "commit-wait"
	livePostgresHelperCommitExit  = "commit-exit"
	livePostgresHelperDuplicate   = "duplicate"

	livePostgresHelperStagedPrefix    = "CPH_AIIE_PROCESS_STAGED "
	livePostgresHelperCommitReady     = "CPH_AIIE_PROCESS_COMMIT_READY"
	livePostgresHelperCommittedPrefix = "CPH_AIIE_PROCESS_COMMITTED "
	livePostgresHelperDuplicatePrefix = "CPH_AIIE_PROCESS_DUPLICATE "
)

// TestLivePostgresConnectionLossProcessDeathAndRestart exercises boundaries
// that an in-process fake driver cannot model. It never drops, truncates or
// reuses authoritative rows: every subtest owns a fresh random replay scope.
func TestLivePostgresConnectionLossProcessDeathAndRestart(t *testing.T) {
	if os.Getenv(livePostgresDisposableEnv) != "YES" {
		t.Skip("set CPH_AIIE_POSTGRES_DISPOSABLE=YES to run the live PostgreSQL process test")
	}
	ownerDSN, runtimeDSN := os.Getenv(livePostgresOwnerDSNEnv), os.Getenv(livePostgresRuntimeDSNEnv)
	if ownerDSN == "" || runtimeDSN == "" {
		t.Fatal("live PostgreSQL process test requires both owner and runtime DSNs")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	ownerDB := openLivePostgres(t, ctx, ownerDSN, "process-test owner")
	runtimeDB := openLivePostgres(t, ctx, runtimeDSN, "process-test runtime")
	if err := MigrateReplayStore(ctx, ownerDB); err != nil {
		t.Fatalf("process-test owner migration: %v", err)
	}
	var runtimeRole, runtimeDatabase string
	if err := runtimeDB.QueryRowContext(ctx,
		"SELECT current_user, current_database()").Scan(&runtimeRole, &runtimeDatabase); err != nil {
		t.Fatal("read process-test runtime identity")
	}
	if err := grantLivePostgresRuntimeACL(ctx, ownerDB, runtimeRole); err != nil {
		t.Fatalf("install exact process-test runtime ACL: %v", err)
	}
	if err := VerifyReplayStore(ctx, runtimeDB); err != nil {
		t.Fatalf("process-test runtime verification: %v", err)
	}

	t.Run("backend termination rolls back and exact redelivery commits", func(t *testing.T) {
		adminDSN := os.Getenv(livePostgresAdminDSNEnv)
		if adminDSN == "" {
			t.Skip("set CPH_AIIE_POSTGRES_ADMIN_DSN to test pg_terminate_backend")
		}
		adminDB := openLivePostgres(t, ctx, adminDSN, "signal-only admin")
		adminConnection, err := adminDB.Conn(ctx)
		if err != nil {
			t.Fatal("open signal-only admin connection")
		}
		defer adminConnection.Close()
		var signalMember bool
		if err := adminConnection.QueryRowContext(ctx,
			"SELECT pg_catalog.pg_has_role(current_user, 'pg_signal_backend', 'MEMBER')").
			Scan(&signalMember); err != nil || !signalMember {
			t.Fatalf("admin lacks pg_signal_backend membership: member=%t err=%v", signalMember, err)
		}
		// The acceptance admin is intentionally NOINHERIT. Elevate only this
		// dedicated connection to its sole predefined signal capability.
		if _, err := adminConnection.ExecContext(ctx, "SET ROLE pg_signal_backend"); err != nil {
			t.Fatal("activate signal-only admin capability")
		}
		nonce := livePostgresNonce(t)
		fixture := newLivePostgresProcessFixture(t, nonce)
		child := startLivePostgresWaitingHelper(t, ctx, livePostgresHelperBackendWait, nonce)
		pid := awaitLivePostgresStaged(t, child)
		assertLivePostgresBackendTarget(t, ctx, adminConnection, pid, runtimeRole,
			runtimeDatabase, livePostgresProcessApplicationName(nonce))
		var terminated bool
		if err := adminConnection.QueryRowContext(ctx,
			"SELECT pg_catalog.pg_terminate_backend($1)", pid).Scan(&terminated); err != nil {
			t.Fatalf("terminate exact helper backend: %v", err)
		}
		if !terminated {
			t.Fatal("exact helper backend was not terminated")
		}
		if _, err := io.WriteString(child.stdin, "continue\n"); err != nil {
			t.Fatalf("release terminated helper: %v", err)
		}
		_ = child.stdin.Close()
		if err := child.command.Wait(); err != nil {
			t.Fatalf("terminated-backend helper rejected expected connection loss: %v", err)
		}
		assertLivePostgresProcessRowsAbsent(t, ctx, ownerDB, fixture)
		runLivePostgresProcessHelper(t, ctx, livePostgresHelperCommitExit, nonce,
			livePostgresHelperCommittedPrefix+livePostgresProcessDigestHex(fixture.receipt.ResultDigest()))
		runLivePostgresProcessHelper(t, ctx, livePostgresHelperDuplicate, nonce,
			livePostgresHelperDuplicatePrefix+livePostgresProcessDigestHex(fixture.receipt.ResultDigest()))
	})

	t.Run("process death before Complete rolls back and exact redelivery commits", func(t *testing.T) {
		nonce := livePostgresNonce(t)
		fixture := newLivePostgresProcessFixture(t, nonce)
		child := startLivePostgresWaitingHelper(t, ctx, livePostgresHelperProcessWait, nonce)
		_ = awaitLivePostgresStaged(t, child)
		if err := child.command.Process.Kill(); err != nil {
			t.Fatalf("kill staged helper process: %v", err)
		}
		_ = child.stdin.Close()
		if err := child.command.Wait(); err == nil {
			t.Fatal("staged helper exited normally after Process.Kill")
		}
		assertLivePostgresProcessRowsAbsent(t, ctx, ownerDB, fixture)
		runLivePostgresProcessHelper(t, ctx, livePostgresHelperCommitExit, nonce,
			livePostgresHelperCommittedPrefix+livePostgresProcessDigestHex(fixture.receipt.ResultDigest()))
		runLivePostgresProcessHelper(t, ctx, livePostgresHelperDuplicate, nonce,
			livePostgresHelperDuplicatePrefix+livePostgresProcessDigestHex(fixture.receipt.ResultDigest()))
	})

	t.Run("process death after handler return before physical commit rolls back", func(t *testing.T) {
		nonce := livePostgresNonce(t)
		fixture := newLivePostgresProcessFixture(t, nonce)
		child := startLivePostgresWaitingHelper(t, ctx, livePostgresHelperCommitWait, nonce)
		awaitLivePostgresCommitReady(t, child)
		if err := child.command.Process.Kill(); err != nil {
			t.Fatalf("kill commit-boundary helper process: %v", err)
		}
		_ = child.stdin.Close()
		if err := child.command.Wait(); err == nil {
			t.Fatal("commit-boundary helper exited normally after Process.Kill")
		}
		assertLivePostgresProcessRowsAbsent(t, ctx, ownerDB, fixture)
		runLivePostgresProcessHelper(t, ctx, livePostgresHelperCommitExit, nonce,
			livePostgresHelperCommittedPrefix+livePostgresProcessDigestHex(fixture.receipt.ResultDigest()))
		runLivePostgresProcessHelper(t, ctx, livePostgresHelperDuplicate, nonce,
			livePostgresHelperDuplicatePrefix+livePostgresProcessDigestHex(fixture.receipt.ResultDigest()))
	})

	t.Run("abrupt exit after commit reloads in a new process", func(t *testing.T) {
		nonce := livePostgresNonce(t)
		fixture := newLivePostgresProcessFixture(t, nonce)
		runLivePostgresProcessHelper(t, ctx, livePostgresHelperCommitExit, nonce,
			livePostgresHelperCommittedPrefix+livePostgresProcessDigestHex(fixture.receipt.ResultDigest()))
		runLivePostgresProcessHelper(t, ctx, livePostgresHelperDuplicate, nonce,
			livePostgresHelperDuplicatePrefix+livePostgresProcessDigestHex(fixture.receipt.ResultDigest()))
	})
}

// TestLivePostgresProcessHelper is invoked only as a subprocess of the parent
// test. Secrets remain in inherited environment variables and are never
// copied into command-line arguments, sentinel output or failure messages.
func TestLivePostgresProcessHelper(t *testing.T) {
	mode := os.Getenv(livePostgresProcessHelperModeEnv)
	if mode == "" {
		t.Skip("live PostgreSQL process helper")
	}
	if os.Getenv(livePostgresDisposableEnv) != "YES" {
		t.Fatal("process helper requires the disposable gate")
	}
	runtimeDSN := os.Getenv(livePostgresRuntimeDSNEnv)
	if runtimeDSN == "" {
		t.Fatal("process helper requires the runtime DSN")
	}
	nonce, err := livePostgresProcessNonceFromEnv()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var commitBarrier *livePostgresCommitBarrier
	var database *sql.DB
	if mode == livePostgresHelperCommitWait {
		config, parseErr := pgx.ParseConfig(runtimeDSN)
		if parseErr != nil {
			t.Fatal("parse process-helper runtime connection")
		}
		commitBarrier = new(livePostgresCommitBarrier)
		database = sql.OpenDB(&livePostgresCommitBarrierConnector{
			Connector: stdlib.GetConnector(*config), barrier: commitBarrier,
		})
	} else {
		var openErr error
		database, openErr = sql.Open("pgx", runtimeDSN)
		if openErr != nil {
			t.Fatal("open process-helper runtime connection")
		}
	}
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	defer database.Close()
	connection, err := database.Conn(ctx)
	if err != nil {
		t.Fatal("connect process-helper runtime")
	}
	defer connection.Close()
	applicationName := livePostgresProcessApplicationName(nonce)
	if _, err := connection.ExecContext(ctx, "SELECT pg_catalog.set_config('application_name', $1, false)",
		applicationName); err != nil {
		t.Fatal("set process-helper application name")
	}
	store, err := NewReplayStore(ctx, connection)
	if err != nil {
		t.Fatalf("construct process-helper replay store: %v", err)
	}
	fixture := newLivePostgresProcessFixture(t, nonce)

	switch mode {
	case livePostgresHelperBackendWait, livePostgresHelperProcessWait:
		var backendPID int
		if err := connection.QueryRowContext(ctx, "SELECT pg_catalog.pg_backend_pid()").Scan(&backendPID); err != nil {
			t.Fatal("read process-helper backend PID")
		}
		decision, executeErr := executeLivePostgresProcessFixture(ctx, store, fixture,
			func() error {
				fmt.Fprintf(os.Stdout, "%s%d\n", livePostgresHelperStagedPrefix, backendPID)
				_, readErr := bufio.NewReader(os.Stdin).ReadString('\n')
				return readErr
			})
		if mode == livePostgresHelperProcessWait {
			t.Fatalf("process-wait helper was released instead of killed: decision=%+v err=%v",
				decision, executeErr)
		}
		if executeErr == nil || decision != (ccse.ReplayDecision{}) {
			t.Fatalf("terminated backend did not abort Execute: decision=%+v err=%v", decision, executeErr)
		}
	case livePostgresHelperCommitExit:
		decision, executeErr := executeLivePostgresProcessFixture(ctx, store, fixture, nil)
		if executeErr != nil {
			t.Fatalf("commit-exit helper Execute: %v", executeErr)
		}
		if decision.Status != ccse.ReplayApplied || decision.OutcomeDigest != fixture.receipt.ResultDigest() {
			t.Fatalf("commit-exit helper decision=%+v", decision)
		}
		fmt.Fprintf(os.Stdout, "%s%s\n", livePostgresHelperCommittedPrefix,
			hex.EncodeToString(decision.OutcomeDigest[:]))
		// Execute returned only after sql.Tx.Commit succeeded. Exit immediately
		// without running defers to model abrupt process death after commit.
		os.Exit(0)
	case livePostgresHelperCommitWait:
		commitBarrier.armed.Store(true)
		decision, executeErr := executeLivePostgresProcessFixture(ctx, store, fixture, nil)
		t.Fatalf("commit-wait helper crossed physical commit boundary: decision=%+v err=%v",
			decision, executeErr)
	case livePostgresHelperDuplicate:
		handlerCalled := false
		decision, executeErr := store.Execute(ctx, fixture.entry, fixture.verified,
			func(context.Context, ccse.VerifiedRecord) ([sha256.Size]byte, error) {
				handlerCalled = true
				return [sha256.Size]byte{}, errors.New("duplicate helper handler invoked")
			})
		if executeErr != nil {
			t.Fatalf("duplicate helper Execute: %v", executeErr)
		}
		if handlerCalled || decision.Status != ccse.ReplayDuplicateCompleted ||
			decision.OutcomeDigest != fixture.receipt.ResultDigest() {
			t.Fatalf("duplicate helper decision=%+v handler_called=%t", decision, handlerCalled)
		}
		result, loadErr := store.LoadDurableResult(ctx, fixture.entry, decision.OutcomeDigest)
		if loadErr != nil {
			t.Fatalf("duplicate helper durable-result reload: %v", loadErr)
		}
		if result.ContentType != fixture.receipt.ResultContentType() ||
			!bytes.Equal(result.Payload, fixture.receipt.ResultPayload()) {
			t.Fatal("duplicate helper durable result differs from committed receipt")
		}
		fmt.Fprintf(os.Stdout, "%s%s\n", livePostgresHelperDuplicatePrefix,
			hex.EncodeToString(decision.OutcomeDigest[:]))
	default:
		t.Fatalf("unknown process-helper mode %q", mode)
	}
}

// livePostgresCommitBarrier wraps only the test process's driver transaction.
// It does not add a callback to ReplayStore's production API. Once armed after
// startup verification, the next driver Commit announces that the handler,
// replay writes, deferred constraints and deadline check have all completed,
// then blocks before delegating to the physical PostgreSQL commit.
type livePostgresCommitBarrier struct {
	armed atomic.Bool
}

type livePostgresCommitBarrierConnector struct {
	driver.Connector
	barrier *livePostgresCommitBarrier
}

func (connector *livePostgresCommitBarrierConnector) Connect(ctx context.Context) (driver.Conn, error) {
	connection, err := connector.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &livePostgresCommitBarrierConn{Conn: connection, barrier: connector.barrier}, nil
}

type livePostgresCommitBarrierConn struct {
	driver.Conn
	barrier *livePostgresCommitBarrier
}

func (connection *livePostgresCommitBarrierConn) BeginTx(ctx context.Context,
	options driver.TxOptions) (driver.Tx, error) {
	beginner, ok := connection.Conn.(driver.ConnBeginTx)
	if !ok {
		return nil, driver.ErrSkip
	}
	transaction, err := beginner.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return &livePostgresCommitBarrierTx{Tx: transaction, barrier: connection.barrier}, nil
}

func (connection *livePostgresCommitBarrierConn) ExecContext(ctx context.Context,
	query string, arguments []driver.NamedValue) (driver.Result, error) {
	executor, ok := connection.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return executor.ExecContext(ctx, query, arguments)
}

func (connection *livePostgresCommitBarrierConn) QueryContext(ctx context.Context,
	query string, arguments []driver.NamedValue) (driver.Rows, error) {
	querier, ok := connection.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return querier.QueryContext(ctx, query, arguments)
}

func (connection *livePostgresCommitBarrierConn) Ping(ctx context.Context) error {
	pinger, ok := connection.Conn.(driver.Pinger)
	if !ok {
		return driver.ErrSkip
	}
	return pinger.Ping(ctx)
}

func (connection *livePostgresCommitBarrierConn) ResetSession(ctx context.Context) error {
	resetter, ok := connection.Conn.(driver.SessionResetter)
	if !ok {
		return nil
	}
	return resetter.ResetSession(ctx)
}

func (connection *livePostgresCommitBarrierConn) IsValid() bool {
	validator, ok := connection.Conn.(driver.Validator)
	return !ok || validator.IsValid()
}

func (connection *livePostgresCommitBarrierConn) CheckNamedValue(value *driver.NamedValue) error {
	checker, ok := connection.Conn.(driver.NamedValueChecker)
	if !ok {
		return driver.ErrSkip
	}
	return checker.CheckNamedValue(value)
}

type livePostgresCommitBarrierTx struct {
	driver.Tx
	barrier *livePostgresCommitBarrier
}

func (transaction *livePostgresCommitBarrierTx) Commit() error {
	if transaction.barrier.armed.CompareAndSwap(true, false) {
		fmt.Fprintln(os.Stdout, livePostgresHelperCommitReady)
		_, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
	}
	return transaction.Tx.Commit()
}

type livePostgresProcessFixture struct {
	entry       ccse.ReplayEntry
	verified    ccse.VerifiedRecord
	receipt     CanonicalUOWReceipt
	parent      idempotency.Binding
	joined      idempotency.Binding
	parentClaim idempotency.Claim
	joinedClaim idempotency.Claim
	eventID     string
	eventClaim  globalid.Claim
	pending     DurablePendingRevision
}

func newLivePostgresProcessFixture(t *testing.T,
	nonce [ccse.MessageIDSize]byte) livePostgresProcessFixture {
	t.Helper()
	entry, verified := livePostgresVerifiedInput(t, nonce)
	suffix := hex.EncodeToString(nonce[:])
	eventID := globalid.JoinedAuditEventIDPrefix + suffix
	parent := idempotency.Binding{
		Key:           nonce,
		Domain:        idempotency.OperationIAMIdentity,
		OwnerID:       "live-process-identity-" + suffix,
		RequestDigest: sha256.Sum256(append([]byte("live-process-request:"), nonce[:]...)),
	}
	joined, err := idempotency.JoinedAuditBinding(parent)
	if err != nil {
		t.Fatal(err)
	}
	progress := sha256.Sum256(append([]byte("live-process-progress:"), nonce[:]...))
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
	eventClaim, err := globalid.Reserve(eventID,
		globalid.Owner{Domain: globalid.OwnerGovernanceAuditEvent, ID: eventID})
	if err != nil {
		t.Fatal(err)
	}
	pendingEnvelope := append([]byte("live-process-pending:"), nonce[:]...)
	receipt, err := NewAdmissionUOWReceipt("application/cph.aiinfra.live-process.v1",
		append([]byte("live-process-result:"), nonce[:]...))
	if err != nil {
		t.Fatal(err)
	}
	return livePostgresProcessFixture{
		entry: entry, verified: verified, receipt: receipt,
		parent: parent, joined: joined, parentClaim: parentClaim, joinedClaim: joinedClaim,
		eventID: eventID, eventClaim: eventClaim,
		pending: DurablePendingRevision{
			PendingKey:              parent.Key,
			Kind:                    DurablePendingMutation,
			Codec:                   DurablePendingIAMCodec,
			CodecVersion:            1,
			Revision:                1,
			EnvelopeDigest:          sha256.Sum256(pendingEnvelope),
			CanonicalEnvelope:       pendingEnvelope,
			Status:                  DurablePendingOpen,
			CommitNotBeforeUnixNano: livePostgresIssuedAt().UnixNano(),
			CommitNotAfterUnixNano:  livePostgresIssuedAt().Add(10 * time.Minute).UnixNano(),
			ExpectedAuditEventID:    eventID,
		},
	}
}

func executeLivePostgresProcessFixture(ctx context.Context, store *ReplayStore,
	fixture livePostgresProcessFixture, staged func() error) (ccse.ReplayDecision, error) {
	return store.Execute(ctx, fixture.entry, fixture.verified,
		func(txCtx context.Context, exact ccse.VerifiedRecord) ([sha256.Size]byte, error) {
			uow, err := BindCanonicalUOW(txCtx, exact, fixture.receipt)
			if err != nil {
				return [sha256.Size]byte{}, err
			}
			if err := uow.ApplyBusinessIdempotency(txCtx, BusinessIdempotencyMutation{
				ExpectedAuditEventID: fixture.eventID,
				Claims:               []idempotency.Claim{fixture.parentClaim, fixture.joinedClaim},
			}); err != nil {
				return [sha256.Size]byte{}, err
			}
			if err := uow.ApplyGlobalClaims(txCtx, GlobalClaimMutation{
				AuditEventID: fixture.eventID,
				Claims:       []globalid.Claim{fixture.eventClaim},
			}); err != nil {
				return [sha256.Size]byte{}, err
			}
			if err := uow.ApplyDurablePendingRevision(txCtx, fixture.pending); err != nil {
				return [sha256.Size]byte{}, err
			}
			if staged != nil {
				if err := staged(); err != nil && !errors.Is(err, io.EOF) {
					return [sha256.Size]byte{}, err
				}
			}
			transaction, ok := Transaction(txCtx)
			if !ok {
				return [sha256.Size]byte{}, ErrTransactionRequired
			}
			return transaction.Complete(txCtx, livePostgresCompletion(fixture.receipt))
		})
}

type livePostgresWaitingHelper struct {
	command *exec.Cmd
	stdin   io.WriteCloser
	stdout  *bufio.Scanner
	stderr  *bytes.Buffer
}

func startLivePostgresWaitingHelper(t *testing.T, ctx context.Context, mode string,
	nonce [ccse.MessageIDSize]byte) livePostgresWaitingHelper {
	t.Helper()
	command := exec.CommandContext(ctx, os.Args[0],
		"-test.run=^TestLivePostgresProcessHelper$", "-test.v")
	command.Env = livePostgresProcessHelperEnv(mode, nonce)
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal("create process-helper stdin")
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal("create process-helper stdout")
	}
	stderr := new(bytes.Buffer)
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		t.Fatal("start process helper")
	}
	t.Cleanup(func() {
		if command.ProcessState == nil {
			_ = command.Process.Kill()
			_ = stdin.Close()
			_ = command.Wait()
		}
	})
	return livePostgresWaitingHelper{
		command: command, stdin: stdin, stdout: bufio.NewScanner(stdout), stderr: stderr,
	}
}

func awaitLivePostgresStaged(t *testing.T, child livePostgresWaitingHelper) int {
	t.Helper()
	for child.stdout.Scan() {
		line := child.stdout.Text()
		if !strings.HasPrefix(line, livePostgresHelperStagedPrefix) {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimPrefix(line, livePostgresHelperStagedPrefix))
		if err != nil || pid <= 0 {
			t.Fatal("process helper emitted a malformed backend PID")
		}
		return pid
	}
	_ = child.stdin.Close()
	_ = child.command.Wait()
	t.Fatalf("process helper exited before staging authoritative writes: %s",
		livePostgresRedactSecrets(child.stderr.String()))
	return 0
}

func awaitLivePostgresCommitReady(t *testing.T, child livePostgresWaitingHelper) {
	t.Helper()
	for child.stdout.Scan() {
		if child.stdout.Text() == livePostgresHelperCommitReady {
			return
		}
	}
	_ = child.stdin.Close()
	_ = child.command.Wait()
	t.Fatalf("process helper exited before entering physical commit: %s",
		livePostgresRedactSecrets(child.stderr.String()))
}

func runLivePostgresProcessHelper(t *testing.T, ctx context.Context, mode string,
	nonce [ccse.MessageIDSize]byte, wantSentinel string) {
	t.Helper()
	command := exec.CommandContext(ctx, os.Args[0],
		"-test.run=^TestLivePostgresProcessHelper$", "-test.v")
	command.Env = livePostgresProcessHelperEnv(mode, nonce)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("process helper mode %q failed: %v", mode, err)
	}
	if !bytes.Contains(output, []byte(wantSentinel)) {
		t.Fatalf("process helper mode %q did not emit its success sentinel", mode)
	}
}

func livePostgresProcessHelperEnv(mode string,
	nonce [ccse.MessageIDSize]byte) []string {
	prefixes := []string{
		livePostgresProcessHelperModeEnv + "=",
		livePostgresProcessNonceEnv + "=",
	}
	environment := make([]string, 0, len(os.Environ())+2)
	for _, value := range os.Environ() {
		replaced := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(value, prefix) {
				replaced = true
				break
			}
		}
		if !replaced {
			environment = append(environment, value)
		}
	}
	return append(environment,
		livePostgresProcessHelperModeEnv+"="+mode,
		livePostgresProcessNonceEnv+"="+hex.EncodeToString(nonce[:]))
}

func livePostgresProcessNonceFromEnv() ([ccse.MessageIDSize]byte, error) {
	var nonce [ccse.MessageIDSize]byte
	encoded := os.Getenv(livePostgresProcessNonceEnv)
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != ccse.MessageIDSize {
		return nonce, errors.New("process helper nonce is malformed")
	}
	copy(nonce[:], decoded)
	if nonce == ([ccse.MessageIDSize]byte{}) {
		return nonce, errors.New("process helper nonce is zero")
	}
	return nonce, nil
}

func livePostgresProcessApplicationName(nonce [ccse.MessageIDSize]byte) string {
	return "cph-aiinfra-live-process-" + hex.EncodeToString(nonce[:])
}

func livePostgresProcessDigestHex(digest [sha256.Size]byte) string {
	return hex.EncodeToString(digest[:])
}

type livePostgresQueryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func assertLivePostgresBackendTarget(t *testing.T, ctx context.Context, adminDB livePostgresQueryRower,
	pid int, runtimeRole, runtimeDatabase, applicationName string) {
	t.Helper()
	var actualRole, actualDatabase, actualApplication string
	if err := adminDB.QueryRowContext(ctx, `
		SELECT usename, datname, application_name
		FROM pg_catalog.pg_stat_activity
		WHERE pid = $1`, pid).Scan(&actualRole, &actualDatabase, &actualApplication); err != nil {
		t.Fatalf("resolve exact helper backend before termination: %v", err)
	}
	if actualRole != runtimeRole || actualDatabase != runtimeDatabase ||
		actualApplication != applicationName {
		t.Fatalf("refuse to terminate unexpected backend identity")
	}
}

func livePostgresRedactSecrets(value string) string {
	for _, environment := range []string{
		livePostgresOwnerDSNEnv,
		livePostgresRuntimeDSNEnv,
		livePostgresAdminDSNEnv,
	} {
		if secret := os.Getenv(environment); secret != "" {
			value = strings.ReplaceAll(value, secret, "[redacted DSN]")
		}
	}
	return value
}

func assertLivePostgresProcessRowsAbsent(t *testing.T, ctx context.Context,
	ownerDB *sql.DB, fixture livePostgresProcessFixture) {
	t.Helper()
	scope, err := replayScopeDigest(fixture.entry)
	if err != nil {
		t.Fatal(err)
	}
	var rows int64
	err = ownerDB.QueryRowContext(ctx, `
		SELECT
		  (SELECT count(*) FROM cph_aiinfra.ccse_replay_head WHERE scope_sha256 = $1) +
		  (SELECT count(*) FROM cph_aiinfra.ccse_durable_result WHERE scope_sha256 = $1 AND message_id = $2) +
		  (SELECT count(*) FROM cph_aiinfra.ccse_replay_inbox WHERE scope_sha256 = $1 AND message_id = $2) +
		  (SELECT count(*) FROM cph_aiinfra.authoritative_uow WHERE scope_sha256 = $1 AND message_id = $2) +
		  (SELECT count(*) FROM cph_aiinfra.business_idempotency_head WHERE idempotency_key IN ($3, $4)) +
		  (SELECT count(*) FROM cph_aiinfra.business_idempotency_history WHERE idempotency_key IN ($3, $4)) +
		  (SELECT count(*) FROM cph_aiinfra.global_identifier_head WHERE identifier = $5) +
		  (SELECT count(*) FROM cph_aiinfra.global_identifier_history WHERE identifier = $5) +
		  (SELECT count(*) FROM cph_aiinfra.global_identifier_claim WHERE audit_event_id = $5) +
		  (SELECT count(*) FROM cph_aiinfra.durable_pending_head WHERE pending_key = $3) +
		  (SELECT count(*) FROM cph_aiinfra.durable_pending_revision WHERE pending_key = $3)`,
		scope[:], fixture.entry.MessageID[:], fixture.parent.Key[:], fixture.joined.Key[:], fixture.eventID,
	).Scan(&rows)
	if err != nil {
		t.Fatalf("inspect rows after interrupted process: %v", err)
	}
	if rows != 0 {
		t.Fatalf("interrupted process retained %d authoritative rows", rows)
	}
}
