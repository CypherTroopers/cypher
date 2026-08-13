// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"math"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	livePostgresRestoreAcceptanceEnv     = "CPH_AIIE_POSTGRES_RESTORE_ACCEPTANCE"
	livePostgresRestoreSourceOwnerDSNEnv = "CPH_AIIE_POSTGRES_RESTORE_SOURCE_OWNER_DSN"
	livePostgresRestoreSourceDSNEnv      = "CPH_AIIE_POSTGRES_RESTORE_SOURCE_RUNTIME_DSN"
	livePostgresRestoredOwnerDSNEnv      = "CPH_AIIE_POSTGRES_RESTORED_OWNER_DSN"
	livePostgresRestoredDSNEnv           = "CPH_AIIE_POSTGRES_RESTORED_RUNTIME_DSN"
)

type livePostgresTableSnapshot struct {
	rows   uint64
	digest [sha256.Size]byte
}

type livePostgresTerminalReload struct {
	database     string
	runtimeRole  string
	server       int
	terminalJSON string
	entry        ccse.ReplayEntry
	outcome      [sha256.Size]byte
	result       DurableResult
}

// TestLivePostgresRestoredSnapshot verifies a completed pg_dump/pg_restore
// cycle. It is separate from the mutable lifecycle test: the source and
// restored runtime DSNs must use the same exact restricted login, while the
// two owner DSNs are used only for the complete logical table snapshot because
// active outbox lease tokens are intentionally unreadable by runtime. Source
// and restore must name distinct databases. The companion integration script
// creates only a previously absent restore database and retains the archive
// and test log.
func TestLivePostgresRestoredSnapshot(t *testing.T) {
	if os.Getenv(livePostgresDisposableEnv) != "YES" ||
		os.Getenv(livePostgresRestoreAcceptanceEnv) != "YES" {
		t.Skip("set the disposable and restore-acceptance gates to run the live restore test")
	}
	sourceOwnerDSN := os.Getenv(livePostgresRestoreSourceOwnerDSNEnv)
	restoredOwnerDSN := os.Getenv(livePostgresRestoredOwnerDSNEnv)
	sourceDSN := os.Getenv(livePostgresRestoreSourceDSNEnv)
	restoredDSN := os.Getenv(livePostgresRestoredDSNEnv)
	if sourceOwnerDSN == "" || restoredOwnerDSN == "" || sourceDSN == "" || restoredDSN == "" {
		t.Fatal("live restore acceptance requires source and restored owner/runtime DSNs")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	sourceDB := openLiveRestorePostgres(t, ctx, sourceDSN, "source runtime")
	restoredDB := openLiveRestorePostgres(t, ctx, restoredDSN, "restored runtime")
	sourceOwnerDB := openLiveRestorePostgres(t, ctx, sourceOwnerDSN, "source owner")
	restoredOwnerDB := openLiveRestorePostgres(t, ctx, restoredOwnerDSN, "restored owner")

	sourceIdentity := liveRestoreIdentity(t, ctx, sourceDB)
	restoredIdentity := liveRestoreIdentity(t, ctx, restoredDB)
	if sourceIdentity.database == restoredIdentity.database {
		t.Fatal("source and restored DSNs name the same database")
	}
	if sourceIdentity.runtimeRole != restoredIdentity.runtimeRole {
		t.Fatalf("runtime role changed across restore: source=%q restored=%q",
			sourceIdentity.runtimeRole, restoredIdentity.runtimeRole)
	}
	if sourceIdentity.server != restoredIdentity.server {
		t.Fatalf("PostgreSQL server version changed across restore: source=%d restored=%d",
			sourceIdentity.server, restoredIdentity.server)
	}

	if err := VerifyReplayStore(ctx, sourceDB); err != nil {
		t.Fatalf("verify source runtime: %v", err)
	}
	if err := VerifyReplayStore(ctx, restoredDB); err != nil {
		t.Fatalf("verify restored runtime: %v", err)
	}
	sourceStore, err := NewReplayStore(ctx, sourceDB)
	if err != nil {
		t.Fatalf("construct source replay store: %v", err)
	}
	restoredStore, err := NewReplayStore(ctx, restoredDB)
	if err != nil {
		t.Fatalf("construct restored replay store: %v", err)
	}

	sourceBefore := snapshotLiveRestoreTables(t, ctx, sourceOwnerDB)
	restored := snapshotLiveRestoreTables(t, ctx, restoredOwnerDB)
	sourceAfter := snapshotLiveRestoreTables(t, ctx, sourceOwnerDB)
	compareLiveRestoreSnapshots(t, "source changed while restore evidence was read", sourceBefore, sourceAfter)
	compareLiveRestoreSnapshots(t, "restored snapshot differs from source", sourceBefore, restored)
	requireLiveRestoreEvidenceRows(t, sourceBefore)

	sourceTerminal := loadLiveRestoreTerminal(t, ctx, sourceDB, sourceStore)
	restoredTerminal := loadLiveRestoreTerminal(t, ctx, restoredDB, restoredStore)
	if sourceTerminal.entry != restoredTerminal.entry ||
		sourceTerminal.outcome != restoredTerminal.outcome ||
		sourceTerminal.terminalJSON != restoredTerminal.terminalJSON ||
		sourceTerminal.result.ContentType != restoredTerminal.result.ContentType ||
		!bytes.Equal(sourceTerminal.result.Payload, restoredTerminal.result.Payload) {
		t.Fatal("terminal canonical UoW or its durable result differs after restore")
	}

	t.Logf("restore accepted source=%s restored=%s runtime=%s server_version_num=%d tables=%d",
		sourceIdentity.database, restoredIdentity.database, sourceIdentity.runtimeRole,
		sourceIdentity.server, len(sourceBefore))
	payloadDigest := sha256Bytes(sourceTerminal.result.Payload)
	t.Logf("terminal durable result outcome_sha256=%s payload_sha256=%s content_type=%s",
		hex.EncodeToString(sourceTerminal.outcome[:]),
		hex.EncodeToString(payloadDigest[:]),
		sourceTerminal.result.ContentType)
	for _, table := range sortedLiveRestoreTables(sourceBefore) {
		evidence := sourceBefore[table]
		t.Logf("table=%s rows=%d logical_sha256=%s", table, evidence.rows,
			hex.EncodeToString(evidence.digest[:]))
	}
}

type liveRestoreDatabaseIdentity struct {
	database    string
	runtimeRole string
	server      int
}

func openLiveRestorePostgres(t *testing.T, ctx context.Context, dsn, label string) *sql.DB {
	t.Helper()
	database, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open %s PostgreSQL connection", label)
	}
	database.SetMaxOpenConns(2)
	database.SetMaxIdleConns(2)
	t.Cleanup(func() { _ = database.Close() })
	if err := database.PingContext(ctx); err != nil {
		t.Fatalf("connect to %s PostgreSQL", label)
	}
	return database
}

func liveRestoreIdentity(t *testing.T, ctx context.Context, database *sql.DB) liveRestoreDatabaseIdentity {
	t.Helper()
	var identity liveRestoreDatabaseIdentity
	if err := database.QueryRowContext(ctx, `
		SELECT pg_catalog.current_database(), current_user,
		       pg_catalog.current_setting('server_version_num')::integer`,
	).Scan(&identity.database, &identity.runtimeRole, &identity.server); err != nil {
		t.Fatalf("read live restore database identity: %v", err)
	}
	return identity
}

func snapshotLiveRestoreTables(t *testing.T, ctx context.Context,
	database *sql.DB) map[string]livePostgresTableSnapshot {
	t.Helper()
	tx, err := database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: true})
	if err != nil {
		t.Fatalf("begin live restore snapshot: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, statement := range []string{
		"SET LOCAL search_path = pg_catalog",
		"SET LOCAL TIME ZONE 'UTC'",
		"SET LOCAL bytea_output = 'hex'",
		"SET LOCAL extra_float_digits = 3",
	} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			t.Fatalf("fix live restore snapshot output: %v", err)
		}
	}

	tables := make([]string, 0, len(replayColumnContract))
	for table := range replayColumnContract {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	snapshot := make(map[string]livePostgresTableSnapshot, len(tables))
	for _, table := range tables {
		primaryKey := liveRestorePrimaryKey(t, ctx, tx, table)
		if len(primaryKey) == 0 {
			t.Fatalf("authoritative table %s has no primary key", table)
		}
		snapshot[table] = liveRestoreTableDigest(t, ctx, tx, table, primaryKey)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit live restore snapshot read: %v", err)
	}
	return snapshot
}

func liveRestorePrimaryKey(t *testing.T, ctx context.Context, tx *sql.Tx, table string) []string {
	t.Helper()
	rows, err := tx.QueryContext(ctx, `
		SELECT attribute.attname
		FROM pg_catalog.pg_index index_catalog
		CROSS JOIN LATERAL pg_catalog.unnest(index_catalog.indkey)
		  WITH ORDINALITY AS key_column(attnum, position)
		JOIN pg_catalog.pg_class relation ON relation.oid = index_catalog.indrelid
		JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
		JOIN pg_catalog.pg_attribute attribute
		  ON attribute.attrelid = relation.oid AND attribute.attnum = key_column.attnum
		WHERE namespace.nspname = 'cph_aiinfra' AND relation.relname = $1
		  AND index_catalog.indisprimary AND key_column.position <= index_catalog.indnkeyatts
		ORDER BY key_column.position`, table)
	if err != nil {
		t.Fatalf("inspect primary key for %s: %v", table, err)
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			t.Fatalf("scan primary key for %s: %v", table, err)
		}
		columns = append(columns, column)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read primary key for %s: %v", table, err)
	}
	return columns
}

func liveRestoreTableDigest(t *testing.T, ctx context.Context, tx *sql.Tx,
	table string, primaryKey []string) livePostgresTableSnapshot {
	t.Helper()
	order := make([]string, len(primaryKey))
	for index, column := range primaryKey {
		order[index] = pgx.Identifier{"row_value", column}.Sanitize()
	}
	query := "SELECT pg_catalog.to_jsonb(row_value)::pg_catalog.text FROM " +
		pgx.Identifier{"cph_aiinfra", table}.Sanitize() + " AS row_value ORDER BY " +
		strings.Join(order, ", ")
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		t.Fatalf("read authoritative table %s: %v", table, err)
	}
	defer rows.Close()
	digest := sha256.New()
	writeLiveRestoreDigestPart(digest, []byte("CPH-AIIE-POSTGRES-LOGICAL-TABLE-V1\x00"))
	writeLiveRestoreDigestPart(digest, []byte(table))
	var count uint64
	for rows.Next() {
		var canonicalJSON string
		if err := rows.Scan(&canonicalJSON); err != nil {
			t.Fatalf("scan authoritative table %s: %v", table, err)
		}
		writeLiveRestoreDigestPart(digest, []byte(canonicalJSON))
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("stream authoritative table %s: %v", table, err)
	}
	var countBytes [8]byte
	binary.BigEndian.PutUint64(countBytes[:], count)
	writeLiveRestoreDigestPart(digest, countBytes[:])
	var sealed [sha256.Size]byte
	copy(sealed[:], digest.Sum(nil))
	return livePostgresTableSnapshot{rows: count, digest: sealed}
}

func writeLiveRestoreDigestPart(digest hash.Hash, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = digest.Write(length[:])
	_, _ = digest.Write(value)
}

func compareLiveRestoreSnapshots(t *testing.T, message string,
	expected, actual map[string]livePostgresTableSnapshot) {
	t.Helper()
	if len(expected) != len(actual) {
		t.Fatalf("%s: table count %d, want %d", message, len(actual), len(expected))
	}
	for table, want := range expected {
		got, found := actual[table]
		if !found || got != want {
			t.Fatalf("%s: table=%s got_rows=%d got_sha256=%s want_rows=%d want_sha256=%s",
				message, table, got.rows, hex.EncodeToString(got.digest[:]),
				want.rows, hex.EncodeToString(want.digest[:]))
		}
	}
}

func requireLiveRestoreEvidenceRows(t *testing.T, snapshot map[string]livePostgresTableSnapshot) {
	t.Helper()
	required := map[string]uint64{
		"schema_migration":              uint64(latestSchemaVersion),
		"ccse_replay_inbox":             1,
		"ccse_durable_result":           1,
		"authoritative_uow":             1,
		"audit_event":                   1,
		"durable_pending_head":          1,
		"canonical_semantic_projection": 1,
		"ccse_outbox_intent":            1,
		"ccse_outbox_delivery":          1,
	}
	for table, minimum := range required {
		evidence, found := snapshot[table]
		if !found || evidence.rows < minimum {
			t.Fatalf("restore source lacks required evidence table=%s rows=%d minimum=%d",
				table, evidence.rows, minimum)
		}
	}
}

func loadLiveRestoreTerminal(t *testing.T, ctx context.Context, database *sql.DB,
	store *ReplayStore) livePostgresTerminalReload {
	t.Helper()
	var result livePostgresTerminalReload
	var messageType, schemaMajor, schemaMinor, counterKind int64
	var scope, chainID, genesisHash, messageID, recordDigest, sequence, outcome []byte
	var expiresAt int64
	err := database.QueryRowContext(ctx, `
		SELECT pg_catalog.current_database(), current_user,
		       pg_catalog.current_setting('server_version_num')::integer,
		       pg_catalog.to_jsonb(pending)::pg_catalog.text,
		       inbox.message_type_id, inbox.schema_major, inbox.schema_minor,
		       inbox.counter_kind, head.replay_domain_id, head.sender_identity,
		       head.environment, head.chain_id, head.genesis_hash,
		       inbox.scope_sha256, inbox.message_id, inbox.record_digest,
		       inbox.sequence, inbox.expires_at_unix_nano, inbox.outcome_digest
		FROM cph_aiinfra.durable_pending_head pending
		JOIN cph_aiinfra.authoritative_uow uow
		  ON uow.scope_sha256 = pending.uow_scope_sha256
		 AND uow.message_id = pending.uow_message_id
		JOIN cph_aiinfra.ccse_replay_inbox inbox
		  ON inbox.scope_sha256 = uow.scope_sha256 AND inbox.message_id = uow.message_id
		JOIN cph_aiinfra.ccse_replay_head head ON head.scope_sha256 = inbox.scope_sha256
		WHERE pending.status = $1
		ORDER BY pending.pending_key
		LIMIT 1`, int16(DurablePendingTerminal)).Scan(
		&result.database, &result.runtimeRole, &result.server, &result.terminalJSON,
		&messageType, &schemaMajor, &schemaMinor, &counterKind,
		&result.entry.ReplayDomainID, &result.entry.SenderIdentity, &result.entry.Environment,
		&chainID, &genesisHash, &scope, &messageID, &recordDigest, &sequence,
		&expiresAt, &outcome)
	if err != nil {
		t.Fatalf("reload terminal canonical UoW: %v", err)
	}
	if messageType < 1 || messageType > math.MaxUint32 || schemaMajor < 1 || schemaMajor > math.MaxUint32 ||
		schemaMinor < 0 || schemaMinor > math.MaxUint32 || counterKind < 1 || counterKind > math.MaxUint32 ||
		len(scope) != sha256.Size || len(chainID) != sha256.Size || len(genesisHash) != sha256.Size ||
		len(messageID) != ccse.MessageIDSize || len(recordDigest) != sha256.Size ||
		len(sequence) != 8 || len(outcome) != sha256.Size {
		t.Fatal("terminal canonical UoW has malformed replay identity")
	}
	result.entry.MessageTypeID = uint32(messageType)
	result.entry.SchemaVersion = ccse.Version{Major: uint32(schemaMajor), Minor: uint32(schemaMinor)}
	result.entry.CounterKind = ccse.CounterKind(counterKind)
	copy(result.entry.ChainID[:], chainID)
	copy(result.entry.GenesisHash[:], genesisHash)
	copy(result.entry.MessageID[:], messageID)
	copy(result.entry.Digest[:], recordDigest)
	result.entry.Sequence = binary.BigEndian.Uint64(sequence)
	result.entry.ExpiresAt = expiresAt
	copy(result.outcome[:], outcome)
	if err := result.entry.Validate(); err != nil {
		t.Fatalf("validate restored terminal replay identity: %v", err)
	}
	result.result, err = store.LoadDurableResult(ctx, result.entry, result.outcome)
	if err != nil {
		t.Fatalf("load restored terminal durable result: %v", err)
	}
	return result
}

func sortedLiveRestoreTables(snapshot map[string]livePostgresTableSnapshot) []string {
	tables := make([]string, 0, len(snapshot))
	for table := range snapshot {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	return tables
}

func sha256Bytes(value []byte) [sha256.Size]byte {
	return sha256.Sum256(value)
}
