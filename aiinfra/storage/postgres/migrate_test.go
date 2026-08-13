// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"testing"
	"testing/fstest"
)

func TestMigrationRegistryLiteralPathAndDigestArePinned(t *testing.T) {
	if latestSchemaVersion != 4 {
		t.Fatalf("latest schema version = %d, want 4", latestSchemaVersion)
	}
	if executionFenceVersion != 1 {
		t.Fatalf("execution fence version = %d, want permanent version 1", executionFenceVersion)
	}
	specs, err := registeredMigrationSpecs()
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 4 {
		t.Fatalf("migration registry length = %d, want 4", len(specs))
	}
	v1 := specs[0]
	if v1.version != 1 || v1.path != "migrations/0001_ccse_replay.sql" {
		t.Fatalf("migration registry entry = {version:%d path:%q}", v1.version, v1.path)
	}
	const wantV1Digest = "ce7e56583b042e2fd94f06a7378981b5afd231b3c2e9305f0b2b359ce2d38359"
	if got := hex.EncodeToString(v1.digest[:]); got != wantV1Digest {
		t.Fatalf("migration 1 registry digest = %s, want %s", got, wantV1Digest)
	}
	v2 := specs[1]
	if v2.version != 2 || v2.path != "migrations/0002_canonical_uow.sql" {
		t.Fatalf("migration registry entry = {version:%d path:%q}", v2.version, v2.path)
	}
	const wantV2Digest = "1e17be9c59cd3d178045b05c26b8db145ef3ff816a6cde5a631ca1a5b8c485ac"
	if got := hex.EncodeToString(v2.digest[:]); got != wantV2Digest {
		t.Fatalf("migration 2 registry digest = %s, want %s", got, wantV2Digest)
	}
	v3 := specs[2]
	if v3.version != 3 || v3.path != "migrations/0003_semantic_projection_v2.sql" {
		t.Fatalf("migration registry entry = {version:%d path:%q}", v3.version, v3.path)
	}
	const wantV3Digest = "b385935c794d9f819b334b002fe80f04e4d2e9d6d854d30e7524f21904e40271"
	if got := hex.EncodeToString(v3.digest[:]); got != wantV3Digest {
		t.Fatalf("migration 3 registry digest = %s, want %s", got, wantV3Digest)
	}
	v4 := specs[3]
	if v4.version != 4 || v4.path != "migrations/0004_outbox_delivery.sql" {
		t.Fatalf("migration registry entry = {version:%d path:%q}", v4.version, v4.path)
	}
	const wantV4Digest = "4c814ecad14885e8ed04726535f6fb8b2dbaf2b24e5ff0c370f92c25847cc482"
	if got := hex.EncodeToString(v4.digest[:]); got != wantV4Digest {
		t.Fatalf("migration 4 registry digest = %s, want %s", got, wantV4Digest)
	}

	entries, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	wantNames := []string{"0000_bootstrap.sql", "0001_ccse_replay.sql", "0002_canonical_uow.sql",
		"0003_semantic_projection_v2.sql", "0004_outbox_delivery.sql"}
	if !slices.Equal(names, wantNames) {
		t.Fatalf("embedded migration file set = %q, want %q", names, wantNames)
	}
	for _, spec := range specs {
		if spec.path == bootstrapMigration.path {
			t.Fatal("bootstrap must remain outside the numbered migration registry")
		}
	}
}

func TestBootstrapMigrationPathAndDigestArePinned(t *testing.T) {
	if bootstrapMigration.path != "migrations/0000_bootstrap.sql" {
		t.Fatalf("bootstrap path = %q, want migrations/0000_bootstrap.sql", bootstrapMigration.path)
	}
	const wantDigest = "f57eae33415e950978dff1e1d9f24c1e4bb2f90aae239ccbc4ee801eda44a760"
	if got := hex.EncodeToString(bootstrapMigration.digest[:]); got != wantDigest {
		t.Fatalf("bootstrap digest = %s, want %s", got, wantDigest)
	}
	if _, err := readPinnedBootstrap(migrationFiles); err != nil {
		t.Fatalf("embedded bootstrap rejected: %v", err)
	}
}

func TestBootstrapSourceMutationFailsBeforeBegin(t *testing.T) {
	source := copiedEmbeddedMigrationFS(t)
	source[bootstrapMigration.path].Data[0] ^= 0xff
	database := new(countingBeginTxer)
	err := migrateReplayStoreWithSources(context.Background(), database, source)
	if !errors.Is(err, errMigrationSourceMismatch) {
		t.Fatalf("bootstrap mutation error = %v, want %v", err, errMigrationSourceMismatch)
	}
	if database.begins != 0 {
		t.Fatalf("BeginTx calls = %d, want 0", database.begins)
	}
}

func TestMigrationLedgerRejectsGap(t *testing.T) {
	specs := syntheticMigrationSpecs(3)
	applied := readFakeMigrationLedger(t, []migrationLedgerRecord{
		ledgerRecord(specs[0]),
		ledgerRecord(specs[2]),
	})
	if _, err := pendingMigrations(specs, applied); !errors.Is(err, ErrMigrationLedgerGap) {
		t.Fatalf("gap error = %v, want %v", err, ErrMigrationLedgerGap)
	}
}

func TestMigrationLedgerRejectsUnknownFutureVersion(t *testing.T) {
	specs, err := registeredMigrationSpecs()
	if err != nil {
		t.Fatal(err)
	}
	applied := readFakeMigrationLedger(t, []migrationLedgerRecord{
		ledgerRecord(specs[0]),
		{version: latestSchemaVersion + 1, digest: make([]byte, sha256.Size)},
	})
	if _, err := pendingMigrations(specs, applied); !errors.Is(err, ErrUnknownMigrationVersion) {
		t.Fatalf("unknown-version error = %v, want %v", err, ErrUnknownMigrationVersion)
	}
}

func TestMigrationLedgerRejectsDigestMismatch(t *testing.T) {
	specs, err := registeredMigrationSpecs()
	if err != nil {
		t.Fatal(err)
	}
	applied := ledgerRecord(specs[0])
	applied.digest[0] ^= 0xff
	if _, err := pendingMigrations(specs, readFakeMigrationLedger(t, []migrationLedgerRecord{applied})); !errors.Is(err, ErrMigrationDigestMismatch) {
		t.Fatalf("digest error = %v, want %v", err, ErrMigrationDigestMismatch)
	}
}

func TestMigrationRegistryRejectsNonContiguousVersions(t *testing.T) {
	specs := syntheticMigrationSpecs(3)
	specs[1].version = 3
	if err := validateMigrationSpecs(specs, 3); !errors.Is(err, errMigrationRegistryInvalid) {
		t.Fatalf("registry gap error = %v, want %v", err, errMigrationRegistryInvalid)
	}
}

func TestMigrationsApplyAndRecordOnlyPendingSuffixInOrder(t *testing.T) {
	specs, prepared := threePreparedMigrations(t)
	applied := readFakeMigrationLedger(t, []migrationLedgerRecord{ledgerRecord(specs[0])})
	pending, err := pendingMigrations(specs, applied)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 2 {
		t.Fatalf("pending migration count = %d, want 2", len(pending))
	}
	pendingPrepared := prepared[len(prepared)-len(pending):]

	database, driverInstance := newUnitDatabase(t)
	tx, err := database.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	if err := applyMigrations(context.Background(), tx, pendingPrepared); err != nil {
		t.Fatal(err)
	}
	if err := recordMigrations(context.Background(), tx, pending); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	driverInstance.mu.Lock()
	got := append([]string(nil), driverInstance.executions...)
	arguments := append([][]driver.NamedValue(nil), driverInstance.executionArgs...)
	commits, rollbacks := driverInstance.commits, driverInstance.rollbacks
	driverInstance.mu.Unlock()
	want := []string{
		"SELECT 'migration-two-a'",
		"SELECT 'migration-two-b'",
		"SELECT 'migration-three'",
		"INSERT INTO cph_aiinfra.schema_migration(version, migration_sha256) VALUES ($1, $2)",
		"INSERT INTO cph_aiinfra.schema_migration(version, migration_sha256) VALUES ($1, $2)",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("migration execution order = %q, want %q", got, want)
	}
	if len(arguments) != len(want) {
		t.Fatalf("captured argument count = %d, want %d", len(arguments), len(want))
	}
	for index := 0; index < 3; index++ {
		if len(arguments[index]) != 0 {
			t.Fatalf("migration statement %d arguments = %#v, want none", index+1, arguments[index])
		}
	}
	assertMigrationInsertArguments(t, arguments[3], specs[1])
	assertMigrationInsertArguments(t, arguments[4], specs[2])
	if commits != 1 || rollbacks != 0 {
		t.Fatalf("commits=%d rollbacks=%d, want commits=1 rollbacks=0", commits, rollbacks)
	}
}

func TestMigrationStatementFailureRollsBackPendingSuffix(t *testing.T) {
	specs, prepared := threePreparedMigrations(t)
	pending, err := pendingMigrations(specs, []migrationLedgerRecord{ledgerRecord(specs[0])})
	if err != nil {
		t.Fatal(err)
	}
	pendingPrepared := prepared[len(prepared)-len(pending):]
	database, driverInstance := newUnitDatabase(t)
	statementFailure := errors.New("synthetic migration statement failure")
	driverInstance.mu.Lock()
	driverInstance.directExecErrorQuery = "SELECT 'migration-two-b'"
	driverInstance.directExecError = statementFailure
	driverInstance.mu.Unlock()

	err = func() error {
		tx, err := database.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		if err := applyMigrations(context.Background(), tx, pendingPrepared); err != nil {
			return err
		}
		if err := recordMigrations(context.Background(), tx, pending); err != nil {
			return err
		}
		return tx.Commit()
	}()
	if !errors.Is(err, statementFailure) {
		t.Fatalf("migration failure = %v, want %v", err, statementFailure)
	}

	driverInstance.mu.Lock()
	got := append([]string(nil), driverInstance.executions...)
	commits, rollbacks := driverInstance.commits, driverInstance.rollbacks
	driverInstance.mu.Unlock()
	want := []string{"SELECT 'migration-two-a'", "SELECT 'migration-two-b'"}
	if !slices.Equal(got, want) {
		t.Fatalf("executions after failure = %q, want %q", got, want)
	}
	if commits != 0 || rollbacks != 1 {
		t.Fatalf("commits=%d rollbacks=%d, want commits=0 rollbacks=1", commits, rollbacks)
	}
}

func TestEmptyMigrationLedgerPlansEveryRegisteredMigration(t *testing.T) {
	applied := readFakeMigrationLedger(t, nil)
	if len(applied) != 0 {
		t.Fatalf("applied migration count = %d, want 0", len(applied))
	}
	specs, err := registeredMigrationSpecs()
	if err != nil {
		t.Fatal(err)
	}
	pending, err := pendingMigrations(specs, applied)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(pending, specs) {
		t.Fatalf("pending migrations = %+v, want %+v", pending, specs)
	}
}

func TestAppliedVersionOnePlansRemainingSuffix(t *testing.T) {
	specs, err := registeredMigrationSpecs()
	if err != nil {
		t.Fatal(err)
	}
	pending, err := pendingMigrations(specs, []migrationLedgerRecord{ledgerRecord(specs[0])})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(pending, specs[1:]) {
		t.Fatalf("pending migrations = %+v, want versions 2 through 4", pending)
	}
	if err := verifyCompleteMigrationLedger(specs, []migrationLedgerRecord{ledgerRecord(specs[0])}); !errors.Is(err, ErrMigrationLedgerGap) {
		t.Fatalf("incomplete migration ledger error = %v, want %v", err, ErrMigrationLedgerGap)
	}
	complete := make([]migrationLedgerRecord, len(specs))
	for index, spec := range specs {
		complete[index] = ledgerRecord(spec)
	}
	if err := verifyCompleteMigrationLedger(specs, complete); err != nil {
		t.Fatalf("complete migration ledger rejected: %v", err)
	}
}

func TestRuntimeMigrationLedgerMustBeComplete(t *testing.T) {
	specs, err := registeredMigrationSpecs()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCompleteMigrationLedger(specs, nil); !errors.Is(err, ErrMigrationLedgerGap) {
		t.Fatalf("incomplete-ledger error = %v, want %v", err, ErrMigrationLedgerGap)
	}
}

func syntheticMigrationSpecs(count int) []migrationSpec {
	specs := make([]migrationSpec, 0, count)
	for version := 1; version <= count; version++ {
		source := []byte{byte(version)}
		specs = append(specs, migrationSpec{
			version: int64(version),
			path:    fmt.Sprintf("migrations/%04d_test.sql", version),
			digest:  sha256.Sum256(source),
		})
	}
	return specs
}

func ledgerRecord(spec migrationSpec) migrationLedgerRecord {
	return migrationLedgerRecord{version: spec.version, digest: append([]byte(nil), spec.digest[:]...)}
}

func testMigrationSpec(version int64, path string, sources fstest.MapFS) migrationSpec {
	return migrationSpec{version: version, path: path, digest: sha256.Sum256(sources[path].Data)}
}

func threePreparedMigrations(t *testing.T) ([]migrationSpec, []preparedMigration) {
	t.Helper()
	sources := fstest.MapFS{
		"migrations/0001_test.sql": {Data: []byte("SELECT 'migration-one';")},
		"migrations/0002_test.sql": {Data: []byte("SELECT 'migration-two-a'; SELECT 'migration-two-b';")},
		"migrations/0003_test.sql": {Data: []byte("SELECT 'migration-three';")},
	}
	specs := []migrationSpec{
		testMigrationSpec(1, "migrations/0001_test.sql", sources),
		testMigrationSpec(2, "migrations/0002_test.sql", sources),
		testMigrationSpec(3, "migrations/0003_test.sql", sources),
	}
	prepared, err := prepareMigrations(sources, specs)
	if err != nil {
		t.Fatal(err)
	}
	return specs, prepared
}

func assertMigrationInsertArguments(t *testing.T, arguments []driver.NamedValue, spec migrationSpec) {
	t.Helper()
	if len(arguments) != 2 {
		t.Fatalf("migration %d insert arguments = %#v, want 2 arguments", spec.version, arguments)
	}
	version, ok := arguments[0].Value.(int64)
	if !ok || arguments[0].Ordinal != 1 || arguments[0].Name != "" || version != spec.version {
		t.Fatalf("migration %d version argument = %#v", spec.version, arguments[0])
	}
	digest, ok := arguments[1].Value.([]byte)
	if !ok || arguments[1].Ordinal != 2 || arguments[1].Name != "" || !bytes.Equal(digest, spec.digest[:]) {
		t.Fatalf("migration %d digest argument = %#v", spec.version, arguments[1])
	}
}

func copiedEmbeddedMigrationFS(t *testing.T) fstest.MapFS {
	t.Helper()
	source := make(fstest.MapFS, len(migrationRegistry)+1)
	paths := []string{bootstrapMigration.path}
	for _, spec := range migrationRegistry {
		paths = append(paths, spec.path)
	}
	for _, path := range paths {
		contents, err := migrationFiles.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		source[path] = &fstest.MapFile{Data: bytes.Clone(contents)}
	}
	return source
}

type countingBeginTxer struct{ begins int }

func (database *countingBeginTxer) BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error) {
	database.begins++
	return nil, errors.New("unexpected BeginTx")
}

func readFakeMigrationLedger(t *testing.T, records []migrationLedgerRecord) []migrationLedgerRecord {
	t.Helper()
	database, driverInstance := newUnitDatabase(t)
	rows := make([][]driver.Value, 0, len(records))
	for _, record := range records {
		rows = append(rows, []driver.Value{record.version, record.digest})
	}
	driverInstance.mu.Lock()
	driverInstance.migrationRows = rows
	driverInstance.mu.Unlock()
	tx, err := database.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	applied, err := readMigrationLedger(context.Background(), tx)
	if err != nil {
		t.Fatal(err)
	}
	return applied
}
