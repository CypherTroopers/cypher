// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strings"
)

const (
	latestSchemaVersion int64 = 2
	// The runtime fence is the immutable v1 ledger row, not the latest schema.
	executionFenceVersion int64 = 1
	// ASCII "CPHAIIE0" interpreted as a positive signed 64-bit integer.
	migrationAdvisoryLock int64 = 0x4350484149494530
)

var (
	ErrDatabaseRequired         = errors.New("aiinfra postgres: database is required")
	ErrMigrationDigestMismatch  = errors.New("aiinfra postgres: applied migration digest does not match source")
	ErrMigrationLedgerGap       = errors.New("aiinfra postgres: migration ledger is not a contiguous prefix")
	ErrUnknownMigrationVersion  = errors.New("aiinfra postgres: migration ledger contains an unknown version")
	ErrSchemaShapeMismatch      = errors.New("aiinfra postgres: database schema does not match the replay contract")
	ErrUnsafeRuntimeRole        = errors.New("aiinfra postgres: runtime database role violates least privilege")
	ErrUnsafeMigrationRole      = errors.New("aiinfra postgres: migration role does not own the schema contract")
	errMigrationRegistryInvalid = errors.New("aiinfra postgres: embedded migration registry is invalid")
	errMigrationSourceMismatch  = errors.New("aiinfra postgres: embedded migration source does not match its pinned digest")
)

//go:embed migrations/0000_bootstrap.sql migrations/0001_ccse_replay.sql migrations/0002_canonical_uow.sql
var migrationFiles embed.FS

type pinnedMigrationSource struct {
	path   string
	digest [sha256.Size]byte
}

type migrationSpec struct {
	version int64
	path    string
	digest  [sha256.Size]byte
}

// Bootstrap is intentionally outside the numbered ledger, but its source is
// still immutable and must be authenticated before any database transaction.
var bootstrapMigration = pinnedMigrationSource{
	path: "migrations/0000_bootstrap.sql",
	digest: [sha256.Size]byte{
		0xf5, 0x7e, 0xae, 0x33, 0x41, 0x5e, 0x95, 0x09,
		0x78, 0xdf, 0xf1, 0xe1, 0xd9, 0xf2, 0x4c, 0x1e,
		0x4b, 0xb2, 0xf9, 0x0a, 0xae, 0x23, 0x9c, 0xcb,
		0xc4, 0xee, 0x80, 0x1e, 0xda, 0x44, 0xa7, 0x60,
	},
}

// migrationRegistry is deliberately an ordered, closed literal rather than a
// directory glob. Adding a file cannot make it executable: a release must add
// the pinned source path and digest here and advance latestSchemaVersion.
var migrationRegistry = [...]migrationSpec{
	{
		version: 1,
		path:    "migrations/0001_ccse_replay.sql",
		digest: [sha256.Size]byte{
			0xce, 0x7e, 0x56, 0x58, 0x3b, 0x04, 0x2e, 0x2f,
			0xd9, 0x4f, 0x06, 0xa7, 0x37, 0x89, 0x81, 0xb5,
			0xaf, 0xd2, 0x31, 0xb3, 0xc2, 0xe9, 0x30, 0x5f,
			0x0b, 0x2b, 0x35, 0x9c, 0xe2, 0xd3, 0x83, 0x59,
		},
	},
	{
		version: 2,
		path:    "migrations/0002_canonical_uow.sql",
		digest: [sha256.Size]byte{
			0xa1, 0xf1, 0xf2, 0x33, 0xfa, 0x2f, 0xe0, 0xf1,
			0x07, 0x72, 0x33, 0xe0, 0x04, 0x3d, 0x25, 0xf7,
			0x1c, 0x4a, 0x7a, 0x7a, 0x95, 0xb1, 0xc8, 0xb0,
			0xa1, 0xe0, 0x90, 0x39, 0xfc, 0x64, 0xeb, 0xc1,
		},
	},
}

type preparedMigration struct {
	spec       migrationSpec
	statements []string
}

type migrationLedgerRecord struct {
	version int64
	digest  []byte
}

// BeginTxer is implemented by sql.DB. Keeping this narrow lets every canonical
// service own and configure its pool while sharing the transaction contract.
type BeginTxer interface {
	BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
}

// ReplayMigrationDigest returns the exact SHA-256 recorded for migration 1.
// The raw migration is immutable after a production deployment; a change must
// be introduced as a new numbered migration.
func ReplayMigrationDigest() ([sha256.Size]byte, error) {
	specs, err := registeredMigrationSpecs()
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	if _, err := readPinnedMigration(migrationFiles, specs[0]); err != nil {
		return [sha256.Size]byte{}, err
	}
	return specs[0].digest, nil
}

// CanonicalUOWMigrationDigest returns the immutable migration-2 source seal.
func CanonicalUOWMigrationDigest() ([sha256.Size]byte, error) {
	specs, err := registeredMigrationSpecs()
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	const index = 1
	if _, err := readPinnedMigration(migrationFiles, specs[index]); err != nil {
		return [sha256.Size]byte{}, err
	}
	return specs[index].digest, nil
}

// MigrateReplayStore installs and verifies the replay inbox schema under one
// serializable transaction and a cluster-wide advisory lock. Numbered DDL runs
// only for the absent ordered suffix; migration 1's CREATE statements
// intentionally fail on partial/look-alike objects. An already-applied version
// is never replayed.
// This owner-side operation is not a readiness check: the service must
// subsequently call VerifyReplayStore or NewReplayStore through the dedicated
// runtime role so the closed writer/ACL contract is evaluated in that identity.
func MigrateReplayStore(ctx context.Context, db BeginTxer) error {
	return migrateReplayStoreWithSources(ctx, db, migrationFiles)
}

func migrateReplayStoreWithSources(ctx context.Context, db BeginTxer, source fs.FS) error {
	if db == nil {
		return ErrDatabaseRequired
	}
	specs, err := registeredMigrationSpecs()
	if err != nil {
		return err
	}
	prepared, err := prepareMigrations(source, specs)
	if err != nil {
		return err
	}
	bootstrap, err := readPinnedBootstrap(source)
	if err != nil {
		return err
	}
	bootstrapStatements, err := splitSQLStatements(string(bootstrap))
	if err != nil {
		return fmt.Errorf("aiinfra postgres: parse migration bootstrap: %w", err)
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("aiinfra postgres: begin migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, "SET LOCAL search_path = pg_catalog"); err != nil {
		return fmt.Errorf("aiinfra postgres: constrain migration search path: %w", err)
	}
	if err := assertSessionReplicationOrigin(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "SELECT pg_catalog.pg_advisory_xact_lock($1)", migrationAdvisoryLock); err != nil {
		return fmt.Errorf("aiinfra postgres: lock migration: %w", err)
	}
	for number, statement := range bootstrapStatements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("aiinfra postgres: bootstrap migration ledger statement %d: %w", number+1, err)
		}
	}
	if err := verifyMigrationLedgerShape(ctx, tx); err != nil {
		return err
	}
	if err := verifyMigrationAuthority(ctx, tx); err != nil {
		return err
	}

	applied, err := readMigrationLedger(ctx, tx)
	if err != nil {
		return err
	}
	pendingSpecs, err := pendingMigrations(specs, applied)
	if err != nil {
		return err
	}
	if len(pendingSpecs) > 0 {
		pending := prepared[len(prepared)-len(pendingSpecs):]
		if err := applyMigrations(ctx, tx, pending); err != nil {
			return err
		}
		if err := verifyReplaySchemaShape(ctx, tx); err != nil {
			return err
		}
		if err := recordMigrations(ctx, tx, pendingSpecs); err != nil {
			return err
		}
	}
	if err := verifyReplaySchemaWithSources(ctx, tx, source); err != nil {
		return err
	}
	if err := assertSessionReplicationOrigin(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("aiinfra postgres: commit migration: %w", err)
	}
	return nil
}

func readPinnedBootstrap(source fs.FS) ([]byte, error) {
	contents, err := fs.ReadFile(source, bootstrapMigration.path)
	if err != nil {
		return nil, fmt.Errorf("aiinfra postgres: read migration bootstrap at %q: %w", bootstrapMigration.path, err)
	}
	if digest := sha256.Sum256(contents); digest != bootstrapMigration.digest {
		return nil, fmt.Errorf("%w: bootstrap at %q", errMigrationSourceMismatch, bootstrapMigration.path)
	}
	return contents, nil
}

func registeredMigrationSpecs() ([]migrationSpec, error) {
	specs := append([]migrationSpec(nil), migrationRegistry[:]...)
	if err := validateMigrationSpecs(specs, latestSchemaVersion); err != nil {
		return nil, err
	}
	return specs, nil
}

func validateMigrationSpecs(specs []migrationSpec, latest int64) error {
	if latest < 1 || int64(len(specs)) != latest {
		return fmt.Errorf("%w: latest version %d has %d entries", errMigrationRegistryInvalid, latest, len(specs))
	}
	paths := make(map[string]struct{}, len(specs))
	for index, spec := range specs {
		wantVersion := int64(index + 1)
		if spec.version != wantVersion {
			return fmt.Errorf("%w: entry %d has version %d, want %d", errMigrationRegistryInvalid, index, spec.version, wantVersion)
		}
		wantPrefix := fmt.Sprintf("migrations/%04d_", wantVersion)
		if !strings.HasPrefix(spec.path, wantPrefix) || !strings.HasSuffix(spec.path, ".sql") {
			return fmt.Errorf("%w: version %d has invalid path %q", errMigrationRegistryInvalid, spec.version, spec.path)
		}
		if _, exists := paths[spec.path]; exists {
			return fmt.Errorf("%w: duplicate path %q", errMigrationRegistryInvalid, spec.path)
		}
		paths[spec.path] = struct{}{}
		if spec.digest == ([sha256.Size]byte{}) {
			return fmt.Errorf("%w: version %d has an empty digest", errMigrationRegistryInvalid, spec.version)
		}
	}
	return nil
}

func prepareMigrations(source fs.FS, specs []migrationSpec) ([]preparedMigration, error) {
	if err := validateMigrationSpecs(specs, int64(len(specs))); err != nil {
		return nil, err
	}
	prepared := make([]preparedMigration, 0, len(specs))
	for _, spec := range specs {
		contents, err := readPinnedMigration(source, spec)
		if err != nil {
			return nil, err
		}
		statements, err := splitSQLStatements(string(contents))
		if err != nil {
			return nil, fmt.Errorf("aiinfra postgres: parse migration %d at %q: %w", spec.version, spec.path, err)
		}
		prepared = append(prepared, preparedMigration{spec: spec, statements: statements})
	}
	return prepared, nil
}

func verifyMigrationSources(source fs.FS, specs []migrationSpec) error {
	if err := validateMigrationSpecs(specs, int64(len(specs))); err != nil {
		return err
	}
	for _, spec := range specs {
		if _, err := readPinnedMigration(source, spec); err != nil {
			return err
		}
	}
	return nil
}

func readPinnedMigration(source fs.FS, spec migrationSpec) ([]byte, error) {
	contents, err := fs.ReadFile(source, spec.path)
	if err != nil {
		return nil, fmt.Errorf("aiinfra postgres: read migration %d at %q: %w", spec.version, spec.path, err)
	}
	if digest := sha256.Sum256(contents); digest != spec.digest {
		return nil, fmt.Errorf("%w: version %d at %q", errMigrationSourceMismatch, spec.version, spec.path)
	}
	return contents, nil
}

func readMigrationLedger(ctx context.Context, tx *sql.Tx) ([]migrationLedgerRecord, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT version, migration_sha256
		FROM cph_aiinfra.schema_migration
		ORDER BY version
		FOR UPDATE`)
	if err != nil {
		return nil, fmt.Errorf("aiinfra postgres: lock migration ledger: %w", err)
	}
	return scanMigrationLedger(rows)
}

func readMigrationLedgerForVerification(ctx context.Context, tx *sql.Tx) ([]migrationLedgerRecord, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT version, migration_sha256
		FROM cph_aiinfra.schema_migration
		ORDER BY version`)
	if err != nil {
		return nil, fmt.Errorf("aiinfra postgres: inspect migration ledger: %w", err)
	}
	return scanMigrationLedger(rows)
}

func scanMigrationLedger(rows *sql.Rows) ([]migrationLedgerRecord, error) {
	defer func() { _ = rows.Close() }()

	var records []migrationLedgerRecord
	for rows.Next() {
		var record migrationLedgerRecord
		if err := rows.Scan(&record.version, &record.digest); err != nil {
			return nil, fmt.Errorf("aiinfra postgres: scan migration ledger: %w", err)
		}
		record.digest = bytes.Clone(record.digest)
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("aiinfra postgres: read migration ledger: %w", err)
	}
	return records, nil
}

func pendingMigrations(specs []migrationSpec, applied []migrationLedgerRecord) ([]migrationSpec, error) {
	if err := validateMigrationSpecs(specs, int64(len(specs))); err != nil {
		return nil, err
	}
	latest := int64(len(specs))
	for index, record := range applied {
		if record.version < 1 || record.version > latest {
			return nil, fmt.Errorf("%w: version %d (latest known version is %d)", ErrUnknownMigrationVersion, record.version, latest)
		}
		wantVersion := int64(index + 1)
		if record.version != wantVersion {
			return nil, fmt.Errorf("%w: found version %d where version %d was required", ErrMigrationLedgerGap, record.version, wantVersion)
		}
		if !bytes.Equal(record.digest, specs[index].digest[:]) {
			return nil, fmt.Errorf("%w: version %d", ErrMigrationDigestMismatch, record.version)
		}
	}
	return append([]migrationSpec(nil), specs[len(applied):]...), nil
}

func verifyCompleteMigrationLedger(specs []migrationSpec, applied []migrationLedgerRecord) error {
	pending, err := pendingMigrations(specs, applied)
	if err != nil {
		return err
	}
	if len(pending) != 0 {
		return fmt.Errorf("%w: ledger ends before version %d", ErrMigrationLedgerGap, pending[0].version)
	}
	return nil
}

func applyMigrations(ctx context.Context, tx *sql.Tx, migrations []preparedMigration) error {
	for _, migration := range migrations {
		for number, statement := range migration.statements {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("aiinfra postgres: apply migration %d statement %d: %w", migration.spec.version, number+1, err)
			}
		}
	}
	return nil
}

func recordMigrations(ctx context.Context, tx *sql.Tx, migrations []migrationSpec) error {
	for _, migration := range migrations {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO cph_aiinfra.schema_migration(version, migration_sha256) VALUES ($1, $2)",
			migration.version, migration.digest[:],
		); err != nil {
			return fmt.Errorf("aiinfra postgres: record migration %d: %w", migration.version, err)
		}
	}
	return nil
}

// VerifyReplayStore is a mandatory startup check performed using the runtime
// role, not the migration owner. It verifies both the catalog shape and the
// least-privilege capability boundary without changing durable state.
func VerifyReplayStore(ctx context.Context, db BeginTxer) error {
	if db == nil {
		return ErrDatabaseRequired
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: true})
	if err != nil {
		return fmt.Errorf("aiinfra postgres: begin runtime verification: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "SET LOCAL search_path = pg_catalog"); err != nil {
		return fmt.Errorf("aiinfra postgres: constrain verification search path: %w", err)
	}
	if err := assertSessionReplicationOrigin(ctx, tx); err != nil {
		return err
	}
	if err := verifyReplaySchema(ctx, tx); err != nil {
		return err
	}
	if err := verifyRuntimeRole(ctx, tx); err != nil {
		return err
	}
	if err := assertSessionReplicationOrigin(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("aiinfra postgres: commit runtime verification: %w", err)
	}
	return nil
}

// splitSQLStatements understands PostgreSQL quotes, nested block comments and
// dollar-quoted procedural bodies. It rejects malformed migration source and
// never treats a semicolon inside one of those regions as a boundary.
func splitSQLStatements(source string) ([]string, error) {
	var statements []string
	start := 0
	for index := 0; index < len(source); {
		switch {
		case source[index] == '\'':
			end, err := skipQuotedSQL(source, index, '\'')
			if err != nil {
				return nil, err
			}
			index = end
		case source[index] == '"':
			end, _, err := readQuotedIdentifier(source, index)
			if err != nil {
				return nil, err
			}
			index = end
		case source[index] == '-' && index+1 < len(source) && source[index+1] == '-':
			index += 2
			for index < len(source) && source[index] != '\n' {
				index++
			}
		case source[index] == '/' && index+1 < len(source) && source[index+1] == '*':
			end, err := skipNestedBlockComment(source, index)
			if err != nil {
				return nil, err
			}
			index = end
		case source[index] == '$':
			end, skipped, err := skipDollarQuotedSQL(source, index)
			if err != nil {
				return nil, err
			}
			if skipped {
				index = end
			} else {
				index++
			}
		case source[index] == ';':
			statement := strings.TrimSpace(source[start:index])
			if statement != "" {
				statements = append(statements, statement)
			}
			index++
			start = index
		default:
			index++
		}
	}
	if statement := strings.TrimSpace(source[start:]); statement != "" {
		statements = append(statements, statement)
	}
	if len(statements) == 0 {
		return nil, errors.New("migration contains no SQL statements")
	}
	return statements, nil
}
