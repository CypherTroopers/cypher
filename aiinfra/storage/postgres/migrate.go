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
	"strings"
)

const (
	replayMigrationVersion int64 = 1
	// ASCII "CPHAIIE0" interpreted as a positive signed 64-bit integer.
	migrationAdvisoryLock int64 = 0x4350484149494530
)

var (
	ErrDatabaseRequired        = errors.New("aiinfra postgres: database is required")
	ErrMigrationDigestMismatch = errors.New("aiinfra postgres: applied migration digest does not match source")
	ErrSchemaShapeMismatch     = errors.New("aiinfra postgres: database schema does not match the replay contract")
	ErrUnsafeRuntimeRole       = errors.New("aiinfra postgres: runtime database role violates least privilege")
	ErrUnsafeMigrationRole     = errors.New("aiinfra postgres: migration role does not own the schema contract")
)

//go:embed migrations/0000_bootstrap.sql migrations/0001_ccse_replay.sql
var migrationFiles embed.FS

// BeginTxer is implemented by sql.DB. Keeping this narrow lets every canonical
// service own and configure its pool while sharing the transaction contract.
type BeginTxer interface {
	BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
}

// ReplayMigrationDigest returns the exact SHA-256 recorded for migration 1.
// The raw migration is immutable after a production deployment; a change must
// be introduced as a new numbered migration.
func ReplayMigrationDigest() ([sha256.Size]byte, error) {
	contents, err := migrationFiles.ReadFile("migrations/0001_ccse_replay.sql")
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("aiinfra postgres: read replay migration: %w", err)
	}
	return sha256.Sum256(contents), nil
}

// MigrateReplayStore installs and verifies the replay inbox schema under one
// serializable transaction and a cluster-wide advisory lock. Operational DDL
// runs only if version 1 is absent; its CREATE statements intentionally fail on
// partial/look-alike objects. An already-applied version is never replayed.
func MigrateReplayStore(ctx context.Context, db BeginTxer) error {
	if db == nil {
		return ErrDatabaseRequired
	}
	contents, err := migrationFiles.ReadFile("migrations/0001_ccse_replay.sql")
	if err != nil {
		return fmt.Errorf("aiinfra postgres: read replay migration: %w", err)
	}
	digest := sha256.Sum256(contents)
	bootstrap, err := migrationFiles.ReadFile("migrations/0000_bootstrap.sql")
	if err != nil {
		return fmt.Errorf("aiinfra postgres: read migration bootstrap: %w", err)
	}
	bootstrapStatements, err := splitSQLStatements(string(bootstrap))
	if err != nil {
		return fmt.Errorf("aiinfra postgres: parse migration bootstrap: %w", err)
	}
	statements, err := splitSQLStatements(string(contents))
	if err != nil {
		return fmt.Errorf("aiinfra postgres: parse replay migration: %w", err)
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

	var applied []byte
	err = tx.QueryRowContext(ctx,
		"SELECT migration_sha256 FROM cph_aiinfra.schema_migration WHERE version=$1 FOR UPDATE",
		replayMigrationVersion,
	).Scan(&applied)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		for number, statement := range statements {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("aiinfra postgres: apply replay migration statement %d: %w", number+1, err)
			}
		}
		if err := verifyReplaySchemaShape(ctx, tx); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO cph_aiinfra.schema_migration(version, migration_sha256) VALUES ($1, $2)",
			replayMigrationVersion, digest[:],
		); err != nil {
			return fmt.Errorf("aiinfra postgres: record replay migration: %w", err)
		}
		if err := verifyReplaySchema(ctx, tx); err != nil {
			return err
		}
	case err != nil:
		return fmt.Errorf("aiinfra postgres: read replay migration record: %w", err)
	case !bytes.Equal(applied, digest[:]):
		return fmt.Errorf("%w: version %d", ErrMigrationDigestMismatch, replayMigrationVersion)
	default:
		if err := verifyReplaySchema(ctx, tx); err != nil {
			return err
		}
	}
	if err := assertSessionReplicationOrigin(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("aiinfra postgres: commit migration: %w", err)
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
