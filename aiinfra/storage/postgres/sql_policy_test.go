// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import (
	"errors"
	"strings"
	"testing"
)

func TestBusinessSQLPolicyAllowsOnlyReviewedSingleStatements(t *testing.T) {
	accepted := []struct {
		sql    string
		access StatementAccess
	}{
		{"INSERT INTO business.job(id) VALUES ($1)", StatementExec},
		{"UPDATE business.job SET state=$2 WHERE id=$1", StatementExec},
		{"WITH current AS (SELECT state FROM business.job WHERE id=$1) SELECT state FROM current", StatementQuery},
		{"SELECT '; COMMIT' FROM business.job", StatementQuery},
		{"SELECT $$; ROLLBACK$$ FROM business.job", StatementQuery},
	}
	for _, test := range accepted {
		if err := validateBusinessSQL(test.sql, test.access); err != nil {
			t.Errorf("validateBusinessSQL(%q) = %v", test.sql, err)
		}
	}

	rejected := []struct {
		sql    string
		access StatementAccess
	}{
		{"COMMIT", StatementExec},
		{"ROLLBACK", StatementExec},
		{"INSERT INTO business.job(id) VALUES ($1); COMMIT", StatementExec},
		{"CREATE TABLE business.job(id bigint)", StatementExec},
		{"SELECT * FROM cph_aiinfra.ccse_replay_inbox", StatementQuery},
		{`SELECT * FROM "cph_aiinfra".ccse_replay_inbox`, StatementQuery},
		{"SELECT pg_catalog.set_config('search_path','public',false)", StatementQuery},
		{"SELECT pg_advisory_xact_lock(1)", StatementQuery},
		{"SELECT nextval('business.job_id_seq')", StatementQuery},
		{"SELECT pg_notify('jobs', 'ready')", StatementQuery},
		{"SELECT dblink_connect('remote')", StatementQuery},
		{`SELECT "nextval"('business.job_id_seq')`, StatementQuery},
		{"SELECT id INTO business.job_copy FROM business.job", StatementQuery},
		{`SELECT * FROM U&"cph\005faiinfra".ccse_replay_inbox`, StatementQuery},
		{"UPDATE business.job SET state=$2 WHERE id=$1", StatementQuery},
		{"WITH changed AS (DELETE FROM business.job WHERE id=$1 RETURNING id) SELECT id FROM changed", StatementQuery},
		{"SELECT 1", StatementExec},
		{"SELECT 'unterminated", StatementQuery},
	}
	for _, test := range rejected {
		if err := validateBusinessSQL(test.sql, test.access); !errors.Is(err, ErrStatementNotAllowed) {
			t.Errorf("validateBusinessSQL(%q) error = %v", test.sql, err)
		}
	}
}

func TestMigrationParserPreservesProceduralBodies(t *testing.T) {
	contents, err := migrationFiles.ReadFile("migrations/0001_ccse_replay.sql")
	if err != nil {
		t.Fatal(err)
	}
	statements, err := splitSQLStatements(string(contents))
	if err != nil {
		t.Fatal(err)
	}
	if len(statements) != 25 {
		t.Fatalf("migration statement count = %d, want 25", len(statements))
	}
	var couplingFunction string
	for _, statement := range statements {
		if strings.Contains(statement, "CREATE FUNCTION cph_aiinfra.assert_completion_coupling") {
			couplingFunction = statement
			break
		}
	}
	if couplingFunction == "" || !strings.Contains(couplingFunction, "RAISE EXCEPTION") || !strings.Contains(couplingFunction, "RETURN NULL;") {
		t.Fatal("procedural function was split at an internal semicolon")
	}
	if strings.Contains(string(contents), "CREATE TABLE IF NOT EXISTS cph_aiinfra.ccse_") {
		t.Fatal("operational migration must fail on pre-existing look-alike tables")
	}
	for _, required := range []string{
		"counter_kind          SMALLINT NOT NULL",
		"transaction_id        XID8 NOT NULL",
		"transaction_inbox_count <> 1 OR matching_inbox_count <> 1",
		"CREATE TRIGGER ccse_replay_inbox_transaction",
		"CREATE CONSTRAINT TRIGGER ccse_replay_inbox_coupling",
	} {
		if !strings.Contains(string(contents), required) {
			t.Fatalf("migration lacks same-transaction replay-head coupling fragment %q", required)
		}
	}
}

func TestMigrationParserRejectsMalformedSource(t *testing.T) {
	for _, source := range []string{
		"SELECT 'unterminated;",
		"SELECT 1; /* unterminated",
		"DO $body$ BEGIN; END;",
	} {
		if _, err := splitSQLStatements(source); err == nil {
			t.Fatalf("splitSQLStatements(%q) succeeded", source)
		}
	}
}

func TestMigrationFunctionBodiesAreDerivedFromSealedSource(t *testing.T) {
	bodies, err := migrationFunctionBodies()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"assert_completion_coupling",
		"enforce_replay_head_monotonic",
		"reject_immutable_change",
		"stamp_unit_of_work_transaction",
	}
	if len(bodies) != len(want) {
		t.Fatalf("function body count = %d, want %d", len(bodies), len(want))
	}
	for _, name := range want {
		if strings.TrimSpace(bodies[name]) == "" {
			t.Fatalf("missing sealed body for %s", name)
		}
	}
}

func TestStatementAllowlistIsClosedByDefault(t *testing.T) {
	config := storeConfig{statements: make(map[string]StatementAccess)}
	input := []AllowedStatement{{
		SQL:    "UPDATE business.job SET state=$2 WHERE id=$1",
		Access: StatementExec,
	}}
	option := WithAllowedStatements(input...)
	input[0] = AllowedStatement{SQL: "COMMIT", Access: StatementExec}
	if err := option(&config); err != nil {
		t.Fatal(err)
	}
	if len(config.statements) != 1 {
		t.Fatalf("statement count = %d", len(config.statements))
	}
	frozen := cloneStatementPolicy(config.statements)
	delete(config.statements, "UPDATE business.job SET state=$2 WHERE id=$1")
	if frozen["UPDATE business.job SET state=$2 WHERE id=$1"] != StatementExec {
		t.Fatal("cloned statement policy changed with its source map")
	}
	bad := WithAllowedStatements(AllowedStatement{SQL: "COMMIT", Access: StatementExec})
	if err := bad(&config); !errors.Is(err, ErrStatementNotAllowed) {
		t.Fatalf("COMMIT allowlist error = %v", err)
	}
	combined := WithAllowedStatements(AllowedStatement{SQL: "SELECT 1", Access: StatementExec | StatementQuery})
	if err := combined(&config); !errors.Is(err, ErrStatementNotAllowed) {
		t.Fatalf("combined-access allowlist error = %v", err)
	}
}
