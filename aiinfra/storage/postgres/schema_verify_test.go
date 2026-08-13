// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestCatalogDefinitionComparisonIsExactAfterWhitespaceNormalization(t *testing.T) {
	want := "CHECK ((octet_length(scope_sha256) = 32))"
	if normalizeCatalogDefinition("\n CHECK   ((octet_length(scope_sha256) = 32)) \t") != want {
		t.Fatal("whitespace-only normalization changed the expected definition")
	}
	for _, drift := range []string{
		"CHECK ((octet_length(scope_sha256) = 32) OR TRUE)",
		"CHECK ((octet_length(scope_sha256) >= 32))",
		"CHECK ((octet_length(message_id) = 32))",
	} {
		if normalizeCatalogDefinition(drift) == normalizeCatalogDefinition(want) {
			t.Fatalf("semantic drift normalized to the sealed definition: %q", drift)
		}
	}
}

func TestClosedSchemaContractsHaveCompleteDefinitions(t *testing.T) {
	if len(replayRelationContract) != 62 {
		t.Fatalf("relation contract count = %d, want 62", len(replayRelationContract))
	}
	for table, constraints := range replayConstraintContract {
		if len(constraints) == 0 {
			t.Fatalf("table %s has no constraint contract", table)
		}
		for name, contract := range constraints {
			if contract.definition == "" || len(contract.keyColumns) == 0 {
				t.Fatalf("constraint %s.%s is incomplete", table, name)
			}
		}
	}
}

func TestCatalogListComparisonPreservesOrderAndIdentity(t *testing.T) {
	value := "scope_sha256" + string(rune(31)) + "message_id"
	parts := splitCatalogList(value)
	if len(parts) != 2 || parts[0] != "scope_sha256" || parts[1] != "message_id" {
		t.Fatalf("splitCatalogList(%q) = %#v", value, parts)
	}
	if splitCatalogList("") != nil {
		t.Fatal("empty catalog list must remain nil")
	}
}

func TestConstraintKeyColumnOrderIsSemanticOnlyForOrderedConstraints(t *testing.T) {
	actual := []string{"audit_event_id", "evidence_assertion_count", "uow_kind"}
	expected := []string{"uow_kind", "audit_event_id", "evidence_assertion_count"}
	if !constraintKeyColumnsEqual("c", actual, expected) ||
		!constraintKeyColumnsEqual("n", []string{"uow_kind"}, []string{"uow_kind"}) {
		t.Fatal("CHECK/NOT NULL column membership must ignore catalog traversal order")
	}
	for _, kind := range []string{"p", "u", "f"} {
		if constraintKeyColumnsEqual(kind, actual, expected) {
			t.Fatalf("ordered constraint kind %q accepted reordered keys", kind)
		}
	}
	if constraintKeyColumnsEqual("c", []string{"uow_kind", "audit_event_id"}, expected) {
		t.Fatal("CHECK column membership accepted a missing key")
	}
}

func TestConstraintContractsAreVersionedForPostgres18(t *testing.T) {
	for table, columns := range replayColumnContract {
		baseline := replayConstraintContract[table]
		postgres17 := constraintContractsForVersion(table, baseline, 170000)
		if len(postgres17) != len(baseline) {
			t.Fatalf("PostgreSQL 17 contract count for %s = %d, want %d", table, len(postgres17), len(baseline))
		}

		notNullColumns := 0
		postgres18 := constraintContractsForVersion(table, baseline, 180000)
		for _, column := range columns {
			name := table + "_" + column.name + "_not_null"
			contract, exists := postgres18[name]
			if !column.notNull {
				if exists {
					t.Fatalf("PostgreSQL 18 contract unexpectedly contains nullable column %s.%s", table, column.name)
				}
				continue
			}
			notNullColumns++
			if !exists {
				t.Fatalf("PostgreSQL 18 contract is missing NOT NULL constraint %s", name)
			}
			if contract.kind != "n" || len(contract.keyColumns) != 1 || contract.keyColumns[0] != column.name ||
				contract.definition != "NOT NULL "+column.name {
				t.Fatalf("PostgreSQL 18 NOT NULL contract %s = %+v", name, contract)
			}
		}
		if len(postgres18) != len(baseline)+notNullColumns {
			t.Fatalf("PostgreSQL 18 contract count for %s = %d, want %d", table, len(postgres18), len(baseline)+notNullColumns)
		}

		// The version adapter must never mutate or alias the frozen baseline.
		postgres18["synthetic"] = constraintContract{kind: "c"}
		if _, exists := baseline["synthetic"]; exists {
			t.Fatalf("version adapter mutated baseline map for %s", table)
		}
		for name, contract := range postgres18 {
			if len(contract.keyColumns) == 0 || len(baseline[name].keyColumns) == 0 {
				continue
			}
			contract.keyColumns[0] = "mutated"
			if baseline[name].keyColumns[0] == "mutated" {
				t.Fatalf("version adapter aliased baseline key columns for %s.%s", table, name)
			}
			break
		}
	}
}

func TestPostgres18V2ConstraintDefinitionDigestsAreClosed(t *testing.T) {
	if len(v2Postgres180004ConstraintDefinitionDigests) != len(v2ColumnContract) {
		t.Fatalf("PostgreSQL 18 v2 definition digest count = %d, want %d",
			len(v2Postgres180004ConstraintDefinitionDigests), len(v2ColumnContract))
	}
	if len(v2Postgres180004RestoredConstraintDefinitionDigests) != 1 {
		t.Fatalf("PostgreSQL 18 restored definition digest count = %d, want 1",
			len(v2Postgres180004RestoredConstraintDefinitionDigests))
	}
	if _, ok := v2Postgres180004RestoredConstraintDefinitionDigests["audit_head"]; !ok {
		t.Fatal("PostgreSQL 18 restored definition digest is not restricted to audit_head")
	}
	for table := range v2ColumnContract {
		values, ok := v2ConstraintDefinitionDigestsForVersion(table, 180004)
		if !ok {
			t.Fatalf("missing PostgreSQL 18 definition digest for %s", table)
		}
		wantCount := 1
		if table == "audit_head" {
			wantCount = 2
		}
		if len(values) != wantCount {
			t.Fatalf("PostgreSQL 18 definition digest count for %s = %d, want %d",
				table, len(values), wantCount)
		}
		seen := make(map[string]struct{}, len(values))
		for _, value := range values {
			decoded, err := hex.DecodeString(value)
			if err != nil || len(decoded) != 32 {
				t.Fatalf("invalid PostgreSQL 18 definition digest for %s: %q", table, value)
			}
			if _, duplicate := seen[value]; duplicate {
				t.Fatalf("duplicate PostgreSQL 18 definition digest for %s: %q", table, value)
			}
			seen[value] = struct{}{}
		}
		if _, ok := v2ConstraintDefinitionDigestsForVersion(table, 170000); ok {
			t.Fatalf("PostgreSQL 18 definition digest leaked to PostgreSQL 17 for %s", table)
		}
		if _, ok := v2ConstraintDefinitionDigestsForVersion(table, 180003); ok {
			t.Fatalf("PostgreSQL 18.4 definition digest leaked to PostgreSQL 18.3 for %s", table)
		}
		if _, ok := v2ConstraintDefinitionDigestsForVersion(table, 180005); ok {
			t.Fatalf("PostgreSQL 18.4 definition digest leaked to PostgreSQL 18.5 for %s", table)
		}
	}
}

func TestConstraintDefinitionHashPreservesQuotedWhitespace(t *testing.T) {
	digest := func(definition string) [sha256.Size]byte {
		hash := sha256.New()
		writeConstraintDefinitionHash(hash, "constraint", definition)
		var result [sha256.Size]byte
		copy(result[:], hash.Sum(nil))
		return result
	}
	if digest("CHECK ((value = 'a b'::text))") == digest("CHECK ((value = 'a  b'::text))") {
		t.Fatal("constraint definition hash collapsed quoted whitespace")
	}
}

func TestConstraintNoInheritIsBoundToConstraintKind(t *testing.T) {
	for _, kind := range []string{"p", "u", "f"} {
		if !constraintNoInherit(kind) {
			t.Fatalf("constraint kind %q must be non-inheritable", kind)
		}
	}
	for _, kind := range []string{"c", "n", "x", "t", ""} {
		if constraintNoInherit(kind) {
			t.Fatalf("constraint kind %q must not be treated as non-inheritable", kind)
		}
	}
}

func TestRuntimeACLContractIsClosed(t *testing.T) {
	expected := runtimeACLContract()
	if len(expected) != 75 {
		t.Fatalf("runtime ACL contract count = %d, want 75", len(expected))
	}
	for _, contract := range []aclGrantContract{
		{"schema", "cph_aiinfra", "USAGE"},
		{"table", "schema_migration", "SELECT"},
		{"table", "schema_migration", "UPDATE"},
		{"table", "ccse_replay_head", "UPDATE"},
		{"table", "authoritative_uow", "INSERT"},
		{"table", "business_idempotency_head", "UPDATE"},
		{"table", "business_idempotency_history", "INSERT"},
		{"table", "canonical_semantic_projection", "INSERT"},
		{"function", "assert_authoritative_uow", "EXECUTE"},
		{"function", "claim_outbox_delivery", "EXECUTE"},
		{"function", "acknowledge_outbox_delivery", "EXECUTE"},
		{"function", "reject_outbox_delivery", "EXECUTE"},
		{"function", "enforce_outbox_delivery_transition", "EXECUTE"},
		{"function", "stamp_unit_of_work_transaction", "EXECUTE"},
	} {
		if _, ok := expected[contract]; !ok {
			t.Fatalf("runtime ACL contract is missing %+v", contract)
		}
	}
	for _, forbidden := range []aclGrantContract{
		{"schema", "cph_aiinfra", "CREATE"},
		{"table", "ccse_replay_inbox", "UPDATE"},
		{"table", "ccse_outbox_delivery", "SELECT"},
		{"table", "ccse_outbox_delivery", "INSERT"},
		{"table", "ccse_outbox_delivery", "UPDATE"},
		{"table", "ccse_outbox_intent", "MAINTAIN"},
		{"table", "business_idempotency_history", "UPDATE"},
		{"table", "authoritative_uow", "UPDATE"},
		{"function", "reject_immutable_change", "ALTER"},
	} {
		if _, ok := expected[forbidden]; ok {
			t.Fatalf("runtime ACL contract unexpectedly permits %+v", forbidden)
		}
	}
}

func TestPostgresServerVersionCalibrationFailsClosed(t *testing.T) {
	if err := validatePostgresServerVersion(v2CalibratedServerVersion); err != nil {
		t.Fatalf("calibrated version %d rejected: %v", v2CalibratedServerVersion, err)
	}
	for _, version := range []int64{0, 120022, 130000, 150013, 170009, 180000, 180003, 180005, 189999, 190000, 200001} {
		if err := validatePostgresServerVersion(version); err == nil {
			t.Fatalf("version %d was accepted", version)
		}
	}
}
