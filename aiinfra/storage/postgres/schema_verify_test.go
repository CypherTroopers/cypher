// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import "testing"

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
	if len(replayRelationContract) != 55 {
		t.Fatalf("relation contract count = %d, want 55", len(replayRelationContract))
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
	if len(expected) != 66 {
		t.Fatalf("runtime ACL contract count = %d, want 66", len(expected))
	}
	for _, contract := range []aclGrantContract{
		{"schema", "cph_aiinfra", "USAGE"},
		{"table", "schema_migration", "SELECT"},
		{"table", "schema_migration", "UPDATE"},
		{"table", "ccse_replay_head", "UPDATE"},
		{"table", "authoritative_uow", "INSERT"},
		{"table", "business_idempotency_head", "UPDATE"},
		{"table", "business_idempotency_history", "INSERT"},
		{"function", "assert_authoritative_uow", "EXECUTE"},
		{"function", "stamp_unit_of_work_transaction", "EXECUTE"},
	} {
		if _, ok := expected[contract]; !ok {
			t.Fatalf("runtime ACL contract is missing %+v", contract)
		}
	}
	for _, forbidden := range []aclGrantContract{
		{"schema", "cph_aiinfra", "CREATE"},
		{"table", "ccse_replay_inbox", "UPDATE"},
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

func TestPostgresServerVersionRangeFailsClosed(t *testing.T) {
	for _, version := range []int64{130000, 150013, 170009, 180004, 189999} {
		if err := validatePostgresServerVersion(version); err != nil {
			t.Fatalf("version %d rejected: %v", version, err)
		}
	}
	for _, version := range []int64{0, 120022, 190000, 200001} {
		if err := validatePostgresServerVersion(version); err == nil {
			t.Fatalf("version %d was accepted", version)
		}
	}
}
