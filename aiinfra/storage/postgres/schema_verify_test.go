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
	if len(replayRelationContract) != 14 {
		t.Fatalf("relation contract count = %d, want 14", len(replayRelationContract))
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
