// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import (
	"fmt"
	"strings"
)

var semanticProjectionColumnContract = []columnContract{
	{"state_namespace", "smallint", true, ""},
	{"object_kind", "text", true, ""},
	{"object_id", "text", true, ""},
	{"version", "numeric(20,0)", true, ""},
	{"state_digest", "bytea", true, ""},
	{"projection_codec", "text", true, ""},
	{"projection_digest", "bytea", true, ""},
	{"canonical_projection", "bytea", true, ""},
	{"lookup_digest", "bytea", false, ""},
	{"audit_event_id", "text", true, ""},
	{"uow_scope_sha256", "bytea", true, ""},
	{"uow_message_id", "bytea", true, ""},
	{"transaction_id", "xid8", true, ""},
	{"recorded_at", "timestamp with time zone", true, "clock_timestamp()"},
}

var semanticProjectionConstraintDefinitions = mustMigrationConstraintDefinitions(
	"migrations/0003_semantic_projection_v2.sql")

func semanticProjectionConstraint(name, kind string, columns []string) constraintContract {
	definition, ok := semanticProjectionConstraintDefinitions[name]
	if !ok {
		panic("aiinfra postgres: missing semantic projection constraint " + name)
	}
	return constraintContract{kind: kind, keyColumns: columns, definition: definition}
}

func semanticProjectionForeign(name string, columns []string, table string,
	referenced []string, index string) constraintContract {
	value := semanticProjectionConstraint(name, "f", columns)
	if definition := semanticProjectionPostgres180004ForeignDefinitions[name]; definition != "" {
		value.definition = definition
	}
	value.deferrable, value.initiallyDeferred = true, true
	value.referencedTable, value.referencedColumns, value.indexName = table, referenced, index
	return value
}

var semanticProjectionPostgres180004ForeignDefinitions = map[string]string{
	"canonical_semantic_projection_state_fk": "FOREIGN KEY (state_namespace, object_kind, object_id, version) REFERENCES cph_aiinfra.canonical_state_history(state_namespace, object_kind, object_id, version) DEFERRABLE INITIALLY DEFERRED",
	"canonical_semantic_projection_uow_fk":   "FOREIGN KEY (uow_scope_sha256, uow_message_id) REFERENCES cph_aiinfra.authoritative_uow(scope_sha256, message_id) DEFERRABLE INITIALLY DEFERRED",
}

func semanticProjectionConstraints() map[string]constraintContract {
	result := map[string]constraintContract{
		"canonical_semantic_projection_pk": func() constraintContract {
			value := semanticProjectionConstraint("canonical_semantic_projection_pk", "p",
				[]string{"state_namespace", "object_kind", "object_id", "version"})
			value.indexName = "cph_aiinfra.canonical_semantic_projection_pk"
			return value
		}(),
		"canonical_semantic_projection_state_fk": semanticProjectionForeign(
			"canonical_semantic_projection_state_fk",
			[]string{"state_namespace", "object_kind", "object_id", "version"},
			"cph_aiinfra.canonical_state_history",
			[]string{"state_namespace", "object_kind", "object_id", "version"},
			"cph_aiinfra.canonical_state_history_pk"),
		"canonical_semantic_projection_uow_fk": semanticProjectionForeign(
			"canonical_semantic_projection_uow_fk", []string{"uow_scope_sha256", "uow_message_id"},
			"cph_aiinfra.authoritative_uow", []string{"scope_sha256", "message_id"},
			"cph_aiinfra.authoritative_uow_pk"),
	}
	checks := map[string][]string{
		"canonical_semantic_projection_namespace":           {"state_namespace"},
		"canonical_semantic_projection_kind_length":         {"object_kind"},
		"canonical_semantic_projection_id_length":           {"object_id"},
		"canonical_semantic_projection_version_range":       {"version"},
		"canonical_semantic_projection_state_digest_length": {"state_digest"},
		"canonical_semantic_projection_codec_length":        {"projection_codec"},
		"canonical_semantic_projection_digest_length":       {"projection_digest"},
		"canonical_semantic_projection_digest_match":        {"projection_digest", "canonical_projection"},
		"canonical_semantic_projection_content_length":      {"canonical_projection"},
		"canonical_semantic_projection_lookup_digest":       {"state_namespace", "object_kind", "lookup_digest"},
		"canonical_semantic_projection_kind_codec_catalog":  {"state_namespace", "object_kind", "projection_codec"},
		"canonical_semantic_projection_event_length":        {"audit_event_id"},
		"canonical_semantic_projection_uow_scope_length":    {"uow_scope_sha256"},
		"canonical_semantic_projection_uow_message_length":  {"uow_message_id"},
	}
	for name, columns := range checks {
		contract := semanticProjectionConstraint(name, "c", columns)
		contract.definition = semanticProjectionPostgres180004ConstraintDefinitions[name]
		if contract.definition == "" {
			panic("aiinfra postgres: missing PostgreSQL 18.4 semantic projection constraint " + name)
		}
		result[name] = contract
	}
	return result
}

var semanticProjectionPostgres180004ConstraintDefinitions = map[string]string{
	"canonical_semantic_projection_codec_length":        "CHECK (((octet_length(projection_codec) >= 1) AND (octet_length(projection_codec) <= 255)))",
	"canonical_semantic_projection_content_length":      "CHECK (((octet_length(canonical_projection) >= 1) AND (octet_length(canonical_projection) <= 67108864)))",
	"canonical_semantic_projection_digest_length":       "CHECK ((octet_length(projection_digest) = 32))",
	"canonical_semantic_projection_digest_match":        "CHECK ((projection_digest = sha256(canonical_projection)))",
	"canonical_semantic_projection_event_length":        "CHECK (((octet_length(audit_event_id) >= 1) AND (octet_length(audit_event_id) <= 1024)))",
	"canonical_semantic_projection_id_length":           "CHECK (((octet_length(object_id) >= 1) AND (octet_length(object_id) <= 1024)))",
	"canonical_semantic_projection_kind_codec_catalog":  "CHECK ((((state_namespace = 1) AND (object_kind = ANY (ARRAY['cph.aiinfra.iam.key-material.v1'::text, 'cph.aiinfra.iam.identity.v1'::text, 'cph.aiinfra.iam.key-lifecycle.v1'::text, 'cph.aiinfra.iam.accepted-ownership-transfer.v1'::text, 'cph.aiinfra.iam.subject-key-set.v1'::text, 'cph.aiinfra.iam.ownership-transfer-profile-activation.v1'::text])) AND (projection_codec = 'cph.aiinfra.iam.semantic-projection.v2'::text)) OR ((state_namespace = 2) AND (object_kind = 'cph.aiinfra.governance.policy-registry.v1'::text) AND (projection_codec = 'cph.aiinfra.governance.policy-registry-projection.v2'::text)) OR ((state_namespace = 2) AND (object_kind = 'cph.aiinfra.governance.profile-activation.v1'::text) AND (projection_codec = 'cph.aiinfra.governance.profile-activation-projection.v2'::text))))",
	"canonical_semantic_projection_kind_length":         "CHECK (((octet_length(object_kind) >= 1) AND (octet_length(object_kind) <= 255)))",
	"canonical_semantic_projection_lookup_digest":       "CHECK ((((state_namespace = 1) AND (object_kind = 'cph.aiinfra.iam.accepted-ownership-transfer.v1'::text) AND (lookup_digest IS NOT NULL) AND (octet_length(lookup_digest) = 32)) OR ((NOT ((state_namespace = 1) AND (object_kind = 'cph.aiinfra.iam.accepted-ownership-transfer.v1'::text))) AND (lookup_digest IS NULL))))",
	"canonical_semantic_projection_namespace":           "CHECK ((state_namespace = ANY (ARRAY[1, 2])))",
	"canonical_semantic_projection_state_digest_length": "CHECK ((octet_length(state_digest) = 32))",
	"canonical_semantic_projection_uow_message_length":  "CHECK ((octet_length(uow_message_id) = 16))",
	"canonical_semantic_projection_uow_scope_length":    "CHECK ((octet_length(uow_scope_sha256) = 32))",
	"canonical_semantic_projection_version_range":       "CHECK (((version >= (1)::numeric) AND (version <= '18446744073709551615'::numeric)))",
}

func mustMigrationConstraintDefinitions(path string) map[string]string {
	contents, err := migrationFiles.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("aiinfra postgres: read constraint source %s: %v", path, err))
	}
	lines := strings.Split(string(contents), "\n")
	definitions := make(map[string]string)
	for index := 0; index < len(lines); index++ {
		line := strings.TrimSpace(lines[index])
		if !strings.HasPrefix(line, "CONSTRAINT ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			panic("aiinfra postgres: malformed migration constraint")
		}
		name := fields[1]
		clause := strings.TrimSpace(strings.TrimPrefix(line, "CONSTRAINT "+name))
		depth := sqlParenthesisDelta(clause)
		for depth > 0 || (!strings.HasSuffix(strings.TrimSpace(clause), ",") &&
			index+1 < len(lines) && strings.TrimSpace(lines[index+1]) != ");") {
			index++
			if index >= len(lines) {
				panic("aiinfra postgres: unterminated migration constraint")
			}
			next := strings.TrimSpace(lines[index])
			clause += " " + next
			depth += sqlParenthesisDelta(next)
			if depth == 0 && strings.HasSuffix(next, ",") {
				break
			}
		}
		clause = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(clause), ","))
		if _, duplicate := definitions[name]; duplicate {
			panic("aiinfra postgres: duplicate migration constraint " + name)
		}
		definitions[name] = clause
	}
	return definitions
}

func semanticProjectionTriggerDefinitions() map[string]string {
	contents, err := migrationFiles.ReadFile("migrations/0003_semantic_projection_v2.sql")
	if err != nil {
		panic(fmt.Sprintf("aiinfra postgres: read semantic trigger source: %v", err))
	}
	statements, err := splitSQLStatements(string(contents))
	if err != nil {
		panic(fmt.Sprintf("aiinfra postgres: parse semantic trigger source: %v", err))
	}
	result := make(map[string]string)
	for _, statement := range statements {
		at, prefix := strings.Index(statement, "CREATE TRIGGER "), "CREATE TRIGGER "
		if constraintAt := strings.Index(statement, "CREATE CONSTRAINT TRIGGER "); constraintAt >= 0 && (at < 0 || constraintAt < at) {
			at, prefix = constraintAt, "CREATE CONSTRAINT TRIGGER "
		}
		if at < 0 {
			continue
		}
		definition := strings.TrimSpace(statement[at:])
		fields := strings.Fields(strings.TrimPrefix(definition, prefix))
		if len(fields) == 0 {
			panic("aiinfra postgres: malformed semantic trigger")
		}
		result[fields[0]] = definition
	}
	return result
}

func init() {
	const table = "canonical_semantic_projection"
	if _, exists := replayColumnContract[table]; exists {
		panic("aiinfra postgres: duplicate semantic projection table")
	}
	replayColumnContract[table] = semanticProjectionColumnContract
	replayConstraintContract[table] = semanticProjectionConstraints()
	replayRelationContract[table] = "r"
	replayRelationContract["canonical_semantic_projection_pk"] = "i"
	replayRelationContract["canonical_semantic_projection_codec_idx"] = "i"
	replayRelationContract["canonical_semantic_projection_lookup_digest_idx"] = "i"

	definitions := semanticProjectionTriggerDefinitions()
	addTrigger := func(table, name, function string, mask int64, constraint bool) {
		contract := triggerContract{functionSchema: "cph_aiinfra", functionName: function,
			typeMask: mask, definition: definitions[name]}
		if constraint {
			contract.deferrable, contract.initiallyDeferred, contract.constraintName = true, true, name
		}
		v2TriggerContract[table+"."+name] = contract
	}
	addTrigger(table, "canonical_semantic_projection_transaction", "stamp_unit_of_work_transaction", 7, false)
	addTrigger(table, "canonical_semantic_projection_immutable", "reject_immutable_change", 27, false)
	addTrigger(table, "canonical_semantic_projection_consistency", "assert_semantic_projection_consistency", 5, true)
	addTrigger("canonical_state_history", "canonical_state_history_semantic_projection", "assert_required_semantic_projection", 5, true)

	v2IndexContract["canonical_semantic_projection_pk"] = v2Index(table,
		"canonical_semantic_projection_pk", true, true, "canonical_semantic_projection_pk",
		[]string{"state_namespace", "object_kind", "object_id", "version"},
		[]string{"pg_catalog.int2_ops", "pg_catalog.text_ops", "pg_catalog.text_ops", "pg_catalog.numeric_ops"},
		[]string{"-", "pg_catalog.C", "pg_catalog.C", "-"})
	v2IndexContract["canonical_semantic_projection_codec_idx"] = v2Index(table,
		"canonical_semantic_projection_codec_idx", false, false, "",
		[]string{"projection_codec"}, []string{"pg_catalog.text_ops"}, []string{"pg_catalog.C"})
	lookupIndex := v2Index(table,
		"canonical_semantic_projection_lookup_digest_idx", true, false, "",
		[]string{"state_namespace", "object_kind", "lookup_digest"},
		[]string{"pg_catalog.int2_ops", "pg_catalog.text_ops", "pg_catalog.bytea_ops"},
		[]string{"-", "pg_catalog.C", "-"})
	lookupIndex.definition += " WHERE (lookup_digest IS NOT NULL)"
	lookupIndex.predicate = "(lookup_digest IS NOT NULL)"
	v2IndexContract["canonical_semantic_projection_lookup_digest_idx"] = lookupIndex
}
