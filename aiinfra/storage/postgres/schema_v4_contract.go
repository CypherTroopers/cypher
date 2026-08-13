// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import (
	"fmt"
	"strings"
)

var outboxDeliveryColumnContract = []columnContract{
	{"event_id", "bytea", true, ""},
	{"attempt_count", "bigint", true, "0"},
	{"lease_owner_sha256", "bytea", false, ""},
	{"lease_token", "bytea", false, ""},
	{"lease_until", "timestamp with time zone", false, ""},
	{"next_attempt_at", "timestamp with time zone", true, "clock_timestamp()"},
	{"delivered_at", "timestamp with time zone", false, ""},
	{"last_error_digest", "bytea", false, ""},
	{"updated_at", "timestamp with time zone", true, "clock_timestamp()"},
}

var outboxDeliveryConstraintDefinitions = mustMigrationConstraintDefinitions(
	"migrations/0004_outbox_delivery.sql")

func outboxDeliveryConstraint(name, kind string, columns []string) constraintContract {
	definition, ok := outboxDeliveryConstraintDefinitions[name]
	if !ok {
		panic("aiinfra postgres: missing outbox delivery constraint " + name)
	}
	return constraintContract{kind: kind, keyColumns: columns, definition: definition}
}

func outboxDeliveryConstraints() map[string]constraintContract {
	primary := outboxDeliveryConstraint("ccse_outbox_delivery_pk", "p", []string{"event_id"})
	primary.indexName = "cph_aiinfra.ccse_outbox_delivery_pk"
	foreign := outboxDeliveryConstraint("ccse_outbox_delivery_intent_fk", "f", []string{"event_id"})
	foreign.referencedTable = "cph_aiinfra.ccse_outbox_intent"
	foreign.referencedColumns = []string{"event_id"}
	foreign.indexName = "cph_aiinfra.ccse_outbox_intent_pk"
	result := map[string]constraintContract{
		"ccse_outbox_delivery_pk":        primary,
		"ccse_outbox_delivery_intent_fk": foreign,
	}
	checks := map[string][]string{
		"ccse_outbox_delivery_event_length":        {"event_id"},
		"ccse_outbox_delivery_attempt_nonnegative": {"attempt_count"},
		"ccse_outbox_delivery_owner_length":        {"lease_owner_sha256"},
		"ccse_outbox_delivery_token_length":        {"lease_token"},
		"ccse_outbox_delivery_lease_shape":         {"lease_owner_sha256", "lease_token", "lease_until"},
		"ccse_outbox_delivery_delivered_unleased":  {"lease_owner_sha256", "lease_token", "lease_until", "delivered_at"},
		"ccse_outbox_delivery_error_length":        {"last_error_digest"},
	}
	for name, columns := range checks {
		contract := outboxDeliveryConstraint(name, "c", columns)
		contract.definition = outboxDeliveryPostgres180004ConstraintDefinitions[name]
		if contract.definition == "" {
			panic("aiinfra postgres: missing PostgreSQL 18.4 outbox delivery constraint " + name)
		}
		result[name] = contract
	}
	return result
}

var outboxDeliveryPostgres180004ConstraintDefinitions = map[string]string{
	"ccse_outbox_delivery_attempt_nonnegative": "CHECK ((attempt_count >= 0))",
	"ccse_outbox_delivery_delivered_unleased":  "CHECK (((delivered_at IS NULL) OR ((lease_owner_sha256 IS NULL) AND (lease_token IS NULL) AND (lease_until IS NULL))))",
	"ccse_outbox_delivery_error_length":        "CHECK (((last_error_digest IS NULL) OR (octet_length(last_error_digest) = 32)))",
	"ccse_outbox_delivery_event_length":        "CHECK ((octet_length(event_id) = 16))",
	"ccse_outbox_delivery_lease_shape":         "CHECK ((((lease_owner_sha256 IS NULL) AND (lease_token IS NULL) AND (lease_until IS NULL)) OR ((lease_owner_sha256 IS NOT NULL) AND (lease_token IS NOT NULL) AND (lease_until IS NOT NULL))))",
	"ccse_outbox_delivery_owner_length":        "CHECK (((lease_owner_sha256 IS NULL) OR (octet_length(lease_owner_sha256) = 32)))",
	"ccse_outbox_delivery_token_length":        "CHECK (((lease_token IS NULL) OR (octet_length(lease_token) = 16)))",
}

func outboxDeliveryTriggerDefinition() string {
	contents, err := migrationFiles.ReadFile("migrations/0004_outbox_delivery.sql")
	if err != nil {
		panic(fmt.Sprintf("aiinfra postgres: read outbox delivery trigger source: %v", err))
	}
	statements, err := splitSQLStatements(string(contents))
	if err != nil {
		panic(fmt.Sprintf("aiinfra postgres: parse outbox delivery trigger source: %v", err))
	}
	for _, statement := range statements {
		if at := strings.Index(statement, "CREATE TRIGGER ccse_outbox_delivery_transition"); at >= 0 {
			return strings.TrimSpace(statement[at:])
		}
	}
	panic("aiinfra postgres: missing outbox delivery transition trigger")
}

func init() {
	const table = "ccse_outbox_delivery"
	if _, exists := replayColumnContract[table]; exists {
		panic("aiinfra postgres: duplicate outbox delivery table contract")
	}
	replayColumnContract[table] = outboxDeliveryColumnContract
	replayConstraintContract[table] = outboxDeliveryConstraints()
	replayRelationContract[table] = "r"
	replayRelationContract["ccse_outbox_delivery_pk"] = "i"
	replayRelationContract["ccse_outbox_delivery_ready_idx"] = "i"
	v2TriggerContract[table+".ccse_outbox_delivery_transition"] = triggerContract{
		functionSchema: "cph_aiinfra", functionName: "enforce_outbox_delivery_transition",
		typeMask: 23, definition: outboxDeliveryTriggerDefinition(),
	}
	v2IndexContract["ccse_outbox_delivery_pk"] = v2Index(table,
		"ccse_outbox_delivery_pk", true, true, "ccse_outbox_delivery_pk",
		[]string{"event_id"}, []string{"pg_catalog.bytea_ops"}, []string{"-"})
	v2IndexContract["ccse_outbox_delivery_ready_idx"] = v2Index(table,
		"ccse_outbox_delivery_ready_idx", false, false, "",
		[]string{"delivered_at", "next_attempt_at", "lease_until", "event_id"},
		[]string{"pg_catalog.timestamptz_ops", "pg_catalog.timestamptz_ops", "pg_catalog.timestamptz_ops", "pg_catalog.bytea_ops"},
		[]string{"-", "-", "-", "-"})
}
