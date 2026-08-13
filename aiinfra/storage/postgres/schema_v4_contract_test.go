// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestOutboxDeliveryMigrationContractIsPinnedAndClosed(t *testing.T) {
	specs, err := registeredMigrationSpecs()
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 4 || specs[3].path != "migrations/0004_outbox_delivery.sql" {
		t.Fatalf("migration registry=%+v", specs)
	}
	digest, err := OutboxDeliveryMigrationDigest()
	if err != nil {
		t.Fatal(err)
	}
	const want = "4c814ecad14885e8ed04726535f6fb8b2dbaf2b24e5ff0c370f92c25847cc482"
	if got := hex.EncodeToString(digest[:]); got != want {
		t.Fatalf("migration 4 digest=%s, want %s", got, want)
	}
	source, err := readPinnedMigration(migrationFiles, specs[3])
	if err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range [][]byte{
		[]byte("CREATE TABLE IF NOT EXISTS"), []byte("CREATE INDEX IF NOT EXISTS"),
		[]byte("CREATE FUNCTION IF NOT EXISTS"),
	} {
		if bytes.Contains(source, unsafe) {
			t.Fatalf("migration 4 contains unsafe DDL %q", unsafe)
		}
	}
	for _, required := range []string{
		"attempt_count = OLD.attempt_count + 1",
		"OLD.lease_until <= clock_timestamp()",
		"NEW.lease_until <= clock_timestamp() + interval '10 minutes'",
		"OLD.lease_owner_sha256 IS NOT NULL",
		"OLD.lease_token IS NOT NULL",
		"OLD.delivered_at IS NOT NULL",
		"outbox delivery insert must use initial state",
		"NEW.next_attempt_at <= clock_timestamp() + interval '24 hours'",
		"RAISE EXCEPTION 'invalid outbox delivery transition'",
		"CREATE FUNCTION cph_aiinfra.claim_outbox_delivery(",
		"CREATE FUNCTION cph_aiinfra.acknowledge_outbox_delivery(",
		"CREATE FUNCTION cph_aiinfra.reject_outbox_delivery(",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog",
		"p_lease_microseconds IS NULL",
		"p_initialize_limit IS NULL",
		"p_retry_microseconds IS NULL",
		"delivery.lease_owner_sha256 = p_worker_sha256",
		"delivery.lease_token = p_lease_token",
		"GET DIAGNOSTICS changed_rows = ROW_COUNT",
		"REVOKE ALL ON FUNCTION cph_aiinfra.claim_outbox_delivery(BYTEA, BYTEA, BIGINT, INTEGER) FROM PUBLIC",
		"REVOKE ALL ON FUNCTION cph_aiinfra.acknowledge_outbox_delivery(BYTEA, BYTEA, BYTEA) FROM PUBLIC",
		"REVOKE ALL ON FUNCTION cph_aiinfra.reject_outbox_delivery(BYTEA, BYTEA, BYTEA, BIGINT, BYTEA) FROM PUBLIC",
	} {
		if !strings.Contains(string(source), required) {
			t.Fatalf("migration 4 lacks transition invariant %q", required)
		}
	}
	for _, function := range []string{
		"claim_outbox_delivery", "acknowledge_outbox_delivery", "reject_outbox_delivery",
	} {
		shape := migrationFunctionShape(function)
		if !shape.known || !shape.securityDefiner || shape.argumentCount == 0 {
			t.Fatalf("outbox function shape is not closed for %s: %+v", function, shape)
		}
	}
	shapes := map[string]migrationFunctionShapeContract{
		"claim_outbox_delivery": {
			known: true, securityDefiner: true,
			arguments:  "p_worker_sha256 bytea, p_lease_token bytea, p_lease_microseconds bigint, p_initialize_limit integer",
			result:     "TABLE(claimed_event_id bytea, claimed_destination text, claimed_deduplication_key text, claimed_content_type text, claimed_payload bytea, claimed_payload_digest bytea, claimed_prior_attempt_count bigint)",
			returnsSet: true, argumentCount: 4, resultRows: 1000,
		},
		"acknowledge_outbox_delivery": {
			known: true, securityDefiner: true,
			arguments: "p_event_id bytea, p_worker_sha256 bytea, p_lease_token bytea",
			result:    "bigint", argumentCount: 3,
		},
		"reject_outbox_delivery": {
			known: true, securityDefiner: true,
			arguments: "p_event_id bytea, p_worker_sha256 bytea, p_lease_token bytea, p_retry_microseconds bigint, p_error_sha256 bytea",
			result:    "bigint", argumentCount: 5,
		},
	}
	for name, want := range shapes {
		if got := migrationFunctionShape(name); got != want {
			t.Fatalf("function shape %s=%+v, want %+v", name, got, want)
		}
	}
	if runtimeTableReadContract("ccse_outbox_delivery") {
		t.Fatal("runtime delivery-table SELECT exposes bearer lease tokens")
	}
	if insert, update := runtimeTableWriteContract("ccse_outbox_delivery"); insert || update {
		t.Fatalf("runtime delivery-table writes are exposed: insert=%t update=%t", insert, update)
	}
	if len(replayColumnContract["ccse_outbox_delivery"]) != 9 ||
		len(replayConstraintContract["ccse_outbox_delivery"]) != 9 {
		t.Fatal("outbox delivery table contract is incomplete")
	}
	for _, relation := range []string{
		"ccse_outbox_delivery", "ccse_outbox_delivery_pk", "ccse_outbox_delivery_ready_idx",
	} {
		if replayRelationContract[relation] == "" {
			t.Fatalf("missing relation contract %s", relation)
		}
	}
}

func TestSchemaVerifierRejectsUnexpectedPartialIndexPredicate(t *testing.T) {
	baseline := v2Index("test_table", "test_index", false, false, "",
		[]string{"event_id"}, []string{"pg_catalog.bytea_ops"}, []string{"-"})
	if baseline.predicate != "" {
		t.Fatal("ordinary index unexpectedly has a predicate")
	}
	lookup := v2IndexContract["canonical_semantic_projection_lookup_digest_idx"]
	if lookup.predicate != "(lookup_digest IS NOT NULL)" ||
		!strings.HasSuffix(lookup.definition, " WHERE (lookup_digest IS NOT NULL)") {
		t.Fatalf("semantic lookup partial index is not exactly sealed: %+v", lookup)
	}
}
