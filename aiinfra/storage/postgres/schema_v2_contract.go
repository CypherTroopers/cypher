// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import (
	"fmt"
	"strings"

	"github.com/cypherium/cypher/aiinfra/globalid"
)

const (
	v2CalibratedServerVersion = int64(180004)
	v2AuditEventMaxBytes      = 64 << 20
	v2DurableEnvelopeMaxBytes = 64 << 20
	v2EvidenceMaxBytes        = 64 << 20
	v2CanonicalStateMaxBytes  = 64 << 20
	v2MaxGlobalClaims         = globalid.MaxClaims
	v2MaxPendingEvidence      = 2048
	v2MaxUOWBusinessClaims    = 384
	v2MaxUOWPendingRevisions  = 384
	v2MaxUOWEvidenceRecords   = 2048
	v2MaxUOWCanonicalBytes    = MaxCanonicalUOWBytes
)

// These are storage enum catalogs, not open application integers.  Changing
// one requires a numbered migration and a compatibility review.
var (
	v2UOWKinds                 = [...]int16{1, 2}
	v2IdempotencyRowKinds      = [...]int16{1, 2, 3}
	v2IdempotencyStates        = [...]int16{1, 2}
	v2GlobalClaimModes         = [...]int16{1, 2, 3}
	v2PendingKinds             = [...]int16{1, 2, 3, 4, 5, 7}
	v2PendingStatuses          = [...]int16{1, 2}
	v2EvidenceKinds            = [...]int16{1, 2, 3, 4}
	v2StateNamespaces          = [...]int16{1, 2}
	v2BusinessOperationDomains = [...]string{
		"cph.aiinfra.iam.key-enrollment.v1",
		"cph.aiinfra.iam.identity.v1",
		"cph.aiinfra.iam.key-lifecycle.v1",
		"cph.aiinfra.iam.ownership-transfer.v1",
		"cph.aiinfra.iam.ownership-transfer-cutover.v1",
		"cph.aiinfra.governance.policy.v1",
		"cph.aiinfra.governance.audit.v1",
		"cph.aiinfra.joined-audit.v1",
	}
	v2GlobalOwnerDomains = [...]string{
		"cph.aiinfra.iam.identity.v1",
		"cph.aiinfra.iam.key.v1",
		"cph.aiinfra.canonical.record.v1",
		"cph.aiinfra.governance.policy-bundle.v1",
		"cph.aiinfra.governance.audit-event.v1",
	}
)

var v2ColumnContract = map[string][]columnContract{
	"authoritative_uow": {
		{"scope_sha256", "bytea", true, ""},
		{"message_id", "bytea", true, ""},
		{"uow_kind", "smallint", true, ""},
		{"outcome_digest", "bytea", true, ""},
		{"result_content_type", "text", true, ""},
		{"result_payload", "bytea", true, ""},
		{"evidence_assertion_count", "smallint", true, ""},
		{"audit_event_id", "text", false, ""},
		{"outer_payload_digest", "bytea", false, ""},
		{"transaction_id", "xid8", true, ""},
		{"committed_at", "timestamp with time zone", true, "clock_timestamp()"},
	},
	"audit_event": {
		{"event_id", "text", true, ""},
		{"stream_id", "text", true, ""},
		{"audit_sequence", "numeric(20,0)", true, ""},
		{"previous_event_digest", "bytea", false, ""},
		{"event_digest", "bytea", true, ""},
		{"record_digest", "bytea", true, ""},
		{"canonical_event", "bytea", true, ""},
		{"scope_sha256", "bytea", true, ""},
		{"message_id", "bytea", true, ""},
		{"occurred_at_unix_nano", "bigint", true, ""},
		{"transaction_id", "xid8", true, ""},
		{"committed_at", "timestamp with time zone", true, "clock_timestamp()"},
	},
	"audit_head": {
		{"stream_id", "text", true, ""},
		{"deployment_anchor_digest", "bytea", true, ""},
		{"highest_sequence", "numeric(20,0)", true, ""},
		{"latest_record_digest", "bytea", true, ""},
		{"audit_event_id", "text", true, ""},
		{"head_writer_identity", "text", true, ""},
		{"authorized_writer_identity", "text", true, ""},
		{"home_region", "text", true, ""},
		{"authorized_home_region", "text", true, ""},
		{"writer_epoch", "numeric(20,0)", true, ""},
		{"authorized_writer_epoch", "numeric(20,0)", true, ""},
		{"head_governance_profile_digest", "bytea", true, ""},
		{"authorized_governance_profile_digest", "bytea", true, ""},
		{"writer_lease_evidence_digest", "bytea", true, ""},
		{"writer_lease_not_before_unix_nano", "bigint", true, ""},
		{"writer_lease_not_after_unix_nano", "bigint", true, ""},
		{"uow_scope_sha256", "bytea", true, ""},
		{"uow_message_id", "bytea", true, ""},
		{"transaction_id", "xid8", true, ""},
		{"updated_at", "timestamp with time zone", true, "clock_timestamp()"},
	},
	"business_idempotency_head": {
		{"idempotency_key", "bytea", true, ""},
		{"row_kind", "smallint", true, ""},
		{"operation_domain", "text", true, ""},
		{"owner_id", "text", true, ""},
		{"request_digest", "bytea", true, ""},
		{"binding_digest", "bytea", true, ""},
		{"parent_key", "bytea", false, ""},
		{"parent_operation_domain", "text", false, ""},
		{"parent_owner_id", "text", false, ""},
		{"parent_request_digest", "bytea", false, ""},
		{"state", "smallint", true, ""},
		{"version", "numeric(20,0)", true, ""},
		{"progress_digest", "bytea", false, ""},
		{"outcome_digest", "bytea", false, ""},
		{"audit_event_id", "text", true, ""},
		{"uow_scope_sha256", "bytea", true, ""},
		{"uow_message_id", "bytea", true, ""},
		{"transaction_id", "xid8", true, ""},
		{"created_at", "timestamp with time zone", true, "clock_timestamp()"},
		{"updated_at", "timestamp with time zone", true, "clock_timestamp()"},
	},
	"business_idempotency_history": {
		{"idempotency_key", "bytea", true, ""},
		{"version", "numeric(20,0)", true, ""},
		{"row_kind", "smallint", true, ""},
		{"operation_domain", "text", true, ""},
		{"owner_id", "text", true, ""},
		{"request_digest", "bytea", true, ""},
		{"binding_digest", "bytea", true, ""},
		{"parent_key", "bytea", false, ""},
		{"parent_operation_domain", "text", false, ""},
		{"parent_owner_id", "text", false, ""},
		{"parent_request_digest", "bytea", false, ""},
		{"state", "smallint", true, ""},
		{"progress_digest", "bytea", false, ""},
		{"outcome_digest", "bytea", false, ""},
		{"audit_event_id", "text", true, ""},
		{"uow_scope_sha256", "bytea", true, ""},
		{"uow_message_id", "bytea", true, ""},
		{"transaction_id", "xid8", true, ""},
		{"recorded_at", "timestamp with time zone", true, "clock_timestamp()"},
	},
	"global_identifier_head": {
		{"identifier", "text", true, ""},
		{"owner_domain", "text", true, ""},
		{"owner_id", "text", true, ""},
		{"version", "numeric(20,0)", true, ""},
		{"transfer_evidence_digest", "bytea", false, ""},
		{"audit_event_id", "text", true, ""},
		{"uow_scope_sha256", "bytea", true, ""},
		{"uow_message_id", "bytea", true, ""},
		{"transaction_id", "xid8", true, ""},
		{"created_at", "timestamp with time zone", true, "clock_timestamp()"},
		{"updated_at", "timestamp with time zone", true, "clock_timestamp()"},
	},
	"global_identifier_history": {
		{"identifier", "text", true, ""},
		{"version", "numeric(20,0)", true, ""},
		{"owner_domain", "text", true, ""},
		{"owner_id", "text", true, ""},
		{"transfer_evidence_digest", "bytea", false, ""},
		{"audit_event_id", "text", true, ""},
		{"uow_scope_sha256", "bytea", true, ""},
		{"uow_message_id", "bytea", true, ""},
		{"transaction_id", "xid8", true, ""},
		{"recorded_at", "timestamp with time zone", true, "clock_timestamp()"},
	},
	"global_identifier_claim": {
		{"audit_event_id", "text", true, ""},
		{"claim_ordinal", "smallint", true, ""},
		{"identifier", "text", true, ""},
		{"claim_mode", "smallint", true, ""},
		{"expected_owner_domain", "text", false, ""},
		{"expected_owner_id", "text", false, ""},
		{"expected_version", "numeric(20,0)", false, ""},
		{"next_owner_domain", "text", true, ""},
		{"next_owner_id", "text", true, ""},
		{"next_version", "numeric(20,0)", true, ""},
		{"transfer_evidence_digest", "bytea", false, ""},
		{"uow_scope_sha256", "bytea", true, ""},
		{"uow_message_id", "bytea", true, ""},
		{"transaction_id", "xid8", true, ""},
		{"recorded_at", "timestamp with time zone", true, "clock_timestamp()"},
	},
	"durable_evidence": {
		{"evidence_digest", "bytea", true, ""},
		{"evidence_kind", "smallint", true, ""},
		{"content_type", "text", true, ""},
		{"canonical_content", "bytea", true, ""},
		{"audit_event_id", "text", true, ""},
		{"uow_scope_sha256", "bytea", true, ""},
		{"uow_message_id", "bytea", true, ""},
		{"transaction_id", "xid8", true, ""},
		{"created_at", "timestamp with time zone", true, "clock_timestamp()"},
	},
	"durable_pending_head": {
		{"pending_key", "bytea", true, ""},
		{"pending_kind", "smallint", true, ""},
		{"codec", "text", true, ""},
		{"codec_version", "bigint", true, ""},
		{"revision", "numeric(20,0)", true, ""},
		{"previous_envelope_digest", "bytea", false, ""},
		{"envelope_digest", "bytea", true, ""},
		{"canonical_envelope", "bytea", true, ""},
		{"evidence_count", "smallint", true, ""},
		{"status", "smallint", true, ""},
		{"commit_not_before_unix_nano", "bigint", true, ""},
		{"commit_not_after_unix_nano", "bigint", true, ""},
		{"terminal_outcome_digest", "bytea", false, ""},
		{"audit_event_id", "text", true, ""},
		{"uow_scope_sha256", "bytea", true, ""},
		{"uow_message_id", "bytea", true, ""},
		{"transaction_id", "xid8", true, ""},
		{"created_at", "timestamp with time zone", true, "clock_timestamp()"},
		{"updated_at", "timestamp with time zone", true, "clock_timestamp()"},
	},
	"durable_pending_revision": {
		{"pending_key", "bytea", true, ""},
		{"revision", "numeric(20,0)", true, ""},
		{"pending_kind", "smallint", true, ""},
		{"codec", "text", true, ""},
		{"codec_version", "bigint", true, ""},
		{"previous_envelope_digest", "bytea", false, ""},
		{"envelope_digest", "bytea", true, ""},
		{"canonical_envelope", "bytea", true, ""},
		{"evidence_count", "smallint", true, ""},
		{"status", "smallint", true, ""},
		{"commit_not_before_unix_nano", "bigint", true, ""},
		{"commit_not_after_unix_nano", "bigint", true, ""},
		{"terminal_outcome_digest", "bytea", false, ""},
		{"audit_event_id", "text", true, ""},
		{"uow_scope_sha256", "bytea", true, ""},
		{"uow_message_id", "bytea", true, ""},
		{"transaction_id", "xid8", true, ""},
		{"recorded_at", "timestamp with time zone", true, "clock_timestamp()"},
	},
	"durable_pending_evidence": {
		{"pending_key", "bytea", true, ""},
		{"revision", "numeric(20,0)", true, ""},
		{"evidence_ordinal", "smallint", true, ""},
		{"evidence_digest", "bytea", true, ""},
		{"audit_event_id", "text", true, ""},
		{"uow_scope_sha256", "bytea", true, ""},
		{"uow_message_id", "bytea", true, ""},
		{"transaction_id", "xid8", true, ""},
		{"recorded_at", "timestamp with time zone", true, "clock_timestamp()"},
	},
	"durable_evidence_assertion": {
		{"uow_scope_sha256", "bytea", true, ""},
		{"uow_message_id", "bytea", true, ""},
		{"evidence_ordinal", "smallint", true, ""},
		{"evidence_digest", "bytea", true, ""},
		{"pending_key", "bytea", false, ""},
		{"pending_revision", "numeric(20,0)", false, ""},
		{"audit_event_id", "text", true, ""},
		{"transaction_id", "xid8", true, ""},
		{"recorded_at", "timestamp with time zone", true, "clock_timestamp()"},
	},
	"canonical_state_head": {
		{"state_namespace", "smallint", true, ""},
		{"object_kind", "text", true, ""},
		{"object_id", "text", true, ""},
		{"version", "numeric(20,0)", true, ""},
		{"state_digest", "bytea", true, ""},
		{"content_type", "text", true, ""},
		{"canonical_state", "bytea", true, ""},
		{"terminal", "boolean", true, ""},
		{"valid_from_unix_nano", "bigint", false, ""},
		{"valid_until_unix_nano", "bigint", false, ""},
		{"audit_event_id", "text", true, ""},
		{"uow_scope_sha256", "bytea", true, ""},
		{"uow_message_id", "bytea", true, ""},
		{"transaction_id", "xid8", true, ""},
		{"created_at", "timestamp with time zone", true, "clock_timestamp()"},
		{"updated_at", "timestamp with time zone", true, "clock_timestamp()"},
	},
	"canonical_state_history": {
		{"state_namespace", "smallint", true, ""},
		{"object_kind", "text", true, ""},
		{"object_id", "text", true, ""},
		{"version", "numeric(20,0)", true, ""},
		{"state_digest", "bytea", true, ""},
		{"content_type", "text", true, ""},
		{"canonical_state", "bytea", true, ""},
		{"terminal", "boolean", true, ""},
		{"valid_from_unix_nano", "bigint", false, ""},
		{"valid_until_unix_nano", "bigint", false, ""},
		{"audit_event_id", "text", true, ""},
		{"uow_scope_sha256", "bytea", true, ""},
		{"uow_message_id", "bytea", true, ""},
		{"transaction_id", "xid8", true, ""},
		{"recorded_at", "timestamp with time zone", true, "clock_timestamp()"},
	},
}

var v2RelationContract = map[string]string{
	"authoritative_uow":                          "r",
	"authoritative_uow_pk":                       "i",
	"authoritative_uow_transaction_key":          "i",
	"audit_event":                                "r",
	"audit_event_pk":                             "i",
	"audit_event_stream_sequence_key":            "i",
	"audit_event_uow_key":                        "i",
	"audit_head":                                 "r",
	"audit_head_pk":                              "i",
	"business_idempotency_head":                  "r",
	"business_idempotency_head_pk":               "i",
	"business_idempotency_head_parent_idx":       "i",
	"business_idempotency_history":               "r",
	"business_idempotency_history_pk":            "i",
	"business_idempotency_history_event_idx":     "i",
	"global_identifier_head":                     "r",
	"global_identifier_head_pk":                  "i",
	"global_identifier_history":                  "r",
	"global_identifier_history_pk":               "i",
	"global_identifier_history_event_idx":        "i",
	"global_identifier_claim":                    "r",
	"global_identifier_claim_pk":                 "i",
	"global_identifier_claim_uow_identifier_key": "i",
	"durable_evidence":                           "r",
	"durable_evidence_pk":                        "i",
	"durable_pending_head":                       "r",
	"durable_pending_head_pk":                    "i",
	"durable_pending_revision":                   "r",
	"durable_pending_revision_pk":                "i",
	"durable_pending_revision_event_idx":         "i",
	"durable_pending_evidence":                   "r",
	"durable_pending_evidence_pk":                "i",
	"durable_pending_evidence_digest_key":        "i",
	"durable_evidence_assertion":                 "r",
	"durable_evidence_assertion_pk":              "i",
	"durable_evidence_assertion_digest_key":      "i",
	"canonical_state_head":                       "r",
	"canonical_state_head_pk":                    "i",
	"canonical_state_history":                    "r",
	"canonical_state_history_pk":                 "i",
	"canonical_state_history_event_idx":          "i",
}

// v2 constraint definitions are read as complete clauses from the pinned
// migration source.  Metadata (kind, keys, referenced relation/index and
// deferred flags) remains independently sealed below.  PostgreSQL deparser
// calibration is still a Gate-0 requirement; startup compares the entire
// normalized clause and never accepts substring matches.
var v2NamedConstraintDefinitions = mustV2NamedConstraintDefinitions()

// PostgreSQL's constraint deparser is not an identity transform of the
// migration source: it adds parentheses, rewrites IN to = ANY (ARRAY[...]),
// expands BETWEEN and annotates NUMERIC constants. These per-table digests
// seal the complete, name-ordered stream of length-prefixed constraint names
// and raw pg_get_constraintdef bytes from PostgreSQL 18.4. Metadata (kind,
// columns, FK target, deferrability and index) is still checked per constraint.
var v2Postgres180004ConstraintDefinitionDigests = map[string]string{
	"audit_event":                  "d2baf431e7bb2ec75fd0f00dd29f54d9e51b85282c63c5f1207fed00b33bade2",
	"audit_head":                   "893b2754c4756c95b29387c25e34e2ef37c6e51a98ef9ccb25ebd2e724eb97fb",
	"authoritative_uow":            "410d20dca07eafb4a653e4bc36a687f67573b0b18ca44872e4d501b2922c17cb",
	"business_idempotency_head":    "ae2c8cdac8cd32f94a65547921ae37733ad58bccfab7d0f94fb71a471d65ca0b",
	"business_idempotency_history": "bd13189508c27c5da5ae105f9d79f1b8ea8e397eb3547918419cfaf681c167cb",
	"canonical_state_head":         "40af9b34f361797ce93a7f15dec38c23cbdadad1fc5a2e5ff4cc720fa98d8ff3",
	"canonical_state_history":      "397858fe35771f1473ecd4c9a49e21f0437cc1bbd09efdce2ae785082857d7d1",
	"durable_evidence":             "6d26d1d53f14c2e4755a20540f29af7627cab09b01f2ca4c7b1c69a7f4745966",
	"durable_evidence_assertion":   "87afbc419f5a70ea8ae97b9599fb8d02f27c272e02deefc15154f004730ec10a",
	"durable_pending_evidence":     "c0a6b4e62237d4935fa575fa1f0782413225c9445b5cadbb36b71192beca5059",
	"durable_pending_head":         "d80bffce6398b7d1a5f2202223061a9d257c2faa03855dfc4ed6f24db3ae20b0",
	"durable_pending_revision":     "070d34115049f4e32a56685f1ca7d728d088846c8ae2cad56b62b72711fd4386",
	"global_identifier_claim":      "96d0799ea65a703d267d3717c8eb1a511c93ddafc5dd0a4cd225c402aeb1d515",
	"global_identifier_head":       "e84e0889beb105b678fb5b6d5542cabbcc409cb7c6dc9b2487e485ce8512c32e",
	"global_identifier_history":    "16bff2693e0625eb4d7e76106e1cb6fc9dd5a008525f3b4586eadc3cfc876edd",
}

// pg_dump 18.4 reconstructs audit_head's three compound AND checks without
// the outer grouping around their first pair of predicates. PostgreSQL parses
// both forms into the same Boolean expression, but pg_get_constraintdef emits
// different byte strings for a directly migrated database and its first
// pg_dump/pg_restore image. Seal that one reviewed round-trip form explicitly;
// every other v2 table remains a single-digest contract. A restored database
// is a fixed point: subsequent dump/restore cycles retain this digest.
var v2Postgres180004RestoredConstraintDefinitionDigests = map[string]string{
	"audit_head": "5f4ea54c818cbd163d83303d92e9c58c31b6626f6abd2f76ab0db56f8defdf86",
}

func mustV2NamedConstraintDefinitions() map[string]string {
	contents, err := migrationFiles.ReadFile("migrations/0002_canonical_uow.sql")
	if err != nil {
		panic(fmt.Sprintf("aiinfra postgres: read v2 constraint source: %v", err))
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
			panic("aiinfra postgres: malformed v2 constraint source")
		}
		name := fields[1]
		clause := strings.TrimSpace(strings.TrimPrefix(line, "CONSTRAINT "+name))
		depth := sqlParenthesisDelta(clause)
		for depth > 0 || (!strings.HasSuffix(strings.TrimSpace(clause), ",") && index+1 < len(lines) && strings.TrimSpace(lines[index+1]) != ");") {
			index++
			if index >= len(lines) {
				panic("aiinfra postgres: unterminated v2 constraint source")
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
			panic("aiinfra postgres: duplicate v2 constraint name " + name)
		}
		definitions[name] = clause
	}
	return definitions
}

func sqlParenthesisDelta(value string) int {
	depth := 0
	inString := false
	for index := 0; index < len(value); index++ {
		switch value[index] {
		case '\'':
			if inString && index+1 < len(value) && value[index+1] == '\'' {
				index++
				continue
			}
			inString = !inString
		case '(':
			if !inString {
				depth++
			}
		case ')':
			if !inString {
				depth--
			}
		}
	}
	return depth
}

func v2Constraint(name, kind string, columns []string) constraintContract {
	definition, ok := v2NamedConstraintDefinitions[name]
	if !ok {
		panic("aiinfra postgres: missing v2 constraint definition " + name)
	}
	return constraintContract{kind: kind, keyColumns: columns, definition: definition}
}

func v2ConstraintDefinitionDigestsForVersion(table string, serverVersion int64) ([]string, bool) {
	if serverVersion != v2CalibratedServerVersion {
		return nil, false
	}
	digest, ok := v2Postgres180004ConstraintDefinitionDigests[table]
	if !ok {
		return nil, false
	}
	digests := []string{digest}
	if restored, exists := v2Postgres180004RestoredConstraintDefinitionDigests[table]; exists {
		digests = append(digests, restored)
	}
	return digests, true
}

func v2Primary(name string, columns ...string) constraintContract {
	contract := v2Constraint(name, "p", columns)
	contract.indexName = "cph_aiinfra." + name
	return contract
}

func v2Unique(name string, columns ...string) constraintContract {
	contract := v2Constraint(name, "u", columns)
	contract.indexName = "cph_aiinfra." + name
	return contract
}

func v2Check(name string, columns ...string) constraintContract {
	return v2Constraint(name, "c", columns)
}

func v2Foreign(name string, columns []string, table string, referenced []string, index string) constraintContract {
	contract := v2Constraint(name, "f", columns)
	contract.deferrable = true
	contract.initiallyDeferred = true
	contract.referencedTable = "cph_aiinfra." + table
	contract.referencedColumns = referenced
	contract.indexName = "cph_aiinfra." + index
	return contract
}

var v2ConstraintContract = buildV2ConstraintContract()

func buildV2ConstraintContract() map[string]map[string]constraintContract {
	result := make(map[string]map[string]constraintContract, len(v2ColumnContract))
	add := func(table, name string, contract constraintContract) {
		if result[table] == nil {
			result[table] = make(map[string]constraintContract)
		}
		result[table][name] = contract
	}
	checks := func(table string, values map[string][]string) {
		for name, columns := range values {
			add(table, name, v2Check(name, columns...))
		}
	}

	add("authoritative_uow", "authoritative_uow_pk", v2Primary("authoritative_uow_pk", "scope_sha256", "message_id"))
	add("authoritative_uow", "authoritative_uow_transaction_key", v2Unique("authoritative_uow_transaction_key", "transaction_id"))
	add("authoritative_uow", "authoritative_uow_result_fk", v2Foreign("authoritative_uow_result_fk", []string{"scope_sha256", "message_id", "outcome_digest"}, "ccse_durable_result", []string{"scope_sha256", "message_id", "result_digest"}, "ccse_durable_result_digest_key"))
	checks("authoritative_uow", map[string][]string{
		"authoritative_uow_scope_length": {"scope_sha256"}, "authoritative_uow_message_length": {"message_id"},
		"authoritative_uow_kind": {"uow_kind"}, "authoritative_uow_outcome_length": {"outcome_digest"},
		"authoritative_uow_content_type_length": {"result_content_type"}, "authoritative_uow_payload_length": {"result_payload"},
		"authoritative_uow_evidence_count":       {"evidence_assertion_count"},
		"authoritative_uow_event_length":         {"audit_event_id"},
		"authoritative_uow_outer_payload_length": {"outer_payload_digest"},
		"authoritative_uow_kind_shape": {"uow_kind", "evidence_assertion_count",
			"audit_event_id", "outer_payload_digest"},
	})

	add("audit_event", "audit_event_pk", v2Primary("audit_event_pk", "event_id"))
	add("audit_event", "audit_event_stream_sequence_key", v2Unique("audit_event_stream_sequence_key", "stream_id", "audit_sequence"))
	add("audit_event", "audit_event_uow_key", v2Unique("audit_event_uow_key", "scope_sha256", "message_id"))
	add("audit_event", "audit_event_uow_fk", v2Foreign("audit_event_uow_fk", []string{"scope_sha256", "message_id"}, "authoritative_uow", []string{"scope_sha256", "message_id"}, "authoritative_uow_pk"))
	checks("audit_event", map[string][]string{
		"audit_event_id_length": {"event_id"}, "audit_event_stream_length": {"stream_id"},
		"audit_event_sequence_range": {"audit_sequence"}, "audit_event_previous_length": {"previous_event_digest"},
		"audit_event_digest_length": {"event_digest"}, "audit_event_record_length": {"record_digest"},
		"audit_event_canonical_length": {"canonical_event"}, "audit_event_scope_length": {"scope_sha256"},
		"audit_event_message_length": {"message_id"}, "audit_event_occurred_positive": {"occurred_at_unix_nano"},
	})

	add("audit_head", "audit_head_pk", v2Primary("audit_head_pk", "stream_id"))
	add("audit_head", "audit_head_event_fk", v2Foreign("audit_head_event_fk", []string{"audit_event_id"}, "audit_event", []string{"event_id"}, "audit_event_pk"))
	add("audit_head", "audit_head_uow_fk", v2Foreign("audit_head_uow_fk", []string{"uow_scope_sha256", "uow_message_id"}, "authoritative_uow", []string{"scope_sha256", "message_id"}, "authoritative_uow_pk"))
	checks("audit_head", map[string][]string{
		"audit_head_stream_length": {"stream_id"}, "audit_head_anchor_length": {"deployment_anchor_digest"},
		"audit_head_sequence_range": {"highest_sequence"},
		"audit_head_digest_length":  {"latest_record_digest"}, "audit_head_event_length": {"audit_event_id"},
		"audit_head_writer_length":       {"head_writer_identity", "authorized_writer_identity"},
		"audit_head_region_length":       {"home_region", "authorized_home_region"},
		"audit_head_epoch_range":         {"writer_epoch", "authorized_writer_epoch"},
		"audit_head_profile_length":      {"head_governance_profile_digest", "authorized_governance_profile_digest"},
		"audit_head_lease_digest_length": {"writer_lease_evidence_digest"},
		"audit_head_lease_window":        {"writer_lease_not_before_unix_nano", "writer_lease_not_after_unix_nano"},
		"audit_head_authorized_shape":    {"head_writer_identity", "authorized_writer_identity", "home_region", "authorized_home_region", "writer_epoch", "authorized_writer_epoch", "head_governance_profile_digest", "authorized_governance_profile_digest"},
		"audit_head_uow_scope_length":    {"uow_scope_sha256"}, "audit_head_uow_message_length": {"uow_message_id"},
	})

	add("business_idempotency_head", "business_idempotency_head_pk", v2Primary("business_idempotency_head_pk", "idempotency_key"))
	add("business_idempotency_head", "business_idempotency_head_parent_fk", v2Foreign("business_idempotency_head_parent_fk", []string{"parent_key"}, "business_idempotency_head", []string{"idempotency_key"}, "business_idempotency_head_pk"))
	add("business_idempotency_head", "business_idempotency_head_uow_fk", v2Foreign("business_idempotency_head_uow_fk", []string{"uow_scope_sha256", "uow_message_id"}, "authoritative_uow", []string{"scope_sha256", "message_id"}, "authoritative_uow_pk"))
	checks("business_idempotency_head", businessIdempotencyChecks("head"))

	add("business_idempotency_history", "business_idempotency_history_pk", v2Primary("business_idempotency_history_pk", "idempotency_key", "version"))
	add("business_idempotency_history", "business_idempotency_history_head_fk", v2Foreign("business_idempotency_history_head_fk", []string{"idempotency_key"}, "business_idempotency_head", []string{"idempotency_key"}, "business_idempotency_head_pk"))
	add("business_idempotency_history", "business_idempotency_history_uow_fk", v2Foreign("business_idempotency_history_uow_fk", []string{"uow_scope_sha256", "uow_message_id"}, "authoritative_uow", []string{"scope_sha256", "message_id"}, "authoritative_uow_pk"))
	checks("business_idempotency_history", businessIdempotencyChecks("history"))

	add("global_identifier_head", "global_identifier_head_pk", v2Primary("global_identifier_head_pk", "identifier"))
	add("global_identifier_head", "global_identifier_head_uow_fk", v2Foreign("global_identifier_head_uow_fk", []string{"uow_scope_sha256", "uow_message_id"}, "authoritative_uow", []string{"scope_sha256", "message_id"}, "authoritative_uow_pk"))
	checks("global_identifier_head", map[string][]string{
		"global_identifier_head_identifier_length": {"identifier"}, "global_identifier_head_owner_domain_length": {"owner_domain"},
		"global_identifier_head_owner_domain_catalog": {"owner_domain"},
		"global_identifier_head_owner_length":         {"owner_id"}, "global_identifier_head_version_range": {"version"},
		"global_identifier_head_evidence_length": {"transfer_evidence_digest"}, "global_identifier_head_event_length": {"audit_event_id"},
		"global_identifier_head_uow_scope_length": {"uow_scope_sha256"}, "global_identifier_head_uow_message_length": {"uow_message_id"},
	})

	add("global_identifier_history", "global_identifier_history_pk", v2Primary("global_identifier_history_pk", "identifier", "version"))
	add("global_identifier_history", "global_identifier_history_head_fk", v2Foreign("global_identifier_history_head_fk", []string{"identifier"}, "global_identifier_head", []string{"identifier"}, "global_identifier_head_pk"))
	add("global_identifier_history", "global_identifier_history_uow_fk", v2Foreign("global_identifier_history_uow_fk", []string{"uow_scope_sha256", "uow_message_id"}, "authoritative_uow", []string{"scope_sha256", "message_id"}, "authoritative_uow_pk"))
	checks("global_identifier_history", map[string][]string{
		"global_identifier_history_identifier_length": {"identifier"}, "global_identifier_history_version_range": {"version"},
		"global_identifier_history_owner_domain_length": {"owner_domain"}, "global_identifier_history_owner_length": {"owner_id"},
		"global_identifier_history_owner_domain_catalog": {"owner_domain"},
		"global_identifier_history_evidence_length":      {"transfer_evidence_digest"}, "global_identifier_history_event_length": {"audit_event_id"},
		"global_identifier_history_uow_scope_length": {"uow_scope_sha256"}, "global_identifier_history_uow_message_length": {"uow_message_id"},
	})

	add("global_identifier_claim", "global_identifier_claim_pk", v2Primary("global_identifier_claim_pk", "uow_scope_sha256", "uow_message_id", "claim_ordinal"))
	add("global_identifier_claim", "global_identifier_claim_uow_identifier_key", v2Unique("global_identifier_claim_uow_identifier_key", "uow_scope_sha256", "uow_message_id", "identifier"))
	add("global_identifier_claim", "global_identifier_claim_identifier_fk", v2Foreign("global_identifier_claim_identifier_fk", []string{"identifier"}, "global_identifier_head", []string{"identifier"}, "global_identifier_head_pk"))
	add("global_identifier_claim", "global_identifier_claim_uow_fk", v2Foreign("global_identifier_claim_uow_fk", []string{"uow_scope_sha256", "uow_message_id"}, "authoritative_uow", []string{"scope_sha256", "message_id"}, "authoritative_uow_pk"))
	checks("global_identifier_claim", map[string][]string{
		"global_identifier_claim_event_length": {"audit_event_id"}, "global_identifier_claim_ordinal_range": {"claim_ordinal"},
		"global_identifier_claim_identifier_length": {"identifier"}, "global_identifier_claim_mode": {"claim_mode"},
		"global_identifier_claim_expected_domain_length": {"expected_owner_domain"}, "global_identifier_claim_expected_owner_length": {"expected_owner_id"},
		"global_identifier_claim_expected_version_range": {"expected_version"},
		"global_identifier_claim_next_domain_length":     {"next_owner_domain"}, "global_identifier_claim_next_owner_length": {"next_owner_id"},
		"global_identifier_claim_owner_domain_catalog": {"expected_owner_domain", "next_owner_domain"},
		"global_identifier_claim_next_version_range":   {"next_version"}, "global_identifier_claim_evidence_length": {"transfer_evidence_digest"},
		"global_identifier_claim_uow_scope_length": {"uow_scope_sha256"}, "global_identifier_claim_uow_message_length": {"uow_message_id"},
		"global_identifier_claim_shape": {"claim_mode", "expected_owner_domain", "expected_owner_id", "expected_version", "next_owner_domain", "next_owner_id", "next_version", "transfer_evidence_digest"},
	})

	add("durable_evidence", "durable_evidence_pk", v2Primary("durable_evidence_pk", "evidence_digest"))
	add("durable_evidence", "durable_evidence_uow_fk", v2Foreign("durable_evidence_uow_fk", []string{"uow_scope_sha256", "uow_message_id"}, "authoritative_uow", []string{"scope_sha256", "message_id"}, "authoritative_uow_pk"))
	checks("durable_evidence", map[string][]string{
		"durable_evidence_digest_length": {"evidence_digest"}, "durable_evidence_kind": {"evidence_kind"},
		"durable_evidence_content_type_length": {"content_type"}, "durable_evidence_content_length": {"canonical_content"},
		"durable_evidence_event_length": {"audit_event_id"}, "durable_evidence_uow_scope_length": {"uow_scope_sha256"},
		"durable_evidence_uow_message_length": {"uow_message_id"},
	})

	add("durable_pending_head", "durable_pending_head_pk", v2Primary("durable_pending_head_pk", "pending_key"))
	add("durable_pending_head", "durable_pending_head_idempotency_fk", v2Foreign("durable_pending_head_idempotency_fk", []string{"pending_key"}, "business_idempotency_head", []string{"idempotency_key"}, "business_idempotency_head_pk"))
	add("durable_pending_head", "durable_pending_head_uow_fk", v2Foreign("durable_pending_head_uow_fk", []string{"uow_scope_sha256", "uow_message_id"}, "authoritative_uow", []string{"scope_sha256", "message_id"}, "authoritative_uow_pk"))
	checks("durable_pending_head", pendingChecks("head"))

	add("durable_pending_revision", "durable_pending_revision_pk", v2Primary("durable_pending_revision_pk", "pending_key", "revision"))
	add("durable_pending_revision", "durable_pending_revision_head_fk", v2Foreign("durable_pending_revision_head_fk", []string{"pending_key"}, "durable_pending_head", []string{"pending_key"}, "durable_pending_head_pk"))
	add("durable_pending_revision", "durable_pending_revision_uow_fk", v2Foreign("durable_pending_revision_uow_fk", []string{"uow_scope_sha256", "uow_message_id"}, "authoritative_uow", []string{"scope_sha256", "message_id"}, "authoritative_uow_pk"))
	checks("durable_pending_revision", pendingChecks("revision"))

	add("durable_pending_evidence", "durable_pending_evidence_pk", v2Primary("durable_pending_evidence_pk", "pending_key", "revision", "evidence_ordinal"))
	add("durable_pending_evidence", "durable_pending_evidence_digest_key", v2Unique("durable_pending_evidence_digest_key", "pending_key", "revision", "evidence_digest"))
	add("durable_pending_evidence", "durable_pending_evidence_revision_fk", v2Foreign("durable_pending_evidence_revision_fk", []string{"pending_key", "revision"}, "durable_pending_revision", []string{"pending_key", "revision"}, "durable_pending_revision_pk"))
	add("durable_pending_evidence", "durable_pending_evidence_content_fk", v2Foreign("durable_pending_evidence_content_fk", []string{"evidence_digest"}, "durable_evidence", []string{"evidence_digest"}, "durable_evidence_pk"))
	add("durable_pending_evidence", "durable_pending_evidence_uow_fk", v2Foreign("durable_pending_evidence_uow_fk", []string{"uow_scope_sha256", "uow_message_id"}, "authoritative_uow", []string{"scope_sha256", "message_id"}, "authoritative_uow_pk"))
	checks("durable_pending_evidence", map[string][]string{
		"durable_pending_evidence_key_length": {"pending_key"}, "durable_pending_evidence_revision_range": {"revision"},
		"durable_pending_evidence_ordinal_range": {"evidence_ordinal"}, "durable_pending_evidence_digest_length": {"evidence_digest"},
		"durable_pending_evidence_event_length": {"audit_event_id"}, "durable_pending_evidence_uow_scope_length": {"uow_scope_sha256"},
		"durable_pending_evidence_uow_message_length": {"uow_message_id"},
	})

	add("durable_evidence_assertion", "durable_evidence_assertion_pk", v2Primary("durable_evidence_assertion_pk", "uow_scope_sha256", "uow_message_id", "evidence_ordinal"))
	add("durable_evidence_assertion", "durable_evidence_assertion_digest_key", v2Unique("durable_evidence_assertion_digest_key", "uow_scope_sha256", "uow_message_id", "evidence_digest"))
	add("durable_evidence_assertion", "durable_evidence_assertion_uow_fk", v2Foreign("durable_evidence_assertion_uow_fk", []string{"uow_scope_sha256", "uow_message_id"}, "authoritative_uow", []string{"scope_sha256", "message_id"}, "authoritative_uow_pk"))
	add("durable_evidence_assertion", "durable_evidence_assertion_content_fk", v2Foreign("durable_evidence_assertion_content_fk", []string{"evidence_digest"}, "durable_evidence", []string{"evidence_digest"}, "durable_evidence_pk"))
	add("durable_evidence_assertion", "durable_evidence_assertion_pending_fk", v2Foreign("durable_evidence_assertion_pending_fk", []string{"pending_key", "pending_revision"}, "durable_pending_revision", []string{"pending_key", "revision"}, "durable_pending_revision_pk"))
	checks("durable_evidence_assertion", map[string][]string{
		"durable_evidence_assertion_scope_length": {"uow_scope_sha256"}, "durable_evidence_assertion_message_length": {"uow_message_id"},
		"durable_evidence_assertion_ordinal_range": {"evidence_ordinal"}, "durable_evidence_assertion_digest_length": {"evidence_digest"},
		"durable_evidence_assertion_pending_key_length": {"pending_key"},
		"durable_evidence_assertion_pending_shape":      {"pending_key", "pending_revision"},
		"durable_evidence_assertion_event_length":       {"audit_event_id"},
	})

	add("canonical_state_head", "canonical_state_head_pk", v2Primary("canonical_state_head_pk", "state_namespace", "object_kind", "object_id"))
	add("canonical_state_head", "canonical_state_head_uow_fk", v2Foreign("canonical_state_head_uow_fk", []string{"uow_scope_sha256", "uow_message_id"}, "authoritative_uow", []string{"scope_sha256", "message_id"}, "authoritative_uow_pk"))
	checks("canonical_state_head", canonicalStateChecks("head"))

	add("canonical_state_history", "canonical_state_history_pk", v2Primary("canonical_state_history_pk", "state_namespace", "object_kind", "object_id", "version"))
	add("canonical_state_history", "canonical_state_history_head_fk", v2Foreign("canonical_state_history_head_fk", []string{"state_namespace", "object_kind", "object_id"}, "canonical_state_head", []string{"state_namespace", "object_kind", "object_id"}, "canonical_state_head_pk"))
	add("canonical_state_history", "canonical_state_history_uow_fk", v2Foreign("canonical_state_history_uow_fk", []string{"uow_scope_sha256", "uow_message_id"}, "authoritative_uow", []string{"scope_sha256", "message_id"}, "authoritative_uow_pk"))
	checks("canonical_state_history", canonicalStateChecks("history"))

	if len(result) != len(v2ColumnContract) {
		panic("aiinfra postgres: incomplete v2 table constraint contract")
	}
	return result
}

func businessIdempotencyChecks(suffix string) map[string][]string {
	prefix := "business_idempotency_" + suffix + "_"
	result := map[string][]string{
		prefix + "key_length": {"idempotency_key"}, prefix + "kind": {"row_kind"},
		prefix + "domain_length": {"operation_domain"}, prefix + "owner_length": {"owner_id"},
		prefix + "request_length": {"request_digest"}, prefix + "binding_length": {"binding_digest"},
		prefix + "parent_key_length": {"parent_key"}, prefix + "parent_domain_length": {"parent_operation_domain"},
		prefix + "parent_owner_length": {"parent_owner_id"}, prefix + "parent_request_length": {"parent_request_digest"},
		prefix + "parent_shape": {"row_kind", "parent_key", "parent_operation_domain", "parent_owner_id", "parent_request_digest"},
		prefix + "domain_shape": {"row_kind", "operation_domain"}, prefix + "state": {"state"},
		prefix + "operation_catalog": {"row_kind", "operation_domain", "parent_operation_domain"},
		prefix + "progress_length":   {"progress_digest"}, prefix + "outcome_length": {"outcome_digest"},
		prefix + "state_shape":                   {"state", "version", "progress_digest", "outcome_digest"},
		prefix + "alias_version_shape":           {"row_kind", "state", "version"},
		prefix + "compound_parent_version_shape": {"row_kind", "operation_domain", "state", "version"},
		prefix + "event_length":                  {"audit_event_id"},
		prefix + "uow_scope_length":              {"uow_scope_sha256"}, prefix + "uow_message_length": {"uow_message_id"},
	}
	if suffix == "head" {
		result[prefix+"version_range"] = []string{"version"}
	} else {
		result[prefix+"version_range"] = []string{"version"}
	}
	return result
}

func pendingChecks(suffix string) map[string][]string {
	prefix := "durable_pending_" + suffix + "_"
	revisionRange := prefix + "revision_range"
	revisionShape := prefix + "revision_shape"
	if suffix == "revision" {
		revisionRange = prefix + "range"
		revisionShape = prefix + "shape"
	}
	return map[string][]string{
		prefix + "key_length": {"pending_key"}, prefix + "kind": {"pending_kind"},
		prefix + "codec_length": {"codec"}, prefix + "codec_version_range": {"codec_version"},
		prefix + "kind_codec_catalog": {"pending_kind", "codec", "codec_version"},
		revisionRange:                 {"revision"}, prefix + "previous_length": {"previous_envelope_digest"},
		prefix + "digest_length": {"envelope_digest"}, prefix + "envelope_length": {"canonical_envelope"},
		prefix + "evidence_count": {"evidence_count"}, prefix + "status": {"status"},
		prefix + "kind_evidence_shape": {"pending_kind", "evidence_count"},
		prefix + "window":              {"commit_not_before_unix_nano", "commit_not_after_unix_nano"},
		prefix + "outcome_length":      {"terminal_outcome_digest"},
		revisionShape:                  {"revision", "previous_envelope_digest"},
		prefix + "status_shape":        {"status", "terminal_outcome_digest"}, prefix + "event_length": {"audit_event_id"},
		prefix + "reconciliation_shape": {"pending_kind", "revision", "status", "previous_envelope_digest"},
		prefix + "uow_scope_length":     {"uow_scope_sha256"}, prefix + "uow_message_length": {"uow_message_id"},
	}
}

func canonicalStateChecks(suffix string) map[string][]string {
	prefix := "canonical_state_" + suffix + "_"
	return map[string][]string{
		prefix + "namespace": {"state_namespace"}, prefix + "kind_length": {"object_kind"},
		prefix + "id_length": {"object_id"}, prefix + "version_range": {"version"},
		prefix + "digest_length": {"state_digest"}, prefix + "content_type_length": {"content_type"},
		prefix + "content_length": {"canonical_state"}, prefix + "event_length": {"audit_event_id"},
		prefix + "kind_content_catalog": {"state_namespace", "object_kind", "content_type"},
		prefix + "validity_shape":       {"object_kind", "valid_from_unix_nano", "valid_until_unix_nano"},
		prefix + "uow_scope_length":     {"uow_scope_sha256"}, prefix + "uow_message_length": {"uow_message_id"},
	}
}

var v2TriggerDefinitions = mustV2TriggerDefinitions()

func mustV2TriggerDefinitions() map[string]string {
	contents, err := migrationFiles.ReadFile("migrations/0002_canonical_uow.sql")
	if err != nil {
		panic(fmt.Sprintf("aiinfra postgres: read v2 trigger source: %v", err))
	}
	statements, err := splitSQLStatements(string(contents))
	if err != nil {
		panic(fmt.Sprintf("aiinfra postgres: parse v2 trigger source: %v", err))
	}
	definitions := make(map[string]string)
	for _, statement := range statements {
		at := strings.Index(statement, "CREATE TRIGGER ")
		prefix := "CREATE TRIGGER "
		if constraintAt := strings.Index(statement, "CREATE CONSTRAINT TRIGGER "); constraintAt >= 0 && (at < 0 || constraintAt < at) {
			at = constraintAt
			prefix = "CREATE CONSTRAINT TRIGGER "
		}
		if at < 0 {
			continue
		}
		definition := strings.TrimSpace(statement[at:])
		fields := strings.Fields(strings.TrimPrefix(definition, prefix))
		if len(fields) == 0 {
			panic("aiinfra postgres: malformed v2 trigger source")
		}
		name := fields[0]
		if _, duplicate := definitions[name]; duplicate {
			panic("aiinfra postgres: duplicate v2 trigger name " + name)
		}
		definitions[name] = definition
	}
	return definitions
}

func v2Trigger(table, name, function string, typeMask int64, constraint bool) triggerContract {
	definition, ok := v2TriggerDefinitions[name]
	if !ok {
		panic("aiinfra postgres: missing v2 trigger definition " + name)
	}
	contract := triggerContract{
		functionSchema: "cph_aiinfra", functionName: function,
		typeMask: typeMask, definition: definition,
	}
	if constraint {
		contract.deferrable = true
		contract.initiallyDeferred = true
		contract.constraintName = name
	}
	return contract
}

var v2TriggerContract = buildV2TriggerContract()

func buildV2TriggerContract() map[string]triggerContract {
	result := make(map[string]triggerContract, len(v2TriggerDefinitions))
	add := func(table, name, function string, mask int64, constraint bool) {
		result[table+"."+name] = v2Trigger(table, name, function, mask, constraint)
	}
	immutable := func(table string) {
		add(table, table+"_transaction", "stamp_unit_of_work_transaction", 7, false)
		add(table, table+"_immutable", "reject_immutable_change", 27, false)
	}
	uowMember := func(table string, insertAndUpdate bool) {
		mask := int64(5)
		if insertAndUpdate {
			mask = 21
		}
		add(table, table+"_uow", "assert_audit_uow_member", mask, true)
	}

	immutable("authoritative_uow")
	add("authoritative_uow", "authoritative_uow_coupling", "assert_authoritative_uow", 5, true)
	immutable("audit_event")
	add("audit_event", "audit_event_uow", "assert_audit_event_uow", 5, true)
	add("audit_head", "audit_head_monotonic", "enforce_audit_head_change", 31, false)
	add("audit_head", "audit_head_event", "assert_audit_head_event", 21, true)

	add("business_idempotency_head", "business_idempotency_head_monotonic", "enforce_business_idempotency_head_change", 31, false)
	add("business_idempotency_head", "business_idempotency_head_consistency", "assert_business_idempotency_consistency", 21, true)
	uowMember("business_idempotency_head", true)
	immutable("business_idempotency_history")
	add("business_idempotency_history", "business_idempotency_history_consistency", "assert_business_idempotency_consistency", 5, true)
	uowMember("business_idempotency_history", false)

	add("global_identifier_head", "global_identifier_head_monotonic", "enforce_global_identifier_head_change", 31, false)
	add("global_identifier_head", "global_identifier_head_consistency", "assert_global_identifier_consistency", 21, true)
	uowMember("global_identifier_head", true)
	immutable("global_identifier_history")
	add("global_identifier_history", "global_identifier_history_consistency", "assert_global_identifier_consistency", 5, true)
	uowMember("global_identifier_history", false)
	immutable("global_identifier_claim")
	add("global_identifier_claim", "global_identifier_claim_consistency", "assert_global_identifier_consistency", 5, true)
	uowMember("global_identifier_claim", false)

	immutable("durable_evidence")
	uowMember("durable_evidence", false)
	add("durable_pending_head", "durable_pending_head_monotonic", "enforce_durable_pending_head_change", 31, false)
	add("durable_pending_head", "durable_pending_head_consistency", "assert_durable_pending_consistency", 21, true)
	uowMember("durable_pending_head", true)
	immutable("durable_pending_revision")
	add("durable_pending_revision", "durable_pending_revision_consistency", "assert_durable_pending_consistency", 5, true)
	uowMember("durable_pending_revision", false)
	immutable("durable_pending_evidence")
	add("durable_pending_evidence", "durable_pending_evidence_consistency", "assert_durable_pending_evidence_consistency", 5, true)
	uowMember("durable_pending_evidence", false)
	immutable("durable_evidence_assertion")
	add("durable_evidence_assertion", "durable_evidence_assertion_consistency", "assert_durable_evidence_assertion", 5, true)
	uowMember("durable_evidence_assertion", false)

	add("canonical_state_head", "canonical_state_head_monotonic", "enforce_canonical_state_head_change", 31, false)
	add("canonical_state_head", "canonical_state_head_consistency", "assert_canonical_state_consistency", 21, true)
	uowMember("canonical_state_head", true)
	immutable("canonical_state_history")
	add("canonical_state_history", "canonical_state_history_consistency", "assert_canonical_state_consistency", 5, true)
	add("canonical_state_history", "canonical_state_history_profile_timeline", "assert_governance_profile_activation_timeline", 5, true)
	uowMember("canonical_state_history", false)

	if len(result) != len(v2TriggerDefinitions) {
		panic(fmt.Sprintf("aiinfra postgres: v2 trigger contract has %d entries, source has %d", len(result), len(v2TriggerDefinitions)))
	}
	return result
}

func v2Index(table, name string, unique, primary bool, constraint string,
	keys, opclasses, collations []string) indexContract {
	uniqueSQL := ""
	if unique {
		uniqueSQL = "UNIQUE "
	}
	return indexContract{
		table: table, unique: unique, primary: primary, constraint: constraint,
		keyColumns: keys, opclasses: opclasses, collations: collations,
		definition: "CREATE " + uniqueSQL + "INDEX " + name + " ON cph_aiinfra." + table +
			" USING btree (" + strings.Join(keys, ", ") + ")",
	}
}

var v2IndexContract = buildV2IndexContract()

func buildV2IndexContract() map[string]indexContract {
	result := make(map[string]indexContract)
	add := func(table, name string, unique, primary bool, constraint string, keys, opclasses, collations []string) {
		result[name] = v2Index(table, name, unique, primary, constraint, keys, opclasses, collations)
	}
	add("authoritative_uow", "authoritative_uow_pk", true, true, "authoritative_uow_pk",
		[]string{"scope_sha256", "message_id"}, []string{"pg_catalog.bytea_ops", "pg_catalog.bytea_ops"}, []string{"-", "-"})
	add("authoritative_uow", "authoritative_uow_transaction_key", true, false, "authoritative_uow_transaction_key",
		[]string{"transaction_id"}, []string{"pg_catalog.xid8_ops"}, []string{"-"})
	add("audit_event", "audit_event_pk", true, true, "audit_event_pk",
		[]string{"event_id"}, []string{"pg_catalog.text_ops"}, []string{"pg_catalog.C"})
	add("audit_event", "audit_event_stream_sequence_key", true, false, "audit_event_stream_sequence_key",
		[]string{"stream_id", "audit_sequence"}, []string{"pg_catalog.text_ops", "pg_catalog.numeric_ops"}, []string{"pg_catalog.C", "-"})
	add("audit_event", "audit_event_uow_key", true, false, "audit_event_uow_key",
		[]string{"scope_sha256", "message_id"}, []string{"pg_catalog.bytea_ops", "pg_catalog.bytea_ops"}, []string{"-", "-"})
	add("audit_head", "audit_head_pk", true, true, "audit_head_pk",
		[]string{"stream_id"}, []string{"pg_catalog.text_ops"}, []string{"pg_catalog.C"})
	add("business_idempotency_head", "business_idempotency_head_pk", true, true, "business_idempotency_head_pk",
		[]string{"idempotency_key"}, []string{"pg_catalog.bytea_ops"}, []string{"-"})
	add("business_idempotency_head", "business_idempotency_head_parent_idx", false, false, "",
		[]string{"parent_key"}, []string{"pg_catalog.bytea_ops"}, []string{"-"})
	add("business_idempotency_history", "business_idempotency_history_pk", true, true, "business_idempotency_history_pk",
		[]string{"idempotency_key", "version"}, []string{"pg_catalog.bytea_ops", "pg_catalog.numeric_ops"}, []string{"-", "-"})
	add("business_idempotency_history", "business_idempotency_history_event_idx", false, false, "",
		[]string{"audit_event_id"}, []string{"pg_catalog.text_ops"}, []string{"pg_catalog.C"})
	add("global_identifier_head", "global_identifier_head_pk", true, true, "global_identifier_head_pk",
		[]string{"identifier"}, []string{"pg_catalog.text_ops"}, []string{"pg_catalog.C"})
	add("global_identifier_history", "global_identifier_history_pk", true, true, "global_identifier_history_pk",
		[]string{"identifier", "version"}, []string{"pg_catalog.text_ops", "pg_catalog.numeric_ops"}, []string{"pg_catalog.C", "-"})
	add("global_identifier_history", "global_identifier_history_event_idx", false, false, "",
		[]string{"audit_event_id"}, []string{"pg_catalog.text_ops"}, []string{"pg_catalog.C"})
	add("global_identifier_claim", "global_identifier_claim_pk", true, true, "global_identifier_claim_pk",
		[]string{"uow_scope_sha256", "uow_message_id", "claim_ordinal"}, []string{"pg_catalog.bytea_ops", "pg_catalog.bytea_ops", "pg_catalog.int2_ops"}, []string{"-", "-", "-"})
	add("global_identifier_claim", "global_identifier_claim_uow_identifier_key", true, false, "global_identifier_claim_uow_identifier_key",
		[]string{"uow_scope_sha256", "uow_message_id", "identifier"}, []string{"pg_catalog.bytea_ops", "pg_catalog.bytea_ops", "pg_catalog.text_ops"}, []string{"-", "-", "pg_catalog.C"})
	add("durable_evidence", "durable_evidence_pk", true, true, "durable_evidence_pk",
		[]string{"evidence_digest"}, []string{"pg_catalog.bytea_ops"}, []string{"-"})
	add("durable_pending_head", "durable_pending_head_pk", true, true, "durable_pending_head_pk",
		[]string{"pending_key"}, []string{"pg_catalog.bytea_ops"}, []string{"-"})
	add("durable_pending_revision", "durable_pending_revision_pk", true, true, "durable_pending_revision_pk",
		[]string{"pending_key", "revision"}, []string{"pg_catalog.bytea_ops", "pg_catalog.numeric_ops"}, []string{"-", "-"})
	add("durable_pending_revision", "durable_pending_revision_event_idx", false, false, "",
		[]string{"audit_event_id"}, []string{"pg_catalog.text_ops"}, []string{"pg_catalog.C"})
	add("durable_pending_evidence", "durable_pending_evidence_pk", true, true, "durable_pending_evidence_pk",
		[]string{"pending_key", "revision", "evidence_ordinal"}, []string{"pg_catalog.bytea_ops", "pg_catalog.numeric_ops", "pg_catalog.int2_ops"}, []string{"-", "-", "-"})
	add("durable_pending_evidence", "durable_pending_evidence_digest_key", true, false, "durable_pending_evidence_digest_key",
		[]string{"pending_key", "revision", "evidence_digest"}, []string{"pg_catalog.bytea_ops", "pg_catalog.numeric_ops", "pg_catalog.bytea_ops"}, []string{"-", "-", "-"})
	add("durable_evidence_assertion", "durable_evidence_assertion_pk", true, true, "durable_evidence_assertion_pk",
		[]string{"uow_scope_sha256", "uow_message_id", "evidence_ordinal"}, []string{"pg_catalog.bytea_ops", "pg_catalog.bytea_ops", "pg_catalog.int2_ops"}, []string{"-", "-", "-"})
	add("durable_evidence_assertion", "durable_evidence_assertion_digest_key", true, false, "durable_evidence_assertion_digest_key",
		[]string{"uow_scope_sha256", "uow_message_id", "evidence_digest"}, []string{"pg_catalog.bytea_ops", "pg_catalog.bytea_ops", "pg_catalog.bytea_ops"}, []string{"-", "-", "-"})
	add("canonical_state_head", "canonical_state_head_pk", true, true, "canonical_state_head_pk",
		[]string{"state_namespace", "object_kind", "object_id"}, []string{"pg_catalog.int2_ops", "pg_catalog.text_ops", "pg_catalog.text_ops"}, []string{"-", "pg_catalog.C", "pg_catalog.C"})
	add("canonical_state_history", "canonical_state_history_pk", true, true, "canonical_state_history_pk",
		[]string{"state_namespace", "object_kind", "object_id", "version"}, []string{"pg_catalog.int2_ops", "pg_catalog.text_ops", "pg_catalog.text_ops", "pg_catalog.numeric_ops"}, []string{"-", "pg_catalog.C", "pg_catalog.C", "-"})
	add("canonical_state_history", "canonical_state_history_event_idx", false, false, "",
		[]string{"audit_event_id"}, []string{"pg_catalog.text_ops"}, []string{"pg_catalog.C"})
	if len(result) != 26 {
		panic(fmt.Sprintf("aiinfra postgres: v2 index contract has %d entries, want 26", len(result)))
	}
	return result
}

func init() {
	for table, columns := range v2ColumnContract {
		if _, exists := replayColumnContract[table]; exists {
			panic("aiinfra postgres: duplicate v2 table contract " + table)
		}
		replayColumnContract[table] = columns
		replayConstraintContract[table] = v2ConstraintContract[table]
	}
	for relation, kind := range v2RelationContract {
		if _, exists := replayRelationContract[relation]; exists {
			panic("aiinfra postgres: duplicate v2 relation contract " + relation)
		}
		replayRelationContract[relation] = kind
	}
}
