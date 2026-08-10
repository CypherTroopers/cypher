// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"slices"
	"sort"
	"strings"
)

type columnContract struct {
	name       string
	typeName   string
	notNull    bool
	defaultSQL string
}

type constraintContract struct {
	kind              string
	deferrable        bool
	initiallyDeferred bool
	keyColumns        []string
	referencedTable   string
	referencedColumns []string
	indexName         string
	definition        string
}

type triggerContract struct {
	functionSchema    string
	functionName      string
	typeMask          int64
	deferrable        bool
	initiallyDeferred bool
	constraintName    string
	definition        string
}

type indexContract struct {
	table      string
	unique     bool
	primary    bool
	constraint string
	keyColumns []string
	opclasses  []string
	collations []string
	definition string
}

var replayColumnContract = map[string][]columnContract{
	"schema_migration": {
		{"version", "bigint", true, ""},
		{"migration_sha256", "bytea", true, ""},
		{"applied_at", "timestamp with time zone", true, "clock_timestamp()"},
	},
	"ccse_replay_head": {
		{"scope_sha256", "bytea", true, ""},
		{"counter_kind", "smallint", true, ""},
		{"replay_domain_id", "text", true, ""},
		{"sender_identity", "text", true, ""},
		{"environment", "text", true, ""},
		{"chain_id", "bytea", true, ""},
		{"genesis_hash", "bytea", true, ""},
		{"highest_sequence", "bytea", false, ""},
		{"updated_at", "timestamp with time zone", true, "clock_timestamp()"},
	},
	"ccse_durable_result": {
		{"scope_sha256", "bytea", true, ""},
		{"message_id", "bytea", true, ""},
		{"result_digest", "bytea", true, ""},
		{"content_type", "text", true, ""},
		{"payload", "bytea", true, ""},
		{"external_effect_mode", "smallint", true, ""},
		{"transaction_id", "xid8", true, ""},
		{"committed_at", "timestamp with time zone", true, "clock_timestamp()"},
	},
	"ccse_replay_inbox": {
		{"scope_sha256", "bytea", true, ""},
		{"message_id", "bytea", true, ""},
		{"counter_kind", "smallint", true, ""},
		{"message_type_id", "bigint", true, ""},
		{"schema_major", "bigint", true, ""},
		{"schema_minor", "bigint", true, ""},
		{"record_digest", "bytea", true, ""},
		{"sequence", "bytea", true, ""},
		{"expires_at_unix_nano", "bigint", true, ""},
		{"outcome_digest", "bytea", true, ""},
		{"transaction_id", "xid8", true, ""},
		{"committed_at", "timestamp with time zone", true, "clock_timestamp()"},
	},
	"ccse_outbox_intent": {
		{"event_id", "bytea", true, ""},
		{"scope_sha256", "bytea", true, ""},
		{"message_id", "bytea", true, ""},
		{"destination", "text", true, ""},
		{"deduplication_key", "text", true, ""},
		{"content_type", "text", true, ""},
		{"payload", "bytea", true, ""},
		{"payload_digest", "bytea", true, ""},
		{"transaction_id", "xid8", true, ""},
		{"created_at", "timestamp with time zone", true, "clock_timestamp()"},
	},
}

var replayConstraintContract = map[string]map[string]constraintContract{
	"schema_migration": {
		"schema_migration_pk":            {kind: "p", keyColumns: []string{"version"}, indexName: "cph_aiinfra.schema_migration_pk", definition: "PRIMARY KEY (version)"},
		"schema_migration_digest_length": {kind: "c", keyColumns: []string{"migration_sha256"}, definition: "CHECK ((octet_length(migration_sha256) = 32))"},
	},
	"ccse_replay_head": {
		"ccse_replay_head_pk":                 {kind: "p", keyColumns: []string{"scope_sha256"}, indexName: "cph_aiinfra.ccse_replay_head_pk", definition: "PRIMARY KEY (scope_sha256)"},
		"ccse_replay_head_scope_length":       {kind: "c", keyColumns: []string{"scope_sha256"}, definition: "CHECK ((octet_length(scope_sha256) = 32))"},
		"ccse_replay_head_counter_kind":       {kind: "c", keyColumns: []string{"counter_kind"}, definition: "CHECK ((counter_kind = ANY (ARRAY[1, 2])))"},
		"ccse_replay_head_domain_length":      {kind: "c", keyColumns: []string{"replay_domain_id"}, definition: "CHECK (((octet_length(replay_domain_id) >= 1) AND (octet_length(replay_domain_id) <= 65536)))"},
		"ccse_replay_head_sender_length":      {kind: "c", keyColumns: []string{"sender_identity"}, definition: "CHECK (((octet_length(sender_identity) >= 1) AND (octet_length(sender_identity) <= 65536)))"},
		"ccse_replay_head_environment_length": {kind: "c", keyColumns: []string{"environment"}, definition: "CHECK (((octet_length(environment) >= 1) AND (octet_length(environment) <= 65536)))"},
		"ccse_replay_head_chain_length":       {kind: "c", keyColumns: []string{"chain_id"}, definition: "CHECK ((octet_length(chain_id) = 32))"},
		"ccse_replay_head_genesis_length":     {kind: "c", keyColumns: []string{"genesis_hash"}, definition: "CHECK ((octet_length(genesis_hash) = 32))"},
		"ccse_replay_head_sequence_length":    {kind: "c", keyColumns: []string{"highest_sequence"}, definition: "CHECK (((highest_sequence IS NULL) OR (octet_length(highest_sequence) = 8)))"},
	},
	"ccse_durable_result": {
		"ccse_durable_result_pk":                  {kind: "p", keyColumns: []string{"scope_sha256", "message_id"}, indexName: "cph_aiinfra.ccse_durable_result_pk", definition: "PRIMARY KEY (scope_sha256, message_id)"},
		"ccse_durable_result_digest_key":          {kind: "u", keyColumns: []string{"scope_sha256", "message_id", "result_digest"}, indexName: "cph_aiinfra.ccse_durable_result_digest_key", definition: "UNIQUE (scope_sha256, message_id, result_digest)"},
		"ccse_durable_result_scope_fk":            {kind: "f", keyColumns: []string{"scope_sha256"}, referencedTable: "cph_aiinfra.ccse_replay_head", referencedColumns: []string{"scope_sha256"}, indexName: "cph_aiinfra.ccse_replay_head_pk", definition: "FOREIGN KEY (scope_sha256) REFERENCES cph_aiinfra.ccse_replay_head(scope_sha256)"},
		"ccse_durable_result_message_length":      {kind: "c", keyColumns: []string{"message_id"}, definition: "CHECK ((octet_length(message_id) = 16))"},
		"ccse_durable_result_digest_length":       {kind: "c", keyColumns: []string{"result_digest"}, definition: "CHECK ((octet_length(result_digest) = 32))"},
		"ccse_durable_result_content_type_length": {kind: "c", keyColumns: []string{"content_type"}, definition: "CHECK (((octet_length(content_type) >= 1) AND (octet_length(content_type) <= 255)))"},
		"ccse_durable_result_payload_length":      {kind: "c", keyColumns: []string{"payload"}, definition: "CHECK ((octet_length(payload) <= 1048576))"},
		"ccse_durable_result_effect_mode":         {kind: "c", keyColumns: []string{"external_effect_mode"}, definition: "CHECK ((external_effect_mode = ANY (ARRAY[1, 2])))"},
	},
	"ccse_replay_inbox": {
		"ccse_replay_inbox_pk":              {kind: "p", keyColumns: []string{"scope_sha256", "message_id"}, indexName: "cph_aiinfra.ccse_replay_inbox_pk", definition: "PRIMARY KEY (scope_sha256, message_id)"},
		"ccse_replay_inbox_scope_fk":        {kind: "f", keyColumns: []string{"scope_sha256"}, referencedTable: "cph_aiinfra.ccse_replay_head", referencedColumns: []string{"scope_sha256"}, indexName: "cph_aiinfra.ccse_replay_head_pk", definition: "FOREIGN KEY (scope_sha256) REFERENCES cph_aiinfra.ccse_replay_head(scope_sha256)"},
		"ccse_replay_inbox_result_fk":       {kind: "f", deferrable: true, initiallyDeferred: true, keyColumns: []string{"scope_sha256", "message_id", "outcome_digest"}, referencedTable: "cph_aiinfra.ccse_durable_result", referencedColumns: []string{"scope_sha256", "message_id", "result_digest"}, indexName: "cph_aiinfra.ccse_durable_result_digest_key", definition: "FOREIGN KEY (scope_sha256, message_id, outcome_digest) REFERENCES cph_aiinfra.ccse_durable_result(scope_sha256, message_id, result_digest) DEFERRABLE INITIALLY DEFERRED"},
		"ccse_replay_inbox_message_length":  {kind: "c", keyColumns: []string{"message_id"}, definition: "CHECK ((octet_length(message_id) = 16))"},
		"ccse_replay_inbox_counter_kind":    {kind: "c", keyColumns: []string{"counter_kind"}, definition: "CHECK ((counter_kind = ANY (ARRAY[1, 2])))"},
		"ccse_replay_inbox_type_range":      {kind: "c", keyColumns: []string{"message_type_id"}, definition: "CHECK (((message_type_id >= 1) AND (message_type_id <= 4294967295)))"},
		"ccse_replay_inbox_major_range":     {kind: "c", keyColumns: []string{"schema_major"}, definition: "CHECK (((schema_major >= 1) AND (schema_major <= 4294967295)))"},
		"ccse_replay_inbox_minor_range":     {kind: "c", keyColumns: []string{"schema_minor"}, definition: "CHECK (((schema_minor >= 0) AND (schema_minor <= 4294967295)))"},
		"ccse_replay_inbox_record_length":   {kind: "c", keyColumns: []string{"record_digest"}, definition: "CHECK ((octet_length(record_digest) = 32))"},
		"ccse_replay_inbox_sequence_length": {kind: "c", keyColumns: []string{"sequence"}, definition: "CHECK ((octet_length(sequence) = 8))"},
		"ccse_replay_inbox_expiry_positive": {kind: "c", keyColumns: []string{"expires_at_unix_nano"}, definition: "CHECK ((expires_at_unix_nano > 0))"},
		"ccse_replay_inbox_outcome_length":  {kind: "c", keyColumns: []string{"outcome_digest"}, definition: "CHECK ((octet_length(outcome_digest) = 32))"},
	},
	"ccse_outbox_intent": {
		"ccse_outbox_intent_pk":                    {kind: "p", keyColumns: []string{"event_id"}, indexName: "cph_aiinfra.ccse_outbox_intent_pk", definition: "PRIMARY KEY (event_id)"},
		"ccse_outbox_intent_dedup_key":             {kind: "u", keyColumns: []string{"destination", "deduplication_key"}, indexName: "cph_aiinfra.ccse_outbox_intent_dedup_key", definition: "UNIQUE (destination, deduplication_key)"},
		"ccse_outbox_intent_result_fk":             {kind: "f", deferrable: true, initiallyDeferred: true, keyColumns: []string{"scope_sha256", "message_id"}, referencedTable: "cph_aiinfra.ccse_durable_result", referencedColumns: []string{"scope_sha256", "message_id"}, indexName: "cph_aiinfra.ccse_durable_result_pk", definition: "FOREIGN KEY (scope_sha256, message_id) REFERENCES cph_aiinfra.ccse_durable_result(scope_sha256, message_id) DEFERRABLE INITIALLY DEFERRED"},
		"ccse_outbox_intent_event_length":          {kind: "c", keyColumns: []string{"event_id"}, definition: "CHECK ((octet_length(event_id) = 16))"},
		"ccse_outbox_intent_scope_length":          {kind: "c", keyColumns: []string{"scope_sha256"}, definition: "CHECK ((octet_length(scope_sha256) = 32))"},
		"ccse_outbox_intent_message_length":        {kind: "c", keyColumns: []string{"message_id"}, definition: "CHECK ((octet_length(message_id) = 16))"},
		"ccse_outbox_intent_destination_length":    {kind: "c", keyColumns: []string{"destination"}, definition: "CHECK (((octet_length(destination) >= 1) AND (octet_length(destination) <= 255)))"},
		"ccse_outbox_intent_dedup_length":          {kind: "c", keyColumns: []string{"deduplication_key"}, definition: "CHECK (((octet_length(deduplication_key) >= 1) AND (octet_length(deduplication_key) <= 1024)))"},
		"ccse_outbox_intent_content_type_length":   {kind: "c", keyColumns: []string{"content_type"}, definition: "CHECK (((octet_length(content_type) >= 1) AND (octet_length(content_type) <= 255)))"},
		"ccse_outbox_intent_payload_length":        {kind: "c", keyColumns: []string{"payload"}, definition: "CHECK ((octet_length(payload) <= 1048576))"},
		"ccse_outbox_intent_payload_digest_length": {kind: "c", keyColumns: []string{"payload_digest"}, definition: "CHECK ((octet_length(payload_digest) = 32))"},
	},
}

var replayRelationContract = map[string]string{
	"schema_migration":                   "r",
	"schema_migration_pk":                "i",
	"ccse_replay_head":                   "r",
	"ccse_replay_head_pk":                "i",
	"ccse_durable_result":                "r",
	"ccse_durable_result_pk":             "i",
	"ccse_durable_result_digest_key":     "i",
	"ccse_replay_inbox":                  "r",
	"ccse_replay_inbox_pk":               "i",
	"ccse_replay_inbox_committed_at_idx": "i",
	"ccse_outbox_intent":                 "r",
	"ccse_outbox_intent_pk":              "i",
	"ccse_outbox_intent_dedup_key":       "i",
	"ccse_outbox_intent_created_at_idx":  "i",
}

func verifyMigrationLedgerShape(ctx context.Context, tx *sql.Tx) error {
	if err := verifyTableColumns(ctx, tx, "schema_migration", replayColumnContract["schema_migration"]); err != nil {
		return err
	}
	return verifyTableConstraints(ctx, tx, "schema_migration", replayConstraintContract["schema_migration"])
}

func verifyReplaySchema(ctx context.Context, tx *sql.Tx) error {
	if err := verifyReplaySchemaShape(ctx, tx); err != nil {
		return err
	}
	digest, err := ReplayMigrationDigest()
	if err != nil {
		return err
	}
	var applied []byte
	if err := tx.QueryRowContext(ctx,
		"SELECT migration_sha256 FROM cph_aiinfra.schema_migration WHERE version=$1",
		replayMigrationVersion,
	).Scan(&applied); err != nil {
		return fmt.Errorf("%w: read migration seal: %v", ErrSchemaShapeMismatch, err)
	}
	if !bytes.Equal(applied, digest[:]) {
		return fmt.Errorf("%w: migration seal mismatch", ErrSchemaShapeMismatch)
	}
	return nil
}

func verifyReplaySchemaShape(ctx context.Context, tx *sql.Tx) error {
	if err := verifyRelationContract(ctx, tx); err != nil {
		return err
	}
	if err := verifyNamespaceTypeContract(ctx, tx); err != nil {
		return err
	}
	if err := verifyNoAuxiliarySchemaObjects(ctx, tx); err != nil {
		return err
	}
	for table, expected := range replayColumnContract {
		if err := verifyTableColumns(ctx, tx, table, expected); err != nil {
			return err
		}
		if err := verifyTableConstraints(ctx, tx, table, replayConstraintContract[table]); err != nil {
			return err
		}
		if err := verifyTableMetadata(ctx, tx, table); err != nil {
			return err
		}
	}
	if err := verifyOutboxCollation(ctx, tx); err != nil {
		return err
	}
	if err := verifyFunctionContract(ctx, tx); err != nil {
		return err
	}
	if err := verifyOwnershipAndPublicACL(ctx, tx); err != nil {
		return err
	}
	if err := verifyTriggerContract(ctx, tx); err != nil {
		return err
	}
	if err := verifyIndexContract(ctx, tx); err != nil {
		return err
	}
	return nil
}

func verifyRelationContract(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT c.relname, c.relkind::text, c.relpersistence::text, c.relispartition
		FROM pg_catalog.pg_class c
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'cph_aiinfra'
		ORDER BY c.relname`)
	if err != nil {
		return fmt.Errorf("%w: inspect relation inventory: %v", ErrSchemaShapeMismatch, err)
	}
	defer rows.Close()
	seen := make(map[string]struct{}, len(replayRelationContract))
	for rows.Next() {
		var name, kind, persistence string
		var partition bool
		if err := rows.Scan(&name, &kind, &persistence, &partition); err != nil {
			return fmt.Errorf("%w: scan relation inventory: %v", ErrSchemaShapeMismatch, err)
		}
		expectedKind, ok := replayRelationContract[name]
		if !ok || kind != expectedKind || persistence != "p" || partition {
			return fmt.Errorf("%w: unexpected or unsafe relation cph_aiinfra.%s", ErrSchemaShapeMismatch, name)
		}
		seen[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%w: read relation inventory: %v", ErrSchemaShapeMismatch, err)
	}
	if len(seen) != len(replayRelationContract) {
		return fmt.Errorf("%w: relation count is %d, want %d", ErrSchemaShapeMismatch, len(seen), len(replayRelationContract))
	}
	var inherited bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
		  SELECT 1
		  FROM pg_catalog.pg_inherits inheritance
		  JOIN pg_catalog.pg_class child ON child.oid = inheritance.inhrelid
		  JOIN pg_catalog.pg_namespace child_namespace ON child_namespace.oid = child.relnamespace
		  JOIN pg_catalog.pg_class parent ON parent.oid = inheritance.inhparent
		  JOIN pg_catalog.pg_namespace parent_namespace ON parent_namespace.oid = parent.relnamespace
		  WHERE child_namespace.nspname = 'cph_aiinfra' OR parent_namespace.nspname = 'cph_aiinfra'
		)`,
	).Scan(&inherited); err != nil {
		return fmt.Errorf("%w: inspect inheritance graph: %v", ErrSchemaShapeMismatch, err)
	}
	if inherited {
		return fmt.Errorf("%w: cph_aiinfra relation participates in inheritance/partitioning", ErrSchemaShapeMismatch)
	}
	return nil
}

func verifyNamespaceTypeContract(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT value.typname, value.typtype::text, value.typcategory::text,
		       value.typowner = namespace.nspowner, value.typispreferred,
		       value.typnotnull, value.typbasetype = 0, value.typcollation = 0,
		       COALESCE(relation.relname, ''), COALESCE(element.typname, ''),
		       COALESCE(element_relation.relname, ''), COALESCE(element.typarray = value.oid, false)
		FROM pg_catalog.pg_type value
		JOIN pg_catalog.pg_namespace namespace ON namespace.oid = value.typnamespace
		LEFT JOIN pg_catalog.pg_class relation ON relation.oid = value.typrelid
		LEFT JOIN pg_catalog.pg_type element ON element.oid = value.typelem
		LEFT JOIN pg_catalog.pg_class element_relation ON element_relation.oid = element.typrelid
		WHERE namespace.nspname = 'cph_aiinfra'
		ORDER BY value.typname`)
	if err != nil {
		return fmt.Errorf("%w: inspect namespace type inventory: %v", ErrSchemaShapeMismatch, err)
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var name, kind, category, relation, element, elementRelation string
		var owner, preferred, notNull, noBase, noCollation, arrayLinked bool
		if err := rows.Scan(&name, &kind, &category, &owner, &preferred, &notNull,
			&noBase, &noCollation, &relation, &element, &elementRelation, &arrayLinked); err != nil {
			return fmt.Errorf("%w: scan namespace type inventory: %v", ErrSchemaShapeMismatch, err)
		}
		_, expectedTable := replayColumnContract[name]
		arrayTable := strings.TrimPrefix(name, "_")
		_, expectedArray := replayColumnContract[arrayTable]
		validComposite := expectedTable && kind == "c" && category == "C" && relation == name &&
			element == "" && elementRelation == "" && !arrayLinked
		validArray := strings.HasPrefix(name, "_") && expectedArray && kind == "b" && category == "A" &&
			relation == "" && element == arrayTable && elementRelation == arrayTable && arrayLinked
		if !owner || preferred || notNull || !noBase || !noCollation || (!validComposite && !validArray) {
			return fmt.Errorf("%w: unexpected namespace type cph_aiinfra.%s", ErrSchemaShapeMismatch, name)
		}
		seen++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%w: read namespace type inventory: %v", ErrSchemaShapeMismatch, err)
	}
	if seen != 2*len(replayColumnContract) {
		return fmt.Errorf("%w: namespace type count is %d, want %d", ErrSchemaShapeMismatch, seen, 2*len(replayColumnContract))
	}
	return nil
}

func verifyNoAuxiliarySchemaObjects(ctx context.Context, tx *sql.Tx) error {
	var extra bool
	if err := tx.QueryRowContext(ctx, `
		SELECT
		  EXISTS (SELECT 1 FROM pg_catalog.pg_collation value WHERE value.collnamespace = namespace.oid) OR
		  EXISTS (SELECT 1 FROM pg_catalog.pg_conversion value WHERE value.connamespace = namespace.oid) OR
		  EXISTS (SELECT 1 FROM pg_catalog.pg_operator value WHERE value.oprnamespace = namespace.oid) OR
		  EXISTS (SELECT 1 FROM pg_catalog.pg_opclass value WHERE value.opcnamespace = namespace.oid) OR
		  EXISTS (SELECT 1 FROM pg_catalog.pg_opfamily value WHERE value.opfnamespace = namespace.oid) OR
		  EXISTS (SELECT 1 FROM pg_catalog.pg_statistic_ext value WHERE value.stxnamespace = namespace.oid) OR
		  EXISTS (SELECT 1 FROM pg_catalog.pg_extension value WHERE value.extnamespace = namespace.oid) OR
		  EXISTS (SELECT 1 FROM pg_catalog.pg_ts_config value WHERE value.cfgnamespace = namespace.oid) OR
		  EXISTS (SELECT 1 FROM pg_catalog.pg_ts_dict value WHERE value.dictnamespace = namespace.oid) OR
		  EXISTS (SELECT 1 FROM pg_catalog.pg_ts_parser value WHERE value.prsnamespace = namespace.oid) OR
		  EXISTS (SELECT 1 FROM pg_catalog.pg_ts_template value WHERE value.tmplnamespace = namespace.oid) OR
		  EXISTS (
		    SELECT 1 FROM pg_catalog.pg_policy policy
		    JOIN pg_catalog.pg_class relation ON relation.oid = policy.polrelid
		    WHERE relation.relnamespace = namespace.oid
		  ) OR
		  EXISTS (
		    SELECT 1 FROM pg_catalog.pg_default_acl defaults
		    WHERE defaults.defaclnamespace = namespace.oid
		  )
		FROM pg_catalog.pg_namespace namespace
		WHERE namespace.nspname = 'cph_aiinfra'`,
	).Scan(&extra); err != nil {
		return fmt.Errorf("%w: inspect auxiliary schema objects: %v", ErrSchemaShapeMismatch, err)
	}
	if extra {
		return fmt.Errorf("%w: unexpected auxiliary object in cph_aiinfra schema", ErrSchemaShapeMismatch)
	}
	return nil
}

func verifyTableColumns(ctx context.Context, tx *sql.Tx, table string, expected []columnContract) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull,
		       COALESCE(pg_get_expr(d.adbin, d.adrelid), '')
		FROM pg_catalog.pg_attribute a
		JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
		WHERE n.nspname = 'cph_aiinfra' AND c.relname = $1
		  AND c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped
		ORDER BY a.attnum`, table)
	if err != nil {
		return fmt.Errorf("%w: inspect columns for %s: %v", ErrSchemaShapeMismatch, table, err)
	}
	defer rows.Close()
	var actual []columnContract
	for rows.Next() {
		var column columnContract
		if err := rows.Scan(&column.name, &column.typeName, &column.notNull, &column.defaultSQL); err != nil {
			return fmt.Errorf("%w: scan columns for %s: %v", ErrSchemaShapeMismatch, table, err)
		}
		actual = append(actual, column)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%w: read columns for %s: %v", ErrSchemaShapeMismatch, table, err)
	}
	if len(actual) != len(expected) {
		return fmt.Errorf("%w: %s column count is %d, want %d", ErrSchemaShapeMismatch, table, len(actual), len(expected))
	}
	for index := range expected {
		if actual[index] != expected[index] {
			return fmt.Errorf("%w: %s column %d is %+v, want %+v", ErrSchemaShapeMismatch, table, index, actual[index], expected[index])
		}
	}
	return nil
}

func verifyTableConstraints(ctx context.Context, tx *sql.Tx, table string, expected map[string]constraintContract) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT con.conname, con.contype::text, con.condeferrable, con.condeferred,
		       con.convalidated, con.connoinherit, con.conislocal, con.coninhcount,
		       con.conparentid = 0, pg_get_constraintdef(con.oid, false),
		       COALESCE(array_to_string(ARRAY(
		         SELECT a.attname
		           FROM unnest(con.conkey) WITH ORDINALITY AS key(attnum, ordinal)
		           JOIN pg_catalog.pg_attribute a
		             ON a.attrelid = con.conrelid AND a.attnum = key.attnum
		          ORDER BY key.ordinal
		       ), chr(31)), ''),
		       COALESCE(refn.nspname || '.' || refc.relname, ''),
		       COALESCE(array_to_string(ARRAY(
		         SELECT a.attname
		           FROM unnest(con.confkey) WITH ORDINALITY AS key(attnum, ordinal)
		           JOIN pg_catalog.pg_attribute a
		             ON a.attrelid = con.confrelid AND a.attnum = key.attnum
		          ORDER BY key.ordinal
		       ), chr(31)), ''),
		       COALESCE(indexn.nspname || '.' || indexc.relname, ''),
		       con.confupdtype::text, con.confdeltype::text, con.confmatchtype::text
		FROM pg_catalog.pg_constraint con
		JOIN pg_catalog.pg_class c ON c.oid = con.conrelid
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		LEFT JOIN pg_catalog.pg_class refc ON refc.oid = con.confrelid
		LEFT JOIN pg_catalog.pg_namespace refn ON refn.oid = refc.relnamespace
		LEFT JOIN pg_catalog.pg_class indexc ON indexc.oid = con.conindid
		LEFT JOIN pg_catalog.pg_namespace indexn ON indexn.oid = indexc.relnamespace
		WHERE n.nspname = 'cph_aiinfra' AND c.relname = $1
		  AND con.contype <> 't'
		ORDER BY con.conname`, table)
	if err != nil {
		return fmt.Errorf("%w: inspect constraints for %s: %v", ErrSchemaShapeMismatch, table, err)
	}
	defer rows.Close()
	seen := make(map[string]struct{}, len(expected))
	for rows.Next() {
		var name, kind, definition, keyList, referencedTable, referencedList, indexName string
		var updateAction, deleteAction, matchType string
		var deferrable, deferred, validated, noInherit, local, noParent bool
		var inheritCount int64
		if err := rows.Scan(&name, &kind, &deferrable, &deferred, &validated,
			&noInherit, &local, &inheritCount, &noParent, &definition, &keyList,
			&referencedTable, &referencedList, &indexName,
			&updateAction, &deleteAction, &matchType); err != nil {
			return fmt.Errorf("%w: scan constraints for %s: %v", ErrSchemaShapeMismatch, table, err)
		}
		contract, ok := expected[name]
		if !ok {
			return fmt.Errorf("%w: unexpected constraint %s.%s", ErrSchemaShapeMismatch, table, name)
		}
		if kind != contract.kind || deferrable != contract.deferrable || deferred != contract.initiallyDeferred ||
			!validated || noInherit || !local || inheritCount != 0 || !noParent ||
			!slices.Equal(splitCatalogList(keyList), contract.keyColumns) ||
			referencedTable != contract.referencedTable ||
			!slices.Equal(splitCatalogList(referencedList), contract.referencedColumns) ||
			indexName != contract.indexName ||
			normalizeCatalogDefinition(definition) != normalizeCatalogDefinition(contract.definition) {
			return fmt.Errorf("%w: exact constraint contract differs for %s.%s", ErrSchemaShapeMismatch, table, name)
		}
		if kind == "f" && (updateAction != "a" || deleteAction != "a" || matchType != "s") {
			return fmt.Errorf("%w: foreign-key action differs for %s.%s", ErrSchemaShapeMismatch, table, name)
		}
		seen[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%w: read constraints for %s: %v", ErrSchemaShapeMismatch, table, err)
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("%w: %s constraint count is %d, want %d", ErrSchemaShapeMismatch, table, len(seen), len(expected))
	}
	return nil
}

func splitCatalogList(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, string(rune(31)))
}

func normalizeCatalogDefinition(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func verifyTableMetadata(ctx context.Context, tx *sql.Tx, table string) error {
	var persistence, accessMethod, replicaIdentity string
	var defaultTablespace, defaultOptions bool
	var rowSecurity, forceRowSecurity, hasIdentity, hasGenerated, hasColumnACL, hasUserRules bool
	if err := tx.QueryRowContext(ctx, `
		SELECT c.relpersistence::text, am.amname, c.relreplident::text,
		       c.reltablespace = 0, c.reloptions IS NULL,
		       c.relrowsecurity, c.relforcerowsecurity,
		       EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a
		                WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped AND a.attidentity <> ''),
		       EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a
		                WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped AND a.attgenerated <> ''),
		       EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a
		                WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped AND a.attacl IS NOT NULL),
		       EXISTS (SELECT 1 FROM pg_catalog.pg_rewrite r
		                WHERE r.ev_class = c.oid AND r.rulename <> '_RETURN')
		FROM pg_catalog.pg_class c
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_catalog.pg_am am ON am.oid = c.relam
		WHERE n.nspname = 'cph_aiinfra' AND c.relname = $1 AND c.relkind = 'r'`, table,
	).Scan(&persistence, &accessMethod, &replicaIdentity, &defaultTablespace, &defaultOptions,
		&rowSecurity, &forceRowSecurity, &hasIdentity, &hasGenerated, &hasColumnACL, &hasUserRules); err != nil {
		return fmt.Errorf("%w: inspect table metadata for %s: %v", ErrSchemaShapeMismatch, table, err)
	}
	if persistence != "p" || accessMethod != "heap" || replicaIdentity != "d" || !defaultTablespace || !defaultOptions ||
		rowSecurity || forceRowSecurity || hasIdentity || hasGenerated || hasColumnACL || hasUserRules {
		return fmt.Errorf("%w: unsafe table metadata for %s", ErrSchemaShapeMismatch, table)
	}
	return nil
}

func verifyOutboxCollation(ctx context.Context, tx *sql.Tx) error {
	serverVersion, err := postgresServerVersion(ctx, tx)
	if err != nil {
		return err
	}
	providerLocale := "''::text"
	providerDetails := "true"
	if serverVersion >= 150000 && serverVersion < 170000 {
		providerLocale = "COALESCE(coll.colliculocale, '')"
	}
	if serverVersion >= 160000 && serverVersion < 170000 {
		providerDetails = "coll.colliculocale IS NULL AND coll.collicurules IS NULL"
	}
	if serverVersion >= 170000 {
		providerLocale = "COALESCE(coll.colllocale, '')"
		providerDetails = "coll.colllocale IS NULL AND coll.collicurules IS NULL"
	}
	query := fmt.Sprintf(`
		SELECT a.attname, coll.oid::bigint, ncoll.nspname, coll.collname,
		       coll.collprovider::text, coll.collisdeterministic, coll.collencoding,
		       coll.collcollate, coll.collctype, %s, %s,
		       COALESCE(coll.collversion, '')
		FROM pg_catalog.pg_attribute a
		JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_catalog.pg_collation coll ON coll.oid = a.attcollation
		JOIN pg_catalog.pg_namespace ncoll ON ncoll.oid = coll.collnamespace
		WHERE n.nspname = 'cph_aiinfra' AND c.relname = 'ccse_outbox_intent'
		  AND a.attname IN ('destination', 'deduplication_key')
		ORDER BY a.attname`, providerLocale, providerDetails)
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("%w: inspect outbox collation: %v", ErrSchemaShapeMismatch, err)
	}
	defer rows.Close()
	seen := 0
	var expectedOID int64
	for rows.Next() {
		var column, namespace, collation, provider, locale, ctype, icuLocale, version string
		var oid, encoding int64
		var deterministic, providerDetailsExact bool
		if err := rows.Scan(&column, &oid, &namespace, &collation, &provider,
			&deterministic, &encoding, &locale, &ctype, &icuLocale, &providerDetailsExact, &version); err != nil {
			return fmt.Errorf("%w: scan outbox collation: %v", ErrSchemaShapeMismatch, err)
		}
		if (column != "deduplication_key" && column != "destination") ||
			namespace != "pg_catalog" || collation != "C" || provider != "c" ||
			!deterministic || encoding != -1 || locale != "C" || ctype != "C" ||
			icuLocale != "" || !providerDetailsExact || version != "" {
			return fmt.Errorf("%w: outbox collation differs for %s", ErrSchemaShapeMismatch, column)
		}
		if seen == 0 {
			expectedOID = oid
		} else if oid != expectedOID {
			return fmt.Errorf("%w: outbox deduplication columns use different collations", ErrSchemaShapeMismatch)
		}
		seen++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%w: read outbox collation: %v", ErrSchemaShapeMismatch, err)
	}
	if seen != 2 {
		return fmt.Errorf("%w: outbox collation column count is %d, want 2", ErrSchemaShapeMismatch, seen)
	}
	return nil
}

func verifyFunctionContract(ctx context.Context, tx *sql.Tx) error {
	expected, err := migrationFunctionBodies()
	if err != nil {
		return fmt.Errorf("%w: derive function contract: %v", ErrSchemaShapeMismatch, err)
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT p.proname, l.lanname, p.prosecdef, p.provolatile::text,
		       COALESCE(array_to_string(p.proconfig, ','), ''),
		       pg_get_function_identity_arguments(p.oid), pg_get_function_result(p.oid), p.prosrc,
		       p.prokind::text, p.proisstrict, p.proretset, p.proleakproof,
		       p.proparallel::text, p.pronargs, p.pronargdefaults, p.provariadic = 0,
		       p.procost, p.prorows, p.prosupport = 0
		FROM pg_catalog.pg_proc p
		JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
		JOIN pg_catalog.pg_language l ON l.oid = p.prolang
		WHERE n.nspname = 'cph_aiinfra'
		ORDER BY p.proname`)
	if err != nil {
		return fmt.Errorf("%w: inspect functions: %v", ErrSchemaShapeMismatch, err)
	}
	defer rows.Close()
	seen := make(map[string]struct{}, len(expected))
	for rows.Next() {
		var name, language, volatility, configuration, arguments, result, body, kind, parallel string
		var securityDefiner, strict, returnsSet, leakproof, noVariadic, noSupport bool
		var argumentCount, defaultCount int64
		var cost, resultRows float64
		if err := rows.Scan(&name, &language, &securityDefiner, &volatility, &configuration,
			&arguments, &result, &body, &kind, &strict, &returnsSet, &leakproof,
			&parallel, &argumentCount, &defaultCount, &noVariadic, &cost, &resultRows, &noSupport); err != nil {
			return fmt.Errorf("%w: scan functions: %v", ErrSchemaShapeMismatch, err)
		}
		expectedBody, ok := expected[name]
		if !ok || language != "plpgsql" || securityDefiner || volatility != "v" ||
			configuration != "search_path=pg_catalog" || arguments != "" || result != "trigger" ||
			strings.TrimSpace(body) != strings.TrimSpace(expectedBody) || kind != "f" || strict ||
			returnsSet || leakproof || parallel != "u" || argumentCount != 0 || defaultCount != 0 ||
			!noVariadic || cost != 100 || resultRows != 0 || !noSupport {
			return fmt.Errorf("%w: function contract differs for %s", ErrSchemaShapeMismatch, name)
		}
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("%w: overloaded/duplicate function %s", ErrSchemaShapeMismatch, name)
		}
		seen[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%w: read functions: %v", ErrSchemaShapeMismatch, err)
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("%w: function count is %d, want %d", ErrSchemaShapeMismatch, len(seen), len(expected))
	}
	return nil
}

func migrationFunctionBodies() (map[string]string, error) {
	contents, err := migrationFiles.ReadFile("migrations/0001_ccse_replay.sql")
	if err != nil {
		return nil, err
	}
	statements, err := splitSQLStatements(string(contents))
	if err != nil {
		return nil, err
	}
	const prefix = "CREATE FUNCTION cph_aiinfra."
	const delimiter = "$cph$"
	bodies := make(map[string]string)
	for _, statement := range statements {
		functionAt := strings.Index(statement, prefix)
		if functionAt < 0 {
			continue
		}
		nameAt := functionAt + len(prefix)
		nameEnd := strings.Index(statement[nameAt:], "()")
		if nameEnd < 1 {
			return nil, fmt.Errorf("malformed function name")
		}
		name := statement[nameAt : nameAt+nameEnd]
		bodyAt := strings.Index(statement[nameAt+nameEnd:], "AS "+delimiter)
		bodyEnd := strings.LastIndex(statement, delimiter)
		if bodyAt < 0 || bodyEnd < 0 {
			return nil, fmt.Errorf("malformed body for %s", name)
		}
		bodyAt += nameAt + nameEnd + len("AS "+delimiter)
		if bodyAt > bodyEnd {
			return nil, fmt.Errorf("malformed body bounds for %s", name)
		}
		bodies[name] = statement[bodyAt:bodyEnd]
	}
	if len(bodies) == 0 {
		return nil, fmt.Errorf("migration contains no functions")
	}
	return bodies, nil
}

func verifyMigrationAuthority(ctx context.Context, tx *sql.Tx) error {
	var ownsSchema, ownsLedger bool
	if err := tx.QueryRowContext(ctx, `
		SELECT pg_has_role(r.oid, n.nspowner, 'MEMBER'),
		       pg_has_role(r.oid, c.relowner, 'MEMBER')
		FROM pg_catalog.pg_namespace n
		JOIN pg_catalog.pg_class c ON c.relnamespace = n.oid AND c.relname = 'schema_migration'
		JOIN pg_catalog.pg_roles r ON r.rolname = current_user
		WHERE n.nspname = 'cph_aiinfra'`,
	).Scan(&ownsSchema, &ownsLedger); err != nil {
		return fmt.Errorf("%w: inspect migration ownership: %v", ErrUnsafeMigrationRole, err)
	}
	if !ownsSchema || !ownsLedger {
		return fmt.Errorf("%w: owns_schema=%t owns_ledger=%t", ErrUnsafeMigrationRole, ownsSchema, ownsLedger)
	}
	return nil
}

func verifyOwnershipAndPublicACL(ctx context.Context, tx *sql.Tx) error {
	var foreignTableOwner, foreignFunctionOwner bool
	var publicSchemaACL, delegatedSchemaCreate, publicTableACL, publicFunctionACL bool
	if err := tx.QueryRowContext(ctx, `
		SELECT
		  EXISTS (
		    SELECT 1 FROM pg_catalog.pg_class c
		    WHERE c.relnamespace = n.oid
		      AND c.relname IN ('schema_migration', 'ccse_replay_head', 'ccse_durable_result',
		                        'ccse_replay_inbox', 'ccse_outbox_intent')
		      AND c.relowner <> n.nspowner
		  ),
		  EXISTS (
		    SELECT 1 FROM pg_catalog.pg_proc p
		    WHERE p.pronamespace = n.oid AND p.proowner <> n.nspowner
		  ),
		  EXISTS (
		    SELECT 1 FROM pg_catalog.aclexplode(COALESCE(n.nspacl, pg_catalog.acldefault('n', n.nspowner))) acl
		    WHERE acl.grantee = 0
		  ),
		  EXISTS (
		    SELECT 1 FROM pg_catalog.aclexplode(COALESCE(n.nspacl, pg_catalog.acldefault('n', n.nspowner))) acl
		    WHERE acl.privilege_type = 'CREATE' AND acl.grantee <> n.nspowner
		  ),
		  EXISTS (
		    SELECT 1
		    FROM pg_catalog.pg_class c,
		         LATERAL pg_catalog.aclexplode(COALESCE(c.relacl, pg_catalog.acldefault('r', c.relowner))) acl
		    WHERE c.relnamespace = n.oid
		      AND c.relname IN ('schema_migration', 'ccse_replay_head', 'ccse_durable_result',
		                        'ccse_replay_inbox', 'ccse_outbox_intent')
		      AND acl.grantee = 0
		  ),
		  EXISTS (
		    SELECT 1
		    FROM pg_catalog.pg_proc p,
		         LATERAL pg_catalog.aclexplode(COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))) acl
		    WHERE p.pronamespace = n.oid AND acl.grantee = 0
		  )
		FROM pg_catalog.pg_namespace n
		WHERE n.nspname = 'cph_aiinfra'`,
	).Scan(&foreignTableOwner, &foreignFunctionOwner, &publicSchemaACL, &delegatedSchemaCreate, &publicTableACL, &publicFunctionACL); err != nil {
		return fmt.Errorf("%w: inspect ownership/ACL contract: %v", ErrSchemaShapeMismatch, err)
	}
	if foreignTableOwner || foreignFunctionOwner || publicSchemaACL || delegatedSchemaCreate || publicTableACL || publicFunctionACL {
		return fmt.Errorf("%w: ownership or PUBLIC/schema-CREATE ACL drift", ErrSchemaShapeMismatch)
	}
	return nil
}

func verifyTriggerContract(ctx context.Context, tx *sql.Tx) error {
	expected := map[string]triggerContract{
		"schema_migration.schema_migration_immutable": {
			functionSchema: "cph_aiinfra", functionName: "reject_immutable_change", typeMask: 27,
			definition: "CREATE TRIGGER schema_migration_immutable BEFORE DELETE OR UPDATE ON cph_aiinfra.schema_migration FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.reject_immutable_change()",
		},
		"ccse_replay_head.ccse_replay_head_monotonic": {
			functionSchema: "cph_aiinfra", functionName: "enforce_replay_head_monotonic", typeMask: 19,
			definition: "CREATE TRIGGER ccse_replay_head_monotonic BEFORE UPDATE ON cph_aiinfra.ccse_replay_head FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.enforce_replay_head_monotonic()",
		},
		"ccse_replay_head.ccse_replay_head_initial": {
			functionSchema: "cph_aiinfra", functionName: "enforce_replay_head_monotonic", typeMask: 7,
			definition: "CREATE TRIGGER ccse_replay_head_initial BEFORE INSERT ON cph_aiinfra.ccse_replay_head FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.enforce_replay_head_monotonic()",
		},
		"ccse_replay_inbox.ccse_replay_inbox_immutable": {
			functionSchema: "cph_aiinfra", functionName: "reject_immutable_change", typeMask: 27,
			definition: "CREATE TRIGGER ccse_replay_inbox_immutable BEFORE DELETE OR UPDATE ON cph_aiinfra.ccse_replay_inbox FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.reject_immutable_change()",
		},
		"ccse_replay_inbox.ccse_replay_inbox_transaction": {
			functionSchema: "cph_aiinfra", functionName: "stamp_unit_of_work_transaction", typeMask: 7,
			definition: "CREATE TRIGGER ccse_replay_inbox_transaction BEFORE INSERT ON cph_aiinfra.ccse_replay_inbox FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.stamp_unit_of_work_transaction()",
		},
		"ccse_replay_inbox.ccse_replay_inbox_coupling": {
			functionSchema: "cph_aiinfra", functionName: "assert_completion_coupling", typeMask: 5,
			deferrable: true, initiallyDeferred: true, constraintName: "ccse_replay_inbox_coupling",
			definition: "CREATE CONSTRAINT TRIGGER ccse_replay_inbox_coupling AFTER INSERT ON cph_aiinfra.ccse_replay_inbox DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_completion_coupling()",
		},
		"ccse_durable_result.ccse_durable_result_transaction": {
			functionSchema: "cph_aiinfra", functionName: "stamp_unit_of_work_transaction", typeMask: 7,
			definition: "CREATE TRIGGER ccse_durable_result_transaction BEFORE INSERT ON cph_aiinfra.ccse_durable_result FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.stamp_unit_of_work_transaction()",
		},
		"ccse_durable_result.ccse_durable_result_immutable": {
			functionSchema: "cph_aiinfra", functionName: "reject_immutable_change", typeMask: 27,
			definition: "CREATE TRIGGER ccse_durable_result_immutable BEFORE DELETE OR UPDATE ON cph_aiinfra.ccse_durable_result FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.reject_immutable_change()",
		},
		"ccse_durable_result.ccse_durable_result_coupling": {
			functionSchema: "cph_aiinfra", functionName: "assert_completion_coupling", typeMask: 5,
			deferrable: true, initiallyDeferred: true, constraintName: "ccse_durable_result_coupling",
			definition: "CREATE CONSTRAINT TRIGGER ccse_durable_result_coupling AFTER INSERT ON cph_aiinfra.ccse_durable_result DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_completion_coupling()",
		},
		"ccse_outbox_intent.ccse_outbox_intent_transaction": {
			functionSchema: "cph_aiinfra", functionName: "stamp_unit_of_work_transaction", typeMask: 7,
			definition: "CREATE TRIGGER ccse_outbox_intent_transaction BEFORE INSERT ON cph_aiinfra.ccse_outbox_intent FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.stamp_unit_of_work_transaction()",
		},
		"ccse_outbox_intent.ccse_outbox_intent_immutable": {
			functionSchema: "cph_aiinfra", functionName: "reject_immutable_change", typeMask: 27,
			definition: "CREATE TRIGGER ccse_outbox_intent_immutable BEFORE DELETE OR UPDATE ON cph_aiinfra.ccse_outbox_intent FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.reject_immutable_change()",
		},
		"ccse_outbox_intent.ccse_outbox_intent_coupling": {
			functionSchema: "cph_aiinfra", functionName: "assert_completion_coupling", typeMask: 5,
			deferrable: true, initiallyDeferred: true, constraintName: "ccse_outbox_intent_coupling",
			definition: "CREATE CONSTRAINT TRIGGER ccse_outbox_intent_coupling AFTER INSERT ON cph_aiinfra.ccse_outbox_intent DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_completion_coupling()",
		},
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT c.relname, t.tgname, pn.nspname, p.proname,
		       pg_get_function_identity_arguments(p.oid), t.tgtype::bigint,
		       t.tgenabled::text, t.tgqual IS NULL, t.tgnargs,
		       octet_length(t.tgargs) = 0, t.tgattr::text = '',
		       t.tgoldtable IS NULL, t.tgnewtable IS NULL, t.tgparentid = 0,
		       t.tgdeferrable, t.tginitdeferred, pg_get_triggerdef(t.oid, false),
		       COALESCE(con.conname, ''), COALESCE(con.contype::text, ''),
		       COALESCE(con.condeferrable, false), COALESCE(con.condeferred, false),
		       COALESCE(con.convalidated, false),
		       t.tgconstrrelid = 0, t.tgconstrindid = 0
		FROM pg_catalog.pg_trigger t
		JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_catalog.pg_proc p ON p.oid = t.tgfoid
		JOIN pg_catalog.pg_namespace pn ON pn.oid = p.pronamespace
		LEFT JOIN pg_catalog.pg_constraint con ON con.oid = t.tgconstraint
		WHERE n.nspname = 'cph_aiinfra' AND NOT t.tgisinternal
		ORDER BY c.relname, t.tgname`)
	if err != nil {
		return fmt.Errorf("%w: inspect triggers: %v", ErrSchemaShapeMismatch, err)
	}
	defer rows.Close()
	seen := make(map[string]struct{}, len(expected))
	for rows.Next() {
		var table, trigger, functionSchema, functionName, arguments, enabled, definition string
		var constraintName, constraintKind string
		var typeMask, argumentCount int64
		var qualNull, argumentsEmpty, attributesEmpty, oldTableNull, newTableNull, noParent bool
		var deferrable, initiallyDeferred, constraintDeferrable, constraintDeferred bool
		var constraintValidated, noConstraintRelation, noConstraintIndex bool
		if err := rows.Scan(&table, &trigger, &functionSchema, &functionName, &arguments,
			&typeMask, &enabled, &qualNull, &argumentCount, &argumentsEmpty, &attributesEmpty,
			&oldTableNull, &newTableNull, &noParent, &deferrable, &initiallyDeferred, &definition,
			&constraintName, &constraintKind, &constraintDeferrable, &constraintDeferred,
			&constraintValidated, &noConstraintRelation, &noConstraintIndex); err != nil {
			return fmt.Errorf("%w: scan triggers: %v", ErrSchemaShapeMismatch, err)
		}
		key := table + "." + trigger
		contract, ok := expected[key]
		if !ok || contract.functionSchema != functionSchema || contract.functionName != functionName ||
			arguments != "" || contract.typeMask != typeMask || enabled != "O" || !qualNull ||
			argumentCount != 0 || !argumentsEmpty || !attributesEmpty || !oldTableNull || !newTableNull || !noParent ||
			contract.deferrable != deferrable || contract.initiallyDeferred != initiallyDeferred ||
			normalizeCatalogDefinition(definition) != normalizeCatalogDefinition(contract.definition) ||
			constraintName != contract.constraintName || !noConstraintRelation || !noConstraintIndex {
			return fmt.Errorf("%w: unexpected or disabled trigger %s", ErrSchemaShapeMismatch, key)
		}
		if contract.constraintName == "" {
			if constraintKind != "" || constraintDeferrable || constraintDeferred || constraintValidated {
				return fmt.Errorf("%w: ordinary trigger %s has a constraint identity", ErrSchemaShapeMismatch, key)
			}
		} else if constraintKind != "t" || constraintDeferrable != contract.deferrable ||
			constraintDeferred != contract.initiallyDeferred || !constraintValidated {
			return fmt.Errorf("%w: constraint-trigger identity differs for %s", ErrSchemaShapeMismatch, key)
		}
		seen[key] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%w: read triggers: %v", ErrSchemaShapeMismatch, err)
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("%w: trigger count is %d, want %d", ErrSchemaShapeMismatch, len(seen), len(expected))
	}
	return nil
}

func verifyIndexContract(ctx context.Context, tx *sql.Tx) error {
	expected := map[string]indexContract{
		"schema_migration_pk": {
			table: "schema_migration", unique: true, primary: true, constraint: "schema_migration_pk",
			keyColumns: []string{"version"}, opclasses: []string{"pg_catalog.int8_ops"}, collations: []string{"-"},
			definition: "CREATE UNIQUE INDEX schema_migration_pk ON cph_aiinfra.schema_migration USING btree (version)",
		},
		"ccse_replay_head_pk": {
			table: "ccse_replay_head", unique: true, primary: true, constraint: "ccse_replay_head_pk",
			keyColumns: []string{"scope_sha256"}, opclasses: []string{"pg_catalog.bytea_ops"}, collations: []string{"-"},
			definition: "CREATE UNIQUE INDEX ccse_replay_head_pk ON cph_aiinfra.ccse_replay_head USING btree (scope_sha256)",
		},
		"ccse_durable_result_pk": {
			table: "ccse_durable_result", unique: true, primary: true, constraint: "ccse_durable_result_pk",
			keyColumns: []string{"scope_sha256", "message_id"}, opclasses: []string{"pg_catalog.bytea_ops", "pg_catalog.bytea_ops"}, collations: []string{"-", "-"},
			definition: "CREATE UNIQUE INDEX ccse_durable_result_pk ON cph_aiinfra.ccse_durable_result USING btree (scope_sha256, message_id)",
		},
		"ccse_durable_result_digest_key": {
			table: "ccse_durable_result", unique: true, constraint: "ccse_durable_result_digest_key",
			keyColumns: []string{"scope_sha256", "message_id", "result_digest"}, opclasses: []string{"pg_catalog.bytea_ops", "pg_catalog.bytea_ops", "pg_catalog.bytea_ops"}, collations: []string{"-", "-", "-"},
			definition: "CREATE UNIQUE INDEX ccse_durable_result_digest_key ON cph_aiinfra.ccse_durable_result USING btree (scope_sha256, message_id, result_digest)",
		},
		"ccse_replay_inbox_pk": {
			table: "ccse_replay_inbox", unique: true, primary: true, constraint: "ccse_replay_inbox_pk",
			keyColumns: []string{"scope_sha256", "message_id"}, opclasses: []string{"pg_catalog.bytea_ops", "pg_catalog.bytea_ops"}, collations: []string{"-", "-"},
			definition: "CREATE UNIQUE INDEX ccse_replay_inbox_pk ON cph_aiinfra.ccse_replay_inbox USING btree (scope_sha256, message_id)",
		},
		"ccse_replay_inbox_committed_at_idx": {
			table: "ccse_replay_inbox", keyColumns: []string{"committed_at"},
			opclasses: []string{"pg_catalog.timestamptz_ops"}, collations: []string{"-"},
			definition: "CREATE INDEX ccse_replay_inbox_committed_at_idx ON cph_aiinfra.ccse_replay_inbox USING btree (committed_at)",
		},
		"ccse_outbox_intent_pk": {
			table: "ccse_outbox_intent", unique: true, primary: true, constraint: "ccse_outbox_intent_pk",
			keyColumns: []string{"event_id"}, opclasses: []string{"pg_catalog.bytea_ops"}, collations: []string{"-"},
			definition: "CREATE UNIQUE INDEX ccse_outbox_intent_pk ON cph_aiinfra.ccse_outbox_intent USING btree (event_id)",
		},
		"ccse_outbox_intent_dedup_key": {
			table: "ccse_outbox_intent", unique: true, constraint: "ccse_outbox_intent_dedup_key",
			keyColumns: []string{"destination", "deduplication_key"}, opclasses: []string{"pg_catalog.text_ops", "pg_catalog.text_ops"}, collations: []string{"pg_catalog.C", "pg_catalog.C"},
			definition: "CREATE UNIQUE INDEX ccse_outbox_intent_dedup_key ON cph_aiinfra.ccse_outbox_intent USING btree (destination, deduplication_key)",
		},
		"ccse_outbox_intent_created_at_idx": {
			table: "ccse_outbox_intent", keyColumns: []string{"created_at"},
			opclasses: []string{"pg_catalog.timestamptz_ops"}, collations: []string{"-"},
			definition: "CREATE INDEX ccse_outbox_intent_created_at_idx ON cph_aiinfra.ccse_outbox_intent USING btree (created_at)",
		},
	}
	serverVersion, err := postgresServerVersion(ctx, tx)
	if err != nil {
		return err
	}
	nullsNotDistinct := "false"
	if serverVersion >= 150000 {
		nullsNotDistinct = "x.indnullsnotdistinct"
	}
	query := fmt.Sprintf(`
		SELECT i.relname, t.relname, am.amname, i.relkind::text, i.relpersistence::text,
		       i.relowner = t.relowner, x.indisunique, x.indisprimary, x.indisexclusion,
		       x.indimmediate, x.indisvalid, x.indisready, x.indislive,
		       x.indisclustered, x.indisreplident, x.indcheckxmin, %s,
		       x.indnkeyatts, x.indnatts,
		       COALESCE(array_to_string(ARRAY(
		         SELECT a.attname
		           FROM unnest(x.indkey::smallint[]) WITH ORDINALITY AS key(attnum, ordinal)
		           JOIN pg_catalog.pg_attribute a
		             ON a.attrelid = x.indrelid AND a.attnum = key.attnum
		          WHERE key.ordinal <= x.indnkeyatts ORDER BY key.ordinal
		       ), chr(31)), ''),
		       COALESCE(array_to_string(ARRAY(
		         SELECT a.attname
		           FROM unnest(x.indkey::smallint[]) WITH ORDINALITY AS key(attnum, ordinal)
		           JOIN pg_catalog.pg_attribute a
		             ON a.attrelid = x.indrelid AND a.attnum = key.attnum
		          WHERE key.ordinal > x.indnkeyatts ORDER BY key.ordinal
		       ), chr(31)), ''),
		       COALESCE(array_to_string(ARRAY(
		         SELECT opn.nspname || '.' || op.opcname
		           FROM unnest(x.indclass::oid[]) WITH ORDINALITY AS item(opcoid, ordinal)
		           JOIN pg_catalog.pg_opclass op ON op.oid = item.opcoid
		           JOIN pg_catalog.pg_namespace opn ON opn.oid = op.opcnamespace
		          ORDER BY item.ordinal
		       ), chr(31)), ''),
		       COALESCE(array_to_string(ARRAY(
		         SELECT CASE WHEN item.colloid = 0 THEN '-'
		                     ELSE colln.nspname || '.' || coll.collname END
		           FROM unnest(x.indcollation::oid[]) WITH ORDINALITY AS item(colloid, ordinal)
		           LEFT JOIN pg_catalog.pg_collation coll ON coll.oid = item.colloid
		           LEFT JOIN pg_catalog.pg_namespace colln ON colln.oid = coll.collnamespace
		          ORDER BY item.ordinal
		       ), chr(31)), ''),
		       COALESCE(array_to_string(x.indoption::smallint[], chr(31)), ''),
		       COALESCE(pg_get_expr(x.indexprs, x.indrelid, false), ''),
		       COALESCE(pg_get_expr(x.indpred, x.indrelid, false), ''),
		       pg_get_indexdef(x.indexrelid, 0, false), COALESCE(con.conname, '')
		FROM pg_catalog.pg_index x
		JOIN pg_catalog.pg_class i ON i.oid = x.indexrelid
		JOIN pg_catalog.pg_class t ON t.oid = x.indrelid
		JOIN pg_catalog.pg_namespace n ON n.oid = t.relnamespace
		JOIN pg_catalog.pg_am am ON am.oid = i.relam
		LEFT JOIN pg_catalog.pg_constraint con
		  ON con.conindid = x.indexrelid AND con.contype IN ('p', 'u', 'x')
		WHERE n.nspname = 'cph_aiinfra'
		ORDER BY i.relname`, nullsNotDistinct)
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("%w: inspect indexes: %v", ErrSchemaShapeMismatch, err)
	}
	defer rows.Close()
	seen := make(map[string]struct{}, len(expected))
	for rows.Next() {
		var name, table, accessMethod, relationKind, persistence string
		var keyList, includeList, opclassList, collationList, optionList string
		var expressions, predicate, definition, constraint string
		var sameOwner, unique, primary, exclusion, immediate, valid, ready, live bool
		var clustered, replicaIdentity, checkXmin, nullsNotDistinctValue bool
		var keyCount, attributeCount int64
		if err := rows.Scan(&name, &table, &accessMethod, &relationKind, &persistence,
			&sameOwner, &unique, &primary, &exclusion, &immediate, &valid, &ready, &live,
			&clustered, &replicaIdentity, &checkXmin, &nullsNotDistinctValue,
			&keyCount, &attributeCount, &keyList, &includeList, &opclassList,
			&collationList, &optionList, &expressions, &predicate, &definition, &constraint); err != nil {
			return fmt.Errorf("%w: scan indexes: %v", ErrSchemaShapeMismatch, err)
		}
		contract, ok := expected[name]
		if !ok {
			return fmt.Errorf("%w: unexpected index %s", ErrSchemaShapeMismatch, name)
		}
		options := splitCatalogList(optionList)
		for _, option := range options {
			if option != "0" {
				return fmt.Errorf("%w: index %s has non-default ordering/nulls options", ErrSchemaShapeMismatch, name)
			}
		}
		if table != contract.table || accessMethod != "btree" || relationKind != "i" || persistence != "p" ||
			!sameOwner || unique != contract.unique || primary != contract.primary || exclusion || !immediate ||
			!valid || !ready || !live || clustered || replicaIdentity || checkXmin || nullsNotDistinctValue ||
			keyCount != int64(len(contract.keyColumns)) || attributeCount != keyCount || includeList != "" ||
			!slices.Equal(splitCatalogList(keyList), contract.keyColumns) ||
			!slices.Equal(splitCatalogList(opclassList), contract.opclasses) ||
			!slices.Equal(splitCatalogList(collationList), contract.collations) ||
			len(options) != len(contract.keyColumns) || expressions != "" || predicate != "" ||
			constraint != contract.constraint ||
			normalizeCatalogDefinition(definition) != normalizeCatalogDefinition(contract.definition) {
			return fmt.Errorf("%w: exact index contract differs for %s", ErrSchemaShapeMismatch, name)
		}
		seen[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%w: read indexes: %v", ErrSchemaShapeMismatch, err)
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("%w: index count is %d, want %d", ErrSchemaShapeMismatch, len(seen), len(expected))
	}
	return nil
}

func verifyRuntimeRole(ctx context.Context, tx *sql.Tx) error {
	var superuser, createRole, createDB, replication, bypassRLS bool
	var dangerousMembership, ownsSchema, schemaUsage, schemaCreate bool
	if err := tx.QueryRowContext(ctx, `
		SELECT r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication, r.rolbypassrls,
		       EXISTS (
		         SELECT 1 FROM pg_catalog.pg_roles delegated
		         WHERE (
		           delegated.rolsuper OR delegated.rolcreaterole OR delegated.rolcreatedb OR
		           delegated.rolreplication OR delegated.rolbypassrls OR
		           delegated.rolname IN (
		             'pg_read_all_data', 'pg_write_all_data', 'pg_read_server_files',
		             'pg_write_server_files', 'pg_execute_server_program', 'pg_signal_backend',
		             'pg_checkpoint', 'pg_maintain', 'pg_create_subscription', 'pg_database_owner',
		             'pg_monitor', 'pg_read_all_settings', 'pg_read_all_stats',
		             'pg_stat_scan_tables', 'pg_use_reserved_connections'
		           )
		         ) AND pg_has_role(r.oid, delegated.oid, 'MEMBER')
		       ),
		       pg_has_role(r.oid, n.nspowner, 'MEMBER'),
		       has_schema_privilege(current_user, 'cph_aiinfra', 'USAGE'),
		       has_schema_privilege(current_user, 'cph_aiinfra', 'CREATE')
		FROM pg_catalog.pg_roles r
		JOIN pg_catalog.pg_namespace n ON n.nspname = 'cph_aiinfra'
		WHERE r.rolname = current_user`,
	).Scan(&superuser, &createRole, &createDB, &replication, &bypassRLS, &dangerousMembership, &ownsSchema, &schemaUsage, &schemaCreate); err != nil {
		return fmt.Errorf("%w: inspect runtime role: %v", ErrUnsafeRuntimeRole, err)
	}
	if superuser || createRole || createDB || replication || bypassRLS || dangerousMembership || ownsSchema || !schemaUsage || schemaCreate {
		return fmt.Errorf("%w: privileged role flags or schema ownership differ", ErrUnsafeRuntimeRole)
	}
	serverVersion, err := postgresServerVersion(ctx, tx)
	if err != nil {
		return err
	}
	if serverVersion >= 150000 {
		var currentCanSet, memberCanSet bool
		if err := tx.QueryRowContext(ctx, `
			SELECT pg_catalog.has_parameter_privilege(current_user, 'session_replication_role', 'SET') OR
			       pg_catalog.has_parameter_privilege(current_user, 'session_replication_role', 'ALTER SYSTEM'),
			       EXISTS (
			         SELECT 1 FROM pg_catalog.pg_roles current_role
			         JOIN pg_catalog.pg_roles delegated
			           ON delegated.oid <> current_role.oid
			          AND pg_catalog.pg_has_role(current_role.oid, delegated.oid, 'MEMBER')
			         WHERE current_role.rolname = current_user
			           AND (
			             pg_catalog.has_parameter_privilege(delegated.oid, 'session_replication_role', 'SET') OR
			             pg_catalog.has_parameter_privilege(delegated.oid, 'session_replication_role', 'ALTER SYSTEM')
			           )
			       )`,
		).Scan(&currentCanSet, &memberCanSet); err != nil {
			return fmt.Errorf("%w: inspect parameter ACL: %v", ErrUnsafeRuntimeRole, err)
		}
		if currentCanSet || memberCanSet {
			return fmt.Errorf("%w: role has session_replication_role parameter ACL", ErrUnsafeRuntimeRole)
		}
	}

	tables := make([]string, 0, len(replayColumnContract))
	for table := range replayColumnContract {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	for _, table := range tables {
		var ownsTable, selectPrivilege, insertPrivilege, updatePrivilege bool
		var deletePrivilege, truncatePrivilege, referencesPrivilege, triggerPrivilege bool
		qualified := "cph_aiinfra." + table
		if err := tx.QueryRowContext(ctx, `
			SELECT pg_has_role(r.oid, c.relowner, 'MEMBER'),
			       has_table_privilege(current_user, $1, 'SELECT'),
			       has_table_privilege(current_user, $1, 'INSERT'),
			       has_table_privilege(current_user, $1, 'UPDATE'),
			       has_table_privilege(current_user, $1, 'DELETE'),
			       has_table_privilege(current_user, $1, 'TRUNCATE'),
			       has_table_privilege(current_user, $1, 'REFERENCES'),
			       has_table_privilege(current_user, $1, 'TRIGGER')
			FROM pg_catalog.pg_class c
			JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			JOIN pg_catalog.pg_roles r ON r.rolname = current_user
			WHERE n.nspname = 'cph_aiinfra' AND c.relname = $2`, qualified, table,
		).Scan(&ownsTable, &selectPrivilege, &insertPrivilege, &updatePrivilege,
			&deletePrivilege, &truncatePrivilege, &referencesPrivilege, &triggerPrivilege); err != nil {
			return fmt.Errorf("%w: inspect privileges for %s: %v", ErrUnsafeRuntimeRole, table, err)
		}
		wantInsert := table != "schema_migration"
		wantUpdate := table == "ccse_replay_head"
		if ownsTable || !selectPrivilege || insertPrivilege != wantInsert || updatePrivilege != wantUpdate ||
			deletePrivilege || truncatePrivilege || referencesPrivilege || triggerPrivilege {
			return fmt.Errorf("%w: table privilege contract differs for %s", ErrUnsafeRuntimeRole, table)
		}
	}
	for _, function := range []string{
		"assert_completion_coupling",
		"enforce_replay_head_monotonic",
		"reject_immutable_change",
		"stamp_unit_of_work_transaction",
	} {
		var executePrivilege bool
		if err := tx.QueryRowContext(ctx,
			"SELECT has_function_privilege(current_user, $1, 'EXECUTE')",
			"cph_aiinfra."+function+"()",
		).Scan(&executePrivilege); err != nil {
			return fmt.Errorf("%w: inspect function privilege for %s: %v", ErrUnsafeRuntimeRole, function, err)
		}
		if !executePrivilege {
			return fmt.Errorf("%w: missing trigger-function privilege for %s", ErrUnsafeRuntimeRole, function)
		}
	}
	return nil
}

func postgresServerVersion(ctx context.Context, tx *sql.Tx) (int64, error) {
	var version int64
	if err := tx.QueryRowContext(ctx,
		"SELECT pg_catalog.current_setting('server_version_num')::bigint",
	).Scan(&version); err != nil {
		return 0, fmt.Errorf("%w: inspect PostgreSQL version: %v", ErrSchemaShapeMismatch, err)
	}
	if version < 130000 {
		return 0, fmt.Errorf("%w: PostgreSQL %d is older than 13", ErrSchemaShapeMismatch, version)
	}
	return version, nil
}
