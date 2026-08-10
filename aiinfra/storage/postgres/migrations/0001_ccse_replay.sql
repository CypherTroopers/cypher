-- Migration 1 is applied only when cph_aiinfra.schema_migration has no row for
-- version 1. Operational objects intentionally omit IF NOT EXISTS: a partial or
-- look-alike schema must fail instead of being blessed by the migration hash.

REVOKE ALL ON SCHEMA cph_aiinfra FROM PUBLIC;

CREATE TABLE cph_aiinfra.ccse_replay_head (
    scope_sha256         BYTEA NOT NULL,
    counter_kind         SMALLINT NOT NULL,
    replay_domain_id     TEXT NOT NULL,
    sender_identity      TEXT NOT NULL,
    environment          TEXT NOT NULL,
    chain_id             BYTEA NOT NULL,
    genesis_hash         BYTEA NOT NULL,
    highest_sequence     BYTEA,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT ccse_replay_head_pk PRIMARY KEY (scope_sha256),
    CONSTRAINT ccse_replay_head_scope_length CHECK (octet_length(scope_sha256) = 32),
    CONSTRAINT ccse_replay_head_counter_kind CHECK (counter_kind IN (1, 2)),
    CONSTRAINT ccse_replay_head_domain_length CHECK (octet_length(replay_domain_id) BETWEEN 1 AND 65536),
    CONSTRAINT ccse_replay_head_sender_length CHECK (octet_length(sender_identity) BETWEEN 1 AND 65536),
    CONSTRAINT ccse_replay_head_environment_length CHECK (octet_length(environment) BETWEEN 1 AND 65536),
    CONSTRAINT ccse_replay_head_chain_length CHECK (octet_length(chain_id) = 32),
    CONSTRAINT ccse_replay_head_genesis_length CHECK (octet_length(genesis_hash) = 32),
    CONSTRAINT ccse_replay_head_sequence_length CHECK (highest_sequence IS NULL OR octet_length(highest_sequence) = 8)
);

CREATE TABLE cph_aiinfra.ccse_durable_result (
    scope_sha256         BYTEA NOT NULL,
    message_id           BYTEA NOT NULL,
    result_digest        BYTEA NOT NULL,
    content_type         TEXT NOT NULL,
    payload              BYTEA NOT NULL,
    external_effect_mode SMALLINT NOT NULL,
    transaction_id       XID8 NOT NULL,
    committed_at         TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT ccse_durable_result_pk PRIMARY KEY (scope_sha256, message_id),
    CONSTRAINT ccse_durable_result_digest_key UNIQUE (scope_sha256, message_id, result_digest),
    CONSTRAINT ccse_durable_result_scope_fk FOREIGN KEY (scope_sha256)
        REFERENCES cph_aiinfra.ccse_replay_head(scope_sha256),
    CONSTRAINT ccse_durable_result_message_length CHECK (octet_length(message_id) = 16),
    CONSTRAINT ccse_durable_result_digest_length CHECK (octet_length(result_digest) = 32),
    CONSTRAINT ccse_durable_result_content_type_length CHECK (octet_length(content_type) BETWEEN 1 AND 255),
    CONSTRAINT ccse_durable_result_payload_length CHECK (octet_length(payload) <= 1048576),
    CONSTRAINT ccse_durable_result_effect_mode CHECK (external_effect_mode IN (1, 2))
);

CREATE TABLE cph_aiinfra.ccse_replay_inbox (
    scope_sha256          BYTEA NOT NULL,
    message_id            BYTEA NOT NULL,
    counter_kind          SMALLINT NOT NULL,
    message_type_id       BIGINT NOT NULL,
    schema_major          BIGINT NOT NULL,
    schema_minor          BIGINT NOT NULL,
    record_digest         BYTEA NOT NULL,
    sequence              BYTEA NOT NULL,
    expires_at_unix_nano  BIGINT NOT NULL,
    outcome_digest        BYTEA NOT NULL,
    transaction_id        XID8 NOT NULL,
    committed_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT ccse_replay_inbox_pk PRIMARY KEY (scope_sha256, message_id),
    CONSTRAINT ccse_replay_inbox_scope_fk FOREIGN KEY (scope_sha256)
        REFERENCES cph_aiinfra.ccse_replay_head(scope_sha256),
    CONSTRAINT ccse_replay_inbox_result_fk FOREIGN KEY (scope_sha256, message_id, outcome_digest)
        REFERENCES cph_aiinfra.ccse_durable_result(scope_sha256, message_id, result_digest)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT ccse_replay_inbox_message_length CHECK (octet_length(message_id) = 16),
    CONSTRAINT ccse_replay_inbox_counter_kind CHECK (counter_kind IN (1, 2)),
    CONSTRAINT ccse_replay_inbox_type_range CHECK (message_type_id BETWEEN 1 AND 4294967295),
    CONSTRAINT ccse_replay_inbox_major_range CHECK (schema_major BETWEEN 1 AND 4294967295),
    CONSTRAINT ccse_replay_inbox_minor_range CHECK (schema_minor BETWEEN 0 AND 4294967295),
    CONSTRAINT ccse_replay_inbox_record_length CHECK (octet_length(record_digest) = 32),
    CONSTRAINT ccse_replay_inbox_sequence_length CHECK (octet_length(sequence) = 8),
    CONSTRAINT ccse_replay_inbox_expiry_positive CHECK (expires_at_unix_nano > 0),
    CONSTRAINT ccse_replay_inbox_outcome_length CHECK (octet_length(outcome_digest) = 32)
);

CREATE INDEX ccse_replay_inbox_committed_at_idx
    ON cph_aiinfra.ccse_replay_inbox (committed_at);

CREATE TABLE cph_aiinfra.ccse_outbox_intent (
    event_id              BYTEA NOT NULL,
    scope_sha256          BYTEA NOT NULL,
    message_id            BYTEA NOT NULL,
    destination           TEXT COLLATE "C" NOT NULL,
    deduplication_key     TEXT COLLATE "C" NOT NULL,
    content_type          TEXT NOT NULL,
    payload               BYTEA NOT NULL,
    payload_digest        BYTEA NOT NULL,
    transaction_id        XID8 NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT ccse_outbox_intent_pk PRIMARY KEY (event_id),
    CONSTRAINT ccse_outbox_intent_dedup_key UNIQUE (destination, deduplication_key),
    CONSTRAINT ccse_outbox_intent_result_fk FOREIGN KEY (scope_sha256, message_id)
        REFERENCES cph_aiinfra.ccse_durable_result(scope_sha256, message_id)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT ccse_outbox_intent_event_length CHECK (octet_length(event_id) = 16),
    CONSTRAINT ccse_outbox_intent_scope_length CHECK (octet_length(scope_sha256) = 32),
    CONSTRAINT ccse_outbox_intent_message_length CHECK (octet_length(message_id) = 16),
    CONSTRAINT ccse_outbox_intent_destination_length CHECK (octet_length(destination) BETWEEN 1 AND 255),
    CONSTRAINT ccse_outbox_intent_dedup_length CHECK (octet_length(deduplication_key) BETWEEN 1 AND 1024),
    CONSTRAINT ccse_outbox_intent_content_type_length CHECK (octet_length(content_type) BETWEEN 1 AND 255),
    CONSTRAINT ccse_outbox_intent_payload_length CHECK (octet_length(payload) <= 1048576),
    CONSTRAINT ccse_outbox_intent_payload_digest_length CHECK (octet_length(payload_digest) = 32)
);

CREATE INDEX ccse_outbox_intent_created_at_idx
    ON cph_aiinfra.ccse_outbox_intent (created_at);

CREATE FUNCTION cph_aiinfra.reject_immutable_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $cph$
BEGIN
    RAISE EXCEPTION 'immutable cph_aiinfra relation % cannot be changed', TG_TABLE_NAME
        USING ERRCODE = '55000';
END;
$cph$;

CREATE FUNCTION cph_aiinfra.enforce_replay_head_monotonic()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $cph$
DECLARE
    transaction_inbox_count BIGINT;
    matching_inbox_count BIGINT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.highest_sequence IS NOT NULL THEN
            RAISE EXCEPTION 'new replay scope must not preseed a sequence'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.scope_sha256 IS DISTINCT FROM OLD.scope_sha256
       OR NEW.counter_kind IS DISTINCT FROM OLD.counter_kind
       OR NEW.replay_domain_id IS DISTINCT FROM OLD.replay_domain_id
       OR NEW.sender_identity IS DISTINCT FROM OLD.sender_identity
       OR NEW.environment IS DISTINCT FROM OLD.environment
       OR NEW.chain_id IS DISTINCT FROM OLD.chain_id
       OR NEW.genesis_hash IS DISTINCT FROM OLD.genesis_hash THEN
        RAISE EXCEPTION 'replay scope identity is immutable' USING ERRCODE = '55000';
    END IF;
    IF NEW.highest_sequence IS NULL
       OR (OLD.highest_sequence IS NOT NULL AND NEW.highest_sequence <= OLD.highest_sequence) THEN
        RAISE EXCEPTION 'replay sequence must increase monotonically' USING ERRCODE = '23514';
    END IF;
    SELECT count(*),
           count(*) FILTER (
               WHERE counter_kind = NEW.counter_kind AND sequence = NEW.highest_sequence
           )
      INTO transaction_inbox_count, matching_inbox_count
      FROM cph_aiinfra.ccse_replay_inbox
     WHERE scope_sha256 = NEW.scope_sha256
       AND transaction_id = pg_current_xact_id();
    IF transaction_inbox_count <> 1 OR matching_inbox_count <> 1 THEN
        RAISE EXCEPTION 'replay head requires exactly one same-transaction inbox row for scope, counter kind and sequence'
            USING ERRCODE = '23514';
    END IF;
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END;
$cph$;

CREATE FUNCTION cph_aiinfra.stamp_unit_of_work_transaction()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $cph$
BEGIN
    NEW.transaction_id := pg_current_xact_id();
    RETURN NEW;
END;
$cph$;

CREATE FUNCTION cph_aiinfra.assert_completion_coupling()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $cph$
DECLARE
    effect_mode SMALLINT;
    intent_count BIGINT;
    durable_digest BYTEA;
    durable_transaction_id XID8;
BEGIN
    SELECT external_effect_mode, result_digest, transaction_id
      INTO effect_mode, durable_digest, durable_transaction_id
      FROM cph_aiinfra.ccse_durable_result
     WHERE scope_sha256 = NEW.scope_sha256 AND message_id = NEW.message_id;
    IF effect_mode IS NULL THEN
        RAISE EXCEPTION 'outbox intent has no durable result' USING ERRCODE = '23503';
    END IF;
    SELECT count(*) INTO intent_count
      FROM cph_aiinfra.ccse_outbox_intent
     WHERE scope_sha256 = NEW.scope_sha256 AND message_id = NEW.message_id;
    IF effect_mode = 1 AND intent_count <> 0 THEN
        RAISE EXCEPTION 'no-effect completion has outbox intents' USING ERRCODE = '23514';
    END IF;
    IF effect_mode = 2 AND intent_count = 0 THEN
        RAISE EXCEPTION 'outbox completion has no intent' USING ERRCODE = '23514';
    END IF;
    IF TG_TABLE_NAME = 'ccse_outbox_intent'
       AND NEW.transaction_id IS DISTINCT FROM durable_transaction_id THEN
        RAISE EXCEPTION 'outbox intent must share the durable-result transaction'
            USING ERRCODE = '23514';
    END IF;
    IF TG_TABLE_NAME = 'ccse_replay_inbox' THEN
        IF NEW.transaction_id IS DISTINCT FROM durable_transaction_id THEN
            RAISE EXCEPTION 'replay inbox must share the durable-result transaction'
                USING ERRCODE = '23514';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM cph_aiinfra.ccse_replay_head
             WHERE scope_sha256 = NEW.scope_sha256
               AND counter_kind = NEW.counter_kind
               AND highest_sequence = NEW.sequence
        ) THEN
            RAISE EXCEPTION 'replay inbox has no exact replay-head scope, counter kind and sequence'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    IF TG_TABLE_NAME = 'ccse_durable_result' AND NOT EXISTS (
        SELECT 1 FROM cph_aiinfra.ccse_replay_inbox
         WHERE scope_sha256 = NEW.scope_sha256 AND message_id = NEW.message_id
           AND outcome_digest = durable_digest
           AND transaction_id = durable_transaction_id
    ) THEN
        RAISE EXCEPTION 'durable result has no matching replay inbox entry' USING ERRCODE = '23503';
    END IF;
    RETURN NULL;
END;
$cph$;

CREATE TRIGGER schema_migration_immutable
BEFORE UPDATE OR DELETE ON cph_aiinfra.schema_migration
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.reject_immutable_change();

CREATE TRIGGER ccse_replay_head_monotonic
BEFORE UPDATE ON cph_aiinfra.ccse_replay_head
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.enforce_replay_head_monotonic();

CREATE TRIGGER ccse_replay_head_initial
BEFORE INSERT ON cph_aiinfra.ccse_replay_head
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.enforce_replay_head_monotonic();

CREATE TRIGGER ccse_replay_inbox_immutable
BEFORE UPDATE OR DELETE ON cph_aiinfra.ccse_replay_inbox
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.reject_immutable_change();

CREATE TRIGGER ccse_replay_inbox_transaction
BEFORE INSERT ON cph_aiinfra.ccse_replay_inbox
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.stamp_unit_of_work_transaction();

CREATE TRIGGER ccse_durable_result_transaction
BEFORE INSERT ON cph_aiinfra.ccse_durable_result
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.stamp_unit_of_work_transaction();

CREATE TRIGGER ccse_durable_result_immutable
BEFORE UPDATE OR DELETE ON cph_aiinfra.ccse_durable_result
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.reject_immutable_change();

CREATE TRIGGER ccse_outbox_intent_transaction
BEFORE INSERT ON cph_aiinfra.ccse_outbox_intent
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.stamp_unit_of_work_transaction();

CREATE TRIGGER ccse_outbox_intent_immutable
BEFORE UPDATE OR DELETE ON cph_aiinfra.ccse_outbox_intent
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.reject_immutable_change();

CREATE CONSTRAINT TRIGGER ccse_durable_result_coupling
AFTER INSERT ON cph_aiinfra.ccse_durable_result
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_completion_coupling();

CREATE CONSTRAINT TRIGGER ccse_replay_inbox_coupling
AFTER INSERT ON cph_aiinfra.ccse_replay_inbox
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_completion_coupling();

CREATE CONSTRAINT TRIGGER ccse_outbox_intent_coupling
AFTER INSERT ON cph_aiinfra.ccse_outbox_intent
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_completion_coupling();

REVOKE ALL ON ALL TABLES IN SCHEMA cph_aiinfra FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA cph_aiinfra FROM PUBLIC;
