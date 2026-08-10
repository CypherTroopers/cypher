\set ON_ERROR_STOP on

BEGIN;
\ir ../migrations/0000_bootstrap.sql
\ir ../migrations/0001_ccse_replay.sql

INSERT INTO cph_aiinfra.schema_migration(version, migration_sha256)
VALUES (1, decode(:'migration_sha', 'hex'));

INSERT INTO cph_aiinfra.ccse_replay_head
    (scope_sha256, counter_kind, replay_domain_id, sender_identity, environment, chain_id, genesis_hash)
VALUES
    (decode(repeat('01', 32), 'hex'), 1, 'cph.integration', 'spiffe://integration/sender',
     'integration', decode(repeat('02', 32), 'hex'), decode(repeat('03', 32), 'hex'));

INSERT INTO cph_aiinfra.ccse_durable_result
    (scope_sha256, message_id, result_digest, content_type, payload, external_effect_mode)
VALUES
    (decode(repeat('01', 32), 'hex'), decode(repeat('04', 16), 'hex'),
     decode(repeat('05', 32), 'hex'), 'application/cph.integration', '\x7b7d', 1);

INSERT INTO cph_aiinfra.ccse_replay_inbox
    (scope_sha256, message_id, counter_kind, message_type_id, schema_major, schema_minor,
     record_digest, sequence, expires_at_unix_nano, outcome_digest)
VALUES
    (decode(repeat('01', 32), 'hex'), decode(repeat('04', 16), 'hex'), 1, 65537, 1, 0,
     decode(repeat('06', 32), 'hex'), decode('0000000000000001', 'hex'), 1,
     decode(repeat('05', 32), 'hex'));

UPDATE cph_aiinfra.ccse_replay_head
SET highest_sequence = decode('0000000000000001', 'hex')
WHERE scope_sha256 = decode(repeat('01', 32), 'hex');

SET CONSTRAINTS ALL IMMEDIATE;
SET CONSTRAINTS ALL DEFERRED;

INSERT INTO cph_aiinfra.ccse_replay_head
    (scope_sha256, counter_kind, replay_domain_id, sender_identity, environment, chain_id, genesis_hash)
VALUES
    (decode(repeat('21', 32), 'hex'), 1, 'cph.integration.outbox', 'spiffe://integration/sender',
     'integration', decode(repeat('22', 32), 'hex'), decode(repeat('23', 32), 'hex'));

INSERT INTO cph_aiinfra.ccse_durable_result
    (scope_sha256, message_id, result_digest, content_type, payload, external_effect_mode)
VALUES
    (decode(repeat('21', 32), 'hex'), decode(repeat('08', 16), 'hex'),
     decode(repeat('09', 32), 'hex'), 'application/cph.integration', '\x7b7d', 2);

INSERT INTO cph_aiinfra.ccse_outbox_intent
    (event_id, scope_sha256, message_id, destination, deduplication_key,
     content_type, payload, payload_digest)
VALUES
    (decode(repeat('0a', 16), 'hex'), decode(repeat('21', 32), 'hex'),
     decode(repeat('08', 16), 'hex'), 'cph.integration.events', 'integration:outbox:1',
     'application/cph.integration', '\x7b7d', decode(repeat('0b', 32), 'hex'));

INSERT INTO cph_aiinfra.ccse_replay_inbox
    (scope_sha256, message_id, counter_kind, message_type_id, schema_major, schema_minor,
     record_digest, sequence, expires_at_unix_nano, outcome_digest)
VALUES
    (decode(repeat('21', 32), 'hex'), decode(repeat('08', 16), 'hex'), 1, 65537, 1, 0,
     decode(repeat('0c', 32), 'hex'), decode('0000000000000002', 'hex'), 2,
     decode(repeat('09', 32), 'hex'));

UPDATE cph_aiinfra.ccse_replay_head
SET highest_sequence = decode('0000000000000002', 'hex')
WHERE scope_sha256 = decode(repeat('21', 32), 'hex');

SET CONSTRAINTS ALL IMMEDIATE;
SET CONSTRAINTS ALL DEFERRED;

DO $test$
BEGIN
    BEGIN
        INSERT INTO cph_aiinfra.ccse_durable_result
            (scope_sha256, message_id, result_digest, content_type, payload, external_effect_mode)
        VALUES
            (decode(repeat('01', 32), 'hex'), decode(repeat('10', 16), 'hex'),
             decode(repeat('11', 32), 'hex'), 'application/cph.integration', '\x7b7d', 1);
        SET CONSTRAINTS ALL IMMEDIATE;
        RAISE EXCEPTION 'completion coupling accepted a result without an inbox';
    EXCEPTION WHEN foreign_key_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO cph_aiinfra.ccse_replay_head
            (scope_sha256, counter_kind, replay_domain_id, sender_identity, environment, chain_id, genesis_hash)
        VALUES
            (decode(repeat('31', 32), 'hex'), 1, 'cph.integration.missing-outbox',
             'spiffe://integration/sender', 'integration',
             decode(repeat('32', 32), 'hex'), decode(repeat('33', 32), 'hex'));
        INSERT INTO cph_aiinfra.ccse_durable_result
            (scope_sha256, message_id, result_digest, content_type, payload, external_effect_mode)
        VALUES
            (decode(repeat('31', 32), 'hex'), decode(repeat('12', 16), 'hex'),
             decode(repeat('13', 32), 'hex'), 'application/cph.integration', '\x7b7d', 2);
        INSERT INTO cph_aiinfra.ccse_replay_inbox
            (scope_sha256, message_id, counter_kind, message_type_id, schema_major, schema_minor,
             record_digest, sequence, expires_at_unix_nano, outcome_digest)
        VALUES
            (decode(repeat('31', 32), 'hex'), decode(repeat('12', 16), 'hex'), 1, 65537, 1, 0,
             decode(repeat('14', 32), 'hex'), decode('0000000000000003', 'hex'), 3,
             decode(repeat('13', 32), 'hex'));
        UPDATE cph_aiinfra.ccse_replay_head
        SET highest_sequence = decode('0000000000000003', 'hex')
        WHERE scope_sha256 = decode(repeat('31', 32), 'hex');
        SET CONSTRAINTS ALL IMMEDIATE;
        RAISE EXCEPTION 'completion coupling accepted outbox mode without an intent';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
END;
$test$;

-- The stamp trigger normally makes a mismatched XID impossible. Temporarily
-- disabling only that trigger as the migration owner proves the deferred
-- coupling trigger independently rejects a forged/cross-transaction intent.
ALTER TABLE cph_aiinfra.ccse_outbox_intent
    DISABLE TRIGGER ccse_outbox_intent_transaction;

DO $test$
BEGIN
    BEGIN
        INSERT INTO cph_aiinfra.ccse_outbox_intent
            (event_id, scope_sha256, message_id, destination, deduplication_key,
             content_type, payload, payload_digest, transaction_id)
        VALUES
            (decode(repeat('0d', 16), 'hex'), decode(repeat('21', 32), 'hex'),
             decode(repeat('08', 16), 'hex'), 'cph.integration.events', 'integration:outbox:forged',
             'application/cph.integration', '\x7b7d', decode(repeat('0e', 32), 'hex'), '0'::xid8);
        SET CONSTRAINTS ALL IMMEDIATE;
        RAISE EXCEPTION 'outbox coupling accepted a mismatched transaction ID';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
END;
$test$;

ALTER TABLE cph_aiinfra.ccse_outbox_intent
    ENABLE TRIGGER ccse_outbox_intent_transaction;

DO $test$
BEGIN
    BEGIN
        UPDATE cph_aiinfra.ccse_replay_head
        SET highest_sequence = decode('0000000000000001', 'hex')
        WHERE scope_sha256 = decode(repeat('01', 32), 'hex');
        RAISE EXCEPTION 'monotonic replay guard accepted a duplicate sequence';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        UPDATE cph_aiinfra.ccse_replay_head
        SET highest_sequence = decode('0000000000000009', 'hex')
        WHERE scope_sha256 = decode(repeat('21', 32), 'hex');
        RAISE EXCEPTION 'replay head accepted a sequence without the exact same-transaction inbox row';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        UPDATE cph_aiinfra.ccse_replay_inbox
        SET outcome_digest = decode(repeat('07', 32), 'hex')
        WHERE scope_sha256 = decode(repeat('01', 32), 'hex');
        RAISE EXCEPTION 'immutable replay inbox accepted an update';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;

    BEGIN
        DELETE FROM cph_aiinfra.ccse_durable_result
        WHERE scope_sha256 = decode(repeat('01', 32), 'hex');
        RAISE EXCEPTION 'immutable durable result accepted a delete';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;
END;
$test$;

ROLLBACK;

\echo 'schema conformance passed; all changes rolled back'
