-- Lossless v2 semantic projections.  This migration is strictly additive:
-- frozen v1 canonical rows are never rewritten or guessed/backfilled.

SET LOCAL search_path = pg_catalog;

CREATE TABLE cph_aiinfra.canonical_semantic_projection (
    state_namespace       SMALLINT NOT NULL,
    object_kind           TEXT COLLATE "C" NOT NULL,
    object_id             TEXT COLLATE "C" NOT NULL,
    version               NUMERIC(20,0) NOT NULL,
    state_digest          BYTEA NOT NULL,
    projection_codec      TEXT COLLATE "C" NOT NULL,
    projection_digest     BYTEA NOT NULL,
    canonical_projection  BYTEA NOT NULL,
	lookup_digest         BYTEA,
    audit_event_id        TEXT COLLATE "C" NOT NULL,
    uow_scope_sha256      BYTEA NOT NULL,
    uow_message_id        BYTEA NOT NULL,
    transaction_id        XID8 NOT NULL,
    recorded_at           TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT canonical_semantic_projection_pk PRIMARY KEY
        (state_namespace, object_kind, object_id, version),
    CONSTRAINT canonical_semantic_projection_state_fk FOREIGN KEY
        (state_namespace, object_kind, object_id, version)
        REFERENCES cph_aiinfra.canonical_state_history
            (state_namespace, object_kind, object_id, version)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT canonical_semantic_projection_uow_fk FOREIGN KEY
        (uow_scope_sha256, uow_message_id)
        REFERENCES cph_aiinfra.authoritative_uow(scope_sha256, message_id)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT canonical_semantic_projection_namespace CHECK (state_namespace IN (1, 2)),
    CONSTRAINT canonical_semantic_projection_kind_length CHECK (octet_length(object_kind) BETWEEN 1 AND 255),
    CONSTRAINT canonical_semantic_projection_id_length CHECK (octet_length(object_id) BETWEEN 1 AND 1024),
    CONSTRAINT canonical_semantic_projection_version_range CHECK (version BETWEEN 1 AND 18446744073709551615),
    CONSTRAINT canonical_semantic_projection_state_digest_length CHECK (octet_length(state_digest) = 32),
    CONSTRAINT canonical_semantic_projection_codec_length CHECK (octet_length(projection_codec) BETWEEN 1 AND 255),
    CONSTRAINT canonical_semantic_projection_digest_length CHECK (octet_length(projection_digest) = 32),
    CONSTRAINT canonical_semantic_projection_digest_match CHECK (projection_digest = pg_catalog.sha256(canonical_projection)),
    CONSTRAINT canonical_semantic_projection_content_length CHECK (octet_length(canonical_projection) BETWEEN 1 AND 67108864),
	CONSTRAINT canonical_semantic_projection_lookup_digest CHECK (
		(state_namespace = 1 AND object_kind = 'cph.aiinfra.iam.accepted-ownership-transfer.v1'
			AND lookup_digest IS NOT NULL AND octet_length(lookup_digest) = 32)
		OR
		(NOT (state_namespace = 1 AND object_kind = 'cph.aiinfra.iam.accepted-ownership-transfer.v1')
			AND lookup_digest IS NULL)
	),
    CONSTRAINT canonical_semantic_projection_kind_codec_catalog CHECK (
        (state_namespace = 1 AND object_kind IN (
            'cph.aiinfra.iam.key-material.v1',
            'cph.aiinfra.iam.identity.v1',
            'cph.aiinfra.iam.key-lifecycle.v1',
            'cph.aiinfra.iam.accepted-ownership-transfer.v1',
            'cph.aiinfra.iam.subject-key-set.v1',
            'cph.aiinfra.iam.ownership-transfer-profile-activation.v1'
        ) AND projection_codec = 'cph.aiinfra.iam.semantic-projection.v2')
        OR
        (state_namespace = 2 AND object_kind = 'cph.aiinfra.governance.policy-registry.v1'
            AND projection_codec = 'cph.aiinfra.governance.policy-registry-projection.v2')
        OR
        (state_namespace = 2 AND object_kind = 'cph.aiinfra.governance.profile-activation.v1'
            AND projection_codec = 'cph.aiinfra.governance.profile-activation-projection.v2')
    ),
    CONSTRAINT canonical_semantic_projection_event_length CHECK (octet_length(audit_event_id) BETWEEN 1 AND 1024),
    CONSTRAINT canonical_semantic_projection_uow_scope_length CHECK (octet_length(uow_scope_sha256) = 32),
    CONSTRAINT canonical_semantic_projection_uow_message_length CHECK (octet_length(uow_message_id) = 16)
);

CREATE INDEX canonical_semantic_projection_codec_idx
    ON cph_aiinfra.canonical_semantic_projection (projection_codec);

CREATE UNIQUE INDEX canonical_semantic_projection_lookup_digest_idx
	ON cph_aiinfra.canonical_semantic_projection (state_namespace, object_kind, lookup_digest)
	WHERE lookup_digest IS NOT NULL;

CREATE FUNCTION cph_aiinfra.assert_semantic_projection_consistency()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $cph$
BEGIN
    IF NEW.transaction_id <> pg_current_xact_id() THEN
        RAISE EXCEPTION 'semantic projection transaction mismatch'
            USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM cph_aiinfra.canonical_state_history state
         WHERE state.state_namespace = NEW.state_namespace
           AND state.object_kind = NEW.object_kind
           AND state.object_id = NEW.object_id
           AND state.version = NEW.version
           AND state.state_digest = NEW.state_digest
           AND state.audit_event_id = NEW.audit_event_id
           AND state.uow_scope_sha256 = NEW.uow_scope_sha256
           AND state.uow_message_id = NEW.uow_message_id
           AND state.transaction_id = NEW.transaction_id
    ) THEN
        RAISE EXCEPTION 'semantic projection has no exact same-transaction canonical row'
            USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM cph_aiinfra.authoritative_uow uow
         WHERE uow.scope_sha256 = NEW.uow_scope_sha256
           AND uow.message_id = NEW.uow_message_id
           AND uow.uow_kind = 2
           AND uow.audit_event_id = NEW.audit_event_id
           AND uow.transaction_id = NEW.transaction_id
    ) THEN
        RAISE EXCEPTION 'semantic projection requires the same audited-final UoW'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$cph$;

CREATE FUNCTION cph_aiinfra.assert_required_semantic_projection()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $cph$
BEGIN
    IF (NEW.state_namespace = 1 AND NEW.object_kind IN (
            'cph.aiinfra.iam.key-material.v1',
            'cph.aiinfra.iam.identity.v1',
            'cph.aiinfra.iam.key-lifecycle.v1',
            'cph.aiinfra.iam.accepted-ownership-transfer.v1',
            'cph.aiinfra.iam.subject-key-set.v1',
            'cph.aiinfra.iam.ownership-transfer-profile-activation.v1'
        )) OR (NEW.state_namespace = 2 AND NEW.object_kind IN (
            'cph.aiinfra.governance.policy-registry.v1',
            'cph.aiinfra.governance.profile-activation.v1'
        )) THEN
        IF NOT EXISTS (
            SELECT 1 FROM cph_aiinfra.canonical_semantic_projection projection
             WHERE projection.state_namespace = NEW.state_namespace
               AND projection.object_kind = NEW.object_kind
               AND projection.object_id = NEW.object_id
               AND projection.version = NEW.version
               AND projection.state_digest = NEW.state_digest
               AND projection.audit_event_id = NEW.audit_event_id
               AND projection.uow_scope_sha256 = NEW.uow_scope_sha256
               AND projection.uow_message_id = NEW.uow_message_id
               AND projection.transaction_id = NEW.transaction_id
        ) THEN
            RAISE EXCEPTION 'lossy canonical row requires a same-UoW v2 semantic projection'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NULL;
END;
$cph$;

CREATE TRIGGER canonical_semantic_projection_transaction
BEFORE INSERT ON cph_aiinfra.canonical_semantic_projection
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.stamp_unit_of_work_transaction();

CREATE TRIGGER canonical_semantic_projection_immutable
BEFORE DELETE OR UPDATE ON cph_aiinfra.canonical_semantic_projection
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.reject_immutable_change();

CREATE CONSTRAINT TRIGGER canonical_semantic_projection_consistency
AFTER INSERT ON cph_aiinfra.canonical_semantic_projection
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_semantic_projection_consistency();

CREATE CONSTRAINT TRIGGER canonical_state_history_semantic_projection
AFTER INSERT ON cph_aiinfra.canonical_state_history
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_required_semantic_projection();

REVOKE ALL ON ALL TABLES IN SCHEMA cph_aiinfra FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA cph_aiinfra FROM PUBLIC;
