CREATE SCHEMA IF NOT EXISTS cph_aiinfra;

CREATE TABLE IF NOT EXISTS cph_aiinfra.schema_migration (
    version          BIGINT NOT NULL,
    migration_sha256 BYTEA NOT NULL,
    applied_at       TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT schema_migration_pk PRIMARY KEY (version),
    CONSTRAINT schema_migration_digest_length CHECK (octet_length(migration_sha256) = 32)
);
