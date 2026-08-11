-- Migration 2 adds the canonical AuditEvent unit-of-work substrate.  Every
-- v2 row carries the outer authoritative UoW receipt and xid8.  Deferred
-- constraint triggers bind those rows to the exact v1 CCSE inbox/result tuple.
-- An ADMISSION UoW has no AuditEvent.  An AUDITED_FINAL UoW names its actual
-- signed event.  Pending/idempotency rows carry their own expected terminal
-- AuditEvent identifier, which can differ from the parent UoW's actual event.
-- Existing v1-only ReplayStore transactions remain valid because they do not
-- create a v2 row.

CREATE TABLE cph_aiinfra.authoritative_uow (
    scope_sha256                BYTEA NOT NULL,
    message_id                  BYTEA NOT NULL,
    uow_kind                    SMALLINT NOT NULL,
    outcome_digest              BYTEA NOT NULL,
    result_content_type         TEXT COLLATE "C" NOT NULL,
    result_payload              BYTEA NOT NULL,
    evidence_assertion_count    SMALLINT NOT NULL,
    audit_event_id              TEXT COLLATE "C",
    transaction_id              XID8 NOT NULL,
    committed_at                TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT authoritative_uow_pk PRIMARY KEY (scope_sha256, message_id),
    CONSTRAINT authoritative_uow_transaction_key UNIQUE (transaction_id),
    CONSTRAINT authoritative_uow_result_fk FOREIGN KEY (scope_sha256, message_id, outcome_digest)
        REFERENCES cph_aiinfra.ccse_durable_result(scope_sha256, message_id, result_digest)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT authoritative_uow_scope_length CHECK (octet_length(scope_sha256) = 32),
    CONSTRAINT authoritative_uow_message_length CHECK (octet_length(message_id) = 16),
    CONSTRAINT authoritative_uow_kind CHECK (uow_kind IN (1, 2)),
    CONSTRAINT authoritative_uow_outcome_length CHECK (octet_length(outcome_digest) = 32),
    CONSTRAINT authoritative_uow_content_type_length CHECK (octet_length(result_content_type) BETWEEN 1 AND 255),
    CONSTRAINT authoritative_uow_payload_length CHECK (octet_length(result_payload) <= 1048576),
    CONSTRAINT authoritative_uow_evidence_count CHECK (evidence_assertion_count BETWEEN 0 AND 2048),
    CONSTRAINT authoritative_uow_event_length CHECK (audit_event_id IS NULL OR octet_length(audit_event_id) BETWEEN 1 AND 1024),
    CONSTRAINT authoritative_uow_kind_shape CHECK (
        (uow_kind = 1 AND audit_event_id IS NULL AND evidence_assertion_count = 0)
        OR
        (uow_kind = 2 AND audit_event_id IS NOT NULL AND evidence_assertion_count > 0)
    )
);

CREATE TABLE cph_aiinfra.audit_event (
    event_id                    TEXT COLLATE "C" NOT NULL,
    stream_id                   TEXT COLLATE "C" NOT NULL,
    audit_sequence              NUMERIC(20,0) NOT NULL,
    previous_event_digest       BYTEA,
    event_digest                BYTEA NOT NULL,
    record_digest               BYTEA NOT NULL,
    canonical_event             BYTEA NOT NULL,
    scope_sha256                BYTEA NOT NULL,
    message_id                  BYTEA NOT NULL,
    occurred_at_unix_nano       BIGINT NOT NULL,
    transaction_id              XID8 NOT NULL,
    committed_at                TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT audit_event_pk PRIMARY KEY (event_id),
    CONSTRAINT audit_event_stream_sequence_key UNIQUE (stream_id, audit_sequence),
    CONSTRAINT audit_event_uow_key UNIQUE (scope_sha256, message_id),
    CONSTRAINT audit_event_uow_fk FOREIGN KEY (scope_sha256, message_id)
        REFERENCES cph_aiinfra.authoritative_uow(scope_sha256, message_id)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT audit_event_id_length CHECK (octet_length(event_id) BETWEEN 1 AND 1024),
    CONSTRAINT audit_event_stream_length CHECK (octet_length(stream_id) BETWEEN 1 AND 255),
    CONSTRAINT audit_event_sequence_range CHECK (audit_sequence BETWEEN 1 AND 18446744073709551615),
    CONSTRAINT audit_event_previous_length CHECK (previous_event_digest IS NULL OR octet_length(previous_event_digest) = 32),
    CONSTRAINT audit_event_digest_length CHECK (octet_length(event_digest) = 32),
    CONSTRAINT audit_event_record_length CHECK (octet_length(record_digest) = 32),
    CONSTRAINT audit_event_canonical_length CHECK (octet_length(canonical_event) BETWEEN 1 AND 67108864),
    CONSTRAINT audit_event_scope_length CHECK (octet_length(scope_sha256) = 32),
    CONSTRAINT audit_event_message_length CHECK (octet_length(message_id) = 16),
    CONSTRAINT audit_event_occurred_positive CHECK (occurred_at_unix_nano > 0)
);

CREATE TABLE cph_aiinfra.audit_head (
    stream_id                   TEXT COLLATE "C" NOT NULL,
    deployment_anchor_digest    BYTEA NOT NULL,
    highest_sequence            NUMERIC(20,0) NOT NULL,
    latest_record_digest        BYTEA NOT NULL,
    audit_event_id              TEXT COLLATE "C" NOT NULL,
    head_writer_identity        TEXT COLLATE "C" NOT NULL,
    authorized_writer_identity  TEXT COLLATE "C" NOT NULL,
    home_region                 TEXT COLLATE "C" NOT NULL,
    authorized_home_region      TEXT COLLATE "C" NOT NULL,
    writer_epoch                NUMERIC(20,0) NOT NULL,
    authorized_writer_epoch     NUMERIC(20,0) NOT NULL,
    head_governance_profile_digest BYTEA NOT NULL,
    authorized_governance_profile_digest BYTEA NOT NULL,
    writer_lease_evidence_digest BYTEA NOT NULL,
    writer_lease_not_before_unix_nano BIGINT NOT NULL,
    writer_lease_not_after_unix_nano BIGINT NOT NULL,
    uow_scope_sha256            BYTEA NOT NULL,
    uow_message_id              BYTEA NOT NULL,
    transaction_id              XID8 NOT NULL,
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT audit_head_pk PRIMARY KEY (stream_id),
    CONSTRAINT audit_head_event_fk FOREIGN KEY (audit_event_id)
        REFERENCES cph_aiinfra.audit_event(event_id) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT audit_head_uow_fk FOREIGN KEY (uow_scope_sha256, uow_message_id)
        REFERENCES cph_aiinfra.authoritative_uow(scope_sha256, message_id) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT audit_head_stream_length CHECK (octet_length(stream_id) BETWEEN 1 AND 255),
    CONSTRAINT audit_head_anchor_length CHECK (octet_length(deployment_anchor_digest) = 32),
    CONSTRAINT audit_head_sequence_range CHECK (highest_sequence BETWEEN 1 AND 18446744073709551615),
    CONSTRAINT audit_head_digest_length CHECK (octet_length(latest_record_digest) = 32),
    CONSTRAINT audit_head_event_length CHECK (octet_length(audit_event_id) BETWEEN 1 AND 1024),
    CONSTRAINT audit_head_writer_length CHECK (octet_length(head_writer_identity) BETWEEN 1 AND 1024 AND octet_length(authorized_writer_identity) BETWEEN 1 AND 1024),
    CONSTRAINT audit_head_region_length CHECK (octet_length(home_region) BETWEEN 1 AND 255 AND octet_length(authorized_home_region) BETWEEN 1 AND 255),
    CONSTRAINT audit_head_epoch_range CHECK (writer_epoch BETWEEN 1 AND 18446744073709551615 AND authorized_writer_epoch BETWEEN 1 AND 18446744073709551615),
    CONSTRAINT audit_head_profile_length CHECK (octet_length(head_governance_profile_digest) = 32 AND octet_length(authorized_governance_profile_digest) = 32),
    CONSTRAINT audit_head_lease_digest_length CHECK (octet_length(writer_lease_evidence_digest) = 32),
    CONSTRAINT audit_head_lease_window CHECK (writer_lease_not_before_unix_nano >= 0 AND writer_lease_not_after_unix_nano > writer_lease_not_before_unix_nano),
    CONSTRAINT audit_head_authorized_shape CHECK (head_writer_identity = authorized_writer_identity AND home_region = authorized_home_region AND writer_epoch = authorized_writer_epoch AND head_governance_profile_digest = authorized_governance_profile_digest),
    CONSTRAINT audit_head_uow_scope_length CHECK (octet_length(uow_scope_sha256) = 32),
    CONSTRAINT audit_head_uow_message_length CHECK (octet_length(uow_message_id) = 16)
);

CREATE TABLE cph_aiinfra.business_idempotency_head (
    idempotency_key             BYTEA NOT NULL,
    row_kind                    SMALLINT NOT NULL,
    operation_domain            TEXT COLLATE "C" NOT NULL,
    owner_id                    TEXT COLLATE "C" NOT NULL,
    request_digest              BYTEA NOT NULL,
    binding_digest              BYTEA NOT NULL,
    parent_key                  BYTEA,
    parent_operation_domain     TEXT COLLATE "C",
    parent_owner_id             TEXT COLLATE "C",
    parent_request_digest       BYTEA,
    state                       SMALLINT NOT NULL,
    version                     NUMERIC(20,0) NOT NULL,
    progress_digest             BYTEA,
    outcome_digest              BYTEA,
    audit_event_id              TEXT COLLATE "C" NOT NULL,
    uow_scope_sha256            BYTEA NOT NULL,
    uow_message_id              BYTEA NOT NULL,
    transaction_id              XID8 NOT NULL,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT business_idempotency_head_pk PRIMARY KEY (idempotency_key),
    CONSTRAINT business_idempotency_head_parent_fk FOREIGN KEY (parent_key)
        REFERENCES cph_aiinfra.business_idempotency_head(idempotency_key)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT business_idempotency_head_uow_fk FOREIGN KEY (uow_scope_sha256, uow_message_id)
        REFERENCES cph_aiinfra.authoritative_uow(scope_sha256, message_id) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT business_idempotency_head_key_length CHECK (octet_length(idempotency_key) = 16),
    CONSTRAINT business_idempotency_head_kind CHECK (row_kind IN (1, 2, 3)),
    CONSTRAINT business_idempotency_head_domain_length CHECK (octet_length(operation_domain) BETWEEN 1 AND 255),
    CONSTRAINT business_idempotency_head_owner_length CHECK (octet_length(owner_id) BETWEEN 1 AND 1024),
    CONSTRAINT business_idempotency_head_request_length CHECK (octet_length(request_digest) = 32),
    CONSTRAINT business_idempotency_head_binding_length CHECK (octet_length(binding_digest) = 32),
    CONSTRAINT business_idempotency_head_parent_key_length CHECK (parent_key IS NULL OR octet_length(parent_key) = 16),
    CONSTRAINT business_idempotency_head_parent_domain_length CHECK (parent_operation_domain IS NULL OR octet_length(parent_operation_domain) BETWEEN 1 AND 255),
    CONSTRAINT business_idempotency_head_parent_owner_length CHECK (parent_owner_id IS NULL OR octet_length(parent_owner_id) BETWEEN 1 AND 1024),
    CONSTRAINT business_idempotency_head_parent_request_length CHECK (parent_request_digest IS NULL OR octet_length(parent_request_digest) = 32),
    CONSTRAINT business_idempotency_head_parent_shape CHECK (
        (row_kind = 1 AND parent_key IS NULL AND parent_operation_domain IS NULL AND parent_owner_id IS NULL AND parent_request_digest IS NULL)
        OR
        (row_kind IN (2, 3) AND parent_key IS NOT NULL AND parent_operation_domain IS NOT NULL AND parent_owner_id IS NOT NULL AND parent_request_digest IS NOT NULL)
    ),
    CONSTRAINT business_idempotency_head_domain_shape CHECK (
        (row_kind = 2 AND operation_domain = 'cph.aiinfra.joined-audit.v1')
        OR
        (row_kind IN (1, 3) AND operation_domain <> 'cph.aiinfra.joined-audit.v1')
    ),
    CONSTRAINT business_idempotency_head_operation_catalog CHECK (
        operation_domain IN (
            'cph.aiinfra.iam.key-enrollment.v1', 'cph.aiinfra.iam.identity.v1',
            'cph.aiinfra.iam.key-lifecycle.v1', 'cph.aiinfra.iam.ownership-transfer.v1',
            'cph.aiinfra.iam.ownership-transfer-cutover.v1', 'cph.aiinfra.governance.policy.v1',
            'cph.aiinfra.governance.audit.v1', 'cph.aiinfra.joined-audit.v1'
        )
        AND (parent_operation_domain IS NULL OR parent_operation_domain IN (
            'cph.aiinfra.iam.key-enrollment.v1', 'cph.aiinfra.iam.identity.v1',
            'cph.aiinfra.iam.key-lifecycle.v1', 'cph.aiinfra.iam.ownership-transfer.v1',
            'cph.aiinfra.iam.ownership-transfer-cutover.v1', 'cph.aiinfra.governance.policy.v1'
        ))
        AND (row_kind <> 3 OR (
            operation_domain IN ('cph.aiinfra.iam.key-enrollment.v1', 'cph.aiinfra.iam.identity.v1', 'cph.aiinfra.iam.key-lifecycle.v1')
            AND parent_operation_domain = 'cph.aiinfra.iam.ownership-transfer-cutover.v1'
        ))
    ),
    CONSTRAINT business_idempotency_head_state CHECK (state IN (1, 2)),
    CONSTRAINT business_idempotency_head_version_range CHECK (version BETWEEN 1 AND 18446744073709551615),
    CONSTRAINT business_idempotency_head_progress_length CHECK (progress_digest IS NULL OR octet_length(progress_digest) = 32),
    CONSTRAINT business_idempotency_head_outcome_length CHECK (outcome_digest IS NULL OR octet_length(outcome_digest) = 32),
    CONSTRAINT business_idempotency_head_state_shape CHECK (
        (state = 1 AND progress_digest IS NOT NULL AND outcome_digest IS NULL)
        OR
        (state = 2 AND outcome_digest IS NOT NULL AND ((version = 1 AND progress_digest IS NULL) OR (version > 1 AND progress_digest IS NOT NULL)))
    ),
    CONSTRAINT business_idempotency_head_alias_version_shape CHECK (
        row_kind = 1 OR (row_kind IN (2, 3) AND ((state = 1 AND version = 1) OR (state = 2 AND version = 2)))
    ),
    CONSTRAINT business_idempotency_head_compound_parent_version_shape CHECK (
        row_kind <> 1 OR operation_domain <> 'cph.aiinfra.iam.ownership-transfer-cutover.v1'
        OR ((state = 1 AND version = 1) OR (state = 2 AND version = 2))
    ),
    CONSTRAINT business_idempotency_head_event_length CHECK (octet_length(audit_event_id) BETWEEN 1 AND 1024),
    CONSTRAINT business_idempotency_head_uow_scope_length CHECK (octet_length(uow_scope_sha256) = 32),
    CONSTRAINT business_idempotency_head_uow_message_length CHECK (octet_length(uow_message_id) = 16)
);

CREATE TABLE cph_aiinfra.business_idempotency_history (
    idempotency_key             BYTEA NOT NULL,
    version                     NUMERIC(20,0) NOT NULL,
    row_kind                    SMALLINT NOT NULL,
    operation_domain            TEXT COLLATE "C" NOT NULL,
    owner_id                    TEXT COLLATE "C" NOT NULL,
    request_digest              BYTEA NOT NULL,
    binding_digest              BYTEA NOT NULL,
    parent_key                  BYTEA,
    parent_operation_domain     TEXT COLLATE "C",
    parent_owner_id             TEXT COLLATE "C",
    parent_request_digest       BYTEA,
    state                       SMALLINT NOT NULL,
    progress_digest             BYTEA,
    outcome_digest              BYTEA,
    audit_event_id              TEXT COLLATE "C" NOT NULL,
    uow_scope_sha256            BYTEA NOT NULL,
    uow_message_id              BYTEA NOT NULL,
    transaction_id              XID8 NOT NULL,
    recorded_at                 TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT business_idempotency_history_pk PRIMARY KEY (idempotency_key, version),
    CONSTRAINT business_idempotency_history_head_fk FOREIGN KEY (idempotency_key)
        REFERENCES cph_aiinfra.business_idempotency_head(idempotency_key)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT business_idempotency_history_uow_fk FOREIGN KEY (uow_scope_sha256, uow_message_id)
        REFERENCES cph_aiinfra.authoritative_uow(scope_sha256, message_id) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT business_idempotency_history_key_length CHECK (octet_length(idempotency_key) = 16),
    CONSTRAINT business_idempotency_history_version_range CHECK (version BETWEEN 1 AND 18446744073709551615),
    CONSTRAINT business_idempotency_history_kind CHECK (row_kind IN (1, 2, 3)),
    CONSTRAINT business_idempotency_history_domain_length CHECK (octet_length(operation_domain) BETWEEN 1 AND 255),
    CONSTRAINT business_idempotency_history_owner_length CHECK (octet_length(owner_id) BETWEEN 1 AND 1024),
    CONSTRAINT business_idempotency_history_request_length CHECK (octet_length(request_digest) = 32),
    CONSTRAINT business_idempotency_history_binding_length CHECK (octet_length(binding_digest) = 32),
    CONSTRAINT business_idempotency_history_parent_key_length CHECK (parent_key IS NULL OR octet_length(parent_key) = 16),
    CONSTRAINT business_idempotency_history_parent_domain_length CHECK (parent_operation_domain IS NULL OR octet_length(parent_operation_domain) BETWEEN 1 AND 255),
    CONSTRAINT business_idempotency_history_parent_owner_length CHECK (parent_owner_id IS NULL OR octet_length(parent_owner_id) BETWEEN 1 AND 1024),
    CONSTRAINT business_idempotency_history_parent_request_length CHECK (parent_request_digest IS NULL OR octet_length(parent_request_digest) = 32),
    CONSTRAINT business_idempotency_history_parent_shape CHECK (
        (row_kind = 1 AND parent_key IS NULL AND parent_operation_domain IS NULL AND parent_owner_id IS NULL AND parent_request_digest IS NULL)
        OR
        (row_kind IN (2, 3) AND parent_key IS NOT NULL AND parent_operation_domain IS NOT NULL AND parent_owner_id IS NOT NULL AND parent_request_digest IS NOT NULL)
    ),
    CONSTRAINT business_idempotency_history_domain_shape CHECK (
        (row_kind = 2 AND operation_domain = 'cph.aiinfra.joined-audit.v1')
        OR
        (row_kind IN (1, 3) AND operation_domain <> 'cph.aiinfra.joined-audit.v1')
    ),
    CONSTRAINT business_idempotency_history_operation_catalog CHECK (
        operation_domain IN (
            'cph.aiinfra.iam.key-enrollment.v1', 'cph.aiinfra.iam.identity.v1',
            'cph.aiinfra.iam.key-lifecycle.v1', 'cph.aiinfra.iam.ownership-transfer.v1',
            'cph.aiinfra.iam.ownership-transfer-cutover.v1', 'cph.aiinfra.governance.policy.v1',
            'cph.aiinfra.governance.audit.v1', 'cph.aiinfra.joined-audit.v1'
        )
        AND (parent_operation_domain IS NULL OR parent_operation_domain IN (
            'cph.aiinfra.iam.key-enrollment.v1', 'cph.aiinfra.iam.identity.v1',
            'cph.aiinfra.iam.key-lifecycle.v1', 'cph.aiinfra.iam.ownership-transfer.v1',
            'cph.aiinfra.iam.ownership-transfer-cutover.v1', 'cph.aiinfra.governance.policy.v1'
        ))
        AND (row_kind <> 3 OR (
            operation_domain IN ('cph.aiinfra.iam.key-enrollment.v1', 'cph.aiinfra.iam.identity.v1', 'cph.aiinfra.iam.key-lifecycle.v1')
            AND parent_operation_domain = 'cph.aiinfra.iam.ownership-transfer-cutover.v1'
        ))
    ),
    CONSTRAINT business_idempotency_history_state CHECK (state IN (1, 2)),
    CONSTRAINT business_idempotency_history_progress_length CHECK (progress_digest IS NULL OR octet_length(progress_digest) = 32),
    CONSTRAINT business_idempotency_history_outcome_length CHECK (outcome_digest IS NULL OR octet_length(outcome_digest) = 32),
    CONSTRAINT business_idempotency_history_state_shape CHECK (
        (state = 1 AND progress_digest IS NOT NULL AND outcome_digest IS NULL)
        OR
        (state = 2 AND outcome_digest IS NOT NULL AND ((version = 1 AND progress_digest IS NULL) OR (version > 1 AND progress_digest IS NOT NULL)))
    ),
    CONSTRAINT business_idempotency_history_alias_version_shape CHECK (
        row_kind = 1 OR (row_kind IN (2, 3) AND ((state = 1 AND version = 1) OR (state = 2 AND version = 2)))
    ),
    CONSTRAINT business_idempotency_history_compound_parent_version_shape CHECK (
        row_kind <> 1 OR operation_domain <> 'cph.aiinfra.iam.ownership-transfer-cutover.v1'
        OR ((state = 1 AND version = 1) OR (state = 2 AND version = 2))
    ),
    CONSTRAINT business_idempotency_history_event_length CHECK (octet_length(audit_event_id) BETWEEN 1 AND 1024),
    CONSTRAINT business_idempotency_history_uow_scope_length CHECK (octet_length(uow_scope_sha256) = 32),
    CONSTRAINT business_idempotency_history_uow_message_length CHECK (octet_length(uow_message_id) = 16)
);

CREATE INDEX business_idempotency_head_parent_idx
    ON cph_aiinfra.business_idempotency_head (parent_key);

CREATE INDEX business_idempotency_history_event_idx
    ON cph_aiinfra.business_idempotency_history (audit_event_id);

CREATE TABLE cph_aiinfra.global_identifier_head (
    identifier                   TEXT COLLATE "C" NOT NULL,
    owner_domain                TEXT COLLATE "C" NOT NULL,
    owner_id                    TEXT COLLATE "C" NOT NULL,
    version                     NUMERIC(20,0) NOT NULL,
    transfer_evidence_digest    BYTEA,
    audit_event_id              TEXT COLLATE "C" NOT NULL,
    uow_scope_sha256            BYTEA NOT NULL,
    uow_message_id              BYTEA NOT NULL,
    transaction_id              XID8 NOT NULL,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT global_identifier_head_pk PRIMARY KEY (identifier),
    CONSTRAINT global_identifier_head_uow_fk FOREIGN KEY (uow_scope_sha256, uow_message_id)
        REFERENCES cph_aiinfra.authoritative_uow(scope_sha256, message_id) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT global_identifier_head_identifier_length CHECK (octet_length(identifier) BETWEEN 1 AND 1024),
    CONSTRAINT global_identifier_head_owner_domain_length CHECK (octet_length(owner_domain) BETWEEN 1 AND 255),
    CONSTRAINT global_identifier_head_owner_domain_catalog CHECK (owner_domain IN (
        'cph.aiinfra.iam.identity.v1', 'cph.aiinfra.iam.key.v1',
        'cph.aiinfra.canonical.record.v1', 'cph.aiinfra.governance.policy-bundle.v1',
        'cph.aiinfra.governance.audit-event.v1'
    )),
    CONSTRAINT global_identifier_head_owner_length CHECK (octet_length(owner_id) BETWEEN 1 AND 1024),
    CONSTRAINT global_identifier_head_version_range CHECK (version BETWEEN 1 AND 18446744073709551615),
    CONSTRAINT global_identifier_head_evidence_length CHECK (transfer_evidence_digest IS NULL OR octet_length(transfer_evidence_digest) = 32),
    CONSTRAINT global_identifier_head_event_length CHECK (octet_length(audit_event_id) BETWEEN 1 AND 1024),
    CONSTRAINT global_identifier_head_uow_scope_length CHECK (octet_length(uow_scope_sha256) = 32),
    CONSTRAINT global_identifier_head_uow_message_length CHECK (octet_length(uow_message_id) = 16)
);

CREATE TABLE cph_aiinfra.global_identifier_history (
    identifier                   TEXT COLLATE "C" NOT NULL,
    version                     NUMERIC(20,0) NOT NULL,
    owner_domain                TEXT COLLATE "C" NOT NULL,
    owner_id                    TEXT COLLATE "C" NOT NULL,
    transfer_evidence_digest    BYTEA,
    audit_event_id              TEXT COLLATE "C" NOT NULL,
    uow_scope_sha256            BYTEA NOT NULL,
    uow_message_id              BYTEA NOT NULL,
    transaction_id              XID8 NOT NULL,
    recorded_at                 TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT global_identifier_history_pk PRIMARY KEY (identifier, version),
    CONSTRAINT global_identifier_history_head_fk FOREIGN KEY (identifier)
        REFERENCES cph_aiinfra.global_identifier_head(identifier) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT global_identifier_history_uow_fk FOREIGN KEY (uow_scope_sha256, uow_message_id)
        REFERENCES cph_aiinfra.authoritative_uow(scope_sha256, message_id) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT global_identifier_history_identifier_length CHECK (octet_length(identifier) BETWEEN 1 AND 1024),
    CONSTRAINT global_identifier_history_version_range CHECK (version BETWEEN 1 AND 18446744073709551615),
    CONSTRAINT global_identifier_history_owner_domain_length CHECK (octet_length(owner_domain) BETWEEN 1 AND 255),
    CONSTRAINT global_identifier_history_owner_domain_catalog CHECK (owner_domain IN (
        'cph.aiinfra.iam.identity.v1', 'cph.aiinfra.iam.key.v1',
        'cph.aiinfra.canonical.record.v1', 'cph.aiinfra.governance.policy-bundle.v1',
        'cph.aiinfra.governance.audit-event.v1'
    )),
    CONSTRAINT global_identifier_history_owner_length CHECK (octet_length(owner_id) BETWEEN 1 AND 1024),
    CONSTRAINT global_identifier_history_evidence_length CHECK (transfer_evidence_digest IS NULL OR octet_length(transfer_evidence_digest) = 32),
    CONSTRAINT global_identifier_history_event_length CHECK (octet_length(audit_event_id) BETWEEN 1 AND 1024),
    CONSTRAINT global_identifier_history_uow_scope_length CHECK (octet_length(uow_scope_sha256) = 32),
    CONSTRAINT global_identifier_history_uow_message_length CHECK (octet_length(uow_message_id) = 16)
);

CREATE TABLE cph_aiinfra.global_identifier_claim (
    audit_event_id                    TEXT COLLATE "C" NOT NULL,
    claim_ordinal                     SMALLINT NOT NULL,
    identifier                        TEXT COLLATE "C" NOT NULL,
    claim_mode                        SMALLINT NOT NULL,
    expected_owner_domain             TEXT COLLATE "C",
    expected_owner_id                 TEXT COLLATE "C",
    expected_version                  NUMERIC(20,0),
    next_owner_domain                 TEXT COLLATE "C" NOT NULL,
    next_owner_id                     TEXT COLLATE "C" NOT NULL,
    next_version                      NUMERIC(20,0) NOT NULL,
    transfer_evidence_digest          BYTEA,
    uow_scope_sha256                  BYTEA NOT NULL,
    uow_message_id                    BYTEA NOT NULL,
    transaction_id                    XID8 NOT NULL,
    recorded_at                       TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT global_identifier_claim_pk PRIMARY KEY (uow_scope_sha256, uow_message_id, claim_ordinal),
    CONSTRAINT global_identifier_claim_uow_identifier_key UNIQUE (uow_scope_sha256, uow_message_id, identifier),
    CONSTRAINT global_identifier_claim_identifier_fk FOREIGN KEY (identifier)
        REFERENCES cph_aiinfra.global_identifier_head(identifier) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT global_identifier_claim_uow_fk FOREIGN KEY (uow_scope_sha256, uow_message_id)
        REFERENCES cph_aiinfra.authoritative_uow(scope_sha256, message_id) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT global_identifier_claim_event_length CHECK (octet_length(audit_event_id) BETWEEN 1 AND 1024),
    CONSTRAINT global_identifier_claim_ordinal_range CHECK (claim_ordinal BETWEEN 1 AND 384),
    CONSTRAINT global_identifier_claim_identifier_length CHECK (octet_length(identifier) BETWEEN 1 AND 1024),
    CONSTRAINT global_identifier_claim_mode CHECK (claim_mode IN (1, 2, 3)),
    CONSTRAINT global_identifier_claim_expected_domain_length CHECK (expected_owner_domain IS NULL OR octet_length(expected_owner_domain) BETWEEN 1 AND 255),
    CONSTRAINT global_identifier_claim_expected_owner_length CHECK (expected_owner_id IS NULL OR octet_length(expected_owner_id) BETWEEN 1 AND 1024),
    CONSTRAINT global_identifier_claim_expected_version_range CHECK (
        expected_version IS NULL OR expected_version BETWEEN 1 AND 18446744073709551615
    ),
    CONSTRAINT global_identifier_claim_next_domain_length CHECK (octet_length(next_owner_domain) BETWEEN 1 AND 255),
    CONSTRAINT global_identifier_claim_owner_domain_catalog CHECK (
        next_owner_domain IN (
            'cph.aiinfra.iam.identity.v1', 'cph.aiinfra.iam.key.v1',
            'cph.aiinfra.canonical.record.v1', 'cph.aiinfra.governance.policy-bundle.v1',
            'cph.aiinfra.governance.audit-event.v1'
        )
        AND (expected_owner_domain IS NULL OR expected_owner_domain IN (
            'cph.aiinfra.iam.identity.v1', 'cph.aiinfra.iam.key.v1',
            'cph.aiinfra.canonical.record.v1', 'cph.aiinfra.governance.policy-bundle.v1',
            'cph.aiinfra.governance.audit-event.v1'
        ))
    ),
    CONSTRAINT global_identifier_claim_next_owner_length CHECK (octet_length(next_owner_id) BETWEEN 1 AND 1024),
    CONSTRAINT global_identifier_claim_next_version_range CHECK (next_version BETWEEN 1 AND 18446744073709551615),
    CONSTRAINT global_identifier_claim_evidence_length CHECK (transfer_evidence_digest IS NULL OR octet_length(transfer_evidence_digest) = 32),
    CONSTRAINT global_identifier_claim_uow_scope_length CHECK (octet_length(uow_scope_sha256) = 32),
    CONSTRAINT global_identifier_claim_uow_message_length CHECK (octet_length(uow_message_id) = 16),
    CONSTRAINT global_identifier_claim_shape CHECK (
        (claim_mode = 1 AND expected_owner_domain IS NULL AND expected_owner_id IS NULL AND expected_version IS NULL AND next_version = 1 AND transfer_evidence_digest IS NULL)
        OR
        (claim_mode = 2 AND expected_owner_domain IS NOT NULL AND expected_owner_id IS NOT NULL AND expected_version IS NOT NULL AND expected_version = next_version AND expected_owner_domain = next_owner_domain AND expected_owner_id = next_owner_id AND transfer_evidence_digest IS NULL)
        OR
        (claim_mode = 3 AND expected_owner_domain IS NOT NULL AND expected_owner_id IS NOT NULL AND expected_version IS NOT NULL AND next_version = expected_version + 1 AND expected_owner_domain = next_owner_domain AND expected_owner_id <> next_owner_id AND transfer_evidence_digest IS NOT NULL)
    )
);

CREATE INDEX global_identifier_history_event_idx
    ON cph_aiinfra.global_identifier_history (audit_event_id);

CREATE TABLE cph_aiinfra.durable_evidence (
    evidence_digest              BYTEA NOT NULL,
    evidence_kind                SMALLINT NOT NULL,
    content_type                 TEXT COLLATE "C" NOT NULL,
    canonical_content            BYTEA NOT NULL,
    audit_event_id               TEXT COLLATE "C" NOT NULL,
    uow_scope_sha256             BYTEA NOT NULL,
    uow_message_id               BYTEA NOT NULL,
    transaction_id               XID8 NOT NULL,
    created_at                   TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT durable_evidence_pk PRIMARY KEY (evidence_digest),
    CONSTRAINT durable_evidence_uow_fk FOREIGN KEY (uow_scope_sha256, uow_message_id)
        REFERENCES cph_aiinfra.authoritative_uow(scope_sha256, message_id) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT durable_evidence_digest_length CHECK (octet_length(evidence_digest) = 32),
    CONSTRAINT durable_evidence_kind CHECK (evidence_kind IN (1, 2, 3, 4)),
    CONSTRAINT durable_evidence_content_type_length CHECK (octet_length(content_type) BETWEEN 1 AND 255),
    CONSTRAINT durable_evidence_content_length CHECK (octet_length(canonical_content) BETWEEN 1 AND 67108864),
    CONSTRAINT durable_evidence_event_length CHECK (octet_length(audit_event_id) BETWEEN 1 AND 1024),
    CONSTRAINT durable_evidence_uow_scope_length CHECK (octet_length(uow_scope_sha256) = 32),
    CONSTRAINT durable_evidence_uow_message_length CHECK (octet_length(uow_message_id) = 16)
);

CREATE TABLE cph_aiinfra.durable_pending_head (
    pending_key                  BYTEA NOT NULL,
    pending_kind                 SMALLINT NOT NULL,
    codec                        TEXT COLLATE "C" NOT NULL,
    codec_version                BIGINT NOT NULL,
    revision                     NUMERIC(20,0) NOT NULL,
    previous_envelope_digest     BYTEA,
    envelope_digest              BYTEA NOT NULL,
    canonical_envelope           BYTEA NOT NULL,
    evidence_count               SMALLINT NOT NULL,
    status                       SMALLINT NOT NULL,
    commit_not_before_unix_nano  BIGINT NOT NULL,
    commit_not_after_unix_nano   BIGINT NOT NULL,
    terminal_outcome_digest      BYTEA,
    audit_event_id               TEXT COLLATE "C" NOT NULL,
    uow_scope_sha256             BYTEA NOT NULL,
    uow_message_id               BYTEA NOT NULL,
    transaction_id               XID8 NOT NULL,
    created_at                   TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at                   TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT durable_pending_head_pk PRIMARY KEY (pending_key),
    CONSTRAINT durable_pending_head_idempotency_fk FOREIGN KEY (pending_key)
        REFERENCES cph_aiinfra.business_idempotency_head(idempotency_key)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT durable_pending_head_uow_fk FOREIGN KEY (uow_scope_sha256, uow_message_id)
        REFERENCES cph_aiinfra.authoritative_uow(scope_sha256, message_id) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT durable_pending_head_key_length CHECK (octet_length(pending_key) = 16),
    CONSTRAINT durable_pending_head_kind CHECK (pending_kind IN (1, 2, 3, 4, 5, 7)),
    CONSTRAINT durable_pending_head_codec_length CHECK (octet_length(codec) BETWEEN 1 AND 255),
    CONSTRAINT durable_pending_head_codec_version_range CHECK (codec_version BETWEEN 1 AND 4294967295),
    CONSTRAINT durable_pending_head_kind_codec_catalog CHECK (
        (pending_kind IN (1, 2, 3, 4, 5)
            AND codec = 'cph.aiinfra.iam.pending.v1' AND codec_version = 1)
        OR (pending_kind = 7
            AND codec = 'cph.aiinfra.governance.policy-approval-collection.v1' AND codec_version = 1)
    ),
    CONSTRAINT durable_pending_head_revision_range CHECK (revision BETWEEN 1 AND 18446744073709551615),
    CONSTRAINT durable_pending_head_previous_length CHECK (previous_envelope_digest IS NULL OR octet_length(previous_envelope_digest) = 32),
    CONSTRAINT durable_pending_head_digest_length CHECK (octet_length(envelope_digest) = 32),
    CONSTRAINT durable_pending_head_envelope_length CHECK (octet_length(canonical_envelope) BETWEEN 1 AND 67108864),
    CONSTRAINT durable_pending_head_evidence_count CHECK (evidence_count BETWEEN 0 AND 2048),
    CONSTRAINT durable_pending_head_kind_evidence_shape CHECK (pending_kind <> 7 OR evidence_count BETWEEN 1 AND 2048),
    CONSTRAINT durable_pending_head_status CHECK (status IN (1, 2)),
    CONSTRAINT durable_pending_head_window CHECK (commit_not_before_unix_nano > 0 AND commit_not_after_unix_nano >= commit_not_before_unix_nano),
    CONSTRAINT durable_pending_head_outcome_length CHECK (terminal_outcome_digest IS NULL OR octet_length(terminal_outcome_digest) = 32),
    CONSTRAINT durable_pending_head_revision_shape CHECK ((revision = 1 AND previous_envelope_digest IS NULL) OR (revision > 1 AND previous_envelope_digest IS NOT NULL)),
    CONSTRAINT durable_pending_head_status_shape CHECK ((status = 1 AND terminal_outcome_digest IS NULL) OR (status = 2 AND terminal_outcome_digest IS NOT NULL)),
    CONSTRAINT durable_pending_head_reconciliation_shape CHECK (pending_kind <> 4 OR (revision > 1 AND status = 2 AND previous_envelope_digest IS NOT NULL)),
    CONSTRAINT durable_pending_head_event_length CHECK (octet_length(audit_event_id) BETWEEN 1 AND 1024),
    CONSTRAINT durable_pending_head_uow_scope_length CHECK (octet_length(uow_scope_sha256) = 32),
    CONSTRAINT durable_pending_head_uow_message_length CHECK (octet_length(uow_message_id) = 16)
);

CREATE TABLE cph_aiinfra.durable_pending_revision (
    pending_key                  BYTEA NOT NULL,
    revision                     NUMERIC(20,0) NOT NULL,
    pending_kind                 SMALLINT NOT NULL,
    codec                        TEXT COLLATE "C" NOT NULL,
    codec_version                BIGINT NOT NULL,
    previous_envelope_digest     BYTEA,
    envelope_digest              BYTEA NOT NULL,
    canonical_envelope           BYTEA NOT NULL,
    evidence_count               SMALLINT NOT NULL,
    status                       SMALLINT NOT NULL,
    commit_not_before_unix_nano  BIGINT NOT NULL,
    commit_not_after_unix_nano   BIGINT NOT NULL,
    terminal_outcome_digest      BYTEA,
    audit_event_id               TEXT COLLATE "C" NOT NULL,
    uow_scope_sha256             BYTEA NOT NULL,
    uow_message_id               BYTEA NOT NULL,
    transaction_id               XID8 NOT NULL,
    recorded_at                  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT durable_pending_revision_pk PRIMARY KEY (pending_key, revision),
    CONSTRAINT durable_pending_revision_head_fk FOREIGN KEY (pending_key)
        REFERENCES cph_aiinfra.durable_pending_head(pending_key) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT durable_pending_revision_uow_fk FOREIGN KEY (uow_scope_sha256, uow_message_id)
        REFERENCES cph_aiinfra.authoritative_uow(scope_sha256, message_id) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT durable_pending_revision_key_length CHECK (octet_length(pending_key) = 16),
    CONSTRAINT durable_pending_revision_range CHECK (revision BETWEEN 1 AND 18446744073709551615),
    CONSTRAINT durable_pending_revision_kind CHECK (pending_kind IN (1, 2, 3, 4, 5, 7)),
    CONSTRAINT durable_pending_revision_codec_length CHECK (octet_length(codec) BETWEEN 1 AND 255),
    CONSTRAINT durable_pending_revision_codec_version_range CHECK (codec_version BETWEEN 1 AND 4294967295),
    CONSTRAINT durable_pending_revision_kind_codec_catalog CHECK (
        (pending_kind IN (1, 2, 3, 4, 5)
            AND codec = 'cph.aiinfra.iam.pending.v1' AND codec_version = 1)
        OR (pending_kind = 7
            AND codec = 'cph.aiinfra.governance.policy-approval-collection.v1' AND codec_version = 1)
    ),
    CONSTRAINT durable_pending_revision_previous_length CHECK (previous_envelope_digest IS NULL OR octet_length(previous_envelope_digest) = 32),
    CONSTRAINT durable_pending_revision_digest_length CHECK (octet_length(envelope_digest) = 32),
    CONSTRAINT durable_pending_revision_envelope_length CHECK (octet_length(canonical_envelope) BETWEEN 1 AND 67108864),
    CONSTRAINT durable_pending_revision_evidence_count CHECK (evidence_count BETWEEN 0 AND 2048),
    CONSTRAINT durable_pending_revision_kind_evidence_shape CHECK (pending_kind <> 7 OR evidence_count BETWEEN 1 AND 2048),
    CONSTRAINT durable_pending_revision_status CHECK (status IN (1, 2)),
    CONSTRAINT durable_pending_revision_window CHECK (commit_not_before_unix_nano > 0 AND commit_not_after_unix_nano >= commit_not_before_unix_nano),
    CONSTRAINT durable_pending_revision_outcome_length CHECK (terminal_outcome_digest IS NULL OR octet_length(terminal_outcome_digest) = 32),
    CONSTRAINT durable_pending_revision_shape CHECK ((revision = 1 AND previous_envelope_digest IS NULL) OR (revision > 1 AND previous_envelope_digest IS NOT NULL)),
    CONSTRAINT durable_pending_revision_status_shape CHECK ((status = 1 AND terminal_outcome_digest IS NULL) OR (status = 2 AND terminal_outcome_digest IS NOT NULL)),
    CONSTRAINT durable_pending_revision_reconciliation_shape CHECK (pending_kind <> 4 OR (revision > 1 AND status = 2 AND previous_envelope_digest IS NOT NULL)),
    CONSTRAINT durable_pending_revision_event_length CHECK (octet_length(audit_event_id) BETWEEN 1 AND 1024),
    CONSTRAINT durable_pending_revision_uow_scope_length CHECK (octet_length(uow_scope_sha256) = 32),
    CONSTRAINT durable_pending_revision_uow_message_length CHECK (octet_length(uow_message_id) = 16)
);

CREATE TABLE cph_aiinfra.durable_pending_evidence (
    pending_key                  BYTEA NOT NULL,
    revision                     NUMERIC(20,0) NOT NULL,
    evidence_ordinal             SMALLINT NOT NULL,
    evidence_digest              BYTEA NOT NULL,
    audit_event_id               TEXT COLLATE "C" NOT NULL,
    uow_scope_sha256             BYTEA NOT NULL,
    uow_message_id               BYTEA NOT NULL,
    transaction_id               XID8 NOT NULL,
    recorded_at                  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT durable_pending_evidence_pk PRIMARY KEY (pending_key, revision, evidence_ordinal),
    CONSTRAINT durable_pending_evidence_digest_key UNIQUE (pending_key, revision, evidence_digest),
    CONSTRAINT durable_pending_evidence_revision_fk FOREIGN KEY (pending_key, revision)
        REFERENCES cph_aiinfra.durable_pending_revision(pending_key, revision)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT durable_pending_evidence_content_fk FOREIGN KEY (evidence_digest)
        REFERENCES cph_aiinfra.durable_evidence(evidence_digest) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT durable_pending_evidence_uow_fk FOREIGN KEY (uow_scope_sha256, uow_message_id)
        REFERENCES cph_aiinfra.authoritative_uow(scope_sha256, message_id) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT durable_pending_evidence_key_length CHECK (octet_length(pending_key) = 16),
    CONSTRAINT durable_pending_evidence_revision_range CHECK (revision BETWEEN 1 AND 18446744073709551615),
    CONSTRAINT durable_pending_evidence_ordinal_range CHECK (evidence_ordinal BETWEEN 1 AND 2048),
    CONSTRAINT durable_pending_evidence_digest_length CHECK (octet_length(evidence_digest) = 32),
    CONSTRAINT durable_pending_evidence_event_length CHECK (octet_length(audit_event_id) BETWEEN 1 AND 1024),
    CONSTRAINT durable_pending_evidence_uow_scope_length CHECK (octet_length(uow_scope_sha256) = 32),
    CONSTRAINT durable_pending_evidence_uow_message_length CHECK (octet_length(uow_message_id) = 16)
);

CREATE INDEX durable_pending_revision_event_idx
    ON cph_aiinfra.durable_pending_revision (audit_event_id);

CREATE TABLE cph_aiinfra.durable_evidence_assertion (
    uow_scope_sha256            BYTEA NOT NULL,
    uow_message_id              BYTEA NOT NULL,
    evidence_ordinal            SMALLINT NOT NULL,
    evidence_digest             BYTEA NOT NULL,
    pending_key                 BYTEA,
    pending_revision            NUMERIC(20,0),
    audit_event_id              TEXT COLLATE "C" NOT NULL,
    transaction_id              XID8 NOT NULL,
    recorded_at                 TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT durable_evidence_assertion_pk PRIMARY KEY (uow_scope_sha256, uow_message_id, evidence_ordinal),
    CONSTRAINT durable_evidence_assertion_digest_key UNIQUE (uow_scope_sha256, uow_message_id, evidence_digest),
    CONSTRAINT durable_evidence_assertion_uow_fk FOREIGN KEY (uow_scope_sha256, uow_message_id)
        REFERENCES cph_aiinfra.authoritative_uow(scope_sha256, message_id) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT durable_evidence_assertion_content_fk FOREIGN KEY (evidence_digest)
        REFERENCES cph_aiinfra.durable_evidence(evidence_digest) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT durable_evidence_assertion_pending_fk FOREIGN KEY (pending_key, pending_revision)
        REFERENCES cph_aiinfra.durable_pending_revision(pending_key, revision) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT durable_evidence_assertion_scope_length CHECK (octet_length(uow_scope_sha256) = 32),
    CONSTRAINT durable_evidence_assertion_message_length CHECK (octet_length(uow_message_id) = 16),
    CONSTRAINT durable_evidence_assertion_ordinal_range CHECK (evidence_ordinal BETWEEN 1 AND 2048),
    CONSTRAINT durable_evidence_assertion_digest_length CHECK (octet_length(evidence_digest) = 32),
    CONSTRAINT durable_evidence_assertion_pending_key_length CHECK (pending_key IS NULL OR octet_length(pending_key) = 16),
    CONSTRAINT durable_evidence_assertion_pending_shape CHECK (
        (pending_key IS NULL AND pending_revision IS NULL)
        OR
        (pending_key IS NOT NULL AND pending_revision BETWEEN 1 AND 18446744073709551615)
    ),
    CONSTRAINT durable_evidence_assertion_event_length CHECK (octet_length(audit_event_id) BETWEEN 1 AND 1024)
);

CREATE TABLE cph_aiinfra.canonical_state_head (
    state_namespace             SMALLINT NOT NULL,
    object_kind                 TEXT COLLATE "C" NOT NULL,
    object_id                   TEXT COLLATE "C" NOT NULL,
    version                     NUMERIC(20,0) NOT NULL,
    state_digest                BYTEA NOT NULL,
    content_type                TEXT COLLATE "C" NOT NULL,
    canonical_state             BYTEA NOT NULL,
    terminal                    BOOLEAN NOT NULL,
    valid_from_unix_nano        BIGINT,
    valid_until_unix_nano       BIGINT,
    audit_event_id              TEXT COLLATE "C" NOT NULL,
    uow_scope_sha256            BYTEA NOT NULL,
    uow_message_id              BYTEA NOT NULL,
    transaction_id              XID8 NOT NULL,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT canonical_state_head_pk PRIMARY KEY (state_namespace, object_kind, object_id),
    CONSTRAINT canonical_state_head_uow_fk FOREIGN KEY (uow_scope_sha256, uow_message_id)
        REFERENCES cph_aiinfra.authoritative_uow(scope_sha256, message_id) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT canonical_state_head_namespace CHECK (state_namespace IN (1, 2)),
    CONSTRAINT canonical_state_head_kind_length CHECK (octet_length(object_kind) BETWEEN 1 AND 255),
    CONSTRAINT canonical_state_head_id_length CHECK (octet_length(object_id) BETWEEN 1 AND 1024),
    CONSTRAINT canonical_state_head_version_range CHECK (version BETWEEN 1 AND 18446744073709551615),
    CONSTRAINT canonical_state_head_digest_length CHECK (octet_length(state_digest) = 32),
    CONSTRAINT canonical_state_head_content_type_length CHECK (octet_length(content_type) BETWEEN 1 AND 255),
    CONSTRAINT canonical_state_head_content_length CHECK (octet_length(canonical_state) BETWEEN 1 AND 67108864),
    CONSTRAINT canonical_state_head_kind_content_catalog CHECK (
        (state_namespace = 1 AND object_kind = 'cph.aiinfra.iam.key-material.v1'
            AND content_type = 'application/cph.aiinfra.iam.key-material-state.v1')
        OR (state_namespace = 1 AND object_kind = 'cph.aiinfra.iam.identity.v1'
            AND content_type = 'application/cph.aiinfra.iam.identity-state.v1')
        OR (state_namespace = 1 AND object_kind = 'cph.aiinfra.iam.key-lifecycle.v1'
            AND content_type = 'application/cph.aiinfra.iam.key-lifecycle-state.v1')
        OR (state_namespace = 1 AND object_kind = 'cph.aiinfra.iam.accepted-ownership-transfer.v1'
            AND content_type = 'application/cph.aiinfra.iam.accepted-ownership-transfer-state.v1')
        OR (state_namespace = 1 AND object_kind = 'cph.aiinfra.iam.proof-challenge.v1'
            AND content_type = 'application/cph.aiinfra.iam.proof-challenge-state.v1')
        OR (state_namespace = 1 AND object_kind = 'cph.aiinfra.iam.principal-identity-index.v1'
            AND content_type = 'application/cph.aiinfra.iam.principal-identity-index-state.v1')
        OR (state_namespace = 1 AND object_kind = 'cph.aiinfra.iam.rotation-predecessor-index.v1'
            AND content_type = 'application/cph.aiinfra.iam.rotation-predecessor-index-state.v1')
        OR (state_namespace = 1 AND object_kind = 'cph.aiinfra.iam.subject-key-set.v1'
            AND content_type = 'application/cph.aiinfra.iam.subject-key-set-state.v1')
        OR (state_namespace = 1 AND object_kind = 'cph.aiinfra.iam.writer-lease.v1'
            AND content_type = 'application/cph.aiinfra.iam.writer-lease-state.v1')
        OR (state_namespace = 1 AND object_kind = 'cph.aiinfra.iam.ownership-transfer-profile-activation.v1'
            AND content_type = 'application/cph.aiinfra.iam.ownership-transfer-profile-activation-state.v1')
        OR (state_namespace = 2 AND object_kind = 'cph.aiinfra.governance.policy-registry.v1'
            AND content_type = 'application/cph.aiinfra.governance.policy-registry-state.v1')
        OR (state_namespace = 2 AND object_kind = 'cph.aiinfra.governance.profile-activation.v1'
            AND content_type = 'application/cph.aiinfra.governance.profile-activation-state.v1')
    ),
    CONSTRAINT canonical_state_head_validity_shape CHECK (
        (object_kind IN (
            'cph.aiinfra.iam.ownership-transfer-profile-activation.v1',
            'cph.aiinfra.governance.profile-activation.v1'
        ) AND valid_from_unix_nano IS NOT NULL AND valid_until_unix_nano IS NOT NULL
            AND valid_from_unix_nano >= 0 AND valid_until_unix_nano > valid_from_unix_nano)
        OR
        (object_kind NOT IN (
            'cph.aiinfra.iam.ownership-transfer-profile-activation.v1',
            'cph.aiinfra.governance.profile-activation.v1'
        ) AND valid_from_unix_nano IS NULL AND valid_until_unix_nano IS NULL)
    ),
    CONSTRAINT canonical_state_head_event_length CHECK (octet_length(audit_event_id) BETWEEN 1 AND 1024),
    CONSTRAINT canonical_state_head_uow_scope_length CHECK (octet_length(uow_scope_sha256) = 32),
    CONSTRAINT canonical_state_head_uow_message_length CHECK (octet_length(uow_message_id) = 16)
);

CREATE TABLE cph_aiinfra.canonical_state_history (
    state_namespace             SMALLINT NOT NULL,
    object_kind                 TEXT COLLATE "C" NOT NULL,
    object_id                   TEXT COLLATE "C" NOT NULL,
    version                     NUMERIC(20,0) NOT NULL,
    state_digest                BYTEA NOT NULL,
    content_type                TEXT COLLATE "C" NOT NULL,
    canonical_state             BYTEA NOT NULL,
    terminal                    BOOLEAN NOT NULL,
    valid_from_unix_nano        BIGINT,
    valid_until_unix_nano       BIGINT,
    audit_event_id              TEXT COLLATE "C" NOT NULL,
    uow_scope_sha256            BYTEA NOT NULL,
    uow_message_id              BYTEA NOT NULL,
    transaction_id              XID8 NOT NULL,
    recorded_at                 TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT canonical_state_history_pk PRIMARY KEY (state_namespace, object_kind, object_id, version),
    CONSTRAINT canonical_state_history_head_fk FOREIGN KEY (state_namespace, object_kind, object_id)
        REFERENCES cph_aiinfra.canonical_state_head(state_namespace, object_kind, object_id)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT canonical_state_history_uow_fk FOREIGN KEY (uow_scope_sha256, uow_message_id)
        REFERENCES cph_aiinfra.authoritative_uow(scope_sha256, message_id) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT canonical_state_history_namespace CHECK (state_namespace IN (1, 2)),
    CONSTRAINT canonical_state_history_kind_length CHECK (octet_length(object_kind) BETWEEN 1 AND 255),
    CONSTRAINT canonical_state_history_id_length CHECK (octet_length(object_id) BETWEEN 1 AND 1024),
    CONSTRAINT canonical_state_history_version_range CHECK (version BETWEEN 1 AND 18446744073709551615),
    CONSTRAINT canonical_state_history_digest_length CHECK (octet_length(state_digest) = 32),
    CONSTRAINT canonical_state_history_content_type_length CHECK (octet_length(content_type) BETWEEN 1 AND 255),
    CONSTRAINT canonical_state_history_content_length CHECK (octet_length(canonical_state) BETWEEN 1 AND 67108864),
    CONSTRAINT canonical_state_history_kind_content_catalog CHECK (
        (state_namespace = 1 AND object_kind = 'cph.aiinfra.iam.key-material.v1'
            AND content_type = 'application/cph.aiinfra.iam.key-material-state.v1')
        OR (state_namespace = 1 AND object_kind = 'cph.aiinfra.iam.identity.v1'
            AND content_type = 'application/cph.aiinfra.iam.identity-state.v1')
        OR (state_namespace = 1 AND object_kind = 'cph.aiinfra.iam.key-lifecycle.v1'
            AND content_type = 'application/cph.aiinfra.iam.key-lifecycle-state.v1')
        OR (state_namespace = 1 AND object_kind = 'cph.aiinfra.iam.accepted-ownership-transfer.v1'
            AND content_type = 'application/cph.aiinfra.iam.accepted-ownership-transfer-state.v1')
        OR (state_namespace = 1 AND object_kind = 'cph.aiinfra.iam.proof-challenge.v1'
            AND content_type = 'application/cph.aiinfra.iam.proof-challenge-state.v1')
        OR (state_namespace = 1 AND object_kind = 'cph.aiinfra.iam.principal-identity-index.v1'
            AND content_type = 'application/cph.aiinfra.iam.principal-identity-index-state.v1')
        OR (state_namespace = 1 AND object_kind = 'cph.aiinfra.iam.rotation-predecessor-index.v1'
            AND content_type = 'application/cph.aiinfra.iam.rotation-predecessor-index-state.v1')
        OR (state_namespace = 1 AND object_kind = 'cph.aiinfra.iam.subject-key-set.v1'
            AND content_type = 'application/cph.aiinfra.iam.subject-key-set-state.v1')
        OR (state_namespace = 1 AND object_kind = 'cph.aiinfra.iam.writer-lease.v1'
            AND content_type = 'application/cph.aiinfra.iam.writer-lease-state.v1')
        OR (state_namespace = 1 AND object_kind = 'cph.aiinfra.iam.ownership-transfer-profile-activation.v1'
            AND content_type = 'application/cph.aiinfra.iam.ownership-transfer-profile-activation-state.v1')
        OR (state_namespace = 2 AND object_kind = 'cph.aiinfra.governance.policy-registry.v1'
            AND content_type = 'application/cph.aiinfra.governance.policy-registry-state.v1')
        OR (state_namespace = 2 AND object_kind = 'cph.aiinfra.governance.profile-activation.v1'
            AND content_type = 'application/cph.aiinfra.governance.profile-activation-state.v1')
    ),
    CONSTRAINT canonical_state_history_validity_shape CHECK (
        (object_kind IN (
            'cph.aiinfra.iam.ownership-transfer-profile-activation.v1',
            'cph.aiinfra.governance.profile-activation.v1'
        ) AND valid_from_unix_nano IS NOT NULL AND valid_until_unix_nano IS NOT NULL
            AND valid_from_unix_nano >= 0 AND valid_until_unix_nano > valid_from_unix_nano)
        OR
        (object_kind NOT IN (
            'cph.aiinfra.iam.ownership-transfer-profile-activation.v1',
            'cph.aiinfra.governance.profile-activation.v1'
        ) AND valid_from_unix_nano IS NULL AND valid_until_unix_nano IS NULL)
    ),
    CONSTRAINT canonical_state_history_event_length CHECK (octet_length(audit_event_id) BETWEEN 1 AND 1024),
    CONSTRAINT canonical_state_history_uow_scope_length CHECK (octet_length(uow_scope_sha256) = 32),
    CONSTRAINT canonical_state_history_uow_message_length CHECK (octet_length(uow_message_id) = 16)
);

CREATE INDEX canonical_state_history_event_idx
    ON cph_aiinfra.canonical_state_history (audit_event_id);

CREATE FUNCTION cph_aiinfra.assert_authoritative_uow()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $cph$
DECLARE
    result_transaction XID8;
    result_content_type TEXT;
    result_payload BYTEA;
    inbox_transaction XID8;
    inbox_outcome BYTEA;
    assertion_count BIGINT;
BEGIN
    SELECT transaction_id, content_type, payload
      INTO result_transaction, result_content_type, result_payload
      FROM cph_aiinfra.ccse_durable_result
     WHERE scope_sha256 = NEW.scope_sha256
       AND message_id = NEW.message_id
       AND result_digest = NEW.outcome_digest;
    SELECT transaction_id, outcome_digest INTO inbox_transaction, inbox_outcome
      FROM cph_aiinfra.ccse_replay_inbox
     WHERE scope_sha256 = NEW.scope_sha256 AND message_id = NEW.message_id;
    IF result_transaction IS NULL OR inbox_transaction IS NULL
       OR result_transaction IS DISTINCT FROM NEW.transaction_id
       OR inbox_transaction IS DISTINCT FROM NEW.transaction_id
       OR inbox_outcome IS DISTINCT FROM NEW.outcome_digest
       OR result_content_type IS DISTINCT FROM NEW.result_content_type
       OR result_payload IS DISTINCT FROM NEW.result_payload THEN
        RAISE EXCEPTION 'authoritative UoW must share the exact CCSE inbox/result receipt'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.uow_kind = 2 AND NOT EXISTS (
        SELECT 1 FROM cph_aiinfra.audit_event
         WHERE event_id = NEW.audit_event_id
           AND scope_sha256 = NEW.scope_sha256
           AND message_id = NEW.message_id
           AND transaction_id = NEW.transaction_id
    ) THEN
        RAISE EXCEPTION 'audited-final UoW has no exact same-transaction AuditEvent'
            USING ERRCODE = '23514';
    END IF;
    SELECT count(*) INTO assertion_count
      FROM cph_aiinfra.durable_evidence_assertion assertion
     WHERE assertion.uow_scope_sha256 = NEW.scope_sha256
       AND assertion.uow_message_id = NEW.message_id
       AND assertion.transaction_id = NEW.transaction_id;
    IF assertion_count <> NEW.evidence_assertion_count THEN
        RAISE EXCEPTION 'authoritative UoW evidence assertion count differs'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$cph$;

CREATE FUNCTION cph_aiinfra.assert_audit_uow_member()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $cph$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM cph_aiinfra.authoritative_uow
         WHERE scope_sha256 = NEW.uow_scope_sha256
           AND message_id = NEW.uow_message_id
           AND transaction_id = NEW.transaction_id
    ) THEN
        RAISE EXCEPTION 'canonical row must share its authoritative UoW receipt and transaction'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$cph$;

CREATE FUNCTION cph_aiinfra.assert_audit_event_uow()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $cph$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM cph_aiinfra.authoritative_uow uow
          JOIN cph_aiinfra.ccse_replay_inbox inbox
            ON inbox.scope_sha256 = uow.scope_sha256
           AND inbox.message_id = uow.message_id
           AND inbox.transaction_id = uow.transaction_id
         WHERE uow.scope_sha256 = NEW.scope_sha256
           AND uow.message_id = NEW.message_id
           AND uow.uow_kind = 2
           AND uow.audit_event_id = NEW.event_id
           AND uow.transaction_id = NEW.transaction_id
           AND inbox.message_type_id = 65547
           AND inbox.schema_major = 1
           AND inbox.schema_minor = 0
           AND inbox.record_digest = NEW.record_digest
    ) THEN
        RAISE EXCEPTION 'AuditEvent is not the exact outer replay record of its audited-final UoW'
            USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
        SELECT 1
          FROM cph_aiinfra.global_identifier_claim claim
          JOIN cph_aiinfra.global_identifier_head head
            ON head.identifier = claim.identifier
           AND head.owner_domain = claim.next_owner_domain
           AND head.owner_id = claim.next_owner_id
           AND head.version = claim.next_version
         WHERE claim.identifier = NEW.event_id
           AND claim.next_owner_domain = 'cph.aiinfra.governance.audit-event.v1'
           AND claim.next_owner_id = NEW.event_id
           AND claim.audit_event_id = NEW.event_id
           AND claim.uow_scope_sha256 = NEW.scope_sha256
           AND claim.uow_message_id = NEW.message_id
           AND claim.transaction_id = NEW.transaction_id
    ) THEN
        RAISE EXCEPTION 'AuditEvent identifier is not globally asserted by its UoW'
            USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM cph_aiinfra.audit_head
         WHERE stream_id = NEW.stream_id
           AND highest_sequence = NEW.audit_sequence
           AND latest_record_digest = NEW.record_digest
           AND audit_event_id = NEW.event_id
           AND uow_scope_sha256 = NEW.scope_sha256
           AND uow_message_id = NEW.message_id
           AND transaction_id = NEW.transaction_id
    ) THEN
        RAISE EXCEPTION 'AuditEvent has no exact same-transaction audit head'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$cph$;

CREATE FUNCTION cph_aiinfra.enforce_audit_head_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $cph$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'audit head cannot be deleted' USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.highest_sequence <> 1 THEN
            RAISE EXCEPTION 'new audit stream must start at sequence one' USING ERRCODE = '23514';
        END IF;
        NEW.transaction_id := pg_current_xact_id();
        NEW.updated_at := clock_timestamp();
        RETURN NEW;
    END IF;
    IF NEW.stream_id IS DISTINCT FROM OLD.stream_id
       OR NEW.deployment_anchor_digest IS DISTINCT FROM OLD.deployment_anchor_digest
       OR NEW.highest_sequence <> OLD.highest_sequence + 1
       OR NEW.latest_record_digest IS NOT DISTINCT FROM OLD.latest_record_digest
       OR NEW.audit_event_id IS NOT DISTINCT FROM OLD.audit_event_id THEN
        RAISE EXCEPTION 'audit head must advance exactly once to a new event'
            USING ERRCODE = '23514';
    END IF;
    NEW.transaction_id := pg_current_xact_id();
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END;
$cph$;

CREATE FUNCTION cph_aiinfra.assert_audit_head_event()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $cph$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM cph_aiinfra.audit_event
         WHERE event_id = NEW.audit_event_id
           AND stream_id = NEW.stream_id
           AND audit_sequence = NEW.highest_sequence
           AND record_digest = NEW.latest_record_digest
           AND scope_sha256 = NEW.uow_scope_sha256
           AND message_id = NEW.uow_message_id
           AND transaction_id = NEW.transaction_id
           AND ((TG_OP = 'INSERT' AND previous_event_digest IS NULL)
                OR (TG_OP = 'UPDATE' AND previous_event_digest = OLD.latest_record_digest))
    ) THEN
        RAISE EXCEPTION 'audit head is not coupled to the exact next AuditEvent'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$cph$;

CREATE FUNCTION cph_aiinfra.enforce_business_idempotency_head_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $cph$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'business idempotency head cannot be deleted' USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.version <> 1 THEN
            RAISE EXCEPTION 'business idempotency row must start at version one' USING ERRCODE = '23514';
        END IF;
        NEW.transaction_id := pg_current_xact_id();
        NEW.updated_at := clock_timestamp();
        RETURN NEW;
    END IF;
    IF OLD.state = 2
       OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
       OR NEW.row_kind IS DISTINCT FROM OLD.row_kind
       OR NEW.operation_domain IS DISTINCT FROM OLD.operation_domain
       OR NEW.owner_id IS DISTINCT FROM OLD.owner_id
       OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
       OR NEW.binding_digest IS DISTINCT FROM OLD.binding_digest
       OR NEW.parent_key IS DISTINCT FROM OLD.parent_key
       OR NEW.parent_operation_domain IS DISTINCT FROM OLD.parent_operation_domain
       OR NEW.parent_owner_id IS DISTINCT FROM OLD.parent_owner_id
       OR NEW.parent_request_digest IS DISTINCT FROM OLD.parent_request_digest
       OR NEW.audit_event_id IS DISTINCT FROM OLD.audit_event_id
       OR NEW.version <> OLD.version + 1
       OR (OLD.state = 1 AND NEW.state = 1 AND NEW.progress_digest IS NOT DISTINCT FROM OLD.progress_digest)
       OR (OLD.state = 1 AND NEW.state = 2 AND NEW.progress_digest IS DISTINCT FROM OLD.progress_digest) THEN
        RAISE EXCEPTION 'business idempotency transition is not monotonic'
            USING ERRCODE = '23514';
    END IF;
    NEW.transaction_id := pg_current_xact_id();
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END;
$cph$;

CREATE FUNCTION cph_aiinfra.assert_business_idempotency_consistency()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $cph$
DECLARE
    pair_count BIGINT;
    member_count BIGINT;
BEGIN
    IF TG_TABLE_NAME = 'business_idempotency_head' THEN
        IF NOT EXISTS (
            SELECT 1 FROM cph_aiinfra.business_idempotency_history history
             WHERE history.idempotency_key = NEW.idempotency_key
               AND history.version = NEW.version
               AND history.row_kind = NEW.row_kind
               AND history.operation_domain = NEW.operation_domain
               AND history.owner_id = NEW.owner_id
               AND history.request_digest = NEW.request_digest
               AND history.binding_digest = NEW.binding_digest
               AND history.parent_key IS NOT DISTINCT FROM NEW.parent_key
               AND history.parent_operation_domain IS NOT DISTINCT FROM NEW.parent_operation_domain
               AND history.parent_owner_id IS NOT DISTINCT FROM NEW.parent_owner_id
               AND history.parent_request_digest IS NOT DISTINCT FROM NEW.parent_request_digest
               AND history.state = NEW.state
               AND history.progress_digest IS NOT DISTINCT FROM NEW.progress_digest
               AND history.outcome_digest IS NOT DISTINCT FROM NEW.outcome_digest
               AND history.audit_event_id = NEW.audit_event_id
               AND history.uow_scope_sha256 = NEW.uow_scope_sha256
               AND history.uow_message_id = NEW.uow_message_id
               AND history.transaction_id = NEW.transaction_id
        ) THEN
            RAISE EXCEPTION 'business idempotency head has no exact same-transaction history'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NOT EXISTS (
        SELECT 1 FROM cph_aiinfra.business_idempotency_head head
         WHERE head.idempotency_key = NEW.idempotency_key
           AND head.version = NEW.version
           AND head.row_kind = NEW.row_kind
           AND head.operation_domain = NEW.operation_domain
           AND head.owner_id = NEW.owner_id
           AND head.request_digest = NEW.request_digest
           AND head.binding_digest = NEW.binding_digest
           AND head.parent_key IS NOT DISTINCT FROM NEW.parent_key
           AND head.parent_operation_domain IS NOT DISTINCT FROM NEW.parent_operation_domain
           AND head.parent_owner_id IS NOT DISTINCT FROM NEW.parent_owner_id
           AND head.parent_request_digest IS NOT DISTINCT FROM NEW.parent_request_digest
           AND head.state = NEW.state
           AND head.progress_digest IS NOT DISTINCT FROM NEW.progress_digest
           AND head.outcome_digest IS NOT DISTINCT FROM NEW.outcome_digest
           AND head.audit_event_id = NEW.audit_event_id
           AND head.uow_scope_sha256 = NEW.uow_scope_sha256
           AND head.uow_message_id = NEW.uow_message_id
           AND head.transaction_id = NEW.transaction_id
    ) THEN
        RAISE EXCEPTION 'business idempotency history has no exact same-transaction head'
            USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM cph_aiinfra.authoritative_uow uow
         WHERE uow.scope_sha256 = NEW.uow_scope_sha256
           AND uow.message_id = NEW.uow_message_id
           AND uow.transaction_id = NEW.transaction_id
           AND ((NEW.state = 1 AND (
                    (uow.uow_kind = 1 AND uow.audit_event_id IS NULL)
                    OR
                    (uow.uow_kind = 2 AND uow.audit_event_id IS NOT NULL
                        AND uow.audit_event_id <> NEW.audit_event_id)
                ))
                OR (NEW.state = 2 AND uow.uow_kind = 2
                    AND uow.audit_event_id = NEW.audit_event_id
                    AND uow.outcome_digest = NEW.outcome_digest))
    ) THEN
        RAISE EXCEPTION 'business idempotency phase does not match its authoritative UoW'
            USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
        SELECT 1
          FROM cph_aiinfra.global_identifier_claim claim
          JOIN cph_aiinfra.global_identifier_head head
            ON head.identifier = claim.identifier
           AND head.owner_domain = claim.next_owner_domain
           AND head.owner_id = claim.next_owner_id
           AND head.version = claim.next_version
         WHERE claim.identifier = NEW.audit_event_id
           AND claim.next_owner_domain = 'cph.aiinfra.governance.audit-event.v1'
           AND claim.next_owner_id = NEW.audit_event_id
           AND claim.audit_event_id = NEW.audit_event_id
           AND claim.uow_scope_sha256 = NEW.uow_scope_sha256
           AND claim.uow_message_id = NEW.uow_message_id
           AND claim.transaction_id = NEW.transaction_id
    ) THEN
        RAISE EXCEPTION 'business idempotency expected AuditEvent is not globally reserved by this UoW'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.row_kind = 1 AND NEW.operation_domain IN (
        'cph.aiinfra.iam.key-enrollment.v1',
        'cph.aiinfra.iam.identity.v1',
        'cph.aiinfra.iam.key-lifecycle.v1',
        'cph.aiinfra.iam.ownership-transfer.v1',
        'cph.aiinfra.iam.ownership-transfer-cutover.v1',
        'cph.aiinfra.governance.policy.v1'
    ) THEN
        IF NOT EXISTS (
            SELECT 1 FROM cph_aiinfra.durable_pending_head pending
             WHERE pending.pending_key = NEW.idempotency_key
               AND pending.audit_event_id = NEW.audit_event_id
               AND pending.uow_scope_sha256 = NEW.uow_scope_sha256
               AND pending.uow_message_id = NEW.uow_message_id
               AND pending.transaction_id = NEW.transaction_id
               AND ((NEW.state = 1 AND pending.status = 1
                    AND pending.pending_kind = CASE NEW.operation_domain
                        WHEN 'cph.aiinfra.iam.key-enrollment.v1' THEN 2
                        WHEN 'cph.aiinfra.iam.identity.v1' THEN 1
                        WHEN 'cph.aiinfra.iam.key-lifecycle.v1' THEN 1
                        WHEN 'cph.aiinfra.iam.ownership-transfer.v1' THEN 3
                        WHEN 'cph.aiinfra.iam.ownership-transfer-cutover.v1' THEN 5
                        WHEN 'cph.aiinfra.governance.policy.v1' THEN 7
                    END)
                    OR (NEW.state = 2 AND pending.status = 2
                        AND pending.terminal_outcome_digest = NEW.outcome_digest
                        AND (pending.pending_kind = CASE NEW.operation_domain
                                WHEN 'cph.aiinfra.iam.key-enrollment.v1' THEN 2
                                WHEN 'cph.aiinfra.iam.identity.v1' THEN 1
                                WHEN 'cph.aiinfra.iam.key-lifecycle.v1' THEN 1
                                WHEN 'cph.aiinfra.iam.ownership-transfer.v1' THEN 3
                                WHEN 'cph.aiinfra.iam.ownership-transfer-cutover.v1' THEN 5
                                WHEN 'cph.aiinfra.governance.policy.v1' THEN 7
                            END
                            OR (pending.pending_kind = 4 AND EXISTS (
                                SELECT 1 FROM cph_aiinfra.durable_pending_revision original
                                 WHERE original.pending_key = pending.pending_key
                                   AND original.revision = pending.revision - 1
                                   AND original.pending_kind = CASE NEW.operation_domain
                                        WHEN 'cph.aiinfra.iam.key-enrollment.v1' THEN 2
                                        WHEN 'cph.aiinfra.iam.identity.v1' THEN 1
                                        WHEN 'cph.aiinfra.iam.key-lifecycle.v1' THEN 1
                                        WHEN 'cph.aiinfra.iam.ownership-transfer.v1' THEN 3
                                        WHEN 'cph.aiinfra.iam.ownership-transfer-cutover.v1' THEN 5
                                    END
                                   AND original.status = 1
                                   AND original.terminal_outcome_digest IS NULL
                                   AND original.envelope_digest = pending.previous_envelope_digest
                                   AND original.audit_event_id = pending.audit_event_id
                            )))) )
        ) THEN
            RAISE EXCEPTION 'joined ordinary idempotency row has no exact recoverable pending state'
                USING ERRCODE = '23514';
        END IF;
        SELECT count(*) INTO pair_count
          FROM cph_aiinfra.business_idempotency_head joined_row
         WHERE joined_row.row_kind = 2
           AND joined_row.parent_key = NEW.idempotency_key
           AND joined_row.parent_operation_domain = NEW.operation_domain
           AND joined_row.parent_owner_id = NEW.owner_id
           AND joined_row.parent_request_digest = NEW.request_digest
           AND joined_row.state = NEW.state
           AND joined_row.version = CASE WHEN NEW.state = 1 THEN 1 ELSE 2 END
           AND joined_row.audit_event_id = NEW.audit_event_id
           AND (NEW.state <> 1 OR NEW.version <> 1 OR joined_row.transaction_id = NEW.transaction_id)
           AND (NEW.state <> 2 OR (
               joined_row.outcome_digest = NEW.outcome_digest
               AND joined_row.transaction_id = NEW.transaction_id
           ));
        IF pair_count <> 1 THEN
            RAISE EXCEPTION 'ordinary idempotency row has no exact joined-audit pair'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.operation_domain = 'cph.aiinfra.iam.ownership-transfer-cutover.v1' THEN
            SELECT count(*) INTO member_count
              FROM cph_aiinfra.business_idempotency_head member_row
             WHERE member_row.row_kind = 3
               AND member_row.parent_key = NEW.idempotency_key
               AND member_row.parent_operation_domain = NEW.operation_domain
               AND member_row.parent_owner_id = NEW.owner_id
               AND member_row.parent_request_digest = NEW.request_digest;
            IF member_count = 0 OR EXISTS (
                SELECT 1 FROM cph_aiinfra.business_idempotency_head member_row
                 WHERE member_row.row_kind = 3
                   AND member_row.parent_key = NEW.idempotency_key
                   AND member_row.parent_operation_domain = NEW.operation_domain
                   AND member_row.parent_owner_id = NEW.owner_id
                   AND member_row.parent_request_digest = NEW.request_digest
                   AND (member_row.state <> NEW.state
                        OR member_row.audit_event_id <> NEW.audit_event_id
                        OR member_row.transaction_id <> NEW.transaction_id
                        OR (NEW.state = 2 AND (
                            member_row.outcome_digest <> NEW.outcome_digest
                        )))
            ) THEN
                RAISE EXCEPTION 'compound umbrella has no complete exact member set'
                    USING ERRCODE = '23514';
            END IF;
        END IF;
    ELSIF NEW.row_kind = 2 THEN
        SELECT count(*) INTO pair_count
          FROM cph_aiinfra.business_idempotency_head parent_row
         WHERE parent_row.row_kind = 1
           AND parent_row.idempotency_key = NEW.parent_key
           AND parent_row.operation_domain = NEW.parent_operation_domain
           AND parent_row.owner_id = NEW.parent_owner_id
           AND parent_row.request_digest = NEW.parent_request_digest
           AND parent_row.binding_digest = NEW.progress_digest
           AND parent_row.state = NEW.state
           AND parent_row.version >= CASE WHEN NEW.state = 1 THEN 1 ELSE 2 END
           AND parent_row.audit_event_id = NEW.audit_event_id
           AND parent_row.transaction_id = NEW.transaction_id
           AND (NEW.state <> 2 OR (
               parent_row.outcome_digest = NEW.outcome_digest
           ));
        IF pair_count <> 1 THEN
            RAISE EXCEPTION 'joined-audit row has no exact ordinary parent'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.row_kind = 3 THEN
        SELECT count(*) INTO pair_count
          FROM cph_aiinfra.business_idempotency_head parent_row
          JOIN cph_aiinfra.business_idempotency_head joined_row
            ON joined_row.row_kind = 2
           AND joined_row.parent_key = parent_row.idempotency_key
           AND joined_row.parent_operation_domain = parent_row.operation_domain
           AND joined_row.parent_owner_id = parent_row.owner_id
           AND joined_row.parent_request_digest = parent_row.request_digest
         WHERE parent_row.row_kind = 1
           AND parent_row.idempotency_key = NEW.parent_key
           AND parent_row.operation_domain = NEW.parent_operation_domain
           AND parent_row.owner_id = NEW.parent_owner_id
           AND parent_row.request_digest = NEW.parent_request_digest
           AND parent_row.operation_domain = 'cph.aiinfra.iam.ownership-transfer-cutover.v1'
           AND parent_row.state = NEW.state
           AND joined_row.state = NEW.state
           AND parent_row.version = NEW.version
           AND joined_row.version = NEW.version
           AND parent_row.audit_event_id = NEW.audit_event_id
           AND joined_row.audit_event_id = NEW.audit_event_id
           AND parent_row.transaction_id = NEW.transaction_id
           AND joined_row.transaction_id = NEW.transaction_id
           AND (NEW.state <> 2 OR (
               parent_row.outcome_digest = NEW.outcome_digest
               AND joined_row.outcome_digest = NEW.outcome_digest
           ));
        IF pair_count <> 1 THEN
            RAISE EXCEPTION 'compound member has no exact umbrella X/Y state'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NULL;
END;
$cph$;

CREATE FUNCTION cph_aiinfra.enforce_global_identifier_head_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $cph$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'global identifier head cannot be deleted' USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.version <> 1 OR NEW.transfer_evidence_digest IS NOT NULL THEN
            RAISE EXCEPTION 'global identifier reservation must start at version one'
                USING ERRCODE = '23514';
        END IF;
        NEW.transaction_id := pg_current_xact_id();
        NEW.updated_at := clock_timestamp();
        RETURN NEW;
    END IF;
    IF NEW.identifier IS DISTINCT FROM OLD.identifier
       OR NEW.owner_domain IS DISTINCT FROM OLD.owner_domain
       OR OLD.owner_domain <> 'cph.aiinfra.iam.identity.v1'
       OR NEW.owner_id IS NOT DISTINCT FROM OLD.owner_id
       OR NEW.version <> OLD.version + 1
       OR NEW.transfer_evidence_digest IS NULL THEN
        RAISE EXCEPTION 'global identifier transfer is not an evidenced IAM identity transition'
            USING ERRCODE = '23514';
    END IF;
    NEW.transaction_id := pg_current_xact_id();
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END;
$cph$;

CREATE FUNCTION cph_aiinfra.assert_global_identifier_consistency()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $cph$
BEGIN
    IF TG_TABLE_NAME = 'global_identifier_head' THEN
        IF NOT EXISTS (
            SELECT 1 FROM cph_aiinfra.global_identifier_history history
             WHERE history.identifier = NEW.identifier
               AND history.version = NEW.version
               AND history.owner_domain = NEW.owner_domain
               AND history.owner_id = NEW.owner_id
               AND history.transfer_evidence_digest IS NOT DISTINCT FROM NEW.transfer_evidence_digest
               AND history.audit_event_id = NEW.audit_event_id
               AND history.uow_scope_sha256 = NEW.uow_scope_sha256
               AND history.uow_message_id = NEW.uow_message_id
               AND history.transaction_id = NEW.transaction_id
        ) THEN
            RAISE EXCEPTION 'global identifier head has no exact same-transaction history'
                USING ERRCODE = '23514';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM cph_aiinfra.global_identifier_claim claim
             WHERE claim.identifier = NEW.identifier
               AND claim.claim_mode = CASE WHEN NEW.version = 1 THEN 1 ELSE 3 END
               AND claim.next_owner_domain = NEW.owner_domain
               AND claim.next_owner_id = NEW.owner_id
               AND claim.next_version = NEW.version
               AND claim.transfer_evidence_digest IS NOT DISTINCT FROM NEW.transfer_evidence_digest
               AND claim.audit_event_id = NEW.audit_event_id
               AND claim.uow_scope_sha256 = NEW.uow_scope_sha256
               AND claim.uow_message_id = NEW.uow_message_id
               AND claim.transaction_id = NEW.transaction_id
        ) THEN
            RAISE EXCEPTION 'global identifier head has no exact same-transaction mutating claim'
                USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'global_identifier_history' THEN
        IF NOT EXISTS (
            SELECT 1 FROM cph_aiinfra.global_identifier_head head
             WHERE head.identifier = NEW.identifier
               AND head.version = NEW.version
               AND head.owner_domain = NEW.owner_domain
               AND head.owner_id = NEW.owner_id
               AND head.transfer_evidence_digest IS NOT DISTINCT FROM NEW.transfer_evidence_digest
               AND head.audit_event_id = NEW.audit_event_id
               AND head.uow_scope_sha256 = NEW.uow_scope_sha256
               AND head.uow_message_id = NEW.uow_message_id
               AND head.transaction_id = NEW.transaction_id
        ) THEN
            RAISE EXCEPTION 'global identifier history has no exact same-transaction head'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        IF NOT EXISTS (
            SELECT 1 FROM cph_aiinfra.global_identifier_head head
             WHERE head.identifier = NEW.identifier
               AND head.owner_domain = NEW.next_owner_domain
               AND head.owner_id = NEW.next_owner_id
               AND head.version = NEW.next_version
        ) THEN
            RAISE EXCEPTION 'global identifier claim does not match the authoritative head'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.claim_mode IN (1, 3) AND NOT EXISTS (
            SELECT 1 FROM cph_aiinfra.global_identifier_history history
             WHERE history.identifier = NEW.identifier
               AND history.version = NEW.next_version
               AND history.owner_domain = NEW.next_owner_domain
               AND history.owner_id = NEW.next_owner_id
               AND history.transfer_evidence_digest IS NOT DISTINCT FROM NEW.transfer_evidence_digest
               AND history.audit_event_id = NEW.audit_event_id
               AND history.uow_scope_sha256 = NEW.uow_scope_sha256
               AND history.uow_message_id = NEW.uow_message_id
               AND history.transaction_id = NEW.transaction_id
        ) THEN
            RAISE EXCEPTION 'mutating global identifier claim has no exact history'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.claim_mode = 3 AND NOT EXISTS (
            SELECT 1 FROM cph_aiinfra.global_identifier_history history
             WHERE history.identifier = NEW.identifier
               AND history.version = NEW.expected_version
               AND history.owner_domain = NEW.expected_owner_domain
               AND history.owner_id = NEW.expected_owner_id
        ) THEN
            RAISE EXCEPTION 'global identifier transfer claim has no exact immutable predecessor'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    IF TG_TABLE_NAME IN ('global_identifier_head', 'global_identifier_history') THEN
        IF NEW.version > 1 AND NOT EXISTS (
            SELECT 1 FROM cph_aiinfra.authoritative_uow uow
             WHERE uow.scope_sha256 = NEW.uow_scope_sha256
               AND uow.message_id = NEW.uow_message_id
               AND uow.uow_kind = 2
               AND uow.audit_event_id = NEW.audit_event_id
               AND uow.transaction_id = NEW.transaction_id
        ) THEN
            RAISE EXCEPTION 'global identifier transfer requires an audited-final UoW'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.claim_mode = 3 AND NOT EXISTS (
        SELECT 1 FROM cph_aiinfra.authoritative_uow uow
         WHERE uow.scope_sha256 = NEW.uow_scope_sha256
           AND uow.message_id = NEW.uow_message_id
           AND uow.uow_kind = 2
           AND uow.audit_event_id = NEW.audit_event_id
           AND uow.transaction_id = NEW.transaction_id
    ) THEN
        RAISE EXCEPTION 'global identifier transfer claim requires an audited-final UoW'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$cph$;

CREATE FUNCTION cph_aiinfra.enforce_durable_pending_head_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $cph$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'durable pending head cannot be deleted' USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.revision <> 1 OR NEW.pending_kind = 4 THEN
            RAISE EXCEPTION 'durable pending row must start at revision one' USING ERRCODE = '23514';
        END IF;
        NEW.transaction_id := pg_current_xact_id();
        NEW.updated_at := clock_timestamp();
        RETURN NEW;
    END IF;
    IF OLD.status = 2
       OR NEW.pending_key IS DISTINCT FROM OLD.pending_key
       OR NEW.codec IS DISTINCT FROM OLD.codec
       OR NEW.codec_version IS DISTINCT FROM OLD.codec_version
       OR NEW.audit_event_id IS DISTINCT FROM OLD.audit_event_id
       OR NEW.revision <> OLD.revision + 1
       OR NEW.previous_envelope_digest IS DISTINCT FROM OLD.envelope_digest
       OR NEW.envelope_digest IS NOT DISTINCT FROM OLD.envelope_digest
       OR (OLD.status = 1 AND NEW.status NOT IN (1, 2))
       OR (NEW.pending_kind IS DISTINCT FROM OLD.pending_kind AND NOT (
            OLD.pending_kind IN (1, 2, 3, 5)
            AND NEW.pending_kind = 4
            AND OLD.status = 1
            AND OLD.terminal_outcome_digest IS NULL
            AND NEW.status = 2
            AND NEW.terminal_outcome_digest IS NOT NULL
       ))
       OR (NEW.pending_kind = 4 AND (
            OLD.pending_kind NOT IN (1, 2, 3, 5)
            OR NEW.status <> 2
            OR NEW.terminal_outcome_digest IS NULL
       )) THEN
        RAISE EXCEPTION 'durable pending transition is not monotonic'
            USING ERRCODE = '23514';
    END IF;
    NEW.transaction_id := pg_current_xact_id();
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END;
$cph$;

CREATE FUNCTION cph_aiinfra.assert_durable_pending_consistency()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $cph$
DECLARE
    linked_evidence BIGINT;
BEGIN
    IF TG_TABLE_NAME = 'durable_pending_head' THEN
        IF NOT EXISTS (
            SELECT 1 FROM cph_aiinfra.durable_pending_revision revision
             WHERE revision.pending_key = NEW.pending_key
               AND revision.revision = NEW.revision
               AND revision.pending_kind = NEW.pending_kind
               AND revision.codec = NEW.codec
               AND revision.codec_version = NEW.codec_version
               AND revision.previous_envelope_digest IS NOT DISTINCT FROM NEW.previous_envelope_digest
               AND revision.envelope_digest = NEW.envelope_digest
               AND revision.canonical_envelope = NEW.canonical_envelope
               AND revision.evidence_count = NEW.evidence_count
               AND revision.status = NEW.status
               AND revision.commit_not_before_unix_nano = NEW.commit_not_before_unix_nano
               AND revision.commit_not_after_unix_nano = NEW.commit_not_after_unix_nano
               AND revision.terminal_outcome_digest IS NOT DISTINCT FROM NEW.terminal_outcome_digest
               AND revision.audit_event_id = NEW.audit_event_id
               AND revision.uow_scope_sha256 = NEW.uow_scope_sha256
               AND revision.uow_message_id = NEW.uow_message_id
               AND revision.transaction_id = NEW.transaction_id
        ) THEN
            RAISE EXCEPTION 'durable pending head has no exact same-transaction revision'
                USING ERRCODE = '23514';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM cph_aiinfra.business_idempotency_head business
             WHERE business.idempotency_key = NEW.pending_key
               AND business.row_kind = 1
               AND business.audit_event_id = NEW.audit_event_id
               AND business.uow_scope_sha256 = NEW.uow_scope_sha256
               AND business.uow_message_id = NEW.uow_message_id
               AND business.transaction_id = NEW.transaction_id
               AND ((NEW.status = 1 AND business.state = 1)
                    OR (NEW.status = 2 AND business.state = 2
                        AND business.outcome_digest = NEW.terminal_outcome_digest))
        ) THEN
            RAISE EXCEPTION 'durable pending status does not match business idempotency state'
                USING ERRCODE = '23514';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM cph_aiinfra.authoritative_uow uow
             WHERE uow.scope_sha256 = NEW.uow_scope_sha256
               AND uow.message_id = NEW.uow_message_id
               AND uow.transaction_id = NEW.transaction_id
               AND ((NEW.status = 1 AND (
                        (uow.uow_kind = 1 AND uow.audit_event_id IS NULL)
                        OR
                        (uow.uow_kind = 2 AND uow.audit_event_id IS NOT NULL
                            AND uow.audit_event_id <> NEW.audit_event_id)
                    ))
                    OR (NEW.status = 2 AND uow.uow_kind = 2
                        AND uow.audit_event_id = NEW.audit_event_id
                        AND uow.outcome_digest = NEW.terminal_outcome_digest))
        ) THEN
            RAISE EXCEPTION 'durable pending phase does not match its authoritative UoW'
                USING ERRCODE = '23514';
        END IF;
        IF NOT EXISTS (
            SELECT 1
              FROM cph_aiinfra.global_identifier_claim claim
              JOIN cph_aiinfra.global_identifier_head global_head
                ON global_head.identifier = claim.identifier
               AND global_head.owner_domain = claim.next_owner_domain
               AND global_head.owner_id = claim.next_owner_id
               AND global_head.version = claim.next_version
         WHERE claim.identifier = NEW.audit_event_id
           AND claim.next_owner_domain = 'cph.aiinfra.governance.audit-event.v1'
           AND claim.next_owner_id = NEW.audit_event_id
           AND claim.audit_event_id = NEW.audit_event_id
           AND claim.uow_scope_sha256 = NEW.uow_scope_sha256
               AND claim.uow_message_id = NEW.uow_message_id
               AND claim.transaction_id = NEW.transaction_id
        ) THEN
            RAISE EXCEPTION 'durable pending expected AuditEvent is not globally reserved by this UoW'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        IF NOT EXISTS (
            SELECT 1 FROM cph_aiinfra.durable_pending_head head
             WHERE head.pending_key = NEW.pending_key
               AND head.revision = NEW.revision
               AND head.pending_kind = NEW.pending_kind
               AND head.codec = NEW.codec
               AND head.codec_version = NEW.codec_version
               AND head.previous_envelope_digest IS NOT DISTINCT FROM NEW.previous_envelope_digest
               AND head.envelope_digest = NEW.envelope_digest
               AND head.canonical_envelope = NEW.canonical_envelope
               AND head.evidence_count = NEW.evidence_count
               AND head.status = NEW.status
               AND head.commit_not_before_unix_nano = NEW.commit_not_before_unix_nano
               AND head.commit_not_after_unix_nano = NEW.commit_not_after_unix_nano
               AND head.terminal_outcome_digest IS NOT DISTINCT FROM NEW.terminal_outcome_digest
               AND head.audit_event_id = NEW.audit_event_id
               AND head.uow_scope_sha256 = NEW.uow_scope_sha256
               AND head.uow_message_id = NEW.uow_message_id
               AND head.transaction_id = NEW.transaction_id
        ) THEN
            RAISE EXCEPTION 'durable pending revision has no exact same-transaction head'
                USING ERRCODE = '23514';
        END IF;
        SELECT count(*) INTO linked_evidence
          FROM cph_aiinfra.durable_pending_evidence link
         WHERE link.pending_key = NEW.pending_key
           AND link.revision = NEW.revision
           AND link.audit_event_id = NEW.audit_event_id
           AND link.uow_scope_sha256 = NEW.uow_scope_sha256
           AND link.uow_message_id = NEW.uow_message_id
           AND link.transaction_id = NEW.transaction_id;
        IF linked_evidence <> NEW.evidence_count THEN
            RAISE EXCEPTION 'durable pending revision evidence count differs'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NULL;
END;
$cph$;

CREATE FUNCTION cph_aiinfra.assert_durable_pending_evidence_consistency()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $cph$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM cph_aiinfra.durable_pending_revision revision
         WHERE revision.pending_key = NEW.pending_key
           AND revision.revision = NEW.revision
           AND revision.audit_event_id = NEW.audit_event_id
           AND revision.uow_scope_sha256 = NEW.uow_scope_sha256
           AND revision.uow_message_id = NEW.uow_message_id
           AND revision.transaction_id = NEW.transaction_id
    ) THEN
        RAISE EXCEPTION 'durable pending evidence link has no exact same-transaction revision'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$cph$;

CREATE FUNCTION cph_aiinfra.enforce_canonical_state_head_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $cph$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'canonical state head cannot be deleted' USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.version <> 1 THEN
            RAISE EXCEPTION 'canonical state must start at version one' USING ERRCODE = '23514';
        END IF;
        IF (NEW.object_kind IN (
                'cph.aiinfra.iam.key-material.v1',
                'cph.aiinfra.iam.accepted-ownership-transfer.v1',
                'cph.aiinfra.iam.rotation-predecessor-index.v1'
            ) AND NOT NEW.terminal)
           OR (NEW.object_kind IN (
                'cph.aiinfra.iam.proof-challenge.v1',
                'cph.aiinfra.iam.principal-identity-index.v1',
                'cph.aiinfra.iam.subject-key-set.v1',
                'cph.aiinfra.iam.writer-lease.v1',
                'cph.aiinfra.iam.ownership-transfer-profile-activation.v1',
                'cph.aiinfra.governance.policy-registry.v1'
            ) AND NEW.terminal) THEN
            RAISE EXCEPTION 'canonical state initial terminal shape is invalid'
                USING ERRCODE = '23514';
        END IF;
        NEW.transaction_id := pg_current_xact_id();
        NEW.updated_at := clock_timestamp();
        RETURN NEW;
    END IF;
    IF OLD.terminal
       OR NEW.state_namespace IS DISTINCT FROM OLD.state_namespace
       OR NEW.object_kind IS DISTINCT FROM OLD.object_kind
       OR NEW.object_id IS DISTINCT FROM OLD.object_id
       OR NEW.version <> OLD.version + 1
       OR NEW.state_digest IS NOT DISTINCT FROM OLD.state_digest
       OR NEW.object_kind IN (
            'cph.aiinfra.iam.key-material.v1',
            'cph.aiinfra.iam.accepted-ownership-transfer.v1',
            'cph.aiinfra.iam.rotation-predecessor-index.v1'
       )
       OR (NEW.object_kind = 'cph.aiinfra.iam.proof-challenge.v1' AND NOT NEW.terminal)
       OR (NEW.object_kind IN (
            'cph.aiinfra.iam.principal-identity-index.v1',
            'cph.aiinfra.iam.subject-key-set.v1',
            'cph.aiinfra.iam.writer-lease.v1',
            'cph.aiinfra.iam.ownership-transfer-profile-activation.v1',
            'cph.aiinfra.governance.policy-registry.v1'
       ) AND NEW.terminal) THEN
        RAISE EXCEPTION 'canonical state transition is not monotonic'
            USING ERRCODE = '23514';
    END IF;
    NEW.transaction_id := pg_current_xact_id();
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END;
$cph$;

CREATE FUNCTION cph_aiinfra.assert_durable_evidence_assertion()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $cph$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM cph_aiinfra.authoritative_uow uow
         WHERE uow.scope_sha256 = NEW.uow_scope_sha256
           AND uow.message_id = NEW.uow_message_id
           AND uow.uow_kind = 2
           AND uow.audit_event_id = NEW.audit_event_id
           AND uow.transaction_id = NEW.transaction_id
    ) THEN
        RAISE EXCEPTION 'durable evidence assertion requires an audited-final UoW'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.pending_key IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM cph_aiinfra.durable_pending_evidence link
         WHERE link.pending_key = NEW.pending_key
           AND link.revision = NEW.pending_revision
           AND link.evidence_digest = NEW.evidence_digest
    ) THEN
        RAISE EXCEPTION 'durable evidence assertion is not retained by the claimed pending revision'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$cph$;

CREATE FUNCTION cph_aiinfra.assert_canonical_state_consistency()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $cph$
BEGIN
    IF TG_TABLE_NAME = 'canonical_state_head' THEN
        IF NOT EXISTS (
            SELECT 1 FROM cph_aiinfra.canonical_state_history history
             WHERE history.state_namespace = NEW.state_namespace
               AND history.object_kind = NEW.object_kind
               AND history.object_id = NEW.object_id
               AND history.version = NEW.version
               AND history.state_digest = NEW.state_digest
               AND history.content_type = NEW.content_type
               AND history.canonical_state = NEW.canonical_state
               AND history.terminal = NEW.terminal
               AND history.audit_event_id = NEW.audit_event_id
               AND history.uow_scope_sha256 = NEW.uow_scope_sha256
               AND history.uow_message_id = NEW.uow_message_id
               AND history.transaction_id = NEW.transaction_id
        ) THEN
            RAISE EXCEPTION 'canonical state head has no exact same-transaction history'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NOT EXISTS (
        SELECT 1 FROM cph_aiinfra.canonical_state_head head
         WHERE head.state_namespace = NEW.state_namespace
           AND head.object_kind = NEW.object_kind
           AND head.object_id = NEW.object_id
           AND head.version = NEW.version
           AND head.state_digest = NEW.state_digest
           AND head.content_type = NEW.content_type
           AND head.canonical_state = NEW.canonical_state
           AND head.terminal = NEW.terminal
           AND head.audit_event_id = NEW.audit_event_id
           AND head.uow_scope_sha256 = NEW.uow_scope_sha256
           AND head.uow_message_id = NEW.uow_message_id
           AND head.transaction_id = NEW.transaction_id
    ) THEN
        RAISE EXCEPTION 'canonical state history has no exact same-transaction head'
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
        RAISE EXCEPTION 'canonical state mutation requires an audited-final UoW'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$cph$;

CREATE TRIGGER authoritative_uow_transaction
BEFORE INSERT ON cph_aiinfra.authoritative_uow
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.stamp_unit_of_work_transaction();

CREATE TRIGGER authoritative_uow_immutable
BEFORE DELETE OR UPDATE ON cph_aiinfra.authoritative_uow
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.reject_immutable_change();

CREATE CONSTRAINT TRIGGER authoritative_uow_coupling
AFTER INSERT ON cph_aiinfra.authoritative_uow
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_authoritative_uow();

CREATE TRIGGER audit_event_transaction
BEFORE INSERT ON cph_aiinfra.audit_event
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.stamp_unit_of_work_transaction();

CREATE TRIGGER audit_event_immutable
BEFORE DELETE OR UPDATE ON cph_aiinfra.audit_event
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.reject_immutable_change();

CREATE CONSTRAINT TRIGGER audit_event_uow
AFTER INSERT ON cph_aiinfra.audit_event
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_audit_event_uow();

CREATE TRIGGER audit_head_monotonic
BEFORE INSERT OR DELETE OR UPDATE ON cph_aiinfra.audit_head
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.enforce_audit_head_change();

CREATE CONSTRAINT TRIGGER audit_head_event
AFTER INSERT OR UPDATE ON cph_aiinfra.audit_head
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_audit_head_event();

CREATE TRIGGER business_idempotency_head_monotonic
BEFORE INSERT OR DELETE OR UPDATE ON cph_aiinfra.business_idempotency_head
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.enforce_business_idempotency_head_change();

CREATE CONSTRAINT TRIGGER business_idempotency_head_consistency
AFTER INSERT OR UPDATE ON cph_aiinfra.business_idempotency_head
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_business_idempotency_consistency();

CREATE CONSTRAINT TRIGGER business_idempotency_head_uow
AFTER INSERT OR UPDATE ON cph_aiinfra.business_idempotency_head
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_audit_uow_member();

CREATE TRIGGER business_idempotency_history_transaction
BEFORE INSERT ON cph_aiinfra.business_idempotency_history
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.stamp_unit_of_work_transaction();

CREATE TRIGGER business_idempotency_history_immutable
BEFORE DELETE OR UPDATE ON cph_aiinfra.business_idempotency_history
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.reject_immutable_change();

CREATE CONSTRAINT TRIGGER business_idempotency_history_consistency
AFTER INSERT ON cph_aiinfra.business_idempotency_history
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_business_idempotency_consistency();

CREATE CONSTRAINT TRIGGER business_idempotency_history_uow
AFTER INSERT ON cph_aiinfra.business_idempotency_history
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_audit_uow_member();

CREATE TRIGGER global_identifier_head_monotonic
BEFORE INSERT OR DELETE OR UPDATE ON cph_aiinfra.global_identifier_head
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.enforce_global_identifier_head_change();

CREATE CONSTRAINT TRIGGER global_identifier_head_consistency
AFTER INSERT OR UPDATE ON cph_aiinfra.global_identifier_head
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_global_identifier_consistency();

CREATE CONSTRAINT TRIGGER global_identifier_head_uow
AFTER INSERT OR UPDATE ON cph_aiinfra.global_identifier_head
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_audit_uow_member();

CREATE TRIGGER global_identifier_history_transaction
BEFORE INSERT ON cph_aiinfra.global_identifier_history
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.stamp_unit_of_work_transaction();

CREATE TRIGGER global_identifier_history_immutable
BEFORE DELETE OR UPDATE ON cph_aiinfra.global_identifier_history
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.reject_immutable_change();

CREATE CONSTRAINT TRIGGER global_identifier_history_consistency
AFTER INSERT ON cph_aiinfra.global_identifier_history
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_global_identifier_consistency();

CREATE CONSTRAINT TRIGGER global_identifier_history_uow
AFTER INSERT ON cph_aiinfra.global_identifier_history
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_audit_uow_member();

CREATE TRIGGER global_identifier_claim_transaction
BEFORE INSERT ON cph_aiinfra.global_identifier_claim
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.stamp_unit_of_work_transaction();

CREATE TRIGGER global_identifier_claim_immutable
BEFORE DELETE OR UPDATE ON cph_aiinfra.global_identifier_claim
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.reject_immutable_change();

CREATE CONSTRAINT TRIGGER global_identifier_claim_consistency
AFTER INSERT ON cph_aiinfra.global_identifier_claim
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_global_identifier_consistency();

CREATE CONSTRAINT TRIGGER global_identifier_claim_uow
AFTER INSERT ON cph_aiinfra.global_identifier_claim
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_audit_uow_member();

CREATE TRIGGER durable_evidence_transaction
BEFORE INSERT ON cph_aiinfra.durable_evidence
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.stamp_unit_of_work_transaction();

CREATE TRIGGER durable_evidence_immutable
BEFORE DELETE OR UPDATE ON cph_aiinfra.durable_evidence
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.reject_immutable_change();

CREATE CONSTRAINT TRIGGER durable_evidence_uow
AFTER INSERT ON cph_aiinfra.durable_evidence
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_audit_uow_member();

CREATE TRIGGER durable_pending_head_monotonic
BEFORE INSERT OR DELETE OR UPDATE ON cph_aiinfra.durable_pending_head
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.enforce_durable_pending_head_change();

CREATE CONSTRAINT TRIGGER durable_pending_head_consistency
AFTER INSERT OR UPDATE ON cph_aiinfra.durable_pending_head
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_durable_pending_consistency();

CREATE CONSTRAINT TRIGGER durable_pending_head_uow
AFTER INSERT OR UPDATE ON cph_aiinfra.durable_pending_head
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_audit_uow_member();

CREATE TRIGGER durable_pending_revision_transaction
BEFORE INSERT ON cph_aiinfra.durable_pending_revision
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.stamp_unit_of_work_transaction();

CREATE TRIGGER durable_pending_revision_immutable
BEFORE DELETE OR UPDATE ON cph_aiinfra.durable_pending_revision
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.reject_immutable_change();

CREATE CONSTRAINT TRIGGER durable_pending_revision_consistency
AFTER INSERT ON cph_aiinfra.durable_pending_revision
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_durable_pending_consistency();

CREATE CONSTRAINT TRIGGER durable_pending_revision_uow
AFTER INSERT ON cph_aiinfra.durable_pending_revision
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_audit_uow_member();

CREATE TRIGGER durable_pending_evidence_transaction
BEFORE INSERT ON cph_aiinfra.durable_pending_evidence
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.stamp_unit_of_work_transaction();

CREATE TRIGGER durable_pending_evidence_immutable
BEFORE DELETE OR UPDATE ON cph_aiinfra.durable_pending_evidence
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.reject_immutable_change();

CREATE CONSTRAINT TRIGGER durable_pending_evidence_consistency
AFTER INSERT ON cph_aiinfra.durable_pending_evidence
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_durable_pending_evidence_consistency();

CREATE CONSTRAINT TRIGGER durable_pending_evidence_uow
AFTER INSERT ON cph_aiinfra.durable_pending_evidence
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_audit_uow_member();

CREATE TRIGGER durable_evidence_assertion_transaction
BEFORE INSERT ON cph_aiinfra.durable_evidence_assertion
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.stamp_unit_of_work_transaction();

CREATE TRIGGER durable_evidence_assertion_immutable
BEFORE DELETE OR UPDATE ON cph_aiinfra.durable_evidence_assertion
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.reject_immutable_change();

CREATE CONSTRAINT TRIGGER durable_evidence_assertion_consistency
AFTER INSERT ON cph_aiinfra.durable_evidence_assertion
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_durable_evidence_assertion();

CREATE CONSTRAINT TRIGGER durable_evidence_assertion_uow
AFTER INSERT ON cph_aiinfra.durable_evidence_assertion
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_audit_uow_member();

CREATE TRIGGER canonical_state_head_monotonic
BEFORE INSERT OR DELETE OR UPDATE ON cph_aiinfra.canonical_state_head
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.enforce_canonical_state_head_change();

CREATE CONSTRAINT TRIGGER canonical_state_head_consistency
AFTER INSERT OR UPDATE ON cph_aiinfra.canonical_state_head
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_canonical_state_consistency();

CREATE CONSTRAINT TRIGGER canonical_state_head_uow
AFTER INSERT OR UPDATE ON cph_aiinfra.canonical_state_head
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_audit_uow_member();

CREATE TRIGGER canonical_state_history_transaction
BEFORE INSERT ON cph_aiinfra.canonical_state_history
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.stamp_unit_of_work_transaction();

CREATE TRIGGER canonical_state_history_immutable
BEFORE DELETE OR UPDATE ON cph_aiinfra.canonical_state_history
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.reject_immutable_change();

CREATE CONSTRAINT TRIGGER canonical_state_history_consistency
AFTER INSERT ON cph_aiinfra.canonical_state_history
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_canonical_state_consistency();

CREATE CONSTRAINT TRIGGER canonical_state_history_uow
AFTER INSERT ON cph_aiinfra.canonical_state_history
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.assert_audit_uow_member();

REVOKE ALL ON ALL TABLES IN SCHEMA cph_aiinfra FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA cph_aiinfra FROM PUBLIC;
