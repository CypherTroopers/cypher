-- Migration 4 adds operational delivery state for the immutable outbox
-- intents installed by migration 1. Publication remains at-least-once: a
-- worker commits a fenced lease before calling the remote publisher, and a
-- crash before acknowledgement makes the same deduplication key eligible
-- after the database-clock lease expires.

CREATE TABLE cph_aiinfra.ccse_outbox_delivery (
    event_id              BYTEA NOT NULL,
    attempt_count         BIGINT NOT NULL DEFAULT 0,
    lease_owner_sha256    BYTEA,
    lease_token           BYTEA,
    lease_until           TIMESTAMPTZ,
    next_attempt_at       TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    delivered_at          TIMESTAMPTZ,
    last_error_digest     BYTEA,
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT ccse_outbox_delivery_pk PRIMARY KEY (event_id),
    CONSTRAINT ccse_outbox_delivery_intent_fk FOREIGN KEY (event_id)
        REFERENCES cph_aiinfra.ccse_outbox_intent(event_id),
    CONSTRAINT ccse_outbox_delivery_event_length CHECK (octet_length(event_id) = 16),
    CONSTRAINT ccse_outbox_delivery_attempt_nonnegative CHECK (attempt_count >= 0),
    CONSTRAINT ccse_outbox_delivery_owner_length CHECK (
        lease_owner_sha256 IS NULL OR octet_length(lease_owner_sha256) = 32),
    CONSTRAINT ccse_outbox_delivery_token_length CHECK (
        lease_token IS NULL OR octet_length(lease_token) = 16),
    CONSTRAINT ccse_outbox_delivery_lease_shape CHECK (
        (lease_owner_sha256 IS NULL AND lease_token IS NULL AND lease_until IS NULL)
        OR
        (lease_owner_sha256 IS NOT NULL AND lease_token IS NOT NULL AND lease_until IS NOT NULL)),
    CONSTRAINT ccse_outbox_delivery_delivered_unleased CHECK (
        delivered_at IS NULL
        OR (lease_owner_sha256 IS NULL AND lease_token IS NULL AND lease_until IS NULL)),
    CONSTRAINT ccse_outbox_delivery_error_length CHECK (
        last_error_digest IS NULL OR octet_length(last_error_digest) = 32)
);

CREATE INDEX ccse_outbox_delivery_ready_idx
    ON cph_aiinfra.ccse_outbox_delivery
       (delivered_at, next_attempt_at, lease_until, event_id);

CREATE FUNCTION cph_aiinfra.enforce_outbox_delivery_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $cph$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.attempt_count <> 0
           OR NEW.lease_owner_sha256 IS NOT NULL
           OR NEW.lease_token IS NOT NULL
           OR NEW.lease_until IS NOT NULL
           OR NEW.delivered_at IS NOT NULL
           OR NEW.last_error_digest IS NOT NULL THEN
            RAISE EXCEPTION 'outbox delivery insert must use initial state'
                USING ERRCODE = '55000';
        END IF;
        NEW.attempt_count := 0;
        NEW.lease_owner_sha256 := NULL;
        NEW.lease_token := NULL;
        NEW.lease_until := NULL;
        NEW.next_attempt_at := clock_timestamp();
        NEW.delivered_at := NULL;
        NEW.last_error_digest := NULL;
        NEW.updated_at := NEW.next_attempt_at;
        RETURN NEW;
    END IF;

    IF NEW.event_id IS DISTINCT FROM OLD.event_id
       OR OLD.delivered_at IS NOT NULL THEN
        RAISE EXCEPTION 'outbox delivery identity or terminal state is immutable'
            USING ERRCODE = '55000';
    END IF;

    -- Acquire a fresh lease. A prior lease can be replaced only after expiry.
    IF NEW.delivered_at IS NULL
       AND NEW.attempt_count = OLD.attempt_count + 1
       AND NEW.lease_owner_sha256 IS NOT NULL
       AND NEW.lease_token IS NOT NULL
       AND NEW.lease_until > clock_timestamp()
       AND NEW.lease_until <= clock_timestamp() + interval '10 minutes'
       AND (OLD.lease_until IS NULL OR OLD.lease_until <= clock_timestamp())
       AND NEW.next_attempt_at IS NOT DISTINCT FROM OLD.next_attempt_at
       AND NEW.last_error_digest IS NOT DISTINCT FROM OLD.last_error_digest THEN
        NEW.updated_at := clock_timestamp();
        RETURN NEW;
    END IF;

    -- Acknowledge a publication while presenting the exact active lease.
    IF OLD.lease_owner_sha256 IS NOT NULL
       AND OLD.lease_token IS NOT NULL
       AND NEW.attempt_count = OLD.attempt_count
       AND NEW.lease_owner_sha256 IS NULL
       AND NEW.lease_token IS NULL
       AND NEW.lease_until IS NULL
       AND NEW.delivered_at IS NOT NULL
       AND NEW.next_attempt_at IS NOT DISTINCT FROM OLD.next_attempt_at
       AND NEW.last_error_digest IS NULL THEN
        NEW.delivered_at := clock_timestamp();
        NEW.updated_at := clock_timestamp();
        RETURN NEW;
    END IF;

    -- Reject a failed publication and schedule it using the database clock.
    IF OLD.lease_owner_sha256 IS NOT NULL
       AND OLD.lease_token IS NOT NULL
       AND NEW.attempt_count = OLD.attempt_count
       AND NEW.lease_owner_sha256 IS NULL
       AND NEW.lease_token IS NULL
       AND NEW.lease_until IS NULL
       AND NEW.delivered_at IS NULL
       AND NEW.next_attempt_at > clock_timestamp()
       AND NEW.next_attempt_at <= clock_timestamp() + interval '24 hours'
       AND NEW.last_error_digest IS NOT NULL THEN
        NEW.updated_at := clock_timestamp();
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'invalid outbox delivery transition' USING ERRCODE = '55000';
END;
$cph$;

CREATE TRIGGER ccse_outbox_delivery_transition
BEFORE INSERT OR UPDATE ON cph_aiinfra.ccse_outbox_delivery
FOR EACH ROW EXECUTE FUNCTION cph_aiinfra.enforce_outbox_delivery_transition();

-- The runtime role has no direct write or read capability on the delivery
-- table.  These owner-executed functions are the complete delivery-state
-- capability surface.  In particular, lease tokens never become visible via
-- table SELECT, and acknowledgements cannot omit the exact worker/token fence.
CREATE FUNCTION cph_aiinfra.claim_outbox_delivery(
    p_worker_sha256 BYTEA,
    p_lease_token BYTEA,
    p_lease_microseconds BIGINT,
    p_initialize_limit INTEGER)
RETURNS TABLE (
    claimed_event_id BYTEA,
    claimed_destination TEXT,
    claimed_deduplication_key TEXT,
    claimed_content_type TEXT,
    claimed_payload BYTEA,
    claimed_payload_digest BYTEA,
    claimed_prior_attempt_count BIGINT)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path = pg_catalog
AS $cph$
DECLARE
    changed_rows BIGINT;
BEGIN
    IF p_worker_sha256 IS NULL
       OR octet_length(p_worker_sha256) <> 32
       OR p_worker_sha256 = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
       OR p_lease_token IS NULL
       OR octet_length(p_lease_token) <> 16
       OR p_lease_token = pg_catalog.decode(pg_catalog.repeat('00', 16), 'hex')
       OR p_lease_microseconds IS NULL
       OR p_lease_microseconds < 1000000
       OR p_lease_microseconds > 600000000
       OR p_initialize_limit IS NULL
       OR p_initialize_limit < 1
       OR p_initialize_limit > 256 THEN
        RAISE EXCEPTION 'invalid outbox claim capability input'
            USING ERRCODE = '22023';
    END IF;

    INSERT INTO cph_aiinfra.ccse_outbox_delivery (event_id)
    SELECT intent.event_id
    FROM cph_aiinfra.ccse_outbox_intent AS intent
    WHERE NOT EXISTS (
        SELECT 1
        FROM cph_aiinfra.ccse_outbox_delivery AS existing
        WHERE existing.event_id = intent.event_id)
    ORDER BY intent.created_at, intent.event_id
    LIMIT p_initialize_limit
    ON CONFLICT (event_id) DO NOTHING;

    RETURN QUERY
    WITH candidate AS MATERIALIZED (
        SELECT intent.event_id,
               intent.destination,
               intent.deduplication_key,
               intent.content_type,
               intent.payload,
               intent.payload_digest,
               delivery.attempt_count
        FROM cph_aiinfra.ccse_outbox_delivery AS delivery
        JOIN cph_aiinfra.ccse_outbox_intent AS intent
          ON intent.event_id = delivery.event_id
        WHERE delivery.delivered_at IS NULL
          AND delivery.next_attempt_at <= pg_catalog.clock_timestamp()
          AND (delivery.lease_until IS NULL
               OR delivery.lease_until <= pg_catalog.clock_timestamp())
        ORDER BY delivery.next_attempt_at, intent.created_at, intent.event_id
        FOR UPDATE OF delivery SKIP LOCKED
        LIMIT 1
    ), claimed AS (
        UPDATE cph_aiinfra.ccse_outbox_delivery AS delivery
        SET attempt_count = delivery.attempt_count + 1,
            lease_owner_sha256 = p_worker_sha256,
            lease_token = p_lease_token,
            lease_until = pg_catalog.clock_timestamp()
                + (p_lease_microseconds * interval '1 microsecond'),
            updated_at = pg_catalog.clock_timestamp()
        FROM candidate
        WHERE delivery.event_id = candidate.event_id
          AND delivery.delivered_at IS NULL
          AND delivery.next_attempt_at <= pg_catalog.clock_timestamp()
          AND (delivery.lease_until IS NULL
               OR delivery.lease_until <= pg_catalog.clock_timestamp())
        RETURNING candidate.event_id,
                  candidate.destination,
                  candidate.deduplication_key,
                  candidate.content_type,
                  candidate.payload,
                  candidate.payload_digest,
                  candidate.attempt_count
    )
    SELECT claimed.event_id,
           claimed.destination,
           claimed.deduplication_key,
           claimed.content_type,
           claimed.payload,
           claimed.payload_digest,
           claimed.attempt_count
    FROM claimed;

    GET DIAGNOSTICS changed_rows = ROW_COUNT;
    IF changed_rows < 0 OR changed_rows > 1 THEN
        RAISE EXCEPTION 'outbox claim changed an invalid row count'
            USING ERRCODE = '55000';
    END IF;
END;
$cph$;

CREATE FUNCTION cph_aiinfra.acknowledge_outbox_delivery(
    p_event_id BYTEA,
    p_worker_sha256 BYTEA,
    p_lease_token BYTEA)
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path = pg_catalog
AS $cph$
DECLARE
    changed_rows BIGINT;
BEGIN
    IF p_event_id IS NULL
       OR octet_length(p_event_id) <> 16
       OR p_event_id = pg_catalog.decode(pg_catalog.repeat('00', 16), 'hex')
       OR p_worker_sha256 IS NULL
       OR octet_length(p_worker_sha256) <> 32
       OR p_worker_sha256 = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
       OR p_lease_token IS NULL
       OR octet_length(p_lease_token) <> 16
       OR p_lease_token = pg_catalog.decode(pg_catalog.repeat('00', 16), 'hex') THEN
        RAISE EXCEPTION 'invalid outbox acknowledgement capability input'
            USING ERRCODE = '22023';
    END IF;

    UPDATE cph_aiinfra.ccse_outbox_delivery AS delivery
    SET delivered_at = pg_catalog.clock_timestamp(),
        lease_owner_sha256 = NULL,
        lease_token = NULL,
        lease_until = NULL,
        last_error_digest = NULL,
        updated_at = pg_catalog.clock_timestamp()
    WHERE delivery.event_id = p_event_id
      AND delivery.delivered_at IS NULL
      AND delivery.lease_owner_sha256 = p_worker_sha256
      AND delivery.lease_token = p_lease_token;
    GET DIAGNOSTICS changed_rows = ROW_COUNT;
    IF changed_rows <> 1 THEN
        RAISE EXCEPTION 'outbox acknowledgement lease was lost'
            USING ERRCODE = '55000';
    END IF;
    RETURN changed_rows;
END;
$cph$;

CREATE FUNCTION cph_aiinfra.reject_outbox_delivery(
    p_event_id BYTEA,
    p_worker_sha256 BYTEA,
    p_lease_token BYTEA,
    p_retry_microseconds BIGINT,
    p_error_sha256 BYTEA)
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path = pg_catalog
AS $cph$
DECLARE
    changed_rows BIGINT;
BEGIN
    IF p_event_id IS NULL
       OR octet_length(p_event_id) <> 16
       OR p_event_id = pg_catalog.decode(pg_catalog.repeat('00', 16), 'hex')
       OR p_worker_sha256 IS NULL
       OR octet_length(p_worker_sha256) <> 32
       OR p_worker_sha256 = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
       OR p_lease_token IS NULL
       OR octet_length(p_lease_token) <> 16
       OR p_lease_token = pg_catalog.decode(pg_catalog.repeat('00', 16), 'hex')
       OR p_retry_microseconds IS NULL
       OR p_retry_microseconds < 1000
       OR p_retry_microseconds > 86400000000
       OR p_error_sha256 IS NULL
       OR octet_length(p_error_sha256) <> 32
       OR p_error_sha256 = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex') THEN
        RAISE EXCEPTION 'invalid outbox rejection capability input'
            USING ERRCODE = '22023';
    END IF;

    UPDATE cph_aiinfra.ccse_outbox_delivery AS delivery
    SET lease_owner_sha256 = NULL,
        lease_token = NULL,
        lease_until = NULL,
        next_attempt_at = pg_catalog.clock_timestamp()
            + (p_retry_microseconds * interval '1 microsecond'),
        last_error_digest = p_error_sha256,
        updated_at = pg_catalog.clock_timestamp()
    WHERE delivery.event_id = p_event_id
      AND delivery.delivered_at IS NULL
      AND delivery.lease_owner_sha256 = p_worker_sha256
      AND delivery.lease_token = p_lease_token;
    GET DIAGNOSTICS changed_rows = ROW_COUNT;
    IF changed_rows <> 1 THEN
        RAISE EXCEPTION 'outbox rejection lease was lost'
            USING ERRCODE = '55000';
    END IF;
    RETURN changed_rows;
END;
$cph$;

REVOKE ALL ON TABLE cph_aiinfra.ccse_outbox_delivery FROM PUBLIC;
REVOKE ALL ON FUNCTION cph_aiinfra.enforce_outbox_delivery_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION cph_aiinfra.claim_outbox_delivery(BYTEA, BYTEA, BIGINT, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION cph_aiinfra.acknowledge_outbox_delivery(BYTEA, BYTEA, BYTEA) FROM PUBLIC;
REVOKE ALL ON FUNCTION cph_aiinfra.reject_outbox_delivery(BYTEA, BYTEA, BYTEA, BIGINT, BYTEA) FROM PUBLIC;
