# CPH AIIE PostgreSQL authoritative unit of work

This package is the PostgreSQL boundary required by ADR-0010. It uses
`database/sql`; the control-plane executable, never the validator, selects and
pins the PostgreSQL driver.

## Runtime contract

`ReplayStore.Execute` owns one serializable transaction. A first-seen handler
must obtain `Transaction(ctx)`, execute only source-controlled SQL registered by
`WithAllowedStatements`, and finish with `AtomicTx.Complete`. The transaction
surface has no `Commit`, `Rollback` or `Prepare`; transaction/session DDL,
multiple statements, internal `cph_aiinfra` access and unlisted SQL fail closed.
Every replay transaction fixes `search_path` to `pg_catalog`, so allowlisted
business SQL must use schema-qualified relations. Streaming rows are guarded
and must be consumed or closed before any subsequent statement or completion.
`QueryRowContext` leaves `sql.ErrNoRows` open until the handler explicitly calls
`AcceptNoRows`; silently ignoring an optional-row miss aborts completion.
`ExecContext` returns a guarded result, so a later `RowsAffected` or
`LastInsertId` driver error also poisons the transaction.

The SQL catalog rejects `SELECT INTO`, Unicode-escaped `U&` tokens, sequence,
advisory-lock, notification, large-object, dblink and other known side-effect
functions. This validator is intentionally not a PostgreSQL semantic parser:
the owning team must also review every exact allowlisted statement and every
business-schema function and trigger it can invoke. Those objects must not
perform non-transactional effects or change session settings.

`Complete` atomically writes:

1. a domain-separated durable result and its digest;
2. an explicit `NoExternalEffects` declaration, or at least one immutable,
   deduplicated outbox intent under `ExternalEffectsViaOutbox`;
3. later in the same owned transaction, the replay inbox row and monotonically
   increasing replay head.

The handler's returned digest must equal the digest produced by `Complete`.
Claiming no transaction, returning only an in-memory digest, leaving query rows
open, ignoring a SQL error, issuing SQL after completion, or returning a
different digest aborts the whole transaction. The database also enforces the
result/inbox foreign key, deferred result/outbox coupling, immutable inbox,
result and outbox rows, and monotonic replay-head updates.
Result and outbox rows receive a trigger-controlled `xid8`; a later transaction
cannot append an effect to an already completed result. Per-result, per-intent
and aggregate outbox bounds cap transaction memory and write volume.
Inbox rows also receive a trigger-controlled `xid8` and explicit counter kind.
A replay-head update requires exactly one inbox inserted by the same top-level
transaction with the same scope, counter kind and sequence; a direct future
sequence update without that row is rejected.

An exact completed redelivery reads the stored outcome digest without invoking
the handler. `LoadDurableResult` then joins the exact replay identity, reloads
the payload and recomputes its domain-separated digest before returning it.
Message-ID conflicts, stale unsigned sequences, nested replay
transactions, incomplete effect declarations and zero outcomes fail closed. No
handler may perform a non-transactional external effect before commit.

`Execute` checks `session_replication_role = origin` at transaction entry,
completion, before replay persistence and before commit. The store also uses an
instance-local atomic single-flight guard, so discarding the supplied context
and recursively calling the same store is rejected. Because Go cannot
distinguish that call from a legitimate overlapping call, this foundation also
rejects concurrent `Execute` calls on one store instance. Parallel execution
must not be enabled until a cross-instance/database UoW-token design is fixed.

## Migration and roles

Run `MigrateReplayStore` with a dedicated migration owner. Bootstrap uses `IF
NOT EXISTS` only for the schema and migration ledger, then verifies their
catalog shape. Migration 1 omits `IF NOT EXISTS` for every operational object:
a partial or look-alike schema fails instead of being blessed. Re-runs compare
the embedded SHA-256 without replaying DDL. Full startup verification checks
columns, defaults, named constraints, deferred flags, triggers, explicit
indexes and the migration seal. Constraint definitions are compared as complete
normalized definitions plus exact catalog keys, referenced keys, backing index
and FK actions. Trigger verification binds the function namespace and identity,
type mask, enable mode, WHEN clause absence, transition/argument state,
constraint identity and complete definition. Index verification covers every
constraint and explicit index, validity/readiness, access method, key/include
columns, opclasses, collations, ordering/null behavior, predicate, expressions
and complete definition. The expected relation inventory is closed and any
inheritance, partition or extra relation fails startup. The `C` collation is
also fixed to its `pg_catalog` identity, libc provider, deterministic mode,
encoding and locale fields.

Migration 1 requires PostgreSQL 13 or newer because it uses the non-deprecated
`xid8`/`pg_current_xact_id()` interface. Workstream 0 must still freeze an exact
supported PostgreSQL image digest and driver version before promotion. Catalog
column branches cover the relevant version differences, but the complete
deparser contract is intentionally image-specific and may reject a different
major version even when its DDL is semantically similar.

The service must use a separate non-owner, non-superuser runtime role without
`CREATEROLE`, `CREATEDB`, `REPLICATION` or `BYPASSRLS`. Broad predefined
PostgreSQL read/write/server-file/monitor/maintenance roles are also rejected.
On PostgreSQL 15 and newer, effective and reachable-role parameter ACLs for
`session_replication_role` are rejected as well. Startup requires the live
session value to be `origin`.
Grant exactly:

```sql
GRANT USAGE ON SCHEMA cph_aiinfra TO cph_aiinfra_runtime;
GRANT SELECT ON cph_aiinfra.schema_migration TO cph_aiinfra_runtime;
GRANT SELECT, INSERT, UPDATE ON cph_aiinfra.ccse_replay_head TO cph_aiinfra_runtime;
GRANT SELECT, INSERT ON cph_aiinfra.ccse_durable_result TO cph_aiinfra_runtime;
GRANT SELECT, INSERT ON cph_aiinfra.ccse_replay_inbox TO cph_aiinfra_runtime;
GRANT SELECT, INSERT ON cph_aiinfra.ccse_outbox_intent TO cph_aiinfra_runtime;
GRANT EXECUTE ON FUNCTION cph_aiinfra.assert_completion_coupling() TO cph_aiinfra_runtime;
GRANT EXECUTE ON FUNCTION cph_aiinfra.enforce_replay_head_monotonic() TO cph_aiinfra_runtime;
GRANT EXECUTE ON FUNCTION cph_aiinfra.reject_immutable_change() TO cph_aiinfra_runtime;
GRANT EXECUTE ON FUNCTION cph_aiinfra.stamp_unit_of_work_transaction() TO cph_aiinfra_runtime;
```

Do not grant schema `CREATE`, table ownership, `DELETE`, `TRUNCATE`,
`REFERENCES` or `TRIGGER`. Migration 1 revokes schema/table/function access from
`PUBLIC`. `NewReplayStore(ctx, runtimeDB, ...)` calls `VerifyReplayStore` and
refuses construction if the schema or runtime privileges differ from this
contract.

## Evidence status

Normal unit, race and vet tests require no database. The offline SQL harness in
[`integration/`](integration/) is schema evidence only and does not start an
external service.

Gate 0 additionally requires an immutable-digest PostgreSQL image, a pinned Go
driver and driver-level fault/concurrency/restore tests covering handler
failure, connection loss, process death before/after commit,
restart/redelivery, serialization conflict, outbox dispatcher deduplication,
backup and restore. Until those tests pass and an EvidenceRecord is retained,
this package is an implemented fail-closed foundation, not evidence of
crash-safe production readiness or regional financial RPO 0.

In particular, the handwritten exact `pg_get_constraintdef`,
`pg_get_triggerdef` and `pg_get_indexdef` contracts have not yet been executed
against a real PostgreSQL catalog in this workspace. The pinned production
image must run both migration/startup verification and malicious-drift cases
(`OR TRUE`, trigger `WHEN false`, wrong-schema same-name function, invalid or
partial index, inheritance child and unsafe parameter ACL) before promotion.
