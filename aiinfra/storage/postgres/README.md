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

Migration 2 adds a closed canonical-state substrate without making every CCSE
message an AuditEvent. Each v2 write belongs to one immutable
`authoritative_uow` receipt containing the exact outer scope, MessageID,
durable-result digest, content type, bounded payload and trigger-stamped xid8.
An `ADMISSION` UoW has no AuditEvent. An `AUDITED_FINAL` UoW names its actual
signed event, advances `audit_head`, and may either complete its own terminal
children or atomically derive a different future operation. Each collecting
idempotency/pending child carries its own immutable expected terminal EventID
and proves the corresponding global-ID reservation in every writing UoW. Thus
an audited transfer-acceptance transaction may reserve a later cutover event,
but cannot reuse its acceptance EventID as that child's terminal EventID.
Terminal idempotency/pending and canonical IAM/governance mutations require the
exact expected event in the same xid8. This keeps admission, repeated progress,
restart/reload, finalize and deadline reconciliation reachable without
fabricating an audit event during quorum collection.

Ordinary X, joined Y and compound-member aliases share one raw 16-byte primary
key in `business_idempotency_head`; row kind is metadata, never a uniqueness
namespace. Completed compound members are accepted only with their exact
umbrella X/Y, identical outcome and xid8. Global-ID assertions are immutable
claim rows and do not manufacture head updates. Mutations require the exact
monotonic head/history pair. Pending envelopes, revisions, evidence links and
generic canonical state use the same head/history and same-UoW rules.

The executable v2 boundary starts with `BindCanonicalUOW`. It accepts only the
exact `VerifiedRecord` and scope/MessageID owned by the active `Execute`
transaction, binds one owned Admission or AuditedFinal result receipt, and
returns a capability whose reads and writes use that transaction's connection.
Global-ID, idempotency, pending and evidence inputs are bounded and normalized
before SQL; authoritative reads use `FOR UPDATE`, and every mutation checks an
exact one-row insert/CAS result. Any validation, query, driver, row-count or
phase failure poisons the outer replay transaction. Admission forbids an audit
append. AuditedFinal cannot complete until its exact audit event/head, global
EventID claim and declared evidence assertions have all been written.

The storage `pending_kind` catalog is exactly IAM kinds 1 through 5 plus
storage kind 7 for a Governance policy-approval collection. IAM kinds use the
closed `cph.aiinfra.iam.pending.v1` codec; kind 7 uses the closed
`cph.aiinfra.governance.policy-approval-collection.v1` codec. IAM's kind-6
`OwnershipTransferAcceptance` is an ephemeral audited-final capability, not a
row discriminator: that UoW terminalizes the existing kind-3 collection and
may atomically create a distinct future kind-5 cutover pending row. Value 6 is
therefore intentionally unused and `ApplyDurablePendingRevision` rejects it
before SQL; its envelope or digest may be retained only as UoW evidence/result
commitment. Governance Admission UoWs retain full signed approval/profile
evidence in kind-7 revisions for reload and reconciliation.

`DurableEvidenceRecord` is a generic typed preimage carrier. Its digest framing
belongs to the semantic codec (for example, IAM pending envelopes use their own
domain separator), so this package cannot safely invent one generic hash rule.
Callers must verify the kind-specific digest before `ReserveDurableEvidence`.
New insertion and existing assertion are deliberately separate operations.
`AssertDurableEvidenceContent` locks an existing digest and requires kind,
content type, bytes and original AuditEvent provenance to match exactly; a
collision, provenance mismatch or restore mismatch poisons the transaction.

`Execute` checks `session_replication_role = origin` at transaction entry,
completion, before replay persistence and before commit. A process-wide atomic
single-flight guard rejects recursion even when a handler discards the supplied
context and calls a different `ReplayStore` instance. A transaction row lock on
the sealed migration record extends the same fail-fast fence across processes
and store instances without exposing a public advisory-lock key. Because the
foundation cannot distinguish recursion from legitimate overlap, it admits at
most one `Execute` across all databases in one process and at most one across
processes for each database. Parallel execution must not be enabled until a
scope-aware, fenced UoW-token design is fixed.

## Migration and roles

Run `MigrateReplayStore` with a dedicated migration owner. Bootstrap uses `IF
NOT EXISTS` only for the schema and migration ledger, then verifies their
catalog shape. Migration 1 omits `IF NOT EXISTS` for every operational object:
a partial or look-alike schema fails instead of being blessed. Re-runs compare
the embedded SHA-256 without replaying DDL. Full startup verification checks
columns, defaults, named constraints, deferred flags, triggers, explicit
indexes and every migration ledger seal. Constraint definitions are compared
as complete normalized definitions plus exact catalog keys, referenced keys,
backing index and FK actions. Trigger verification binds the function namespace
and identity, type mask, enable mode, WHEN clause absence,
transition/argument state, constraint identity and complete definition. Index
verification covers every constraint and explicit index, validity/readiness,
access method, key/include columns, opclasses, collations, ordering/null
behavior, predicate, expressions
and complete definition. The expected relation inventory is closed and any
inheritance, partition or extra relation fails startup. The `C` collation is
also fixed to its `pg_catalog` identity, libc provider, deterministic mode,
encoding and locale fields.

The numbered migration registry is closed and contiguous from version 1;
startup applies only an absent ordered suffix. Any change that requires service
quiescence, moves the execution-fence row, or breaks mixed-version read/write
compatibility is a maintenance cutover, not an unattended startup migration.

`MigrateReplayStore` alone is never a readiness signal because the owner-side
call cannot identify the intended runtime grantee. Readiness requires a
successful `VerifyReplayStore`/`NewReplayStore` call made by the dedicated
runtime login after grants are installed.

Migration 1 requires PostgreSQL 13 or newer because it uses the non-deprecated
`xid8`/`pg_current_xact_id()` interface. Workstream 0 must still freeze an exact
supported PostgreSQL image digest and driver version before promotion. Catalog
column branches cover the relevant version differences. On PostgreSQL 18 and
newer, every column-level `NOT NULL` entry is also required as its exact
`contype='n'` catalog constraint, including its generated name, key column,
definition, validation/enforcement status and non-period form. On older
versions the verifier requires the pre-18 catalog shape. The complete deparser
contract is intentionally image-specific and may reject a different major
version even when its DDL is semantically similar. Unreviewed PostgreSQL 19 and
newer versions are rejected before catalog inspection.

The service must use a separate non-owner, non-superuser runtime role without
`CREATEROLE`, `CREATEDB`, `REPLICATION`, `BYPASSRLS` or inherited privileges.
The connection must log in directly as that role (`current_user =
session_user`), and neither the runtime role nor schema-owner role may
participate in any membership edge. Broad predefined
PostgreSQL read/write/server-file/monitor/maintenance roles are also rejected.
On PostgreSQL 15 and newer, effective and reachable-role parameter ACLs for
`session_replication_role` are rejected as well. Startup requires the live
session value to be `origin`.
Grant exactly:

```sql
GRANT USAGE ON SCHEMA cph_aiinfra TO cph_aiinfra_runtime;
GRANT SELECT, UPDATE ON cph_aiinfra.schema_migration TO cph_aiinfra_runtime;
GRANT SELECT, INSERT, UPDATE ON cph_aiinfra.ccse_replay_head TO cph_aiinfra_runtime;
GRANT SELECT, INSERT ON cph_aiinfra.ccse_durable_result TO cph_aiinfra_runtime;
GRANT SELECT, INSERT ON cph_aiinfra.ccse_replay_inbox TO cph_aiinfra_runtime;
GRANT SELECT, INSERT ON cph_aiinfra.ccse_outbox_intent TO cph_aiinfra_runtime;
GRANT SELECT, INSERT ON cph_aiinfra.authoritative_uow, cph_aiinfra.audit_event,
  cph_aiinfra.business_idempotency_history, cph_aiinfra.global_identifier_history,
  cph_aiinfra.global_identifier_claim, cph_aiinfra.durable_evidence,
  cph_aiinfra.durable_pending_revision, cph_aiinfra.durable_pending_evidence,
  cph_aiinfra.durable_evidence_assertion,
  cph_aiinfra.canonical_state_history TO cph_aiinfra_runtime;
GRANT SELECT, INSERT, UPDATE ON cph_aiinfra.audit_head,
  cph_aiinfra.business_idempotency_head, cph_aiinfra.global_identifier_head,
  cph_aiinfra.durable_pending_head, cph_aiinfra.canonical_state_head
  TO cph_aiinfra_runtime;
GRANT EXECUTE ON FUNCTION cph_aiinfra.assert_completion_coupling() TO cph_aiinfra_runtime;
GRANT EXECUTE ON FUNCTION cph_aiinfra.enforce_replay_head_monotonic() TO cph_aiinfra_runtime;
GRANT EXECUTE ON FUNCTION cph_aiinfra.reject_immutable_change() TO cph_aiinfra_runtime;
GRANT EXECUTE ON FUNCTION cph_aiinfra.stamp_unit_of_work_transaction() TO cph_aiinfra_runtime;
GRANT EXECUTE ON FUNCTION cph_aiinfra.assert_authoritative_uow(),
  cph_aiinfra.assert_audit_uow_member(), cph_aiinfra.assert_audit_event_uow(),
  cph_aiinfra.assert_audit_head_event(),
  cph_aiinfra.assert_business_idempotency_consistency(),
  cph_aiinfra.assert_global_identifier_consistency(),
  cph_aiinfra.assert_durable_evidence_assertion(),
  cph_aiinfra.assert_durable_pending_consistency(),
  cph_aiinfra.assert_durable_pending_evidence_consistency(),
  cph_aiinfra.assert_canonical_state_consistency(),
  cph_aiinfra.enforce_audit_head_change(),
  cph_aiinfra.enforce_business_idempotency_head_change(),
  cph_aiinfra.enforce_global_identifier_head_change(),
  cph_aiinfra.enforce_durable_pending_head_change(),
  cph_aiinfra.enforce_canonical_state_head_change() TO cph_aiinfra_runtime;
```

Do not grant schema `CREATE`, table ownership, `DELETE`, `TRUNCATE`,
`REFERENCES` or `TRIGGER`. Migration 1 revokes schema/table/function access from
`PUBLIC`. Runtime startup inventories every direct ACL row and rejects grants to
any role other than the schema owner and `current_user`; `current_user` must
have exactly the grants above, directly from the owner and without grant
options. The authoritative database may not be a logical subscriber; explicit
publication membership, database-wide publications and schema publications are
also rejected because replication workers can bypass origin-only triggers or
turn internal writes into an undeclared external effect.
`NewReplayStore(ctx, runtimeDB, ...)` calls
`VerifyReplayStore` and refuses construction if the schema or runtime
privileges differ from this contract.

`schema_migration` receives `UPDATE` only because PostgreSQL requires it for
the transaction-scoped `FOR UPDATE SKIP LOCKED` execution fence. The sealed
table's mandatory immutable trigger rejects every actual update or delete.

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

A local disposable PostgreSQL 18.4 calibration has exercised the complete
migration-1 and runtime startup verifier, exact PostgreSQL 18 `NOT NULL` catalog
rows, restricted-role ACLs, membership drift, publication/subscription drift,
the immutable migration row and its cross-session execution fence. A local pgx
driver smoke test also completed an authoritative `Execute`, reloaded its
durable result and recovered an exact duplicate without rerunning the handler.
This is diagnostic evidence only: it used an unpacked local package and an
untracked driver harness rather than the retained immutable-image CI evidence
required by Gate 0. The pinned production image must also run all malicious
catalog cases
(`OR TRUE`, trigger `WHEN false`, wrong-schema same-name function, invalid or
partial index, inheritance child and unsafe parameter ACL), crash/restart and
restore cases before promotion.

Migration 2's handwritten deparser contracts and its admission/final/reconcile
trigger graph have not been executed against any real PostgreSQL server in this
workspace. Immutable-image migration, full catalog calibration, malicious
drift, multi-admission, crash/reload, finalize/reconcile and backup/restore
evidence therefore remain an explicit Gate-0 blocker.
