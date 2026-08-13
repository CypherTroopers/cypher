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

SQLSTATE `40001` aborts are retried in a fresh SERIALIZABLE transaction with a
bounded, context-aware exponential backoff (three attempts by default, at most
eight when explicitly configured). The handler can therefore run more than
once; remote effects belong only in its durable outbox completion.

Migration 4 adds the mutable delivery state beside the immutable outbox intent.
`OutboxDispatcher` initializes a state row, commits a database-clock lease,
then calls the publisher outside the database transaction. Success or failure
is acknowledged only by the exact random lease token. Failed publication and
expired-worker recovery redeliver the stable destination/deduplication key with
bounded retry scheduling. Delivery is intentionally at-least-once: publishers
must atomically deduplicate that key because a process can die after the remote
publish succeeds and before PostgreSQL records its acknowledgement.
The runtime role has no direct privilege on `ccse_outbox_delivery`: active
lease tokens are bearer capabilities and cannot be exposed through table
`SELECT`. Initialization/claim and fenced acknowledgement/rejection run only
through three sealed schema-owner `SECURITY DEFINER` functions with a fixed
`pg_catalog` search path, bounded inputs, database-clock deadlines and exact
row-count enforcement.

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
before SQL; mutable heads use `FOR UPDATE`, immutable histories/evidence use
the same SERIALIZABLE connection, and every mutation checks an exact one-row
insert/CAS result. Any validation, query, driver, row-count or phase failure
poisons the outer replay transaction. An outer AuditEvent maps if and only if
the UoW is AuditedFinal; Admission cannot downgrade one or append an audit
event. AuditedFinal cannot complete until its exact audit event/head, global
EventID claim and declared evidence assertions have all been written.
The authoritative receipt stores the verified outer envelope payload digest
for AuditedFinal only; deferred SQL binds it to `audit_event.event_digest`,
while the event bytes must independently hash to that digest and the inbox
continues to bind the complete signed-record digest.

Handlers whose semantic result depends on transaction-bound reads use
`OpenCanonicalUOW`, perform only reads and `SnapshotTransactionClock`, prove
the result's outer record with `AssertOuterVerifiedRecord`, then call the
one-shot `BindResult` before any mutation. The clock snapshot exposes immutable
getters for the full xid8 text and Unix-nanosecond database time from that exact
SERIALIZABLE transaction; its first valid observation is cached byte-exactly for
all later calls on the same UoW. Pre-bind writes and completion fail
closed, so a process clock or another connection cannot authorize commit-time
revalidation.

Immediately before PostgreSQL commit, the replay store first executes every
deferred constraint and then performs a fresh uncached database-clock check of
the bound half-open `CommitNotAfter` fence. No write is permitted after that
observation. `CommitNotAfter` therefore names the database commit-
authorization instant, not client acknowledgement or synchronous-replication
latency after PostgreSQL has accepted `COMMIT`.

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

Every same-kind OPEN advance carries the preceding canonical envelope,
digest, and commit window as explicit optimistic-CAS inputs. PostgreSQL locks
and compares that complete predecessor before replacing the head, while the
deferred history invariant requires the new revision to name the exact prior
OPEN revision. IAM kind 3 is append-only and therefore retains every prior
evidence link. Governance kind 7 permits exactly the two semantic transitions
that its planner can produce: add one approval digest while retaining the
entire prior set, or exchange exactly one prior digest for exactly one new
digest. The deferred database invariant rejects no-op, multi-add, multi-drop,
and arbitrary replacement sets even when the typed coordinator is bypassed.

A successful same-kind terminal revision is lifecycle metadata, not a new
semantic envelope: it preserves the preceding OPEN revision's codec, canonical
bytes, envelope digest, commit window and retained evidence set exactly while
adding only terminal status and outcome. Its update CAS includes the
caller-owned preceding canonical bytes and commit window. Kind 4 reconciliation
is the sole terminal path that changes
kind and semantic envelope; its immutable predecessor must be an exact OPEN IAM
kind 1, 2, 3 or 5 revision.

`DurableEvidenceRecord` is a generic typed preimage carrier. Its digest framing
belongs to the semantic codec (for example, IAM pending envelopes use their own
domain separator), so this package cannot safely invent one generic hash rule.
Callers must verify the kind-specific digest before `ReserveDurableEvidence`.
New insertion and existing assertion are deliberately separate operations.
`AssertDurableEvidenceContent` reads an immutable digest in the active
SERIALIZABLE transaction and requires kind, content type, bytes and original
AuditEvent attribution to match exactly; a
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
`xid8`/`pg_current_xact_id()` interface. Migration 2's complete constraint
deparser contract is currently calibrated only for `server_version_num =
180004` (PostgreSQL 18.4); every other minor or major version fails closed.
Workstream 0 must still freeze that exact supported PostgreSQL image digest and
the pinned driver version before promotion. On PostgreSQL 18.4, every
column-level `NOT NULL` entry is also required as its exact
`contype='n'` catalog constraint, including its generated name, key column,
definition, validation/enforcement status and non-period form. Migration 1
retains its reviewed version branches, but migration 2 rejects uncalibrated
servers even when their DDL is semantically similar.

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
  cph_aiinfra.canonical_state_history,
  cph_aiinfra.canonical_semantic_projection TO cph_aiinfra_runtime;
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
  cph_aiinfra.assert_governance_profile_activation_timeline(),
  cph_aiinfra.assert_required_semantic_projection(),
  cph_aiinfra.assert_semantic_projection_consistency(),
  cph_aiinfra.enforce_audit_head_change(),
  cph_aiinfra.enforce_business_idempotency_head_change(),
  cph_aiinfra.enforce_global_identifier_head_change(),
  cph_aiinfra.enforce_durable_pending_head_change(),
  cph_aiinfra.enforce_canonical_state_head_change(),
  cph_aiinfra.enforce_outbox_delivery_transition() TO cph_aiinfra_runtime;
GRANT EXECUTE ON FUNCTION
  cph_aiinfra.claim_outbox_delivery(BYTEA, BYTEA, BIGINT, INTEGER),
  cph_aiinfra.acknowledge_outbox_delivery(BYTEA, BYTEA, BYTEA),
  cph_aiinfra.reject_outbox_delivery(BYTEA, BYTEA, BYTEA, BIGINT, BYTEA)
  TO cph_aiinfra_runtime;
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

The workspace now pins pgx v5.7.6 and has run the opt-in driver tests against a
local disposable PostgreSQL 18.4 host package. That run exercised both sealed
migrations, owner-side idempotent migration, exact restricted-runtime startup
verification and an `OR TRUE` constraint-tamper rejection whose DDL was rolled
back. The migration-2 lifecycle persisted Admission revision 1, reloaded and
advanced it to revision 2, committed an AuditedFinal terminal revision, loaded
the terminal state and durable evidence in a later UoW, and proved exact
redelivery of both Admission and AuditedFinal without invoking either handler
again. A separate database-clock test crossed the admitted deadline and
committed the audited kind-4 reconciliation transition before reloading its
terminal state.

The live fault test also observed complete rollback after an injected handler
failure and after a deferred-constraint drain failure. It exercised concurrent
exact redelivery and the cross-session execution fence followed by successful
redelivery. A separate helper-process run terminated the exact runtime backend
after staged canonical writes and killed a process before `AtomicTx.Complete`;
both cases retained zero authoritative rows and exact redelivery then committed.
It also exited the helper immediately after `Execute` returned from a successful
commit and recovered the duplicate result in a new process. A test-only driver
wrapper now stops at `driver.Tx.Commit` entry, after the handler returned and
all replay writes, deferred constraints and commit-deadline checks completed;
killing that child retains zero rows and exact redelivery commits. The live
fault suite additionally constructs a real PostgreSQL SERIALIZABLE read/write
conflict, observes SQLSTATE `40001`, and requires a fresh successful retry.

The opt-in outbox suite exercises publisher failure, database-clock retry,
lease-expiry recovery, multi-worker `SKIP LOCKED`, immutable-intent tamper
rejection, and the crash-after-publish-before-acknowledge window. Its idempotent
sink observes two publication calls for that crash window but one logical
effect, followed by a terminal fenced acknowledgement.

The backup/restore harness in [`integration/`](integration/) has run a
PostgreSQL 18.4 custom-format `pg_dump`/`pg_restore` fixed-point test. Restricted
runtime verification passed on source and restore, all 22 authoritative tables
matched as primary-key-ordered logical SHA-256 streams, and a terminal pending
UoW's durable result was reloaded through `ReplayStore`. The retained local
archive, digest, manifest and logs record that host-package run. Calibration
also found PostgreSQL 18.4's first dump/restore changes only the deparser's
parenthesis grouping for three compound `audit_head` checks. Startup therefore
accepts a closed two-digest raw-definition set for that table; the other 14 v2
tables retain one raw-definition digest each. Exact server version, complete
per-constraint metadata and malicious-definition rejection remain mandatory.

Gate 0 is still not complete. The successful historical runs used an unpacked
host package, not PostgreSQL supplied by the release's immutable OCI digest;
the newly added migration-3 semantic projection and migration-4 outbox tests
also require the final integrated PostgreSQL 18.4 run. CI must retain the
signed EvidenceRecord and supply-chain evidence. Until those items pass on the
pinned image, this package remains a fail-closed storage foundation rather than
evidence of crash-safe production readiness or regional financial RPO 0.
