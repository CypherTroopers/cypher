# PostgreSQL integration evidence harness

`run-schema-conformance.sh` applies the bootstrap and migration 1, then exercises the
database-enforced immutable inbox/result, monotonic replay head, positive
no-effect/outbox completions, missing inbox/intent rejection and forged `xid8`
rejection inside one transaction. It also rejects a replay-head sequence that
does not have the exact same-transaction inbox scope/counter/sequence. It always
ends with `ROLLBACK`,
but still requires both of these explicit environment variables so it cannot be
pointed at a shared database accidentally:

```text
CPH_AIIE_POSTGRES_DISPOSABLE=YES
CPH_AIIE_POSTGRES_DSN=postgres://...
```

This rollback-only harness remains migration-1 schema evidence. The opt-in Go
test in the parent package separately installs and verifies migrations 1 and 2
and exercises their driver-level canonical lifecycle on PostgreSQL 18.4. A
local host-package run has completed Admission revision 1, open revision 2,
AuditedFinal terminalization, later reload, exact Admission/final duplicates,
deadline-driven kind-4 reconciliation, handler/deferred-constraint rollback,
concurrent redelivery and execution-fence recovery. Helper-process cases also
terminate the exact backend after staged writes, kill the process before
`AtomicTx.Complete`, stop exactly at driver `Commit` entry after handler return
and kill there, and exit immediately after a successful commit before a new
process proves duplicate/result recovery. The fault suite constructs a real
PostgreSQL SERIALIZABLE conflict and observes a fresh retry. The outbox suite
covers publish failure, lease expiry, multi-worker `SKIP LOCKED`, immutable
payload tamper rejection and crash-after-publish recovery through an idempotent
sink.

The rollback-only harness deliberately does not start Docker, download an
image, create a database or select a driver. CI must supply PostgreSQL 18.4 by
immutable image digest. It must repeat the completed live cases and retain
their evidence, and the driver-level suite must add or complete:

- concurrent same-scope and independent-scope requests;
- handler failure and serialization conflict;
- the handler-return-to-physical-commit kill window;
- restart plus exact redelivery;
- duplicate message-ID conflict and unsigned-sequence boundaries;
- outbox dispatcher redelivery and deduplication;
- backup, restore and catalog/role verification after restore on that image;
- malicious catalog drift for complete constraint, trigger, index, relation,
  inheritance, collation and PostgreSQL 15+ parameter-ACL contracts.

No Gate 0 or crash-safety claim is valid until those driver-level cases run in
CI and their EvidenceRecord is retained. The new commit-adjacent kill,
serialization-retry and outbox cases still need the final integrated
PostgreSQL 18.4 and immutable-image executions. The local SQL harness is schema
evidence only; host-package Go and restore runs do not establish the required
immutable-image provenance.

## Live backup/restore acceptance

`run-live-backup-restore.sh` captures a consistent custom-format dump from a
completed live-lifecycle database, creates one previously absent restore
database, restores through its direct owner login and invokes the opt-in Go
restore test through both direct owner and restricted runtime logins. The owner
connections compute the complete logical table digests because runtime cannot
read active outbox bearer tokens; startup verification and durable-result
reload still run through runtime. The harness never drops, truncates, cleans or
reuses a database. A failure intentionally retains the newly created database
and evidence directory for diagnosis.

The source must already contain at least one replay inbox/result, authoritative
UoW, AuditEvent, terminal durable-pending head, v2 semantic projection, outbox
intent and initialized delivery row; run the complete live lifecycle and
outbox suites against that same disposable source first. The test performs full
`VerifyReplayStore` and `NewReplayStore` checks against source and restore,
then compares every authoritative table as a primary-key-ordered logical
SHA-256 stream. It also reconstructs the replay identity attached to a terminal
pending head and loads its durable result through the public runtime adapter.
It reads the source immediately before and after the comparison, so writes that
occur after `pg_dump` make the evidence fail instead of silently comparing
different points in time.

The admin login may create databases; it is not used to restore objects or run
the verifier. Both owner and runtime roles must already exist. The restored
runtime login must be the same role as the source runtime because the archive
retains the reviewed direct ACL. The restore database name and evidence path
must both be new:

```sh
export CPH_AIIE_POSTGRES_DISPOSABLE=YES
export CPH_AIIE_POSTGRES_RESTORE_ACCEPTANCE=YES
export CPH_AIIE_POSTGRES_RESTORE_SOURCE_OWNER_DSN='postgres://owner:...@host/source?sslmode=require'
export CPH_AIIE_POSTGRES_RESTORE_SOURCE_RUNTIME_DSN='postgres://runtime:...@host/source?sslmode=require'
export CPH_AIIE_POSTGRES_RESTORE_ADMIN_DSN='postgres://admin:...@host/postgres?sslmode=require'
export CPH_AIIE_POSTGRES_RESTORE_DATABASE='cph_aiinfra_restore_unique'
export CPH_AIIE_POSTGRES_RESTORE_OWNER='cph_aiinfra_restore_owner'
export CPH_AIIE_POSTGRES_RESTORED_OWNER_DSN='postgres://restore_owner:...@host/cph_aiinfra_restore_unique?sslmode=require'
export CPH_AIIE_POSTGRES_RESTORED_RUNTIME_DSN='postgres://runtime:...@host/cph_aiinfra_restore_unique?sslmode=require'
export CPH_AIIE_POSTGRES_RESTORE_EVIDENCE_DIR='/retained-evidence/cph-aiinfra-restore-unique'
./aiinfra/storage/postgres/integration/run-live-backup-restore.sh
```

For a local peer-authenticated cluster, the optional
`CPH_AIIE_POSTGRES_RESTORE_ADMIN_OS_USER=postgres` makes only the database
existence check and `createdb` run through `runuser`; dump, restore and both
verifiers still use the explicit direct-login DSNs. Leave it unset in CI and
remote environments.

The retained directory contains the custom archive and SHA-256, archive table
of contents, dump/restore logs, verbose Go acceptance log and a manifest with
tool versions, Git commit, database/role identities and completion status. DSNs
and passwords are not written to those artifacts. The immutable PostgreSQL
image digest and CI EvidenceRecord must be retained alongside this directory;
an unpacked host-package run is useful real-DB evidence but does not by itself
close Gate 0.
