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

Migration 2 is intentionally not claimed by this harness yet. Its catalog
deparser output and admission/advance/final/reconcile trigger graph must first
be calibrated on the immutable-digest PostgreSQL image; until then it remains
a Gate-0 blocker rather than simulated database evidence.

The harness deliberately does not start Docker, download an image, create a
database or select a driver. CI must supply a PostgreSQL image by immutable
digest and a separately pinned Go `database/sql` driver. The future driver-level
suite must exercise `ReplayStore.Execute` against that database with:

- concurrent same-scope and independent-scope requests;
- handler failure and serialization conflict;
- connection loss before commit;
- process death immediately before and after commit;
- restart plus exact redelivery;
- duplicate message-ID conflict and unsigned-sequence boundaries;
- outbox dispatcher redelivery and deduplication;
- backup, restore and catalog/role verification after restore;
- malicious catalog drift for complete constraint, trigger, index, relation,
  inheritance, collation and PostgreSQL 15+ parameter-ACL contracts.

No Gate 0 or crash-safety claim is valid until those driver-level cases run in
CI and their EvidenceRecord is retained. The local SQL harness is schema
evidence only.
