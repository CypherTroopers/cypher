# Rolling devnet WAL / snapshot v2 (local replay codec)

The current rolling WAL writer uses the exact action dictionary in
[wal-action-dictionary-spec.md](wal-action-dictionary-spec.md), then normalizes
to this v2 replay format on load. The v2 snapshot, legacy WAL interpretation,
state omission and all recovery rules described below remain unchanged.

This extends local persistence only. Checkpoint schema 4, financial state v5,
action bytes, consensus messages and signature domains are unchanged. Legacy
WAL/snapshot v1 and schema 1/2/3 retain their existing interpretation.

A rolling schema-4 writer emits Version=2. The records named in Finalized except
its last element encode State as JSON null. The finalized tip and every other
record retain their complete State. No action, proposal ref, QC, finality proof,
parent, safety watermark, reserved right or genesis data is removed. Selection
uses exact record keys, not a claimed height or a local finalized cache. The
writer copies records and never clears live application state.

Recovery checks the version/schema and exact omission layout before replay.
Starting from the configured genesis, it executes every record in parent-height
order. Missing State is reconstructed only for the permitted v2 entries. The
existing execution comparison still checks the entire checkpoint and proposal
ref, then verifies every QC, finalized descendant proof and durable safety
record. Present state must match byte for byte. No imported snapshot becomes a
trust root. Signing starts only after full recovery. A checksum-valid altered
action/root/ref/QC remains invalid. The imported snapshot contains no peer vote
watermarks or private keys; the receiver retains its own identity.

The WAL envelope remains JSON Payload plus SHA-256(domain || NUL || Payload).
Version 1 uses common-dex/wal/v1; version 2 uses common-dex/wal/v2. Unknown
versions, v2 with another execution schema, omission in an unfinalized/tip
record, or non-null old finalized state are rejected. A v2 WAL payload must
round-trip to exactly its canonical JSON bytes, so deleting a State field is
not interchangeable with explicitly encoding null. Legacy v1 loading and the
existing canonical snapshot JSON requirement remain. Bootstrap provenance hashes the complete
versioned snapshot bytes with the existing bootstrap-snapshot/v1 domain.

The serialized WAL and snapshot limit remains 2 MiB, record/finality count 128,
action 64 KiB, and individual reconstructed state 1 MiB. The aggregate retained
record states are additionally limited to 2 MiB in memory. Temporary execution
of one bounded state precedes the aggregate check. Exhaustion disables further
signing without deleting data or claims. This is finite retention, not indefinite
operation or snapshot-only trust. Startup now spends execution work to restore
omitted copies; total work remains bounded by 128 records. Native CLX state,
relay history, and source-anchor evidence limits are untouched.

Writes retain the existing temp-file fsync, atomic rename and directory fsync
boundary. A rolling v1 WAL is fully checked before its next save upgrades to v2.
No operational directory is migrated by the runner. Golden compact_replay.json
is an independent structural codec vector; its dummy records are not proofs.

## Bounded crash temporaries (all isolated DEX WAL versions)

The writer uses the single private name `state.pending.tmp`, created with
O_EXCL, O_NOFOLLOW and mode0600. Its bytes are never a recovery source. A complete
write, file fsync, atomic rename to `state.json`, and directory fsync are required
before a vote or other durable action may succeed. An unexpected pending-name
collision during an active process is a persistence failure and disables further
signing; it is not silently overwritten.

After acquiring the existing directory lock, startup first authenticates and
replays the canonical WAL, including the local vote/timeout/outbox watermarks.
The configured RestoreVote and finalized-execution callbacks must also succeed.
Only at the first subsequent persist may it inspect and remove old temporary
files. A fresh canonical-empty directory with no temporary candidates is allowed
through the existing configured-genesis recovery path. If `state.json` is
missing and any candidate remains, startup refuses and preserves all candidates:
an interrupted first creation cannot be distinguished from loss of an established
canonical WAL. Even an initial-creation crash therefore needs operator
investigation in that case, not automatic deletion. Missing/partial temporary bytes never supply
votes, checkpoints, finality, finance state or a replacement genesis.

Cleanup includes `state.pending.tmp` and legacy names `state-*.tmp`; every other
name is left untouched. The private directory must be owned by the current UID
with mode0700. All directory entries count toward a64-entry enumeration limit.
There may be at most32 temporary candidates, each at most2 MiB and together at
most8 MiB. Each candidate must be a current-UID, mode0600 regular file with one
hard link. Symlinks, other ownership/permissions/types, excess counts or bytes,
and validation errors stop startup. All candidates are inspected before any is
removed, so an unsafe candidate prevents deletion of the safe candidates too.
Successful removal is followed by directory fsync. No unmarked or external
directory is cleaned, and unknown names or symlink targets are never deleted.

Thus each subsequent process crash can leave at most one bounded temporary
generation. Legacy debris is reclaimed only within these explicit limits;
excess or unsafe debris requires operator investigation and remains intact.
Canonical corruption or replay/safety/callback failure must leave all debris
untouched. The crash test kills an owned subprocess after writing only half a
new generation, then authenticates the old canonical state and repeats recovery
to check that neither safety state nor temporary disk usage accumulates.
