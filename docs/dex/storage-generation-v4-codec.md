# Storage generation v4: fixed codec and implementation gate

Status: specification fixed before implementation; tests below are initially
NOT_RUN. This is a local DEX persistence schema, not a committee epoch or CLX
genesis change. Continuous financial execution uses its separately configured
schema 5. Existing finite fixtures keep their prior persistence paths.

`StorageGenerations=true` selects local WAL v4. Absolute `MaxHeight` is a finite
operating budget (2..4096), not the hot-record capacity. Hot records remain at
128 and normal cuts archive a finalized prefix every 64 heights. No old-format
migration is provided by this option. A v4 directory cannot silently open as a
legacy WAL and the reverse is refused.

Canonical JSON means Go `encoding/json` output for the stated struct order,
without insignificant whitespace or trailing data. Every envelope has fields
`Payload` (raw JSON object) and `Checksum` (protocol.Hash). Digest domains are
`common-dex/wal/v4`, `common-dex/archive-entry/v4`, and
`common-dex/storage-current/v4`. Their digest is existing
`SHA256(label || 0x00 || payload)` via `protocol.Digest`; codec golden tests fix the bytes and digest. A checksum only
detects corruption; it never authenticates the financial state or signatures.

The WAL retains the existing execution/domain/own-safety fields, plus:

- `Generation`: local storage generation, initially zero.
- `BaseHeight`: greatest archived finalized height; `Finalized[0]` has absolute
  height `BaseHeight+1`.
- `ArchiveTip`: lower-case 64-character hex hash of archive entry `BaseHeight`,
  omitted at genesis.
- `ArchiveBytes`: checked byte sum of the retained immutable archive files.

The latest cut record is stored in the hot record set as a parent/safety pin.
Old own LastVote, HighestQC, selected parent, Outbox and outstanding build
parents retain their records; their authenticated canonical parents may be
loaded as bounded archive entries. If required pins do not fit, admission stops.
No watermark is reduced and no signature is emitted after a persistence error.

`CURRENT` golden payload `{"Version":4,"Generation":2}` has digest
`06d8f5c6afb82ed3a9e02e35152d9c21d289f611bbf9df47f789f6cadd4c69e9`,
independently calculated using Python `hashlib.sha256` and the stated bytes.

Each immutable archive file is `history/archive-%020d.json` for one absolute
finalized height. Its payload field order is `Version`, `Domain`, `Height`,
`Previous`, `Record`, `Finalized`; version is exactly 4, and Previous is the prior
archive digest (zero for height 1). Record preserves checkpoint, full action,
full state, proposal reference and QC; Finalized preserves key/hash/descendant
proof. Each entry is <=2 MiB. Single-entry chunks avoid cumulative byte expansion
when a state approaches the existing 1 MiB per-state bound. Unknown schemas,
noncanonical encodings and invalid bounds are rejected.

Archive entries are not pruned in this implementation: old unpaid claims retain
the exact state/proof required by existing FinalizedState/Checkpoint APIs.
Nullifiers, custody and claim reservations remain CLX consensus state. Total
local archive capacity defaults to 256 MiB and is limited to 8 MiB..1 GiB; 4 MiB
is reserved for hot/pending files. This is finite retention, not unlimited
operation: quota exhaustion pauses new proposals without deleting rights or
vote safety. Recovery streams one archive entry and its predecessor at a time,
reexecutes from configured genesis, validates each QC/2-chain finality and
checkpoint/state continuity, then replays bounded hot records. It never loads
the entire old WAL into a map. Cold verification work grows with archive length.
Cold replay reconstructs a fixed 4,097-entry digest array (131,104 bytes). Later
historical reads check one <=2 MiB entry against that authenticated index and
verify its QC/finality. This index is never loaded as a persisted trust root;
it does not contain or cache old financial state. The archive quota counts
logical file bytes, with reserved workspace; filesystem metadata/allocation and
host free space must additionally be observed by the deployment runner.

`CURRENT` is a <=1 KiB canonical envelope with payload fields `Version`=4 and
`Generation`. It names `state-%020d.json`. The hot file stays <=2 MiB. Rotation
persists immutable entries, writes/fsyncs the next hot state, then atomically
replaces CURRENT and fsyncs its directory before enabling further signing.
Old hot state can be removed only after this publication succeeds. A published
CURRENT with a missing/corrupt named state fails closed; it never falls back to
the old generation and signs with stale safety state. Unpublished archive tails
are never trusted by their checksum. Before reuse, both old and newly supplied
QC/finality proofs are authenticated, and domain, height, previous archive
digest, checkpoint, reference, action, state, finalized key/hash and QC semantics
must match the reexecuted prefix. A different valid signer subset can prove the
same QC; the existing authenticated bytes and their digest chain remain immutable.
The low-level archive writer still rejects every nonidentical replacement.

Snapshot/export must preserve the authenticated archive chain. Until a bounded
archive-transfer interface is implemented, legacy single-file snapshot export
after a cut is explicitly unavailable, not falsely advertised as a complete
bootstrap snapshot. Existing voter cold restart and historical claim data
retrieval remain required by the initial implementation gate.

Required tests: real seven-manager FHS at >=130 heights, two 64-height cuts,
same-directory cold reopen, identical absolute roots/checkpoints, old state
retrieval, unchanged vote/timeout/outbox safety, same-view conflict rejection,
missing/corrupt archive/CURRENT/hot state, disk quota backpressure, and selected
crash boundaries. Small-threshold tests do not substitute for actual 64 cuts.
