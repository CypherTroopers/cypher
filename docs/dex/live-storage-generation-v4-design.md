# Q3: Concrete design proposal for DEX consensus storage generation v4

2026-09-23. **DESIGN_ONLY / NOT_IMPLEMENTED / New tests NOT_RUN**. This document proposes an implementation based on the current Go source; no Go edits, codec adoption, migration, or live generation switch have been performed. See the [storage cap audit](live-storage-cap-audit.md) for the actual caps.

Here, **v4 is the proposed local WAL/storage format version**. It does not share a version namespace with the current `RollingExecutionSchema=4`, FinancialState v5, CLX DEX config v3, or snapshot v2. Financial state and CLX storage changes require separate consensus specifications with their own versions/domains. Matching version numbers alone do not establish compatibility. Automatic migration from old WAL v1/v2/v3 is outside the current request, but recovery after the same new v4 generation has signed is mandatory.

## 1. Current coupling points

- In [app.go](../../dex/consensus/app.go), `FinalizedHeight()` is `len(a.disk.Finalized)`. `FinalizedCheckpoint`, `commitAncestors`, and `reconcileFinalizedExecution` index heights using `height-1`. `storeRecord` stops the lifetime map at 128 entries.
- In [wal.go](../../dex/consensus/wal.go), `parentQC` scans all Records, and `recover` orders all records and reexecutes from genesis. `compactRecords` and the action dictionary retain all records.
- In [execution.go](../../dex/consensus/execution.go), `executionParent` retrieves the parent Record's State. `FinalizedState` also depends on the lifetime map and finalized array.
- [snapshot.go](../../dex/consensus/snapshot.go) includes all records with QCs in snapshots. `ImportSnapshot` only supports a new, empty voter. `extendsFinalized` follows parentQC links and compares against the current finalized tip.
- [repair.go](../../dex/consensus/repair.go) sends certified data from the entire map, oldest first, and also indexes old finalized bodies with `Sequence-1` for comparison. If every received old record is reinserted into the hot map, generation rotation will still have its reclamation undone.
- [finance/factory_data.go](../../dex/service/finance/factory_data.go) regenerates old claims from `FinalizedState(height)`. The latest financial state alone cannot reconstruct claim bytes/paths for past blocks.
- The existing fields in [FHSSafetyState](../../reconfig/hotstuff/fhs_v2.go) are Version, Domain, LastVote, LastTimeoutVote, LastTimeoutView, HighestQC, and HighestTC. There is no separate `LockedQC` field in the current implementation. `lockView` prunes the manager's view cache; do not introduce a separate BFT lock rule into this storage update.

## 2. Stored information and responsibilities

### 2.1 Absolute height and hot offset

The proposed `diskStateV4` explicitly includes the following.

|Field|Meaning|
|---|---|
|Binding|domain, ExecutionID/schema, configured GenesisRoot, registry commitment, local vote public key|
|Generation|Local storage generation; distinct from the DEX epoch and CLX chain generation|
|BaseHeight/BaseCheckpoint/BaseRef/BaseQC/BaseFinality|Authenticated finalized cut preceding the hot array; height zero is only the existing configured execution genesis|
|BaseState|Complete financial state matching the cut checkpoint's PostRoot and passing the execution-specific validator|
|HotFinalized|Consecutive finalized records starting at `BaseHeight+1`; global height is `BaseHeight+len(HotFinalized)`|
|HotRecords|Canonical/certified/pending/orphan records after the cut, retaining the maximum of 128|
|SafetyPins|Old bodies/QCs referenced by own safety state, unfinished outbox/build, or selected parent, and their authenticated retrieval locations|
|Safety/Outbox|Current exact own safety and leader QC outbox; generation rotation does not reset them|
|ArchiveTip|Terminal range/commitment of the generation archive and index generation; the checksum only detects corruption|
|CallbackCursor|Boundary through which local subsystem finalization notifications have completed; neither economic finality nor CLX acceptance|

First centralize `finalizedAt(height)`, `lookupRecord(proposalID)`, and `lookupParentQC(qcID)` instead of leaving `height-1` throughout the code. Treat height and view separately. Absolute DEX height remains consecutive even when timeouts skip views.

Separate the hot map's 128-entry cap from the fixture's absolute execution-height limit. Simply increasing the current `Config.MaxHeight` is not generation rotation. Live operation needs separate submission/work budgets and storage windows to avoid unlimited lifetime record retention. The consensus limit on accepted sequences must match the CLX specification maintained by the integration owner.

### 2.2 Retaining safety information

Perform normal rotation on the Application's serialized event loop, avoiding persistence of an old safety snapshot concurrently with a new vote/timeout/signature. Fix the following candidate pin set.

- Own LastVote's ProposalID/Ref and the exact parent QC/state used for its execution.
- HighestQC, selected parent, leader Outbox, and the pending build's ParentQC.
- Existing highest TC and last timeout vote/view. Retain their deadline/view watermarks independently of the cut.
- The latest finalized cut's target QC and actual FHS descendant proof. Do not promote a single QC to finality.

Pins have both a maximum count and a byte budget. If too many old references remain to fit, defer rotation with `storage_wait`. Do not discard safety records arbitrarily. If an orphan older than the cut supports own LastVote, authenticate its body/action/ref and original parent through a dedicated historical verification path without readopting it as an active parent. Obtain required parents from authenticated historical snapshots and bounded chunk replay. Do not provide a fallback that expands all Records from genesis into the map.

The current `Collector.BeforeVote` fsyncs the collector watermark before the FHS WAL, and `CheckFHSWatermark` checks that the collector is at least as advanced as FHS. Collector reclamation must retain own LastVote target/ClosedThrough and preserve this one-way crash tolerance. Do not roll back FHS and collector together to make them appear consistent.

### 2.3 State, old claims, and archives

Make archive chunks immutable and check each chunk's structural limits before reading it. Proposed limits are **2 MiB and 64 records per chunk**. Close the chunk before either limit is reached. This does not mean that 64 records with maximum-size actions must fit into one chunk. Retain existing limits of 64 KiB per action, 1 MiB per state, and 2 MiB per snapshot/active WAL.

Each chunk contains an absolute range, previous chunk commitment, start/end checkpoint hashes/roots, the exact action/ref/QC/finality of each canonical record, and references to required boundary snapshots. Store noncanonical safety pins with a separate type and index from canonical ranges. A matching local chunk checksum does not authenticate economic state or finality.

Archive each finalized block's **existing SettlementBundle** (checkpoint, FinanceSummary, FHS proof, all withdrawal/reward leaves and counts/paths) before reclaiming its state copy. Retain the existing bundle limits of 128 KiB / 128 claims / path depth 7, and verify claim totals and roots with `VerifySettlementBundle`. Generate bundle bytes from the finalized state matching that cp. Archive presence alone must not be displayed as CLX accepted/paid.

The initial Q3 approach does not delete archives. Set a finite total disk quota and headroom for two generations during switching, and throttle intake when full. **Bounding the hot set does not eliminate disk growth across the full history**. Display the limitation that operation stops safely at the quota. Do not make quota space by deleting unpaid claims, unsettled checkpoints, imported boundaries, own safety, or relay nonces.

Split the archive generation index itself into bounded pages. Do not load all filenames or the entire index into `ReadDir`/a `map` every time. The range index locates candidates; reauthenticate final evidence using the target cp/proof and chain connection. Reject unknown paths, symlinks, different owners, oversized files, different domains, and noncanonical codecs.

## 3. Authenticated cut and startup recovery

### 3.1 Authentication order

1. Construct the configured genesis/domain/fixed epoch registry through the current entry points. Do not adopt the snapshot submitter's validator set.
2. Use `Epoch.Verify(BaseCheckpoint, BaseFinality)` to check the target and descendants, domain/epoch, and proof metadata corresponding to parent/view/SignInfo.
3. Use the finance component's `ValidateSnapshotState(raw, context)` to check canonical decoding, accounting invariants, absolute height, inbox cursor, anchor identity, unclosed fees/participation, and state Root, matching `BaseCheckpoint.PostRoot`. The consensus package must not guess the hash function.
4. Stream archive chunks from genesis/the previous authenticated cut and reauthenticate checkpoint Previous/PreRoot/PostRoot, consecutive sequences, parent QC/ref, and the connection through the target cut. Do not skip missing data or forks using only the latest snapshot. Bound the state held while processing each chunk, and release unnecessary buffers from the previous chunk before moving to the next.
5. With BaseState as the active parent, reexecute post-cut hot records using the existing `Execute`, matching checkpoint/ref/action root/state root and QC. Use the correct parent state for each unfinalized branch.
6. Check exact own Safety/Outbox and pins against the collector watermark. Do not start the signer, transport votes, or new external effects of `OnFinalizedExecution` until recovery completes.

Total cold-recovery work grows with the number of historical chunks; do not describe it as constant time. Bound bytes and signature/replay counts per step, and retain the authenticated frontier and input commitments when resuming intermediate state. External RPC latest values and memory caches are not substitutes for authentication.

### 3.2 New nodes and existing voters

Do not simply remove `ImportSnapshot`'s rejection of existing voters.

- **New syncing node**: Do not import a peer's own Safety. After obtaining and verifying an authenticated cut, archive connection, and subsequent records, voting is permitted only once its own key/registration/synchronization conditions are met.
- **Existing voter cold recovery**: Retain the voter's latest persisted safety. Do not reset its LastVote/timeout when adopting a remote snapshot.
- **Long-lagging existing voter**: Provide a separate proposed `CatchUpFinalizedBase` entry point that authenticates consecutive evidence from the current finalized hash/root to the new cut and newer certified data. Commit a new local generation preserving required pins without replacing own safety. Missing data remains a waiting state; do not convert it into an economic VALID/INVALID judgment.

The snapshot root is authenticated by the fixed committee's finality proof and chain connection, not a computational Validity Proof. This storage update does not change that trust model.

## 4. Atomic rotation and crash boundaries

The fixed name `CURRENT` points to the sole canonical local generation and active WAL. `CURRENT`'s checksum detects local corruption and is not a new trust root. Recovery must not simply search for and adopt the file with the largest generation number.

1. In the serialized actor, fix the rotation target and latest own safety, and temporarily pause new signatures. Capacity calculations include the next WAL/snapshot, immutable archives, old generation, temporary files, and a reserve for safety updates.
2. Exclusive-create new archive chunks and old claim bundles, fsync files, and fsync the archive directory.
3. Exclusive-create the new snapshot and hot WAL, decode and authenticate them locally, fsync files, and fsync the new generation directory. Own safety must exactly match the latest values in the old active WAL.
4. Write `CURRENT.next`, fsync the file, atomically rename it to `CURRENT`, and fsync the parent directory. The new generation becomes canonical here.
5. Update the active generation in memory and complete necessary callback reconciliation before resuming signing.
6. Reclaim only old hot copies whose references have all moved to the canonical archive/new generation. Do not reclaim unpaid bundles, archives, or latest safety.

A crash before step 4 recovers the old CURRENT/latest old WAL; a crash after step 4 recovers the new CURRENT/new WAL. **If CURRENT points to the new generation but its WAL is corrupt, do not automatically fall back to the old generation's LastVote and sign**. Later votes issued in the new generation may be lost, so fail closed. An old backup does not authorize rollback.

For local finality notifications, the current `notifiedHeight` exists only in memory, so cold recovery reruns idempotent callbacks for the entire finalized history. In v4, either persist a local durable callback cursor or stream and renotify the entire history. If using a cursor, fsync it after checking callback success and the receiving subsystem's durable watermark; do not trust the cursor alone to skip work when the receiving pool/collector has been lost. Renotify through bounded archive iteration when the cursor is invalidated.

## 5. Implementation mapping

|Current function/area|Proposed required change|
|---|---|
|`Application.Open`|Check v4 binding/registry, read CURRENT, stream-authenticate archive/cut, replay hot parents, check own safety/collector, recover callbacks, then create the manager|
|`FinalizedHeight`, `FinalizedCheckpoint`, `FinalizedState`|Separate global height and hot offset. Use an archive reader for old heights. Do not restart the entire engine for old CP/bundle queries|
|`parent`, `executionParent`, `recordForQC`, `parentQC`|Typed hot/base/pinned references. Exact BaseRef/QCID matching. Missing old parents return ErrUnavailable. Do not expand the entire archive without bounds during lookup|
|`validateRecordState`, `buildAction`|Preserve absolute height and reexecute the correct parent. Do not mix storage generation into financial actions or clocks|
|`storeRecord`, `certify`|Reserve local capacity before each new record. Provide opportunities to archive-commit/rotate existing finalized data. Storage failure stops signing; it must not create a different economic root|
|`commitAncestors`|Stop ancestry traversal at BaseHeight and connect the hot finalized array to the cut hash. Process new finality from lower-view QCs under the existing rules|
|`PersistFHSVote/Timeout`, `AcceptTC`|Persist the latest exact own safety values in the new generation. Preserve collector-first fsync order. A generation switch does not create a new view/epoch|
|`recover`, `compactLayout`, dictionary|Remove full-history expansion. Restrict the dictionary to hot data and preserve expanded byte/state limits. Use an independent bounded archive reader|
|`extendsFinalized`, `SelectFHSProposalParent`|Authenticate that the selected parent extends the finalized tip without rolling back before the cut. A local index describing history alone is insufficient|
|`ExportSnapshot/ImportSnapshot`|Add a v4 envelope and authenticated cut. Explicitly reject old versions. Continue rejecting replacement of an existing voting WAL|
|`ProposalData/CertifiedData/ImportProposalData`|Bounded pagination. Keep historical authentication separate from active QC adoption without reinserting past finalized history into hot storage|
|`reconcileFinalizedExecution`|Global cursor. Process old callbacks from a bounded archive. Do not write directly to canonical CLX state|
|`finance.FinalizedSettlement`|Prefer the authenticated bundle archive generated before reclamation. Verify bindings every time; missing bundles return data_unavailable|
|`wal_orphans.cleanupTemporary`|Fix temporary file types/counts/bytes under CURRENT. Do not delete old generations or unknown names before authenticating the new canonical generation|
|service API/manifest/replication|Separate absolute sequence from local window. Do not enlarge the 128 KiB maximum TLS/control frame. Fetch larger snapshots/chunks through bounded read-only HTTP/pages, with total reassembly still within 2 MiB|

Do not change the 5/7 voting threshold, 2-chain finality, leader order, or view/signature domains in `reconfig/hotstuff`. Distinguish existing manager cache limits/view pruning from Application storage generations.

## 6. Responsibilities shared with the integration owner and additional caps

**Consensus/storage owner**: absolute height/offset, v4 WAL/CURRENT/archives, exact own safety, snapshot authentication and parent replay, durable bundle storage and read-only retrieval, bounded streaming, and crash/cap tests.

**Finance owner**: period aggregation of Fee arrays and the new state codec, snapshot state validator, and state equations covering unpaid rights/reservations/inbox and anchors. Preserve existing FIFO/cash/PnL/funding/dust/independent goldens.

**CLX settlement owner**: cumulative on-chain CP/anchor/inbox caps, retained roots/paid/nullifiers/reservations, updates through normal TX and gas/write limits, genesis/version/registry, and activation. Consensus storage callbacks do not change canonical CLX state.

**Relay/source owner**: authenticated segment archives for the source WAL, retention of unconsumed nonces/signed TX/jobs, old bundle retrieval, backpressure at limits, and reauthentication on restart. The relay does not import the engine.

The following entry points also need changes. Omitting them stops financial operation even if the v4 WAL works.

- `dex/relay/network.go` and `cmd/cypher/dex_relay.go` also check `MaxHeight<=128`. Inbox creation and DEX status matching in `planner.go` follow the same limit.
- Query heights and registration in `dex/service/finance/factory.go` are bound to the manifest MaxHeight.
- `dex/service/replication/controller.go` **limits every ReceiptHeights value to at most 128**, and Observe/Receive/addReceipt/remember ignore or reject duties outside that explicit set. Merely lengthening the list does not provide general continuous operation. Explicitly configure the period duty policy within the fixed epoch, preserving pre-signature deadlines and collector watermarks.
- Define reclamation rules for the collector's 2048 entries and replication `known`/`receipts` in terms of financial state closed periods and safety watermarks. Do not reintroduce local evidence availability into proposal validity.

## 7. Proposed tests across two or more generations

All tests are proposals and are NOT_RUN in this document. Start with units using small thresholds, then use a real network in the same generation with actual settings.

|Test|Required observations|
|---|---|
|unit two rotations|Reach 3 generations with fixture-only cut intervals 4/8. Do not lower global finalized/certified/sequence/view; maintain hot limits of 128 records/2 MiB|
|real-config two rotations|With proposed default cut interval 64 (half of hot cap 128), cross boundaries 64/128 and reach DEX finalized at least 129. Fix this setting during implementation; do not change thresholds only for the test|
|old and new claims|Pay an unpaid first-generation claim in the third generation through a normal CLX TX. Resubmit an already paid claim through another relay/after restart; native increase 0 and unchanged nullifier|
|exact replay|Resubmitting the same snapshot/chunk/job has no semantic effect. Reject different bytes with the same range/hash/sequence|
|same-view safety|Create conflicting pending proposals in the same view immediately before switching through the actual FHS path, then reject a conflicting vote after cold recovery. Do not use only a mirror test comparing state bytes|
|TC/outbox|Preserve an actual 5-party TC, an unfinalized timeout, and own leader QC outbox across the switch, and retransmit correct wire signatures|
|all selected crash boundaries|Before/after archive fsync, new WAL fsync, before/after CURRENT rename/dirsync, after new vote fsync, and before/after old hot reclamation. Recover the latest safety history and reject fallback signing from an old generation|
|DA corruption/missing|Reject missing chunks, bad QCs, forged roots/committees/parents, range gaps/overlaps, forged snapshot checksums, and altered claims; do not fill gaps with latest RPC data|
|bounded-memory recovery|Stream and reauthenticate a long archive. Measure with an intentionally small resident budget to show that the whole archive is not expanded, and enforce limits before decoding even maximum block/state/action sizes|
|archive/full/pin cap|Stop new intake at disk quota, temporary two-generation headroom, or pin limits. Verify retention of backing funds/rights/votes, and resume from the same DB after capacity recovers|
|late node|A registered new DEX node with a separate key authenticates the cut and deltas and votes only after synchronization. A separate DEX OFF Common retains engine 0 with CLX synchronization alone|
|60min LIVE|Continue normal signed deposits/trades/funding/rewards/checkpoints/claims, including 2 rotations, DEX/CLX/relay stop-and-resume, old claims, and late-node synchronization. Do not include terminal certified data among settled data|

Do not promote Go race, fault injection, or unit PASS results to LIVE results. A short test with a large height does not substitute for 60 minutes of operation. Preserve the original finite fixtures, or record why an old codec must be discontinued and mark them RETIRED; do not erase past FAIL results.

## 8. Decisions required before implementation

- v4 canonical field order, hash domains, CURRENT/segment/snapshot envelopes, and independent goldens.
- Initial total disk quota and free-space headroom for nondeleted old generation archives, cut interval, and pin limits. Raising limits is not evidence of continuity.
- Concrete reconciliation procedure for the callback cursor and collector/pool durable markers.
- Bounded historical verifier when the active parent references a safety pin before the cut, and a waiting API when capacity is insufficient.
- One-to-one mapping to the financial state/CLX storage versions fixed by the integration owner. Disclose that starting a new schema live may require an approved new network generation.

Until these points are made concrete through codecs/goldens and tests, this document is not evidence of completed implementation or removed storage caps.
