# Q3 DEX Storage Generations — Implementation and Test Scope

The target is uncommitted changes in `dex/consensus`. This work did not change existing PM2,
CLX DBs, or ordinary cypher deployment. It does not establish PASS for storage transitions on the running network.

## Implementation

`Config.StorageGenerations=true` selects local WAL v4 and moves an authenticated prefix to
immutable archives at the normal interval of 64 finalized heights. Absolute heights and hot-array offsets are separate;
the 128 hot-record limit remains. The absolute operating budget is finite, at most 4096;
this means neither indefinite operation nor unlimited storage. Existing short-fixture defaults remain unchanged.

Each archive file holds 1 finalized record/action/full state/QC/descendant proof,
at most 2 MiB each. Old `FinalizedState` / `FinalizedCheckpoint` remain retrievable after archival.
Funds, nullifiers, and unpaid reserves are not deleted. CLX-side settlement accounting is unchanged.

Cold open deterministically re-executes archives one at a time from configured genesis, checking QCs,
finality proofs, and parent/state/checkpoint continuity. It then restores hot state and own LastVote,
HighestQC, timeouts, and outbox. Local checksums are not authentication roots.
Financial schema 5 also invokes the financial implementation's `ValidateSnapshot`.
If an old unfinalized own vote belongs to a noncanonical branch, pin that vote and the
noncanonical parent QCs/records required for re-execution in hot storage. Stop admission if pins cannot fit within 128.

Instead of restoring every record into memory, restore only authenticated digests into a fixed array of 4,097 elements.
Historical-height retrieval is bounded to one file read and digest/QC/finality verification.
Cold revalidation of the entire history costs work proportional to stored height.

Transition ordering is archive fsync, next-hot-WAL fsync, CURRENT atomic rename, then directory fsync.
Reject a CURRENT with missing hot data, or leftover old-generation artifacts without CURRENT.
Do not fall back to old own-vote state and sign. Reclaim older hot copies
only after authenticating archives and the new canonical generation.
Reuse archives left by a pre-transition crash after checking old/new QCs/finality proofs and the same execution prefix.
Do not overwrite saved bytes when peers have different valid signer sets for the same QC.
Reject differences in state, parent-archive digest, or checkpoint.

Default archive budget 256 MiB, allowed range 8 MiB–1 GiB, with 4 MiB reserved working space.
Quota tracks file-content bytes and a finite entry count; OS metadata/free-disk monitoring is separately required.
At capacity, `StorageStatus.Blocked` / `ErrStorageCapacity` suppress new proposals
while preserving existing state, reserves, and signing safety. `MaintainStorage` reevaluates after capacity is restored.
Pruning that deletes stored unpaid rights is not implemented.

## Executed Tests

Raw logs: `/tmp/common-dex-live.8gezz_j9/public/`. This document is not a substitute for logs.

|Test|Result and scope limits|Raw log|
|---|---|---|
|`TestGenerationRealFHS128BoundaryRestartAndOldState`|PASS(UNIT). Seven actual FHS managers in one process, 130 certified/129 finalized, 2 transitions at 64 and 128, cold recovery of all 7, old states/CPs, same-view double-vote rejection, timeout retention.|`q3-consensus-generation-attempt2.jsonl`|
|`TestGenerationCutFailurePublicationAndRestart`|PASS(UNIT). Recovery from injected persistence errors at 3 archive/hot/CURRENT-durable boundaries. Subsequent QCs reauthenticated through ordinary CertifiedData/ImportProposalData.|Same as above|
|Missing/corrupt data, altered state with recomputed checksum, missing hot data referenced by CURRENT|PASS(UNIT). Rejected without skipping authentication.|Same as above|
|Independent CURRENT golden, immutable duplicate writes, quota|PASS(UNIT)|Same as above|
|`TestGenerationCapacityBackpressureKeepsStateAndResumes`|PASS(UNIT). Separate test with small threshold 2. Admission suppression, state/safety retention, capacity recovery, transition, and cold recovery.|`q3-consensus-capacity.log`|
|Existing WAL/compact/counter/generic/snapshot regressions|PASS(UNIT). Checked normal fixture defaults.|`q3-consensus-existing-regression.jsonl`|
|`TestGenerationOwnOrphanVoteRetainsNoncanonicalParent`|PASS(UNIT). Retained a noncanonical parent of an old own vote after 2 small-threshold transitions and cold recovery.|`q3-consensus-pin-closure-attempt1.jsonl`|
|`TestLatestCertifiedDataSelectsHighestViewWithinBound`|PASS(UNIT/race). Highest view among 10 candidates, out-of-range rejection, conflict rejection at the highest view, no map-order dependence from lower-view conflicts.|`q3-certified-query-final-race.jsonl`|
|`TestGenerationTailRecoveryAcceptsAlternateAuthenticatedQC`|PASS(UNIT/race). Cold recovery after archive durability, reuse of the same immutable tail with a valid descendant proof from another signer set, rejection of state/Previous/proof modifications.|`q3-consensus-tail-subset-race.jsonl`|
|Consensus package race (before pin/API additions)|PASS(UNIT/race),49 top-level, 702.516 seconds. Does not establish PASS for later changes.|`q3-consensus-final-race.jsonl`, `q3-consensus-race-source.json`|
|Consensus package race (before tail-reuse fix)|PASS(UNIT/race),51 top-level, 732.353 seconds. Does not establish PASS for final source.|`q3-consensus-final-race-v2.jsonl`, `q3-consensus-final-source-v2.json`|
|Consensus package race on final source|PASS(UNIT/race),718.078 seconds, exit 0. Full consensus regression including the tail-reuse fix and final read-only API. Source hashes matched afterward.|`q3-consensus-final-race-v4.jsonl`, `q3-consensus-final-source-v4.json`, `q3-consensus-final-result.json`|

Final consensus source inventory: `q3-consensus-final-source-v4.json`; manifest hash:
`d88cfb6359ec2aca7ba79f974df2395789f17df084ca4be25db809e6e962c993`.
Changes after v2 cover read-only queries, reauthentication of alternate signer sets for the same semantic QC
to reuse an immutable archive tail, related tests, and codec documentation.
Public APIs do not label certified as finalized or substitute for required finality evidence beyond a QC.

The initial `q3-consensus-generation-attempt1.log` remains FAIL.
A node recovered at archive/hot durability received a view beyond a QC it had not fetched,
causing the test to fail with `invalid leader view`. Ordinary authenticated proposal repair was added to the test;
head and signing thresholds stayed unchanged, and the rerun passed.

## Incomplete and Unexecuted Work

- Old single-file snapshots are not reused in generation mode. Formal bootstrap transport to provide
  generation snapshots + archives to a new late DEX participant is unimplemented; the API explicitly rejects it.
  Bounded `CertifiedData` can retrieve ordinary proposal-repair data from archives too.
  Existing TLS replication can reauthenticate/re-execute these records one at a time, but
  this work has no passing 130-height run with a new late DEX participant. Future tests may
  start late only a member registered from the beginning with its own unique key that had not previously started.
  This does not authorize deleting an already-voting DB, copying active keys, or self-authenticating unknown new keys.
  It is separate from the required LIVE CLX synchronization of a later DEX-OFF Common.
- Old state/proof retention was verified, but the 7-manager test uses a nonfinancial reference executor.
  Actual native-financial claim payments and duplicate-claim rejection across generations need separate financial integration tests.
- Actual-process SIGKILL, disk failure, and power loss during v4 transitions differ from these injected-error tests.
  They are not claimed as executed. Existing SIGKILL regressions for other WALs also retain their separate scope.
- Two transitions with actual settings on the designated PM2 network, 60 minutes of continuous finance, and later Common synchronization are NOT_RUN.
- Finite archive quotas or absolute budgets cause a safe stop.
  This implementation does not solve indefinite full-history retention costs or indefinite operation.

Specification: [storage-generation-v4-codec.md](storage-generation-v4-codec.md).
Design background: [live-storage-generation-v4-design.md](live-storage-generation-v4-design.md).
