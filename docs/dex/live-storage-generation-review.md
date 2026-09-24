# Independent source review of Q3 storage generations

2026-09-23. Scope: current uncommitted changes. The initial cap audit remains a historical record in
[live-storage-cap-audit.md](live-storage-cap-audit.md).
This is an independent source review, not a PASS for storage switching or financial operation on the PM2 network.
Production source, live DBs, PM2, and keys were not changed during this review.

## Authentication and persistence order

`recoverArchive` in `dex/consensus/generation.go` reads the persisted prefix in order from genesis,
verifies each record's QC and checkpoint descendant finality, and reexecutes its action against the
immediately preceding authenticated parent. Financial execution schema 5 also requires state-invariant
and root checks through `ValidateSnapshot`. The archive digest is a file-integrity index after this cold
verification; a checksum alone does not create a new trust root. Reading old records during operation
also checks finality proofs and the digest established during cold verification.

Switch order: write old finalized records to archive and fsync files/directories; write/fsync the new hot
WAL; atomically rename `CURRENT` and fsync its directory; delete the old hot WAL.
Uncertain persistence failures in `persist`, other than capacity errors, are fatal and stop signing.
If CURRENT is missing but generation files/history remain, do not revert to a fresh voter.
Unpublished archive tails from failed switches count toward capacity; only identical authenticated
content may be reused.

`LastVote`, `HighestQC`, outbox, selected QC, and the parent of an in-progress build are pinned in hot
storage. An old own vote on an unfinalized branch retains its noncanonical parent chain, referencing
only canonical parents from authenticated archives. This review found no additional authentication or
voting-safety defect in this consensus path. That does not guarantee safety of unexecuted paths.

## Rights, costs, and effective limits

|Scope|Retention and limits|Limitation|
|---|---|---|
|FHS hot|128 records, WAL 2 MiB, normally switches every 64 finalized records|Stops intake without raising limits even if too many pins prevent reclamation|
|FHS archive|Retains complete records/state/actions/finality. Default 256 MiB, configurable 8 MiB–1 GiB, absolute height 4096|Does not delete old claim evidence to make room. Not perpetual operation|
|Cold recovery|Streams and reexecutes the entire authenticated prefix|Total work grows with history even with bounded hot memory. Independent v4 financial snapshot bootstrap is currently rejected|
|Financial fees|Retains at most 16 unclosed nonzero-fee periods. Closed periods are sequentially bound to cumulative amount/root|Rejects new nonzero-fee periods at the limit. Zero-fee operations and valid closes may continue without erasing retention obligations|
|Collector|2048 hot records/2 MiB, retired archive 1024 periods/128 MiB|Storage reclamation based on finalized close evidence; not a rule authorizing hidden evidence or extra rewards|

The current financial block's claim array is not the sole authoritative record of historical rights.
Old finalized checkpoints/states/proofs remain in FHS and relay bundle archives; CLX reservations,
cumulative paid amounts, and nullifiers persist separately as ordinary consensus state.
This review alone does not establish LIVE PASS for old-claim payment or replay without extra payment.

Append/close in `fee_history.go` acts on a local copy decoded by execution. It rejects closes that skip
periods and matches unclosed totals against market `PeriodFees`. FIFO, cash/PnL, and funding/dust
arithmetic were not changed for storage reclamation.

## Recovery defect found: collector and FHS WALs

At review time, `collector.go` updated `RecoveryVote` to the collector's own immediately preceding
`LastVote` in `BeforeVote`. That single pin is insufficient for repeated crashes as follows.

1. The durably committed own vote in the FHS WAL is A. The collector fsyncs B, then stops before FHS persists B.
2. Recovery restores A and passes collector checks. A's reward period may already be retired.
3. When collector fsync for C advances RecoveryVote to B, retired A's target is removed from hot storage.
4. Another stop before FHS persists C leaves no target needed to check valid FHS A, so same-DB recovery is rejected.

This does not weaken signature thresholds or voting checks; it loses recoverability after repeated stops.
The issue was reported to the integration and finance owners, requesting **a fix separating the watermark
confirmed durable in FHS from the collector's leading LastVote, plus a two-consecutive-crash regression**.
Do not weaken `CheckFHSWatermark` checks. In the fix, `CheckFHSWatermark` retains A from the actual
FHS WAL as a runtime pin, and the first `BeforeVote` after restart carries A into durable RecoveryVote.
It uses the existing ordering in which the next callback in the same process is reached only after the
previous FHS persistence succeeds (FHS persistence failure is fatal). Retention of B at C after a
successful exact retry of B was also checked.
`TestCollectorRetiredPinSurvivesRepeatedCollectorAheadCrashes` and
`TestCollectorExactRetryAdvancesRecoveredFHSPin` were added, and the fix was independently checked
without weakening verification. Preserve pre-fix FAIL. Map final-source race/full-regression results to
the execution record; do not transfer them to LIVE repeated-crash results.

## Additional check: unpublished archive tails and valid QC evidence differences

After archive fsync but before hot WAL/CURRENT updates, a stop may allow recovery to receive a QC
for the same proposal from a different valid signer subset. Requiring exact equality to old bytes alone
could cause a safe halt from an immutable conflict even for the same finalized checkpoint.
The added `reuseOrWriteArchive` independently verifies old/new QCs/finality and adopts existing
bytes/digest only when domain, height, Previous, checkpoint, ref, action/state, Finalized.Key/Hash, and
QC semantics agree. This minimal fix was independently checked. Low-level `writeArchive` still does
not overwrite existing files with different bytes.

Relay bundle archives do not combine CURRENT with an unpublished tail. Cold open reauthenticates
and indexes the entire published consecutive file sequence, then resumes retrieval at the next sequence.
Separate relays may store different valid proofs, with business IDs bound to checkpoint hash/claim leaf.
No equivalent reconstruction issue was found in the ordinary path, so no unconditional relaxation of
private-archive duplicate byte comparisons was made.

## Additional check: collector tails and delayed evidence delivery

If a stop occurs after collector archive publication but before persisting the active-frontier WAL,
restoring the old WAL and receiving a valid delayed certificate for the same period before the next
retention Tick can make the original archive set differ from the reconstructed hot set, causing an
immutable-conflict halt. The pre-fix FAIL was reproduced with
`TestCollectorOrphanRetirementCompletesBeforeLateCertificateAdmission`.
The fix authenticates the next single fully published tail and completes retirement matching the
original hot set before exposing `OpenCollector` externally. It does not accept new evidence and then
discard it to force consistency. If the canonical collector WAL is missing, the archive cannot replace
fresh signing state. Checks also bind unpublished-tail filenames to periods, avoiding mistaking a copy
of an old period archive for the next period. This too requires mapping to final regression logs and
is not a LIVE crash result.

## Test and review boundaries

Existing `TestGenerationRealFHS128BoundaryRestartAndOldState` covers 2 rotations at the actual 64
threshold and cold restart of 7 actors; `TestGenerationCutFailurePublicationAndRestart` covers selected
archive/hot/CURRENT boundaries; `TestGenerationOwnOrphanVoteRetainsNoncanonicalParent` covers
retention of the own-vote branch. Financial fee history has an independent 320-step golden and tests for
retention at capacity and tamper rejection. Map these executions to the final source/race records.
Do not reinterpret in-process actors, component fault injection, or Go race as guarantees for LIVE PM2,
disk failure, physical power loss, or all C BLS behavior.
