# DEX Finality Stall Observed on the Real PM2 Network

The target is `build/stage/live-finance-20260923-smoke` on 2026-09-23.
Chain ID is `10101919`, genesis is
`0xa4a61fa952509cde79c14e152702a1d7dea1cc0320b4552566b2efb9e4a575de`.
This investigation performed no init, WAL editing, QC injection, signature-threshold change, or chain-ID change.

## Real-Network Observations and Assessment

All seven Common nodes' real TLS DEX instances reported `Certified=15, Finalized=0`.
Each `ParentQCID` was traced backward from the WAL's `HighestQC` using canonical semantic QC IDs;
all seven participants retained the same chain below.
Even with different-view QCs at the same height, actual parents were followed rather than simply ordering maximum views.

|DEX height|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|QC view|56|58|118|121|123|126|129|132|135|137|139|141|143|145|148|

Real-network financial finalization/settlement is **FAIL (liveness)**.
Certified is not finalized, and the engine's inbox-import execution counter is not a count of finalized credits.
Inclusion of a deposit in normal CLX does not establish usability on DEX, CLX checkpoint settlement, or withdrawal.

Raw data is in `/tmp/common-dex-live-test.x5z_05oq/public/finality-wal-chain.json`.
It records each read WAL's SHA-256, record count, timeout watermark,
and the selected chain's heights/views/hashes/parent QC IDs.
The audit program is `finality-audit.go` in the same artifact area.
It outputs neither private keys nor financial-state contents.

## Two Causes

1. No consecutive-view finality edge ever formed.
   `dex/consensus/app.go:commitAncestors` and `dex/checkpoint/proof.go:Epoch.Verify`
   enforce the existing FHS rule that the final parent/child are consecutive in both height and view.
   Manifest timeout was 4,000 ms. The test runner waited at least five seconds after authenticating/confirming
   each action, plus time to fetch/verify reference proofs.
   View timeout in `dex/service/service.go` advances even with empty ingress,
   so views have skipped when the next authenticated action arrives.
   This is an operating-pattern problem that fails to create descendants satisfying finality,
   not a shortage of QC signatures.
2. Once consecutive unfinalized heights exceed the existing proof limit, faster input alone cannot recover.
   `MaxDescendants=8`, `MaxProofBytes=16384` remain unchanged.
   `commitAncestors` first creates/verifies proofs for every old unfinalized ancestor from the latest
   consecutive-view edge, then adds them to `Finalized`.
   Heights 1–15 are already unfinalized; even a new consecutive edge leaves the oldest ancestor's path
   longer than eight, so it is rejected.
   Finalizing only a subset, erasing old votes, lowering HighestQC, or treating a single QC as finalized does not solve this.

## Deterministic Reproduction Test

`TestLiveFinalityBacklogBeyondProofBoundFailsClosed` in `dex/consensus/live_finality_backlog_test.go`
is a component test using seven real FHS managers, normal BLS signatures, and five-member timeout certificates.
It causes empty-view timeouts between actions and accumulates nine unfinalized heights.
The normal manager then creates a valid child QC at height 10/view 18.
It checks that the existing cap rejects an ancestor proof requiring nine descendants without publishing finality,
and that restarting the same WAL preserves certified state and vote/lock/QC/timeout state.

PASS for this test means **PASS(UNIT): reproduces the known failure and verifies fail-closed behavior**;
it is not a PASS for repairing LIVE liveness or financial settlement.
Initial test-harness failures are also preserved in `finality-backlog-regression*.log`
and distinguished from the real-network failure.

Execution results follow. None changed current production source.

|Test|Assessment|Raw log|
|---|---|---|
|New backlog reproduction/same-WAL restore, 10.48 seconds|PASS(UNIT), liveness failure remains|`/tmp/common-dex-live-test.x5z_05oq/public/finality-backlog-regression-r4.log`|
|Above plus existing `TestFiniteWorkloadNeedsChildAfterSkippedLeaderViews` with race detection, 22.678 seconds|PASS(UNIT)|`/tmp/common-dex-live-test.x5z_05oq/public/finality-backlog-race.log`|

Go race covers only these execution paths; it does not prove C BLS safety, full financial correctness, or LIVE recovery.
Corresponding file SHA-256 hashes are in `finality-audit-source.sha256` in the same artifact area.

## Unimplemented Repair Proposal and Required Verification

Future input must provide finalizing descendants promptly through valid signed actions/Noops
and suppress new financial input before the unfinalized chain reaches proof limits.
Extending timeout alone permits recurrence after long shutdowns or low load.
Noops also follow existing Oracle/Funding/participation-evidence/nonce rules.
Do not manufacture finality through unauthorized financial actions or background updates to CLX canonical state.

Settling the current 15-height history on the same DB requires specification and implementation
of authentication beyond the existing single proof.
The proposal under consideration is a **segmented shared finality anchor**.
It is unimplemented and not enabled in the current handler.

1. Verify a valid target/child QC pair under existing FHS rules, authenticating a finalized tip
   containing chain/domain/epoch, checkpoint hash, and height.
2. From the authenticated tip, verify the `Checkpoint.Previous` hash chain backward in ranges
   of at most eight per submission and within current byte/work limits.
   Do not use RPC latest or local cache as an authentication root.
3. Persist this authentication state on CLX through normal signed TXs.
   Later financial-checkpoint acceptance retains existing sequence, pre/post root, inbox,
   bucket, reserve, and nullifier rules, using only reconciled finality references.
4. Adapt DEX shared evidence, ancestor references, WAL, snapshot, repair, and APIs as well.
   Test crashes/restarts preserving signing safety state and unpaid rights, different branches,
   altered roots, false metadata, missing segments, and duplicate submissions.

Specify new version/domain/gas/storage limits/acceptance conditions first.
A repair that merely raises `MaxDescendants` is not adopted.
The financial engine need not return to the CLX committee or DEX OFF Common nodes.
Do not deploy this specification extension without review or deem it safe based only on this reproduction test.

General delivery of reward evidence, fairness, and complete FROZEN recovery are not resolved by this investigation.
A QC is a finality proof based on committee trust, not a computational Validity Proof.

## Reference to the 2026-09-23 Fix

The above records the old schema 5 LIVE failure. Bounded ancestry proofs and idle-timer fixes for new schema 6 were implemented and documented in the [init preparation and final test record](finality-fix-status.md). The old LIVE FAIL remains unchanged; new-generation LIVE testing follows user-executed init.
