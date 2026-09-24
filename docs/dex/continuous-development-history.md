# Continuous Operation Development History

This record preserves the progress before the final assessment on 2026-09-23. “In progress” and “unverified” below describe the state at each attempt; see the [continuous operation results](continuous-status.md) and [26-item matrix](continuous-acceptance-matrix.md) for the current assessment. Later PASS results do not overwrite failure logs.

# Common DEX Continuous Operation Development Record

The target is `FHS-D-ExchangeCore`, with starting HEAD
`70862a71dfaf2b00694dc1354c6a64e9504d7db5`. This record is in progress;
the G3 long-duration test and acceptance assessment of the final diff are not yet complete.
PASS results from earlier records are not copied into the new 26 items.

## Preservation and Work Boundaries

The 377 changed/new files at the start were checked against the previous final manifest
and preserved separately in `/tmp/common-dex-continuous.uye5vgqi/baseline`.
The initial classification was 37 CLX production, 43 DEX production, 95 test,
43 documentation, and 159 result files; this does not mean all 377 were production changes.
The previous review archive also exists, with SHA-256
`f6253d4d51b968cef56e78c389c6f6354a94473f41273e59cfc2444e66804367`.
Starting materials are saved in [continuous-start](results/continuous-start/environment.json)
and the [classification](results/continuous-start/classification.json).

Go1.27.1/linux-amd64, readonly modules, dedicated Go cache, GOMAXPROCS=2.
Only new genesis files, keys, datadirs, loopback-only user/network namespaces,
and process handles started by the test operator are used. There is no host fallback if isolation fails.
No writes are made to the operational checkout, genesis, keystore, WAL, chaindata, or distributed binaries;
no signals are sent to operational processes, and no commits, remote pushes, or real-fund operations are performed.
Normal data updates by operational nodes themselves must not be confused with whole-file immutability.

The 2026-09-23 recheck found that 68 of 70 protected files matched their G0 hashes;
`build/bin/cypher` and `build/bin/cypher-linux-amd64` did not match.
Both currently have hash `bcfb21b13a82eb0a9ffdfec843a5d7c3dededf735607da680b8dfa43db2759f8`
and mtime 2026-09-22 15: 22: 40 (Europe/Berlin). The source of the changes is under investigation;
“all protected targets unchanged” is not the assessment. The current files are protected without unilateral restoration or rebuild.
The isolated runner writes to a dedicated `/tmp` location.
The [comparison results](results/continuous-resume-protected-observation.json) were saved separately.

Against the normal 32 GiB DAG, initial MemAvailable was 21,282,628 KiB, memlock was 8 MiB,
and swap was 0. Normal-size PoW search, proof delivery, and combined performance are NOT_RUN.
PASS results for small PoW fixtures and start/stop lifecycles do not replace them.

## Implemented Boundaries

G0 reproduced reward-close decisions for the same parent/proposal differing according to
the evidence held by a local collector. This was changed to commit evidence into shared state
through a CDXP action before the deadline. Reward close refers to the committed participant set;
the presence of local mempool/WAL data is not used to declare a proposal invalid.
This does not mean general evidence inclusion or delivery guarantees are complete.
See the [reward audit](continuous-g0-rewards.md) and [CLX boundary audit](continuous-g0-clx.md).

DEXDevnet version3 in the new isolated genesis uses checkpoint schema 4 and financial state 5.
The meanings of old version2/schema 3 and the 225→214 fixture are protected.
The fixed checkpoint portion remains 525 bytes; CLX anchor v1 is 246 bytes, and v2,
which authenticates normal keyblock renewals, is 286 bytes. Old codec meanings are retained.
Only reordering under existing CLX rules for the same seven registered participants is authenticated;
unknown committees and public epoch transitions are not accepted. The source epoch remains fixed at 1.
See the [authenticated anchor specification](rolling-anchor-spec.md), [normal keyblock renewals](fixed-key-renewal-spec.md),
and [MPT verification for native storage and relay](key-renewal-native-relay.md).

* On DEX, consecutive CLX headers from the current anchor in consensus state are checked for QC,
  descendant finality, and MPT validity; CDXA atomically updates anchor/cursor/credit.
* On CLX, NativeAnchorUpdate in normal signed TXs stores short ranges.
  Old ranges are staged, and checkpoint funding reservations are not allowed until their connection
  to a canonical ancestor within the existing 64-block window is verified. References to verified old anchors
  do not receive a renewed 64-block age restriction; continuity with the same chain as the history determines acceptance.
* Unpaid claims, nullifiers, and funding reservations for old checkpoints are not deleted by anchor updates.
  Limits such as 1024 anchor-history entries stop new acceptance. Neither capacity recovery through erasing rights
  nor unlimited history retention is implemented.

The limits remain 64 ancestors/update, 8 descendants/header, 7 signers, 64 KiB native calldata,
65 MPT nodes/path, 1024 bytes/node, and 128 entries/range.
Even with at most 64 headers, a range that hits the byte limit must be reduced or stopped as unavailable.
Total work for long-term following grows with the number of updates.

Normal entry points are the existing `--dex.validator` / `--dex.config` and the new
`cypher dex-relay --relay.config /absolute/config.json`.
The relay uses purpose-specific gas keys and does not require reward-recipient or voter private keys.
It persists submission intent, business ID, nonce, signed raw TX, ACK, and authenticated completion,
then reconciles them through FHS/MPT/bundles after restart.
`--relay.once` and finite `--relay.duration` specify administrative execution bounds.
See the [relay specification](relay-core-spec.md), [CLI specification](relay-cli-spec.md),
[network specification](relay-network-spec.md), and [planner audit](relay-planner-review.md).

Read-only `eth_getCLXFinalityWitness` and `eth_getDEXInboxEntries` are entry points for fetching
unauthenticated evidence with explicit block selection; RPC responses themselves are not trusted.
The latest height is used only as a discovery hint. DEX callbacks and background workers
do not modify the CLX canonical StateDB.

CLX settlement/relay production dependencies do not include the DEX engine/devnet/runtime.
DEX OFF Common nodes validate the same settlement transactions under normal CLX rules.
A source QC is not a computational Validity Proof, and a DA root does not guarantee successful retrieval.

## Tests and Unfinished Work

G0, rolling components in both directions, selected persistent-relay crash boundaries, real TLS/HTTP,
and a short normal-CLI relay end-to-end test were executed. Detailed raw logs and conditions are in the specifications and audit documents.
The short G2 relay run uses a separate 225→215 ledger, which is not mixed with either the old
reward-inclusive 225→214 ledger or the new long-duration ledger.

The long-duration test follows the [predefined scenario](continuous-g3-scenario.md).
Attempt 1 failed on a test-side cycle while waiting for certified-deposit finality; attempt 2 failed on
collector selection that mixed evidence from different views at the same height; attempt 3 failed because
deposit catch-up did not finish in seven slots provided after a 65-height shutdown.
Attempt 3 stopped DEX from CLX166→231 and restored the same WAL, but at
DEX certified 47/finalized 45 and CLX anchor172/cursor 6 it had not reached the expected cursor 8.
It also identified a boundary where real CLX fixed-committee keyblock renewals at ten-minute intervals stopped source authentication.
Attempt 4 reached CLX158/checkpoint 38 and then failed because a pre-shutdown inspection helper
checked the new WAL v2 using only the old checksum. The helper was changed to check each version,
and regressions for old v1, unknown versions, and altered checksums were added.
Attempt 5 reached CLX275, DEX finalized 59, and CLX accepted 49,
authenticating deposit catch-up after a DEX shutdown exceeding 65 heights and a real keyblock renewal.
It then failed when the old 12-minute alarm terminated the CLX test subprocess.
Only the test helper was changed to derive the child's lifetime from the parent's finite 45-minute allowance;
FHS timers, verification limits, and the financial schedule were retained.
Attempt 6 was interrupted during execution on 2026-09-22, leaving logs ending at CLX46;
it was preserved as NOT_RUN (interrupted), not as a completed test.
Attempt 7 on 2026-09-23 treated a transient HTTP503 during close 18 processing as an immediate FAIL.
The service's two-second limit was retained; only test-side state observation was changed to retry
within the existing 75-second deadline. Invalid JSON, explicit errors, and expired deadlines are not successes.
Attempt 8 failed after 726.17 seconds. DEX was stopped for 66 heights from CLX168→234;
after restart from the same WAL, the source authenticated a normal keyblock renewal.
Relay inbox observation then omitted the target anchor v2 key context and quarantined valid
229→245 evidence before submission. It stopped at DEX finalized 51/certified 52 and CLX accepted 40,
without reaching final settlement at 295.
Following the [reproduction and fix boundaries](relay-renewal-observation-fix.md), a fix restored
the target key context from verified source history. The dedicated race test passed.
The old failed journal's quarantine is preserved without silently clearing it.
The post-fix long-duration end-to-end run is still incomplete.
Attempt 9 failed after 952.43 seconds. After a 66-height shutdown from CLX160→226, DEX authenticated
anchor82→242 in multiple steps and caught up to cursor 8. A new deposit after CLX257 also finalized,
but the fixed six-minute test deadline for checkpoint 58 expired at accepted 54/CLX314/DEX finalized 59.
Normal CLX proposals progressed even immediately before the deadline and quarantine was 0,
so this is not classified as a permanent halt. The latest source was v2, but deposit CDXA61 targeted v1 at 262.
An interim report inferring this deposit's version from the latest source version was corrected;
this is not a real-network PASS for a v2 deposit.
A limited change to [relay selection](relay-payer-scheduling.md) made unsigned jobs sharing a payer
with an unresolved nonce wait first. Authentication, gas, and nonce rules for processed jobs remain unchanged.
The next run will follow the [progress observation specification](continuous-progress-observation.md),
checking canonical acceptance/payment progress, the no-progress deadline, and the existing 45-minute
absolute limit separately. Each attempt's failures and unreached scope are retained, not overwritten by later results.

Attempt 10 failed after 716.63 seconds. A normal CLX key renewal was authenticated up to
source height 264/version2 after waiting 5 minutes 47.68 seconds and making three normal transfers.
Subsequent new deposits finalized at 266/268, but catch-up from the pre-shutdown DEX anchor87
reached only 119→151→183→215→231→247 within 13 test slots.
DEX certified 53/finalized 51 and cursor 6 did not meet the expected cursor 8;
subsequent market operations were not executed. Quarantine was 0 and runtime source diffs were also 0.
This is preserved as failure to catch up within the finite input allowance, including ranges where
the 64 KiB evidence limit reduced one update from 32 to 16 ancestors.
Successful key-renewal authentication is not treated as successful DEX credit for the new deposits.

Attempt 11 failed after 1311.84 seconds. The third deposit was placed before the normal-key-renewal wait,
retaining the same financial formulas, golden data, and deadlines. CLX was at 160 before shutdown,
the 65-height observation point was 225, and source 254 was authenticated before DEX restart,
so the complete DEX shutdown lasted at least 94 heights.
DEX caught up in multiple steps to anchor241/cursor 8; the final new deposits at 282/285
were also authenticated at DEX anchor289/version2/cursor 10.
During the complete CLX shutdown, 16 unsettled items were retained at DEX78 versus CLX accepted 62;
after resuming from the same CLX DB, checkpoint 78 was accepted at CLX419.

At the final relay cold restart, checkpoints through 109 had been accepted, but reauthentication of
historical completion records deferred unresolved nonce processing. Claims stopped progressing at 62/72 for 120 seconds.
Paid amounts were three withdrawals totaling 30 CLX and 59 rewards totaling 8.714285714285714286 CLX.
Custody was 306.285714285714285714 CLX, short of the target of 295.
Unpaid amounts were one withdrawal of 10 CLX and nine rewards totaling 1.285714285714285714 CLX.
Final ledger reconciliation and later-starting DEX OFF synchronization were not run.
The [raw log](results/continuous-g3-normal-11.log) and
[conditions and reauthentication observation history](results/continuous-g3-normal-11-metadata.json) were saved.
The [selection rules](relay-cold-scheduling.md) were changed to alternate unfinished work with
reauthentication of completed history within each lane, without skipping authentication.
In a 204-item reproduction, unresolved nonce observation moved from calls 203/204 to calls 2/3,
and an already-waiting claim was processed on call 20.
Relay race tests and focused real BLS/MPT/HTTP tests passed, but improved processing order
is not treated as completion of the normal financial network.

For attempt 12, the [observation specification](continuous-progress-observation.md) separated relay-history
reauthentication into a phase after all 72 confirmed payments and full accounting reconciliation.
The financial phase's 120-second no-progress condition and overall 45-minute deadline remain.
Reauthentication progress does not extend a financial phase with unpaid amounts.

Attempt 12 failed 25.43 seconds after startup because TxQUIC UDP ports overlapped inside the isolated namespace.
This was before deposits or relay startup, so the financial phase is NOT_RUN.
The path binding `base+2000` after acquiring the base UDP port was confirmed,
but cleanup had already occurred and the competing process could not be identified.
Attempt 13 started successfully with the same source and a new namespace, keys, and datadirs.

Attempt 13 failed after 1077.63 seconds. The complete DEX shutdown lasted at least 83 heights,
from CLX164 to authenticated source 247; it resumed from the same WAL and caught up to anchor262/cursor 8.
The final deposits at 276/279 were also authenticated at anchor308/version2/cursor 10.
The 18 unsettled items at DEX78 versus CLX60 during complete CLX shutdown were retained;
after restart from the same DB, checkpoint 78 was accepted at CLX444.
Saving DEX105 then reached the existing 2 MiB WAL byte limit and signing stopped.
The final reward period, 72 payments, cold audit, and DEX OFF synchronization were not run.
The last full accounting observation, at CLX446, showed custody330 and 34 claims,
but CLX continued afterward, so these are not treated as final balances.
The [raw log](results/continuous-g3-normal-13.log) and
[reached scope and WAL sizes](results/continuous-g3-normal-13-metadata.json) were saved.
On the node with 112 records, the saved WAL was 2,080,398 bytes; the 128-record limit had not been reached.
The format was changed to [local WAL v3](wal-action-dictionary-spec.md), which dictionary-encodes only identical actions.
All records, state omission rules, QCs, finality, safety state, and outbox entries are retained;
after expansion, existing v2 replay and authentication are applied.
Snapshot v2 and existing limits remain, with an additional 2 MiB limit on the sum of actions after all references expand.
Go output for the seven public WALs matched independent Python structural calculations,
but structural comparison alone is not treated as authentication of financial state.
The [focused results](results/continuous-wal-dictionary/metadata.json) report WAL race 21 top-level/86 PASS events
and financial regression 6 top-level/41 PASS events.
Attempt 14's normal-CLI long-duration test began on final candidate source
`a64dc7053ad435113f488cb0f457683cd0d9cf69e05dbea6593bf7d840ae4e16`.
Completion assessment awaits that end-to-end result and final regressions.

With the old eight-period independent golden data and ledger 297 protected, the
[ten-period fixture specification](continuous-extended10-fixture.md) and
[independent golden data](../../dex/testdata/continuous-extended10.json), adding 20 financial blocks solely for catch-up,
were fixed in advance. The new ledger is 345−40−10=295 with 72 claims;
achievement on the real network remains unverified.
The next test uses a [separate fixture changing only the final deposit timing](continuous-early-final-deposit-spec.md).
The old model and golden data are retained, and the same final ledger and differences at all 111 height boundaries
were independently reconciled. This is a test-input change separate from the relay fix for attempt 8.
[WAL/snapshot v2](compact-replay-spec.md) omits only duplicate copies of historically finalized state;
all actions/QCs/finality/safety data remain for replay. The 2 MiB/128 limits are not increased,
and the total restored state is also limited to 2 MiB.
The old snapshot-corruption test, which did not handle state omission in WAL v2, was also corrected;
rejection of root alteration on the omitted-state side was added.
The test's initial panic remains in the historical log, and final unit/race tests were rerun.

At the freeze before the HTTP503 observation-helper fix, the source manifest SHA-256 was
`061f4a0b6bed257c6ba8ad60f377f52cf8640cb6dcb8d4dcbd01a1575cfe1630`.
This manifest hashes the Go/source/scripts list, not report documents added later.
The freeze's [unit/race run](results/continuous-final-unit.jsonl) covered 19 packages, 270 top-level tests,
783 PASS events, 22 SKIP, 0 FAIL, and 0 runtime source diffs.
SKIPs include network opt-ins and are distinguished from separately executed real-socket gates.
Retesting the final full diff after the observation-helper fix is pending.
The [26-item working matrix](continuous-acceptance-matrix.md) awaits the final end-to-end result.

For attempt 11's fixed source manifest
`148e42afa9261eab328a3efc92895428e1844ff86abd86b311980435c01f4d2e`,
the [unit/race run](results/continuous-final148-unit.jsonl) had 19 packages, 274 top-level PASS,
789 PASS test events, 25 SKIP, and 0 FAIL.
The [execution conditions and source mapping](results/continuous-final148-unit-metadata.json) were saved.
SKIPs include tests requiring real-socket opt-in. Go race coverage is distinguished from safety of the entire C BLS implementation.
Relay selection rules and test observations were subsequently changed, so this unit result is evidence for an intermediate source.
G3 and necessary final regressions will be rerun against the next fixed source.

The source manifest for attempts 12 and 13 is
`59b0ac84536503682915fb0a1d5c75de60dedf7c70fd74ab9f65eb7bc729823d`.
Its [unit/race run](results/continuous-final59-unit-metadata.json) had 19 packages,
277 top-level PASS, 802 PASS events, 25 SKIP, 0 FAIL, runner 0, and 0 source diffs.
This result likewise does not verify the final diff after the forthcoming WAL codec change.

The existing two `core/forkid` failures and the three failures/one timeout in `internal/ethapi`,
reproduced from the starting archive during expanded auditing, are separated into the
[baseline issue record](continuous-baseline-issues.md).
No expectation-only changes or PoW/consensus changes bundled into this DEX connection are made.

The limited measurement is the [maximum-calldata native component test](results/continuous-native-cost.md).
Maximum verification time across all allowed combinations, C heap alone, equal-load CLX network comparison,
WAN, 60-minute mixed load, real MM/Oracle operation, and performance comparison with Hyperliquid are unexecuted.
New FROZEN loss allocation, public committee rotation, production fee rates, additional issuance,
and public real-fund use are unimplemented/unapproved.

The final 26-item matrix, final source manifest, and review archive will be linked to this record
after G3 and retesting of the final diff. Overall completion is not declared at this point.

## Attempt 14 and the Final Reconciliation Helper Fix

Attempt 14 on source `a64dc7053ad435113f488cb0f457683cd0d9cf69e05dbea6593bf7d840ae4e16`
failed after 1412.09 seconds. It completed CLX754, DEX finalized/CLX accepted 109, 72 payments,
custody295, cold-relay reauthentication 410/410, and full accounting reconciliation.
The final RPC block comparison for Common index 0 returned `ordinary parent block/root/gas mismatch 0 <nil>`;
later-starting DEX OFF synchronization is NOT_RUN. `0` is the Common index, not a block height.
The [raw log](results/continuous-g3-normal-14.log) and [metadata](results/continuous-g3-normal-14-metadata.json) are retained.
This partial success is not changed to an overall G3 PASS.

A reproduction using real `ethapi.RPCMarshalHeader` showed that the RPC `hash` matched the canonical block hash,
but rehashing a Header without the Common admission/reward roots, KeyInfo, and other fields omitted from RPC differed.
The failed run did not save the full raw response, so that log alone does not establish whether a real fork occurred.
The test helper was changed to compare the explicitly exposed RPC hash/number/parentHash/
stateRoot/transactionsRoot/receiptsRoot/gasUsed against an already authenticated source block.
Independent tests require every field and reject missing/null/altered values.
Receipt, gas, and mining=false reconciliation remains; production RPC/consensus and financial formulas were unchanged.

The final candidate source is `7f786223801e567b77c6c37bf437c189ea440de3db91f0b93d4fae705cdc97e2`.
The same later-starting OFF synchronization and DB-restart helper was added to the short normal CLX source test,
which passed at CLX11 with six deposits. The source's test peer capacity was set to two connections
for CLX and the later Common node. Final reconciliation with long history will be assessed separately in the next complete G3 run.

The initial startup request for attempt 15 was rejected by automatic approval review due to shared-capacity risk
with approximately 1.7 GiB free in `/tmp`. No test process started from that request.
The dedicated Go cache, containing 23,545 files and 5,281,325,292 bytes, was copied to a new ignored
`build/stage` location in the workspace; all hashes were verified before switching the dedicated cache path.
Logs, failed archives, operational data, and distributed binaries were not moved/deleted;
approximately 6.7 GiB of free `/tmp` space was secured.
The [environment change record](results/continuous-cache-storage-migration.json) was retained,
and the test restarted in a new namespace with the same source, evidence limits, and 45-minute deadline.

## Final Result of Attempt 15

PASS on the same source `7f786223…cdc97e2` in 1546.32 seconds, runner 0,
matching before/after source hashes and 0 diffs.
CLX749, DEX finalized 109/CLX accepted 109, unsettled gap 0, deposit cursor 10, 72 payments, custody295.
Cold-relay reauthentication covered this run's actual 406/406 records, without reusing attempt 14's 410 records.
RPC projections and all receipt/gas comparisons for the seven existing Common nodes also passed,
as did 750-block/410-receipt synchronization, same-DB restart, and engine 0 on the later-starting OFF Common node.

The complete DEX shutdown, from 168 to authenticated source 257, lasted at least 89 heights;
it caught up from the same WAL and authenticated the final deposits at 281/285 as DEX source 314/version2/cursor 10.
The 18 unsettled items at accepted 60 versus DEX78 during CLX shutdown were settled after same-DB resumption,
when checkpoint 78 was accepted at CLX467.
Final gas was 4,473,920,409,600,000,000, Common 894,784,081,920,000,000,
and burn 3,579,136,327,680,000,000 atoms. These are not mixed with costs from attempt 14 or interim height 707.
See the [raw log](results/continuous-g3-normal-15.log), [complete final extraction](results/continuous-final-g3/summary.json),
[final record](continuous-status.md), and [26-item matrix](continuous-acceptance-matrix.md).
These results were appended after retesting, without rewriting previous FAIL or unexecuted portions as PASS.
