# Continuous Operation: Final Assessment of 26 Items

2026-09-23. Starting/ending HEAD: `70862a71dfaf2b00694dc1354c6a64e9504d7db5`.
Final execution source manifest: `7f786223801e567b77c6c37bf437c189ea440de3db91f0b93d4fae705cdc97e2`.
**25 items PASS within the stated scope; O26 FAIL**. O23 is a PASS for limited component measurements, not comprehensive performance evaluation.
PASS entries in this matrix do not overwrite existing forkid/RPC test FAILs.

G3 attempt 15 took 1546.32 seconds, runner 0, matching before/after source hashes and 0 diffs.
It completed height 749, DEX/CLX sequence 109, 72 payments, custody 295, synchronization of all 750 blocks/410 receipts
on a later-starting OFF node, and same-DB restart.
Cross-reference the [G3 raw log], [final extraction], [test index], and [packaging and reproduction method].
Earlier FAILs/interruptions remain in the [development history] and are not rewritten by new results.

| ID | Result | Implementation, tests, and raw logs | Conditions and unfinished work |
|---|---|---|---|
| O01 | PASS | [Starting preservation], before/after source per run, final HEAD/status/untracked/manifest/coverage; [packaging and reproduction method] | Preserved 377 initial items. Classified CLX/DEX production, tests, documents, results, protected targets, generated artifacts. Binary mismatch is O26 FAIL |
| O02 | PASS | [U] `TestG0EarlyQCContentFailureBoundaries`, `TestFHSEarlyQCBeforePrepareUsesAuthenticatedCatchup`, [Q] `TestFHSProcessRecoveryQCBeforePrepare` | Distinguish unit alteration/missing/duplicate checks from body repair on seven real CLX nodes. Signature thresholds/finality unchanged |
| O03 | PASS | [C] `TestG0CanonicalHeadStorageFailureAndRetry`, [B] core durability tests, [F]/[G3 raw log] same-DB CLX resumption | Trie→synchronous batch→head publication; no publication on write failure. Selected SIGKILL/fault injection, not actual power loss/full disk failure |
| O04 | PASS | [CLI] `TestG0CommonCLIJournalPathRestart`, `TestCommonCLIEmptyTrieJournalRestartDEXOff`, [C] `TestG0NativeOnlyLocalGenesisFieldsMayDiffer` | Omitted/empty/relative/absolute journal and restart. Permitted local fields: RnetPort/EnabledTPS. General rejection of explicit path collisions is unsupported |
| O05 | PASS | [U] `TestNativeCLXFinancialFHSScenario/reward_execution_independent_of_local_certificate_delivery`, `/speculative_reward_proposal_does_not_pin_period` | The same parent/proposal is assessed using only shared CDXP state. General inclusion/delivery fairness remains incomplete |
| O06 | PASS | [Rolling specification]/[key-renewal specification], [U] rolling/native renewal tests, [G3 raw log] | Both DEX CDXA and CLX NativeAnchorUpdate directions. Normal key renewals for the same seven CLX members are distinct from DEX fixed epoch 1 |
| O07 | PASS | [U] `TestRollingFinancialCreditBeyond257AndColdReplay`, `TestNativeRollingStagingHistoricalCheckpointClaimsRestartAndRollback`, `TestNativeRenewalAnchorWritesHistoricalContinuationAndRestart`, [G3 raw log] | Updates from old anchors through bounded consecutive evidence, persistence/replay in both domains. MPT alone is not finality; callbacks do not rewrite CLX |
| O08 | PASS | [U]/[S] `TestRollingRejectHeaderRefAndSignInfoTampering`, `TestRollingRejectBaseAndPartialStorageProofs`, `TestKeyRenewalRejectsContextAndGenerationAttacks` | Component rejection of wrong root/domain/committee/epoch/parent/SignInfo, single QC, etc. Not simultaneous injection of every attack into seven-process financial operation |
| O09 | PASS | [G3 raw log] `TestFHSNativeContinuousOrdinaryCLI`, [TX list], `NORMAL_CONTINUOUS_PASS` | CLX 749 with L=64 unchanged. Finalized four initial deposits + six after the 65 boundary, new trades/rewards, 109 checkpoints, 72 claims |
| O10 | PASS | [G3 raw log] `CONTINUOUS_DEX_ABSENCE`/CDXA/`CONTINUOUS_DEX_ANCHOR` | Complete DEX shutdown 168→authenticated source 257, at least 89 heights. Multiple steps from the same WAL, flat 255/cursor 8→renewed key 314/v2/cursor 10 |
| O11 | PASS | [S] `TestRelaySourceHTTPFailureBoundaries`, `TestRelaySourceWALFailClosed`, `TestRelaySourceHeaderBoundAndReverifiedWAL`, [N] | Invalid data and unavailability separated; only verified prefixes saved. Permanent-missing-data recovery unimplemented. No skipping ahead by self-declaring a new root |
| O12 | PASS | [U] `TestNativeRollingPaidClaimAdvanceColdReopenAndDifferentRelay`, native historical claim tests, [G3 raw log] old CP14 withdrawal | Payment→additional anchor→real DB/trie reopen→retry by another sender is a compound unit test. G3 covers first payment of an old claim after earlier restarts and retry by another relay. No pruning of CLX rights roots |
| O13 | PASS | [U] `TestRelayAuthenticationNonceAndIndependentPayers`/ownership tests, [G3 raw log] two relays and checkpoint/claim replay | 109 new checkpoints + 91 retries, 72 payments + 60 retries. No double reservation/payment. Retries consume normal nonce/gas |
| O14 | PASS | [U] `TestRelayCrashBoundaryRecoveryAndProofRevalidation`, `TestRelayActualSIGKILLAndRestartBoundaries`, `TestRelayActualSIGKILLDuringTemporaryWrite`, WAL orphan tests, [G3 raw log] | Seven selected boundaries use a component backend. Real financial cold relay reauthenticates 406/406 records. Not every boundary was crashed in the same network run |
| O15 | PASS | [F]/[G3 raw log] RPC→admission→TxQUIC→TX/receipt, [S] `TestRelayInboxCompletionNeedsWholeProofBoundEffect`/planner tests | ACK/mempool/single QC≠finality. Reconcile effects/nonces through FHS/MPT. Separate recipient and gas payer |
| O16 | PASS | [G3 raw log] `CONTINUOUS_CLX_OUTAGE/REOPEN`, checkpoint 78 TX | Retained 18 unsettled items at CLX accepted 60 versus DEX78. Accepted 78 at height 467 after same-DB resumption; final 109/109, gap 0 |
| O17 | PASS | [U] `TestRelayCapacityFairnessHistoryAndRestartCursor`, cold scheduling, `TestWALDictionaryUniqueBodyCapStopsBeforeCanonicalReplacement`/compact bounds | Finite queue/cap rejection and resumption of recoverable queues. Unpaid rights/orphan proposals/safety state retained. Indefinite GC at hard caps unimplemented |
| O18 | PASS | [N] short source test, [G3 raw log] `DEX_OFF_CONTINUOUS_AUTO_ETH_RESTART_PASS` | Reconciled seven normal Common nodes; later OFF node synchronized 750 blocks/410 receipts/native state and restarted from the same DB. No manual head correction; engine 0/0/0 |
| O19 | PASS | [U]/[S] `TestFinancialSnapshotDistinctRegisteredLateVoter`, snapshot negatives, [G3 raw log] `CONTINUOUS_SEVENTH_JOIN` | Registered seventh participant's unique key authenticates a financial snapshot at final 19/cert 20, with fresh own WAL. Does not enable public admission or key duplication |
| O20 | PASS (lifecycle) | [R] eight real-API combinations, [CLI] eight normal-CLI combinations/configuration/independent start-stop | Normal 32 GiB PoW nonce search/proof delivery/combined performance NOT_RUN due to insufficient resources. Lifecycle is not a substitute |
| O21 | PASS | [F]225→214, [G3 raw log]/[final ledger]345−40−10=295, 17 wallets/8 buckets/all 410 TXs | Original and long-duration ledgers are separate. Long-duration fee funding 0.168＋support 9.832 funds reward 10. Separately reconcile gas/Common/burn, surplus, and reservations |
| O22 | PASS (limits) | [U] codec/native write/MPT bounds, [S] source bounds, [G3 raw log] anchor cost | Retain 64 headers/64 KiB/7 signers/8 descendants. Observed maximum 63566 bytes/32 headers/7 MPT nodes/2105 bytes. V2 initial 16 writes/normal 13/replay 0 |
| O23 | PASS (limited measurements) | [Cost] three each 65536-byte success/late-MPT failure, [Deps], [TX list] | Record wall time/Go allocation/RSS/native gas/writes. Worst cases for all operations, equal-CLX-load network control, instrumentation of real BLS calls, C heap, WAN, 60 minutes NOT_RUN |
| O24 | PASS (deferral and limits) | [U] committed participation/Noop after close rejection, [F] reward omission/existing FROZEN fault | Separate reward-period deferral from market progress. General inclusion fairness, remedies for withheld evidence, new FROZEN loss allocation/full recovery NOT_IMPLEMENTED |
| O25 | PASS (rerun and classification) | [Test index]: unit/race/HotStuff/core/VM/CLI finance/socket/source/process/roles/G3 | Retain existing [B] forkid 2 FAIL, RPC 3 FAILs + 1 timeout. Explicitly record that standalone relay/native/financial modes were not rerun for the final source. Does not mean all tests passed |
| O26 | FAIL (protected-file invariance) | [Protection comparison], [stage evidence], final manifest/archive and coverage of all untracked/public supplements | Of 70 G0-selected files, 68 match and two distributed binaries differ. All 70 unchanged since resumption; origin of changes unidentified. Excluded hashes recorded without restoration. Separate review packaging from protection FAIL |

## Treatment of Unexecuted and Unimplemented Work

Of 26 unit SKIPs, 22 require dedicated sockets and two invoke child entry points from parent SIGKILL tests.
Actual chown for a foreign UID and optional external Trial13 structural comparison were not run in the final unit suite.
The five core/VM/CLI SKIPs are supplemented by dedicated CLI tests. Details are in the [test index].

Normal PoW, WAN, 60-minute mixed load, equal-CLX-load comparisons with/without DEX,
all maximum-proof arrangements, and C heap are NOT_RUN.
General reward fairness, recovery from permanently missing DA, complete FROZEN recovery,
public participation/committee rotation, production financial terms, USD collateral,
real Oracle/MM, and Validity Proofs are NOT_IMPLEMENTED/out of scope.
A QC is not a computational Validity Proof, and a DA root is not a retrieval guarantee.
O23 PASS does not establish a performance advantage.

[U]: results/continuous-final-7f78-unit/raw.jsonl
[C]: results/continuous-final-7f78-core-vm-cli/raw.jsonl
[Q]: results/continuous-final-7f78-g0-qc-process/raw.jsonl
[S]: results/continuous-final-socket-raw.log
[N]: results/continuous-final-source-raw.log
[R]: results/continuous-final-roles-raw.log
[CLI]: results/continuous-final-cli-roles-raw.log
[F]: results/continuous-final-7f78-cli-financial-raw.log
[B]: results/continuous-final-7f78-baseline/raw.log
[Cost]: results/continuous-final-native-cost.md
[Deps]: results/continuous-final-7f78-production-deps/metadata.json
[G3 raw log]: results/continuous-g3-normal-15.log
[Final extraction]: results/continuous-final-g3/summary.json
[Final ledger]: continuous-final-ledger.md
[TX list]: results/continuous-final-g3/transactions.csv
[Test index]: results/continuous-final-test-index.md
[Starting preservation]: results/continuous-start/classification.json
[Packaging and reproduction method]: continuous-review-bundle.md
[Rolling specification]: rolling-anchor-spec.md
[Key-renewal specification]: fixed-key-renewal-spec.md
[Protection comparison]: results/continuous-final-protected-observation.json
[Stage evidence]: results/continuous-protected-build-stage-evidence.json
[Development history]: continuous-development-history.md
