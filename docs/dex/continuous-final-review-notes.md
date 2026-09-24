# Independent review notes for the final continuous-operation assessment

2026-09-23. In addition to a read-only review of source, current specifications, and saved raw logs,
one new O12 unit test described below was added as instructed. Production code and existing fixtures were not changed.
This is not a test execution record for the final complete diff.
It records an audit while the G3 trial 8 failure, relay fix, and preparations for trial 9 were in progress.
The authoritative assessment is the [26-item matrix](continuous-acceptance-matrix.md),
accompanied by the final source manifest and corresponding raw logs.

## Items to resolve or disclose first

1. **G3 trial 8 is FAIL due to an implementation defect.** After a normal CLX key update, the relay's
   `observeInbox` omitted KeyContext when reverifying an entry proof at the target anchor,
   quarantining valid CDXA data. DEX stopped at finalized 51; no fallback credited funds
   without authentication. After focused tests covering pre-fix reproduction, a key update
   between base and target, the same anchor, forged/missing current and previous contexts, and
   cold source WAL, rerun G3 and final regressions. Check the latest logs from the fix owner.
2. **Distinguish the combined old-claim replay check.** Current G3 holds old CP14 until the end and
   pays it after multiple anchor updates and a relay restart. It also checks subsequent
   OFF Common synchronization and DB reopening, but the complete sequence
   "pay old claim → further anchor update → cold restart/different relay → resubmit same claim"
   is not currently explicit as a single real-network path.
   `TestNativeRollingStagingHistoricalCheckpointClaimsRestartAndRollback` checks reopening
   before payment and replay after payment in the same StateDB; `TestStateDBDiskReopenPreservesNativeClaims`
   checks reopening after payment without rolling. Additional combination testing, specifically
   the new O12 unit below, further checked this combined sequence. The whole sequence has
   not run on the real network, so report that scope separately.
3. **The review archive needs a supplement.** The current `source_manifest.py` suffix allowlist
   excludes `.diff` and `.csv`. New independent-ledger CSV files and source-diff logs are currently omitted.
   Add a supplemental archive/hash with explicitly selected safe public result files to the final archive,
   or address this before freezing the runner. Retain the full untracked list and reasons for exclusions.

This review identified no new loss of funds or authentication bypass. The trial 8 relay omission is
an already escalated progress-blocking defect; this review does not anticipate a post-fix PASS.

Additional test specification (recorded before implementation): Add a check only to the new
`dex/settlement/native_rolling_paid_recovery_test.go`, reusing the existing real-BLS/MPT rolling
fixture. After authenticated updates 16→32→48, reserve a 10 CLX withdrawal in CP1 referencing
retained old anchor 16 and pay a recipient distinct from the relay sender. Then authenticate 48→64,
commit state and trie, close the new test-owned LevelDB, and reopen it with a fresh handle without
cache. Require the same claim from a different sender to be a replay that leaves balances, buckets,
nullifier, and CP/anchor history unchanged; an altered payload with the same claim ID must be
rejected without changing the root. Do not directly alter anchor cap metadata. This is a unit test
of the combined sequence using synthesized evidence with real finality signatures and a persistent
StateDB, not a normal TX path or real-network restart. Final full-diff PASS is still separately required.

Result: The focused `-race -count=1` run of
`TestNativeRollingPaidClaimAdvanceColdReopenAndDifferentRelay` is PASS (test 0.92 seconds / package
1.986 seconds, 1 top-level test, no FAIL/SKIP). Raw log:
`/tmp/common-dex-continuous.uye5vgqi/logs/rolling-paid-recovery-focused-race.jsonl`;
stderr has the same basename with `.stderr` (empty). Go 1.27.1, GOMAXPROCS=2, readonly modules,
dedicated cache, GOPROXY=off, `-p 1 -timeout=2m`. Freeze the Go file after this success and
include it in the next G3/final unit manifest. Other source fixes were still in progress, so this
focused PASS is not a PASS for the final complete diff.

## O01–O26 evidence mapping and final-assessment conditions

"Required evidence" below confirms that tests are implemented; it is not a final PASS column.

| ID | Required evidence / implementation mapping | Final reporting conditions and limits |
|---|---|---|
| O01 | `results/continuous-start`, initial archive, tracked.patch, all untracked files, classification | Initial 377 files: CLX 37 / DEX 43 / tests 95 / docs 43 / results 159. Recollect final counts; do not call all files production changes. |
| O02 | `TestG0EarlyQCContentFailureBoundaries`, `TestFHSEarlyQCBeforePrepareUsesAuthenticatedCatchup`, `TestFHSProcessRecoveryQCBeforePrepare` | Distinguish malformed/missing/duplicate unit cases from positive body repair on 7 real CLX nodes. Verify that a single QC has not become finality. |
| O03 | `TestG0CanonicalHeadStorageFailureAndRetry`, `TestFHSCanonicalStateDurableBeforeShutdown`, G3 full CLX stop and same-DB recovery | Trie → batch sync → publication order, with no publication on failure. Selected SIGKILL cases do not guarantee physical-power-loss or full-disk-failure recovery. |
| O04 | `TestG0CommonCLIJournalPathRestart`, `TestCommonCLIEmptyTrieJournalRestartDEXOff`, `TestG0NativeOnlyLocalGenesisFieldsMayDiffer` | 8 launches covering omitted/empty/safe relative/absolute paths. Rejection of explicit journal settings that collide with instance/DB paths remains unsupported. |
| O05 | `reward_execution_independent_of_local_certificate_delivery`, `speculative_reward_proposal_does_not_pin_period`, CDXP committed participation | The same parent/proposal is independent of local collector differences. Preserve pre-fix FAIL and distinguish this from general inclusion guarantees. |
| O06 | `rolling-anchor-spec.md`, `fixed-key-renewal-spec.md`, CDXA/NativeAnchorUpdate | Both the base in DEX parent state and history in CLX canonical state. Do not confuse source key renewal with fixed DEX epoch 1. |
| O07 | Rolling financial cold replay, native history/key renewal, multiple G3 anchors | Multiple steps preserving 64-ancestor/64 KiB limits. Callbacks do not change canonical state. |
| O08 | Rolling base/header/SignInfo/MPT negatives, `TestKeyRenewalRejectsContextAndGenerationAttacks`, etc. | State malformed-fixture rejection results and the unsupported/rejected scope of unknown committees and key renewal with PoW candidates. |
| O09 | `TestFHSNativeContinuousOrdinaryCLI`, `NORMAL_CONTINUOUS_PASS`, each `CONTINUOUS_TX` | Require finalized new deposits/CPs/claims across multiple intervals, in addition to CLX height ≥257. Do not erase current trial FAIL results by replacing them with final PASS. |
| O10 | `CONTINUOUS_DEX_ABSENCE`, same-WAL restart, subsequent CDXA/cursor/CP | Trial 8 observed 66 CLX heights, 168→234, during the actual outage, but subsequent catch-up was incomplete. Partial observations are not an overall O10 PASS. |
| O11 | Source HTTP/WAL/missing/corrupt negatives, `TestFHSNativeOrdinaryETHSource` | Distinguish unavailability from authentication failure. There is no recovery feature for permanently missing historical data. |
| O12 | Long-held old CP14, native rolling old claims, DB reopening/nullifier, new `TestNativeRollingPaidClaimAdvanceColdReopenAndDifferentRelay` | CLX rights-history pruning is not implemented. A unit filling metadata to 1024 is not 1024 real TXs. Separate combined unit PASS for post-payment update → cold DB reopen → different-relay replay from real-network scope. |
| O13 | 2 independent payer relays, normal TX CP/claim replay, sender/nonce in `CONTINUOUS_TX` | Distinguish same-raw retransmission / same business operation with new nonce / different sender; account for added gas in the ledger. Local dedup alone is not the defense. |
| O14 | 7 relay crash boundaries, actual midwrite SIGKILL, DEX orphan WAL recovery, G3 cold relay | Distinguish 7 boundaries using component backends from the real CLX network test. Authenticated canonical proof remains the completion condition after ACK. |
| O15 | Normal RPC/admission/TxQUIC, source finality + MPT, native nonce/gas/receipt | Do not label HTTP ACK/mempool/certified as finalized. No recipient private key is required; the gas payer is separate. |
| O16 | OUTAGE/REOPEN in `withCLXStopped`, subsequent CP acceptance TX after restart | Do not reuse old CP18 or old 214 for later settlement. Record final DEX finalized, CLX accepted, and their difference. |
| O17 | Capacity/fairness/history tests, compact expansion bound, native cap | Stop safely at caps. This is not indefinite capacity reclamation without deleting rights. Retry-count caps and automatic gas replacement are unimplemented. |
| O18 | `DEX_OFF_CONTINUOUS_AUTO_ETH_RESTART_PASS`, full block/receipt/root/gas/native comparison | One ordinary ETH AddPeer call, no manual InsertChain/Downloader calls. DEX engine instances/actions/imports are 0. |
| O19 | `joinSeventh`, `CONTINUOUS_SEVENTH_JOIN`, snapshot negatives, cold replay | The genesis-registered seventh node starts with its own key and fresh own WAL. This is not public joining, committee expansion, or snapshot compression beyond 128 records. |
| O20 | All 8 ordinary CLI combinations, `TestDEXActualCommonAPIEightCombinationsWithoutPoWDataset` | Separate lifecycle from normal 32 GiB DAG/nonce search. Resource-limited PoW is NOT_RUN. |
| O21 | Old 225→214 CLI, new independent golden, full canonical TX ledger | Identify fixtures explicitly. Long-run target 345−40−10=295 remains expected until observed. Reconcile gas/Common rewards/burn/surplus separately. |
| O22 | Pre-codec/crypto limits, key context, write budget, G3 observed maxima | Report maximum permitted values separately from run maxima. Fixed 525 bytes is not the whole submission. |
| O23 | `TestNativeRollingFullCalldataCostAndLateProofFailure`, G3 operation costs | Limited to bounded component measurements. A control network with the same normal CLX load, all-operation worst cases, C heap, WAN, and 60 minutes are NOT_RUN. |
| O24 | Committed participation, Noop after close rejection, missing-reward regression | Distinguish market continuity from held reward periods. General fairness and full FROZEN recovery are NOT_IMPLEMENTED. |
| O25 | Final-freeze unit/race/socket/source/roles/CLI/core/HotStuff/baseline | Separate package SKIP, incomplete runs, and PASS while source is changing. Preserve existing forkid 2 FAIL and RPC 3 FAIL + 1 timeout. |
| O26 | Final manifest/archive/reproducible runner/raw logs/protected-file comparison | Test binaries use dedicated /tmp. Check distributed binaries against G0 hashes for protection; do not erase their differences from HEAD. |

See the [coverage review](continuous-coverage-review.md) for detailed O11–O17/O22–O24 test names and limits.

## Interpreting saved results

Despite filenames such as `continuous-final-unit.json` and `continuous-final-cli-financial.json`,
the current source manifest is `061f4a0b6bed257c6ba8ad60f377f52cf8640cb6dcb8d4dcbd01a1575cfe1630`.
Trial 8 used `845f2af52a3c28a0a9b64ed3765d2f24ab4afdfac3ff2ec8e482c91a9431b898`.
Do not transfer those PASS results directly to the final diff containing the relay fix and new fixture.
If source differs before and after a run, `check.sh` exits 3 even if the test exits 0.
The review archive hash including docs/results and the execution source-list hash serve different purposes.

Trial 6 is NOT_RUN/incomplete because external interruption left no final assessment or ledger;
trials 1–5 and 7–8 are FAIL. Do not report the trial 7 status HTTP 503 observation-helper fix
and trial 8 production key-context omission as the same cause.

## Specific O19 authentication boundary

`reconfig/dex_continuous_economy_test.go:joinSeventh` obtains a finalized snapshot from the
existing 6 nodes through the public API and starts the dedicated Common/sidecar for `identity[6]`,
already registered at genesis. `dex/consensus/snapshot.go:ImportSnapshot` rejects overwriting
an existing voter's WAL and checks domain, ExecutionID/schema, genesis root/state, canonical JSON,
record count, and bytes. It does not copy peer LastVote/timeout watermarks; it uses new Safety
retaining the local VotePublic. It reexecutes each body and matches QC/finality and roots before
persisting. Reconstructing HighestQC from verified records is not copying a peer's private key or
personal Safety. After startup, financial root, engine bytes, and inbox cursor match the original
nodes, and catch-up conditions are checked.

This snapshot scheme reexecutes a finite set of records from genesis; it does not make an arbitrary
signature-only snapshot a new trust root. Do not treat it as completed long-term financial snapshots
or indefinite history compaction beyond MaxRecords 128, wire 2 MiB, and total reconstructed state 2 MiB.

## Measurements and unimplemented scope

Existing component measurements cover maximum calldata 65536 bytes, 35 source headers, fixture QC
records 70, MPT 8 nodes/1682 bytes, and ordinary legacy-anchor 12 writes. Altering the final count proof is
rejected with 0 writes. Native execution gas excludes TX intrinsic gas. `fixtureQCRecords` is not
instrumentation of actual cryptographic verification calls. New anchor v2 uses 16 initial / 13 ordinary
writes; do not mix these with the legacy 12-write measurement. Process RSS/HWM does not separately
measure the C heap.

60 minutes, WAN, Hyperliquid comparison, normal PoW search, real Oracle/MM, USD collateral, public
joining, general reward inclusion guarantees, new FROZEN loss allocation, and Validity Proof are separate
gates. A QC is committee finality certification, not a computational Validity Proof; a DA root does not
guarantee retrieval.

## Protected files and review package

The initial `/tmp/common-dex-continuous.uye5vgqi/baseline/protected-before.sha256` retains hashes
of distributed binaries/DLLs, the BLS archive, genesis, and existing local data.
The initial hashes of `build/bin/cypher` and `build/bin/cypher-linux-amd64` are both
`ae6ae08d01d731a963344bfc8ea16f7e84586535fcecf78649b823d91402edf1`.
Their git modification status predates G0, so final comparison uses this initial hash.
However, a 2026-09-23 recheck found that these two files alone had changed to another hash.
Their mtime is 2026-09-22 15:22:40 CEST; provenance is unconfirmed.
See the [70-file comparison record](results/continuous-resume-protected-observation.json).
Do not ignore this new mismatch because the files were already modified in git. Do not restore or overwrite them.
Do not promise byte-for-byte immutability for DBs written by running nodes. Separately record that no
operations were performed on operational processes/datadirs and that selected immutable files match their hashes.

Check the following for final preservation.

* Compare all `git ls-files -m --others --exclude-standard` entries with the archive manifest.
  Record exclusions by reason, such as protected binaries, generated pycache, and public supplemental results.
* Ensure reconstruction from HEAD + tracked.patch + an archive including new source/specifications.
  Recollect final classification/hashes and verify before/after the runner that source did not change during execution.
* Ensure the archive excludes private keys, keystores, chaindata, operational WALs, and executable binaries.
  An allowlist does not guarantee absence of secrets in content, so select only public diagnostic files.
  No PEM private-key markers were found in these result files, but that is not proof of comprehensive
  detection of secrets in arbitrary encodings.
* `preserveFailure` uses a fixed allowlist containing only test-owned public signature WALs/configs/status.
  Distinguish paths to private keys from secret values, and record that external watch capture on failure
  is not an atomic snapshot across multiple files.

In final runtime observations, separate actual process counts from role counts. In addition to the usual
7 CLX helpers, 7 Common parents, 7 DEX sidecars, and 2 relays, state the running intervals of Common
inside the coordinator and the late OFF Common. DEX initially has 6 participants; the seventh starts
later. Namespace-local loopback traffic is not WAN.

## Independent joint review before Trial12 (added 2026-09-23)

Trial12 execution source manifest:
`59b0ac84536503682915fb0a1d5c75de60dedf7c70fd74ab9f65eb7bc729823d`.
This hashes the list of execution inputs such as Go files; it differs from the final deliverable archive
hash, which includes this review document. A read-only comparison of the saved Trial11 archive and
latest source independently checked relay selection and the post-financial-completion audit wait.
Starting was judged acceptable, but Trial12 was still running when this note was added; this is not
an overall G3 or final full-diff regression PASS. Preserve Trial11's 62/72 payments and canonical-idle
deadline FAIL, and distinguish the mapping of 72 expected Claim.IDs to 62 actual payments as evidence
from the failed run.

The relay change alternates between `active` and unauthenticated `complete` history within a lane,
prioritizing the reservation owner of an unresolved nonce within active work. Separate owner/sequence
hints for history and active work prevent an unavailable oldest history item or slow reservation owner
from resetting traversal of subsequent history to the beginning every time. Hints update after successful
persistence of the existing main cursor and before `Observe`. Persistence failure starts no hint update,
observation, or signing. FHS/MPT/nonce authentication after `Observe`, dependencies, exact retransmission
of saved signed TXs, payment, and the WAL schema are unchanged. `completed_pending_nonce` remains
active; quarantine/nonce-conflict reservations are not automatically released.

These hints affect only local selection order; they create no authenticated completion or authority over
funds. Cold reopening starts with empty hints and `validated`, then reauthenticates history. The verified
fairness therefore concerns a finite set of selection opportunities without intervening restarts, not
progress under unlimited crashes/restarts. Improved selection counts in the 204-record test are not
BLS/MPT wall-clock performance. The [cold scheduling specification/results](relay-cold-scheduling.md)
and [focused raw-log mapping](results/continuous-relay-cold-scheduling/metadata.json) record relay race
with 18 top-level PASS / 96 PASS events in 26.170 seconds (1 subprocess-only entry SKIP), and real
BLS/MPT/HTTP race with 14 top-level PASS / 106 PASS events in 66.982 seconds.
These do not replace ordinary CLI G3.

The G3 financial phase retains the existing 120-second idle condition based only on canonical progress.
It does not finish until all 72 native payments, the final checkpoint, independent 345→295 ledger,
wallet/bucket/gas/Common rewards/burn, ordinary source synchronization, and financial roots reconcile.
It checks the deadline again after reconciliation. As in Trial11, no carrier is sent with fewer than
72 payments. Only then does it transition once to the audit of cold reauthentication and nonce resolution,
observing only known job IDs moving from incomplete to authenticated `complete` as separate audit
progress. Audit status does not confer financial authority. ACKs, ordinary CLX height, first observation
of new IDs, and redisplay of already completed IDs do not extend idle time. Reject omissions, duplicates,
truncation, count mismatches, and completion regression; unresolved nonces are not complete.
`Reserved=true` remaining in completed history is a historical Attempt record and alone is not rejected.

The audit also uses 120-second idle and shares the existing parent hard deadline of 45 minutes minus
30 seconds for cleanup. Current time is evaluated after status retrieval; waiting for retrieval must not
revive an observation after the deadline. Account for gas from ordinary carriers/exact retransmissions
during the audit and reconcile all finances again after stopping relays. After the timestamp fix, the
fake-clock focused race run ×3 passed in 1.551 seconds
([raw log](results/continuous-trial12-audit-final-race.jsonl)). This tests the audit clock; the financial
network's final result must be determined from Trial12's own raw logs.

The G0 hash mismatches for protected `build/bin/cypher` and `build/bin/cypher-linux-amd64` remain unresolved.
This start decision does not change O26 "protected files unchanged" to PASS. Do not restore, overwrite,
or distribute them. Exclude binaries from the final review patch/archive and separately record initial/current
hashes and their unconfirmed provenance.
