# DEX leader submission change history

2026-09-24. **See [leader-submission-final.md](leader-submission-final.md) for the latest deployment, handoff, and financial reconciliation results.** Release r8 was deployed to all 21 processes; all seven participants recovered from the same databases. Authenticated accounting confirmed CLX acceptance through DEX finalized sequence 165, eight claim payments, and no additional payment on replay. There are no independent relays. The following is the r1–r7 history; failures and incomplete work remain recorded as observed at each stage. This is not a completion report for all of Q0–Q5.

Target: `vmi3365213`, `/root/work/cypher-FHS-D-ExchangeCore`, branch `FHS-D-ExchangeCore`. HEAD remains `70862a71dfaf2b00694dc1354c6a64e9504d7db5`; the implementation is in uncommitted changes. Artifacts are under `/tmp/common-dex-leader-submit-yda0gkpo`. Unless specified otherwise, raw log names below are relative to its `results/` directory.

## Implementation and deployment

A submission worker was integrated into the existing `dex-validator` supervised by each normal Common process. The current DEX HotStuff leader submits ordinary CLX transactions. Standby members read finalized data and authenticated CLX state to reconstruct unfinished business in their own durable journals. A successor uses its own gas account and nonce. Committee voting keys and the predecessor's signing keys are not copied.

`cypherdex-relay0/1` were removed from the normal PM2 configuration. Submission uses the existing seven Common parents and seven DEX sidecars without adding processes. Including the seven fixed CLX committee nodes, immediately after r1 deployment there were 21 actual processes and 14 PM2 entries. Each Common's submission configuration is in the manifest's `LeaderSubmission`; its journal is in `submission/` under its own DEX datadir. The old `dex-relay` CLI remains for historical fixture regression tests.

This change retained chain ID `10101919`, CLX genesis `0xb2385f44d0adaf948957528f4e6c7c493fddf1311555c960d925b12dbe0f1626`, and DEX ID `0xae8b961b841fb8b270e87639314f2881c8ac3c6154480eb96b44296ad9c1be62`. No initialization or data deletion was performed. See `deployment.json` and `live-deployed.json` for r1 deployment and running-executable checks, and `pm2-retire-relays.log` for removal of the old relay entries. The r1 binary SHA-256 is `d1f4ec8184c6b7a2d17e39059a69bd3eed3489f0ddb4e5372871ed5858084ef3`.

Implementation rules and limitations are in [leader-submission-spec.md](leader-submission-spec.md).

## Observations on the designated network with r1

| Observation | Result and evidence |
|---|---|
| Normal PM2 startup launched a DEX sidecar and internal submission worker for each of seven Commons, with no independent relay process | PASS(LIVE), `live-deployed.json`. This is the observation at that stage; the final state is collected separately. |
| SIGTERM stopped current leader 0's DEX sidecar while its Common parent and CLX RPC remained running. The remaining six moved from view 29 to 30 and elected leader 1 | PASS(LIVE: leadership change only), `live-handoff-stop.json`. DEX remained certified 1/finalized 0 before and after the stop; this does not establish successful financial settlement handoff. |
| Delayed startup of CLX deposit authentication | FAIL. After the first short anchor update became certified, preparation of the next update waited for finality and could not produce the required descendant block. See `live-drive-handoff.log` and `live-drive-handoff-r2.log`. The latter is the second attempt on r1, not a result from release-r2 deployment. |
| Traffic to a stopped DEX recipient occupied the shared outbox | FAIL. The other six had PendingTransport 245–256, certified 11/finalized 0, view 75. See `live-stalled-status.json`. The stopped recipient recovered from the same DB, and normal ACKs drained existing frames without deleting them. |
| CLX deposits and partial accounting | PASS(LIVE: partial scope only), `live-accounting-before-fix.log`. DEX credit, checkpoints, and claims remained incomplete, as shown below. |

Partial accounting reconciled authenticated CLX anchors 1080 through 1161. The ending CLX block hash was `0xdf391387fcf58c33aa13ad933d52d0b98598f9ca566e73e9de450d8a4ba58d70` and state root `0x20a04d6f12702a5087273897a0dc1b2bbb9dbd083a3e105405ac7851e4f746bd`. All 14 CLX execution processes showed those values and DEX engine `Instances/Actions/InboxImports = 0/0/0`. DEX was certified 12/finalized 0; that unfinalized root is not treated as accepted by CLX.

| Account | Integer amount in smallest units |
|---|---:|
| custody | 225000000000000000000 |
| Unimported trader deposits U | 200000000000000000000 |
| support S | 20000000000000000000 |
| insurance I | 5000000000000000000 |
| trader T / fee F / withdrawal W / reward R / Z | 0 each |
| surplus | 0 |
| CLX gas expenditure in this run | 1821400000000000 |
| Common RPC rewards | 364280000000000 |
| burn | 1457120000000000 |
| CLX accepted sequence / paid claim count | 0 / 0 |

The run processed 35 ordinary transfers, two trader deposits, one support deposit, and one insurance deposit. Existing CLX issuance is accounted for separately; no new DEX issuance was introduced. The underlying acceptance log checks CLX FHS/account-proof authentication and receipt consistency, but does not establish independent receipt-trie reconstruction. The financial fixture's 225→214 result does not apply to this partial run.

## r2 fixes and component tests

Certified chains can now be used **only to prepare** the next deposit-authentication update. Checks cover connection from an authenticated finalized prefix, 5/7 signatures, checkpoint hash, parent QC, pre/post roots, domain/epoch, and inbox boundaries. CLX source finality and inbox proofs are checked separately. A single QC is not promoted to finality; business completion and CLX payments still require descendant finality evidence. The submission worker creates neither financial Noops nor fabricated prices.

Transport retains the shared limits of 256 entries and 8 MiB and adds per-recipient quotas. The normal configuration allows 36 entries per recipient; byte quotas also accommodate the largest legal frame. A full recipient explicitly returns busy while delivery to healthy recipients continues. Accepted frames and voting history are retained. Startup recovery may continue through pure transport backpressure only after signing-safety state has been restored. Mixed DB or authentication errors are not suppressed.

`r2-production-source.json` records hashes for 124 production files; all matched when this section was written. `final-source-r2-regression-start-manifest.json` records the source hashes for financial and proof regressions. The following component and isolated tests are not r2 LIVE results.

| Test | Result and conditions | Raw log |
|---|---|---|
| `TestLeaderStandbyNeverReservesSignsOrSends`, `TestLeaderRechecksRoleAtSigningAndSendingBoundaries`, `TestLeaderJournalCannotBypassGuardAndInboxIsGated` | PASS(UNIT): reject sends from standby participants, expired views, and direct journal calls | `final-source-r2-proof-relay-source-race.jsonl` |
| `TestLeaderLeaseLossCancelsInFlightObservation`, `TestLeaderHandoffUsesOwnNonceAndRetainsPredecessorSignedAttempt` | PASS(UNIT): cancellation, distinct gas accounts, and preservation of old nonces | Same log |
| `TestCertifiedPlanningQCIsNeverFinality` | PASS(UNIT): reject single-QC finality and altered domain/epoch/metadata | `final-source-r2-proof-relay-source-race.jsonl` |
| `TestPendingSubmissionReplacesIdleOfflineLeaderOverTLS` | PASS(ISOLATED): real TLS; six/five participants form a TC with one/two stopped, while four cannot form a TC with three stopped. No financial actions generated | `final-runtime-r2-service-race-approved.log`. Rerun against frozen r2 source; earlier attempts retained. |
| `TestOfflinePeerCannotExhaustHealthyTLSOutbox` | PASS(ISOLATED): 300 deliveries to another real TLS recipient while retaining 36 frames for the stopped peer; after restart with the same journal, the peer returned and all 36 frames drained | `unit-or-isolated-component-dex-leader-transport-fairness-r2.log` |
| `TestOfflinePeerQuotaPreservesFHSQuorumProgress` | PASS(ISOLATED): six real FHS/TLS actors reached certified 40/finalized 39 with matching roots. Healthy actors restarted with the same DB while retaining 36 frames for the stopped recipient. This is not a financial model | `final-runtime-preserved-dex-leader-service-quota-r2.log`, 77.23 seconds. The initial incomplete copy was retained and the completed log saved separately. |
| `TestDEXNormalCLILeaderSubmissionLifecycle` | PASS(ISOLATED): workers inside seven existing validator processes; Common stop and same-DB restart. The CLX endpoint was intentionally unavailable, so this tests lifecycle rather than financial settlement | `final-runtime-r2-cli-approved.log`. Rerun against frozen r2 source: 8.55 seconds, six top-level tests passed. |
| Existing 225→214 financial fixture | PASS(UNIT): seven real FHS managers with queues in one process; regression of 18 financial blocks and native StateDB accounting | `final-source-r2-unit-financial.jsonl` |
| Existing forkid tests | FAIL: `TestCreation` and `TestValidation`; expectations unchanged | `final-baseline-forkid.jsonl` |

`final-runtime-r2-summary.json` maps the final focused tests. A read-only parser rechecked deployed configuration for seven participants and independence of 21 gas keys in `final-runtime-r2-candidate-parser.log`. Leader observation after signing-safety restoration is in `final-runtime-r2-leadership-race.log`. The initial sandbox denial of namespace creation remains in `final-runtime-r2-service-race.log`; a subsequent approved run used a loopback-only namespace. There was no host-network fallback.

The r2 release build log is `release-build-r2.log`. When this section was written, observation of post-deployment r2 PID/executable hashes and post-handoff CLX finality/payments was still pending. Successful logs for earlier source are not a PASS for the entire final source.

## Shutdown and leader-eligibility review

On a signal, `runDEXValidator` cancels the worker context and waits for it to exit before closing the journal, keys, and service. A stopping Common parent signals only its own child handle, allows five seconds for graceful exit, then terminates it forcibly if necessary. Child failure does not stop the parent's CLX/RPC/PoW work. Under the existing lifecycle, a child stopped on its own is not automatically respawned; restarting Common restarts the sidecar.

Leader eligibility comes from the consensus actor's current view. On view change, failure, or shutdown, the actor closes the lease and cancels the worker's in-flight context. The worker rechecks the same view before and after signing and immediately before each send. Standby reconciliation neither signs nor sends. Network calls do not hold the actor. Notices of pending settlement only activate the timeout mechanism; they do not change proposal validity or state roots.

Starting a send and its network arrival are not atomic, so a delivered transaction cannot be recalled. A node temporarily retaining an old view may also send. Payment safety relies on ordinary CLX authentication, reservations, nullifiers, and business-ID idempotence. Previously signed nonces remain in the journal even if another participant completes the business. Business completion and a sender's unconsumed nonce are reported as separate residuals.

BLS uses only the existing package initialization. Workers and actors do not share key/verifier objects. A Go race PASS covers the executed Go paths and does not prove all internal concurrency safety of the C library.

## Outstanding r2 LIVE handoff checks

All seven participants currently fetch CLX proofs and submit ordinary transactions through one endpoint, `http://127.0.0.1:8999`, served by the `cyphermine` Common parent. If that parent also stops, CLX submissions wait even after DEX leader replacement. Redundant independent CLX ingress is not implemented. Requiring RPC reward work as a prerequisite for DEX participation is not an acceptable workaround.

The next live test keeps CLX ingress available and stops only the current leader's DEX sidecar. Success requires more than TC-based leader replacement: the unfinished business ID from before the stop must become an ordinary CLX transaction submitted using the successor's distinct gas account, finalize under CLX FHS, and reach authenticated checkpoint acceptance or claim payment. ACK or mempool admission alone is insufficient.

The predecessor must recover from the same DB, retain old signed transactions/nonces, and reconcile that overlap with the successor does not increase reservations or payments. Final observations will collect all Common/sidecar PIDs, roles, DEX certified/finalized sequences, CLX accepted sequence, outstanding business, unconsumed nonces, custody, buckets, and gas. Journals need not have zero rows for settlement to be complete.

The PASS scope of this intermediate record excludes 60-minute continuous operation, A/B/C release-performance comparisons, normal PoW, public RPC redundancy, general reward-inclusion fairness, and complete FROZEN recovery. QCs are committee-trust finality evidence, not computational Validity Proofs. A single-host loopback test does not demonstrate WAN operation or independent operators.

## Additional r2 LIVE attempts and boundaries during r3 work

The r2 normal-release SHA-256 is `e6c1ae2a41810015ec694736b769437cc3fba83601a4e052686db2fe4a6e1463`. All 14 target PM2 applications underwent a planned stop and same-DB restart; executable hashes matched for 14 CLX/Common processes and seven DEX sidecars. See `deployment-r2.json` and `live-deployed-r2.json`. Genesis and chain ID were unchanged, and no init was performed. CLX heavy-engine counters were 0/0/0 on all 14.

The existing funded journal `/tmp/live-finance-leader-handoff` was resumed. Initially, the runner resent a Noop already included at h12 and received HTTP 400. After fixing the runner to reconcile the authenticated exact action/root before replay, participation-proof commits and financial Noops progressed. Signatures, nonces, and financial state were not adjusted. See `live-drive-release-r2.log`, `pending-action-readonly-evidence.json`, and `unit-runner-cold-reconcile.log`.

The next attempt reached DEX certified 46/finalized 39 and advanced the CLX anchor beyond 16, but CLX accepted remained 0. Ordinary transaction rejection was caused by a submission gas limit of 20,000,000 exceeding the current genesis's Osaka cap of 16,777,216. Read-only execution of the same payload succeeded; the estimate was `0xd33bf8`, the sender nonce was 0, and the transaction was not included. See `anchor-readonly-simulation.json` and `live-r2-anchor-receipts.json`. This requires a submitter fix with preservation of existing signed transactions, without weakening genesis or CLX admission rules.

DEX actors 0/3/5 then stopped signing with `DEX WAL byte budget exhausted` and returned status 503. The remaining four could not meet the five-participant threshold for a new QC. The financial-input runner exited on 503, retaining its journal and all balances. See `live-drive-release-r2-resume.log`, `live-r2-status-unavailable.json`, and `live-r2-storage-failure-metadata.json`. The current generation's WAL reached 2 MiB before the first cut at 64 finalized blocks. The required fix is lossless storage-generation rotation without increasing the cap. Reinitialization is not a substitute for recovery.

This attempt did not establish a LIVE PASS for fills, withdrawals, or reward payments. The component fixture's 225→214 result remains a separate regression result.

## Additional r3–r5 fixes and live-network observations

r3 implemented gas-cap compliance and early hot-WAL rotation using an authenticated finalized prefix. The specification records when only the gas limit of the same nonce may be corrected while retaining the old signed transaction. Read-only copies of all seven live WALs were restored twice each; original WALs were not modified. See `r4-current-seven-wals-copy-replay-final.log`. Deployment also resumed from the same DBs, and the r4 observation showed storage generation 3 on all seven. A 600-second component-test timeout remains in `r4-wal-final-race.log`; rerunning the remaining existing storage tests passed in `r4-wal-existing-race-r2.log`.

Only r3 leader 0's DEX sidecar was stopped, preserving the Common parent's CLX ingress. Six participants moved from view 610 to 611 and reached certified 68/finalized 53. See `live-handoff-stop-r3.json`. Restarting `cyphermine` with the same DB restored the sidecar. This leadership change alone does not establish completed financial settlement.

Pending submissions repeatedly triggered four-second timeouts between sparse financial inputs. r4 added a bounded grace period specifically for submission waits. Four real-TLS tests passed with race detection, retaining normal input handling and the 5/7 TC rule. See `r4-submission-grace-tls-race.log`. Financial/relay regressions also passed 40 top-level tests; 225→214 remains a same-process financial fixture result. See `r4-final-relay-finance.jsonl`.

When a height had QCs from multiple views, independently selecting the maximum view at each height could splice chains with different parents. r4 added explicit `selected=true` traversal from HighestQC through its parents. The live test then exposed an integration omission: the outer query argument-count check rejected this parameter. See `r4-selected-live-query.json`. r5 fixed the complete factory-handler path; both that path's race tests and the full finance-package race tests passed. See `r6-full-factory-query-race.log` and `r6-finance-full-race.log`. r5 was built but not deployed.

The deployed r4 SHA-256 is `276bec77f0203369119c3cedd988fd93fe26fea2adffd250a2a4ab2e68e0ddb1`. See `deployment-r4.json` and `live-deployed-r4.json`. Executables were checked across 14 CLX/Common processes and seven DEX sidecars. No independent relay exists; chain ID, genesis, and financial schema were retained.

After the r4 restart, all seven CLX nodes stalled at height 1419 with identical hash/root/receipt values. Authenticated QC 1428 was repeatedly delivered, and proposals at view 1429 repeatedly conflicted with durable votes. Refusing those votes is required safety behavior. However, duplicate QCs and revalidated proposals repeatedly reset the pacemaker start time, preventing recovery through normal timeout; a fix was in progress. See `r4-live-clx-restart-stall-ipc.json`, `r4-live-clx-restart-stall-logs.json`, and `r4-live-clx-restart-stall-qc-tail.json`. Vote-WAL deletion, head correction, and init are not used as workarounds.

The funded run continued to retain the same `/tmp/live-finance-leader-handoff` journal. At certified 105/finalized 83 and CLX accepted 0, later DEX state was not treated as settled on CLX. New final accounting and post-handoff acceptance would be recorded separately after deployment of the fixes.

## r6/r7 fixes and final-source regressions

r6 prevents repeated authenticated QCs at the same view and revalidated proposals from indefinitely extending the CLX pacemaker deadline. It locally tracks proposal-stage and certified-stage progress and suppresses resets from duplicates or old views. Normal lifecycle start, actual canonical insertion, and a legitimate timeout set a new deadline. Durable votes/locks/QCs, signature verification, thresholds, and the consensus schema were unchanged. The current native deadline of 516 seconds—130 seconds each for body/repair and 256 seconds for execution—was not shortened. Artificially aging a test timestamp must not be confused with observing 516 seconds in live operation.

The r6 SHA-256 is `9582763e424ac1662c9165382aed96c17c13664fe6f77b0b820980e0efcf20bf`. `live-deployed-r6.json` confirms matching executables for 14 CLX/Common processes and seven DEX sidecars. In `live-r6-clx-deadline-observation.json`, all seven CLX nodes reached height 1432 with matching hash/root/receipt values and heavy-engine counters of 0/0/0, progressing beyond the earlier stall at 1419. `live-r6-monitor.log` also records later CLX accepted progress, along with the subsequent recurrence of the DEX hot-WAL limit from unfinalized data.

r7 replaces exactly repeated hot-WAL Actions/State data with dictionary references. The local stored format is v5 and the expanded state remains v4; financial schema 6, archive/CURRENT v4, and signing domains remain unchanged. All records, votes, locks, QCs, timeouts, and unfinished work are retained, including the distinction between nil and empty slices. Limits remain: encoded 2 MiB, 128 records, total expanded Actions 2 MiB, total expanded State 2 MiB, individual Action 64 KiB, individual State 1 MiB. The new format is persisted only after authenticated replay; checksums are not authentication evidence. A [storage-format specification](wal-generation-dictionary-spec.md) and independent golden vectors were added. Unique data or unfinalized backlog can still trigger a safe stop; this does not unconditionally solve capacity constraints.

The r7 SHA-256 is `7aa9a559ade3f44931145b1398d4b734c1375f1cba133ddb471b5e9d48fca59f`. `r7-predeploy-compatibility.json` records that production changes from r6 were confined to four DEX-local WAL files, with no change to CLX rules, wire format, or genesis. The seven Commons first restarted with the same DBs. `live-deployed-r7-commons.json` confirms r7 on all seven Common parents and seven sidecars while the seven CLX committee nodes still ran r6. In `live-r7-startup.json`, all seven participants returned to active, with matching certified 127/finalized 124 and storage generation 5 at that observation. Local storage-cut bases were 124 for participants 0/1/2/4 and 122 for 3/5/6. These were intermediate observations, not final values. The later r7 update of all seven CLX nodes and final state are reconciled in the final deployment record.

No independent relay PM2 application was added. The r6/r7 deployment targets were 14 PM2 entries: `cypher0..6`, `cyphermine`, and `cypherdex1..6`. The 21 actual cypher processes comprise seven CLX committee nodes, seven Commons, and seven sidecars. Submission workers run inside sidecars. They use ordinary CLX gas, nonce, and admission rules and never directly modify CLX canonical state. Chain ID, genesis, and DEX ID remain as listed above; no init was performed.

The following regressions ran on the final source identified by each manifest. Counts are not added across overlapping packages/tests. The `r8-` log prefix names dictionary-fix test artifacts; the deployed release at this stage was r7.

| Test scope | Result and limitations | Raw logs and corresponding manifest |
|---|---|---|
| CLX duplicate-QC/proposal deadline, actual timer loop, concurrent updates | PASS(UNIT/race), 17 final top-level tests. Duplicate QCs did not prevent timeout with either healthy or missing heartbeat | `r7-clx-pacemaker-final-race.log`, `r7-clx-pacemaker-source-and-results.json` |
| Actual factory selected-certified query and full finance package | PASS(UNIT/race), including the outer query argument check | `r6-full-factory-query-race.log`, `r6-finance-full-race.log`, `runtime-final-source-and-results.json` |
| v5 dictionary, tampering, expansion limits, atomic partial writes, post-authentication updates | PASS(UNIT/race), 13 top-level tests. One optional historical-artifact comparison was SKIP | `r8-generation-dictionary-final-race-r2.log`, `r8-generation-dictionary-source-and-results.json` |
| Existing generation rotation, unfinalized branches, own orphan-vote retention | PASS(UNIT/race), three top-level tests | `r8-generation-retention-final-race.log` |
| Read-only copies of all seven real financial WALs | PASS(UNIT): two authenticated cold Opens per WAL with identical decoded state; 355.933 seconds. No original-data changes, Start, voting, or network transmission | `r8-current-seven-wals-dictionary-replay.log` |
| Independent dictionary golden vectors and fuzz | Golden regeneration matched. Fuzzing covered only 21.135 seconds and eight executions, so exploration was limited | `scripts/dex/wal_generation_dictionary_vectors.py --check`, `r8-generation-dictionary-fuzz.log` |
| Financial fixture and relay regressions | PASS(UNIT/ISOLATED), 40 top-level tests. Required sockets used an approved loopback-only namespace. The 225→214 result is the same-process fixture | `r8-final-financial-relay.jsonl` |
| core/vm, HotStuff, forkid | VM 47, HotStuff 101, and forkid four top-level PASS(UNIT). forkid `TestCreation` and `TestValidation` remain existing FAILs, with matching assertion output | `r7-final-core-vm-hotstuff-forkid-r2.jsonl`, corresponding `-summary.json` / `-source.json`. All 1329 source hashes unchanged before/after |
| Python normal deployment, initialization targets, financial runner, review-artifact boundaries | PASS(UNIT), 97 tests; not a live financial success result | `python-live-tests-r7.log` |

The first new-test failure incorrectly assumed an individual State limit of 64 KiB and remains in `r8-generation-dictionary-unit.log`. The test was corrected without changing the production 1 MiB limit, then rerun as above. An attempt using `-p1` did not apply Go build parallelism as intended and ran only the root package with “no test files”; it remains NOT_RUN in `r7-final-core-vm-hotstuff-forkid.jsonl`. The actual three-package run with `-p 1` is the `-r2` result. Earlier 600-second timeouts and r1–r4 LIVE failures are also retained.

## r7 leader handoff and incomplete work

`handoff-r7-independent-receipt.json` and its `.log` confirm that business ID `0c666009afc6ddd8319ad729e1f282d9bbd493b140910f1d3e48a817a3c2c034` was unsent in both outgoing leader 2 and successor 3 before the stop. After leader 2's DEX sidecar stopped, successor 3 submitted an ordinary CLX transaction using its own checkpoint payer `0x0c22394c5811594df9d7d1bef2aab24a33f6d032`, nonce 3. The Common parent remained running. The observed transition was view 1123→1124, but the journal does not record the sending view, so it does not prove that submission occurred within view 1124.

The target was checkpoint 65/hash `0xd7f81ca53fe7c5ee468178f5ec509bfe6a8eff97b72fd89d04f5bf61bef102d7`, transaction `0x757d2afe0748771149f88aa7cd6ffd1568f24e55494d54a19fee5e795b90faec`. Eighteen checks covered matching canonical block/successful receipt at CLX height 1593, normal admission metadata, independently computed checkpoint hash/business ID, and other fields. This record is limited to **PASS(LIVE: successor submission of the same business and observation of a successful receipt)**. Independent CLX FHS/MPT authentication and completion of all checkpoint/claim/conservation checks remain separate requirements. Restoration of all seven sidecars is also checked in the final-state record.

The complete financial runner had not finished. `live-drive-release-r7.log` stopped rather than accepting uncommitted evidence for an elapsed reward period; `live-drive-r7-held-rewards.log` ended with `certification deadline; durable action retained`. `live-drain-r7-restored.log` records replay HTTP 400. These remain FAILs; actions/nonces/balances and reward deadlines are not altered to force success. `r7-reward-hold-durable-observation.json` is a durable-state diagnostic without reauthentication and is not final financial accounting. Final custody, buckets, gas, unpaid amounts, and the DEX finalized/CLX accepted gap remain undetermined until authenticated final reconciliation is available.

Normal PoW is NOT_RUN. At the r7 Common deployment observation, MemAvailable was 22,376,332 KiB (about 21.3 GiB), swap was absent, and memlock was limited to 8 MiB. This cannot accommodate a 32 GiB DAG plus cache and running CLX/DEX processes. DAG/PoW rules and host protections were unchanged. The zero process count inside the sandbox in `resources-r6-prebuild.json` does not prove the target processes were absent; distinguish it from host-side deployment observation. CPU/RSS measured while heavy tests overlapped deployment is not release-performance data. C heap was not independently measured.

Full financial operation for at least 60 minutes, equal-load A/B/C comparisons, normal PoW generation/adoption/rewards, and WAN measurements remain NOT_RUN. Single dependency on CLX ingress `:8999`, general reward-inclusion fairness, full FROZEN recovery, and complete generation-archive bootstrap for late joiners remain unresolved/unimplemented. Independent reviews are in `leader-final-independent-audit.md`, `leader-r6-timer-independent-audit.md`, and `leader-r7-wal-dictionary-independent-audit.md`. The full Q0–Q5 and L01–L20 sets have not been marked PASS.
