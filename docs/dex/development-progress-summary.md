# Common-participating perp DEX — completed work, incomplete work, and next steps

Created: 2026-09-24. Target: `CypherTroopers/cypher`, branch `FHS-D-ExchangeCore`, host `vmi3365213`, workspace `/root/work/cypher-FHS-D-ExchangeCore`.

**This development version has demonstrated perp trading and CLX settlement with test CLX on the designated live network. A frontend UI, permissionless DEX committee admission, long-term operation, and production readiness are not complete.**

This document consolidates development records, actual source, and saved test results. The latest process observation used here is **2026-09-24 01:07:33 UTC**; preparing this document did not rerun network tests. HEAD remains `70862a71dfaf2b00694dc1354c6a64e9504d7db5`, with the implementation in uncommitted changes. HEAD alone does not identify these artifacts.

Results distinguish `PASS(LIVE)` for the designated PM2 network, `PASS(ISOLATED)` for isolated networks, and `PASS(UNIT)` for component tests. Historical successes are not automatically successes for new source or generations.

## 1. Completed work

### 1.1 Design, implementation, and verified behavior

| Item | Completed work | Verification scope and evidence |
|---|---|---|
| CLX/DEX execution separation | Heavy order, position, risk, Funding, and liquidation work runs on Common-side DEX. CLX performs bounded proof verification, native custody, deposits/withdrawals, and reward settlement. No WCLX or additional DEX issuance was introduced. | Latest LIVE observation: engine instance/action/inbox-import counters were zero on all 14 CLX execution processes. Proof, accounting, and storage overhead still exists. [Latest report](leader-submission-final.md) |
| Optional roles and normal startup | PoW, Common RPC, and DEX are separate; DEX defaults OFF. Existing Common supervises its DEX sidecar through `--dex.validator --dex.config ...`. Voting keys, RPC signers, gas accounts, and reward recipients are separate. | All eight normal CLI/API combinations, start/stop, and restart passed in isolation. This is separate from successful normal PoW nonce exploration. [Integration record](integration-status.md) |
| Dedicated DEX HotStuff/FHS and real transport | Implemented a DEX committee, consensus state, DB/WAL independent of CLX, plus real TLS authenticating registered identity/domain/epoch. | Real-socket regressions and operation on the designated PM2 network. Currently seven registered members, threshold five, fixed DEX epoch 1; not public admission. |
| Financial and independent models | Implemented FIFO positions, cash/PnL, fees, Funding/dust, margin, liquidation, and deficits for the BTC/CLX test market; checked independent arithmetic-model and codec golden vectors. Later integration did not replace the accounting formulas. | Financial fixtures, unit tests, isolated financial integration, and normal paths in the latest LIVE run. Stale-price and insurance-shortfall FROZEN behavior has limited component/isolated coverage. [Financial specification](finance-spec.md), [integration record](integration-status.md) |
| Separate deposit IDs and finality evidence | DepositID does not self-reference the containing block hash. Ordinary transactions update custody and inbox. DEX credits each continuous range once, after verifying both CLX FHS finality and account/storage MPT inclusion proofs. | Rejection tests for unfinalized/duplicate deposits, orphan proposals, and altered metadata/owner/amount/domain, plus normal CLX financial integration. [Deposit specification](integration-deposit-spec.md) |
| Settlement through ordinary CLX transactions | Connected deposit, anchor, checkpoint, and claim to signed TX→Common RPC/admission→TxQUIC→block execution→FHS finality→storage/sync. Callbacks do not change CLX canonical funds. | PASS(LIVE): normal nonce/gas, purpose-specific reservations, nullifiers, recipient binding, and no additional value on replay. Component-only scope is identified for outer revert/OOG and related checks. [Native TX specification](native-tx-spec.md) |
| Incremental authenticated-anchor updates | Implemented rolling anchors in both directions: DEX authenticating CLX deposits and CLX authenticating checkpoint CLX reference points. Multiple bounded authenticated updates cross the 64-ancestor/64-block restriction. | Isolated G3 repeated through CLX 749 with staged catch-up after downtime and later settlement. Latest LIVE run processed 119 anchors. RPC latest does not become a new trust root. [Rolling specification](rolling-anchor-spec.md), [G3 record](continuous-status.md) |
| CLX/DEX finality fixes | Fixed QC-before-body repair, canonical root/head durability, empty trie-journal path resolution, and separation of local/genesis settings. Added bounded DEX finality evidence using actual parent-QC history and prevented duplicate QC/proposal delivery from indefinitely extending CLX timeouts. | Focused regressions, selected crash boundaries, and normal-network observations. Not a guarantee for every power-loss/disk-failure boundary. [Finality fixes](finality-fix-status.md), [latest report](leader-submission-final.md) |
| Leader submission and handoff | Integrated submission into existing DEX validators. The current leader sends; successors restore unfinished work from authenticated finalized data and durable records, using their own gas accounts/nonces. Old signed transactions remain recorded. | PASS(LIVE): leader 2 stop→leader 3 takeover, successor submission of checkpoint 65, and CLX acceptance. Independent `relay0/1` applications were removed from normal PM2. [Submission specification](leader-submission-spec.md) |
| Storage-generation rotation and same-DB recovery | Implemented authenticated prefixes, archives, hot WAL, and exact-data dictionary encoding while retaining votes/locks/QCs/unpaid rights. Also repaired the path where different-view QCs at one height prevented a recovering node from obtaining a child's parent. | Latest LIVE: all seven reached storage generation 8 and recovered from the same DBs to certified 166/finalized 165. Component tests cover atomic writes, tamper rejection, and retention. This does not resolve every storage cap. [Storage specification](wal-generation-dictionary-spec.md), [parent-QC repair](leader-repair-followup.md) |
| Deterministic reward decisions | Fixed decisions diverging for the same parent/proposal solely because local collectors held different evidence. Decisions use participation records included in common state before the deadline. | Covered by focused tests; general inclusion fairness is not complete. [Reward audit](continuous-g0-rewards.md) |
| Deployment, startup configuration, init targets | Built/deployed normal releases, restarted target applications with the same DBs, and verified running executables. `init.sh` includes additional Common/DEX runtime paths, preserves nodekeys/keystores and keys outside runtime, and uses explicit targets without creating data backups. | Latest configuration: 14 PM2 applications, 21 node processes, zero independent relays/orphans. The latest leader-submission change neither performed nor requires init. [init.sh](../../init.sh), [deployment record](leader-submission-final.md) |
| Reproduction materials | Saved specifications, independent golden vectors, runners, source manifests, tracked/untracked changes, raw logs, and historical FAILs. | Review archive excludes private keys and operational DB/WAL. No remote push was performed. |

### 1.2 Financial results — keep separate runs separate

| Run | Result scope | Outcome |
|---|---|---|
| Original financial fixture / normal CLI financial integration | PASS(UNIT) / PASS(ISOLATED), with separate execution evidence | `225 − withdrawal 10 − rewards 1 = custody 214 CLX`. Normal CLI run: CLX 69, checkpoint 18, eight claims. [Record](integration-status.md) |
| Rolling-anchor/stop-restart G3 attempt 15 | PASS(ISOLATED), 1546.32 seconds; not a 60-minute test | `345 − withdrawals 40 − rewards 10 = custody 295 CLX`. CLX 749, DEX finalized 109 = CLX accepted 109, 72 payments. Eighteen unsettled items created during the CLX stop drained after same-DB restart. [Record](continuous-status.md) |
| Latest designated-PM2-network leader-handoff run | PASS(LIVE), authenticated ledger reconciliation across CLX 1080→1904 | `225.2 − withdrawal 0.01 − rewards 1 = custody 224.19 CLX`. DEX finalized 165 = CLX accepted 165, eight claims; replay of a paid claim from another sender produced zero additional payment. [Record](leader-submission-final.md) |

Final values for the latest LIVE run follow. The 1 CLX reward came from support, not demonstrated fee-only profitability.

| Account | Integer amount in smallest CLX units |
|---|---:|
| custody | 224190000000000000000 |
| trader | 200189200000000000000 |
| fee | 800000000000000 |
| support | 19000000000000000000 |
| insurance | 5000000000000000000 |
| Unimported deposits / withdrawal reserve / reward reserve / Z / surplus | 0 each |
| Gas expenditure across all CLX transactions | 3916394944000000000 |
| Common RPC rewards | 783278988800000000 |
| burn | 3133115955200000000 |

Native balance changes across 42 accounts were reconciled. Gas is separate from custody. Existing ordinary CLX issuance was also reconciled separately. Receipt consistency checks do not constitute independent receipt-trie reconstruction, which was not performed.

### 1.3 Latest verified deployment and state

- Chain ID: **10101919**. CLX genesis: `0xb2385f44d0adaf948957528f4e6c7c493fddf1311555c960d925b12dbe0f1626`.
- DEX domain: `0xae8b961b841fb8b270e87639314f2881c8ac3c6154480eb96b44296ad9c1be62`. Seven registered members, threshold five, fixed epoch 1, financial state 6.
- Running r8 binary SHA-256: `e73798f290929dcaf8d611705403aa30b3ea3aa9b2f3e13e30c372ea3d140bfe`. All 21 observed processes matched.
- PM2: 14 online applications, `cypher0..6`, `cyphermine`, `cypherdex1..6`. Seven CLX committee nodes + seven Commons + seven Common-owned DEX sidecars = 21 processes. Zero separate relay nodes.
- Authenticated CLX reconciliation height: **1904**, hash `0x540728a4af2fabfcc5d91448ec40a1c835efed7bf4e5b6dd1c2df5eba63d2391`, root `0x0397095895117270217de27d5e7bf02fd8cd2b56dc21bdfb59ffd661d04351f9`.
- DEX: **certified 166 / finalized 165 / CLX accepted 165**. Finalized-but-unsettled gap zero. Tail 166 is a certified-only Noop, excluded from settled completion.
- Submission workers: zero observed unfinished business and zero reserved, unconsumed nonces. Completed history remains in durable journals.

Evidence: [latest deployment/financial report](leader-submission-final.md), [authenticated final accounting](/tmp/common-dex-leader-submit-yda0gkpo/results/accounting-r8-post-restart-result.json), [process observation](/tmp/common-dex-leader-submit-yda0gkpo/results/live-final-r8-post-restart.json), and [process ownership](/tmp/common-dex-leader-submit-yda0gkpo/results/final-process-ownership-r8.json). Earlier records of “16 applications stopped awaiting init,” “two independent relays,” or “rolling anchors unimplemented” describe their respective historical states, not the latest state.

## 2. Incomplete work

| Item | Status | Remaining work and limitations |
|---|---|---|
| Perp trading frontend UI | NOT_IMPLEMENTED in this development work | Wallet connection, order book/order entry, positions, PnL/history, deposits/withdrawals, and distinct finality-stage displays. A UI connecting to existing APIs remains to be built. |
| End-user API connectivity | Incomplete | Current order API is for loopback use. User-facing connectivity needs wallet signatures, exposure policy, authentication, rate limits, reconnection, and data-feed integration/validation. |
| Permissionless DEX committee membership | NOT_IMPLEMENTED | Only seven preregistered members can vote. `--dex.validator` expresses intent to participate; it does not automatically grant voting rights. Selection, admission/exit, Sybil resistance, and epoch/committee transitions are incomplete. |
| Continuous operation across storage caps | Partially implemented; incomplete | Hot-WAL/authenticated-archive rotation works, but approaching the collector's 2048-entry cap stopped new financial input in the latest run. Other archive/height/history budgets are finite; indefinite operation is not guaranteed. |
| Reward-period progress and general inclusion fairness | Unresolved | Period 7 in the latest run was held because participation evidence was not included before the deadline. Local-evidence-dependent decision divergence is fixed, but delivery/inclusion/remedies for every legitimate participant are incomplete. |
| Redundant CLX submission ingress | NOT_IMPLEMENTED | Seven workers use the same Common `:8999`. Leader-sidecar failure was tested, but losing its parent Common and ingress causes submission to wait. |
| General recovery with an alternate archived parent QC | NOT_IMPLEMENTED | The hot-region missing-parent path is repaired. General cases requiring a different QC of an archived anchor remain fail-closed. [Boundary](leader-repair-followup.md) |
| Financial bootstrap for new DEX participants | Incomplete | Existing registered participants can recover from the same DB and isolated snapshot tests exist. Complete third-party authentication/bootstrap from the current financial snapshot/archive generations remains incomplete; it is distinct from public admission. |
| Full recovery from FROZEN, insurance shortfall, or permanent DA loss | Unimplemented / specification unsettled | Safe stops and liability retention have been tested. Emergency prices, open positions, loss allocation, entitlement finalization, safe resumption, and withdrawals remain unspecified/incomplete. Uniform refunds of old balances are not a substitute. |
| Full fault matrix on the latest configuration | Some items NOT_RUN | Historical isolated 5/2 and 4/3 partitions or full CLX/DEX stops do not establish all combinations on the latest PM2 configuration. Cases beyond selected LIVE stop/recovery checks need revalidation. |
| At least 60 minutes of mixed financial operation | NOT_RUN | A single same-generation run without init covering fresh deposits/trading/Funding/rewards/settlement, at least two storage rotations, and stop/recovery remains incomplete. |
| A/B/C load comparison and performance verdict | NOT_RUN | Compare no DEX / DEX / increased DEX under equal ordinary CLX arrival load, with latency quantiles, completion rate, backlog, and resource costs. Hyperliquid superiority has neither been achieved nor established. |
| Normal-size PoW and concurrent DEX performance | NOT_RUN | Observed environment: about 22 GiB MemAvailable, swap 0, memlock 8 MiB. Insufficient for a normal 32 GiB DAG plus cache and running CLX/DEX. IsMining and eight-role tests are not substitutes. Known PoW issues including Candidate.HashNoNonce remain separate. |
| WAN, independent operators, hardware worst-case load | NOT_RUN | Seven processes on one host are not seven independent operators. Sufficient maximum-proof calibration, independent C-heap measurements, and all disk/power-cut boundaries remain uncovered. |
| Existing regression defects | FAILs remain | Two core/forkid failures: `TestCreation`/`TestValidation`. Three known internal/ethapi failures are also unresolved and were not rerun on latest r8. Historical RPC timeouts remain recorded. |
| Production markets and operation | Includes undesigned / unapproved / unimplemented items | Real Oracle, external market makers/liquidity, USD-denominated CLX collateral, production fees/capital/reward funding/upgrade authority/operational SLOs, and independent review are needed. |
| Computational Validity Proof | Not selected or implemented | The current scheme trusts an authenticated DEX committee. A QC is not an independent proof of computation correctness; a DA root is not a retrieval guarantee. |

Historical O26 binary mismatch remains a historical FAIL. Subsequent user-authorized deployment/hash changes are separate facts; the earlier restriction does not prohibit current ordinary deployment. Intermediate FAILs, post-fix PASSes, and unexecuted work are not combined into an “all tests PASS” claim.

**A UI can make perp trading usable with the currently registered committee and test CLX. Completing the UI alone would not complete a production service or permissionless DEX.**

## 3. Next steps

The following is a proposed development order. This document does not itself execute deployment, load tests, or public admission.

1. **Prepare the next tests from the latest state.** On resumption, recapture source manifests, actual executables, PM2, genesis/domain, finalized height, unpaid/unsettled amounts, nonces, and storage usage. Use current chain ID `10101919` and the owner's `genesis.json`; do not change chain ID without authorization. Leader submission does not require reinitialization.

2. **Resolve storage and reward-period blockers.** Classify collector, hot-WAL, archive, anchor, checkpoint/inbox, and submission-journal caps. Connect timely evidence inclusion, held-period handling, and authenticated storage rotation while preserving legitimate evidence, unpaid rights, nullifiers, and signing-safety state. Test admission stops and resumption at capacity; init or merely raising limits does not establish success.

3. **Complete recovery and submission continuity.** Implement/verify archived-parent-QC authentication, current financial snapshot/bootstrap, and redundant CLX ingress. Keep submission in the DEX leader; handoff including Common-parent failure must preserve authentication and settle outstanding work through ordinary transactions. Do not restore a separate relay node type.

4. **Build a test frontend UI.** This can proceed alongside backend work. Initially label BTC/CLX, synthetic Oracle, and test CLX explicitly. Connect wallet access, deposits, orders/cancellation, positions/PnL/Funding, withdrawals, and reward history to existing APIs. Display ACK / DEX certified / DEX finalized / CLX accepted / claim paid separately. Validate signatures, nonces, errors, and reconnection without requiring server custody of private keys. External publication is a separate decision.

5. **Complete continuous-operation and fault tests on the designated PM2 network.** Combine at least 60 minutes of mixed finance without init, at least two real-config storage rotations, one/two DEX stops, continued CLX progress with all DEX stopped, post-CLX-stop settlement, leader changes, old/duplicate claims, cold restart, and late DEX-OFF sync. Stop new input at the end, finalize the relevant tail, and independently reconcile every account, bucket, gas, Common reward, burn, and residual.

6. **Evaluate existing regressions and additional load.** Resolve forkid, RPC ingress, and known PoW issues by cause under the current specification. Use normal releases for equal-CLX-arrival-load A/B/C measurements; save p50/p95/p99, completion/rejection rates, backlog, CPU/RSS, disk growth, and full proof bytes/gas. Stop new load when resources deteriorate. Test normal PoW separately only when its resource requirements can be met.

7. **Specify and implement permissionless Common participation.** Define public registration, selection, capacity, Sybil resistance, entry/exit, liability periods, epoch/committee changes, and CLX authentication of historical committees. Do not make PoW, bond amounts, or delegation mandatory without approval. Test HotStuff leader rotation separately from committee membership changes.

8. **Establish production market, recovery, and security gates.** Settle real Oracle/liquidity, collateral/settlement units, liquidation/deficits/FROZEN recovery, reward funding, production fees, operational powers/limits, monitoring, and independent review. USD-denominated products and computational proofs remain separate design decisions. Do not claim public real-fund readiness or performance superiority beforehand.

9. **Leave post-completion init and verification to the owner's decision.** When needed, explain its reason, targets, and impact on current liabilities/claims. Follow the owner's instruction to avoid unnecessary runtime backups during init while preserving nodekeys and designated keystores. With the same chain ID, changing only the DEX domain does not prevent ordinary CLX signed-transaction replay; verify procedures preventing reintroduction of old signed transactions/nonces/journals. Do not report init as performed before it occurs.

Continuation references: [latest live-network results](leader-submission-final.md), [historical integration acceptance matrix](acceptance-matrix.md), [rolling/G3 acceptance matrix](continuous-acceptance-matrix.md), and [designated PM2 development acceptance matrix](live-acceptance-matrix.md). Interpret each against its date, source, and test environment; do not present old unimplemented/stopped states as current.

Latest review materials: `/tmp/common-dex-leader-submit-yda0gkpo/final-review/reviewable-leader-submission.tar.gz`. This existing archive contains source manifests, raw logs, and secret-free configuration and predates this document. Preserving reproduction evidence is separate from making runtime-data backups when the owner runs init.
