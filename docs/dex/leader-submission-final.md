# DEX leader submission — deployment and handoff test results

2026-09-24 UTC. **The designated network now runs the change in which the DEX leader submits ordinary CLX transactions and its successor takes over unfinished business. Independent relay0/1 applications were removed from the normal PM2 configuration.** This change required no init, and none was performed. This is not a completion verdict for all of Q0–Q5, 60-minute continuous financial operation, or public operation.

Target: `vmi3365213`, `/root/work/cypher-FHS-D-ExchangeCore`, branch `FHS-D-ExchangeCore`. Starting and ending HEAD: `70862a71dfaf2b00694dc1354c6a64e9504d7db5`. Existing uncommitted/untracked implementation was preserved; no commit, push, reset, or clean was performed. Raw logs and review materials are under `/tmp/common-dex-leader-submit-yda0gkpo`. Log names below refer to its `results/` directory.

## Configuration changes

A submission worker was integrated into the existing Common-supervised `dex-validator` process. It derives leader eligibility from the HotStuff actor's current view and rechecks it before/after signing and immediately before sending. A view change cancels in-flight work. Network calls do not hold the consensus actor.

Each participant persists business IDs, signed transactions, nonces, and attempt states in `submission/` under its own DEX datadir. Standbys reconstruct work from authenticated finalized data and CLX state; on becoming leader they submit using **their own gas accounts and nonces**. Voting keys, predecessor submission keys, and recipient private keys are not transferred. Transactions already delivered by an old leader cannot be recalled, so CLX authentication, reservations, business idempotence, and nullifiers prevent duplicate payment.

`LeaderSubmission` is wired into each of the seven manifests. The three anchor/checkpoint/claim sender accounts separate purposes inside the process; they are not additional nodes. The old `dex-relay` CLI remains for historical fixture regressions, but is not registered in normal PM2 operation. `init.sh` targets were aligned with deployment that requires no independent relays; the script was not executed.

DEX OFF starts neither sidecar nor submission worker. CLX execution paths in the fixed committee and Commons perform bounded settlement verification without reexecuting DEX matching/risk/funding/liquidation.

See the [submission specification](leader-submission-spec.md), [storage format](wal-generation-dictionary-spec.md), and [QC-parent repair on recovery](leader-repair-followup.md). Earlier attempts and fixes remain in the [development record](leader-submission-status.md).

## Deployment and current generation

| Item | Final value |
|---|---|
| Normal release r8 SHA-256 | `e73798f290929dcaf8d611705403aa30b3ea3aa9b2f3e13e30c372ea3d140bfe` |
| Initially deployed binary SHA-256 | `7ad62239831d318cefbcc2115e267601b7d3ef590826ea0c64ca339731a3d623` |
| Chain ID | `10101919`, unchanged during this work |
| genesis.json SHA-256 | `06e879c0c1277008cc915b8a0ad4c73704f45119ec64cef875f503360d7d15ff`, matching the starting value |
| CLX genesis | `0xb2385f44d0adaf948957528f4e6c7c493fddf1311555c960d925b12dbe0f1626` |
| DEX domain ID | `0xae8b961b841fb8b270e87639314f2881c8ac3c6154480eb96b44296ad9c1be62` |
| Financial schema / epoch | 6 / fixed DEX epoch 1; seven participants and threshold five retained |
| PM2 | 14 applications: `cypher0..6`, `cyphermine`, `cypherdex1..6`; all online |
| Actual node processes | Seven CLX committee nodes + seven Commons + seven Common-owned DEX sidecars = 21; every executable matches the r8 hash |
| Independent relay processes / PM2 entries | 0 / 0; the final PM2 save contains only the 14 applications |

The normal Makefile built into a dedicated release destination, followed by a switch to the new executable. Running executables were not truncated. The seven Common/sidecar pairs were updated using the same DBs; `cypher0..6` then restarted one at a time. Production changes from r7 to r8 affect only authenticated DEX parent-data retrieval, with no difference in CLX consensus/execution rules. Each stage retained the remaining committee, restored existing roles, and checked hash/root/receipt/gas for the same historical block. The stop test stopped only predecessor DEX 2's sidecar while preserving its Common parent's CLX ingress.

Evidence: `release-build-r8.log`, `r8-build-source.json`, `r8-build-final-verification.json`, `commons-rolling-r8-result.json`, `clx-rolling-r8-result.json`, `live-final-r8-post-restart.json`, and `pm2-save-r8-final.json`. The historical O26 verdict under the restrictions then in force was retained. This work's hash changes are separately recorded as authorized deployment.

## Live-network handoff

Stopping DEX leader 2's sidecar caused the remaining six participants to move from view 1123 to 1124 and leader 3. The successor submitted the same business from its own account; neither participant had sent it before the stop.

| Identifier | Value |
|---|---|
| Business ID | `0c666009afc6ddd8319ad729e1f282d9bbd493b140910f1d3e48a817a3c2c034` |
| Checkpoint | 65, `0xd7f81ca53fe7c5ee468178f5ec509bfe6a8eff97b72fd89d04f5bf61bef102d7` |
| Successor gas payer / nonce | `0x0c22394c5811594df9d7d1bef2aab24a33f6d032` / 3 |
| Ordinary CLX transaction | `0x757d2afe0748771149f88aa7cd6ffd1568f24e55494d54a19fee5e795b90faec` |
| CLX inclusion block | 1593, `0xac4bc62b0c253522ce81a8f13e0cd32122d6ab83776aadbccac02f75918b257a` |
| Receipt / gas used | success / 12,179,012 |

`handoff-r7-independent-report.md` contains 18 independent payload/business-ID/receipt checks. Subsequent final accounting reauthenticated heights 1080→1904, including this block, using CLX FHS finality evidence linked from genesis and account/storage MPT proofs. The monitor also shows an unsent→complete transition during successor view 1124, but the journal itself has no signed proof of the sending view. Receipt consistency was checked; independent receipt-trie reconstruction was not performed.

On recovery, participant 2 held a QC from a different view at the same height and lacked the child's exact ParentQCID. r8 refetches the selected chain's parents through bounded traversal from an authenticated finalized prefix. Wire format, signature threshold, and proof/queue limits remain unchanged; votes/locks/QCs/WAL are not deleted. After deployment, **all seven recovered to certified 166 / finalized 165 without additional financial actions**. Recovery for the general case requiring a different QC of an archived anchor remains unimplemented and fails closed.

## Final financial reconciliation

`accounting-r8-post-restart-result.json` reports **PASS_AUTHENTICATED_LEDGER**. For heights 1080→1904 of the same run, it reconciled native balance changes across 42 accounts, all buckets, gas, Common rewards, burn, and existing CLX issuance. All seven DEX finality proofs and roots also matched. This is a BTC/CLX test market with a synthetic Oracle, not verification of a real Oracle or BTC/USD.

| Account | Integer amount in smallest CLX units |
|---|---:|
| Total deposits into custody | 225200000000000000000 |
| User withdrawals | 10000000000000000 |
| Total DEX reward payments (seven recipients) | 1000000000000000000 |
| Final custody | 224190000000000000000 |
| trader T | 200189200000000000000 |
| fee F | 800000000000000 |
| support S | 19000000000000000000 |
| insurance I | 5000000000000000000 |
| Unimported U / withdrawal reserve W / reward reserve R / Z / surplus | 0 each |
| Gas expenditure across all CLX transactions | 3916394944000000000 |
| Of that, anchor/checkpoint/claim and replay gas | 3913022344000000000 |
| Common RPC rewards | 783278988800000000 |
| burn | 3133115955200000000 |

**225.2 − 0.01 − 1 = 224.19 CLX**. Custody did not pay gas. The 1 CLX reward in this run came from support; this does not establish fee-only profitability. Reward period 6 closed; period 7 was held because participation evidence had not entered common state before its deadline. No deadline relaxation, retrospective signing, or unproven payment was used. The existing 225→214 fixture remained a regression PASS for its separate input sequence.

Operations: four trader deposits, one support deposit, one insurance deposit, 119 anchors, 165 checkpoints, 16 exact checkpoint replays, eight claims, one claim replay, and 83 ordinary transfers. Existing CLX issuance of `40500000000000000000000000` smallest units was reconciled separately. This introduced no additional issuance for DEX.

A paid withdrawal claim was replayed from another owned account in transaction `0x179a2e66ace49fce3d39fbb31a62fe420727345659973fe0b37ca2d41bd698b7`. The durable nullifier matching claim leaf `0x05d6bc56a84557251e3e890eef80b749dfa8fc77673ae80b1d66b28bddcdff99` and replay event were verified. Custody, all buckets, and additional payment changed by zero. Gas of 384,672 was paid normally. See `r8-live-paid-claim-replay.json`.

The initial audit failed before submission because it incorrectly treated a nullifier as boolean 1. Production already stored the claim leaf hash; accounting/state were unchanged while the Python auditor and independent check were corrected. The next attempt also stopped before submission because the trader helper restricted sender purpose. The restriction was retained, and the replay above used the normal signing path of an existing owned test-funds account. Failed r2–r4 logs and successful r5 are preserved.

## Final state

The final authenticated CLX height is **1904**, hash `0x540728a4af2fabfcc5d91448ec40a1c835efed7bf4e5b6dd1c2df5eba63d2391`, state root `0x0397095895117270217de27d5e7bf02fd8cd2b56dc21bdfb59ffd661d04351f9`. All 14 CLX execution processes agreed on hash/root/receipt/gas and reported heavy-engine `Instances/Actions/InboxImports = 0/0/0`. This does not mean settlement verification and storage have zero additional cost.

All seven DEX participants are active: certified 166 / finalized 165 / CLX accepted 165. The finalized root is `0xf3a6e8fee32a2475a53c8571f4da878d50f2b9aaa181d73580da23f781413eaa`, checkpoint hash `0x48ca0224585135c7b4fd70e7b049ace1a37a300c12a2f9c513ee14c6c2475ece`. The finalized-but-unsettled gap is zero. Tail sequence 166 is a certified-only Noop and is excluded from settled completion. No refunds or loss-allocation rules were added to FROZEN.

The final worker observation found zero unfinished business and zero reserved, unconsumed nonces. Journals retained 220–246 completed history entries each; their row counts were not reset to zero. `final-submission-residuals.json` reports worker authentication state and ordinary RPC nonce observations. Independent final financial authentication is provided separately by the accounting evidence above.

All seven participants reached storage generation 8, with 21–29 hot records and approximately 7.5–7.7 MB of archives, within the 256 MiB archive budget; storage blocked=false. Nothing was deleted at the expense of signing safety or history. However, the participation-evidence collector approached its 2048-entry cap, so new financial input stopped and settlement drained. This does not complete all storage-growth work or 60-minute continuous operation. Remaining transport frames numbered 27–56 in the observation; these are not unpaid claims.

After all CLX committee nodes restarted with their same DBs, ordinary one-smallest-unit transfer `0x9831908b5022a0d8474437660e9bae1ef7d77273cfa55ac5ed2f593901d31836` finalized at height 1904. See `post-r8-restart-smoke.json`. No PM2 application was intentionally left stopped. Mining was false on all seven Commons. The committee's mining=true indicates its existing committee service was running, not successful normal PoW.

## Regressions and incomplete work

| Scope | Result | Raw logs and limitations |
|---|---|---|
| Leader submission and handoff using the successor's own account | PASS(LIVE) | `handoff-r7-independent-*` and final authenticated accounting |
| Same-DB recovery of all seven, deployment to all 21 processes, no independent relay | PASS(LIVE) | `commons-rolling-r8-result.json`, `clx-rolling-r8-result.json`, `live-final-r8-post-restart.json` |
| CLX acceptance through 165, eight claims, no increase on replay, post-restart transfer | PASS(LIVE) | `accounting-r8-post-restart-*`, `r8-live-paid-claim-replay.json`, `post-r8-restart-smoke.json` |
| Parent-QC repair, cold restart, signature/chain tampering | PASS(UNIT/race) | `r8-replication-parent-repair-source-and-results.json` |
| Parent repair with a busy child retained; wrong key/epoch/partial/out-of-order input over real TLS | PASS(ISOLATED/race) | `r8-repair-tls-order-race.log` |
| All eight PoW/RPC/DEX combinations through normal CLI/API; integrated-worker lifecycle | PASS(ISOLATED) | `r8-final-eight-roles-cli-lifecycle-*`; not normal-size DAG/nonce exploration |
| Dictionary WAL, retention, atomic partial writes, two cold restorations of each of seven actual WAL copies | PASS(UNIT/race) | `r8-generation-dictionary-*`, `r8-generation-retention-final-race.log`, `r8-current-seven-wals-dictionary-replay.log`. One optional historical-artifact comparison was SKIP |
| Financial 225→214 fixture and relay | PASS(UNIT/ISOLATED) | `r8-final-financial-relay.jsonl`, 40 top-level tests; separate from live accounting |
| CLX duplicate-QC/proposal deadline and actual timer loop | PASS(UNIT/race) | `r7-clx-pacemaker-final-race.log`, 17 top-level tests; existing 516-second deadline unchanged |
| core/vm / HotStuff / forkid | PASS(UNIT) 47 / 101 / 4; two existing FAILs | `r7-final-core-vm-hotstuff-forkid-r2*`; existing `TestCreation`/`TestValidation` failures retained |
| Python runner, deployment, accounting audit | PASS(UNIT) | `python-all-final-nullifier-r8.log`, 114 tests; source correspondence in `final-source-verification-r8.json` |
| Normal PoW generation, delivery, adoption, rewards | NOT_RUN | MemAvailable about 22 GiB, swap 0, memlock 8 MiB: insufficient for a 32 GiB DAG plus cache and running CLX/DEX. OS limits and PoW rules unchanged |
| At least 60 minutes of mixed operation, A/B/C performance, WAN, Hyperliquid comparison | NOT_RUN | Neither elapsed time nor block count substitutes for these tests. Performance acceptance remains undetermined |

Changed final-production paths were retested; regressions for unchanged areas retain source-hash correspondence. See `r8-build-source.json`, per-test source/result manifests, and `final-source-verification-r8.json`. Fuzzing covered only about 21 seconds and eight executions. Go race checks executed paths and does not prove safety of the entire C BLS library. The three known internal/ethapi failures were not rerun here. Earlier LIVE failures, test timeouts, and incorrect-fixture FAILs were not overwritten.

Final observed MemAvailable was 23,053,552 KiB; the simple RSS sum for 21 processes was 3,663,268 KiB. This is neither unique physical consumption excluding shared pages nor peak usage. Observed maxima: calldata 65,220 bytes, DEX finality proof 2,031 bytes, 32 source headers, MPT eight nodes/2,348 bytes, claim depth three. These are values observed in this run, not results of increased limits. Wall-clock, C heap, and equal-load A/B/C costs were not measured.

All workers depend on Common `:8999` for CLX ingress/proof retrieval; this endpoint remained available during the leader handoff. Ingress redundancy including parent-Common failure, general reward-inclusion fairness, full FROZEN recovery, complete financial snapshot/archive bootstrap for late joiners, and long-term participation-evidence retention remain incomplete. Independent relays or relaxed authentication were not used to bypass them.

## Reproduction materials

Final review archive: `/tmp/common-dex-leader-submit-yda0gkpo/final-review/reviewable-leader-submission.tar.gz`. It includes tracked patches, new untracked source/specifications, source hashes, secret-free configuration, raw test/deployment/accounting logs, and reproduction scripts with fixed targets. Actual private keys, keystores, runtime DB/WAL, distributed binaries, and unlock scripts are excluded. Starting identity/diff listings and intermediate implementation manifests are retained. An intermediate manifest is not described as a complete pre-work capture.

The archive does not automatically redeploy or initialize anything. Final-init preparation retains the existing explicit-target procedure, but init was not performed. QCs are committee-trust finality evidence, not computational Validity Proofs. DA roots do not guarantee retrieval, and seven participants on one host do not establish seven independent operators or WAN distribution.
