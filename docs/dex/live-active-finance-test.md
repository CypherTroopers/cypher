# Real PM2 financial test after user reinitialization — 2026-09-23

The real-network financial end-to-end result is **FAIL (DEX finality liveness)**. Normal CLX deposit inclusion succeeded, but DEX reached certified 15 / finalized 0, and CLX accepted 0. No change was made to pay on QCs treated as finality. See the [finality investigation](live-finality-gap.md) for the cause and deterministic reproduction.

Scope: `vmi3365213`, root, `/root/work/cypher-FHS-D-ExchangeCore`, branch `FHS-D-ExchangeCore`. Starting and ending HEAD: `70862a71dfaf2b00694dc1354c6a64e9504d7db5`. Chain ID **10101919** was unchanged. This run did not modify genesis, init.sh, or ordinary cypher binaries, and performed no init, data deletion, commit, or push.

## Operations performed

Verified that all 14 CLX instances returned the same new genesis/hash/root after the user's restart. Enabled optional DEX role selection and restarted only the 7 explicitly named Common instances. Initial startup failed because the dedicated DEX parent directory was missing. Created the empty parent directory and retried with the same settings, confirming startup of 7 DEX sidecars. No existing WAL was deleted.

PM2 targets were `cyphermine`, `cypherdex1`–`cypherdex6`, `cypherdex-relay0`, and `cypherdex-relay1`. Committee nodes `cypher0`–`cypher6` were not stopped/restarted during this run. Each Common supervises one sidecar; PM2 does not manage the sidecars a second time. Ordinary CLX/Common 14 + DEX 7 + relay 2 = **23 cypher role processes**. This is one host with loopback TLS, not WAN or 7 independent operators.

Funded test wallets with a total of 254 CLX from existing owned test accounts using normal signed TXs / Common RPC / admission / TxQUIC. Of this, 225 CLX was held in 4 native custody deposit TXs (trader 100+100, support 20, insurance 5). No direct live StateDB balance edits, additional issuance, or deductions from existing PoW/RPC rewards occurred. Relay senders and fund recipients are distinct.

The short runner first stopped on a logging-function `kind` argument collision, then resumed from the same signed actions/journal. It next stopped on participation retrieval conditions. When evidence from different views exists at the same height, all active participants need not have voted for the same target; the runner's unanimity requirement was excessive. The current helper/runner selects a known certificate set for the same formally verified target, preserving authentication by at least 5 collectors, deadlines, and canonical order. This is not completed general fairness. A LIVE financial rerun after the runner fix was not performed because of the finality issue below.

## Why finance stopped

The actual parent QC chain at heights 1–15 had views `56,58,118,121,123,126,129,132,135,137,139,141,143,145,148`. No pair meets the FHS finality condition requiring consecutive final parent/child views. Test inputs were spaced at least 5 seconds apart against a 4-second timeout, so low load failed to produce finalizing descendants.

Furthermore, the existing proof limit is **8 descendants / 16384 bytes**. Finalizing all 15 unfinalized heights later would make the oldest proof exceed this limit. Shortening input intervals alone cannot recover existing state. This was reproduced in component tests using valid QCs and timeouts. Do not work around it by expanding limits, treating a single QC as finality, or rolling back historical WALs.

Resolution requires a proof scheme that authenticates and stores a shared finalized base over bounded intervals, plus input control before unfinalized history reaches the limit. The current handler does not implement this. No improvised new specification was registered for fund processing. **Init alone does not fix this defect, and no reinitialization was performed in this run.**

## Failure-test scope

After the financial prerequisite failed, stopped the 2 relays by name while retaining nonces, signed TXs, and unfinished jobs. Then sent SIGTERM only to the 7 DEX sidecars after checking ownership, PID start ticks, and executable hashes. Common parents and RPC 8999 remained running; observed inclusion of a normal signed 1-atom transfer and CLX height 1119→1121. The finally path restarted the 7 Common instances with the same DB/manifest/binary and checked identical certified checkpoints, disappearance of old parent/child PIDs, and unchanged datadir inodes. Final reconciliation using independent CLX evidence appears in the accounting results below.

This tests ordinary CLX progress during a DEX outage and recovery of existing records from the same DB; it does not settle outstanding finance or repair finality. Financial progress with 1/2 nodes down, financial settlement after full CLX shutdown, 2 storage-generation rotations, A/B/C load, and 60-minute mixed finance are BLOCKED/NOT_RUN because prerequisites failed.

## Authenticated generation and execution boundaries

- CLX genesis: `0xa4a61fa952509cde79c14e152702a1d7dea1cc0320b4552566b2efb9e4a575de`
- Genesis root: `0xd3e0fd99e2cbcafe3ca718d616b73ea47664153c0ffc01888c3cedef893a33f0`
- DEX ID: `0x433b712c48506710a611d48e351ff827d00e64941fff9c085817c266585af497`
- DEX epoch 1 / 7 registered participants / quorum 5 / configuration 4 / financialstate 6 / dataschema 5.
- SHA256 of the ordinary release and all 23 executing binaries: `76d2d104bb101451b2729cd1f6c55374350ea9ee297dbf2e5f5d27ab70f5ad1c`.
- Heavy engine instance/action/inbox-import counters are all 0 for the 7 CLX committee nodes and 7 Common parents. Each DEX sidecar has 1 instance. This does not claim zero proof-verification/storage/RPC load.
- Normal DAG 32 GiB + cache 512 MiB versus observed MemAvailable about 23.98 GiB. Normal PoW search/candidate delivery/adoption/rewards are NOT_RUN. Common PoW was not automatically started. Committee mining=true is not PoW success.
- Product: BTC/CLX with a synthetic Oracle. This run did not complete LIVE orders/trades/rewards/withdrawals end to end.

## Regressions and evidence

The existing `TestNativeCLXFinancialFHSScenario` reran PASS(UNIT): 7 FHS managers, 18 financial blocks, 225−10−1=214 CLX, matching buckets. This is an in-process fixture in a separate run from this LIVE 225 CLX balance.

Results for 4 packages, `dex/checkpoint`, `dex/rewards`, `dex/settlement`, and `dex/service/finance`: 60 top-level tests PASS. PASS for reproducing the finality backlog confirms that invalid finality is not published and safety state is retained; it is not a liveness-repair PASS.

Historical 2 core/forkid and 3 RPC FAIL results remain recorded, with no fixes or expectation changes in this run. A full rescan of core/VM/all ordinary CLI roles is NOT_RUN. Separately record the newly found finality failure, runner defects, and test-isolation defect where a default-OFF unit read live settings.

The 20 acceptance items are in the [current matrix](live-acceptance-matrix.md). Raw logs: [this run's results](results/live/20260923-active-finance/), original `/tmp/common-dex-live-test.x5z_05oq/public`. Funding journal: `build/stage/live-finance-20260923-smoke`; keys/runtime remain in private configuration storage and are excluded from public archives.

Starting git status was preserved privately and compared with the active release's production source manifest. There is no record of a newly created full-file archive at this run's start. Map the earlier full-diff archive to source hashes before/after each helper change and the final complete reviewable manifest. Matching HEAD does not establish matching worktrees.

## Final accounting and runtime state

Authenticated CLX height **1121**, hash `0xf6b0428aa9fcd443ba9d96ddfb8c8f96c52bab818075c08890f210c9c40265cb`, root `0x87adc3f1c979f299969635f9167189edc182d4379edaebe2077ef2ed9f6ad3e4`. All 14 CLX verifier nodes agree. Authentication used bounded FHS evidence intervals from genesis, matching account/storage MPT and block bodies/receipts across the full interval. ACKs or RPC latest values alone were not the basis.

Reconciled 29 transactions across 1057→1121: 25 ordinary transfers, 2 trader deposits, 1 support, and 1 insurance. The ordinary 1-atom transfer during full DEX shutdown is within this authenticated interval. Native deltas for all wallets are saved in `partial-accounting.json` under `native_delta_atoms` and wallet proofs. Since DEX funds remain unsettled, the following is **partial accounting PASS(LIVE)**, not financial completion.

|Account|Integer CLX base units|
|---|---:|
|custody|225000000000000000000|
|U: trader deposits not yet reflected in DEX|200000000000000000000|
|S: support|20000000000000000000|
|I: insurance|5000000000000000000|
|T: reflected trader funds, F: fee, Z: dust|0 each|
|W: withdrawal reserve, R: reward reserve|0 each|
|surplus|0|
|Withdrawals and DEX reward payments|0|
|Total ordinary TX gas|1611400000000000|
|Common RPC rewards|322280000000000|
|burn|1289120000000000|

`gas = Common rewards + burn` balances. Wallets paid gas; custody did not. Block issuance of `3100000000000000000000000` atoms under existing CLX rules in this interval is separately accounted for in wallet deltas. It is neither additional DEX issuance nor an assessment of normal PoW success.

Maximum native calldata included in CLX in this run was 12 bytes; this does not measure checkpoint/anchor/claim submissions. Do not conflate source-observer outer authentication evidence with this TX calldata measurement. Maximum proofs, C heap, wall-clock load, A/B/C, and 60-minute performance are NOT_RUN; performance acceptance remains undecided.

At completion, 7 CLX committee nodes, 7 Common parents, and 7 DEX sidecars were running; only the 2 relays were intentionally stopped (21 cypher role processes total). DEX certified 15 / finalized 0 / CLX accepted 0, storage-generation rotations 0. Existing signatures/WAL/inbox/225 CLX remain intact. New financial input is stopped. No new FROZEN loss allocation/refund mechanism was introduced.

Final Python: 78 tests PASS. Finance/source-observer helpers: 2 packages race, 8 top-level PASS (2 foreign-owner subtests SKIP due to sandbox UID-mapping restrictions). Existing finite-gap and new backlog reproduction races also returned PASS. Go race reports detection on executed paths; it is not proof of C BLS or overall consensus safety. Initial Python 2 FAIL and partial-audit relative-path rejection FAIL are preserved and mapped to final reruns.

Same-DB recovery checks for disappearance of old parent/child PIDs and matching datadir inodes/manifest/checkpoints are in `dex-stop-isolation.json`; final runtime is in `final-live-observation.json`. All 600 ordinary production files match the release manifest; source changes are limited to this run's helpers/runners/tests/reports. No production financial-finality repair/redeployment was performed.

Authentication scope: block RLP hash/number/transaction trie root and ancestor connection to the authenticated endpoint, plus account/storage MPT, were verified. RPC receipt TX/sender/block bindings, block gas totals, accounting conservation, and receiptsRoot agreement across 14 nodes were also checked. However, **independently rebuilding the receipt trie to prove each receipt's inclusion is unimplemented**. Receipt reconciliation must not be called an independent receipt inclusion proof.

Final review artifacts under `/tmp/common-dex-live-test.x5z_05oq/final/`: `changed-source-sha256.json`, `reviewable-worktree.tar.gz`, `tracked-review.patch`, and `end-status.z`. These include untracked implementation; root credential scripts, keystores, runtime, and operational DBs are excluded. Configuration files are mapped to public genesis and file hashes; private keys were not copied into saved artifacts.
