# Common DEX Continuous Operation — Final Isolated-Devnet Record

G3 trial 15 using the ordinary CLI and real communication was **PASS (1546.32 seconds)**.
Reconciliation reached CLX height 749, DEX finalized 109/CLX accepted 109, no unsettled finalized sequences, inbox cursor 10,
72 native payments, and custody 295 CLX. The later DEX-OFF Common also passed synchronization of all 750 blocks
and restart with the same DB. Certified 110 is not counted as settled.
This does not establish indefinite operation, production readiness, or superior performance.

Target branch: `FHS-D-ExchangeCore`; starting/ending HEAD:
`70862a71dfaf2b00694dc1354c6a64e9504d7db5`. Deliverables are uncommitted changes.
Final Go/scripts manifest: `7f786223801e567b77c6c37bf437c189ea440de3db91f0b93d4fae705cdc97e2`.
Source matched before and after final regressions, with 0 changes during execution.
The [26-item matrix](continuous-acceptance-matrix.md), [test index](results/continuous-final-test-index.md),
[G3 raw log](results/continuous-g3-normal-15.log), and [machine extraction](results/continuous-final-g3/summary.json) are linked.

## Implemented Authentication and Persistence Boundaries

G0 reproduced and fixed reward-close decisions for the same parent/proposal depending on differences in evidence
held by local collectors. Close uses only the set imported into common state by CDXP before the deadline.
Reward-period waiting and market progress are distinct; unshared private evidence does not become another node's permanent rejection condition.
General inclusion/delivery fairness remains unimplemented. [Reward audit](continuous-g0-rewards.md), [CLX fix audit](continuous-g0-clx.md).

G1 explicitly introduced DEXDevnet3/checkpoint schema 4/financial state 5 for new isolated genesis configurations.
Legacy config 2/schema 3 and the 225→214 fixture retain their meaning. The fixed checkpoint portion is 525 bytes.
Deposit IDs are independent of the containing block hash; FHS finality and MPT inbox-inclusion proofs are verified externally.

- DEX verifies QC/descendants, historical key context, MPT, and continuous entries from the CLX anchor in current consensus state.
  CDXA actions atomically update anchor/cursor/credit and re-execute from WAL/snapshots.
- CLX stores bounded segments through `NativeAnchorUpdate` in ordinary signed TXs. Old segments are staged;
  checkpoint fund reservations are disallowed until connection to a canonical ancestor in the current execution context's 64-block window.
  Previously connected anchors and accepted rights remain in history and do not expire merely with age.
- Anchor v1 is 246 bytes; v2 is 286 bytes. Authentication covers only ordinary CLX keyblock updates/reordering of the same 7 registered members.
  DEX epoch is fixed at 1. Unknown committees, public joining, and unsupported key updates involving PoW candidates are rejected.

Bounds remain 64 headers/update, 8 descendants/header, 7 signers, 64 KiB native calldata, 65 MPT nodes/path,
1024 bytes/node, and 128 inbox entries. The source fetches at most 32 headers at a time and shortens segments further
according to byte limits. Total work for long catch-up grows with the number of steps.
Latest RPC, local time, and in-memory finalized flags are not new trust roots.
Only ordinary TXs update canonical CLX state; DEX callbacks do not rewrite it.
[Rolling specification](rolling-anchor-spec.md), [key-renewal specification](fixed-key-renewal-spec.md), [native persistence](key-renewal-native-relay.md).

G2 persists semantic IDs, submission intents, nonces, signed TXs, attempts, ACKs, and authenticated completion in the relay.
After startup, it reauthenticates through FHS/MPT. ACKs, mempool admission, and single QCs do not mean payment completion.
Even when another relay completes the operation, its own unconsumed nonce is retained; consensus history/nullifiers prevent double settlement.
Processing alternates incomplete work and reauthentication of completed history so cold history cannot defer unresolved nonces indefinitely.
[Relay specification](relay-core-spec.md), [cold scheduling rules](relay-cold-scheduling.md).

Local WAL v3 dictionary-encodes only exactly identical Actions bytes. It retains all records, QCs, finality, voting-safety state,
and outboxes without enlarging 2 MiB wire/128-record limits. Total expanded actions and total restored state each also have a 2 MiB limit.
Legacy v1/v2 recover fully before saving as v3. Snapshots remain expanded v2.
[WAL specification and independent golden vectors](wal-action-dictionary-spec.md).

Ordinary entry points are `--dex.validator --dex.config /absolute/manifest.json` and
`cypher dex-relay --relay.config /absolute/config.json` (supporting `--relay.once`/`--relay.duration`).
DEX defaults OFF; relay gas keys, DEX voting keys, RPC signers, and recipients are separate.
`eth_getCLXFinalityWitness`/`eth_getDEXInboxEntries` are read APIs that obtain unauthenticated evidence from explicit blocks;
responses must always be verified. CLX submissions use ordinary `eth_sendRawTransaction`/Common admission/TxQUIC.
The order API was loopback-only in this work. [Entry points and configuration](README.md), [relay CLI](relay-cli-spec.md).

## Measured Repetition, Outages, and Recovery

Trial 15 was a loopback test with new genesis, keys, datadirs, and user/network namespaces.
Source Common ran inside the coordinator; main roles were 7 CLX, 7 Common parents, 7 DEX sidecars, and 2 relays.
One later OFF Common started/restarted separately. Logs confirm 50 main-role starts/50 PIDs including restarts.
The 24 role slots are not a concurrent process count. Total OS children including initialization/key-generation helpers were not measured.

| Connection/fault | Observation in the final run |
|---|---|
| Late DEX participation | After cycle 1, authenticated a snapshot using the registered seventh member's unique key. Peer voting-safety state was not copied. |
| All DEX nodes stopped beyond L | At least 89 heights from CLX 168 to authenticated source 257. The intermediate 241 difference of 73 is not the final outage length. |
| Ordinary CLX key renewal | Clock unchanged; 4 ordinary transfer carriers and 6 minutes 8.496 seconds of waiting authenticated source v2. |
| Cold DEX catch-up | Multiple steps from old anchor 95 to anchor 255/cursor 8. Actual version while flat was 1. |
| New deposits after 257 | The final 40 CLX finalized at CLX 281/285. Subsequent DEX authenticated source 314/version 2/cursor 10. |
| All CLX nodes stopped | Around height 361, CLX accepted 60 and DEX finalized 78. Retained 18 unsettled checkpoints. |
| CLX recovery with the same DB | Compared pre-stop canonical state. Accepted checkpoint 78 through an ordinary TX at height 467. |
| Final settlement | Height 749, DEX finalized 109 = CLX accepted 109, all 72 claims paid, unsettled difference 0. |
| Cold relays | Two independent relays reauthenticated 406/406 operations. Resubmission gas was tallied separately. |
| Common comparison | Explicit RPC hash/root/receipt/gas matched across 7 existing Common nodes. Later OFF synchronized all 750 blocks/410 receipts, restarted with the same DB, engine 0. |

Measured engine instances/actions/inbox imports for CLX/source/OFF were 0/0/0.
The 363 production settlement/relay dependencies exclude the heavy engine/devnet/runtime.
CLX performs additional bounded authentication/storage/accounting work; overhead is not claimed to be zero.
Common peer heads were not corrected by the test; nodes caught up through ordinary ETH connection/reconnection/synchronization.

## Financial Ledger and Additional Costs

The original ordinary-CLI fixture also passed on the same final source:225−10−1=214 CLX, CLX 69, accepted 18,8 claims.
Its subsequent existing FROZEN fault roots are intentionally unsettled and are not mixed with this long-run final state.

The long run uses a separate ledger:345−40−10=295 CLX, 4 withdrawals +68 rewards.
Trader 279.664, fee 0.168, support 10.168, insurance 5; unconsumed/dust/withdrawal reserves/reward reserves are 0.
Surplus, the difference between custody and all buckets, is also 0.
Of total fees 0.336, rewards consumed 0.168 plus 9.832 from support. This does not establish fee-only profitability.
Existing FIFO/cash/PnL/funding/dust formulas and independent golden vectors were preserved.

Gas for 410 canonical TXs was 4,473,920,409,600,000,000 atoms;
Common rewards 894,784,081,920,000,000; burn 3,579,136,327,680,000,000.
Custody does not pay relay gas. All 17 native accounts, 8 buckets, and costs by payer/operation are saved in the
[final ledger](continuous-final-ledger.md) and [TX inventory](results/continuous-final-g3/transactions.csv).
The [claim inventory](results/continuous-final-g3/claims.jsonl) distinguishes actual Claim.ID from leaf hashes.
The old CP 14 withdrawal root is `9ba637d859bc20d8174fed5ae7a76ec13f97b75bb08b91a87c3e882ab86548cf`.
A separate unit test also checked the combined sequence of additional updates/payment, cold DB, and resubmission by another sender.

This run's maximum observed native anchor had 63,566 bytes calldata, 32 headers, 7 MPT nodes/2,105 bytes,
and gas 15,416,776. Allowed limits and observed maxima are distinct.
Successful 65536-byte input and an invalid final MPT proof were each run 3 times in separate limited component measurements.
[Costs and unmeasured scope](results/continuous-final-native-cost.md) records wall time, Go allocations, RSS, and write counts.
C heap alone, worst-case values across all proof arrangements, an equal-CLX-load control network, WAN, and 60-minute mixed performance are NOT_RUN.

## Regressions, Protection, and Incomplete Work

Unit/race across 19 packages:284 top-level/839 PASS events. Sockets, 8 role combinations, core/VM, QC-first 7-CLX,
ordinary-CLI finance, source, and G3 were reverified on final source. The [index](results/continuous-final-test-index.md) details SKIP coverage and scope.
Existing failures were 2 core/forkid cases, 3 existing RPC cases, and a separate 40-second timeout.
Reproduction from the starting archive is distinguished; failures were not removed by changing expectations.
Failures/interruptions from the previous 14 attempts remain in [development history](continuous-development-history.md).

All 377 initially changed files and old manifests/archives were preserved. Go 1.27.1/AMD EPYC/12 visible CPUs/
GOMAXPROCS 2/readonly modules/dedicated cache; no host fallback on isolation failure.
[Environment](results/continuous-final-environment.json), [test-only cache migration](results/continuous-cache-storage-migration.json).
Ordinary 32 GiB PoW was NOT_RUN with final MemAvailable 17,040,748 KiB (about 16.25 GiB), memlock 8 MiB, swap 0.
PASS for 8 lifecycle combinations does not establish nonce search, proof delivery, or concurrent PoW performance.

**The O26 protection invariant is FAIL**. Of 70 selected files, 68 match G0 hashes; 2 distributed binaries differ.
All 70 match the resumed-work baseline. A contemporaneous stage manifest has the same hashes as current binaries, but who performed the operation is unidentified.
No unauthorized restoration/rebuild was performed. [Comparison](results/continuous-final-protected-observation.json),
[stage evidence](results/continuous-protected-build-stage-evidence.json).
Read-only PID/executable-name/datadir checks matched for 8 operational processes, but G0 lacks start ticks, so this does not prove absence of PID reuse.
Ordinary updates to operational DBs are not file immutability. Operational-node signals, real-fund operations, commits, and remote pushes were prohibited in this work.
[Reproducible changes and archive boundaries](continuous-review-bundle.md) lists exclusions of keys, operational data, and distributed binaries.

The design stops safely at finite queue/history/cap limits; indefinite garbage collection for 128 records/anchor 1024 and similar bounds is unimplemented.
General reward-inclusion fairness, recovery from permanent DA loss, new FROZEN loss allocation/full recovery, public participation/committee rotation,
production rates, USD collateral, real Oracle/MM, and computation Validity Proofs are unimplemented/outside this work.
A QC proves finality under committee trust, not computation validity. A DA root does not guarantee retrieval;
fixed epochs or loopback tests do not establish public decentralization, WAN behavior, or superiority over Hyperliquid.
