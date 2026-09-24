# Acceptance items and execution boundaries — native CLX integration

2026-09-22, uncommitted changes on HEAD `70862a71dfaf2b00694dc1354c6a64e9504d7db5`.
The previous matrix is preserved in [initial-acceptance-matrix.md](initial-acceptance-matrix.md).
PASS applies only to the stated scope. Distinguish components, in-process fixtures, real sockets, and ordinary CLI.
Unimplemented/unrun items remain, so this is not overall A–D completion.

Evidence abbreviations:

* **U**: [Final DEX/HotStuff unit/race](results/integration-final-unit.jsonl). Includes FIFO/cash/PnL/funding/dust and 39 arithmetic goldens.
* **V**: [Final native core/VM race](results/integration-final-native-race.jsonl), [proof/dependency audit](integration-security-review.md).
* **N**: [Ordinary CLI financial end-to-end](results/integration-final-financial-cli.log). CLX 7 + ordinary Common 7 + DEX sidecar 7, real loopback/netns TLS/ETH/TxQUIC, synchronization/restart of a separate DEX OFF Common.
* **S**: [Real financial socket-helper regression](results/integration-final-financial-sockets.log). CLX 7 + DEX 7 test processes, a separate mode from ordinary CLI.
* **R**: [8 ordinary CLI role combinations/restarts](results/integration-trie-journal-cli.log), [8 real API role combinations](results/integration-final-api-roles.log). PoW lifecycle uses rejection before allocation.
* **T**: [Explicit opt-in real TLS race](results/integration-final-sockets.log). A separate run from unit socket SKIPs.
* **B**: [Final existing baseline](results/integration-final-baseline.log), [final 6 old process tests](results/integration-final-process.log).

See the [integration record](integration-status.md) and [validation index](results/integration-validation-index.json)
for final N/S execution results, source mapping, and trial FAIL results.

## Current 30 items

|ID|Result / prior-item mapping|Execution evidence, limits, and incomplete scope|
|---|---|---|
|I01|PASS / P06|Preserved 136 initially changed files including untracked files. Matched old final logs to starting hashes. Separately saved final-diff archive, environment, and source manifest.|
|I02|PASS(lifecycle) / R01,R02|R: All 8 ordinary CLI combinations, independent start/stop, manifest/DB restart. Normal PoW nonce search/DAG/proof delivery are resource-limited NOT_RUN.|
|I03|PASS / R03,C05|N,V: Independent DEX OFF Common performs real ETH synchronization/restart and verifies all settlement. Measured engine instance/action/inbox-import counters are 0/0/0 on CLX 7 and syncing Common.|
|I04|PASS(isolated integration) / L01|N: 4 signed deposit TXs pass through HTTP RPC → Common admission → TxQUIC → CLX blocks → real FHS finality. No fixture anchor is injected into the handler.|
|I05|PASS / L01|U,V: 223-byte inbox separate from inclusion evidence. Depends on sender/nonce/action/payload/value, not inclusion block hash. Independent Python golden.|
|I06|PASS / L01,C02|U,V,N: Only private VerifiedRange authenticated using genesis-bound historical CLX committees, 2-chain descendant evidence, and account/storage MPT proof can credit funds.|
|I07|PASS(component + integration) / L01|U,V: Rejects unfinalized/orphan proposals, forged header/domain/custody, forged owner/amount, and discarded snapshots with zero credit. N credits from real finalized evidence. Distributed RPC injection of all attacks is NOT_RUN.|
|I08|PASS(component) / C01,C02|U,V: Authenticates SignInfo/finality metadata every time even for the same header hash, rejecting tampering. Hash equality is not finality proof.|
|I09|PASS / L01|U,V,N: Consecutive index/cursor, duplicates, gaps, ordering, owner/amount/payload tampering. Four valid entries credit once.|
|I10|PASS / C05,L01|Call graph + separate-process stop/restart in N. DEX callbacks affect only their own WAL/outbox; ordinary TX StateDB execution owns canonical CLX updates.|
|I11|PASS(isolated integration) / L03,L04|N: Financial checkpoints 1–18 accepted/finalized through separate ordinary CLX TXs. Reconciles fee/support/withdrawal/reward reservations by purpose.|
|I12|PASS(isolated integration) / L02,L05|N: WithdrawalClaim 1 + RewardClaim 7 finalized through ordinary TXs. Relay and recipients are distinct; the leaf binds the recipient.|
|I13|PASS / L02,L03|N,V: Same checkpoint from another relay is unchanged; different payload at same sequence fails; same claim in a new TX succeeds/no additional payout; recipient tampering yields failed receipt.|
|I14|PASS(fixed fixture) / L04|N: Independently reconciles every wallet/nonce/custody/8 buckets/gas/Common reward 1/5/burn 4/5 in base units. 225−10−1=214. Reward 1 comes from fee 0.02 + support 0.98.|
|I15|PASS(component) / L02–L04|V: Deposit OOG and actual resource-guard excess after checkpoint/claim writes revert the outer snapshot, preserving root/nonce/gas/log/nullifier/reserve; same-TX retry succeeds. Internal CALL/create/SELFDESTRUCT surplus are checked separately.|
|I16|PASS(isolated integration) / C03,L03|N,V: Canonical block/root/receipt/gas agreement across proposer/7 validators/ETH sync/CLX SIGKILL/DEX OFF Common restart. Host power loss/disk failure NOT_RUN.|
|I17|PASS / C05|No engine in production dependencies. N measures 0/0/0 on all CLX 7 + independent syncing Common. Bounded accounting/proof checks still add load.|
|I18|PASS(boundary checks) / C06|U,V,T: Calldata 64 KiB, fixed 7 keys, descendant/ancestor/signature/MPT/entry/claim/storage/queue limits, gas/resource recorder. Maximum-input wall-clock/C heap measurement NOT_RUN.|
|I19|PASS(real sockets) / C01,C03,D02|T,N,S: TLS 1.3 peer proofs + chain/genesis/DEX/epoch/recipient, reconnects, wrong keys, old epochs, corrupt/partial frames, reordering/duplicates, WAL resume. WAN NOT_RUN.|
|I20|PASS(isolated integration) / L01–L05|N: CLX 7 + DEX-participating Common 7. Financial execution has 21 child processes including sidecars. Late Common sync after full DEX stop has CLX 7 + Common 7 + late 1 = 15 children. RPC source inside coordinator recorded separately. Not 7 independent operators.|
|I21|PASS(limited delivery conditions) / C03,D01|N: Stops 1 then 2 DEX nodes, remaining 5 progress, old WAL restart, real iptables 5/2 partition progresses on the 5-node side, roots agree after healing. S uses helper connection controls, recorded separately.|
|I22|PASS(limited delivery conditions) / C02|N: Actual 4/3 packet partition creates no new 5-party QC, distinguished from applying existing proofs; recovery after healing. Threshold unchanged.|
|I23|PASS(isolated integration) / R04,L08|N: Ordinary CLX transfers continue with all DEX sidecars stopped; paid claim adds no payout; altered claim fails. Common parents continue and sync CLX.|
|I24|PASS(finite fixture) / L01,L08|N: Distinguishes internal DEX progress during full CLX shutdown from CLX accepted 18; unpaid rights/reserves unchanged on resume. U/T checks outbox/queue caps. Long-term automatic relay/rolling anchors NOT_IMPLEMENTED.|
|I25|PASS(selected crash boundaries) / C03,L02,L03|N,V: All 7 CLX processes SIGKILL after checkpoint acceptance at 47 and after claims at 63; unique recovery of head/state/receipts/nullifiers. Two DEX nodes reopen WALs. Exhaustive power cuts between all fsyncs NOT_RUN.|
|I26|PASS(limited economic failures) / L07,L08,D02|N,S: Stale-price/cancel/reduce-only restrictions + partition/missing DA, unavailable API 503, refetch after healing, unliquidatable positions/insurance 5 exhaustion leave debt and FROZEN. Failure-state DEX roots after 18 are unsettled on CLX.|
|I27|PASS(known-proof omission) / NOT_IMPLEMENTED(general delivery guarantee) / W01,W03|U,N: Rejects omission of 1 of 7 certificates known to all collectors, with unchanged reserves/nonces; valid action branches and complete-close retries remain possible. Deadline unchanged. Inclusion of all honest parties for proofs held only by a minority or withheld, and unconditional liveness, remain unresolved.|
|I28|PASS(component + end-to-end backing) / W04,L04|U,V: Zero fee/support shortage/cap/delayed close reject unbacked reservations. N uses fee 0.02 + support 0.98. Distributed reruns of every exhaustion combination NOT_RUN.|
|I29|PASS(ordinary Common) / R03,D01|N: Late DEX OFF Common reexecutes through 69 using only real ETH sync; block/receipt/gas/native 214 still match after restart, engine 0/0/0.|
|I30|PASS(reverification procedure), existing FAIL retained / R05,P06|Maps U,V,R,T,B,N,S to source. Retains forkid 2 FAIL and resource-limited PoW/WAN/performance NOT_RUN. Does not claim all repository tests PASS.|

## Continued mapping of the previous 31 items

|ID|Current result|Mapping and remaining scope|
|---|---|---|
|R01|PASS(lifecycle)|I02/R. Normal PoW nonce search NOT_RUN.|
|R02|PASS|I02/I03; DEX vote/reward separate from CLX membership/RPC signer/coinbase.|
|R03|PASS|I03/I29. Ordinary DEX OFF has no DEX DB/worker/signing/sync, but does verify CLX.|
|R04|PASS(limited failures)|I21–I24. Queue limits U/T, continued CLX transfers N. Sustained verification-budget measurement NOT_RUN.|
|R05|PASS(primary baseline) + FAIL(2 known cases)|B. Retains forkid TestCreation/TestValidation without merely changing expectations.|
|C01|PASS|I07–I09/I19. Not a proof under every public-adversary model.|
|C02|PASS|I06/I08/I22. Rejects single QC; fixtures add required valid descendants when views have gaps.|
|C03|PASS(component/restart)|I16/I19/I25. Certified-parent reexecution, double-vote prevention, WAL.|
|C04|PASS(component) / NOT_IMPLEMENTED(normal connection rotation)|Epoch-boundary rejection in U. Native v2 has authenticated fixed epoch 1; actual committee rotation is not provided.|
|C05|PASS(separation/limits)|I17/I18. Added proof/accounting work is nonzero. Comparative performance NOT_RUN.|
|C06|PASS(component/socket)|I18/I19. Long fuzzing/maximum-load measurement NOT_RUN.|
|L01|PASS|I04–I09. Real CLX finality + MPT deposits in addition to old fixtures.|
|L02|PASS|I12/I13/I15/I25.|
|L03|PASS|I11/I13/I15/I25.|
|L04|PASS(fixed fixture)|I14/I28. Preserves 39 independent arithmetic goldens and 225→214.|
|L05|PASS|I12/I13/I15. Signed TX sender separate from claim recipient; surplus is not backing.|
|L06|PASS(trust assumptions recorded)|Committee signatures, no computational Validity Proof, explicit trust against improper account reallocations.|
|L07|PASS(fixture)|I26. Synthetic feed/BTC/CLX. Real Oracle/USD-collateral product NOT_RUN/not designed.|
|L08|PASS(conservative halt) / NOT_IMPLEMENTED(full recovery)|I23/I24/I26. Funds freeze at FROZEN/DA/anchor limits. No blanket old-balance refund.|
|W01|PASS(authenticated records)|I27, actual votes + 5/7 collectors/cutoff, duplicate/post-fact signatures rejected. Not proof of CPU execution.|
|W02|PASS(component)|U rejects self-trades, fixes support/cap. Long-term multi-account market attacks NOT_RUN.|
|W03|PASS(fixed fixture)|I14/I27, authenticated allocation to 7 participants. General inclusion fairness/public profitability unresolved.|
|W04|PASS(component)|I28, conservative rejection for insufficient backing, no unlimited issuance.|
|D01|PASS(component/real sync)|I19/I21/I29, financial certified-data refetch and WAL rejoining. Full financial snapshot setup for public third parties remains incomplete.|
|D02|PASS(explicit missing data)|I19/I26. A root alone does not establish successful retrieval or available withdrawal.|
|P01|PASS(stage identification)|N includes ingress/DEX certified/finalized/CLX finalized/claim paid identifiers. Latency SLO comparison NOT_RUN.|
|P02|NOT_RUN|Open-loop all-percentile/rejection-rate/backlog load measurement.|
|P03|NOT_RUN|At least 60 minutes of mixed load.|
|P04|NOT_RUN|Mixed-settlement comparison on the same hardware/CLX load.|
|P05|NOT_RUN|Normal PoW 32 GiB DAG + cache exceeds MemAvailable about 20–24 GiB, memlock 8 MiB. No host changes.|
|P06|PASS(reproduction materials)|I01/I30. No raw results exist for unrun performance tests.|

This matrix does not approve production/public release, real funds, WAN, MM, additional issuance, public participation/bonds, or adoption of computational proofs.
