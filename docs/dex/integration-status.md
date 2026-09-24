# Common DEX Development Record — Isolated Devnet with Actual CLX Integration

The target is `CypherTroopers/cypher` / `FHS-D-ExchangeCore`. Existing FIFO positions, cash/PnL, funding/dust, and the independent arithmetic model were preserved while connecting ordinary CLX TXs, ordinary Common startup, real authenticated transport, and financial failures spanning both domains. This does not declare all of A–D complete, production release, or superior performance.

The final ordinary-CLI financial run was **PASS (262.12 seconds)**; the separate financial real-socket regression mode was also **PASS (219.08 seconds)**. Native custody moved from 225 to 214 CLX, matching synchronization/restart through CLX height 69.

Final results correspond to the [acceptance matrix](acceptance-matrix.md), [validation index](results/integration-validation-index.json), and raw logs below. Earlier financial-fixture PASS results were not reused as network results for this run.

## Protection, Start, and Finish

Starting/ending HEAD was `70862a71dfaf2b00694dc1354c6a64e9504d7db5`. A read-only `git ls-remote` recheck of the public branch returned the same HEAD: [public HEAD](results/integration-public-head-final.txt). No commits/resets/pushes or changes to operational genesis/keystore/WAL/chaindata/distributed binaries were made.

The workspace and ancestors contained no repository-specific work instructions. At startup, the prior `final-unit.jsonl`, `final-baseline-regression.log`, and `final-process-regression.log` were read, and the prior final-source manifest was compared with actual files. All 136 initially changed files, including untracked files, were preserved.

* [Initial state, source hashes, and previous-log comparison](results/integration-start)
* Starting archive: `/tmp/common-dex-integration.hnc63_8r/baseline/worktree-sources.tar.gz`. tracked.patch/status/HEAD were saved in the same area.
* [Final environment and protected PID identification](results/integration-environment-final.json). The ordinary sandbox used a separate PID namespace, so 8 operational PIDs were rechecked with host-visible read-only commands. All 8 comm/cwd/datadir values matched the starting record. No owned test processes remained after completion.
* [Hash recheck of 70 protected files](results/integration-protected-check.log). Distributed binaries, original genesis, existing local DBs, etc. matched. This is not a claim that running operational DBs were snapshotted.

The run used Go 1.27.1 linux/amd64, gomod 1.25.6, GOPROXY=off, readonly modules, GOMAXPROCS 2, nice 10, and a dedicated /tmp cache. Host resources: 12 CPUs, MemTotal 49,325,352 KiB, initial MemAvailable 24,729,084 KiB, recheck 20,881,572 KiB, after all tests 21,566,464 KiB, swap 0, memlock 8 MiB. The ordinary PoW 32 GiB DAG plus cache exceeded available resources, so nonce search, proof delivery, and performance with concurrent PoW were NOT_RUN with that reason. Resources were not freed by changing host settings or stopping existing nodes.

## Implementation and Exposed Entry Points

Ordinary Common starts with `--dex.validator --dex.config /absolute/manifest.json`, default OFF. The parent Common validates chain/genesis and manifest and supervises a `dex-validator` sidecar from the same newly built binary. Starting PoW, attracting RPC clients, or changing CLX membership is not a prerequisite for DEX participation. Configuration, vote keys, RPC signer, reward recipients, and WAL are separate. All 8 ordinary-CLI combinations, shutdown, and DB restart were tested, while distinguishing PoW lifecycle IsMining from ordinary-size nonce search.

Actual APIs in the `native-finance` manifest are loopback `/v1/actions`, `/v1/action-status`, `/v1/status`, `/v1/checkpoint`, and `/v1/participation`. The order API authenticates signed raw actions and admits them to bounded durable ingress. Ordinary APIs cannot specify height or authenticated CLX context. ACK, certified, finalized, and CLX-accepted are separate states. Peers use real TLS 1.3 sockets bound to registered identity/domain/epoch, with size/queue/rate bounds.

CLX uses ordinary `eth_sendRawTransaction`: RPC -> existing Common admission -> TxQUIC -> TxPool/proposer -> execution/receipt verification by the 7-member CLX committee -> existing FHS finality -> canonical persistence. Only genesis-bound devnet configuration enables the native handler. The same settlement rules are verified with local DEX OFF. A valid external relay may be separate from the order sender, DEX voter, and fund recipient.

An additional test started RPC + DEX concurrently on ordinary Common and relayed a native withdrawal claim with an independent, unfunded RPC operator-signing key. The gas payer and operator signer are distinct, as are CLX gas-reward and DEX reward recipients. Reward recipients' private keys are not placed on the signing server.

## Deposit Cycle, Finality Authentication, and Accounting

The [223-byte InboxEntry specification and golden vectors](integration-deposit-spec.md) define a stable DepositID using authenticated sender, TX nonce, action index, canonical payload hash, and chain/genesis/DEX/custody. The payload also binds TX.value, owner, asset, and purpose bucket. The current containing block hash is not written into entries/state. Inbox sequencing and custody transfer execute within the same ordinary TX snapshot.

After finalization, external RangeEvidence includes actual CLX header/SignInfo/descendant evidence and custody account/count/entry MPT proofs against that state root. It verifies the genesis-authenticated historical committee and ancestor linkage, existing FHS 2-chain/descendant rules, and SignInfo every time. It rejects modified metadata with the same hash, single QCs, and isolated/unfinalized deposits. Only a verified Range is credited once through a continuous cursor. Historical anchor references on CLX are also assessed through the execution branch's GetHash; latest RPC, local time, and in-memory finalized caches are not consensus inputs. Finality callbacks do not rewrite canonical StateDB, and no SealInbox TX was added.

The [ordinary native TX specification](native-tx-spec.md) and [TX/simulation audit](native-tx-audit.md) record treatment of signature/nonce/gas/receipt/resource recorder/outer revert, eth_call/estimateGas/trace, and internal CALL/CREATE/SELFDESTRUCT surplus. Fake from values or state overrides in simulation do not confer canonical authority.

The CLX call graph is `ApplyTransaction → EVM.Call → settlement.RunNative → bounded checkpoint/MPT/accounting`. Production dependencies do not include the matching/risk engine. Measured engine instances/actions/inbox imports were 0/0/0 in the 7 CLX processes and DEX-OFF synchronizing Common. Verification of evidence/signatures/MPT/storage adds work beyond the 525-byte checkpoint; this is not reported as zero overhead. See the [resource-bound audit](integration-security-review.md). Bounds are 64 KiB total native calldata, 7 fixed keys, 16 KiB DEX evidence/at most 8 descendants, 64 CLX ancestors, 65 nodes/1024 bytes each per MPT proof, 10 claim siblings, and 128 deposit entries per range. Gas uses bounded conservative fixture values; maximum-load time and C-heap performance were not measured.

## Financial Run and Fault-Test Scope

The [final ordinary-CLI raw log](results/integration-final-financial-cli.log) and [final real-socket helper raw log](results/integration-final-financial-sockets.log) are saved separately. Every process used only loopback in new user/network namespaces, with no external route and new keys/genesis/datadirs/ports. Stops, restarts, and iptables changes were limited to owned test handles and dedicated namespaces.

The ordinary-CLI financial phase used 7 CLX test processes + 7 ordinary Common parents + 7 DEX sidecars, totaling 21 child processes. A separate RPC-source Common service ran inside the coordinator. The later DEX-OFF synchronizing Common started after all DEX nodes stopped, so that phase had 7 CLX + 7 ordinary Common + 1 later Common, totaling 15 children. Restarted PIDs are recorded separately in the log; this is not counted as 22 concurrent nodes. The initial identity-generation helper stopped before ordinary Common startup. This does not measure 7 independent operators or a 14-host WAN. CLX-side PoW used the fixture faker, without ordinary nonce search.

1. Four ordinary deposit TXs supplied traders 100 + 100, support 20, and insurance 5, for native custody 225. Finalized CLX headers + MPT proofs credited DEX once.
2. Authenticated orders over real DEX transport, fills, price updates, fees, funding, position closure, withdrawal reservation 10, 7-member participation evidence, and reward reservation 1. Accounting results of the existing 18 financial blocks were preserved.
3. Checkpoints 1–18 were accepted through ordinary CLX TXs. Exact relay resubmission changed nothing; the same sequence with a different payload produced a failed receipt. After acceptance, all 7 nodes were SIGKILLed at CLX height 47 and restarted with the same DB/WAL; all roots/receipts/reserves matched.
4. One WithdrawalClaim + 7 RewardClaims finalized through ordinary TXs, producing native custody 214. All wallets/nonces, 8 buckets, and gas/Common rewards/burn were reconciled against an independent integer ledger.
5. Internal DEX finality progressed while all CLX nodes were stopped after the height 63 claims. The unsettled difference from CLX-accepted 18 was shown explicitly; CLX resumption confirmed no duplicate payments/reservations.
6. One DEX node down, two down, recovery/WAL identity comparison, real packet 5/2 and 4/3 partitions, and healing. New QCs require 5 members. For view gaps, legitimate descendants were added to reach finality; a QC at the same height alone was not treated as finality.
7. Confirmed price outage/stale conditions, DA isolation/unavailable API 503/retrieval, and FROZEN on inability to liquidate/insufficient insurance. Existing positions/debt were retained, with no blanket refund of old balances. These DEX roots after 18 remain unsettled on CLX; native 214 is not conflated with the new DEX economic state.
8. While all DEX nodes were stopped, ordinary CLX transfers, replay of paid claims with no additional payout, and rejection of modified recipients advanced CLX to 69. The 7 ordinary Common nodes and later DEX-OFF Common performed actual ETH synchronization; the latter also restarted with the same DB. All blocks/receipts/roots/gas/native balances were compared.
9. Actual eth_call 223-byte output, estimateGas 271600, an actual TX with that gas, 1 gas too little, native/ordinary-transfer traces, and fake from/overrides were checked, with canonical state unchanged.

The [identified trace and balance table](results/integration-financial-trace.json) are extracted from the final log. They link TX/block hash/height, depositID, anchor-evidence hash, DEX sequence/checkpoint/root/finality-evidence hash, and claim ID/recipient/amount. Random keys and gas values from different runs are not mixed.

Final custody in CLX is `trader189.916 + fee0.064 + support19.02 + insurance5 = 214`. The period's reward 1 is `fee0.02 + support0.98`; this does not establish fee-only profitability or production rates. Each relay pays gas separately from its wallet, not custody. Total gas paid in the final ordinary-CLI run was 397,482,764,800,000,000 minimum units, Common rewards 79,496,552,960,000,000, and burn 317,986,211,840,000,000. The sum of balance changes across 16 accounts matched −burn. Maximum checkpoint calldata was 18,984 bytes. These values apply only to that run and are not load-performance measurements. All details are saved in the trace above.

## Findings and Fixes

Raw logs of failed attempts are saved in [integration-attempts](results/integration-attempts); final PASS logs do not replace them.

* Connected the path where CLX received a QC before Prepare and failed against an empty view to existing standalone QC authentication and body repair. [QC-order regression](clx-qc-arrival-regression.md). Thresholds/finality rules were unchanged.
* Connected trie persistence and synchronous batches in the existing DB to fix FHS canonical root/head being cached only and lost after SIGKILL. A failed write does not publish the head. [FHS durability](clx-state-durability-regression.md).
* Fixed the existing path that resolved empty `--cache.trie.journal` to instanceDir, allowing fastcache on shutdown to replace that directory and delete the new test DB. Empty remains disabled. [Empty-journal restart](empty-trie-journal-restart.md).
* Fixed native-receipt divergence caused by conflating ordinary Common's local RnetPort and similar fields with immutable genesis configuration. Separated saved configuration from permitted existing local fields without weakening genesis authentication.
* Fixed a test gap where an RPC-enabled Common's peer head remained at 47 after the test source advanced through ordinary InsertChain, using normal ETH disconnect/re-handshake on owned connections. Verification and the 75-second deadline remained unchanged. [Peer-refresh rationale](common-sync-peer-refresh-review.md).
* Fixed test certificate sorting, native-outbox fixture capacity, claim-resubmission receipt expectations, Go child-PID lookup, canonical-key genesis, ETH inbound peer count, and finality waiting across view gaps. The financial model was not adjusted to force balances to match.
* An added RPC + DEX fixture attempt copied an existing operator key and was rejected by all 7 nodes through TxQUIC nonce-replay prevention. It was changed to an independent unfunded operator key, and locking before asynchronous signing after HTTP ACK completed was avoided. [Combined RPC relay review](combined-rpc-relay-review.md). Production replay prevention was not weakened.

## PASS, FAIL, and Not Run

DEX/HotStuff race tests across 17 packages matching final source produced 204 top-level PASS results and 446 PASS events including subtests. Seven opt-in socket SKIPs were verified in separate explicit socket runs. Core/VM native race, explicit TLS, 8 ordinary-CLI combinations + restart, 8 actual-API combinations, 6 legacy process tests, and 2 financial modes are recorded separately in the validation index. Go race detects issues in the Go paths executed; it does not prove C BLS safety or overall consensus/financial safety.

The existing baseline had FAIL results for core/forkid `TestCreation` / `TestValidation`; the other 16 packages passed. Expected values were retained and a [cause record](baseline-failures.md) preserved. Known PoW items such as Candidate.HashNoNonce were not changed without authorization for DEX work. General handshake compatibility is not guaranteed.

The following remain incomplete/not run and are not included in PASS.

* **NOT_IMPLEMENTED**: Rolling authenticated anchors. Reaching the 64-ancestor-from-genesis evidence limit or 64 KiB native calldata limit prevents new anchors; reuse of old anchors also has a 64-block limit. Long-term operation may freeze. Public committee rotation from fixed devnet epoch 1 is also unavailable.
* **NOT_IMPLEMENTED**: General inclusion fairness/delivery guarantees for reward evidence. Rejection of omissions known to all collectors and complete-close retries were tested, but guarantees for valid evidence hidden or held by only some nodes remain unresolved. [Rewards and market progress](reward-omission-market-review.md). Paying unsupported evidence or relaxing deadlines is not a workaround.
* **NOT_IMPLEMENTED**: Complete perp recovery from open positions/FROZEN, emergency-price/loss-allocation contracts, third-party full-financial-snapshot setup, and indefinite automatic CLX relaying. Bounded devnet outbox/history/caps cause conservative stops.
* **NOT_RUN**: Ordinary PoW 32 GiB DAG/nonce/proof delivery/concurrent performance; WAN/independent operators; 60-minute mixed/open-loop percentiles; comparison at equal CLX load; maximum-proof wall-clock/C-heap measurements; every disk/power-cut boundary; every distributed financial combination of malicious inputs; real MM/external Oracle.
* Production rates/public participation/Sybil resistance/collateral/upgrades/computation proofs/USD-denominated CLX collateral are unapproved/unselected. Do not describe a QC as a Validity Proof or the signed devnet as a ZK-rollup, trustless bridge, or equivalent in security to CLX.

## Reproduction and Reviewable Changes

The [runner](../../scripts/dex/check.sh) retains legacy unit/process/roles/baseline modes and adds native/financial/cli-financial/cli-roles/socket. Each mode creates fresh /tmp artifacts and does not fall back to the host if isolation fails. CLI-financial builds a new ordinary binary without overwriting an existing binary.

The final bundle in `/tmp/common-dex-integration.hnc63_8r/final/` contains HEAD/status/tracked.patch, hash inventories for all changed/untracked source/spec/raw results, and `reviewable-worktree.tar.gz`. It excludes keys, operational data, test datadirs, and WALs. It supports review by unpacking over the baseline HEAD; it is not a procedure for applying changes to an operational checkout. Subsequent reviews should compare the manifest as well as HEAD.

External references [EIP-1186](https://eips.ethereum.org/EIPS/eip-1186) and the [Go race detector](https://go.dev/doc/articles/race_detector) were rechecked on 2026-09-22. An EIP-1186 state proof alone does not prove CLX finality. No new measurements of Hyperliquid comparison material or performance comparison were performed in this work.
