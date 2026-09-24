# Independent security review of native CLX integration

Retains component and audit results as recorded. See the [integration record](integration-status.md) and [acceptance matrix](acceptance-matrix.md) for subsequent final process results.

2026-09-22. Scope: the uncommitted `FHS-D-ExchangeCore` working tree, with baseline HEAD `70862a71dfaf2b00694dc1354c6a64e9504d7db5`. This review compares specifications and implementation and reruns existing negative tests; it is not an external audit, computational proof, or production approval. Source SHA-256 hashes and rerun results are saved in the [review source manifest](results/integration-security-source-sha256.json), [proof/settlement race](results/integration-security-proof-race.jsonl), and [native VM race](results/integration-security-vm-race.jsonl). Treat subsequent shared-working-tree changes as differences from this manifest.

## Conclusions and findings

No new critical fund-transfer or authentication defects were detected within the reviewed scope. The following limits and unrun items remain. This scoped result does not mean all acceptance conditions are complete.

* A test expectation mismatch was found. The financial network test expected a failed receipt when replaying an already paid withdrawal, but the established specification and `Adapter.Claim` treat the same leaf as a successful replay with no payment. The integration owner corrected the expectation and added recipient-tampering rejection. Post-fix status follows the final process execution record. Retransmitting a signed TX with the same nonce differs from resubmitting the same claim with a new nonce.
* Package comments in `settlement/adapter.go` and `checkpoint/proof.go` retain the earlier description "not registered with CLX execution." Distinguish the schema 2 direct adapter fixture from the schema 3 native TX path enabled at genesis. Activation for real funds remains prohibited.
* The initial I15 review found that deposit OOG and adapter failure tests alone did not directly establish outer rollback for schema 3. `TestDEXNativeCheckpointAndClaimOuterResourceRollback` was added to address this gap. After actual native event persistence, fault injection exceeds the access recorder limit and checks restoration of all roots/logs/nonces/gas, including checkpoint reservations and claim payout/nullifier.
* Fixed gas, explicit limits, and a StateDB resource recorder exist. No performance results measure BLS time, peak Go/C heap, or sustained CLX verification budgets at maximum input.

## Authentication and accounting boundaries

Deposit entries are stable 223-byte data defined by [protocol/inbox.go](../../dex/protocol/inbox.go) and the [native funding payload](../../dex/protocol/native_tx.go). They include chain/genesis/DEX/custody, authenticated sender/nonce/action index/payload, consecutive index, owner, native asset, amount, and bucket. They do not include the current block hash. The native payload includes TX.value as well as calldata, so an alternative execution differing only in value for the same sender/nonce/index still changes SourceID. Block inclusion is established by a separate state proof.

CLX-side [nativeAccept](../../dex/settlement/native_accept.go:14) checks ancestor hashes preceding the executing block with `GetHash(height)`. It does not consult the current RPC head. The initial anchor uses a verifier built from the actual genesis header, persisted config corresponding to the genesis commitment, and CLX genesis key hash. A DEX's self-reported committee or deposit total is not evidence. Reusing an authenticated anchor still checks consecutive cursors, authenticated count, immutable entries, and inclusion height. A DEX proof failure after anchor persistence rolls back through the `RunNative` snapshot.

[clxevidence/finality.go](../../dex/clxevidence/finality.go:192) reconstructs signed content from actual CLX block RLP and verifies `SignInfo` every time. Since CLX header hashes exclude SignInfo, a matching hash alone is not authentication. It verifies every ancestor block's QC, parent connection, bounded descendant QC sequence from the target, and final consecutive views under the existing FHS 2-chain rule. A single QC is rejected. Registrations are deep-copied, selecting a fixed snapshot for the historical height/KeyHash. Native v2 is a fixture with a fixed CLX committee and fixed DEX epoch 1, not an implementation of public rotation.

[clxevidence/inbox.go](../../dex/clxevidence/inbox.go:234) verifies MPT inclusion of the custody account against the finalized header's state root, then matches count and entry hashes against the authenticated account's storage root. It does not accept RPC-reported `storageHash`, balance, or slot values. Even empty ranges authenticate account/count. Verified objects have private fields, and header/entry getters return copies. An unverified proof builder's output alone cannot authorize credit.

[adapter.acceptVerified](../../dex/settlement/adapter.go:377) checks checkpoint/summary/previous root/cursor connections, custody, authenticated trader deposit totals, reservations, reward-period continuity, and accepted fee windows. It transfers among the 8 accounts U/Trader/Fees/Support/Insurance/Dust/Withdrawals/Rewards, rejecting negative values and u128 overflow. Rewards reserve half the period's fees plus funded support up to the fixture cap; margin and insurance do not fund rewards. The difference between total accounts and native custody balance is tracked separately as forced-transfer surplus and excluded from DEX backing funds.

[Adapter.Claim](../../dex/settlement/adapter.go:536) checks the leaf bound to the accepted checkpoint's domain and fixed owner/recipient/asset/amount, count-bound Merkle inclusion, ID nullifier, cumulative payout per checkpoint, and global reserve. A permissionless relayer may submit the claim but cannot change its recipient. A valid replay of the same leaf causes no additional payment; reusing an ID with a different leaf is rejected. Payout, bucket, cumulative amount, and nullifier share one StateDB snapshot.

CLX verifies this accounting boundary and committee proof. It does not independently prove per-account allocation, matching, margin, funding, or liquidation. Total-value conservation alone cannot prevent a malicious authenticated DEX committee from reallocating funds between accounts. A QC is not a Validity Proof.

## I05–I18 implementation and test mapping

`PASS(component)` means the relevant tests were rerun in this review. `SOURCE` means source inspection only. `PROCESS_PENDING` identifies items whose final real-process results must be checked independently of this review.

| ID | Implementation evidence | Execution evidence and limits |
|---|---|---|
| I05 | `protocol/inbox.go`, `protocol/native_tx.go:65`, `settlement/native.go:186`. Entries are separate from header/finality evidence. | PASS(component): inbox golden, `TestDEXNativeFundingSourceIdentityBindsSignedValue`. |
| I06 | `clxevidence/finality.go:268` → `inbox.go:234` → private `VerifiedRange` → `engine/native_inbox.go`. Native TX uses the same verification from `native_accept.go:43`. | PASS(component): `TestNativeFinancialProofDrivenCredit`, `TestVerifiedInboxStateProofRoundTripAndOwnership`. See process records for final results with evidence retrieved from real CLX RPC. |
| I07 | Checks ancestor chain, signatures, custody/domain, MPT root, and entry hashes. | PASS(component): unfinalized/orphan/genesis/amount/owner/custody/payload/slot/cursor negatives in `TestRejectUnfinalizedOrphanAndSameHashSignInfoBeforeCredit`. |
| I08 | Verifies SignInfo/QC/descendant signatures and parent connections independently of block hash. | PASS(component): same-header-hash SignInfo tampering, single QC, and child metadata tampering in that test. |
| I09 | `native_accept.go:22` cursor/range, `:53` proof matches actual entries, `:75` identity/height, `:91` root/total matching. | PASS(component): cursor gaps, owner/amount tampering, duplicate credit, empty anchor, unchanged legacy fixtures. |
| I10 | `vm.EVM.Call` owns native execution. DEX `Execution.Finalized` only persists Common-side participation records and holds no CLX StateDB reference. | SOURCE + PASS(component): simulation copy/resource-error rollback. Real behavior during separate DEX/CLX outages is PROCESS_PENDING. |
| I11 | `core/vm/dex_native.go` → `RunNative` → `nativeAccept` → `acceptVerified`, genesis activation and normal signed TX. | PASS(component): accounting/connection/signature failures. `reconfig/dex_financial_network_test.go` sends 18 native checkpoint TXs and reconciles reservations. Final status depends on process PASS. |
| I12 | `adapter.go:536` and `native.go:161`. Fixed recipient in the signed claim leaf. | PASS(component): recipient tampering, reserve excess, native transfer failure. The process scenario sends 1 withdrawal and 7 rewards as real TXs. |
| I13 | Replay with the same history hash is unchanged; different payload at the same sequence is rejected; nullifier IDs are unique. | PASS(component): checkpoint/reward history, duplicate claim, disk reopening. The final process replay receipt expectation mismatch was fixed; status awaits the final rerun. |
| I14 | Conservation across 8 accounts; EVM transfers native value once; normal gas/Common reward/burn paths remain. | PASS(component): conservation of native value/fees/support/insurance/dust. Actual TX wallets/nonces/gas/Common reward 1/5/burn remainder are reconciled with the independent integer ledger in `nativeLedger.send/reconcile`. PROCESS_PENDING. |
| I15 | Outer snapshot in `vm/evm.go:157`, handler snapshot in `settlement/native.go:115`, atomic adapter writes. Rejects alt calls/internal calls/create. | PASS(component): native deposit OOG/revert/resource failure, unconsumed reserve/nullifier after recipient overflow, simulation rollback. Added test injects outer failure after schema 3 checkpoint/claim writes and restores all roots/logs/nonces/gas. |
| I16 | Separates persisted genesis config from runtime config. Invalid local authentication context is a block error, not a TX revert. Durable publication of FHS canonical root/head. | PASS(component): `TestDEXNativeImmutableGenesisConfigAndLocalFailure`, etc. Separate cold StateDB reopen test: [durability record](clx-state-durability-regression.md). No overall PASS is declared here for 21-process finance, SIGKILL restart, or ETH synchronization. |
| I17 | `go list -deps ./core/vm ./dex/settlement` excludes `dex/engine` / `dex/devnet` / `dex/consensus` / `dex/accounting`. | PASS(static): [dependencies](results/integration-security-dependencies.txt). Actual engine counters 0/0/0 per CLX process are a separate process-projection assertion. |
| I18 | Call/evidence/QC/MPT/entry/storage limits below and gas/resource recorder. | PASS(component): codec/bounds negatives and fuzz seed corpus. Maximum-load time/heap measurement and long-running fuzzing were not run. |

## Work limits beyond 525 bytes

| Item | Current limit/behavior |
|---|---|
| Entire native TX calldata | 64 KiB. Checks 12-byte envelope, exact body length, zero reserved fields, and version/opcode. Rejects overlength before decoding. |
| Checkpoint body | 525-byte checkpoint + 456-byte finance summary + 2 lengths + DEX proof + CLX evidence. Fixed length alone is not the verification budget. |
| DEX proof | 16 KiB, target and 1–8 descendants, QC ref 2 KiB, signature/leader 128 bytes, canonical 7-member mask/threshold 5. At most 9 aggregate signature checks after all shape/edge checks. |
| CLX evidence | Offline API 4 MiB, 64 ancestor blocks from genesis, block 1 MiB, each finality 16 KiB / at most 8 descendants. Native TX has the stricter 64 KiB total limit. At most 9 QC checks per block, 576 for 64 blocks. |
| MPT | At most 65 nodes/path, 1024 bytes/node, 65 reader Gets, duplicate nodes rejected. Account + count + at most 128 entry paths gives at most 130 paths. |
| Inbox | At most 128 entries/import, 223 bytes/entry, 4096 total entries, consecutive cursor, index/owner/amount/domain/hash matching. |
| Claim | 239-byte leaf + index/count/depth + at most 10 siblings. Count-bound tree has at most 1024 leaves; index/count/depth must agree; native asset only. |
| Storage | At most 4096 checkpoints, 8 accounts, fixed-length blobs, 128 imported entries, 10 fee-window entries. History/nullifiers are bounded by accepted checkpoint/claim counts; this is not a long-term state-growth policy. |
| Gas/resource | Funding 250k, claim 350k, checkpoint 12m + 40/byte. Maximum call including ordinary intrinsic gas is 15,691,016 gas, below the Osaka limit. Also passes through the StateDB access/log/returndata resource recorder. |

Outer RLP raw-byte limits are checked before decoding, while inner slice counts are also checked afterward. The raw limit bounds allocation, but a 4 MiB allowance does not exactly represent actual Go/C allocator heap use. The figures of 585 signatures and 8450 MPT reader accesses conservatively combine individual limits; they do not claim all maxima can coexist within 64 KiB calldata.

This initial approach includes all ancestor evidence from genesis, so new anchors at height 65 and later cannot be accepted. Large ancestor blocks or TX data in evidence may reach the 64 KiB limit earlier. Reusing old anchors within 64 blocks does not imply indefinite operation. Rolling authenticated anchor/history updates are unimplemented; reaching limits stops operation and freezes funds. There is no automatic refund of historical balances or bypass of signature checks.

## Reruns in this review

```sh
GOCACHE=/tmp/common-dex-devnet.0wvjd5/gocache GOPROXY=off \
  go test -race -json ./dex/protocol ./dex/checkpoint ./dex/clxevidence ./dex/settlement -count=1
GOCACHE=/tmp/common-dex-devnet.0wvjd5/gocache GOPROXY=off \
  go test -race -json ./core ./core/vm -run '^TestDEXNative' -count=1
```

Results: 6 packages PASS, 46 ordinary tests and 3 fuzz seed groups, 96 subtests/seeds, 0 FAIL/SKIP. Proof-side package times: 1.070/1.308/1.604/2.039 seconds; core 1.879 seconds; core/vm 1.062 seconds. These are not benchmark values. This rerun excludes full isolated-process tests, long-running fuzzing, WAN/60-minute loads, public participation, external DA, oracle validity in real markets, and production recovery.

For the additional I15 test, see [core/dex_native_rollback_test.go](../../core/dex_native_rollback_test.go) and [additional results](results/native-checkpoint-claim-rollback-race.jsonl). Starting from a StateDB created by a normal signed native deposit, it builds 5/7 target+child QCs and MPT evidence using actual CLX/DEX codecs, then passes valid schema 3 checkpoints/claims through the real EVM path. A test observer checks state after native event persistence, then makes the real access recorder perform bounded extra reads. It does not directly inject authentication results, accepted checkpoints, entries, or nullifiers. Successful reexecution of the same signed TX and claim replay marker=0 also confirm that the fault did not consume the nullifier. This unit fixture owns 7 signing keys and is distinct from an experiment using network-finalized proofs. The first compile attempt failed because the test fixture passed `types.NewBlock` arguments in the wrong order; after correction, results were PASS for the ordinary test in 0.136 seconds and the additional race test in 1.389 seconds (1 ordinary test / 2 subtests). Do not count this as a preexisting defect.

## Remaining trust and halt conditions

Trust remains in the DEX committee proof, fixed CLX committee, fixture registration keys, native config/upgrade mechanism, oracle, and data holders. This fixed fixture does not solve unrestricted public-key registration, Sybil resistance, or proof of key ownership for public committees. Computational proofs, permissionless public participation, a trustless bridge, safe escape of all perp balances, SLAs/APY, and superiority over Hyperliquid remain unmet or unevaluated.

A data root is not successful data retrieval. Even valid proofs can leave withdrawals frozen due to DEX/DA outages, retention periods, unimplemented anchor updates, or unsettled positions/loss handling. Do not add automatic signature-only fallback or blanket refunds of old balances. Keep ordinary CLX separate from full DEX execution and retain these conditions as devnet limits.
