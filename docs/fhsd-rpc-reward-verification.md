# FHS-D integrated RPC/reward verification record

## Scope and baseline

The working branch is `FHS-D`, with starting HEAD `1857c9fee48d3e37764dd1874a2acf5e27731bdd`. The initial status, branch, HEAD, diff, Makefile, CI configuration, and existing test conventions were inspected. No applicable AGENTS.md was found in the repository or its parents.

The implementation follows the updated requirement: restart the network from a fresh genesis and use one mandatory signed reward-recipient rule. It does not retain reward activation scheduling, historical RLP compatibility, or a payout-to-A fallback. All Japanese repository text found in the source/documentation scan was in the two new documentation files; both are now English.

The pre-existing changes to `build/bin/cypher` and `build/bin/cypher-linux-amd64` remain untouched. No checkout/reset/clean/stash/pull/merge, commit, push, PR, deployed-binary update, operational node restart, live account unlock, or real transfer was performed. Tests use generated keys, temporary databases, and local endpoints.

## Implementation map

| Area | Main files | Behavior |
|---|---|---|
| Public RPC registration | `node/rpc_public.go`, `node/node.go`, `node/rpcstack.go`, `rpc/server.go`, `rpc/service.go` | Shared explicit method registration boundary for HTTP, WS, and HTTP/3, independent of namespace/exposeAll settings |
| Transport identity | `rpc/transport.go`, `rpc/client.go`, `rpc/http.go`, `rpc/inproc.go`, `rpc/ipc.go`, `rpc/ipc_unix.go`, `rpc/ipc_windows.go` | Server-established IPC/in-process/network identity; unknown transports do not gain local privileges |
| IPC registration | `internal/ethapi/common_rpc_reward.go`, `commonrpcreward/registry.go`, `commonrpcreward/persist_unix.go`, `commonrpcreward/persist_windows.go`, `accounts/keystore/keystore.go` | Local ECDSA password reauthentication, strict B validation, chain-scoped durable registration without changing A's unlock lifetime |
| Console | `console/bridge.go`, `console/console.go`, `internal/web3ext/web3ext.go` | Both personal methods and hidden password prompt |
| Admission and delivery | `eth/common_rpc_reward.go`, `eth/api_backend.go`, `eth/backend.go`, `eth/tx_ingress_wal.go`, `eth/tx_quic_ingress.go`, `reconfig/bftview/committee.go` | Mandatory A/B snapshot, immutable local proof reuse, WAL ownership through fsync, shared public HTTP/3 handler |
| Proof and reward encoding | `core/types/common_rpc.go`, `core/types/common_rpc_encoding.go`, `core/types/block.go` | One Version=2 format binding B into signature, ID, encoding, and roots; old formats rejected |
| Consensus and payout | `core/common_rpc_admission.go`, `core/block_validator.go`, `core/fhs_sidecar_handoff.go`, `core/state_processor.go`, `reconfig/txblock.go` | Proof/reward A/B matching through caches, proposals, and import; deterministic direct payment to B after all TXs |
| Fresh genesis | `params/config.go`, `params/modern_config.go`, `genesis.json` | v3 genesis commitment domain, no reward activation field, explicit rejection of obsolete activation options |
| RPC outputs | `internal/ethapi/api.go`, `eth/api.go` | `commonTxApprover` remains A; `commonTxRewardRecipient` exposes B alongside reward and burn |
| Tests and instructions | Related test files, `README.md`, both `docs/fhsd-rpc-reward-*.md` files | Mandatory-from-genesis, tamper, persistence, concurrency, transport, and full FHS regression coverage; English setup instructions |

The former `params/common_rpc_reward.go`, `core/common_rpc_version.go`, activation-transition hooks, fork-specific cache commitment, fork-ID tests for that optional setting, and legacy encoding/migration tests have been removed or replaced with unconditional-rule and old-format rejection tests. The new genesis changes its commitment without changing chain allocation, committee entries, or unrelated EVM fork settings. The non-FHS example genesis files are unchanged.

## Public methods and transport evidence

The complete allowed-method and subscription inventory is in the [operation guide](fhsd-rpc-reward-recipient.md#public-method-boundary). Reflection registration is tested against the allowlist, including promoted methods. `fillTransaction` does not sign; `ecRecover` only recovers a signer from a supplied signature. Services are shared, so the API split does not duplicate raw TX workers.

The existing methods excluded from public registration are:

| Namespace | Prohibited methods (namespace prefix omitted) |
|---|---|
| `eth` | `autoTransaction`, `rescueCommittee`, `resend`, `sendTransaction`, `sendTransactionWithOpts`, `sign`, `signTransaction`, `stop`, `subscribeSyncStatus` |
| `personal` | `deriveAccount`, `getCommonRPCRewardAddress`, `importRawKey`, `lockAccount`, `newAccount`, `newAccountEd25519`, `openWallet`, `sendTransaction`, `setCommonRPCRewardAddress`, `sign`, `signAndSendTransaction`, `signTransaction`, `unlockAccount`, `unlockAll` |
| `miner` | `setEtherbase`, `setExtra`, `setGasPrice`, `setRecommitInterval`, `start`, `stop` |
| `admin` | `addPeer`, `addTrustedPeer`, `exportChain`, `importChain`, `removePeer`, `removeTrustedPeer`, `startRPC`, `startWS`, `stopRPC`, `stopWS` |
| `clique` | `discard`, `propose` |
| `debug` | `backtraceAt`, `blockProfile`, `chaindbCompact`, `cpuProfile`, `freeOSMemory`, `goTrace`, `mutexProfile`, `setBlockProfileRate`, `setGCPercent`, `setHead`, `setMutexProfileFraction`, `startCPUProfile`, `stopCPUProfile`, `testSignCliqueBlock`, `verbosity`, `vmodule`, `writeBlockProfile`, `writeMemProfile`, `writeMutexProfile` |

Unimplemented typed-data/key-export aliases and newly added methods also remain unavailable unless explicitly reviewed and added to the allowlist.

| Transport | Node-wallet signing and transfers | B registration/read | Preserved behavior checked |
|---|---|---|---|
| localhost HTTP | `-32601` with funded, unlocked A and valid arguments | `-32601`, including forged headers | Raw single/batch/options, externally signed A TX, reads; actual-node HTTP admission through FHS finality |
| WebSocket | Connection messages, mixed batches, and notifications cannot invoke prohibited methods | `-32601` | Raw submission and subscription events |
| HTTP/3 | Actual TLS/QUIC HTTP/3 client receives `-32601`; test asserts `ProtoMajor == 3` | `-32601` | Raw submission and reads; full FHS finality over HTTP/3 itself is not a separate combined test |
| Actual IPC | Existing trusted wallet operations and unlock remain available with network RPC enabled | Successful after A password verification | Strict addresses, password failures, persistence failures, and restart |
| Trusted in-process | Existing trusted local operations retained | New methods return `-32601` | Kept distinct from IPC |
| Unknown codec / internal handler served through HTTP | No local transport identity granted | New methods refused | Caller headers cannot grant IPC privileges |

Prohibited notifications receive no response and cause no side effects. Allowed notifications retain normal execution. Tests also exercise empty modules, explicit dangerous namespaces, insecure-unlock, WS exposeAll, dynamically started network RPC, and inherited Go methods.

## Mandatory proof and payout semantics

The IPC commands are `personal.setCommonRPCRewardAddress(A, B)` and `personal.getCommonRPCRewardAddress(A)`. Omitting the setter password uses a hidden prompt for A; JSON-RPC requires the password string explicitly. No B secret is required. Preferences are stored by ChainID + GenesisHash + A in `<datadir>/<instance>/common-rpc-rewards/<decimal-chain-id>-<0x-genesis-hash>.json`.

All new admissions require `Version=2`, `Miner=A`, and nonzero `RewardRecipient=B`, with B distinct from A. Rewards require the same version, `Approver=A`, and matching B. There is no height-dependent path. A missing or unreadable preference fails new admissions while allowing node startup and reads. Already durable same-network proofs can be restored and retried without the current preference.

Admission RLP is the flat list `[Version, ChainID, GenesisHash, TxRoot, AdmissionID, Miner, RewardRecipient, KeyBlockNumber, Timestamp, TxHashes, Signature]`; reward RLP is `[Version, TxHash, Approver, RewardRecipient, ApproverReward, Burn]`. Unsupported or recipient-less data is rejected. The explicit version marker identifies one protocol, not a compatibility branch.

Signature payload, Admission ID, proof hash, and admission root bind B. Reward A/B/version must match the selected proof, including trusted-cache paths. The recipient-free winner ordering prevents B changes from improving the primary priority or tie-break. This makes no additional claim about Sybil resistance.

The fee split remains `actualFee = gasUsed * effectiveGasPrice`, `reward = floor(actualFee / 5)`, and `burn = actualFee - reward`. Proposal and import share the deterministic direct-credit implementation after all TXs execute. There is no A-to-B transfer or call to B's code. TX/receipt output distinguishes A, B, reward, and burn.

## Regression coverage

| Requirement | Tests and assertions |
|---|---|
| Public key-operation boundary | `node/rpc_public_test.go`, `rpc/transport_test.go`: real generated unlocked keystore A, sufficient balance, locally successful signing followed by HTTP/WS/actual-HTTP/3 rejection with no wallet side effects |
| Reauthentication and durable preferences | `accounts/keystore/password_verification_test.go`, `commonrpcreward/registry_test.go`, `internal/ethapi/common_rpc_reward_test.go`: bad passwords even while unlocked, invalid B, B=A, fsync/save failures, old-value retention, deadline preservation, foreign-wallet duplicate A |
| Hidden password input | `console/reward_bridge_test.go`: omitted/null password enters the existing private prompt; no B credential requested |
| Single-format commitments | `core/types/common_rpc_v2_test.go`: canonical round trips, unsupported/old-format rejection, B/B+ID/chain/TX tampering, recipient-independent winner ordering |
| Direct payment and execution order | `core/common_rpc_v2_test.go`: serial, parallel, and imported state roots match; distinct initial A/B balances, B's code not executed, later TX cannot spend earlier reward; proof/reward/cache tampering refused |
| Mandatory genesis rule | `core/common_rpc_genesis_test.go`, `params/common_rpc_recipient_test.go`, and format regressions: no reward activation field, first-block B required, obsolete scheduling options rejected, new genesis commitment validated |
| Real node, IPC, HTTP, and restart | `eth/common_rpc_reward_integration_test.go`: missing B at startup, raw U/A transfers, B-to-C update, locked-A old-proof reuse, corrupt-registry recovery, unique outbox, concurrent batches, deployment/call/options |
| Consistent snapshots and WAL ownership | `eth/common_rpc_reward_snapshot_test.go`, `eth/common_rpc_reward_wal_test.go`: concurrent IPC changes and signer changes, fixed A/B per batch, cancellation during fsync, checkpoint/restart identity retention |
| Abrupt Common process termination | `eth/common_rpc_reward_crash_test.go`: HTTP acceptance at B plus IPC C registration, then Process.Kill without Close/drain; separate process restores old proof bytes/ID and persisted C; repeated old TX has no duplicate outbox; new TX needs unlock and uses C |
| Real FHS finality and recovery | `reconfig/fhs_reward_process_test.go`, `reconfig/fhs_reward_network_test.go`, extended existing process harness: actual BLS, LevelDB, QUIC, seven validator processes, message loss and proposer termination recovery |

The full network test follows actual IPC registration and A unlock, public HTTP raw admission, proof/TX WAL, outbox, real TxQUIC, seven-process FHS finality, and HTTP `eth_getTransactionReceipt`. Transfer, deployment, successful call, and reverted call are compared across all validators. The Common keystore has neither U's key nor B's key; direct fixture TX injection into validators is checked to remain zero. The network test verifies receipts, gas, effective fee, status, contract address, roots, A/B, and reward. The separate `TestFHSProcessRecoveryRewardFinality` checks burn and the fee split explicitly. A receives no Common TX reward.

The Common crash test keeps its committee offline and verifies durability, recovery, and retry uniqueness. Final payout is verified separately by the seven-process test; it is not presented as one combined crash-then-seven-node-finality scenario.

## Verification environment and commands

Verification uses Linux amd64, Go 1.26.2, and the repository's actual BLS/MCL dependencies. Writable cache/temp paths avoid the environment's default GO111MODULE=off, read-only default cache, and full `/tmp`. Local socket tests run with the required execution permission, using only generated test data and local endpoints.

```sh
export GO111MODULE=on
export GOCACHE=/root/cypher/build/stage/fhsd-work/go-cache
export GOTMPDIR=/root/cypher/build/stage/fhsd-work/tmp
export TMPDIR=/root/cypher/build/stage/fhsd-work/tmp
```

The following checks were rerun for the mandatory-from-genesis implementation. Logs are under `build/stage/fhsd-work/`.

Public transport and registration checks passed with the race detector across all six packages (`unified-boundary-race.log`):

```sh
go test -mod=readonly -p 2 -race -count=1 ./rpc ./node ./accounts/keystore ./internal/ethapi ./console ./commonrpcreward -run 'TestTransportIdentity|TestPublicRPC|TestCommonRPC|TestRewardRegistrationHiddenPassword|TestVerifySigningPassword|TestRegistry'
```

The complete affected eth packages passed (`unified-eth-tests.log`), followed by the focused race suite including forced process termination and concurrent IPC updates, which passed in 87.697 seconds (`unified-eth-race.log`):

```sh
go test -mod=readonly -p 2 -count=1 ./eth ./eth/downloader ./eth/fetcher
go test -race -mod=readonly -p 2 -count=1 -run 'TestCommonRPCReward|TestCommonRPCLocal|TestTxQUICRewardRecipientRequiredIncludingDurableReuse' ./eth
```

Full params/types/core/rawdb checks and targeted race checks passed (`unified-core-full-local.log`, `unified-core-race.log`):

```sh
go test -mod=readonly -p 2 -count=1 ./params ./core/types ./core ./core/rawdb
go test -race -mod=readonly -p 2 -count=1 ./params ./core/types ./core -run 'TestCommonRPC|TestCommonTx|TestFHSSidecar|TestFHSBlockWorkMeterBoundariesAndOverflow'
```

All four existing-harness process tests passed in 140.729 seconds (`unified-reconfig-process.log`): SplitTC recovery 36.15s, OfflineProposer recovery 44.25s, RewardFinality 28.20s, and HTTPToTxQUICToFinality 32.07s. These are opt-in tests and were explicitly enabled:

```sh
CYPHER_FHS_PROCESS_RECOVERY=1 go test -mod=readonly -p 2 ./reconfig -run 'TestFHSProcessRecovery(SplitTC|OfflineProposer|RewardFinality)$|TestFHSRewardHTTPToTxQUICToFinality$' -count=1 -timeout=8m -v
```

The final shared worktree was independently checked through the complete HTTP-to-FHS network path again and passed in 35.785 seconds (`unified-network-final.log`):

```sh
CYPHER_FHS_PROCESS_RECOVERY=1 go test -mod=readonly -p 2 -count=1 -timeout=5m -v ./reconfig -run '^TestFHSRewardHTTPToTxQUICToFinality$'
```

The final combined command includes all eight requested packages plus params, rawdb, console, and the registry (`unified-required-final.log`):

```sh
go test -mod=readonly -p 2 -count=1 ./rpc ./node ./accounts/keystore ./internal/ethapi ./core/types ./core ./eth ./reconfig ./params ./core/rawdb ./console ./commonrpcreward
```

Eleven packages passed. `accounts/keystore` failed only the seven missing-fixture tests listed below, so the command's exit status is 1. The keystore reauthentication regressions passed separately with the race detector. No timing failures occurred in this final combined run.

Earlier integration failures were corrected before these final runs: single-format custom RLP decoders must return the end-of-list sentinel unchanged, and the reward work-meter boundary fixtures must include the mandatory version/recipient payload. Protocol limits and fee amounts were not increased to make the tests pass.

The official native build succeeded with freshly built pinned BLS/MCL libraries, module verification, and the BLS tests (`unified-build.log`):

```sh
JOBS=3 make cypher BINDIR=/root/cypher/build/stage/fhsd-work/unified-bin STAGE_ROOT=/root/cypher/build/stage/fhsd-work/unified-native-stage BUILD_TMPDIR=/root/cypher/build/stage/fhsd-work/unified-native-tmp
```

Outputs are `build/stage/fhsd-work/unified-bin/cypher` and `cypher-linux-amd64`. Existing native compiler warnings remain; the build exited successfully. The tracked distribution binaries were not overwritten.

The newly built executable also initialized the supplied `genesis.json` successfully in a newly created, empty temporary datadir (`unified-genesis-init.log`, exit 0). The exact temporary path is recorded in `unified-init-datadir.txt`; the invocation was:

```sh
/root/cypher/build/stage/fhsd-work/unified-bin/cypher --datadir <new-empty-temporary-datadir> init /root/cypher/genesis.json
```

This check did not reuse or modify any existing chain database. Final `git diff --check` passed, all 78 changed/new Go source files had no `gofmt -l` output, and the repository scan found no remaining Japanese text in source or documentation.

## Known baseline issues and limits

The starting HEAD independently reproduces seven keystore test failures caused by missing fixtures: `very-light-scrypt.json`, `v3_test_vector.json`, `v1_test_vector.json`, and a V1 key fixture. The affected tests are `TestKeyEncryptDecrypt`, `TestV3_30_Byte_Key`, `TestV3_31_Byte_Key`, `TestV3_PBKDF2_1`, `TestV3_Scrypt_1`, `TestV1_1`, and `TestV1_2`. The baseline record is `build/stage/fhsd-work/keystore-baseline.log`; existing tests were not weakened or replaced to hide those failures.

The pre-existing `core/forkid` tests `TestCreation` and `TestValidation` also have expected-value mismatches on the starting HEAD; all 56 failure lines matched the earlier working-tree run (`baseline-forkid.log`). The integrated reward rule no longer adds an optional fork schedule or depends on fork-ID activation detection.

Windows persistence has previously been cross-compiled, but actual Windows named pipe, ACL, and WRITE_THROUGH behavior has not been run here. Full-repository `go test ./...`, operational-data synchronization, and real power-loss filesystem testing are not claimed. The auxiliary `retesteth` test_* network API is excluded by the same default-deny allowlist and requires separate tooling consideration.

A remains unlocked inside the process when internal signing is enabled. OS or IPC compromise, out-of-scope rewards paid to A, and previously stolen keys or signed TXs remain outside this protection. No production restart, datadir deletion, distribution, or network reset was performed by this work.
