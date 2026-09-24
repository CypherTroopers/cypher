# Common / CLX Lifecycle Source Audit

Target: local HEAD `70862a71dfaf2b00694dc1354c6a64e9504d7db5`. This document records source inspection; the candidate tests below are not treated as PASS. Operational data, keys, and configuration were neither read nor written.

## Call Graph and Impact Table

| Area | Actual path/evidence | Implication for the DEX boundary |
|---|---|---|
| Configuration | `cmd/cypher/config.go:107` defaults → TOML load → `SetNodeConfig` → `node.New` → `SetEthConfig`. At `:149`, dumpconfig truncates the specified destination. | Do not write DEX-specific settings into existing dumpconfig/operational configuration. |
| Common synchronization | `eth/backend.go:680` Ethereum.Start → `eth/handler.go:284` ProtocolManager.Start → chainSync.loop / txsyncLoop64. At `eth/sync.go:290`, FHS uses FullSync against the executed canonical head. | Retain with DEX OFF. Do not remove existing CLX execution verification. |
| PoW startup | `eth/api.go:420` miner.start → lifecycle mutex → wallet key pair → `ReconfigBackend.MinerStart` → PoW result transport → `Ethereum.StartMining` (`eth/backend.go:604`) → `Miner.Start` (`miner/miner.go:74`) → worker.start | Do not add DEX startup or eligibility to this path. |
| PoW worker | At `miner/worker.go:129`, worker.start performs existing UDP connectivity checks, key-head subscription, autoCommit, and agents.Start. At `:156`, stop cancels the PoW context. | Do not change existing PoW-start semantics or ColossusX computation. |
| PoW shutdown | `eth/api.go:494` miner.stop → SetThreads(-1) → PoW transport stop → StopMining → MinerStop → `reconfig/service.go:732` service.stop | Keep separate from DEX stop. |
| CLX FHS | `reconfig/backend.go:105` New → `reconfig/service.go:215` Hotstuff manager → `:218` SetCommitteeConfig. service.start (`:636`) handles identity, WAL replay, membership, peer authentication, and pacemaker. Common nonmembers keep FHS stopped (`:681`). | Do not substitute creation of a second CLX Service for DEX. |
| RPC admission | `eth/api_backend.go:288` shouldRecordCommonRPCAdmission requires nonzero ServerCoinBase and CLX IamMember<0; it does not consult IsMining. At `:616`, batch → bounded live ingress → signer/recipient snapshot → signed durable intent → pool publication → outbox. | Do not require PoW for RPC or mix DEX membership into this decision. |
| Signer and recipient | `eth/common_rpc_reward.go:66` WithServerCoinBase → account-scoped Registry.Recipient → WAL retry reuse / SignCommonRPCAdmissions. `internal/ethapi/common_rpc_reward.go:41` is IPC-only and sets the recipient after validating the signer password. | DEX vote keys/reward recipients need separate values and APIs. |
| Shared setter | `eth/backend.go:568` SetEtherbase changes etherbase, miner coinbase, and bftview ServerCoinBase together. | DEX configuration must not call it. |
| Reward-configuration persistence | `commonrpcreward/registry.go:55` uses JSON per chainID/genesis. At `:171`, Set publishes only after validation/fsync/atomic replacement succeed. Existing PoWRewardRecipient reads the same registry (`eth/backend.go:580`). | Preserve current PoW/RPC recipient relationships; do not add DEX to the registry. |
| L1 execution before voting | `core/blockchain.go:1973` Process → `:1981` ValidateState → VerifiedProposal. FHS commits are at `:2025` /`:2046`. | Putting order TXs on L1 restores heavy re-execution. L1 handles only bounded checkpoints/custody. |
| Shutdown order | `eth/backend.go:430` registers lifecycle components in eth → reconfig → txIngress → PoW ingress order. `node/node.go:278` stops them in reverse. reconfig.Stop (`reconfig/backend.go:169`) drains the content writer. Ethereum.Stop (`eth/backend.go:701`) closes the DB/chain it owns and lends to others. | DEX closes its own workers/WAL/queues, not shared CLX DBs. |

## Same-Process Open Issues and Execution Boundaries

`m_config` in `reconfig/bftview/committee.go:105` is package-global. SetCommitteeConfig (`:139`) overwrites DB, key chain, service, and cache; SetServerInfo (`:152`) and SetServerCoinBase (`:164`) change CLX identity. These cannot be reused for a second DEX committee.

DB, signer, and finalized lookup in `core/common_rpc_admission.go:150` /`:309` /`:325` are also process-global. A test starting a second Ethereum backend in the same process cannot prove separation of the two domains.

`crypto/bls/bls.go:40` explicitly states that Init is not thread-safe. The GetPublicKey map cache is commented out and is not classified as an active race. BLS initialization/concurrent key usage and CPU/RAM/IO bounds need further verification. A new runtime without imports from existing CLX packages is a candidate isolation boundary. Do not declare an unimplemented sidecar or complete context separation safe merely because it is proposed.

HotStuffApplication (`reconfig/hotstuff/hotstuff.go:243`) is the starting point for reuse investigation. CalcThreshold (`:461`) uses `(n+1)*2/3`; committee-size checks at `:465` require n=3f+1 (including 1) and enforce an upper bound. The 7-member fixture threshold is 5. A single QC is not finality. FHS safety state resides in the CLX chain DB (`reconfig/service.go:187`) and checks chainID/genesis (`reconfig/fhs_persistence.go:502`). DEX requires a dedicated WAL and additional domain identification.

## Candidate Regression Tests and Current Status

No tests were run as part of this source investigation. Execution results follow the shared results records for the work.

| Package / Test | Behavior protected | Execution status in this investigation |
|---|---|---|
| `./params` TestFairHotstuffConfigAllowsCommonRPCWithoutRegistration / TestFairHotstuffConfigRequiresSeedAndThreeFPlusOne | Optional Common participation, existing threshold | NOT_RUN |
| `./commonrpcreward` TestRegistryDurabilityIdentityAndValidation / TestRegistryDirectorySyncFailureRestoresPreviousFile | Chain-specific recipient configuration and persistence on failure | NOT_RUN |
| `./miner` TestPoWCandidateRewardRecipient / TestPoWCandidateRecipientSnapshotSurvivesSettingChanges / TestPoWCandidateConcurrentAccountChanges | PoW recipient snapshot | NOT_RUN |
| `./eth` TestCommonRPCNodeStartsBeforeAccountCreationAndPersistsIndependentAdmissions | Common startup without PoW, required recipient, unlock, durable admission | NOT_RUN |
| `./eth` TestCommonRPCRewardHTTPIPCChangeAndRestart / TestCommonRPCPoWRewardRecipient / TestCommonRPCRewardSnapshotExcludesIdentityWriter | RPC configuration persistence, existing PoW/RPC identity | NOT_RUN |
| `./eth` TestTransactionIngressLifecycleStopsExactlyOnce / TestFHSProtocolManagerUsesFullSync / TestFHSSyncDoesNotResumeFastSync | Shutdown / FullSync | NOT_RUN |
| `./reconfig` TestFHSRestartRejectsConflictingSameViewVote / TestFHSSyncCallbackDoesNotWaitForLifecycleLock | Durable anti-equivocation, separation of synchronization and lifecycle | NOT_RUN |
| `./reconfig/hotstuff` TestFHSPrepareQCCertifiesWithoutDecideCommit / TestFHSSevenNodesRestartDoesNotEnableConflictingQC | QC/finality distinction, restart | NOT_RUN |

`eth/common_rpc_open_access_test.go:141` is a suitable fixture using t.TempDir, loopback, NoDiscovery, MaxPeers=0, and an offline route provider. The overall environment audit owns records protecting running operational-node processes/datadirs.
