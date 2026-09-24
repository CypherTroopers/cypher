# Actual Common roles: prerequisite evidence and limits

Local source remains the protected baseline `70862a71dfaf2b00694dc1354c6a64e9504d7db5`; the DEX additions do not modify the existing miner, reward, or admission lifecycle.

## Real PoW resource boundary

`consensus/colossusX/algorithm.go:25` defines a 32 GiB genesis dataset, 8 GiB growth per epoch, and a 512 MiB initial cache. `consensus/colossusX/colossusX.go:623` requires the whole normal-mode dataset to be mmap-locked regardless of CLI lock flags. `:412` generates a missing full dataset before the subsequent lock attempt. Therefore merely pointing mining at a new temporary directory can cause substantial work and writes before failing the resource requirement.

Measured `/proc/meminfo` and `RLIMIT_MEMLOCK` are preserved in `docs/dex/results/real-role-resources.txt`. At the inspection, only approximately 24 GiB was available and the soft/hard memory-lock limit was 8 MiB. Normal-mode nonce search is NOT_RUN. Existing operational DAG/cache directories are not reused, lock limits are not raised, and the PoW algorithm is not changed.

`eth/backend.go:511` creates a normal-mode ColossusX engine without forwarding `PowMode`; changing a test config's mode would not select the small fixture engine. `colossusX.NewTester` is explicitly test-only (`consensus/colossusX/colossusX.go:538`) and reduces its dataset to 32 KiB (`:360`). A test using it cannot establish production PoW resource coexistence.

## Existing API semantics

`eth/api.go:420` PrivateMinerAPI.Start authenticates the configured account, installs the existing reconfig identity, starts the fixed-mode PoW result listener, then calls StartMining. `eth/backend.go:604` starts the real miner worker; `miner/worker.go:129` starts its event loop and CpuAgent. `PrivateMinerAPI.Stop` (`eth/api.go:494`) stops PoW and the existing CLX reconfig lifecycle. DEX is not attached to either operation.

`p2p/netutil/net.go:327` checks UDP using a local UDP dial, not a remote committee handshake. Common PoW startup does not require the seven CLX validators to be online. Successful candidate delivery and CLX acceptance still require the authenticated committee and are not inferred from `IsMining`.

`eth/api_backend.go:288` checks configured operational identity and non-membership in the CLX committee without checking IsMining. Common RPC requires the existing recipient registry, signer unlock, and durable admission pipeline. The existing `eth/common_rpc_open_access_test.go:141` supplies a safe loopback/temporary-datadir fixture with an explicit offline committee route. Admission acceptance can therefore be tested without pretending that the transaction reached CLX finality.

PoW resource shortage limits only the real PoW coexistence measurement. It is not a prerequisite for DEX participation or independent C-stage development. C-stage financial enablement remains unavailable because native settlement, trading, and participation accounting have not been integrated and tested, independently of PoW resources.

## Acceptance accounting

The `dex/runtime` eight-combination live-worker tests and the two-domain process test prove their stated boundaries. They do not prove all eight combinations of production-size ColossusX nonce search, public Common RPC collection, and DEX consensus under load. That stronger R01/P05 scope remains NOT_RUN until sufficient isolated resources and a real PoW proof-delivery fixture are available.

## Safe actual-API experiment planned before implementation

The additional opt-in test will use the actual Ethereum backend, IPC `miner_start`/`miner_stop`, optional loopback HTTP raw-transaction RPC, mandatory-recipient IPC registration, and real durable admission signatures. Normal ColossusX mode remains unchanged, but its dataset directory is deliberately empty: the existing dataset initializer must reject nonce search before any large allocation, and the test must observe that resource error. `IsMining=true` then means only that the real worker lifecycle started; the result must never be described as successful PoW hashing or proof delivery.

For DEX enabled cases, a separate test process runs seven actual `dex/consensus.Application` instances with separate WAL directories and the bounded deterministic-action message loop. This is one OS sidecar with seven registered fixture actors, not seven independent operators or a production transport. DEX disabled cases create no sidecar. All eight choices concern real API/sidecar lifecycle coexistence under explicitly unavailable PoW resources; they cannot replace the missing production-size PoW coexistence measurement. All sockets are limited to an isolated loopback-only network namespace and all data directories are newly created.

Implementation: `eth/dex_role_independence_test.go`. The non-opt-in compile check passed and the actual test was SKIP. The root task runs the opted-in command `CYPHER_DEX_ROLE_API_DEVNET=1 go test ./eth -run '^TestDEXActualCommonAPIEightCombinationsWithoutPoWDataset$' -count=1 -timeout=5m` inside unshare; only its captured result can establish this limited API experiment as PASS.

The root-task isolated run subsequently PASSed in 14.797 seconds; raw output is `docs/dex/results/real-role-api.log`. Its old three-bit subtest suffix encodes bit 0=PoW, bit 1=RPC, bit 2=DEX (so `001` means PoW on). The test names now spell out each Boolean to remove this display ambiguity; no behavior changed. This PASS remains limited to resource-unavailable PoW lifecycle plus actual RPC/DEX execution, with successful normal-size nonce search and proof delivery NOT_RUN.
