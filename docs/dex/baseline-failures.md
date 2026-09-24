# Independent Audit of Existing forkid Baseline Failures

Investigation date: 2026-09-21 UTC. Target HEAD: `70862a71dfaf2b00694dc1354c6a64e9504d7db5`.
Existing source/tests/genesis were unchanged. Operational datadirs, running-node RPC, WALs, and keystores were not accessed.

## Findings and Effects on Project Phases

Existing `TestCreation` / `TestValidation` failures in `core/forkid` are explained by fixed expectations for old Ethereum networks disagreeing with genesis/fork settings in the current Cypherium `params`. They are not new regressions caused by DEX changes. The relevant source/tests match HEAD, and both the pre-change `baseline-isolated-tests.log` and this rerun show the same failures.

This does not mean all failures can be ignored or that all CLX peer compatibility is sound. The audit separately reproduced an existing `newFilter` false rejection exactly at a fork height. Treat section 4 below as an independent unresolved issue.

* **Individual prerequisites for B without funds**: These failures do not directly prevent testing independent DEX FHS/context and bounded checkpoints. DEX consensus/proof does not call `core/forkid`. New isolated CLX fixtures must be checked against their actual genesis/config; Ethereum expectations are not the correct CLX values.
* **Completion of B overall**: This audit alone does not make B's CLX progress, independent roles, or restart/partition tests PASS. The full baseline suite remains recorded as FAIL. Explaining existing failures is distinct from satisfying B's acceptance conditions.
* **Prerequisites for C**: Before connecting native custody/actual CLX settlement, verify the new isolated CLX chain's actual genesis, peer handshake, synchronization, and finality progress. This memory-only fork-ID self-filter is not a network test. Fixtures with positive-height forks are affected by the boundary issue below. Do not assume an operational chain has the same config.

## 1. Observed Existing Failures

Original record: `results/baseline-isolated-tests.log:12-71`. This rerun: `results/baseline-forkid-audit-tests.log`.

```
GOCACHE=/tmp/common-dex-accounting-go-cache go test -count=1 -v ./core/forkid
```

Results: `TestCreation` and `TestValidation` FAIL; `TestEncoding`, `TestGatherForksIgnoresNonPositiveBlocks`, `TestGatherForksNilConfig`, and `TestNewIDWithNilConfig` PASS. Package FAIL (0.050s in this run). Failures were not relabeled PASS and tests were not skipped.

`TestCreation` references `params.*ChainConfig` and `params.*GenesisHash`, while its expectations fix old Ethereum-network history such as Homestead 1,150,000, DAO 1,920,000, and Byzantium 4,370,000, explicitly described in the file's comments (`core/forkid/forkid_test.go:33-120`). `TestValidation` also submits the same old checksum sets against current Mainnet params (`:132-205`).

## 2. Actual Params and Corresponding Failures

An independent read-only diagnostic program printed current configs, genesis values, CRC32 values, and positive-height forks. Input source: `params/config.go:35-38`, `:63-80`, `:92-108`, `:133-153`, `:184-201`. Raw output: `results/baseline-forkid-audit-values.log`.

|Params name|Chain ID|Current genesis CRC32|Current positive-height block forks|Difference from old tests|
|---|---:|---|---|---|
|Mainnet|16166|`5705bf8f`|None|Old expectations: initial `fc64ec04`, next fork 1,150,000. Current genesis is `e8186a…`, with all forks 0.|
|Ropsten|16164|`04e4bab1`|None|Old expectations: initial `30c7ddbc`, next fork 10. Current genesis is `1d2bc3…`, with all forks 0.|
|Rinkeby|4|`3b8e0691`|1, 2, 3, 103, 366, 432, 543|The first 3 entries match, but old expectations use next fork 1,035,301 and others; current settings use 103 and others.|
|Goerli|5|`a3f5ab08`|156|Initial checksum matches, but the old expected next fork is 1,561,651.|

`newID` starts from genesis CRC32 and adds positive-height forks already reached (`core/forkid/forkid.go:80-97`). `gatherForks` excludes 0/nil (`:216-257`). Thus current Mainnet values are `{5705bf8f 0}` at all tested heights, and Ropsten values are `{04e4bab1 0}`, exactly matching baseline logs. This input mismatch also explains `TestValidation` returning `local incompatible or needs update` for old Mainnet checksums.

This is not a proposal to mechanically change expectations to current settings. Future repairs should separate self-contained explicit configurations testing the general fork-ID algorithm from CLX-specific genesis/upgrade fixtures. Do not change CLX genesis or operational settings to match unrelated Ethereum values.

Source verified identical before the changes and at this audit:

|File|Current SHA-256 (unchanged from HEAD)|
|---|---|
|`params/config.go`|`f9e663ae25aa3b6432aee515c88205b1f6b57d6b0272529ba6cc1c472b13e988`|
|`core/forkid/forkid.go`|`d41ae061183f3568631de10a3594d57e945fde237f7f7bb02846be663b872d5a`|
|`core/forkid/forkid_test.go`|`b2fd8e02be8caf4105f31b624552f4d0305823285ff9aba1b286cb872e1cb473`|

`git diff HEAD -- core/forkid params/config.go core/genesis.go` is empty. Mainnet/Ropsten names alone do not identify current operational CLX genesis values.

## 3. Repository CLX Genesis Fixtures

Repository-root `genesis.json` is a fixed-committee/rotating-leader fixture with `chainId=10101919` and `fairHotstuff=true`. Block forks and timestamp forks are active from genesis, distinct from `chainId=16166` in the Mainnet constants above. `cmd/cypher/genesis.json` uses chainId 10 and `cmd/cypher/genesisLocal.json` uses 12367; do not conflate similarly named files.

Reading the root JSON and generating only in the memory database of `core.Genesis.ToBlock(nil)` gave:

```
genesis hash = 0xe69022ef43f6d238846015e0a4e7cdd190cf45e9fd98cfa0666acb482a05017e
chain ID     = 10101919
fork ID      = f6d70575 / next 0
positive-height block forks = []
NewFilter(same fixture)(NewID(same fixture)) = nil
```

This hash was recalculated from the fixture's source JSON; it was not obtained from block 0 of a running CLX node. Running-node genesis remains **NOT_VERIFIED**. JSON-file SHA-256: `131acbb21ef77f4229c91a639c51348bc1d0f0f5b6c4cbf4299e46c90efd4b1f`; contents were unchanged.

Actual nodes use their blockchain's real genesis/config through `forkid.NewID(blockchain)` / `NewFilter(blockchain)` (`core/forkid/forkid.go:69-74`, `:101-108`, `eth/handler.go:128`, `:356`). Handshake checks network ID/protocol version/genesis before calling the fork filter (`eth/peer.go:720-753`). This path does not replace operational-chain values with `params.MainnetGenesisHash`. `SetupGenesisBlock` also checks consistency between the existing DB genesis/config and supplied genesis (`core/genesis.go:199-289`).

Additional existing CLX genesis tests ran unchanged:

```
GOCACHE=/tmp/common-dex-accounting-go-cache go test -count=1 -v ./core \
  -run '^(TestCypheriumCustomGenesisConfigPinsUpgradeSurface|TestCypheriumModernForkConfigDecoding|TestSetupGenesisRejectsFairHotstuffSeedReplacement|TestSetupGenesisRejectsFairHotstuffCommitteeReplacement|TestSetupGenesisRejectsFairHotstuffActivationChange|TestSetupGenesisRejectsMissingStoredFairHotstuffConfig)$'
```

All 6 PASS. Raw results: `results/baseline-clx-genesis-audit.log`. These test genesis commitment/config immutability, not actual network handshake, synchronization, or deposits/withdrawals.

## 4. Separately Reproduced Existing Fork-Boundary Issue (Unfixed)

The following independent input reproduced false filter rejection. This is distinct from the causes of `TestCreation` / `TestValidation` failures above.

```
same genesis, same config, one known HomesteadBlock = 8
local head = 8
remote head = 7, remote advertises pre-fork checksum and Next = 8
NewFilter(local)(NewID(remote)) => local incompatible or needs update
```

The local node has applied a known fork; the remote node knows the same fork and is 1 block behind. The function's documented subset-compatibility rule should accept this combination, but `newID` considers `fork <= head` applied while `newFilter` advances its search only for `head > fork` (`core/forkid/forkid.go:87`, `:160`). At equal height, it compares the pre-fork checksum and rejects at the subsequent `head >= id.Next` check (`:168`).

The impact is false rejection of compatible peers at positive-height block-fork boundaries. The root genesis fixture examined here has no such forks and does not meet this reproduction condition. This is existing code, not a change introduced by DEX. This audit did not repair source/tests. Future general CLX fork/peer compatibility work requires an independent regression test and fix review.

## 5. Reproduction Artifacts and Unexecuted Scope

Diagnostic source: `results/baseline-forkid-audit.go.txt`. It uses `.txt` so Go builds do not mistake docs for a package. It does not replace existing tests/implementation and can be copied to `/tmp` and run as follows.

```
cp docs/dex/results/baseline-forkid-audit.go.txt /tmp/common-dex-forkid-audit.go
GOCACHE=/tmp/common-dex-accounting-go-cache go run /tmp/common-dex-forkid-audit.go
```

Executed: reproduction of existing forkid failures; printing/CRC calculations for 4 network params; memory-only root-genesis generation and self-filter; independent exact-fork-boundary reproduction; 6 existing CLX genesis tests.

Not executed: running-node genesis comparison, actual peer handshakes, fork compatibility under partitions/restarts, future timestamp-fork compatibility, native custody/deposits/withdrawals, or C/D integration acceptance. This audit does not mark those PASS.
