# Native TX v2 execution audit

This records the new genesis-enabled path separately from the earlier direct
StateDB fixture. It is not a production approval or an A–D completion statement.

## CLX execution boundary

`core.ApplyTransaction -> core.NewEVMContextWithConfig -> vm.EVM.Call ->
settlement.RunNative` uses the authenticated standard transaction sender/nonce,
ordinary EVM value transfer, snapshots, receipt finalisation and gas accounting.
The reserved address participates in the precompile-address selector and access
list, preventing the plain-value-transfer shortcut from bypassing its dispatch.
DEX workload flags are absent from this call graph. The only activation input is
the genesis-committed `ChainConfig.DEXDevnet` value and execution block number.

`go list -deps ./core/vm` and `./dex/settlement` include neither `dex/engine`,
`dex/devnet`, `dex/accounting` nor `dex/consensus`. Raw package lists:
[VM](results/native-vm-dependencies.txt),
[settlement](results/native-settlement-v2-dependencies.txt).
Native verification includes financial bucket arithmetic and bounded signature/
MPT verification, without matching, margin, funding or liquidation execution.

## Historical context and circularity

`NewEVMContextWithConfig` obtains regular genesis header0 from the execution
chain's immutable historical reader. `BlockChain.DEXGenesisKeyHash` obtains
keychain header0, checks missing keychain explicitly, and never reads its head
or current committee. A missing trust anchor rejects financial evidence; no
caller-supplied committee/genesis fallback exists.

Ordinary Common replay exposed a real integration bug: `eth.New` rewrites
`ChainConfig.RnetPort` with a node-local port, while the genesis commitment
includes that field. Rehashing the runtime configuration in settlement caused
a revert receipt without the funding log, rejected by normal bloom validation.
The fix obtains a fresh configuration from the database under the canonical
genesis hash (`BlockChain.DEXGenesisConfig`) and passes it separately through
the EVM context. Its complete commitment must match the historical genesis.
Runtime configuration must match it after substituting only the two existing
local fields, `RnetPort` and `EnabledTPS`; DEX activation, registry, chain ID and
fork overrides fail closed. Missing/corrupt configuration produces an outer
execution error before funds, nonce or gas change, never an alternative revert
receipt. Regression tests also check that a returned config cannot mutate its
database source through aliases. Genesis commitments and block validation were
not weakened. The pointer-keyed modern fork side table is detached immediately
after each historical config read and registered only on short-lived private
copies during authentication/execution; it cannot retain one config per native
transaction. A modern-fork regression checks authentication and execution after
detachment.

Funding identity review also found that hashing empty funding calldata alone
did not bind `TX.value` in `InboxEntry.SourceID`. The native handler now hashes
the canonical91-byte funding payload (version, authenticated sender/owner,
amount, native asset, bucket and call), fixed in independent Python vectors
before the Go change. Six vectors bind individual economics changes; an actual
signed-transaction test executes two alternative states with identical
sender/nonce/index and different values, requiring different source IDs.
The entry format and generic envelope hash remain separate.

Latest component validation for these changes:
[native context/funding race results](results/native-genesis-context-funding-race.jsonl).
The reconfig RPC parity helper compiled; actual network execution is recorded
by the caller's integration log, not implied by compilation.

For a newly certified inbox anchor, the handler compares its height/hash to
`GetHash` of the block branch being executed, within64 heights and strictly
before the execution block. The evidence verifier separately authenticates its
actual FHS finality and storage root. A cached anchor/count is immutable native
state. The genesis anchor has a known empty inbox by construction.

The initial CLX regular genesis commits configuration seed and reserved account
nonce, while the initial DEX root is derived later from that seed plus the actual
CLX genesis/domain. Inbox entries use sender/nonce/payload/index identities and
never their containing block hash. Neither calculation requires a fixed point.

The current offline evidence format starts from genesis and allows64 ancestry
blocks; it is a finite devnet fixture. Empty-range proofs support refreshing an
anchor within that range. A long-running rolling-anchor protocol is not implied.

## Work and gas bounds

Input is at most64KiB. Funding has no variable body, claims at most10 siblings,
and a checkpoint carries at most16KiB of DEX finality proof. DEX finality contains
one target and at most8 descendants, hence at most9 aggregate signature checks.
CLX evidence permits at most64 signed blocks, each with a target and at most8
descendants: at most576 aggregate signature checks before the DEX checks.
The independent64KiB transaction limit further restricts encodable combinations.
The fixed trusted registry has7 members; proof input cannot enlarge it.

An inbox range has at most128 entries. Account/count/each entry MPT paths have
at most65 nodes, each at most1024 bytes, and a bounded proof reader. The complete
native calldata limit applies before nested decoding. Local shape/connection
checks and verifier shape passes precede signature checks. Fixed trusted-key
parsing also has an explicit seven-member bound.

Execution gas is funding250000 / claim350000 / checkpoint12000000 plus40 per
calldata byte, on top of normal intrinsic gas. At64KiB, worst-case checkpoint
execution plus ordinary all-nonzero intrinsic gas is15691016, below Osaka's
16777216 transaction gas limit. This is a conservative fixture schedule, not a
measured market gas price or a claim of wall-clock performance. Working memory
reserves4MiB plus calldata against the VM's configured memory limit. Independent
codec collection bounds remain mandatory; C-library allocation safety is not
established merely by Go's race detector.

All state accesses/logs go through the supplied VM StateDB wrapper. The native
adapter does not unwrap MVCC/resource guards. Existing per-transaction and block
access/log/compute limits can reject a large otherwise well-formed request; the
protocol maxima are not promises that all maxima fit simultaneously.

## Call, estimate and trace

`eth_call` and `eth_estimateGas` use `EthAPIBackend.GetEVM`, which passes the same
header/genesis context and native handler. `isActivePrecompile` prevents the
21000-gas EOA fast path even for an empty invalid native call. The newly added
`core.NewEVMForNativeSimulation` applies the same native access/log/memory/output
guards when this system address is the target, with snapshot rollback on guard
failure. Other targets keep their previous simulation behavior.

Blockscout trace uses `core.ApplyTransaction` directly. Legacy `traceTx`, standard
trace-to-file and transaction-prefix replay now use the same native simulation
guard helper. Top-level CaptureStart/CaptureEnd reports native execution, return
data and gas; the system operation is not fabricated into EVM opcode steps.

RPC `from` and state overrides are simulation inputs. An override of custody,
balances or sender cannot modify canonical state or create a finalized deposit
proof. Result bytes from simulation are not a native deposit receipt. Actual
state effects require an accepted signed transaction and subsequent CLX finality.

## Verification records

[native-tx-race.jsonl](results/native-tx-race.jsonl) records the initial core/VM,
config, codec and legacy adapter race checks. Signed transaction tests cover
value, nonce, gas, receipt/logs, replay, restart, OOG/revert, simulation/trace,
resource guard enforcement, alternate CALL contexts, reserved creation, actual
SELFDESTRUCT surplus, and wrong-chain signatures.
[native-simulation-parity-race.jsonl](results/native-simulation-parity-race.jsonl)
also passes: seven native core tests (including simulation resource parity and
activation/genesis binding) plus the two existing Blockscout trace regressions.
Real RPC/CLX process results are recorded separately by the integrated network
test; these component logs alone do not prove that network scenario.

The v1 direct adapter tests remain intact. No existing operational genesis,
keystore, chain database or binary is written by these tests.
