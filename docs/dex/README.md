# Common DEX — native CLX integration and continuous operation

Scope: `CypherTroopers/cypher` / `FHS-D-ExchangeCore`.
Starting HEAD: `70862a71dfaf2b00694dc1354c6a64e9504d7db5`. Deliverables are uncommitted working changes.

For implementation/deployment on the currently specified PM2 network, see the [live work record](live-status.md)
and [L01–L20](live-acceptance-matrix.md). The user's new authorization permits normal deployment,
targeted stop/restart, and test CLX operations on the specified development network. Intermediate init
requires separate approval. The evidence below is from earlier isolated tests and must not be reinterpreted as LIVE success.

For earlier continuous-operation development, see the [continuous record](continuous-status.md) and
[26-item matrix](continuous-acceptance-matrix.md). Final-source G3 achieved PASS through CLX 749, DEX/CLX 109,
72 claims, and custody 295. The 26 items are 25 PASS (limited scope) / O26 FAIL for protected-binary mismatch.
The [final-source test index](results/continuous-final-test-index.md),
[diff reproduction/review boundaries](continuous-review-bundle.md), and
[past failures/design changes](continuous-development-history.md) are also retained.
Earlier ordinary CLX integration results remain in the [integration record](integration-status.md)
and [acceptance matrix](acceptance-matrix.md). The earlier 7 FHS manager + StateDB fixture is preserved in
the [previous report](initial-devnet-report.md) and [previous matrix](initial-acceptance-matrix.md).
Historical `final-*.log/jsonl` files are the previous final logs, not PASS for the current new changes.
Integration-stage final tests are under `results/integration-final-*`; continuous-development evidence is
under `results/continuous-*`. Match source manifests and execution conditions even when PASS labels match.

Bounded checkpoint authentication and native custody accounting are connected to normal signed CLX TX
admission, Common admission, TxQUIC, block execution, and FHS finality. Local DEX participation defaults OFF.
DEX OFF CLX validating full nodes also verify genesis-enabled settlement under the same rules.
DEX runs on separate Common nodes with dedicated FHS/keys/WAL/real TLS transport; CLX does not reexecute
matching, margin, funding, or liquidation. There is no WCLX or additional CLX issuance.

Deposit IDs derive from authenticated sender/nonce/payload and related fields, excluding the current
inclusion block hash. DEX credits only after verifying both actual CLX-header FHS descendant finality
evidence and account/storage proofs against its state root. DEX callbacks do not modify canonical CLX StateDB.

* [Deposit IDs and CLX finality evidence](integration-deposit-spec.md)
* [Ordinary native TX codec, gas, activation](native-tx-spec.md)
* [Ordinary TX/simulation audit](native-tx-audit.md)
* [Schema 3 financial execution](native-financial-execution.md), [FIFO accounting](engine-spec.md)
* [Ordinary Common/sidecar API](financial-service-spec.md), [admission semantics](mempool-spec.md)
* [Real TLS/process fixture](financial-process-helper-spec.md)
* [Independent audit](integration-security-review.md), [missing rewards and market progress](reward-omission-market-review.md)
* [Bidirectional rolling anchors](rolling-anchor-spec.md), [fixed-committee key renewal](fixed-key-renewal-spec.md)
* [Persistent relay](relay-core-spec.md), [relay CLI](relay-cli-spec.md), [repeated financial scenario](continuous-g3-scenario.md)
* [Omitting reconstructible state and snapshot v2](compact-replay-spec.md), [local WAL v3 sharing identical actions](wal-action-dictionary-spec.md)

Connect ordinary startup with `--dex.validator --dex.config /absolute/manifest.json`.
Parent Common verifies its own chain/genesis and starts `dex-validator` from the same binary as a child.
`native-finance` is an explicit mode in isolated-devnet manifests; existing counter mode remains.
DEX APIs are loopback `/v1/actions`, `/v1/status`, `/v1/action-status`, `/v1/checkpoint`, and
`/v1/participation`. An ACK for a signed action is neither DEX finality nor CLX settlement.
CLX settlement TXs use existing `eth_sendRawTransaction`; there is no dedicated signature-bypass RPC.

Reproduction runner (outputs/binaries/datadirs use new `/tmp` locations):

```sh
DEX_TEST_GOCACHE=/absolute/owned/go-cache bash scripts/dex/check.sh unit
DEX_TEST_GOCACHE=/absolute/owned/go-cache bash scripts/dex/check.sh socket
DEX_TEST_GOCACHE=/absolute/owned/go-cache bash scripts/dex/check.sh cli-roles
DEX_TEST_GOCACHE=/absolute/owned/go-cache bash scripts/dex/check.sh native
DEX_TEST_GOCACHE=/absolute/owned/go-cache bash scripts/dex/check.sh financial
DEX_TEST_GOCACHE=/absolute/owned/go-cache bash scripts/dex/check.sh cli-financial
DEX_TEST_GOCACHE=/absolute/owned/go-cache bash scripts/dex/check.sh source
DEX_TEST_GOCACHE=/absolute/owned/go-cache bash scripts/dex/check.sh relay
DEX_TEST_GOCACHE=/absolute/owned/go-cache bash scripts/dex/check.sh continuous
DEX_TEST_GOCACHE=/absolute/owned/go-cache bash scripts/dex/check.sh baseline
```

Earlier `process` (unfunded pipe) and `roles` (8 real API combinations) remain. Network modes use new
Linux user/network namespaces and loopback only. Ordinary CLI packet-partition tests also require
iptables inside the namespace. Do not fall back to the host network if isolation fails.
Modules are cached; validation uses `GOPROXY=off`, `-mod=readonly`, and Go 1.27.1.
Normal PoW nonce search/32 GiB DAG generation are not runner prerequisites.

This uses committee signatures; QCs are not Validity Proofs. It depends on the fixed CLX committee,
DEX committee, Oracle, DA, and genesis/upgrade authority. Compared with the old devnet configuration's
64-ancestor limit from genesis, a new explicit devnet configuration implements rolling anchors with
bounded updates from existing authenticated bases. The 64-ancestor submission and 64 KiB total native
calldata limits remain, and retention counts also have finite caps. Consult final-source results in the
continuous record for long-run end-to-end assessment. Caps, missing DA, or inability to liquidate can
freeze funds. No blanket refunds of old balances or authentication fallback exist.

Production rates, public participation, bonds, USD-denominated CLX collateral, real Oracle/MM,
recovery agreements, and computational proofs remain undecided. WAN/60-minute load/normal PoW mixed
load are unevaluated. No claim of superiority over Hyperliquid, profitability, or completed public operation.
Earlier isolated tests excluded operational-node/data changes. Latest deployment authorization for the
specified network is recorded in the live work record. External/third-party funds, production/public release,
and remote push remain out of scope.
