# I 27: Rejecting Omitted Reward Evidence While Market Actions Continue

**Limitation and fix found in G0:** This document's old I 27 PASS did not verify consistent execution
of the same proposal with different local evidence. G0/O05 reproduced that divergence,
so rejection based on old collector knowledge is not evidence of consensus safety.
Currently, every node rejects omission of evidence recorded in finalized state by a preceding CDXP action
with `ErrCommittedOmission`. Tests verify success of a subsequent complete set with the same nonce
and continued ordinary Noop execution. Details and before/after results: [continuous-g0-rewards.md](continuous-g0-rewards.md).
The following records the earlier test state.

Component/audit findings are retained as of their recording date. For subsequent final process results, see the [integration record](integration-status.md) and [acceptance matrix](acceptance-matrix.md).

This record checks that a reward close can be rejected without changing its deadline and that this rejection alone does not stop ordinary market actions. It does not establish participation-evidence delivery guarantees on a public network.

## Executed Unit Test

Extended `TestNativeCLXFinancialFHSScenario/speculative_reward_proposal_does_not_pin_period` in `dex/devnet/integration_test.go`.

1. Executing an unfinalized reward candidate does not durably pin the collector's period root.
2. After participation evidence is registered with the collector, a correctly signed close omitting it is rejected with `ErrOmittedCertificate`.
3. Against the same parent and expected nonce, a signed Noop satisfying existing price/funding conditions can execute. It does not increase reward periods/reserves, create reward leaves, or alter parent bytes.
4. A complete close with the same parent/nonce can be re-executed. Rejection and speculative Noop execution consume neither nonce nor period.

`go test -race -json ./dex/devnet -run '^TestNativeCLXFinancialFHSScenario$' -count=1` was PASS, package 36.206 seconds. [Raw results](results/reward-omission-market-race.jsonl). This Noop is a pure-execution branch; it and the complete reward close were not both finalized at the same height.

## Real-HTTP Test Helper for the Ordinary CLI

`exerciseDEXRewardOmission` in [reconfig/dex_financial_reward_test.go](../../reconfig/dex_financial_reward_test.go) targets only 7 DEX sidecars started by ordinary Common. It does not use test stdin/action-height APIs.

* Confirm through `/v1/participation` that evidence for the omitted duty has already reached all 7 collectors.
* Copy a complete 7-certificate ClosePackage, omit only the final certificate, and sign with the legitimate oracle key and next expected nonce.
* Check ACK/id from `/v1/actions`, then wait for `/v1/action-status` to report `rejected` for omitting known evidence. An ACK alone is not final success.
* Confirm that each node's finalized checkpoint/root/state is unchanged and reward reserves remain zero.
* Return without changing the caller's complete package or nonce. The existing scenario's complete h18 close finalizes with the same nonce and proceeds to CLX acceptance/native claims, demonstrating retry progress.

Helper compilation passed (`go test ./reconfig -run '^$'`,0.038 seconds). Actual HTTP execution status follows the final result of `TestFHSNativeFinancialOrdinaryCLI`. Compilation alone does not count as demonstrated execution.

## Unresolved Delivery Conditions

Collector rejection applies when correct collectors hold receipts/evidence received before the deadline and that evidence has been delivered. A protocol guaranteeing inclusion for all valid participants even when evidence is hidden, undelivered, or delivered only to a minority of nodes is incomplete. No workaround reduces signature counts, delays cutoff, or awards points unconditionally for signatures after the deadline.

While reward-close evidence is insufficient, reject only that close and its reward reservation. Ordinary actions still require existing oracle freshness, unsettled-funding, risk, and nonce conditions; these separate stop conditions remain effective. This Noop test uses a fixture satisfying them; it does not prove liveness for every market action or every failure condition.
