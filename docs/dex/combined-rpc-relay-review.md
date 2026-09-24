# Normal Common RPC + DEX relay: fixture identity and cleanup

This document retains component and audit results as recorded at the time. For subsequent final process results, see the [integration record](integration-status.md) and [acceptance matrix](acceptance-matrix.md).

This record covers the failed normal-CLI financial run on 2026-09-22 and the
test-fixture correction. It does not claim that the corrected full scenario
passed; its subsequent process result must be recorded separately.

## Observed failure

`/tmp/common-dex-integration.hnc63_8r/logs/native-financial-cli-6.log` records
normal Common 0 synchronizing the actual CLX chain through height 47, enabling
the existing Common RPC admission/reward APIs while its DEX sidecar remained
active and PoW remained disabled, and returning HTTP acceptance for withdrawal
transaction `0xc170c7aed6f2c084b9f673db8b7e49d377c5b146118ed60b40f3933a732198f5`.
The subsequent CLX receipt wait timed out.

All seven CLX validator logs record the same batch
`0xbe290f0adf329baddd1cd5b3b0a0523dc5b348773bb52278b9d338438b16356c`
at 09: 29: 23 +0200 with `txquic nonce is below the replay window`. Evidence is in
`/tmp/fhs-process-failure-432895872.log:171`,
`/tmp/fhs-process-failure-1025405488.log:157`,
`/tmp/fhs-process-failure-201005632.log:112`,
`/tmp/fhs-process-failure-1402094264.log:111`,
`/tmp/fhs-process-failure-3684601818.log:109`,
`/tmp/fhs-process-failure-820251207.log:108`, and
`/tmp/fhs-process-failure-1803826592.log:108`.
Thus the packet reached the committee; the observed failure was not a missing
route or port. The normal Common log is
`/tmp/dex-normal-cli-failure-2978949744.log`.

## Source-backed cause and correction

The fixture copied the original source Common's operator key into another
Common with a fresh TxQUIC outbox. `txQUICSenderEpoch`
(`eth/tx_quic_ingress.go:571`) deterministically binds chain ID, genesis and
operator address. `TxOutbox.NextNonce` (`eth/tx_quic_ingress.go:8075`) starts a
fresh stream at 1 and durably reserves ranges. Receiver `LookupPacket`
(`eth/tx_quic_ingress.go:5732`) looks up the same operator/epoch watermark and
rejects a nonce below its retained floor. A new database does not create a new
authenticated sender epoch. Reusing the operator while discarding its nonce
history was a test-fixture error; the rejection preserves replay safety.

`reconfig/dex_financial_combined_rpc_test.go` now creates an independent local
fixture operator, asserts its native balance is zero, imports only that key,
and retains the exact existing reward recipient. Registration and admission
require the operator's signature; this operator does not pay the trader's TX
gas and is not funded. The ledger checks the new approver for this one relay
and keeps the same strict reward-recipient, fee-share, gas and burn accounting.
No nonce floor, replay window, production API or consensus rule was changed.

An additional cleanup race was identified by source inspection. HTTP success
follows durable admission/outbox ownership (`eth/api_backend.go:855`), while
`completeVerifiedLocalTxsIntent` stores the batch without a signed transport
envelope (`eth/tx_ingress_wal.go:2407`). The outbox worker later calls
`encodeSignedTxQUICPacket` for initial delivery and retries
(`eth/tx_quic_ingress.go:2302`, `:2333`). Locking the operator immediately after
HTTP acceptance can prevent those signatures. The test coordinator now logs
HTTP acceptance separately, observes the real validator's CLX receipt, and
then closes its HTTP endpoint and locks its operator. The public RPC response
still means ingress acceptance. No automatic unlock or production lifetime
change was added.

## Executed checks and pending process validation

The existing nonce reservation/restart, same-batch replay/restart, and bounded
replay-window compaction tests all passed (3 tests, 0.082 seconds):

```sh
GOCACHE=/tmp/common-dex-devnet.0wvjd5/gocache GOPROXY=off \
go test ./eth -run '^(TestTxOutboxNonceReservationPersistsAcrossRestart|TestTxQUICIngressReplaySameBatchAndNonceSurvivesRestart|TestTxQUICIngressReplayAcceptsHugeNonceJumpsAndCompactsOldWindow)$' -count=1 -json
```

Raw results: `docs/dex/results/combined-rpc-replay-regression.jsonl`.
These tests confirm the existing mechanism and do not substitute for the
normal-CLI financial relay rerun. That rerun was pending when this record was
written. Trial 6 remains a failed process run in the preserved results.

Subsequent trial 7 (`logs/native-financial-cli-7.log`) recorded the corrected
normal Common HTTP acceptance and successful native withdrawal receipt at
height 49, including the independent approver and unchanged reward recipient.
Its later financial custody reconciliation reached 214 CLX at height 69. The
whole run failed at the final normal Common ETH synchronization gate; see
`common-sync-peer-refresh-review.md`. The relay's observed success must not be
reported as a passing whole run.
