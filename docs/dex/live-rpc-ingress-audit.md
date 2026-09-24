# Additional Audit of Existing Current RPC Ingress Failures

2026-09-23, Q3 read-only review. Production scheduler, existing test expectations, rates, and PoW/CLX consensus were unchanged. The latest rerun, `/tmp/common-dex-live.8gezz_j9/public/q3-current-rpc-baseline.jsonl`, had 3 **FAIL** results (22.174 seconds). This document does not relabel FAIL as PASS or RETIRED.

Current `internal/ethapi/api.go` SHA-256 is `4bbb3930c38ff204960439c6091eb3c6cd82fd4b4bcb733e89874033a71c3c63`; `api_london_test.go` is `0e8413ff3b785f38a3cfc21cdbdee9e4c48d48e62cf2876e9e8d6cff2911f9ce`. They match the previously independently reconstructed baseline byte for byte. Their status as pre-existing failures in the [earlier issue record](continuous-baseline-issues.md) is distinct from whether current behavior is appropriate.

## Underlying Current Behavior

[`partitionPreparedRawTransactions`](../../internal/ethapi/api.go:3411) first creates sender groups but limits workers to `max(1, floor(transactionCount/64))`. Below 64 transactions, it combines them into one backend job regardless of sender count. Comments describe amortizing admission certificates and durable transport, not a rule requiring separate backend calls for every sender. The single-RPC coalescer uses the same partitioner.

[`startRawTxIngressWorkersLocked`](../../internal/ethapi/api.go:3195) and [`dequeueRawTxIngressJobLocked`](../../internal/ethapi/api.go:3265) make the **whole job** wait if any sender is already active/reserved. All senders in a waiting job are then reserved against later jobs to preserve per-sender order. This protects nonce ordering while also causing head-of-line blocking in multi-sender jobs.

## Distinctions Among the 3 Failures

|Test|Actual cause and what cannot be concluded|
|---|---|
|`TestRawTxIngressStopDrainsDetachedCancelledBulk`|Submits 2 independent TXs with workerLimit 2 and waits for 2 backend calls. Current partitioning creates 1 job, yielding `only 1/2` after 10 seconds. **FAIL occurs before cancellation or `Stop()`**, so this result alone establishes neither a Stop-drain defect nor success. Expected backend-call count disagrees with current batching policy.|
|`TestSendRawTransactionPipelinesAdaptiveIndependentSenderWaves`|The first 1 TX creates 1 job; the next 7 independent TXs create 1 job. It requires 8 calls with 1 item per batch against current minimum 8 workers, and fails after observing 2. Result channels are collected after release, but FAIL precedes full later-result verification, so do not infer PASS for that verification. Fixed parallelism expectations disagree with amortization policy.|
|`TestSendRawTransactionsBusySenderDoesNotBlockIndependentGroups`|One follow-up TX from an already busy sender and 3 independent TXs share one 4-TX job. The busy sender prevents scheduling the independent 3 too, giving `only 0/3`. The mock also accepts only 1-item batches, conflicting with current format, but **the test reproduces actual current liveness behavior where independent senders wait**. It cannot be dismissed merely as an obsolete count expectation.|

The earlier 40-second timeout in `TestSendRawTransactionPipelineSerializesSenderAcrossWaves` is also consistent with waiting in a mixed wave of 2 senders, but that fourth test was not rerun here; its cause is not definitively resolved.

## Advice for the Pre-Initialization Gate

These 3 FAIL results did not demonstrate broken CLX signatures, nonces, roots, receipts, FHS finality, or native-custody conservation. They also do not invalidate formal new-genesis derivation, domain separation, or storage specifications themselves. Therefore, they are not grounds for permanently stopping all candidate-initialization preparation, preservation work, or ordinary low-load tests.

However, mixed Common RPC submissions, multiple gas lanes from 2 relays, and ordinary CLX workloads share this scheduler. Backend delay for one sender propagates to independent senders in the same batch, directly affecting Q4 outage recovery and Q5 tail latency/backlog/completion rates. Retain this as an **unresolved issue preventing a claim that general independent-sender liveness/load conditions have passed**. Long-term tests need input bounds and stop conditions, must count stalled requests in statistics, and cannot mark this resolved based only on low load.

Backend [`SendTxBatch`](../../eth/api_backend.go:562) has individual timeouts for live-ingress acquisition, WAL intents, TxQUIC enqueue, etc.; these are not finite-response guarantees for the entire scheduler or all paths including DB/hash locks. RPC caller cancellation does not cancel already admitted node-owned work; [Stop](../../internal/ethapi/api.go:2832) waits for it to complete.

The next step is not simply rewriting expected counts to 1/2. Preserve amortization goals and sender ordering while either separating busy senders or documenting current waiting behavior, then verify fairness within/across batches, cancel/Stop, bounded backend delays, result alignment, and pending capacity. The first 2 cases are candidates for replacement with current-specification tests that avoid fixing batch-size implementation details, but remain **FAIL, not RETIRED**, until replacement verification and intentional retirement are decided. This audit made no production fix or test-expectation change.
