# Existing baseline failures discovered by expanded RPC regression

These failures are additional to the previously recorded two `core/forkid`
failures. They were reproduced in a fresh separate directory reconstructed from
HEAD plus the preserved G0 archive, including the original untracked work.
No active checkout was reset or overlaid. No scheduler expectation, PoW rule or
RPC worker implementation was changed to make these tests pass.

Command environment: Go1.27.1 linux/amd64, GOPROXY=off, GOMAXPROCS=2,
`-p 1 -mod=readonly -count=1`. The environment is recorded; it is not established
as the cause. The repository scheduler sources below match the baseline byte
for byte.

|Source|SHA256|Matches G0 baseline copy|
|---|---|---|
|`internal/ethapi/api.go`|`4bbb3930c38ff204960439c6091eb3c6cd82fd4b4bcb733e89874033a71c3c63`|True|
|`internal/ethapi/api_london_test.go`|`0e8413ff3b785f38a3cfc21cdbdee9e4c48d48e62cf2876e9e8d6cff2911f9ce`|True|

|Test|Baseline result|Observation|
|---|---|---|
|`TestRawTxIngressStopDrainsDetachedCancelledBulk`|FAIL|one of two expected workers arrived by10s|
|`TestSendRawTransactionsBusySenderDoesNotBlockIndependentGroups`|FAIL|zero of three expected independent groups bypassed by10s|
|`TestSendRawTransactionPipelinesAdaptiveIndependentSenderWaves`|FAIL|two workers rather than expected eight by2s|
|`TestSendRawTransactionPipelineSerializesSenderAcrossWaves`|FAIL (timeout)|isolated test exceeded40s; goroutine dump retained|

The first3-test selection took22.157s in the baseline copy. The fourth test
independently timed out at40.073s. The broader current-tree RPC suite also
reported the first3 failures and later reached its5-minute timeout. These are
not evidence that all unrelated RPC tests pass. Final-source targeted evidence
RPC tests are tracked separately, and the known scheduler failures must remain
in the final acceptance report.

Raw evidence:
[three failures](results/continuous-baseline-rpc-failures.jsonl),
[isolated timeout](results/continuous-baseline-rpc-hang.jsonl).
