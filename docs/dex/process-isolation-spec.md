# B-stage process-isolation experiment

This specification precedes the opt-in integration test. The experiment is enabled only with both `CYPHER_DEX_PROCESS_DEVNET=1` and `CYPHER_FHS_PROCESS_RECOVERY=1`, and must run inside a new network namespace with loopback enabled. The guard requires exactly one active loopback interface and no non-loopback IPv4/IPv6 routes. An optional `CYPHER_DEX_PARENT_NETNS` captured before unshare adds an unequal-namespace check, and cannot bypass interface/route checks. It never discovers production peers or attaches to an existing datadir. Only process handles created by this test may be killed.

Seven existing CLX recovery-helper processes exercise actual CLX FHS, authenticated QUIC, temporary LevelDB, execution, and finality. Seven additional DEX helper processes each own their BLS key, separate new DEX WAL directory, and an instance of `dex/consensus.Application`. DEX transport is a bounded parent-controlled stdin/stdout message bus: this is network simulation across real OS processes, not a claim of DEX QUIC networking or independent operators.

The DEX bus limits message size, envelopes per response, pending messages/bytes, and total deliveries. Each child runs one serialized application event loop. Real FHS messages/signatures and WAL writes are executed in children; the parent only routes encoded messages. Known asynchronous protocol rejection states are counted separately from fatal failures.

Sequence:

1. Create seven isolated CLX fixture processes and finalize a transaction with the existing fixture's first-transaction gate. Capture the authenticated CLX genesis and finalized anchor.
2. Register a separate seven-key DEX committee using that CLX domain and a distinct DEX identifier. Drive the bounded deterministic counter action to finality. Check all DEX processes agree and verify a checkpoint using the actual bounded checkpoint verifier.
3. Kill all seven DEX processes using only their owned handles. Release the CLX fixture's remaining transactions and require a strictly newer canonical CLX height on all seven CLX processes, with agreement at the measured height.
4. Restart seven DEX helpers using only the same test-created key/WAL directories. Require recovered finalized state/proofs to match the pre-crash state, then continue DEX consensus to a later finalized checkpoint.

The original genesis file is read as a template; the existing helper changes fixture identities/endpoints/accounts/time in memory only. All fixture funds are isolated synthetic CLX. No RPC is exposed publicly and no production DEX flag is wired.

This test does not establish native DEX custody, public registration, production DA, long-duration performance, or real DEX networking. CLX checkpoint inclusion and native settlements are not implemented by the parent-side checkpoint verification. Results must distinguish process isolation and WAL recovery from those NOT_RUN capabilities.

## Execution status

The non-opt-in command `GOCACHE=/tmp/common-dex-devnet.0wvjd5/gocache GOPROXY=off go test ./reconfig -run '^TestDEXAndCLXProcessIsolation$' -count=1 -timeout=8m` compiled successfully and skipped the integration test. This is not a process-test PASS. The opted-in network-namespace run is owned by the root task and its recorded results determine the experiment outcome.

The first opted-in attempt failed before any child started: comparing `/proc/self/ns/net` to `/proc/1/ns/net` was incompatible with cross-user-namespace proc access (EACCES). The guard was replaced with the stricter observable interface/route checks above. This is an experiment-harness/environment issue, not a DEX/CLX consensus failure; the initial failed attempt must remain in the run artifacts.
