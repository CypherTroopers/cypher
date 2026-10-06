# Verification record — 2026-10-03

All commands ran in `/root/cypher` with `GOCACHE=/tmp/cypher-common-relay-go-cache-20261003` and `GOMAXPROCS=4`. No live node was started, stopped or restarted. Network tests used temporary loopback listeners and in-process protocol fixtures. Tests did not use the live chain databases.

| Status | Command / evidence |
| --- | --- |
| PASS | `go test -mod=readonly ./p2p ./p2p/relay ./eth ./core ./miner ./consensus/colossusX ./params ./reconfig -count=1 -timeout=180s` — `/tmp/cypher-network-full-final.log`; all eight packages passed, reconfig 70.117s. |
| PASS | `go test -mod=readonly -race ./p2p/relay ./p2p ./eth ./core -run 'TestRelay\|TestReserved\|TestCommonRelayTxRealCommitteeIngress\|TestPoWResultRelayRealIngressRewardIntegrity' -count=1 -timeout=120s` — `/tmp/cypher-relay-application-race-final.log`. No race report. |
| PASS | `go test -mod=readonly -race ./p2p/relay -count=1 -timeout=60s` — `/tmp/cypher-relay-final-match-check.log`. Repeated after the final check that a queued response's child is still active when verification finishes. |
| PASS | `go test -mod=readonly ./cmd/cypher ./consensus/colossusX -run 'TestCommonRelayOperatorExamplesDecode\|TestCandidateSeal' -count=1 -timeout=90s` — `/tmp/cypher-relay-config-vector-tests.log`. Actual CLI TOML parsing and independent codec preimage/mutation tests. |
| PASS | `go test -mod=readonly ./eth -run TestCommonRelayTxRealCommitteeIngress -count=1 -timeout=60s` — `/tmp/cypher-tx-relay-integration.log`. |
| PASS | `go test -mod=readonly ./core -run TestPoWResultRelayRealIngressRewardIntegrity -count=1 -timeout=60s` — `/tmp/cypher-pow-relay-integration.log`. |
| PASS | `go build -mod=readonly -o /tmp/cypher-common-relay-build-20261003-n99n0l/cypher ./cmd/cypher` — `/tmp/cypher-relay-build-final.log`; this binary includes the final queued-response check. |
| PASS | `git diff --check`. |
| PASS | SHA-256 comparison against `/tmp/cypher-relay-user-files-20261003.json`: all 25 pre-existing dirty/untracked user files unchanged. Parsed baseline/current `genesis.json` identical after removing only mixHash. |
| FAIL, pre-existing test compilation | `go test -mod=readonly ./p2p/... -run '^$' -count=1 -timeout=60s` — `/tmp/cypher-p2p-tree-compile-final.log`. Unchanged `p2p/discover` tests lack dgramPipe/newpipe/newUDPTest/udpTest/futureExp helpers; unchanged `p2p/enode` tests lack hexPubkey. Direct `./p2p` and relay suites pass. |
| NOT RUN | Repository-wide `go test ./...`; live/certified/recovery full-chain journey using the new seal; 300–400 running processes; production throughput/latency/RSS/churn experiment; new encrypted RLPx multi-node application deployment. |
| NOT RUN | Reset, init.sh, live database migration, live process operation, commit, push or deployment. |

The full eight-package run preceded the final queued-response child recheck and the additional independent seal preimage assertion. Those changes were covered by the focused final relay race suite and the codec test command above. Earlier v3 genesis expectation failures were fixed by the v4 commitment and updated expectation; they are not unresolved final failures. The default root Go cache was not writable, so all final commands used the explicit `/tmp` cache. A pre-existing C compiler warning from go-duktape appeared in race compilation and did not prevent tests from passing.

The transaction test uses real committee ingress, application signatures, WAL/StoreSync and TxPool code, with in-memory test databases. It is not a disk crash/fsync hardware test. The PoW test uses the real network ingress and seal verifier, with a chain-head admission callback fixture rather than a full chain-backed CandidatePool. Four hundred identities exercise actual peer admission functions in one process; no claim of a 400-process experiment is made.

## Independent reviewer verification

After Codex handed back sole-writer ownership, the reviewer verified all 25 baseline user-file hashes again (unchanged), `git diff --check`, the unique binary version and SHA256, and initialized the updated genesis successfully into only `/tmp/cypher-relay-genesis-proof-BkOwEY` (no networking). See `deployment-commands.md` for exact proposed cutover commands requiring confirmation.

Independent runs (normal host Go cache) passed:

- `go test ./p2p ./p2p/relay ./eth ./core ./miner ./consensus/colossusX ./params -count=1` — `/tmp/cypher-independent-full-tests-2.log`.
- `go test ./reconfig/... ./cmd/cypher ./node -count=1` — `/tmp/cypher-independent-integration-tests.log` (reconfig 69.694s, bftview 0.047s, hotstuff 6.344s, CLI 0.088s, node 1.331s).
- `go test -race ./p2p/relay ./p2p -run "TestRelay|TestReserved" -count=1` — `/tmp/cypher-independent-race-tests-2.log`.
- `go test ./core ./eth ./p2p ./p2p/relay ./consensus/colossusX ./cmd/cypher -run "TestPoWResultRelay|TestCommonRelay|TestRelay|TestReserved|TestCandidateSeal" -count=3` — `/tmp/cypher-independent-feature-tests.log`, all six packages passed three repetitions.

Review found and fed back missing genesis commitment updates, deterministic failed-path retry starvation, missing per-peer pending quotas, shutdown joins, and a race-instrumentation timing flaw in a byte-cap test. These were corrected and rerun. The earlier failing runs are retained in `/tmp/cypher-independent-full-tests.log` and `/tmp/cypher-independent-race-tests.log`; they are not reported as final passes.
