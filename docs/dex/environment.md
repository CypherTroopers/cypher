# Investigation and Test Environment

Start date: 2026-09-21 UTC (distinct from 2026-09-22 in the request).
Workspace: `/root/work/cypher-FHS-D-ExchangeCore`.

* Local branch: `FHS-D-ExchangeCore`
* Starting HEAD: `70862a71dfaf2b00694dc1354c6a64e9504d7db5`
* Public `origin/FHS-D-ExchangeCore`: same SHA, confirmed read-only with `git ls-remote`.
  The same query found no matching `main` / `master` refs. A retrieval failure was not assumed to mean equality.
* Initial `git status --short`: clean. No reset, checkout, or remote push.
* Applicable project guidance was checked in parent directories and throughout the workspace, including hidden directories; none was found.
* The complete supplied requirements were used without relying on prior discussions or separate DEX artifacts.
* Go `go1.27.1 linux/amd64`, go.mod requirement `1.25.6`, CGO enabled.
  Cached dependencies used with `-mod=readonly GOPROXY=off`. No go.mod/sum changes.
* Linux `7.0.0-30-generic`, KVM, AMD EPYC, 12 logical CPUs, 47 GiB RAM.
  This is a shared host, not a dedicated performance-test machine; it is not evidence of performance superiority.

## Protected Targets and Isolation

Host nodes were invisible in the normal sandbox PID namespace, so a limited read-only
`/proc` inspection was performed with extended read permission. Eight running CLX processes were confirmed on the host:
PIDs `477749,477750,477760,477766,477767,477781,477787,561356`.
Cwd `/root/cypher`, datadirs `chaindb0`–`chaindb6`, `chaindbmine`.
These processes are not stopped, restarted, or signaled, and their data is not read or written.
Full command lines and private keys are not output in test records.

Workspace `genesis.json`, `cmd/cypher/data` (including chaindata/keystore),
`build/bin` (distributed artifacts), and `crypto/bls/lib` are protected existing assets.
Initial SHA-256 list: `results/protected-before.sha256`.
The presence of `/root/.ethereum/history` was also checked, without reading or writing its contents.

The new isolated location is `/tmp/common-dex-devnet.0wvjd5`.
Dedicated `gocache` and `bin/cypher` are used; builds do not write to existing distributed binaries.
Test datadirs use only new `testing.T.TempDir` locations.
Existing tests that read repository genesis convert it to in-memory fixtures without changing the original file.

Socket tests run in a new user/network namespace created by `unshare -Urn`,
with only loopback enabled and no route to host or public networks.
They use `GOMAXPROCS=2` and `go test -p 1`; DEX process tests use the same conditions.
Only child-process handles created and retained by the tests may be terminated.

## Initial Environment-Related Failures

The standard sandbox prohibited DNS resolution and socket creation.
The first `git ls-remote` failed with a DNS error; a read-only network execution then confirmed the result successfully.
Initial baseline tests failed creating RPC/PoW transport sockets.
The affected tests passed after switching to a new namespace without external connectivity.
These failures are distinct from source regressions.

The baseline build succeeded with an existing format-overflow warning in go-duktape C source.
The warning is retained in raw logs rather than treated as a new DEX-code issue.
The two existing `core/forkid` test failures are recorded separately; the entire suite is not reported as PASS.

## Initial Baseline Commands

```
GOCACHE=/tmp/common-dex-devnet.0wvjd5/gocache GOPROXY=off \
  go build -mod=readonly -o /tmp/common-dex-devnet.0wvjd5/bin/cypher ./cmd/cypher

unshare -Urn sh -c 'ip link set lo up && GOMAXPROCS=2 \
  GOCACHE=/tmp/common-dex-devnet.0wvjd5/gocache GOPROXY=off \
  go test -p 1 -mod=readonly -count=1 -timeout=5m \
  ./commonrpcreward ./params ./consensus/colossusX ./miner ./eth \
  ./reconfig/... ./core/...'

unshare -Urn sh -c 'ip link set lo up && GOMAXPROCS=2 \
  CYPHER_FHS_PROCESS_RECOVERY=1 \
  GOCACHE=/tmp/common-dex-devnet.0wvjd5/gocache GOPROXY=off \
  go test -p 1 -mod=readonly ./reconfig \
  -run "^TestFHSProcessRecovery" -count=1 -timeout=5m -v'
```

All three existing seven-CLX-process tests—SplitTC, OfflineProposer, and RewardFinality—passed.
These are not DEX financial integration tests. See raw logs for execution times and other details.
