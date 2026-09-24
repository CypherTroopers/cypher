# Final verification — 2026-09-22 (Europe/Berlin)

Code is the uncommitted FHS-D-ExchangeCore worktree based on
70862a71dfaf2b00694dc1354c6a64e9504d7db5. The final code fingerprint is
`results/final-source-sha256.txt`; tests used Go1.27.1 linux/amd64,
GOPROXY=off, readonly modules and a dedicated /tmp cache.

* Build: PASS (`post-build.log`), output only /tmp/common-dex-devnet.0wvjd5/bin/cypher-final.
* All10 DEX packages and existing HotStuff: race PASS,11 packages,
 174 top-level test pass events /372 including subtests (`final-unit.jsonl`).
* All8 independent Python reference/golden programs: PASS (`final-python-vectors.log`).
* CLX7 + DEX7 processes: PASS33.00s; DEX stopped while CLX1→3,
 DEX WAL2 restored then final4 (`final-process-regression.log`). Counter only.
* Actual Common IPC/HTTP/sidecar role combinations: all8 PASS13.30s in the same
 final process log. Normal-mode PoW dataset deliberately unavailable;
 lifecycle/admission is tested, actual nonce search is NOT_RUN.
* Financial integration: seven real FHS managers,18 finalized financial blocks,
 signed trades/funding/participation, native StateDB225 CLX→214 after withdrawal10
 and operator rewards1; all DEX WALs and native trie reopened. Final race run
 includes nonfinalized reward proposal retry and malformed snapshot regression.
 Native sender/inclusion context is trusted fixture input, not a CLX TX handler.
* Regression selection (PoW/RPC/miner/eth/reconfig/core trees): only the same
 pre-existing core/forkid TestCreation and TestValidation failures remain.
 `final-baseline-regression.log` intentionally exits1, matching the baseline.
* Reproduction runner unit mode: PASS (`reproduction-runner.log`); complete raw
 artifacts are /tmp/common-dex-check.4AOcIzVb. Its executable source inventory,
 vectors, git diff, HEAD and environment were retained. A dedicated existing
 /tmp Go cache was supplied with DEX_TEST_GOCACHE; default creates a fresh cache.
* Protected fixture/operational-path manifest SHA256: unchanged
 (`protected-check.log`). git diff --check and gofmt checks passed.

No claim of A–D completion: CLX transaction dispatch and noncircular finalized
native-deposit sealing, optional production daemon wiring, live epoch rotation,
full financial two-domain fault matrix and open-position emergency recovery
remain unimplemented or untested. The31-row acceptance matrix distinguishes
component coverage from these missing integration boundaries. P02–P05/load,
latency, profitability and Hyperliquid comparisons are NOT_RUN.

No running operational node was stopped; no real funds, production activation,
operational genesis/data/keystore/WAL/distributed binary change or remote push.
