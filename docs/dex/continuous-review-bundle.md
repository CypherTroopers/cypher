# Reproducing and Reviewing the Continuous-Operation Changes

Base HEAD is `70862a71dfaf2b00694dc1354c6a64e9504d7db5`.
The work is uncommitted. Do not reset/clean the existing working tree or overwrite an operational checkout with an archive.
In a new review checkout, apply `tracked.patch` to the base HEAD
and extract changed/new source files from `reviewable-worktree.tar.gz`.
`git diff` alone omits untracked DEX implementation, specifications, and runners.

The final bundle contains the following. Generated `coverage.json`, `changed-source-sha256.json`,
`supplement-manifest.json`, `SHA256SUMS`, and `PACKAGING-COMPLETE.json` are authoritative
for exact counts, hashes, and exclusions.
Output whose generation stopped at `REVIEW_REQUIRED` is not a completed archive.

| Artifact | Contents |
|---|---|
| `HEAD.txt` / `branch.txt` / status and untracked lists | Mapping between the starting point and full working diff. Does not modify the index |
| `tracked.patch` | Tracked diff from the base HEAD. Distributed binaries excluded |
| `reviewable-worktree.tar.gz` | Changed/new source, specifications, and public results selected by the existing manifest runner |
| `supplement.tar.gz` | Explicit public CSV/diff files, reporting parser/packaging helpers, extracted final financial trace |
| `coverage.json` | Classifies every changed/new path and records its archive location or exclusion reason |
| `source-snapshot-before/after.json` | Detects changes to source, documents, and results during packaging |
| `SHA256SUMS` / `PACKAGING-COMPLETE.json` | Hashes of completed artifacts and consistency-check results |

Distributed binaries, generated caches, private keys, keystores, chaindata, operational WALs,
and test-runtime DBs/WALs are excluded.
`dex/settlement`, `dex/checkpoint`, `dex/clxevidence`, and `dex/protocol`, used by CLX,
are classified as shared verification code on the CLX production side.
Classification counts are not execution counts or added-load measurements.
For the two distributed binaries that differ from the start, only hashes and exclusion reasons
are retained; they are neither restored nor distributed.
See the [protected-target comparison](results/continuous-final-protected-observation.json).

The final Go/scripts execution manifest is
`7f786223801e567b77c6c37bf437c189ea440de3db91f0b93d4fae705cdc97e2`.
Tests used Go1.27.1, readonly modules, `GOPROXY=off`, `GOMAXPROCS=2`, and a dedicated Go cache.
Each `check.sh` run creates binaries, logs, and datadirs in an independent new `/tmp/common-dex-check.*` location.
Network modes use new user/network namespaces, loopback, and necessary namespace-local iptables;
they stop if isolation fails, without host-network fallback.
For execution modes and conditions, see the [README](README.md) and [final test index](results/continuous-final-test-index.md).
Temporary-space shortages were resolved as described in the [dedicated-cache migration record](results/continuous-cache-storage-migration.json).

The `supplement` parser organizes raw logs; it is not a new FHS/MPT authenticator.
`CONTINUOUS_CLAIM id=` is a leaf hash, distinct from protocol `Claim.ID`.
Decode Claim.ID/period/owner/recipient/amount from the explicitly public relay-job bytes,
and verify that leaf hash, sequence, and amount match actual payment logs.
Public captures are not atomic across files, and checksums alone are not consensus authentication.

The packaging helper checks changed paths/formats against an allowlist and performs limited
secret-pattern checks on public documents/logs. This is not a general proof that arbitrary encoded data contains no secrets.
No remote push, operational-node shutdown, production application, or real-fund operation is performed.
