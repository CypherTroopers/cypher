# G0 CLX boundary audit

Scope: the current uncommitted CLX changes on `FHS-D-ExchangeCore`, against
`70862a71dfaf2b00694dc1354c6a64e9504d7db5`. This audit does not activate DEX,
change operational genesis, modify existing data, run normal PoW nonce search,
or change the two known legacy `core/forkid` expectations.

The new checks below were specified before their implementation. Their bounded
results are recorded below; they do not establish completion of the whole G0
or A–D programme.

|Boundary|Existing evidence|Additional G0 check|
|---|---|---|
|Early QC before Prepare|Authenticated aggregate/envelope/proposal negatives, actual7-process repair regression|Duplicate early QC coalesces one content job; unavailable body cannot certify or vote; stale completion is rejected; a hard invalid-body result is not retried as missing data.|
|FHS canonical state/head|Real5/7 QC and child proof; fresh/cached roots cold-read through new LevelDB handle; injected head fsync failure|Unsupported synchronous batch, trie write failure, and head sync failure leave transaction and key heads unchanged; after the transient failure is removed, the same staged transition can commit once.|
|Clean trie journal|Explicit empty value remains disabled and normal CLI restarts with DEX ON/OFF|Normal Common CLI with omitted option, explicit empty, a safe relative directory and a safe absolute directory; normal shutdown/restart preserves both genesis mappings and a sibling sentinel, and only enabled journals create their specified cache directory.|
|Immutable genesis settings|Native execution accepts local RnetPort/EnabledTPS changes; missing/corrupt/activation override rejected|Exercise these allowed local settings alongside each altered consensus field (chain, transport, committee, DEX identity/custody/activation/cap and modern fork) through the native transaction path; invalid settings must produce no receipt, gas use, nonce or balance change.|

The journal tests use newly owned paths only. An explicitly configured journal
directory is a replaceable cache directory, not a general data directory.
The empty-value fix does not by itself reject a user-selected path equal to the
instance or database directory. No claim of protection from every explicit
path collision is made by the four safe-path cases.

Failure injection is at repository interfaces, not physical disk power loss.
The additional head-marker fixture isolates persistence ordering with an
existing test validator; the existing real-BLS/cold-LevelDB test remains the
authentication and disk-reopen control. A persisted unreferenced trie after a
failed head batch is allowed; publishing a new canonical head is not.

Production source remains read-only during these test additions. Any newly
observed defect is reported separately before modifying production code.

## Source audit

|Area|Observed current boundary|Effect on existing CLX|
|---|---|---|
|QC arrival|`reconfig/hotstuff/hotstuff.go:2011` routes only an existing FHS view with no key/transaction proposal into `handleStandaloneFHSQCBroadcast`. That path checks decoded chain/view/leader, canonical signer mask, aggregate vote signature and authenticated leader envelope before scheduling content validation.|Nonempty conflicting proposals still reject. Neither quorum threshold nor two-chain finality changes. A QC cannot substitute for the body/state validation callback.|
|Root and head durability|`core/blockchain.go:843` persists the root before staging all canonical transaction/key markers. At line938 FHS requires `ethdb.SyncBatch.WriteSync`; memory heads are published only after success. `writeBlockWithState` also persists FHS roots at line2786.|FHS storage ordering changes; existing PoW dirty-trie policy remains on its prior branch. This adds storage work; no disk-performance result is claimed.|
|Journal|`eth/backend.go:273` preserves the empty string; nonempty values still use `node.Config.ResolvePath`. Default is `triecache`.|Default and explicitly enabled safe directories still persist cache. Empty disables cache persistence rather than resolving to the instance directory. Operational DB paths were never used by these tests.|
|Genesis authentication|`core/dex_native_context.go:28` normalizes only RnetPort and EnabledTPS against persisted genesis. All other fields remain in the genesis commitment. `DEXGenesisConfig` at line45 decodes stored data afresh and detaches the modern-fork side table.|Local transport port/metrics settings do not change native receipts. A local consensus override fails before native receipt/gas/nonce/funds mutations; genesis authentication is not bypassed.|

The tracked diff also includes native dispatch/context, devnet genesis account
reservation and optional CLI wiring. Those wider DEX changes are not newly
certified by this four-boundary audit. The original reference files were not
reset and the known `core/forkid` failures were not modified.

## Executed results

All final runs used Go1.27.1, `GOMAXPROCS=2`, `nice -n 10`, readonly modules,
`GOPROXY=off`, the existing task cache and separate fresh user/network
namespaces with only loopback. The owned run root is
`/tmp/common-dex-continuous.uye5vgqi`.

|Run|Result|Exact boundary|
|---|---|---|
|[CLX boundary race](results/continuous-g0-clx-unit.jsonl)|PASS:3 packages,22 top-level tests,70 passing test events including subtests;0 FAIL/0 SKIP. core1.983s, hotstuff1.315s, reconfig23.041s.|New storage/genesis/QC boundaries plus existing real-BLS cold-LevelDB, invalid QC, missing-data retry, manifest authority, missing/changed blob body, malformed/out-of-manifest TX repair controls.|
|[Normal CLI journals](results/continuous-g0-clx-cli.log)|PASS29.987s: omitted, empty, safe relative and safe absolute; each starts twice after one genesis init.|All8 starts keep PoW off. Both canonical genesis mappings and an instance-directory sibling sentinel survive both stops. The three enabled cache paths contain persisted files; empty creates no journal.|
|[Actual7 CLX early-QC process](results/continuous-g0-clx-process.log)|PASS26.976s.|A nonleader misses Prepare but repairs bodies and reaches identical certified/canonical block, TX, receipt, gas and root over real QUIC. This is a positive repair/finality control, not distributed injection of every unit-level invalid body.|

Commands, UTC times, loopback namespace identifiers and before/after Go source
hashes are linked by [unit metadata](results/continuous-g0-clx-unit-metadata.json),
[CLI metadata](results/continuous-g0-clx-cli-metadata.json) and
[process metadata](results/continuous-g0-clx-process-metadata.json). The first
unit launch did not execute because automatic approval review timed out; one
identical retry was approved and ran. The other two launches ran on their first
attempt. There was no host-network fallback.

CLI and process source manifests are identical before/after. During the race
run another worker changed four financial/reward test files, listed in its
metadata. No production file or selected boundary/repair test changed. Those
separate test additions are not claimed as covered by this run.

The early-QC manager unit reuses the existing4-member HotStuff fixture with a
3-signature QC. The independent process control uses7 members. The storage
ordering test uses the existing permissive test validator to isolate batch
ordering; real5/7 target/child QC validation remains covered by the existing
cold-LevelDB test in the same run. These boundaries are deliberately distinct.

## Remaining limits

Normal32GiB PoW nonce search, committee candidate delivery under PoW load,
physical power loss, torn/partial device writes, disk exhaustion during every
possible fsync interval, and distributed malicious QC/body combinations remain
NOT_RUN here. No new production defect was observed by the executed cases.

An explicit journal path colliding with the instance/DB directory remains an
unmitigated configuration hazard inferred from `ResolvePath` and fastcache's
replace-directory semantics. It is not exercised against any operational
path, and the four safe-path PASS results do not imply collision rejection.
