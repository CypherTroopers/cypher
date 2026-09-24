# Authenticated Bundle Archive for Relay Config 4

2026-09-23. `dex/relay/bundle_archive.go` is used only by ordinary config 4 relays. Legacy config 3's 128-entry array fixture remains for regression. This does not directly modify canonical CLX state, custody, nullifiers, or voting WALs.

## Storage and Bounds

|Target|Limit|
|---|---|
|One signed settlement bundle|Existing 128 KiB, 128 claims, depth 7 per path, existing FHS proof bounds|
|Decoded/raw hot cache|16 records, at most 2 MiB original raw bytes and bounded decoded objects|
|Small authenticated index|At most 4096 checkpoints (about 2 MiB fixed portions + hash/size metadata)|
|Immutable archive|At most 4096 records/512 MiB; unpaid claims are not deleted to free space|
|Checkpoint discovery|At most 8 new bundles/tick|
|Checkpoint planning|At most 8 submissions/tick|
|Historical claim scanning|At most 8 claim candidates/tick, at most 8 bundle scans/tick, round-robin|

This does not mean indefinite operation or constant cost. 4096 is one generation's finite operating budget; 512 MiB is a finite history-storage limit. At capacity, `ErrCapacity` suppresses new bundle retrieval. The CLX source-WAL limit of 1024 segments/32 MiB remains a separate constraint. Even without holding the whole chain in memory, total cold-authentication work is proportional to saved history.

Storage is private `bundles-v4` under the parent of configured `Source.Dir`. Its ownership marker binds native genesis root, custody, and operating budget; validation requires 0700 directories, 0600 regular files, no symlinks, and one owned lock. Filenames have fixed-width absolute DEX sequences. Markers/checksums are not authentication roots.

Before persistence, check decode size and record/byte quotas; using the registered DEX epoch, verify FHS descendant-finality proof, domain, custody, schema 5, sequence, previous checkpoint hash, pre/post-root linkage, finance previous, and block/inbox ranges. Write raw data to a temporary file and fsync, rename to a previously nonexistent final filename, then publish to the authenticated index/cache only after directory fsync. Stored data is immutable; resubmitting identical raw bytes adds no size. A different payload at the same sequence is rejected.

## Restarts and Failures

A new process does not trust the index; it reauthenticates every stored bundle one at a time from genesis. Current RPC or snapshot checksums do not create new trust roots. Gaps, missing/modified data, different roots/registries, unknown files, or unsafe secret/file types prevent startup.

Temporary files before/after fsync or rename are not authoritative. Only after acquiring the exclusive lock may an unpublished `.bundle.pending` file with correct ownership/type/size be removed. Bundles already published under final names are reauthenticated and recovered, not collectively deleted. An instance experiencing I/O errors enters a fault state and stops new persistence. Unit-hook observations are not SIGKILL/actual-power-loss guarantees.

On every read, a bundle outside hot cache revalidates registered-committee finality proof and continuity, beyond merely matching digest/size against the index reauthenticated during cold startup. Unavailable data produces an explicit error. Index inbox/CLX references come only from authenticated checkpoints, not RPC assertions.

## Old Rights and Fair Scanning

All bundles, including unpaid, deferred, and paid claims, remain in the finite archive. Claim-scan cursors are delivery hints only; paid status follows ordinary authenticated CLX state/nullifiers. A cursor resetting on restart does not roll back authoritative financial state. After deferral ends, rotation rediscovers old claims. Another relay can discover the same work; exactly-once protection remains in canonical CLX reserves/nullifiers.

The checkpoint lane advances separately from old-claim scanning. Bounded candidates per tick prevent one old bundle with 128 claims from consuming every worker indefinitely. Local ACKs or retrieved cache entries do not become finalized/paid state.

## Test Scope

Focused unit PASS: `TestBundleArchiveBoundedHotColdAndOldRights`, `TestBundleArchiveCrashBoundaries`, `TestBundleArchiveRejectsMissingTamperedForeignAndQuota`, `TestContinuousClaimScanBoundAndDeferredFairness`, and existing `TestNetworkDiscoveryRequiresAuthenticatedSequentialBundles`. Verified 40 historical records/hot 16, old-claim reads, full cold reauthentication, exact repeats, quota, 3 selected crash hooks, missing/corrupt/foreign/symlink cases, 8 jobs/tick, and fair rotation after deferral removal.

This is **PASS(UNIT)**. Deployment to ordinary PM2 relays, actual-network finance, actual CLX claim double-payment prevention, reaching actual 4096 settings, wall-clock/RSS near the 512 MiB quota, and 60-minute operation are NOT_RUN in these component tests. Original log: `/tmp/common-dex-live.8gezz_j9/public/q3-relay-archive-unit.log`; final race results are linked through separate logs.
