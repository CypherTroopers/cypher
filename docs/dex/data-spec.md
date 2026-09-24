# Devnet retained data v1

Before joining, a DEX replica must retrieve and validate the actual parent data.
A committed root is never a claim of successful data retrieval. The local store
returns distinct DATA_UNAVAILABLE and DATA_MISMATCH errors. A sidecar must not
vote or become eligible until application replay confirms the committed root.

Content ID is SHA256(`common-dex/data/v1` + NUL + exact bytes). A local store
accepts at most 1 MiB per item, with explicit item and total-byte limits. No
automatic deletion/pruning of data or WAL is performed. Budget exhaustion rejects
admission. The directory must be freshly created by the store, or contain its
exact devnet marker on restart. Symlink directories/files are rejected. Writes
are fsync-before-publication and directory-synced. An existing ID cannot change
content. Corruption on read is an error, never an empty snapshot.

One sidecar owns each store directory and uses one Store handle. Capacity
accounting is serialized within that handle; cross-process shared writers are
not supported. The sidecar WAL/datadir ownership lock must enforce that boundary
before production integration. Files left by an interrupted staged write in the
devnet parent are not adopted as committed data.

These are local retention primitives. Multi-provider retrieval, certified
snapshot manifests, full engine replay, pruning responsibility and independent
operator availability require separate integration tests. Local storage tests
alone do not satisfy D01 or prove external DA. Missing open-position data cannot
authorize an old-balance refund.
