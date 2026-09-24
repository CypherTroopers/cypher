# Storage Limit Audit for Continuous Real-Network Operation

## 2026-09-23 Q3 — Current Source Addendum

The following table describes the state after Q3 implementation. The later “Q0 — Initial Audit”
section preserves the historical wording and hashes; its “unimplemented,” “append-only,” and
“MaxHeight also 128” statements do not assess the current generation mode.
Normal binary deployment is distinguished from activation of a new DEX financial generation
and real-network storage testing. Mid-operation init was not approved, so financial LIVE testing was not performed.

|Current target|Limits and classification|Reclamation, retention, and behavior at capacity|
|---|---|---|
|DEX FHS WAL v4|Hot 128 records/2 MiB; normally switches every 64 finalized heights. Local storage rule. Absolute operation budget configurable from 2–4096|Fsync archive first, then atomically switch CURRENT. Pin own votes, noncanonical parents, QCs, timeouts, outbox, etc.; stop acceptance if required pins do not fit|
|FHS archive|At most 2 MiB per finalized record/action/full state/QC/descendant proof. Default 256 MiB, configurable 8 MiB–1 GiB, 4 MiB work reserve. Maximum 4096 heights|Retain old state and claim evidence. On cold start, replay and authenticate finality sequentially from genesis, restoring only a fixed digest index. Insufficient capacity suppresses new proposals. Do not expand all history into hot storage; total reauthentication work is proportional to history|
|Financial state v6|16 unclosed nonzero-fee periods. DEX consensus financial-state rule|Aggregate closed periods sequentially into cumulative amounts/roots and retain details in authenticated history. Atomically reject an action creating the 17th nonzero-fee period. Zero-fee operations and valid closes remain possible. Retain unpaid reservations|
|Participation collector|Hot 2048 records/2 MiB. Retired archive 1024 periods/128 MiB, each at most 2 MiB. Local storage|Retire only against an authenticated finalized checkpoint containing the next reward period. Save evidence to archive before reclaiming hot storage. Retain the real FHS durability watermark, LastVote/RecoveryVote and targets, ClosedThrough, and unclosed evidence. Pins survive repeated two-WAL crashes. Stop at capacity without eliminating retention obligations|
|Relay financial bundle archive|Hot cache 16, cumulative 4096 records/512 MiB, each bundle at most 128 KiB. Local storage/wire|Reauthenticate consecutive checkpoints, funding summaries, and finality proofs on cold start. Preserve old claim leaves/paths; hot eviction does not erase rights. Reject new bundles at capacity|
|Relay source|Cumulative 1024 segments/32 MiB, maximum 32 headers/segment. Local storage/wire|Still append-only; source archive generations are unimplemented. Retain the authentication chain and stop at capacity. FHS generations do not remove this limit|
|Relay job WAL|Active 256/32 MiB, completed history 1024/8 MiB, total 48 MiB. Local storage|Limited reclamation only for authentically completed jobs without dependent references. Retain unfinished business, signed TXs, and unconsumed nonces. Do not reclaim `completed_pending_nonce` as completed; use `capacity_wait` if reclamation is impossible|
|CLX consensus state|Checkpoint configuration maximum 4096, cumulative rolling anchors 1024, cumulative inbox 4096,128 per deposit range|Acceptance budgets remain in the new generation. Do not overwrite with only the latest root or prune old claims. Retain unpaid reservations, cumulative paid, nullifiers, and inbox boundaries in normal CLX state. Reject new affected business at capacity without expiring existing claim rights|
|Single-proof submission limits|64 ancestors, 64 KiB native calldata; existing signature, MPT, and decode limits remain|Catch up through repeated updates. Do not expand limits, trust latest RPC, or update canonical CLX from callbacks|

Financial FIFO, cash/PnL, funding/dust, funding/support limits, and claim arithmetic remain unchanged.
No change returns the DEX engine to the CLX committee or DEX OFF Common nodes.
These are storage updates within finite budgets, not permanent archive retention or completed indefinite operation.

**L10 is verified within PASS(UNIT) scope**: seven real FHS managers in one process reached
130 certified/129 finalized, switched twice at 64 and 128, cold-resumed all seven participants,
and checked retention of old state/checkpoints and signing safety state.
The final consensus race run had 52 top-level/130 pass events, 718.078 seconds, FAIL 0, source manifest
`d88cfb6359ec2aca7ba79f974df2395789f17df084ca4be25db809e6e962c993`.
This is a component test of old-claim evidence retention, not real-network verification of native financial payments
across storage generations. **L11's two LIVE switches using real configuration are NOT_RUN**.
Fresh initialization/bootstrap distribution from a single current-v4 snapshot is NOT_IMPLEMENTED;
the API explicitly rejects it. This is separate from cold restoration of the same DB, old-snapshot regressions,
and CLX synchronization of a later-starting DEX OFF Common node.

Current specifications and evidence:

- [Storage codec](storage-generation-v4-codec.md), [implementation and final consensus tests](storage-generation-v4-status.md), and [independent storage review](live-storage-generation-review.md).
- [Financial v6 and collector specification](financial-storage-v6-spec.md), [financial component tests](financial-storage-v6-status.md). For final integration results across the full working diff, see the coordinating runner's corresponding source record.
- [New-generation schema mapping](live-continuous-schema.md), [mid-operation init candidate and unexecuted conditions](live-generation-candidate.md).
- Implementation evidence: [FHS generation storage](../../dex/consensus/generation.go), [collector reclamation](../../dex/rewards/retirement.go), [fee periods](../../dex/devnet/fee_history.go), and [relay bundle storage](../../dex/relay/bundle_archive.go).

## 2026-09-23 Q0 — Initial Audit (Historical Text Below)

2026-09-23 Q0 read-only source audit. The target is the implementation in `FHS-D-ExchangeCore`, including current uncommitted changes. The initial preservation location is `/tmp/common-dex-live.8gezz_j9`. This is a new document and does not overwrite earlier test assessments or specifications.

The instructions for this work authorized normal builds, deployment, and narrowly scoped stop/restart operations on the designated PM2 network. Earlier deployment prohibitions did not apply to this work. A mid-operation new-generation init required separate approval from a normal restart.

## 1. Facts Confirmed in the Implementation

**Storage-generation switching is not complete in the implementation at this point.** WAL v3's action dictionary and omission of old state copies compress the representation of the same full history. They do not reclaim all 128 records by generation. The following is static source inspection, not a new PASS(LIVE) or PASS(UNIT).

|Target|Limits and classification|Growth, reduction, and behavior at capacity|Information that must survive|
|---|---|---|---|
|DEX FHS|`MaxRecords=128`, WAL 2 MiB. Local storage and fixture execution limits are coupled|Records only append. Config/manifest `MaxHeight` is also at most 128. Reject record/build when full|Own vote, lock, highest QC, timeout, TC, outbox, referenced bodies, finality, unsettled checkpoints|
|DEX snapshot|2 MiB, 128 records. Wire/local restoration limit|Retain all QC-bearing records and finalized entries; reauthenticate/replay from genesis. Import only into a new empty WAL|Do not replace existing voter safety with a peer snapshot|
|Financial state|`len(Fees)==market.Height`, at most 128. DEX consensus execution rule|Append each block; no deletion. Reject financial decoding above 128|Fees for unclosed periods, participation, FIFO/cash/PnL, reservations, inbox cursor, CLX anchor|
|CLX rolling anchor|Cumulative 1024. CLX consensus-state acceptance rule|`Records++` for each newly retained anchor. No decrease. Reject update TX at 1024|CLX references for delayed checkpoints, base IDs, key/committee authentication chain|
|CLX checkpoint|Genesis `MaxCheckpoints`, maximum 4096. CLX consensus rule|Sequence is absolute. Reject beyond the limit. Reward period also bound by limit/10|Old roots, unpaid reservations, claim amount/period, cumulative paid, nullifiers|
|CLX inbox|Cumulative 4096,128/range. Consensus/wire rule|Deposits increase count; no decrease|Unconsumed deposits, consumption boundaries, unique IDs and contents|
|Relay source|1024 segments/32 MiB. 32 headers/range, each within native calldata limits. Local/wire|Append-only. Cold start reauthenticates every range from genesis. Insufficient capacity stops as source durability failure|Historical header/MPT/key context and authenticated anchor chain|
|Participation collector|2048 records/2 MiB. Local storage|Total of Targets＋Issued＋Certificates＋Closed. No deletion|Own LastVote/ClosedThrough, unclosed evidence, closed roots|
|Relay core|Active 256/32 MiB, complete history 1024/8 MiB, total 48 MiB. Local|Limited reclamation. Remove only the oldest reauthenticated complete item without dependent references. Use capacity_wait if reclamation is impossible|Unfinished intent, signed TX, unconsumed nonce. Retain `completed_pending_nonce` as active|
|Financial ingress pool|Pending 64/1 MiB, status 256, disk 2 MiB. Local|Remove pending entries on finalization/rejection. Reclaim only old statuses in FIFO order|Status is not the authoritative record of canonical rights|
|TLS outbox|Queue maximum 256/8 MiB. Local delivery/wire|Remove delivery record after receiver ACK|Do not confuse delivery ACK with financial finality or payment|

Principal evidence:

- [FHS config/record](../../dex/consensus/app.go), [WAL](../../dex/consensus/wal.go), [snapshot](../../dex/consensus/snapshot.go), [state-copy omission](../../dex/consensus/compact.go), and [action dictionary](../../dex/consensus/wal_dictionary.go). `FinalizedHeight()` is `len(Finalized)` and checkpoint/state references use `height-1`; absolute heights and hot-array offsets are not yet separated.
- [Financial execution](../../dex/devnet/execution.go). The Fee array matches absolute height, and RewardClose references `Fees[i-1]`. Generational WAL storage alone still stops at this 128 limit.
- [CLX anchor](../../dex/settlement/native_rolling.go), [checkpoint/claim accounting](../../dex/settlement/adapter.go), [inbox](../../dex/protocol/inbox.go), and [genesis DEX configuration](../../params/dex_devnet.go). These acceptance limits must not be changed through local configuration alone.
- [Source WAL](../../dex/relay/source/wal.go) and [source Advance](../../dex/relay/source/client.go). Currently all segments are re-encoded into one storage generation.
- [Collector](../../dex/rewards/collector.go), [relay reclamation conditions](../../dex/relay/relay.go), [relay state validation](../../dex/relay/store.go), [pool](../../dex/service/finance/pool.go), and [TLS store](../../dex/transport/store.go).

A CLX Claim requires the accepted checkpoint body's withdrawal/reward roots, total reservations, and period, plus cumulative paid and nullifiers. Withdrawals/Rewards in the latest DEX FinancialState cover only that block. Before old WAL data is deleted, settlement bundles and claim evidence for old checkpoints must be secured in separate durable storage.

## 2. Proposed Storage-Generation Design for the Current Schema (Unimplemented)

This is a design candidate, not an adopted schema or implemented feature. Automatic migration of old formats is not required; the new current specification's version/domain must be explicit. Do not activate CLX financial processing or change consensus-state layout by locally overwriting an existing running DB.

1. **Separate absolute heights from hot offsets.** Include the authenticated finalized cut, financial state/root, checkpoint, and descendant finality proof in the snapshot. The hot WAL retains post-cut records and pinned records referenced by own-safety lock/QC/vote/timeout/outbox. Do not reset voting watermarks or signing history during snapshot generation.
2. **Separate historical archive and hot WAL.** First durably archive old finalized checkpoints, proofs, settlement bundles, claim leaves/paths, and required actions. A snapshot hash alone does not establish retrievability; stop explicitly for unavailable data. Apply byte/quotas and acceptance-stop conditions to the archive too. Do not erase unpaid rights to create capacity.
3. **Aggregate closed financial Fee periods.** Retain fee evidence and consensus participation evidence for unclosed periods. Explicitly encode aggregation boundaries, cumulative amounts, and absolute periods in the new codec without changing FIFO/cash/PnL/funding/dust arithmetic. Do not delete unavailable valid evidence to allow reward close.
4. **Archive source-evidence chains by segment.** Separate bounded hot segments from reauthenticatable historical segments. Cold recovery authenticates the archive as a stream; latest RPC, local checksums, and snapshot submitters do not become new trust roots. Do not unilaterally enable public committee transitions beyond authenticated key renewals for the fixed seven participants.
5. **Define CLX retention rules as consensus specifications.** Old unpaid roots, reservations, paid totals/nullifiers survive. If old-root compression is adopted, first specify cumulative commitments, bounded membership proofs, persistent nullifiers, and funding reconciliation together with the codec. Overwriting with only the latest root is prohibited. Simply increasing caps does not constitute generation renewal.
6. **Make generation switching crash-safe.** Fsync archive＋snapshot, fsync the next hot/WAL and manifest, atomically rename the manifest, fsync the directory, and only then delete reclaimable old canonical data. Stop signing and new submissions on indeterminate rename/fsync errors. Every fault point must restore either a complete old or complete new generation and the latest own safety.
7. **Reuse existing relay reclamation.** Preserve the conditions that retain unconsumed nonces/signed TXs and make dependencies between source-archive and core-intent updates explicit. A completed cache does not authorize skipping reauthentication.

## 3. Required Tests (NOT_RUN in This Audit)

|Test|Verification|
|---|---|
|Small-threshold unit|Continuous absolute height/sequence/period across generations; more than merely increasing 128|
|FHS safety crash|Retain vote/lock/QC/TC/timeout/outbox before and after the cut; reject double voting after restart|
|Storage crash|Selected faults in archive/snapshot/fsync/rename/dir-sync; do not resume signing from an incomplete generation|
|Old claim|Pay an unpaid claim exactly once across generations; restart/retry from another relay must not increase payment|
|Source authentication|Follow from an old anchor in bounded ranges; reject corrupt/missing archives, altered metadata, and another domain|
|Finance regression|Preserve independent golden data and FIFO/PnL/funding/dust, support exhaustion, insurance shortage/FROZEN|
|Relay nonce|Retain unconsumed nonces and unfinished jobs across stops before/after signature persistence, after ACK, and after finality|
|Real-configuration LIVE|Same generation on the designated PM2 network, no mid-operation init, at least two switches at real caps, unpaid/paid claims, and 60 minutes of mixed financial operation|

Component tests and real-network tests are separate. Only static-source limits and retention behavior are confirmed at this point; the new tests above have not run.

## 4. Read-Only Check of Financial Activation on the Existing DB

The workspace `genesis.json` has chain ID `10101919`, a seven-member CLX committee, `fairHotstuff=true`, `fixedCommittee=true`, and no `dexDevnet`. Its mixHash is `0x73a979fba0ba41027e06626a2d94ac71e55476a36244bcda9acb2288d8510257`. This is the **genesis configuration commitment, not the genesis block hash**. This section does not open the live DB; live canonical-genesis agreement is reconciled against the coordinating Q0 observation.

The current official implementation has no path to enable financial processing on an existing DEX-disabled genesis DB merely by adding CLI/manifest settings.

- `ToBlock` in [core/genesis.go](../../core/genesis.go) includes custody nonce=1 in the state root only for DEX-enabled genesis. Enabling DEX changes both the root and genesis hash.
- `FairHotstuffGenesisCommitment` in [params/config.go](../../params/config.go) binds all configuration, including `DEXDevnet`, to the genesis mixHash.
- `SetupGenesisBlock` rejects a supplied genesis-hash mismatch; `validateFairHotstuffConfigTransition` rejects a mismatch between the existing genesis mixHash and new configuration. Startup without a supplied genesis adopts the existing DB configuration.
- `DEXGenesisConfig` in [core/dex_native_context.go](../../core/dex_native_context.go) reads the DB configuration saved under the canonical genesis hash, and `authenticateDEXGenesisConfig` rejects differences between runtime and genesis. The only permitted local fields are `RnetPort` and `EnabledTPS`.
- `loadNative` in [dex/settlement/native.go](../../dex/settlement/native.go) also rechecks DEX activation, genesis/config commitment, and custody nonce=1/empty code.
- [dex/clxevidence/finality.go](../../dex/clxevidence/finality.go) verifies the source genesis commitment, and fixed-key renewal activation also depends on DEX config version3. Inserting a false DEX configuration into a manifest cannot pass deposit-source authentication.

Therefore, **live financial operation reusing the current design requires separate approval for a mid-operation new-generation init**. An alternative authenticated protocol upgrade to the current generation is conceivable, but that path does not exist in the implementation and was neither introduced nor approved by this audit. Direct DB-config rewriting, direct custody creation, or relaxed genesis authentication are not substitutes.

Normal binary deployment, same-DB restart and CLX regression, and nondestructive storage design/unit development can proceed independently. Separate only the affected financial LIVE tests as BLOCKED; do not make this a permanent blocker for the whole deployment.

## 5. SHA-256 of Audited Targets

```text
87116776000a545f813061c5a1ed2599fb550317a4827a0d5803f7bba0aa3bc6  dex/consensus/app.go
58758fbb381a7823ff63c74050935912674627237576fe8f6e6a738c60fd545b  dex/consensus/wal.go
ab6486a77dc0ea116dee93fb52fc9171edf0a2be02b011db42ff877f68c10247  dex/consensus/snapshot.go
75025ec5aa5f137eea7c404b6ece2f193ed14c72a85d67e950422e3ab751124e  dex/consensus/compact.go
1e701cca3bc4e52cb6331a012e37275fee3e630dfaf12b74e15d718ba7bc2904  dex/consensus/wal_dictionary.go
27c7756b02ccd990eb53a1bddc2d957b6748cfbbfaecda8dcd14a420b81fb996  dex/devnet/execution.go
30d0c0dc5c389b1ba6c81ed5257db5ca037da8939fef889b7452d59b7c21152f  dex/settlement/native_rolling.go
8ad345bed1d27ac0a145b4ce40de37c52cce899e03d4c76cc9666cffd88102ea  dex/settlement/adapter.go
2adb5071b37524d488e8ca1356c2c97f555f7257bde9c1febafd18e03176e815  dex/protocol/inbox.go
ec86c2bf9f5e14357fb504ad46e0ba7676f94849d45a54c013eaf7ed9507d8bc  params/dex_devnet.go
9d913668394a2d2fc3f1ea9cb0c4fbdc25404ebbfd7a8c4650bca8a503440bf0  dex/relay/source/wal.go
9f92837d4954f831a6a0468a8a4cbe4c0de5a2486a45afb84ff4dd7e2e71899e  dex/relay/source/client.go
9cabb6105defbeac25d98b1f3140fa75226f381a8e872a6b57469164ab581e0b  dex/rewards/collector.go
7c3477f4b43c7dfa5d98a81be28369e714475974f4a0f0127945b4fca9b6b3dd  dex/relay/relay.go
15aa3ae4d0642e2b53bbb90befd3a79e6f7b17438db10317424263d9bfaa73c6  dex/relay/store.go
c91cfe5156f7478151f47ea3b436dcf3920f360f41df092676183a0025a47e3a  dex/service/finance/pool.go
e6f13fa51bc8545ddf65374bf2c72be48f3f81696f2becf247aefb1df03fce8a  dex/transport/store.go
e4147dd3785705b389d713a3689a1e7383464fb8c2eaaad373b0fab1fe2ada41  core/genesis.go
3c9e9d2b65c5e05c67440e085a421ac86f93f0be89b773dd8d2c651bd7ca380e  core/dex_native_context.go
ac15f411dd7f9379c598b1434e28763ab46424cd408395aa3d09166c3ffb2ab3  params/config.go
131acbb21ef77f4229c91a639c51348bc1d0f0f5b6c4cbf4299e46c90efd4b1f  genesis.json
```
