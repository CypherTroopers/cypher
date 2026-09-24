# G2 network authorization and discovery

This extends the fixed G1 spec and relay-core spec. All endpoints supply
untrusted data. The source client preserves and revalidates a bounded chain of
header/MPT segments from the configured genesis. A numeric latest height is
only a discovery hint. CLX observations use the source client's authenticated
anchor root, exact account/storage proofs and the configured custody/payer.
Neither a receipt JSON status nor an HTTP ACK completes work.

Job ID is SHA-256(`common-dex/relay-job/v1` + NUL + domain.EpochKey(32) +
custody(20) + lane(u8) + semanticKey(32)). The key is target anchor ID for
Anchor, checkpoint hash for Checkpoint, claim leaf hash for Claim. Inbox uses
SHA-256(`common-dex/relay-inbox-key/v1` + NUL + start(u64 BE) + end(u64 BE) +
counted entry root(32)); an empty range uses the target anchor ID instead.
Changing gas payer, transaction nonce or equivalent proof bytes does not create
a different business identity. Stored pending bytes stay immutable; conflicting
payloads for the same local ID are reported and reconciled against chain state.

The network backend verifies each job's authorization before marking it ready.
Checkpoint and claim authorization is the complete bounded settlement bundle:
registered DEX epoch/finality, canonical finance hash, complete claim sets and
their counted roots/totals. Native calldata is reconstructed from that verified
bundle and must match exactly. Anchor authorization is the canonical target
anchor, checked against the update evidence and a base read from authenticated
CLX storage. Inbox authorization is a source-proof-authenticated target anchor;
execution still checks the actual DEX parent anchor/cursor. No caller-supplied
anchor becomes a source trust root.

Completion requires exact checkpoint-history hash, exact nullifier leaf, or
exact stored anchor ID in a finalized CLX root. Staged anchor acceptance is
recorded separately from permission to use it financially (confirmedThrough).
One staged transaction must finish its own nonce before the next catch-up step;
the planner keeps creating steps until canonical confirmation. Claim readiness
requires the checkpoint's accepted hash. Checkpoint readiness requires the next
sequence and a retained confirmed source anchor. Conflicts quarantine a job;
missing data and dependencies wait. Payer nonce and balance come from account
proofs against the same authenticated root as the economic observation.

DEX inbox completion follows the semantic job ID, not equivalent proof bytes.
An empty CDXA completes when a verified schema4 checkpoint references the exact
source-authenticated target anchor, or a later anchor authenticated from the
same immutable contiguous source chain. Its execution-data hash need not equal
this relay's encoding of the equivalent action. A nonempty range completes only
when contiguous verified checkpoint ranges cover every pending entry and each
range commitment equals the corresponding authenticated entries. Subranges
within the job use its already-verified entries. For a broader overlapping
checkpoint, authenticate that checkpoint's source anchor, fetch at most128
entries, verify the complete same-anchor MPT range and root, then compare the
overlap entry by entry. A cursor alone never establishes credit. Contradictory
authenticated commitments are conflicts; missing proofs wait. The step retains
its three-second deadline and4MiB observation bound. The inbox forensic DEX field
contains RLP `[1, [verifiedSettlementBundleBytes, ...]]`; completion is freshly
revalidated on reopen rather than inferred from this stored forensic blob.
Discovery walks at most the existing128 checkpoint records in
order, checks Previous/PreRoot and registered proof, and caches only verified
bundles. Provider status merely bounds attempts and never supplies finality.

The planner may prepare multiple bounded source updates. An unretained old
checkpoint reference is registered with G1's historical continuation proof;
nearest retained bases/endpoints are found with bounded storage proofs over at
most64 heights on either side. It never raises64/64KiB limits. Missing history
waits with an explicit error. Each historical leg is fetched as at most two
32-header source ranges, then recomposed and reverified from its original
authenticated base; only the final target's MPT proofs are retained in the
combined leg. The combined update still has at most64 headers and the existing
native calldata byte cap. The32-header per-source-request limit is unchanged.
A legal header count does not guarantee that its particular proof bytes fit;
oversized historical evidence remains explicitly unavailable. Native actions
are ordinary signed zero-value TXs
to custody, with independent gas keys. Deposits, orders, oracle updates, reward
close and support top-ups remain separately authorized operator/user inputs.

Default relay discovery polls finalized checkpoints and their claims; optional
inbox automation builds CDXA only from authenticated source entries and the
verified DEX cursor. The planner is constrained by pending job/history budgets
and finite experiment record limits. Queue saturation cannot delete reserves,
unpaid claims or unresolved signed transactions. The CLI is explicitly isolated
devnet/loopback, separate from DEX voting and Common RPC signing. It has no remote
public administration API. A local status file reports observed stages and
errors; it is not financial authority.
