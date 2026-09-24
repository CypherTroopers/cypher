# G2 settlement bundles and explicit financial bootstrap

This isolated-devnet format was fixed before implementation. It transports
authenticated finality and accounting, not computation validity or evidence that
CLX has already accepted a checkpoint or paid a claim.

## Bundle version1

Canonical bytes concatenate `CDXB`, version u16=1, canonical checkpoint525 bytes,
canonical FinanceSummary456 bytes, proof length u32 and DEX finality proof bytes,
withdrawal count u16, reward count u16, then each withdrawal path followed by each
reward path. All integers are unsigned big endian. A path is canonical Claim239
bytes, index u32, count u32, depth u8 and depth32-byte siblings. Combined claim
count is at most128, each depth at most7, proof at most16KiB, entire bundle at
most128KiB. Bounds and fixed-width codecs are checked before signature work.
The framing golden uses an explicitly opaque, invalid finality-proof placeholder;
real FHS proofs are exercised separately by Go tests.

Each category contains its complete set, ordered by strictly increasing claimID,
with index equal to its position and count equal to the category size. Domain,
sequence, kind and period must match the checkpoint. Each counted inclusion path,
the complete reconstructed counted root, and the u128 sum must match the
checkpoint root/total. Empty categories have zero root/total. Finance domain,
sequence, withdrawal total and reward period match the checkpoint; fees+support
reward funding is a bounded u128 sum equal to RewardTotal. FundingRef is the
canonical summary hash. Schema2–4 are supported; schema1 is not financial.

`checkpoint.VerifySettlementBundle` requires an independently registered Epoch
and verifies the target and descendant FHS proof using the existing exact rule.
Its return value owns copies of the bundle and exposes immutable copies of
checkpoint, finance, proof and claim paths. This consumer does not import the
engine. It does not authorize epoch changes, custody debits or transaction
submission by itself. CLX's native handler still applies authenticated inbox,
source-anchor, budget, nullifier and normal transaction rules.

`GET /v1/settlement?height=N` runs on the existing serialized DEX actor, reads an
already finalized checkpoint and full financial state, verifies their root and
summary binding, and returns JSON `{ "Bytes": "<base64 canonical bundle>" }`.
No state mutation, collector-local validity predicate, current-state inference
or background CLX write is introduced. Missing retained data is unavailable.

## Snapshot bootstrap

`GET /v1/snapshot?height=N` accepts only the actual current finalized tip, greater
than zero. The response is `{ "Height": N, "Bytes": "<base64 snapshot>" }`.
The canonical snapshot is the existing replaySnapshot version1, capped at2MiB:
exact genesis bytes/root, domain/execution identity, complete certified records
and finalized proofs. It contains no keys, local votes, timeout watermark or
outbox. JSON API output is capped at3MiB to accommodate bounded base64 expansion;
the snapshot itself retains its stricter2MiB bound.

The optional manifest `BootstrapSnapshotFile` must be an absolute regular-file
path. Service.Open reads bounded bytes and invokes bootstrap after constructing
and recovering the locally registered Application, before opening transport,
ActorInit, Start or any vote. The existing ImportSnapshot validates canonical
encoding, exact configured genesis/domain/execution identity, all parent-state
reexecution, complete records and QC/finality proofs. Failed import cannot begin
signing. The local vote key must already match its own registered member.

The initial import is permitted only for an empty WAL and records the digest
`SHA256("common-dex/bootstrap-snapshot/v1" || NUL || canonical snapshot bytes)`
as local SnapshotOrigin in the same durable WAL update as the verified records.
The origin is not imported from peer data. Existing ImportSnapshot remains a
strict empty-only operation. Service startup uses BootstrapSnapshot: on a later
restart, an identical origin is accepted as a no-write operation after normal
WAL recovery, even if the local voter has since advanced. A different snapshot,
or an existing voter with no matching bootstrap origin, is rejected. Thus a
manifest may retain its bootstrap file without replacing durable own votes.

This bootstrap is a bounded full replay from trusted genesis. It does not prune
history or establish permissionless whole-financial-state sync at arbitrary
scale. Missing action/state data fails closed; data roots alone do not suffice.
PoW, Common RPC admission and CLX committee membership are unchanged.
