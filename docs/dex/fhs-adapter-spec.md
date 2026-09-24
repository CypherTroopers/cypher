# Isolated FHS application adapter, devnet v1

This specification precedes implementation of the instance committee resolver.
It selects reuse of the existing `reconfig/hotstuff` protocol manager and its
NewView/TC/vote authentication and two-chain rule. It does not introduce another
consensus or finality rule. See `consensus-audit.md` for source evidence.

## Committee dependency injection

An optional `hotstuff.CommitteeResolverApplication` interface supplies
`ResolveHotstuffCommittee(keyNumber uint64, keyHash common.Hash, needIP bool)
(*bftview.Committee, error)`. The supplied number/hash must be an exact entry in
the application's authenticated historical registry. An implementation must
return an immutable snapshot, or hold its registry lock until copying it; it
must never resolve a foreign/missing generation as the current one.

All four existing direct protocol committee loads pass through a manager helper.
For applications without the interface, the existing CLX global lookup remains
the fallback, preserving existing CLX behavior. Once the interface is implemented,
an error, nil committee, invalid size, missing/duplicate identity or key,
commitment mismatch, or difference from `GetPublicKey(keyHash)` rejects the
operation. It **never** falls back to the CLX global.

For resolver applications the manager copies both the node slice and each node,
checks `n=3f+1`, checks the expected ordered committee hash, and verifies every
hex-encoded node key equals the corresponding application public key. Node
addresses identify protocol senders and must be nonempty and unique. The
application must bound and authenticate endpoints; the existing committee hash
commits ordered coinbases and public keys, not addresses. Endpoint identities are
an immutable part of the separately authenticated fixture registry; every proof
must check leader ID against that registry and the view's leader schedule.

View initialization must apply the same resolver validation before recording
the signer ordering. No DEX path calls `SetCommitteeConfig`, `SetServerInfo`,
`SetServerCoinBase`, `Committee.ToBlsPublicKeys` (which uses global cache), or
CLX miner lifecycle functions. The manager remains serialized by its owning
control loop; resolver injection is not a claim of arbitrary concurrent manager
method safety.

## Reused transport metadata

The narrow adapter reuses existing `bftview.View` and
`types.HotstuffProposalRef` RLP metadata. It does not construct or execute an EVM
block to represent a DEX action. Application payloads use the DEX canonical codec
and are execution-verified before a vote. Compatibility fields map as follows:

| Existing field | DEX meaning |
|---|---|
| `View.TxNumber`, `TxHash` | Selected execution-parent DEX height/hash |
| `View.ViewNumber` | Certified/timed-out protocol view watermark |
| `View.KeyNumber`, `KeyHash` | DEX epoch and authenticated domain+epoch commitment |
| `View.CommitteeHash` | Existing RLP hash of ordered DEX member coinbase/public keys |
| `View.LeaderIndex` | Deterministic DEX application leader in that registry |
| `ProposalRef.Number`, `ParentHash`, `BlockHash` | DEX block height, parent and canonical block hash |
| `ProposalRef.ViewNumber`, `ViewID`, `LeaderID` | Existing FHS proposal context |
| `ProposalRef.StateRoot`, `BodyHash`, `BodySize` | DEX post-state root and exact bounded DEX body commitment |
| `ProposalRef.ExtraHash`, `ParentQCID` | Existing protocol proof and semantic QC commitments |
| `ProposalRef.KeyHash` | DEX domain+epoch commitment |
| CLX-specific receipt/admission/reward/gas fields | Canonical zero; never used as CLX RPC or PoW rewards |

ProposalRef version stays its existing version 5; FHS context/TC wire version
stays 3. The DEX canonical body's own protocol version is independently committed.
`Time` is the explicitly specified DEX logical clock; it does not modify CLX time.
The adapter must check all unused fields are zero instead of admitting multiple
equivalent encodings.

Every DEX epoch registry key is `protocol.Domain.EpochKey()`, the SHA-256
commitment specified in `protocol-spec.md` to domain (`CLX chain ID`,
`CLX genesis hash`, `DEX ID`, DEX protocol version), epoch, and ordered
coinbase/public-key committee commitment. This full commitment occupies `KeyHash`;
it must not be shortened to a numeric synthetic chain ID. Thus timeout and NewView
objects, which do not carry the DEX body, also bind the full domain through
`KeyHash`. `GetPublicKey`, resolver and `ValidateFHSContext` admit only that
application's authenticated registry. The main DEX codec specification fixes
the concrete epoch commitment bytes and golden vectors before DEX app code.
Activation boundaries and endpoints are checked against that registry separately;
the epoch hash must not be described as independently committing them. The initial
fixture selects leader index `(view-1) % 7`, with view starting at one.

## Required DEX application interfaces and state

The new app owns transport queues, worker budget, WAL, data store and registry.
It implements `HotStuffApplication`, `FHSApplication`,
`CommitteeResolverApplication`, `FHSProposalBuildApplication` (required by the
current FHS leader path), `FHSProposalParentApplication`,
`FHSLeaderKeyApplication`, `FHSTimeoutVoteRecoveryApplication` and
`FHSLeaderCertificationApplication`. Validation may initially use synchronous
`OnPropose` on its dedicated sidecar; bounded worker callbacks are preferable
when execution becomes substantial. Missing data returns an explicit
`ErrProposalDataUnavailable` and is never voted as an empty action.

Keep highest observed QC separate from quorum-selected execution parent.
Persist proposal data, last vote, last timeout statement, highest QC/TC and
leader QC dissemination outbox under the DEX domain. Fsync before signing;
fail closed on a foreign/corrupt WAL, lock collision, sync failure or missing
parent state. Reconstruct and reexecute authenticated bodies before voting
after restart. `OnCertified` must validate the two-chain/ancestor rule before
publishing finality. A single QC only updates certification.

Epoch changes require the preinstalled devnet registry's explicit activation
boundary. Production registry governance remains unresolved. A new committee
must not self-authorize using its own signatures.

## Resolver isolation gate

The immediate implementation gate exercises one existing CLX global committee
and two independent DEX app committees in the same process. It must show:

* Both DEX contexts resolve their own ordered keys and reject the other's context.
* Correct same-domain QCs verify; foreign chain/DEX/epoch contexts and QCs fail.
* Resolver failure and nil/malformed data never use a valid CLX global entry.
* Bad committee commitment, reordered keys, duplicate identities/keys and nil
  members fail before a vote; returned node objects cannot mutate provider state.
* CLX global identity, coinbase and committee remain unchanged by DEX calls, and
  existing no-provider behavior still works.
* Existing `reconfig/hotstuff` regression tests pass.

Passing this gate establishes dependency isolation only. It does not establish
a seven-process DEX, WAL durability, complete B, C/D, native custody, data
availability, performance, or production safety. Those results must be recorded
separately when run.
