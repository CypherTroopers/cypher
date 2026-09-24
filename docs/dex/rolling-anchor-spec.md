# Rolling authenticated CLX anchors — isolated devnet v3

This specification extends the existing native v2 experiment; it does not
reinterpret its genesis, checkpoint schema3, evidence v1 or financial goldens.
G0 found and corrected local reward-certificate dependent proposal validation;
the committed-participation regression and CLX boundary checks must pass before
enabling this extension. All new tests begin NOT_RUN. This remains a fixed
seven-member, epoch1, committee-trust experiment, not a validity proof.

## Two state machines and their trust roots

The DEX execution state authenticates CLX inbox data. CLX settlement independently
authenticates the source anchors referenced by DEX checkpoints. Both start with
the exact consensus-committed CLX genesis, chain configuration, genesis key hash,
DEX identity and custody address. An HTTP result never supplies a trust root.
CLX source committee and DEX checkpoint committee remain distinct. Unknown key
hashes, epochs and committee transitions fail closed.

New isolated genesis uses `DEXDevnet.Version=3`. Its DEX checkpoints use
`DataSchema=4` in the unchanged 525-byte checkpoint structure. Its native empty
DEX root uses the new `common-dex/native-genesis/v3` hash domain and its financial
state uses version5 / `common-dex/financial-state/v5`, with committed reward
participation present from genesis. Old config2/schema3 and financial versions
1–4 retain their previous meanings. Mixed schemas and WAL execution identities
are rejected. No existing or operational genesis is upgraded implicitly.

## Canonical anchor and evidence

An anchor is exactly246 bytes, fields concatenated in this order, integers
unsigned big endian: version(u16=1), chainID(u64), genesis(32), DEX(32), custody(20),
height(u64), blockHash(32), stateRoot(32), sourceKeyHash(32), sourceCommittee(32),
sourceEpoch(u64=1), inboxCount(u64). Its identifier is SHA-256 of
`common-dex/clx-anchor/v1` followed by NUL and these bytes. It has no local
counter: authenticating the same target through different segment sizes produces
the same identifier. An anchor record supplied by a client is not a capability.
The base passed to verification MUST come from authenticated parent state.

Rolling evidence v2 is canonical RLP of version2, base-anchor identifier,
header witnesses, custody account proof, inbox-count proof, and entry proofs.
Each header witness contains canonical header RLP (including SignInfo) and the
exact signed HotstuffProposalRef bytes. The target proposal ref must match every
header-derived field, including state/transaction/receipt roots, hash, height,
parent, gas, key hash, time and block type, plus the SignInfo view, leader,
ExtraHash and ParentQCID. Body hash and size are the QC-attested commitments.
The ordinary CLX validators still execute and validate the complete body.

Using headers avoids recursive evidence growth: a full source block can itself
contain a prior anchor/checkpoint TX and its evidence. Such recursive full-body
proofs are not accumulated. Header hash equality is insufficient: target QC,
canonical signer mask, deterministic leader, source domain, and the existing
descendant proof with exact parent QC identity and terminal consecutive-view
edge are all verified. A single target QC is not finality.

There are at most64 consecutive source headers per update, starting immediately
after the trusted base. Every header's finality is checked. Same-anchor evidence
may contain zero headers to prove another inbox range against an already trusted
root. The derived inbox count cannot decrease. Entries are strictly contiguous
from the committed DEX cursor, match all identities, and are proven against the
target custody storage root. Empty entry ranges allow anchor-only catch-up.
Deposits are credited only after both finality and exact MPT inclusion succeed.
Base-anchor mismatch, historical-data absence, malformed bytes and invalid
authentication are distinct errors; none advances state or invents freshness.

## DEX persistence

FinancialState version5 contains the full current anchor, separate from the
legacy height/hash field. It is hashed, finalized and WAL-replayed along with
the engine cursor and committed participation state. A rolling inbox action
uses evidence v2 and advances this anchor atomically with any imported entries.
Zero-entry actions advance authenticated knowledge without manufacturing funds.
Admission may check immutable bounds/authentication, but only deterministic
execution against the proposal's committed parent anchor can accept continuity.
Local source caches and collector state are never validity predicates.
The distinct `CDXA` action marker carries rolling evidence v2; legacy `CDXI`
continues to carry only evidence v1.

The read-only `eth_getCLXFinalityWitness` RPC takes one explicit positive block
number and returns hex-encoded canonical header/proposal-ref bytes from available
canonical storage. It accepts neither `latest` nor `pending` as an authenticated
anchor and returns an unavailable error if the required body/finality metadata
cannot be obtained. It is enabled only for the isolated FHS DEX configuration.
This transports untrusted evidence: consumers still verify every QC, continuity
and MPT proof. It is not a new authority or canonical-state mutation endpoint.

## CLX native anchor update and checkpoint acceptance

Native opcode6 (`AnchorUpdate`) is enabled only by genesis config3. The existing
CDXN outer transaction envelope remains version2; its body is canonical RLP
`[1, RollingEvidenceBytes, Continuation]`, with zero entries in the evidence.
Continuation is empty for ordinary tip advancement; historical insertion is
specified below. It passes the normal nonce, gas, admission, snapshot,
receipt and canonical-state pipeline. No callback writes canonical state.

CLX stores a certified tip, immutable anchor records keyed by source height,
their accepted evidence digest, an anchor-count budget, and
`confirmedThroughHeight`. Ordinary updates extend the stored tip; historical
insertions fill omitted heights without rolling it back. Both use at most64
headers total. Old/equal-height exact evidence replay is a semantic no-op; conflicting
payload at an occupied height or a stale base for a new target is rejected.
A delayed relay reads authenticated canonical state and rebuilds its next step.
New transaction nonce/gas costs still apply to semantic replay.

A long lag cannot be resolved by an unbounded GetHash walk. An old authenticated
segment can advance the **staged certified tip** without authorizing a checkpoint.
When a segment reaches a target strictly before the executing block and within
the unchanged64-block GetHash window, its hash MUST equal that canonical ancestor.
Only then does confirmedThrough advance, confirming all earlier stored anchors
on this single continuous chain. A mismatched recent ancestor rejects the TX.
Staging does not credit funds, reserve rewards or authorize claims. This assumes
the existing source BFT trust model; a quorum signing contradictory finality can
freeze progress and is not repaired by a new untrusted fallback.

A schema4 checkpoint may reference a retained anchor at/below confirmedThrough,
with exact hash and authenticated inbox count, without reapplying a64-block age
limit to an already authenticated fact. CLX checks its own immutable inbox
entries, their inclusion heights, cursor, commitment, finance summary and DEX
finality proof. It never imports the DEX matching/risk/funding/liquidation engine.
New source evidence is submitted separately as ordinary anchor-update TXs.
Schema4 checkpoint evidence bytes must be empty; no second implicit update path.

## Bounds, rights and stopping

Existing limits remain:64 source ancestors,8 descendants/header,7 source signers,
2048-byte proposal refs,16KiB finality/header,65 MPT nodes/path,1024 bytes/node,
128 entries/range,4096 inbox entries,4MiB offline evidence,64KiB native calldata.
Canonical header witnesses have an additional20KiB per-witness bound. Shape and
aggregate byte/count limits are checked before cryptography. The native64KiB
limit usually forces smaller batches than64 headers; relays split dynamically.
Target and descendant signed refs retain the existing1MiB source-body bound.
The transport builder also checks source block size before deriving its ref;
blocks beyond this experiment's bound are explicitly unavailable to this relay.
Anchor update gas is12,000,000 plus40 per calldata byte (plus normal intrinsic
gas), matching the existing conservative checkpoint schedule, not a measured
production price. A successful anchor stores at most16 fixed32-byte slots,
including metadata/counters; exact replay writes none beyond ordinary TX costs.
At most1024 anchor records are retained. No anchor pruning is introduced.

CLX storage uses the existing namespaced settlement slot codec: anchor bytes are
eight `rolling-anchor(height,index=0..7)` slots; `rolling-id(height)` and
`rolling-evidence(height)` store its identifier and accepted-evidence digest.
`rolling-meta(0)` is one32-byte slot of tipHeight:u64, confirmedThrough:u64,
recordCount:u64, reserved:u64=0. The anchor-ID lookup described below adds
one slot, so an established update writes12 slots. First-use config/root and a
newly observed unallocated surplus add at most3, for15, remaining below16.
Genesis is implicit from authenticated configuration and
does not consume a record. The evidence digest domain is
`common-dex/native-anchor-evidence/v1`. Exact replay returns anchorID plus byte1
without a new log or storage write; a new update returns anchorID plus byte0 and
emits the anchorID and confirmedThrough:u64. Reusing an occupied height with
different canonical evidence is a conflict, even if it describes the same root.
An opcode6 request must advance the tip, insert a proven historical anchor as
specified below, or exactly replay an accepted payload. General same-anchor
zero-header evidence remains useful for DEX inbox
proofs but cannot create a new native anchor record.

Independent `scripts/dex/native_rolling_vectors.py` fixes the v3 genesis root,
slot keys, packed metadata and opcode6 outer frame before the Go implementation.
Its opaque example body tests framing only, not acceptance of evidence.

Old checkpoint finance roots, unpaid reserves and nullifiers retain the existing
bounded history (genesis MaxCheckpoints, maximum4096). Anchor updates cannot
expire rights. Capacity exhaustion rejects new work without deleting unpaid
claims; claims against retained roots remain enabled. Existing DEX128-record,
1MiB-state and queue limits remain explicit experiment capacity limits. This is
bounded repeated operation, not an unlimited-lifetime storage claim. Catch-up
cost increases with the number of segments and claims even though each is bounded.

## Verification gates and non-goals

Independent byte/hash goldens precede implementation. Focused tests cover both
directions, strict continuation, exact/conflicting replay, old claims, rollback,
wrong roots/identities/epochs/parents/metadata, orphan/unfinalized headers, range
and MPT changes, capacity, and cold replay. Then normal CLI real-socket runs must
cross257 CLX blocks with new financial work on multiple intervals, long-lag
recovery, and settlement of later DEX sequences after CLX resumes. The original
225→214 run remains a separate regression ledger. Evidence bounds, gas, writes,
signatures and observed resource costs are reported separately from performance.
Relay durability and authenticated completion are specified in
[continuous-relay-design.md](continuous-relay-design.md).

No new FROZEN loss/recovery rule, public committee transition, production fee,
PoW alteration, emission or wrapped asset is introduced. Missing historical data
can halt recovery; a DA root does not guarantee availability. General reward
inclusion fairness and whole-financial-state permissionless snapshot bootstrap
are separate from deterministic committed-participation validation.

### Historical anchor insertion (fixed before implementation)

Opcode6 body is canonical RLP `[Version=1, RollingEvidenceBytes, Continuation]`,
where Continuation is a list of the same bounded `[HeaderRLP, ProposalRef]` pairs.
The sum of evidence headers and continuation headers is at most 64, checked
before cryptography, and the complete outer native call remains at most 64 KiB.
Usual tip advancement has empty Continuation and must start at the current tip.
Historical insertion starts at any retained base, proves a strictly later target
with account/count MPT proof, and has a nonempty continuation from the target to
an already retained strictly later descendant. The continuation endpoint hash
and state root must equal that record. Thus targets skipped by another relayer
can be recorded later without rolling the tip back. Historical insertion increments
only the record count; tip and confirmedThrough stay unchanged. A record at or
below confirmedThrough is usable by schema4 checkpoint. No GetHash traversal is
performed for historical insertion; the authenticated descendant supplies the link.
The alternate-branch and missing-descendant cases fail. Genesis is an implicit
base, but schema4 financial checkpoints require a retained nonzero source height.

Each stored anchor additionally writes one ID lookup slot
`SHA256("common-dex/settlement/rolling-height-by-id/v1" || 0x00 || AnchorID)`
whose value is its uint64 height encoded in a zero-padded 32-byte word. This permits
one keyed base lookup without scanning the retained history. The record costs **12 writes**, and first initialization plus changed surplus
adds at most 3, for **15 writes**, below the unchanged maximum16. Exact evidence identity covers the whole
new opcode body, including Continuation, so a different body at an occupied target
height is a conflict; exact replay still performs zero storage writes or logs.
Python native_rolling_vectors.py fixes this envelope and index before Go code.
