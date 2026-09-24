# Current scope

The current wire extension is RLP v4, described in the final section: it authenticates normal CLX deterministic reordering of the same seven registered identities. The earlier v3 sections preserve the fixed-order codec semantics and are retained for compatibility. Public membership changes remain unsupported. PoW reward-candidate-bearing key renewals are explicitly unsupported in this verifier; the current continuous fixture has PoW disabled and does not establish real PoW coexistence. CLX cadence and committee rules are unchanged.

## Legacy RLP v3: fixed ordered committee key renewal

The following paragraphs specify the retained v3 interpretation, before the v4 extension below. Version 3 extends rolling evidence only for config3's fixed, exact ordered seven
genesis members. It does not authorize a public membership epoch, replacement
validator, changed endpoint/reward identity, or reordered committee. Existing
CLX keyblock cadence, signatures and finality rules are unchanged.

Anchor v1 remains246 bytes and uses `common-dex/clx-anchor/v1`. Anchor v2 is286
bytes: the original ordered fixed-width fields with Version2, followed by
`ActivationEnd:u64be` and `ActivationRoot:bytes32`; its ID uses
`common-dex/clx-anchor/v2`. In v2, SourceKeyHash identifies the currently
authenticated keyblock. SourceCommittee remains the exact ordered genesis
committee commitment and SourceEpoch remains1. The extra fields are zero when
no old-key activation descendants remain above the anchor's height. Otherwise
ActivationEnd is above Height by at most8 and ActivationRoot is nonzero.

Boundary IDs are the chronologically ordered semantic QC IDs of the complete
old-key finality proof of the key carrier. Their commitment is
`SHA256("common-dex/clx-key-boundary/v1" || NUL || count:u8 || ids32...)`, with
count1..8. This commits each exact signed ref, chain/key domain and state; it
is not a claim that any old key remains generally eligible. Each supplied QC
still receives full signature/context verification. A noncurrent-key QC is
permitted only by exact semantic-ID membership in this authenticated list.
Current new-key QCs must lie strictly after ActivationEnd. Once the next
anchor's height reaches the activation end, both boundary fields are cleared.

Rolling evidence v2 retains its original bytes and semantics. Explicit RLPv3 is
`[3,Base,Headers,AccountProof,CountProof,Entries,KeyHeader,BoundaryIDs]`.
KeyHeader is canonical RLP of the base's current `types.KeyBlockHeader`, at most
512 bytes, with hash equal to the caller-authenticated base SourceKeyHash.
BoundaryIDs is at most8 hashes and must reproduce the base ActivationRoot; it
must be empty when that root is zero. No key history is appended. Only key
carriers in this update's contiguous headers can introduce another key.

The existing source read `eth_getKeyBlockByHash` supplies an untrusted header
preimage; the client reconstructs the header and checks its hash. RPC-reported
hash/currentness is not authority. On cold restart the source WAL replays all
stored bounded ranges and reconstructs the same anchor; no new key is learned
from a mutable runtime setting.

For a carrier, verify its exact header/ref/KeyInfo binding and old-key target QC,
then every old-key descendant and the existing terminal consecutive-view rule.
The new key must have the exact authenticated parent hash, next key number,
carrier transaction parent, allowed Time/Pace type, deterministic timestamp
under the existing zero-time-genesis exception or600-second cadence, and exact
same ordered committee/body identities. PoW candidates and any incoming/outgoing
member or order change are unsupported and rejected. The new key is activated
only after this complete proof. The still-pending old QC IDs are retained in
the resulting anchor, so carrier255/old-child256/new-child257 is handled without
an unrestricted old-key grace period.

The64-header ancestor bound,8-descendant bound,64KiB native/action limit and
4MiB source-evidence limit remain unchanged. Long lags advance through multiple
short updates from the last authenticated anchor. Renewal evidence does not
grow with the number of historical renewals. A v2 anchor occupies9 storage
words rather than8; the native first-write budget stays16 (9 anchor words plus
4 existing metadata/ID writes plus3 initial materialization writes).

Legacy v1 decoding is preserved. Fresh config3 runs produce v2 at their first
supported renewal. Existing v1 anchors that already passed a renewal without
recording its activation context do not acquire a guessed current key; an
explicit authenticated migration would be a separate feature.

Independent codec goldens precede implementation. Required gates include
unchanged v1 bytes/IDs, altered carrier/body/key header, missing/single/bad QC,
new key used too early, arbitrary old key after activation, exact old activation
child, cleared boundary, repeated short renewal segments, source/native cold
restore, historical continuation, and financial credit using the new anchor.

## Authenticated permutation extension (RLP v4)

The normal fixed-membership CLX path still applies `Committee.Add(nil,
authenticatedPRFLeaderIndex, "")`. It can permute the same seven identities;
rejecting that normal operation would stop the continuous experiment. This
extension authenticates exactly that deterministic permutation. It does not add,
remove, substitute or admit a validator. SourceEpoch remains 1.

Anchor v2's SourceCommittee is the current authenticated ordered commitment.
Its 286-byte encoding and ID domain are unchanged. Context carries Order, exactly
seven unique byte indices 0..6 into the immutable genesis registry. The hash of
that ordered registry must equal the authenticated anchor's SourceCommittee and
current KeyHeader.CommitteeHash. Every key block transition computes Add(nil,
PRFLeaderIndex, "") on that order and checks every resulting body identity and
committee hash. No caller-supplied next order is accepted.

RLP v4 is `[4, Base, Headers, AccountProof, CountProof, Entries, KeyHeader,
BoundaryIDs, Order, PreviousKeyHeader, PreviousOrder]`. Order and PreviousOrder
are byte strings. A pending boundary additionally carries the previous key-header
preimage (<=512 bytes) and its seven-index order. The current header.ParentHash
must equal that previous header's hash. A boundary QC's exact semantic ID, key
hash, PRF leader and BLS signatures are checked with that previous order. The
previous context is absent once ActivationEnd is cleared. Current-key QCs use the
current order and cannot impersonate the old-key boundary. v3 keeps its existing
fixed-order interpretation and bytes; v4 is selected only by a nonempty Order.

No cumulative key history is appended: current header/order plus, only while
pending, one previous header/order and at most eight committed QC IDs. Every
context and derived epoch is call-local; shared Verifier registries and BLS
public keys remain immutable. Ancestor64, descendant8, native64KiB and proof4MiB
limits are unchanged. Clock checks use the already certified CLX carrier and
existing deterministic cadence; verifier execution does not query local time.


## Financial parent integration

FinancialState5 keeps its existing v1-anchor byte/root interpretation. A v2
anchor restored from a DEX parent is checked for codec/domain/custody/epoch1
identity; its key/order need not equal genesis after authenticated renewal.
`Execution.Execute` first binds that entire parent to `ctx.ParentRoot`, then
`VerifyRolling` validates the new CDXA from that base before inbox credit. No
client-supplied decoded state becomes a trust root. The integration fixture
performs two nonzero-PRF renewals, exact-once credit, pending-boundary advancement,
new-parent decoding and fresh-verifier financial replay. Altered parent key,
committee, epoch or custody does not execute under the original parent root.

Focused race PASS: continuous-financial-renewal-race.jsonl (1.813s). The initial
fixture selected legacy RLPv3 without a permutation context and correctly failed;
that log is continuous-financial-renewal-initial.jsonl. The correction explicitly
selects RLPv4 with the configured initial identity order, rather than weakening
legacy verification. The live long-run gate remains separate.
