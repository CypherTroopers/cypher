# Stable native inbox and CLX evidence v2

This ADR and the independent `scripts/dex/inbox_vectors.py` vectors precede the
new implementation. Existing 236-byte `protocol.Deposit` v1 remains unchanged for
regression fixtures. It must not be confused with this transaction-integrated
inbox. No current block hash is included in an entry: that would make the block's
state root depend on its own block hash.

## Stable authenticated entry

`InboxEntry` has this exact 223-byte, big-endian layout:

```
Version:u16=2, ChainID:u64, Genesis:32, DEXID:32, Custody:20,
Sender:20, Nonce:u64, ActionIndex:u32, PayloadHash:32, Index:u64,
Owner:20, Amount:32, Bucket:u8, Asset:u32=0
```

Chain/genesis/DEX/custody are fixed authenticated execution configuration.
Sender and Nonce come from the authenticated CLX transaction, ActionIndex from
the decoded bounded native action, and PayloadHash commits that action's exact
canonical payload, including the native value and resulting owner/bucket. The
native TX path uses the versioned `NativeFundingPayloadHash` specified in
`native-tx-spec.md`, rather than hashing the operation envelope alone. The sender is never a caller-provided substitute for the
transaction sender. Native transaction execution atomically debits its value,
stores the entry and increments its custody-local sequential Index. Bucket 1
means trader deposit, 2 prepaid support, 3 prepaid insurance. Amount is positive
and fits u128; asset zero means native CLX. Owner, Sender, Custody, Genesis,
DEXID and PayloadHash are nonzero. Nonce and Index may be zero. No DEX epoch,
block height or block hash is an entry field.

Hash is SHA256(`common-dex/inbox-entry/v2` || NUL || all 223 bytes).
SourceID is SHA256(`common-dex/inbox-source/v2` || NUL || first158 bytes), binding
the transaction origin/payload independently of its assigned inbox index.
`InboxEntryStorageKey(index)` is SHA256(`common-dex/inbox-entry-slot/v2` || NUL ||
uint64be(index)); its StateDB value is the entry Hash.
`InboxCountStorageKey()` is SHA256(`common-dex/inbox-count-slot/v2` || NUL).
Its value is the count as a zero-padded 32-byte unsigned integer (u64).
Raw entry serving storage is separate from these proof commitment slots.
All three buckets append entries. Trader value enters U; support and insurance
enter their separate native buckets immediately. The DEX consumes the continuous
entry range and accounts for the bucket classes separately.

## Offline CLX finality authentication

`clxevidence.Config` installs the trusted CLX ChainID, genesis Header, actual
FairHotstuffSeed, DEXID, custody, and immutable historical CommitteeEpoch entries
(First inclusive, End exclusive CLX block heights, KeyHash, ordered Members).
These are supplied by authenticated genesis/history configuration, never inferred
from the witness, latest RPC head, DEX votes, or a self-declared committee. An
unknown key/activation boundary fails closed. Dynamic key activation is not
inferred from proof descendants; registry updates require separate authorization.
Config also requires the actual `params.ChainConfig`: verify its complete FHS
genesis commitment equals Genesis.MixDigest, its ChainID/seed match, and the first
registered committee exactly matches the ordered genesis committee. Genesis
keychain hash comes from the trusted fixed-height0 keychain anchor, since it
cannot be recomputed from the regular genesis header alone.

The range witness carries canonical actual CLX block RLP from genesis+1 through
the target. Every block directly links its parent hash and height. Each block's
own QC is reconstructed with
`types.NewHotstuffProposalRefFromUnsignedBlockWithCommitments`, exactly as
`core/block_validator.go` does. A Header alone cannot reconstruct signed BodyHash
and BodySize; the bounded unsigned block body is therefore required.
The original Header.SignInfo, including signature, bitmap, view, leader,
ExtraHash and ParentQCID, is verified even when Header.Hash matches a known hash.
`core/types/block.go:Header.Hash` explicitly excludes SignInfo.

Embedded CLX finality uses the existing core envelope version2 and descendant
SignedState codec. Require an authenticated target QC and 1..8 descendant QCs.
Every edge binds exact parent BlockHash, height+1, increasing view, and semantic
ParentQCID; the terminal edge also requires view+1. A single target QC is not
finality. Every signature is verified against the historical registered committee
for that reference height/KeyHash with the actual FHS public-key-augmented digest
and `CalcThreshold`. The leader uses the actual `cypher-fhs-leader-v2` SHA256 PRF
with the trusted seed, ChainID, view and committee RlpHash (rejection sampling).
This verifier reads no mutable global bftview committee.

The stricter fixture bounds are 64 ancestry blocks, 1MiB per block, 16KiB embedded
finality proof, 8 descendants, 2KiB ref, 128-byte signature/leader, 7 registered
equal members and 5 signatures. These do not change CLX consensus rules; evidence
outside the fixture budget is unavailable rather than silently truncated.

## State inclusion and wire bounds

`RangeEvidence` contains Blocks, AccountProof, CountProof and Entries, each entry
paired with an MPT storage proof. The target's verified Header.Root anchors the
custody account proof. Decode the actual Ethereum account RLP; its StorageRoot
anchors both count and entry-hash slots. Trie lookup keys and proof-node keys use
the repository's Keccak256 secure-trie convention. Ignore unauthenticated RPC
balance/storageHash/value labels. Compare values decoded from proof nodes only.

Require 0..128 entries, beginning at the caller's expected cursor, contiguous
indices, all within the authenticated count (at most4096), with exact configured
domain/custody. Hash each canonical entry and compare to its authenticated slot.
An empty/missing account or entry is a failure. An authenticated missing count
slot means zero; an empty range authenticates an anchor/count without crediting
funds. Its expected cursor must still be <=count. Count may not be fabricated from
the manifest. No accepted result is created until all finality and trie proofs
pass. `VerifiedRange` has private fields and copy-returning accessors.

Range wire envelope is canonical RLP of `[version=1, blocks, accountProof,
countProof, [[entry223bytes, storageProof], ...]]`. Total encoded/offline work is
bounded to4MiB; every MPT path has at most65 nodes, each1KiB. Bound all collections
and byte totals before BLS verification. Native TX ingress adds its smaller64KiB
limit independently. Decode/encode rejects alternate versions and trailing RLP.

When used inside a CLX transaction, the handler additionally requires the proved
header to be an earlier ancestor within its64-block budget and checks
`Context.GetHash(header.Number)==header.Hash`. A caller's CurrentHead is never the
canonicality authority. Offline genesis ancestry plus FHS proof and execution's
historical GetHash comparison are distinct checks.

This first integration fixture intentionally stops at CLX height64. It carries
ancestry from genesis and does not introduce a rolling trusted anchor. A later
height fails closed even for an empty entry range. Stopping does not authorize a
refund or discard open positions; new credit/settlement requiring fresh evidence
remains unavailable. A rolling authenticated anchor/recovery design is deferred.
The64-block ceiling is not a guaranteed usable lifetime: the64KiB native-call
limit may be reached earlier. In particular, ancestral blocks retain earlier
checkpoint calldata, which itself can contain evidence. The implementation
does not hide, truncate, or fetch those nested bytes during execution.

## Tests and limitations

Before a positive credit test, reject a target without descendant finality, an
orphan parent, same-header-hash forged SignInfo, changed genesis/committee,
changed entry/source/bucket/value, wrong custody, bad trie proof, cursor gap,
and excess proof work. Independent vectors fix entry bytes/hash/SourceID, storage
keys and actual leader election. Real finalized CLX transaction tests remain a
separate integration gate; unit-signed fixtures do not establish that gate.

The CLX committee's signature authenticates its executed state. Neither this
inclusion proof nor a DEX committee checkpoint proves the DEX computation. This
work introduces no token wrapper, public deployment, mutable committee global,
production funds, network HTTP dependency or local-time balance updates.

## Recorded integration gate, 2026-09-22

`scripts/dex/inbox_vectors.py --check` passed. The13 specified negative finality/
inbox cases were executed before the positive credit unit fixture; they created
no VerifiedRange. Unit cases additionally cover empty count/ranges, immutable
configuration snapshots, proof/codec bounds, native seed/recipient/domain binding,
unproved and duplicate financial credit, and preservation of the legacy mode.
The final focused race run passed for clxevidence, protocol and rewards
(`clxevidence-financial-race-final.log`). The evidence decoder's5-second fuzz run
passed54,806 executions (`clxevidence-codec-fuzz.log`).

The actual7-process CLX test then used ordinary public RPC, Common admission and
TxQUIC to finalize four incoming native transactions: trader100+100, support20,
insurance5 CLX. Their real finality and account/storage proofs passed the same
verifier and schema3 execution credited225 CLX. The source Common reexecuted the
blocks with ordinary InsertChain. A separate DEX OFF Common process downloaded
the full chain over RLPx/ETH FullSync and reproduced all block bytes, receipt
wire data, roots, gas, native buckets and inbox entries. A second PID reopened
that Common's own temporary datadir and reproduced the same results. Both child
observations had no wallet, mining or CLX committee service, and DEX engine
instance/action/inbox-import counters were0/0/0. The gate passed in40.51 seconds;
this is test duration, not order latency or throughput.

Raw logs for these recorded runs are under
`/tmp/common-dex-integration.hnc63_8r/`; the passing process log is
`clx-native-off-sync-3.log`. Prior runs are retained: the first exposed native
authentication of an eth.New runtime-modified genesis config (subsequently fixed
by authenticating the stored genesis config), and the second exposed the test's
nil-versus-empty receipt JSON comparison (corrected without relaxing block or
receipt content validation). Full native withdrawal/reward and7-process financial
DEX fault tests are separate gates; they are not established by this deposit and
ordinary Common synchronization result.
