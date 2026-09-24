# Native settlement transaction v2 — isolated devnet specification

This specification precedes implementation. It supersedes neither the v1
fixture nor production CLX rules: the new path exists only on a new genesis
whose consensus configuration explicitly contains `dexDevnet`. A local DEX
validator flag never changes validity. DEX OFF nodes execute identical bounded
settlement verification. No order engine is imported by CLX settlement.

## Genesis and execution identity

`params.DEXDevnetConfig` fields, in JSON declaration order: Version:u16=2,
ActivationBlock:u64>=1, DEXID:32 nonzero, GenesisSeed:32 nonzero, Custody:20,
Committee: ordered seven Cnode records, MaxCheckpoints:u64 in1..4096.
Custody is the fixed reserved address `0x0000000000000000000000000000000000de0001`.
Only fixed-seven-member CLX FairHotstuff genesis with rotating leaders supports
this finite experiment; DEX registration independently contains seven members.
Other CLX committee configurations cannot enable funding through this fixture.
The existing
full-config FairHotstuff genesis commitment includes these fields. Absence is
disabled; activation and committee do not come from runtime CLI/RPC settings.
Genesis reserves this otherwise unallocated address with nonce1 and empty code.

`NativeGenesisRoot(seed,domain,custody)` is SHA256 of
`common-dex/native-genesis/v2 || NUL || seed:32 || Domain:114 || custody:20`.
Domain contains the actual CLX genesis hash obtained from trusted execution
chain context. Seed is configured before that hash exists; it is not a hash of
the CLX genesis or future deposits. This breaks the genesis/state-root cycle.
The DEX wrapper interprets this sentinel only for the prescribed empty initial
state; all subsequent states use their ordinary canonical state hashes.

## Canonical transaction call

Use existing signed Ethereum envelopes addressed to Custody; ordinary sender
recovery, nonce, intrinsic/execution gas, fee payment, receipts and revert apply.
The transaction payload is max65536 bytes. Header is ASCII `CDXN`, version:u16=2,
opcode:u8, reserved:u8=0, bodyLength:u32, then exactly bodyLength bytes, all BE.
Unknown operation/version, trailing bytes and malformed shape revert.

|Opcode|Body|Transaction value|
|---|---|---|
|1 trader deposit|empty|positive native CLX, u128|
|2 support funding|empty|positive native CLX, u128|
|3 insurance funding|empty|positive native CLX, u128|
|4 accept checkpoint|Checkpoint:525, FinanceSummary:456, dexProofLength:u32+dexProof, clxEvidenceLength:u32+clxEvidence|zero|
|5 native claim|Claim:239,index:u32,count:u32,depth:u8,siblings:32*depth|zero|

Amounts do not duplicate TX.value in funding calldata. The EVM transfers value
once before the handler; the handler books it, without debiting the sender again.
An invalid call reverts both transfer and storage/logs while the ordinary sender
nonce/gas semantics remain. Fund entry owner is authenticated sender; nonce comes
from the transaction context, actionIndex=0. Funding `payloadHash` uses the
canonical **funding payload**, binding TX.value as well as calldata:

`SHA256("common-dex/native-funding-payload/v2" || NUL || version:u16=2 ||
sender:20 || owner:20 || amount:32 || asset:u32=0 || bucket:u8 || call:12)`.

The preimage after the hash domain is exactly91 bytes, integers big endian.
Amount is a positive u128 represented in32 bytes with zero high16 bytes. Sender
and owner are nonzero; the native handler sets both to the authenticated sender.
Bucket is1/2/3 and must equal the canonical empty-body call's opcode. Asset is
native0. The generic `NativePayloadHash(call)` remains an envelope identifier
and **is not** the funding source payload hash. `InboxEntry.SourceID` consequently
changes if an alternative transaction with the same sender/nonce changes its
amount, owner, asset or funding bucket; it does not rely on nonce uniqueness to
bind those economic fields. Non-native assets are rejected before hashing.
Independent Python vectors for this strengthened funding identity are fixed
before the Go helper and native handler use it.

No endpoint lets a caller substitute a victim address. `eth_call` and estimate
execute the same handler over the usual temporary state and cannot persist credit.

`protocol.InboxEntry` v2 is specified independently in the inbox/finality spec.
It never includes its containing block hash/state root or a DEX epoch. Store its
raw bytes and hash, global next index, and inclusion height. Native proofs use
the protocol-specified canonical count/hash storage keys. All three funding classes
append one entry. Trader funding increases U; support increases S; insurance I.
The DEX consumes every contiguous entry once and applies each bucket explicitly.

## Finality and financial acceptance

CLX evidence is canonical bounded actual signed block ancestry plus account/
storage proofs against the certified anchor root. The verifier uses genesis and
pre-authorized historical CLX committee data, not submitted committee definitions,
current committee globals, HTTP, or `CurrentHead`. In addition, the handler checks
anchorHeight < executionHeight, distance<=64, and execution-context
GetHash(anchorHeight)==anchorHash. The actual finalized ancestor is therefore on
the branch being executed. A sole QC does not establish finality.

The first use of an anchor supplies evidence. Authenticated anchor/count state is
persisted; subsequent checkpoints may reuse it with zero evidence. A new anchor
or a newly authenticated count requires evidence. Entry proofs are matched to the
native StateDB's immutable entries; snapshot count determines what is eligible.
DepositTotal sums only trader entries. InboxRoot commits all entries in index order.
DEX matching/risk/funding/liquidation are never called from this path.

Existing v1 fixed financial summary, bounded DEX committee verification, fee
period budgets, buckets, historical checkpoint/nullifier and native claims remain
the accounting rules. Inbox/config identities have v2 domains; shared bucket/
history slot layouts are authenticated by the distinct v2 config identity at the
new reserved address. Explicit v1 fixture addresses and tests retain behavior.
Every storage read/write and log goes through the EVM StateDB interface, preserving
MVCC/resource recording and snapshot behavior; never unwrap a resource wrapper.

## VM restrictions and surplus

The initial transaction path allows top-level CALL only. Internal CALL,
CALLCODE, DELEGATECALL and STATICCALL to Custody reject; CREATE/CREATE2 cannot
install code there. No synchronous EVM/DEX trading is implied. EIP-7702
authorization also explicitly rejects the reserved custody authority.
Any SELFDESTRUCT or other unsolicited native surplus remains separately tracked
as unallocated surplus, never margin, fee income, support, insurance or rewards.
It cannot freeze normal custody accounting or be claimed by the next depositor.
Missing backing (negative surplus) fails closed.
Surplus uses the full native u256 range independently of u128 financial buckets.

## Gas, events and required tests

Gas is a conservative fixed base plus calldata byte cost per operation; worst-case
proof committee/ancestry/storage bounds must be covered. OOG uses existing EVM
OOG behavior; semantic errors return bounded error data and ErrExecutionReverted.
The fixture schedule is funding250000, claim350000, checkpoint12000000 execution
gas plus40 per calldata byte, in addition to ordinary intrinsic gas. Native
working memory reserves4MiB plus calldata against an enabled VM resource limit.
The64KiB bound keeps worst-case checkpoint execution+intrinsic gas below Osaka's
2^24 per-transaction limit. The offline evidence verifier's4MiB cap does not
increase the native transaction limit.
Successful funding emits one event containing the stable entry bytes; checkpoint
and claim emit their canonical hash/sequence/result. No log or reserve remains
after a failed call. Call/estimate/trace must use the same activation and handler.

The initial funding-call/genesis vectors were generated independently by stdlib
Python before Go codec implementation. Additional checkpoint/claim envelope
vectors compose the previously fixed independent component codecs; their opaque
synthetic evidence tests encoding, not proof acceptance. Integration tests cover signed transaction
replay, wrong sender/value/codec, nonce and gas on revert/OOG, logs/receipts,
StateDB restart, state resource wrappers, simulation, internal calls, reserved
creation, forced surplus, finalized inbox proof and repeated checkpoint/claim.
Executed results and remaining scope are recorded in [native-tx-audit.md](native-tx-audit.md).
