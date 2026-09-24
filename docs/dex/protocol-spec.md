# Common DEX devnet protocol draft v1

This is a development protocol, not a deployment authorization. No public
registry, bond, production fee, issuance, oracle, recovery authority or proving
system has been selected. Signature certification is not a validity proof.

## Execution boundary

Use a separate opt-in DEX service/process. Existing CLX processes, configuration,
coinbase, RPC signers, committee globals and datadirs are never reused for DEX.
The initial implementation is not automatically registered with `eth.New`.
Default OFF therefore has no DEX database, goroutine or subscription. The runtime
and existing FHS library must pass isolation tests before a sidecar can be wired.
CLX settlement imports only codec, authentication and accounting components, never
matching, positions, margin, oracle, funding or liquidation execution.

The reason for this choice is the actual global committee/RPC state and the
non-thread-safe BLS initialization found in the source audit. Process separation
does not itself make an application a valid FHS participant: all safety callbacks,
parent execution, durable votes and authenticated epoch lookup remain required.

## Canonical checkpoint bytes

Fixed-width big-endian encoding; no implicit padding, optional fields, strings,
JSON numbers or alternate encodings. Hashes and monetary integers occupy 32 bytes;
amounts are unsigned native CLX atoms (not another token). Field order:

| Field | Bytes | Meaning |
|---|---:|---|
| version, proofMode | 2, 1 | 1, 1 (committee signatures); all other values rejected |
| chainID, genesis, dexID | 8, 32, 32 | CLX chain ID, CLX genesis hash, unique DEX domain |
| epoch, committee | 8, 32 | CLX-authorized epoch and ordered committee commitment |
| sequence, previous | 8, 32 | consecutive accepted checkpoint ID and previous payload hash |
| preRoot, postRoot | 32, 32 | connected DEX state roots; no L1 reexecution claim |
| firstBlock, lastBlock | 8, 8 | contiguous finalized DEX range, inclusive |
| clxHeight, clxHash | 8, 32 | authenticated finalized CLX anchor, never local clock |
| inboxStart, inboxEnd, inboxRoot | 8, 8, 32 | half-open deposit range [start,end), exact commitment |
| withdrawalRoot, withdrawalTotal | 32, 32 | this checkpoint's newly reserved withdrawal set/amount |
| rewardPeriod, rewardRoot, rewardTotal, fundingRef | 8, 32, 32, 32 | newly reserved rewards and authenticated source reference |
| dataRoot, dataSchema | 32, 2 | exact replay data commitment; schema 1 counter or 2 bounded execution |

Payload length is 525 bytes. Hash = SHA-256 of ASCII
`common-dex/checkpoint/v1` followed by byte 0 then these bytes. Domain strings
never contain zero. This SHA-256 codec is separate from the existing FHS
BLAKE3/RLP signature codec; the FHS proposal commits this checkpoint hash.
The independent Python generator fixes bytes and hashes before Go codec code.

`EpochKey = SHA256("common-dex/epoch/v1" || 0 || version:u16 || chainID:u64 ||
genesis:32 || dexID:32 || epoch:u64 || committee:32)` maps full domain into the
existing FHS `KeyHash`. Registry lookup must match full domain as well. A new
committee cannot authorize its own activation. Registry entries are immutable
snapshots with inclusive first/exclusive last checkpoint sequence boundaries;
historical proof lookup uses that sequence, not today's membership. Catch-up is
one consecutive checkpoint at a time, never an unbounded loop in CLX execution.

## Certification and bounded admission

Reuse existing FHS v3 vote/timeout/QC and proposal-ref v5 only through an explicit
metadata adapter (see consensus audit). Seven registered equal-weight validators,
threshold five. A target QC alone is never finality. Target QC plus an authenticated
direct child with exact parent block and semantic QC ID, height +1, increasing
view, and terminal view +1 is the minimal proof. Longer ancestry may precede the
terminal consecutive pair. At most eight descendant QCs, at most 16 KiB total
encoded proof, at most 2 KiB per proposal ref, at most 128 bytes signature, at
most 128 bytes leader ID, exactly one canonical seven-member bitmap byte. Reject
all shapes before cryptography. These are devnet bounds, smaller than L1 limits.

Target metadata must bind the complete payload hash, postRoot, lastBlock,
EpochKey and dataRoot. BodySize is 1..1 MiB; Time equals logical DEX height.
Tx/receipt/CLX RPC reward roots, block type and gas fields are canonical zero.
Descendants must remain in the authorized epoch for this
first version; activation cannot split a proof. Prior epoch's last checkpoint
must finalize before the next epoch activates. Unsupported transitions fail
closed. No new finality rule is introduced by this adapter.

Same payload hash replay is a no-op; a different payload at an accepted sequence
is a conflict. Validate everything on a temporary state before atomic commit.
Sequence, block range, state root and inbox cursor must all connect. L1 uses
only submitted bytes and authenticated L1 state. No HTTP, external DA fetch,
matching/risk calls or wall-clock balance changes are allowed in verification.

Mode 2 is reserved for future computation proofs, currently rejected. A future
proof-required deployment must never fall back to mode 1 on failure.

## Custody and claims boundary

Native CLX moves to custody through the explicit devnet StateDB adapter. A pending
deposit can exist in custody, but only a trusted finalized anchor permits inbox
consumption. A deposit ID binds full domain, custody and monotonic cursor. DEX consumes
only the next contiguous authenticated range and credits each once. A supplied
deposit total is not evidence. CLX derives totals from its own inbox.

Withdrawal leaves bind full domain, checkpoint sequence, kind, unique ID, owner,
recipient, asset and amount. Kind distinguishes withdrawal and reward. Asset 0
means native CLX. The DEX debits/reserves before committing a leaf. Claims require
bounded Merkle inclusion (depth <=32), exact recipient/amount, unused domain/kind
nullifier, and remaining checkpoint reserve. Successful native transfer and
nullifier/accounting update are atomic. Failure changes neither. A root alone
does not prove sum or fairness: signature-only operation trusts the DEX committee.

Separate custody buckets: trader liabilities/withdraw reserves, fee revenue,
insurance, prepaid support, reward reserves. Fees enter rewards only after actual
collection and authorization. No issuance, PoW deductions, insurance diversion,
external-asset valuation or user-margin subsidy. Detailed arithmetic and fixture
values are in accounting-spec.md. `finance-spec.md` fixes the456-byte finance
summary and236-byte custody-bound deposit. Native StateDB integration includes
actual fixture transfers and persistent nullifiers; see README for scoped results.
It is not registered in the CLX transaction handler. The fixture uses a preinstalled
authenticated anchor. Real inclusion needs a pending/seal protocol avoiding a
block hash in its own state root.

## Data and failure behavior

Schema 1 is the stage B no-funds counter: a big-endian uint64 increment action,
its signed checkpoint/ref, certified ancestry and reconstructible pre/post counter
state. Its DataRoot is SHA256(`common-dex/counter-action/v1` + NUL + action bytes).
The generic local data-store content ID is a separate storage hash, not this root.
Schema2 uses the bounded execution-action envelope in `execution-adapter-spec.md`.
The financial fixture carries authenticated orders, oracle updates, a canonical
participation close package and replayable states/leaves. Its fixed authenticated
native inbox is bound into genesis. See `financial-execution-spec.md` and
`finance-spec.md` for this StateDB scenario; it does not implement live inclusion.
A reader returns `DATA_UNAVAILABLE` for absent content
and `DATA_MISMATCH` for bytes failing the commitment, never success from a root.
No voting/activation on an unavailable parent. Joining starts with authenticated
snapshot plus bounded replay and compares its root before becoming eligible.

Full disk/WAL failure stops DEX signing. Queue full returns explicit rejection;
it cannot block CLX, RPC or PoW. DEX/DA stop freezes new settlement progress;
already accepted proven/reserved claims remain claimable. Open positions are not
refunded using old balances. Emergency unwind prices, loss allocation and recovery
authority remain unresolved; unsafe recovery remains disabled.

API timing states are `received`, `dex_finalized`, `clx_settled`, `claim_paid`.
They are different events, not synonyms for an ACK. Public-network latency,
throughput, liquidity, profitable operation and Hyperliquid superiority remain
unmeasured. No comparison experiment is authorized by this A–D prototype run.
