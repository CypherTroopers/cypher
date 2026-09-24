# Native settlement devnet finance v1 / data schema 2

This specification is fixed before the finance/deposit/count-tree Go implementation.
It is only for explicitly enabled isolated devnet StateDB adapters; there is no
CLX transaction-handler registration, issuance, wrapped token, or production switch.
Authenticated committee checkpoints are not computation validity proofs.

## Canonical submitted objects

All fields are fixed-width big endian, with no padding or alternate encodings.
`Domain` is the existing 114-byte full domain. Every Amount occupies 32 wire
bytes and must fit unsigned 128-bit magnitude; deposits must be positive.

`FinanceSummary` is 456 bytes, in order: Version:u16 (=1), Domain:114,
Custody:20 (nonzero fixed native vault), Sequence:u64 (>0), Previous:32 (previous accepted summary hash; zero initially),
DepositTotal:32, CollectedFees:32, FundingDust:32, InsuranceUsed:32,
WithdrawalTotal:32, RewardFromFees:32, RewardFromSupport:32, RewardPeriod:u64,
FeePeriodFirst:u64, FeePeriodLast:u64, ParticipationRoot:32.
Hash domain is `common-dex/finance/v1`. Checkpoint DataSchema=2 and FundingRef
must equal this hash. The existing 525-byte checkpoint otherwise stays unchanged.
RewardPeriod=0 requires zero reward amounts, zero fee-period bounds and zero
participation root. A closing period has strictly sequential positive period,
contiguous previously unclosed10-checkpoint fee sequence range ending at least4
checkpoints before the closing checkpoint,
and a nonzero participation root. A zero-budget period may close with a root.

`Deposit` is 236 bytes: Version:u16 (=1), Domain:114, Custody:20 (nonzero), ID:u64 (zero-based),
Owner:20 (nonzero native account), Amount:32, CLXHeight:u64, CLXHash:32 (nonzero).
Hash domain is `common-dex/deposit/v1`. It commits the native transaction's
inclusion anchor, not a submitter's declaration of finality. Finality is checked
against the adapter's trusted CLX anchor registry when the deposit is consumed.
The explicit Custody field is checked against the adapter address in both
objects; signed financial checkpoints cannot replay into a second custody
address even if a caller configures the same DEX domain there.
A deposit range is half-open, contiguous, at most128 entries. Its commitment is
DepositInboxRoot: the counted tree of deposit hashes in increasing ID order.
The empty range has zero root and zero total. Consuming derives the total from
StateDB inbox records; the summary's DepositTotal must match that derived sum.

Hash(domain,data) means SHA256(ASCII domain || NUL || data).

## Counted Merkle trees

At most1024 leaves. Empty tree root=zero. Nonempty leaves are already hashes
(e.g. Claim.Hash or Deposit.Hash). Pad to the next power of two with
Hash(`common-dex/merkle-empty/v1`, empty). Parent hashes reuse the existing
`common-dex/merkle/v1` hash of left32||right32. The externally committed root is
Hash(`common-dex/merkle-count/v1`, count:u32 || paddedBinaryRoot:32).
A proof has exactly log2(nextPowerOfTwo(count)) siblings (maximum10), low-index
bit first; require index<count before hashing. A wholly out-of-count sibling
must equal the canonical empty subtree at its level. Claim manifests sort by ID bytes,
reject duplicate IDs, and separate withdrawal/reward trees. Deposit manifests
use increasing contiguous inbox IDs. Membership does not prove summed amounts
or fair allocations; the initial trust in authenticated DEX execution remains.

## Native state transition and source accounting

The adapter stores every bucket, accepted payload/summary, anchor, deposit,
per-checkpoint reserve/paid total and global domain/kind/ID nullifier in StateDB
storage under the explicitly configured devnet custody address. Reopening uses
that storage; it must reject config/registry changes. Epoch.RegistryCommitment
binds Domain+first/end boundaries+ordered64-byte keys+u16-length-prefixed leaders.
The reserved custody account is initialized with nonce1 so EIP-161 empty-account
cleanup cannot erase its storage/history when its native balance reaches zero.
No mutable accounting cache survives outside StateDB, so an outer CLX snapshot
revert also reverts all adapter state. No operation calls the DEX engine or HTTP.

The caller supplies the authenticated CLX transaction sender for Deposit/FundPool;
these library methods are not exposed as an RPC accepting an arbitrary victim
address. Deposit moves native balance using StateDB.SubBalance/AddBalance, then
records an inbox item and increases U. It cannot debit custody itself. FundPool
moves native balance to explicitly separate prepaid S (support) or I (insurance).
An authenticated finalized-anchor snapshot is installed in Config and persisted;
unfinalized or foreign deposit anchors cannot be consumed. This devnet fixture
uses preinstalled anchors and does not implement a production finality oracle.

For accepted summary amounts d,f,z,i,w,rf,rs:

```
U -= d; T += d-f-z+i-w; F += f-rf; S -= rs; I -= i;
Z += z; W += w; R += rf+rs.
```

All subtraction sources must exist, totals must fit u128, and sum(U,T,F,S,I,Z,W,R)
must equal StateDB.GetBalance(custody). d comes from StateDB inbox, w and rf+rs
must equal checkpoint withdrawal/reward totals. A mismatched custody balance
fails closed; unsolicited direct native transfers are not silently booked as fees.
DEX total cash+unrealized PnL (not cash alone) corresponds to T before reserves.

Devnet reward period is10 checkpoints, rho=1/2, support allowance2 CLX, cap1 CLX.
Period p covers fee/participation target checkpoints (p-1)*10+1 through p*10.
A close is allowed only at checkpoint >=p*10+4, after the receipt dispute grace;
it need not occur at the earliest boundary. Only the next unclosed period can
close, and other checkpoints use RewardPeriod=0. Sum exactly10 persisted fee
deltas for the referenced range, excluding subsequent fees. Budget is
min(floor(periodFees/2)+min(S,2 CLX),1 CLX). The authenticated DEX may reserve less
(e.g. no eligible participants); rf+rs cannot exceed budget, rf cannot exceed
floor(periodFees/2), rs cannot exceed min(S,2 CLX). Persist the closed period watermark only on successful close. Prior-period leftover fees are not counted as new fees.
This is a fixture rule, not a production rate/period decision.

Claim requires an accepted historical checkpoint/domain/period, counted inclusion,
unchanged owner/recipient/asset/amount, unused cross-epoch nullifier and remaining
per-checkpoint/global reserve. Any sender may relay it; payment always goes to the
committed recipient. A duplicate valid claim is an idempotent no-op. Reservation
and native transfer are atomic using StateDB snapshots. Recipient=custody is
rejected. Errors/revert never consume a nullifier or change balances.

## Bounds and failure behavior

Max4096 deposits/accepted checkpoints, max64 preinstalled epochs, max4096 anchors,
max128 deposits/checkpoint, max1024 claims/tree. Existing bounded FHS proof checks
run after all local shape/accounting/anchor checks and before state mutation.
Native insolvency, stale/unfinalized anchor, wrong root/summary, bad signature,
wrong epoch, conflicting sequence, capacity and overflow fail with unchanged state.
No old-balance emergency refund; open-position recovery remains separately frozen.

Python `finance_vectors.py` fixes finance/deposit bytes, hashes, empty/single/three-
leaf counted trees and exact paths before Go code. Native StateDB integration
needs separate tests of actual balances, restart/revert, reservations and nullifiers.

## Executed native adapter tests

The independent Python vectors pass. The subsequent Go protocol implementation
matches2 finance encodings/hashes,3 deposit encodings/hashes, and4 counted trees.
The native adapter's10 tests pass under the race detector; raw test events are in
`results/native-settlement-race.jsonl` (2026-09-21 UTC / 2026-09-22 Europe/Berlin).

The native fixture starts with100 CLX each from two sender accounts and25 CLX
from a separate sponsor. Actual StateDB.SubBalance/AddBalance place225 CLX in
custody. After a fee transfer of0.084 CLX,10 CLX withdrawal and1 CLX funded rewards,
native custody holds214 CLX. Buckets are T=189.916,F=0.042,S=19.042,I=5 CLX;
U/Z/W/R=0. These are actual StateDB balances, not only integer-model counters.

Tests also cover externally reverting a StateDB execution snapshot; failed native
recipient overflow without consuming a reserve/nullifier; LevelDB close/reopen
and fresh trie cache with persistent deposits/history/nullifiers; replay and
changed-recipient rejection; falsely high deposit totals; unfinalized deposits;
insufficient fee/insurance/reward sources; funding-dust conservation; counted-root
padding; and a delayed close at checkpoint15 which excludes checkpoint11..14 fees.
Cross-custody summary/deposit commitments are distinguished before proof work;
an adapter whose StateDB initialization was reverted cannot subsequently move funds.

The adapter tests construct genuine threshold-signed2-chain proof fixtures,
but do not run the distributed DEX network or order engine. They do not establish
the full C acceptance path, participation receipt correctness, or a live CLX
transaction-handler integration. The constructor remains explicit Devnet=true,
and no default CLX/RPC/native transaction dispatch enables this adapter.
