# Financial Boundary and Authentication Specification Gate Before Stage C

**Progress addendum (2026-09-22 Europe/Berlin):** The following lists gaps identified during the initial audit.
Subsequently, `finance-spec.md` and independent Python golden data were fixed first,
and `dex/protocol/{finance,deposit,claim_count}.go` plus the native StateDB adapter in
`dex/settlement` were implemented. Financial summaries, deposit/count-tree codecs,
purpose-specific buckets, real native transfers, amount derivation from persistent inbox entries,
reserve/nullifier handling, StateDB revert, and LevelDB reload were tested individually
(10 tests, race PASS). To align with reward deadlines, period p covers ten checkpoints,
such as 1..10; close may occur at any checkpoint no earlier than `p*10+4` and refers only to that period's fees.
This resolved the codec/golden prerequisites for implementing the financial adapter on its own.
A limited end-to-end test of seven FHS actors, the order engine, participation receipts,
and real native StateDB then passed. The CLX transaction handler/financial CLX block finality remain unconnected.
Current pass/fail scope is recorded in the [acceptance record](acceptance-matrix.md)
and [financial integration log](results/financial-finality-callback.log).
Do not reuse this document's initial `unimplemented` statements as the current completion status.

Independent review dated 2026-09-21 UTC. This document does not halt devnet work because production choices remain undecided. It identifies connection specifications and tests still needing concrete definition when moving from the current fundless stage B and arithmetic model to stage C using native CLX. This review added no financial code, native transfers, or operational configuration changes.

## Existing Components and Remaining Gaps

|Evidence|What exists|What stage C lacks|
|---|---|---|
|`dex/protocol/checkpoint.go`, `protocol-spec.md`|Canonical 525-byte checkpoint, withdrawal/reward roots and totals, `FundingRef`|Submission codec/golden data authenticating fee deltas from trader backing to funding accounts, insurance/funding-dust transfers, and reward-period funding reservations|
|`dex/checkpoint/proof.go`|Registered epoch, domain, bounded FHS2-chain authentication|Does not independently verify financial accounting or deposits/claims. A QC is not a computational validity proof|
|`dex/checkpoint/accept.go`|Checkpoint/root/epoch linkage, finalized anchor, same-payload retries|`ErrNoFundsMode` rejects all inbox consumption, financial roots, amounts, periods, and FundingRef. Native custody, accounting buckets, nullifiers, and StateDB atomicity are unconnected|
|`dex/accounting`, `accounting-spec.md`|Python/Go arithmetic for 39 fixed vectors, funding rounding, fees/rewards, insurance shortage, equity conservation|No state machines for account authentication, order engine, native deposit proofs, period uniqueness, receipt authentication, or claim execution. Arithmetic-function caller assumptions must be implemented|
|`accounting-spec.md` §6|Design for seven registrants, duplicate-slot exclusion, pre-finality acceptance, 5/7 receipts, dispute period, budget allocation|No canonical receipt/complaint/period-close bytes, signing payloads, authenticated deadlines, or WAL implementation/tests|
|`counter-devnet-spec.md`, `dex/consensus`|Parent-state execution, FHS, WAL/replay for a fundless counter|These actions/schemas do not constitute implemented financial orders, deposits/withdrawals, or participation proofs|

An arbitrary 32-byte hash in `FundingRef` alone cannot establish the funding source's type, amount, period, or relationship to prior reservations for CLX. CLX consensus execution must not query HTTP to learn its meaning. Finite submissions and transition rules verifiable using only authenticated payloads and CLX state are required.

## 1. Required Specification Connecting Fees, Backing, and Rewards

Stage C must reconcile the CLX native custody balance with at least the following purpose-specific buckets:

* Unconsumed finalized deposits `U`, trader backing `T` (corresponding to total DEX cash＋total unrealized PnL)
* Unreserved CLX fees `F`, natively deposited support `S`, natively deposited insurance `I`
* Funding rounding reserve `Z`, unpaid withdrawal reservations `W`, unpaid reward reservations `R`

Let `d` be deposits consumed from the authenticated inbox, `f` the amount transferred to net fees in this checkpoint, `z` the amount transferred to funding dust, `i` the insurance payment covering cash shortfalls, `w` new withdrawal reservations, and `rf/rs` new reward reservations from fees/support. The proposed entries are:

```
U -= d                     T += d - f - z + i - w
F += f - rf                S -= rs
I -= i                     Z += z
W += w                     R += rf + rs
```

sum(bucket) is unchanged. Native custody changes only on actual native deposits/claims. Calculate `d` from the finalized CLX inbox rather than trusting DEX self-reports. Require `w` to equal checkpoint.WithdrawalTotal and `rf+rs` to equal checkpoint.RewardTotal. Check each source balance, existing reservations, and cumulative payments before transfers; preserve all state on failure. The financial validity of `f/z/i` initially retains trust in the DEX committee. Conservation of totals alone cannot prove the absence of invalid transfers between accounts.

**Proposed additional devnet codec**: make `FundingRef` a domain-separated hash of `FinanceSummaryV1`. Include the summary with checkpoint submissions; CLX first checks bounded length, canonical encoding, and hash agreement. Fixed-width BE fields cover version, EpochKey, checkpoint sequence, previous finance-summary hash, deposit-cursor range, `d/f/z/i/w/rf/rs`, reward period, period-fee start/end sequences, and participation-record root. Amounts use the same u256 wire width as existing checkpoints, with a separately enforced devnet u128 arithmetic limit. CLX state tracks one-time use of period fees, carryover of unclaimed reserves, and support exhaustion.

This is a proposed additional specification, not a finalized codec/golden. Adding only a hash is insufficient: first fix golden cases for field order, lengths, empty values, insufficient funds, amount overflow, different summaries at the same sequence, reuse of past periods, and totals after duplicate claims.

## 2. Required Specification for Deposit, Withdrawal, and Reward Claims

The logical leaf fields in `protocol-spec.md` are insufficient to implement a canonical Merkle tree. Fix the following before stage C starts:

1. **Native custody entry point**: define which StateDB/system-transaction/contract-adapter path moves native balances and records the inbox. Specify a fixture custody identifier for new isolated genesis only, explicit devnet activation, sender authentication, chain/genesis agreement, deposit nonce/ID, and the source of the finalized CLX anchor. Deposit receipt and DEX credit are separate states.
2. **Leaf codec**: define order, widths, and empty values for version, full domain or fixed EpochKey, checkpoint sequence, withdraw/reward kind, claim ID, owner, recipient, native asset ID, amount, and reward period/validator identity. Unused reward/withdraw fields are canonical zero. Fix the recipient in the leaf; do not permit sender rewriting.
3. **Merkle codec**: define separate leaf/node hash domains, leaf order, padding, leaf-count commitment, index bounds, and sibling order/length. The candidate uses at most 1024 devnet leaves, sorted by claim ID, forbids duplicates, and commits count in the root. Existing depth 32 is an absolute cap; also check the depth corresponding to the actual count.
4. **Nullifier**: distinguish kind and claim ID by CLX genesis/DEX, with a definition preventing used historical claims from becoming unused after epoch changes. Handle checkpoint-resubmission and claim-resubmission idempotency separately.
5. **Atomicity**: verify inclusion, recipient, funding, totals, and nullifier, then perform native transfer and payment/reservation updates as one CLX state transition. Transfer failure, snapshot revert, and replay must not cause double payment.

A minimal fixture can be limited to flat-account withdrawals; unsafe refunds for open positions are unnecessary. Fund native custody only through fixture allocations in a new isolated genesis, without using existing operational wallets or native CLX. Because these codec/proof/accounting golden cases do not yet exist, claim endpoints and native transfers must not be enabled at this point.

## 3. Required Specification for Authenticating Participation Deadlines

The current `Reward` arithmetic assumes **already authenticated scores**. A caller-supplied map cannot directly serve as participation proof.

A proposed fixed receipt signs domain/epoch, target block height/hash/view/state root, validator identity, role/slot, the incorporating finalizing child's height/view/semantic parent QC, and collector identity. Avoid the circular definition of putting the child-body hash in a receipt and then putting that receipt into the same child body. Design deadline context determinable before proposal construction.

Implement and test the following before reserving period rewards:

* A collector checks the authenticated target and signs receipts only **before** voting for the target child. Fsync receipt-acceptance/child-vote ordering to the WAL so restart cannot enable signing for past periods.
* Bind 5/7 receipts to the child's participation commitment and verify that the target block finalizes under real 2-chain/ancestry rules. Do not derive scores only from the first QC bitmap. Define deadlines unambiguously even with view gaps.
* Fix the period-close range, eligible registry snapshot, single-use slots, dispute deadline, and complaint codec. The four-logical-slot dispute window is the existing devnet proposal; do not close by local wall time.
* Tests must cover delay/inclusion refusal, receipt/vote restart order, end-of-period partitions, old epochs, self-reporting, duplicates, and rejection of post-finality signing. Authenticated contradictions place only the reward period into DISPUTED/FROZEN.
* Receipts do not prove CPU use or actual physical execution. Fix payment destinations to registered recipients with separate keys, allowing recomputation that demonstrates allocations do not depend on QC-signature or submission order.

## 4. Stage C Gate Status and Work That Can Proceed

The financial summary, claim/receipt codecs and golden data, and native-state adapter specifications above are not yet complete; therefore, **the gate for starting stage C financial implementation is not yet satisfied**. The next safe work is to define them concretely as devnet fixtures, create fixed vectors and failure conditions, and verify existing fundless-B results and connection conditions. Native settlement can then be implemented/tested. This does not require additional user permission; these are technical prerequisites within the already authorized A–D scope.

Undecided production fee rates, public Sybil controls, bond amounts, external Oracle contracts, computational proof methods, and public-upgrade authority do not prevent designing an isolated devnet with seven explicit registrants, a synthetic feed, and prefunded pools. Do not embed these as production-approved values.

Future acceptance of C requires an end-to-end run of native deposit→exactly-once credit→authenticated orders/matching→fee→funding/liquidation shortage→authenticated participation/funding reservation→FHS checkpoint→native withdrawal/reward claim. The 39 arithmetic vectors and fundless counter successes cannot substitute for this test. Reconcile native balances, unconsumed inbox, total DEX equity, all purpose-specific buckets, and reserves/nullifiers at every connection point.
