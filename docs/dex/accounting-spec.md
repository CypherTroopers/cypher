# Native CLX / BTC–CLX Accounting Specification v0 (Isolated Devnet Fixture)

This is the design deliverable for section 10A of the instructions. The formulas and Python reference model below do not mean that a CLX node, authentication, FHS, or native custody have been implemented. They define the contract for connecting C after B's prerequisite tests succeed; production products, rates, collateral, and public participation remain undecided. The reference model does not simulate cryptographic signatures or networking and report them as PASS.

## 1. Domains and Accounts

CLX settlement holds native CLX custody, the authenticated deposit inbox, checkpoints, reserves, and claim nullifiers. DEX holds the ledger of rights against custody. It issues neither WCLX nor any other token. DEX credit is not a native wallet balance and cannot be spent twice alongside the wallet. PoW issuance/coinbase and Common RPC reward accounts/recipients remain untouched.

Let `C` be the actual native custody balance, `U` finalized deposits not yet imported by DEX, `A_i` each account's cash, `P_i` FIFO unrealized PnL at the same mark, `F` unreserved net CLX fees, `S` support actually deposited, `I` deposited insurance, `D` the funding-rounding reserve, `W` unpaid withdrawal reserves, and `R` unpaid reward reserves. Check the following at normal integration boundaries.

```
C = U + sum(A_i + P_i) + F + S + I + D + W + R
sum(positionQuantity_i) = 0
sum(realizedPnL_i over history) + sum(P_i) = 0 # Pure PnL, excluding fees/funding, etc.
```

Distinguish cash from equity; do not write unrealized PnL into cash and then add it again. The sum of cash alone can change in a trade that closes one side and opens the other. For example, from Alice long@100 / Bob short@100, if Bob closes at 110 and Carol opens short@110, Bob's cash falls by 10, offsetting Alice's unrealized gain of 10. A conservation equation ignoring unrealized PnL is wrong in this case. Internal DEX transfers move amounts within the right-hand side. `C` changes only on native deposits/claims. Insurance/support are funds deposited by third parties into custody for specific purposes; trader margin does not replenish them. Apply each journal entry atomically after validating inputs; on failure, leave cursors, nullifiers, roots, and reserves unchanged too. Across the asynchronous DEX/CLX connection, separately reconcile unimported inbox amounts and reserves whose checkpoints are not yet accepted; do not pretend both domains update simultaneously.

## 2. Deposits, Withdrawals, and Claims

The Deposit ID is `(CLX genesis, custody ID, sequential inbox index)`. Import only continuous ranges backed by CLX-authenticated finalized blocks and inbox commitments. Reject self-reported amounts, different genesis, unfinalized deposits, and skipped indexes. Re-executing a deposit adds no credit; a different payload with the same ID conflicts. Restore the cursor from the state root/WAL after restart.

For withdrawals, verify account-owner authentication, native asset ID, positive amount, nonce, and fixed recipient; debit cash and reserve it in `W`. The minimum devnet permits withdrawals only from accounts with 0 positions, 0 open orders, and 0 pending funding. Safe partial-margin withdrawal is a later item. A claim leaf includes domain/version, checkpoint sequence, withdrawal ID, owner, recipient, native asset, and amount; it requires a bounded inclusion proof under an accepted checkpoint and an unused nullifier. A claim reduces `W` and `C` equally. Resubmitting the same claim does not pay twice; changing its leaf is rejected. Checkpoint resubmission behaves similarly.

The withdrawal total authenticated by CLX for a checkpoint is the amount **newly** reserved in that checkpoint. Track cumulative reserved/paid amounts separately. Merkle membership alone does not prove that the total is valid. The initial approach retains trust in correct computation by the registered DEX committee. There is no blanket refund based on past balances.

## 3. Test Market and Integer Rules

One linear FIFO market, `BTC/CLX-fixture-v0`. Quote/collateral/settlement are all CLX. Do not label them USD. Consistent with the 10^18 native subdivision in `params/denomination.go`, 1 CLX = `10^18` atoms.

|Quantity|Unit/constraint|
|---|---|
|Quantity `q`|10^-8 BTC units, signed position, order lot `10^5` (= 0.001 BTC)|
|Price `p`|CLX atoms per BTC, tick `10^3`, positive|
|Cash / fee / reserve|CLX atoms, normally nonnegative; explicitly negative cash only for insolvency|
|Rate|Integer ppm with denominator `10^6`; no external floating-point values in consensus|
|Fixture IMR/MMR|100,000 / 50,000 ppm (= 10% / 5%)|
|Fixture taker/maker fee|300 / 100 ppm (= 0.03% / 0.01%), no discounts|
|Fixture funding|Every 10 finalized DEX logical slots. The fixture oracle specifies rate/mark.|
|Fixture reward|`rho=1/2`, period 10 slots, support allowance 2 CLX, cap 1 CLX|

Prices, amounts, and quantities have an unsigned-magnitude storage limit of `2^128 - 1`; intermediate products use big integers, with range checks before final storage. Quantity signs are handled as signed positions separately. Price ticks and quantity lots make `p*q/10^8` exactly divisible. Reject orders that silently truncate amounts below the minimum unit. Round fractional-atom fees up. Do not reallocate fees/insurance/support among one another without authorization.

```
notional(p,q) = p * abs(q) / 10^8             # Integer; a remainder is an error
fee(p,q,r) = ceil(notional(p,q) * r / 10^6)
initialMargin = ceil(markNotional * 100000 / 10^6)
maintenanceMargin = ceil(markNotional * 50000 / 10^6)
equity_i = cash_i + sum(FIFO_lot_q * (mark - entryPrice) / 10^8)
realizedPnL = closed_signed_q * (exitPrice - entryPrice) / 10^8
```

Retain FIFO lots for each fill; opposite-side fills close the oldest lots first. Only the remainder creates a new lot. For each party, add realized PnL from closed lots to cash and conserve value together with the remaining lots' unrealized PnL. When one side opens a new position, that side's realized PnL is 0, so realized cashflows are not always opposite signed across both sides. Avoid creating CLX through rounding an average entry price. Initially, risk is fully pre-funded and isolated to a single market, with no cross-market margin. At execution, recheck IMR for incoming and resting orders using the new mark/current cash/all reservations, including reserved fees. Time in price-time priority means the DEX-authenticated ingress sequence, not physical arrival order worldwide. Reject self-trades within the same beneficial devnet account. Do not claim that cryptography alone detects one beneficial owner using different identities.

This independent Python model covers financial arithmetic. Order signatures, the book, FIFO transitions, and the full margin engine are outside its scope; arithmetic-vector agreement alone does not establish acceptance of those components. See the [acceptance record](acceptance-matrix.md) for the execution scope of subsequent `dex/engine` work and isolated financial integration.

## 4. Funding and Oracle Outages

Mark and rate are authenticated values from the registered devnet feed. Do not reuse fictional fixture values in a production feed. Determine freshness from DEX-authenticated logical slots and feed sequences; do not consult HTTP or the local clock during CLX settlement execution. Fixture rates satisfy `abs(rate) <= 10000 ppm`; each funding operation covers `1..1024` accounts. The target snapshot must have net quantity 0.

```
x_i = positionQuantity_i * mark * rate / (10^8 * 10^6)
cashDelta_i = -ceil(x_i)  if x_i > 0    # payer
cashDelta_i = floor(-x_i) if x_i < 0    # receiver
cashDelta_i = 0           if x_i == 0
fundingDustDelta = -sum(cashDelta_i) >= 0
```

`D` is an explicit rounding reserve; do not divert it to fees/rewards. The one-sided rounding fraction per account is less than 1 atom. Include the difference between payer rounding up and receiver rounding down in conservation. A reversed rate sign makes shorts pay. If a debit causes insufficient margin, move the account into liquidation instead of incorrectly treating it as healthy.

An expired feed means `ORACLE_STALE`. Stop new/increasing/reducing fills, funding, new withdrawal reservations, and finalization of new reward periods. Order cancellation and claims for withdrawals/rewards already accepted by CLX remain possible. Do not reissue old prices as fresh. After a fresh feed returns, resume from the authenticated recovery point without inventing retrospective funding for the outage (keep the domain FROZEN if unsettled cashflows remain). More permissive reduction/withdrawal during stale periods requires a separate design.

## 5. Liquidation, Deficits, and Recovery Limits

If equity is at or below MMR, mark the account LIQUIDATING and cancel its orders. Use counterparty orders within the permitted collar around a fresh price to execute ordinary value-conserving close entries. The minimum fixture adds no liquidation penalty. If there is no counterparty, stop without inventing a fill. Uncollateralized position takeovers by liquidators/insurance, ADL, and automatic socialized losses are unimplemented.

For negative cash `-b` after the position is completely 0, transfer `min(b,I)` from insurance. Display the remaining deficit as negative cash and `uncoveredDebt`, two observations of the same state (do not subtract it twice). Insufficient insurance makes the entire market FROZEN. Stop new orders, funding, and new withdrawal/reward reservations; funds other than previously accepted reserves remain frozen. Do not improvise loss allocations or recovery prices. Do not hide debt by resetting negative cash to zero or treat margin/support/rewards as insurance.

DEX outages/partitions/missing DA also do not justify accepting new checkpoints. An accepted root alone is insufficient: if proof data cannot be retrieved, new claims cannot be constructed and funds freeze. Recovery first requires an authenticated snapshot + bounded replay and data retrieval. Do not exchange open positions for old wallet balances. Public use with real funds is not permitted because safe market dissolution is unimplemented.

## 6. Participation Records and Rewards

The initial registration consists of 7 equally weighted DEX identities authenticated by CLX. A configuration flag is not voting authority. Separate vote keys from reward recipients; a recipient change affects only authenticated configuration for future periods. Do not rewrite old leaves.

Following the actual source's finality rule using consecutive parent/child QCs, include an attestation that re-executed a target proposal in the bounded participation commitment of the child proposal that finalizes that target. Parent and child must have consecutive heights/views and refer to the same semantic ParentQCID. A single QC is not finality. The attestation domain is genesis/DEX/version/epoch/target block/view/state root/validator ID. The point slot is `(epoch, target block, role, validator ID)`, worth 1 point once; timeout re-signing, retransmission, and multiple QCs add no points. Only eligible members of the target epoch score; 0 points earn 0 rewards.

An attestation does not prove that computation actually ran on that CPU. Self-reported CPU usage, order counts, and volume do not earn points. Participation is not limited to the first QC bitmap: eligible members that missed the QC can submit records before the child proposal is signed.

An acknowledgment certificate has signatures from 5/7 collectors. A collector signs an acknowledgment only before its vote for the target finalizing child and records it in the WAL. An honest collector does not vote for a child omitting an acknowledged record. A 5/7 acknowledgment certificate, under f<=2 and quorum intersection with the 5/7 voting threshold, prevents finalization that omits a valid record. Inclusion is not guaranteed when collector delays/refusals prevent obtaining 5 acknowledgments. Expose this availability limit in the API.

A later block's `reward-close` verifies the finalized target/child and acknowledgment records, then seals the period once after a challenge window of at most 4 logical slots. A mismatch between an authenticated acknowledgment certificate and inclusion makes the period DISPUTED/FROZEN, separately from CLX/trading progress. Reject mere after-the-fact signatures, old-epoch signatures, receipts after the deadline, duplicates, and self-reports. Preventing collectors from signing closed history and preserving receipt-before-vote ordering across restarts requires implementation and adversarial tests. This Python model does not implement that authentication; it evaluates only arithmetic with authenticated scores as inputs.

```
feeShare = floor(collectedNetFeesCLX * 1/2)
supportAllowance = min(fundedUnreservedSupport, 2 CLX)
periodBudget = min(feeShare + supportAllowance, 1 CLX)
```

Use feeShare first and reserve any shortfall from support. If feeShare exceeds the cap, use only the cap. Consume each period's fee base once; do not recount earlier leftover fees as new fees each period. Reserve 0 if total points are 0 or the period is disputed. Fees in another asset are not funding until actually exchanged into CLX. A period ending with zero fees/support has budget 0. Wash trading cannot increase the support cap.

Allocate `floor(budget*points_i/totalPoints)` and distribute the remainder 1 atom each in descending fractional-remainder order, breaking ties by ascending canonical validator ID. Input order/QC-signature order has no effect. sum(allocation)=budget. At period sealing, fully reserve funds as `F/S -> R` before creating leaves. Commit the reward leaf's period, validator identity, fixed recipient, asset, amount, and domain; CLX checks a separate reward nullifier and reserved/paid limits. Do not pay from existing PoW/RPC rewards, insurance, or trader margin. Unclaimed rewards must not be reserved again in the next period automatically.

## 7. Golden Vectors and Execution Scope

`dex/testdata/accounting.json` contains manually fixed inputs/outputs. `scripts/dex/reference_model.py --check` independently recalculates them with Python standard-library integers/Fraction. Do not generate expected values from the Go implementation. Cases cover notional, fees, PnL, IM/MM, positive/negative funding and rounding, insurance deficits, reward allocation/funding, end-to-end accounting entries, unrealized PnL when one side closes and the other opens, and rejected numbers. Both Python and `go test ./dex/accounting` read 39 cases.

`dex/accounting` implements pure Go arithmetic functions using `math/big`. Public APIs exchange canonical decimal strings and do not share mutable `big.Int` values externally. Returned maps are newly created per call. Tests cover upper bounds, negative values, concurrent calls, and map ownership. This is not connected to node/runtime/settlement and therefore does not mean phase C is implemented. Future callers must enforce state preconditions such as “after closing the position” for `ResolveInsurance` and “authenticated, unused period” for `Reward`.

The end-to-end journal is an arithmetic trace treating native deposits as custody-credit inputs. Actual-chain native transfers, finalized-deposit proofs, order authentication, FHS, checkpoint verifiers, nullifiers, and cryptographic/DA/distributed faults were not run. Matching numbers do not make R/C/L/W/D integration conditions PASS.

Principal arithmetic rejection categories are `INTEGER` (noncanonical decimal), `RANGE` (sign/128-bit magnitude), `PRICE_TICK`, `QUANTITY_LOT`, `RATE`/`FUNDING_RATE`, `ACCOUNT_BOUND`/`VALIDATOR_BOUND`, `UNBALANCED_POSITION`, `POINT_BOUND`, `RHO`, and `CONSERVATION`. Do not conflate them with higher-level state-machine errors for authentication/epoch/duplicates/expiry/missing DA. Rewards have an arithmetic bound of at most 7 identities and `0..10` points per period for each identity; an in-range number alone is not valid participation evidence.

Arithmetic execution record, 2026-09-21 UTC: Python fixed vectors were 39/39 PASS. Go passed the same 39 vectors and API bounds/ownership/concurrent-call tests. `GOCACHE=/tmp/common-dex-accounting-go-cache go test -race ./dex/accounting` was PASS (1.050s). The first race invocation had a SETUP FAIL because `/root/.cache/go-build` was read-only; a dedicated `/tmp` cache resolved it. This was not a code race failure. C integration had not run at this point.

Subsequent implementation passed a limited end-to-end run with actual StateDB native balances, 7 FHS actors, and authenticated participation records. Scope is recorded in the [financial specification](finance-spec.md), [financial integration log](results/financial-finality-callback.log), and [acceptance record](acceptance-matrix.md). Connection to the CLX transaction handler and finalization of financial CLX blocks remained NOT_RUN.

Open decisions: production rates/periods/rho/caps; public participation/Sybil resistance/collateral/exit obligations; real oracle/price authority and fault model; USD-denominated CLX-collateralized products; insurance capital/deficit resolution; market dissolution/recovery/upgrade authority; computation proofs; DA-retention SLA; collector operation; and economic compensation for participation rejection. Do not promote devnet fixtures to approved production settings.
