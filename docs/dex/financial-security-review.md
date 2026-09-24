# Focused financial implementation review

2026-09-22. Scope: the new isolated `dex/engine`, native `dex/settlement`,
and their participation/consensus integration boundaries. This is an internal
source review with regression tests, not an independent security audit or a
production approval. The committee trust model is unchanged.

## Reproduced defects and corrections

* Liquidation sell-floor tick rounding widened the specified 5% collar. With
  mark 2000 atoms and a resting bid at 1000, the old code sold 50% below mark.
  With mark 1000, its computed zero limit rejected all liquidation. Both cases
  failed before the fix. Sell floors now round upward and buy ceilings downward,
  using a single rational-to-tick division. `TestLiquidationTickCollarNeverRoundsAgainstVictim`
  also checks parent immutability and that an unfilled liquidation spends no insurance.
* The single-anchor engine fixture accepted a lower deposit inclusion height
  with the same configured block hash. It now requires the exact height/hash;
  historical anchors require a separate authenticated registry. The mismatch was
  reproduced by `TestEngineRejectsMismatchedDepositAnchorHeight`.
* `Engine.Apply(nil, ...)` panicked before returning an input error. A nil-state
  guard and `TestApplyRejectsAbsentParent` make this boundary fail closed.

The first two failing-run artifacts are `engine-collar-before.log` and
`engine-anchor-before.log` in `/tmp/common-dex-devnet.0wvjd5`. Corrected focused
results are `engine-collar-after.log` and `engine-security-final.log`.

## Integration findings

* Missing collector WAL must not be attached to an already-voting FHS WAL.
  `Config.RestoreVote` now invokes the collector's recovery check after full FHS
  replay and before manager creation. It receives an owned vote copy. A rejection
  closes the application WAL and returns no signing-capable instance.
* Irreversibly closing a reward period during speculative execution can lock a
  root for a proposal that never finalizes. `OnFinalizedExecution` now reconciles
  external state only after the FHS finalized record is durable. Startup and
  authenticated snapshot import also reconcile finalized records in order.
  Callback failure stops signing without rolling back finality. The callback is
  required to be idempotent. Pure execution retains the nonmutating omission check.
* Recipient and endpoint configuration must be bound in both collector WAL and
  financial genesis. This was reported to the registry/wrapper owners, who added
  an immutable registry commitment rather than inferring it from available receipts.
* Funding slots previously depended solely on the oracle choosing a Funding
  action. An explicit pending-funding state now ensures that skipped
  slots cannot be bypassed by trading or withdrawal. Oracle recovery uses an
  explicitly authenticated resumed mark/rate, without inventing historical feeds.

Tests for recovery hooks, durable-before-callback ordering, deep-copy ownership,
callback failure, startup reconciliation and snapshot reconciliation passed in
`consensus-finality-hook.log`. These tests use real existing FHS managers and
isolated WAL directories; they do not demonstrate production node integration.

## Reviewed invariants and limits

Native consumption derives deposits from StateDB inbox records and checks trusted
finalized anchors, cursor continuity, commitment and total. Native account
operations snapshot StateDB, check all source buckets, and roll back on failure.
Claims bind the historical checkpoint, recipient, owner, asset and amount,
enforce global ID nullifiers and per-checkpoint reserves, and pay only the fixed
recipient. No engine call is needed for those CLX checks. The existing tests also
exercise recipient overflow, reserve exhaustion, reopen and outer state rollback.

Engine actions clone their parent, authenticate canonical signed actions, reserve
fees/margin, recheck resting orders, execute FIFO closes, and check conservation
using cash plus unrealized PnL. Liquidation cannot create counterpart liquidity.
Insurance only covers a fully closed negative-cash account; uncovered debt freezes
new financial operations. These observations do not independently validate a
committee-signed balance allocation or prove data availability.

The targeted `engine-settlement-review-tests.log` passed before the subsequent
custody-domain/funding integration changes. The final combined test run must
validate those later changes separately. No new claim of production security,
performance, operator profitability, or public-network readiness follows here.

The combined final-unit.jsonl run passed all11 packages after these corrections,
including the uncommitted reward proposal retry regression and authenticated
funding recovery against the independent Python vector.
