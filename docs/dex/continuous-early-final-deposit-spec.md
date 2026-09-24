# G3 extended10 early final deposit / test specification isolating deposit timing

Name: `extended10-early-final-deposit`. This named input variant was calculated
independently under `/tmp` before adoption and before changing the Go schedule.
It is selected for the next G3 run after trial 8's separate relay-context defect
is fixed. The original extended10 model/golden remain `extended10` with deposits
at logical financial heights 21/41/81; legacy8 is unchanged. Its authentication
and network result remain NOT_RUN until the new complete run finishes.

The previous seven-slot final-deposit prelude allowed only a few bounded source
updates. Settling two intervals of older checkpoints/claims first can lengthen
the source gap without refreshing the DEX anchor, because automatic inbox relay
correctly does not generate endless empty updates. This fixture moves the same
last deposit earlier; it does not change the production relay's behavior, proof
bounds, or economic rules. Trial8 failed earlier on a distinct missing target
key-context bug, so this timing change is not presented as the fix for trial 8.

## Input sequence changes

Retain initial funding of A100/B100/support 20/insurance 5 CLX and three additional A20+B20 deposits.
Move only the final 40 CLX deposit from logical financial-model height 81 to 61. The new sequence is 21/41/61.
Trade order, FIFO positions, cash/PnL, funding/dust, maker/taker fees, and reward formulas are unchanged.
The four trading cycles are 1–20,21–40,61–80,81–100. Heights 41–60 are a zero-position catch-up interval.
Keep reward closes at 18/34/38/54/58/74/78/94/98/108,10 periods,68 recipient entries, and 4 withdrawals.
Pay the withdrawal from old height 14 at arithmetic step 109 without changing historical claim IDs or economic rights.

The intended network schedule confirms actual CLX height at least 257 using a normal TX after flat
catch-up, finalizes the last A20+B20 deposit on real CLX, then waits for CLX settlement of CP58. Cycle 3
then credits it through valid consecutive inbox evidence. This test input retains a new deposit above 257
while reducing the long evidence lag immediately before cycle 4; arithmetic checks do not establish
successful progress. Actual credit height is determined by valid CDXA finality; model height 61 is the
logical boundary where funds become available before the next trade. Between CLX finality and DEX
credit, funds sit in native custody's unconsumed inbox account. This arithmetic golden assumes both
stages succeed together; actual operation separately reconciles intervening U, every receipt, and gas.

## Trial10 normal key-renewal scheduling condition

Trial9's final deposit anchor 262 was version 1; only its later relay source became
version 2. No version 2 DEX inbox-network coverage is claimed for that failed run.
To exercise that boundary, the next fixture waits after the actual 66-block DEX
absence and before the third A20+B20 funding / thirteen-slot flat catch-up.
Both relay processes must report their already independently verified source
anchor as version 2. This is only a scheduling hint: the subsequent CDXA must
still authenticate the actual headers, key context and MPT in DEX consensus.

The existing normal ten-minute CLX key clock is unchanged. To make a new key's
normal block context observable without creating a large source gap, permit
at most seven ordinary signed zero-value transfers, no more often than once
every two minutes (first eligible immediately). Otherwise only read status.
The phase has a fourteen-minute bound and the existing parent 45-minute deadline,
with 30 seconds reserved for cleanup. Missing/old status is never treated as v2.
No test may synthesize a key block, change the protocol clock, or import state.

Seven carrier transactions usually need about fourteen finalized source blocks;
the actual height delta is recorded, not assumed. The larger thirteen-slot flat
catch-up absorbs that bounded extra input before the final cycle's seven slots.
For the trial 9 example the original 82→242 gap was 160; adding fourteen source
blocks would need roughly six 32-header updates, or more if the unchanged byte
bound requires shorter intervals. This is only a sizing estimate, not a
guarantee. If actual view gaps or proof bytes exhaust thirteen slots, fail closed
and retain evidence; never enlarge the proof or action limits.

Trial10 required the flat-catch-up anchor to be version 2 and placed the third
funding after the key wait. It failed its earlier source-slot bound. Trial11
instead funds the third 40 CLX immediately after the greater-than 64-block absence,
then waits for normal key renewal before restarting DEX. Flat state 58 must
authenticate cursor 8; its actual anchor version is recorded and may be 1.
The existing 55/57 non-financial slots may carry genuine CDXA/descendants while
54/56/58 remain fixed (see the G3 scenario's pre-code dependency review).
After flat catch-up, actual CLX 257 and the verified source-v2 scheduling hint
are checked before the last 40 CLX funding. Cycle 3's finalized financial anchor
must also be version 2 with cursor 10. Input amounts, logical 21/41/61 credit
boundaries, orders, periods and every independent arithmetic golden remain
unchanged. Fake-time scheduling tests cover the carrier cap, missing hints,
minimum spacing and the absolute finite deadline.

## Arithmetic and intermediate ledger

`continuous_early_final_deposit_vectors.py` uses an unchanged, SHA-256 recorded
copy of the existing independent `reference_model.py`; it reads no Go output.
The candidate JSON and CSV retain every economic event and every height boundary:
163 rows, 111 boundaries for heights 0–110. Entries include all buckets, cash,
positions, mark, unrealized PnL/equity, inputs, paid amounts, claim counts and fees.
Conservation and nonnegative buckets are checked after every recorded event.

Compared with the preserved extended10 golden, at every boundary 61≤h<81 the
only monetary differences are custody +40, A cash +20, B cash +20 and trader
bucket +40 CLX. Fees, support, insurance, dust, reward/withdrawal reservations,
positions and PnL rules are unchanged. At 81 and every later boundary the ledgers
coincide. The change increases collateral before the same fixed orders; it does
not alter their price, quantity or execution order. General margin acceptance or
matching correctness is not newly established by this schedule arithmetic.

| Final amount (CLX) | Fixed expectation |
|---|---|
| Inputs / withdrawal paid / reward paid / custody | 345 / 40 / 10 / 295 |
| A cash / B cash | 159.796 / 119.868 |
| U / T / F / S | 0 / 279.664 / 0.168 / 10.168 |
| I / Z / W / R | 5 / 0 / 0 / 0 |
| Fees collected / reward fee source / reward support source | 0.336 / 0.168 / 9.832 |
| Claims | 4 withdrawal + 68 reward = 72 |

## Verification and scope

Run from the repository root:

```
python3 scripts/dex/continuous_early_final_deposit_vectors.py --check
```

Both arithmetic checks PASS. `comparison.json` verifies the complete unchanged
final amounts, per-period allocations, intermediate differences and hashes of
six repository inputs before/after. An initial JSON-check mismatch came from
integer trace map keys being loaded as strings; `initial-check-failure.txt`
records it, and the candidate now emits canonical string keys.

Authentication, FHS finality, relay success, real 257+ native deposits, gas/Common
reward/burn, capacity/liveness and old-claim replay are **NOT_RUN before the next real-process execution**.
No proof limit, 64-header interval, 64 KiB calldata limit, 128-record fixture cap,
protocol rule or FROZEN recovery rule changes. The separately named model/golden and per-height comparison preserve the original
input variant; no old expected value is overwritten to hide the changed cashflow sequence.
