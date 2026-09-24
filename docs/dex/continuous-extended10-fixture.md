# G3 extended10 fixture: fixed inputs before scenario implementation

This is a separate devnet input schedule. The original eight-period calculation
and JSON remain unchanged and are also retained as
`scripts/dex/continuous_vectors_legacy8.py` and
`dex/testdata/continuous-legacy8.json`. The new reference is
`scripts/dex/continuous_extended_vectors.py`, with its own
`dex/testdata/continuous-extended10.json`. No trading, funding, fee, reward,
finality, proof-size or checkpoint accounting rule is changed by this fixture.

The actual native settlement blocks plus the planned 65-block DEX outage create
a source gap larger than the previous schedule's catch-up slots. This fixture
adds a flat 20-height DEX interval for bounded source catch-up. It does not raise
the 64-header evidence limit, the native calldata limit or the 128-height DEX
fixture limit. The exact number of catch-up transactions remains constrained by
the encoded evidence size and authenticated source, and is not assumed here.

All height numbers below are DEX heights. Initial native funding is trader
A100, trader B100, support20 and insurance5 CLX. Additional trader funding is A20
and B20 at each of heights21,41,81: total inputs345. Deposits are credited only
after the existing authenticated source proof; the arithmetic reference assumes
that authentication has succeeded. Trade cycles occupy1–20,21–40,61–80,81–100.

| Cycle start | Oracle100 | Open1 BTC at100 | Funding | Oracle110 | Close1 BTC at110 | New A withdrawal10 |
|---|---|---|---|---|---|---|
| 1 | 7 | 9 | 10 | 11 | 13 | 14, deferred |
| 21 | 27 | 29 | 30 | 31 | 33 | 37 |
| 61 | 67 | 69 | 70 | 71 | 73 | 77 |
| 81 | 87 | 89 | 90 | 91 | 93 | 97 |

Opening uses A taker300 ppm and B maker100 ppm. Closing uses A maker100 ppm and
B taker300 ppm. Funding uses mark100 and rate100 ppm each cycle. The41–60
interval is flat: no fill, new position or funding action; its height59 oracle
update is100 and introduces no cashflow. It still carries genuine receipt duties
at45 and55, committed at46 and56, alongside bounded catch-up actions. Duties in
the trading intervals retain their offsets5/15 with commitment6/16. The first
two periods have six equal authenticated participants; the next eight have
seven. Point authentication and closing grace rules are unchanged.

| Reward period | Closing height | Fee interval | Collected CLX fees | Participants |
|---|---|---|---|---|
| 1 | 18 | 1–10 | 0.040 | 6 |
| 2 | 34 | 11–20 | 0.044 | 6 |
| 3 | 38 | 21–30 | 0.040 | 7 |
| 4 | 54 | 31–40 | 0.044 | 7 |
| 5 | 58 | 41–50 | 0 | 7 |
| 6 | 74 | 51–60 | 0 | 7 |
| 7 | 78 | 61–70 | 0.040 | 7 |
| 8 | 94 | 71–80 | 0.044 | 7 |
| 9 | 98 | 81–90 | 0.040 | 7 |
| 10 | 108 | 91–100 | 0.044 | 7 |

Every period uses the unchanged fixture allowance1, cap1 and fee share one-half.
Periods5 and6 have zero fees, but real participation; their budgets are funded
entirely from the pre-funded support pool. There are68 reward claims
(2×6 + 8×7) and4 withdrawal claims, for72 unique claims. The original height14
withdrawal is released at109 using its unchanged historical claim identity and
path. The reference pays other claims immediately after reservation solely to
check accounting; actual native claim heights and gas come from the network
ledger and are not asserted by this arithmetic schedule.

Fixed expected final amounts, in CLX:

| Amount | Expected |
|---|---|
| Inputs / withdrawals / rewards / remaining custody | 345 / 40 / 10 / 295 |
| Trader A / trader B | 159.796 / 119.868 |
| U / T / F / S | 0 / 279.664 / 0.168 / 10.168 |
| I / Z / W / R | 5 / 0 / 0 / 0 |

The independent Python calculation must assert these fixed values, the fee
sequence, zero open positions, every intermediate conservation equation and the
72-claim count before the Go scenario consumes its new JSON. Legacy8 remains
custody297/support12.168/rewards8 and is never silently reinterpreted as this
fixture. Neither reference proves authentication, network synchronization,
availability, consensus liveness or actual native settlement; those require the
separate G3 execution record.
