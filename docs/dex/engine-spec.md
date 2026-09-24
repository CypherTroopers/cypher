# BTC/CLX fixture engine v1

2026-09-21 UTC. This specification precedes the financial engine implementation.
This is an isolated devnet contract, not a production product or price feed.
The arithmetic units, FIFO PnL, funding rounding and pool rules are those in
`accounting-spec.md`; the Python arithmetic vectors remain independent inputs.

## Authentication and ordering

One authenticated action per certified DEX block. The FHS proposal order is the
price-time order; no global physical-arrival or MEV guarantee is made. Every
action has a fixed 217-byte big-endian payload, followed by a 65-byte canonical
low-S secp256k1 recoverable signature. The signing digest is SHA256 of
`common-dex/action/v1\0 || payload`. The signer must equal Owner. The payload is:

`version:u16, epochKey:32, kind:u8, owner:20, nonce:u64, orderID:u64,
side:i8, quantity:u64, price:u256, recipient:20, amount:u256,
depositID:u64, feedSequence:u64, fundingRate:i64, validUntil:u64,
target:20, flags:u8`.

All unused fields must be zero. Nonce must equal the signer's previous nonce+1;
failures leave the state and nonce unchanged. EpochKey includes chain/genesis,
DEX identity and historical committee. Price and amount have u128 magnitude
limits. Quantity is positive, lot-aligned and at most 10^12 (10,000 BTC fixture
bound). Limits are 16 accounts, 64 resting orders, 64 FIFO lots per account,
282-byte signed engine action and 1MiB state. The outer financial envelope has
its separately bounded 64KiB limit. The fixture has no public onboarding/session keys.
The immutable deposit fixture binds every deposit to the exact configured CLX
anchor height and hash. Historical deposits from other anchors require a separate
authenticated registry extension; a repeated hash at another height is rejected.

Kinds: 0 authenticated clock/no-op (fixture oracle only); 1 credit of the next
deposit from an immutable CLX-authenticated inbox snapshot; 2 oracle update
(registered fixture oracle, sequence+1, positive tick price, |rate|<=10000ppm,
expiry >= current logical height and <= height+100); 3 limit order; 4 cancel;
5 cancel-and-replace (same owner, fresh price-time position); 6 reserve flat
withdrawal; 7 funding (oracle only, height divisible by10 and once per slot);
8 liquidation against existing orders (oracle fixture coordinator only).
Reward close is a separately authenticated participation operation; raw caller
points cannot authorize reserves.

Flags are IOC=1, post-only=2, reduce-only=4. IOC+post-only is invalid. Market
orders are bounded IOC limits. All price crossing uses price then certified
ingress index, not map iteration. Self match is rejected atomically. Post-only
orders that would cross are rejected. Cancel is allowed during stale prices;
new, reduce, liquidation, funding and withdrawal require a fresh price.
Amend cancels and creates atomically; rejection preserves the original order.

## Execution and risk

The whole action executes against a private copy, so any error leaves roots,
nonces and reserves unchanged. Both incoming and resting orders are checked
again at execution. Fees are taker300/maker100 ppm. Reserve for every open order
is ceil(mark notional*10%) plus worst fixture taker fee; open position IMR is
also reserved. This intentionally conservative fixture does not net opposite
orders. Orders that fail the updated resting margin/reduce check are removed;
the incoming action may continue with other eligible orders. A trade closes
FIFO lots first, books realized PnL and opens only its remainder. Price changes
never silently write unrealized PnL into cash. Sum(cash+unrealized)+all pools
is checked after every successful transition, including asymmetric close/new.

Funding uses all positions at the authenticated mark, payer-ceil / receiver-floor
and an explicit dust pool. Liquidation first cancels the distressed account's
orders, then closes its exposure against compatible resting orders within a
5% mark collar. Sell floors round upward to the next price tick and buy ceilings
round downward, so rounding never widens the collar. It never invents a fill or transfers exposure to an unfunded
insurance account. Only a fully closed negative cash position can consume
insurance; remaining debt sets FROZEN and blocks new financial operations.
An unfilled liquidation remains explicit and cannot authorize withdrawals.

At each10-block boundary with open positions, `PendingFunding` records the
unsettled slot. Until explicit funding is applied, only cancel, authenticated
oracle updates and no-op clock actions can proceed. Positions cannot be closed
or increased, and deposits, withdrawals and rewards cannot bypass the payable
cashflow. A stale feed therefore leaves funding pending; it does not invent a
fresh mark. After authenticated feed recovery, one explicit Funding action uses
the newly authenticated mark/rate at its actual resume height and clears the
pending flag. Missing intervals are not retroactively priced or repeatedly
charged. This resume contract is a devnet fixture, not a production funding
policy. The independent recovery vector fixes slot10 -> fresh mark110 at12 ->
funding at13, rate100ppm, cashflow0.011 CLX per1 BTC, no dust.

Withdrawals require no position and no order, sufficient positive cash, a fixed
native recipient and a fresh feed. A domain-separated claim ID binds signer
and nonce. Cash is debited once and the checkpoint reserves the matching total.
No old-balance escape hatch exists. Accepted claims remain payable while DEX
or oracle stops; new reservations cannot be made.

State is canonical compact JSON of an explicitly versioned structure (decimal
integer strings, addresses lowercase hex, sorted JSON map keys, chronological
orders/lots). Decoder rejects noncanonical JSON, unknown fields, excess bytes,
invalid ranges and inconsistent conservation. Root is SHA256 of
`common-dex/engine-state/v1\0 || bytes`. JSON is internal state, not the signed
action codec. Public action/proof sizes are bounded before signature work.

CLX consumes only the fixed checkpoint, its bounded FHS finality proof, finance
summary and native inbox/claim state. It imports neither this engine nor its
order book. Initial financial correctness still trusts the registered DEX
committee; these signatures are not computation validity proofs.

## Golden-before-code order

`scripts/dex/engine_vectors.py` independently writes the fixed action bytes and
hashes plus a hand-specified trading/funding/withdrawal trace. Go must read these
vectors and recover/verify signatures separately. Existing accounting vectors
also cover insurance exhaustion and asymmetric close/new. Codec agreement does
not by itself prove engine or native integration correctness.
