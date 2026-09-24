# Native financial execution (isolated devnet, version 2)

This supplements, and does not replace, the existing FIFO lots, cash/PnL,
funding rounding and insurance rules. The original schema-2 financial fixture
and its genesis remain a regression target.

The native TX experiment uses checkpoint data schema 3. Its initial root is
`protocol.NativeGenesisRoot(seed, domain, custody)`. The initial serialized
financial state is prescribed by the configured market/reward registry, has
zero collateral, support and insurance, no deposits, and no CLX anchor. Every
validator checks those exact genesis bytes. The seed and DEX registry are
committed by the CLX genesis configuration; the full domain contains the actual
CLX genesis hash. The genesis sentinel therefore does not require a circular
CLX genesis/DEX state hash calculation. After the first transition the usual
canonical state hash applies.

The native market seed is not an arbitrary label. Before implementation the
version-2 fixture fixes `NativeMarketSeed(oracle)` as SHA256 of
`common-dex/native-market-config/v2 || NUL || oracle20`, rejecting a zero oracle.
All other financial rules are the versioned constants of this fixture; initial
balances and inbox are empty. Native execution checks this seed against the
market's exact oracle, and every reward recipient against the corresponding
genesis-committed DEX committee CoinBase address. Schema 2 retains its original
configuration rules. Independent Python vectors fix this seed derivation.
Native startup also requires the market's explicit native-inbox mode and an
exact reward-registry domain match, so legacy credit fixtures or another DEX's
participation registry cannot be installed behind the native genesis sentinel.

A schema-3 inbox action is `CDXI || canonical RangeEvidence`. It advances one
DEX height and imports the entire bounded contiguous range beginning at the
parent inbox cursor. There is no caller supplied credit amount, owner, committee
or finalized flag. The immutable CLX verifier authenticates the historical
committee, complete finality evidence and account/storage inclusion first.
Trader entries increase the named account cash and total; support/insurance
entries increase only their named pool and total. The checkpoint inbox root
commits every entry, while Finance.DepositTotal counts only trader entries
(CLX support/insurance TXs already fund their separate buckets). This action
does not consume a trading signature nonce. Each transaction-derived source is
consumed exactly once through the contiguous cursor. Credit while frozen or
with funding pending is refused; cancel/oracle/funding rules remain unchanged.
An empty proved range may refresh the anchor without credit. The verified range
retains its chain/genesis/DEX/custody identity even with no entries; the engine
must match that identity before applying it. A zero-value verified range is
invalid and cannot authorize any transition.

The authenticated CLX anchor is part of the serialized DEX state. Actions other
than inbox import retain it; no validator consults its latest local CLX head.
An inbox action may advance but cannot regress that anchor. Before the first
verified import, financial checkpoints cannot be settled. Building proofs and
querying RPC occur outside deterministic execution.

Schema 3 uses the existing bounded execution action envelope; the checkpoint
schema and WAL execution identity additionally bind the execution version.
The CLX adapter accepts only schema 3 through the native TX entry point. It
never imports or runs this engine. Signatures certify committee agreement;
they are not proofs of the validity of the financial calculation.

Reward-close evidence absence or rejection rejects that action, without
closing or discarding the period. Later ordinary market actions remain
possible when the existing price/funding conditions permit them. A missing
participation certificate is not replaced by fewer signatures or a changed
deadline. The collector's local omission check can withhold its vote on a
reward-close proposal; it must not become a mandatory close at every height.
Network scheduling/retry and omission fault results are recorded separately.

Certified data repair imports one bounded record at a time, in parent order.
It verifies the five-signature QC, execution domain, known parent QC, exact
reexecution result, and existing finalized branch before persisting. It then
uses the ordinary certification/finality path. A missing parent remains
unavailable; a peer cannot replace the local LastVote or timeout watermark with
its own. Data messages contain no private keys or voter safety state. At most
eight records may be requested per call, each below128KiB, and retention remains
128 records/2MiB WAL. A large or missing record is explicitly unavailable;
no root-only synchronization is allowed.
