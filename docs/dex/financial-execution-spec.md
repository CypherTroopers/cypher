# Financial execution envelope (isolated devnet)

Written before the wrapper implementation. Schema2 action data is either the
282-byte signed engine action or the reward envelope `CDXR` + signed oracle
RewardClose action282 + u32BE close-package length + canonical participation close
package. It is bounded by the generic execution action limit. The oracle signs
the close-package digest by using the otherwise-unused Target field of a new
engine RewardClose kind9: Target is the first20 bytes of SHA256
`common-dex/reward-close-action/v1\0 || close-package`. The full package also
has its own authenticated domain, period, finality witnesses and certificates;
the truncated target provides 160-bit action binding, never validity by itself.
All other unused fields remain zero. The close command increments the oracle
nonce and authenticated block clock only after verification; it cannot by
itself authorize a reward allocation.

The wrapper state is canonical compact JSON of `{Version,Registry,Engine,Finance,Fees,
Withdrawals,Rewards}`. Engine is canonical engine-state bytes; Finance is the
last fixed456-byte summary (absent at genesis), Fees is a bounded list of the
per-block collected fees, and the two claim lists describe only this block's
new reservations. State root is SHA256
`common-dex/financial-state/v1\0 || canonical JSON`. Its configuration includes
the immutable authenticated native inbox fixture, oracle and prefunded pools.

Every action creates one summary, linked to the preceding summary hash. The
DEX FHS owns checkpoint sequence/parent/domain/CLX anchor and commits to the
wrapper root. The wrapper owns only the deterministic execution fields. CLX
settlement verifies the summary hash, native inbox, reserved funding and bounded
FHS proof; it never loads this wrapper or matches orders.

A reward period covers10 blocks and closes after4 blocks of certified grace.
The close package proves every target block and finality of the grace block.
Since a finality child must already exist before proposing close, the earliest
practical linear fixture close is later than the bare logical bound. Each local
collector checks omission against its durable certificates before the close
proposal can receive its vote. Speculative execution uses a non-mutating check;
only the callback after durable FHS finality pins the period root. Startup and
snapshot replay reconcile this callback idempotently. Different points for an
already finalized period are rejected. Receipt collection and
certificate delivery can fail, in which case the period cannot claim an
inclusion guarantee. The oracle cannot turn arbitrary raw points into rewards.

The wrapper recomputes authenticated points, sums only the referenced10 blocks'
fees, applies rho1/2/support allowance2CLX/cap1CLX, and debits fee/support before
creating reward leaves. It never debits insurance or margin for rewards.
Claim leaves are sorted by ID before building the counted canonical tree.
An old period, future close, stale oracle, frozen debt or certificate omission
fails atomically without new monetary reserves.

Native StateDB tests use fixture allocation only. The adapter remains explicitly
enabled and is not registered as a production CLX system transaction handler.
An in-process StateDB integration result must be distinguished from finalized
CLX chain transactions and from the14-process no-funds experiment.

The Registry commitment binds ordered keys/endpoints, epoch boundaries and separate
reward recipients into both financial genesis and collector WAL.
