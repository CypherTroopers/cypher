# Stage C deterministic execution adapter (devnet)

This specification and `dex/testdata/execution.json` fix the generic action
envelope before the consensus application is extended. The financial engine is
a separately supplied dependency. Consensus and CLX settlement never import it.
The original schema 1 counter remains the default when no execution is supplied.

## Execution API and ownership

`Execution` provides `ID() string`, `Schema() uint16`,
`Genesis() (state []byte, root protocol.Hash, err error)`, and
`Execute(parentState []byte, action []byte, context ExecutionContext)
(ExecutionResult, error)`. Only schema 2 is admitted for this new extension.
IDs are 1..64 printable ASCII bytes. They identify a fixed deterministic engine
and financial configuration, not an upgrade authorization.

`ExecutionContext` contains the full protocol Domain, DEX Height, CLXHeight,
CLXHash and ParentRoot. These fields come from the application and its trusted
fixture configuration. The action cannot override them. The engine receives
private copies of action and parent bytes and must be deterministic: no external
fetch, local wall clock, randomness or nondeterministic map iteration may change
execution. Oracle updates and finalized deposits must be authenticated by the
engine's separately specified inputs/fixture registry.

`ExecutionResult` contains State, PostRoot, InboxStart, InboxEnd, InboxRoot,
WithdrawalRoot, WithdrawalTotal, RewardPeriod, RewardRoot, RewardTotal and
FundingRef. The engine owns those financial calculations. The application owns
domain, sequence, previous checkpoint, pre-root, finalized block range, CLX anchor,
data schema and data root. The engine cannot assign those fields. A separate
financial settlement adapter interprets FundingRef according to its specification.

`Config.Actions(height)` supplies a bounded action only to the local leader's
proposal construction. It must return the same fixture action for retries of the
same height; validation and recovery execute the action committed by the proposal
and never call the action source. The application copies returned buffers.

## Canonical schema 2 action and proposal record

An action envelope is exactly:

```text
schema = uint16be(2)
action_length = uint32be(len(action))
action = action_length bytes
```

The action is opaque to consensus and may encode an engine-defined canonical
batch. Action length is 0..65536 bytes; zero bytes are admitted by the envelope,
and the engine determines whether that is a valid no-op. Unknown schema, oversized
length, truncation and trailing bytes are rejected before execution.

`DataRoot = SHA256("common-dex/execution-data/v1" || 0 || envelope)`.
`ComputeExecutionDataRoot(action)` exports this exact calculation. The proposal's
BodyHash is this data root and BodySize is `6 + len(action)`. The complete proposal
Extra is `checkpoint:525 bytes || envelope`; its existing FHS ExtraHash binds the
complete record. No full post-state is transmitted in the voting message: every
validator derives it from its authenticated parent by execution. The existing
128 KiB overall DEX wire limit applies, including aggregate QC overhead. Each
embedded finality proof remains separately bounded at 16 KiB by its verifier.
The larger batch bound accommodates bounded participation closure certificates;
it does not increase finality proof ancestry or committee limits.

Schema 2 genesis parent:

```text
SHA256("common-dex/execution-genesis/v1" || 0 ||
       EpochKey:32 || execution_id_length:uint16be || execution_id || genesis_root:32)
```

The engine ID, schema, genesis state bytes and genesis root are bound into the
local WAL header. A restart with another execution configuration fails closed.
Counter schema 1 keeps its existing hashes, eight-byte action and proposal codec.

## Replay, limits and failure behavior

Each record retains canonical action bytes, resulting state bytes, checkpoint,
proposal ref and any QC. State length is 0..1 MiB, and there are at most 128 records
within the existing 2 MiB total WAL/snapshot bound. Limits compose: the 1 MiB state
maximum is not a promise that 128 such states can be retained. The instance refuses
additional work when its total budget is exhausted. It never prunes safety records
or silently skips state validation to continue.

On initial execution, restart and snapshot import, derive each record from its
exact authenticated parent's recomputed state. Compare both complete state bytes
and every checkpoint field to the recorded result. Do not trust a cached state
blob merely because its hash is present. Invalid state, root, accounting output,
parent, missing data or an engine error prevents voting/publication. The supplied
Execution's correctness remains a committee trust assumption; this is not a
computation validity proof.

Snapshot import retains the existing rule: only a new, empty, unstarted instance
may import peer certified records; it never imports another voter's local votes,
timeout votes, signing key or outbox. Generic execution does not weaken that rule.

Independent Python vectors cover empty, small binary and textual envelopes,
their data hashes and the ID/genesis binding. Unknown schema, altered lengths,
noncanonical tails, oversized actions/state and changed execution IDs require
negative Go tests. Existing counter fixtures and FHS regression tests must pass.

## Participation collector hooks

`Config.BeforeVote` receives an owned copy of the validated proposal's PersistedVote
after proposal execution and local safety checks, before the consensus WAL stores
the vote or the FHS signs it. A collector uses this callback to durably register
the target and close older participation windows. Callback failure prevents the
new vote. A retry of an already durable identical vote need not repeat this hook;
collector recovery must preserve the earlier durable registration.

`Config.RestoreVote` checks an owned copy of the recovered LastVote (or nil) before
the FHS manager is created. Collector integration must reject a nonnil FHS vote
whose corresponding collector registration/cutoff is absent. A new collector WAL
cannot be silently paired with a previously voting FHS WAL. Collector state may
be conservatively ahead if a crash occurred between the two fsync operations.

`Config.OnFinalizedExecution(height, action, state)` receives private copies only
after the corresponding finalized record and proof are durably stored. It never
runs for speculative proposal execution or a merely certified unfinalized record.
At startup (after RestoreVote and replay validation, before manager creation), and
after a successfully persisted snapshot import, it reconciles all finalized schema
2 records in height order. The callback must be idempotent across crashes. Failure
disables further signing; it does not roll back the durable finality record.
Participation Close belongs at this finalization callback. Pure Execute uses only
the nonmutating CheckClose, avoiding irreversible period locks from proposals that
never finalize. The voting hook still enforces authenticated certificate omission.

`Config.ObserveVote` receives independent copies of a locally generated signed
prepare vote and its proposal ref before transport. Delivery retries can repeat
the observation. Receipt issuance must authenticate the signature, enforce the
collector deadline and deduplicate its own durable record. The hook does not
prove CPU execution. A deadline refusal should be recorded by the integration
closure without blocking ordinary consensus transport; a callback error does
block that delivery. The collector package specifies participation and issuance.
