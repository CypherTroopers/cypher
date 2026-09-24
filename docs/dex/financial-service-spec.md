# Native financial sidecar service (isolated devnet)

This document retains component and audit results as recorded at the time. For subsequent final process results, see the [integration record](integration-status.md) and [acceptance matrix](acceptance-matrix.md).

This design precedes the financial CLI factory. The existing counter mode remains
available. `native-finance` remains an explicit devnet mode and requires the actual
CLX genesis commitment to authorize the native settlement configuration. Normal
Common checks its own chain ID/genesis before re-exec; the child checks trusted CLX
genesis/FHS history, DEX epoch 1/ordered members/custody, market oracle-derived seed,
and the genesis-authorized checkpoint bound. JSON assertions are not deposit proof.

The native factory composes the existing deterministic Execution, collector,
authenticated TLS transport, and one service actor in the separate process.
The default Common path never opens these stores or starts this actor. Its JSON
manifest adds `Finance` with Market configuration, authenticated CLX configuration,
and explicitly named devnet receipt heights. Native market genesis is empty;
funding and trader credits require offline-verifiable finalized CLX inbox evidence.
No validator wallet pays a trader or recipient.

Ingress accepts exact signed action bytes or their existing CDXI/CDXR envelopes at
`POST /v1/actions`, without a client-assigned execution height. After bounded codec,
signature/domain or CLX-evidence authentication, a bounded persistent mempool ACKs
admission. The registered TLS network distributes the same bytes. The mempool has
64 pending entries, 1 MiB raw bytes, bounded status history, exact-byte deduplication,
durable fsync before ACK, exclusive ownership and immutable execution identity.
Nonce/margin/funding/local certificate inclusion checks remain parent-state checks.

When the leader requests an action, consensus supplies an owned copy of the actual
certified parent state and the same ExecutionContext used by proposal execution.
Selection tries the bounded admitted candidates in local arrival order. An
economically invalid candidate is rejected with a bounded reason and removed from
the pending queue; selection continues with other candidates. Ingress admission
is not execution success. The current bounded status history deduplicates rejected
bytes too: an identical future-nonce payload cannot be re-admitted to that node
while its rejection is retained. An explicit resubmission operation tied to a new
authenticated parent is not implemented. Clients must submit against the observed
account nonce; tests wait for certification before signing dependent actions.
No candidate can reserve a DEX height or force other users to wait for its margin,
reward evidence or nonce. Each selected transition is re-executed by the existing
consensus validation path before voting. Followers do not trust leader selection.

Selected bytes remain available until finality or until they are obsolete under
a later certified parent. Finality notifications durably update local status and
run the existing reward close callback. Persistent uncertainty stops this DEX
participant; CLX remains independent. No unsigned/automatic oracle heartbeat is
generated. An empty market waits for authenticated work; counter fixture height
limits remain explicit. Arrival order is that observed by the elected leader's
authenticated local ingress, not global first arrival or MEV elimination.

Receipt and repair extensions use the canonical `CDXEXT01` envelope specified in
financial-process-helper-spec.md and its independent Python golden. Registered
receipts require actual prepare votes and collector pre-child-vote WAL deadlines;
the first QC bitmap alone does not determine payment. Collector certificates are
exported from their durable store for `GET /v1/participation?height=N`. Missing
period evidence rejects only the requested close; normal market actions continue.
`GET /v1/checkpoint?height=N` returns finalized checkpoint, proof and retained state
with explicit unavailable responses. Certified-data repair imports no remote
safety watermark and always verifies QC and re-executes against the correct parent.

HTTP is bound to numeric loopback and retains the existing body/connection/time
bounds. Read queries run on the actor. Ingress, DEX finality, CLX settlement and
claim completion remain distinct. The 21-process scenario uses seven Common
parents owning seven sidecars plus seven CLX committee processes; it is still one
host/isolated fixture, not seven independent operators or production performance.

## Local status and idle ingress

`GET /v1/action-status` reports this node's durable mempool observation. `rejected`
is a local selection decision, not a consensus-wide cancellation: another peer
may retain the same signed candidate and find it valid under a different certified
parent. Finality overrides an earlier local rejection. There is no promise that a
rejected signed order can never execute; an authenticated cancellation mechanism
for pending signed actions is not yet implemented. HTTP resubmission of bytes
already rejected locally returns an error. Duplicate finalized bytes return a
truthful `dex_finalized` stage, with CLX settlement still separate.

New durable ingress requests a proposal only through the existing authenticated
view and certified parent. `NotifyIngress` does not change the view, assign a
height, manufacture a timeout or bypass voting. Repeated notifications leave at
most the existing bounded proposal callback queued. Empty ingress and unavailable
proposal data are explicit wait/retry conditions, not a permanent service failure.
Unavailable proposal data is not acknowledged as validated network delivery.

## Executed checks and remaining scope

The native CLI startup/admission smoke passed in 4.302 seconds in an isolated
network namespace (`results/cli-native-finance-smoke-1.log`). One normal Common
parent owned its native financial sidecar; six other authenticated sidecars formed
the test committee. The test checked unsigned HTTP rejection, signed admission,
the missing authenticated native inbox anchor rejection, unavailable checkpoints,
and shutdown of the parent's own child. It did not transfer funds or complete the
native financial trace. The seven-manager ingress regression passed, including
same-view progress after idle ingress without a timeout certificate. These checks
do not by themselves establish the full 21-process financial scenario or its
economic fault results; those must be reported from their separate execution logs.

The later explicit socket opt-in race run passed without skipped tests
(`results/financial-service-socket-race.log`): service 5.247s, financial pool 1.377s,
replication 1.060s, transport 1.985s and process helper 1.087s. It includes seven
actual FHS managers finalizing height 4 over pinned TLS, disconnection/reconnection,
outbox restart, wrong sender/epoch, partial/huge frames, canonical codec bounds,
registration matching and durable admission failure. These package tests remain
separate from native on-chain settlement and the complete financial fault run.
