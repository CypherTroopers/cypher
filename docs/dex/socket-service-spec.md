# Optional Common DEX sidecar and socket transport v1 — isolated devnet

This specification precedes implementation. It extends the existing consensus
application; it does not introduce a second FHS protocol. The audited CLX globals
and C BLS implementation require a separate OS process. Ordinary Common adds
`--dex.validator` (default false) and `--dex.config PATH`. Neither miner start/stop
nor RPC admission starts/stops the sidecar. TOML persists the two DEX options;
the separate bounded JSON manifest contains devnet-only registration and paths.
The Common supervisor checks the actual CLX chain ID/genesis against the manifest,
re-executes its own binary's `dex-validator` command, and terminates only the child
it owns when Common shuts down. Child crash is reported without stopping CLX.
No registration flag by itself confers votes. Explicit trusted seven-member
registration, own BLS key, pinned TLS identity and separate reward address are
required. Operational CLX datadirs and keys are never passed to the child.

## Trust, framing and persistence

TLS1.3 uses mutually presented Ed25519 certificates pinned by complete DER SHA256
in the immutable seven-peer registration. CA/DNS discovery and TOFU are absent.
The registry commitment binds protocol.Domain, ordered node IDs/endpoints/BLS
public keys/reward recipients/TLS pins. Connections also carry the domain's
EpochKey and registry commitment, so a valid old certificate cannot join another
epoch/DEX/genesis. TLS checks run outside the serialized actor; BLS/FHS and engine
callbacks run only on that actor. Signed FHS message IDs/public keys must match
the TLS peer, and existing message authentication remains mandatory.

Frame: 4-byte big-endian length (body only), marker ASCII `CDXNET01`:8,
EpochKey:32, registry:32, source:u8, destination:u8, kind:u8, payload:1..131072.
Kinds:1=FHS RLP,2=authenticated application action,3=application extension.
Length is exactly75+payload, bounded before allocation/RLP. Frame ID is
SHA256(`common-dex/socket-frame/v1` || NUL || body). One bounded frame per TLS
connection; ACK is status:u8 (1 accepted,2 rejected) || frameID:32. ACK only follows
the actor callback. Delivery is at least once and can duplicate/reorder across
connections; FHS and signed action nonces must reject replay independently.

A separate owned/locked/fsynced outbox persists each frame before Send succeeds.
It is bounded by item count (at most256) and8MiB raw frame bytes; an item is removed
only after matching ACK. Concurrent sends/ACK commits serialize on a mutex.
Per-peer workers retry disconnected peers with bounded backoff and deadlines;
no goroutine per queued frame. Invalid permanent messages are acknowledged as
rejected and counted, while temporary actor queue saturation retries. Partial
frames, invalid length, wrong TLS identity/domain/epoch/destination and exhausted
peer rate/connection budgets are closed. TLS handshake/IO deadlines are transport
behavior only; no local time affects balances, finality or funding.

Outbound TCP selects the same numeric loopback IP as the local registered listener,
with an ephemeral source port. This fixes interface selection without adding a
public fault-control option or treating an IP as authenticated validator identity;
TLS pins, registered keys and message domains remain mandatory. Existing fixtures
on 127.0.0.1 keep that source. New financial process fixtures allocate node i's
listener and HTTP API on 127.0.0.(i+2), preserving those endpoints in its owned
identity file across restart. Test-only rules inside a fresh network namespace may
then drop peer traffic by these dedicated source IPs while the parent HTTP client
and CLX fixtures remain on 127.0.0.1. No host routing or firewall is modified.
An actual TLS socket test checks the received source address and a separate source
port; this changes neither the frame codec nor its existing independent goldens.
Missing proposal data also retries. A per-peer round-robin over unsettled frames
allows a parent-data response to pass a deferred child; this does not promise FIFO
socket arrival. FHS timeout intervals reset only when the authenticated QC/TC view
advances, preventing a periodic wall-clock tick from prematurely timing out a new
view. The FHS consecutive-view finality rule remains unchanged.

## Actor and ingress boundaries

`service.Open(Config)` restores the application and outbox before Start. A single
actor calls Start/Handle/Advance/Timeout and optional signed-action admission.
Socket handlers only enqueue bounded copied events and await bounded responses.
Actions are authenticated by an explicit application callback; no raw unsigned
map can authorize trading. Action ingestion ACK is distinct from DEX finality and
CLX settlement. Generic application callbacks and the financial engine can be
injected for the real-network integration. The default CLI fixture is money-free
counter unless an authenticated financial adapter is configured explicitly.
Reward close is an optional authenticated action: missing period witnesses must
reject/defer that close without making ordinary market actions wait for rewards.
No automatic signed-only proof fallback or invented oracle/funding action occurs.

## Required tests and limits

Tests use fresh datadirs and loopback-only network namespaces, never host listeners.
They cover mutually pinned real TLS sockets, old epoch/wrong key, partial/huge
frames, disconnect/reconnect, duplicate/out-of-order delivery, queue limits,
outbox recovery, serialized actor callbacks and common/sidecar start/stop/crash.
An isolated TLS benchmark is not a throughput claim. Production peer discovery,
public operator admission, financial CLX synchronization, WAN resource sizing and
independent operators remain separate acceptance items. Existing application
MaxRecords/height bounds are retained and reaching them is an explicit fixture
limit, not silent pruning or continued unsigned execution.

## Executed CLI tests and retained failures

`results/cli-roles.log`: ordinary CLI all eight PoW/RPC/DEX combinations passed in
36.302 seconds. DEX ON starts its own process from normal Common, seven registered
sidecars finalize via real TLS, and miner stop leaves DEX active. RPC-enabled cases
submit an actual signed transaction. These are lifecycle tests: normal-size PoW
nonce exploration remains NOT_RUN because the32GiB dataset/mlock requirement is
unavailable. A dedicated eight-byte correctly tagged but wrong-size dataset makes
the existing loader reject before cache/DAG allocation, then miner is stopped.

The earlier CLI test failure is retained in `results/cli-roles-attempt2.log`.
Unlike the Go API's empty path, CLI DirectoryFlag cleans an empty path to `.`;
this caused four new test-owned partial DAG preparations. Child processes were
stopped by their owned test cleanup. Their exact paths, logical/allocated sizes
and header hashes are in `results/cli-partial-dag-cleanup.json`; only these four
task-created partial files were removed with parent authorization. No operational
datasets were touched. The existing negative-thread idle comment also differs
from `SealCandidate`, which loads the dataset before checking/clamping threads;
negative threads were not used as a resource guard.

The first final socket race run (`results/socket-final.log`) retained a service
failure: all seven reached certified5 but only finalized2 at the fixture height
limit. After correcting timeout scheduling as above, the unchanged MaxHeight5
test reached finalized4 and passed under race in `results/socket-view-timeout.log`
(transport2.023s, service5.313s). This is local functionality evidence, not latency
or throughput qualification.
