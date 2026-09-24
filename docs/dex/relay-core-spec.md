# Durable relay core v1 — isolated fixture

This fixes the G2 core codec before implementation. G1 directional component
gates passed; actual long-running relay/network tests remain NOT_RUN here.
Network proof fetching, finality verification and CLI are separate files/tasks.

Four lanes:1 anchor,2 inbox,3 checkpoint,4 claim. A Job is canonical RLP:
`[Version=1,Lane,ID32,Payload,Authorization,Dependencies[],Owner20]`.
Payload is ≤64KiB, Authorization≤4MiB, dependencies≤16 distinct nonzero IDs.
The store is domain-bound. ID is a semantic identity validated by the network
proof backend before signing: checkpoint hash, claim hash, target anchor ID,
or inbox start/end/root, all domain/custody bound. It is not a payer identity.
Same ID/different stored payload is reported as a conflict, never overwritten.
Funding opcodes1–3 are prohibited. Relay native transactions have value0 and
destination equal to the fixed configured custody. Inbox carries only CDXA.

ConfigBinding is canonical RLP `[1,DomainBytes114,Custody20,Payers20[4],
GasLimitsU64[4],GasPrice32,MaxGasCost32]`, hash domain
`common-dex/relay/binding/v1`. Domain bytes use the existing big-endian codec.
Amounts are positive u128 atoms. Inbox payer/gas fields are zero; other lanes
have explicit gas payers and gas limits. Gas is paid exclusively by these keys.
One outstanding signed/prepared nonce per payer; fees never use native custody.

Attempt RLP is `[Nonce,GasLimit,GasPrice32,RawTX,TXHash32,Sends,ACKHash32]`.
Record RLP is `[LocalID,Job,Phase,Attempt,Proof,LastError]`. Proof≤4MiB,
error≤512bytes. RawTX≤65KiB, fixed EIP155 chain ID, exact nonce/to/value0/data/
gas/price/sender checked both after signing and at startup. Signer is sign-only;
it cannot broadcast as part of this contract. No automatic fee replacement or
nonce cancellation exists in v1. Nonce consumed without matching completion
becomes nonce_conflict; the relay does not guess the replacement transaction.

The whole state is canonical RLP `[1,Binding32,NextLocalID,LaneCursor,
LastSequence[4],LastOwner20[4],Records[]]`. Disk envelope is `CDXR || u16(1) ||
u32(payloadLength) || payload || SHA256("common-dex/relay/store/v1" || NUL ||
payload)`. Independent stdlib Python golden vectors fix these encodings.
Unknown versions/trailing bytes/noncanonical RLP, duplicate IDs/local IDs,
invalid references, duplicate outstanding payer nonce and mismatched binding
fail closed. An existing owned directory missing its state is not reinitialized.

The dedicated Linux directory has ownership marker and exclusive flock.
Each mutation writes a bounded new snapshot to a private temporary file,
fsyncs it, renames to state.bin and fsyncs the directory. Initial directory and
parent are synced. A failed persistence operation stops signing/sending for this
instance. Unrelated datadirs, keystores, operational state are never opened.
Completed history pruning uses this same atomic replacement; no append-only WAL
grows indefinitely. An incomplete temporary generation is never used as state.

State steps: queued→prepared→signed→submitted→complete, plus waiting/quarantined/
nonce_conflict. Intent is durable before preparation; complete unsigned template
and nonce are durable before signing; signed bytes are durable before send.
ACK is observation only. Backend Observe returns a package-private authenticated
observation, with job authorization checked, readiness, independently derived
completion, payer nonce/balance, finality/MPT evidence and source anchor. Public
RPC booleans cannot construct that capability. `verified=false` is never usable.
The network implementation must validate against its separately persisted,
revalidated genesis-rooted bounded anchor chain. Root labels alone are not proof.

On every restart, stored complete records first require fresh Observe validation.
Dependencies cannot use an unvalidated stored completion. If another relay
completes a job while our signed nonce remains unconsumed, our reservation stays
live and the identical raw transaction may still be submitted to resolve nonce;
the semantic completion remains a no-op on chain. A prepared but never signed
attempt can be released after independently proven external completion, because
no network effect was permitted before signed bytes became durable.

Fixture bounds:256 active jobs /32MiB, each lane at most208 so the other three
retain16 slots; completed history1024 /8MiB; entire file48MiB; dependencies16.
Proofs/claim bytes and unresolved raw TXs are not evicted to admit more work.
Completed records still referenced by a queued job are not pruned. Exhaustion
returns capacity_wait. These are devnet limits, not production economics.

Each Step processes at most one selected job, with3-second context deadline.
Lane and owner rotation are persisted before contacting the backend, including
failed jobs, so a bad head/provider does not monopolize selection after restart.
One blocked EOA nonce necessarily blocks its other native lanes; separate payer
keys permit independent progress. Retry is bounded250ms–10s; no wall time drives
financial state, finality or account nonce. Workers are independent of Common,
PoW and DEX lifecycle. Close affects only this relay.

Fault-hook names are after_intent, after_prepared, after_signed, before_send,
after_send, after_proof, after_completion. They inject process/storage-boundary
failures in devnet tests; they cannot alter validated payload or financial state.
G2 tests must cover restart at these boundaries, forged/unverified observations,
nonce conflict, one payer blocking, independent payers, duplicate relay completion,
capacity/fairness/history, corruption/ownership and signed bytes before send.

The explicit `ReplaceUnsent(Job)` operation may replace stale evidence/calldata
only while a record is queued/waiting/quarantined and has no nonce reservation,
raw signed TX or send attempt. ID/lane/owner/dependencies must be unchanged. A
normal Enqueue with different payload remains a conflict. Semantic identity and
new evidence are reauthenticated before signing. A prepared/sent attempt is never
rewritten to hide a stale-base failure. The phase `completed_pending_nonce`
retains a signed pending attempt after externally proven semantic completion.

Snapshot temporary generation is now the fixed exclusive0600 `state.next`.
After valid canonical state restore under LOCK, startup verifies at most64 directory
entries and removes at most32 owned single-link regular0600 legacy `relay-state-*.tmp`
or `state.next` files. Files are bounded by48MiB and every candidate is checked
before any removal. Unsafe/counted-out directories fail closed; unrelated names
are retained. New repeated mid-write crashes can leave only one orphan generation.
An existing invalid canonical state prevents cleanup. Independent source WAL and
CLI status use their own corresponding recovery rules, not this store's authority.
