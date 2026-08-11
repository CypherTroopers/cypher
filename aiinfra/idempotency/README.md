# Business idempotency contract

CCSE `MessageID` identifies one signed delivery inside its replay scope.
`RecordMetadata.IdempotencyKey` identifies the logical business mutation. They
are deliberately different: multiple approvers sign the same mutation, and a
transport retry may use the exact original authorization or, only where that
operation's counter rules permit it, a fresh authorization while retaining the
same business key.

The durable table key is the raw 16-byte business key alone. Operation domain
is immutable binding metadata, not a uniqueness namespace. Reusing a key with
a different owner or canonical request digest fails closed.

`Precheck` runs before semantic state lookup:

- absent returns `Proceed`;
- an exact `COLLECTING` row returns `ContinueCollection` with its version and
  progress digest;
- an exact `COMPLETED` row returns `DuplicateCompleted` and the stored outcome
  without re-running a planner against state that has already advanced;
- any binding mismatch is a conflict.

One-shot plans use `ReserveCompletion`. Multi-approval ingestion uses
`ReserveCollection` and `AdvanceCollection`; final policy/audit execution uses
`CompleteCollection`. The final outcome digest is intentionally supplied by
the durable result writer rather than embedded in the claim, avoiding a cycle
between plan and result digests.

Ownership-transfer authorization collection uses the dedicated
`OperationIAMOwnershipTransfer` domain. It must not be folded into key
enrollment or identity append: the transfer's metadata idempotency key names
the complete old/new-authority approval workflow, while its accepted digest is
an immutable dependency of the later staged IAM mutations.

The actual ownership cutover is a second operation. Its binding is obtained
only through `OwnershipTransferCutoverBinding` from the complete accepted
authorization binding and uses `OperationIAMOwnershipTransferCutover`.
Collection success therefore cannot be confused with ownership state having
changed. The cutover planner must atomically apply every old-key closure, old
identity terminal record, new key enrollment, successor identity, replay row,
global-ID assertion and mandatory joined audit; individually committable
cutover steps are forbidden.

Each signed child record keeps its own globally unique business key, but it is
not an independently audited operation during cutover. Such a key is stored as
a `CompoundMemberSnapshot`, never as an ordinary X row with a missing Y.
`NewReserveCompoundMember` binds the exact child request and mutation progress
to the cutover X; `NewCompleteCompoundMember` copies the cutover's final
outcome. `PrecheckCompoundMember` then recovers that outcome for an exact child
retry. Its `CompoundMemberView` must return the member and umbrella X/Y from
one transactionally consistent snapshot; an orphan, mixed state or unequal
outcome fails closed. Storage must use one raw-key unique index across ordinary
and member rows, enforce the parent/member row-kind distinction, and defer
completion until the parent and joined audit are completed with the identical
outcome in the same transaction. A different child binding or parent is a
conflict, not a retry.

Every mandatory joined AuditEvent is a second business operation.
`JoinedAuditBinding` derives its distinct key and immutable reservation binding
from the complete parent mutation Binding. The parent admission transaction
reserves both rows as `COLLECTING`; this closes the interval in which another
valid operation could squat the predictable audit key. The AuditEvent signs the
derived key in its metadata, and its full fields remain constrained by the
parent AuditIntent. `JoinedAuditEventID` derives the single canonical EventID
from that same binding. Admission reserves the EventID directly against its
final audit-event owner, and abort retains the reservation as a tombstone;
joined audit IDs are never transferred from a provisional owner. The finalizer
completes both rows in the same transaction. A standalone audit append instead
uses its own caller-authorized business key and `OperationGovernanceAudit`
binding.

Joined operations use `PrecheckJoined` and an atomic `JoinedView`; two ordinary
lookups are not equivalent. The only valid pair shapes are both absent, both
collecting, or both completed with the same outcome digest. The joined row stays
at version 1 while collecting and retains the parent Binding digest as progress;
completion moves it exactly to version 2. Missing, mixed, mismatched, or
independently completed rows fail closed. Admission durably stores the pending
plan and complete signed source evidence in the same transaction as both
reservations. A restart or CAS loser reloads that pending state, revalidates its
digest and current time/state preconditions, and resumes audit finalization; it
does not attempt to reconstruct authority from an idempotency row alone.

`COLLECTING` is recoverable state, not an indefinite lock.  Every pending plan
records a bounded success deadline and a deterministic failure-closure intent.
If the required signatures, policy window, writer lease, or state
preconditions can no longer succeed, an authorized reconciler appends the
corresponding signed `FAILED`, `REJECTED`, `TIMED_OUT`, or `EXPIRED` audit
outcome and completes both X and Y with the same durable failure-result digest,
without applying the requested domain mutation.  The transaction retains the
failed plan and source evidence, completes replay/result/outbox state, and
leaves any globally reserved identifiers as permanent tombstones.  Deleting or
silently resetting a collecting row to absent is never a recovery operation.

WS0.2b MUST apply each claim in the same serializable transaction as CCSE
replay, global-ID claims, canonical state mutation, signed audit append,
durable result and outbox. A policy approval collector counts each sender
identity at most once and never permits one key ID to represent multiple
senders. An exact signed-record retry returns its stored ingestion outcome. A
new authorization from the same declared sender/key for the same canonical
policy payload replaces that sender's retained evidence under
collection-version CAS; it never adds another quorum vote. The replacement is
valid only when the message type permits a fresh replay counter without changing
the canonical business payload. A key rotation changes the PolicyBundle's exact
approver-key set and therefore requires a new canonical payload and business
idempotency key. The collection progress digest is derived from the bounded
canonical set of complete retained signed authorizations. Final policy planning
consumes that durable collection snapshot, not an arbitrary caller array.

An insert or version-CAS loser reloads with `Precheck` using the exact Binding.
`DuplicateCompleted` returns the stored outcome. `ContinueCollection` reloads
the authoritative evidence set, performs the identity/key uniqueness and
replacement checks above, recomputes the progress digest, and retries against
the returned version. A changed Binding is a terminal conflict; callers MUST
NOT reinterpret it as an absent request.

Reachable completed rows are either a one-shot completion at version 1 with no
progress digest, or a collection completion at version 2 or later retaining a
nonzero progress digest. Other completed shapes fail validation. Backup/restore
and crash evidence remain Gate 0 requirements.

This package does not relax CCSE time or replay checks. An exact duplicate can
recover its outcome only while the signed authorization is otherwise accepted
by the receiver. A message whose counter is semantically fixed (for example an
AuditEvent sequence or an expected-generation mutation) cannot be made fresh by
changing only MessageID. Outcome recovery after authorization expiry therefore
uses a separately authorized result-read operation, keyed by the business key
and original record/plan digest; it never re-enters the mutation planner. That
read schema and its durable adapter are a WS0.2b Gate 0 deliverable.
