# IAM/Governance joined coordinator

This package owns the composition boundary between the non-committable IAM
`JoinedAuditRequest`, the non-committable Governance `JoinedAuditFragment`, and
the outer first-seen signed `AuditEvent` replay transaction.

`NewAuditedFinalHandler` is the only exported IAM/Governance joined final write path.
The internal audited-result builder proves the supplied outer record is the record that opened
the UoW, reads PostgreSQL's cached xid8 and clock, derives the evidence count
from Governance, and one-shot binds the result receipt. It fails closed unless
all three capabilities name the same
pending operation, X/Y snapshots, state/global commitment, event identifier,
commit window, audit sequence, canonical payload, full signed record and
evidence bundle. A successful durable result commits those values in a closed
CCSE projection. Reconciliation wraps IAM's exact failure-result preimage in a
second closed projection which also commits the final PostgreSQL xid8/clock
receipt. That joined digest, rather than the inner failure digest, closes X/Y,
compound members, pending state and the authoritative UoW to one outcome.

The result codec does not apply state by itself. The executable handler must,
inside the `ReplayStore.Execute` context:

1. open the exact outer `VerifiedRecord` with `postgres.OpenCanonicalUOW`;
2. read trusted database time and require it inside the intersected half-open
   IAM/Governance commit window;
3. byte-exactly assert every optimistic pre-sign IAM and Governance read
   capability, including IAM sidecar CAS rows and all source/writer key
   material, lifecycle and identity rows;
4. build and one-shot bind the exact durable result;
5. apply all pre-state assertions, ordered writes and planned-predecessor
   edges, X/Y/member claims, global claims and pending lifecycle changes;
6. retain and assert every typed evidence preimage;
7. append the exact signed AuditEvent and advance its full audit-head CAS;
8. call `AtomicTx.Complete` with the byte-exact result returned here.

No callback may perform an external effect before commit. Any missing semantic
state codec, transaction-time proof, evidence preimage, CAS relation or exact
row count is a hard failure; the coordinator must never reconstruct a private
IAM/Governance digest in the storage layer.

`NewTransactionBoundIAMView` accepts only a trusted IAM state adapter which
declares the same `CanonicalUOW`; it then supplies reconciliation with
PostgreSQL's clock and xid8 from that exact active UoW. It does not make an
arbitrary cache or process-memory `iam.View` transaction-bound, and a process
clock is never substituted.
`DecodeAuditedSuccessResult` and `DecodeAuditedFailureResult` are the closed
duplicate/restore decoders. Neither recreates a write capability.

IAM first-OPEN persistence uses `NewIAMAdmissionHandler`. Its opaque IAM
capability binds the exact signed source record, inert durable envelope,
read-only canonical-state assertions/absences, X/Y and global reservations,
full evidence actions and revision-one pending row. The coordinator adds the
final PostgreSQL xid8/clock receipt and exposes only the inert
`DecodeIAMAdmissionResult` duplicate decoder. Collection continuation uses a
separate predecessor-bound capability and `NewIAMCollectionAdvanceHandler`.
That handler locks and byte-compares the full source pending revision, source
evidence, parent X and joined Y snapshots, then advances only X and stores the
next OPEN revision. Its durable outcome uses the distinct
`DecodeIAMCollectionAdvanceResult` codec and is never represented as another
absent-row admission.

Governance has three closed standalone paths:

- `NewGovernanceApprovalAdmissionHandler` stores one kind-7 approval revision;
- `NewGovernancePolicyFinalHandler` publishes/activates/rolls back/revokes/
  expires a policy or executes a non-legacy terminal Abort;
- `NewGovernanceAuditAppendHandler` appends an audit-only event without
  inventing policy or pending state.

Their result projections use distinct admission, policy-final and audit-only
content types. `DecodeGovernanceResult` is inert and accepts only the reachable
phase/kind/pending shapes. Legacy collections without a canonical pending
predecessor fail closed and require an explicit offline migration.
