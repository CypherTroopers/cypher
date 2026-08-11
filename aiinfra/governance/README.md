# Governance semantic kernel (WS0.2a)

This package is the fail-closed semantic boundary for v1 policy approval and
audit append. It does not write a database, consume a replay counter, publish
an outbox message, or change a registry. It returns detached, deterministic
CAS plans. Only a `MutationPlan` with `CommitReady()==true` may reach the
WS0.2b storage adapter.

## Immutable inputs and trust boundary

Every public signed input is bounded before its first copy. The raw
`ccse.Record` is rebound to every field in `ccse.VerifiedRecord`, its canonical
preimage digest is recomputed, and Ed25519 is checked again against the IAM
snapshot used for authorization. The v1 schema and message type are unchanged.

Read views are authoritative but not assertions that the kernel accepts
blindly:

- `IAMView` must project the IAM resolver's key material, enrollment domain,
  target identity, lifecycle and identity versions/digests. The composition
  adapter adds organization and versioned role policy. All of those fields are
  committed by the authorization fingerprint and commit-time key
  precondition.
- `GovernanceProfileCatalog` is the immutable, versioned profile activation
  timeline. A history record and each retained approval must resolve to the
  exact activation row active at its acceptance/issuance time: profile digest,
  activation version, half-open interval and activation-evidence digest. A
  record cannot select a weaker profile merely by naming its digest.
- `PolicyView` returns a closed history from sequence 1 through the exact head.
  Its acceptance-evidence plan/result and writer-lease digests refer to WORM,
  content-addressed objects verified by the adapter before exposure. Missing
  base history is not supported by v1.
- `PolicyDocumentView` returns bounded content bytes. The kernel recomputes the
  SHA-256 digest and checks the media type for every policy, not only emergency
  policies. v1 pins `application/json` and requires its deterministic compact
  byte representation; adding another media type requires a versioned parser.
- `EvidenceView` is a closed union of content evidence and a full signed CCSE
  record. A signed source is rebound, reauthorized, and retained with its key
  CAS; an unsigned preimage cannot masquerade as signed authorization.
- `ApprovalCollectionView`, `idempotency.JoinedView`, `globalid.View`, and
  `AuditView` must each return one detached authoritative snapshot. The joined
  idempotency pair read is atomic, never two independently composed reads.

## Policy approval collection

`PolicyBundle.Metadata.IdempotencyKey` is the business operation X. CCSE
`MessageID` remains sender-scoped transport/replay identity and is not equated
with X. The first accepted approval atomically reserves:

1. X as a `COLLECTING` governance-policy operation;
2. the derived joined-audit operation Y;
3. the final deterministic `idempotency.JoinedAuditEventID(X)`;
4. the policy bundle and canonical record global identifiers.

Each collected vote retains the complete signed record and the IAM/profile
snapshot that authorized it. Its admission fingerprint commits the signature,
content-derived public key and KeyID, sender/target-identity ownership,
lifecycle and identity state, allowed message types, organization/roles,
authorization policy, enrollment domain, profile-at-issuance and validation
time. The collection progress digest commits the canonical set of these
fingerprints. One sender is one vote; one key cannot represent two senders.
Every non-legacy vote in one collection must name the same exact activation
row. Re-activating the same profile digest under a new version, interval or
evidence object cannot carry votes across the cutover. A legacy vote that did
not retain this row can participate only in a terminal abort, never in a
successful mutation or a new admission.
An exact record retry is read-only. A fresh signature may replace only the same
declared sender/key and payload, with a fresh valid replay record; replacement
never increases quorum. Key rotation changes the canonical approver-key set and
requires a new bundle and idempotency key.

All approval records must sign the identical canonical PolicyBundle payload.
Actual sender/key sets must exactly equal the declared sets. Identities, keys,
and record digests are distinct. IAM ownership, active lifetime, non-revocation,
allowed type, authorization-policy set, organization quorum, and a distinct
bipartite assignment of required roles are rechecked at planning and finalize.
Policy sequence is independent of each sender's CCSE replay counter.

## Closed policy state machine

The registry is a contiguous, unique full history. Each next record has exact
`sequence=head+1` and names the previous canonical PolicyBundle payload digest.
The allowed transitions are:

| Prior state | Next state | Required continuity/time |
| --- | --- | --- |
| empty | `APPROVED_DELAYED` | normal first revision; accepted before effective/expiry |
| empty or non-delayed head | emergency `ACTIVE` | explicit break-glass direct-active exception |
| `APPROVED_DELAYED` | `ACTIVE` | same bundle/version/document/approvers/times; effective <= commit < expiry |
| `APPROVED_DELAYED` or `ACTIVE` | `REVOKED` | same invariants; approved <= commit < expiry |
| `APPROVED_DELAYED` or `ACTIVE` | `EXPIRED` | same invariants; commit >= expiry |
| `ACTIVE` | `ROLLED_BACK` | same invariants; target is an eligible, unexpired, non-emergency historical ACTIVE record |
| active/rolled-back/revoked/expired | new `APPROVED_DELAYED` | new bundle ID and revision |

Normal direct `ACTIVE` is rejected. Emergency policy requires the stronger
dual-control quorum, distinct organizations/roles, canonical JSON scope
derivation, an allowed narrow scope, and
`break_glass_expiry == policy_expiry`. Historical emergency rules are evaluated
under their profile active at acceptance, so later tightening neither blesses
nor invalidates old history. A rollback cannot revive an expired, emergency,
or subsequently terminal target.

Policy predecessor, rollback target and registry head identity use
`SHA256(canonical PolicyBundle payload)`. They never use a signer-specific
CCSE record digest.

## Mandatory audit and reconciliation

`PlanPolicyApproval` returns a non-committable `PendingPolicyPlan` plus an exact
`AuditIntent`. `FinalizePolicyMutation` atomically reloads X/Y, the full
collection, current IAM authorization, policy head/writer lease, global IDs,
document and audit head. It accepts only a signed successful AuditEvent that
matches every intent field and then returns one compound commit-ready plan.
X and Y are completed with the same durable result digest in that transaction.

If a collecting operation can no longer succeed after its earliest signature,
profile-activation cutover, effective, policy, or break-glass deadline,
`ReconcilePolicyOperation` produces
`MutationPolicyAbort`. It never changes policy-registry state. It authenticates
the retained admission evidence under the immutable profile active when each
vote was issued, without applying current quorum/role rules, and requires a
currently authorized Audit Writer to sign the exact `FAILED` or `TIMED_OUT`
event. X and Y complete with the same failure result; reserved global IDs remain
permanent tombstones. A collecting operation is never deleted or reset to
absent.

## IAM joined-audit boundary

The IAM integration accepts only IAM's opaque, planner-verified
`JoinedAuditRequest`; callers cannot supply an expected audit intent, X/Y
snapshot, EventID assertion, evidence set or completion claim. Governance
atomically rereads X/Y, derives Y and the joined EventID again, resolves the
full evidence set before validating the signed AuditEvent, and can return only
an opaque `JoinedAuditFragment` whose `CommitReady()` is always false. The
fragment digest binds the IAM request/pending/state commitments, both exact
snapshots and completion claims, expected outcome, canonical audit intent,
audit/head/global-ID CAS, retained evidence, key fences and intersected commit
window. It exposes no standalone `MutationPlan`.

The bridge remains fail-closed until IAM's capability-bearing request exposes
closed, aggregate-bounded typed evidence fragments for its domain-separated
PoP, transfer and snapshot digests. A bare digest plus caller-selected domain
label is not accepted as evidence. Expired-operation reconciliation likewise
requires historical admission authorization for the original source and
separate current failure/Audit Writer evidence; it never treats an expired
source as currently active.

## Audit invariants

The CCSE envelope sender/key is the technical Audit Writer. The payload actor
is the logical transition actor. If they differ, exactly one retained, fully
verified signed source must bind the payload actor identity/key. Internal
governance transitions use the Audit Writer as actor and retain all approvers
as sources.

The stream has one nonzero deployment anchor, exact sequence continuity, an
immutable head region/epoch/profile and separately authorized current
region/epoch/profile. A higher-epoch regional or profile failover can append
without rewriting the old head. For sequence zero the previous digest is the
deployment anchor. Thereafter `previous_event_digest_sha256` is exactly the
previous `ccse.Record.Digest` (SHA-256 of the canonical CCSE preimage); no
custom signature-inclusive chain digest exists. `AuditEvent.audit_sequence`
equals both CCSE counters. Correlation, causation, metadata policy set,
RecordID/EventID, outcome and event time are bound exactly. The signed evidence
set equals the authoritative source set—no missing or extra digest is allowed.
The applied-policy set is also exact: the active governance profile, Audit
Writer authorization policy and every retained signed source's authorization
policy are all required, with no unbound extra policy.
The `cph-audit-v1:` EventID namespace is reserved for mandatory joined audits:
the kernel re-derives its exact ID from parent X, while standalone audit calls
are rejected if they attempt to use that namespace.

## Commit adapter contract (WS0.2b)

The adapter must recompute `VerifyDigest()` and, using database time, require
`CommitNotBeforeUnixNano <= now < CommitNotAfterUnixNano`. In one serializable
transaction it must CAS all fields carried by the plan:

- the authoritative governance-profile activation row (digest, version,
  half-open interval and activation-evidence digest);
- policy head, immutable-head region/profile/epoch and authorized writer lease;
- audit head, global EventID absence, sequence and previous full-record digest;
- every lifecycle, identity and external authorization fingerprint
  precondition for approvers, sources and Audit Writer;
- X/Y idempotency snapshots and claims, using one identical nonzero durable
  outcome digest for both completions;
- deployment-global identifier claims (identifier string alone is unique);
- CCSE replay state, canonical policy/audit rows, retained evidence, durable
  result, outbox and checkpoint.

`MutationPolicyAbort` must skip the policy-row mutation while applying its
audit/idempotency/global-ID tombstone work. Any CAS loss reloads the atomic X/Y
pair and authoritative evidence; it is never repaired by weakening a check.
Backup/restore must preserve full policy history, signed evidence, admission
fingerprints, profile activation timeline, writer leases, global IDs, X/Y,
audit chain and durable result objects. A missing gap, fork, splice or
unresolvable evidence object fails closed.
