# IAM semantic kernel (WS0.2a)

This package is the deterministic, side-effect-free IAM boundary for the CPH
AI Infrastructure Extension. It accepts canonical foundation projections plus
read-only authoritative snapshots and returns only non-committable pending
plans. It never reads a host clock, writes storage, consumes replay state, or
appends audit records.

## Cryptographic identities

Production v1 accepts only a raw 32-byte Ed25519 public key and a 64-byte
Ed25519 signature. Every other registered or unknown algorithm fails closed.
The content-addressed key identifier is:

```
SHA256(
  "CPH-AIIE-KEY-ID-V1\x00" ||
  uint32BE(algorithm) ||
  uint32BE(len(canonical_public_key)) || canonical_public_key
)
```

Its sole display form is
`cph-key-v1:sha256:<64 lowercase hex characters>`. The subject is deliberately
not part of the hash. Immutable KeyMaterial binds one KeyID to one subject,
principal kind, target EntityRef and enrollment domain; global-ID reservation
and absence CAS prevent material reuse under another subject.

The Ed25519 test key whose 32-byte seed is all `0x01` has this KeyID:

```
cph-key-v1:sha256:9bb63de08cc85e272226905b136de6064045a38c43d16615ef88af1964ad40fb
```

PoP signs `SHA256("CPH-AIIE-KEY-POP-V1\x00" || CCSE(fields))`. In schema order,
the fields are KeyID, subject identity, subject kind, target entity kind,
target principal kind, target entity ID, transfer-evidence digest, enrollment
domain ID, environment, genesis hash, one-use challenge and challenge expiry.
CCSE strings and fixed byte strings include their canonical 32-bit length
prefix; integers are big-endian. Challenge, subject, target, domain and expiry
must exactly equal the authoritative challenge snapshot. The golden PoP digest
in `keyid_test.go` is:

```
b58a5c8ed1375b30e665077708151da397511d4e27f42d4f0a4e5d1a2fee0398
```

## Public operations

`PlanKeyEnrollment` is the only public first-key path. It atomically describes
immutable KeyMaterial creation, the admin-CCSE-authorized first PREACTIVE
KeyLifecycle record, PoP challenge consumption, target/principal/key/record
global IDs, writer fencing, X/Y business idempotency and one audit intent.
Standalone unsigned material registration is intentionally private, and
`PlanKeyLifecycle` rejects an unknown lifecycle.

`PlanIdentity` and `PlanKeyLifecycle` first normalize a canonical v1 payload,
then rebind the complete immutable `ccse.VerifiedRecord` before disclosing an
idempotency result. Receiver purpose, audience, tenant/provider, environment,
chain, genesis, enrollment domain, replay domain, counter kind/value, validity,
sender, key, payload, MessageID, correlation and source causation are exact.
IAM mutations require `CounterExpectedGeneration`; a Profile may narrow but
cannot relax this baseline.

AuditIntent retains the full detached signed source record and its digest.
The logical actor/key are the original IAM authorization sender/key. The
canonical Audit Writer is a different signer. Audit event causation is the
direct triggering authorization MessageID; the source record's own causation
is retained separately as the ancestor chain. Correlation is copied exactly.
Its EventID is exactly `idempotency.JoinedAuditEventID(X)`, not a caller value.

## Closed state rules

Identity creation is PENDING. Core transitions are PENDING to ACTIVE, REVOKED
or EXPIRED; ACTIVE to SUSPENDED, REVOKED, TRANSFERRED or EXPIRED; and SUSPENDED
to ACTIVE, REVOKED, TRANSFERRED or EXPIRED. REVOKED, TRANSFERRED and EXPIRED are
terminal. State version is exact-next, writer row epoch and authorized lease
epoch are separate CAS values, and every immutable binding/generation change
has an explicit path. ACTIVE is inside the identity validity interval;
EXPIRED is at or after `valid_until`; other nonterminal states cannot survive
past it.

Typed graph checks cover Provider, Agent, Host, Device, Miner, Runner, Buyer
and Service. Parent identities must be current ACTIVE snapshots with compatible
validity, provider/ownership generation and host binding. A Miner's Agent and
all Devices must share the exact Host. Snapshot metadata and typed bindings are
re-derived from canonical payload bytes; detached View fields are never trusted
as an alternate projection.

Key lifecycle is PREACTIVE to ACTIVE to RETIRING to EXPIRED, with direct
PREACTIVE/ACTIVE/RETIRING to EXPIRED after `not_after`. Any nonterminal state
may become permanently REVOKED. PREACTIVE future keys may be cancelled before
`not_before`; `revoked_at` must equal the trusted evaluation time and may not
exceed `not_after`. A key lifetime is contained within its subject identity
lifetime, allowing multiple shorter-lived rotations. ACTIVE identity use
requires an ACTIVE, unrevoked, in-window key with the identity message type in
the frozen production registry. Predecessors must have the same subject/kind,
cannot self-reference, cycle, fork, or be reused by two successors.

The resolver pins a registry and deployment enrollment domain. It composes
KeyMaterial, KeyLifecycle, current principal index, ACTIVE Identity and exact
global-ID owners. It returns lifecycle and identity state versions, writer
epochs and canonical snapshot digests so consumers can re-CAS both at commit.

## Pending admission and finalization

Every operation uses two raw, globally unique business-idempotency keys:

- X is the IAM mutation binding (`OperationIAMKeyEnrollment`,
  `OperationIAMIdentity` or `OperationIAMKeyLifecycle`).
- Y is `idempotency.JoinedAuditBinding(X)` and is reserved for the mandatory
  Governance/Audit append. X and Y are different by construction.

`PrecheckJoined` reads the pair from one transactionally consistent snapshot.
Only absent/absent, exact COLLECTING/COLLECTING, or exact
COMPLETED/COMPLETED with the same outcome are reachable. A COLLECTING result
returns `IdempotencyCollectingError`; the coordinator must reload the durable
pending plan and signed evidence, verify its digest and resume it. It must not
rerun semantic planning against state that may have advanced. Mixed, missing,
or mismatched rows fail closed.

Pending admission is a distinct transaction boundary. `AdmissionIntent`
reserves X/Y as COLLECTING and reserves every new global ID directly to its
final semantic owner in the same transaction as the complete pending plan and
source evidence. The mutation CAS then uses exact `AssertExisting` claims.
Reservations survive abort as permanent tombstones; an identifier is never
released or reused. This includes the canonical joined AuditEvent ID, reserved
at admission directly to `OwnerGovernanceAuditEvent`; finalize and abort both
assert that immutable owner. X progress commits the mutation core plus
full-source AuditIntent; Y progress commits the X binding digest. The final
plan digest commits core, admission and both completion claims. Admission also
commits `EvaluatedAt`, `CommitNotBefore` and `CommitNotAfter`; its durable
adapter must use trusted transaction time and reject admission outside that
same half-open window.

WS0.2b must join all of the following in one serializable transaction before a
commit-ready type may exist:

1. trusted DB time inside the plan's half-open commit window;
2. all state, writer-lease, principal, predecessor, challenge, global-ID and
   snapshot-digest CAS preconditions;
3. CCSE replay admission/result;
4. the IAM mutation(s);
5. a canonical Audit-Writer-signed event validated by the Governance/Audit
   planner, including audit-head CAS and AuditIntent/source rebinding;
6. X and Y completion with one identical outcome digest.

MessageID is transport replay identity. Metadata.IdempotencyKey is business
mutation identity; they are not required to be equal. Exact valid MessageID
duplicates return the stored outcome. A later re-sign is not assumed valid:
expected-generation counters and operation semantics may require a dedicated
signed result-read path.

After the deadline, `PlanReconciliation` produces a non-committable EXPIRED or
FAILED reconciliation plan. It completes X/Y to one deterministic failure
outcome, asserts all final-owner tombstones, and requires a new canonical
failure AuditEvent/head CAS. EXPIRED is time-gated at `CommitNotAfter`; FAILED
also remains blocked on external signed failure evidence.

## Ownership transfer boundary

Foundation v1 identity and lifecycle bytes remain frozen and contain only a
transfer evidence digest out of band. Until the separately versioned
OwnershipTransferAuthorization schema, frozen transfer profile and complete
multi-signer acceptance evidence are joined, every public planner rejects a
nonzero transfer digest with `ErrTransferAuthorizationRequired` before creating
an admission/tombstone. Host/Device same-principal staging and Agent
rotated-principal staging remain package-internal graph/CAS fixtures only; they
cannot be obtained through the public API or treated as authority acceptance.
The future verifier must enforce old/new authority rotation, exact entities,
principals, providers, generations, terminal old identity/key-set closure,
next key, validity, policy, signer-pair sets, quorum and separation.

## Adapter rules and v1 limit

View and Profile are injected, read-only and treated as untrusted. Slices are
preflight-bounded before copying, all returned canonical records are decoded
again, and contradictory snapshots fail closed. No adapter may substitute a
host clock, a mutable registry, a namespaced global-ID uniqueness rule, or
string-fragment policy checks.

This package does not silently add fields to the eight frozen foundation-v1
identity projections or KeyLifecycle v1. Semantics that cannot be proven from
those projections plus explicitly typed, signed evidence remain blocked behind
a new versioned schema/workstream boundary.
