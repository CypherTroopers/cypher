# Deployment-global identifier CAS

This package is the shared identifier contract for CPH AI Infrastructure
Extension semantic planners. It implements the Master Architecture rule that
canonical domain and record identifiers are globally unique.

The durable registry key is the identifier string alone. `OwnerDomain` is
binding metadata and MUST NOT be included in a composite uniqueness key. This
prevents, for example, an IAM identity, policy bundle and audit event from
silently reusing the same identifier under different namespaces.

Claims are immutable plan inputs:

- `ReserveNew` compares absence and creates version 1;
- `AssertExisting` compares the exact owner and version without changing it;
- `TransferExisting` compares the old owner/version and atomically writes the
  new owner at the next version, with a nonzero signed evidence digest.

An operation that can spend time in a pending authorization or audit phase
reserves every identifier at admission against its final semantic owner.  A
later successful finalization uses `AssertExisting`; it does not rewrite a
provisional owner into a final owner.  If the operation is rejected, expires,
or is reconciled after a crash, the reservation remains as an immutable
tombstone.  Burning an identifier is preferable to making an aborted identity,
record, policy bundle, or audit event identifier available for a different
meaning.  Consequently, callers must derive all future record/event IDs before
admission and include the reservations in the pending-plan digest and atomic
transaction.

`TransferExisting` is deliberately restricted to the IAM identity owner
domain.  Key IDs, canonical record IDs, policy bundle IDs, and audit event IDs
never change semantic owners.  A planner must not model pending state by
transferring one of those identifiers between temporary and final owners.

Exact duplicate claims for one owner are canonicalized to one entry. Any
different claim for the same identifier fails closed. Identifiers and owner IDs
are bounded, valid UTF-8, NFC-normalized and free of control characters. The
closed owner-domain catalog is versioned in source; adding a domain requires a
reviewed code change.

One operation carries at most 384 claims and at most 4 MiB of canonical claim
bytes. This covers the v1 ownership-transfer maximum (256 future key-closure
records, 64 retained evidence assertions and the base identity/record/audit
IDs) while keeping planner and transaction memory bounded.

Machine-derived namespaces are closed as well. `cph-key-v1:sha256:` identifiers
require exactly 64 lowercase hexadecimal digest characters and can only be
owned by the exact matching IAM key. `cph-audit-v1:` identifiers require
exactly 32 lowercase hexadecimal key characters and can only be owned by the
exact matching Governance AuditEvent. An identity,
canonical record, or policy operation therefore cannot pre-squat a predictable
joined-audit ID before atomic X/Y admission. Standalone audit planners must
also reject the joined-audit prefix; only a binding derived by
`idempotency.JoinedAuditBinding` may use it.

`View` is read-only. A production adapter MUST lock and execute every claim in
the same serializable transaction as CCSE replay admission, the canonical
domain mutation, immutable audit append, durable result and outbox. It MUST
also compare the plan's canonical claim bytes or enclosing plan digest before
applying anything. The PostgreSQL implementation and backup/restore evidence
belong to WS0.2b and are not supplied by this package.

CCSE envelope `MessageID` remains part of its complete replay-scope identity;
it is not automatically promoted into this canonical entity/record registry.
When a message ID is also a domain record ID, the domain planner must emit an
explicit global claim for it.
