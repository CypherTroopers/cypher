# ADR-0010: Canonical state ownership and signing

- Status: Accepted
- Date: 2026-08-10
- Baseline: `CPH-AIIE-0.2`

## Context

The target spans Go, C++, Solidity, PostgreSQL, an event log and multiple regions.
Ordinary Protobuf serialization is not a cross-language canonical signing form,
and active-active projections cannot safely decide device ownership or money.

## Decision

Every canonical entity MUST have one named writer and monotonically increasing
state/writer generation. Provider Agent owns actual local device/process state;
Lease Service owns desired reservation/lease/allocation state; Marketplace owns
Job/Attempt orchestration; Metering owns Measurement/Receipt; Cypher contracts
own escrow/finalized payment; Financial Ledger and Pool Accounting own their
off-chain ledgers. Event streams, indexes, telemetry and dashboards are
rebuildable projections.

Cross-region failover MUST fence the old writer before a higher writer epoch may
act. Lease/financial state uses serializable updates and durable outbox/inbox.
Financial RPO 0 additionally requires synchronous acknowledgement from a quorum
or journal spanning the declared region-loss domain; a local outbox is
insufficient and loss of that durability fails new financial writes closed.
State machines for Device, Lease, Job, Attempt,
Receipt, Escrow, Dispute, Settlement, Reward and Payout remain orthogonal.

Protobuf MUST be treated as the API representation only. All signed off-chain
operations MUST use the versioned `CCSE-v1` canonical projection in Master
Architecture §10.1, including domain, audience, tenant, chain/genesis/environment,
issue/expiry, sequence and key ID. Maps/floats are prohibited in signed
projections and absence differs from a default value. EVM operations use EIP-712
and commit the CCSE record digest. The reference authorization algorithms are
Ed25519 off chain and EIP-712/secp256k1 on chain; policy-scoped TPM/HSM P-256 is
allowed only with its algorithm ID bound and no downgrade. Go, C++ and
Solidity-compatible positive and
negative golden vectors are a Gate 0 requirement.

Delivery is at-least-once, handlers are idempotent, ledger economic identities
are unique, economic effects are at-most-once and unfinished operations are
eventually reconciled. “Exactly once” MUST NOT describe network delivery.

## Consequences

- A service cannot acquire authority merely by consuming a projection.
- Replay, language-specific encoding, regional split brain and duplicate payment
  have explicit conformance tests.
- Schema and state ownership changes require a superseding ADR and migration
  plan.
