# ADR-0006: Application protocol before transport migration

- Status: Accepted
- Date: 2026-08-10
- Baseline: `CPH-AIIE-0.2`

## Context

Fixed-mode PoW results currently use a separate KCP-over-UDP path, while Fair
HotStuff has authenticated QUIC infrastructure. The transport migration is
intentionally deferred, but GPU-miner and pool work must not become coupled to
the legacy wire format.

## Decision

- Work-template and result semantics are defined independently of transport.
- Every message MUST contain a protocol version, chain identity, stable message
  ID, expiry, replay domain, and application-level signature.
- A KCP adapter MAY be used only for controlled development or an explicitly
  firewalled pilot.
- KCP MUST run in an external Gateway process. Bind/listener/adapter failure
  MUST NOT fail validator startup or FHS finality, and KCP never shares a public
  listener or resource budget with committee traffic.
- Public or multi-tenant service requires an authenticated, encrypted, bounded
  transport with connection, stream, source, and global work budgets.
- QUIC migration is a release gate before public pool operation, not a blocker
  for local GPU-kernel conformance work.
- Miner and provider identities MUST remain separate from committee BLS keys.
- Public miner QUIC MUST use a separate process, listener, port, ALPN, trust root,
  key set and handshake/stream/memory/verification budget from committee/FHS
  QUIC. Miner streams on the FHS listener are prohibited.

## Consequences

- The later KCP-to-QUIC change does not alter domain messages, accounting, or
  settlement semantics.
- The current KCP endpoint is not treated as a production mining-pool protocol.
