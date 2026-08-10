# ADR-0005: Compute measurement and pricing

- Status: Accepted
- Date: 2026-08-10
- Baseline: `CPH-AIIE-0.2`

## Context

Tokens are not a uniform physical-compute unit. GPU model, precision, memory,
bandwidth, workload, latency, and SLA materially change cost and delivered
value. A premature universal scalar would hide these differences and invite
metering disputes.

## Decision

- Raw measurements MUST remain multidimensional and immutable.
- Every measurement and derived Compute Unit MUST name its schema version,
  benchmark suite version, hardware identity, runtime identity, and precision.
- Compute Unit versions are derived views over measurements; historical records
  MUST never be silently re-rated under a newer formula.
- Service quality, region, urgency, and commercial margin belong in the quote,
  not in the physical measurement itself.
- Raw/validated measurement MUST retain GPU type, effective time, VRAM,
  memory-bandwidth and linked latency/SLA context. A workload-class formula MAY
  use a factor only when its calibration justifies it; latency/SLA remain linked
  commercial rating inputs rather than hidden physical-work multipliers.
- Buyer-facing interfaces MUST support transparent procurement-readable
  fiat/stable display where configured, while the signed quote fixes the CPH
  conversion snapshot and expiry used for settlement.
- CU derivation MUST use declared fixed-point/rational arithmetic, rounding and
  overflow rules plus cross-language recomputation vectors.
- Provider self-report alone is insufficient for payment. Receipts require the
  configured combination of agent signature, orchestrator observation, buyer or
  verifier acceptance, and optional hardware attestation.

## Consequences

- `CU-v1` starts with workload classes and benchmark tables rather than a claim
  of universal equivalence.
- Price-oracle failure prevents new quotes and may stop mining decisions, but it
  does not rewrite already accepted leases.
