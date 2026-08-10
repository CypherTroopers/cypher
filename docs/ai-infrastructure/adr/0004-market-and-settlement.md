# ADR-0004: Market, execution, and settlement split

- Status: Accepted
- Date: 2026-08-09
- Baseline: `CPH-AIIE-0.2`

## Context

External buyers paying for useful compute are the strategy's intended source of
productive demand. Matching and workload execution are high-volume, mutable,
privacy-sensitive activities; settlement requires durable finality and shared
financial state.

## Decision

- Provider discovery, inventory, quoting, matching, reservation, orchestration,
  artifact transfer, execution logs, and raw measurements are off chain.
- Provider registration commitments, escrow, accepted receipt commitments,
  payout, refund, dispute outcome, and slashing MAY be on chain.
- Models, inputs, outputs, checkpoints, logs, secrets, and personal data MUST NOT
  be stored on chain.
- The first commercial verification modes are buyer acceptance, deterministic
  replay where possible, redundant sampling, and hardware attestation. The
  architecture does not claim trustless verification of arbitrary AI results.
- On-chain contracts MUST be independently audited and have pause, upgrade,
  reconciliation, and bounded-authority controls before public funds are used.

## Consequences

- Compute may continue through a temporary chain disruption only under a signed,
  prefunded lease whose risk limits permit it; settlement is queued idempotently.
- Evidence is content-addressed, encrypted, and retained off chain according to
  the lease and jurisdiction policy.
