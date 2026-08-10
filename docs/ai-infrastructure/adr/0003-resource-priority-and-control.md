# ADR-0003: Resource priority and provider control

- Status: Accepted
- Date: 2026-08-10
- Baseline: `CPH-AIIE-0.2`

## Context

The strategy makes AI the high-value primary load and mining a flexible backup
load. GPU utilization alone cannot reveal whether a device is actually free:
an inference server may have resident weights and an active SLA while reporting
low instantaneous utilization.

## Decision

- Provider policy and the provider's authoritative cluster scheduler determine
  whether capacity is releasable.
- The extension MUST NOT infer availability from utilization alone.
- Owner-reserved AI capacity has priority over market jobs and mining.
- An accepted market lease follows its declared preemption and compensation
  policy; it MUST NOT be silently terminated merely because mining or another
  quote appears more profitable.
- Mining is always preemptible and MUST release the accelerator before the
  owner-workload readiness deadline.
- The local provider agent is the final actuator for start, drain, kill, reset,
  and release operations.
- Expired control commands, leases, work templates, price snapshots, or policy
  versions fail closed.
- If no profitable and permitted workload exists, the GPU enters READY or OFF;
  continuous mining is not the default. OFF is preferred when certified safe;
  READY requires a versioned low-power exception and its energy is accounted.
- Priority order is physical/security emergency, owner scheduler authority,
  obligations of accepted leases, then new market/mining/off economics.
- “Mining workload” is always preemptible. A CPH-settled market workload is a
  separate class and follows its signed lease; genuinely non-preemptible market
  capacity must be dedicated outside discretionary owner recall for the term.

## Consequences

- Kubernetes, Slurm, Ray, and other schedulers are adapters behind one resource
  lease contract.
- Revenue optimization cannot override safety, power, thermal, data-residency,
  or accepted-SLA constraints.
- Every state transition requires an auditable reason and correlation ID.
