# ADR-0001: System boundary

- Status: Accepted
- Date: 2026-08-09
- Baseline: `CPH-AIIE-0.2`

## Context

The strategy connects GPU PoW, preemptible scheduling, a distributed compute
pool, a paid AI workload marketplace, and CPH settlement. Putting all of these
responsibilities in the validator process would combine untrusted workload
execution, vendor GPU runtimes, customer data, economic control, and consensus
keys in one failure domain.

## Decision

Cypher L1 MUST remain the finality and settlement plane. The following MUST run
outside the validator process:

- GPU device discovery and telemetry;
- DAG construction and GPU mining;
- mining-pool share accounting;
- provider inventory and capacity leasing;
- revenue optimization and workload switching;
- customer workload execution;
- model, dataset, checkpoint, and result storage;
- market matching and quote generation;
- raw metering and receipt construction.

The chain MAY hold provider registrations, commitments, escrow balances,
receipt hashes, dispute outcomes, aggregate payout roots, and final settlement.
Validator BLS keys MUST NOT be shared with miners, agents, runners, marketplace
services, or buyer-facing APIs.

## Consequences

- GPU SDK failures cannot crash or compromise consensus by design.
- Customer artifacts remain outside consensus storage.
- Service APIs and signed records become explicit compatibility boundaries.
- Control-plane operation can continue temporarily during a chain outage, but
  new financial commitments are restricted by the failure policies in the
  Master Architecture.
