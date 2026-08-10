# Implementation Roadmap

- Baseline: `CPH-AIIE-0.2`
- Principle: Complete target architecture first; implement it in gated slices
- Calendar estimates: intentionally omitted until team, budget, and hardware
  availability are assigned

## 1. Dependency chain

```text
Architecture baseline
  -> platform/security foundation
  -> consensus and work-template conformance
  -> GPU backends and preemption primitives
  -> private mining pool and resource leases
  -> revenue optimizer automation
  -> paid AI job and measurement pilot
  -> on-chain market settlement
  -> multi-provider enterprise operation
```

No workstream may bypass an upstream safety gate merely to demonstrate a later
user interface. Parallel implementation is encouraged where interfaces are
frozen, but promotion remains dependency ordered.

## 2. Workstream 0 — Platform and security foundation

### Deliverables

- canonical Protobuf schema registry plus independent CCSE-v1 signing
  projections and Go/C++/Solidity golden vectors;
- domain/audience/replay rules, schema compatibility checks and key-rotation
  lifecycle;
- separate Provider, Agent, Host, Device, Miner, Runner, Buyer and Service
  identities with bootstrap, revocation and ownership-transfer procedures;
- Governance/Policy Registry with signed versioned bundles, approval workflow,
  delay, rollback and immutable audit;
- CI/CD, dependency pinning, signed OCI/binaries, SBOM, provenance, secret
  scanning and fleet rollback before the first Agent or Miner distribution;
- OpenTelemetry conventions, bounded metric labels, log/trace redaction,
  retention/residency and audit-access controls;
- data-classification/store/retention matrix and threat models for validator,
  provider host, public miner, buyer and contract boundaries;
- release EvidenceRecord schema and predeclared numeric SLO/experiment-plan
  template.

### Gate 0

- canonical positive and negative signatures match in Go, C++ and Solidity;
- expired, wrong-audience, wrong-environment, replayed, unknown-critical and
  revoked-key operations fail closed;
- every shipped artifact has verified signature, SBOM and provenance and passes
  a practiced rollback;
- policy and audit histories survive backup/restore without state ambiguity;
- metrics have no unbounded tenant/resource labels and sensitive telemetry
  redaction tests pass;
- every downstream pilot has an owner and a frozen template for numeric
  thresholds, sample size, observation window and confidence before collection.

## 3. Workstream A — Protocol and chain foundation

### Deliverables

- normative legacy Colossus-X specification and historical vectors;
- named future consensus version and activation mechanism;
- one-time `BOOTSTRAP-UM-V1`, fixed Upgrade Registry and complete manifest,
  authorization, cancellation, readiness and historical-resolution rules;
- nonrecursive manifest payload/finality records, deterministic expiry and the
  parent-KeyBlock carrier transaction state-root anchor;
- Chain Work Adapter/Template Authority isolated from validator liveness;
- immutable signed WorkTemplate and minimal Solution schemas;
- expected chain, parent, height, epoch, time, target and difficulty checks on
  every candidate ingress;
- proposal-local candidate validity with absent-candidate validity, plus an
  optional deterministic leader selection policy that is not a global-best rule;
- difficulty design supported by quantitative shock/timestamp simulation;
- unique reward identity, state/maturity and at-most-one economic effect;
- unique reward slot plus final carrier/body, recipient and amount commitment;
- fixed-committee invariant that mining loss never stops transaction finality;
- Upgrade Manifest design for the existing FHS genesis/config commitment;
- separate consensus, work-protocol, transport and artifact-format versions;
- conformance harness used by CPU and all GPU backends.

### Gate A

- CPU full/light vectors are bit-identical across epoch and target boundaries.
- Historical sync works from genesis through all supported versions.
- One-field mutations of every template constraint are rejected.
- Zero-miner and 100x fleet-shock simulations preserve FHS liveness/safety and
  stay within specified reward/difficulty bounds.
- Candidate load cannot starve FHS CPU, memory, queues or networking.
- Bootstrap/registry historical sync, conflict, cancellation, minimum-lead and
  all-seven-validator readiness/abort rehearsals pass.
- Independent consensus/security review has no unresolved critical issue.

## 4. Workstream B — GPU miner and hardware certification

### Deliverables

- standalone native miner with CPU reference backend;
- AMD HIP/ROCm backend, followed by NVIDIA CUDA;
- current/next epoch DAG lifecycle and checksummed artifacts;
- device-local DAG loading, residence reporting and cancellation;
- multi-GPU selection, watchdog, ECC, power and thermal handling;
- signed work/result client behind a transport-neutral interface;
- deterministic backend differential tests;
- reproducible benchmark and raw-result provenance tooling;
- capability certification matrix by GPU, VRAM, driver, firmware, OS, runtime,
  allocation/isolation mode, clocks and power cap.

### Gate B-Core

- CPU light/full and each backend under promotion match every vector and the
  randomized corpus.
- No automatic production fallback masks a full/light mismatch.
- Minimum 72-hour soak has zero invalid output and bounded restart behavior.
- Hash/s, hash/W, DAG generation/load and device-ready latency are reproducible.
- Full-DAG advantage is measured against cache-only and reviewed against
  plausible FPGA/ASIC tradeoffs.
- Target hardware claim is limited to the certified matrix.

### Gate B-AMD

- Gate B-Core passes with the HIP/ROCm backend on the AMD Max 395-class matrix.
- AMD-specific power, thermal, reset, DAG-residency and AI-readiness evidence is
  approved before the report's first hardware claim advances.

### Gate B-NVIDIA

- Gate B-Core independently passes with the CUDA backend on each H200/B300
  class; AMD evidence is not reused.
- NVIDIA expansion is not required for the AMD-first private pilot and cannot be
  described as validated before this separate gate.

## 5. Workstream C — Provider execution foundation

### Deliverables

- Provider Agent with durable local WAL and generation fencing;
- minimal privileged Device Helper for reset, binding, power cap and sanitation;
- device/subresource inventory and capability snapshots;
- Kubernetes, Slurm, Ray and standalone adapter contract;
- Local Policy Evaluator enforcing owner priority, facility limits and fail-safe;
- GPU Miner and AI Runner lifecycle supervision;
- isolated runner, short-lived workload identity and encrypted artifacts;
- restart reconciliation, orphan miner kill and quarantine workflow;
- per-device state, transition reason, telemetry and audit correlation.
- canonical Lease Service with reservation/lease state, CAS/fencing, expiry,
  renewal, reconciliation and short-lived Mining Leases;
- unified ResourceClaim exclusion across reservation conversion, renewal,
  revocation, drain, expiry-pending-release and gang in-doubt recovery;
- orthogonal Device, Job, Attempt, Lease, Receipt and Settlement projections;
- reset/readiness attestation and decommission/ownership-transfer lifecycle.

### Gate C

- at most one active lease per `device_subresource_id` under concurrency,
  restart, clock fault and network partition;
- stale fencing tokens are rejected by agent, helper and runner;
- owner recall passes graceful-stop, kill, reset, sanitation and readiness tests;
- mining does not regress owner AI SLO in controlled comparison;
- unknown or stale policy, lease, time or price state fails closed;
- sandbox, egress, secret and memory-sanitation security tests pass.
- direct Marketplace-to-Agent lease creation is impossible and all mining paths
  hold a valid Mining Lease.

## 6. Workstream D — Mining pool and distributed resource pool

### Deliverables

- Mining Pool Gateway isolated from validators and FHS hot paths;
- separate Pool Accounting/Payout service and immutable share ledger;
- signed raw share-evidence retention and independent Accounting revalidation of
  every credited share, target, vardiff epoch and integer work unit;
- worker enrollment, short-lived credentials, work subscriptions and vardiff;
- share verification, duplicate/replay/stale handling and bounded admission;
- canonical reward maturity and payout reconciliation;
- Resource Pool inventory, offer, reservation and lease services;
- signed heartbeat TTL, quarantine and site/power-domain projection;
- finality-aware Chain Indexer for reward and contract events;
- provider/miner portal and auditable statements;
- KCP adapter confined to a controlled pilot; authenticated QUIC release path.
- public miner ingress separated from FHS by process/listener/port/ALPN/trust
  root/key/resource budget;
- signed miner/provider/payout binding, reward and payout state machines, PPS or
  PPLNS solvency/rounding policy.

### Gate D

- no duplicate economic reward or payout effect across retransmit, restart and
  replay; incomplete operations reconcile;
- gateway overload does not measurably violate the approved FHS latency budget;
- share ledger reconciles exactly to canonical matured rewards and fees;
- KCP bind/gateway/pool failure does not stop a validator or transaction finality;
- lease overlap is zero across the pilot fleet;
- public pool cannot launch until the authenticated bounded transport gate passes.
- a compromised Gateway forging AcceptedShare/work units cannot obtain credit,
  alter another miner's allocation or bypass Accounting verification.

## 7. Workstream E — Revenue Optimizer and asset economics

### Deliverables

- versioned provider, site, power, thermal and economics policies;
- price, CPH liquidity, difficulty/reward and energy snapshots with confidence
  and TTL;
- market/mining/off conservative marginal-value models;
- switch, model/DAG reload, retry, wear and risk costs;
- hysteresis, minimum idle/run, cooldown and maximum-switch limits;
- shadow mode comparing recommendations with operator decisions;
- signed desired-state request; local policy remains final authority;
- complete decision evidence and realized-versus-predicted reporting.
- Financial Ledger and Asset Analytics with acquisition/commissioning basis,
  owner-AI/shadow value, mining issuance, external revenue, full costs,
  depreciation/impairment, residual model and per-device/cohort replay;
- scenario horizon, discount, uncertainty and realized-versus-modeled reports.

### Gate E

- shadow-mode decisions are reproducible from archived inputs;
- stale or conflicting economic inputs never start new mining;
- facility power and owner reservations always override optimizer output;
- pilot-defined false-start and missed-opportunity limits are met;
- realized net margin is positive in the declared scenario after all included
  costs; no profitability claim extends beyond that evidence.
- payback/lifetime/residual reports reproduce from immutable entries and show
  unknown inputs rather than inferred owner revenue.

## 8. Workstream F — Compute market and execution

### Deliverables

- Buyer/organization IAM, quotas and financial authorization;
- workload-class catalog and immutable JobSpec;
- quote, reservation, lease, attempt, retry, cancellation and acceptance flows;
- pre-execution cancel/reject/expiry states and idempotent JobClosureSaga across
  Attempt, ResourceClaim, Lease, artifact grants and Escrow reconciliation;
- AllocationGroup/GangLease prepare/commit/abort and topology-aware renewal;
- non-billable IN_DOUBT reconciliation for partial gang commits;
- encrypted content-addressed Artifact Service;
- deterministic/buyer-accepted batch inference as the first paid class;
- Metering/Receipt service organizationally separated from matching;
- raw measurement, validated measurement and `CU-v1` derivation;
- memory-bandwidth measurement, linked latency/SLA context, fixed-point CU
  arithmetic and cross-language recomputation vectors;
- Verification/Dispute service and WORM evidence;
- ReceiptPolicy signer/quorum/clock/sequence/correction rules and separate Job,
  Attempt, Receipt, Escrow, Dispute and Settlement state machines;
- provider-trusted/hardened/attested/confidential trust tiers and a pure or
  idempotent atomic-output first paid workload class;
- encrypted-manifest artifact identity, key grants, site/cache/log/backup
  lifecycle and cross-tenant deduplication prohibition;
- enterprise API, SDK, invoice and provider statements;
- paid-compute ledger separate from mining issuance.

### Gate F

- quote-to-receipt workflow is idempotent and fully traceable;
- accepted receipt loss, duplicate billing and overlapping lease count are zero;
- cross-observer measurement variance is within the approved `CU-v1` tolerance;
- job success, retry, refund and dispute targets are met in an allowlisted pilot;
- no cross-tenant artifact, secret, GPU-memory or network disclosure is found;
- hold/funding races always release capacity and refund within the frozen bound;
- quote/lease/amount/generation-bound lock-or-refund saga makes FHS-final LOCKED
  escrow the sole market Lease ACTIVE/Attempt RUNNING financial guard;
- funded-but-unadmitted escrow, appeal-waiver/deadline and no-appeal paths reach
  deterministic terminal refund/dispute states;
- at least one external paid use case demonstrates realized provider margin;
  mining subsidy is excluded from that claim.

## 9. Workstream G — On-chain settlement

### Deliverables

- ProviderRegistry, ComputeEscrow, ComputeSettlement and DisputeResolution;
- optional aggregate PoolPayout contract if economically justified;
- integer rating, rounding, fee, dust, timeout and refund rules;
- settlement coordinator with idempotent submission, at-most-one economic effect
  and finality-aware reconciliation;
- chain pause/upgrade/governance roles with timelock and dual control;
- contract event completeness and accounting reconciliation;
- invariant/fuzz/static tests, testnet rehearsal, external audit and runbooks.
- Cypher EVM execution profile covering fork/opcodes, Solidity/ABI, gas,
  receipts/events, RPC and FHS finality conformance;
- receipt-committer threshold, dispute resolver/quorum/conflict/appeal/timeout,
  stake-withdrawal hold and partial refund rules.

### Gate G

- escrow cannot be trapped beyond its defined timeout path;
- settlement/refund has at-most-one economic effect and eventual reconciliation
  under reorg, retry and service restart;
- all contract balances reconcile to finalized receipts and liabilities;
- critical/high external audit findings are resolved;
- contract admin, treasury, dispute and validator identities are separated;
- gas and batching economics fit the paid workload model.

## 10. Workstream H — Enterprise and commercial scale

### Deliverables

- multi-provider, multi-region control plane and regional data boundaries;
- H200/B300 and additional certified hardware classes;
- checkpointable training and reserved/non-preemptible market classes;
- hardware/runtime attestation tiers and independent verifier assignment;
- provider stake, reputation, challenge and slashing policy;
- SLO/error-budget program, DR, backup/restore and incident management;
- KYC/AML, sanctions, tax, data-processing, residency and export controls;
- scaled validation of the signed-release, SBOM/provenance and rollback
  foundation established at Gate 0;
- audited product claims and commercial-scale evidence program.

### Gate H

- production availability, RTO/RPO and region-loss objectives are met;
- external security, privacy, contract and operational audits close blockers;
- provider and buyer repeat use meets the quantitative
  COMMERCIAL_SCALE_VALIDATED rule in Requirements Traceability;
- paid-compute GMV, CPH demand, provider net margin and energy intensity are
  separately reported;
- all public claims carry their capability evidence level.

## 11. Parallelization map

After Gate 0 and the relevant Gate A interface freeze, these may proceed in
parallel:

- HIP and CUDA backends against the same conformance harness;
- Provider Agent state model and Artifact/Runner security foundation;
- Resource Pool schemas and Chain Indexer read-only projections;
- contract prototypes with no public funds;
- workload benchmark/CU research and economic simulation;
- hardware-specific lab work and non-financial UI prototypes.

The following remain sequential:

- automatic optimizer actuation after preemption safety;
- public pool after candidate and transport safety;
- paid market after lease/metering integrity;
- automated settlement after receipt and contract integrity;
- enterprise claims after external audit and real buyer/provider evidence.

## 12. Work-item requirements

Every epic must state:

- affected requirement and invariant IDs;
- responsible service and prohibited responsibility expansion;
- input/output schema versions;
- security and privacy impact;
- failure and rollback behavior;
- test evidence and release gate;
- metrics, SLO and runbook changes, including predeclared numerical threshold,
  sample size, observation window and confidence/error-budget rule;
- compatibility and migration impact;
- public capability evidence level after completion.

An epic is incomplete if it only starts the happy-path process. Drain, retry,
reconciliation, expiry, idempotency, observability and operator recovery are part
of the same deliverable.
