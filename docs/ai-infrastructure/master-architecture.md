# CPH AI Infrastructure Extension — Master Architecture

- Baseline: `CPH-AIIE-0.2`
- Status: Approved architecture baseline
- Date: 2026-08-10
- Strategy source SHA-256: `91bf6a6c9e1246f8a9a4dd06c7baf0555019cf976894e6f1fdd6816ec1abe120`
- Reviewed code commit: `7ae80156b23b20f804557eedc921bf431dc3a536`
- Code-tree condition: no tracked working-tree modifications at review time;
  untracked architecture/reference files were outside the runtime-code audit
- Scope: End-state product architecture; implementation is staged

## 1. Executive intent

The target CPH AI Infrastructure Extension is designed to turn eligible idle,
underutilized, and economically retired accelerators into productive capacity
without displacing higher-value AI work. It is intended to add two revenue paths
to provider hardware:

1. preemptible CPH mining when released capacity has no higher-value job; and
2. paid external AI compute through a distributed resource pool and market.

CPH mining is intended to bootstrap GPU supply and create a fallback load. Paid
compute is the target long-term source of external productive demand. The target
will use Cypher L1 for finality, escrow, and settlement; Cypher L1 is not the
workload execution platform.

This document defines the full destination before implementation
begins. Delivery still proceeds through dependency-ordered releases so that
hardware, economics, and service-level assumptions are measured rather than
invented.

No present-tense sentence in this document is evidence that a target component
exists. Capability claims are governed by the evidence levels in Requirements
Traceability; the code-evidence statements in §12.1 are pinned to the reviewed
commit above.

## 2. Interpretation of the strategy report

The source report is a strategic thesis, not evidence that all described
capabilities exist. This baseline classifies its statements as follows:

| Report statement | Architectural interpretation |
|---|---|
| AI remains the highest-value workload | Hard scheduling invariant |
| Idle GPUs switch to CPH mining | Required preemptible fallback capability |
| Retired GPUs join a distributed compute pool | Required federated capacity plane |
| External users pay CPH for AI compute | Required marketplace and settlement path |
| Compute Revenue Optimizer | Required policy and economics service |
| Standardized Compute Unit | Versioned measurement program, not one timeless scalar |
| AMD Max 395 followed by H200/B300 | Hardware validation order, subject to lab access |
| PoW revenue improves payback | Hypothesis measured net of all marginal costs |
| Potential hardware yield floor | Conditional economic outcome, never guaranteed |
| Proof-of-Useful-Work | Research and future product option, not baseline consensus |

### 2.1 Capability evidence snapshot

Evidence is scoped; a level never transfers from one component, hardware class,
workload class or version to another.

| Capability at reviewed code commit | Level | Scope/evidence limitation |
|---|---|---|
| Target integration of Cypher L1, EVM and fixed-committee FHS | DESIGNED | Existing code is present, but extension integration, supply chain and release gates are not passed |
| Target versioned CPU Colossus-X reference/light conformance | DESIGNED | Legacy code exists, but normative spec, vector, difficulty, ingress and provenance gates remain open |
| HIP/ROCm and CUDA full-DAG miner | DESIGNED | No backend exists in the reviewed tree |
| Mining pool/accounting public protocol | DESIGNED | Remote/KCP primitives are not a production pool |
| Provider Agent, Lease Service and Resource Pool | DESIGNED | Target additions |
| AI Runner, Artifact, Metering/CU and market | DESIGNED | Target additions; no external paid pilot evidence |
| Escrow, compute settlement and dispute suite | DESIGNED | Target contracts; current EVM conformance gate not yet passed |
| Full-lifecycle Asset Analytics | DESIGNED | Target addition; accounting policy and cohort evidence open |
| General Proof-of-Useful-Work | CONCEPT | Explicitly outside baseline consensus |
| Commercial demand, profitability and yield-floor outcomes | CONCEPT | Must be demonstrated independently; never inferred from design |

The report's financial examples, prices, and market data are contextual inputs.
They MUST NOT be embedded as permanent protocol constants.

## 3. Scope

### 3.1 In scope

- versioned Colossus-X CPU and GPU implementations;
- mining work distribution, share accounting, and payout coordination;
- provider enrollment, device inventory, capacity offers, and leases;
- local GPU telemetry, policy enforcement, and workload switching;
- isolated AI workload execution and artifact handling;
- quote, match, reservation, job, receipt, dispute, and settlement workflows;
- multidimensional compute measurement and versioned Compute Units;
- on-chain provider commitments, escrow, settlement, refund, and slashing;
- enterprise identity, security, privacy, observability, and operations;
- economic simulation and realized-margin reporting.

### 3.2 Explicit non-goals for this baseline

- changing Fair HotStuff into GPU- or PoW-based finality;
- requiring validators to store the full Colossus-X DAG;
- full-DAG Merkle roots or cell proofs in key blocks;
- claiming cryptographic proof that a miner retained 32 GiB throughout mining;
- trustless verification of arbitrary training or inference outputs;
- storing customer artifacts or raw telemetry on chain;
- using instantaneous GPU utilization as proof of availability;
- promising mining profitability, payback reduction, or a yield floor;
- defining one permanent universal Compute Unit;
- sharing validator BLS keys with any extension service;
- making KCP a production public-pool transport.

## 4. Architectural invariants

Implementations MUST preserve the following invariants.

| ID | Invariant |
|---|---|
| INV-001 | Provider-authorized owner AI work has the highest hardware priority. |
| INV-002 | Mining never starts without an unexpired scheduler release and local policy approval. |
| INV-003 | Mining is always drainable; a failed drain escalates to process kill and device reset according to policy. |
| INV-004 | Accepted market jobs follow their signed preemption, checkpoint, refund, and penalty terms. |
| INV-005 | Cypher consensus and validator keys are isolated from GPU and customer-workload failure domains. |
| INV-006 | Fixed-committee Fair HotStuff provides finality; PoW reward loss does not stop transaction finality. |
| INV-007 | A certified reference/production miner MUST use a full epoch DAG except in an explicitly labeled conformance mode; validators use deterministic cache-based verification, and network validity does not claim or require proof of DAG residency. |
| INV-008 | All consensus-visible mining behavior is versioned and activated by explicit chain rules. |
| INV-009 | Expired leases, work templates, policies, quotes, or economic snapshots fail closed. |
| INV-010 | No new mining is authorized when its conservative expected marginal profit is non-positive. |
| INV-011 | Models, data, outputs, checkpoints, secrets, and raw logs remain off chain. |
| INV-012 | Every billable action is traceable from quote to lease, attempt, measurement, receipt, and settlement. |
| INV-013 | Mining subsidy and paid-compute revenue are separately accounted and reported. |
| INV-014 | Provider, device, miner, runner, buyer, operator, and validator identities are distinct roles. |
| INV-015 | No tenant relies solely on a provider's self-reported measurement for payment. |
| INV-016 | Region, power, thermal, data-residency, and egress constraints override revenue optimization. |
| INV-017 | State-changing operations are idempotent, signed, replay-bounded, and auditable. |
| INV-018 | Chain or control-plane outages cannot create an unbounded financial obligation. |
| INV-019 | Historical measurements and receipts retain their original schema and pricing versions. |
| INV-020 | Public claims distinguish implemented, pilot, experimental, and roadmap capabilities. |
| INV-021 | At most one active revenue-producing lease exists for a `device_subresource_id` and time interval. |
| INV-022 | PoW candidates never change committee membership, leader selection, quorum, or QC validity in fixed-committee mode. |
| INV-023 | Transaction proposal and FHS finality continue when there are zero miners, no pool, no valid solution, or a DAG failure. |
| INV-024 | Exactly one consensus algorithm, difficulty rule, candidate rule and reward rule applies at any key height. |
| INV-025 | Production miners never hide a full/light mismatch by automatically switching algorithms. |
| INV-026 | Network endpoints and transport connection identifiers never enter consensus work or reward identity. |
| INV-027 | A finalized mining reward and every derived pool payout have one unique economic identity, at-most-one economic effect, and eventual reconciliation over at-least-once delivery. |
| INV-028 | Privileged device operations are isolated from market, wallet, validator and buyer-facing authority. |
| INV-029 | Every canonical entity and transition has one named writer; caches, event streams, telemetry and indexes are projections only. |
| INV-030 | Mining and market execution require an unexpired generation-fenced Lease issued by the Lease Service and admitted by the Provider Agent. |
| INV-031 | Job, attempt, lease, measurement/receipt, escrow, dispute, settlement, mining reward and pool payout states remain orthogonal. |
| INV-032 | Protobuf is an API representation, never implicitly the signing serialization; every signed operation uses the canonical rules in §10.1. |
| INV-033 | Asset-economics claims are reproducible per GPU/cohort from versioned acquisition, revenue, cost, depreciation, residual-value, horizon and uncertainty inputs. |
| INV-034 | A proposed PoW candidate may be validated without agreement on a network-wide candidate set; absence of a candidate is always valid for FHS progress. |

## 5. System context

```text
┌──────────────────────────── Provider site ────────────────────────────┐
│                                                                      │
│  Owner scheduler ──release/recall──► Provider Agent                  │
│                                          │                           │
│                 telemetry/policy ◄───────┼──────► GPU adapters       │
│                                          │                           │
│                         ┌────────────────┴──────────────┐            │
│                         │                               │            │
│                    AI Runner                    GPU Miner             │
│                 isolated workloads          full epoch DAG           │
│                         │                               │            │
└─────────────────────────┼───────────────────────────────┼────────────┘
                          │                               │
                          ▼                               ▼
              ┌──────────────────────┐       ┌──────────────────────┐
              │ Compute Control Plane│       │ Mining Pool Gateway  │
              │ inventory / market   │       │ work / share checks  │
              │ leases / receipts    │       └──────────┬───────────┘
              └──────────┬───────────┘                  │ candidate/share event
                         │                              ▼
                         │        ┌───────────────────────────────┐
                         │        │ Pool Accounting / Payout     │
                         │        └──────────────┬────────────────┘
                         │                       │ finalized reward/payout
                         ▼                       ▼
                         ┌────────────────────────────────────────┐
                         │ Cypher L1 — EVM + fixed FHS            │
                         │ commitments / escrow / settlement      │
                         └────────────────────────────────────────┘
```

The distributed GPU resource pool is logical and federated. It does not imply
that a central operator obtains unrestricted access to provider machines. A
provider agent exposes only policy-approved capabilities and accepts only
signed, bounded leases.

The end state is organized into four independently scalable planes:

| Plane | Components |
|---|---|
| Settlement | Cypher L1, contracts, finality-aware chain indexer |
| Market | Marketplace, matcher, pricing/quote, verification/dispute, settlement coordination |
| Control | Resource pool, leases, revenue optimizer, policy distribution |
| Execution | Provider Agent, Local Policy Evaluator, Device Helper, GPU Miner, AI Runner, metering probes |

No plane may treat another plane's cache or projection as its own authoritative
state. In particular, the chain index is a finality-aware projection and never
replaces canonical contract state.

## 6. Actors and trust boundaries

| Actor | Authority | Never trusted to do alone |
|---|---|---|
| Provider organization | Owns hardware and local policy | Self-approve billable measurements |
| Provider Agent | Controls local resource transitions | Hold validator or buyer funds keys |
| Common miner | Builds DAG and searches work | Choose its own network target or template |
| Pool operator | Distributes work and calculates shares | Rewrite chain-final reward outcomes |
| Compute buyer | Creates jobs and accepts results | Execute directly on provider host |
| Marketplace operator | Supplies quote inputs and orchestrates matching | Issue the canonical Quote or unilaterally release escrow |
| Runner | Executes one tenant workload | Reach validator keys or unrestricted host devices |
| Metering/verifier service | Produces or validates evidence | Change historical measurement versions |
| Pricing/oracle operator | Supplies bounded price snapshots | Rewrite an accepted quote |
| Fixed committee member | Validates and finalizes chain state | Execute customer workloads in validator process |
| Dispute authority | Resolves bounded contractual disputes | Access plaintext artifacts without policy basis |
| Auditor | Reads authorized evidence | Mutate production state |

Trust zones are: consensus, settlement contracts, marketplace control plane,
provider control plane, workload sandbox, public buyer edge, artifact storage,
and observability. Crossing a zone requires authenticated identity, explicit
authorization, schema validation, size limits, time bounds, and audit context.

## 7. Component model

### 7.1 Cypher L1 and settlement plane

Responsibilities:

- fixed-committee Fair HotStuff finality;
- EVM execution and contract events;
- canonical algorithm activation and mining-reward state;
- provider and contract commitments;
- escrow, settlement, refund, dispute result, and optional slashing;
- immutable hashes for accepted job terms and receipts.

It MUST NOT perform GPU scheduling, AI execution, artifact storage, high-rate
telemetry ingestion, market order-book matching, or raw share accounting.

### 7.1.1 Chain Work Adapter and Template Authority

The Chain Work Adapter is outside the validator process and derives mining work
from the node's canonical chain state. It is the only authority that may issue a
`NetworkWorkTemplate`. Its signature authenticates distribution; validators
still recompute every consensus field from local canonical state and never trust
the signature as a substitute for validation.

The template binds chain/genesis, parent, key height, transaction height,
algorithm and rule versions, epoch/seed, expected difficulty and target, allowed
timestamp window, reward-rule version, issue/expiry time and a monotonic template
sequence. Parent change, key-height change, rule activation, or expiry invalidates
the template. HA replicas use one fenced signing generation and publish key
rotation before use. Failure of this adapter produces no mining candidate and
MUST NOT prevent validator startup, transaction proposal, or FHS finality.

A Pool Gateway MAY add a separately signed `PoolWorkAssignment` containing
miner identity, share target, vardiff epoch and assignment expiry. It MUST NOT
alter the embedded network template. Network-template and pool-assignment keys,
domains and audit streams are distinct.

### 7.2 Colossus-X GPU Miner

The miner is a standalone native process with a vendor-neutral control surface
and backend-specific kernels.

Required modules:

- work-template client;
- algorithm-version dispatcher;
- CPU reference backend used for conformance, not competitive production;
- AMD HIP/ROCm backend;
- NVIDIA CUDA backend;
- device discovery and capability reporting;
- current- and next-epoch DAG manager;
- device-memory allocator, loader, checksum, and zeroization;
- nonce search, result construction, and local verification;
- multi-device worker manager;
- cancellation, watchdog, ECC/error recovery, and thermal/power integration;
- metrics and structured audit events.

The process MUST NOT contain validator keys, buyer artifacts, marketplace
credentials, or settlement authority.

### 7.3 Mining Pool Gateway

Responsibilities:

- obtain canonical signed network work templates;
- publish versioned miner work with expiry;
- assign pool share targets distinct from the network target;
- validate cheap fields, signatures, replay domains, duplicate shares, then PoW;
- emit an immutable `AcceptedShare` with share identity and integer work units;
- select and submit network-valid candidates;
- expose miner health, stale-rate and invalid-rate projections; and
- expose payout statements only as read-only projections obtained from Pool
  Accounting and Payout.

The pool MUST distinguish a share, a network-valid solution, a candidate accepted
by the committee, a canonical reward, and a payout. A share is never proof that
the chain paid a reward.

The hot-path gateway MUST NOT own provider balances or payout finality. Those
belong to a separate Pool Accounting and Payout service so network compromise or
load cannot silently change the accounting ledger.

### 7.3.1 Pool Accounting and Payout

Responsibilities:

- immutable accepted-share ledger and configured payout-window calculation;
- ingest the signed raw Share, NetworkWorkTemplate and PoolWorkAssignment
  evidence and independently revalidate every credited share's identity,
  template/assignment, vardiff epoch, target, integer work and PoW;
- share deduplication identity, vardiff-boundary history and integer work units;
- pool fee and rounding policy by version;
- canonical reward maturity and finality reconciliation;
- provider balance, payout threshold and liability statements;
- at-most-one economic payout effect and eventual finalized-chain reconciliation;
- correction entries rather than mutation of closed periods.

Mining reward state is `OBSERVED -> FINALIZED -> MATURED -> ALLOCATED`, and pool
payout state is `PLANNED -> SUBMITTED -> FINALIZED -> CORRECTED`. `OBSERVED` is
never spendable. Miner-to-provider/payout-address binding is signed, versioned,
effective-dated and rotation-safe. A closed allocation retains the identity that
was effective when its share window closed.

PPLNS, PPS, or another payout model is a commercial policy version, not a
consensus rule. A public pool cannot activate a model until its solvency,
variance, fee, maturity and abuse assumptions are reviewed.

For PPS the service MUST publish and monitor reserve, insolvency and tail-risk
limits. For PPLNS it MUST publish window, stale/orphan treatment and rounding/dust
rules. Delivery is at-least-once, handlers are idempotent, ledger identities are
unique, economic effects are at-most-once, and incomplete effects are eventually
reconciled; the design does not promise exactly-once network delivery.

A Gateway `AcceptedShare` is a proposal to the ledger, not accounting truth.
Pool Accounting runs with separate identity, credentials and deployment and
credits nothing until independent revalidation succeeds. It may use the common
audited PoW conformance library, but it MUST NOT trust a Gateway-supplied work
value, boolean validity result or mutable vardiff history. Missing raw evidence
is non-creditable and an alarm; forged Gateway events cannot silently dilute
another miner's allocation.

### 7.4 Provider Agent

One logical agent controls a provider failure domain. It may be replicated with
single-writer leadership, but two agents MUST NOT own the same device lease.

Responsibilities:

- hardware and runtime inventory;
- scheduler-authoritative release and recall;
- local policy, maintenance, region, data, power, and thermal enforcement;
- signed heartbeats and capability snapshots;
- lease preparation and admission;
- launch, observe, drain, kill, reset, and reconcile runner/miner processes;
- artifact staging and secure deletion coordination;
- local measurement and signed transition records;
- safe recovery after restart or network partition.

The agent MUST retain enough durable local state to discover and stop an orphaned
miner before declaring a GPU ready for owner AI work.

### 7.4.1 Local Policy Evaluator

The Local Policy Evaluator is an independently testable module at the provider
site. It applies owner priority, lease fencing, facility power, temperature,
minimum idle window, cooldown, emergency recall and network-partition rules.
Central optimization is advisory until this evaluator accepts it. The evaluator
MUST remain capable of stopping mining and denying new work when disconnected.

### 7.4.2 Privileged Device Helper

Root or equivalent privilege is confined to a minimal helper that performs only
device binding, reset, power-cap, sanitation, and sandbox preparation operations.
It accepts generation-fenced local requests from the Provider Agent. It has no
market API, pricing logic, provider wallet, artifact credentials, or validator
key access.

### 7.5 Distributed GPU Resource Pool

The resource pool is the authoritative logical inventory of offered capacity.
It contains:

- provider registry projection;
- device and partition inventory;
- versioned capability snapshots;
- health, attestation, driver/runtime, region, and network capabilities;
- owner-policy and maintenance constraints;
- capacity offers and availability windows;
- reservations and leases;
- heartbeat TTL and quarantine state;
- utilization and realized-delivery summaries, not raw customer data.

Inventory observations are not leases. Only the lease service may assign
exclusive use, and the provider agent performs the final local admission check.

### 7.5.1 Lease Service

The Lease Service is the sole control-plane writer for Reservation, Lease and
AllocationGroup desired state. It performs serializable compare-and-set updates
against the current resource generation, enforces non-overlapping exclusion
ranges, issues short-lived fencing tokens, and coordinates Provider Agent local
admission. Direct Marketplace-to-Agent lease creation is prohibited; the
Marketplace requests a reservation or lease through this service.

Distributed jobs use an `AllocationGroup` and `GangLease`. The service performs
prepare/commit/abort across all members, binds topology/interconnect constraints,
renews members as one generation, and closes or replaces the group according to
the signed partial-failure/checkpoint policy. A partial prepare is non-billable
and is compensated by releasing all prepared members.

### 7.6 Revenue Optimizer

The optimizer evaluates allowed alternatives for released capacity. It consumes
signed or authenticated snapshots with explicit observation times and expiry:

- owner scheduler state;
- accepted or available market jobs;
- mining target, expected issuance, fees, and measured device hashrate;
- CPH conversion price and liquidity haircut;
- electricity tariff, demand charge, PUE, cooling, and carbon constraints;
- device power curve, temperature, health, and wear allowance;
- switch, checkpoint, DAG load, model load, and opportunity costs;
- provider risk margin and minimum run/cooldown windows.

The decision order is fixed:

1. physical or security emergency and facility protection;
2. owner scheduler authority and reserved owner capacity;
3. obligations of an already accepted lease under its signed preemption terms;
4. economic comparison among new eligible market work, mining and off.

Accepted work is therefore a constraint, not a fresh profit candidate. Capacity
sold as genuinely non-preemptible is a separately declared dedicated capacity
class that the provider has removed from discretionary owner recall for the
contracted interval; ordinary released capacity MUST NOT be sold under that
label.

For released capacity, the decision is constrained optimization rather than an
unbounded price auction:

```text
eligible options = policy ∩ lease/SLA ∩ region ∩ power ∩ thermal ∩ security
choose max(conservative expected marginal value) among eligible options
if max value <= 0: READY or OFF
```

`OFF` is the default negative-margin target when the provider/runtime can safely
power down the device. `READY` is allowed only under a versioned operator policy
that explains why power-off is unsafe or uneconomic, places the device in its
approved lowest-power ready state, and includes that idle energy in accounting.

Mining expected value MUST deduct power, cooling, operations, pool/chain fees,
switch cost, wear allowance, stale-data haircut, and configured risk margin.
The optimizer records the complete input snapshot and reason code for every
decision. It never starts a process directly; it requests a state transition
from the provider agent.

Where applicable, the site model also includes demand charges, bandwidth and
storage, insurance/warranty impact, tax treatment, failure reserve, checkpoint
transfer, capital reserve and lost owner-work opportunity. Omitted costs are
listed in the signed decision snapshot instead of silently treated as zero.

### 7.7 Marketplace and Matcher

Responsibilities:

- buyer identity, organization, quota, and billing profile;
- workload-class catalog and policy eligibility;
- capacity discovery without exposing sensitive provider topology;
- quote-input construction and request to the sole Pricing/Quote authority;
- deterministic matching under region, hardware, data, SLA, and price rules;
- reservation and lease coordination;
- job and attempt state orchestration;
- cancellation, retry, replacement, and compensation policy;
- buyer acceptance and dispute initiation;
- settlement request creation.

The matcher MUST NOT allocate a device directly. It creates a reservation offer;
the lease service and provider agent complete two-sided admission.

Admission and matching policy is a versioned deterministic policy with tenant
and provider quotas, bounded queues, anti-starvation aging, concentration limits
and a canonical tie-break over immutable quote/request IDs. Commercial fairness
does not mean equal allocation; it means the declared policy can be replayed and
no undisclosed mutable priority changes the result.

### 7.8 AI Workload Runner

The runner is ephemeral and scoped to one execution attempt. It MUST provide:

- verified and signed workload image or runtime bundle;
- resource limits and exclusive accelerator assignment;
- tenant-specific identity and short-lived credentials;
- encrypted input, output, checkpoint, and scratch volumes;
- configurable network egress allowlist and ingress denial;
- host filesystem and control-socket isolation;
- checkpoint, cancellation, timeout, and output-finalization hooks;
- GPU reset or memory-zero procedure before reassignment;
- execution manifest and measurement evidence.

The target isolation may use hardened containers, Kata Containers, gVisor,
microVMs, confidential-compute features, or equivalent controls according to
hardware capability. A plain privileged container is not sufficient for
untrusted public workloads.

The first paid class is pure or idempotent, bounded batch work with content-
addressed inputs and an atomic output commit. A retry always creates a new
`ExecutionAttempt`; a workload with an external side effect is ineligible until
it supplies its own signed idempotency/compensation contract.

Every quote names one trust tier: `PROVIDER_TRUSTED`, `HARDENED_MULTI_TENANT`,
`ATTESTED_RUNTIME`, or `CONFIDENTIAL_COMPUTE`. Attestation proves only the
measured properties named by its policy. It MUST NOT be described as preventing
provider-root plaintext access unless the certified confidential-compute tier
and threat model explicitly provide that property.

### 7.9 Artifact Service

Models, inputs, outputs, checkpoints, logs, and evidence are content-addressed
and encrypted outside the chain. The service provides:

- tenant-controlled envelope encryption;
- immutable digest and size verification;
- region and retention enforcement;
- short-lived scoped download/upload grants;
- malware and policy scanning where permitted;
- deletion attestations and legal-hold handling;
- evidence references usable in disputes without public disclosure.

Each reference states whether its digest covers plaintext, ciphertext, or an
encrypted manifest; the canonical artifact ID is the digest of the encrypted
manifest and separately commits the plaintext digest inside the encrypted
metadata. Cross-tenant deduplication is prohibited by default to prevent
existence disclosure. The tenant or its delegated KMS owns envelope keys and
grants only the active attempt identity.

The retention policy covers object store, site cache, scratch, checkpoint,
runner logs, traces and backups by data class and region. Deletion revokes keys
first and then performs best-effort physical deletion with an attestation;
neither is called guaranteed erasure where media or backup semantics cannot
support it. WORM billing/security evidence stores digests and minimum necessary
metadata, not customer plaintext, and legal-hold precedence is explicit.

### 7.10 Metering and Receipt Service

The service normalizes observations without destroying the raw record. It
correlates:

- job, lease, attempt, provider, device, and workload identifiers;
- monotonic start/stop and wall-clock anchors;
- accelerator active time and allocation time;
- declared and observed memory capacity/bandwidth class plus transfer counters;
- hardware, driver, firmware, runtime, image, model, and precision digests;
- energy, thermal, throttling, restart, checkpoint, and error observations;
- benchmark and Compute Unit schema versions;
- agent, orchestrator, buyer/verifier, and attestation signatures.

Every quote fixes a `ReceiptPolicy` naming required signers/quorum, attestation
freshness, allowed observation gaps and clock drift, sequence domains, acceptance
deadline, correction and clawback rules. Device observations bind `boot_id` and
a monotonic device counter; attempt and device sequences are distinct. Energy
for a partition is attributed by a certified device-class allocation method and
otherwise reported as uncertain rather than fabricated.

It creates an immutable receipt and a separately versioned settlement
instruction. A receipt correction creates a new record linked to the old one;
it never mutates signed history.

Meter sequences are monotonic per attempt/device and form an integrity chain.
Original closed receipts and security audit evidence are retained in an
append-only or WORM-capable store; the operational time-series database is not
the billing ledger.

### 7.11 Pricing, Quote and Oracle Service

Responsibilities:

- workload-class benchmark and price tables;
- provider asks and buyer constraints;
- fiat/stable-unit display prices;
- CPH conversion snapshots with source, timestamp, confidence, and expiry;
- mining profitability inputs and liquidity/risk haircuts;
- sole canonical Quote issuance/signing and historical reproducibility.

Marketplace and Matcher provide a proposed placement, buyer constraints and
policy inputs, but cannot create or mutate a Quote. The service validates every
input/snapshot, allocates the Quote sequence and signs the immutable canonical
record. A later price observation creates a new Quote ID; it never rerates one
already accepted.

An oracle snapshot is an input to a quote, not authority to change accepted
terms. Stale or disputed data disables new quotes and new optimizer decisions.

### 7.12 Settlement Coordinator

The coordinator bridges accepted off-chain evidence to contracts. It:

- verifies quote, lease, receipt, acceptance, and policy-version linkage;
- calculates provider, pool/operator, treasury, verifier, and refund amounts;
- submits idempotent settlement transactions;
- tracks finality and reorg-safe reconciliation;
- retries without duplicate payment;
- emits immutable settlement journal entries to Financial Ledger and exposes a
  read-only reconciliation projection;
- opens the dispute path instead of guessing when evidence conflicts.

### 7.12.1 Finality-aware Chain Indexer

The indexer projects finalized contract and reward events into control-plane
read models. It tracks block/key-block identity, finality status, event position,
and projection version; detects and safely handles non-final reorganization; and
can rebuild from canonical history. It never authorizes payment from an
unfinalized or merely observed transaction.

### 7.12.2 Verification and Dispute Service

This service owns challenge sampling, known-answer checks, redundant execution,
buyer acceptance evidence, dispute deadlines and bounded evidence evaluation.
It is organizationally and technically separated from marketplace matching and
provider self-metering. A provider, buyer, verifier, or marketplace operator
cannot unilaterally settle a contested amount outside the signed policy.

Each dispute policy fixes resolver eligibility and quorum, conflict-of-interest
exclusion, evidence access, appeal count, provider-stake withdrawal hold,
verifier-outage timeout, partial receipt/refund rules and terminal authority.
Protected evidence is disclosed only to authorized resolvers under the same
residency and audit policy as the originating lease.

### 7.12.3 IAM and PKI

IAM issues and revokes organization, user, service, host, device and workload
identities plus short-lived scoped credentials. It maintains role and policy
bindings without importing consensus BLS authority. Long-lived identity keys
are hardware- or KMS-protected where possible; runners receive only attempt-
scoped credentials.

Provider organization, human user, service, Agent instance, Host, Device
attestation identity, Miner and Runner attempt are separate principals. Signed
bindings establish organization ownership without sharing private keys. The PKI
specifies bootstrap, renewal, revocation propagation, maximum offline expiry,
re-enrollment, compromise recovery and ownership transfer. SPIFFE-compatible
identity authenticates a principal; versioned authorization policy decides what
that principal may do.

### 7.13 Operations, portal, and SDK

The end-state product includes:

- provider CLI and portal;
- buyer API, CLI, and SDK;
- operator administration with dual control;
- dashboards and SLO views;
- audit export and accounting statements;
- incident, maintenance, key-rotation, and disaster-recovery workflows;
- capability and status pages that distinguish production from experimental.

### 7.14 Governance and Policy Registry

The registry publishes signed, versioned, effective-dated policy bundles for
provider eligibility, workload classes, CU formulas, benchmark certification,
pricing sources, optimizer bounds, pool fees, verification tiers, retention and
emergency controls. Services persist the exact policy digest used for every
decision and reject unknown critical policy versions.

Normal changes use review, separation of duties, delayed activation and rollback
plans. Break-glass actions have a narrow scope and expiry, require dual control
where feasible, and always emit immutable audit evidence. An emergency market
pause cannot rewrite finalized chain history or silently seize provider hardware.

### 7.15 Financial Ledger and Asset Analytics

This service is the canonical operational ledger for off-chain asset economics;
on-chain balances and finalized payments remain authoritative contract state. It
maintains immutable double-entry realized entries for mining issuance, external
compute revenue, costs, treasury flows and asset events without combining them
into one revenue number. Owner-AI shadow value and forward scenarios are tagged
non-booked memo series and never presented as realized accounting revenue.

For every physical GPU or accounting cohort it records:

- acquisition cost, commissioning date, quantity, accounting currency and
  versioned FX basis;
- depreciation method, useful-life estimate, impairment/correction entries and
  policy version;
- provider-supplied owner-AI revenue or confidential shadow-value entries;
- realized mining issuance, externally paid compute revenue and all marginal
  and allocated costs;
- downtime, eligible/used idle hours, failure/maintenance and disposal events;
- residual-value model/version, sale or retirement outcome;
- scenario horizon, discount rate, price/power assumptions, uncertainty bands
  and sensitivity set.

Every formula has a versioned digest. The baseline definitions are:

```text
IncrementalNet(t) = externally_paid_compute_cash(t)
                  + separately_valued_mining_issuance(t)
                  - attributable_power_cooling_operations_fees_wear_switch(t)

LifetimeNetCash(t) = owner_AI_realized_cash_or_declared_shadow(t)
                   + IncrementalNet(t) + realized_disposal_cash(t)
                   - acquisition_and_commissioning_cash
                   - other_allocated_lifetime_cost(t)

SimplePayback = earliest t where cumulative undiscounted net cash >= 0
DiscountedPayback = earliest t where cumulative discounted net cash >= 0
PaybackDelta = comparable_baseline_payback - extension_scenario_payback
```

Reports label realized cash, non-booked shadow value and scenario values
separately, state whether payback is simple or discounted, and never add a model
residual value to realized disposal cash for the same asset.

Payback, NPV, lifetime recovery and residual-income reports are derived views
whose inputs and formula digest are preserved. Missing owner-revenue data is
shown as `UNKNOWN` or a provider-supplied shadow series, never inferred from
private utilization. Scenario results and realized accounting are displayed
separately. A model may inform policy, but it cannot rewrite booked entries or
guarantee payback, profitability or a hardware yield floor.

### 7.16 Accountability model

| Decision domain | Accountable role | Required independent review |
|---|---|---|
| Consensus algorithm and activation | Protocol governance | Consensus security and validator readiness |
| GPU backend and hardware certification | GPU runtime owner | Independent conformance/performance QA |
| Local device and AI-priority policy | Provider organization | Platform safety policy |
| Pool fee and payout method | Pool product/finance | Accounting, solvency and abuse review |
| CU schema and benchmark factors | Measurement governance | Buyer/provider reproducibility review |
| Quote/oracle sources | Market pricing owner | Treasury risk and audit |
| Contracts and settlement | Protocol treasury/product | Smart-contract security and accounting |
| Asset ledger, depreciation and residual model | Finance/accounting owner | Independent finance and evidence review |
| Isolation and identity controls | Security owner | Privacy and penetration review |
| Data residency/retention/acceptable use | Legal/privacy/product | Security and provider applicability |
| SLO, deployment and incident policy | SRE owner | Service owners and provider operations |
| Public capability/economic claims | Product communications | Evidence, finance and legal review |

## 8. Resource state model

State machines below are orthogonal. A completed Job may have an open Receipt
challenge; a finalized Receipt may await Settlement; a failed Attempt may be
followed by another Attempt. Combining those facts into one status is forbidden.

### 8.1 Canonical state ownership

| State | Canonical writer/source | Projection or physical authority |
|---|---|---|
| Actual device/process/readiness | Provider Agent local WAL | Device Helper actuates; Resource Pool projects |
| Desired Reservation/Lease/AllocationGroup | Lease Service in serializable PostgreSQL | Provider Agent locally admits/rejects |
| Observed inventory/capability | Provider Agent signed snapshot | Resource Pool indexes and expires it |
| Job/Attempt orchestration | Marketplace Orchestrator | Runner reports; event log projects |
| Quote | Pricing, Quote and Oracle Service | Marketplace supplies validated inputs only |
| Raw measurement/Receipt/Acceptance record | Metering and Receipt Service | Buyer/verifier/timeout policy submits decisions; WORM preserves closed records |
| Escrow, payout and refund balance | Cypher contract state | Chain Indexer is a finalized projection |
| Off-chain accounting/liability | Financial Ledger or Pool Accounting | Dashboards/statements are projections |
| Finalized chain payment/reward | Cypher canonical history | Indexer/accounting reconcile from it |

Each entity has a `home_region`, monotonically increasing writer epoch and
single active writer. Region failover requires expiry or explicit transfer of
the old writer lease, quorum-approved recovery, a higher writer epoch and local
Agent reconciliation before new work. A partitioned old region cannot renew or
create financial obligations. Financial metadata has RPO 0 only when the primary
commit is synchronously replicated to a quorum spanning the declared region-
loss failure domain or durably journaled in an independently survivable domain
before acknowledgement. A local durable outbox alone does not satisfy regional
RPO 0. If the quorum/journal is unavailable, new financial transitions fail
closed. Read models may have a declared nonzero RPO and are rebuildable.

### 8.2 Device state

Each physical GPU or indivisible certified partition has one actual state and a
monotonically increasing generation.

| State | Meaning | Permitted next states |
|---|---|---|
| DISCOVERED | Seen locally but not trusted | ATTESTING, QUARANTINED, OFFLINE |
| ATTESTING | Identity/capability checks running | READY, QUARANTINED, ERROR |
| READY | Released and idle, no active lease | RESERVED_OWNER, RESERVED_MARKET, PREPARING_MINING, MAINTENANCE, OFFLINE |
| RESERVED_OWNER | Owner scheduler has reclaimed capacity | RUNNING_OWNER, RESETTING, ERROR |
| RUNNING_OWNER | Provider's primary AI workload | DRAINING, ERROR |
| RESERVED_MARKET | Market lease locally admitted | STAGING_MARKET, DRAINING, ERROR |
| STAGING_MARKET | Artifacts/runtime being prepared | RUNNING_MARKET, DRAINING, ERROR |
| RUNNING_MARKET | Accepted external compute lease | DRAINING, ERROR |
| PREPARING_MINING | Mining lease admitted; DAG/miner preparation | MINING, DRAINING, ERROR |
| MINING | Preemptible CPH mining | DRAINING, ERROR |
| DRAINING | Checkpoint/stop/kill in progress | RESETTING, QUARANTINED, ERROR |
| RESETTING | Helper reset, sanitation and health/readiness check | READY, RESERVED_OWNER, COOLDOWN, QUARANTINED, ERROR |
| COOLDOWN | Thermal or anti-flap hold | READY, OFFLINE, ERROR |
| MAINTENANCE | Operator-controlled service state | ATTESTING, TRANSFER_PENDING, DECOMMISSIONED, OFFLINE |
| QUARANTINED | Security, correctness, or health concern | ATTESTING, MAINTENANCE, DECOMMISSIONED, OFFLINE |
| ERROR | Reconciliation required | QUARANTINED, MAINTENANCE, DECOMMISSIONED, OFFLINE |
| OFFLINE | No usable heartbeat or intentionally powered down | DISCOVERED, ATTESTING, TRANSFER_PENDING, DECOMMISSIONED |
| TRANSFER_PENDING | Ownership/key/data closure in progress | ATTESTING, DECOMMISSIONED |
| DECOMMISSIONED | Terminal retired/revoked identity | none |

Any tenant workload or mining kernel execution requires `DRAINING -> RESETTING`.
The sole exception is cancellation before any device context, secret, artifact
or kernel was created; its signed no-execution attestation may authorize direct
release. Runner zeroizes its process scope, but only Device Helper can attest
device reset/sanitation. READY requires a current reset/readiness attestation.

Every command names the expected generation; stale commands are rejected. A
lease is bound to that generation and cannot survive reassignment. Owner recall
from MINING enters DRAINING immediately. Recall from RUNNING_MARKET follows the
signed class; emergency termination emits evidence, refund and penalty. ERROR or
QUARANTINED is never offered. Agent restart reconciles local WAL, process table,
GPU state and Lease Service before READY. Ownership transfer revokes old
bindings, keys and offers and sanitizes caches before a new attestation.

### 8.3 Reservation, Lease and AllocationGroup state

```text
Reservation: PROPOSED -> HELD -> CONVERTED_TO_LEASE
                              \-> RELEASED | EXPIRED | REJECTED

Lease: PROPOSED -> HELD -> LOCALLY_ADMITTED -> ACTIVE
             ACTIVE -> RENEWING -> ACTIVE
             ACTIVE/RENEWING -> REVOKE_REQUESTED | EXPIRY_REQUESTED
                              | FAILURE_REQUESTED -> DRAINING -> CLOSED
             PROPOSED/HELD/LOCALLY_ADMITTED -> REJECTED | EXPIRED_UNUSED

AllocationGroup: PREPARING -> PREPARED -> COMMITTING -> ACTIVE
                               \             \-> IN_DOUBT -> RECONCILING
                                \-> ABORTING <----------/       |       |
                                      |                    ACTIVE   ABORTING
                                   ABORTED
                         ACTIVE -> DRAINING -> CLOSED | FAILED

GroupMember: PROPOSED -> PREPARED -> COMMITTED -> ACTIVE
                         \             \-> ABORTING -> ABORTED
                          \-> ABORTING
                       ACTIVE -> DRAINING -> CLOSED | FAILED
```

Lease Service is the only writer. Each transition is a serializable CAS over
`lease_id`, `device_subresource_id`, half-open interval `[start,end)`, resource
generation, writer epoch and fencing token. A PostgreSQL exclusion constraint
is applied to one unified `ResourceClaim` used by Reservation, Lease and group
member records. It prevents overlap while a claim is HELD, LOCALLY_ADMITTED,
ACTIVE, RENEWING, REVOKE/EXPIRY/FAILURE_REQUESTED, DRAINING, PREPARED, COMMITTED,
IN_DOUBT or awaiting an Agent release attestation. Expiry never releases the
claim merely because wall time passed. Agent enforces the same token locally.
`HELD` is short, capacity-exclusive and non-billable unless its quote explicitly
prices the hold. Reservation-to-Lease conversion changes owner/type of the same
claim in one serializable transaction without a release/reacquire gap. Market and
mining both use leases; mining leases are short-lived, preemptible,
renew-before-expiry leases without escrow.

Provider Agent signs local admission. Only Lease Service may enter ACTIVE after
local admission and the linked market Escrow is LOCKED, or after the lease policy
explicitly records `funding_not_required` for a Mining Lease.
Heartbeat loss stops renewal, prevents new attempts and enters reconciliation;
it does not invent completion. Expiry terminates billable time at the last valid
metered boundary, commands drain, and applies the signed checkpoint/refund rule.
Agent restart presents its last token; a lower token is killed, an equal token is
reconciled, and a higher canonical token supersedes it. Gang prepare failure
aborts all members. No group member may start or bill before every member is
COMMITTED and the group is ACTIVE. A coordinator crash or partial commit enters
IN_DOUBT: all member claims remain exclusive and non-billable while reconciliation
either proves every prepared token still valid and completes activation, or
drains/releases every member and records ABORTED. After ACTIVE, the signed group
policy defines replace, checkpoint or whole-group failure.

### 8.4 Job and ExecutionAttempt state

```text
Job: DRAFT -> SUBMITTED -> ADMITTED -> EXECUTING
     DRAFT -> CANCELED
     SUBMITTED -> CANCELING | REJECTING | EXPIRING
     ADMITTED -> CANCELING | FAILING | EXPIRING
     EXECUTING -> COMPLETED | CANCELING | FAILING
     CANCELING -> CANCELED
     REJECTING -> REJECTED
     EXPIRING -> EXPIRED
     FAILING -> FAILED

Attempt: CREATED -> STAGING -> STARTING -> RUNNING
       RUNNING -> CHECKPOINTING -> RUNNING
       RUNNING -> OUTPUT_COMMITTING -> SUCCEEDED
       any nonterminal -> CANCELED | TIMED_OUT | FAILED
```

Marketplace Orchestrator writes Job/Attempt states. A retry creates a new
Attempt with a new identity and never reopens a terminal Attempt. Job COMPLETED
means its required attempts and atomic output manifest completed; it does not
mean accepted, paid or dispute-free. No Attempt becomes RUNNING before active
lease fencing, artifact digests, attempt identity, a linked LOCKED Escrow (or
Mining Lease `funding_not_required`) and local
admission agree. Recovery observes external state before issuing a compensating
transition; it never assumes a timed-out command failed.

Entering CANCELING, REJECTING, EXPIRING or FAILING atomically records a unique
`JobClosureSagaID` and immediately prohibits new Attempts. The idempotent saga
cancels/drains any Attempt, revokes artifact grants, converts or releases the
Reservation/Lease/ResourceClaim, and selects the linked Escrow lock/refund path.
A terminal Job requires execution and resource ownership to be closed and every
remaining financial obligation to have a durable reconciliation record; Escrow,
Dispute and Settlement may finish later in their own orthogonal states. On
restart the Orchestrator resumes the closure saga and MUST NOT recreate work for
a Job in a closure or terminal state.

### 8.5 Measurement, Receipt, Escrow, Dispute and Settlement state

```text
Measurement: OPEN -> CLOSED -> VALIDATED | REJECTED -> SUPERSEDED
Receipt: DRAFT -> ISSUED -> SUPERSEDED
Acceptance: PENDING -> ACCEPTED | REJECTED | CHALLENGED | TIMED_OUT
Escrow: UNFUNDED -> FUNDING -> FUNDED
                    \-> FUNDING_FAILED
        FUNDED -> LOCKED | REFUND_PENDING
        LOCKED -> RELEASE_PENDING | REFUND_PENDING | PARTIAL_PENDING
        RELEASE_PENDING -> RELEASED
        REFUND_PENDING -> REFUNDED
        PARTIAL_PENDING -> PARTIAL
Dispute: OPEN -> EVIDENCE_LOCKED -> REVIEWING -> DECIDED -> APPEAL_WINDOW
        APPEAL_WINDOW -> FINAL
        APPEAL_WINDOW -> APPEALED -> APPEAL_REVIEW -> FINAL
Settlement: PLANNED -> SUBMITTED -> OBSERVED -> FINALIZED -> CORRECTED
```

Metering and Receipt Service is the sole writer for Measurement, Receipt and
Acceptance records. A buyer/verifier submits a signed decision and the service
serializes it against the Receipt generation; a configured timeout is a policy
input, not a competing writer. Conflicting timely accept/challenge submissions
enter CHALLENGED and cannot be overwritten by a later timeout. Contracts own
Escrow; Verification/Dispute writes off-chain case state while the configured
resolver threshold authorizes the on-chain outcome; Settlement Coordinator
plans/submits and canonical chain finality writes the economic result. A funded
but unadmitted or hold-expired job uses `FUNDED -> REFUND_PENDING -> REFUNDED`.
`DECIDED -> APPEAL_WINDOW -> FINAL` occurs on signed waiver or deadline expiry;
the policy permits at most its declared appeal count. A correction references,
but never mutates, the prior record. `Settlement.identity = H(chain/genesis,
contract, lease_id, receipt_id,
settlement_policy_version)` and has at-most-one economic effect. Partial release
and refund use numbered child entries whose integer sum equals the locked amount.

### 8.6 Mining reward and pool payout state

```text
Reward: OBSERVED -> FINALIZED -> MATURED -> ALLOCATED
Payout: PLANNED -> SUBMITTED -> OBSERVED -> FINALIZED -> CORRECTED
```

Canonical reward identity is two-level:

```text
reward_slot_id = H("CPH-POW-REWARD-SLOT-V1", chain_id, genesis_hash,
                   reward_rule_version, key_height, reward_event_index)
reward_id = H("CPH-POW-REWARD-V1", reward_slot_id,
              canonical_fhs_final_carrier_tx_block_hash,
              recipient_address, amount)
```

The carrier transaction-block hash commits the complete encoded KeyBlock body,
including candidate and output address; recipient and amount are also explicit.
There are zero or one rewards per `reward_slot_id`, enforced by a unique ledger
and protocol constraint, so a different recipient/amount hash cannot allocate
the same slot twice. Reward becomes FINALIZED only after direct-child-QC proof
for that exact carrier succeeds and MATURED only after the versioned pool safety
delay. Pool payout identity adds `reward_id`, payout-policy version, closed
share-window ID and recipient-binding version. Retries reuse the identity;
corrections are linked entries and cannot create a second liability allocation.

## 9. Canonical domain model

All identifiers are globally unique, immutable, and included in audit events.
Every record carries `schema_version`, `created_at`, and an integrity digest.

| Entity | Purpose and key relationships |
|---|---|
| Provider | Organization, payout identity, jurisdictions, policy and stake reference |
| ProviderSite | Region, power domain, network, data-residency and scheduler adapter |
| Device | Physical accelerator identity and ownership lifecycle |
| DevicePartition | Schedulable whole device or supported isolated partition |
| CapabilitySnapshot | Signed hardware/runtime/benchmark/attestation observation |
| CapacityOffer | Time-bounded provider willingness and constraints |
| Quote | Signed price, conversion snapshot, SLA, verification and expiry |
| Reservation | Short hold while both sides complete admission |
| Lease | Binding resource, policy, escrow, preemption and financial terms |
| AllocationGroup | Atomic topology-aware set of reservations/leases for a gang job |
| JobSpec | Immutable workload, artifact, resource, output and verification request |
| ExecutionAttempt | One placement and runtime attempt under a lease |
| Artifact | Encrypted content reference, digest, size, region and retention policy |
| Measurement | Immutable raw and normalized resource observations |
| ComputeUnitRecord | Versioned derivation from one or more measurements |
| Receipt | Signed evidence bundle and billable outcome |
| Acceptance | Buyer/verifier decision or timeout rule result |
| Dispute | Contested scope, evidence references, authority and resolution |
| Settlement | Idempotent allocation of escrow to all destinations |
| WorkTemplate | Canonical mining work and target with expiry and signature |
| Share | Pool-target result tied to one work template and miner identity |
| MiningCandidate | Network-target result submitted toward chain acceptance |
| PoolPayout | Canonical reward reconciliation and provider allocation |
| AssetRecord | Acquisition, commissioning, ownership, depreciation and retirement basis |
| EconomicEntry | Immutable classified realized revenue, cost, impairment or residual event |
| EconomicScenario | Versioned horizon, discount, uncertainty and sensitivity assumptions |
| PolicySnapshot | Versioned provider, market, power, security and optimizer rules |
| AuditEvent | Append-only state transition with actor, cause and correlation ID |

Financial amounts use integer smallest units plus asset/decimals metadata. Times
used for durations are monotonic within a host; signed wall-clock anchors are
used across systems. Floating-point values MUST NOT determine on-chain payment.
Every lifecycle entity also carries `home_region`, `writer_epoch`, `state_version`,
`idempotency_key`, `policy_digests` and the identity of its transition authority.

## 10. Interface contracts

### 10.1 Common envelope

Every state-changing cross-service message contains:

```text
protocol_version
schema_version
message_id
correlation_id
causation_id
sender_identity
chain_id / environment
issued_at
expires_at
sequence or expected_generation
payload_digest
signature_algorithm_id
signature_key_id
signature
```

Protobuf carries API data but is not the signing byte representation. Signed
off-chain records use `CPH Canonical Signing Encoding v1` (`CCSE-v1`):

```text
preimage = "CPH-AIIE-CCSE-V1\0"
         || u32be(message_type_id)
         || u32be(schema_major) || u32be(schema_minor)
         || len32(domain) || canonical_domain
         || len64(envelope_without_signature) || canonical_envelope
         || len64(payload) || canonical_payload
signature = algorithm(signature_algorithm_id, key_id, SHA-256(preimage))
```

The schema registry defines the ordered signing projection for every message.
Unsigned/unknown critical fields are rejected. Optional unknown fields may be
ignored only when their schema marks them noncritical and they are outside the
signing projection. Presence is encoded separately from a scalar default; maps
and floating point are prohibited in signed projections. Integers are fixed-
width big-endian, byte/string values are length-prefixed, timestamps are signed
UTC nanoseconds, strings are valid UTF-8 NFC, ordered lists retain order, and
declared sets sort by their canonical encoded bytes. No transport serialization,
field insertion order, locale or host clock representation affects the digest.

The canonical domain includes message purpose, sender, recipient/audience,
tenant/provider organization, chain ID, genesis hash, deployment environment,
protocol/schema version, key ID, issue/expiry, nonce/sequence and replay-domain
ID. The signature covers that domain, the complete envelope except `signature`,
and the canonical payload. A payload digest without the bound envelope is not a
valid authorization.

The reference authorization profile uses Ed25519 for service/miner records;
registered TPM/HSM-bound P-256 keys MAY sign only message types allowed by their
policy. The algorithm ID is inside the signed envelope and downgrade is rejected.
EVM authorization uses secp256k1 through EIP-712. New signature algorithms
require a policy/ADR, cross-language vectors and an overlap/retirement schedule.

Operations consumed by Solidity use EIP-712 with `chainId`,
`verifyingContract`, protocol name/version and `genesis_hash` salt, and include
the SHA-256 CCSE record digest plus the canonical financial identifiers. The
schema repository MUST publish Go, C++ and Solidity-compatible golden vectors
for every signed type, including absence/default, Unicode rejection, set order,
unknown field, wrong audience, expiry and key-rotation negatives.

Receivers authenticate before expensive work, enforce maximum encoded and
decoded sizes, validate canonical encoding, reject replay, and return an
idempotent result for repeated `message_id`.

Mining work is narrower than the generic envelope. The Chain Work Adapter fixes
chain ID, genesis/network domain, parent, key height, transaction height,
algorithm version, epoch, seed, expected difficulty, network target, timestamp
window, expiry and reward binding from canonical state. The Gateway may only
wrap it with miner identity, vardiff/share target and a shorter expiry. A miner
returns only the template/assignment hashes, nonce, mix digest and miner
signature. GPU type, full-DAG status and capability evidence are pool and
certification metadata, never consensus validity inputs.
IP address, port, transport, connection ID and miner-selected difficulty are not
consensus work inputs.

### 10.2 Required APIs

| API | Direction | Minimum operations |
|---|---|---|
| Scheduler Adapter | Provider scheduler ↔ Agent | release, recall, status, readiness |
| Device Adapter | Agent ↔ GPU runtime | discover, metrics, allocate, reset, power-cap |
| Miner Control | Agent ↔ GPU Miner | prepare, start, drain, stop, health, metrics |
| Runner Control | Agent ↔ Runner | stage, launch, checkpoint, cancel, finalize |
| Provider Control | Agent ↔ Resource Pool | enroll, heartbeat, offer, admit, transition |
| Market API | Buyer ↔ Marketplace | discover, quote, reserve, submit, status, accept, dispute |
| Lease API | Marketplace ↔ Lease Service ↔ Agent | hold, propose, local-admit/reject, fund, activate, renew, recall, close |
| Artifact API | Buyer/Runner ↔ Storage | grant, upload, download, finalize, delete |
| Metering API | Agent/Runner ↔ Metering | observe, attest, close, receipt-status |
| Mining Work API | Pool ↔ Miner | capabilities, get-work/subscribe, submit-share, status |
| Candidate API | Pool ↔ Chain ingress | template, submit-candidate, canonical-result |
| Settlement API | Control plane ↔ L1 | fund, commit, settle, refund, dispute, reconcile |

Local agent-to-runner/miner communication SHOULD use a Unix-domain socket or
equivalent host-local authenticated channel. Provider and control-plane APIs
MUST use mutually authenticated encrypted transport in production. Buyer APIs
MUST use organization identity, scoped authorization, quotas, and request
signing for financial operations.

### 10.3 Event model

Durable domain events form the integration history. Consumers are idempotent and
may receive duplicates. Core events include:

```text
ProviderEnrolled, CapabilityObserved, DeviceQuarantined
CapacityOffered, ReservationCreated, LeaseAccepted, LeaseExpired
JobSubmitted, AttemptStarted, AttemptCheckpointed, AttemptCompleted
MeasurementClosed, ReceiptIssued, ReceiptAccepted, DisputeOpened
SettlementSubmitted, SettlementFinalized, RefundFinalized
MiningPrepared, MiningStarted, MiningDrained
GatewayShareValidated, AccountingShareCredited, CandidateSubmitted,
RewardFinalized, PoolPayoutFinalized
```

The event bus is not the financial source of truth. Settlement state is
reconciled against finalized chain events.

## 11. Critical end-to-end flows

### 11.1 Provider enrollment

1. Provider organization completes identity, payout, policy, and jurisdiction
   registration.
2. Host/Device generates a non-exportable key or attestation handle through
   TPM/KMS where available; Agent submits its CSR/attestation and ownership proof
   to IAM.
3. IAM issues the Device identity and signed Provider/Agent/Host/Device binding;
   Agent is never a certificate authority.
4. Agent discovers devices and produces a signed capability snapshot.
5. Attestation and benchmark evidence are validated according to capability
   class.
6. Resource pool records the device as READY or QUARANTINED.
7. On-chain provider commitment is created only when required by market policy.

### 11.2 Mining fallback

1. Owner scheduler explicitly releases a device.
2. No accepted market lease requires it.
3. Optimizer evaluates an unexpired conservative mining snapshot.
4. Lease Service issues a short-lived preemptible Mining Lease for the current
   device generation; Provider Agent locally admits its fencing token.
5. Agent enters PREPARING_MINING, loads the canonical DAG, and verifies a
   golden-vector self-test.
6. Pool supplies a signed, expiring work template and share target.
7. Miner searches, submits shares, and reports power/thermal metrics while the
   Agent renews the Mining Lease.
8. Owner recall, lease expiry or higher-priority eligible work immediately
   enters DRAINING.
9. Agent stops the miner, closes the lease, resets/sanitizes the device, proves
   readiness, and
   returns control to the owner scheduler.

### 11.3 Paid AI job

1. Buyer submits an immutable JobSpec and verification requirements.
2. Marketplace submits matched capacity, buyer and policy inputs; Pricing, Quote
   and Oracle Service validates them and solely issues the expiring canonical
   Quote with a fixed CPH conversion snapshot.
3. Buyer signs the quote; Lease Service obtains a bounded exclusive HELD
   reservation and Provider Agent performs preliminary local admission.
4. Buyer funds escrow before the hold expiry. Failure or late finality releases
   the hold and executes the quote's deterministic full-refund path, including
   the named gas/fee bearer.
5. Settlement Coordinator requests one escrow outcome keyed by quote, lease,
   amount and resource generation: LOCKED for the admitted unexpired hold, or
   REFUND_PENDING after expiry/rejection. Contract state makes these outcomes
   mutually exclusive and idempotent.
6. Lease becomes ACTIVE only after local admission and FHS-final LOCKED escrow.
7. Artifacts are encrypted and staged with scoped credentials.
8. Runner starts a unique Attempt; agent and orchestrator produce correlated
   measurements.
9. Output and evidence are atomically finalized; buyer/verifier accepts or
   disputes under the ReceiptPolicy.
10. Receipt is issued, settlement instruction is calculated, and L1 finality is
   reconciled before balances are reported as paid.
11. Artifacts are retained or deleted under the signed policy and legal holds.

### 11.4 Owner recall

1. Scheduler issues a signed/local-authoritative recall with deadline.
2. Agent rejects new work and sets DRAINING.
3. Mining stops immediately; a market job checkpoints or follows its lease
   emergency policy.
4. Agent escalates from graceful stop to kill to device reset within configured
   bounded stages.
5. Memory sanitation and readiness checks complete.
6. Scheduler receives exclusive control; transition evidence is emitted.

### 11.5 Dispute

1. Buyer or provider opens a dispute before the receipt deadline.
2. Undisputed funds may settle only if contract policy permits; disputed funds
   remain locked.
3. Evidence digests, signatures, measurements, logs, attestations, and artifact
   references are assembled without publishing protected data.
4. Configured automated checks, redundant verifier, or bounded human authority
   resolves the dispute.
5. Contract executes payout, refund, fee, and optional slash.
6. Reputation projections update from the finalized outcome.

## 12. Colossus-X and mining architecture

### 12.1 Canonical behavior

The following code evidence is pinned to tracked commit
`7ae80156b23b20f804557eedc921bf431dc3a536` reviewed on 2026-08-10, with no
tracked working-tree modification at review time. The current codebase
establishes the reference shape but is not yet a complete GPU product:

- `miner/miner.go` registers only the CPU agent;
- `consensus/colossusX/sealer.go` searches with CPU goroutines;
- `consensus/colossusX/consensus.go` verifies through `colossusXlight`;
- `core/types/keyblock.go` contains nonce and mix digest but no DAG root/proof;
- `consensus/colossusX/algorithm.go` uses 128 accesses and folds a local sampled
  root into the digest, not a canonical full-DAG commitment;
- the effective early-epoch cache table begins near 16 MiB although a 512 MiB
  constant exists;
- no CUDA, HIP/ROCm, or OpenCL mining backend is present; and
- no algorithm golden-vector/differential test suite is present under
  `consensus/colossusX`.

The current miner can generate a full dataset, but its full/light self-check can
fall back to light mining; that behavior is prohibited for the target production
miner. The repository proposal for a full-DAG Merkle protocol is
`consensus/modifications.md`, not the attached strategy report, and is not the
implemented algorithm.

Baseline `CPH-AIIE-0.2` does not silently resolve these consensus discrepancies.
Before a public GPU backend, a normative algorithm version and golden vectors
MUST pin:

- chain/fork identity and activation height;
- epoch derivation and seed;
- cache and dataset size calculation;
- cache generation and DAG cell generation;
- access count, sample selection, and all hash functions;
- integer widths, overflow, byte order, and nonce order;
- header/work-template hashing;
- mix digest and final result;
- target boundary and expected difficulty;
- candidate time, parent, height, and ordering rules.

For every canonical template and nonce, CPU full, CPU light and every certified
GPU backend produce the same digest and result bit for bit. A mismatch rejects
the result, quarantines the backend/device as configured, and raises an alert;
production code does not switch hashing paths and continue.

Mining is optional to chain liveness. Zero miners, pool outage, DAG failure,
candidate-ingress failure, or an empty mining round produces no mining payout
for that round but MUST NOT stop transaction proposals or FHS finality. Failure
of a newly activated algorithm never causes automatic consensus fallback to an
older algorithm at the same height.

The report calls PoW a “network security incentive.” In this fixed-committee
baseline, PoW supplies a bounded issuance/reward incentive and candidate input;
it does not add a defined FHS safety, committee-admission, leader-selection,
quorum or liveness property. No product claim may say PoW secures fixed-committee
finality unless a future threat model, protocol change and evidence define that
property through a new baseline.

### 12.2 DAG lifecycle

The miner manages current and next epoch datasets:

```text
ABSENT -> GENERATING -> VERIFYING -> ON_DISK -> LOADING -> RESIDENT
       -> DRAINING -> EVICTED
                     \-> CORRUPT -> QUARANTINED
```

Requirements:

- generation is cancellable and resumable only from authenticated checkpoints;
- files include algorithm version, epoch, seed, size, checksum, and atomic-ready
  marker;
- GPU upload is checksummed and followed by backend self-test;
- next-epoch preparation must respect owner storage, memory, and power policy;
- device-local residence is reported, not assumed;
- page-mapped host data is not described as physically resident unless locked;
- AI recall may evict the DAG, and reload cost is included in optimization;
- multi-GPU devices never share mutable DAG buffers unsafely.

A certified reference/production miner MUST use the full epoch DAG in its normal
mining mode. Cache-only CPU or GPU paths are allowed only as labeled conformance,
debug and validator modes. Because the network has no full-DAG residency proof,
a consensus-valid cache-only result remains valid; certification and pool policy,
not validators, enforce the production-miner profile. Full-DAG performance and
memory-hard advantage remain empirical gates rather than protocol assumptions.

### 12.3 Conformance and performance

Correctness gates precede performance work. Every backend runs the same vectors
for seed, cache samples, DAG cells, nonce traversal, digest, result, and boundary
target. Differential tests compare CPU full, CPU light, HIP, and CUDA.

Performance reporting includes:

- DAG generation, disk persistence, host load, and device upload time;
- steady-state hash/s and hash/W at declared clocks and power caps;
- device and host memory footprint;
- ECC, thermal, throttle, and invalid-result counts;
- full-DAG versus cache-only performance ratio;
- start, drain, kill, reset, and AI-ready latency distributions;
- 72-hour minimum soak before pilot promotion.

Marketing MUST NOT use “GPU-exclusive,” “ASIC-proof,” or guaranteed memory
residency without independent evidence and an approved claim review.

### 12.4 Difficulty and candidate safety gates

The public pool is blocked until the active fork validates expected difficulty,
parent, height, chain, time window, target, and template expiry on every ingress
path. A validator validates only the zero or one candidate included in a proposal;
agreement on an uncommitted network-wide or local “best candidate” set is never a
block-validity condition. An absent candidate is valid. A leader/pool MAY use a
versioned deterministic selection policy over candidates it observed, using
solution hash/work and a canonical tie-break rather than raw numeric nonce, but
different observation sets cannot make two otherwise valid proposals invalid.

Each canonical round has at most one `reward_slot_id` and zero or one `reward_id`
with the exact domain and fields in §8.6. The active reward rule fixes amount,
supply/emission bounds and whether an absent candidate yields zero reward. Reward
progresses through OBSERVED, FINALIZED only after direct-child-QC proof for the
body-committing carrier transaction block, MATURED after its rule-defined delay
and ALLOCATED. Duplicate
transport submissions, pool retry, validator restart, block replay, or service
reconciliation cannot produce a second reward or pool payout. Committee
membership, leader selection, quorum threshold and QC validity are unaffected
by the presence or value of a PoW candidate.

`TBD-EXPERIMENT-POW-01`: select and simulate the future difficulty adjustment
and candidate ordering under rapid fleet entry/exit. The simulation must cover
timestamp manipulation, oscillation, concentrated hashrate, long idle periods,
and fixed-committee operation. Before Gate A, its ADR MUST fix target solution
probability/interval, permitted timestamp source/window, difficulty floor/ceiling,
maximum per-adjustment change, shock recovery bound, zero-miner behavior and an
issuance cap independent of reported hashrate. Tests cover at least 0%, 50%, 90%,
10x and 100x instantaneous fleet loss/gain plus adversarial timestamp sequences.
The chosen formula requires its own ADR and fork; no current formula is promoted
by this architecture.

## 13. GPU resource pool and scheduling

### 13.1 Capacity semantics

A provider advertises an offer, not a guarantee. An offer names:

- capability-snapshot digest and schedulable partition;
- earliest start, maximum duration, renewal and notice policy;
- supported workload and verification classes;
- region, data, egress, image, and confidentiality constraints;
- price floor, currency preference, and energy constraints;
- preemption/checkpoint class;
- attestation and isolation level;
- offer expiry and provider signature.

A reservation is temporary and non-billable unless its quote says otherwise. A
lease is binding only after provider admission, buyer acceptance, and required
escrow state. Heartbeat expiry prevents new reservations and triggers controlled
reconciliation; it does not automatically declare an active workload dead.

### 13.2 Scheduler adapters

Adapters MUST map native scheduler concepts into the canonical release/recall
contract without pretending all schedulers behave alike. At minimum:

- Kubernetes: node/device plugin allocation, taints, priorities, disruption and
  pod termination readiness;
- Slurm: allocation, drain, reservation, prolog/epilog, and job ownership;
- Ray: logical resource ownership and actor/job lifecycle;
- standalone: explicit operator policy with exclusive process/device locking.

MIG or other partitions are offered only after isolation, accounting, and reset
behavior are proven for the hardware/runtime combination. The first hardware
conformance class MAY require whole-GPU allocation.

### 13.3 Optimizer policy

The optimizer evaluates owner value as a constraint or provider-provided shadow
price; it does not infer or inspect confidential business revenue. It computes
separate conservative values for eligible market jobs and mining.

```text
MiningNet = expected_CPH * conservative_CPH_price
          - electricity - demand_charge - cooling
          - pool_and_chain_fees - operations - wear_allowance
          - amortized_switch_and_reload_cost - risk_margin

MarketNet = eligible_new_job_expected_revenue
          - electricity - cooling - platform_and_verification_fees
          - artifact_and_network_cost - expected_retry_and_penalty
          - operations - wear_allowance - risk_margin
```

Hysteresis, minimum run time, cooldown, and maximum switch frequency prevent
flapping. A positive estimate does not override a recall or safety constraint.

## 14. AI workload market

### 14.1 Workload classes

The architecture supports a growing catalog while preserving class-specific
verification and scheduling:

1. deterministic or buyer-verifiable batch inference;
2. conventional batch inference with acceptance sampling;
3. data processing and embedding generation;
4. checkpointable fine-tuning;
5. distributed training;
6. latency-sensitive inference;
7. confidential or regulated workloads.

Release order is defined in the roadmap. A class is not enabled merely because
the runner can launch its container; billing, failure, verification, privacy,
and dispute semantics must also be approved.

### 14.2 Job specification

A JobSpec includes:

- immutable ID, owner, schema and workload-class versions;
- signed image/runtime, model, input and expected output declarations;
- GPU, memory, interconnect, CPU, RAM, disk, and network requirements;
- precision, batch, latency, duration, checkpoint, and retry policy;
- region, residency, confidentiality, retention, and egress policy;
- verification and acceptance method;
- maximum price and settlement asset preferences;
- timeout, cancellation, refund, penalty, and dispute terms.

No executable field is accepted without canonical encoding, digest validation,
authorization, and policy evaluation.

### 14.3 Result verification tiers

| Tier | Mechanism | Suitable use |
|---|---|---|
| V0 | Buyer acceptance | Trusted/private pilots |
| V1 | Deterministic replay or known-answer checks | Deterministic batch work |
| V2 | Redundant execution and sampling | Higher-value verifiable tasks |
| V3 | Hardware/runtime attestation plus evidence | Enterprise assurance |
| V4 | Specialized cryptographic proof | Future supported workloads only |

The marketplace exposes the tier in every quote and receipt. It never labels V0
through V3 as general Proof-of-Useful-Work.

## 15. Compute measurement and Compute Unit

### 15.1 Measurement layers

1. **Raw observation** — signed device/runtime counters and timestamps.
2. **Validated measurement** — reconciled observations with anomalies and
   confidence.
3. **Compute Unit derivation** — versioned transformation for a workload class.
4. **Commercial rating** — quote-specific price and SLA application.
5. **Settlement** — integer asset allocation under accepted terms.

These layers MUST remain separately reproducible.

### 15.2 `CU-v1` shape

`CU-v1` is a family of workload-class records, not one cross-workload scalar.
It includes:

- accelerator allocation and active seconds;
- GPU model, VRAM capacity/class, certified memory-bandwidth factor and validated
  partition;
- precision and workload-class ID;
- benchmark suite/version and performance factor;
- runtime/image/model digests;
- delivered work count where meaningful;
- energy and throttle observations;
- verification tier and evidence confidence.

Raw/validated measurement also links observed latency distribution and the
accepted SLA/region context. Memory-bandwidth factors may enter the physical CU
formula only where the workload-class calibration proves relevance. Latency and
SLA remain linked, immutable commercial context used for acceptance/rating, not
silent multipliers in physical work. This preserves every report factor while
separating measurement, derivation and price.

Each class also declares reference hardware, calibration period, statistical
confidence/error band, minimum sample quality, supported conversion domain and
deprecation date. A new benchmark or factor creates a new CU version. Quotes
MUST NOT compare two workload classes as equivalent unless the published
calibration explicitly supports that comparison.

Latency, availability, region, urgency, confidentiality, and provider margin are
commercial quote dimensions. They do not retroactively change physical work.

CU derivation uses integer fixed-point or rational arithmetic with declared
scale, rounding direction, overflow bounds and missing-data behavior. Every
version publishes cross-language recomputation vectors and rejects a receipt
rather than using an unspecified fallback factor.

`TBD-EXPERIMENT-CU-01`: benchmark tables and error tolerances are established on
the target hardware matrix before paid public use. Cross-provider measurement
disagreement must be within the release gate in the roadmap.

## 16. On-chain contracts

The target contract suite is modular:

| Contract | Responsibility |
|---|---|
| ProviderRegistry | Provider commitment, payout address, stake and status |
| ComputeEscrow | Buyer funding and lease-terms commitment |
| ComputeSettlement | Receipt commitment, payout and refund finalization |
| DisputeResolution | Disputed amount lock and resolution execution |
| PoolPayout | Optional aggregate mining payout claims |
| ProtocolGovernance | Parameter roles, upgrade delay, pause and emergency scope |
| ConsensusUpgradeRegistry | Ordered, threshold-authorized manifest/cancellation/readiness records for §22.1 |

Contract requirements:

- least-privilege roles and separation of pause, upgrade, treasury and dispute;
- replay-safe domain-separated signatures including chain ID and contract;
- pull-based payout where appropriate to limit reentrancy and batch failure;
- bounded loops and storage growth;
- explicit decimals, rounding and dust policy;
- idempotent settlement keyed by the canonical lease/receipt/settlement identity
  with at-most-one economic effect and correction entries;
- event completeness for independent accounting;
- timeout paths that cannot lock funds indefinitely;
- upgrade delay and public implementation/version visibility;
- invariant, fuzz, static, differential and external audit before public funds.

Before contract implementation, Gate G requires a Cypher EVM execution profile
that pins supported fork/opcodes, Solidity compiler and ABI, transaction/receipt
semantics, gas limits/estimates, event ordering, reorg behavior and the exact FHS
finality point used by the indexer. Common contract/RPC/event vectors MUST pass on
every supported node implementation.

The `ReceiptPolicy` names who may commit a receipt and the required signature
threshold. `DisputePolicy` names resolver set/quorum, conflict exclusions,
appeal/timeout rules, provider-stake withdrawal hold, verifier-outage and partial
refund behavior. No generic admin key may invent a receipt or seize an
undisputed amount. Reservation holds expire automatically; a funded-but-unadmitted
lease has a deterministic refund deadline and names the gas/fee bearer.
`LockOrRefundSagaID = H(quote_id, lease_id, amount, asset, resource_generation)`
has one contract state slot and may reach exactly one of LOCKED or REFUND_PENDING;
retries cannot choose the other branch. Lease ACTIVE and Attempt RUNNING require
the FHS-final LOCKED branch, while hold expiry/rejection makes only refund legal.

The first pilot MAY reconcile receipts off chain and execute a simpler escrow,
but it must use the same canonical IDs and evidence linkage as the target suite.

### 16.1 Treasury and accounting separation

The financial model maintains separate ledgers and statements for:

- owner-AI revenue or provider-supplied shadow value;
- protocol mining issuance and canonical mining rewards;
- pool share liabilities, fees and payouts;
- external buyer compute-service GMV;
- provider service revenue and platform/verifier fees;
- CPH inventory, conversion, slippage and realized/unrealized gains/losses;
- buyer refund and disputed liabilities;
- treasury subsidy, incentive and operating expense.
- GPU acquisition, commissioning, depreciation, impairment, disposal and
  realized/model residual value.

Financial Ledger and Asset Analytics joins these classifications only in a
versioned per-device/cohort report. It preserves accounting currency/FX basis,
scenario horizon, discount rate, uncertainty and formula digest so payback delta
is reproducible. Missing owner revenue or residual observations remain unknown;
mining issuance is never reclassified as external paid demand.

Buyer CPH acquisition, provider conversion, hedging, liquidity reserves, tax and
accounting treatment are `TBD-COMMERCIAL`/`TBD-POLICY` decisions. The system may
facilitate a conversion flow only after responsibility for volatility,
counterparty, custody, slippage and compliance is explicit.

## 17. Security and privacy architecture

### 17.1 Key separation

| Key | Holder | Purpose |
|---|---|---|
| Validator BLS | Remote signer/HSM for committee node | Consensus only |
| Chain treasury/governance | Multisig/HSM | Contract administration |
| Provider organization | Provider KMS | Enrollment and policy |
| Agent instance | IAM-issued service credential | Control sessions and local transition signing; never acts as a CA |
| Host | TPM/KMS or protected keystore | Host enrollment and measured-boot binding |
| Device attestation | Vendor/TPM-backed identity where available | Capability and device evidence only |
| Miner | Mining identity keystore | Work/share/result signing |
| Runner attempt | Short-lived workload identity | Artifact and service access |
| Buyer organization | Buyer KMS/wallet | Job, quote and acceptance |
| Marketplace/service | Service KMS | Quotes and orchestration records |

Secrets MUST NOT be transported as command arguments, RPC password strings, or
logs. Rotation, revocation, recovery, and audit procedures are release gates.

Bindings among Provider, Agent, Host, Device, Miner and payout identity are
separately signed and effective-dated. Revocation maximum propagation and
offline-credential lifetime are fixed per credential class before its pilot;
ownership transfer always rotates organization and workload authority.

### 17.2 Threats and mandatory controls

| Threat | Mandatory controls |
|---|---|
| Malicious workload escapes sandbox | Strong isolation, least privilege, syscall/device policy, patching, egress limits |
| Cross-tenant model/data leakage | Envelope encryption, scoped keys, memory/storage sanitation, retention enforcement |
| Forged capabilities or measurements | Device identity, attestation where available, cross-observation, anomaly detection |
| Fake mining shares/results | Signed template, expected target, replay protection, independent PoW verification |
| Candidate-verification DoS | Cheap checks first, quotas, bounded workers, deduplication, timeouts |
| Sybil providers/root builders | Stake/identity/reputation and demand-side limits; no identity-count majority |
| Oracle manipulation | Multiple sources, confidence/TTL, circuit breaker, accepted-quote immutability |
| Control-plane compromise | Least privilege, dual control, scoped services, immutable audit, blast-radius isolation |
| Artifact supply-chain attack | Signed images, SBOM/provenance, digest pinning, scanning and policy |
| Contract theft or lockup | Formal invariants, audits, bounded admin, pause, timelock, reconciliation |
| Lease replay/split brain | Generation fencing, expiry, idempotency and single-writer agent ownership |
| Result fraud | Verification tiers, redundant sampling, buyer acceptance and disputes |
| Denial of AI recall | Local owner authority, staged kill/reset, watchdog and readiness proof |

### 17.3 Privacy and compliance

Before enterprise release, the operator must define controller/processor roles,
data-processing terms, retention, deletion, incident notification, audit access,
data residency, export controls, sanctions, tax, KYC/AML applicability, and
acceptable-workload policy. These are `TBD-POLICY` inputs owned jointly by legal,
security, finance, and product; code cannot decide them implicitly.

The data-classification matrix covers public metadata, tenant metadata,
customer-confidential artifacts, credentials, billing evidence and security
evidence. For every class it names canonical store, encryption owner, allowed
regions/replicas, site caches, logs/traces, backup policy, retention owner,
deletion method and legal-hold precedence. High-sensitivity values are never
copied into telemetry labels or general audit text.

## 18. Reliability and failure policy

| Failure | Required behavior |
|---|---|
| Marketplace unavailable | No new leases; active signed leases continue under local policy |
| Resource pool unavailable | Agent preserves current ownership; no speculative reassignment |
| Price/oracle stale | No new quote or mining start; accepted terms remain unchanged |
| Chain unavailable | No unbounded new obligations; prefunded jobs follow lease; receipts queue idempotently |
| Pool unavailable | Miner drains or retries bounded endpoints; owner recall remains local |
| Agent restart | Reconcile processes/device before READY; stop unknown miner first |
| Runner crash | Apply retry/checkpoint policy; record attempt; never fabricate completion |
| Artifact failure | Do not start without verified inputs; preserve or delete partial output by policy |
| GPU ECC/thermal fault | Stop, quarantine, preserve health evidence, notify scheduler |
| Network partition | Lease generation and expiry fence ownership; fail closed on new work |
| Validator quorum loss | Compute may finish under lease; settlement waits; no claim of final payment |
| Contract pause | Stop new funded leases; preserve evidence and provide bounded refund path |

Financial workflows use transactional outbox/inbox patterns or equivalent so a
database commit and event publication cannot create double payment or lost
settlement. Every recovery procedure is exercised in chaos and restore tests.
Message/event delivery is at-least-once; handlers are idempotent; each ledger
operation has a unique economic identity; payment effects are at-most-once; and
reconciliation eventually completes or raises a durable operator exception.

## 19. Observability and accounting

All services emit metrics, structured logs, traces, and immutable audit events.
Correlation IDs such as provider, device, lease, job, attempt, receipt, work and
settlement belong in access-controlled traces/logs and audit records; they MUST
NOT become unbounded Prometheus-style labels. Metrics use a reviewed bounded
label allowlist such as service, region, hardware class, workload class and
outcome.

Required metric families:

- chain: head/finality lag, view/leader changes, committee health, reorg and
  settlement finality;
- mining: work age, hash/s, hash/W, accepted/invalid/stale shares, candidate and
  reward outcomes, DAG state and load time;
- GPU: allocation, utilization, memory, temperature, power, ECC, throttle,
  reset and health;
- scheduling: state duration, decision reason, recall, drain, reset, readiness,
  flap and policy rejection;
- market: quote, match, reservation, admission, job success/retry/cancel,
  acceptance and dispute;
- measurement: observation gaps, signer disagreement, CU variance and receipt
  correction;
- settlement: escrow, submitted/finalized payout, refund, reconciliation lag,
  duplicate prevention and outstanding liability;
- economics: mining subsidy, paid-compute GMV, realized provider revenue,
  electricity/cooling/fees, net margin, idle-hours recovered and payback delta.

Dashboards MUST show mining issuance separately from external buyer revenue.
SLOs have error budgets, alerts, runbooks, owners, and post-incident review.
Telemetry applies tenant authorization, region/retention policy and redaction of
PII, secrets, artifact names, model names and financial credentials. Access to
audit evidence is itself audited. A release gate fixes sample size, observation
window, confidence interval and numerical p95/p99/RTO/RPO/error-budget targets
before that pilot collects promotion evidence; post-hoc thresholds are invalid.

## 20. Deployment topology

### 20.1 Provider site

- one or more provider agents with fenced leadership;
- scheduler and device adapters;
- local miner and runner processes;
- optional artifact cache;
- outbound-first control connectivity where possible;
- site-local emergency recall independent of WAN and chain availability.

### 20.2 Regional control plane

- stateless API and orchestration replicas across fault domains;
- strongly consistent authoritative lease/financial database;
- durable event bus and transactional outbox;
- regional artifact storage and key service;
- matcher, inventory, metering, pricing, settlement and audit services;
- per-region data boundaries with explicit cross-region replication policy.

Device, Lease, Job, Receipt and financial records have a declared home region
and writer epoch. Cross-region transfer is a fenced state transition, not active-
active last-write-wins. The regional design documents quorum placement,
promotion authority, stale-region isolation and entity-specific RTO/RPO before
production; financial RPO remains zero as required in §8.1.

### 20.3 Chain plane

- validators distributed across independent operator, host, network, region and
  power fault domains;
- public RPC separated from validator administration;
- remote signing and protected consensus keys;
- archive/indexing and settlement reconciliation outside validator hot paths.

No production topology may treat several processes on one host as independent
fault domains. For a seven-member committee with a five-vote threshold, no
single operator, host, credential, region, network/ASN, power, or administrative
failure domain may control or disable three committee identities.

The reviewed `genesis.json` currently lists seven committee members on one
network endpoint. Physical co-location was not proven, but the endpoint itself
is a confirmed common failure domain and fails the target topology requirement.
It is a deployment blocker, not evidence that the target requirement is met.

## 21. Technology and repository boundaries

The architecture fixes interfaces, not every vendor. Recommended boundaries are:

```text
cypher/                         existing chain and contracts integration
cph-gpu-miner/                 native CPU/HIP/CUDA executable
cph-compute-agent/             provider-local policy and orchestration agent
cph-compute-control-plane/     inventory, market, lease, metering, settlement
cph-ai-runner/                 isolated workload runtime adapters
cph-asset-analytics/           classified financial ledger and cohort economics
cph-sdk/                       buyer/provider APIs and generated clients
```

They may begin in one workspace for coordinated development but MUST build,
release, version, and fail independently. Vendor GPU toolchains MUST NOT become
dependencies of the validator binary. Shared schemas are generated from one
versioned source and compatibility-tested.

The existing repository's `docs/ai-infrastructure` directory remains the
architecture source even if implementations move to separate repositories.

The reference implementation profile is fixed by ADR-0008: standalone C++20
CPU/HIP/CUDA miner; Go agent/control/market/indexer services; Solidity contracts;
Protobuf/gRPC; PostgreSQL authoritative state; Kafka-compatible durable events;
S3-compatible encrypted artifacts; WORM receipt evidence; OCI workloads; and
OpenTelemetry/Prometheus observability. A substitution requires an ADR and a
tested migration path rather than an implementation-local choice.

## 22. Compatibility and migration

### 22.1 Consensus changes

Every consensus-visible change has:

- named algorithm/fork version resolved from canonical Upgrade Registry state;
- activation height or epoch;
- old-history verification retained indefinitely;
- new and old golden vectors;
- testnet rehearsal and rollback/abort conditions before activation;
- binary minimum-version and operator-readiness plan;
- independent security and economic review.

Changing an `algorithmRevision` used only in a filename is not sufficient.

The existing FHS chain commits its chain configuration through genesis-related
state, so adding a field and rewriting stored configuration is prohibited. The
one-time bootstrap is a dormant client feature compiled against this exact
network tuple:

```text
BOOTSTRAP-UM-V1 = chain_id, genesis_hash, bootstrap_key_height,
                  upgrade_registry_address, registry_runtime_code_hash,
                  registry_init_carrier_number,
                  registry_init_carrier_hash, registry_init_state_root,
                  registry_init_child_qc_digest,
                  initial_upgrade_authority_set_hash,
                  initial_authority_threshold, minimum_lead_rule
```

Gate A fixes and publishes that tuple before any binary containing it is called
release-ready. At `bootstrap_key_height`, clients enable reads of the registry at
the fixed address/code hash; the bootstrap does not change Colossus-X behavior
and never rewrites stored genesis configuration. A mismatched chain, code hash or
registry state fails the new upgrade path without changing historical rules.
The registry deployment and initialization transaction MUST itself be FHS-final
at least 14 days before the bootstrap height, and clients test its initial state
before readiness. Registry replacement or code change is itself an Upgrade
Manifest field authorized under the old registry; clients retain old registries
for historical resolution.

Thereafter, the sole source for future consensus activation is an Upgrade
Manifest accepted by that registry and finalized by FHS. The initial production
reference uses five-of-seven dedicated protocol-governance keys. Those keys may
be controlled by committee organizations but MUST NOT reuse validator BLS key
material. Governance threshold signatures authorize the record; the FHS QC only
orders/finalizes it and is not additional governance authorization.

Governance signs only `ManifestPayloadV1`. It contains no self hash and no
finalization data that is unknowable at signing time:

```text
chain_id and genesis_hash
manifest_sequence and previous_terminal_record_hash
registry address and runtime code hash
old and new consensus algorithm versions
activation key height and epoch mapping
cache/DAG/seed/hash/difficulty/reward parameter versions
normative specification digest
golden-vector set digest
minimum validator and miner protocol versions
minimum lead rule, arm deadline and readiness policy
authority_set_version/hash and optional next authority/registry tuple
```

```text
manifest_id = H("CPH-UPGRADE-MANIFEST-V1", CCSE(ManifestPayloadV1))

ManifestFinalizationRecord = manifest_id,
  carrier_transaction_block_number, carrier_transaction_block_hash,
  carrier_state_root, direct_child_qc_digest

SIGNED -> FINALIZED_PENDING -> ARMED -> ACTIVATED
                           \-> CANCELED
                           \-> EXPIRED
```

Only `last_terminal_sequence + 1` and the exact previous terminal record hash are
admissible; only one record may be pending. Competing/replayed records are
rejected. A threshold cancellation names `manifest_id` and is terminal. Normal
activation requires FINALIZED_PENDING at least `max(two complete algorithm
epochs, 14 days)` before activation. Each of seven current committee members then
signs readiness bound to manifest, binary, vectors and artifacts. The ARMED
record contains all seven attestations and MUST itself be carried and FHS-final
at least 24 hours before activation. FHS finality metadata is appended in the
separate record above and is never part of the signed payload or its own hash.

If a manifest is not ARMED by its payload's arm deadline, resolution changes it
deterministically to EXPIRED: the old algorithm remains valid at and after the
proposed activation height, the pending slot is released, and the next sequence
references `H("CPH-UPGRADE-EXPIRED-V1", manifest_id, activation_key_height)`.
CANCELED references
`H("CPH-UPGRADE-CANCELED-V1", manifest_id, cancellation_id,
cancellation_final_carrier_hash)`; ACTIVATED references
`H("CPH-UPGRADE-ACTIVATED-V1", manifest_id, activation_key_height,
RegistryAnchor(activation_key_height).Hash)`. These exact hashes, not a status
label, are the next payload's `previous_terminal_record_hash`.
There is no automatic algorithm fallback because the new rule never activated.

For key height `H`, registry resolution has one dual-chain anchor:

```text
Kp = canonical key block K(H-1)
C.Number = Kp.T_Number + 1
DecodeCanonical(C.KeyInfo) = Kp
VerifyFHS2ChainCommitProof(C, direct_child_qc) = success

RegistryAnchor(H) = (C.Number, C.Hash, C.Root)
ActiveRules(H) = ResolveUpgradeRegistry(state_at=C.Root, key_height=H)
```

`C` is the FHS-final transaction block carrying the complete parent KeyBlock.
No newer transaction head, RPC response, mutable file or local configuration may
affect `ActiveRules(H)`. Bootstrap fixes the initialization carrier's number,
hash, state root and child-QC digest in `BOOTSTRAP-UM-V1`. Historical sync
verifies every anchor, registry code hash, signature, sequence/predecessor,
readiness, terminal transition and direct-child QC. An emergency change still
uses a new explicit manifest; this baseline defines no silent or same-height
fallback.

The migration sequence is:

1. freeze and vectorize historical behavior;
2. independently audit and testnet-rehearse `BOOTSTRAP-UM-V1` and registry;
3. deploy and FHS-finalize the initialized registry; pin its carrier anchor;
4. deploy bootstrap-capable binaries to every committee member and verify the
   compiled tuple without changing active consensus;
5. deploy dormant old/new dual-verifier binaries;
6. rehearse historical sync, expiration, activation and cancellation on testnet;
7. sign/submit the payload and FHS-finalize FINALIZED_PENDING before its lead
   deadline;
8. distribute the work protocol/backends and collect all seven readiness
   attestations;
9. FHS-finalize ARMED at least 24 hours before activation;
10. pre-generate activation-epoch artifacts; and
11. accept exactly the new algorithm from the activation height onward.

Old and new consensus algorithms are never both valid at the same height. An
abort is allowed before activation; an after-activation reversal is another
explicit fork. Operational readiness MUST be confirmed for every fixed committee
member under the normal activation policy even when the protocol quorum is
smaller.

Cache and DAG artifact keys include chain/genesis, consensus algorithm version,
epoch, full seed, expected size, endian, artifact-format revision and checksum.
A loader validates exact file size, metadata, checksum and atomic-ready marker;
checking only a magic prefix is insufficient.

### 22.2 Service changes

- wire schemas use additive compatibility where possible;
- breaking fields require a new protocol major version;
- consumers tolerate unknown optional fields but reject unknown critical
  semantics;
- database migrations are expand/migrate/contract with tested rollback;
- receipt and Compute Unit versions remain verifiable forever;
- contract upgrades preserve events and settlement reconciliation.

### 22.3 KCP-to-QUIC evolution

Local conformance work may use a KCP adapter only in a gateway process outside
the validator lifecycle. KCP bind, listener, queue or adapter failure MUST fail
open for validator startup and FHS transaction finality and fail closed only for
new mining work. The adapter is firewalled, rate/budget bounded and never shares
a public socket with committee traffic.

Before a public pool, the result path moves to authenticated encrypted QUIC with
bounded handshake, connection, stream, source, tenant, memory and PoW-verification
work. Public miner QUIC uses a separate process, listener, port, ALPN, trust root,
certificate policy, key set and resource budget from authenticated committee/FHS
QUIC. Adding miner streams to the FHS listener is prohibited. The domain message
does not change solely because the transport changes.

## 23. Verification strategy

| Layer | Required verification |
|---|---|
| Colossus-X | Golden vectors, differential backends, boundary targets, fuzz/property, historical blocks |
| GPU runtime | Hardware matrix, soak, fault injection, cancellation, power/thermal and reset tests |
| State machine | Model-based transition tests, stale generation, crash/restart and partition tests |
| Canonical signing | Go/C++/Solidity golden/negative vectors, rotation, audience and replay tests |
| Pool | Share/target math, duplicate/replay, payout reconciliation, adversarial load |
| Marketplace | Contract/state invariants, idempotency, expiry, retry and compensation tests |
| Runner | Escape, egress, secret, artifact, memory sanitation and multi-tenant tests |
| Metering/CU | Clock faults, missing counters, signer disagreement, reproducibility and variance |
| Contracts | Unit, invariant, fuzz, static analysis, testnet rehearsal and external audit |
| End to end | Quote-to-settlement and mining-to-payout with injected failures |
| Economics | Price/power/difficulty sensitivity, fleet churn, fees, wear and liquidity stress |
| Asset analytics | Per-device/cohort ledger replay, depreciation/residual scenarios and uncertainty audit |
| Operations | Backup/restore, key rotation, region loss, quorum loss and incident drills |

No performance benchmark is accepted without hardware, driver, firmware,
runtime, clock, power cap, ambient/thermal condition, workload version, sample
duration, and raw result provenance.

## 24. Release gates

The implementation roadmap owns the detailed gates. The non-negotiable system
gates are:

1. **Architecture gate** — this baseline, traceability, ADRs, review and
   `baseline-manifest.json` hash verification accepted.
2. **Platform/security foundation gate** — canonical schemas/signatures, IAM,
   supply-chain provenance, policy registry, audit and telemetry foundations.
3. **Consensus gate** — canonical algorithm version and candidate safety fixed.
4. **GPU correctness gate** — CPU full/light and each backend being promoted
   match exactly; HIP/AMD and CUDA/NVIDIA promotion gates are independent.
5. **Hardware economics gate** — measured full-DAG advantage and positive
   conservative scenarios on target hardware.
6. **Preemption gate** — owner AI readiness and failure escalation meet the
   provider's declared SLO without AI regression.
7. **Private-pool gate** — authenticated accounting and reward reconciliation.
8. **Market-integrity gate** — measurement, acceptance, escrow and refund close
   end to end without unreconciled value.
9. **Enterprise gate** — isolation, privacy, keys, compliance, HA and external
   audits meet policy.

Failing a gate stops promotion; it does not silently weaken the target design.

## 25. Open decision and experiment register

| ID | Question | Resolution owner/gate |
|---|---|---|
| TBD-EXPERIMENT-POW-01 | Difficulty and objective candidate ordering under fleet churn | Consensus gate |
| TBD-EXPERIMENT-GPU-01 | AMD Max 395 backend feasibility and full/light advantage | GPU economics gate |
| TBD-EXPERIMENT-GPU-02 | H200/B300 DAG residency, power curve and reload latency | Hardware expansion gate |
| TBD-EXPERIMENT-SCHED-01 | Owner recall p95/p99 and model readiness budget | Preemption gate |
| TBD-EXPERIMENT-CU-01 | Workload benchmark factors and cross-provider variance | Market-integrity gate |
| TBD-EXPERIMENT-VERIFY-01 | Verification method per initial AI workload | Market design gate |
| TBD-EXPERIMENT-ASSET-01 | Depreciation, residual-value, horizon and uncertainty model per accounting jurisdiction | Hardware economics gate |
| TBD-COMMERCIAL-01 | Pool fee, payout threshold and treasury allocation | Private-pool gate |
| TBD-COMMERCIAL-02 | Initial buyer segment and paid workload class | Market launch gate |
| TBD-COMMERCIAL-03 | Quote denomination and CPH volatility allocation | Market-integrity gate |
| TBD-POLICY-01 | Provider stake, reputation and slashing | Public market gate |
| TBD-POLICY-02 | Data retention, residency, KYC/AML, tax and export control | Enterprise gate |
| TBD-SLO-01 | Production availability, RTO/RPO and regional objectives | Enterprise gate |
| TBD-SLO-02 | Numeric lease, recall, receipt, share, quote, settlement and recovery thresholds plus sampling plan | Relevant pilot gate before evidence collection |

Each item must be resolved by measured evidence and a new ADR or approved policy
before its gate. None blocks architecture approval because the decision method,
owner boundary, and dependent release are defined.

## 26. Definition of architecture completion

Baseline `CPH-AIIE-0.2` is considered architecturally complete because:

- every material strategy-report requirement maps to a component and gate;
- component ownership and negative boundaries are explicit;
- the resource, market, mining, measurement and financial state models connect
  end to end;
- trust zones, identities, failure behavior and data placement are explicit;
- current implementation is not confused with target capability;
- unknown empirical and commercial values have named resolution gates;
- staged implementation does not require replacing the end-state interfaces;
- change control prevents silent divergence.

Architecture completion is not a claim of product implementation, commercial
validation, security certification, or profitability. Those claims require the
release evidence defined here and in the roadmap.
