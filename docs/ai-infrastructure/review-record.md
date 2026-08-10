# Architecture Review Record

- Baseline reviewed: `CPH-AIIE-0.2`
- Final review date: 2026-08-10
- Decision: **APPROVED AS DESIGN BASELINE**
- Runtime implementation approval: **NOT GRANTED BY THIS REVIEW**
- Reviewed runtime-code commit: `7ae80156b23b20f804557eedc921bf431dc3a536`

## 1. Review method and identity

The primary architecture synthesis was reviewed through three independent
evidence tracks, each reading the actual documents rather than a summary:

1. strategy/report traceability, assumptions, caveats and public claims;
2. consensus, Fair HotStuff, Colossus-X, candidate/reward and network transport;
3. GPU/provider execution, market, settlement, security, data and operations.

The initial candidate was deliberately rejected. Its stable review hashes were
`c2bf3e67a2bb9297f78cd7a8873fe30a26f844f0e171336283a1bf37d9bc601e`
for Master Architecture and
`3f122b5b5ac120a6a8f00e9e2c6bcd63c348347ff608b81f1a1d06d067bb317b`
for Requirements Traceability. Findings below were applied to create 0.2 and the
actual frozen 0.2 file hashes are recorded in `baseline-manifest.json`; the
manifest excludes itself to avoid a recursive hash.

The reviewed strategy is 474 lines with SHA-256
`91bf6a6c9e1246f8a9a4dd06c7baf0555019cf976894e6f1fdd6816ec1abe120`.
The latest attachment and repository reference copy are byte-identical.

Reviewer roles are recorded here rather than presented as cryptographic or legal
signatures. Future organizational approval MUST name human approvers and sign the
manifest or a release EvidenceRecord.

## 2. Review scope and result

| Track | Scope | Design result | Runtime implication |
|---|---|---|---|
| Strategy/claims | Goals, equations, assumptions, caveats, provenance | Pass after full trace/evidence and Asset Analytics additions | Economic outcomes remain unvalidated |
| Consensus/network | Fixed committee, light validation, upgrade, candidate, reward, DoS, KCP/QUIC | Pass after deterministic manifest, proposal-local candidate and transport isolation decisions | Gate A/D blockers remain |
| GPU/execution | Miner/DAG, device/lease states, preemption, isolation, gang allocation | Pass after full-DAG scope and orthogonal state-machine additions | Hardware and preemption gates remain |
| Market/finance | Quote, hold/fund, CU, receipt, dispute, settlement, asset ledger | Pass after canonical authority and economic-state additions | Gate F/G and external audit remain |
| Security/operations | Signing, identity, data lifecycle, multi-region, SLO, supply chain | Pass after Gate 0 and CCSE/state-writer decisions | Gate 0/C/H remain |

## 3. Findings and dispositions

| ID | Severity | Finding | Disposition in 0.2 |
|---|---|---|---|
| REV-001 | Critical | AI priority could be interpreted as a mutable price comparison | Fixed by INV-001/002, explicit priority order and ADR-0003 |
| REV-002 | Critical | Fixed-committee FHS and PoW security/reward were conflated | Fixed by INV-006/022/023/034, FR-07, ADR-0002 and claim guard CAV-16 |
| REV-003 | Critical | Full-DAG behavior was overstated as residency/security proof | Fixed: production-miner certification is MUST, cache validation remains valid, no residency proof |
| REV-004 | Critical | Current candidate/difficulty ingress is unsafe for a public pool | Preserved as runtime blocker in Gate A/D with quantitative shock/DoS requirements |
| REV-005 | Blocker | Pool Gateway both owned and was prohibited from owning balances/payouts | Fixed: Gateway only emits AcceptedShare; Pool Accounting owns immutable ledger/balance/payout |
| REV-006 | Blocker | Lease lifecycle, writer, expiry and mining lease were missing | Fixed by Lease Service, §8.3, Mining Lease flow, CAS/fencing and reconciliation |
| REV-007 | Blocker | Job status mixed Attempt, Receipt, Dispute, Escrow and Settlement | Fixed by orthogonal state machines and canonical writer table in §8 |
| REV-008 | Blocker | Protobuf signing bytes/domain were undefined | Fixed by CCSE-v1, EIP-712 bridge, algorithm profile and cross-language vectors |
| REV-009 | Blocker | Full-lifecycle GPU economics had no component or canonical data | Fixed by Financial Ledger/Asset Analytics and ADR-0009 |
| REV-010 | Blocker | ASM/CAV provenance, dependencies and release evidence were not traced | Fixed in Requirements Traceability §§6–7 |
| REV-011 | Blocker | Upgrade Manifest lacked bootstrap, authority, ordering, cancellation and sync rules | Fixed by §22.1 and ADR-0007 |
| REV-012 | High | Full-DAG provenance/normative strength was inconsistent | Fixed by FR-05 versus AR-01 separation and ADR-0002 |
| REV-013 | High | Candidate ranking depended on an undefined observed set | Fixed: only proposed candidate validity matters; absent candidate remains valid |
| REV-014 | High | Reward identity, finality, maturity and payout binding were ambiguous | Fixed by §8.6/12.4 and Pool Accounting states |
| REV-015 | High | Difficulty experiment lacked objective/acceptance envelope | Fixed design inputs and 0/50/90%/10x/100x shock cases; formula still Gate A experiment |
| REV-016 | High | KCP/public miner QUIC could share validator/FHS failure domain | Fixed by ADR-0006 and §22.3 process/listener/ALPN/key/budget separation |
| REV-017 | High | Network WorkTemplate authority was unclear | Fixed by Chain Work Adapter and separate PoolWorkAssignment authority |
| REV-018 | High | Multi-region/device source of truth and failover fencing were unclear | Fixed by §8.1 home-region/writer-epoch model and financial RPO 0 |
| REV-019 | High | Device sanitation could be bypassed after execution | Fixed: executed work requires Helper-owned RESETTING and readiness attestation |
| REV-020 | High | Pool work units, vardiff boundaries, solvency and identity rotation were incomplete | Fixed as Pool Accounting responsibilities and Gate D deliverables |
| REV-021 | High | Accepted leases were incorrectly eligible for fresh optimizer profit selection | Fixed by emergency/owner/contract/new-work priority order |
| REV-022 | High | Distributed training had no atomic gang allocation | Fixed by AllocationGroup/GangLease prepare/commit/abort model |
| REV-023 | High | Receipt signer/clock/sequence/correction trust policy was incomplete | Fixed by versioned ReceiptPolicy and §8.5 |
| REV-024 | High | Runner retries and provider-host trust claims were unsafe | Fixed by pure/idempotent atomic-output first class and four explicit trust tiers |
| REV-025 | High | Fund-before-capacity ordering could strand buyer funds | Fixed by quote -> bounded hold -> fund -> activate and deterministic refund path |
| REV-026 | High | Dispute authority and Cypher EVM conformance were underdefined | Fixed in §§7.12.2/16 and Gate G deliverables |
| REV-027 | High | IAM combined principals and omitted full key lifecycle | Fixed by distinct organization/Agent/Host/Device/Miner/Attempt identities |
| REV-028 | High | Artifact/log/cache/backup lifecycle and digest meaning were incomplete | Fixed by encrypted-manifest identity and data-classification lifecycle |
| REV-029 | High | Security/IAM/supply-chain foundations occurred too late | Fixed by Workstream/Gate 0 before Agent/Miner distribution |
| REV-030 | High | CU omitted memory bandwidth and separated latency/SLA without trace | Fixed: all report factors retained; physical derivation versus commercial linkage is explicit |
| REV-031 | High | Capability evidence was assigned only to the whole extension | Fixed by scoped component snapshot, per-requirement level and cumulative promotion rules |
| REV-032 | High | Current-code facts were not pinned to a repository revision | Fixed by commit/worktree condition in README/Master/manifest |
| REV-033 | Medium | Negative-margin power-down intent was weakened without reason | Fixed by AR-05 and ADR-0003 low-power exception/accounting |
| REV-034 | Medium | “CPH workload” mixed mining and CPH-settled market jobs | Fixed by AR-04 and claim template terminology |
| REV-035 | Medium | “Exactly once” overstated distributed delivery semantics | Fixed: at-least-once delivery, idempotency, unique identity, at-most-once effect, reconciliation |
| REV-036 | Medium | Observability IDs could cause cardinality/privacy failures | Fixed by bounded metric labels and access-controlled/redacted logs/traces |
| REV-037 | Medium | Device retirement and ownership transfer were missing | Fixed by TRANSFER_PENDING/DECOMMISSIONED and key/data closure rules |
| REV-038 | Medium | Matcher fairness/quota/backpressure was only implied | Fixed by replayable versioned quota/aging/concentration/tie-break policy |
| REV-039 | High | Normal fork readiness used SHOULD despite a seven-member fixed committee | Fixed as all-member MUST with unarmed/cancel behavior |
| REV-040 | High | Current seven genesis members share one network endpoint | Recorded below as a deployment blocker against the target failure-domain rule |
| REV-041 | High | Gateway-produced AcceptedShare could forge accounting credit | Fixed: Accounting independently revalidates signed raw share/template/assignment evidence before credit |
| REV-042 | High | Lease exclusion omitted renewal/drain/expired-but-not-released and gang in-doubt states | Fixed by unified ResourceClaim, atomic reservation conversion and non-billable group reconciliation |
| REV-043 | High | Quote/Acceptance had competing writers; Agent identity looked like an issuing CA | Fixed by sole Pricing/Quote and Metering/Acceptance writers; Agent is IAM-issued and never a CA |
| REV-044 | High | Local outbox was incorrectly offered as regional financial RPO 0 | Fixed by cross-failure-domain synchronous quorum/survivable journal and fail-closed writes |
| REV-045 | Blocker | Upgrade payload self-hashed unknown finality metadata and lacked a dual-chain state anchor/expiry | Fixed by nonrecursive payload ID, appended finality record, deterministic state machine and carrier-root anchor |
| REV-046 | High | Reward ID did not commit KeyBlock body, recipient and amount | Fixed by unique reward slot plus body-committing final carrier hash and explicit recipient/amount |
| REV-047 | High | Escrow refund, no-appeal dispute and device transfer paths were unreachable or racy | Fixed state transitions plus mutually exclusive LOCKED/refund saga and reachable transfer state |
| REV-048 | High | Sole Quote/IAM authority conflicted with enrollment/paid flows; Job lacked pre-execution closure | Fixed issuer/request flows and an idempotent closure saga with cancel/reject/expiry states |

## 4. Current-code constraints and evidence boundary

At the pinned commit the review confirmed:

- only the CPU mining agent is wired into the node;
- no HIP/ROCm or CUDA backend exists;
- validation reconstructs cells from cache and key headers have no full-DAG
  Merkle commitment;
- the current full/light self-check can fall back to light mining;
- documented cache/access/seed behavior and executable behavior are inconsistent;
- the Colossus-X directory has no algorithm golden-vector/differential test suite;
- legacy candidate paths do not uniformly bind expected difficulty, parent and
  time, and current ranking/difficulty are not accepted future rules;
- fixed-mode results use KCP without the public-pool identity/budget model;
- the remote mining API skeleton is not a production pool protocol;
- resource pool, runner, market, CU, receipt, escrow, dispute and Asset Analytics
  are target additions; and
- all seven entries in `genesis.json` use one IP endpoint. Physical co-location
  was not established, but the shared endpoint is a confirmed target-topology
  violation.

These facts are not claims about later commits. A changed code tree requires a
new evidence snapshot. They are roadmap blockers, not reasons to weaken the
approved destination.

## 5. Gated empirical and policy decisions

Architecture completeness does not fabricate values. The open register in
Master Architecture §25 retains named gates for difficulty, hardware full/light
advantage, recall SLOs, CU factors, workload verification, asset/depreciation
models, commercial policies, compliance and production SLOs. Each has a fixed
owner/method and MUST be numerically specified before its evidence is collected.

No open item permits a service boundary, state authority, identity separation,
AI priority, consensus rule or claim guard to be chosen differently without a
superseding ADR and baseline increment.

## 6. Approval rationale and limits

The design baseline is approved because it now has:

- complete report-to-goal/requirement/assumption/caveat provenance;
- explicit component ownership, prohibited responsibilities and source of truth;
- orthogonal canonical lifecycles with transition authority and recovery;
- deterministic signing, consensus activation and version boundaries;
- end-to-end mining, market, measurement, financial and asset-economics models;
- security, privacy, data, deployment, observability and failure controls;
- quantitative evidence-promotion rules and dependency-ordered release gates;
- hash-based freeze and ADR change control.

This approval permits implementation planning. It does not approve production
code, a consensus fork, public mining ingress, public funds, buyer data,
profitability/payback claims or commercial launch. Those require the applicable
roadmap gates and human organizational authorization.

## 7. Change condition

Implementation MUST cite requirement/invariant IDs and may not silently change a
canonical writer, trust boundary, state transition or gate. A material change
requires a superseding ADR, updated traceability/review, baseline increment and
new manifest. Runtime promotion evidence is recorded separately from this design
approval.
