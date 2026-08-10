# CPH AI Infrastructure Extension

## Design baseline

| Field | Value |
|---|---|
| Baseline | `CPH-AIIE-0.2` |
| Status | Approved architecture baseline for implementation planning |
| Baseline date | 2026-08-10 |
| Strategy source | `reference/1-1071437753-CPH-AI-Infrastructure-Value-Recovery-Report.txt` |
| Strategy source SHA-256 | `91bf6a6c9e1246f8a9a4dd06c7baf0555019cf976894e6f1fdd6816ec1abe120` |
| Reviewed runtime-code commit | `7ae80156b23b20f804557eedc921bf431dc3a536` |
| Reviewed tracked worktree condition | No tracked modifications; architecture/reference files were untracked |
| Runtime code changes in this baseline | None |

This directory is the normative architecture baseline for the CPH AI
Infrastructure Extension. It turns the strategy report into implementable
system boundaries, invariants, interfaces, controls, acceptance gates, and a
traceable delivery sequence.

The architecture is complete in scope but deliberately staged in delivery.
Unknown commercial or hardware-dependent values are recorded as experiments
or release gates instead of being invented.

“Approved” authorizes implementation planning against these boundaries. It does
not approve runtime promotion, public funds, economic claims or commercial
availability. Those require the roadmap evidence gates.

## Normative document set

1. [Master Architecture](master-architecture.md) — end-state system and all
   cross-component invariants.
2. [Requirements Traceability](requirements-traceability.md) — report claim to
   requirement, component, evidence, and acceptance mapping.
3. [Implementation Roadmap](implementation-roadmap.md) — dependency-ordered
   workstreams and release gates.
4. [Review Record](review-record.md) — independent review findings and their
   dispositions.
5. [Architecture decisions](adr/README.md) — decisions that implementation may
   not silently override.
6. `baseline-manifest.json` — hashes that identify the exact frozen baseline.

If this README conflicts with the Master Architecture, the Master Architecture
wins. If an ADR intentionally supersedes the Master Architecture, the ADR must
name the superseded section and the baseline version must be incremented.

## Normative language

The terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are
normative. Descriptions marked `TBD-EXPERIMENT`, `TBD-POLICY`, or
`TBD-COMMERCIAL` are unresolved inputs with an explicit resolution gate; they
are not permission to choose an arbitrary implementation value.

## Fixed product thesis

The target extension is designed to recover value from eligible idle,
underutilized, and economically retired GPU capacity through two successive
revenue sources:

1. preemptible CPH mining as a bootstrap and fallback load; and
2. paid external AI compute as the long-term source of productive demand.

Owner AI workloads remain the highest-priority use of provider hardware. CPH
mining is never allowed to displace an owner workload or violate an accepted AI
service-level agreement.

## Fixed system boundary

The existing Cypher chain remains the finality and settlement plane. GPU mining,
resource pooling, workload execution, matching, metering, artifact storage, and
revenue optimization are separate services. Customer models, datasets, and
outputs are never placed directly on chain.

## Change control

Any change to one of the following requires a new ADR, compatibility analysis,
security review, updated traceability, and a baseline version increment:

- consensus-visible Colossus-X inputs or outputs;
- key-block or candidate encoding;
- GPU ownership and workload-priority rules;
- lease, receipt, Compute Unit, or settlement semantics;
- trust boundaries or signing identities;
- on-chain contract responsibilities;
- data-retention or tenant-isolation guarantees;
- release-gate safety requirements.

The baseline may be amended without a version increment only for spelling,
formatting, or links that do not change meaning. The updated manifest must still
be regenerated.

## Design versus present implementation

This baseline describes the target extension. It does not claim that the target
services already exist. In the current repository, the reusable foundations are
primarily Cypher L1, EVM execution, Fair HotStuff, the CPU Colossus-X reference
path, networking primitives, RPC, and basic metrics. The GPU backends, mining
pool, distributed resource pool, revenue optimizer, AI runner, marketplace,
Compute Unit metering, escrow, and dispute system are additions.
