# Architecture Decision Records

These ADRs are normative parts of baseline `CPH-AIIE-0.2`.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-system-boundary.md) | Keep Cypher L1 as finality and settlement plane | Accepted |
| [0002](0002-mining-and-validation.md) | Full-DAG miners, cache-based validators, fixed committee | Accepted |
| [0003](0003-resource-priority-and-control.md) | Provider control and AI-first resource scheduling | Accepted |
| [0004](0004-market-and-settlement.md) | Off-chain execution and matching, on-chain escrow and settlement | Accepted |
| [0005](0005-compute-measurement.md) | Versioned multidimensional measurement before universal Compute Unit | Accepted |
| [0006](0006-transport-evolution.md) | Version the application protocol and defer KCP-to-QUIC transport migration | Accepted |
| [0007](0007-upgrade-manifest.md) | Activate consensus changes through a finalized Upgrade Manifest | Accepted |
| [0008](0008-reference-technology-profile.md) | Fix the default implementation stack and substitution rules | Accepted |
| [0009](0009-asset-economics.md) | Preserve auditable full-lifecycle GPU economics | Accepted |
| [0010](0010-canonical-state-and-signing.md) | Fix canonical writers, state separation and signing form | Accepted |

An accepted ADR may only be superseded by another ADR. Editing an accepted ADR
in place to reverse its decision is prohibited.
