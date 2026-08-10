# ADR-0008: Reference technology profile

- Status: Accepted
- Date: 2026-08-10
- Baseline: `CPH-AIIE-0.2`

## Context

Stable service boundaries are not enough to begin coordinated implementation if
teams make incompatible choices for schemas, state, events, artifacts, identity,
GPU toolchains and observability. The reference stack must also keep vendor GPU
SDKs out of the validator binary.

## Decision

The default implementation profile is:

| Concern | Default |
|---|---|
| GPU miner/kernel | Standalone C++20 executable with CPU reference, HIP/ROCm and CUDA backends |
| Agent/control/market/indexer | Go services and CLIs |
| Contracts | Solidity on Cypher EVM |
| Canonical service schemas | Protobuf with generated clients and compatibility checks; CCSE-v1 is the separate signing form |
| Internal synchronous API | gRPC; Unix-domain socket locally, mTLS remotely |
| Buyer API | Versioned HTTP/JSON gateway generated from the service contract plus signed financial operations |
| Authoritative off-chain operational state | High-availability PostgreSQL; on-chain balances/finality remain canonical contract state |
| Durable integration history | Kafka-compatible event log with transactional outbox/inbox |
| Artifacts | S3-compatible encrypted object storage using immutable content digests |
| Receipt/security evidence | Append-only/WORM-capable storage |
| Operational telemetry | OpenTelemetry, Prometheus-compatible metrics and Grafana-compatible dashboards |
| Workload packaging | Digest-pinned signed OCI artifacts |
| Orchestration | Kubernetes reference adapter; Slurm, Ray and standalone adapters share the lease contract |
| Workload isolation | Pluggable hardened-container/microVM adapter; plain privileged containers prohibited for public jobs |
| Service/workload identity | SPIFFE-compatible short-lived identity with KMS/HSM/TPM-backed roots where available |
| Secret management | External KMS/HSM/Vault-class service; no secrets in arguments or logs |

All toolchains, dependencies, schemas, images and actions are version-pinned and
produce SBOM/provenance. GPU miner, agent, control plane, runner, contracts and
SDK build and release independently.

## Consequences

- GPU toolchains and cgo/vendor runtime risk do not enter the validator binary.
- PostgreSQL is the authoritative off-chain lease/job/financial metadata store;
  on-chain balances and finalized payments remain canonical contract state. The
  event log, search index and telemetry database are projections, not competing
  truth.
- A substitute technology is allowed only when it preserves the architecture
  invariants and an ADR documents compatibility, migration, failure and
  operational consequences.
