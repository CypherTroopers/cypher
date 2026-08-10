# ADR-0002: Mining and validation model

- Status: Accepted
- Date: 2026-08-10
- Baseline: `CPH-AIIE-0.2`

## Context

The current code can mine against a full epoch dataset and verifies candidates
by reconstructing accessed cells from an epoch cache. Its full/light self-check
can fall back to light mining. The repository proposal
`consensus/modifications.md` separately describes a full-DAG Merkle root and
proof protocol, but the key-block header and candidate encoding do not carry
those fields. That proposal is not the attached strategy report. The deployment
uses a fixed Fair HotStuff committee.

## Decision

The target architecture adopts the following model:

- Fair HotStuff with the fixed committee is the finality and safety mechanism.
- A certified reference/production miner MUST keep the complete epoch DAG in
  device-local memory during normal mining. A cache-only path MAY exist only as
  a clearly labeled validator, conformance or debug mode.
- A validator MUST NOT require the full DAG and MUST deterministically verify a
  candidate from the canonical epoch cache.
- The consensus candidate remains compact: nonce, mix digest, and the canonical
  work-template fields required by the active algorithm version.
- Full-DAG Merkle roots and cell proofs are not part of baseline `CPH-AIIE-0.2`.
- The design MUST be described as performance-enforced memory hardness, not as
  cryptographic proof of 32 GiB residency or GPU exclusivity.
- CPU full, CPU light, AMD HIP, and NVIDIA CUDA implementations MUST conform to
  the same versioned golden vectors before release.
- Any change to cache sizing, seed derivation, DAG sizing, access count, hashing,
  endianness, difficulty, candidate ordering, or encoding is consensus-visible
  and requires a fork activation rule.

Mining subsidy and candidate rewards MUST be accounted separately from revenue
paid by external AI-compute buyers. Product reporting MUST NOT describe token
issuance alone as external cash flow.

## Consequences

- Committee members do not need 32 GiB DAG storage.
- Candidate messages remain compact and require no proof sidecar.
- Cache-only mining remains valid but is expected to be economically slower;
  this assumption must be measured against CPU, GPU, FPGA, and ASIC strategies.
- Candidate ingress must be authenticated, bounded, and ordered so inexpensive
  canonical checks run before the expensive light verification.
- Because residency is not proven, validators continue to accept any result
  that satisfies the canonical PoW, including one computed by an economically
  slower cache-only implementation. Certification and pool policy, not
  consensus, enforce the reference production profile.
- In fixed-committee mode PoW is a reward incentive and candidate workload; it
  is not claimed to add FHS committee, quorum, leader, safety or liveness
  security.
