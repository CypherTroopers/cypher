# Gate 0 supply-chain evidence

This repository now has a fail-closed Gate 0 evidence contract. It does not
claim that Gate 0 has passed.

## Immutable execution identity

The opt-in GitHub workflow uses the Docker Official Image
`postgres:18.4-bookworm` by immutable OCI index digest:

```text
docker.io/library/postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382
linux/amd64 manifest: sha256:7e6103cf85f88f7a0eddb3ec0b1ba8940eba098ed118ade25a729ca9daee5568
```

The job inspects the pulled image and rejects an index/platform mismatch. The
digest was resolved from the Docker Hub registry API on 2026-08-13. A future
update is a reviewed repository change; the mutable tag cannot silently select
a different image.

Go compilation and tests run through the independently digest-pinned official
`golang:1.26.2-bookworm` OCI image (index
`sha256:47ce5636e9936b2c5cbf708925578ef386b4f8872aec74a67bd13a627d242b19`,
linux/amd64 child
`sha256:6b9b1ff26b22fde9b31abc5c6994586f588107ee3aa54dba50626aaac5884995`).
Both index and platform child membership are checked before execution; the
mutable GitHub-hosted runner's preinstalled Go is not used as release evidence.
The exact reviewed image set is closed: both Go and PostgreSQL index and
linux/amd64 child digests must match, and an additional image is rejected.

All enabled reusable GitHub actions are pinned to full commit SHA. The legacy
binary workflow is manual-only, has read-only permissions, cannot publish, and
currently fails before native dependency installation because the apt,
Homebrew and MSYS package identities have not yet been frozen. This prevents it
from remaining an unsigned alternate release path.

## Evidence hierarchy

The normative claim remains the existing
`cph.aiinfra.foundation.v1.EvidenceRecord`. Its numerical criteria must be
frozen first in the existing `ExperimentPlan`; both are canonical CCSE-v1
payloads signed by the protected release Ed25519 identity.

`cmd/gate0-evidence` is the repository-local offline tool. Its `plan` command
signs the closed ten-criterion ExperimentPlan before collection begins;
`source-archive` produces a deterministic archive of the exact tracked source
that the tests exercised; `sign-file`/`verify-file` create and verify that
artifact's raw Ed25519 signature; `sbom` produces canonical SPDX; and `bundle`
plus `verify` construct and independently re-check the complete retained
package. All inputs are strict JSON with unknown fields rejected. Existing
outputs are never overwritten.
The current release subject is deliberately named a candidate tested-source
artifact. It is not a production executable or an assertion that every future
shipped binary has been covered. Gate 0 for a binary release remains
incomplete until each actual shipped artifact is built under an approved
immutable toolchain identity and receives its own signature, SBOM, provenance,
and verification evidence.
Offline acceptance also binds the external trust policy to the exact foundation
message type/schema, sender identity, chain ID, genesis hash, replay domain,
protocol/schema versions, validity and sequence counter—not only to a supplied
public key and self-consistent record.

The JSON `ArtifactManifest` in `aiinfra/gate0` is only a closed artifact index.
The SHA-256 of its canonical detached-signature payload is committed as an
evidence artifact digest inside the foundation EvidenceRecord. The offline
verifier rejects unknown JSON fields,
non-canonical JSON, unsafe paths, missing/extra files, digest or size changes,
expired/failed evidence, an unpracticed rollback, an unexpected source/workflow
or OCI identity, and a missing/incorrect signature.

The same package generates deterministic canonical SPDX 2.3 JSON from an
explicit sorted component set and independently verifies its namespace,
creation identity, SHA-256 package checksums and document relationships. A
passed manifest must contain an SPDX SBOM whose checksums cover every listed
non-SBOM release artifact; a structurally valid but unrelated SBOM is rejected.

No private key is stored in the repository. A protected CI environment must
inject a non-placeholder approver identity and Ed25519 signing material. The
workflow fails before evidence generation when any identity is absent. The
actual chain ID and genesis hash are required as protected
`GATE0_CHAIN_ID_SHA256` and `GATE0_GENESIS_HASH_SHA256` variables; the workflow
does not synthesize either trust-domain identity. A successful rollback must
similarly use actual current and previously approved artifact digests. The
current FAILED candidate encodes those digest fields as absent because no real
rollback was run; it never hashes a description into a pretend target. GitHub
OIDC build provenance supplements the signed foundation record; it does not
replace the application release signature.

The manifest also requires the retained DSSE/Sigstore provenance bundle and a
separate verification log. That log must be produced by `gh attestation verify`
with the exact repository and signer-workflow identity policy (and retained
trusted root for an offline verification package). The repository hook
`build/verify-github-provenance.sh` additionally pins the reviewed `gh` binary,
artifact, bundle and trusted-root SHA-256 values; requires the exact signer and
source commit/ref, GitHub Actions OIDC issuer and GitHub-hosted runner; and
writes a new log only after the returned certificate identity, artifact subject
and verified timestamp pass policy. The retained custom trusted root can
validate either GitHub's private or public-good Sigstore hierarchy without
weakening the exact workflow/certificate identity checks. Merely creating or
downloading an attestation is insufficient. The workflow generates, retains,
and verifies this provenance before marking only that individual check passed;
it still emits an aggregate FAILED candidate while other checks are absent.

## Closed required-check set

A PASSED aggregate manifest is valid only when every one of these exact checks
exists and passed:

- `cross-language-signatures`
- `ccse-fail-closed`
- `artifact-signature`
- `sbom-policy`
- `artifact-provenance`
- `secret-scan`
- `rollback-drill`
- `backup-restore`
- `telemetry-cardinality-redaction`
- `pilot-plan-owner-coverage`

The workflow currently stops as INCOMPLETE after the checks that can honestly
run in the present repository. It must not emit a PASSED EvidenceRecord until
real CI logs cover the full set, a deterministic SPDX or CycloneDX SBOM is
generated for each shipped artifact and both the PostgreSQL restore and
rollback drills run on the exact OCI digest. The workflow now performs
`pg_dump`/`pg_restore` with the pinned PostgreSQL image into a fresh database,
then uses the pinned Go image to compare the authoritative logical snapshots
and terminal durable result. It marks `backup-restore` passed only when that
entire round trip succeeds. The rollback record must name distinct
from/target artifact digests; merely documenting a procedure is not a drill.
The CI job nevertheless emits a signed `FAILED` candidate manifest and FAILED
foundation EvidenceRecord for forensic audit. Candidate verification is a
separate API from normative PASSED verification, so this retained failure
cannot be consumed as Gate 0 acceptance.

The current pinned-PostgreSQL live selection includes
`TestLivePostgresCanonicalAdmissionAndReload`; that test now performs the
semantic-v2 audited-final apply/attach operation and reloads it through the
production `ProductionSemanticAdapter.LookupKeyMaterial` path. The workflow
retains an explicit scope line and requires that exact test's PASS line before
the fresh-database backup/restore round trip begins.

The workflow also runs the Solidity/Cypher-EVM harness inside the pinned Go
image. `solc` 0.8.30 is downloaded only through the repository provisioner and
must match SHA-256
`f3e987dc6ecebd4bd350c48edcbc320b46cf9e3109bd3fc3d88f1acaf4c428f7`;
the test independently checks its version, recompiles deterministically, and
runs the positive and negative vectors. This remains partial evidence. The C++
consumer requires GCC 15.2.0, OpenSSL 3.5.5, and ICU 72.1/Unicode 15.0.0, but
repository policy currently identifies only those versions and ICU source—not
an immutable compiler/OpenSSL toolchain OCI or complete verified binary set.
The workflow therefore refuses mutable apt provisioning and correctly records
`cross-language-signatures` as FAILED even when the locked Solidity half
passes.

The repository-local secret scanner has positive and negative fixtures and no
path allowlist that can suppress broad source trees. It is an early fail-fast
hook, not a substitute for platform secret scanning or review.

## Local verification

The pure Go contract and its tamper tests run without a container or signing
secret:

```sh
go test ./aiinfra/gate0 -count=1
go test ./cmd/gate0-evidence -count=1
./build/test-scan-secrets.sh
./build/scan-secrets.sh
./build/test-verify-github-provenance.sh
```

Local success proves the verifier behavior only. Immutable-image execution,
protected CI identity, signed SBOM/artifact provenance and practiced rollback
remain external evidence and cannot be inferred from a host-package run.

The protected `gate0-release` environment must provide:

- `GATE0_APPROVER_IDENTITY`
- raw Ed25519 public/private material as the documented base64 variables
- `GATE0_CHAIN_ID_SHA256` and `GATE0_GENESIS_HASH_SHA256`
- `GATE0_POSTGRES_ADMIN_PASSWORD`
- a reviewed GitHub CLI SHA-256 and matching offline trusted-root bundle/hash

Until real cross-language, rollback to an actually approved prior digest,
telemetry redaction/cardinality, and downstream pilot owner-plan evidence
exist, the CI job intentionally uploads only a signed FAILED candidate and
exits nonzero. The backup/restore evidence itself still exists only after this
protected workflow executes successfully; local unit success cannot create it.
