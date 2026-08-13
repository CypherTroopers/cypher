#!/usr/bin/env bash
set -euo pipefail

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

: "${CPH_GATE0_GH_BINARY:?path to reviewed gh binary is required}"
: "${CPH_GATE0_GH_SHA256:?reviewed gh binary SHA-256 is required}"
: "${CPH_GATE0_PROVENANCE_ARTIFACT:?artifact path is required}"
: "${CPH_GATE0_PROVENANCE_ARTIFACT_SHA256:?expected artifact SHA-256 is required}"
: "${CPH_GATE0_PROVENANCE_BUNDLE:?offline DSSE/Sigstore bundle is required}"
: "${CPH_GATE0_PROVENANCE_BUNDLE_SHA256:?expected offline bundle SHA-256 is required}"
: "${CPH_GATE0_PROVENANCE_TRUSTED_ROOT:?offline trusted root is required}"
: "${CPH_GATE0_PROVENANCE_TRUSTED_ROOT_SHA256:?expected trusted-root SHA-256 is required}"
: "${CPH_GATE0_PROVENANCE_REPOSITORY:?expected owner/repository is required}"
: "${CPH_GATE0_PROVENANCE_SIGNER_WORKFLOW:?expected signer workflow is required}"
: "${CPH_GATE0_PROVENANCE_SIGNER_DIGEST:?expected signer digest is required}"
: "${CPH_GATE0_PROVENANCE_SOURCE_DIGEST:?expected source commit is required}"
: "${CPH_GATE0_PROVENANCE_SOURCE_REF:?expected source ref is required}"
: "${CPH_GATE0_PROVENANCE_LOG:?new verification log path is required}"

[[ ${CPH_GATE0_GH_SHA256} =~ ^[0-9a-f]{64}$ ]] || die 'invalid gh SHA-256'
[[ ${CPH_GATE0_PROVENANCE_ARTIFACT_SHA256} =~ ^[0-9a-f]{64}$ ]] || die 'invalid artifact SHA-256'
[[ ${CPH_GATE0_PROVENANCE_BUNDLE_SHA256} =~ ^[0-9a-f]{64}$ ]] || die 'invalid bundle SHA-256'
[[ ${CPH_GATE0_PROVENANCE_TRUSTED_ROOT_SHA256} =~ ^[0-9a-f]{64}$ ]] || die 'invalid trusted-root SHA-256'
[[ ${CPH_GATE0_PROVENANCE_SIGNER_DIGEST} =~ ^[0-9a-f]{40}$ ]] || die 'invalid signer digest'
[[ ${CPH_GATE0_PROVENANCE_SOURCE_DIGEST} =~ ^[0-9a-f]{40}$ ]] || die 'invalid source digest'
for path in "${CPH_GATE0_GH_BINARY}" "${CPH_GATE0_PROVENANCE_ARTIFACT}" \
  "${CPH_GATE0_PROVENANCE_BUNDLE}" "${CPH_GATE0_PROVENANCE_TRUSTED_ROOT}"; do
  [[ -f ${path} && ! -L ${path} ]] || die "missing regular input: ${path}"
done
[[ ! -e ${CPH_GATE0_PROVENANCE_LOG} ]] || die 'verification log already exists'

actual_gh_sha=$(sha256sum "${CPH_GATE0_GH_BINARY}" | awk '{print $1}')
[[ ${actual_gh_sha} == "${CPH_GATE0_GH_SHA256}" ]] || die 'gh binary digest mismatch'
actual_artifact_sha=$(sha256sum "${CPH_GATE0_PROVENANCE_ARTIFACT}" | awk '{print $1}')
[[ ${actual_artifact_sha} == "${CPH_GATE0_PROVENANCE_ARTIFACT_SHA256}" ]] || die 'artifact digest mismatch'
actual_bundle_sha=$(sha256sum "${CPH_GATE0_PROVENANCE_BUNDLE}" | awk '{print $1}')
[[ ${actual_bundle_sha} == "${CPH_GATE0_PROVENANCE_BUNDLE_SHA256}" ]] || die 'bundle digest mismatch'
actual_root_sha=$(sha256sum "${CPH_GATE0_PROVENANCE_TRUSTED_ROOT}" | awk '{print $1}')
[[ ${actual_root_sha} == "${CPH_GATE0_PROVENANCE_TRUSTED_ROOT_SHA256}" ]] || die 'trusted-root digest mismatch'

umask 077
log_tmp=$(mktemp "${CPH_GATE0_PROVENANCE_LOG}.tmp.XXXXXX")
trap 'rm -f -- "${log_tmp}"' EXIT
"${CPH_GATE0_GH_BINARY}" attestation verify "${CPH_GATE0_PROVENANCE_ARTIFACT}" \
  --repo "${CPH_GATE0_PROVENANCE_REPOSITORY}" \
  --bundle "${CPH_GATE0_PROVENANCE_BUNDLE}" \
  --custom-trusted-root "${CPH_GATE0_PROVENANCE_TRUSTED_ROOT}" \
  --signer-workflow "${CPH_GATE0_PROVENANCE_SIGNER_WORKFLOW}" \
  --signer-digest "${CPH_GATE0_PROVENANCE_SIGNER_DIGEST}" \
  --source-digest "${CPH_GATE0_PROVENANCE_SOURCE_DIGEST}" \
  --source-ref "${CPH_GATE0_PROVENANCE_SOURCE_REF}" \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --predicate-type https://slsa.dev/provenance/v1 \
  --digest-alg sha256 \
  --deny-self-hosted-runners \
  --format json > "${log_tmp}"

jq -e \
  --arg artifact "${CPH_GATE0_PROVENANCE_ARTIFACT_SHA256}" \
  --arg repository "${CPH_GATE0_PROVENANCE_REPOSITORY}" \
  --arg signer "${CPH_GATE0_PROVENANCE_SIGNER_DIGEST}" \
  --arg source "${CPH_GATE0_PROVENANCE_SOURCE_DIGEST}" \
  --arg ref "${CPH_GATE0_PROVENANCE_SOURCE_REF}" '
  length == 1 and
  all(.[].verificationResult;
    .statement.predicateType == "https://slsa.dev/provenance/v1" and
    (.statement.subject | length == 1 and .[0].digest.sha256 == $artifact) and
    (.verifiedTimestamps | length > 0) and
    .signature.certificate.issuer == "https://token.actions.githubusercontent.com" and
    .signature.certificate.githubWorkflowRepository == $repository and
    .signature.certificate.buildSignerDigest == $signer and
    .signature.certificate.sourceRepositoryDigest == $source and
    .signature.certificate.sourceRepositoryRef == $ref and
    .signature.certificate.runnerEnvironment == "github-hosted"
  )
' "${log_tmp}" >/dev/null || die 'verified provenance output violates policy'

mv -- "${log_tmp}" "${CPH_GATE0_PROVENANCE_LOG}"

printf 'offline GitHub provenance verified; log_sha256=%s\n' \
  "$(sha256sum "${CPH_GATE0_PROVENANCE_LOG}" | awk '{print $1}')"
