#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/gate0-provenance-test.XXXXXX")
trap 'rm -rf -- "${test_dir}"' EXIT

artifact="${test_dir}/artifact.bin"
bundle="${test_dir}/bundle.jsonl"
trusted_root="${test_dir}/trusted-root.jsonl"
fake_gh="${test_dir}/gh"
verification_log="${test_dir}/verification.json"
repository=example/cypher
signer_digest=1111111111111111111111111111111111111111
source_digest=2222222222222222222222222222222222222222
source_ref=refs/tags/v1.2.3

printf 'release artifact\n' > "${artifact}"
printf '{"bundle":"fixture"}\n' > "${bundle}"
printf '{"trustedRoot":"fixture"}\n' > "${trusted_root}"

cat > "${fake_gh}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 26 ]]
[[ $1 == attestation && $2 == verify && $3 == "${TEST_ARTIFACT}" ]]
[[ $4 == --repo && $5 == "${TEST_REPOSITORY}" ]]
[[ $6 == --bundle && $7 == "${TEST_BUNDLE}" ]]
[[ $8 == --custom-trusted-root && $9 == "${TEST_TRUSTED_ROOT}" ]]
[[ ${10} == --signer-workflow && ${11} == example/cypher/.github/workflows/release.yml ]]
[[ ${12} == --signer-digest && ${13} == "${TEST_SIGNER_DIGEST}" ]]
[[ ${14} == --source-digest && ${15} == "${TEST_SOURCE_DIGEST}" ]]
[[ ${16} == --source-ref && ${17} == "${TEST_SOURCE_REF}" ]]
[[ ${18} == --cert-oidc-issuer && ${19} == https://token.actions.githubusercontent.com ]]
[[ ${20} == --predicate-type && ${21} == https://slsa.dev/provenance/v1 ]]
[[ ${22} == --digest-alg && ${23} == sha256 ]]
[[ ${24} == --deny-self-hosted-runners ]]
[[ ${25} == --format && ${26} == json ]]

timestamp='[{"type":"Tlog","timestamp":"2026-08-13T00:00:00Z"}]'
if [[ ${TEST_INVALID_TIMESTAMP:-0} == 1 ]]; then
  timestamp='[]'
fi
jq -n \
  --arg artifact "${TEST_ARTIFACT_SHA256}" \
  --arg repository "${TEST_REPOSITORY}" \
  --arg signer "${TEST_SIGNER_DIGEST}" \
  --arg source "${TEST_SOURCE_DIGEST}" \
  --arg ref "${TEST_SOURCE_REF}" \
  --argjson timestamp "${timestamp}" '[{
    verificationResult: {
      statement: {
        predicateType: "https://slsa.dev/provenance/v1",
        subject: [{name: "artifact.bin", digest: {sha256: $artifact}}]
      },
      signature: {certificate: {
        issuer: "https://token.actions.githubusercontent.com",
        githubWorkflowRepository: $repository,
        buildSignerDigest: $signer,
        sourceRepositoryDigest: $source,
        sourceRepositoryRef: $ref,
        runnerEnvironment: "github-hosted"
      }},
      verifiedTimestamps: $timestamp
    }
  }]'
EOF
chmod 0755 "${fake_gh}"

artifact_sha=$(sha256sum "${artifact}" | awk '{print $1}')
bundle_sha=$(sha256sum "${bundle}" | awk '{print $1}')
root_sha=$(sha256sum "${trusted_root}" | awk '{print $1}')
gh_sha=$(sha256sum "${fake_gh}" | awk '{print $1}')

export TEST_ARTIFACT="${artifact}"
export TEST_ARTIFACT_SHA256="${artifact_sha}"
export TEST_BUNDLE="${bundle}"
export TEST_TRUSTED_ROOT="${trusted_root}"
export TEST_REPOSITORY="${repository}"
export TEST_SIGNER_DIGEST="${signer_digest}"
export TEST_SOURCE_DIGEST="${source_digest}"
export TEST_SOURCE_REF="${source_ref}"

run_verifier() {
  CPH_GATE0_GH_BINARY="${fake_gh}" \
  CPH_GATE0_GH_SHA256="${gh_sha}" \
  CPH_GATE0_PROVENANCE_ARTIFACT="${artifact}" \
  CPH_GATE0_PROVENANCE_ARTIFACT_SHA256="${artifact_sha}" \
  CPH_GATE0_PROVENANCE_BUNDLE="${bundle}" \
  CPH_GATE0_PROVENANCE_BUNDLE_SHA256="${bundle_sha}" \
  CPH_GATE0_PROVENANCE_TRUSTED_ROOT="${trusted_root}" \
  CPH_GATE0_PROVENANCE_TRUSTED_ROOT_SHA256="${root_sha}" \
  CPH_GATE0_PROVENANCE_REPOSITORY="${repository}" \
  CPH_GATE0_PROVENANCE_SIGNER_WORKFLOW=example/cypher/.github/workflows/release.yml \
  CPH_GATE0_PROVENANCE_SIGNER_DIGEST="${signer_digest}" \
  CPH_GATE0_PROVENANCE_SOURCE_DIGEST="${source_digest}" \
  CPH_GATE0_PROVENANCE_SOURCE_REF="${source_ref}" \
  CPH_GATE0_PROVENANCE_LOG="$1" \
  "${repo_root}/build/verify-github-provenance.sh"
}

run_verifier "${verification_log}" >/dev/null
jq -e 'length == 1' "${verification_log}" >/dev/null

wrong_digest_log="${test_dir}/wrong-digest.json"
artifact_sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
if run_verifier "${wrong_digest_log}" >/dev/null 2>&1; then
  printf 'expected artifact digest mismatch to fail\n' >&2
  exit 1
fi
[[ ! -e ${wrong_digest_log} ]]
artifact_sha="${TEST_ARTIFACT_SHA256}"

invalid_timestamp_log="${test_dir}/invalid-timestamp.json"
export TEST_INVALID_TIMESTAMP=1
if run_verifier "${invalid_timestamp_log}" >/dev/null 2>&1; then
  printf 'expected missing verified timestamp to fail\n' >&2
  exit 1
fi
[[ ! -e ${invalid_timestamp_log} ]]

printf 'GitHub provenance verifier fixtures passed\n'
