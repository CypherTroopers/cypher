#!/usr/bin/env bash
set -Eeuo pipefail

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

require_file() {
  [[ -s "$1" ]] || die "Missing required artifact: $1"
}

manifest_value() {
  local manifest="$1"
  local key="$2"
  sed -n "s/^${key}=//p" "${manifest}"
}

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

verify_manifest() {
  local directory="$1"
  local expected_os="$2"
  local expected_arch="$3"
  local expected_binary="$4"
  shift 4
  local expected_files=("$@")
  local manifest="${directory}/manifest.txt"
  local declared_sha
  local actual_sha
  local declared_files
  local required_files

  require_file "${manifest}"
  require_file "${directory}/SHA256SUMS"
  require_file "${directory}/${expected_binary}"
  (
    cd "${directory}"
    sha256sum --check --strict SHA256SUMS
  ) || die "Artifact checksum validation failed in ${directory}"
  declared_files="$(
    sed -E -n 's/^[[:xdigit:]]{64}  (.+)$/\1/p' "${directory}/SHA256SUMS" |
      LC_ALL=C sort
  )"
  required_files="$(printf '%s\n' "${expected_files[@]}" | LC_ALL=C sort)"
  [[ "${declared_files}" == "${required_files}" ]] ||
    die "Unexpected checksum file set in ${directory}"
  [[ "$(manifest_value "${manifest}" source_sha)" == "${SOURCE_SHA}" ]] ||
    die "Source SHA mismatch in ${manifest}"
  [[ "$(manifest_value "${manifest}" source_state)" == "clean" ]] ||
    die "Refusing non-clean source artifact in ${manifest}"
  [[ "$(manifest_value "${manifest}" embedded_source_sha)" == "${SOURCE_SHA}" ]] ||
    die "Embedded source identity mismatch in ${manifest}"
  [[ "$(manifest_value "${manifest}" goos)" == "${expected_os}" ]] ||
    die "GOOS mismatch in ${manifest}"
  [[ "$(manifest_value "${manifest}" goarch)" == "${expected_arch}" ]] ||
    die "GOARCH mismatch in ${manifest}"
  [[ "$(manifest_value "${manifest}" binary)" == "${expected_binary}" ]] ||
    die "Binary name mismatch in ${manifest}"
  [[ "$(manifest_value "${manifest}" go_version)" == "go${GO_VERSION}" ]] ||
    die "Go version mismatch in ${manifest}"
  declared_sha="$(manifest_value "${manifest}" binary_sha256)"
  actual_sha="$(sha256_file "${directory}/${expected_binary}")"
  [[ "${declared_sha}" == "${actual_sha}" ]] ||
    die "Binary checksum mismatch for ${directory}/${expected_binary}"
}

refresh_remote_branch_sha() {
  if ! git fetch --no-tags origin \
    "+refs/heads/${TARGET_BRANCH}:refs/remotes/origin/${TARGET_BRANCH}" \
    >/dev/null; then
    die "Unable to fetch origin/${TARGET_BRANCH}"
  fi
  if ! REMOTE_BRANCH_SHA="$(git rev-parse "refs/remotes/origin/${TARGET_BRANCH}")"; then
    die "Unable to resolve origin/${TARGET_BRANCH}"
  fi
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
cd "${REPO_ROOT}"

: "${SOURCE_SHA:?SOURCE_SHA is required}"
: "${TARGET_BRANCH:?TARGET_BRANCH is required}"
: "${GO_VERSION:?GO_VERSION is required}"
ARTIFACT_ROOT="${ARTIFACT_ROOT:-artifacts}"

require_command file
require_command git
require_command install
require_command sha256sum
require_command cmp
require_command sort

[[ "$(git rev-parse HEAD)" == "${SOURCE_SHA}" ]] ||
  die "Checkout does not match ${SOURCE_SHA}"

LINUX_DIR="${ARTIFACT_ROOT}/cypher-linux-amd64"
MACOS_DIR="${ARTIFACT_ROOT}/cypher-macos-arm64"
WINDOWS_DIR="${ARTIFACT_ROOT}/cypher-windows-amd64"
HERUMI_REF="$(tr -d '\r\n' < build/herumi-bls.ref)"

verify_manifest "${LINUX_DIR}" linux amd64 cypher-linux-amd64 \
  cypher cypher-linux-amd64
verify_manifest "${MACOS_DIR}" darwin arm64 cypher-darwin-arm64 \
  cypher-darwin-arm64
verify_manifest "${WINDOWS_DIR}" windows amd64 cypher.exe \
  cypher.exe \
  libcrypto-3-x64.dll \
  libgmp-10.dll \
  libstdc++-6.dll \
  libgcc_s_seh-1.dll \
  libwinpthread-1.dll

require_file "${LINUX_DIR}/cypher"
require_file "${WINDOWS_DIR}/libcrypto-3-x64.dll"
require_file "${WINDOWS_DIR}/libgmp-10.dll"
require_file "${WINDOWS_DIR}/libstdc++-6.dll"
require_file "${WINDOWS_DIR}/libgcc_s_seh-1.dll"
require_file "${WINDOWS_DIR}/libwinpthread-1.dll"
cmp -s "${LINUX_DIR}/cypher" "${LINUX_DIR}/cypher-linux-amd64" ||
  die "Linux generic and canonical binaries differ"

[[ "$(manifest_value "${LINUX_DIR}/manifest.txt" herumi_ref)" == "${HERUMI_REF}" ]] ||
  die "Linux artifact used the wrong Herumi commit"
[[ "$(manifest_value "${MACOS_DIR}/manifest.txt" herumi_ref)" == "${HERUMI_REF}" ]] ||
  die "macOS artifact used the wrong Herumi commit"
[[ "$(manifest_value "${WINDOWS_DIR}/manifest.txt" herumi_ref)" == "${HERUMI_REF}" ]] ||
  die "Windows artifact used the wrong Herumi commit"

file "${LINUX_DIR}/cypher-linux-amd64" | grep -q 'ELF 64-bit.*x86-64' ||
  die "Linux artifact has the wrong architecture"
file "${MACOS_DIR}/cypher-darwin-arm64" | grep -q 'Mach-O 64-bit arm64' ||
  die "macOS artifact has the wrong architecture"
file "${WINDOWS_DIR}/cypher.exe" | grep -q 'PE32+.*x86-64' ||
  die "Windows artifact has the wrong architecture"

REMOTE_BRANCH_SHA=""
refresh_remote_branch_sha
if [[ "${REMOTE_BRANCH_SHA}" != "${SOURCE_SHA}" ]]; then
  printf 'Branch advanced after %s; refusing to publish stale binaries.\n' "${SOURCE_SHA}"
  exit 0
fi

mkdir -p build/bin
install -m 0755 "${LINUX_DIR}/cypher" build/bin/cypher
install -m 0755 "${LINUX_DIR}/cypher-linux-amd64" build/bin/cypher-linux-amd64
install -m 0755 "${MACOS_DIR}/cypher-darwin-arm64" build/bin/cypher-darwin-arm64
install -m 0755 "${WINDOWS_DIR}/cypher.exe" build/bin/cypher.exe
install -m 0755 "${WINDOWS_DIR}/libcrypto-3-x64.dll" build/bin/libcrypto-3-x64.dll
install -m 0755 "${WINDOWS_DIR}/libgmp-10.dll" build/bin/libgmp-10.dll
install -m 0755 "${WINDOWS_DIR}/libstdc++-6.dll" build/bin/libstdc++-6.dll
install -m 0755 "${WINDOWS_DIR}/libgcc_s_seh-1.dll" build/bin/libgcc_s_seh-1.dll
install -m 0755 "${WINDOWS_DIR}/libwinpthread-1.dll" build/bin/libwinpthread-1.dll

git config user.name "github-actions[bot]"
git config user.email "github-actions[bot]@users.noreply.github.com"
git add --chmod=+x -- \
  build/bin/cypher \
  build/bin/cypher-linux-amd64 \
  build/bin/cypher-darwin-arm64 \
  build/bin/cypher.exe \
  build/bin/libcrypto-3-x64.dll \
  build/bin/libgmp-10.dll \
  build/bin/libstdc++-6.dll \
  build/bin/libgcc_s_seh-1.dll \
  build/bin/libwinpthread-1.dll

if git diff --cached --quiet; then
  printf 'Built binaries are unchanged.\n'
  exit 0
fi

git commit -m "Update macOS Linux and Windows binaries"

refresh_remote_branch_sha
if [[ "${REMOTE_BRANCH_SHA}" != "${SOURCE_SHA}" ]]; then
  printf 'Branch advanced before push; refusing to attach stale binaries.\n'
  exit 0
fi

git push origin "HEAD:refs/heads/${TARGET_BRANCH}"
