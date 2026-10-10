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
  local expected_files=("$@" manifest.txt go-build-info.txt)
  local manifest="${directory}/manifest.txt"
  local declared_sha
  local actual_sha

  require_file "${manifest}"
  require_file "${directory}/SHA256SUMS"
  require_file "${directory}/go-build-info.txt"
  require_file "${directory}/${expected_binary}"
  python3 - "${directory}" "${GO_VERSION}" "${expected_os}" "${expected_arch}" \
    "${expected_files[@]}" <<'PY'
import pathlib, re, sys

directory = pathlib.Path(sys.argv[1])
version, goos, goarch = sys.argv[2:5]
expected = set(sys.argv[5:])
entries = list(directory.iterdir())
if {entry.name for entry in entries} != expected | {"SHA256SUMS"}:
    raise SystemExit(f"Unexpected artifact file set in {directory}")
if any(entry.is_symlink() or not entry.is_file() for entry in entries):
    raise SystemExit(f"Artifact must contain only regular files: {directory}")
declared = set()
for line in (directory / "SHA256SUMS").read_text().splitlines():
    match = re.fullmatch(r"[0-9a-f]{64}  ([A-Za-z0-9._+-]+)", line)
    if not match or match.group(1) in declared:
        raise SystemExit(f"Invalid or duplicate checksum entry in {directory}")
    declared.add(match.group(1))
if declared != expected:
    raise SystemExit(f"Unexpected checksum coverage in {directory}")

info = (directory / "go-build-info.txt").read_text().splitlines()
if not info or not info[0].endswith(f": go{version}"):
    raise SystemExit(f"Go build information has the wrong version: {directory}")
settings = {}
for line in info[1:]:
    fields = line.strip().split("\t")
    if len(fields) == 2 and fields[0] == "build":
        key, separator, value = fields[1].partition("=")
        if not separator or key in settings:
            raise SystemExit(f"Invalid Go build setting: {directory}")
        settings[key] = value
for key, value in {"GOOS": goos, "GOARCH": goarch, "CGO_ENABLED": "1", "-compiler": "gc", "-tags": "cypher_bounded_storage"}.items():
    if settings.get(key) != value:
        raise SystemExit(f"Go build setting {key} mismatch: {directory}")
PY
  (
    cd "${directory}"
    sha256sum --check --strict SHA256SUMS
  ) || die "Artifact checksum validation failed in ${directory}"
  [[ "$(manifest_value "${manifest}" source_sha)" == "${SOURCE_SHA}" ]] ||
    die "Source SHA mismatch in ${manifest}"
  [[ "$(manifest_value "${manifest}" goos)" == "${expected_os}" ]] ||
    die "GOOS mismatch in ${manifest}"
  [[ "$(manifest_value "${manifest}" goarch)" == "${expected_arch}" ]] ||
    die "GOARCH mismatch in ${manifest}"
  [[ "$(manifest_value "${manifest}" binary)" == "${expected_binary}" ]] ||
    die "Binary name mismatch in ${manifest}"
  [[ "$(manifest_value "${manifest}" go_version)" == "go${GO_VERSION}" ]] ||
    die "Go version mismatch in ${manifest}"
  [[ "$(manifest_value "${manifest}" build_tags)" == "cypher_bounded_storage" ]] ||
    die "Native build tags mismatch in ${manifest}"
  [[ -n "$(manifest_value "${manifest}" compiler_identity)" ]] ||
    die "Missing compiler identity in ${manifest}"
  [[ "$(manifest_value "${manifest}" ipc_transaction_finality_method)" == "eth_getTransactionFinality" &&
     "$(manifest_value "${manifest}" ipc_transaction_finality_transport)" == "ipc" ]] ||
    die "Missing IPC transaction finality capability in ${manifest}"
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
require_command python3

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

PROVENANCE_FILES=()
for platform in linux-amd64 darwin-arm64 windows-amd64; do
  case "${platform}" in
    linux-amd64) directory="${LINUX_DIR}" ;;
    darwin-arm64) directory="${MACOS_DIR}" ;;
    windows-amd64) directory="${WINDOWS_DIR}" ;;
  esac
  mkdir -p "build/provenance/${platform}"
  for filename in manifest.txt SHA256SUMS go-build-info.txt; do
    path="build/provenance/${platform}/${filename}"
    install -m 0644 "${directory}/${filename}" "${path}"
    PROVENANCE_FILES+=("${path}")
  done
done

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
git add --chmod=-x -- "${PROVENANCE_FILES[@]}"

if git diff --cached --quiet; then
  printf 'Built binaries and provenance are unchanged.\n'
  exit 0
fi

git commit -m "Update macOS Linux and Windows binaries and provenance"

refresh_remote_branch_sha
if [[ "${REMOTE_BRANCH_SHA}" != "${SOURCE_SHA}" ]]; then
  printf 'Branch advanced before push; refusing to attach stale binaries.\n'
  exit 0
fi

git push origin "HEAD:refs/heads/${TARGET_BRANCH}"
