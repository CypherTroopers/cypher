#!/usr/bin/env bash
set -Eeuo pipefail

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

absolute_from_repo() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s/%s\n' "${REPO_ROOT}" "${1#./}" ;;
  esac
}

detect_jobs() {
  if command -v nproc >/dev/null 2>&1; then
    nproc
  elif command -v sysctl >/dev/null 2>&1; then
    sysctl -n hw.ncpu
  else
    printf '4\n'
  fi
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "Neither sha256sum nor shasum is available"
  fi
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
cd "${REPO_ROOT}"

GO_BIN="${GO:-go}"
require_command "${GO_BIN}"
require_command git
require_command make
require_command ar
require_command file
require_command install

HOST_OS="$("${GO_BIN}" env GOHOSTOS)"
HOST_ARCH="$("${GO_BIN}" env GOHOSTARCH)"
TARGET_OS="${TARGET_OS:-${HOST_OS}}"
TARGET_ARCH="${TARGET_ARCH:-${HOST_ARCH}}"

if [[ "${TARGET_OS}/${TARGET_ARCH}" != "${HOST_OS}/${HOST_ARCH}" ]]; then
  die "Native build required: target ${TARGET_OS}/${TARGET_ARCH}, host ${HOST_OS}/${HOST_ARCH}"
fi

case "${TARGET_OS}/${TARGET_ARCH}" in
  linux/amd64)
    PLATFORM_ID="linux-amd64"
    ARTIFACT_NAME="cypher-linux-amd64"
    ;;
  darwin/arm64)
    PLATFORM_ID="darwin-arm64"
    ARTIFACT_NAME="cypher-darwin-arm64"
    ;;
  windows/amd64)
    PLATFORM_ID="windows-amd64"
    ARTIFACT_NAME="cypher.exe"
    ;;
  *)
    die "Unsupported native target: ${TARGET_OS}/${TARGET_ARCH}"
    ;;
esac

BINDIR="$(absolute_from_repo "${BINDIR:-build/bin}")"
STAGE_ROOT="$(absolute_from_repo "${STAGE_ROOT:-build/stage}")"

mkdir -p "${BINDIR}" "${STAGE_ROOT}"
BINDIR="$(cd "${BINDIR}" && pwd -P)"
STAGE_ROOT="$(cd "${STAGE_ROOT}" && pwd -P)"
[[ "${STAGE_ROOT}" != "/" && "${STAGE_ROOT}" != "${REPO_ROOT}" ]] ||
  die "Unsafe staging root: ${STAGE_ROOT}"

TMP_ROOT="$(mktemp -d)"
NATIVE_LIB_DIR="${TMP_ROOT}/native-lib"
NEW_OUTPUT=""
STAGE_DIR="${STAGE_ROOT}/${PLATFORM_ID}"
STAGE_NEW="${STAGE_ROOT}/.${PLATFORM_ID}.new.$$"
STAGE_BACKUP="${STAGE_ROOT}/.${PLATFORM_ID}.backup.$$"
LOCAL_TEMP_FILES=()
mkdir -p "${NATIVE_LIB_DIR}"

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  set +u
  [[ -n "${NEW_OUTPUT}" ]] && rm -f -- "${NEW_OUTPUT}"
  for local_temp in "${LOCAL_TEMP_FILES[@]}"; do
    rm -f -- "${local_temp}"
  done
  [[ -n "${STAGE_NEW}" ]] && rm -rf -- "${STAGE_NEW}"
  if [[ -n "${STAGE_BACKUP}" && -e "${STAGE_BACKUP}" ]]; then
    if [[ ! -e "${STAGE_DIR}" ]]; then
      mv -- "${STAGE_BACKUP}" "${STAGE_DIR}" || status=1
    else
      rm -rf -- "${STAGE_BACKUP}"
    fi
  fi
  rm -rf -- "${TMP_ROOT}"
  exit "${status}"
}
trap cleanup EXIT

HERUMI_REF_FILE="${REPO_ROOT}/build/herumi-bls.ref"
[[ -s "${HERUMI_REF_FILE}" ]] || die "Missing Herumi ref file: ${HERUMI_REF_FILE}"
read -r HERUMI_REF < "${HERUMI_REF_FILE}"
[[ "${HERUMI_REF}" =~ ^[0-9a-f]{40}$ ]] || die "Invalid Herumi commit: ${HERUMI_REF}"

fetch_herumi() {
  local destination="$1"
  git init -q "${destination}"
  git -C "${destination}" remote add origin https://github.com/herumi/bls.git
  git -C "${destination}" fetch --depth=1 origin "${HERUMI_REF}"
  git -C "${destination}" checkout -q --detach FETCH_HEAD
  [[ "$(git -C "${destination}" rev-parse HEAD)" == "${HERUMI_REF}" ]] ||
    die "Herumi checkout does not match ${HERUMI_REF}"
  git -C "${destination}" submodule update --init --recursive --depth=1
}

prepare_herumi_generated_headers() {
  local source_root="$1"
  require_command python3
  rm -f "${source_root}/mcl/src/bint_switch.hpp"
  rm -f "${source_root}/mcl/src/llvm_proto.hpp"
  python3 "${source_root}/mcl/src/gen_llvm_proto.py" \
    > "${source_root}/mcl/src/llvm_proto.hpp"
}

repack_apple_archive() {
  local source_archive="$1"
  local output_archive="$2"
  local label="$3"
  local work_dir="${TMP_ROOT}/repack-${label}"
  mkdir -p "${work_dir}"
  (
    cd "${work_dir}"
    ar -x "${source_archive}"
    shopt -s nullglob
    objects=(*.o)
    [[ "${#objects[@]}" -gt 0 ]] || die "No objects found in ${source_archive}"
    /usr/bin/libtool -static -o "${output_archive}" "${objects[@]}"
  )
}

archive_description() {
  local archive="$1"
  local label="$2"
  local inspect_dir="${TMP_ROOT}/inspect-${label}"
  local member
  local object

  [[ -s "${archive}" ]] || die "Missing native archive: ${archive}"
  mkdir -p "${inspect_dir}"
  ar -t "${archive}" > "${inspect_dir}/members.txt"
  member="$(awk '{ sub(/\r$/, ""); if ($0 ~ /\.o$/) { print; exit } }' \
    "${inspect_dir}/members.txt")"
  [[ -n "${member}" ]] || die "No object member found in native archive: ${archive}"
  (
    cd "${inspect_dir}"
    ar -x "${archive}" "${member}"
  )
  object="${inspect_dir}/${member##*/}"
  [[ -f "${object}" ]] || die "Unable to extract object ${member} from ${archive}"
  file -b "${object}"
}

validate_native_archives() {
  local bls_description
  local mcl_description

  if [[ "${TARGET_OS}/${TARGET_ARCH}" == "darwin/arm64" ]]; then
    lipo "${NATIVE_LIB_DIR}/libbls256.a" -verify_arch arm64
    lipo "${NATIVE_LIB_DIR}/libmcl.a" -verify_arch arm64
  fi

  bls_description="$(archive_description "${NATIVE_LIB_DIR}/libbls256.a" bls)"
  mcl_description="$(archive_description "${NATIVE_LIB_DIR}/libmcl.a" mcl)"

  case "${TARGET_OS}/${TARGET_ARCH}" in
    linux/amd64)
      [[ "${bls_description}" == *"ELF 64-bit"* && "${bls_description}" == *"x86-64"* ]] ||
        die "Unexpected Linux BLS archive: ${bls_description}"
      [[ "${mcl_description}" == *"ELF 64-bit"* && "${mcl_description}" == *"x86-64"* ]] ||
        die "Unexpected Linux MCL archive: ${mcl_description}"
      ;;
    darwin/arm64)
      [[ "${bls_description}" == *"Mach-O 64-bit"* &&
        "${bls_description}" == *"arm64"* &&
        "${bls_description}" == *"object"* ]] ||
        die "Unexpected macOS BLS archive: ${bls_description}"
      [[ "${mcl_description}" == *"Mach-O 64-bit"* &&
        "${mcl_description}" == *"arm64"* &&
        "${mcl_description}" == *"object"* ]] ||
        die "Unexpected macOS MCL archive: ${mcl_description}"
      ;;
    windows/amd64)
      [[ "${bls_description}" == *"COFF"* &&
        ( "${bls_description}" == *"x86-64"* || "${bls_description}" == *"Intel amd64"* ) ]] ||
        die "Unexpected Windows BLS archive: ${bls_description}"
      [[ "${mcl_description}" == *"COFF"* &&
        ( "${mcl_description}" == *"x86-64"* || "${mcl_description}" == *"Intel amd64"* ) ]] ||
        die "Unexpected Windows MCL archive: ${mcl_description}"
      ;;
  esac
}

JOBS="${JOBS:-$(detect_jobs)}"
[[ "${JOBS}" =~ ^[1-9][0-9]*$ ]] || die "Invalid JOBS value: ${JOBS}"
HERUMI_MANIFEST_VALUE="bundled"
HERUMI_MAKE_ARGS=(MCL_FP_BIT=256 MCL_FR_BIT=256 CFLAGS_USER=-g0)

case "${TARGET_OS}/${TARGET_ARCH}" in
  linux/amd64)
    export CC="${CC:-gcc}"
    export CXX="${CXX:-g++}"
    require_command "${CC}"
    require_command "${CXX}"
    CC_MACHINE="$("${CC}" -dumpmachine)"
    [[ "${CC_MACHINE}" == x86_64*-linux* ]] ||
      die "Expected an x86_64 Linux compiler, got ${CC_MACHINE}"
    HERUMI_SOURCE="${TMP_ROOT}/herumi-bls"
    fetch_herumi "${HERUMI_SOURCE}"
    prepare_herumi_generated_headers "${HERUMI_SOURCE}"
    export CGO_CFLAGS="-I${HERUMI_SOURCE}/include -I${HERUMI_SOURCE}/mcl/include ${CGO_CFLAGS:-}"
    export CGO_CXXFLAGS="${CGO_CFLAGS}"
    export CGO_LDFLAGS="-L${NATIVE_LIB_DIR} ${CGO_LDFLAGS:-}"
    make -C "${HERUMI_SOURCE}/mcl" -j"${JOBS}" \
      lib/libmcl.a "${HERUMI_MAKE_ARGS[@]}"
    rm -f "${HERUMI_SOURCE}"/obj/*.d "${HERUMI_SOURCE}"/obj/*.o
    rm -f "${HERUMI_SOURCE}/lib/libbls256.a"
    make -C "${HERUMI_SOURCE}" -j"${JOBS}" \
      lib/libbls256.a "${HERUMI_MAKE_ARGS[@]}"
    cp "${HERUMI_SOURCE}/lib/libbls256.a" "${NATIVE_LIB_DIR}/libbls256.a"
    cp "${HERUMI_SOURCE}/mcl/lib/libmcl.a" "${NATIVE_LIB_DIR}/libmcl.a"
    HERUMI_MANIFEST_VALUE="${HERUMI_REF}"
    ;;

  darwin/arm64)
    export CC="${CC:-clang}"
    export CXX="${CXX:-clang++}"
    require_command "${CC}"
    require_command "${CXX}"
    require_command brew
    require_command lipo
    require_command otool
    [[ "$(uname -m)" == "arm64" ]] || die "macOS build requires an arm64 runner"

    HOMEBREW_PREFIX="$(brew --prefix)"
    OPENSSL_PREFIX="$(brew --prefix openssl@3)"
    GMP_PREFIX="$(brew --prefix gmp)"
    for static_library in \
      "${OPENSSL_PREFIX}/lib/libcrypto.a" \
      "${GMP_PREFIX}/lib/libgmp.a" \
      "${GMP_PREFIX}/lib/libgmpxx.a"; do
      [[ -s "${static_library}" ]] ||
        die "Missing macOS static dependency: ${static_library}"
      cp -p "${static_library}" "${NATIVE_LIB_DIR}/"
    done
    HERUMI_SOURCE="${TMP_ROOT}/herumi-bls"
    fetch_herumi "${HERUMI_SOURCE}"
    prepare_herumi_generated_headers "${HERUMI_SOURCE}"
    export CGO_CFLAGS="-I${HERUMI_SOURCE}/include -I${HERUMI_SOURCE}/mcl/include -I${OPENSSL_PREFIX}/include -I${GMP_PREFIX}/include ${CGO_CFLAGS:-}"
    export CGO_CXXFLAGS="${CGO_CFLAGS}"
    export CGO_LDFLAGS="-L${NATIVE_LIB_DIR} -L${OPENSSL_PREFIX}/lib -L${GMP_PREFIX}/lib ${CGO_LDFLAGS:-}"
    export LIBRARY_PATH="${NATIVE_LIB_DIR}:${OPENSSL_PREFIX}/lib:${GMP_PREFIX}/lib${LIBRARY_PATH:+:${LIBRARY_PATH}}"
    make -C "${HERUMI_SOURCE}/mcl" -j"${JOBS}" \
      lib/libmcl.a "${HERUMI_MAKE_ARGS[@]}"
    rm -f "${HERUMI_SOURCE}"/obj/*.d "${HERUMI_SOURCE}"/obj/*.o
    rm -f "${HERUMI_SOURCE}/lib/libbls256.a"
    make -C "${HERUMI_SOURCE}" -j"${JOBS}" \
      lib/libbls256.a "${HERUMI_MAKE_ARGS[@]}"
    repack_apple_archive "${HERUMI_SOURCE}/mcl/lib/libmcl.a" \
      "${NATIVE_LIB_DIR}/libmcl.a" mcl
    repack_apple_archive "${HERUMI_SOURCE}/lib/libbls256.a" \
      "${NATIVE_LIB_DIR}/libbls256.a" bls
    HERUMI_MANIFEST_VALUE="${HERUMI_REF}"
    ;;

  windows/amd64)
    export PATH="/mingw64/bin:/usr/bin:${PATH}"
    export CC="${CC:-gcc}"
    export CXX="${CXX:-g++}"
    require_command "${CC}"
    require_command "${CXX}"
    require_command cygpath
    require_command objdump
    CC_MACHINE="$("${CC}" -dumpmachine)"
    [[ "${CC_MACHINE}" == "x86_64-w64-mingw32" ]] ||
      die "Expected MinGW x86_64 compiler, got ${CC_MACHINE}"
    HERUMI_SOURCE="${TMP_ROOT}/herumi-bls"
    fetch_herumi "${HERUMI_SOURCE}"
    prepare_herumi_generated_headers "${HERUMI_SOURCE}"
    MINGW_INCLUDE="$(cygpath -m /mingw64/include)"
    MINGW_LIB="$(cygpath -m /mingw64/lib)"
    NATIVE_LIB_LINK_DIR="$(cygpath -m "${NATIVE_LIB_DIR}")"
    HERUMI_INCLUDE="$(cygpath -m "${HERUMI_SOURCE}/include")"
    HERUMI_MCL_INCLUDE="$(cygpath -m "${HERUMI_SOURCE}/mcl/include")"
    export CGO_CFLAGS="-I${HERUMI_INCLUDE} -I${HERUMI_MCL_INCLUDE} -I${MINGW_INCLUDE} ${CGO_CFLAGS:-}"
    export CGO_CXXFLAGS="${CGO_CFLAGS}"
    export CGO_LDFLAGS="-L${NATIVE_LIB_LINK_DIR} -L${MINGW_LIB} ${CGO_LDFLAGS:-}"
    make -C "${HERUMI_SOURCE}/mcl" -j"${JOBS}" OS=mingw64 \
      lib/libmcl.a "${HERUMI_MAKE_ARGS[@]}"
    rm -f "${HERUMI_SOURCE}"/obj/*.d "${HERUMI_SOURCE}"/obj/*.o
    rm -f "${HERUMI_SOURCE}/lib/libbls256.a"
    make -C "${HERUMI_SOURCE}" -j"${JOBS}" \
      lib/libbls256.a "${HERUMI_MAKE_ARGS[@]}"
    cp "${HERUMI_SOURCE}/lib/libbls256.a" "${NATIVE_LIB_DIR}/libbls256.a"
    cp "${HERUMI_SOURCE}/mcl/lib/libmcl.a" "${NATIVE_LIB_DIR}/libmcl.a"
    HERUMI_MANIFEST_VALUE="${HERUMI_REF}"
    ;;
esac

validate_native_archives

export GO111MODULE=on
export GOOS="${TARGET_OS}"
export GOARCH="${TARGET_ARCH}"
export CGO_ENABLED=1

[[ -s "${REPO_ROOT}/genesis.json" ]] || die "genesis.json is missing or empty"
MOD_BEFORE="$(git hash-object go.mod)"
SUM_BEFORE="$(git hash-object go.sum)"
"${GO_BIN}" mod download
"${GO_BIN}" mod verify
[[ "$(git hash-object go.mod)" == "${MOD_BEFORE}" ]] ||
  die "go mod download modified go.mod"
[[ "$(git hash-object go.sum)" == "${SUM_BEFORE}" ]] ||
  die "go mod download modified go.sum"

"${GO_BIN}" test -mod=readonly -a ./crypto/bls -count=1

HEAD_SHA="$(git rev-parse HEAD)"
SOURCE_SHA="${SOURCE_SHA:-${HEAD_SHA}}"
[[ "${HEAD_SHA}" == "${SOURCE_SHA}" ]] ||
  die "Checked out ${HEAD_SHA}, expected ${SOURCE_SHA}"
GIT_DATE="$(git show -s --format=%cd --date=format:%Y%m%d "${SOURCE_SHA}")"
LDFLAGS="-buildid= -X main.gitCommit=${SOURCE_SHA} -X main.gitDate=${GIT_DATE}"
if [[ "${TARGET_OS}" == "windows" ]]; then
  LDFLAGS="${LDFLAGS} -extldflags=-Wl,--dynamicbase"
fi

BUNDLE_DIR="${TMP_ROOT}/bundle"
mkdir -p "${BUNDLE_DIR}"
NEW_OUTPUT="${BUNDLE_DIR}/${ARTIFACT_NAME}"

"${GO_BIN}" build \
  -mod=readonly \
  -trimpath \
  -a \
  -buildvcs=false \
  -ldflags "${LDFLAGS}" \
  -o "${NEW_OUTPUT}" \
  ./cmd/cypher

[[ -s "${NEW_OUTPUT}" ]] || die "Go build did not produce ${NEW_OUTPUT}"
BINARY_DESCRIPTION="$(file -b "${NEW_OUTPUT}")"
case "${TARGET_OS}/${TARGET_ARCH}" in
  linux/amd64)
    [[ "${BINARY_DESCRIPTION}" == *"ELF 64-bit"* && "${BINARY_DESCRIPTION}" == *"x86-64"* ]] ||
      die "Unexpected Linux binary: ${BINARY_DESCRIPTION}"
    ;;
  darwin/arm64)
    [[ "${BINARY_DESCRIPTION}" == *"Mach-O 64-bit"* &&
      "${BINARY_DESCRIPTION}" == *"arm64"* ]] ||
      die "Unexpected macOS binary: ${BINARY_DESCRIPTION}"
    lipo "${NEW_OUTPUT}" -verify_arch arm64
    MACOS_DEPENDENCIES="$(otool -L "${NEW_OUTPUT}")"
    [[ "${MACOS_DEPENDENCIES}" != *"${HOMEBREW_PREFIX}/"* ]] ||
      die "macOS binary still depends on a Homebrew dynamic library"
    ;;
  windows/amd64)
    [[ "${BINARY_DESCRIPTION}" == *"PE32+"* && "${BINARY_DESCRIPTION}" == *"x86-64"* ]] ||
      die "Unexpected Windows binary: ${BINARY_DESCRIPTION}"
    WINDOWS_FILE_HEADERS="$(objdump -f "${NEW_OUTPUT}")"
    WINDOWS_PRIVATE_HEADERS="$(objdump -p "${NEW_OUTPUT}")"
    grep -q 'file format pei-x86-64' <<< "${WINDOWS_FILE_HEADERS}" ||
      die "Windows binary is not pei-x86-64"
    grep -q 'DYNAMIC_BASE' <<< "${WINDOWS_PRIVATE_HEADERS}" ||
      die "Windows binary does not enable ASLR"
    ;;
esac

"${GO_BIN}" version -m "${NEW_OUTPUT}" >/dev/null
RUNTIME_DLLS=(
  libcrypto-3-x64.dll
  libgmp-10.dll
  libstdc++-6.dll
  libgcc_s_seh-1.dll
  libwinpthread-1.dll
)
if [[ "${TARGET_OS}" == "windows" ]]; then
  for dll in "${RUNTIME_DLLS[@]}"; do
    [[ -s "/mingw64/bin/${dll}" ]] || die "Missing required runtime DLL: ${dll}"
    cp -p "/mingw64/bin/${dll}" "${BUNDLE_DIR}/${dll}"
  done
  VERSION_OUTPUT="$(
    env PATH="${BUNDLE_DIR}:/usr/bin:/c/Windows/System32" \
      "${NEW_OUTPUT}" version
  )"
else
  VERSION_OUTPUT="$("${NEW_OUTPUT}" version)"
fi
grep -Fq "Operating System: ${TARGET_OS}" <<< "${VERSION_OUTPUT}" ||
  die "Binary reported the wrong operating system"
grep -Fq "Architecture: ${TARGET_ARCH}" <<< "${VERSION_OUTPUT}" ||
  die "Binary reported the wrong architecture"
grep -Fq "Git Commit: ${SOURCE_SHA}" <<< "${VERSION_OUTPUT}" ||
  die "Binary did not report source commit ${SOURCE_SHA}"

if [[ "${TARGET_OS}" != "windows" ]]; then
  cp -p "${NEW_OUTPUT}" "${BUNDLE_DIR}/cypher"
  chmod +x "${NEW_OUTPUT}" "${BUNDLE_DIR}/cypher"
fi

rm -rf -- "${STAGE_NEW}"
mkdir -p "${STAGE_NEW}"
STAGED_FILES=()
LOCAL_FILES=()
case "${TARGET_OS}/${TARGET_ARCH}" in
  linux/amd64)
    cp -p "${BUNDLE_DIR}/cypher" "${STAGE_NEW}/cypher"
    cp -p "${NEW_OUTPUT}" "${STAGE_NEW}/cypher-linux-amd64"
    STAGED_FILES=(cypher cypher-linux-amd64)
    LOCAL_FILES=(cypher cypher-linux-amd64)
    ;;
  darwin/arm64)
    cp -p "${NEW_OUTPUT}" "${STAGE_NEW}/cypher-darwin-arm64"
    STAGED_FILES=(cypher-darwin-arm64)
    LOCAL_FILES=(cypher cypher-darwin-arm64)
    ;;
  windows/amd64)
    cp -p "${NEW_OUTPUT}" "${STAGE_NEW}/cypher.exe"
    for dll in "${RUNTIME_DLLS[@]}"; do
      cp -p "${BUNDLE_DIR}/${dll}" "${STAGE_NEW}/${dll}"
    done
    STAGED_FILES=(cypher.exe "${RUNTIME_DLLS[@]}")
    LOCAL_FILES=(cypher.exe "${RUNTIME_DLLS[@]}")
    ;;
esac

for staged_file in "${STAGED_FILES[@]}"; do
  printf '%s  %s\n' \
    "$(sha256_file "${STAGE_NEW}/${staged_file}")" \
    "${staged_file}"
done > "${STAGE_NEW}/SHA256SUMS"

GO_VERSION="$("${GO_BIN}" version | awk '{print $3}')"
BINARY_SHA256="$(sha256_file "${NEW_OUTPUT}")"
BLS_SHA256="$(sha256_file "${NATIVE_LIB_DIR}/libbls256.a")"
MCL_SHA256="$(sha256_file "${NATIVE_LIB_DIR}/libmcl.a")"
{
  printf 'source_sha=%s\n' "${SOURCE_SHA}"
  printf 'goos=%s\n' "${TARGET_OS}"
  printf 'goarch=%s\n' "${TARGET_ARCH}"
  printf 'go_version=%s\n' "${GO_VERSION}"
  printf 'herumi_ref=%s\n' "${HERUMI_MANIFEST_VALUE}"
  printf 'binary=%s\n' "${ARTIFACT_NAME}"
  printf 'binary_sha256=%s\n' "${BINARY_SHA256}"
  printf 'bls_sha256=%s\n' "${BLS_SHA256}"
  printf 'mcl_sha256=%s\n' "${MCL_SHA256}"
} > "${STAGE_NEW}/manifest.txt"

rm -rf -- "${STAGE_BACKUP}"
if [[ -e "${STAGE_DIR}" ]]; then
  mv -- "${STAGE_DIR}" "${STAGE_BACKUP}" ||
    die "Unable to preserve existing stage ${STAGE_DIR}"
fi
if ! mv -- "${STAGE_NEW}" "${STAGE_DIR}"; then
  if [[ -e "${STAGE_BACKUP}" ]]; then
    mv -- "${STAGE_BACKUP}" "${STAGE_DIR}" || true
  fi
  die "Unable to replace stage ${STAGE_DIR}"
fi
STAGE_NEW=""
rm -rf -- "${STAGE_BACKUP}"
STAGE_BACKUP=""

LOCAL_BACKUP="${TMP_ROOT}/local-backup"
mkdir -p "${LOCAL_BACKUP}"
for local_file in "${LOCAL_FILES[@]}"; do
  if [[ -e "${BINDIR}/${local_file}" ]]; then
    cp -p "${BINDIR}/${local_file}" "${LOCAL_BACKUP}/${local_file}"
  fi
  local_temporary="${BINDIR}/.${local_file}.new.$$"
  rm -f -- "${local_temporary}"
  install -m 0755 "${BUNDLE_DIR}/${local_file}" "${local_temporary}" ||
    die "Unable to prepare ${BINDIR}/${local_file}"
  LOCAL_TEMP_FILES+=("${local_temporary}")
done

if [[ "${TARGET_OS}" == "windows" ]]; then
  COMMIT_FILES=("${RUNTIME_DLLS[@]}" cypher.exe)
else
  COMMIT_FILES=("${LOCAL_FILES[@]}")
fi

for local_file in "${COMMIT_FILES[@]}"; do
  local_temporary="${BINDIR}/.${local_file}.new.$$"
  if ! mv -f -- "${local_temporary}" "${BINDIR}/${local_file}"; then
    restore_failed=0
    for restore_file in "${LOCAL_FILES[@]}"; do
      if [[ -e "${LOCAL_BACKUP}/${restore_file}" ]]; then
        cp -p "${LOCAL_BACKUP}/${restore_file}" "${BINDIR}/${restore_file}" ||
          restore_failed=1
      else
        rm -f -- "${BINDIR}/${restore_file}" || restore_failed=1
      fi
    done
    [[ "${restore_failed}" -eq 0 ]] ||
      die "Local output update and rollback both failed"
    die "Unable to replace ${BINDIR}/${local_file}; previous outputs restored"
  fi
done
LOCAL_TEMP_FILES=()
NEW_OUTPUT=""

printf 'Built %s (%s/%s)\n' "${BINDIR}/${ARTIFACT_NAME}" "${TARGET_OS}" "${TARGET_ARCH}"
printf 'Staged artifacts in %s\n' "${STAGE_DIR}"
