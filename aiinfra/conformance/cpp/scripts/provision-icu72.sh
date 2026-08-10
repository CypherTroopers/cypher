#!/usr/bin/env bash
# Copyright 2026 The Cypherium Authors
# SPDX-License-Identifier: LGPL-3.0-only

set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lock.sh
source "${SCRIPT_DIR}/lock.sh"

usage() {
  printf 'usage: %s --work-dir ABSOLUTE_PATH [--jobs N] [--offline]\n' "$0" >&2
  exit 64
}

work_dir=""
jobs="1"
offline="0"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --work-dir)
      [[ $# -ge 2 ]] || usage
      work_dir="$2"
      shift 2
      ;;
    --jobs)
      [[ $# -ge 2 ]] || usage
      jobs="$2"
      shift 2
      ;;
    --offline)
      offline="1"
      shift
      ;;
    *) usage ;;
  esac
done

[[ -n "${work_dir}" && "${work_dir}" == /* ]] || \
  die "--work-dir must be an absolute path"
[[ "${jobs}" =~ ^[1-9][0-9]*$ ]] || die "--jobs must be a positive integer"

require_command awk
require_command uname
validate_lock
validate_host_toolchain
require_command make
require_command mktemp
require_command readlink
require_command sha256sum
require_command tar
require_command cp
require_command ln

mkdir -p "${work_dir}"
work_dir="$(CDPATH= cd -- "${work_dir}" && pwd -P)"
case "${work_dir}/" in
  "${CPP_ROOT}/"*) die "build artifacts must not be placed under ${CPP_ROOT}" ;;
esac

archive_name="$(lock_value icu_source_archive)"
archive_url="$(lock_value icu_source_url)"
expected_sha="$(lock_value icu_source_sha256)"
download_dir="${work_dir}/downloads"
archive_path="${download_dir}/${archive_name}"
[[ ! -L "${download_dir}" ]] || die "download directory must not be a symlink"
mkdir -p "${download_dir}"
download_dir="$(CDPATH= cd -- "${download_dir}" && pwd -P)"
case "${download_dir}/" in
  "${work_dir}/"*) ;;
  *) die "download directory escaped the work directory" ;;
esac
archive_path="${download_dir}/${archive_name}"
[[ ! -L "${archive_path}" ]] || die "cached ICU archive must not be a symlink"
[[ ! -e "${archive_path}" || -f "${archive_path}" ]] || \
  die "cached ICU archive is not a regular file"

verify_archive() {
  local actual_sha
  actual_sha="$(sha256sum -- "$1" | awk '{print $1}')"
  [[ "${actual_sha}" == "${expected_sha}" ]] || \
    die "ICU archive digest mismatch: expected ${expected_sha}, found ${actual_sha}"
}

if [[ -f "${archive_path}" ]]; then
  verify_archive "${archive_path}"
elif [[ "${offline}" == "1" ]]; then
  die "verified ICU archive is absent in offline mode: ${archive_path}"
else
  require_command curl
  partial_path="$(mktemp "${download_dir}/.${archive_name}.unverified.XXXXXXXX")"
  cleanup_partial() {
    if [[ -n "${partial_path:-}" ]]; then
      rm -f -- "${partial_path}"
    fi
  }
  trap cleanup_partial EXIT HUP INT TERM
  [[ -f "${partial_path}" && ! -L "${partial_path}" ]] || \
    die "download quarantine is not a regular file"
  printf 'Fetching pinned ICU source into quarantine: %s\n' "${partial_path}" >&2
  curl --disable --fail --location --proto '=https' --proto-redir '=https' \
    --tlsv1.2 --retry 3 --output "${partial_path}" "${archive_url}"
  verify_archive "${partial_path}"
  chmod 0600 -- "${partial_path}"
  # A hard link in the same directory publishes the verified file atomically
  # and fails if another process or symlink appeared at the destination.
  ln -- "${partial_path}" "${archive_path}" || \
    die "refusing to replace an existing ICU archive"
  rm -f -- "${partial_path}"
  partial_path=""
  trap - EXIT HUP INT TERM
fi

# Extraction is deliberately after the digest check. Even a cached archive is
# reverified on every run. The pinned release must retain its single `icu/` root.
run_dir="$(mktemp -d "${work_dir}/icu72.verified.XXXXXXXX")"
chmod 0700 -- "${run_dir}"
verified_archive="${run_dir}/${archive_name}"
cp -- "${archive_path}" "${verified_archive}"
[[ -f "${verified_archive}" && ! -L "${verified_archive}" ]] || \
  die "verified ICU archive copy is not a regular file"
chmod 0400 -- "${verified_archive}"
verify_archive "${verified_archive}"

tar_version="$(tar --version | awk 'NR == 1 { print; exit }')"
[[ "${tar_version}" == "tar (GNU tar)"* ]] || \
  die "safe extraction requires GNU tar, found: ${tar_version}"
archive_list="${run_dir}/archive.list"
archive_types="${run_dir}/archive.types"
env -u GZIP -u TAR_OPTIONS tar -tzf "${verified_archive}" >"${archive_list}"
awk '
  $0 !~ /^icu\// || $0 ~ /(^|\/)\.\.($|\/)/ || $0 ~ /^\// || $0 ~ /\\/ {
    print "unsafe ICU archive entry: " $0 > "/dev/stderr"
    failed = 1
  }
  ++seen[$0] > 1 {
    print "duplicate ICU archive entry: " $0 > "/dev/stderr"
    failed = 1
  }
  END { exit failed }
' "${archive_list}" || die "refusing to extract an archive with unsafe paths"
env -u GZIP -u TAR_OPTIONS LC_ALL=C tar -tvzf "${verified_archive}" >"${archive_types}"
awk '
  substr($0, 1, 1) != "-" && substr($0, 1, 1) != "d" {
    print "unsafe ICU archive entry type: " $0 > "/dev/stderr"
    failed = 1
  }
  END { exit failed }
' "${archive_types}" || \
  die "refusing to extract links, devices, FIFOs, or other special entries"

source_dir="${run_dir}/source"
build_dir="${run_dir}/build"
prefix_dir="${run_dir}/install"
tmp_dir="${run_dir}/tmp"
mkdir -p "${source_dir}" "${build_dir}" "${prefix_dir}" "${tmp_dir}"
verify_archive "${verified_archive}"
env -u GZIP -u TAR_OPTIONS tar -xzf "${verified_archive}" -C "${source_dir}" \
  --no-same-owner --no-same-permissions

configure="${source_dir}/icu/source/configure"
[[ -x "${configure}" ]] || die "verified archive lacks executable icu/source/configure"

printf 'Configuring verified ICU %s in %s\n' "$(lock_value icu_version)" "${run_dir}" >&2
configure_log="${run_dir}/configure.log"
build_log="${run_dir}/build.log"
install_log="${run_dir}/install.log"
(
  cd "${build_dir}"
  env \
    -u BASH_ENV \
    -u COMPILER_PATH \
    -u CONFIG_SITE \
    -u CPATH \
    -u CPPFLAGS \
    -u CPLUS_INCLUDE_PATH \
    -u C_INCLUDE_PATH \
    -u ENV \
    -u GCC_EXEC_PREFIX \
    -u GNUMAKEFLAGS \
    -u LD_AUDIT \
    -u LDFLAGS \
    -u LD_LIBRARY_PATH \
    -u LD_PRELOAD \
    -u LIBRARY_PATH \
    -u MAKEFLAGS \
    -u MFLAGS \
    LC_ALL=C \
    TZ=UTC \
    TMPDIR="${tmp_dir}" \
    CC="$(lock_value cc_command)" \
    CXX="$(lock_value cxx_command)" \
    CFLAGS='-O2 -g0 -fPIC' \
    CXXFLAGS='-O2 -g0 -fPIC' \
    "${configure}" \
      --prefix="${prefix_dir}" \
      --enable-shared \
      --disable-static \
      --disable-debug \
      --disable-samples \
      --disable-tests \
      --disable-extras \
      --disable-tools \
      --with-data-packaging=library
) >"${configure_log}" 2>&1 || {
  tail -n 100 "${configure_log}" >&2
  die "ICU configure failed; full log: ${configure_log}"
}
printf 'Building verified ICU %s (log: %s)\n' "$(lock_value icu_version)" \
  "${build_log}" >&2
env -u LD_AUDIT -u LD_LIBRARY_PATH -u LD_PRELOAD -u MAKEFLAGS -u MFLAGS \
  -u GNUMAKEFLAGS LC_ALL=C TZ=UTC TMPDIR="${tmp_dir}" \
  make -C "${build_dir}" --jobs "${jobs}" >"${build_log}" 2>&1 || {
  tail -n 100 "${build_log}" >&2
  die "ICU build failed; full log: ${build_log}"
}
env -u LD_AUDIT -u LD_LIBRARY_PATH -u LD_PRELOAD -u MAKEFLAGS -u MFLAGS \
  -u GNUMAKEFLAGS LC_ALL=C TZ=UTC TMPDIR="${tmp_dir}" \
  make -C "${build_dir}" install >"${install_log}" 2>&1 || {
  tail -n 100 "${install_log}" >&2
  die "ICU install failed; full log: ${install_log}"
}

icu_library="${prefix_dir}/lib/libicuuc.so.$(lock_value icu_abi)"
icu_data_library="${prefix_dir}/lib/libicudata.so.$(lock_value icu_abi)"
[[ -f "${icu_library}" ]] || die "ICU build did not install ${icu_library}"
[[ -f "${icu_data_library}" ]] || die "ICU build did not install ${icu_data_library}"
icu_library="$(readlink -f -- "${icu_library}")"

printf 'source_url=%s\nsource_sha256=%s\ncc=%s\ncxx=%s\nicu_library=%s\nconfigure_log=%s\nbuild_log=%s\ninstall_log=%s\n' \
  "${archive_url}" \
  "${expected_sha}" \
  "$(lock_value cc_command) $(lock_value cc_version)" \
  "$(lock_value cxx_command) $(lock_value cxx_version)" \
  "${icu_library}" \
  "${configure_log}" \
  "${build_log}" \
  "${install_log}" >"${run_dir}/provision.manifest"

# stdout is intentionally machine-readable: the caller receives exactly the
# verified, newly built ICU library path. Progress and diagnostics use stderr.
printf '%s\n' "${icu_library}"
