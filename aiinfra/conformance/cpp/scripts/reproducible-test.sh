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
offline_flag=()
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
      offline_flag=(--offline)
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
require_command grep
require_command make
require_command mktemp
require_command openssl
require_command sed

openssl_cli_version="$(env -u OPENSSL_CONF -u OPENSSL_MODULES openssl version | \
  awk '{print $2}')"
[[ "${openssl_cli_version}" == "$(lock_value openssl_version)" ]] || \
  die "locked OpenSSL version is $(lock_value openssl_version), found ${openssl_cli_version}"

icu_library="$("${SCRIPT_DIR}/provision-icu72.sh" \
  --work-dir "${work_dir}" --jobs "${jobs}" "${offline_flag[@]}")"
[[ "${icu_library}" == /* && -f "${icu_library}" ]] || \
  die "provisioner did not return an absolute ICU library path"
icu_lib_dir="$(dirname -- "${icu_library}")"

run_dir="$(mktemp -d "${work_dir}/ccse-cpp.verified.XXXXXXXX")"
build_dir="${run_dir}/build"
output_file="${run_dir}/conformance.out"
target="${build_dir}/cph_ccse_conformance"
tmp_dir="${run_dir}/tmp"
mkdir -p "${tmp_dir}"

env -u CC -u CXX -u CPPFLAGS -u CFLAGS -u CXXFLAGS -u LDFLAGS -u LDLIBS \
  -u BASH_ENV -u COMPILER_PATH -u CPATH -u CPLUS_INCLUDE_PATH -u C_INCLUDE_PATH \
  -u ENV -u GCC_EXEC_PREFIX -u GNUMAKEFLAGS -u LD_AUDIT -u LD_LIBRARY_PATH \
  -u LD_PRELOAD -u LIBRARY_PATH -u MAKEFLAGS -u MFLAGS \
  LC_ALL=C \
  TZ=UTC \
  TMPDIR="${tmp_dir}" \
  make -C "${CPP_ROOT}" \
    BUILD_DIR="${build_dir}" \
    CC="$(lock_value cc_command)" \
    CXX="$(lock_value cxx_command)" \
    --jobs "${jobs}"

positive_fixture="${CPP_ROOT}/../../ccse/testdata/ccse_v1_ed25519_positive.json"
negative_fixture="${CPP_ROOT}/../../ccse/testdata/ccse_v1_negative.json"
"${SCRIPT_DIR}/provider-selection-test.sh" \
  "${target}" "${positive_fixture}" "${negative_fixture}"

if ! env \
  -u CPH_CCSE_ALLOW_AMBIENT_ICU \
  -u ICU_DATA \
  -u ICU_TIMEZONE_FILES_DIR \
  -u LD_AUDIT \
  -u LD_PRELOAD \
  -u OPENSSL_MODULES \
  LD_LIBRARY_PATH="${icu_lib_dir}" \
  OPENSSL_CONF=/dev/null \
  CPH_CCSE_ICU_LIBRARY="${icu_library}" \
  CPH_CCSE_ICU_ABI="$(lock_value icu_abi)" \
  "${target}" "${positive_fixture}" "${negative_fixture}" \
  >"${output_file}" 2>&1; then
  sed -n '1,240p' "${output_file}" >&2
  die "C++ conformance executable failed; full output: ${output_file}"
fi

grep -F "Compiler: " "${output_file}" | grep -F "$(lock_value cxx_version)" >/dev/null || \
  die "conformance executable did not report the locked compiler version"
grep -F "Crypto headers: OpenSSL $(lock_value openssl_version) " "${output_file}" >/dev/null || \
  die "conformance executable was not built with the locked OpenSSL headers"
grep -F "Crypto provider: OpenSSL $(lock_value openssl_version) " "${output_file}" >/dev/null || \
  die "conformance executable did not load the locked OpenSSL provider"
grep -F "Unicode provider: explicit ${icu_library} (ICU 72.1.0, Unicode 15.0.0)" \
  "${output_file}" >/dev/null || die "conformance executable did not load the pinned ICU provider"
grep -F "Vectors executed: 1 positive, 18 negative" "${output_file}" >/dev/null || \
  die "conformance executable did not execute the complete locked vector set"
pass_count="$(grep -c '^\[PASS\] ' "${output_file}")"
[[ "${pass_count}" == "18" ]] || \
  die "expected 18 passing negative vectors, found ${pass_count}"
if grep -F "PROVISIONAL" "${output_file}" >/dev/null; then
  die "pinned execution was unexpectedly marked provisional"
fi
grep -F "PASS: independent C++20 CCSE-v1 conformance consumer" \
  "${output_file}" >/dev/null || die "C++ conformance vectors did not pass"

sed -n '/^Compiler:/,$p' "${output_file}"
printf 'Reproducible test evidence: %s\n' "${output_file}"
