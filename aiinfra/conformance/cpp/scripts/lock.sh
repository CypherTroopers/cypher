#!/usr/bin/env bash
# Copyright 2026 The Cypherium Authors
# SPDX-License-Identifier: LGPL-3.0-only

set -euo pipefail

LOCK_SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CPP_ROOT="$(CDPATH= cd -- "${LOCK_SCRIPT_DIR}/.." && pwd)"
LOCK_FILE="${CPP_ROOT}/toolchain.lock"

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

lock_value() {
  local key="$1"
  awk -F= -v wanted="${key}" '$1 == wanted { print substr($0, length($1) + 2) }' \
    "${LOCK_FILE}"
}

validate_lock() {
  [[ -f "${LOCK_FILE}" ]] || die "dependency lock is missing: ${LOCK_FILE}"
  awk -F= '
    BEGIN {
      keys["lock_format"] = 1
      keys["target_os"] = 1
      keys["target_arch"] = 1
      keys["cc_command"] = 1
      keys["cc_version"] = 1
      keys["cxx_command"] = 1
      keys["cxx_version"] = 1
      keys["openssl_version"] = 1
      keys["icu_version"] = 1
      keys["icu_abi"] = 1
      keys["unicode_version"] = 1
      keys["icu_source_url"] = 1
      keys["icu_source_sha256"] = 1
      keys["icu_source_archive"] = 1
    }
    /^[[:space:]]*$/ { next }
    /^#/ { next }
    NF != 2 || $1 !~ /^[a-z][a-z0-9_]*$/ || $2 == "" {
      print "invalid lock line: " $0 > "/dev/stderr"
      failed = 1
      next
    }
    !($1 in keys) {
      print "unknown lock key: " $1 > "/dev/stderr"
      failed = 1
      next
    }
    ++seen[$1] != 1 {
      print "duplicate lock key: " $1 > "/dev/stderr"
      failed = 1
    }
    END {
      for (key in keys) {
        if (seen[key] != 1) {
          print "missing lock key: " key > "/dev/stderr"
          failed = 1
        }
      }
      exit failed
    }
  ' "${LOCK_FILE}" || die "dependency lock validation failed"

  [[ "$(lock_value lock_format)" == "1" ]] || die "unsupported lock format"
  [[ "$(lock_value target_os)" == "linux" ]] || die "locked target OS changed"
  [[ "$(lock_value target_arch)" == "x86_64" ]] || die "locked target architecture changed"
  [[ "$(lock_value cc_command)" == "gcc" ]] || die "locked C compiler changed"
  [[ "$(lock_value cc_version)" == "15.2.0" ]] || die "locked C compiler version changed"
  [[ "$(lock_value cxx_command)" == "g++" ]] || die "locked C++ compiler changed"
  [[ "$(lock_value cxx_version)" == "15.2.0" ]] || die "locked C++ compiler version changed"
  [[ "$(lock_value openssl_version)" == "3.5.5" ]] || die "locked OpenSSL version changed"
  [[ "$(lock_value icu_version)" == "72.1" ]] || die "locked ICU version changed"
  [[ "$(lock_value icu_abi)" == "72" ]] || die "locked ICU ABI changed"
  [[ "$(lock_value unicode_version)" == "15.0.0" ]] || die "locked Unicode version changed"
  [[ "$(lock_value icu_source_url)" == \
    "https://github.com/unicode-org/icu/releases/download/release-72-1/icu4c-72_1-src.tgz" ]] || \
    die "locked ICU source URL changed"
  [[ "$(lock_value icu_source_sha256)" == \
    "a2d2d38217092a7ed56635e34467f92f976b370e20182ad325edea6681a71d68" ]] || \
    die "locked ICU source digest changed"
  [[ "$(lock_value icu_source_archive)" == "icu4c-72_1-src.tgz" ]] || \
    die "locked ICU archive name changed"
}

validate_host_toolchain() {
  local cc cxx cc_version cxx_version host_os host_arch
  cc="$(lock_value cc_command)"
  cxx="$(lock_value cxx_command)"
  require_command "${cc}"
  require_command "${cxx}"
  host_os="$(uname -s)"
  host_arch="$(uname -m)"
  [[ "${host_os}" == "Linux" ]] || die "locked build requires Linux, found ${host_os}"
  [[ "${host_arch}" == "$(lock_value target_arch)" ]] || \
    die "locked build requires $(lock_value target_arch), found ${host_arch}"
  cc_version="$("${cc}" -dumpfullversion -dumpversion)"
  cxx_version="$("${cxx}" -dumpfullversion -dumpversion)"
  [[ "${cc_version}" == "$(lock_value cc_version)" ]] || \
    die "locked C compiler version is $(lock_value cc_version), found ${cc_version}"
  [[ "${cxx_version}" == "$(lock_value cxx_version)" ]] || \
    die "locked C++ compiler version is $(lock_value cxx_version), found ${cxx_version}"
}
