#!/usr/bin/env bash
# Copyright 2026 The Cypherium Authors
# SPDX-License-Identifier: LGPL-3.0-only

set -euo pipefail

if [[ $# -ne 3 ]]; then
  printf 'usage: %s BINARY POSITIVE_FIXTURE NEGATIVE_FIXTURE\n' "$0" >&2
  exit 64
fi

target="$1"
positive_fixture="$2"
negative_fixture="$3"
[[ -x "${target}" ]] || {
  printf 'ERROR: test binary is not executable: %s\n' "${target}" >&2
  exit 1
}

expect_blocker() {
  local label="$1"
  local expected="$2"
  shift 2
  local output status
  set +e
  output="$("$@" 2>&1)"
  status=$?
  set -e
  if [[ "${status}" -ne 2 || "${output}" != *"${expected}"* ]]; then
    printf 'FAIL: %s (status %s)\n%s\n' "${label}" "${status}" "${output}" >&2
    exit 1
  fi
  if [[ "${output}" == *"ambient development"* ]]; then
    printf 'FAIL: %s fell back to an ambient provider\n%s\n' \
      "${label}" "${output}" >&2
    exit 1
  fi
}

expect_blocker default-fail-closed "no explicit ICU provider selected" \
  env -u CPH_CCSE_ICU_LIBRARY -u CPH_CCSE_ICU_ABI \
    -u CPH_CCSE_ALLOW_AMBIENT_ICU \
    "${target}" "${positive_fixture}" "${negative_fixture}"

expect_blocker partial-explicit-selection "must be set together" \
  env -u CPH_CCSE_ICU_ABI -u CPH_CCSE_ALLOW_AMBIENT_ICU \
    CPH_CCSE_ICU_LIBRARY=/definitely/not/a/provider/libicuuc.so.72 \
    "${target}" "${positive_fixture}" "${negative_fixture}"

expect_blocker invalid-explicit-path \
  "explicit ICU load failed for /definitely/not/a/provider/libicuuc.so.72" \
  env -u CPH_CCSE_ALLOW_AMBIENT_ICU \
    CPH_CCSE_ICU_LIBRARY=/definitely/not/a/provider/libicuuc.so.72 \
    CPH_CCSE_ICU_ABI=72 \
    "${target}" "${positive_fixture}" "${negative_fixture}"

expect_blocker conflicting-selection "cannot be combined with an explicit provider" \
  env CPH_CCSE_ALLOW_AMBIENT_ICU=1 \
    CPH_CCSE_ICU_LIBRARY=/definitely/not/a/provider/libicuuc.so.72 \
    CPH_CCSE_ICU_ABI=72 \
    "${target}" "${positive_fixture}" "${negative_fixture}"

printf 'PASS: ICU provider selection is explicit and fail-closed\n'
