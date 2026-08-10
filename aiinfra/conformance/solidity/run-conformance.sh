#!/bin/sh
# Copyright 2026 The Cypherium Authors
# This file is part of the Cypherium library.

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "${script_dir}/../../.." && pwd)
work_dir="${repo_root}/.codex-tmp/solidity-conformance"
tmp_dir="${work_dir}/tmp"
cache_dir="${work_dir}/gocache"

mkdir -p -- "${tmp_dir}" "${cache_dir}"
"${script_dir}/fetch-solc.sh" >/dev/null

cd -- "${repo_root}"
exec env \
  GO111MODULE=on \
  TMPDIR="${tmp_dir}" \
  GOTMPDIR="${tmp_dir}" \
  GOCACHE="${cache_dir}" \
  go test -mod=readonly -count=1 -tags=solidity_conformance \
    ./aiinfra/conformance/solidity
