#!/usr/bin/env bash
# Copyright 2026 The Cypherium Authors
# This file is part of the Cypherium library.

set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
schema_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
repository_root=$(CDPATH= cd -- "$schema_root/../.." && pwd)
bin_dir=$($script_dir/bootstrap-tools.sh)
verify_root="$repository_root/.codex-tmp/schema-tools/verify"

mkdir -p "$verify_root"
run_dir=$(mktemp -d "$verify_root/run.XXXXXXXX")
trap 'rm -rf -- "$run_dir"' EXIT

export PATH="$bin_dir:/usr/bin:/bin"
export BUF_CACHE_DIR="$repository_root/.codex-tmp/schema-tools/buf-cache"

cd "$schema_root"
expected_baseline_sha256=6aff2b5c3321eefc7439fab7e65a6ace41f943cbddf6a1de85dd5a296fb7d3a2
baseline_sha256=$(sha256sum descriptor/baseline-v1.binpb | awk '{print $1}')
if [[ "$baseline_sha256" != "$expected_baseline_sha256" ]]; then
  printf 'schema verify: compatibility baseline SHA-256 mismatch: got %s, want %s\n' "$baseline_sha256" "$expected_baseline_sha256" >&2
  exit 1
fi

buf format --diff --exit-code
buf lint --config buf.yaml
buf breaking --config buf.yaml --against descriptor/baseline-v1.binpb

mkdir -p "$run_dir/first" "$run_dir/second"
buf generate --template buf.gen.yaml --output "$run_dir/first"
buf generate --template buf.gen.yaml --output "$run_dir/second"
diff -ru --no-dereference "$run_dir/first" "$run_dir/second"

expected_generated_files=$'common/v1/common.pb.go\nfoundation/v1/foundation.pb.go\ntransport/v1/foundation_transport.pb.go'
actual_generated_files=$(cd "$run_dir/first" && find . -type f -printf '%P\n' | LC_ALL=C sort)
if [[ "$actual_generated_files" != "$expected_generated_files" ]]; then
  printf 'schema verify: generated file set mismatch\n%s\n' "$actual_generated_files" >&2
  exit 1
fi

for generated_file in common/v1/common.pb.go foundation/v1/foundation.pb.go transport/v1/foundation_transport.pb.go; do
  cmp "$run_dir/first/$generated_file" "$schema_root/$generated_file"
done

buf build --config buf.yaml --as-file-descriptor-set --exclude-source-info --output "$run_dir/current.binpb"
cmp "$run_dir/current.binpb" "$schema_root/descriptor/current.binpb"
