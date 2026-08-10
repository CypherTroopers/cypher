#!/usr/bin/env bash
# Copyright 2026 The Cypherium Authors
# This file is part of the Cypherium library.

set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
schema_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
bin_dir=$($script_dir/bootstrap-tools.sh)
repository_root=$(CDPATH= cd -- "$schema_root/../.." && pwd)

export PATH="$bin_dir:/usr/bin:/bin"
export BUF_CACHE_DIR="$repository_root/.codex-tmp/schema-tools/buf-cache"

cd "$schema_root"
buf format --write
buf lint --config buf.yaml
buf generate --template buf.gen.yaml --output "$schema_root"
buf build --config buf.yaml --as-file-descriptor-set --exclude-source-info --output "$schema_root/descriptor/current.binpb"
