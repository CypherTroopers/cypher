#!/usr/bin/env bash
# Copyright 2026 The Cypherium Authors
# This file is part of the Cypherium library.

set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
schema_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
repository_root=$(CDPATH= cd -- "$schema_root/../.." && pwd)
tools_root="$schema_root/tools"
workspace_root="$repository_root/.codex-tmp/schema-tools"
bin_dir="$workspace_root/bin"

mkdir -p "$bin_dir" "$workspace_root/buf-cache" "$workspace_root/gocache" "$workspace_root/modcache" "$workspace_root/tmp"

export GO111MODULE=on
export GOWORK=off
export GOTOOLCHAIN=local
export CGO_ENABLED=0
export GOFLAGS=
export GOEXPERIMENT=
export GOCACHE="$workspace_root/gocache"
export GOMODCACHE="$workspace_root/modcache"
export GOTMPDIR="$workspace_root/tmp"

go_version=$(go env GOVERSION)
if [[ "$go_version" != "go1.26.2" ]]; then
  printf 'schema tools: Go toolchain mismatch: got %s, want go1.26.2\n' "$go_version" >&2
  exit 1
fi

(
  cd "$tools_root"
  go mod verify >&2
  go build -mod=readonly -trimpath -o "$bin_dir/buf" github.com/bufbuild/buf/cmd/buf
  go build -mod=readonly -trimpath -o "$bin_dir/protoc-gen-go" google.golang.org/protobuf/cmd/protoc-gen-go
)

buf_version=$($bin_dir/buf --version)
if [[ "$buf_version" != "1.69.0" ]]; then
  printf 'schema tools: buf version mismatch: got %s, want 1.69.0\n' "$buf_version" >&2
  exit 1
fi

plugin_version=$($bin_dir/protoc-gen-go --version)
if [[ "$plugin_version" != "protoc-gen-go v1.36.11" ]]; then
  printf 'schema tools: protoc-gen-go version mismatch: got %s, want protoc-gen-go v1.36.11\n' "$plugin_version" >&2
  exit 1
fi

for tool in "$bin_dir/buf" "$bin_dir/protoc-gen-go"; do
  build_info=$(go version -m "$tool")
  build_version=${build_info%%$'\n'*}
  if [[ "$build_version" != "$tool: go1.26.2" || "$build_info" != *$'\tbuild\tCGO_ENABLED=0'* ]]; then
    printf 'schema tools: nonconforming Go build metadata for %s\n%s\n' "$tool" "$build_info" >&2
    exit 1
  fi
done

printf '%s\n' "$bin_dir"
