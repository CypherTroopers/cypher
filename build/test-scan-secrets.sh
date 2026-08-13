#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
scanner="${repo_root}/build/scan-secrets.sh"
fixture_dir=$(mktemp -d)
trap 'rm -rf -- "${fixture_dir}"' EXIT

printf 'ordinary application configuration\n' > "${fixture_dir}/clean.txt"
"${scanner}" "${fixture_dir}/clean.txt"

printf '%s%s%s\n' '-----BEGIN ' 'PRIVATE KEY' '-----' > "${fixture_dir}/secret.txt"
if "${scanner}" "${fixture_dir}/secret.txt" >/dev/null 2>&1; then
  printf 'secret scanner accepted the positive fixture\n' >&2
  exit 1
fi

if "${scanner}" "${fixture_dir}" >/dev/null 2>&1; then
  printf 'secret scanner accepted a directory in explicit mode\n' >&2
  exit 1
fi

printf 'secret scanner self-test passed\n'
