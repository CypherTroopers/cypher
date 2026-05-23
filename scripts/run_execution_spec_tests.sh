#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC_DIR="${SPEC_DIR:-$ROOT_DIR/execution-spec-tests}"
EVM_BIN="${EVM_BIN:-$ROOT_DIR/build/bin/evm}"
FORKS=(berlin london shanghai cancun prague)

if [[ ! -x "$EVM_BIN" ]]; then
  echo "missing evm binary: $EVM_BIN" >&2
  echo "build it first, for example: make evm" >&2
  exit 1
fi

if [[ ! -d "$SPEC_DIR" ]]; then
  echo "missing execution-spec-tests checkout: $SPEC_DIR" >&2
  echo "clone it with: git clone https://github.com/ethereum/execution-spec-tests $SPEC_DIR" >&2
  exit 1
fi

cd "$SPEC_DIR"
export EVM_BIN

for fork in "${FORKS[@]}"; do
  if [[ -d "tests/$fork" ]]; then
    echo "===== execution-spec-tests: $fork ====="
    uv run fill "tests/$fork" -m state_test -v
  else
    echo "skip missing fork directory: tests/$fork"
  fi
done
