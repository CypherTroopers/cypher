#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "${repo_root}"

scan_file() {
  local path=$1
  local finding
  finding=$(LC_ALL=C rg -n --no-heading --color=never \
    -e '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----' \
    -e 'AKIA[0-9A-Z]{16}' \
    -e 'ASIA[0-9A-Z]{16}' \
    -e 'gh[opsu]_[A-Za-z0-9]{20,}' \
    -e 'github_pat_[A-Za-z0-9_]{22,}' \
    -e 'xox[baprs]-[A-Za-z0-9-]{20,}' \
    -e 'sk-proj-[A-Za-z0-9_-]{20,}' \
    -e 'AIza[0-9A-Za-z_-]{35}' \
    -- "${path}" || true)
  if [[ -n ${finding} ]]; then
    printf 'potential credential in %s\n%s\n' "${path}" "${finding}" >&2
    return 1
  fi
}

if (($#)); then
  for path in "$@"; do
    [[ -f ${path} ]] || { printf 'not a regular file: %s\n' "${path}" >&2; exit 2; }
    scan_file "${path}"
  done
  exit 0
fi

status=0
mapfile -d '' scan_paths < <(git ls-files -z --cached --others --exclude-standard)
if ((${#scan_paths[@]})); then
  finding=$(LC_ALL=C rg -n --no-heading --color=never \
    -e '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----' \
    -e 'AKIA[0-9A-Z]{16}' \
    -e 'ASIA[0-9A-Z]{16}' \
    -e 'gh[opsu]_[A-Za-z0-9]{20,}' \
    -e 'github_pat_[A-Za-z0-9_]{22,}' \
    -e 'xox[baprs]-[A-Za-z0-9-]{20,}' \
    -e 'sk-proj-[A-Za-z0-9_-]{20,}' \
    -e 'AIza[0-9A-Za-z_-]{35}' \
    -- "${scan_paths[@]}" || true)
  if [[ -n ${finding} ]]; then
    printf 'potential credential(s):\n%s\n' "${finding}" >&2
    status=1
  fi
fi
exit "${status}"
