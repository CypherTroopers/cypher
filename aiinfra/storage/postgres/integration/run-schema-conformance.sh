#!/usr/bin/env bash
set -euo pipefail

if [[ ${CPH_AIIE_POSTGRES_DISPOSABLE:-} != YES ]]; then
  echo "refusing to run: set CPH_AIIE_POSTGRES_DISPOSABLE=YES for a disposable PostgreSQL database" >&2
  exit 2
fi
if [[ -z ${CPH_AIIE_POSTGRES_DSN:-} ]]; then
  echo "CPH_AIIE_POSTGRES_DSN is required" >&2
  exit 2
fi
if ! command -v psql >/dev/null 2>&1; then
  echo "psql is required" >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  echo "sha256sum is required" >&2
  exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
migration_file="${script_dir}/../migrations/0001_ccse_replay.sql"
migration_sha=$(sha256sum "$migration_file")
migration_sha=${migration_sha%% *}

psql -X "$CPH_AIIE_POSTGRES_DSN" \
  --set=ON_ERROR_STOP=1 \
  --set=migration_sha="$migration_sha" \
  --file="${script_dir}/schema_conformance.sql"
