#!/usr/bin/env bash
set -euo pipefail

gate=${CPH_AIIE_POSTGRES_DISPOSABLE:-}
restore_gate=${CPH_AIIE_POSTGRES_RESTORE_ACCEPTANCE:-}
source_owner_dsn=${CPH_AIIE_POSTGRES_RESTORE_SOURCE_OWNER_DSN:-}
source_runtime_dsn=${CPH_AIIE_POSTGRES_RESTORE_SOURCE_RUNTIME_DSN:-}
admin_dsn=${CPH_AIIE_POSTGRES_RESTORE_ADMIN_DSN:-}
admin_os_user=${CPH_AIIE_POSTGRES_RESTORE_ADMIN_OS_USER:-}
restore_database=${CPH_AIIE_POSTGRES_RESTORE_DATABASE:-}
restore_owner=${CPH_AIIE_POSTGRES_RESTORE_OWNER:-}
restored_owner_dsn=${CPH_AIIE_POSTGRES_RESTORED_OWNER_DSN:-}
restored_runtime_dsn=${CPH_AIIE_POSTGRES_RESTORED_RUNTIME_DSN:-}
evidence_dir=${CPH_AIIE_POSTGRES_RESTORE_EVIDENCE_DIR:-}

if [[ $gate != YES || $restore_gate != YES ]]; then
  echo "refusing to run: set CPH_AIIE_POSTGRES_DISPOSABLE=YES and CPH_AIIE_POSTGRES_RESTORE_ACCEPTANCE=YES" >&2
  exit 2
fi
for required in source_owner_dsn source_runtime_dsn admin_dsn restore_database restore_owner \
  restored_owner_dsn restored_runtime_dsn evidence_dir; do
  if [[ -z ${!required} ]]; then
    echo "refusing to run: required restore setting ${required} is empty" >&2
    exit 2
  fi
done
if [[ ! $restore_database =~ ^[a-z][a-z0-9_]{0,62}$ ]]; then
  echo "refusing to run: restore database must match ^[a-z][a-z0-9_]{0,62}$" >&2
  exit 2
fi
if [[ ! $restore_owner =~ ^[a-zA-Z_][a-zA-Z0-9_]{0,62}$ ]]; then
  echo "refusing to run: restore owner is not a safely quoted PostgreSQL role name" >&2
  exit 2
fi
if [[ -n $admin_os_user && ! $admin_os_user =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
  echo "refusing to run: admin OS user is not a safe local account name" >&2
  exit 2
fi
if [[ -e $evidence_dir ]]; then
  echo "refusing to overwrite existing evidence path: $evidence_dir" >&2
  exit 2
fi
for command in createdb go pg_dump pg_restore psql sha256sum; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required command is missing: $command" >&2
    exit 2
  fi
done
if [[ -n $admin_os_user ]] && ! command -v runuser >/dev/null 2>&1; then
  echo "runuser is required when CPH_AIIE_POSTGRES_RESTORE_ADMIN_OS_USER is set" >&2
  exit 2
fi

admin_psql_scalar() {
  local statement=$1
  if [[ -n $admin_os_user ]]; then
    runuser -u "$admin_os_user" -- psql -XAt --no-password --set=ON_ERROR_STOP=1 \
      --dbname="$admin_dsn" --command="$statement"
  else
    psql -XAt --no-password --set=ON_ERROR_STOP=1 \
      --dbname="$admin_dsn" --command="$statement"
  fi
}

create_restore_database() {
  if [[ -n $admin_os_user ]]; then
    runuser -u "$admin_os_user" -- createdb --maintenance-db="$admin_dsn" --no-password \
      --owner="$restore_owner" --template=template0 --encoding=UTF8 -- "$restore_database"
  else
    createdb --maintenance-db="$admin_dsn" --no-password --owner="$restore_owner" \
      --template=template0 --encoding=UTF8 -- "$restore_database"
  fi
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "${script_dir}/../../../.." && pwd)
mkdir -m 0700 -- "$evidence_dir"
archive="${evidence_dir}/cph-aiinfra.pgdump"
dump_log="${evidence_dir}/pg-dump.log"
restore_log="${evidence_dir}/pg-restore.log"
test_log="${evidence_dir}/go-restore-test.log"
manifest="${evidence_dir}/manifest.txt"

source_database=$(psql -XAt --no-password --set=ON_ERROR_STOP=1 \
  --dbname="$source_owner_dsn" --command='SELECT pg_catalog.current_database()')
source_owner=$(psql -XAt --no-password --set=ON_ERROR_STOP=1 \
  --dbname="$source_owner_dsn" --command='SELECT current_user')
source_runtime=$(psql -XAt --no-password --set=ON_ERROR_STOP=1 \
  --dbname="$source_runtime_dsn" --command='SELECT current_user')
if [[ -z $source_database || -z $source_owner || -z $source_runtime || $source_owner == "$source_runtime" ]]; then
  echo "source DSNs must use distinct, direct owner and runtime logins" >&2
  exit 2
fi

existing_database=$(admin_psql_scalar \
  "SELECT pg_catalog.count(*) FROM pg_catalog.pg_database WHERE datname = '${restore_database}'")
if [[ $existing_database != 0 ]]; then
  echo "refusing to reuse existing restore database: $restore_database" >&2
  exit 2
fi
existing_owner=$(admin_psql_scalar \
  "SELECT pg_catalog.count(*) FROM pg_catalog.pg_roles WHERE rolname = '${restore_owner}'")
if [[ $existing_owner != 1 ]]; then
  echo "restore owner must already exist exactly once: $restore_owner" >&2
  exit 2
fi

{
  printf 'evidence_format=CPH-AIIE-POSTGRES-BACKUP-RESTORE-V1\n'
  printf 'started_at_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'git_commit=%s\n' "$(git -C "$repo_root" rev-parse HEAD)"
  printf 'source_database=%s\n' "$source_database"
  printf 'source_owner=%s\n' "$source_owner"
  printf 'source_runtime=%s\n' "$source_runtime"
  printf 'restore_database=%s\n' "$restore_database"
  printf 'restore_owner=%s\n' "$restore_owner"
  printf 'pg_dump_version=%s\n' "$(pg_dump --version)"
  printf 'pg_restore_version=%s\n' "$(pg_restore --version)"
  printf 'go_version=%s\n' "$(go version)"
} >"$manifest"

pg_dump --dbname="$source_owner_dsn" --no-password --format=custom \
  --compress=zstd:9 --serializable-deferrable --no-owner --verbose \
  --file="$archive" 2>"$dump_log"
sha256sum "$archive" >"${archive}.sha256"
pg_restore --list "$archive" >"${evidence_dir}/archive.list"

# This is the sole database-creation operation. The absence check above and
# intentionally unique name prevent overwriting an earlier restore. On any
# later failure the database is retained for diagnosis; this script never
# drops, truncates, cleans or reuses a database.
create_restore_database

actual_restore_database=$(psql -XAt --no-password --set=ON_ERROR_STOP=1 \
  --dbname="$restored_owner_dsn" --command='SELECT pg_catalog.current_database()')
actual_restore_owner=$(psql -XAt --no-password --set=ON_ERROR_STOP=1 \
  --dbname="$restored_owner_dsn" --command='SELECT current_user')
database_owner=$(psql -XAt --no-password --set=ON_ERROR_STOP=1 \
  --dbname="$restored_owner_dsn" \
  --command='SELECT pg_catalog.pg_get_userbyid(datdba) FROM pg_catalog.pg_database WHERE datname = pg_catalog.current_database()')
schema_count=$(psql -XAt --no-password --set=ON_ERROR_STOP=1 \
  --dbname="$restored_owner_dsn" \
  --command="SELECT pg_catalog.count(*) FROM pg_catalog.pg_namespace WHERE nspname = 'cph_aiinfra'")
if [[ $actual_restore_database != "$restore_database" || $actual_restore_owner != "$restore_owner" || \
      $database_owner != "$restore_owner" || $schema_count != 0 ]]; then
  echo "new restore database identity or emptiness check failed; database retained for diagnosis" >&2
  exit 1
fi

pg_restore --dbname="$restored_owner_dsn" --no-password --exit-on-error \
  --single-transaction --no-owner --verbose "$archive" 2>"$restore_log"

actual_runtime=$(psql -XAt --no-password --set=ON_ERROR_STOP=1 \
  --dbname="$restored_runtime_dsn" --command='SELECT current_user')
if [[ $actual_runtime != "$source_runtime" ]]; then
  echo "restored runtime DSN does not use the source runtime role; database retained for diagnosis" >&2
  exit 1
fi

(
  cd "$repo_root"
  CPH_AIIE_POSTGRES_DISPOSABLE=YES \
  CPH_AIIE_POSTGRES_RESTORE_ACCEPTANCE=YES \
  CPH_AIIE_POSTGRES_RESTORE_SOURCE_OWNER_DSN="$source_owner_dsn" \
  CPH_AIIE_POSTGRES_RESTORE_SOURCE_RUNTIME_DSN="$source_runtime_dsn" \
  CPH_AIIE_POSTGRES_RESTORED_OWNER_DSN="$restored_owner_dsn" \
  CPH_AIIE_POSTGRES_RESTORED_RUNTIME_DSN="$restored_runtime_dsn" \
  GO111MODULE=on \
    go test ./aiinfra/storage/postgres -run '^TestLivePostgresRestoredSnapshot$' -count=1 -v
) 2>&1 | tee "$test_log"

{
  printf 'archive_sha256=%s\n' "$(cut -d' ' -f1 "${archive}.sha256")"
  printf 'completed_at_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'status=accepted\n'
} >>"$manifest"

echo "backup/restore acceptance passed; evidence retained at $evidence_dir"
