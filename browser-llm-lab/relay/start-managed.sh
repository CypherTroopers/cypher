#!/bin/sh
# Scoped operations only; this never saves or resurrects a global PM2 dump.
set -eu
umask 077
export PATH=/usr/local/bin:/usr/bin:/bin
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec /usr/bin/python3 "$script_dir/managed-apps.py" "$@"
