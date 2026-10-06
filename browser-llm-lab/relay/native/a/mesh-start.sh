#!/bin/sh
set -eu
umask 077
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$script_dir"
export GOMAXPROCS=2
exec python3 ./mesh-exec.py
