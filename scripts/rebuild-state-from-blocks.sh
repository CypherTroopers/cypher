#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/rebuild-state-from-blocks.sh --datadir <path> --genesis <genesis.json> --blocks <rlp-file-or-dir> [options]

Options:
  --datadir <path>     Target data directory for rebuilt state (required)
  --genesis <path>     Genesis JSON used to initialize the chain (required)
  --blocks <path>      RLP block file or directory containing multiple RLP files (required)
  --cache <mb>         Cache size (MB) passed to --cache (default: 2048)
  --syncmode <mode>    Sync mode (default: full)
  --gcmode <mode>      GC mode (default: archive)
  --keep-datadir       Do not move existing datadir out of the way
  --skip-keyblocks     Skip key-block validation/import (sets CYPHER_SKIP_KEYBLOCKCHAIN=1)
  
Notes:
  - The block files must be RLP-encoded block exports compatible with `cypher import`.
  - When --blocks is a directory, files are imported in lexicographical order.
EOF
}

datadir=""
genesis=""
blocks=""
cache="2048"
syncmode="full"
gcmode="archive"
keep_datadir="false"
skip_keyblocks="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --datadir)
      datadir="$2"
      shift 2
      ;;
    --genesis)
      genesis="$2"
      shift 2
      ;;
    --blocks)
      blocks="$2"
      shift 2
      ;;
    --cache)
      cache="$2"
      shift 2
      ;;
    --syncmode)
      syncmode="$2"
      shift 2
      ;;
    --gcmode)
      gcmode="$2"
      shift 2
      ;;
    --keep-datadir)
      keep_datadir="true"
      shift 1
      ;;
    --skip-keyblocks)
      skip_keyblocks="true"
      shift 1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$datadir" || -z "$genesis" || -z "$blocks" ]]; then
  echo "Missing required arguments." >&2
  usage
  exit 1
fi

cypher_bin="./build/bin/cypher"
if [[ ! -x "$cypher_bin" ]]; then
  echo "cypher binary not found at $cypher_bin. Run: make cypher" >&2
  exit 1
fi

if [[ -d "$datadir" && "$keep_datadir" != "true" ]]; then
  backup="${datadir}.bak.$(date +%Y%m%d%H%M%S)"
  echo "Moving existing datadir to $backup"
  mv "$datadir" "$backup"
fi

echo "Initializing genesis..."
"$cypher_bin" --datadir "$datadir" init "$genesis"

declare -a block_files
if [[ -d "$blocks" ]]; then
  while IFS= read -r file; do
    block_files+=("$file")
  done < <(find "$blocks" -maxdepth 1 -type f | sort)
else
  block_files+=("$blocks")
fi

if [[ ${#block_files[@]} -eq 0 ]]; then
  echo "No block files found to import." >&2
  exit 1
fi

echo "Importing ${#block_files[@]} block file(s)..."
declare -a import_env=()
if [[ "$skip_keyblocks" == "true" ]]; then
  import_env=(CYPHER_SKIP_KEYBLOCKCHAIN=1)
fi

"${import_env[@]}" "$cypher_bin" \
  --datadir "$datadir" \
  --cache "$cache" \
  --syncmode "$syncmode" \
  --gcmode "$gcmode" \
  import "${block_files[@]}"

echo "Done. State has been rebuilt into: $datadir"
