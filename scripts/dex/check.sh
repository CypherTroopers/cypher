#!/usr/bin/env bash
# Development tests only. No operational datadir, node binary or genesis writes.
set -euo pipefail

mode="${1:-unit}"
case "$mode" in unit|process|roles|baseline|native|financial|cli-financial|cli-roles|socket|source|relay|continuous) ;; *) echo 'usage: check.sh [unit|process|roles|baseline|native|financial|cli-financial|cli-roles|socket|source|relay|continuous]' >&2; exit 2;; esac
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$repo_root"
run_root="$(mktemp -d /tmp/common-dex-check.XXXXXXXX)"
mkdir -p "$run_root/bin" "$run_root/gocache"
source_hashes() {
  rg --files dex scripts/dex reconfig core eth params cmd/cypher cmd/utils commonrpcreward internal node |
    LC_ALL=C sort | xargs sha256sum
}
finish_run() {
  test_result=$?
  trap - EXIT
  set +e
  source_hashes > "$run_root/source-sha256-after.txt"
  diff -u "$run_root/source-sha256.txt" "$run_root/source-sha256-after.txt" > "$run_root/source-during-run.diff"
  source_result=$?
  printf '%s\n' "$test_result" > "$run_root/test-exit-code.txt"
  if [[ "$test_result" == 0 && "$source_result" != 0 ]]; then test_result=3; fi
  printf '%s\n' "$test_result" > "$run_root/run-exit-code.txt"
  if [[ "$test_result" == 0 ]]; then printf 'PASS (%s); retained artifacts: %s\n' "$mode" "$run_root"; fi
  exit "$test_result"
}
trap finish_run EXIT
export GOCACHE="${DEX_TEST_GOCACHE:-$run_root/gocache}" GOPROXY=off GOMAXPROCS=2
printf '%s\n' "$GOCACHE" > "$run_root/go-cache.txt"
printf '%s\n' "$run_root" > "$run_root/artifact-root.txt"
date -u +%FT%TZ > "$run_root/time.txt"
git rev-parse HEAD > "$run_root/head.txt"
git status --porcelain=v1 > "$run_root/status.txt"
git diff --binary > "$run_root/tracked.patch"
go version > "$run_root/go-version.txt"
uname -a > "$run_root/kernel.txt"
source_hashes > "$run_root/source-sha256.txt"
python3 scripts/dex/source_manifest.py "$run_root"
printf 'Artifacts: %s\n' "$run_root"

python3 scripts/dex/codec_vectors.py --check > "$run_root/codec-vectors.log"
python3 scripts/dex/claim_vectors.py --check > "$run_root/claim-vectors.log"
python3 scripts/dex/reference_model.py --check > "$run_root/accounting-vectors.log"
for vector in counter execution finance participation participation_commit engine inbox native_tx native_rolling process transport relay relay_job settlement_bundle continuous continuous_extended continuous_early_final_deposit compact_replay wal_dictionary; do
  python3 "scripts/dex/${vector}_vectors.py" --check > "$run_root/${vector}-vectors.log"
done
python3 scripts/dex/rolling_anchor_golden.py --check > "$run_root/rolling-anchor-vectors.log"
python3 scripts/dex/key_renewal_golden.py --check > "$run_root/key-renewal-vectors.log"
python3 scripts/dex/source_wal_golden.py --check > "$run_root/source-wal-vectors.log"

case "$mode" in
  unit)
    go test -p 1 -mod=readonly -race -count=1 -timeout=5m -json ./dex/... ./reconfig/hotstuff > "$run_root/unit.jsonl" 2> "$run_root/unit.stderr"
    ;;
  process)
    # This command fails rather than falling back to the host network. The test
    # independently checks loopback-only interfaces and absence of external routes.
    unshare -Urn sh -c 'ip link set lo up && exec nice -n 10 env CYPHER_DEX_PROCESS_DEVNET=1 CYPHER_FHS_PROCESS_RECOVERY=1 go test -p 1 -mod=readonly -count=1 -timeout=8m -v ./reconfig -run "^TestDEXAndCLXProcessIsolation$"' > "$run_root/process.log" 2>&1
    ;;
  roles)
    unshare -Urn sh -c 'ip link set lo up && exec nice -n 10 env CYPHER_DEX_ROLE_API_DEVNET=1 go test -p 1 -mod=readonly -count=1 -timeout=5m -v ./eth -run "^TestDEXActualCommonAPIEightCombinationsWithoutPoWDataset$"' > "$run_root/roles.log" 2>&1
    ;;
  native|financial|cli-financial|source|relay|continuous)
    go test -p 1 -mod=readonly -c -o "$run_root/bin/reconfig.test" ./reconfig > "$run_root/build.log" 2>&1
    native_test='^TestFHSNativeDepositRPCFinalityEvidence$'
    if [[ "$mode" == financial ]]; then native_test='^TestFHSNativeFinancialTwoDomainSockets$'; fi
    if [[ "$mode" == source ]]; then native_test='^TestFHSNativeOrdinaryETHSource$'; fi
    if [[ "$mode" == cli-financial || "$mode" == relay || "$mode" == continuous ]]; then
      native_test='^TestFHSNativeFinancialOrdinaryCLI$'
      go build -p 1 -mod=readonly -o "$run_root/bin/cypher" ./cmd/cypher >> "$run_root/build.log" 2>&1
    fi
    if [[ "$mode" == relay ]]; then native_test='^TestFHSNativeContinuousRelayShort$'; fi
    if [[ "$mode" == continuous ]]; then native_test='^TestFHSNativeContinuousOrdinaryCLI$'; fi
    "$run_root/bin/reconfig.test" -test.list="$native_test" > "$run_root/selected-tests.txt"
    if ! rg -q '^Test' "$run_root/selected-tests.txt"; then echo 'Requested test is not implemented in this binary' >&2; exit 2; fi
    # These are newly built test binaries and new namespace/datadirs only.
    test_timeout=15m
    if [[ "$mode" == continuous ]]; then test_timeout=45m; fi
    (cd reconfig && unshare -Urn sh -c 'ip link set lo up && test -z "$(ip route show default)" && exec env CYPHER_FHS_PROCESS_RECOVERY=1 CYPHER_DEX_FINANCIAL_DEVNET=1 CYPHER_DEX_SOURCE_DEVNET=1 CYPHER_DEX_CONTINUOUS_DEVNET=1 CYPHER_DEX_CLI_BINARY="$1/bin/cypher" "$1/bin/reconfig.test" -test.run="$2" -test.v -test.timeout="$3"' sh "$run_root" "$native_test" "$test_timeout") > "$run_root/$mode.log" 2>&1
    ;;
  cli-roles)
    unshare -Urn sh -c 'ip link set lo up && test -z "$(ip route show default)" && exec env CYPHER_DEX_CLI_DEVNET=1 go test -p 1 -mod=readonly -count=1 -timeout=6m -v ./cmd/cypher -run "^(TestDEXNormalCLI|TestG0CommonCLIJournalPathRestart|TestCommonCLIEmptyTrieJournalRestartDEXOff)"' > "$run_root/cli-roles.log" 2>&1
    ;;
  socket)
    unshare -Urn sh -c 'ip link set lo up && test -z "$(ip route show default)" && exec nice -n 10 env CYPHER_DEX_SOCKET_DEVNET=1 CYPHER_DEX_SOURCE_DEVNET=1 go test -p 1 -mod=readonly -race -count=1 -timeout=5m -v ./dex/transport ./dex/service ./dex/service/finance ./dex/service/replication ./dex/devnet/testnet ./dex/clxevidence' > "$run_root/socket.log" 2>&1
    ;;
  baseline)
    go build -p 1 -mod=readonly -o "$run_root/bin/cypher" ./cmd/cypher > "$run_root/build.log" 2>&1
    unshare -Urn sh -c 'ip link set lo up && exec nice -n 10 go test -p 1 -mod=readonly -count=1 -timeout=5m ./commonrpcreward ./params ./consensus/colossusX ./miner ./eth ./reconfig/... ./core/...' > "$run_root/baseline.log" 2>&1
    ;;
esac
