# Continuous late Common helper and independent arithmetic

The O18 helper is implemented in `reconfig/dex_continuous_off_common_test.go`.
It launches a fresh child process with public genesis/key-block/committee data,
adds one ordinary ETH peer, and waits for the normal synchronization scheduler.
The new `follow` dispatch never calls Downloader.Synchronise, InsertChain, or
remove/add-peer refreshes. A stable source head is required. The helper compares
every encoded block and complete receipt, native custody/buckets/inbox, account
count, PoW/CLX role status, and zero financial engine metrics. It then stops its
owned child and checks the same database after a fresh process restart.

The new read-only report allows up to 1024 CLX heights. The legacy helper retains
its 128-height report and existing explicit synchronization semantics. Neither
changes the production 64-header proof limit. Commands remain below 8 MiB and
reports below 16 MiB; report construction accounts for encoded block, receipt and
entry sizes incrementally, and transmission checks the exact final frame size.

Executed compile gate:

```
GOCACHE=/tmp/common-dex-accounting-go-cache GOPROXY=off go test ./reconfig -run '^TestNativeDEXOffCommonProcess$' -count=1 -timeout=90s
ok github.com/cypherium/cypher/reconfig 0.050s
```

The child-only test body is SKIP without its explicit subprocess environment.
This result establishes compilation only. Actual late-join synchronization and
restart through this helper remain NOT_RUN until the continuous network scenario
invokes it and records its own result.

Independent arithmetic executed:

```
python3 scripts/dex/continuous_vectors.py --check
PASS: four cycles, eight periods, inputs345 - withdrawals40 - rewards8 = custody297; T279.664 F0.168 S12.168 I5 Z0; Alice159.796 Bob119.868 CLX
```

`continuous-accounting-reference.json` records every financial action and each
reward period. The script imports the existing independent Python arithmetic
model without editing it or regenerating its goldens. It checks fixed expected
amounts, all eight custody buckets, paired PnL and funding, and preservation of
custody at every step. Odd reward periods collect 0.040 CLX, even periods 0.044;
rho is the existing fixture's one-half and each budget is capped at one CLX.
The first two periods allocate among six equal point holders and the remaining
six among seven, with deterministic remainder distribution by recipient rank.

This calculation assumes authenticated deposits, participation, checkpoints and
native payments. It proves arithmetic consistency only; it does not replace the
real network tests of those assumptions, and excludes gas, which the actual CLX
ledger must reconcile separately. Source digests for the helper and Python
reference are in `continuous-off-common-source.sha256`.
