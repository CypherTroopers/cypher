# Finite action sequences and FHS finality in financial failure tests

2026-09-22. `native-financial-sockets-5.log` reached finalized 25 after stopping 1 node; after stopping 2, all 5 remaining nodes had `Certified=29, Finalized=27`. The test hit its deadline waiting for `Finalized>=28`. This is consistent with stopping input after action 29 while waiting for required descendants, rather than failure to form new QCs.

All 7 saved DEX helper logs for this run were 0 bytes, so its specific QC view numbers could not be reconstructed. The following diagnosis uses code and a minimal reproduction; it does not invent missing metadata for the original run.

## Existing rule and reproduction

`commitAncestors` in `dex/consensus/app.go:714` advances ancestor finality when the tip QC and parent QC differ in view number by 1. Consecutive heights alone are insufficient. The verifier in `dex/checkpoint/proof.go:210` requires the same consecutive-view condition on the final edge of the descendant sequence.

[TestFiniteWorkloadNeedsChildAfterSkippedLeaderViews](../../dex/consensus/finality_gap_test.go) reproduced the following with real FHS managers,5/7 BLS signatures, and WALs.

|Input and failure|Result on 5 running instances|
|---|---|
|Stop delivery to index 5/6, action cap 6, first 5 actions|QC height 5/view 5, finalized 4|
|Pass 2 absent-leader views through valid timeouts|QC height 6/view 8, certified 6, finalized 4. Height 5 cannot be retrieved as finalized|
|Add valid action 7|QC height 7/view 9, finalized 6. Height 5's gapped ancestor proof also passes `Epoch.Verify`|

`go test -race -json ./dex/consensus -run '^TestFiniteWorkloadNeedsChildAfterSkippedLeaderViews$' -count=1` returned PASS, package 5.618 seconds. [Raw results](results/finite-workload-fhs-gap-race.jsonl). No change treats a single QC as finality or alters thresholds/committees/timeout rules.

## Failure fixture change

Each phase in `reconfig/dex_financial_faults_test.go` first waits for certification at the specified height. If the tail's parent remains unfinalized on all target nodes, it adds one signed Noop at each next unused height, stopping after at most 7 additions. Each addition updates `last/next`, aligning checkpoint comparisons and the next 4/3 partition's fresh-action boundary with the actual finalized tail.

Total input remains within fixture `init.MaxHeight<=128`, reserving 24 heights for subsequent economic tests. This neither waits indefinitely for admission to resume nor removes limits. Financial accounting continues checking 225 CLX and 11 CLX reservation invariants.

Record minimal-reproduction PASS separately from full post-fix financial-process PASS. Retain original trial 5 FAIL; do not mark the entire failure phase complete until the full rerun finishes.
