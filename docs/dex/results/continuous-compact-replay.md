# Compact replay focused gate

2026-09-22: `go test -race -json -p 1 -mod=readonly ./dex/consensus
./dex/clxevidence ./dex/service/finance ./dex/devnet -count=1 -timeout=5m`
PASS: 4 packages, 56 top-level test passes, 180 subtest passes, 9 optional
socket/network tests skipped without their opt-in environment. These skips are
NOT_RUN, not transport passes. Raw: continuous-compact-focused-race.jsonl.

Rolling WAL/snapshot Version2 removes only old finalized State copies.
Tests reconstruct every old state, keep the local vote watermark, reject a
conflicting restarted vote, bootstrap another registered identity without
copying vote history, and read/verify old full Version1 before the local upgrade.
Checksum-valid changed action/root/ref/QC/finality, missing parent, altered tip
state, forbidden omissions, wrong version/schema fail. Independent structural
checksum/selection golden and unchanged 2MiB/128 limits pass.

The legacy financial suite in this focused run includes 225→214. This is an
in-process financial regression, not the final ordinary CLI/network retest.
Additional review and final whole-diff runs remain required. Race detection is
limited to executed Go paths and does not establish C BLS or financial safety.


A later complete `./dex/consensus -race -json -count=1 -timeout=5m` run passed
in 98.073s (continuous-compact-complete-race.jsonl), including the strengthened
same-view consistent-vote, real timeout/TC/outbox, canonical v2 JSON, bounded
aggregate reconstruction and owned WAL temporary-file crash tests. The aggregate
fixture supplies real 5/7 signatures and valid descendant proofs in a wire file
below 2MiB; reconstruction exceeding 2MiB fails without publishing partial state.
The 5-record control is accepted. This is still a component checkpoint before
all final frozen-source regression modes.
