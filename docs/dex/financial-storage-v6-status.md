# Financial storage v6 — implementation and scoped results

2026-09-23. **PASS(UNIT); LIVE NOT_RUN.** Specification:
[financial-storage-v6-spec.md](financial-storage-v6-spec.md). This change selects
new financial state v6 only through authenticated generation-v4 configuration,
manifest v2 and execution schema 5. Existing v2/v3 genesis financial fixtures
retain their codec and arithmetic.

Implemented:

- Bounded sparse fee-period totals, sequential closed-period hash and total,
  last-block fee binding, and equality to engine.PeriodFees. Maximum 16 distinct
  unclosed nonzero-fee periods; zero-fee work remains possible when reward close
  is delayed. Closing an authenticated period releases only that period's hot
  entry. FIFO, PnL, funding/dust, support formula and claim amounts are unchanged.
- Snapshot canonical state/height/root validation for consensus storage cuts.
- Continuous, finite every-height receipt duties within the manifest's absolute
  operating height; finite historical ReceiptHeights fixtures remain distinct.
- Collector retirement only with authenticated descendant-finality checkpoint
  for the next reward period. Immutable bounded archives retain receipts,
  certificates (including locally known omitted certificates), local-close
  diagnostics, target references and finality proof. Hot WAL preserves LastVote,
  previous RecoveryVote, both targets, ClosedThrough and all unclosed evidence.
- Archive fsync and directory sync precede active retirement frontier publication.
  A fixed RETIRE.next staging inode is reclaimed only after authoritative WAL
  and referenced archives validate. Missing/corrupt authoritative data fails
  closed. Existing markers/checksum alone do not authorize a new period.
- `/v1/participation?height=...` now reports hot/archive retention and bounded
  storage counters. It does not declare archived certificates newly payable.

Final scoped verification is recorded in
[summary.json](results/live/financial-storage-v6/summary.json) and its
[source manifest](results/live/financial-storage-v6/source-manifest.sha256).

|Verification|Result|Evidence|
|---|---|---|
|rewards/devnet/replication/finance race suites|PASS(UNIT), 4 packages, 32 top-level / 88 test pass events|[race JSONL](results/live/financial-storage-v6/final-race-2.jsonl)|
|v6 authenticated CLX header + MPT import, 320 actions, 64-height cold replay, snapshot rejection|PASS(UNIT), 1 top-level / 5 pass events under race|[v6 race JSONL](results/live/financial-storage-v6/final-continuous-race.jsonl)|
|Original 7-FHS financial 225→214 fixture|PASS(UNIT), included in devnet race suite|`TestNativeCLXFinancialFHSScenario` in race JSONL|
|Independent fee model|PASS(UNIT), 320 blocks / 31 closes|`python3 scripts/dex/financial_storage_reference.py --check` and `TestFinancialV6IndependentFeeHistory320`|
|Collector two retirements, pre/post frontier crash, old vote pin, lost/tampered data, bounded staging recovery|PASS(UNIT)|`TestCollector*Retirement*`, `TestCollectorRetiredPinSurvivesCollectorAheadOfFHS` in race JSONL|
|Replication envelope mutation fuzz|PASS(UNIT), 5 seconds, 25,375 executions|[fuzz log](results/live/financial-storage-v6/final-fuzz.log)|
|Specified PM2 generation-v4 financial network / two storage cuts / 60 minutes|NOT_RUN by this component task|Requires root-runner deployment and approved generation transition|

An intermediate build failure is retained in `attempt2.log`: the concurrently
edited consensus generation file temporarily referenced a missing field. The
storage owner completed that edit before final tests; this is not classified as
a remaining financial failure. Earlier logs are not substituted for final
source results. The final whole-worktree regression remains the root task's
responsibility after all parallel edits finish.

Archive totals remain finite: collector 1024 retired periods / 128 MiB and each
archive at most 2 MiB; hot WAL 2048 records / 2 MiB. The CLX generation's lifetime
checkpoint/inbox quotas are separate limits. Reaching a retention budget does
not erase claim rights, receipts, safety records or balances. General reward
inclusion fairness, FROZEN loss allocation, public epoch transitions, real
Oracle safety, performance and LIVE fault recovery are not established by these
component tests. Go race covers exercised Go paths, not all C BLS behavior.
