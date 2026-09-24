# Named PM2 finance runner preparation

The original preparation was **PASS(UNIT)** only and used candidate chain
`10101920`; that historical candidate is no longer the authorized generation.
The user's later instruction retains chain ID `10101919` and requires a new
DEX-enabled genesis/deployment. Current tools bind inventory, exact candidate
`genesis.json` SHA256, chain ID, DEX config4, manifest genesis and DEX domain. They
reject the existing DEX-disabled genesis before sending. Init is performed only
by the user under the current instruction; neither these commands nor the offline
plan execute or authorize init. Same-chain ordinary CLX signatures do not bind a
genesis: changing DEX domain alone cannot cryptographically prevent replay of old
ordinary CLX signed TXs. Old local runner intents are rejected by genesis/domain
journal binding; the CLX signature protocol is unchanged.

## Same-chain preparation checkpoint (2026-09-23)

This checkpoint validates only the corrected generation binding and the existing
financial helper/runner unit regression: the offline helper has three passing Go
tests and the Python runner/accounting suite has eight passing tests. The prepared
helper accepts the approved inventory chain ID, including `10101919`, and rejects
mismatched chain IDs, exact genesis SHA256 mismatch, missing DEX configuration and
retired DEX version 3. The new candidate still requires its own offline plan and
the user's init before any LIVE finance result can exist.

The working tree also preserves unfinished measurement preparation:

- `cmd/dex-live-source-observer`: read-only wrapper around the existing relay
  source verifier, with a dedicated proof journal. Request-bound unit checks and
  compile passed; full candidate startup, network authentication, cold recovery
  and account proof delivery are **NOT_RUN**.
- `scripts/dex/live_finance_load.py`: A/B/C scheduled ordinary-transfer injector
  and latency/resource output is **WIP / NOT_RUN**, not an accepted load runner.
  No LIVE traffic, A/B/C comparison or 60-minute run was performed.
- `fund-wallets` separates wallet funding from native deposits. Optional
  `--observer` adds authenticated native reserve checks to drain. These new
  connections have not yet received focused behavioral or LIVE tests; neither
  should be treated as a completed Q4/Q5 gate.

The same-chain helper normal binary and current source hashes are recorded in
`finance-helper-same-chain-manifest.json` under the latest public results. No
cypher production code, PM2 process, live balance or node database was changed by
this preparation. These helper additions do not gate the user's genesis preparation.

The existing FIFO position, cash/PnL, funding/dust and reward execution is reused.
`cmd/dex-live-finance` is a pure offline codec/signature/proof helper. It has no RPC,
StateDB or PM2 handle. It loads only test trader/oracle/support/insurance keys when
signing is requested; it does not load DEX vote keys or reward-recipient keys.
`--mode` is not an option: `plan`, `fund-wallets`, `fund`, `drive`, and `drain` are positional modes.

## Entrypoints prepared

```
GOMAXPROCS=2 GOFLAGS=-p=1 GOPROXY=off go build -mod=readonly -o build/stage/dex-live-finance ./cmd/dex-live-finance
python3 scripts/dex/live_finance.py plan --helper build/stage/dex-live-finance --output build/stage/live-finance-RUN_ID
```

After approved generation activation, normal auth/startup, and separate resource
verification, the prepared LIVE commands are:

```
python3 scripts/dex/live_finance.py fund --execute --helper build/stage/dex-live-finance --output build/stage/live-finance-RUN_ID
python3 scripts/dex/live_finance.py drive --execute --seconds 3600 --interval 10 --helper build/stage/dex-live-finance --output build/stage/live-finance-RUN_ID
python3 scripts/dex/live_finance_accounting.py --run build/stage/live-finance-RUN_ID --candidate build/stage/live-generation-candidate --helper build/stage/dex-live-finance --decoder build/stage/dex-block-audit
```

The output directory must be a dedicated private `build/stage/live-finance-*` or
`/tmp/live-finance-*` directory, with matching ownership/generation marker. A
nonempty unowned directory, symlink traversal or second locked runner is rejected.

The normal funding plan totals 254 CLX: trader A/B 105 each, support owner 21,
insurance owner 6, synthetic oracle 1, each checkpoint relay payer 6, and each
anchor/claim relay payer 1. Initial native deposits are 200 trader + 20 support +
5 insurance. The runner may add at most four 0.1 CLX deposits at 64-height intervals.
These additional deposits are funded from the existing allocated trader wallet,
not fresh issuance or balance edits. Relay gas is paid from its separate six lanes.

The runner signs the existing funding owner through committee0 IPC and sends all
CLX TX through the Common HTTP admission path. It records business ID, exact signed
TX bytes, sender nonce and economics with fsync before send. Pending nonce windows
are limited to owned recorded transactions; unknown pending nonce activity stops
new signing. ACK, mempool knowledge and canonical receipt are separately labeled.
A bounded ordinary one-atom transfer can supply needed CLX descendants when the
head stops. The runner never writes a canonical root or uses a fixture proof flag.

The read-only `/v1/certified?height=...` API returns a bounded existing QC/record with
`Stage=certified`, `Finality=not_asserted`, `CLXSettlement=separate`. The helper
verifies domain, schema5, QC quorum, reference, action commitment and state root.
This is used only to schedule the next action. `/v1/checkpoint` supplies the actual
FHS descendant finality proof and authenticated state for close packages and drain.

Participation is gathered from the declared registered active nodes, checked
against the certified target, and committed by an ordinary signed DEX action.
Reward close uses the exact committed certificates and 11 authenticated finalized
block witnesses. `--active-indices 0,1,2,3,4` can explicitly describe a planned
five-node stop test; it never changes the quorum. Nodes are not silently removed
from the expected participant set after an error.

The driver performs repeated 0.01 BTC/CLX opens, real funding across the ten-block
boundary, flat close, 0.01 CLX withdrawal and sequential reward close. Prices are
synthetic 100 CLX/BTC. It does not construct a new FROZEN recovery policy. New input
has finite action, TX, gas, memory, disk and duration budgets. `STOP_INPUT` preserves
the journal; operator recovery can invoke `drain` separately. Stateless helper
processes rotate before 32 MiB/1000 requests, preserving their per-process decode
limits without restarting any validator or changing vote state.

Drain advances at most eight ordinary DEX noop descendants, verifies DEX finality,
and waits a finite interval for both relays' authenticated acceptance observations.
It leaves certified-only trailing descendants explicit. Local relay status is
reported as an observation of the relay's formal authentication, not a new trust
root. The final canonical native ledger separately checks every TX, receipt,
issuance, gas, Common reward, burn, bucket movement, native claim and nullifier.
Unknown EVM calls reject this ledger rather than being modeled as plain transfers.
It reuses the formal native codec and `dex-block-audit` header issuance decoder.

## Remaining LIVE gates and limitations

- The candidate generation is not running; all `fund/drive/drain/audit` network
  outcomes remain **NOT_RUN**. The init decision and PM2 procedure belong to the
  main operator.
- Q4 fault orchestration, planned PM2 stops/restarts, DEX route delay and process
  observations are not implemented in this runner. Use the named project control
  tools and retain their event records. The runner does not touch PM2 or firewall.
- A/B/C arrival-load comparison and p50/p95/p99 analysis have unverified WIP
  source only, as listed above. EVM workload accounting remains
  **NOT_IMPLEMENTED**. Action timestamps are raw measurements only.
- The driver records observed storage generations and the auditor compares all 14
  CLX process roots, receipts/gas and native projection, zero heavy-engine counters,
  and all seven DEX finalized roots/proofs. These comparisons are implemented but
  NOT_RUN against LIVE. Late Common cold synchronization and crash-boundary
  verification still require the independent process tests. Elapsed 60 minutes or
  observed counters alone do not set L15 to PASS.
- Concurrent automatic inbox work is reconciled over at most eight authenticated
  certified records. The exact signed action must occur, its actual parent must
  connect, and existing execution must reproduce its root. No nonce or state is
  patched. A longer gap or rejected action preserves the pending intent and stops;
  this race/restart connection is implemented but still requires LIVE validation.
- An action-only terminal market position can remain open. The report records
  `phase_at_input_stop`; native reserves, open lots, certified tail and unpaid claims
  must be reconciled before any overall acceptance statement.
- Independent CLX FHS authentication remains the relay/DEX source verifier's
  responsibility. Canonical IPC/RPC ledger observations alone are not a validity
  proof, DA guarantee, or independent financial safety audit.

The final runner must be rerun against the actual deployed source. Preparation
PASS must not be copied to L08, L09, L13, L15 or a complete Q4/Q5 verdict.

## Short LIVE financial run preparation (2026-09-23, subsequent turn)

The current candidate was checked offline: chain `10101919`, CLX genesis
`a4a61fa952509cde79c14e152702a1d7dea1cc0320b4552566b2efb9e4a575de`, DEX ID
`433b712c48506710a611d48e351ff827d00e64941fff9c085817c266585af497`, financial
state 6 / execution schema 5. This check does not itself show deployment or TX
success. The primary operator owns all LIVE funding, PM2 and scenario execution.
No init is part of these commands.

The helper's native projection requires 17 storage slots, below the existing
32-slot proof limit. Source cold catch-up counts **segments**, not absolute block
height: at most 32 headers per segment, at most 1024 retained segments, and 32 MiB
source WAL. A head above 1024 therefore does not alone exceed this cap. Every
intermediate segment must authenticate from genesis; missing history stops it.
DEX-enabled genesis reserves custody with nonce 1, so zero-inbox evidence can
exist before the first deposit.

Prepared initial sequence (run once from the same journal, after live generation,
admission/signers, seven sidecars and two relays have been checked):

```
python3 scripts/dex/live_finance.py plan --helper /tmp/common-dex-live-test.x5z_05oq/dex-live-finance --output build/stage/live-finance-20260923-smoke
python3 scripts/dex/live_finance.py fund-wallets --execute --helper /tmp/common-dex-live-test.x5z_05oq/dex-live-finance --output build/stage/live-finance-20260923-smoke
python3 scripts/dex/live_finance.py fund --execute --helper /tmp/common-dex-live-test.x5z_05oq/dex-live-finance --output build/stage/live-finance-20260923-smoke
python3 scripts/dex/live_finance.py drive --execute --seconds 300 --interval 5 --helper /tmp/common-dex-live-test.x5z_05oq/dex-live-finance --observer /tmp/common-dex-live-test.x5z_05oq/dex-live-source-observer --output build/stage/live-finance-20260923-smoke
python3 scripts/dex/live_finance_accounting.py --run build/stage/live-finance-20260923-smoke --candidate build/stage/live-generation-candidate --helper /tmp/common-dex-live-test.x5z_05oq/dex-live-finance --observer /tmp/common-dex-live-test.x5z_05oq/dex-live-source-observer --decoder /tmp/common-dex-live-test.x5z_05oq/dex-block-audit
```

`fund` reuses the exact already-recorded wallet-funding transactions; it does not
add another 254 CLX. The drive request stops new scheduled input after 300 seconds,
then finishes only an already-open ordinary cycle within 32 actions. Existing
funding/oracle/participation rules still apply. It never creates a new cycle during
drain or changes FROZEN recovery. Certification time means the actual count can be
less than 60 new actions. The expected functionality must be checked from the
resulting records: fills, funding with positions, committed participation, reward
close and paid withdrawal/reward claims cannot be inferred from elapsed time.

Drain checks fresh authenticated relay sequence observations and no incomplete
jobs, then independently authenticates a CLX custody/storage proof with zero
withdrawal/reward reservations. The ledger endpoint is that exact authenticated
height/hash/state root, never an unrelated RPC latest block. The auditor reopens
the observer proof journal and verifies both endpoint anchors, initial/final
native projections, every paid nullifier and every changed wallet's start/end
balance proofs. Its ordinary TX/receipt/RLP decoder still recomputes native bucket
flows, gas, Common rewards, burn and existing CLX static issuance. The exact
recipient and proof authentication do not claim calculation validity beyond the
specified committee trust model.

Use the same journal for later extension. A later audit must select a fresh
`--output-name accounting-60min` (or another explicit label), preserving the first
result. The 300-second run is not the required 60-minute or two-storage-cut run.
A/B/C injector and process fault orchestration remain separate, unverified gates.
Budgets remain 254 CLX wallet allocation, 225 CLX initial custody, at most 0.4 CLX
additional trader deposits from those wallets, at most 1 CLX runner gas reservation,
1024 runner TX / 512 actions, memory floor 4 GiB, disk floor 2 GiB. Relay lane gas
is separately funded and accounted. Short-run LIVE results belong in the primary
operator's scenario log; unit and preparation results below do not substitute.

Observed preparation fixes during the short LIVE attempt:

- The first `dex_certified` event raised a Python argument collision because
  `kind` named both the event parameter and action payload. The action had already
  been durably recorded. `event_type` now names the event parameter; recorded
  signed actions/nonce/phase are retained, and a focused regression covers it.
  The primary operator retains the original failed LIVE log.
- Participation commit originally ran only at height 6/16/etc. Concurrent source
  updates or drain descendants can consume those heights. The runner now checks
  authenticated parent participation and commits its selected height-5 duty later
  within the unchanged `period*10+4` deadline. It keeps the existing two-open-period
  bound and rejects missing evidence after the deadline. Drain performs necessary
  oracle/funding/participation maintenance without opening another trade or
  reserving a new reward period just to produce descendants. Cumulative transport
  error counters are retained as observations; every certificate still must pass
  the registry verifier, exact certified target and declared participant set.
- Final Python preparation regression: **15 tests PASS(UNIT)**. The read-only
  observer ownership/bounds suite has four passing top-level tests; two foreign
  UID fault cases are **NOT_RUN** because the sandbox maps only UID 0. Initial
  fixture `chown` failures are preserved separately, not rewritten as PASS.

A/B/C remains unfinished: using the same output concurrently conflicts with the
run lock. Separate outputs avoid that lock but their shared funding-owner control
TX nonce would conflict with the financial driver. An independent control sender
or one control coordinator is required before simultaneous B/C injection. The
current single-loop observer also adds measurable sending lateness; this is not a
validated high-rate injector. None of these unexecuted measurements is a LIVE PASS.

## Bounded A/B/C entrance after control-sender fix

The identified control-nonce collision is now fixed in the preparation source.
`Runner.control_purpose` defaults to the original financial funding owner. Only
the load tool selects `synthetic-oracle`, an already-funded test wallet, for its
ordinary CLX scheduled and descendant-control transactions. All its exact TX
bytes/nonces share a separate durable load journal. DEX oracle action nonces are
separate from CLX TX nonces. A journal with financial funding/actions or a different
recorded control sender is rejected. No existing normal CLX signature or nonce
rule changes.

Example low-rate phase, to be executed only by the primary operator after the
short financial scenario and the declared phase conditions are established:

```
python3 scripts/dex/live_finance_load.py --phase A --execute --candidate build/stage/live-generation-candidate --helper /tmp/common-dex-live-test.x5z_05oq/dex-live-finance --observer /tmp/common-dex-live-test.x5z_05oq/dex-live-source-observer --decoder /tmp/common-dex-live-test.x5z_05oq/dex-block-audit --output build/stage/live-finance-20260923-load --seconds 120 --interval 10
```

Use that same separate load output for sequential phases B and C. A's relays and
financial input are stopped by the primary operator; B and C retain the same
10-second ordinary arrival schedule while financial input runs separately. The
load command never stops/starts services itself. Its sender remains distinct from
the financial runner's control sender. No extra wallet funding is implicit.

The injector preserves a predetermined schedule, every rejected/unresolved entry,
sending lateness and completed-request p50/p95/p99. Its single synchronous proof
observer can delay sends, which is explicitly reported; this is a low-rate
comparison, not demonstrated maximum network throughput. Finality is authenticated
from source genesis, and the real committed body must contain each finalized TX.
Canonical receipt gas/Common/burn costs are reported separately for scheduled TX
and that phase's descendant controls, including reverted TX. Missing receipts stay
explicit. These receipt costs remain canonical observations; the full financial
ledger remains a separate audit. CPU/RSS/I/O sampling and proof-observer work occur
inside the measurement window and must be included in its limitations.

Preparation verification is **20 Python tests PASS(UNIT)** plus a current-candidate
no-network offline load plan. A/B/C LIVE results, calibration, actual performance
acceptance and 60-minute mixed operation are still **NOT_RUN** in this preparation
record. Every completed phase reports `MEASURED_PERFORMANCE_ACCEPTANCE_UNJUDGED`;
no threshold or performance superiority is inferred after seeing its results.

## Short-run failures and partial-accounting boundary

The subsequent real-network attempt exposed a runner assumption: seven online
validators need not have signed the same view at a given height. The observed
height-15 votes spanned views 147 and 148. Collection now queries every declared
available node, verifies each certificate against the exact selected certified
target, and uses the union of all observed valid participants (5–7). It does not
create votes for other online nodes or mix certificates from another view. While
the original deadline remains open, newly observed valid duties are added to
committed participation. General delivery fairness remains unproved.

The client helper orders close certificates by height/participant and filters the
committed set against the actual authenticated finality witnesses before invoking
`Registry.CheckCommittedClose`. It does not discard eligible committed duties or
pay orphan duties. A real close still requires the existing finalized block and
grace witnesses. This helper preparation does not repair the separately diagnosed
DEX FHS finality stall. No new financial input is justified until that issue has a
reviewed recovery path; no WAL reset or proof-bound enlargement is used here.

`live_finance_accounting.py --partial --output-name accounting-partial-r1` supports
an independent report when the financial run has not drained. It obtains a CLX
endpoint through the source finality verifier, verifies the complete ordinary
CLX interval and its account/storage proofs, then records actual DEX certified
and finalized values separately. It never writes runner `journal.json`, its end,
completion status, nonce or business records. Its output is
`accounting-partial-r1/partial-accounting.json`; a successful interval check is
`PASS_PARTIAL_AUTHENTICATED_ACCOUNTING`, not successful DEX trading, finality,
checkpoint settlement, paid claims or a complete Q4/Q5 result.

Current final preparation: 23 Python tests and four offline-helper Go tests PASS.
The helper is `/tmp/common-dex-live-test.x5z_05oq/dex-live-finance-r3` with SHA256
`50d28b86104c49679972eedbd1357ea94a42ae92c09d372458a380f79076e696`.
The previous helper and failed LIVE attempt logs remain retained. Current LIVE
facts and the eventual partial ledger belong to the separately recorded primary
operator run, not to these unit counts.

## Authenticated partial live ledger, 2026-09-23

The read-only audit completed for CLX heights **1057–1121**. Its raw files are
retained under `results/live/20260923-active-finance/accounting/`. The first audit
attempt rejected a relative observer directory before reading network data. The
wrapper now converts paths to absolute paths without resolving away symlinks;
the observer's ownership and symlink checks remain active. The final focused
Python suite has **24 PASS(UNIT)** tests. The helper binary remains the r3 hash
listed above. No normal node binary or financial state-transition rule changed.

The authenticated endpoint is block
`0xf6b0428aa9fcd443ba9d96ddfb8c8f96c52bab818075c08890f210c9c40265cb`,
state root
`0x87adc3f1c979f299969635f9167189edc182d4379edaebe2077ef2ed9f6ad3e4`.
The genesis-linked CLX source verifier authenticated this endpoint. The decoder
checked actual block RLP hashes, transaction trie commitments and the intervening
ancestry; account/storage MPT proofs authenticated native custody, bucket values
and all 20 changed wallet deltas. RPC receipt identity, gas, logs and accounting
were consistency-checked, including 14-node receipt-root equality. **The auditor
did not independently reconstruct the receipt trie.**

The partial ledger contains 225 CLX in custody: 200 CLX of uncredited trader
deposits, 20 CLX support and 5 CLX insurance. All other buckets and surplus are
zero. Accepted DEX sequence and paid claims are zero. In CLX atoms, gas is
`1611400000000000`, Common RPC reward is `322280000000000`, and burn is
`1289120000000000`. Existing CLX block issuance is separately accounted as
`3100000000000000000000000` atoms; it is not DEX revenue or new DEX issuance.

All 14 CLX processes agree on the endpoint hash/root/receipt root/gas/native
projection and report zero heavy-engine instances, actions and inbox imports.
The ordinary one-atom transaction
`0x854ebddf8fa239390850bb85757cbcfb711255e4b8fd897f5f594ac31d985c48`,
submitted by the primary operator while all seven DEX sidecars were stopped,
is included in authenticated block 1121. This establishes that limited CLX
progress condition, not a completed DEX financial scenario.

All seven DEX nodes remain certified 15, finalized 0, inbox cursor 0. No DEX
credit, fills, fee accounting, reward reservation, checkpoint acceptance or claim
payment is demonstrated by this run. The FHS finality stall remains unresolved;
no proof bound, vote WAL, deadline, balance or quorum was changed to bypass it.
The financial journal remained byte-identical across the audit (SHA256
`4db02852e2bd7a9522683929caa64185593eb90163f6c50cc79f1a2a01f197ef`)
and remains `STOPPED_WITH_JOURNAL_PRESERVED`.

The raw r2 result's generic `scope` text incorrectly mentions DEX finality,
although its explicit DEX observations report finalized 0. That historical raw
result is preserved. `scope-correction.json` records the narrower interpretation;
the reporting source now states partial native accounting and certified-only DEX
observation, with the receipt-proof limitation. This is a label correction after
the run, not an additional live test. A/B/C, 60-minute finance, actual claims and
two live storage-generation switches remain NOT_RUN or blocked by finality.
