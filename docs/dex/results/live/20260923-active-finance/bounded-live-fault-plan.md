# Same-generation LIVE fault plan — prepared, NOT_RUN

Read-only source review. This document executed no PM2 operation, signal, transaction, key loading, init or DB mutation. Root operator owns all live operations.

## Fixed inputs

- Network chain 10101919; genesis `0xa4a61fa952509cde79c14e152702a1d7dea1cc0320b4552566b2efb9e4a575de`.
- Retain the existing private journal `build/stage/live-finance-20260923-smoke/journal.json`, its OWNER/LOCK, events and source-observer directory. Never call fund with a new journal to continue this run.
- Existing CLI modes are exactly `plan`, `fund-wallets`, `fund`, `drive`, `drain`. Existing `--active-indices` accepts 5..7 registered indices and does not change quorum five.
- Helpers: `/tmp/common-dex-live-test.x5z_05oq/dex-live-finance`, `dex-live-source-observer`, `dex-block-audit`.
- Relay0 alone has AutoInbox=true, targets API19000. Relay1 AutoInbox=false targets API19001. Both submit/source at Common8999. Keep endpoints0/1 alive in minority-stop phases.
- Current v4 manifests have every-height participation, fixed epoch1, max4096, seven unique members, 256MiB participant archive budget. Do not edit manifest, receipt deadlines or quorum for a stop.

## Gate before any fault

1. Fix/retest the observed `Runner.event(kind, **values)` versus `kind=item["kind"]` TypeError. The initial action was already certified and the journal transition persisted before that logging exception. Resume the same journal; do not recreate its pending intent or reset nonce.
2. Finish the current short drive/drain with all seven. Verify authenticated native projection, accepted sequence and nullifiers rather than HTTP ACK. Save a reference DEX finalized checkpoint/root and all seven matching projections at that height. Record certified trailing descendants separately.
3. End the existing runner and release its LOCK before running another mode. At most one writer owns this journal and source observer. Do not start the A/B/C load driver concurrently on this same output.
4. Record PM2 name/id, boot ID, parent and sidecar PID/start ticks/exe hash, exact manifest/datadir, and initial relay status. Recheck identities immediately before each signal. Record available memory/disk and remaining sender/relay lane funds.
5. Keep all keys, hot WAL, archives, collector safety pins, nullifiers, relay signed TX and nonce state. No init, copying another vote key, snapshot reset, or manual head repair.

## Phase 1: one, then two participants stopped

Status: NOT_RUN. Root stops **cypherdex6** by its PM2 name, verifies both parent and its owned DEX child exited, and no datadir writer remains. Run existing drive with `--seconds 60 --interval 10 --active-indices 0,1,2,3,4,5`, the original --output, --execute, helper and observer. Keep Common0/1 and both relays alive. Wait for actual new finalized/CLX-accepted checkpoints and financial actions; a stationary status is not progress.

After this bounded run/drain ends, stop **cypherdex5** identically. Run the same mode with `--active-indices 0,1,2,3,4` for 60 seconds. Five remaining registered participants must form normal five-signer evidence. Never reduce the threshold.

Root resumes in reverse stop order: cypherdex5 then cypherdex6, using the same datadirs and keys. Wait at most180s for cold WAL replay, registered/synced status and the same authenticated checkpoint root. Do not include a rejoining index in the driver's active set until it catches up. If unavailable historical data or receipt errors prevent convergence, preserve the failed phase and report it; do not silently treat all seven as active.

## Phase 2: relay restart and retained work

Status: NOT_RUN. After all seven have caught up, stop relay1 by exact PM2 name; let relay0 continue a bounded 30-second drive, then stop new input. Record target finalized sequence and actual native accepted sequence. Restart relay1 from its existing directory, wait up to180s for its own authenticated status and same persisted jobs to reconcile. Then repeat one relay0 restart only while relay1 remains up and no new CLX deposit is pending (relay1 does not auto-import inbox). Resume relay0 before submitting any new deposit. No source directory copying or nonce reset.

This checks cold resume and competing discovery, but normal dedup can avoid sending a duplicate paid TX. It is not evidence of explicit claim-resubmission execution. A separate bounded, persisted signed native claim replay is required for that assertion.

## Phase 3: all DEX stopped, ordinary CLX continues

Status: NOT_RUN. Do **not** PM2-stop all seven Commons: that removes the sole Common admission endpoint8999. Minimal topology-preserving test: stop both relays and the financial driver first; then signal only the seven verified, currently owned `dex-validator` child handles, indices6..0, leaving all Common parents alive. Sidecar supervisor does not automatically respawn an exited child. Require all seven API endpoints unavailable and owned children exited, while parent Common8999 and committee7 remain alive.

Existing `live_finance_load.py --phase A --seconds 30 --interval 10 --execute` can then send exactly3 scheduled ordinary 1-atom transfers from the funded synthetic-oracle wallet through8999, with the same helper/observer/decoder/output. It does not query DEX APIs. Use only if that output's A directory does not already exist; never remove an old A result. This preserves signed sender intents in the existing journal. Account for any bounded control descendants separately. The old `live_clx_smoke.py` is genesis-fixed to the old network and must not be reused here.

Require authenticated source header progress and included ordinary TXs, with unchanged native accepted sequence/reserves/nullifiers except any already-in-flight settlement explicitly identified. This test submits no unsupported withdrawal.

Restore by named Common parent restarts, indices0..6, never by a second sidecar owner. After cyphermine restarts, restore only its unlock/reward registration as needed, not whole committee auth. Verify seven children and cold state, then restart relay0 and relay1. Preserve all directories.

## Phase 4: CLX planned stop and later DEX settlement

Status: NOT_IMPLEMENTED in current generic drive mode; needs a small bounded coordinator, not a new trust path.

Current drive's startup preflight requires every committee IPC. During a CLX stop its control() tries committee0 IPC signing after five seconds of no CLX-head progress. Therefore an unmodified drive cannot reliably exercise this scenario; an early exception is a preserved failure, not a pass.

A coordinator may acquire the same journal/observer lock, perform ordinary preflight while CLX is online, verify phase0/no pending action/funding/no imminent64-boundary deposit, and then wait for root's observed stop event. Root stops only committee PM2 names cypher6..cypher0, after recording handles, leaving Common7/DEX7 and relay state intact. No miner.stop and no init.

While stopped, coordinator can use existing certified/economic_step/submit methods for **at most4 signed DEX actions within45s**, without calling CLX tx/control/fund or pretending to drain. Preserve normal oracle/funding/participation/reward rules. Record authenticated DEX finalized growth and native accepted staying at the previously authenticated value; certify-only tail does not count. Fail rather than change FROZEN, deadlines, oracle freshness or reward evidence.

Root restarts committee apps on the same DB, then normal `live_auth restore --generation-inventory ...` is appropriate here because committee miner/FHS start is intentionally required. It also unlocks Common; never publish credentials. This is different from minority/sidecar phases, which must not call whole restore.

Resume existing normal drive/drain only after source Common observes normal sync and source proof authentication resumes. Require **CLX accepted > pre-stop sequence** and at least the saved DEX finalized target, independently proven native reserves/claims, unchanged duplicate/nullifier accounting, and matching all committee roots. Relay ACK or current latest height is insufficient.

## Budgets and stop conditions

- Additional minority-phase scheduled actions: approximately6 per60s at10s interval, but each drive also performs at most32 existing-cycle steps plus8 descendant steps. Capture actual counts; do not call this fixed6-action work.
- Existing total hard limits remain512 signed DEX actions,1024 runner TXs,1CLX runner gas reservation,4 pending control TXs,8 owned sender pending nonces,8MiB journal/64MiB events. Planned faults stop before fewer than128 actions or32 TX slots remain; no cap increase.
- At1gwei with each relay lane GasLimit20M, worst gas reservation is0.02CLX per native attempt. Check both checkpoint lane balances against planned checkpoint count plus retry headroom before the phase; actual gas goes into the independent ledger. No custody gas funding.
- Native initial funding225 and total wallet funding254 are historical inputs, not expected final balances. Repeat deposits, withdrawals, fee/support rewards, insurance, dust, surplus, gas/Common reward/burn and outstanding reserves are recomputed from this run.
- Driver collects authenticated participation for the declared active set and equal certificate sets. Missing/late evidence stops that reward-close path; do not lower required set, invent after-deadline participation or erase committed rights.
- Keep synthetic BTC/CLX oracle definition; funding height and ValidUntil use DEX state. Resource floor4GiB MemAvailable/2GiB free disk remains. Stop new input on pressure, no host configuration changes.
- Every wait is event-driven with a finite deadline (DEX certification60s, certificate collection45s, transaction receipt120s, drain180s). Record exact timeout and preserved state instead of merely increasing sleep.

## Process and result accounting

For whole-system planned shutdown, stop new-input worker, relays, owned sidecar children, then the specifically selected parent processes. For minority PM2 stop, normal parent supervisor may gracefully stop its own child; poll both handles to exit. PID reuse or a changed start tick aborts signaling. Stop PM2 by name so autorestart cannot erase fault conditions; direct child stop is deliberate only when the parent must remain up. Startup is reverse dependency order, followed by authentication and proof checks.

Each phase logs before/after CLX height/hash/root, DEX certified/finalized/accepted, inbox cursor, native buckets/W/R reserves, nullable pending action, jobs/nonce stages, process handles and stop/restart outcome. SIGTERM/graceful and timeout/SIGKILL are separate observations. No disk/power-failure claim follows from a process kill.

This plan does not implement partition, permanent DA loss, explicit paid-claim replay, >2 storage cuts, 60-minute operation, WAN, PoW or FROZEN recovery. Those remain separate gates.
