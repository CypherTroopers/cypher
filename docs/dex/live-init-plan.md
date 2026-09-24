# Init preparation for the specified real network — current procedure and historical record

## Currently applicable procedure (corrective instruction dated 2026-09-23)

**Retain CLX chain ID `10101919`. Update the current `genesis.json` and preparation materials; the user personally performs init and restart. Stopping, init, and restarting are outside this preparation work.** Do not use the old `10101920` candidate, old plan, or old approval for this operation.

See the [same-chain-ID genesis preparation record](live-same-chain-genesis-preparation.md) for current settings, candidate inventory, genesis hash, DEX domain, validation results, and next user operations. This latest preparation record and the corrective instruction above take precedence over the old plan retained below.

1. Preserve the chain ID, existing CLX committee, and alloc in `genesis.json`, and align the new DEX configuration, voting identities, and domain. Validate genesis and inventory through the canonical Go paths.
2. Present the prepared configuration and its hash. Creating these materials or validating candidates alone does not establish that the real DB has entered a new generation.
3. The user performs init and restart. Do not proceed to delete old data or run an automatic switch executor as part of preparation.
4. After the user's re-init, observe that the real DB's block zero and chain ID match the candidate inventory before handling active DEX role/relay selection. Do not accept an old DB merely because its chain ID matches. See [pre-launch checks](live-same-chain-launch-bindings.md) for details.

**With the same chain ID, old ordinary signed CLX TXs may be replayable.** A new genesis hash and DEX domain bind DEX evidence to the generation but do not change ordinary CLX TX signature rules. Operationally excluding old raw TXs, nonces, and ingress/relay queues is not a cryptographic proof of replay prevention. Distinguish key preservation from importing old nonces, DBs, and voting/payment history into a new generation. Erasing safety history during a restart of the same current generation is not authorized.

## Historical record of the superseded plan

References in the old text to "new chain ID required," "reject old chain ID reuse," "awaiting intermediate-init approval," and "automated stop/archive/init/start" describe design and test conditions at that time; they are not instructions for this operation. Statements about the state of `genesis` and implementation scope also reflect observations at that time. Preserve old PASS/FAIL/NOT_RUN results and linked logs as history, without transferring them to current results. Check source and latest validation results for the current script state.

<details>
<summary>Historical init plan, initial planner, and replay checks (do not execute as the current procedure)</summary>

2026-09-23. Target host: `vmi3365213`; workspace: `/root/work/cypher-FHS-D-ExchangeCore`. **No init/reset/PM2 operation was performed in this document's work. Approval for intermediate init had not been obtained.** This is separate from approval for normal builds, deployment, and same-DB restarts.

## Current blocker and old script that must not run

The genesis then in use had no DEX configuration; adding a manifest to an existing DB alone could not enable native settlement. Preserve the current specification binding all config to genesis MixDigest and including custody nonce=1 in the genesis root. Evidence is recorded in the [storage cap/genesis audit](live-storage-cap-audit.md). Financial LIVE tests require a new generation, while normal same-DB deployment, CLX regressions, nondestructive implementation, and unit work can proceed.

Do not run the existing [reset-chain.sh](../../reset-chain.sh) as part of observation or deployment. The identified issues are:

- Stop targets are `start-cypher0`–`start-cypher6` and `start-cyphermine`, differing from the specified PM2 names `cypher0`–`cypher6` and `cyphermine`.
- `set -e` currently stops the script if stopping fails, but that is not a safety guarantee. It does not verify actual target PIDs, descendants, start ticks, datadir locks, or cessation of writes.
- It directly deletes parts of DB/cache/TX ingress data in each datadir. It does not archive the entire old generation or account for signing safety history, DEX/relay data, or unpaid rights.
- It initializes with the same `genesis.json`. It does not guarantee consistency of the new chain ID, genesis, DEX deployment/domain, registry, and relay generation, or replay protection.
- Conditions distinguishing retained keystores from avoiding old nonce/fund-ledger/vote-WAL mixing are not documented.

After preserving the original in a private area, the old script was replaced by a wrapper that only invokes a nondestructive planner. `bash -n` was checked. This entry point contains no stop/delete/init code. An executor must support only a separately approved exact plan. Do not add generic deletion or `pm2 stop all`.

## Implemented nondestructive planner

[scripts/dex/live_generation_plan.py](../../scripts/dex/live_generation_plan.py) compares public observation JSON from [live_observe.py](../../scripts/dex/live_observe.py) with actual datadir metadata. **It contains no code that performs PM2 operations, signals, rename, copy, deletion, init, or signing.** It only saves output JSON as a new file.

Inputs:

- `--observation`: observation JSON for the specified host/root/workspace, no older than 15 minutes.
- `--new-chain-id`: a positive uint64 differing from the old chain ID.
- `--dex-id`: a nonzero new 32-byte deployment ID.
- `--output`: a nonexistent output JSON file.
- `--new-genesis`: optional candidate at an absolute path distinct from the current `genesis.json`. Missing gates can be shown even without it.

Public output includes every PM2 name/id, observed PID/start ticks/boot ID, old datadir, device/inode, exact planned archive path, old/new chain IDs, observed genesis hash/root, candidate genesis file hash, preserved key paths/counts, and the stop/archive/selective-copy/init/verification order.

In addition to the original 8 targets, explicitly passing `--include-added-commons` makes the current planner check **exactly 14 targets**, including `cypherdex1`–`cypherdex6`. Additional datadirs are restricted to `build/stage/live-commons/chaindbdex1`–`chaindbdex6`. Do not reuse an 8-target plan for a 14-target switch; regenerate it from the latest 14-process/genesis/datadir inventory. The existence of out-of-scope PM2 apps does not authorize changes to them. The planner itself has no stop/init operations.

The new genesis candidate is intended **to switch this specified PM2 network itself to a new generation**, not to add a separate isolated CLX committee. Archive all 14 current CLX datadirs in full, using the same PM2 names and preserved CLX wallet/node identities. New DEX runtime starts empty; if it already exists, reject rather than silently delete it. The relay also starts with empty runtime for the new domain, but once that generation has started, retain signed TXs/unconsumed nonces/completion evidence and resume from the same DB. Distinguish wallet-key retention/selective copying from avoiding import of old nonce/balance/vote/payment history into the new generation.

Reject symlinks, hardlinked secrets, duplicate PIDs/datadirs, different hosts/workspaces, stale observations, genesis hash/root mismatches, reuse of the old chain ID, and existing archive destinations. Use only lstat for keystore files; do not publish their contents, hashes, or individual filenames. Do not read nodekey contents either.

Even if a candidate genesis exists and its JSON ID matches, planner output always remains `BLOCKED`, `reset_authorized=false`, and `executor_implemented=false` (meaning the planner has no execution capability). The separately built target-restricted executor is documented in [live-switch-executor.md](live-switch-executor.md), but must not run until specific intermediate-init approval and the final exact plan are obtained. Python JSON comparisons do not replace Go genesis/registry/finality verification. Do not infer genesis block hashes from mixHash or JSON SHA-256. The current candidate derived through the formal core path is mapped in [live-generation-candidate.md](live-generation-candidate.md).

## Concrete execution plan for approval

1. Fix the current storage-generation schema, CLX settlement configuration, separate DEX registry, Oracle/market, and relay as one candidate generation, validating genesis/configuration in Go. Compute and record the new chain ID, actual genesis hash, DEX domain/epoch/committee, and source trust root.
2. Immediately before initialization, reobserve source/build/config hashes, target PM2 names, PID/start ticks/boot ID, and all datadirs. Show the user the intermediate-init targets, stop/archive/recovery limits, and exact plan hash, and obtain approval specifically for this reset. Do not request renewed approval for already authorized ordinary restarts.
3. Explicitly name and gracefully stop each target PM2 app. Do not stop at parent-shell termination; verify actual CLX/Common/DEX/relay descendants, open DBs/WALs, locks, and cessation of writes. Distinguish graceful shutdown from intentional crashes.
4. Create a private-mode, same-filesystem, nonexistent generation archive directory and **archive each entire datadir by renaming its exact path**. Do not delete only parts of DBs or merge into an existing archive. Preserve keys, configuration, source, and final results first.
5. Create new datadirs and selectively copy only the approved inventory's `keystore`, `cypher/nodekey`, and required settings. Do not copy DBs, old nonces, vote WALs, snapshots, DEX financial ledgers, relay signed TXs/journals, TX ingress/outbox, or peer DB/cache into the new generation. Record retention and permissible reuse of old keys by purpose. Align DEX vote/TLS keys as new unique identities; do not run duplicate identities concurrently.
6. Init each explicitly named new datadir with the approved new genesis. Bind the new DEX deployment, source CLX genesis, registry, market/synthetic Oracle, and relay gas payer to the same generation. Do not use external funds or direct StateDB edits.
7. Confirm synchronization and finality progress from normal PM2 startup, and smoke-test DEX OFF engine=0, independent Common DEX participation, and normal signed deposit → trading → rewards → native claim. Reconcile each process's executable hash/configuration, accounting, and gas.

## Replay and recovery limits

A new chain ID is required; changing only DEX ID does not establish replay prevention for ordinary CLX TXs. Verify binding to the new genesis/domain/registry. Check rejection of protected TXs bound to the old chain ID and raw bytes of DEX votes, timeouts, checkpoints, anchors, and claims. Preserving old wallet keys does not migrate old nonces/balances. Use new test accounts and an explicit funding budget.

Inspection confirmed that `EIP155Signer.Sender` in `core/types` falls back to Homestead signature
recovery when `!tx.Protected()`. Therefore **new chain ID 10101920 rejects EIP-155-protected signatures
for old 10101919, but does not universally prevent replay of old unprotected TXs without a chain ID**.
If old wallet keys are reused in the new generation and execution conditions such as sender nonce/balance
match again, this legacy-format risk remains. Candidate genesis alone has not changed ordinary CLX
signature rules; this remains an unresolved item requiring a separate decision and resolution before
public release. The characterization test in `cmd/dex-live-candidate/replay_scope_test.go` distinguishes
rejection of protected old TXs from continued recovery of old unprotected signatures. The new financial
runner enforces the target EIP-155 chain ID and does not import old raw TXs/nonces/ingress/relay queues.
Do not report complete replay protection across all signature formats.

Rollback before signing in the new generation may be considered after stopping all new writers and verifying the exact old datadirs/config/binaries for restoration. Once new-generation votes/trades/payments occur, do not overwrite with old data and erase new safety history. Preserve both generations, avoid concurrent startup, and require a separate recovery decision. Do not include private keys or whole-datadir archives in the public review archive.

## Test record

The initial `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/dex -p test_live_generation_plan.py -v` passed 11 tests PASS(UNIT); retain this as a historical result for the original 8-target scope. Source now supports optional 14-target operation and must be matched to the latest full live Python regression. Initial temporary fixtures, which did not modify real data, checked:

- Exactly 8 targets, unique archive paths, no key-content reads, and unchanged file inode/size/mtime before/after planning.
- Rejection of the old chain ID, zero/invalid domain, different host/user/workspace, and expired observations.
- Rejection of added/missing apps, wrong app names, duplicate processes, different datadirs, and genesis/chain mismatches.
- Rejection of datadir symlinks, secret symlinks/hardlinks, and existing archive destinations.
- Candidate genesis ID matching and mismatch rejection. Candidate existence does not imply execution approval or successful genesis authentication.

This is **PASS(UNIT)**, not PASS(LIVE) for init/stop/recovery. Real network reset, final init, new-generation financial tests, and generation-switch crashes are **NOT_RUN** in this planner's tests.

</details>
