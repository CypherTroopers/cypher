# Scoped Init Executor — Current Execution Hold and Historical Record

## Applicable Instructions (Correction Dated 2026-09-23)

**Keep chain ID `10101919` and update the current `genesis.json` and preparation materials. The user performs init and restart personally. The automated executor's stop/archive/init/start steps are not performed as part of this work.** Do not reuse the old `10101920` plan/approval. This document does not request new execution authorization.

Current configuration, verification results, and information for user-executed re-init are in the [same-chain-ID genesis preparation record](live-same-chain-genesis-preparation.md). Active-role placement, authentication, and relay resumption are handled only after verifying the actual DB genesis following the user's re-init. [Pre-start validation](live-same-chain-launch-bindings.md) rejects the old DB even with the same chain ID.

The new DEX domain does not change normal CLX TX signatures, so **replay of old normal signed TXs under the same chain ID remains possible**. Avoiding import of old queues is an operational rule, not cryptographic replay separation. Executor unit tests are neither records of init/restart execution nor authorization to perform the user's operations on their behalf.

## Historical Record of the Superseded Execution Plan

The old text's additional approval procedure, automated exact 14 shutdown, whole-datadir archival, init/start, and recovery/replay descriptions assuming a new chain ID were design conditions at that time. They are not executed as the current procedure. “Current,” “unexecuted,” and similar wording also refer to that historical point, not the latest running state. Prior FAILs, test results, and log references are retained.

<details>
<summary>Historical executor design, approval boundaries, and unit tests (not the current init procedure)</summary>

2026-09-23. Existing authorization for candidate generation, storage implementation, and normal build/restart did not authorize intermediate init. The additional instruction “Let me know when it is time to init” was treated as a requirement to notify the user once preparations were complete. **No live stop/reset/init had been performed when this document/executor was created. No command to delete all chaindata had been generated.**

Once the existing eight nodes and six additional Common nodes were aligned and reviews of current-source regressions, release, genesis/domain, and configuration were complete, the exact plan, shutdown targets, key preservation, and recovery limits would be presented to the user with notification that it was time to init. Until then, old DBs would remain. Targeted archival of whole datadirs was recommended over deletion.

## Executor Boundaries

[`scripts/dex/live_switch_generation.py`](../../scripts/dex/live_switch_generation.py) separates `preflight` from `stop/archive/init/start`. Import does not execute operations. Initial `preflight` is read-only; other phases require a private approval file recording a separate actual user instruction. Creating an approval file is not itself a substitute for user approval.

Targets are exactly 14 PM2 names—`cypher0`–`cypher6`, `cyphermine`, and `cypherdex1`–`cypherdex6`—and only their inventoried datadirs. Other PM2 apps are excluded from the read-only listing and left unchanged. The normal fixed CLX committee is not repurposed as DEX workers. DEX sidecars start through the official Common supervision entry point, without duplicate PM2 management. Starting two additional relays is a separate normal deployment procedure from initializing these 14 DBs.

The input plan is the 14-target dry plan from [`live_generation_plan.py`](../../scripts/dex/live_generation_plan.py), extended with these JSON `execution` fields. Approval binds the SHA-256 of the complete final JSON.

- `release_file`: exact `build/stage/live-q3-release/bin/cypher-linux-amd64`, and `release_sha256`.
- `old_running_exe_sha256`: hash of the currently running executable verified on all 14 nodes.
- `candidate_inventory_file`, `candidate_inventory_sha256`: candidate records officially derived in Go.
- `validation_status`=`PASS(UNIT)`, `validation_source_manifest`=`{path,sha256}`: mapping of final source/build/candidate validation. Every phase recalculates actual hashes of the manifest and all listed files. Required entries include 14 wrappers and ecosystems, `live_start/common/roles/auth/switch_generation.py`, candidate genesis/inventory/seven manifests/two relays/activation. Keys and operational data are prohibited. This does not mean LIVE tests passed.
- `ecosystem_files`: path/hash list. App-name union must be exactly 14, with 0 duplicates.
- `launcher_files`: 14 exact wrapper paths and hashes. Reject content changes after planning.
- Optional `activation`: source/hash of candidate `local-deployment.json`, and exact destination `build/stage/live-deployment.json`. If omitted, Common startup remains DEX OFF.

The approval record contains version1, operation=`intermediate-generation-reset`, plan SHA, actual `user_instruction_reference`, approval time, and expiry within 24 hours. Every phase rechecks the same host/root/boot ID and plan hash. Existing eight-/14-node deployment permission is not copied as consent to an intermediate reset.

## Shutdown Through Resumption

1. **Preflight**: check observations within 15 minutes, exact PM2/PID/start ticks, every running executable, original datadir inode/device, original genesis, and final release/candidate/launcher hashes. If a new-generation archive already exists, do not merge into unknown stored data.
2. **Stop**: before writes, durably save the private control journal, original genesis, and each wrapper. PM2 behavior verified in Q1 showed that a kill timeout passed to `stop` does not update existing configuration, while config `restart` retains the existing pm_exec_path. Therefore atomically replace the **same verified wrapper path** with a temporary `exit 0` maintenance stub and perform named restart using exact 14 config with `autorestart=false / treekill=true / kill_timeout=60000`. Wait for normal exit of the old executable; the newly started stub exits without opening the DB. This handles the issue of an old wrapper at another path restarting while the existing parent is stopped.
3. **Verify stopped**: besides all 14 PM2 entries being stopped, scan host-wide `/proc` for target-datadir arguments, open FDs, and memory mappings. Parent-PID disappearance alone does not establish that cypher/sidecar children stopped. Do not erase failure conditions through automatic restart. Record observed exit codes/SIGKILL separately in PM2 logs; mere disappearance is not normal exit.
4. **Archive**: whole-rename each of 14 old datadirs into `build/stage/live-generations/<exact-generation>/`. Verify source inode/device and require the same filesystem and a nonexistent target. Fsync parent directories before/after rename and journal each completion. Deletions 0. If stopped immediately after rename before journaling, resume using the original inode at the archive destination.
5. **Init**: selectively copy only `keystore` and `cypher/nodekey` from the old archive into new 0700 datadirs. Do not copy authoritative DBs, nonces, old vote/lock/QC, snapshots, DEX financial ledgers, or relay nonces/signed TXs. New directories carry a plan-SHA marker. Reject symlink/hardlink keys, another-generation markers, and unknown nonempty datadirs. Run normal `cypher init` with the exact new release, each new datadir, and candidate genesis. On intermediate failure, retry normal init for the same unstarted new generation; do not recover by overwriting with old data.
6. **Install**: after all 14 init operations succeed, atomically switch the two normal binary paths and genesis to new files. Do not truncate running files. Place activation only at this phase if specified; do not overwrite another generation's activation. Prepare only candidate `runtime/<Common name>` parent directories with 0700 permissions, letting the official sidecar create DEX DBs. Maintain 10 GiB free headroom.
7. **Start**: recheck all hashes and stop conditions, then restore the saved approved wrappers. Durably journal `signing_may_have_started=true` **before** the first PM2 resumption. Perform exact normal-ecosystem restart and set status to `started_requires_live_verification`. CLI startup success does not establish FHS progress or financial success.

The executor does not automatically restore old WALs. After the start-attempt marker, archive/init/restart attempts are rejected. Even if a communication error occurs partway through the first start, it does not revert to old keys/WALs. Observe the new-generation processes/datadirs and review targets again as a normal restart. Restoring an old generation after signing/payments in the new generation requires a separate decision; automatic rollback that loses the latest safety history is prohibited.

If official role activation is installed by the deployment coordinator, DEX sidecars also start under supervision of the seven normal Common nodes. FHS startup in the new CLX generation separately requires key unlock and restoration of miner APIs for all seven committee members through official `live_auth`; Common PoW is not started. The Common RPC registry also starts empty from the new genesis, so the old reward recipient `0xed2772838f7a7aec042a972084998cb30d63b660` is explicitly registered through an auth entry point bound to the new-generation inventory. Neither these operations nor actual RPC/state reconciliation may be inferred from init/PM2 startup exit 0.

Whole-DB archives contain existing keys, so archive/control data are private. Do not copy key material, keystore names/hashes, PM2 raw environment, or credentials into public reports. Source/config/build/public-run evidence is mapped to a separate secret-free review archive.

## Remaining Review and Test Scope

Unit tests use only temporary filesystems and fake PM2. They verify unchanged preflight, rejection of missing/expired/other-plan/foreign/stale approval, changed launchers, and symlinks; exact 14 phases; key-only copying; retention of archived old WALs; resumption during rename/init; rejection after prior start; and unchanged nontarget apps. **PASS(UNIT) is not a LIVE reset result.**

The first unit run had one FAIL because a test expected an approval-SHA mismatch after changing a plan and restoring exactly its original bytes. The test was corrected to actually add a separate revision. The original `q3-generation-switch-unit.log` is retained separately from later final logs. LIVE execution of all executor phases, host `/proc` writer scanning, 14 whole-DB renames, 14 normal init operations, and normal PM2 resumption with activation is **NOT_RUN**.

Before approval, the deployment coordinator fixes the final exact plan and release hash and reviews the functions. Source creation alone does not establish deployment or initialization. If the user performs init personally, the same shutdown, whole-datadir archival, new chain/genesis/domain consistency, key preservation, and verification procedure applies instead of unspecified blanket deletion.

</details>
