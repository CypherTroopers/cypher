# Pre-launch checks retaining the same CLX chain ID — 2026-09-23

Following the latest user instruction, prepare for user-performed re-init while retaining the existing chain ID. Changes here affect pre-launch checks in `scripts/dex/live_auth.py`, `live_roles.py`, and `live_relay.py`. This work performed no init, PM2 operations, key reads/writes, DB operations, transfers, unlocks, miner starts, or actual process launches.

## Current checks

- Do not require old candidate `10101920`. Match the Go-validated/generated inventory's `ChainID` against the SHA-256 of exact `genesis.json` bytes and configured chain ID/DEX ID/version 4.
- Require `generation_inventory` (absolute path under the same workspace's `build/stage`) and `generation_inventory_sha256` in `build/stage/live-deployment.json`. Existing `genesis_sha256`, `chain_id`, and `dex_id` must also match. Do not silently fill missing fields in old roles.
- An enabled DEX role matches manifest chain/genesis/DEX ID/committee commitment/epoch 1/participant index against inventory. Do not enable unsupported epochs. An absent ordinary Common role means OFF; CLX committee nodes remain ineligible for DEX workers.
- Read inventory/role/manifest as bounded regular files, rejecting symlinks, hardlinks, excessive sizes, and file replacement at read start. File SHA-256 establishes correspondence to approved configuration, not CLX finality.
- `live_auth.py --generation-inventory` uses only the same path/hash recorded in the active role. Do not call signing/unlock/FHS resume until block zero and chain ID match on all 8 IPC endpoints. Latest heights or finalized caches do not replace this check.
- Before invoking normal `cypher dex-relay`, the relay matches candidate config, active inventory, and active genesis against source Common's block zero/chain ID. This does not replace Go relay FHS/MPT verification.

The existing guard in `cmd/cypher/dex.go` is unchanged. It reads block zero from Common's actual DB and rejects a manifest-genesis mismatch before creating the sidecar. Updating only configuration while retaining an old DB therefore does not count as a new generation merely because chain IDs match.

The historical Q1 no-inventory authentication path remains restricted to exact matches of the previously recorded old genesis-file SHA-256, old block-zero hash, and chain ID. New DEX-enabled genesis requires explicit inventory and an active role.

## Limits and unrun scope

Retaining the same chain ID may allow replay of old ordinary signed CLX TXs. New genesis, DEX domain, voting keys, and these launcher checks do not change ordinary CLX TX signature rules or cryptographically prevent old-TX replay when nonces/balances recur. Operational exclusion of old raw TXs/relay queues does not prove removal of this remaining condition.

Actual active-role deployment awaits verification after user re-init. These unit results exclude actual IPC/DB/sidecar/relay restart results.

## Reproducible unit tests

`scripts/dex/test_live_roles.py` and `test_live_relay.py` use temporary directories and mock RPCs.

- Permit matching new inventory/genesis/domain with the same chain ID.
- Reject different inventory paths/hashes, altered genesis, different manifest genesis/DEX/committee/epoch, old roles, symlinks, etc.
- Reject an old-generation source/IPC block-zero hash even with the correct chain ID. Even if only the last IPC mismatches, no signing or stateful RPC may have been called before it.
- Check ordinary relay command construction, restriction to 2 relays, and rejection of candidate tampering, duplicate payers, and unauthorized runtime. Units do not exec commands or invoke PM2.

Raw logs/source hashes are saved under `/tmp/common-dex-samechain-binding.hp7qh7tq/`. Distinguish these from real-network PASS.
