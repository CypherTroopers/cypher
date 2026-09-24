# Same-chain-ID genesis and user init preparation

2026-09-23. Scope: `vmi3365213`, `/root/work/cypher-FHS-D-ExchangeCore`, branch `FHS-D-ExchangeCore`. Starting and ending HEAD: `70862a71dfaf2b00694dc1354c6a64e9504d7db5`. Existing changes were retained; no commit/push occurred.

Following the user's corrective instruction, **retain chain ID 10101919**. Updated the current [genesis.json](../../genesis.json). No node stop/init/restart was performed during this preparation. The user performs init personally. The old 10101920 candidate and plan awaiting approval do not apply to this operation.

## Prepared configuration

|Item|Value|
|---|---|
|CLX chain ID|10101919 (unchanged)|
|New genesis hash|`0xa4a61fa952509cde79c14e152702a1d7dea1cc0320b4552566b2efb9e4a575de`|
|Genesis state root|`0xd3e0fd99e2cbcafe3ca718d616b73ea47664153c0ffc01888c3cedef893a33f0`|
|Key genesis hash|`0x2e2c6be19a05958b75c2f163fed60d3380c4616a2c14aa12ca396cd73cc61ee2`|
|DEX domain ID|`0x433b712c48506710a611d48e351ff827d00e64941fff9c085817c266585af497`|
|genesis.json SHA256|`ac548d8dc6da5e32b471fc3fb863e5bc0e9c243af6b404825cf9cd3933a5634c`|
|DEX configuration|configuration 4, financial state 6, data schema 5, fixed epoch 1,7 participants/threshold 5|
|Market|BTC/CLX, synthetic Oracle. Not a real-price-source test|

The 2026-09-23 display-order correction made EVM settings consecutive and grouped CLX consensus, committee, and DEX separately. JSON values remained identical, as did the Go Genesis structure and block hash/root. Only the file SHA changed, so candidate inventory/role/relay file-match values were updated. Old file SHAs in past logs remain records from their time.

Only JSON fields `config.dexDevnet` and `mixHash` changed. The existing 7-member CLX committee, all 12 alloc entries,27 other settings including chain ID, and other top-level values are identical. Custody's reserved nonce enters the root through normal genesis processing. No additional initial CLX allocation was added. Distinguish JSON text hashes from block hashes derived through the formal core path.

The old unused candidate was archived in full at `build/stage/live-candidate-history/retired-chain10101920-20260923`. Current `build/stage/live-generation-candidate` was regenerated for the same chain ID. Wallet identities of the 6 additional Common nodes were retained after key-based verification against the archive; DEX voting/TLS/rewards, relays, and test accounts use new unique keys. Keys remain private and are excluded from public results.

The 7-member manifest,2 relay configs, and candidate `local-deployment.json` bind to the same genesis/domain. Activation at `build/stage/live-deployment.json` has not yet occurred; it follows confirmation of actual block 0 in the new generation. Candidate inventory `BLOCKED` and `NOT_RUN` fields describe unapplied gates at creation time and are distinct from this document's additional test results.

Since the chain ID is retained, the new DEX domain does not prevent replay of old ordinary signed CLX TXs. Old raw TXs/nonces/ingress/relay queues are excluded from the new generation, but this is not cryptographic replay separation. Ordinary CLX signature rules and PoW specifications are unchanged.

## User-executed init.sh — path additions only, as finally instructed

Following the user's final instruction, "Only add the DEX-side paths to the init.sh script," exactly 12 lines were added to the original [init.sh](../../init.sh):

- PM2 targets: `cypherdex1`, `cypherdex2`, `cypherdex3`, `cypherdex4`, `cypherdex5`, `cypherdex6`.
- Datadirs: all 6 from `build/stage/live-commons/chaindbdex1` through `chaindbdex6`, listed individually.

Original stop/delete/key-retention/ordinary CLI init behavior is unchanged. The archive-helper connection was removed. Newly created helper/test source was preserved in private historical storage and removed from the current implementation. Earlier helper-version UNIT/read-only checks are historical results for that version, not results for current init.sh.

**Current init.sh has no dry-run/--check feature.** Running it performs the original stop/data deletion/initialization and leaves PM2 stopped. It was not executed during preparation. Validation consisted of `bash -n init.sh` and verifying that the only difference from the original file is 12 added lines.

Chain ID remains 10101919. These additions do not target source/configuration/test logs or out-of-scope datadirs for deletion. After the user runs init, recheck actual DB block 0, then continue DEX startup and normal financial tests.

## Validation and real-network boundaries

- PASS(UNIT): Same-chain candidate generation, preservation of original settings, format authentication, Common identity reuse. Derived genesis using a formal core memory DB and checked 7 manifests against keys/registration.
- PASS(UNIT): Final race for 2 helper packages,10 top-level tests. One actual candidate-read test through ordinary cypher relay CLI/parser also race PASS. Not proof of financial processing or production safety.
- PASS(UNIT): Launcher/auth/relay reject same-chain old DBs, tampering, etc. Init-helper tests belong to a superseded version. Only syntax and added lines were checked for current init.sh.
- PASS(UNIT): Finance-runner offline plan. Separately calculated planned 254 CLX transfers and 225 CLX custody; transfers/deposits/settlement are NOT_RUN.
- NOT_RUN: Init of target PM2 nodes with the new genesis, DEX startup, LIVE finance, A/B/C,60-minute operation. Continue after reconciling actual block 0/runtime following user init.

During read-only observation, the existing 8 nodes returned height 1049 with old genesis `0xe69022ef43f6d238846015e0a4e7cdd190cf45e9fd98cfa0666acb482a05017e`; the 6 added Common nodes were stopped. Actual executable SHA256: `76d2d104bb101451b2729cd1f6c55374350ea9ee297dbf2e5f5d27ab70f5ad1c`; heavy engine instance/action/inbox-import counters were all 0 on the 8 nodes. This is not new-generation LIVE financial PASS.

## Evidence locations

All work evidence is under `/tmp/common-dex-live-resume-496b6e0e`. The 1298 initially changed tracked/untracked files were preserved in a private archive, with every hash verified. Initial manifest SHA256: `19017ef41bc41a2f53a7f3765c97def26dd86b73234f2b33a9382c2f00a3584a`.

Public records there: `public/current-genesis-update.json`, `same-chain-final-helper-race.jsonl`, `same-chain-normal-cli-race.jsonl`, `same-chain-final-python.log`, `same-chain-finance-plan.log`, and `same-chain-prepared-live-observation.json`. Do not conflate new-genesis validation with unexecuted init.
