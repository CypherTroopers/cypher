# DEX Finality Fix — Ready for Init

2026-09-23. Target `vmi3365213`, `/root/work/cypher-FHS-D-ExchangeCore`, branch `FHS-D-ExchangeCore`. Starting and ending HEAD were `70862a71dfaf2b00694dc1354c6a64e9504d7db5`. Uncommitted changes were retained; no commit/push was performed.

The fix, verification, and normal binary deployment are complete. **The system is stopped, awaiting the user's execution of `./init.sh`.** Actual datadirs were not deleted, init was not performed, and the new generation was not restarted during this work. New-generation LIVE financial end-to-end testing follows init. This UNIT success does not change the old generation's [failure record](live-finality-gap.md), certified 15/finalized 0 with custody225 and unsettled funds, to PASS.

## Fix

Config 5/data schema 6/proof v2 were added according to the [finality proof specification](finality-ancestry-spec.md). A fixed-depth12 history is built from the semantic IDs of actual parent QCs, authenticating inclusion under an anchor finalized by genuine consecutive-view parent/child QCs. A 32-level view gap can finalize without increasing the existing16 KiB/8-descendant limits. Single-QC finality, lower thresholds, trust in HTTP latest, and CLX callback rewriting were not introduced.

Financial state 6, FIFO/cash/PnL/Funding/dust, and reward-funding formulas remain unchanged. Unnecessary idle timeouts are reduced; timeouts for actual unprocessed operations/unresolved votes remain. Timer changes alone do not guarantee removal of all view gaps. The final single QC still requires an authenticated subsequent action.

The remaining fixed schema 4 assumption in relay checkpoint/claim verification was also corrected. Authenticated configuration determines config 4→schema 5 and config 5→schema 6, with archive versions bound as well. Financial helpers, the normal factory, candidate generation, and relay startup now support the same configuration.

CLX settlement does not import matching/margin/funding/liquidation. Across 315 production dependency packages there are 0 DEX engine/finance/consensus/runtime packages. Generated inclusion proofs require at most 3 QC verifications and 12 siblings, measuring 2,003/2,006 bytes in this run. Accepted normal-form proofs retain the existing maximum 8 descendants＝9 QC verifications. Checkpoint gas is 12,000,000＋calldata bytes×40 before execution; normal TX intrinsic gas is separate. Processing bounds are distinct from an assessment that real-machine execution is sufficiently lightweight.

## Deployment and Initialization Targets

- ChainID **10101919 is retained**. The current root `genesis.json` was updated.
- Only `config.dexDevnet` and its authentication commitment `mixHash` were changed in genesis. Deep comparison confirmed retention of all other values and structure, including the CLX committee, alloc, and EVM configuration.
- New genesis `0xb2385f44d0adaf948957528f4e6c7c493fddf1311555c960d925b12dbe0f1626`.
- New DEX ID `0xae8b961b841fb8b270e87639314f2881c8ac3c6154480eb96b44296ad9c1be62`, fixed epoch 1, seven registrants/threshold 5.
- Genesis file SHA256 `06e879c0c1277008cc915b8a0ad4c73704f45119ec64cef875f503360d7d15ff`.
- Normal binary old SHA `76d2d104bb101451b2729cd1f6c55374350ea9ee297dbf2e5f5d27ab70f5ad1c` → new SHA `7ad62239831d318cefbcc2115e267601b7d3ef590826ea0c64ca339731a3d623`. The same new executable was deployed to `build/bin/cypher` and `build/bin/cypher-linux-amd64` by atomic rename. Running executable files were not truncated.
- The normal Makefile wrote to dedicated `build/stage/finality-v5-release`; deployment followed verification. BLS used the existing fixed SHA, and Go modules used readonly/verify. The initial sandbox DNS failure was preserved; a normal build then succeeded with authorized network retrieval.
- Private configuration is in `build/stage/live-generation-finality-v5`. Wallet identities for the six additional Common nodes remain unchanged. New DEX/TLS/relay/test keys were generated with private 0600 permissions and excluded from public material. Existing CLX nodekeys/committee keystores were unchanged.
- `build/stage/live-deployment.json` binds hashes for the new inventory and seven manifests. The existing relay PM2 wrapper still execs the normal launcher, which selects new configuration from this authenticated selection. There is no startup fallback to old fixed paths.
- `init.sh` stops 16 target applications by name and deletes 14 CLX datadirs plus **only runtime data** from the old/new candidates. It retains nodekeys, keystores, and keys/configuration outside runtime. It creates no data backup. Only seven empty DEX parent directories are prepared with 0700 permissions; normal startup creates actual DEX/relay DBs.
- No migration reads old WAL/financial schemas with new semantics. Normal CLX signed TX replay under the same chainID is not cryptographically separated merely by changing genesis/DEX ID. The operational condition forbidding import of old signed TXs/nonces/relay queues into the new generation remains.

PM2 remains stopped after `./init.sh` executes. After normal startup/synchronization of the new generation, Common admission and test funds will be prepared and financial testing resumed. Init completion and operation of the new binary are not yet reported.

## Final-Diff Tests

Raw logs are saved in [results/finality-v5](results/finality-v5). Pass-event counts include subtests; duplicates across runs are not summed as independent tests.

|Scope|Assessment and conditions|Main log|
|---|---|---|
|18 packages including DEX/finance/proof/rewards/HotStuff/helpers|PASS(UNIT), 260 top-level, 719 pass events, 0 FAIL|final-unit.jsonl|
|Full consensus, two storage-generation switches, long gaps, seven-participant cold restart|PASS(UNIT), 58 top-level, 136 events, 651.613 seconds|common-dex-history-consensus-final.jsonl|
|Focused consensus race|PASS(UNIT), 32-gap/frontier/existing finality|common-dex-history-focused-race.log|
|Full relay race, schema separation, old rights/cold archive|PASS(UNIT), 24 top-level, 114 events|common-dex-history-relay-final-race.jsonl|
|Real TLS, idle beyond three timeouts, sparse operations, one/two participants stopped, same-WAL resumption|PASS(ISOLATED), normal fixture two-second and real-manifest four-second settings unchanged|common-dex-idle-pacing-normal-timeout.log / race.log|
|New native handler/params and normal signed ApplyTransaction|PASS(UNIT), params/settlement 70 events, core 25 events. Deposit 100 minimum units→withdraw 10→custody90. Invalid-proof/OOG rollback, no payment increase after retry/cold resume, consistent gas receipts|native-history-params-settlement-unit.jsonl / native-history-core-tx-unit.jsonl|
|New native/core, financial readiness and identical arithmetic race|PASS(UNIT)|native-history-focused-race.jsonl / final-integration-race.jsonl|
|Old 225→214 financial fixture|PASS(UNIT), same fixture retained. Does not describe new-network balances|final-unit.jsonl TestNativeCLXFinancialFHSScenario|
|Old/new financial-state byte/root comparison with the same authenticated inbox and 320 operations|PASS(UNIT), financial state 6 retained|final-unit.jsonl TestAncestryExecutionPreservesFinancialStateAndArithmetic|
|Independent Python model of all 4096 leaves/frontier, proof fuzz|PASS(UNIT), 57,678 saved fuzz executions|checkpoint-history-independent-golden.json / checkpoint-history-fuzz.log|
|25 existing independent codec/financial golden cases|PASS(UNIT), reconciled without changing expectations|goldens/summary.json|
|All eight normal-CLI roles/all eight real Common API roles|PASS(ISOLATED), counter/lifecycle scope, excludes normal PoW|finality-cli-eight-roles.log / finality-api-eight-roles.log|
|Normal financial factory open/close/cold reopen with seven prepared real manifests, normal relay CLI/signer reads|PASS(UNIT), temporary DataDir only, no Start/voting|final-candidate-cli.jsonl|
|Full Python launcher/mock execution of init copy|PASS(UNIT), 83 cases plus one init case. Actual data deletion unexecuted|final-python-live.log / final-init-paths-r2.log|
|Full rpc|PASS(ISOLATED), sandbox socket EPERM attempt saved separately|finality-rpc-network-namespace.log|
|core/forkid|FAIL, reproducing the two existing TestCreation/TestValidation failures|finality-scoped-baseline-classification.json|
|internal/ethapi|FAIL, reproducing three existing failures. Distinguished from rpc package failures|finality-existing-ingress-regressions.jsonl|

Intermediate FAILs remain: old helper fixtures omitting versions were adapted to the new strict binding and retested; unstable 300 ms real-TLS test attempts were rechecked with the existing two-second fixture; the candidate generator's “non-DEX only” restriction was updated to permit only authenticated current v4, with rejection tests added. No new FAIL remains after those fixes. The five existing FAILs were not hidden by changing expectations.

## Ending State and Unexecuted Work

All 16 target PM2 applications are `stopped`, PID 0. No project cypher child processes remain. Nontarget PM2 applications are unchanged (observed count 0). Before shutdown there were 21 processes: committee 7＋Common 7＋DEX sidecar 7; relay 2 were already stopped. All 14 CLX nodes agreed at height 1133, hash `0xf1a8e7b7953e17a15fb5a713ce5d99049f0e18fa1a59857c8807775505323adb`, root `0x6b42971eb01f33ad9870e2411eb98730e033eac89cd8abac8cff51cee88b8b24`. Heavy DEX instances/actions/inbox imports on the CLX committee were 0. This observes the old running generation and is not evidence that the new binary was running.

LIVE financial TX submissions, funding, withdrawals, and reward payments during this work were 0. The old run's225CLX/unsettled funds are not carried into new-generation deposits or starting balances. New-generation DEX certified/finalized, CLX accepted, and custody/bucket/gas/Common reward/burn are **NOT_RUN (awaiting user init)**.

Normal PoW is NOT_RUN. Observed MemAvailable 26,068,408 KiB (approximately 24.86 GiB), memlock 8 MiB, and swap 0 are insufficient for the normal 32 GiB DAG＋cache＋CLX/DEX. Small DAGs or IsMining were not substitutes. Sixty-minute financial operation, A/B/C loads, WAN, real-machine maximum-proof calibration, and direct C-heap measurement are NOT_RUN. Foreign-UID chown fault injection is NOT_RUN due to namespace environment limits. These UNIT results do not establish completion of new-generation LIVE operation, two storage generations with financial activity, or later-starting DEX financial snapshots.

Existing finite caps remain, including 128 hot unfinalized entries, operation height 4096, and archive limits. Import/export of old single-file snapshots into generation storage is unsupported. General reward fairness, complete FROZEN recovery/loss allocation, and public committee transitions are unimplemented/out of scope. QCs rely on committee trust and are not Validity Proofs.

## Correspondence to L01–L20

This table covers evidence from the fix work. It does not overwrite the previous LIVE assessments.

|ID|Assessment in this work|Evidence and remaining items|
|---|---|---|
|L01|PASS(LIVE)|Host/branch/actual exe/14 datadirs/16 PM2 observations before and after deployment|
|L02|PASS(LIVE)|Planned shutdown/deployment only for authorized targets; no nontarget changes|
|L03|NOT_RUN|Shutdown/no orphans verified; new-generation startup/restart follows init|
|L04|NOT_RUN|Deployment hashes verified; actual new-exe operation follows init|
|L05|NOT_RUN|Seven manifests with unique keys prepared and factory UNIT complete; new-generation LIVE not started|
|L06|PASS(ISOLATED)|All eight normal CLI/API combinations; excludes normal PoW operation|
|L07|PASS(UNIT)|Normal signed native TXs, gas, bounded proofs, 0 dependencies; new-generation LIVE unexecuted|
|L08|NOT_RUN|New-generation financial end-to-end testing follows init; old LIVE liveness FAIL retained|
|L09|PASS(UNIT)|New-proof claim/replay/cold-DB consistency; LIVE follows init|
|L10|PASS(UNIT)|Existing generation storage integrated with new history; bounded caps retained|
|L11|NOT_RUN|Two UNIT switches PASS; two new-generation real-network switches unexecuted|
|L12|PASS(UNIT)|Signing safety state/old claims/replay/storage reauthentication; LIVE unexecuted|
|L13|NOT_RUN|New-generation LIVE settlement after shutdown follows init|
|L14|NOT_RUN|A/B/C unmeasured|
|L15|NOT_RUN|Sixty-minute financial operation unexecuted|
|L16|NOT_RUN|Insufficient normal-PoW resources; separate from lifecycle|
|L17|PASS(UNIT)＋existing FAIL|Unit/race/socket/roles for these changes passed; forkid 2 and internal/ethapi 3 recorded separately|
|L18|PASS(UNIT)|Init script/generation configuration/mock deletion-retention tests; actual init is user-executed|
|L19|PASS(LIVE)|All 16 targets stopped, 0 orphans, new generation explicitly unstarted|
|L20|PASS(UNIT)|Source/build/config/raw evidence mapping; secrets and operational data excluded from review archive|

## Preservation and Reproduction

Starting state is in `/tmp/common-dex-finality-fix-xs_6hyaf/start`, with the tracked diff in its `private` directory. Complete review material immediately preceding this work remains in `/tmp/common-dex-live-test.x5z_05oq/final`. Initial preservation overlapped parallel development work and is not described as an atomic snapshot of the whole worktree. Starting HEAD/genesis/binary and the previous manifest are distinguished from each workstream's changed files/hashes.

The final test-input manifest is [final-test-source-manifest.json](results/finality-v5/final-test-source-manifest.json), SHA256 `5e20e8389ad44f3cffd5c06dfac831ecbb5d2e46fc3af15ccf1e6ba4237fa0cb`. Duplicate result-JSONL entries are not counted as “independent tests.” The dedicated source archive is `/tmp/common-dex-finality-fix-xs_6hyaf/final`. Normal binaries are identified by the binary SHA above and production source manifest, not git HEAD alone.
