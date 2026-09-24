# Real-network acceptance conditions — same-chain genesis prepared, awaiting user init

Following the 2026-09-23 corrective instruction: **retain chain ID 10101919** and update workspace genesis for DEX. The user performs init/restart personally. This preparation did not change PM2/live DBs. See the [latest preparation record](live-same-chain-genesis-preparation.md) and final logs in the same area. The previous matrix is preserved in this artifact's `public/live-acceptance-before-same-chain.md`. Do not convert existing FAIL or UNIT/ISOLATED results into new LIVE PASS.

Judge every item using evidence from the new run. Do not transfer historical UNIT/ISOLATED PASS to LIVE.

|ID|Condition|Assessment|Evidence/incomplete scope|
|---|---|---|---|
|L01|Host/workspace/branch/PM2/exe/config/datadir matching|PASS(LIVE)|Current run's current/same-chain-prepared-live-observation.json. Specified host,14 PM2 targets,8 online/6 stopped. Active 8 observed old-genesis height 1049. Not new-generation financial verification|
|L02|Authorized scope and unchanged out-of-scope resources|PASS(LIVE)|Q1 specified 8-node update + authorized 6 additional Common nodes. Out-of-scope PM2 apps 0; no external/third-party funds, push, or reset|
|L03|Normal start/stop/restart, no orphan duplicates|PASS(LIVE)|Q1 old 16 PIDs gone, exit code 0. Q2 Common 6 same-DB restart removed old PID, new PID 1271425. Not run with DEX enabled|
|L04|Actual deployment of built binary|PASS(LIVE)|All 8 executing binaries match deployed release `76d2d104…`. Observation after user restart, not deployment during this preparation. New-genesis restart unrun|
|L05|Independent 7 DEX Common nodes|NOT_RUN|Common 7 synchronized. Unique vote/TLS/reward keys and manifests prepared; DEX sidecars/relays not started|
|L06|Independent PoW/RPC/DEX roles|PASS(ISOLATED)|Final CLI all 8 combinations and start/stop PASS. All 8 with DEX enabled on specified LIVE network and normal PoW nonce search NOT_RUN|
|L07|Ordinary TX/admission/finality/CLX engine 0|NOT_RUN|Measured heavy engine instance/action/inbox-import 0 on existing 8 nodes. New-genesis normal financial settlement TXs follow user init|
|L08|LIVE financial deposits/trading/Funding/rewards|BLOCKED|Same-chain-ID DEX genesis prepared. LIVE testing follows user init of actual DBs and DEX startup. Authentication requirements unchanged|
|L09|LIVE claim/replay/cold consistency|BLOCKED|New-generation LIVE financial claims unrun. Continue after user init; distinct from UNIT regression|
|L10|Storage cap classification/generations|PASS(UNIT)|Implemented hot 128/cut 64, authenticated archive, collector/relay reclamation, finance v6. Two cuts at 64/128,7 cold recoveries, crash component tests PASS. Finite archive/cumulative caps and unimplemented fresh snapshot bootstrap remain|
|L11|At least 2 storage generations with actual settings|NOT_RUN|LIVE test of 2 generation switches with actual settings unrun|
|L12|Same-generation rights/nonce/voting-safety retention|PASS(UNIT)|Old claims, nullifiers, relay intents, collector/FHS dual WALs, archive restart with different signer sets regression PASS. Reverification in specified LIVE finance NOT_RUN|
|L13|LIVE stop/resume and outstanding settlement resolution|BLOCKED|Normal CLX same-DB resume PASS. LIVE recovery of unsettled finance awaits new genesis|
|L14|A/B/C ordinary CLX comparison|NOT_RUN|Planned for Q0–Q5|
|L15|At least 60 minutes of repeated LIVE finance|BLOCKED|60-minute LIVE finance without intermediate init unrun. Prepared DEX genesis not applied to actual DBs|
|L16|Normal PoW nonce/delivery/adoption/rewards|NOT_RUN|Current MemAvailable about 26.02 GiB is insufficient for normal DAG 32 GiB + cache 512 MiB + existing nodes. Swap 0/memlock 8 MiB. Normal nonce search not forced; distinct from CLI lifecycle|
|L17|Current-spec regressions and FAIL classification|FAIL|Retains existing forkid 2/RPC 3 FAIL. Final DEX 21 packages, consensus, CLI/TLS, financial 225→214, Python 45, golden 26 PASS. Core socket-environment FAIL reran PASS in namespace with same source|
|L18|Final init/new-generation preparation|PASS(UNIT)|Same-chain 10101919 formal core candidate validation preserving original committee/alloc and normal relay CLI race PASS. User-created init.sh changes only add 12 lines for 6 DEX PM2 names/datadirs. bash -n PASS. Init unrun|
|L19|Ending network/financial state|PASS(LIVE)|Current observation: old-genesis 8 online, additional Common 6 stopped, DEX/relay 0. Active 8 engine 0. New finance unrun, so new DEX certified/finalized/accepted N/A. Reobserve after user init|
|L20|Source/build/config/run mapping and secret exclusion|PASS(UNIT)|Maps preservation/hash checks of 1298 initially changed files, same-chain helper/normalCLI/launcher tests, and public results excluding secrets. Current init differs from original by 12 lines with syntax PASS. Helper-version tests are superseded history|

For final-log counts/hashes/failure classification, see [q3-final-test-summary.json](results/live/q3-final-test-summary.json). The same tests appear in multiple runs; do not sum counts as a safety metric. The previous matrix is preserved in the [old matrix](results/live/live-acceptance-before-init-ready.md). Historical O26 assessment is unchanged.
