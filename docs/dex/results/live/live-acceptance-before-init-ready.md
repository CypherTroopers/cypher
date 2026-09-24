# Actual-Network Acceptance Conditions — Q1 Complete, Q2/Q3 in Progress

Assess every condition using evidence from new runs. Do not copy earlier UNIT/ISOLATED PASS results into LIVE.

|ID|Condition|Verdict|Evidence/incomplete work|
|---|---|---|---|
|L01|Host/workspace/branch/PM2/executable/config/datadir comparison|PASS(LIVE)|Q0/q1-post-smoke observations, start manifest. Separate inventory being updated for Q2 additional Common nodes.|
|L02|Authorized scope and unchanged out-of-scope resources|PASS(LIVE)|Q1 deployed/stopped/restarted only the designated 8 apps. No external/third-party funds, pushes, or existing-DB resets.|
|L03|Ordinary startup/stop/restart without orphans/duplicates|PASS(LIVE)|Q1 removed 16 old PIDs, exit code 0, 8 new PM2PID=cypherPID. DEX-enabled case not run.|
|L04|Actual deployment of built binary|PASS(LIVE)|Q1 release 33f22a… checked against 8 actual executables. Schema 4 source under development not yet deployed.|
|L05|7 independent DEX Common nodes|NOT_RUN|Keys/manifests for 7 members prepared; 6 additional Common nodes synchronizing. DEX work not started.|
|L06|Independent PoW/RPC/DEX roles|NOT_RUN|Planned across Q0–Q5.|
|L07|Ordinary TX/admission/finality/CLX engine 0|NOT_RUN|10 ordinary CLX transfers PASS(LIVE). Actual DEX settlement/engine 0 measurement awaits new genesis.|
|L08|LIVE financial deposits/trading/Funding/rewards|BLOCKED|Current genesis lacks DEX. Financial activation requires separate approval of concrete mid-run initialization.|
|L09|LIVE claim/replay/cold consistency|BLOCKED|Mid-run initialization for LIVE finance unapproved. Distinct from UNIT claim regressions.|
|L10|Storage-cap classification and generations|NOT_IMPLEMENTED|Cap audit complete; authenticated archive/financial v6/relay hot-cache implementation/testing in progress.|
|L11|At least 2 storage generations with actual settings|NOT_RUN|LIVE test of 2 actual-setting generation transitions not run.|
|L12|Preserved rights/nonces/voting safety within the same generation|NOT_RUN|Planned across Q0–Q5.|
|L13|LIVE stop/restart and clearing unsettled work|BLOCKED|Ordinary CLX same-DB recovery PASS. LIVE recovery of unsettled finance awaits new genesis.|
|L14|A/B/C ordinary-CLX comparison|NOT_RUN|Planned across Q0–Q5.|
|L15|At least 60 minutes of repeated LIVE finance|BLOCKED|60-minute LIVE finance without mid-run initialization not run; financial-enabled genesis not applied.|
|L16|Ordinary PoW nonce/delivery/acceptance/rewards|NOT_RUN|MemAvailable about 20.5 GiB before additions, DAG 32 GiB + cache 512 MiB, swap 0/memlock 8 MiB. Ordinary nonce search not performed.|
|L17|Current-specification regressions and FAIL classification|NOT_RUN|Planned across Q0–Q5.|
|L18|Final initialization/new-generation preparation|NOT_RUN|Go-validated candidate and dry-run planner prepared. Final initialization not performed.|
|L19|Ending network/financial state|NOT_RUN|Planned across Q0–Q5.|
|L20|Source/build/config/run correspondence and secret exclusion|NOT_RUN|Planned across Q0–Q5.|
