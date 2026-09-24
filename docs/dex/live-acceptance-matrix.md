# Real-Network Acceptance Conditions — Financial Testing After User Reinitialization

2026-09-23. Chain ID **10101919 is unchanged**. The main result is **LIVE financial FAIL (DEX finality stalled)**. The earlier state of awaiting user init has been resolved. See the [execution report](live-active-finance-test.md) and [cause/reproduction](live-finality-gap.md). The old matrix is [preserved with these results](results/live/20260923-active-finance/live-acceptance-before-this-test.md). Historical O26 retains its assessment from that time.

Evidence prefix: `results/live/20260923-active-finance/`. UNIT successes are not transferred to LIVE. Assessments below cover only what this run executed; a partial PASS does not complete the whole item.

|ID|Assessment|Evidence from this run and remaining scope|
|---|---|---|
|L01|PASS(LIVE)|start/final-live-observation.json. Mapped designated host/branch, parent-child relationships, executables, and datadirs for 14 CLX/Common nodes, seven sidecars, and two relays. All 14 matched the new genesis|
|L02|PASS(LIVE)|Operated only the seven target Common nodes/two relays. Seven committee PIDs unchanged. No nontarget PM2 apps. Chain ID/genesis/init/normal binaries unchanged in this work|
|L03|PASS(LIVE)|dex-stop-isolation.json. Cleanly stopped seven owned sidecars and normally restarted seven Common nodes on the same DBs. Old parent/child PIDs disappeared; one sidecar each; matching inodes/manifests/checkpoints. Initial missing-directory FAIL saved separately|
|L04|PASS(LIVE)|All 23 running executables matched release 76d2d104…. All 600 production source files also matched the existing build manifest. No normal-binary redeployment in this work|
|L05|PASS(LIVE)|Started real TLS for seven Common-side participants with distinct manifests/DBs/vote keys. CLX committee engine 0. Fixed epoch 1, same host; not public admission/WAN|
|L06|NOT_RUN|This LIVE run observed RPC＋DEX, Common PoW OFF, and all DEX children stopped. Full rerun of all eight combinations and normal PoW unexecuted. Earlier ISOLATED lifecycle PASS is recorded separately|
|L07|BLOCKED|Four native deposits through normal signed TXs/Common admission/CLX finality plus external authentication reconciliation PASS(LIVE). Heavy counters 0 on 14 CLX nodes. LIVE DEX checkpoint/claim path not established with finality 0|
|L08|FAIL|Native 225 CLX deposited, but DEX certified 15/finalized 0/inbox 0. LIVE financial end-to-end orders/matching/participation-reward reservations incomplete. finality-wal-chain.json and reproduction test|
|L09|BLOCKED|Payments 0, reservations 0. No unauthenticated funds paid. Prerequisites unmet for completing LIVE financial claims/replay/financial cold resumption|
|L10|NOT_RUN|Current hot 128/cut 64 implementation and earlier UNIT results retained. Full acceptance retest of storage updates not executed in this run. Discovered separate finality stall caused by proof 8 limit|
|L11|BLOCKED|All DEX storage generation 0. Prerequisites unmet for LIVE financial testing of two switches under real configuration|
|L12|NOT_RUN|Restoration of existing certified checkpoints from the same DB PASS(LIVE). New backlog reproduction retains vote/lock/QC/timeout, PASS(UNIT). LIVE continuity of all items including unpaid claims unexecuted|
|L13|BLOCKED|Normal CLX transfer during complete DEX shutdown plus same-DB recovery partially PASS(LIVE), with independent FHS/MPT/inclusion reconciliation. Clearing unsettled financial items after CLX shutdown unexecuted|
|L14|NOT_RUN|A/B/C runner unit tests and offline plan only. Measured comparison unexecuted because financial prerequisites FAIL. Performance acceptance undecided|
|L15|BLOCKED|Short drive configured for five minutes failed partway through. Did not pass 60-minute mixed financial operation, two storage generations, or post-shutdown financial settlement|
|L16|NOT_RUN|Observed MemAvailable approximately 23.98–25.09 GiB, insufficient for normal DAG 32 GiB＋cache 512 MiB＋node resources. Nonce search/delivery/adoption/rewards unexecuted. No DAG/difficulty/OS changes|
|L17|FAIL|New LIVE finality failure remains unfixed. Final Python 78, finance/source helper race 8 top-level, four financial packages 60, old 225→214 fixture, and backlog reproduction/race PASS(UNIT). Initial harness FAIL retained. Historical forkid 2/RPC3 FAIL unfixed and not rerun here|
|L18|NOT_RUN|New generation after user init observed. init.sh was neither changed nor executed during this work. Final init after completion unexecuted. Retaining the same chain ID does not separate normal signed-TX replay|
|L19|PASS(LIVE)|Ended with 14 CLX nodes online＋seven DEX instances active, two relays intentionally stopped. Recorded CLX1121/root agreement, DEX15/0/accepted 0, custody225, payments/reservations 0, generation 0|
|L20|PASS(UNIT)|Mapped final source/build/config/run/public raw logs to review archive. Keys/runtime excluded. Starting git status, release-source reconciliation, and separate helper manifest saved. No record of a new starting archive covering the full diff; reported as unperformed|

The new segmented finality-anchor recovery method is **NOT_IMPLEMENTED**. No specification or test was intentionally RETIRED in this run. Complete FROZEN recovery, general reward fairness, maximum-proof measurement, C heap, WAN, and 60-minute performance also remain incomplete. Init alone does not resolve this defect.
