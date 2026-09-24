# Same-DB Common restart plan — review only; NOT_RUN

Financial fault expansion is blocked by certified15/finalized0. This restart tests persistence/replay only; retaining that state is not a finality fix or financial integration PASS. No fresh signed actions, native funding, schema change, init, WAL deletion, archive removal or key replacement.

Source observation: `common-seven-pre-restart-host-bindings.json`, host /proc read-only. Exact PM2 status is not obtained by this observer; root must recheck the named PM2 app immediately before use. The earlier sandbox observation that saw zero processes is an environment visibility failure, not node-stop evidence.

| Expected PM2 app | Observed parent PID / start ticks | Observed DEX child PID / start ticks |
|---|---|---|
| cyphermine | 1319552 / 46822975 | 1319725 / 46823534 |
| cypherdex1 | 1319579 / 46823040 | 1319738 / 46823547 |
| cypherdex2 | 1319606 / 46823089 | 1319749 / 46823612 |
| cypherdex3 | 1319631 / 46823139 | 1319761 / 46823714 |
| cypherdex4 | 1319656 / 46823212 | 1319774 / 46823831 |
| cypherdex5 | 1319683 / 46823327 | 1319785 / 46823847 |
| cypherdex6 | 1319708 / 46823389 | 1319787 / 46823847 |

Every parent/child exe SHA was `76d2d104bb101451b2729cd1f6c55374350ea9ee297dbf2e5f5d27ab70f5ad1c`. Full boot ID, parent-child relationships, exact manifest path and CLX datadir device/inode are in the observation. Old PIDs are never reusable authorization: recheck boot ID/start ticks/exe/datadir immediately before each operation.

1. Root ends input and named-stops the two relays as already planned, preserving their full runtime/source/outbox/journal. Record pending nonce/job states. Do not use stop-all.
2. Record all seven DEX status values and cryptographically check checkpoint15's certified root/domain/action bytes. Record CLX Common6 genesis and a selected canonical hash/root. Save DEX datadir, hot WAL/archive/collector paths and directory identities as a baseline, without editing them.
3. Root checks PM2 `cypherdex6` resolves to the observed parent and exact wrapper/datadir, with no duplicate writer, then runs only `pm2 restart cypherdex6` using the reviewed existing lifecycle configuration. No miner.start or miner.stop is needed for this Common. If existing kill_timeout is shorter than normal shutdown, do not quietly treat a timeout kill as graceful; use the reviewed graceful-stop mechanism and record the actual outcome. The supervisor closes only its owned child; do not separately launch another dex-validator under PM2.
4. Wait on process events (finite120s): both old parent and child must have exited; exactly one new Common parent and one new DEX child must appear, with matching release SHA, expected PPid, unchanged manifest, same CLX and DEX datadir identity. A still-online parent with a dead child is failure. Never kill a different/reused PID to make this pass.
5. Query API19006 and ordinary Common6 IPC. Require correct chain/genesis, retained certified height15 and identical checkpoint15 root/action commitment. Finalized remains0 unless genuine new valid finality evidence is independently obtained; never write an expected finalized flag. Require no collector/FHS watermark mismatch, immutable archive conflict or replay error. Node may advance its timeout view normally; this must not erase own vote/lock/QC safety history.
6. Compare certified15 root with the six untouched peers. On mismatch, stop new test input, keep data, record failure and diagnose. Do not restore an older WAL or reinit.
7. Only after this persistence gate passes may root repeat one Common at a time, proposed order5,4,3,2,1,cyphermine. For each use the freshly observed handles and same checks. Restarting cyphermine interrupts source8999: leave relays stopped, wait source sync, then restore only Common admission signer unlock/recipient if needed. Whole `live_auth restore` would also invoke committee miner.start and is not appropriate for this Common-only sequence.
8. End record must list actual PM2/sidecar state, certified/finalized/accepted, custody and pending reserves/claims, and relays intentionally stopped. Do not restart financial input or relays merely because a cold restart preserved certified15/finalized0; the finality defect remains an independent blocking issue.
