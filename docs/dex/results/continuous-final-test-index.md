# Continuous Operation: Final-Source Test Index

HEAD is `70862a71dfaf2b00694dc1354c6a64e9504d7db5`; the Go/scripts manifest is
`7f786223801e567b77c6c37bf437c189ea440de3db91f0b93d4fae705cdc97e2`.
The following runs executed on 2026-09-23, with matching before/after source hashes and 0 source diffs verified for each run.
Added documentation/logs are hashed separately in the final archive, outside this execution-source manifest.
G3 attempt 15 also passed on the same source. Component, real-socket, and normal-CLI financial scopes are shown separately.

The RPC block comparison failure in attempt 14 was reproduced with the real RPC formatter as a test-side problem:
it expected a rehash of a Header containing Common admission/reward roots and other fields omitted by RPC.
`TestContinuousRPCProjectionCanonicalAndIncompleteHeader` rejects missing/null/altered required fields.
The explicitly reported RPC hash is checked against an authenticated source block;
RPC latest is not added as a trust root.
Final source/baseline includes this fix. Attempt 14 retains its overall FAIL and unexecuted long-duration later-node synchronization.
See the [history](../continuous-development-history.md).

| Test | Result | Raw logs and conditions |
|---|---|---|
| DEX/HotStuff etc. unit/race | PASS: 19 packages, 284 top-level, 839 PASS events | [metadata](continuous-final-7f78-unit/metadata.json), [JSONL](continuous-final-7f78-unit/raw.jsonl) |
| Real socket/TLS | PASS: 6 packages, 65 top-level, 325 events | [metadata](continuous-final-socket-metadata.json), [raw](continuous-final-socket-raw.log) |
| Eight normal-CLI role combinations/journal restart | PASS: 5 top-level, 17 events, 82.575 seconds | [metadata](continuous-final-cli-roles-metadata.json), [raw](continuous-final-cli-roles-raw.log) |
| Eight real Common API role combinations | PASS: 1 top-level, 9 events, 13.112 seconds | [metadata](continuous-final-roles-metadata.json), [raw](continuous-final-roles-raw.log) |
| CLX7＋DEX7 processes | PASS: 29.804 seconds. Fundless, bounded pipe | [metadata](continuous-final-process-metadata.json), [raw](continuous-final-process-raw.log) |
| Normal CLX source/short later-starting OFF synchronization and restart | PASS: 55.65 seconds, CLX11, 6 deposits | [metadata](continuous-final-source-metadata.json), [raw](continuous-final-source-raw.log) |
| Original normal-CLI financial 225→214 | PASS: 249.80 seconds, CLX69, accepted 18, 8 claims | [metadata](continuous-final-7f78-cli-financial-metadata.json), [raw](continuous-final-7f78-cli-financial-raw.log) |
| G3 repetition/post-shutdown settlement/cold recovery | PASS: 1546.32 seconds, CLX749, DEX/CLX109, 72 claims, custody295, later-starting OFF synchronization/restart | [raw](continuous-g3-normal-15.log), [extraction and before/after source](continuous-final-g3/summary.json) |
| Core/VM/CLI focused race | PASS: 6 packages, 63 top-level, 135 events | [metadata](continuous-final-7f78-core-vm-cli/metadata.json), [JSONL](continuous-final-7f78-core-vm-cli/raw.jsonl) |
| QC arriving first/seven real CLX processes | PASS: 24.656 seconds | [metadata](continuous-final-7f78-g0-qc-process/metadata.json), [JSONL](continuous-final-7f78-g0-qc-process/raw.jsonl) |
| Production dependency boundary | PASS: 363 dependencies, 0 engine/devnet/runtime dependencies | [metadata](continuous-final-7f78-production-deps/metadata.json) |
| Bounded native cost | PASS:three each 65536-byte success/late-MPT failure | [limited scope](continuous-final-native-cost.md), [JSONL](continuous-final-7f78-native-cost/raw.jsonl) |
| Existing baseline | FAIL:two existing core/forkid failures; other 16 packages PASS | [metadata](continuous-final-7f78-baseline/metadata.json), [raw](continuous-final-7f78-baseline/raw.log) |
| Selected existing RPC tests | FAIL:three existing failures; another test timed out at 40 seconds | [three failures](continuous-final-7f78-rpc-existing-failures/metadata.json), [timeout](continuous-final-7f78-rpc-existing-timeout/metadata.json) |

Baseline failure names are `TestCreation` and `TestValidation`. The three RPC failures are
`TestRawTxIngressStopDrainsDetachedCancelledBulk`,
`TestSendRawTransactionsBusySenderDoesNotBlockIndependentGroups`, and
`TestSendRawTransactionPipelinesAdaptiveIndependentSenderWaves`.
The timeout is `TestSendRawTransactionPipelineSerializesSenderAcrossWaves`.
These remain as issues also reproduced in the starting archive;
they were not changed to PASS through altered expectations or unauthorized protocol changes.

All 26 unit SKIP events remain in the [metadata](continuous-final-7f78-unit/metadata.json).
Opt-in socket/process items and child-process entry points run in dedicated modes/parent tests above.
Of these, 22 passed in final socket mode and two are child entry points invoked by parent SIGKILL tests.
The actual foreign-UID chown test is NOT_RUN due to insufficient permission conditions
(rejection of invalid UID metadata was tested separately).
The optional external Trial13 WAL structural comparison is SKIP in the final unit run,
distinct from earlier component results.
Real-FHS WAL v3 restoration/replay tests ran in the final unit suite.
The five core/VM/CLI SKIPs are supplemented by dedicated CLI mode.

Standalone `check.sh relay` (`TestFHSNativeContinuousRelayShort`) is NOT_RUN on 7f78.
The earlier G2 short test passed in 73.31 seconds on another source and separate 225→215 ledger;
its result is not transferred into final PASS.
The normal relay's long-duration path is assessed through G3.
Independent `native`/`financial` modes are also outside this final index's executed scope;
do not confuse integration/fault checks within normal-CLI finance with rerunning standalone modes under different test names.

Normal 32 GiB PoW DAG nonce search, proof delivery, and combined performance are NOT_RUN.
These are distinct from normal CLI/API lifecycle PASS; resource conditions are recorded in the
[host observation](continuous-final-host-observation.json).
Controlled network measurement with/without DEX submissions under the same CLX load,
C heap alone, worst time across all proof arrangements, WAN, 60-minute mixed load,
and Hyperliquid comparison are NOT_RUN.
Go race PASS reports detection results for executed paths; it does not prove safety of C BLS
or the financial/consensus system as a whole.

All network tests use new user/network namespaces and loopback. Isolation failure has no host fallback.
For detailed conditions and the distinction between fundless pipes, real sockets, and normal-CLI finance,
see [role and financial scope](continuous-final-regression-scope.md).
Earlier G3 FAILs/interruptions are retained separately from final-source results.
