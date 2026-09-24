# Bounded Native Verification Cost of the Final Candidate

2026-09-23, source manifest
`7f786223801e567b77c6c37bf437c189ea440de3db91f0b93d4fae705cdc97e2`.
[Conditions and before/after source](continuous-final-7f78-native-cost/metadata.json),
[raw log](continuous-final-7f78-native-cost/raw.jsonl).
`TestNativeRollingFullCalldataCostAndLateProofFailure` passed.
It ran after other isolated test processes exited, without Go race and with GOMAXPROCS=2.
The measurement did not quiesce the entire operational host.

| Input | Runs | Wall time (ms) | Native execution gas | State writes |
|---|---:|---|---:|---:|
| Valid 65536-byte input | 3 | 232.391 / 229.262 / 223.594 | 14,621,440 | 12 |
| Same size, invalid final count MPT | 3 | 240.184 / 235.037 / 292.096 | 14,621,440 | 0 |

The fixture contains 35 source headers, 70 QC records, and 8 MPT nodes/1682 bytes.
Each header has one descendant; bounded unused MPT nodes fill the remaining space.
The calldata cap was exercised, but this is not the worst time across every allowed descendant/key-renewal arrangement.
`fixtureQCRecords` counts records in the fixture, not instrumented real BLS calls.
Failure retains the state root and balances. Gas covers native processing; normal TX intrinsic gas is separate.

Go allocation ranged from 2,877,280–3,212,856 bytes/run, process RSS from 22,596–22,956 KiB,
and HWM was 24,332 KiB. RSS includes the whole process; C heap alone was not measured.

Network comparison with/without DEX submissions on the same hardware under equal CLX load,
full checkpoint/claim wall time, instrumentation of actual signature calls/storage writes,
and worst cases across all proof arrangements are NOT_RUN.
Each TX in normal financial tests separately records calldata/gas/payer.
WAN, 60-minute mixed load, combined normal 32 GiB PoW, and Hyperliquid comparison are also NOT_RUN.
This limited measurement does not establish comprehensive lightweight operation or a performance advantage.
