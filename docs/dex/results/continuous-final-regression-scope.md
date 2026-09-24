# Five-Mode Regression of the Final Candidate

HEAD: `70862a71dfaf2b00694dc1354c6a64e9504d7db5`.
Go/scripts source manifest: `7f786223801e567b77c6c37bf437c189ea440de3db91f0b93d4fae705cdc97e2`.
All runs had matching before/after hashes, source diff 0, and test/run exit 0.
This table does not include the G3 long-term financial-test result.

| Mode | Artifact | PASS top-level / events | Scope |
|---|---|---:|---|
| socket | `/tmp/common-dex-check.XplElRBr` | 65 / 325 | 6 packages with race checking, real TLS, reconnect/frame/epoch, source/MPT/finality, snapshots, etc. Events include seeds/subtests. |
| cli-roles | `/tmp/common-dex-check.9z9Fch83` | 5 / 17 | 82.575s. All 8 ordinary-CLI combinations, independent IPC/HTTP/TLS, DEX OFF, omitted/empty/relative/absolute trie-journal paths, and ordinary restart. |
| roles | `/tmp/common-dex-check.NvHLhkU7` | 1 / 9 | 13.112s. Independent lifecycle for all 8 existing Common-API combinations. |
| process | `/tmp/common-dex-check.qL6Oh3I0` | 1 / 1 | 29.804s. 14 distinct CLX/DEX process identities. All 7 DEX nodes stopped/restarted with the same WAL, finalized 2→4; CLX 1→3 during the outage. DEX communication uses bounded pipe simulation, without native financial settlement. |
| source | `/tmp/common-dex-check.CPDk7uJa` | 1 / 1 | 55.65s. 6 deposits through ordinary admission, 7 CLX child processes and ordinary ETH source, height 11/inbox 6/custody 6 CLX. RPC projection comparison, automatic synchronization and same-DB restart of a later DEX-OFF Common, engine 0/0/0. |

All 5 modes had FAIL/SKIP 0. Ordinary-size PoW nonce search is NOT_RUN, distinct from lifecycle PASS using invalid dedicated small data. Source uses a short separate ledger, not the 225→214 or long-term 295 financial test. Long-term key renewal/full history/reported capacity for later Common are checked separately in G3.

All modes used existing runners, new `unshare -Urn` namespaces, and loopback only. There is no host fallback if namespace creation fails. These are not evidence of WAN behavior, 60-minute load, performance with ordinary PoW, or C-heap safety. Raw logs, metadata, and source before/after are saved in each `continuous-final-<mode>-*` file. Evidence previously using final names was hash-checked and preserved in `continuous-superseded-061f4a0b6bed` and `continuous-superseded-c3e925e9445d` before replacement. Earlier FAIL results/datadirs were not deleted.

For unit, baseline, core/RPC/G0, ordinary-CLI finance, limited cost measurements, and the G3 long run, consult their separate raw logs and acceptance matrices. Counts for these 5 modes are neither counts of independent safety requirements nor an overall completion verdict.

## Additional Regression of Original Ordinary-CLI Finance

With the same `7f786…97e2`, `TestFHSNativeFinancialOrdinaryCLI`
in `/tmp/common-dex-check.8eoz6Xmw` passed in 249.80s. Source diff 0, test/run exit 0.
It processed 4 deposits, 18 checkpoints, 1 withdrawal, and 7 rewards through ordinary TXs and reconciled CLX height 69,
custody 225−10−1=214 CLX, trader 189.916/fee 0.064/support 19.02/insurance 5.
All native balances, gas, Common rewards, burn, and TX/claim IDs are saved in
[ledger-and-fault-trace](continuous-final-7f78-cli-financial-ledger-and-fault-trace.log) and
[raw log](continuous-final-7f78-cli-financial-raw.log).
Final gas 397485267200000000, Common rewards 79497053440000000, and burn 317988213760000000
are in minimum CLX units. Custody did not pay gas.

Passed: CLX stops/same-DB recovery at height 47/63; 1/2 DEX nodes stopped; 5/2 and 4/3 partitions/recovery; price outage/shock;
DA loss/repair; insufficient-insurance FROZEN; CLX progress with all DEX stopped; exact claim replay and modified-recipient rejection;
synchronization/DB restart of 7 ordinary Common nodes and an independent DEX-OFF Common; eth_call/estimate/trace consistency.
Subsequent fault-test DEX financial roots (including FROZEN 50) were intentionally not submitted to CLX; accepted sequence remained 18.
This is not evidence of settlement of later states or FROZEN recovery. Legacy-fixture synchronization for the 7 ordinary Common nodes
includes explicit disconnect/re-handshake of owned peers; automatic catch-up is assessed through separate source/G3 gates.
See [metadata](continuous-final-7f78-cli-financial-metadata.json) for all conditions and source hashes.
