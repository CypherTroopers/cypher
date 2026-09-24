# Regression Evidence and Scope When Work Resumed

Target HEAD: `70862a71dfaf2b00694dc1354c6a64e9504d7db5`.
Go/scripts manifest at execution: `061f4a0b6bed257c6ba8ad60f377f52cf8640cb6dcb8d4dcbd01a1575cfe1630`.
Results precede the G3 test-observer fix; they do not establish final PASS for all later changes.
Raw logs, before/after hashes, and metadata are saved in [continuous-intermediate-061f4a0b](continuous-intermediate-061f4a0b/).

| Mode | Execution artifact | Result | Scope |
|---|---|---|---|
| socket | `/tmp/common-dex-check.WG87JtqP` | PASS, 6 packages/62 top-level/262 pass events, FAIL/SKIP 0 | TLS identity/epoch/frame/reconnect, 7 FHS actors, snapshot/settlement-response bounds, deposit finality/MPT, rolling/key-renewal unit and opt-in socket tests. |
| cli-roles | `/tmp/common-dex-check.y55dGoZ2` | PASS, 1 package/5 top-level/17 pass events, FAIL/SKIP 0 | All 8 ordinary-CLI combinations, independent IPC/HTTP/TLS, native smoke and same-DB restart, DEX OFF, and omitted/empty/relative/absolute trie-journal restart. |
| source | `/tmp/common-dex-check.uQb9iw1e` | PASS, 1 top-level/1 pass event, 44.57s | 7 CLX children + source Common, 6 ordinary deposits, ordinary ETH catch-up, height 11/inbox 6/custody 6 CLX after DB restart, engineDelta 0, no coordinator InsertChain. |
| roles | Not started | NOT_RUN | Automatic permission-review timeout. No child process/session was created. Source freeze had been lifted for the G3 observer fix, so no retry was made at this point. |
| process | Not started in this run | NOT_RUN | To be rerun after final source freeze. Prior c3e925 PASS retained as intermediate evidence. |

All 3 executed modes had source diff 0 and test/run exit 0. Ordinary 32 GiB PoW nonce search did not run, distinct from CLI lifecycle PASS. Socket pass-event counts include subtests/seeds, not independent safety requirements. Source's 6 CLX is a short separate ledger, not the 225→214 or long-term 295 financial test. Loopback is not a WAN measurement. Each runner was limited to a new `unshare -Urn` namespace, with no host-network fallback.
