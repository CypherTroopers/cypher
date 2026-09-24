# Final Financial Ledger for Continuous Operation — Trial 15

The isolated devnet test using the ordinary CLI and real TLS/ETH/TxQUIC was **PASS (1546.32 seconds)**. Final CLX height 749, DEX finalized 109, CLX accepted 109, and 0 unsettled finalized sequences. Certified 110 is not counted as settled. Confirmed 72 unique native payments and completed reauthentication of 406 operations across 2 relays (203 each).

Target source manifest: `7f786223801e567b77c6c37bf437c189ea440de3db91f0b93d4fae705cdc97e2`. Matched at start/end; run/test exit 0. Raw SHA-256: `ac45652614b46d0c800e450064acebe3c2fff87beab6aa88d512a8d66ee523df`.

Evidence: [raw log](results/continuous-g3-normal-15.log), [execution metadata](results/continuous-g3-normal-15-metadata.json), [independent ledger reconciliation](results/continuous-trial15-independent-ledger-audit.json). The original 225→214 regression belongs to another run and is not mixed into this ledger.

## Conservation and Final Buckets

Native deposits in this run totaled 345 CLX (trader 320, support 20, insurance 5). Four withdrawals paid 40 CLX and 68 rewards paid 10 CLX, giving **345−40−10=295 CLX**. Rewards consumed 0.168 of 0.336 CLX in DEX fee revenue and 9.832 from support, leaving fee 0.168 and support 10.168. There was no unlimited issuance or gas payment from custody. This does not establish that fees alone sustained 10 CLX in rewards.

All values below are integers in the minimum CLX unit (1 CLX = 10^18 atoms). Height 707 was an intermediate reconciliation at payment completion; height 749 is authoritative and includes final gas.

| Bucket | Meaning | Final atoms |
|---|---|---:|
| F | Unused fees | 168000000000000000 |
| I | insurance | 5000000000000000000 |
| R | Unpaid reward reserves | 0 |
| S | Unused support | 10168000000000000000 |
| T | Trader rights | 279664000000000000000 |
| U | Unimported deposits | 0 |
| W | Unpaid withdrawal reserves | 0 |
| Z | dust | 0 |

Total 295000000000000000000 atoms. Surplus 0, unpaid reserves W/R 0. Internal trader rights result from the existing FIFO/cash/PnL/funding model and are not added again to wallet balances.

## All 17 Native Accounts

| Role | Address | Initial atoms | Final atoms | Delta atoms |
|---|---|---:|---:|---:|
| Common RPC reward recipient | `0x000000000000000000000000000000000000B123` | 123 | 894784081920000123 | 894784081920000000 |
| native custody | `0x0000000000000000000000000000000000De0001` | 0 | 295000000000000000000 | 295000000000000000000 |
| DEX reward recipient 6 | `0x031ffCDA4a3cbf4Ae9ffBafD66263D3b9D7C3449` | 0 | 1142857142857142856 | 1142857142857142856 |
| Alternate recipient for an old claim | `0x08F389Bc3bef2e7495254158cdD49e9178A303A2` | 0 | 10000000000000000000 | 10000000000000000000 |
| relay gas payer 1 | `0x12a025b972e8bC244FF4Ae8fC89E028150F27Ea3` | 1000000000000000000000 | 997759441926400000000 | -2240558073600000000 |
| Support/insurance funder and fixture sender | `0x34982A282B5cF900B54df3A4e07672e43a08097d` | 1000000000000000000000 | 974997551680000000000 | -25002448320000000000 |
| DEX reward recipient 4 | `0x3fB187aF2CA2E5DbFb28E56d0AfcfD028274633f` | 0 | 1476190476190476188 | 1476190476190476188 |
| DEX reward recipient 3 | `0x4902cAE82C265a0C5204F968af923B1819daadaa` | 0 | 1476190476190476190 | 1476190476190476190 |
| DEX reward recipient 2 | `0x4d57aD290bB35078f8fEd3d19a4473524624eD3c` | 0 | 1476190476190476190 | 1476190476190476190 |
| relay gas payer 0 | `0x6AA32A6a6b85eb0e65859804f2665139868524A1` | 1000000000000000000000 | 997772562464000000000 | -2227437536000000000 |
| DEX reward recipient 5 | `0x80E15c782f9f2386060741c54f18ff41B2359E9E` | 0 | 1476190476190476188 | 1476190476190476188 |
| DEX reward recipient 1 | `0x8C468f4eBbE4c3d17d0E346EF574852C176320E6` | 0 | 1476190476190476190 | 1476190476190476190 |
| trader B | `0xE7CA5fF5C20FF72e1A1e45a11083a0E640663e90` | 1000000000000000000000 | 839998261760000000000 | -160001738240000000000 |
| Existing CLX fixture account (unused) | `0xb27862213A666048ebd414DD0E46D5247501e0c4` | 1000000000000000000000000000 | 1000000000000000000000000000 | 0 |
| DEX reward recipient 0 | `0xdA727833F3383E29DfA8A1c082d7FEeE7a10AA20` | 0 | 1476190476190476198 | 1476190476190476198 |
| Common RPC admission signer (77 atoms unchanged) | `0xe835CB3A8F9407103E54053CAb9f0373133600e4` | 77 | 77 | 0 |
| trader A | `0xfa1a89887B3d554B5A15733FFFE4F642De3910b8` | 1000000000000000000000 | 869998261760000000000 | -130001738240000000000 |

Recipients 0–6 correspond to `Members`/`Peers` indexes and recipients in the public DEX manifest, not address sort order. Relay indexes were checked against `NORMAL_RELAY` in the raw log and public relay configuration.

The sum of all account deltas is `−3579136327680000000` atoms, matching burn. The Common admission signer, Common reward recipient, DEX reward recipients, and relay gas payers are separate accounts.

## Gas, Common Rewards, and Burn

The 410 canonical TXs were counted without duplicates by TX hash. Total gas units 2796200256; paid 4473920409600000000 atoms; Common rewards 894784081920000000 atoms; burn 3579136327680000000 atoms. All TXs have receipt status 1, but semantically exact checkpoint/claim resubmissions also pay ordinary gas.

| Gas payer | TX count | Gas units | Gas atoms | Common atoms | Burn atoms |
|---|---:|---:|---:|---:|---:|
| trader A (`0xfa1a89887B3d554B5A15733FFFE4F642De3910b8`) | 4 | 1086400 | 1738240000000000 | 347648000000000 | 1390592000000000 |
| trader B (`0xE7CA5fF5C20FF72e1A1e45a11083a0E640663e90`) | 4 | 1086400 | 1738240000000000 | 347648000000000 | 1390592000000000 |
| Support/insurance funder and fixture sender (`0x34982A282B5cF900B54df3A4e07672e43a08097d`) | 49 | 1530200 | 2448320000000000 | 489664000000000 | 1958656000000000 |
| relay gas payer 1 (`0x12a025b972e8bC244FF4Ae8fC89E028150F27Ea3`) | 176 | 1400348796 | 2240558073600000000 | 448111614720000000 | 1792446458880000000 |
| relay gas payer 0 (`0x6AA32A6a6b85eb0e65859804f2665139868524A1`) | 177 | 1392148460 | 2227437536000000000 | 445487507200000000 | 1781950028800000000 |

| Operation | TX count | Total gas atoms | Maximum gas units/TX | Maximum calldata bytes/TX |
|---|---:|---:|---:|---:|
| funding-1 | 8 | 3476480000000000 | 271600 | 12 |
| funding-2 | 1 | 434560000000000 | 271600 | 12 |
| funding-3 | 1 | 434560000000000 | 271600 | 12 |
| anchor | 21 | 503310208000000000 | 15416776 | 63566 |
| checkpoint | 109 | 2115908057600000000 | 12181972 | 3104 |
| checkpoint-replay | 91 | 1766448147200000000 | 12181748 | 3100 |
| claim | 72 | 44909990400000000 | 390156 | 356 |
| claim-replay | 60 | 37419206400000000 | 390156 | 356 |
| transfer | 47 | 1579200000000000 | 21000 | 0 |

## Authentication, Claims, and Recovery from Outages

The CLX deposit-authentication base advanced through consensus from old source 95 using multiple bounded proofs. The all-DEX outage lasted at least 89 heights, from CLX 168 to source 257 authenticated before restart. The logged `resumedCLXHead=241` is an intermediate observation of 73 heights of progress, not the actual restart height. The ordinary CLX key-renewal clock was unchanged; 4 ordinary carriers and 6 minutes 8.496 seconds produced the source 246→257/v2 observation. This describes input timing, not authentication authority.

The flat state was finalized 58 (version checked at 59)/source 255/v1/cursor 8. The next 40 CLX in deposits finalized at actual CLX 281/285; finalized DEX 79 in cycle 3 demonstrated source 314/v2/cursor 10. When all 7 CLX nodes stopped, CLX 361/accepted 60 versus DEX finalized 78 retained a difference of 18. After recovery with the same DB, subsequent checkpoint 78 finalized through an ordinary TX at CLX 467.

The unpaid claim under old checkpoint 14 was paid once after later anchors/reward periods; 72 Claim.ID/nullifiers and 72 leaf hashes were reconciled. Logged `CONTINUOUS_CLAIM id=` is a leaf hash, distinct from protocol Claim.ID. The 239-byte claims were reconstructed independently from public relay-storage bytes, checking domain/recipient/amount/period/hash/nullifier and actual bytes in both relays. This offline audit did not perform new FHS/MPT authentication. The combined endpoint of payment followed by another anchor update, DB restart, and another relay resubmission belongs to a separate focused unit test; this long run did not execute every combination.

The financial phase retained a 120-second canonical idle limit and reached 72 payments in 1 minute 50.176 seconds. After full-ledger reconciliation, relay reauthentication reached 406/406 in 2 minutes 9.133 seconds. The reauthentication phase also retained idle 120 seconds and a 45-minute parent limit. ACKs, source heights, ordinary carriers, and redisplay of the same IDs did not extend deadlines.

## Evidence, Storage, and Execution Bounds

| Item | Maximum observed in this run | Retained bound/meaning |
|---|---:|---|
| Native anchor calldata | 63566 bytes | 65536 bytes/TX |
| Ancestor + continuation headers | 32 | 64/update |
| MPT nodes (measured account/count/entry total) | 7 | 65 nodes/proof, 1024 bytes/node. The total 7 is not a theoretical limit. |
| MPT bytes (same total) | 2105 | Overall limits such as calldata also apply. |
| Native anchor gas | 15416776 | Actual receipt value; does not mean zero/constant processing. |
| Observed DEX WAL v3 | 1870382 bytes | 2097152 bytes |
| Observed WAL records / dictionary | 115 / 110 | 128 records; deduplication of exactly identical actions. Snapshot format remains v2. |
| Relay history | 203 complete each | Existing bounds including active 256/history 1024 and persistent store 48 MiB. |

Existing bounds also apply to descendant proofs, signatures, MPT, and decoding beyond ancestry. The 525-byte fixed checkpoint portion is not the cost of the entire submission. The table shows observed maxima for native anchor TXs, not theoretical maxima for every evidence type, cryptographic verify-call counts, state-write counts, C heap, or wall-clock bounds. Limited cost tests are documented separately; WAN/60-minute load/ordinary PoW are separate gates.

## Process and Synchronization Scope

| Role | Distinct role slots | Successful starts confirmed in logs |
|---|---:|---:|
| CLX committee | 7 | 14 (resumed after all stopped) |
| Common DEX parent | 7 | 14（cold reopen） |
| DEX sidecar | 7 | 14 |
| relay | 2 | 6 |
| Later DEX-OFF Common | 1 | 2 (same-DB restart) |
| Total | 24 | 50 |

One additional test-coordinator process hosted CLX source Common. The ordinary full-participation layout was 23 role processes +1 coordinator. The 50 in the table counts successful role starts including restarts; it is neither 50 concurrent processes nor a comprehensive count of all OS children including key generation/initialization/failed startup probes. This does not measure a 7-host WAN or 7 independent operators.

The 7 existing Common nodes matched CLX 749 hash/state/tx/receipt roots/gas and 410 receipts. The later DEX-OFF Common synchronized 750 blocks from genesis using ordinary ETH only, with every encoded block/receipt/native bucket/inbox compared. These also matched after same-DB restart; engine instances/actions/inbox imports were 0/0/0. The coordinator did not correct synchronization state.

After execution, runner/public watcher exited 0, and all 50 role PIDs in the logs were confirmed absent from `/proc` ([exit audit](results/continuous-trial15-process-exit-audit.json)). No signals were sent to operational processes.

The signing-committee trust model and DA/Oracle dependencies remain. Results use fixed DEX epoch 1, loopback, and fixture rates/budgets; they do not establish completed Validity Proofs, public committee rotation, new FROZEN loss allocation, or production performance/profitability.
