# Native browser acceptance claim audit — final

Updated 2026-10-03T17:53:23.212947+00:00 by read-only inspection of `native-discovery-browser-report.json`, its events/log, `tests/mesh-browser.mjs`, `tests/mesh-evidence.mjs`, and the final scale report. No product edits, browser launches or native calls were performed by this audit.

## Completed native acceptance

**PASS**, 2026-10-03T17:14:47.203Z to 2026-10-03T17:47:07.980Z. Measured soak: **1,860,003ms (31minutes)** beginning 2026-10-03T17:15:49.597Z. Product source hashes remained unchanged, including `relay/discovery.mjs` SHA256 `ada83d15070ee19a7076de2e2665234cf9706aa5dc6e4b0ead5521d6dddac178`.

| Result | Verified evidence and boundary |
| --- | --- |
| Real browser/native data path | Independent Chromium processes and separate loopback TLS gateway origins; each browser has exactly one configured native Common attachment. Common authentication is native RLPx. Workers verify the other Common's signed advertisement despite its absence from their local Common list. |
| Exact transfer/receipt | Separate sender/receiver observations match canonical base64, browser generations, raw byte length and SHA-256 against a returned hop ACK:529bytes on initial A→B,570bytes on replacement C→B, plus a new proof after abrupt death. Ciphertext samples can be RLPx handshake/stream chunks; ACK proves bounded browser-queue acceptance, not consensus, finality or native block adoption. |
| Graceful and abrupt route replacement | A OFF drains native/browser routes and queues; a3.5second stable-counter interval excludes old buffered traffic. C establishes a new native circuit. After the soak, SIGKILL of owned C reclaims the route/queue in4,604ms in this environment, and D establishes another independently matched transfer. |
| Chain data | B remains mesh-only and progresses from height4,008 to4,017. A/B/reference hashes match at0,1,1,000 and4,017; height4,017 is `0x2318cf83fbaac646d54f444634ff7163756a2cef941c47ed5030f26cfb4a3089`. Existing B data was retained: this is incremental sync, not genesis-to-tip bootstrap. |
| Lease renewal | B and C each complete15 native lease renewals, confirmed in the event file and advancing expiry within the same session. Each has one session generation during the182 recorded soak samples, all with unexpired reported leases. Sampling does not establish authoritative native lease existence at every instant. |
| Natural30minute circuit expiry | Both Workers record `circuit-expired` for the same circuit, with `expiresAt-createdAt=1,800,000ms`. A different authenticated native circuit is subsequently observed carrying720bytes received and778bytes sent. This proves the natural TTL event and reconnection separately from the earlier forced recovery test. |
| Browser lifecycle | Trusted desktop-Chromium hide/freeze/resume events stop participation; resume remains OFF. Navigation removes the last Worker. Five exact runner-owned lease credentials subsequently return401; native A/B routes and B peers are zero. |

The run has no page errors, but records two `invalid_receipt` Worker events before the measured soak (one A, one C). Do not call the entire run error-free. These rejected receipts did not defeat the subsequent exact receipt checks or the completed soak; their cause is not inferred from the counter alone.

## What this run does not prove

**Signed public endpoint attachment is a separate result.** The real Common endpoint descriptors name the production gateway origin, whereas this harness uses synthetic `native-gateway-a/b.example.org` origins. The gateway correctly rejects that origin mismatch; both browsers have `verifiedEndpoints:0` throughout the soak, and `maxCommonConnections:1` intentionally isolates the relay path. This run proves previously unlisted **native advertisement** verification and native data transport, not automatic remote-primary selection or live-native remote endpoint attachment.

The signed protocol-fixture browser test separately proves discovery/verification of an unknown endpoint and an independent foreign WSS lease. The actual HTTPS publisher test separately verifies test-CA TLS/SNI and unknown-Common self-publication. A public remote-endpoint/native-browser acceptance was still a separate, unassessed test when requested; this audit does not predeclare its outcome. Read its completed report independently before making that claim.

This native run forces direct RTC, with all participants on one host and local hostname mapping. Temporary browser test certificates are accepted through test flags. It is not public PKI/Nginx rollout acceptance, TURN traversal, multiple physical devices/regions, cellular networks or iOS/Android hardware. Native B's network-namespace isolation has separate deployment evidence; `nativeBIsolated:true` alone is not that proof. Native owner RPC/status and canonical-hash comparisons do not independently establish browser finality verification.

AI checks inject loading/benchmarking/generating state signals and verify circuit/byte policy; `actualLLM:false` remains explicit. Sampled Worker reservation peaks are326,696bytes(B)/325,778bytes(C), and queue peaks2,520bytes(B)/1,502bytes(C), within4MiB/512KiB accounting limits. These are application accounting, not browser RSS, total heap/GPU memory, thermal behavior or real model coexistence.

## Scale acceptance

`discovery-browser-scale-report.json` is **PASS**. Its S0…S20 entries have21 distinct Chromium process IDs, with one isolated context/page per process. All21 report20 connected RTC peers and one Common attachment at the final convergence check. The scale phase takes164,358ms, including sequential browser launches, and ends immediately after that condition; it does **not** test sustained20-neighbor throughput. Native endpoints here are signed protocol fixtures (`nativeFixture:true`, `nativeRLPx:false`, `sameHostOnly:true`, `physicalMobile:false`). Earlier A/B/C/D participants explain the25 total recorded process entries; they are closed before the21-process phase.

The final scale source hashes match. Gateway rejection counts remain `peer_capacity`7/9 and `signal_capacity`1/0; valid delayed unavailable destinations are dropped87/122 times. No signature/replay/renewal/ICE-limit rejection is recorded. `peer_capacity` combines target-count and recipient enqueue refusal, so exact causal attribution is unavailable. Report bounded admission/retry convergence, not uninterrupted20-peer service. Separate cleanup evidence records all25 owned browser PIDs absent, with no native access.

## Cleanup and ownership

Path assertions and revocation select this runner's captured browser identities/leases; only tracked owned Chromium children are killed. The native inspector enumerates the dedicated endpoints' peer/status metadata using bounded read-only IPC and never opens chain DBs. No native processes are stopped by this browser test.

The harness finalizer has an exception-path weakness: rejection of `browser.close()` can skip subsequent child/profile cleanup in that callback. Independent `native-browser-owned-cleanup.json` found all4 browser PIDs absent but two leftover B/D profiles. `native-browser-owned-cleanup-resolution.json` records scoped removal of exactly those validated directories at17:51:08UTC, with both PIDs and paths absent afterward and the initial audit preserved. Cleanup is therefore resolved by that separate evidence, not inferred merely from the PASS field or entry into `finally`.
