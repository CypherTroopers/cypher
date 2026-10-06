# Browser Common mesh verification — 2026-10-03

This record covers the public deployment at https://ai-test.make-cph-great-again.community/ and the revised native encrypted-stream contract. The31-minute run is complete with a preserved runner failure and audited partial results. Post-run readiness correction and short direct/UI PASS results are recorded separately; these do not retroactively change the long-run result.

## Deployment and preserved state

Web baseline HEAD was `1e2839e95612d22b5fdc2aed5bf5b78e344f2e0b`; native baseline HEAD was `f8ee241a2cb2e813589df5d0dbe3dba93e0734d7`. Existing uncommitted changes were inventoried and retained, and web implementation was staged outside the live public directory. Public HTML/assets were exchanged atomically and the existing web server's explicit asset allowlist was updated. `evidence/web-preservation.json` records original dirty-file hashes and the intentional merged edits.

The two new Commons use separate datadirs, identities and private sockets. They run the supplied native build with SHA256 `3bafe0f18343f18533ef8528ab314ddaa7264953c2bc2ad9f33376ef5756bc6f`. Common B remains in a separate network namespace with only loopback, no outbound route, no discovery/static/bootstrap peer, and no copied/imported chain data. Only its browser mesh transport supplies chain ingress. The owner inspector reads IPC for evidence; it neither opens another process's chain database nor injects chain bytes.

The public gateway admits fixed Common A/B socket targets only. It exposes `/relay/v1/mesh/` and separate native WSS/signaling WSS; it has no Common-to-Common data bridge or general TCP/RPC proxy. The actual data hop is an ordered/reliable browser WebRTC DataChannel. Native endpoints perform secp256k1 advertisement verification and RLPx authentication. The browser preserves raw signed advertisement bytes and ciphertext, checks schemas/network/pins/freshness/sequence, and uses a separate digest-bound hop receipt.

During this work another actor changed the original miner launcher at04:27:00 UTC and PM2 explicitly stopped that app at04:27:07; its new startup then failed. Seven original native PID/starttime pairs remained unchanged. This work did not edit/restart the original miner. To restore fresh data independently, only our Common A received an additional normal TCP static peer to existing node0 at04:59:35.936 UTC; existing6099 was retained. A/B/reference advanced3777→3789, canonical hashes0/1/1000/3789 matched, and B's same test-owned browser circuit received the new bytes. Source change and B namespace proof: `evidence/mesh-upstream-addition.json`. node0 is not a browser gateway endpoint; gateway/browser A/B pins and B network configuration stayed unchanged.

## Executed checks

| Check | Result and scope | Evidence |
| --- | --- | --- |
| Web JavaScript automated suite | 216 PASS,3 opt-in TURN checks skipped in this suite (219 total), including the post-soak401 recovery fix | `evidence/cypher-mesh-postfix-unit.log` |
| Python server and scoped process operations | 23 PASS | `evidence/cypher-mesh-final-python.log` |
| Existing rendered workspace behavior | 27 PASS, with mocked model/GPU/OpenClaw; includes mobile layout, IME, local memory and automatic search behaviors | `evidence/cypher-mesh-workspace-smoke.log` |
| Native race tests | cmd/cypher, node/browserrelay and p2p PASS;84 top-level +85 subtests; protected native source hashes unchanged | `evidence/mesh-native-race-result.json`, full JSONL alongside |
| Real dedicated TURN | 3 PASS: unauthenticated/forged/expired credentials, allocation quota/private destination rejection, actual relayed bytes | `evidence/cypher-mesh-turn.log` |
| Public HTTPS boundary | 15 PASS through public DNS/Cloudflare: config, Origin/auth/query-token checks and rejection of owner/private endpoints | `evidence/cypher-mesh-public-boundary.json` |
| Public OFF layout | 1440px/390px no horizontal overflow or page errors; no automatic session participation | `evidence/cypher-mesh-ui-report.json` and screenshots |
| Public31-minute forced-TURN run | 1,860,002ms observed; raw runner FAIL on an arbitrary14-renewal threshold (actual13 each), with real data exchange and automatic recovery. Uninterrupted stability is not established. | `evidence/soak-pre-fix/cypher-mesh-final-audit-summary.json` plus gzipped raw report/events and hash manifest |
| Public direct RTC run, post-fix | PASS in46.553s: actual direct RTC, native authentication/bytes/digest/ACK, A OFF, replacementC, workload/readmission and trusted hidden/freeze/resume/navigation | `evidence/direct-post-fix/` |
| Ordinary public UI ON/OFF, post-fix | PASS using two independent Chromium processes and normal buttons,1440px/390px; Common1/1, browser1/3, circuits1/2, ACK11 each; OFF/reload staysOFF and no overflow | `evidence/mesh-ui-browser-report.json` and six screenshots |

Invalid-input/resource checks cover duplicate/unknown JSON fields, pins/network/expiry, route loops, old sessions, sequence/credit mismatches, receipt replay, resource reservations, queue/frame/handshake limits, gateway admission/Origin/rate limits, and stale asynchronous work after OFF. These tests establish bounded application logic; they are not an Internet-scale denial-of-service or network capacity benchmark.

## Evidence interpretation

Actual native browser-mesh peers, their RLPx stream bytes and canonical hashes are distinct from RTC traffic/receipts. A browser hop ACK confirms acceptance of exact ciphertext into a bounded next-hop queue; it is not proof of Common consumption, chain adoption or finality. Native credit is unsigned flow control, not an independent receipt. Successful send() is never counted as acknowledgment.

The long test observed two unsolicited paired browser-hop/native losses plus two further C-only readmissions. Timed automatic readmissions were B2/C4; both ended ACTIVE. Do not describe it as uninterrupted stability. Their initiating cause is not yet determined; native Attach currently discards the close error. The second loss preceded the added TCP source and cannot be attributed to that operation. A new circuit ID after early loss is not evidence of natural30-minute circuit expiry. The final audit separates those claims and preserves the runner's unmodified report SHA256 `eb32dbafb4275272cf5c0ef106564440f7a3609fdd56831d8a060f5049203396`. The original harness stopped on its fixed14-renewal assertion;13 successful renewals each plus readmissions were observed. Auditing does not turn that runner FAIL into PASS. Consequently lifecycle checks after that assertion require the separate short direct run.

Earlier partial reports remain historical diagnostics: one used a stale UI statistic for its OFF assertion, another timed out waiting for near-tip sync while B had actually progressed from genesis, and a preflight required an excessive immediate idle-circuit byte count. These were not final PASS runs. The meaningful Worker correction was ordering the exact source advertisement immediately before an incoming native open when native candidate state may have been removed after a failed dial.

## Post-run readiness correction

At05:13:56 UTC a scoped two-file controller change was deployed after preserving the long-run versions. HTTP errors now retain a numeric status; an authenticated current-generation status401 immediately clears native readiness and triggers bounded fresh admission, instead of waiting for the delayed WSS close event. Old-generation401 responses cannot stop a new session, temporary503 status does not cause readmission, and the ON transfer budget survives recovery. Four targeted regressions pass; two reproduced the defect before the fix. `evidence/mesh-status-recovery-deploy.json` records before/after hashes. This corrects stale UI/recovery delay, not the unknown cause of the earlier underlying connection losses. The31-minute test was not rerun on this revision; short direct/UI results below use it.

## Long-run measured values

The timed interval started04:38:37.896 UTC and lasted1,860,002ms, using independent Chromium processes through public DNS/Cloudflare with actual forced-TURN RTC. Common B advanced3777→3789; the added normal TCP source on A is explicitly recorded above. All7 frozen deployed core hashes matched before/after, checked independently because the legacy runner assertion aborted its normal final hash check.

| Measurement | Browser B | Browser C |
| --- | --- | --- |
| Final cumulative application bytes during this ON | 4,426,505 | 4,382,234 |
| Final independent hop receipts | 1,291 | 1,287 |
| Peak sampled application reservation bytes | 302,774 | 302,934 |
| Peak sampled queued bytes | 2,615 | 862 |
| Successful lease renewal events | 13 | 13 |
| Automatic readmissions in timed interval | 2 | 4 |

These are cumulative ON/sample measurements, not all exclusively timed-interval deltas, and sampled peaks can miss shorter bursts. One invalid receipt was rejected without stopping C. Reported session expiries kept progressing, but stale status/401 gaps prevent treating those reported dates as continuous authoritative lease validity. Final owned cleanup found no native A/B test sessions/routes/mesh peers. No unrelated participant lease was revoked.

## Post-fix direct/lifecycle result

A separate public run from05:14:35.190 to05:15:21.743 UTC used actual direct RTC (no TURN ICE entries in this test harness) and passed. The test independently compared an exact448-byte encrypted chunk, SHA-256 and hop ACK, then proved A OFF drains/stops the sole path and newly admittedC restores native RLPx. B advanced3789→3792 with canonical hashes matchingA/reference at0/1/1000/3792. There was no gateway-only data fallback or direct injection.

Actual browser-generated trusted hidden/freeze/resume events stopped participation; returning to visible did not restart it. Navigating away terminated the last Worker. All4 runner-owned leases returned401 and owned native routes/mesh peers were reclaimed, with no unowned lease revocation. All7 core hashes stayed unchanged on the post-fix revision. One invalid receipt during churn was rejected without stopping B; there were no fatal browser errors. The mobile viewport is Chromium emulation, not physical iOS/Android hardware.

## Ordinary public UI result

At05:18:45–05:19:39 UTC, two independent Chromium processes visited the public page through normal DNS/Cloudflare and used only the actual navigation and Node buttons. There was no controller injection, DOM mutation, request interception, forced transport or hidden Common selection. Both startedOFF without a session POST. On explicitON they naturally received common-a/common-b, displayed Common1/1, browser peers1/3, circuits1/2, and11 hop receipts each (808/815 bytes). Country metadata displayedFrance for both; no coordinates were invented.

Desktop1440px and mobile390px had no horizontal overflow or page errors. NodeOFF reset Common to0/1 and browser peers to0; waiting16seconds, navigatingHome and reloading did not restart participation. Both owned pages closed afterOFF; no unowned session was revoked. The first attempt failed only because the test treated a transformed offscreen drawer item as visible; the corrected test uses the real menu button. That original harness failure remains separate. Physical phone testing is not claimed.

## Cleanup

The retired header-only source was rechecked as stopped under its exact PM2id10/name/launcher/cwd/interpreter with PID0, then only that obsolete PM2entry and its obsolete P-256 test signing key were removed. Retained DB/config/log archive metadata was unchanged. Runtime A/B native identities and TURN operation secret remain owner-only because the deployed services still use them. See `evidence/retired-source-cleanup.json`. No original uncommitted file was deleted for being unused. Twelve obsolete header-prototype files were removed only from isolated staging after preserving a historical archive; deployed reusable modules and the pre-existing workspace were retained. Final05:20:43 UTC observation found A/B still running at their original PIDs with zero restarts, and the independently changed original miner stillerrored. With all test browsersOFF, A had its ordinary TCP upstream and B had zero native peers/mesh sessions: A/reference reached3795 while B remained3792. This is expected cessation of B's sole browser ingress, not a claim that an OFF browser continues relaying. Final observation files are `evidence/mesh-final-native-status.json` and `evidence/mesh-final-process-status.json`.

## Current UI measurements

The main Browser peers, Common connections and Common relay circuits counters now show actual counts as integers, without capacity denominators. Only open DataChannels count as browser peers; the authenticated Common WSS attachment counts as a Common connection. Circuit counts exclude pending opens, which are displayed separately. The unchanged 3 / 1 / up-to-40 capacity bounds appear under Connection limits & counting. The map explicitly describes this browser's connected neighbors, not a global Common topology. See the display update at the end of [capacity-update.md](capacity-update.md). Earlier reports and screenshots above retain their original UI and validation scope.

The map revision described in [map-update.md](map-update.md) expands country anchors from16 to249, separates same-country pins, keeps mobile markers readable and drives directional lights from actual chunk receipt, send-queue submission and hop ACK events. Unknown locations remain unknown in a separate non-geographic area. Its renderer fixtures and ordinary public-browser acceptance are recorded separately from the native mesh/soak results above. The user's iPhone screenshot is an independent observation, not a controlled physical-mobile acceptance run.

## Unverified limits

- Different physical devices/access networks, restrictive NATs, real iOS/Android background transitions and radio switching: NOT_RUN.
- Actual sustained local LLM inference/model loading on a GPU while forwarding: NOT_RUN. Harness workload transitions exercise the application's real load signals with measured browser behavior, not a model inference.
- Actual four-browser native stream path: NOT_RUN; four-browser routing is exercised in Worker tests.
- Natural30-minute lifetime of one uninterrupted native circuit: requires an exact expiry event followed by new authentication/data, not merely a replacement ID.
- Host reboot, macOS/Windows native operation, TURN TLS/443 and IPv6 paths: NOT_RUN/unsupported in this deployment as described in the operation guides.
- Application byte/queue/reservation measurements exclude TLS/SCTP/IP framing, retransmissions and browser implementation memory. The4MiB reservation budget is not total browser RSS; the100MiB ON budget is not an ISP byte meter.
- Full sync of arbitrary maximum-size native blocks is not guaranteed over the bounded supplementary path; mesh native frame maximum remains4MiB.

Start/stop instructions and actual endpoints are in [README](README.md), [native operations](mesh-native-operations.md), [gateway operations](gateway-operations.md), and [scoped service operations](managed-operations.md). The scoped service is enabled for future boot; enabling did not restart the running apps or configure the original nodes' reboot behavior.


## Current connection-capacity follow-up

The20-browser-peer /20-Common-attachment update is recorded separately in [capacity-update.md](capacity-update.md#follow-up-20-browser-peers-and-20-common-attachments) and `evidence/mesh-20x20/`. Earlier3-peer/1-Common results above retain their historical scope. The newer limits do not retroactively extend the31-minute result or establish20 physical devices,20 distinct native Commons or sustained mobile performance. Native signed advertisement/candidate discovery already exists; the current web pin policy and missing public mesh-WSS bootstrap remain explicit deployment limitations.
