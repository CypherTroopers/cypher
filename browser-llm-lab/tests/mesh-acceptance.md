# Common browser mesh acceptance

This record concerns `cypher-browser-mesh/1`, the opaque Common-to-Common RLPx transport. It does not use the earlier signed-header overlay as a substitute for native peer communication.

The browser protocol and Worker are `public/mesh-protocol.js` and `public/mesh-worker.js`. The Worker receives an operator-pinned Common connection and up to three admitted browser peers, propagates bounded advertisements, and routes ordered encrypted chunks through native WebSocket and WebRTC endpoints. Native Common nodes verify secp256k1 advertisements and RLPx identities. Browser checks validate exact schemas, network and public-identity pins, timestamps, route labels, sequence numbers, queue reservations and hop receipts. The browser does not claim to verify secp256k1 signatures itself.

`nativeCreditBytes` measures forwarded native flow-control messages. `acknowledgedBytes` measures independent browser hop receipts, issued after the receiving browser accepts the exact SHA-256-bound chunk into a bounded downstream queue. Neither counter proves chain adoption, finality, a reward, or honest native consumption. `pendingHandshakes` is the number of pending mesh circuit opens; native RLPx authentication is established separately by native peer evidence.

## Focused automated checks

```sh
node --test tests/mesh-protocol.test.mjs tests/mesh-worker.test.mjs \
  tests/mesh-controller.test.mjs tests/relay-controller.test.mjs
```

The protocol and Worker tests cover duplicate JSON keys, strict native/peer schemas, advertisement byte preservation, explicit signature-verification boundaries, network and endpoint pins, route loops, stream and credit limits, direct and four-browser routing, independently calculated opaque-byte hashes, separate native credit, receipt replay, stale connection generations, close propagation, bounded eight-chunk bursts, AI load policy, retained participation budgets, and stopping during asynchronous hashing.

A native implementation detail matters after failures: a failed outbound dial can remove its candidate while the browser still retains a valid advertisement. Before forwarding an incoming `open` to its target Common, the Worker now enqueues the exact signed source advertisement on the same ordered native queue. A regression asserts the advertisement immediately precedes the open and preserves the signed payload and target session.

## Actual browser runner

`tests/mesh-browser.mjs` launches separate Chromium processes with separate profiles. It connects real Common A and B through the public gateway and browser DataChannels. Common B is operated in an isolated network namespace without ordinary outbound connectivity or static/discovery peers. Owner-only native RPC is used exclusively for observation of native peers, stream counters and canonical block hashes; it does not inject chain data or bridge connections.

```sh
MESH_PUBLIC_ORIGIN=https://ai-test.make-cph-great-again.community \
MESH_FORCE_TURN=1 MESH_CHECK_LIFECYCLE=1 \
MESH_CHECK_WORKLOAD=1 MESH_CHECK_READMISSION=1 \
MESH_SOAK_MS=1860000 MESH_REPORT=/tmp/cypher-mesh-final-report.json \
node tests/mesh-browser.mjs
```

The runner verifies real A-to-B opaque bytes against an independent SHA-256 calculation and the separate hop receipt. It then turns A off, waits for native circuits and browser queues to drain, checks that RTC reception stops, and admits C as the replacement route. Native peer authentication and canonical hashes are observed again. Already-synced nodes may exchange fewer than 1,000 bytes immediately after re-authentication; acceptance therefore requires an authenticated native mesh peer and positive bidirectional stream counters, with exact-byte/receipt evidence checked separately.

The optional workload checks use the application's actual workload signals. They do not run a WebLLM inference. Loading and benchmarking close circuits while keeping control sessions; idle resumes advertisements; generating permits one circuit with a smaller JSON budget. A deliberate native WebSocket close must obtain new app, browser and native session identities without resetting the participation byte count.

For a 31-minute run, the report captures lease renewals, native circuit IDs and bytes, real transfer counters, source advertisement times, RTC statistics and bounded application reservations. A changed circuit ID proves replacement only. Natural expiry is reported separately as `OBSERVED` only when an exact `circuit-expired` event is followed by a different authenticated native circuit carrying bytes in both directions; otherwise it is `NOT_OBSERVED`. `MESH_REQUIRE_NATURAL_TTL=1` makes that separate observation mandatory. Implementation hashes are checked before and after; deployed browser module hashes must match the staged files.

With lifecycle checks enabled, Chromium is started independently and attached using CDP without Playwright's normal visibility overrides. An actual foreground-tab change produces trusted `visibilitychange`, and CDP freeze/resume produces trusted browser lifecycle events. Participation must stop and remain off after resume. Navigating the last active test page away must terminate its Worker. Final owner-only inspection requires this runner's native routes and native peers to disappear, and each runner-owned bearer lease must return HTTP 401. The native nodes and TURN process are not stopped by this runner.

The public service can have real participants during the test. The harness filters candidate adoption, peer creation and incoming signaling to the peer IDs it admitted itself, updating that private allowlist after native readmission. Native proof and cleanup checks use only the recorded test browser route labels. It never deletes someone else's lease and does not require global session counts to reach zero.

`MESH_FORCE_DIRECT=1` instead removes ICE servers in the test harness and requires an actual direct candidate path. It cannot be combined with forced TURN. `MESH_ORIGIN_LOOPBACK=1` is an explicit diagnostic fallback that maps the public hostname to local Nginx while retaining TLS; a report using it must not be described as traversing public DNS/Cloudflare.

## Limits and interpretation

- Browser application reservations: 4 MiB; combined ingress, outgoing and pending-send queues: 512 KiB; outgoing frames: 64; incoming queued frames: 128. These are explicit application reservations, not total browser RSS.
- A chunk is at most 8,192 raw bytes and a complete native or peer JSON frame is at most 16,384 bytes. A circuit permits eight uncredited chunks per direction. Circuit count is at most eight globally and two at the local native endpoint; generating retains one circuit.
- Idle JSON scheduling is 48 KiB/s outbound and 64 KiB/s inbound. Generating uses 24/32 KiB/s. A 16 KiB token burst accommodates one full frame; additional incoming native bursts wait in bounded queues. Controls have a separate 4 KiB/s cap within the aggregate outgoing budget. Actual throughput depends on duplex contention, small-chunk overhead, control traffic and native processing; these values do not guarantee a minimum native stream rate.
- The 100 MiB application-message participation budget survives automatic native readmission. It does not include IP/TLS/DTLS framing overhead.
- Native candidates already delivered to a Common are removed by its own session/expiry/dial rules. The browser removes its routing hints and closes affected circuits immediately on hop loss; it does not claim a nonexistent native candidate-withdraw API.
- The same-host Chromium/TURN checks do not establish operation across different access networks, restrictive third-party NATs, physical iOS/Android hardware, or real AI inference under sustained device load. Four-browser forwarding is covered by the Worker routing tests; an actual four-browser native stream path requires its own browser acceptance evidence.

## Evidence status

The pre-recovery-fix run on 2026-10-03 completed its measured interval from 04:38:37.896 UTC for 1,860,002 ms over actual public DNS, Cloudflare HTTPS/WSS and forced TURN. It used separate same-host Chromium processes and actual isolated Common B. A was turned off, B's original path drained, and C supplied a replacement authenticated native RLPx path. Exact opaque bytes were independently hashed and matched to browser hop receipts. A later authorized ordinary TCP upstream addition to A at 04:59:35.936 UTC restored source availability; B advanced from block 3777 to 3789 through its browser route, with canonical A/B/reference hashes matching. B's network isolation and mesh endpoint identities did not change.

This was **not uninterrupted stability**. There were two unsolicited paired hop losses (04:42:03.804 and 04:57:20.155 UTC), followed by recovery, plus two later C-only readmissions. During the timed interval B readmitted twice and C four times. The originating causes of the paired losses remain undetermined. The run also exposed stale readiness after an authoritative native-status HTTP 401; a later scoped controller correction and its separate validation must not be attributed to this older run. Single-circuit natural 30-minute expiry was `NOT_OBSERVED`.

The original runner ended with **FAIL**, because its old assertion required at least 14 renewal events per browser. The measured count was 13 each; fresh admission had restarted renewal timers. Raw output and that failure remain intact. The audited evidence reports expiry progression and fresh admissions separately, and does not treat a future reported expiry as proof that an authoritative native lease still exists during a stale-status gap. The corrected future harness avoids inferring expiry from a changed circuit ID and has regressions for both evidence mistakes.

At the last sample, B/C had 1,291/1,287 acknowledged chunks and 4,426,505/4,382,234 application-message bytes. Peak sampled application reservations were 302,774/302,934 bytes; sampled queues peaked at 2,615/862 bytes. These are application reservations, not process RSS. Peak averages over roughly ten-second sample intervals were 12,548/12,714 aggregate application bytes per second, not instantaneous bandwidth. One nonfatal `C:invalid_receipt` occurred during preflight circuit churn and is retained in the report. The workload policy test ran for 8,073 ms with 1,190 JSON bytes sent and 0.096829 s of Chromium main-thread task time; it did not run an LLM.

The original assertion ran before lifecycle/final-hash assertions. A separate post-run read-only observation confirmed native A/B routes and mesh peers were gone after the runner closed its own browsers. It did not delete another participant's lease. At 05:11:01 UTC, all five deployed browser-module hashes were fetched through public Cloudflare HTTPS and, together with the two deployed gateway-module hashes, matched the run's initial seven hashes. Browser controller hash: `5a1ac06199a33df91d39ce948db93c3ac41d9f1fab3d71274d4e392519ee2f64`.

Durable evidence is archived under `relay/evidence/soak-pre-fix/`, with exact raw-byte SHA-256 values and compressed-artifact paths in `manifest.json`. Hashes refer to decompressed original bytes. The raw runner, separate audit summary, full events, log, final live hashes and cleanup observation are retained; the large derived audited report is kept separately in /tmp rather than duplicated in the repository. Preliminary reports remain separate, including the original partial-sync timeout and the preflight with the overly strict idle-byte threshold.

## Post-correction direct transport and lifecycle

The separate public-DNS direct run **PASS** completed from 05:14:35.190 to 05:15:21.743 UTC on 2026-10-03 (46.553 seconds). This used the scoped authoritative-401 readiness/recovery correction, browser controller SHA-256 `670aa4fa466ee3a778a5c08beeb9cefac8ab1fce0946d9085590d32eae62b651`. It does not retroactively change the result or bytes of the preceding 31-minute run, and it does not establish that the cause of unsolicited transport losses was fixed.

```sh
MESH_PUBLIC_ORIGIN=https://ai-test.make-cph-great-again.community \
MESH_ORIGIN_LOOPBACK=0 MESH_FORCE_DIRECT=1 MESH_CHECK_LIFECYCLE=1 \
MESH_CHECK_WORKLOAD=1 MESH_CHECK_READMISSION=1 MESH_SOAK_MS=0 \
MESH_REPORT=/tmp/cypher-mesh-direct-report.json node tests/mesh-browser.mjs
```

The actual selected path was direct. A 448-byte encrypted native chunk matched both the independently computed SHA-256 (`01c071baab3733a30c9c38eea06dc4e4689daedb04ab9697af84202ec1597f8a`) and its separate hop receipt. A OFF drained the old route, C reauthenticated native RLPx, canonical hashes matched, loading/benchmarking/generating policy checks passed, and a deliberate native WebSocket close obtained new identities without resetting the participation byte count. One nonfatal `B:invalid_receipt` during circuit churn is preserved; there were no fatal or browser-runner errors.

Trusted tab hiding and freeze/resume left participation OFF without automatic rejoin. Navigating C away terminated its Worker. All four runner-issued leases returned HTTP 401 after cleanup, the runner's native routes/mesh peers were reclaimed, and no unowned lease was revoked. All seven implementation hashes stayed unchanged during this short run. This remains same-host Chromium with a mobile viewport, not a physical iPhone/Android test or a cross-network direct-NAT test.

Compact durable evidence is in `relay/evidence/direct-post-fix/`: `summary.json`, the raw report and events (gzip when large), log, and `manifest.json` containing decompressed-byte hashes. The workload signal interval measured 8,203 ms, 1,301 sent JSON bytes, 0.193242 s of main-thread task time and a 55.3 ms maximum 100-ms-heartbeat delay; no LLM inference ran.
