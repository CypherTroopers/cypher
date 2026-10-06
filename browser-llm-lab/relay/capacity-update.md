# Common browser mesh capacity update — 2026-10-03

The expanded native capacity is deployed at <https://ai-test.make-cph-great-again.community/>. The gateway, Worker and UI use the running Common's verified capacity profile. Independent browsers carried real encrypted native traffic over WebRTC, confirmed exact bytes/digests with hop ACKs, stopped the path on OFF, and recovered through newly joined replacement browsers. Capacity acceptance and sustained performance are separate results below.

## Applied capacity

| Resource | Previous deployment | Current deployment |
| --- | --- | --- |
| Native browser leases per Common | 8 | 80, shared by all callers |
| Public gateway leases | 16 | 160 across the two registered Commons |
| Gateway TCP connections | 96 | 384: room for 320 browser WebSockets plus HTTP/handshake work |
| Public leases per client address | 4 | 4, including pending admissions |
| Native mesh peer ceiling | 4 | 40; ordinary native total/inbound/outbound limits also apply |
| Native Common circuits, including pending opens | 8 total / 2 per session | 40 total / 40 per session; the total is shared across all 80 sessions |
| Browser circuits, including endpoint, transit and opening | 8 total / 2 endpoint | 40 shared total, up to 40 endpoint while idle |
| Browser circuits during AI generation | 1 | 1; model load/benchmark closes circuits and permits 0 |
| Browser pending opens | 1 | 8 total, at most 4 per direction/type, within the total circuit ceiling |
| Direct WebRTC neighbors per browser | 3 | 3 |
| Native owner-socket connections | 16 | 88: 80 WS plus 8 metadata/authentication slots |
| Native HTTP status response bound | 16 KiB | 64 KiB; other native responses/frames remain 16 KiB |

Forty is an acceptance ceiling, not a reservation for every browser. Endpoint and transit circuits share the browser limit; Common endpoint circuits also compete for the Common's shared 40. Only `common-a` and `common-b` are registered. This does not create 40 different remote native peers. Native total `MaxPeers=40` also includes ordinary TCP peers; inbound/outbound admission can further reduce available mesh slots. Browser participants are never counted as native peers.

`GET /relay/v1/mesh/config` on the native socket currently exposes `maxSessions` and `nativePeers`, but not the circuit limits. The gateway strictly recognizes the audited 80/40 and legacy 8/4 profiles, derives their specified circuit limits, and sends a bounded `nativeLimits` object with each browser admission. Unknown or inconsistent profiles fail before a lease is issued. Legacy nodes retain 8 total / 2 endpoint behavior. Capability reads are coalesced, cached for up to 30 seconds and invalidated after upstream failure. A downgrade without an active upstream socket can remain cached until expiry or admission failure; the native node always enforces its actual capacity.

## Resource and admission controls

Per-Common active, pending and cleanup-pending leases all count toward 80. Global and per-client slots are reserved before asynchronous admission work. Native metadata concurrency is bounded to 8, uses no idle keepalive sockets, and shares the native 16 requests/s, burst 32 budget with WS upgrades. Session creation separately remains 1/s, burst 8 per Common. An 80-session capacity does not allow an 80-request issuance burst. Status polls are coalesced and cached for one second. The native 40-route status fixture is 18,333 bytes, exceeding the former 16 KiB reader; the new 64 KiB ceiling remains finite.

The gateway's shared 1 MiB/s application budget, per-client admission limit of 32/minute, and 4 sessions per client address are unchanged. Users behind the same public IP/NAT share those four slots. Increasing session capacity does not multiply the shared bandwidth budget.

OFF revokes the public lease immediately. If native DELETE is temporarily busy, a bounded retry queue retains its occupied capacity until deletion, confirmed invalidation or original expiry. Cleanup does not renew a lease. Native WS closure normally invalidates its lease immediately; process death with an unattached lease still relies on the native expiry backstop. Peer assignment notifications are sent only when the assignment changes.

Native bandwidth remains 64 KiB/s per browser session and 256 KiB/s per Common, independently in each direction and counting complete JSON. Native control frames use the supplied build's 32/s, burst 160 Common-wide budget. Chunk/frame sizes, native 64-frame / 512 KiB send queues, 64 KiB unconsumed circuit buffers, 4-label routes, 5/15-second heartbeat timing and 30-minute circuit lifetime are unchanged. Native pending handshakes remain 4 inbound and 4 outbound.

Browser normal JSON send/receive budgets remain 48/64 KiB/s; generation uses 24/32 KiB/s. All admitted circuits share these budgets. The shared queue byte budget remains 512 KiB. Outgoing queued and pending sends together are limited to 64 frames; the input queue is limited to 128 frames. Outstanding hop receipts, including pending send reservations, remain bounded to 128. Each explicit ON retains its 100 MiB application transfer budget through automatic readmissions. Application memory reservations remain bounded to 4 MiB, with conservative accounting for the pinned registry, routes, circuits, pending sends and receipts. This is application accounting, not a hard browser RSS or JS heap limit.

Bulk closing up to 40 circuits can require more control frames than one queue permits. The Worker preserves the existing queue limit: if close propagation cannot be queued, it retires the affected hop or native session so the adjacent endpoint reclaims the routes. Delayed send callbacks cannot recreate closed circuits or count stale ACKs. AI load/benchmark closes streams; returning to idle permits new authentication. Generation allows at most one circuit, although teardown under backpressure can temporarily leave zero.

The UI derives its Common circuit denominator from the actual Worker policy: up to `/40` while idle, `/1` during generation, and `/0` during load/benchmark. Its hint states that the Common shares 40 across 80 sessions, including opening circuits. WebRTC still displays `/3`. The operator pin registry accepts up to 64 fixed identities for future expansion; no extra Common or arbitrary TCP target was added.

## Deployment and preservation

Work started from the existing dirty working trees, not just HEAD:

- Web HEAD: `1e2839e95612d22b5fdc2aed5bf5b78e344f2e0b`.
- Native HEAD: `f8ee241a2cb2e813589df5d0dbe3dba93e0734d7`.
- Baseline file hashes and dirty-state inventory: `evidence/capacity-update/baseline.json`.
- Supplied and deployed native binary SHA-256: `3efc534447a00e0abb0926f04325d78f498e5077d75e31ffd5b4e48c29f9ee29`.

Only the two dedicated mesh Commons were switched to the supplied binary. Their existing datadirs, identities, source configuration and launchers were retained; their dedicated `Node.P2P.MaxPeers` changed from 8 to 40 and `MaxPendingPeers` remains 4. No database was initialized, imported, copied, or opened by a second node process. The `/root/cypher` source and supplied binaries were not modified. Unrelated native processes were checked before/after and retained their PIDs/start times.

Both private native configs were re-read after startup and returned `maxSessions:80`, `nativePeers:40`, version 1, frame 16384, 300-second lease and 120-second renewal interval. B's launcher again established a separate network namespace with only loopback and no external route. A uses its existing research TCP upstreams; B's only native ingress during acceptance was the browser-mesh circuit.

| Service | Actual connection / scoped process |
| --- | --- |
| Public API and signaling | `https://ai-test.make-cph-great-again.community/relay/v1/mesh/`, WSS `connect` and `signal` |
| Gateway | `127.0.0.1:8091`, PM2 home `.runtime/mesh-gateway/pm2`, name `cypher-browser-mesh-gateway` |
| Common A | `.runtime/mesh-a/source.sock`, root PM2 `cypher-browser-mesh-a` / id 11 |
| Common B | `.runtime/mesh-b/source.sock`, root PM2 `cypher-browser-mesh-b` / id 12, isolated network namespace |
| Page server | Existing `127.0.0.1:8080`, unchanged |

The gateway was restarted with its scoped PM2 home. The complete prepared public directory was exchanged atomically after the gateway update. Public HTTPS assets were fetched through normal public DNS and matched the prepared hashes. Existing page server, proxy allowlist, TLS and TURN configuration were reused.

Rollback copies and the before/after deployment manifest are retained under `.runtime/releases/capacity-v1/`: `public/` holds the previous public directory, `previous/relay/` the previous gateway modules/config, and `native/{a,b}/` the previous dedicated binary/config. These are operator rollback material, not public assets. A native rollback must stop only the matching owned process before replacing its binary/config and must retain B's namespace launcher. Do not run global PM2 actions or reset a datadir.

## Executed validation

| Check | Result and scope |
| --- | --- |
| Baseline web suite | 225 passed, 3 opt-in TURN tests skipped; 23 Python tests passed |
| Final web suite | 247 passed, 3 opt-in TURN tests skipped, 0 failed; 23 Python tests passed |
| Gateway capacity subset | 30 passed, included in the final suite |
| Worker/controller/protocol/UI subset | 69 passed, included in the final suite |
| Public API boundary | 15 passed: authentication, Origin, query-token rejection and private paths |
| Actual native configs / running binaries | PASS for both dedicated Commons; exact supplied SHA and 80/40 response |
| Independent public browser path | PASS with separate Chromium processes and profiles; actual ordered/reliable direct WebRTC |
| Native chain ingress | B advanced height 3813 → 3870; canonical hashes at 0, 1, 1000 and 3870 matched A/B/reference |
| A OFF | PASS after draining: no new A-route transfer, no replacement or gateway-only data fallback in this phase |
| Replacement C | PASS: new browser route, new native circuit/authentication, exact data/digest/hop ACK |
| Abrupt C termination / replacement D | PASS: SIGKILL of the owned browser, route/queue reclamation, fresh D-route native authentication and exact data/digest/hop ACK |
| AI workload policy | PASS with actual application load/generation state signals; no GPU model inference was run |
| Native WSS loss | PASS: new browser/session/native generation, retained explicit-ON byte budget |
| Lease renewal observation | PASS over 180,001 ms: same-session expiry advanced for B and C; this is not a 30-minute test |
| Browser lifecycle | PASS: trusted hidden/freeze stops participation; resume stays OFF; navigation terminates Worker |
| Ordinary public UI | PASS with normal buttons on independent 1440 px / 390 px browsers: circuits `1 / 40`, shared 40/80 hint, RTC `1 / 3`, real map activity, no overflow or page errors, OFF/reload stays OFF |

Gateway tests use real HTTP/WebSocket connections to controlled Unix-socket native fixtures: 160 public sessions, 320 public-side WebSockets and 160 upstream WebSockets (80 per Common), rejection/reuse boundaries, paced admission, metadata headroom, old/new native profiles, oversized responses and concurrent OFF cleanup. The test clock is controlled. They establish acceptance/accounting boundaries, not sustained performance of 160 browser devices or native RLPx peers. Worker tests establish 40/41 boundaries, endpoint/transit sharing, pending opens, 40-circuit teardown and receipt/queue/memory limits. One 40-endpoint / 85-route fixture reserved 1,376,950 of 4,194,304 application bytes; it did not measure browser RSS.

The real browser run lasted 09:25:57–09:31:12 UTC with a separate 180-second measured interval. Exact ciphertext proof samples were A→B 333 bytes, C→B 516 bytes and D→B 356 bytes; their SHA-256 digests and receipt bindings are retained in the summary and raw event evidence. These samples are distinct from total traffic. At the final timed sample, B had 391 confirmed hop receipts covering 10,474 raw bytes and 1,457,252 cumulative application bytes for its explicit ON; C had 351 receipts covering 66,132 raw bytes and 1,335,722 application bytes. Application bytes exclude TLS/IP/SCTP framing, and totals include earlier phases of the same ON.

The real run observed at most one concurrent endpoint circuit per browser, with the applied limit 40. B and C each had one same-session renewal event inside the measured interval. C automatically readmitted once during that interval; therefore this run demonstrates renewal and recovery, not uninterrupted circuit stability. The audit does not infer a cause or natural 30-minute expiry from a changed circuit ID. Peak sampled reservations were 303,762 bytes for B and 302,992 for C; peak sampled queues were 275 and 0 bytes. Sampled maxima can miss shorter bursts.

All six browser-run-owned lease tokens returned 401 after cleanup. Both Commons then had zero test sessions, circuits and candidates; B had no native peer. No unrelated participant lease was revoked. Raw runner output is preserved separately from its audit. Earlier long-run failures in `verification.md` retain their original status and are not relabeled by this update.

The separate ordinary UI test ran 09:32:28–09:33:16 UTC with no controller injection, request interception or forced transport. Both views displayed 11 actual hop receipts (desktop 902 bytes, mobile 841 bytes). The mobile metrics screenshot is `evidence/capacity-update/capacity-public-ui/screen-mobile-metrics.png`. A final read-only check again found zero sessions/circuits/candidates on both Commons and all four managed services online.

## Reproduce and operate

From `/root/browser-llm-lab`:

```sh
npm test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_*.py'
node tests/mesh-public-boundary.mjs
MESH_PUBLIC_ORIGIN=https://ai-test.make-cph-great-again.community MESH_FORCE_DIRECT=1 MESH_CHECK_LIFECYCLE=1 MESH_CHECK_WORKLOAD=1 MESH_CHECK_READMISSION=1 MESH_CHECK_ABRUPT=1 MESH_SOAK_MS=180000 MESH_REQUIRE_RENEWAL=1 MESH_EXPECT_NATIVE_CAPACITY=40 node tests/mesh-browser.mjs
./relay/start-managed.sh check
./relay/start-managed.sh status
```

The live browser harness needs the existing browser-test execution environment and permission to inspect the owned native IPC/namespace. Run it without a competing admission test; it opens and cleans only its own sessions. See the runner's environment options and `tests/mesh-acceptance.md`. The native upgrade helper and its read-only preflight/apply report are retained as evidence, not a new long-running service.

Normal service start/stop uses `./relay/start-managed.sh start` and `./relay/start-managed.sh stop`. These operate only the four managed components (the two dedicated Commons, gateway and TURN); stop interrupts browser participation. For only the gateway, use the exact PM2 home/name commands in `gateway-operations.md`. Browser users reload the page and explicitly select Node ON. Clearing browser history or local AI memory is unnecessary.

## Not established by this revision

- 40 distinct remote native Common peers or sustained 40-circuit data traffic: NOT_RUN; only two Common identities are registered.
- 80 physical browsers per Common / 160 overall sustained performance: NOT_RUN; the capacity boundaries use fixtures.
- A new 30-minute-plus soak or natural circuit TTL expiry: NOT_RUN. The measured interval here is three minutes.
- Physical iOS/Android lifecycle, different devices/access networks, restrictive NAT/radio switching: NOT_RUN. A mobile viewport is not a phone.
- New forced-TURN acceptance: NOT_RUN in this revision. Direct WebRTC passed; existing TURN configuration and historical evidence were retained.
- Sustained actual local LLM GPU inference concurrent with relaying: NOT_RUN; application workload state transitions passed.
- A real four-browser intermediate-hop native path: NOT_RUN; multi-hop routing is covered by Worker fixtures.

The supplied native build/Go test results were reviewed with its provenance. Native Go tests and `make cypher` were not rerun in this web task. Browser hop ACK, native flow-control credit, native RLPx authentication and chain finality remain different claims.


## Follow-up: actual connection counts

The 2026-10-03 follow-up moves capacity denominators out of the primary counters. Browser peers counts only currently open direct DataChannels; Common connections counts the authenticated native WSS attachment; Common relay circuits counts open endpoint transport circuits. Opening circuits are reported separately. Existing Worker occupancy counters still include pending opens for admission accounting; the UI subtracts the matching pending inbound/outbound/transit counts when reporting open paths. OFF forces the current connection counts to zero.

Limits remain unchanged and are available in the collapsed Connection limits & counting details. This is a presentation/measurement correction, not a new 6-peer or 2-Common deployment. The map title is YOUR BROWSER CONNECTIONS · LIVE: it shows the connected browser neighbors for which this page has current evidence. Country pins describe coarse browser-client locations, not native Common locations or a measured global network population. Distributed Common deployment and its location metadata remain separate operational work.

Only public/index.html and public/relay-ui.js changed in the runtime. The complete public directory was exchanged atomically; no gateway, native Common, TURN or page-server restart was needed. Prior public files and edited tests/docs are retained in .runtime/releases/connection-counts-v1/. The UI unit tests cover connected-versus-connecting peers, pending circuit exclusion, AI capacity in secondary details and stale OFF snapshots. A separate ordinary public UI run checks the new counts and live traffic on desktop/mobile viewports. Its results, screenshots and the preserved initial harness expectation failure are in evidence/connection-counts/; the initial failure was the test expecting a map title without the actual “ · LIVE” suffix, before any session admission.

Final follow-up validation: 16 UI unit tests passed; the independent ordinary public-browser run passed all 6 checkpoints. Both desktop and mobile views observed 1 connected browser peer, 1 Common attachment and 1 open endpoint circuit. OFF and reload returned every current count to zero. Evidence is summarized in `evidence/connection-counts/summary.json`. The mobile result is Chromium viewport emulation, not physical phone testing.


## Follow-up: 20 browser peers and 20 Common attachments

This follow-up changes the earlier 3/1 connection architecture. A browser can hold up to20 direct, ordered/reliable WebRTC peers and up to20 distinct pinned Common WSS attachments, managed by one Worker and one signaling identity. Primary counters continue to show actual current connections; limits are separate details. A Common attachment is not a native peer or a native circuit. The current research deployment still exposes two distinct Commons.

The primary lease owns authenticated child leases. Each child has its own native browser/session/token, is renewed and released independently, and cannot create another signaling participant. A failed secondary endpoint removes only its own circuits and queues. Primary loss still replaces the whole browser group with new sessions and native authentication; seamless primary migration is not implemented. OFF, hidden/freeze and page exit clear all children and RTC, and old asynchronous admission/renewal/HELLO callbacks cannot resurrect them.

All connections share the existing40-circuit Worker ceiling, four pending opens per direction/type and eight overall,4MiB application reservation,512KiB temporary queues,64 outgoing queued/pending frames,128 receipts and100MiB per explicit ON. Idle JSON send/receive remains48/64KiB/s. AI generation reduces the circuit policy to1 and load/benchmark closes circuits. Gateway groups share64KiB/s per direction and100MiB. The control subbudget increased from4 to24KiB/s **within** the unchanged global Worker rate: the20×20 bounded fixture emitted400 RTC and380 native advertisements plus heartbeats,666,316 JSON bytes in26.5 simulated seconds. Its peak reservation was1,453,050 bytes and queue36,250 bytes/52 frames; these are simulated application measurements, not RSS or LIVE throughput.

Gateway capacity remains160 native-backed leases and384 TCP connections across the two Commons. Per-client capacity is80 leases (including pending), not80 fully populated browser groups;20 attachments consume20 leases. Admission pacing remains32/minute per public client and1/second with burst8 per Common. Signaling negotiation is separately paced at150ms with a64-message/64KiB queue and at most4 concurrent RTC negotiations. Matching preserves existing links and admits new participants into a saturated graph through bounded edge replacements.

The map can show self plus20 real browser neighbors, with bounded pulses and labels. Unknown location stays in a non-geographic area; Common WSS connection cards do not invent native locations. Fixtures include21 markers at390px and1440px, same-country/mixed/unknown cases.

### Existing advertisements and deployment scope

Normal native Common P2P participation does not require registering with this website. The native implementation already signs enode advertisements and verifies received advertisements to discover temporary mesh candidates. In this web deployment, `config.nodes` additionally restricts advertisements and direct attachments to operator pins. Native endpoints verify secp256k1 signatures; browser code currently checks schema/network/freshness/pins and preserves exact signed bytes. The mesh advertisement schema has no public WSS URL. The separate native proof API discovery advertises HTTP/3 for `/api/node/v1`; it is not wired to mesh WSS bootstrap. This capacity update does not add permissionless endpoint discovery or remove those pins. Those are distinct integration tasks, not missing native advertising.

Implementation, test and deployment evidence for this follow-up is kept in `evidence/mesh-20x20/`. Existing native source, DBs, identities, running binaries, proxy, page server and TURN are preserved; only the dedicated web gateway is restarted for the web update. Rollback public assets and gateway files are retained in `.runtime/releases/mesh-20x20-v1/`. Use the exact gateway PM2 commands in `gateway-operations.md`; the managed four-service stop script also stops dedicated Commons and should not be used for a gateway-only rollout.

### Executed follow-up validation

- Final JavaScript suite:271 passed,3 existing opt-in TURN tests skipped,0 failed. Gateway39 tests, Worker/protocol42 tests and controller/legacy35 tests are included; map renderer29 cases are separate.
- Actual scale:21 independent Chromium processes through a private loopback gateway, one browser with20 open RTC DataChannels and20 selected host/host UDP candidate pairs. Other observed degrees18–20. Hub76 hop ACKs; sampled maximum application reservation512,970B and queue14,604B. Hub OFF removed all20 neighbor links; all21 owned leases returned401; owned browsers and listener were closed. About89seconds, samehost only.
- Public HTTPS/WSS/native path:12 checkpoints PASS with exact ciphertext/digest/hop ACK on A→B(525 bytes), replacement C→B(497 bytes), and new D→B(461 bytes) after C SIGKILL. These are bounded proof samples, not total traffic. A OFF stopped its drained path; B has no native TCP ingress. Canonical hashes matched A/B/reference. B was already at height3909 and remained3909 during this run; do not claim new-block progress.
- Public180,004ms interval: B/C each renewed the same lease once; no automatic readmission observed within that timed interval. One native loss was deliberately induced before it. This is not a30-minute or maximum-load stability claim. Final sampled B/C hop receipts165/156; application bytes610,147/560,592. All5 runner-owned leases returned401 after final lifecycle checks.
- Final ordinary public UI:6 checkpoints PASS, independent1440px/390px browser processes, actual Common2 / browser1 / endpoint circuit1 in both active observations, ACK11/26 at that observation. Counters become0 on OFF; reload does not rejoin. Default and Connecting details now show20 before config is fetched; known gateway limits remain authoritative after config. Actual map activity, no horizontal overflow/page errors. Mobile viewport is not a physical phone.
- Public boundary15 checks PASS. Seven changed assets fetched via normal public DNS match deployment hashes. Final native A/B sessions/circuits/candidates all0. Dedicated native PIDs3232347/3232354 and TURN PID3068233 remained unchanged from this rollout preflight; only gateway PID changed to3246454.

The initial scale run is retained as FAIL for six Playwright response-body observation errors despite20 RTC connections; revised read-only lease collection then passed. The first public UI pass found an initial OFF detail showing1, and a subsequent stricter UI run found the same display during config loading. Both intermediate records are retained separately from the final PASS. The display fix changed no transport core, and the final public-byte acceptance core hashes match the deployed core.

Current limitations remain:20 real distinct Commons, different devices/access networks, physical iOS/Android, sustained20-peer operation, a new30-minute run, and actual concurrent LLM GPU inference are NOT_RUN. Twenty simultaneous TURN paths are also NOT_RUN: the retained TURN service still has6 allocations per credential identity,64 overall and a finite relay-port pool; the20 direct-RTC measurement does not establish that TURN capacity. All browser links share the same bounded resources.

To reproduce the additional scale acceptance, use the authorized research endpoints with `MESH_SCALE_JOIN_AUTHORIZED=1 node tests/mesh-scale-browser.mjs`; it requires the existing Playwright/Chromium environment and private-socket access and cleans only its own fixture/sessions. For normal public UI use `MESH_UI_JOIN_AUTHORIZED=1 MESH_EXPECT_COMMON_CONNECTIONS=2 MESH_EXPECT_NATIVE_CAPACITY=40 node tests/mesh-ui-browser.mjs`. These commands join the research network and should run separately. The public native runner remains `tests/mesh-browser.mjs`, using `maxCommonConnections:1` intentionally to isolate the A/B/C/D path from alternative local attachments.
