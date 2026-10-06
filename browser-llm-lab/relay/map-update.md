# World map visibility and traffic update — 2026-10-03

Deployed to `https://ai-test.make-cph-great-again.community/` at 05:55:20 UTC. The change is limited to map rendering, country display anchors and the successful DataChannel send telemetry used by the map. Native protocol frames, cipher bytes, receipts, circuit routing, Common identities and node configuration are unchanged.

## Changes

The previous fixed-size canvas shrank pins and text on phones, grouped same-country participants at one point and suppressed traffic whenever an endpoint lacked country metadata. Outbound stream sends also lacked their own animation event; received ACK direction was reversed. The country table covered only 16 codes. These are confirmed implementation limitations, not a determination of which country header the user's earlier iPhone request supplied.

`public/relay-map.js` now renders at the canvas's CSS size with bounded device-pixel scaling. Every connected browser has a distinct pin. Geographic pins remain close to their country anchor; colliding label cards use leader lines. Unsupported or missing location metadata appears in a separate non-geographic area. A country anchor is neither a precise user position nor a city estimate. The 249-entry static table and attribution are documented in [geo-data.md](geo-data.md). No browser GPS or external per-user lookup was added.

Static lines indicate an established browser connection. Cyan lights travel from the peer to this browser on actual accepted chunks, orange lights travel to the peer after a successful DataChannel send-queue submission, and green lights travel from the peer on a verified browser hop ACK. Queue submission does not increment receipt counters. Reduced motion uses a static activity badge. Animation is bounded to 24 pulses and 30 fps, with no continuous idle animation. OFF, hidden and offscreen handling cancel drawing work; OFF and old-generation protection remain in the existing controller/Worker.

## Verification

| Check | Result | Evidence |
| --- | --- | --- |
| Entire JavaScript unit suite | 225 PASS, 3 opt-in TURN checks SKIP, 0 FAIL; 228 total | `evidence/map-update/unit.log` |
| Entire Python suite | 23 PASS | `evidence/map-update/python.log` |
| Isolated renderer fixtures | 21 PASS,17 screenshots; 390px/1440px, same-country 2–4 participants, known/unknown/mixed locations, directions, resizing, late bursts, bounded event floods, idle/OFF and reduced motion | `evidence/map-update/renderer-fixtures/report.json` |
| Actual public UI, two independent Chromium processes | PASS, 06:02:01.966–06:02:52.719 UTC; ordinary navigation and Node ON/OFF buttons, no controller/DOM/event/coordinate injection or request interception | `evidence/map-update/public-ui/final-pass/cypher-map-ui-final-report.json` |
| Public delivery |HTML and all four changed JS/CSS assets returned 200 and matched local SHA-256 | `evidence/map-update/public-assets.json` |
| Managed service check |Both Common PIDs and TURN PID unchanged; gateway online after its scoped restart | `evidence/map-update/services.json` |

The final real-browser run assigned Common A and Common B and used actual browser traffic. Both browsers received the provider's country estimate France; both displayed two separate pins near that country anchor. During the captured animation samples, desktop event count rose 68→83 and draw count 43→49; mobile-width event count rose 108→114 and draw count 85→90. Both canvas pixel hashes changed. Received, sent and ACK event types were observed on both pages. Node OFF cleared peers and map nodes/pulses, and Home navigation/reload did not create another admission. Both test pages were turned OFF and both owned browser processes closed. No external user's session was revoked.

The first full public UI attempt passed traffic/map/OFF checks but failed during reload with `net::ERR_CONNECTION_CLOSED`. It remains a **FAIL** in `evidence/map-update/public-ui/first-navigation-failure/`. The harness subsequently gained at most two retries for narrowly specified transient navigation failures while already OFF; product assertions are not retried. The final passing run needed **zero retries**. Python urllib delivery probes also returned 403, including with its environment proxy disabled; the cause is unestablished. Independent public curl requests and the real browser run succeeded. Neither observation is rewritten as a passing test.

Renderer fixtures deliberately use synthetic locations and events and do not join the mesh. The public UI test uses real events but is not an isolated native byte/hash acceptance test. It does not supersede the native/WebRTC byte proofs, 31-minute runner failure or other limitations in [verification.md](verification.md). Physical iPhone/Safari, Android hardware, distinct devices/networks and restrictive NAT were **NOT_RUN** for this map update. Country availability on a past phone session remains unverified.

## Reproduction and operations

```sh
npm test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_*.py'
PLAYWRIGHT_MODULE=/tmp/browser-llm-preview/node_modules/playwright/index.mjs \
  MAP_FIXTURE_ARTIFACTS=/tmp/cypher-map-fixtures-check node tests/relay-map-browser.mjs
# Only with authorization to join the configured research mesh:
MESH_UI_JOIN_AUTHORIZED=1 \
  PLAYWRIGHT_MODULE=/tmp/browser-llm-preview/node_modules/playwright/index.mjs \
  PLAYWRIGHT_BROWSERS_PATH=/tmp/browser-llm-browsers \
  node tests/mesh-ui-browser.mjs
```

Playwright/module/browser paths are environment-specific and can be overridden by the harness environment variables. The browser fixture's default asset root is its own checkout. No browser dependency was added to the production page.

The normal user flow is reload the page, then explicitly select Node ON. Browser history/site-data deletion is unnecessary. Node OFF and background/page lifecycle stopping behavior are unchanged.

Deployment first added the server's explicit `relay-map.js` allowlist and refreshed the gateway's static country table, restarting only the existing web server and this gateway. Public assets were then exchanged atomically after comparison with the preserved working-tree baseline. Before/after hashes are recorded in `evidence/map-update-deploy.json`; the rollback public directory and prior server/geo files remain in `.runtime/releases/map-v2/`. Keep rollback code and matching server allowlist consistent. Native Commons, TURN, Nginx and other applications were not restarted or reconfigured for this revision. Normal scoped start/stop instructions remain in [gateway-operations.md](gateway-operations.md).
