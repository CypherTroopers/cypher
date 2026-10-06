# Public native upstream closure — bounded read-only audit

Updated 2026-10-03T18:19:37.335109+00:00. Product/runtime was not changed and no additional sessions, browsers or native calls were made by this audit.

## Confirmed observations

- The130-second public renewal attempt remains **FAIL** in `public-native-renewal-interruption/`: both browsers automatically acquired fresh native sessions before the original120-second renewal due time, so the short remaining interval did not demonstrate renewal.
- Gateway status in that report advances `upstream_closed` from0 to2. `pong_timeout`, `invalid_control`, `native_capacity`, `session_expired`, `upstream_error` and other non-cleanup categories remain0. Gateway process identity was unchanged according to the recorded parent-operation check. This establishes that gateway lifecycle handling observed its **private native Unix WebSockets closing**; it does not establish the native reason.
- The separate240,003ms public run finishes **PASS** at18:15:34.670UTC, with one actual renewal each for B/C after fresh admission, real WebRTC/native RLPx, matching bytes/digest/ACK, chain progress4,023→4,026 and lifecycle/cleanup checkpoints. It is a recovery-and-renewal result, not uninterrupted session continuity. Product source hashes are unchanged; C records two rejected `invalid_receipt` events.
- During that run gateway `upstream_closed` advances2→4. Samples show a fresh B generation by18:12:01 and C by18:12:11. The test observer later records browser native sockets closing1006 at18:12:54/55; these timestamps are browser observations and cannot be used as the exact private-side failure time. `readNativeStatus()` can recover upon401 before the old socket's `onclose` arrives.

## Source-level narrowing

`relay/gateway.mjs` increments `upstream_closed` only through the private upstream WebSocket close handler before it removes that live session. Frontend close, gateway Pong timeout, bandwidth/queue rejection and invalid-control paths have separate counters. The first recorded gateway category is therefore native-upstream closure, not a demonstrated Cloudflare/frontend disconnect. An indirect network/control effect cannot be excluded without native exit diagnostics.

`node/browserrelay/mesh.go` treats missing/late circuit data/credit/close as circuit-scoped: it optionally replies `unknown-circuit` and returns nil. Invalid data or credit closes that circuit and also returns nil. These paths do not ordinarily terminate the entire browser WS. Full-session exits include WebSocket ReadMessage/deadline/control failures, inbound budgets, frame/schema/session validation, advertisement/open validation, writer failure and cancellation. No current evidence identifies which exit occurred.

Crucially, `cmd/cypher/browser_mesh.go` discards the return value at `_ = h.mesh.Attach(s.ctx, s.id, ws)` (line469 in the inspected tree). The dedicated native logs around the first and second interruption contain owner canonical-hash read notices but no mesh session exit reason. Gateway errors/counters therefore cannot reconstruct that cause retrospectively. **Root cause: UNDETERMINED.** Do not label it native rate rejection, expiry, invalid credit, packet loss, Cloudflare, or Nginx timeout without additional evidence.

For a separately authorized diagnostic change, retain only a finite native exit-category counter (read deadline, control budget, inbound budget/schema, advertisement/open, writer/context) plus bounded timestamps. Never log bearer values, payloads, native keys or arbitrary remote error text. This audit did not implement or deploy diagnostics.

## Separate HTTP body-limit finding

The installed mesh Nginx location previously imposed `client_max_body_size1k`, while `/discovery` explicitly accepts up to16KiB JSON. A valid signed845-byte envelope plus2048bytes of JSON whitespace was rejected413 at the public proxy (`public-discovery-body-limit-before.json`). This is a demonstrated contract mismatch, separate from established WebSocket lifecycles.

The operator changed only the mesh location to16k after the public soak. Read-only inspection now confirms16k in both `/etc/nginx/sites-enabled/ai-test.make-cph-great-again.community` and `relay/nginx-site.conf`. Gateway native-lease HTTP bodies remain independently limited to1024bytes; discovery remains16384bytes, with existing strict schema/Origin/rate limits. HTTP body size does not set WebSocket message limits and this proxy correction is not evidence that the native-upstream closure cause was fixed. Validate its own public boundary tests separately.

The completed31-minute isolated-TLS native acceptance remains valid, with15 renewals per browser and observed natural30-minute circuit expiry. The shorter public-path interruption/recovery reports must remain separately labeled.
