# Discovery reproduction and bootstrap audit

Date: 2026-10-03. This is a source/document audit, not a new transport or deployment acceptance result. Product files were not edited by this audit. The current native soak and Web rollout have separate records.

## Startup boundary verified in source

`public/mesh-controller.js` `join()` reads the same-origin `/relay/v1/mesh/config`, rejects a disabled or empty local Common configuration, then creates a home primary lease using `/relay/v1/mesh/sessions`. Only after that response does it construct the discovery client/Worker. `scheduleAttachments()` and `fillAttachments()` require `nativeConnected` plus idle AI before contacting verified remote gateways. Remote root leases are managed as secondary attachments by this browser. Primary loss releases them and retries the home gateway. No remote-primary fallback or serverless bootstrap exists.

`releaseSession()` sends each remote bearer only to its issuing origin. `stop()` releases remote leases separately, closes every native socket, destroys discovery state, then releases the home primary group. DELETE is best effort; sudden loss relies on WS closure, heartbeat and lease expiry. Hidden/freeze/page exit remains OFF until a user explicitly switches ON again.

## Test inputs and portability

| Test/input | Current dependency | Durable reproduction requirement |
| --- | --- | --- |
| `tests/mesh-discovery.test.mjs` | checked-in production vendor JS/provenance and `tests/mesh-signing-fixtures.mjs`; fixed Go signatures embedded in test | Keep these files with package-lock; no evidence JSON is read by the test |
| `tests/relay-discovery.test.mjs` | same signing helper, `tests/mesh-tls-fixture.mjs`, OpenSSL, `ws` package | Keep helpers under `tests/`; TLS cert/key generated in temporary directory and deleted, no saved private key required |
| `tests/mesh-discovery-client.test.mjs` | local production modules and synthetic in-memory HTTP/WS fixtures | No external file or evidence input |
| `tests/mesh-discovery-browser.mjs` | local production modules, TLS helper, independently launched Chromium | `PLAYWRIGHT_MODULE` and `CHROMIUM` must name installed tools; defaults under `/tmp` are this environment only; create report parent directory before execution |
| `tests/mesh-browser.mjs` | TLS helper, `tests/mesh-evidence.mjs`, operator `relay/config.json`, `relay/mesh-targets.json`, `relay/mesh-native-inspect.py`, live dedicated native endpoints | Preserve harness/helpers under `tests/`; this explicitly joins the operator's native test environment and cannot be represented as offline unit testing |
| Browser tooling | observed Playwright 1.63.0; Chromium path defaults to revision1243 | Install the matching Playwright/Chromium into an operator-selected durable tools directory and use environment overrides; browser tooling is not included by this project's npm ci |
| Test temporary directories | TLS keys, local Unix sockets, browser profiles under `/tmp` | Generated at runtime, not archived inputs; OpenSSL and a writable temporary directory are required |

All normal fixtures use local relative imports. Node22+ and `npm ci --ignore-scripts` install locked project packages. This project's package.json does not install Playwright. The generated TLS fixture has local-only hostname mappings and test certificate trust; no production DNS, host trust store or /etc/hosts mutation is required.

## Archive paths needed at final rollout

The current staging directory is temporary. Preserve the following evidence under the single durable destination `/root/browser-llm-lab/relay/evidence/discovery-update/`, retaining names/timestamps/source hashes and avoiding test private production keys:

- `evidence/native-advertisement-vector.go` and `.json`.
- `evidence/native-endpoint-vector.go` and `.json`.
- Discovery unit/gateway logs and actual TLS publisher log.
- Final discovery-browser and 21-browser reports/logs, plus the separately labeled unsuccessful earlier attempts.
- Native discovery browser final report/events/log and native deployment/isolation/build identity records selected by the rollout owner.
- This audit note and `discovery-bootstrap-audit-hashes.json`.

The two vector generators deliberately use public test scalar1; these are public test vectors, not runtime native keys. Re-running their Go generators requires the Cypher module's crypto package, but the JavaScript tests use fixed expected signatures and do not load `/root/cypher` or archived vector files.

One test comment currently names `relay/evidence/discovery/` for vector reproduction; the agreed final archive is `relay/evidence/discovery-update/`. This is documentation-only drift, not a runtime input. Update that comment as a test-only follow-up, or use this audit and guide as the authoritative archive location. The native `/root/cypher/node/browserrelay/testdata/mesh-endpoint-vector.json` is already a durable native fixture; keep it with that checkout.

## Observed limit distinction

The compatibility `/signal` implementation resets both sides' ICE counts on an offer. The new discovery rendezvous currently resets the offering sender's counter; the answerer retains its destination-route count until route removal or its own offer. The docs now state this accurately. The limit is finite and fails closed; prolonged repeated renegotiation may reconnect the rendezvous when it exhausts64 candidates. This audit did not change signaling or claim uninterrupted21-browser performance.
