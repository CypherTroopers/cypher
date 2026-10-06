# Browser LLM Lab - OpenClaw workspace

The interface is now presented as **Cypher Browser**, a local AI web workspace
with a home dashboard, Cypher Claw assistant, and a settings drawer. It is a web
application; website addresses entered in its top search bar open in a new
browser tab.

## Cypher interface

Home provides three working entry points: OpenClaw connection, browser model
setup, and web research. The status cards show the actual loaded model,
available WebGPU runtime, model memory estimate, measured benchmark throughput,
and Gateway connection. Memory estimates are not current RAM/VRAM usage.

The main question field lets you choose Local AI, Web, or Agent. Submitting a
question sends it when that runtime is ready. If setup is needed, the question
is kept in the assistant while the relevant settings open; finishing setup
does not automatically send that saved question. The top search bar opens
HTTP(S) addresses in a separate tab or uses Web research for search terms.
Ctrl+K / Cmd+K focuses that bar.

On wider screens Home and the assistant appear side by side. The sidebar can
open a focused conversation. On phones Home and the assistant are separate
views, while model and Gateway setup use a full-width settings drawer.
Background controls are inert while the settings dialog is open, and keyboard
focus returns to the opening control when it closes.

On mobile, the workspace follows both the height and the vertical offset of the
visual viewport when the onscreen keyboard opens or pans the page. While editing
in the composer, secondary headers collapse, the input grows with the draft,
and long drafts scroll inside it. The Send control stays in the available space.
Focus changes within the composer keep this compact layout stable. Very short
landscape views give the input and Send row priority over the transcript.
Sizing does not rewrite the text or selection, and composition blocks the
keyboard send shortcut until Japanese IME conversion finishes.

The landscape is a project-specific generated asset. Its exact production path
and generation prompt are recorded in [the artwork notes](public/assets/README.md).

This integration adds an OpenClaw Gateway client and official installation links
to the browser chat workspace. It is an independent interface, not an official
OpenClaw application. The existing browser model catalog and benchmark behavior
are documented in [README.models.md](README.models.md).

## Three conversation modes

| Mode | Where generation runs | What leaves the browser |
|---|---|---|
| Chat | WebLLM in this browser's Worker | Web Auto (default) looks up time-sensitive questions; Always requests search; Off sends no question text to search. Search terms go to the existing server and search providers. Runtime and model downloads require network access. |
| Web research | WebLLM in this browser's Worker | The current question or custom search terms go to this server and external search engines. Search snippets are supplied to the browser model. |
| OpenClaw agent | The model configured on the connected Gateway | Tasks go directly from the browser to that Gateway. Model-provider requests and tool activity follow the Gateway's configuration. |

The browser model and OpenClaw model are separate runtimes. Loading a WebLLM
model does not configure OpenClaw, transfer its weights to the Gateway, or turn
the browser into a Gateway host. Configure a local model in OpenClaw if agent
generation must also stay on hardware you control; a Gateway can instead use a
hosted provider. WebGPU is required for browser inference, but is not required
for this interface's Gateway connection.

The browser inference limits remain 400 characters / 1,200 UTF-8 bytes per
question, a 4,096-token context, and model-specific input/output budgets. Agent
tasks have a separate UI limit of 16,000 characters / 48,000 UTF-8 bytes and are
also subject to the Gateway's payload limit.

## Automatic search and device memory

Chat defaults to **Web Auto**. Deterministic Japanese/English rules look for
freshness, prices, news, compatibility and explicit lookup requests. This can
miss topics or overmatch terms; the Auto/Always/Off control remains visible in
Chat and the search settings. Research always searches independently of Chat's
setting. Agent tasks keep using the Gateway and do not receive this browser's
saved memory. Answer language defaults to following the question; an existing
saved language preference is preserved.

Search uses the question or separate custom search terms. A follow-up can use
only recognized public maker/model names from the latest user turn or from a
note whose search checkbox the user explicitly enabled. Entire memories and
conversation transcripts are never appended to search requests. The finite
public-topic allowlist asks for clarification when it cannot resolve a subject.
Basic sensitive-string checks can block a query, but are not a complete privacy
filter. Users should choose Off or public custom search terms for private text.
Search query and supplied source links are shown with each answer. Japanese
queries use Japanese search. Responses use bounded snippets, not full pages;
retrieval time is not publication time. Search failure does not produce an
unverified offline fallback. Prompts include the current UTC date.

Memory is on by default and uses IndexedDB `cypher-memory-v1`, separate from
model files and Gateway credentials. User messages are saved before generation;
answers are attached after successful generation. A failed search can therefore
leave a saved user-only message. Up to three recent completed turns in the
current session are restored after reload, including when preparing the model
again. Clear view / New conversation starts another session and keeps the
archive. The Memory panel lets the user inspect recent items, save/edit notes,
delete individual items or all memory, switch saving/recall off, and export or
import validated JSON backups. Turning memory off or deleting an item also
clears active local context so it cannot continue being supplied as dialogue.
The current browser conversation and saved archive are separate from Gateway
history.

Memory records have no automatic expiry or deletion. Normal read/retrieval
operations use indexes and bounded candidate sets instead of loading the entire
archive. Recalled context is limited to a few relevant user messages/notes;
model answers are not indexed as user facts. It is quoted reference context,
not model-weight training. Context limits may omit some matched memories, and
keyword retrieval is not a guarantee that every relevant old item is found.
No extra embedding model or background inference is downloaded. The list shows
up to 100 recent items per filter. Export/import is explicitly bounded to
5 MiB and 10,000 items per file; limit errors do not delete stored data. Import
validates the complete file before a single transaction and resets each
imported note's search permission to off.

Reloads and closed tabs retain data in the same browser profile. Browser
**cookies/site data** deletion removes IndexedDB memory; clearing only ordinary
browsing history or cached images is not reliable for this. Private browsing,
storage pressure or browser policy can also remove it. The user can request
persistent storage using the Memory panel, but the browser decides whether to
grant it; this never overrides manual deletion. Export important notes before
clearing data. App **Delete all memory** removes only the local memory archive
and active conversation; it keeps downloaded models. Browser-wide site-data
clearing may also remove those model caches and require another download.
Model inference can itself be the main CPU/GPU/RAM cost; deleting a text archive
does not guarantee faster inference. Storage errors are displayed rather than
claiming that data was saved successfully.

## Desktop setup and downloads

1. In Setup, review the browser model recommendation. Choose whether to request
   the OpenClaw installer alongside model preparation.
2. Select **Prepare local AI** and review the confirmation. When the installer
   option is selected and a compatible package is known, the confirmation also
   identifies that package. Canceling requests neither model weights nor the
   native installer.
3. Open the downloaded package and finish OpenClaw's native setup yourself.
   Alternatively, use the direct download link without preparing a browser model.
4. Configure OpenClaw's model and Gateway, then connect the workspace as described
   below.

The page can request a file download. It cannot silently install a native app,
start an OS service, grant desktop permissions, or finish Gateway onboarding.
A browser may block the automatic download; the direct link remains available.
The download-request message does not verify that the file finished downloading
or that OpenClaw was installed.

The desktop catalog in [public/openclaw-install.js](public/openclaw-install.js)
was checked against the official website and GitHub release metadata on
**2026-10-02**. Each referenced release was published and not marked as a
prerelease. Desktop applications publish separately, so their versions differ.

| OS | Pinned version | Package selection | Requirements |
|---|---|---|---|
| macOS | 2026.9.7 | Apple Silicon, Intel, or Universal DMG | macOS 15 or later |
| Windows | 2026.9.4 | Windows Hub x64 or ARM64 EXE | Windows 10 20H2 or later / Windows 11 |
| Linux | 2026.9.5 | x64 AppImage; `.deb` is also in the catalog | AppImage requires glibc 2.35 or later and GLIBCXX_3.4.30; check distribution dependencies |

These are reviewed, pinned downloads, not a live claim about the newest release.
Only exact URLs in the module's official-asset allowlist can be requested by the
automatic desktop download path. When updating the catalog, verify the asset
exists on a published stable release and update its verification date and tests.
The [official download page](https://openclaw.ai/) and platform instructions for
[macOS](https://docs.openclaw.ai/platforms/macos),
[Windows](https://docs.openclaw.ai/platforms/windows), and
[Linux](https://docs.openclaw.ai/platforms/linux) describe the native packages.

OS and CPU architecture choose the application package. RAM and GPU estimates
choose the WebLLM model, not a different size of OpenClaw. CPU detection uses
User-Agent Client Hints when supplied by the browser. Legacy strings such as
`MacIntel` are not treated as reliable CPU detection. An unknown Mac CPU uses
Universal; Windows and Linux need an explicit CPU selection when it cannot be
detected. The reviewed Linux desktop catalog has no ARM64 or 32-bit package.

## Connect this browser to a Gateway

Use an OpenClaw Gateway supporting protocol 4. This client requests the
`operator.read` and `operator.write` scopes for session history and chat tasks.
It does not request administrative, pairing-management, or approval-resolution
scopes.

1. Finish Gateway onboarding and confirm the Gateway is running. Obtain its
   configured bootstrap token through your own OpenClaw setup; do not put it in
   the browser URL or commit it to this repository.
2. Serve this workspace over HTTPS or the browser device's localhost. Browser
   device identity requires Web Crypto with Ed25519 and IndexedDB.
3. Add this workspace's exact origin to the Gateway's
   `gateway.controlUi.allowedOrigins` when required for a separate browser
   origin. For example, a workspace at `https://workspace.example/chat` has origin
   `https://workspace.example`, without a path or trailing slash. Preserve any
   other origins you intentionally allow. This is configured on the Gateway,
   not through this repository's `PUBLIC_ORIGIN` server setting. See the
   [Gateway configuration reference](https://docs.openclaw.ai/gateway/config-gateway).
4. Enter the Gateway WebSocket address and token in Setup, then connect. For a
   Gateway running on the same computer, `ws://127.0.0.1:18789` can be used when
   the browser allows that connection. A Gateway on another device requires
   `wss://` with a certificate trusted by the browser. URLs containing embedded
   credentials, a query string, or a fragment are rejected.
5. If pairing is required, review the request in OpenClaw, approve that specific
   browser device, and reconnect. On the Gateway host, `openclaw devices list`
   shows pending requests and `openclaw devices approve <requestId>` approves the
   chosen one. The [official client guide](https://docs.openclaw.ai/gateway/clients)
   describes the challenge, device pairing, and scope negotiation.

Keep Gateway authentication and device pairing enabled. An origin rejection or
pairing request is not fixed by bypassing approval, disabling device identity,
or granting every origin access. Hosted HTTPS pages can also encounter browser
restrictions on loopback WebSockets; use a trusted HTTPS/WSS endpoint or host the
workspace on localhost as appropriate.

The entered Gateway bootstrap token is not written to browser storage. The
client stores its non-extractable Ed25519 private key and public identity in
IndexedDB. A Gateway-issued device token can be retained in sessionStorage,
scoped to the Gateway URL and browser identity, for reconnecting in that tab.
Disconnect closes the connection; it does not revoke the paired device. Manage
device revocation in OpenClaw. Agent tasks and history use a direct WebSocket;
the Python search server does not proxy Gateway credentials or tasks.

## iPhone, iPad, and Android

The official mobile apps are companions. Neither hosts the Gateway on the phone
or tablet; use a Gateway running on your computer or another host you control.
The official links were verified through platform documentation on
**2026-10-03**:

- [OpenClaw for iPhone / iPad](https://apps.apple.com/app/openclaw-ai-that-does-things/id6780396132)
  requires iOS / iPadOS 18 or later. See the
  [official iOS instructions](https://docs.openclaw.ai/platforms/ios).
- [OpenClaw for Android](https://play.google.com/store/apps/details?id=ai.openclaw.app)
  lists current device compatibility in Google Play. See the
  [official Android instructions](https://docs.openclaw.ai/platforms/android).

On mobile, the recommendation returns a companion-store URL and never a desktop
installer URL. The companion is installed separately through its store. The
store links and desktop-download links have separate allowlists.

You can also connect this browser workspace directly to your remote Gateway
without installing the companion. Use that host's reachable **WSS** address:
`localhost` and `127.0.0.1` on a phone refer to the phone itself. This workspace
requires WSS for all non-loopback connections, including private LAN addresses.
Set up the Gateway's reachable endpoint and exact allowed workspace origin on
the host; this page does not create a tunnel or change network bindings.

Opening the browser workspace does not grant access to the phone's camera,
microphone, location, screen, or other native features. Such capabilities belong
to a separately paired companion and remain subject to the operating system's
permissions and Gateway policy. Browser and native companion pairing are
separate. Desktop browser/computer operations likewise depend on the enabled
OpenClaw tools, paired nodes, and native permissions.

## Sessions, stopping, and approvals

The workspace lists Gateway sessions, reads text history, sends tasks, and
displays streamed chat and tool-status updates. Rich attachments, complete tool
artifacts, administrative settings, and approval decisions remain in OpenClaw's
own interface. Approval notifications, when received, direct you there; this
client does not grant approvals or expand tool permissions.

Stopping a Gateway run requests an abort; completed tool actions can remain in
effect. Disconnecting, closing a tab, or timing out is not proof that the remote
task stopped. Reconnect and inspect the session history before repeating a task
that might have made changes. A new conversation uses a new Gateway session;
clearing this view does not delete Gateway history. Browser-model conversation
history is separate from Gateway sessions.

If refreshed history reports an existing task in progress, this workspace shows
its available text and blocks new sends in that session. Review or stop that
task in the OpenClaw dashboard, then refresh history to confirm completion.

## Run and validate

From this repository, start the existing server with `python3 -B server.py` when
no instance is already using its port. It binds to `127.0.0.1:8080` by default;
an HTTPS frontend is needed for access from a phone. `PORT`, `PUBLIC_ORIGIN`, and
`SEARXNG_URL` remain server settings. They do not configure an OpenClaw Gateway.

When adding paths to `server.py`'s `STATIC` allowlist, restart this application's
running Python process. Updating files alone serves the new HTML immediately
but leaves the old in-memory allowlist in effect, so newly linked CSS, modules,
or images can return 404. Verify the running process's script and working
directory before targeting its PM2 name or ID. After restarting, check the
public URL's `/workspace.css?v=cypher-v4`, `/openclaw-client.js?v=openclaw-v1`,
`/openclaw-install.js?v=openclaw-v1`, `/local-memory.js?v=memory-v1`,
`/chat-policy.js?v=chat-v1`, and `/assets/cypher-horizon.png` for HTTP 200
and the expected MIME types, then open the public page on desktop and mobile.
The `/healthz` value `models-v1` alone does not identify the current UI release;
check its `workspace` value (`cypher-v4`) and the served asset contents too.

Run automated checks with Node.js 18 or later and Python:

```sh
npm test
python3 -B -m unittest discover -s tests -p 'test_*.py' -v
git diff --check
```

For focused OpenClaw tests:

```sh
node --test tests/openclaw-install.test.mjs tests/openclaw-client.test.mjs
```

Optional rendered-browser checks use test-only Playwright and `ws` packages:

```sh
npm install --no-save playwright ws
npx playwright install chromium
npm run test:browser
```

`PLAYWRIGHT_MODULE`, `WS_MODULE`, and `PLAYWRIGHT_BROWSERS_PATH` can point to an
existing test installation. The browser harness uses an actual browser Worker,
WebSocket, Web Crypto, and IndexedDB with simulated inference and a Gateway
fixture. It intercepts installer requests instead of downloading native apps.

These tests use simulated platform information, transport, and inference where
applicable. They do not install OpenClaw or establish a live authenticated
Gateway connection. Verify actual downloads, native onboarding, device pairing,
session streaming, abort behavior, and permission prompts on the intended
desktop and mobile devices. Browser inference additionally needs a real WebGPU
download and generation check.

Validation performed on 2026-10-03: 117 Node checks, 14 Python server checks,
and 27 rendered Chromium scenarios passed. In the rendered scenarios, GPU,
inference, and Gateway behavior were fixtures; browser signing, IndexedDB, and
WebSocket transport were real.

The UI checks also cover Japanese Auto search, Off preventing search, note
create/edit/delete, saved conversation reload and restoration after model
preparation, memory recall in the actual Worker input, and disabled memory
preventing further recall/saving across reload.

The UI checks include homepage navigation, ready and unprepared question
submission, model/status cards, safe address opening, modal focus and visible
setup feedback, phone layouts, and shorter viewports. Delayed Gateway replies
are tested against later Home, Web, and Local navigation so an earlier Agent
question cannot be submitted in the newer mode or reopen an abandoned view.
The phone checks also simulate visual viewport heights of 180–360px and
independent vertical offsets while leaving the layout viewport larger. They
check clipping and actual hit targets, multiline Japanese drafts, composition,
rotation, mode focus, and a pointer press/release on Send without a moving target.
The phone checks use Chromium with simulated device settings; native Safari,
Android keyboard behavior, and actual mobile inference still need device checks.

A separate isolated check connected this client to the installed OpenClaw
Gateway 2026.9.7 (c074824), protocol 4. It confirmed pairing rejection and exact
test-device approval, scoped authentication, session listing, message
subscription, text history, abort of a nonexistent test run, unsubscribe, and
device-token reconnection. Only a fresh temporary Gateway state was used; no
model requests or agent runs were started. This establishes those Gateway
contracts, not model quality, completed native installation, or real tool use.
