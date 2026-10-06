#!/usr/bin/env node
// Root-authorized, genuine public mobile-width UI smoke. No node operations.
// Controller interception only observes the original UI start/post methods.
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdtemp, rm, lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';

if (process.env.MESH_SMOKE_AUTHORIZED !== '1') throw new Error('Root authorization is required before public participation.');
const origin = process.env.MESH_SMOKE_ORIGIN || 'https://ai-test.make-cph-great-again.community';
const dir = '/tmp/cypher-zero-connections-20261004';
const output = process.env.MESH_SMOKE_REPORT || join(dir, 'public-smoke-report.json');
assert(output.startsWith('/tmp/'));
const { chromium } = await import(pathToFileURL(process.env.PLAYWRIGHT_MODULE || '/tmp/cypher-zero-tools/node_modules/playwright/index.mjs'));
const executable = process.env.CHROMIUM || '/tmp/cypher-zero-browsers/chromium-1243/chrome-linux64/chrome';
const profile = await mkdtemp('/tmp/cypher-zero-ui-');
const child = spawn(executable, ['--no-sandbox', '--no-proxy-server', '--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank'],
  { stdio: 'ignore', env: { ...process.env, XDG_CONFIG_HOME: join(profile, 'xdg-config'), XDG_CACHE_HOME: join(profile, 'xdg-cache') } });
const report = { status: 'RUNNING', startedAt: new Date().toISOString(), origin, chromePid: child.pid,
  sameHostOnly: true, mobile: { width: 390, height: 844, touch: true, emulated: true, realPhone: false },
  scope: 'Actual public UI Common WSS connections and signature validation, explicit OFF and reload lifecycle; no independent WebRTC transfer claim',
  nativeLifecycleMutations: 0, transportReplacements: 0, sourceByteInjection: false, checkpoints: [], pageErrors: [], httpErrors: [] };
let browser, context, page;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const save = () => writeFile(output, JSON.stringify(report, null, 2) + '\n');
async function until(label, check, ms = 60000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) { const value = await check(); if (value) return value; await sleep(200); }
  if (page) try { report.failureObservation = await page.evaluate(() => window.zeroSmokeEvidence?.() || {
    state: document.querySelector('#relayState')?.dataset.state, reason: document.querySelector('#relayReason')?.textContent,
    errors: document.querySelector('#relayErrors')?.textContent }); } catch {}
  throw new Error(label + ' timed out');
}
async function checkpoint(name, value) { report.checkpoints.push({ name, at: new Date().toISOString(), value }); await save(); console.log('PASS', name); }
try {
  await save();
  const port = await until('Owned Chrome CDP startup', async () => { try { return Number((await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]); } catch { return false; } }, 20000);
  browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`, { noDefaults: true });
  const session = await browser.newBrowserCDPSession(), info = await session.send('SystemInfo.getProcessInfo');
  assert.equal(info.processInfo.find(row => row.type === 'browser').id, child.pid);
  context = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true });
  page = await context.newPage();
  page.on('pageerror', error => { if (report.pageErrors.length < 32) report.pageErrors.push(error.message.slice(0, 500)); });
  page.on('response', async response => {
    if (!response.url().startsWith(origin + '/relay/v1/mesh/') || response.status() < 400 || report.httpErrors.length >= 32) return;
    let errorCode = null;
    try { const body = await response.json(); errorCode = typeof body.error?.code === 'string' ? body.error.code.slice(0, 100) : null; } catch {}
    report.httpErrors.push({ path: new URL(response.url()).pathname, status: response.status(), code: errorCode });
  });
  await page.goto(origin, { waitUntil: 'domcontentloaded', timeout: 45000 });
  await page.waitForFunction(() => document.querySelector('#relayState')?.dataset.state === 'OFF' && document.querySelector('#relayOn')?.disabled === false);
  report.initial = await page.evaluate(() => ({ state: document.querySelector('#relayState').dataset.state,
    commons: document.querySelector('#relayCommonPeers').textContent, peers: document.querySelector('#relayPeers').textContent,
    width: innerWidth, pageVisibility: document.visibilityState }));
  assert.equal(report.initial.commons, '0'); assert.equal(report.initial.width, 390);
  await checkpoint('Public mobile-width page starts OFF', report.initial);
  await page.evaluate(async () => {
    const { MeshController } = await import('/mesh-controller.js?v=mesh-v1');
    const { verifyEndpoint, verifyMeshAdvertisement } = await import('/mesh-discovery.js');
    const original = MeshController.prototype.start;
    window.zeroSmoke = { startCalls: 0, hellos: new Map(), events: [] };
    MeshController.prototype.start = function(...args) {
      zeroSmoke.startCalls++;
      if (!zeroSmoke.mesh) {
        zeroSmoke.mesh = this;
        const post = this.post.bind(this);
        this.post = (message, transfer) => {
          if (message.type === 'nativeHello') zeroSmoke.hellos.set(message.sourceId, message.frame);
          return post(message, transfer);
        };
        this.addEventListener('event', event => {
          const e = event.detail;
          if (['native-connected', 'native_ready', 'session-renewed', 'common-renewed', 'error'].includes(e.name) && zeroSmoke.events.length < 64)
            zeroSmoke.events.push({ name: e.name, sourceId: e.sourceId, nodeId: e.nodeId, browserId: e.browserId,
              nativeSession: e.nativeSession, browserSignatureVerified: e.browserSignatureVerified,
              endpointSignatureVerified: e.endpointSignatureVerified, code: e.code, message: e.message, fatal: e.fatal });
        });
      }
      return original.apply(this, args);
    };
    window.zeroSmokeEvidence = () => {
      const mesh = zeroSmoke.mesh; if (!mesh) return { captured: false };
      const state = mesh.snapshot(), signatures = [];
      for (const connection of state.commonConnections) {
        const attachment = [...mesh.attachments.values()].find(value => value.session.sourceId === connection.sourceId);
        const hello = zeroSmoke.hellos.get(connection.sourceId);
        if (!attachment || !hello) continue;
        const candidate = mesh.discovery?.endpoints().find(record => record.nodeId === connection.nodeId && record.sourceId === connection.sourceId);
        try {
          const native = verifyMeshAdvertisement(hello.advertisement, mesh.config.network);
          const endpoint = candidate ? verifyEndpoint(candidate.envelope, mesh.config.network) : null;
          signatures.push({ sourceId: connection.sourceId, nodeId: connection.nodeId, nativeSignatureVerified: true,
            nativeIdentityMatches: native.nodeId === connection.nodeId,
            nativeSessionMatches: hello.session === attachment.nativeSession, nativeBootId: native.payload.bootId,
            endpointSignatureVerified: Boolean(endpoint), endpointIdentityMatches: endpoint ? endpoint.nodeId === native.nodeId : null,
            endpointBootMatches: endpoint ? endpoint.payload.bootId === native.payload.bootId : null,
            endpointSequence: endpoint?.payload.sequence ?? null, endpointExpiresAt: endpoint?.expiresAt ?? null,
            wsReadyState: attachment.socket?.readyState, workerSignatureVerified: connection.browserSignatureVerified === true });
        } catch (error) { signatures.push({ sourceId: connection.sourceId, error: error.message }); }
      }
      const native = state.nativeStatus;
      return { captured: true, state: state.state, reason: state.reason, requested: state.requested, generation: mesh.generation,
        startCalls: zeroSmoke.startCalls, sessionId: mesh.session?.id || null, sessionExpiresAt: mesh.session?.expiresAt || null,
        primarySourceId: mesh.session?.sourceId || null, network: mesh.config?.network || null,
        configNodeIds: mesh.config?.nodes.map(node => node.nodeId) || [], workerPresent: Boolean(mesh.worker),
        commonConnections: state.commonConnections, nativeConnections: state.nativeConnections,
        peers: state.peers.filter(peer => peer.connected).length, circuits: state.circuits, queuedBytes: state.queuedBytes,
        appBytes: state.appBytes, pendingSends: mesh.pendingPeerSends.size, nativeReceivedBytes: state.nativeReceivedBytes,
        nativeSentBytes: state.nativeSentBytes, sourceErrors: state.sourceErrors, signatures,
        workerValidatedCommons: (state.sources || []).map(source => ({ nodeId: source.nodeId, sourceId: source.sourceId, browserSignatureVerified: source.browserSignatureVerified })),
        discovery: state.discovery, events: zeroSmoke.events.slice(),
        gatewayStatus: native ? { sourceId: native.sourceId, running: native.running, sessions: native.sessions,
          circuits: native.circuits, candidates: native.candidates, participants: native.participants, leases: native.leases,
          receivedBytes: native.receivedBytes, sentBytes: native.sentBytes, nativeLimits: native.nativeLimits,
          browserTransfer: native.session ? { transferredBytes: native.session.transferredBytes, transferLimitBytes: native.session.transferLimitBytes,
            attachments: native.session.attachments, maxAttachments: native.session.maxAttachments } : null } : null,
        ui: { state: document.querySelector('#relayState').dataset.state, reason: document.querySelector('#relayReason').textContent,
          commons: document.querySelector('#relayCommonPeers').textContent, peers: document.querySelector('#relayPeers').textContent,
          wssReceived: document.querySelector('#relayGatewayRx').textContent,
          sources: [...document.querySelectorAll('#relayCommonList [data-common-source]')].map(element => element.dataset.commonSource),
          onDisabled: document.querySelector('#relayOn').disabled, offDisabled: document.querySelector('#relayOff').disabled } };
    };
  });
  const evidence = () => page.evaluate(() => zeroSmokeEvidence());
  await page.evaluate(() => document.querySelector('#navRelay').click());
  await page.locator('#relayOn').click();
  report.on = await until('At least two real Common WSS connections validated by Worker', async () => {
    const state = await evidence(), connected = state.commonConnections?.filter(connection => connection.connected);
    if (!connected || connected.length < 2 || !state.requested || !state.workerPresent || state.nativeConnections !== connected.length || Number(state.ui.commons) !== connected.length || state.nativeReceivedBytes <= 0) return false;
    if (!connected.every(connection => connection.browserSignatureVerified && state.signatures.some(signature => signature.sourceId === connection.sourceId &&
      signature.wsReadyState === 1 && signature.nativeSignatureVerified && signature.nativeIdentityMatches && signature.nativeSessionMatches && signature.workerSignatureVerified))) return false;
    if (!connected.every(connection => state.workerValidatedCommons.some(source => source.nodeId === connection.nodeId && source.browserSignatureVerified))) return false;
    return state;
  }, 90000);
  assert.equal(report.on.startCalls, 1);
  assert.equal(new Set(report.on.commonConnections.filter(connection => connection.connected).map(connection => connection.nodeId)).size, report.on.nativeConnections);
  await checkpoint('Real signed Common WSS connections restored on public mobile-width UI', report.on);
  report.statusObservation = await until('Bounded normal UI gateway status observation', async () => {
    const state = await evidence(); return state.gatewayStatus?.running ? state : false;
  }, 20000);
  await checkpoint('Normal session/status and receipt-free counters observed without credentials', report.statusObservation);
  report.onScreenshot = join(dir, 'public-mobile-on.png');
  await page.screenshot({ path: report.onScreenshot, fullPage: true });
  await page.locator('#relayOff').click();
  report.off = await until('OFF clears Worker, native sockets, leases and queues', async () => {
    const state = await evidence(); return !state.requested && state.state === 'OFF' && !state.workerPresent && !state.sessionId &&
      state.commonConnections.length === 0 && state.nativeConnections === 0 && state.peers === 0 && state.circuits === 0 &&
      state.queuedBytes === 0 && state.appBytes === 0 && state.pendingSends === 0 && state.ui.commons === '0' &&
      !state.ui.onDisabled && state.ui.offDisabled ? state : false;
  });
  assert(report.off.generation > report.on.generation);
  await sleep(2500); report.offStable = await evidence();
  assert.equal(report.offStable.requested, false); assert.equal(report.offStable.workerPresent, false);
  assert.equal(report.offStable.nativeConnections, 0); assert.equal(report.offStable.startCalls, 1);
  await checkpoint('Explicit OFF clears connections and does not revive', report.offStable);
  report.offScreenshot = join(dir, 'public-mobile-off.png');
  await page.screenshot({ path: report.offScreenshot, fullPage: true });
  await page.reload({ waitUntil: 'domcontentloaded', timeout: 45000 });
  await page.waitForFunction(() => document.querySelector('#relayState')?.dataset.state === 'OFF');
  await sleep(1500);
  report.reload = await page.evaluate(() => ({ state: document.querySelector('#relayState').dataset.state,
    commons: document.querySelector('#relayCommonPeers').textContent, peers: document.querySelector('#relayPeers').textContent,
    onDisabled: document.querySelector('#relayOn').disabled, offDisabled: document.querySelector('#relayOff').disabled }));
  assert.equal(report.reload.state, 'OFF'); assert.equal(report.reload.commons, '0'); assert.equal(report.reload.peers, '0');
  assert.equal(report.reload.onDisabled, false); assert.equal(report.reload.offDisabled, true);
  assert.equal(report.pageErrors.length, 0);
  await checkpoint('Reload stays OFF until an explicit new ON', report.reload);
  report.status = 'PASS';
} catch (error) { report.status = 'FAIL'; report.error = error.stack; process.exitCode = 1; }
finally {
  try { if (page && !page.isClosed()) await page.evaluate(() => document.querySelector('#relayOff')?.click()); } catch {}
  try { await Promise.race([context?.close(), sleep(8000)]); } catch {}
  try { await Promise.race([browser?.close(), sleep(8000)]); } catch (error) { report.browserCloseError = error.message; }
  if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
  for (let n = 0; n < 30 && child.exitCode === null && child.signalCode === null; n++) await sleep(100);
  if (child.exitCode === null && child.signalCode === null) { child.kill('SIGKILL'); for (let n = 0; n < 30 && child.exitCode === null && child.signalCode === null; n++) await sleep(100); }
  report.cleanup = { chromeExited: child.exitCode !== null || child.signalCode !== null, profileRemoved: false };
  try {
    assert(report.cleanup.chromeExited); const stat = await lstat(profile); assert(stat.isDirectory() && !stat.isSymbolicLink());
    await rm(profile, { recursive: true, force: true }); report.cleanup.profileRemoved = await lstat(profile).then(() => false, error => error.code === 'ENOENT');
  } catch (error) { report.cleanup.error = error.message; }
  if (!report.cleanup.chromeExited || !report.cleanup.profileRemoved) { report.status = 'FAIL'; process.exitCode = 1; }
  report.finishedAt = new Date().toISOString(); await save();
}
console.log(report.status, output);
