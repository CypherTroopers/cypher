#!/usr/bin/env node
// One ordinary Common, two independent real browsers. No native DB/IPC calls.
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdtemp, mkdir, rm, lstat } from 'node:fs/promises';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';

if (process.env.MIGRATION_SMOKE_AUTHORIZED !== '1') throw new Error('Prepared only. Set MIGRATION_SMOKE_AUTHORIZED=1 after the operator confirms cutover.');
// In the repository this file lives at tests/mesh-consolidation-browser.mjs.
const root = process.env.MIGRATION_ROOT || fileURLToPath(new URL('../', import.meta.url));
const origin = 'https://ai-test.make-cph-great-again.community';
const expectedNodeId = process.env.MIGRATION_NODE_ID || 'ef4d1c50627c52801acc77a036826aa68b429d2c7d713e10c8b9a743d0492efb';
const output = process.env.MIGRATION_SMOKE_REPORT || '/tmp/cypher-post-migration-smoke.json';
assert(output.startsWith('/tmp/'), 'Evidence output must remain under /tmp');
const { chromium } = await import(pathToFileURL(process.env.PLAYWRIGHT_MODULE || '/tmp/browser-llm-preview/node_modules/playwright/index.mjs'));
const executablePath = process.env.CHROMIUM || '/tmp/browser-llm-browsers/chromium-1243/chrome-linux64/chrome';
const runDirectory = await mkdtemp('/tmp/cypher-migration-smoke-');
const participants = new Map();
const report = { status: 'RUNNING', startedAt: new Date().toISOString(), origin, root, expectedNodeId,
  sameHostOnly: true, actualPhoneHardware: false, ordinaryCommons: 1, nativeCommonToCommonRelay: 'NOT_TESTED_REQUIRES_TWO_COMMONS',
  loopbackHostOverride: process.env.MIGRATION_SMOKE_LOOPBACK === '1', runDirectory,
  processes: {}, checkpoints: [], pageErrors: [], peerErrors: [], cleanup: [] };
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const save = async () => writeFile(output, JSON.stringify(report, null, 2) + '\n');
const checkpoint = async (name, details = {}) => { report.checkpoints.push({ name, at: new Date().toISOString(), ...details }); await save(); console.log('PASS', name); };
async function waitFor(name, predicate, timeout = 60000) {
  const began = Date.now();
  while (Date.now() - began < timeout) { const value = await predicate(); if (value) return value; await sleep(250); }
  throw new Error(`${name} timed out after ${timeout}ms`);
}
async function evidence(name) {
  return participants.get(name).page.evaluate(() => window.__migrationEvidence());
}
async function launch(name) {
  const profile = join(runDirectory, name); await mkdir(profile, { mode: 0o700 });
  const args = ['--no-sandbox', '--no-proxy-server', '--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`,
    ...(report.loopbackHostOverride ? [`--host-resolver-rules=MAP ${new URL(origin).hostname} 127.0.0.1, EXCLUDE localhost`] : []), 'about:blank'];
  const child = spawn(executablePath, args, { stdio: 'ignore', env: { ...process.env, XDG_CONFIG_HOME: join(profile, 'xdg-config'), XDG_CACHE_HOME: join(profile, 'xdg-cache') } });
  const row = { child, profile }; participants.set(name, row);
  report.processes[name] = { browserPid: child.pid, profile, executablePath, independentProcess: true }; await save();
  let spawnError; child.once('error', error => { spawnError = error; });
  const debugPort = await waitFor(`${name} CDP`, async () => {
    if (spawnError) throw spawnError;
    if (child.exitCode !== null) throw new Error(`${name} Chrome exited before CDP`);
    try { return Number((await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]) || false; } catch { return false; }
  }, 20000);
  row.browser = await chromium.connectOverCDP(`http://127.0.0.1:${debugPort}`, { noDefaults: true });
  row.context = row.browser.contexts()[0]; row.page = row.context.pages()[0] || await row.context.newPage();
  await row.page.setViewportSize({ width: name === 'B' ? 390 : 1280, height: 844 });
  const browserCDP = await row.browser.newBrowserCDPSession();
  const processInfo = await browserCDP.send('SystemInfo.getProcessInfo');
  const actualPID = processInfo.processInfo.find(value => value.type === 'browser')?.id;
  assert.equal(actualPID, child.pid, 'Owned child must be the independent browser process');
  row.page.on('pageerror', error => { if (report.pageErrors.length < 32) report.pageErrors.push({ browser: name, message: error.message.slice(0, 500) }); });
  await row.page.goto(origin, { waitUntil: 'domcontentloaded', timeout: 45000 });
  await row.page.waitForFunction(() => document.querySelector('#relayState')?.dataset.state === 'OFF' && document.querySelector('#relayOn')?.disabled === false);
  const initialUI = await row.page.evaluate(() => ({ state: document.getElementById('relayState').dataset.state,
    commonConnections: document.getElementById('relayCommonPeers').textContent, peers: document.getElementById('relayPeers').textContent,
    nodeOnEnabled: !document.getElementById('relayOn').disabled, nodeOffDisabled: document.getElementById('relayOff').disabled }));
  assert.equal(initialUI.state, 'OFF'); assert.equal(initialUI.commonConnections, '0'); assert.equal(initialUI.peers, '0'); assert(initialUI.nodeOffDisabled);
  const paths = ['mesh-controller.js', 'mesh-worker.js', 'mesh-discovery.js', 'mesh-discovery-client.js', 'vendor/mesh-crypto.js', 'relay-ui.js'];
  const localHashes = Object.fromEntries(await Promise.all(paths.map(async path => [path, createHash('sha256').update(await readFile(resolve(root, 'public', path))).digest('hex')])));
  const remoteHashes = await row.page.evaluate(async paths => Object.fromEntries(await Promise.all(paths.map(async path => {
    const response = await fetch('/' + path, { cache: 'no-store' }); if (!response.ok) throw new Error('Missing deployed module ' + path);
    const digest = await crypto.subtle.digest('SHA-256', await response.arrayBuffer());
    return [path, [...new Uint8Array(digest)].map(value => value.toString(16).padStart(2, '0')).join('')];
  }))), paths);
  assert.deepEqual(remoteHashes, localHashes, 'Deployed modules must match moved project');
  report.processes[name].moduleHashes = remoteHashes;
  await row.page.evaluate(async expectedNodeId => {
    // Same module URL used by relay-ui.js: capture its existing controller when
    // the genuine UI Node ON handler calls start. Do not replace transports.
    const { MeshController } = await import('/mesh-controller.js?v=mesh-v1');
    const { verifyEndpoint, verifyMeshAdvertisement } = await import('/mesh-discovery.js');
    const original = MeshController.prototype.start;
    window.__migrationLifecycle = []; window.__migrationErrors = [];
    for (const type of ['visibilitychange', 'freeze', 'resume']) document.addEventListener(type, event => window.__migrationLifecycle.push({ type, trusted: event.isTrusted, visibility: document.visibilityState }));
    MeshController.prototype.start = function(...args) {
      if (!window.__migrationMesh) {
        window.__migrationMesh = this; window.__migrationInitialGeneration = this.generation;
        const post = this.post.bind(this);
        this.post = function(message, transfer) {
          if (message.type === 'nativeHello') window.__migrationHello = message.frame;
          return post(message, transfer);
        };
        this.addEventListener('event', event => { if (event.detail.name === 'error' && window.__migrationErrors.length < 32) window.__migrationErrors.push({ code: event.detail.code, fatal: event.detail.fatal }); });
      }
      return original.apply(this, args);
    };
    window.__migrationEvidence = () => {
      const mesh = window.__migrationMesh;
      if (!mesh) return { captured: false };
      const s = mesh.snapshot();
      let signedEndpoint = null;
      try {
        const candidate = mesh.discovery?.endpoints().find(record => record.nodeId === expectedNodeId && record.sourceId === 'common-mine');
        if (candidate && window.__migrationHello) {
          const endpoint = verifyEndpoint(candidate.envelope, mesh.config.network);
          const advertisement = verifyMeshAdvertisement(window.__migrationHello.advertisement, mesh.config.network);
          signedEndpoint = { sourceId: endpoint.sourceId, nodeId: endpoint.nodeId, origin: endpoint.origin, expiresAt: endpoint.expiresAt,
            bootId: endpoint.payload.bootId, sequence: endpoint.payload.sequence,
            matchesNativeHelloIdentity: advertisement.nodeId === endpoint.nodeId,
            matchesNativeHelloBoot: advertisement.payload.bootId === endpoint.payload.bootId,
            matchesNativeSession: window.__migrationHello.session === s.nativeSession,
            bothSignaturesVerified: true };
        }
      } catch (error) { signedEndpoint = { error: error.message }; }
      return { captured: true, state: s.state, requested: s.requested, generation: mesh.generation,
        initialGeneration: window.__migrationInitialGeneration, sessionId: s.sessionId || null, nativeSession: s.nativeSession,
        peerId: mesh.session?.peerId || null, sourceId: s.sourceId, nodeId: s.nodeId,
        workerPresent: Boolean(mesh.worker), nativeConnected: s.nativeConnected, signalConnected: s.signalConnected,
        commonConnections: s.commonConnections, peers: s.peers, rtcStats: s.rtcStats,
        circuits: s.circuits, queuedBytes: s.queuedBytes, appBytes: s.appBytes,
        nativeConnections: s.nativeConnections, pendingSends: mesh.pendingPeerSends.size,
        timerCount: mesh.timers.size, discovery: s.discovery, signedEndpoint,
        workerCommonSignatures: (s.sources || []).filter(source => source.nodeId === expectedNodeId).map(source => ({ nodeId: source.nodeId, browserSignatureVerified: source.browserSignatureVerified })),
        errors: window.__migrationErrors.slice(), lifecycle: window.__migrationLifecycle.slice(),
        ui: { state: document.getElementById('relayState').dataset.state, peers: document.getElementById('relayPeers').textContent,
          commons: document.getElementById('relayCommonPeers').textContent, sourceLabels: [...document.querySelectorAll('#relayCommonList [data-common-source]')].map(element => element.dataset.commonSource) } };
    };
  }, expectedNodeId);
  await checkpoint(`${name}: actual page starts OFF`, { browser: name, initialUI });
  return row;
}
function off(row) {
  return row.captured && !row.requested && row.state === 'OFF' && !row.workerPresent && !row.nativeConnected && !row.signalConnected &&
    row.sessionId === null && row.nativeSession === null && row.peers.length === 0 && row.commonConnections.length === 0 &&
    row.circuits === 0 && row.queuedBytes === 0 && row.appBytes === 0 && row.pendingSends === 0;
}
async function turnOn(name) {
  const page = participants.get(name).page;
  await page.evaluate(() => document.getElementById('navRelay').click());
  await page.locator('#relayOn').click({ timeout: 15000 });
  const row = await waitFor(`${name} verified ordinary Common`, async () => {
    const r = await evidence(name), e = r.signedEndpoint;
    return r.nativeConnected && r.commonConnections.length === 1 && r.commonConnections[0].connected &&
      r.commonConnections[0].sourceId === 'common-mine' && r.commonConnections[0].browserSignatureVerified &&
      e?.bothSignaturesVerified && e.sourceId === 'common-mine' && e.nodeId === expectedNodeId && e.origin === origin &&
      e.matchesNativeHelloIdentity && e.matchesNativeHelloBoot && e.matchesNativeSession ? r : false;
  }, 90000);
  await checkpoint(`${name}: UI ON verifies signed endpoint and native HELLO`, { browser: name, evidence: row });
  return row;
}
try {
  await save(); await launch('A'); await launch('B');
  assert.notEqual(report.processes.A.browserPid, report.processes.B.browserPid);
  const firstA = await turnOn('A'); await sleep(1100); await turnOn('B');
  const connected = await waitFor('Independent browsers connect to each other through RTC', async () => {
    const a = await evidence('A'), b = await evidence('B');
    return a.peers.some(peer => peer.peerId === b.peerId && peer.connected) && b.peers.some(peer => peer.peerId === a.peerId && peer.connected) ? { A: a, B: b } : false;
  }, 90000);
  await checkpoint('Two independent browsers have a real RTC DataChannel; one shared native Common', connected);
  await participants.get('A').page.locator('#relayOff').click();
  const stoppedA = await waitFor('A OFF clears generation/session/Worker/queues', async () => { const r = await evidence('A'); return off(r) ? r : false; });
  assert(stoppedA.generation > firstA.generation);
  await sleep(3000); assert(off(await evidence('A')), 'Old asynchronous work must not revive A');
  await waitFor('B removes A RTC peer', async () => !(await evidence('B')).peers.some(peer => peer.peerId === firstA.peerId && peer.connected));
  await checkpoint('A OFF clears its session and Worker and stays OFF', { A: stoppedA });
  const secondA = await turnOn('A');
  assert.notEqual(secondA.sessionId, firstA.sessionId); assert.notEqual(secondA.nativeSession, firstA.nativeSession);
  await waitFor('A manually rejoins through a new RTC generation', async () => { const a = await evidence('A'), b = await evidence('B'); return a.peers.some(peer => peer.peerId === b.peerId && peer.connected) && b.peers.some(peer => peer.peerId === a.peerId && peer.connected); });
  await checkpoint('Manual ON creates fresh browser/native sessions', { oldSession: firstA.sessionId, newSession: secondA.sessionId, oldNativeSession: firstA.nativeSession, newNativeSession: secondA.nativeSession });
  const b = participants.get('B'), cdp = await b.context.newCDPSession(b.page);
  const foreground = await b.context.newPage(); await foreground.bringToFront();
  await waitFor('Trusted hidden transition', () => b.page.evaluate(() => document.visibilityState === 'hidden'), 5000);
  await cdp.send('Page.setWebLifecycleState', { state: 'frozen' }); await sleep(300);
  await cdp.send('Page.setWebLifecycleState', { state: 'active' }); await b.page.bringToFront();
  await waitFor('Hidden/freeze stops B', async () => off(await evidence('B')), 10000);
  await sleep(3000); const lifecycle = await evidence('B'); assert(off(lifecycle));
  assert(lifecycle.lifecycle.some(event => event.type === 'visibilitychange' && event.trusted && event.visibility === 'hidden'));
  assert(lifecycle.lifecycle.some(event => event.type === 'freeze' && event.trusted));
  await checkpoint('Trusted hide/freeze stops B; foreground return stays OFF', { B: lifecycle });
  await participants.get('A').page.locator('#relayOff').click();
  await waitFor('Final A OFF', async () => off(await evidence('A')));
  report.final = { A: await evidence('A'), B: await evidence('B') };
  report.peerErrors = [...report.final.A.errors.map(row => ({ browser: 'A', ...row })), ...report.final.B.errors.map(row => ({ browser: 'B', ...row }))];
  assert.equal(report.pageErrors.length, 0); report.status = 'PASS';
} catch (error) {
  report.status = 'FAIL'; report.error = error.stack;
  for (const [name, row] of participants) { try { report[name] = await evidence(name); } catch {} }
  process.exitCode = 1;
} finally {
  for (const [name, row] of participants) {
    const cleanup = { browser: name, browserPid: row.child?.pid, profile: row.profile }; report.cleanup.push(cleanup);
    try { await row.page?.evaluate(() => window.__migrationMesh?.stop()); } catch {}
    try { await Promise.race([row.browser?.close(), sleep(8000)]); } catch (error) { cleanup.browserCloseError = error.message; }
    if (row.child && row.child.exitCode === null && row.child.signalCode === null) row.child.kill('SIGTERM');
    for (let count = 0; count < 30 && row.child?.exitCode === null && row.child?.signalCode === null; count++) await sleep(100);
    if (row.child && row.child.exitCode === null && row.child.signalCode === null) { row.child.kill('SIGKILL'); for (let count = 0; count < 30 && row.child.exitCode === null && row.child.signalCode === null; count++) await sleep(100); }
    cleanup.childExited = !row.child || row.child.exitCode !== null || row.child.signalCode !== null;
    try {
      assert(cleanup.childExited, 'Owned Chrome child must exit before profile cleanup');
      assert(dirname(row.profile) === runDirectory && ['A', 'B'].includes(name));
      const info = await lstat(row.profile); assert(info.isDirectory() && !info.isSymbolicLink());
      await rm(row.profile, { recursive: true, force: true });
      cleanup.profileRemoved = await lstat(row.profile).then(() => false, error => error.code === 'ENOENT');
    } catch (error) { cleanup.error = error.message; cleanup.profileRemoved = false; }
  }
  report.cleanupComplete = report.cleanup.every(row => row.childExited && row.profileRemoved);
  if (!report.cleanupComplete) { report.status = 'FAIL'; process.exitCode = 1; }
  report.finishedAt = new Date().toISOString(); await save();
}
console.log(report.status, output);
