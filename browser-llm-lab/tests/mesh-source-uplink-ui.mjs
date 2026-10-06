#!/usr/bin/env node
// Genuine public Node ON UI; only passive observation is installed.
// Root starts the temporary Common after this script prints READY.
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdtemp, rm, lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';

if (process.env.SOURCE_ACCEPTANCE_AUTHORIZED !== '1') throw new Error('Root authorization is required before live UI smoke.');
const origin = process.env.SOURCE_PUBLIC_ORIGIN || 'https://ai-test.make-cph-great-again.community';
const output = process.env.SOURCE_UI_REPORT || '/tmp/cypher-source-uplink-review/ui-dynamic-report.json';
const readyFile = process.env.SOURCE_UI_READY || '/tmp/cypher-source-uplink-review/ui-dynamic-ready.json';
assert(output.startsWith('/tmp/') && readyFile.startsWith('/tmp/'));
const expectedSourceId = process.env.SOURCE_ID || null;
if (expectedSourceId) assert(/^[a-f0-9]{64}$/.test(expectedSourceId));
const timeout = Number(process.env.SOURCE_UI_TIMEOUT_MS || 240000);
assert(Number.isInteger(timeout) && timeout >= 10000 && timeout <= 600000);
const { chromium } = await import(pathToFileURL(process.env.PLAYWRIGHT_MODULE || '/tmp/browser-llm-preview/node_modules/playwright/index.mjs'));
const executable = process.env.CHROMIUM || '/tmp/browser-llm-browsers/chromium-1243/chrome-linux64/chrome';
const profile = await mkdtemp('/tmp/cypher-uplink-ui-');
const child = spawn(executable, ['--no-sandbox', '--no-proxy-server', '--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank'],
  { stdio: 'ignore', env: { ...process.env, XDG_CONFIG_HOME: join(profile, 'xdg-config'), XDG_CACHE_HOME: join(profile, 'xdg-cache') } });
const report = { status: 'RUNNING', startedAt: new Date().toISOString(), origin, pid: child.pid, profile,
  sameHostOnly: true, scope: 'Normal public UI dynamic same-origin Common discovery without OFF/ON; no independent RTC transfer claim',
  nativeLifecycleMutations: 0, transportReplacements: 0, sourceByteInjection: false, checkpoints: [], pageErrors: [] };
let browser, page;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const save = () => writeFile(output, JSON.stringify(report, null, 2) + '\n');
async function until(label, check, ms = 45000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) { const value = await check(); if (value) return value; await sleep(200); }
  throw new Error(label + ' timed out');
}
async function checkpoint(name, value) { report.checkpoints.push({ name, at: new Date().toISOString(), value }); await save(); console.log('PASS', name); }
try {
  await save();
  const port = await until('CDP startup', async () => { try { return Number((await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]); } catch { return false; } }, 20000);
  browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`, { noDefaults: true });
  const session = await browser.newBrowserCDPSession(), processInfo = await session.send('SystemInfo.getProcessInfo');
  assert.equal(processInfo.processInfo.find(row => row.type === 'browser').id, child.pid);
  page = browser.contexts()[0].pages()[0] || await browser.contexts()[0].newPage();
  page.on('pageerror', error => { if (report.pageErrors.length < 32) report.pageErrors.push(error.message.slice(0, 500)); });
  await page.goto(origin, { waitUntil: 'domcontentloaded', timeout: 45000 });
  await page.waitForFunction(() => document.querySelector('#relayState')?.dataset.state === 'OFF' && document.querySelector('#relayOn')?.disabled === false);
  report.initial = await page.evaluate(() => ({ state: document.querySelector('#relayState').dataset.state,
    commons: document.querySelector('#relayCommonPeers').textContent, peers: document.querySelector('#relayPeers').textContent }));
  assert.equal(report.initial.commons, '0');
  await checkpoint('Public page initially OFF', report.initial);
  await page.evaluate(async () => {
    const { MeshController } = await import('/mesh-controller.js?v=mesh-v1');
    const { verifyEndpoint, verifyMeshAdvertisement } = await import('/mesh-discovery.js');
    const original = MeshController.prototype.start;
    window.sourceSmoke = { startCalls: 0, hellos: new Map(), events: [] };
    MeshController.prototype.start = function(...args) {
      sourceSmoke.startCalls++;
      if (!sourceSmoke.mesh) {
        sourceSmoke.mesh = this;
        const post = this.post.bind(this);
        this.post = (message, transfer) => {
          if (message.type === 'nativeHello') sourceSmoke.hellos.set(message.sourceId, message.frame);
          return post(message, transfer);
        };
        this.addEventListener('event', event => {
          if (['native-connected', 'native_ready', 'error'].includes(event.detail.name) && sourceSmoke.events.length < 64) sourceSmoke.events.push(event.detail);
        });
      }
      return original.apply(this, args);
    };
    window.sourceSmokeEvidence = () => {
      const mesh = sourceSmoke.mesh;
      if (!mesh) return { captured: false };
      const state = mesh.snapshot(), signatures = [];
      for (const connection of state.commonConnections) {
        const candidate = mesh.discovery?.endpoints().find(record => record.nodeId === connection.nodeId && record.sourceId === connection.sourceId);
        const hello = sourceSmoke.hellos.get(connection.sourceId);
        if (!candidate || !hello) continue;
        try {
          const endpoint = verifyEndpoint(candidate.envelope, mesh.config.network), native = verifyMeshAdvertisement(hello.advertisement, mesh.config.network);
          const attachment = [...mesh.attachments.values()].find(value => value.session.sourceId === connection.sourceId);
          signatures.push({ sourceId: endpoint.sourceId, nodeId: endpoint.nodeId, origin: endpoint.origin, sequence: endpoint.payload.sequence,
            bootId: endpoint.payload.bootId, expiresAt: endpoint.expiresAt, bothSignaturesVerified: true,
            identityMatches: endpoint.nodeId === native.nodeId, bootMatches: endpoint.payload.bootId === native.payload.bootId,
            nativeSessionMatches: hello.session === attachment?.nativeSession,
            parentMatchesHomeSession: !attachment?.attachmentId || attachment.session.parentId === mesh.session?.id });
        } catch (error) { signatures.push({ sourceId: connection.sourceId, error: error.message }); }
      }
      return { captured: true, state: state.state, requested: state.requested, generation: mesh.generation, startCalls: sourceSmoke.startCalls,
        sessionId: mesh.session?.id || null, configNodeIds: mesh.config?.nodes.map(node => node.nodeId) || [],
        workerPresent: Boolean(mesh.worker), commonConnections: state.commonConnections, nativeConnections: state.nativeConnections,
        peers: state.peers.length, circuits: state.circuits, queuedBytes: state.queuedBytes, appBytes: state.appBytes,
        pendingSends: mesh.pendingPeerSends.size, signatures, events: sourceSmoke.events.slice(), sourceErrors: state.sourceErrors,
        workerCommonSignatures: (state.sources || []).map(source => ({ nodeId: source.nodeId, browserSignatureVerified: source.browserSignatureVerified })),
        ui: { state: document.querySelector('#relayState').dataset.state, commons: document.querySelector('#relayCommonPeers').textContent,
          sources: [...document.querySelectorAll('#relayCommonList [data-common-source]')].map(element => element.dataset.commonSource) } };
    };
  });
  const evidence = () => page.evaluate(() => sourceSmokeEvidence());
  await page.evaluate(() => document.querySelector('#navRelay').click());
  await page.locator('#relayOn').click();
  report.home = await until('One normal Common before unknown source starts', async () => {
    const state = await evidence();
    return state.commonConnections?.length === 1 && state.commonConnections[0].sourceId === 'common-mine' &&
      state.commonConnections[0].connected && state.commonConnections[0].browserSignatureVerified && state.ui.commons === '1' && state.workerPresent ? state : false;
  });
  assert.equal(report.home.startCalls, 1);
  await checkpoint('Node ON has one verified Common; waiting for external source startup', report.home);
  await writeFile(readyFile, JSON.stringify({ ready: true, at: new Date().toISOString(), pid: child.pid, sourceId: expectedSourceId, generation: report.home.generation,
    initialNodeIds: report.home.configNodeIds, report: output }, null, 2) + '\n');
  console.log('READY', readyFile);
  report.dynamic = await until('Automatically discovered second Common without OFF/ON', async () => {
    const state = await evidence(), added = state.commonConnections?.find(connection =>
      connection.sourceId !== 'common-mine' && /^[a-f0-9]{64}$/.test(connection.sourceId) && (!expectedSourceId || connection.sourceId === expectedSourceId));
    const signature = state.signatures?.find(record => record.sourceId === added?.sourceId);
    return added?.connected && added.browserSignatureVerified && added.endpointVerified && state.ui.commons === '2' &&
      state.nativeConnections === 2 && signature?.bothSignaturesVerified && signature.identityMatches && signature.bootMatches &&
      signature.nativeSessionMatches && signature.parentMatchesHomeSession ? state : false;
  }, timeout);
  const added = report.dynamic.commonConnections.find(connection => connection.sourceId !== 'common-mine');
  assert(!report.home.configNodeIds.includes(added.nodeId), 'New source was absent from initial config');
  assert.equal(report.dynamic.generation, report.home.generation); assert.equal(report.dynamic.sessionId, report.home.sessionId);
  assert.equal(report.dynamic.startCalls, 1); assert.equal(report.dynamic.workerPresent, true);
  report.sourceId = added.sourceId;
  await checkpoint('New signed source appears as actual Common connection number 2', report.dynamic);
  await page.locator('#relayOff').click();
  report.off = await until('OFF clears native leases, Worker, queues and display', async () => {
    const state = await evidence(); return !state.requested && state.state === 'OFF' && !state.workerPresent && !state.sessionId &&
      state.commonConnections.length === 0 && state.nativeConnections === 0 && state.peers === 0 && state.circuits === 0 &&
      state.queuedBytes === 0 && state.appBytes === 0 && state.pendingSends === 0 && state.ui.commons === '0' ? state : false;
  });
  assert(report.off.generation > report.home.generation); await sleep(1500);
  assert.equal((await evidence()).requested, false);
  assert.equal(report.pageErrors.length, 0);
  await checkpoint('OFF clears both Common links without stale reconnection', report.off);
  report.status = 'PASS';
} catch (error) { report.status = 'FAIL'; report.error = error.stack; process.exitCode = 1; }
finally {
  try { await page?.evaluate(() => sourceSmoke.mesh?.stop()); } catch {}
  try { await Promise.race([browser?.close(), sleep(8000)]); } catch (error) { report.browserCloseError = error.message; }
  if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
  for (let n = 0; n < 30 && child.exitCode === null && child.signalCode === null; n++) await sleep(100);
  if (child.exitCode === null && child.signalCode === null) { child.kill('SIGKILL'); for (let n = 0; n < 30 && child.exitCode === null && child.signalCode === null; n++) await sleep(100); }
  report.cleanup = { exited: child.exitCode !== null || child.signalCode !== null, profileRemoved: false };
  try {
    assert(report.cleanup.exited); const info = await lstat(profile); assert(info.isDirectory() && !info.isSymbolicLink());
    await rm(profile, { recursive: true, force: true }); report.cleanup.profileRemoved = await lstat(profile).then(() => false, error => error.code === 'ENOENT');
  } catch (error) { report.cleanup.error = error.message; }
  if (!report.cleanup.exited || !report.cleanup.profileRemoved) { report.status = 'FAIL'; process.exitCode = 1; }
  report.finishedAt = new Date().toISOString(); await save();
}
console.log(report.status, output);
