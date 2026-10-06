#!/usr/bin/env node
// Real 20-neighbor acceptance: a private loopback gateway, pinned research
// Commons, and 21 independent Chromium processes. Never runs without the gate.
// Plan: check resources -> admit every 1.1s -> observe hub degree20 -> OFF hub
// -> OFF all -> verify owned leases/routes -> stop fixture -> compare hashes.
// This does not prove 20 independent Commons or native consensus/finality.
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { request as httpRequest } from 'node:http';
import { createServer } from 'node:net';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { createGateway } from '../relay/gateway.mjs';

assert.equal(process.env.MESH_SCALE_JOIN_AUTHORIZED, '1',
  'Scale participation is disabled. Wait for the parent readiness gate before setting MESH_SCALE_JOIN_AUTHORIZED=1.');
const root = fileURLToPath(new URL('../', import.meta.url));
const port = Number(process.env.MESH_SCALE_PORT || 8094);
assert(Number.isInteger(port) && port > 1024 && port < 65536, 'Use an unprivileged private loopback port');
const base = `http://127.0.0.1:${port}`;
const nativeOrigin = 'https://ai-test.make-cph-great-again.community';
const output = resolve(process.env.MESH_SCALE_REPORT || '/tmp/cypher-mesh-scale-browser-report.json');
const coreFiles = ['public/mesh-controller.js', 'public/mesh-worker.js', 'public/mesh-protocol.js',
  'public/relay-controller.js', 'public/relay-protocol.js', 'relay/gateway.mjs', 'relay/config.mjs',
  'tests/mesh-scale-browser.mjs'];
const sourceHashes = async () => Object.fromEntries(await Promise.all(coreFiles.map(async file =>
  [file, createHash('sha256').update(await readFile(resolve(root, file))).digest('hex')])));
const sleep = ms => new Promise(done => setTimeout(done, ms));
const participants = [], ownLeases = new Map(), ownedBrowserIds = new Set();
let gateway, fixtureListening = false, lastAdmissionAt = 0;
const report = { kind: 'ACTUAL_20_RTC_PEER_SCALE', startedAt: new Date().toISOString(), status: 'RUNNING',
  sameHostOnly: true, independentBrowserProcesses: true, requiredBrowsers: 21, requiredHubPeers: 20,
  gatewayOrigin: base, nativeOrigin, syntheticFrames: false, fakeRTC: false, controllerMethodOverrides: false,
  forcedTransport: false, publicDeployment: false, maxCommonConnectionsPerBrowser: 1,
  leaseObservation: 'Read-only current controller session; tokens retained only in runner memory and omitted from evidence',
  twentyCommonEndpoints: 'NOT_RUN: only the two pinned research Commons are configured',
  exactNativeByteVerification: false, consensusOrFinalityProof: false,
  observations: [], participants: {}, pageErrors: [], evidenceDiagnostics: [], checkpoints: [], cleanup: {}, maxima: {},
  memoryNotes: 'Worker appBytes is the application reservation; Chromium RSS sum includes shared pages more than once; performance.memory is the page heap, not all Worker or process memory.' };
const shortError = error => String(error?.message || error).replace(/Bearer\s+\S+/gi, 'Bearer [redacted]')
  .replace(/\b[a-f0-9]{64,}\b/gi, '[opaque identifier]').slice(0, 300);
const save = async () => { await mkdir(dirname(output), { recursive: true }); await writeFile(output, JSON.stringify(report, null, 2) + '\n'); };
async function checkpoint(name, detail = {}) {
  report.checkpoints.push({ name, at: new Date().toISOString(), ...detail });
  await save(); console.log('PASS', name);
}
async function hostMemory() {
  const text = await readFile('/proc/meminfo', 'utf8');
  return Object.fromEntries(['MemTotal', 'MemAvailable', 'SwapTotal', 'SwapFree'].map(key =>
    [key + 'Bytes', Number(text.match(new RegExp(`^${key}:\\s+(\\d+)`, 'm'))?.[1] || 0) * 1024]));
}
async function portUnused() {
  const probe = createServer();
  await new Promise((done, fail) => { probe.once('error', fail); probe.listen(port, '127.0.0.1', done); });
  await new Promise(done => probe.close(done));
}
function gatewayStats() {
  const stats = gateway.stats();
  return { sessions: stats.sessions, pendingAdmissions: stats.pendingAdmissions, webSockets: stats.webSockets,
    connections: stats.connections, dropReasons: stats.dropReasons,
    nodes: Object.fromEntries(Object.entries(stats.nodes).map(([id, value]) =>
      [id, { sessions: value.sessions, pending: value.pending, releasing: value.releasing }])) };
}
async function nativeStatus(node) {
  return new Promise((done, fail) => {
    const req = httpRequest({ socketPath: node.socketPath, path: '/relay/v1/mesh/status', method: 'GET',
      headers: { Origin: nativeOrigin, Connection: 'close' }, agent: false }, res => {
      const chunks = []; let size = 0;
      res.on('data', chunk => { size += chunk.length; if (size > 65536) req.destroy(new Error('Native status exceeds bounded response')); else chunks.push(chunk); });
      res.on('end', () => {
        try {
          assert.equal(res.statusCode, 200, 'Pinned research Common status must be available');
          const row = JSON.parse(Buffer.concat(chunks).toString());
          assert(Array.isArray(row.routes) && row.routes.length <= 40, 'Bounded native route list required');
          done({ sourceId: node.id, running: row.running, sessions: row.sessions, circuits: row.circuits,
            receivedBytes: row.receivedBytes, sentBytes: row.sentBytes,
            ownedRoutes: row.routes.filter(route => route.relayIds?.some(id => ownedBrowserIds.has(id))) });
        } catch (error) { fail(error); }
      });
      res.on('error', fail);
    });
    req.setTimeout(6000, () => req.destroy(new Error('Pinned Common status timeout'))); req.on('error', fail); req.end();
  });
}
async function waitFor(label, predicate, timeout = 180000, interval = 1000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) { const value = await predicate(); if (value) return value; await sleep(interval); }
  throw new Error(label + ' timed out after ' + timeout + 'ms');
}
async function processMemory(participant) {
  const session = await participant.browser.newBrowserCDPSession();
  try {
    const info = await session.send('SystemInfo.getProcessInfo');
    const processes = await Promise.all(info.processInfo.map(async process => {
      try {
        const text = await readFile(`/proc/${process.id}/status`, 'utf8');
        return { pid: process.id, type: process.type, rssBytes: Number(text.match(/^VmRSS:\s+(\d+)/m)?.[1] || 0) * 1024 };
      } catch { return { pid: process.id, type: process.type, rssBytes: null }; }
    }));
    return { processes, summedRSSBytes: processes.reduce((sum, value) => sum + (value.rssBytes || 0), 0) };
  } finally { await session.detach(); }
}
async function sample(participant, detailed = false) {
  const row = await participant.page.evaluate(async detailed => {
    const controller = mesh.snapshot(), evidence = detailed ? await mesh.inspect() : null;
    const peers = controller.peers.map(({ peerId, connected, path, state }) => ({ peerId, connected, path, state }));
    const candidates = [];
    if (detailed) for (const [peerId, peer] of mesh.peers) {
      const stats = await peer.pc.getStats(); let selected;
      for (const entry of stats.values()) if (entry.type === 'transport' && entry.selectedCandidatePairId) selected = stats.get(entry.selectedCandidatePairId);
      if (!selected) for (const entry of stats.values()) if (entry.type === 'candidate-pair' && entry.state === 'succeeded' && entry.nominated) selected = entry;
      const local = selected && stats.get(selected.localCandidateId), remote = selected && stats.get(selected.remoteCandidateId);
      const channels = [...stats.values()].filter(entry => entry.type === 'data-channel').map(entry => ({
        state: entry.state, label: entry.label, bytesSent: entry.bytesSent, bytesReceived: entry.bytesReceived,
        messagesSent: entry.messagesSent, messagesReceived: entry.messagesReceived }));
      candidates.push({ peerId, connectionState: peer.pc.connectionState, dataChannelState: peer.dc?.readyState,
        selected: !!selected, localType: local?.candidateType || null, remoteType: remote?.candidateType || null,
        protocol: local?.protocol || null, relayProtocol: local?.relayProtocol || null,
        candidatePairState: selected?.state || null, currentRoundTripTime: selected?.currentRoundTripTime ?? null, channels });
    }
    const numericKeys = ['connectedPeers', 'nativeConnections', 'circuits', 'endpointCircuits', 'transitCircuits',
      'pendingHandshakes', 'pendingInbound', 'pendingOutbound', 'pendingTransit', 'queuedBytes', 'appBytes',
      'totalBytes', 'receivedBytes', 'sentBytes', 'nativeReceivedBytes', 'nativeSentBytes',
      'streamReceivedBytes', 'streamForwardedBytes', 'acknowledgedBytes', 'acknowledgedCount'];
    const summarize = value => ({ ...Object.fromEntries(numericKeys.map(key => [key, value?.[key] ?? 0])), capacities: value?.capacities || null });
    return { ownedLease: mesh.session ? { id: mesh.session.id, token: mesh.session.token, browserId: mesh.session.browserId } : null,
      at: Date.now(), state: controller.state, requested: controller.requested, visibility: document.visibilityState,
      sourceId: controller.sourceId, sessionId: controller.sessionId, browserId: controller.browserId,
      peerId: mesh.session?.peerId || null, signalConnected: controller.signalConnected,
      commonConnections: controller.commonConnections, peers, connectionLimits: controller.connectionLimits,
      controller: summarize(controller), worker: evidence ? summarize(evidence.stats) : null,
      candidates: detailed ? candidates : undefined, events: detailed ? meshScaleEvents : undefined,
      eventCounts: { ...meshScaleEventCounts },
      pageHeap: performance.memory ? { usedBytes: performance.memory.usedJSHeapSize, totalBytes: performance.memory.totalJSHeapSize, limitBytes: performance.memory.jsHeapSizeLimit } : null };
  }, detailed);
  // Read the actual controller lease without intercepting admission responses.
  // Strip its token before any evidence object is stored or serialized.
  if (row.ownedLease?.id && row.ownedLease?.token) {
    ownLeases.set(row.ownedLease.id, row.ownedLease.token); ownedBrowserIds.add(row.ownedLease.browserId);
  }
  delete row.ownedLease;
  row.connected = row.peers.filter(peer => peer.connected).length;
  assert(row.connected <= 20 && row.peers.length <= 20, 'Actual RTC participants never exceed 20');
  assert(row.commonConnections.filter(common => common.connected).length <= 1, 'This scale fixture isolates one Common per browser');
  for (const state of [row.controller, row.worker].filter(Boolean)) {
    assert(state.appBytes <= 4 * 1048576 && state.queuedBytes <= 512 * 1024, 'Existing application and queue budgets remain unchanged');
    assert(state.circuits <= 40 && state.connectedPeers <= 20, 'Worker/controller capacities remain globally bounded');
  }
  const previous = report.maxima[participant.name] || {};
  report.maxima[participant.name] = { connected: Math.max(previous.connected || 0, row.connected),
    appBytes: Math.max(previous.appBytes || 0, row.controller.appBytes, row.worker?.appBytes || 0),
    queuedBytes: Math.max(previous.queuedBytes || 0, row.controller.queuedBytes, row.worker?.queuedBytes || 0),
    acknowledgedCount: Math.max(previous.acknowledgedCount || 0, row.controller.acknowledgedCount) };
  report.participants[participant.name].latest = row;
  return row;
}
async function recordObservation(label) {
  const rows = await Promise.all(participants.map(participant => sample(participant)));
  if (report.observations.length < 80) report.observations.push({ label, at: Date.now(), gateway: gatewayStats(),
    browsers: rows.map((row, index) => ({ name: participants[index].name, connected: row.connected,
      commonConnected: row.commonConnections.filter(common => common.connected).length, state: row.state,
      appBytes: row.controller.appBytes, queuedBytes: row.controller.queuedBytes, acknowledgedCount: row.controller.acknowledgedCount })) });
  await save(); return rows;
}
async function launch(chromium, index, sourceId) {
  const name = index ? `peer-${String(index).padStart(2, '0')}` : 'hub';
  const browser = await chromium.launch({ headless: true,
    executablePath: process.env.CHROMIUM || '/tmp/browser-llm-browsers/chromium-1243/chrome-linux64/chrome',
    args: ['--no-sandbox'], env: { ...process.env, XDG_CONFIG_HOME: '/tmp/cypher-mesh-scale-config', XDG_CACHE_HOME: '/tmp/cypher-mesh-scale-cache' } });
  const participant = { name, browser, sourceId }; participants.push(participant);
  const context = await browser.newContext({ viewport: { width: 800, height: 600 } });
  participant.context = context; participant.page = await context.newPage();
  const cdp = await browser.newBrowserCDPSession(), info = await cdp.send('SystemInfo.getProcessInfo'); await cdp.detach();
  participant.pid = info.processInfo.find(process => process.type === 'browser')?.id;
  assert(participant.pid && participants.filter(row => row.pid === participant.pid).length === 1, 'Every browser uses an independent process');
  report.participants[name] = { browserPid: participant.pid, sourceId, admissionAttempts: 0 };
  participant.page.on('pageerror', error => { if (report.pageErrors.length < 64) report.pageErrors.push({ name, error: shortError(error) }); });
  participant.page.on('response', response => {
    if (response.request().method() !== 'POST' || new URL(response.url()).pathname !== '/relay/v1/mesh/sessions') return;
    report.participants[name].admissionAttempts++;

  });
  await participant.page.goto(base, { waitUntil: 'domcontentloaded' });
  await sleep(Math.max(0, 1100 - (Date.now() - lastAdmissionAt))); lastAdmissionAt = Date.now();
  await participant.page.evaluate(async sourceId => {
    const { MeshController } = await import('/mesh-controller.js');
    globalThis.mesh = new MeshController({ sourceId, maxCommonConnections: 1 });
    globalThis.meshScaleEvents = []; globalThis.meshScaleEventCounts = {};
    mesh.addEventListener('event', ({ detail }) => {
      const key = String(detail.name || 'unknown').slice(0, 64);
      meshScaleEventCounts[key] = (meshScaleEventCounts[key] || 0) + 1;
      const row = Object.fromEntries(['name', 'code', 'fatal', 'peerId', 'circuitId', 'sourceId', 'path', 'at']
        .filter(key => typeof detail[key] === 'string' || typeof detail[key] === 'number' || typeof detail[key] === 'boolean')
        .map(key => [key, typeof detail[key] === 'string' ? detail[key].slice(0, 80) : detail[key]]));
      meshScaleEvents.push(row); if (meshScaleEvents.length > 128) meshScaleEvents.shift();
    });
    await mesh.start();
  }, sourceId);
  await waitFor(name + ' attached to its pinned Common', async () => {
    const row = await sample(participant); return row.signalConnected && row.commonConnections.filter(common => common.connected).length === 1;
  }, 45000);
  await recordObservation('admitted ' + name); return participant;
}
async function stopParticipant(participant) {
  if (!participant.page || participant.page.isClosed()) return;
  await participant.page.evaluate(() => globalThis.mesh?.stop());
}
async function leaseStatus(token) {
  const response = await fetch(base + '/relay/v1/mesh/status', { headers: { Origin: base, Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(6000) });
  await response.arrayBuffer(); return response.status;
}
let targets;
try {
  report.sourceHashes = await sourceHashes(); report.hostBefore = await hostMemory(); await save();
  assert(report.hostBefore.MemAvailableBytes >= 6 * 1024 ** 3, 'Insufficient available RAM for 21 independent browser processes; no participation started');
  await portUnused();
  targets = JSON.parse(await readFile(resolve(root, 'relay/mesh-targets.json'), 'utf8'));
  assert.equal(targets.length, 2, 'Only the two existing pinned research Common endpoints are allowed');
  const runtimeRoot = resolve(process.env.MESH_LIVE_ROOT || root, '.runtime');
  const expectedSockets = { 'common-a': resolve(runtimeRoot, 'mesh-a/source.sock'), 'common-b': resolve(runtimeRoot, 'mesh-b/source.sock') };
  for (const target of targets) assert.equal(target.socketPath, expectedSockets[target.id], 'Research Common socket must match its fixed operator pin');
  const operation = JSON.parse(await readFile(resolve(root, 'relay/config.json'), 'utf8'));
  report.nativeBefore = await Promise.all(targets.map(nativeStatus));
  gateway = createGateway({ config: { enabled: true, origin: base, nativeOrigin, network: operation.network,
    nodes: targets.map(({ id, socketPath, enode, nodeId }) => ({ id, socketPath, enode, nodeId })),
    limits: { maxSessions: 64, maxSessionsPerClient: 64, maxConnections: 160, maxPeers: 20, maxCommonConnections: 20,
      httpRequestsPerSecond: 128, httpBytesPerSecond: 1048576, admissionsPerMinute: 128 },
    iceServers: operation.iceServers, ...(operation.turn ? { turn: operation.turn } : {}) } });
  const handler = gateway.server.listeners('request')[0]; gateway.server.removeAllListeners('request');
  gateway.server.on('request', async (request, response) => {
    if (request.url.startsWith('/relay/')) return handler(request, response);
    const path = new URL(request.url, base).pathname;
    if (path === '/') { response.writeHead(200, { 'Content-Type': 'text/html' }); response.end('<!doctype html><meta charset="utf-8"><title>Actual 20 RTC peers</title><p>Private research mesh scale fixture</p>'); return; }
    const file = path.slice(1);
    if (!coreFiles.includes('public/' + file)) { response.writeHead(404); response.end(); return; }
    try { const bytes = await readFile(resolve(root, 'public', file)); response.writeHead(200, { 'Content-Type': 'text/javascript', 'Cache-Control': 'no-store' }); response.end(bytes); }
    catch { response.writeHead(404); response.end(); }
  });
  await gateway.listen({ host: '127.0.0.1', port }); fixtureListening = true;
  const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || '/tmp/browser-llm-preview/node_modules/playwright/index.mjs');
  await checkpoint('Private stage gateway is listening; research endpoints are pinned', { gateway: gatewayStats() });
  for (let index = 0; index < 21; index++) await launch(chromium, index, targets[index % 2].id);
  assert.equal(new Set(participants.map(participant => participant.pid)).size, 21);
  const peak = await waitFor('Hub has 20 actual open RTC DataChannels', async () => {
    const rows = await recordObservation('connecting');
    if (rows[0].connected !== 20) return false;
    const hub = await sample(participants[0], true);
    return hub.worker.connectedPeers === 20 && hub.candidates.length === 20 && hub.candidates.every(peer => peer.dataChannelState === 'open' && peer.selected) ? rows : false;
  }, 180000, 5000);
  report.peak = await Promise.all(participants.map(async participant => ({ name: participant.name,
    ...(await sample(participant, true)), processMemory: await processMemory(participant) })));
  assert.equal(report.peak[0].connected, 20); assert.equal(report.peak[0].worker.connectedPeers, 20);
  assert(report.peak.every(row => row.requested && row.commonConnections.filter(common => common.connected).length === 1));
  report.nativeAtPeak = await Promise.all(targets.map(nativeStatus));
  report.nativeHopACKsObserved = report.peak.some(row => row.controller.acknowledgedCount > 0);
  await checkpoint('21 independent browsers; hub has 20 real RTC peers within existing global budgets', {
    hubConnected: report.peak[0].connected, peerDegrees: peak.slice(1).map(row => row.connected),
    nativeHopACKsObserved: report.nativeHopACKsObserved });
  const departingPeerId = report.peak[0].peerId;
  assert(peak.slice(1).every(row => row.peers.some(peer => peer.peerId === departingPeerId && peer.connected)), 'All twenty peers really connect to the hub');
  await stopParticipant(participants[0]);
  report.afterHubOFF = await waitFor('Hub OFF removes its RTC connection from every remaining browser', async () => {
    const rows = await recordObservation('hub OFF');
    return !rows[0].requested && rows[0].connected === 0 && rows.slice(1).every(row => row.connected <= 19 && !row.peers.some(peer => peer.peerId === departingPeerId)) ? rows : false;
  }, 30000);
  await checkpoint('Hub OFF removes all twenty owned neighbor connections', { remainingDegrees: report.afterHubOFF.slice(1).map(row => row.connected) });
  report.status = 'CHECKING_CLEANUP';
} catch (error) {
  report.status = 'FAIL'; report.error = shortError(error); process.exitCode = 1;
} finally {
  const cleanupErrors = [];
  const stops = await Promise.allSettled(participants.map(stopParticipant));
  stops.forEach((result, index) => { if (result.status === 'rejected') cleanupErrors.push(participants[index].name + ': ' + shortError(result.reason)); });
  if (fixtureListening) {
    try {
      await waitFor('Private fixture has no active or releasing owned sessions', () => {
        const stats = gatewayStats(); return stats.sessions === 0 && stats.pendingAdmissions === 0 &&
          Object.values(stats.nodes).every(node => node.sessions === 0 && node.pending === 0 && node.releasing === 0);
      }, 30000, 1000);
      report.cleanup.gateway = gatewayStats();
      assert(ownLeases.size >= participants.length, 'Every admitted browser must have an observed owned lease');
      report.cleanup.ownedLeases = [];
      for (const [sessionId, token] of ownLeases) {
        const status = await leaseStatus(token); report.cleanup.ownedLeases.push({ sessionId, status });
        assert.equal(status, 401, 'Every lease issued to this runner must be invalid after OFF');
      }
      report.cleanup.native = await waitFor('Only runner-owned native routes are reclaimed', async () => {
        const rows = await Promise.all(targets.map(nativeStatus)); return rows.every(row => row.ownedRoutes.length === 0) ? rows : false;
      }, 20000, 1000);
      report.cleanup.globalNativeZeroRequired = false;
      report.cleanup.browserOFF = await Promise.all(participants.map(participant => sample(participant)));
      assert(report.cleanup.browserOFF.every(row => !row.requested && row.connected === 0 && row.controller.appBytes === 0 && row.controller.queuedBytes === 0 && row.controller.circuits === 0 && row.controller.nativeConnections === 0));
    } catch (error) { cleanupErrors.push(shortError(error)); }
  }
  const closes = await Promise.allSettled(participants.map(participant => participant.browser.close()));
  closes.forEach((result, index) => { if (result.status === 'rejected') cleanupErrors.push(participants[index].name + ' close: ' + shortError(result.reason)); });
  try { await gateway?.close(); report.cleanup.fixtureStopped = true; if (gateway) report.cleanup.gatewayAfterClose = gatewayStats(); } catch (error) { cleanupErrors.push('Fixture close: ' + shortError(error)); }
  report.cleanup.errors = cleanupErrors;
  try {
    report.finalHashes = await sourceHashes(); report.changedCoreFiles = coreFiles.filter(file => report.sourceHashes?.[file] !== report.finalHashes[file]);
    assert.deepEqual(report.changedCoreFiles, [], 'Stage implementation changed during acceptance');
    report.hostAfter = await hostMemory();
  } catch (error) { cleanupErrors.push(shortError(error)); }
  if (cleanupErrors.length || report.pageErrors.length) { report.status = 'FAIL'; process.exitCode = 1; }
  else if (report.status === 'CHECKING_CLEANUP') report.status = 'PASS';
  report.finishedAt = new Date().toISOString(); await save();
  console.log(report.status, output);
}
