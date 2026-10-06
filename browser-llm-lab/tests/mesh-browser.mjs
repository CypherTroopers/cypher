#!/usr/bin/env node
// Actual native RLPx bytes over independent browser processes. No bridge fixture or chain injection.
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdtemp, rm, lstat } from 'node:fs/promises';
import { resolve, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile, spawn as spawnProcess } from 'node:child_process';
import { createHash } from 'node:crypto';
import { promisify } from 'node:util';
import { createMeshTLSFixture } from './mesh-tls-fixture.mjs';
import { createGateway } from '../relay/gateway.mjs';
import { classifyCircuitLifecycle, leaseEvidence } from './mesh-evidence.mjs';
const execute = promisify(execFile), { chromium } = await import(process.env.PLAYWRIGHT_MODULE || '/tmp/browser-llm-preview/node_modules/playwright/index.mjs');
const root = fileURLToPath(new URL('../', import.meta.url));
const port = Number(process.env.MESH_TEST_PORT || 8093), publicOrigin = process.env.MESH_PUBLIC_ORIGIN || '', base = publicOrigin || `http://127.0.0.1:${port}`;
const discoveryGateways = process.env.MESH_DISCOVERY_GATEWAYS === '1';
assert(!(discoveryGateways && publicOrigin), 'Choose isolated TLS gateways or public deployment');
const tlsFixture = discoveryGateways ? await createMeshTLSFixture({ root, names: ['native-gateway-a', 'native-gateway-b'] }) : null;
const output = process.env.MESH_REPORT || '/tmp/cypher-mesh-browser-report.json';
const soakMs = Number(process.env.MESH_SOAK_MS || 0), forceTurn = process.env.MESH_FORCE_TURN === '1';
const forceDirect = process.env.MESH_FORCE_DIRECT === '1';
assert(!(forceTurn && forceDirect), 'Choose exactly one transport forcing policy');
const abrupt = process.env.MESH_CHECK_ABRUPT === '1', expectedCapacity = Number(process.env.MESH_EXPECT_NATIVE_CAPACITY || 0);
const lifecycle = process.env.MESH_CHECK_LIFECYCLE === '1', workload = process.env.MESH_CHECK_WORKLOAD === '1', readmission = process.env.MESH_CHECK_READMISSION === '1';
const hostOverride = !!publicOrigin && process.env.MESH_ORIGIN_LOOPBACK === '1';
const coreFiles = ['public/mesh-protocol.js', 'public/mesh-worker.js', 'public/mesh-controller.js', 'public/relay-protocol.js', 'public/relay-controller.js', 'relay/gateway.mjs', 'relay/config.mjs', 'public/mesh-discovery.js', 'public/mesh-discovery-client.js', 'public/vendor/mesh-crypto.js', 'relay/discovery.mjs'];
const fileHashes = async () => Object.fromEntries(await Promise.all(coreFiles.map(async path => [path, createHash('sha256').update(await readFile(resolve(root, path))).digest('hex')])));
const targets = JSON.parse(await readFile(resolve(root, 'relay/mesh-targets.json'), 'utf8'));
const operation = JSON.parse(await readFile(resolve(root, 'relay/config.json'), 'utf8'));
const config = { enabled: true, origin: base, nativeOrigin: 'https://ai-test.make-cph-great-again.community', network: operation.network,
  nodes: targets.map(({ id, socketPath, enode, nodeId }) => ({ id, socketPath, enode, nodeId })),
  limits: { maxSessions: 8, maxSessionsPerClient: 8, maxConnections: 32, maxPeers: 20, maxCommonConnections: 1, httpRequestsPerSecond: 128, httpBytesPerSecond: 1048576, admissionsPerMinute: 32 },
  iceServers: operation.iceServers, ...(operation.turn ? { turn: operation.turn } : {}) };
const gateway = publicOrigin || discoveryGateways ? null : createGateway({ config });
const discoveryServers = [];
if (discoveryGateways) {
  for (const [index, origin] of tlsFixture.origins.entries()) {
    const node = config.nodes.find(n => n.id === (index ? 'common-b' : 'common-a'));
    const server = createGateway({ config: { ...config, origin, nodes: [node],
      discovery: { enabled: true, bootstrapOrigins: tlsFixture.origins, allowedOrigins: tlsFixture.origins } } });
    await server.listen({ port: 0 }); tlsFixture.addGateway(index, server); discoveryServers.push(server);
  }
}
if (gateway) {
const nativeHandler = gateway.server.listeners('request')[0]; gateway.server.removeAllListeners('request');
gateway.server.on('request', async (req, res) => {
  if (req.url.startsWith('/relay/')) return nativeHandler(req, res);
  try {
    const path = new URL(req.url, base).pathname;
    if (path === '/') { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<!doctype html><meta charset="utf-8"><title>Native Common mesh test</title><body>Actual browser mesh test</body>'); return; }
    const file = resolve(root, 'public', '.' + path);
    if (!file.startsWith(resolve(root, 'public') + '/')) { res.writeHead(403); res.end(); return; }
    const data = await readFile(file);
    res.writeHead(200, { 'Content-Type': extname(file) === '.js' ? 'text/javascript' : 'text/plain', 'Cache-Control': 'no-store' }); res.end(data);
  } catch { res.writeHead(404); res.end(); }
});
await gateway.listen({ port });
}
const browsers = [], ownedChildren = new Set(), ownedProfiles = new Set(), participants = new Map(), pages = new Map(), allEvents = [], testIdentities = new Map(), ownedBrowserIds = new Set(), ownLeases = new Map(), report = { startedAt: new Date().toISOString(), status: 'RUNNING', forceTurn, forceDirect, sameHostOnly: true,
  publicOrigin: publicOrigin || null, discoveryGateways: tlsFixture?.origins || null, hostOverride, transportPath: discoveryGateways ? 'two distinct loopback TLS gateway origins, native owner sockets, cross-gateway signed rendezvous and WebRTC' : publicOrigin ? 'public HTTPS/Nginx/WSS and WebRTC' : 'local HTTP/WS fixture and WebRTC',
  nativeBIsolated: true, webRTCPath: true, directInjection: false, nativeEvidence: [], checkpoints: [], errors: [], samples: [], actualLLM: false, expectedCapacity,
  processes: {}, peerErrors: {}, nativeCircuitHistory: [], lifecycle: null, sourceHashes: await fileHashes() };
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function save() { await writeFile(output, JSON.stringify(report, null, 2)); }
async function checkpoint(name, details) { report.checkpoints.push({ name, at: new Date().toISOString(), ...details }); await save(); console.log('PASS', name); }
async function native() {
  const result = await execute('python3', [resolve(root, 'relay/mesh-native-inspect.py')], { timeout: 20000, maxBuffer: 4 * 1048576, env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
  return JSON.parse(result.stdout);
}
async function spawn(name, sourceId) {
  const executablePath = process.env.CHROMIUM || '/tmp/browser-llm-browsers/chromium-1243/chrome-linux64/chrome';
  const participantOrigin = discoveryGateways ? tlsFixture.origins[sourceId === 'common-b' ? 1 : 0] : base;
  const args = ['--no-sandbox', ...(discoveryGateways ? ['--no-proxy-server', '--ignore-certificate-errors', `--host-resolver-rules=${tlsFixture.hostResolverRules}`] : []), ...(hostOverride ? [`--host-resolver-rules=MAP ${new URL(base).hostname} 127.0.0.1, EXCLUDE localhost`] : [])];
  const env = { ...process.env, XDG_CONFIG_HOME: '/tmp/cypher-mesh-chrome-config', XDG_CACHE_HOME: '/tmp/cypher-mesh-chrome-cache' };
  let browser, context, page, child, profile;
  if (lifecycle || abrupt) {
    profile = await mkdtemp(`/tmp/cypher-mesh-${name}-`);
    ownedProfiles.add(profile);
    child = spawnProcess(executablePath, [...args, '--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank'], { env, stdio: 'ignore' });
    ownedChildren.add(child);
    const deadline = Date.now() + 20000; let debugPort;
    while (!debugPort && Date.now() < deadline) { try { debugPort = Number((await readFile(`${profile}/DevToolsActivePort`, 'utf8')).split('\n')[0]); } catch {} if (!debugPort) await sleep(100); }
    assert(debugPort, 'Standalone Chromium exposes its own CDP endpoint');
    browser = await chromium.connectOverCDP(`http://127.0.0.1:${debugPort}`, { noDefaults: true });
    browsers.push(browser);
    context = browser.contexts()[0]; page = context.pages()[0] || await context.newPage();
    await page.setViewportSize({ width: name === 'B' ? 390 : 1280, height: 844 });
  } else {
    browser = await chromium.launch({ headless: true, executablePath, args, env });
    browsers.push(browser);
    context = await browser.newContext({ ignoreHTTPSErrors: discoveryGateways, viewport: { width: name === 'B' ? 390 : 1280, height: 844 } }); page = await context.newPage();
  }
  pages.set(name, page); participants.set(name, { browser, context, page, child, profile });
  const browserCDP = await browser.newBrowserCDPSession(), processInfo = await browserCDP.send('SystemInfo.getProcessInfo');
  report.processes[name] = { origin: participantOrigin, browserPid: processInfo.processInfo.find(row => row.type === 'browser')?.id, separateProfile: true, mobileViewport: name === 'B', actualPhone: false, webGPUInitialization: false };
  await page.exposeFunction('meshTransportClosed', event => {
    report.transportCloses ||= [];
    report.transportCloses.push({ browser: name, observedAt: Date.now(), ...event });
    if (report.transportCloses.length > 128) report.transportCloses.shift();
  });
  // Passive diagnostics: preserve native WebSocket behavior and record only
  // path, close code and bounded reason, never authentication frames/tokens.
  await page.addInitScript(() => {
    const Original = WebSocket;
    globalThis.WebSocket = class extends Original {
      constructor(...args) {
        super(...args);
        const path = new URL(String(args[0]), location.href).pathname;
        this.addEventListener('close', event => globalThis.meshTransportClosed?.({ path, code: event.code, clean: event.wasClean, reason: event.reason.slice(0, 200) }));
      }
    };
  });
  await page.exposeFunction('meshEvidenceEvent', event => { allEvents.push({ browser: name, observedAt: Date.now(), ...event }); if (event.name === 'error') { const key = `${name}:${event.code || 'unknown'}`; report.peerErrors[key] = (report.peerErrors[key] || 0) + 1; } });
  await page.exposeFunction('meshFixtureIdentity', async ({ token, ...identity }) => {
    testIdentities.set(name, identity); ownedBrowserIds.add(identity.browserId); ownLeases.set(identity.sessionId, { token, origin: participantOrigin });
    const ids = [...testIdentities.values()].map(row => row.peerId);
    await Promise.allSettled([...pages.values()].map(p => p.evaluate(ids => globalThis.meshFixtureSetAllowed?.(ids), ids)));
  });
  if (forceDirect) await page.addInitScript(() => { const Native = RTCPeerConnection; globalThis.RTCPeerConnection = class extends Native { constructor(config, constraints) { super({ ...config, iceServers: [], iceTransportPolicy: 'all' }, constraints); } }; });
  page.on('pageerror', error => report.errors.push({ browser: name, message: error.message }));
  await page.goto(participantOrigin, { waitUntil: 'domcontentloaded' });
  if (publicOrigin) {
    const remote = await page.evaluate(async paths => Object.fromEntries(await Promise.all(paths.map(async path => {
      const response = await fetch('/' + path.replace(/^public\//, '') + '?acceptance-hash=1', { cache: 'no-store' }); if (!response.ok) throw new Error('Remote module unavailable');
      const data = await response.arrayBuffer(); const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', data))].map(v => v.toString(16).padStart(2, '0')).join(''); return [path, digest];
    }))), coreFiles.filter(path => path.startsWith('public/')));
    for (const [path, hash] of Object.entries(remote)) assert.equal(hash, report.sourceHashes[path], `Deployed ${path} must match tested staged implementation`);
    report.remoteHashes = remote;
  }
  await page.evaluate(async ({ sourceId, forceTurn, allowedPeers }) => {
    const { MeshController } = await import('/mesh-controller.js');
    window.meshEvents = []; window.meshWire = { sent: [], received: [], receipts: [], dataFrames: 0, dataBytes: 0 }; window.mesh = new MeshController({ sourceId, maxCommonConnections: 1, iceTransportPolicy: forceTurn ? 'relay' : 'all' });
    let allowed = new Set(allowedPeers), assigned = [];
    const adopt = mesh.adoptPeers.bind(mesh), createPeer = mesh.createPeer.bind(mesh), receiveSignal = mesh.receiveSignal.bind(mesh);
    mesh.adoptPeers = function(peers, generation) { assigned = peers; return adopt(peers.filter(peer => allowed.has(peer.peerId)), generation); };
    mesh.createPeer = function(candidate, generation) { return allowed.has(candidate.peerId) ? createPeer(candidate, generation) : null; };
    mesh.receiveSignal = async function(message, generation) { if (allowed.has(message.from)) return receiveSignal(message, generation); };
    window.meshFixtureSetAllowed = ids => { allowed = new Set(ids); if (mesh.session) adopt(assigned.filter(peer => allowed.has(peer.peerId)), mesh.generation); };
    const pending = new Map(), post = mesh.post.bind(mesh), workerMessage = mesh.workerMessage.bind(mesh);
    mesh.workerMessage = function(message, generation) {
      if (message.type === 'send' && message.transport === 'peer') {
        const value = JSON.parse(message.text);
        if (value.type === 'FRAME' && value.frame.type === 'data') pending.set(message.sendId, value);
      }
      return workerMessage(message, generation);
    };
    mesh.post = function(message, transfer) {
      if (message.type === 'init') void meshFixtureIdentity({ ...message.identity, token: mesh.session.token }).catch(() => {});
      if (message.type === 'sent' && pending.has(message.sendId)) {
        const value = pending.get(message.sendId); pending.delete(message.sendId);
        if (message.ok) { meshWire.dataFrames++; meshWire.dataBytes += new TextEncoder().encode(JSON.stringify(value)).length; if (meshWire.sent.length < 16) meshWire.sent.push(value); }
      }
      if (message.type === 'message' && meshWire.received.length < 16) {
        const value = JSON.parse(new TextDecoder().decode(message.buffer));
        if (value.type === 'FRAME' && value.frame.type === 'data') meshWire.received.push(value);
      }
      return post(message, transfer);
    };
    window.meshHeartbeat = { count: 0, maxLagMs: 0, totalLagMs: 0 }; let last = performance.now();
    setInterval(() => { const now = performance.now(), lag = Math.max(0, now - last - 100); last = now; meshHeartbeat.count++; meshHeartbeat.maxLagMs = Math.max(meshHeartbeat.maxLagMs, lag); meshHeartbeat.totalLagMs += lag; }, 100);
    mesh.addEventListener('event', event => {
      meshEvents.push(event.detail); if (meshEvents.length > 512) meshEvents.shift();
      if (event.detail.name === 'acknowledged' && meshWire.receipts.length < 32) meshWire.receipts.push(event.detail);
      void meshEvidenceEvent(event.detail).catch(() => {});
    });
    mesh.addEventListener('state', event => { if (event.detail.state === 'ERROR') meshEvents.push({ name: 'controller-error', message: event.detail.reason }); });
    await mesh.start();
  }, { sourceId, forceTurn, allowedPeers: [...testIdentities.values()].map(row => row.peerId) });
  return page;
}
const state = name => pages.get(name).evaluate(() => mesh.snapshot());
const fresh = name => pages.get(name).evaluate(async () => (await mesh.inspect()).stats);
const ownPeer = peer => peer.network.transport === 'browser-mesh' && peer.network.browserMesh.relayIds.length >= 2 && peer.network.browserMesh.relayIds.every(id => ownedBrowserIds.has(id));
const ownRoute = route => route.relayIds.some(id => ownedBrowserIds.has(id));
const authenticatedWithData = row => row.nodes.b.peers.some(peer => ownPeer(peer) && peer.network.browserMesh.bytesReceived > 0 && peer.network.browserMesh.bytesSent > 0);
async function waitFor(label, predicate, timeout = 90000, interval = 300) {
  const start = Date.now(); let last;
  while (Date.now() - start < timeout) {
    last = await predicate(); if (last) return last;
    await sleep(interval);
  }
  for (const [name, page] of pages) report[name] = await page.evaluate(async () => ({ stats: mesh.snapshot(), evidence: await mesh.inspect(), events: meshEvents })).catch(e => ({ error: e.message }));
  await save(); throw new Error(`${label} timed out after ${timeout}ms`);
}
async function byteProof(left, right, forbiddenCircuit = null) {
  const rawProof = await waitFor(`${left}/${right} independent exact encrypted chunk and receipt proof`, async () => {
    const a = await pages.get(left).evaluate(() => meshWire), b = await pages.get(right).evaluate(() => meshWire);
    for (const [senderName, receiverName, sender, receiver] of [[left, right, a, b], [right, left, b, a]]) for (const sent of sender.sent) {
      if (sent.frame.circuitId === forbiddenCircuit) continue;
      const received = receiver.received.find(row => row.receipt.requestId === sent.receipt.requestId);
      const receipt = sender.receipts.find(row => row.requestId === sent.receipt.requestId);
      if (received && receipt) return { sender: senderName, receiver: receiverName, sent, received, receipt };
    }
    return null;
  }, 20000);
  assert.equal(rawProof.sent.frame.data, rawProof.received.frame.data);
  assert.equal(rawProof.sent.fromSessionId, rawProof.received.fromSessionId);
  assert.equal(rawProof.sent.toSessionId, rawProof.received.toSessionId);
  const rawBytes = Buffer.from(rawProof.received.frame.data, 'base64');
  assert.equal(createHash('sha256').update(rawBytes).digest('hex'), rawProof.receipt.digest);
  assert.equal(rawBytes.length, rawProof.receipt.rawBytes);
  return rawProof;
}
async function resetWireSamples(name) {
  // Clear bounded observer samples only. This neither changes relay state nor injects bytes.
  await pages.get(name).evaluate(() => { meshWire.sent = []; meshWire.received = []; meshWire.receipts = []; });
}
try {
  report.before = await native(); await save();
  await spawn('A', 'common-a'); await spawn('B', 'common-b');
  await waitFor('A/B native sockets and RTC', async () => { const a = await state('A'), b = await state('B'); return a.nativeConnected && b.nativeConnected && a.peers.some(p => p.connected) && b.peers.some(p => p.connected); });
  await checkpoint('A/B are independent real browser processes with connected native WSS and RTC', { A: await state('A'), B: await state('B') });
  const initial = await waitFor('isolated B authenticated native RLPx peer', async () => { const r = await native(); return authenticatedWithData(r) ? r : null; }, 120000, 100);
  report.nativeEvidence.push({ stage: 'A-B', ...initial });
  await waitFor('browser hop receipt', async () => (await state('A')).acknowledgedCount > 0 || (await state('B')).acknowledgedCount > 0, 20000);
  assert.notEqual(report.processes.A.browserPid, report.processes.B.browserPid);
  report.rawProof = await byteProof('A', 'B');
  if (discoveryGateways) {
    const observations = {};
    for (const name of ['A', 'B']) observations[name] = await pages.get(name).evaluate(() => ({
      origin: location.origin, localSources: mesh.config.nodes.map(n => n.id),
      rendezvous: [...mesh.discovery.sockets.values()].filter(row => row.ready).map(row => row.origin),
      verifiedAdvertisements: meshEvents.filter(row => row.name === 'advertisement' && row.browserSignatureVerified).map(row => row.nodeId),
      directCommons: mesh.snapshot().commonConnections.map(row => row.sourceId) }));
    assert.notEqual(observations.A.origin, observations.B.origin);
    assert.deepEqual(observations.A.localSources, ['common-a']); assert.deepEqual(observations.B.localSources, ['common-b']);
    for (const row of Object.values(observations)) { assert(row.rendezvous.length >= 1); assert.equal(row.directCommons.length, 1); assert(new Set(row.verifiedAdvertisements).size >= 2); }
    report.discoveryProof = observations;
    await checkpoint('Different gateway origins introduce browsers with disjoint local Common lists; both Workers verify the previously unlisted Common signature', observations);
  }
  if (expectedCapacity) {
    for (const name of ['A', 'B']) {
      const row = await fresh(name);
      assert.equal(row.capacities.hardCircuits, expectedCapacity);
      assert.equal(row.capacities.endpointCircuits, expectedCapacity);
      assert.equal(row.capacities.common.circuits, expectedCapacity);
      assert.equal(row.capacities.common.maxSessions, 80);
      assert.equal(row.capacities.peers, 20);
      assert(row.connectedPeers <= 20);
    }
    await checkpoint('Actual browser Workers apply the discovered Common40 circuit capacity with twenty-peer capacity and a single Common attachment for path isolation', { A: (await fresh('A')).capacities, B: (await fresh('B')).capacities });
  }
  if (forceTurn || forceDirect) await waitFor('required RTC candidate selected at both browser endpoints', async () => {
    for (const name of ['A', 'B']) await pages.get(name).evaluate(() => mesh.collectRTC(mesh.generation));
    const path = forceTurn ? 'TURN' : 'direct';
    return (await state('A')).peers.some(p => p.connected && p.path === path) && (await state('B')).peers.some(p => p.connected && p.path === path);
  }, 20000);
  await checkpoint('B has only browser-mesh native peer with actual RLPx traffic and separate browser ACKs', { BHead: initial.nodes.b.head, BMesh: initial.nodes.b.meshStatus });
  report.A = await pages.get('A').evaluate(async () => ({ stats: mesh.snapshot(), evidence: await mesh.inspect() }));
  await pages.get('A').evaluate(() => mesh.stop());
  await waitFor('A OFF removes only this test native circuit', async () => { const r = await native(); return !r.nodes.b.peers.some(ownPeer) && !r.nodes.b.meshStatus.routes.some(ownRoute) ? r : null; }, 25000, 500);
  await waitFor('B worker ingress and outgoing queues drain after RTC departure', async () => { const r = await pages.get('B').evaluate(async () => (await mesh.inspect()).stats); return r.connectedPeers === 0 && r.circuits === 0 && r.queuedBytes === 0; }, 15000);
  const drained = await pages.get('B').evaluate(async () => (await mesh.inspect()).stats); await sleep(3500); const stopped = await pages.get('B').evaluate(async () => (await mesh.inspect()).stats);
  assert.equal(stopped.receivedBytes, drained.receivedBytes, 'No new RTC message bytes after A is OFF and existing queues drain');
  assert.equal(stopped.streamForwardedBytes, drained.streamForwardedBytes, 'No new stream forwarded from the departed hop');
  const aOff = await state('A'); assert.equal(aOff.requested, false); assert.equal(aOff.circuits, 0); assert.equal(aOff.queuedBytes, 0);
  await checkpoint('A OFF stops the only RTC path after draining, without a gateway-only fallback', { BBefore: drained, BAfter: stopped });
  await resetWireSamples('B');
  await spawn('C', 'common-a');
  const alternative = await waitFor('new C path authenticates native B', async () => { const r = await native(); return authenticatedWithData(r) ? r : null; }, 120000, 500);
  report.nativeEvidence.push({ stage: 'C-B', ...alternative });
  await waitFor('C forwards and receives hop ACK', async () => (await state('C')).acknowledgedCount > 0, 30000);
  const firstCircuit = initial.nodes.b.peers.find(ownPeer).network.browserMesh.circuitId;
  assert.notEqual(alternative.nodes.b.peers.find(ownPeer).network.browserMesh.circuitId, firstCircuit, 'Replacement route must authenticate a new native circuit');
  report.alternativeRawProof = await byteProof('C', 'B', firstCircuit);
  await checkpoint('B reconnected through newly joined C and fresh native RLPx circuit', { beforePeers: initial.nodes.b.peers, afterPeers: alternative.nodes.b.peers, C: await state('C'), B: await state('B') });
  const progress = await waitFor('isolated B receives real blocks or is already near the current Common head', async () => {
    const r = await native(); return r.nodes.b.head > report.before.nodes.b.head || r.nodes.b.head >= r.nodes.a.head - 1 ? r : null;
  }, Number(process.env.MESH_SYNC_WAIT_MS || 600000), 3000);
  report.nativeEvidence.push({ stage: 'progress-through-C', ...progress });
  await checkpoint('Native canonical hashes match A/B/reference while C is the only browser route', { hashes: progress.hashes, BHead: progress.nodes.b.head,
    progressSinceStart: progress.nodes.b.head - report.before.nodes.b.head, nearTip: progress.nodes.b.head >= progress.nodes.a.head - 1 });
  if (workload) {
    const before = await state('B');
    for (const busy of ['loading', 'benchmarking']) {
      await pages.get('B').evaluate(state => mesh.setAiLoad(state), busy);
      await waitFor(`AI ${busy} closes endpoint circuits`, async () => { const row = await fresh('B'); return row.paused && row.circuits === 0; }, 10000);
      await sleep(3000); const row = await state('B'); assert(row.signalConnected && row.nativeConnected && row.requested);
      await pages.get('B').evaluate(() => mesh.setAiLoad('idle'));
      await waitFor('native RLPx reconnects after AI pause', async () => authenticatedWithData(await native()), 90000, 1000);
    }
    const performanceCDP = await participants.get('B').context.newCDPSession(pages.get('B')); await performanceCDP.send('Performance.enable');
    const taskSeconds = async () => (await performanceCDP.send('Performance.getMetrics')).metrics.find(m => m.name === 'TaskDuration')?.value || 0;
    const startingCPU = await taskSeconds(), startingBytes = await fresh('B'), beganWork = Date.now();
    await pages.get('B').evaluate(() => mesh.setAiLoad('generating')); await sleep(8000);
    const endingBytes = await fresh('B'), endingCPU = await taskSeconds();
    assert.equal(endingBytes.aiLoad, 'generating'); assert(endingBytes.circuits <= 1);
    const actualJSONSent = endingBytes.sentBytes + endingBytes.nativeSentBytes - startingBytes.sentBytes - startingBytes.nativeSentBytes;
    assert(actualJSONSent <= 16384 + 24576 * (Date.now() - beganWork) / 1000);
    assert((await state('B')).signalConnected); await pages.get('B').evaluate(() => mesh.setAiLoad('idle'));
    await checkpoint('AI workload signals preserve control sessions and enforce close/pause/one-circuit policy', {
      actualLLMRun: false, generatingMs: Date.now() - beganWork, actualJSONSent, mainThreadTaskSeconds: endingCPU - startingCPU,
      heartbeat: await pages.get('B').evaluate(() => meshHeartbeat), sameSessionAcrossPolicy: (await state('B')).sessionId === before.sessionId });
  }
  if (readmission) {
    const before = await state('B');
    await pages.get('B').evaluate(() => mesh.native.close(4000, 'acceptance-native-close'));
    await waitFor('native transport close obtains fresh app/browser/native generations', async () => {
      const row = await state('B'); return row.nativeConnected && row.sessionId !== before.sessionId && row.browserId !== before.browserId && row.nativeSession !== before.nativeSession;
    }, 90000);
    const next = await state('B'); assert(next.totalBytes >= before.totalBytes, 'ON participation bytes cannot reset on native readmission');
    await waitFor('fresh attachment authenticates native RLPx', async () => { const row = await native(); return authenticatedWithData(row) ? row : null; }, 90000, 1000);
    await checkpoint('Native WSS loss creates fresh identities and preserves ON byte budget before re-authentication', { beforeSession: before.sessionId, afterSession: next.sessionId, beforeNativeSession: before.nativeSession, afterNativeSession: next.nativeSession, beforeBytes: before.totalBytes, afterBytes: next.totalBytes });
  }
  const startRecoveryAt = Date.now(); let startObservations = 0, startTransientObservations = 0;
  const startNative = await waitFor('authenticated native circuit carrying bytes before soak', async () => {
    const row = await native(); startObservations++;
    if (authenticatedWithData(row)) return row;
    startTransientObservations++; return null;
  }, 120000, 500);
  report.soakStartRecovery = { waitedMs: Date.now() - startRecoveryAt, observations: startObservations, transientObservations: startTransientObservations, timeoutMs: 120000 };
  const startCircuit = startNative.nodes.b.peers.find(peer => ownPeer(peer) && peer.network.browserMesh.bytesReceived > 0 && peer.network.browserMesh.bytesSent > 0)?.network.browserMesh.circuitId;
  assert(startCircuit); report.startCircuit = startCircuit;
  report.nativeEvidence.push({ stage: 'soak-start', ...startNative });
  const began = Date.now(); report.soakStartedAt = new Date().toISOString(); await save(); console.log('SOAK_STARTED', report.soakStartedAt, 'duration_ms=' + soakMs);
  while (Date.now() - began < soakMs) {
    const B = await state('B'), C = await state('C');
    assert(B.requested && C.requested, 'Mesh must remain manually joined during soak');
    for (const row of [B, C]) { assert(row.appBytes <= 4194304); assert(row.queuedBytes <= 524288); assert(row.totalBytes < 104857600); assert(row.peers.length <= 20); }
    report.samples.push({ at: new Date().toISOString(), elapsedMs: Date.now() - began, B, C });
    if (report.samples.length % 3 === 0) {
      const evidence = await native(); report.nativeEvidence.push({ stage: 'soak', ...evidence });
      for (const peer of evidence.nodes.b.peers.filter(ownPeer)) {
        const route = peer.network.browserMesh;
        report.nativeCircuitHistory.push({ at: evidence.utc, circuitId: route.circuitId, bytesReceived: route.bytesReceived, bytesSent: route.bytesSent, BHead: evidence.nodes.b.head });
      }
    }
    await save(); await sleep(Math.min(10000, Math.max(1, soakMs - (Date.now() - began))));
  }
  report.soakElapsedMs = Date.now() - began;
  if (process.env.MESH_REQUIRE_RENEWAL === '1') {
    assert(soakMs >= 130000, 'Renewal acceptance needs at least130 seconds of observation');
    report.observedLeaseRenewals = {};
    for (const name of ['B', 'C']) {
      const events = allEvents.filter(row => row.browser === name && row.name === 'session-renewed' && (row.observedAt ?? row.at) >= began);
      const groups = new Map();
      for (const sample of report.samples) {
        const state = sample[name];
        if (!state.sessionId || !Number.isFinite(state.sessionExpiresAt)) continue;
        const rows = groups.get(state.sessionId) || []; rows.push(state.sessionExpiresAt); groups.set(state.sessionId, rows);
      }
      const advanced = [...groups.entries()].filter(([, values]) => Math.max(...values) > Math.min(...values));
      assert(events.length > 0, `${name} must actually complete a gateway lease renewal`);
      assert(advanced.length > 0, `${name} same-session expiry must actually advance`);
      report.observedLeaseRenewals[name] = { events: events.length, sessionsWithAdvancedExpiry: advanced.map(([sessionId, values]) => ({ sessionId, first: Math.min(...values), last: Math.max(...values) })) };
    }
    await checkpoint('Both browser leases renewed during measured soak with same-session expiry advancing', report.observedLeaseRenewals);
  }
  const finalRecoveryAt = Date.now(); let finalObservations = 0, finalTransientObservations = 0;
  report.finalNative = await waitFor('authenticated native circuit carrying bytes at soak completion', async () => {
    const row = await native(); finalObservations++;
    if (authenticatedWithData(row)) return row;
    finalTransientObservations++; return null;
  }, 120000, 500);
  report.soakEndRecovery = { waitedMs: Date.now() - finalRecoveryAt, observations: finalObservations, transientObservations: finalTransientObservations, timeoutMs: 120000 };
  report.headProgress = { before: report.before.nodes.b.head, after: report.finalNative.nodes.b.head, nearTip: report.finalNative.nodes.b.head >= report.finalNative.nodes.a.head - 1 };
  if (soakMs >= 1860000) {
    report.circuitLifecycle = classifyCircuitLifecycle(startCircuit, report.nativeCircuitHistory, allEvents);
    if (process.env.MESH_REQUIRE_NATURAL_TTL === '1') assert.equal(report.circuitLifecycle.naturalTTL.status, 'OBSERVED',
      'An exact circuit-expired event must precede replacement native authentication and bidirectional bytes');
    const renewals = Object.fromEntries(['B', 'C'].map(name => [name, allEvents.filter(row => row.browser === name && row.name === 'session-renewed').length]));
    report.leaseContinuity = Object.fromEntries(['B', 'C'].map(name => [name, leaseEvidence(report.samples, name)]));
    for (const name of ['B', 'C']) {
      assert(renewals[name] > 0, 'Both participants actually renew leases');
      assert(report.leaseContinuity[name].unexpiredReportedLeases, 'Active transport samples report unexpired leases, including fresh admissions');
    }
    report.renewals = renewals;
    await checkpoint('More than 30 minutes of actual mesh includes lease renewal; circuit recovery and natural expiry are classified separately',
      { elapsedMs: report.soakElapsedMs, circuitLifecycle: report.circuitLifecycle, renewals });
  }
  for (const [name, page] of pages) {
    report[name] = { ...(report[name] || {}), final: await page.evaluate(async () => ({ stats: mesh.snapshot(), evidence: await mesh.inspect(), events: meshEvents })) };
  }
  let finalRouteName = 'C';
  if (abrupt) {
    const prior = await native(), priorCircuit = prior.nodes.b.peers.find(ownPeer)?.network.browserMesh.circuitId;
    const c = participants.get('C'); assert(c.child?.pid, 'Abrupt test owns a standalone Chromium process');
    const killedPID = c.child.pid, beganKill = Date.now(); c.child.kill('SIGKILL');
    await waitFor('abrupt browser death reclaims native routes and surviving Worker queues', async () => {
      const n = await native(), b = await fresh('B');
      return !n.nodes.b.peers.some(ownPeer) && !n.nodes.b.meshStatus.routes.some(ownRoute) && b.connectedPeers === 0 && b.circuits === 0 && b.queuedBytes === 0;
    }, 30000, 500);
    const after = await fresh('B'); await sleep(2000); const stable = await fresh('B');
    assert.equal(stable.streamForwardedBytes, after.streamForwardedBytes);
    assert.equal(stable.receivedBytes, after.receivedBytes);
    await checkpoint('SIGKILL of owned C browser reclaims native route and surviving B queue without stale transfer', { killedPID, reclaimedMs: Date.now() - beganKill, B: stable });
    await resetWireSamples('B'); await spawn('D', 'common-a'); finalRouteName = 'D';
    const replacement = await waitFor('fresh browser after sudden death authenticates new native circuit', async () => { const n = await native(); return authenticatedWithData(n) ? n : null; }, 120000, 500);
    assert.notEqual(replacement.nodes.b.peers.find(ownPeer).network.browserMesh.circuitId, priorCircuit);
    report.abruptReplacementRawProof = await byteProof('D', 'B', priorCircuit);
    report.nativeEvidence.push({ stage: 'D-B-after-abrupt-C', ...replacement });
    await checkpoint('New D browser reconnects after abrupt C death with fresh native authentication and exact bytes/digest/ACK');
  }
  if (lifecycle) {
    const b = participants.get('B'), c = participants.get(finalRouteName), cdp = await b.context.newCDPSession(b.page);
    await b.page.evaluate(() => { window.meshLifecycle = []; for (const type of ['visibilitychange', 'freeze', 'resume']) document.addEventListener(type, event => meshLifecycle.push({ type, trusted: event.isTrusted, visibility: document.visibilityState })); });
    const foreground = await b.context.newPage(); await foreground.bringToFront();
    await waitFor('actual mobile viewport page hidden', () => b.page.evaluate(() => document.visibilityState === 'hidden'), 5000);
    await cdp.send('Page.setWebLifecycleState', { state: 'frozen' }); await sleep(300); await cdp.send('Page.setWebLifecycleState', { state: 'active' }); await b.page.bringToFront();
    await waitFor('native lifecycle leaves participation OFF', async () => !(await state('B')).requested, 5000); await sleep(1000);
    const events = await b.page.evaluate(() => meshLifecycle); assert(events.some(row => row.type === 'visibilitychange' && row.trusted && row.visibility === 'hidden')); assert(events.some(row => row.type === 'freeze' && row.trusted));
    assert.equal((await state('B')).state, 'OFF'); assert.equal((await state('B')).circuits, 0); assert.equal((await state('B')).appBytes, 0);
    report.lifecycle = { events, autoRejoined: false, mobileViewport: true, actualPhoneHardware: false };
    await c.page.goto('about:blank'); assert.equal(c.page.workers().length, 0);
    await checkpoint('Trusted tab hide/freeze stops participation; resume stays OFF and navigation terminates the last Worker', report.lifecycle);
  } else for (const page of pages.values()) if (!page.isClosed()) await page.evaluate(() => mesh.stop());
  const cleaned = await waitFor('all test-owned native routes and native peers reclaimed', async () => {
    const row = await native(); return !row.nodes.a.meshStatus.routes.some(ownRoute) && !row.nodes.b.meshStatus.routes.some(ownRoute) && !row.nodes.b.peers.some(ownPeer) ? row : null;
  }, 15000, 500);
  report.cleanup = cleaned; if (gateway) assert.equal(gateway.stats().sessions, 0); for (const server of discoveryServers) assert.equal(server.stats().sessions, 0);
  // These are only bearer tokens issued to this runner. No external participant
  // is deleted, disconnected, inspected or counted as a test browser.
  report.ownLeaseCleanup = [];
  for (const [sessionId, lease] of ownLeases) {
    const status = await pages.get('B').evaluate(async ({ token, origin }) => (await fetch(origin + '/relay/v1/mesh/status', { credentials: 'omit', headers: { Authorization: `Bearer ${token}` } })).status, lease);
    assert.equal(status, 401, 'Only the runner-owned lease must be gone'); report.ownLeaseCleanup.push({ sessionId, status });
  }
  report.testIsolation = { allowedPeerIds: [...testIdentities.values()].map(row => row.peerId), allOwnedBrowserIds: [...ownedBrowserIds], unownedLeasesRevoked: 0, globalSessionZeroRequired: false };
  report.finalHashes = await fileHashes(); report.changedCoreFiles = coreFiles.filter(path => report.finalHashes[path] !== report.sourceHashes[path]);
  assert.deepEqual(report.changedCoreFiles, [], 'Core implementation must remain unchanged throughout final acceptance');
  await writeFile(output.replace(/\.json$/, '-events.json'), JSON.stringify(allEvents, null, 2));
  assert.equal(report.errors.length, 0); report.status = 'PASS'; report.finishedAt = new Date().toISOString(); await save(); console.log('PASS actual Common WebRTC mesh', output);
} catch (error) {
  report.status = 'FAIL'; report.error = error.stack;
  for (const [name, page] of pages) report[name] = await page.evaluate(async () => ({ stats: mesh.snapshot(), evidence: await mesh.inspect(), events: meshEvents })).catch(e => ({ error: e.message }));
  await save(); console.error(error.stack); process.exitCode = 1;
} finally {
  const cleanup = report.resourceCleanup = { attempts: [], browsers: [], children: [], profiles: [], errors: [] };
  async function attempt(resource, fn, timeoutMs = 15000) {
    let timer;
    try {
      await Promise.race([fn(), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Cleanup timed out')), timeoutMs); })]);
      cleanup.attempts.push({ resource, ok: true }); return true;
    } catch (error) { cleanup.attempts.push({ resource, ok: false, error: error.message }); return false; }
    finally { clearTimeout(timer); }
  }
  await attempt('event evidence', () => writeFile(output.replace(/\.json$/, '-events.json'), JSON.stringify(allEvents, null, 2)));
  await Promise.allSettled(browsers.map((browser, index) => attempt('browser-' + index, () => browser.close())));
  for (const child of ownedChildren) {
    const running = () => child.exitCode === null && child.signalCode === null;
    if (running()) { try { child.kill('SIGTERM'); } catch (error) { cleanup.errors.push({ resource: 'child-' + child.pid, error: error.message }); } }
    const deadline = Date.now() + 3000; while (running() && Date.now() < deadline) await sleep(50);
    if (running()) { try { child.kill('SIGKILL'); } catch (error) { cleanup.errors.push({ resource: 'child-' + child.pid, error: error.message }); } }
    const finalDeadline = Date.now() + 3000; while (running() && Date.now() < finalDeadline) await sleep(50);
    cleanup.children.push({ pid: child.pid, exited: !running(), exitCode: child.exitCode, signalCode: child.signalCode });
  }
  for (const profile of ownedProfiles) {
    await attempt('profile ' + profile, () => rm(profile, { recursive: true, force: true }));
    cleanup.profiles.push({ path: profile, removed: !(await lstat(profile).catch(() => null)) });
  }
  if (gateway) await attempt('local gateway', () => gateway.close());
  for (const [index, server] of discoveryServers.entries()) await attempt('discovery gateway-' + index, () => server.close());
  if (tlsFixture) await attempt('TLS fixture', () => tlsFixture.close());
  for (const [name, process] of Object.entries(report.processes)) cleanup.browsers.push({ name, pid: process.browserPid,
    exited: !!process.browserPid && !(await lstat('/proc/' + process.browserPid).catch(() => null)) });
  cleanup.complete = cleanup.children.every(row => row.exited) && cleanup.profiles.every(row => row.removed) && cleanup.browsers.every(row => row.exited)
    && cleanup.attempts.every(row => row.ok || row.resource.startsWith('browser-')) && cleanup.errors.length === 0;
  // A disconnected CDP client may throw on close after intentional SIGKILL.
  // Final owned PID/profile state is authoritative; retain that close error
  // without skipping any later cleanup or overwriting the original test error.
  if (!cleanup.complete) { report.status = 'FAIL'; process.exitCode = 1; report.cleanupError = 'Some owned resources or cleanup evidence remain incomplete'; }
  report.cleanupFinishedAt = new Date().toISOString(); await save();
}
