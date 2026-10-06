#!/usr/bin/env node
// Independent Chromium, real TLS gateways, WSS and WebRTC. Native endpoints are
// explicit signed protocol fixtures; this is not a native RLPx/chain-sync test.
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFile, writeFile, mkdtemp, rm } from 'node:fs/promises';
import { resolve, extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, createHash } from 'node:crypto';
import { WebSocketServer } from 'ws';
import { createGateway } from '../relay/gateway.mjs';
import { createBrowserIdentity, publicKeyNodeId, DISCOVERY_DOMAINS } from '../public/mesh-discovery.js';
import { secp256k1, keccak_256 } from '../public/vendor/mesh-crypto.js';
import { createMeshTLSFixture } from './mesh-tls-fixture.mjs';

const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || '/tmp/browser-llm-preview/node_modules/playwright/index.mjs');
const root = fileURLToPath(new URL('../', import.meta.url)), BASE = '/relay/v1/mesh', PROTOCOL = 'cypher-browser-mesh/1';
const output = process.env.MESH_DISCOVERY_REPORT || resolve(root, 'evidence/discovery-browser-report.json');
const scale = process.env.MESH_DISCOVERY_SCALE === '1';
const tmp = await mkdtemp('/tmp/cypher-discovery-browser-'), network = { chainId: 10101919, genesisHash: '0x' + '11'.repeat(32) };
const browsers = [], nativeFixtures = [], gateways = [], timers = new Set(), pages = new Map();
const report = { status: 'RUNNING', startedAt: new Date().toISOString(), sameHostOnly: true, nativeFixture: true, nativeRLPx: false, webRTC: true, physicalMobile: false, checkpoints: [], errors: [], participants: {} };
const sleep = ms => new Promise(r => setTimeout(r, ms));
const opaque = () => randomBytes(16).toString('hex');
const sha = raw => createHash('sha256').update(raw).digest('hex');
const files = ['public/mesh-controller.js', 'public/mesh-discovery-client.js', 'public/mesh-discovery.js', 'public/mesh-worker.js', 'public/mesh-protocol.js', 'relay/gateway.mjs', 'relay/discovery.mjs'];
const hashes = async () => Object.fromEntries(await Promise.all(files.map(async file => [file, sha(await readFile(resolve(root, file)))])));
const save = () => writeFile(output, JSON.stringify(report, null, 2));
async function checkpoint(name, details = {}) { report.checkpoints.push({ name, at: new Date().toISOString(), ...details }); await save(); console.log('PASS', name); }
async function until(check, label, ms = 45000) { const until = Date.now() + ms; while (Date.now() < until) { const value = await check(); if (value) return value; await sleep(200); } throw new Error('Timed out: ' + label); }
function signed(identity, domain, payload) {
  const raw = Buffer.from(JSON.stringify(payload)), input = Buffer.concat([Buffer.from(domain), raw]);
  const sig = secp256k1.sign(keccak_256(input), identity.privateKey, { prehash: false, format: 'recovered', lowS: true });
  return { payloadBase64: raw.toString('base64'), signatureHex: Buffer.from(sig.subarray(1)).toString('hex') + sig[0].toString(16).padStart(2, '0') };
}
let tls;
try {
  report.sourceHashes = await hashes();
  tls = await createMeshTLSFixture({ root });
  const { origins } = tls; report.origins = origins;
  for (let index = 0; index < 2; index++) {
    const identity = createBrowserIdentity(), bootId = opaque(), enode = `enode://${identity.publicKeyHex}@127.0.0.1:${30445 + index}?discport=0`;
    const node = { id: `common-${index === 0 ? 'a' : 'b'}`, nodeId: publicKeyNodeId(identity.publicKeyHex), enode, socketPath: join(tmp, `native-${index}.sock`) };
    const sessions = new Map(), circuits = new Map(), received = [], sent = [], advertisements = new Map(); let sequence = 0, endpointSequence = 0;
    const ad = () => { const now = Date.now(); return signed(identity, DISCOVERY_DOMAINS.advertisement, { version: 1, network, enode, bootId, issuedAt: now, expiresAt: now + 120000 }); };
    const endpoint = () => { const now = Date.now(); return signed(identity, DISCOVERY_DOMAINS.endpoint, { version: 1, network, enode, sourceId: node.id, gatewayOrigin: origins[index], bootId, sequence: ++endpointSequence, issuedAt: now, expiresAt: now + 120000 }); };
    const server = http.createServer(async (req, res) => {
      if (req.headers.origin !== origins[index]) { res.writeHead(403); res.end(); return; }
      res.setHeader('Content-Type', 'application/json');
      if (req.url === BASE + '/config') { res.end(JSON.stringify({ version: 1, sessionSeconds: 300, renewAfterSeconds: 120, maxSessions: 80, maxFrameBytes: 16384, nativeMaxFrameBytes: 4194304, nativePeers: 40, initialState: 'OFF' })); return; }
      if (req.url === BASE + '/endpoint') { res.end(JSON.stringify(endpoint())); return; }
      if (req.url === BASE + '/sessions' && req.method === 'POST') {
        for await (const chunk of req) {};
        const token = randomBytes(32).toString('hex'), session = { token, browserId: opaque(), expiresAt: Date.now() + 300000 }; sessions.set(token, session);
        res.writeHead(201); res.end(JSON.stringify(session)); return;
      }
      if (req.url === BASE + '/status') { res.end(JSON.stringify({ running: true, sessions: sessions.size, circuits: circuits.size, candidates: advertisements.size, receivedBytes: received.reduce((n, row) => n + row.bytes, 0), sentBytes: sent.reduce((n, row) => n + row.bytes, 0), routes: [] })); return; }
      const token = req.headers.authorization?.slice(7), session = sessions.get(token);
      if (!session) { res.writeHead(401); res.end(); return; }
      if (req.url === BASE + '/renew' && req.method === 'POST') { session.expiresAt = Date.now() + 300000; res.end(JSON.stringify({ expiresAt: session.expiresAt })); return; }
      if (req.url === BASE + '/sessions' && req.method === 'DELETE') { sessions.delete(token); session.ws?.close(); res.writeHead(204); res.end(); return; }
      res.writeHead(404); res.end();
    });
    const wss = new WebSocketServer({ noServer: true, maxPayload: 16384 });
    server.on('upgrade', (req, socket, head) => { if (req.url !== BASE + '/connect' || req.headers.origin !== origins[index]) { socket.destroy(); return; } wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws)); });
    const send = (session, frame) => { if (session.ws?.readyState === 1) session.ws.send(JSON.stringify({ ...frame, session: session.nativeSession })); };
    function begin(session, value) {
      if (index !== 0 || [...circuits.values()].some(c => c.session === session)) return;
      const remote = JSON.parse(Buffer.from(value.advertisement.payloadBase64, 'base64').toString());
      if (remote.enode === enode) return;
      const circuitId = opaque(); circuits.set(circuitId, { session, seq: 0, opened: false });
      send(session, { type: 'open', circuitId, target: publicKeyNodeId(remote.enode.slice(8, 136)), advertisement: ad(), route: [...value.route].reverse() });
    }
    wss.on('connection', ws => {
      let session; ws.on('error', () => {});
      ws.on('message', data => {
        try {
          const value = JSON.parse(data);
          if (!session) {
            session = sessions.get(value.token); if (!session || session.ws) { ws.close(1008); return; }
            session.ws = ws; session.nativeSession = opaque(); session.lastAdvert = Date.now(); send(session, { type: 'hello', browserId: session.browserId, protocol: PROTOCOL, advertisement: ad() }); return;
          }
          if (value.session !== session.nativeSession) throw new Error('wrong generation');
          if (value.type === 'advertisement') { advertisements.set(session.browserId, value); begin(session, value); }
          else if (value.type === 'open') { circuits.set(value.circuitId, { session, seq: 0, opened: true }); send(session, { type: 'opened', circuitId: value.circuitId }); }
          else if (value.type === 'opened') { const circuit = circuits.get(value.circuitId); if (circuit) circuit.opened = true; }
          else if (value.type === 'data') {
            const circuit = circuits.get(value.circuitId); assert(circuit && circuit.session === session); assert.equal(value.seq, circuit.seq + 1); circuit.seq = value.seq;
            const raw = Buffer.from(value.data, 'base64'); received.push({ circuitId: value.circuitId, seq: value.seq, bytes: raw.length, sha256: sha(raw), at: Date.now() });
            send(session, { type: 'credit', circuitId: value.circuitId, seq: value.seq, bytes: raw.length });
          } else if (value.type === 'close') circuits.delete(value.circuitId);
        } catch (error) { report.errors.push({ fixture: node.id, error: error.message }); ws.close(1008); }
      });
      ws.on('close', () => { if (!session) return; sessions.delete(session.token); advertisements.delete(session.browserId); for (const [id, c] of circuits) if (c.session === session) circuits.delete(id); });
    });
    const timer = setInterval(() => {
      for (const session of sessions.values()) if (session.ws?.readyState === 1 && Date.now() - session.lastAdvert >= 30000) { session.lastAdvert = Date.now(); send(session, { type: 'advertisement', advertisement: ad() }); }
      for (const [circuitId, c] of circuits) if (index === 0 && c.opened && c.session.ws?.readyState === 1) {
        const raw = Buffer.concat([Buffer.from(`opaque-fixture-stream-${++sequence}:`), randomBytes(700)]), seq = ++c.seq;
        send(c.session, { type: 'data', circuitId, seq, data: raw.toString('base64') }); sent.push({ circuitId, seq, bytes: raw.length, sha256: sha(raw), at: Date.now() });
      }
    }, 500); timers.add(timer);
    await new Promise(r => server.listen(node.socketPath, r));
    const fixture = { node, identity, server, wss, sessions, circuits, received, sent, endpoint }; nativeFixtures.push(fixture);
    const gateway = createGateway({ config: { enabled: true, origin: origins[index], nativeOrigin: origins[index], network, nodes: [node],
      limits: { maxSessions: scale ? 48 : 8, maxSessionsPerClient: scale ? 48 : 8, maxConnections: scale ? 112 : 32, httpBytesPerSecond: 1048576, maxPeers: 20, maxCommonConnections: 20 },
      discovery: { enabled: true, bootstrapOrigins: [origins[1 - index]], allowedOrigins: origins }, iceServers: [] } });
    await gateway.listen({ port: 0 }); gateways.push(gateway); tls.addGateway(index, gateway);
  }
  async function browser(name, origin, maxCommonConnections = 1) {
    const browser = await chromium.launch({ executablePath: process.env.CHROMIUM || '/tmp/browser-llm-browsers/chromium-1243/chrome-linux64/chrome', headless: true,
      args: ['--no-sandbox', '--no-proxy-server', `--host-resolver-rules=${tls.hostResolverRules}`],
      env: { ...process.env, XDG_CONFIG_HOME: join(tmp, 'chrome-config'), XDG_CACHE_HOME: join(tmp, 'chrome-cache') } });
    browsers.push(browser); const context = await browser.newContext({ ignoreHTTPSErrors: true }), page = await context.newPage(); pages.set(name, page);
    page.on('pageerror', error => report.errors.push({ browser: name, error: error.message }));
    const cdp = await browser.newBrowserCDPSession(), info = await cdp.send('SystemInfo.getProcessInfo');
    report.participants[name] = { pid: info.processInfo.find(row => row.type === 'browser')?.id, origin, maxCommonConnections };
    await page.goto(origin);
    await page.evaluate(async max => { const { MeshController } = await import('/mesh-controller.js'); window.mesh = new MeshController({ maxCommonConnections: max }); window.events = []; mesh.addEventListener('event', event => events.push(event.detail)); await mesh.start(); }, maxCommonConnections);
    return page;
  }
  const a = await browser('A', origins[0]), b = await browser('B', origins[1]);
  await until(async () => (await a.evaluate(() => mesh.snapshot().connectedPeers)) === 1 && (await b.evaluate(() => mesh.snapshot().connectedPeers)) === 1, 'cross-gateway RTC');
  await until(() => nativeFixtures[1].received.length >= 3, 'fixture bytes through actual RTC');
  await until(async () => (await a.evaluate(() => mesh.snapshot().acknowledgedCount)) >= 3, 'browser hop receipts');
  const delivered = nativeFixtures[1].received.slice();
  for (const row of delivered) assert(nativeFixtures[0].sent.some(sent => sent.circuitId === row.circuitId && sent.seq === row.seq && sent.sha256 === row.sha256 && sent.bytes === row.bytes));
  assert.notEqual(report.participants.A.pid, report.participants.B.pid);
  await checkpoint('Two separate gateways and browser processes establish signed discovery, WebRTC, exact fixture bytes and hop ACK', { delivered, a: await a.evaluate(() => mesh.snapshot()), b: await b.evaluate(() => mesh.snapshot()), nativeRLPx: false });
  const firstPeer = await a.evaluate(() => mesh.session.peerId); await a.evaluate(() => mesh.stop());
  await until(() => nativeFixtures[0].sessions.size === 0 && nativeFixtures[0].circuits.size === 0, 'A OFF cleanup'); await sleep(1500);
  const stopped = nativeFixtures[1].received.length; await sleep(1500); assert.equal(nativeFixtures[1].received.length, stopped);
  await checkpoint('A OFF stops new RTC stream and removes its native fixture lease', { stoppedFrames: stopped });
  const c = await browser('C', origins[0]);
  await until(() => nativeFixtures[1].received.length > stopped + 2, 'replacement peer RTC path');
  assert.notEqual(await c.evaluate(() => mesh.session.peerId), firstPeer);
  await checkpoint('New browser C automatically replaces departed A across gateways', { peerId: await c.evaluate(() => mesh.session.peerId), b: await b.evaluate(() => mesh.snapshot()) });
  await c.evaluate(() => mesh.stop()); await until(() => nativeFixtures[0].sessions.size === 0, 'C cleanup');
  const d = await browser('D', origins[0], 20);
  await until(async () => await d.evaluate(() => mesh.snapshot().nativeConnections === 2 && mesh.snapshot().commonConnections.some(c => c.remoteOrigin && c.connected && c.endpointVerified && c.browserSignatureVerified)), 'unknown remote Common signed descriptor attachment and Worker verification');
  const remote = await d.evaluate(() => ({ snapshot: mesh.snapshot(), controllerNodes: mesh.config.nodes.map(n => n.nodeId), worker: null, endpoints: mesh.discovery.endpoints().map(e => ({ nodeId: e.nodeId, origin: e.origin, bootId: e.payload.bootId })) }));
  assert.equal(remote.controllerNodes.length, 1); assert(remote.snapshot.commonConnections.some(row => row.nodeId === nativeFixtures[1].node.nodeId && row.connected));
  await checkpoint('Browser discovers unpinned remote Common, verifies descriptor and native hello, and opens its own foreign WSS lease', remote);
  await sleep(32000);
  assert.equal(await d.evaluate(() => mesh.discovery.sockets.size), 2);
  assert.equal(await d.evaluate(() => [...mesh.discovery.sockets.values()].every(s => s.ready && s.expiresAt > Date.now() + 80000)), true);
  await checkpoint('Signed browser records renew beyond the initial 30 second refresh interval', { rendezvous: await d.evaluate(() => [...mesh.discovery.sockets.values()].map(s => ({ origin: s.origin, expiresAt: s.expiresAt, lastRenew: s.lastRenew }))) });
  for (const page of pages.values()) await page.evaluate(() => mesh.stop()).catch(() => {});
  await until(() => nativeFixtures.every(f => f.sessions.size === 0 && f.circuits.size === 0) && gateways.every(g => g.stats().sessions === 0 && g.stats().discovery.visitors === 0), 'owned resources released');
  if (scale) {
    for (const browser of browsers) await browser.close().catch(() => {}); pages.clear();
    report.scale = { startedAt: new Date().toISOString(), independentBrowsers: 21, nativeFixture: true, samples: [] };
    for (let n = 0; n < 21; n++) { await browser('S' + n, origins[n % 2]); await sleep(1100); }
    await until(async () => {
      const counts = await Promise.all([...pages.values()].map(page => page.evaluate(() => ({ connected: mesh.snapshot().peers.filter(p => p.connected).length, known: mesh.candidates.size, native: mesh.snapshot().nativeConnections, requested: mesh.requested, state: mesh.state }))));
      assert(counts.every(c => c.connected <= 20 && c.known <= 20), 'Browser and introduction upper bounds stay at twenty');
      report.scale.samples.push({ at: Date.now(), counts }); if (report.scale.samples.length > 30) report.scale.samples.shift();
      return counts.every(c => c.connected === 20 && c.native === 1 && c.requested);
    }, 'twenty actual RTC neighbors for every browser including late entrant', 240000);
    assert.equal(new Set(Object.entries(report.participants).filter(([name]) => name.startsWith('S')).map(([, p]) => p.pid)).size, 21);
    report.scale.finishedAt = new Date().toISOString();
    await checkpoint('Twenty-one independent browsers use signed cross-gateway discovery with twenty actual RTC neighbors each', { scale: report.scale });
    for (const page of pages.values()) await page.evaluate(() => mesh.stop()).catch(() => {});
    await until(() => nativeFixtures.every(f => f.sessions.size === 0 && f.circuits.size === 0) && gateways.every(g => g.stats().sessions === 0 && g.stats().discovery.visitors === 0), 'scale resources released');
  }
  const after = await hashes(); assert.deepEqual(after, report.sourceHashes); report.sourceHashesAfter = after;
  assert.equal(report.errors.length, 0); await checkpoint('OFF removes all owned gateway and fixture leases and leaves product source unchanged', { gateways: gateways.map(g => g.stats()) });
  report.status = 'PASS';
} catch (error) {
  report.status = 'FAIL'; report.failure = error.stack;
  report.last = await Promise.all([...pages].map(async ([name, page]) => ({ name, value: await page.evaluate(() => ({ snapshot: mesh.snapshot(), events, discovery: mesh.discovery ? { origins: [...mesh.discovery.origins], records: [...mesh.discovery.records.keys()], sockets: [...mesh.discovery.sockets].map(([o, s]) => ({ origin: o, ready: s.ready, state: s.ws.readyState })) } : null })).catch(() => null) })));
  console.error(error); process.exitCode = 1;
} finally {
  for (const page of pages.values()) await page.evaluate(() => mesh.stop()).catch(() => {});
  for (const browser of browsers) await browser.close().catch(() => {});
  for (const timer of timers) clearInterval(timer);
  for (const gateway of gateways) await gateway.close().catch(() => {});
  for (const fixture of nativeFixtures) { for (const ws of fixture.wss.clients) ws.terminate(); await new Promise(r => fixture.wss.close(r)); await new Promise(r => fixture.server.close(r)); fixture.identity.privateKey.fill(0); }
  await tls?.close();
  await rm(tmp, { recursive: true, force: true }); report.finishedAt = new Date().toISOString(); await save();
}
