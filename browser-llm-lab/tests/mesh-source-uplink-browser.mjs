#!/usr/bin/env node
// Real native Common streams through an outgoing source uplink and real RTC.
// The caller provisions native processes. This file never starts/stops a node.
import assert from 'node:assert/strict';
import net from 'node:net';
import { readFile, writeFile, mkdtemp, mkdir, rm, rmdir, lstat } from 'node:fs/promises';
import { join, isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';

if (process.env.SOURCE_ACCEPTANCE_AUTHORIZED !== '1') throw new Error('Prepared only. Root must authorize live acceptance explicitly.');
const project = process.env.SOURCE_PROJECT_ROOT || '/root/cypher/browser-llm-lab';
const origin = process.env.SOURCE_PUBLIC_ORIGIN || 'https://ai-test.make-cph-great-again.community';
const sourceId = process.env.SOURCE_ID || process.env.SOURCE_NODE_ID;
assert(/^[0-9a-f]{64}$/.test(sourceId || ''), 'SOURCE_ID must be the temporary Common native nodeId64');
const paths = { primary: process.env.PRIMARY_NATIVE_IPC || '/root/cypher/chaindbmine/cypher.ipc', source: process.env.SOURCE_NATIVE_IPC };
assert(isAbsolute(paths.source || '') && paths.source !== paths.primary, 'Explicit independent SOURCE_NATIVE_IPC required');
const output = process.env.SOURCE_ACCEPTANCE_REPORT || '/tmp/cypher-source-uplink-review/browser-report.json';
assert(output.startsWith('/tmp/'));
const renewalSoakMs = Number(process.env.SOURCE_RENEWAL_SOAK_MS || 0);
assert(Number.isInteger(renewalSoakMs) && (renewalSoakMs === 0 || renewalSoakMs >= 130000 && renewalSoakMs <= 600000));
const { enodePublicKey, publicKeyNodeId } = await import(pathToFileURL(join(project, 'public/mesh-discovery.js')));
const { chromium } = await import(pathToFileURL(process.env.PLAYWRIGHT_MODULE || '/tmp/browser-llm-preview/node_modules/playwright/index.mjs'));
const executablePath = process.env.CHROMIUM || '/tmp/browser-llm-browsers/chromium-1243/chrome-linux64/chrome';
const runDirectory = await mkdtemp('/tmp/cypher-uplink-browsers-');
const participants = new Map(), identities = new Map();
let requestId = 0;
const report = { status: 'RUNNING', startedAt: new Date().toISOString(), origin, sourceId, project,
  sameHostOnly: true, physicalDeviceNetworkTest: false, browserMode: 'Independent processes, controller-driven path isolation; not a normal UI test',
  networkNamespaceIsolation: false, nativePathIsolation: 'NoDiscovery, empty static/trusted/bootstrap lists, loopback native listener; native peer transport inspected. No OS network exclusion claim.',
  nativeLifecycleMutations: 0, directCommonByteInjection: false, processes: {}, checkpoints: [], errors: [], cleanup: [] };
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const save = () => writeFile(output, JSON.stringify(report, null, 2) + '\n');
async function checkpoint(name, value = {}) { report.checkpoints.push({ name, at: new Date().toISOString(), ...value }); await save(); console.log('PASS', name); }
async function waitFor(name, check, milliseconds = 90000) {
  const deadline = Date.now() + milliseconds;
  while (Date.now() < deadline) { const value = await check(); if (value) return value; await sleep(300); }
  throw new Error(name + ' timed out');
}
function ipc(path, method, params = []) {
  assert(['admin_nodeInfo', 'admin_peers', 'eth_blockNumber', 'eth_getBlockByNumber'].includes(method));
  const id = ++requestId;
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ path }); let raw = Buffer.alloc(0), complete = false;
    const finish = (error, value) => { if (complete) return; complete = true; socket.destroy(); error ? reject(error) : resolve(value); };
    socket.setTimeout(8000, () => finish(new Error('Read-only native IPC timeout: ' + method)));
    socket.on('error', error => finish(error)); socket.on('end', () => { if (!complete) finish(new Error('Native IPC ended before reply')); });
    socket.on('connect', () => socket.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n'));
    socket.on('data', data => {
      raw = Buffer.concat([raw, data]); if (raw.length > 1048576) return finish(new Error('Native response exceeds 1MiB bound'));
      const end = raw.indexOf(10); if (end < 0) return;
      try { const reply = JSON.parse(raw.subarray(0, end)); assert.equal(reply.id, id); if (reply.error) throw new Error(method + ' returned an RPC error'); finish(null, reply.result); } catch (error) { finish(error); }
    });
  });
}
async function native() {
  const peers = await ipc(paths.source, 'admin_peers');
  const primaryHead = Number(BigInt(await ipc(paths.primary, 'eth_blockNumber')));
  const sourceHead = Number(BigInt(await ipc(paths.source, 'eth_blockNumber')));
  return { at: new Date().toISOString(), primaryHead, sourceHead, sourcePeers: peers.map(peer => ({ id: peer.id, transport: peer.network?.transport, browserMesh: peer.network?.browserMesh })) };
}
async function canonical() {
  const observation = await native(), height = Math.min(observation.primaryHead, observation.sourceHead);
  const hashes = {};
  for (const number of new Set([0, Math.min(1, height), Math.min(1000, height), height])) {
    const primary = await ipc(paths.primary, 'eth_getBlockByNumber', ['0x' + number.toString(16), false]);
    const source = await ipc(paths.source, 'eth_getBlockByNumber', ['0x' + number.toString(16), false]);
    assert.equal(primary.hash, source.hash, 'Canonical block hashes must agree');
    hashes[number] = primary.hash;
  }
  return { ...observation, hashes };
}
const state = name => participants.get(name).page.evaluate(() => mesh.snapshot());
const fresh = name => participants.get(name).page.evaluate(async () => (await mesh.inspect()).stats);
async function launch(name, targetSource) {
  const profile = join(runDirectory, name); await mkdir(profile, { mode: 0o700 });
  const child = spawn(executablePath, ['--no-sandbox', '--no-proxy-server', '--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank'],
    { stdio: 'ignore', env: { ...process.env, XDG_CONFIG_HOME: join(profile, 'xdg-config'), XDG_CACHE_HOME: join(profile, 'xdg-cache') } });
  const row = { child, profile }; participants.set(name, row);
  report.processes[name] = { pid: child.pid, profile, sourceId: targetSource }; await save();
  const port = await waitFor(name + ' browser CDP', async () => { try { return Number((await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]); } catch { return false; } }, 20000);
  row.browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`, { noDefaults: true });
  row.context = row.browser.contexts()[0]; row.page = row.context.pages()[0] || await row.context.newPage();
  const cdp = await row.browser.newBrowserCDPSession(), proc = await cdp.send('SystemInfo.getProcessInfo');
  assert.equal(proc.processInfo.find(value => value.type === 'browser').id, child.pid);
  row.page.on('pageerror', error => { if (report.errors.length < 32) report.errors.push({ browser: name, message: error.message.slice(0, 500) }); });
  await row.page.exposeFunction('recordOwnedIdentity', async value => {
    identities.set(name, value);
    const allowed = [...identities.values()].map(value => value.peerId);
    await Promise.allSettled([...participants.values()].filter(value => value.page).map(value => value.page.evaluate(ids => window.setOwnedPeers?.(ids), allowed)));
  });
  await row.page.goto(origin, { waitUntil: 'domcontentloaded', timeout: 45000 });
  await row.page.evaluate(async ({ targetSource, allowed }) => {
    const { MeshController } = await import('/mesh-controller.js');
    window.mesh = new MeshController({ sourceId: targetSource, maxCommonConnections: 1 });
    window.wire = { sent: [], received: [], receipts: [] }; window.renewals = [];
    const proofChunk = value => value.type === 'FRAME' && value.frame.type === 'data' && value.frame.seq > 1 && value.receipt.rawBytes >= 1024;
    let permit = new Set(allowed), assigned = [];
    const adopt = mesh.adoptPeers.bind(mesh), create = mesh.createPeer.bind(mesh), signal = mesh.receiveSignal.bind(mesh);
    mesh.adoptPeers = function(candidates, generation) { assigned = candidates; return adopt(candidates.filter(row => permit.has(row.peerId)), generation); };
    mesh.createPeer = function(candidate, generation) { return permit.has(candidate.peerId) ? create(candidate, generation) : null; };
    mesh.receiveSignal = async function(message, generation) { if (permit.has(message.from)) return signal(message, generation); };
    window.setOwnedPeers = ids => { permit = new Set(ids); if (mesh.session) adopt(assigned.filter(row => permit.has(row.peerId)), mesh.generation); };
    const pending = new Map(), post = mesh.post.bind(mesh), workerMessage = mesh.workerMessage.bind(mesh);
    mesh.workerMessage = function(message, generation) {
      if (message.type === 'send' && message.transport === 'peer') {
        const value = JSON.parse(message.text);
        if (proofChunk(value)) pending.set(message.sendId, value);
      }
      return workerMessage(message, generation);
    };
    mesh.post = function(message, transfer) {
      if (message.type === 'init') void recordOwnedIdentity(message.identity).catch(() => {});
      if (message.type === 'sent' && pending.has(message.sendId)) {
        const frame = pending.get(message.sendId); pending.delete(message.sendId);
        if (message.ok && wire.sent.length < 16) wire.sent.push(frame);
      }
      if (message.type === 'message' && wire.received.length < 16) {
        const frame = JSON.parse(new TextDecoder().decode(message.buffer));
        if (proofChunk(frame)) wire.received.push(frame);
      }
      return post(message, transfer);
    };
    mesh.addEventListener('event', event => {
      if (event.detail.name === 'acknowledged' && event.detail.seq > 1 && event.detail.rawBytes >= 1024 && wire.receipts.length < 64) wire.receipts.push(event.detail);
      if (event.detail.name === 'session-renewed' && renewals.length < 8) renewals.push({ expiresAt: event.detail.expiresAt, at: Date.now() });
    });
    await mesh.start();
  }, { targetSource, allowed: [...identities.values()].map(value => value.peerId) });
}
async function rawProof(left, right, forbiddenCircuit) {
  const found = await waitFor('Independent actual RTC bytes and peer hop ACK', async () => {
    const a = await participants.get(left).page.evaluate(() => wire), b = await participants.get(right).page.evaluate(() => wire);
    for (const [sender, receiver, sentRows, receivedRows] of [[left, right, a, b], [right, left, b, a]]) for (const sent of sentRows.sent) {
      if (sent.frame.circuitId === forbiddenCircuit || sent.frame.seq <= 1 || sent.receipt.rawBytes < 1024) continue;
      const received = receivedRows.received.find(row => row.receipt.requestId === sent.receipt.requestId);
      const receipt = sentRows.receipts.find(row => row.requestId === sent.receipt.requestId);
      if (received && receipt) return { sender, receiver, sent, received, receipt };
    }
    return false;
  }, 30000);
  assert.equal(found.sent.frame.data, found.received.frame.data);
  assert.equal(found.sent.fromSessionId, found.received.fromSessionId); assert.equal(found.sent.toSessionId, found.received.toSessionId);
  const raw = Buffer.from(found.received.frame.data, 'base64'), digest = createHash('sha256').update(raw).digest('hex');
  assert(raw.length >= 1024 && found.sent.frame.seq > 1, 'Proof must capture a larger stream chunk beyond the first native handshake chunk');
  assert.equal(digest, found.receipt.digest); assert.equal(raw.length, found.receipt.rawBytes);
  return { sender: found.sender, receiver: found.receiver, circuitId: found.sent.frame.circuitId, seq: found.sent.frame.seq,
    bytes: raw.length, digest, bytesEqual: true, acknowledgementMatched: true, path: found.receipt.path,
    samplePolicy: { minimumRawBytes: 1024, minimumSequence: 2 },
    meaning: 'Real peer browser bounded-queue acceptance, not native consumption or chain finality' };
}
const controlState = name => participants.get(name).page.evaluate(() => {
  const state = mesh.snapshot(), endpoint = mesh.discovery?.endpoints().find(record => record.nodeId === mesh.session?.nodeId);
  return { state: state.state, requested: state.requested, generation: mesh.generation, sessionId: mesh.session?.id,
    expiresAt: mesh.session?.expiresAt, nativeSession: mesh.nativeSession, nativeConnected: state.nativeConnected,
    sourceId: mesh.session?.sourceId, workerPresent: Boolean(mesh.worker), aiLoad: state.aiLoad,
    endpoint: endpoint ? { nodeId: endpoint.nodeId, sourceId: endpoint.sourceId, sequence: endpoint.payload.sequence, expiresAt: endpoint.expiresAt, bootId: endpoint.payload.bootId } : null,
    renewals: renewals.slice() };
});
async function renewalSoak() {
  if (!renewalSoakMs) { report.renewalSoak = { status: 'NOT_RUN', requestedMs: 0 }; return; }
  const names = ['B', 'C'], before = {};
  for (const name of names) before[name] = await waitFor(name + ' fresh endpoint before renewal soak', async () => {
    const row = await controlState(name); return row.endpoint?.expiresAt > Date.now() && row.nativeConnected ? row : false;
  });
  for (const name of names) await participants.get(name).page.evaluate(() => mesh.setAiLoad('loading'));
  await waitFor('AI state signal closes circuits while keeping native control connections', async () => {
    const rows = await Promise.all(names.map(fresh)); return rows.every(row => row.circuits === 0 && row.queuedBytes === 0 && row.aiLoad === 'loading') && (await native()).sourcePeers.length === 0;
  });
  const started = Date.now(), samples = [];
  report.renewalSoak = { status: 'RUNNING', requestedMs: renewalSoakMs, startedAt: new Date(started).toISOString(), before,
    aiTest: 'AI workload state signal only; no actual model load, WebGPU benchmark or physical-device performance claim', samples };
  await checkpoint('Renewal soak begins with AI pause policy and live control channels');
  while (Date.now() - started < renewalSoakMs) {
    await sleep(Math.min(10000, renewalSoakMs - (Date.now() - started)));
    const sample = { at: new Date().toISOString(), elapsedMs: Date.now() - started };
    for (const name of names) {
      const current = await controlState(name), original = before[name];
      assert(current.requested && current.workerPresent && current.nativeConnected, name + ' control path must remain live');
      assert.equal(current.generation, original.generation); assert.equal(current.sessionId, original.sessionId);
      assert.equal(current.nativeSession, original.nativeSession); assert.equal(current.aiLoad, 'loading');
      assert(current.endpoint?.expiresAt > Date.now(), name + ' signed endpoint must remain fresh');
      assert.equal(current.endpoint.bootId, original.endpoint.bootId);
      sample[name] = current;
    }
    samples.push(sample); await save();
    if (samples.length % 3 === 0) console.log('SOAK', sample.elapsedMs, 'ms; native control sessions unchanged');
  }
  const after = {};
  for (const name of names) {
    const current = await controlState(name), original = before[name]; after[name] = current;
    assert(current.expiresAt > original.expiresAt, name + ' original gateway/native lease must renew');
    assert(current.renewals.length > original.renewals.length, name + ' real session-renewed event must occur');
    assert(current.endpoint.sequence > original.endpoint.sequence, name + ' signed source endpoint sequence must advance');
    assert(current.endpoint.expiresAt > original.endpoint.expiresAt, name + ' signed endpoint freshness must refresh');
  }
  Object.assign(report.renewalSoak, { status: 'PASS', elapsedMs: Date.now() - started, after });
  await checkpoint('Session renewal and signed source refresh preserve generation during AI pause', { renewalSoak: report.renewalSoak });
}
function ownNativePeer(row, forbiddenCircuit) {
  const labels = new Set([...identities.values()].map(identity => identity.browserId));
  assert(row.sourcePeers.every(peer => peer.transport === 'browser-mesh'), 'Temporary Common must have no native TCP peer');
  return row.sourcePeers.find(peer => peer.browserMesh?.remoteId === report.primaryNodeId && peer.browserMesh.circuitId !== forbiddenCircuit &&
    peer.browserMesh.relayIds.length >= 2 && peer.browserMesh.relayIds.every(id => labels.has(id)) && peer.browserMesh.bytesReceived > 0 && peer.browserMesh.bytesSent > 0);
}
try {
  await save();
  const localConfig = JSON.parse(await readFile(join(project, 'relay/config.json'), 'utf8'));
  assert(!localConfig.nodes.some(node => node.nodeId === sourceId || node.id === sourceId), 'Temporary source must not be manually registered in fixed gateway nodes');
  const primaryInfo = await ipc(paths.primary, 'admin_nodeInfo'), sourceInfo = await ipc(paths.source, 'admin_nodeInfo');
  report.primaryNodeId = primaryInfo.id; report.sourceNodeId = sourceInfo.id;
  assert.equal(sourceInfo.id, sourceId); assert.notEqual(primaryInfo.id, sourceId);
  assert.equal(publicKeyNodeId(enodePublicKey(primaryInfo.enode)), primaryInfo.id);
  assert.equal(publicKeyNodeId(enodePublicKey(sourceInfo.enode)), sourceInfo.id);
  report.before = await native(); assert.equal(report.before.sourcePeers.length, 0, 'Temporary Common starts without native peers');
  await launch('A', process.env.PRIMARY_SOURCE_ID || 'common-mine'); await sleep(1100); await launch('B', sourceId);
  assert.notEqual(report.processes.A.pid, report.processes.B.pid);
  await waitFor('Both native leases and own RTC link', async () => { const a = await state('A'), b = await state('B'); return a.nativeConnected && b.nativeConnected && a.peers.some(peer => peer.connected && peer.peerId === identities.get('B')?.peerId) && b.peers.some(peer => peer.connected && peer.peerId === identities.get('A')?.peerId); });
  await checkpoint('Unregistered source obtains browser access through outgoing source WSS', { A: await state('A'), B: await state('B') });
  const transferred = await waitFor('Native Common authentication and bidirectional actual bytes via owned RTC path', async () => { const n = await native(); return ownNativePeer(n) ? n : false; }, 120000);
  report.firstNative = transferred; report.firstRawProof = await rawProof('A', 'B');
  await waitFor('Temporary Common receives non-genesis chain data', async () => { const n = await native(); return n.sourceHead > report.before.sourceHead ? n : false; }, 120000);
  report.firstCanonical = await canonical();
  await checkpoint('Actual native stream, exact RTC bytes/digest/hop ACK, and matching chain data', { native: report.firstCanonical, raw: report.firstRawProof });
  await participants.get('A').page.evaluate(() => mesh.stop());
  await waitFor('A OFF removes B RTC/circuit/queue and native peer', async () => {
    const b = await fresh('B'), n = await native(); return b.connectedPeers === 0 && b.circuits === 0 && b.queuedBytes === 0 && n.sourcePeers.length === 0;
  });
  const drained = await fresh('B'); await sleep(2500); const stable = await fresh('B');
  report.offNative = await native();
  assert.equal(stable.streamForwardedBytes, drained.streamForwardedBytes); assert.equal(stable.receivedBytes, drained.receivedBytes);
  await checkpoint('A OFF stops the only browser relay path after queues drain', { before: drained, after: stable });
  await participants.get('B').page.evaluate(() => { wire.sent = []; wire.received = []; wire.receipts = []; });
  await launch('C', process.env.PRIMARY_SOURCE_ID || 'common-mine');
  const replaced = await waitFor('Replacement C creates a fresh authenticated native route', async () => { const n = await native(); return ownNativePeer(n, report.firstRawProof.circuitId) ? n : false; }, 120000);
  report.replacementNative = replaced; report.replacementRawProof = await rawProof('C', 'B', report.firstRawProof.circuitId);
  report.replacementProgress = await waitFor('C transfers chain data that B had not received before C joined', async () => {
    const n = await native(), peer = ownNativePeer(n, report.firstRawProof.circuitId);
    return n.sourceHead > report.offNative.sourceHead && peer?.browserMesh.bytesReceived > 5000 ? n : false;
  }, 120000);
  report.finalCanonical = await canonical();
  await checkpoint('New C route carries newly observed encrypted bytes and matching hop ACK', { native: report.finalCanonical, raw: report.replacementRawProof });
  await renewalSoak();
  for (const row of participants.values()) await row.page.evaluate(() => mesh.stop());
  await waitFor('Own temporary Common native peers are reclaimed', async () => (await native()).sourcePeers.length === 0);
  report.final = await native();
  assert.equal(report.errors.length, 0); report.status = 'PASS';
} catch (error) { report.status = 'FAIL'; report.error = error.stack; process.exitCode = 1; }
finally {
  for (const [name, row] of participants) {
    const result = { browser: name, pid: row.child.pid, profile: row.profile }; report.cleanup.push(result);
    try { await row.page?.evaluate(() => mesh.stop()); } catch {}
    try { await Promise.race([row.browser?.close(), sleep(8000)]); } catch (error) { result.closeError = error.message; }
    if (row.child.exitCode === null && row.child.signalCode === null) row.child.kill('SIGTERM');
    for (let n = 0; n < 30 && row.child.exitCode === null && row.child.signalCode === null; n++) await sleep(100);
    if (row.child.exitCode === null && row.child.signalCode === null) { row.child.kill('SIGKILL'); for (let n = 0; n < 30 && row.child.exitCode === null && row.child.signalCode === null; n++) await sleep(100); }
    result.exited = row.child.exitCode !== null || row.child.signalCode !== null;
    try { assert(result.exited); const info = await lstat(row.profile); assert(info.isDirectory() && !info.isSymbolicLink()); await rm(row.profile, { recursive: true, force: true }); result.profileRemoved = await lstat(row.profile).then(() => false, error => error.code === 'ENOENT'); }
    catch (error) { result.cleanupError = error.message; result.profileRemoved = false; }
  }
  report.cleanupComplete = report.cleanup.every(row => row.exited && row.profileRemoved);
  if (report.cleanupComplete) {
    try { await rmdir(runDirectory); report.profileParentRemoved = true; }
    catch (error) { report.profileParentRemoved = false; report.profileParentCleanupError = error.message; report.cleanupComplete = false; }
  }
  if (!report.cleanupComplete) { report.status = 'FAIL'; process.exitCode = 1; }
  report.finishedAt = new Date().toISOString(); await save();
}
console.log(report.status, output);
