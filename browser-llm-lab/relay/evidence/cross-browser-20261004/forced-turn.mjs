#!/usr/bin/env node
// Explicit live diagnostic. Genuine public discovery/signaling and ordered RTC.
// Only test-owned browser sessions may connect; no node/daemon/config mutation.
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdtemp, rm, lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';

assert.equal(process.env.FORCED_TURN_AUTHORIZED, '1', 'Root must authorize live browser participation');
const origin = process.env.FORCED_TURN_ORIGIN || 'https://ai-test.make-cph-great-again.community';
const mode = process.env.TURN_TRANSPORT || 'both';
assert(['both', 'udp', 'tcp'].includes(mode));
const clockOffsetA = Number(process.env.BROWSER_CLOCK_OFFSET_A || 0);
assert(Number.isInteger(clockOffsetA) && Math.abs(clockOffsetA) <= 10000);
const output = process.env.FORCED_TURN_REPORT || `/tmp/cypher-cross-browser-20261004/forced-turn-${mode}.json`;
assert(output.startsWith('/tmp/'));
const { chromium } = await import(pathToFileURL(process.env.PLAYWRIGHT_MODULE || '/tmp/cypher-zero-tools/node_modules/playwright/index.mjs'));
const executable = process.env.CHROMIUM || '/tmp/cypher-zero-browsers/chromium-1243/chrome-linux64/chrome';
const rows = new Map(), identities = new Map(), sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const report = { status: 'RUNNING', startedAt: new Date().toISOString(), origin, transportFilter: mode,
  icePolicy: 'relay', simulatedClockOffsetA: clockOffsetA, sameHostOnly: true, realDevices: false, separatePhysicalNetworks: false,
  scope: 'Independent Chrome processes; genuine public discovery/signaling/native hello; actual selected relay ICE pair and ordered reliable DataChannel. No separate Common RLPx transfer acceptance claim.',
  privateDataCaptured: false, injectedPeerOrSourceData: false, nodeOrDaemonChanges: false,
  processes: {}, servedAssetHashes: {}, checkpoints: [], samples: [], pageErrors: [], httpErrors: [], cleanup: [] };
const save = () => writeFile(output, JSON.stringify(report, null, 2) + '\n');
async function until(label, check, timeout = 70000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) { const value = await check(); if (value) return value; await sleep(400); }
  throw new Error(label + ' timed out');
}
async function checkpoint(name, value) { report.checkpoints.push({ name, at: new Date().toISOString(), value }); await save(); console.log('PASS', name); }
async function observe(name) { return rows.get(name).page.evaluate(() => window.turnEvidence?.()); }
async function start(name) {
  const profile = await mkdtemp('/tmp/cypher-forced-turn-');
  const child = spawn(executable, ['--no-sandbox', '--no-proxy-server', '--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank'],
    { stdio: 'ignore', env: { ...process.env, XDG_CONFIG_HOME: join(profile, 'xdg-config'), XDG_CACHE_HOME: join(profile, 'xdg-cache') } });
  const row = { name, profile, child }; rows.set(name, row); report.processes[name] = { pid: child.pid };
  const port = await until(name + ' Chrome CDP startup', async () => { try { return Number((await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]); } catch { return false; } }, 20000);
  row.browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`, { noDefaults: true });
  const info = await (await row.browser.newBrowserCDPSession()).send('SystemInfo.getProcessInfo');
  assert.equal(info.processInfo.find(value => value.type === 'browser').id, child.pid);
  row.context = await row.browser.newContext({ viewport: { width: 1280, height: 800 } });
  row.page = await row.context.newPage();
  if (name === 'A' && clockOffsetA) await row.page.addInitScript(offset => { const original = Date.now.bind(Date); Date.now = () => original() + offset; }, clockOffsetA);
  row.page.on('pageerror', error => { if (report.pageErrors.length < 16) report.pageErrors.push({ browser: name, message: error.message.slice(0, 160) }); });
  row.page.on('response', response => { if (response.url().startsWith(origin + '/relay/v1/mesh/') && response.status() >= 400 && report.httpErrors.length < 32)
    report.httpErrors.push({ browser: name, path: new URL(response.url()).pathname, status: response.status() }); });
  await row.page.exposeFunction('turnOwnedIdentity', async identity => {
    identities.set(name, identity);
    await Promise.allSettled([...rows.values()].filter(r => r.page).map(r => r.page.evaluate(ids => window.turnPermit?.(ids), [...identities.values()].map(r => r.peerId))));
  });
  await row.page.goto(origin, { waitUntil: 'domcontentloaded', timeout: 45000 });
  report.servedAssetHashes[name] = await row.page.evaluate(async () => {
    const hashes = {};
    for (const path of ['/mesh-discovery.js', '/mesh-discovery-client.js']) {
      const response = await fetch(path, { cache: 'no-store' });
      if (!response.ok) throw new Error('Asset unavailable: ' + path);
      const digest = await crypto.subtle.digest('SHA-256', await response.arrayBuffer());
      hashes[path] = [...new Uint8Array(digest)].map(value => value.toString(16).padStart(2, '0')).join('');
    }
    return hashes;
  });
  await row.page.evaluate(async ({ mode, allowed }) => {
    const { MeshController } = await import('/mesh-controller.js');
    window.mesh = new MeshController({ sourceId: 'common-mine', iceTransportPolicy: 'relay', maxCommonConnections: 1 });
    let permit = new Set(allowed), assigned = [];
    const traces = []; const log = value => { if (traces.length < 96) traces.push({ at: Date.now(), ...value }); };
    const adopted = mesh.adoptPeers.bind(mesh), created = mesh.createPeer.bind(mesh), signaled = mesh.receiveSignal.bind(mesh), post = mesh.post.bind(mesh);
    mesh.adoptPeers = (candidates, generation) => { assigned = candidates; return adopted(candidates.filter(r => permit.has(r.peerId)), generation); };
    mesh.receiveSignal = (message, generation) => permit.has(message.from) ? signaled(message, generation) : Promise.resolve();
    mesh.createPeer = (candidate, generation) => {
      if (!permit.has(candidate.peerId)) return null;
      const peer = created(candidate, generation); if (!peer) return peer;
      const configuration = peer.pc.getConfiguration();
      const selected = [];
      for (const server of configuration.iceServers || []) {
        const urls = (Array.isArray(server.urls) ? server.urls : [server.urls]).filter(url => typeof url === 'string' && /^turns?:/.test(url) &&
          (mode === 'both' || (url.match(/[?&]transport=(udp|tcp)/)?.[1] || 'udp') === mode));
        if (urls.length) selected.push({ ...server, urls });
      }
      peer.pc.setConfiguration({ ...configuration, iceTransportPolicy: 'relay', iceServers: selected });
      log({ event: 'peer-created', turnUrls: selected.flatMap(r => r.urls).map(url => ({ scheme: url.split(':')[0], transport: url.match(/[?&]transport=(udp|tcp)/)?.[1] || 'udp' })) });
      peer.pc.addEventListener('icecandidate', event => { if (event.candidate) log({ event: 'candidate', candidateType: event.candidate.type, protocol: event.candidate.protocol }); else log({ event: 'gather-complete' }); });
      peer.pc.addEventListener('icecandidateerror', event => log({ event: 'candidate-error', errorCode: event.errorCode,
        scheme: typeof event.url === 'string' ? event.url.split(':')[0] : null, transport: event.url?.match(/[?&]transport=(udp|tcp)/)?.[1] || null }));
      for (const event of ['connectionstatechange', 'iceconnectionstatechange', 'icegatheringstatechange']) peer.pc.addEventListener(event, () =>
        log({ event, connectionState: peer.pc.connectionState, iceState: peer.pc.iceConnectionState, gathering: peer.pc.iceGatheringState }));
      return peer;
    };
    mesh.post = (message, transfer) => { if (message.type === 'init') void turnOwnedIdentity(message.identity).catch(() => {}); return post(message, transfer); };
    window.turnPermit = ids => { permit = new Set(ids); if (mesh.session) adopted(assigned.filter(r => permit.has(r.peerId)), mesh.generation); };
    window.turnEvidence = async () => {
      const snapshot = mesh.snapshot(), peers = [];
      for (const peer of mesh.peers.values()) {
        const stats = await peer.pc.getStats(); let pair;
        for (const item of stats.values()) if (item.type === 'transport' && item.selectedCandidatePairId) pair = stats.get(item.selectedCandidatePairId);
        if (!pair) for (const item of stats.values()) if (item.type === 'candidate-pair' && item.state === 'succeeded' && item.nominated) pair = item;
        const local = pair && stats.get(pair.localCandidateId), remote = pair && stats.get(pair.remoteCandidateId);
        const channels = [...stats.values()].filter(item => item.type === 'data-channel').map(item => ({ label: item.label, state: item.state,
          bytesSent: item.bytesSent || 0, bytesReceived: item.bytesReceived || 0, messagesSent: item.messagesSent || 0, messagesReceived: item.messagesReceived || 0 }));
        peers.push({ peerId: peer.peerId, owned: permit.has(peer.peerId), connectionState: peer.pc.connectionState, iceState: peer.pc.iceConnectionState,
          gathering: peer.pc.iceGatheringState, path: peer.path, iceSent: peer.iceSent, iceReceived: peer.iceReceived, policy: peer.pc.getConfiguration().iceTransportPolicy,
          dc: peer.dc ? { state: peer.dc.readyState, ordered: peer.dc.ordered, maxRetransmits: peer.dc.maxRetransmits, maxPacketLifeTime: peer.dc.maxPacketLifeTime } : null,
          selected: pair ? { state: pair.state, nominated: pair.nominated, bytesSent: pair.bytesSent || 0, bytesReceived: pair.bytesReceived || 0,
            local: local ? { type: local.candidateType, protocol: local.protocol, relayProtocol: local.relayProtocol || null } : null,
            remote: remote ? { type: remote.candidateType, protocol: remote.protocol } : null } : null, channels });
      }
      return { at: Date.now(), state: snapshot.state, requested: snapshot.requested, sourceId: snapshot.sourceId, nativeConnections: snapshot.nativeConnections,
        nativeVerified: snapshot.commonConnections.filter(r => r.connected).every(r => r.browserSignatureVerified), turnEnabled: mesh.config?.turnEnabled,
        signalReady: mesh.ws?.readyState === WebSocket.OPEN, discovery: { knownCandidates: mesh.discovery?.records.size || 0,
          readyGateways: [...(mesh.discovery?.sockets.values() || [])].filter(r => r.ready && r.ws.readyState === WebSocket.OPEN).length },
        adoptedOwnedCandidates: [...mesh.candidates.values()].filter(r => permit.has(r.peerId)).map(r => ({ peerId: r.peerId, initiator: r.initiator })),
        workerPresent: Boolean(mesh.worker), pendingSends: mesh.pendingPeerSends.size, circuits: snapshot.circuits, queuedBytes: snapshot.queuedBytes, traces: traces.slice(), peers };
    };
    await mesh.start();
  }, { mode, allowed: [...identities.values()].map(r => r.peerId) });
}
try {
  await save(); await start('A'); await sleep(1500); await start('B');
  assert.notEqual(report.processes.A.pid, report.processes.B.pid);
  await checkpoint('Two independent Chrome processes admitted via genuine public mesh', await Promise.all(['A', 'B'].map(observe)));
  const states = await until('Owned ordered DataChannels with selected relay candidates', async () => {
    const states = await Promise.all(['A', 'B'].map(observe));
    if (report.samples.length < 90) { report.samples.push(states); await save(); }
    return states.every(s => s?.requested && s.nativeConnections > 0 && s.nativeVerified && s.peers.some(p => p.owned && p.dc?.state === 'open' &&
      p.connectionState === 'connected' && p.selected?.state === 'succeeded' && p.selected.local?.type === 'relay' && p.policy === 'relay')) ? states : false;
  }, 60000);
  for (const state of states) {
    const peer = state.peers.find(r => r.dc?.state === 'open'); assert(peer.dc.ordered); assert.equal(peer.dc.maxRetransmits, null); assert.equal(peer.dc.maxPacketLifeTime, null);
  }
  await checkpoint('Actual selected TURN relay ICE pair and reliable ordered DataChannel', states);
  await sleep(3000); report.finalObservation = await Promise.all(['A', 'B'].map(observe));
  assert(report.finalObservation.every(s => s.peers.some(p => p.channels.some(c => c.bytesReceived > 0 && c.messagesReceived > 0))), 'Actual RTC application traffic must arrive at both independent browsers');
  await checkpoint('Actual controller/Worker protocol messages received across RTC', report.finalObservation);
  report.status = 'PASS';
} catch (error) { report.status = 'FAIL'; report.error = error.stack; report.failureObservation = await Promise.allSettled([...rows.keys()].map(observe)); process.exitCode = 1; }
finally {
  for (const row of rows.values()) {
    const cleanup = { browser: row.name, leaseRevoked: false, chromeExited: false, profileRemoved: false }; report.cleanup.push(cleanup);
    try {
      cleanup.stopped = await row.page.evaluate(async () => {
        const session = window.mesh?.session, base = window.mesh?.base; window.mesh?.stop();
        await new Promise(r => setTimeout(r, 2000));
        const snapshot = window.mesh?.snapshot();
        let leaseStatus = null;
        if (session?.token) leaseStatus = (await fetch(base + '/status', { headers: { Authorization: `Bearer ${session.token}` }, credentials: 'omit' })).status;
        return { leaseStatus, requested: snapshot?.requested, workerPresent: Boolean(window.mesh?.worker), peers: window.mesh?.peers.size,
          nativeConnections: snapshot?.nativeConnections, circuits: snapshot?.circuits, queuedBytes: snapshot?.queuedBytes };
      });
      cleanup.leaseRevoked = cleanup.stopped.leaseStatus === 401;
      assert.equal(cleanup.stopped.requested, false); assert.equal(cleanup.stopped.workerPresent, false); assert.equal(cleanup.stopped.peers, 0);
    } catch (error) { cleanup.error = error.message.slice(0, 200); }
    try { await Promise.race([row.context?.close(), sleep(5000)]); } catch {}
    try { await Promise.race([row.browser?.close(), sleep(5000)]); } catch {}
    if (row.child.exitCode === null && row.child.signalCode === null) row.child.kill('SIGTERM');
    for (let i = 0; i < 30 && row.child.exitCode === null && row.child.signalCode === null; i++) await sleep(100);
    if (row.child.exitCode === null && row.child.signalCode === null) { row.child.kill('SIGKILL'); await sleep(1000); }
    cleanup.chromeExited = row.child.exitCode !== null || row.child.signalCode !== null;
    try { assert(cleanup.chromeExited); const stat = await lstat(row.profile); assert(stat.isDirectory() && !stat.isSymbolicLink()); await rm(row.profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 }); cleanup.profileRemoved = true; } catch (error) { cleanup.profileError = error.message; }
    if (!cleanup.chromeExited || !cleanup.profileRemoved || !cleanup.leaseRevoked) { report.status = 'FAIL'; process.exitCode = 1; }
  }
  report.finishedAt = new Date().toISOString(); await save();
}
console.log(report.status, output);
