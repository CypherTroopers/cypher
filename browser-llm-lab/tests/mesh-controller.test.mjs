import test from 'node:test';
import assert from 'node:assert/strict';
import { MeshController } from '../public/mesh-controller.js';
const LIMIT = 100 * 1048576, PROTOCOL = 'cypher-browser-mesh/1';
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };
const flush = async () => { for (let i = 0; i < 10; i++) await Promise.resolve(); };
const size = value => new TextEncoder().encode(typeof value === 'string' ? value : JSON.stringify(value)).length;
const network = { chainId: 10101919, genesisHash: '0x' + '11'.repeat(32) };
const node = { id: 'common-a', nodeId: '22'.repeat(32), publicKey: '33'.repeat(64) };
const config = { enabled: true, version: 1, protocol: PROTOCOL, network, nodes: [node], connectPath: '/relay/v1/mesh/connect', signalPath: '/relay/v1/mesh/signal', limits: { renewAfterMs: 120000 } };
function setup(t, options = {}) {
  const names = ['fetch', 'location', 'Worker', 'WebSocket', 'RTCPeerConnection'];
  const originals = new Map(names.map(name => [name, globalThis[name]]));
  const workers = [], sockets = [], requests = [], scheduled = [], emitted = []; let admissions = 0, responseBytes = 0, requestBytes = 0;
  class FakeWorker { constructor() { this.messages = []; this.terminated = 0; workers.push(this); } postMessage(message) { this.messages.push(message); } terminate() { this.terminated++; } }
  class FakeSocket { static OPEN = 1; constructor(url) { this.url = String(url); this.readyState = 0; this.sent = []; this.bufferedAmount = 0; this.closes = 0; sockets.push(this); }
    send(value) { if (this.readyState !== 1) throw new Error('socket not open'); this.sent.push(value); }
    close() { this.closes++; this.readyState = 3; } open() { this.readyState = 1; this.onopen?.(); } message(value) { this.onmessage?.({ data: typeof value === 'string' ? value : JSON.stringify(value) }); }
  }
  class FakeRTC { constructor(options) { this.options = options; this.connectionState = 'new'; this.sctp = { maxMessageSize: 65536 }; this.closed = false; }
    getConfiguration() { return this.options; } setConfiguration(options) { this.options = options; } close() { this.closed = true; this.connectionState = 'closed'; } }
  Object.assign(globalThis, { Worker: FakeWorker, WebSocket: FakeSocket, RTCPeerConnection: FakeRTC,
    location: { href: 'https://mesh.test/', origin: 'https://mesh.test', protocol: 'https:' } });
  const makeSession = () => { admissions++; return { id: admissions.toString(16).padStart(32, '0'), peerId: (admissions + 100).toString(16).padStart(32, '0'), browserId: (admissions + 200).toString(16).padStart(32, '0'), token: 'aa'.repeat(32), expiresAt: Date.now() + 300000, sourceId: 'common-a', nodeId: node.nodeId, iceServers: [], ...(options.nativeLimits ? { nativeLimits: options.nativeLimits } : {}) }; };
  globalThis.fetch = async (url, request = {}) => {
    requests.push({ url: String(url), ...request }); requestBytes += size(request.body || '');
    let value;
    if (request.method === 'DELETE') return new Response(null, { status: 204 });
    if (String(url).endsWith('/config')) value = options.config ? await options.config() : config;
    else if (String(url).endsWith('/sessions')) value = options.session ? await options.session(makeSession, request) : makeSession();
    else if (String(url).endsWith('/renew')) value = options.renew ? await options.renew() : { expiresAt: Date.now() + 300000, iceServers: [] };
    else if (String(url).endsWith('/status')) value = options.status ? await options.status() : { sessions: 1, circuits: 0, routes: [] };
    else throw new Error('Unexpected fixture URL: ' + url);
    if (value instanceof Response) { responseBytes += Number(value.headers.get('content-length')) || 0; return value; }
    const text = JSON.stringify(value); responseBytes += size(text); return new Response(text, { headers: { 'content-type': 'application/json', 'content-length': String(size(text)) } });
  };
  const c = new MeshController({ sourceId: 'common-a', ...options.controller });
  c.emit = (type, detail) => emitted.push({ type, detail });
  c.later = (fn, ms, g = c.generation) => { const entry = { fn, ms, g, run: () => c.live(g) ? fn() : undefined }; scheduled.push(entry); return entry; };
  t.after(() => { c.stop(); for (const [name, value] of originals) { if (value === undefined) delete globalThis[name]; else globalThis[name] = value; } });
  const hello = () => ({ type: 'hello', protocol: PROTOCOL, session: 'bb'.repeat(16), browserId: c.session.browserId, advertisement: { payloadBase64: 'e30=', signatureHex: 'cc'.repeat(64) + '00' } });
  return { c, workers, sockets, requests, scheduled, emitted, hello, admissions: () => admissions, bytes: () => requestBytes + responseBytes };
}

test('OFF during delayed configuration makes no session, sockets or Worker and cannot resurrect', async t => {
  const pending = deferred(), f = setup(t, { config: () => pending.promise });
  const starting = f.c.start(); f.c.stop(); pending.resolve(config); await starting;
  assert.equal(f.admissions(), 0); assert.equal(f.sockets.length, 0); assert.equal(f.workers.length, 0); assert.equal(f.c.requested, false);
});

test('delayed native hello and old Worker events are ignored after OFF and a new ON generation', async t => {
  const f = setup(t); await f.c.start(); const oldSocket = f.c.native, oldEvent = oldSocket.onmessage, oldWorkerEvent = f.c.worker.onmessage, oldGeneration = f.c.generation;
  const oldHello = f.hello(); f.c.stop(); await f.c.start(); const current = f.c.worker;
  oldEvent({ data: JSON.stringify(oldHello) }); oldWorkerEvent({ data: { generation: oldGeneration, type: 'stopped', reason: 'error' } });
  assert.equal(f.c.worker, current); assert.equal(f.c.nativeConnected, false); assert.equal(f.c.requested, true);
  f.c.native.open(); f.c.native.message(f.hello()); assert.equal(f.c.nativeConnected, true);
  f.c.stop(); assert.equal(f.workers.every(worker => worker.terminated === 1), true); assert.equal(f.sockets.every(socket => socket.closes >= 1), true);
});

test('native close readmits with a new session and carries ON traffic and counters exactly once', async t => {
  const f = setup(t); await f.c.start(); f.c.native.open(); f.c.native.message(f.hello());
  const oldId = f.c.session.id, oldWorker = f.c.worker;
  f.c.stats = { ...f.c.stats, nativeReceivedBytes: 250, acknowledgedBytes: 123, acknowledgedCount: 1 };
  const before = f.c.observedBytes; f.emitted.length = 0; f.c.native.onclose();
  assert.equal(f.c.state, 'RECONNECTING'); assert.equal(oldWorker.terminated, 1); assert.equal(f.c.native, null);
  assert.equal(f.c.snapshot().acknowledgedBytes, 123); assert.ok(f.emitted.every(event => !event.detail?.acknowledgedBytes || event.detail.acknowledgedBytes === 123));
  const retry = f.scheduled.findLast(row => row.g === f.c.generation); await retry.run();
  assert.notEqual(f.c.session.id, oldId); assert.equal(f.c.reconnects, 1);
  assert.equal(f.c.worker.messages.find(message => message.type === 'init').initialTotalBytes, before);
  assert.equal(f.c.observedBytes, f.bytes() + size(oldWorker.messages.find(message => message.type === 'nativeHello').frame) + size({ token: 'aa'.repeat(32) }));
});

test('100MiB budget persists across automatic rejoin and cannot be reset by stale stats', async t => {
  const f = setup(t); await f.c.start(); f.c.observedBytes = LIMIT - 10000; f.c.stats = { ...f.c.stats, totalBytes: 1 };
  f.c.recover('fixture native disconnect', f.c.generation); const prior = f.c.consumedBytes;
  assert.equal(prior, LIMIT - 10000); await f.scheduled.findLast(row => row.g === f.c.generation).run();
  assert.equal(f.c.worker.messages.find(message => message.type === 'init').initialTotalBytes, prior);
  f.c.account(10000, 'in', 'signal'); assert.equal(f.c.state, 'OFF_LIMIT'); assert.equal(f.c.requested, false); assert.equal(f.c.native, null);
});

test('repeated failed admissions stop after twelve retries and old callbacks cannot rejoin', async t => {
  const f = setup(t, { config: async () => { throw new Error('Common unavailable'); } });
  await f.c.start();
  for (let attempt = 0; attempt < 12; attempt++) await f.scheduled.findLast(row => row.g === f.c.generation).run();
  assert.equal(f.c.state, 'ERROR'); assert.equal(f.c.requested, false); assert.equal(f.c.reconnects, 12);
  const requests = f.requests.length; for (const callback of f.scheduled) await callback.run(); assert.equal(f.requests.length, requests);
});

test('renewal failure closes old transports before admitting another native generation', async t => {
  const f = setup(t, { renew: async () => { throw new Error('expired'); } }); await f.c.start();
  const native = f.c.native, signal = f.c.ws, worker = f.c.worker;
  await f.scheduled.find(row => row.ms === 120000).run();
  assert.equal(f.c.state, 'RECONNECTING'); assert.equal(native.closes, 1); assert.equal(signal.closes, 1); assert.equal(worker.terminated, 1);
  assert.equal(f.c.session, null); assert.equal(f.c.nativeSession, null);
});

test('HTTP prelude, signaling, native JSON and RTC sends/receives are charged once from observed bytes', async t => {
  const f = setup(t); await f.c.start(); const c = f.c; assert.equal(c.observedBytes, f.bytes());
  const prelude = c.worker.messages.filter(message => message.type === 'account').reduce((sum, message) => sum + message.bytes, 0);
  assert.equal(prelude, f.bytes()); c.native.open(); const hello = f.hello(); c.native.message(hello);
  let expected = f.bytes() + size({ token: 'aa'.repeat(32) }) + size(hello); assert.equal(c.observedBytes, expected);
  c.account(13, 'out', 'signal'); expected += 13;
  const outgoing = JSON.stringify({ type: 'credit', session: hello.session, circuitId: 'cc'.repeat(16), seq: 1, bytes: 3 });
  c.workerMessage({ type: 'send', transport: 'native', sendId: 'native-send', text: outgoing }, c.generation); expected += size(outgoing);
  const dc = { readyState: 'open', bufferedAmount: 0, send() {} }; c.peers.set('peer', { peerId: 'peer', sessionId: 'remote', pc: { connectionState: 'connected', close() {} }, dc });
  c.workerMessage({ type: 'send', transport: 'peer', peerId: 'peer', sendId: 'rtc-send', text: 'opaque-peer-json' }, c.generation); expected += size('opaque-peer-json');
  c.post({ type: 'message', peerId: 'peer', buffer: new Uint8Array(17).buffer }); expected += 17;
  assert.equal(c.observedBytes, expected); assert.equal(c.pendingPeerSends.size, 0);
  assert.equal(c.worker.messages.at(-1).type, 'peerMessage');
});

test('native/RTC high-water and maximum-frame checks report failed sends without charging successes', async t => {
  const f = setup(t); await f.c.start(); f.c.native.open(); f.c.native.message(f.hello()); const c = f.c, before = c.observedBytes;
  c.native.bufferedAmount = 65536;
  c.workerMessage({ type: 'send', transport: 'native', sendId: 'blocked', text: 'abc' }, c.generation);
  assert.equal(c.worker.messages.at(-1).ok, false); assert.equal(c.observedBytes, before);
  c.native.bufferedAmount = 0;
  c.workerMessage({ type: 'send', transport: 'native', sendId: 'oversized', text: 'x'.repeat(16385) }, c.generation);
  assert.equal(c.worker.messages.at(-1).ok, false); assert.equal(c.observedBytes, before);
  const dc = { readyState: 'open', bufferedAmount: 65536, send() { throw new Error('must not send'); } }; c.peers.set('peer', { peerId: 'peer', pc: { connectionState: 'connected', close() {} }, dc });
  c.workerMessage({ type: 'send', transport: 'peer', peerId: 'peer', sendId: 'blocked-peer', text: 'abc' }, c.generation);
  assert.equal(c.worker.messages.at(-1).ok, false); assert.equal(c.observedBytes, before); assert.equal(c.pendingPeerSends.size, 0);
});

test('oversized or stale native messages fail closed before reaching the Worker', async t => {
  const f = setup(t); await f.c.start(); const worker = f.c.worker;
  f.c.native.message(' '.repeat(16385)); assert.equal(f.c.state, 'ERROR'); assert.equal(f.c.requested, false); assert.equal(worker.terminated, 1);
  await f.c.start(); f.c.native.open(); f.c.native.message(f.hello());
  f.c.native.message({ type: 'closed', session: 'ff'.repeat(16) }); assert.equal(f.c.state, 'ERROR'); assert.equal(f.c.requested, false);
});

test('AI load states reach the Worker, pause circuit UI, and suppress additional RTC handshakes', async t => {
  const f = setup(t); await f.c.start(); const c = f.c; c.native.open(); c.native.message(f.hello());
  for (const load of ['loading', 'benchmarking', 'generating']) {
    c.setAiLoad(load); assert.equal(c.worker.messages.at(-1).state, load);
    assert.equal(c.createPeer({ peerId: 'new-peer', id: 'new-session' }, c.generation), null);
    if (load !== 'generating') assert.equal(c.state, 'PAUSED_AI');
  }
  c.setAiLoad('idle'); const peer = c.createPeer({ peerId: 'new-peer', id: 'new-session' }, c.generation);
  assert.ok(peer); assert.equal(peer.pc.options.iceTransportPolicy, 'all');
});

test('signaling frame reaching the transfer cap preserves OFF_LIMIT without processing peer assignments', async t => {
  const f = setup(t); await f.c.start(); const c = f.c, ws = c.ws;
  c.observedBytes = LIMIT - 1;
  ws.message({ type: 'peers', peers: [{ peerId: 'peer-A', id: 'peer-session-A' }] });
  assert.equal(c.state, 'OFF_LIMIT'); assert.equal(c.requested, false); assert.equal(c.peers.size, 0);
});

test('native status and RTC diagnostics keep at most one outstanding read of each kind', async t => {
  const f = setup(t); await f.c.start(); f.c.native.open(); f.c.native.message(f.hello());
  const status = deferred(), stats = deferred(); let statusReads = 0, rtcReads = 0;
  f.c.json = async () => { statusReads++; return status.promise; };
  f.c.peers.set('peer', { peerId: 'peer', pc: { connectionState: 'connected', getStats() { rtcReads++; return stats.promise; }, close() {} } });
  const status1 = f.c.readNativeStatus(f.c.generation), status2 = f.c.readNativeStatus(f.c.generation);
  const rtc1 = f.c.collectRTC(f.c.generation), rtc2 = f.c.collectRTC(f.c.generation);
  assert.equal(statusReads, 1); assert.equal(rtcReads, 1);
  f.c.stop(); status.resolve({ sessions: 99 }); stats.resolve(new Map()); await Promise.all([status1, status2, rtc1, rtc2]);
  assert.equal(f.c.nativeStatus, null); assert.deepEqual(f.c.rtcStats, []);
});

const statusFailure = status => {
  const body = 'fixture response body must never become a user-facing error';
  return new Response(body, { status, headers: { 'content-length': String(size(body)) } });
};

test('current status 401 immediately withdraws native readiness and readmits without resetting the ON budget', async t => {
  const f = setup(t, { status: () => statusFailure(401) }); await f.c.start();
  f.c.native.open(); f.c.native.message(f.hello());
  const oldSession = f.c.session.id, oldNative = f.c.native, oldSignal = f.c.ws, oldWorker = f.c.worker;
  const prior = LIMIT - 10000; f.c.observedBytes = prior;
  await f.c.readNativeStatus(f.c.generation);
  assert.equal(f.c.state, 'RECONNECTING'); assert.equal(f.c.nativeConnected, false); assert.equal(f.c.nativeStatus, null);
  assert.equal(oldNative.closes, 1); assert.equal(oldSignal.closes, 1); assert.equal(oldWorker.terminated, 1);
  assert.equal(f.c.reconnects, 1); assert.equal(f.c.nativeStatusRead, null);
  const carried = prior + Number(statusFailure(401).headers.get('content-length'));
  assert.equal(f.c.consumedBytes, carried);
  assert.equal(JSON.stringify(f.emitted).includes('fixture response body'), false);
  await f.scheduled.findLast(row => row.g === f.c.generation).run();
  assert.notEqual(f.c.session.id, oldSession);
  assert.equal(f.c.worker.messages.find(message => message.type === 'init').initialTotalBytes, carried);
  assert.ok(f.c.snapshot().totalBytes > carried);
  f.c.account(10000, 'in', 'signal'); assert.equal(f.c.state, 'OFF_LIMIT'); assert.equal(f.c.requested, false);
});

test('an old status 401 cannot retire a new ON session or clear its pending status read', async t => {
  const first = deferred(), second = deferred(); let calls = 0;
  const f = setup(t, { status: () => (++calls === 1 ? first.promise : second.promise) });
  await f.c.start(); f.c.native.open(); f.c.native.message(f.hello());
  const oldRead = f.c.readNativeStatus(f.c.generation); f.c.stop();
  await f.c.start(); f.c.native.open(); f.c.native.message(f.hello());
  const currentSession = f.c.session, currentNative = f.c.native, currentWorker = f.c.worker, before = f.c.observedBytes;
  const newRead = f.c.readNativeStatus(f.c.generation), marker = f.c.nativeStatusRead;
  first.resolve(statusFailure(401)); await oldRead;
  assert.equal(f.c.session, currentSession); assert.equal(f.c.native, currentNative); assert.equal(f.c.worker, currentWorker);
  assert.equal(f.c.nativeConnected, true); assert.equal(f.c.reconnects, 0); assert.equal(f.c.nativeStatusRead, marker);
  assert.equal(f.c.observedBytes, before); assert.equal(currentNative.closes, 0); assert.equal(currentWorker.terminated, 0);
  second.resolve({ sessions: 1, circuits: 2, routes: [] }); await newRead;
  assert.equal(f.c.nativeStatus.circuits, 2); assert.equal(f.c.nativeStatusRead, null);
});

test('temporary status failures report an error without replacing a healthy native session', async t => {
  const f = setup(t, { status: () => statusFailure(503) }); await f.c.start(); f.c.native.open(); f.c.native.message(f.hello());
  const session = f.c.session, native = f.c.native;
  await f.c.readNativeStatus(f.c.generation);
  assert.equal(f.c.session, session); assert.equal(f.c.native, native); assert.equal(f.c.nativeConnected, true);
  assert.equal(f.c.reconnects, 0); assert.equal(native.closes, 0);
  assert.equal(f.c.sourceErrors['common-a'], 'Gateway 503: source not ready or expired');
});


test('fresh admission capacities reach Worker and stale statistics cannot restore their OFF display', async t => {
  const nativeLimits = { maxSessions: 80, nativePeers: 40, circuits: 40, circuitsPerSession: 40, pendingInbound: 4, pendingOutbound: 4 };
  const f = setup(t, { nativeLimits }); await f.c.start();
  assert.deepEqual(f.c.worker.messages.find(row => row.type === 'init').nativeLimits, nativeLimits);
  const event = f.c.worker.onmessage, generation = f.c.generation;
  event({ data: { generation, type: 'stats', stats: { capacities: { endpointCircuits: 40, common: nativeLimits }, endpointCircuits: 39 } } });
  assert.equal(f.c.snapshot().capacities.endpointCircuits, 40);
  f.c.stop(); event({ data: { generation, type: 'stats', stats: { capacities: { endpointCircuits: 40 }, endpointCircuits: 39 } } });
  assert.equal(f.c.snapshot().capacities, null); assert.equal(f.c.snapshot().endpointCircuits, 0);
});

test('invalid admission capacity is released before native sockets or Worker start', async t => {
  const f = setup(t, { nativeLimits: { maxSessions: 800, nativePeers: 400 } }); await f.c.start();
  assert.equal(f.workers.length, 0); assert.equal(f.sockets.length, 0);
  assert.ok(f.requests.some(row => row.method === 'DELETE'));
});

test('bounded large status accepts native 64KiB plus envelope and rejects responses above 128KiB', async t => {
  let huge = false;
  const f = setup(t, { status: () => ({ routes: [], description: 'x'.repeat(huge ? 131072 : 65536) }) });
  await f.c.start(); f.c.native.open(); f.c.native.message(f.hello());
  await f.c.readNativeStatus(f.c.generation); assert.equal(f.c.nativeStatus.description.length, 65536);
  huge = true; await f.c.readNativeStatus(f.c.generation);
  assert.ok(f.c.sourceErrors['common-a']); assert.equal(f.c.nativeStatus.description.length, 65536);
});

function multiSetup(t, options = {}) {
  const nodes = [node, ...Array.from({ length: 20 }, (_, i) => ({ id: `common-${i + 1}`, nodeId: (i + 80).toString(16).padStart(64, '0'), publicKey: (i + 80).toString(16).padStart(128, '0') }))];
  const multiConfig = { ...config, nodes, limits: { ...config.limits, maxCommonConnections: 20, maxPeers: 20 } };
  let parent;
  const f = setup(t, { ...options, config: async () => multiConfig,
    session: async (make, request) => {
      const body = JSON.parse(request.body || '{}'), selected = nodes.find(n => n.id === body.sourceId) || nodes[0], session = make();
      Object.assign(session, { sourceId: selected.id, nodeId: selected.nodeId, token: session.id.repeat(2) });
      if (body.attach) Object.assign(session, { parentId: parent.id, peerId: parent.peerId }); else parent = session;
      return options.childSession && body.attach ? options.childSession(session) : session;
    } });
  f.open = a => { a.socket.open(); a.socket.message({ ...f.hello(), browserId: a.session.browserId, session: (Number.parseInt(a.session.id, 16) + 500).toString(16).padStart(32, '0') }); };
  f.add = async () => { await f.c.fillAttachments(f.c.generation); const a = [...f.c.attachments.values()].at(-1); f.open(a); return a; };
  return f;
}

test('twenty distinct Common attachments share one Worker and signal; twenty-first is not admitted', async t => {
  const f = multiSetup(t); await f.c.start(); f.open(f.c.attachments.get('native'));
  for (let i = 1; i < 20; i++) await f.add();
  assert.equal(f.c.attachments.size, 20); assert.equal(f.c.snapshot().commonConnections.filter(a => a.connected).length, 20);
  assert.equal(new Set(f.c.snapshot().commonConnections.map(a => a.nodeId)).size, 20);
  assert.equal(f.workers.length, 1); assert.equal(f.sockets.filter(s => s.url.endsWith('/signal')).length, 1);
  await f.c.fillAttachments(f.c.generation); assert.equal(f.admissions(), 20);
  const attachments = f.requests.filter(r => r.method === 'POST' && r.body && JSON.parse(r.body).attach);
  assert.equal(attachments.length, 19); assert(attachments.every(r => r.headers.Authorization === `Bearer ${f.c.session.token}`));
  const worker = f.c.worker; f.c.stop(); assert.equal(worker.terminated, 1); assert.equal(f.c.snapshot().commonConnections.length, 0); assert.equal(f.c.snapshot().nativeConnections, 0);
  assert(f.sockets.every(s => s.closes === 1));
});

test('secondary loss closes only its circuit endpoint and late callbacks cannot revive it', async t => {
  const f = multiSetup(t); await f.c.start(); f.open(f.c.attachments.get('native')); const a = await f.add(), b = await f.add();
  const worker = f.c.worker, parent = f.c.native, signal = f.c.ws, oldMessage = a.socket.onmessage;
  a.socket.onclose();
  assert.equal(f.c.attachments.size, 2); assert.equal(f.c.worker, worker); assert.equal(f.c.native, parent); assert.equal(f.c.ws, signal);
  assert.equal(b.connected, true); assert.equal(worker.terminated, 0);
  assert(worker.messages.some(m => m.type === 'nativeClose' && m.attachmentId === a.session.id));
  const before = worker.messages.length; oldMessage({ data: JSON.stringify({ ...f.hello(), browserId: a.session.browserId }) });
  assert.equal(worker.messages.length, before); assert.equal(f.c.snapshot().commonConnections.filter(a => a.connected).length, 2);
});

test('secondary renewal uses its own bearer and a delayed response after removal changes no connection', async t => {
  const response = deferred(); const f = multiSetup(t, { renew: () => response.promise }); await f.c.start(); f.open(f.c.attachments.get('native')); const a = await f.add();
  const callback = f.scheduled.findLast(row => row.ms > 120000), renewing = callback.run(); await flush();
  assert.equal(f.requests.at(-1).headers.Authorization, `Bearer ${a.session.token}`);
  const expiresAt = a.session.expiresAt; f.c.retireAttachment(a.attachmentId, 'fixture', f.c.generation);
  response.resolve({ expiresAt: expiresAt + 100000 }); await renewing;
  assert.equal(a.session.expiresAt, expiresAt); assert.equal(f.c.attachments.size, 1); assert.equal(f.c.nativeConnected, true);
});

test('OFF during a pending secondary admission cannot resurrect transports or Worker', async t => {
  const child = deferred(); const f = multiSetup(t, { childSession: () => child.promise }); await f.c.start(); f.open(f.c.attachments.get('native'));
  const adding = f.c.fillAttachments(f.c.generation); await flush(); const sockets = f.sockets.length, workers = f.workers.length;
  f.c.stop(); child.resolve({}); await adding;
  assert.equal(f.c.requested, false); assert.equal(f.c.attachments.size, 0); assert.equal(f.sockets.length, sockets); assert.equal(f.workers.length, workers);
  for (const callback of f.scheduled) await callback.run(); assert.equal(f.sockets.length, sockets);
});

test('twenty RTC peers are admitted while a twenty-first is refused; AI still suppresses negotiation', async t => {
  const f = multiSetup(t); await f.c.start();
  for (let i = 0; i < 20; i++) { const p = f.c.createPeer({ peerId: `peer-${i}`, id: `session-${i}` }, f.c.generation); assert(p); p.pc.connectionState = 'connected'; }
  assert.equal(f.c.peers.size, 20); assert.equal(f.c.createPeer({ peerId: 'peer-21', id: 'session-21' }, f.c.generation), null);
  f.c.closePeer('peer-0', false); f.c.setAiLoad('generating'); assert.equal(f.c.createPeer({ peerId: 'peer-new', id: 'new' }, f.c.generation), null);
});

test('multiple native sockets and RTC share aggregate buffered-send and ON byte budgets', async t => {
  const f = multiSetup(t); await f.c.start(); f.open(f.c.attachments.get('native'));
  for (let i = 1; i < 10; i++) await f.add();
  for (const a of f.c.attachments.values()) a.socket.bufferedAmount = 60000;
  const child = [...f.c.attachments.values()].at(-1), before = f.c.observedBytes;
  f.c.workerMessage({ type: 'send', transport: 'native', attachmentId: child.attachmentId, sendId: 'full', text: 'abc' }, f.c.generation);
  assert.equal(f.c.worker.messages.at(-1).ok, false); assert.equal(f.c.observedBytes, before);
  for (const a of f.c.attachments.values()) a.socket.bufferedAmount = 0;
  const primarySends = f.c.native.sent.length;
  f.c.workerMessage({ type: 'send', transport: 'native', attachmentId: child.attachmentId, sendId: 'child-send', text: 'opaque' }, f.c.generation);
  assert.equal(f.c.native.sent.length, primarySends); assert.equal(child.socket.sent.at(-1), 'opaque');
  assert.equal(f.c.observedBytes, before + 6);
  f.c.observedBytes = LIMIT - 1; child.socket.message({ type: 'credit', session: child.nativeSession, circuitId: 'cc'.repeat(16), seq: 1, bytes: 5 });
  assert.equal(f.c.state, 'OFF_LIMIT'); assert.equal(f.c.attachments.size, 0);
});

test('failed secondary WebSocket construction releases its lease without consuming an attachment slot', async t => {
  const f = multiSetup(t); await f.c.start(); f.open(f.c.attachments.get('native'));
  const NativeSocket = globalThis.WebSocket;
  globalThis.WebSocket = class extends NativeSocket { constructor() { throw new Error('socket allocation failed'); } };
  await f.c.fillAttachments(f.c.generation);
  assert.equal(f.c.attachments.size, 1); assert.equal(f.c.nativeConnected, true); assert.equal(f.c.worker.terminated, 0);
  assert(f.requests.some(r => r.method === 'DELETE' && r.headers.Authorization === 'Bearer ' + '2'.padStart(32, '0').repeat(2)));
  globalThis.WebSocket = NativeSocket;
});

test('signaling bursts are paced and messages for retired peer instances or OFF generations never send', async t => {
  const f = multiSetup(t); await f.c.start(); f.c.ws.open();
  const socket = f.c.ws, peer = { peerId: 'candidate' }; f.c.peers.set(peer.peerId, peer);
  for (let i = 0; i < 10; i++) assert(f.c.signal({ type: 'ice', to: peer.peerId, candidate: { candidate: 'candidate-' + i } }));
  assert.equal(socket.sent.length, 1); assert.equal(f.c.signalQueue.length, 10);
  f.c.peers.delete(peer.peerId); f.c.signalTimer = null; f.c.signalNextAt = 0; f.c.pumpSignal(f.c.generation);
  assert.equal(f.c.signalQueue.length, 0); assert.equal(f.c.signalQueueBytes, 0); assert.equal(socket.sent.length, 1);
  f.c.signal({ type: 'ping' }); const sent = socket.sent.length;
  f.c.stop(); for (const timer of f.scheduled) await timer.run();
  assert.equal(socket.sent.length, sent); assert.equal(f.c.signalQueue.length, 0);
});
