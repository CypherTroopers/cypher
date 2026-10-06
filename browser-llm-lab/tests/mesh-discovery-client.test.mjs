import test from 'node:test';
import assert from 'node:assert/strict';
import { MeshDiscoveryClient, discoveryJSON } from '../public/mesh-discovery-client.js';
import { MeshController } from '../public/mesh-controller.js';
import { createBrowserIdentity, signBrowserRecord, signSignal, verifyChallenge, publicKeyNodeId, DISCOVERY_DOMAINS } from '../public/mesh-discovery.js';
import { secp256k1, keccak_256 } from '../public/vendor/mesh-crypto.js';

const network = { chainId: 10101919, genesisHash: '0x' + '11'.repeat(32) };
const A = 'https://gateway-a.example.org', B = 'https://gateway-b.example.org';
const bytes = s => new TextEncoder().encode(s), hex = b => Buffer.from(b).toString('hex');
const id = n => n.toString(16).padStart(32, '0');
const flush = async () => { for (let i = 0; i < 35; i++) await Promise.resolve(); };
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };
function signedEndpoint(identity = createBrowserIdentity(), origin = B, now = Date.now()) {
  const payload = { version: 1, network, enode: 'enode://' + identity.publicKeyHex, sourceId: 'common-b', gatewayOrigin: origin, bootId: id(700), sequence: 1, issuedAt: now, expiresAt: now + 120000 };
  const raw = bytes(JSON.stringify(payload)), domain = bytes(DISCOVERY_DOMAINS.endpoint), input = new Uint8Array(domain.length + raw.length); input.set(domain); input.set(raw, domain.length);
  const signature = secp256k1.sign(keccak_256(input), identity.privateKey, { prehash: false, format: 'recovered', lowS: true });
  return { payloadBase64: Buffer.from(raw).toString('base64'), signatureHex: hex(signature.subarray(1)) + hex(signature.subarray(0, 1)) };
}
function record(identity, { origin = B, sessionId = id(20), now = Date.now(), lifetime = 120000 } = {}) {
  return signBrowserRecord({ network, sessionId, browserId: id(21), nodeId: '33'.repeat(32), sourceId: 'common-b', rendezvous: [origin], issuedAt: now, expiresAt: now + lifetime }, identity);
}
function fixtures(t, { bootstrap = [B], directories = {} } = {}) {
  const originals = new Map(['WebSocket', 'location', 'fetch'].map(k => [k, globalThis[k]]));
  const sockets = [], calls = [], scheduled = [], received = [], events = [];
  class Socket {
    static OPEN = 1;
    constructor(url) { this.url = String(url); this.readyState = 1; this.bufferedAmount = 0; this.sent = []; this.closes = 0; sockets.push(this); }
    send(text) { this.sent.push(JSON.parse(text)); }
    close() { this.readyState = 3; this.closes++; }
    message(message) { this.onmessage?.({ data: JSON.stringify(message) }); }
  }
  globalThis.WebSocket = Socket; globalThis.location = { origin: A, href: A + '/', protocol: 'https:' };
  globalThis.fetch = async (url, options) => { calls.push({ url: String(url), ...options }); return new Response(JSON.stringify(directories[new URL(url).origin] || { version: 1, network, endpoints: [], peers: [] })); };
  const c = {
    config: { network, discovery: { version: 1, bootstrapOrigins: bootstrap, directoryPath: '/relay/v1/mesh/discovery', rendezvousPath: '/relay/v1/mesh/rendezvous' } },
    session: { id: id(1), browserId: id(2), nodeId: '22'.repeat(32), sourceId: 'common-a', expiresAt: Date.now() + 300000 },
    generation: 1, requested: true, abort: new AbortController(), candidates: new Map(), peers: new Map(), attachments: new Map(),
    account(n) { this.total = (this.total || 0) + n; }, live(g) { return this.requested && this.generation === g; },
    later(fn, ms, g) { scheduled.push({ fn, ms, g }); }, emit(type, detail) { events.push({ type, detail }); },
    updateState() {}, scheduleAttachments() {}, peerLimit() { return 20; },
    adoptPeers(rows) { this.candidates = new Map(rows.map(row => [row.peerId, row])); }, closePeer(peerId) { this.peers.delete(peerId); },
    receiveSignal(message) { received.push(message); return Promise.resolve(); }, releaseSession(session) { this.released = session; },
    stop() { this.requested = false; this.generation++; this.abort.abort(); this.discovery?.stop(); }
  };
  const identity = createBrowserIdentity(), manager = new MeshDiscoveryClient(c, identity, 1); c.discovery = manager;
  t.after(() => { c.stop(); for (const [key, value] of originals) { if (value === undefined) delete globalThis[key]; else globalThis[key] = value; } });
  const ready = (socket, peers = []) => {
    const origin = socket.url.replace(/^wss:/u, 'https:').split('/relay/')[0], challenge = { nonce: '77'.repeat(32), origin, expiresAt: Date.now() + 5000 };
    socket.message({ type: 'challenge', ...challenge }); manager.nextSend = 0; manager.timer = null; manager.pump();
    const auth = socket.sent.find(row => row.type === 'auth'); assert.ok(auth); verifyChallenge(challenge, auth.record, auth.signatureHex, network);
    socket.message({ type: 'ready', peers, expiresAt: Date.now() + 120000 }); return auth;
  };
  return { c, manager, identity, sockets, calls, scheduled, received, events, ready };
}

test('two gateway directories verify endpoint signatures and browser introductions without native tokens', async t => {
  const common = createBrowserIdentity(), peer = createBrowserIdentity(), endpoint = signedEndpoint(common), peerRecord = record(peer);
  const f = fixtures(t, { directories: { [B]: { version: 1, network, endpoints: [endpoint], peers: [peerRecord] } } });
  f.manager.start(); await flush(); f.ready(f.sockets[0]); f.ready(f.sockets[1], [peerRecord]);
  assert.equal(f.manager.endpoints().length, 1); assert.equal(f.manager.endpoints()[0].nodeId, publicKeyNodeId(common.publicKeyHex));
  assert.equal(f.c.candidates.get(peer.peerId).id, id(20)); assert.equal(f.c.candidates.get(peer.peerId).initiator, f.identity.peerId < peer.peerId);
  assert.equal(f.manager.transport.readyState, 1); assert.ok(f.calls.every(call => !call.headers.Authorization && call.credentials === 'omit' && call.redirect === 'error'));
  assert.equal(f.sockets.length, 2);
});

test('signed SDP and ICE bind both browser generations and reject replay without killing rendezvous', async t => {
  const f = fixtures(t), peer = createBrowserIdentity(), peerRecord = record(peer);
  f.manager.start(); await flush(); f.ready(f.sockets[0]); f.ready(f.sockets[1], [peerRecord]);
  const now = Date.now(), message = signSignal({ version: 1, network, from: peer.peerId, to: f.identity.peerId, fromSessionId: id(20), toSessionId: id(1), seq: 1, type: 'offer', value: 'v=0\r\n', issuedAt: now, expiresAt: now + 30000 }, peer);
  f.sockets[1].message({ type: 'signal', record: peerRecord, message }); await flush();
  assert.equal(f.received.length, 1); assert.equal(f.received[0].sdp, 'v=0\r\n');
  f.sockets[1].message({ type: 'signal', record: peerRecord, message });
  assert.equal(f.received.length, 1); assert.equal(f.sockets[1].closes, 0);
  const forged = { ...message, signatureHex: '00'.repeat(65) };
  f.sockets[1].message({ type: 'signal', record: peerRecord, message: forged }); assert.equal(f.received.length, 1);
  const wrong = signSignal({ version: 1, network, from: peer.peerId, to: f.identity.peerId, fromSessionId: id(20), toSessionId: id(999), seq: 2, type: 'ice', value: null, issuedAt: now, expiresAt: now + 30000 }, peer);
  f.sockets[1].message({ type: 'signal', record: peerRecord, message: wrong }); assert.equal(f.received.length, 1);
});

for (const scenario of ['replacement', 'new-generation', 'current']) test(`signed negotiation failure protects ${scenario} peer ownership`, async t => {
  const f = fixtures(t), peer = createBrowserIdentity(), peerRecord = record(peer), operation = deferred();
  f.manager.start(); await flush(); f.ready(f.sockets[0]); f.ready(f.sockets[1], [peerRecord]);
  const old = { sessionId: id(20) };
  f.c.receiveSignal = () => { f.c.peers.set(peer.peerId, old); return operation.promise; };
  const now = Date.now(), message = signSignal({ version: 1, network, from: peer.peerId, to: f.identity.peerId, fromSessionId: id(20),
    toSessionId: id(1), seq: 1, type: 'offer', value: 'v=0', issuedAt: now, expiresAt: now + 30000 }, peer);
  f.sockets[1].message({ type: 'signal', record: peerRecord, message }); assert.equal(f.c.peers.get(peer.peerId), old);
  const replacement = { sessionId: id(20) };
  if (scenario !== 'current') f.c.peers.set(peer.peerId, replacement);
  if (scenario === 'new-generation') { f.c.stop(); f.c.requested = true; f.c.generation++; }
  operation.reject(new Error('old remote description rejected')); await flush();
  if (scenario === 'current') assert.equal(f.c.peers.has(peer.peerId), false, 'current failed negotiation still closes its own peer');
  else assert.equal(f.c.peers.get(peer.peerId), replacement, 'stale rejection must preserve the replacement');
});

test('signals from an adjacent valid gateway renewal use current identity without rolling the cache backwards', async t => {
  const f = fixtures(t), peer = createBrowserIdentity(), now = Date.now(), older = record(peer, { now: now - 1000 }), newer = record(peer, { now });
  f.manager.start(); await flush(); f.ready(f.sockets[0]); f.ready(f.sockets[1], [newer]);
  const message = signSignal({ version: 1, network, from: peer.peerId, to: f.identity.peerId, fromSessionId: id(20), toSessionId: id(1), seq: 1, type: 'offer', value: 'v=0', issuedAt: now, expiresAt: now + 30000 }, peer);
  f.sockets[1].message({ type: 'signal', record: older, message });
  assert.equal(f.received.length, 1); assert.equal(f.manager.records.get(peer.peerId).issuedAt, now);
  f.sockets[1].message({ type: 'signal', record: older, message }); assert.equal(f.received.length, 1);
  f.sockets[1].message({ type: 'peers', peers: [older] }); assert.equal(f.c.candidates.has(peer.peerId), true);
  assert.equal(f.manager.records.get(peer.peerId).expiresAt, now + 120000);
});

test('outgoing signals are signed to the peer lease and stale queued peer instances are discarded', async t => {
  const f = fixtures(t), peer = createBrowserIdentity(), peerRecord = record(peer);
  f.manager.start(); await flush(); f.ready(f.sockets[0]); f.ready(f.sockets[1], [peerRecord]);
  const connection = { sessionId: id(20) }; f.c.peers.set(peer.peerId, connection);
  f.manager.nextSend = Date.now() + 100000;
  assert.equal(f.manager.send({ type: 'offer', to: peer.peerId, sdp: 'v=0' }), true);
  assert.equal(f.manager.queue.length, 1); const queued = f.manager.queue[0]; assert.equal(queued.entry.origin, B);
  f.c.peers.delete(peer.peerId); f.manager.timer = null; f.manager.nextSend = 0; f.manager.pump();
  assert.equal(f.manager.queue.length, 0); assert.equal(f.sockets[1].sent.some(row => row.type === 'signal'), false);
});

test('peer departure keeps replay high-water marks until its signed lease expires', async t => {
  const f = fixtures(t), peer = createBrowserIdentity(), peerRecord = record(peer);
  f.manager.start(); await flush(); f.ready(f.sockets[0]); f.ready(f.sockets[1], [peerRecord]);
  const now = Date.now(), message = signSignal({ version: 1, network, from: peer.peerId, to: f.identity.peerId, fromSessionId: id(20), toSessionId: id(1), seq: 1, type: 'offer', value: 'v=0', issuedAt: now, expiresAt: now + 30000 }, peer);
  f.sockets[1].message({ type: 'signal', record: peerRecord, message }); assert.equal(f.received.length, 1);
  f.sockets[1].message({ type: 'peer-left', peerId: peer.peerId }); assert.equal(f.c.candidates.has(peer.peerId), false);
  f.sockets[1].message({ type: 'peers', peers: [peerRecord] });
  f.sockets[1].message({ type: 'signal', record: peerRecord, message });
  assert.equal(f.received.length, 1); assert.equal(f.c.candidates.has(peer.peerId), false);
  assert.equal(f.manager.receivedSeq.get(peer.peerId).seq, 1);
});

test('forged directory metadata cannot add an endpoint or introduce an unsigned browser', async t => {
  const endpoint = signedEndpoint(), peer = record(createBrowserIdentity());
  endpoint.signatureHex = '00'.repeat(65); peer.signatureHex = '00'.repeat(65);
  const f = fixtures(t, { directories: { [B]: { version: 1, network, endpoints: [endpoint], peers: [peer] } } });
  f.manager.start(); await flush(); assert.equal(f.manager.endpoints().length, 0); assert.equal(f.manager.records.size, 0);
});

test('a newer self-signed record cannot change its native claim within an existing browser generation', t => {
  const f = fixtures(t), peer = createBrowserIdentity(), now = Date.now(), original = record(peer, { now });
  const accepted = f.manager.acceptPeer(original); assert.ok(accepted);
  const changed = signBrowserRecord({ network, sessionId: accepted.sessionId, browserId: accepted.browserId, nodeId: '44'.repeat(32), sourceId: accepted.sourceId,
    rendezvous: [B], issuedAt: now + 1, expiresAt: now + 120000 }, peer);
  assert.equal(f.manager.acceptPeer(changed), null); assert.equal(f.manager.records.get(peer.peerId).nodeId, accepted.nodeId);
});

test('gateway introductions take priority over a full directory cache and only home gateway supplies country hints', async t => {
  const f = fixtures(t), originPeer = createBrowserIdentity(), now = Date.now(), homeRecord = record(originPeer, { origin: A });
  f.manager.start(); await flush(); f.ready(f.sockets[0]); f.ready(f.sockets[1]);
  for (let n = 0; n < 64; n++) assert(f.manager.acceptPeer(record(createBrowserIdentity(), { sessionId: id(100 + n) })));
  assert.equal(f.manager.records.size, 64);
  const geo = { countryCode: 'JP', label: 'Japan', lat: 36.2048, lon: 138.2529, accuracy: 'country' };
  f.sockets[0].message({ type: 'peers', peers: [homeRecord], peerLocations: { [originPeer.peerId]: geo } });
  assert.equal(f.manager.records.size, 64); assert.equal(f.c.candidates.size, 1); assert.equal(f.c.candidates.get(originPeer.peerId).geo.lat, 36.2048);
  f.sockets[1].message({ type: 'peers', peers: [homeRecord], peerLocations: { [originPeer.peerId]: { ...geo, lat: 1 } } });
  assert.equal(f.c.candidates.get(originPeer.peerId).geo.lat, 36.2048);
  assert.equal(f.sockets.every(socket => socket.closes === 0), true);
});

test('discovery limits catalogs, rendezvous sockets, shared request concurrency and OFF generations', async t => {
  const f = fixtures(t, { bootstrap: Array.from({ length: 8 }, (_, i) => `https://gateway-${i}.example.org`) });
  const pending = deferred(); let active = 0, peak = 0;
  globalThis.fetch = async () => { peak = Math.max(peak, ++active); await pending.promise; active--; return new Response(JSON.stringify({ version: 1, network, endpoints: [], peers: [] })); };
  f.manager.start(); await flush(); assert.equal(f.sockets.length, 4); assert.equal(peak, 2);
  const lateEvent = f.sockets[0].onmessage; f.c.stop(); pending.resolve(); await flush();
  lateEvent({ data: JSON.stringify({ type: 'ready', peers: [], expiresAt: Date.now() + 120000 }) });
  assert.equal(f.manager.sockets.size, 0); assert.equal(f.manager.records.size, 0); assert.equal(f.manager.endpoints().length, 0); assert.equal(f.c.requested, false);
  assert.equal(f.sockets.every(socket => socket.closes === 1), true);
});

test('endpoint expiry removes foreign attachment and RAM candidate without automatic resurrection', async t => {
  const f = fixtures(t), common = createBrowserIdentity(), now = Date.now();
  const endpoint = signedEndpoint(common, B, now - 119900); f.manager.cache.add(endpoint);
  const nodeId = publicKeyNodeId(common.publicKeyHex); f.c.attachments.set(id(12), { attachmentId: id(12), session: { nodeId, remoteOrigin: B } });
  f.c.retireAttachment = (key, reason) => { f.c.attachments.delete(key); f.c.retired = reason; };
  const originalNow = Date.now; Date.now = () => now + 101; f.manager.cache.now = Date.now; t.after(() => { Date.now = originalNow; });
  f.manager.tick(); assert.equal(f.manager.endpoints().length, 0); assert.equal(f.c.attachments.size, 0); assert.match(f.c.retired, /expired/u);
});

test('foreign admission completed after OFF is released at its issuing origin and creates no connection', async t => {
  const f = fixtures(t), pending = deferred();
  globalThis.fetch = async () => { await pending.promise; return new Response(JSON.stringify({ token: 'foreign-only-token', id: id(9) })); };
  const admission = discoveryJSON(f.c, B, '/sessions', { method: 'POST', body: '{}' });
  await flush(); f.c.stop(); pending.resolve(); await assert.rejects(admission, /stopped/u);
  assert.equal(f.c.released.remoteOrigin, B); assert.equal(f.c.released.token, 'foreign-only-token'); assert.equal(f.sockets.length, 0);
});

test('typed HTTPS requests reject unsafe origins, paths, oversized bodies and prevent credentials by default', async t => {
  const f = fixtures(t);
  await assert.rejects(discoveryJSON(f.c, 'http://example.org', '/config'), /HTTPS/u);
  await assert.rejects(discoveryJSON(f.c, 'https://127.0.0.1', '/config'), /private|reserved/u);
  await assert.rejects(discoveryJSON(f.c, B, '/admin'), /invalid/u);
  assert.equal(f.calls.length, 0);
  globalThis.fetch = async () => new Response(' '.repeat(100), { headers: { 'content-length': '100' } });
  await assert.rejects(discoveryJSON(f.c, B, '/config', { max: 32 }), /limit/u);
});

test('remote Common attachment uses its own origin and bearer for admission, connect, renewal and deletion', async t => {
  const saved = new Map(['location', 'fetch', 'WebSocket'].map(k => [k, globalThis[k]]));
  const common = createBrowserIdentity(), signed = signedEndpoint(common), calls = [], sockets = [], scheduled = [];
  const nodeId = publicKeyNodeId(common.publicKeyHex), primary = { id: id(1), browserId: id(2), peerId: id(3), nodeId: '11'.repeat(32), sourceId: 'common-a', token: 'primary-secret', expiresAt: Date.now() + 300000 };
  globalThis.location = { origin: A, href: A + '/', protocol: 'https:' };
  globalThis.WebSocket = class { constructor(url) { this.url = String(url); this.readyState = 1; this.bufferedAmount = 0; this.sent = []; sockets.push(this); } send(v) { this.sent.push(v); } close() { this.readyState = 3; } };
  globalThis.fetch = async (url, options) => {
    calls.push({ url: String(url), ...options });
    if (options.method === 'DELETE') return new Response(null, { status: 204 });
    if (String(url).endsWith('/config')) return new Response(JSON.stringify({ enabled: true, version: 1, protocol: 'cypher-browser-mesh/1', network, nodes: [{ id: 'common-b', nodeId, enode: 'enode://' + common.publicKeyHex }] }));
    if (String(url).endsWith('/sessions')) return new Response(JSON.stringify({ id: id(30), browserId: id(31), peerId: id(32), nodeId, sourceId: 'common-b', token: 'foreign-secret', expiresAt: Date.now() + 300000 }));
    return new Response(JSON.stringify({ expiresAt: Date.now() + 300000 }));
  };
  const c = new MeshController(); c.requested = true; c.generation = 1; c.abort = new AbortController(); c.session = primary; c.nativeConnected = true;
  c.config = { network, nodes: [{ id: 'common-a', nodeId: primary.nodeId }], limits: { maxCommonConnections: 20 } }; c.sourceErrors = {}; c.prelude = [];
  c.emit = () => {}; c.later = (fn, ms, g) => scheduled.push({ fn, ms, g });
  const identity = createBrowserIdentity(); c.config.discovery = { version: 1, bootstrapOrigins: [B], directoryPath: '/relay/v1/mesh/discovery', rendezvousPath: '/relay/v1/mesh/rendezvous' };
  c.discovery = new MeshDiscoveryClient(c, identity, 1); c.discovery.cache.add(signed);
  c.attachments.set('native', { session: primary, connected: true, socket: { readyState: 1, close() {} } });
  t.after(() => { c.stop(); for (const [k, v] of saved) { if (v === undefined) delete globalThis[k]; else globalThis[k] = v; } });
  await c.fillAttachments(1);
  assert.equal(sockets[0].url, B.replace('https:', 'wss:') + '/relay/v1/mesh/connect');
  const admission = calls.find(row => row.url.endsWith('/sessions')); assert.equal(admission.headers.Authorization, undefined); assert.equal(JSON.parse(admission.body).attach, undefined);
  sockets[0].onopen(); assert.deepEqual(JSON.parse(sockets[0].sent[0]), { token: 'foreign-secret' });
  const a = c.attachments.get(id(30)); c.renewAttachment(a, 1); await scheduled.findLast(row => row.ms > 30000).fn();
  assert.ok(calls.some(row => row.url === B + '/relay/v1/mesh/renew' && row.headers.Authorization === 'Bearer foreign-secret'));
  c.stop(); assert.ok(calls.some(row => row.url === B + '/relay/v1/mesh/sessions' && row.method === 'DELETE' && row.headers.Authorization === 'Bearer foreign-secret'));
  assert.equal(calls.filter(row => row.url.startsWith(B)).some(row => JSON.stringify(row).includes('primary-secret')), false);
});

for (const scenario of ['connect', 'wrong-identity', 'wrong-parent', 'late-off']) {
  test(`new signed Common discovered at the home origin: ${scenario}`, async t => {
    const saved = new Map(['location', 'fetch', 'WebSocket'].map(k => [k, globalThis[k]]));
    const common = createBrowserIdentity(), nodeId = publicKeyNodeId(common.publicKeyHex);
    const signed = signedEndpoint(common, A), calls = [], sockets = [], pending = deferred();
    const primary = { id: id(1), browserId: id(2), peerId: id(3), nodeId: '11'.repeat(32), sourceId: 'common-a', token: 'primary-secret', expiresAt: Date.now() + 300000 };
    const child = { id: id(40), parentId: scenario === 'wrong-parent' ? id(999) : primary.id, browserId: id(41), peerId: id(42), nodeId,
      sourceId: 'common-b', token: 'child-secret', expiresAt: Date.now() + 300000 };
    globalThis.location = { origin: A, href: A + '/', protocol: 'https:' };
    globalThis.WebSocket = class { constructor(url) { this.url = String(url); this.readyState = 1; this.bufferedAmount = 0; this.sent = []; sockets.push(this); } send(text) { this.sent.push(text); } close() { this.readyState = 3; } };
    globalThis.fetch = async (url, options) => {
      calls.push({ url: String(url), ...options });
      if (options.method === 'DELETE') return new Response(null, { status: 204 });
      if (String(url).endsWith('/config')) return new Response(JSON.stringify({ enabled: true, version: 1, protocol: 'cypher-browser-mesh/1', network,
        nodes: [{ id: child.sourceId, nodeId: scenario === 'wrong-identity' ? primary.nodeId : nodeId, enode: 'enode://' + common.publicKeyHex }] }));
      if (String(url).endsWith('/sessions')) { if (scenario === 'late-off') await pending.promise; return new Response(JSON.stringify(child)); }
      throw new Error('Unexpected request');
    };
    const c = new MeshController(); c.requested = true; c.generation = 1; c.abort = new AbortController(); c.session = primary; c.nativeConnected = true;
    c.config = { network, nodes: [{ id: primary.sourceId, nodeId: primary.nodeId }], limits: { maxCommonConnections: 20 },
      discovery: { version: 1, bootstrapOrigins: [A], directoryPath: '/relay/v1/mesh/discovery', rendezvousPath: '/relay/v1/mesh/rendezvous' } };
    c.sourceErrors = {}; c.prelude = []; c.emit = () => {}; c.later = () => {};
    c.discovery = new MeshDiscoveryClient(c, createBrowserIdentity(), 1); c.discovery.cache.add(signed);
    c.attachments.set('native', { session: primary, connected: true, socket: { readyState: 1, close() {} } });
    t.after(() => { c.stop(); for (const [k, v] of saved) { if (v === undefined) delete globalThis[k]; else globalThis[k] = v; } });
    const filling = c.fillAttachments(1);
    if (scenario === 'late-off') { await flush(); assert(calls.some(row => row.method === 'POST')); c.stop(); pending.resolve(); }
    await filling;
    assert.equal(c.config.nodes.length, 1, 'Signed discovery must work without modifying the initial pins');
    const admission = calls.find(row => row.method === 'POST');
    if (scenario === 'wrong-identity') { assert.equal(admission, undefined); assert.equal(sockets.length, 0); return; }
    assert.deepEqual(JSON.parse(admission.body), { sourceId: child.sourceId, attach: true });
    assert.equal(admission.headers.Authorization, 'Bearer primary-secret', 'Home attachment stays in its parent participation');
    if (scenario === 'connect') {
      assert.equal(sockets.length, 1); assert.equal(sockets[0].url, A.replace('https:', 'wss:') + '/relay/v1/mesh/connect');
      const a = c.attachments.get(child.id); assert.equal(a.session.endpointBootId, id(700)); assert.equal(a.session.remoteOrigin, A);
      sockets[0].onopen(); assert.deepEqual(JSON.parse(sockets[0].sent[0]), { token: child.token });
    } else {
      assert.equal(sockets.length, 0); assert.equal(c.attachments.has(child.id), false);
      assert(calls.some(row => row.method === 'DELETE' && row.headers.Authorization === 'Bearer child-secret'), 'Rejected or late leases are released');
    }
  });
}
