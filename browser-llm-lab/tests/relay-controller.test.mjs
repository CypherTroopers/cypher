import test from 'node:test';
import assert from 'node:assert/strict';
import { RelayController } from '../public/relay-controller.js';
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };
const flush = async () => { for (let i = 0; i < 8; i++) await Promise.resolve(); };
function fixture(t) {
  const originals = { WebSocket: globalThis.WebSocket, Worker: globalThis.Worker, RTCPeerConnection: globalThis.RTCPeerConnection };
  globalThis.WebSocket = class { static OPEN = 1; };
  globalThis.Worker = class {};
  globalThis.RTCPeerConnection = class {};
  t.after(() => Object.assign(globalThis, originals));
  const c = new RelayController(); c.requested = true; c.generation = 1; c.ws = { readyState: 1, close() {} }; c.aiLoad = 'idle'; c.prelude = [];
  c.updateState = () => {}; c.emit = () => {}; c.scheduled = []; c.later = (fn, ms, g) => c.scheduled.push({ fn, ms, g });
  c.attachChannel = () => {}; c.signal = message => { c.signals.push(message); return true; }; c.signals = [];
  c.candidates.set('other-browser', { peerId: 'other-browser', id: 'other-session', initiator: true, retryAt: 0, failures: 0 });
  c.createPeer = (candidate, g) => {
    const offer = deferred(), calls = [];
    const pc = { connectionState: 'new', createDataChannel() { return {}; }, createOffer: () => offer.promise,
      async setLocalDescription(value) { calls.push(value); pc.localDescription = value; }, close() { pc.connectionState = 'closed'; } };
    const peer = { peerId: candidate.peerId, sessionId: candidate.id, pc, offer, calls };
    c.peers.set(peer.peerId, peer); return peer;
  };
  t.after(() => { c.requested = false; c.stop(); }); return c;
}

test('late offer rejection from an old ON generation does not close the replacement peer', async t => {
  const c = fixture(t); c.connectNext(1); const old = c.peers.get('other-browser');
  c.stop(); c.requested = true; c.generation++; c.ws = { readyState: 1, close() {} };
  c.candidates.set('other-browser', { peerId: 'other-browser', id: 'other-session', initiator: true, retryAt: 0, failures: 0 });
  c.connectNext(c.generation); const replacement = c.peers.get('other-browser');
  old.offer.reject(new Error('old transport closed')); await flush();
  assert.equal(c.peers.get('other-browser'), replacement);
  assert.equal(replacement.pc.connectionState, 'new');
});

test('late offer rejection in the same generation cannot close a different peer instance', async t => {
  const c = fixture(t); c.connectNext(1); const old = c.peers.get('other-browser');
  c.peers.delete('other-browser'); old.pc.close(); c.connectNext(1); const replacement = c.peers.get('other-browser');
  old.offer.reject(new Error('superseded offer')); await flush();
  assert.equal(c.peers.get('other-browser'), replacement);
});

test('an offer resolved after OFF never sets local description or emits signaling', async t => {
  const c = fixture(t); c.connectNext(1); const old = c.peers.get('other-browser'); c.stop();
  old.offer.resolve({ type: 'offer', sdp: 'stale-offer' }); await flush();
  assert.equal(old.calls.length, 0); assert.equal(c.signals.length, 0); assert.equal(c.requested, false);
});

test('configuration completion after OFF cannot resurrect a Worker or create a session', async t => {
  const c = fixture(t); c.requested = false; const pending = deferred(), paths = [];
  c.json = async path => { paths.push(path); return pending.promise; };
  const started = c.start(); c.stop(); pending.resolve({ enabled: true, version: 1, sources: [{}] }); await started;
  assert.deepEqual(paths, ['/config']); assert.equal(c.worker, null); assert.equal(c.session, null); assert.equal(c.requested, false);
});

test('session renewal supplies fresh TURN configuration for the next peer connection', async t => {
  const c = fixture(t), iceServers = [{ urls: 'turn:example.invalid:3478', username: 'fresh:test-peer', credential: 'fixture-only' }];
  c.config = { limits: { renewAfterMs: 120000 } }; c.session = { id: 'session', expiresAt: Date.now() + 300000, iceServers: [{ urls: 'stun:example.invalid' }] };
  c.json = async () => ({ expiresAt: Date.now() + 300000, iceServers });
  await c.renewSession(1); assert.equal(c.scheduled.length, 1); await c.scheduled.shift().fn();
  assert.deepEqual(c.session.iceServers, iceServers);
  c.session = null;
});

test('rejected incoming negotiation cannot close a later peer instance with the same ID', async t => {
  const c = fixture(t), pending = deferred();
  const location = globalThis.location; globalThis.location = { href: 'https://relay.test/', origin: 'https://relay.test', protocol: 'https:' };
  t.after(() => { if (location === undefined) delete globalThis.location; else globalThis.location = location; });
  globalThis.WebSocket = class { static OPEN = 1; constructor() { this.readyState = 1; } close() {} };
  c.config = { signalPath: '/relay/v1/signal' }; c.session = { id: 'our-session', expiresAt: Date.now() + 300000 };
  let old;
  c.receiveSignal = async () => { old = c.createPeer(c.candidates.get('other-browser'), 1); return pending.promise; };
  c.openSignal(1); c.ws.onmessage({ data: JSON.stringify({ type: 'offer', from: 'other-browser', sdp: 'fixture-offer' }) });
  c.peers.delete(old.peerId); old.pc.close(); const replacement = c.createPeer(c.candidates.get('other-browser'), 1);
  pending.reject(new Error('superseded remote description')); await flush();
  assert.equal(c.peers.get('other-browser'), replacement);
  c.session = null;
});

test('an answer resolved after OFF cannot continue ICE or set local description', async t => {
  const c = fixture(t), answer = deferred(), create = c.createPeer;
  c.candidates.get('other-browser').initiator = false;
  c.createPeer = (candidate, g) => {
    const p = create(candidate, g); p.ice = [];
    p.pc.setRemoteDescription = async () => {};
    p.pc.createAnswer = () => answer.promise; return p;
  };
  const operation = c.receiveSignal({ type: 'offer', from: 'other-browser', sdp: 'fixture-offer' }, 1);
  const peer = c.peers.get('other-browser'); await flush(); c.stop();
  answer.resolve({ type: 'answer', sdp: 'stale-answer' }); await operation;
  assert.equal(peer.calls.length, 0); assert.equal(c.signals.length, 0);
});

test('signaling keepalive continues during AI load, respects 20 seconds and stops with the generation', t => {
  const c = fixture(t), originalNow = Date.now; let time = 20000; Date.now = () => time; t.after(() => { Date.now = originalNow; });
  c.aiLoad = 'loading'; c.lastSignalPing = 0;
  c.heartbeat(1); c.heartbeat(1); assert.deepEqual(c.signals, [{ type: 'ping' }]);
  time = 40000; c.heartbeat(1); assert.equal(c.signals.length, 2); assert.equal(c.snapshot().signalConnected, true);
  c.ws.readyState = 3; time = 60000; c.heartbeat(1); assert.equal(c.signals.length, 2); assert.equal(c.snapshot().signalConnected, false);
  c.stop(); c.heartbeat(1); assert.equal(c.signals.length, 2);
});

test('HTTP failures expose a numeric status while retaining safe messages and charging response bytes', async t => {
  const c = fixture(t), originalFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = originalFetch; });
  c.abort = new AbortController(); c.session = { token: 'fixture-token' };
  const body = 'private gateway response detail', bytes = new TextEncoder().encode(body).length;
  try {
    for (const status of [401, 503]) {
      globalThis.fetch = async () => new Response(body, { status, headers: { 'content-length': String(bytes) } });
      await assert.rejects(c.request('/status', {}, 1), error => {
        assert.equal(error.status, status); assert.equal(typeof error.status, 'number');
        assert.equal(error.message, status === 503 ? 'Gateway 503: source not ready or expired' : 'Gateway 401');
        assert.equal(error.message.includes(body), false); return true;
      });
    }
    assert.equal(c.prelude.filter(entry => entry.type === 'account').reduce((sum, entry) => sum + entry.bytes, 0), bytes * 2);
  } finally { c.session = null; }
});
