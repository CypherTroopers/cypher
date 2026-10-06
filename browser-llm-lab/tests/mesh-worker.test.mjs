import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { fixtureIdentity, meshAdvertisement, endpointAdvertisement } from './mesh-signing-fixtures.mjs';
import { MeshEngine } from '../public/mesh-worker.js';
import { MESH_PROTOCOL, MESH_LIMITS as L } from '../public/mesh-protocol.js';

const baseTime = 1780000000000;
const network = { chainId: 10101919, genesisHash: '0x' + 'f1'.repeat(32) };
const id = n => n.toString(16).padStart(32, '0');
const keyFor = name => fixtureIdentity(`worker-${name}`);
const node = name => ({ id: `common-${name}`, nodeId: keyFor(name).nodeId, publicKey: keyFor(name).publicKey });
const advertisement = (name, now = baseTime) => meshAdvertisement(keyFor(name), { network, bootId: id(name.charCodeAt(0)) }, now);

async function fixture(names = ['A', 'B'], edges = [['A', 'B']]) {
  const engines = {}, outputs = [], nativeFrames = {}, delivered = [], pending = []; let now = baseTime;
  const config = { network, nodes: names.map(node) };
  for (const name of names) {
    nativeFrames[name] = [];
    engines[name] = new MeshEngine({ now: () => now, post: message => { outputs.push({ name, at: now, ...message }); if (message.type === 'send') pending.push({ name, ...message }); } });
    await engines[name].accept({ type: 'init', config, generation: 1, identity: { peerId: `peer-${name}`, sessionId: `app-${name}`, browserId: `browser-${name}`, sourceId: `common-${name}`, nodeId: node(name).nodeId } });
    await engines[name].accept({ type: 'nativeHello', sourceId: `common-${name}`, frame: { type: 'hello', session: id(name.charCodeAt(0)), browserId: `browser-${name}`, protocol: MESH_PROTOCOL, advertisement: advertisement(name) } });
  }
  for (const [a, b] of edges) for (const [from, to] of [[a, b], [b, a]])
    await engines[from].accept({ type: 'peerOpen', peerId: `peer-${to}`, sessionId: `app-${to}`, browserId: `browser-${to}`, sourceId: `common-${to}`, nodeId: node(to).nodeId, maxMessageSize: 16384, path: 'direct' });
  async function flush(steps = 30) {
    for (let step = 0; step < steps; step++) {
      let operations = 0;
      while (pending.length) {
        assert.ok(++operations < 5000, 'No unbounded immediate send loop');
        const row = pending.shift(), frame = JSON.parse(row.text);
        await engines[row.name].accept({ type: 'sent', sendId: row.sendId, ok: true, bufferedAmount: 0 });
        if (row.transport === 'native') nativeFrames[row.name].push(frame);
        else {
          delivered.push({ name: row.name, to: row.peerId, ...frame });
          const receiver = engines[row.peerId.slice(5)];
          if (receiver?.peers.has(`peer-${row.name}`)) await receiver.accept({ type: 'peerMessage', peerId: `peer-${row.name}`, buffer: new TextEncoder().encode(row.text).buffer });
        }
      }
      if (Object.values(engines).every(engine => !engine.queue.length && !engine.ingress.length && !engine.pendingSends.size)) return;
      now += 100; for (const engine of Object.values(engines)) await engine.accept({ type: 'tick' });
    }
  }
  const sendNative = async (name, frame) => { await engines[name].accept({ type: 'nativeMessage', frame: { session: id(name.charCodeAt(0)), ...frame } }); await flush(); };
  const open = async (route = names, circuitId = id(1)) => {
    const a = route[0], b = route.at(-1);
    await sendNative(a, { type: 'open', circuitId, target: node(b).nodeId, advertisement: advertisement(a), route: route.map(n => `browser-${n}`) });
    assert.ok(nativeFrames[b].some(row => row.type === 'open' && row.circuitId === circuitId), 'Open reached its pinned native destination');
    await sendNative(b, { type: 'opened', circuitId }); return circuitId;
  };
  await flush();
  return { engines, outputs, nativeFrames, delivered, pending, flush, sendNative, open, get now() { return now; }, async advance(ms) { now += ms; for (const engine of Object.values(engines)) await engine.accept({ type: 'tick' }); await flush(); } };
}

test('direct pinned Common routing preserves encrypted bytes, native generations, hop receipts and independent credit', async () => {
  const f = await fixture(), circuitId = await f.open(), raw = Buffer.from([0, 255, 23, 40, 100]);
  await f.sendNative('A', { type: 'data', circuitId, seq: 1, data: raw.toString('base64') });
  const received = f.nativeFrames.B.find(row => row.type === 'data');
  assert.equal(received.session, id(66)); assert.equal(received.circuitId, circuitId); assert.equal(received.data, raw.toString('base64'));
  assert.equal(f.engines.A.snapshot().acknowledgedBytes, raw.length);
  assert.equal(f.engines.A.snapshot().nativeCreditBytes, 0, 'Hop receipt cannot manufacture a native credit');
  const receipt = f.engines.A.receipts[0]; assert.equal(receipt.digest, createHash('sha256').update(raw).digest('hex'));
  assert.equal(receipt.meaning, 'bounded-hop-queue-acceptance');
  await f.sendNative('B', { type: 'credit', circuitId, seq: 1, bytes: raw.length });
  assert.equal(f.engines.A.snapshot().nativeCreditBytes, raw.length);
  assert.ok(f.nativeFrames.A.some(row => row.type === 'credit' && row.session === id(65)));
  assert.equal(f.engines.A.snapshot().acknowledgedBytes, raw.length, 'Forwarded native credit does not add receipt value');
});

test('four browser route forwards both directions through RTC-to-RTC intermediaries', async () => {
  const f = await fixture(['A', 'B', 'C', 'D'], [['A', 'B'], ['B', 'C'], ['C', 'D']]), circuitId = await f.open();
  await f.sendNative('A', { type: 'data', circuitId, seq: 1, data: Buffer.from('opaque-forward').toString('base64') });
  await f.sendNative('D', { type: 'data', circuitId, seq: 1, data: Buffer.from('opaque-reverse').toString('base64') });
  assert.equal(Buffer.from(f.nativeFrames.D.find(row => row.type === 'data').data, 'base64').toString(), 'opaque-forward');
  assert.equal(Buffer.from(f.nativeFrames.A.find(row => row.type === 'data').data, 'base64').toString(), 'opaque-reverse');
  assert.equal(f.nativeFrames.B.filter(row => row.type === 'data').length, 0);
  assert.equal(f.nativeFrames.C.filter(row => row.type === 'data').length, 0);
  for (const name of ['B', 'C']) assert.equal(f.engines[name].snapshot().endpointCircuits, 0);
  assert.ok(f.engines.C.receipts.some(row => row.direction === 'reverse'));
  assert.ok(f.outputs.some(row => row.name === 'chunk_sent' && row.peerId === 'peer-C'), 'Middle-hop outgoing data has a real-send map event');
});

test('map send events require successful peer DATA submission and never count as receipts', async () => {
  const f = await fixture(), circuitId = await f.open();
  await f.engines.A.accept({ type: 'nativeMessage', frame: { session: id(65), type: 'data', circuitId, seq: 1, data: 'AQID' } });
  const row = f.pending.find(row => row.name === 'A' && row.transport === 'peer' && JSON.parse(row.text).frame?.type === 'data');
  assert.ok(row); assert.equal(f.engines.A.events.filter(row => row.name === 'chunk_sent').length, 0);
  await f.engines.A.accept({ type: 'sent', sendId: row.sendId, ok: true, bufferedAmount: 0 });
  const events = f.engines.A.events.filter(row => row.name === 'chunk_sent');
  assert.equal(events.length, 1); assert.equal(events[0].peerId, 'peer-B'); assert.equal(events[0].rawBytes, 3);
  assert.equal(events[0].meaning, 'datachannel-send-queued');
  assert.equal(f.engines.A.snapshot().acknowledgedCount, 0, 'Successful send is not reception');
  await f.engines.A.accept({ type: 'sent', sendId: row.sendId, ok: true, bufferedAmount: 0 });
  assert.equal(f.engines.A.events.filter(row => row.name === 'chunk_sent').length, 1, 'Repeated callback cannot animate twice');
  await f.flush(); assert.equal(f.engines.A.snapshot().acknowledgedCount, 1);
  assert.equal(f.engines.B.events.filter(row => row.name === 'chunk_sent').length, 0, 'Native writes and peer receipt/control messages are not peer DATA sends');
});

test('failed peer DATA sends do not emit map traffic events', async () => {
  const f = await fixture(), circuitId = await f.open();
  await f.engines.A.accept({ type: 'nativeMessage', frame: { session: id(65), type: 'data', circuitId, seq: 1, data: 'AQ==' } });
  const row = f.pending.find(row => row.name === 'A' && row.transport === 'peer' && JSON.parse(row.text).frame?.type === 'data');
  assert.ok(row); await f.engines.A.accept({ type: 'sent', sendId: row.sendId, ok: false, bufferedAmount: 0 });
  assert.equal(f.engines.A.events.filter(row => row.name === 'chunk_sent').length, 0);
  assert.equal(f.engines.A.snapshot().acknowledgedCount, 0);
});

test('hop loss closes both native ends and removes routes that use the lost browser', async () => {
  const f = await fixture(['A', 'B', 'C'], [['A', 'B'], ['B', 'C']]), circuitId = await f.open();
  await f.engines.B.accept({ type: 'peerClose', peerId: 'peer-C' });
  await f.engines.C.accept({ type: 'peerClose', peerId: 'peer-B' }); await f.flush();
  assert.equal(f.engines.B.circuits.size, 0); assert.equal(f.engines.A.circuits.size, 0); assert.equal(f.engines.C.circuits.size, 0);
  assert.ok(f.nativeFrames.A.some(row => row.type === 'close' && row.circuitId === circuitId));
  assert.ok(f.nativeFrames.C.some(row => row.type === 'close' && row.circuitId === circuitId));
  assert.equal([...f.engines.B.routes.values()].some(row => row.route.includes('browser-C')), false);
});

test('duplicate sequence and forged native credit close circuits instead of inventing stream progress', async () => {
  const f = await fixture(), circuitId = await f.open();
  await f.sendNative('A', { type: 'data', circuitId, seq: 1, data: 'AQI=' });
  await f.sendNative('B', { type: 'credit', circuitId, seq: 1, bytes: 1 });
  assert.equal(f.engines.B.circuits.size, 0); assert.equal(f.engines.A.circuits.size, 0); assert.equal(f.engines.A.snapshot().nativeCreditBytes, 0);
  const next = await f.open(['A', 'B'], id(2));
  await f.sendNative('A', { type: 'data', circuitId: next, seq: 1, data: 'AQI=' });
  await f.sendNative('A', { type: 'data', circuitId: next, seq: 1, data: 'AQI=' });
  assert.equal(f.engines.A.circuits.size, 0); assert.equal(f.engines.B.circuits.size, 0);
});

test('eight uncredited chunks are bounded; ninth chunk closes without accepting an independent receipt', async () => {
  const f = await fixture(), circuitId = await f.open();
  for (let seq = 1; seq <= 8; seq++) await f.sendNative('A', { type: 'data', circuitId, seq, data: 'AQ==' });
  assert.equal(f.engines.A.circuits.get(circuitId).forward.pending.length, 8);
  assert.equal(f.engines.A.snapshot().acknowledgedCount, 8);
  await f.sendNative('A', { type: 'data', circuitId, seq: 9, data: 'AQ==' });
  assert.equal(f.engines.A.circuits.size, 0); assert.equal(f.engines.A.snapshot().acknowledgedCount, 8);
});

test('receipt is credited once and must bind current peer session, exact hash and actual transmitted chunk', async () => {
  const f = await fixture(), circuitId = await f.open();
  await f.sendNative('A', { type: 'data', circuitId, seq: 1, data: 'AQI=' });
  const message = f.delivered.find(row => row.type === 'RECEIPT');
  const { name, to, ...wire } = message;
  await f.engines.A.accept({ type: 'peerMessage', peerId: 'peer-B', buffer: new TextEncoder().encode(JSON.stringify(wire)).buffer });
  assert.equal(f.engines.A.snapshot().acknowledgedCount, 1); assert.equal(f.engines.A.snapshot().rejectedFrames, 1);
  await f.engines.A.accept({ type: 'peerMessage', peerId: 'peer-B', buffer: new TextEncoder().encode(JSON.stringify({ ...wire, fromSessionId: 'retired' })).buffer });
  assert.equal(f.engines.A.peers.size, 0); assert.equal(f.engines.A.snapshot().acknowledgedCount, 1);
});

test('loading/benchmarking close active circuits, preserve control participation and resume with current advertisements', async () => {
  const f = await fixture(), circuitId = await f.open();
  await f.engines.A.accept({ type: 'aiLoad', state: 'loading' }); await f.flush();
  assert.equal(f.engines.A.circuits.size, 0); assert.equal(f.engines.A.peers.size, 1); assert.equal(f.engines.A.snapshot().paused, true);
  assert.ok(f.nativeFrames.B.some(row => row.type === 'close' && row.circuitId === circuitId));
  await f.sendNative('A', { type: 'open', circuitId: id(9), target: node('B').nodeId, advertisement: advertisement('A'), route: ['browser-A', 'browser-B'] });
  assert.equal(f.engines.A.circuits.size, 0);
  await f.engines.A.accept({ type: 'aiLoad', state: 'idle' }); await f.flush(); await f.open(['A', 'B'], id(10));
  await f.engines.A.accept({ type: 'aiLoad', state: 'benchmarking' }); assert.equal(f.engines.A.circuits.size, 0);
});

test('generating retains only one circuit and uses explicit 24/32 KiB JSON scheduling', async () => {
  const f = await fixture(); await f.open(['A', 'B'], id(1)); await f.open(['A', 'B'], id(2));
  assert.equal(f.engines.A.circuits.size, 2);
  await f.engines.A.accept({ type: 'aiLoad', state: 'generating' }); await f.flush();
  assert.equal(f.engines.A.circuits.size, 1); assert.equal(f.engines.A.sendBucket.rate, 24576); assert.equal(f.engines.A.receiveBucket.rate, 32768);
  assert.equal(f.engines.A.sendBucket.burst, 16384);
});

test('stale native generation fails closed and OFF purges opaque state immediately', async () => {
  const f = await fixture(); await f.open();
  await f.engines.A.accept({ type: 'nativeMessage', frame: { type: 'close', session: id(999), circuitId: id(1), reason: 'closed' } });
  assert.equal(f.engines.A.active, false); assert.equal(f.engines.A.circuits.size, 0);
  await f.engines.B.accept({ type: 'stop', reason: 'hidden' }); assert.equal(f.engines.B.active, false);
  assert.equal(f.engines.B.routes.size, 0); assert.equal(f.engines.B.queue.length, 0); assert.equal(f.engines.B.receipts.length, 0);
});

test('ON-session byte budget survives readmission and stops exactly at exhausted allowance', async () => {
  const out = [], engine = new MeshEngine({ post: row => out.push(row) });
  await engine.accept({ type: 'init', generation: 7, config: { network, nodes: [node('A')] }, identity: { peerId: 'peer-A', sessionId: 'app-A', browserId: 'browser-A', sourceId: 'common-A', nodeId: node('A').nodeId }, initialTotalBytes: L.transferBytes - 10 });
  await engine.accept({ type: 'account', bytes: 10, direction: 'in', kind: 'signal' });
  assert.equal(engine.active, false); assert.ok(out.some(row => row.type === 'event' && row.code === 'transfer_limit' && row.fatal));
  assert.equal(out.at(-1).reason, 'limit');
});

test('future advertisement expiry and circuit TTL do not retain stale route hints or circuits', async () => {
  const f = await fixture(), circuitId = await f.open();
  f.engines.A.circuits.get(circuitId).expiresAt = f.now + 1;
  await f.advance(2); assert.equal(f.engines.A.circuits.size, 0); assert.equal(f.engines.B.circuits.size, 0);
  for (const row of f.engines.A.routes.values()) row.payload.expiresAt = f.now;
  await f.engines.A.accept({ type: 'tick' }); assert.equal(f.engines.A.routes.size, 0);
});

test('full eight-chunk native burst is scheduled under JSON rates without dropping or reordering opaque bytes', async () => {
  const f = await fixture(), circuitId = await f.open(), firstOutput = f.outputs.length, started = f.now;
  for (let seq = 1; seq <= 8; seq++) await f.engines.A.accept({ type: 'nativeMessage', frame: {
    type: 'data', session: id(65), circuitId, seq, data: Buffer.alloc(8192, seq).toString('base64') } });
  assert.ok(f.engines.A.bufferBytes() <= L.queueBytes); assert.ok(f.engines.A.appBytes() <= L.appBytes);
  await f.flush(100);
  const chunks = f.nativeFrames.B.filter(row => row.type === 'data'); assert.equal(chunks.length, 8);
  chunks.forEach((row, index) => { assert.equal(row.seq, index + 1); assert.deepEqual(Buffer.from(row.data, 'base64'), Buffer.alloc(8192, index + 1)); });
  assert.equal(f.engines.A.snapshot().acknowledgedBytes, 65536);
  for (const name of ['A', 'B']) {
    let sent = 0;
    for (const row of f.outputs.slice(firstOutput).filter(row => row.name === name && row.type === 'send')) {
      sent += Buffer.byteLength(row.text);
      assert.ok(sent <= 16384 + 49152 * (row.at - started) / 1000, 'Actual JSON emission stays within token-bucket envelope');
    }
  }
});

test('OFF during asynchronous chunk hashing cannot resurrect a circuit or acknowledge data', async () => {
  const f = await fixture(), circuitId = await f.open(), original = crypto.subtle.digest.bind(crypto.subtle);
  let release, entered;
  const started = new Promise(resolve => { entered = resolve; });
  crypto.subtle.digest = async (...args) => { entered(); await new Promise(resolve => { release = resolve; }); return original(...args); };
  try {
    const work = f.engines.A.accept({ type: 'nativeMessage', frame: { type: 'data', session: id(65), circuitId, seq: 1, data: 'AQI=' } });
    await started; const before = f.outputs.length; await f.engines.A.accept({ type: 'stop', reason: 'off' }); release(); await work;
    assert.equal(f.engines.A.circuits.size, 0); assert.equal(f.engines.A.queue.length, 0);
    assert.equal(f.outputs.slice(before).some(row => row.name === 'A' && row.type === 'send'), false);
  } finally { crypto.subtle.digest = original; }
});

test('delayed heartbeat keeps one outstanding nonce instead of rejecting its eventual matching response', async () => {
  const f = await fixture();
  const peer = f.engines.A.peers.get('peer-B'); peer.ping = id(999); peer.lastPing = f.now - 6000;
  await f.engines.A.accept({ type: 'tick' }); assert.equal(peer.ping, id(999));
  assert.equal(f.outputs.some(row => row.name === 'A' && row.type === 'send' && JSON.parse(row.text).type === 'PING'), false);
  await f.engines.A.accept({ type: 'peerMessage', peerId: 'peer-B', buffer: new TextEncoder().encode(JSON.stringify({ type: 'PONG', v: 1, fromSessionId: 'app-B', toSessionId: 'app-A', nonce: id(999) })).buffer });
  assert.equal(f.engines.A.peers.size, 1); assert.ok(peer.ping !== id(999));
});

test('native target receives fresh source advertisement immediately before open even after its candidate was evicted', async () => {
  const f = await fixture();
  // Native Dial removes a candidate after a failed outbound open, while the
  // browser may retain the same valid advertisement. Model that independent
  // native state reset without changing either browser's routing cache.
  f.nativeFrames.B.length = 0;
  const circuitId = await f.open();
  const index = f.nativeFrames.B.findIndex(frame => frame.type === 'open' && frame.circuitId === circuitId);
  assert.ok(index > 0, 'A remembered browser route alone cannot satisfy the native prerequisite');
  const prior = f.nativeFrames.B[index - 1], open = f.nativeFrames.B[index];
  assert.equal(prior.type, 'advertisement'); assert.equal(prior.session, id(66));
  assert.deepEqual(prior.route, open.route); assert.deepEqual(prior.advertisement, open.advertisement);
  assert.equal(prior.advertisement.payloadBase64, advertisement('A').payloadBase64, 'Signed raw payload is preserved');
});

const modernLimits = { maxSessions: 80, nativePeers: 40, circuits: 40, circuitsPerSession: 40, pendingInbound: 4, pendingOutbound: 4 };
// These are distinct operator-pinned fixture identities and exact opaque ad bytes.
// Signatures are encoding fixtures, not native authenticity evidence (Go/live tests
// retain that boundary); no private method is used to insert circuits or routes.
async function capacityFixture(nativeLimits = modernLimits) {
  const pins = Array.from({ length: 44 }, (_, n) => ({ id: `common-${n}`, nodeId: keyFor(`capacity-${n}`).nodeId, publicKey: keyFor(`capacity-${n}`).publicKey }));
  const nowStart = baseTime, pending = [], sent = [], events = []; let now = nowStart;
  const ad = n => meshAdvertisement(keyFor(`capacity-${n}`), { network, bootId: id(n + 1) }, nowStart);
  const engine = new MeshEngine({ now: () => now, post(row) { if (row.type === 'send') pending.push(row); if (row.type === 'event') events.push(row); } });
  await engine.accept({ type: 'init', config: { network, nodes: pins }, nativeLimits, generation: 1, identity: { peerId: 'peer-R', sessionId: 'app-R', browserId: 'browser-R', sourceId: pins[0].id, nodeId: pins[0].nodeId } });
  await engine.accept({ type: 'nativeHello', frame: { type: 'hello', session: id(100), browserId: 'browser-R', protocol: MESH_PROTOCOL, advertisement: ad(0) } });
  async function peerMessage(side, message) { await engine.accept({ type: 'peerMessage', peerId: `peer-${side}`, buffer: new TextEncoder().encode(JSON.stringify(message)).buffer }); }
  const envelope = (side, type, fields) => ({ type, v: 1, fromSessionId: `app-${side}`, toSessionId: 'app-R', ...fields });
  async function input(endpoint, frame) {
    if (endpoint === 'native') await engine.accept({ type: 'nativeMessage', frame: { ...frame, session: id(100) } });
    else await peerMessage(endpoint, envelope(endpoint, 'FRAME', { frame: { ...frame, session: id(200) }, receipt: null }));
  }
  let autoOpen = true;
  async function flush() {
    for (let loops = 0; loops < 2000; loops++) {
      while (pending.length) {
        const row = pending.shift(), message = JSON.parse(row.text), side = row.peerId?.slice(5); sent.push(row);
        await engine.accept({ type: 'sent', sendId: row.sendId, ok: true, bufferedAmount: 0 });
        if (message.type === 'PING') await peerMessage(side, envelope(side, 'PONG', { nonce: message.nonce }));
        const frame = row.transport === 'native' ? message : message.frame;
        if (autoOpen && frame?.type === 'open') await input(row.transport === 'native' ? 'native' : side, { type: 'opened', circuitId: frame.circuitId });
      }
      if (!engine.queue.length && !engine.ingress.length && !engine.pendingSends.size) return;
      now += 100; await engine.accept({ type: 'tick' });
    }
    assert.fail('Bounded fixture failed to drain');
  }
  async function connect(side) {
    await engine.accept({ type: 'peerOpen', peerId: `peer-${side}`, sessionId: `app-${side}`, browserId: `browser-${side}`, maxMessageSize: L.frameBytes });
    await peerMessage(side, { type: 'HELLO', v: 1, network, peerId: `peer-${side}`, sessionId: `app-${side}`, browserId: `browser-${side}` }); await flush();
  }
  for (const side of ['left', 'right']) await connect(side);
  for (let n = 1; n <= 42; n++) {
    await input('left', { type: 'advertisement', advertisement: ad(n), route: ['browser-left'] }); await flush();
    await input('right', { type: 'advertisement', advertisement: ad(n), route: ['browser-right'] }); await flush();
  }
  async function open(n, kind = 'inbound', serial = n) {
    const route = kind === 'inbound' ? ['browser-left', 'browser-R'] : kind === 'outbound' ? ['browser-R', 'browser-right'] : ['browser-left', 'browser-R', 'browser-right'];
    const circuitId = id(1000 + serial);
    await input(kind === 'outbound' ? 'native' : 'left', { type: 'open', circuitId, target: pins[kind === 'inbound' ? 0 : 43 - n].nodeId, advertisement: ad(kind === 'outbound' ? 0 : n), route }); await flush();
    return circuitId;
  }
  return { engine, pins, events, sent, pending, ad, input, flush, open, connect, set autoOpen(value) { autoOpen = value; }, get now() { return now; },
    async advance(ms) { now += ms; await engine.accept({ type: 'tick' }); await flush(); } };
}

test('40 distinct pinned source circuits fit unchanged application reserve; 41st rejects and freed slot is reused', async t => {
  const f = await capacityFixture();
  for (let n = 1; n <= 40; n++) { await f.open(n); assert.equal(f.engine.circuits.size, n); }
  const stats = f.engine.snapshot();
  assert.equal(new Set([...f.engine.circuits.values()].map(c => c.sourceNodeId)).size, 40);
  t.diagnostic(`40 admitted endpoint circuits: app reservation ${stats.appBytes} / ${L.appBytes} bytes; routes ${stats.routes}; queue ${stats.queuedBytes} / ${L.queueBytes}`);
  assert.equal(stats.endpointCircuits, 40); assert.equal(stats.capacities.endpointCircuits, 40); assert.ok(stats.appBytes < L.appBytes);
  assert.equal(f.engine.sendBucket.rate, 49152); assert.equal(f.engine.receiveBucket.rate, 65536);
  await f.open(41); assert.equal(f.engine.circuits.size, 40);
  assert.ok(f.sent.some(row => JSON.parse(row.text).frame?.reason === 'capacity'));
  await f.input('native', { type: 'close', circuitId: id(1001), reason: 'closed' }); await f.flush();
  await f.open(41, 'inbound', 141); assert.equal(f.engine.circuits.size, 40);
  await f.engine.accept({ type: 'peerClose', peerId: 'peer-left' }); await f.flush();
  assert.equal(f.engine.circuits.size, 0); assert.equal(f.engine.pendingReceipts.size, 0); assert.equal(f.engine.queuedBytes, 0);
});

test('endpoint and transit circuits share 40 slots including pending opens; old Common cap remains independent', async () => {
  const f = await capacityFixture();
  for (let n = 1; n <= 20; n++) await f.open(n);
  for (let n = 21; n <= 39; n++) await f.open(n, 'transit');
  f.autoOpen = false; await f.open(40, 'transit');
  const stats = f.engine.snapshot(); assert.equal(stats.circuits, 40); assert.equal(stats.endpointCircuits, 20); assert.equal(stats.transitCircuits, 20); assert.equal(stats.pendingHandshakes, 1);
  await f.open(41); assert.equal(f.engine.circuits.size, 40);
  await f.advance(L.openTimeout); assert.equal(f.engine.circuits.size, 39);
  f.autoOpen = true; await f.open(41); assert.equal(f.engine.circuits.size, 40);
  const legacy = await capacityFixture({ maxSessions: 8, nativePeers: 4, circuits: 8, circuitsPerSession: 2, pendingInbound: 4, pendingOutbound: 4 });
  await legacy.open(1); await legacy.open(2); await legacy.open(3);
  assert.equal(legacy.engine.snapshot().endpointCircuits, 2); assert.equal(legacy.engine.snapshot().capacities.endpointCircuits, 2);
  await legacy.open(4, 'transit'); assert.equal(legacy.engine.circuits.size, 3, 'Transit does not use attached Common endpoint allowance');
});

test('pending handshakes admit four in each native direction with a shared eight ceiling and timeout recovery', async () => {
  const f = await capacityFixture(); f.autoOpen = false;
  for (let n = 1; n <= 4; n++) await f.open(n);
  await f.open(5); assert.equal(f.engine.pendingCount(), 4);
  for (let n = 6; n <= 9; n++) await f.open(n, 'outbound');
  assert.equal(f.engine.pendingCount(), 8); assert.equal(f.engine.snapshot().pendingInbound, 4); assert.equal(f.engine.snapshot().pendingOutbound, 4);
  await f.open(10, 'transit'); assert.equal(f.engine.pendingCount(), 8);
  await f.advance(L.openTimeout); assert.equal(f.engine.circuits.size, 0);
  f.autoOpen = true; await f.open(11); assert.equal(f.engine.circuits.size, 1);
});

test('40-circuit AI transition retires an overloaded hop instead of dropping close frames, then reconnects within one-circuit cap', async () => {
  const f = await capacityFixture(); for (let n = 1; n <= 40; n++) await f.open(n);
  await f.engine.accept({ type: 'aiLoad', state: 'generating' }); await f.flush();
  assert.equal(f.engine.circuits.size, 0); assert.equal(f.engine.active, true); assert.equal(f.engine.snapshot().capacities.circuits, 1); assert.equal(f.engine.snapshot().capacities.endpointCircuits, 1);
  assert.equal(f.engine.sendBucket.rate, 24576); assert.equal(f.engine.receiveBucket.rate, 32768);
  assert.ok(f.engine.queue.length + f.engine.pendingSends.size <= 64); assert.ok(f.engine.bufferBytes() <= 512 * 1024);
  assert.ok(f.events.some(row => row.name === 'peer_closed' && row.reason === 'close-queue-full'));
  const nativeCloses = f.sent.filter(row => row.transport === 'native' && JSON.parse(row.text).type === 'close');
  assert.equal(new Set(nativeCloses.map(row => JSON.parse(row.text).circuitId)).size, 40);
  await f.connect('left');
  await f.input('left', { type: 'advertisement', advertisement: f.ad(41), route: ['browser-left'] }); await f.flush();
  await f.open(41); assert.equal(f.engine.circuits.size, 1);
  await f.engine.accept({ type: 'aiLoad', state: 'loading' }); await f.flush();
  assert.equal(f.engine.circuits.size, 0); assert.equal(f.engine.snapshot().capacities.circuits, 0);
  await f.engine.accept({ type: 'aiLoad', state: 'idle' }); await f.flush();
  assert.equal(f.engine.snapshot().capacities.endpointCircuits, 40); await f.open(41, 'inbound', 141); assert.equal(f.engine.circuits.size, 1);
  await f.engine.accept({ type: 'stop', reason: 'hidden' });
  await f.input('native', { type: 'opened', circuitId: id(1041) }); await f.flush();
  assert.equal(f.engine.active, false); assert.equal(f.engine.circuits.size, 0); assert.equal(f.engine.pendingSends.size, 0);
});


test('128 hop receipt budget includes parallel send reservations, then timeout frees all affected circuits', async () => {
  const f = await capacityFixture();
  for (let n = 1; n <= 40; n++) await f.open(n, n <= 20 ? 'inbound' : 'outbound');
  for (let i = 0; i < 127; i++) {
    await f.input('native', { type: 'data', circuitId: id(1001 + i % 40), seq: Math.floor(i / 40) + 1, data: 'AQ==' }); await f.flush();
  }
  assert.equal(f.engine.pendingReceipts.size, 127);
  // Parallel receipt reservation needs scheduler tokens; ad fanout now drains faster.
  await f.advance(100);
  await f.input('native', { type: 'data', circuitId: id(1008), seq: 4, data: 'AQ==' });
  await f.input('native', { type: 'data', circuitId: id(1021), seq: 4, data: 'AQ==' });
  const awaitingSend = [...f.engine.pendingSends.values()].filter(row => row.receipt).length;
  assert.equal(f.engine.pendingReceipts.size + awaitingSend, L.hopReceipts);
  assert.equal(f.engine.queue.filter(row => row.receipt).length, 1, 'A second endpoint cannot reserve receipt 129');
  while (f.pending.length) { const row = f.pending.shift(); await f.engine.accept({ type: 'sent', sendId: row.sendId, ok: true, bufferedAmount: 0 }); }
  assert.equal(f.engine.pendingReceipts.size, 128);
  await f.advance(15001);
  assert.equal(f.engine.pendingReceipts.size, 0); assert.equal(f.engine.circuits.size, 0);
  assert.equal(f.engine.snapshot().acknowledgedCount, 0, 'Timeout is never presented as receipt');
  assert.ok(f.events.some(row => row.name === 'circuit_closed' && row.reason === 'receipt-timeout'));
  assert.ok(f.engine.bufferBytes() <= L.queueBytes); assert.ok(f.engine.appBytes() <= L.appBytes);
});

// Twenty sockets are a transport fanout of one browser, never twenty workers or
// budgets. Native browser labels differ per lease; RTC always uses browser-R.
async function multiAttachmentFixture({ localCount = 20, peerCount = 20, peerAds = true } = {}) {
  const pins = Array.from({ length: 42 }, (_, n) => ({ id: `source-${n}`, nodeId: keyFor(`multi-${n}`).nodeId, publicKey: keyFor(`multi-${n}`).publicKey }));
  let now = baseTime, autoOpen = true;
  const pending = [], sent = [], events = [], peak = { appBytes: 0, queuedBytes: 0, frames: 0, pendingAdvertisements: 0 };
  const ad = (n, issuedAt = baseTime) => meshAdvertisement(keyFor(`multi-${n}`), { network, bootId: id(n + 1) }, issuedAt);
  const attachmentId = n => n === 0 ? undefined : `attach-${n}`;
  const browserId = n => n === 0 ? 'browser-R' : `local-browser-${n}`;
  const engine = new MeshEngine({ now: () => now, post(row) { if (row.type === 'send') pending.push({ ...row, at: now }); if (row.type === 'event' || row.type === 'disconnect') events.push(row); } });
  await engine.accept({ type: 'init', generation: 9, nativeLimits: modernLimits, config: { network, nodes: pins }, identity: { peerId: 'peer-R', sessionId: 'app-R', browserId: 'browser-R', sourceId: pins[0].id, nodeId: pins[0].nodeId } });
  const sample = () => {
    const stats = engine.snapshot();
    peak.appBytes = Math.max(peak.appBytes, stats.appBytes); peak.queuedBytes = Math.max(peak.queuedBytes, stats.queuedBytes);
    peak.frames = Math.max(peak.frames, engine.queue.length + engine.pendingSends.size); peak.pendingAdvertisements = Math.max(peak.pendingAdvertisements, stats.pendingAdvertisements);
    assert.ok(stats.appBytes <= L.appBytes); assert.ok(stats.queuedBytes <= L.queueBytes); assert.ok(peak.frames <= L.queueFrames);
  };
  async function attach(n, changes = {}) { await engine.accept({ type: 'nativeHello', attachmentId: attachmentId(n), browserId: browserId(n), sourceId: pins[n].id, nodeId: pins[n].nodeId, nativeLimits: modernLimits,
    frame: { type: 'hello', session: id(1000 + n), browserId: browserId(n), protocol: MESH_PROTOCOL, advertisement: ad(n) }, ...changes }); sample(); }
  async function nativeInput(n, frame) { await engine.accept({ type: 'nativeMessage', attachmentId: attachmentId(n), frame: { session: id(1000 + n), ...frame } }); sample(); }
  const envelope = (n, type, values) => ({ type, v: 1, fromSessionId: `remote-session-${n}`, toSessionId: 'app-R', ...values });
  async function peerMessage(n, message) { await engine.accept({ type: 'peerMessage', peerId: `remote-${n}`, buffer: new TextEncoder().encode(JSON.stringify(message)).buffer }); sample(); }
  async function peerInput(n, frame, receipt = null) { await peerMessage(n, envelope(n, 'FRAME', { frame: { session: id(2000 + n), ...frame }, receipt })); }
  async function connect(n) {
    await engine.accept({ type: 'peerOpen', peerId: `remote-${n}`, sessionId: `remote-session-${n}`, browserId: `remote-browser-${n}`, maxMessageSize: L.frameBytes });
    await peerMessage(n, { type: 'HELLO', v: 1, network, peerId: `remote-${n}`, sessionId: `remote-session-${n}`, browserId: `remote-browser-${n}` });
  }
  async function flush() {
    for (let steps = 0; steps < 1500; steps++) {
      let processed = 0;
      while (pending.length) {
        assert.ok(++processed < 10000);
        const row = pending.shift(), message = JSON.parse(row.text), n = row.transport === 'native' ? Number(row.attachmentId?.slice(7) || 0) : Number(row.peerId.slice(7));
        sent.push(row); await engine.accept({ type: 'sent', sendId: row.sendId, ok: true, bufferedAmount: 0 }); sample();
        if (message.type === 'PING') await peerMessage(n, envelope(n, 'PONG', { nonce: message.nonce }));
        const frame = row.transport === 'native' ? message : message.frame;
        if (autoOpen && frame?.type === 'open') {
          if (row.transport === 'native') await nativeInput(n, { type: 'opened', circuitId: frame.circuitId });
          else await peerInput(n, { type: 'opened', circuitId: frame.circuitId });
        }
        if (message.receipt) await peerMessage(n, envelope(n, 'RECEIPT', { receipt: message.receipt }));
      }
      const stats = engine.snapshot();
      if (!engine.queue.length && !engine.ingress.length && !engine.pendingSends.size && !stats.pendingAdvertisements) return;
      now += 100; await engine.accept({ type: 'tick' }); sample();
    }
    assert.fail('Multi-attachment fixture did not drain within its bounded deadline');
  }
  for (let n = 0; n < localCount; n++) await attach(n);
  for (let n = 0; n < peerCount; n++) await connect(n);
  // The remote browser can attach to the very same pinned Commons. These hints
  // must reach other local Commons even while each source also has a local socket.
  if (peerAds) for (let n = 0; n < peerCount; n++) await peerInput(n, { type: 'advertisement', advertisement: ad(n), route: [`remote-browser-${n}`] });
  await flush();
  async function open(n, serial = n, inbound = false, target = (n + 1) % localCount) {
    const circuitId = id(5000 + serial);
    const frame = { type: 'open', circuitId, target: pins[target].nodeId, advertisement: ad(n), route: inbound ? [`remote-browser-${n}`, 'browser-R'] : [browserId(n), `remote-browser-${target}`] };
    if (inbound) await peerInput(n, frame); else await nativeInput(n, frame);
    await flush(); return circuitId;
  }
  return { engine, pins, pending, sent, events, peak, ad, attach, connect, nativeInput, peerInput, peerMessage, envelope, flush, open, browserId, attachmentId,
    get now() { return now; }, set autoOpen(value) { autoOpen = value; }, async advance(ms) { now += ms; await engine.accept({ type: 'tick' }); await flush(); } };
}

test('20 distinct Common attachments and 20 direct RTC peers fit one Worker; 21st and duplicate pins reject independently', async t => {
  const f = await multiAttachmentFixture();
  const stats = f.engine.snapshot();
  assert.equal(stats.nativeConnections, 20); assert.equal(stats.connectedPeers, 20); assert.equal(stats.capacities.circuits, 40);
  assert.equal(stats.capacities.peers, 20); assert.equal(stats.capacities.nativeConnections, 20);
  assert.equal(stats.capacities.sendBytesPerSecond, 49152); assert.equal(stats.capacities.receiveBytesPerSecond, 65536);
  await f.attach(20); await f.connect(20);
  assert.equal(f.engine.locals.size, 20); assert.equal(f.engine.peers.size, 20); assert.equal(f.engine.active, true);
  assert.ok(f.events.some(row => row.type === 'disconnect' && row.attachmentId === 'attach-20' && row.reason === 'capacity'));
  assert.ok(f.events.some(row => row.type === 'disconnect' && row.peerId === 'remote-20'));
  const ads = f.sent.filter(row => (row.transport === 'native' ? JSON.parse(row.text) : JSON.parse(row.text).frame)?.type === 'advertisement');
  const rtcAds = ads.filter(row => row.transport === 'peer'), nativeAds = ads.filter(row => row.transport === 'native');
  assert.equal(rtcAds.length, 400, 'Each canonical local source reaches all twenty peers exactly once');
  assert.equal(nativeAds.length, 380, 'Each remote source reaches nineteen other local Commons');
  assert.ok(f.peak.pendingAdvertisements > L.queueFrames, 'Fanout is coalesced as bounded references, not queued JSON');
  assert.ok(f.now - baseTime < 30000, '780 control advertisements drain before the next 30-second refresh');
  let sentBytes = 0;
  for (const row of f.sent) { sentBytes += Buffer.byteLength(row.text); assert.ok(sentBytes <= L.frameBytes + 24576 * (row.at - baseTime) / 1000, 'Actual control emissions respect their share of the shared send budget'); }
  t.diagnostic(`20x20 fixture: ${rtcAds.length} RTC + ${nativeAds.length} native ads, ${sentBytes} JSON bytes, ${f.now - baseTime} ms simulated; peak app ${f.peak.appBytes}/${L.appBytes}, queue ${f.peak.queuedBytes}/${L.queueBytes}, frames ${f.peak.frames}/${L.queueFrames}, pending ad refs ${f.peak.pendingAdvertisements}`);
  await f.engine.accept({ type: 'nativeClose', attachmentId: 'attach-19' });
  await f.attach(20, { sourceId: f.pins[1].id, nodeId: f.pins[1].nodeId, frame: { type: 'hello', session: id(9999), browserId: 'new-browser', protocol: MESH_PROTOCOL, advertisement: f.ad(1) }, browserId: 'new-browser' });
  assert.equal(f.engine.locals.size, 19, 'A second socket to the same pinned Common does not consume another attachment');
});

test('twenty distinct local sources use canonical RTC routes while target attachments retain exact signed advertisement bytes', async () => {
  const f = await multiAttachmentFixture();
  for (let n = 0; n < 20; n++) await f.open(n);
  for (let n = 0; n < 20; n++) await f.open(n, 100 + n, true);
  assert.equal(f.engine.circuits.size, 40); assert.equal(new Set([...f.engine.circuits.values()].map(c => c.sourceNodeId)).size, 20);
  for (let n = 0; n < 20; n++) {
    const outgoing = f.sent.find(row => row.transport === 'peer' && JSON.parse(row.text).frame?.circuitId === id(5000 + n) && JSON.parse(row.text).frame.type === 'open');
    const frame = JSON.parse(outgoing.text).frame;
    assert.deepEqual(frame.route, ['browser-R', `remote-browser-${(n + 1) % 20}`]); assert.deepEqual(frame.advertisement, f.ad(n));
    const incoming = f.sent.find(row => row.transport === 'native' && JSON.parse(row.text).type === 'open' && JSON.parse(row.text).circuitId === id(5100 + n));
    assert.equal(incoming.attachmentId, f.attachmentId((n + 1) % 20));
    const nativeFrame = JSON.parse(incoming.text); assert.deepEqual(nativeFrame.route, [`remote-browser-${n}`, f.browserId((n + 1) % 20)]);
    assert.deepEqual(nativeFrame.advertisement, f.ad(n)); assert.equal(nativeFrame.session, id(1000 + (n + 1) % 20));
    // Other independent sockets and heartbeat frames may progress concurrently.
    // Ordering is required on this native destination, not across all sockets.
    const previous = f.sent.slice(0, f.sent.indexOf(incoming)).findLast(row => row.transport === 'native' && row.attachmentId === incoming.attachmentId);
    assert.equal(JSON.parse(previous.text).type, 'advertisement'); assert.deepEqual(JSON.parse(previous.text).advertisement, f.ad(n));
  }
  for (let n = 0; n < 20; n++) {
    const raw = Buffer.from(`opaque-source-${n}`), data = raw.toString('base64');
    await f.nativeInput(n, { type: 'data', circuitId: id(5000 + n), seq: 1, data }); await f.flush();
    const outgoing = f.sent.find(row => row.transport === 'peer' && JSON.parse(row.text).frame?.type === 'data' && JSON.parse(row.text).frame.circuitId === id(5000 + n));
    assert.equal(JSON.parse(outgoing.text).frame.data, data); assert.equal(outgoing.peerId, `remote-${(n + 1) % 20}`);
    const receipt = { requestId: id(9000 + n), circuitId: id(5100 + n), seq: 1, direction: 'forward', digest: createHash('sha256').update(raw).digest('hex'), rawBytes: raw.length };
    await f.peerInput(n, { type: 'data', circuitId: id(5100 + n), seq: 1, data }, receipt); await f.flush();
    const incoming = f.sent.find(row => row.transport === 'native' && JSON.parse(row.text).type === 'data' && JSON.parse(row.text).circuitId === id(5100 + n));
    assert.equal(JSON.parse(incoming.text).data, data); assert.equal(incoming.attachmentId, f.attachmentId((n + 1) % 20));
  }
  assert.equal(f.engine.snapshot().acknowledgedCount, 20, 'Each native source has a distinct confirmed RTC hop send');
  await f.open(1, 999); assert.equal(f.engine.circuits.size, 40, 'Forty endpoint circuits share a global ceiling across attachments');
  await f.engine.accept({ type: 'aiLoad', state: 'generating' }); await f.flush();
  assert.ok(f.engine.circuits.size <= 1); assert.equal(f.engine.snapshot().capacities.circuits, 1); assert.equal(f.engine.sendBucket.rate, 24576);
  await f.engine.accept({ type: 'aiLoad', state: 'loading' }); await f.flush();
  assert.equal(f.engine.circuits.size, 0); assert.equal(f.engine.snapshot().capacities.endpointCircuits, 0);
});

test('secondary close reclaims its circuit, queued data and routes without affecting another Common or RTC; retired generation never revives', async () => {
  const f = await multiAttachmentFixture({ localCount: 3, peerCount: 3 });
  const first = await f.open(0), second = await f.open(1), third = await f.open(2);
  await f.engine.accept({ type: 'buffered', transport: 'native', attachmentId: 'attach-1', bytes: 20000 });
  // Reverse encrypted bytes waiting behind the secondary socket's backpressure.
  const raw = Buffer.from('opaque-secondary'), frame = { type: 'data', circuitId: second, seq: 1, data: raw.toString('base64') };
  const receipt = { requestId: id(999), circuitId: second, seq: 1, direction: 'reverse', digest: createHash('sha256').update(raw).digest('hex'), rawBytes: raw.length };
  await f.peerInput(2, frame, receipt);
  assert.ok(f.engine.queue.some(row => row.endpoint === 'native:attach-1' && row.data));
  const beforeBytes = f.engine.snapshot().totalBytes;
  await f.engine.accept({ type: 'nativeClose', attachmentId: 'attach-1' }); await f.flush();
  assert.equal(f.engine.active, true); assert.equal(f.engine.locals.size, 2); assert.equal(f.engine.peers.size, 3);
  assert.equal(f.engine.circuits.has(first), true); assert.equal(f.engine.circuits.has(third), true); assert.equal(f.engine.circuits.has(second), false);
  assert.equal(f.engine.queue.some(row => row.endpoint === 'native:attach-1' || row.circuitId === second), false);
  assert.equal([...f.engine.routes.values()].some(row => row.via === 'native:attach-1'), false);
  assert.ok(f.engine.snapshot().totalBytes >= beforeBytes, 'Removing an attachment never resets the global transfer budget');
  await f.nativeInput(1, { type: 'open', circuitId: id(888), target: f.pins[2].nodeId, advertisement: f.ad(1), route: ['local-browser-1', 'remote-browser-2'] });
  await f.attach(1); assert.equal(f.engine.locals.size, 2); assert.equal(f.engine.circuits.size, 2);
  await f.nativeInput(2, { type: 'close', session: id(1), circuitId: third, reason: 'old-session' });
  assert.equal(f.engine.locals.size, 1); assert.equal(f.engine.active, true); assert.equal(f.engine.circuits.has(first), true);
});

test('wrong target and cross-attachment circuit frames fail closed only on the offending hop', async () => {
  const f = await multiAttachmentFixture({ localCount: 3, peerCount: 3 });
  const c = await f.open(1);
  await f.nativeInput(2, { type: 'data', circuitId: c, seq: 1, data: 'AQ==' });
  assert.equal(f.engine.locals.has('native:attach-2'), false); assert.equal(f.engine.locals.has('native:attach-1'), true);
  assert.equal(f.engine.circuits.has(c), true); assert.equal(f.engine.peers.size, 3);
  await f.peerInput(0, { type: 'open', circuitId: id(988), target: f.pins[40].nodeId, advertisement: f.ad(0), route: ['remote-browser-0', 'browser-R'] });
  assert.equal(f.engine.peers.has('remote-0'), false); assert.equal(f.engine.active, true);
  // A one-label route could bridge two local sockets without an RTC hop: reject.
  await f.nativeInput(1, { type: 'open', circuitId: id(989), target: f.pins[0].nodeId, advertisement: f.ad(1), route: ['local-browser-1'] });
  assert.equal(f.engine.locals.has('native:attach-1'), false); assert.equal(f.engine.locals.has('native'), true);
});

test('multi-attachment pending opens share four per direction and eight total; attachment capacities are not multiplied', async () => {
  const f = await multiAttachmentFixture({ localCount: 6, peerCount: 6 }); f.autoOpen = false;
  for (let n = 0; n < 5; n++) await f.open(n);
  assert.equal(f.engine.pendingCount('outbound'), 4, 'Fifth distinct native source cannot obtain a fifth outbound handshake');
  for (let n = 0; n < 5; n++) await f.open(n, 100 + n, true);
  assert.equal(f.engine.pendingCount('inbound'), 4); assert.equal(f.engine.pendingCount(), 8);
  assert.equal(new Set([...f.engine.circuits.values()].map(c => c.a)).size, 8, 'The pending ceiling spans independent native and RTC endpoints');
  await f.engine.accept({ type: 'aiLoad', state: 'loading' }); await f.flush();
  assert.equal(f.engine.pendingCount(), 0); assert.equal(f.engine.snapshot().capacities.circuits, 0);
  assert.equal(f.engine.snapshot().nativeConnections, 6);
  await f.engine.accept({ type: 'account', bytes: L.transferBytes - f.engine.counters.totalBytes, kind: 'signal', direction: 'in' });
  assert.equal(f.engine.active, false); assert.equal(f.engine.locals.size, 0); assert.equal(f.engine.peers.size, 0);
});

test('a legacy child keeps its own two-circuit allowance alongside modern Common attachments', async () => {
  const f = await multiAttachmentFixture({ localCount: 1, peerCount: 3 });
  const old = { maxSessions: 8, nativePeers: 4, circuits: 8, circuitsPerSession: 2, pendingInbound: 4, pendingOutbound: 4 };
  await f.attach(1, { nativeLimits: old }); await f.flush();
  for (let n = 0; n < 3; n++) await f.open(1, n, false, 2);
  assert.equal(f.engine.endpointCount('native:attach-1'), 2); assert.equal(f.engine.snapshot().capacities.endpointCircuits, 40);
  await f.open(0, 20, false, 2); assert.equal(f.engine.endpointCount('native'), 1);
  assert.equal(f.engine.circuits.size, 3, 'A legacy child cannot reduce or enlarge another attachment capacity');
});


test('close before secondary HELLO retires the identifier and cannot resurrect its delayed attachment', async () => {
  const f = await multiAttachmentFixture({ localCount: 1, peerCount: 1 });
  await f.engine.accept({ type: 'nativeClose', attachmentId: 'attach-1' });
  await f.attach(1);
  assert.equal(f.engine.locals.size, 1); assert.equal(f.engine.locals.has('native:attach-1'), false);
  assert.equal(f.engine.retiredAttachments.has('native:attach-1'), true); assert.equal(f.engine.active, true);
});

test('unknown Common requires a signed endpoint binding for attachment; independent signed route discovery remains open', async () => {
  const f = await fixture(['A'], []), engine = f.engines.A, remote = keyFor('remote'), bootId = id(901);
  const signed = meshAdvertisement(remote, { network, bootId }, f.now);
  const endpoint = endpointAdvertisement(remote, { network, sourceId: 'regional-common', bootId,
    gatewayOrigin: 'https://regional.cypher.example.org' }, f.now);
  await engine.accept({ type: 'nativeHello', attachmentId: 'remote-good', sourceId: 'regional-common', nodeId: remote.nodeId,
    browserId: 'remote-browser', nativeLimits: modernLimits, endpointAdvertisement: endpoint,
    frame: { type: 'hello', session: id(902), browserId: 'remote-browser', protocol: MESH_PROTOCOL, advertisement: signed } });
  assert.equal(engine.locals.size, 2);
  assert.equal(engine.locals.get('native:remote-good').sourceId, 'regional-common');
  assert.ok(engine.events.some(row => row.name === 'native_ready' && row.nodeId === remote.nodeId && row.endpointSignatureVerified && row.browserSignatureVerified));
  const stranger = keyFor('stranger');
  await engine.accept({ type: 'nativeHello', attachmentId: 'remote-unbound', sourceId: 'unbound', nodeId: stranger.nodeId,
    browserId: 'unbound-browser', nativeLimits: modernLimits,
    frame: { type: 'hello', session: id(903), browserId: 'unbound-browser', protocol: MESH_PROTOCOL,
      advertisement: meshAdvertisement(stranger, { network }, f.now) } });
  assert.equal(engine.locals.size, 2, 'A signed native ad alone does not authenticate a remote URL');
  await engine.accept({ type: 'peerOpen', peerId: 'regional-peer', sessionId: 'regional-session', browserId: 'regional-browser',
    sourceId: 'unlisted-common', nodeId: stranger.nodeId, maxMessageSize: L.frameBytes });
  assert.ok(engine.peers.has('regional-peer'), 'Ephemeral browser identities are not a Common allowlist');
  const message = value => engine.accept({ type: 'peerMessage', peerId: 'regional-peer', buffer: JSON.stringify(value) });
  await message({ type: 'HELLO', v: 1, network, peerId: 'regional-peer', sessionId: 'regional-session', browserId: 'regional-browser' });
  await message({ type: 'FRAME', v: 1, fromSessionId: 'regional-session', toSessionId: engine.identity.sessionId, receipt: null,
    frame: { type: 'advertisement', session: id(904), advertisement: meshAdvertisement(stranger, { network }, f.now), route: ['regional-browser'] } });
  assert.ok([...engine.routes.values()].some(row => row.nodeId === stranger.nodeId));
  assert.ok(engine.events.some(row => row.name === 'advertisement' && row.nodeId === stranger.nodeId && row.browserSignatureVerified));
  assert.ok(!engine.config.nodes.some(row => row.nodeId === stranger.nodeId), 'No operator pin was inserted');
  await engine.accept({ type: 'stop' }); assert.equal(engine.routes.size, 0); assert.equal(engine.locals.size, 0);
});

test('remote endpoint and live native advertisement must bind the same node process', async () => {
  for (const mutation of ['wrong-key', 'wrong-boot', 'tampered-endpoint']) {
    const f = await fixture(['A'], []), remote = keyFor('remote-boot');
    const endpoint = endpointAdvertisement(remote, { network, sourceId: 'regional-common', bootId: id(950) }, f.now);
    if (mutation === 'tampered-endpoint') endpoint.signatureHex = '00'.repeat(65);
    const ad = meshAdvertisement(mutation === 'wrong-key' ? keyFor('other') : remote,
      { network, bootId: mutation === 'wrong-boot' ? id(951) : id(950) }, f.now);
    await f.engines.A.accept({ type: 'nativeHello', attachmentId: 'remote', sourceId: 'regional-common', nodeId: remote.nodeId,
      browserId: 'remote-browser', nativeLimits: modernLimits, endpointAdvertisement: endpoint,
      frame: { type: 'hello', session: id(952), browserId: 'remote-browser', protocol: MESH_PROTOCOL, advertisement: ad } });
    assert.equal(f.engines.A.locals.size, 1, mutation);
    assert.equal(f.engines.A.active, true, 'Only the offending secondary attachment is rejected');
  }
});
