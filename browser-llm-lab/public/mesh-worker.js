import { MESH_LIMITS as L, MESH_CHANNEL, TokenBucket, byteLength, strictJSON, check, protocolError,
  validateConfig, nativeCapacity, validateAdvertisement, validateNativeFrame, validatePeerMessage, encodePeerMessage,
  validLabel, validNodeId, sameNetwork, decodeBase64, chunkDigest } from './mesh-protocol.js';
import { verifyEndpoint } from './mesh-discovery.js';

const randomId = () => [...crypto.getRandomValues(new Uint8Array(16))].map(v => v.toString(16).padStart(2, '0')).join('');
const native = 'native';
const isNative = endpoint => endpoint === native || endpoint?.startsWith('native:');
const nativeEndpoint = attachmentId => attachmentId === undefined ? native : `native:${attachmentId}`;
const rates = { idle: [49152, 65536], generating: [24576, 32768], loading: [4096, 8192], benchmarking: [4096, 8192] };
const wireOf = frame => typeof frame === 'string' || frame instanceof ArrayBuffer || ArrayBuffer.isView(frame) ? frame : JSON.stringify(frame);
const sameRoute = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

// The browser only moves opaque bytes. Native credit is forwarded unchanged;
// a separate peer receipt means bounded hop-queue acceptance, not native Read.
export class MeshEngine {
  constructor({ post = () => {}, now = () => Date.now() } = {}) {
    this.post = post; this.now = now; this.active = false; this.epoch = 0;
    this.chain = Promise.resolve(); this.processingBytes = 0; this.pendingInputs = 0;
  }
  emit(value) { this.post({ ...value, generation: this.generation }); }
  event(name, detail = {}) {
    const row = { name, at: this.now(), ...detail };
    this.events.push(row); if (this.events.length > 128) this.events.shift(); this.emit({ type: 'event', ...row });
  }
  fatal(code, message) { this.event('error', { code, message, fatal: true }); this.stop(code === 'transfer_limit' ? 'limit' : 'error'); }
  stop(reason = 'off') {
    if (!this.active) return;
    this.active = false; this.epoch++;
    for (const name of ['peers', 'routes', 'circuits', 'pendingSends', 'pendingReceipts', 'locals', 'advertisements', 'retiredAttachments']) this[name].clear();
    this.queue = []; this.ingress = []; this.queuedBytes = 0; this.ingressBytes = 0; this.local = null;
    this.events = []; this.receipts = []; this.emit({ type: 'stopped', reason });
  }
  accept(input) {
    if (input.type === 'stop') { this.stop(input.reason); return Promise.resolve(); }
    const wire = input.buffer ?? input.frame;
    let bytes = 256;
    try { if (wire !== undefined) bytes += byteLength(wireOf(wire)) * 2 + L.chunkBytes; }
    catch { if (this.active) this.fatal('invalid_message', 'Invalid input object.'); return Promise.resolve(); }
    if (this.pendingInputs >= L.inputFrames || bytes > L.frameBytes * 3 || (this.active && this.appBytes() + bytes > L.appBytes)) {
      if (this.active) this.fatal('memory_limit', 'Mesh input reservation exhausted.'); return Promise.resolve();
    }
    this.pendingInputs++; this.processingBytes += bytes; const epoch = this.epoch;
    const work = this.chain.then(async () => {
      if (input.type !== 'init' && (!this.active || this.epoch !== epoch)) return;
      try { await this.handle(input); }
      catch (error) {
        if (input.type === 'init') { this.generation = input.generation; this.emit({ type: 'event', name: 'error', code: error.code || 'configuration', message: error.message, fatal: true }); this.emit({ type: 'stopped', reason: 'error' }); }
        else if (this.active && input.attachmentId !== undefined) this.disconnectNative(nativeEndpoint(input.attachmentId), error.code || 'invalid_native');
        else if (this.active && input.peerId) this.disconnect(input.peerId, error.code || 'invalid_message');
        else if (this.active) this.fatal(error.code || 'invalid_message', error.message || 'Mesh operation rejected.');
      }
    }).finally(() => { this.pendingInputs--; this.processingBytes -= bytes; });
    this.chain = work.catch(() => {}); return work;
  }
  init({ config, identity, generation, nativeLimits, initialTotalBytes = 0 }) {
    if (this.active) this.stop(); this.generation = generation;
    validateConfig(config);
    this.configBytes = byteLength(JSON.stringify(config)) * 2;
    check(this.configBytes <= 128 * 1024, 'Pinned configuration exceeds memory reservation.', 'configuration');
    const capacity = nativeCapacity(nativeLimits);
    check(identity && [identity.peerId, identity.sessionId, identity.browserId, identity.sourceId].every(validLabel), 'Invalid mesh session identity.', 'configuration');
    const assigned = config.nodes.find(n => n.id === identity.sourceId);
    check(assigned && assigned.nodeId === identity.nodeId, 'Assigned Common differs from operator pins.', 'configuration');
    check(Number.isSafeInteger(initialTotalBytes) && initialTotalBytes >= 0 && initialTotalBytes <= L.transferBytes, 'Invalid retained ON-session byte count.', 'configuration');
    this.nativeLimits = capacity; this.config = structuredClone(config); this.identity = { ...identity }; this.epoch++; this.active = true;
    this.peers = new Map(); this.routes = new Map(); this.circuits = new Map(); this.pendingSends = new Map(); this.pendingReceipts = new Map();
    this.queue = []; this.ingress = []; this.events = []; this.receipts = []; this.queuedBytes = 0; this.ingressBytes = 0;
    this.locals = new Map(); this.retiredAttachments = new Set(); this.advertisements = new Map();
    this.local = null; this.aiLoad = 'idle'; this.nativeBuffered = 0; this.lastStats = -Infinity;
    this.counters = { receivedBytes: 0, sentBytes: 0, nativeReceivedBytes: 0, nativeSentBytes: 0,
      streamReceivedBytes: 0, streamForwardedBytes: 0, acknowledgedBytes: 0, acknowledgedCount: 0,
      nativeCreditBytes: 0, gatewayBytes: 0, signalingBytes: 0, totalBytes: initialTotalBytes,
      rejectedFrames: 0, circuitsOpened: 0, circuitsClosed: 0 };
    const now = this.now(); this.sendBucket = new TokenBucket(49152, L.frameBytes, now); this.receiveBucket = new TokenBucket(65536, L.frameBytes, now);
    // Twenty local sources can fan out to twenty RTC peers. Control has a bounded
    // 24 KiB/s share of the unchanged 48 KiB/s global send bucket.
    this.controlBucket = new TokenBucket(24576, L.frameBytes, now); this.messageBucket = new TokenBucket(128, 256, now);
    if (initialTotalBytes >= L.transferBytes) this.fatal('transfer_limit', 'The 100 MiB ON-session budget is exhausted.');
    else this.publishStats(true);
  }
  appBytes() {
    if (!this.active) return this.processingBytes;
    return this.processingBytes + this.configBytes + this.queuedBytes * 2 + this.ingressBytes * 2 +
      [...this.pendingSends.values()].reduce((sum, row) => sum + row.bytes * 2, 0) +
      // Reserve decoded raw bytes, UTF-16 base64, parsed metadata and bookkeeping.
      this.routes.size * 12288 + this.locals.size * 12288 + this.retiredAttachments.size * 256 + this.advertisements.size * 512 +
      this.circuits.size * 4096 + this.peers.size * 8192 + this.pendingReceipts.size * 512 + (this.events.length + this.receipts.length) * 1024;
  }
  paused() { return this.aiLoad === 'loading' || this.aiLoad === 'benchmarking'; }
  endpointCount(endpoint) { return [...this.circuits.values()].filter(c => endpoint ? c.a === endpoint || c.b === endpoint : isNative(c.a) || isNative(c.b)).length; }
  pendingCount(kind) { return [...this.circuits.values()].filter(c => !c.opened && (!kind || c.kind === kind)).length; }
  capacities() {
    const policy = this.paused() ? 0 : this.aiLoad === 'generating' ? 1 : L.circuits;
    return { circuits: policy, endpointCircuits: Math.min(policy, L.endpointCircuits, [...this.locals.values()].reduce((sum, local) => sum + Math.min(local.limits.circuitsPerSession, local.limits.circuits), 0) || Math.min(this.nativeLimits.circuitsPerSession, this.nativeLimits.circuits)),
      pendingHandshakes: Math.min(policy, L.pendingHandshakes), pendingPerDirection: Math.min(policy, L.pendingPerDirection),
      hardCircuits: L.circuits, hardEndpointCircuits: L.endpointCircuits, peers: L.peers, nativeConnections: L.nativeConnections, commonConnections: L.nativeConnections,
      appBytes: L.appBytes, queueBytes: L.queueBytes, transferBytes: L.transferBytes,
      sendBytesPerSecond: this.sendBucket.rate, receiveBytesPerSecond: this.receiveBucket.rate, controlBytesPerSecond: this.controlBucket.rate, common: { ...this.nativeLimits } };
  }
  charge(bytes) {
    this.counters.totalBytes += bytes;
    if (this.counters.totalBytes >= L.transferBytes) { this.fatal('transfer_limit', 'The 100 MiB ON-session budget is exhausted.'); return false; }
    return true;
  }
  async handle(input) {
    switch (input.type) {
      case 'init': this.init(input); return;
      case 'nativeHello': this.nativeHello(input); break;
      case 'nativeMessage': this.enqueueInput(nativeEndpoint(input.attachmentId), wireOf(input.frame)); break;
      case 'peerMessage': case 'message': this.enqueueInput(input.peerId, input.buffer); break;
      case 'nativeClose': this.disconnectNative(nativeEndpoint(input.attachmentId), 'native_closed', false); break;
      case 'peerOpen': this.peerOpen(input); break;
      case 'peerClose': this.disconnect(input.peerId, 'closed', false); break;
      case 'peerPath': if (this.peers.has(input.peerId)) this.peers.get(input.peerId).path = ['direct', 'TURN'].includes(input.path) ? input.path : 'unknown'; break;
      case 'sent': this.sent(input); break;
      case 'buffered': if (input.transport === native) { const local = this.locals.get(nativeEndpoint(input.attachmentId)); if (local) { local.buffered = Math.max(0, Number(input.bytes) || 0); if (!input.attachmentId) this.nativeBuffered = local.buffered; } } else if (this.peers.has(input.peerId)) this.peers.get(input.peerId).buffered = Math.max(0, Number(input.bytes) || 0); break;
      case 'aiLoad': this.load(input.state); break;
      case 'account': {
        check(Number.isSafeInteger(input.bytes) && input.bytes >= 0 && ['https', 'signal'].includes(input.kind) && ['in', 'out'].includes(input.direction), 'Invalid traffic accounting.');
        this.counters[input.kind === 'https' ? 'gatewayBytes' : 'signalingBytes'] += input.bytes; this.charge(input.bytes); break;
      }
      case 'inspect': this.emit({ type: 'evidence', requestId: input.requestId, stats: this.snapshot(), circuits: [...this.circuits.values()].map(c => this.circuitInfo(c)), receipts: [...this.receipts], events: [...this.events], routes: [...this.routes.values()].map(r => ({ nodeId: r.nodeId, route: r.route, expiresAt: r.payload.expiresAt })) }); return;
      case 'tick': break;
      default: throw protocolError('configuration', 'Unknown mesh Worker command.');
    }
    if (this.active) { await this.drainInputs(); if (this.active) this.tick(); }
  }
  nativeHello({ frame: input, attachmentId, browserId, nodeId, sourceId, nativeLimits, endpointAdvertisement }) {
    const endpoint = nativeEndpoint(attachmentId), primary = endpoint === native;
    check(primary || validLabel(attachmentId), 'Invalid native attachment identifier.');
    check(!this.locals.has(endpoint) && !this.retiredAttachments.has(endpoint), 'Native HELLO cannot replace a live or retired connection generation.');
    check(this.locals.size < L.nativeConnections && this.retiredAttachments.size < 128, 'Native attachment capacity exhausted.', 'capacity');
    check(primary || this.local, 'Primary native attachment is not ready.');
    const expected = primary ? this.identity : { browserId, nodeId, sourceId };
    const frame = validateNativeFrame(wireOf(input), { allowHello: true });
    check(validLabel(expected.browserId) && validLabel(expected.sourceId) && frame.type === 'hello' && frame.browserId === expected.browserId &&
      (!sourceId || sourceId === expected.sourceId) && (!nodeId || nodeId === expected.nodeId) && (!browserId || browserId === expected.browserId), 'Native attachment identity mismatch.');
    const pin = this.config.nodes.find(n => n.id === expected.sourceId);
    const descriptor = endpointAdvertisement ? verifyEndpoint(endpointAdvertisement, this.config.network, this.now()) : null;
    check(descriptor ? !primary && descriptor.nodeId === expected.nodeId && descriptor.sourceId === expected.sourceId : pin && pin.nodeId === expected.nodeId,
      'Native attachment differs from its verified endpoint or local assignment.', 'untrusted_node');
    const ad = validateAdvertisement(frame.advertisement, this.config, this.now());
    check(ad.nodeId === expected.nodeId && (!descriptor || descriptor.payload.bootId === ad.payload.bootId) &&
      ![...this.locals.values()].some(local => local.nodeId === ad.nodeId || local.browserId === frame.browserId) && ![...this.peers.values()].some(peer => peer.browserId === frame.browserId), 'Native Common differs from its verified identity or duplicates an attachment.', 'untrusted_node');
    const limits = primary && nativeLimits === undefined ? this.nativeLimits : nativeCapacity(nativeLimits);
    check(primary || nativeLimits !== undefined, 'Child Common capacity is required.', 'configuration');
    const local = { session: frame.session, ...ad, sourceId: expected.sourceId, endpoint, attachmentId, browserId: frame.browserId, limits, buffered: 0, route: [this.identity.browserId] };
    this.locals.set(endpoint, local); if (primary) this.local = local;
    const bytes = byteLength(wireOf(input)); this.counters.nativeReceivedBytes += bytes; if (!this.charge(bytes)) return;
    this.rememberAdvertisement(endpoint, { type: 'advertisement', session: frame.session, advertisement: frame.advertisement, route: [this.identity.browserId] }, ad);
    for (const record of this.routes.values()) if (!isNative(record.via)) this.markAdvertisement(endpoint, record.nodeId);
    for (const peer of this.peers.values()) this.sendHello(peer);
    this.event('native_ready', { attachmentId, sourceId: expected.sourceId, nodeId: ad.nodeId, browserId: frame.browserId,
      verification: 'browser_secp256k1_signature', browserSignatureVerified: true, endpointSignatureVerified: Boolean(descriptor) });
  }
  peerOpen({ peerId, sessionId, browserId, nodeId, sourceId, path, maxMessageSize }) {
    if (![peerId, sessionId, browserId].every(validLabel) || peerId === native || peerId === this.identity.peerId || [...this.locals.values()].some(local => local.browserId === browserId) || browserId === this.identity.browserId || this.peers.has(peerId) ||
      [...this.peers.values()].some(p => p.browserId === browserId) || this.peers.size >= L.peers || !Number.isFinite(maxMessageSize) || maxMessageSize < L.frameBytes ||
      (nodeId && !validNodeId(nodeId)) || (sourceId && !validLabel(sourceId))) {
      this.emit({ type: 'disconnect', transport: 'peer', peerId, reason: 'unsupported_peer' }); return;
    }
    const now = this.now(), peer = { id: peerId, sessionId, browserId, nodeId, sourceId, path: ['direct', 'TURN'].includes(path) ? path : 'unknown', hello: false, helloSent: false, buffered: 0, openedAt: now, lastSeen: now, lastPing: now, ping: null };
    this.peers.set(peerId, peer); if (this.local) this.sendHello(peer);
  }
  sendHello(peer) {
    if (peer.helloSent) return; peer.helloSent = true;
    this.queuePeer(peer.id, { type: 'HELLO', v: 1, network: this.config.network, peerId: this.identity.peerId, sessionId: this.identity.sessionId, browserId: this.identity.browserId });
  }
  peerEnvelope(peerId, type, extra) {
    const peer = this.peers.get(peerId); check(peer, 'Missing mesh peer.');
    return { type, v: 1, fromSessionId: this.identity.sessionId, toSessionId: peer.sessionId, ...extra };
  }
  queuePeer(peerId, message, meta = {}) { return this.enqueue(peerId, encodePeerMessage(message), meta); }
  enqueue(endpoint, text, meta = {}) {
    const bytes = byteLength(text);
    if (!this.active || (isNative(endpoint) ? !this.locals.has(endpoint) : !this.peers.has(endpoint))) return false;
    if (bytes > L.frameBytes || this.queue.length + this.pendingSends.size >= L.queueFrames || this.bufferBytes() + bytes > L.queueBytes || this.appBytes() + bytes * 2 > L.appBytes) return false;
    this.queue.push({ endpoint, text, bytes, at: this.now(), ...meta }); this.queuedBytes += bytes; return true;
  }
  enqueueInput(endpoint, wire) {
    if (isNative(endpoint) ? !this.locals.has(endpoint) : !this.peers.has(endpoint)) return;
    const bytes = byteLength(wire);
    check(bytes <= L.frameBytes && bytes > 0, 'Incoming frame exceeds limit.', 'oversize');
    if (!this.messageBucket.take(1, this.now()) || this.ingress.length >= L.inputFrames || this.bufferBytes() + bytes > L.queueBytes || this.appBytes() + bytes * 2 > L.appBytes) {
      if (isNative(endpoint)) this.disconnectNative(endpoint, 'input_budget'); else this.disconnect(endpoint, 'input_budget'); return;
    }
    this.counters[isNative(endpoint) ? 'nativeReceivedBytes' : 'receivedBytes'] += bytes;
    if (!this.charge(bytes)) return;
    this.ingress.push({ endpoint, wire, bytes, at: this.now() }); this.ingressBytes += bytes;
  }
  async drainInputs() {
    while (this.active && this.ingress.length && this.receiveBucket.take(this.ingress[0].bytes, this.now())) {
      const row = this.ingress.shift(); this.ingressBytes -= row.bytes;
      if (isNative(row.endpoint) ? !this.locals.has(row.endpoint) : !this.peers.has(row.endpoint)) continue;
      try {
        if (isNative(row.endpoint)) {
          const frame = validateNativeFrame(row.wire, { allowLocalAdvertisement: true });
          check(frame.session === this.locals.get(row.endpoint).session, 'Stale native session.');
          await this.frame(row.endpoint, frame);
        } else await this.peerMessage(row.endpoint, row.wire);
      } catch (error) {
        if (!this.active) return;
        this.counters.rejectedFrames++;
        if (isNative(row.endpoint)) this.disconnectNative(row.endpoint, error.code || 'invalid_native');
        else this.disconnect(row.endpoint, error.code || 'invalid_message');
      }
    }
  }
  async peerMessage(peerId, wire) {
    const peer = this.peers.get(peerId), message = validatePeerMessage(wire); if (!peer) return;
    peer.lastSeen = this.now();
    if (message.type === 'HELLO') {
      check(!peer.hello && message.peerId === peer.id && message.sessionId === peer.sessionId && message.browserId === peer.browserId && sameNetwork(message.network, this.config.network), 'Peer HELLO differs from admitted identity.', 'wrong_session');
      peer.hello = true; this.sendHello(peer); for (const route of this.routes.values()) this.advertise(route, peer); return;
    }
    check(peer.hello && message.fromSessionId === peer.sessionId && message.toSessionId === this.identity.sessionId, 'Stale peer session.', 'wrong_session');
    if (message.type === 'PING') { this.queuePeer(peerId, this.peerEnvelope(peerId, 'PONG', { nonce: message.nonce })); return; }
    if (message.type === 'PONG') { check(peer.ping === message.nonce, 'Unexpected heartbeat reply.'); peer.ping = null; return; }
    if (message.type === 'RECEIPT') { this.receipt(peerId, message.receipt); return; }
    await this.frame(peerId, message.frame, message.receipt);
  }
  rememberAdvertisement(from, frame, ad) {
    const route = isNative(from) ? [this.identity.browserId] : [...frame.route, this.identity.browserId];
    if (!isNative(from)) {
      const peer = this.peers.get(from);
      check(frame.route.at(-1) === peer.browserId && !frame.route.includes(this.identity.browserId) && route.length <= L.hops, 'Advertisement route does not match this hop.');
    }
    const key = `${ad.nodeId}:${route.join('/')}`, previous = this.routes.get(key);
    if (previous && previous.payload.issuedAt >= ad.payload.issuedAt) return;
    const sameNode = [...this.routes.entries()].filter(([, row]) => row.nodeId === ad.nodeId);
    if (!previous && sameNode.length >= 4) {
      const replace = sameNode.filter(([, row]) => !isNative(row.via)).sort((a, b) => b[1].route.length - a[1].route.length || a[1].payload.issuedAt - b[1].payload.issuedAt)[0];
      if (!replace || replace[1].route.length < route.length) return; this.routes.delete(replace[0]);
    }
    if (!previous && (this.routes.size >= 256 || this.appBytes() + 12288 > L.appBytes)) return;
    const record = { ...ad, route, via: from, session: frame.session, key }; this.routes.set(key, record);
    // Ads remain route references until scheduler capacity is available: a
    // 20-by-20 fanout never materializes hundreds of JSON frames in queue64.
    if (!isNative(from)) for (const endpoint of this.locals.keys()) this.markAdvertisement(endpoint, ad.nodeId);
    for (const peer of this.peers.values()) this.advertise(record, peer);
    this.event('advertisement', { nodeId: ad.nodeId, sourceId: ad.sourceId, route, expiresAt: ad.payload.expiresAt, browserSignatureVerified: true });
  }
  markAdvertisement(endpoint, nodeId) {
    const key = `${endpoint}/${nodeId}`, previous = this.advertisements.get(key);
    if (previous) { previous.pending = true; return; }
    if (this.advertisements.size >= 64 * (L.peers + L.nativeConnections) || this.appBytes() + 512 > L.appBytes) return;
    this.advertisements.set(key, { endpoint, nodeId, pending: true, routeKey: null, issuedAt: null });
  }
  advertise(record, peer) { if (peer.hello) this.markAdvertisement(peer.id, record.nodeId); }
  scheduleAdvertisements() {
    for (const row of this.advertisements.values()) {
      if (!row.pending) continue;
      const local = this.locals.get(row.endpoint), peer = this.peers.get(row.endpoint);
      if ((isNative(row.endpoint) && (!local || this.paused())) || (!isNative(row.endpoint) && !peer?.hello)) continue;
      const best = [...this.routes.values()].filter(r => r.nodeId === row.nodeId && r.payload.expiresAt > this.now() &&
        (local ? !isNative(r.via) && r.nodeId !== local.nodeId : !r.route.includes(peer.browserId) && r.route.length < L.hops))
        .sort((a, b) => a.route.length - b.route.length || b.payload.issuedAt - a.payload.issuedAt || a.key.localeCompare(b.key))[0];
      if (!best || (row.routeKey === best.key && row.issuedAt === best.payload.issuedAt)) { row.pending = false; continue; }
      if (this.queue.length + this.pendingSends.size >= L.queueFrames / 2) break;
      if (!this.forward(row.endpoint, { type: 'advertisement', session: best.session, advertisement: best.advertisement, route: best.route }, null, { advertisementRouteKey: best.key })) break;
      row.pending = false; row.routeKey = best.key; row.issuedAt = best.payload.issuedAt;
    }
  }
  forward(endpoint, frame, receipt, meta = {}) {
    if (isNative(endpoint)) {
      const local = this.locals.get(endpoint); if (!local) return false;
      const route = frame.route ? [...frame.route.slice(0, -1), local.browserId] : undefined;
      return this.enqueue(endpoint, JSON.stringify({ ...frame, ...(route ? { route } : {}), session: local.session }), { ...meta, circuitId: frame.circuitId || meta.circuitId, rawBytes: receipt?.rawBytes || 0, data: frame.type === 'data' });
    }
    const peer = this.peers.get(endpoint); if (!peer?.hello) return false;
    const hopReceipt = frame.type === 'data' ? { ...receipt, requestId: randomId() } : null;
    return this.queuePeer(endpoint, this.peerEnvelope(endpoint, 'FRAME', { frame, receipt: hopReceipt }), { ...meta, circuitId: frame.circuitId || meta.circuitId, rawBytes: hopReceipt?.rawBytes || 0, receipt: hopReceipt, data: frame.type === 'data' });
  }
  async frame(from, frame, hopReceipt = null) {
    if (frame.type === 'advertisement') {
      const ad = validateAdvertisement(frame.advertisement, this.config, this.now());
      if (isNative(from)) { const local = this.locals.get(from); check(local && ad.nodeId === local.nodeId && frame.route === undefined, 'Unexpected local advertisement route.'); Object.assign(local, ad); }
      this.rememberAdvertisement(from, frame, ad); return;
    }
    if (frame.type === 'open') { await this.openCircuit(from, frame); return; }
    const c = this.circuits.get(frame.circuitId);
    if (!c) { if (frame.type !== 'close') this.sendClose(from, frame.circuitId, 'unknown-circuit'); return; }
    check(from === c.a || from === c.b, 'Circuit belongs to another hop.', 'wrong_circuit');
    const destination = from === c.a ? c.b : c.a, direction = from === c.a ? 'forward' : 'reverse';
    if (frame.type === 'close') { this.closeCircuit(c.id, frame.reason, from); return; }
    if (frame.type === 'opened') {
      if (from !== c.b || c.opened) { this.closeCircuit(c.id, 'unexpected-open'); return; }
      c.opened = true; this.counters.circuitsOpened++; this.event('circuit_opened', this.circuitInfo(c));
      if (!await this.forward(destination, frame, null)) this.closeCircuit(c.id, 'queue-full'); return;
    }
    if (!c.opened) { this.closeCircuit(c.id, 'not-opened'); return; }
    if (frame.type === 'credit') {
      const outstanding = c[direction === 'forward' ? 'reverse' : 'forward'].pending, expected = outstanding[0];
      if (!expected || expected.seq !== frame.seq || expected.bytes !== frame.bytes) { this.closeCircuit(c.id, 'invalid-credit'); return; }
      if (!await this.forward(destination, frame, null)) { this.closeCircuit(c.id, 'queue-full'); return; }
      outstanding.shift(); this.counters.nativeCreditBytes += frame.bytes; return;
    }
    if (frame.type === 'data') {
      if (this.paused()) { this.closeCircuit(c.id, 'ai-paused'); return; }
      const stream = c[direction], raw = decodeBase64(frame.data, L.chunkBytes);
      if (frame.seq !== stream.seq + 1 || stream.pending.length >= 8) { this.closeCircuit(c.id, 'invalid-data'); return; }
      const epoch = this.epoch, digest = await chunkDigest(raw);
      if (!this.active || epoch !== this.epoch || this.circuits.get(c.id) !== c) return;
      const receipt = { circuitId: c.id, seq: frame.seq, direction, digest, rawBytes: raw.length };
      if (!isNative(from)) check(hopReceipt && Object.entries(receipt).every(([key, value]) => hopReceipt[key] === value), 'Hop receipt does not bind the exact chunk.', 'invalid_digest');
      if (!await this.forward(destination, frame, receipt)) { this.closeCircuit(c.id, 'queue-full'); return; }
      stream.seq = frame.seq; stream.pending.push({ seq: frame.seq, bytes: raw.length }); this.counters.streamReceivedBytes += raw.length;
      this.event('chunk_accepted', { ...receipt, from: isNative(from) ? 'native' : from, to: destination, path: this.peers.get(from)?.path || this.peers.get(destination)?.path || 'native' });
      if (!isNative(from) && !this.queuePeer(from, this.peerEnvelope(from, 'RECEIPT', { receipt: hopReceipt }))) this.closeCircuit(c.id, 'receipt-queue-full');
    }
  }
  async openCircuit(from, frame) {
    if (this.paused()) { this.sendClose(from, frame.circuitId, 'ai-paused'); return; }
    if (this.circuits.has(frame.circuitId)) { this.sendClose(from, frame.circuitId, 'duplicate-circuit'); return; }
    const ad = validateAdvertisement(frame.advertisement, this.config, this.now());
    if (isNative(from)) {
      const local = this.locals.get(from);
      check(local && frame.route[0] === local.browserId && ad.nodeId === local.nodeId && frame.route.length >= 2 && !frame.route.slice(1).includes(this.identity.browserId), 'Native open source or route mismatch.');
      frame = { ...frame, route: [this.identity.browserId, ...frame.route.slice(1)] };
    }
    const index = frame.route.indexOf(this.identity.browserId); let destination;
    if (isNative(from)) {
      const known = [...this.routes.values()].some(r => r.nodeId === frame.target && sameRoute([...r.route].reverse(), frame.route) && r.payload.expiresAt > this.now());
      if (!known) { this.sendClose(from, frame.circuitId, 'route-unavailable'); return; }
    } else {
      check(index > 0 && frame.route[index - 1] === this.peers.get(from)?.browserId, 'Open route is not attached to sender.');
      const known = [...this.routes.values()].some(r => r.nodeId === ad.nodeId && sameRoute(r.route, frame.route.slice(0, index + 1)) && r.payload.expiresAt > this.now());
      if (!known) { this.sendClose(from, frame.circuitId, 'source-unadvertised'); return; }
    }
    if (index === frame.route.length - 1) {
      check(!isNative(from), 'Native cannot bridge directly to another local Common.', 'untrusted_node');
      destination = [...this.locals.values()].find(local => local.nodeId === frame.target)?.endpoint;
      check(destination, 'Open destination differs from attached Commons.', 'untrusted_node');
    } else destination = [...this.peers.values()].find(p => p.hello && p.browserId === frame.route[index + 1])?.id;
    if (!destination || destination === from) { this.sendClose(from, frame.circuitId, 'route-unavailable'); return; }
    const endpoint = isNative(from) ? from : isNative(destination) ? destination : null, limits = this.capacities();
    const local = this.locals.get(endpoint);
    const kind = isNative(from) ? 'outbound' : isNative(destination) ? 'inbound' : 'transit';
    // Opening circuits already consume the shared browser total. Transit consumes
    // that same total, but never the attached Common's endpoint allowance.
    if (this.circuits.size >= limits.circuits || (endpoint && (this.endpointCount() >= limits.endpointCircuits || this.endpointCount(endpoint) >= Math.min(local.limits.circuits, local.limits.circuitsPerSession))) ||
      this.pendingCount() >= limits.pendingHandshakes || this.pendingCount(kind) >= limits.pendingPerDirection) { this.sendClose(from, frame.circuitId, 'capacity'); return; }
    if (this.appBytes() + 5120 > L.appBytes) { this.sendClose(from, frame.circuitId, 'memory-capacity'); return; }
    const c = { id: frame.circuitId, a: from, b: destination, route: frame.route, sourceNodeId: ad.nodeId, targetNodeId: frame.target,
      kind, opened: false, at: this.now(), expiresAt: this.now() + L.circuitTTL, forward: { seq: 0, pending: [] }, reverse: { seq: 0, pending: [] } };
    this.circuits.set(c.id, c);
    if (isNative(destination)) {
      // A failed native outbound dial can evict its candidate independently of
      // this browser's still-current route cache. Reassert the exact signed
      // source advertisement on the ordered native queue before every open.
      // This does not authenticate the ad in JavaScript: Common verifies it.
      const advertised = await this.forward(destination, { type: 'advertisement', session: frame.session,
        advertisement: frame.advertisement, route: frame.route }, null, { circuitId: c.id });
      if (!advertised) { this.closeCircuit(c.id, 'queue-full'); return; }
    }
    if (!await this.forward(destination, frame, null)) { this.closeCircuit(c.id, 'queue-full'); return; }
    this.event('circuit_opening', this.circuitInfo(c));
  }
  sendClose(endpoint, circuitId, reason) {
    if (!this.local) return;
    if (this.forward(endpoint, { type: 'close', session: this.local.session, circuitId, reason: validLabel(reason) ? reason : 'closed' }, null)) return;
    // A full control queue must not silently orphan a remote circuit. Losing
    // the transport withdraws all its circuits; fixed queue limits still apply.
    if (isNative(endpoint)) this.disconnectNative(endpoint, 'native_close_queue_full');
    else this.disconnect(endpoint, 'close-queue-full');
  }
  closeCircuit(id, reason, except = null) {
    const c = this.circuits.get(id); if (!c) return; this.circuits.delete(id);
    this.queue = this.queue.filter(row => { if (row.circuitId !== id) return true; this.queuedBytes -= row.bytes; return false; });
    for (const [key, row] of this.pendingReceipts) if (row.receipt.circuitId === id) this.pendingReceipts.delete(key);
    for (const endpoint of [c.a, c.b]) if (endpoint !== except) this.sendClose(endpoint, id, reason);
    if (!this.active) return;
    this.counters.circuitsClosed++; this.event('circuit_closed', { ...this.circuitInfo(c), reason });
  }
  disconnect(peerId, reason, notify = true) {
    const peer = this.peers.get(peerId); if (!peer) return; this.peers.delete(peerId);
    // Release the dead hop's queued frames before close propagation uses the same budget.
    this.queue = this.queue.filter(row => { if (row.endpoint !== peerId) return true; this.queuedBytes -= row.bytes; return false; });
    for (const c of [...this.circuits.values()]) if (c.a === peerId || c.b === peerId) this.closeCircuit(c.id, 'peer-left', peerId);
    if (!this.active) return;
    for (const [key, route] of this.routes) if (route.route.includes(peer.browserId)) this.routes.delete(key);
    this.ingress = this.ingress.filter(row => { if (row.endpoint !== peerId) return true; this.ingressBytes -= row.bytes; return false; });
    for (const [key, row] of this.pendingSends) if (row.endpoint === peerId) this.pendingSends.delete(key);
    for (const [key, row] of this.pendingReceipts) if (row.endpoint === peerId) this.pendingReceipts.delete(key);
    for (const [key, row] of this.advertisements) { if (row.endpoint === peerId) this.advertisements.delete(key); else row.pending = true; }
    if (notify) this.emit({ type: 'disconnect', transport: 'peer', peerId, reason });
    this.event('peer_closed', { peerId, reason, nativeCandidateRemoval: 'native-session-close-or-advertisement-expiry' });
  }
  disconnectNative(endpoint, reason, notify = true) {
    if (endpoint === native) { this.stop(reason === 'native_closed' ? reason : 'error'); return; }
    const local = this.locals.get(endpoint);
    if (!local) {
      // A close may overtake a delayed HELLO callback. Retire that identifier
      // too, so neither old callback nor old native bytes can recreate it.
      if (validLabel(endpoint.slice(7)) && this.retiredAttachments.size < 128) this.retiredAttachments.add(endpoint);
      if (notify) this.emit({ type: 'disconnect', transport: native, attachmentId: endpoint.slice(7), reason }); return;
    }
    this.locals.delete(endpoint); this.retiredAttachments.add(endpoint);
    this.queue = this.queue.filter(row => { if (row.endpoint !== endpoint) return true; this.queuedBytes -= row.bytes; return false; });
    this.ingress = this.ingress.filter(row => { if (row.endpoint !== endpoint) return true; this.ingressBytes -= row.bytes; return false; });
    for (const [key, row] of this.pendingSends) if (row.endpoint === endpoint) this.pendingSends.delete(key);
    for (const [key, row] of this.pendingReceipts) if (row.endpoint === endpoint) this.pendingReceipts.delete(key);
    for (const c of [...this.circuits.values()]) if (c.a === endpoint || c.b === endpoint) this.closeCircuit(c.id, 'native-left', endpoint);
    const removedRoutes = new Set();
    for (const [key, route] of this.routes) if (route.via === endpoint) { this.routes.delete(key); removedRoutes.add(key); }
    this.queue = this.queue.filter(row => { if (!removedRoutes.has(row.advertisementRouteKey)) return true; this.queuedBytes -= row.bytes; return false; });
    for (const [key, row] of this.advertisements) { if (row.endpoint === endpoint) this.advertisements.delete(key); else if (row.nodeId === local.nodeId) row.pending = true; }
    if (notify) this.emit({ type: 'disconnect', transport: native, attachmentId: local.attachmentId, reason });
    this.event('native_closed', { attachmentId: local.attachmentId, sourceId: local.sourceId, nodeId: local.nodeId, reason });
  }
  sent({ sendId, ok, bufferedAmount }) {
    const row = this.pendingSends.get(sendId); if (!row) return; this.pendingSends.delete(sendId);
    if (isNative(row.endpoint)) { const local = this.locals.get(row.endpoint); if (!local) return; local.buffered = Math.max(0, Number(bufferedAmount) || 0); if (row.endpoint === native) this.nativeBuffered = local.buffered; }
    else if (this.peers.has(row.endpoint)) this.peers.get(row.endpoint).buffered = Math.max(0, Number(bufferedAmount) || 0);
    if (!ok) { if (isNative(row.endpoint)) this.disconnectNative(row.endpoint, 'native_send_failed'); else this.disconnect(row.endpoint, 'send-failed'); return; }
    this.counters[isNative(row.endpoint) ? 'nativeSentBytes' : 'sentBytes'] += row.bytes;
    if (row.data) this.counters.streamForwardedBytes += row.rawBytes;
    if (!this.charge(row.bytes)) return;
    if (row.receipt && this.circuits.has(row.receipt.circuitId)) {
      this.pendingReceipts.set(row.receipt.requestId, { endpoint: row.endpoint, receipt: row.receipt, at: this.now(), sessionId: this.peers.get(row.endpoint)?.sessionId });
      if (row.data && !isNative(row.endpoint) && this.peers.has(row.endpoint)) {
        // The map can show a real send here; only receipt() confirms reception.
        this.event('chunk_sent', { peerId: row.endpoint, circuitId: row.receipt.circuitId,
          seq: row.receipt.seq, rawBytes: row.rawBytes, path: this.peers.get(row.endpoint).path,
          meaning: 'datachannel-send-queued' });
      }
    }
  }
  receipt(peerId, receipt) {
    const pending = this.pendingReceipts.get(receipt.requestId), peer = this.peers.get(peerId);
    if (!pending || pending.endpoint !== peerId || pending.sessionId !== peer.sessionId || !Object.keys(receipt).every(key => receipt[key] === pending.receipt[key])) {
      this.counters.rejectedFrames++; this.event('error', { code: 'invalid_receipt', fatal: false, peerId }); return;
    }
    this.pendingReceipts.delete(receipt.requestId); this.counters.acknowledgedBytes += receipt.rawBytes; this.counters.acknowledgedCount++;
    const row = { ...receipt, peerId, fromSessionId: peer.sessionId, toSessionId: this.identity.sessionId, path: peer.path, at: this.now(), meaning: 'bounded-hop-queue-acceptance' };
    this.receipts.push(row); if (this.receipts.length > L.hopReceipts) this.receipts.shift(); this.event('acknowledged', row);
  }
  load(state) {
    check(Object.hasOwn(rates, state), 'Unknown AI workload.');
    const wasPaused = this.paused(); this.aiLoad = state; const [tx, rx] = rates[state]; this.sendBucket.set(tx, L.frameBytes, this.now()); this.receiveBucket.set(rx, L.frameBytes, this.now());
    if (this.paused()) for (const c of [...this.circuits.values()]) this.closeCircuit(c.id, 'ai-paused');
    else if (state === 'generating') for (const c of [...this.circuits.values()].slice(1)) this.closeCircuit(c.id, 'ai-capacity');
    if (wasPaused && !this.paused()) for (const row of this.advertisements.values()) if (isNative(row.endpoint)) { row.pending = true; row.issuedAt = null; }
    this.event('ai_policy', { state, txJSONBytesPerSecond: tx, rxJSONBytesPerSecond: rx, capacities: this.capacities(), reason: 'bounded-throughput-with-native-RLPx-deadlines' });
  }
  pump() {
    this.scheduleAdvertisements();
    const blocked = new Set([...this.pendingSends.values()].map(row => row.endpoint));
    for (let index = 0; this.active && index < this.queue.length;) {
      const row = this.queue[index], peer = this.peers.get(row.endpoint);
      if ((isNative(row.endpoint) ? !this.locals.has(row.endpoint) : !peer) || (row.circuitId && row.data && !this.circuits.has(row.circuitId))) { this.queue.splice(index, 1); this.queuedBytes -= row.bytes; continue; }
      const buffered = isNative(row.endpoint) ? this.locals.get(row.endpoint).buffered : peer.buffered;
      if (blocked.has(row.endpoint)) { index++; continue; } blocked.add(row.endpoint);
      if (buffered > 16384 || (row.data && this.paused())) { index++; continue; }
      this.sendBucket.refill(this.now()); this.controlBucket.refill(this.now());
      if (row.bytes > this.sendBucket.tokens || (!row.data && row.bytes > this.controlBucket.tokens)) { index++; continue; }
      if (row.receipt && this.pendingReceipts.size + [...this.pendingSends.values()].filter(send => send.receipt).length >= L.hopReceipts) { index++; continue; }
      this.sendBucket.take(row.bytes, this.now()); if (!row.data) this.controlBucket.take(row.bytes, this.now());
      this.queue.splice(index, 1); this.queuedBytes -= row.bytes;
      const sendId = randomId(); this.pendingSends.set(sendId, { ...row, sentAt: this.now() });
      this.emit({ type: 'send', transport: isNative(row.endpoint) ? native : 'peer', ...(isNative(row.endpoint) ? (row.endpoint === native ? {} : { attachmentId: this.locals.get(row.endpoint).attachmentId }) : { peerId: row.endpoint }), text: row.text, sendId });
    }
  }
  tick() {
    const now = this.now();
    for (const [key, route] of this.routes) if (route.payload.expiresAt <= now) this.routes.delete(key);
    for (const c of [...this.circuits.values()]) if (c.expiresAt <= now || (!c.opened && now - c.at >= L.openTimeout)) this.closeCircuit(c.id, c.opened ? 'circuit-expired' : 'open-timeout');
    for (const [id, row] of this.pendingReceipts) if (now - row.at > 15000) { this.pendingReceipts.delete(id); this.closeCircuit(row.receipt.circuitId, 'receipt-timeout'); }
    for (const row of [...this.pendingSends.values()]) if (now - row.sentAt > 5000) { if (isNative(row.endpoint)) { this.disconnectNative(row.endpoint, 'native_send_timeout'); if (!this.active) return; continue; } this.disconnect(row.endpoint, 'send-timeout'); }
    for (const row of this.queue) if (now - row.at > 15000) { if (isNative(row.endpoint)) { this.disconnectNative(row.endpoint, 'native_queue_timeout'); if (!this.active) return; break; } this.disconnect(row.endpoint, 'queue-timeout'); break; }
    for (const peer of [...this.peers.values()]) {
      if (now - peer.lastSeen >= L.peerTimeout || (!peer.hello && now - peer.openedAt > 5000)) { this.disconnect(peer.id, 'heartbeat-timeout'); continue; }
      // Keep one outstanding nonce: replacing it while its control frame waits
      // behind bounded DATA would reject the eventual legitimate PONG.
      if (peer.hello && !peer.ping && now - peer.lastPing >= L.heartbeat) {
        const nonce = randomId();
        if (this.queuePeer(peer.id, this.peerEnvelope(peer.id, 'PING', { nonce }))) { peer.lastPing = now; peer.ping = nonce; }
      }
    }
    if (this.appBytes() > L.appBytes) { this.fatal('memory_limit', 'Mesh application reservation exhausted.'); return; }
    this.pump(); this.publishStats();
  }
  circuitInfo(c) { return { circuitId: c.id, sourceNodeId: c.sourceNodeId, targetNodeId: c.targetNodeId, route: c.route, opened: c.opened, createdAt: c.at, expiresAt: c.expiresAt, forwardSeq: c.forward.seq, reverseSeq: c.reverse.seq, uncreditedChunks: c.forward.pending.length + c.reverse.pending.length }; }
  bufferBytes() { return this.queuedBytes + this.ingressBytes + [...this.pendingSends.values()].reduce((sum, row) => sum + row.bytes, 0); }
  snapshot() {
    return { ...this.counters, connectedPeers: this.peers.size, nativeConnections: this.locals.size,
      connections: [...this.locals.values()].map(local => ({ attachmentId: local.attachmentId, sourceId: local.sourceId, nodeId: local.nodeId, browserId: local.browserId, endpointCircuits: this.endpointCount(local.endpoint), limits: { ...local.limits } })),
      pendingAdvertisements: [...this.advertisements.values()].filter(row => row.pending).length, circuits: this.circuits.size, pendingHandshakes: this.pendingCount(), routes: this.routes.size,
      queuedBytes: this.bufferBytes(), appBytes: this.appBytes(), capacities: this.capacities(),
      transitCircuits: this.circuits.size - this.endpointCount(), pendingInbound: this.pendingCount('inbound'), pendingOutbound: this.pendingCount('outbound'), pendingTransit: this.pendingCount('transit'),
      sources: [...new Map([...this.routes.values()].map(r => [r.nodeId, { nodeId: r.nodeId, sourceId: r.sourceId, issuedAt: r.payload.issuedAt, expiresAt: r.payload.expiresAt, browserSignatureVerified: true }])).values()],
      receipts: this.receipts.slice(-12), aiLoad: this.aiLoad, paused: this.paused(), endpointCircuits: this.endpointCount(), verification: 'native-RLPx-endpoints; browser-secp256k1-signatures-and-hop-receipts', channel: MESH_CHANNEL };
  }
  publishStats(force = false) { if (force || this.now() - this.lastStats >= 1000) { this.lastStats = this.now(); this.emit({ type: 'stats', stats: this.snapshot() }); } }
}

if (typeof WorkerGlobalScope !== 'undefined' && globalThis instanceof WorkerGlobalScope) {
  const engine = new MeshEngine({ post: message => postMessage(message) });
  globalThis.onmessage = event => { void engine.accept(event.data); };
  setInterval(() => { if (engine.active) void engine.accept({ type: 'tick' }); }, 100);
}
