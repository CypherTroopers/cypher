import { RelayController, Bucket } from './relay-controller.js?v=mesh-v1';
import { strictJSON } from './relay-protocol.js?v=relay-v1';
import { nativeCapacity } from './mesh-protocol.js';
import { createBrowserIdentity, safeGatewayOrigin, enodePublicKey, verifyMeshAdvertisement } from './mesh-discovery.js';
import { MeshDiscoveryClient, discoveryJSON } from './mesh-discovery-client.js';
const encoder = new TextEncoder();
const PROTOCOL = 'cypher-browser-mesh/1', CHANNEL = 'cypher-common-mesh/1', FRAME = 16384, ON_LIMIT = 100 * 1048576;
const COUNTERS = ['nativeReceivedBytes', 'nativeSentBytes', 'receivedBytes', 'sentBytes', 'streamReceivedBytes', 'streamForwardedBytes', 'acknowledgedBytes', 'acknowledgedCount', 'nativeCreditBytes', 'gatewayBytes', 'signalingBytes'];
const empty = () => ({ nativeConnections: 0, circuits: 0, pendingHandshakes: 0, routes: 0, queuedBytes: 0, appBytes: 0, totalBytes: 0, receipts: [], endpointCircuits: 0, transitCircuits: 0, pendingInbound: 0, pendingOutbound: 0, pendingTransit: 0, capacities: null, ...Object.fromEntries(COUNTERS.map(k => [k, 0])) });

/** Native WSS and peer signaling are different sockets. Only RTC carries inter-browser data. */
export class MeshController extends RelayController {
  constructor({ sourceId, iceTransportPolicy = 'all', maxCommonConnections = 20, ...options } = {}) {
    super({ ...options, base: '/relay/v1/mesh', channel: CHANNEL,
      workerURL: new URL('./mesh-worker.js?v=mesh-v1', import.meta.url) });
    this.sourceId = sourceId; this.icePolicy = iceTransportPolicy === 'relay' ? 'relay' : 'all';
    this.stats = empty(); this.carried = empty(); this.consumedBytes = 0; this.reconnects = 0;
    this.observedBytes = 0; this.pendingPeerSends = new Map();
    this.native = null; this.nativeSession = null; this.nativeConnected = false; this.rtcStats = [];
    if (!Number.isInteger(maxCommonConnections) || maxCommonConnections < 1 || maxCommonConnections > 20) throw new Error('Common connection limit must be between 1 and 20');
    this.maxCommonConnections = maxCommonConnections;
    this.attachments = new Map(); this.attachmentRetries = new Map(); this.attachmentAdmission = null; this.attachmentTimer = null;
    this.signalQueue = []; this.signalQueueBytes = 0; this.signalTimer = null; this.signalNextAt = 0;
  }
  peerLimit() { return Math.min(20, Math.max(1, this.config?.limits?.maxPeers || 20)); }
  pendingPeerLimit() { return 4; }
  commonLimit() { return Math.min(this.maxCommonConnections, this.config?.limits?.maxCommonConnections || 1); }
  snapshot() {
    const current = super.snapshot();
    for (const key of COUNTERS) current[key] = (this.carried?.[key] || 0) + (this.stats[key] || 0);
    return { ...current, protocol: PROTOCOL, sourceId: this.session?.sourceId || this.sourceId || null,
      nodeId: this.session?.nodeId || null, browserId: this.session?.browserId || null,
      nativeConnected: this.nativeConnected, nativeSession: this.nativeSession,
      nativeConnections: [...this.attachments.values()].filter(a => this.requested && a.connected && a.socket?.readyState === 1).length,
      commonConnections: [...this.attachments.values()].map(a => ({ id: a.session.id, sourceId: a.session.sourceId,
        nodeId: a.session.nodeId, browserId: a.session.browserId, connected: this.requested && a.connected && a.socket?.readyState === 1, expiresAt: a.session.expiresAt,
        remoteOrigin: a.session.remoteOrigin || null, endpointVerified: this.requested && a.endpointVerified === true, browserSignatureVerified: this.requested && a.browserSignatureVerified === true })),
      discovery: { enabled: Boolean(this.config?.discovery?.version === 1), verifiedEndpoints: this.discovery?.endpoints().length || 0,
        knownBrowserCandidates: this.discovery?.records.size || 0, connectedGateways: [...(this.discovery?.sockets.values() || [])].filter(s => s.ready && s.ws.readyState === 1).length,
        knownGatewayOrigins: this.discovery ? [...this.discovery.origins] : [] },
      connectionLimits: { peers: this.peerLimit(), commons: this.commonLimit() },
      totalBytes: this.observedBytes || 0, reconnects: this.reconnects, rtcStats: this.rtcStats, nativeStatus: this.nativeStatus || null };
  }
  observe(bytes) {
    if (!this.requested || !Number.isSafeInteger(bytes) || bytes < 0) return;
    this.observedBytes += bytes;
    if (this.observedBytes >= ON_LIMIT) this.stop('100 MiB participation limit reached', 'OFF_LIMIT');
  }
  account(bytes, direction, kind) { this.observe(bytes); super.account(bytes, direction, kind); }
  post(message, transfer = []) {
    if (message.type === 'message') this.observe(message.buffer?.byteLength || 0);
    if (message.type === 'sent' && this.pendingPeerSends.has(message.sendId)) {
      const bytes = this.pendingPeerSends.get(message.sendId); this.pendingPeerSends.delete(message.sendId); if (message.ok) this.observe(bytes);
    }
    if (message.type === 'message') message = { ...message, type: 'peerMessage' };
    if (message.type === 'peerOpen') {
      const candidate = this.candidates.get(message.peerId);
      message = { ...message, browserId: candidate?.browserId, nodeId: candidate?.nodeId, sourceId: candidate?.sourceId };
    }
    if (message.type === 'buffered' && !message.transport) message = { ...message, transport: 'peer' };
    super.post(message, transfer);
  }
  async start() {
    if (this.requested) return;
    if (globalThis.document?.visibilityState === 'hidden') throw new Error('Keep this page visible to join');
    this.carried = empty(); this.stats = empty(); this.consumedBytes = 0; this.observedBytes = 0; this.reconnects = 0; this.rejoinFailures = 0;
    this.attachmentRetries.clear();
    const g = ++this.generation; this.requested = true;
    await this.join(g);
  }
  async join(g) {
    if (!this.live(g)) return;
    this.abort = new AbortController(); this.prelude = []; this.sourceErrors = {};
    this.signalBucket = new Bucket(4096, 32768); this.lastNativeStats = 0;
    this.transition('CONNECTING', 'Opening a Common connection and browser mesh');
    try {
      if (!globalThis.Worker || !globalThis.RTCPeerConnection || !globalThis.crypto?.subtle) throw new Error('WebRTC, WebCrypto and Workers are required; WebGPU is not required.');
      const config = await this.json('/config', { authenticated: false, max: 65536 }, g);
      if (!this.live(g)) return;
      if (!config.enabled || config.version !== 1 || config.protocol !== PROTOCOL || !Array.isArray(config.nodes) || !config.nodes.length || config.nodes.length > 64) throw new Error('Common mesh is not configured');
      this.config = config;
      const session = await this.json('/sessions', { method: 'POST', authenticated: false,
        body: JSON.stringify(this.sourceId ? { sourceId: this.sourceId } : {}), max: 16384 }, g);
      if (!this.live(g)) { this.releaseSession(session); return; }
      delete session.remoteOrigin;
      this.session = session;
      this.validateSession(session);
      if (config.discovery?.version === 1) {
        const identity = createBrowserIdentity();
        session.peerId = identity.peerId;
        this.discovery = new MeshDiscoveryClient(this, identity, g);
      }
      this.worker = new Worker(this.workerURL, { type: 'module', name: 'Cypher encrypted Common mesh' });
      this.worker.onmessage = event => { if (this.live(g) && event.data.generation === g) this.workerMessage(event.data, g); };
      this.worker.onerror = () => { if (this.live(g)) this.stop('Mesh Worker failed', 'ERROR'); };
      this.post({ type: 'init', config, identity: { peerId: session.peerId, sessionId: session.id, browserId: session.browserId, sourceId: session.sourceId, nodeId: session.nodeId }, nativeLimits: session.nativeLimits, initialTotalBytes: this.consumedBytes });
      for (const entry of this.prelude.splice(0)) this.post(entry);
      this.post({ type: 'aiLoad', state: this.aiLoad });
      this.openNative(g); this.openSignal(g); this.heartbeat(g); this.renewSession(g);
      this.updateState();
    } catch (error) { if (this.live(g)) this.recover(error.message, g); }
  }
  validateSession(session, parentId, endpoint) {
    nativeCapacity(session.nativeLimits);
    if (![session.id, session.peerId, session.browserId].every(v => typeof v === 'string' && /^[a-f0-9]{32}$/.test(v)) ||
      typeof session.token !== 'string' || !Number.isSafeInteger(session.expiresAt) || session.expiresAt <= Date.now()) throw new Error('Invalid mesh session');
    if (parentId !== undefined && session.parentId !== parentId) throw new Error('Common attachment belongs to another participation');
    if (endpoint) {
      if (session.sourceId !== endpoint.sourceId || session.nodeId !== endpoint.nodeId || endpoint.expiresAt <= Date.now()) throw new Error('Common session differs from signed endpoint');
    } else if (!this.config.nodes.some(n => n.id === session.sourceId && n.nodeId === session.nodeId)) throw new Error('Common identity is not in the operator configuration');
  }
  scheduleAttachments(g, delay = 1100) {
    if (!this.live(g) || !this.nativeConnected || this.attachmentTimer || this.attachmentAdmission || this.aiLoad !== 'idle' || this.attachments.size >= this.commonLimit()) return;
    const marker = {}; this.attachmentTimer = marker;
    this.later(() => { if (this.attachmentTimer !== marker) return; this.attachmentTimer = null; return this.fillAttachments(g); }, delay, g);
  }
  async fillAttachments(g) {
    if (!this.live(g) || !this.nativeConnected || this.aiLoad !== 'idle' || this.attachmentAdmission || this.attachments.size >= this.commonLimit()) return;
    const parent = this.session;
    // An authenticated Common can join this gateway after the initial config
    // read. Its signed endpoint must be eligible without cycling node OFF/ON.
    const discovered = (this.discovery?.endpoints() || []).filter(n => n.origin !== location.origin ||
      !this.config.nodes.some(pin => pin.nodeId === n.nodeId)).map(endpoint => ({ id: endpoint.sourceId, nodeId: endpoint.nodeId, endpoint }));
    const targets = [...new Map([...discovered, ...this.config.nodes].map(n => [n.nodeId, n])).values()]
      .filter(n => ![...this.attachments.values()].some(a => a.session.nodeId === n.nodeId));
    const target = targets.find(n => { const r = this.attachmentRetries.get(n.nodeId); return (!r || (r.failures < 12 && r.at <= Date.now())); });
    if (!target) { if (targets.some(n => (this.attachmentRetries.get(n.nodeId)?.failures || 0) < 12)) this.scheduleAttachments(g, 5000); return; }
    const marker = {}; this.attachmentAdmission = marker; let child;
    try {
      if (target.endpoint) {
        const endpoint = target.endpoint;
        const remote = await discoveryJSON(this, endpoint.origin, '/config', { max: 65536 }, g);
        if (!this.live(g) || this.session !== parent) return;
        if (remote.version !== 1 || remote.protocol !== PROTOCOL || !remote.enabled || !Array.isArray(remote.nodes) || remote.nodes.length > 64 ||
          remote.network?.chainId !== this.config.network.chainId || remote.network?.genesisHash !== this.config.network.genesisHash ||
          !remote.nodes.some(n => n.id === endpoint.sourceId && n.nodeId === endpoint.nodeId && (n.publicKey || enodePublicKey(n.enode)) === endpoint.publicKey)) throw new Error('Remote gateway does not expose the signed Common identity');
        const home = endpoint.origin === location.origin;
        child = await discoveryJSON(this, endpoint.origin, '/sessions', { method: 'POST',
          body: JSON.stringify({ sourceId: endpoint.sourceId, ...(home ? { attach: true } : {}) }),
          ...(home ? { token: parent.token } : {}), max: 16384 }, g);
        // Mark the origin before any later validation so a rejected or late lease
        // is released only at the origin which issued it.
        child.remoteOrigin = endpoint.origin;
        child.endpointBootId = endpoint.payload.bootId;
        child.endpointAdvertisement = endpoint.envelope;
      } else { child = await this.json('/sessions', { method: 'POST', body: JSON.stringify({ sourceId: target.id, attach: true }), token: parent.token, max: 16384 }, g); delete child.remoteOrigin; }
      if (!this.live(g) || this.session !== parent) { this.releaseSession(child); return; }
      this.validateSession(child, target.endpoint && target.endpoint.origin !== location.origin ? undefined : parent.id, target.endpoint);
      if (child.sourceId !== target.id || this.attachments.has(child.id) || child.id === parent.id || [...this.attachments.values()].some(a => a.session.nodeId === child.nodeId) || this.attachments.size >= this.commonLimit()) throw new Error('Duplicate or excess Common attachment');
      this.openNative(g, child);
    } catch (error) {
      if (child) this.releaseSession(child);
      if (this.live(g) && this.session === parent) this.recordAttachmentFailure(target.id, error.message, target.nodeId);
    } finally {
      if (this.attachmentAdmission === marker) { this.attachmentAdmission = null; this.scheduleAttachments(g); }
    }
  }
  recordAttachmentFailure(sourceId, reason, nodeId) {
    const failures = (this.attachmentRetries.get(nodeId)?.failures || 0) + 1, errorKey = `${sourceId} (${nodeId.slice(0, 8)})`;
    if (!this.attachmentRetries.has(nodeId) && this.attachmentRetries.size >= 128) {
      const [first, value] = this.attachmentRetries.entries().next().value; this.attachmentRetries.delete(first); delete this.sourceErrors[value.errorKey];
    }
    this.attachmentRetries.set(nodeId, { errorKey, failures, at: Date.now() + Math.min(60000, 1000 * 2 ** Math.min(failures, 6)) });
    this.sourceErrors[errorKey] = reason;
  }
  retireAttachment(attachmentId, reason, g) {
    if (!attachmentId) { this.recover(reason, g); return; }
    const a = this.attachments.get(attachmentId); if (!a || !this.live(g)) return;
    this.attachments.delete(attachmentId); a.connected = false;
    a.socket.onmessage = null; a.socket.onclose = null; a.socket.onopen = null;
    try { a.socket.close(1000); } catch {}
    this.post({ type: 'nativeClose', attachmentId }); this.releaseSession(a.session);
    this.recordAttachmentFailure(a.session.sourceId, reason, a.session.nodeId);
    this.emit('event', { name: 'common-disconnected', sourceId: a.session.sourceId, reason });
    this.emit('stats', this.snapshot()); this.scheduleAttachments(g);
  }
  openNative(g, child) {
    if (!this.live(g)) return;
    const session = child || this.session, attachmentId = child?.id, key = attachmentId || 'native';
    const a = { attachmentId, session, connected: false, nativeSession: null, socket: null };
    const origin = session.remoteOrigin ? safeGatewayOrigin(session.remoteOrigin) : location.origin;
    const url = new URL(session.remoteOrigin ? `${this.base}/connect` : this.config.connectPath || `${this.base}/connect`, origin); url.protocol = origin.startsWith('https:') ? 'wss:' : 'ws:';
    if (url.origin.replace(/^ws/, 'http') !== origin) { this.stop('Common WSS origin mismatch', 'ERROR'); return; }
    const socket = new WebSocket(url); a.socket = socket; this.attachments.set(key, a); if (!child) this.native = socket;
    const current = () => this.live(g) && this.attachments.get(key) === a;
    socket.onopen = () => {
      if (!current()) { socket.close(); return; }
      const auth = JSON.stringify({ token: session.token }); socket.send(auth); this.account(encoder.encode(auth).length, 'out', 'https');
    };
    socket.onmessage = event => {
      if (!current()) return;
      try {
        if (typeof event.data !== 'string') throw new Error('Non-text native frame');
        this.observe(encoder.encode(event.data).length); if (!this.live(g)) return;
        const frame = strictJSON(event.data, FRAME);
        if (frame.type === 'hello') {
          if (a.connected || frame.protocol !== PROTOCOL || frame.browserId !== session.browserId || !/^[a-f0-9]{32}$/.test(frame.session)) throw new Error('Invalid native hello');
          if (session.remoteOrigin) {
            const advertisement = verifyMeshAdvertisement(frame.advertisement, this.config.network);
            if (advertisement.nodeId !== session.nodeId || advertisement.payload.bootId !== session.endpointBootId) throw new Error('Common hello differs from signed endpoint generation');
          }
          a.nativeSession = frame.session; a.connected = true;
          if (!child) { this.nativeSession = frame.session; this.nativeConnected = true; this.rejoinFailures = 0; }
          const retry = this.attachmentRetries.get(session.nodeId); if (retry) delete this.sourceErrors[retry.errorKey];
          this.attachmentRetries.delete(session.nodeId); delete this.sourceErrors[session.sourceId];
          this.post({ type: 'nativeHello', frame, sourceId: session.sourceId, ...(child ? { attachmentId, browserId: session.browserId, nodeId: session.nodeId, nativeLimits: session.nativeLimits,
            ...(session.remoteOrigin ? { endpointAdvertisement: session.endpointAdvertisement, gatewayOrigin: session.remoteOrigin } : {}) } : {}) });
          this.emit('event', { name: 'native-connected', nodeId: session.nodeId, sourceId: session.sourceId, nativeSession: frame.session, ...(child ? { attachmentId } : {}) });
          if (child) this.renewAttachment(a, g);
          this.scheduleAttachments(g);
          this.updateState();
        } else {
          if (!a.connected || frame.session !== a.nativeSession) throw new Error('Stale native generation');
          this.post({ type: 'nativeMessage', frame, ...(child ? { attachmentId } : {}) });
        }
      } catch { if (child) this.retireAttachment(attachmentId, 'Invalid or stale Common frame', g); else this.stop('Invalid or stale Common frame', 'ERROR'); }
    };
    socket.onerror = () => {};
    socket.onclose = () => { if (current()) this.retireAttachment(attachmentId, 'Common connection closed; creating a new session', g); };
    this.later(() => { if (current() && !a.connected) this.retireAttachment(attachmentId, 'Common handshake timed out', g); }, 10000, g);
  }
  renewAttachment(a, g) {
    const delay = Math.min((this.config.limits?.renewAfterMs || 120000) + this.attachments.size * 500,
      Math.max(1000, a.session.expiresAt - Date.now() - 30000));
    this.later(async () => {
      if (this.attachments.get(a.attachmentId) !== a) return;
      try {
        const update = a.session.remoteOrigin ? await discoveryJSON(this, a.session.remoteOrigin, '/renew', { method: 'POST', token: a.session.token, max: 8192 }, g) :
          await this.json('/renew', { method: 'POST', token: a.session.token, max: 8192 }, g);
        if (!this.live(g) || this.attachments.get(a.attachmentId) !== a) return;
        if (!Number.isSafeInteger(update.expiresAt) || update.expiresAt <= Date.now()) throw new Error('Expired Common attachment');
        a.session.expiresAt = update.expiresAt;
        this.emit('event', { name: 'common-renewed', sourceId: a.session.sourceId, expiresAt: update.expiresAt }); this.renewAttachment(a, g);
      } catch { if (this.live(g) && this.attachments.get(a.attachmentId) === a) this.retireAttachment(a.attachmentId, 'Common attachment renewal failed', g); }
    }, delay, g);
  }
  releaseSession(session) {
    if (!session?.token) return;
    const origin = session.remoteOrigin ? safeGatewayOrigin(session.remoteOrigin) : '';
    fetch(`${origin}${this.base}/sessions`, { method: 'DELETE', headers: { Authorization: `Bearer ${session.token}` }, credentials: 'omit', mode: 'cors', redirect: 'error', keepalive: true }).catch(() => {});
  }
  stop(reason = 'Stopped by you', state = 'OFF') {
    // Neighbors propagate circuit close when this hop closes; native WS closure
    // removes every circuit/candidate belonging to its session at the Common.
    this.discovery?.stop(); this.discovery = null;
    for (const a of this.attachments.values()) {
      if (a.session.remoteOrigin) this.releaseSession(a.session);
      a.connected = false;
      if (!a.socket) continue;
      a.socket.onmessage = null; a.socket.onclose = null; a.socket.onopen = null;
      try { a.socket.close(1000); } catch {}
    }
    this.attachments.clear(); this.native = null;
    this.attachmentAdmission = null; this.attachmentTimer = null;
    this.signalQueue = []; this.signalQueueBytes = 0; this.signalTimer = null; this.signalNextAt = 0;
    this.nativeConnected = false; this.nativeSession = null; this.nativeStatus = null;
    this.nativeStatusRead = null; this.rtcRead = null;
    super.stop(reason, state);
    this.stats = { ...this.stats, nativeConnections: 0, circuits: 0, endpointCircuits: 0, transitCircuits: 0, pendingHandshakes: 0, pendingInbound: 0, pendingOutbound: 0, pendingTransit: 0, routes: 0, queuedBytes: 0, appBytes: 0, capacities: null };
    this.pendingPeerSends.clear(); this.rtcStats = []; this.emit('stats', this.snapshot());
  }
  recover(reason, g) {
    if (!this.live(g)) return;
    const current = this.snapshot();
    this.consumedBytes = Math.max(this.consumedBytes, current.totalBytes || 0);
    this.stop(reason, 'RECONNECTING');
    for (const key of COUNTERS) this.carried[key] = current[key] || 0;
    this.stats = { ...empty(), totalBytes: this.consumedBytes };
    if (this.consumedBytes >= ON_LIMIT) { this.transition('OFF_LIMIT', '100 MiB participation limit reached'); return; }
    if (++this.rejoinFailures > 12) { this.transition('ERROR', 'Common remains unavailable. Turn Node ON to try again.'); return; }
    this.requested = true; this.reconnects++; const next = this.generation;
    this.transition('RECONNECTING', reason);
    const delay = Math.min(15000, 1000 * 2 ** Math.min(this.rejoinFailures - 1, 4)) + Math.random() * 250;
    this.later(() => this.join(next), delay, next);
  }
  async renewSession(g) {
    if (!this.live(g)) return;
    const delay = Math.min(this.config.limits?.renewAfterMs || 120000, Math.max(1000, this.session.expiresAt - Date.now() - 30000));
    this.later(async () => {
      try {
        const update = await this.json('/renew', { method: 'POST', max: 8192 }, g);
        if (!this.live(g)) return;
        if (!Number.isSafeInteger(update.expiresAt) || update.expiresAt <= Date.now()) throw new Error('Expired session');
        this.session.expiresAt = update.expiresAt;
        if (Array.isArray(update.iceServers)) this.session.iceServers = update.iceServers;
        this.emit('event', { name: 'session-renewed', expiresAt: update.expiresAt }); this.renewSession(g);
      } catch { if (this.live(g)) this.recover('Session renewal failed; reconnecting with a fresh identity', g); }
    }, delay, g);
  }
  updateState() {
    if (!this.requested) return;
    if (['loading', 'benchmarking'].includes(this.aiLoad)) this.transition('PAUSED_AI', 'Circuits paused while local AI loads or benchmarks');
    else if (this.nativeConnected && [...this.peers.values()].some(p => p.dc?.readyState === 'open')) this.transition('ACTIVE', 'Encrypted Common traffic can pass through browser peers');
    else this.transition(this.nativeConnected ? 'WAITING_PEER' : 'CONNECTING', this.nativeConnected ? 'Common connected. Waiting for a browser peer.' : 'Connecting to the assigned Common');
  }
  setAiLoad(state) { super.setAiLoad(state); if (state === 'idle') this.scheduleAttachments(this.generation); }
  openSignal(g) {
    if (!this.discovery) { super.openSignal(g); return; }
    this.ws = this.discovery.transport; this.discovery.start();
  }
  signal(message) {
    if (this.discovery) return this.discovery.send(message);
    if (!this.requested || this.ws?.readyState !== WebSocket.OPEN) return false;
    const text = JSON.stringify(message), bytes = encoder.encode(text).length;
    if (message.type === 'auth') { this.signalQueue = []; this.signalQueueBytes = 0; this.signalTimer = null; this.signalNextAt = 0; }
    if (bytes > 32768 || this.signalQueue.length >= 64 || this.signalQueueBytes + bytes > 65536) { this.stop('Signaling queue limit', 'OFF_LIMIT'); return false; }
    this.signalQueue.push({ text, bytes, socket: this.ws, to: message.to, peer: this.peers.get(message.to) }); this.signalQueueBytes += bytes;
    this.pumpSignal(this.generation); return true;
  }
  pumpSignal(g) {
    if (!this.live(g) || this.signalTimer) return;
    while (this.signalQueue.length) {
      const row = this.signalQueue[0];
      if (row.socket !== this.ws || (row.to && this.peers.get(row.to) !== row.peer)) { this.signalQueue.shift(); this.signalQueueBytes -= row.bytes; continue; }
      if (this.ws?.readyState !== WebSocket.OPEN) return;
      if (Date.now() < this.signalNextAt || this.ws.bufferedAmount + row.bytes > 32768 || !this.signalBucket.take(row.bytes)) break;
      this.signalQueue.shift(); this.signalQueueBytes -= row.bytes;
      try { this.ws.send(row.text); } catch { this.recover('Signaling send failed', g); return; }
      this.signalNextAt = Date.now() + 150; this.account(row.bytes, 'out', 'signal');
      break; // Pace negotiation below the gateway's unchanged 10 messages/s cap.
    }
    if (this.live(g) && this.signalQueue.length) {
      const marker = {}; this.signalTimer = marker;
      this.later(() => { if (this.signalTimer !== marker) return; this.signalTimer = null; this.pumpSignal(g); }, 150, g);
    }
  }
  transportBufferedBytes() {
    return [...this.attachments.values()].reduce((sum, a) => sum + (a.socket?.bufferedAmount || 0), 0) +
      [...this.peers.values()].reduce((sum, p) => sum + (p.dc?.bufferedAmount || 0), 0);
  }
  createPeer(candidate, g) {
    const peer = super.createPeer(candidate, g);
    if (peer && this.icePolicy === 'relay') peer.pc.setConfiguration({ ...peer.pc.getConfiguration(), iceTransportPolicy: 'relay' });
    return peer;
  }
  workerMessage(message, g) {
    if (message.type === 'event' && message.name === 'native_ready') {
      const a = this.attachments.get(message.attachmentId || 'native');
      if (a?.connected && a.session.browserId === message.browserId && a.session.nodeId === message.nodeId) {
        a.browserSignatureVerified = message.browserSignatureVerified === true; a.endpointVerified = message.endpointSignatureVerified === true;
      }
    }
    if (message.type === 'send' && message.transport === 'native') {
      let ok = false; const a = this.attachments.get(message.attachmentId || 'native'), socket = a?.socket;
      try {
        const size = encoder.encode(message.text).length;
        if (a?.connected && socket?.readyState === 1 && size <= FRAME && socket.bufferedAmount + size <= 65536 && this.transportBufferedBytes() + size <= 512 * 1024) { socket.send(message.text); ok = true; this.observe(size); }
      } catch {}
      this.post({ type: 'sent', sendId: message.sendId, ok, bufferedAmount: socket?.bufferedAmount || 0 });
    } else if (message.type === 'send') {
      const size = encoder.encode(message.text).length;
      if (this.transportBufferedBytes() + size > 512 * 1024) { this.post({ type: 'sent', sendId: message.sendId, ok: false, bufferedAmount: 0 }); return; }
      this.pendingPeerSends.set(message.sendId, size); super.workerMessage(message, g);
    } else if (message.type === 'disconnect' && message.transport === 'native') {
      this.retireAttachment(message.attachmentId, `Common route closed: ${message.reason || 'transport failure'}`, g);
    } else if (message.type === 'stopped') this.stop(message.reason === 'limit' ? '100 MiB participation limit reached' : 'Mesh Worker stopped', message.reason === 'limit' ? 'OFF_LIMIT' : 'ERROR');
    else super.workerMessage(message, g);
  }
  heartbeat(g) {
    if (!this.live(g)) return;
    for (const a of this.attachments.values()) this.post({ type: 'buffered', transport: 'native', ...(a.attachmentId ? { attachmentId: a.attachmentId } : {}), bytes: a.socket?.bufferedAmount || 0 });
    super.heartbeat(g);
    if (Date.now() - this.lastNativeStats >= 10000) {
      this.lastNativeStats = Date.now(); this.readNativeStatus(g); this.collectRTC(g);
    }
  }
  async readNativeStatus(g) {
    if (!this.live(g) || !this.nativeConnected || this.nativeStatusRead) return;
    const read = {}; this.nativeStatusRead = read;
    try {
      const status = await this.json('/status', { max: 131072 }, g);
      if (this.live(g)) { this.nativeStatus = status; delete this.sourceErrors[this.session.sourceId]; }
    } catch (error) {
      if (!this.live(g) || !this.session) return;
      // A rejected lease is no longer evidence of native readiness, even if
      // the browser has not yet received the transport's close event.
      if (error.status === 401) this.recover('Common session is no longer valid; reconnecting with a fresh identity', g);
      else this.sourceErrors[this.session.sourceId] = error.message;
    }
    finally { if (this.nativeStatusRead === read) this.nativeStatusRead = null; }
  }
  async collectRTC(g) {
    if (!this.live(g) || this.rtcRead) return;
    const read = {}; this.rtcRead = read;
    try {
      const peers = [...this.peers.values()]; const records = [];
      for (const peer of peers) {
        try {
          const report = await peer.pc.getStats(); if (!this.live(g)) return;
          if (this.peers.get(peer.peerId) !== peer) continue;
          let bytesSent = 0, bytesReceived = 0, messagesSent = 0, messagesReceived = 0;
          for (const entry of report.values()) if (entry.type === 'data-channel' && entry.label === CHANNEL) {
            bytesSent += entry.bytesSent || 0; bytesReceived += entry.bytesReceived || 0;
            messagesSent += entry.messagesSent || 0; messagesReceived += entry.messagesReceived || 0;
          }
          records.push({ peerId: peer.peerId, bytesSent, bytesReceived, messagesSent, messagesReceived, path: peer.path });
          await this.inspectPath(peer, g);
        } catch {}
      }
      if (this.live(g)) this.rtcStats = records;
    } finally {
      if (this.rtcRead === read) this.rtcRead = null;
    }
  }
}
