/* Window owns network transports; the dedicated Worker owns verification and RAM. */
const utf8 = new TextEncoder();
const CHANNEL = 'cypher-public-headers/1';
const MAX_MESSAGE = 16 * 1024, MAX_SIGNAL = 32 * 1024, BUFFER_HIGH = 64 * 1024;
const blankStats = () => ({ connectedPeers: 0, cacheEntries: 0, cacheBytes: 0, receivedBytes: 0, sentBytes: 0, gatewayBytes: 0, signalingBytes: 0, totalBytes: 0, acknowledgedBytes: 0, acknowledgedCount: 0, inflight: 0, queuedBytes: 0, appBytes: 0, sources: [], receipts: [] });
export class Bucket {
  constructor(rate, burst) { this.rate = rate; this.burst = burst; this.tokens = burst; this.at = performance.now(); }
  take(n) { const now = performance.now(); this.tokens = Math.min(this.burst, this.tokens + (now - this.at) * this.rate / 1000); this.at = now; if (n > this.tokens) return false; this.tokens -= n; return true; }
}
export class RelayController extends EventTarget {
  constructor({ base = '/relay/v1', allowFallback, channel = CHANNEL, workerURL = new URL('./relay-worker.js?v=relay-v1', import.meta.url) } = {}) {
    super(); this.base = base; this.fallback = allowFallback; this.workerURL = workerURL; this.channel = channel;
    this.generation = 0; this.requested = false; this.state = 'OFF'; this.reason = ''; this.aiLoad = 'idle';
    this.stats = blankStats(); this.peers = new Map(); this.candidates = new Map(); this.timers = new Set(); this.pendingInspect = new Map();
    this.onHide = () => { if (document.visibilityState === 'hidden') this.stop('Page moved to the background'); };
    this.onPageHide = () => this.stop('Page closed or suspended');
    globalThis.document?.addEventListener?.('visibilitychange', this.onHide);
    globalThis.addEventListener?.('pagehide', this.onPageHide);
    globalThis.document?.addEventListener?.('freeze', this.onPageHide);
  }
  live(g) { return this.requested && g === this.generation; }
  emit(type, detail) { this.dispatchEvent(new CustomEvent(type, { detail })); }
  transition(state, reason = this.reason) { this.state = state; this.reason = reason; this.emit('state', this.snapshot()); }
  snapshot() {
    return { ...this.stats, state: this.state, reason: this.reason, requested: this.requested, aiLoad: this.aiLoad,
      sourceErrors: { ...this.sourceErrors }, sessionId: this.session?.id, sessionExpiresAt: this.session?.expiresAt,
      signalConnected: this.ws?.readyState === 1, selfGeo: this.session?.geo || null, peers: [...this.peers].map(([peerId, p]) => ({ peerId, sessionId: p.sessionId, state: p.pc.connectionState, path: p.path, geo: p.geo || null, connected: p.dc?.readyState === 'open' })) };
  }
  later(fn, ms, g = this.generation) {
    const timer = setTimeout(() => { this.timers.delete(timer); if (this.live(g)) fn(); }, ms);
    this.timers.add(timer); return timer;
  }
  post(message, transfer = []) { if (this.requested && this.worker) this.worker.postMessage({ ...message, generation: this.generation }, transfer); }
  account(bytes, direction, kind) {
    if (!bytes) return;
    if (!this.worker) { if (this.requested) this.prelude.push({ type: 'account', bytes, direction, kind }); return; }
    this.post({ type: 'account', bytes, direction, kind });
  }
  async request(path, { method = 'GET', body, max = 24 * 1024, authenticated = true, metadata = false, token } = {}, g = this.generation) {
    if (!this.live(g)) throw new Error('Relay stopped');
    const headers = { Accept: 'application/json' };
    if (authenticated) headers.Authorization = `Bearer ${token ?? this.session.token}`;
    if (body) headers['Content-Type'] = 'application/json';
    if (metadata && !this.metadataBucket.take(max)) throw new Error('Manifest bandwidth limit; retrying');
    if (body) this.account(utf8.encode(body).length, 'out', 'https');
    const response = await fetch(`${this.base}${path}`, { method, headers, body, cache: 'no-store', credentials: 'omit', signal: this.abort.signal, redirect: 'error' });
    if (!this.live(g)) { await response.body?.cancel(); throw new Error('Relay stopped'); }
    const size = Number(response.headers.get('content-length'));
    if (size > max) { await response.body?.cancel(); throw new Error('Gateway message too large'); }
    const reader = response.body.getReader(); let n = 0; const chunks = [];
    try {
      while (true) {
        const { value, done } = await reader.read(); if (done) break;
        if (!this.live(g)) throw new Error('Relay stopped');
        n += value.byteLength; this.account(value.byteLength, 'in', 'https');
        if (n > max) throw new Error('Gateway message too large'); chunks.push(value);
      }
    } catch (error) { await reader.cancel().catch(() => {}); throw error; }
    const result = new Uint8Array(n); let offset = 0; for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.length; }
    if (!response.ok) throw Object.assign(new Error(`Gateway ${response.status}${response.status === 503 ? ': source not ready or expired' : ''}`), { status: response.status });
    return result.buffer;
  }
  async json(path, options, g) { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(await this.request(path, options, g))); }
  async start() {
    if (this.requested) return;
    if (globalThis.document?.visibilityState === 'hidden') throw new Error('Keep this page visible to join');
    const g = ++this.generation; this.requested = true; this.stats = blankStats(); this.sourceErrors = {}; this.seedQueue = new Map(); this.seedBusy = false; this.prelude = []; this.manifestIndex = 0;
    this.abort = new AbortController(); this.signalBucket = new Bucket(4096, MAX_SIGNAL); this.metadataBucket = new Bucket(3072, 24576);
    this.transition('CONNECTING', 'Connecting to the public-header relay');
    try {
      if (!globalThis.Worker || !globalThis.RTCPeerConnection || !globalThis.crypto?.subtle) throw new Error('This browser needs WebRTC, WebCrypto and Workers. WebGPU is not required.');
      const config = await this.json('/config', { authenticated: false }, g);
      if (!this.live(g)) return;
      this.config = config;
      if (!this.config.enabled || this.config.version !== 1 || !Array.isArray(this.config.sources) || this.config.sources.length < 1 || this.config.sources.length > 2) throw new Error('Relay is not configured');
      const session = await this.json('/sessions', { method: 'POST', authenticated: false, body: JSON.stringify({ userApproved: true }) }, g);
      if (!this.live(g)) { this.releaseSession(session); return; }
      this.session = session;
      if (!this.session.id || !this.session.peerId || !this.session.token || !Number.isFinite(this.session.expiresAt)) throw new Error('Invalid relay session');
      this.worker = new Worker(this.workerURL, { type: 'module', name: 'Cypher public header relay' });
      this.worker.onmessage = event => { if (this.live(g) && event.data.generation === g) this.workerMessage(event.data, g); };
      this.worker.onerror = () => { if (this.live(g)) this.stop('Verification Worker failed', 'ERROR'); };
      this.post({ type: 'init', config: { ...this.config, allowFallback: this.fallback ?? this.config.allowGatewayFallback, role: this.session.role }, identity: { peerId: this.session.peerId, sessionId: this.session.id } });
      for (const entry of this.prelude.splice(0)) this.post(entry);
      this.post({ type: 'aiLoad', state: this.aiLoad });
      this.adoptPeers(this.session.peers || [], g); this.openSignal(g);
      this.pollManifests(g); this.heartbeat(g); this.renewSession(g); this.pumpSeeds(g);
      this.updateState();
    } catch (error) { if (this.live(g)) this.stop(error.message, 'ERROR'); }
  }
  releaseSession(session) {
    if (!session?.id || !session?.token) return;
    // Best effort; local shutdown never waits for the network. Expiry is the backstop.
    fetch(`${this.base}/sessions/${encodeURIComponent(session.id)}`, { method: 'DELETE', headers: { Authorization: `Bearer ${session.token}` }, credentials: 'omit', keepalive: true }).catch(() => {});
  }
  stop(reason = 'Stopped by you', state = 'OFF') {
    this.requested = false; ++this.generation; this.abort?.abort();
    for (const timer of this.timers) clearTimeout(timer); this.timers.clear();
    const session = this.session; this.session = null;
    if (this.ws) { this.ws.onclose = null; this.ws.onmessage = null; try { this.ws.close(1000); } catch {} this.ws = null; }
    for (const peerId of [...this.peers.keys()]) this.closePeer(peerId, false);
    this.candidates.clear(); this.worker?.terminate(); this.worker = null;
    this.seedQueue?.clear(); this.seedBusy = false;
    for (const pending of this.pendingInspect.values()) pending.reject(new Error('Relay stopped')); this.pendingInspect.clear();
    this.stats = { ...this.stats, connectedPeers: 0, cacheEntries: 0, cacheBytes: 0, queuedBytes: 0, inflight: 0, appBytes: 0 };
    this.releaseSession(session); this.transition(state, reason);
  }
  destroy() {
    this.stop(); globalThis.document?.removeEventListener?.('visibilitychange', this.onHide);
    globalThis.removeEventListener?.('pagehide', this.onPageHide); globalThis.document?.removeEventListener?.('freeze', this.onPageHide);
  }
  setAiLoad(state) {
    if (!['idle', 'loading', 'benchmarking', 'generating'].includes(state)) throw new Error('Unknown AI load');
    this.aiLoad = state; this.post({ type: 'aiLoad', state });
    if (this.requested) { this.updateState(); if (state === 'idle') this.connectNext(this.generation); }
  }
  updateState() {
    if (!this.requested) return;
    if (['loading', 'benchmarking'].includes(this.aiLoad)) this.transition('PAUSED_AI', 'Header transfers paused while local AI is busy');
    else if ([...this.peers.values()].some(p => p.dc?.readyState === 'open')) this.transition('ACTIVE', 'Browser-to-browser relay connected');
    else this.transition(this.ws?.readyState === WebSocket.OPEN ? 'WAITING_PEER' : 'RECONNECTING', 'Waiting for a browser peer');
  }
  async pollManifests(g) {
    for (const source of [this.config.sources[this.manifestIndex++ % this.config.sources.length]]) {
      if (!this.live(g)) return;
      try {
        const envelope = await this.request(`/head?sourceId=${encodeURIComponent(source.sourceId)}`, { metadata: true }, g);
        if (!this.live(g)) return;
        delete this.sourceErrors[source.sourceId]; this.post({ type: 'manifest', sourceId: source.sourceId, envelope, https: true }, [envelope]);
      } catch (error) { if (this.live(g)) this.sourceErrors[source.sourceId] = error.message; }
    }
    this.later(() => this.pollManifests(g), 11000, g);
  }
  async renewSession(g) {
    if (!this.live(g)) return;
    this.later(async () => {
      try {
        const renewed = await this.json(`/sessions/${encodeURIComponent(this.session.id)}/renew`, { method: 'POST', body: JSON.stringify({ userApproved: true }) }, g);
        if (!this.live(g)) return;
        this.session.expiresAt = renewed.expiresAt;
        if (Array.isArray(renewed.iceServers)) this.session.iceServers = renewed.iceServers;
        this.emit('event', { name: 'session-renewed', expiresAt: renewed.expiresAt }); this.renewSession(g);
      } catch (error) {
        if (!this.live(g)) return;
        if (Date.now() + 15000 >= this.session.expiresAt) this.stop('Relay session expired; turn Node ON to join again', 'ERROR');
        else this.later(() => this.renewSession(g), 3000, g);
      }
    }, Math.min(this.config.limits?.renewAfterMs || 120000, Math.max(1000, this.session.expiresAt - Date.now() - 30000)), g);
  }
  openSignal(g) {
    if (!this.live(g)) return;
    const url = new URL(this.config.signalPath || `${this.base}/signal`, location.href); url.protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    if (url.origin.replace(/^ws/, 'http') !== location.origin) { this.stop('Signaling must use this site', 'ERROR'); return; }
    const ws = new WebSocket(url); this.ws = ws;
    ws.onopen = () => { if (!this.live(g) || this.ws !== ws) { ws.close(); return; } this.lastSignalPing = Date.now(); this.signal({ type: 'auth', id: this.session.id, token: this.session.token }); };
    ws.onmessage = event => {
      if (!this.live(g) || this.ws !== ws) return;
      try {
        if (typeof event.data !== 'string' || utf8.encode(event.data).length > MAX_SIGNAL) throw new Error('Signaling size limit');
        this.account(utf8.encode(event.data).length, 'in', 'signal');
        if (!this.live(g) || this.ws !== ws) return;
        const message = JSON.parse(event.data);
        if (message.type === 'ready' || message.type === 'peers') { this.signalRetries = 0; this.adoptPeers(message.peers || [], g); this.updateState(); }
        else if (message.type === 'peer-left') { this.candidates.delete(message.peerId); this.closePeer(message.peerId); }
        else if (message.type === 'renewed') {
          this.session.expiresAt = message.expiresAt;
          if (Array.isArray(message.iceServers)) this.session.iceServers = message.iceServers;
        }
        else if (['offer', 'answer', 'ice'].includes(message.type)) {
          const operation = this.receiveSignal(message, g), peer = this.peers.get(message.from);
          operation.catch(() => { if (this.live(g) && peer && this.peers.get(message.from) === peer) this.closePeer(message.from); });
        }
        else if (message.type === 'error') this.emit('event', { name: 'error', code: 'SIGNAL', message: 'Signaling request rejected' });
      } catch { this.stop('Invalid signaling response', 'ERROR'); }
    };
    ws.onerror = () => {}; // close owns retry; no secret URL or SDP in diagnostics.
    ws.onclose = () => {
      if (!this.live(g) || this.ws !== ws) return;
      this.ws = null; this.updateState();
      if (Date.now() >= this.session.expiresAt) { this.stop('Relay session expired', 'ERROR'); return; }
      const delay = Math.min(15000, 1000 * 2 ** Math.min(this.signalRetries || 0, 4)); this.signalRetries = (this.signalRetries || 0) + 1;
      this.later(() => this.openSignal(g), delay + Math.random() * 250, g);
    };
  }
  signal(message) {
    if (!this.requested || this.ws?.readyState !== WebSocket.OPEN) return false;
    const text = JSON.stringify(message), bytes = utf8.encode(text).length;
    if (bytes > MAX_SIGNAL || this.ws.bufferedAmount + bytes > MAX_SIGNAL || !this.signalBucket.take(bytes)) {
      this.stop('Signaling resource limit', 'OFF_LIMIT'); return false;
    }
    this.ws.send(text); this.account(bytes, 'out', 'signal'); return true;
  }
  peerLimit() { return 3; }
  pendingPeerLimit() { return 1; }
  adoptPeers(peers, g) {
    if (!Array.isArray(peers) || peers.length > this.peerLimit()) { this.stop('Too many assigned peers', 'ERROR'); return; }
    const next = new Map();
    for (const peer of peers) {
      if (typeof peer.peerId !== 'string' || typeof peer.id !== 'string' || peer.peerId === this.session.peerId) continue;
      next.set(peer.peerId, { ...peer, failures: this.candidates.get(peer.peerId)?.failures || 0, retryAt: this.candidates.get(peer.peerId)?.retryAt || 0 });
    }
    const removed = [...this.candidates.keys()].filter(id => !next.has(id));
    this.candidates = next;
    for (const id of removed) this.closePeer(id, false); this.connectNext(g);
  }
  connectNext(g) {
    if (!this.live(g) || this.aiLoad !== 'idle' || this.ws?.readyState !== WebSocket.OPEN || this.peers.size >= this.peerLimit() || [...this.peers.values()].filter(p => p.pc.connectionState === 'new' || p.pc.connectionState === 'connecting').length >= this.pendingPeerLimit()) return;
    const candidate = [...this.candidates.values()].find(p => p.initiator && !this.peers.has(p.peerId) && p.retryAt <= Date.now());
    if (!candidate) return;
    const peer = this.createPeer(candidate, g); if (!peer) return;
    this.attachChannel(peer, peer.pc.createDataChannel(this.channel, { ordered: true }), g);
    (async () => {
      const offer = await peer.pc.createOffer();
      if (!this.live(g) || this.peers.get(candidate.peerId) !== peer) return;
      await peer.pc.setLocalDescription(offer);
      if (this.live(g) && this.peers.get(candidate.peerId) === peer) this.signal({ type: 'offer', to: candidate.peerId, sdp: peer.pc.localDescription.sdp });
    })().catch(() => { if (this.live(g) && this.peers.get(candidate.peerId) === peer) this.closePeer(candidate.peerId); });
  }
  createPeer(candidate, g) {
    if (!this.live(g) || this.aiLoad !== 'idle' || this.peers.size >= this.peerLimit() || [...this.peers.values()].filter(p => ['new', 'connecting'].includes(p.pc.connectionState)).length >= this.pendingPeerLimit()) return null;
    const pc = new RTCPeerConnection({ iceServers: this.session.iceServers || this.config.iceServers || [], iceTransportPolicy: 'all', bundlePolicy: 'max-bundle' });
    const peer = { pc, peerId: candidate.peerId, sessionId: candidate.id, geo: candidate.geo, path: 'unknown', ice: [], iceReceived: 0, iceSent: 0 };
    this.peers.set(peer.peerId, peer);
    pc.onicecandidate = event => {
      if (!this.live(g) || this.peers.get(peer.peerId) !== peer) return;
      if (++peer.iceSent > 64) { this.closePeer(peer.peerId); return; }
      this.signal({ type: 'ice', to: peer.peerId, candidate: event.candidate?.toJSON() || null });
    };
    pc.ondatachannel = event => this.attachChannel(peer, event.channel, g);
    pc.onconnectionstatechange = () => {
      if (!this.live(g) || this.peers.get(peer.peerId) !== peer) return;
      if (['failed', 'closed', 'disconnected'].includes(pc.connectionState)) this.closePeer(peer.peerId);
      else if (pc.connectionState === 'connected') { this.inspectPath(peer, g); this.connectNext(g); }
      this.updateState();
    };
    this.later(() => { if (this.peers.get(peer.peerId) === peer && peer.dc?.readyState !== 'open') this.closePeer(peer.peerId); }, 15000, g);
    return peer;
  }
  async receiveSignal(message, g) {
    const candidate = this.candidates.get(message.from); if (!candidate) return;
    let peer = this.peers.get(message.from);
    if (message.type === 'offer') {
      if (candidate.initiator || typeof message.sdp !== 'string') return;
      if (peer) this.closePeer(message.from, false);
      peer = this.createPeer(candidate, g); if (!peer) return;
      await peer.pc.setRemoteDescription({ type: 'offer', sdp: message.sdp });
      if (!this.live(g) || this.peers.get(message.from) !== peer) return;
      for (const ice of peer.ice.splice(0)) {
        if (!this.live(g) || this.peers.get(message.from) !== peer) return;
        await peer.pc.addIceCandidate(ice);
      }
      if (!this.live(g) || this.peers.get(message.from) !== peer) return;
      const answer = await peer.pc.createAnswer();
      if (!this.live(g) || this.peers.get(message.from) !== peer) return;
      await peer.pc.setLocalDescription(answer);
      if (this.live(g) && this.peers.get(message.from) === peer) this.signal({ type: 'answer', to: message.from, sdp: peer.pc.localDescription.sdp });
    } else if (message.type === 'answer' && peer && peer.pc.signalingState === 'have-local-offer') {
      await peer.pc.setRemoteDescription({ type: 'answer', sdp: message.sdp });
      if (!this.live(g) || this.peers.get(message.from) !== peer) return;
      for (const ice of peer.ice.splice(0)) {
        if (!this.live(g) || this.peers.get(message.from) !== peer) return;
        await peer.pc.addIceCandidate(ice);
      }
    } else if (message.type === 'ice' && peer) {
      if (utf8.encode(JSON.stringify(message.candidate)).length > 2048 || ++peer.iceReceived > 64) { this.closePeer(message.from); return; }
      if (peer.pc.remoteDescription) await peer.pc.addIceCandidate(message.candidate);
      else peer.ice.push(message.candidate);
    }
  }
  attachChannel(peer, dc, g) {
    if (!this.live(g) || dc.label !== this.channel || peer.dc || !dc.ordered || dc.maxRetransmits !== null || dc.maxPacketLifeTime !== null) { dc.close(); return; }
    peer.dc = dc; dc.binaryType = 'arraybuffer'; dc.bufferedAmountLowThreshold = 16 * 1024;
    dc.onopen = () => {
      if (!this.live(g) || this.peers.get(peer.peerId) !== peer) { dc.close(); return; }
      const maxMessageSize = peer.pc.sctp?.maxMessageSize || MAX_MESSAGE;
      if (maxMessageSize < MAX_MESSAGE) { this.closePeer(peer.peerId); return; }
      this.post({ type: 'peerOpen', peerId: peer.peerId, sessionId: peer.sessionId, path: peer.path, maxMessageSize });
      this.inspectPath(peer, g); this.updateState(); this.connectNext(g);
    };
    dc.onmessage = event => {
      if (!this.live(g) || this.peers.get(peer.peerId) !== peer) return;
      const buffer = typeof event.data === 'string' ? utf8.encode(event.data).buffer : event.data;
      if (!(buffer instanceof ArrayBuffer) || buffer.byteLength > MAX_MESSAGE) { this.closePeer(peer.peerId); return; }
      this.post({ type: 'message', peerId: peer.peerId, buffer }, [buffer]);
    };
    dc.onbufferedamountlow = () => this.post({ type: 'buffered', peerId: peer.peerId, bytes: dc.bufferedAmount });
    dc.onerror = () => this.closePeer(peer.peerId); dc.onclose = () => this.closePeer(peer.peerId);
  }
  async inspectPath(peer, g) {
    try {
      const report = await peer.pc.getStats(); if (!this.live(g) || this.peers.get(peer.peerId) !== peer) return;
      let selected; for (const s of report.values()) if (s.type === 'transport' && s.selectedCandidatePairId) selected = report.get(s.selectedCandidatePairId);
      if (!selected) for (const s of report.values()) if (s.type === 'candidate-pair' && s.state === 'succeeded' && s.nominated) selected = s;
      if (selected) {
        const local = report.get(selected.localCandidateId), remote = report.get(selected.remoteCandidateId);
        peer.path = local?.candidateType === 'relay' || remote?.candidateType === 'relay' ? 'TURN' : local && remote ? 'direct' : 'unknown';
        this.post({ type: 'peerPath', peerId: peer.peerId, path: peer.path });
      }
    } catch { /* No invented route when the browser cannot expose candidate stats. */ }
  }
  closePeer(peerId, retry = true) {
    const peer = this.peers.get(peerId); if (!peer) return;
    this.peers.delete(peerId); peer.pc.onconnectionstatechange = null; peer.pc.onicecandidate = null; peer.pc.ondatachannel = null;
    if (peer.dc) { peer.dc.onclose = null; peer.dc.onbufferedamountlow = null; peer.dc.onerror = null; peer.dc.onmessage = null; peer.dc.onopen = null; try { peer.dc.close(); } catch {} }
    peer.pc.close(); this.post({ type: 'peerClose', peerId });
    const candidate = this.candidates.get(peerId);
    if (retry && candidate && this.requested) {
      const delay = Math.min(15000, 1000 * 2 ** Math.min(candidate.failures++, 4)) + Math.random() * 250; candidate.retryAt = Date.now() + delay;
      this.later(() => this.connectNext(this.generation), delay);
    }
    if (this.requested) { this.updateState(); this.connectNext(this.generation); }
  }
  workerMessage(message, g) {
    if (message.type === 'send') {
      const peer = this.peers.get(message.peerId), dc = peer?.dc; let ok = false;
      try {
        const bytes = utf8.encode(message.text).length;
        if (dc?.readyState === 'open' && bytes <= MAX_MESSAGE && dc.bufferedAmount + bytes <= BUFFER_HIGH) { dc.send(message.text); ok = true; }
      } catch {}
      this.post({ type: 'sent', sendId: message.sendId, ok, bufferedAmount: dc?.bufferedAmount || 0 });
    } else if (message.type === 'needHeaders') {
      if (message.reason === 'fallback' && !(this.fallback ?? this.config.allowGatewayFallback)) return;
      for (const digest of (message.digests || []).slice(0, 32)) {
        if (/^[a-f0-9]{64}$/.test(digest) && this.seedQueue.size < 64) this.seedQueue.set(`${message.sourceId}:${digest}`, { sourceId: message.sourceId, digest });
      }
    } else if (message.type === 'disconnect') this.closePeer(message.peerId);
    else if (message.type === 'stats') { this.stats = message.stats || message; this.emit('stats', this.snapshot()); }
    else if (message.type === 'event') {
      this.emit('event', message);
      if (message.fatal) this.stop(message.message || 'Relay verification failed', message.code === 'transfer_limit' ? 'OFF_LIMIT' : 'ERROR');
    } else if (message.type === 'stopped') this.stop(message.reason === 'limit' ? 'Participation limit reached. Turn Node ON for a new session.' : 'Relay Worker stopped', message.reason === 'limit' ? 'OFF_LIMIT' : 'ERROR');
    else if (message.type === 'evidence') { const pending = this.pendingInspect.get(message.requestId); if (pending) { this.pendingInspect.delete(message.requestId); pending.resolve(message); } }
  }
  async pumpSeeds(g) {
    if (!this.live(g)) return;
    if (!this.seedBusy && !['loading', 'benchmarking'].includes(this.aiLoad) && this.seedQueue.size) {
      this.seedBusy = true; const [key, item] = this.seedQueue.entries().next().value; this.seedQueue.delete(key);
      try {
        const packet = await this.request(`/headers/${item.digest}?sourceId=${encodeURIComponent(item.sourceId)}`, { max: MAX_MESSAGE }, g);
        if (this.live(g)) this.post({ type: 'seed', sourceId: item.sourceId, packet }, [packet]);
      } catch (error) { if (this.live(g)) { this.sourceErrors[item.sourceId] = error.message; this.post({ type: 'headerError', sourceId: item.sourceId, digest: item.digest }); } }
      finally { if (this.live(g)) this.seedBusy = false; }
    }
    this.later(() => this.pumpSeeds(g), this.aiLoad === 'generating' ? 1050 : 300, g);
  }
  heartbeat(g) {
    if (!this.live(g)) return;
    if (this.ws?.readyState === WebSocket.OPEN && Date.now() - (this.lastSignalPing ?? 0) >= 20000) {
      if (this.signal({ type: 'ping' })) this.lastSignalPing = Date.now();
    }
    for (const [peerId, peer] of this.peers) this.post({ type: 'buffered', peerId, bytes: peer.dc?.bufferedAmount || 0 });
    this.post({ type: 'tick' }); this.connectNext(g);
    this.later(() => this.heartbeat(g), 1000, g);
  }
  inspect() {
    if (!this.requested) return Promise.resolve({ cache: [], stats: this.snapshot() });
    if (this.pendingInspect.size >= 2) return Promise.reject(new Error('Diagnostic request limit'));
    const requestId = crypto.randomUUID();
    return new Promise((resolve, reject) => {
      this.pendingInspect.set(requestId, { resolve, reject }); this.post({ type: 'inspect', requestId });
      this.later(() => { if (this.pendingInspect.delete(requestId)) reject(new Error('Diagnostic timed out')); }, 3000);
    });
  }
}
