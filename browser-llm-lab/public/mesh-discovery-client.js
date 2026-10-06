import { Bucket } from './relay-controller.js?v=mesh-v1';
import { strictJSON, sameNetwork } from './relay-protocol.js?v=relay-v1';
import { EndpointCache, safeGatewayOrigin, signBrowserRecord, verifyBrowserRecord, signSignal, verifySignal, signChallenge } from './mesh-discovery.js';

const utf8 = new TextEncoder(), BASE = '/relay/v1/mesh';
const PATHS = new Set(['/config', '/discovery', '/sessions', '/renew', '/status']);
const bytes = value => utf8.encode(value).length;
function acquireHTTP(controller, signal) {
  const budget = controller.discoveryHTTP ||= { active: 0, waiting: [] };
  if (signal.aborted) return Promise.reject(new Error('Discovery stopped'));
  if (budget.active < 2) { budget.active++; return Promise.resolve(() => releaseHTTP(budget)); }
  if (budget.waiting.length >= 32) return Promise.reject(new Error('Discovery request queue limit'));
  return new Promise((resolve, reject) => {
    const row = { grant: () => { signal.removeEventListener('abort', cancel); budget.active++; resolve(() => releaseHTTP(budget)); } };
    const cancel = () => { const at = budget.waiting.indexOf(row); if (at >= 0) budget.waiting.splice(at, 1); reject(new Error('Discovery stopped')); };
    signal.addEventListener('abort', cancel, { once: true }); budget.waiting.push(row);
  });
}
function releaseHTTP(budget) { budget.active--; budget.waiting.shift()?.grant(); }

/** Fixed-path HTTPS only. No primary token is ever forwarded to another origin. */
export async function discoveryJSON(controller, origin, path, { method = 'GET', body, token, max = 262144 } = {}, generation = controller.generation) {
  safeGatewayOrigin(origin);
  if (!PATHS.has(path) || !controller.live(generation)) throw new Error('Discovery request stopped or invalid');
  const abort = new AbortController(), parent = controller.abort?.signal;
  const stop = () => abort.abort(); parent?.addEventListener('abort', stop, { once: true });
  if (parent?.aborted) abort.abort();
  const timeout = setTimeout(stop, 5000);
  let release;
  try {
    release = await acquireHTTP(controller, abort.signal);
    if (!controller.live(generation)) throw new Error('Discovery stopped');
    const headers = { Accept: 'application/json' };
    if (token) headers.Authorization = `Bearer ${token}`;
    if (body) { headers['Content-Type'] = 'application/json'; controller.account(bytes(body), 'out', 'https'); }
    const response = await fetch(origin + BASE + path, { method, body, headers, signal: abort.signal, credentials: 'omit', redirect: 'error', cache: 'no-store', mode: 'cors' });
    const admission = method === 'POST' && path === '/sessions';
    if (!controller.live(generation) && !admission) { await response.body?.cancel(); throw new Error('Discovery stopped'); }
    if (Number(response.headers.get('content-length')) > max) { await response.body?.cancel(); throw new Error('Discovery response exceeds limit'); }
    const reader = response.body?.getReader(); let length = 0; const chunks = [];
    if (reader) {
      try {
        for (;;) {
          const part = await reader.read(); if (part.done) break;
          controller.account(part.value.byteLength, 'in', 'https'); length += part.value.byteLength;
          if (!controller.live(generation) && !admission || length > max) throw new Error('Discovery response stopped or exceeds limit');
          chunks.push(part.value);
        }
      } catch (error) { await reader.cancel().catch(() => {}); throw error; }
    }
    if (!response.ok) throw Object.assign(new Error(`Discovery gateway ${response.status}`), { status: response.status });
    if (response.status === 204) return null;
    const raw = new Uint8Array(length); let at = 0;
    for (const part of chunks) { raw.set(part, at); at += part.length; }
    const result = strictJSON(raw, max, { allowDecimals: true });
    if (!controller.live(generation)) {
      if (admission && typeof result?.token === 'string') controller.releaseSession({ ...result, remoteOrigin: origin });
      throw new Error('Discovery stopped');
    }
    return result;
  } finally { release?.(); clearTimeout(timeout); parent?.removeEventListener('abort', stop); }
}

/** RAM-only discovery and signed signaling. Real relay bytes remain on WebRTC. */
export class MeshDiscoveryClient {
  constructor(controller, identity, generation) {
    this.controller = controller; this.identity = identity; this.generation = generation;
    this.network = controller.config.network; this.cache = new EndpointCache(this.network);
    this.origin = safeGatewayOrigin(location.origin); this.origins = new Set([this.origin]);
    const config = controller.config.discovery;
    if (config?.version !== 1 || config.directoryPath !== BASE + '/discovery' || config.rendezvousPath !== BASE + '/rendezvous' ||
      !Array.isArray(config.bootstrapOrigins) || config.bootstrapOrigins.length > 8) throw new Error('Invalid discovery configuration');
    for (const origin of config.bootstrapOrigins) this.addOrigin(origin);
    this.sockets = new Map(); this.records = new Map(); this.receivedSeq = new Map(); this.sentSeq = new Map();
    this.queue = []; this.queueBytes = 0; this.timer = null; this.refreshing = false; this.stopped = false; this.lastRefresh = 0;
    this.signalBucket = new Bucket(4096, 32768); this.nextSend = 0; this.failures = new Map();
    const manager = this;
    this.transport = { get readyState() { return !manager.stopped && [...manager.sockets.values()].some(s => s.ready && s.ws.readyState === 1) ? 1 : 0; },
      get bufferedAmount() { return [...manager.sockets.values()].reduce((n, s) => n + (s.ws.bufferedAmount || 0), 0); }, close() { manager.stop(); } };
  }
  live() { return !this.stopped && this.controller.live(this.generation) && this.controller.discovery === this; }
  addOrigin(origin) { safeGatewayOrigin(origin); if (this.origins.size < 8 || this.origins.has(origin)) this.origins.add(origin); }
  endpoints() { return this.cache.values(); }
  start() { if (!this.live()) return; this.ensureSockets(); this.refresh(); this.tick(); }
  browserRecord() {
    const now = Date.now(), session = this.controller.session;
    return signBrowserRecord({ network: this.network, sessionId: session.id, browserId: session.browserId, nodeId: session.nodeId,
      sourceId: session.sourceId, rendezvous: [...this.sockets.keys()], issuedAt: now, expiresAt: Math.min(now + 120000, session.expiresAt) }, this.identity);
  }
  ensureSockets() {
    if (!this.live()) return;
    for (const origin of this.origins) {
      if (this.sockets.size >= 4) break;
      if (this.sockets.has(origin) || (this.failures.get(origin)?.at || 0) > Date.now()) continue;
      this.openSocket(origin);
    }
  }
  openSocket(origin) {
    let ws; try { ws = new WebSocket(origin.replace(/^https:/u, 'wss:') + BASE + '/rendezvous'); } catch { this.failed(origin); return; }
    const entry = { origin, ws, ready: false, expiresAt: 0, lastRenew: 0, peers: new Set() }; this.sockets.set(origin, entry);
    const current = () => this.live() && this.sockets.get(origin) === entry;
    ws.onmessage = event => {
      if (!current()) return;
      try {
        if (typeof event.data !== 'string' || bytes(event.data) > 32768) throw new Error('Rendezvous message limit');
        this.controller.account(bytes(event.data), 'in', 'signal'); if (!current()) return;
        const message = strictJSON(event.data, 32768, { allowDecimals: true });
        if (message.type === 'challenge') {
          if (entry.challenged || message.origin !== origin) throw new Error('Unexpected rendezvous challenge');
          entry.challenged = true;
          const record = this.browserRecord(), challenge = { nonce: message.nonce, origin, expiresAt: message.expiresAt };
          this.enqueue(entry, { type: 'auth', record, signatureHex: signChallenge(challenge, record, this.identity) });
        } else if (message.type === 'ready' || message.type === 'peers') {
          if (!entry.challenged || !Array.isArray(message.peers) || message.peers.length > 64) throw new Error('Invalid rendezvous peer list');
          if (message.type === 'ready') {
            if (!Number.isSafeInteger(message.expiresAt) || message.expiresAt <= Date.now()) throw new Error('Expired rendezvous lease');
            entry.ready = true; entry.expiresAt = message.expiresAt; entry.lastRenew = Date.now(); this.failures.delete(origin);
          }
          entry.peers.clear();
          for (const envelope of message.peers) {
            const record = this.acceptPeer(envelope, true); if (record) {
              entry.peers.add(record.peerId);
              if (origin === this.origin) record.geo = this.locationHint(message.peerLocations?.[record.peerId]);
            }
          }
          this.adopt(); this.controller.updateState();
        } else if (message.type === 'renewed') {
          if (!entry.ready || !Number.isSafeInteger(message.expiresAt) || message.expiresAt <= Date.now()) throw new Error('Invalid rendezvous renewal');
          entry.expiresAt = message.expiresAt;
        } else if (message.type === 'peer-left') {
          entry.peers.delete(message.peerId);
          // A directory lease or another rendezvous can still advertise this peer.
          if (![...this.sockets.values()].some(s => s.peers.has(message.peerId))) this.removePeer(message.peerId);
          this.adopt();
        } else if (message.type === 'signal') {
          try { this.receiveSignal(message, entry); } catch { this.controller.emit('event', { name: 'discovery-signal-rejected' }); }
        }
        else if (message.type !== 'pong' && message.type !== 'error') throw new Error('Unknown rendezvous message');
      } catch { this.closeSocket(entry, 'Invalid rendezvous response'); }
    };
    ws.onerror = () => {};
    ws.onclose = () => { if (current()) this.closeSocket(entry, 'Rendezvous disconnected'); };
    this.controller.later(() => { if (current() && !entry.ready) this.closeSocket(entry, 'Rendezvous authentication timed out'); }, 10000, this.generation);
  }
  failed(origin) { const count = Math.min(8, (this.failures.get(origin)?.count || 0) + 1); this.failures.set(origin, { count, at: Date.now() + Math.min(60000, 1000 * 2 ** count) }); }
  closeSocket(entry, reason) {
    if (this.sockets.get(entry.origin) !== entry) return;
    this.sockets.delete(entry.origin); entry.ready = false; entry.ws.onmessage = null; entry.ws.onclose = null;
    try { entry.ws.close(); } catch {}
    this.queue = this.queue.filter(row => row.entry !== entry); this.queueBytes = this.queue.reduce((n, row) => n + row.bytes, 0);
    this.failed(entry.origin);
    if (this.live()) { this.controller.emit('event', { name: 'rendezvous-disconnected', reason }); this.controller.updateState(); }
  }
  locationHint(geo) {
    if (!geo || typeof geo.countryCode !== 'string' || !/^[A-Z]{2}$/u.test(geo.countryCode) || typeof geo.label !== 'string' || geo.label.length > 100 ||
      !Number.isFinite(geo.lat) || !Number.isFinite(geo.lon) || Math.abs(geo.lat) > 90 || Math.abs(geo.lon) > 180) return null;
    return { countryCode: geo.countryCode, label: geo.label, lat: geo.lat, lon: geo.lon, accuracy: 'country', source: 'gateway-country-estimate' };
  }
  acceptPeer(envelope, introduced = false) {
    try {
      const record = verifyBrowserRecord(envelope, this.network);
      if (record.peerId === this.identity.peerId) return null;
      const old = this.records.get(record.peerId);
      const sameGeneration = old?.sessionId === record.sessionId && ['browserId', 'nodeId', 'sourceId', 'publicKey'].every(key => record[key] === old[key]);
      if (old?.sessionId === record.sessionId && !sameGeneration) return null;
      // Independent rendezvous sockets may hold adjacent, still-valid renewals
      // of the same browser generation. Accept their introductions/signals using
      // the existing high-water record, without rolling back its lease or data.
      if (old && record.issuedAt < old.issuedAt) return sameGeneration ? old : null;
      if (old && record.issuedAt === old.issuedAt && record.envelope.payloadBase64 !== old.envelope.payloadBase64) return null;
      if (old && record.envelope.payloadBase64 === old.envelope.payloadBase64) return old;
      if (!old && this.records.size >= 64) {
        if (!introduced) return null;
        const replace = [...this.records.keys()].find(id => !this.controller.peers.has(id) && !this.receivedSeq.has(id) && !this.sentSeq.has(id) && ![...this.sockets.values()].some(s => s.peers.has(id)));
        if (!replace) return null;
        this.records.delete(replace); this.controller.candidates.delete(replace);
      }
      if (old && old.sessionId !== record.sessionId) this.removePeer(record.peerId);
      if (old?.geo) record.geo = old.geo;
      this.records.set(record.peerId, record);
      for (const origin of record.rendezvous) this.addOrigin(origin);
      return record;
    } catch { return null; }
  }
  removePeer(id) {
    // Keep the signed lease and sequence high-water mark until expiry. A
    // duplicated directory response must not resurrect a departed generation.
    const record = this.records.get(id); if (record) record.departed = true;
    this.controller.candidates.delete(id); this.controller.closePeer(id, false);
  }
  adopt(preferred) {
    if (!this.live()) return;
    const now = Date.now();
    for (const [id, record] of this.records) if (record.expiresAt <= now) { this.removePeer(id); this.records.delete(id); this.receivedSeq.delete(id); this.sentSeq.delete(id); }
    const introduced = new Set([...this.sockets.values()].filter(s => s.ready).flatMap(s => [...s.peers]));
    const rows = [...this.records.values()].filter(r => !r.departed && introduced.has(r.peerId) && r.rendezvous.some(origin => this.sockets.get(origin)?.ready));
    rows.sort((a, b) => Number(b.peerId === preferred) - Number(a.peerId === preferred) || Number(this.controller.peers.has(b.peerId)) - Number(this.controller.peers.has(a.peerId)) || a.peerId.localeCompare(b.peerId));
    this.controller.adoptPeers(rows.slice(0, this.controller.peerLimit()).map(r => ({ peerId: r.peerId, id: r.sessionId, browserId: r.browserId,
      nodeId: r.nodeId, sourceId: r.sourceId, geo: r.geo || null, initiator: this.identity.peerId < r.peerId })), this.generation);
  }
  async refresh() {
    if (!this.live() || this.refreshing) return;
    this.refreshing = true; this.lastRefresh = Date.now();
    try {
      const origins = [...this.origins]; let index = 0;
      const fetchNext = async () => {
        while (this.live() && index < origins.length) {
          const origin = origins[index++];
          try {
            const data = await discoveryJSON(this.controller, origin, '/discovery', {}, this.generation);
            if (!this.live()) return;
            if (data.version !== 1 || !sameNetwork(data.network, this.network) || !Array.isArray(data.endpoints) || data.endpoints.length > 64 || !Array.isArray(data.peers) || data.peers.length > 64) throw new Error('Invalid discovery directory');
            for (const envelope of data.endpoints) { try { const record = this.cache.add(envelope); this.addOrigin(record.origin); } catch {} }
            for (const envelope of data.peers) this.acceptPeer(envelope);
          } catch { /* An unavailable introduction point does not stop working RTC paths. */ }
        }
      };
      await Promise.all([fetchNext(), fetchNext()]);
      if (this.live()) { this.ensureSockets(); this.adopt(); this.controller.scheduleAttachments(this.generation); }
    } finally { this.refreshing = false; }
  }
  send(message) {
    if (!this.live()) return false;
    if (message.type === 'ping') return true; // WebSocket Ping/Pong is owned by the rendezvous server.
    if (!['offer', 'answer', 'ice'].includes(message.type)) return false;
    const record = this.records.get(message.to), peer = this.controller.peers.get(message.to);
    if (!record || record.departed || record.expiresAt <= Date.now() || !peer || peer.sessionId !== record.sessionId) return false;
    const entry = record.rendezvous.map(o => this.sockets.get(o)).find(s => s?.ready && s.ws.readyState === 1); if (!entry) return false;
    const seq = (this.sentSeq.get(message.to) || 0) + 1; this.sentSeq.set(message.to, seq);
    let value = message.type === 'ice' ? message.candidate : message.sdp;
    if (message.type === 'ice' && value) value = { candidate: value.candidate, sdpMid: value.sdpMid ?? null, sdpMLineIndex: value.sdpMLineIndex ?? null, usernameFragment: value.usernameFragment ?? null };
    const now = Date.now();
    const envelope = signSignal({ version: 1, network: this.network, from: this.identity.peerId, to: record.peerId, fromSessionId: this.controller.session.id,
      toSessionId: record.sessionId, seq, type: message.type, value, issuedAt: now, expiresAt: now + 30000 }, this.identity);
    return this.enqueue(entry, { type: 'signal', message: envelope }, { peerId: record.peerId, peer, expiresAt: now + 30000 });
  }
  receiveSignal(message, entry) {
    const record = this.acceptPeer(message.record, true); if (!record || record.departed) return;
    const signal = verifySignal(message.message, record, this.network);
    const prior = this.receivedSeq.get(record.peerId);
    if (signal.to !== this.identity.peerId || signal.toSessionId !== this.controller.session.id || prior?.sessionId === record.sessionId && signal.seq <= prior.seq) throw new Error('Stale or replayed browser signal');
    this.receivedSeq.set(record.peerId, { sessionId: record.sessionId, seq: signal.seq });
    if (entry?.ready && entry.peers.size < 64) entry.peers.add(record.peerId);
    this.adopt(record.peerId);
    const converted = { type: signal.type, from: record.peerId, ...(signal.type === 'ice' ? { candidate: signal.value } : { sdp: signal.value }) };
    const operation = this.controller.receiveSignal(converted, this.generation), peer = this.controller.peers.get(record.peerId);
    operation.catch(() => { if (this.live() && peer && this.controller.peers.get(record.peerId) === peer) this.controller.closePeer(record.peerId); });
  }
  enqueue(entry, message, extra = {}) {
    if (!this.live()) return false;
    const text = JSON.stringify(message), length = bytes(text);
    if (length > 32768 || this.queue.length >= 64 || this.queueBytes + length > 65536) { this.controller.stop('Discovery signaling queue limit', 'OFF_LIMIT'); return false; }
    this.queue.push({ entry, text, bytes: length, ...extra }); this.queueBytes += length; this.pump(); return true;
  }
  pump() {
    if (!this.live() || this.timer) return;
    while (this.queue.length) {
      const row = this.queue[0];
      if (this.sockets.get(row.entry.origin) !== row.entry || row.entry.ws.readyState !== 1 || row.expiresAt <= Date.now() || row.peer && this.controller.peers.get(row.peerId) !== row.peer) {
        this.queue.shift(); this.queueBytes -= row.bytes; continue;
      }
      if (Date.now() < this.nextSend || this.transport.bufferedAmount + row.bytes > 65536 || !this.signalBucket.take(row.bytes)) break;
      this.queue.shift(); this.queueBytes -= row.bytes;
      try { row.entry.ws.send(row.text); } catch { this.closeSocket(row.entry, 'Rendezvous send failed'); continue; }
      this.controller.account(row.bytes, 'out', 'signal'); this.nextSend = Date.now() + 150; break;
    }
    if (this.queue.length && this.live()) {
      const marker = {}; this.timer = marker;
      this.controller.later(() => { if (this.timer !== marker) return; this.timer = null; this.pump(); }, 150, this.generation);
    }
  }
  tick() {
    if (!this.live()) return;
    const now = Date.now(); this.cache.prune();
    for (const a of this.controller.attachments.values()) if (a.session.remoteOrigin) {
      const endpoint = this.cache.get(a.session.nodeId);
      if (!endpoint || endpoint.origin !== a.session.remoteOrigin || endpoint.sourceId !== a.session.sourceId || endpoint.payload.bootId !== a.session.endpointBootId)
        this.controller.retireAttachment(a.attachmentId, 'Signed Common endpoint expired or changed', this.generation);
    }
    for (const entry of this.sockets.values()) {
      if (!entry.ready) continue;
      if (entry.expiresAt <= now) { this.closeSocket(entry, 'Rendezvous lease expired'); continue; }
      if (now - entry.lastRenew >= 30000) { entry.lastRenew = now; this.enqueue(entry, { type: 'renew', record: this.browserRecord() }); }
    }
    this.ensureSockets(); this.adopt();
    if (now - this.lastRefresh >= 30000) this.refresh();
    this.controller.later(() => this.tick(), 1000, this.generation);
  }
  stop() {
    if (this.stopped) return; this.stopped = true;
    for (const entry of this.sockets.values()) { entry.ws.onclose = null; entry.ws.onmessage = null; try { entry.ws.close(); } catch {} }
    this.sockets.clear(); this.records.clear(); this.receivedSeq.clear(); this.sentSeq.clear(); this.queue = []; this.queueBytes = 0; this.timer = null;
    this.cache.records.clear(); this.identity.privateKey.fill(0);
  }
}
