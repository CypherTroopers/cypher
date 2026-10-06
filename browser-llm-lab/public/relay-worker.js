import { LIMITS, TokenBucket, asBytes, byteLength, decodeBase64, encodeMessage, headerDigest,
  protocolError, sameNetwork, validId, validateMessage, validateNetwork, validatePacket, verifyManifest } from "./relay-protocol.js";

const keyOf = (sourceId, digest) => `${sourceId}:${digest}`;
const randomHex = bytes => [...crypto.getRandomValues(new Uint8Array(bytes))].map(v => v.toString(16).padStart(2, "0")).join("");
const BULK_RATES = { idle: [32768, 65536], generating: [8192, 16384], loading: [0, 0], benchmarking: [0, 0] };
const boundedReason = error => error?.code || "invalid";

// The controller owns connections and actual sends. This Worker owns all data
// requests, exact-byte verification, bounded RAM state and receipt accounting.
export class RelayEngine {
  constructor({ post = () => {}, now = () => Date.now() } = {}) {
    this.post = post; this.now = now; this.active = false; this.generation = null;
    this.chain = Promise.resolve(); this.processingBytes = 0; this.pendingInputs = 0; this.epoch = 0;
  }
  emit(message) { this.post({ ...message, generation: this.generation }); }
  event(name, detail = {}) {
    const value = { name, at: this.now(), ...detail };
    if (this.events) { this.events.push(value); if (this.events.length > 256) this.events.shift(); }
    this.emit({ type: "event", ...value });
  }
  stop(reason = "off") {
    if (!this.active) return;
    this.active = false; this.epoch++;
    this.peers.clear(); this.cache.clear(); this.manifests.clear(); this.requests.clear(); this.outgoing.clear();
    this.queue = []; this.pendingSends.clear(); this.seedRequests.clear(); this.queuedBytes = 0; this.cacheBytes = 0;
    this.emit({ type: "stopped", reason });
  }
  fatal(code, message) { this.event("error", { code, message, fatal: true }); this.stop(code === "transfer_limit" ? "limit" : "error"); }
  accept(input) {
    if (input.type === "stop") { this.stop(input.reason || "off"); return Promise.resolve(); }
    let reserved = 256;
    if (input.type === "message") reserved += (input.buffer?.byteLength || 0) + LIMITS.maxHeaderBytes;
    if (input.type === "manifest") reserved += typeof input.envelope === "string" ? input.envelope.length * 2 : input.envelope?.byteLength || 0;
    if (input.type === "seed") reserved += typeof input.packet === "string" ? input.packet.length * 2 : input.packet?.byteLength || 0;
    if (this.pendingInputs >= 128 || reserved > 65536 || (this.active && this.appBytes() + reserved > LIMITS.appBytes)) {
      if (this.active && input.peerId) this.disconnect(input.peerId, "budget");
      else if (this.active) this.fatal("memory_limit", "Relay input reservation limit reached.");
      return Promise.resolve();
    }
    this.pendingInputs++; this.processingBytes += reserved;
    const epoch = this.epoch;
    const work = this.chain.then(async () => {
      if (input.type !== "init" && (!this.active || epoch !== this.epoch)) return;
      try { await this.handle(input); }
      catch (error) {
        if (input.type === "init") { this.emit({ type: "event", name: "error", code: boundedReason(error), message: error.message, fatal: true }); this.emit({ type: "stopped", reason: "error" }); return; }
        if (!this.active && input.type !== "init") return;
        if (input.peerId && this.active) this.violation(input.peerId, boundedReason(error));
        else this.event("error", { code: boundedReason(error), message: error.message || "Relay operation rejected.", fatal: false });
      }
    }).finally(() => { this.pendingInputs--; this.processingBytes -= reserved; });
    this.chain = work.catch(() => {}); return work;
  }
  init({ config, identity, generation }) {
    if (this.active) this.stop("off");
    this.generation = generation;
    validateNetwork(config?.network);
    if (!Array.isArray(config.sources) || !config.sources.length || config.sources.length > 2 ||
      !config.sources.every(source => validId(source.sourceId) && validId(source.keyId) && source.jwk) ||
      new Set(config.sources.map(source => source.sourceId)).size !== config.sources.length ||
      !validId(identity?.peerId) || !validId(identity?.sessionId)) throw protocolError("configuration", "Pinned sources and session identity are required.");
    this.config = structuredClone(config); this.identity = { ...identity }; this.generation = generation; this.epoch++;
    this.active = true; this.aiLoad = "idle"; this.peers = new Map(); this.cache = new Map(); this.manifests = new Map();
    this.boots = new Map(); this.requests = new Map(); this.outgoing = new Map(); this.seedRequests = new Map();
    this.missing = new Map(); this.failures = new Map(); this.acknowledged = new Map(); this.seenRequests = new Map(); this.sentPayloads = new Map();
    this.pendingSends = new Map(); this.queue = []; this.queuedBytes = 0; this.cacheBytes = 0;
    this.receipts = []; this.events = []; this.lastStats = -Infinity; this.manifestAsked = new Map();
    this.stats = { receivedBytes: 0, sentBytes: 0, gatewayBytes: 0, signalingBytes: 0, totalBytes: 0,
      acknowledgedBytes: 0, acknowledgedCount: 0, duplicateCount: 0, retryBytes: 0 };
    const now = this.now();
    this.sendBucket = new TokenBucket(32768, 32768, now); this.receiveBucket = new TokenBucket(65536, 65536, now);
    this.receivePlan = new TokenBucket(65536, 65536, now);
    this.controlOut = new TokenBucket(1024, 4096, now); this.controlIn = new TokenBucket(1024, 4096, now);
    this.metadata = new TokenBucket(3072, 24576, now);
    for (const source of config.sources) this.requestManifest(source.sourceId);
    this.publishStats(true);
  }
  appBytes() {
    if (!this.active) return this.processingBytes;
    let retained = this.processingBytes + this.queuedBytes + this.receipts.length * 512 + this.events.length * 512;
    for (const entry of this.cache.values()) retained += entry.cost;
    for (const current of this.manifests.values()) retained += current.wireBytes * 3 + 4096;
    for (const pending of this.pendingSends.values()) retained += pending.bytes;
    return retained + (this.requests.size + this.outgoing.size + this.seedRequests.size + this.missing.size +
      this.failures.size + this.acknowledged.size + this.seenRequests.size + this.sentPayloads.size) * 512 + this.peers.size * 8192;
  }
  async handle(input) {
    switch (input.type) {
      case "init": this.init(input); return;
      case "manifest": await this.manifest(input); break;
      case "seed": await this.seed(input); break;
      case "headerError": this.seedRequests.delete(keyOf(input.sourceId, input.digest)); this.failures.set(keyOf(input.sourceId, input.digest), { at: this.now(), peerId: "gateway" }); break;
      case "peerOpen": this.peerOpen(input); break;
      case "peerClose": this.disconnect(input.peerId, "closed", false); break;
      case "peerPath": if (this.peers.has(input.peerId)) this.peers.get(input.peerId).path = ["direct", "TURN"].includes(input.path) ? input.path : "unknown"; break;
      case "message": await this.message(input); break;
      case "sent": this.sent(input); break;
      case "buffered": {
        const peer = this.peers.get(input.peerId);
        if (peer) { peer.buffered = Math.max(0, Number(input.bytes) || 0); if (peer.buffered <= 16384) peer.blocked = false; }
        break;
      }
      case "aiLoad": {
        if (!Object.hasOwn(BULK_RATES, input.state)) throw protocolError("configuration", "Unknown AI workload.");
        this.aiLoad = input.state; const [send, receive] = BULK_RATES[input.state], now = this.now();
        this.sendBucket.set(send, Math.max(send, 16384), now); this.receiveBucket.set(receive, Math.max(receive, 16384), now);
        this.receivePlan.set(receive, Math.max(receive, 16384), now); break;
      }
      case "account": {
        if (!Number.isSafeInteger(input.bytes) || input.bytes < 0 || !["in", "out"].includes(input.direction) || !["https", "signal"].includes(input.kind))
          throw protocolError("configuration", "Invalid controller traffic accounting.");
        if (input.kind === "https" && input.direction === "in") this.stats.gatewayBytes += input.bytes;
        if (input.kind === "signal") this.stats.signalingBytes += input.bytes;
        this.charge(input.bytes); break;
      }
      case "inspect": this.emit({ type: "evidence", requestId: input.requestId, cache: [...this.cache.values()].map(entry => ({
        sourceId: entry.sourceId, manifestId: entry.manifestId, packet: entry.packet, receivedFrom: entry.receivedFrom,
        receivedAt: entry.receivedAt, path: entry.path })), stats: this.snapshot(), events: [...this.events] }); return;
      case "tick": break;
      default: throw protocolError("configuration", "Unknown Worker command.");
    }
    if (this.active) this.tick();
  }
  charge(bytes) {
    this.stats.totalBytes += bytes;
    if (this.stats.totalBytes >= LIMITS.transferBytes) { this.fatal("transfer_limit", "The 100 MiB ON-session transfer budget is exhausted."); return false; }
    return true;
  }
  requestManifest(sourceId) {
    if (!this.config.sources.some(source => source.sourceId === sourceId) || this.now() - (this.manifestAsked.get(sourceId) ?? -Infinity) < 10000) return;
    this.manifestAsked.set(sourceId, this.now()); this.emit({ type: "needManifest", sourceId });
  }
  async manifest({ sourceId, envelope, https }) {
    if (https !== true) throw protocolError("untrusted_source", "Manifests must arrive through the pinned HTTPS controller.");
    const wire = asBytes(envelope, LIMITS.maxEnvelopeBytes);
    if (!this.metadata.take(wire.byteLength, this.now())) throw protocolError("metadata_limit", "Manifest metadata rate exceeded.");
    const epoch = this.epoch, previous = this.manifests.get(sourceId);
    const result = await verifyManifest(wire, this.config, previous, this.now());
    if (!this.active || epoch !== this.epoch) return;
    if (result.manifest.sourceId !== sourceId) throw protocolError("untrusted_source", "Manifest source routing mismatch.");
    const seen = this.boots.get(sourceId) || new Set();
    if (result.bootChanged && seen.has(result.manifest.sourceBootId)) throw protocolError("manifest_rollback", "An old source boot was replayed.");
    if (!seen.has(result.manifest.sourceBootId) && seen.size >= 64) throw protocolError("manifest_limit", "Source restart tracking budget exhausted; start a new ON session.");
    seen.add(result.manifest.sourceBootId); this.boots.set(sourceId, seen); this.manifests.set(sourceId, result);
    for (const [otherId, other] of this.manifests) {
      if (otherId === sourceId || other.manifest.expiresAt <= this.now()) continue;
      const conflict = result.manifest.entries.find(entry => other.manifest.entries.some(row => row.height === entry.height && row.digest !== entry.digest));
      if (conflict) this.event("conflict", { sourceId, otherSourceId: otherId, height: conflict.height, message: "Pinned sources report different header bytes; no canonical winner was selected." });
    }
    this.prune();
    this.event("manifest", { sourceId, manifestId: result.id, sequence: result.manifest.sequence,
      headHeight: result.manifest.headHeight, observedAt: result.manifest.observedAt, expiresAt: result.manifest.expiresAt, bootChanged: result.bootChanged });
    for (const peer of this.peers.values()) if (peer.hello) this.advertise(peer, sourceId);
  }
  current(sourceId, digest) {
    const state = this.manifests.get(sourceId);
    if (!state || state.manifest.expiresAt <= this.now()) return null;
    const entry = state.manifest.entries.find(entry => entry.digest === digest);
    return entry ? { state, entry } : null;
  }
  async verifyPacket(sourceId, input) {
    const packet = validatePacket(input), target = this.current(sourceId, packet.digest);
    if (!target || !sameNetwork(packet.network, this.config.network) || packet.height !== target.entry.height)
      throw protocolError("outside_window", "Header is outside the current pinned source window.");
    const raw = decodeBase64(packet.headerRLP);
    if (raw.length !== target.entry.rawBytes || await headerDigest(packet.network, packet.height, raw) !== packet.digest)
      throw protocolError("invalid_digest", "Complete header bytes do not match the signed observation.");
    return { packet, raw, target };
  }
  retain(sourceId, verified, receivedFrom, path) {
    const { packet, raw, target } = verified, key = keyOf(sourceId, packet.digest);
    if (this.cache.has(key)) return false;
    const cost = raw.length + byteLength(JSON.stringify(packet)) + 512;
    while (this.cache.size >= 32 || this.cacheBytes + raw.length > LIMITS.cacheBytes || this.appBytes() + cost > LIMITS.appBytes) {
      const oldest = [...this.cache.values()].sort((a, b) => a.receivedAt - b.receivedAt)[0];
      if (!oldest) throw protocolError("memory_limit", "No cache reservation is available.");
      this.evict(keyOf(oldest.sourceId, oldest.packet.digest));
    }
    this.cache.set(key, { sourceId, packet, raw, cost, manifestId: target.state.id, receivedFrom, path,
      receivedAt: this.now(), expiresAt: Math.min(this.now() + 60000, target.state.manifest.expiresAt) });
    this.cacheBytes += raw.length; this.missing.delete(key);
    this.event("received", { sourceId, manifestId: target.state.id, peerId: receivedFrom, sessionId: this.identity.sessionId,
      peerSessionId: this.peers.get(receivedFrom)?.sessionId || null, height: packet.height, digest: packet.digest, rawBytes: raw.length, path });
    for (const peer of this.peers.values()) if (peer.hello) this.advertise(peer, sourceId);
    return true;
  }
  async seed({ sourceId, packet }) {
    const parsed = validatePacket(packet), key = keyOf(sourceId, parsed.digest), requested = this.seedRequests.get(key);
    if (!requested) throw protocolError("unsolicited", "Unrequested gateway header discarded.");
    this.seedRequests.delete(key);
    const epoch = this.epoch, verified = await this.verifyPacket(sourceId, parsed);
    if (!this.active || epoch !== this.epoch || !this.current(sourceId, parsed.digest)) return;
    if (!this.receiveBucket.take(byteLength(packet), this.now())) throw protocolError("rate_limit", "Gateway header receive rate exceeded.");
    if (!this.retain(sourceId, verified, "gateway", requested.reason === "seed" ? "gateway seed" : "gateway fallback")) this.stats.duplicateCount++;
  }
  peerOpen({ peerId, sessionId, path, maxMessageSize }) {
    if (!validId(peerId) || !validId(sessionId) || peerId === this.identity.peerId || this.peers.has(peerId) || this.peers.size >= 3 ||
      !Number.isFinite(maxMessageSize) || maxMessageSize < LIMITS.maxDataBytes) {
      this.emit({ type: "disconnect", peerId, reason: "unsupported_peer" }); return;
    }
    const now = this.now();
    const peer = { id: peerId, sessionId, path: ["direct", "TURN"].includes(path) ? path : "unknown", maxMessageSize,
      hello: false, inventories: new Map(), buffered: 0, blocked: false, violations: 0, messageTimes: [],
      controlSentAt: [],
      lastSeen: now, lastPing: now, openedAt: now };
    this.peers.set(peerId, peer);
    this.enqueue(peer, { type: "HELLO", v: 1, network: this.config.network, peerId: this.identity.peerId, sessionId: this.identity.sessionId });
  }
  disconnect(peerId, reason, notify = true) {
    const peer = this.peers.get(peerId); if (!peer) return;
    this.peers.delete(peerId);
    for (const [id, request] of this.requests) if (request.peerId === peerId) this.failRequest(id);
    for (const [id, request] of this.outgoing) if (request.peerId === peerId) this.outgoing.delete(id);
    this.queue = this.queue.filter(row => { if (row.peerId !== peerId) return true; this.queuedBytes -= row.bytes; return false; });
    for (const [id, pending] of this.pendingSends) if (pending.peerId === peerId) this.pendingSends.delete(id);
    if (notify) this.emit({ type: "disconnect", peerId, reason });
  }
  violation(peerId, reason) {
    const peer = this.peers.get(peerId); if (!peer) return;
    peer.violations++;
    this.event("error", { peerId, code: reason, message: "Peer message rejected.", fatal: false });
    if (peer.violations >= 3 || ["wrong_network", "wrong_session", "oversize"].includes(reason)) this.disconnect(peerId, reason);
  }
  enqueue(peer, message, operation = null) {
    if (!this.active || !this.peers.has(peer.id)) return false;
    const text = encodeMessage(message), bytes = byteLength(text);
    if (bytes > peer.maxMessageSize || this.queue.length >= 64 || this.queuedBytes + bytes > 256 * 1024 || this.appBytes() + bytes > LIMITS.appBytes) return false;
    // Coalesce unsent inventory updates rather than retaining stale advertisements.
    if (message.type === "INV") {
      this.queue = this.queue.filter(row => {
        if (row.peerId !== peer.id || row.message.type !== "INV" || row.message.sourceId !== message.sourceId) return true;
        this.queuedBytes -= row.bytes; return false;
      });
    }
    this.queue.push({ peerId: peer.id, sessionId: peer.sessionId, message, text, bytes, operation, createdAt: this.now() });
    this.queuedBytes += bytes; return true;
  }
  advertise(peer, sourceId) {
    const state = this.manifests.get(sourceId); if (!state || state.manifest.expiresAt <= this.now()) return;
    const digests = [...this.cache.values()].filter(entry => entry.sourceId === sourceId && this.current(sourceId, entry.packet.digest)).map(entry => entry.packet.digest);
    this.enqueue(peer, { type: "INV", v: 1, sourceId, manifestId: state.id, digests });
  }
  async message({ peerId, buffer }) {
    const peer = this.peers.get(peerId); if (!peer) return;
    const wire = asBytes(buffer, LIMITS.maxDataBytes); this.stats.receivedBytes += wire.byteLength;
    if (!this.charge(wire.byteLength)) return;
    const message = validateMessage(wire), now = this.now();
    if (message.type === "DATA") {
      if (!this.receiveBucket.take(wire.byteLength, now)) throw protocolError("rate_limit", "Peer payload rate exceeded.");
    } else {
      peer.messageTimes = peer.messageTimes.filter(time => now - time < 1000);
      if (peer.messageTimes.length >= 10 || !this.controlIn.take(wire.byteLength, now)) throw protocolError("rate_limit", "Peer control rate exceeded.");
      peer.messageTimes.push(now);
    }
    if (message.type === "HELLO") {
      if (!sameNetwork(message.network, this.config.network)) throw protocolError("wrong_network", "Peer network mismatch.");
      if (message.peerId !== peer.id || message.sessionId !== peer.sessionId || peer.hello) throw protocolError("wrong_session", "Peer/session does not match signaling assignment.");
      peer.hello = true; peer.lastSeen = now;
      for (const source of this.config.sources) this.advertise(peer, source.sourceId);
      return;
    }
    if (!peer.hello) throw protocolError("wrong_session", "HELLO must precede relay traffic.");
    peer.lastSeen = now;
    switch (message.type) {
      case "INV": {
        if (!this.config.sources.some(source => source.sourceId === message.sourceId)) throw protocolError("untrusted_source", "Unknown inventory source.");
        peer.inventories.set(message.sourceId, new Set(message.digests));
        const state = this.manifests.get(message.sourceId);
        if (!state || state.id !== message.manifestId || message.digests.some(digest => !this.current(message.sourceId, digest))) this.requestManifest(message.sourceId);
        break;
      }
      case "WANT": this.want(peer, message); break;
      case "DATA": await this.data(peer, message); break;
      case "ACK": this.ack(peer, message); break;
      case "NACK": {
        const request = this.requests.get(message.requestId);
        if (request && request.peerId === peer.id && request.peerSessionId === peer.sessionId && request.digest === message.digest) this.failRequest(message.requestId);
        break;
      }
      case "PING": this.enqueue(peer, { type: "PONG", v: 1, nonce: message.nonce }); break;
      case "PONG": if (message.nonce !== peer.ping) this.violation(peer.id, "invalid_heartbeat"); break;
      case "LEAVE": this.disconnect(peer.id, "left"); break;
    }
  }
  nack(peer, requestId, digest, reason) { this.enqueue(peer, { type: "NACK", v: 1, requestId, digest, reason }); }
  want(peer, message) {
    const now = this.now(), requestKey = `${peer.id}:${peer.sessionId}:${message.requestId}`;
    if (this.seenRequests.has(requestKey) || this.outgoing.has(message.requestId)) { this.nack(peer, message.requestId, message.digest, "invalid"); return; }
    if (this.seenRequests.size >= 512) { this.nack(peer, message.requestId, message.digest, "budget"); return; }
    this.seenRequests.set(requestKey, now);
    const entry = this.cache.get(keyOf(message.sourceId, message.digest)), current = this.current(message.sourceId, message.digest);
    if (!entry || !current) { this.nack(peer, message.requestId, message.digest, "outside_window"); return; }
    const [rate] = BULK_RATES[this.aiLoad];
    const maxPeer = this.aiLoad === "generating" ? 1 : 2, maxAll = this.aiLoad === "generating" ? 2 : 4;
    const peerPending = [...this.outgoing.values()].filter(row => row.peerId === peer.id).length;
    if (!rate || this.outgoing.size >= maxAll || peerPending >= maxPeer) { this.nack(peer, message.requestId, message.digest, "busy"); return; }
    const frame = { type: "DATA", v: 1, requestId: message.requestId, sessionId: this.identity.sessionId,
      sourceId: message.sourceId, manifestId: current.state.id, packet: entry.packet };
    const frameBytes = byteLength(encodeMessage(frame));
    const localDeadline = now + Math.min(30000, Math.max(5000, 5000 + 2000 * (this.queuedBytes + frameBytes) / rate));
    const deadline = Math.min(message.deadline, localDeadline);
    if (deadline < now + 1000 || deadline > now + 30000) { this.nack(peer, message.requestId, message.digest, "expired"); return; }
    if (now + 2000 * (this.queuedBytes + frameBytes) / rate > deadline) { this.nack(peer, message.requestId, message.digest, "busy"); return; }
    const request = { requestId: message.requestId, peerId: peer.id, peerSessionId: peer.sessionId, sourceId: message.sourceId,
      digest: message.digest, rawBytes: entry.raw.length, height: entry.packet.height, manifestId: current.state.id, deadline, confirmed: false };
    this.outgoing.set(message.requestId, request);
    if (!this.enqueue(peer, frame, { kind: "data", requestId: message.requestId })) {
      this.outgoing.delete(message.requestId); this.nack(peer, message.requestId, message.digest, "busy");
    }
  }
  async data(peer, message) {
    const request = this.requests.get(message.requestId), packet = message.packet;
    if (!request || !request.confirmed || request.peerId !== peer.id || request.peerSessionId !== peer.sessionId ||
      message.sessionId !== peer.sessionId || request.sourceId !== message.sourceId || request.digest !== packet.digest || request.deadline <= this.now())
      throw protocolError("unsolicited", "DATA does not match a current, sent WANT.");
    const epoch = this.epoch;
    let verified;
    try { verified = await this.verifyPacket(message.sourceId, packet); }
    catch (error) { this.failRequest(message.requestId); this.nack(peer, message.requestId, packet.digest, "invalid"); throw error; }
    if (!this.active || epoch !== this.epoch || !this.peers.has(peer.id) || this.requests.get(message.requestId) !== request) return;
    if (request.deadline <= this.now() || !this.current(message.sourceId, packet.digest)) { this.failRequest(message.requestId); this.nack(peer, message.requestId, packet.digest, "expired"); return; }
    const accepted = this.retain(message.sourceId, verified, peer.id, peer.path);
    this.requests.delete(message.requestId); if (!accepted) this.stats.duplicateCount++;
    this.enqueue(peer, { type: "ACK", v: 1, requestId: message.requestId, fromPeerId: this.identity.peerId, fromSessionId: this.identity.sessionId,
      toPeerId: peer.id, toSessionId: peer.sessionId, digest: packet.digest, rawBytes: verified.raw.length, status: accepted ? "accepted" : "duplicate" });
  }
  ack(peer, message) {
    const request = this.outgoing.get(message.requestId);
    if (!request || !request.confirmed || request.peerId !== peer.id || request.peerSessionId !== peer.sessionId || request.deadline <= this.now() ||
      message.fromPeerId !== peer.id || message.fromSessionId !== peer.sessionId || message.toPeerId !== this.identity.peerId ||
      message.toSessionId !== this.identity.sessionId || message.digest !== request.digest || message.rawBytes !== request.rawBytes)
      throw protocolError("invalid_ack", "Receipt does not match an actual send to the current peer session.");
    this.outgoing.delete(message.requestId);
    const key = `${peer.id}:${peer.sessionId}:${request.sourceId}:${request.digest}`;
    if (message.status !== "accepted" || this.acknowledged.has(key)) { this.stats.duplicateCount++; return; }
    this.acknowledged.set(key, { sourceId: request.sourceId, digest: request.digest, at: this.now() });
    this.stats.acknowledgedBytes += request.rawBytes; this.stats.acknowledgedCount++;
    const receipt = { peerId: peer.id, sessionId: peer.sessionId, sourceId: request.sourceId, height: request.height,
      digest: request.digest, rawBytes: request.rawBytes, path: peer.path, at: this.now() };
    this.receipts.push(receipt); if (this.receipts.length > 256) this.receipts.shift();
    this.event("acknowledged", { ...receipt, fromSessionId: this.identity.sessionId, manifestId: request.manifestId });
  }
  failRequest(id) {
    const request = this.requests.get(id); if (!request) return;
    this.requests.delete(id); this.failures.set(keyOf(request.sourceId, request.digest), { at: this.now(), peerId: request.peerId });
  }
  sent({ sendId, ok, bufferedAmount }) {
    const pending = this.pendingSends.get(sendId); if (!pending) return;
    this.pendingSends.delete(sendId);
    const peer = this.peers.get(pending.peerId);
    if (!ok) { this.disconnect(pending.peerId, "send_failed"); return; }
    this.stats.sentBytes += pending.bytes; if (!this.charge(pending.bytes)) return;
    if (peer) { peer.buffered = Math.max(0, Number(bufferedAmount) || 0); if (peer.buffered >= 65536) peer.blocked = true; }
    const operation = pending.operation;
    if (operation?.kind === "want") { const request = this.requests.get(operation.requestId); if (request) request.confirmed = true; }
    if (operation?.kind === "data") {
      const request = this.outgoing.get(operation.requestId);
      if (request) {
        request.confirmed = true;
        const key = `${request.peerId}:${request.peerSessionId}:${request.sourceId}:${request.digest}`;
        if (this.sentPayloads.has(key)) this.stats.retryBytes += pending.bytes;
        this.sentPayloads.set(key, { sourceId: request.sourceId, digest: request.digest, at: this.now() });
      }
    }
  }
  evict(key) { const entry = this.cache.get(key); if (entry) { this.cache.delete(key); this.cacheBytes -= entry.raw.length; } }
  prune() {
    const now = this.now();
    for (const [key, entry] of this.cache) {
      const target = this.current(entry.sourceId, entry.packet.digest);
      if (!target || now >= entry.receivedAt + 60000) this.evict(key);
      else { entry.expiresAt = Math.min(entry.receivedAt + 60000, target.state.manifest.expiresAt); entry.manifestId = target.state.id; }
    }
    for (const [id, request] of this.requests) if (request.deadline <= now || !this.current(request.sourceId, request.digest)) this.failRequest(id);
    for (const [id, request] of this.outgoing) if (request.deadline <= now || !this.current(request.sourceId, request.digest)) this.outgoing.delete(id);
    for (const [key, request] of this.seedRequests) if (now - request.at > 10000 || !this.current(request.sourceId, request.digest)) this.seedRequests.delete(key);
    for (const [key, value] of this.acknowledged) if (!this.current(value.sourceId, value.digest)) this.acknowledged.delete(key);
    for (const [key, value] of this.sentPayloads) if (now - value.at > 60000 || !this.current(value.sourceId, value.digest)) this.sentPayloads.delete(key);
    for (const [key, time] of this.seenRequests) if (now - time > 60000) this.seenRequests.delete(key);
    for (const [key, row] of this.failures) if (now - row.at > 60000) this.failures.delete(key);
    for (const [key, time] of this.missing) if (now - time > 60000) this.missing.delete(key);
    for (const map of [this.failures, this.missing, this.acknowledged, this.sentPayloads]) while (map.size > 512) map.delete(map.keys().next().value);
  }
  plan() {
    const [rate, receive] = BULK_RATES[this.aiLoad]; if (!rate || !receive) return;
    const source = this.config.sources.map(row => this.manifests.get(row.sourceId)).find(state => state && state.manifest.expiresAt > this.now());
    if (!source) return;
    const sourceId = source.manifest.sourceId, maximum = this.aiLoad === "generating" ? 2 : 4, perPeer = this.aiLoad === "generating" ? 1 : 2;
    for (const entry of [...source.manifest.entries].reverse()) {
      if (this.requests.size + this.seedRequests.size >= maximum) break;
      const key = keyOf(sourceId, entry.digest);
      if (this.cache.has(key) || this.seedRequests.has(key) || [...this.requests.values()].some(row => row.sourceId === sourceId && row.digest === entry.digest)) continue;
      if (!this.missing.has(key)) this.missing.set(key, this.now());
      const failed = this.failures.get(key), candidates = [...this.peers.values()].filter(peer => peer.hello && peer.inventories.get(sourceId)?.has(entry.digest) &&
        [...this.requests.values()].filter(row => row.peerId === peer.id).length < perPeer);
      candidates.sort((a, b) => Number(a.id === failed?.peerId) - Number(b.id === failed?.peerId));
      const peer = candidates.find(peer => peer.id !== failed?.peerId || this.now() - failed.at >= 2000);
      const expectedBytes = Math.ceil(entry.rawBytes / 3) * 4 + 1100;
      if (peer) {
        if (!this.receivePlan.take(expectedBytes, this.now())) continue;
        const requestId = randomHex(16), deadline = this.now() + Math.ceil(Math.min(30000, 5000 + 2000 * (65536 + expectedBytes) / Math.max(rate, 8192)));
        const request = { peerId: peer.id, peerSessionId: peer.sessionId, sourceId, digest: entry.digest, deadline, confirmed: false };
        this.requests.set(requestId, request);
        if (!this.enqueue(peer, { type: "WANT", v: 1, requestId, digest: entry.digest, sourceId, deadline }, { kind: "want", requestId })) this.requests.delete(requestId);
      } else if (this.seedRequests.size < 2 && (this.config.role === "seed" ||
          (this.config.allowFallback !== false && this.now() - this.missing.get(key) >= 8000)) && (!failed || failed.peerId !== "gateway" || this.now() - failed.at >= 2000)) {
        if (!this.receivePlan.take(expectedBytes, this.now())) continue;
        const reason = this.config.role === "seed" ? "seed" : "fallback";
        this.seedRequests.set(key, { sourceId, digest: entry.digest, at: this.now(), reason });
        this.emit({ type: "needHeaders", sourceId, digests: [entry.digest], reason });
      }
    }
  }
  pump() {
    const now = this.now();
    this.queue.sort((a, b) => Number(a.message.type === "DATA") - Number(b.message.type === "DATA"));
    for (let index = 0; index < this.queue.length && this.active;) {
      const item = this.queue[index], peer = this.peers.get(item.peerId);
      const operation = item.operation, request = operation?.kind === "want" ? this.requests.get(operation.requestId) : operation?.kind === "data" ? this.outgoing.get(operation.requestId) : null;
      if (!peer || peer.sessionId !== item.sessionId || (operation && !request) || now - item.createdAt > 15000) {
        this.queue.splice(index, 1); this.queuedBytes -= item.bytes; continue;
      }
      if ([...this.pendingSends.values()].some(row => row.peerId === peer.id) || peer.blocked || peer.buffered + item.bytes > 65536) { index++; continue; }
      const bulk = item.message.type === "DATA";
      if (bulk && (!BULK_RATES[this.aiLoad][0] || !this.current(item.message.sourceId, item.message.packet.digest))) { index++; continue; }
      if (!bulk) {
        peer.controlSentAt = peer.controlSentAt.filter(time => now - time < 1000);
        if (peer.controlSentAt.length >= 10) { index++; continue; }
      }
      if (!(bulk ? this.sendBucket : this.controlOut).take(item.bytes, now)) { index++; continue; }
      const reserved = [...this.pendingSends.values()].reduce((sum, row) => sum + row.bytes, 0);
      if (this.stats.totalBytes + reserved + item.bytes >= LIMITS.transferBytes) { this.fatal("transfer_limit", "ON-session transfer budget reached."); return; }
      this.queue.splice(index, 1); this.queuedBytes -= item.bytes;
      if (!bulk) peer.controlSentAt.push(now);
      const sendId = randomHex(16); this.pendingSends.set(sendId, { ...item, at: now });
      this.emit({ type: "send", peerId: peer.id, text: item.text, sendId });
    }
  }
  tick() {
    if (!this.active) return;
    this.prune(); const now = this.now();
    for (const source of this.config.sources) if (now - (this.manifestAsked.get(source.sourceId) ?? -Infinity) >= 10000) this.requestManifest(source.sourceId);
    for (const peer of this.peers.values()) {
      if (now - peer.lastSeen >= 15000 || (!peer.hello && now - peer.openedAt >= 5000)) { this.disconnect(peer.id, "heartbeat_timeout"); continue; }
      if (peer.hello && now - peer.lastPing >= 5000) { peer.lastPing = now; peer.ping = randomHex(8); this.enqueue(peer, { type: "PING", v: 1, nonce: peer.ping }); }
    }
    for (const pending of this.pendingSends.values()) if (now - pending.at >= 5000) this.disconnect(pending.peerId, "send_confirmation_timeout");
    this.plan(); this.pump();
    if (this.appBytes() > LIMITS.appBytes) { this.fatal("memory_limit", "Relay application reservation exceeded 4 MiB."); return; }
    this.publishStats();
  }
  snapshot() {
    return { ...this.stats, connectedPeers: [...this.peers.values()].filter(peer => peer.hello).length,
      cacheEntries: this.cache.size, cacheBytes: this.cacheBytes, inflight: this.requests.size + this.outgoing.size + this.seedRequests.size,
      queuedBytes: this.queuedBytes + [...this.pendingSends.values()].reduce((sum, row) => sum + row.bytes, 0), appBytes: this.appBytes(), aiLoad: this.aiLoad,
      sources: [...this.manifests.values()].map(state => ({ sourceId: state.manifest.sourceId, headHeight: state.manifest.headHeight,
        observedAt: state.manifest.observedAt, expiresAt: state.manifest.expiresAt, manifestId: state.id, fresh: state.manifest.expiresAt > this.now() })),
      receipts: [...this.receipts], verification: "gateway_authenticated_header" };
  }
  publishStats(force = false) { if (force || this.now() - this.lastStats >= 1000) { this.lastStats = this.now(); this.emit({ type: "stats", stats: this.snapshot() }); } }
}

if (typeof WorkerGlobalScope !== "undefined" && globalThis instanceof WorkerGlobalScope) {
  const engine = new RelayEngine({ post: message => postMessage(message) });
  onmessage = event => { void engine.accept(event.data); };
  setInterval(() => { if (engine.active) void engine.accept({ type: "tick" }); }, 250);
}
