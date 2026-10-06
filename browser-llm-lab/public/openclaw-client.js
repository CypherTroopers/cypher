// OpenClaw Gateway protocol 4, verified against the official Gateway client guide.
// https://docs.openclaw.ai/gateway/clients
// This client connects to an installed Gateway; it does not execute tools in the page.
export const OPENCLAW_PROTOCOL = 4;
const CLIENT_ID = "gateway-client";
const CLIENT_MODE = "ui";
const SCOPES = ["operator.read", "operator.write"];
const encoder = new TextEncoder();

function failure(code, message, details) {
  return Object.assign(new Error(message), { code, ...(details ? { details } : {}) });
}

export function normalizeGatewayURL(value) {
  let url;
  try { url = new URL(String(value).trim()); }
  catch { throw failure("URL", "Enter a valid Gateway WebSocket URL."); }
  if (!["ws:", "wss:"].includes(url.protocol) || url.username || url.password || url.search || url.hash)
    throw failure("URL", "Use a ws:// or wss:// Gateway URL without credentials, a query, or a fragment.");
  if (url.protocol === "ws:" && !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))
    throw failure("TRANSPORT", "Use wss:// for a Gateway on another device. ws:// is supported only for localhost on this device.");
  return url.href;
}

export function extractTextMessage(message) {
  if (typeof message === "string") return message;
  if (!message || typeof message !== "object") return "";
  if (typeof message.content === "string") return message.content;
  if (!Array.isArray(message.content)) return "";
  return message.content.filter(block => block?.type === "text" && typeof block.text === "string")
    .map(block => block.text).join("\n");
}

function base64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

// The v3 proof binds the nonce and timestamp supplied by this particular Gateway.
// Its field order and ASCII metadata normalization are part of the wire contract.
export function deviceAuthPayload({ deviceId, scopes, signedAt, token, nonce }) {
  return ["v3", deviceId, CLIENT_ID, CLIENT_MODE, "operator", scopes.join(","),
    String(signedAt), token || "", nonce, "web", "browser"].join("|");
}

function storageTransaction(db, mode, operation) {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction("identity", mode);
    let result;
    transaction.oncomplete = () => resolve(result);
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error || new Error("Identity storage aborted"));
    operation(transaction.objectStore("identity"), value => { result = value; });
  });
}

async function deviceIdentity(crypto, indexedDB) {
  if (!crypto?.subtle || !indexedDB)
    throw failure("IDENTITY", "Device authentication requires HTTPS or localhost and browser IndexedDB storage.");
  const db = await new Promise((resolve, reject) => {
    const request = indexedDB.open("browser-llm-openclaw-identity", 1);
    request.onupgradeneeded = () => request.result.createObjectStore("identity");
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(failure("IDENTITY", "The browser could not store its device identity."));
    request.onblocked = () => reject(failure("IDENTITY", "Another tab is blocking device identity storage. Close that tab and reconnect."));
  });
  try {
    let record = await storageTransaction(db, "readonly", (store, done) => {
      store.get("operator").onsuccess = event => done(event.target.result);
    });
    if (!record) {
      let keys;
      try { keys = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]); }
      catch { throw failure("IDENTITY", "This browser does not support Ed25519 device authentication. Update your browser and reconnect."); }
      const raw = await crypto.subtle.exportKey("raw", keys.publicKey);
      const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", raw));
      const candidate = {
        deviceId: [...digest].map(byte => byte.toString(16).padStart(2, "0")).join(""),
        publicKey: base64url(raw), privateKey: keys.privateKey,
      };
      // Resolve simultaneous first connections from different tabs atomically.
      record = await storageTransaction(db, "readwrite", (store, done) => {
        store.get("operator").onsuccess = event => {
          const existing = event.target.result;
          if (!existing) store.put(candidate, "operator");
          done(existing || candidate);
        };
      });
    }
    if (!record?.privateKey || record.privateKey.extractable !== false ||
        !/^[a-f0-9]{64}$/.test(record.deviceId) || typeof record.publicKey !== "string")
      throw failure("IDENTITY", "The stored browser device identity could not be read.");
    return { deviceId: record.deviceId, publicKey: record.publicKey,
      sign: async payload => base64url(await crypto.subtle.sign("Ed25519", record.privateKey, encoder.encode(payload))) };
  } finally { db.close(); }
}

function tabStorage() {
  try { return globalThis.sessionStorage; } catch { return null; }
}

export class OpenClawClient {
  constructor({ onEvent = () => {}, onState = () => {}, WebSocketImpl = globalThis.WebSocket,
    crypto = globalThis.crypto, indexedDB = globalThis.indexedDB, storage = tabStorage(),
    identityProvider, requestTimeoutMs = 30000, connectTimeoutMs = 20000 } = {}) {
    Object.assign(this, { onEvent, onState, WebSocketImpl, crypto, storage, requestTimeoutMs, connectTimeoutMs });
    this.identityProvider = identityProvider || (() => deviceIdentity(crypto, indexedDB));
    this.connected = false;
    this.hello = null;
    this.generation = 0;
    this.pending = new Map();
    this.streams = new Map();
    this.secrets = new Set();
  }

  emitState(state, error) {
    this.state = state;
    try { this.onState({ state, ...(error ? { error } : {}), ...(this.hello ? { hello: this.hello } : {}) }); }
    catch { /* A view callback must not corrupt the transport state. */ }
  }

  redact(value) {
    if (typeof value === "string") {
      for (const secret of this.secrets) if (secret) value = value.split(secret).join("[redacted]");
      return value;
    }
    if (Array.isArray(value)) return value.map(item => this.redact(item));
    if (value && typeof value === "object")
      return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, this.redact(item)]));
    return value;
  }

  connect({ url, token = "", password = "" }) {
    this.close(failure("CANCELLED", "A new connection attempt replaced this connection."), false);
    const generation = this.generation;
    this.emitState("connecting");
    let endpoint;
    try { endpoint = normalizeGatewayURL(url); }
    catch (error) { this.emitState("error", error); return Promise.reject(error); }
    token = token.trim();
    this.secrets = new Set([token, password].filter(Boolean));
    this.url = endpoint;
    this.lastSequence = null;
    this.challengeReceived = false;
    const promise = new Promise((resolve, reject) => { this.connectWait = { resolve, reject }; });
    this.connectTimer = setTimeout(() => {
      this.fail(failure("TIMEOUT", "Gateway connection timed out. Check that it is running and verify the URL and allowed Origin."));
    }, this.connectTimeoutMs);
    Promise.resolve().then(() => this.identityProvider()).then(identity => {
      if (generation !== this.generation) return;
      this.identity = identity;
      this.tokenKey = `browser-llm:openclaw:v1:${encodeURIComponent(endpoint)}:${identity.deviceId}`;
      let cached;
      try { cached = JSON.parse(this.storage?.getItem(this.tokenKey)); } catch { /* no stored credential */ }
      const stored = !token && !password && typeof cached?.token === "string" &&
        Array.isArray(cached.scopes) && cached.scopes.every(scope => typeof scope === "string") ? cached : null;
      this.auth = token ? { token } : password ? { password } : stored ? { deviceToken: stored.token } : null;
      if (!this.auth) throw failure("AUTH_REQUIRED", "The first connection requires the Gateway token.");
      this.signatureToken = token || stored?.token || "";
      if (stored) this.secrets.add(stored.token);
      this.scopes = stored ? SCOPES.filter(scope => stored.scopes.includes(scope)) : [...SCOPES];
      const socket = new this.WebSocketImpl(endpoint);
      this.socket = socket;
      const current = () => generation === this.generation && socket === this.socket;
      socket.onmessage = event => {
        if (!current()) return;
        this.receive(event.data, generation).catch(error => { if (current()) this.fail(error); });
      };
      socket.onerror = () => {
        if (current()) this.fail(failure("CONNECTION", "Could not connect to the Gateway. Check that it is running and verify the URL and allowed Origin."));
      };
      socket.onclose = event => {
        if (current()) this.fail(failure("DISCONNECTED", `The Gateway connection closed (${event.code}).`,
          { closeCode: event.code, reason: this.redact(event.reason || "") }));
      };
    }).catch(error => { if (generation === this.generation) this.fail(error); });
    return promise;
  }

  async receive(raw, generation) {
    if (typeof raw !== "string" || raw.length > 16 * 1024 * 1024)
      throw failure("PROTOCOL", "The Gateway sent an unreadable or oversized frame.");
    let frame;
    try { frame = JSON.parse(raw); }
    catch { throw failure("PROTOCOL", "The Gateway sent invalid JSON."); }
    if (!frame || typeof frame !== "object") throw failure("PROTOCOL", "The Gateway sent an invalid frame.");
    if (frame.type === "res") {
      const task = this.pending.get(frame.id);
      if (!task) return;
      clearTimeout(task.timer);
      this.pending.delete(frame.id);
      if (frame.ok === true) task.resolve(frame.payload);
      else task.reject(failure(typeof frame.error?.code === "string" ? frame.error.code : "GATEWAY",
        this.redact(frame.error?.message || "The Gateway rejected the request."), this.redact(frame.error?.details)));
      return;
    }
    if (frame.type !== "event" || typeof frame.event !== "string")
      throw failure("PROTOCOL", "The Gateway frame format is not supported.");
    if (frame.event === "connect.challenge") {
      if (this.challengeReceived || this.connected) throw failure("PROTOCOL", "The Gateway sent a duplicate device authentication challenge.");
      const { nonce, ts } = frame.payload || {};
      if (typeof nonce !== "string" || !nonce.trim() || !Number.isSafeInteger(ts) || ts < 0)
        throw failure("PROTOCOL", "The Gateway authentication challenge has an invalid nonce or timestamp.");
      this.challengeReceived = true;
      const signed = deviceAuthPayload({ deviceId: this.identity.deviceId, scopes: this.scopes,
        signedAt: ts, token: this.signatureToken, nonce });
      const signature = await this.identity.sign(signed);
      if (generation !== this.generation) return;
      const hello = await this.sendRequest("connect", {
        minProtocol: OPENCLAW_PROTOCOL, maxProtocol: OPENCLAW_PROTOCOL,
        client: { id: CLIENT_ID, displayName: "Browser LLM Lab", version: "1.0.0", platform: "web", deviceFamily: "browser", mode: CLIENT_MODE },
        role: "operator", scopes: this.scopes, caps: ["tool-events"], auth: this.auth,
        device: { id: this.identity.deviceId, publicKey: this.identity.publicKey, signature, signedAt: ts, nonce },
      });
      if (generation !== this.generation) return;
      if (hello?.type !== "hello-ok" || hello.protocol !== OPENCLAW_PROTOCOL ||
          hello.auth?.role !== "operator" || !Array.isArray(hello.auth?.scopes))
        throw failure("PROTOCOL", "This interface requires an OpenClaw Gateway protocol 4 operator connection.");
      if (!SCOPES.every(scope => hello.auth.scopes.includes(scope)))
        throw failure("SCOPE", "This interface requires operator.read and operator.write. Reconnect using credentials paired and approved for both scopes.");
      if (typeof hello.auth.deviceToken === "string") {
        this.secrets.add(hello.auth.deviceToken);
        try { this.storage?.setItem(this.tokenKey, JSON.stringify({ token: hello.auth.deviceToken, scopes: hello.auth.scopes })); }
        catch { /* This connection works even if a new token cannot be stored. */ }
      }
      // Never expose reusable credentials to UI callbacks, status text, or logs.
      const { deviceToken, deviceTokens, ...auth } = hello.auth;
      this.hello = { ...hello, auth };
      this.connected = true;
      this.auth = null;
      this.signatureToken = "";
      clearTimeout(this.connectTimer);
      const waiting = this.connectWait;
      this.connectWait = null;
      waiting?.resolve(this.hello);
      this.emitState("connected");
      return;
    }
    if (!this.connected) return;
    const gap = Number.isSafeInteger(frame.seq) && this.lastSequence !== null && frame.seq > this.lastSequence + 1;
    if (Number.isSafeInteger(frame.seq)) {
      if (this.lastSequence !== null && frame.seq <= this.lastSequence) return;
      this.lastSequence = frame.seq;
    }
    const terminal = frame.event === "chat" && ["final", "aborted", "error"].includes(frame.payload?.state);
    // A terminal snapshot remains authoritative even if it reveals a missing event.
    if (!gap || terminal) {
      if (frame.event === "chat") {
        const payload = frame.payload || {};
        const key = JSON.stringify([payload.sessionKey, payload.agentId || "", payload.runId]);
        let text = this.streams.get(key) || "";
        if (payload.state === "delta") {
          // A full message snapshot already includes deltaText from that frame.
          if (payload.message !== undefined) text = extractTextMessage(payload.message);
          else if (typeof payload.deltaText === "string") {
            if (!payload.replace && !this.streams.has(key))
              throw failure("EVENT_GAP", "The beginning of this reply was missed. Reconnect and reload conversation history.");
            text = payload.replace ? payload.deltaText : text + payload.deltaText;
          }
          this.streams.set(key, text);
        } else if (terminal) {
          if (payload.message) text = extractTextMessage(payload.message);
          this.streams.delete(key);
        }
        frame = { ...frame, text };
      }
      try { this.onEvent(this.redact(frame)); } catch { /* Views do not own transport state. */ }
    }
    if (gap) throw failure("EVENT_GAP", "Some Gateway updates were missed. Reconnect and reload conversation history.");
  }

  sendRequest(method, params, timeoutMs = this.requestTimeoutMs) {
    if (!this.socket || this.socket.readyState !== 1)
      return Promise.reject(failure("DISCONNECTED", "Connect to the Gateway first."));
    const id = this.crypto.randomUUID();
    let data;
    try { data = JSON.stringify({ type: "req", id, method, params }); }
    catch { return Promise.reject(failure("INPUT", "The request could not be encoded as JSON.")); }
    const bytes = encoder.encode(data).length;
    if (bytes > (this.hello?.policy?.maxPayload || 65536))
      return Promise.reject(failure("INPUT", "The request exceeds the Gateway input limit."));
    if ((this.socket.bufferedAmount || 0) + bytes > (this.hello?.policy?.maxBufferedBytes || 1048576))
      return Promise.reject(failure("BUSY", "The Gateway connection is busy sending data. Wait briefly and retry."));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(failure("TIMEOUT", `${method} timed out. An operation already sent to the Gateway may still be running.`));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      try { this.socket.send(data); }
      catch {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(failure("DISCONNECTED", "The request could not be sent to the Gateway."));
      }
    });
  }

  request(method, params = {}, timeoutMs = this.requestTimeoutMs) {
    if (!this.connected) return Promise.reject(failure("DISCONNECTED", "Connect to the Gateway first."));
    if (method === "connect") return Promise.reject(failure("INPUT", "Use connect() to authenticate a new connection."));
    return this.sendRequest(method, params, timeoutMs);
  }

  sendMessage({ sessionKey, agentId, message, idempotencyKey = this.crypto.randomUUID() }) {
    return this.request("chat.send", { sessionKey, ...(agentId ? { agentId } : {}), message, idempotencyKey });
  }

  history(sessionKey, agentId) {
    return this.request("chat.history", { sessionKey, ...(agentId ? { agentId } : {}), limit: 100 });
  }

  abort({ sessionKey, agentId, runId }) {
    return this.request("chat.abort", { sessionKey, ...(agentId ? { agentId } : {}), ...(runId ? { runId } : {}) });
  }

  subscribe(sessionKey, agentId) {
    return this.request("sessions.messages.subscribe", { key: sessionKey, ...(agentId ? { agentId } : {}) });
  }

  async unsubscribe(sessionKey, agentId) {
    const result = await this.request("sessions.messages.unsubscribe", { key: sessionKey, ...(agentId ? { agentId } : {}) });
    for (const key of this.streams.keys()) {
      const [session, owner] = JSON.parse(key);
      if (session === sessionKey && (!agentId || owner === agentId)) this.streams.delete(key);
    }
    return result;
  }

  fail(error) {
    const safe = failure(error.code || "CONNECTION", this.redact(error.message || "The Gateway connection failed."), this.redact(error.details));
    this.close(safe, false);
    this.emitState("error", safe);
  }

  close(error, notify = true) {
    this.generation++;
    const socket = this.socket;
    this.socket = null;
    clearTimeout(this.connectTimer);
    this.connectWait?.reject(error);
    this.connectWait = null;
    for (const task of this.pending.values()) { clearTimeout(task.timer); task.reject(error); }
    this.pending.clear();
    this.streams.clear();
    this.connected = false;
    this.hello = null;
    this.auth = null;
    this.signatureToken = "";
    if (socket) { try { socket.close(1000, "Client disconnected"); } catch { /* already closed */ } }
    if (notify) this.emitState("disconnected");
  }

  disconnect() { this.close(failure("DISCONNECTED", "Disconnected from the Gateway.")); }
}
