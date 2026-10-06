import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto, randomUUID } from "node:crypto";
import { OpenClawClient, normalizeGatewayURL, extractTextMessage, deviceAuthPayload } from "../public/openclaw-client.js";

const crypto = { subtle: webcrypto.subtle, randomUUID };
const tick = () => new Promise(resolve => setTimeout(resolve, 0));
const encode = bytes => Buffer.from(bytes).toString("base64url");
const challenge = { type: "event", event: "connect.challenge", payload: { nonce: "gateway-challenge", ts: 1770000000000 } };
const hello = {
  type: "hello-ok", protocol: 4, server: { version: "test", connId: "connection" },
  features: { methods: ["chat.send", "chat.history", "chat.abort", "sessions.list"], events: ["chat", "agent"] },
  snapshot: {}, auth: { role: "operator", scopes: ["operator.read", "operator.write"], deviceToken: "paired-device-secret" },
  policy: { maxPayload: 100000, maxBufferedBytes: 200000, tickIntervalMs: 15000 },
};

async function identity() {
  const keys = await webcrypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]);
  const raw = await webcrypto.subtle.exportKey("raw", keys.publicKey);
  return {
    deviceId: Buffer.from(await webcrypto.subtle.digest("SHA-256", raw)).toString("hex"),
    publicKey: encode(raw),
    sign: async payload => encode(await webcrypto.subtle.sign("Ed25519", keys.privateKey, new TextEncoder().encode(payload))),
  };
}

class MemoryStorage {
  values = new Map();
  getItem(key) { return this.values.get(key) ?? null; }
  setItem(key, value) { this.values.set(key, value); }
}

async function setup(t, overrides = {}) {
  const sockets = [], events = [], states = [];
  class Socket {
    constructor(url) { this.url = url; this.readyState = 1; this.sent = []; this.bufferedAmount = 0; sockets.push(this); }
    send(value) { this.sent.push(JSON.parse(value)); }
    emit(frame) { this.onmessage?.({ data: JSON.stringify(frame) }); }
    close(code, reason) { this.readyState = 3; this.onclose?.({ code, reason }); }
    reply(request, payload = {}) { this.emit({ type: "res", id: request.id, ok: true, payload }); }
  }
  const device = await identity();
  const storage = new MemoryStorage();
  const client = new OpenClawClient({ crypto, storage, WebSocketImpl: Socket,
    identityProvider: async () => device, onEvent: frame => events.push(frame), onState: state => states.push(state), ...overrides });
  t.after(() => client.disconnect());
  async function begin(options = {}) {
    const pending = client.connect({ url: "ws://127.0.0.1:18789", token: "shared-bootstrap-secret", ...options });
    await tick();
    return { pending, socket: sockets.at(-1) };
  }
  async function finish(socket, pending, response = hello) {
    socket.emit(challenge);
    for (let i = 0; i < 30 && !socket.sent.length; i++) await tick();
    socket.reply(socket.sent[0], response);
    return pending;
  }
  async function connect(options) { const started = await begin(options); await finish(started.socket, started.pending); return started.socket; }
  return { client, device, sockets, events, states, storage, begin, finish, connect };
}

test("Gateway URLs require TLS except exact loopback and never embed credentials", () => {
  assert.equal(normalizeGatewayURL("ws://localhost:18789"), "ws://localhost:18789/");
  assert.equal(normalizeGatewayURL("wss://gateway.example/control"), "wss://gateway.example/control");
  for (const url of ["ws://192.168.1.1:18789", "ws://localhost.example", "https://gateway.example", "wss://user:secret@example.com", "wss://example.com?token=secret", "wss://example.com/#token"]) {
    assert.throws(() => normalizeGatewayURL(url));
  }
});

test("text extraction includes only plain text content, never tool or reasoning blocks", () => {
  assert.equal(extractTextMessage("plain"), "plain");
  assert.equal(extractTextMessage({ content: "text" }), "text");
  assert.equal(extractTextMessage({ content: [{ type: "text", text: "A" }, { type: "tool_use", text: "ignored" }, { type: "thinking", thinking: "hidden" }, { type: "text", text: "B" }] }), "A\nB");
  assert.equal(extractTextMessage(null), "");
});

test("connect waits for challenge and sends a real verifiable Ed25519 v3 device proof", async t => {
  const { client, device, begin, finish, storage, states } = await setup(t);
  const { pending, socket } = await begin();
  assert.equal(socket.sent.length, 0);
  const connected = await finish(socket, pending);
  const request = socket.sent[0];
  assert.equal(request.method, "connect");
  assert.equal(request.params.minProtocol, 4);
  assert.equal(request.params.maxProtocol, 4);
  assert.equal(request.params.role, "operator");
  assert.deepEqual(request.params.scopes, ["operator.read", "operator.write"]);
  assert.deepEqual(request.params.auth, { token: "shared-bootstrap-secret" });
  assert.equal(request.params.device.signedAt, challenge.payload.ts);
  const payload = deviceAuthPayload({ deviceId: device.deviceId, scopes: request.params.scopes,
    signedAt: challenge.payload.ts, token: "shared-bootstrap-secret", nonce: challenge.payload.nonce });
  const publicKey = await webcrypto.subtle.importKey("raw", Buffer.from(device.publicKey, "base64url"), "Ed25519", false, ["verify"]);
  assert.equal(await webcrypto.subtle.verify("Ed25519", publicKey, Buffer.from(request.params.device.signature, "base64url"), new TextEncoder().encode(payload)), true);
  assert.equal(client.connected, true);
  assert.ok(!("deviceToken" in connected.auth));
  assert.ok(!JSON.stringify(states).includes("paired-device-secret"));
  assert.ok(![...storage.values.values()].join("").includes("shared-bootstrap-secret"));
});

test("paired device token is reused only for the same endpoint and device", async t => {
  const { client, connect, begin, finish, storage } = await setup(t);
  await connect();
  client.disconnect();
  const second = await begin({ token: "" });
  await finish(second.socket, second.pending);
  assert.deepEqual(second.socket.sent[0].params.auth, { deviceToken: "paired-device-secret" });
  assert.equal(storage.values.size, 1);
  await assert.rejects(client.connect({ url: "wss://other.example", token: "" }), { code: "AUTH_REQUIRED" });
});

test("a read-only paired token is not expanded and insufficient hello scopes fail closed", async t => {
  const { client, connect, begin, finish, storage, states } = await setup(t);
  await connect();
  client.disconnect();
  const key = [...storage.values.keys()][0];
  storage.setItem(key, JSON.stringify({ token: "read-only-device-secret", scopes: ["operator.read"] }));
  const { socket, pending } = await begin({ token: "" });
  const rejected = assert.rejects(pending, error => error.code === "SCOPE" && /operator.write/.test(error.message));
  await finish(socket, pending, { ...hello, auth: {
    role: "operator", scopes: ["operator.read"], deviceToken: "new-read-only-secret",
  } }).catch(() => {});
  await rejected;
  assert.deepEqual(socket.sent[0].params.scopes, ["operator.read"]);
  assert.equal(client.connected, false);
  assert.equal(client.hello, null);
  assert.equal(states.at(-1).state, "error");
  assert.equal(states.at(-1).error.code, "SCOPE");
  assert.ok(!JSON.stringify(states).includes("read-only-device-secret"));
  assert.ok(!JSON.stringify(states).includes("new-read-only-secret"));
  assert.equal(JSON.parse(storage.getItem(key)).token, "read-only-device-secret");
});

test("empty and write-only granted scope sets cannot enable agent tasks", async t => {
  for (const scopes of [[], ["operator.write"]]) {
    const { client, begin, finish } = await setup(t);
    const { socket, pending } = await begin();
    const rejected = assert.rejects(pending, { code: "SCOPE" });
    await finish(socket, pending, { ...hello, auth: { ...hello.auth, scopes } }).catch(() => {});
    await rejected;
    assert.equal(client.connected, false);
  }
});

test("invalid challenge timestamp never falls back to local time or unsigned auth", async t => {
  const { begin } = await setup(t);
  const { socket, pending } = await begin();
  const rejected = assert.rejects(pending, { code: "PROTOCOL" });
  socket.emit({ ...challenge, payload: { nonce: "nonce" } });
  await rejected;
  assert.equal(socket.sent.length, 0);
});

test("pairing errors retain request IDs and recovery details while redacting secrets", async t => {
  const { begin, states } = await setup(t);
  const { socket, pending } = await begin();
  const rejected = assert.rejects(pending, error => error.code === "NOT_PAIRED" && error.details.requestId === "request-123" && !error.message.includes("shared-bootstrap-secret"));
  socket.emit(challenge);
  for (let i = 0; i < 30 && !socket.sent.length; i++) await tick();
  socket.emit({ type: "res", id: socket.sent[0].id, ok: false, error: { code: "NOT_PAIRED", message: "Pairing required shared-bootstrap-secret", details: { code: "PAIRING_REQUIRED", requestId: "request-123", recommendedNextStep: "approve_pairing" } } });
  await rejected;
  assert.equal(states.at(-1).state, "error");
  assert.ok(!JSON.stringify(states).includes("shared-bootstrap-secret"));
});

test("chat commands preserve run correlation and idempotency without sending WebLLM identifiers", async t => {
  const { client, connect } = await setup(t);
  const socket = await connect();
  const send = client.sendMessage({ sessionKey: "agent:main:main", message: "Read this page", idempotencyKey: "logical-send-1" });
  const request = socket.sent.at(-1);
  assert.equal(request.method, "chat.send");
  assert.deepEqual(request.params, { sessionKey: "agent:main:main", message: "Read this page", idempotencyKey: "logical-send-1" });
  socket.reply(request, { runId: "run-1", status: "started" });
  assert.equal((await send).runId, "run-1");
  const abort = client.abort({ sessionKey: "agent:main:main", runId: "run-1" });
  assert.deepEqual(socket.sent.at(-1).params, { sessionKey: "agent:main:main", runId: "run-1" });
  socket.reply(socket.sent.at(-1), { aborted: true });
  await abort;
  const history = client.history("agent:main:main");
  assert.equal(socket.sent.at(-1).method, "chat.history");
  socket.reply(socket.sent.at(-1), { messages: [] });
  assert.deepEqual(await history, { messages: [] });
});

test("stream snapshots include their deltas and later frames append, replace, and settle correctly", async t => {
  const { connect, events } = await setup(t);
  const socket = await connect();
  const emit = (seq, payload) => socket.emit({ type: "event", event: "chat", seq, payload: { sessionKey: "s", runId: "r", ...payload } });
  emit(10, { state: "delta", message: { content: [{ type: "text", text: "Hello" }] }, deltaText: "Hello" });
  emit(11, { state: "delta", deltaText: " world" });
  emit(12, { state: "delta", replace: true, deltaText: "Replaced" });
  emit(13, { state: "final", message: { content: "Complete" } });
  assert.deepEqual(events.map(event => event.text), ["Hello", "Hello world", "Replaced", "Complete"]);
});

test("agent-scoped global sessions retain their owner in every chat RPC", async t => {
  const { client, connect } = await setup(t);
  const socket = await connect();
  const cases = [
    [() => client.sendMessage({ sessionKey: "global", agentId: "research", message: "Continue", idempotencyKey: "turn" }),
      "chat.send", { sessionKey: "global", agentId: "research", message: "Continue", idempotencyKey: "turn" }],
    [() => client.history("global", "research"), "chat.history", { sessionKey: "global", agentId: "research", limit: 100 }],
    [() => client.abort({ sessionKey: "global", agentId: "research", runId: "turn" }),
      "chat.abort", { sessionKey: "global", agentId: "research", runId: "turn" }],
  ];
  for (const [invoke, method, params] of cases) {
    const pending = invoke();
    assert.equal(socket.sent.at(-1).method, method);
    assert.deepEqual(socket.sent.at(-1).params, params);
    socket.reply(socket.sent.at(-1), {});
    await pending;
  }
});

test("message subscriptions use key and optional agentId, preserving canonical acknowledgments", async t => {
  const { client, connect } = await setup(t);
  const socket = await connect();
  const pending = client.subscribe("global", "research");
  assert.equal(socket.sent.at(-1).method, "sessions.messages.subscribe");
  assert.deepEqual(socket.sent.at(-1).params, { key: "global", agentId: "research" });
  socket.reply(socket.sent.at(-1), { subscribed: true, key: "agent:research:main", agentId: "research" });
  assert.deepEqual(await pending, { subscribed: true, key: "agent:research:main", agentId: "research" });
  socket.emit({ type: "event", event: "chat", payload: { state: "delta", sessionKey: "agent:research:main", agentId: "research", runId: "run", replace: true, deltaText: "Working" } });
  assert.equal(client.streams.size, 1);
  const unsubscribe = client.unsubscribe("agent:research:main", "research");
  assert.equal(socket.sent.at(-1).method, "sessions.messages.unsubscribe");
  assert.deepEqual(socket.sent.at(-1).params, { key: "agent:research:main", agentId: "research" });
  socket.reply(socket.sent.at(-1), { subscribed: false });
  await unsubscribe;
  assert.equal(client.streams.size, 0);
  const defaultOwner = client.subscribe("agent:main:main");
  assert.deepEqual(socket.sent.at(-1).params, { key: "agent:main:main" });
  socket.reply(socket.sent.at(-1), { subscribed: true });
  await defaultOwner;
});

test("out-of-order events are ignored and missing stream baselines require reconnection", async t => {
  const { client, connect, events, states } = await setup(t);
  const socket = await connect();
  const frame = { type: "event", event: "chat", seq: 8, payload: { sessionKey: "s", runId: "r", state: "delta", replace: true, deltaText: "Start" } };
  socket.emit(frame);
  socket.emit(frame);
  assert.equal(events.length, 1);
  socket.emit({ ...frame, seq: 10, payload: { ...frame.payload, replace: false, deltaText: "missing" } });
  await tick();
  assert.equal(client.connected, false);
  assert.equal(states.at(-1).error.code, "EVENT_GAP");
});

test("a terminal snapshot is delivered before closing a connection with an event gap", async t => {
  const { client, connect, events } = await setup(t);
  const socket = await connect();
  socket.emit({ type: "event", event: "tick", seq: 1, payload: {} });
  socket.emit({ type: "event", event: "chat", seq: 3, payload: { sessionKey: "s", runId: "r", state: "final", message: { content: "Done" } } });
  await tick();
  assert.equal(events.at(-1).text, "Done");
  assert.equal(client.connected, false);
});

test("request timeout and explicit disconnect reject pending requests", async t => {
  const { client, connect } = await setup(t);
  await connect();
  await assert.rejects(client.request("status", {}, 2), { code: "TIMEOUT" });
  assert.equal(client.connected, true);
  const pending = client.request("sessions.list");
  const rejected = assert.rejects(pending, { code: "DISCONNECTED" });
  client.disconnect();
  await rejected;
  assert.equal(client.pending.size, 0);
});

test("stale sockets cannot overwrite the state of a newer connection", async t => {
  const { client, begin, finish, states } = await setup(t);
  const first = await begin();
  const rejected = assert.rejects(first.pending, { code: "CANCELLED" });
  const oldClose = first.socket.onclose;
  const second = await begin();
  await rejected;
  await finish(second.socket, second.pending);
  oldClose({ code: 1006, reason: "old socket" });
  assert.equal(client.connected, true);
  assert.equal(states.at(-1).state, "connected");
});

test("identity failure and protocol mismatch fail closed", async t => {
  const unavailable = await setup(t, { identityProvider: async () => { throw new Error("No device signing"); } });
  await assert.rejects(unavailable.client.connect({ url: "ws://localhost:18789", token: "secret" }), /No device signing/);
  assert.equal(unavailable.sockets.length, 0);
  const mismatch = await setup(t);
  const { socket, pending } = await mismatch.begin();
  const rejected = assert.rejects(pending, { code: "PROTOCOL" });
  await mismatch.finish(socket, pending, { ...hello, protocol: 3 }).catch(() => {});
  await rejected;
  assert.equal(mismatch.client.connected, false);
});
