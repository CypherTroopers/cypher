// Application event-flow tests with an in-memory DOM and the actual Worker dispatcher.
// This is NOT a rendered browser test, real GPU test, or a real model download.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRuntime } from "../public/worker.js";
import { MODELS, PROFILE_KEY, ATTEMPT_KEY, errorDetails } from "../public/models.js";

class Element {
  constructor(tag = "div") {
    this.tagName = tag.toUpperCase(); this.children = []; this._text = ""; this.value = ""; this.disabled = false; this.open = false; this.hidden = false; this.style = { setProperty() {} };
    this.attributes = new Map();
    const classes = new Set();
    this.classList = { add: (...names) => names.forEach(name => classes.add(name)), remove: (...names) => names.forEach(name => classes.delete(name)), contains: name => classes.has(name), toggle: (name, force) => {
      const add = force ?? !classes.has(name); add ? classes.add(name) : classes.delete(name); return add;
    } };
  }
  get textContent() { return this._text + this.children.map(child => typeof child === "string" ? child : child.textContent).join(""); }
  set textContent(text) { this._text = String(text); this.children = []; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this._text = ""; this.children = children; }
  addEventListener() {}
  scrollIntoView() {}
  setAttribute(name, value) { this.attributes.set(name, String(value)); this[name] = value; }
  getAttribute(name) { return this.attributes.get(name) ?? null; }
  removeAttribute(name) { this.attributes.delete(name); delete this[name]; }
  contains(node) { return node === this || this.children.some(child => typeof child !== "string" && child.contains(node)); }
  blur() {}
  focus() { globalThis.document.activeElement = this; }
  remove() {}
}
class MemoryStorage {
  constructor() { this.map = new Map(); }
  getItem(key) { return this.map.get(key) ?? null; }
  setItem(key, value) { this.map.set(key, String(value)); }
  removeItem(key) { this.map.delete(key); }
}
const tick = () => new Promise(resolve => setTimeout(resolve, 0));

function environment() {
  const html = readFileSync(new URL("../public/index.html", import.meta.url), "utf8");
  const elements = {};
  for (const [, tag, attributes] of html.matchAll(/<([a-zA-Z][\w-]*)\b([^>]*)>/g)) {
    const id = attributes.match(/\bid="([^"]+)"/)?.[1];
    if (!id) continue;
    const element = elements[id] = new Element(tag);
    for (const name of ["hidden", "disabled", "open", "checked"])
      element[name] = new RegExp(`(?:^|\\s)${name}(?:\\s|=|$)`).test(attributes);
    for (const [, name, value] of attributes.matchAll(/([\w-]+)="([^"]*)"/g)) element.setAttribute(name, value);
    for (const name of (element.getAttribute("class") || "").split(/\s+/).filter(Boolean)) element.classList.add(name);
  }
  elements.mode.value = "auto"; elements.cap.value = "1200"; elements.answerLanguage.value = "en";
  elements.taskMode.value = "local"; elements.heroMode.value = "local"; elements.installOS.value = "auto"; elements.installArch.value = "auto";
  elements.start.disabled = true; elements.send.disabled = true; elements.timeRange.value = "";
  const listeners = {};
  const state = { consent: false, calls: [], loadFail: false, searchFail: false, reasoningOnly: false, reloads: 0, workers: [] };
  const localStorage = new MemoryStorage(), sessionStorage = new MemoryStorage();
  const window = {
    localStorage, isSecureContext: true, innerWidth: 1440, innerHeight: 844,
    addEventListener(name, callback) { (listeners[name] ||= []).push(callback); },
    confirm() { return state.consent; },
  };
  const records = MODELS.flatMap((model, i) => model.variants.map(model_id => ({ model_id,
    model: `https://huggingface.co/mock/${model.key}`, model_lib: "mock.wasm",
    vram_required_MB: 500 + i * 10, overrides: { context_window_size: 4096 },
  })));
  class FakeEngine {
    constructor(options) { this.options = options; this.chat = { completions: { create: request => this.create(request) } }; }
    async reload(modelId) {
      state.calls.push({ kind: "load", modelId }); this.id = modelId;
      if (state.loadFail) { state.loadFail = false; throw Object.assign(new Error("Synthetic device loss"), { name: "DeviceLostError" }); }
      this.options.initProgressCallback({ text: "Loaded mock", progress: 1 });
    }
    async unload() { state.calls.push({ kind: "unload" }); }
    async resetChat() {}
    async create(request) {
      state.calls.push({ kind: "generate", modelId: this.id, request });
      if (!request.stream) return { usage: { completion_tokens: request.max_tokens } };
      const text = this.id.startsWith("DeepSeek") ? state.reasoningOnly ? "<think>Unfinished draft" : "<think>Draft</think>Answer [1]." : "Answer [1].";
      return (async function* () {
        yield { choices: [{ delta: { content: text }, finish_reason: state.reasoningOnly ? "length" : "stop" }] };
        yield { choices: [], usage: { completion_tokens: request.max_tokens, prompt_tokens: 100, extra: { decode_tokens_per_s: 20 } } };
      })();
    }
  }
  class MockWorker {
    constructor() {
      this.dead = false; let clock = 0;
      this.runtime = createRuntime({
        loadLibrary: async () => ({ prebuiltAppConfig: { model_list: records }, MLCEngine: FakeEngine, hasModelInCache: async () => false }),
        readDevice: async () => ({ features: ["shader-f16"], maxBufferSize: 1e9, maxStorageBufferBindingSize: 1e9 }),
        fetcher: async () => ({ ok: true, text: async () => JSON.stringify({ records: [{ dataPath: "shard", nbytes: 1000 }] }) }),
        estimate: async () => ({ usage: 0, quota: 1e9 }), now: () => (clock += 100),
      });
      state.workers.push(this);
    }
    postMessage({ id, type, data }) {
      queueMicrotask(async () => {
        const send = (kind, value) => { if (!this.dead) this.onmessage?.({ data: { id, kind, value } }); };
        if (this.dead) return;
        try { send("result", await this.runtime.dispatch(type, data, send)); }
        catch (error) { send("error", errorDetails(error, type)); }
      });
    }
    terminate() { this.dead = true; }
  }
  Object.assign(globalThis, { window, sessionStorage,
    document: { getElementById: id => elements[id], createElement: tag => new Element(tag), documentElement: new Element("html"), body: new Element("body"), addEventListener() {} },
    location: { reload: () => state.reloads++ },
    requestAnimationFrame: callback => setTimeout(callback, 0),
    Option: class extends Element { constructor(text, value) { super("option"); this.textContent = text; this.value = value; } },
    Worker: MockWorker,
    fetch: async (url, options) => {
      state.calls.push({ kind: "search", body: JSON.parse(options.body) });
      if (state.searchFail) return { ok: false, status: 502, json: async () => ({ ok: false, error: "Synthetic search error" }) };
      return { ok: true, json: async () => ({ ok: true, retrieved_at: "2026-09-28T00:00:00Z", results: [
        { title: "Source", domain: "example.com", url: "https://example.com/test", snippet: "Synthetic test evidence.", published: "" },
      ] }) };
    },
  });
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: { userAgent: "test-browser", deviceMemory: 8 } });
  return { state, elements, localStorage, sessionStorage, listeners };
}

test("UI event flow using an in-memory DOM and mocked inference", async t => {
  const { state, elements: el, localStorage, listeners } = environment();
  await import(`../public/app.js?ui-test=${Date.now()}`);
  for (let i = 0; i < 20 && el.start.disabled; i++) await tick();
  const loads = () => state.calls.filter(call => call.kind === "load");
  const generations = () => state.calls.filter(call => call.kind === "generate");
  const send = async text => { el.prompt.value = text; await el.form.onsubmit({ preventDefault() {} }); };

  await t.test("Connection counts exclude pending paths and keep capacity in secondary details", async () => {
    const { setupRelayUI } = await import('../public/relay-ui.js'); const relay = setupRelayUI();
    assert.match(el.relayConnectionLimits.textContent, /Common attachment limit: 20/, 'Initial OFF shows the configured ceiling before any gateway admission');
    relay.emit('stats', { ...relay.snapshot(), requested: true });
    assert.match(el.relayConnectionLimits.textContent, /Common attachment limit: 20/, 'Connecting before config arrives retains the configured ceiling');
    const common = { maxSessions: 80, circuits: 40 };
    const connections = Array.from({ length: 20 }, (_, i) => ({ id: `attachment-${i}`, sourceId: `common-${i}`, connected: i < 2 }));
    for (const [limit, aiLoad] of [[40, 'idle'], [1, 'generating'], [0, 'loading']]) {
      relay.emit('stats', { ...relay.snapshot(), requested: true, nativeConnected: true, commonConnections: connections, connectionLimits: { peers: 20, commons: 20 }, aiLoad,
        endpointCircuits: limit, capacities: { endpointCircuits: limit, circuits: limit, common },
        peers: [{ peerId: 'connected-peer', connected: true }, { peerId: 'pending-peer', connected: false }] });
      assert.equal(el.relayCommonCircuits.textContent, String(limit));
      assert.equal(el.relayCommonPeers.textContent, '2');
      assert.equal(el.relayCommonList.children.length, 20);
      assert.equal(el.relayCommonList.children.filter(row => row.getAttribute('data-common-connected') === 'true').length, 2);
      assert.equal(el.relayCommonPeerHint.textContent, 'common-0, common-1 · WSS connected');
      assert.match(el.relayConnectionLimits.textContent, /Browser peer limit: 20 · Common attachment limit: 20/);
      assert.match(el.relayConnectionLimits.textContent, /Shared browser circuit policy: 40 total across all Common links and browser peers/);
      assert.equal(el.relayPeers.textContent, '1');
      assert.match(el.relayConnectionLimits.textContent, /shares 40 circuits across up to 80 sessions/);
      assert(el.relayConnectionLimits.textContent.includes(`Endpoint circuit limit: ${limit}`));
    }
    relay.emit('stats', { ...relay.snapshot(), requested: true, nativeConnected: true, commonConnections: connections,
      endpointCircuits: 5, pendingInbound: 1, pendingOutbound: 1, transitCircuits: 2, pendingTransit: 1,
      circuits: 7, pendingHandshakes: 3, peers: [] });
    assert.equal(el.relayCommonCircuits.textContent, '3');
    assert.equal(el.relayCommonCircuitHint.textContent, 'Open across Common links · 2 opening');
    assert.equal(el.relayCacheEntries.textContent, '4 open circuits · 3 opening · 1 transit · RAM only');
    relay.emit('stats', { ...relay.snapshot(), requested: true, nativeConnected: true,
      commonConnections: connections.map(connection => ({ ...connection, connected: true })),
      peers: Array.from({ length: 20 }, (_, i) => ({ peerId: `peer-${i}`, connected: true })) });
    assert.equal(el.relayCommonPeers.textContent, '20'); assert.equal(el.relayPeers.textContent, '20');
    assert.equal(el.relayCommonList.children.filter(row => row.getAttribute('data-common-connected') === 'true').length, 20);
    relay.emit('stats', { ...relay.snapshot(), requested: true, nativeConnected: true,
      commonConnections: connections.map(connection => ({ ...connection, connected: false })), peers: [] });
    assert.equal(el.relayCommonPeers.textContent, '0', 'A generic nativeConnected flag does not invent live Common attachments');
    relay.emit('stats', { ...relay.snapshot(), requested: false, nativeConnected: true, commonConnections: connections,
      endpointCircuits: 5, circuits: 5, peers: [{ peerId: 'stale-peer', connected: true }] });
    assert.equal(el.relayCommonCircuits.textContent, '0');
    assert.equal(el.relayCommonPeers.textContent, '0');
    assert.equal(el.relayPeers.textContent, '0');
    assert.equal(el.relayCommonList.children.filter(row => row.getAttribute('data-common-connected') === 'true').length, 0);
    relay.config = { limits: { maxPeers: 6, maxCommonConnections: 1 } };
    relay.emit('stats', { ...relay.snapshot(), connectionLimits: { peers: 6, commons: 1 } });
    assert.match(el.relayConnectionLimits.textContent, /Browser peer limit: 6 · Common attachment limit: 1/,
      'Connection details honor the controller applied limits, including a single-Common harness');
    relay.stop(); assert.equal(el.relayCommonCircuits.textContent, '0');
  });
  await t.test("initialization enables Start but does not load model weights", () => {
    assert.equal(el.start.disabled, false);
    assert.equal(loads().length, 0);
    assert.match(el.device.textContent, /26\/26/);
    assert.equal(el.setupPanel.hidden, true);
    assert.equal(el.cardModelName.textContent, "Not loaded");
    assert.equal(el.cardSpeed.textContent, "Not measured");
    assert.equal(el.systemGateway.textContent, "Not connected");
  });
  await t.test("a home question survives missing-model setup without downloading or generating", async () => {
    el.heroInput.value = "Help me organize a private idea";
    await el.heroForm.onsubmit({ preventDefault() {} });
    assert.equal(el.prompt.value, "Help me organize a private idea");
    assert.equal(el.taskMode.value, "local");
    assert.equal(el.setupPanel.hidden, false);
    assert.equal(el.modelPanel.open, true);
    assert.equal(loads().length, 0);
    assert.equal(generations().length, 0);
    assert.equal(state.calls.filter(call => call.kind === "search").length, 0);
    el.closeSetup.onclick();
    el.navHome.onclick();
    assert.equal(el.homePanel.inert, false);
    assert.equal(document.body.classList.contains("chat-open"), false);
  });
  await t.test("cancel initial selection leaves no model loaded", async () => {
    await el.start.onclick();
    assert.equal(loads().length, 0);
    assert.equal(el.send.disabled, true);
    assert.match(el.status.textContent, /Cancelled/);
  });
  await t.test("Start loads exactly one model and runs the complete benchmark", async () => {
    state.consent = true;
    await el.start.onclick();
    assert.equal(el.send.disabled, false);
    assert.equal(loads().length, 1);
    assert.deepEqual(generations().map(call => call.request.max_tokens), [8, 64, 64]);
  });
  await t.test("default local chat generates without a search request", async () => {
    const searches = state.calls.filter(call => call.kind === "search").length;
    await send("Help me think through an idea");
    assert.equal(state.calls.filter(call => call.kind === "search").length, searches);
    assert.equal(generations().at(-1).request.messages.at(-1).content, "Help me think through an idea");
    assert.match(el.status.textContent, /without web search/);
    el.taskMode.value = "web";
    await el.taskMode.onchange();
  });
  await t.test("search, streamed answer, and citation UI retain their event flow", async () => {
    await send("Explain browser inference");
    assert.match(el.chat.textContent, /Answer \[1\]/);
    assert.ok(state.calls.some(call => call.kind === "search"));
    assert.match(el.status.textContent, /Answer complete/);
  });
  await t.test("cancelling replacement keeps current chat and loaded model", async () => {
    state.consent = false;
    const old = el.chat.textContent;
    await el.start.onclick();
    assert.equal(el.chat.textContent, old);
    assert.equal(loads().length, 1);
    assert.equal(el.send.disabled, false);
  });
  await t.test("benchmark profile is local and successful conversation is recorded", () => {
    const profile = JSON.parse(localStorage.getItem(PROFILE_KEY));
    assert.equal(profile.results.length, 1);
    assert.equal(profile.results[0].chatSucceeded, true);
    assert.ok(!("messages" in profile.results[0]));
  });
  await t.test("manual reasoning model has separate output settings and final-answer handling", async () => {
    state.consent = true;
    el.mode.value = MODELS.find(model => model.key.startsWith("DeepSeek")).variants[0];
    el.mode.onchange();
    await el.start.onclick();
    await send("Explain the evidence");
    assert.match(el.chat.textContent, /Model-generated reasoning/);
    assert.equal(generations().at(-1).request.max_tokens, 1024);
    assert.equal(generations().at(-1).request.messages[0].role, "user");
  });
  await t.test("reasoning-only output is not mistaken for final answer or GPU failure", async () => {
    state.reasoningOnly = true;
    await send("Another question");
    assert.match(el.status.textContent, /No final answer/);
    assert.equal(el.send.disabled, false);
    state.reasoningOnly = false;
  });
  await t.test("search failure does not generate an offline answer", async () => {
    const count = generations().length;
    state.searchFail = true;
    await send("Fail the search");
    assert.match(el.status.textContent, /Search failed/);
    assert.equal(generations().length, count);
    assert.equal(el.send.disabled, false);
    state.searchFail = false;
  });
  await t.test("GPU failure does not start additional hidden model loads", async () => {
    el.mode.value = "auto";
    state.loadFail = true;
    const count = loads().length;
    await el.start.onclick();
    assert.equal(loads().length, count + 1);
    assert.match(el.status.textContent, /Startup failed \[GPU\]/);
    assert.equal(el.send.disabled, true);
    assert.equal(el.start.disabled, false);
  });
  await t.test("Forget measurements clears performance data but not caches", () => {
    const count = state.calls.length;
    el.forgetProfile.onclick();
    assert.deepEqual(JSON.parse(localStorage.getItem(PROFILE_KEY)).results, []);
    assert.equal(state.calls.length, count);
  });
  await t.test("BFCache recovery does not force a page reload", async () => {
    await el.start.onclick();
    for (const handler of listeners.pagehide) handler({ persisted: true });
    for (const handler of listeners.pageshow) await handler({ persisted: true });
    assert.equal(el.send.disabled, false);
    assert.equal(state.reloads, 0);
  });
  for (const worker of state.workers) worker.terminate();
  await tick();
});
