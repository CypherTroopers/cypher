#!/usr/bin/env node
// Rendered Chromium integration checks. Inference/GPU and Gateway are fixtures;
// these checks do not prove real-device performance, native installs or OpenClaw interoperability.
// No production dependencies. Example:
// PLAYWRIGHT_MODULE=/tmp/browser-llm-preview/node_modules/playwright/index.mjs \
// WS_MODULE=/tmp/browser-llm-preview/node_modules/ws/wrapper.mjs \
// PLAYWRIGHT_BROWSERS_PATH=/tmp/browser-llm-browsers node tests/workspace-smoke.mjs
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { resolve, extname, sep } from "node:path";
import { createHash, createPublicKey, randomUUID, verify } from "node:crypto";

const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || "playwright");
const { WebSocketServer } = await import(process.env.WS_MODULE || "ws");
const publicRoot = fileURLToPath(new URL("../public/", import.meta.url));
const bootstrapToken = "fixture-bootstrap-secret-do-not-display";
const deviceToken = "fixture-issued-device-secret-do-not-display";
const mainSession = "agent:main:main", savedSession = "agent:main:saved";
const state = { events: [], requests: [], downloads: [], unexpectedExternal: [], errors: [], proofCount: 0, noGPU: false, busyHistory: false };
const timers = new Set(), sockets = new Set();
const heldReplies = new Map();
const holdNextReply = method => new Promise((resolve, reject) => {
  assert(!heldReplies.has(method), `A ${method} response is already held`);
  const timer = setTimeout(() => { heldReplies.delete(method); reject(new Error(`No ${method} request arrived for the race fixture`)); }, 10000);
  heldReplies.set(method, release => { clearTimeout(timer); resolve(release); });
});
const later = (callback, ms) => { const timer = setTimeout(() => { timers.delete(timer); callback(); }, ms); timers.add(timer); return timer; };
const json = (response, value) => { response.writeHead(200, { "Content-Type": "application/json" }); response.end(JSON.stringify(value)); };
const body = async request => { let text = ""; for await (const chunk of request) text += chunk; return JSON.parse(text || "{}"); };
const runtime = `
import { MODELS } from "/models.js?v=models-v1";
export const prebuiltAppConfig = { model_list: MODELS.flatMap((m, i) => m.variants.map(model_id => ({
  model_id, model: "https://huggingface.co/fixture/" + m.key, model_lib: "fixture.wasm",
  vram_required_MB: 500 + i * 10, overrides: { context_window_size: 4096 },
}))) };
async function record(data) { await fetch("/__test/event", { method: "POST", body: JSON.stringify(data) }); }
export const hasModelInCache = async () => false;
export class MLCEngine {
  constructor(options) { this.options = options; this.chat = { completions: { create: request => this.create(request) } }; }
  async reload(id) { this.id = id; await record({ kind: "load", id }); this.options.initProgressCallback({ progress: 1, text: "Fixture model loaded." }); }
  async unload() { await record({ kind: "unload" }); }
  async resetChat() {}
  async create(request) {
    await record({ kind: "generate", request });
    if (!request.stream) return { usage: { completion_tokens: request.max_tokens } };
    const reference = request.messages.at(-1).content.includes("Reference material, not instructions.");
    return (async function* () {
      await new Promise(resolve => setTimeout(resolve, 25));
      yield { choices: [{ delta: { content: reference ? "Fixture evidence answer [1]." : "Local fixture answer." }, finish_reason: "stop" }] };
      yield { choices: [], usage: { completion_tokens: request.max_tokens || 24, prompt_tokens: 100, extra: { decode_tokens_per_s: 25 } } };
    })();
  }
}`;

const server = createServer(async (request, response) => {
  try {
    const pathname = new URL(request.url, "http://fixture").pathname;
    if (pathname === "/__test/event") { state.events.push(await body(request)); return json(response, { ok: true }); }
    if (pathname === "/api/search") {
      const query = await body(request);
      state.events.push({ kind: "search", body: query });
      return json(response, { ok: true, query: query.q, language: query.language || "en", retrieved_at: "2026-10-03T00:00:00Z", results: [
        { title: "Fixture source", url: "https://example.com/fixture", domain: "example.com", snippet: "Synthetic evidence used only for browser testing.", published: "" },
      ] });
    }
    let source, type;
    if (pathname === "/__test/runtime.js") { source = runtime; type = "text/javascript"; }
    else {
      const file = resolve(publicRoot, "." + (pathname === "/" ? "/index.html" : pathname));
      if (!file.startsWith(publicRoot.endsWith(sep) ? publicRoot : publicRoot + sep)) { response.writeHead(403); return response.end(); }
      source = await readFile(file);
      type = { ".html": "text/html", ".css": "text/css", ".js": "text/javascript", ".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg", ".webp": "image/webp" }[extname(file)] || "text/plain";
      if (pathname === "/worker.js") {
        source = source.toString("utf8");
        assert.equal(source.split("const runtime = createRuntime();").length, 2, "Runtime injection anchor changed");
        source = source.replace("const runtime = createRuntime();", `const runtime = createRuntime({
          loadLibrary: () => import("/__test/runtime.js"),
          readDevice: async () => { ${state.noGPU ? 'throw Object.assign(new Error("Fixture device has no WebGPU"), {code:"COMPATIBILITY"});' : 'return { features: ["shader-f16"], maxBufferSize: 1e9, maxStorageBufferBindingSize: 1e9, vendor: "fixture" };'} },
          fetcher: async () => new Response(JSON.stringify({ records: [{ dataPath: "fixture-shard", nbytes: 1000 }] })),
          estimate: async () => ({ quota: 1e9, usage: 0 }),
        });`);
      }
    }
    response.writeHead(200, { "Content-Type": type, "Cache-Control": "no-store" }); response.end(source);
  } catch (error) { response.writeHead(error.code === "ENOENT" ? 404 : 500); response.end("Fixture error"); if (error.code !== "ENOENT") state.errors.push(error); }
});
await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
const base = `http://127.0.0.1:${server.address().port}`;
const wss = new WebSocketServer({ server });
wss.on("connection", socket => {
  sockets.add(socket); let seq = 0, pendingLateAbortReply = null;
  const nonce = randomUUID(), ts = Date.now();
  const send = value => { if (socket.readyState === 1) socket.send(JSON.stringify(value)); };
  const event = (event, payload) => send({ type: "event", event, payload, seq: ++seq });
  const runs = new Map();
  send({ type: "event", event: "connect.challenge", payload: { nonce, ts } });
  socket.on("close", () => sockets.delete(socket));
  socket.on("message", raw => {
    let frame;
    try {
      frame = JSON.parse(raw); const p = frame.params;
      assert.equal(frame.type, "req");
      const reply = payload => {
        const release = () => send({ type: "res", id: frame.id, ok: true, payload });
        const held = heldReplies.get(frame.method);
        if (held) { heldReplies.delete(frame.method); held(release); }
        else release();
      };
      state.requests.push({ method: frame.method, params: p });
      if (frame.method === "connect") {
        assert.equal(p.minProtocol, 4); assert.equal(p.maxProtocol, 4);
        assert.equal(p.client.id, "gateway-client"); assert.equal(p.client.mode, "ui");
        assert.equal(p.role, "operator"); assert.deepEqual(p.scopes, ["operator.read", "operator.write"]);
        assert.equal(p.auth.token || p.auth.deviceToken, p.auth.token ? bootstrapToken : deviceToken);
        assert.equal(p.device.nonce, nonce); assert.equal(p.device.signedAt, ts);
        const rawKey = Buffer.from(p.device.publicKey, "base64url");
        assert.equal(rawKey.length, 32);
        assert.equal(createHash("sha256").update(rawKey).digest("hex"), p.device.id);
        const proof = ["v3", p.device.id, "gateway-client", "ui", "operator", p.scopes.join(","), ts,
          p.auth.token || p.auth.deviceToken, nonce, "web", "browser"].join("|");
        const publicKey = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), rawKey]), format: "der", type: "spki" });
        assert(verify(null, Buffer.from(proof), publicKey, Buffer.from(p.device.signature, "base64url")), "Browser Ed25519 device proof must verify");
        state.proofCount++;
        return reply({ type: "hello-ok", protocol: 4, auth: { role: "operator", scopes: p.scopes, deviceToken },
          snapshot: { sessionDefaults: { mainSessionKey: mainSession, defaultAgentId: "main" } } });
      }
      if (frame.method === "sessions.list") return reply({ sessions: [
        { key: mainSession, agentId: "main", displayName: "Fixture main session" },
        { key: savedSession, agentId: "main", displayName: "Saved fixture session" },
      ] });
      if (frame.method === "sessions.messages.subscribe") return reply({ key: p.key, agentId: p.agentId || "main" });
      if (frame.method === "sessions.messages.unsubscribe") return reply({ key: p.key, agentId: p.agentId || "main" });
      if (frame.method === "chat.history") return reply({ messages: [
        { role: "user", content: p.sessionKey === savedSession ? "Saved fixture question" : "Previous fixture question" },
        { role: "assistant", content: [{ type: "text", text: p.sessionKey === savedSession ? "Saved fixture answer" : "Previous fixture answer" }] },
      ], ...(state.busyHistory ? { inFlightRun: { runId: "existing-fixture-run", text: "Existing task is working" }, sessionInfo: { hasActiveRun: true } } : {}) });
      if (frame.method === "chat.send") {
        const runId = randomUUID(), run = { runId, sessionKey: p.sessionKey, agentId: "main", lateAbort: p.message === "Finish before Stop responds" };
        assert.equal(typeof p.idempotencyKey, "string"); assert(p.idempotencyKey.length > 10);
        runs.set(runId, run); reply({ runId });
        later(() => event("chat", { runId, sessionKey: run.sessionKey, agentId: run.agentId, state: "delta", message: { content: [{ type: "text", text: "Fixture agent partial reply" }] } }), 60);
        if (pendingLateAbortReply) {
          const lateReply = pendingLateAbortReply; pendingLateAbortReply = null;
          later(() => {
            lateReply();
            event("agent", { runId, stream: "tool", data: { name: "fixtureAfterAbort", phase: "update" } });
          }, 120);
        }
        if (p.message !== "Keep working" && !run.lateAbort) run.timer = later(() => {
          event("chat", { runId, sessionKey: run.sessionKey, agentId: run.agentId, state: "final", message: { content: [{ type: "text", text: `Fixture agent complete ${bootstrapToken} ${deviceToken}` }] } }); runs.delete(runId);
        }, 650);
        return;
      }
      if (frame.method === "chat.abort") {
        const run = runs.get(p.runId); assert(run, "Stop must target the accepted run"); assert.equal(p.sessionKey, run.sessionKey);
        clearTimeout(run.timer); timers.delete(run.timer); runs.delete(p.runId);
        if (run.lateAbort) {
          event("chat", { runId: run.runId, sessionKey: run.sessionKey, agentId: run.agentId, state: "final", message: { content: "Task finished before its Stop response" } });
          pendingLateAbortReply = () => reply({ aborted: true });
          return;
        }
        reply({ aborted: true }); return event("chat", { runId: run.runId, sessionKey: run.sessionKey, agentId: run.agentId, state: "aborted" });
      }
      throw new Error(`Unexpected Gateway method: ${frame.method}`);
    } catch (error) {
      state.errors.push(error);
      send({ type: "res", id: frame?.id, ok: false, error: { code: "FIXTURE", message: "Fixture assertion failed" } });
    }
  });
});

let browser;
const passes = [], errors = [];
const pass = label => { passes.push(label); console.log("PASS:", label); };
const count = kind => state.events.filter(event => event.kind === kind).length;
const waitStatus = (page, text) => page.waitForFunction(text => document.querySelector("#status").textContent.includes(text)
  && (text !== "Answer complete" || !document.querySelector("#send").disabled), text);
const openSetup = async page => { if (!(await page.locator("#setupPanel").isVisible())) await page.locator("#setupToggle").click(); };
const closeSetup = async page => { if (await page.locator("#setupPanel").isVisible()) await page.locator("#closeSetup").click(); };
// Observe completion of actual async UI handlers so races need no arbitrary sleep.
const observeHandler = (page, id, property) => page.evaluate(({ id, property }) => {
  const node = document.getElementById(id), original = node[property];
  window.__fixtureHandlers ||= {};
  node[property] = function (...args) {
    return window.__fixtureHandlers[id] = Promise.resolve(original.apply(this, args));
  };
}, { id, property });
const handlerDone = (page, id) => page.evaluate(id => window.__fixtureHandlers[id], id);
const memoryArchive = page => page.evaluate(async () => {
  const { LocalMemory } = await import("/local-memory.js");
  const store = new LocalMemory(); await store.init();
  try { return await store.exportData(); } finally { store.close(); }
});
const openMemory = async page => {
  await closeSetup(page); await page.locator("#navMemory").click();
  await page.waitForFunction(() => document.querySelector("#memoryStorage").textContent.includes("saved items"));
};
const installVisualViewportFixture = () => {
  const viewport = window.visualViewport, prototype = Object.getPrototypeOf(viewport);
  let values = {};
  for (const key of ["height", "offsetTop", "offsetLeft"]) {
    const getter = Object.getOwnPropertyDescriptor(prototype, key).get;
    Object.defineProperty(viewport, key, { configurable: true, get: () => values[key] ?? getter.call(viewport) });
  }
  window.__fixtureVisualViewport = (next, event = "resize") => {
    values = next === null ? {} : { ...values, ...next };
    viewport.dispatchEvent(new Event(event));
  };
};
const visualViewport = async (page, values, event = "resize") => {
  await page.evaluate(({ values, event }) => window.__fixtureVisualViewport(values, event), { values, event });
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
};
const composerBounds = page => page.evaluate(() => ({
  innerHeight, innerWidth, top: window.visualViewport.offsetTop, bottom: window.visualViewport.offsetTop + window.visualViewport.height,
  panel: (() => { const rect = document.getElementById("chatPanel").getBoundingClientRect(); return { top: rect.top, bottom: rect.bottom }; })(),
  elements: Object.fromEntries(["form", "prompt", "send"].map(id => {
    const node = document.getElementById(id), rect = node.getBoundingClientRect();
    return [id, { top: rect.top, bottom: rect.bottom, left: rect.left, right: rect.right, height: rect.height,
      clientHeight: node.clientHeight, scrollHeight: node.scrollHeight, scrollTop: node.scrollTop,
      maxHeight: getComputedStyle(node).maxHeight, overflowY: getComputedStyle(node).overflowY }];
  })),
}));
const assertComposerVisible = async (page, label) => {
  const bounds = await composerBounds(page);
  for (const [id, rect] of Object.entries(bounds.elements)) {
    assert(rect.top >= bounds.top - 1 && rect.bottom <= bounds.bottom + 1,
      `${label}: ${id} ${JSON.stringify(rect)} must fit visible [${bounds.top}, ${bounds.bottom}]`);
    assert(rect.left >= -1 && rect.right <= bounds.innerWidth + 1, `${label}: ${id} must fit horizontally`);
  }
  assert(bounds.elements.form.top >= bounds.panel.top - 1 && bounds.elements.form.bottom <= bounds.panel.bottom + 1,
    `${label}: the chat panel must not clip its composer`);
  for (const id of ["prompt", "send"]) assert(await page.locator(`#${id}`).evaluate(node => {
    const rect = node.getBoundingClientRect(), hit = document.elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2);
    return hit === node || node.contains(hit);
  }), `${label}: ${id} must be reachable, not clipped by another container`);
  return bounds;
};
const connect = async page => {
  await openSetup(page);
  await page.locator("#gatewayUrl").fill(base.replace("http:", "ws:"));
  await page.locator("#gatewayToken").fill(bootstrapToken);
  await page.locator("#connectGateway").click();
  await waitStatus(page, "Gateway history loaded");
  assert.equal(await page.locator("#gatewayToken").inputValue(), "");
  await closeSetup(page);
};
async function context(options = {}) {
  const context = await browser.newContext(options);
  await context.route("**/*", route => {
    const url = route.request().url();
    if (url.startsWith(base + "/")) return route.continue();
    if (url.startsWith("https://github.com/openclaw/") && url.includes("/releases/download/")) {
      state.downloads.push(url); return route.fulfill({ status: 204, body: "" });
    }
    state.unexpectedExternal.push(url); return route.abort();
  });
  context.on("page", page => page.on("pageerror", error => errors.push(error.message)));
  return context;
}

try {
  browser = await chromium.launch({ headless: true, args: ["--no-sandbox"], ...(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {}) });
  const desktop = await context({ viewport: { width: 1440, height: 1000 } });
  await desktop.addInitScript(() => Object.defineProperty(navigator, "userAgentData", { configurable: true,
    value: { platform: "Windows", mobile: false, getHighEntropyValues: async () => ({ platform: "Windows", architecture: "x86", bitness: "64" }) } }));
  const page = await desktop.newPage();
  let consent = false; page.on("dialog", dialog => consent ? dialog.accept() : dialog.dismiss());
  await page.goto(base);
  await page.waitForFunction(() => !document.querySelector("#start").disabled && document.querySelector("#downloadOpenClaw").textContent.startsWith("Download"));
  for (const [id, property] of [["heroForm", "onsubmit"], ["connectGateway", "onclick"], ["newChat", "onclick"]]) await observeHandler(page, id, property);
  assert.equal(await page.locator("#taskMode").inputValue(), "local");
  assert.equal(count("load"), 0); assert.equal(state.downloads.length, 0);
  assert(await page.locator("#homePanel").isVisible());
  assert(await page.locator("#chatPanel").isVisible());
  assert(await page.locator("#setupPanel").isHidden());
  assert.equal(await page.locator("#navHome").getAttribute("aria-current"), "page");
  assert.match(await page.locator("#cardModelName").innerText(), /not loaded/i);
  assert.match(await page.locator("#cardSpeed").innerText(), /not measured|—/i);
  assert.match(await page.locator("#systemGateway").innerText(), /not connected|disconnected/i);
  await page.screenshot({ path: "/tmp/browser-llm-cypher-home-desktop.png" });
  pass("Initial desktop page selects local chat without loading weights or downloading OpenClaw");

  await page.locator("#openLocal").click();
  assert(await page.locator("#setupPanel").isVisible());
  assert(await page.locator("#closeSetup").evaluate(node => node === document.activeElement));
  assert(await page.locator("#homePanel").evaluate(node => node.inert));
  assert(await page.locator("#chatPanel").evaluate(node => node.inert));
  await page.keyboard.press("Shift+Tab");
  assert(await page.locator("#setupPanel").evaluate(node => node.contains(document.activeElement)));
  assert(!(await page.locator("#closeSetup").evaluate(node => node === document.activeElement)));
  await page.keyboard.press("Tab");
  assert(await page.locator("#closeSetup").evaluate(node => node === document.activeElement));
  assert.equal(await page.locator("#modelPanel").getAttribute("open"), "");
  await closeSetup(page); await page.locator("#navHome").click();
  await page.locator("#openAgent").click();
  assert(await page.locator("#setupPanel").isVisible());
  assert.equal(await page.locator("#gatewayPanel").getAttribute("open"), "");
  assert.equal(state.requests.length, 0);
  await closeSetup(page); await page.locator("#navHome").click();
  await page.locator("#openPrivacy").click();
  assert(await page.locator("#setupPanel").isVisible());
  assert.equal(await page.locator("#privacyPanel").getAttribute("open"), "");
  assert.match(await page.locator("#privacyPanel").innerText(), /search terms|Search terms/);
  await page.keyboard.press("Escape");
  assert(await page.locator("#setupPanel").isHidden());
  assert(await page.locator("#openPrivacy").evaluate(node => node === document.activeElement));
  await page.locator("#openResearch").click();
  assert.equal(await page.locator("#taskMode").inputValue(), "web");
  assert(await page.locator("#setupPanel").isVisible());
  assert.equal(count("search"), 0);
  await closeSetup(page); await page.locator("#navHome").click();
  pass("Home cards open the appropriate model, agent, and data-handling controls without starting work");

  await page.locator("#heroMode").selectOption("local");
  await page.locator("#heroInput").fill("Keep this private idea as a draft");
  await page.locator("#heroInput").press("Enter");
  assert.equal(await page.locator("#prompt").inputValue(), "Keep this private idea as a draft");
  assert.equal(await page.locator("#taskMode").inputValue(), "local");
  assert(await page.locator("#setupPanel").isVisible());
  assert.equal(count("load"), 0); assert.equal(count("generate"), 0); assert.equal(count("search"), 0);
  await closeSetup(page); await page.locator("#navHome").click();
  assert(await page.locator("#homePanel").isVisible());
  await page.keyboard.press("Control+k");
  assert(await page.locator("#omniInput").evaluate(node => node === document.activeElement));
  await page.locator("#omniInput").fill("javascript:alert('do not execute')");
  await page.locator("#omniInput").press("Enter");
  assert.equal(await desktop.pages().length, 1); assert.equal(count("search"), 0);
  const popupPromise = desktop.waitForEvent("page");
  await page.locator("#omniInput").fill(`${base}/?from=omnisearch`);
  await page.locator("#omniInput").press("Enter");
  const popup = await popupPromise;
  await popup.waitForURL(`${base}/?from=omnisearch`);
  assert.equal(await popup.evaluate(() => window.opener), null);
  await popup.close();
  pass("Questions wait for missing-model setup; keyboard search opens safe URLs without executing script URLs");

  await openSetup(page);
  await page.locator("#start").click(); await waitStatus(page, "Cancelled");
  assert(await page.locator("#setupStatus").isVisible());
  assert.match(await page.locator("#setupStatus").innerText(), /Cancelled/);
  assert.equal(count("load"), 0); assert.equal(state.downloads.length, 0);
  pass("Cancelled startup consent requests neither model weights nor the native installer");
  consent = true;
  const recommendedDownload = await page.locator("#downloadOpenClaw").getAttribute("href");
  assert.match(recommendedDownload, /OpenClawCompanion-Setup-x64\.exe$/);
  await page.locator("#start").click();
  await page.waitForFunction(() => !document.querySelector("#send").disabled);
  assert.equal(count("load"), 1); assert.deepEqual(state.downloads, [recommendedDownload]);
  assert.deepEqual(state.events.filter(event => event.kind === "generate").map(event => event.request.max_tokens), [8, 64, 64]);
  pass("Approved preparation requests the selected installer and one model, then benchmarks it");
  await closeSetup(page);
  await page.locator("#heroMode").selectOption("local");
  await page.locator("#heroInput").fill("Help organize my private notes");
  await page.locator("#heroInput").press("Enter");
  await waitStatus(page, "Answer complete");
  assert.match(await page.locator("#chat").innerText(), /Local fixture answer/); assert.equal(count("search"), 0);
  assert.equal(await page.locator("#chat .sources").count(), 0);
  pass("Submitting a ready local hero question uses the real Worker path without requesting web search");
  await page.locator("#navHome").click();
  const loadedId = state.events.find(event => event.kind === "load").id;
  assert.match(loadedId, new RegExp((await page.locator("#cardModelName").innerText()).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.match(await page.locator("#cardMemory").innerText(), /MB|MiB/);
  assert.match(await page.locator("#cardSpeed").innerText(), /\d+(?:\.\d+)?\s*(?:tok|token)/i);
  await page.locator("#omniInput").fill("Research a fixture topic");
  await page.locator("#omniInput").press("Enter");
  assert.equal(await page.locator("#taskMode").inputValue(), "web");
  assert.match(await page.locator("#privacyBadge").textContent(), /web|search/i);
  await waitStatus(page, "Answer complete"); assert.equal(count("search"), 1);
  assert.equal(state.events.find(event => event.kind === "search").body.q, "Research a fixture topic");
  pass("Homepage metrics reflect the loaded runtime and submitted omnisearch queries explicitly use web research");
  await page.locator("#chat .sources > summary").click();
  assert.equal(await page.locator("#chat .source a").getAttribute("href"), "https://example.com/fixture");
  assert.match(await page.locator("#chat").innerText(), /Fixture evidence answer \[1\]/);
  pass("Explicit web research retrieves fixture evidence and renders its source link");
  await connect(page); assert.equal(state.proofCount, 1);
  assert.match(await page.locator("#chat").innerText(), /Previous fixture answer/);
  await page.locator("#prompt").fill("Complete a fixture task"); await page.locator("#send").click();
  await page.waitForFunction(() => document.querySelector("#chat").textContent.includes("Fixture agent partial reply"));
  assert(await page.locator("#stop").isVisible());
  await waitStatus(page, "OpenClaw task complete");
  assert.match(await page.locator("#chat").innerText(), /Fixture agent complete \[redacted\] \[redacted\]/);
  assert.equal(state.requests.find(request => request.method === "chat.send").params.agentId, "main");
  pass("Real browser Ed25519 proof authenticates the simulated protocol 4 Gateway and streams an agent reply");
  await page.locator("#prompt").fill("Keep working"); await page.locator("#send").click();
  await page.waitForFunction(() => !document.querySelector("#stop").hidden && !document.querySelector("#stop").disabled);
  await page.locator("#stop").click(); await waitStatus(page, "Stopped by OpenClaw");
  assert.equal(state.requests.filter(request => request.method === "chat.abort").length, 1);
  await page.locator("#sessionList .session-item").filter({ hasText: "Saved fixture session" }).click();
  await waitStatus(page, "Gateway history loaded"); assert.match(await page.locator("#chat").innerText(), /Saved fixture answer/);
  assert(!(await page.locator("#chat").innerText()).includes("Previous fixture answer"));
  pass("Stop targets the accepted run and session selection loads the selected Gateway history");
  await page.locator("#prompt").fill("Finish before Stop responds"); await page.locator("#send").click();
  await page.waitForFunction(() => !document.querySelector("#stop").hidden && !document.querySelector("#stop").disabled);
  await page.locator("#stop").click(); await waitStatus(page, "OpenClaw task complete");
  await page.locator("#prompt").fill("Keep working"); await page.locator("#send").click();
  await waitStatus(page, "fixtureAfterAbort");
  assert(await page.locator("#send").isDisabled()); assert(!(await page.locator("#stop").isDisabled()));
  await page.locator("#stop").click(); await waitStatus(page, "Stopped by OpenClaw");
  pass("A late Stop response for a finished task cannot cancel the next active task");
  await openSetup(page); await page.locator("#disconnectGateway").click();
  state.busyHistory = true;
  const sentBeforeReconnect = state.requests.filter(request => request.method === "chat.send").length;
  await page.locator("#connectGateway").click(); await waitStatus(page, "A task is already running");
  assert.equal(state.proofCount, 2);
  const connects = state.requests.filter(request => request.method === "connect");
  assert.equal(connects[0].params.device.id, connects[1].params.device.id, "Reconnect must reuse the real IndexedDB device identity");
  assert.equal(connects[1].params.auth.deviceToken, deviceToken);
  assert(await page.locator("#send").isDisabled());
  assert.match(await page.locator("#chat").innerText(), /Existing task is working/);
  assert.equal(state.requests.filter(request => request.method === "chat.send").length, sentBeforeReconnect);
  state.busyHistory = false; await page.locator("#refreshSessions").click(); await waitStatus(page, "Gateway history loaded");
  assert(!(await page.locator("#send").isDisabled()));
  pass("Reconnect reuses device credentials and blocks duplicate sends until existing task history settles");
  assert(!(await page.locator("body").innerText()).includes(bootstrapToken));
  assert(!(await page.locator("body").innerText()).includes(deviceToken));
  assert(!(await page.content()).includes(bootstrapToken));
  pass("Gateway credentials are cleared from the input and redacted from rendered replies");

  const taskRequests = () => [count("search"), count("generate"), state.requests.filter(request => request.method === "chat.send").length];
  const requestsBeforeNavigation = taskRequests();
  await closeSetup(page); await page.locator("#navHome").click();
  await page.locator("#heroMode").selectOption("agent");
  await page.locator("#heroInput").fill("Agent-only draft that must never become a web search");
  const deferredAgent = holdNextReply("chat.history");
  await page.locator("#heroInput").press("Enter");
  const releaseAgent = await deferredAgent;
  await page.locator("#tabWeb").click();
  await page.locator("#prompt").fill("My newer web draft");
  releaseAgent(); await handlerDone(page, "heroForm");
  assert.equal(await page.locator("#taskMode").inputValue(), "web");
  assert.equal(await page.locator("#prompt").inputValue(), "My newer web draft");
  assert.deepEqual(taskRequests(), requestsBeforeNavigation);
  await page.locator("#navWeb").click();
  assert(await page.locator("#homePanel").isHidden());
  await page.locator("#tabLocal").click();
  assert(await page.locator("#homePanel").isHidden());
  assert.equal(await page.locator("#taskMode").inputValue(), "local");
  pass("A delayed Agent draft cannot submit through a newer Web selection, and tabs preserve full conversation view");

  await page.locator("#navHome").click();
  await page.locator("#heroMode").selectOption("agent");
  await page.locator("#heroInput").fill("Abandoned agent question after returning home");
  const deferredHome = holdNextReply("chat.history");
  await page.locator("#heroInput").press("Enter");
  const releaseHome = await deferredHome;
  await page.locator("#navHome").click();
  releaseHome(); await handlerDone(page, "heroForm");
  assert(await page.locator("#homePanel").isVisible());
  assert.equal(await page.locator("#navHome").getAttribute("aria-current"), "page");
  assert.equal(await page.locator("#prompt").inputValue(), "My newer web draft");
  assert.deepEqual(taskRequests(), requestsBeforeNavigation);
  pass("Returning Home while Agent history is loading cancels the pending question submission");

  const deferredNewChat = holdNextReply("chat.history");
  await page.locator("#newChat").click();
  const releaseNewChat = await deferredNewChat;
  await page.locator("#navWeb").click();
  await page.locator("#prompt").fill("A later draft after leaving the new agent conversation");
  await page.locator("#navHome").click();
  releaseNewChat(); await handlerDone(page, "newChat");
  assert.equal(await page.locator("#taskMode").inputValue(), "web");
  assert.equal(await page.locator("#navHome").getAttribute("aria-current"), "page");
  assert(await page.locator("#homePanel").isVisible());
  assert.equal(await page.locator("#prompt").inputValue(), "A later draft after leaving the new agent conversation");
  assert.deepEqual(taskRequests(), requestsBeforeNavigation);
  pass("A delayed new-agent conversation cannot override a newer Web draft or Home navigation");

  await openSetup(page); await page.locator("#disconnectGateway").click();
  const deferredConnectionHistory = holdNextReply("chat.history");
  await page.locator("#connectGateway").click();
  const releaseConnectionHistory = await deferredConnectionHistory;
  await closeSetup(page); await page.locator("#navWeb").click();
  await page.locator("#prompt").fill("Keep this newer web draft after connection history");
  await page.locator("#navHome").click();
  releaseConnectionHistory(); await handlerDone(page, "connectGateway");
  assert.equal(await page.locator("#taskMode").inputValue(), "web");
  assert.equal(await page.locator("#prompt").inputValue(), "Keep this newer web draft after connection history");
  assert.equal(await page.locator("#navHome").getAttribute("aria-current"), "page");
  assert(!(await page.locator("body").getAttribute("class") || "").includes("chat-open"));
  assert.deepEqual(taskRequests(), requestsBeforeNavigation);
  pass("Gateway connection history completing late preserves the user's newer mode and Home view");

  await openSetup(page); await page.locator("#disconnectGateway").click();
  const deferredHello = holdNextReply("connect");
  await page.locator("#connectGateway").click();
  const releaseHello = await deferredHello;
  await closeSetup(page); await page.locator("#navChat").click();
  await page.locator("#prompt").fill("Local draft chosen while connecting");
  await page.locator("#navHome").click();
  releaseHello(); await handlerDone(page, "connectGateway");
  assert.equal(await page.locator("#taskMode").inputValue(), "local");
  assert.equal(await page.locator("#prompt").inputValue(), "Local draft chosen while connecting");
  assert.equal(await page.locator("#navHome").getAttribute("aria-current"), "page");
  assert.match(await page.locator("#gatewayBadge").innerText(), /connected/);
  assert.deepEqual(taskRequests(), requestsBeforeNavigation);
  pass("A late authenticated Gateway connection preserves a Local mode selected while it was connecting");
  await openSetup(page); await page.screenshot({ path: "/tmp/browser-llm-workspace-desktop.png" });

  state.noGPU = true;
  const noGPU = await context({ viewport: { width: 1200, height: 900 } }), agentPage = await noGPU.newPage();
  await agentPage.goto(base); await waitStatus(agentPage, "Browser inference is unavailable");
  assert(await agentPage.locator("#start").isDisabled());
  await connect(agentPage); assert(!(await agentPage.locator("#send").isDisabled()));
  await agentPage.locator("#prompt").fill("Complete without GPU"); await agentPage.locator("#send").click();
  await waitStatus(agentPage, "OpenClaw task complete"); assert.equal(count("load"), 1);
  pass("Gateway agent chat works when browser WebGPU inference is unavailable");
  state.noGPU = false;

  for (const [name, userAgent, store] of [
    ["iPhone", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1", "https://apps.apple.com/"],
    ["Android", "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 Chrome/140.0.0.0 Mobile Safari/537.36", "https://play.google.com/"],
  ]) {
    const mobile = await context({ viewport: { width: 390, height: 844 }, userAgent, isMobile: true, hasTouch: true });
    await mobile.addInitScript(() => Object.defineProperty(navigator, "userAgentData", { configurable: true, value: undefined }));
    await mobile.addInitScript(installVisualViewportFixture);
    const phone = await mobile.newPage(); await phone.goto(base);
    await phone.waitForFunction(() => document.querySelector("#mobileGatewayHelp").hidden === false);
    assert(await phone.locator("#homePanel").isVisible());
    assert(await phone.locator("#chatPanel").isHidden());
    assert(await phone.locator("#setupPanel").isHidden());
    await openSetup(phone);
    assert((await phone.locator("#downloadOpenClaw").getAttribute("href")).startsWith(store));
    assert(await phone.locator("#includeOpenClaw").isDisabled()); assert(!(await phone.locator("#includeOpenClaw").isChecked()));
    assert.equal(await phone.locator("#gatewayUrl").inputValue(), "");
    assert.match(await phone.locator("#mobileGatewayHelp").innerText(), /WSS.*PC/);
    assert(await phone.locator("#desktopInstallChoices").isHidden());
    assert(await phone.evaluate(() => document.documentElement.scrollWidth === innerWidth));
    await phone.evaluate(() => {
      document.querySelector("#modelPanel").open = false;
      const panel = document.querySelector("#setupPanel"), link = document.querySelector("#downloadOpenClaw");
      panel.scrollTop += link.getBoundingClientRect().top - panel.getBoundingClientRect().top - 130;
    });
    await phone.screenshot({ path: `/tmp/browser-llm-workspace-${name.toLowerCase()}-setup.png` });
    await closeSetup(phone); assert(await phone.locator("#homePanel").isVisible());
    await phone.locator("#openAssistant").click();
    assert(await phone.locator("#chatPanel").isVisible());
    assert(await phone.locator("#emptyState").isVisible());
    assert(await phone.locator("#homePanel").isHidden());
    assert.equal(await phone.locator("#navChat").getAttribute("aria-current"), "page");
    assert(await phone.evaluate(() => document.documentElement.scrollWidth === innerWidth));
    assert(await phone.locator("#prompt").evaluate(node => parseFloat(getComputedStyle(node).fontSize) >= 16));
    await phone.setViewportSize({ width: 390, height: 500 });
    await phone.waitForFunction(() => parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--chat-viewport")) <= 500);
    assert(await phone.locator("#send").evaluate(node => node.getBoundingClientRect().bottom <= visualViewport.height + 1));
    await openSetup(phone);
    assert(await phone.locator("#setupPanel").evaluate(node => node.getBoundingClientRect().bottom <= visualViewport.height + 1));
    await closeSetup(phone);
    await phone.setViewportSize({ width: 390, height: 844 });
    await phone.waitForFunction(() => parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--chat-viewport")) >= 840);
    assert(await phone.locator("#sidebar").evaluate(node => node.inert && node.getAttribute("aria-hidden") === "true"));
    await phone.locator("#sidebarToggle").click(); assert(await phone.locator("#sidebar").isVisible());
    assert(await phone.locator("#sidebar").evaluate(node => !node.inert && node.getAttribute("aria-hidden") === "false"));
    await phone.locator("#navHome").click(); assert(!(await phone.locator("body").getAttribute("class") || "").includes("sidebar-open"));
    assert(await phone.locator("#homePanel").isVisible());
    assert(await phone.locator("#chatPanel").isHidden());
    assert.equal(await phone.locator("#navHome").getAttribute("aria-current"), "page");
    await phone.waitForFunction(() => document.querySelector("#sidebar").getBoundingClientRect().right <= 0);
    assert(await phone.locator("#sidebar").evaluate(node => node.inert));
    await phone.locator("#sidebarToggle").click();
    await phone.waitForFunction(() => document.querySelector("#sidebar").getBoundingClientRect().left >= 0);
    await phone.mouse.click(375, 300);
    await phone.waitForFunction(() => document.querySelector("#sidebar").getBoundingClientRect().right <= 0);
    assert(await phone.locator("#sidebar").evaluate(node => node.inert));
    assert(await phone.evaluate(() => document.documentElement.scrollWidth === innerWidth));
    await phone.screenshot({ path: `/tmp/browser-llm-workspace-${name.toLowerCase()}.png` });
    pass(`${name} offers its official companion store, explains remote WSS, and navigates home/assistant without overflow at 390px`);

    // A phone keyboard shrinks/pans the visual viewport while the layout viewport stays tall.
    // Load only the fixture engine so the real textarea can receive text and composition events.
    phone.on("dialog", dialog => dialog.accept());
    await openSetup(phone);
    await phone.locator("#modelPanel").evaluate(node => { node.open = true; });
    await phone.locator("#start").click();
    await phone.waitForFunction(() => !document.querySelector("#prompt").disabled);
    await closeSetup(phone);
    const inferenceBeforeDraft = count("generate"), searchesBeforeDraft = count("search");
    await phone.locator("#prompt").fill("短い質問です。");
    await visualViewport(phone, { height: 300, offsetTop: 80, offsetLeft: 0 });
    const shortBounds = await assertComposerVisible(phone, `${name} short keyboard draft`);
    assert.equal(shortBounds.innerHeight, 844, "Keyboard fixture must not shrink the layout viewport");
    const japaneseDraft = Array.from({ length: 12 }, (_, i) => `${i + 1}行目：この質問の続きを日本語で入力しています。`).join("\n");
    assert(japaneseDraft.length < 380);
    await phone.locator("#prompt").fill(japaneseDraft);
    await phone.evaluate(() => new Promise(resolve => requestAnimationFrame(resolve)));
    const longBounds = await assertComposerVisible(phone, `${name} long Japanese keyboard draft`);
    assert(longBounds.elements.prompt.height > shortBounds.elements.prompt.height, "Textarea must grow for multiline text");
    assert(longBounds.elements.prompt.height <= parseFloat(longBounds.elements.prompt.maxHeight) + 1, "Textarea growth must remain bounded");
    assert(longBounds.elements.prompt.scrollHeight > longBounds.elements.prompt.clientHeight, "Overflowing draft needs internal scrolling");
    assert.match(longBounds.elements.prompt.overflowY, /auto|scroll/);
    await phone.locator("#prompt").evaluate(node => { node.scrollTop = node.scrollHeight; });
    assert(await phone.locator("#prompt").evaluate(node => node.scrollTop > 0));
    assert.equal(await phone.locator("#prompt").inputValue(), japaneseDraft);

    const composedDraft = await phone.locator("#prompt").evaluate(node => {
      node.setSelectionRange(node.value.length, node.value.length);
      node.dispatchEvent(new CompositionEvent("compositionstart", { bubbles: true, data: "" }));
      node.setRangeText("日本語変換中", node.selectionStart, node.selectionEnd, "end");
      node.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertCompositionText", data: "日本語変換中", isComposing: true }));
      node.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true, cancelable: true, key: "Enter", ctrlKey: true, isComposing: true }));
      node.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true, cancelable: true, key: "Enter", ctrlKey: true, isComposing: false }));
      node.dispatchEvent(new CompositionEvent("compositionend", { bubbles: true, data: "日本語変換中" }));
      node.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: "日本語変換中", isComposing: false }));
      return node.value;
    });
    assert.equal(composedDraft, japaneseDraft + "日本語変換中");
    await visualViewport(phone, { height: 360, offsetTop: 140 });
    await assertComposerVisible(phone, `${name} keyboard resize and pan`);
    await phone.locator("#prompt").evaluate(node => node.setSelectionRange(15, 15));
    await visualViewport(phone, { offsetTop: 95 }, "scroll");
    await assertComposerVisible(phone, `${name} offset-only viewport scroll`);
    assert.equal(await phone.locator("#prompt").evaluate(node => node.selectionStart), 15);
    assert.equal(await phone.locator("#prompt").inputValue(), composedDraft);
    assert.equal(count("generate"), inferenceBeforeDraft, "IME Enter must not submit an unfinished draft");
    assert.equal(count("search"), searchesBeforeDraft);
    await visualViewport(phone, { height: 300, offsetTop: 80 });
    await phone.screenshot({ path: `/tmp/browser-llm-keyboard-${name.toLowerCase()}.png`, clip: { x: 0, y: 80, width: 390, height: 300 } });

    await phone.setViewportSize({ width: 844, height: 390 });
    await visualViewport(phone, { height: 230, offsetTop: 80 });
    await assertComposerVisible(phone, `${name} landscape keyboard`);
    assert(await phone.locator("#prompt").evaluate(node => parseFloat(getComputedStyle(node).fontSize) >= 16));
    assert.equal(await phone.locator("#prompt").inputValue(), composedDraft);
    await visualViewport(phone, { height: 180, offsetTop: 80 });
    await assertComposerVisible(phone, `${name} short landscape keyboard`);
    assert.equal(await phone.locator("#prompt").inputValue(), composedDraft);
    await phone.locator("#prompt").evaluate(node => node.blur());
    await visualViewport(phone, null);
    await phone.setViewportSize({ width: 390, height: 844 });
    await visualViewport(phone, null);
    assert(await phone.locator("#workspaceHeader").isVisible());
    assert(await phone.locator("#closeAssistant").isVisible());
    assert.equal(await phone.locator("#prompt").inputValue(), composedDraft);
    assert(!(await phone.locator("body").getAttribute("class") || "").includes("composer-focused"));
    assert(await phone.evaluate(() => document.documentElement.scrollWidth === innerWidth));

    await phone.locator("#prompt").focus();
    await visualViewport(phone, { height: 300, offsetTop: 80 });
    await phone.locator("#taskMode").focus();
    await phone.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    assert(await phone.locator("body").evaluate(node => node.classList.contains("composer-focused")), "Mode focus must retain the compact composer");
    await assertComposerVisible(phone, `${name} mode selector focus`);
    await phone.keyboard.press("Control+k");
    assert(await phone.locator("#omniInput").evaluate(node => node === document.activeElement));
    assert(await phone.locator("#workspaceHeader").isVisible());
    assert(!(await phone.locator("body").getAttribute("class") || "").includes("composer-focused"));
    assert.equal(await phone.locator("#prompt").inputValue(), composedDraft);
    await phone.locator("#prompt").focus();
    await visualViewport(phone, { height: 300, offsetTop: 80 });
    const sendBefore = await phone.locator("#send").boundingBox();
    const sendPoint = { x: sendBefore.x + sendBefore.width / 2, y: sendBefore.y + sendBefore.height / 2 };
    await phone.mouse.move(sendPoint.x, sendPoint.y);
    await phone.mouse.down();
    await phone.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    assert(await phone.locator("#send").evaluate(node => node === document.activeElement));
    assert(await phone.locator("body").evaluate(node => node.classList.contains("composer-focused")), "Send focus must retain the compact composer until pointer up");
    const sendAfter = await phone.locator("#send").boundingBox();
    assert(Math.abs(sendAfter.x - sendBefore.x) <= 1 && Math.abs(sendAfter.y - sendBefore.y) <= 1, "Send must not jump away between pointer down and up");
    await phone.mouse.up();
    await waitStatus(phone, "Answer complete");
    assert.equal(count("generate"), inferenceBeforeDraft + 1, "One click must submit exactly once");
    assert.equal(state.events.filter(event => event.kind === "generate").at(-1).request.messages.at(-1).content, composedDraft);
    assert.equal(count("search"), searchesBeforeDraft);
    pass(`${name} keeps Japanese/IME drafts visible through keyboard resize, pan, rotation and blur, then sends once without a moving button`);
    await mobile.close();
  }
  const features = await context({ viewport: { width: 1440, height: 1000 } });
  const feature = await features.newPage();
  feature.on("dialog", dialog => dialog.accept());
  await feature.goto(base);
  await feature.waitForFunction(() => !document.querySelector("#start").disabled && document.querySelector("#memoryStorage").textContent.includes("saved items"));
  const prepareFeatureModel = async () => {
    await openSetup(feature);
    await feature.locator("#modelPanel").evaluate(node => { node.open = true; });
    if (await feature.locator("#includeOpenClaw").isEnabled()) await feature.locator("#includeOpenClaw").uncheck();
    await feature.locator("#start").click();
    await feature.waitForFunction(() => !document.querySelector("#send").disabled);
    await closeSetup(feature);
  };
  const featureSend = async text => {
    await closeSetup(feature);
    await feature.locator("#prompt").fill(text); await feature.locator("#send").click();
    await waitStatus(feature, "Answer complete");
  };
  await prepareFeatureModel();
  assert.equal(await feature.locator("#chatSearchPolicy").inputValue(), "auto");
  const beforeAuto = count("search");
  await featureSend("WebGPUの最新情報を教えてください");
  assert.equal(count("search"), beforeAuto + 1);
  assert.equal(state.events.filter(event => event.kind === "search").at(-1).body.language, "ja");
  assert.match(await feature.locator("#chat .answer-route").last().textContent(), /Web search/);
  await feature.locator("#chatSearchPolicy").selectOption("off");
  await featureSend("今日のWebGPUのニュースを教えてください");
  assert.equal(count("search"), beforeAuto + 1, "Off must not search a fresh-information question");
  assert.match(await feature.locator("#chat .answer-route").last().textContent(), /no Web search/);
  pass("Auto searches a current Japanese question with language ja; Off prevents search and the answer identifies its route");

  await openMemory(feature);
  assert(await feature.locator("#memoryEnabled").isChecked());
  assert(!(await feature.locator("#memorySearchable").isChecked()));
  const marker = "cobalt-orchid-782";
  await feature.locator("#memoryText").fill(`My hiking preference is quiet forests. Recall marker ${marker}.`);
  await feature.locator("#saveMemory").click();
  await feature.waitForFunction(marker => document.querySelector("#memoryList").textContent.includes(marker) && !document.querySelector("#saveMemory").disabled, marker);
  const noteBefore = (await memoryArchive(feature)).records.find(record => record.kind === "note" && record.text.includes(marker));
  await feature.locator("#memoryList .memory-item").filter({ hasText: marker }).getByRole("button", { name: "Edit", exact: true }).click();
  await feature.locator("#memoryText").fill(`My hiking preference is quiet cedar forests. Recall marker ${marker}.`);
  await feature.locator("#saveMemory").click();
  await feature.waitForFunction(() => document.querySelector("#memoryList").textContent.includes("quiet cedar forests") && !document.querySelector("#saveMemory").disabled);
  const noteAfter = (await memoryArchive(feature)).records.find(record => record.kind === "note" && record.text.includes(marker));
  assert.equal(noteAfter.id, noteBefore.id); assert.equal(noteAfter.searchable, false);
  const savedQuestion = "Remember my hiking preference for our next conversation.";
  await featureSend(savedQuestion);
  const savedTurn = (await memoryArchive(feature)).records.find(record => record.kind === "turn" && record.user === savedQuestion);
  assert(savedTurn); assert.match(savedTurn.assistant, /Local fixture answer/);
  assert(!savedTurn.user.includes(marker), "Archive must keep the user's message separate from injected memory references");
  await feature.reload();
  await feature.waitForFunction(question => document.querySelector("#chat").textContent.includes(question) && !document.querySelector("#start").disabled, savedQuestion);
  assert.match(await feature.locator("#chat").textContent(), /Saved conversation/);
  assert.equal(await feature.locator("#chatSearchPolicy").inputValue(), "off");
  await prepareFeatureModel();
  assert((await feature.locator("#chat").textContent()).includes(savedQuestion), "Preparing a model must preserve the restored conversation");
  await featureSend("What do you remember about my hiking preference?");
  let latestRequest = state.events.filter(event => event.kind === "generate").at(-1).request;
  assert(JSON.stringify(latestRequest.messages).includes(marker));
  assert(await feature.locator("#chat .memory-used").count() > 0);
  assert.equal(count("search"), beforeAuto + 1, "Recall in Off mode must not send notes to search");
  pass("A note can be created and edited; saved user/assistant messages restore after reload and the note is recalled after model preparation");

  await openMemory(feature);
  await feature.locator("#memoryList .memory-item").filter({ hasText: marker }).getByRole("button", { name: "Delete", exact: true }).click();
  await feature.waitForFunction(marker => !document.querySelector("#memoryList").textContent.includes(marker) && !document.querySelector("#saveMemory").disabled, marker);
  assert(!(await memoryArchive(feature)).records.some(record => record.kind === "note" && record.text.includes(marker)));
  await featureSend("What do you remember about my hiking preference?");
  latestRequest = state.events.filter(event => event.kind === "generate").at(-1).request;
  assert(!JSON.stringify(latestRequest.messages).includes(marker), "Deleted note must leave both recall and working prompt context");
  await openMemory(feature);
  await feature.locator("#memoryText").fill(`My hiking preference has private marker ${marker}.`);
  await feature.locator("#saveMemory").click();
  await feature.waitForFunction(marker => document.querySelector("#memoryList").textContent.includes(marker) && !document.querySelector("#saveMemory").disabled, marker);
  await feature.locator("#memoryEnabled").uncheck();
  const beforeOff = await memoryArchive(feature);
  await featureSend("Remember my hiking preference, but do not save this test question.");
  latestRequest = state.events.filter(event => event.kind === "generate").at(-1).request;
  assert(!JSON.stringify(latestRequest.messages).includes(marker));
  assert.deepEqual(await memoryArchive(feature), beforeOff, "Memory Off must leave all stored records unchanged");
  await feature.reload();
  await feature.waitForFunction(() => document.querySelector("#memoryStorage").textContent.includes("saved items"));
  assert(!(await feature.locator("#memoryEnabled").isChecked()));
  assert(!(await feature.locator("#chat").textContent()).includes("do not save this test question"));
  assert.deepEqual(await memoryArchive(feature), beforeOff);
  pass("Deleting a note removes it from future prompts; Memory Off neither recalls nor saves and persists across reload");
  await features.close();
  assert.equal(state.downloads.length, 1, "Phones must not request native desktop installers");
  assert.deepEqual(state.unexpectedExternal, []); assert.deepEqual(state.errors, []); assert.deepEqual(errors, []);
  pass("No unexpected external requests or uncaught page/fixture errors");
  console.log(`${passes.length} rendered-browser scenarios passed. Limits: mocked WebLLM/GPU and simulated Gateway; no real model weights, native installation, tool execution or real OpenClaw server tested.`);
} finally {
  await browser?.close();
  for (const timer of timers) clearTimeout(timer);
  for (const socket of sockets) socket.terminate();
  await new Promise(resolve => wss.close(resolve));
  await new Promise(resolve => server.close(resolve));
}
