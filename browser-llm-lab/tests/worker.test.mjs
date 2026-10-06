import test from "node:test";
import assert from "node:assert/strict";
import { createRuntime } from "../public/worker.js";
import { MODELS, CONTEXT } from "../public/models.js";

function setup({ importFailure = false, manifestFailure = false, features = ["shader-f16"] } = {}) {
  const events = [];
  const records = MODELS.flatMap(model => model.variants.map(model_id => ({ model_id,
    model: `https://huggingface.co/test/${model.key}`, model_lib: "test.wasm", vram_required_MB: 900,
    overrides: { context_window_size: CONTEXT, max_history_size: 1 },
  })));
  let clock = 0;
  class FakeEngine {
    constructor() { events.push(["construct"]); this.chat = { completions: { create: request => this.generate(request) } }; }
    async reload(...args) { events.push(["reload", ...args]); this.id = args[0]; }
    async unload() { events.push(["unload"]); }
    async resetChat() { events.push(["reset"]); }
    async generate(request) {
      events.push(["generate", request]);
      if (!request.stream) return { usage: { completion_tokens: request.max_tokens } };
      const text = this.id.startsWith("DeepSeek") ? "<think>Draft</think>Answer [1]." : "Answer [1].";
      return (async function* () {
        yield { choices: [{ delta: { content: text }, finish_reason: "stop" }] };
        yield { choices: [], usage: { completion_tokens: request.max_tokens, prompt_tokens: 99, extra: { decode_tokens_per_s: 20 } } };
      })();
    }
  }
  const runtime = createRuntime({
    loadLibrary: async () => {
      if (importFailure) throw new Error("Import unavailable");
      return { prebuiltAppConfig: { model_list: records }, MLCEngine: FakeEngine, hasModelInCache: async () => true };
    },
    readDevice: async () => ({ features, maxBufferSize: 1e9, maxStorageBufferBindingSize: 1e9 }),
    fetcher: async url => {
      events.push(["fetch", String(url)]);
      if (manifestFailure) throw new TypeError("Failed to fetch");
      return { ok: true, text: async () => JSON.stringify({ records: [{ dataPath: "shard", nbytes: 100 }] }) };
    },
    estimate: async () => ({ usage: 0, quota: 1000 }), now: () => (clock += 100),
  });
  return { runtime, events };
}
const qwen = MODELS[0].variants[0];
const deep = MODELS.find(model => model.key.startsWith("DeepSeek")).variants[0];
const messages = [{ role: "system", content: "Be accurate." }, { role: "user", content: "Explain." }];

test("probe only inspects capabilities and metadata; does not create an engine", async () => {
  const { runtime, events } = setup();
  const result = await runtime.dispatch("probe");
  assert.equal(result.catalog.length, 26);
  assert.equal(events.length, 0);
});
test("inspect fetches only the model manifest, not model weight shards", async () => {
  const { runtime, events } = setup();
  const result = await runtime.dispatch("inspect", { modelId: qwen });
  assert.equal(result.weightsBytes, 100);
  assert.equal(result.cached, true);
  assert.equal(events.length, 1);
  assert.match(events[0][1], /ndarray-cache.json$/);
});
test("unavailable size metadata is reported as unknown", async () => {
  const { runtime } = setup({ manifestFailure: true });
  const result = await runtime.dispatch("inspect", { modelId: qwen });
  assert.equal(result.weightsBytes, null);
});
test("runtime module fetch failure is classified as NETWORK", async () => {
  await assert.rejects(setup({ importFailure: true }).runtime.dispatch("probe"), { code: "NETWORK" });
});
test("load validates allowlist before creating engine", async () => {
  const { runtime, events } = setup();
  await assert.rejects(runtime.dispatch("load", { modelId: "other" }), { code: "MODEL" });
  assert.equal(events.length, 0);
});
test("load rechecks GPU compatibility, not just the UI decision", async () => {
  await assert.rejects(setup({ features: [] }).runtime.dispatch("load", { modelId: qwen }), { code: "COMPATIBILITY" });
});
test("load preserves registered runtime overrides", async () => {
  const { runtime, events } = setup();
  const result = await runtime.dispatch("load", { modelId: qwen });
  assert.equal(result.context, 4096);
  assert.deepEqual(events.find(event => event[0] === "reload"), ["reload", qwen]);
  await assert.rejects(runtime.dispatch("load", { modelId: qwen }), { code: "STATE" });
});
test("benchmark uses warmup and two longer reference-material requests", async () => {
  const { runtime, events } = setup();
  await runtime.dispatch("load", { modelId: qwen });
  const result = await runtime.dispatch("benchmark", { language: "ja" });
  assert.equal(result.tokens, 128);
  assert.equal(result.runs.length, 2);
  assert.equal(result.decode, 20);
  assert.ok(result.firstTokenMs > 0);
  const requests = events.filter(event => event[0] === "generate").map(event => event[1]);
  assert.deepEqual(requests.map(request => request.max_tokens), [8, 64, 64]);
  assert.match(requests[1].messages[0].content, /Japanese/);
});
test("chat streams text and returns usage", async () => {
  const { runtime } = setup();
  await runtime.dispatch("load", { modelId: qwen });
  const deltas = [];
  const result = await runtime.dispatch("chat", { messages, web: true }, (kind, value) => deltas.push([kind, value]));
  assert.equal(result.text, "Answer [1].");
  assert.equal(result.outputTokens, 256);
  assert.equal(deltas[0][0], "delta");
});
test("input errors do not unload a usable model", async () => {
  const { runtime } = setup();
  await runtime.dispatch("load", { modelId: qwen });
  await assert.rejects(runtime.dispatch("chat", { messages: [] }), { code: "INPUT" });
  assert.equal((await runtime.dispatch("health")).model, qwen);
});
test("DeepSeek system folding and reasoning separation", async () => {
  const { runtime, events } = setup();
  await runtime.dispatch("load", { modelId: deep });
  const result = await runtime.dispatch("chat", { messages, web: true });
  assert.equal(result.text, "Answer [1].");
  assert.equal(result.reasoning, "Draft");
  const request = events.find(event => event[0] === "generate")[1];
  assert.equal(request.messages[0].role, "user");
  assert.equal(request.max_tokens, 1024);
  assert.equal(request.temperature, 0.6);
});
test("unload clears state and permits a fresh load", async () => {
  const { runtime, events } = setup();
  await runtime.dispatch("load", { modelId: qwen });
  await runtime.dispatch("unload");
  await assert.rejects(runtime.dispatch("health"), { code: "NOT_LOADED" });
  await runtime.dispatch("load", { modelId: qwen });
  assert.equal(events.filter(event => event[0] === "construct").length, 2);
});
test("unknown operations are refused", async () => {
  await assert.rejects(setup().runtime.dispatch("unsafe-operation"), { code: "INPUT" });
});
