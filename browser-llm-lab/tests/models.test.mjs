import test from "node:test";
import assert from "node:assert/strict";
import {
  MODELS, CONTEXT, PROFILE_KEY, makeCatalog, resolveModel, compatibility, autoCandidates,
  readProfile, fingerprint, adaptMessages, generationOptions, splitAnswer,
  modelBaseURL, manifestBytes, errorDetails,
} from "../public/models.js";

// Synthetic metadata for policy tests. These are NOT real model memory measurements.
const device = { features: ["shader-f16"], maxBufferSize: 1e9, maxStorageBufferBindingSize: 1e9 };
const records = MODELS.flatMap((model, i) => model.variants.map(model_id => ({
  model_id, model: `https://huggingface.co/test/${model.key}`,
  model_lib: "https://example.invalid/test.wasm", vram_required_MB: 400 + i * 10,
  overrides: { context_window_size: CONTEXT },
})));
const catalog = makeCatalog(records, device);
const qwen = MODELS[0];
const deep = MODELS.find(model => model.key.startsWith("DeepSeek"));
const messages = [{ role: "system", content: "Follow instructions." }, { role: "user", content: "Explain this." }];

test("26 logical profiles and 51 unique, explicitly allowed variants", () => {
  assert.equal(MODELS.length, 26);
  assert.equal(new Set(MODELS.flatMap(model => model.variants)).size, 51);
  assert.ok(!MODELS.some(model => /DeepSeek.*1\.5B|Kimi/.test(model.key)));
});
test("f16 available: select f16 for each supported profile", () => {
  assert.equal(catalog.filter(model => !model.disabled).length, 26);
  assert.ok(catalog.every(model => model.modelId.includes("f16")));
});
test("f16 unavailable: select registered f32 or disable f16-only profile", () => {
  const list = makeCatalog(records, { ...device, features: [] });
  assert.equal(list.filter(model => model.disabled).length, 1);
  assert.ok(list.filter(model => !model.disabled).every(model => model.modelId.includes("f32")));
});
test("unregistered entries never become selectable", () => {
  assert.ok(makeCatalog([], device).every(model => model.disabled));
  assert.throws(() => resolveModel(qwen.variants[0], [], device), { code: "COMPATIBILITY" });
});
test("arbitrary model IDs are refused in the Worker policy", () => {
  assert.throws(() => resolveModel("unknown", records, device), { code: "MODEL" });
});
test("recorded feature requirements and buffer limits are enforced", () => {
  const record = { ...records[0], required_features: ["missing-feature"] };
  assert.match(compatibility(record, device), /Missing GPU feature/);
  assert.match(compatibility({ ...records[0], buffer_size_required_bytes: 2e9 }, device), /maxStorage/);
});
test("missing buffer metadata is explicitly unknown, not proof of sufficient memory", () => {
  assert.equal(catalog[0].bufferRequirementKnown, false);
});
test("1k variants are not silently overridden to 4k", () => {
  assert.match(compatibility({ ...records[0], overrides: { context_window_size: 1024 } }, device), /4096/);
});
test("Auto excludes experimental and unknown-memory profiles", () => {
  const altered = catalog.map((model, i) => i === 0 ? { ...model, vramMB: null } : model);
  const choices = autoCandidates(altered, { capMB: 2200 });
  assert.ok(choices.length > 0);
  assert.ok(choices.every(model => !model.experimental && model.vramMB !== null));
});
test("Auto respects the ceiling and target language", () => {
  assert.ok(autoCandidates(catalog, { capMB: 600, language: "ja" }).every(model => model.vramMB <= 600 && model.languages.includes("ja")));
  assert.ok(!autoCandidates(catalog, { capMB: 600, language: "ja" }).some(model => model.family === "SmolLM2"));
  assert.throws(() => autoCandidates(catalog, { capMB: 123 }), { code: "INPUT" });
});
test("saved passing measurements in the candidate pool take priority", () => {
  const result = autoCandidates(catalog, { capMB: 2200,
    saved: [{ modelId: catalog[0].modelId, score: 12, at: 100 }] });
  assert.equal(result[0].modelId, catalog[0].modelId);
});
test("interrupted / explicitly avoided model is not reselected by Auto", () => {
  assert.ok(!autoCandidates(catalog, { capMB: 2200, avoid: [catalog[0].modelId] })
    .some(model => model.modelId === catalog[0].modelId));
});
test("corrupt or unavailable local storage is nonfatal", () => {
  assert.deepEqual(readProfile(null, "key").results, []);
  assert.deepEqual(readProfile({ getItem: () => "{" }, "key").results, []);
});
test("profile changes and expired/future measurements are discarded", () => {
  const now = 31 * 86400000;
  const getItem = () => JSON.stringify({ fingerprint: "key", results: [
    { modelId: "old", score: 10, at: 0 },
    { modelId: "fresh", score: 10, at: now - 1000 },
    { modelId: "future", score: 10, at: now + 1000 },
  ] });
  assert.equal(readProfile({ getItem }, "key", now).results.length, 1);
  assert.equal(readProfile({ getItem }, "changed", now).results.length, 0);
});
test("fingerprint reacts to browser or adapter changes", () => {
  assert.notEqual(fingerprint(device, "A"), fingerprint(device, "B"));
  assert.notEqual(fingerprint(device, "A"), fingerprint({ ...device, features: [] }, "A"));
});
test("system text is folded for no-system profiles without mutating input", () => {
  const folded = adaptMessages(messages, deep);
  assert.equal(folded.length, 1);
  assert.equal(folded[0].role, "user");
  assert.match(folded[0].content, /Follow instructions/);
  assert.equal(messages.length, 2);
  assert.deepEqual(adaptMessages(messages, qwen), messages);
});
test("malformed roles, message order, and oversized input are refused", () => {
  for (const invalid of [[{ role: "tool", content: "X" }], [{ role: "assistant", content: "X" }],
    [{ role: "user", content: "X" }, { role: "user", content: "Y" }],
    [{ role: "user", content: "a".repeat(4000) }]]) {
    assert.throws(() => adaptMessages(invalid, qwen), { code: "INPUT" });
  }
});
test("DeepSeek generation has its own budget and sampling settings", () => {
  const options = generationOptions(deep);
  assert.equal(options.max_tokens, 1024);
  assert.equal(options.temperature, 0.6);
  assert.ok(!("extra_body" in options));
});
test("Qwen3 / Qwen3.5 non-thinking setting is explicit", () => {
  const options = generationOptions(MODELS.find(model => model.thinking === "off"));
  assert.deepEqual(options.extra_body, { enable_thinking: false });
  assert.equal(options.max_tokens, 256);
});
test("reasoning is separated from final answers and not mistaken for a completed answer", () => {
  assert.deepEqual(splitAnswer("<think>Draft</think>Answer [1]", deep), { reasoning: "Draft", text: "Answer [1]" });
  assert.deepEqual(splitAnswer("<think>Not done", deep), { reasoning: "Not done", text: "" });
  assert.deepEqual(splitAnswer("Draft</think>Answer", deep), { reasoning: "Draft", text: "Answer" });
  assert.equal(splitAnswer("<think>Literal markup", qwen).text, "<think>Literal markup");
});
test("HF URL normalization handles fixed revisions without discarding them", () => {
  assert.equal(modelBaseURL("https://huggingface.co/org/model"), "https://huggingface.co/org/model/resolve/main/");
  assert.equal(modelBaseURL("https://huggingface.co/org/model/resolve/abc/"), "https://huggingface.co/org/model/resolve/abc/");
  assert.throws(() => modelBaseURL("https://other.invalid/model"), { code: "MODEL" });
});
test("manifest sums shard bytes, not tensor subrecords or VRAM", () => {
  assert.equal(manifestBytes({ records: [{ dataPath: "a", nbytes: 10, records: [{ nbytes: 20 }] }, { dataPath: "b", nbytes: 30 }] }), 40);
  assert.equal(manifestBytes({ records: [{ dataPath: "a", nbytes: 10 }, { dataPath: "a", nbytes: 10 }] }), null);
  assert.equal(manifestBytes({ records: [{ dataPath: "a", nbytes: -1 }] }), null);
  assert.equal(manifestBytes({}), null);
});
test("network-like errors are never asserted to be out-of-memory", () => {
  assert.equal(errorDetails(new TypeError("Failed to fetch"), "load").code, "UNKNOWN");
  assert.equal(errorDetails(Object.assign(new Error("GPU lost"), { name: "DeviceLostError" }), "load").code, "GPU");
  assert.equal(errorDetails(Object.assign(new Error("Quota"), { name: "QuotaExceededError" }), "load").code, "STORAGE");
});
