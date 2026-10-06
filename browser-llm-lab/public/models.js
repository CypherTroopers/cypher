// Application policy, not a hardware guarantee or a model quality ranking.
// ModelRecords (URLs, GPU requirements, overrides) come from the pinned runtime.
export const VERSION = "models-v1";
export const LIBRARY = "https://esm.run/@mlc-ai/web-llm@0.2.85";
export const CONTEXT = 4096;
export const TARGET_TPS = 8;
export const PROFILE_KEY = "browser-llm:models-v1:profile";
export const ATTEMPT_KEY = "browser-llm:models-v1:attempt";
const encoder = new TextEncoder();
export const byteLength = value => encoder.encode(value).length;

function entry(base, family, card, options = {}) {
  const { q0 = false, f32 = true, ...policy } = options;
  const quant = q0 ? "q0" : "q4";
  const suffix = q0 ? "" : "_1";
  return Object.freeze({
    key: base, label: base, family,
    variants: [`${base}-${quant}f16${suffix}-MLC`,
      ...(f32 ? [`${base}-${quant}f32${suffix}-MLC`] : [])],
    card: `https://huggingface.co/${card}`,
    autoPriority: 0, languages: ["en"], foldSystem: false,
    experimental: false, thinking: false, inputBytes: 3000, outputTokens: 256,
    ...policy,
  });
}

export const MODELS = Object.freeze([
  ...["0.5B", "1.5B", "3B", "7B"].map((size, i) => entry(
    `Qwen2.5-${size}-Instruct`, "Qwen2.5", `Qwen/Qwen2.5-${size}-Instruct`,
    { autoPriority: [30, 50, 70, 80][i], languages: ["en", "ja", "auto"] })),
  ...["0.6B", "1.7B", "4B", "8B"].map(size => entry(
    `Qwen3-${size}`, "Qwen3 (experimental)", `Qwen/Qwen3-${size}`,
    { experimental: true, thinking: "off", languages: ["en", "ja", "auto"] })),
  ...["0.8B", "2B", "4B", "9B"].map(size => entry(
    `Qwen3.5-${size}`, "Qwen3.5 (experimental)", `Qwen/Qwen3.5-${size}`,
    { experimental: true, thinking: "off", languages: ["en", "ja", "auto"] })),
  entry("SmolLM2-135M-Instruct", "SmolLM2", "HuggingFaceTB/SmolLM2-135M-Instruct", { q0: true }),
  entry("SmolLM2-360M-Instruct", "SmolLM2", "HuggingFaceTB/SmolLM2-360M-Instruct", { autoPriority: 10 }),
  entry("SmolLM2-1.7B-Instruct", "SmolLM2", "HuggingFaceTB/SmolLM2-1.7B-Instruct", { autoPriority: 40 }),
  entry("Llama-3.2-1B-Instruct", "Llama", "meta-llama/Llama-3.2-1B-Instruct", { autoPriority: 25 }),
  entry("Llama-3.2-3B-Instruct", "Llama", "meta-llama/Llama-3.2-3B-Instruct", { autoPriority: 60 }),
  entry("gemma3-1b-it", "Gemma", "google/gemma-3-1b-it", { f32: false, foldSystem: true, autoPriority: 20 }),
  entry("gemma-2-2b-it", "Gemma", "google/gemma-2-2b-it", { foldSystem: true, autoPriority: 45 }),
  entry("gemma-2-2b-jpn-it", "Gemma", "google/gemma-2-2b-jpn-it",
    { foldSystem: true, autoPriority: 55, languages: ["ja"] }),
  entry("Phi-3.5-mini-instruct", "Phi", "microsoft/Phi-3.5-mini-instruct", { experimental: true }),
  entry("Phi-4-mini-instruct", "Phi", "microsoft/Phi-4-mini-instruct", { experimental: true }),
  entry("DeepSeek-R1-Distill-Qwen-7B", "DeepSeek (reasoning / experimental)",
    "deepseek-ai/DeepSeek-R1-Distill-Qwen-7B",
    { experimental: true, thinking: "on", foldSystem: true, inputBytes: 1800, outputTokens: 1024 }),
  entry("DeepSeek-R1-Distill-Llama-8B", "DeepSeek (reasoning / experimental)",
    "deepseek-ai/DeepSeek-R1-Distill-Llama-8B",
    { experimental: true, thinking: "on", foldSystem: true, inputBytes: 1800, outputTokens: 1024 }),
  entry("Mistral-7B-Instruct-v0.3", "Mistral", "mistralai/Mistral-7B-Instruct-v0.3", { experimental: true, foldSystem: true }),
  entry("Hermes-3-Llama-3.2-3B", "Hermes", "NousResearch/Hermes-3-Llama-3.2-3B", { experimental: true }),
]);

export function problem(code, message) {
  return Object.assign(new Error(message), { code });
}

export function compatibility(record, device) {
  if (!record) return "Not registered in WebLLM 0.2.85.";
  const features = new Set(device.features || []);
  const required = new Set(record.required_features || []);
  // Some upstream records omit required_features for f16 artifacts.
  if (/-q(?:0|4)f16(?:_1)?-MLC$/.test(record.model_id)) required.add("shader-f16");
  for (const feature of required) if (!features.has(feature)) return `Missing GPU feature: ${feature}`;
  const bytes = record.buffer_size_required_bytes;
  if (Number.isFinite(bytes) && bytes > 0) {
    if (Number.isFinite(device.maxStorageBufferBindingSize) && bytes > device.maxStorageBufferBindingSize)
      return "maxStorageBufferBindingSize is below the recorded requirement.";
    if (Number.isFinite(device.maxBufferSize) && bytes > device.maxBufferSize)
      return "maxBufferSize is below the recorded storage-buffer requirement.";
  }
  if (record.overrides?.context_window_size !== CONTEXT) return "This application only enables recorded 4096-token profiles.";
  return null;
}

export function makeCatalog(records, device) {
  const byId = new Map(records.map(record => [record.model_id, record]));
  return MODELS.map(profile => {
    const available = profile.variants.map(id => byId.get(id)).filter(Boolean);
    const record = available.find(record => !compatibility(record, device));
    const reason = record ? null : available.length ? compatibility(available[0], device) : "Not registered in WebLLM 0.2.85.";
    return { ...profile, modelId: record?.model_id || null,
      vramMB: Number.isFinite(record?.vram_required_MB) ? record.vram_required_MB : null,
      context: CONTEXT, disabled: !!reason, reason,
      bufferRequirementKnown: Number.isFinite(record?.buffer_size_required_bytes),
    };
  });
}

export function resolveModel(modelId, records, device) {
  const profile = MODELS.find(profile => profile.variants.includes(modelId));
  if (!profile) throw problem("MODEL", "Model ID is not in the application allowlist.");
  const record = records.find(record => record.model_id === modelId);
  const reason = compatibility(record, device);
  if (reason) throw problem("COMPATIBILITY", reason);
  return { profile, record };
}

// Raw fingerprints and measurements stay in this origin's local storage.
export function fingerprint(device, userAgent) {
  return JSON.stringify([VERSION, LIBRARY, userAgent || "", device.vendor || "", device.architecture || "",
    [...(device.features || [])].sort(), device.maxBufferSize, device.maxStorageBufferBindingSize]);
}

export function readProfile(storage, key, now = Date.now()) {
  try {
    const saved = JSON.parse(storage.getItem(PROFILE_KEY));
    if (saved?.fingerprint !== key || !Array.isArray(saved.results)) return { fingerprint: key, results: [] };
    // Re-check after runtime/browser changes or 30 days. Measurements are not permanent guarantees.
    saved.results = saved.results.filter(row => typeof row.modelId === "string" &&
      Number.isFinite(row.at) && row.at <= now && now - row.at < 30 * 86400000 &&
      Number.isFinite(row.score) && row.score > 0).slice(-32);
    return saved;
  } catch { return { fingerprint: key, results: [] }; }
}

export function autoCandidates(catalog, { capMB, language = "en", saved = [], avoid = [] } = {}) {
  if (![600, 1200, 2200, 3500, 6500].includes(Number(capMB))) throw problem("INPUT", "Invalid Auto memory ceiling.");
  const excluded = new Set(avoid);
  const candidates = catalog.filter(model => !model.disabled && model.autoPriority > 0 &&
    !model.experimental && model.languages.includes(language) && Number.isFinite(model.vramMB) &&
    model.vramMB <= Number(capMB) && !excluded.has(model.modelId));
  candidates.sort((a, b) => b.autoPriority - a.autoPriority || a.vramMB - b.vramMB);
  // A prior passing benchmark in exactly this environment beats an unmeasured policy choice.
  const successful = saved.filter(row => row.score >= TARGET_TPS && candidates.some(model => model.modelId === row.modelId))
    .sort((a, b) => b.at - a.at);
  if (successful.length) candidates.sort((a, b) => Number(b.modelId === successful[0].modelId) - Number(a.modelId === successful[0].modelId));
  return candidates;
}

export function validateMessages(messages, maxBytes) {
  if (!Array.isArray(messages) || !messages.length || messages.length > 8 ||
      byteLength(JSON.stringify(messages)) > maxBytes) throw problem("INPUT", "Input is too large for this model profile. Shorten the question or clear the chat.");
  let expected = "user";
  for (let i = 0; i < messages.length; i++) {
    const message = messages[i];
    if (!message || typeof message.content !== "string") throw problem("INPUT", "Only text messages are supported.");
    if (i === 0 && message.role === "system") continue;
    if (message.role !== expected) throw problem("INPUT", "Invalid conversation message order.");
    expected = expected === "user" ? "assistant" : "user";
  }
  if (messages.at(-1).role !== "user") throw problem("INPUT", "The last message must be a user message.");
}

export function adaptMessages(messages, profile) {
  validateMessages(messages, profile.inputBytes);
  const out = messages.map(({ role, content }) => ({ role, content }));
  if (profile.foldSystem && out[0]?.role === "system") {
    const system = out.shift().content;
    out[0].content = `Instructions:\n${system}\n\n${out[0].content}`;
  }
  return out;
}

export function generationOptions(profile, web = true) {
  const options = { max_tokens: profile.outputTokens, temperature: web ? 0.1 : 0.6 };
  if (profile.thinking === "off") {
    options.temperature = 0.7;
    options.top_p = 0.8;
    options.extra_body = { enable_thinking: false };
  } else if (profile.thinking === "on") {
    options.temperature = 0.6;
    options.top_p = 0.95;
  }
  return options;
}

export function splitAnswer(text, profile) {
  if (!profile.thinking) return { text, reasoning: "" };
  const end = text.indexOf("</think>");
  if (end >= 0) return { text: text.slice(end + 8).trim(), reasoning: text.slice(0, end).replace(/^\s*<think>\s*/, "").trim() };
  if (/^\s*<think>/.test(text)) return { text: "", reasoning: text.replace(/^\s*<think>\s*/, "").trim() };
  return { text, reasoning: "" };
}

export function modelBaseURL(value) {
  const url = new URL(value);
  if (url.protocol !== "https:" || url.hostname !== "huggingface.co" || url.search || url.hash)
    throw problem("MODEL", "Unexpected model artifact host.");
  const parts = url.pathname.split("/").filter(Boolean);
  if (parts.length === 2) return `${url.origin}/${parts.join("/")}/resolve/main/`;
  if (parts.length >= 4 && parts[2] === "resolve") return `${url.origin}/${parts.join("/")}/`;
  throw problem("MODEL", "Unexpected model artifact path.");
}

export function manifestBytes(manifest) {
  if (!Array.isArray(manifest?.records) || !manifest.records.length) return null;
  let total = 0;
  const paths = new Set();
  for (const record of manifest.records) {
    if (!Number.isSafeInteger(record.nbytes) || record.nbytes <= 0 ||
        typeof record.dataPath !== "string" || paths.has(record.dataPath)) return null;
    paths.add(record.dataPath);
    total += record.nbytes;
    if (!Number.isSafeInteger(total)) return null;
  }
  return total;
}

export function errorDetails(error, stage) {
  let code = error?.code;
  if (typeof code !== "string") {
    if (error?.name === "QuotaExceededError") code = "STORAGE";
    else if (error?.name === "DeviceLostError") code = "GPU";
    else if (/^(InputExceed|ContextWindow|MessageOrder|SystemMessageOrder|ContentType|UnsupportedRole)/.test(error?.name || "")) code = "INPUT";
    else if (/^(ShaderF16SupportError|FeatureSupportError|WebGPUNotAvailableError|WebGPUNotFoundError)$/.test(error?.name || "")) code = "COMPATIBILITY";
    else code = "UNKNOWN"; // Never relabel a generic fetch failure or timeout as insufficient VRAM.
  }
  return { code, stage, message: error instanceof Error ? error.message : String(error) };
}
