// Inference stays in this Worker. Search requests still originate only in app.js.
import {
  LIBRARY, CONTEXT, makeCatalog, resolveModel, problem, adaptMessages,
  generationOptions, splitAnswer, modelBaseURL, manifestBytes, errorDetails,
} from "./models.js?v=models-v1";

export async function readGPU() {
  if (!globalThis.isSecureContext || !globalThis.navigator?.gpu)
    throw problem("COMPATIBILITY", "WebGPU is not available in this secure Worker.");
  const adapter = await navigator.gpu.requestAdapter();
  if (!adapter) throw problem("COMPATIBILITY", "Unable to obtain a WebGPU adapter.");
  const info = adapter.info || {};
  return {
    features: [...adapter.features].sort(),
    maxBufferSize: adapter.limits.maxBufferSize,
    maxStorageBufferBindingSize: adapter.limits.maxStorageBufferBindingSize,
    vendor: info.vendor || "", architecture: info.architecture || "",
    // Buffer limits are not free VRAM. No large allocation probe is performed.
  };
}

const median = values => {
  const sorted = values.filter(Number.isFinite).sort((a, b) => a - b);
  if (!sorted.length) return null;
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
};

// Dependencies are injectable so the state machine can be tested without downloading weights.
export function createRuntime({
  loadLibrary = () => import(LIBRARY), readDevice = readGPU,
  fetcher = (...args) => fetch(...args), now = () => performance.now(),
  estimate = () => globalThis.navigator?.storage?.estimate?.(),
} = {}) {
  let imported, engine, current;
  async function library() {
    if (!imported) {
      try { imported = await loadLibrary(); }
      catch (error) { throw problem("NETWORK", `Could not load WebLLM 0.2.85: ${error.message}`); }
    }
    return imported;
  }
  async function selection(modelId) {
    const webllm = await library();
    return { webllm, ...resolveModel(modelId, webllm.prebuiltAppConfig.model_list, await readDevice()) };
  }
  function requireEngine() {
    if (!engine || !current) throw problem("NOT_LOADED", "No model is loaded. Press Start.");
  }
  async function measure(messages, profile, tokens) {
    await engine.resetChat();
    const start = now();
    let firstTokenMs = null, usage;
    const chunks = await engine.chat.completions.create({
      ...generationOptions(profile), messages: adaptMessages(messages, profile),
      stream: true, stream_options: { include_usage: true }, max_tokens: tokens, ignore_eos: true,
    });
    for await (const chunk of chunks) {
      if (firstTokenMs === null && chunk.choices?.[0]?.delta?.content) firstTokenMs = now() - start;
      if (chunk.usage) usage = chunk.usage;
    }
    const seconds = (now() - start) / 1000;
    const count = usage?.completion_tokens;
    if (!Number.isFinite(count) || count <= 0 || seconds <= 0 || firstTokenMs === null)
      throw problem("BENCHMARK", "The runtime did not return valid benchmark measurements.");
    return { tokens: count, seconds, score: count / seconds, firstTokenMs,
      decode: usage?.extra?.decode_tokens_per_s ?? null, promptTokens: usage?.prompt_tokens ?? null };
  }
  return {
    async dispatch(type, data = {}, send = () => {}) {
      if (type === "probe") {
        const device = await readDevice();
        const webllm = await library();
        return { device, catalog: makeCatalog(webllm.prebuiltAppConfig.model_list, device) };
      }
      if (type === "inspect") {
        const { webllm, record } = await selection(data.modelId);
        let cached = null, weightsBytes = null, disk = null;
        try { cached = await webllm.hasModelInCache(data.modelId, webllm.prebuiltAppConfig); } catch { /* unknown */ }
        try { disk = await estimate(); } catch { /* storage API may be unavailable */ }
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 15000);
        try {
          const response = await fetcher(new URL("ndarray-cache.json", modelBaseURL(record.model)), {
            signal: controller.signal, credentials: "omit", referrerPolicy: "no-referrer",
          });
          if (!response.ok) throw new Error(`Manifest HTTP ${response.status}`);
          // Only the small manifest is fetched; model weight shards are not downloaded here.
          const text = await response.text();
          if (text.length > 8_000_000) throw new Error("Oversized model manifest.");
          weightsBytes = manifestBytes(JSON.parse(text));
        } catch { /* Show unknown size; do not confuse a metadata fetch failure with GPU failure. */ }
        finally { clearTimeout(timeout); }
        return { cached, weightsBytes, disk, context: CONTEXT };
      }
      if (type === "load") {
        if (engine) throw problem("STATE", "Unload the existing model before loading another one.");
        const { webllm, profile, record } = await selection(data.modelId);
        send("progress", { progress: 0, text: `Loading ${data.modelId}...` });
        engine = new webllm.MLCEngine({
          initProgressCallback: report => send("progress", report), logLevel: "WARN",
        });
        // Preserve upstream overrides, including Qwen3.5 max_history_size and Mistral settings.
        // Only recorded 4096-token variants are allowed by resolveModel().
        await engine.reload(data.modelId);
        current = { profile, modelId: data.modelId };
        return { model: data.modelId, context: CONTEXT, outputTokens: profile.outputTokens,
          inputBytes: profile.inputBytes, vramMB: record.vram_required_MB ?? null };
      }
      if (type === "benchmark") {
        requireEngine();
        const profile = current.profile;
        await engine.resetChat();
        await engine.chat.completions.create({
          ...generationOptions(profile),
          messages: [{ role: "user", content: "Give a short explanation of browser computing." }],
          max_tokens: 8, ignore_eos: true,
        });
        const language = data.language === "ja" ? "Japanese" : "English";
        const messages = [
          { role: "system", content: `Answer in ${language}. Explain supplied evidence and cite [1] and [2]. Do not invent facts.` },
          { role: "user", content:
            "Explain local browser inference and why GPU limits alone cannot establish that a model will fit. " +
            "Use only these synthetic reference notes, not outside facts.\n" +
            "[1] In this example, a browser loads a model into a Worker and generates answers locally. " +
            "Downloading model files uses network bandwidth and persistent cache storage. " +
            "Model loading and token generation are distinct operations.\n" +
            "[2] In this example, reported buffer limits constrain individual buffers, not available total GPU memory. " +
            "Other applications and the operating system also use resources. A short benchmark is useful " +
            "but does not guarantee stability under every future workload." },
        ];
        const runs = [];
        for (let i = 0; i < 2; i++) {
          send("progress", { progress: (i + 1) / 3, text: `Benchmark ${i + 1}/2: 64 tokens with reference material...` });
          runs.push(await measure(messages, profile, 64));
        }
        await engine.resetChat();
        return { score: median(runs.map(r => r.score)), decode: median(runs.map(r => r.decode)),
          firstTokenMs: median(runs.map(r => r.firstTokenMs)), tokens: runs.reduce((n, r) => n + r.tokens, 0),
          seconds: runs.reduce((n, r) => n + r.seconds, 0), runs };
      }
      if (type === "chat") {
        requireEngine();
        const profile = current.profile;
        const messages = adaptMessages(data.messages, profile);
        await engine.resetChat();
        let raw = "", usage = null, finish = "";
        const start = now();
        const chunks = await engine.chat.completions.create({
          ...generationOptions(profile, !!data.web), messages, stream: true,
          stream_options: { include_usage: true },
        });
        for await (const chunk of chunks) {
          const delta = chunk.choices?.[0]?.delta?.content ?? "";
          raw += delta;
          if (delta) send("delta", delta);
          if (chunk.usage) usage = chunk.usage;
          finish = chunk.choices?.[0]?.finish_reason || finish;
        }
        return { ...splitAnswer(raw, profile), usage, finish, outputTokens: profile.outputTokens,
          seconds: (now() - start) / 1000 };
      }
      if (type === "health") {
        requireEngine();
        await engine.resetChat();
        return { model: current.modelId }; // Worker/engine state check, not a full GPU stress test.
      }
      if (type === "unload") {
        const old = engine;
        engine = undefined;
        current = undefined;
        if (old) await old.unload();
        return null;
      }
      throw problem("INPUT", "Unknown Worker operation.");
    },
  };
}

if (typeof self !== "undefined" && typeof self.postMessage === "function") {
  const runtime = createRuntime();
  let busy = false;
  self.onmessage = async event => {
    const { id, type, data } = event.data || {};
    if (!Number.isSafeInteger(id) || typeof type !== "string") return;
    const send = (kind, value) => self.postMessage({ id, kind, value });
    if (busy) return send("error", { code: "BUSY", stage: type, message: "Another task is running." });
    busy = true;
    try { send("result", await runtime.dispatch(type, data, send)); }
    catch (error) { send("error", errorDetails(error, type)); }
    finally { busy = false; }
  };
}
