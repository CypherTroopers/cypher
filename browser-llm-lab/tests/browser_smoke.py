#!/usr/bin/env python3
"""Optional real-Chromium UI tests with a MOCK GPU and MOCK WebLLM.

These tests do not establish GPU compatibility, answer quality, or real memory use.
Requires Python Playwright and Chromium; no actual model is downloaded.
Set CHROMIUM to a browser path when necessary.
"""
import importlib.util
import json
import os
import shutil
import sys
import threading
from pathlib import Path

sys.dont_write_bytecode = True
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("browser_llm_smoke_server", ROOT / "server.py")
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)
state = {"events": [], "fail_load": False, "fail_search": False, "reasoning_only": False, "f16": True}

MOCK_LIBRARY = r'''
import { MODELS } from "/models.js?v=models-v1";
export const prebuiltAppConfig = { model_list: MODELS.flatMap((model, i) => model.variants.map(model_id => ({
  model_id, model: `https://huggingface.co/mock/${model.key}`, model_lib: "mock.wasm",
  vram_required_MB: 500 + i * 10, overrides: { context_window_size: 4096 },
}))) };
async function record(data) {
  return (await fetch("/__test/event", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) })).json();
}
export const hasModelInCache = async () => false;
export class MLCEngine {
  constructor(options) { this.options = options; this.chat = { completions: { create: request => this.create(request) } }; }
  async reload(id) {
    this.id = id;
    const response = await record({ kind: "load", id });
    if (response.fail) { const error = new Error("Synthetic device loss"); error.name = "DeviceLostError"; throw error; }
    this.options.initProgressCallback({ progress: 1, text: "Mock model loaded." });
  }
  async unload() { await record({ kind: "unload" }); }
  async resetChat() {}
  async create(request) {
    const config = await record({ kind: "generate", id: this.id, request });
    if (!request.stream) return { usage: { completion_tokens: request.max_tokens } };
    let text = "Test answer [1].";
    if (this.id.startsWith("DeepSeek")) text = config.reasoning_only ? "<think>Draft without final answer" : "<think>Draft</think>Test answer [1].";
    return (async function* () {
      await new Promise(resolve => setTimeout(resolve, 10));
      yield { choices: [{ delta: { content: text }, finish_reason: config.reasoning_only ? "length" : "stop" }] };
      yield { choices: [], usage: { completion_tokens: request.max_tokens, prompt_tokens: 100, extra: { decode_tokens_per_s: 20 } } };
    })();
  }
}
'''


class Handler(server.Handler):
    def do_GET(self):
        path = server.urlsplit(self.path).path
        if path == "/__test/runtime.js":
            return self.send_bytes(200, MOCK_LIBRARY.encode(), "text/javascript")
        if path == "/worker.js":
            source = (ROOT / "public/worker.js").read_text()
            features = '["shader-f16"]' if state["f16"] else "[]"
            replacement = '''const runtime = createRuntime({
              loadLibrary: () => import("/__test/runtime.js"),
              readDevice: async () => ({ features: FEATURES, maxBufferSize: 1e9, maxStorageBufferBindingSize: 1e9, vendor: "mock" }),
              fetcher: async () => new Response(JSON.stringify({ records: [{ dataPath: "mock-shard", nbytes: 1000 }] })),
              estimate: async () => ({ quota: 1e9, usage: 0 }),
            });'''.replace("FEATURES", features)
            assert source.count("const runtime = createRuntime();") == 1
            return self.send_bytes(200, source.replace("const runtime = createRuntime();", replacement).encode(), "text/javascript")
        return super().do_GET()

    def do_POST(self):
        if self.path == "/__test/event":
            event = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state["events"].append(event)
            fail = event["kind"] == "load" and state["fail_load"]
            if fail:
                state["fail_load"] = False
            return self.send_json(200, {"fail": fail, "reasoning_only": state["reasoning_only"]})
        if self.path == "/api/search":
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state["events"].append({"kind": "search", "body": body})
            if state["fail_search"]:
                return self.send_json(502, {"ok": False, "error": "Synthetic search failure"})
            return self.send_json(200, {"ok": True, "retrieved_at": "2026-09-28T00:00:00Z", "results": [
                {"title": "Test source", "url": "https://example.com/test", "domain": "example.com", "snippet": "Synthetic reference material for a UI test.", "published": ""}
            ]})
        return super().do_POST()


def run():
    httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    passed = []
    try:
        with sync_playwright() as p:
            browser_path = os.environ.get("CHROMIUM") or shutil.which("chromium") or shutil.which("chromium-browser")
            browser = p.chromium.launch(executable_path=browser_path, headless=True, args=["--no-sandbox"])
            context = browser.new_context(viewport={"width": 390, "height": 844})
            context.add_init_script("document.addEventListener('DOMContentLoaded', () => { document.getElementById('includeOpenClaw').checked = false; });")
            page = context.new_page()

            def open_model_settings():
                if not page.locator("#setupPanel").is_visible():
                    page.click("#setupToggle")
                if page.locator("#modelPanel").get_attribute("open") is None:
                    page.locator("#modelPanel > summary").click()

            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            consent = {"yes": False}
            page.on("dialog", lambda dialog: dialog.accept() if consent["yes"] else dialog.dismiss())
            loads = lambda: [event for event in state["events"] if event["kind"] == "load"]
            generates = lambda: [event for event in state["events"] if event["kind"] == "generate"]
            page.goto(base)
            page.wait_for_function("!document.getElementById('start').disabled")
            assert page.locator("#mode option").count() == 27
            assert not loads()
            passed.append("Initial page renders 26 profiles without loading a model")

            open_model_settings()
            page.click("#start")
            page.wait_for_function("document.getElementById('status').textContent.includes('Cancelled')")
            assert not loads()
            passed.append("Cancelling initial consent does not load model weights")

            consent["yes"] = True
            page.click("#start")
            page.wait_for_function("!document.getElementById('send').disabled")
            assert len(loads()) == 1
            assert [event["request"]["max_tokens"] for event in generates()] == [8, 64, 64]
            passed.append("Start loads one model and runs warmup plus two benchmarks")

            page.fill("#prompt", "Explain local inference")
            page.select_option("#taskMode", "web")
            page.click("#send")
            page.wait_for_function("document.getElementById('status').textContent.includes('Answer complete')")
            assert "Test answer [1]." in page.locator("#chat").inner_text()
            chat_request = generates()[-1]["request"]
            assert not chat_request.get("ignore_eos")
            assert any(event["kind"] == "search" for event in state["events"])
            passed.append("Existing search, streaming chat, and source rendering still work")

            open_model_settings()
            old_chat = page.locator("#chat").inner_text()
            consent["yes"] = False
            page.click("#start")
            page.wait_for_function("document.getElementById('status').textContent.includes('Cancelled')")
            assert page.locator("#chat").inner_text() == old_chat
            assert not page.locator("#send").is_disabled()
            assert len(loads()) == 1
            passed.append("Cancelling replacement preserves the running model and conversation")

            before = len(loads())
            page.reload()
            page.wait_for_function("!document.getElementById('start').disabled")
            open_model_settings()
            assert "Measured here" in page.locator("#modelInfo").inner_text()
            assert len(loads()) == before
            passed.append("Saved measurements survive reload without auto-downloading weights")

            consent["yes"] = True
            deep = "DeepSeek-R1-Distill-Qwen-7B-q4f16_1-MLC"
            page.select_option("#mode", deep)
            page.click("#start")
            page.wait_for_function("!document.getElementById('send').disabled")
            page.fill("#prompt", "Explain the reference")
            page.select_option("#taskMode", "web")
            page.click("#send")
            page.wait_for_function("document.getElementById('status').textContent.includes('Answer complete')")
            assert page.locator("#chat details summary").filter(has_text="Model-generated reasoning").count() == 1
            assert generates()[-1]["request"]["messages"][0]["role"] == "user"
            assert generates()[-1]["request"]["max_tokens"] == 1024
            passed.append("Manual DeepSeek uses separate generation settings and reasoning display")

            state["reasoning_only"] = True
            page.fill("#prompt", "Another question")
            page.click("#send")
            page.wait_for_function("document.getElementById('status').textContent.includes('No final answer')")
            assert not page.locator("#send").is_disabled()
            state["reasoning_only"] = False
            passed.append("Incomplete reasoning is not treated as a final answer or a dead engine")

            count = len(generates())
            state["fail_search"] = True
            page.fill("#prompt", "Search should fail")
            page.click("#send")
            page.wait_for_function("document.getElementById('status').textContent.includes('Search failed')")
            assert len(generates()) == count
            assert not page.locator("#send").is_disabled()
            state["fail_search"] = False
            passed.append("Search failure still prevents an unsupported offline answer")

            open_model_settings()
            page.select_option("#mode", "auto")
            state["fail_load"] = True
            before = len(loads())
            page.click("#start")
            page.wait_for_function("document.getElementById('status').textContent.includes('Startup failed [GPU]')")
            assert len(loads()) == before + 1
            assert page.locator("#send").is_disabled()
            assert not page.locator("#start").is_disabled()
            passed.append("GPU load failure does not launch hidden fallback downloads")

            page.locator("#modelPanel .nested-details > summary").click()
            page.click("#forgetProfile")
            assert page.evaluate("JSON.parse(localStorage.getItem('browser-llm:models-v1:profile')).results.length") == 0
            passed.append("Forget measurements clears calibration without deleting model caches")

            state["f16"] = False
            page.reload()
            page.wait_for_function("!document.getElementById('start').disabled")
            open_model_settings()
            assert "f32" in page.locator("#modelInfo").inner_text()
            assert page.locator("#mode option:disabled").count() == 1
            passed.append("No-f16 device shows f32 alternatives and disables f16-only Gemma")

            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            screenshot = os.environ.get("SMOKE_SCREENSHOT")
            if screenshot:
                page.screenshot(path=screenshot, full_page=True)
            assert not errors, errors
            passed.append("390px mobile layout has no horizontal overflow or page JavaScript errors")
            browser.close()
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()
    for name in passed:
        print("PASS:", name)
    print(f"{len(passed)} browser scenarios passed (mock inference / mock GPU).")


if __name__ == "__main__":
    run()
