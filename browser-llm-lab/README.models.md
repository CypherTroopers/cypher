# Browser LLM Lab - models-v1

The current workspace also integrates OpenClaw Gateway connections and mobile
companion guidance. See [README.openclaw.md](README.openclaw.md) for its setup,
conversation modes, and the distinction between browser and Gateway models.

## Scope and changes

Baseline: `CypherTroopers/browser-llm`, branch `main`, commit
`1d705e95d9cab67fc1cb340445ee20ad89b53915` (September 28, 2026).
The original package verified that the four modified source files matched the
Git blob hashes returned by GitHub. The patch also applies to `062f6e8` when
those affected files are identical. It does not overwrite files unconditionally.

This patch replaces Qwen2.5-only size selection with a catalog of allowed model IDs.
It defines 26 model profiles with 51 candidate variants in total. At runtime, the
application checks the active registrations in its WebLLM version and the GPU's
features, then chooses one compatible f16/f32 variant for each model. This does
not mean that all 26 models are available or can run on every device.

This English edition translates the documentation and regenerates the patch and
installer integrity hashes. Application code, model selection, and language
options are unchanged. The interface, code comments, and diagnostic messages
are in English. English remains the default answer language.

### Catalog

| Family | Sizes / models | Initial Auto policy |
|---|---|---|
| Qwen2.5 Instruct | 0.5B / 1.5B / 3B / 7B | Included |
| SmolLM2 Instruct | 135M / 360M / 1.7B | 360M / 1.7B; English |
| Llama 3.2 Instruct | 1B / 3B | English |
| Gemma | Gemma 3 1B, Gemma 2 2B, Japanese Gemma 2 2B | Filtered by language |
| Qwen3 | 0.6B / 1.7B / 4B / 8B | Manual / experimental |
| Qwen3.5 | 0.8B / 2B / 4B / 9B | Manual / experimental |
| Phi | Phi-3.5-mini / Phi-4-mini | Manual / experimental |
| DeepSeek-R1-Distill | Qwen-7B / Llama-8B | Manual / experimental |
| Mistral | 7B Instruct v0.3 | Manual / experimental |
| Hermes | Hermes 3 Llama 3.2 3B | Manual / experimental |

DeepSeek-R1-Distill-Qwen-1.5B is excluded because it is not actively registered
in this WebLLM version. Full-size Kimi models are outside this patch's scope.
No model weights are included or redistributed in this package. Review each
model's original license through its model-card link before use or redistribution.

## Apply to a local checkout

The standalone `apply_browser_llm_models_en.py` includes the complete patch.
It requires Python 3.9 or later and Git, but no additional Python packages.
Save the installer in your home directory, then run these commands from your
local repository:

```sh
python3 ~/apply_browser_llm_models_en.py --check
git switch -c feature/models-v1-en
python3 ~/apply_browser_llm_models_en.py --apply
```

Adjust the script path when it is saved elsewhere. To run from another directory,
add `--repo /path/to/your/checkout`.

`--check` does not modify application files. It checks the original files against
SHA-256 hashes, detects collisions at new file paths, rejects staged changes to
affected paths, and runs `git apply --check`.

`--apply` backs up the affected files and patch inside the repository's Git
administrative directory before applying changes. It stops when affected files
have unexpected contents. Unrelated files are not modified. It does not commit,
push to GitHub, install packages, or restart PM2.

```sh
# Inspect all changes, including newly created files.
git status --short
git diff --check
git diff --stat

# Requires Node.js 18 or later. No npm install is needed.
npm test

# Run server tests using the Python standard library.
python3 -B -m unittest discover -s tests -p 'test_*.py' -v
```

`git diff --stat` alone does not show untracked files. Use `git status --short`
to inspect the newly added files as well.

### Updating a checkout that already has the original models-v1 patch

Do not apply the full patch again. The package also includes
`apply_browser_llm_english_docs.py`, which updates only `README.models.md` from
the original Japanese version to this English version:

```sh
python3 ~/apply_browser_llm_english_docs.py --check
python3 ~/apply_browser_llm_english_docs.py --apply
```

The documentation-only installer verifies the original README hash and creates
a backup before writing. It refuses to overwrite a README with local edits.
It does not modify application code, and no service restart is needed for this
README-only update. Its `--rollback` option restores the original README, provided
that the translated README has not been edited afterward.

### Start or restart

For an application that is already running, restart only that application's
process. With PM2, use `pm2 list` to identify it, then run `pm2 restart` with that
process's name or ID. To start the server directly for the first time, run this
from the repository:

```sh
python3 -B server.py
```

The default port is 8080. Do not start a second server on an occupied port.
The meanings of `PORT`, `PUBLIC_ORIGIN`, and `SEARXNG_URL` are unchanged.
A `/healthz` response with `"version": "models-v1"` identifies the updated Python
server. Manually reload an already-open browser page once after deployment.

### Roll back the full patch

```sh
python3 ~/apply_browser_llm_models_en.py --rollback
```

Before rollback, the installer checks that affected files exactly match this
patch's output. It stops when a file has been edited after installation rather
than deleting those edits. It does not erase Git history or run `reset --hard`.
After a committed installation, review and commit the rollback as ordinary changes.

For an installation made with the original installer followed by the README-only
update, either use the English full installer to roll back the complete English
state, or undo the README-only update before using the original installer.

## Behavior

When the page opens, the Worker checks WebGPU capabilities and WebLLM's registered
models. No model weights are loaded at this stage. WebLLM's JavaScript itself is
fetched from the CDN.

Pressing Start checks the cache and lightweight manifests for one selected model,
then displays a download confirmation dialog. Canceling preserves the currently
loaded model and conversation. Agreeing to load a model resets the conversation.

Auto uses registered GPU requirements, memory estimates, the user's selected
memory-estimate ceiling, the answer language, and previous measurements. Priority
among unmeasured models is an application policy, not a measured ranking of
answer quality. The conservative default ceiling is 1,200 MB. The application
does not infer free GPU memory from system RAM. Adjust the ceiling as needed.

After an eight-token warm-up, the benchmark performs two 64-token generations
using a fixed input containing reference material. It records time to first
text, effective throughput, and the runtime's reported decode throughput. This
is a short workload test, not a guarantee of Japanese-language quality, long-term
stability, or maximum memory consumption. When effective throughput is below
8 tokens per second, an unmeasured alternative may become the next Auto candidate.
The application does not automatically download additional models in succession.

Measurements are stored only in this site's localStorage. Browser identification
and available GPU information form part of the local environment key. Saved
measurements are not reused after an environment-key change or after 30 days.
No transmission of conversation text or performance profiles was added. The
existing search feature still sends search terms to the server and search engines.

`Forget measurements` clears measurements and the current session's exclusion
list, not cached model files. `Stop & Reset` also preserves measurements and
model caches. Restoring a page checks Worker state only; it does not guarantee
continuous background operation or GPU health.

The registry's `vram_required_MB` is an execution-memory estimate, not a download
size. The confirmation dialog's weight size is the sum of manifest shard sizes;
tokenizer, WASM, and other files are additional. The exact remaining download
size is not determined. Missing files may still be fetched when cache entries exist.

## Not implemented and known limitations

- Context is fixed at 4,096 tokens for all models. Automatic reduction to
  1,024/2,048 and exact model-specific tokenizer budgeting are not implemented.
  Defensive byte limits remain: normally 3,000 bytes, or 1,800 for DeepSeek.
  Byte counts are not presented as token counts.
- The normal output limit is 256 tokens. DeepSeek's limit is 1,024 tokens,
  including reasoning. Reasoning alone can consume this budget. Unfinished
  reasoning is not added to conversation history as a final answer.
- There is no CPU inference fallback for environments without WebGPU.
- Thermal conditions, free RAM/VRAM, other applications' workloads, and
  OS-triggered tab termination are not predicted precisely. Not every loading
  or inference failure can be caught by JavaScript.
- Errors are not uniformly classified as out-of-memory failures. After a GPU
  failure or benchmark timeout, downloading another model still requires a new
  Start action and confirmation. There is no automatic switch to cloud inference.
- WebLLM is pinned to 0.2.85, but not every upstream model-weight/WASM URL is
  pinned to an immutable hash. Review upstream changes and model licenses before
  a production release.
- SearXNG configuration and its default search language, English, are unchanged.
  `Answer language` changes the generation language only.

## Validation status

The English edition reruns the package's automated regression tests and checks
its regenerated installers. Results and exact artifact hashes are recorded in
`VALIDATION.txt`.

The original package recorded 49 passing Node.js tests, including 12 mock-DOM
interaction scenarios, and nine passing Python tests covering HTTP routes and
search-input validation. These tests do not use real model weights, a real GPU,
or a real CDN-backed inference session. The optional `tests/browser_smoke.py`
is included, but the original validation could not open the page in Chromium
because of an environment administration policy. Browser testing was not repeated
for this documentation-only revision.

Visual appearance, real-device GPU performance, actual downloads and inference,
and iPhone/Android/Safari stability remain unverified. Before production use,
verify one small model's download and generation on the intended devices, then
test larger or experimental models.

## Primary sources referenced by the original implementation

- Target source: https://github.com/CypherTroopers/browser-llm/tree/1d705e95d9cab67fc1cb340445ee20ad89b53915
- Model registry: https://github.com/mlc-ai/web-llm/blob/v0.2.85/src/config.ts
- API types: https://github.com/mlc-ai/web-llm/blob/v0.2.85/src/types.ts
- Exports: https://github.com/mlc-ai/web-llm/blob/v0.2.85/src/index.ts
- Basic usage: https://webllm.mlc.ai/docs/user/basic_usage.html
- Workers and caching: https://webllm.mlc.ai/docs/user/advanced_usage.html
