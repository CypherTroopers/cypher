#!/usr/bin/env python3
"""Linux offline contract tests: private files/flocks; all build tools mocked."""
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

PIN = "334b65d254ccc35df4fca82706d1753227b01039"
VERSION = "154.0.8037.92"

SPEC = importlib.util.spec_from_file_location("cypher_browser_build", Path(__file__).with_name("browser-build.py"))
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)


class FinishedProcess:
    pid = 424242  # Fake identity; killpg is always mocked in process tests.

    def __init__(self, returncode=0):
        self.returncode = returncode

    def poll(self):
        return self.returncode


class WaitingProcess(FinishedProcess):
    def __init__(self, timeout_on_term=False):
        super().__init__(None)
        self.timeout_on_term = timeout_on_term
        self.waits = []

    def wait(self, timeout=None):
        self.waits.append(timeout)
        if self.timeout_on_term and len(self.waits) == 1:
            raise subprocess.TimeoutExpired("owned-mock-build", timeout)
        self.returncode = -signal.SIGTERM
        return self.returncode


class BrowserBuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cypher-browser-build-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.src = self.base / "checkout/src"
        self.out = self.base / "out-chrome"
        self.depot = self.base / "depot_tools"
        self.sources = self.base / "source-package"
        self.stage = self.base / "asset-stage"
        self.environment = {
            "BROWSER_SRC": str(self.src), "BROWSER_OUT": str(self.out),
            "BROWSER_DEPOT_TOOLS": str(self.depot), "BROWSER_SOURCES": str(self.sources),
            "BROWSER_ASSET_STAGE": str(self.stage), "BROWSER_JOBS": "2",
            "BROWSER_GO": str(self.base / "mock-go"),
            "BROWSER_MIN_FREE_GIB": "100", "BROWSER_MIN_AVAILABLE_GIB": "12",
            "PATH": "/usr/bin:/bin",
        }
        for path in (
            self.src / "chrome/BUILD.gn", self.depot / "autoninja", self.depot / "gn",
            self.src / "third_party/llvm-build/Release+Asserts/bin/clang++",
            self.sources / "chromium-app/apply_native.py", self.sources / "wasm/build.sh",
        ):
            self.write(path, b"MOCK TOOL: never executed\n")
        self.write(self.sources / "browser/app.mjs", b"new source app\n")
        self.write(self.sources / "browser/config.json", b'{"fixture":"must-not-copy"}')
        self.write(self.sources / "chromium-app/browser-assets.json", b'{"stale_source_pins":true}')
        self.write(self.out / "build.ninja", b"mock GN output\n")
        self.installed = "chrome/browser/resources/cypher_node/app.mjs"
        self.write(self.src / self.installed, b"installed baseline app\n")
        self.write_manifest()
        self.commands = []
        self.write(self.sources / "chromium-app/apply_native.py", ('PIN = "' + PIN + '"\n').encode())
        self.write(self.sources / "chromium-app/browser-manifest.json", json.dumps({"schema": 1, "chromium_commit": PIN, "chromium_version": VERSION, "chromium_channel": "Stable"}).encode())
        self.write(self.src / "chrome/VERSION", b"MAJOR=154\nMINOR=0\nBUILD=8037\nPATCH=92\n")
        self.asset_bytes = {"wasm/wasm_exec.js": b"mock Go JS\n", "wasm/verifier.wasm": b"mock generated WASM\n", "app.mjs": b"new source app\n"}
        self.generated_pins = json.dumps({p: {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)} for p, raw in self.asset_bytes.items()}).encode()
        wasm_source = self.sources / "wasm/build.sh"
        self.write(self.sources / "SOURCE-MANIFEST.json", json.dumps({"schema": 1, "chromium_commit": PIN,
            "files": [{"path": "wasm/build.sh", "sha256": hashlib.sha256(wasm_source.read_bytes()).hexdigest(), "bytes": wasm_source.stat().st_size}]}).encode())
        c = {"sources": self.sources, "stage": self.stage}
        BUILD.copy_staged_sources(c)
        self.write_generated_assets()

    def write_generated_assets(self):
        for relative, raw in self.asset_bytes.items():
            self.write(self.stage / "browser" / relative, raw)
        self.write(self.stage / "chromium-app/browser-assets.json", self.generated_pins)
        pins = json.loads(self.generated_pins)
        self.write(self.stage / "wasm-build.json", json.dumps({"schema": 1, "target": "js/wasm",
            "source_manifest_sha256": hashlib.sha256((self.sources / "SOURCE-MANIFEST.json").read_bytes()).hexdigest(),
            "generated_assets": {p: pins[p] for p in ("wasm/wasm_exec.js", "wasm/verifier.wasm")}}).encode())

    @staticmethod
    def write(path, raw):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    def write_manifest(self):
        manifest = {"chromium_commit": PIN, "files": [{"path": self.installed,
                    "after_sha256": hashlib.sha256((self.src / self.installed).read_bytes()).hexdigest()}]}
        self.write(self.stage / "chromium-app/applied-manifest.json", json.dumps(manifest).encode())

    def compiler(self, command, **kwargs):
        self.assertTrue(kwargs["start_new_session"])
        self.assertEqual(kwargs["cwd"], self.src)
        environment = kwargs["env"]
        self.assertEqual(environment["DEPOT_TOOLS_UPDATE"], "0")
        self.assertEqual(environment["GOPROXY"], "off")
        self.assertEqual(environment["GOSUMDB"], "off")
        self.assertEqual(environment["GOTOOLCHAIN"], "local")
        self.assertEqual(command[:3], ["nice", "-n", "15"])
        tool = command[3:]
        self.commands.append(tool)
        if tool[0] == "bash":
            self.assertEqual(tool, ["bash", str(self.sources / "wasm/build.sh"), "--output-root", str(self.stage), "--jobs", self.expected_go_jobs, "--go", self.expected_go])
            self.write_generated_assets()
        elif tool[0] == sys.executable:
            self.assertEqual((self.stage / "browser/app.mjs").read_bytes(), b"new source app\n")
            self.assertEqual((self.stage / "chromium-app/browser-assets.json").read_bytes(), self.generated_pins)
            self.assertTrue((self.stage / "browser/wasm/verifier.wasm").is_file())
            self.assertFalse((self.stage / "browser/config.json").exists())
            self.write_manifest()
        elif tool[0] == str(self.depot / "gn"):
            self.assertEqual(tool, [str(self.depot / "gn"), "gen", str(self.out)])
            self.write(self.out / "build.ninja", b"mock generated ninja\n")
        elif tool[0] == str(self.depot / "autoninja"):
            target = Path(tool[2])
            self.write(target / "chrome", b"mock Linux chrome artifact\n")
        else:
            self.fail("unexpected build tool: " + repr(tool))
        return FinishedProcess()

    def invoke(self, action, popen=None, head=None, resources=None, extra_env=None):
        environment = {**self.environment, **(extra_env or {})}
        self.expected_go = environment["BROWSER_GO"]
        self.expected_go_jobs = str(min(int(environment["BROWSER_JOBS"]), 2))
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.dict(os.environ, environment, clear=True))
            stack.enter_context(mock.patch.object(sys, "argv", [str(Path(BUILD.__file__)), action]))
            stack.enter_context(mock.patch.object(BUILD.os, "cpu_count", return_value=8))
            stack.enter_context(mock.patch.object(BUILD.subprocess, "check_output", return_value=(head or PIN) + "\n"))
            stack.enter_context(mock.patch.object(BUILD.subprocess, "Popen", side_effect=popen or self.compiler))
            stack.enter_context(mock.patch.object(BUILD.shutil, "which", return_value=None))
            stack.enter_context(mock.patch.object(BUILD, "resources", side_effect=resources))
            stack.enter_context(mock.patch.object(BUILD.signal, "signal"))
            stack.enter_context(mock.patch.object(BUILD.time, "sleep"))
            return BUILD.main()

    def test_missing_prerequisite_and_wrong_revision_never_start_compiler(self):
        prerequisite = self.src / "third_party/llvm-build/Release+Asserts/bin/clang++"
        prerequisite.unlink()
        with self.assertRaisesRegex(BUILD.BuildError, "Missing Chromium hooks/toolchain"):
            self.invoke("build")
        self.assertEqual(self.commands, [])
        self.assertFalse((self.src / "out/.cypher-browser-source.lock").exists())
        self.write(prerequisite, b"mock\n")
        with self.assertRaisesRegex(BUILD.BuildError, "revision differs"):
            self.invoke("build", head="0" * 40)
        self.assertEqual(self.commands, [])

    def test_jobs_and_positive_reserve_configuration_fail_before_compiler(self):
        for values in ({"BROWSER_JOBS": "0"}, {"BROWSER_JOBS": "9"},
                       {"BROWSER_MIN_FREE_GIB": "0"}, {"BROWSER_MIN_AVAILABLE_GIB": "-1"}):
            with self.subTest(values=values):
                with self.assertRaises((BUILD.BuildError, ValueError)):
                    self.invoke("build", extra_env=values)
                self.assertEqual(self.commands, [])

    def test_actual_reserve_comparison_uses_available_ram_and_disk_without_build(self):
        c = {"out": self.out, "min_disk": 100 << 30, "min_memory": 12 << 30}
        with mock.patch.object(BUILD.shutil, "disk_usage", return_value=SimpleNamespace(free=(100 << 30) - 1)), \
             mock.patch.object(BUILD.Path, "read_text") as read:
            with self.assertRaisesRegex(BUILD.BuildError, "BROWSER_MIN_FREE_GIB"):
                BUILD.resources(c)
            read.assert_not_called()
        with mock.patch.object(BUILD.shutil, "disk_usage", return_value=SimpleNamespace(free=100 << 30)), \
             mock.patch.object(BUILD.Path, "read_text", return_value="MemAvailable: 12582911 kB\nMemFree: 99999999 kB\n"):
            with self.assertRaisesRegex(BUILD.BuildError, "BROWSER_MIN_AVAILABLE_GIB"):
                BUILD.resources(c)
        with mock.patch.object(BUILD.shutil, "disk_usage", return_value=SimpleNamespace(free=100 << 30)), \
             mock.patch.object(BUILD.Path, "read_text", return_value="MemAvailable: 12582912 kB\nMemFree: 1 kB\n"):
            BUILD.resources(c)

    def test_check_is_read_only_and_build_calls_explicit_chrome_target(self):
        self.invoke("check")
        self.assertEqual(self.commands, [])
        self.assertFalse((self.out / ".cypher-browser-build.lock").exists())
        self.invoke("build")
        self.assertEqual(self.commands, [[str(self.depot / "autoninja"), "-C", str(self.out), "-j2", "chrome"]])
        self.assertTrue((self.out / "chrome").is_file())

    def test_successful_tool_without_artifact_is_not_successful_build(self):
        called = []
        def no_artifact(command, **kwargs):
            called.append(command)
            return FinishedProcess()
        with self.assertRaisesRegex(BUILD.BuildError, "without the Linux chrome artifact"):
            self.invoke("build", popen=no_artifact)
        self.assertEqual(called[0][3:], [str(self.depot / "autoninja"), "-C", str(self.out), "-j2", "chrome"])

    def test_setup_generates_then_copies_preserving_output_pins_then_applies_and_gn(self):
        self.invoke("setup")
        self.assertEqual([command[0] for command in self.commands], ["bash", sys.executable, str(self.depot / "gn")])
        self.assertEqual((self.stage / "chromium-app/browser-assets.json").read_bytes(), self.generated_pins)
        self.assertTrue((self.stage / "browser/wasm/verifier.wasm").is_file())
        self.assertNotIn(str(self.depot / "autoninja"), [command[0] for command in self.commands])
        self.assertIn("use_remoteexec=false", (self.out / "args.gn").read_text())

    def test_setup_caps_go_jobs_and_preserves_configured_go_as_single_argument(self):
        configured_go = str(self.base / "configured go executable")
        self.invoke("setup", extra_env={"BROWSER_JOBS": "7", "BROWSER_GO": configured_go})
        self.assertEqual(self.commands[0][-4:], ["--jobs", "2", "--go", configured_go])

    def test_unsupported_platform_and_missing_flock_fail_without_compiler(self):
        with mock.patch.object(BUILD.sys, "platform", "win32"):
            with self.assertRaisesRegex(BUILD.BuildError, "tested for Linux only"):
                self.invoke("build")
        self.assertEqual(self.commands, [])
        with mock.patch.object(BUILD, "fcntl", None):
            with self.assertRaisesRegex(BUILD.BuildError, "requires Linux flock support"):
                with BUILD.locked(self.base / "unsupported-lock", True):
                    self.fail("unsupported lock was acquired")

    def test_missing_wasm_and_gn_output_explain_explicit_setup(self):
        (self.stage / "chromium-app/applied-manifest.json").unlink()
        with self.assertRaisesRegex(BUILD.BuildError, "run make browser-setup first after the active build finishes"):
            self.invoke("build")
        self.assertEqual(self.commands, [])
        self.write_manifest()
        (self.out / "build.ninja").unlink()
        with self.assertRaisesRegex(BUILD.BuildError, "GN output missing; run make browser-setup"):
            self.invoke("build")
        self.assertEqual(self.commands, [])

    def test_modified_native_source_or_fixture_config_is_rejected(self):
        self.write(self.src / self.installed, b"parallel source change\n")
        with self.assertRaisesRegex(BUILD.BuildError, "Native source differs"):
            self.invoke("build")
        self.write_manifest()
        self.write(self.src / "chrome/browser/resources/cypher_node/config.json", b'{"fixture":true}')
        with self.assertRaisesRegex(BUILD.BuildError, "Fixture config must not be packed"):
            self.invoke("build")
        self.assertEqual(self.commands, [])

    @contextlib.contextmanager
    def held_lock(self, path, mode):
        path.parent.mkdir(parents=True, exist_ok=True)
        script = "import os,fcntl,sys;fd=os.open(sys.argv[1],os.O_RDWR|os.O_CREAT,0o600);fcntl.flock(fd,int(sys.argv[2])|fcntl.LOCK_NB);print('READY',flush=True);sys.stdin.read(1)"
        process = subprocess.Popen([sys.executable, "-c", script, str(path), str(mode)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            ready, _, _ = select.select([process.stdout], [], [], 3)
            self.assertTrue(ready, "private lock holder did not become ready")
            self.assertEqual(process.stdout.readline().strip(), "READY")
            yield process
        finally:
            if process.poll() is None:
                process.stdin.write("\n"); process.stdin.flush()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=3)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()

    def test_os_flock_source_exclusion_across_different_outputs(self):
        with self.held_lock(self.src / "out/.cypher-browser-source.lock", BUILD.fcntl.LOCK_EX) as owner:
            with self.assertRaisesRegex(BUILD.BuildError, "Another browser build/setup owns"):
                self.invoke("build", extra_env={"BROWSER_OUT": str(self.base / "different-output")})
            self.assertIsNone(owner.poll())
        self.assertEqual(self.commands, [])
        with self.held_lock(self.src / "out/.cypher-browser-source.lock", BUILD.fcntl.LOCK_SH) as owner:
            with self.assertRaisesRegex(BUILD.BuildError, "Another browser build/setup owns"):
                self.invoke("setup", extra_env={"BROWSER_OUT": str(self.base / "different-output")})
            self.assertIsNone(owner.poll())
        self.assertEqual(self.commands, [])

    def test_shared_source_allows_separate_output_build_and_exclusive_output_blocks(self):
        with self.held_lock(self.src / "out/.cypher-browser-source.lock", BUILD.fcntl.LOCK_SH) as owner:
            with self.held_lock(self.base / "other-output/.cypher-browser-build.lock", BUILD.fcntl.LOCK_EX) as other_output:
                self.invoke("build")
                self.assertIsNone(owner.poll())
                self.assertIsNone(other_output.poll())
        self.commands.clear()
        with self.held_lock(self.out / ".cypher-browser-build.lock", BUILD.fcntl.LOCK_EX) as owner:
            with self.assertRaisesRegex(BUILD.BuildError, "Another browser build/setup owns"):
                self.invoke("build")
            self.assertIsNone(owner.poll())
        self.assertEqual(self.commands, [])
        with BUILD.locked(self.src / "out/.cypher-browser-source.lock", True):
            pass  # Failed second lock released this invocation's source lock.

    def test_direct_siso_flock_blocks_without_stopping_other_owner(self):
        with self.held_lock(self.out / ".siso_lock", BUILD.fcntl.LOCK_EX) as owner:
            with self.assertRaisesRegex(BUILD.BuildError, "Another browser build/setup owns"):
                self.invoke("build")
            self.assertIsNone(owner.poll())
        self.assertEqual(self.commands, [])

    def test_symlink_lock_is_rejected_without_touching_target(self):
        target = self.base / "unrelated-file"
        self.write(target, b"unrelated content\n")
        self.out.mkdir(parents=True, exist_ok=True)
        (self.out / ".cypher-browser-build.lock").symlink_to(target)
        with self.assertRaises(OSError):
            self.invoke("build")
        self.assertEqual(target.read_bytes(), b"unrelated content\n")
        self.assertEqual(self.commands, [])

    def test_compiler_failure_propagates_without_signalling_any_process(self):
        with mock.patch.object(BUILD.os, "killpg") as kill:
            with self.assertRaisesRegex(BUILD.BuildError, "failed with exit 17"):
                self.invoke("build", popen=lambda *args, **kwargs: FinishedProcess(17))
            kill.assert_not_called()

    def test_resource_loss_stops_only_new_owned_process_group(self):
        for kill_fallback in (False, True):
            with self.subTest(kill_fallback=kill_fallback):
                process = WaitingProcess(timeout_on_term=kill_fallback)
                with mock.patch.object(BUILD.os, "killpg") as kill:
                    with self.assertRaisesRegex(BUILD.BuildError, "RAM reserve disappeared"):
                        self.invoke("build", popen=lambda *args, **kwargs: process,
                                    resources=[None, BUILD.BuildError("RAM reserve disappeared")])
                    wanted = [mock.call(process.pid, signal.SIGTERM)]
                    if kill_fallback:
                        wanted.append(mock.call(process.pid, signal.SIGKILL))
                    self.assertEqual(kill.call_args_list, wanted)

    def test_initial_resource_failure_starts_no_build(self):
        with self.assertRaisesRegex(BUILD.BuildError, "Disk reserve"):
            self.invoke("build", resources=BUILD.BuildError("Disk reserve below explicit minimum"))
        self.assertEqual(self.commands, [])


    def test_stable_defaults_and_make_cypher_recipe_are_separate(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            c = BUILD.configuration()
        self.assertEqual(c["src"], (BUILD.ROOT / "../cypher-services/chromium-stable-work/checkout/src").resolve())
        self.assertEqual(c["out"], c["src"] / "out/CypherClawperStable")
        self.assertEqual(c["stage"], c["out"] / "cypher-assets")
        self.assertEqual(c["depot"], (BUILD.ROOT / "../cypher-services/chromium-work/depot_tools").resolve())

    def test_invalid_release_metadata_never_starts_tools(self):
        path = self.sources / "chromium-app/browser-manifest.json"
        good = json.loads(path.read_text())
        variants = [{**good, "schema": True}, {**good, "chromium_commit": "HEAD"},
                    {**good, "chromium_commit": PIN.upper()}, {**good, "chromium_version": "154"},
                    {**good, "chromium_version": "0154.0.8037.92"}, {**good, "chromium_channel": "Dev"}, [], {**good, "chromium_commit": None}]
        for bad in variants:
            with self.subTest(bad=bad):
                path.write_text(json.dumps(bad))
                with self.assertRaises(BUILD.BuildError):
                    self.invoke("setup")
                self.assertEqual(self.commands, [])
                self.assertFalse((self.out / ".cypher-browser-build.lock").exists())

    def test_mismatched_apply_pin_or_checkout_version_stops_before_lock(self):
        script = self.sources / "chromium-app/apply_native.py"
        script.write_text('PIN = "' + '0' * 40 + '"\n')
        with self.assertRaisesRegex(BUILD.BuildError, "Native apply script PIN differs"):
            self.invoke("setup")
        script.write_text('PIN = "' + PIN + '"\n')
        (self.src / "chrome/VERSION").write_text("MAJOR=157\nMINOR=0\nBUILD=8080\nPATCH=0\n")
        with self.assertRaisesRegex(BUILD.BuildError, "Chromium version differs"):
            self.invoke("build")
        self.assertEqual(self.commands, [])
        self.assertFalse((self.out / ".cypher-browser-build.lock").exists())

    def test_stale_stage_release_or_source_is_rejected(self):
        for relative in ("chromium-app/browser-manifest.json", "chromium-app/apply_native.py", "browser/app.mjs"):
            with self.subTest(relative=relative):
                target = self.stage / relative
                original = target.read_bytes()
                target.write_bytes(b"stale previous package\n")
                with self.assertRaisesRegex(BUILD.BuildError, "Staged browser source differs"):
                    self.invoke("build")
                self.assertEqual(self.commands, [])
                target.write_bytes(original)
        overlay = "chromium-app/overlay/chrome/browser/ui/webui/cypher_ai/cypher_ai_ui.cc"
        self.write(self.sources / overlay, b"updated isolated AI native overlay\n")
        with self.assertRaisesRegex(BUILD.BuildError, "Staged browser source differs"):
            self.invoke("check")
        self.assertEqual(self.commands, [])

    def test_changed_or_invalid_generated_assets_stop_before_compiler(self):
        target = self.stage / "browser/wasm/verifier.wasm"
        target.write_bytes(b"tampered generated WASM")
        with self.assertRaisesRegex(BUILD.BuildError, "Generated browser asset differs"):
            self.invoke("build")
        self.write_generated_assets()
        pins_path = self.stage / "chromium-app/browser-assets.json"
        pins = json.loads(pins_path.read_text())
        del pins["wasm/wasm_exec.js"]
        pins_path.write_text(json.dumps(pins))
        with self.assertRaisesRegex(BUILD.BuildError, "lack required WASM assets"):
            self.invoke("build")
        self.assertEqual(self.commands, [])

    def test_unsafe_or_empty_installed_manifest_is_rejected(self):
        path = self.stage / "chromium-app/applied-manifest.json"
        good = json.loads(path.read_text())
        bad_lists = [[], [good["files"][0], good["files"][0]], [{**good["files"][0], "path": "../outside"}],
                     [{**good["files"][0], "after_sha256": "bad"}], None]
        for entries in bad_lists:
            with self.subTest(entries=entries):
                path.write_text(json.dumps({**good, "files": entries}))
                with self.assertRaises(BUILD.BuildError):
                    self.invoke("build")
                self.assertEqual(self.commands, [])

    def test_installed_release_mismatch_is_rejected(self):
        path = self.stage / "chromium-app/applied-manifest.json"
        good = json.loads(path.read_text())
        for field, value in (("chromium_commit", "0" * 40), ("chromium_version", "157.0.8080.0")):
            with self.subTest(field=field):
                path.write_text(json.dumps({**good, field: value}))
                with self.assertRaisesRegex(BUILD.BuildError, "Native overlay .* differs"):
                    self.invoke("build")
                self.assertEqual(self.commands, [])

    def test_asset_symlink_cannot_escape_stage(self):
        target = self.stage / "browser/wasm/verifier.wasm"
        raw = target.read_bytes()
        target.unlink()
        outside = self.base / "outside.wasm"
        outside.write_bytes(raw)
        target.symlink_to(outside)
        with self.assertRaisesRegex(BUILD.BuildError, "outside its root"):
            self.invoke("build")
        self.assertEqual(self.commands, [])
        self.assertEqual(outside.read_bytes(), raw)


    def test_installed_manifest_must_cover_new_native_ai_overlay(self):
        relative = "chrome/browser/ui/webui/cypher_ai/cypher_ai_ui.cc"
        raw = b"native AI controller\n"
        for root in (self.sources, self.stage):
            self.write(root / "chromium-app/overlay" / relative, raw)
        self.write(self.src / relative, raw)
        with self.assertRaisesRegex(BUILD.BuildError, "Installed native manifest omits or differs from overlay"):
            self.invoke("build")
        self.assertEqual(self.commands, [])
        path = self.stage / "chromium-app/applied-manifest.json"
        manifest = json.loads(path.read_text())
        manifest["files"].append({"path": relative, "after_sha256": hashlib.sha256(raw).hexdigest()})
        path.write_text(json.dumps(manifest))
        self.invoke("check")
        self.assertEqual(self.commands, [])
        self.write(self.src / relative, b"old native AI controller\n")
        manifest["files"][-1]["after_sha256"] = hashlib.sha256((self.src / relative).read_bytes()).hexdigest()
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(BUILD.BuildError, "Installed native manifest omits or differs from overlay"):
            self.invoke("build")
        self.assertEqual(self.commands, [])


    def test_deleted_overlay_or_ui_cannot_survive_in_old_stage(self):
        for relative in ("chromium-app/overlay/chrome/browser/ui/webui/cypher_ai/retired.cc", "browser/retired-ui.mjs"):
            with self.subTest(relative=relative):
                target = self.stage / relative
                self.write(target, b"retired source still staged\n")
                with self.assertRaisesRegex(BUILD.BuildError, "Staged browser source differs: file inventory"):
                    self.invoke("build")
                self.assertEqual(self.commands, [])
                target.unlink()


    def test_changed_or_extra_wasm_source_stops_before_compiler(self):
        source = self.sources / "wasm/build.sh"
        original = source.read_bytes()
        source.write_bytes(b"changed compiler recipe\n")
        with self.assertRaisesRegex(BUILD.BuildError, "WASM source differs from portable manifest"):
            self.invoke("setup")
        source.write_bytes(original)
        self.write(self.sources / "wasm/cmd/verifier/extra.go", b"package main\n")
        with self.assertRaisesRegex(BUILD.BuildError, "WASM source differs from portable manifest: file inventory"):
            self.invoke("build")
        self.assertEqual(self.commands, [])
        self.assertFalse((self.out / ".cypher-browser-build.lock").exists())

    def test_stale_wasm_receipt_is_rejected(self):
        path = self.stage / "wasm-build.json"
        original = json.loads(path.read_text())
        for changes in ({"source_manifest_sha256": "0" * 64}, {"generated_assets": {}}, {"target": "linux/amd64"}):
            with self.subTest(changes=changes):
                path.write_text(json.dumps({**original, **changes}))
                with self.assertRaisesRegex(BUILD.BuildError, "WASM build receipt differs"):
                    self.invoke("build")
                self.assertEqual(self.commands, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
