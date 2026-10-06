#!/usr/bin/env python3
"""Explicit Chromium build entry; never downloads or starts a browser/node."""
import argparse
import ast
import hashlib
import re
import contextlib
try:
    import fcntl
except ImportError:
    fcntl = None
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent


class BuildError(Exception):
    pass


def configured_path(name, default):
    value = Path(os.environ.get(name, str(default))).expanduser()
    return (ROOT / value if not value.is_absolute() else value).resolve()


def configuration():
    src = configured_path("BROWSER_SRC", "../cypher-services/chromium-stable-work/checkout/src")
    out = configured_path("BROWSER_OUT", src / "out/CypherClawperStable")
    return {
        "src": src,
        "depot": configured_path("BROWSER_DEPOT_TOOLS", "../cypher-services/chromium-work/depot_tools"),
        "sources": configured_path("BROWSER_SOURCES", "browser/source"),
        "out": out,
        "stage": configured_path("BROWSER_ASSET_STAGE", out / "cypher-assets"),
        "jobs": int(os.environ.get("BROWSER_JOBS", "2")),
        "go": os.environ.get("BROWSER_GO", "go"),
        "min_disk": int(os.environ.get("BROWSER_MIN_FREE_GIB", "100")) << 30,
        "min_memory": int(os.environ.get("BROWSER_MIN_AVAILABLE_GIB", "12")) << 30,
    }


@contextlib.contextmanager
def locked(path, exclusive):
    if fcntl is None:
        raise BuildError("The guarded build entry requires Linux flock support")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise BuildError("Another browser build/setup owns " + str(path))
        yield
    finally:
        os.close(fd)


def resources(c):
    if shutil.disk_usage(c["out"]).free < c["min_disk"]:
        raise BuildError("Disk reserve is below BROWSER_MIN_FREE_GIB; no build started")
    values = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, value = line.split(":", 1)
        values[key] = int(value.strip().split()[0]) * 1024
    if values.get("MemAvailable", 0) < c["min_memory"]:
        raise BuildError("RAM reserve is below BROWSER_MIN_AVAILABLE_GIB; no build started")


def read_object(path, label):
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        raise BuildError(label + " is missing or invalid: " + str(path)) from error
    if not isinstance(value, dict):
        raise BuildError(label + " must be an object: " + str(path))
    return value


def source_release(c):
    manifest_path = c["sources"] / "chromium-app/browser-manifest.json"
    manifest = read_object(manifest_path, "Browser release manifest")
    if type(manifest.get("schema")) is not int or manifest["schema"] != 1:
        raise BuildError("Browser release manifest schema must be 1")
    commit = manifest.get("chromium_commit")
    version = manifest.get("chromium_version")
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise BuildError("Browser release manifest requires an exact 40-character lowercase Chromium commit")
    if not isinstance(version, str) or re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version) is None:
        raise BuildError("Browser release manifest requires a four-part Chromium version")
    if manifest.get("chromium_channel") != "Stable":
        raise BuildError("This browser package requires chromium_channel Stable")
    # Do not execute overlay code while checking which release it targets.
    try:
        tree = ast.parse((c["sources"] / "chromium-app/apply_native.py").read_text())
        pins = [node.value.value for node in tree.body if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == "PIN" for target in node.targets)
                and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)]
    except (OSError, SyntaxError) as error:
        raise BuildError("Native apply script cannot be checked") from error
    if pins != [commit]:
        raise BuildError("Native apply script PIN differs from browser release manifest")
    return manifest


def version_from_checkout(c):
    try:
        values = dict(line.strip().split("=", 1) for line in (c["src"] / "chrome/VERSION").read_text().splitlines() if line.strip())
        return ".".join(values[key] for key in ("MAJOR", "MINOR", "BUILD", "PATCH"))
    except (OSError, ValueError, KeyError) as error:
        raise BuildError("Chromium chrome/VERSION is missing or invalid") from error


def safe_manifest_file(base, name, label):
    if not isinstance(name, str) or not name or "\\" in name:
        raise BuildError("Invalid " + label + " path")
    relative = Path(name)
    if relative.is_absolute() or ".." in relative.parts or relative.as_posix() != name:
        raise BuildError("Invalid " + label + " path")
    path = base / relative
    if not path.resolve().is_relative_to(base.resolve()):
        raise BuildError("Invalid " + label + " path outside its root")
    return path


def source_wasm_manifest(c, release):
    path = c["sources"] / "SOURCE-MANIFEST.json"
    manifest = read_object(path, "Portable source manifest")
    if type(manifest.get("schema")) is not int or manifest["schema"] != 1 or manifest.get("chromium_commit") != release["chromium_commit"]:
        raise BuildError("Portable source manifest release differs")
    entries = manifest.get("files")
    if not isinstance(entries, list):
        raise BuildError("Portable source manifest has invalid file inventory")
    wasm = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise BuildError("Portable source manifest has invalid entry")
        if not entry["path"].startswith("wasm/"):
            continue
        relative = entry["path"]
        target = safe_manifest_file(c["sources"], relative, "WASM source")
        if relative in wasm or not isinstance(entry.get("sha256"), str) or re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is None or type(entry.get("bytes")) is not int:
            raise BuildError("Invalid WASM source manifest entry: " + relative)
        if not target.is_file() or target.stat().st_size != entry["bytes"] or hashlib.sha256(target.read_bytes()).hexdigest() != entry["sha256"]:
            raise BuildError("WASM source differs from portable manifest: " + relative)
        wasm[relative] = entry["sha256"]
    actual = {path.relative_to(c["sources"]).as_posix() for path in (c["sources"] / "wasm").rglob("*")
              if path.is_file() and "__pycache__" not in path.relative_to(c["sources"] / "wasm").parts}
    if not wasm or set(wasm) != actual:
        raise BuildError("WASM source differs from portable manifest: file inventory")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_staged_sources(c, module):
    if module != c["sources"]:
        # These are immutable inputs copied by setup. Generated WASM/pins and
        # installed-manifest records are checked separately below.
        def inventory(root):
            relatives = {Path("chromium-app/browser-manifest.json"), Path("chromium-app/apply_native.py")}
            for subtree in ("browser", "chromium-app/overlay"):
                source_root = root / subtree
                for source in source_root.rglob("*"):
                    if not source.is_file():
                        continue
                    subrelative = source.relative_to(source_root)
                    if "__pycache__" in subrelative.parts or (subtree == "browser" and ("wasm" in subrelative.parts or source.name == "config.json")):
                        continue
                    relatives.add(source.relative_to(root))
            return relatives
        relatives = inventory(c["sources"])
        if relatives != inventory(module):
            raise BuildError("Staged browser source differs: file inventory; use a fresh browser-setup stage")
        for relative in sorted(relatives):
            staged = safe_manifest_file(module, relative.as_posix(), "staged source")
            source = safe_manifest_file(c["sources"], relative.as_posix(), "source package")
            if not staged.is_file() or staged.read_bytes() != source.read_bytes():
                raise BuildError("Staged browser source differs: " + str(relative) + "; use a fresh browser-setup stage")
    pins = read_object(module / "chromium-app/browser-assets.json", "Generated browser asset pins")
    if not {"wasm/wasm_exec.js", "wasm/verifier.wasm"}.issubset(pins):
        raise BuildError("Generated browser asset pins lack required WASM assets")
    for relative, entry in pins.items():
        path = safe_manifest_file(module / "browser", relative, "browser asset")
        if not isinstance(entry, dict) or not isinstance(entry.get("sha256"), str) or re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is None or type(entry.get("bytes")) is not int or entry["bytes"] < 0:
            raise BuildError("Invalid generated browser asset pin: " + relative)
        if not path.is_file() or path.stat().st_size != entry["bytes"] or hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
            raise BuildError("Generated browser asset differs: " + relative)

    source_digest = source_wasm_manifest(c, source_release(c))
    receipt = read_object(module / "wasm-build.json", "Portable WASM build receipt")
    if type(receipt.get("schema")) is not int or receipt["schema"] != 1 or receipt.get("source_manifest_sha256") != source_digest:
        raise BuildError("WASM build receipt differs from portable source manifest; use a fresh browser-setup stage")
    generated = {relative: pins[relative] for relative in ("wasm/wasm_exec.js", "wasm/verifier.wasm")}
    if receipt.get("generated_assets") != generated or receipt.get("target") != "js/wasm":
        raise BuildError("WASM build receipt differs from generated asset pins")


def prerequisites(c):
    if sys.platform != "linux":
        raise BuildError("This guarded entry is tested for Linux only; see browser/README.md for Mac/Windows prerequisites")
    if c["jobs"] < 1 or c["jobs"] > (os.cpu_count() or 1):
        raise BuildError("BROWSER_JOBS must be between 1 and the available CPU count")
    if c["min_disk"] <= 0 or c["min_memory"] <= 0:
        raise BuildError("Build reserve variables must be positive GiB values")
    for path, label in ((c["src"] / "chrome/BUILD.gn", "official Chromium checkout"),
                        (c["depot"] / "autoninja", "depot_tools autoninja"),
                        (c["depot"] / "gn", "depot_tools gn"),
                        (c["sources"] / "chromium-app/apply_native.py", "Cypher browser source package"),
                        (c["src"] / "third_party/llvm-build/Release+Asserts/bin/clang++", "Chromium hooks/toolchain")):
        if not path.is_file():
            raise BuildError("Missing " + label + ": " + str(path) + "; no automatic download. See browser/README.md")
    release = source_release(c)
    source_wasm_manifest(c, release)
    head = subprocess.check_output(["git", "-C", str(c["src"]), "rev-parse", "HEAD"], text=True).strip()
    if head != release["chromium_commit"]:
        raise BuildError("Chromium revision differs from the source package pin: " + release["chromium_commit"])
    if version_from_checkout(c) != release["chromium_version"]:
        raise BuildError("Chromium version differs from the source package release: " + release["chromium_version"])


def asset_module(c):
    if (c["stage"] / "chromium-app/applied-manifest.json").is_file():
        return c["stage"]
    # A configured integration checkout with already generated assets is valid.
    if (c["sources"] / "browser/wasm/verifier.wasm").is_file():
        return c["sources"]
    raise BuildError("Generated WASM/native overlay is missing; run make browser-setup first after the active build finishes")


def verify_installed(c, module):
    release = source_release(c)
    verify_staged_sources(c, module)
    manifest_path = module / "chromium-app/applied-manifest.json"
    if not manifest_path.is_file():
        raise BuildError("Native overlay is not applied; run make browser-setup")
    manifest = read_object(manifest_path, "Installed native overlay manifest")
    if manifest.get("chromium_commit") != release["chromium_commit"]:
        raise BuildError("Native overlay revision differs")
    if "chromium_version" in manifest and manifest["chromium_version"] != release["chromium_version"]:
        raise BuildError("Native overlay version differs")
    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries:
        raise BuildError("Native overlay manifest must contain installed files")
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("after_sha256"), str) or re.fullmatch(r"[0-9a-f]{64}", entry["after_sha256"]) is None:
            raise BuildError("Invalid native manifest entry")
        relative = entry.get("path")
        path = safe_manifest_file(c["src"], relative, "native manifest")
        if relative in seen:
            raise BuildError("Duplicate native manifest path: " + relative)
        seen.add(relative)
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != entry["after_sha256"]:
            raise BuildError("Native source differs: " + relative + "; refusing to overwrite during build")
    installed_hashes = {entry["path"]: entry["after_sha256"] for entry in entries}
    overlay_root = module / "chromium-app/overlay"
    for overlay in sorted(overlay_root.rglob("*")):
        if not overlay.is_file():
            continue
        relative = overlay.relative_to(overlay_root).as_posix()
        source = safe_manifest_file(overlay_root, relative, "native overlay")
        if installed_hashes.get(relative) != hashlib.sha256(source.read_bytes()).hexdigest():
            raise BuildError("Installed native manifest omits or differs from overlay: " + relative)
    if (c["src"] / "chrome/browser/resources/cypher_node/config.json").exists():
        raise BuildError("Fixture config must not be packed into the browser")


def run_guarded(command, c, environment):
    # Child process group belongs exclusively to this invocation.
    prefix = ["nice", "-n", "15"]
    if shutil.which("ionice"):
        prefix += ["ionice", "-c", "3"]
    def interrupt(number, frame):
        raise BuildError("Build interrupted; only this invocation is stopped")
    old_signals = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGHUP)}
    for number in old_signals:
        signal.signal(number, interrupt)
    process = None
    deadline = time.monotonic() + 24 * 3600
    try:
        process = subprocess.Popen(prefix + command, cwd=c["src"], env=environment, start_new_session=True)
        while process.poll() is None:
            time.sleep(1)
            if time.monotonic() > deadline:
                raise BuildError("24-hour build limit reached; only this invocation is stopped")
            resources(c)
        if process.returncode:
            raise BuildError("Chromium command failed with exit " + str(process.returncode))
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        for number, previous in old_signals.items():
            signal.signal(number, previous)


def copy_staged_sources(c):
    # Generated pins belong to the new output stage, never the source checkout.
    shutil.copytree(c["sources"] / "browser", c["stage"] / "browser", dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("wasm", "config.json"))
    shutil.copytree(c["sources"] / "chromium-app", c["stage"] / "chromium-app", dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("browser-assets.json", "__pycache__", "*.tar"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "setup", "build"))
    args = parser.parse_args()
    c = configuration()
    prerequisites(c)
    environment = dict(os.environ)
    environment.update(PATH=str(c["depot"]) + os.pathsep + environment.get("PATH", ""), DEPOT_TOOLS_UPDATE="0", DEPOT_TOOLS_METRICS="0", GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off")
    if args.action == "check":
        verify_installed(c, asset_module(c))
        print("Browser prerequisites and installed overlay match; this check starts no compiler")
        print("Browser output: " + str(c["out"]) + "; jobs=" + str(c["jobs"]))
        return
    with locked(c["src"] / "out/.cypher-browser-source.lock", args.action == "setup"):
        with locked(c["out"] / ".cypher-browser-build.lock", True):
            # A direct Siso user outside this wrapper also holds this OS lock.
            siso_lock = c["out"] / ".siso_lock"
            if siso_lock.exists():
                with locked(siso_lock, True):
                    pass
            resources(c)
            if args.action == "setup":
                run_guarded(["bash", str(c["sources"] / "wasm/build.sh"), "--output-root", str(c["stage"]), "--jobs", str(min(c["jobs"], 2)), "--go", c["go"]], c, environment)
                copy_staged_sources(c)
                run_guarded([sys.executable, str(c["stage"] / "chromium-app/apply_native.py"), "--src", str(c["src"])], c, environment)
                verify_installed(c, c["stage"])
                if not (c["out"] / "args.gn").exists():
                    (c["out"] / "args.gn").write_text('is_debug=false\nis_component_build=true\nsymbol_level=0\nuse_remoteexec=false\n')
                run_guarded([str(c["depot"] / "gn"), "gen", str(c["out"])], c, environment)
                print("Browser setup completed; make browser performs the chrome target/link")
                return
            verify_installed(c, asset_module(c))
            if not (c["out"] / "build.ninja").is_file():
                raise BuildError("GN output missing; run make browser-setup. No dependencies are downloaded by this command")
            run_guarded([str(c["depot"] / "autoninja"), "-C", str(c["out"]), "-j" + str(c["jobs"]), "chrome"], c, environment)
            if not (c["out"] / "chrome").is_file():
                raise BuildError("Build returned without the Linux chrome artifact")
            print("Browser built: " + str(c["out"] / "chrome"))
            print("Keep its shared libraries, .pak resources, locales and other output files together. Existing cypher binaries are untouched.")


if __name__ == "__main__":
    try:
        main()
    except (BuildError, ValueError, OSError, subprocess.CalledProcessError) as error:
        print("browser: " + str(error), file=sys.stderr)
        sys.exit(75 if isinstance(error, BuildError) and "owns " in str(error) else 1)
