#!/usr/bin/env python3
"""Exact fourteen-app intermediate init executor; approval is mandatory.

preflight is read-only. No phase is invoked by importing this module. A consent
file records a separate, actual user instruction; creating that file is not a
substitute for obtaining the instruction. No rollback/delete implementation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import time
import re

from live_generation_plan import APPS, ADDED_COMMONS, HOST, directory, public_json, regular
from live_observe import processes

ROOT = Path(__file__).resolve().parents[2]
TARGETS = APPS + ADDED_COMMONS
MAINTENANCE = b"#!/usr/bin/env bash\n# Approved generation switch; no DB access.\nexit 0\n"


def sha(path):
    regular(path)
    h = hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()


def safe_file(path):
    if not path.is_absolute() or path != path.resolve():
        raise ValueError("absolute non-symlink file path required")
    regular(path)


def syncdir(path):
    fd = os.open(path, os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    syncdir(path.parent)


def atomic(path, data, mode=0o600):
    temporary = path.with_name(path.name + ".generation-new")
    if temporary.exists() or temporary.is_symlink():
        # Never delete an unknown interrupted file to force a restart through.
        regular(temporary)
        if temporary.read_bytes() != data:
            raise ValueError("conflicting interrupted configuration write")
    else:
        write_new(temporary, data, mode)
    os.chmod(temporary, mode)
    os.replace(temporary, path)
    syncdir(path.parent)


class Host:
    """Named PM2 and read-only process checks; stdout/env never copied to logs."""
    def apps(self):
        daemon = Path("/root/.pm2/pm2.pid")
        if not daemon.is_file() or not (Path("/proc") / daemon.read_text().strip()).is_dir():
            raise ValueError("existing PM2 daemon required")
        raw = subprocess.check_output(["pm2", "jlist"], timeout=20)
        return json.loads(raw)

    def pm2(self, *args):
        p = subprocess.run(["pm2", *args], capture_output=True, timeout=180)
        if p.returncode:
            raise ValueError("named PM2 operation failed; raw output withheld")

    def boot(self):
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()

    def pid_ticks(self):
        return {pid: value[1] for pid, value in processes().items()}

    def exe_hash(self, pid):
        h = hashlib.sha256()
        with (Path("/proc") / str(pid) / "exe").open("rb") as f:
            for b in iter(lambda: f.read(1024 * 1024), b""):
                h.update(b)
        return h.hexdigest()

    def writers(self, paths):
        roots = [str(p) for p in paths]
        for p in Path("/proc").iterdir():
            if not p.name.isdecimal():
                continue
            try:
                args = (p / "cmdline").read_bytes().split(b"\0")
                cwd = Path(os.readlink(p / "cwd"))
                for i, arg in enumerate(args):
                    value = arg.split(b"=", 1)[1] if arg.startswith(b"--datadir=") else args[i + 1] if arg == b"--datadir" and i + 1 < len(args) else None
                    if value is not None:
                        d = Path(os.fsdecode(value)); d = d if d.is_absolute() else cwd / d
                        if str(d.resolve()) in roots:
                            return True
                for fd in (p / "fd").iterdir():
                    try:
                        target = os.readlink(fd).removesuffix(" (deleted)")
                    except (FileNotFoundError, ProcessLookupError, PermissionError):
                        continue
                    if any(target == root or target.startswith(root + "/") for root in roots):
                        return True
                maps = (p / "maps").read_text(errors="replace")
                if any(root + "/" in maps for root in roots):
                    return True
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
        return False

    def initialize(self, binary, datadir, genesis, log):
        with log.open("xb") as f:
            os.chmod(log, 0o600)
            p = subprocess.run([str(binary), "--datadir", str(datadir), "--cache", "64", "--cache.trie.journal", "", "init", str(genesis)], stdout=f, stderr=f, timeout=180)
            f.flush(); os.fsync(f.fileno())
        if p.returncode:
            raise ValueError("normal CLI init failed; private log retained")


class Switch:
    def __init__(self, repo, plan_path, host=None, now=None):
        self.repo, self.plan_path = Path(repo), Path(plan_path)
        directory(self.repo)
        self.plan = public_json(self.plan_path)
        self.plan_hash = sha(self.plan_path)
        self.host = Host() if host is None else host
        self.now = time.time() if now is None else now
        p = self.plan
        if p.get("host") != HOST or p.get("workspace") != str(self.repo) or p.get("version") != 1:
            raise ValueError("foreign plan host/workspace/version")
        if len(p.get("targets", [])) != 14 or {n.get("pm2_name") for n in p["targets"]} != set(TARGETS):
            raise ValueError("exact fourteen named apps required")
        self.nodes = {n["pm2_name"]: n for n in p["targets"]}
        allow_stopped = p.get("allow_stopped_added_commons", False)
        if type(allow_stopped) is not bool:
            raise ValueError("explicit boolean stopped-Common mode required")
        for name, n in self.nodes.items():
            status = n.get("observed_status", "online")
            if status == "stopped":
                if (not allow_stopped or name not in ADDED_COMMONS or
                        type(n.get("observed_pid")) is not int or n["observed_pid"] != 0 or
                        n.get("observed_start_ticks") is not None or
                        n.get("observed_exe_sha256") is not None or
                        n.get("old_db_genesis_status") != "NOT_OBSERVED_STOPPED"):
                    raise ValueError("invalid explicitly stopped added-Common identity")
            elif status != "online" or type(n.get("observed_pid")) is not int or n["observed_pid"] <= 1:
                raise ValueError("invalid observed active process identity")
        self.base = self.repo / "build/stage/live-generations" / p["generation_label"]
        if self.base.parent != self.repo / "build/stage/live-generations" or "/" in p["generation_label"] or p["generation_label"] in (".", ".."):
            raise ValueError("invalid generation label")
        self.control = self.base / "control"
        self.journal = self.control / "journal.json"
        if self.base.exists() or self.base.is_symlink():
            if directory(self.base).st_mode & 0o077:
                raise ValueError("generation archive must be private")
            if directory(self.control).st_mode & 0o077:
                raise ValueError("switch control must be private")
        self.exec = p.get("execution", {})
        for name, n in self.nodes.items():
            expected = (self.repo / "build/stage/live-commons" / ("chaindbdex" + name.removeprefix("cypherdex")) if name in ADDED_COMMONS else self.repo / ("chaindbmine" if name == "cyphermine" else "chaindb" + name.removeprefix("cypher")))
            if n["old_datadir"] != str(expected) or n["archive_datadir"] != str(self.base / expected.name):
                raise ValueError("datadir not exact allowlist")
        self.state = public_json(self.journal) if self.journal.exists() else None
        if self.state and self.state.get("plan_sha256") != self.plan_hash:
            raise ValueError("journal belongs to another approved plan")

    def configuration(self):
        if self.host.boot() != self.plan["observed_boot_id"]:
            raise ValueError("host reboot requires a new observation/review")
        release = Path(self.exec.get("release_file", ""))
        safe_file(release)
        if release != self.repo / "build/stage/live-q3-release/bin/cypher-linux-amd64" or sha(release) != self.exec.get("release_sha256"):
            raise ValueError("reviewed Q3 release binary/hash unavailable")
        new = self.plan["new_generation"]
        genesis = Path(new.get("genesis_file") or "")
        safe_file(genesis)
        if not genesis.is_absolute() or genesis == self.repo / "genesis.json" or sha(genesis) != new.get("genesis_sha256"):
            raise ValueError("candidate genesis differs from plan")
        candidate = public_json(genesis)
        same_chain = candidate["config"]["chainId"] == self.plan["old_generation"]["chain_id"]
        if candidate["config"]["chainId"] != new["chain_id"] or same_chain != self.plan.get("chain_id_preserved", False) or candidate["config"]["dexDevnet"]["dexId"].lower() != new["dex_deployment_id"].lower():
            raise ValueError("candidate generation identity mismatch")
        inventory_path = Path(self.exec.get("candidate_inventory_file", ""))
        safe_file(inventory_path)
        if not inventory_path.is_absolute() or sha(inventory_path) != self.exec.get("candidate_inventory_sha256"):
            raise ValueError("Go-validated candidate inventory missing/changed")
        inv = public_json(inventory_path)
        if inv.get("GenesisSHA256") != new["genesis_sha256"] or inv.get("ChainID") != new["chain_id"] or inv.get("DEXID", "").lower() != new["dex_deployment_id"].lower() or not inv.get("AllocPreserved") or not inv.get("CLXCommitteePreserved"):
            raise ValueError("candidate inventory binding mismatch")
        if self.exec.get("validation_status") != "PASS(UNIT)":
            raise ValueError("final source/build/candidate validation gate not supplied")
        configs = self.exec.get("ecosystem_files", [])
        names = []
        for entry in configs:
            path = Path(entry["path"])
            safe_file(path)
            if not path.is_absolute() or not path.is_relative_to(self.repo) or sha(path) != entry["sha256"]:
                raise ValueError("launch configuration hash/path mismatch")
            for app in public_json(path).get("apps", []):
                names.append(app.get("name"))
        if len(names) != 14 or set(names) != set(TARGETS):
            raise ValueError("launch configs must contain exactly these fourteen apps")
        approved_scripts = self.exec.get("launcher_files", [])
        expected_scripts = {str(self.repo / ("start-" + name + ".sh")) for name in APPS} | {str(self.repo / "build/stage/live-commons" / ("common" + name.removeprefix("cypherdex")) / "start.sh") for name in ADDED_COMMONS}
        if len(approved_scripts) != 14 or {e.get("path") for e in approved_scripts} != expected_scripts:
            raise ValueError("all fourteen launcher content hashes required")
        for entry in approved_scripts:
            path = Path(entry["path"]); safe_file(path)
            if path.read_bytes() == MAINTENANCE and self.state:
                name = next((n for n, e in self.state["wrappers"].items() if e["path"] == str(path)), None)
                if name is None or sha(self.control / (name + ".wrapper")) != entry["sha256"]:
                    raise ValueError("maintenance launcher lacks approved original")
            elif sha(path) != entry["sha256"]:
                raise ValueError("approved launcher content changed")
        activation = self.exec.get("activation")
        if activation:
            source = Path(activation["source"]); safe_file(source)
            if not source.is_relative_to(self.repo / "build/stage/live-generation-candidate") or sha(source) != activation["sha256"] or activation["destination"] != str(self.repo / "build/stage/live-deployment.json"):
                raise ValueError("generation activation binding/path mismatch")
        self.verify_source_manifest(inv)
        return release, genesis

    def verify_source_manifest(self, inventory):
        binding = self.exec.get("validation_source_manifest")
        if not isinstance(binding, dict) or set(binding) != {"path", "sha256"}:
            raise ValueError("source manifest path/hash binding required")
        path = Path(binding["path"]); safe_file(path)
        if path.stat().st_size > 8 * 1024 * 1024 or sha(path) != binding["sha256"]:
            raise ValueError("source manifest digest/size differs from plan")
        files = {}
        for line in path.read_text().splitlines():
            pieces = line.split(None, 1)
            if len(pieces) != 2 or not re.fullmatch(r"[0-9a-f]{64}", pieces[0]):
                raise ValueError("canonical sha256 source manifest required")
            target = Path(pieces[1])
            if not target.is_absolute(): target = self.repo / target
            if not target.is_relative_to(self.repo) or target != target.resolve() or target in files or len(files) >= 15000:
                raise ValueError("source manifest path/count/duplicate violation")
            relative_parts = target.relative_to(self.repo).parts
            if target.is_relative_to(self.repo / "build/stage/live-generation-candidate/keys") or any(p.startswith("chaindb") for p in relative_parts[:-1]) or "chaindata" in relative_parts or target.suffix == ".key":
                raise ValueError("private keys/operational data must not enter source manifest")
            safe_file(target); actual = sha(target)
            if self.state:
                if target == self.repo / "genesis.json" and actual == self.plan["new_generation"]["genesis_sha256"]:
                    actual = sha(self.control / "old-genesis.json")
                elif target.stat().st_size == len(MAINTENANCE) and target.read_bytes() == MAINTENANCE:
                    name = next((n for n, e in self.state["wrappers"].items() if e["path"] == str(target)), None)
                    if name is not None: actual = sha(self.control / (name + ".wrapper"))
            if actual != pieces[0]:
                raise ValueError("source file changed; rebuild/review requires a new approved plan")
            files[target] = actual
        required = {self.repo / "scripts/dex" / name for name in ("live_start.py", "live_common.py", "live_roles.py", "live_auth.py", "live_switch_generation.py")}
        required.update(Path(e["path"]) for e in self.exec["launcher_files"])
        required.update(Path(e["path"]) for e in self.exec["ecosystem_files"])
        required.add(Path(self.plan["new_generation"]["genesis_file"]))
        required.add(Path(self.exec["candidate_inventory_file"]))
        required.update(Path(p["Manifest"]) for p in inventory.get("Participants", []))
        required.update(Path(p) for p in inventory.get("RelayConfigs", []))
        if self.exec.get("activation"): required.add(Path(self.exec["activation"]["source"]))
        if not required.issubset(files):
            raise ValueError("source manifest omitted launcher/executor/candidate settings")

    def selected(self):
        apps = [a for a in self.host.apps() if a.get("name") in TARGETS]
        if len(apps) != 14 or {a["name"] for a in apps} != set(TARGETS):
            raise ValueError("PM2 exact fourteen inventory mismatch")
        for a in apps:
            name, env = a["name"], a["pm2_env"]
            expected = (self.repo / "build/stage/live-commons" / ("common" + name.removeprefix("cypherdex")) / "start.sh" if name in ADDED_COMMONS else self.repo / ("start-" + name + ".sh"))
            if env.get("pm_cwd") != str(self.repo) or env.get("pm_exec_path") != str(expected) or env.get("args") or env.get("shutdown_with_message"):
                raise ValueError("unreviewed PM2 wrapper/cwd/arguments")
        return apps

    def require_stopped(self):
        apps = self.selected()
        if any(a.get("pid") or a["pm2_env"].get("status") != "stopped" for a in apps):
            raise ValueError("all fourteen apps must be stopped")
        paths = [Path(n["old_datadir"]) for n in self.nodes.values()] + [Path(n["archive_datadir"]) for n in self.nodes.values()]
        if self.host.writers(paths):
            raise ValueError("process/datadir fd or mapping still live")

    def approval(self, path):
        path = Path(path)
        s = regular(path, 8192)
        if s.st_mode & 0o077:
            raise ValueError("approval record must be private")
        a = public_json(path)
        if a.get("version") != 1 or a.get("approved") is not True or a.get("operation") != "intermediate-generation-reset" or a.get("plan_sha256") != self.plan_hash or not a.get("user_instruction_reference"):
            raise ValueError("separate explicit user reset approval is required")
        if type(a.get("approved_unix")) not in (int, float) or type(a.get("expires_unix")) not in (int, float) or a["approved_unix"] > self.now or self.now > a["expires_unix"] or a["expires_unix"] - a["approved_unix"] > 86400:
            raise ValueError("approval expired/invalid")

    def preflight(self):
        self.configuration()
        if self.state:
            return {"status": "RESUME_REVIEW", "phase": self.state["phase"], "plan_sha256": self.plan_hash, "started": self.state.get("signing_may_have_started", False)}
        observed = time.strptime(self.plan["observation_utc"], "%Y-%m-%dT%H:%M:%SZ")
        import calendar
        age = self.now - calendar.timegm(observed)
        if age < -30 or age > 900:
            raise ValueError("fresh process observation required before first stop")
        apps = self.selected(); ticks = self.host.pid_ticks()
        old_exe = self.exec.get("old_running_exe_sha256", "")
        if not isinstance(old_exe, str) or not re.fullmatch(r"[0-9a-f]{64}", old_exe):
            raise ValueError("exact existing executable digest required")
        for a in apps:
            n = self.nodes[a["name"]]
            if n.get("observed_status", "online") == "stopped":
                if type(a.get("pid")) is not int or a["pid"] != 0 or a["pm2_env"].get("status") != "stopped":
                    raise ValueError("planned stopped Common changed after review")
                if self.host.writers([Path(n["old_datadir"])]):
                    raise ValueError("stopped Common datadir writer still live")
            else:
                if a.get("pid") != n["observed_pid"] or ticks.get(n["observed_pid"]) != n["observed_start_ticks"] or a["pm2_env"].get("status") != "online":
                    raise ValueError("process identity changed after plan")
                if n.get("observed_exe_sha256", old_exe) != old_exe or self.host.exe_hash(n["observed_pid"]) != old_exe:
                    raise ValueError("running executable changed after review")
            s = directory(Path(n["old_datadir"]))
            if (s.st_dev, s.st_ino) != (n["datadir_device"], n["datadir_inode"]):
                raise ValueError("datadir identity changed")
        if self.base.exists() or self.base.is_symlink():
            raise ValueError("generation archive already exists without this journal")
        if sha(self.repo / "genesis.json") != self.plan["old_generation"]["genesis_file_sha256"]:
            raise ValueError("old genesis changed")
        return {"status": "READY_FOR_SEPARATE_USER_APPROVAL", "plan_sha256": self.plan_hash, "reset_executed": False}

    def save(self):
        atomic(self.journal, (json.dumps(self.state, indent=2) + "\n").encode())

    def invoke(self, phase, approval):
        self.approval(approval); self.configuration()
        if self.state and self.state.get("signing_may_have_started"):
            raise ValueError("generation may already have signed; no reset/rollback/repeated start")
        getattr(self, phase)()

    def stop(self):
        if self.state is None:
            self.preflight()
            self.base.parent.mkdir(mode=0o700, exist_ok=True); directory(self.base.parent)
            self.base.mkdir(mode=0o700); self.control.mkdir(mode=0o700)
            self.state = {"version": 1, "plan_sha256": self.plan_hash, "phase": "stopping", "wrappers": {}, "archived": [], "initialized": [], "signing_may_have_started": False}
            self.save()
            write_new(self.control / "approved-plan.json", self.plan_path.read_bytes())
            write_new(self.control / "old-genesis.json", (self.repo / "genesis.json").read_bytes())
        if self.state["phase"] != "stopping":
            raise ValueError("stop phase already completed")
        apps = self.selected()
        for a in apps:
            name = a["name"]; path = Path(a["pm2_env"]["pm_exec_path"])
            saved = self.control / (name + ".wrapper")
            if not saved.exists():
                regular(path); write_new(saved, path.read_bytes())
            if name not in self.state["wrappers"]:
                self.state["wrappers"][name] = {"path": str(path), "sha256": sha(saved)}; self.save()
            if path.read_bytes() != MAINTENANCE and sha(path) != self.state["wrappers"][name]["sha256"]:
                raise ValueError("wrapper changed during stop")
            atomic(path, MAINTENANCE, 0o700)
        # Already stopped added Commons remain stopped. Never start their old DB
        # (or even a maintenance stub) merely to satisfy the original live plan.
        config = {"apps": [{"name": a["name"], "script": a["pm2_env"]["pm_exec_path"], "cwd": str(self.repo), "interpreter": "bash", "exec_mode": "fork", "autorestart": False, "watch": False, "kill_timeout": 60000, "treekill": True} for a in apps if self.nodes[a["name"]].get("observed_status", "online") == "online"]}
        path = self.control / "maintenance.json"
        if not path.exists(): write_new(path, json.dumps(config).encode())
        self.host.pm2("restart", str(path))
        deadline = time.monotonic() + 70
        while True:
            try:
                self.require_stopped(); break
            except ValueError:
                if time.monotonic() > deadline: raise
                time.sleep(0.25)
        self.state["phase"] = "stopped"; self.save()

    def archive(self):
        if not self.state or self.state["phase"] not in ("stopped", "archiving"):
            raise ValueError("completed controlled stop required")
        self.require_stopped(); self.state["phase"] = "archiving"; self.save()
        for name, n in self.nodes.items():
            source, target = Path(n["old_datadir"]), Path(n["archive_datadir"])
            if target.exists():
                s = directory(target)
                if source.exists() or (s.st_dev, s.st_ino) != (n["datadir_device"], n["datadir_inode"]):
                    raise ValueError("ambiguous/resumed archive identity")
            else:
                s = directory(source)
                if (s.st_dev, s.st_ino) != (n["datadir_device"], n["datadir_inode"]) or s.st_dev != self.base.stat().st_dev:
                    raise ValueError("archive requires exact same-filesystem source")
                self.require_stopped(); os.rename(source, target); syncdir(source.parent); syncdir(target.parent)
            if name not in self.state["archived"]:
                self.state["archived"].append(name); self.save()
        self.state["phase"] = "archived"; self.save()

    def copy_identities(self, source, target):
        marker = target / "GENERATION_CANDIDATE"
        if not target.exists(): target.mkdir(mode=0o700)
        directory(target)
        if not marker.exists():
            if list(target.iterdir()): raise ValueError("unmarked nonempty new datadir")
            write_new(marker, (self.plan_hash + "\n").encode())
        elif marker.read_text() != self.plan_hash + "\n":
            raise ValueError("new datadir belongs to another generation")
        for relative in (Path("keystore"), Path("cypher")):
            destination = target / relative
            if not destination.exists(): destination.mkdir(mode=0o700)
            directory(destination)
        directory(source / "keystore"); directory(source / "cypher")
        files = [(p, target / "keystore" / p.name) for p in (source / "keystore").iterdir()]
        if len(files) > 256: raise ValueError("keystore count bound")
        files.append((source / "cypher/nodekey", target / "cypher/nodekey"))
        for original, copied in files:
            regular(original, 1024 * 1024)
            if copied.exists():
                regular(copied)
                if copied.read_bytes() != original.read_bytes(): raise ValueError("copied identity differs")
            else:
                write_new(copied, original.read_bytes())

    def init(self):
        if not self.state or self.state["phase"] not in ("archived", "initializing"):
            raise ValueError("whole datadir archive required")
        self.require_stopped(); binary, genesis = self.configuration()
        if shutil.disk_usage(self.base).free < 10 * 1024**3:
            raise ValueError("new generation requires 10GiB free headroom")
        self.state["phase"] = "initializing"; self.save()
        for name, n in self.nodes.items():
            source, target = Path(n["archive_datadir"]), Path(n["old_datadir"])
            s = directory(source)
            if (s.st_dev, s.st_ino) != (n["datadir_device"], n["datadir_inode"]):
                raise ValueError("archived identity source changed")
            self.copy_identities(source, target)
            if name not in self.state["initialized"]:
                self.require_stopped()
                attempt = 1
                while (self.control / (name + ".init-" + str(attempt) + ".log")).exists(): attempt += 1
                self.host.initialize(binary, target, genesis, self.control / (name + ".init-" + str(attempt) + ".log"))
                self.state["initialized"].append(name); self.save()
        for name in ("cypher", "cypher-linux-amd64"):
            target = self.repo / "build/bin" / name; regular(target)
            saved = self.control / ("old-" + name)
            if not saved.exists(): write_new(saved, target.read_bytes(), 0o700)
            if sha(target) not in (sha(saved), self.exec["release_sha256"]): raise ValueError("binary changed during switch")
            atomic(target, binary.read_bytes(), 0o755)
        target = self.repo / "genesis.json"
        if sha(target) not in (self.plan["old_generation"]["genesis_file_sha256"], self.plan["new_generation"]["genesis_sha256"]): raise ValueError("genesis changed during switch")
        atomic(target, genesis.read_bytes())
        activation = self.exec.get("activation")
        if activation:
            inventory = public_json(Path(self.exec["candidate_inventory_file"]))
            runtime = self.repo / "build/stage/live-generation-candidate/runtime"
            if not runtime.exists(): runtime.mkdir(mode=0o700)
            if directory(runtime).st_mode & 0o077:
                raise ValueError("candidate runtime root must be private")
            participants = inventory.get("Participants", [])
            if len(participants) != 7 or {p["Name"] for p in participants} != {"cyphermine", *ADDED_COMMONS}:
                raise ValueError("seven unique Common sidecar parents required")
            for p in participants:
                expected = runtime / p["Name"] / "dex"
                if Path(p["DEXDataDir"]) != expected:
                    raise ValueError("candidate sidecar path is not exact approved runtime layout")
                if expected.exists() or expected.is_symlink():
                    raise ValueError("DEX runtime DB already exists before new generation start")
                if not expected.parent.exists(): expected.parent.mkdir(mode=0o700)
                if directory(expected.parent).st_mode & 0o077:
                    raise ValueError("candidate sidecar parent must be private")
                syncdir(expected.parent)
            syncdir(runtime)
            target = Path(activation["destination"])
            if target.exists() and sha(target) != activation["sha256"]:
                raise ValueError("refuse overwrite of another active deployment")
            atomic(target, Path(activation["source"]).read_bytes())
        self.state["phase"] = "initialized"; self.save()

    def start(self):
        if not self.state or self.state["phase"] != "initialized" or set(self.state["initialized"]) != set(TARGETS):
            raise ValueError("all fourteen normal CLI init results required")
        self.require_stopped(); self.configuration()
        if sha(self.repo / "build/bin/cypher-linux-amd64") != self.exec["release_sha256"] or sha(self.repo / "genesis.json") != self.plan["new_generation"]["genesis_sha256"]:
            raise ValueError("deployed candidate hash mismatch")
        for name, entry in self.state["wrappers"].items():
            saved = self.control / (name + ".wrapper")
            if sha(saved) != entry["sha256"]: raise ValueError("saved launcher mismatch")
            atomic(Path(entry["path"]), saved.read_bytes(), 0o700)
        # Durable BEFORE starting any new process. There is intentionally no
        # automated old-WAL restoration once a start has been attempted.
        self.state["signing_may_have_started"] = True; self.state["phase"] = "start_attempted"; self.save()
        for entry in self.exec["ecosystem_files"]:
            self.host.pm2("restart", entry["path"])
        self.state["phase"] = "started_requires_live_verification"; self.save()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("phase", choices=("preflight", "stop", "archive", "init", "start"))
    p.add_argument("--plan", required=True, type=Path)
    p.add_argument("--approval", type=Path)
    args = p.parse_args()
    if socket.gethostname() != HOST or os.getuid() != 0:
        raise ValueError("named host/root required")
    s = Switch(ROOT, args.plan)
    if args.phase == "preflight": print(json.dumps(s.preflight())); return
    if args.approval is None: raise ValueError("separate actual user approval record required")
    s.invoke(args.phase, args.approval)
    print(json.dumps({"phase": args.phase, "state": s.state["phase"], "plan_sha256": s.plan_hash, "auto_rollback": False}))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as e:
        print(json.dumps({"status": "REFUSED", "reason": str(e) if isinstance(e, ValueError) else "local filesystem/process failure; private state retained"}), file=sys.stderr)
        sys.exit(1)
