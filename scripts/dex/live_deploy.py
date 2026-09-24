#!/usr/bin/env python3
"""Explicit eight-app deployment phases; never initializes or rewinds a DB.

Each phase is separately invoked after reviewing the previous result. PM2 raw
environment and application logs are not copied into the public journal.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from live_observe import APPS, digest, observation, processes

REPO = Path(__file__).resolve().parents[2]
RELEASE = REPO / "build/stage/live-q1-release"
OLD_HASH = "bcfb21b13a82eb0a9ffdfec843a5d7c3dededf735607da680b8dfa43db2759f8"
NEW_HASH = "33f22a4677f35baf7d6e492b46931b8436566a17a2d5fa3f0aed1977ebee768e"


def pm2(*args):
    value = subprocess.run(["pm2", *args], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=180)
    if value.returncode:
        raise RuntimeError("PM2 command failed; raw environment/output withheld")


def app_list():
    daemon = Path("/root/.pm2/pm2.pid")
    if not daemon.is_file() or not (Path("/proc") / daemon.read_text().strip()).is_dir():
        raise ValueError("existing PM2 daemon required; refusing implicit daemon start")
    apps = json.loads(subprocess.check_output(["pm2", "jlist"], timeout=15))
    selected = [a for a in apps if a.get("name") in APPS]
    if len(selected) != 8 or {a["name"] for a in selected} != set(APPS):
        raise ValueError("exactly one of each authorized PM2 app required")
    if any(Path(a["pm2_env"]["pm_cwd"]).resolve() != REPO for a in selected):
        raise ValueError("PM2 cwd mismatch")
    return selected


def write_once(path, obj):
    with path.open("x") as f:
        json.dump(obj, f, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())


def require_stopped():
    apps = app_list()
    if any(a["pid"] or a["pm2_env"]["status"] != "stopped" for a in apps):
        raise ValueError("all eight authorized apps must be stopped")
    # Check every process, including possible orphans outside the PM2 tree.
    for pid in processes():
        try:
            args = (Path("/proc") / str(pid) / "cmdline").read_bytes().split(b"\0")
            cwd = Path(os.readlink(Path("/proc") / str(pid) / "cwd"))
            for i, arg in enumerate(args):
                value = arg.split(b"=", 1)[1] if arg.startswith(b"--datadir=") else args[i + 1] if arg == b"--datadir" and i + 1 < len(args) else None
                if value is not None:
                    path = Path(os.fsdecode(value))
                    path = (cwd / path).resolve() if not path.is_absolute() else path.resolve()
                    if path in {REPO / ("chaindb" + str(n)) for n in range(7)} | {REPO / "chaindbmine"}:
                        raise ValueError("owned datadir still has a live process")
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    return apps


def stop(out):
    if digest(RELEASE / "bin/cypher-linux-amd64") != NEW_HASH:
        raise ValueError("release hash mismatch")
    apps = app_list()
    before = observation(REPO)
    expected_dirs = {str(REPO / ("chaindb" + str(n))) for n in range(7)} | {str(REPO / "chaindbmine")}
    nodes = [p for a in before["apps"] for p in a["processes"] if "datadir" in p]
    if len(nodes) != 8 or {p["datadir"] for p in nodes} != expected_dirs:
        raise ValueError("process/datadir mismatch")
    if any(p["exe_sha256"] != OLD_HASH for p in nodes):
        raise ValueError("unexpected running executable")
    for a in apps:
        if a["pm2_env"]["pm_exec_path"] != str(REPO / ("start-" + a["name"] + ".sh")):
            raise ValueError("unexpected current PM2 entry")
        if a["pm2_env"].get("shutdown_with_message"):
            raise ValueError("unexpected PM2 message-based shutdown")
        if a["pm2_env"].get("args"):
            raise ValueError("unreviewed PM2 arguments")
    write_once(out / "q1-pre-stop.json", before)
    # PM2 stop ignores new kill_timeout options; config restart does merge it
    # before signaling. PM2 also keeps the existing pm_exec_path on restart, so
    # use the SAME reviewed wrapper path, temporarily containing only exit 0.
    # Original scripts must match the private start-of-task backup exactly.
    private = out.parent / "private"
    replacements = []
    for app in apps:
        name = "start-" + app["name"] + ".sh"
        target, saved = REPO / name, private / name
        if not saved.is_file() or target.is_symlink() or digest(target) != digest(saved):
            raise ValueError("wrapper differs from preserved original")
        replacements.append(target)
    for target in replacements:
        temporary = target.with_suffix(".sh.maintenance-new")
        with temporary.open("x") as f:
            f.write("#!/usr/bin/env bash\n# Planned deployment stop; no DB access.\nexit 0\n")
            f.flush()
            os.fsync(f.fileno())
        temporary.chmod(0o755)
        os.replace(temporary, target)
    fd = os.open(REPO, os.O_DIRECTORY)
    os.fsync(fd)
    os.close(fd)
    config = {"apps": [{"name": a["name"], "script": str(REPO / ("start-" + a["name"] + ".sh")), "cwd": str(REPO),
                       "interpreter": "bash", "exec_mode": "fork", "autorestart": False,
                       "watch": False, "kill_timeout": 60000, "restart_delay": 0,
                       "treekill": True} for a in apps]}
    maintenance = RELEASE / "maintenance.json"
    write_once(maintenance, config)
    pm2("restart", str(maintenance))
    deadline = time.monotonic() + 65
    while True:
        try:
            require_stopped()
            break
        except ValueError:
            if time.monotonic() > deadline:
                raise
            time.sleep(.5)
    table = processes()
    previous = [p for a in before["apps"] for p in a["processes"]]
    if any(p["pid"] in table and table[p["pid"]][1] == p["start_ticks"] for p in previous):
        raise ValueError("prior owned process still exists")
    write_once(out / "q1-stopped.json", {"utc": time.time(), "owned_processes_exited": len(previous),
               "apps": list(APPS), "method": "PM2 named maintenance restart, 60s graceful timeout",
               "forced_exit_status": "inspect PM2 exit records; not inferred from absence"})


def backup(out):
    require_stopped()
    root = RELEASE / "cold-backup"
    sources = [REPO / name for name in ["chaindb" + str(n) for n in range(7)] + ["chaindbmine"]]
    total = sum(p.stat().st_size for source in sources for p in source.rglob("*") if p.is_file() and not p.is_symlink())
    if shutil.disk_usage(RELEASE).free < total + 10 * 1024**3:
        raise ValueError("cold backup needs all source bytes plus 10 GiB headroom")
    root.mkdir(mode=0o700)
    inventory = []
    for source in sources:
        name = source.name
        if source.is_symlink() or not source.is_dir():
            raise ValueError("datadir must be a regular directory")
        subprocess.run(["cp", "-a", "--reflink=auto", "--", str(source), str(root / name)], check=True)
        count = size = 0
        for original in source.rglob("*"):
            copied = root / name / original.relative_to(source)
            if original.is_symlink():
                if not copied.is_symlink() or os.readlink(original) != os.readlink(copied):
                    raise ValueError("backup symlink mismatch")
            elif original.is_file():
                if original.stat().st_size != copied.stat().st_size or digest(original) != digest(copied):
                    raise ValueError("cold backup file hash mismatch")
                count += 1
                size += original.stat().st_size
        inventory.append({"datadir": name, "regular_files_verified": count, "bytes_verified": size})
    subprocess.run(["sync", "-f", str(root)], check=True)
    require_stopped()
    write_once(out / "q1-cold-backup.json", {"path": str(root), "apps": list(APPS),
               "method": "cp -a --reflink=auto while all DB writers stopped; every regular file size/hash compared; sync -f",
               "inventory": inventory, "auto_restore": False})


def install(out):
    require_stopped()
    if not (out / "q1-cold-backup.json").is_file():
        raise ValueError("completed cold backup required")
    source = RELEASE / "bin/cypher-linux-amd64"
    if digest(source) != NEW_HASH:
        raise ValueError("release hash mismatch")
    changes = []
    for name in ("cypher", "cypher-linux-amd64"):
        target = REPO / "build/bin" / name
        if target.is_symlink() or digest(target) != OLD_HASH:
            raise ValueError("deployed binary differs from reviewed precondition")
        temporary = target.with_name(name + ".live-q1-new")
        with temporary.open("xb") as dst, source.open("rb") as src:
            shutil.copyfileobj(src, dst)
            dst.flush()
            os.fsync(dst.fileno())
        temporary.chmod(0o755)
        if digest(temporary) != NEW_HASH:
            raise ValueError("staged copy mismatch")
        os.replace(temporary, target)
        changes.append({"path": str(target), "before": OLD_HASH, "after": NEW_HASH})
    for name in APPS:
        target = REPO / ("start-" + name + ".sh")
        old = digest(target)
        content = '#!/usr/bin/env bash\nset -euo pipefail\nexec python3 "' + str(REPO / "scripts/dex/live_start.py") + '" ' + name + '\n'
        temporary = target.with_suffix(".sh.live-q1-new")
        with temporary.open("x") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        temporary.chmod(0o755)
        os.replace(temporary, target)
        changes.append({"path": str(target), "before": old, "after": digest(target)})
    for directory in (REPO, REPO / "build/bin"):
        fd = os.open(directory, os.O_DIRECTORY)
        os.fsync(fd)
        os.close(fd)
    write_once(out / "q1-installed.json", {"utc": time.time(), "changes": changes, "genesis_changed": False})


def start(out):
    require_stopped()
    if not (out / "q1-installed.json").is_file() or digest(REPO / "build/bin/cypher-linux-amd64") != NEW_HASH:
        raise ValueError("completed reviewed install required")
    pm2("restart", str(REPO / "scripts/dex/live-ecosystem.json"))
    write_once(out / "q1-start-requested.json", {"utc": time.time(), "apps": list(APPS),
               "consensus_identity_restore": "separate existing miner.start through local IPC", "init": False})


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("stop", "backup", "install", "start"))
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    out = Path(args.output_dir).resolve()
    if not out.is_dir() or os.uname().nodename != "vmi3365213" or os.getuid() != 0:
        raise SystemExit("authorized host/root and existing output directory required")
    globals()[args.phase](out)
    print(json.dumps({"phase": args.phase, "status": "completed", "output": str(out)}))
