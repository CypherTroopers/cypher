#!/usr/bin/env python3
"""Initialize/start only six NEW Commons on the existing approved CLX genesis.

This does not reset any old datadir or install the candidate DEX genesis. Every
index is explicit; fresh private configuration, empty datadir, and absent PM2
name are required. Existing nodes and optional jobs remain untouched.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import time

from live_common import ROOT, command, layout, prepare
from live_observe import digest

OLD_GENESIS_FILE_HASH = "131acbb21ef77f4229c91a639c51348bc1d0f0f5b6c4cbf4299e46c90efd4b1f"
Q1_BINARY = "33f22a4677f35baf7d6e492b46931b8436566a17a2d5fa3f0aed1977ebee768e"


def execute(index, output):
    if socket.gethostname() != "vmi3365213" or os.getuid() != 0:
        raise ValueError("wrong authorized host/user")
    if output.exists():
        raise ValueError("fresh run record required")
    if digest(ROOT / "genesis.json") != OLD_GENESIS_FILE_HASH or digest(ROOT / "build/bin/cypher-linux-amd64") != Q1_BINARY:
        raise ValueError("reviewed current genesis/release changed")
    daemon = Path("/root/.pm2/pm2.pid")
    if not daemon.is_file() or not (Path("/proc") / daemon.read_text().strip()).is_dir():
        raise ValueError("existing PM2 daemon required")
    apps = json.loads(subprocess.check_output(["pm2", "jlist"], timeout=15))
    name = "cypherdex" + str(index)
    if any(a.get("name") == name for a in apps):
        raise ValueError("PM2 target already exists; refusing duplicate start")
    mem = {line.split(":")[0]: int(line.split()[1]) for line in Path("/proc/meminfo").read_text().splitlines()}
    if mem["MemAvailable"] < 10 * 1024 * 1024:
        raise ValueError("less than 10GiB available; stop adding new workload")
    inventory = json.loads((ROOT / "build/stage/live-generation-candidate/public/inventory.json").read_text())
    member = next(p for p in inventory["Participants"] if p["Name"] == name)
    owner = member["CommonWallet"]
    invocation = command(ROOT, index, owner)
    datadir = Path(invocation[invocation.index("--datadir") + 1])
    if str(datadir) != member["CLXDataDir"] or datadir.exists() or datadir.is_symlink():
        raise ValueError("exact NEW empty Common datadir required")
    for port, kind in ((6200 + index, socket.SOCK_STREAM), (6200 + index, socket.SOCK_DGRAM),
                       (7200 + 2 * index, socket.SOCK_DGRAM), (7201 + 2 * index, socket.SOCK_DGRAM)):
        with socket.socket(socket.AF_INET, kind) as listener:
            listener.bind(("127.0.0.1", port))
    plan = prepare(ROOT, index, owner)
    directory = layout(ROOT, index)
    result = {"status": "INITIALIZING_NEW_COMMON", "app": name, "datadir": str(datadir),
              "binary_sha256": Q1_BINARY, "genesis_file_sha256": OLD_GENESIS_FILE_HASH,
              "old_datadirs_reset": False, "dex_enabled": False, "pow_started": False,
              "mem_available_before_kib": mem["MemAvailable"], "start_time": time.time()}
    def save():
        temp = output.with_suffix(".new")
        temp.write_text(json.dumps(result, indent=2) + "\n")
        temp.replace(output)
    save()
    try:
        with (directory / "init.log").open("x") as log:
            subprocess.run([invocation[0], "--datadir", str(datadir), "--cache", "128",
                            "init", str(ROOT / "genesis.json")], stdout=log, stderr=subprocess.STDOUT,
                           timeout=90, check=True, cwd=ROOT)
        result["initialized_current_genesis"] = True
        # Verify the real CLI's resolved listen address; never infer it only
        # from TOML. dumpconfig runs only against this new, stopped datadir.
        with (directory / "dumpconfig.stderr").open("x") as log:
            subprocess.run(invocation + ["dumpconfig", str(directory / "resolved.toml")],
                           stdout=log, stderr=subprocess.STDOUT, timeout=45, check=True, cwd=ROOT)
        import tomllib
        resolved = tomllib.loads((directory / "resolved.toml").read_text())
        if resolved["Node"]["P2P"]["ListenAddr"] != plan["p2p_listen"]:
            raise ValueError("CLI overrode private listen address")
        result["p2p_listen"] = plan["p2p_listen"]
        save()
        with (directory / "pm2-start.log").open("x") as log:
            subprocess.run(["pm2", "start", str(directory / "ecosystem.json"), "--only", name],
                           stdout=log, stderr=subprocess.STDOUT, timeout=40, check=True)
        result["status"] = "START_REQUESTED_NOT_SYNC_VERIFIED"
        result["end_time"] = time.time()
        save()
        return result
    except Exception as error:
        result["status"] = "FAIL"
        result["error_class"] = type(error).__name__
        save()
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", type=int, choices=range(1, 7), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(execute(args.index, args.output)))
