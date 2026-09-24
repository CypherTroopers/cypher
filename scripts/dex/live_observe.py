#!/usr/bin/env python3
"""Read-only observation of the eight explicitly authorized live PM2 apps.

Never print PM2 environment, arbitrary arguments, keystores or RPC errors. IPC
methods are a closed read-only list. Run with host visibility, not via nsenter.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import socket
import subprocess
import time
import urllib.request

APPS = tuple("cypher" + str(i) for i in range(7)) + ("cyphermine",)
ADDED_COMMONS = tuple("cypherdex" + str(i) for i in range(1, 7))
RELAYS = ("cypherdex-relay0", "cypherdex-relay1")
SAFE_FLAGS = {"--datadir", "--port", "--rnetport", "--networkid", "--config",
              "--http.addr", "--http.port", "--ws.addr", "--ws.port",
              "--ipcpath", "--dex.config", "--relay.config", "--syncmode",
              "--gcmode", "--cache", "--cache.trie.journal", "--nat"}
BOOL_FLAGS = {"--dex.validator", "--mine", "--http", "--ws", "--nodiscover"}
BLOCK_FIELDS = ("number", "hash", "parentHash", "stateRoot", "transactionsRoot",
                "receiptsRoot", "gasUsed", "gasLimit", "timestamp", "keyHash")


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_args(args):
    result = {}
    for i, item in enumerate(args):
        name, sep, value = item.partition("=")
        if name in SAFE_FLAGS:
            result[name] = value if sep else args[i + 1] if i + 1 < len(args) else None
        elif name in BOOL_FLAGS:
            result[name] = value if sep else True
    return result


def processes():
    found = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text().rsplit(") ", 1)[1].split()
            found[int(entry.name)] = (int(stat[1]), int(stat[19]), stat)
        except (OSError, ValueError, IndexError):
            continue
    return found


def descendant_pids(root_pid, table):
    # PM2 uses pid=0 for stopped apps. It is a sentinel, not a /proc process:
    # following PPid=0 would incorrectly adopt PID 1 and the entire host tree.
    # A root missing from this snapshot also cannot establish app ownership.
    if type(root_pid) is not int or root_pid <= 0 or root_pid not in table:
        return set()
    descendants = {root_pid}
    while True:
        expanded = descendants | {pid for pid, (parent, _, _) in table.items()
                                  if parent in descendants}
        if expanded == descendants:
            return descendants
        descendants = expanded


def process(pid, table):
    base = Path("/proc") / str(pid)
    parent, ticks, stat = table[pid]
    args = (base / "cmdline").read_bytes().decode(errors="replace").split("\0")
    status = (base / "status").read_text().splitlines()
    memory = {line.split(":", 1)[0]: line.split(":", 1)[1].strip()
              for line in status if line.startswith(("VmRSS:", "VmHWM:", "VmSwap:", "VmLck:", "Threads:"))}
    exe = os.readlink(base / "exe")
    result = {"pid": pid, "ppid": parent, "start_ticks": ticks,
              "comm": (base / "comm").read_text().strip(),
              "exe": exe, "exe_sha256": digest(base / "exe"),
              "cwd": os.readlink(base / "cwd"), "flags": safe_args(args),
              "memory": memory, "cpu_user_ticks": int(stat[11]), "cpu_system_ticks": int(stat[12])}
    result["role"] = next((a for a in args[1:2] if a in ("dex-validator", "dex-relay")), "clx-or-wrapper")
    result["dag_mappings"] = [line.split()[-1] for line in (base / "maps").read_text().splitlines()
                              if "colossus" in line.lower() or "/full-R" in line or "/cache-R" in line]
    result["dag_mappings"] = sorted(set(result["dag_mappings"]))
    return result


def rpc(ipc, method, params=()):
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(8)
        conn.connect(str(ipc))
        conn.sendall(json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)}).encode() + b"\n")
        data = b""
        while len(data) <= 4 * 1024 * 1024:
            chunk = conn.recv(65536)
            if not chunk:
                raise ValueError("truncated RPC")
            data += chunk
            try:
                value = json.loads(data)
            except json.JSONDecodeError:
                continue
            if "error" in value:
                return {"error_code": value["error"].get("code")}
            return value.get("result")
        raise ValueError("RPC byte cap")


def observation(repo, include_added_commons=False, include_relays=False):
    names = APPS + ADDED_COMMONS if include_added_commons else APPS
    if include_relays:
        names += RELAYS
    daemon = Path("/root/.pm2/pm2.pid")
    if not daemon.is_file() or not (Path("/proc") / daemon.read_text().strip()).is_dir():
        raise RuntimeError("existing PM2 daemon unavailable; refusing to start one")
    apps = json.loads(subprocess.check_output(["pm2", "jlist"], timeout=15))
    table = processes()
    result = {"observed_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "host": socket.gethostname(), "uid": os.getuid(), "workspace": str(repo),
              "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
              "clock_ticks": os.sysconf("SC_CLK_TCK"), "apps": [],
              "other_pm2_app_count": sum(a.get("name") not in names for a in apps),
              "meminfo": Path("/proc/meminfo").read_text(),
              "observer_memlock": resource.getrlimit(resource.RLIMIT_MEMLOCK),
              "loadavg": os.getloadavg()}
    for app in apps:
        if app.get("name") not in names:
            continue
        env = app["pm2_env"]
        item = {key: app.get(key) for key in ("name", "pm_id", "pid")}
        item["pm2"] = {key: env.get(key) for key in ("status", "pm_exec_path", "pm_cwd",
                      "exec_interpreter", "exec_mode", "autorestart", "kill_timeout", "restart_delay", "watch", "restart_time")}
        descendants = descendant_pids(app.get("pid"), table)
        item["processes"] = []
        for pid in sorted(descendants):
            if pid in table:
                try:
                    item["processes"].append(process(pid, table))
                except OSError as error:
                    item["processes"].append({"pid": pid, "observation_error": type(error).__name__})
        nodes = [p for p in item["processes"] if "--datadir" in p.get("flags", {})]
        for node in nodes:
            datadir = Path(node["flags"]["--datadir"])
            if not datadir.is_absolute():
                datadir = Path(node["cwd"]) / datadir
            node["datadir"] = str(datadir.resolve())
            ipc = datadir / "cypher.ipc"
            node["ipc"] = str(ipc)
            node["rpc"] = {}
            methods = [("chain_id", "eth_chainId", []), ("peer_count", "net_peerCount", []),
                       ("mining", "eth_mining", []), ("miner_status", "miner_status", []),
                       ("coinbase", "eth_coinbase", []), ("syncing", "eth_syncing", []),
                       ("genesis", "eth_getBlockByNumber", ["0x0", False]),
                       ("latest", "eth_getBlockByNumber", ["latest", False]),
                       ("key", "eth_getKeyBlockByNumber", ["latest"]),
                       ("dex_execution", "debug_dexExecutionStats", [])]
            for label, method, params in methods:
                try:
                    value = rpc(ipc, method, params)
                    if label in ("latest", "genesis") and isinstance(value, dict):
                        value = {k: value[k] for k in BLOCK_FIELDS + ("error_code",) if k in value}
                    elif label == "key" and isinstance(value, dict):
                        value = {k: value[k] for k in ("hash", "keyBlockNumber", "number", "parentHash", "leader", "error_code") if k in value}
                    node["rpc"][label] = value
                except (OSError, ValueError) as error:
                    node["rpc"][label] = {"observation_error": type(error).__name__}
        if include_added_commons and app["name"] in ("cyphermine",) + ADDED_COMMONS:
            index = (("cyphermine",) + ADDED_COMMONS).index(app["name"])
            try:
                # This is local observation, never a new finality trust root.
                url = "http://127.0.0.1:" + str(19000 + index) + "/v1/status"
                with urllib.request.urlopen(url, timeout=3) as response:
                    raw = response.read(65537)
                if len(raw) > 65536:
                    raise ValueError("DEX status byte bound")
                value = json.loads(raw)
                item["dex_observation"] = {k: value[k] for k in
                    ("State", "Certified", "Finalized", "PendingTransport", "Execution", "Storage") if k in value}
            except (OSError, ValueError) as error:
                item["dex_observation"] = {"observation_error": type(error).__name__}
        result["apps"].append(item)
    result["deployed"] = [{"path": str(p), "sha256": digest(p), "bytes": p.stat().st_size}
                          for p in (repo / "build/bin/cypher", repo / "build/bin/cypher-linux-amd64") if p.is_file()]
    result["disk"] = {str(p): {"free_bytes": os.statvfs(p).f_bavail * os.statvfs(p).f_frsize}
                      for p in (repo, Path("/tmp"))}
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--include-added-commons", action="store_true")
    parser.add_argument("--include-relays", action="store_true")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    result = observation(repo, args.include_added_commons, args.include_relays)
    output = Path(args.output)
    with output.open("x") as f:
        json.dump(result, f, indent=2)
        f.write("\n")
    print(json.dumps({"path": str(output), "apps": len(result["apps"]),
                      "sha256": digest(output), "host": result["host"]}))
