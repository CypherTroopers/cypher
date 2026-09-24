#!/usr/bin/env python3
"""Prepare or exec only the two named, generation-bound local settlement relays.

prepare writes into the existing private candidate only; it does not activate,
init, send TX, manage PM2 or load private keys. run requires the active genesis
and source Common's block zero to match, then replaces itself with normal cypher.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import urllib.request
from live_roles import inventory_identity, activated_inventory

ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = Path("build/stage/live-generation-candidate")
NAMES = ("cypherdex-relay0", "cypherdex-relay1")


def safe_read(path, limit=1024*1024):
    path = Path(path)
    if not path.is_absolute() or any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("absolute non-symlink relay path required")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
        raise ValueError("bounded single-link regular relay file required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        actual = os.fstat(stream.fileno())
        if (actual.st_dev, actual.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError("relay file changed during read")
        raw = stream.read(limit+1)
    if len(raw) > limit:
        raise ValueError("relay file exceeds bound")
    return raw


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def hash32(value):
    if isinstance(value, list) and len(value) == 32 and all(type(b) is int and 0 <= b <= 255 for b in value):
        return "0x"+bytes(value).hex()
    raise ValueError("canonical 32-byte relay domain required")


def candidate(repo, selected=None):
    directory = repo / CANDIDATE if selected is None else Path(selected)
    if not directory.is_absolute():
        directory = repo / directory
    stage = repo / "build/stage"
    if (directory == stage or not directory.is_relative_to(stage) or
            directory != directory.resolve() or
            any(p.is_symlink() for p in (directory, *directory.parents))):
        raise ValueError("exact non-symlink project candidate path required")
    if (not directory.is_dir() or directory.stat().st_mode & 0o077 or
            directory.stat().st_uid != os.getuid()):
        raise ValueError("private owned candidate required")
    files = {}
    inventory_raw = safe_read(directory/"public/inventory.json")
    inventory = json.loads(inventory_raw)
    genesis_raw = safe_read(directory/"genesis.json")
    inventory_identity(genesis_raw, inventory)
    files[str(directory/"genesis.json")] = digest(genesis_raw)
    files[str(directory/"public/inventory.json")] = digest(inventory_raw)
    configs = []
    for index in range(2):
        path = directory / f"relays/relay-{index}.json"
        raw = safe_read(path)
        config = json.loads(raw)
        domain = config["Domain"]
        if (config["Version"] != 2 or config["Devnet"] is not True or domain["Version"] != 1 or
                domain["ChainID"] != inventory["ChainID"] or domain["Epoch"] != 1 or
                hash32(domain["Genesis"]) != inventory["Genesis"].lower() or
                hash32(domain["DEXID"]) != inventory["DEXID"].lower() or
                hash32(domain["Committee"]) != inventory["DEXCommittee"].lower() or
                config["DataDir"] != str(directory/f"runtime/relay-{index}") or
                config["SourceURL"] != "http://127.0.0.1:8999" or config["SubmitURL"] != config["SourceURL"] or
                config["DEXURL"] != f"http://127.0.0.1:{19000+index}" or config["MaxHeight"] != 4096):
            raise ValueError("relay domain/path/endpoint differs from candidate")
        files[str(path)] = digest(raw)
        configs.append(config)
    payers = [p for config in configs for p in config["Payers"]]
    if (len(payers) != 6 or len({p["Address"].lower() for p in payers}) != 6 or
            len({p["KeyFile"] for p in payers}) != 6 or
            any(Path(p["KeyFile"]).parent != directory/"keys" for p in payers)):
        raise ValueError("six distinct candidate relay payer identities required")
    return directory, inventory, files


def rpc_source(method, params):
    # This is a startup identity check, not a replacement for the Go source
    # verifier's FHS/MPT authentication. No latest/head flag is trusted here.
    body = json.dumps({"jsonrpc":"2.0", "id":1, "method":method, "params":params}).encode()
    request = urllib.request.Request("http://127.0.0.1:8999", data=body,
                                     headers={"Content-Type":"application/json"})
    with urllib.request.urlopen(request, timeout=8) as response:
        raw = response.read(65537)
    if len(raw) > 65536:
        raise ValueError("source identity response bound")
    result = json.loads(raw)
    if "error" in result:
        raise ValueError("source Common identity RPC unavailable")
    return result["result"]


def command(repo, index, query=rpc_source):
    if type(index) is not int or index not in (0, 1):
        raise ValueError("only relay indices 0 and 1 are authorized")
    genesis_raw = safe_read(repo/"genesis.json")
    active = json.loads(safe_read(repo/"build/stage/live-deployment.json"))
    _, _, active_inventory = activated_inventory(repo, genesis_raw, active)
    inventory_path = Path(active["generation_inventory"])
    directory = inventory_path.parent.parent
    if inventory_path != directory/"public/inventory.json":
        raise ValueError("active inventory must name the candidate public/inventory.json")
    directory, inventory, files = candidate(repo, directory)
    plan = json.loads(safe_read(directory/"pm2-relays/plan.json"))
    if plan.get("version") != 1 or plan.get("files") != files or plan.get("names") != list(NAMES):
        raise ValueError("relay preparation differs from reviewed files")
    if (digest(genesis_raw) != inventory["GenesisSHA256"] or active_inventory != inventory):
        raise ValueError("candidate genesis/domain is not activated; relay remains stopped")
    runtime = directory/"runtime"
    if (not runtime.is_dir() or runtime.is_symlink() or runtime.stat().st_mode & 0o077 or
            runtime.stat().st_uid != os.getuid()):
        raise ValueError("approved private runtime parent must exist after init activation")
    chain = query("eth_chainId", [])
    block = query("eth_getBlockByNumber", ["0x0", False])
    if (not isinstance(chain, str) or int(chain, 16) != inventory["ChainID"] or
            not isinstance(block, dict) or block.get("hash", "").lower() != inventory["Genesis"].lower()):
        raise ValueError("source Common still runs a different genesis; relay remains stopped")
    binary = repo/"build/bin/cypher-linux-amd64"
    if binary.is_symlink() or not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError("normal installed cypher binary unavailable")
    return [str(binary), "dex-relay", "--relay.config", str(directory/f"relays/relay-{index}.json")]


def write_new(path, data, mode=0o600):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def prepare(repo, candidate_path=None):
    directory, inventory, files = candidate(repo, candidate_path)
    output = directory/"pm2-relays"
    output.mkdir(mode=0o700, exist_ok=False)
    apps = []
    for index, name in enumerate(NAMES):
        wrapper = output/f"start-{name}.sh"
        write_new(wrapper, ('#!/usr/bin/env bash\nset -euo pipefail\nexec python3 "'+str(repo/"scripts/dex/live_relay.py")+'" run --index '+str(index)+'\n').encode(), 0o700)
        apps.append({"name":name, "script":str(wrapper), "cwd":str(repo), "interpreter":"bash",
                     "exec_mode":"fork", "autorestart":True, "watch":False, "treekill":True,
                     "kill_timeout":30000, "restart_delay":5000, "min_uptime":10000, "max_restarts":5,
                     "out_file":str(output/f"{name}.out.log"), "error_file":str(output/f"{name}.err.log")})
    write_new(output/"ecosystem.json", (json.dumps({"apps":apps}, indent=2)+"\n").encode())
    plan = {"version":1, "names":list(NAMES), "files":files, "genesis":inventory["Genesis"],
            "chain_id":inventory["ChainID"], "dex_id":inventory["DEXID"], "started":False,
            "scope":"prepared only; no PM2, init, DB opening, key reading or transaction"}
    write_new(output/"plan.json", (json.dumps(plan, indent=2)+"\n").encode())
    readme = """# Prepared named relay launchers — NOT STARTED

Only cypherdex-relay0 and cypherdex-relay1 are described here. This directory
does not manage DEX validator sidecars: their seven Common parents own them.
Each wrapper execs the checked Python launcher, which execs normal build/bin
cypher-linux-amd64 dex-relay --relay.config with its exact candidate config.

After the user performs generation init, normal Common RPC/admission
activation and gas funding, the operator may start this ecosystem with PM2.
The launcher rejects the old genesis, missing local-deployment activation,
changed candidate files and mismatching source Common block zero before exec.
This identity check does not replace the relay's FHS/MPT verifier.
The chain ID is inventory-bound, not hard-coded. Retaining the previous chain
ID does not prevent replay of old ordinary CLX signed transactions; a fresh
DEX domain and these launcher checks do not change ordinary transaction rules.

Runtime data remains under candidate/runtime/relay-0 and relay-1. Existing
signed TX, nonces, source history and jobs must be resumed; never erase them
to restart. The Go CLI holds an exclusive root lock and validates payer keys.
PM2 uses a 30 second graceful exit timeout, process-tree cleanup, 5 second
restart delay and at most 5 unstable restarts. For planned fault tests, stop
only the named app and verify its owned process tree has actually exited.
Inspect actual PM2 signal/exit status; a timeout kill is not a graceful stop.

No application has been registered or started by preparation. Before first
start, inspect PM2 names to avoid creating a second owner of these datadirs.
Logs are inside this private directory; never publish secret files or PM2 env.
"""
    write_new(output/"README.md", readme.encode())
    fd = os.open(output, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return plan


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "print", "run"))
    parser.add_argument("--index", type=int)
    parser.add_argument("--candidate", type=Path,
                        help="prepare only: exact candidate directory under project build/stage")
    args = parser.parse_args()
    if args.mode == "prepare":
        print(json.dumps(prepare(ROOT, args.candidate)))
    else:
        if args.candidate is not None:
            parser.error("run/print select the authenticated active deployment; --candidate is prepare-only")
        invocation = command(ROOT, args.index)
        if args.mode == "print":
            print(json.dumps(invocation))
        else:
            if os.geteuid() != 0 or os.uname().nodename != "vmi3365213":
                raise SystemExit("named host/root required")
            os.chdir(ROOT)
            os.execv(invocation[0], invocation)
