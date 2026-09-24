#!/usr/bin/env python3
"""Produce a non-executable, secret-free reset plan for the eight owned apps.

This module has no PM2, process-control, rename, copy, delete, signing or init
implementation. A plan never authorizes an intermediate reset. Secret files are
only lstat'ed; their content and names inside keystore are not serialized.
"""
import argparse
import calendar
import hashlib
import json
from pathlib import Path
import re
import socket
import stat
import sys
import time

HOST = "vmi3365213"
APPS = tuple("cypher" + str(i) for i in range(7)) + ("cyphermine",)
ADDED_COMMONS = tuple("cypherdex" + str(i) for i in range(1, 7))
MAX_PUBLIC_JSON = 8 * 1024 * 1024
HEX32 = re.compile(r"0x[0-9a-fA-F]{64}\Z")


def regular(path, limit=None):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("regular non-linked file required")
    if limit is not None and info.st_size > limit:
        raise ValueError("public input exceeds byte bound")
    return info


def public_json(path):
    regular(path, MAX_PUBLIC_JSON)
    try:
        value = json.loads(path.read_bytes())
    except (ValueError, UnicodeError):
        raise ValueError("invalid public JSON") from None
    if not isinstance(value, dict):
        raise ValueError("public JSON object required")
    return value


def public_hash(path):
    regular(path, MAX_PUBLIC_JSON)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or path != path.resolve():
        raise ValueError("existing non-symlink directory required")
    return info


def hash32(value):
    if not isinstance(value, str) or not HEX32.fullmatch(value) or int(value, 16) == 0:
        raise ValueError("nonzero 32-byte public hash required")
    return value.lower()


def chain_id(value):
    if type(value) is not int or not 0 < value < 2**64:
        raise ValueError("positive uint64 chain ID required")
    return value


def inspect_key_paths(datadir):
    """Do not read or hash key contents, even for audit output."""
    keystore = datadir / "keystore"
    directory(keystore)
    count = 0
    for entry in keystore.iterdir():
        regular(entry)
        count += 1
        if count > 256:
            raise ValueError("keystore entry count requires manual review")
    nodekey = datadir / "cypher/nodekey"
    directory(nodekey.parent)
    regular(nodekey)
    return [{"relative_path": "keystore", "regular_file_count": count,
             "purpose": "wallet keys only; do not import old nonce or balances"},
            {"relative_path": "cypher/nodekey", "regular_file_count": 1,
             "purpose": "P2P identity only; never duplicate a running identity"}]


def plan(workspace, observation, new_chain_id, dex_id, new_genesis=None, now=None, include_added_commons=False, allow_stopped_added_commons=False, preserve_chain_id=False):
    if type(allow_stopped_added_commons) is not bool or (allow_stopped_added_commons and not include_added_commons):
        raise ValueError("stopped Common mode requires explicit added-Common inventory")
    targets = APPS + ADDED_COMMONS if include_added_commons else APPS
    workspace = Path(workspace)
    directory(workspace)
    new_chain_id = chain_id(new_chain_id)
    dex_id = hash32(dex_id)
    now = time.time() if now is None else now
    if observation.get("host") != HOST or observation.get("uid") != 0 or observation.get("workspace") != str(workspace):
        raise ValueError("observation host, user or workspace mismatch")
    try:
        observed = calendar.timegm(time.strptime(observation["observed_utc"], "%Y-%m-%dT%H:%M:%SZ"))
    except (KeyError, TypeError, ValueError, OverflowError):
        raise ValueError("invalid observation timestamp") from None
    if now < observed - 30 or now - observed > 900:
        raise ValueError("fresh observation within 15 minutes required")
    boot_id = observation.get("boot_id")
    if not isinstance(boot_id, str) or not re.fullmatch(r"[0-9a-f-]{36}", boot_id):
        raise ValueError("observed boot ID required")
    apps = observation.get("apps")
    if not isinstance(apps, list) or len(apps) != len(targets) or {a.get("name") for a in apps} != set(targets):
        raise ValueError("exact selected eight/fourteen-app inventory required; re-inventory other roles")
    old_genesis = workspace / "genesis.json"
    old = public_json(old_genesis)
    old_config = old.get("config", {})
    old_chain_id = chain_id(old_config.get("chainId"))
    if type(preserve_chain_id) is not bool:
        raise ValueError("explicit boolean chain-ID preservation mode required")
    if preserve_chain_id:
        if old_chain_id != new_chain_id:
            raise ValueError("chain ID must remain unchanged in preservation mode")
    elif old_chain_id == new_chain_id:
        raise ValueError("same chain ID requires explicit preserve-chain-id mode; ordinary TX replay is not separated")
    old_dex = old_config.get("dexDevnet")
    if old_dex and hash32(old_dex.get("dexId")) == dex_id:
        raise ValueError("new DEX deployment ID required")
    generation = "chain-" + str(new_chain_id) + "-dex-" + dex_id[2:18]
    archive_parent = workspace / "build/stage/live-generations"
    if archive_parent.exists() or archive_parent.is_symlink():
        directory(archive_parent)
    archive = archive_parent / generation
    if archive.exists() or archive.is_symlink():
        raise ValueError("archive destination already exists")
    nodes, genesis_hashes, genesis_roots = [], set(), set()
    pids, identities, seen_dirs = set(), set(), set()
    for name in targets:
        app = next(a for a in apps if a["name"] == name)
        suffix = "mine" if name == "cyphermine" else name.removeprefix("cypher")
        datadir = (workspace / "build/stage/live-commons" / ("chaindbdex" + name.removeprefix("cypherdex"))
                   if name in ADDED_COMMONS else workspace / ("chaindb" + suffix))
        info = directory(datadir)
        identity = (info.st_dev, info.st_ino)
        if identity in identities or str(datadir) in seen_dirs:
            raise ValueError("duplicate datadir identity")
        identities.add(identity)
        seen_dirs.add(str(datadir))
        status = app.get("pm2", {}).get("status")
        if status == "stopped":
            if not allow_stopped_added_commons or name not in ADDED_COMMONS or type(app.get("pid")) is not int or app["pid"] != 0 or app.get("processes") != []:
                raise ValueError("only explicitly inventoried stopped added Commons may lack a process")
            nodes.append({"pm2_name": name, "pm2_id": app.get("pm_id"),
                          "observed_status": "stopped", "observed_pid": 0,
                          "observed_start_ticks": None, "observed_exe_sha256": None,
                          "old_db_genesis_status": "NOT_OBSERVED_STOPPED",
                          "old_datadir": str(datadir), "archive_datadir": str(archive / datadir.name),
                          "datadir_device": info.st_dev, "datadir_inode": info.st_ino,
                          "selected_identity_copy": inspect_key_paths(datadir)})
            continue
        if status != "online" or type(app.get("pid")) is not int or app["pid"] <= 1:
            raise ValueError("explicit online PM2 process required")
        candidates = [p for p in app.get("processes", []) if "--datadir" in p.get("flags", {})]
        if len(candidates) != 1:
            raise ValueError("exactly one observed CLX process per app required")
        node = candidates[0]
        if node.get("datadir") != str(datadir):
            raise ValueError("observed datadir does not match exact allowlist")
        if node.get("pid") in pids or type(node.get("pid")) is not int or node["pid"] != app["pid"]:
            raise ValueError("unique observed PID required")
        pids.add(node["pid"])
        if type(node.get("start_ticks")) is not int or node["start_ticks"] <= 0:
            raise ValueError("observed process start ticks required")
        if not isinstance(node.get("exe_sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", node["exe_sha256"]):
            raise ValueError("observed executable digest required")
        rpc = node.get("rpc", {})
        try:
            observed_chain_id = int(rpc.get("chain_id", ""), 16)
        except (TypeError, ValueError):
            raise ValueError("read-only chain identity observation required") from None
        if observed_chain_id != old_chain_id:
            raise ValueError("RPC chain ID and old genesis file differ")
        genesis = rpc.get("genesis", {})
        if genesis.get("number") != "0x0":
            raise ValueError("explicit genesis block observation required")
        genesis_hashes.add(hash32(genesis.get("hash")))
        genesis_roots.add(hash32(genesis.get("stateRoot")))
        nodes.append({"pm2_name": name, "pm2_id": app.get("pm_id"),
                      "observed_status": "online", "observed_exe_sha256": node["exe_sha256"],
                      "old_db_genesis_status": "RPC_OBSERVED",
                      "observed_pid": node["pid"], "observed_start_ticks": node["start_ticks"],
                      "old_datadir": str(datadir), "archive_datadir": str(archive / datadir.name),
                      "datadir_device": info.st_dev, "datadir_inode": info.st_ino,
                      "selected_identity_copy": inspect_key_paths(datadir)})
    if len(genesis_hashes) != 1 or len(genesis_roots) != 1:
        raise ValueError("existing nodes disagree on genesis hash or state root")
    new = {"chain_id": new_chain_id, "dex_deployment_id": dex_id,
           "epoch": 1, "genesis_hash": None, "genesis_validation": "NOT_RUN",
           "genesis_file": None, "genesis_sha256": None}
    if new_genesis is not None:
        new_genesis = Path(new_genesis)
        if not new_genesis.is_absolute() or new_genesis == old_genesis:
            raise ValueError("separate absolute candidate genesis file required")
        candidate = public_json(new_genesis)
        config = candidate.get("config", {})
        dex = config.get("dexDevnet", {})
        if chain_id(config.get("chainId")) != new_chain_id or hash32(dex.get("dexId")) != dex_id:
            raise ValueError("candidate generation differs from declared IDs")
        if not config.get("fairHotstuff") or not config.get("fixedCommittee") or config.get("fixedLeader") or len(config.get("committee", {})) != 7 or len(dex.get("committee", [])) != 7:
            raise ValueError("candidate must retain seven fixed CLX and separate seven DEX registrations")
        new.update({"genesis_file": str(new_genesis), "genesis_sha256": public_hash(new_genesis),
                    "genesis_validation": "JSON_IDENTITY_ONLY; full Go genesis/registry validation NOT_RUN"})
    return {"version": 1, "mode": "DRY_RUN_ONLY", "status": "BLOCKED",
            "reset_authorized": False, "executor_implemented": False,
            "host": HOST, "workspace": str(workspace), "observed_boot_id": boot_id,
            "allow_stopped_added_commons": allow_stopped_added_commons,
            "observation_utc": observation["observed_utc"], "generation_label": generation,
            "chain_id_preserved": preserve_chain_id,
            "old_generation": {"chain_id": old_chain_id, "genesis_hash": next(iter(genesis_hashes)),
                               "genesis_state_root": next(iter(genesis_roots)),
                               "genesis_file_sha256": public_hash(old_genesis),
                               "dex_configured": old_dex is not None},
            "new_generation": new, "targets": nodes,
            "gates": ["explicit user approval for this intermediate reset and exact plan digest",
                      "full Go validation of candidate genesis, computed hash, DEX manifest, Oracle/market and relay bindings",
                      "fresh host/process inventory and exact target hashes immediately before stopping",
                      "graceful target-only PM2 stop; verify descendants exited and all writers/locks stopped",
                      "private same-filesystem archive destination and free space; never merge or overwrite an archive",
                      "preserve source, config, keys and final results before any generation switch"],
            "ordered_procedure": [
                {"step": "stop", "apps": list(targets), "scope": "these exact app names only; never all"},
                {"step": "verify_stopped", "scope": "PM2, descendants, start ticks/boot ID, open data files and locks"},
                {"step": "archive", "method": "rename each whole exact datadir to its non-existing archive path; do not delete"},
                {"step": "identity_only", "method": "create fresh datadirs; selectively copy inventoried keystore and cypher/nodekey with restrictive modes"},
                {"step": "configure", "method": "retain reviewed static peer/local settings; bind new genesis, DEX domain/registry, unique vote/TLS keys, market, synthetic Oracle and relay"},
                {"step": "init", "method": "explicit inventoried new datadirs and approved candidate genesis; never invoke the existing destructive reset script"},
                {"step": "start_and_smoke", "method": "normal PM2, full sync, independent DEX roles, authenticated native deposit/trade/reward/claim; record actual hashes"}],
            "never_copy_into_new_generation": ["chaindata", "CLX/DEX vote WAL", "snapshot", "financial state", "relay journal/raw TX/nonce", "tx ingress/outbox", "old peer database or caches"],
            "rollback": "Before new generation signing, stop all new writers and restore exact archived datadirs/config/binary after review. After new signing/payment, never overwrite newer safety/payment history or run old/new generations together; retain both for an explicit recovery decision.",
            "replay_policy": ("User-selected unchanged CLX chain ID. New genesis and DEX domain authenticate DEX messages but do NOT prevent old ordinary CLX signed TX replay. Preserve keys separately from nonce/balances; never reuse old ingress/relay raw TX."
                              if preserve_chain_id else "New non-equal CLX chain ID separates protected ordinary TX; unprotected signatures remain a separate risk. Fresh genesis/DEX domain/registry bind DEX messages. Preserve keys separately from nonce/balances; no old raw TX import."),
            "secrets": "Key contents, hashes and keystore filenames are not read or emitted. This public plan contains paths/counts only; the later whole-datadir archive must remain private."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observation", required=True, type=Path)
    parser.add_argument("--new-chain-id", required=True, type=int)
    parser.add_argument("--preserve-chain-id", action="store_true", help="Keep the input chain ID; no ordinary-CLX-TX replay separation is claimed")
    parser.add_argument("--dex-id", required=True)
    parser.add_argument("--new-genesis", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--include-added-commons", action="store_true")
    parser.add_argument("--allow-stopped-added-commons", action="store_true",
                        help="Explicitly inventory stopped cypherdex1..6 without claiming their DB genesis was observed")
    args = parser.parse_args()
    if socket.gethostname() != HOST:
        raise ValueError("run the read-only planner on the named host")
    workspace = Path(__file__).resolve().parents[2]
    value = plan(workspace, public_json(args.observation), args.new_chain_id, args.dex_id, args.new_genesis, include_added_commons=args.include_added_commons, allow_stopped_added_commons=args.allow_stopped_added_commons, preserve_chain_id=args.preserve_chain_id)
    raw = (json.dumps(value, indent=2) + "\n").encode()
    with args.output.open("xb") as output:
        output.write(raw)
    print(json.dumps({"path": str(args.output), "sha256": hashlib.sha256(raw).hexdigest(),
                      "status": "BLOCKED", "reset_executed": False}))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        print(json.dumps({"status": "REFUSED", "error_type": type(error).__name__,
                          "reason": str(error) if isinstance(error, ValueError) else "filesystem access failed; no reset operation exists"}), file=sys.stderr)
        sys.exit(1)
