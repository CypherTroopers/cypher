#!/usr/bin/env python3
"""Explicit additional Common launcher. Never starts PoW, unlock or RPC work.
DEX defaults OFF and requires an explicit generation-bound local role selection.

prepare writes reviewed start/config files only into a fresh private directory.
The operator separately initializes an empty datadir and starts the named PM2
application. No existing database is removed, migrated or initialized here.
"""
import argparse
import json
import os
from pathlib import Path
import re
from live_roles import dex_arguments

ROOT = Path(__file__).resolve().parents[2]


def layout(repo, index):
    if type(index) is not int or not 1 <= index <= 6:
        raise ValueError("only additional Common indices 1..6 are authorized")
    return repo / "build/stage/live-commons" / ("common" + str(index))


def command(repo, index, owner):
    directory = layout(repo, index)
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", owner) or int(owner, 16) == 0:
        raise ValueError("explicit unique Common public wallet required")
    config = json.loads((repo / "genesis.json").read_text())["config"]
    if not config["fixedCommittee"] or config["fixedLeader"] or len(config["committee"]) != 7:
        raise ValueError("unexpected CLX committee policy")
    return [str(repo / "build/bin/cypher-linux-amd64"),
            "--config", str(directory / "static.toml"),
            "--datadir", str(repo / "build/stage/live-commons" / ("chaindbdex" + str(index))),
            "--nat", "extip:127.0.0.1", "--rnetport", str(7200 + 2 * index),
            "--nodiscover", "--maxpeers", "16", "--networkid", str(config["chainId"]),
            "--syncmode", "full", "--gcmode", "archive", "--cache", "256",
            "--cache.trie.journal", "", "--miner.etherbase", owner,
            "--metrics", "--verbosity", "3"] + dex_arguments(repo, "cypherdex" + str(index))


def prepare(repo, index, owner):
    invocation = command(repo, index, owner)
    directory = layout(repo, index)
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    static = (repo / "static-nodes.toml").read_text()
    matches = re.findall(r'enode://([0-9a-fA-F]{128})@[^"\s]+:([0-9]+)', static)
    if len(matches) != 7 or {int(port) for _, port in matches} != set(range(6000, 6007)):
        raise ValueError("exact seven reviewed CLX static peers required")
    peers = ["enode://" + public + "@127.0.0.1:" + port for public, port in matches]
    toml = "[Node.P2P]\nListenAddr = \"127.0.0.1:" + str(6200 + index) + "\"\nStaticNodes = " + json.dumps(peers) + "\n"
    (directory / "static.toml").write_text(toml)
    wrapper = directory / "start.sh"
    wrapper.write_text('#!/usr/bin/env bash\nset -euo pipefail\nexec python3 "' + str(repo / "scripts/dex/live_common.py") + '" run --index ' + str(index) + ' --owner ' + owner + '\n')
    wrapper.chmod(0o700)
    app = {"name": "cypherdex" + str(index), "script": str(wrapper), "cwd": str(repo),
           "interpreter": "bash", "exec_mode": "fork", "autorestart": True,
           "watch": False, "kill_timeout": 30000, "restart_delay": 2000,
           "min_uptime": 10000, "max_restarts": 5, "treekill": True}
    (directory / "ecosystem.json").write_text(json.dumps({"apps": [app]}, indent=2) + "\n")
    public = {"app": app["name"], "command": invocation, "static_peers": peers,
              "p2p_listen": "127.0.0.1:" + str(6200 + index), "initialized": False,
              "dex_enabled": False, "pow_enabled": False, "rpc_work_enabled": False}
    (directory / "plan.json").write_text(json.dumps(public, indent=2) + "\n")
    return public


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "run", "print"))
    parser.add_argument("--index", type=int, required=True)
    parser.add_argument("--owner", required=True)
    args = parser.parse_args()
    if args.mode == "prepare":
        print(json.dumps(prepare(ROOT, args.index, args.owner)))
    else:
        invocation = command(ROOT, args.index, args.owner)
        if args.mode == "print":
            print(json.dumps(invocation))
        else:
            os.chdir(ROOT)
            os.execv(invocation[0], invocation)
