#!/usr/bin/env python3
"""Explicit PM2 entrypoint for the authorized existing development network.

No initialization, unlocking, mining, external address discovery or PM2
operations. Explicit generation-bound local roles optionally select the normal
Common-supervised DEX sidecar. exec keeps PM2's PID equal to the actual node PID.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
from live_roles import dex_arguments

COMMON_ACCOUNT = "0xeb8c07def4c5a2541de730b027376e1068aa861a"
APPS = tuple("cypher" + str(i) for i in range(7)) + ("cyphermine",)


def command(repo, app):
    if app not in APPS:
        raise ValueError("unrecognized authorized app")
    config = json.loads((repo / "genesis.json").read_text())["config"]
    committee = config["committee"]
    if len(committee) != 7 or not config["fixedCommittee"] or config["fixedLeader"]:
        raise ValueError("unexpected fixed committee configuration")
    hosts = {n["address"].rsplit(":", 1)[0] for n in committee.values()}
    if len(hosts) != 1:
        raise ValueError("this launcher only serves the authorized single host")
    host = str(ipaddress.IPv4Address(next(iter(hosts))))
    common = app == "cyphermine"
    suffix = "mine" if common else app.removeprefix("cypher")
    port = 6099 if common else 6000 + int(suffix)
    rnet = 7155 if common else int(committee[suffix]["address"].rsplit(":", 1)[1])
    coinbase = COMMON_ACCOUNT if common else "0x" + committee[suffix]["coinbase"].removeprefix("0x")
    args = [str(repo / "build/bin/cypher-linux-amd64"),
            "--config", str(repo / "static-nodes.toml"), "--verbosity", "4",
            "--rnetport", str(rnet), "--syncmode", "full", "--nat", "extip:" + host,
            "--metrics", "--allow-insecure-unlock", "--port", str(port),
            "--datadir", str(repo / ("chaindb" + suffix)),
            "--networkid", str(config["chainId"]), "--gcmode", "archive",
            "--miner.etherbase", coinbase]
    if common:
        args += ["--ws", "--ws.addr", "127.0.0.1", "--ws.port", "8434",
                 "--http", "--http.addr", "127.0.0.1", "--http.port", "8999",
                 "--http.api", "eth,web3,net,debug,txpool"]
    return args + dex_arguments(repo, app)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("app", choices=APPS)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    invocation = command(root, args.app)
    if args.print_json:
        print(json.dumps(invocation))
    else:
        os.chdir(root)
        os.execv(invocation[0], invocation)
