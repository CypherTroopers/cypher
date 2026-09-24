#!/usr/bin/env python3
"""Restore existing roles via IPC without exposing credentials or mining Common.

The existing local scripts remain the credential source. They are parsed as
data, never sourced/executed. preflight signs only a domain-tagged text challenge
and verifies recovery; it sends no transaction and does not alter unlock state.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import time

from live_observe import rpc
from live_roles import activated_inventory, read_regular, ROLE_PATH

REPO = Path(__file__).resolve().parents[2]
GENESIS = "0xe69022ef43f6d238846015e0a4e7cdd190cf45e9fd98cfa0666acb482a05017e"
COMMON_RPC_RECIPIENT = "0xed2772838f7a7aec042a972084998cb30d63b660"
CHALLENGE = "0x" + b"CYPHER_OWNED_DEVNET_Q1_CREDENTIAL_PREFLIGHT_NO_TRANSACTION".hex()


def network_identity(repo, inventory_path=None):
    raw = read_regular(repo / "genesis.json")
    config = json.loads(raw)["config"]
    if inventory_path is None:
        expected_sha = "131acbb21ef77f4229c91a639c51348bc1d0f0f5b6c4cbf4299e46c90efd4b1f"
        expected_chain, expected_genesis = 10101919, GENESIS
    else:
        role = json.loads(read_regular(repo / ROLE_PATH))
        if str(Path(inventory_path)) != role.get("generation_inventory"):
            raise ValueError("inventory is not the reviewed active selection")
        config, expected_genesis, inventory = activated_inventory(repo, raw, role)
        expected_sha, expected_chain = inventory["GenesisSHA256"], inventory["ChainID"]
    if (hashlib.sha256(raw).hexdigest() != expected_sha or
            config["chainId"] != expected_chain or len(config["committee"]) != 7):
        raise ValueError("unreviewed network generation")
    return config, expected_genesis


def credentials(config):
    matches = re.findall(r'miner\.start\((\d+),"(0x[0-9a-fA-F]{40})","([^"\n]*)"\).*chaindb([0-6])/cypher.ipc',
                         (REPO / "start-mining.sh").read_text())
    if len(matches) != 7 or {m[3] for m in matches} != set(map(str, range(7))):
        raise ValueError("exactly seven existing committee credentials required")
    result = []
    for threads, address, password, index in sorted(matches, key=lambda m: m[3]):
        if address.lower() != "0x" + config["committee"][index]["coinbase"].lower().removeprefix("0x"):
            raise ValueError("committee identity mismatch")
        result.append(("cypher" + index, REPO / ("chaindb" + index) / "cypher.ipc", address, password))
    source = (REPO / "unlock.sh").read_text()
    found = re.search(r'^MINE_PASSWORD=(.*)$', source, re.M)
    value = shlex.split(found[1]) if found else []
    if len(value) != 1 or any(c in value[0] for c in ("$", "`", "\n")):
        raise ValueError("literal existing Common credential unavailable")
    result.append(("cyphermine", REPO / "chaindbmine/cypher.ipc", "0xeb8c07def4c5a2541de730b027376e1068aa861a", value[0]))
    return result


def execute(mode, inventory_path=None, apps=None):
    config, expected_genesis = network_identity(REPO, inventory_path)
    records = credentials(config)
    if apps is not None:
        if (not apps or len(set(apps)) != len(apps) or
                not set(apps) <= {record[0] for record in records}):
            raise ValueError("explicit unique existing role targets required")
        records = [record for record in records if record[0] in apps]
    # Validate all IPC endpoints before making any signed or stateful call.
    deadline = time.monotonic() + 60
    for name, ipc, address, password in records:
        while True:
            try:
                genesis = rpc(ipc, "eth_getBlockByNumber", ["0x0", False])
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if time.monotonic() >= deadline:
                    raise ValueError("IPC readiness deadline before any role restore") from None
                time.sleep(.25)
        if not isinstance(genesis, dict) or genesis.get("hash") != expected_genesis:
            raise ValueError("IPC genesis mismatch")
        chain = rpc(ipc, "eth_chainId")
        if not isinstance(chain, str) or not re.fullmatch(r"0x[0-9a-fA-F]+", chain) or int(chain, 16) != config["chainId"]:
            raise ValueError("IPC chain ID mismatch")
    output = []
    for name, ipc, address, password in records:
        if mode == "preflight":
            signature = rpc(ipc, "personal_sign", [CHALLENGE, address, password])
            if not isinstance(signature, str) or len(signature) != 132:
                raise ValueError("credential preflight signing failed for " + name)
            recovered = rpc(ipc, "personal_ecRecover", [CHALLENGE, signature])
            if not isinstance(recovered, str) or recovered.lower() != address.lower():
                raise ValueError("credential preflight recovery failed for " + name)
            output.append({"app": name, "credential_verified": True, "transaction_sent": False})
        else:
            if rpc(ipc, "personal_unlockAccount", [address, password, 0]) is not True:
                raise ValueError("existing account unlock failed for " + name)
            if name == "cyphermine":
                reward = rpc(ipc, "personal_getCommonRPCRewardAddress", [address])
                if not isinstance(reward, dict):
                    raise ValueError("Common RPC reward configuration unavailable")
                if not reward.get("configured"):
                    if inventory_path is None:
                        raise ValueError("existing Common RPC configuration unexpectedly missing")
                    reward = rpc(ipc, "personal_setCommonRPCRewardAddress",
                                 [address, COMMON_RPC_RECIPIENT, password])
                if (not reward.get("configured") or
                        reward.get("rewardRecipient", "").lower() != COMMON_RPC_RECIPIENT):
                    raise ValueError("refuse overwriting an unexpected Common RPC recipient")
            if name != "cyphermine":
                started = rpc(ipc, "miner_start", [1, address, password])
                if not isinstance(started, str) or started not in ("Mining started", "Mining threads updated"):
                    raise ValueError("existing committee FHS start failed for " + name)
            output.append({"app": name, "unlocked_existing_account": True,
                           "committee_start": name != "cyphermine",
                           "mining": rpc(ipc, "eth_mining"), "role": rpc(ipc, "miner_status")})
    return {"phase": mode, "utc": time.time(), "records": output,
            "chain_id": config["chainId"], "genesis": expected_genesis,
            "Common_miner_start_called": False, "credential_material_recorded": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("preflight", "restore"))
    parser.add_argument("--output", required=True)
    parser.add_argument("--generation-inventory", type=Path)
    parser.add_argument("--apps", nargs="+", choices=["cypher"+str(i) for i in range(7)]+["cyphermine"],
                        help="restore only these existing roles; omitted preserves the full existing role restore")
    args = parser.parse_args()
    result = execute(args.phase, args.generation_inventory, args.apps)
    with Path(args.output).open("x") as f:
        json.dump(result, f, indent=2)
        f.write("\n")
    print(json.dumps({"phase": args.phase, "verified_apps": len(result["records"]), "output": args.output}))
