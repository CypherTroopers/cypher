#!/usr/bin/env python3
"""Bounded ordinary signed CLX transfers through the existing Common HTTP RPC.

No settlement activation, balance edits, new funds or mining. Uses the already
authorized/unlocked test Common account. Saves public receipts, never keys.
"""
import argparse
import json
from pathlib import Path
import time
import urllib.request

from live_observe import rpc, BLOCK_FIELDS
from live_auth import GENESIS, REPO
from live_clx_accounting import audit

SENDER = "0xeb8c07def4c5a2541de730b027376e1068aa861a"
RECIPIENT = "0x3555d2c2af8ff75009f7dbfcf7de7ed80f68588d"
MAX_TX = 10
GAS_LIMIT = 100000
BUDGET = 10**16  # 0.01 test CLX maximum gas reservation, no custody involved.


def quantity(value):
    if isinstance(value, int):
        return value
    return int(value, 16) if value.startswith("0x") else int(value)


def http(method, params):
    request = urllib.request.Request("http://127.0.0.1:8999", data=json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=15) as response:
        raw = response.read(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError("RPC response cap")
    value = json.loads(raw)
    if "error" in value:
        raise ValueError("HTTP RPC error code " + str(value["error"].get("code")))
    return value.get("result")


def run(output, decoder):
    ipc = REPO / "chaindbmine/cypher.ipc"
    endpoints = [REPO / ("chaindb" + str(i)) / "cypher.ipc" for i in range(7)] + [ipc]
    genesis = http("eth_getBlockByNumber", ["0x0", False])
    if genesis.get("hash") != GENESIS or quantity(http("eth_chainId", [])) != 10101919:
        raise ValueError("unexpected network generation")
    gas_price = quantity(http("eth_gasPrice", []))
    if gas_price <= 0 or gas_price * GAS_LIMIT * MAX_TX > BUDGET:
        raise ValueError("gas budget exceeded before signing")
    addresses = [SENDER, RECIPIENT]
    start = http("eth_getBlockByNumber", ["latest", False])
    before = {a: quantity(http("eth_getBalance", [a, start["number"]])) for a in addresses}
    if before[SENDER] < BUDGET + MAX_TX:
        raise ValueError("insufficient owned test balance")
    nonce = quantity(http("eth_getTransactionCount", [SENDER, "pending"]))
    if nonce != quantity(http("eth_getTransactionCount", [SENDER, "latest"])):
        raise ValueError("existing pending sender nonce; refusing concurrent workload")
    result = {"kind": "ordinary CLX deployment smoke, not DEX finance", "status": "RUNNING",
              "genesis": GENESIS, "start": {k: start[k] for k in BLOCK_FIELDS if k in start},
              "balances_before": {a: str(b) for a, b in before.items()}, "gas_budget_atoms": str(BUDGET),
              "gas_price": gas_price, "max_transactions": MAX_TX, "transactions": [], "receipts": {}}
    def save():
        temporary = output.with_suffix(".new")
        temporary.write_text(json.dumps(result, indent=2) + "\n")
        temporary.replace(output)
    save()
    try:
        start_time = time.monotonic()
        next_send = start_time
        while time.monotonic() - start_time < 150:
            if len(result["transactions"]) < MAX_TX and time.monotonic() >= next_send:
                index = len(result["transactions"])
                tx = {"from": SENDER, "to": RECIPIENT, "value": "0x1", "gas": hex(GAS_LIMIT),
                      "gasPrice": hex(gas_price), "nonce": hex(nonce + index), "data": "0x"}
                signed = rpc(ipc, "eth_signTransaction", [tx])
                if not isinstance(signed, dict) or not isinstance(signed.get("raw"), str):
                    raise ValueError("ordinary IPC transaction signing failed")
                tx_hash = http("eth_sendRawTransaction", [signed["raw"]])
                if not isinstance(tx_hash, str) or len(tx_hash) != 66:
                    raise ValueError("ordinary RPC did not return transaction hash")
                result["transactions"].append({"hash": tx_hash, "nonce": nonce + index, "value": "1",
                                               "rpc_ack_seconds": time.monotonic() - start_time})
                next_send = time.monotonic() + 1
                save()
            for tx in result["transactions"]:
                if tx["hash"] not in result["receipts"]:
                    receipt = http("eth_getTransactionReceipt", [tx["hash"]])
                    if receipt:
                        result["receipts"][tx["hash"]] = receipt
                        tx["receipt_observed_seconds"] = time.monotonic() - start_time
                        save()
            if len(result["transactions"]) == MAX_TX and len(result["receipts"]) == MAX_TX:
                break
            time.sleep(.25)
        end = http("eth_getBlockByNumber", ["latest", False])
        result["end"] = {k: end[k] for k in BLOCK_FIELDS if k in end}
        result["elapsed_seconds"] = time.monotonic() - start_time
        result["all_node_projection"] = []
        for endpoint in endpoints:
            catchup_deadline = time.monotonic() + 25
            block = rpc(endpoint, "eth_getBlockByNumber", [end["number"], False])
            while block is None and time.monotonic() < catchup_deadline:
                time.sleep(.25)
                block = rpc(endpoint, "eth_getBlockByNumber", [end["number"], False])
            if not isinstance(block, dict) or any(block.get(k) != end.get(k) for k in BLOCK_FIELDS):
                raise ValueError("same canonical block projection differs between full nodes")
            for tx in result["transactions"]:
                receipt = rpc(endpoint, "eth_getTransactionReceipt", [tx["hash"]])
                if receipt != result["receipts"].get(tx["hash"]):
                    raise ValueError("receipt differs between full nodes")
            result["all_node_projection"].append(str(endpoint))
        if len(result["receipts"]) != MAX_TX:
            raise ValueError("incomplete canonical receipts at finite workload deadline")
        result["accounting"] = audit(result, decoder, output.with_suffix(".accounting"))
        result["status"] = "PASS"
        save()
    except Exception as error:
        result["status"] = "FAIL"
        result["error"] = type(error).__name__ + ": " + str(error)
        save()
        raise
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--decoder", type=Path, required=True)
    args = parser.parse_args()
    output = Path(args.output)
    if output.exists():
        raise SystemExit("fresh output required; do not silently resend a prior run")
    result = run(output, args.decoder)
    print(json.dumps({"status": result["status"], "sent": len(result["transactions"]),
                      "receipts": len(result["receipts"]), "output": str(output)}))
