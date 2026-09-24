#!/usr/bin/env python3
"""Read-only interval accounting for the bounded, ordinary CLX smoke.

The standalone Go decoder models existing CLX issuance from real block RLP.
Canonical IPC observations are not an independent FHS finality certificate.
"""
import argparse
import json
from pathlib import Path
import subprocess

from live_observe import rpc
from live_auth import REPO

MAX_BLOCKS = 256


def number(value):
    return int(value, 16) if isinstance(value, str) and value.startswith("0x") else int(value)


def model(run, blocks):
    """Use decoded headers and receipts, never the RPC display-only miner field."""
    expected, issuance, common = {}, 0, 0
    gas = burn = 0
    chain_hash = run["start"]["hash"].lower()
    height = number(run["start"]["number"])
    seen = []

    def add(address, amount):
        address = address.lower()
        expected[address] = expected.get(address, 0) + amount

    for block in blocks:
        height += 1
        if block["number"] != height or block["parent_hash"].lower() != chain_hash:
            raise ValueError("non-contiguous canonical interval")
        chain_hash = block["actual_hash"].lower()
        seen.extend(h.lower() for h in block["transaction_hashes"])
        subtotal = 0
        for item in block["issuance_by_recipient"]:
            amount = number(item["atoms"])
            if amount < 0:
                raise ValueError("negative modeled issuance")
            add(item["recipient"], amount)
            subtotal += amount
        if subtotal != number(block["issuance_total_atoms"]):
            raise ValueError("issuance model sum differs")
        issuance += subtotal
    if height != number(run["end"]["number"]) or chain_hash != run["end"]["hash"].lower():
        raise ValueError("canonical interval end mismatch")
    if blocks and blocks[-1]["state_root"].lower() != run["end"]["stateRoot"].lower():
        raise ValueError("canonical interval state root mismatch")
    sent = [item["hash"].lower() for item in run["transactions"]]
    if sorted(seen) != sorted(sent) or len(set(sent)) != len(sent):
        raise ValueError("interval contains missing, duplicate or unrelated transactions")
    if set(run["receipts"]) != set(sent):
        raise ValueError("not every submitted transaction has a canonical receipt")
    for item in run["transactions"]:
        receipt = run["receipts"][item["hash"]]
        sender, recipient = receipt["from"].lower(), receipt["to"].lower()
        if number(receipt["status"]) != 1 or receipt.get("commonTxApprover", "").lower() != sender:
            raise ValueError("failed transfer or unexpected Common admission")
        cost = number(receipt["gasUsed"]) * number(receipt.get("effectiveGasPrice", run["gas_price"]))
        part, burned = number(receipt["commonTxApproverReward"]), number(receipt["commonTxBurn"])
        if min(cost, part, burned) < 0 or cost != part + burned:
            raise ValueError("gas/Common/burn mismatch")
        value = number(item["value"])
        if value != 1:
            raise ValueError("this auditor only accepts the one-atom ordinary transfer smoke")
        add(sender, -cost - value)
        add(recipient, value)
        add(receipt["commonTxRewardRecipient"], part)
        gas += cost
        common += part
        burn += burned
    if sum(expected.values()) != issuance - burn:
        raise ValueError("model conservation mismatch")
    return {"expected_delta_atoms": {a: str(n) for a, n in sorted(expected.items())},
            "existing_clx_issuance_atoms": str(issuance), "gas_atoms": str(gas),
            "common_reward_atoms": str(common), "burn_atoms": str(burn),
            "transaction_count": len(sent), "block_count": len(blocks)}


def audit(run, binary, directory):
    directory.mkdir(parents=True, exist_ok=False)
    ipc = REPO / "chaindbmine/cypher.ipc"
    start, end = number(run["start"]["number"]), number(run["end"]["number"])
    if not 0 < end - start <= MAX_BLOCKS:
        raise ValueError("accounting interval exceeds local work budget")
    raw_path = directory / "canonical-blocks.jsonl"
    with raw_path.open("x") as stream:
        for height in range(start + 1, end + 1):
            block = rpc(ipc, "eth_getBlockByNumber", [hex(height), False])
            raw = rpc(ipc, "debug_getBlockRlp", [height])
            if not isinstance(block, dict) or not isinstance(raw, str):
                raise ValueError("historical canonical block data unavailable")
            stream.write(json.dumps({"rlp": raw, "expected_hash": block["hash"],
                                     "expected_number": height}) + "\n")
    decoded_path = directory / "decoded-issuance.jsonl"
    with raw_path.open("rb") as source, decoded_path.open("xb") as destination:
        completed = subprocess.run([str(binary.resolve())], stdin=source, stdout=destination,
                                   stderr=subprocess.PIPE, timeout=60, check=False)
    if completed.returncode:
        raise ValueError("bounded block decoder rejected interval; exit " + str(completed.returncode))
    blocks = [json.loads(line) for line in decoded_path.read_text().splitlines()]
    result = model(run, blocks)
    result["scope"] = "canonical IPC accounting; not independent FHS authentication or DEX finance"
    result["balances_before"], result["balances_after"], result["actual_delta_atoms"] = {}, {}, {}
    for address, expected in result["expected_delta_atoms"].items():
        before = number(rpc(ipc, "eth_getBalance", [address, hex(start)]))
        after = number(rpc(ipc, "eth_getBalance", [address, hex(end)]))
        result["balances_before"][address], result["balances_after"][address] = str(before), str(after)
        result["actual_delta_atoms"][address] = str(after - before)
    result["status"] = "PASS" if result["actual_delta_atoms"] == result["expected_delta_atoms"] else "FAIL"
    (directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    if result["status"] != "PASS":
        raise ValueError("native balance delta differs from independent issuance/transfer/gas model")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--decoder", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    result = audit(json.loads(args.run.read_text()), args.decoder, args.output_dir)
    print(json.dumps({k: result[k] for k in ("status", "block_count", "transaction_count",
                     "existing_clx_issuance_atoms", "gas_atoms", "common_reward_atoms", "burn_atoms")}))
