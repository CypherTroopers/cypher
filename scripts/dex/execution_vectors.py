#!/usr/bin/env python3
"""Independent canonical schema-2 action vectors; Python standard library."""
import argparse
import hashlib
import json
import pathlib
import struct

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "dex/testdata/execution.json"


def digest(label, payload):
    return hashlib.sha256(label.encode("ascii") + b"\0" + payload).hexdigest()


def vectors():
    cases = []
    for name, action in [("empty", b""), ("binary", b"\x00\x01\xff"),
                         ("fixture", b"fixture-action")]:
        envelope = struct.pack(">HI", 2, len(action)) + action
        cases.append({"name": name, "action": action.hex(),
                      "envelope": envelope.hex(),
                      "root": digest("common-dex/execution-data/v1", envelope)})
    execution_id = b"fixture-execution/v1"
    epoch_key, genesis_root = bytes.fromhex("22" * 32), bytes.fromhex("33" * 32)
    genesis = epoch_key + struct.pack(">H", len(execution_id)) + execution_id + genesis_root
    return {"source": "docs/dex/execution-adapter-spec.md",
            "max_action_bytes": 65536, "max_wire_bytes": 131072, "actions": cases,
            "genesis": {"epoch_key": epoch_key.hex(), "root": genesis_root.hex(),
                        "execution_id": execution_id.decode("ascii"),
                        "parent": digest("common-dex/execution-genesis/v1", genesis)}}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--check", action="store_true")
    args = p.parse_args()
    rendered = json.dumps(vectors(), indent=2) + "\n"
    if args.check:
        if OUT.read_text() != rendered:
            raise SystemExit("execution vectors differ")
        print("execution vectors: PASS")
    else:
        OUT.write_text(rendered)


if __name__ == "__main__":
    main()
