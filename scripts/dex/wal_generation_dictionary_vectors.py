#!/usr/bin/env python3
"""Independent local WAL v5 structural vectors; sample records are not proofs."""
import argparse
import base64
import hashlib
import json
from pathlib import Path


def encoded(value):
    return None if value is None else base64.b64encode(value).decode()


def vectors():
    actions = {"a": b"same-body", "b": b"\x00\xff", "c": b"same-body",
               "empty": b"", "nil": None, "orphan": b"\xff\x00"}
    states = {"a": b"same-state", "b": b"\x00\xff", "c": b"same-state",
              "empty": b"", "nil": None, "orphan": None}
    component = {}
    for label, values in [("Action", actions), ("State", states)]:
        dictionary = sorted(set(values.values()), key=lambda x: (x is not None, x or b""))
        component[label + "Dictionary"] = [encoded(x) for x in dictionary]
        component[label + "Refs"] = {key: dictionary.index(value) for key, value in sorted(values.items())}
    payload = json.dumps(component, separators=(",", ":")).encode()
    return {"description": "structural dictionary component only; not a WAL or consensus proof",
            "component": component, "payload": payload.hex(),
            "checksum": hashlib.sha256(b"common-dex/wal/v5\0" + payload).hexdigest(),
            "expanded_action_bytes": sum(len(x or b"") for x in actions.values()),
            "expanded_state_bytes": sum(len(x or b"") for x in states.values()),
            "limits": {"wal_bytes": 2 * 1024 * 1024, "records": 128,
                       "action_bytes": 64 * 1024, "state_bytes": 1024 * 1024,
                       "expanded_action_bytes": 2 * 1024 * 1024,
                       "expanded_state_bytes": 2 * 1024 * 1024}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    path = Path(__file__).resolve().parents[2] / "dex/testdata/wal_generation_dictionary.json"
    raw = json.dumps(vectors(), indent=2) + "\n"
    if args.check:
        if path.read_text() != raw:
            raise SystemExit("generation WAL dictionary golden mismatch")
    else:
        path.write_text(raw)
