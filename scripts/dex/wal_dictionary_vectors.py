#!/usr/bin/env python3
"""Independent local WAL v3 dictionary vectors; dummy records are not proofs."""
import argparse
import base64
import hashlib
import json
from pathlib import Path


def encoded(value):
    return None if value is None else base64.b64encode(value).decode()


def vectors():
    records = {"a": b"same-body", "b": b"\x00\xff", "c": b"same-body",
               "empty": b"", "nil": None, "orphan": b"\xff\x00"}
    dictionary = sorted(set(records.values()), key=lambda x: (x is not None, x or b""))
    refs = {key: dictionary.index(value) for key, value in sorted(records.items())}
    component = {"ActionDictionary": [encoded(x) for x in dictionary], "ActionRefs": refs}
    payload = json.dumps(component, separators=(",", ":")).encode()
    return {
        "description": "structural dictionary component only; not an accepted WAL or consensus proof",
        "records": {k: encoded(v) for k, v in sorted(records.items())},
        "component": component,
        "expanded_action_bytes": sum(len(x or b"") for x in records.values()),
        "unique_action_bytes": sum(len(x or b"") for x in dictionary),
        "payload": payload.hex(),
        "checksum": hashlib.sha256(b"common-dex/wal/v3\0" + payload).hexdigest(),
        "limits": {"wal_bytes": 2 * 1024 * 1024, "records": 128,
                   "action_bytes": 64 * 1024, "expanded_action_bytes": 2 * 1024 * 1024},
        "expansion_boundary": {"action_bytes": 64 * 1024, "references_accepted": 32,
                               "references_rejected": 33},
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    path = Path(__file__).resolve().parents[2] / "dex/testdata/wal_dictionary.json"
    raw = json.dumps(vectors(), indent=2) + "\n"
    if args.check:
        if path.read_text() != raw:
            raise SystemExit("WAL dictionary golden mismatch")
    else:
        path.write_text(raw)
