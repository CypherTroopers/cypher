#!/usr/bin/env python3
"""Independent full-tree SHA-256 model for history_test.go golden vectors.

No Go frontier algorithm or repository cryptographic helper is imported.
"""
import hashlib
import json


def digest(label, data):
    return hashlib.sha256(label.encode("ascii") + b"\0" + data).digest()


def vector(count):
    empty = digest("common-dex/history-empty/v1", b"")
    nodes = [
        digest("common-dex/history-leaf/v1", (index + 1).to_bytes(32, "big"))
        if index < count else empty
        for index in range(4096)
    ]
    for level in range(12):
        nodes = [
            digest("common-dex/history-node/v1", bytes([level]) + nodes[i] + nodes[i + 1])
            for i in range(0, len(nodes), 2)
        ]
    root = nodes[0]
    data_root = digest(
        "common-dex/history-data/v1",
        (17).to_bytes(32, "big") + root + count.to_bytes(8, "big"),
    )
    return {"count": count, "root": root.hex(), "data_root": data_root.hex()}


if __name__ == "__main__":
    print(json.dumps([vector(count) for count in (0, 1, 3, 4095)], indent=2))
