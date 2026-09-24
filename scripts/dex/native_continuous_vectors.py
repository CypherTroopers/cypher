#!/usr/bin/env python3
"""Independent SHA-256 + fixed-width native config4 bootstrap vector."""
import argparse
import hashlib
import json
from pathlib import Path
import struct


def vectors():
    seed = bytes([4]) * 32
    domain = struct.pack(">HQ", 1, 10101920) + bytes([1]) * 32 + bytes([2]) * 32 + struct.pack(">Q", 1) + bytes([3]) * 32
    custody = bytes.fromhex("0000000000000000000000000000000000de0001")
    return {"config_version": 4, "financial_state_version": 6, "checkpoint_schema": 5,
            "seed": seed.hex(), "domain": domain.hex(), "custody": custody.hex(),
            "genesis_root": hashlib.sha256(b"common-dex/native-genesis/v4\0" + seed + domain + custody).hexdigest(),
            "native_call_limit_bytes": 65536, "source_ancestry_limit": 64,
            "hot_records": 128, "rotation_interval": 64,
            "remaining_chain_quotas": {"checkpoints": 4096, "anchors": 1024, "inbox": 4096}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    target = Path(__file__).resolve().parents[2] / "dex/testdata/native_continuous.json"
    raw = json.dumps(vectors(), indent=2, sort_keys=True) + "\n"
    if args.check:
        if target.read_text() != raw:
            raise SystemExit("native continuous vector mismatch")
        print("PASS native config4 independent root/bounds vector")
    else:
        target.write_text(raw)
