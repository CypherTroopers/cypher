#!/usr/bin/env python3
"""Independent v2 commit codec vectors; zero signatures are structural only."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

def digest(label, raw):
    return hashlib.sha256(label.encode() + b"\0" + raw).digest()

def vector():
    domain = struct.pack(">HQ", 1, 9127001) + b"\1" * 32 + b"\2" * 32 + struct.pack(">Q", 3) + b"\4" * 32
    certificates = []
    for participant in [2, 6]:
        duty = struct.pack(">H", 1) + domain + struct.pack(">QQQ", 2, 17, 21) + b"\5" * 32 + bytes([participant]) + bytes([0x20 + participant]) * 20
        cert = duty + b"\5" + b"".join(bytes([i]) + bytes(32) for i in range(5))
        assert len(duty) == 193 and len(cert) == 359
        certificates.append((digest("common-dex/participation-duty/v1", duty), cert))
    certificates.sort()
    payload = b"CDXPCB02" + struct.pack(">HH", 2, len(certificates)) + b"".join(struct.pack(">H", len(c)) + c for _, c in certificates)
    h = digest("common-dex/participation-commit/v2", payload)
    return {"description": "independent Python v2 participation commit codec; zero signatures are not valid proofs", "payload": payload.hex(), "payload_hash": h.hex(), "action_target": h[:20].hex(), "duty_hashes": [h.hex() for h, _ in certificates], "certificates": [c.hex() for _, c in certificates]}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    path = Path(__file__).resolve().parents[2] / "dex/testdata/participation_commit.json"
    raw = json.dumps(vector(), indent=2) + "\n"
    if args.check:
        if path.read_text() != raw:
            raise SystemExit("participation commit golden mismatch")
    else:
        path.write_text(raw)
