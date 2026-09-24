#!/usr/bin/env python3
"""Independent structural replay selection; dummy records are not proofs."""
import argparse, base64, hashlib, json
from pathlib import Path

def vectors():
    states = {"a": b"state-one", "b": b"state-two", "c": b"state-three", "orphan": b"other-branch"}
    finalized = ["a", "b"]
    records = {k: {"Actions": base64.b64encode(b"action-" + k.encode()).decode(), "State": None if k in finalized[:-1] else base64.b64encode(v).decode()} for k,v in states.items()}
    payload = json.dumps({"Version": 2, "ExecutionSchema": 4, "Records": records, "Finalized": finalized}, separators=(",", ":"), sort_keys=True).encode()
    return {"description": "structural selection only; not valid consensus records", "finalized": finalized, "omitted": ["a"], "retained": ["b", "c", "orphan"], "aggregate_state_bytes": sum(map(len,states.values())), "payload": payload.hex(), "checksum": hashlib.sha256(b"common-dex/wal/v2\0"+payload).hexdigest()}
if __name__ == "__main__":
    p=argparse.ArgumentParser(); p.add_argument("--check",action="store_true"); args=p.parse_args()
    path=Path(__file__).resolve().parents[2]/"dex/testdata/compact_replay.json"
    raw=json.dumps(vectors(),indent=2)+"\n"
    if args.check:
        if path.read_text()!=raw: raise SystemExit("compact replay golden mismatch")
    else: path.write_text(raw)
