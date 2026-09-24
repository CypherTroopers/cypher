#!/usr/bin/env python3
"""Independent native TX v2 wire vectors. No Go output is consumed."""
import argparse
import hashlib
import json
import pathlib
import struct

ROOT = pathlib.Path(__file__).resolve().parents[2]
TARGET = ROOT / "dex/testdata/native_tx.json"

def digest(domain, raw):
    return hashlib.sha256(domain.encode("ascii") + b"\x00" + raw).hexdigest()

def vectors():
    domain = struct.pack(">HQ", 1, 10101919) + bytes([1])*32 + bytes([2])*32 + struct.pack(">Q", 1) + bytes([3])*32
    seed = bytes([4])*32
    custody = bytes.fromhex("0000000000000000000000000000000000de0001")
    calls = []
    for opcode in (1, 2, 3):
        raw = b"CDXN" + struct.pack(">HBBI", 2, opcode, 0, 0)
        calls.append({"opcode": opcode, "encoded": raw.hex(), "payload_hash": digest("common-dex/native-call/v2", raw)})
    # Composition of independently generated fixed v1 codecs; these opaque
    # synthetic proof bytes test the call envelope, not financial acceptance.
    checkpoint = bytes.fromhex(json.loads((ROOT / "dex/testdata/checkpoint.json").read_text())["vectors"][0]["encoded"])
    summary = bytes.fromhex(json.loads((ROOT / "dex/testdata/finance.json").read_text())["summaries"][0]["encoded"])
    dex_proof, clx_proof = bytes.fromhex("010203"), bytes.fromhex("04050607")
    checkpoint_body = checkpoint + summary + struct.pack(">I", len(dex_proof)) + dex_proof + struct.pack(">I", len(clx_proof)) + clx_proof
    claim = bytes.fromhex(json.loads((ROOT / "dex/testdata/claims.json").read_text())["leaves"][0]["encoded"])
    claim_body = claim + struct.pack(">IIB", 0, 1, 0)
    for opcode, body in ((4, checkpoint_body), (5, claim_body)):
        raw = b"CDXN" + struct.pack(">HBBI", 2, opcode, 0, len(body)) + body
        calls.append({"opcode": opcode, "encoded": raw.hex(), "payload_hash": digest("common-dex/native-call/v2", raw)})
    funding = []
    for name, sender, owner, amount, bucket in (
        ("trader_one_atom", bytes([5])*20, bytes([5])*20, 1, 1),
        ("trader_two_atoms_same_nonce", bytes([5])*20, bytes([5])*20, 2, 1),
        ("different_owner", bytes([5])*20, bytes([6])*20, 1, 1),
        ("different_sender", bytes([6])*20, bytes([5])*20, 1, 1),
        ("support_one_atom", bytes([5])*20, bytes([5])*20, 1, 2),
        ("insurance_one_atom", bytes([5])*20, bytes([5])*20, 1, 3),
    ):
        call = b"CDXN" + struct.pack(">HBBI", 2, bucket, 0, 0)
        payload = struct.pack(">H", 2) + sender + owner + amount.to_bytes(32, "big") + struct.pack(">IB", 0, bucket) + call
        assert len(payload) == 91
        payload_hash = digest("common-dex/native-funding-payload/v2", payload)
        source = struct.pack(">HQ", 2, 10101919) + bytes([1])*32 + bytes([2])*32 + custody + sender + struct.pack(">QI", 7, 0) + bytes.fromhex(payload_hash)
        assert len(source) == 158
        funding.append({"name": name, "sender": sender.hex(), "owner": owner.hex(), "amount": str(amount), "asset": 0, "bucket": bucket, "call": call.hex(), "encoded": payload.hex(), "payload_hash": payload_hash, "source_id": digest("common-dex/inbox-source/v2", source)})
    assert len({v["payload_hash"] for v in funding}) == len(funding)
    assert len({v["source_id"] for v in funding}) == len(funding)
    return {"version": 2, "calls": calls, "funding_payloads": funding, "genesis": {"seed": seed.hex(), "domain": domain.hex(), "custody": custody.hex(), "root": digest("common-dex/native-genesis/v2", seed+domain+custody)}}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = json.dumps(vectors(), indent=2, sort_keys=True) + "\n"
    if args.check:
        if TARGET.read_text() != expected:
            raise SystemExit("native TX golden mismatch")
        print("PASS: 5 native call envelopes, 6 funding payload/source identities and genesis commitment")
    else:
        TARGET.write_text(expected)

if __name__ == "__main__":
    main()
