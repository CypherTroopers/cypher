#!/usr/bin/env python3
"""Independent native v3 root/storage vectors, fixed before implementation."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / 'dex/testdata/native_rolling.json'

def digest(label, data):
    return hashlib.sha256(label.encode('ascii') + b'\0' + data).hexdigest()

def rlp(value):
    if isinstance(value, list):
        b = b"".join(rlp(v) for v in value)
        offset = 192
    else:
        b = value
        if len(b) == 1 and b[0] < 128: return b
        offset = 128
    if len(b) < 56: return bytes([offset+len(b)])+b
    size = len(b).to_bytes((len(b).bit_length()+7)//8,"big")
    return bytes([offset+55+len(size)])+size+b

def vectors():
    seed = bytes([4]) * 32
    domain = struct.pack('>HQ', 1, 10101919) + bytes([1])*32 + bytes([2])*32 + struct.pack('>Q', 1) + bytes([3])*32
    custody = bytes.fromhex('0000000000000000000000000000000000de0001')
    slots = []
    for name, height, index in [('rolling-meta', 0, 0), ('rolling-id', 257, 0), ('rolling-evidence', 257, 0), ('history', 17, 0), ('cursor', 0, 0), ('sequence', 0, 0)]:
        slots.append({'name': name, 'height': height, 'index': index, 'key': digest('common-dex/settlement/storage/v1', name.encode() + b'\0' + struct.pack('>QI',height,index))})
    for index in range(8):
        slots.append({'name': 'rolling-anchor', 'height': 257, 'index': index, 'key': digest('common-dex/settlement/storage/v1', b'rolling-anchor\0' + struct.pack('>QI',257,index))})
    # Opaque body checks only the outer opcode6 framing, not evidence validity.
    evidence = bytes.fromhex('c102')
    body = rlp([b'\x01', evidence, []])
    historical = rlp([b'\x01', evidence, [[b'\xaa', b'\xbb']]])
    call = b'CDXN' + struct.pack('>HBBI',2,6,0,len(body)) + body
    return {'version': 3, 'seed': seed.hex(), 'domain': domain.hex(), 'custody': custody.hex(), 'genesis_root': digest('common-dex/native-genesis/v3',seed+domain+custody), 'slots': slots, 'metadata': {'tip': 257, 'confirmed': 193, 'count': 5, 'encoded': struct.pack('>QQQQ',257,193,5,0).hex()}, 'id_lookup': {'anchor_id': bytes([9]*32).hex(), 'key': digest('common-dex/settlement/rolling-height-by-id/v1', bytes([9]*32))}, 'body_vectors': [{'evidence': evidence.hex(), 'continuation': [], 'encoded': body.hex()}, {'evidence': evidence.hex(), 'continuation': [['aa','bb']], 'encoded': historical.hex()}], 'anchor_call': {'body': body.hex(), 'encoded': call.hex(), 'payload_hash': digest('common-dex/native-call/v2',call)}}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check',action='store_true')
    args = parser.parse_args()
    raw = json.dumps(vectors(),indent=2,sort_keys=True)+'\n'
    if args.check:
        if TARGET.read_text() != raw:
            raise SystemExit('native rolling golden mismatch')
        print('PASS: native v3 root, 14 storage slots, ID lookup, metadata and opcode6 framing')
    else:
        TARGET.write_text(raw)

if __name__ == '__main__':
    main()
