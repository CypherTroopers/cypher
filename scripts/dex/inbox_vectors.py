#!/usr/bin/env python3
"""Independent fixed-width inbox and existing CLX leader-election vectors."""
import argparse
import hashlib
import json
import pathlib
import struct

OUT = pathlib.Path(__file__).resolve().parents[2] / "dex/testdata/inbox.json"

def digest(label, data=b""):
    return hashlib.sha256(label.encode("ascii") + b"\0" + data).hexdigest()

def vectors():
    entries = []
    for index, bucket in [(0, 1), (1, 2), (2, 3)]:
        raw = (struct.pack(">HQ", 2, 10101919) + bytes.fromhex("11"*32)
               + bytes.fromhex("22"*32) + bytes.fromhex("33"*20)
               + bytes.fromhex("44"*20) + struct.pack(">QI", 7+index, 0)
               + bytes.fromhex("55"*32) + struct.pack(">Q", index)
               + bytes.fromhex("44"*20) + (10**18+index).to_bytes(32,"big")
               + struct.pack(">BI", bucket, 0))
        assert len(raw) == 223
        entries.append({"index":index,"bucket":bucket,"encoded":raw.hex(),
                        "hash":digest("common-dex/inbox-entry/v2",raw),
                        "source_id":digest("common-dex/inbox-source/v2",raw[:158]),
                        "slot":digest("common-dex/inbox-entry-slot/v2",struct.pack(">Q",index))})
    leaders=[]
    for view in range(1,15):
        counter=0
        while True:
            h=hashlib.sha256(b"cypher-fhs-leader-v2"+bytes.fromhex("66"*32)
              +struct.pack(">QQ",10101919,view)+bytes.fromhex("77"*32)+struct.pack(">Q",counter)).digest()
            candidate=int.from_bytes(h[:8],"big")
            if candidate >= 2**64 % 7: break
            counter+=1
        leaders.append({"view":view,"index":candidate%7,"counter":counter})
    return {"source":"docs/dex/integration-deposit-spec.md","entry_size":223,
            "market_oracle":"88"*20,
            "market_seed":digest("common-dex/native-market-config/v2",bytes.fromhex("88"*20)),
            "count_slot":digest("common-dex/inbox-count-slot/v2"),"entries":entries,
            "leader_seed":"66"*32,"leader_committee":"77"*32,"chain_id":10101919,
            "leaders":leaders,
            "finality_cases":[{"name":name,"accepted":False} for name in
                ["unfinalized_target", "orphan_parent", "forged_sign_info_same_hash",
                 "single_qc_only", "terminal_view_gap", "forged_committee", "wrong_genesis",
                 "entry_amount", "entry_owner", "entry_custody", "entry_payload", "bad_storage_proof", "cursor_gap"]]}

def main():
    parser=argparse.ArgumentParser();parser.add_argument("--check",action="store_true")
    args=parser.parse_args(); raw=json.dumps(vectors(),indent=2)+"\n"
    if args.check:
        if OUT.read_text()!=raw: raise SystemExit("inbox vectors differ")
        print("inbox vectors: PASS")
    else: OUT.write_text(raw)

if __name__=="__main__": main()
