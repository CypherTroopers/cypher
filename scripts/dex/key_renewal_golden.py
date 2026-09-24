#!/usr/bin/env python3
"""Independent anchor-v2 and RLP-v3 codec fixtures, not finality proofs."""
import argparse,hashlib,json,pathlib,struct
from rolling_anchor_golden import rlp,vectors as old_vectors
OUT=pathlib.Path(__file__).resolve().parents[2]/'dex/testdata/key_renewal.json'
def digest(label,raw):return hashlib.sha256(label.encode()+b'\0'+raw).digest()
def vectors():
 old=old_vectors()['anchors'][1];raw=bytes.fromhex(old['encoded']);ids=[bytes.fromhex('a1'*32),bytes.fromhex('a2'*32)];boundary=digest('common-dex/clx-key-boundary/v1',bytes([len(ids)])+b''.join(ids));rows=[]
 for name,end,root in [('pending',259,boundary),('cleared',0,bytes(32))]:
  encoded=struct.pack('>H',2)+raw[2:]+struct.pack('>Q',end)+root
  assert len(encoded)==286
  rows.append(dict(name=name,encoded=encoded.hex(),id=digest('common-dex/clx-anchor/v2',encoded).hex(),activation_end=end,activation_root=root.hex()))
 base=bytes.fromhex(rows[0]['id']);wire=rlp([3,base,[],[b'\xc0'],[],[],b'\xc0',ids]);wire4=rlp([4,base,[],[b'\xc0'],[],[],b'\xc0',ids,bytes([3,1,2,4,5,6,0]),b'\xc0',bytes(range(7))])
 return dict(spec='docs/dex/fixed-key-renewal-spec.md',anchor_size=286,legacy_anchor=old,anchors=rows,boundary_ids=[x.hex()for x in ids],boundary_root=boundary.hex(),codec_only_evidence=dict(encoded=wire.hex(),key_header='c0',base=base.hex(),authenticates_state=False),codec_only_permutation_evidence=dict(encoded=wire4.hex(),authenticates_state=False))
def main():
 p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');a=p.parse_args();raw=json.dumps(vectors(),indent=2)+'\n'
 if a.check:
  if OUT.read_text()!=raw:raise SystemExit('key renewal golden mismatch')
  print('key renewal goldens: legacy246 unchanged, two286-byte anchors, boundary ID commitment and RLPv3 PASS')
 else:OUT.write_text(raw)
if __name__=='__main__':main()
