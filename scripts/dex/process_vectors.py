#!/usr/bin/env python3
"""Independent financial test-network envelope fixtures, before Go codec."""
import json, struct, sys
from pathlib import Path
prefix=b'CDXEXT01'
ref=b'reference-fixture'
vote=b'rlp-structural-only'
result={
 'description':'structural framing only; signatures are exercised by real BLS tests',
 'request':(prefix+b'\x04'+struct.pack('>Q',0x0102030405060708)).hex(),
 'vote':(prefix+b'\x01'+struct.pack('>H',len(ref))+ref+struct.pack('>I',len(vote))+vote).hex(),
 'record':(prefix+b'\x05'+b'{"fixture":1}').hex(),
}
p=Path(__file__).resolve().parents[2]/'dex/testdata/process.json'
s=json.dumps(result,indent=2)+'\n'
if '--check' in sys.argv:
 if p.read_text()!=s:raise SystemExit('process golden mismatch')
 print('process golden PASS')
else:p.write_text(s)
