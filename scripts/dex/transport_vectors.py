#!/usr/bin/env python3
"""Independent socket codec fixture, before Go implementation."""
import hashlib,json,struct,sys
from pathlib import Path

def digest(label,b):return hashlib.sha256(label.encode()+b'\0'+b).digest()
body=b'CDXNET01'+bytes([1])*32+bytes([2])*32+bytes([3,6,1])+bytes.fromhex('01020304')
result={'description':'independent bounded socket frame, TLS authentication tested separately','body':body.hex(),'frame':(struct.pack('>I',len(body))+body).hex(),'id':digest('common-dex/socket-frame/v1',body).hex(),'ack':(bytes([1])+digest('common-dex/socket-frame/v1',body)).hex()}
p=Path(__file__).resolve().parents[2]/'dex/testdata/transport.json'
s=json.dumps(result,indent=2)+'\n'
if '--check' in sys.argv:
 if p.read_text()!=s:raise SystemExit('transport golden mismatch')
 print('transport golden PASS')
else:p.write_text(s)
