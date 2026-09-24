#!/usr/bin/env python3
"""Independent fixed-width business ID vectors; no Go imports or live keys."""
import hashlib, json, pathlib, struct, sys
def digest(label, data): return hashlib.sha256(label.encode()+b'\0'+data).digest()
domain=struct.pack('>HQ',1,1337)+bytes.fromhex('11'*32+'22'*32)+struct.pack('>Q',1)+bytes.fromhex('33'*32)
epoch=digest('common-dex/epoch/v1',domain)
custody=bytes.fromhex('00'*17+'de0001')
key=bytes.fromhex('44'*32)
result={'epoch':epoch.hex(),'custody':custody.hex(),'key':key.hex(),'jobs':{str(lane):digest('common-dex/relay-job/v1',epoch+custody+bytes([lane])+key).hex() for lane in range(1,5)},'inbox_key':digest('common-dex/relay-inbox-key/v1',struct.pack('>QQ',4,8)+key).hex()}
path=pathlib.Path(__file__).resolve().parents[2]/'dex/testdata/relay_job.json'
out=json.dumps(result,indent=2)+'\n'
if '--check' in sys.argv:
 assert path.read_text()==out,'relay job golden differs'
 print('PASS independent relay job vectors')
else:path.write_text(out)
