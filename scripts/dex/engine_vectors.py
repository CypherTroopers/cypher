#!/usr/bin/env python3
"""Independent devnet action codec and financial trace; no Go execution."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

def digest(label, data):
    return hashlib.sha256(label.encode() + b'\0' + data).hexdigest()

def vectors():
    cases = []
    for kind in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]:
        fields = dict(version=1, epoch='11'*32, kind=kind, owner='22'*20,
                      nonce=kind+1, order_id=0, side=0, quantity=0, price='0',
                      recipient='00'*20, amount='0', deposit_id=0,
                      feed_sequence=0, funding_rate=0, valid_until=0,
                      target='00'*20, flags=0)
        if kind == 1: fields['deposit_id'] = 0
        if kind == 2: fields.update(price=str(100*10**18), feed_sequence=1, funding_rate=100, valid_until=40)
        if kind in [3,5]: fields.update(order_id=100, side=-1, quantity=10**8, price=str(100*10**18))
        if kind == 4: fields['order_id'] = 100
        if kind == 6: fields.update(recipient='33'*20, amount=str(10*10**18))
        if kind == 8: fields['target'] = '44'*20
        if kind == 9: fields['target'] = digest('common-dex/reward-close-action/v1', b'fixture close payload')[:40]
        f=fields
        raw=(struct.pack('>H',f['version']) + bytes.fromhex(f['epoch']) + struct.pack('>B',kind)
             +bytes.fromhex(f['owner'])+struct.pack('>QQbQ',f['nonce'],f['order_id'],f['side'],f['quantity'])
             +int(f['price']).to_bytes(32,'big')+bytes.fromhex(f['recipient'])+int(f['amount']).to_bytes(32,'big')
             +struct.pack('>QQqQ',f['deposit_id'],f['feed_sequence'],f['funding_rate'],f['valid_until'])
             +bytes.fromhex(f['target'])+struct.pack('>B',f['flags']))
        assert len(raw)==217
        cases.append(dict(fields=f, encoded=raw.hex(), hash=digest('common-dex/action/v1',raw)))
    # Alice buys 1 BTC at100 CLX as taker; Bob maker. funding +100ppm.
    # Bob buys back at110 (taker), Alice's resting sell closes her long.
    atom=10**18
    a=100*atom - 3*atom//100 - atom//100 + 10*atom - 11*atom//1000
    b=100*atom - atom//100 + atom//100 - 10*atom - 33*atom//1000
    fees=84*atom//1000
    assert a+b+fees==200*atom
    return dict(version=1,codec=cases,trace=dict(alice_cash_before_withdraw=str(a),bob_cash=str(b),
         fees=str(fees),funding_dust='0',withdrawal=str(10*atom),alice_cash_after_withdraw=str(a-10*atom)),
         funding_resume=dict(pending_slot=10,resume_height=13,mark=str(110*atom),rate=100,
             long_delta=str(-(110*atom*100//1000000)),short_delta=str(110*atom*100//1000000),dust='0'))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');a=p.parse_args()
    path=Path(__file__).resolve().parents[2]/'dex/testdata/engine.json'
    expected=vectors()
    if a.check:
        assert json.loads(path.read_text())==expected
        print('PASS: 10 action codecs + independent trade/funding/withdrawal trace')
    else: path.write_text(json.dumps(expected,indent=2)+'\n')
