#!/usr/bin/env bash

echo 'miner.start(1,"0x3555d2c2af8ff75009f7dbfcf7de7ed80f68588d","cypher0101")' | ./build/bin/cypher-linux-amd64 attach ipc:./chaindb0/cypher.ipc
echo 'miner.start(1,"0x60746b20d36500f3353163226ad62bf7e92e1f3c","cypher0101")' | ./build/bin/cypher-linux-amd64 attach ipc:./chaindb1/cypher.ipc
echo 'miner.start(1,"0x01cbcb9b60e73f0244ea1debbee0fd1b8bb11b31","cypher0101")' | ./build/bin/cypher-linux-amd64 attach ipc:./chaindb2/cypher.ipc
echo 'miner.start(1,"0x4b91661f2659a62cb1a0ee54f6540c283d448a86","cypher0101")' | ./build/bin/cypher-linux-amd64 attach ipc:./chaindb3/cypher.ipc
echo 'miner.start(1,"0x9c01a453daf5c36951301ea26c1605ce7489b186","cypher0101")' | ./build/bin/cypher-linux-amd64 attach ipc:./chaindb4/cypher.ipc
echo 'miner.start(1,"0xf1cf67fd1669ddf1df76fd887b2f6da0d11b2cd9","cypher0101")' | ./build/bin/cypher-linux-amd64 attach ipc:./chaindb5/cypher.ipc
echo 'miner.start(1,"0x3abb765b281d2ef60aac35bc85b62692f89c7ee3","cypher0101")' | ./build/bin/cypher-linux-amd64 attach ipc:./chaindb6/cypher.ipc
echo 'miner.start(4,"0xeb8c07def4c5a2541de730b027376e1068aa861a","your password")' | ./build/bin/cypher-linux-amd64 attach ipc:./chaindbmine/cypher.ipc
