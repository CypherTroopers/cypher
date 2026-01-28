---
touch chaindbname/cypher/blocks.rlp
---
 all blocks ver
---
./build/bin/cypher --datadir ./chaindbname  export ./chaindbname/cypher/blocks.rlp
---
Range specification　ver
---
./build/bin/cypher export /path/to/blocks.rlp 0 182531
---
mkdir chaindata-rebuild

chmod +x scripts/rebuild-state-from-blocks.sh

./scripts/rebuild-state-from-blocks.sh --datadir ./chaindata-rebuild --genesis ./genesis.json --blocks ./chaindbname/cypher/blocks.rlp --cache 4096 --syncmode full --gcmode archive


./build/bin/cypher --datadir ./chaindata-rebuild <your usual flags>




