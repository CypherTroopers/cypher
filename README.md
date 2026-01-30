~~~
touch chaindbname/cypher/blocks.rlp
~~~
all blocks ver
~~~
./build/bin/cypher --datadir ./chaindbname  export ./chaindbname/cypher/blocks.rlp
~~~
Range specification　ver
~~~
./build/bin/cypher --datadir ./chaindbname export ./chaindbname/cypher/blocks.rlp 0 141118
~~~
###
~~~
mkdir chaindata-rebuild
~~~
###
~~~
chmod +x scripts/rebuild-state-from-blocks.sh
~~~
###
~~~
./scripts/rebuild-state-from-blocks.sh --datadir ./chaindata-rebuild --genesis ./genesis.json --blocks ./chaindbname/cypher/blocks.rlp --cache 4096 --syncmode full --gcmode archive
~~~
###
~~~
./build/bin/cypher --datadir ./chaindata-rebuild <your usual flags>
~~~
###
~~~
./build/bin/cypher attach ipc:./chaindata-rebuild/cypher.ipc
~~~
###export　and import
~~~
mkdir -p ./exports
~~~
./build/bin/cypher --datadir ./data3 export ./exports/blocks-000001-184999.rlp 1 184999
~~~
~~~
./build/bin/cypher --datadir ./data4 export ./exports/blocks-185000-208223.rlp 185000 208223
~~~
~~~
scripts/rebuild-state-from-blocks.sh \
  --datadir ./data5 \
  --genesis ./genesis.json \
  --blocks ./exports \
  --cache 4096 \
  --syncmode full \
  --gcmode archive
~~~


