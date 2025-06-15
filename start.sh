#!/bin/bash

./build/bin/cypher \
  --verbosity 4 \
  --rnetport 7100 \
  --syncmode full \
  --nat none \
  --ws \
  --ws.addr 0.0.0.0 \
  --ws.port 8546 \
  --ws.origins "*" \
  --http \
  --http.addr 0.0.0.0 \
  --http.port 8000 \
  --http.api eth,web3,net,miner,txpool,personal \
  --http.corsdomain "*" \
  --port 6000 \
  --miner.gastarget 3758096384 \
  --datadir chaindbname \
  --networkid 16166 \
  --gcmode archive \
  --allow-insecure-unlock \
  --mine \
  --bootnodes enode://a37941b709d0c6138704ee961c495cddbf6e92a09e85f88ddef977619b3d8e054197e9b89ef83891698668c5bdcbec6deeec1951bf41f65800c8285a7ea047fe@5.180.149.109:30303 \
  console
