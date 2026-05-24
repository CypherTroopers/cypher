#!/usr/bin/env bash
set -euo pipefail

echo "==> Init genesis"
./build/bin/cypher-linux-amd64 --datadir chaindbname init ./genesistest.json

echo "==> Start Cypher node"
./build/bin/cypher \
  --verbosity 1 \
  --rnetport 7200 \
  --syncmode full \
  --nat extip:$(curl -4 -s ifconfig.io) \
  --ws \
  --ws.addr 0.0.0.0 \
  --ws.port 9251 \
  --ws.origins "*" \
  --metrics \
  --http \
  --http.addr 0.0.0.0 \
  --http.port 8000 \
  --http.api eth,web3,net,txpool \
  --http.corsdomain "*" \
  --port 6000 \
  --datadir chaindbname \
  --networkid 123678 \
  --gcmode archive \
  --bootnodes enode://e10a90e9c7d077002d4d56b88943b8dfbca1d6490bb92c8202e6acb68ef23b521bf187fb40c07eed2f453f3782e8c53ca5a4ec1d34a4454960143501df8c4b95@149.102.156.210:6000 \
  console
