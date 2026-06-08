#!/usr/bin/env bash
set -euo pipefail

DATADIR="chaindbname"

PEER_DIR="./${DATADIR}/cypher"
CHAINDATA_DIR="${PEER_DIR}/chaindata"
STATIC_NODES_FILE="${PEER_DIR}/static-nodes.toml"
TRUSTED_NODES_FILE="${PEER_DIR}/trusted-nodes.toml"

if [ ! -d "${CHAINDATA_DIR}" ]; then
  echo "==> Chaindata not found: ${CHAINDATA_DIR}"
  echo "==> Init genesis"

  ./build/bin/cypher-linux-amd64 \
    --datadir "${DATADIR}" \
    init ./genesistest.json
else
  echo "==> Existing chaindata detected: ${CHAINDATA_DIR}"
  echo "==> Skip init genesis"
fi

mkdir -p "${PEER_DIR}"

if [ ! -f "${STATIC_NODES_FILE}" ]; then
  echo "==> static-nodes.toml not found"
  echo "==> Write static peers: ${STATIC_NODES_FILE}"

  cat > "${STATIC_NODES_FILE}" <<'EOF'
nodes = [
  "enode://e10a90e9c7d077002d4d56b88943b8dfbca1d6490bb92c8202e6acb68ef23b521bf187fb40c07eed2f453f3782e8c53ca5a4ec1d34a4454960143501df8c4b95@158.220.101.48:6000",
  "enode://0c8a37a7803c358d8ae68784ef247a0c8b4df542d925b23491dd92f4c2172a146a124171ec5bbdcc2e5932e4cead917505ce3b5dbd72155a78e830ebd8e37b07@158.220.101.48:6001",
  "enode://65ebdea1e99c440bb5463b68565e7422ab332ef8d1472daa956d23b70245ef9703c23ea110291eeb6fe0b60c7e55fed08f76e71fb980ae9b3e2fe583a115e7f3@158.220.101.48:6002",
  "enode://c7a724e53dc21ff034e628bb4e50d720e6bbc276bd17cc15cc9a28149a5f0a6bd90c0e50f862f5546fa9bc153c7ea818cdf3d133d06356e76b99726754a6b3da@158.220.101.48:6003",
  "enode://a99ba2027de40c50220e45af60698d7e04237c128258065261fae82cef723837f00ce8611c3164b9efdfc15f0480a308ac65058db9a3abdf83aae05604c9a495@158.220.101.48:6004",
  "enode://8a3aad9282f773ddd38b05516c2c5847ef168b8b5095f57312a458e0a5b358655cb971d1ba193999b0454fc4ae5642f31c6f6bce311a8da11b0a6d9940719a5e@158.220.101.48:6005",
  "enode://7eb6bd844e05f64114ea6e6f06ae04e075df0a8a6d783620344f3535df2f2115ad2ad09dab69cf3515ee2d0ac50379c0825a0abfa5a50216d8e4b97823acbd67@158.220.101.48:6006",
]
EOF

else
  echo "==> Existing static-nodes.toml detected: ${STATIC_NODES_FILE}"
  echo "==> Skip static-nodes.toml generation"
fi

if [ ! -f "${TRUSTED_NODES_FILE}" ]; then
  echo "==> trusted-nodes.toml not found"
  echo "==> Copy static-nodes.toml to trusted-nodes.toml"

  cp "${STATIC_NODES_FILE}" "${TRUSTED_NODES_FILE}"
else
  echo "==> Existing trusted-nodes.toml detected: ${TRUSTED_NODES_FILE}"
  echo "==> Skip trusted-nodes.toml generation"
fi

PUBLIC_IP="$(curl -4 -s ifconfig.io || true)"

if [ -z "${PUBLIC_IP}" ]; then
  echo "ERROR: Failed to detect public IPv4 address"
  exit 1
fi

echo "==> Public IP: ${PUBLIC_IP}"
echo "==> Start Cypher node"

./build/bin/cypher-linux-amd64 \
  --verbosity 4 \
  --rnetport 7200 \
  --syncmode full \
  --nat "extip:${PUBLIC_IP}" \
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
  --allow-insecure-unlock \
  --datadir "${DATADIR}" \
  --networkid 10101919 \
  --gcmode archive \
  --bootnodes "enode://e10a90e9c7d077002d4d56b88943b8dfbca1d6490bb92c8202e6acb68ef23b521bf187fb40c07eed2f453f3782e8c53ca5a4ec1d34a4454960143501df8c4b95@158.220.101.48:6000" \
  console
