#!/usr/bin/env bash
set -euo pipefail

DATADIR="chaindbname"

CYPHER_BIN="./build/bin/cypher-darwin-arm64"

BOOTNODE_HOST="${CYPHER_BOOTNODE_HOST:-13.140.169.170}"
BOOTNODE_HOST="${BOOTNODE_HOST#[}"
BOOTNODE_HOST="${BOOTNODE_HOST%]}"

BOOTNODE_ADDR="${BOOTNODE_HOST}"
if [[ "${BOOTNODE_ADDR}" == *:* ]]; then
  BOOTNODE_ADDR="[${BOOTNODE_ADDR}]"
fi

BOOTNODES_ARRAY=(
  "enode://e10a90e9c7d077002d4d56b88943b8dfbca1d6490bb92c8202e6acb68ef23b521bf187fb40c07eed2f453f3782e8c53ca5a4ec1d34a4454960143501df8c4b95@${BOOTNODE_ADDR}:6000"
  "enode://0c8a37a7803c358d8ae68784ef247a0c8b4df542d925b23491dd92f4c2172a146a124171ec5bbdcc2e5932e4cead917505ce3b5dbd72155a78e830ebd8e37b07@${BOOTNODE_ADDR}:6001"
  "enode://65ebdea1e99c440bb5463b68565e7422ab332ef8d1472daa956d23b70245ef9703c23ea110291eeb6fe0b60c7e55fed08f76e71fb980ae9b3e2fe583a115e7f3@${BOOTNODE_ADDR}:6002"
  "enode://c7a724e53dc21ff034e628bb4e50d720e6bbc276bd17cc15cc9a28149a5f0a6bd90c0e50f862f5546fa9bc153c7ea818cdf3d133d06356e76b99726754a6b3da@${BOOTNODE_ADDR}:6003"
  "enode://a99ba2027de40c50220e45af60698d7e04237c128258065261fae82cef723837f00ce8611c3164b9efdfc15f0480a308ac65058db9a3abdf83aae05604c9a495@${BOOTNODE_ADDR}:6004"
  "enode://8a3aad9282f773ddd38b05516c2c5847ef168b8b5095f57312a458e0a5b358655cb971d1ba193999b0454fc4ae5642f31c6f6bce311a8da11b0a6d9940719a5e@${BOOTNODE_ADDR}:6005"
  "enode://7eb6bd844e05f64114ea6e6f06ae04e075df0a8a6d783620344f3535df2f2115ad2ad09dab69cf3515ee2d0ac50379c0825a0abfa5a50216d8e4b97823acbd67@${BOOTNODE_ADDR}:6006"
)

BOOTNODES="$(IFS=,; echo "${BOOTNODES_ARRAY[*]}")"

RPC_BIND="${CYPHER_RPC_BIND:-0.0.0.0}"
WS_BIND="${CYPHER_WS_BIND:-${RPC_BIND}}"

PEER_DIR="./${DATADIR}/cypher"
CHAINDATA_DIR="${PEER_DIR}/chaindata"
STATIC_NODES_FILE="${PEER_DIR}/static-nodes.json"
TRUSTED_NODES_FILE="${PEER_DIR}/trusted-nodes.json"

if [ ! -x "${CYPHER_BIN}" ]; then
  echo "ERROR: Cypher binary not found or not executable: ${CYPHER_BIN}"
  echo "Run: chmod +x ${CYPHER_BIN}"
  exit 1
fi

if [ ! -f "./genesistest.json" ]; then
  echo "ERROR: genesistest.json not found"
  exit 1
fi

if [ ! -d "${CHAINDATA_DIR}" ]; then
  echo "==> Chaindata not found: ${CHAINDATA_DIR}"
  echo "==> Init genesis"

  "${CYPHER_BIN}" \
    --datadir "${DATADIR}" \
    init ./genesistest.json
else
  echo "==> Existing chaindata detected: ${CHAINDATA_DIR}"
  echo "==> Skip init genesis"
fi

mkdir -p "${PEER_DIR}"

if [ ! -f "${STATIC_NODES_FILE}" ]; then
  echo "==> static-nodes.json not found"
  echo "==> Write static peers: ${STATIC_NODES_FILE}"

  {
    printf '[\n'
    for i in "${!BOOTNODES_ARRAY[@]}"; do
      comma=","
      if [ "${i}" -eq "$((${#BOOTNODES_ARRAY[@]} - 1))" ]; then
        comma=""
      fi
      printf '  "%s"%s\n' "${BOOTNODES_ARRAY[$i]}" "${comma}"
    done
    printf ']\n'
  } > "${STATIC_NODES_FILE}"
else
  echo "==> Existing static-nodes.json detected: ${STATIC_NODES_FILE}"
  echo "==> Skip static-nodes.json generation"
fi

if [ ! -f "${TRUSTED_NODES_FILE}" ]; then
  echo "==> trusted-nodes.json not found"
  echo "==> Copy static-nodes.json to trusted-nodes.json"

  cp "${STATIC_NODES_FILE}" "${TRUSTED_NODES_FILE}"
else
  echo "==> Existing trusted-nodes.json detected: ${TRUSTED_NODES_FILE}"
  echo "==> Skip trusted-nodes.json generation"
fi

echo "==> Start Cypher node"
echo "==> Bootnode host: ${BOOTNODE_HOST}"
echo "==> RPC bind: ${RPC_BIND}"
echo "==> WS bind: ${WS_BIND}"

"${CYPHER_BIN}" \
  --verbosity 1 \
  --rnetport 7200 \
  --syncmode full \
  --ws \
  --ws.addr "${WS_BIND}" \
  --ws.port 9251 \
  --ws.origins "*" \
  --metrics \
  --http \
  --allow-insecure-unlock \
  --http.addr "${RPC_BIND}" \
  --http.port 8000 \
  --http.api eth,web3,net,txpool \
  --http.corsdomain "*" \
  --port 6000 \
  --datadir "${DATADIR}" \
  --networkid 10101919 \
  --gcmode archive \
  --bootnodes "${BOOTNODES}" \
  console
