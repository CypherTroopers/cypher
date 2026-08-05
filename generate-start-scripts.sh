#!/bin/bash

set -euo pipefail

BINARY="./build/bin/cypher"
NETWORK_ID=16166
NODE_COUNT=21

BASE_RNET_PORT=7102
BASE_P2P_PORT=6000
BASE_HTTP_PORT=8000
BASE_WS_PORT=8546

for ((i=0; i<NODE_COUNT; i++)); do
    RNET_PORT=$((BASE_RNET_PORT + i * 2))
    P2P_PORT=$((BASE_P2P_PORT + i * 2))
    HTTP_PORT=$((BASE_HTTP_PORT + i * 2))
    WS_PORT=$((BASE_WS_PORT + i * 2))

    SCRIPT="start-cypher${i}.sh"
    DATADIR="chaindb${i}"

    cat > "${SCRIPT}" <<SCRIPT_EOF
#!/bin/bash

set -euo pipefail

exec ${BINARY} \\
  --verbosity 4 \\
  --rnetport ${RNET_PORT} \\
  --syncmode full \\
  --nat none \\
  --nodiscover \\
  --netrestrict 127.0.0.0/8 \\
  --ws \\
  --ws.addr 127.0.0.1 \\
  --ws.port ${WS_PORT} \\
  --ws.origins "*" \\
  --metrics \\
  --metrics.addr 127.0.0.1 \\
  --http \\
  --http.addr 127.0.0.1 \\
  --http.port ${HTTP_PORT} \\
  --http.api eth,web3,net,txpool \\
  --http.corsdomain "*" \\
  --allow-insecure-unlock \\
  --port ${P2P_PORT} \\
  --datadir ${DATADIR} \\
  --networkid ${NETWORK_ID} \\
  --gcmode archive \\
  console
SCRIPT_EOF

    chmod +x "${SCRIPT}"

    printf '%-20s datadir=%-12s p2p=%-5s rnet=%-5s http=%-5s ws=%-5s\n' \
        "${SCRIPT}" "${DATADIR}" "${P2P_PORT}" "${RNET_PORT}" \
        "${HTTP_PORT}" "${WS_PORT}"
done

echo
echo "${NODE_COUNT}個の起動スクリプトを作成しました。"
