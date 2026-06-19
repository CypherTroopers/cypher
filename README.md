## preparations 
### Requirements
- Go ver 1.24 or later
- Git
- GCC / build-essential for CGO dependencies
- Minimum requirement is 48GB RAM(VRAM is preferred)
For stable operation, 96GB or more is recommended.


### Clone

```bash
git clone -b ColossusX_CommonRPC_TXrewards --single-branch https://github.com/CypherTroopers/cypher.git
cd cypher
```
## run a node on Linux
```bash
./colossusX_linux.sh
```
## run a node on Mac
```bash
./colossusX_mac.sh
```
## run a node on Windows
```bash
./colossusX_windows.ps1
```
## Mining
1.
~~~
personal.newAccount("your password")
~~~
2.
~~~
miner.start(5, "your address", "your password")
~~~
3.(optional)change mining reward wallet
~~~
miner.setEtherbase("")
~~~
4.check wallet balance
~~~
web3.fromWei(eth.getBalance("your address"), "ether")
~~~
5.unlock your account for Tx Approval rewards 
~~~
personal.unlockAccount("your address", "your password", 0)
~~~

## go mod（Only if you continue development）
```bash
go mod download
```
## build（Only if you continue development）
```bash
make cypher
```
## setting http/3 QUIC RPC port(example)
Low-latency high-speed communicati
```
https://github.com/CypherTroopers/cypher/blob/ColossusX_CommonRPC_TXrewards/nginx%20example
```
<img width="1448" height="1086" alt="image" src="https://github.com/user-attachments/assets/dbb7c1bd-f031-41a0-933b-2eeadbeac9ba" />

# Validators and Common Miners

## Overview

Validator nodes are responsible for consensus and finality.

They create blocks, verify blocks, run HotStuff finality, and decide the final state of the chain.

Validator nodes do not need to expose public RPC endpoints. Their main role is block production, verification, and finalization.

Common miner nodes are responsible for public transaction admission.

They open public RPC endpoints, receive user transactions, create signed `CommonTxAdmission` records, and relay those admissions to the validator leader.

Common miners do not replace validator consensus. They add a public RPC transaction admission layer in front of the validator network.

## Simple Difference

Validators finalize blocks.

Common miners receive user transactions through public RPC and prove that they accepted them.

Users can choose any common miner RPC endpoint. If one RPC endpoint is down, users can use another common miner RPC endpoint.

Common miners can earn more transaction admission rewards if more users send transactions through their public RPC endpoints.

## Common RPC Reward Rule

When a transaction admitted by a common miner is included in a finalized block, the actual transaction fee is split as follows:

```text
20% → common RPC miner reward
80% → burned
```

The actual transaction fee is calculated from the real execution result:

```text
actualTxFee = gasUsed × effectiveGasPrice
commonRpcReward = actualTxFee / 5
commonRpcBurn = actualTxFee - commonRpcReward
```

The validator verifies the reward values during state processing.

If the included `CommonTxReward` does not match the actual gas used and effective gas price, the block is rejected.

## RPC Output

Common RPC admission and reward data can be checked through:

```text
eth_getTransactionReceipt
eth_getTransactionByHash
```

JavaScript console equivalents:

```text
eth.getTransactionReceipt(txHash)
eth.getTransaction(txHash)
```

Main additional fields:

```text
commonRpcMiner
commonRpcReward
commonRpcBurn
commonTxAdmissionRoot
commonTxRewardRoot
commonTxAdmissionChainId
commonTxAdmissionKeyBlockNumber
commonTxAdmissionTxBlockNumber
commonTxAdmissionTimestamp
commonTxAdmissionSignature
```

Example:

```json
{
  "transactionHash": "0xda4ae1a37dd98beaace23ba670280c26e410177ef8bc7cea78857a4775e17f4e",
  "blockHash": "0xbda50a751138e7a0d5d3ae4275e1ef36698f362c4e320a54dc6a61b550fbd8d4",
  "blockNumber": "0x2",
  "transactionIndex": "0x0",
  "commonRpcMiner": "0x946d4abb364716fd2f8403df28fa4f2b5e953d62",
  "commonRpcReward": "0x3d1e3821000",
  "commonRpcBurn": "0xf478e084000",
  "commonTxAdmissionChainId": "0x9a249f",
  "commonTxAdmissionRoot": "0x7b0ac32c2a18e85c754af34efe8ec8de14b77e754d323e28eddd6a896b17c9dd",
  "commonTxRewardRoot": "0xdaf7c9c4144355ae34108fcf9fd9b2e1b5e113083f25d72c3ebe47cb3a47ff54",
  "commonTxAdmissionSignature": "0x..."
}
```

## Example Fee Calculation

For a normal transfer:

```text
gasUsed = 21000
effectiveGasPrice = 1,000,000,000 wei
```

Total transaction fee:

```text
21000 × 1,000,000,000
= 21,000,000,000,000 wei
= 0.000021 CPH
```

Common miner reward:

```text
20% = 4,200,000,000,000 wei
    = 0.0000042 CPH
```

Burn:

```text
80% = 16,800,000,000,000 wei
    = 0.0000168 CPH
```

Example hex values:

```text
commonRpcReward = 0x3d1e3821000
commonRpcBurn   = 0xf478e084000
```

## Bash Test Commands

Set RPC endpoint, transaction hash, and common miner address:

```bash
RPC_URL="http://167.86.76.166:8000"
TX_HASH="0xee94ceccbb785ee41e479f6ad4a7c04b0a3f0bfe2362d90fa0a05e04afaddec5"
MINER_ADDR="0x946d4abb364716fd2f8403df28fa4f2b5e953d62"
```

Check transaction receipt:

```bash
curl -s -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionReceipt\",\"params\":[\"$TX_HASH\"],\"id\":1}" | jq
```

Check transaction details:

```bash
curl -s -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionByHash\",\"params\":[\"$TX_HASH\"],\"id\":1}" | jq
```

Check common miner balance:

```bash
curl -s -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"$MINER_ADDR\",\"latest\"],\"id\":1}" | jq
```

Show only common RPC reward fields from the receipt:

```bash
curl -s -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionReceipt\",\"params\":[\"$TX_HASH\"],\"id\":1}" \
| jq '.result | {
  transactionHash,
  blockHash,
  blockNumber,
  transactionIndex,
  commonRpcMiner,
  commonRpcReward,
  commonRpcBurn,
  commonTxAdmissionChainId,
  commonTxAdmissionRoot,
  commonTxRewardRoot,
  commonTxAdmissionSignature
}'
```

## All-in-One Bash Check

```bash
#!/usr/bin/env bash
set -euo pipefail

RPC_URL="http://167.86.76.166:8000"
TX_HASH="0x065d4a9562d0cac21a4ea892336ac447e586cb1c2cd9e8a9595a0c618912b812"
MINER_ADDR="0x946d4abb364716fd2f8403df28fa4f2b5e953d62"

echo "===== Transaction Receipt ====="
curl -s -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionReceipt\",\"params\":[\"$TX_HASH\"],\"id\":1}" \
| jq

echo
echo "===== Transaction Details ====="
curl -s -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionByHash\",\"params\":[\"$TX_HASH\"],\"id\":1}" \
| jq

echo
echo "===== Common Miner Balance ====="
curl -s -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"$MINER_ADDR\",\"latest\"],\"id\":1}" \
| jq

echo
echo "===== Common RPC Reward Fields ====="
curl -s -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionReceipt\",\"params\":[\"$TX_HASH\"],\"id\":1}" \
| jq '.result | {
  transactionHash,
  blockHash,
  blockNumber,
  transactionIndex,
  commonTxApprover,
  commonTxApproverReward,
  commonTxBurn,
  commonTxAdmissionChainId,
  commonTxAdmissionRoot,
  commonTxRewardRoot,
  commonTxAdmissionSignature
}'
```

For one normal transfer with `gasUsed = 21000` and `effectiveGasPrice = 1 gwei`, the expected common miner balance increase is:

```text
4,200,000,000,000 wei
= 0.0000042 CPH
```

## Notes

This feature does not make common miners validator consensus members.

Common miners only provide public RPC transaction admission and receive a fee share when their admitted transaction is included in a finalized block.

Validator nodes still verify all admission records, reward records, roots, signatures, chain ID, and final state before accepting the block.
```bash
sudo apt update && sudo apt full-upgrade -y && sudo apt autoremove -y && sudo apt autoclean -y && rm -f go1.26.2.linux-amd64.tar.gz && wget https://go.dev/dl/go1.26.2.linux-amd64.tar.gz && sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.26.2.linux-amd64.tar.gz && export PATH=/usr/local/go/bin:$PATH && export GOPATH=$HOME/go && export GO111MODULE=on && go env -w GO111MODULE=on && echo 'export PATH=/usr/local/go/bin:$PATH' >> ~/.bashrc && echo 'export GOPATH=$HOME/go' >> ~/.bashrc && echo 'export GO111MODULE=on' >> ~/.bashrc && sudo apt-get install -y gcc cmake libssl-dev openssl libgmp-dev bzip2 m4 build-essential git curl libc-dev wget texinfo nodejs npm pcscd && sudo npm install -g n && sudo n stable && sudo apt purge -y nodejs npm && sudo apt autoremove -y && export PATH="/usr/local/bin:$PATH" && hash -r && sudo npm install -g pm2
```
