https://arxiv.org/html/2501.02970v3

## Preparations

### Requirements

- Git
- Go 1.25.6 or later. GitHub Actions uses Go 1.26.2.
- A supported native build host: Linux amd64, macOS arm64, or Windows amd64.
- miner Minimum requirement is 48GB RAM(VRAM is preferred)For stable operation, 96GB or more is recommended.
- RPC only Minimum 8GB RAM or more is recommended(RPC reward Tx fee 20%)

### Clone

```bash
git clone -b Fair-HotStuff-FHS-D --single-branch https://github.com/CypherTroopers/cypher.git
cd cypher
```

## Build from source

`make cypher` is the single build entry point on every supported operating system. It performs a native build for the current host; it does not cross-compile another operating system.

The build downloads and verifies Go modules, builds the pinned BLS/MCL native libraries, runs the BLS tests, validates the resulting architecture, and places the final files in `build/bin`.

### Linux amd64

Install the native dependencies:

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential git python3 file ca-certificates \
  libgmp-dev libssl-dev
```

Build Cypher:

```bash
make cypher
```

Generated files:

```text
build/bin/cypher
build/bin/cypher-linux-amd64
```

The explicit native alias is `make cypher-linux-amd64`.

### macOS Apple Silicon arm64

Install the Xcode command-line tools if they are not already installed, then install the Homebrew build dependencies:

```bash
xcode-select --install
brew install openssl@3 gmp python
```

Build Cypher:

```bash
make cypher
```

Generated files:

```text
build/bin/cypher
build/bin/cypher-darwin-arm64
```

The explicit native alias is `make cypher-darwin-arm64`. Intel Macs are not a supported build target.

### Windows amd64

Use an **MSYS2 MINGW64** shell for the build. PowerShell and `cmd.exe` are not supported build shells.

Update MSYS2 first:

```bash
pacman -Syu
```

If MSYS2 asks you to close the terminal, reopen the MINGW64 shell and run `pacman -Syu` again. When no further system update is pending, install the build dependencies:

```bash
pacman -S --needed \
  mingw-w64-x86_64-gcc \
  mingw-w64-x86_64-gmp \
  mingw-w64-x86_64-openssl \
  git make python file
```

Ensure that the installed Windows Go toolchain is available inside the MINGW64 shell:

```bash
go version
```

From the repository directory, build Cypher:

```bash
make cypher
```

Generated files:

```text
build/bin/cypher.exe
build/bin/libcrypto-3-x64.dll
build/bin/libgmp-10.dll
build/bin/libstdc++-6.dll
build/bin/libgcc_s_seh-1.dll
build/bin/libwinpthread-1.dll
```

The explicit native alias is `make cypher-windows-amd64`.

### GitHub Actions native builds

The [`Build Binaries`](.github/workflows/build-binaries.yml) workflow uses one native matrix:

| Target | GitHub-hosted runner | Build command |
| --- | --- | --- |
| Linux amd64 | `ubuntu-24.04` | `make cypher TARGET_OS=linux TARGET_ARCH=amd64` |
| macOS arm64 | `macos-15` | `make cypher TARGET_OS=darwin TARGET_ARCH=arm64` |
| Windows amd64 | `windows-2022` with MSYS2 MINGW64 | `make cypher TARGET_OS=windows TARGET_ARCH=amd64` |

Each matrix job uploads only freshly staged and checksummed artifacts. After all three native builds succeed, the default-branch publish job validates their source commit, architecture, toolchain version, BLS revision, and checksums before automatically committing and pushing the files under `build/bin`.

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
## get RPC owner rewards
1.
~~~
personal.newAccount("your password")
~~~
2.(If you want to mining)
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
5.unlock your account for Tx Approval RPC rewards
~~~
personal.unlockAccount("your address", "your password", 0)
~~~

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
