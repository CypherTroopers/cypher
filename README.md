## 2ChainedBFT

[Fair Byzantine Fault-Tolerant Consensus (FHS-C), arXiv:2501.02970v3](https://arxiv.org/html/2501.02970v3)

### PoW x EVM (through OSAKA) x RPC reward x Mining Reward

New to operating a Common RPC node? Start with the [beginner setup walkthrough](#beginner-setup-common-rpc-node-and-rewards) after building the executable.


## Preparations

### Requirements

- Git
- Go 1.25.6 or later. GitHub Actions uses Go 1.26.2.
- A supported native build host: Linux amd64, macOS arm64, or Windows amd64.
- miner Minimum requirement is 48GB RAM(VRAM is preferred)For stable operation, 96GB or more is recommended.
- RPC only Minimum 8GB RAM or more is recommended(RPC reward Tx fee 20%)

### Clone

```bash
git clone -b FHS-D --single-branch https://github.com/CypherTroopers/cypher.git
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

## Hardened Fair HotStuff consensus

This branch implements the FHS-C current-leader QC-broadcast change and the safety machinery needed to operate it outside the paper's crash-free model:

- Fair HotStuff requires a committee of `n = 3f + 1` validators (`4 <= n <= 100`) and rejects malformed, duplicate, or invalid BLS committee keys at genesis. The upper bound keeps the quorum proof within the authenticated control-message budget.
- Every signer mask has one canonical encoding. Extra bytes, committee-external bits, and under-quorum masks are rejected.
- `NewView` carries each replica's highest observed QC. A leader includes `n - f` independently signed reports and proposes on their highest QC. After verifying the complete aggregate, a replica can select that parent even if it privately observed a higher QC on another uncommitted branch. The observed maximum remains durable and is still advertised in later `NewView` messages. Canonical committed ancestry cannot change.
- Finality requires a certified parent and direct child in consecutive views. This commits the parent and its ancestors. Ancestors separated by skipped views carry the complete descendant-QC path ending in the consecutive pair; sync and restart verify the same proof. A QC alone does not finalize a block.
- Votes go to the current proposer, which persists the QC and pending broadcast before directly sending it to every member of its signing committee. Replay resolves that committee from the QC, including after a committee change. Transport retains the previous committee and generations referenced by durable QC state; message-level authority remains specific to each proof.
- A local timer cannot change views by itself. A view changes only after a verified `2f + 1` timeout certificate; timeout votes and certificates are bounded and persisted. Members periodically relay their active durable TC to repair partial delivery. TX arrivals do not reset the Fair HotStuff no-progress deadline.
- Prepare, vote, QC, NewView, and timeout envelopes are signed by their committee BLS key. QUIC uses mutual, short-lived TLS certificates whose chain ID, node address, and TLS public key are attested by the same BLS identity. Fair HotStuff disables TCP fallback.
- Votes, timeout votes, QCs and safety watermarks are synchronously written before the corresponding message or state transition becomes visible. Reconstructable proposal bodies use a separate durable cache and can be repaired from peers. A persisted leader signature authenticates relayed manifests while missing transactions are fetched, including after the proposer stops. Ahead-of-receiver donors serve historical requests, and a temporary data retrieval timeout retries the retained HighQC. Restart restores the WAL and fails closed on corruption or conflicting same-view votes.
- The QC producer cannot grind the next leader by choosing a signature or signer subset. Leader selection is a domain-separated PRF of the genesis seed, chain ID, absolute view, and historical committee hash, with unbiased rejection sampling.

The supplied [`genesis.json`](genesis.json) commits the complete Fair HotStuff configuration in the genesis header `mixHash`, including the chain ID, committee, EVM fork settings, transport policy, and `fairHotstuffSeed`. The `cypher-fhs-genesis-config-v3` commitment domain identifies the integrated Common RPC reward-recipient protocol. This changes the genesis block hash; existing databases from the old protocol must not be reused.

Common RPC operators are no longer listed in genesis. Initialize every node from the updated genesis in a fresh data directory, including fresh transaction ingress and outbox databases.

The finality-proof format, signed manifest envelope, and certificate recovery records in this experiment require a fresh genesis database. The [self-healing tests](docs/fhs-self-healing.md) include seven separate validator processes with fresh temporary keys and databases, selective message loss, and proposer termination over real QUIC. These tests supplement the signed-QC convergence, finality, and committee-handoff regression tests; they are not a proof of consensus correctness for all adversarial schedules.

The committed seed is a trusted-genesis implementation of the paper's fair-election assumption for a static Byzantine set. It removes current-leader QC grinding, but the schedule is predictable after genesis and the seed creator must generate the seed honestly. Deployments that require resistance to a malicious seed ceremony, adaptive corruption, or targeted future-leader denial of service should replace it with a DKG-backed threshold beacon or an independently verified external beacon.

## Beginner setup: Common RPC node and rewards

This walkthrough sets up a **Common RPC node** that accepts users' signed transactions and earns their admission fees. It does not set up the validator committee. The network's validators must already be configured and running before transactions can finalize and rewards can appear.

### 1. Understand the three accounts

| Name used below | Purpose | Where its private key belongs |
|---|---|---|
| **A: signing account** | Your Common node signs admission proofs and delivery packets with A | In this node's encrypted keystore; unlock only A |
| **B: reward address** | Receives this node's Common RPC transaction rewards directly | In a separate wallet/environment; never import B's key into the Common node |
| **U: user account** | Signs and pays for the transactions submitted to public RPC | In the user's own wallet |

Prepare B first. Copy its complete address: `0x` followed by 40 hexadecimal characters. B must be nonzero and different from A. B does not need an existing balance or a key on this server. An ordinary address or a contract address can receive rewards.

You also need the new network's agreed **genesis.json** and **bootnode enode URLs** from its operator. Use the same genesis as the validators. A Common node alone cannot create a working network, and old-network balances or pending transactions do not automatically move to this new genesis.

### 2. Build and initialize a fresh data directory

Run the build instructions for your operating system above. Use an executable built from the updated FHS-D source; an older checked-in binary may not contain these RPC methods.

The main commands below use **Bash on Linux or macOS**. Run them from the repository directory. Windows equivalents are provided below step 4.

**Terminal 1 — normal shell:**

```bash
CYPHER_BIN="$PWD/build/bin/cypher"
CYPHER_DATA="$PWD/data-common-fhsd"
umask 077
mkdir -m 700 "$CYPHER_DATA" && \
  "$CYPHER_BIN" --datadir "$CYPHER_DATA" init ./genesis.json
```

`Successfully wrote genesis state` means initialization succeeded. Do this once for a new directory. If `mkdir` reports that the directory already exists, the initialization command above is not run: choose a new name for a fresh network, or skip initialization when restarting this same network. Do not delete your old datadir, keystore, WAL, or outbox to make this command succeed.

Keep the same datadir path in every later command. The node stores its chain, encrypted A key, and reward settings there. The private directory permissions also protect access to the IPC socket created inside it.

### 3. Start the Common node

Still in **Terminal 1**, paste the comma-separated bootnode enode URLs supplied by the network operator when prompted. These are public peer addresses, not private keys.

```bash
read -r -p "Paste the new network's bootnode enode URLs: " CYPHER_BOOTNODES
CYPHER_RPC_BIND="127.0.0.1"

"$CYPHER_BIN" \
  --datadir "$CYPHER_DATA" \
  --networkid 10101919 \
  --syncmode full \
  --rnetport 7200 \
  --port 6000 \
  --bootnodes "${CYPHER_BOOTNODES:?Enter the network bootnode URLs first}" \
  --ipcpath cypher.ipc \
  --http --http.addr "$CYPHER_RPC_BIND" --http.port 8000 \
  --http.api eth,net,web3,txpool \
  --ws --ws.addr "$CYPHER_RPC_BIND" --ws.port 9251 \
  --ws.api eth,net,web3,txpool
```

Leave this terminal running. It displays node logs; it is not the JavaScript console. Do not start a second node against the same datadir.

| Setting | Meaning in this example |
|---|---|
| `10101919` | Network ID used by the supplied network; its wallet chain ID is also 10101919 |
| `--rnetport 7200` | Selects the Common bridge role with the supplied genesis, whose committee ports are 7102 through 7114 |
| `6000` | P2P port for peer connectivity |
| `8000` | HTTP JSON-RPC port |
| `9251` | WebSocket JSON-RPC port |
| `cypher.ipc` | Local administrative socket inside the datadir on Linux/macOS |
| `127.0.0.1` | Allows the initial HTTP/WS checks from this computer only |

For a customized genesis, obtain the matching network ID and a Common rnet port that is **not one of its committee ports**. With the supplied configuration, look for `TxQUIC auto role: common RPC FHS bridge` in the startup log. TxQUIC forwarding is selected automatically; public HTTP/3 is a separate optional service and is not needed for this walkthrough. A firewall must allow the required peer traffic and outbound UDP to the network's validator TxQUIC endpoints.

Startup messages that the signing account is not configured yet are expected on the first run. A node can start and synchronize before A or B is configured. Do not add `--mine`, `--unlock`, a command-line password, or `--allow-insecure-unlock` for this Common RPC setup.

### 4. Open the local IPC console

Open **Terminal 2** on the same computer, change to the same repository directory, and attach to the socket belonging to Terminal 1:

```bash
./build/bin/cypher attach "$PWD/data-common-fhsd/cypher.ipc"
```

If you chose a different datadir, substitute its actual path. Successful attachment displays the JavaScript `>` prompt. The `personal.*`, `miner.*`, and `eth.*` commands below go at this prompt, not in Bash. Do not copy the `>` prompt itself.

Use **IPC attach** here. Attaching to `http://127.0.0.1:8000` cannot register B. The embedded console started by the existing launcher scripts also uses an in-process connection, so open this separate IPC session when using those scripts.

Type `exit` to close the attached console when finished. The node in Terminal 1 keeps running.

<details>
<summary>Windows: PowerShell equivalents for steps 2–4</summary>

Build first in MSYS2 MINGW64 as described above. You can then run the resulting executable from PowerShell in the repository directory. Keep its companion DLLs next to the executable.

**PowerShell window 1 — first initialization only:**

```powershell
$ErrorActionPreference = "Stop"
$CYPHER_BIN = Join-Path $PWD "build\bin\cypher.exe"
$CYPHER_DATA = Join-Path $PWD "data-common-fhsd"
if (Test-Path $CYPHER_DATA) { throw "Choose a fresh directory, or skip initialization for a same-network restart." }
New-Item -ItemType Directory -Path $CYPHER_DATA | Out-Null
```

Before proceeding, restrict this folder's Windows Security permissions to the operator account and the administrators required by your deployment. Keep the local named pipe under that account's access controls; never proxy it to TCP.

```powershell
& $CYPHER_BIN --datadir $CYPHER_DATA init .\genesis.json
if ($LASTEXITCODE -ne 0) { throw "Genesis initialization failed; do not continue." }
```

**Start the node in the same window:**

```powershell
$CYPHER_BOOTNODES = Read-Host "Paste the new network's bootnode enode URLs"
if ([string]::IsNullOrWhiteSpace($CYPHER_BOOTNODES)) { throw "Bootnode URLs are required." }
& $CYPHER_BIN `
  --datadir $CYPHER_DATA `
  --networkid 10101919 `
  --syncmode full `
  --rnetport 7200 `
  --port 6000 `
  --bootnodes $CYPHER_BOOTNODES `
  --ipcpath cypher-common-fhsd.ipc `
  --http `
  --http.addr 127.0.0.1 `
  --http.port 8000 `
  --http.api eth,net,web3,txpool `
  --ws `
  --ws.addr 127.0.0.1 `
  --ws.port 9251 `
  --ws.api eth,net,web3,txpool
```

**PowerShell window 2 — attach to the local named pipe:**

```powershell
.\build\bin\cypher.exe attach '\\.\pipe\cypher-common-fhsd.ipc'
```

Continue with the same JavaScript commands below. Use a unique pipe name for each local node. The Windows commands have been checked against the CLI and IPC implementation; this walkthrough has not been executed on Windows.

</details>

### 5. Create A, register B, and unlock A

At the **IPC JavaScript prompt**, create A once:

```javascript
var A = personal.newAccount();
A;
```

Enter a new password at `Passphrase:` and repeat it. The password is not displayed. Save A's returned public address and keep a protected backup of its encrypted keystore and password. You will need the same A after a restart.

If you already created A in this datadir, do not create another account. Instead, list the local addresses and select the intended one:

```javascript
personal.listAccounts;
var A = "0x<replace with your complete existing A address>";
```

Replace the placeholder below with B's actual address from your separate wallet, then register it:

```javascript
var B = "0x<replace with your complete B address>";
personal.setCommonRPCRewardAddress(A, B);
personal.getCommonRPCRewardAddress(A);
```

Enter **A's password** when prompted. B's password or private key is never requested. Successful output contains `configured: true`, `signer` equal to A, and `rewardRecipient` equal to B. It also identifies the chain. Registration is required from the first admission; no activation height is needed.

Now select A as the node's internal signer and unlock it for one hour:

```javascript
miner.setEtherbase(A);
personal.unlockAccount(A, null, 3600);
eth.coinbase;
```

The first two commands should return `true`, and `eth.coinbase` should display A. Despite the existing `setEtherbase` name, B remains the Common RPC reward recipient. Registration does not unlock A or extend an existing unlock deadline.

The `null` argument requests hidden password input; `3600` is seconds. After an hour, call the same unlock command again when you want new admissions to continue. No balance is required on A merely to sign admission proofs. U pays the submitted transaction's fee from U's own balance. Other uses of A, including separate mining rewards, are outside this walkthrough.

The A-to-B setting is saved automatically under `data-common-fhsd/cypher/common-rpc-rewards/`, scoped to ChainID + GenesisHash + A. Do not edit the JSON file to change B; use the authenticated setter.

### 6. Check connectivity, then provide your RPC URL

In the **IPC console**, check:

```javascript
net.peerCount;
eth.syncing;
eth.blockNumber;
eth.chainId();
```

Expect peers on a running network. `eth.syncing` returns progress while syncing and `false` when no sync is active; `false` alone does not prove that an isolated node is up to date. The supplied chain ID is `10101919` (hex `0x9a249f`). Confirm peer connectivity and chain progress with the network operator before expecting finality.

For a separate HTTP check, open a **normal Bash terminal**, not the IPC console:

```bash
curl -sS http://127.0.0.1:8000 \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
```

The response should contain `"result":"0x9a249f"` for the supplied genesis.

To serve users on other computers, set `CYPHER_RPC_BIND="0.0.0.0"` in the Bash startup settings for the next launch; on Windows, change both `--http.addr` and `--ws.addr` accordingly. Allow the intended HTTP/WS ports through your firewall and give users your actual reachable server address. `0.0.0.0` is a listening setting, not a URL to enter in a wallet. A remote wallet's `127.0.0.1` refers to the wallet's own computer.

For an HTTPS service and browser dApps, configure TLS at your chosen endpoint and restrict the accepted hostname/origins to your own service. Example additional flags, with the example domains replaced by your actual domains:

```text
--http.vhosts rpc.example.com
--http.corsdomain https://wallet.example.com
--ws.origins https://wallet.example.com
```

These flags do not grant administrative access. HTTP, WS, and HTTP/3 reject node-wallet signing, sending, key management, and B registration even when A is unlocked. IPC stays local and must not be exposed through a public proxy.

### 7. Send a user-signed transaction and check B's reward

In U's own wallet, add the network using:

| Wallet setting | Value for the supplied network |
|---|---|
| Network name | A descriptive name, such as `Cypher FHS-D` |
| RPC URL | Your reachable HTTP/HTTPS RPC URL; `http://127.0.0.1:8000` only when the wallet runs on the node computer |
| Chain ID | `10101919` |
| Currency symbol | `CPH` |

U needs funds on **this new chain** to pay transaction fees. Obtain test funds through the network's normal funding process. Do not import U's or B's private key into the Common node. Send a small test transaction from U's wallet; the wallet signs it locally and submits the signed transaction to RPC. Transfers, contract calls, and deployments use this same path.

Before sending, you can record B's starting balance in the **IPC console**:

```javascript
var balanceBefore = eth.getBalance(B);
```

<details>
<summary>Optional: submit an already signed raw TX with curl (Bash)</summary>

This broadcasts the supplied transaction and uses U's funds for its fee. Obtain the signed transaction hex from U's own wallet, then run in a normal Bash terminal on the node computer:

```bash
read -r -p "Paste the user-signed raw TX hex: " SIGNED_RAW_TX
curl -sS http://127.0.0.1:8000 \
  -H 'Content-Type: application/json' \
  --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_sendRawTransaction\",\"params\":[\"$SIGNED_RAW_TX\"],\"id\":1}"
```

A successful result is the TX hash. It confirms admission, not block finality. Signed raw batches and options remain supported by `eth_sendRawTransactions` and `eth_sendRawTransactionWithOpts`.

</details>

Copy the TX hash returned by the wallet or RPC. In the **IPC console**, replace the placeholder and inspect its receipt:

```javascript
var txHash = "0x<replace with the complete transaction hash>";
var receipt = eth.getTransactionReceipt(txHash);
receipt;
```

If the result is `null`, wait for finality and repeat the receipt lookup. Once it is an object, check:

```javascript
receipt.commonTxApprover;
receipt.commonTxRewardRecipient;
receipt.commonTxApproverReward;
receipt.commonTxBurn;
web3.fromWei(eth.getBalance(B), "ether").toString(10);
web3.fromWei(eth.getBalance(B).minus(balanceBefore), "ether").toString(10);
```

For a TX credited to your Common node, the first field identifies A and the second identifies B. The reward is `floor(gasUsed * effectiveGasPrice / 5)`, paid directly to B. A earns no part of this Common TX reward. `"ether"` is the web3 unit name for 10^18 wei; the balance here is in CPH. The balance change can also include other transfers/rewards, so distinguish those when checking the amount. If another Common operator's valid admission wins, the receipt identifies that operator and its recipient instead.

### 8. Restart safely or change B later

For a normal restart of this same network, reuse the datadir and repeat the node start command; do not run initialization again. In a new terminal, first restore the `CYPHER_BIN` and `CYPHER_DATA` assignments from step 2, then follow step 3. Skip the directory creation and genesis initialization commands. Reattach by IPC and select/unlock the existing A:

```javascript
var A = "0x<replace with your saved A address>";
miner.setEtherbase(A);
personal.getCommonRPCRewardAddress(A);
personal.unlockAccount(A, null, 3600);
```

The B registration survives restart, but the unlocked state does not. `miner.setEtherbase(A)` changes the running process; to select A automatically on later launches, add `--miner.etherbase "0x<your actual A address>"` to your saved startup command. That public address is safe to put in configuration; its password is not. Continue unlocking through IPC.

To direct future admissions to a new address C, prepare C separately and run in IPC:

```javascript
var C = "0x<replace with the complete new reward address>";
personal.setCommonRPCRewardAddress(A, C);
personal.getCommonRPCRewardAddress(A);
```

Enter A's password again. Already accepted transactions and retries retain their original B proof; only new transactions use C. This operation does not move B's existing funds.

### Common problems

| Symptom | What to check |
|---|---|
| `method not found` for reward registration | Use actual IPC attach and the newly built executable. HTTP/WS/HTTP/3 and the embedded in-process console cannot register B |
| `Common RPC reward recipient is not configured` | Register B for the same A shown by `eth.coinbase`, on this chain and datadir |
| `authentication needed`, locked account, or signing error | Select the intended A and unlock it through IPC; check whether the one-hour deadline expired |
| Incorrect password or invalid recipient error | Enter A's password and a complete nonzero B address different from A; the old preference remains unchanged |
| Cannot open IPC | Keep Terminal 1 running; use its actual socket/pipe path and operator account; check private-directory/pipe permissions |
| Zero peers, delivery retries, or receipt stays `null` | Check the agreed genesis, bootnode URLs, synchronization, validator availability, and required TCP/UDP connectivity. An admission response alone is not finality |
| Genesis mismatch on startup | Use the agreed updated genesis with a fresh datadir for the new network; preserve old data instead of deleting it |
| Registry cannot be read or saved | Check datadir permissions and storage; repair the cause. Do not replace it with an empty file or expect fallback payment to A |
| Node is running but no rewards appear | Rewards require submitted TXs that finalize with your selected admission; uptime alone does not earn this fee reward |

The unlocked A key still exists inside the node process. Protect the OS account, keystore backups, and IPC access. These RPC restrictions do not protect against an attacker who controls that process or the operator account.

For the exact API inventory, storage guarantees, and remaining platform limitations, see the [operation guide](docs/fhsd-rpc-reward-recipient.md) and [verification record](docs/fhsd-rpc-reward-verification.md).

### Using the existing launcher scripts

The scripts below are alternatives to the manual startup command. Review their datadir, binary, genesis, peer, and bind settings before running one; do not run it alongside the manual node against the same datadir. The Unix scripts set `DATADIR`, while the Windows script sets `DATADIR_NAME`. Their embedded console is not IPC, so use a separate IPC attach session for B registration as shown above.

```bash
# Linux
./colossusX_linux.sh
```

```bash
# macOS
./colossusX_mac.sh
```

```powershell
# Windows
.\colossusX_windows.ps1
```

## setting http/3 QUIC RPC port(example)
Low-latency, high-speed communication example: [nginx HTTP/3 configuration](https://github.com/CypherTroopers/cypher/blob/ColossusX_CommonRPC_TXrewards/nginx%20example).
<img width="1448" height="1086" alt="image" src="https://github.com/user-attachments/assets/dbb7c1bd-f031-41a0-933b-2eeadbeac9ba" />

# Validators and Common Miners

## Overview

Validator nodes are responsible for consensus and finality.

They create blocks, verify blocks, run HotStuff finality, and decide the final state of the chain.

Validator nodes do not need to expose public RPC endpoints. Their main role is block production, verification, and finalization.

Common miner nodes are responsible for public transaction admission.

They open public RPC endpoints, receive user transactions, create signed `CommonTxAdmission` records, and relay those admissions to the validator leader.

Common miners do not replace validator consensus. They add a public RPC transaction admission layer in front of the validator network.

TxQUIC verifies each sender's signature. Its optional `AllowedSigners` and `AllowIPs` settings restrict a local endpoint only when populated; empty lists accept any correctly signed sender from any source IP. The supplied configuration leaves both filters empty. Validator committee authentication remains required.

## Simple Difference

Validators finalize blocks.

Common miners receive user transactions through public RPC and prove that they accepted them.

Users can choose any common miner RPC endpoint. If one RPC endpoint is down, users can use another common miner RPC endpoint.

Common miners can earn more transaction admission rewards if more users send transactions through their public RPC endpoints.

## Common RPC Reward Rule

Every Common RPC admission identifies signing account A and a distinct reward recipient B. A signs the complete proof, including B. Validators require the matching A and B in the reward record; they do not use their local reward preference to decide block payouts.

The actual transaction fee is split without changing its calculation or rounding:

```text
actualTxFee = gasUsed * effectiveGasPrice
commonRpcReward = floor(actualTxFee / 5)
commonRpcBurn = actualTxFee - commonRpcReward
```

After every transaction in the block executes, rewards are aggregated by recipient and credited directly to B. There is no intermediate credit to A, automatic transfer, contract call to B, or claim transaction. A missing B prevents a new admission; it never restores payment to A.

For a transaction using 21,000 gas at an effective gas price of 1 gwei, B receives 4,200,000,000,000 wei (0.0000042 CPH), and 16,800,000,000,000 wei is burned. Other reward types retain their existing recipients and amounts.

## RPC Output

Use `eth_getTransactionReceipt` and `eth_getTransactionByHash`, or the console equivalents `eth.getTransactionReceipt(txHash)` and `eth.getTransaction(txHash)`.

| Field | Meaning |
|---|---|
| `commonTxApprover` | Admission signer A |
| `commonTxRewardRecipient` | Actual reward recipient B |
| `commonTxApproverReward` | Common RPC fee reward credited to B; existing field name retained |
| `commonTxBurn` | Burned remainder of the actual fee |
| `commonTxAdmissionRoot` | Block commitment to the signed admissions and references |
| `commonTxRewardRoot` | Block commitment to reward records |
| `commonTxAdmissionChainId` | Chain ID bound to the proof |
| `commonTxAdmissionKeyBlockNumber` | Admission's key-block boundary |
| `commonTxAdmissionTimestamp` | Signed admission timestamp |
| `commonTxAdmissionSignature` | A's signature over the admission payload |

For a client connected to public RPC:

```javascript
var receipt = eth.getTransactionReceipt(txHash);
receipt.commonTxApprover;
receipt.commonTxRewardRecipient;
receipt.commonTxApproverReward;
receipt.commonTxBurn;
eth.getBalance(receipt.commonTxRewardRecipient);
```

Compare B's balance against its initial balance and ordinary transfers. Receiving Common RPC fees does not make B or the Common operator a validator. Validators still verify proofs, reward amounts, roots, signatures, chain identity, and final state.
