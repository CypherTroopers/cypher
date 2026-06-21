## For Devs 
If you want to continue development locally, you need to work with GO111MODULE=off because this project does not use Go modules.
You will also need to install several required tools.
For Windows, Mac, and Linux setup steps, please refer to:
***.github/workflows/build-binaries.yml***
## EVM Prague and Osaka pipelines are partially prepared.
If you upgrade them, please add the required files to the params directory.
Refer to ***params/modern_config.go***and***params/config.go***
If the added files still contain PoS-related settings, please comment out the PoS-related code.


## Setup Linux/Windows/mac

```bash
git clone https://github.com/CypherTroopers/cypher.git
cd cypher
 ```
## go mod（Only if you continue development）
```bash
go mod download
```
## build（Only if you continue development）
```bash
make cypher
```
## start node

***Linux***
```bash
chmod +x colossusX_linux.sh
chmod +x ./build/bin/cypher-linux-amd64
./colossusX_linux.sh
```

***Windows***
```powershell
Unblock-File .\colossusX_windows.ps1
Unblock-File .\build\bin\cypher.exe
powershell -ExecutionPolicy Bypass -File .\colossusX_windows.ps1
```

***mac(Apple Silicon Mac)***
```bash
chmod +x colossusX_mac.sh
chmod +x ./build/bin/cypher-darwin-arm64
./colossusX_mac.sh
```

## start mining (console)Linux/Windows/mac
## console command Linux/Windows/mac
1. Generate a wallet
 ```
personal.newAccount("your password")
 ```
2.Start mining
 ```
miner.start(1, "0x your address here", "your password")
 ```
3.You can specify the wallet address that will receive the mining rewards.
If you do not specify one, the rewards will be sent to the address that started mining.
```
miner.setEtherbase("0x your address here")
```
4.Check the wallet balance
 ```
web3.fromWei(eth.getBalance("0x your address"), "ether")
```
For other console commands, please refer to the section near the bottom of the page below:
https://github.com/cypherium/cypher

##  If the node is running in the background, you can enter the console from the cypher directory using the following commands.
### Linux / macOS / PowerShell
Move to the cypher directory.
```bash
cd ~/cypher
```

Linux
```
./build/bin/cypher-linux-amd64 attach ipc:./chaindbname/cypher.ipc
```
Apple Silicon Mac
```
./build/bin/cypher-darwin-arm64 attach ipc:./chaindbname/cypher.ipc
```
Windows
```
.\build\bin\cypher.exe attach ipc:\\.\pipe\cypher.ipc
```



colossusX consensus EVM cancun PoW

Solidity v0.8.36✅

Istanbul✅

CHAINID (0x46)✅

Istanbul✅

SELFBALANCE (0x47)✅

Berlin✅

London✅

BASEFEE (0x48)✅

Paris / The Merge ⚠️ → Not supported as Ethereum PoS semantics → However, ColossusX uses a custom PoW mechanism, so this may not be required

PREVRANDAO (0x44) ✅/⚠️ → Opcode execution is OK → The returned value is the same as difficulty

Shanghai✅

PUSH0 (0x5f)✅

Cancun✅

BLOBHASH (0x49)✅

Cancun✅

BLOBBASEFEE (0x4a)✅

Cancun✅

TLOAD (0x5c)✅

Cancun✅

TSTORE (0x5d)✅

Cancun✅

MCOPY (0x5e)✅

Transaction test Type 1 transaction submission ✅ Type 1 transaction hash compatibility ✅ Type 1 receipt retrieval ✅ Type 1 contract execution ✅

Type 2 transaction submission ✅ Type 2 transaction hash compatibility ✅ Type 2 receipt retrieval ✅ Type 2 contract execution ✅

ABI dynamic array encode/decode ✅ ecrecover precompile ✅ sha256 precompile ✅ ripemd160 precompile ✅ identity precompile ✅ native coin receive() ✅ CREATE2 ✅ DELEGATECALL ✅ STATICCALL write protection ✅ custom error / revert data ✅
