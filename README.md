## Setup on PowerShell

Clone the repository and switch to the target branch:

```powershell
git clone https://github.com/CypherTroopers/cypher.git
cd cypher
git fetch --all
git checkout ecdsa_1.1_test_colossus-Xv2test
```

Initialize the node with the test genesis file:

```powershell
.\build\bin\cypher.exe --datadir chaindbname init .\genesistest.json
```

Start the node:

```powershell
.\build\bin\cypher.exe --verbosity 4 --rnetport 7200 --syncmode full --nat extip:$((Invoke-RestMethod -Uri "https://ifconfig.io/ip").Trim()) --ws --ws.addr 0.0.0.0 --ws.port 9251 --ws.origins "*" --metrics --http --http.addr 0.0.0.0 --http.port 8000 --http.api eth,web3,net,txpool --http.corsdomain "*" --port 6000 --datadir chaindbname --networkid 12367 --gcmode archive --bootnodes "enode://1300eb515ce5ae1167f05cc2123c8ca7100cb86cfefc39d761e26ce19ba14535b233e9fc4c263444cc4c5934058eb9daa9cf7c4f9c40cbff19ee83055284c718@161.97.184.220:6000" console
```

## console command (mining)
```powershell
personal.newAccountEd25519("your password")
```
```powershell
miner.start(1, "Ed25519 address", "your password")
```


## Setup linux 

Clone the repository and switch to the target branch:

```bash
git clone https://github.com/CypherTroopers/cypher.git
cd cypher
git fetch --all
git checkout ecdsa_1.1_test_colossus-Xv2test
```
```
./build/bin/cypher --datadir chaindbname init ./genesistest.json
```
```bash
./build/bin/cypher --verbosity 4 --rnetport 7200 --syncmode full --nat extip:$(curl -4 -s ifconfig.io) --ws --ws.addr 0.0.0.0 --ws.port 9251 --ws.origins "*" --metrics --http --http.addr 0.0.0.0 --http.port 8000 --http.api eth,web3,net,txpool --http.corsdomain "*" --port 6000 --datadir chaindbname --networkid 12367 --gcmode archive  --bootnodes enode://1300eb515ce5ae1167f05cc2123c8ca7100cb86cfefc39d761e26ce19ba14535b233e9fc4c263444cc4c5934058eb9daa9cf7c4f9c40cbff19ee83055284c718@161.97.184.220:6000 console
```
## assume
reconfig/service.go   core/tx_pool.go  reconfig/service.go

1)  5k TPS 
tryProposeDebounce: 25ms → 12ms

fastPerAccountTierSmall: 4 → 8

fastPerAccountTierMedium: 16 → 24

fastPerAccountTierLarge: 64 → 96

fastBlockGasTargetPct: 80 → 88

slowBlockGasTargetPct: 95 → 96

GlobalSlots: 262144 → 400000

GlobalQueue: 262144 → 400000

2) 10k TPS 
tryProposeDebounce: 25ms → 8ms

fastPerAccountTierSmall: 4 → 12

fastPerAccountTierMedium: 16 → 32

fastPerAccountTierLarge: 64 → 128

fastBlockGasTargetPct: 80 → 92

slowBlockGasTargetPct: 95 → 97

GlobalSlots: 262144 → 600000

GlobalQueue: 262144 → 600000

slowBlockMinPending: 64 → 32（slow lane）

3) 20k TPS 
tryProposeDebounce: 25ms → 5ms

fastPerAccountTierSmall: 4 → 16

fastPerAccountTierMedium: 16 → 48

fastPerAccountTierLarge: 64 → 192

fastBlockGasTargetPct: 80 → 94

slowBlockGasTargetPct: 95 → 98

GlobalSlots: 262144 → 1,000,000

GlobalQueue: 262144 → 1,000,000

slowBlockMinPending: 64 → 16

slowBlockMinInterval: 750ms → 300ms
