## Setup on PowerShell
Here is two files that needed to make it run on my windows11 AIPC
WINDOWS_BUILD.md
build_windows.ps1

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
.\build\bin\cypher.exe --verbosity 4 --rnetport 7200 --syncmode full --nat extip:$((Invoke-RestMethod -Uri "https://ifconfig.io/ip").Trim()) --ws --ws.addr 0.0.0.0 --ws.port 9251 --ws.origins "*" --metrics --http --http.addr 0.0.0.0 --http.port 8000 --http.api eth,web3,net,txpool --http.corsdomain "*" --port 6000 --datadir chaindbname --networkid 12367 --gcmode archive --bootnodes "enode://fe37c100a751e024f9bce73764b7360edf7690619e6e0bf2473f876834adf200feb68f17562a6eea77f263e947744978269db295c2ece9bfc24ad2be14eb69f1@161.97.184.220:6800" console
```

## console command (mining)
```powershell
personal.newAccount("your password")
```
```powershell
miner.start(1, "ECDSA address", "your password")
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
./build/bin/cypher --verbosity 4 --rnetport 7200 --syncmode full --nat extip:$(curl -4 -s ifconfig.io) --ws --ws.addr 0.0.0.0 --ws.port 9251 --ws.origins "*" --metrics --http --http.addr 0.0.0.0 --http.port 8000 --http.api eth,web3,net,txpool --http.corsdomain "*" --port 6000 --datadir chaindbname --networkid 12367 --gcmode archive  --bootnodes enode://fe37c100a751e024f9bce73764b7360edf7690619e6e0bf2473f876834adf200feb68f17562a6eea77f263e947744978269db295c2ece9bfc24ad2be14eb69f1@161.97.184.220:6800 console
```
