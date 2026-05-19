
## Setup Linux/Windows

```bash
git clone https://github.com/CypherTroopers/cypher.git
cd cypher
git fetch --all
 ```
linux
 ```
git checkout colossusX_dev_test_linux
 ```
Windows powershell
```
git switch colossusX_dev_test_powershell
```
init genesistest.json
```
./build/bin/cypher --datadir chaindbname init ./genesistest.json
```
Start node Linux
```
./build/bin/cypher --verbosity 4 --rnetport 7200 --syncmode full --nat extip:$(curl -4 -s ifconfig.io) --ws --ws.addr 0.0.0.0 --ws.port 9251 --ws.origins "*" --metrics --http --http.addr 0.0.0.0 --http.port 8000 --http.api eth,web3,net,txpool --http.corsdomain "*" --port 6000 --datadir chaindbname --networkid 123678 --gcmode archive --bootnodes enode://e10a90e9c7d077002d4d56b88943b8dfbca1d6490bb92c8202e6acb68ef23b521bf187fb40c07eed2f453f3782e8c53ca5a4ec1d34a4454960143501df8c4b95@149.102.156.210:6000 console
```
Start node Windows
```
.\build\bin\cypher.exe --verbosity 4 --rnetport 7200 --syncmode full --nat "extip:$((Invoke-RestMethod -Uri 'https://api4.ipify.org').Trim())" --ws --ws.addr 0.0.0.0 --ws.port 9251 --ws.origins "*" --metrics --http --http.addr 0.0.0.0 --http.port 8000 --http.api eth,web3,net,txpool --http.corsdomain "*" --port 6000 --datadir .\chaindbname --networkid 123678 --gcmode archive --bootnodes "enode://e10a90e9c7d077002d4d56b88943b8dfbca1d6490bb92c8202e6acb68ef23b521bf187fb40c07eed2f453f3782e8c53ca5a4ec1d34a4454960143501df8c4b95@149.102.156.210:6000"
```


## console command Linux/Windows
1. Generate a wallet
 ```
personal.newAccount("your password")
 ```
2.Start mining
 ```
miner.start(1, "0x your address here", "your password")
 ```
3.Check the wallet balance
 ```
web3.fromWei(eth.getBalance("your address"), "ether")
```
For other console commands, please refer to the section near the bottom of the page below:
https://github.com/cypherium/cypher
