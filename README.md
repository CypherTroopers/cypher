
## Setup Linux/Windows/mac

```bash
git clone https://github.com/CypherTroopers/cypher.git
cd cypher
 ```
## start node 

***Linux***
```
chmod +x colossusX_linux.sh
./colossusX_linux.sh
```
***Windows***
```
powershell -ExecutionPolicy Bypass -File .\colossusX_windows.ps1
```
***mac(Apple Silicon Mac)***
```
chmod +x colossusX_mac.sh
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
## Node restart command
***Linux***
```
chmod +x Restart_linux.sh
./Restart_linux.sh
```
***Windows***
```
powershell -ExecutionPolicy Bypass -File .\Restart_windows.ps1
```
***mac(Apple Silicon Mac)***
```
chmod +x Restart_mac.sh
./Restart_mac.sh
```

##  If the node is running in the background, you can enter the console from the cypher directory using the following commands.
### Linux / macOS / PowerShell
Move to the cypher directory.
```bash
cd ~/cypher
```

Linux
```
./build/bin/cypher attach ipc:./chaindbname/cypher.ipc
```
Apple Silicon Mac
```
./build/bin/cypher-darwin-arm64 attach ipc:./chaindbname/cypher.ipc
```
Windows
```
.\build\bin\cypher.exe attach ipc:\\.\pipe\cypher.ipc
```
