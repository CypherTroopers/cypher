
## Setup Linux/Windows/mac

```bash
git clone https://github.com/CypherTroopers/cypher.git
cd cypher
 ```
##start node 
***Linux***
```
chmod +x start-cypher.sh
./colossusX_linux.sh
```
***Windows***
```
powershell -ExecutionPolicy Bypass -File .\colossusX_windows.ps1
```
***mac(Apple Silicon Mac)***
```

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
3.Check the wallet balance
 ```
web3.fromWei(eth.getBalance("your address"), "ether")
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
