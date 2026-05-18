# cypher-deploy
This is the bulk setup .sh script.

If you get an error, follow the error message, then run the .sh script again.
## Setup Linux/Windows

```bash
git clone https://github.com/CypherTroopers/cypher-deploy.git
cd cypher-deploy
 ```
linux
 ```
chmod +x setup_cypherium2.sh
./setup_cypherium2.sh
 ```
Windows
```
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
./setup_cypherium2.ps1
```
## Check logs

```bash
pm2 logs
 ```
```bash
Ctrl+C
 ```
## start mining (console)Linux/Windows
```bash
cd ~/go/src/github.com/cypherium/cypher
 ```
Linux
 ```
./build/bin/cypher attach ipc:./chaindbname/cypher.ipc
 ```
Windows
```
.\build\bin\cypher.exe attach ipc:\\.\pipe\cypher.ipc
```
console command Linux/Windows
 ```
personal.newAccount("your password")
 ```
 ```
miner.start(1, "your address here", "your password")
 ```
