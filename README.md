
## Setup Linux/Windows

```bash
git clone https://github.com/CypherTroopers/cypher.git
cd cypher
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


## Run a Cypher node without the cypher-deploy script Linux

If you want to run a Cypher node manually without using the `cypher-deploy` setup script, you can use the steps below.

> This script is intended for Ubuntu Linux amd64 environments.
> It installs Go, build dependencies, Node.js/PM2, clones the Cypher repository, builds the binary, initializes chain data, and starts the node with PM2.

```bash
#!/usr/bin/env bash
set -euo pipefail
```
```
export PATH=/usr/local/go/bin:/usr/local/bin:$PATH
export GOPATH="$HOME/go"
export GO111MODULE=off
```
update/upgrade your linux"
```
sudo apt update
sudo apt upgrade -y
sudo apt autoremove -y
sudo apt autoclean -y
```
install Go
```
cd /tmp
wget https://go.dev/dl/go1.26.2.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.26.2.linux-amd64.tar.gz
```
```
go version || true
go env -w GO111MODULE=off
```
```
grep -qxF 'export PATH=/usr/local/go/bin:/usr/local/bin:$PATH' ~/.bashrc || echo 'export PATH=/usr/local/go/bin:/usr/local/bin:$PATH' >> ~/.bashrc
grep -qxF 'export GOPATH=$HOME/go' ~/.bashrc || echo 'export GOPATH=$HOME/go' >> ~/.bashrc
grep -qxF 'export GO111MODULE=off' ~/.bashrc || echo 'export GO111MODULE=off' >> ~/.bashrc
```
install build dependencies..."
```
sudo apt-get install -y \
  gcc cmake libssl-dev openssl libgmp-dev \
  bzip2 m4 build-essential git curl libc-dev \
  wget texinfo nodejs npm pcscd
````

install latest node via n and pm2..."
```
sudo npm install -g n
sudo n stable
sudo apt purge -y nodejs npm
sudo apt autoremove -y
```
```
export PATH=/usr/local/bin:$PATH
hash -r
sudo /usr/local/bin/npm install -g pm2
```
clone cypher repo..."
```
mkdir -p "$GOPATH/src/github.com/cypherium"
cd "$GOPATH/src/github.com/cypherium"
```
```
git clone https://github.com/CypherTroopers/cypher.git
cd cypher
```
```
cd cypher
git fetch --all
git checkout colossusX_dev_test
cp -f ./crypto/bls/lib/linux/* ./crypto/bls/lib/
```

 clone GOPATH dependencies
```
mkdir -p "$GOPATH/src/github.com/VictoriaMetrics"
cd "$GOPATH/src/github.com/VictoriaMetrics"
[ -d fastcache ] || git clone https://github.com/VictoriaMetrics/fastcache.git

mkdir -p "$GOPATH/src/github.com/shirou"
cd "$GOPATH/src/github.com/shirou"
[ -d gopsutil ] || git clone https://github.com/shirou/gopsutil.git

mkdir -p "$GOPATH/src/github.com/dlclark"
cd "$GOPATH/src/github.com/dlclark"
if [ ! -d regexp2 ]; then
  git clone https://github.com/dlclark/regexp2.git
fi
cd regexp2
git fetch --tags
git checkout v1.1.8

mkdir -p "$GOPATH/src/github.com/go-sourcemap"
cd "$GOPATH/src/github.com/go-sourcemap"
[ -d sourcemap ] || git clone https://github.com/go-sourcemap/sourcemap.git

mkdir -p "$GOPATH/src/github.com/tklauser"
cd "$GOPATH/src/github.com/tklauser"
[ -d go-sysconf ] || git clone https://github.com/tklauser/go-sysconf.git
[ -d numcpus ] || git clone https://github.com/tklauser/numcpus.git

mkdir -p "$GOPATH/src/golang.org/x"
cd "$GOPATH/src/golang.org/x"
[ -d sys ] || git clone https://go.googlesource.com/sys
```
patch dependencies
```
cd "$GOPATH/src/github.com/cypherium/cypher"

rm -rf vendor/github.com/dlclark/regexp2
mkdir -p vendor/github.com/dlclark
cp -a "$GOPATH/src/github.com/dlclark/regexp2" vendor/github.com/dlclark/

DUK_LOGGING_PATH="$GOPATH/src/github.com/cypherium/cypher/vendor/gopkg.in/olebedev/go-duktape.v3/duk_logging.c"

if [ -f "$DUK_LOGGING_PATH" ]; then
  sed -i 's/duk_uint8_t date_buf\[32\]/duk_uint8_t date_buf[64]/' "$DUK_LOGGING_PATH"
  sed -i 's/snprintf((char \*) date_buf, sizeof(date_buf),, /snprintf((char *) date_buf, sizeof(date_buf), /g' "$DUK_LOGGING_PATH"
  sed -i 's/sprintf((char \*) date_buf, "\(.*\)"/snprintf((char *) date_buf, sizeof(date_buf), "\1"/' "$DUK_LOGGING_PATH" || true
fi
```
build cypher
```
cd "$GOPATH/src/github.com/cypherium/cypher"
make clean
make cypher
```
init chain data..."
```
./build/bin/cypher --datadir chaindbname init ./genesistest.json
```
create start script and register pm2&strat Pm2
```
cat <<'EOS' > start-cypher.sh
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

./build/bin/cypher \
  --verbosity 4 \
  --rnetport 7200 \
  --syncmode full \
  --nat extip:$(curl -4 -s ifconfig.io) \
  --ws \
  --ws.addr 0.0.0.0 \
  --ws.port 9251 \
  --ws.origins "*" \
  --metrics \
  --http \
  --http.addr 0.0.0.0 \
  --http.port 8000 \
  --http.api eth,web3,net,txpool \
  --http.corsdomain "*" \
  --port 6000 \
  --datadir chaindbname \
  --networkid 123678 \
  --gcmode archive \
  --bootnodes enode://e10a90e9c7d077002d4d56b88943b8dfbca1d6490bb92c8202e6acb68ef23b521bf187fb40c07eed2f453f3782e8c53ca5a4ec1d34a4454960143501df8c4b95@149.102.156.210:6000
EOS

chmod +x start-cypher.sh

/usr/local/bin/pm2 delete cypher-node >/dev/null 2>&1 || true
/usr/local/bin/pm2 start ./start-cypher.sh --name cypher-node
/usr/local/bin/pm2 save

echo
echo "PM2 started cypher-node."
echo "Check status with:"
echo "  /usr/local/bin/pm2 status"
echo "  /usr/local/bin/pm2 logs cypher-node"
echo
echo "To enable auto-start after reboot, also run:"
echo "  /usr/local/bin/pm2 startup systemd -u $USER --hp $HOME"

echo
echo "Done."
```
If you want to run the node without PM2, use the command below and run it with your preferred process manager or application.
```
./build/bin/cypher \
  --verbosity 4 \
  --rnetport 7200 \
  --syncmode full \
  --nat extip:$(curl -4 -s ifconfig.io) \
  --ws \
  --ws.addr 0.0.0.0 \
  --ws.port 9251 \
  --ws.origins "*" \
  --metrics \
  --http \
  --http.addr 0.0.0.0 \
  --http.port 8000 \
  --http.api eth,web3,net,txpool \
  --http.corsdomain "*" \
  --port 6000 \
  --datadir chaindbname \
  --networkid 123678 \
  --gcmode archive \
  --bootnodes enode://e10a90e9c7d077002d4d56b88943b8dfbca1d6490bb92c8202e6acb68ef23b521bf187fb40c07eed2f453f3782e8c53ca5a4ec1d34a4454960143501df8c4b95@149.102.156.210:6000 \
console
```
