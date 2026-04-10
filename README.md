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

## 7ノード分をコマンドで作る手順（chaindb0〜chaindb6）

### 1) chaindb0〜6 を作成して genesis を初期化

```bash
for i in $(seq 0 6); do
  mkdir -p "chaindb${i}"
  ./build/bin/cypher --datadir "chaindb${i}" init ./genesistest.json
done
```

### 2) 各 chaindb に Ed25519 アカウントを作成して「アドレス/公開鍵」を保存

```bash
# 1行目にパスワードだけを書く
printf 'test1234\n' > ./testnet.pass
chmod 600 ./testnet.pass

for i in $(seq 0 6); do
  out=$(./build/bin/cypher account new25519 --datadir "chaindb${i}" --password ./testnet.pass 2>&1)
  addr=$(awk '/Public address of the key:/ {print $NF}' <<<"$out")
  pub=$(printf 'test1234\n' | ./build/bin/cypher account unlock --datadir "chaindb${i}" "$addr" 2>&1 | awk '/public key:/ {print $3}')

  cat > "chaindb${i}/validator.txt" <<EOF
address=$addr
public=$pub
EOF

done
```

### 3) enode アドレスの取得方法

```bash
# nodekey が無い場合だけ生成
for i in $(seq 0 6); do
  mkdir -p "chaindb${i}/geth"
  [ -f "chaindb${i}/geth/nodekey" ] || ./build/bin/bootnode -genkey "chaindb${i}/geth/nodekey"
done

# enode の公開鍵部分を取得
for i in $(seq 0 6); do
  enode_pub=$(./build/bin/bootnode -nodekey "chaindb${i}/geth/nodekey" -writeaddress)
  echo "chaindb${i}: enode://${enode_pub}@<YOUR_IP>:<P2P_PORT>"
done
```

`validator.txt` と enode を使って `genesistest.json` の `config.committee` を 0〜6 で埋めれば、7ノード用の testnet 設定を作れます。

