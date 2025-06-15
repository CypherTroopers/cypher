#!/bin/bash

# Goオフモード確認
export GO111MODULE=off
export GOPATH=$HOME/go

# 基本依存パス
BASE=$GOPATH/src/github.com

echo "===> Fetching GOPATH dependencies..."

# GitHubからcloneする依存
declare -A repos=(
  # Cypherium依存
  [shirou/gopsutil]=https://github.com/shirou/gopsutil.git
  [VictoriaMetrics/fastcache]=https://github.com/VictoriaMetrics/fastcache.git
  [dlclark/regexp2]=https://github.com/dlclark/regexp2.git
  [go-sourcemap/sourcemap]=https://github.com/go-sourcemap/sourcemap.git
  [tklauser/go-sysconf]=https://github.com/tklauser/go-sysconf.git
  [tklauser/numcpus]=https://github.com/tklauser/numcpus.git
  [deckarep/golang-set]=https://github.com/deckarep/golang-set.git
  [pborman/uuid]=https://github.com/pborman/uuid.git
  [rjeczalik/notify]=https://github.com/rjeczalik/notify.git
  [cespare/cp]=https://github.com/cespare/cp.git
  [naoina/toml]=https://github.com/naoina/toml.git
  [aws/aws-sdk-go]=https://github.com/aws/aws-sdk-go.git
  [cloudflare/cloudflare-go]=https://github.com/cloudflare/cloudflare-go.git
  [gorilla/websocket]=https://github.com/gorilla/websocket.git
  [gballet/go-libpcsclite]=https://github.com/gballet/go-libpcsclite.git
  [BurntSushi/toml]=https://github.com/BurntSushi/toml.git
  [tv42/httpunix]=https://github.com/tv42/httpunix.git
  [aristanetworks/goarista]=https://github.com/aristanetworks/goarista.git
  [hashicorp/golang-lru]=https://github.com/hashicorp/golang-lru.git
  [edsrzf/mmap-go]=https://github.com/edsrzf/mmap-go.git
  [dop251/goja]=https://github.com/dop251/goja.git
  [mattn/go-colorable]=https://github.com/mattn/go-colorable.git
  [peterh/liner]=https://github.com/peterh/liner.git
  [golang/snappy]=https://github.com/golang/snappy.git
  [olekukonko/tablewriter]=https://github.com/olekukonko/tablewriter.git
  [steakknife/bloomfilter]=https://github.com/steakknife/bloomfilter.git
  [pkg/errors]=https://github.com/pkg/errors.git
  [holiman/uint256]=https://github.com/holiman/uint256.git
  [btcsuite/btcd]=https://github.com/btcsuite/btcd.git
  [xtaci/kcp-go]=https://github.com/xtaci/kcp-go.git
  [satori/go.uuid]=https://github.com/satori/go.uuid.git
  [julienschmidt/httprouter]=https://github.com/julienschmidt/httprouter.git
  [huin/goupnp]=https://github.com/huin/goupnp.git
  [jackpal/go-nat-pmp]=https://github.com/jackpal/go-nat-pmp.git
  [rs/cors]=https://github.com/rs/cors.git
  [davecgh/go-spew]=https://github.com/davecgh/go-spew.git
  [fatih/color]=https://github.com/fatih/color.git
  [go-stack/stack]=https://github.com/go-stack/stack.git
  [influxdata/influxdb]=https://github.com/influxdata/influxdb.git
  [fjl/memsize]=https://github.com/fjl/memsize.git
  [docker/docker]=https://github.com/docker/docker.git
)

# clone 実行
for path in "${!repos[@]}"; do
  repo_url="${repos[$path]}"
  full_path="$BASE/$path"
  echo "-> Cloning $repo_url to $full_path"
  mkdir -p "$(dirname "$full_path")"
  rm -rf "$full_path"
  git clone "$repo_url" "$full_path"
done

# golang.org/x 系
mkdir -p "$GOPATH/src/golang.org/x"
cd "$GOPATH/src/golang.org/x"
for repo in crypto sys tools time; do
  rm -rf "$repo"
  git clone https://go.googlesource.com/$repo
done

# go.dedis.ch 系
mkdir -p "$GOPATH/src/go.dedis.ch"
cd "$GOPATH/src/go.dedis.ch"
git clone https://github.com/dedis/protobuf.git
mv protobuf protobuf.tmp && cd protobuf.tmp
# パスの整合性調整（必要であれば）...

echo "✅ 完了：全依存を $GOPATH/src に配置しました（Go modules 無効）"
