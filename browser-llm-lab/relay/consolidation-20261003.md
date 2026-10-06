# Cypher配下への統合とgenesis整合確認 — 2026-10-03

## 現在の配置と接続先

`/root/browser-llm-lab` 全体を `/root/cypher/browser-llm-lab` へ移動した。旧パスへのsymlinkは作っていない。移動前後の3,178項目・2,758通常ファイルを照合し、内容、所有者、権限、inodeの一致を確認した。`.git`、未コミット変更、node_modules、モデル関連コード、鍵、A/Bの保存DB、過去の検証証跡を含む。元のWeb HEADは `1e2839e95612d22b5fdc2aed5bf5b78e344f2e0b`。履歴を保持するため、WebはCypher配下の既存Gitリポジトリとして残している。二つの履歴を消したり、HEADへ戻したりしていない。

現在の本番経路は次のとおり。

```text
/root/cypher/genesis.json
  → 既存の chaindbmine（再初期化していない）
  → start-cyphermine.sh
  → build/bin/cypher-linux-amd64
  → config/browser-relay/common-mine.sock（所有者限定0600）
  → browser-llm-lab/relay/main.mjs（127.0.0.1:8091）
  → Nginx / HTTPS・WSS
  → https://ai-test.make-cph-great-again.community/
  → ブラウザのWorker・WebRTC
```

通常CommonのsourceIdは `common-mine`、node IDは `ef4d1c50627c52801acc77a036826aa68b429d2c7d713e10c8b9a743d0492efb`、native enodeの接続口は `13.140.169.170:6099`。切替前後で同じnative identity、genesis、datadirを使用している。鍵を新規生成・置換していない。通常Commonの所有者IPCは `/root/cypher/chaindbmine/cypher.ipc`。gatewayはこのIPCを公開せず、限定されたmesh socket APIだけを扱う。

公開gatewayが所有者socketで直接扱うCommonは現在1台。ブラウザの上限は引き続きWebRTC 20台・Common接続20台で、表示の現在値は実接続数。gatewayの同時leaseは1 Common×80に合わせ80、接続socket枠384を維持した。Commonのshared circuit40、native mesh peer40、frame/chunk/buffer/通信量上限は変更していない。上限20や40は、実際にその数のCommonが発見・稼働していることを意味しない。

Web専用のCommon A/Bは停止し、PM2の自動起動対象から外した。データ、鍵、以前の検証binary、試験結果は移動先に保全した。`relay/mesh-targets.json` と `relay/native/{a,b}` は明示的に使う研究fixture用で、本番接続先は `relay/config.json`。fixtureを今後明示起動する場合も実行binaryは通常の `/root/cypher/build/bin/cypher-linux-amd64` を使用する。

## genesisから確認したコード経路

nativeの既存実装を使い、RAMだけのDBで `Genesis.ToBlock(nil)`、`SetupGenesisKeyBlock`、`SetupGenesisBlock`、保存configの再読取りを行った。既存の稼働DBを別プロセスで開いていない。

| 項目 | 検証結果 |
| --- | --- |
| chainId / 今回のP2P networkId | `10101919` / `10101919` |
| transaction genesis block hash | `0x001c8239f25a697933e2a54511a576205fb21cbb80dc974adb29894dc80250ad` |
| key genesis block hash | `0xfd4eea7524a89a440d09282888220a0731c3cb152be4b4a535031b7bbef86285` |
| genesis JSON SHA-256 | `cbba1850877ca5d2a4b2f2c9ef759c357ef579918130196ce773c29ee0c06b6c` |
| committee / FHS | fixedCommittee=true、7委員、FairHotstuff=true |
| 通常Commonの実block0、relay config、gateway config | 同じgenesis hash・chainId |

JSONのSHA-256とblock hashは異なる値。再計算に独自codecは追加していない。確認した接続経路は `genesis → native chain backend → Commonの役割判定 → RLPx/native handshake → native署名endpoint → gateway署名検査 → ブラウザ署名検査とWorkerのidentity/session照合`。ファイル・行の詳細は [genesis検証記録](evidence/consolidation-20261003/genesis/README.md) に残した。これは関連経路の監査・実行確認であり、リポジトリ全コードの形式検証ではない。

`start-cyphermine.sh`、`colossusX_linux.sh`、`colossusX_mac.sh`、`colossusX_windows.ps1` は既にrelayを既定ONにする入口であり、この作業で別ノード実装を増やしていない。OS別ColossusX入口は新規datadirだけをrootのgenesisから初期化し、既存miner入口は既存chaindbmineを使う。通常Commonに `mesh.publicGatewayOrigin` を設定し、今回のHTTPS originをnative keyで署名して公開directoryへ供給するよう接続した。

各地域で新しいCommonを運用する場合、実際に所有するHTTPS/WSS gatewayのoriginをそのCommonに設定する。他の運用者のCommonへこのホストのURLを一律に設定する方式ではない。同一ホストで複数Commonを動かす場合は、datadir、identity、sourceId、socketを分ける。4起動スクリプトが4台の独立Commonを自動作成するわけではない。

## 起動・停止

通常Commonは `/root/cypher` の既存管理を使用する。現在はPM2の `cyphermine` が `start-cyphermine.sh` を実行している。稼働中に別の同datadirプロセスを起動しない。

```sh
cd /root/cypher
# 同じ標準binaryを構築する
make cypher
# このホストで既存の通常Commonだけを管理する
pm2 restart cyphermine
pm2 stop cyphermine
# 停止済みの既存PM2エントリを起動
pm2 start cyphermine
```

Web中継の管理はgatewayとTURNだけを対象とする。通常Common、委員会、Webページサーバー、検索コンテナはこのhelperから停止しない。

```sh
cd /root/cypher/browser-llm-lab
./relay/start-managed.sh check
./relay/start-managed.sh status
./relay/start-managed.sh start
./relay/start-managed.sh stop
```

対応する `cypher-browser-mesh.service` は更新・daemon-reload済みで、enabled/active。実機の再起動試験は未実施。WebページはPM2 `server` が新パスの `server.py` を実行し、127.0.0.1:8080で配信する。検索コンテナ `browser-llm-searxng` は同じ固定image・127.0.0.1:8888・restart policyを保持し、bind mountだけを新ディレクトリへ変更した。旧コンテナは停止・新コンテナ動作検証後に除去し、bindデータを保持した。Nginxの上流ポートは変わっていない。

`/root/cypher/init.sh` は全体停止とDB再初期化を含むため、今回の移行では使用していない。通常Commonへの切替時に委員会0～6のPID・起動時刻が不変であることを照合した。

## 今回実行した検証

| 試験 | 結果と範囲 |
| --- | --- |
| 全フォルダー移動の保全照合 | PASS、3,178項目・2,758ファイルの内容/権限/owner/inode一致 |
| 標準 `make cypher` | PASS、BLS・DB adapter・cmd/cypher・browserrelay・p2p関連テストを含む |
| canonical binary | SHA-256 `5aeb4c61d95a862aa103d7352adf3540d480e5a363ea4198b550af707ca1b82b`。通常Commonの実行中exeと一致 |
| nativeによるRAM内genesis導出 | PASS、通常Commonのblock0・network設定とも一致 |
| Web Node.js既存試験 | 331件中328 PASS、FAIL0、3 SKIP（coturn opt-in） |
| Python既存試験 | 27 PASS |
| systemd descriptor | 構文検証PASS、インストール/daemon-reload/起動PASS |
| 公開HTML・module | curl/実ブラウザで200、実ブラウザが取得した6moduleのhashは移動先ソースと一致 |
| 公開config・署名directory | PASS、common-mineだけのlocal socket mapping、signed endpointの供給を確認 |
| 検索APIとDocker mount | PASS、公開APIから5検索結果、固定image・ポート・新bind元を確認 |
| 独立Chrome 2プロセス | PASS、初期OFF・本物のUI ON・通常Commonのnative HELLO/endpoint署名/identity/boot一致 |
| ブラウザ間WebRTC | PASS、各1 peer、直接DataChannel。両ブラウザのCommon接続は同じ1台 |
| OFF・再参加・hidden/freeze | PASS、Worker/session/queue破棄、古い世代の復活なし、手動再参加で新session、復帰時OFF |
| 検証用ブラウザの後始末 | PASS、所有していた2プロセス・一時profileを終了/削除 |

ビルドに既存Duktape C警告、systemd検証にホストのxfs unitに関するCPUAccounting廃止警告が出た。試験は完了した。Python urllibで公開URLへアクセスした確認は403、誤った `/mesh/directory` への確認は404だった。実際のAPIはconfigで通知される `/mesh/discovery`。curlと実ブラウザでは公開HTTPSと正しいAPIの成功を確認しており、失敗した試行を成功へ付け替えていない。

## 未実施・制約

- 今回の本番構成は通常Common1台であり、異なるCommon間のnative RLPx stream転送・ACK・代替Common経路の試験は今回実施していない。同じCommonへ接続したブラウザ2台のRTC成功とは区別する。
- 新配置での30分超の耐久試験、実LLM負荷、実iPhone/Android、別端末・別地域・異なる回線、強制TURN、ホスト再起動は今回未実施。過去の31分やA/Bの結果は旧条件の証跡として残す。
- Linux amd64のみ今回build/運用。macOS・Windows実機build/運用は未実施。Windows nativeにはowner named pipe対応があるが、Web gatewayはUnix socket前提の検査が残っており、Windowsまで接続完成とは扱わない。
- 任意の最大サイズnative blockを帯域制限付きmeshで必ず転送できる保証はない。ブラウザは採掘・投票・合意形成・native peer・独立finality検証の参加者ではない。

詳細な測定結果は [今回の証跡ディレクトリ](evidence/consolidation-20261003/) を参照。元の変更記録 [discovery-update.md](discovery-update.md)、[capacity-update.md](capacity-update.md) は過去の実行条件のまま保持する。
