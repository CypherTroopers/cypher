# Common 自動発見・複数 gateway 更新の検証記録

2026-10-03。配置は `/root/browser-llm-lab` と `/root/cypher` のまま。対象公開サイトは https://ai-test.make-cph-great-again.community/ 。既存の未コミット作業を保持し、隔離した作業場所で実装・試験後に反映した。commit/push は行っていない。

## 実装・配信した内容

1. Common の中央公開鍵一覧への手動登録を不要にした。各 owner の gateway がローカル Common の署名付き公開接続先を取得し、設定済み bootstrap directory へ自動広告する。未知 Common の署名・network・期限・世代を検証して有界 cache へ受け入れる。
2. ブラウザと専用 Worker が native advertisement と公開 endpoint の署名を検証する。正確な payload bytes と domain を使い、再 serialize や gateway による再署名は行わない。候補は RAM のみ、最大64件、期限・sequence 巻戻し・旧 boot 再送を検査する。
3. ブラウザが検証済み endpoint の公開 HTTPS/WSS へ接続する。実際の native HELLO の公開鍵・bootId を照合し、その接続先が発行した token だけを使用する。
4. 複数 gateway の rendezvous へ参加し、ブラウザ一時鍵の challenge 認証、署名付き browser record と SDP/ICE を使って紹介・接続する。実データは ordered/reliable WebRTC DataChannel を通る。

`/root/cypher` には任意の `mesh.publicGatewayOrigin`、既存 native 鍵による endpoint 署名、owner 限定 `/relay/v1/mesh/endpoint` を追加した。既存 mesh の boot ID、120秒 TTL、30秒更新を使用する。旧設定は互換。native 秘密鍵・RPC・任意TCP接続を公開する機能ではない。採掘・投票・合意形成の変更はない。

接続数表示は現在接続している数。上限20 RTC peer、20 Common 接続、全接続共有40 circuitは詳細欄に分けて表示する。Common の80 session/40共有 circuit、Worker の4MiB予約・512KiB queue・100MiB/ON、AI負荷に応じた縮小は維持する。

プロトコル・運用条件は [discovery-protocol.md](discovery-protocol.md)、native 変更と地域別導入手順・引き継ぎ文は [common-endpoint-native-handoff.md](common-endpoint-native-handoff.md) を参照。

## 実際の配信・接続先

| 対象 | 配置・経路 |
| --- | --- |
| Web | `/root/browser-llm-lab/public`、既存 Python server `127.0.0.1:8080`、既存 Nginx/HTTPS |
| Gateway | `/root/browser-llm-lab/relay/config.json`、`127.0.0.1:8091` |
| 公開 discovery | `https://ai-test.make-cph-great-again.community/relay/v1/mesh/discovery` |
| 公開 signaling | `wss://ai-test.make-cph-great-again.community/relay/v1/mesh/rendezvous` |
| 公開 native WSS | `wss://ai-test.make-cph-great-again.community/relay/v1/mesh/connect` |
| Common A | `.runtime/mesh-a/source.sock`、専用 datadir `.runtime/mesh-a/data` |
| Common B | `.runtime/mesh-b/source.sock`、専用 datadir `.runtime/mesh-b/data`、独立 network namespace・loopback のみ |

今回ブラウザ用の公開接続口に接続した専用CommonはA/Bの2台で、両方とも同じ公開gateway originを署名する。20台の実Commonや複数の実地域が配備済みという意味ではない。Aは既存Commonとnative TCPで接続し、Bの試験時の唯一のチェーン受信経路はnative `browser-mesh`。DBを別プロセスから重複して開いていない。

専用 A/B の稼働バイナリー SHA-256:

```text
be38686525295758caecfad9e76ddda4fc9579e3521b3651662fbf464e07052c
```

`/root/cypher/build/bin` は今回の隔離 build で上書きしていない。専用 A/B はそれぞれ `.runtime/mesh-{a,b}/cypher` を実行する。owner socket 0600・親 directory 0700を維持。既存の8ノードとTURNの再起動は行わず、専用 A/B・gateway・Web server の必要な切替だけを実施した。

## 検証結果

| 試験 | 結果・範囲 |
| --- | --- |
| Web unit | 331件中328 PASS、0 FAIL、3 SKIP。SKIPは明示実行が必要な実coturn試験 |
| Python | 23 PASS |
| Native | 既存 `make cypher` の必須テストと Linux amd64 build PASS。関連3packageの race test PASS |
| Go/ブラウザ署名互換 | 公開された固定 vector の exact payload・domain・Keccak・65byte secp256k1署名が一致 |
| Gateway自動広告 | 未登録native鍵の署名付きendpointを、証明書検証を有効にしたHTTPS fixture間で自動POST・受付。PASS |
| 21独立Chromium | 全21ブラウザがそれぞれ20本の実RTC接続へ164.358秒で到達。これは収束・受付の試験で、20接続の長時間持続性能ではない |
| 実Common・別gateway・31分 | 14チェックポイント PASS。実チェーンの暗号化stream、bytes/digest/ブラウザhop ACK、A OFF、代替C、C突然終了後のD、lease更新、lifecycleを検証 |
| 実Commonの公開endpoint自動取得 | ホームgateway一覧をAのみに限定し、公開directoryから未知Bを取得。Workerのendpoint/HELLO署名検証後に公開WSSで独立lease接続。PASS。RTCデータ試験とは別 |
| 公開HTTPS/WSS＋実WebRTC | 4分（240,003ms）の観測とA OFF・C/D代替経路・実bytes/digest/ACK・lifecycleがPASS。B/C各1回の同一session更新、Bの高さ4023→4026 |
| 公開ページの通常UI | 独立したdesktop1440px/mobile390px、6チェックポイントPASS。両方とも実Common2・実RTC peer1・open circuit1。実通信による地図pixel変化、OFF/reload、横overflowなし |
| 公開proxyのbody境界 | 修正前は有効な2KiB discovery POSTが413。修正後は2KiB/16KiBが202、16KiB+1が413。他のsessions APIの2KiBは引き続き413 |

31分試験は同一ホスト内の独立ブラウザプロセスと二つのTLS originを使った。ゲートウェイfixtureへはそれぞれ実Common A/Bを接続し、相手のnative鍵をホームの固定一覧に入れていない。Bへの本文注入、gateway-only転送、代替TCP経路は使用していない。gateway経由のメタデータとWebRTC経由の実データを分けて確認した。

31分の実測:

- 観測時間 **1,860,003 ms**。B/C各 **15回**のlease更新。同じsessionの期限が実際に進んだ。
- Bの高さ **4008 → 4017**。A/B/referenceのcanonical block hashを照合した。
- A→Bの照合例 **529 raw bytes**、SHA-256 `c0c9b7ec5efff0bb149b5f49f1157304d1604597ab5b1eae2dbf2e07b606f604`。
- 代替C→Bの新しい照合例 **570 raw bytes**、SHA-256 `76da14a1ad75215771f2d495b25a8cddd1f54484f17357a3751178136316949b`。
- 回線の自然な30分期限切れを `circuit-expired` で確認し、別circuitの再認証と双方向bytesを確認した。単なるID変更から期限切れを推測していない。
- A OFF後は送信済みqueueを排出してから新しい転送が止まることを確認。C突然終了後も旧回線を撤去し、新規D経由で別のbytes/digest/ACKを照合した。
- 終了後のA/Bはsessions/circuits/candidatesすべて0。試験中の製品ファイルhash変更なし。
- 観測snapshot内の最大queue **2,520 bytes / 524,288 bytes**、最大application予約 **326,696 bytes / 4,194,304 bytes**。OSの実RAM使用量や、観測間の絶対peakを測ったものではない。

未処理のJavaScript例外は0件だったが、soak前にWorkerの `invalid_receipt` 拒否イベントがA/Cで各1件ある。試験全体を無エラーとは記載しない。詳細は `native-browser-final-metrics.json` と `native-browser-claim-audit.md`。

ここでのhop ACKは、相手ブラウザが次hop用の有界queueに受け入れたbytesの確認。native credit、Commonのstream消費、チェーン採用、finalityの暗号学的証明とは区別する。`send()`成功を受領成功に数えていない。

AI共存は loading/benchmarking/generating の状態通知を使う制御試験。実LLMを同時に推論した性能試験ではない。hidden/freeze・復帰OFF・navigationによるWorker終了は実Chromium lifecycleイベントで確認したが、390px viewportは物理iPhone/Androidではない。

公開経路の4分試験は通常の公開DNS/TLS/Nginx/WSSを利用し、host override・証明書検証の無効化・TURN/直結の強制は行っていない。両ブラウザの24観測でRTC経路は `direct`。B/Cは途中で各1回native sessionを再取得し、その後の同一session更新が成功した。Gatewayの記録ではnative upstream切断を観測しているが、その先の原因は確定していない。Cには `invalid_receipt` 拒否が2件あり、無切断・無エラー試験とは扱わない。最終的な所有browser PID/profileは全て回収済み。

通常UIの数値は、desktopのhop receipt16件、mobile10件の時点で比較した。地図の国推定は双方France。スクリーンショットは時点が異なるため後続のreceipt数とは一致しなくてもよい。物理端末の位置測定や別地域間通信の証明ではない。mobile metrics画像は目視でも2列カードの読みやすさを確認した。

## 証跡と途中の失敗

保存先は [evidence/discovery-update/](evidence/discovery-update/)。最終PASSと、途中の失敗・変更前の結果を別ファイルで保持する。

- `native-discovery-browser-report.json`、`-events.json`、`native-discovery-browser.log`: 31分の実Common試験。
- `public-remote-discovery-browser-report.json`: 未登録の実Common Bを公開署名広告から接続。設定の一時Origin追加・完全復元、browser終了、native lease回収を記録。
- `public-native-browser-report.json`、`-events.json`、`public-ui/`: 通常の公開経路を使う最終試験とUI画像。
- `discovery-browser-scale-report.json`: 21ブラウザの20RTC収束。gatewayの容量拒否・再認証も含むため無切断運転とは主張しない。
- `all-tests-final-summary.json`、native build/race logs、build provenance、公開asset照合、稼働前後、変更hash manifest。

31分試験の初回cleanup監査では全ブラウザPIDの終了を確認した一方、B/Dの試験用profileだけが残った。記録済みの所有PID・pathを照合してその2directoryだけを削除し、別のresolution記録で解消を確認した。以後のharnessはCDP closeの失敗でも他のcleanupを継続し、所有PID/profileの最終状態を記録する。

最初の大規模ブラウザ試験で、別gatewayから到着した正当だが古いbrowser recordを過剰に拒否する問題を修正した。同じidentity/sessionの最新cacheを維持して署名検証済みメッセージを扱い、世代巻戻しは許可しない。

離脱した宛先への有効な遅延SDP/ICEで送信者まで切断する問題も修正した。署名と順序検査の後、その宛先messageだけを破棄し、peer一覧を更新する。改ざん・replay・速度・容量超過の制約は保持する。修正前後の再現証跡と回帰テストを保存した。

公開経路の初回追加試験は6チェックポイント通過後、soak開始直前の回線スナップショットが空で停止した。結果は `public-native-first-snapshot-failure/` にFAILのまま保存し、試験側の開始判定を有限時間の実再認証待ちへ修正した。製品コードは変更していない。

次の130秒試験も同じ6チェックポイントは通過したが、B/Cのnative sessionが途中で再取得され、観測区間内の同一session更新がなかったためFAIL。`public-native-renewal-interruption/` に保持する。最終試験は観測を240秒へ延ばし、再参加と同一session更新の双方を区別して記録し、PASSとなった。短い失敗試験を削除・PASSへ書き換えていない。

既存Nginxのmesh locationに残っていた1KiB body制限を16KiBへ変更した。新しいdiscovery POSTに合わせた有限上限であり、他APIのgateway側1KiB制限は維持する。実署名広告に正当なJSON空白を加えた公開URL試験で修正前の413を再現し、`nginx -t`とreload後に境界値を再検証した。RPC等の非公開locationは変更しない。

配備時の最初の依存導入は既定npm cacheの読み取り専用制限で失敗し、gatewayが一時利用不能になった。専用の書込可能cacheで導入し再起動した後、公開APIとassetのhashを再検証した。途中の記録は残す。

Webのdiffチェックと今回編集したnativeファイルのdiffチェックはPASS。native checkout全体には、今回の編集範囲外の `browser/source/chromium-app/patches/native-node.patch:663` に既存作業の末尾空白があるため、全体を無警告とは扱わない。

## 試験の再現

通常のunit/build手順は上記のprotocol/native手順を参照。LIVE試験は、この実験研究用A/B・専用datadir・owner権限・正常な公開gatewayを確認した環境でのみ実行する。出力先は例として `/tmp`。Playwright/Chromiumは別途必要で、`PLAYWRIGHT_MODULE`/`CHROMIUM` に実際の導入先を指定できる。同時に複数のnative経路試験を実行しない。

```sh
cd /root/browser-llm-lab
# 別TLS gateway・実Common・31分
MESH_DISCOVERY_GATEWAYS=1 MESH_FORCE_DIRECT=1 MESH_EXPECT_NATIVE_CAPACITY=40 \
MESH_CHECK_ABRUPT=1 MESH_CHECK_LIFECYCLE=1 MESH_CHECK_WORKLOAD=1 \
MESH_CHECK_READMISSION=1 MESH_SOAK_MS=1860000 MESH_REQUIRE_RENEWAL=1 \
MESH_REPORT=/tmp/native-discovery-browser-report.json node tests/mesh-browser.mjs

# 実際の公開DNS/TLS/WSSを通す4分試験
MESH_PUBLIC_ORIGIN=https://ai-test.make-cph-great-again.community \
MESH_EXPECT_NATIVE_CAPACITY=40 MESH_CHECK_ABRUPT=1 MESH_CHECK_LIFECYCLE=1 \
MESH_SOAK_MS=240000 MESH_REQUIRE_RENEWAL=1 \
MESH_REPORT=/tmp/public-native-browser-report.json node tests/mesh-browser.mjs

# 公開署名endpointから未知の実Common Bを接続する別試験
# gatewayに一時的な正確なOriginを追加し、前後で専用gatewayをrestartする。
MESH_PUBLIC_REMOTE_ACCEPTANCE=1 MESH_ALLOW_GATEWAY_RESTART=1 \
MESH_PUBLIC_SOAK_STOPPED=1 node tests/mesh-public-discovery-browser.mjs
```

最後の試験は研究用配置を明示的に対象とする。事前に全試験ブラウザが停止済みであることを検査し、configの変更競合をhashで拒否する。終了時に元のbytes・modeを復元する。nativeプロセスの再起動はしない。

## 起動・停止

ブラウザ参加はページの **Node ON / Node OFF**。背景移行やページ終了で停止し、復帰しても自動ONにはならない。

サーバー上の専用サービスは以下で操作する。既存の8ノードやWeb serverを対象にしない。

```sh
cd /root/browser-llm-lab
./relay/start-managed.sh status
./relay/start-managed.sh check
./relay/start-managed.sh start
./relay/start-managed.sh stop
```

`start`/`stop`の対象は専用Common A/B、mesh gateway、TURN。停止時も専用datadir/鍵を保持する。Bのnetwork namespaceを維持するため、そのバイナリーを手動で直接起動しない。手順と管理対象の厳密照合は [managed-operations.md](managed-operations.md) を参照。

## 残る制約・未実施

- ページのhome gatewayとローカルCommonから主leaseを取る起動依存は残る。homeが利用不能なとき、未知の遠隔Commonを主接続にして起動するfallbackは今回の実装範囲に含まれない。
- 各地域ownerによる公開DNS/TLS/WSS、同一所有者のsocket配線、利用するWebページOriginの許可、bootstrap指定は必要。Commonを通常P2P起動するだけで公開HTTPS接続口が自動的に用意されるわけではない。
- 異なる物理端末・地域・アクセス回線、実iOS Safari/Android、TURN実経路の今回の再試験、20実Common同時接続、20RTCでの長時間性能、実LLM同時推論はNOT_RUN。
- 署名は鍵所有者のendpoint申告を認証する。位置・正直さ・役割の認証やSybil耐性ではない。地域表示は接続元の国推定で、正確なGPS位置ではない。
- directory64件、既知origin8、同時rendezvous4等の有界探索。完全なserverless DHTではなく、少なくとも一つの到達可能なbootstrapが必要。
- WebRTC成功とnative CommonのP2P認証成功は別々に確認した。ブラウザ数をnative peer数へ加算せず、ブラウザは採掘・合意形成・報酬取得をしない。
