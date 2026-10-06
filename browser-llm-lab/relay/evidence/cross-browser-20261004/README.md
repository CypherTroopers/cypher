# Chrome / Brave のブラウザピア未接続に対する修正・検証（2026-10-04）

公開対象: https://ai-test.make-cph-great-again.community/ 。作業対象は `/root/cypher/browser-llm-lab`。ユーザー申告は「Windows Chrome / Brave の Common 接続は成功するが Browser peers が0。Safari 同士は接続可能」。ユーザー端末の実時計・ICE trace は取得していないため、その端末の原因が単独で特定されたという報告ではない。

## 修正

既存 `public/mesh-discovery.js` のブラウザ challenge 署名に、既存 discovery 上限の10秒の時計差許容を適用した。修正前はサーバーより1秒遅いだけで正常な5秒 challenge を拒否していた。gateway の署名照合はサーバー時計で厳密な5秒期限のまま。nonce、Origin、identity、署名対象bytesと形式は保持。

既存 `public/mesh-discovery-client.js` の SDP / ICE 失敗 callback は、現在のON世代と同じpeer instanceだけを閉じる。古い処理の失敗が同じpeerIdの新しい接続を閉じない。対応する既存2テストファイルを拡張した。

4ファイルは `signaling-manifest.json` のハッシュで配備。既存ノード・Common・gateway・TURNの再起動は行っていない。元の委員会7プロセス、Common、Web serverのPID/開始時刻は `runtime-final.json` で一致。以前から変更済みのnative binary2本は今回変更していない。

## 結果

| 試験 | 結果 | 証跡 |
|---|---|---|
| 純粋な署名fixture: 時計 −10秒/−1秒/0秒/+6秒/+10秒、gateway期限厳守 | PASS | `clock-skew-before-after.json`, 既存 `tests/mesh-discovery.test.mjs` |
| 古いsignal失敗で交換済みpeerを閉じる不具合 | 修正前再現・修正後PASS | `stale-signal-before.log`, 既存 `tests/mesh-discovery-client.test.mjs` |
| focused staged tests | 37 PASS / 0 FAIL | `signaling-staged-tests.log` |
| Web全test | 356件:353 PASS /0 FAIL /3 optional TURN SKIP | `web-all-tests.log` |
| 実coturn認証・quota・private拒否・公開relay間データ | 3 PASS | `summary.json`（実行tool出力から記録、専用log未保存） |
| 修正前、時計差なし、実公開forced TURN | PASS | `forced-turn-before.json` |
| 修正前、browser A の時計を1秒遅らせる | 意図したFAIL: A Common1・紹介gateway0・peer0 | `clock-behind-before.json` |
| 修正後、A時計−1秒、実公開forced TURN | PASS: 両ブラウザCommon1・peer1・実RTC送受信 | `clock-behind-after.json` |
| TURNへのTCP接続だけを許可 | PASS: selected local relayProtocol=tcp、両方向の実RTC送受信 | `forced-turn-tcp.json` |
| TURNへのUDP接続だけを許可、A時計+6秒 | PASS | `forced-turn-udp-clock-ahead.json` |
| 修正後最初の試験の後始末 | RTC成功 / cleanup FAIL: 一時Chrome profile ENOTEMPTY | `clock-behind-after-first-cleanup-failure.json` |
| 上記profileの回収・test harness修正 | 残存試験processなし、profile削除、bounded rm retry導入、再実行clean PASS | `first-cleanup-recovery.json`, `clock-behind-after.json` |

実ブラウザは同一Linuxホスト上の独立Chrome2プロセス（Chrome153、Playwright1.63）。公開HTTPS/WSS、署名済みブラウザ候補、Common HELLO、専用Worker、ordered/reliable DataChannelを実際に使用した。ICEはrelayだけに限定し、`getStats()` の選択済みrelay候補とDataChannelの実受信bytes/messagesを両ブラウザで確認した。TCP試験でもrelay候補のprotocol自体はUDPで、ブラウザ→TURNのrelayProtocolがTCP。Common間のnative RLPx認証・チェーン同期成功としては扱わない。

試験は自分で起動したブラウザIDだけを相互接続対象に絞る。候補IDは実gatewayへの参加で生成されたもの。テスト側からpeer広告・本文・native streamを直接注入していない。各ブラウザで実際のcontroller/Worker protocolメッセージを1239 bytes /2 messages受信した。これは少量のアプリケーション通信の到達確認であり、持続性能やnative同期量ではない。

PASS試験は停止後のlease401、requested=false、Workerなし、peer0、Common0、circuit0、queue0、Chrome終了、一時profile削除まで確認した。公開配信moduleのSHA-256は `clock-behind-after.json` 内 `servedAssetHashes` に保存し、配備ファイルと一致した。

## 再実行

既存unit / integration testはWeb directoryから次を実行する。

```sh
npm test
RELAY_TURN_TEST=1 node --test tests/relay-turn.test.mjs
```

2行目と以下のブラウザ試験は実公開gateway/TURNに試験用leaseを作る。実ネットワークの試験が許可された環境で実行する。既存node datadir・秘密鍵には触れない。Chromium executableとPlaywright moduleを用意し、その実pathを指定する。依存物を本番Web packageへ追加する必要はない。

```sh
PLAYWRIGHT_MODULE=/absolute/path/to/playwright/index.mjs \
CHROMIUM=/absolute/path/to/chrome \
FORCED_TURN_AUTHORIZED=1 TURN_TRANSPORT=tcp \
FORCED_TURN_REPORT=/tmp/browser-mesh-tcp-result.json \
node relay/evidence/cross-browser-20261004/forced-turn.mjs
```

`TURN_TRANSPORT` は `both` / `udp` / `tcp`。`BROWSER_CLOCK_OFFSET_A=-1000` または `6000` でブラウザA内の `Date.now()` だけを変える。OSやgatewayの時計は変えない。レポートは `/tmp/` 配下に限る。token、TURN credential、SDP、candidate IP、native payloadはレポートへ保存しない。過去の修正前レポートは旧module配信時点の保存証跡であり、現在の公開ページで再実行すると修正後動作になる。

## 未確認・制約

実際のWindows OS / Brave / Safari / ユーザーの端末・別アクセス回線では未実施。同一ホストのChrome成功を、別地域・別回線の接続成功とは扱わない。この変更での30分継続・AI共存・実スマホlifecycleも未実施。

現在のTURNはUDP/TCP34790、TLS/443 TURNは未配備。ユーザー回線がこれらの接続を通せるかは未測定。clock差10秒超は許容範囲外。再読み込み前のページは旧コードを実行しているため、ユーザー側の確認は両端の再読み込み後、Node ONとページ表示継続が必要。
