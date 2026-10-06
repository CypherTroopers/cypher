# 移動後・通常Common1台の公開ページsmoke

状態: **LIVE SMOKE PASS / CLEANUP PASS**。2026-10-03 19:22:13–19:22:35 UTC、親作業からcutover完了を受けた後に実行した。`node --check` もPASS。

準備したharness: `/tmp/cypher-post-migration-smoke.mjs`。保存先は移動済みprojectの `tests/mesh-consolidation-browser.mjs`。親作業がコピーする。再利用用の既定rootはmoduleの1階層上とし、`MIGRATION_ROOT` で上書きできる。

既定の対象は公開 `https://ai-test.make-cph-great-again.community/`、配置元は `/root/cypher/browser-llm-lab`。既存Playwright module `/tmp/browser-llm-preview/node_modules/playwright/index.mjs` と、既存Chromium executableを再利用する。

```sh
cd /root/cypher/browser-llm-lab
MIGRATION_SMOKE_AUTHORIZED=1 node tests/mesh-consolidation-browser.mjs
```

旧cwd `/root/browser-llm-lab` は移動により存在しない。保存前の `/tmp` 版を再実行する場合だけ `MIGRATION_ROOT=/root/cypher/browser-llm-lab` も指定する。必要な場合だけ `MIGRATION_SMOKE_LOOPBACK=1` で公開hostnameの接続先を127.0.0.1に固定できるが、その値は証跡に残り、既定は通常の公開DNS経路。今回の成功runではhost overrideを使っていない。

結果は `/tmp/cypher-post-migration-smoke.json`。試験は専用の `/tmp/cypher-migration-smoke-*/A` と `/B` を作り、正確なPID・profile・cleanup結果を記録する。cleanupでは所有するChrome childだけを閉じ、終了確認後にその2プロファイルを削除する。既存profileやnative processには触れない。

## 実際に確認する項目

1. 独立したChrome process/profile A/Bで本物の公開ページを開き、UIの初期OFF、Common数0・browser peer数0を確認する。
2. 配信されるcontroller/Worker/discovery/crypto/UI moduleのSHA-256が新rootのファイルと一致することを確認する。
3. 実UIのNode ONボタンをclickする。UIが所有する既存MeshControllerの `start` / `post` を観測するだけで、別controllerの隠れた接続は作らない。
4. `common-mine` のCommon接続が1本、native sessionが存在し、WorkerがCommon署名を検証していることを確認する。配布endpointと実native HELLOの署名を配信済みの検証moduleでも検証し、nodeId・bootId・session・originの対応を確認する。
5. A/Bそれぞれが相手のpeerIdを持つ実DataChannelをopenしたことを確認する。
6. Aの実UIでOFFにし、世代が変わり、session/Worker/RTC/native/queue/reservationが空になること、3秒後も自動復活しないことを確認する。
7. 手動ONで新しいbrowser session/native sessionを作り、再びA/BがRTC接続することを確認する。
8. Bを実際の別tabでhiddenにしてtrusted `visibilitychange` とCDP freeze/resumeを発生させ、OFF停止とforeground復帰後の自動再開なしを確認する。実機スマホではなく390px viewportのChromiumであることを明記する。
9. 最後にAもOFFにし、専用Chromeとプロファイルのcleanupを別項目として記録する。

**Commonは1台なので、Common同士の認証済みstream転送・block同期・native受信bytesの成功をこの試験で主張しない。** 証跡は `nativeCommonToCommonRelay: NOT_TESTED_REQUIRES_TWO_COMMONS` を持つ。

## 今回の実測結果

- `/tmp/cypher-post-migration-smoke.json`: **PASS**、9 checkpoint、page error 0、peer error 0。SHA-256 `b95bce584db1131a509d9be41144e31d4c599b79365ed0e26b6df531e9cb7429`。
- A PID3352717 / B PID3352919の独立Chrome process。両方のUIは **BROWSER PEERS=1、COMMON CONNECTIONS=1** を表示。RTC peer stateは `connected`、pathは `direct`。
- 署名endpoint・native HELLOはsourceId `common-mine`、期待nodeId、bootId、native sessionが一致。配信moduleのSHA-256も移動済み配置元と一致。
- OFF、手動ONでの新session、trusted hidden/freeze、復帰時にOFF保持、Worker/queue/reservationの解放を確認。
- `/tmp/cypher-post-migration-smoke-cleanup.json`: **CLEAN**。19:23:55 UTCに独立してホストPID不存在、A/B profile不存在を確認。空の試験用親directoryも削除済み。
- 普通Commonのowner statusをこのbrowser harnessは問い合わせていない。親作業の最終owner status=0という読取と、上記browser内停止・プロセス後始末は別の証跡として扱う。
- スクリーンショットは取得していない。追加のlive runは行わない。
- `/tmp/cypher-post-migration-smoke-preparation.json` のNOT_RUNは実行前19:21 UTCの準備記録であり、最終結果ではない。
- 成功run時のharness SHAは準備記録の `f093deef05a423a76018781b896494781e2e060cb7ca6851a3aa5e0fdee775f6`。成功後に、再配置可能にするため既定rootを固定pathからmoduleの1階層上へ変更し、そのための`fileURLToPath` importを追加した。再利用版のSHAは `0551a8088d7b91de1de523f2b2ee41af0de38598392dc0ba8fcd9f70e541ae87`。このpath解決変更後はsyntax checkのみ再実施し、製品コードや試験内容は変更していない。

## gateway pin準備の最小owner IPC読取

対象を `/root/cypher/chaindbmine/cypher.ipc` に固定し、1methodずつ・deadlineを付けた有限応答の読み取りにする。以下は手順の説明であり、このharnessはIPCへ接続しない。

| 呼出し | params | 保存するfield | 推奨上限 |
|---|---|---|---|
| `admin_nodeInfo` | `[]` | `id`, `enode`（必要なら`ports.listener`） | 応答64KiB、5秒 |
| `eth_chainId` | `[]` | hex scalar | 応答4KiB、5秒 |
| `eth_getBlockByNumber` | `["0x0", false]` | `number`, `hash` | 応答64KiB、5秒 |
| `eth_blockNumber` | `[]` | hex scalar | 応答4KiB、5秒 |

固定の期待値はchainId **10101919 / `0x9a249f`**、genesis block hash **`0x001c8239f25a697933e2a54511a576205fb21cbb80dc974adb29894dc80250ad`**。headは接続時点の観測値として記録し、同期待高さを固定しない。wallet/account列挙、unlock、peer追加、DB直接読取は不要。`admin_nodeInfo` はpublic identityであり秘密鍵を返さない。

`admin_nodeInfo.id` はnative `enode.ID` の64桁hex。`enode://` 内の128桁hex public keyとは異なる。既存のWeb実装を再利用して以下を照合する。

```js
import { enodePublicKey, publicKeyNodeId } from '/root/cypher/browser-llm-lab/public/mesh-discovery.js';
const derivedId = publicKeyNodeId(enodePublicKey(info.enode));
// derivedId === info.id === verifyEndpoint(envelope, network).nodeId
```

導出は **Keccak-256(publicKey X || Y)**。非圧縮公開鍵の先頭`04`は含めない。NIST SHA3-256やSHA-256へ置き換えない。native側の対応は `p2p/enode/urlv4.go:PubkeyToIDV4`、`p2p/server.go:NodeInfo`。private nodekeyを読む必要はない。

親作業から通知された通常Commonの期待nodeIdは `ef4d1c50627c52801acc77a036826aa68b429d2c7d713e10c8b9a743d0492efb`、現在のenode addressは `13.140.169.170:6099`。署名endpoint/HELLOの検証はこのpublic identityを確認する。IPアドレス部分が将来変わっても、同じ鍵のnodeIdを保持する。

`/relay/v1/mesh/endpoint` のowner HTTP読取は上記IPCとは別のUnix socket API。gatewayが取得したenvelopeに対して既存 `verifyEndpoint` を適用し、sourceId=`common-mine`・network・origin・native public identityを確認する。JSONの再serializeや再署名は不要。
