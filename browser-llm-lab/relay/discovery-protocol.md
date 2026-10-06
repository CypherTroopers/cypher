# Common の自動発見と複数 gateway

この機能は、Common の公開接続口を中央の固定一覧に追加しなくても、署名付き広告からブラウザが接続先を取得できるようにする。各 Common の所有者は、自分の private socket と自分の HTTPS/WSS gateway を接続する。各 gateway のローカル socket 設定は必要だが、他地域の Common の公開鍵を中央運用者が手動登録する必要はない。

## 接続と発見

```text
Common A ─ owner socket ─ gateway A ─ WSS ─ browser A
                                              │
                                 ordered / reliable WebRTC
                                              │
Common B ─ owner socket ─ gateway B ─ WSS ─ browser B
```

実データは Common 間で認証・暗号化された RLPx stream。gateway 間でその stream を転送する機能はない。ブラウザは native peer、採掘者、委員会にはならず、native 秘密鍵を受け取らない。

1. Node ON 後、まず表示中ページと同じ origin の `GET /relay/v1/mesh/config` を読み、その gateway がローカル設定した Common への `POST /relay/v1/mesh/sessions` で主接続の lease を取得する。その成功後に Worker と discovery を開始し、home gateway を含む最大8 origin から署名付き Common endpoint とブラウザ候補を取得する。読み込み時は OFF のまま。
2. endpoint の network、期限、bootId、sequence、native 公開鍵、署名をブラウザが独立検証する。許可する network は固定し、未知の公開鍵を理由に拒否しない。署名が証明するのは公開鍵の所有者の申告であり、正直な Common・委員会外の役割・所在地の証明ではない。
3. 主接続の native WSS が確立しており AI が idle の場合、検証済み HTTPS origin の固定された mesh API を利用して追加接続する。別地域の gateway の `/config` を照合後、`POST /sessions` に署名された `sourceId` を指定し、その接続先だけに使う独立した token を取得する。遠隔側では独立した主 lease だが、このブラウザでは追加 Common 接続として管理する。home gateway の bearer を別 origin に転送しない。HTTPS redirect は追わない。
4. 実際の WSS HELLO の署名・native identity・bootId を endpoint と照合する。controller と Worker の双方で照合する。接続が開いている数を Common connections に表示する。
5. ブラウザは複数 gateway の rendezvous に自分の RAM 内の一時鍵で参加する。チャレンジ認証と署名付き SDP/ICE で接続世代・宛先・順序・期限を検証し、WebRTC DataChannel を張る。紹介先が異なるブラウザ同士も共通の rendezvous を訪問して接続できる。

**現在の起動条件として、ページを配信する home gateway と、その gateway のローカル Common が利用可能であることが必要。** home の `/config` が無効・空一覧、または主 session の取得が失敗した場合は、遠隔 Common を主接続に選んで起動する fallback はない。主接続が失われると遠隔追加接続も一度閉じ、home gateway から新しい主 lease を取得する有限回の再試行を行う。遠隔 Common の発見は中央への公開鍵登録を不要にするが、この home 起動依存まで取り除く機能ではない。

紹介先は接触先であり、Common の身元を保証する鍵の一覧ではない。最初に接触できる bootstrap origin と到達可能な HTTPS/WSS の用意は必要。これは完全な serverless DHT ではない。地域の離れた端末間で接続できるかは NAT・firewall・STUN/TURN 等にも依存する。

## 設定

各 Common owner の gateway 設定例（既存の network、nodes、limits 等へ追加）:

```json
{
  "discovery": {
    "enabled": true,
    "bootstrapOrigins": ["https://ai-test.make-cph-great-again.community"],
    "allowedOrigins": ["https://ai-test.make-cph-great-again.community"]
  }
}
```

`origin` はその gateway 自身の公開 HTTPS origin。`allowedOrigins` はその gateway の API/WSS を利用する Web ページの origin。`nativeOrigin` は local Common が許可する origin に合わせる。Common の署名設定・Go と JavaScript の固定ベクトル・起動配線は [Common endpoint 実装・接続手順](common-endpoint-native-handoff.md) を参照。

gateway は自身の設定済み owner socket の `/relay/v1/mesh/endpoint` だけを poll する。署名とローカル identity/source/origin の一致を確認し、元の署名 envelope をそのまま配布する。gateway は署名 payload を再 serialize したり再署名したりしない。取得できない場合は前の広告の期限を延長しない。

自身の有効な署名広告は、設定された bootstrapOrigins に gateway が自動通知する。公開 POST の新規 origin は、その広告が署名した gatewayOrigin と一致する場合に限り受付対象となる。署名・network・期限・通信量・容量の検査は常に必要。未知 gateway の origin を中央の CORS 一覧へ追記する手続きは不要。session と rendezvous の Origin 制限は別に維持する。

## 追加 API

すべて `/relay/v1/mesh` 以下:

| Path | 用途 |
| --- | --- |
| GET `/discovery` | network と最大64 Common endpoint・最大64ブラウザ候補。最大256KiB |
| POST `/discovery` | `{ "endpoint": { "payloadBase64": "...", "signatureHex": "..." } }`。署名済み広告の公開受付。最大16KiB body |
| WSS `/rendezvous` | ephemeral browser key の challenge/auth、紹介、署名付き SDP/ICE。native データ転送には使わない |

Common の private `/endpoint` API は public HTTP proxy の任意転送口として公開しない。ブラウザが取得するのは bounded directory 内の署名 envelope。HTTP RPC、IPC、任意 URL/host/port、古い owner header API は公開しない。

## 署名と保存

Common endpoint payload の正確な schema/domain は native 接続手順の記載が基準。TTL は最大120秒、未来時計の許容は10秒、更新目安30秒。JSON の重複 key、未知 field、unsafe integer、非 canonical base64、署名改変を拒否する。署名は exact UTF-8 payload を native と互換の Keccak256/secp256k1 で検証する。

候補は RAM のみで最大64件。期限切れは削除し、同じ boot の sequence 巻き戻し・同 sequence の改変・期限内に残る旧 boot の再登場を拒否する。再起動した Common は、新 boot と進んだ発行時刻を伴う新しい候補になる。ブラウザに native チェーン採用や finality の検証をさせる機能ではない。

Native v1 の既存 advertisement も、ブラウザが exact bytes と domain を暗号検証してから route に保存する。未知 Common の広告でも正当な署名なら有界の route 候補になる。従来の mesh/1 advertisement schema に URL field を追加しない。

ブラウザの一時鍵の署名はそのブラウザ identity と signaling message を結び付ける。そのブラウザが主張した Common affiliation は保証しない。native 両端が advertisement と RLPx を独立して検証し、既存の role/admission 制限を適用する。新たな鍵を無数に作る Sybil 行為を完全に防ぐ認証制ではなく、容量と受付速度によって資源を制限する。

## 資源と lifecycle

20 RTC peer、20 Common 接続、40共有 circuit、Worker 4MiB reservation、512KiB queue、100MiB/ON の上限は維持する。40 circuit はブラウザと Common 双方の共有上限・pending 制限に従い、20本の接続ごとに40本を保証しない。

発見用 metadata は Worker reservation と別の有界領域。Common 候補64、ブラウザ候補64、既知 origin8、同時 rendezvous4、同時 discovery/遠隔 metadata HTTP2、待機 HTTP32、応答256KiB、signaling queue64件/64KiB。各 HTTP は5秒の期限。署名付き signaling は最大32KiB/message、送信4KiB/s、burst32KiB、150ms間隔で送出する。HTTP と signaling のアプリケーション bytes も全接続共通の100MiB/ONに加算する。これらはブラウザ全体のRSSやTLS/RTCのwire bytesではない。

Node OFF、hidden、freeze、page終了時は discovery と rendezvous、native/WSS、RTC、Worker、候補、待機処理、一時秘密鍵を破棄する。停止時は各遠隔 origin の `DELETE /relay/v1/mesh/sessions` にその origin の bearer だけを送信し、home の同じ API には主 bearer を送信する。home の主 lease 削除は同じ gateway の子 lease も解放する。削除要求は best effort で、突然終了時は WS 切断・生存確認・lease 期限が残存資源を回収する。古い非同期 callback の再参加は generation 検査で防ぐ。復帰時の自動 ON は行わない。endpoint が失効・別 origin/boot へ変更された場合は、その遠隔 Common 接続を閉じる。新 session/circuit に古い stream を移行しない。

## 再現と検証範囲

今回の最終配信・実測結果は [discovery-update.md](discovery-update.md) を参照。

```sh
npm ci --ignore-scripts
npm run build:mesh-crypto
node --test --test-concurrency=2 tests/*.test.mjs
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_*.py'
PLAYWRIGHT_MODULE=/absolute/path/playwright/index.mjs CHROMIUM=/absolute/path/chromium node tests/mesh-discovery-browser.mjs
```

実験研究用の native へ参加する試験は、その専用 Common と稼働 gateway の設定・権限・datadir 隔離を確認してから実行する。今回の実行結果、公開反映、継続観測、未実施項目は同ディレクトリの verification 記録と `relay/evidence/discovery-update/` の保存記録を参照。この説明自体は Web 公開反映や実ネットワーク試験完了の証明ではない。署名付き模擬 Common の WebRTC 試験と、実 Common の RLPx/チェーンデータ試験を分けて記録する。同一ホストの複数 TLS origin を、異なる地域や異なる回線の実測として扱わない。

ブラウザ試験は Node 22 以降、OpenSSL、Playwright と対応する Chromium が必要。`npm ci` は本ページの依存を導入するが、Playwright/Chromium は含まれないため上記2環境変数で実際の導入先を指定する。既定値の `/tmp/browser-llm-preview/` と `/tmp/browser-llm-browsers/` はこの検証環境の便宜的な値。`MESH_DISCOVERY_REPORT` は作成済みの出力 directory 内の JSON path を指定できる。TLS 証明書・試験鍵・一時 profile は試験が生成して終了時に削除し、保存済みの検証証跡を入力として使わない。
