# Commonとブラウザメッシュの接続仕様

状態: `NODE_MESH_IMPLEMENTED / LINUX_NODE_LIVE_TEST_PASS / WEBRTC_NOT_VERIFIED_HERE / WINDOWS_NATIVE_NOT_RUN`

更新日: 2026-10-03。対象Web: https://ai-test.make-cph-great-again.community/

署名付き公開接続先（§3.1）: `IMPLEMENTED / LINUX_BUILD_AND_RACE_PASS`。公開配信・実ブラウザ間の検証結果はWeb側の記録で別途管理する。

## 1. 目的と境界

固定委員会をコアとして保護し、外側のCommonマイナー・Common RPC提供ノードのピア発見と通信経路をブラウザで補助する。ブラウザは採掘、投票、合意形成、報酬取得を行わない。Commonマイナーであることは参加拒否理由にしない。

当初の「最近ヘッダーをブラウザへ配るだけ」の計画を、Common同士の認証済みP2P通信を運ぶ設計へ改訂した。旧ヘッダー供給機能は任意の補助機能として保持する。本仕様が旧ブラウザヘッダー配布案のAPI・完成条件に優先する。

```text
Common A -- WSS -- ブラウザA -- WebRTC -- ブラウザB -- WSS -- Common B
    └────────────── 両端で既存RLPx認証・暗号化 ──────────────┘
```

ノード側はowner限定のローカルIPC上にHTTP/WebSocketを提供し、Web側のHTTPS/WSS gatewayが中継する。Linux/macOSはUnix socket、Windowsはlocal named pipeを使う。ブラウザ間WebRTC、peer紹介・SDP/ICE signaling、ON/OFF UIは別のWeb側実装を接続する。ノード側WS試験クライアントの成功をWebRTCの成功と扱わない。

ブラウザが運ぶのは暗号化streamで、実際のnative peerは両端のCommon。ブラウザ数はnative peer数に加算しない。RLPxとその上の既存protocolが相手identity、network/genesis、実データを検証する。ブラウザにnative秘密鍵を渡さない。

ローカルではTxQUIC ingress有効またはFairHotstuff無効の役割設定を拒否し、設定されたCommitteePublicKeyがchainのGenCommitteeに一致する場合も起動を拒否する。ブラウザサービスを有効にしたプロセスは起動後もCommon専用とし、miner.startで選択したBLS公開鍵を現在の委員情報と照合して委員としての起動を拒否し、WAL復旧後にも検証済みの鍵と委員情報を再確認する。native identityがP2PのReservedNodesに登録されている場合は、ローカルのmesh起動と相手へのmesh接続を拒否する。任意の相手enode IDから委員会のBLS役割を自動判定する機能はない。接続先の除外範囲は運用者が設定したReservedNodesに依存し、StaticNodesへの登録だけではmesh接続先から除外されない。IP制限NetRestrictを有効にしたノードでは、IPを持たないmeshがその制限を迂回しないよう起動を拒否する。ブラウザから任意URL/host/portへTCP接続するAPIはない。

## 2. buildと起動

Linux amd64・macOS arm64・Windows amd64の各native hostで既存の`make cypher`を使用し、同一binaryへ組み込む。build helperはchecksum固定の上流goleveldbへ追加7ファイルを適用し、一時modfileと`cypher_bounded_storage`を使う。この処理は元のgo.mod/go.sumや上流の既存DB処理を書き換えない。追加差分は`build/goleveldb-bounded.patch`、provenanceはstageの`manifest.txt`。別のfork checkoutは不要。

`start-cyphermine.sh`、`colossusX_linux.sh`、`colossusX_mac.sh`、`colossusX_windows.ps1`は同梱の`config/browser-relay/common-mine.json`を使い、meshを既定ONで起動する。追加引数は`console`前へ渡し、genesisの`init`には渡さない。初期化失敗で起動を止め、最終ノード終了コードを返す。各launcherのdatadir/genesisが意図したCommon用であることを確認する。同じdatadirで複数launcherを同時起動しない。`start-cyphermine.sh`は従来からgitignore対象のローカルスクリプト。

```sh
make cypher
./start-cyphermine.sh
# 中継なしで起動する場合:
# CYPHER_BROWSER_RELAY=0 ./start-cyphermine.sh
```

WindowsはMSYS2 MINGW64で`make cypher`を実行し、PowerShellから`.\colossusX_windows.ps1`を使う。OFFは`$env:CYPHER_BROWSER_RELAY = "0"`を設定して起動する。`build_windows.ps1`は同じMSYS2 buildを呼ぶ互換入口であり、依存を自動installしない。

4つのlauncherは`CYPHER_BROWSER_RELAY=0`で両方のrelay flagを省略する。別configは`CYPHER_BROWSER_RELAY_CONFIG`または`--browser.public-relay.config <absolute-path>`で選び、CLI指定を環境変数より優先する。CLIでconfigを明示しながらOFFにはできない。custom configやendpointの権限は運用者が準備する。

binary自体は従来どおり既定OFF。直接起動は`--browser.public-relay --browser.public-relay.config <absolute-path>`の両方を指定する。flagなしなら追加config/key/IPC/mesh読取・接続を開始しない。`init`/`attach`へflagを付けない。通常Commonとconsoleコマンドを許可し、Commonの`--mine`やunlockを理由に拒否しない。委員会は別の役割検査で拒否する。

別OS/architectureへのcross buildは未対応で、`TARGET_OS/TARGET_ARCH`またはGoの実効`GOOS/GOARCH`がhostと異なればstaging前に拒否する。今回のLinux環境ではWindows native test/full build・Windows実ノード起動はNOT_RUNであり、cross compile成功だけをその代用としない。OS別手順はREADMEの「OS-specific node launchers」を参照。

同梱の最小mesh専用config:

```json
{
  "enabled": true,
  "socketPath": "auto",
  "network": {
    "chainId": 10101919,
    "genesisHash": "0x001c8239f25a697933e2a54511a576205fb21cbb80dc974adb29894dc80250ad"
  },
  "sourceId": "common-mine",
  "mesh": {
    "allowedOrigins": ["https://ai-test.make-cph-great-again.community"],
    "publicGatewayOrigin": "https://ai-test.make-cph-great-again.community",
    "gatewayUplink": true
  }
}
```

networkは研究ネットワークで確認した値。別networkへ流用しない。設定は4KiB以内のowner管理regular fileとし、重複/未知key、nullを拒否する。mesh広告の署名にはそのCommonの既存native node keyを使う。公開するのは署名と公開identityのみ。

`socketPath: "auto"`はOS別に解決する。Linux/macOSではconfigと同じdirectoryの`<config名から拡張子を除いた名前>.sock`となり、同梱設定なら`config/browser-relay/common-mine.sock`。socket親は実行user所有0700、socketは0600。同梱設定の親directoryだけはUnix launcher helperが0700に整える。custom配置は事前作成し、設定は同user所有・group/worldから書込不可にする。途中のsymlinkや既存socketの上書きを拒否する。macOSの`/var`・`/tmp`は実体側の`/private/var`・`/private/tmp`等を使う。Unix socketのOS固有パス長上限にも注意する。

Windowsのautoは実行user SIDと小文字化した絶対canonical config pathから導く`\\.\pipe\cypher-browser-relay-<32桁のSHA-256 hex>`。解決したendpointは`--verbosity 3`以上の起動logの`Browser relay listening`で確認する。macOS/Windows launcherの既定verbosityではこのINFO logは表示されない。明示指定は正確な`\\.\pipe\`prefixと、1〜128文字のASCII英数字・`_`・`-`だけのleafを許す。remote UNC、device path、dot/space/separator入りleafは拒否する。JSON内のbackslashはescapeする。protected DACLは実行owner SIDだけを許可し、remote pipe clientを拒否、既存pipeを上書きしない。config/任意鍵のownerは実行user SIDが必要で、Administrators所有のファイルもそのままでは受理しない。DACLでは他userの書込（鍵では読取も）を拒否し、SYSTEM/Administratorsは既に所有権を取得できる特権主体として許可する。途中のreparse pointや信頼しないownerによる置換を拒否する。Unix mode0600をWindowsのアクセス制御とみなさない。

複数Commonはdatadir・native identity・config/endpointを分ける。同梱configの`mesh.gatewayUplink: true`により、Common自身が§3.2の公開gatewayへ外向きWSSで接続する。遠隔Commonごとの手動一覧登録、独自ドメイン、受信用公開ポート、別Node.js gatewayは不要。公開側ではnative identityに基づく一意のsourceIdを使い、owner APIのsourceIdは維持する。ローカルIPC方式を使う運用ではowner gatewayを同じhost・同じownerで動かし、owner限定権限を緩めない。Linuxのgatewayから別hostのWindows local pipeへ直接接続することはない。`start-cypher0..6.sh`という名前だけでCommonと判断せず、委員会プロセスには有効化しない。

mesh専用ならP-256配布鍵もbounded header snapshotも不要。補助ヘッダー機能も有効にする場合だけ、後述のkeyId/signingKeyPathを追加する。

## 3. 公開gatewayとのHTTP契約

private endpointのうち、Web側gatewayが公開してよい対象は`/relay/v1/mesh/`。HTTP RPC、通常IPC、旧owner用ヘッダーAPIをまとめてproxyしない。HTTPS/WSS終端と接続元別の受付制限はgatewayでも行う。ノードはmesh HTTP要求数と接続数・session数を制限する。Originは許可したHTTPS origin完全一致で、認証の代わりではない。

Windows gatewayの引継ぎ事項（今回`/root/browser-llm-lab`は変更していない）:

- `relay/gateway.mjs`の`http.request({socketPath})`と`net.connect({path})`はNodeのnamed-pipe IPCを利用でき、HTTP/WS protocolは共通。ただしWindows host上で動かす必要がある。
- `relay/config.mjs`の親path走査は`/`固定なので、platformの`dirname`とroot判定へ変更する。Windowsの接続先は上記local pipe形式だけ許可し、最大137文字、重複判定はcase-insensitiveとする。現在の`isAbsolute`/`normalize`だけの検査ではremote UNCも通る。
- `relay/turn.mjs`の同じpath走査と`process.getuid()`/mode0600/`O_NOFOLLOW`によるsecret検査はWindows非対応。owner SID・DACL・reparseを検査する安全な読込が必要で、未対応中はTURN issuer設定を明示的に拒否する。既存検査を単純に省略しない。
- gateway試験のUnix `.sock` fixture、`mesh-native-inspect.py`の`AF_UNIX`、Linux用process管理は別途Windows対応が必要。Windows node実装だけでWindows gateway・TURN・独立browserのend-to-end検証完了とはしない。

| 経路 | 入出力 |
| --- | --- |
| `GET /relay/v1/mesh/config` | version、session期間、更新間隔、frame/peer上限。参加は開始しない |
| `POST /relay/v1/mesh/sessions` | 空bodyまたは`{}`。201で`token`, `browserId`, `expiresAt` |
| `GET /relay/v1/mesh/connect` | WebSocket upgrade後3秒以内に最初のmessageとして`{"token":"..."}`。認証messageはtextまたはbinary内のJSONを受理 |
| `POST /relay/v1/mesh/renew` | `Authorization: Bearer <token>`、bodyなし。`expiresAt`更新 |
| `DELETE /relay/v1/mesh/sessions` | 同じBearer、bodyなし。即失効・接続停止、204 |
| `GET /relay/v1/mesh/status` | sessions/circuits/candidates、送受信bytes、現在の回線経路。秘密tokenなし |

全要求に許可Originを必要とする。queryにtokenを入れない。config応答のversionは1。session発行・renew応答のexpiresAtはUnix epoch millisecondsの整数。sessionは5分、2分を目安にrenew。同じtokenの同時2接続を拒否し、WS切断時はtokenも失効する。再接続は新session発行から。期限後のrenewで復活しない。認証前Ping/Pongを拒否する。

mesh HTTP全体16 req/s・burst32、session発行1/s・burst8、有効session最大80、各sessionのrenew/deleteは1/s・burst4。このHTTP request limiterは任意のowner用ヘッダーAPIには適用しない。HTTP接続はローカルIPC全体で最大88（mesh有効時）で、最大80本のWS以外に認証・metadata処理用の8枠を残す。受付速度と同時session容量は別の制限であり、80件を同時に発行できるという意味ではない。public gatewayはこれに加えて接続元別の容量を設ける。

### 3.1. Common自身が署名する公開接続先（2026-10-03追加）

任意設定 `mesh.publicGatewayOrigin` を実装した。例は `"publicGatewayOrigin": "https://relay.example.org"`。指定先は当該Commonのowner gatewayの公開HTTPS originとし、TLS・gateway配置は運用者が準備する。省略時は従来meshを継続し、新APIは404となる。別鍵・P-256鍵・新datadirは不要。native秘密鍵は既存のprocess内signerだけが扱う。

owner限定IPCの `GET /relay/v1/mesh/endpoint` は、既存のOrigin・要求数制限を適用し、bodyなしで元の署名envelopeを返す。200は有効な `{payloadBase64,signatureHex}`、404は未設定、503は停止・期限切れ・利用不能。GETでsessionやcircuitを作成せず、署名対象JSONの再serializeや再署名を行わない。

署名対象payloadは、次の9フィールドだけを持つ厳密JSONである。

```text
version, network, enode, sourceId, gatewayOrigin,
bootId, sequence, issuedAt, expiresAt
```

- `version=1`、networkは既存chainId/genesis。`sourceId`はgatewayのローカル接続先IDと一致させ、最大64文字の既存mesh label形式。
- `gatewayOrigin`は正規HTTPS origin。path・末尾slash・資格情報・query・fragment・private/reserved IP・localhost等を拒否する。ノードは広告先へDNS解決・HTTP接続を行わない。
- `bootId`は既存mesh広告と同じprocess起動ごとの32桁hex。`sequence`は1以上のJS-safe整数、初回1で署名成功時だけ増加。
- 時刻はUnix epoch milliseconds。TTL最大120秒、発行時刻の許容未来幅10秒。既存maintenanceで30秒ごとに更新し、HTTP GET自体では更新しない。署名失敗時に古いbytesの期限を延長しない。Unix時刻の巻戻しやsequence上限では更新を停止する。
- 署名digestは `Keccak256(UTF8("cypher-browser-mesh-endpoint-v1\0") || exactPayloadBytes)`。末尾は1 byteのNUL。既存native node keyの65 byte `R || S || V`、小文字hex、low-S、V=0/1。payload最大4096 bytes、envelope最大8192 bytes。

既存 `cypher-browser-mesh/1` の広告payload・domain・WSS frameには変更を加えない。公開接続先の署名はURLとnative identityの対応を広告するもので、Common役割・接続成功・chain finalityの証明ではない。ブラウザの接続後はnative HELLOのidentity/boot/networkを照合し、両端の既存RLPxと役割検査を継続する。

Web gatewayはローカルIPCから30秒ごとに取得し、検証済みenvelopeをdirectoryへ保持する。設定したbootstrap gatewayへ同じenvelopeを自動POSTする。ブラウザは未知のCommonも暗号署名を検証して候補にできる。bootstrapは発見の手掛かりであり、公開鍵の信頼元ではない。詳細な設定・公開API・ブラウザ署名・CORS・再現手順は[Web側の接続手順](../../browser-llm-lab/relay/common-endpoint-native-handoff.md)を参照する。

固定Go/ブラウザ相互運用vectorは `node/browserrelay/testdata/mesh-endpoint-vector.json`。公開テストscalar 1と固定時刻を使用し、実運用鍵・研究networkとは区別する。今回追加の署名・改ざん・期限・更新失敗・再起動・owner HTTP・旧configの試験、Linux `make cypher` と `go test -race` のcmd/cypher・node/browserrelay・p2pはPASS。隔離buildのSHA-256は `be38686525295758caecfad9e76ddda4fc9579e3521b3651662fbf464e07052c`。下記§8の過去のnative LIVE記録は保持し、この追加機能の公開配信や異なる端末/回線の成功へ読み替えない。

### 3.2. Commonから公開gatewayへの外向き接続

`mesh.gatewayUplink`は任意booleanで、省略時false。trueには`mesh.publicGatewayOrigin`と同じOriginの`allowedOrigins`が必要。同梱launcher configはtrueを指定する。既存のprivate IPC、チェーンDB、native key、Common役割検査を再利用し、新しい公開RPCやTCP proxyは作らない。共通の`make cypher`で生成した新binaryと更新済みconfigを配布し、各オーナーは既存datadirのままCommonを停止・再起動する。古いbinaryは新しいconfig項目を受理しない。`init`による再初期化は不要。

CommonはTLS検証を有効にした`wss://<publicGatewayOriginのhost>/relay/v1/mesh/source`へ自ら接続する。公開gatewayは5秒期限のランダムchallengeを送り、Commonは既存native keyで`Keccak256(UTF8("cypher-browser-mesh-source-v1\0") || exactChallengeBytes)`へ署名する。gatewayは署名付きendpointとchallengeの鍵一致、固定network/genesis、期限、同一identityの重複、接続元別の上限を検証して候補へ追加する。署名済み広告だけのリプレイでは接続を占有できない。ローカル接続先と同一identityのuplinkは拒否し、ローカル経路を優先する。uplinkが使えなくても通常native P2Pは継続する。

uplinkのendpointは`sourceId = native enode ID (64桁hex)`。owner用endpointは設定したsourceIdのまま。bootIdは共通で、sequenceはプロセス全体で単調増加する。endpointは30秒更新、120秒期限。gatewayは元のenvelopeを配布し、再署名しない。離脱・期限切れで候補と該当sessionを撤去し、再接続には新challenge・新browser sessionを使う。

中継するのは固定mesh HTTPのconfig/status/session/renewとnative mesh WSのみ。Common内部の有界in-process接続で既存HTTP handlerを再利用する。uplink所有token以外を操作できず、切断時もownerの別sessionを失効させない。任意のRPC/IPC/URL/host/portを要求できない。WS native Ping/Pongはブラウザまで転送し、gatewayやuplinkがブラウザの生存応答を代作しない。

外側JSONは最大96KiB（64KiB statusのbase64化を含む）。送受信それぞれ384KiB/s・burst512KiB、128件/s・burst256、queueは64件かつ512KiB、HTTP同時8件、native WS最大80、stream ID履歴最大4096。外側のbase64分の予算であり、native内部のJSON frame16KiB、chunk8KiB、session64KiB/s、node256KiB/s、共有40回線等を引き上げない。metadataのdeadlineとqueue滞留は有限、4096stream使用後は新uplink世代へ移る。

gatewayは`sourceUplink: {enabled: true, maxSources: 32, maxSourcesPerClient: 4}`で受入を有効化する。ローカルと遠隔を合計64Common以内、未認証は全体8・接続元2、既存の全体接続・通信量上限も適用する。ブラウザのCommon接続上限20・WebRTC peer上限20・Workerの共有40回線は維持する。ON中に追加された同じgatewayのCommonも署名検証して発見する。これは公開gatewayをbootstrapに用いる方式であり、すべてのCommonやgatewayを無条件に世界中から発見する仕組みではない。

今回の検証結果と未実施範囲は[Web側の運用記録](../../browser-llm-lab/relay/common-endpoint-native-handoff.md)に追記する。過去のnative fixtureやWebRTC検証結果を今回のuplinkの成功へ読み替えない。

## 4. browser接続の世代とCommon広告

認証後、ノードから次のhelloが届く。

```json
{"type":"hello","session":"32桁のランダムhex","browserId":"発行済みID","protocol":"cypher-browser-mesh/1","advertisement":{"payloadBase64":"...","signatureHex":"..."}}
```

以後のprotocol messageはtext形式のJSONで、すべて現在の`session`を持つ。ブラウザ間で転送して別CommonのWSへ渡す際は、その受信先WSのhello.sessionへ差し替える。circuitIdとseqは変更しない。sessionは接続ごとの世代で、古いframeを新接続へ持ち越さない。

広告payloadの厳密JSONは`version, network, enode, bootId, issuedAt, expiresAt`。versionは1、bootIdはプロセス起動ごとのランダム128bitを表す32桁の小文字hex。issuedAtとexpiresAtはUnix epoch millisecondsの整数。raw UTF-8を再serializeせず運ぶ。署名対象は`Keccak256(UTF8("cypher-browser-mesh-advertisement-v1\0") || exactPayloadBytes)`。末尾`\0`は1byteのNUL。native secp256k1の65byte署名を小文字hexで運ぶ。TTL120秒、正常ノードは30秒ごとに広告更新。network、時刻、有効期限、署名とenode公開鍵の一致をノードが確認する。hostnameを許可せず、広告検証でDNS問い合わせを行わない。

広告frameは`{"type":"advertisement","session":"...","advertisement":{...},"route":["browserA","browserB"]}`。routeは発信Commonから受信Commonへ向かう順で、受信Commonに直接接続するbrowserIdが末尾。最大4ラベル、重複禁止。ブラウザがhopを追加するため、route自体はnative本人性の証明ではない。

Common BがA広告を上記routeで受けた場合、BからAへ開く回線のrouteは`[browserB,browserA]`。候補は最大64Common、各4経路。WS切断または広告失効時に削除する。静的peerやtrusted peerへ永続登録しない。

ブラウザ由来candidateは由来を保持したmesh専用dialとし、広告に書かれたIPを通常TCP接続先へ転用しない。TTL失効との競合でもこの性質を維持する。運用者が既に指定したstatic peerは直接TCPを優先し、失敗時に有効mesh経路があれば利用する。既存の直接接続は維持する。

## 5. 回線streamの契約

| type | hello以外の共通`type,session`に追加するfield |
| --- | --- |
| `advertisement` | `advertisement,route` |
| `open` | `circuitId,target,advertisement,route` |
| `opened` | `circuitId` |
| `data` | `circuitId,seq,data` |
| `credit` | `circuitId,seq,bytes` |
| `close` | `circuitId,reason` |

未知field/type・重複key・不正整数を拒否する。circuitIdは回線ごとのランダム128bit小文字hex、targetは相手Commonのenode ID。openには発信Commonの署名済み広告を入れる。受信先は自分宛だけ受理し、発信元は同じsessionで事前に広告されている必要がある。Commonが他のCommonへopenをサーバー中継する機能はない。ブラウザ間で経路を作る。

opened後、両方向で独立にseq=1から始まるdataを送る。dataは最大8192byteの暗号化stream chunkをcanonical base64にした文字列。順序を維持し、途中chunkの省略・重複・並替えを拒否する。最大frameはJSON込み16384bytes。

正規のCommon実装はReadがそのchunk全量を消費してからcreditを返す。seqとbytesを厳密照合し、未creditは最大8chunk=64KiB。credit自体はRLPx暗号化streamの外側にあるflow control情報で、署名やRLPxによる暗号学的な受領証明ではない。途中のブラウザはcreditを偽装できるため、creditだけから相手Commonの消費を保証してはいけない。正規ブラウザはcreditを偽造せず転送する。creditはチェーンへの採用、合意の確定、ブラウザ間の独立した受領ACKも意味しない。Web側は別途hopごとの受領・RTC統計を測定する。

ブラウザ間DataChannelはordered/reliableとし、circuit対応表でdata/credit/closeを双方向に転送する。宛先sessionの差替え以外、暗号化bytesを書き換えない。途中のbrowserはRLPx message種別を読めない。公開Common間の通信にだけ使い、委員会通信への汎用トンネルを作らない。

Web側はDataChannelの切断時に、そのhopを使う回線のcloseを生きている隣接先へ通知し、対応表・queue・経路広告を撤去する。ノードONはbrowserのWorker/通信session開始、OFFは新規受付停止・close伝播・WS/RTC切断・一時buffer破棄であり、利用者端末でシェルコマンドを実行する操作ではない。ページ終了・background移行もOFFと同じ停止処理を行い、処理が実行されない突然死はlease・生存確認・native deadlineで回収する。接続だけを保った中間hopの無応答検知はnative deadline等に依存し、WSが切れた試験と同じ再接続時間を保証しない。

## 6. 制限と切断を前提にした運用

| 対象 | ノード側v1上限 |
| --- | --- |
| browser WS session | 80 |
| circuit | 全体40、1 sessionあたり40（全sessionで全体枠を共有、open待ちを含む） |
| native mesh peer / pending handshake | peer最大40、同時pending handshakeはinbound/outboundそれぞれ最大4。既存native全体・inbound上限も適用 |
| 経路のbrowserラベル | 最大4 |
| chunk / frame | raw8192 / JSON16384 bytes |
| 未消費受信buffer | 64KiB/circuit |
| WS送信queue | 64framesかつ512KiB/session |
| WS JSON message量 | 64KiB/s/session、256KiB/s/node、送受信それぞれ |
| RLPx frame | mesh経路のみ最大4MiB、通常TCPの上限は変更しない |
| RLPx transfer deadline | 16KiB/sを最低速度の基準に算出、最大5分。16KiB/sは流量上限ではない |
| 生存確認 | WS Ping5秒、15秒無応答で切断 |
| 回線寿命 | 30分。以降は新しい回線で再認証 |

上表のWS byte rateはbase64化後のJSON message全体の長さを数え、data以外の広告・credit等も含む。raw stream量やTLS/IPを含む回線通信量ではない。WS control Ping/Pong/Closeには独立したsession/node全体のmessage/byte予算を適用する。通常JSON messageの受信件数・byte予算も強制する。native ping応答が遅い回線で無制限goroutineを生まないよう有界化する。実際の定数は`mesh_protocol.go`、`mesh.go`、`p2p/browser_mesh.go`を参照。

80 sessionの5秒ごとの生存確認と切断処理が共存できるよう、node全体のWS control message予算は32件/s・burst160（送受信それぞれ）とする。control byte予算と各sessionの制限は維持する。これは生存確認用の枠であり、中継データの帯域を増やすものではない。

`config.nativePeers`はmesh独自の上限40を表す。実際のnative接続数には通常の`--maxpeers`とinbound/outbound配分も適用され、mesh用に40枠を追加予約するものではない。`--maxpeers`が40未満ならmesh設定もその値まで縮める。1 sessionあたり40回線は受付可能な上限であり、80 sessionそれぞれに40回線を保証しない。データ帯域・queue・frame・TTLの上限は増やさず、80 sessionと最大40回線で共有する。

これらはCommon側の受入上限である。Web gatewayのCommon割当数、browser Workerの回線数、WebRTC peer数、表示用status応答の読取サイズはWeb側が別途制限する。Common側の更新だけではWeb側の上限は増えない。Web側で回線数を増やす場合、Common全回線の`status.routes`を含む応答が読取上限に収まることも確認する。

突然の切断、再起動、ページ終了は通常事象。WSが消えたら、そのsessionの全回線・候補・queueを撤去し、blocked Read/WriteとRLPx handshakeを終了する。新接続は新session/circuitと新RLPx認証を使用する。無停止stream migrationや、署名済み取引を別nonceで再作成する処理は行わない。

複数経路があるときは前回選択を回転させ、openedだけ返してDATAを捨てる経路へ固定しない。再試行はnative schedulerの短いjitter付き間隔で行い、接続/queue上限を超えない。HTTP leaseが切れる前に更新できなければ停止し、古いtokenは復活させない。

4MiBを超えるnative frameは明示的に拒否する。通常の全同期・最大サイズblockをブラウザ低帯域で必ず運べるとは保証しない。native直結と小さいmesh経路の補助を区別する。ブラウザ側は利用者の回線・RAM・AI負荷に合わせた追加制限を実装する必要がある。

## 7. 任意の旧ヘッダー供給機能

`keyId`と`signingKeyPath`をconfigへ追加すると、既存lightnode.Factory/View/HeaderDigestを再利用する最近32件の署名付き供給も同時に動く。meshを省略した旧6項目configはヘッダー供給だけを動かす。片方の鍵項目だけ指定することはできない。

鍵は所有者管理のPKCS8 P-256（Unix0600、Windowsはownerと上記特権主体以外のアクセスを拒否するDACL）。wallet/native/BLS鍵を流用しない。2秒poll・読取deadline2秒・manifest期限30秒、1header最大8KiB。source失敗時に古いbytesへ新期限を付けない。この上限を超えるheaderでmeshそのものが停止しないよう、mesh専用configではexporterを作らない。

owner専用APIは`/relay/v1/source-config`, `/source-status`, `/head`, `/headers/{digest}`（すべて先頭に`/relay/v1`）。networkと完全RLPを結びつけるHeaderDigestおよびP-256 manifest署名形式は`node/browserrelay/protocol.go`、固定vectorは`node/browserrelay/testdata/`。これらを公開mesh APIと混同しない。

## 8. 実装配置と検証

- `node/browserrelay/mesh_protocol.go`: wire、署名広告、上限。
- `node/browserrelay/mesh.go`, `mesh_conn.go`: WS世代、経路、credit、stream、churn処理。
- `p2p/browser_mesh.go`と既存dial/server/rlpx/peer: native認証、admission、候補由来、frame上限、peer統計。
- `cmd/cypher/browser_mesh.go`: Common役割/chain照合、private HTTP session、起動停止、接続配線。
- `cmd/cypher/browser_public_relay*.go`: 既存flag/config/socket lifecycleの再利用。
- `build/build-cypher.sh`, `goleveldb-bounded.patch`: 同一native binaryのbuild。

2026-10-03の最終検証（Linux amd64）:

| 項目 | 結果 |
| --- | --- |
| 通常の`make cypher` | PASS。BLS・通常/有界DB adapterの検証を含めて同一binaryをbuild/binへ配置 |
| `go test -race ./cmd/cypher ./node/browserrelay ./p2p -count=1 -timeout=120s` | 3 packageすべてPASS |
| ノードfixture | native identity認証、広告偽造/期限、宛先制約、旧世代、突然切断と反復参加、遅いreader、queue/credit上限、代替経路、control flood、停止時のblocked処理解放を検証 |
| 研究ネットワーク実データ | PASS。一時Common Aが既存Commonからnative TCPで受信し、独立したWS fixtureの二経路を通して一時Common Bへ転送 |
| 同期経路の隔離 | Bは外向き経路を持たない別network namespace、discoveryなし・static peerなし。Bの唯一のnative peerは`transport=browser-mesh` |
| 突然離脱と経路切替 | Bが高さ0の時点で使用中fixtureをSIGKILL。別のfixture経路に新circuit/RLPxで1.673秒後に再接続（この環境での観測値） |
| 代替経路の実転送・同期 | Bはその代替circuitでRLPx stream 1,691,682 bytesを受信し、高さ3,762まで同期 |
| 受信内容の照合 | 高さ0・1・1,000・3,762のblock hashがA・B・既存Commonで一致。3,762のhashは`0x00d7453cbf65e0b3268e62ea8fbd6b497a70f8ea5067b5ea2a51e669c00eca43` |
| 全経路停止と再参加 | 全fixture停止でBのnative peer/session/circuit/candidateが0。新fixture接続で新browser ID・新session・新circuitによる参加を確認 |
| 後始末 | 一時Common・fixtureを全停止し、試験DB/鍵/config/socketを削除。元の8ノードのPID/開始時刻と稼働を確認 |
| 実ブラウザ/WebRTC/公開WSS gateway | 上記ノード側試験ではNOT_RUN。Web側の実装・検証は別管理。fixtureはWS間の試験転送でありWebRTCではない |
| macOS/Windowsの今回変更のbuild・運用 | NOT_RUN |

検証binary SHA-256: `3bafe0f18343f18533ef8528ab314ddaa7264953c2bc2ad9f33376ef5756bc6f`。build provenanceは`build/stage/linux-amd64/manifest.txt`。現場の結果・ログは`/tmp/cypher-mesh-node-20261003-cuxo62eu/`の`final-live-result.json`, `isolation-proof.json`, `cleanup-result.json`, `final-make.log`, `final-race.log`。この一時パスは配布APIや実行時依存ではない。

ビルドに既存のDuktape C警告が出るが完了している。検証途中には試験ノードの既定UDP port競合、およびfixture統計の初回出力待ち・先読み済みデータによる測定条件の不足があった。上記LIVE結果は名前空間隔離と接続直後切断に修正した最終試験の結果。通常ノードの再起動・flag追加、公衆向けgateway公開は実施していない。

`admin_peers.network.browserMesh`のbytesはそのnative circuitでRead/WriteしたRLPx stream量。`/mesh/status`のbytesはノードが計数したWSアプリケーションpayload（JSONとcontrol payload）の累積で、TLS/RTC/ネットワーク全体のwire bytesでも相手による採用証明でもない。Web側はRTC統計とhop単位ACKを別の指標として表示する。

同日のOS別起動・ビルド追加検証では、Linux/macOS launcherの模擬実行10ケース、Linux上のPowerShell 7.6.6によるWindows launcher/build wrapperの構文・模擬実行16項目、異なるtarget/GOOS/GOARCHの事前拒否7ケースがPASS。初回のビルド時検査で判明したUnix socket試験の長いTMPDIR問題は、既存テストの一時directoryを短いcanonical pathに修正した。共通helperはBLS・DBに加えてCLI/mesh/P2P関連25テストを同一modfile/tagで実行し、その後のLinux amd64 build・binary形式/version検査もPASSした。macOS/Windowsのnative build、Windows PowerShell 5.1、各OSでのlauncherによる実ノード起動はこの追加検証ではNOT_RUN。

追加検証結果は`/tmp/cypher-os-launch-20261003-ekc2tfda/verification-result.json`、build logは同directoryの`linux-make-final.log`。一時stageのLinux binary SHA-256は`a42295bcdd94982b917c821baad4a8a9d29e9fbfe3177976519ad4f8627a8737`。この再buildでは既存のbuild/bin、go.mod/go.sum、稼働ノードを変更していない。現行CIは各OSのnative runnerを使う方式であり、cross buildの検証ではない。

Web側の完成条件は、独立ブラウザのWebRTCを実経路としてCommon間で認証済みデータ交換し、ブラウザ離脱で経路が切れ、代替browser経路で再接続すること。Bへのテスト直接注入や、gatewayだけを通った配信をbrowser中継として扱わない。端末/回線差、TURN、mobile lifecycle、30分超のsession更新、AI共存は別途実測する。
