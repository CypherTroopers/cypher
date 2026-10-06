# Automatic Common source uplink acceptance


今回の最終LIVE結果（Linux amd64、同一ホスト上の独立Chrome。別物理端末/回線ではない）:

| 検証 | 結果 |
| --- | --- |
| 通常公開UI、ON後の未知Common追加 | Common connections 1→2。OFF/ONなし。同じbrowser世代。署名/native HELLO照合。OFFでWorker/接続回収 |
| 独立browser A→B | seq19、7,734 raw bytes、exact ciphertext・SHA-256・hop ACK一致。native circuit受信114,509 bytes |
| A OFF、代替経路なし | native peer/circuit/queue 0。drain後の新規受信/転送counter不変 |
| 代替C→B | 新circuitのseq19、7,734 bytes/ACK一致。native circuit受信9,496 bytes。Bが新規取得した高さ576のhash一致 |
| 新規データの区別 | A停止・drain後444→C経由576。後からimportされた既存bufferを新規転送へ数えない |
| 更新・AI pause policy | 130,043ms。B/C各1回lease更新、同じbrowser/native sessionとgeneration、署名endpoint更新。実LLM負荷ではなくloading状態通知 |
| 通常build・race・Web tests | make cypher PASS。cmd/cypher・node/browserrelay race PASS。Web348 PASS、0 FAIL、任意TURN3 SKIP |
| cleanup | 試験Common終了、専用DB/鍵/config/socket削除、gateway候補2→1、元のnative/page/TURN PIDと開始時刻維持 |

試験Commonのdiscovery/static/trusted/bootstrapは無効/空で、native接続はbrowser-meshのみ。TxQUICは取引送信/受領証経路であり、確認した処理にblock同期経路はない。OS network namespaceによる遮断は実施していない。hop ACKは相手browserの受領であり、native消費・finalityの証明ではない。完全なreport/log、限定経路監査、build SHA/provenance、更新patchを[result.json](result.json)へ保存した。Python HTTPSのcleanup確認はCDN403で変更前に停止したため、cleanupの候補回収確認は稼働gatewayのloopback configを使用。実際の公開HTTPS/WSS/RTC経路はChromeでPASS。


For remote update and start/stop commands see [Common handoff](../../common-endpoint-native-handoff.md).
