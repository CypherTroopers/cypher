# Financial fixture: refresh an existing ETH source connection

The normal-CLI financial trial 7 (`logs/native-financial-cli-7.log` under
`/tmp/common-dex-integration.hnc63_8r`) passed the combined normal Common RPC +
DEX withdrawal at CLX height 49, completed the financial fault scenarios, and
reconciled native custody 214 CLX at height 69. Its later seven-parent ETH full
sync gate timed out. The failed run remains recorded as failed.

The added combined-role scenario had connected Common 0 to the test source
and synchronized through height 47. That connection remains registered as a
static peer; the normal parent runs with `--maxpeers 1`. The source subsequently
imports the real finalized blocks through normal `BlockChain.InsertChain` in
`nativeLedger.syncSource`. This fixture import does not publish the miner's
`NewMinedBlockEvent`.

The following source behavior explains why simply calling `admin_addPeer`
again does not refresh the existing connection:

* `eth/handler.go:295` subscribes the broadcast loop to `NewMinedBlockEvent`;
  `minedBroadcastLoop` (`:975`) propagates those events.
* `eth/peer.go:690` initializes remote peer head/TD from the ETH handshake.
* `eth/sync.go:270` compares that stored peer TD with local TD and schedules no
  downloader operation when the peer's advertised TD is no larger.
* `p2p/dial.go:276` ignores an already registered static peer. Adding the same
  public enode is not a new status handshake.

Trial 7 did not log the final per-parent local heights or peer heads, so the
specific height-47 stale peer remains a source-backed explanation rather than
a direct observation from that run. The corrected fixture records these fields.

Only `verifyFinancialCommonSync` in
`reconfig/dex_financial_cli_test.go` changed. Before final synchronization it
uses the ordinary IPC `admin_removePeer` on the owned test source connection,
checks that the peer disappeared, then uses `admin_addPeer`. Production
`Server.RemovePeer` waits for the protocols and peer removal to finish
(`p2p/server.go:351`). The fixture verifies the refreshed ETH peer head equals
the actual source's final hash, and still requires every imported block's hash,
state root, receipts root and gas used to match. The final native balance must
remain 214 CLX. No block or state is injected into a normal Common parent.

The original 75-second synchronization deadline is unchanged. Failure now
records all seven local heights and observed peer heads. The source and
committee protocols, difficulty calculation, consensus validation and
downloader were not changed.

Compilation passed: `go test ./reconfig -run '^$' -count=1` (0.042 seconds), raw
`/tmp/common-dex-integration.hnc63_8r/logs/common-sync-refresh-compile.log`.
The corrected full process rerun was pending when this record was written;
compilation is not evidence of a passing synchronization run.
