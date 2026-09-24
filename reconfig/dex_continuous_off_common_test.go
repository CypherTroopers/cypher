package reconfig_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/settlement"
	"github.com/cypherium/cypher/p2p/enode"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig"
	"github.com/cypherium/cypher/rlp"
)

// followOffCommon joins the ordinary ETH network exactly once and observes the
// normal synchronization scheduler. It neither starts the downloader directly
// nor imports, repairs or supplies any block/state to the child.
func followOffCommon(t *testing.T, node *nativeCommonNode, command offCommonCommand) {
	t.Helper()
	if command.Height == 0 || command.Height > 1024 {
		t.Fatal("ordinary Common follow height outside fixture report bound")
	}
	peer, err := enode.ParseV4(command.Peer)
	if err != nil {
		t.Fatal(err)
	}
	node.Stack.Server().AddPeer(peer)
	deadline := time.NewTimer(65 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for node.Service.BlockChain().CurrentBlock().NumberU64() < command.Height {
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatalf("ordinary ETH automatic follow timeout: head=%d target=%d peers=%+v", node.Service.BlockChain().CurrentBlock().NumberU64(), command.Height, node.Stack.Server().PeersInfo())
		}
	}
	head := node.Service.BlockChain().CurrentBlock()
	if head.NumberU64() != command.Height || head.Hash() != command.Hash {
		t.Fatal("ordinary ETH automatic follow reached unexpected canonical head")
	}
}

// continuousSyncOffCommon is the O18 late-join/restart gate. The caller must stop
// its own fixture producers at target first. Bootstrap input consists only of
// the public genesis/key block/committee and a peer address; all canonical
// financial state and receipts must be obtained by normal ETH synchronization.
func continuousSyncOffCommon(t *testing.T, fixture *reconfig.FHSRewardNetworkFixture, source *nativeCommonNode, target uint64) {
	t.Helper()
	chain := source.Service.BlockChain()
	head := chain.GetBlockByNumber(target)
	if target == 0 || target > 1024 || head == nil || chain.CurrentBlock().NumberU64() != target || source.Stack.Server().NodeInfo().Ports.Listener == 0 {
		t.Fatal("late Common requires a stable, reachable source at target <= 1024")
	}
	key, err := rlp.EncodeToBytes(fixture.KeyBlock)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bootstrap := offCommonCommand{Op: "init", DataDir: filepath.Join(dir, "node"), Genesis: fixture.Genesis, KeyBlock: key, Committee: fixture.Committee}
	child := startOffCommonChild(t, dir)
	started := child.call(t, bootstrap)
	if started.PID == os.Getpid() || started.Height != 0 {
		t.Fatal("late Common must start as a distinct process with a fresh chain")
	}
	check := func(report offCommonReport) {
		if chain.CurrentBlock().Hash() != head.Hash() {
			t.Fatal("source changed while checking the late Common; fixture was not quiescent")
		}
		if report.Height != target || report.Engine != (engine.ProcessMetrics{}) || report.Mining || report.CLX || report.Accounts != 0 || len(report.Blocks) != int(target+1) || len(report.Receipts) != int(target+1) {
			t.Fatalf("late Common role/execution mismatch: pid=%d height=%d engine=%+v mining=%v CLX=%v accounts=%d", report.PID, report.Height, report.Engine, report.Mining, report.CLX, report.Accounts)
		}
		for height, raw := range report.Blocks {
			block := chain.GetBlockByNumber(uint64(height))
			if block == nil || !bytes.Equal(raw, block.EncodeToBytes()) {
				t.Fatalf("late Common canonical block/root/gas mismatch at %d", height)
			}
			got, gotErr := json.Marshal(report.Receipts[height])
			want, wantErr := json.Marshal(chain.GetReceiptsByHash(block.Hash()))
			if gotErr != nil || wantErr != nil || !bytes.Equal(got, want) {
				t.Fatalf("late Common complete receipts/gas/logs mismatch at %d: %v/%v", height, gotErr, wantErr)
			}
		}
		state, err := chain.StateAt(head.Root())
		if err != nil {
			t.Fatal(err)
		}
		status, buckets, surplus, err := settlement.NativeStatus(state, params.DEXSettlementAddress)
		if err != nil {
			t.Fatal(err)
		}
		if report.Status != status || !reflect.DeepEqual(report.Buckets, buckets) || report.Surplus != surplus || report.Balance == nil || report.Balance.Cmp(state.GetBalance(params.DEXSettlementAddress)) != 0 || len(report.Entries) != int(status.Deposits) {
			t.Fatal("late Common native custody/buckets/cursor/history mismatch")
		}
		for i, entry := range report.Entries {
			stored, err := settlement.ReadNativeEntry(state, params.DEXSettlementAddress, uint64(i))
			if err != nil || entry != stored {
				t.Fatalf("late Common native inbox entry mismatch at %d: %v", i, err)
			}
		}
	}
	check(child.call(t, offCommonCommand{Op: "follow", Peer: source.Stack.Server().Self().URLv4(), Height: target, Hash: head.Hash()}))
	child.stop(t)
	restarted := startOffCommonChild(t, dir)
	bootstrap.Restart = true
	resumed := restarted.call(t, bootstrap)
	if resumed.PID == os.Getpid() || resumed.PID == started.PID || resumed.Height != target {
		t.Fatal("late Common same-database restart identity/head mismatch")
	}
	check(restarted.call(t, offCommonCommand{Op: "snapshot_follow", Height: target}))
	restarted.stop(t)
	t.Logf("DEX_OFF_CONTINUOUS_AUTO_ETH_RESTART_PASS pid=%d restartPid=%d height=%d root=%s receipts=%s gas=%d engine=0/0/0 blocks=%d manualSync=false", started.PID, resumed.PID, target, head.Root().Hex(), head.ReceiptHash().Hex(), head.GasUsed(), target+1)
}
