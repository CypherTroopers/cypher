package reconfig_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/settlement"
	"github.com/cypherium/cypher/eth/downloader"
	"github.com/cypherium/cypher/p2p"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig"
)

func nativeSyncPeers() *p2p.Config {
	return &p2p.Config{NoDiscovery: true, MaxPeers: 3, ListenAddr: "127.0.0.1:0"}
}

// nativeSyncOffCommon sends no transactions and directly inserts no blocks into
// the follower. Headers/bodies travel over loopback RLPx/ETH and the ordinary full
// downloader runs its FHS verification and StateProcessor. Restart reuses only
// this helper's newly allocated temporary datadir.
func nativeSyncOffCommonInProcess(t *testing.T, fixture *reconfig.FHSRewardNetworkFixture, source *nativeCommonNode, target uint64) {
	t.Helper()
	if source.Stack.Server().NodeInfo().Ports.Listener == 0 {
		t.Fatal("source Common needs nativeSyncPeers before start")
	}
	before := engine.Metrics()
	plain := startFHSRewardCommon(t, fixture, nativeCommonOptions{P2P: nativeSyncPeers(), Plain: true})
	if plain.Service.BlockChain().CurrentBlock().NumberU64() != 0 {
		t.Fatal("new DEX OFF Common did not start at genesis")
	}
	peer := source.Stack.Server().Self()
	plain.Stack.Server().AddPeer(peer)
	peerID := fmt.Sprintf("%x", peer.ID().Bytes()[:8])
	head := source.Service.BlockChain().GetBlockByNumber(target)
	if head == nil || source.Service.BlockChain().CurrentBlock().NumberU64() != target {
		t.Fatal("source canonical head does not match bounded sync target")
	}
	td := source.Service.BlockChain().GetTd(head.Hash(), target)
	deadline := time.NewTimer(75 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	result := make(chan error, 1)
	active := false
	var lastErr error
	for plain.Service.BlockChain().CurrentBlock().NumberU64() < target || active {
		select {
		case err := <-result:
			active = false
			lastErr = err
		case <-tick.C:
			if !active {
				active = true
				go func() { result <- plain.Service.Downloader().Synchronise(peerID, head.Hash(), td, downloader.FullSync) }()
			}
		case <-deadline.C:
			plain.Service.Downloader().Cancel()
			t.Fatalf("standard ETH full sync timeout: head=%d peers=%+v last=%v", plain.Service.BlockChain().CurrentBlock().NumberU64(), plain.Stack.Server().PeersInfo(), lastErr)
		}
	}
	compareNativeCommon(t, source, plain, target)
	if engine.Metrics() != before {
		t.Fatal("DEX OFF sync invoked financial engine")
	}
	for _, suffix := range []string{"dex", "dex-state", "dex-wal"} {
		if _, err := os.Stat(filepath.Join(plain.DataDir, suffix)); !os.IsNotExist(err) {
			t.Fatal("DEX OFF node created DEX data", suffix, err)
		}
	}
	dir := plain.DataDir
	plain.Client.Close()
	if err := plain.Stack.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := startFHSRewardCommon(t, fixture, nativeCommonOptions{DataDir: dir, Plain: true, Restart: true})
	compareNativeCommon(t, source, reopened, target)
	if reopened.Service.IsMining() || reopened.Service.ServiceIsRunning() || engine.Metrics() != before {
		t.Fatal("DEX OFF restart activated a role")
	}
	t.Logf("DEX_OFF_FULLSYNC_RESTART height=%d root=%s receipts=%s gas=%d peer=%s financialEngineDelta=0", target, head.Root().Hex(), head.ReceiptHash().Hex(), head.GasUsed(), peer.ID())
}

func compareNativeCommon(t *testing.T, source, follower *nativeCommonNode, target uint64) {
	t.Helper()
	a, b := source.Service.BlockChain(), follower.Service.BlockChain()
	if b.CurrentBlock().NumberU64() != target {
		t.Fatal("DEX OFF canonical height mismatch")
	}
	for height := uint64(0); height <= target; height++ {
		left, right := a.GetBlockByNumber(height), b.GetBlockByNumber(height)
		if left == nil || right == nil || left.Hash() != right.Hash() || left.Root() != right.Root() || left.ReceiptHash() != right.ReceiptHash() || left.GasUsed() != right.GasUsed() || !bytes.Equal(left.EncodeToBytes(), right.EncodeToBytes()) {
			t.Fatalf("DEX OFF block/root/receipt/gas mismatch height=%d", height)
		}
		if !reflect.DeepEqual(a.GetReceiptsByHash(left.Hash()), b.GetReceiptsByHash(right.Hash())) {
			t.Fatalf("DEX OFF receipt data mismatch height=%d", height)
		}
	}
	left, err := a.StateAt(a.GetBlockByNumber(target).Root())
	if err != nil {
		t.Fatal(err)
	}
	right, err := b.StateAt(b.GetBlockByNumber(target).Root())
	if err != nil {
		t.Fatal(err)
	}
	ls, lb, lu, err := settlement.NativeStatus(left, params.DEXSettlementAddress)
	if err != nil {
		t.Fatal(err)
	}
	rs, rb, ru, err := settlement.NativeStatus(right, params.DEXSettlementAddress)
	if err != nil {
		t.Fatal(err)
	}
	if ls != rs || !reflect.DeepEqual(lb, rb) || lu != ru || left.GetBalance(params.DEXSettlementAddress).Cmp(right.GetBalance(params.DEXSettlementAddress)) != 0 {
		t.Fatal("DEX OFF native custody/bucket mismatch")
	}
	for i := uint64(0); i < ls.Deposits; i++ {
		le, err := settlement.ReadNativeEntry(left, params.DEXSettlementAddress, i)
		if err != nil {
			t.Fatal(err)
		}
		re, err := settlement.ReadNativeEntry(right, params.DEXSettlementAddress, i)
		if err != nil || le != re {
			t.Fatal("DEX OFF native inbox mismatch", err)
		}
	}
}
