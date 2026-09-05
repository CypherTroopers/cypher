package eth

import (
	"encoding/json"
	"math/big"
	"os"
	"sync/atomic"
	"testing"

	"github.com/cypherium/cypher/consensus/colossusX"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/eth/downloader"
	"github.com/cypherium/cypher/event"
)

func TestFHSProtocolManagerUsesFullSync(t *testing.T) {
	for _, test := range []struct {
		name      string
		requested downloader.SyncMode
		fastHead  bool
	}{
		{"default", DefaultConfig.SyncMode, false},
		{"explicit fast", downloader.FastSync, false},
		{"explicit full", downloader.FullSync, false},
		{"full with fast head", downloader.FullSync, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := newSyncModeTestManager(t, true, test.requested, test.fastHead)
			if atomic.LoadUint32(&manager.fastSync) != 0 {
				t.Fatal("Fair HotStuff enabled receipt-only fast sync")
			}
			assertFHSFullSyncHead(t, manager)
		})
	}
}

func TestFHSSyncDoesNotResumeFastSync(t *testing.T) {
	for _, test := range []struct {
		name     string
		fastFlag bool
		pivot    bool
	}{
		{"persisted pivot", false, true},
		{"stale fast flag", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := newSyncModeTestManager(t, true, downloader.FullSync, true)
			atomic.StoreUint32(&manager.fastSync, 0)
			if test.fastFlag {
				atomic.StoreUint32(&manager.fastSync, 1)
			}
			if test.pivot {
				rawdb.WriteLastPivotNumber(manager.chaindb, 1)
			}
			assertFHSFullSyncHead(t, manager)
		})
	}
}

func TestNonFHSSyncModeSelection(t *testing.T) {
	for _, test := range []struct {
		name      string
		requested downloader.SyncMode
		fastHead  bool
		want      downloader.SyncMode
	}{
		{"fast", downloader.FastSync, false, downloader.FastSync},
		{"full", downloader.FullSync, false, downloader.FullSync},
		{"resume fast head", downloader.FullSync, true, downloader.FastSync},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := newSyncModeTestManager(t, false, test.requested, test.fastHead)
			mode, _ := manager.chainSync.modeAndLocalHead()
			if mode != test.want {
				t.Fatalf("sync mode = %v, want %v", mode, test.want)
			}
		})
	}
}

func assertFHSFullSyncHead(t *testing.T, manager *ProtocolManager) {
	t.Helper()
	mode, td := manager.chainSync.modeAndLocalHead()
	if mode != downloader.FullSync {
		t.Fatalf("Fair HotStuff sync mode = %v, want full", mode)
	}
	// The fixture leaves the executed chain at genesis while optional header and
	// fast heads advance. Neither can suppress synchronization of finalized bodies.
	want := manager.blockchain.Genesis().Difficulty()
	if td == nil || td.Cmp(want) != 0 {
		t.Fatalf("Fair HotStuff local TD = %v, want executed genesis TD %v", td, want)
	}
}

func newSyncModeTestManager(t *testing.T, fairHotstuff bool, mode downloader.SyncMode, fastHead bool) *ProtocolManager {
	t.Helper()
	encoded, err := os.ReadFile("../genesis.json")
	if err != nil {
		t.Fatal(err)
	}
	genesis := new(core.Genesis)
	if err := json.Unmarshal(encoded, genesis); err != nil {
		t.Fatal(err)
	}
	if !fairHotstuff {
		genesis.Config.FairHotstuff = false
		genesis.Config.NativeParallel = nil
	}
	db := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { db.Close() })
	keyGenesis := &core.GenesisKey{Config: genesis.Config, Difficulty: big.NewInt(1)}
	if _, _, err := core.SetupGenesisKeyBlock(db, keyGenesis); err != nil {
		t.Fatal(err)
	}
	block, err := genesis.Commit(db)
	if err != nil {
		t.Fatal(err)
	}
	if fastHead {
		header := block.Header()
		header.ParentHash = block.Hash()
		header.Number = big.NewInt(1)
		header.Time = 1
		fastBlock := types.NewBlockWithHeader(header)
		rawdb.WriteBlock(db, fastBlock)
		rawdb.WriteTd(db, fastBlock.Hash(), 1, new(big.Int).Mul(block.Difficulty(), big.NewInt(2)))
		rawdb.WriteHeadFastBlockHash(db, fastBlock.Hash())
		rawdb.WriteHeadHeaderHash(db, fastBlock.Hash())
	}
	mux := new(event.TypeMux)
	engine := colossusX.NewFaker()
	t.Cleanup(func() { engine.Close() })
	keychain, err := core.NewKeyBlockChain(new(Ethereum), db, nil, genesis.Config, engine, mux)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := core.NewBlockChain(db, &core.CacheConfig{TrieDirtyDisabled: true}, genesis.Config, engine, vm.Config{}, nil, nil, keychain)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(chain.Stop)
	manager, err := NewProtocolManager(genesis.Config, nil, mode, genesis.Config.ChainID.Uint64(), mux,
		new(p2PFilterTestTxPool), engine, chain, db, 1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.downloader.Terminate)
	return manager
}
