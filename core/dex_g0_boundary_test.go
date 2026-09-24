package core

import (
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	lru "github.com/hashicorp/golang-lru"
)

var errG0Storage = errors.New("G0 owned fixture storage failure")

type g0FaultDB struct {
	ethdb.Database
	mode string
}
type g0NoSyncBatch struct{ ethdb.Batch }
type g0FaultBatch struct {
	ethdb.Batch
	db *g0FaultDB
}

func (db *g0FaultDB) NewBatch() ethdb.Batch {
	b := db.Database.NewBatch()
	if db.mode == "no-sync" {
		return g0NoSyncBatch{b}
	}
	return g0FaultBatch{b, db}
}
func (b g0FaultBatch) Write() error {
	if b.db.mode == "trie-write" {
		return errG0Storage
	}
	return b.Batch.Write()
}
func (b g0FaultBatch) WriteSync() error {
	if b.db.mode == "head-sync" {
		return errG0Storage
	}
	return b.Batch.(ethdb.SyncBatch).WriteSync()
}

// This test isolates storage ordering using the existing permissive test
// validator. TestFHSCanonicalStateDurableBeforeShutdown separately exercises
// real 5/7 certificates and cold LevelDB reads without a shutdown flush.
func TestG0CanonicalHeadStorageFailureAndRetry(t *testing.T) {
	for _, mode := range []string{"no-sync", "trie-write", "head-sync"} {
		t.Run(mode, func(t *testing.T) {
			disk := rawdb.NewMemoryDatabase()
			defer disk.Close()
			db := &g0FaultDB{Database: disk}
			keyGenesis := types.NewKeyBlock(&types.KeyBlockHeader{Difficulty: big.NewInt(1), Number: big.NewInt(0), Time: 1})
			keyChild := types.NewKeyBlock(&types.KeyBlockHeader{ParentHash: keyGenesis.Hash(), Difficulty: big.NewInt(1), Number: big.NewInt(1), Time: 2})
			rawdb.WriteKeyBlock(db, keyGenesis)
			rawdb.WriteKeyBlockHash(db, keyGenesis.Hash(), 0)
			rawdb.WriteHeadKeyBlockHash(db, keyGenesis.Hash())
			keyCache, _ := lru.New(blockCacheLimit)
			kbc := &KeyBlockChain{db: db, blockCache: keyCache}
			kbc.currentBlock.Store(keyGenesis)
			cache := state.NewDatabase(db)
			st, err := state.New(types.EmptyRootHash, cache, nil)
			if err != nil {
				t.Fatal(err)
			}
			account := common.Address{0x93}
			st.SetBalance(account, big.NewInt(77))
			root, err := st.Commit(false)
			if err != nil {
				t.Fatal(err)
			}
			genesis := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(0), Difficulty: big.NewInt(1), Root: types.EmptyRootHash, BlockType: types.FastTx_Block})
			block := types.NewBlockWithHeader(&types.Header{ParentHash: genesis.Hash(), Number: big.NewInt(1), Difficulty: big.NewInt(1), BlockType: types.Key_Block, KeyHash: keyGenesis.Hash(), Root: root})
			block.SetKeyblock(keyChild)
			proof, err := encodeFHSFinalityProof(&hotstuff.SignedState{State: []byte{1}, Sign: []byte{1}, Mask: []byte{1}, ViewID: common.Hash{1}, LeaderID: "fixture", Number: 1})
			if err != nil {
				t.Fatal(err)
			}
			if err = block.SetFHSFinalityProof(proof); err != nil {
				t.Fatal(err)
			}
			rawdb.WriteBlock(db, genesis)
			rawdb.WriteCanonicalHash(db, genesis.Hash(), 0)
			rawdb.WriteHeadBlockHash(db, genesis.Hash())
			rawdb.WriteHeadHeaderHash(db, genesis.Hash())
			rawdb.WriteHeadFastBlockHash(db, genesis.Hash())
			hc := &HeaderChain{}
			hc.SetCurrentHeader(genesis.Header())
			bc := &BlockChain{chainConfig: &params.ChainConfig{FairHotstuff: true}, db: db, keyBlockChain: kbc, validator: &fhsCanonicalHeadTestValidator{}, stateCache: cache, hc: hc}
			bc.currentBlock.Store(genesis)
			bc.currentFastBlock.Store(genesis)
			db.mode = mode
			if err := bc.writeHeadBlock(block); err == nil {
				t.Fatal("storage failure accepted")
			}
			if rawdb.ReadHeadBlockHash(db) != genesis.Hash() || rawdb.ReadHeadHeaderHash(db) != genesis.Hash() || rawdb.ReadHeadFastBlockHash(db) != genesis.Hash() || rawdb.ReadHeadKeyBlockHash(db) != keyGenesis.Hash() || rawdb.ReadCanonicalHash(db, 1) != (common.Hash{}) || rawdb.ReadKeyBlockHash(db, 1) != (common.Hash{}) {
				t.Fatal("storage failure published a durable transaction/key marker")
			}
			if bc.CurrentBlock().Hash() != genesis.Hash() || bc.CurrentFastBlock().Hash() != genesis.Hash() || kbc.CurrentBlock().Hash() != keyGenesis.Hash() || hc.CurrentHeader().Hash() != genesis.Hash() {
				t.Fatal("storage failure published an in-memory head")
			}
			db.mode = ""
			if err := bc.writeHeadBlock(block); err != nil {
				t.Fatal("same transition retry failed", err)
			}
			if rawdb.ReadHeadBlockHash(db) != block.Hash() || rawdb.ReadHeadKeyBlockHash(db) != keyChild.Hash() || rawdb.ReadCanonicalHash(db, 1) != block.Hash() || rawdb.ReadKeyBlockHash(db, 1) != keyChild.Hash() || bc.CurrentBlock().Hash() != block.Hash() || kbc.CurrentBlock().Hash() != keyChild.Hash() {
				t.Fatal("retry did not commit both heads")
			}
			cold, err := state.New(root, state.NewDatabase(db), nil)
			if err != nil || cold.GetBalance(account).Cmp(big.NewInt(77)) != 0 {
				t.Fatal("committed head has no cold state", err)
			}
		})
	}
}

func TestG0NativeOnlyLocalGenesisFieldsMayDiffer(t *testing.T) {
	for _, field := range []string{"local-port", "local-metrics", "chain-id", "transport", "fallback", "committee", "fixed-committee", "seed", "dex-id", "custody", "activation", "checkpoint-cap", "modern-fork"} {
		t.Run(field, func(t *testing.T) {
			f := newNativeTXFixture(t, 0)
			raw, err := json.Marshal(f.config)
			if err != nil {
				t.Fatal(err)
			}
			var runtime params.ChainConfig
			if err = json.Unmarshal(raw, &runtime); err != nil {
				t.Fatal(err)
			}
			defer runtime.SetModernForkConfig(nil)
			switch field {
			case "local-port":
				runtime.RnetPort = "49271"
			case "local-metrics":
				runtime.EnabledTPS = !runtime.EnabledTPS
			case "chain-id":
				runtime.ChainID = new(big.Int).Add(runtime.ChainID, big.NewInt(1))
			case "transport":
				runtime.RnetTransport = "tcp"
			case "fallback":
				runtime.RnetFallbackTransport = "tcp"
			case "committee":
				n := runtime.GenCommittee[0]
				n.Address = "127.0.0.1:19999"
				runtime.GenCommittee[0] = n
			case "fixed-committee":
				runtime.FixedCommittee = false
			case "seed":
				runtime.FairHotstuffSeed[0] ^= 1
			case "dex-id":
				runtime.DEXDevnet.DEXID[0] ^= 1
			case "custody":
				runtime.DEXDevnet.Custody[0] ^= 1
			case "activation":
				runtime.DEXDevnet.ActivationBlock++
			case "checkpoint-cap":
				runtime.DEXDevnet.MaxCheckpoints++
			case "modern-fork":
				runtime.SetModernForkConfig(&params.ModernForkConfig{LondonBlock: big.NewInt(99)})
			}
			db := rawdb.NewMemoryDatabase()
			defer db.Close()
			rawdb.WriteChainConfig(db, f.chain.genesis.Hash(), f.config)
			chain := nativeGenesisConfigChain{nativeTXChain: f.chain, store: &BlockChain{db: db, genesisBlock: f.chain.genesis}}
			input, _ := (protocol.NativeCall{Operation: protocol.NativeDeposit}).Encode()
			tx := f.tx(t, 0, big.NewInt(5), 600000, input)
			balance := new(big.Int).Set(f.st.GetBalance(f.sender))
			before := f.st.IntermediateRoot(false)
			gp, used := new(GasPool).AddGas(f.header.GasLimit), uint64(0)
			f.st.Prepare(tx.Hash(), f.header.Hash(), 0)
			receipt, err := ApplyTransaction(&runtime, chain, nil, gp, f.st, f.header, tx, &used, vm.Config{})
			if field == "local-port" || field == "local-metrics" {
				if err != nil || receipt == nil || receipt.Status != types.ReceiptStatusSuccessful {
					t.Fatal("local setting changed native execution", receipt, err)
				}
			} else if err == nil || receipt != nil || used != 0 || gp.Gas() != f.header.GasLimit || f.st.GetNonce(f.sender) != 0 || f.st.GetBalance(f.sender).Cmp(balance) != 0 || f.st.IntermediateRoot(false) != before {
				t.Fatal("unauthenticated consensus override changed execution", receipt, used, err)
			}
			stored := rawdb.ReadChainConfig(db, f.chain.genesis.Hash())
			got, err := json.Marshal(stored)
			stored.SetModernForkConfig(nil)
			if err != nil || string(got) != string(raw) {
				t.Fatal("runtime authentication changed persisted genesis", err)
			}
		})
	}
}
