package core

import (
	"bytes"
	"errors"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/ethdb/leveldb"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	lru "github.com/hashicorp/golang-lru"
)

var errFHSHeadSyncFixture = errors.New("injected canonical head fsync failure")

type fhsHeadSyncFailureDB struct{ ethdb.Database }

func (db fhsHeadSyncFailureDB) NewBatch() ethdb.Batch {
	return fhsHeadSyncFailureBatch{Batch: db.Database.NewBatch()}
}

type fhsHeadSyncFailureBatch struct{ ethdb.Batch }

func (fhsHeadSyncFailureBatch) WriteSync() error { return errFHSHeadSyncFixture }

// Exercise canonical publication with real 5/7 BLS target/child certificates
// and an already-executed StateDB fixture. Cold state reads use a new trie
// database before any Blockchain.Stop, so shutdown cannot hide missing writes.
func TestFHSCanonicalStateDurableBeforeShutdown(t *testing.T) {
	for _, name := range []string{"fresh proposal", "known cached state", "head fsync failure"} {
		t.Run(name, func(t *testing.T) {
			known := name == "known cached state"
			validator, secrets, public, keyHash := makeFHSCommitProofValidator(t)
			bc := validator.bc
			dir := filepath.Join(t.TempDir(), "chain")
			disk, err := leveldb.New(dir, 16, 16, "fhs-cold-state-test")
			if err != nil {
				t.Fatal(err)
			}
			db := rawdb.NewDatabase(disk)
			t.Cleanup(func() { _ = db.Close() })
			iterator := bc.db.NewIterator(nil, nil)
			for iterator.Next() {
				if err := db.Put(bytes.Clone(iterator.Key()), bytes.Clone(iterator.Value())); err != nil {
					t.Fatal(err)
				}
			}
			if err := iterator.Error(); err != nil {
				t.Fatal(err)
			}
			iterator.Release()
			bc.db, bc.keyBlockChain.db, bc.keyBlockChain.khc.chainDb = db, db, db
			bftview.SetCommitteeConfig(db, nil, nil)
			bc.stateCache = state.NewDatabase(db)
			cache := *defaultCacheConfig
			cache.TrieDirtyDisabled = false
			bc.cacheConfig = &cache
			bc.blockCache, _ = lru.New(16)
			bc.futureBlocks, _ = lru.New(16)
			bc.receiptsCache, _ = lru.New(16)
			account := common.Address{0x51}
			slot, value := common.Hash{0x52}, common.Hash{0x53}
			code := []byte{0x60, 0x00, 0x56}
			initial, err := state.New(common.Hash{}, bc.stateCache, nil)
			if err != nil {
				t.Fatal(err)
			}
			initial.SetBalance(account, big.NewInt(1000))
			genesisRoot, err := initial.Commit(false)
			if err != nil {
				t.Fatal(err)
			}
			if err := bc.stateCache.TrieDB().Commit(genesisRoot, false, nil); err != nil {
				t.Fatal(err)
			}
			genesis := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(0), Difficulty: big.NewInt(1), Root: genesisRoot, KeyHash: keyHash})
			rawdb.WriteBlock(db, genesis)
			rawdb.WriteCanonicalHash(db, genesis.Hash(), 0)
			rawdb.WriteHeadBlockHash(db, genesis.Hash())
			rawdb.WriteTd(db, genesis.Hash(), 0, big.NewInt(1))
			bc.genesisBlock = genesis
			bc.currentBlock.Store(genesis)
			bc.currentFastBlock.Store(genesis)
			bc.hc, err = NewHeaderChain(db, bc.chainConfig, nil, func() bool { return false })
			if err != nil {
				t.Fatal(err)
			}
			executed, err := state.New(genesisRoot, bc.stateCache, nil)
			if err != nil {
				t.Fatal(err)
			}
			executed.SetBalance(account, big.NewInt(997))
			executed.SetNonce(account, 1)
			executed.SetCode(account, code)
			executed.SetState(account, slot, value)
			root := executed.IntermediateRoot(false)
			block := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1), ParentHash: genesis.Hash(), Root: root, KeyHash: keyHash, BlockType: types.FastTx_Block})
			ref, qc := makeFHSCommitProofQC(t, block, 1, "leader-1", common.Hash{}, secrets, public)
			block.SetFHSSignature(qc.Sign, qc.Mask, qc.ViewID, qc.LeaderID, qc.Number, ref.ExtraHash, ref.ParentQCID)
			id, err := hotstuff.SignedStateID(qc)
			if err != nil {
				t.Fatal(err)
			}
			child := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(2), Difficulty: big.NewInt(1), ParentHash: block.Hash(), Root: root, KeyHash: keyHash, BlockType: types.FastTx_Block})
			_, childQC := makeFHSCommitProofQC(t, child, 2, "leader-2", id.Hash(), secrets, public)
			if known {
				if _, err := executed.Commit(false); err != nil {
					t.Fatal(err)
				}
				rawdb.WriteBlock(db, block)
				rawdb.WriteTd(db, block.Hash(), 1, big.NewInt(2))
				if !bc.HasBlockAndState(block.Hash(), 1) {
					t.Fatal("known fixture did not populate cached state")
				}
			}
			if _, err := state.New(root, state.NewDatabase(db), nil); err == nil {
				t.Fatal("fixture state was already durable before publication")
			}
			verified := &VerifiedProposal{ProposalID: ref.ProposalID(), ViewNumber: qc.Number, ViewID: qc.ViewID, LeaderID: qc.LeaderID, Block: block, StateDB: executed, ParentHash: genesis.Hash(), ParentNumber: 0, ParentRoot: genesisRoot}
			if name == "head fsync failure" {
				bc.db = fhsHeadSyncFailureDB{Database: db}
				status, err := bc.CommitFHSVerifiedProposalWithProof(verified, &FHSCommitProof{QCs: []*hotstuff.SignedState{childQC}}, false)
				if !errors.Is(err, errFHSHeadSyncFixture) || status != NonStatTy || bc.CurrentBlock().Hash() != genesis.Hash() || rawdb.ReadHeadBlockHash(db) != genesis.Hash() || rawdb.ReadCanonicalHash(db, 1) != (common.Hash{}) {
					t.Fatalf("failed fsync published canonical head: status=%d err=%v", status, err)
				}
				return
			}
			if status, err := bc.CommitFHSVerifiedProposalWithProof(verified, &FHSCommitProof{QCs: []*hotstuff.SignedState{childQC}}, false); err != nil || status != CanonStatTy {
				t.Fatalf("finality-aware commit: status=%d err=%v", status, err)
			}
			check := func() {
				t.Helper()
				if rawdb.ReadHeadBlockHash(db) != block.Hash() {
					t.Fatal("durable canonical head differs")
				}
				cold, err := state.New(root, state.NewDatabase(db), nil)
				if err != nil {
					t.Fatalf("published head has no cold trie state: %v", err)
				}
				if cold.GetBalance(account).Cmp(big.NewInt(997)) != 0 || cold.GetNonce(account) != 1 || cold.GetState(account, slot) != value || !bytes.Equal(cold.GetCode(account), code) || cold.Error() != nil {
					t.Fatal("cold account/storage/code differs from committed state")
				}
				stored := rawdb.ReadBlock(db, block.Hash(), 1)
				proof, present, err := DecodeFHSCommitProof(stored)
				if err != nil || !present || !fhsCommitProofSemanticEqual(proof, &FHSCommitProof{QCs: []*hotstuff.SignedState{childQC}}) {
					t.Fatal("durable block lost its exact finality evidence")
				}
			}
			check()
			// Close only the disk, deliberately never Blockchain.Stop or a trie
			// flush. A new LevelDB handle must expose the same published state.
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			disk, err = leveldb.New(dir, 16, 16, "fhs-cold-state-reopen-test")
			if err != nil {
				t.Fatal(err)
			}
			db = rawdb.NewDatabase(disk)
			check()
		})
	}
}
