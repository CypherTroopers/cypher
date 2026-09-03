package core

import (
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/cypherium/cypher/consensus/colossusX"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/trie"
)

// receiptChainMutationDatabase records durable writes after the test fixture is
// complete. Receipt import must authenticate every KZG proof before initiating
// any database mutation, including a batch commit or tx-index-tail update.
type receiptChainMutationDatabase struct {
	ethdb.Database
	tracking  atomic.Bool
	mutations atomic.Int64
}

func (db *receiptChainMutationDatabase) Put(key, value []byte) error {
	if db.tracking.Load() {
		db.mutations.Add(1)
	}
	return db.Database.Put(key, value)
}

func (db *receiptChainMutationDatabase) Delete(key []byte) error {
	if db.tracking.Load() {
		db.mutations.Add(1)
	}
	return db.Database.Delete(key)
}

func (db *receiptChainMutationDatabase) NewBatch() ethdb.Batch {
	return &receiptChainMutationBatch{Batch: db.Database.NewBatch(), db: db}
}

func (db *receiptChainMutationDatabase) AppendAncient(number uint64, hash, header, body, receipt, td []byte) error {
	if db.tracking.Load() {
		db.mutations.Add(1)
	}
	return db.Database.AppendAncient(number, hash, header, body, receipt, td)
}

func (db *receiptChainMutationDatabase) TruncateAncients(items uint64) error {
	if db.tracking.Load() {
		db.mutations.Add(1)
	}
	return db.Database.TruncateAncients(items)
}

func (db *receiptChainMutationDatabase) startTracking() {
	db.mutations.Store(0)
	db.tracking.Store(true)
}

type receiptChainMutationBatch struct {
	ethdb.Batch
	db *receiptChainMutationDatabase
}

func (batch *receiptChainMutationBatch) Write() error {
	if batch.db.tracking.Load() && batch.ValueSize() != 0 {
		batch.db.mutations.Add(1)
	}
	return batch.Batch.Write()
}

func newReceiptChainBlobFixture(t *testing.T) (*BlockChain, *receiptChainMutationDatabase, *types.Block, types.Receipts) {
	t.Helper()

	db := &receiptChainMutationDatabase{Database: rawdb.NewMemoryDatabase()}
	config := pragueSystemTestConfig()
	genesis := (&Genesis{
		Config:     config,
		Difficulty: big.NewInt(1),
		GasLimit:   params.GenesisGasLimit,
	}).MustCommit(db)
	chain, err := NewBlockChain(
		db,
		&CacheConfig{TrieDirtyDisabled: true},
		config,
		colossusX.NewFaker(),
		vm.Config{},
		nil,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("NewBlockChain failed: %v", err)
	}
	t.Cleanup(chain.Stop)

	tx := buildCoreBlobTxWithRealSidecar(t)
	receipts := types.Receipts{&types.Receipt{
		Type:              types.BlobTxType,
		Status:            types.ReceiptStatusSuccessful,
		CumulativeGasUsed: params.TxGas,
		TxHash:            tx.Hash(),
		GasUsed:           params.TxGas,
	}}
	header := &types.Header{
		ParentHash:      genesis.Hash(),
		Root:            genesis.Root(),
		Difficulty:      big.NewInt(1),
		Number:          big.NewInt(1),
		GasLimit:        params.GenesisGasLimit,
		GasUsed:         params.TxGas,
		Time:            1,
		BaseFee:         big.NewInt(params.FixedBaseFeePerGas),
		WithdrawalsHash: types.EmptyWithdrawalsHash,
		RequestsHash:    types.EmptyRequestsHash,
		BlobGasUsed:     CalcBlobGasUsed(types.Transactions{tx}),
	}
	block := types.NewBlock(header, types.Transactions{tx}, nil, receipts, new(trie.Trie))

	// Fast receipt sync receives bodies only after the corresponding header is
	// already known. Write exactly that prerequisite, but no body or receipts.
	rawdb.WriteHeader(db, block.Header())
	rawdb.WriteTd(db, block.Hash(), block.NumberU64(), big.NewInt(2))
	db.startTracking()
	return chain, db, block, receipts
}

func TestInsertReceiptChainAuthenticatesBlobSidecarsBeforeMutation(t *testing.T) {
	t.Run("invalid proof", func(t *testing.T) {
		chain, db, valid, receipts := newReceiptChainBlobFixture(t)
		sidecars := valid.BlobSidecars()
		sidecars[0].Proofs[0][0] ^= 0xff
		invalid, err := valid.WithBlobSidecars(sidecars)
		if err != nil {
			t.Fatalf("constructing structurally valid bad-proof block failed: %v", err)
		}

		_, err = chain.InsertReceiptChain(types.Blocks{invalid}, []types.Receipts{receipts}, 0)
		if err == nil {
			t.Error("InsertReceiptChain accepted an invalid EIP-4844 KZG proof")
		}
		if mutations := db.mutations.Load(); mutations != 0 {
			t.Errorf("invalid KZG proof caused %d database mutations before rejection", mutations)
		}
		if rawdb.HasBody(db, invalid.Hash(), invalid.NumberU64()) {
			t.Error("invalid KZG proof persisted a block body")
		}
		if rawdb.HasReceipts(db, invalid.Hash(), invalid.NumberU64()) {
			t.Error("invalid KZG proof persisted receipts")
		}
		if number := rawdb.ReadTxLookupEntry(db, invalid.Transactions()[0].Hash()); number != nil {
			t.Errorf("invalid KZG proof persisted a transaction lookup at block %d", *number)
		}
		if tail := rawdb.ReadTxIndexTail(db); tail != nil {
			t.Errorf("invalid KZG proof changed tx index tail to %d", *tail)
		}
	})

	t.Run("valid proof", func(t *testing.T) {
		chain, db, block, receipts := newReceiptChainBlobFixture(t)
		if _, err := chain.InsertReceiptChain(types.Blocks{block}, []types.Receipts{receipts}, 0); err != nil {
			t.Fatalf("InsertReceiptChain rejected a valid EIP-4844 sidecar: %v", err)
		}
		if mutations := db.mutations.Load(); mutations == 0 {
			t.Fatal("valid receipt import did not mutate the database")
		}
		body := rawdb.ReadBody(db, block.Hash(), block.NumberU64())
		if body == nil {
			t.Fatal("valid receipt import did not persist the block body")
		}
		sidecars := body.BlobSidecars
		want := block.BlobSidecars()
		if len(sidecars) != 1 || len(sidecars[0].Proofs) != 1 || sidecars[0].Proofs[0] != want[0].Proofs[0] {
			t.Fatal("valid receipt import did not preserve the authenticated blob sidecar")
		}
		if !rawdb.HasReceipts(db, block.Hash(), block.NumberU64()) {
			t.Fatal("valid receipt import did not persist receipts")
		}
		if number := rawdb.ReadTxLookupEntry(db, block.Transactions()[0].Hash()); number == nil || *number != block.NumberU64() {
			t.Fatalf("valid receipt import tx lookup = %v, want block %d", number, block.NumberU64())
		}
	})
}
