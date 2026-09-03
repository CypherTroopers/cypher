package core

import (
	"errors"
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/params"
)

type countingFinalityDatabase struct {
	ethdb.Database
	reads atomic.Int64
}

func (db *countingFinalityDatabase) Get(key []byte) ([]byte, error) {
	db.reads.Add(1)
	return db.Database.Get(key)
}

type receiptChainSignatureValidator struct {
	failAt uint64
	calls  []uint64
}

func (*receiptChainSignatureValidator) ValidateBody(*types.Block) error { return nil }
func (*receiptChainSignatureValidator) ValidateBodyWithHotstuffParent(*types.Block) error {
	return nil
}
func (*receiptChainSignatureValidator) ValidateState(*types.Block, *state.StateDB, types.Receipts, uint64) error {
	return nil
}
func (validator *receiptChainSignatureValidator) VerifySignature(block *types.Block) error {
	validator.calls = append(validator.calls, block.NumberU64())
	if block.NumberU64() == validator.failAt {
		return errors.New("injected invalid QC")
	}
	return nil
}

func receiptChainTestBlock(number uint64, parent common.Hash, signature string) *types.Block {
	block := types.NewBlockWithHeader(&types.Header{
		ParentHash: parent,
		Number:     new(big.Int).SetUint64(number),
		Difficulty: big.NewInt(1),
		GasLimit:   1,
	})
	block.SetFHSSignature([]byte(signature), []byte{0x1f}, common.HexToHash("0x11"), "leader", number, common.HexToHash("0xaa"), common.HexToHash("0xbb"))
	return block
}

func TestFHSReceiptPreflightIsAtomicAndReplacesSameHashHeaderProof(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	stored1 := receiptChainTestBlock(1, common.HexToHash("0x01"), "stored-one")
	stored2 := receiptChainTestBlock(2, stored1.Hash(), "stored-two")
	rawdb.WriteHeader(db, stored1.Header())
	rawdb.WriteHeader(db, stored2.Header())

	incoming1 := receiptChainTestBlock(1, stored1.ParentHash(), "verified-one")
	incoming2 := receiptChainTestBlock(2, incoming1.Hash(), "verified-two")
	if incoming1.Hash() != stored1.Hash() || incoming2.Hash() != stored2.Hash() {
		t.Fatal("SignInfo-only test mutations changed a block hash")
	}
	validator := &receiptChainSignatureValidator{failAt: 2}
	bc := &BlockChain{
		db:          db,
		chainConfig: &params.ChainConfig{FairHotstuff: true},
		validator:   validator,
	}
	if err := bc.preflightFHSReceiptChain(types.Blocks{incoming1, incoming2}); err == nil {
		t.Fatal("receipt preflight accepted an invalid second QC")
	}
	if got := rawdb.ReadHeader(db, stored1.Hash(), 1); got == nil || string(got.SignInfo.Signature) != "stored-one" {
		t.Fatal("failed preflight partially rewrote an earlier header")
	}

	validator.failAt = 0
	if err := bc.preflightFHSReceiptChain(types.Blocks{incoming1, incoming2}); err != nil {
		t.Fatalf("valid receipt proof chain rejected: %v", err)
	}
	if got := rawdb.ReadHeader(db, stored1.Hash(), 1); got == nil || string(got.SignInfo.Signature) != "verified-one" {
		t.Fatal("verified same-hash header did not replace untrusted SignInfo")
	}
	if got := rawdb.ReadHeader(db, stored2.Hash(), 2); got == nil || string(got.SignInfo.Signature) != "verified-two" {
		t.Fatal("verified second header proof was not persisted")
	}
}

func TestFHSBlockProofGuardRejectsBeforeAlternateImportPaths(t *testing.T) {
	validator := &receiptChainSignatureValidator{failAt: 7}
	bc := &BlockChain{
		chainConfig: &params.ChainConfig{FairHotstuff: true},
		validator:   validator,
	}
	block := receiptChainTestBlock(7, common.HexToHash("0x06"), "invalid")
	if err := bc.verifyFHSBlockProof(block); err == nil {
		t.Fatal("invalid Fair HotStuff proof passed the common persistence guard")
	}
	if len(validator.calls) != 1 || validator.calls[0] != 7 {
		t.Fatalf("signature verifier calls = %v, want [7]", validator.calls)
	}
}

func TestIsFinalizedTransactionRejectsReceiptSyncLookupAheadOfStateHead(t *testing.T) {
	db := &countingFinalityDatabase{Database: rawdb.NewMemoryDatabase()}
	tx := types.NewTransaction(0, common.Address{1}, big.NewInt(1), params.TxGas, big.NewInt(1), nil)
	genesis := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(0), Difficulty: big.NewInt(1)})
	block := types.NewBlockWithHeader(&types.Header{
		ParentHash: genesis.Hash(), Number: big.NewInt(1), Difficulty: big.NewInt(1),
	}).WithBody(types.Transactions{tx}, nil)
	rawdb.WriteBlock(db, block)
	rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
	rawdb.WriteTxLookupEntries(db, block)

	bc := &BlockChain{db: db, chainConfig: &params.ChainConfig{FairHotstuff: true}}
	bc.currentBlock.Store(genesis)
	if bc.IsFinalizedTransaction(tx.Hash()) {
		t.Fatal("receipt-sync lookup ahead of the FHS state head was treated as finalized")
	}
	bc.currentBlock.Store(block)
	if bc.IsFinalizedTransaction(tx.Hash()) {
		t.Fatal("ordinary canonical tx lookup was treated as an FHS finality marker")
	}
	rawdb.WriteFHSFinalizedTxLookupEntries(db, block)
	db.reads.Store(0)
	if !bc.IsFinalizedTransaction(tx.Hash()) {
		t.Fatal("canonical transaction at the FHS state head was not finalized")
	}
	if reads := db.reads.Load(); reads != 2 {
		t.Fatalf("exact finalized lookup performed %d DB reads, want marker+canonical only", reads)
	}
	rawdb.WriteCanonicalHash(db, common.HexToHash("0xdead"), block.NumberU64())
	if bc.IsFinalizedTransaction(tx.Hash()) {
		t.Fatal("transaction outside the canonical block body was treated as finalized")
	}
}
