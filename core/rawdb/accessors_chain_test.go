package rawdb

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/ethdb/memorydb"
	"github.com/cypherium/cypher/rlp"
)

func TestReadSignedHeaderFromAncient(t *testing.T) {
	freezerDir := t.TempDir()
	db, err := NewDatabaseWithFreezer(memorydb.New(), freezerDir, "test/ancient/")
	if err != nil {
		t.Fatalf("NewDatabaseWithFreezer: %v", err)
	}

	genesis := ancientTestBlock(0, common.Hash{}, nil, nil)
	signed := ancientTestBlock(1, genesis.Hash(), []byte("signed-header"), []byte{1, 4})
	WriteAncientBlock(db, genesis, nil, big.NewInt(1))
	WriteAncientBlock(db, signed, nil, big.NewInt(2))
	if err := db.Sync(); err != nil {
		t.Fatalf("sync ancient database: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close ancient database: %v", err)
	}
	db, err = NewDatabaseWithFreezer(memorydb.New(), freezerDir, "test/ancient/")
	if err != nil {
		t.Fatalf("reopen ancient database: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("Close database: %v", err)
		}
	})

	headerRLP, err := rlp.EncodeToBytes(signed.Header())
	if err != nil {
		t.Fatalf("encode signed header: %v", err)
	}
	if rawHash := crypto.Keccak256Hash(headerRLP); rawHash == signed.Hash() {
		t.Fatal("test requires the signed header RLP hash to differ from Header.Hash")
	}
	if got := ReadCanonicalHash(db, signed.NumberU64()); got != signed.Hash() {
		t.Fatalf("canonical hash = %s, want %s", got, signed.Hash())
	}
	if got := ReadHeaderRLP(db, signed.Hash(), signed.NumberU64()); !bytes.Equal(got, headerRLP) {
		t.Fatalf("signed ancient header RLP was not returned")
	}
	if got := ReadHeader(db, signed.Hash(), signed.NumberU64()); got == nil || got.Hash() != signed.Hash() {
		t.Fatalf("signed ancient header = %v, want hash %s", got, signed.Hash())
	}
	if got := ReadBlock(db, signed.Hash(), signed.NumberU64()); got == nil || got.Hash() != signed.Hash() {
		t.Fatalf("signed ancient block = %v, want hash %s", got, signed.Hash())
	}

	wrongHash := signed.Hash()
	wrongHash[0] ^= 0xff
	if got := ReadHeaderRLP(db, wrongHash, signed.NumberU64()); len(got) != 0 {
		t.Fatalf("ancient header returned for non-canonical hash %s", wrongHash)
	}
}

func TestReadSignedHeaderFromHotDatabase(t *testing.T) {
	db := NewMemoryDatabase()
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("Close database: %v", err)
		}
	})

	block := ancientTestBlock(1, common.HexToHash("0x01"), []byte("signed-header"), []byte{2, 5})
	WriteBlock(db, block)
	WriteCanonicalHash(db, block.Hash(), block.NumberU64())

	if got := ReadBlock(db, block.Hash(), block.NumberU64()); got == nil || got.Hash() != block.Hash() {
		t.Fatalf("signed hot-database block = %v, want hash %s", got, block.Hash())
	}
}

func TestReadAncientHeaderRejectsMissingCanonicalHash(t *testing.T) {
	db, err := NewDatabaseWithFreezer(memorydb.New(), t.TempDir(), "test/malformed-ancient/")
	if err != nil {
		t.Fatalf("NewDatabaseWithFreezer: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("Close database: %v", err)
		}
	})

	headerRLP, err := rlp.EncodeToBytes(ancientTestBlock(0, common.Hash{}, nil, nil).Header())
	if err != nil {
		t.Fatalf("encode header: %v", err)
	}
	if err := db.AppendAncient(0, nil, headerRLP, nil, nil, nil); err != nil {
		t.Fatalf("append malformed ancient block: %v", err)
	}
	if got := ReadHeaderRLP(db, common.Hash{}, 0); len(got) != 0 {
		t.Fatal("ancient header returned without a complete canonical hash")
	}
}

func ancientTestBlock(number uint64, parent common.Hash, signature, exceptions []byte) *types.Block {
	header := &types.Header{
		ParentHash:  parent,
		UncleHash:   types.EmptyUncleHash,
		Root:        types.EmptyRootHash,
		TxHash:      types.EmptyRootHash,
		ReceiptHash: types.EmptyRootHash,
		Difficulty:  big.NewInt(1),
		Number:      new(big.Int).SetUint64(number),
		GasLimit:    1,
		Time:        number,
		SignInfo: types.SignInfo{
			Signature:  signature,
			Exceptions: exceptions,
		},
	}
	return types.NewBlockWithHeader(header).WithBody(nil, nil)
}
