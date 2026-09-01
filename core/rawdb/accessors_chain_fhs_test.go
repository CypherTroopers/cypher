package rawdb

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/rlp"
)

func TestHeaderRLPMatchesHashWithHotstuffSignInfo(t *testing.T) {
	header := &types.Header{
		Number:     big.NewInt(90000),
		Difficulty: big.NewInt(1),
		GasLimit:   1,
		SignInfo: types.SignInfo{
			Signature:  []byte("aggregate-signature"),
			Exceptions: []byte{0x1f},
			ViewID:     common.HexToHash("0x11"),
			LeaderID:   "leader",
			ViewNumber: 42,
			ExtraHash:  common.HexToHash("0xaa"),
			ParentQCID: common.HexToHash("0xbb"),
		},
	}
	encoded, err := rlp.EncodeToBytes(header)
	if err != nil {
		t.Fatal(err)
	}
	if !headerRLPMatchesHash(encoded, header.Hash()) {
		t.Fatal("freezer lookup rejected a header whose hash intentionally excludes SignInfo")
	}
	if headerRLPMatchesHash(encoded, common.HexToHash("0xdead")) {
		t.Fatal("freezer lookup accepted the wrong requested header hash")
	}
	if headerRLPMatchesHash([]byte{0xff}, header.Hash()) {
		t.Fatal("freezer lookup accepted malformed header RLP")
	}
}

func TestReadBlockRejectsCorruptCommonTransactionBody(t *testing.T) {
	db := NewMemoryDatabase()
	tx := types.NewTransaction(0, common.Address{1}, big.NewInt(1), 21_000, big.NewInt(1), nil)
	batch := &types.CommonTxAdmissionBatch{
		ChainID:     big.NewInt(1),
		GenesisHash: common.Hash{1},
		Miner:       common.Address{2},
		Timestamp:   1,
		TxHashes:    []common.Hash{tx.Hash()},
		Signature:   make([]byte, 65),
	}
	batch.TxRoot = types.DeriveCommonTxAdmissionTxRoot(batch.TxHashes)
	batch.AdmissionID = types.CommonTxAdmissionID(batch)
	refs := []types.CommonTxAdmissionRef{{}}
	reward := &types.CommonTxReward{TxHash: tx.Hash(), Approver: batch.Miner, ApproverReward: big.NewInt(1), Burn: big.NewInt(1)}
	block := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1)}).WithBody(types.Transactions{tx}, nil)
	block.AttachCommonTxData([]*types.CommonTxAdmissionBatch{batch}, refs, []*types.CommonTxReward{reward})
	WriteBlock(db, block)

	if restored := ReadBlock(db, block.Hash(), block.NumberU64()); restored == nil || restored.Hash() != block.Hash() {
		t.Fatalf("valid stored block was not restored: %#v", restored)
	}
	WriteBody(db, block.Hash(), block.NumberU64(), &types.Body{Transactions: block.Transactions()})
	if restored := ReadBlock(db, block.Hash(), block.NumberU64()); restored != nil {
		t.Fatalf("body with mismatched sidecar roots was accepted as %s", restored.Hash())
	}
}
