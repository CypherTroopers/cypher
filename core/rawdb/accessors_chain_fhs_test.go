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
	batch := &types.CommonTxAdmissionBatch{Version: 2, RewardRecipient: common.Address{0xb7, 0x09},
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
	reward := &types.CommonTxReward{Version: 2, RewardRecipient: common.Address{0xb7, 0x09}, TxHash: tx.Hash(), Approver: batch.Miner, ApproverReward: big.NewInt(1), Burn: big.NewInt(1)}
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

func TestKeyBlockRoundTripsPermissionlessProofs(t *testing.T) {
	db := NewMemoryDatabase()
	proof := [][]byte{[]byte("timeout-view-115")}
	key := types.NewKeyBlock(&types.KeyBlockHeader{
		Number:     big.NewInt(17),
		ParentHash: common.HexToHash("0x10"),
		Difficulty: big.NewInt(1),
		Time:       100,
		BlockType:  types.PowReconfig,
		T_Number:   53,
	}).WithBody("in-pub", "in-addr", "out-pub", "out-addr", "leader-pub", "leader-addr")
	key.SetPermissionlessFaults(proof)
	WriteKeyBlock(db, key)

	restored := ReadKeyBlock(db, key.Hash(), key.NumberU64())
	if restored == nil || !restored.PermissionlessSeat() {
		t.Fatalf("permissionless key block lost its seat flag: %#v", restored)
	}
	got := restored.FaultProofBytes()
	if len(got) != 1 || string(got[0]) != string(proof[0]) {
		t.Fatalf("permissionless proofs = %#v, want %#v", got, proof)
	}
}

func TestKeyBlockLegacyBodyRestoredFromCarrierKeyInfo(t *testing.T) {
	db := NewMemoryDatabase()
	proof := [][]byte{[]byte("timeout-view-115")}
	key := types.NewKeyBlock(&types.KeyBlockHeader{
		Number:     big.NewInt(17),
		ParentHash: common.HexToHash("0x10"),
		Difficulty: big.NewInt(1),
		Time:       100,
		BlockType:  types.PowReconfig,
		T_Number:   53,
	}).WithBody("in-pub", "in-addr", "out-pub", "out-addr", "leader-pub", "leader-addr")
	key.SetPermissionlessFaults(proof)

	// Simulate the pre-fix body format that dropped the permissionless payload.
	WriteKeyHeader(db, key.Header())
	WriteKeyBody(db, key.Hash(), key.NumberU64(), key.Body())

	carrier := types.NewBlockWithHeader(&types.Header{
		Number:    big.NewInt(int64(key.T_Number() + 1)),
		BlockType: types.Key_Block,
		KeyHash:   key.ParentHash(),
	})
	carrier.SetKeyblock(key)
	WriteBlock(db, carrier)
	WriteCanonicalHash(db, carrier.Hash(), carrier.NumberU64())

	restored := ReadKeyBlock(db, key.Hash(), key.NumberU64())
	if restored == nil || !restored.PermissionlessSeat() {
		t.Fatalf("legacy body was not restored from carrier KeyInfo: %#v", restored)
	}
	got := restored.FaultProofBytes()
	if len(got) != 1 || string(got[0]) != string(proof[0]) {
		t.Fatalf("restored proofs = %#v, want %#v", got, proof)
	}
}
