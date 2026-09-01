package types

import (
	"bytes"
	"math/big"
	"strings"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto"
)

func makeSignedCommonTxAdmissionBatch(t *testing.T, count int) *CommonTxAdmissionBatch {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	txHashes := make([]common.Hash, count)
	for index := range txHashes {
		txHashes[index] = common.BigToHash(new(big.Int).SetUint64(uint64(index + 1)))
	}
	batch := &CommonTxAdmissionBatch{
		ChainID:        big.NewInt(99),
		GenesisHash:    common.HexToHash("0x1234"),
		Miner:          crypto.PubkeyToAddress(key.PublicKey),
		KeyBlockNumber: 7,
		Timestamp:      1_700_000_000,
		TxHashes:       txHashes,
	}
	batch.TxRoot = DeriveCommonTxAdmissionTxRoot(batch.TxHashes)
	batch.AdmissionID = CommonTxAdmissionID(batch)
	batch.Signature, err = crypto.Sign(CommonTxAdmissionSigningHash(batch).Bytes(), key)
	if err != nil {
		t.Fatal(err)
	}
	return batch
}

func cloneCommonTxAdmissionBatchForTest(batch *CommonTxAdmissionBatch) *CommonTxAdmissionBatch {
	if batch == nil {
		return nil
	}
	clone := *batch
	if batch.ChainID != nil {
		clone.ChainID = new(big.Int).Set(batch.ChainID)
	}
	clone.TxHashes = append([]common.Hash(nil), batch.TxHashes...)
	clone.Signature = append([]byte(nil), batch.Signature...)
	return &clone
}

func TestCommonTxAdmissionBatchBoundsAndSignature(t *testing.T) {
	for _, count := range []int{1, MaxCommonTxAdmissionBatchItems} {
		batch := makeSignedCommonTxAdmissionBatch(t, count)
		if err := VerifyCommonTxAdmissionSignature(batch); err != nil {
			t.Fatalf("valid %d-item admission rejected: %v", count, err)
		}
	}
	for _, count := range []int{0, MaxCommonTxAdmissionBatchItems + 1} {
		batch := makeSignedCommonTxAdmissionBatch(t, count)
		if err := VerifyCommonTxAdmissionSignature(batch); err == nil || !strings.Contains(err.Error(), "invalid transaction count") {
			t.Fatalf("%d-item admission error = %v, want count rejection", count, err)
		}
	}
}

func TestCommonTxAdmissionBatchBindsOrderAndUniqueHashes(t *testing.T) {
	batch := makeSignedCommonTxAdmissionBatch(t, 3)
	originalRoot, originalID := batch.TxRoot, batch.AdmissionID
	batch.TxHashes[0], batch.TxHashes[1] = batch.TxHashes[1], batch.TxHashes[0]
	if reordered := DeriveCommonTxAdmissionTxRoot(batch.TxHashes); reordered == originalRoot {
		t.Fatal("transaction root did not bind hash order")
	}
	if reordered := CommonTxAdmissionID(batch); reordered == originalID {
		t.Fatal("admission ID did not bind hash order")
	}
	if err := VerifyCommonTxAdmissionSignature(batch); err == nil || !strings.Contains(err.Error(), "transaction root mismatch") {
		t.Fatalf("reordered admission error = %v, want root mismatch", err)
	}
	batch.TxRoot = DeriveCommonTxAdmissionTxRoot(batch.TxHashes)
	batch.AdmissionID = CommonTxAdmissionID(batch)
	if err := VerifyCommonTxAdmissionSignature(batch); err == nil {
		t.Fatal("signature remained valid after reordered hashes and recomputed commitments")
	}

	duplicate := makeSignedCommonTxAdmissionBatch(t, 2)
	duplicate.TxHashes[1] = duplicate.TxHashes[0]
	duplicate.TxRoot = DeriveCommonTxAdmissionTxRoot(duplicate.TxHashes)
	duplicate.AdmissionID = CommonTxAdmissionID(duplicate)
	if err := VerifyCommonTxAdmissionSignature(duplicate); err == nil || !strings.Contains(err.Error(), "repeats transaction") {
		t.Fatalf("duplicate admission error = %v, want duplicate rejection", err)
	}
}

func TestCommonTxAdmissionBatchRejectsTampering(t *testing.T) {
	valid := makeSignedCommonTxAdmissionBatch(t, 4)
	if err := VerifyCommonTxAdmissionSignature(valid); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*CommonTxAdmissionBatch)
	}{
		{"chain-id", func(batch *CommonTxAdmissionBatch) { batch.ChainID.Add(batch.ChainID, big.NewInt(1)) }},
		{"genesis", func(batch *CommonTxAdmissionBatch) { batch.GenesisHash[0] ^= 1 }},
		{"tx-root", func(batch *CommonTxAdmissionBatch) { batch.TxRoot[0] ^= 1 }},
		{"admission-id", func(batch *CommonTxAdmissionBatch) { batch.AdmissionID[0] ^= 1 }},
		{"miner", func(batch *CommonTxAdmissionBatch) { batch.Miner[0] ^= 1 }},
		{"key-block", func(batch *CommonTxAdmissionBatch) { batch.KeyBlockNumber++ }},
		{"timestamp", func(batch *CommonTxAdmissionBatch) { batch.Timestamp++ }},
		{"signature", func(batch *CommonTxAdmissionBatch) { batch.Signature[0] ^= 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			batch := cloneCommonTxAdmissionBatchForTest(valid)
			test.mutate(batch)
			if err := VerifyCommonTxAdmissionSignature(batch); err == nil {
				t.Fatal("tampered admission was accepted")
			}
		})
	}
}

func TestCommonTxAdmissionBatchRejectsNonCanonicalSignatureValues(t *testing.T) {
	valid := makeSignedCommonTxAdmissionBatch(t, 2)
	if err := VerifyCommonTxAdmissionSignature(valid); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func([]byte)
	}{
		{"recovery-id", func(signature []byte) { signature[crypto.RecoveryIDOffset] = 2 }},
		{"zero-r", func(signature []byte) {
			for index := 0; index < 32; index++ {
				signature[index] = 0
			}
		}},
		{"high-s", func(signature []byte) {
			s := new(big.Int).SetBytes(signature[32:crypto.RecoveryIDOffset])
			highS := new(big.Int).Sub(crypto.S256().Params().N, s)
			highS.FillBytes(signature[32:crypto.RecoveryIDOffset])
			signature[crypto.RecoveryIDOffset] ^= 1
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			batch := cloneCommonTxAdmissionBatchForTest(valid)
			test.mutate(batch.Signature)
			if err := VerifyCommonTxAdmissionSignature(batch); err == nil || !strings.Contains(err.Error(), "non-canonical signature values") {
				t.Fatalf("non-canonical signature error = %v", err)
			}
		})
	}
}

func TestCommonTxAdmissionRootBindsCountsAndPositions(t *testing.T) {
	first := makeSignedCommonTxAdmissionBatch(t, 2)
	second := makeSignedCommonTxAdmissionBatch(t, 2)
	refs := []CommonTxAdmissionRef{{Batch: 0, Item: 1}, {Batch: 1, Item: 0}}
	root := DeriveCommonTxAdmissionRoot([]*CommonTxAdmissionBatch{first, second}, refs)
	if root == (common.Hash{}) {
		t.Fatal("non-empty admission data derived an empty root")
	}
	if got := DeriveCommonTxAdmissionRoot([]*CommonTxAdmissionBatch{second, first}, refs); got == root {
		t.Fatal("admission root did not bind batch positions")
	}
	if got := DeriveCommonTxAdmissionRoot([]*CommonTxAdmissionBatch{first, second}, []CommonTxAdmissionRef{refs[1], refs[0]}); got == root {
		t.Fatal("admission root did not bind reference positions")
	}
	if got := DeriveCommonTxAdmissionRoot([]*CommonTxAdmissionBatch{first, second}, append(refs, CommonTxAdmissionRef{})); got == root {
		t.Fatal("admission root did not bind reference count")
	}
	if got := DeriveCommonTxAdmissionRoot([]*CommonTxAdmissionBatch{first, nil, second}, refs); got == root {
		t.Fatal("nil batch entry was omitted from admission root")
	}
	if got := DeriveCommonTxAdmissionRoot(nil, nil); got != (common.Hash{}) {
		t.Fatalf("empty admission root = %s, want zero", got)
	}
}

func TestCommonTxAdmissionBlockRLPRoundTrip(t *testing.T) {
	tx := NewTransaction(0, common.HexToAddress("0x1000"), big.NewInt(1), 21_000, big.NewInt(1), nil)
	batch := makeSignedCommonTxAdmissionBatch(t, 1)
	batch.TxHashes[0] = tx.Hash()
	batch.TxRoot = DeriveCommonTxAdmissionTxRoot(batch.TxHashes)
	batch.AdmissionID = CommonTxAdmissionID(batch)
	// The changed commitments invalidate the helper's signature. RLP round-trip
	// tests encoding ownership; cryptographic validity is covered above.
	ref := CommonTxAdmissionRef{Batch: 0, Item: 0}
	reward := &CommonTxReward{
		TxHash: tx.Hash(), Approver: batch.Miner,
		ApproverReward: big.NewInt(2), Burn: big.NewInt(8),
	}
	block := NewBlockWithHeader(&Header{
		ParentHash: common.HexToHash("0x41"), Number: big.NewInt(4), Difficulty: big.NewInt(1), GasLimit: 21_000,
	}).WithBody(Transactions{tx}, nil)
	block.AttachCommonTxData([]*CommonTxAdmissionBatch{batch}, []CommonTxAdmissionRef{ref}, []*CommonTxReward{reward})
	encoded := block.EncodeToBytes()
	batch.TxHashes[0] = common.HexToHash("0xbeef")
	reward.ApproverReward.SetUint64(99)
	if !bytes.Equal(block.EncodeToBytes(), encoded) {
		t.Fatal("admission attachment retained caller-owned nested storage")
	}
	decoded := DecodeToBlock(encoded)
	if decoded == nil {
		t.Fatal("failed to decode admission-batch block")
	}
	if !bytes.Equal(decoded.EncodeToBytes(), encoded) {
		t.Fatal("block admission data did not round-trip canonically")
	}
	if decoded.Header().CommonTxAdmissionRoot != block.Header().CommonTxAdmissionRoot {
		t.Fatal("decoded block changed admission root")
	}
	batches := decoded.CommonTxAdmissionBatches()
	refs := decoded.CommonTxAdmissionRefs()
	if len(batches) != 1 || len(refs) != 1 || batches[0].AdmissionID != batch.AdmissionID || refs[0] != ref {
		t.Fatalf("decoded admission data = batches %d refs %v", len(batches), refs)
	}
	// Accessors and attachment must own nested slices rather than aliasing caller
	// memory, otherwise a post-hash mutation can change the encoded body.
	batches[0].TxHashes[0] = common.HexToHash("0xdead")
	refs[0].Item = 9
	if !bytes.Equal(decoded.EncodeToBytes(), encoded) {
		t.Fatal("admission accessor exposed mutable block storage")
	}
}

func TestHotstuffProposalRefBindsViewNumber(t *testing.T) {
	block := NewBlockWithHeader(&Header{
		ParentHash: common.HexToHash("0x01"),
		Number:     big.NewInt(1),
		Difficulty: big.NewInt(1),
		GasLimit:   1,
	})
	viewID := common.HexToHash("0x02")
	ref, err := NewHotstuffProposalRef(1, 7, viewID, "leader", block, nil)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeHotstuffProposalRef(ref.EncodeToBytes())
	if err != nil {
		t.Fatal(err)
	}
	if decoded.ViewNumber != 7 {
		t.Fatalf("view number = %d, want 7", decoded.ViewNumber)
	}

	other := *ref
	other.ViewNumber = 8
	if other.ProposalID() == ref.ProposalID() {
		t.Fatal("proposal ID did not bind the FHS view number")
	}

	if _, err := NewHotstuffProposalRef(1, 0, viewID, "leader", block, nil); err == nil {
		t.Fatal("constructor accepted zero FHS view number")
	}
	zero := *ref
	zero.ViewNumber = 0
	if err := zero.Validate(); err == nil {
		t.Fatal("zero FHS view number was accepted")
	}
}

func TestHotstuffProposalRefBindsExtraAndParentQC(t *testing.T) {
	block := NewBlockWithHeader(&Header{
		ParentHash: common.HexToHash("0x11"),
		Number:     big.NewInt(2),
		Difficulty: big.NewInt(1),
		GasLimit:   1,
	})
	base, err := NewHotstuffProposalRefWithProof(1, 9, common.HexToHash("0x12"), "leader", block, nil, []byte("proof-a"), common.HexToHash("0x13"))
	if err != nil {
		t.Fatal(err)
	}
	differentExtra, err := NewHotstuffProposalRefWithProof(1, 9, base.ViewID, "leader", block, nil, []byte("proof-b"), base.ParentQCID)
	if err != nil {
		t.Fatal(err)
	}
	if base.ProposalID() == differentExtra.ProposalID() {
		t.Fatal("proposal ID did not bind application proof")
	}
	differentParent := *base
	differentParent.ParentQCID = common.HexToHash("0x14")
	if base.ProposalID() == differentParent.ProposalID() {
		t.Fatal("proposal ID did not bind semantic parent QC")
	}
}

func TestFHSSignInfoReconstructsExactSignedProposalRef(t *testing.T) {
	block := NewBlockWithHeader(&Header{
		ParentHash: common.HexToHash("0x21"),
		Number:     big.NewInt(3),
		Difficulty: big.NewInt(1),
		GasLimit:   1,
	})
	viewID := common.HexToHash("0x22")
	extra := []byte("candidate-proof")
	parentQCID := common.HexToHash("0x23")
	unsigned := block.EncodeToBytes()
	ref, err := NewHotstuffProposalRefWithProof(1, 11, viewID, "leader", block, unsigned, extra, parentQCID)
	if err != nil {
		t.Fatal(err)
	}
	block.SetFHSSignature([]byte{1}, []byte{0x1f}, viewID, "leader", 11, ref.ExtraHash, ref.ParentQCID)
	decoded := DecodeToBlock(block.EncodeToBytes())
	if decoded == nil {
		t.Fatal("failed to decode FHS signed block")
	}
	si := decoded.SignInfo()
	reconstructedUnsigned := decoded.CopyOrg().EncodeToBytes()
	reconstructed, err := NewHotstuffProposalRefWithCommitments(1, si.ViewNumber, si.ViewID, si.LeaderID, decoded.CopyOrg(), reconstructedUnsigned, si.ExtraHash, si.ParentQCID)
	if err != nil {
		t.Fatal(err)
	}
	if string(reconstructed.EncodeToBytes()) != string(ref.EncodeToBytes()) {
		t.Fatal("sync reconstruction did not reproduce the QC-signed proposal reference")
	}
}
