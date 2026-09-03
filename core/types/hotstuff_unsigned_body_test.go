package types

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
)

var hotstuffProposalRefAllocationSink *HotstuffProposalRef

func makeLargeSignedHotstuffBlockForTest(count int) *Block {
	txs := make(Transactions, count)
	for index := range txs {
		data := bytes.Repeat([]byte{byte(index), byte(index >> 8)}, 64)
		txs[index] = NewTransaction(
			uint64(index), common.BytesToAddress([]byte{byte(index + 1)}), big.NewInt(int64(index+1)),
			100_000, big.NewInt(1), data,
		)
	}
	uncles := make([]*Header, 32)
	for index := range uncles {
		uncles[index] = &Header{
			ParentHash: common.BigToHash(big.NewInt(int64(index + 1))),
			Difficulty: big.NewInt(1),
			Number:     big.NewInt(int64(index + 1)),
			Extra:      bytes.Repeat([]byte{byte(index)}, 256),
			KeyInfo:    bytes.Repeat([]byte{byte(index + 1)}, 256),
		}
	}
	block := NewBlockWithHeader(&Header{
		ParentHash:  common.HexToHash("0x101"),
		Root:        common.HexToHash("0x102"),
		TxHash:      common.HexToHash("0x103"),
		ReceiptHash: common.HexToHash("0x104"),
		Difficulty:  big.NewInt(1),
		Number:      big.NewInt(9),
		GasLimit:    1_000_000_000,
		GasUsed:     uint64(count) * 21_000,
		Time:        12345,
		BlockType:   FastTx_Block,
		KeyHash:     common.HexToHash("0x105"),
	}).WithBody(txs, uncles)

	// Populate a large sidecar graph directly. Its validity is irrelevant to
	// this encoding test; nested ownership makes the legacy CopyOrg cost visible.
	batchCount := (count + 7) / 8
	block.commonTxAdmissionBatches = make([]*CommonTxAdmissionBatch, batchCount)
	for batchIndex := range block.commonTxAdmissionBatches {
		hashes := make([]common.Hash, 8)
		for index := range hashes {
			hashes[index] = common.BigToHash(new(big.Int).SetUint64(uint64(batchIndex*8 + index + 1)))
		}
		block.commonTxAdmissionBatches[batchIndex] = &CommonTxAdmissionBatch{
			ChainID: big.NewInt(10101919), TxHashes: hashes,
			Signature: bytes.Repeat([]byte{byte(batchIndex)}, 96),
		}
	}
	block.commonTxAdmissionRefs = make([]CommonTxAdmissionRef, count)
	block.commonTxRewards = make([]*CommonTxReward, count)
	for index := 0; index < count; index++ {
		block.commonTxAdmissionRefs[index] = CommonTxAdmissionRef{Batch: uint32(index / 8), Item: uint16(index % 8)}
		block.commonTxRewards[index] = &CommonTxReward{
			TxHash:         common.BigToHash(new(big.Int).SetUint64(uint64(index + 1))),
			ApproverReward: big.NewInt(int64(index + 1)),
			Burn:           big.NewInt(int64(index + 2)),
		}
	}
	return block
}

func legacyUnsignedHotstuffProposalRefForTest(block *Block, viewID common.Hash) (*HotstuffProposalRef, error) {
	unsigned := block.CopyOrg()
	encoded := unsigned.EncodeToBytes()
	return NewHotstuffProposalRefWithCommitments(
		10101919, 77, viewID, "leader", unsigned, encoded,
		HotstuffProposalExtraHash(nil), common.HexToHash("0x106"),
	)
}

func TestUnsignedHotstuffProposalRefMatchesLegacyBytes(t *testing.T) {
	block := makeLargeSignedHotstuffBlockForTest(512)
	signature := bytes.Repeat([]byte{0x41}, 96)
	mask := []byte{0x1f, 0x03}
	viewID := common.HexToHash("0x107")
	block.SetFHSSignature(signature, mask, viewID, "leader", 77, HotstuffProposalExtraHash(nil), common.HexToHash("0x106"))
	signedEncoding := append([]byte(nil), block.EncodeToBytes()...)

	want, err := legacyUnsignedHotstuffProposalRefForTest(block, viewID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := NewHotstuffProposalRefFromUnsignedBlockWithCommitments(
		10101919, 77, viewID, "leader", block,
		HotstuffProposalExtraHash(nil), common.HexToHash("0x106"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.EncodeToBytes(), want.EncodeToBytes()) {
		t.Fatalf("streamed proposal ref changed signed bytes:\n got  %x\n want %x", got.EncodeToBytes(), want.EncodeToBytes())
	}
	if got.BodyHash != want.BodyHash || got.BodySize != want.BodySize {
		t.Fatalf("streamed body commitment = %s/%d, want %s/%d", got.BodyHash, got.BodySize, want.BodyHash, want.BodySize)
	}
	if after := block.EncodeToBytes(); !bytes.Equal(after, signedEncoding) {
		t.Fatal("unsigned commitment calculation mutated the signed block")
	}

	// Signature setters and the streamed result must not retain caller-owned
	// byte slices even though the body itself is synchronously shared while read.
	signature[0] ^= 0xff
	mask[0] ^= 0xff
	if block.SignInfo().Signature[0] != 0x41 || block.SignInfo().Exceptions[0] != 0x1f {
		t.Fatal("block signature metadata aliases caller-owned input")
	}
}

func TestUnsignedHotstuffProposalRefAvoidsLargeBodyCopies(t *testing.T) {
	block := makeLargeSignedHotstuffBlockForTest(512)
	viewID := common.HexToHash("0x108")
	block.SetFHSSignature([]byte{1}, []byte{0x1f}, viewID, "leader", 77, HotstuffProposalExtraHash(nil), common.HexToHash("0x106"))

	// Warm both encoders and the shared RLP buffer pool before counting.
	_, _ = legacyUnsignedHotstuffProposalRefForTest(block, viewID)
	_, _ = NewHotstuffProposalRefFromUnsignedBlockWithCommitments(
		10101919, 77, viewID, "leader", block,
		HotstuffProposalExtraHash(nil), common.HexToHash("0x106"),
	)
	legacyAllocs := testing.AllocsPerRun(3, func() {
		hotstuffProposalRefAllocationSink, _ = legacyUnsignedHotstuffProposalRefForTest(block, viewID)
	})
	sharedAllocs := testing.AllocsPerRun(3, func() {
		hotstuffProposalRefAllocationSink, _ = NewHotstuffProposalRefFromUnsignedBlockWithCommitments(
			10101919, 77, viewID, "leader", block,
			HotstuffProposalExtraHash(nil), common.HexToHash("0x106"),
		)
	})
	if sharedAllocs >= legacyAllocs {
		t.Fatalf("shared unsigned encoding allocations = %.0f, want below legacy %.0f", sharedAllocs, legacyAllocs)
	}
	// CopyOrg allocates at least one nested reward copy per transaction. Requiring
	// this much separation ensures the optimized path did not quietly retain the
	// large sidecar copy while allowing harmless encoder allocation variance.
	if saved := legacyAllocs - sharedAllocs; saved < 512 {
		t.Fatalf("shared unsigned encoding saved only %.0f allocations, want at least 512", saved)
	}
	t.Logf("large-body allocations: legacy=%.0f shared-stream=%.0f", legacyAllocs, sharedAllocs)
}
