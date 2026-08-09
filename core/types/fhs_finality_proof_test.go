package types

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/rlp"
)

func newFHSFinalityProofTestBlock() *Block {
	block := NewBlockWithHeader(&Header{
		ParentHash: common.HexToHash("0x01"),
		Number:     big.NewInt(1),
		Difficulty: big.NewInt(1),
		GasLimit:   1,
	})
	block.SetFHSSignature([]byte{1, 2, 3}, []byte{0x1f}, common.HexToHash("0x02"), "leader", 7, common.HexToHash("0x03"), common.HexToHash("0x04"))
	return block
}

func TestFHSFinalityProofIsMetadataAndRoundTrips(t *testing.T) {
	block := newFHSFinalityProofTestBlock()
	hashBefore := block.Hash()
	unsignedBefore := block.CopyOrg().EncodeToBytes()
	sizeBefore := block.Size()

	input := []byte{9, 8, 7, 6}
	if err := block.SetFHSFinalityProof(input); err != nil {
		t.Fatal(err)
	}
	input[0] = 0
	if got := block.FHSFinalityProof(); !bytes.Equal(got, []byte{9, 8, 7, 6}) {
		t.Fatalf("proof was not defensively copied: %x", got)
	}
	if got := block.Hash(); got != hashBefore {
		t.Fatalf("finality metadata changed block hash: have %s want %s", got, hashBefore)
	}
	if got := block.CopyOrg().EncodeToBytes(); !bytes.Equal(got, unsignedBefore) {
		t.Fatal("finality metadata changed unsigned proposal bytes")
	}
	if block.Size() <= sizeBefore {
		t.Fatalf("block size did not include finality proof: before=%v after=%v", sizeBefore, block.Size())
	}

	encoded, err := rlp.EncodeToBytes(block)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Block
	if err := rlp.DecodeBytes(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if got := decoded.FHSFinalityProof(); !bytes.Equal(got, []byte{9, 8, 7, 6}) {
		t.Fatalf("proof did not survive RLP round trip: %x", got)
	}

	headerCopy := CopyHeader(decoded.Header())
	headerCopy.SignInfo.FHSFinalityProof[0] ^= 0xff
	if bytes.Equal(headerCopy.SignInfo.FHSFinalityProof, decoded.SignInfo().FHSFinalityProof) {
		t.Fatal("CopyHeader aliased FHS finality proof")
	}

	decoded.SetSignature([]byte{4}, []byte{1}, common.HexToHash("0x05"), "next", 8)
	if len(decoded.FHSFinalityProof()) != 0 {
		t.Fatal("assigning a new one-chain QC retained stale finality metadata")
	}
}

func TestFHSFinalityProofSizeBound(t *testing.T) {
	block := newFHSFinalityProofTestBlock()
	oversized := make([]byte, MaxFHSFinalityProofSize+1)
	if err := block.SetFHSFinalityProof(oversized); err == nil {
		t.Fatal("oversized FHS finality proof was accepted")
	}
	header := block.Header()
	header.SignInfo.FHSFinalityProof = oversized
	if err := header.SanityCheck(); err == nil {
		t.Fatal("header sanity check accepted oversized FHS finality proof")
	}
}
