package types

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
)

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
