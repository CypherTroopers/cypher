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
