package reconfig

import (
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

func TestFHS2ChainCommitTarget(t *testing.T) {
	b1Hash := common.HexToHash("0x101")
	b2Hash := common.HexToHash("0x102")
	b3Hash := common.HexToHash("0x103")
	canonicalHash := common.HexToHash("0x100")

	b1 := &fhsCertifiedProposal{
		ref: &types.HotstuffProposalRef{BlockHash: b1Hash, ParentHash: canonicalHash},
		qc:  &hotstuff.SignedState{Number: 11},
	}
	b2 := &fhsCertifiedProposal{
		ref: &types.HotstuffProposalRef{BlockHash: b2Hash, ParentHash: b1Hash},
		qc:  &hotstuff.SignedState{Number: 12},
	}
	certified := map[common.Hash]*fhsCertifiedProposal{
		b1Hash: b1,
		b2Hash: b2,
	}

	proposal := &types.HotstuffProposalRef{BlockHash: b3Hash, ParentHash: b2Hash}
	if target := fhs2ChainCommitTarget(certified, proposal); target != b1 {
		t.Fatalf("commit target = %p, want first block %p", target, b1)
	}

	b2.qc.Number = 13
	if target := fhs2ChainCommitTarget(certified, proposal); target != nil {
		t.Fatalf("non-consecutive certified views produced commit target %p", target)
	}

	b2.qc.Number = 12
	proposal.ParentHash = common.HexToHash("0xffff")
	if target := fhs2ChainCommitTarget(certified, proposal); target != nil {
		t.Fatalf("non-extending proposal produced commit target %p", target)
	}
}

func TestValidateViewUsesIndependentFHSViewNumber(t *testing.T) {
	current := bftview.View{
		TxNumber:   20,
		TxHash:     common.HexToHash("0x20"),
		KeyNumber:  1,
		ViewNumber: 37,
	}
	wire := current

	_, number, err := validateViewAgainstSnapshot(wire.EncodeConsensusToBytes(), current, true)
	if err != nil {
		t.Fatal(err)
	}
	if number != 38 {
		t.Fatalf("next FHS view = %d, want 38", number)
	}

	wire.ViewNumber = 38
	if _, _, err := validateViewAgainstSnapshot(wire.EncodeConsensusToBytes(), current, true); err != hotstuff.ErrFutureState {
		t.Fatalf("future FHS view error = %v, want %v", err, hotstuff.ErrFutureState)
	}
}

func TestFHSProposalMustCarryHighestParentQC(t *testing.T) {
	b1Hash := common.HexToHash("0x201")
	b2Hash := common.HexToHash("0x202")
	parentRef := &types.HotstuffProposalRef{
		Version:    types.HotstuffProposalRefVersion,
		ChainID:    1,
		Number:     2,
		ViewNumber: 12,
		ViewID:     common.HexToHash("0x12"),
		LeaderID:   "leader-2",
		BlockHash:  b2Hash,
		ParentHash: b1Hash,
		BodyHash:   common.HexToHash("0x99"),
		BodySize:   1,
	}
	parentQC := &hotstuff.SignedState{
		State:    parentRef.EncodeToBytes(),
		Sign:     []byte("qc"),
		Mask:     []byte{0x07},
		ViewID:   parentRef.ViewID,
		LeaderID: parentRef.LeaderID,
		Number:   parentRef.ViewNumber,
	}
	s := &Service{
		currentView: bftview.View{TxNumber: 2, TxHash: b2Hash, ViewNumber: 12},
		fhsHighest: &fhsCertifiedProposal{
			ref: parentRef,
			qc:  parentQC,
		},
	}
	proposal := &types.HotstuffProposalRef{
		Number:     3,
		ViewNumber: 13,
		BlockHash:  common.HexToHash("0x203"),
		ParentHash: b2Hash,
	}

	if err := s.validateFHSProposalParent(proposal, hotstuff.CloneSignedState(parentQC)); err != nil {
		t.Fatalf("highest parent QC rejected: %v", err)
	}
	stale := hotstuff.CloneSignedState(parentQC)
	stale.Number--
	if err := s.validateFHSProposalParent(proposal, stale); err == nil {
		t.Fatal("stale parent QC was accepted")
	}
	proposal.ParentHash = b1Hash
	if err := s.validateFHSProposalParent(proposal, parentQC); err == nil {
		t.Fatal("proposal that did not extend highest certified block was accepted")
	}
}
