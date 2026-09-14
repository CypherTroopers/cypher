package reconfig

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

func TestFHSUncommittedKeyBlockSuppressesCompetingTransition(t *testing.T) {
	keyBlock := types.NewBlockWithHeader(&types.Header{
		Number:     big.NewInt(8),
		Difficulty: big.NewInt(1),
		BlockType:  types.Key_Block,
	})
	txBlock := types.NewBlockWithHeader(&types.Header{
		Number:     big.NewInt(9),
		Difficulty: big.NewInt(1),
		BlockType:  types.FastTx_Block,
	})
	certified := map[common.Hash]*fhsCertifiedProposal{
		keyBlock.Hash(): {verified: &core.VerifiedProposal{Block: keyBlock}},
		txBlock.Hash():  {verified: &core.VerifiedProposal{Block: txBlock}},
	}

	if !fhsHasUncommittedKeyBlock(certified, func(*types.Block) bool { return false }) {
		t.Fatal("uncommitted certified key block was not detected")
	}
	if fhsHasConflictingUncommittedKeyBlock(certified, keyBlock, func(*types.Block) bool { return false }) {
		t.Fatal("reprocessing the same certified key proposal was treated as a conflict")
	}
	competingKeyBlock := types.NewBlockWithHeader(&types.Header{
		Number:     big.NewInt(10),
		Difficulty: big.NewInt(1),
		BlockType:  types.Key_Block,
	})
	if !fhsHasConflictingUncommittedKeyBlock(certified, competingKeyBlock, func(*types.Block) bool { return false }) {
		t.Fatal("competing key proposal was not rejected while a certified transition was uncommitted")
	}
	if fhsHasUncommittedKeyBlock(certified, func(block *types.Block) bool { return block.Hash() == keyBlock.Hash() }) {
		t.Fatal("already committed key block still suppressed the next transition")
	}
	delete(certified, keyBlock.Hash())
	if fhsHasUncommittedKeyBlock(certified, func(*types.Block) bool { return false }) {
		t.Fatal("ordinary certified transaction block suppressed a key transition")
	}
}

func TestFHSFinalityBlockCompletesEpochHandoffWithoutEmptyLoop(t *testing.T) {
	oldKeyHash := common.HexToHash("0x701")
	newKeyHash := common.HexToHash("0x702")
	emptyOldEpoch := types.NewBlockWithHeader(&types.Header{
		Number:     big.NewInt(8),
		Difficulty: big.NewInt(1),
		BlockType:  types.FastTx_Block,
		KeyHash:    oldKeyHash,
	})
	certified := map[common.Hash]*fhsCertifiedProposal{
		emptyOldEpoch.Hash(): {verified: &core.VerifiedProposal{Block: emptyOldEpoch}},
	}

	if !fhsNeedsFinalityBlock(certified, newKeyHash, func(*types.Block) bool { return false }) {
		t.Fatal("old-epoch empty certified frontier did not request a handoff child")
	}
	if fhsNeedsFinalityBlock(certified, oldKeyHash, func(*types.Block) bool { return false }) {
		t.Fatal("current-epoch empty frontier requested an unbounded empty child")
	}
	if fhsNeedsFinalityBlock(certified, newKeyHash, func(block *types.Block) bool {
		return block.Hash() == emptyOldEpoch.Hash()
	}) {
		t.Fatal("canonical frontier requested another finality block")
	}

	keyBlock := types.NewBlockWithHeader(&types.Header{
		Number:     big.NewInt(9),
		Difficulty: big.NewInt(1),
		BlockType:  types.Key_Block,
		KeyHash:    newKeyHash,
	})
	certified = map[common.Hash]*fhsCertifiedProposal{
		keyBlock.Hash(): {verified: &core.VerifiedProposal{Block: keyBlock}},
	}
	if !fhsNeedsFinalityBlock(certified, newKeyHash, func(*types.Block) bool { return false }) {
		t.Fatal("uncommitted key block did not request a finality child")
	}
}

func TestFHSKeyBlockCarrierUsesCertifiedParentNumber(t *testing.T) {
	canonical := uint64(2)
	certifiedParent := types.NewBlockWithHeader(&types.Header{
		Number:     big.NewInt(3),
		Difficulty: big.NewInt(1),
		BlockType:  types.FastTx_Block,
	})
	verified := &core.VerifiedProposal{Block: certifiedParent}

	if got := fhsProposalParentNumber(canonical, verified); got != 3 {
		t.Fatalf("proposal parent = %d, want certified height 3", got)
	}
	if got := fhsProposalParentNumber(canonical, nil); got != canonical {
		t.Fatalf("proposal parent without certified frontier = %d, want canonical %d", got, canonical)
	}

	keyBlock := types.NewKeyBlock(&types.KeyBlockHeader{
		Number:     big.NewInt(2),
		Difficulty: big.NewInt(1),
		T_Number:   3,
	})
	if err := verifyKeyBlockCarrierParent(keyBlock, 3); err != nil {
		t.Fatalf("valid pipelined key carrier parent rejected: %v", err)
	}
	if err := verifyKeyBlockCarrierParent(keyBlock, canonical); err == nil {
		t.Fatal("canonical head was incorrectly accepted instead of certified carrier parent")
	}
}

func TestFHS2ChainCommitTarget(t *testing.T) {
	b1Hash := common.HexToHash("0x101")
	b2Hash := common.HexToHash("0x102")
	canonicalHash := common.HexToHash("0x100")

	b1 := &fhsCertifiedProposal{
		ref: &types.HotstuffProposalRef{Number: 1, BlockHash: b1Hash, ParentHash: canonicalHash},
		qc:  &hotstuff.SignedState{Number: 11},
	}
	b2 := &fhsCertifiedProposal{
		ref: &types.HotstuffProposalRef{Number: 2, BlockHash: b2Hash, ParentHash: b1Hash},
		qc:  &hotstuff.SignedState{Number: 12},
	}
	b1.qc.State, b1.qc.ViewID, b1.qc.LeaderID = []byte("certified parent"), common.HexToHash("0x11"), "leader"
	parentID, err := hotstuff.SignedStateID(b1.qc)
	if err != nil {
		t.Fatal(err)
	}
	b2.ref.ParentQCID = parentID.Hash()
	certified := map[common.Hash]*fhsCertifiedProposal{
		b1Hash: b1,
		b2Hash: b2,
	}

	if target := fhs2ChainCommitTarget(certified, b2); target != b1 {
		t.Fatalf("commit target = %p, want first block %p", target, b1)
	}

	b2.qc.Number = 14
	if target := fhs2ChainCommitTarget(certified, b2); target != nil {
		t.Fatalf("nonconsecutive certified views produced commit target %p", target)
	}
	b2.qc.Number = 11
	if target := fhs2ChainCommitTarget(certified, b2); target != nil {
		t.Fatalf("non-increasing certified views produced commit target %p", target)
	}

	b2.qc.Number = 12
	b2.ref.ParentHash = common.HexToHash("0xffff")
	if target := fhs2ChainCommitTarget(certified, b2); target != nil {
		t.Fatalf("non-extending certified child produced commit target %p", target)
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

func TestNormalizeFHSEpochViewUsesCommonChildQC(t *testing.T) {
	keyBlock := types.NewKeyBlock(&types.KeyBlockHeader{
		Difficulty:    big.NewInt(1),
		Number:        big.NewInt(3),
		Time:          3,
		CommitteeHash: common.HexToHash("0x303"),
	})
	ref := &types.HotstuffProposalRef{
		Version:    types.HotstuffProposalRefVersion,
		ChainID:    101,
		Number:     8,
		ViewNumber: 17,
		ViewID:     common.HexToHash("0x17"),
		LeaderID:   "leader-17",
		BlockHash:  common.HexToHash("0x808"),
		ParentHash: common.HexToHash("0x707"),
		BodyHash:   common.HexToHash("0x818"),
		BodySize:   1,
		ExtraHash:  types.HotstuffProposalExtraHash(nil),
	}
	qc := &hotstuff.SignedState{
		State:    ref.EncodeToBytes(),
		Number:   ref.ViewNumber,
		ViewID:   ref.ViewID,
		LeaderID: ref.LeaderID,
	}
	service := &Service{
		chainConfig: &params.ChainConfig{ChainID: big.NewInt(101), FairHotstuff: true},
		currentView: bftview.View{TxNumber: 7, ViewNumber: 29}, // local old-epoch TC was higher
	}
	if err := service.normalizeFHSEpochView(qc, keyBlock); err != nil {
		t.Fatal(err)
	}
	view := service.GetCurrentView()
	if view.ViewNumber != qc.Number || view.TxNumber != ref.Number || view.TxHash != ref.BlockHash {
		t.Fatalf("epoch view did not normalize to common QC: %+v", view)
	}
	if view.KeyNumber != keyBlock.NumberU64() || view.KeyHash != keyBlock.Hash() || view.CommitteeHash != keyBlock.CommitteeHash() {
		t.Fatalf("epoch key context mismatch: %+v", view)
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
		ExtraHash:  types.HotstuffProposalExtraHash(nil),
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
