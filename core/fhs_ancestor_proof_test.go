package core

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
	lru "github.com/hashicorp/golang-lru"
)

func makeFHSAncestorProofChain(t *testing.T, validator *BlockValidator, secrets []bls.SecretKey, public []*bls.PublicKey, keyHash common.Hash, views []uint64) ([]*types.Block, []*hotstuff.SignedState) {
	t.Helper()
	genesis := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(0), Difficulty: big.NewInt(1), KeyHash: keyHash})
	validator.bc.currentBlock.Store(genesis)
	parentHash := genesis.Hash()
	parentQCID := common.Hash{}
	blocks := make([]*types.Block, len(views))
	qcs := make([]*hotstuff.SignedState, len(views))
	for index, view := range views {
		block := types.NewBlockWithHeader(&types.Header{
			ParentHash: parentHash, Number: new(big.Int).SetUint64(uint64(index + 1)),
			Difficulty: big.NewInt(1), BlockType: types.FastTx_Block, KeyHash: keyHash,
		})
		ref, qc := makeFHSCommitProofQC(t, block, view, fmt.Sprintf("leader-%d", view), parentQCID, secrets, public)
		block.SetFHSSignature(qc.Sign, qc.Mask, qc.ViewID, qc.LeaderID, qc.Number, ref.ExtraHash, ref.ParentQCID)
		id, err := hotstuff.SignedStateID(qc)
		if err != nil {
			t.Fatal(err)
		}
		blocks[index], qcs[index] = block, qc
		parentHash, parentQCID = block.Hash(), id.Hash()
	}
	return blocks, qcs
}

func TestFHSAncestorProofCommitsOnlyAfterConsecutiveTerminalViews(t *testing.T) {
	validator, secrets, public, keyHash := makeFHSCommitProofValidator(t)
	blocks, qcs := makeFHSAncestorProofChain(t, validator, secrets, public, keyHash, []uint64{1, 4, 5})
	proof := &FHSCommitProof{QCs: qcs[1:]}
	if err := validator.bc.VerifyFHSCommitProof(blocks[0], proof); err != nil {
		t.Fatalf("ancestor A(v1) was not finalized by B(v4)->C(v5): %v", err)
	}
	if err := validator.VerifyFHS2ChainCommitProof(blocks[1], qcs[2]); err != nil {
		t.Fatalf("terminal parent B was not finalized: %v", err)
	}
	for _, test := range []struct {
		name  string
		proof *FHSCommitProof
	}{
		{"only skipped edge", &FHSCommitProof{QCs: qcs[1:2]}},
		{"omitted intermediate", &FHSCommitProof{QCs: qcs[2:]}},
		{"reordered", &FHSCommitProof{QCs: []*hotstuff.SignedState{qcs[2], qcs[1]}}},
		{"nil entry", &FHSCommitProof{QCs: []*hotstuff.SignedState{qcs[1], nil}}},
		{"empty", &FHSCommitProof{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validator.bc.VerifyFHSCommitProof(blocks[0], test.proof); err == nil {
				t.Fatal("incomplete or disconnected finality path was accepted")
			}
		})
	}
	for index := range proof.QCs {
		tampered := CloneFHSCommitProof(proof)
		tampered.QCs[index].Sign[0] ^= 0xff
		if err := validator.bc.VerifyFHSCommitProof(blocks[0], tampered); err == nil {
			t.Fatalf("tampered signature at proof index %d was accepted", index)
		}
	}
	_, wrongParent := makeFHSCommitProofQC(t, blocks[2], 5, "leader-5", common.HexToHash("0xbad"), secrets, public)
	if err := validator.VerifyFHSCommitProof(blocks[0], &FHSCommitProof{QCs: []*hotstuff.SignedState{qcs[1], wrongParent}}); err == nil {
		t.Fatal("terminal QC with a valid signature but wrong ParentQCID was accepted")
	}
}

func TestFHSAncestorProofMetadataPreservesFullPathAtCanonicalBoundary(t *testing.T) {
	validator, secrets, public, keyHash := makeFHSCommitProofValidator(t)
	blocks, qcs := makeFHSAncestorProofChain(t, validator, secrets, public, keyHash, []uint64{1, 4, 5})
	proof := &FHSCommitProof{QCs: qcs[1:]}
	encoded, err := EncodeFHSCommitProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := blocks[0].SetFHSFinalityProof(encoded); err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeFHSFinalityProof(blocks[0]); err == nil {
		t.Fatal("single-child decoder silently truncated an ancestor proof")
	}
	// Exercise the real proof-aware canonical DB publication with actual BLS
	// QCs. Preseed its height mapping to avoid unrelated HeaderChain caches.
	rawdb.WriteCanonicalHash(validator.bc.db, blocks[0].Hash(), blocks[0].NumberU64())
	if err := validator.bc.writeHeadBlock(blocks[0]); err != nil {
		t.Fatalf("publish ancestor-finalized block: %v", err)
	}
	stored := rawdb.ReadBlock(validator.bc.db, blocks[0].Hash(), blocks[0].NumberU64())
	recovered, present, err := DecodeFHSCommitProof(stored)
	if err != nil || !present || !fhsCommitProofSemanticEqual(proof, recovered) {
		t.Fatalf("canonical DB lost the complete finality path: proof=%v present=%v err=%v", recovered, present, err)
	}
	if err := validator.bc.VerifyFHSCommitProof(stored, recovered); err != nil {
		t.Fatalf("recovered ancestor proof does not verify: %v", err)
	}
	// A different, higher-view child branch can also prove the same target.
	// Its descendants must not replace or invalidate the committed target.
	parentID, err := hotstuff.SignedStateID(qcs[0])
	if err != nil {
		t.Fatal(err)
	}
	alternateChild := types.NewBlockWithHeader(&types.Header{
		ParentHash: blocks[0].Hash(), Number: big.NewInt(2), Difficulty: big.NewInt(1), KeyHash: keyHash, Time: 1,
	})
	_, alternateQC := makeFHSCommitProofQC(t, alternateChild, 7, "leader-7", parentID.Hash(), secrets, public)
	alternateID, err := hotstuff.SignedStateID(alternateQC)
	if err != nil {
		t.Fatal(err)
	}
	alternateTip := types.NewBlockWithHeader(&types.Header{
		ParentHash: alternateChild.Hash(), Number: big.NewInt(3), Difficulty: big.NewInt(1), KeyHash: keyHash, Time: 2,
	})
	_, alternateTipQC := makeFHSCommitProofQC(t, alternateTip, 8, "leader-8", alternateID.Hash(), secrets, public)
	targetRef, _, err := validator.ReconstructFHSQC(blocks[0])
	if err != nil {
		t.Fatal(err)
	}
	validator.bc.blockCache, _ = lru.New(4)
	validator.bc.stateCache = state.NewDatabase(validator.bc.db)
	verified := &VerifiedProposal{
		ProposalID: targetRef.ProposalID(), ViewNumber: qcs[0].Number, ViewID: qcs[0].ViewID, LeaderID: qcs[0].LeaderID,
		Block: blocks[0].WithSeal(blocks[0].Header()), ParentHash: blocks[0].ParentHash(), ParentNumber: 0,
	}
	status, err := validator.bc.CommitFHSVerifiedProposalWithProof(verified, &FHSCommitProof{QCs: []*hotstuff.SignedState{alternateQC, alternateTipQC}}, false)
	if err != nil || status != CanonStatTy {
		t.Fatalf("valid sibling descendant proof was mistaken for conflicting target finality: status=%v err=%v", status, err)
	}
	retained, present, err := DecodeFHSCommitProof(verified.Block)
	if err != nil || !present || !fhsCommitProofSemanticEqual(retained, recovered) {
		t.Fatal("equivalent finality replaced the canonical target's stored proof")
	}
	// Finality also belongs to the payload when that same block obtains a
	// different QC in another view. Preserve the original QC/proof together.
	recertified := blocks[0].CopyOrg()
	recertifiedRef, recertifiedQC := makeFHSCommitProofQC(t, recertified, 2, "leader-2", common.Hash{}, secrets, public)
	recertified.SetFHSSignature(recertifiedQC.Sign, recertifiedQC.Mask, recertifiedQC.ViewID, recertifiedQC.LeaderID,
		recertifiedQC.Number, recertifiedRef.ExtraHash, recertifiedRef.ParentQCID)
	recertifiedID, err := hotstuff.SignedStateID(recertifiedQC)
	if err != nil {
		t.Fatal(err)
	}
	_, recertifiedChildQC := makeFHSCommitProofQC(t, alternateChild, 7, "leader-7", recertifiedID.Hash(), secrets, public)
	recertifiedChildID, err := hotstuff.SignedStateID(recertifiedChildQC)
	if err != nil {
		t.Fatal(err)
	}
	_, recertifiedTipQC := makeFHSCommitProofQC(t, alternateTip, 8, "leader-8", recertifiedChildID.Hash(), secrets, public)
	recertifiedVerified := *verified
	recertifiedVerified.Block = recertified
	recertifiedVerified.ProposalID, recertifiedVerified.ViewNumber = recertifiedRef.ProposalID(), recertifiedRef.ViewNumber
	recertifiedVerified.ViewID, recertifiedVerified.LeaderID = recertifiedRef.ViewID, recertifiedRef.LeaderID
	status, err = validator.bc.CommitFHSVerifiedProposalWithProof(&recertifiedVerified,
		&FHSCommitProof{QCs: []*hotstuff.SignedState{recertifiedChildQC, recertifiedTipQC}}, false)
	if err != nil || status != CanonStatTy {
		t.Fatalf("valid re-certification of canonical payload rejected: status=%v err=%v", status, err)
	}
	_, retainedQC, err := validator.ReconstructFHSQC(recertifiedVerified.Block)
	if err != nil || !hotstuff.SignedStateSemanticEqual(retainedQC, qcs[0]) {
		t.Fatalf("canonical SignInfo was replaced or mismatched its retained proof: %v", err)
	}
	if count, err := validator.bc.insertFHSFinalizedChain(types.Blocks{recertified}, true, true); err != nil || count != 1 {
		t.Fatalf("sync rejected a different valid QC for its canonical prefix: count=%d err=%v", count, err)
	}
	// Full sync must normalize its service epoch to the terminal view (5),
	// matching live commit, rather than the first descendant's view (4).
	var syncView uint64
	var syncOwnQC *hotstuff.SignedState
	validator.bc.SetFHSFinalizedSyncLifecycle(
		func(*types.Block, *hotstuff.SignedState) (bool, error) { return true, nil },
		func() {},
		func(_ *types.Block, ownQC *hotstuff.SignedState, terminalQC *hotstuff.SignedState) error {
			syncView = terminalQC.Number
			syncOwnQC = ownQC
			return nil
		},
		func(*types.Block, FHSFinalizedSyncKeyCommitOutcome) {},
	)
	status, err = validator.bc.commitFHSSyncVerifiedProposalWithProof(verified, proof)
	if err != nil || status != CanonStatTy || syncView != qcs[len(qcs)-1].Number {
		t.Fatalf("ancestor sync lifecycle did not receive terminal view: status=%v view=%d err=%v", status, syncView, err)
	}
	recertifiedVerified.Block = recertified
	status, err = validator.bc.commitFHSSyncVerifiedProposalWithProof(&recertifiedVerified,
		&FHSCommitProof{QCs: []*hotstuff.SignedState{recertifiedChildQC, recertifiedTipQC}})
	if err != nil || status != CanonStatTy || !hotstuff.SignedStateSemanticEqual(syncOwnQC, qcs[0]) {
		t.Fatalf("re-certification sync lifecycle did not receive canonical own QC: status=%v own=%v err=%v", status, syncOwnQC, err)
	}
	// The downloader must reject a corrupt terminal certificate, even though
	// the first child is valid and has a genuine quorum signature.
	tampered := CloneFHSCommitProof(proof)
	tampered.QCs[1].Sign[0] ^= 0xff
	badBytes, err := EncodeFHSCommitProof(tampered)
	if err != nil {
		t.Fatal(err)
	}
	bad := blocks[0].WithSeal(blocks[0].Header())
	if err := bad.SetFHSFinalityProof(badBytes); err != nil {
		t.Fatal(err)
	}
	if committed, err := validator.bc.commitFHSSyncProposalFromEmbeddedProof(&VerifiedProposal{Block: bad}); err == nil || committed {
		t.Fatal("embedded sync proof bypassed the corrupt terminal QC")
	}
}

func TestFHSAncestorProofBoundAndVersion(t *testing.T) {
	validator, secrets, public, keyHash := makeFHSCommitProofValidator(t)
	views := make([]uint64, MaxFHSCommitProofQCs+1)
	for index := range views {
		views[index] = uint64(index*3 + 1)
	}
	views[len(views)-1] = views[len(views)-2] + 1
	blocks, qcs := makeFHSAncestorProofChain(t, validator, secrets, public, keyHash, views)
	proof := &FHSCommitProof{QCs: qcs[1:]}
	encoded, err := EncodeFHSCommitProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d authenticated descendant QCs encode to %d bytes (reserve %d)", len(proof.QCs), len(encoded), types.MaxFHSFinalityProofSize)
	if len(encoded) <= 64*1024 {
		t.Fatal("fixture did not exercise a proof larger than the previous 64 KiB reserve")
	}
	if err := validator.VerifyFHSCommitProof(blocks[0], proof); err != nil {
		t.Fatalf("maximum supported certified ancestry rejected: %v", err)
	}
	tooLong := CloneFHSCommitProof(proof)
	tooLong.QCs = append(tooLong.QCs, qcs[len(qcs)-1])
	if _, err := EncodeFHSCommitProof(tooLong); err == nil {
		t.Fatal("oversized QC count encoded")
	}
	legacy, err := rlp.EncodeToBytes(struct {
		Version uint32
		ChildQC []byte
	}{Version: 1, ChildQC: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	if err := blocks[0].SetFHSFinalityProof(legacy); err != nil {
		t.Fatal(err)
	}
	if _, _, err := DecodeFHSCommitProof(blocks[0]); err == nil {
		t.Fatal("legacy direct-child metadata was accepted by the new-genesis format")
	}
}

func TestFHSKeyActivationRetainsOnlyProvenCertifiedDescendants(t *testing.T) {
	validator, secrets, public, oldKeyHash := makeFHSCommitProofValidator(t)
	committee := bftview.LoadMember(0, oldKeyHash, false)
	newKey := types.NewKeyBlock(&types.KeyBlockHeader{
		ParentHash: oldKeyHash, Number: big.NewInt(1), Difficulty: big.NewInt(1),
		T_Number: 0, Time: 2, CommitteeHash: committee.RlpHash(),
	})
	carrier := types.NewBlockWithHeader(&types.Header{
		ParentHash: common.HexToHash("0xc001"), Number: big.NewInt(1), Difficulty: big.NewInt(1),
		BlockType: types.Key_Block, KeyHash: oldKeyHash,
	})
	carrier.SetKeyblock(newKey)
	carrierRef, carrierQC := makeFHSCommitProofQC(t, carrier, 1, "leader-1", common.Hash{}, secrets, public)
	carrier.SetFHSSignature(carrierQC.Sign, carrierQC.Mask, carrierQC.ViewID, carrierQC.LeaderID, carrierQC.Number, carrierRef.ExtraHash, carrierRef.ParentQCID)
	parent, parentQC := carrier, carrierQC
	var descendants []*types.Block
	var qcs []*hotstuff.SignedState
	for _, view := range []uint64{4, 5, 6} {
		parentID, err := hotstuff.SignedStateID(parentQC)
		if err != nil {
			t.Fatal(err)
		}
		block := types.NewBlockWithHeader(&types.Header{
			ParentHash: parent.Hash(), Number: new(big.Int).SetUint64(parent.NumberU64() + 1),
			Difficulty: big.NewInt(1), KeyHash: oldKeyHash,
		})
		ref, qc := makeFHSCommitProofQC(t, block, view, fmt.Sprintf("leader-%d", view), parentID.Hash(), secrets, public)
		block.SetFHSSignature(qc.Sign, qc.Mask, qc.ViewID, qc.LeaderID, qc.Number, ref.ExtraHash, ref.ParentQCID)
		descendants, qcs = append(descendants, block), append(qcs, qc)
		parent, parentQC = block, qc
	}
	encoded, err := EncodeFHSCommitProof(&FHSCommitProof{QCs: qcs[:2]})
	if err != nil {
		t.Fatal(err)
	}
	if err := carrier.SetFHSFinalityProof(encoded); err != nil {
		t.Fatal(err)
	}
	rawdb.WriteBlock(validator.bc.db, carrier)
	rawdb.WriteCanonicalHash(validator.bc.db, carrier.Hash(), carrier.NumberU64())
	rawdb.WriteKeyBlock(validator.bc.db, newKey)
	rawdb.WriteKeyBlockHash(validator.bc.db, newKey.Hash(), newKey.NumberU64())
	if !bftview.WriteCommittee(newKey.NumberU64(), newKey.Hash(), committee) {
		t.Fatal("store activated signing committee")
	}
	validator.bc.keyBlockChain.currentBlock.Store(newKey)
	if err := validator.VerifyFHS2ChainCommitProof(descendants[0], qcs[1]); err != nil {
		t.Fatalf("pre-activation certified terminal QC rejected after key handoff: %v", err)
	}
	if err := validator.bc.validateFHSKeyActivationWithProof(descendants[1], oldKeyHash, newKey); err != nil {
		t.Fatalf("captured old-epoch descendant cannot commit: %v", err)
	}
	if err := validator.VerifyFHS2ChainCommitProof(descendants[1], qcs[2]); err == nil {
		t.Fatal("old epoch created a further QC beyond the activation proof")
	}
	if err := validator.bc.validateFHSKeyActivationWithProof(descendants[2], oldKeyHash, newKey); err == nil {
		t.Fatal("unproven old-epoch descendant bypassed key activation")
	}
	lastOldID, err := hotstuff.SignedStateID(qcs[1])
	if err != nil {
		t.Fatal(err)
	}
	newEpochChild := types.NewBlockWithHeader(&types.Header{
		ParentHash: descendants[1].Hash(), Number: big.NewInt(4), Difficulty: big.NewInt(1), KeyHash: newKey.Hash(),
	})
	_, newEpochQC := makeFHSCommitProofQC(t, newEpochChild, 6, "leader-6", lastOldID.Hash(), secrets, public)
	if err := validator.VerifyFHSCommitProof(descendants[0], &FHSCommitProof{QCs: []*hotstuff.SignedState{qcs[1], newEpochQC}}); err != nil {
		t.Fatalf("remaining ancestor could not finalize across the already canonical key handoff: %v", err)
	}
}

func TestFHSKeyCarrierCannotActivateItsOwnUncommittedCommittee(t *testing.T) {
	validator, oldSecrets, oldPublic, oldKeyHash := makeFHSCommitProofValidator(t)
	newSecrets := make([]bls.SecretKey, len(oldSecrets))
	newPublic := make([]*bls.PublicKey, len(oldPublic))
	committee := &bftview.Committee{List: make([]*common.Cnode, len(newPublic))}
	for index := range newSecrets {
		newSecrets[index].SetByCSPRNG()
		newPublic[index] = newSecrets[index].GetPublicKey()
		committee.List[index] = &common.Cnode{Address: fmt.Sprintf("new-validator-%d", index), Public: newPublic[index].SerializeToHexStr()}
	}
	newKey := types.NewKeyBlock(&types.KeyBlockHeader{
		ParentHash: oldKeyHash, Number: big.NewInt(1), Difficulty: big.NewInt(1),
		T_Number: 0, Time: 2, CommitteeHash: committee.RlpHash(),
	})
	// A persisted header/committee is available for QC verification but has not
	// been made canonical by an old-epoch finality proof.
	rawdb.WriteKeyBlock(validator.bc.db, newKey)
	if !bftview.WriteCommittee(newKey.NumberU64(), newKey.Hash(), committee) {
		t.Fatal("store proposed signing committee")
	}
	carrier := types.NewBlockWithHeader(&types.Header{
		ParentHash: common.HexToHash("0xc001"), Number: big.NewInt(1), Difficulty: big.NewInt(1),
		BlockType: types.Key_Block, KeyHash: oldKeyHash,
	})
	carrier.SetKeyblock(newKey)
	ref, ownQC := makeFHSCommitProofQC(t, carrier, 1, "leader-1", common.Hash{}, oldSecrets, oldPublic)
	carrier.SetFHSSignature(ownQC.Sign, ownQC.Mask, ownQC.ViewID, ownQC.LeaderID, ownQC.Number, ref.ExtraHash, ref.ParentQCID)
	ownID, err := hotstuff.SignedStateID(ownQC)
	if err != nil {
		t.Fatal(err)
	}
	newChild := types.NewBlockWithHeader(&types.Header{
		ParentHash: carrier.Hash(), Number: big.NewInt(2), Difficulty: big.NewInt(1), KeyHash: newKey.Hash(),
	})
	_, newQC := makeFHSCommitProofQC(t, newChild, 2, "new-leader-2", ownID.Hash(), newSecrets, newPublic)
	if err := validator.VerifyFHS2ChainCommitProof(carrier, newQC); err == nil {
		t.Fatal("uncommitted new committee finalized its own activating carrier")
	}
	oldChild := types.NewBlockWithHeader(&types.Header{
		ParentHash: carrier.Hash(), Number: big.NewInt(2), Difficulty: big.NewInt(1), KeyHash: oldKeyHash,
	})
	_, oldQC := makeFHSCommitProofQC(t, oldChild, 2, "old-leader-2", ownID.Hash(), oldSecrets, oldPublic)
	if err := validator.VerifyFHS2ChainCommitProof(carrier, oldQC); err != nil {
		t.Fatalf("old committee could not activate its valid carrier: %v", err)
	}
	encoded, err := EncodeFHSCommitProof(singleFHSCommitProof(oldQC))
	if err != nil {
		t.Fatal(err)
	}
	if err := carrier.SetFHSFinalityProof(encoded); err != nil {
		t.Fatal(err)
	}
	rawdb.WriteBlock(validator.bc.db, carrier)
	rawdb.WriteCanonicalHash(validator.bc.db, carrier.Hash(), carrier.NumberU64())
	rawdb.WriteKeyBlockHash(validator.bc.db, newKey.Hash(), newKey.NumberU64())
	validator.bc.keyBlockChain.currentBlock.Store(newKey)
	if err := validator.VerifyFHS2ChainCommitProof(carrier, newQC); err != nil {
		t.Fatalf("already activated committee's alternative carrier proof rejected: %v", err)
	}
}
