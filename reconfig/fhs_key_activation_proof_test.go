package reconfig

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rnet/network"
)

func TestFHSKeyActivationManifestCarriesAncestorFinality(t *testing.T) {
	fixture := newFHSEpochTestFixture(t)
	s := fixture.service
	s.chainConfig.FairHotstuffSeed = common.HexToHash("0x5151")
	nextCommittee := fixture.committee.Copy()
	newMember := *nextCommittee.List[len(nextCommittee.List)-1]
	newMember.Address = "validator-new"
	nextCommittee.List[len(nextCommittee.List)-1] = &newMember
	nextKey := types.NewKeyBlock(&types.KeyBlockHeader{
		ParentHash: fixture.current.Hash(), Difficulty: big.NewInt(1), Number: big.NewInt(2), Time: 3,
		T_Number: 1, CommitteeHash: nextCommittee.RlpHash(),
	})
	rawdb.WriteKeyBlock(fixture.db, nextKey)
	if !bftview.WriteCommittee(nextKey.NumberU64(), nextKey.Hash(), nextCommittee) {
		t.Fatal("store next committee")
	}
	carrierBlock := types.NewBlockWithHeader(&types.Header{
		ParentHash: common.HexToHash("0xc001"), Number: big.NewInt(2), Difficulty: big.NewInt(1),
		BlockType: types.Key_Block, KeyHash: fixture.current.Hash(),
	})
	carrierBlock.SetKeyblock(nextKey)
	makeRef := func(block *types.Block, view uint64, parentQC *hotstuff.SignedState) (*types.HotstuffProposalRef, *hotstuff.SignedState) {
		t.Helper()
		var parentID common.Hash
		if parentQC != nil {
			id, err := hotstuff.SignedStateID(parentQC)
			if err != nil {
				t.Fatal(err)
			}
			parentID = id.Hash()
		}
		ref, err := types.NewHotstuffProposalRefWithProof(s.ChainID(), view,
			common.BigToHash(new(big.Int).SetUint64(view)), fixture.committee.List[0].Address,
			block, block.EncodeToBytes(), nil, parentID)
		if err != nil {
			t.Fatal(err)
		}
		return ref, signFHSEpochProposalQC(t, fixture, ref)
	}
	carrierRef, carrierQC := makeRef(carrierBlock, 21, nil)
	childBlock := types.NewBlockWithHeader(&types.Header{
		ParentHash: carrierBlock.Hash(), Number: big.NewInt(3), Difficulty: big.NewInt(1), KeyHash: fixture.current.Hash(),
	})
	_, childQC := makeRef(childBlock, 24, carrierQC)
	tipBlock := types.NewBlockWithHeader(&types.Header{
		ParentHash: childBlock.Hash(), Number: big.NewInt(4), Difficulty: big.NewInt(1), KeyHash: fixture.current.Hash(),
	})
	_, tipQC := makeRef(tipBlock, 25, childQC)
	carrier := &certifiedFHSKeyCarrier{keyBlock: nextKey, ref: carrierRef, qc: carrierQC}
	proof := &core.FHSCommitProof{QCs: []*hotstuff.SignedState{childQC, tipQC}}
	proofBytes, err := core.EncodeFHSCommitProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.verifyCertifiedFHSKeyActivation(carrier, childQC); err == nil {
		t.Fatal("view 21 -> 24 alone activated the next epoch")
	}
	if terminal, err := s.verifyFHSKeyActivationFinality(carrier, proofBytes); err != nil || terminal.ViewNumber != 25 {
		t.Fatalf("consecutive terminal pair did not finalize the ancestor carrier: terminal=%v err=%v", terminal, err)
	}
	for _, test := range []struct {
		name string
		qcs  []*hotstuff.SignedState
	}{
		{"skipped edge only", []*hotstuff.SignedState{childQC}},
		{"missing intermediate", []*hotstuff.SignedState{tipQC}},
		{"reversed", []*hotstuff.SignedState{tipQC, childQC}},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := core.EncodeFHSCommitProof(&core.FHSCommitProof{QCs: test.qcs})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.verifyFHSKeyActivationFinality(carrier, encoded); err == nil {
				t.Fatal("incomplete activation proof accepted")
			}
		})
	}
	for index := range proof.QCs {
		bad := core.CloneFHSCommitProof(proof)
		bad.QCs[index].Sign[0] ^= 0xff
		encoded, err := core.EncodeFHSCommitProof(bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.verifyFHSKeyActivationFinality(carrier, encoded); err == nil {
			t.Fatalf("tampered signature %d accepted", index)
		}
	}
	// The same carrier block can be certified again. The block hash artifact
	// points at a later, privately observed QC, while the proof must find the
	// exact earlier QC. Private HighQC alone cannot invalidate finality.
	laterRef, laterQC := makeRef(carrierBlock, 28, nil)
	record := fhsEpochCertifiedRecord(carrierRef, carrierBlock, carrierQC)
	later := fhsEpochCertifiedRecord(laterRef, carrierBlock, laterQC)
	s.fhsCertifiedByID = map[common.Hash]*fhsCertifiedProposal{carrierRef.ProposalID(): record, laterRef.ProposalID(): later}
	s.fhsCertifiedByHash = map[common.Hash]*fhsCertifiedProposal{carrierBlock.Hash(): later}
	s.fhsHighest = later
	s.proposalBodies = make(map[common.Hash]*proposalBodyMsg)
	s.currentView.TxNumber, s.currentView.TxHash, s.currentView.ViewNumber = carrierBlock.NumberU64(), carrierBlock.Hash(), 28
	leaderIndex, err := fairHotstuffLeaderIndex(s.chainConfig.FairHotstuffSeed, s.ChainID(), 26, nextKey.CommitteeHash(), len(nextCommittee.List))
	if err != nil {
		t.Fatal(err)
	}
	leader := nextCommittee.List[leaderIndex]
	proposal := types.NewBlockWithHeader(&types.Header{
		ParentHash: tipBlock.Hash(), Number: big.NewInt(5), Difficulty: big.NewInt(1), KeyHash: nextKey.Hash(),
		UncleHash: types.CalcUncleHash(nil), CommonTxAdmissionRoot: types.DeriveCommonTxAdmissionRoot(nil, nil),
		CommonTxRewardRoot: types.DeriveCommonTxRewardRoot(nil),
	})
	tipID, err := hotstuff.SignedStateID(tipQC)
	if err != nil {
		t.Fatal(err)
	}
	proposalRef, err := types.NewHotstuffProposalRefWithProof(s.ChainID(), 26, common.HexToHash("0xc026"),
		leader.Address, proposal, proposal.EncodeToBytes(), nil, tipID.Hash())
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := encodeProposalDataManifest(proposal)
	if err != nil {
		t.Fatal(err)
	}
	tipBytes, err := hotstuff.EncodeSignedState(tipQC)
	if err != nil {
		t.Fatal(err)
	}
	body := &proposalBodyMsg{
		Type: proposalBodyMsgManifest, ProposalID: proposalRef.ProposalID(), BodyHash: proposalRef.BodyHash,
		BodySize: proposalRef.BodySize, Number: proposalRef.Number, ViewNumber: proposalRef.ViewNumber,
		ViewID: proposalRef.ViewID, LeaderID: proposalRef.LeaderID, From: proposalRef.LeaderID,
		ProposalKeyHash: nextKey.Hash(), SenderKeyHash: nextKey.Hash(), Manifest: manifest, ParentQC: tipBytes,
		KeyActivationProof: proofBytes,
	}
	signBody := func(body *proposalBodyMsg) {
		t.Helper()
		digest, err := proposalBodyAuthDigest(s.ChainID(), body)
		if err != nil {
			t.Fatal(err)
		}
		body.AuthSig = fixture.keys[leaderIndex].SignHash(digest).Serialize()
	}
	signBody(body)
	from := &network.ServerIdentity{Address: network.Address(leader.Address)}
	withoutProof := cloneProposalBodyMsg(body)
	withoutProof.KeyActivationProof = nil
	signBody(withoutProof)
	if err := s.verifyProposalBodySender(from, withoutProof); err == nil {
		t.Fatal("terminal QC alone authenticated a gapped activation carrier")
	}
	if err := s.verifyProposalBodySender(from, body); err != nil {
		t.Fatalf("authenticate gapped activation manifest: %v", err)
	}
	if err := s.verifyProposalManifestAuthority(body); err != nil {
		t.Fatalf("gapped activation manifest authority: %v", err)
	}
	tampered := cloneProposalBodyMsg(body)
	tampered.KeyActivationProof[len(tampered.KeyActivationProof)-1] ^= 1
	if err := s.verifyProposalBodySender(from, tampered); err == nil {
		t.Fatal("activation metadata was not authenticated by sender signature")
	}
	oversized := cloneProposalBodyMsg(body)
	oversized.KeyActivationProof = make([]byte, types.MaxFHSFinalityProofSize+1)
	if err := validateProposalBodyWireShapeForConfig(s.chainConfig, oversized); err == nil {
		t.Fatal("oversized activation metadata passed wire bounds")
	}
	if _, err := s.storeProposalManifest(body); err != nil {
		t.Fatalf("store authenticated activation manifest: %v", err)
	}
	if _, err := s.proposalBodySenderKey(nextKey.Hash(), leader.Address); err != nil {
		t.Fatalf("authenticated cached proof did not preserve new epoch signer resolution: %v", err)
	}
	if len(s.fhsCertifiedByID) != 2 || s.fhsHighest != later {
		t.Fatal("manifest authentication published synthetic certified descendants")
	}
}

func TestFHSKeyActivationProofFitsMaximumManifestDelivery(t *testing.T) {
	// A maximum manifest plus independently bounded control and activation
	// proofs must fit the bulk queue. Otherwise wire-valid recovery metadata
	// would be dropped before transport delivery.
	q := newPeerQueuesWithBudgetAndLimit(nil, proposalPeerQueueBulkLimitForConfig(nil))
	defer q.close()
	message := &networkMsg{Pmsg: &proposalBodyMsg{
		Type: proposalBodyMsgManifest, Manifest: make([]byte, proposalBodyLimitForConfig(nil)),
		ParentQC: make([]byte, proposalBodyControlMaxBytes), KeyActivationProof: make([]byte, types.MaxFHSFinalityProofSize),
		From: "sender", LeaderID: "leader", AuthSig: make([]byte, 256),
	}}
	if reserved, _ := q.reserve(message); !reserved {
		t.Fatal("maximum bounded manifest and activation proof do not fit the outbound queue")
	}
	q.release(message)
}
