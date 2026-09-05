package reconfig

import (
	"context"
	"math/big"
	"strings"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus/colossusX"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

func historicalKeyFixture(t *testing.T) (*convergenceFixture, *fhsCertifiedProposal, *types.KeyBlock) {
	t.Helper()
	f := newConvergenceFixture(t)
	s := f.replicas[0]
	parentKey := s.kbc.CurrentBlock()
	committee := bftview.LoadMember(parentKey.NumberU64(), parentKey.Hash(), true)
	const leader = 6
	view := uint64(1)
	for ; view < 1000; view++ {
		index, err := fairHotstuffLeaderIndex(s.chainConfig.FairHotstuffSeed, s.ChainID(), view, committee.RlpHash(), len(committee.List))
		if err != nil {
			t.Fatal(err)
		}
		if index == leader {
			break
		}
	}
	if view == 1000 {
		t.Fatal("cannot select historical fixture leader")
	}
	nextCommittee := committee.Copy()
	nextCommittee.Add(nil, leader, "")
	key := types.NewKeyBlock(&types.KeyBlockHeader{ParentHash: parentKey.Hash(), Number: big.NewInt(1), Difficulty: big.NewInt(1),
		Time: scheduledKeyBlockTimestamp(parentKey.Time()), T_Number: 0, BlockType: types.TimeReconfig, CommitteeHash: nextCommittee.RlpHash()})
	key = key.WithBody(nextCommittee.In().Public, nextCommittee.In().CoinBase, "", "", nextCommittee.Leader().Public, nextCommittee.Leader().CoinBase)
	base := s.bc.CurrentBlock()
	header := &types.Header{ParentHash: base.Hash(), Number: big.NewInt(1), Difficulty: big.NewInt(1), GasLimit: base.GasLimit(),
		BaseFee: big.NewInt(params.FixedBaseFeePerGas), Time: base.Time() + 1, KeyHash: parentKey.Hash(), BlockType: types.Key_Block}
	state, err := s.bc.StateAt(base.Root())
	if err != nil {
		t.Fatal(err)
	}
	colossusX.AccumulateRewards(s.chainConfig, state, header, nil, nil)
	header.Root = state.IntermediateRoot(s.chainConfig.IsEIP158(header.Number))
	block := types.NewBlock(header, nil, nil, nil, nil)
	block.SetKeyblock(key)
	encoded := block.EncodeToBytes()
	ref, err := types.NewHotstuffProposalRefWithProof(s.ChainID(), view, common.BigToHash(new(big.Int).SetUint64(view)), committee.List[leader].Address, block, encoded, nil, common.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	qc := &hotstuff.SignedState{State: ref.EncodeToBytes(), Number: view, ViewID: ref.ViewID, LeaderID: ref.LeaderID, Mask: []byte{0x1f}}
	var signature *bls.Sign
	for i := 0; i < 5; i++ {
		sig, err := hotstuff.SignFHSSignatureWithContext(&f.keys[i], f.public[i], qc.State, s.ChainID(), hotstuff.MsgVotePrepare, qc.ViewID, qc.LeaderID)
		if err != nil {
			t.Fatal(err)
		}
		if signature == nil {
			signature = sig
		} else {
			signature.Add(sig)
		}
	}
	qc.Sign = signature.Serialize()
	for _, replica := range f.replicas {
		replica.keyService = &keyService{s: replica, bc: replica.bc, kbc: replica.kbc, config: replica.chainConfig}
		body := &proposalBodyMsg{Type: proposalBodyMsgManifest, ProposalID: ref.ProposalID(), BodyHash: ref.BodyHash, BodySize: ref.BodySize,
			Number: ref.Number, ViewNumber: view, ViewID: ref.ViewID, LeaderID: ref.LeaderID, ProposalKeyHash: ref.KeyHash, EncodedBlock: encoded}
		if err := replica.storeProposalBody(body); err != nil {
			t.Fatal(err)
		}
		verified, err := replica.bc.ValidateBlockForHotstuffWithParent(ref.ProposalID(), view, ref.ViewID, ref.LeaderID, types.DecodeToBlock(encoded), nil)
		if err != nil {
			t.Fatalf("execute actual key carrier: %v", err)
		}
		replica.verifiedProposalByID[ref.ProposalID()] = verified
	}
	return f, &fhsCertifiedProposal{ref: ref, qc: qc, verified: s.verifiedProposalByID[ref.ProposalID()]}, key
}

func TestFHSStageAndWALReplayHistoricalKeyCarrierAfterLeaderChange(t *testing.T) {
	f, carrier, key := historicalKeyFixture(t)
	s := f.replicas[0]
	// Register the fixture's real committee for the unchanged live verifier.
	committee := bftview.LoadMember(0, key.ParentHash(), true)
	committeeDB := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { committeeDB.Close() })
	bftview.SetCommitteeConfig(committeeDB, s.kbc, nil)
	if !bftview.WriteCommittee(0, key.ParentHash(), committee) {
		t.Fatal("store historical signing committee")
	}
	s.currentView.LeaderIndex = 3
	if err := s.keyService.verifyKeyBlock(key, nil, 0); err == nil || !strings.Contains(err.Error(), "leaderindex(3) error, nowIndex:6") {
		t.Fatalf("did not reproduce runtime's exact live-view mismatch: %v", err)
	}
	child := f.proposal(t, carrier, carrier.qc.Number+2, 'c')
	persistBranchSafetyBodies(t, s, carrier, child)
	if err := s.persistValidatedFHSCertificates([]fhsHighQCValidationItem{{ref: carrier.ref, qc: carrier.qc, verified: carrier.verified}}, false); err != nil {
		t.Fatal(err)
	}
	s.cacheFHSCertificateLocked(carrier)
	s.fhsHighest = carrier
	output, err := s.stageFHSHighQC(context.Background(), hotstuff.FHSHighQCValidationKey{}, child.qc, 0, 0)
	if err != nil {
		t.Fatalf("certified historical carrier was compared with the new live leader: %v", err)
	}
	if err := s.installStagedFHSHighQC(output, false, false); err != nil {
		t.Fatal(err)
	}
	resetBranchSafetyRuntime(s)
	s.currentView.LeaderIndex = 3
	if err := s.loadFHSWAL(); err != nil {
		t.Fatalf("historical key carrier could not restart under another live leader: %v", err)
	}
	if !hotstuff.SignedStateSemanticEqual(s.HighestCertified(), child.qc) {
		t.Fatal("WAL recovery lost the certified child")
	}
}

func TestFHSHistoricalKeyCarrierRejectsInvalidAuthenticatedContext(t *testing.T) {
	f, carrier, key := historicalKeyFixture(t)
	s := f.replicas[0]
	s.currentView.LeaderIndex = 3
	if err := s.keyService.verifyCertifiedFHSKeyBlock(carrier.ref, key, nil); err != nil {
		t.Fatalf("valid historical context rejected: %v", err)
	}
	if s.currentView.LeaderIndex != 3 {
		t.Fatal("historical validation changed the live leader")
	}
	for _, scenario := range []string{"proposal_leader", "embedded_leader", "committee_commitment", "signing_parent", "missing_pow_candidate"} {
		t.Run(scenario, func(t *testing.T) {
			ref := *carrier.ref
			invalid := key.CopyMe()
			switch scenario {
			case "proposal_leader":
				ref.LeaderID = "unauthorized-validator"
			case "embedded_leader":
				invalid = invalid.WithBody(key.InPubKey(), key.InAddress(), "", "", f.public[0].SerializeToHexStr(), key.LeaderAddress())
			case "committee_commitment":
				invalid.SetCommitteeHash(common.HexToHash("0xbad"))
			case "signing_parent":
				ref.KeyHash = common.HexToHash("0xbad")
			case "missing_pow_candidate":
				invalid.SetBlockType(types.PowReconfig)
			}
			if err := s.keyService.verifyCertifiedFHSKeyBlock(&ref, invalid, nil); err == nil {
				t.Fatal("invalid certified key carrier accepted")
			}
		})
	}
}
