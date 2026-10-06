package reconfig

import (
	"context"
	"fmt"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus/colossusX"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/ethdb/leveldb"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

// These replicas use independent canonical chains and real synchronous LevelDB
// safety stores. Delivery order is controlled by the test; certificate parsing,
// BLS verification, ancestry staging and publication are the Service's real path.
type convergenceFixture struct {
	replicas []*Service
	keys     []bls.SecretKey
	public   []*bls.PublicKey
}

func newConvergenceFixture(t *testing.T) *convergenceFixture {
	t.Helper()
	f := &convergenceFixture{keys: make([]bls.SecretKey, 7), public: make([]*bls.PublicKey, 7)}
	committee := &bftview.Committee{List: make([]*common.Cnode, 7)}
	for i := range f.keys {
		f.keys[i].SetByCSPRNG()
		f.public[i] = f.keys[i].GetPublicKey()
		committee.List[i] = &common.Cnode{Address: fmt.Sprintf("127.0.0.1:%d", 27100+i), CoinBase: common.BigToAddress(big.NewInt(int64(i + 1))).Hex(), Public: f.public[i].SerializeToHexStr()}
	}
	key := types.NewKeyBlock(&types.KeyBlockHeader{Number: big.NewInt(0), Difficulty: big.NewInt(1), Time: 1, CommitteeHash: committee.RlpHash()})
	for i := 0; i < 7; i++ {
		db := rawdb.NewMemoryDatabase()
		config := *params.TestChainConfig
		config.ChainID = big.NewInt(73041)
		config.FairHotstuff = false // The fixture initializes the canonical store directly.
		config.FairHotstuffSeed = common.HexToHash("0xc011")
		config.SetModernForkConfig(&params.ModernForkConfig{BerlinBlock: big.NewInt(0), LondonBlock: big.NewInt(0)})
		t.Cleanup(func() { config.SetModernForkConfig(nil) })
		rawdb.WriteKeyBlock(db, key)
		rawdb.WriteKeyBlockHash(db, key.Hash(), 0)
		rawdb.WriteHeadKeyBlockHash(db, key.Hash())
		rawdb.WriteHeadKeyHeaderHash(db, key.Hash())
		rawdb.WriteTd(db, key.Hash(), 0, key.Difficulty())
		bftview.SetCommitteeConfig(db, nil, nil)
		if !bftview.WriteCommittee(0, key.Hash(), committee) {
			t.Fatal("write committee")
		}
		kbc, err := core.NewKeyBlockChain(&fhsEpochTestBackend{}, db, nil, &config, nil, new(event.TypeMux))
		if err != nil {
			t.Fatal(err)
		}
		genesis := (&core.Genesis{Config: &config, Difficulty: big.NewInt(1), GasLimit: params.GenesisGasLimit, Timestamp: 1}).MustCommit(db)
		engine := colossusX.NewFaker()
		bc, err := core.NewBlockChain(db, nil, &config, engine, vm.Config{}, nil, nil, kbc)
		if err != nil {
			t.Fatal(err)
		}
		config.FairHotstuff = true
		wal, err := leveldb.New(filepath.Join(t.TempDir(), "safety"), 1, 8, "")
		if err != nil {
			t.Fatal(err)
		}
		s := &Service{chainConfig: &config, bc: bc, kbc: kbc, netService: &netService{serverAddress: committee.List[i].Address},
			fhsStore:       newFHSSafetyStore(wal, config.ChainID.Uint64(), genesis.Hash()),
			proposalBodies: make(map[common.Hash]*proposalBodyMsg), verifiedProposalByID: make(map[common.Hash]*core.VerifiedProposal),
			fhsCertifiedByHash: make(map[common.Hash]*fhsCertifiedProposal), fhsCertifiedByID: make(map[common.Hash]*fhsCertifiedProposal),
			currentView: bftview.View{TxHash: genesis.Hash(), KeyHash: key.Hash(), CommitteeHash: committee.RlpHash()},
		}
		s.txService = &txService{bc: bc, kbc: kbc, config: &config, proposedChain: newProposedChain(), mux: new(event.TypeMux)}
		s.txService.proposedChain.clear(genesis)
		f.replicas = append(f.replicas, s)
		t.Cleanup(func() { bc.Stop(); kbc.Stop(); engine.Close(); wal.Close(); db.Close() })
	}
	return f
}

func (f *convergenceFixture) proposal(t *testing.T, parent *fhsCertifiedProposal, view uint64, marker byte, signers ...int) *fhsCertifiedProposal {
	t.Helper()
	s := f.replicas[0]
	base := s.bc.CurrentBlock()
	var parentQC *hotstuff.SignedState
	var parentID common.Hash
	if parent != nil {
		base, parentQC = parent.verified.Block, parent.qc
		id, err := hotstuff.SignedStateID(parentQC)
		if err != nil {
			t.Fatal(err)
		}
		parentID = id.Hash()
	}
	block := types.NewBlock(&types.Header{ParentHash: base.Hash(), Number: new(big.Int).SetUint64(base.NumberU64() + 1), Root: base.Root(),
		Difficulty: big.NewInt(1), GasLimit: base.GasLimit(), BaseFee: big.NewInt(params.FixedBaseFeePerGas), Time: base.Time() + 1, KeyHash: s.kbc.CurrentBlock().Hash(), BlockType: types.FastTx_Block, Extra: []byte{marker}}, nil, nil, nil, nil)
	encoded := block.EncodeToBytes()
	leader, err := fairHotstuffLeaderIndex(s.chainConfig.FairHotstuffSeed, s.ChainID(), view, s.currentView.CommitteeHash, len(f.keys))
	if err != nil {
		t.Fatal(err)
	}
	ref, err := types.NewHotstuffProposalRefWithProof(s.ChainID(), view, common.BigToHash(new(big.Int).SetUint64(view)), fmt.Sprintf("127.0.0.1:%d", 27100+leader), block, encoded, nil, parentID)
	if err != nil {
		t.Fatal(err)
	}
	if len(signers) == 0 {
		signers = []int{0, 1, 2, 3, 4}
	}
	qc := &hotstuff.SignedState{State: ref.EncodeToBytes(), Number: view, ViewID: ref.ViewID, LeaderID: ref.LeaderID, Mask: []byte{0}}
	var agg *bls.Sign
	for _, i := range signers {
		qc.Mask[0] |= 1 << uint(i)
		sig, err := hotstuff.SignFHSSignatureWithContext(&f.keys[i], f.public[i], qc.State, s.ChainID(), hotstuff.MsgVotePrepare, qc.ViewID, qc.LeaderID)
		if err != nil {
			t.Fatal(err)
		}
		if agg == nil {
			agg = sig
		} else {
			agg.Add(sig)
		}
	}
	qc.Sign = agg.Serialize()
	parentBytes, err := hotstuff.EncodeSignedState(parentQC)
	if err != nil {
		t.Fatal(err)
	}
	for _, replica := range f.replicas {
		body := &proposalBodyMsg{Type: proposalBodyMsgManifest, ProposalID: ref.ProposalID(), BodyHash: ref.BodyHash, BodySize: ref.BodySize, Number: ref.Number,
			ViewNumber: view, ViewID: ref.ViewID, LeaderID: ref.LeaderID, ProposalKeyHash: ref.KeyHash, EncodedBlock: encoded, ParentQC: parentBytes}
		if err := replica.storeProposalBody(body); err != nil {
			t.Fatal(err)
		}
		var parentVerified *core.VerifiedProposal
		if parent != nil {
			parentVerified = replica.verifiedProposalByID[parent.ref.ProposalID()]
		}
		verified, err := replica.bc.ValidateBlockForHotstuffWithParent(ref.ProposalID(), view, ref.ViewID, ref.LeaderID, types.DecodeToBlock(encoded), parentVerified)
		if err != nil {
			t.Fatalf("execute proposal %c on real chain: %v", marker, err)
		}
		replica.verifiedProposalByID[ref.ProposalID()] = verified
	}
	return &fhsCertifiedProposal{ref: ref, qc: qc, verified: f.replicas[0].verifiedProposalByID[ref.ProposalID()]}
}

func TestFHSServiceConvergesAfterSelectiveSiblingQC(t *testing.T) {
	f := newConvergenceFixture(t)
	// Match the deployed deterministic leader schedule: both selective-QC
	// collectors are Byzantine, then an honest leader can finish with five votes.
	s := f.replicas[0]
	firstView := uint64(10)
	for ; firstView < 10000; firstView++ {
		leaders := make([]int, 3)
		for offset := range leaders {
			index, err := fairHotstuffLeaderIndex(s.chainConfig.FairHotstuffSeed, s.ChainID(), firstView+uint64(offset), s.currentView.CommitteeHash, len(f.keys))
			if err != nil {
				t.Fatal(err)
			}
			leaders[offset] = int(index)
		}
		if leaders[0] >= 5 && leaders[1] >= 5 && leaders[2] < 5 {
			break
		}
	}
	if firstView == 10000 {
		t.Fatal("failed to find the bounded adversarial leader schedule")
	}
	a := f.proposal(t, nil, firstView, 'a', 0, 1, 2, 5, 6)
	b := f.proposal(t, nil, firstView+1, 'b', 1, 2, 3, 4, 5)
	// Honest signers persist one vote per view. Only H0 receives A's QC;
	// H1/H2 can legitimately vote again in B's later view without knowing it.
	for _, schedule := range []struct {
		proposal *fhsCertifiedProposal
		honest   []int
	}{{a, []int{0, 1, 2}}, {b, []int{1, 2, 3, 4}}} {
		for _, index := range schedule.honest {
			ref := schedule.proposal.ref
			if err := f.replicas[index].validateFHSProposalParent(ref, nil); err != nil {
				t.Fatalf("H%d cannot validate initial vote: %v", index, err)
			}
			vote := &hotstuff.PersistedVote{ViewNumber: ref.ViewNumber, ViewID: ref.ViewID, LeaderID: ref.LeaderID,
				ProposalID: ref.ProposalID(), ProposalRef: ref.EncodeToBytes(), ProposalRefHash: hotstuff.StateDigest(ref.EncodeToBytes())}
			if err := f.replicas[index].PersistFHSVote(vote); err != nil {
				t.Fatalf("H%d cannot persist initial vote: %v", index, err)
			}
		}
		if schedule.proposal == a {
			if err := f.replicas[0].adoptFHSHighQC(a.qc, false, false); err != nil {
				t.Fatalf("deliver A to H0: %v", err)
			}
		}
	}
	for i := 1; i < 5; i++ {
		if err := f.replicas[i].adoptFHSHighQC(b.qc, false, false); err != nil {
			t.Fatalf("deliver B to H%d: %v", i, err)
		}
	}
	// Byzantine replicas now withhold. The five honest replicas must be able to
	// adopt B and vote for its child without a Byzantine vote or a WAL reset.
	if err := f.replicas[0].adoptFHSHighQC(b.qc, false, false); err != nil {
		t.Fatalf("H0 cannot adopt newer sibling QC: %v", err)
	}
	c := f.proposal(t, b, firstView+2, 'c')
	for i := 0; i < 5; i++ {
		s := f.replicas[i]
		if !hotstuff.SignedStateSemanticEqual(s.HighestCertified(), b.qc) {
			t.Fatalf("H%d did not converge on B", i)
		}
		if err := s.validateFHSProposalParent(c.ref, b.qc); err != nil {
			t.Fatalf("H%d cannot validate child: %v", i, err)
		}
		vote := &hotstuff.PersistedVote{ViewNumber: c.ref.ViewNumber, ViewID: c.ref.ViewID, LeaderID: c.ref.LeaderID, ProposalID: c.ref.ProposalID(), ProposalRef: c.ref.EncodeToBytes(), ProposalRefHash: hotstuff.StateDigest(c.ref.EncodeToBytes())}
		if err := s.PersistFHSVote(vote); err != nil {
			t.Fatalf("H%d cannot vote: %v", i, err)
		}
		output, err := s.stageFHSHighQC(context.Background(), hotstuff.FHSHighQCValidationKey{}, c.qc, 0, 0)
		if err != nil {
			t.Fatalf("H%d cannot stage child QC: %v", i, err)
		}
		if err := s.installStagedFHSHighQC(output, false, false); err != nil {
			t.Fatalf("H%d cannot install child QC: %v", i, err)
		}
		if target := fhs2ChainCommitTarget(s.fhsCertifiedByID, s.fhsHighest); target == nil || target.ref.BlockHash != b.ref.BlockHash {
			t.Fatalf("H%d cannot finalize B", i)
		}
		if err := s.adoptFHSHighQC(a.qc, false, false); err != nil {
			t.Fatalf("delayed A: %v", err)
		}
		if !hotstuff.SignedStateSemanticEqual(s.HighestCertified(), c.qc) {
			t.Fatalf("H%d regressed on delayed A", i)
		}
		if err := s.commitFHS2ChainForCertified(c.qc); err != nil {
			t.Fatalf("H%d cannot commit converged branch: %v", i, err)
		}
		if s.bc.CurrentBlock().Hash() != b.ref.BlockHash {
			t.Fatalf("H%d did not persist B as canonical", i)
		}
	}
}

func TestFHSServiceCommitsGappedAncestorsWithConsecutiveTerminalPair(t *testing.T) {
	f := newConvergenceFixture(t)
	a := f.proposal(t, nil, 1, 'a')
	b := f.proposal(t, a, 4, 'b')
	c := f.proposal(t, b, 5, 'c')
	s := f.replicas[0]
	if err := s.adoptFHSHighQC(b.qc, false, false); err != nil {
		t.Fatal(err)
	}
	if err := s.commitFHS2ChainForCertified(b.qc); err != nil {
		t.Fatal(err)
	}
	if s.bc.CurrentBlockN() != 0 {
		t.Fatal("nonconsecutive terminal pair committed")
	}
	if err := s.adoptFHSHighQC(c.qc, false, false); err != nil {
		t.Fatal(err)
	}
	if err := s.commitFHS2ChainForCertified(c.qc); err != nil {
		t.Fatal(err)
	}
	if s.bc.CurrentBlockN() != 2 || s.bc.GetCanonicalHash(1) != a.ref.BlockHash || s.bc.GetCanonicalHash(2) != b.ref.BlockHash {
		t.Fatal("consecutive terminal pair did not commit complete ancestor path")
	}
	for number, count := range map[uint64]int{1: 2, 2: 1} {
		block := s.bc.GetBlockByNumber(number)
		proof, present, err := core.DecodeFHSCommitProof(block)
		if err != nil || !present || len(proof.QCs) != count {
			t.Fatalf("canonical block %d lost full finality proof: %v", number, err)
		}
		if err := s.bc.VerifyFHSCommitProof(block, proof); err != nil {
			t.Fatalf("canonical block %d proof fails verification: %v", number, err)
		}
	}
}
