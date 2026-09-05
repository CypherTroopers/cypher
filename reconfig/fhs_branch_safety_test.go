package reconfig

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/ethdb/leveldb"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

func reloadBranchSafetyState(t *testing.T, s *Service) (*hotstuff.FHSSafetyState, common.Hash) {
	t.Helper()
	reloaded := newFHSSafetyStore(s.fhsStore.db, s.fhsStore.chainID, s.fhsStore.genesisHash)
	state, hash, err := reloaded.snapshot()
	if err != nil {
		t.Fatalf("reload safety WAL: %v", err)
	}
	return state, hash
}

func resetBranchSafetyRuntime(s *Service) {
	s.fhsStore = newFHSSafetyStore(s.fhsStore.db, s.fhsStore.chainID, s.fhsStore.genesisHash)
	s.fhsHighest, s.fhsSelectedParent, s.fhsParentSelected = nil, nil, false
	s.fhsCertifiedByHash = make(map[common.Hash]*fhsCertifiedProposal)
	s.fhsCertifiedByID = make(map[common.Hash]*fhsCertifiedProposal)
	s.verifiedProposalByID = make(map[common.Hash]*core.VerifiedProposal)
	s.proposalBodies = make(map[common.Hash]*proposalBodyMsg)
	canonical := s.bc.CurrentBlock()
	s.txService.proposedChain.clear(canonical)
	s.currentView.TxHash, s.currentView.TxNumber = canonical.Hash(), canonical.NumberU64()
}

func persistBranchSafetyBodies(t *testing.T, s *Service, certificates ...*fhsCertifiedProposal) {
	t.Helper()
	for _, certificate := range certificates {
		if err := s.persistFHSProposalData(certificate.ref, s.proposalBodies[certificate.ref.ProposalID()]); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFHSBranchRecoveryCommitsEarlierConsecutivePair(t *testing.T) {
	f := newConvergenceFixture(t)
	s := f.replicas[0]
	a := f.proposal(t, nil, 1, 'a')
	b := f.proposal(t, a, 2, 'b')
	c := f.proposal(t, b, 5, 'c')
	persistBranchSafetyBodies(t, s, a, b, c)
	if err := s.adoptFHSHighQC(c.qc, false, false); err != nil {
		t.Fatal(err)
	}
	resetBranchSafetyRuntime(s)
	if err := s.loadFHSWAL(); err != nil {
		t.Fatalf("restore gapped certified chain: %v", err)
	}
	if s.bc.CurrentBlock().Hash() != a.ref.BlockHash || !hotstuff.SignedStateSemanticEqual(s.HighestCertified(), c.qc) {
		t.Fatal("restart did not finish the earlier consecutive-view decision")
	}
}

func TestFHSBranchRecoveryRetainsObservationOutsideCanonicalExecution(t *testing.T) {
	f := newConvergenceFixture(t)
	s := f.replicas[0]
	observation := f.proposal(t, nil, 20, 'o')
	b := f.proposal(t, nil, 10, 'b')
	c := f.proposal(t, b, 11, 'c')
	persistBranchSafetyBodies(t, s, observation, b, c)
	for _, certificate := range []*fhsCertifiedProposal{observation, c} {
		if err := s.adoptFHSHighQC(certificate.qc, false, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.commitFHS2ChainForCertified(c.qc); err != nil {
		t.Fatal(err)
	}
	if s.bc.CurrentBlock().Hash() != b.ref.BlockHash || !hotstuff.SignedStateSemanticEqual(s.HighestCertified(), observation.qc) {
		t.Fatal("fixture did not retain the observed watermark beside the canonical proof")
	}
	resetBranchSafetyRuntime(s)
	if err := s.loadFHSWAL(); err != nil {
		t.Fatalf("an obsolete execution branch prevented canonical recovery: %v", err)
	}
	if s.GetCurrentView().TxHash != b.ref.BlockHash || !hotstuff.SignedStateSemanticEqual(s.HighestCertified(), observation.qc) {
		t.Fatal("recovery confused the advertised observation with the canonical execution parent")
	}
}

func TestFHSBranchMissingContentRecoveryKeepsConsensusGated(t *testing.T) {
	f := newConvergenceFixture(t)
	s := f.replicas[0]
	a := f.proposal(t, nil, 10, 'a')
	if err := s.adoptFHSHighQC(a.qc, false, false); err != nil {
		t.Fatal(err)
	}
	// Certificate and maximum are durable, while the asynchronous body write
	// was interrupted. Restart may advertise the QC but cannot execute it yet.
	if err := rawdb.DeleteFHSProposal(s.fhsStore.db, a.ref.ProposalID()); err != nil {
		t.Fatal(err)
	}
	resetBranchSafetyRuntime(s)
	if err := s.loadFHSWAL(); err != nil {
		t.Fatal(err)
	}
	if !s.hasDeferredFHSRecovery() || !hotstuff.SignedStateSemanticEqual(s.HighestCertified(), a.qc) || s.HasValidatedFHSCertificate(a.qc) {
		t.Fatal("recovery did not distinguish an observed QC from validated content")
	}
	atomic.StoreInt32(&s.runningState, 1)
	t.Cleanup(func() { atomic.StoreInt32(&s.runningState, 0) })
	atomic.StoreInt32(&s.fhsRecoveryRetryQueued, 1) // Suppress a timer in the manually driven recovery loop.
	s.attemptDeferredFHSRecovery()
	if !s.hasDeferredFHSRecovery() || s.fhsHighest != nil || s.bc.CurrentBlockN() != 0 {
		t.Fatal("advertised WAL watermark incorrectly completed missing-content recovery")
	}
}

func TestFHSBranchCanonicalRecertificationPersistsBeforeSelection(t *testing.T) {
	f := newConvergenceFixture(t)
	s := f.replicas[0]
	a := f.proposal(t, nil, 10, 'a')
	b := f.proposal(t, a, 11, 'b')
	if err := s.adoptFHSHighQC(b.qc, false, false); err != nil {
		t.Fatal(err)
	}
	if err := s.commitFHS2ChainForCertified(b.qc); err != nil {
		t.Fatal(err)
	}
	ref := *a.ref
	ref.ViewNumber, ref.ViewID = 20, common.HexToHash("0xc020")
	qc := &hotstuff.SignedState{State: ref.EncodeToBytes(), Number: ref.ViewNumber, ViewID: ref.ViewID, LeaderID: ref.LeaderID, Mask: []byte{0x1f}}
	var aggregate *bls.Sign
	for i := 0; i < 5; i++ {
		signature, err := hotstuff.SignFHSSignatureWithContext(&f.keys[i], f.public[i], qc.State, s.ChainID(), hotstuff.MsgVotePrepare, qc.ViewID, qc.LeaderID)
		if err != nil {
			t.Fatal(err)
		}
		if aggregate == nil {
			aggregate = signature
		} else {
			aggregate.Add(signature)
		}
	}
	qc.Sign = aggregate.Serialize()
	if s.HasValidatedFHSCertificate(qc) {
		t.Fatal("canonical block hash bypassed observation of a new certificate")
	}
	if err := s.SelectFHSProposalParent(qc); !errors.Is(err, hotstuff.ErrProposalValidationPending) {
		t.Fatalf("canonical recertification selected without persisting parent watermark: %v", err)
	}
	key := hotstuff.FHSHighQCValidationKey{TargetView: 21, SelectProposalParent: true}
	output, err := s.stageFHSHighQC(context.Background(), key, qc, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.installStagedFHSHighQC(output, false, false); err != nil {
		t.Fatal(err)
	}
	state, hash := reloadBranchSafetyState(t, s)
	if !hotstuff.SignedStateSemanticEqual(state.HighestQC, qc) || hash != a.ref.BlockHash ||
		!hotstuff.SignedStateSemanticEqual(s.SelectedFHSProposalParent(), qc) {
		t.Fatal("canonical certificate selection did not retain its durable observation")
	}
}

func TestFHSBranchSelectionStagesLowerSiblingWithoutDowngradingWAL(t *testing.T) {
	f := newConvergenceFixture(t)
	s := f.replicas[0]
	lower := f.proposal(t, nil, 10, 'a')
	higher := f.proposal(t, nil, 11, 'b')
	if err := s.adoptFHSHighQC(higher.qc, false, false); err != nil {
		t.Fatal(err)
	}
	if err := s.SelectFHSProposalParent(lower.qc); !errors.Is(err, hotstuff.ErrProposalValidationPending) {
		t.Fatalf("uncached quorum parent must stage before selection: %v", err)
	}
	if !hotstuff.SignedStateSemanticEqual(s.SelectedFHSProposalParent(), higher.qc) {
		t.Fatal("unvalidated lower parent changed execution parent")
	}
	id, err := hotstuff.SignedStateID(lower.qc)
	if err != nil {
		t.Fatal(err)
	}
	key := hotstuff.FHSHighQCValidationKey{QCID: id.Hash(), TargetView: 12, SelectProposalParent: true}
	output, err := s.stageFHSHighQC(context.Background(), key, lower.qc, 0, 0)
	if err != nil {
		t.Fatalf("stage lower certified sibling: %v", err)
	}
	if s.HasValidatedFHSCertificate(lower.qc) || !hotstuff.SignedStateSemanticEqual(s.HighestCertified(), higher.qc) {
		t.Fatal("background staging published certificate state")
	}
	result := &hotstuff.FHSHighQCValidationResult{Key: key, ApplicationData: output}
	if err := s.ApplyFHSHighQCValidation(result); err != nil {
		t.Fatalf("apply lower quorum parent: %v", err)
	}
	s.FinishFHSHighQCValidation(result)
	if !hotstuff.SignedStateSemanticEqual(s.SelectedFHSProposalParent(), lower.qc) || s.GetCurrentView().TxHash != lower.ref.BlockHash {
		t.Fatal("quorum-selected lower parent did not become the execution parent")
	}
	// Read the actual LevelDB bytes through a fresh store before the vote. The
	// observed maximum remains the report watermark while the lower QC and its
	// body are available for the selected execution branch.
	state, hash := reloadBranchSafetyState(t, s)
	if !hotstuff.SignedStateSemanticEqual(state.HighestQC, higher.qc) || hash != higher.ref.BlockHash {
		t.Fatal("selecting lower parent downgraded durable observed maximum")
	}
	if encoded, err := rawdb.ReadFHSCertificate(s.fhsStore.db, lower.ref.ProposalID()); err != nil || len(encoded) == 0 {
		t.Fatalf("selected parent was not durable before voting: bytes=%d err=%v", len(encoded), err)
	}
	child := f.proposal(t, lower, 12, 'c')
	if err := s.validateFHSProposalParent(child.ref, lower.qc); err != nil {
		t.Fatalf("child of selected lower parent was rejected: %v", err)
	}
	encoded := child.ref.EncodeToBytes()
	vote := &hotstuff.PersistedVote{ViewNumber: child.ref.ViewNumber, ViewID: child.ref.ViewID, LeaderID: child.ref.LeaderID,
		ProposalID: child.ref.ProposalID(), ProposalRef: encoded, ProposalRefHash: hotstuff.StateDigest(encoded)}
	if err := s.PersistFHSVote(vote); err != nil {
		t.Fatalf("vote for quorum-selected sibling: %v", err)
	}
	state, hash = reloadBranchSafetyState(t, s)
	if !hotstuff.SignedStateSemanticEqual(state.HighestQC, higher.qc) || hash != higher.ref.BlockHash ||
		state.LastVote == nil || state.LastVote.ProposalID != child.ref.ProposalID() {
		t.Fatal("fresh WAL read lost observed maximum or selected-branch vote")
	}
	wal, ok := s.fhsStore.db.(*leveldb.Database)
	if !ok {
		t.Fatal("branch regression requires the real LevelDB WAL")
	}
	path, chainID, genesisHash := wal.Path(), s.fhsStore.chainID, s.fhsStore.genesisHash
	if err := wal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := leveldb.New(path, 1, 8, "")
	if err != nil {
		t.Fatalf("reopen selected-branch WAL: %v", err)
	}
	t.Cleanup(func() { reopened.Close() })
	s.fhsStore = newFHSSafetyStore(reopened, chainID, genesisHash)
	state, hash = reloadBranchSafetyState(t, s)
	if !hotstuff.SignedStateSemanticEqual(state.HighestQC, higher.qc) || hash != higher.ref.BlockHash ||
		state.LastVote == nil || state.LastVote.ProposalID != child.ref.ProposalID() {
		t.Fatal("reopened LevelDB lost observed maximum or selected-branch vote")
	}
}

func TestFHSBranchSelectionFailurePreservesExecutionState(t *testing.T) {
	for _, scenario := range []string{"invalid_signature", "missing_certificate", "missing_ancestor"} {
		t.Run(scenario, func(t *testing.T) {
			f := newConvergenceFixture(t)
			s := f.replicas[0]
			selected := f.proposal(t, nil, 20, 'h')
			ancestor := f.proposal(t, nil, 10, 'a')
			candidate := f.proposal(t, ancestor, 11, 'c')
			if err := s.adoptFHSHighQC(selected.qc, false, false); err != nil {
				t.Fatal(err)
			}
			if err := s.SelectFHSProposalParent(selected.qc); err != nil {
				t.Fatal(err)
			}
			qc := hotstuff.CloneSignedState(candidate.qc)
			switch scenario {
			case "invalid_signature":
				qc.Sign[0] ^= 1
			case "missing_ancestor":
				// Model a missing cached ancestor without forging either certificate.
				// Selection must preflight the whole branch before publishing a head.
				s.fhsCertifiedByHash[candidate.ref.BlockHash] = candidate
				s.fhsCertifiedByID[candidate.ref.ProposalID()] = candidate
			}
			before := s.GetCurrentView()
			beforeParent := s.txService.currentProposalParent().Hash()
			if err := s.SelectFHSProposalParent(qc); err == nil {
				t.Fatal("invalid or incomplete parent was selected")
			}
			after := s.GetCurrentView()
			if !hotstuff.SignedStateSemanticEqual(s.SelectedFHSProposalParent(), selected.qc) ||
				after.TxHash != before.TxHash || after.TxNumber != before.TxNumber ||
				s.txService.currentProposalParent().Hash() != beforeParent {
				t.Fatal("failed selection partially changed execution state")
			}
		})
	}
}

func TestFHSBranchRawObservationPreservesQuorumSelectedParent(t *testing.T) {
	f := newConvergenceFixture(t)
	s := f.replicas[0]
	selected := f.proposal(t, nil, 10, 'a')
	private := f.proposal(t, nil, 11, 'b')
	if err := s.adoptFHSHighQC(selected.qc, false, false); err != nil {
		t.Fatal(err)
	}
	if err := s.SelectFHSProposalParent(selected.qc); err != nil {
		t.Fatal(err)
	}
	// The replica is already in view 12 when a private view-11 QC arrives.
	// Learning it must update future NewView reports without invalidating the
	// current view's previously verified quorum choice.
	s.currentView.ViewNumber = 11
	if err := s.adoptFHSHighQC(private.qc, false, false); err != nil {
		t.Fatal(err)
	}
	if !hotstuff.SignedStateSemanticEqual(s.HighestCertified(), private.qc) ||
		!hotstuff.SignedStateSemanticEqual(s.SelectedFHSProposalParent(), selected.qc) ||
		s.GetCurrentView().TxHash != selected.ref.BlockHash {
		t.Fatal("private QC replaced a quorum-authorized execution parent")
	}
	child := f.proposal(t, selected, 12, 'c')
	if err := s.validateFHSProposalParent(child.ref, selected.qc); err != nil {
		t.Fatalf("private QC vetoed the quorum-selected child: %v", err)
	}
}

func TestFHSBranchSameBlockRecertifiedInHigherView(t *testing.T) {
	f := newConvergenceFixture(t)
	s := f.replicas[0]
	old := f.proposal(t, nil, 10, 'a')
	newer := f.proposal(t, nil, 11, 'a')
	if old.ref.BlockHash != newer.ref.BlockHash || old.ref.ProposalID() == newer.ref.ProposalID() {
		t.Fatal("fixture must repropose the same block with distinct view-bound proposal identities")
	}
	if err := s.adoptFHSHighQC(old.qc, false, false); err != nil {
		t.Fatal(err)
	}
	if err := s.adoptFHSHighQC(newer.qc, false, false); err != nil {
		t.Fatalf("a valid later QC for the same uncommitted block cannot converge: %v", err)
	}
	if err := s.SelectFHSProposalParent(newer.qc); err != nil {
		t.Fatalf("select recertified block: %v", err)
	}
	child := f.proposal(t, newer, 12, 'c')
	if err := s.validateFHSProposalParent(child.ref, newer.qc); err != nil {
		t.Fatalf("child binding the later certificate was rejected: %v", err)
	}
	state, hash := reloadBranchSafetyState(t, s)
	if !hotstuff.SignedStateSemanticEqual(state.HighestQC, newer.qc) || hash != newer.ref.BlockHash {
		t.Fatal("durable maximum did not retain the later certificate identity")
	}
	olderChild := f.proposal(t, old, 13, 'd')
	for _, candidate := range []*fhsCertifiedProposal{child, olderChild} {
		if err := s.adoptFHSHighQC(candidate.qc, false, false); err != nil {
			t.Fatalf("adopt child with an exact earlier certificate binding: %v", err)
		}
	}
	if parent := fhsCertifiedParent(s.fhsCertifiedByID, olderChild); parent == nil || !hotstuff.SignedStateSemanticEqual(parent.qc, old.qc) {
		t.Fatal("a later certification replaced an earlier child's parent identity")
	}
	if target := fhs2ChainCommitTarget(s.fhsCertifiedByID, child); target == nil || !hotstuff.SignedStateSemanticEqual(target.qc, newer.qc) {
		t.Fatal("finality selected the wrong certificate for a recertified block")
	}
	for _, certificate := range []*fhsCertifiedProposal{old, newer} {
		if encoded, err := rawdb.ReadFHSCertificate(s.fhsStore.db, certificate.ref.ProposalID()); err != nil || len(encoded) == 0 {
			t.Fatalf("lost distinct durable certificate: bytes=%d err=%v", len(encoded), err)
		}
	}
}

func TestFHSBranchFsyncFailurePublishesNoPartialCertificateState(t *testing.T) {
	f := newConvergenceFixture(t)
	s := f.replicas[0]
	old := f.proposal(t, nil, 10, 'a')
	newer := f.proposal(t, nil, 11, 'b')
	if err := s.adoptFHSHighQC(old.qc, false, false); err != nil {
		t.Fatal(err)
	}
	if err := s.SelectFHSProposalParent(old.qc); err != nil {
		t.Fatal(err)
	}
	output, err := s.stageFHSHighQC(context.Background(), hotstuff.FHSHighQCValidationKey{SelectProposalParent: true}, newer.qc, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	before := s.GetCurrentView()
	beforeHashes, beforeIDs, beforeVerified := len(s.fhsCertifiedByHash), len(s.fhsCertifiedByID), len(s.verifiedProposalByID)
	underlying := s.fhsStore.db
	s.fhsStore.db = &failingSyncStore{KeyValueStore: underlying}
	err = s.installStagedFHSHighQC(output, false, false)
	s.fhsStore.db = underlying
	if err == nil || !strings.Contains(err.Error(), "injected fsync failure") {
		t.Fatalf("wanted injected durable-write failure, got %v", err)
	}
	state, hash := reloadBranchSafetyState(t, s)
	if !hotstuff.SignedStateSemanticEqual(s.HighestCertified(), old.qc) || !hotstuff.SignedStateSemanticEqual(state.HighestQC, old.qc) ||
		hash != old.ref.BlockHash || !hotstuff.SignedStateSemanticEqual(s.SelectedFHSProposalParent(), old.qc) ||
		s.GetCurrentView().TxHash != before.TxHash || len(s.fhsCertifiedByHash) != beforeHashes ||
		len(s.fhsCertifiedByID) != beforeIDs || len(s.verifiedProposalByID) != beforeVerified {
		t.Fatal("failed fsync published partial branch, maximum, or execution state")
	}
	if encoded, err := rawdb.ReadFHSCertificate(underlying, newer.ref.ProposalID()); err != nil || len(encoded) != 0 {
		t.Fatalf("failed fsync left durable certificate: bytes=%d err=%v", len(encoded), err)
	}
	// An uncertain synchronous write is fail-stop for this store instance.
	// Merely restoring the transport cannot clear that safety guard; recovery
	// must reread the durable state through a new store, as a restart would.
	if err := s.installStagedFHSHighQC(output, false, false); err == nil {
		t.Fatal("failed safety store resumed without recovery")
	}
	s.fhsStore = newFHSSafetyStore(underlying, s.fhsStore.chainID, s.fhsStore.genesisHash)
	if err := s.installStagedFHSHighQC(output, false, false); err != nil {
		t.Fatalf("retrying the same verified branch after store recovery failed: %v", err)
	}
	if !hotstuff.SignedStateSemanticEqual(s.HighestCertified(), newer.qc) || !hotstuff.SignedStateSemanticEqual(s.SelectedFHSProposalParent(), newer.qc) {
		t.Fatal("successful retry did not publish the complete branch")
	}
}
