package reconfig

import (
	"errors"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/ethdb/memorydb"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

type failingSyncStore struct{ ethdb.KeyValueStore }

func (store *failingSyncStore) NewBatch() ethdb.Batch {
	return &failingSyncBatch{Batch: store.KeyValueStore.NewBatch()}
}

type failingSyncBatch struct{ ethdb.Batch }

func (*failingSyncBatch) WriteSync() error { return errors.New("injected fsync failure") }

func TestFHSSafetyStoreRejectsCorruptOrForeignWAL(t *testing.T) {
	db := memorydb.New()
	store := newFHSSafetyStore(db, 101, common.HexToHash("0xabc"))
	if err := store.load(); err != nil {
		t.Fatalf("empty safety store did not initialize: %v", err)
	}

	foreign := &fhsDiskSafety{
		Version:     fhsDiskVersion,
		ChainID:     202,
		GenesisHash: common.HexToHash("0xabc"),
		State:       hotstuff.NewFHSSafetyState(),
	}
	encoded, err := rlp.EncodeToBytes(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if err := rawdb.WriteFHSSafetyState(db, encoded); err != nil {
		t.Fatal(err)
	}
	foreignStore := newFHSSafetyStore(db, 101, common.HexToHash("0xabc"))
	if err := foreignStore.load(); err == nil {
		t.Fatal("foreign-chain safety WAL was accepted")
	}

	if err := rawdb.WriteFHSSafetyState(db, []byte{0xff, 0x01}); err != nil {
		t.Fatal(err)
	}
	corruptStore := newFHSSafetyStore(db, 101, common.HexToHash("0xabc"))
	if err := corruptStore.load(); err == nil {
		t.Fatal("corrupt safety WAL was silently treated as empty")
	}
}

func TestFHSBatchSupportsSynchronousWrite(t *testing.T) {
	db := memorydb.New()
	batch := db.NewBatch()
	if err := rawdb.WriteFHSSafetyState(batch, []byte("durable")); err != nil {
		t.Fatal(err)
	}
	if err := writeFHSBatchSync(batch); err != nil {
		t.Fatalf("synchronous batch failed: %v", err)
	}
	got, err := rawdb.ReadFHSSafetyState(db)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "durable" {
		t.Fatalf("synchronous batch wrote %q", got)
	}
}

func TestPersistedVoteEqualityRejectsEquivocation(t *testing.T) {
	vote := &hotstuff.PersistedVote{
		ViewNumber: 8,
		ViewID:     common.HexToHash("0x800"),
		LeaderID:   "leader",
		TState:     []byte("proposal-a"),
		TStateHash: hotstuff.StateDigest([]byte("proposal-a")),
	}
	if err := validatePersistedVote(vote); err != nil {
		t.Fatalf("valid vote rejected: %v", err)
	}
	same := hotstuff.ClonePersistedVote(vote)
	if !persistedVotesEqual(vote, same) {
		t.Fatal("same vote does not compare equal")
	}
	conflict := hotstuff.ClonePersistedVote(vote)
	conflict.TState = []byte("proposal-b")
	conflict.TStateHash = hotstuff.StateDigest(conflict.TState)
	if persistedVotesEqual(vote, conflict) {
		t.Fatal("same-view conflicting votes compare equal")
	}
}

func TestFHSRestartRejectsConflictingSameViewVote(t *testing.T) {
	db := memorydb.New()
	config := &params.ChainConfig{ChainID: big.NewInt(101), FairHotstuff: true}
	genesis := common.HexToHash("0xabc")
	first := &Service{chainConfig: config, fhsStore: newFHSSafetyStore(db, 101, genesis)}
	vote := &hotstuff.PersistedVote{
		ViewNumber: 9,
		ViewID:     common.HexToHash("0x900"),
		LeaderID:   "leader",
		KState:     []byte("proposal-a"),
		KStateHash: hotstuff.StateDigest([]byte("proposal-a")),
	}
	if err := first.PersistFHSVote(vote); err != nil {
		t.Fatalf("persist first vote: %v", err)
	}

	// Construct a new Service/store over the same DB to model a process restart.
	restarted := &Service{chainConfig: config, fhsStore: newFHSSafetyStore(db, 101, genesis)}
	if err := restarted.PersistFHSVote(hotstuff.ClonePersistedVote(vote)); err != nil {
		t.Fatalf("idempotent vote rejected after restart: %v", err)
	}
	conflict := hotstuff.ClonePersistedVote(vote)
	conflict.KState = []byte("proposal-b")
	conflict.KStateHash = hotstuff.StateDigest(conflict.KState)
	if err := restarted.PersistFHSVote(conflict); err == nil {
		t.Fatal("conflicting same-view vote accepted after restart")
	}
}

func TestFHSVoteFsyncFailureLeavesNoDurableVote(t *testing.T) {
	underlying := memorydb.New()
	db := &failingSyncStore{KeyValueStore: underlying}
	service := &Service{
		chainConfig: &params.ChainConfig{ChainID: big.NewInt(101), FairHotstuff: true},
		fhsStore:    newFHSSafetyStore(db, 101, common.HexToHash("0xabc")),
	}
	vote := &hotstuff.PersistedVote{
		ViewNumber: 10,
		ViewID:     common.HexToHash("0x1000"),
		LeaderID:   "leader",
		KState:     []byte("proposal"),
		KStateHash: hotstuff.StateDigest([]byte("proposal")),
	}
	if err := service.PersistFHSVote(vote); err == nil {
		t.Fatal("vote persistence succeeded despite injected fsync failure")
	}
	encoded, err := rawdb.ReadFHSSafetyState(underlying)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != 0 {
		t.Fatal("failed fsync published a durable safety vote")
	}
}

func TestFHSProposalCommitmentsRejectAlteredRecoveryProofs(t *testing.T) {
	service, body := testProposalSidecar(t)
	block := types.DecodeToBlock(body.EncodedBlock)
	if block == nil {
		t.Fatal("decode proposal fixture")
	}
	ref, err := types.NewHotstuffProposalRefWithProof(
		service.ChainID(), body.ViewNumber, body.ViewID, body.LeaderID,
		block, body.EncodedBlock, body.Extra, common.Hash{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateFHSProposalCommitments(ref, body.EncodedBlock, body.Extra, nil); err != nil {
		t.Fatalf("valid recovery proposal rejected: %v", err)
	}
	if _, err := validateFHSProposalCommitments(ref, body.EncodedBlock, []byte("altered-proof"), nil); err == nil {
		t.Fatal("altered recovery extra proof was accepted")
	}
	wrongParent := *ref
	wrongParent.ParentQCID = common.HexToHash("0x1234")
	if _, err := validateFHSProposalCommitments(&wrongParent, body.EncodedBlock, body.Extra, nil); err == nil {
		t.Fatal("missing recovery parent QC was accepted against a nonzero commitment")
	}
}

func TestFHSRestartValidatesLastVoteProposalRecord(t *testing.T) {
	service, body := testProposalSidecar(t)
	service.chainConfig.FairHotstuff = true
	db := memorydb.New()
	service.fhsStore = newFHSSafetyStore(db, service.ChainID(), common.HexToHash("0xabc"))
	block := types.DecodeToBlock(body.EncodedBlock)
	if block == nil {
		t.Fatal("decode proposal fixture")
	}
	ref, err := types.NewHotstuffProposalRefWithProof(
		service.ChainID(), body.ViewNumber, body.ViewID, body.LeaderID,
		block, body.EncodedBlock, body.Extra, common.Hash{},
	)
	if err != nil {
		t.Fatal(err)
	}
	vote := &hotstuff.PersistedVote{
		ViewNumber: ref.ViewNumber,
		ViewID:     ref.ViewID,
		LeaderID:   ref.LeaderID,
		TState:     ref.EncodeToBytes(),
		TStateHash: hotstuff.StateDigest(ref.EncodeToBytes()),
		Extra:      append([]byte(nil), body.Extra...),
	}
	proposal := &fhsDiskProposal{
		Version:      fhsDiskVersion,
		ProposalID:   ref.ProposalID(),
		ProposalRef:  append([]byte(nil), vote.TState...),
		EncodedBlock: append([]byte(nil), body.EncodedBlock...),
		Extra:        append([]byte(nil), body.Extra...),
	}
	encoded, err := rlp.EncodeToBytes(proposal)
	if err != nil {
		t.Fatal(err)
	}
	if err := rawdb.WriteFHSProposal(db, proposal.ProposalID, encoded); err != nil {
		t.Fatal(err)
	}
	if err := service.validateRestoredFHSVote(vote); err != nil {
		t.Fatalf("valid durable vote proposal rejected: %v", err)
	}
	proposal.Extra = []byte("altered-after-vote")
	encoded, err = rlp.EncodeToBytes(proposal)
	if err != nil {
		t.Fatal(err)
	}
	if err := rawdb.WriteFHSProposal(db, proposal.ProposalID, encoded); err != nil {
		t.Fatal(err)
	}
	if err := service.validateRestoredFHSVote(vote); err == nil {
		t.Fatal("altered durable vote proposal was accepted after restart")
	}
}

func TestFHSRestartPendingTimeoutUsesUncommittedHighestQC(t *testing.T) {
	state := hotstuff.NewFHSSafetyState()
	state.HighestQC = &hotstuff.SignedState{Number: 10}
	if got := fhsRecoveryBaseView(8, state); got != 10 {
		t.Fatalf("recovery base view = %d, want uncommitted highest QC view 10", got)
	}
	state.HighestTC = &hotstuff.TimeoutCertificate{
		Statement: hotstuff.TimeoutStatement{TimedOutView: 12},
	}
	if got := fhsRecoveryBaseView(8, state); got != 12 {
		t.Fatalf("recovery base view = %d, want highest timeout view 12", got)
	}
}

func TestFHSCertificateAtomicallyClearsSupersededTimeoutVote(t *testing.T) {
	service, body := testProposalSidecar(t)
	service.chainConfig.FairHotstuff = true
	db := memorydb.New()
	genesis := common.HexToHash("0xabc")
	service.fhsStore = newFHSSafetyStore(db, service.ChainID(), genesis)

	block := types.DecodeToBlock(body.EncodedBlock)
	if block == nil {
		t.Fatal("decode proposal fixture")
	}
	ref, err := types.NewHotstuffProposalRefWithProof(
		service.ChainID(), body.ViewNumber, body.ViewID, body.LeaderID,
		block, body.EncodedBlock, body.Extra, common.Hash{},
	)
	if err != nil {
		t.Fatal(err)
	}
	state := hotstuff.NewFHSSafetyState()
	state.LastTimeoutVote = &hotstuff.TimeoutStatement{
		ChainID:      service.ChainID(),
		TimedOutView: ref.ViewNumber,
	}
	encoded, err := service.fhsStore.encodeSafety(state, common.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	if err := rawdb.WriteFHSSafetyState(db, encoded); err != nil {
		t.Fatal(err)
	}
	qc := &hotstuff.SignedState{
		State:    ref.EncodeToBytes(),
		Number:   ref.ViewNumber,
		ViewID:   ref.ViewID,
		LeaderID: ref.LeaderID,
	}
	if err := service.persistFHSCertificate(ref, qc, body, body.Extra); err != nil {
		t.Fatalf("persist certificate: %v", err)
	}

	// Load through a fresh store to assert the timeout cleanup and QC landed in
	// the same durable transaction rather than only changing live memory.
	restarted := newFHSSafetyStore(db, service.ChainID(), genesis)
	recovered, _, err := restarted.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if recovered.LastTimeoutVote != nil {
		t.Fatalf("superseded timeout vote survived QC persistence: %+v", recovered.LastTimeoutVote)
	}
	if recovered.HighestQC == nil || recovered.HighestQC.Number != ref.ViewNumber {
		t.Fatalf("highest QC was not persisted with timeout cleanup: %+v", recovered.HighestQC)
	}
	staleTimeout := &hotstuff.TimeoutStatement{
		Version:       recovered.Version,
		ChainID:       service.ChainID(),
		TimedOutView:  ref.ViewNumber,
		KeyHash:       common.HexToHash("0x01"),
		CommitteeHash: common.HexToHash("0x02"),
	}
	service.fhsStore = restarted
	if err := service.PersistFHSTimeoutVote(staleTimeout); err == nil {
		t.Fatal("timeout vote at an already certified QC view was accepted")
	}
}

func TestFHSRestartRejectsKeyStateOnlyVote(t *testing.T) {
	service := &Service{chainConfig: &params.ChainConfig{ChainID: big.NewInt(101), FairHotstuff: true}}
	vote := &hotstuff.PersistedVote{
		ViewNumber: 13,
		ViewID:     common.HexToHash("0x1300"),
		LeaderID:   "leader",
		KState:     []byte("key-only"),
		KStateHash: hotstuff.StateDigest([]byte("key-only")),
	}
	if err := service.validateRestoredFHSVote(vote); err == nil {
		t.Fatal("FHS v3 restart accepted a key-state-only safety vote")
	}
}
