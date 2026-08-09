package reconfig

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/ethdb/memorydb"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
	"github.com/zeebo/blake3"
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
	restoredBody, err := service.restoredFHSVoteProposal(vote)
	if err != nil {
		t.Fatalf("load durable vote proposal: %v", err)
	}
	if err := service.installRestoredFHSVoteProposal(restoredBody); err != nil {
		t.Fatalf("hydrate durable vote proposal cache: %v", err)
	}
	if got := service.getProposalBody(ref.ProposalID()); got == nil ||
		!bytes.Equal(got.EncodedBlock, body.EncodedBlock) || !bytes.Equal(got.Extra, body.Extra) {
		t.Fatalf("hydrated durable proposal mismatch: %+v", got)
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

func TestValidateCanonicalFHSQCAdvanceRequiresExactAncestor(t *testing.T) {
	makeQC := func(blockNumber, view uint64, blockHash common.Hash) (*types.HotstuffProposalRef, *hotstuff.SignedState) {
		ref := &types.HotstuffProposalRef{
			Version:    types.HotstuffProposalRefVersion,
			ChainID:    101,
			Number:     blockNumber,
			BlockHash:  blockHash,
			ParentHash: common.BigToHash(new(big.Int).SetUint64(blockNumber + 100)),
			BodyHash:   common.BigToHash(new(big.Int).SetUint64(blockNumber + 200)),
			BodySize:   1,
			ExtraHash:  common.BigToHash(new(big.Int).SetUint64(blockNumber + 300)),
			ViewNumber: view,
			ViewID:     common.BigToHash(new(big.Int).SetUint64(view)),
			LeaderID:   "leader",
		}
		return ref, &hotstuff.SignedState{
			State: ref.EncodeToBytes(), Number: view, ViewID: ref.ViewID, LeaderID: ref.LeaderID,
		}
	}
	oldHash := common.HexToHash("0x1001")
	targetHash := common.HexToHash("0x1004")
	_, oldQC := makeQC(1, 10, oldHash)
	targetRef, targetQC := makeQC(4, 40, targetHash)
	verify := func(qc *hotstuff.SignedState) (*types.HotstuffProposalRef, error) {
		return types.DecodeHotstuffProposalRef(qc.State)
	}

	advance, err := validateCanonicalFHSQCAdvance(
		oldQC, oldHash, targetRef, targetQC, targetHash, verify,
		func(number uint64, hash common.Hash) bool { return number == 1 && hash == oldHash },
	)
	if err != nil || !advance {
		t.Fatalf("exact canonical ancestor gap rejected: advance=%v err=%v", advance, err)
	}
	if _, err := validateCanonicalFHSQCAdvance(
		oldQC, oldHash, targetRef, targetQC, targetHash, verify,
		func(uint64, common.Hash) bool { return false },
	); err == nil {
		t.Fatal("noncanonical prior QC was accepted across a sync gap")
	}

	advance, err = validateCanonicalFHSQCAdvance(
		targetQC, targetHash, targetRef, targetQC, targetHash, verify,
		func(uint64, common.Hash) bool { return true },
	)
	if err != nil || advance {
		t.Fatalf("idempotent canonical watermark was not a no-op: advance=%v err=%v", advance, err)
	}
	conflictRef, conflictQC := makeQC(4, 40, common.HexToHash("0x2004"))
	if _, err := validateCanonicalFHSQCAdvance(
		conflictQC, conflictRef.BlockHash, targetRef, targetQC, targetHash, verify,
		func(uint64, common.Hash) bool { return true },
	); err == nil {
		t.Fatal("conflicting same-view canonical watermark was accepted")
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
	state.LastTimeoutView = ref.ViewNumber
	state.HighestTC = &hotstuff.TimeoutCertificate{
		Statement: hotstuff.TimeoutStatement{
			ChainID:      service.ChainID(),
			TimedOutView: ref.ViewNumber,
		},
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
	if err := service.persistFHSCertificateWithBroadcast(ref, qc, body, body.Extra, true); err != nil {
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
	if recovered.HighestTC != nil || recovered.LastTimeoutView != 0 {
		t.Fatalf("superseded timeout certificate survived QC persistence: tc=%+v view=%d", recovered.HighestTC, recovered.LastTimeoutView)
	}
	if recovered.HighestQC == nil || recovered.HighestQC.Number != ref.ViewNumber {
		t.Fatalf("highest QC was not persisted with timeout cleanup: %+v", recovered.HighestQC)
	}
	pending, err := restarted.pendingBroadcastSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !hotstuff.SignedStateSemanticEqual(pending, qc) {
		t.Fatalf("leader QC restart outbox mismatch: %+v", pending)
	}
	if err := restarted.clearPendingBroadcast(qc); err != nil {
		t.Fatalf("complete canonical QC outbox: %v", err)
	}
	reopened := newFHSSafetyStore(db, service.ChainID(), genesis)
	cleared, err := reopened.pendingBroadcastSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if cleared != nil {
		t.Fatalf("completed QC outbox survived restart: %+v", cleared)
	}
	reopenedState, _, err := reopened.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !hotstuff.SignedStateSemanticEqual(reopenedState.HighestQC, qc) {
		t.Fatalf("clearing outbox altered highest QC: %+v", reopenedState.HighestQC)
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

type fhsEpochTestBackend struct{}

func (*fhsEpochTestBackend) BlockChain() *core.BlockChain       { return nil }
func (*fhsEpochTestBackend) KeyBlockChain() *core.KeyBlockChain { return nil }
func (*fhsEpochTestBackend) CandidatePool() *core.CandidatePool { return nil }
func (*fhsEpochTestBackend) Engine() consensus.Engine           { return nil }

type fhsEpochTestFixture struct {
	service     *Service
	db          ethdb.Database
	keys        []bls.SecretKey
	public      []*bls.PublicKey
	historical  *types.KeyBlock
	current     *types.KeyBlock
	committee   *bftview.Committee
	genesisHash common.Hash
}

func newFHSEpochTestFixture(t *testing.T) *fhsEpochTestFixture {
	t.Helper()
	const chainID = uint64(101)
	db := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { db.Close() })

	keys := make([]bls.SecretKey, 4)
	public := make([]*bls.PublicKey, len(keys))
	committee := &bftview.Committee{List: make([]*common.Cnode, len(keys))}
	for index := range keys {
		keys[index].SetByCSPRNG()
		public[index] = keys[index].GetPublicKey()
		committee.List[index] = &common.Cnode{
			Address:  "validator-" + string(rune('a'+index)),
			CoinBase: "coinbase-" + string(rune('a'+index)),
			Public:   public[index].SerializeToHexStr(),
		}
	}
	historical := types.NewKeyBlock(&types.KeyBlockHeader{
		Difficulty:    big.NewInt(1),
		Number:        big.NewInt(0),
		Time:          1,
		CommitteeHash: committee.RlpHash(),
	})
	current := types.NewKeyBlock(&types.KeyBlockHeader{
		ParentHash:    historical.Hash(),
		Difficulty:    big.NewInt(1),
		Number:        big.NewInt(1),
		Time:          2,
		CommitteeHash: committee.RlpHash(),
	})
	for _, block := range []*types.KeyBlock{historical, current} {
		rawdb.WriteKeyBlock(db, block)
		rawdb.WriteKeyBlockHash(db, block.Hash(), block.NumberU64())
		rawdb.WriteTd(db, block.Hash(), block.NumberU64(), block.Difficulty())
	}
	rawdb.WriteHeadKeyBlockHash(db, current.Hash())
	rawdb.WriteHeadKeyHeaderHash(db, current.Hash())
	bftview.SetCommitteeConfig(db, nil, nil)
	if !bftview.WriteCommittee(historical.NumberU64(), historical.Hash(), committee) ||
		!bftview.WriteCommittee(current.NumberU64(), current.Hash(), committee) {
		t.Fatal("store FHS epoch test committees")
	}
	config := &params.ChainConfig{ChainID: new(big.Int).SetUint64(chainID), FairHotstuff: true}
	kbc, err := core.NewKeyBlockChain(&fhsEpochTestBackend{}, db, nil, config, nil, new(event.TypeMux))
	if err != nil {
		t.Fatalf("create key block chain: %v", err)
	}
	genesisHash := common.HexToHash("0xf105")
	service := &Service{
		chainConfig: config,
		kbc:         kbc,
		currentView: bftview.View{
			KeyNumber:     current.NumberU64(),
			KeyHash:       current.Hash(),
			CommitteeHash: current.CommitteeHash(),
			ViewNumber:    20,
		},
		fhsStore: newFHSSafetyStore(db, chainID, genesisHash),
	}
	return &fhsEpochTestFixture{
		service: service, db: db, keys: keys, public: public,
		historical: historical, current: current, committee: committee, genesisHash: genesisHash,
	}
}

func fhsEpochTestTC(t *testing.T, statement hotstuff.TimeoutStatement, keys []bls.SecretKey, public []*bls.PublicKey) *hotstuff.TimeoutCertificate {
	t.Helper()
	baseDigest, err := hotstuff.TimeoutStatementDigest(&statement)
	if err != nil {
		t.Fatal(err)
	}
	threshold := hotstuff.CalcThreshold(len(keys))
	mask := make([]byte, (len(keys)+7)/8)
	var aggregate *bls.Sign
	for index := 0; index < threshold; index++ {
		encoded, err := rlp.EncodeToBytes([]interface{}{
			[]byte("cypher-fhs-signer-v3"), uint32(3), baseDigest, public[index].Serialize(),
		})
		if err != nil {
			t.Fatal(err)
		}
		digest := blake3.Sum256(encoded)
		signature := keys[index].SignHash(digest[:])
		if aggregate == nil {
			aggregate = signature
		} else {
			aggregate.Add(signature)
		}
		mask[index/8] |= 1 << uint(index&7)
	}
	tc := &hotstuff.TimeoutCertificate{Statement: statement, Sign: aggregate.Serialize(), Mask: mask}
	if err := hotstuff.VerifyTimeoutCertificate(tc, public, threshold); err != nil {
		t.Fatalf("invalid timeout certificate fixture: %v", err)
	}
	return tc
}

func persistFHSEpochTestState(t *testing.T, fixture *fhsEpochTestFixture, state *hotstuff.FHSSafetyState, highestHash common.Hash) *hotstuff.FHSSafetyState {
	t.Helper()
	encoded, err := fixture.service.fhsStore.encodeSafety(state, highestHash)
	if err != nil {
		t.Fatal(err)
	}
	if err := rawdb.WriteFHSSafetyState(fixture.db, encoded); err != nil {
		t.Fatal(err)
	}
	recovered, recoveredHighest, err := fixture.service.fhsStore.recoverySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if recoveredHighest != highestHash {
		t.Fatalf("highest certificate pointer = %s, want %s", recoveredHighest, highestHash)
	}
	return recovered
}

func TestReconcileFHSTimeoutEpochClearsCanonicalHistoricalTimeouts(t *testing.T) {
	fixture := newFHSEpochTestFixture(t)
	historical := hotstuff.TimeoutStatement{
		Version: 3, ChainID: fixture.service.ChainID(), TimedOutView: 19,
		KeyNumber: fixture.historical.NumberU64(), KeyHash: fixture.historical.Hash(),
		CommitteeHash: fixture.historical.CommitteeHash(),
	}
	state := hotstuff.NewFHSSafetyState()
	state.LastVote = &hotstuff.PersistedVote{
		ViewNumber: 18, ViewID: common.HexToHash("0x1800"), LeaderID: "leader",
		TState: []byte("proposal"), TStateHash: hotstuff.StateDigest([]byte("proposal")),
	}
	state.HighestQC = &hotstuff.SignedState{
		State: []byte("highest-qc"), Number: 18,
		ViewID: common.HexToHash("0x1801"), LeaderID: "leader",
	}
	state.LastTimeoutVote = &historical
	state.LastTimeoutView = historical.TimedOutView
	state.HighestTC = fhsEpochTestTC(t, historical, fixture.keys, fixture.public)
	highestHash := common.HexToHash("0xcafe")
	recovered := persistFHSEpochTestState(t, fixture, state, highestHash)

	reconciled, err := fixture.service.reconcileFHSTimeoutEpoch(recovered, highestHash)
	if err != nil {
		t.Fatalf("reconcile historical timeout epoch: %v", err)
	}
	if reconciled.LastTimeoutVote != nil || reconciled.HighestTC != nil || reconciled.LastTimeoutView != 0 {
		t.Fatalf("historical timeout state survived reconciliation: %+v", reconciled)
	}
	if !persistedVotesEqual(reconciled.LastVote, state.LastVote) {
		t.Fatalf("reconciliation altered last vote: %+v", reconciled.LastVote)
	}
	if !hotstuff.SignedStateSemanticEqual(reconciled.HighestQC, state.HighestQC) {
		t.Fatalf("reconciliation altered highest QC: %+v", reconciled.HighestQC)
	}

	reopened := newFHSSafetyStore(fixture.db, fixture.service.ChainID(), fixture.genesisHash)
	durable, durableHighest, err := reopened.recoverySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if durable.LastTimeoutVote != nil || durable.HighestTC != nil || durable.LastTimeoutView != 0 {
		t.Fatalf("historical timeout cleanup was not durable: %+v", durable)
	}
	if !persistedVotesEqual(durable.LastVote, state.LastVote) || !hotstuff.SignedStateSemanticEqual(durable.HighestQC, state.HighestQC) {
		t.Fatal("durable timeout cleanup altered global FHS safety watermarks")
	}
	if durableHighest != highestHash {
		t.Fatalf("durable highest certificate pointer = %s, want %s", durableHighest, highestHash)
	}
}

func TestReconcileFHSTimeoutEpochRetainsCurrentTimeouts(t *testing.T) {
	fixture := newFHSEpochTestFixture(t)
	certified := hotstuff.TimeoutStatement{
		Version: 3, ChainID: fixture.service.ChainID(), TimedOutView: 20,
		KeyNumber: fixture.current.NumberU64(), KeyHash: fixture.current.Hash(),
		CommitteeHash: fixture.current.CommitteeHash(),
	}
	pending := certified
	pending.TimedOutView++
	state := hotstuff.NewFHSSafetyState()
	state.LastTimeoutVote = &pending
	state.LastTimeoutView = certified.TimedOutView
	state.HighestTC = fhsEpochTestTC(t, certified, fixture.keys, fixture.public)
	highestHash := common.HexToHash("0xbeef")
	recovered := persistFHSEpochTestState(t, fixture, state, highestHash)

	reconciled, err := fixture.service.reconcileFHSTimeoutEpoch(recovered, highestHash)
	if err != nil {
		t.Fatalf("current timeout epoch rejected: %v", err)
	}
	if reconciled.LastTimeoutVote == nil || *reconciled.LastTimeoutVote != pending ||
		reconciled.HighestTC == nil || reconciled.HighestTC.Statement != certified ||
		reconciled.LastTimeoutView != certified.TimedOutView {
		t.Fatalf("current timeout state was changed: %+v", reconciled)
	}
	if _, err := fixture.service.validateFHSTimeoutState(reconciled); err != nil {
		t.Fatalf("retained current timeout state is not active: %v", err)
	}
}

func TestReconcileFHSTimeoutEpochRejectsInactiveNonHistoricalMetadata(t *testing.T) {
	fixture := newFHSEpochTestFixture(t)
	siblingCurrent := types.NewKeyBlock(&types.KeyBlockHeader{
		ParentHash: fixture.historical.Hash(), Difficulty: big.NewInt(1),
		Number: big.NewInt(1), Time: 99, CommitteeHash: fixture.committee.RlpHash(),
	})
	siblingHistorical := types.NewKeyBlock(&types.KeyBlockHeader{
		Difficulty: big.NewInt(1), Number: big.NewInt(0), Time: 99,
		CommitteeHash: fixture.committee.RlpHash(),
	})
	// Make both siblings fully known, while deliberately leaving the canonical
	// number-to-hash mappings on fixture.historical and fixture.current.
	for _, sibling := range []*types.KeyBlock{siblingCurrent, siblingHistorical} {
		rawdb.WriteKeyBlock(fixture.db, sibling)
		if !bftview.WriteCommittee(sibling.NumberU64(), sibling.Hash(), fixture.committee) {
			t.Fatal("store noncanonical sibling committee")
		}
	}

	tests := []struct {
		name      string
		number    uint64
		keyHash   common.Hash
		committee common.Hash
	}{
		{name: "same-height sibling", number: 1, keyHash: siblingCurrent.Hash(), committee: siblingCurrent.CommitteeHash()},
		{name: "future", number: 2, keyHash: common.HexToHash("0xf002"), committee: fixture.current.CommitteeHash()},
		{name: "noncanonical historical", number: 0, keyHash: siblingHistorical.Hash(), committee: siblingHistorical.CommitteeHash()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := hotstuff.NewFHSSafetyState()
			state.LastTimeoutVote = &hotstuff.TimeoutStatement{
				Version: 3, ChainID: fixture.service.ChainID(), TimedOutView: 21,
				KeyNumber: test.number, KeyHash: test.keyHash, CommitteeHash: test.committee,
			}
			if _, err := fixture.service.reconcileFHSTimeoutEpoch(state, common.Hash{}); err == nil {
				t.Fatal("inactive non-historical timeout metadata was accepted")
			}
		})
	}
}
