package reconfig

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math/big"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

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
	"github.com/cypherium/cypher/rnet/network"
	"github.com/zeebo/blake3"
)

type failingSyncStore struct{ ethdb.KeyValueStore }

func (store *failingSyncStore) NewBatch() ethdb.Batch {
	return &failingSyncBatch{Batch: store.KeyValueStore.NewBatch()}
}

type failingSyncBatch struct{ ethdb.Batch }

func (*failingSyncBatch) WriteSync() error { return errors.New("injected fsync failure") }

type fhsBodyWriteCountingStore struct {
	ethdb.KeyValueStore
	bodyWrites int
	bodyReads  int
}

func (store *fhsBodyWriteCountingStore) countBodyWrite(key []byte) {
	if bytes.HasPrefix(key, []byte("cypher-fhs-body/")) {
		store.bodyWrites++
	}
}

func (store *fhsBodyWriteCountingStore) Put(key, value []byte) error {
	store.countBodyWrite(key)
	return store.KeyValueStore.Put(key, value)
}

func (store *fhsBodyWriteCountingStore) Get(key []byte) ([]byte, error) {
	if bytes.HasPrefix(key, []byte("cypher-fhs-body/")) {
		store.bodyReads++
	}
	return store.KeyValueStore.Get(key)
}

func (store *fhsBodyWriteCountingStore) NewBatch() ethdb.Batch {
	return &fhsBodyWriteCountingBatch{
		Batch:        store.KeyValueStore.NewBatch(),
		countBodyPut: store.countBodyWrite,
	}
}

type fhsBodyWriteCountingBatch struct {
	ethdb.Batch
	countBodyPut func([]byte)
}

func (batch *fhsBodyWriteCountingBatch) Put(key, value []byte) error {
	batch.countBodyPut(key)
	return batch.Batch.Put(key, value)
}

func (batch *fhsBodyWriteCountingBatch) WriteSync() error {
	syncBatch, ok := batch.Batch.(ethdb.SyncBatch)
	if !ok {
		return errors.New("wrapped database does not support synchronous writes")
	}
	return syncBatch.WriteSync()
}

type fhsDeleteCountingStore struct {
	ethdb.KeyValueStore
	directDeletes int
	batchDeletes  int
	batchWrites   int
}

func (store *fhsDeleteCountingStore) Delete(key []byte) error {
	store.directDeletes++
	return store.KeyValueStore.Delete(key)
}

func (store *fhsDeleteCountingStore) NewBatch() ethdb.Batch {
	return &fhsDeleteCountingBatch{Batch: store.KeyValueStore.NewBatch(), store: store}
}

type fhsDeleteCountingBatch struct {
	ethdb.Batch
	store *fhsDeleteCountingStore
}

func (batch *fhsDeleteCountingBatch) Delete(key []byte) error {
	batch.store.batchDeletes++
	return batch.Batch.Delete(key)
}

func (batch *fhsDeleteCountingBatch) Write() error {
	batch.store.batchWrites++
	return batch.Batch.Write()
}

func (batch *fhsDeleteCountingBatch) WriteSync() error {
	batch.store.batchWrites++
	syncBatch, ok := batch.Batch.(ethdb.SyncBatch)
	if !ok {
		return errors.New("wrapped database does not support synchronous writes")
	}
	return syncBatch.WriteSync()
}

func writeFHSPersistenceProposal(
	t *testing.T,
	db ethdb.KeyValueStore,
	chainID, number, view, marker uint64,
	block *types.Block,
) (*types.HotstuffProposalRef, *proposalBodyMsg) {
	t.Helper()
	if block == nil {
		parentNumber := uint64(1)
		if number > 1 {
			parentNumber = number - 1
		}
		block = types.NewBlockWithHeader(&types.Header{
			ParentHash: common.BigToHash(new(big.Int).SetUint64(parentNumber)),
			Root:       common.BigToHash(new(big.Int).SetUint64(marker + 1)),
			Number:     new(big.Int).SetUint64(number),
			Difficulty: big.NewInt(1),
			GasLimit:   1,
			Extra:      new(big.Int).SetUint64(marker + 1).Bytes(),
		})
	}
	encodedBlock := block.EncodeToBytes()
	extra := []byte("persistence-gc-proof")
	viewID := common.BigToHash(new(big.Int).SetUint64(marker + view + 1))
	ref, err := types.NewHotstuffProposalRefWithProof(
		chainID, view, viewID, "leader", block, encodedBlock, extra, common.Hash{},
	)
	if err != nil {
		t.Fatal(err)
	}
	proposal := &fhsDiskProposal{
		ProposalID:  ref.ProposalID(),
		ProposalRef: ref.EncodeToBytes(),
		Extra:       append([]byte(nil), extra...),
	}
	encodedProposal, err := rlp.EncodeToBytes(proposal)
	if err != nil {
		t.Fatal(err)
	}
	if err := rawdb.WriteFHSProposal(db, proposal.ProposalID, encodedProposal); err != nil {
		t.Fatal(err)
	}
	bodyRecord := &fhsDiskBody{BodyHash: ref.BodyHash, EncodedBlock: encodedBlock}
	encodedBody, err := rlp.EncodeToBytes(bodyRecord)
	if err != nil {
		t.Fatal(err)
	}
	if err := rawdb.WriteFHSBody(db, ref.BodyHash, encodedBody); err != nil {
		t.Fatal(err)
	}
	return ref, &proposalBodyMsg{
		Type:            proposalBodyMsgManifest,
		ProposalID:      ref.ProposalID(),
		BodyHash:        ref.BodyHash,
		BodySize:        ref.BodySize,
		Number:          ref.Number,
		ViewNumber:      ref.ViewNumber,
		ViewID:          ref.ViewID,
		LeaderID:        ref.LeaderID,
		ProposalKeyHash: ref.KeyHash,
		EncodedBlock:    encodedBlock,
		Extra:           extra,
	}
}

func writeFHSPersistenceCertificate(t *testing.T, db ethdb.KeyValueStore, ref *types.HotstuffProposalRef) *hotstuff.SignedState {
	t.Helper()
	qc := &hotstuff.SignedState{
		State:    ref.EncodeToBytes(),
		Number:   ref.ViewNumber,
		ViewID:   ref.ViewID,
		LeaderID: ref.LeaderID,
	}
	encoded, err := rlp.EncodeToBytes(&fhsDiskCertificate{ProposalID: ref.ProposalID(), QC: qc})
	if err != nil {
		t.Fatal(err)
	}
	if err := rawdb.WriteFHSCertificate(db, ref.ProposalID(), encoded); err != nil {
		t.Fatal(err)
	}
	return qc
}

func countFHSPersistenceRecords(t *testing.T, db ethdb.KeyValueStore) (proposals, bodies, certificates int) {
	t.Helper()
	if err := rawdb.IterateFHSProposals(db, func(common.Hash, []byte) error {
		proposals++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := rawdb.IterateFHSBodies(db, func(common.Hash) error {
		bodies++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := rawdb.IterateFHSCertificates(db, func(common.Hash, []byte) error {
		certificates++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return proposals, bodies, certificates
}

func testPersistedVote(t *testing.T, chainID, view uint64, viewID common.Hash, leader string, marker byte) *hotstuff.PersistedVote {
	t.Helper()
	block := types.NewBlockWithHeader(&types.Header{
		ParentHash: common.BigToHash(new(big.Int).SetUint64(view + 1)),
		Number:     new(big.Int).SetUint64(view),
		Difficulty: big.NewInt(1),
		GasLimit:   1,
	})
	encodedBlock := block.EncodeToBytes()
	ref, err := types.NewHotstuffProposalRefWithProof(
		chainID, view, viewID, leader, block, encodedBlock, []byte{marker}, common.Hash{},
	)
	if err != nil {
		t.Fatal(err)
	}
	proposalRef := ref.EncodeToBytes()
	return &hotstuff.PersistedVote{
		ViewNumber:      view,
		ViewID:          viewID,
		LeaderID:        leader,
		ProposalID:      ref.ProposalID(),
		ProposalRef:     proposalRef,
		ProposalRefHash: hotstuff.StateDigest(proposalRef),
	}
}

func TestFHSSafetyStoreRejectsCorruptOrForeignWAL(t *testing.T) {
	db := memorydb.New()
	store := newFHSSafetyStore(db, 101, common.HexToHash("0xabc"))
	if err := store.load(); err != nil {
		t.Fatalf("empty safety store did not initialize: %v", err)
	}

	foreign := &fhsDiskSafety{
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
	vote := testPersistedVote(t, 101, 8, common.HexToHash("0x800"), "leader", 1)
	if err := validatePersistedVote(vote); err != nil {
		t.Fatalf("valid vote rejected: %v", err)
	}
	same := hotstuff.ClonePersistedVote(vote)
	if !persistedVotesEqual(vote, same) {
		t.Fatal("same vote does not compare equal")
	}
	conflict := testPersistedVote(t, 101, 8, common.HexToHash("0x800"), "leader", 2)
	if persistedVotesEqual(vote, conflict) {
		t.Fatal("same-view conflicting votes compare equal")
	}
}

func TestFHSRestartRejectsConflictingSameViewVote(t *testing.T) {
	db := memorydb.New()
	config := &params.ChainConfig{ChainID: big.NewInt(101), FairHotstuff: true}
	genesis := common.HexToHash("0xabc")
	first := &Service{chainConfig: config, fhsStore: newFHSSafetyStore(db, 101, genesis)}
	vote := testPersistedVote(t, 101, 9, common.HexToHash("0x900"), "leader", 1)
	if err := first.PersistFHSVote(vote); err != nil {
		t.Fatalf("persist first vote: %v", err)
	}

	// Construct a new Service/store over the same DB to model a process restart.
	restarted := &Service{chainConfig: config, fhsStore: newFHSSafetyStore(db, 101, genesis)}
	if err := restarted.PersistFHSVote(hotstuff.ClonePersistedVote(vote)); err != nil {
		t.Fatalf("idempotent vote rejected after restart: %v", err)
	}
	conflict := testPersistedVote(t, 101, 9, common.HexToHash("0x900"), "leader", 2)
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
	vote := testPersistedVote(t, 101, 10, common.HexToHash("0x1000"), "leader", 1)
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

func TestFHSVoteWatermarkRecoversWithoutProposalBody(t *testing.T) {
	db := memorydb.New()
	config := &params.ChainConfig{ChainID: big.NewInt(101), FairHotstuff: true}
	genesis := common.HexToHash("0xabc")
	service := &Service{chainConfig: config, fhsStore: newFHSSafetyStore(db, 101, genesis)}
	vote := testPersistedVote(t, 101, 11, common.HexToHash("0x1100"), "leader", 1)

	if err := service.PersistFHSVote(vote); err != nil {
		t.Fatalf("persist body-independent vote watermark: %v", err)
	}
	proposal, err := rawdb.ReadFHSProposal(db, vote.ProposalID)
	if err != nil {
		t.Fatal(err)
	}
	if len(proposal) != 0 {
		t.Fatalf("vote safety write unexpectedly persisted %d proposal bytes", len(proposal))
	}
	ref, err := types.DecodeHotstuffProposalRef(vote.ProposalRef)
	if err != nil {
		t.Fatal(err)
	}
	persistedBody, err := rawdb.ReadFHSBody(db, ref.BodyHash)
	if err != nil {
		t.Fatal(err)
	}
	if len(persistedBody) != 0 {
		t.Fatalf("vote safety write unexpectedly persisted %d body bytes", len(persistedBody))
	}

	restarted := &Service{chainConfig: config, fhsStore: newFHSSafetyStore(db, 101, genesis)}
	body, err := restarted.restoredFHSVoteProposal(vote)
	if err != nil {
		t.Fatalf("missing recoverable proposal body rejected restart: %v", err)
	}
	if body != nil {
		t.Fatal("missing proposal body was synthesized during restart")
	}
	conflict := testPersistedVote(t, 101, 11, common.HexToHash("0x1100"), "leader", 2)
	if err := restarted.PersistFHSVote(conflict); err == nil {
		t.Fatal("restart watermark allowed a conflicting vote while its body was missing")
	}
}

func TestFHSSafetyVoteDoesNotWaitForContentMutex(t *testing.T) {
	db := memorydb.New()
	service := &Service{
		chainConfig: &params.ChainConfig{ChainID: big.NewInt(101), FairHotstuff: true},
		fhsStore:    newFHSSafetyStore(db, 101, common.HexToHash("0xabc")),
	}
	vote := testPersistedVote(t, 101, 12, common.HexToHash("0x1200"), "leader", 1)

	service.fhsStore.contentMu.Lock()
	defer service.fhsStore.contentMu.Unlock()
	done := make(chan error, 1)
	go func() { done <- service.PersistFHSVote(vote) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("persist safety vote while content lock is held: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("small safety vote waited for the proposal/body content lock")
	}
}

func TestFHSContentPersistenceDoesNotWaitForSafetyMutex(t *testing.T) {
	service, body := testProposalSidecar(t)
	service.chainConfig.FairHotstuff = true
	service.fhsStore = newFHSSafetyStore(memorydb.New(), service.ChainID(), common.HexToHash("0xabc"))
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

	service.fhsStore.safetyMu.Lock()
	defer service.fhsStore.safetyMu.Unlock()
	done := make(chan error, 1)
	go func() { done <- service.persistFHSProposalData(ref, body) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("persist proposal content while safety lock is held: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("proposal/body content write waited for the safety WAL lock")
	}
}

func TestFHSContentWriterBoundsAndDeduplicates(t *testing.T) {
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
	jobBytes := proposalBodyMsgPayloadBytes(body)
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var calls atomic.Int32
	writer := newFHSContentWriterWithLimits(2, 2*jobBytes, func(*types.HotstuffProposalRef, *proposalBodyMsg) error {
		if calls.Add(1) == 1 {
			started <- struct{}{}
			<-release
		}
		return nil
	})
	if writer == nil {
		t.Fatal("content writer was not created")
	}
	if !writer.enqueue(ref, body) {
		t.Fatal("first content job was rejected")
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("content writer did not start its first job")
	}
	if !writer.enqueue(ref, body) {
		t.Fatal("duplicate in-flight content job was not idempotent")
	}
	second := *ref
	second.ViewNumber++
	if !writer.enqueue(&second, body) {
		t.Fatal("second bounded content job was rejected")
	}
	third := second
	third.ViewNumber++
	if writer.enqueue(&third, body) {
		t.Fatal("content writer exceeded its entry/byte bound")
	}
	close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := writer.shutdown(ctx); err != nil {
		t.Fatalf("drain content writer: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("content persistence calls = %d, want 2 unique jobs", got)
	}
	if writer.enqueue(&third, body) {
		t.Fatal("content writer accepted a job after shutdown")
	}
}

func TestFHSContentWriterFailureIsRetryable(t *testing.T) {
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
	completed := make(chan int, 2)
	var calls atomic.Int32
	writer := newFHSContentWriterWithLimits(1, proposalBodyMsgPayloadBytes(body), func(*types.HotstuffProposalRef, *proposalBodyMsg) error {
		call := int(calls.Add(1))
		completed <- call
		if call == 1 {
			return errors.New("injected recoverable content failure")
		}
		return nil
	})
	if writer == nil || !writer.enqueue(ref, body) {
		t.Fatal("first content job was rejected")
	}
	select {
	case call := <-completed:
		if call != 1 {
			t.Fatalf("first persistence call = %d", call)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first content persistence call did not complete")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		writer.mu.Lock()
		_, pending := writer.pending[ref.ProposalID()]
		writer.mu.Unlock()
		if !pending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("failed content job remained pending")
		}
		time.Sleep(time.Millisecond)
	}
	if !writer.enqueue(ref, body) {
		t.Fatal("content job could not be retried after a recoverable failure")
	}
	select {
	case call := <-completed:
		if call != 2 {
			t.Fatalf("retry persistence call = %d", call)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("content persistence retry did not complete")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := writer.shutdown(ctx); err != nil {
		t.Fatalf("shutdown content writer after retry: %v", err)
	}
}

func TestFHSContentWriterShutdownAbortsQueuedJobsAfterDeadline(t *testing.T) {
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
	jobBytes := proposalBodyMsgPayloadBytes(body)
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	writer := newFHSContentWriterWithLimits(3, 3*jobBytes, func(*types.HotstuffProposalRef, *proposalBodyMsg) error {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		return nil
	})
	if writer == nil || !writer.enqueue(ref, body) {
		t.Fatal("first content job was rejected")
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("content writer did not start")
	}
	for index := uint64(1); index <= 2; index++ {
		next := *ref
		next.ViewNumber += index
		if !writer.enqueue(&next, body) {
			t.Fatalf("queued content job %d was rejected", index)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- writer.shutdown(ctx) }()
	select {
	case err := <-shutdownDone:
		t.Fatalf("shutdown returned while a database write was active: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-shutdownDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("shutdown error = %v, want deadline exceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("content writer did not join after the active database write completed")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("persistence calls after shutdown deadline = %d, want only the active call", got)
	}
}

func TestFHSAsyncContentFailureDoesNotBlockSafetyVote(t *testing.T) {
	service, body := testProposalSidecar(t)
	service.chainConfig.FairHotstuff = true
	db := memorydb.New()
	service.fhsStore = newFHSSafetyStore(db, service.ChainID(), common.HexToHash("0xabc"))
	failed := make(chan struct{}, 1)
	service.fhsContentWriter = newFHSContentWriterWithLimits(1, proposalBodyMsgPayloadBytes(body), func(*types.HotstuffProposalRef, *proposalBodyMsg) error {
		failed <- struct{}{}
		return errors.New("injected proposal content write failure")
	})
	if err := service.storeProposalBody(body); err != nil {
		t.Fatalf("cache-first proposal store failed with recoverable writer error: %v", err)
	}
	select {
	case <-failed:
	case <-time.After(2 * time.Second):
		t.Fatal("asynchronous proposal content writer did not run")
	}
	if cached := service.getProposalBody(body.ProposalID); cached == nil || !bytes.Equal(cached.EncodedBlock, body.EncodedBlock) {
		t.Fatal("validated proposal body was not published before asynchronous persistence")
	}
	block := types.DecodeToBlock(body.EncodedBlock)
	ref, err := types.NewHotstuffProposalRefWithProof(
		service.ChainID(), body.ViewNumber, body.ViewID, body.LeaderID,
		block, body.EncodedBlock, body.Extra, common.Hash{},
	)
	if err != nil {
		t.Fatal(err)
	}
	vote := &hotstuff.PersistedVote{
		ViewNumber: ref.ViewNumber, ViewID: ref.ViewID, LeaderID: ref.LeaderID,
		ProposalID: ref.ProposalID(), ProposalRef: ref.EncodeToBytes(), ProposalRefHash: hotstuff.StateDigest(ref.EncodeToBytes()),
	}
	if err := service.PersistFHSVote(vote); err != nil {
		t.Fatalf("small safety WAL was coupled to recoverable content failure: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := service.shutdownFHSContentWriter(ctx); err != nil {
		t.Fatalf("shutdown failed content writer: %v", err)
	}
	if encoded, err := rawdb.ReadFHSSafetyState(db); err != nil || len(encoded) == 0 {
		t.Fatalf("vote watermark was not durable: bytes=%d err=%v", len(encoded), err)
	}
	if encoded, err := rawdb.ReadFHSBody(db, ref.BodyHash); err != nil || len(encoded) != 0 {
		t.Fatalf("injected content failure unexpectedly wrote a body: bytes=%d err=%v", len(encoded), err)
	}
}

func TestFHSProposalBodyStoredOnceAndNotRewrittenByCertificate(t *testing.T) {
	service, body := testProposalSidecar(t)
	service.chainConfig.FairHotstuff = true
	store := &fhsBodyWriteCountingStore{KeyValueStore: memorydb.New()}
	service.fhsStore = newFHSSafetyStore(store, service.ChainID(), common.HexToHash("0xabc"))

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
	if err := service.storeProposalBody(body); err != nil {
		t.Fatalf("store content-addressed proposal body: %v", err)
	}
	if store.bodyWrites != 1 {
		t.Fatalf("initial proposal persistence performed %d body writes, want 1", store.bodyWrites)
	}

	encodedBody, err := rawdb.ReadFHSBody(store, ref.BodyHash)
	if err != nil {
		t.Fatal(err)
	}
	var bodyRecord fhsDiskBody
	if err := rlp.DecodeBytes(encodedBody, &bodyRecord); err != nil {
		t.Fatalf("decode content-addressed body record: %v", err)
	}
	if bodyRecord.BodyHash != ref.BodyHash || !bytes.Equal(bodyRecord.EncodedBlock, body.EncodedBlock) {
		t.Fatalf("content-addressed body mismatch: hash=%s bytes=%d", bodyRecord.BodyHash, len(bodyRecord.EncodedBlock))
	}
	encodedProposal, err := rawdb.ReadFHSProposal(store, ref.ProposalID())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encodedProposal, body.EncodedBlock) {
		t.Fatal("proposal proof record still embeds the complete block body")
	}
	restored, found, err := service.readFHSProposalBody(ref)
	if err != nil {
		t.Fatalf("read proposal through BodyHash: %v", err)
	}
	if !found || restored == nil || !bytes.Equal(restored.EncodedBlock, body.EncodedBlock) {
		t.Fatalf("content-addressed proposal body was not recoverable: found=%v body=%+v", found, restored)
	}

	if err := service.storeProposalBody(cloneProposalBodyMsg(body)); err != nil {
		t.Fatalf("idempotent proposal body store: %v", err)
	}
	if store.bodyWrites != 1 {
		t.Fatalf("idempotent proposal store rewrote body: writes=%d", store.bodyWrites)
	}
	beforeCertificate := append([]byte(nil), encodedBody...)
	qc := &hotstuff.SignedState{
		State:    ref.EncodeToBytes(),
		Number:   ref.ViewNumber,
		ViewID:   ref.ViewID,
		LeaderID: ref.LeaderID,
	}
	if err := service.persistFHSCertificateWithBroadcast(ref, qc, body, body.Extra, false); err != nil {
		t.Fatalf("persist certificate: %v", err)
	}
	if store.bodyWrites != 1 {
		t.Fatalf("certificate persistence rewrote proposal body: writes=%d", store.bodyWrites)
	}
	afterCertificate, err := rawdb.ReadFHSBody(store, ref.BodyHash)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterCertificate, beforeCertificate) {
		t.Fatal("certificate persistence changed content-addressed proposal body")
	}
	store.bodyReads = 0
	store.bodyWrites = 0
	if err := service.persistValidatedFHSCertificateWithBroadcast(ref, qc, false); err != nil {
		t.Fatalf("persist prevalidated certificate: %v", err)
	}
	if store.bodyReads != 0 || store.bodyWrites != 0 {
		t.Fatalf("serialized prevalidated certificate path touched full body storage: reads=%d writes=%d", store.bodyReads, store.bodyWrites)
	}
}

func TestFHSDeferredRecoveryMatchesDurableHighestQC(t *testing.T) {
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
	qc := &hotstuff.SignedState{State: ref.EncodeToBytes(), Number: ref.ViewNumber, ViewID: ref.ViewID, LeaderID: ref.LeaderID}
	if err := service.persistValidatedFHSCertificateWithBroadcast(ref, qc, false); err != nil {
		t.Fatalf("persist body-independent certificate: %v", err)
	}
	recovery := &fhsDeferredRecovery{HighestQC: qc, HighestBlockHash: ref.BlockHash, RecoveredView: qc.Number + 2}
	if err := service.fhsStore.deferRecovery(recovery); err != nil {
		t.Fatalf("defer matching highest QC recovery: %v", err)
	}
	snapshot := service.fhsStore.deferredRecoverySnapshot()
	if snapshot == nil || snapshot.HighestBlockHash != ref.BlockHash || snapshot.RecoveredView != recovery.RecoveredView ||
		!hotstuff.SignedStateSemanticEqual(snapshot.HighestQC, qc) {
		t.Fatalf("deferred recovery snapshot mismatch: %+v", snapshot)
	}
	snapshot.HighestQC.Number++
	if got := service.fhsStore.deferredRecoverySnapshot(); got == nil || got.HighestQC.Number != qc.Number {
		t.Fatal("deferred recovery snapshot aliases store state")
	}
	conflict := hotstuff.CloneSignedState(qc)
	conflict.Number++
	if err := service.fhsStore.deferRecovery(&fhsDeferredRecovery{HighestQC: conflict, HighestBlockHash: ref.BlockHash}); err == nil {
		t.Fatal("conflicting deferred recovery was accepted")
	}
	if err := service.fhsStore.completeDeferredRecovery(conflict); err == nil {
		t.Fatal("mismatched deferred recovery completion was accepted")
	}
	if err := service.fhsStore.completeDeferredRecovery(qc); err != nil {
		t.Fatalf("complete deferred recovery: %v", err)
	}
	if got := service.fhsStore.deferredRecoverySnapshot(); got != nil {
		t.Fatalf("completed deferred recovery remained active: %+v", got)
	}
}

func TestFHSDeferredRecoveryGatesVotesTimeoutsAndPacemaker(t *testing.T) {
	service, body := testProposalSidecar(t)
	service.chainConfig.FairHotstuff = true
	service.fhsStore = newFHSSafetyStore(memorydb.New(), service.ChainID(), common.HexToHash("0xabc"))
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
	qc := &hotstuff.SignedState{State: ref.EncodeToBytes(), Number: ref.ViewNumber, ViewID: ref.ViewID, LeaderID: ref.LeaderID}
	if err := service.persistValidatedFHSCertificateWithBroadcast(ref, qc, false); err != nil {
		t.Fatal(err)
	}
	if err := service.fhsStore.deferRecovery(&fhsDeferredRecovery{
		HighestQC: qc, HighestBlockHash: ref.BlockHash, RecoveredView: qc.Number + 2,
	}); err != nil {
		t.Fatal(err)
	}
	vote := testPersistedVote(t, service.ChainID(), qc.Number+1, common.HexToHash("0x8001"), "next-leader", 1)
	if err := service.PersistFHSVote(vote); !errors.Is(err, errFHSRecoveryPending) {
		t.Fatalf("vote during deferred recovery error = %v, want recovery gate", err)
	}
	statement := &hotstuff.TimeoutStatement{
		Version: hotstuff.NewFHSSafetyState().Version, ChainID: service.ChainID(), TimedOutView: qc.Number + 1,
		KeyNumber: 1, KeyHash: common.HexToHash("0x11"), CommitteeHash: common.HexToHash("0x12"),
	}
	if err := service.PersistFHSTimeoutVote(statement); !errors.Is(err, errFHSRecoveryPending) {
		t.Fatalf("timeout vote during deferred recovery error = %v, want recovery gate", err)
	}
	timer := &paceMakerTimer{service: service, beStop: true}
	if err := timer.start(); !errors.Is(err, errFHSRecoveryPending) {
		t.Fatalf("pacemaker start during deferred recovery error = %v, want recovery gate", err)
	}
	if !timer.beStop {
		t.Fatal("pacemaker opened while durable HighestQC content was missing")
	}
	if err := service.fhsStore.completeDeferredRecovery(qc); err != nil {
		t.Fatal(err)
	}
	if err := timer.start(); err != nil {
		t.Fatalf("pacemaker remained gated after exact recovery completion: %v", err)
	}
	if err := service.PersistFHSVote(vote); err != nil {
		t.Fatalf("vote remained gated after exact recovery completion: %v", err)
	}
}

func TestFHSDeferredRecoveryInstallsExistingPrefixWithoutRegressingSafetyWAL(t *testing.T) {
	service, body := testProposalSidecar(t)
	service.chainConfig.FairHotstuff = true
	db := memorydb.New()
	service.fhsStore = newFHSSafetyStore(db, service.ChainID(), common.HexToHash("0xabc"))
	block := types.DecodeToBlock(body.EncodedBlock)
	targetRef, err := types.NewHotstuffProposalRefWithProof(
		service.ChainID(), body.ViewNumber, body.ViewID, body.LeaderID,
		block, body.EncodedBlock, body.Extra, common.Hash{},
	)
	if err != nil {
		t.Fatal(err)
	}
	targetQC := &hotstuff.SignedState{
		State: targetRef.EncodeToBytes(), Number: targetRef.ViewNumber, ViewID: targetRef.ViewID, LeaderID: targetRef.LeaderID,
	}
	if err := service.persistValidatedFHSCertificateWithBroadcast(targetRef, targetQC, false); err != nil {
		t.Fatal(err)
	}
	lowerRef, _ := writeFHSPersistenceProposal(t, db, service.ChainID(), 1, targetQC.Number-1, 400, nil)
	lowerQC := writeFHSPersistenceCertificate(t, db, lowerRef)
	if err := service.fhsStore.deferRecovery(&fhsDeferredRecovery{
		HighestQC: targetQC, HighestBlockHash: targetRef.BlockHash, RecoveredView: targetQC.Number + 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := service.persistValidatedFHSCertificateWithBroadcast(lowerRef, lowerQC, false); err != nil {
		t.Fatalf("install exact durable recovery prefix: %v", err)
	}
	state, highestHash, err := service.fhsStore.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !hotstuff.SignedStateSemanticEqual(state.HighestQC, targetQC) || highestHash != targetRef.BlockHash {
		t.Fatalf("prefix install regressed safety WAL: highest=%+v hash=%s", state.HighestQC, highestHash)
	}
	conflicting := hotstuff.CloneSignedState(lowerQC)
	conflicting.ViewID = common.HexToHash("0xdead")
	if err := service.persistValidatedFHSCertificateWithBroadcast(lowerRef, conflicting, false); err == nil {
		t.Fatal("conflicting lower certificate bypassed deferred recovery gate")
	}
}

func TestFHSPersistencePruneAllowsCertifiedContentAwaitingRepair(t *testing.T) {
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
	qc := &hotstuff.SignedState{State: ref.EncodeToBytes(), Number: ref.ViewNumber, ViewID: ref.ViewID, LeaderID: ref.LeaderID}
	if err := service.persistValidatedFHSCertificateWithBroadcast(ref, qc, false); err != nil {
		t.Fatalf("persist certificate without proposal content: %v", err)
	}
	if err := service.pruneFHSPersistence(ref.Number+100, ref.ViewNumber+1000); err != nil {
		t.Fatalf("GC rejected certified content awaiting repair: %v", err)
	}
	if encoded, err := rawdb.ReadFHSCertificate(db, ref.ProposalID()); err != nil || len(encoded) == 0 {
		t.Fatalf("GC collected protected certificate: bytes=%d err=%v", len(encoded), err)
	}
	proposals, bodies, certificates := countFHSPersistenceRecords(t, db)
	if proposals != 0 || bodies != 0 || certificates != 1 {
		t.Fatalf("repairable persistence records = proposals:%d bodies:%d certificates:%d, want 0/0/1", proposals, bodies, certificates)
	}
}

func TestFHSPersistencePruneKeepsMoreThanCacheLimitDuringHighQCCatchup(t *testing.T) {
	db := memorydb.New()
	service := &Service{
		chainConfig: &params.ChainConfig{ChainID: big.NewInt(101), FairHotstuff: true},
		fhsStore:    newFHSSafetyStore(db, 101, common.HexToHash("0xabc")),
	}
	service.activeHighQCValidation = &highQCValidationControl{
		key:        hotstuff.FHSHighQCValidationKey{RequestID: 1, QCID: common.HexToHash("0x100"), TargetView: 1000},
		generation: 1,
		authorized: make(map[common.Hash]proposalBodyAuthority),
	}
	refs := make([]*types.HotstuffProposalRef, 0, proposalBodyCacheMaxEntries+1)
	for index := 0; index <= proposalBodyCacheMaxEntries; index++ {
		ref, _ := writeFHSPersistenceProposal(t, db, 101, uint64(index+2), uint64(index+10), uint64(index+1), nil)
		refs = append(refs, ref)
		service.activeHighQCValidation.authorized[ref.ProposalID()] = proposalBodyAuthority{
			key: hotstuff.FHSProposalValidationKey{
				ViewNumber: ref.ViewNumber, ViewID: ref.ViewID, LeaderID: ref.LeaderID, ProposalID: ref.ProposalID(),
			},
			keyHash: ref.KeyHash,
		}
	}
	if err := service.pruneFHSPersistence(1000, 1000); err != nil {
		t.Fatalf("prune active HighQC catch-up: %v", err)
	}
	for index, ref := range refs {
		if encoded, err := rawdb.ReadFHSProposal(db, ref.ProposalID()); err != nil || len(encoded) == 0 {
			t.Fatalf("active HighQC proposal %d/%d was collected: bytes=%d err=%v", index+1, len(refs), len(encoded), err)
		}
		if encoded, err := rawdb.ReadFHSBody(db, ref.BodyHash); err != nil || len(encoded) == 0 {
			t.Fatalf("active HighQC body %d/%d was collected: bytes=%d err=%v", index+1, len(refs), len(encoded), err)
		}
	}
}

func TestFHSPersistencePruneKeepsSharedBodyUntilLastReference(t *testing.T) {
	db := memorydb.New()
	service := &Service{
		chainConfig: &params.ChainConfig{ChainID: big.NewInt(101), FairHotstuff: true},
		fhsStore:    newFHSSafetyStore(db, 101, common.HexToHash("0xabc")),
	}
	block := types.NewBlockWithHeader(&types.Header{
		ParentHash: common.HexToHash("0x12"),
		Root:       common.HexToHash("0x1300"),
		Number:     big.NewInt(13),
		Difficulty: big.NewInt(1),
		GasLimit:   1,
	})
	oldRef, _ := writeFHSPersistenceProposal(t, db, 101, 13, 700, 1, block)
	recentRef, _ := writeFHSPersistenceProposal(t, db, 101, 13, 1000, 2, block)
	if oldRef.ProposalID() == recentRef.ProposalID() || oldRef.BodyHash != recentRef.BodyHash {
		t.Fatal("shared-body proposal fixture is invalid")
	}

	if err := service.pruneFHSPersistence(20, 1000); err != nil {
		t.Fatalf("prune old shared-body proposal: %v", err)
	}
	if encoded, err := rawdb.ReadFHSProposal(db, oldRef.ProposalID()); err != nil || len(encoded) != 0 {
		t.Fatalf("old proposal survived GC: bytes=%d err=%v", len(encoded), err)
	}
	if encoded, err := rawdb.ReadFHSProposal(db, recentRef.ProposalID()); err != nil || len(encoded) == 0 {
		t.Fatalf("recent proposal was collected: bytes=%d err=%v", len(encoded), err)
	}
	if encoded, err := rawdb.ReadFHSBody(db, recentRef.BodyHash); err != nil || len(encoded) == 0 {
		t.Fatalf("shared body was collected while referenced: bytes=%d err=%v", len(encoded), err)
	}

	if err := service.pruneFHSPersistence(30, 2000); err != nil {
		t.Fatalf("prune final shared-body reference: %v", err)
	}
	if encoded, err := rawdb.ReadFHSBody(db, recentRef.BodyHash); err != nil || len(encoded) != 0 {
		t.Fatalf("unreferenced body survived GC: bytes=%d err=%v", len(encoded), err)
	}
}

func TestFHSPersistencePruneProtectsRecoveryWatermarksAndCertificates(t *testing.T) {
	counting := &fhsDeleteCountingStore{KeyValueStore: memorydb.New()}
	service := &Service{
		chainConfig: &params.ChainConfig{ChainID: big.NewInt(101), FairHotstuff: true},
		fhsStore:    newFHSSafetyStore(counting, 101, common.HexToHash("0xabc")),
	}
	staleRef, _ := writeFHSPersistenceProposal(t, counting, 101, 10, 10, 10, nil)
	writeFHSPersistenceCertificate(t, counting, staleRef)
	protectedRef, _ := writeFHSPersistenceProposal(t, counting, 101, 11, 11, 11, nil)
	protectedQC := writeFHSPersistenceCertificate(t, counting, protectedRef)
	lastVoteRef, _ := writeFHSPersistenceProposal(t, counting, 101, 12, 12, 12, nil)
	recentRef, _ := writeFHSPersistenceProposal(t, counting, 101, 93, 13, 13, nil)
	writeFHSPersistenceCertificate(t, counting, recentRef)
	orphanHash := common.HexToHash("0xdeadbeef")
	orphanBody, err := rlp.EncodeToBytes(&fhsDiskBody{BodyHash: orphanHash, EncodedBlock: []byte("orphan")})
	if err != nil {
		t.Fatal(err)
	}
	if err := rawdb.WriteFHSBody(counting, orphanHash, orphanBody); err != nil {
		t.Fatal(err)
	}

	if err := service.fhsStore.load(); err != nil {
		t.Fatal(err)
	}
	service.fhsStore.safetyMu.Lock()
	service.fhsStore.state.HighestQC = hotstuff.CloneSignedState(protectedQC)
	service.fhsStore.highestBlockHash = protectedRef.BlockHash
	lastVoteBytes := lastVoteRef.EncodeToBytes()
	service.fhsStore.state.LastVote = &hotstuff.PersistedVote{
		ViewNumber:      lastVoteRef.ViewNumber,
		ViewID:          lastVoteRef.ViewID,
		LeaderID:        lastVoteRef.LeaderID,
		ProposalID:      lastVoteRef.ProposalID(),
		ProposalRef:     lastVoteBytes,
		ProposalRefHash: hotstuff.StateDigest(lastVoteBytes),
	}
	service.fhsStore.safetyMu.Unlock()

	if err := service.pruneFHSPersistence(100, 1000); err != nil {
		t.Fatalf("prune durable recovery cache: %v", err)
	}
	if counting.directDeletes != 0 || counting.batchDeletes == 0 || counting.batchWrites == 0 {
		t.Fatalf("GC did not use database batches: direct=%d batchDeletes=%d batchWrites=%d",
			counting.directDeletes, counting.batchDeletes, counting.batchWrites)
	}
	if encoded, err := rawdb.ReadFHSCertificate(counting, staleRef.ProposalID()); err != nil || len(encoded) != 0 {
		t.Fatalf("stale certificate survived: bytes=%d err=%v", len(encoded), err)
	}
	for name, ref := range map[string]*types.HotstuffProposalRef{
		"highest QC":       protectedRef,
		"last vote":        lastVoteRef,
		"canonical suffix": recentRef,
	} {
		if encoded, err := rawdb.ReadFHSProposal(counting, ref.ProposalID()); err != nil || len(encoded) == 0 {
			t.Fatalf("%s proposal was collected: bytes=%d err=%v", name, len(encoded), err)
		}
		if encoded, err := rawdb.ReadFHSBody(counting, ref.BodyHash); err != nil || len(encoded) == 0 {
			t.Fatalf("%s body was collected: bytes=%d err=%v", name, len(encoded), err)
		}
	}
	if encoded, err := rawdb.ReadFHSBody(counting, orphanHash); err != nil || len(encoded) != 0 {
		t.Fatalf("orphan body survived: bytes=%d err=%v", len(encoded), err)
	}
}

func TestFHSPersistencePruneBoundsUncertifiedProposalSet(t *testing.T) {
	db := memorydb.New()
	service := &Service{
		chainConfig: &params.ChainConfig{ChainID: big.NewInt(101), FairHotstuff: true},
		fhsStore:    newFHSSafetyStore(db, 101, common.HexToHash("0xabc")),
	}
	for index := 0; index < fhsPersistenceUncertifiedLimit+17; index++ {
		writeFHSPersistenceProposal(t, db, 101, 93, 1000, uint64(index+1), nil)
	}
	if err := service.pruneFHSPersistence(100, 1000); err != nil {
		t.Fatalf("bound uncertified proposal set: %v", err)
	}
	proposals, bodies, certificates := countFHSPersistenceRecords(t, db)
	if proposals != fhsPersistenceUncertifiedLimit || bodies != fhsPersistenceUncertifiedLimit || certificates != 0 {
		t.Fatalf("bounded records = proposals:%d bodies:%d certificates:%d, want %d/%d/0",
			proposals, bodies, certificates, fhsPersistenceUncertifiedLimit, fhsPersistenceUncertifiedLimit)
	}
}

func TestFHSPersistencePruneFailsSafeOnCorruptProposal(t *testing.T) {
	counting := &fhsDeleteCountingStore{KeyValueStore: memorydb.New()}
	service := &Service{
		chainConfig: &params.ChainConfig{ChainID: big.NewInt(101), FairHotstuff: true},
		fhsStore:    newFHSSafetyStore(counting, 101, common.HexToHash("0xabc")),
	}
	validRef, _ := writeFHSPersistenceProposal(t, counting, 101, 1, 1, 1, nil)
	if err := rawdb.WriteFHSProposal(counting, common.HexToHash("0xbad"), []byte{0xff}); err != nil {
		t.Fatal(err)
	}
	if err := service.pruneFHSPersistence(100, 1000); err == nil {
		t.Fatal("corrupt proposal did not stop GC")
	}
	if counting.batchWrites != 0 || counting.batchDeletes != 0 || counting.directDeletes != 0 {
		t.Fatalf("fail-safe GC mutated storage: direct=%d batchDeletes=%d batchWrites=%d",
			counting.directDeletes, counting.batchDeletes, counting.batchWrites)
	}
	if encoded, err := rawdb.ReadFHSProposal(counting, validRef.ProposalID()); err != nil || len(encoded) == 0 {
		t.Fatalf("valid proposal was deleted after corrupt scan: bytes=%d err=%v", len(encoded), err)
	}
}

func TestFHSPersistencePruneSplitsLargeDeletesIntoBoundedBatches(t *testing.T) {
	counting := &fhsDeleteCountingStore{KeyValueStore: memorydb.New()}
	service := &Service{
		chainConfig: &params.ChainConfig{ChainID: big.NewInt(101), FairHotstuff: true},
		fhsStore:    newFHSSafetyStore(counting, 101, common.HexToHash("0xabc")),
	}
	const records = fhsPersistenceDeleteBatchSize + 44
	for index := 0; index < records; index++ {
		writeFHSPersistenceProposal(t, counting, 101, 1, 1, uint64(index+1), nil)
	}
	if err := service.pruneFHSPersistence(100, 1000); err != nil {
		t.Fatalf("prune large stale set: %v", err)
	}
	if counting.directDeletes != 0 || counting.batchDeletes != records*2 || counting.batchWrites != 4 {
		t.Fatalf("bounded delete batches = direct:%d deletes:%d writes:%d, want 0/%d/4",
			counting.directDeletes, counting.batchDeletes, counting.batchWrites, records*2)
	}
	proposals, bodies, certificates := countFHSPersistenceRecords(t, counting)
	if proposals != 0 || bodies != 0 || certificates != 0 {
		t.Fatalf("stale records remain: proposals=%d bodies=%d certificates=%d", proposals, bodies, certificates)
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
		ViewNumber:      ref.ViewNumber,
		ViewID:          ref.ViewID,
		LeaderID:        ref.LeaderID,
		ProposalID:      ref.ProposalID(),
		ProposalRef:     ref.EncodeToBytes(),
		ProposalRefHash: hotstuff.StateDigest(ref.EncodeToBytes()),
	}
	proposal := &fhsDiskProposal{
		ProposalID:  ref.ProposalID(),
		ProposalRef: append([]byte(nil), vote.ProposalRef...),
		Extra:       append([]byte(nil), body.Extra...),
	}
	bodyRecord := &fhsDiskBody{BodyHash: ref.BodyHash, EncodedBlock: append([]byte(nil), body.EncodedBlock...)}
	encoded, err := rlp.EncodeToBytes(proposal)
	if err != nil {
		t.Fatal(err)
	}
	if err := rawdb.WriteFHSProposal(db, proposal.ProposalID, encoded); err != nil {
		t.Fatal(err)
	}
	encodedBody, err := rlp.EncodeToBytes(bodyRecord)
	if err != nil {
		t.Fatal(err)
	}
	if err := rawdb.WriteFHSBody(db, ref.BodyHash, encodedBody); err != nil {
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

func testFHSCertifiedFrontierRecord(number, view uint64, parent common.Hash, discriminator byte) *fhsCertifiedProposal {
	block := types.NewBlockWithHeader(&types.Header{
		ParentHash: parent,
		Number:     new(big.Int).SetUint64(number),
		Difficulty: big.NewInt(1),
		BlockType:  types.FastTx_Block,
		KeyHash:    common.BytesToHash([]byte{discriminator, 1}),
		Extra:      []byte{discriminator},
	})
	ref := &types.HotstuffProposalRef{
		Version:    types.HotstuffProposalRefVersion,
		ChainID:    101,
		Number:     number,
		BlockHash:  block.Hash(),
		ParentHash: parent,
		BodyHash:   common.BytesToHash([]byte{discriminator, 2}),
		BodySize:   1,
		ExtraHash:  types.HotstuffProposalExtraHash(nil),
		KeyHash:    block.KeyHash(),
		BlockType:  block.BlockType(),
		ViewNumber: view,
		ViewID:     common.BytesToHash([]byte{discriminator, 3}),
		LeaderID:   "frontier-leader",
	}
	qc := &hotstuff.SignedState{
		State: ref.EncodeToBytes(), Number: view, ViewID: ref.ViewID, LeaderID: ref.LeaderID,
	}
	return &fhsCertifiedProposal{
		ref: ref,
		qc:  qc,
		verified: &core.VerifiedProposal{
			ProposalID: ref.ProposalID(), ViewNumber: view, ViewID: ref.ViewID, LeaderID: ref.LeaderID,
			Block: block, ParentHash: parent, ParentNumber: number - 1,
		},
	}
}

func TestReconcileFHSCertifiedFrontierDropsCanonicalizedPrefix(t *testing.T) {
	canonical := types.NewBlockWithHeader(&types.Header{
		ParentHash: common.HexToHash("0xc012"), Number: big.NewInt(13), Difficulty: big.NewInt(1),
		BlockType: types.FastTx_Block,
	})
	stale := testFHSCertifiedFrontierRecord(7, 11, common.HexToHash("0x700"), 1)
	child := testFHSCertifiedFrontierRecord(14, 23, canonical.Hash(), 2)
	tip := testFHSCertifiedFrontierRecord(15, 24, child.ref.BlockHash, 3)
	parentID, err := hotstuff.SignedStateID(child.qc)
	if err != nil {
		t.Fatal(err)
	}
	tip.ref.ParentQCID = parentID.Hash()
	tip.qc.State = tip.ref.EncodeToBytes()
	tip.verified.ProposalID = tip.ref.ProposalID()
	service := &Service{
		fhsCertifiedByHash: map[common.Hash]*fhsCertifiedProposal{
			stale.ref.BlockHash: stale, child.ref.BlockHash: child, tip.ref.BlockHash: tip,
		},
		fhsCertifiedByID: map[common.Hash]*fhsCertifiedProposal{
			stale.ref.ProposalID(): stale, child.ref.ProposalID(): child, tip.ref.ProposalID(): tip,
		},
		proposalBodies: map[common.Hash]*proposalBodyMsg{
			stale.ref.ProposalID(): {ProposalID: stale.ref.ProposalID()},
			child.ref.ProposalID(): {ProposalID: child.ref.ProposalID()},
			tip.ref.ProposalID():   {ProposalID: tip.ref.ProposalID()},
		},
		verifiedProposalByID: map[common.Hash]*core.VerifiedProposal{
			stale.ref.ProposalID(): stale.verified,
			child.ref.ProposalID(): child.verified,
			tip.ref.ProposalID():   tip.verified,
		},
		fhsHighest: stale,
	}

	if err := service.reconcileFHSCertifiedFrontierLocked(canonical); err != nil {
		t.Fatalf("reconcile certified suffix: %v", err)
	}
	if service.fhsHighest != tip {
		t.Fatalf("certified frontier = %p, want contiguous tip %p", service.fhsHighest, tip)
	}
	if len(service.fhsCertifiedByHash) != 2 || service.fhsCertifiedByHash[child.ref.BlockHash] != child ||
		service.fhsCertifiedByHash[tip.ref.BlockHash] != tip {
		t.Fatalf("unexpected reconciled certified suffix: %#v", service.fhsCertifiedByHash)
	}
	if service.fhsCertifiedByHash[stale.ref.BlockHash] != nil || service.fhsCertifiedByID[stale.ref.ProposalID()] != nil ||
		service.proposalBodies[stale.ref.ProposalID()] != nil || service.verifiedProposalByID[stale.ref.ProposalID()] != nil {
		t.Fatal("canonicalized stale certificate survived volatile frontier reconciliation")
	}
	if service.proposalBodies[child.ref.ProposalID()] == nil || service.verifiedProposalByID[tip.ref.ProposalID()] == nil {
		t.Fatal("contiguous uncommitted suffix caches were discarded")
	}
}

func TestReconcileFHSCertifiedFrontierSelectsHighestSibling(t *testing.T) {
	canonical := types.NewBlockWithHeader(&types.Header{
		Number: big.NewInt(13), Difficulty: big.NewInt(1), BlockType: types.FastTx_Block,
	})
	first := testFHSCertifiedFrontierRecord(14, 23, canonical.Hash(), 4)
	second := testFHSCertifiedFrontierRecord(14, 24, canonical.Hash(), 5)
	service := &Service{
		fhsCertifiedByHash: map[common.Hash]*fhsCertifiedProposal{
			first.ref.BlockHash: first, second.ref.BlockHash: second,
		},
		fhsCertifiedByID: map[common.Hash]*fhsCertifiedProposal{
			first.ref.ProposalID(): first, second.ref.ProposalID(): second,
		},
		fhsHighest: first,
	}
	if err := service.reconcileFHSCertifiedFrontierLocked(canonical); err != nil {
		t.Fatal(err)
	}
	if len(service.fhsCertifiedByHash) != 2 || service.fhsHighest != second {
		t.Fatal("did not retain siblings and select highest view")
	}
	second.ref.ViewNumber = first.qc.Number
	second.qc.Number = first.qc.Number
	second.qc.State = second.ref.EncodeToBytes()
	second.verified.ViewNumber = first.qc.Number
	second.verified.ProposalID = second.ref.ProposalID()
	if err := service.reconcileFHSCertifiedFrontierLocked(canonical); err == nil {
		t.Fatal("conflicting same-view QCs accepted")
	}

}

func TestFHSHighQCCanonicalClassificationAndStaleBase(t *testing.T) {
	canonicalHash := common.HexToHash("0xc013")
	lookup := func(number uint64) common.Hash {
		if number == 13 {
			return canonicalHash
		}
		return common.Hash{}
	}
	exact := &types.HotstuffProposalRef{Number: 13, BlockHash: canonicalHash}
	if isExact, finalized, err := classifyFHSRefAgainstCanonical(exact, 13, lookup); err != nil || !isExact || !finalized {
		t.Fatalf("exact canonical HighQC classification = exact:%v finalized:%v err:%v", isExact, finalized, err)
	}
	fork := &types.HotstuffProposalRef{Number: 13, BlockHash: common.HexToHash("0xdead")}
	if isExact, finalized, err := classifyFHSRefAgainstCanonical(fork, 13, lookup); err != nil || isExact || !finalized {
		t.Fatalf("finalized-height fork classification = exact:%v finalized:%v err:%v", isExact, finalized, err)
	}
	future := &types.HotstuffProposalRef{Number: 14, BlockHash: common.HexToHash("0xf014")}
	if isExact, finalized, err := classifyFHSRefAgainstCanonical(future, 13, lookup); err != nil || isExact || finalized {
		t.Fatalf("future HighQC classification = exact:%v finalized:%v err:%v", isExact, finalized, err)
	}

	stale := &fhsCertifiedProposal{ref: &types.HotstuffProposalRef{Number: 7}}
	if got := fhsCertifiedFrontierAboveCanonical(stale, 13); got != nil {
		t.Fatalf("canonicalized height 7 certificate remained an execution base: %p", got)
	}
	uncommitted := &fhsCertifiedProposal{ref: &types.HotstuffProposalRef{Number: 14}}
	if got := fhsCertifiedFrontierAboveCanonical(uncommitted, 13); got != uncommitted {
		t.Fatalf("uncommitted height 14 certificate was discarded: %p", got)
	}
}

func TestValidateCanonicalFHSQCAdvanceSupersedesUncommittedObservation(t *testing.T) {
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
	); err != nil {
		t.Fatalf("verified canonical QC could not supersede old uncommitted fork: %v", err)
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

type fhsConsensusResumeRecorder struct {
	events []string
}

func (recorder *fhsConsensusResumeRecorder) replayPendingFHSQCBroadcast() {
	recorder.events = append(recorder.events, "replay")
}

func (recorder *fhsConsensusResumeRecorder) sendNewViewMsg(uint64) {
	// This mirrors the Service contract: sendNewViewMsg performs the durable
	// replay before it queues MsgStartNewView.
	recorder.replayPendingFHSQCBroadcast()
	recorder.events = append(recorder.events, "new-view")
}

func (recorder *fhsConsensusResumeRecorder) enqueueFHSTimeout() {
	recorder.events = append(recorder.events, "timeout")
}

func TestFHSStartupAndDeferredResumeReplayDurableQCExactlyOnce(t *testing.T) {
	tests := []struct {
		name           string
		pendingTimeout bool
		want           []string
	}{
		{name: "normal new view", want: []string{"replay", "new-view"}},
		{name: "durable timeout", pendingTimeout: true, want: []string{"replay", "timeout"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := new(fhsConsensusResumeRecorder)
			resumeFHSConsensusMessaging(recorder, 17, test.pendingTimeout)
			if len(recorder.events) != len(test.want) {
				t.Fatalf("resume events = %v, want %v", recorder.events, test.want)
			}
			replays := 0
			for index := range test.want {
				if recorder.events[index] != test.want[index] {
					t.Fatalf("resume events = %v, want %v", recorder.events, test.want)
				}
				if recorder.events[index] == "replay" {
					replays++
				}
			}
			if replays != 1 {
				t.Fatalf("durable QC replay count = %d, want 1", replays)
			}
		})
	}
}

func TestFHSQCBroadcastSuppressesOnlyMatchingImmediateReplay(t *testing.T) {
	service, body := testProposalSidecar(t)
	service.chainConfig.FairHotstuff = true
	db := memorydb.New()
	genesis := common.HexToHash("0xbca5")
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
	qc := &hotstuff.SignedState{
		State:    ref.EncodeToBytes(),
		Number:   ref.ViewNumber,
		ViewID:   ref.ViewID,
		LeaderID: ref.LeaderID,
	}
	if err := service.persistFHSCertificateWithBroadcast(ref, qc, body, body.Extra, true); err != nil {
		t.Fatalf("persist leader QC outbox: %v", err)
	}
	if err := service.beginFHSQCBroadcast(qc); err != nil {
		t.Fatalf("begin initial QC broadcast: %v", err)
	}
	now := time.Now()
	pending, err := service.fhsStore.pendingBroadcastSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !service.fhsQCBroadcastReplaySuppressed(pending, now) {
		t.Fatal("matching durable replay was not suppressed during the initial broadcast window")
	}
	if err := service.beginFHSQCBroadcast(hotstuff.CloneSignedState(qc)); err != nil {
		t.Fatalf("same QC did not re-enter its idempotent broadcast window: %v", err)
	}
	other := hotstuff.CloneSignedState(qc)
	other.ViewID = common.HexToHash("0xd1ff")
	if service.fhsQCBroadcastReplaySuppressed(other, now) {
		t.Fatal("unrelated pending QC replay was suppressed")
	}
	if err := service.beginFHSQCBroadcast(other); err == nil {
		t.Fatal("overlapping certification broadcast replaced the active QC")
	}

	// The marker is not persisted. A crash/restart must immediately recover the
	// durable outbox instead of inheriting same-process duplicate suppression.
	restarted := &Service{fhsStore: newFHSSafetyStore(db, service.ChainID(), genesis)}
	restartedPending, err := restarted.fhsStore.pendingBroadcastSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !hotstuff.SignedStateSemanticEqual(restartedPending, qc) {
		t.Fatalf("restart lost durable leader QC outbox: %+v", restartedPending)
	}
	if restarted.fhsQCBroadcastReplaySuppressed(restartedPending, now) {
		t.Fatal("restart inherited volatile initial-broadcast suppression")
	}

	if err := service.completeFHSQCBroadcast(qc, now); err != nil {
		t.Fatalf("complete initial QC broadcast: %v", err)
	}
	if !service.fhsQCBroadcastReplaySuppressed(qc, now.Add(fhsQCBroadcastReplaySuppressionWindow-time.Nanosecond)) {
		t.Fatal("matching durable replay was not suppressed immediately after the physical broadcast")
	}
	if service.fhsQCBroadcastReplaySuppressed(other, now.Add(time.Second)) {
		t.Fatal("post-send window suppressed a different QC")
	}
	if err := service.beginFHSQCBroadcast(hotstuff.CloneSignedState(qc)); err != nil {
		t.Fatalf("post-send suppression blocked a direct physical broadcast retry: %v", err)
	}
	if err := service.abortFHSQCBroadcast(qc); err != nil {
		t.Fatalf("abort direct retry fixture: %v", err)
	}
	if service.fhsQCBroadcastReplaySuppressed(qc, now.Add(fhsQCBroadcastReplaySuppressionWindow)) {
		t.Fatal("matching durable replay remained suppressed after the bounded window")
	}
	if restarted.fhsQCBroadcastReplaySuppressed(restartedPending, now.Add(time.Second)) {
		t.Fatal("restart inherited post-send replay suppression")
	}
	stillPending, err := service.fhsStore.pendingBroadcastSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !hotstuff.SignedStateSemanticEqual(stillPending, qc) {
		t.Fatal("memory-only replay suppression altered the durable replay outbox")
	}
}

func TestFHSQCBroadcastAbortDoesNotPretendPhysicalSend(t *testing.T) {
	qc := &hotstuff.SignedState{
		State:    []byte{0xfe},
		Number:   1,
		ViewID:   common.HexToHash("0xe000"),
		LeaderID: "leader",
	}
	service := &Service{}
	if err := service.beginFHSQCBroadcast(qc); err != nil {
		t.Fatal(err)
	}
	if err := service.abortFHSQCBroadcast(qc); err != nil {
		t.Fatal(err)
	}
	if service.fhsQCBroadcastReplaySuppressed(qc, time.Now()) {
		t.Fatal("aborted Before hook created post-send replay suppression")
	}

	failedBefore := &Service{
		chainConfig: &params.ChainConfig{ChainID: big.NewInt(101), FairHotstuff: true},
	}
	if err := failedBefore.OnFHSLeaderCertifiedBeforeBroadcast(qc); err == nil {
		t.Fatal("invalid QC unexpectedly passed the Before hook")
	}
	if failedBefore.fhsQCBroadcastReplaySuppressed(qc, time.Now()) {
		t.Fatal("failed Before hook pretended a physical send occurred")
	}
}

func TestFHSQCBroadcastAfterWithoutBeforeDoesNotPretendPhysicalSend(t *testing.T) {
	service := &Service{}
	qc := &hotstuff.SignedState{
		State:    []byte{0xff},
		Number:   1,
		ViewID:   common.HexToHash("0xe001"),
		LeaderID: "leader",
	}
	if err := service.OnFHSLeaderCertifiedAfterBroadcast(qc, true); err == nil {
		t.Fatal("unbracketed completion unexpectedly succeeded")
	}
	if service.fhsQCBroadcastReplaySuppressed(qc, time.Now()) {
		t.Fatal("unbracketed completion created post-send replay suppression")
	}
}

func beginRunningFHSQCBroadcast(t *testing.T, service *Service, qc *hotstuff.SignedState) uint64 {
	t.Helper()
	atomic.StoreInt32(&service.runningState, 1)
	service.muLifecycle.Lock()
	generation := service.lifecycleGenerationLocked()
	err := service.beginFHSQCBroadcastForGeneration(qc, generation)
	service.muLifecycle.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	return generation
}

func TestFHSQCBroadcastCompletionErrorStillRecordsPhysicalSend(t *testing.T) {
	service := &Service{}
	qc := &hotstuff.SignedState{
		State:    []byte{0xfd},
		Number:   2,
		ViewID:   common.HexToHash("0xe002"),
		LeaderID: "leader",
	}
	beginRunningFHSQCBroadcast(t, service, qc)
	if err := service.OnFHSLeaderCertifiedAfterBroadcast(qc, true); err == nil {
		t.Fatal("invalid certification completion unexpectedly succeeded")
	}
	if !service.fhsQCBroadcastReplaySuppressed(qc, time.Now()) {
		t.Fatal("post-send application error lost immediate replay suppression")
	}
}

func TestFHSQCBroadcastDeliveryErrorLeavesDurableReplayUnsuppressed(t *testing.T) {
	qc := &hotstuff.SignedState{
		State:    []byte{0xfc},
		Number:   3,
		ViewID:   common.HexToHash("0xe003"),
		LeaderID: "leader",
	}
	store := &fhsSafetyStore{
		loaded:           true,
		pendingBroadcast: hotstuff.CloneSignedState(qc),
	}
	service := &Service{fhsStore: store}
	beginRunningFHSQCBroadcast(t, service, qc)
	if err := service.OnFHSLeaderCertifiedAfterBroadcast(qc, false); err == nil {
		t.Fatal("invalid certification completion unexpectedly succeeded")
	}
	if service.fhsQCBroadcastReplaySuppressed(qc, time.Now()) {
		t.Fatal("failed committee delivery suppressed durable QC replay")
	}
	if !hotstuff.SignedStateSemanticEqual(store.pendingBroadcast, qc) {
		t.Fatal("failed committee delivery cleared the durable QC outbox")
	}
}

func TestFHSQCBroadcastMarkersResetAcrossMinerStopStart(t *testing.T) {
	first := &hotstuff.SignedState{
		State:    []byte{0xfb},
		Number:   4,
		ViewID:   common.HexToHash("0xe004"),
		LeaderID: "leader",
	}
	second := &hotstuff.SignedState{
		State:    []byte{0xfa},
		Number:   5,
		ViewID:   common.HexToHash("0xe005"),
		LeaderID: "leader",
	}
	service := &Service{
		netService:      &netService{},
		pacetMakerTimer: &paceMakerTimer{},
	}
	atomic.StoreInt32(&service.runningState, 1)
	if err := service.beginFHSQCBroadcast(first); err != nil {
		t.Fatal(err)
	}
	if err := service.completeFHSQCBroadcast(first, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := service.beginFHSQCBroadcast(second); err != nil {
		t.Fatal(err)
	}

	service.stop()
	service.muFHSQCBroadcast.Lock()
	activeAfterStop := service.fhsActiveQCBroadcast
	completedAfterStop := service.fhsCompletedQCBroadcast
	expiryAfterStop := service.fhsCompletedQCBroadcastExpiry
	service.muFHSQCBroadcast.Unlock()
	if activeAfterStop != nil || completedAfterStop != nil || !expiryAfterStop.IsZero() {
		t.Fatalf("MinerStop retained volatile QC markers: active=%v completed=%v expiry=%v",
			activeAfterStop, completedAfterStop, expiryAfterStop)
	}

	// Exercise the independent MinerStart boundary too. A later startup failure
	// must not restore stale process-local suppression ahead of durable WAL replay.
	if err := service.beginFHSQCBroadcast(first); err != nil {
		t.Fatal(err)
	}
	if err := service.completeFHSQCBroadcast(first, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := service.beginFHSQCBroadcast(second); err != nil {
		t.Fatal(err)
	}
	if err := service.start(nil); err == nil {
		t.Fatal("MinerStart without a consensus identity unexpectedly succeeded")
	}
	service.muFHSQCBroadcast.Lock()
	activeAfterStart := service.fhsActiveQCBroadcast
	completedAfterStart := service.fhsCompletedQCBroadcast
	expiryAfterStart := service.fhsCompletedQCBroadcastExpiry
	service.muFHSQCBroadcast.Unlock()
	if activeAfterStart != nil || completedAfterStart != nil || !expiryAfterStart.IsZero() {
		t.Fatalf("MinerStart retained volatile QC markers: active=%v completed=%v expiry=%v",
			activeAfterStart, completedAfterStart, expiryAfterStart)
	}
}

func TestFHSServiceLifecycleSerializesStartActivationBeforeStop(t *testing.T) {
	service := &Service{
		netService:      &netService{},
		pacetMakerTimer: &paceMakerTimer{beStop: true},
	}
	startEntered := make(chan struct{})
	releaseStart := make(chan struct{})
	startDone := make(chan struct{})
	go func() {
		// Service.start owns this exact critical section from its initial running
		// check through setRunState(1). The barrier makes the formerly unsafe
		// Start-observed-stopped -> Stop-returned -> Start-activated ordering exact.
		service.muLifecycle.Lock()
		service.advanceLifecycleGenerationLocked()
		close(startEntered)
		<-releaseStart
		service.setRunState(1)
		service.muLifecycle.Unlock()
		close(startDone)
	}()
	<-startEntered

	stopCalling := make(chan struct{})
	stopDone := make(chan struct{})
	go func() {
		close(stopCalling)
		service.stop()
		close(stopDone)
	}()
	<-stopCalling
	select {
	case <-stopDone:
		t.Fatal("MinerStop returned while Start still owned the activation boundary")
	case <-time.After(25 * time.Millisecond):
	}

	close(releaseStart)
	select {
	case <-startDone:
	case <-time.After(time.Second):
		t.Fatal("Start activation barrier did not complete")
	}
	select {
	case <-stopDone:
	case <-time.After(time.Second):
		t.Fatal("MinerStop did not resume after Start activation completed")
	}
	if running := atomic.LoadInt32(&service.runningState); running != 0 {
		t.Fatalf("service running state = %d after ordered Start/Stop, want stopped", running)
	}
}

func TestFHSQCBroadcastAfterStopCannotResumeConsensus(t *testing.T) {
	for _, succeeded := range []bool{false, true} {
		t.Run(map[bool]string{false: "delivery failed", true: "delivery succeeded"}[succeeded], func(t *testing.T) {
			qc := &hotstuff.SignedState{
				State: []byte{0xf9}, Number: 6, ViewID: common.HexToHash("0xe006"), LeaderID: "leader",
			}
			store := &fhsSafetyStore{loaded: true, pendingBroadcast: hotstuff.CloneSignedState(qc)}
			timer := &paceMakerTimer{beStop: true}
			service := &Service{
				fhsStore: store, netService: &netService{}, pacetMakerTimer: timer,
			}
			beginRunningFHSQCBroadcast(t, service, qc)

			service.stop()
			if err := service.OnFHSLeaderCertifiedAfterBroadcast(qc, succeeded); err == nil {
				t.Fatal("pre-stop QC completion unexpectedly resumed the stopped service")
			}
			_, stopped, _, _ := timer.get()
			if !stopped {
				t.Fatal("pre-stop QC completion restarted the pacemaker")
			}
			if !service.lastStartNewViewAt.IsZero() {
				t.Fatal("pre-stop QC completion queued a NewView after MinerStop")
			}
			if !hotstuff.SignedStateSemanticEqual(store.pendingBroadcast, qc) {
				t.Fatal("pre-stop QC completion cleared the durable replay outbox")
			}
		})
	}
}

func TestFHSReplicaCertificationAfterStopCannotResumeConsensus(t *testing.T) {
	block := types.NewBlockWithHeader(&types.Header{
		ParentHash: common.HexToHash("0xe100"),
		Number:     big.NewInt(7),
		Difficulty: big.NewInt(1),
		GasLimit:   1,
	})
	encodedBlock := block.EncodeToBytes()
	ref, err := types.NewHotstuffProposalRefWithProof(
		101, 8, common.HexToHash("0xe101"), "replica-leader",
		block, encodedBlock, []byte("replica-stop-race"), common.Hash{},
	)
	if err != nil {
		t.Fatal(err)
	}
	qc := &hotstuff.SignedState{
		State: ref.EncodeToBytes(), Number: ref.ViewNumber,
		ViewID: ref.ViewID, LeaderID: ref.LeaderID,
	}
	timer := &paceMakerTimer{beStop: true}
	service := &Service{netService: &netService{}, pacetMakerTimer: timer}
	atomic.StoreInt32(&service.runningState, 1)
	service.stop()

	if err := service.OnCertified(qc); !errors.Is(err, types.ErrNotRunning) {
		t.Fatalf("post-stop replica certification error = %v, want ErrNotRunning", err)
	}
	_, stopped, _, _ := timer.get()
	if !stopped {
		t.Fatal("post-stop replica certification restarted the pacemaker")
	}
	if !service.lastStartNewViewAt.IsZero() {
		t.Fatal("post-stop replica certification queued a NewView")
	}
}

func waitForFHSLifecycleCriticalSection(t *testing.T, service *Service) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if !service.muLifecycle.TryLock() {
			return
		}
		service.muLifecycle.Unlock()
		runtime.Gosched()
	}
	t.Fatal("certification did not enter the lifecycle critical section")
}

func testFHSLifecycleCertification(t *testing.T) (*Service, *hotstuff.SignedState, uint64) {
	t.Helper()
	block := types.NewBlockWithHeader(&types.Header{
		ParentHash: common.HexToHash("0xe200"),
		Number:     big.NewInt(9),
		Difficulty: big.NewInt(1),
		GasLimit:   1,
	})
	encodedBlock := block.EncodeToBytes()
	ref, err := types.NewHotstuffProposalRefWithProof(
		101, 10, common.HexToHash("0xe201"), "lifecycle-leader",
		block, encodedBlock, []byte("lifecycle-certification"), common.Hash{},
	)
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{
		chainConfig:     &params.ChainConfig{ChainID: big.NewInt(101), FairHotstuff: true},
		netService:      &netService{},
		pacetMakerTimer: &paceMakerTimer{beStop: true},
		hotstuffMsgQ:    newHotstuffMessageQueue(),
	}
	atomic.StoreInt32(&service.runningState, 1)
	service.muLifecycle.Lock()
	generation := service.lifecycleGenerationLocked()
	service.muLifecycle.Unlock()
	return service, &hotstuff.SignedState{
		State: ref.EncodeToBytes(), Number: ref.ViewNumber,
		ViewID: ref.ViewID, LeaderID: ref.LeaderID,
	}, generation
}

func TestFHSCertificationStopWaitsForInFlightStateCommit(t *testing.T) {
	service, qc, generation := testFHSLifecycleCertification(t)
	service.muProposalBody.Lock()
	finishDone := make(chan error, 1)
	go func() {
		finishDone <- service.finishFHSCertificationForGeneration(qc, generation)
	}()
	waitForFHSLifecycleCriticalSection(t, service)

	stopDone := make(chan struct{})
	go func() {
		service.stop()
		close(stopDone)
	}()
	select {
	case <-stopDone:
		t.Fatal("MinerStop returned while certification still owned its state/DB boundary")
	case <-time.After(25 * time.Millisecond):
	}

	service.muProposalBody.Unlock()
	select {
	case err := <-finishDone:
		if err != nil && !errors.Is(err, types.ErrNotRunning) {
			t.Fatalf("certification completion error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("certification did not leave the state/DB boundary")
	}
	select {
	case <-stopDone:
	case <-time.After(time.Second):
		t.Fatal("MinerStop did not resume after certification released the lifecycle boundary")
	}
	if running := atomic.LoadInt32(&service.runningState); running != 0 {
		t.Fatalf("running state = %d after certification/Stop interleaving", running)
	}
	_, stopped, _, _ := service.pacetMakerTimer.get()
	if !stopped {
		t.Fatal("MinerStop left the pacemaker running after in-flight certification")
	}
}

func TestFHSCertificationFailsClosedWhenSynchronousCommitStopsService(t *testing.T) {
	service, qc, generation := testFHSLifecycleCertification(t)
	service.muProposalBody.Lock()
	finishDone := make(chan error, 1)
	go func() {
		finishDone <- service.finishFHSCertificationForGeneration(qc, generation)
	}()
	waitForFHSLifecycleCriticalSection(t, service)

	// Canonical insertion invokes ProcInsertDone synchronously while the outer
	// lifecycle boundary is held. Model its reconciliation failure, which clears
	// runningState without reacquiring muLifecycle, before allowing commit to return.
	service.setRunState(0)
	service.muProposalBody.Unlock()
	select {
	case err := <-finishDone:
		if !errors.Is(err, types.ErrNotRunning) {
			t.Fatalf("synchronously stopped certification error = %v, want ErrNotRunning", err)
		}
	case <-time.After(time.Second):
		t.Fatal("synchronously stopped certification did not return")
	}
	_, stopped, _, _ := service.pacetMakerTimer.get()
	if !stopped {
		t.Fatal("synchronous commit-side stop was overwritten by pacemaker restart")
	}
	if !service.lastStartNewViewAt.IsZero() {
		t.Fatal("synchronous commit-side stop was overwritten by NewView admission")
	}
}

func TestFHSRestartRejectsIncompleteVoteWatermark(t *testing.T) {
	service := &Service{chainConfig: &params.ChainConfig{ChainID: big.NewInt(101), FairHotstuff: true}}
	vote := &hotstuff.PersistedVote{
		ViewNumber: 13,
		ViewID:     common.HexToHash("0x1300"),
		LeaderID:   "leader",
	}
	if err := service.validateRestoredFHSVote(vote); err == nil {
		t.Fatal("FHS restart accepted an incomplete safety vote watermark")
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

func signFHSEpochProposalQC(t *testing.T, fixture *fhsEpochTestFixture, ref *types.HotstuffProposalRef) *hotstuff.SignedState {
	t.Helper()
	if fixture == nil || ref == nil {
		t.Fatal("missing FHS proposal QC fixture")
	}
	state := ref.EncodeToBytes()
	threshold := hotstuff.CalcThreshold(len(fixture.keys))
	mask := make([]byte, (len(fixture.keys)+7)/8)
	var aggregate *bls.Sign
	for index := 0; index < threshold; index++ {
		signature, err := hotstuff.SignFHSSignatureWithContext(
			&fixture.keys[index], fixture.public[index], state, fixture.service.ChainID(),
			hotstuff.MsgVotePrepare, ref.ViewID, ref.LeaderID,
		)
		if err != nil {
			t.Fatal(err)
		}
		if aggregate == nil {
			aggregate = signature
		} else {
			aggregate.Add(signature)
		}
		mask[index/8] |= 1 << uint(index&7)
	}
	return &hotstuff.SignedState{
		State: state, Sign: aggregate.Serialize(), Mask: mask,
		ViewID: ref.ViewID, LeaderID: ref.LeaderID, Number: ref.ViewNumber,
	}
}

func fhsEpochCertifiedRecord(ref *types.HotstuffProposalRef, block *types.Block, qc *hotstuff.SignedState) *fhsCertifiedProposal {
	return &fhsCertifiedProposal{
		ref: ref,
		verified: &core.VerifiedProposal{
			ProposalID: ref.ProposalID(), ViewNumber: ref.ViewNumber, ViewID: ref.ViewID, LeaderID: ref.LeaderID,
			Block: block, ParentHash: block.ParentHash(), ParentNumber: block.NumberU64() - 1,
		},
		qc: qc,
	}
}

func TestCertifiedUncommittedKeyCommitteeAuthenticatesNextEpoch(t *testing.T) {
	fixture := newFHSEpochTestFixture(t)
	fixture.service.chainConfig.FairHotstuffSeed = common.HexToHash("0x5151")

	nextCommittee := fixture.committee.Copy()
	newMember := *nextCommittee.List[len(nextCommittee.List)-1]
	newMember.Address = "validator-new"
	nextCommittee.List[len(nextCommittee.List)-1] = &newMember
	nextKey := types.NewKeyBlock(&types.KeyBlockHeader{
		ParentHash: fixture.current.Hash(), Difficulty: big.NewInt(1), Number: big.NewInt(2), Time: 3,
		T_Number: 1, CommitteeHash: nextCommittee.RlpHash(),
	})
	if fixture.service.kbc.GetBlockByHash(nextKey.Hash()) != nil {
		t.Fatal("next key block unexpectedly exists in the committed key chain")
	}
	if !bftview.WriteCommittee(nextKey.NumberU64(), nextKey.Hash(), nextCommittee) {
		t.Fatal("store certified uncommitted committee")
	}
	// A hash->header lookup alone is not canonicality. Persist a noncanonical
	// copy to prove the resolver cannot bypass the certified activation path.
	rawdb.WriteKeyBlock(fixture.db, nextKey)
	if fixture.service.kbc.GetBlockByHash(nextKey.Hash()) == nil || fixture.service.kbc.GetBlockByNumber(nextKey.NumberU64()) != nil {
		t.Fatal("failed to construct noncanonical key-block lookup fixture")
	}
	if _, err := fixture.service.proposalBodySenderKey(nextKey.Hash(), nextCommittee.List[0].Address); err == nil {
		t.Fatal("noncanonical stored key block bypassed certified committee activation")
	}

	carrier := types.NewBlockWithHeader(&types.Header{
		ParentHash: common.HexToHash("0xc001"), Number: big.NewInt(2), Difficulty: big.NewInt(1),
		BlockType: types.Key_Block, KeyHash: fixture.current.Hash(),
	})
	carrier.SetKeyblock(nextKey)
	carrierRef, err := types.NewHotstuffProposalRefWithProof(
		fixture.service.ChainID(), 21, common.HexToHash("0xc021"), fixture.committee.List[0].Address,
		carrier, carrier.EncodeToBytes(), nil, common.Hash{},
	)
	if err != nil {
		t.Fatal(err)
	}
	carrierQC := signFHSEpochProposalQC(t, fixture, carrierRef)

	carrierQCID, err := hotstuff.SignedStateID(carrierQC)
	if err != nil {
		t.Fatal(err)
	}
	child := types.NewBlockWithHeader(&types.Header{
		ParentHash: carrier.Hash(), Number: big.NewInt(3), Difficulty: big.NewInt(1), KeyHash: fixture.current.Hash(),
	})
	childRef, err := types.NewHotstuffProposalRefWithProof(
		fixture.service.ChainID(), 22, common.HexToHash("0xc022"), fixture.committee.List[1].Address,
		child, child.EncodeToBytes(), nil, carrierQCID.Hash(),
	)
	if err != nil {
		t.Fatal(err)
	}
	childQC := signFHSEpochProposalQC(t, fixture, childRef)

	fixture.service.fhsCertifiedByHash = map[common.Hash]*fhsCertifiedProposal{
		carrier.Hash(): fhsEpochCertifiedRecord(carrierRef, carrier, carrierQC),
	}
	fixture.service.fhsCertifiedByID = map[common.Hash]*fhsCertifiedProposal{carrierRef.ProposalID(): fixture.service.fhsCertifiedByHash[carrier.Hash()]}
	fixture.service.proposalBodies = make(map[common.Hash]*proposalBodyMsg)
	fixture.service.fhsHighest = fixture.service.fhsCertifiedByHash[carrier.Hash()]
	fixture.service.currentView.TxNumber = carrier.NumberU64()
	fixture.service.currentView.TxHash = carrier.Hash()
	fixture.service.currentView.ViewNumber = carrierRef.ViewNumber
	transportPeers, err := fixture.service.fhsPeerAuthorizationWithCertifiedCarriers(fixture.committee)
	if err != nil {
		t.Fatalf("authorize pending certified committee transport peers: %v", err)
	}
	if len(transportPeers) != len(fixture.committee.List)+1 || len(transportPeers[newMember.Address]) == 0 {
		t.Fatalf("pending committee transport union omitted new member: peers=%d new=%x", len(transportPeers), transportPeers[newMember.Address])
	}
	if _, err := fixture.service.proposalBodySenderKey(nextKey.Hash(), nextCommittee.List[0].Address); err == nil {
		t.Fatal("committee DB entry and certified carrier were trusted without an activation QC")
	}

	leaderIndex, err := fairHotstuffLeaderIndex(
		fixture.service.chainConfig.FairHotstuffSeed, fixture.service.ChainID(), childRef.ViewNumber+1,
		nextKey.CommitteeHash(), len(nextCommittee.List),
	)
	if err != nil {
		t.Fatal(err)
	}
	leader := nextCommittee.List[leaderIndex]
	proposal := types.NewBlockWithHeader(&types.Header{
		ParentHash: child.Hash(), Number: big.NewInt(4), Difficulty: big.NewInt(1), KeyHash: nextKey.Hash(),
		UncleHash:             types.CalcUncleHash(nil),
		CommonTxAdmissionRoot: types.DeriveCommonTxAdmissionRoot(nil, nil),
		CommonTxRewardRoot:    types.DeriveCommonTxRewardRoot(nil),
	})
	childQCBytes, err := hotstuff.EncodeSignedState(childQC)
	if err != nil {
		t.Fatal(err)
	}
	childQCID, err := hotstuff.SignedStateID(childQC)
	if err != nil {
		t.Fatal(err)
	}
	proposalRef, err := types.NewHotstuffProposalRefWithProof(
		fixture.service.ChainID(), childRef.ViewNumber+1, common.HexToHash("0xc023"), leader.Address,
		proposal, proposal.EncodeToBytes(), nil, childQCID.Hash(),
	)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := encodeProposalDataManifest(proposal)
	if err != nil {
		t.Fatal(err)
	}
	body := &proposalBodyMsg{
		Type: proposalBodyMsgManifest, ProposalID: proposalRef.ProposalID(), BodyHash: proposalRef.BodyHash,
		BodySize: proposalRef.BodySize, Number: proposalRef.Number, ViewNumber: proposalRef.ViewNumber,
		ViewID: proposalRef.ViewID, LeaderID: proposalRef.LeaderID, From: proposalRef.LeaderID,
		ProposalKeyHash: nextKey.Hash(), SenderKeyHash: nextKey.Hash(), Manifest: manifest, ParentQC: childQCBytes,
	}
	digest, err := proposalBodyAuthDigest(fixture.service.ChainID(), body)
	if err != nil {
		t.Fatal(err)
	}
	body.AuthSig = fixture.keys[leaderIndex].SignHash(digest).Serialize()

	// Reproduce the live ordering: carrier QC installed, child manifest/body
	// validated and voted, but the child QCBroadcast was dropped. The first
	// new-epoch manifest must authenticate from its old-committee ParentQC
	// without publishing a synthetic certified child.
	carrierQCBytes, err := hotstuff.EncodeSignedState(carrierQC)
	if err != nil {
		t.Fatal(err)
	}
	wrongActivation := cloneProposalBodyMsg(body)
	wrongActivation.ParentQC = carrierQCBytes
	wrongDigest, err := proposalBodyAuthDigest(fixture.service.ChainID(), wrongActivation)
	if err != nil {
		t.Fatal(err)
	}
	wrongActivation.AuthSig = fixture.keys[leaderIndex].SignHash(wrongDigest).Serialize()
	if err := fixture.service.verifyProposalBodySender(&network.ServerIdentity{Address: network.Address(leader.Address)}, wrongActivation); err == nil {
		t.Fatal("carrier QC was accepted as its own direct-child activation proof")
	}
	if err := fixture.service.verifyProposalBodySender(&network.ServerIdentity{Address: network.Address(leader.Address)}, body); err != nil {
		t.Fatalf("authenticate first next-epoch manifest from activation QC: %v", err)
	}
	if err := fixture.service.verifyProposalManifestAuthority(body); err != nil {
		t.Fatalf("first next-epoch manifest authority rejected: %v", err)
	}
	if _, err := fixture.service.proposalBodySenderKey(nextKey.Hash(), leader.Address); err == nil {
		t.Fatal("contextual activation proof escaped before authenticated manifest publication")
	}
	if _, err := fixture.service.storeProposalManifest(body); err != nil {
		t.Fatalf("publish authenticated next-epoch manifest: %v", err)
	}

	public, err := fixture.service.proposalBodySenderKey(nextKey.Hash(), leader.Address)
	if err != nil || public == nil || !public.IsEqual(fixture.public[leaderIndex]) {
		t.Fatalf("resolve certified uncommitted sidecar signer: public=%v err=%v", public, err)
	}
	keys, err := fixture.service.GetPublicKey(nextKey.Hash())
	if err != nil || len(keys) != len(nextCommittee.List) {
		t.Fatalf("resolve certified uncommitted QC committee: keys=%d err=%v", len(keys), err)
	}
	leaderKey, err := fixture.service.FHSLeaderPublicKey(nextKey.Hash(), leader.Address)
	if err != nil || leaderKey == nil || !leaderKey.IsEqual(fixture.public[leaderIndex]) {
		t.Fatalf("resolve certified uncommitted leader key: public=%v err=%v", leaderKey, err)
	}
	proposalQC := signFHSEpochProposalQC(t, fixture, proposalRef)
	if _, err := fixture.service.verifyFHSQCCryptographic(proposalQC); err != nil {
		t.Fatalf("verify next-epoch QC with certified uncommitted committee: %v", err)
	}
	if target := fixture.service.proposalRepairTarget(proposalRef, 0); target == nil || target.Address != leader.Address {
		t.Fatalf("next-epoch repair target = %#v, want %s", target, leader.Address)
	}
	prepareCommittee, err := fixture.service.hotstuffBroadcastCommittee(&hotstuff.HotstuffMessage{
		Code: hotstuff.MsgPrepare, DataB: proposalRef.EncodeToBytes(),
	})
	if err != nil || prepareCommittee == nil || prepareCommittee.RlpHash() != nextCommittee.RlpHash() {
		t.Fatalf("resolve next-epoch Prepare committee: committee=%v err=%v", prepareCommittee, err)
	}
	peers := make(map[string][]byte)
	if err := fixture.service.addFHSCommitteePeers(peers, nextKey.Hash()); err != nil || len(peers) != len(nextCommittee.List) {
		t.Fatalf("resolve next-epoch authenticated peers: peers=%d err=%v", len(peers), err)
	}
	tamperedLeader := cloneProposalBodyMsg(body)
	tamperedLeader.LeaderID = nextCommittee.List[(int(leaderIndex)+1)%len(nextCommittee.List)].Address
	tamperedLeader.From = tamperedLeader.LeaderID
	if err := fixture.service.verifyProposalManifestAuthority(tamperedLeader); err == nil {
		t.Fatal("non-PRF next-epoch manifest leader was accepted")
	}
	tamperedParent := cloneProposalBodyMsg(body)
	tamperedParent.ParentQC = nil
	if err := fixture.service.verifyProposalManifestAuthority(tamperedParent); err == nil {
		t.Fatal("next-epoch manifest without its activation parent QC was accepted")
	}
	farFuture := cloneProposalBodyMsg(body)
	farFuture.ViewNumber++
	if err := fixture.service.verifyProposalManifestAuthority(farFuture); err == nil {
		t.Fatal("activation QC authorized an unbound future-view manifest")
	}

	fixture.service.muProposalBody.Lock()
	delete(fixture.service.proposalBodies, body.ProposalID)
	fixture.service.muProposalBody.Unlock()
	if _, err := fixture.service.proposalBodySenderKey(nextKey.Hash(), leader.Address); err == nil {
		t.Fatal("activated committee remained trusted after its only verified activation proof was removed")
	}
	fixture.service.fhsCertifiedByHash[child.Hash()] = fhsEpochCertifiedRecord(childRef, child, childQC)
	fixture.service.fhsCertifiedByID[childRef.ProposalID()] = fixture.service.fhsCertifiedByHash[child.Hash()]
	fixture.service.fhsHighest = fixture.service.fhsCertifiedByHash[child.Hash()]
	if _, err := fixture.service.proposalBodySenderKey(nextKey.Hash(), leader.Address); err != nil {
		t.Fatalf("installed direct-child activation QC did not resolve the new committee: %v", err)
	}
}

func TestProposalRepairUsesProposalHistoricalCommitteeGeneration(t *testing.T) {
	fixture := newFHSEpochTestFixture(t)
	historicalKey := fixture.historical
	historicalNode := fixture.committee.List[0]

	public, err := fixture.service.proposalBodySenderKey(historicalKey.Hash(), historicalNode.Address)
	if err != nil || public == nil || !public.IsEqual(fixture.public[0]) {
		t.Fatalf("resolve historical sidecar signer: public=%v err=%v", public, err)
	}
	ref := &types.HotstuffProposalRef{
		Version: types.HotstuffProposalRefVersion, ChainID: fixture.service.ChainID(),
		Number: 2, ViewNumber: 30, ViewID: common.HexToHash("0x3001"), LeaderID: historicalNode.Address,
		BlockHash: common.HexToHash("0x3002"), ParentHash: common.HexToHash("0x3003"),
		BodyHash: common.HexToHash("0x3004"), BodySize: 1, ExtraHash: types.HotstuffProposalExtraHash(nil),
		KeyHash: historicalKey.Hash(),
	}
	target := fixture.service.proposalRepairTarget(ref, 0)
	if target == nil || target.Address != historicalNode.Address {
		t.Fatalf("repair target = %#v, want historical proposal leader %s", target, historicalNode.Address)
	}
}

func TestProposalRepairTargetHandlesHighBitProposalID(t *testing.T) {
	fixture := newFHSEpochTestFixture(t)
	ref := &types.HotstuffProposalRef{
		Version: types.HotstuffProposalRefVersion, ChainID: fixture.service.ChainID(),
		Number: 2, ViewNumber: 30, ViewID: common.HexToHash("0x3101"), LeaderID: "unavailable-leader",
		BlockHash: common.HexToHash("0x3102"), ParentHash: common.HexToHash("0x3103"),
		BodySize: 1, ExtraHash: types.HotstuffProposalExtraHash(nil), KeyHash: fixture.historical.Hash(),
	}
	const attempt = uint64(1)
	var seed uint64
	found := false
	for nonce := uint64(1); nonce < 1<<16; nonce++ {
		ref.BodyHash = common.BigToHash(new(big.Int).SetUint64(nonce))
		proposalID := ref.ProposalID()
		seed = binary.BigEndian.Uint64(proposalID[:8]) + attempt
		if seed&(uint64(1)<<63) != 0 && seed%uint64(len(fixture.committee.List)) != 0 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("failed to construct a high-bit proposal repair seed")
	}

	want := fixture.committee.List[int(seed%uint64(len(fixture.committee.List)))]
	got := fixture.service.proposalRepairTarget(ref, attempt)
	if got == nil || got.Address != want.Address {
		t.Fatalf("high-bit repair target = %#v, want index %d (%s)", got, seed%uint64(len(fixture.committee.List)), want.Address)
	}
}

func TestProposalRepairFallsBackToValidatedDurableBody(t *testing.T) {
	db := memorydb.New()
	service := &Service{
		chainConfig:    &params.ChainConfig{ChainID: big.NewInt(101), FairHotstuff: true},
		fhsStore:       newFHSSafetyStore(db, 101, common.HexToHash("0xabc")),
		proposalBodies: make(map[common.Hash]*proposalBodyMsg),
	}
	ref, persistedBody := writeFHSPersistenceProposal(t, db, 101, 7, 19, 1, nil)
	request := &proposalBodyMsg{
		Type:            proposalBodyMsgRepairRequest,
		ProposalID:      ref.ProposalID(),
		BodyHash:        ref.BodyHash,
		BodySize:        ref.BodySize,
		Number:          ref.Number,
		ViewNumber:      ref.ViewNumber,
		ViewID:          ref.ViewID,
		LeaderID:        ref.LeaderID,
		ProposalKeyHash: ref.KeyHash,
	}

	body, fromDurable, err := service.proposalBodyForRepairRequest(request)
	if err != nil {
		t.Fatalf("read durable repair body: %v", err)
	}
	if !fromDurable || body == nil || !bytes.Equal(body.EncodedBlock, persistedBody.EncodedBlock) ||
		!bytes.Equal(body.Extra, persistedBody.Extra) {
		t.Fatalf("durable repair body mismatch: durable=%v body=%+v", fromDurable, body)
	}
	if cached := service.getProposalBody(ref.ProposalID()); cached != nil {
		t.Fatal("durable repair lookup unexpectedly mutated the volatile cache")
	}

	mismatched := cloneProposalBodyMsg(request)
	mismatched.ViewNumber++
	if body, _, err := service.proposalBodyForRepairRequest(mismatched); err == nil || body != nil {
		t.Fatalf("mismatched durable repair context was accepted: body=%+v err=%v", body, err)
	}

	encodedProposal, err := rawdb.ReadFHSProposal(db, ref.ProposalID())
	if err != nil {
		t.Fatal(err)
	}
	if err := rawdb.WriteFHSProposal(db, ref.ProposalID(), []byte{0xff}); err != nil {
		t.Fatal(err)
	}
	if body, _, err := service.proposalBodyForRepairRequest(request); err == nil || body != nil {
		t.Fatalf("corrupt durable proposal was accepted: body=%+v err=%v", body, err)
	}
	if err := rawdb.WriteFHSProposal(db, ref.ProposalID(), encodedProposal); err != nil {
		t.Fatal(err)
	}

	corruptBody, err := rlp.EncodeToBytes(&fhsDiskBody{BodyHash: ref.BodyHash, EncodedBlock: []byte("corrupt")})
	if err != nil {
		t.Fatal(err)
	}
	if err := rawdb.WriteFHSBody(db, ref.BodyHash, corruptBody); err != nil {
		t.Fatal(err)
	}
	if body, _, err := service.proposalBodyForRepairRequest(request); err == nil || body != nil {
		t.Fatalf("corrupt durable body was accepted: body=%+v err=%v", body, err)
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
	state.LastVote = testPersistedVote(t, fixture.service.ChainID(), 18, common.HexToHash("0x1800"), "leader", 1)
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
