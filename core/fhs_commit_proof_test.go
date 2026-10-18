package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus/colossusX"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/trie"
	lru "github.com/hashicorp/golang-lru"
)

func TestInsertChainRetriesFHSPublicationBusyAfterUnlock(t *testing.T) {
	bc := &BlockChain{}
	release := make(chan struct{})
	waiting := make(chan struct{})
	var calls, waits int32
	bc.fhsSyncWaitPublication = func() {
		atomic.AddInt32(&waits, 1)
		close(waiting)
		<-release
	}

	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := bc.insertChainWithFHSPublicationRetry(func() (int, error) {
			if atomic.AddInt32(&calls, 1) == 1 {
				return 3, ErrFHSFinalizedSyncPublicationBusy
			}
			return 7, nil
		})
		done <- result{n: n, err: err}
	}()

	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	select {
	case <-waiting:
	case <-time.After(time.Second):
		t.Fatal("insertion did not wait after the retryable publication conflict")
	}
	// The live publication must be able to take chainmu while the importer is
	// waiting; otherwise this retry path recreates the original ABBA deadlock.
	chainLockAvailable := make(chan struct{})
	go func() {
		bc.chainmu.Lock()
		bc.chainmu.Unlock()
		close(chainLockAvailable)
	}()
	select {
	case <-chainLockAvailable:
	case <-time.After(time.Second):
		t.Fatal("chainmu remained locked while waiting for the publication barrier")
	}
	close(release)
	released = true

	select {
	case got := <-done:
		if got.err != nil || got.n != 7 {
			t.Fatalf("retry result = (%d, %v), want (7, nil)", got.n, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("insertion did not retry after publication release")
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("insertion calls = %d, want 2", got)
	}
	if got := atomic.LoadInt32(&waits); got != 1 {
		t.Fatalf("publication waits = %d, want 1", got)
	}
}

func TestInsertChainDoesNotRetryNonBusyError(t *testing.T) {
	bc := &BlockChain{}
	var calls, waits int32
	bc.fhsSyncWaitPublication = func() { atomic.AddInt32(&waits, 1) }
	wantErr := errors.New("invalid proof")
	n, err := bc.insertChainWithFHSPublicationRetry(func() (int, error) {
		atomic.AddInt32(&calls, 1)
		return 4, wantErr
	})
	if n != 4 || !errors.Is(err, wantErr) {
		t.Fatalf("non-busy result = (%d, %v), want (4, %v)", n, err, wantErr)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("insertion calls = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&waits); got != 0 {
		t.Fatalf("publication waits = %d, want 0", got)
	}
}

func TestFHSFinalizedSyncLifecycleRejectsPartialHooks(t *testing.T) {
	bc := &BlockChain{
		fhsSyncBeforeKeyCommit: func(*types.Block, *hotstuff.SignedState) (bool, error) {
			return true, nil
		},
	}
	block := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(1)})
	_, err := bc.commitFHSSyncVerifiedProposal(
		&VerifiedProposal{Block: block},
		&hotstuff.SignedState{},
	)
	if err == nil || err.Error() != "incomplete Fair HotStuff finalized sync key lifecycle" {
		t.Fatalf("partial lifecycle error = %v", err)
	}
}

func makeFHSCommitProofValidator(t *testing.T) (*BlockValidator, []bls.SecretKey, []*bls.PublicKey, common.Hash) {
	t.Helper()
	db := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { _ = db.Close() })
	secrets := make([]bls.SecretKey, 7)
	public := make([]*bls.PublicKey, 7)
	committee := &bftview.Committee{List: make([]*common.Cnode, 7)}
	for index := range secrets {
		secrets[index].SetByCSPRNG()
		public[index] = secrets[index].GetPublicKey()
		committee.List[index] = &common.Cnode{
			Address: fmt.Sprintf("validator-%d:7101", index),
			Public:  public[index].SerializeToHexStr(),
		}
	}
	keyBlock := types.NewKeyBlock(&types.KeyBlockHeader{
		Difficulty:    big.NewInt(1),
		Number:        big.NewInt(0),
		Time:          1,
		CommitteeHash: committee.RlpHash(),
	})
	rawdb.WriteKeyBlock(db, keyBlock)
	rawdb.WriteKeyBlockHash(db, keyBlock.Hash(), 0)
	rawdb.WriteHeadKeyBlockHash(db, keyBlock.Hash())
	bftview.SetCommitteeConfig(db, nil, nil)
	if !bftview.WriteCommittee(0, keyBlock.Hash(), committee) {
		t.Fatal("store FHS proof committee")
	}
	numberCache, _ := lru.New(headerCacheLimit)
	headerCache, _ := lru.New(headerCacheLimit)
	blockCache, _ := lru.New(blockCacheLimit)
	kbc := &KeyBlockChain{
		db:         db,
		blockCache: blockCache,
		khc: &KeyHeaderChain{
			chainDb:     db,
			headerCache: headerCache,
			numberCache: numberCache,
		},
	}
	kbc.currentBlock.Store(keyBlock)
	config := &params.ChainConfig{ChainID: big.NewInt(10101919), FairHotstuff: true}
	bc := &BlockChain{chainConfig: config, db: db, keyBlockChain: kbc}
	validator := NewBlockValidator(config, bc, nil)
	bc.validator = validator
	return validator, secrets, public, keyBlock.Hash()
}

func makeFHSCommitProofQC(t *testing.T, block *types.Block, view uint64, leader string, parentQCID common.Hash, secrets []bls.SecretKey, public []*bls.PublicKey) (*types.HotstuffProposalRef, *hotstuff.SignedState) {
	t.Helper()
	viewID := common.BigToHash(new(big.Int).SetUint64(view))
	unsigned := block.CopyOrg()
	encoded := unsigned.EncodeToBytes()
	ref, err := types.NewHotstuffProposalRefWithCommitments(
		10101919, view, viewID, leader, unsigned, encoded,
		types.HotstuffProposalExtraHash(nil), parentQCID,
	)
	if err != nil {
		t.Fatal(err)
	}
	state := ref.EncodeToBytes()
	var aggregate *bls.Sign
	for index := 0; index < 5; index++ {
		signature, err := hotstuff.SignFHSSignatureWithContext(&secrets[index], public[index], state, 10101919, hotstuff.MsgVotePrepare, viewID, leader)
		if err != nil {
			t.Fatal(err)
		}
		if aggregate == nil {
			aggregate = signature
		} else {
			aggregate.Add(signature)
		}
	}
	qc := &hotstuff.SignedState{
		State:    state,
		Sign:     aggregate.Serialize(),
		Mask:     []byte{0x1f},
		ViewID:   viewID,
		LeaderID: leader,
		Number:   view,
	}
	return ref, qc
}

func TestVerifyFHS2ChainCommitProofRequiresDirectChildQC(t *testing.T) {
	validator, secrets, public, keyHash := makeFHSCommitProofValidator(t)
	target := types.NewBlockWithHeader(&types.Header{
		ParentHash: common.HexToHash("0x01"),
		Number:     big.NewInt(1),
		Difficulty: big.NewInt(1),
		BlockType:  types.FastTx_Block,
		KeyHash:    keyHash,
	})
	targetRef, targetQC := makeFHSCommitProofQC(t, target, 10, "leader-10", common.Hash{}, secrets, public)
	target.SetFHSSignature(targetQC.Sign, targetQC.Mask, targetQC.ViewID, targetQC.LeaderID, targetQC.Number, targetRef.ExtraHash, targetRef.ParentQCID)
	targetID, err := hotstuff.SignedStateID(targetQC)
	if err != nil {
		t.Fatal(err)
	}
	child := types.NewBlockWithHeader(&types.Header{
		ParentHash: target.Hash(),
		Number:     big.NewInt(2),
		Difficulty: big.NewInt(1),
		BlockType:  types.FastTx_Block,
		KeyHash:    keyHash,
	})
	_, skippedQC := makeFHSCommitProofQC(t, child, 14, "leader-14", targetID.Hash(), secrets, public)
	if err := validator.VerifyFHS2ChainCommitProof(target, skippedQC); err == nil {
		t.Fatal("nonconsecutive views were accepted as a terminal 2-chain commit proof")
	}
	_, childQC := makeFHSCommitProofQC(t, child, 11, "leader-11", targetID.Hash(), secrets, public)
	if err := validator.VerifyFHS2ChainCommitProof(target, childQC); err != nil {
		t.Fatalf("valid direct-child QC proof rejected: %v", err)
	}

	_, wrongParentQC := makeFHSCommitProofQC(t, child, 15, "leader-15", common.HexToHash("0xdead"), secrets, public)
	if err := validator.VerifyFHS2ChainCommitProof(target, wrongParentQC); err == nil {
		t.Fatal("child QC without the exact target QC identity was accepted")
	}
	if err := validator.VerifyFHS2ChainCommitProof(target, targetQC); err == nil {
		t.Fatal("target's own one-chain QC was accepted as a 2-chain finality proof")
	}
	tampered := hotstuff.CloneSignedState(childQC)
	tampered.Sign[0] ^= 0xff
	if err := validator.VerifyFHS2ChainCommitProof(target, tampered); err == nil {
		t.Fatal("tampered child QC was accepted as a finality proof")
	}

	encoded, err := encodeFHSFinalityProof(childQC)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.SetFHSFinalityProof(encoded); err != nil {
		t.Fatal(err)
	}
	decoded, present, err := decodeFHSFinalityProof(target)
	if err != nil || !present {
		t.Fatalf("decode valid embedded proof: present=%v err=%v", present, err)
	}
	if err := validator.VerifyFHS2ChainCommitProof(target, decoded); err != nil {
		t.Fatalf("valid embedded direct-child QC rejected: %v", err)
	}

	malformed := target.WithSeal(target.Header())
	if err := malformed.SetFHSFinalityProof([]byte{0xff}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeFHSFinalityProof(malformed); err == nil {
		t.Fatal("malformed embedded finality proof was accepted")
	}

}

func TestVerifyFHS2ChainCommitProofBindsPipelinedKeyCarrierHeight(t *testing.T) {
	validator, secrets, public, oldKeyHash := makeFHSCommitProofValidator(t)
	makeTarget := func(tNumber uint64) (*types.Block, *hotstuff.SignedState) {
		keyBlock := types.NewKeyBlock(&types.KeyBlockHeader{
			ParentHash: oldKeyHash,
			Number:     big.NewInt(1),
			Difficulty: big.NewInt(1),
			Time:       2,
			T_Number:   tNumber,
		})
		target := types.NewBlockWithHeader(&types.Header{
			ParentHash: common.HexToHash("0x03"),
			Number:     big.NewInt(4),
			Difficulty: big.NewInt(1),
			BlockType:  types.Key_Block,
			KeyHash:    oldKeyHash,
		})
		target.SetKeyblock(keyBlock)
		targetRef, targetQC := makeFHSCommitProofQC(t, target, 39, "leader-39", common.Hash{}, secrets, public)
		target.SetFHSSignature(targetQC.Sign, targetQC.Mask, targetQC.ViewID, targetQC.LeaderID, targetQC.Number, targetRef.ExtraHash, targetRef.ParentQCID)
		return target, targetQC
	}
	makeChildQC := func(target *types.Block, targetQC *hotstuff.SignedState) *hotstuff.SignedState {
		targetID, err := hotstuff.SignedStateID(targetQC)
		if err != nil {
			t.Fatal(err)
		}
		child := types.NewBlockWithHeader(&types.Header{
			ParentHash: target.Hash(),
			Number:     big.NewInt(5),
			Difficulty: big.NewInt(1),
			BlockType:  types.FastTx_Block,
			KeyHash:    oldKeyHash,
		})
		_, qc := makeFHSCommitProofQC(t, child, 40, "leader-40", targetID.Hash(), secrets, public)
		return qc
	}

	staleTarget, staleQC := makeTarget(2) // canonical head, not proposal parent
	if err := validator.VerifyFHS2ChainCommitProof(staleTarget, makeChildQC(staleTarget, staleQC)); err == nil {
		t.Fatal("child QC accepted a key carrier whose T_Number omitted the certified parent")
	}

	validTarget, validQC := makeTarget(3) // exact parent of carrier tx block #4
	if err := validator.VerifyFHS2ChainCommitProof(validTarget, makeChildQC(validTarget, validQC)); err != nil {
		t.Fatalf("valid pipelined key carrier proof rejected: %v", err)
	}
}

// The checkpoint fixtures use a fresh state database for every read. A warm trie
// or code cache must not conceal content missing from the persistent database.
type fhsCheckpointTestFixture struct {
	bc          *BlockChain
	genesis     *Genesis
	block       *types.Block
	address     common.Address
	storageRoot common.Hash
	child       common.Hash
}

func newFHSCheckpointTestFixture(t *testing.T, db ethdb.Database) fhsCheckpointTestFixture {
	t.Helper()
	genesis := testFairHotstuffGenesis()
	address := common.HexToAddress("0xcafe")
	storage := make(map[common.Hash]common.Hash)
	for i := int64(1); i <= 8; i++ {
		storage[common.BigToHash(big.NewInt(i))] = common.BigToHash(big.NewInt(100 + i))
	}
	genesis.Alloc[address] = GenesisAccount{
		Balance: big.NewInt(123456789), Nonce: 7,
		Code: []byte{0x60, 0x2a, 0x60, 0x00, 0x52, 0x00}, Storage: storage,
	}
	for i := int64(1); i <= 5; i++ {
		genesis.Alloc[common.BigToAddress(big.NewInt(i))] = GenesisAccount{Balance: big.NewInt(1000 + i)}
	}
	block, err := genesis.Commit(db)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := state.New(block.Root(), state.NewDatabase(db), nil)
	if err != nil {
		t.Fatal(err)
	}
	storageRoot := fresh.StorageTrie(address).Hash()
	accountTrie, err := fresh.Database().OpenTrie(block.Root())
	if err != nil {
		t.Fatal(err)
	}
	iterator := accountTrie.NodeIterator(nil)
	var child common.Hash
	for iterator.Next(true) {
		if hash := iterator.Hash(); hash != (common.Hash{}) && hash != block.Root() {
			child = hash
			break
		}
	}
	if err := iterator.Error(); err != nil {
		t.Fatal(err)
	}
	if child == (common.Hash{}) {
		t.Fatal("checkpoint fixture has no standalone interior account node")
	}
	return fhsCheckpointTestFixture{
		bc:      &BlockChain{db: db, chainConfig: genesis.Config, genesisBlock: block},
		genesis: genesis, block: block, address: address, storageRoot: storageRoot, child: child,
	}
}

func assertFHSCheckpointNoReady(t *testing.T, bc *BlockChain) {
	t.Helper()
	if _, err := bc.FHSCheckpointAnchor(); err == nil {
		t.Fatal("incomplete checkpoint exposed a completed anchor")
	}
	ready, err := rawdb.ReadFHSCheckpointReady(bc.db)
	if err != nil || len(ready) != 0 {
		t.Fatalf("incomplete checkpoint READY bytes=%x error=%v", ready, err)
	}
}

func runFHSCheckpointTest(t *testing.T, job *FHSCheckpoint, nodes, byteLimit uint64) (FHSCheckpointProgress, error) {
	t.Helper()
	var progress FHSCheckpointProgress
	for i := 0; i < 4096; i++ {
		previous := job.progress
		var err error
		progress, err = job.Step(context.Background(), nodes, byteLimit)
		if progress.Nodes < previous.Nodes || progress.Bytes < previous.Bytes {
			t.Fatalf("checkpoint counters moved backwards: previous=%+v current=%+v", previous, progress)
		}
		if progress.Nodes-previous.Nodes > nodes || progress.Bytes-previous.Bytes > byteLimit {
			t.Fatalf("checkpoint step exceeded node/byte budget (%d, %d): previous=%+v current=%+v", nodes, byteLimit, previous, progress)
		}
		if err != nil || progress.Ready {
			return progress, err
		}
	}
	t.Fatal("checkpoint did not finish within the small fixture's step bound")
	return progress, nil
}

func assertFHSCheckpointTestState(t *testing.T, db ethdb.Database, fixture fhsCheckpointTestFixture) {
	t.Helper()
	fresh, err := state.New(fixture.block.Root(), state.NewDatabase(db), nil)
	if err != nil {
		t.Fatalf("open checkpoint state from a fresh cache: %v", err)
	}
	for address, account := range fixture.genesis.Alloc {
		if balance := fresh.GetBalance(address); balance.Cmp(account.Balance) != 0 {
			t.Fatalf("balance for %s=%s, want %s", address, balance, account.Balance)
		}
		if code := fresh.GetCode(address); !bytes.Equal(code, account.Code) {
			t.Fatalf("code for %s=%x, want %x", address, code, account.Code)
		}
		if nonce := fresh.GetNonce(address); nonce != account.Nonce {
			t.Fatalf("nonce for %s=%d, want %d", address, nonce, account.Nonce)
		}
		for key, want := range account.Storage {
			if got := fresh.GetState(address, key); got != want {
				t.Fatalf("storage for %s at %s=%s, want %s", address, key, got, want)
			}
		}
	}
	if err := fresh.Error(); err != nil {
		t.Fatalf("fresh checkpoint state read: %v", err)
	}
}

func TestFHSCheckpointGenesisDurableReopen(t *testing.T) {
	path := t.TempDir()
	db, err := rawdb.NewLevelDBDatabase(path, 16, 16, "fhs-checkpoint-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	fixture := newFHSCheckpointTestFixture(t, db)
	assertFHSCheckpointNoReady(t, fixture.bc)
	job, err := fixture.bc.BeginFHSCheckpoint(context.Background(), fixture.block.Hash(), FHSCheckpointLimits{MaxNodes: 10000, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer job.Close()
	assertFHSCheckpointNoReady(t, fixture.bc)
	progress, err := runFHSCheckpointTest(t, job, 1, 4096)
	if err != nil || !progress.Ready {
		t.Fatalf("checkpoint ready=%v error=%v", progress.Ready, err)
	}
	anchor, err := fixture.bc.FHSCheckpointAnchor()
	if err != nil {
		t.Fatal(err)
	}
	if anchor != progress.Anchor || anchor.Number != 0 || anchor.BlockHash != fixture.block.Hash() || anchor.StateRoot != fixture.block.Root() || anchor.GenesisHash != fixture.block.Hash() || anchor.ConfigHash == (common.Hash{}) {
		t.Fatalf("wrong checkpoint anchor: %+v, progress=%+v", anchor, progress)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = rawdb.NewLevelDBDatabase(path, 16, 16, "fhs-checkpoint-reopened-test")
	if err != nil {
		t.Fatal(err)
	}
	reopened := &BlockChain{db: db, chainConfig: fixture.genesis.Config, genesisBlock: fixture.block}
	persisted, err := reopened.FHSCheckpointAnchor()
	if err != nil || persisted != anchor {
		t.Fatalf("reopened checkpoint anchor=%+v error=%v, want %+v", persisted, err, anchor)
	}
	assertFHSCheckpointTestState(t, db, fixture)
}

func TestFHSCheckpointRejectsIncompleteReachableState(t *testing.T) {
	for _, name := range []string{"root", "interior", "storage", "code", "corrupt-root", "corrupt-code"} {
		t.Run(name, func(t *testing.T) {
			db := rawdb.NewMemoryDatabase()
			defer db.Close()
			fixture := newFHSCheckpointTestFixture(t, db)
			codeHash := crypto.Keccak256Hash(fixture.genesis.Alloc[fixture.address].Code)
			switch name {
			case "root":
				rawdb.DeleteTrieNode(db, fixture.block.Root())
			case "interior":
				rawdb.DeleteTrieNode(db, fixture.child)
				// Merely opening the root still succeeds when a descendant is missing.
				if _, err := state.New(fixture.block.Root(), state.NewDatabase(db), nil); err != nil {
					t.Fatalf("missing-interior fixture lost its root: %v", err)
				}
			case "storage":
				rawdb.DeleteTrieNode(db, fixture.storageRoot)
			case "code":
				rawdb.DeleteCode(db, codeHash)
				if err := db.Delete(codeHash.Bytes()); err != nil {
					t.Fatal(err)
				}
			case "corrupt-root":
				if err := db.Put(fixture.block.Root().Bytes(), []byte{0xff}); err != nil {
					t.Fatal(err)
				}
			case "corrupt-code":
				rawdb.WriteCode(db, codeHash, []byte{0x00})
			}
			job, err := fixture.bc.BeginFHSCheckpoint(context.Background(), fixture.block.Hash(), FHSCheckpointLimits{MaxNodes: 10000, MaxBytes: 1 << 20})
			if err == nil {
				defer job.Close()
				var progress FHSCheckpointProgress
				progress, err = runFHSCheckpointTest(t, job, 1, 4096)
				if progress.Ready {
					t.Fatal("incomplete or corrupt reachable state became READY")
				}
			}
			if err == nil {
				t.Fatal("incomplete or corrupt reachable state was accepted")
			}
			assertFHSCheckpointNoReady(t, fixture.bc)
		})
	}
}

var errFHSCheckpointTestIO = errors.New("injected checkpoint database failure")

type fhsCheckpointTestDB struct {
	ethdb.Database
	noSync        bool
	failSync      int
	commitFailure bool
	failPut       bool
	failGet       []byte
	enterSync     chan struct{}
	releaseSync   <-chan struct{}
	readyApplied  chan struct{}
	readyRelease  <-chan struct{}
	failReady     bool
	syncCalls     int
	asyncCalls    int
	maxBatchBytes uint64
}

func (db *fhsCheckpointTestDB) Get(key []byte) ([]byte, error) {
	if len(db.failGet) != 0 && bytes.Equal(key, db.failGet) {
		return nil, errFHSCheckpointTestIO
	}
	return db.Database.Get(key)
}

func (db *fhsCheckpointTestDB) NewBatch() ethdb.Batch {
	batch := &fhsCheckpointTestBatch{Batch: db.Database.NewBatch(), db: db}
	if db.noSync {
		// This wrapper deliberately exposes only ethdb.Batch, even when the
		// underlying memory database implements the stronger SyncBatch API.
		return &fhsCheckpointTestPlainBatch{Batch: batch}
	}
	return batch
}

type fhsCheckpointTestPlainBatch struct{ ethdb.Batch }

type fhsCheckpointTestBatch struct {
	ethdb.Batch
	db    *fhsCheckpointTestDB
	bytes uint64
	ready bool
}

func (batch *fhsCheckpointTestBatch) Put(key, value []byte) error {
	if batch.db.failPut {
		return errFHSCheckpointTestIO
	}
	batch.bytes += uint64(len(key) + len(value))
	batch.ready = batch.ready || bytes.Equal(key, rawdb.FHSCheckpointReadyRecord(nil).Key)
	return batch.Batch.Put(key, value)
}

func (batch *fhsCheckpointTestBatch) Reset() {
	batch.bytes = 0
	batch.ready = false
	batch.Batch.Reset()
}

func (batch *fhsCheckpointTestBatch) Write() error {
	batch.db.asyncCalls++
	return batch.Batch.Write()
}

func (batch *fhsCheckpointTestBatch) WriteSync() error {
	batch.db.syncCalls++
	if batch.bytes > batch.db.maxBatchBytes {
		batch.db.maxBatchBytes = batch.bytes
	}
	if batch.db.enterSync != nil {
		close(batch.db.enterSync)
		<-batch.db.releaseSync
	}
	syncBatch, ok := batch.Batch.(ethdb.SyncBatch)
	if !ok {
		return errors.New("fixture backing batch does not implement SyncBatch")
	}
	if batch.db.failSync == batch.db.syncCalls || (batch.ready && batch.db.failReady) {
		if batch.db.commitFailure {
			if err := syncBatch.WriteSync(); err != nil {
				return err
			}
		}
		return errFHSCheckpointTestIO
	}
	if err := syncBatch.WriteSync(); err != nil {
		return err
	}
	if batch.ready && batch.db.readyApplied != nil {
		close(batch.db.readyApplied)
		<-batch.db.readyRelease
	}
	return nil
}

func newFHSCheckpointWrappedFixture(t *testing.T) (fhsCheckpointTestFixture, *fhsCheckpointTestDB) {
	t.Helper()
	base := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { _ = base.Close() })
	fixture := newFHSCheckpointTestFixture(t, base)
	db := &fhsCheckpointTestDB{Database: base}
	fixture.bc.db = db
	return fixture, db
}

func TestFHSCheckpointWriteSyncFailuresNeverPublishReady(t *testing.T) {
	// The successful run discovers the number of barriers without coupling the
	// test to the current traversal order or number of trie nodes.
	fixture, recording := newFHSCheckpointWrappedFixture(t)
	job, err := fixture.bc.BeginFHSCheckpoint(context.Background(), fixture.block.Hash(), FHSCheckpointLimits{MaxNodes: 10000, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	progress, err := runFHSCheckpointTest(t, job, 1, 64*1024)
	job.Close()
	if err != nil || !progress.Ready || recording.syncCalls < 2 || recording.asyncCalls != 0 {
		t.Fatalf("successful checkpoint: ready=%v sync=%d async=%d error=%v", progress.Ready, recording.syncCalls, recording.asyncCalls, err)
	}
	if recording.maxBatchBytes > 64*1024 {
		t.Fatalf("batch bytes=%d exceeded step limit", recording.maxBatchBytes)
	}
	for failedBarrier := 1; failedBarrier <= recording.syncCalls; failedBarrier++ {
		t.Run(fmt.Sprintf("barrier-%d", failedBarrier), func(t *testing.T) {
			fixture, db := newFHSCheckpointWrappedFixture(t)
			db.failSync = failedBarrier
			job, err := fixture.bc.BeginFHSCheckpoint(context.Background(), fixture.block.Hash(), FHSCheckpointLimits{MaxNodes: 10000, MaxBytes: 1 << 20})
			if err != nil {
				t.Fatal(err)
			}
			progress, err := runFHSCheckpointTest(t, job, 1, 64*1024)
			job.Close()
			if !errors.Is(err, errFHSCheckpointTestIO) || progress.Ready {
				t.Fatalf("failed sync ready=%v error=%v", progress.Ready, err)
			}
			assertFHSCheckpointNoReady(t, fixture.bc)
		})
	}
	t.Run("content-committed-then-error", func(t *testing.T) {
		fixture, db := newFHSCheckpointWrappedFixture(t)
		db.failSync, db.commitFailure = 1, true
		job, err := fixture.bc.BeginFHSCheckpoint(context.Background(), fixture.block.Hash(), FHSCheckpointLimits{MaxNodes: 10000, MaxBytes: 1 << 20})
		if err != nil {
			t.Fatal(err)
		}
		progress, err := runFHSCheckpointTest(t, job, 1, 64*1024)
		job.Close()
		if !errors.Is(err, errFHSCheckpointTestIO) || progress.Ready {
			t.Fatalf("partially committed sync ready=%v error=%v", progress.Ready, err)
		}
		assertFHSCheckpointNoReady(t, fixture.bc)
		// Content-addressed prior writes are harmless. Restarting the complete
		// traversal succeeds once the injected storage fault has been removed.
		db.failSync = 0
		retry, err := fixture.bc.BeginFHSCheckpoint(context.Background(), fixture.block.Hash(), FHSCheckpointLimits{MaxNodes: 10000, MaxBytes: 1 << 20})
		if err != nil {
			t.Fatal(err)
		}
		defer retry.Close()
		progress, err = runFHSCheckpointTest(t, retry, 1, 64*1024)
		if err != nil || !progress.Ready {
			t.Fatalf("retry after partial content write ready=%v error=%v", progress.Ready, err)
		}
	})
}

func TestFHSCheckpointRequiresSyncAndPropagatesIOErrors(t *testing.T) {
	for _, name := range []string{"unsupported-sync", "metadata-read", "root-read", "put"} {
		t.Run(name, func(t *testing.T) {
			fixture, db := newFHSCheckpointWrappedFixture(t)
			switch name {
			case "unsupported-sync":
				db.noSync = true
			case "metadata-read":
				db.failGet = append([]byte("ethereum-config-"), fixture.block.Hash().Bytes()...)
			case "root-read":
				db.failGet = fixture.block.Root().Bytes()
			case "put":
				db.failPut = true
			}
			job, err := fixture.bc.BeginFHSCheckpoint(context.Background(), fixture.block.Hash(), FHSCheckpointLimits{MaxNodes: 10000, MaxBytes: 1 << 20})
			if err == nil {
				defer job.Close()
				var progress FHSCheckpointProgress
				progress, err = runFHSCheckpointTest(t, job, 1, 64*1024)
				if progress.Ready {
					t.Fatal("checkpoint became READY despite unsupported or failing database operation")
				}
			}
			if err == nil {
				t.Fatal("unsupported or failing database operation was accepted")
			}
			if name != "unsupported-sync" && !errors.Is(err, errFHSCheckpointTestIO) {
				t.Fatalf("underlying database error was lost: %v", err)
			}
			// Clear read injection so this assertion observes persisted state.
			db.failGet = nil
			assertFHSCheckpointNoReady(t, fixture.bc)
		})
	}
}

func TestFHSCheckpointRejectsUnsupportedTargetsAndForgedAnchors(t *testing.T) {
	fixture, _ := newFHSCheckpointWrappedFixture(t)
	unknown := common.HexToHash("0xdecaf")
	if job, err := fixture.bc.BeginFHSCheckpoint(context.Background(), unknown, FHSCheckpointLimits{MaxNodes: 10000, MaxBytes: 1 << 20}); err == nil {
		job.Close()
		t.Fatal("unknown checkpoint target was accepted")
	}
	header := fixture.block.Header()
	header.Number, header.ParentHash = big.NewInt(1), fixture.block.Hash()
	nonGenesis := types.NewBlockWithHeader(header)
	rawdb.WriteBlock(fixture.bc.db, nonGenesis)
	rawdb.WriteCanonicalHash(fixture.bc.db, nonGenesis.Hash(), 1)
	if job, err := fixture.bc.BeginFHSCheckpoint(context.Background(), nonGenesis.Hash(), FHSCheckpointLimits{MaxNodes: 10000, MaxBytes: 1 << 20}); err == nil {
		job.Close()
		t.Fatal("nonzero checkpoint target was accepted by the genesis-only prototype")
	}
	assertFHSCheckpointNoReady(t, fixture.bc)
	job, err := fixture.bc.BeginFHSCheckpoint(context.Background(), fixture.block.Hash(), FHSCheckpointLimits{MaxNodes: 10000, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	progress, err := runFHSCheckpointTest(t, job, 1, 64*1024)
	job.Close()
	if err != nil || !progress.Ready {
		t.Fatalf("checkpoint ready=%v error=%v", progress.Ready, err)
	}
	originalReady, err := rawdb.ReadFHSCheckpointReady(fixture.bc.db)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"number", "block", "root", "genesis", "config"} {
		t.Run(field, func(t *testing.T) {
			forged := progress.Anchor
			switch field {
			case "number":
				forged.Number++
			case "block":
				forged.BlockHash[0] ^= 1
			case "root":
				forged.StateRoot[0] ^= 1
			case "genesis":
				forged.GenesisHash[0] ^= 1
			case "config":
				forged.ConfigHash[0] ^= 1
			}
			var descriptor fhsCheckpointDescriptor
			if err := rlp.DecodeBytes(originalReady, &descriptor); err != nil {
				t.Fatal(err)
			}
			descriptor.Anchor = forged
			encoded, err := rlp.EncodeToBytes(descriptor)
			if err != nil {
				t.Fatal(err)
			}
			record := rawdb.FHSCheckpointReadyRecord(encoded)
			if err := fixture.bc.db.Put(record.Key, record.Value); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := fixture.bc.db.Put(record.Key, originalReady); err != nil {
					t.Error(err)
				}
			})
			if _, err := fixture.bc.FHSCheckpointAnchor(); err == nil {
				t.Fatalf("persisted forged %s anchor field was accepted", field)
			}
		})
	}
	storedConfig := rawdb.ReadChainConfig(fixture.bc.db, fixture.block.Hash())
	storedConfig.FairHotstuffSeed = common.HexToHash("0xbad")
	rawdb.WriteChainConfig(fixture.bc.db, fixture.block.Hash(), storedConfig)
	if _, err := fixture.bc.FHSCheckpointAnchor(); err == nil {
		t.Fatal("persisted anchor accessor accepted changed genesis configuration")
	}
}

func TestFHSCheckpointCanonicalChangeBeforeReady(t *testing.T) {
	fixture, _ := newFHSCheckpointWrappedFixture(t)
	job, err := fixture.bc.BeginFHSCheckpoint(context.Background(), fixture.block.Hash(), FHSCheckpointLimits{MaxNodes: 10000, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer job.Close()
	progress, err := job.Step(context.Background(), 1, 64*1024)
	if err != nil || progress.Ready {
		t.Fatalf("first bounded step ready=%v error=%v", progress.Ready, err)
	}
	rawdb.WriteCanonicalHash(fixture.bc.db, common.HexToHash("0xdead"), 0)
	progress, err = runFHSCheckpointTest(t, job, 1, 64*1024)
	if err == nil || progress.Ready {
		t.Fatalf("changed canonical target ready=%v error=%v", progress.Ready, err)
	}
	assertFHSCheckpointNoReady(t, fixture.bc)
}

func TestFHSCheckpointCancellationAndCloseReleaseGuard(t *testing.T) {
	fixture, _ := newFHSCheckpointWrappedFixture(t)
	limits := FHSCheckpointLimits{MaxNodes: 10000, MaxBytes: 1 << 20}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if job, err := fixture.bc.BeginFHSCheckpoint(canceled, fixture.block.Hash(), limits); !errors.Is(err, context.Canceled) {
		if job != nil {
			job.Close()
		}
		t.Fatalf("canceled Begin error=%v", err)
	}
	job, err := fixture.bc.BeginFHSCheckpoint(context.Background(), fixture.block.Hash(), limits)
	if err != nil {
		t.Fatal(err)
	}
	if duplicate, err := fixture.bc.BeginFHSCheckpoint(context.Background(), fixture.block.Hash(), limits); err == nil {
		duplicate.Close()
		t.Fatal("second simultaneous checkpoint was accepted")
	}
	progress, err := job.Step(canceled, 1, 64*1024)
	if !errors.Is(err, context.Canceled) || progress.Ready {
		t.Fatalf("canceled Step ready=%v error=%v", progress.Ready, err)
	}
	job.Close()
	job.Close() // release is idempotent
	assertFHSCheckpointNoReady(t, fixture.bc)
	if progress, err := job.Step(context.Background(), 1, 64*1024); err == nil || progress.Ready {
		t.Fatalf("closed checkpoint Step ready=%v error=%v", progress.Ready, err)
	}
	retry, err := fixture.bc.BeginFHSCheckpoint(context.Background(), fixture.block.Hash(), limits)
	if err != nil {
		t.Fatalf("Close did not release active checkpoint guard: %v", err)
	}
	defer retry.Close()
	progress, err = runFHSCheckpointTest(t, retry, 1, 64*1024)
	if err != nil || !progress.Ready {
		t.Fatalf("retry after canceled job ready=%v error=%v", progress.Ready, err)
	}
}

func TestFHSCheckpointEnforcesTotalAndPerCallBudgets(t *testing.T) {
	for _, name := range []string{"zero-total-nodes", "zero-total-bytes", "total-nodes", "total-bytes", "step-nodes", "step-bytes", "tiny-step-bytes"} {
		t.Run(name, func(t *testing.T) {
			fixture, db := newFHSCheckpointWrappedFixture(t)
			limits := FHSCheckpointLimits{MaxNodes: 10000, MaxBytes: 1 << 20}
			nodes, byteLimit := uint64(1), uint64(64*1024)
			switch name {
			case "zero-total-nodes":
				limits.MaxNodes = 0
			case "zero-total-bytes":
				limits.MaxBytes = 0
			case "total-nodes":
				limits.MaxNodes = 1
			case "total-bytes":
				limits.MaxBytes = 1
			case "step-nodes":
				nodes = 0
			case "step-bytes":
				byteLimit = 0
			case "tiny-step-bytes":
				byteLimit = 1
			}
			job, err := fixture.bc.BeginFHSCheckpoint(context.Background(), fixture.block.Hash(), limits)
			if err == nil {
				defer job.Close()
				var progress FHSCheckpointProgress
				progress, err = runFHSCheckpointTest(t, job, nodes, byteLimit)
				if progress.Ready {
					t.Fatal("checkpoint became READY after exceeding its accepted work budget")
				}
			}
			if err == nil {
				t.Fatal("invalid or insufficient checkpoint work budget was accepted")
			}
			if name != "total-nodes" && db.syncCalls != 0 {
				t.Fatalf("invalid/insufficient first record budget wrote %d synchronous batches", db.syncCalls)
			}
			assertFHSCheckpointNoReady(t, fixture.bc)
		})
	}
}

func TestFHSCheckpointRejectsMalformedTrieNodes(t *testing.T) {
	branch := func(child, value interface{}) []interface{} {
		fields := make([]interface{}, 17)
		for index := range fields {
			fields[index] = []byte{}
		}
		fields[0], fields[16] = child, value
		return fields
	}
	secureLeafPath := make([]byte, 33)
	secureLeafPath[0] = 0x20
	for _, test := range []struct {
		name  string
		depth uint8
		node  interface{}
	}{
		{"extension-to-empty", 0, []interface{}{[]byte{0x11}, []byte{}}},
		{"empty-leaf", 0, []interface{}{secureLeafPath, []byte{}}},
		{"short-secure-leaf", 0, []interface{}{[]byte{0x31}, []byte{0x01}}},
		{"compact-padding", 0, []interface{}{[]byte{0x21}, []byte{0x01}}},
		{"empty-extension", 0, []interface{}{[]byte{0x00}, make([]byte, 32)}},
		{"oversized-inline", 0, []interface{}{[]byte{0x11}, []interface{}{make([]byte, 32), []byte{0x01}}}},
		{"branch-child-hash-length", 0, branch([]byte{0x01}, []byte{})},
		{"branch-value", 0, branch([]byte{}, []byte{0x01})},
		{"branch-depth", 64, branch([]byte{}, []byte{})},
	} {
		t.Run(test.name, func(t *testing.T) {
			blob, err := rlp.EncodeToBytes(test.node)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fhsCheckpointChildren(fhsCheckpointItem{depth: test.depth}, blob); err == nil {
				t.Fatal("malformed trie node was accepted")
			}
		})
	}
}

func TestFHSCheckpointCancelAndCloseDuringWriteSync(t *testing.T) {
	fixture, db := newFHSCheckpointWrappedFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	db.enterSync, db.releaseSync = entered, release
	limits := FHSCheckpointLimits{MaxNodes: 10000, MaxBytes: 1 << 20}
	job, err := fixture.bc.BeginFHSCheckpoint(context.Background(), fixture.block.Hash(), limits)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type result struct {
		progress FHSCheckpointProgress
		err      error
	}
	stepDone := make(chan result, 1)
	go func() {
		progress, err := job.Step(ctx, 1, 64*1024)
		stepDone <- result{progress, err}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("checkpoint Step did not enter the synchronous write")
	}
	// A database operation already in flight cannot be interrupted. Cancellation
	// and Close must still serialize safely with its eventual successful return.
	cancel()
	closeDone := make(chan struct{})
	go func() {
		job.Close()
		close(closeDone)
	}()
	close(release)
	select {
	case got := <-stepDone:
		if !errors.Is(got.err, context.Canceled) || got.progress.Ready {
			t.Fatalf("canceled in-flight write ready=%v error=%v", got.progress.Ready, got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("checkpoint Step remained blocked after WriteSync returned")
	}
	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("checkpoint Close remained blocked after Step returned")
	}
	assertFHSCheckpointNoReady(t, fixture.bc)
	if progress, err := job.Step(context.Background(), 1, 64*1024); err == nil || progress.Ready {
		t.Fatalf("closed checkpoint Step ready=%v error=%v", progress.Ready, err)
	}
	retry, err := fixture.bc.BeginFHSCheckpoint(context.Background(), fixture.block.Hash(), limits)
	if err != nil {
		t.Fatalf("Close did not release the active checkpoint guard: %v", err)
	}
	retry.Close()
}

func TestFHSCheckpointGetterWaitsForReadySyncReturn(t *testing.T) {
	fixture, db := newFHSCheckpointWrappedFixture(t)
	applied, release := make(chan struct{}), make(chan struct{})
	db.readyApplied, db.readyRelease = applied, release
	job, err := fixture.bc.BeginFHSCheckpoint(context.Background(), fixture.block.Hash(), FHSCheckpointLimits{MaxNodes: 10000, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer job.Close()
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	type stepResult struct {
		progress FHSCheckpointProgress
		err      error
	}
	stepDone := make(chan stepResult, 1)
	go func() {
		for attempts := 0; attempts < 4096; attempts++ {
			progress, err := job.Step(context.Background(), 1, 64*1024)
			if err != nil || progress.Ready {
				stepDone <- stepResult{progress, err}
				return
			}
		}
		stepDone <- stepResult{err: errors.New("checkpoint did not reach READY within the fixture step bound")}
	}()
	select {
	case <-applied:
	case got := <-stepDone:
		t.Fatalf("checkpoint returned before applying READY: %+v", got)
	case <-time.After(5 * time.Second):
		t.Fatal("checkpoint did not apply the READY write")
	}
	// The marker is already visible to plain KV reads, while the enclosing
	// WriteSync has not returned and therefore has not acknowledged durability.
	if ready, err := rawdb.ReadFHSCheckpointReady(db); err != nil || len(ready) == 0 {
		t.Fatalf("fixture did not apply READY before blocking: bytes=%x error=%v", ready, err)
	}
	type anchorResult struct {
		anchor FHSCheckpointAnchor
		err    error
	}
	getterStarted, getterDone := make(chan struct{}), make(chan anchorResult, 1)
	go func() {
		close(getterStarted)
		anchor, err := fixture.bc.FHSCheckpointAnchor()
		getterDone <- anchorResult{anchor, err}
	}()
	<-getterStarted
	select {
	case got := <-getterDone:
		t.Fatalf("anchor getter returned before READY WriteSync completed: anchor=%+v error=%v", got.anchor, got.err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	released = true
	var progress FHSCheckpointProgress
	select {
	case got := <-stepDone:
		if got.err != nil || !got.progress.Ready {
			t.Fatalf("successful READY write progress=%+v error=%v", got.progress, got.err)
		}
		progress = got.progress
	case <-time.After(5 * time.Second):
		t.Fatal("checkpoint did not finish after READY WriteSync returned")
	}
	select {
	case got := <-getterDone:
		if got.err != nil || got.anchor != progress.Anchor {
			t.Fatalf("completed getter anchor=%+v error=%v, want %+v", got.anchor, got.err, progress.Anchor)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("anchor getter remained blocked after READY WriteSync returned")
	}
}

func TestFHSCheckpointReadyCommittedThenErrorRequiresSuccessfulRetry(t *testing.T) {
	fixture, db := newFHSCheckpointWrappedFixture(t)
	db.failReady, db.commitFailure = true, true
	limits := FHSCheckpointLimits{MaxNodes: 10000, MaxBytes: 1 << 20}
	job, err := fixture.bc.BeginFHSCheckpoint(context.Background(), fixture.block.Hash(), limits)
	if err != nil {
		t.Fatal(err)
	}
	progress, err := runFHSCheckpointTest(t, job, 1, 64*1024)
	job.Close()
	if !errors.Is(err, errFHSCheckpointTestIO) || progress.Ready {
		t.Fatalf("applied then failed READY progress=%+v error=%v", progress, err)
	}
	if ready, err := rawdb.ReadFHSCheckpointReady(db); err != nil || len(ready) == 0 {
		t.Fatalf("fixture did not persist its uncertain READY write: bytes=%x error=%v", ready, err)
	}
	if anchor, err := fixture.bc.FHSCheckpointAnchor(); err == nil {
		t.Fatalf("getter exposed an anchor after an uncertain READY write: %+v", anchor)
	}
	// Repeating the complete traversal and receiving a successful final sync
	// repairs the current BlockChain's conservative uncertainty latch.
	db.failReady = false
	retry, err := fixture.bc.BeginFHSCheckpoint(context.Background(), fixture.block.Hash(), limits)
	if err != nil {
		t.Fatal(err)
	}
	defer retry.Close()
	progress, err = runFHSCheckpointTest(t, retry, 1, 64*1024)
	if err != nil || !progress.Ready {
		t.Fatalf("retry after uncertain READY progress=%+v error=%v", progress, err)
	}
	anchor, err := fixture.bc.FHSCheckpointAnchor()
	if err != nil || anchor != progress.Anchor {
		t.Fatalf("repaired getter anchor=%+v error=%v, want %+v", anchor, err, progress.Anchor)
	}
}

func certifyFHSCheckpointBlock(t *testing.T, block *types.Block, view uint64, secrets []bls.SecretKey, public []*bls.PublicKey) *types.Block {
	t.Helper()
	ref, qc := makeFHSCommitProofQC(t, block, view, fmt.Sprintf("checkpoint-%d", view), common.Hash{}, secrets, public)
	block.SetFHSSignature(qc.Sign, qc.Mask, qc.ViewID, qc.LeaderID, qc.Number, ref.ExtraHash, ref.ParentQCID)
	id, err := hotstuff.SignedStateID(qc)
	if err != nil {
		t.Fatal(err)
	}
	child := types.NewBlockWithHeader(&types.Header{ParentHash: block.Hash(), Number: new(big.Int).Add(block.Number(), big.NewInt(1)), Difficulty: big.NewInt(1), BlockType: types.FastTx_Block, KeyHash: block.KeyHash()})
	_, childQC := makeFHSCommitProofQC(t, child, view+1, fmt.Sprintf("checkpoint-%d", view+1), id.Hash(), secrets, public)
	proof, err := EncodeFHSCommitProof(singleFHSCommitProof(childQC))
	if err != nil {
		t.Fatal(err)
	}
	if err := block.SetFHSFinalityProof(proof); err != nil {
		t.Fatal(err)
	}
	return block
}

func newFHSNonGenesisCheckpointFixture(t *testing.T) (fhsCheckpointTestFixture, []bls.SecretKey, []*bls.PublicKey) {
	t.Helper()
	validator, secrets, public, _ := makeFHSCommitProofValidator(t)
	bc := validator.bc
	genesis := testFairHotstuffGenesis()
	config := *params.TestChainConfig
	config.ChainID, config.FairHotstuff, config.FairHotstuffSeed, config.FixedCommittee = genesis.Config.ChainID, true, genesis.Config.FairHotstuffSeed, true
	genesis.Config = &config
	config.SetModernForkConfig(&params.ModernForkConfig{BerlinBlock: big.NewInt(0), LondonBlock: big.NewInt(0)})
	genesis.Config.GenCommittee = make(params.GenesisCommittee, len(public))
	committee := &bftview.Committee{List: make([]*common.Cnode, len(public))}
	for i, key := range public {
		node := common.Cnode{Address: fmt.Sprintf("checkpoint-validator-%d:7101", i), CoinBase: fmt.Sprintf("%040x", i+1), Public: key.SerializeToHexStr()}
		genesis.Config.GenCommittee[i] = node
		committee.List[i] = &node
	}
	var err error
	genesis.Mixhash, err = params.FairHotstuffGenesisCommitment(genesis.Config)
	if err != nil {
		t.Fatal(err)
	}
	address := common.HexToAddress("0xcafe")
	genesis.Alloc[address] = GenesisAccount{Balance: big.NewInt(1000), Code: []byte{0x60, 0x01, 0x00}, Storage: map[common.Hash]common.Hash{common.HexToHash("0x01"): common.HexToHash("0x02")}}
	base, err := genesis.Commit(bc.db)
	if err != nil {
		t.Fatal(err)
	}
	key := (&GenesisKey{Config: genesis.Config, Difficulty: big.NewInt(1), Time: 1}).ToBlock()
	key.SetCommitteeHash(committee.RlpHash())
	rawdb.WriteKeyBlock(bc.db, key)
	rawdb.WriteKeyBlockHash(bc.db, key.Hash(), 0)
	rawdb.WriteTd(bc.db, key.Hash(), 0, key.Difficulty())
	rawdb.WriteChainConfig(bc.db, key.Hash(), genesis.Config)
	rawdb.WriteHeadKeyBlockHash(bc.db, key.Hash())
	rawdb.WriteHeadKeyHeaderHash(bc.db, key.Hash())
	if !bftview.WriteCommittee(0, key.Hash(), committee) {
		t.Fatal("write checkpoint key genesis committee")
	}
	bc.keyBlockChain.genesisBlock = key
	bc.keyBlockChain.currentBlock.Store(key)
	bc.keyBlockChain.blockCache.Add(key.Hash(), key)
	bc.keyBlockChain.khc.headerCache.Add(key.Hash(), key.Header())
	bc.keyBlockChain.khc.numberCache.Add(key.Hash(), uint64(0))
	bc.genesisBlock, bc.chainConfig = base, genesis.Config
	bc.engine = colossusX.NewFaker()
	t.Cleanup(func() { _ = bc.engine.Close() })
	validator.config, validator.engine = genesis.Config, bc.engine
	bc.stateCache = state.NewDatabase(bc.db)
	dirty, err := state.New(base.Root(), bc.stateCache, nil)
	if err != nil {
		t.Fatal(err)
	}
	dirty.SetBalance(address, big.NewInt(2000))
	dirty.SetNonce(address, 8)
	dirty.SetCode(address, []byte{0x60, 0x02, 0x00})
	dirty.SetState(address, common.HexToHash("0x01"), common.HexToHash("0x03"))
	root, err := dirty.Commit(false)
	if err != nil {
		t.Fatal(err)
	}
	if has, err := bc.db.Has(root[:]); err != nil || has {
		t.Fatalf("fixture root must remain dirty, present=%v error=%v", has, err)
	}
	block := types.NewBlock(&types.Header{ParentHash: base.Hash(), Number: big.NewInt(1), Time: base.Time() + 1, GasLimit: base.GasLimit(), Difficulty: big.NewInt(1), Root: root, KeyHash: key.Hash(), BlockType: types.FastTx_Block, BaseFee: big.NewInt(params.FixedBaseFeePerGas)}, nil, nil, nil, new(trie.Trie))
	certifyFHSCheckpointBlock(t, block, 10, secrets, public)
	rawdb.WriteBlock(bc.db, block)
	rawdb.WriteCanonicalHash(bc.db, block.Hash(), 1)
	rawdb.WriteTd(bc.db, block.Hash(), 1, big.NewInt(2))
	rawdb.WriteReceipts(bc.db, block.Hash(), 1, nil)
	rawdb.WriteHeadBlockHash(bc.db, block.Hash())
	rawdb.WriteHeadHeaderHash(bc.db, block.Hash())
	rawdb.WriteHeadFastBlockHash(bc.db, block.Hash())
	bc.currentBlock.Store(block)
	return fhsCheckpointTestFixture{bc: bc, genesis: genesis, block: block, address: address}, secrets, public
}

func fhsNonGenesisCheckpointLimits() FHSCheckpointLimits {
	return FHSCheckpointLimits{MaxNodes: 10000, MaxBytes: 8 << 20, MaxHistoryBlocks: 16, MaxKeyBlocks: 16}
}

func TestFHSCheckpointFinalizedHeadPersistsDirtyClosure(t *testing.T) {
	fixture, _, _ := newFHSNonGenesisCheckpointFixture(t)
	job, err := fixture.bc.BeginFHSCheckpoint(context.Background(), fixture.block.Hash(), fhsNonGenesisCheckpointLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer job.Close()
	progress, err := runFHSCheckpointTest(t, job, 1, 64*1024)
	if err != nil || !progress.Ready {
		t.Fatalf("finalized head checkpoint progress=%+v error=%v", progress, err)
	}
	anchor, err := fixture.bc.FHSCheckpointAnchor()
	if err != nil || anchor != progress.Anchor || anchor.Number != 1 {
		t.Fatalf("anchor=%+v error=%v", anchor, err)
	}
	fresh, err := state.New(anchor.StateRoot, state.NewDatabase(fixture.bc.db), nil)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.GetBalance(fixture.address).Cmp(big.NewInt(2000)) != 0 || fresh.GetNonce(fixture.address) != 8 || !bytes.Equal(fresh.GetCode(fixture.address), []byte{0x60, 0x02, 0x00}) || fresh.GetState(fixture.address, common.HexToHash("0x01")) != common.HexToHash("0x03") || fresh.Error() != nil {
		t.Fatalf("fresh checkpoint closure incomplete: %v", fresh.Error())
	}
}

func TestFHSCheckpointFinalizedHeadFailsClosed(t *testing.T) {
	for _, name := range []string{"missing-key", "missing-key-config", "missing-committee", "corrupt-committee", "missing-proof", "invalid-header", "separate-key-db", "history-limit", "key-limit", "read-error", "runtime-config", "variable-committee", "key-transition"} {
		t.Run(name, func(t *testing.T) {
			fixture, secrets, public := newFHSNonGenesisCheckpointFixture(t)
			bc := fixture.bc
			limits := fhsNonGenesisCheckpointLimits()
			key := bc.keyBlockChain.genesisBlock
			if len(bc.keyBlockChain.GetCommitteeByHash(key.Hash())) == 0 {
				t.Fatal("warm checkpoint committee cache")
			}
			switch name {
			case "missing-key":
				_ = bc.db.Delete(rawdb.FHSCheckpointKeyKeys(0, key.Hash())[3])
			case "missing-key-config":
				_ = bc.db.Delete(rawdb.FHSCheckpointConfigKey(key.Hash()))
			case "missing-committee":
				_ = bc.db.Delete(rawdb.CommitteeKey(0, key.Hash()))
			case "corrupt-committee":
				_ = bc.db.Put(rawdb.CommitteeKey(0, key.Hash()), []byte{0xc1, 0xc0})
			case "missing-proof":
				block := fixture.block.WithSeal(fixture.block.Header())
				_ = block.SetFHSFinalityProof(nil)
				rawdb.WriteBlock(bc.db, block)
			case "invalid-header":
				header := fixture.block.Header()
				header.GasUsed = header.GasLimit + 1
				block := certifyFHSCheckpointBlock(t, fixture.block.WithSeal(header), 30, secrets, public)
				rawdb.WriteBlock(bc.db, block)
				rawdb.WriteCanonicalHash(bc.db, block.Hash(), 1)
				rawdb.WriteTd(bc.db, block.Hash(), 1, big.NewInt(2))
				rawdb.WriteReceipts(bc.db, block.Hash(), 1, nil)
				rawdb.WriteHeadBlockHash(bc.db, block.Hash())
				rawdb.WriteHeadHeaderHash(bc.db, block.Hash())
				rawdb.WriteHeadFastBlockHash(bc.db, block.Hash())
				bc.currentBlock.Store(block)
				fixture.block = block
			case "separate-key-db":
				bc.keyBlockChain.db = rawdb.NewMemoryDatabase()
				defer bc.keyBlockChain.db.Close()
			case "history-limit":
				limits.MaxHistoryBlocks = 1
			case "key-limit":
				limits.MaxKeyBlocks = 0
			case "runtime-config":
				clone := *bc.chainConfig
				clone.ChainID = big.NewInt(12345)
				bc.chainConfig = &clone
			case "variable-committee":
				clone := *bc.chainConfig
				clone.FixedCommittee = false
				bc.chainConfig = &clone
			case "key-transition":
				header := key.Header()
				header.Number = big.NewInt(1)
				header.ParentHash = key.Hash()
				bc.keyBlockChain.currentBlock.Store(types.NewKeyBlockWithHeader(header))
			case "read-error":
				wrapped := &fhsCheckpointTestDB{Database: bc.db, failGet: rawdb.FHSCheckpointKeyKeys(0, key.Hash())[2]}
				bc.db = wrapped
				bc.keyBlockChain.db = wrapped
			}
			job, err := bc.BeginFHSCheckpoint(context.Background(), fixture.block.Hash(), limits)
			if err == nil {
				_, err = runFHSCheckpointTest(t, job, 1, 64*1024)
				job.Close()
			}
			if err == nil {
				t.Fatal("invalid finalized checkpoint accepted")
			}
			if name == "invalid-header" && !strings.Contains(err.Error(), "invalid gasUsed") {
				t.Fatalf("full header validation was bypassed: %v", err)
			}
			if name == "read-error" && !errors.Is(err, errFHSCheckpointTestIO) {
				t.Fatalf("checkpoint hid source I/O error: %v", err)
			}
			assertFHSCheckpointNoReady(t, bc)
		})
	}
}

func extendFHSCheckpointFixture(t *testing.T, fixture fhsCheckpointTestFixture, secrets []bls.SecretKey, public []*bls.PublicKey) fhsCheckpointTestFixture {
	t.Helper()
	bc := fixture.bc
	dirty, err := state.New(fixture.block.Root(), bc.stateCache, nil)
	if err != nil {
		t.Fatal(err)
	}
	dirty.SetBalance(fixture.address, big.NewInt(3000))
	root, err := dirty.Commit(false)
	if err != nil {
		t.Fatal(err)
	}
	header := fixture.block.Header()
	header.ParentHash, header.Number, header.Root, header.Time = fixture.block.Hash(), new(big.Int).Add(fixture.block.Number(), big.NewInt(1)), root, fixture.block.Time()+1
	header.SetSignInfoNull()
	block := certifyFHSCheckpointBlock(t, fixture.block.WithSeal(header), 20, secrets, public)
	rawdb.WriteBlock(bc.db, block)
	rawdb.WriteCanonicalHash(bc.db, block.Hash(), block.NumberU64())
	rawdb.WriteTd(bc.db, block.Hash(), block.NumberU64(), big.NewInt(3))
	rawdb.WriteReceipts(bc.db, block.Hash(), block.NumberU64(), nil)
	rawdb.WriteHeadBlockHash(bc.db, block.Hash())
	rawdb.WriteHeadHeaderHash(bc.db, block.Hash())
	rawdb.WriteHeadFastBlockHash(bc.db, block.Hash())
	bc.currentBlock.Store(block)
	fixture.block = block
	return fixture
}

func TestFHSCheckpointReplacementPreservesAcknowledgedAnchor(t *testing.T) {
	fixture, secrets, public := newFHSNonGenesisCheckpointFixture(t)
	bc := fixture.bc
	wrapped := &fhsCheckpointTestDB{Database: bc.db}
	bc.db, bc.keyBlockChain.db = wrapped, wrapped
	limits := fhsNonGenesisCheckpointLimits()
	genesisJob, err := bc.BeginFHSCheckpoint(context.Background(), bc.genesisBlock.Hash(), limits)
	if err != nil {
		t.Fatal(err)
	}
	genesisProgress, err := runFHSCheckpointTest(t, genesisJob, 1, 64*1024)
	genesisJob.Close()
	if err != nil || !genesisProgress.Ready {
		t.Fatalf("genesis checkpoint=%+v error=%v", genesisProgress, err)
	}
	old := genesisProgress.Anchor
	wrapped.failReady, wrapped.commitFailure = true, true
	job, err := bc.BeginFHSCheckpoint(context.Background(), fixture.block.Hash(), limits)
	if err != nil {
		t.Fatal(err)
	}
	if anchor, err := bc.FHSCheckpointAnchor(); err != nil || anchor != old {
		t.Fatalf("pending switch lost old anchor=%+v error=%v", anchor, err)
	}
	progress, err := runFHSCheckpointTest(t, job, 1, 64*1024)
	job.Close()
	if !errors.Is(err, errFHSCheckpointTestIO) || progress.Ready {
		t.Fatalf("failed READY switch=%+v error=%v", progress, err)
	}
	if anchor, err := bc.FHSCheckpointAnchor(); err != nil || anchor != old {
		t.Fatalf("uncertain switch lost old anchor=%+v error=%v", anchor, err)
	}
	wrapped.failReady, wrapped.commitFailure = false, false
	job, err = bc.BeginFHSCheckpoint(context.Background(), fixture.block.Hash(), limits)
	if err != nil {
		t.Fatal(err)
	}
	progress, err = runFHSCheckpointTest(t, job, 1, 64*1024)
	job.Close()
	if err != nil || !progress.Ready {
		t.Fatalf("retry switch=%+v error=%v", progress, err)
	}
	old = progress.Anchor
	fixture = extendFHSCheckpointFixture(t, fixture, secrets, public)
	job, err = bc.BeginFHSCheckpoint(context.Background(), fixture.block.Hash(), limits)
	if err != nil {
		t.Fatal(err)
	}
	if anchor, err := bc.FHSCheckpointAnchor(); err != nil || anchor != old {
		t.Fatalf("advanced head lost acknowledged anchor=%+v error=%v", anchor, err)
	}
	wrapped.failSync = wrapped.syncCalls + 1
	progress, err = runFHSCheckpointTest(t, job, 1, 64*1024)
	job.Close()
	if !errors.Is(err, errFHSCheckpointTestIO) || progress.Ready {
		t.Fatalf("failed state switch=%+v error=%v", progress, err)
	}
	if anchor, err := bc.FHSCheckpointAnchor(); err != nil || anchor != old {
		t.Fatalf("failed state switch lost old anchor=%+v error=%v", anchor, err)
	}
	wrapped.failSync = 0
	wrapped.failReady, wrapped.commitFailure = true, true
	job, err = bc.BeginFHSCheckpoint(context.Background(), fixture.block.Hash(), limits)
	if err != nil {
		t.Fatal(err)
	}
	progress, err = runFHSCheckpointTest(t, job, 1, 64*1024)
	job.Close()
	if !errors.Is(err, errFHSCheckpointTestIO) || progress.Ready {
		t.Fatalf("uncertain v2 replacement=%+v error=%v", progress, err)
	}
	if anchor, err := bc.FHSCheckpointAnchor(); err != nil || anchor != old {
		t.Fatalf("uncertain v2 replacement lost old anchor=%+v error=%v", anchor, err)
	}
	wrapped.failReady, wrapped.commitFailure = false, false
	job, err = bc.BeginFHSCheckpoint(context.Background(), fixture.block.Hash(), limits)
	if err != nil {
		t.Fatal(err)
	}
	progress, err = runFHSCheckpointTest(t, job, 1, 64*1024)
	job.Close()
	if err != nil || !progress.Ready {
		t.Fatalf("successful switch=%+v error=%v", progress, err)
	}
	if anchor, err := bc.FHSCheckpointAnchor(); err != nil || anchor != progress.Anchor || anchor.Number != 2 {
		t.Fatalf("new anchor=%+v error=%v", anchor, err)
	}
	previous, err := state.New(old.StateRoot, state.NewDatabase(wrapped), nil)
	if err != nil {
		t.Fatal(err)
	}
	if previous.GetBalance(fixture.address).Cmp(big.NewInt(2000)) != 0 || previous.Error() != nil {
		t.Fatalf("handoff removed old state closure: %v", previous.Error())
	}
}

func TestFHSCheckpointRejectsHeadChangeAndAcceptsRecertification(t *testing.T) {
	t.Run("head-change", func(t *testing.T) {
		fixture, secrets, public := newFHSNonGenesisCheckpointFixture(t)
		job, err := fixture.bc.BeginFHSCheckpoint(context.Background(), fixture.block.Hash(), fhsNonGenesisCheckpointLimits())
		if err != nil {
			t.Fatal(err)
		}
		defer job.Close()
		extendFHSCheckpointFixture(t, fixture, secrets, public)
		progress, err := job.Step(context.Background(), 1, 64*1024)
		if !errors.Is(err, ErrFHSCheckpointStale) || progress.Ready {
			t.Fatalf("changed head progress=%+v error=%v", progress, err)
		}
		assertFHSCheckpointNoReady(t, fixture.bc)
	})
	t.Run("recertification", func(t *testing.T) {
		fixture, secrets, public := newFHSNonGenesisCheckpointFixture(t)
		job, err := fixture.bc.BeginFHSCheckpoint(context.Background(), fixture.block.Hash(), fhsNonGenesisCheckpointLimits())
		if err != nil {
			t.Fatal(err)
		}
		progress, err := runFHSCheckpointTest(t, job, 1, 64*1024)
		job.Close()
		if err != nil || !progress.Ready {
			t.Fatalf("checkpoint=%+v error=%v", progress, err)
		}
		originalHeader, _ := rlp.EncodeToBytes(fixture.block.Header())
		recertified := certifyFHSCheckpointBlock(t, fixture.block.WithSeal(fixture.block.Header()), 300, secrets, public)
		if recertified.Hash() != fixture.block.Hash() {
			t.Fatal("recertification changed unsigned identity")
		}
		newHeader, _ := rlp.EncodeToBytes(recertified.Header())
		if len(originalHeader) == len(newHeader) {
			t.Fatal("fixture requires a different-sized certificate")
		}
		rawdb.WriteBlock(fixture.bc.db, recertified)
		if anchor, err := fixture.bc.FHSCheckpointAnchor(); err != nil || anchor != progress.Anchor {
			t.Fatalf("valid recertification invalidated anchor=%+v error=%v", anchor, err)
		}
	})
}
