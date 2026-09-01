package core

import (
	"crypto/ecdsa"
	"errors"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/ethdb/memorydb"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
)

type countingAdmissionDB struct {
	ethdb.KeyValueStore
	mu           sync.Mutex
	batchPuts    int
	batchDeletes int
	batchWrites  int
	writeErr     error
}

func (db *countingAdmissionDB) NewBatch() ethdb.Batch {
	return &countingAdmissionBatch{Batch: db.KeyValueStore.NewBatch(), db: db}
}

func (db *countingAdmissionDB) reset() {
	db.mu.Lock()
	db.batchPuts, db.batchDeletes, db.batchWrites = 0, 0, 0
	db.mu.Unlock()
}

func (db *countingAdmissionDB) counts() (int, int, int) {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.batchPuts, db.batchDeletes, db.batchWrites
}

type countingAdmissionBatch struct {
	ethdb.Batch
	db *countingAdmissionDB
}

func (batch *countingAdmissionBatch) Put(key, value []byte) error {
	batch.db.mu.Lock()
	batch.db.batchPuts++
	batch.db.mu.Unlock()
	return batch.Batch.Put(key, value)
}

func (batch *countingAdmissionBatch) Delete(key []byte) error {
	batch.db.mu.Lock()
	batch.db.batchDeletes++
	batch.db.mu.Unlock()
	return batch.Batch.Delete(key)
}

func (batch *countingAdmissionBatch) Write() error {
	batch.db.mu.Lock()
	batch.db.batchWrites++
	err := batch.db.writeErr
	batch.db.mu.Unlock()
	if err != nil {
		return err
	}
	return batch.Batch.Write()
}

func resetAdmissionTestState(t *testing.T) (*countingAdmissionDB, common.Address, *big.Int, common.Hash, *int64) {
	t.Helper()
	db := &countingAdmissionDB{KeyValueStore: memorydb.New()}
	SetCommonRPCAdmissionDatabase(db)
	SetCommonRPCAdmissionFinalizedLookup(nil)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	miner := crypto.PubkeyToAddress(key.PublicKey)
	var signs int64
	SetCommonRPCAdmissionSigner(func(batch *types.CommonTxAdmissionBatch) error {
		atomic.AddInt64(&signs, 1)
		signature, err := crypto.Sign(types.CommonTxAdmissionSigningHash(batch).Bytes(), key)
		if err == nil {
			batch.Signature = signature
		}
		return err
	})
	return db, miner, big.NewInt(1), common.HexToHash("0x1234"), &signs
}

func signedAdmissionBatch(t *testing.T, txHashes []common.Hash, chainID *big.Int, genesis common.Hash, keyBlock, timestamp uint64) *types.CommonTxAdmissionBatch {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return signedAdmissionBatchWithKey(t, key, txHashes, chainID, genesis, keyBlock, timestamp)
}

func signedAdmissionBatchWithKey(t *testing.T, key *ecdsa.PrivateKey, txHashes []common.Hash, chainID *big.Int, genesis common.Hash, keyBlock, timestamp uint64) *types.CommonTxAdmissionBatch {
	t.Helper()
	batch := &types.CommonTxAdmissionBatch{
		ChainID: new(big.Int).Set(chainID), GenesisHash: genesis, Miner: crypto.PubkeyToAddress(key.PublicKey),
		KeyBlockNumber: keyBlock, Timestamp: timestamp, TxHashes: append([]common.Hash(nil), txHashes...),
	}
	batch.TxRoot = types.DeriveCommonTxAdmissionTxRoot(batch.TxHashes)
	batch.AdmissionID = types.CommonTxAdmissionID(batch)
	signature, err := crypto.Sign(types.CommonTxAdmissionSigningHash(batch).Bytes(), key)
	if err != nil {
		t.Fatal(err)
	}
	batch.Signature = signature
	return batch
}

func testTransaction(nonce uint64) *types.Transaction {
	return types.NewTransaction(nonce, common.Address{byte(nonce + 1)}, big.NewInt(1), 21000, big.NewInt(1), nil)
}

func TestCommonRPCAdmissionSigns512OnceAndGroupCommits(t *testing.T) {
	db, miner, chainID, genesis, signs := resetAdmissionTestState(t)
	hashes := make([]common.Hash, types.MaxCommonTxAdmissionBatchItems)
	for i := range hashes {
		hashes[i] = common.BigToHash(big.NewInt(int64(i + 1)))
	}
	db.reset()
	results, err := SignAndRecordCommonRPCAdmissions(hashes, miner, chainID, genesis, 7, uint64(time.Now().Unix()))
	if err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(signs); got != 1 {
		t.Fatalf("signed %d times, want one batch signature", got)
	}
	if len(results) != len(hashes) {
		t.Fatalf("result count %d, want %d", len(results), len(hashes))
	}
	for i, result := range results {
		if result.Batch != results[0].Batch {
			t.Fatalf("item %d does not share immutable batch pointer", i)
		}
		if result.Item != uint16(i) || !result.Updated {
			t.Fatalf("item %d result = %+v", i, result)
		}
	}
	puts, _, writes := db.counts()
	if puts != len(hashes)+1 || writes != 1 {
		t.Fatalf("DB group commit puts=%d writes=%d, want %d/1", puts, writes, len(hashes)+1)
	}
	if _, err := VerifyAndStoreCommonRPCAdmissionBatch(results[0].Batch, chainID, genesis); err != nil {
		t.Fatal(err)
	}
	putsAfter, _, writesAfter := db.counts()
	if putsAfter != puts || writesAfter != writes {
		t.Fatalf("duplicate amplified DB writes: before=%d/%d after=%d/%d", puts, writes, putsAfter, writesAfter)
	}
}

func TestCommonRPCAdmissionRejectsWrongIdentityBeforeStore(t *testing.T) {
	db, _, chainID, genesis, _ := resetAdmissionTestState(t)
	batch := signedAdmissionBatch(t, []common.Hash{{1}}, chainID, genesis, 1, uint64(time.Now().Unix()))
	db.reset()
	if _, err := VerifyAndStoreCommonRPCAdmissionBatch(batch, big.NewInt(2), genesis); !errors.Is(err, ErrInvalidCommonRPCAdmission) {
		t.Fatalf("wrong chain error = %v", err)
	}
	if _, err := VerifyAndStoreCommonRPCAdmissionBatch(batch, chainID, common.Hash{9}); !errors.Is(err, ErrInvalidCommonRPCAdmission) {
		t.Fatalf("wrong genesis error = %v", err)
	}
	puts, _, writes := db.counts()
	if puts != 0 || writes != 0 {
		t.Fatalf("invalid identity wrote DB: puts=%d writes=%d", puts, writes)
	}
}

func TestCommonRPCAdmissionWinnerAndAdmissionIDTieBreak(t *testing.T) {
	db, _, chainID, genesis, _ := resetAdmissionTestState(t)
	hash := common.Hash{7}
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Now().Unix())
	first := signedAdmissionBatchWithKey(t, key, []common.Hash{hash, {1}}, chainID, genesis, 4, now)
	second := signedAdmissionBatchWithKey(t, key, []common.Hash{hash, {2}}, chainID, genesis, 4, now)
	if types.CommonTxAdmissionWinnerHash(first, hash) != types.CommonTxAdmissionWinnerHash(second, hash) {
		t.Fatal("test batches do not exercise the AdmissionID tie-break")
	}
	better, worse := first, second
	if !types.IsBetterCommonTxAdmission(first, second, hash) {
		better, worse = second, first
	}
	if _, err := VerifyAndStoreCommonRPCAdmissionBatch(worse, chainID, genesis); err != nil {
		t.Fatal(err)
	}
	results, err := VerifyAndStoreCommonRPCAdmissionBatch(better, chainID, genesis)
	if err != nil {
		t.Fatal(err)
	}
	if !results[0].Updated || results[0].Batch.AdmissionID != better.AdmissionID {
		t.Fatalf("better winner was not selected: %+v", results[0])
	}
	loaded, ok := CommonRPCAdmissionForTransaction(hash)
	if !ok || loaded.Batch.AdmissionID != better.AdmissionID || loaded.Item != 0 {
		t.Fatalf("loaded winner = %+v", loaded)
	}
	for _, expected := range []struct {
		batch *types.CommonTxAdmissionBatch
		refs  uint32
	}{{better, 2}, {worse, 1}} {
		raw, err := db.Get(commonRPCAdmissionBatchDBKey(expected.batch.AdmissionID))
		if err != nil {
			t.Fatal(err)
		}
		var disk commonRPCAdmissionDiskBatch
		if err := rlp.DecodeBytes(raw, &disk); err != nil {
			t.Fatal(err)
		}
		if disk.References != expected.refs || (expected.refs == 0) != (disk.UnreferencedAt != 0) {
			t.Fatalf("winner replacement body %s refs=%d unreferenced=%d", expected.batch.AdmissionID, disk.References, disk.UnreferencedAt)
		}
	}
}

func TestCommonRPCAdmissionRestoreSharesBatchPointer(t *testing.T) {
	db, miner, chainID, genesis, _ := resetAdmissionTestState(t)
	hashes := []common.Hash{{1}, {2}, {3}}
	if _, err := SignAndRecordCommonRPCAdmissions(hashes, miner, chainID, genesis, 2, uint64(time.Now().Unix())); err != nil {
		t.Fatal(err)
	}
	SetCommonRPCAdmissionDatabase(db)
	var shared *types.CommonTxAdmissionBatch
	for i, hash := range hashes {
		result, ok := CommonRPCAdmissionForTransaction(hash)
		if !ok || result.Item != uint16(i) {
			t.Fatalf("restore item %d = %+v, %v", i, result, ok)
		}
		if shared == nil {
			shared = result.Batch
		} else if result.Batch != shared {
			t.Fatalf("restored indexes do not share one batch pointer")
		}
	}
}

func TestBuildCommonTxAdmissionsSortsUniqueBatchesAndRefs(t *testing.T) {
	_, miner, chainID, genesis, _ := resetAdmissionTestState(t)
	tx0, tx1, tx2 := testTransaction(0), testTransaction(1), testTransaction(2)
	now := uint64(time.Now().Unix())
	first, err := SignAndRecordCommonRPCAdmissions([]common.Hash{tx0.Hash(), tx2.Hash()}, miner, chainID, genesis, 5, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SignAndRecordCommonRPCAdmissions([]common.Hash{tx1.Hash()}, miner, chainID, genesis, 5, now+1)
	if err != nil {
		t.Fatal(err)
	}
	config := &params.ChainConfig{ChainID: chainID, FairHotstuff: true, CommonRPCSigners: []common.Address{miner}}
	txs := types.Transactions{tx1, tx0, tx2}
	batches, refs, err := BuildCommonTxAdmissions(txs, config, genesis, 5, 10, now+1)
	if err != nil {
		t.Fatal(err)
	}
	if len(batches) != 2 || len(refs) != len(txs) {
		t.Fatalf("batches/refs = %d/%d", len(batches), len(refs))
	}
	if bytesCompareHash(batches[0].AdmissionID, batches[1].AdmissionID) >= 0 {
		t.Fatal("batches are not AdmissionID sorted")
	}
	for i, tx := range txs {
		ref := refs[i]
		if batches[ref.Batch].TxHashes[ref.Item] != tx.Hash() {
			t.Fatalf("ref %d does not select its block transaction", i)
		}
	}
	if first[0].Batch == nil || second[0].Batch == nil {
		t.Fatal("missing stored certificates")
	}
}

func TestCommonRPCAdmissionRemainsValidAcrossKeyBlocksAndRestart(t *testing.T) {
	db, miner, chainID, genesis, _ := resetAdmissionTestState(t)
	tx := testTransaction(17)
	const admittedAt = uint64(1_000)
	results, err := SignAndRecordCommonRPCAdmissions([]common.Hash{tx.Hash()}, miner, chainID, genesis, 2, admittedAt)
	if err != nil {
		t.Fatal(err)
	}
	SetCommonRPCAdmissionDatabase(db)
	config := &params.ChainConfig{ChainID: chainID, FairHotstuff: true, CommonRPCSigners: []common.Address{miner}}
	selection, err := CommonRPCAdmissionForBlockTransaction(tx, config, genesis, 25, 90, admittedAt+86_400)
	if err != nil {
		t.Fatalf("durable admission became stale across key blocks: %v", err)
	}
	if selection.Batch.AdmissionID != results[0].Batch.AdmissionID || selection.Item != 0 || selection.Batch.KeyBlockNumber != 2 {
		t.Fatalf("restored cross-key selection = %+v", selection)
	}
	batches, refs, err := BuildCommonTxAdmissions(types.Transactions{tx}, config, genesis, 25, 90, admittedAt+86_400)
	if err != nil {
		t.Fatalf("proposal rejected durable cross-key admission: %v", err)
	}
	if len(batches) != 1 || len(refs) != 1 || batches[refs[0].Batch].TxHashes[refs[0].Item] != tx.Hash() {
		t.Fatalf("cross-key proposal evidence batches=%d refs=%+v", len(batches), refs)
	}
	approvers, err := buildCommonAdmissionApprovers(config, batches, refs, types.Transactions{tx}, genesis, 25, admittedAt+86_400)
	if err != nil {
		t.Fatalf("validator rejected durable cross-key admission: %v", err)
	}
	if len(approvers) != 1 || approvers[0] != miner {
		t.Fatalf("cross-key validator approvers = %v", approvers)
	}
}

func TestCommonRPCAdmissionRejectsFutureBoundary(t *testing.T) {
	_, miner, chainID, genesis, _ := resetAdmissionTestState(t)
	tx := testTransaction(18)
	const admittedAt = uint64(10_000)
	if _, err := SignAndRecordCommonRPCAdmissions([]common.Hash{tx.Hash()}, miner, chainID, genesis, 8, admittedAt); err != nil {
		t.Fatal(err)
	}
	config := &params.ChainConfig{ChainID: chainID, FairHotstuff: true, CommonRPCSigners: []common.Address{miner}}
	if _, err := CommonRPCAdmissionForBlockTransaction(tx, config, genesis, 7, 1, admittedAt); err == nil {
		t.Fatal("future-key admission was accepted")
	}
	blockTimestamp := admittedAt - commonRPCAdmissionDurationSeconds(commonRPCAdmissionFutureClockSkew) - 1
	if _, err := CommonRPCAdmissionForBlockTransaction(tx, config, genesis, 8, 1, blockTimestamp); err == nil {
		t.Fatal("future-clock admission was accepted")
	}
}

func TestCommonRPCAdmissionConcurrentCrossKeySelection(t *testing.T) {
	_, _, chainID, genesis, _ := resetAdmissionTestState(t)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	miner := crypto.PubkeyToAddress(key.PublicKey)
	tx := testTransaction(19)
	oldBatch := signedAdmissionBatchWithKey(t, key, []common.Hash{tx.Hash()}, chainID, genesis, 1, 1_000)
	newBatch := signedAdmissionBatchWithKey(t, key, []common.Hash{tx.Hash()}, chainID, genesis, 20, 2_000)
	if _, err := VerifyAndStoreCommonRPCAdmissionBatch(oldBatch, chainID, genesis); err != nil {
		t.Fatal(err)
	}
	config := &params.ChainConfig{ChainID: chainID, FairHotstuff: true, CommonRPCSigners: []common.Address{miner}}
	start := make(chan struct{})
	errs := make(chan error, 33)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		_, storeErr := VerifyAndStoreCommonRPCAdmissionBatch(newBatch, chainID, genesis)
		errs <- storeErr
	}()
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			selection, selectionErr := CommonRPCAdmissionForBlockTransaction(tx, config, genesis, 50, 3, 10_000)
			if selectionErr == nil && selection.Batch.KeyBlockNumber > 50 {
				selectionErr = errors.New("selected future-key admission")
			}
			errs <- selectionErr
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func bytesCompareHash(a, b common.Hash) int {
	for i := range a {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

func TestCommonRPCAdmissionPartialFinalizationKeepsBodyAndOtherIndexes(t *testing.T) {
	db, miner, chainID, genesis, _ := resetAdmissionTestState(t)
	hashes := []common.Hash{{1}, {2}, {3}}
	results, err := SignAndRecordCommonRPCAdmissions(hashes, miner, chainID, genesis, 3, uint64(time.Now().Unix()))
	if err != nil {
		t.Fatal(err)
	}
	body := results[0].Batch
	writeBatch := db.NewBatch()
	release, forget, err := stageFinalizedCommonRPCAdmissionDeletes(writeBatch, []*types.CommonTxAdmissionBatch{body}, []types.CommonTxAdmissionRef{{Batch: 0, Item: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeBatch.Write(); err != nil {
		release()
		t.Fatal(err)
	}
	forget()
	release()
	if HasCommonRPCAdmission(hashes[1]) {
		t.Fatal("finalized item index remains")
	}
	if !HasCommonRPCAdmission(hashes[0]) || !HasCommonRPCAdmission(hashes[2]) {
		t.Fatal("partial finalization deleted an unselected item")
	}
	if has, err := db.Has(commonRPCAdmissionBatchDBKey(body.AdmissionID)); err != nil || !has {
		t.Fatalf("batch body was deleted: has=%v err=%v", has, err)
	}
}

func TestCommonRPCAdmissionConcurrentPartialFinalizationPreservesReferences(t *testing.T) {
	db, miner, chainID, genesis, _ := resetAdmissionTestState(t)
	hashes := make([]common.Hash, 8)
	for i := range hashes {
		hashes[i] = common.Hash{byte(i + 1)}
	}
	results, err := SignAndRecordCommonRPCAdmissions(hashes, miner, chainID, genesis, 3, uint64(time.Now().Unix()))
	if err != nil {
		t.Fatal(err)
	}
	body := results[0].Batch
	start := make(chan struct{})
	errs := make(chan error, 6)
	var wg sync.WaitGroup
	for item := uint16(0); item < 6; item++ {
		wg.Add(1)
		go func(item uint16) {
			defer wg.Done()
			<-start
			writeBatch := db.NewBatch()
			release, forget, stageErr := stageFinalizedCommonRPCAdmissionDeletes(writeBatch, []*types.CommonTxAdmissionBatch{body}, []types.CommonTxAdmissionRef{{Batch: 0, Item: item}})
			if stageErr != nil {
				errs <- stageErr
				return
			}
			if writeErr := writeBatch.Write(); writeErr != nil {
				release()
				errs <- writeErr
				return
			}
			forget()
			release()
		}(item)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	raw, err := db.Get(commonRPCAdmissionBatchDBKey(body.AdmissionID))
	if err != nil {
		t.Fatal(err)
	}
	var disk commonRPCAdmissionDiskBatch
	if err := rlp.DecodeBytes(raw, &disk); err != nil {
		t.Fatal(err)
	}
	if disk.References != 2 || disk.UnreferencedAt != 0 {
		t.Fatalf("concurrent partial finalization refs=%d unreferenced=%d", disk.References, disk.UnreferencedAt)
	}
	if !HasCommonRPCAdmission(hashes[6]) || !HasCommonRPCAdmission(hashes[7]) {
		t.Fatal("concurrent partial finalization removed a live item")
	}
}

func TestCommonRPCAdmissionWriteFailureDoesNotPublish(t *testing.T) {
	db, miner, chainID, genesis, _ := resetAdmissionTestState(t)
	db.writeErr = errors.New("injected")
	hash := common.Hash{1}
	if _, err := SignAndRecordCommonRPCAdmissions([]common.Hash{hash}, miner, chainID, genesis, 1, uint64(time.Now().Unix())); err == nil {
		t.Fatal("expected persistence failure")
	}
	if HasCommonRPCAdmission(hash) {
		t.Fatal("failed DB batch published an in-memory winner")
	}
}

func TestCommonRPCAdmissionPendingSurvivesAgeAndRestart(t *testing.T) {
	db, miner, chainID, genesis, _ := resetAdmissionTestState(t)
	hash := common.Hash{1}
	results, err := SignAndRecordCommonRPCAdmissions([]common.Hash{hash}, miner, chainID, genesis, 1, uint64(time.Now().Unix()))
	if err != nil {
		t.Fatal(err)
	}
	expired := time.Now().Add(-commonRPCAdmissionTTL - time.Minute)
	index := &commonRPCAdmissionIndexEntry{batch: results[0].Batch, item: 0, storedAt: expired, updatedAt: expired}
	body := &commonRPCAdmissionBatchEntry{batch: results[0].Batch, storedAt: expired, updatedAt: expired, references: 1}
	indexRaw, err := encodeCommonRPCAdmissionIndexEntry(hash, index)
	if err != nil {
		t.Fatal(err)
	}
	bodyRaw, err := encodeCommonRPCAdmissionBatchEntry(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Put(commonRPCAdmissionIndexDBKey(hash), indexRaw); err != nil {
		t.Fatal(err)
	}
	if err := db.Put(commonRPCAdmissionBatchDBKey(body.batch.AdmissionID), bodyRaw); err != nil {
		t.Fatal(err)
	}
	commonRPCAdmissionIndexes.Store(hash, index)
	commonRPCAdmissionBatches.Store(body.batch.AdmissionID, body)
	cleanupCommonRPCAdmissions(time.Now())
	if has, _ := db.Has(commonRPCAdmissionIndexDBKey(hash)); !has {
		t.Fatal("pending index was deleted by age")
	}
	if has, _ := db.Has(commonRPCAdmissionBatchDBKey(body.batch.AdmissionID)); !has {
		t.Fatal("referenced batch body was deleted by age")
	}
	SetCommonRPCAdmissionDatabase(db)
	if restored, ok := CommonRPCAdmissionForTransaction(hash); !ok || restored.Batch.AdmissionID != body.batch.AdmissionID {
		t.Fatalf("aged pending admission was not restored: %+v ok=%v", restored, ok)
	}
}

func TestCommonRPCAdmissionBodyCollectedOnlyAfterLastReference(t *testing.T) {
	db, miner, chainID, genesis, _ := resetAdmissionTestState(t)
	hashes := []common.Hash{{1}, {2}}
	results, err := SignAndRecordCommonRPCAdmissions(hashes, miner, chainID, genesis, 1, uint64(time.Now().Unix()))
	if err != nil {
		t.Fatal(err)
	}
	body := results[0].Batch
	finalize := func(item uint16) {
		writeBatch := db.NewBatch()
		release, forget, stageErr := stageFinalizedCommonRPCAdmissionDeletes(writeBatch, []*types.CommonTxAdmissionBatch{body}, []types.CommonTxAdmissionRef{{Batch: 0, Item: item}})
		if stageErr != nil {
			t.Fatal(stageErr)
		}
		if writeErr := writeBatch.Write(); writeErr != nil {
			release()
			t.Fatal(writeErr)
		}
		forget()
		release()
	}
	finalize(0)
	raw, err := db.Get(commonRPCAdmissionBatchDBKey(body.AdmissionID))
	if err != nil {
		t.Fatal(err)
	}
	var disk commonRPCAdmissionDiskBatch
	if err := rlp.DecodeBytes(raw, &disk); err != nil {
		t.Fatal(err)
	}
	if disk.References != 1 || disk.UnreferencedAt != 0 {
		t.Fatalf("partial finalization body state refs=%d unreferenced=%d", disk.References, disk.UnreferencedAt)
	}
	cleanupCommonRPCAdmissions(time.Now().Add(2 * commonRPCAdmissionTTL))
	if has, _ := db.Has(commonRPCAdmissionBatchDBKey(body.AdmissionID)); !has {
		t.Fatal("body with a live item reference was collected")
	}
	finalize(1)
	raw, err = db.Get(commonRPCAdmissionBatchDBKey(body.AdmissionID))
	if err != nil {
		t.Fatal(err)
	}
	if err := rlp.DecodeBytes(raw, &disk); err != nil {
		t.Fatal(err)
	}
	if disk.References != 0 || disk.UnreferencedAt == 0 {
		t.Fatalf("last finalization body state refs=%d unreferenced=%d", disk.References, disk.UnreferencedAt)
	}
	cleanupCommonRPCAdmissions(time.Unix(int64(disk.UnreferencedAt), 0).Add(commonRPCAdmissionTTL - time.Second))
	if has, _ := db.Has(commonRPCAdmissionBatchDBKey(body.AdmissionID)); !has {
		t.Fatal("zero-reference body was collected before retention elapsed")
	}
	cleanupCommonRPCAdmissions(time.Unix(int64(disk.UnreferencedAt), 0).Add(commonRPCAdmissionTTL + time.Second))
	if has, _ := db.Has(commonRPCAdmissionBatchDBKey(body.AdmissionID)); has {
		t.Fatal("zero-reference body remains after retention")
	}
}

func TestCommonRPCAdmissionCapacityRejectsNewPendingWithoutEviction(t *testing.T) {
	db, miner, chainID, genesis, _ := resetAdmissionTestState(t)
	existing := common.Hash{1}
	if _, err := SignAndRecordCommonRPCAdmissions([]common.Hash{existing}, miner, chainID, genesis, 1, uint64(time.Now().Unix())); err != nil {
		t.Fatal(err)
	}
	atomic.StoreInt64(&commonRPCAdmissionCount, commonRPCAdmissionMaxEntries)
	defer SetCommonRPCAdmissionDatabase(db)
	if _, err := SignAndRecordCommonRPCAdmissions([]common.Hash{{2}}, miner, chainID, genesis, 1, uint64(time.Now().Unix())); !errors.Is(err, ErrCommonRPCAdmissionCapacity) {
		t.Fatalf("capacity error = %v", err)
	}
	if !HasCommonRPCAdmission(existing) {
		t.Fatal("capacity handling evicted an existing pending admission")
	}
	if has, _ := db.Has(commonRPCAdmissionIndexDBKey(common.Hash{2})); has {
		t.Fatal("capacity-rejected admission was persisted")
	}
}

func TestCommonRPCAdmissionPersistentEncodingRoundTrip(t *testing.T) {
	_, _, chainID, genesis, _ := resetAdmissionTestState(t)
	batch := signedAdmissionBatch(t, []common.Hash{{1}}, chainID, genesis, 1, uint64(time.Now().Unix()))
	now := time.Now().Truncate(time.Second)
	raw, err := encodeCommonRPCAdmissionBatchEntry(&commonRPCAdmissionBatchEntry{batch: batch, storedAt: now, updatedAt: now, references: 1})
	if err != nil {
		t.Fatal(err)
	}
	var disk commonRPCAdmissionDiskBatch
	if err := rlp.DecodeBytes(raw, &disk); err != nil {
		t.Fatal(err)
	}
	if disk.Batch.AdmissionID != batch.AdmissionID || disk.StoredAt != uint64(now.Unix()) || disk.References != 1 {
		t.Fatalf("round trip mismatch: %+v", disk)
	}
}

func TestRejectedCommonRPCAdmissionCleanupKeepsAcceptedBatchReferences(t *testing.T) {
	db, miner, chainID, genesis, _ := resetAdmissionTestState(t)
	hashes := []common.Hash{{1}, {2}, {3}}
	results, err := SignAndRecordCommonRPCAdmissions(hashes, miner, chainID, genesis, 1, uint64(time.Now().Unix()))
	if err != nil {
		t.Fatal(err)
	}
	for i, result := range results {
		if !result.Updated || !result.Inserted {
			t.Fatalf("initial result %d was not marked inserted: %+v", i, result)
		}
	}
	db.reset()
	if err := DropRejectedCommonRPCAdmissions([]CommonRPCAdmissionResult{results[1]}); err != nil {
		t.Fatal(err)
	}
	if HasCommonRPCAdmission(hashes[1]) {
		t.Fatal("rejected transaction admission remains")
	}
	if !HasCommonRPCAdmission(hashes[0]) || !HasCommonRPCAdmission(hashes[2]) {
		t.Fatal("cleanup removed an accepted transaction admission from the mixed certificate")
	}
	raw, err := db.Get(commonRPCAdmissionBatchDBKey(results[0].Batch.AdmissionID))
	if err != nil {
		t.Fatal(err)
	}
	var disk commonRPCAdmissionDiskBatch
	if err := rlp.DecodeBytes(raw, &disk); err != nil {
		t.Fatal(err)
	}
	if disk.References != 2 || disk.UnreferencedAt != 0 {
		t.Fatalf("mixed certificate refs=%d unreferenced=%d, want 2/0", disk.References, disk.UnreferencedAt)
	}
	puts, deletes, writes := db.counts()
	if puts != 1 || deletes != 1 || writes != 1 {
		t.Fatalf("cleanup DB operations puts=%d deletes=%d writes=%d, want 1/1/1", puts, deletes, writes)
	}
	if got := atomic.LoadInt64(&commonRPCAdmissionCount); got != 2 {
		t.Fatalf("pending admission count=%d, want 2", got)
	}
	SetCommonRPCAdmissionDatabase(db)
	if HasCommonRPCAdmission(hashes[1]) || !HasCommonRPCAdmission(hashes[0]) || !HasCommonRPCAdmission(hashes[2]) {
		t.Fatal("mixed cleanup did not survive admission-store restart")
	}
}

func TestRejectedCommonRPCAdmissionCleanupSkipsNewWinnerAndReplacement(t *testing.T) {
	_, _, chainID, genesis, _ := resetAdmissionTestState(t)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	hash := common.Hash{9}
	now := uint64(time.Now().Unix())
	first := signedAdmissionBatchWithKey(t, key, []common.Hash{hash, {1}}, chainID, genesis, 1, now)
	second := signedAdmissionBatchWithKey(t, key, []common.Hash{hash, {2}}, chainID, genesis, 1, now)
	better, worse := first, second
	if !types.IsBetterCommonTxAdmission(first, second, hash) {
		better, worse = second, first
	}
	worseResults, err := VerifyAndStoreCommonRPCAdmissionBatch(worse, chainID, genesis)
	if err != nil {
		t.Fatal(err)
	}
	betterResults, err := VerifyAndStoreCommonRPCAdmissionBatch(better, chainID, genesis)
	if err != nil {
		t.Fatal(err)
	}
	if !worseResults[0].Inserted || !betterResults[0].Updated || betterResults[0].Inserted {
		t.Fatalf("insert/replacement markers worse=%+v better=%+v", worseResults[0], betterResults[0])
	}
	if err := DropRejectedCommonRPCAdmissions(worseResults[:1]); err != nil {
		t.Fatal(err)
	}
	if err := DropRejectedCommonRPCAdmissions(betterResults[:1]); err != nil {
		t.Fatal(err)
	}
	loaded, ok := CommonRPCAdmissionForTransaction(hash)
	if !ok || loaded.Batch.AdmissionID != better.AdmissionID {
		t.Fatalf("conditional cleanup removed/reverted the newer winner: %+v ok=%v", loaded, ok)
	}
}

func TestRejectedCommonRPCAdmissionCleanupWriteFailureRetainsState(t *testing.T) {
	db, miner, chainID, genesis, _ := resetAdmissionTestState(t)
	hash := common.Hash{7}
	results, err := SignAndRecordCommonRPCAdmissions([]common.Hash{hash}, miner, chainID, genesis, 1, uint64(time.Now().Unix()))
	if err != nil {
		t.Fatal(err)
	}
	wantCount := atomic.LoadInt64(&commonRPCAdmissionCount)
	db.writeErr = errors.New("injected cleanup failure")
	if err := DropRejectedCommonRPCAdmissions(results); err == nil {
		t.Fatal("expected cleanup persistence failure")
	}
	if !HasCommonRPCAdmission(hash) {
		t.Fatal("failed cleanup removed in-memory admission")
	}
	if got := atomic.LoadInt64(&commonRPCAdmissionCount); got != wantCount {
		t.Fatalf("failed cleanup changed count from %d to %d", wantCount, got)
	}
	if has, err := db.Has(commonRPCAdmissionIndexDBKey(hash)); err != nil || !has {
		t.Fatalf("failed cleanup removed durable index: has=%v err=%v", has, err)
	}
}

func TestRejectedCommonRPCAdmissionCleanupDoesNotLeakUniqueReplacementHashes(t *testing.T) {
	db, miner, chainID, genesis, _ := resetAdmissionTestState(t)
	const attempts = 256
	for i := 0; i < attempts; i++ {
		// These represent unique, equal-priced transactions competing at the
		// same sender nonce. TxPool retains the first and definitively rejects
		// every later hash as an underpriced replacement.
		to := common.Address{byte(i), byte(i >> 8), 1}
		tx := types.NewTransaction(0, to, big.NewInt(int64(i+1)), 21000, big.NewInt(1), nil)
		results, err := SignAndRecordCommonRPCAdmissions([]common.Hash{tx.Hash()}, miner, chainID, genesis, 1, uint64(time.Now().Unix()))
		if err != nil {
			t.Fatal(err)
		}
		if err := DropRejectedCommonRPCAdmissions(results); err != nil {
			t.Fatal(err)
		}
		if HasCommonRPCAdmission(tx.Hash()) {
			t.Fatalf("attempt %d retained rejected admission", i)
		}
	}
	if got := atomic.LoadInt64(&commonRPCAdmissionCount); got != 0 {
		t.Fatalf("unique rejected admissions leaked capacity: count=%d", got)
	}
	if got := countPersistedCommonRPCAdmissionIndexes(db); got != 0 {
		t.Fatalf("unique rejected admissions leaked %d durable indexes", got)
	}
}

func TestRejectedCommonRPCAdmissionCleanupConcurrentWinnerReplacement(t *testing.T) {
	_, _, chainID, genesis, _ := resetAdmissionTestState(t)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Now().Unix())
	for i := 0; i < 64; i++ {
		hash := common.BigToHash(big.NewInt(int64(i + 1_000)))
		first := signedAdmissionBatchWithKey(t, key, []common.Hash{hash, common.BigToHash(big.NewInt(int64(i + 2_000)))}, chainID, genesis, 1, now)
		second := signedAdmissionBatchWithKey(t, key, []common.Hash{hash, common.BigToHash(big.NewInt(int64(i + 3_000)))}, chainID, genesis, 1, now)
		better, worse := first, second
		if !types.IsBetterCommonTxAdmission(first, second, hash) {
			better, worse = second, first
		}
		worseResults, err := VerifyAndStoreCommonRPCAdmissionBatch(worse, chainID, genesis)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		errs := make(chan error, 2)
		go func() {
			<-start
			errs <- DropRejectedCommonRPCAdmissions(worseResults[:1])
		}()
		go func() {
			<-start
			_, storeErr := VerifyAndStoreCommonRPCAdmissionBatch(better, chainID, genesis)
			errs <- storeErr
		}()
		close(start)
		for j := 0; j < 2; j++ {
			if err := <-errs; err != nil {
				t.Fatal(err)
			}
		}
		loaded, ok := CommonRPCAdmissionForTransaction(hash)
		if !ok || loaded.Batch.AdmissionID != better.AdmissionID {
			t.Fatalf("iteration %d lost concurrent replacement: %+v ok=%v", i, loaded, ok)
		}
	}
}
