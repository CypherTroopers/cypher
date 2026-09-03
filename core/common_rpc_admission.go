package core

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
)

var (
	ErrInvalidCommonRPCAdmission  = errors.New("invalid common RPC admission")
	ErrCommonRPCAdmissionCapacity = errors.New("common RPC admission capacity exceeded")
)

const (
	commonRPCAdmissionTTL             = 30 * time.Minute
	commonRPCAdmissionCleanupInterval = time.Minute
	// Retain two full implementation-maximum native blocks. The genesis pool
	// intentionally buffers four configured blocks, but finalized admissions
	// are removed as blocks commit; a two-block index window absorbs concurrent
	// ingress and proposal publication without the old 1,000,000-entry ceiling
	// rejecting the final 48,576 transactions of a four-block native buffer.
	commonRPCAdmissionMaxEntries       = int64(2 * params.NativeParallelHardMaxTransactions)
	commonRPCAdmissionPersistentGCPage = 1024
	commonRPCAdmissionFutureClockSkew  = 30 * time.Second
)

// CommonRPCAdmissionResult is aligned with the input transaction hash. Batch
// and Item identify its current deterministic winner. Updated is true only
// when this operation inserted or replaced the tx index. Inserted is the
// narrower compensation boundary: it is true only when this operation created
// a previously absent tx index. Batch is immutable after publication and must
// be treated as read-only.
type CommonRPCAdmissionResult struct {
	Batch              *types.CommonTxAdmissionBatch
	Item               uint16
	Updated            bool
	Inserted           bool
	entry              *commonRPCAdmissionIndexEntry
	finalityGeneration uint64
}

type commonRPCAdmissionIndexEntry struct {
	batch     *types.CommonTxAdmissionBatch
	item      uint16
	storedAt  time.Time
	updatedAt time.Time
	// finalized is published while the transaction's admission stripe is held,
	// after the canonical DB batch commits and before the new head is exposed.
	// Proposal readers can therefore reject a stale loaded pointer without a DB
	// lookup or a giant finalized-block body scan.
	finalized atomic.Bool
}

type commonRPCAdmissionBatchEntry struct {
	batch          *types.CommonTxAdmissionBatch
	storedAt       time.Time
	updatedAt      time.Time
	references     uint32
	unreferencedAt time.Time
}

type commonRPCAdmissionDiskIndex struct {
	AdmissionID common.Hash
	Item        uint16
	StoredAt    uint64
	UpdatedAt   uint64
}

type commonRPCAdmissionDiskBatch struct {
	Batch          types.CommonTxAdmissionBatch
	StoredAt       uint64
	UpdatedAt      uint64
	References     uint32
	UnreferencedAt uint64
}

var (
	commonRPCAdmissionDBMu sync.RWMutex
	commonRPCAdmissionDB   ethdb.KeyValueStore

	commonRPCAdmissionIndexDBPrefix = []byte("common-rpc-admission-index:")
	commonRPCAdmissionBatchDBPrefix = []byte("common-rpc-admission-batch:")
	commonRPCAdmissionIndexGCCursor = []byte("common-rpc-admission-index-gc-cursor")
	commonRPCAdmissionBatchGCCursor = []byte("common-rpc-admission-batch-gc-cursor")

	commonRPCAdmissionPersistentGCMu          sync.Mutex
	commonRPCAdmissionPersistentIndexPosition []byte
	commonRPCAdmissionPersistentBatchPosition []byte
)

// Admission materialization runs behind the node-global ingress scheduler.
// A 256-way table makes two independent 32-64 transaction micro-batches
// collide with near certainty, serializing otherwise independent RPC/QUIC
// work. Twelve hash bits keep the table compact while making accidental
// overlap uncommon for the bounded micro-batches used by ingress.
const commonRPCAdmissionStoreStripeCount = 1 << 12

var commonRPCAdmissionStoreLocks [commonRPCAdmissionStoreStripeCount]sync.Mutex
var commonRPCAdmissionBatchLocks [commonRPCAdmissionStoreStripeCount]sync.Mutex

var (
	commonRPCAdmissionIndexes sync.Map // map[common.Hash]*commonRPCAdmissionIndexEntry
	commonRPCAdmissionBatches sync.Map // map[common.Hash]*commonRPCAdmissionBatchEntry
	commonRPCAdmissionCount   int64
	commonRPCAdmissionLastGC  int64

	commonRPCAdmissionSigner          atomic.Value // func(*types.CommonTxAdmissionBatch) error
	commonRPCAdmissionFinalizedLookup atomic.Value // commonRPCAdmissionFinalizedLookupHolder
	commonRPCAdmissionFinalityGen     atomic.Uint64
)

type commonRPCAdmissionFinalizedLookupHolder struct {
	lookup func(common.Hash) bool
}

func commonRPCAdmissionStoreLock(txHash common.Hash) *sync.Mutex {
	return &commonRPCAdmissionStoreLocks[commonRPCAdmissionStripe(txHash)]
}

func commonRPCAdmissionStripe(hash common.Hash) int {
	return int(hash[0])<<4 | int(hash[1]>>4)
}

// SetCommonRPCAdmissionDatabase installs the chain-local durable store. It is a
// lifecycle operation; clearing the read-through caches prevents a new genesis
// from observing admission state belonging to an old database.
func SetCommonRPCAdmissionDatabase(db ethdb.KeyValueStore) {
	// Invalidate proposal-local admission results before replacing their
	// database/cache ownership.
	commonRPCAdmissionFinalityGen.Add(1)
	var indexCursor, batchCursor []byte
	if db != nil {
		if raw, err := db.Get(commonRPCAdmissionIndexGCCursor); err == nil && len(raw) == common.HashLength {
			indexCursor = append(indexCursor, raw...)
		}
		if raw, err := db.Get(commonRPCAdmissionBatchGCCursor); err == nil && len(raw) == common.HashLength {
			batchCursor = append(batchCursor, raw...)
		}
	}
	commonRPCAdmissionDBMu.Lock()
	commonRPCAdmissionDB = db
	commonRPCAdmissionDBMu.Unlock()
	commonRPCAdmissionPersistentGCMu.Lock()
	commonRPCAdmissionPersistentIndexPosition = indexCursor
	commonRPCAdmissionPersistentBatchPosition = batchCursor
	commonRPCAdmissionPersistentGCMu.Unlock()
	commonRPCAdmissionIndexes.Range(func(key, _ interface{}) bool { commonRPCAdmissionIndexes.Delete(key); return true })
	commonRPCAdmissionBatches.Range(func(key, _ interface{}) bool { commonRPCAdmissionBatches.Delete(key); return true })
	atomic.StoreInt64(&commonRPCAdmissionCount, countPersistedCommonRPCAdmissionIndexes(db))
	atomic.StoreInt64(&commonRPCAdmissionLastGC, 0)
}

func countPersistedCommonRPCAdmissionIndexes(db ethdb.KeyValueStore) int64 {
	if db == nil {
		return 0
	}
	iterator := db.NewIterator(commonRPCAdmissionIndexDBPrefix, nil)
	defer iterator.Release()
	var count int64
	for iterator.Next() {
		if len(iterator.Key()) == len(commonRPCAdmissionIndexDBPrefix)+common.HashLength {
			count++
		}
	}
	return count
}

func currentCommonRPCAdmissionDatabase() ethdb.KeyValueStore {
	commonRPCAdmissionDBMu.RLock()
	db := commonRPCAdmissionDB
	commonRPCAdmissionDBMu.RUnlock()
	return db
}

func commonRPCAdmissionIndexDBKey(txHash common.Hash) []byte {
	key := make([]byte, len(commonRPCAdmissionIndexDBPrefix)+common.HashLength)
	copy(key, commonRPCAdmissionIndexDBPrefix)
	copy(key[len(commonRPCAdmissionIndexDBPrefix):], txHash[:])
	return key
}

func commonRPCAdmissionBatchDBKey(admissionID common.Hash) []byte {
	key := make([]byte, len(commonRPCAdmissionBatchDBPrefix)+common.HashLength)
	copy(key, commonRPCAdmissionBatchDBPrefix)
	copy(key[len(commonRPCAdmissionBatchDBPrefix):], admissionID[:])
	return key
}

func copyAdmissionChainID(chainID *big.Int) *big.Int {
	if chainID == nil {
		return nil
	}
	return new(big.Int).Set(chainID)
}

func copyCommonRPCAdmissionBatch(batch *types.CommonTxAdmissionBatch) *types.CommonTxAdmissionBatch {
	if batch == nil {
		return nil
	}
	cpy := *batch
	cpy.ChainID = copyAdmissionChainID(batch.ChainID)
	cpy.TxHashes = append([]common.Hash(nil), batch.TxHashes...)
	cpy.Signature = append([]byte(nil), batch.Signature...)
	return &cpy
}

// Signatures may differ for the same semantic AdmissionID. The ID commits all
// consensus fields, so signature bytes intentionally do not participate here.
func commonRPCAdmissionBatchesEqual(a, b *types.CommonTxAdmissionBatch) bool {
	if a == nil || b == nil || a.ChainID == nil || b.ChainID == nil {
		return a == b
	}
	if a.ChainID.Cmp(b.ChainID) != 0 || a.GenesisHash != b.GenesisHash || a.TxRoot != b.TxRoot ||
		a.AdmissionID != b.AdmissionID || a.Miner != b.Miner || a.KeyBlockNumber != b.KeyBlockNumber ||
		a.Timestamp != b.Timestamp || len(a.TxHashes) != len(b.TxHashes) {
		return false
	}
	for i := range a.TxHashes {
		if a.TxHashes[i] != b.TxHashes[i] {
			return false
		}
	}
	return true
}

func encodeCommonRPCAdmissionBatchEntry(entry *commonRPCAdmissionBatchEntry) ([]byte, error) {
	if entry == nil || entry.batch == nil || entry.batch.AdmissionID == (common.Hash{}) {
		return nil, fmt.Errorf("invalid common RPC admission batch persistence entry")
	}
	storedAt := entry.storedAt
	if storedAt.IsZero() {
		storedAt = time.Now()
	}
	updatedAt := entry.updatedAt
	if updatedAt.IsZero() {
		updatedAt = storedAt
	}
	return rlp.EncodeToBytes(&commonRPCAdmissionDiskBatch{
		Batch: *copyCommonRPCAdmissionBatch(entry.batch), StoredAt: uint64(storedAt.Unix()), UpdatedAt: uint64(updatedAt.Unix()),
		References: entry.references, UnreferencedAt: func() uint64 {
			if entry.unreferencedAt.IsZero() {
				return 0
			}
			return uint64(entry.unreferencedAt.Unix())
		}(),
	})
}

func encodeCommonRPCAdmissionIndexEntry(txHash common.Hash, entry *commonRPCAdmissionIndexEntry) ([]byte, error) {
	if entry == nil || entry.batch == nil || int(entry.item) >= len(entry.batch.TxHashes) || entry.batch.TxHashes[entry.item] != txHash {
		return nil, fmt.Errorf("invalid common RPC admission index persistence entry for %s", txHash)
	}
	storedAt := entry.storedAt
	if storedAt.IsZero() {
		storedAt = time.Now()
	}
	updatedAt := entry.updatedAt
	if updatedAt.IsZero() {
		updatedAt = storedAt
	}
	return rlp.EncodeToBytes(&commonRPCAdmissionDiskIndex{
		AdmissionID: entry.batch.AdmissionID, Item: entry.item, StoredAt: uint64(storedAt.Unix()), UpdatedAt: uint64(updatedAt.Unix()),
	})
}

func deletePersistedCommonRPCAdmissionIndex(txHash common.Hash) {
	if db := currentCommonRPCAdmissionDatabase(); db != nil {
		if err := db.Delete(commonRPCAdmissionIndexDBKey(txHash)); err != nil {
			log.Debug("Failed to delete persisted common RPC admission index", "tx", txHash, "err", err)
		}
	}
}

func deletePersistedCommonRPCAdmissionBatch(admissionID common.Hash) {
	if db := currentCommonRPCAdmissionDatabase(); db != nil {
		if err := db.Delete(commonRPCAdmissionBatchDBKey(admissionID)); err != nil {
			log.Debug("Failed to delete persisted common RPC admission batch", "admission", admissionID, "err", err)
		}
	}
}

func SetCommonRPCAdmissionSigner(signer func(*types.CommonTxAdmissionBatch) error) {
	commonRPCAdmissionSigner.Store(signer)
}

func signCommonRPCAdmission(batch *types.CommonTxAdmissionBatch) error {
	value := commonRPCAdmissionSigner.Load()
	if value == nil {
		return fmt.Errorf("common RPC admission signer is not installed")
	}
	signer, ok := value.(func(*types.CommonTxAdmissionBatch) error)
	if !ok || signer == nil {
		return fmt.Errorf("common RPC admission signer has invalid type")
	}
	return signer(batch)
}

func SetCommonRPCAdmissionFinalizedLookup(lookup func(common.Hash) bool) {
	commonRPCAdmissionFinalizedLookup.Store(commonRPCAdmissionFinalizedLookupHolder{lookup: lookup})
}

// isFinalizedCommonRPCTransactionStrong is reserved for ingress/recovery paths
// which may attempt to create a new admission after the in-memory winner has
// already been removed. Proposal selection must use the entry's atomic
// finalized bit and must never call this external/database-backed lookup for a
// memory hit.
func isFinalizedCommonRPCTransactionStrong(txHash common.Hash) bool {
	value := commonRPCAdmissionFinalizedLookup.Load()
	if value == nil {
		return false
	}
	holder, ok := value.(commonRPCAdmissionFinalizedLookupHolder)
	return ok && holder.lookup != nil && holder.lookup(txHash)
}

func commonRPCAdmissionBodyCollectable(entry *commonRPCAdmissionBatchEntry, now time.Time) bool {
	return entry != nil && entry.references == 0 && !entry.unreferencedAt.IsZero() && now.Sub(entry.unreferencedAt) > commonRPCAdmissionTTL
}

func reserveCommonRPCAdmissionEntries(count int64) bool {
	if count <= 0 {
		return true
	}
	for {
		current := atomic.LoadInt64(&commonRPCAdmissionCount)
		if current > commonRPCAdmissionMaxEntries-count {
			return false
		}
		if atomic.CompareAndSwapInt64(&commonRPCAdmissionCount, current, current+count) {
			return true
		}
	}
}

func releaseCommonRPCAdmissionEntries(count int64) {
	for ; count > 0; count-- {
		decrementCommonRPCAdmissionCount()
	}
}

func decrementCommonRPCAdmissionCount() {
	for {
		current := atomic.LoadInt64(&commonRPCAdmissionCount)
		if current <= 0 || atomic.CompareAndSwapInt64(&commonRPCAdmissionCount, current, current-1) {
			return
		}
	}
}

func unixTimeOr(value uint64, fallback time.Time) time.Time {
	if value == 0 {
		return fallback
	}
	return time.Unix(int64(value), 0)
}

func loadPersistedCommonRPCAdmissionBatch(admissionID common.Hash, now time.Time) (*commonRPCAdmissionBatchEntry, bool) {
	if value, ok := commonRPCAdmissionBatches.Load(admissionID); ok {
		entry, valid := value.(*commonRPCAdmissionBatchEntry)
		if valid && entry != nil && entry.batch != nil {
			return entry, true
		}
	}
	db := currentCommonRPCAdmissionDatabase()
	if db == nil {
		return nil, false
	}
	raw, err := db.Get(commonRPCAdmissionBatchDBKey(admissionID))
	if err != nil || len(raw) == 0 {
		return nil, false
	}
	var disk commonRPCAdmissionDiskBatch
	if err := rlp.DecodeBytes(raw, &disk); err != nil || disk.Batch.AdmissionID != admissionID {
		deletePersistedCommonRPCAdmissionBatch(admissionID)
		return nil, false
	}
	if err := types.VerifyCommonTxAdmissionSignature(&disk.Batch); err != nil {
		deletePersistedCommonRPCAdmissionBatch(admissionID)
		return nil, false
	}
	storedAt := unixTimeOr(disk.StoredAt, time.Unix(int64(disk.Batch.Timestamp), 0))
	updatedAt := unixTimeOr(disk.UpdatedAt, storedAt)
	unreferencedAt := unixTimeOr(disk.UnreferencedAt, time.Time{})
	if (disk.References > 0 && !unreferencedAt.IsZero()) || (disk.References == 0 && unreferencedAt.IsZero()) {
		deletePersistedCommonRPCAdmissionBatch(admissionID)
		return nil, false
	}
	entry := &commonRPCAdmissionBatchEntry{
		batch: copyCommonRPCAdmissionBatch(&disk.Batch), storedAt: storedAt, updatedAt: updatedAt,
		references: disk.References, unreferencedAt: unreferencedAt,
	}
	actual, loaded := commonRPCAdmissionBatches.LoadOrStore(admissionID, entry)
	if loaded {
		existing, ok := actual.(*commonRPCAdmissionBatchEntry)
		return existing, ok && existing != nil && existing.batch != nil
	}
	return entry, true
}

func loadPersistedCommonRPCAdmissionIndexLocked(txHash common.Hash, now time.Time) (*commonRPCAdmissionIndexEntry, bool) {
	db := currentCommonRPCAdmissionDatabase()
	if db == nil {
		return nil, false
	}
	raw, err := db.Get(commonRPCAdmissionIndexDBKey(txHash))
	if err != nil || len(raw) == 0 {
		return nil, false
	}
	var disk commonRPCAdmissionDiskIndex
	if err := rlp.DecodeBytes(raw, &disk); err != nil || disk.AdmissionID == (common.Hash{}) {
		deletePersistedCommonRPCAdmissionIndex(txHash)
		return nil, false
	}
	body, ok := loadPersistedCommonRPCAdmissionBatch(disk.AdmissionID, now)
	if !ok || body == nil || body.batch == nil || int(disk.Item) >= len(body.batch.TxHashes) || body.batch.TxHashes[disk.Item] != txHash {
		deletePersistedCommonRPCAdmissionIndex(txHash)
		return nil, false
	}
	storedAt := unixTimeOr(disk.StoredAt, body.storedAt)
	updatedAt := unixTimeOr(disk.UpdatedAt, storedAt)
	entry := &commonRPCAdmissionIndexEntry{batch: body.batch, item: disk.Item, storedAt: storedAt, updatedAt: updatedAt}
	actual, loaded := commonRPCAdmissionIndexes.LoadOrStore(txHash, entry)
	if loaded {
		existing, ok := actual.(*commonRPCAdmissionIndexEntry)
		return existing, ok && existing != nil && existing.batch != nil
	}
	return entry, true
}

func loadCommonRPCAdmissionIndex(txHash common.Hash, now time.Time) (*commonRPCAdmissionIndexEntry, bool) {
	if value, ok := commonRPCAdmissionIndexes.Load(txHash); ok {
		entry, valid := value.(*commonRPCAdmissionIndexEntry)
		if valid && entry != nil && entry.batch != nil && !entry.finalized.Load() {
			// Pair with finalization's Store(true) before cache deletion. A
			// reader which raced the first check observes the second one.
			if !entry.finalized.Load() {
				return entry, true
			}
		}
	}
	lock := commonRPCAdmissionStoreLock(txHash)
	lock.Lock()
	defer lock.Unlock()
	return loadCommonRPCAdmissionIndexLocked(txHash, now)
}

func loadCommonRPCAdmissionIndexLocked(txHash common.Hash, now time.Time) (*commonRPCAdmissionIndexEntry, bool) {
	value, ok := commonRPCAdmissionIndexes.Load(txHash)
	if !ok {
		return loadPersistedCommonRPCAdmissionIndexLocked(txHash, now)
	}
	entry, valid := value.(*commonRPCAdmissionIndexEntry)
	if !valid || entry == nil || entry.batch == nil || entry.finalized.Load() {
		return nil, false
	}
	return entry, true
}

func maybeCleanupCommonRPCAdmissions(now time.Time, force bool) {
	last := atomic.LoadInt64(&commonRPCAdmissionLastGC)
	if !force && now.Unix()-last < int64(commonRPCAdmissionCleanupInterval/time.Second) && atomic.LoadInt64(&commonRPCAdmissionCount) <= commonRPCAdmissionMaxEntries {
		return
	}
	if !atomic.CompareAndSwapInt64(&commonRPCAdmissionLastGC, last, now.Unix()) && !force {
		return
	}
	cleanupCommonRPCAdmissions(now)
}

func cleanupCommonRPCAdmissions(now time.Time) {
	commonRPCAdmissionIndexes.Range(func(key, value interface{}) bool {
		_, hashOK := key.(common.Hash)
		entry, entryOK := value.(*commonRPCAdmissionIndexEntry)
		if !hashOK || !entryOK || entry == nil || entry.batch == nil {
			commonRPCAdmissionIndexes.CompareAndDelete(key, value)
			return true
		}
		if entry.finalized.Load() {
			commonRPCAdmissionIndexes.CompareAndDelete(key, value)
		}
		return true
	})
	commonRPCAdmissionBatches.Range(func(key, value interface{}) bool {
		entry, ok := value.(*commonRPCAdmissionBatchEntry)
		if !ok || entry == nil || entry.batch == nil || commonRPCAdmissionBodyCollectable(entry, now) {
			commonRPCAdmissionBatches.CompareAndDelete(key, value)
		}
		return true
	})
	cleanupPersistedCommonRPCAdmissions(now)
}

func prunePersistedCommonRPCAdmissionIndex(raw []byte, txHash common.Hash, now time.Time) bool {
	var disk commonRPCAdmissionDiskIndex
	if err := rlp.DecodeBytes(raw, &disk); err != nil || disk.AdmissionID == (common.Hash{}) {
		return false
	}
	return isFinalizedCommonRPCTransactionStrong(txHash)
}

func prunePersistedCommonRPCAdmissionBatch(raw []byte, admissionID common.Hash, now time.Time) bool {
	var disk commonRPCAdmissionDiskBatch
	if err := rlp.DecodeBytes(raw, &disk); err != nil || disk.Batch.AdmissionID != admissionID {
		return true
	}
	if disk.References != 0 || disk.UnreferencedAt == 0 {
		return false
	}
	return now.Sub(time.Unix(int64(disk.UnreferencedAt), 0)) > commonRPCAdmissionTTL
}

func scanCommonRPCAdmissionPrefix(db ethdb.KeyValueStore, prefix, cursor []byte, now time.Time, prune func([]byte, common.Hash, time.Time) bool) (keys [][]byte, next []byte, touched bool, err error) {
	iterator := db.NewIterator(prefix, cursor)
	defer iterator.Release()
	last := append([]byte(nil), cursor...)
	visited := 0
	exhausted := true
	for iterator.Next() {
		key := iterator.Key()
		if len(key) < len(prefix) {
			continue
		}
		suffix := key[len(prefix):]
		if len(cursor) > 0 && visited == 0 && bytes.Equal(suffix, cursor) {
			continue
		}
		visited++
		if len(suffix) != common.HashLength {
			keys = append(keys, append([]byte(nil), key...))
		} else {
			last = append(last[:0], suffix...)
			if prune(iterator.Value(), common.BytesToHash(suffix), now) {
				keys = append(keys, append([]byte(nil), key...))
			}
		}
		if visited >= commonRPCAdmissionPersistentGCPage {
			exhausted = false
			break
		}
	}
	if err := iterator.Error(); err != nil {
		return nil, nil, false, err
	}
	if !exhausted && visited > 0 {
		next = append(next, last...)
	}
	return keys, next, visited > 0 || len(cursor) > 0, nil
}

// Pending transaction indexes are never evicted by age or capacity. Finalized
// indexes decrement durable certificate references; only zero-reference bodies
// are eligible for bounded-retention collection.
func cleanupPersistedCommonRPCAdmissions(now time.Time) {
	db := currentCommonRPCAdmissionDatabase()
	if db == nil {
		return
	}
	commonRPCAdmissionPersistentGCMu.Lock()
	defer commonRPCAdmissionPersistentGCMu.Unlock()
	indexKeys, nextIndex, touchedIndex, err := scanCommonRPCAdmissionPrefix(db, commonRPCAdmissionIndexDBPrefix, commonRPCAdmissionPersistentIndexPosition, now, prunePersistedCommonRPCAdmissionIndex)
	if err != nil {
		log.Warn("Failed to scan persisted common RPC admission indexes", "err", err)
		return
	}
	if touchedIndex {
		batch := db.NewBatch()
		hashes := make([]common.Hash, 0, len(indexKeys))
		var stripes [commonRPCAdmissionStoreStripeCount]bool
		for _, key := range indexKeys {
			if len(key) == len(commonRPCAdmissionIndexDBPrefix)+common.HashLength {
				hash := common.BytesToHash(key[len(commonRPCAdmissionIndexDBPrefix):])
				hashes = append(hashes, hash)
				stripes[commonRPCAdmissionStripe(hash)] = true
			} else if err := batch.Delete(key); err != nil {
				log.Warn("Failed to stage malformed common RPC admission index cleanup", "err", err)
				return
			}
		}
		release, forget, stageErr := stageCommonRPCAdmissionIndexDeletes(batch, hashes, stripes)
		if stageErr != nil {
			log.Warn("Failed to stage persisted common RPC admission index cleanup", "err", stageErr)
			return
		}
		if len(nextIndex) == 0 {
			err = batch.Delete(commonRPCAdmissionIndexGCCursor)
		} else {
			err = batch.Put(commonRPCAdmissionIndexGCCursor, nextIndex)
		}
		if err == nil {
			err = batch.Write()
		}
		if err == nil {
			forget()
			commonRPCAdmissionPersistentIndexPosition = append(commonRPCAdmissionPersistentIndexPosition[:0], nextIndex...)
		} else {
			log.Warn("Failed to clean persisted common RPC admission indexes", "err", err)
		}
		release()
		if err != nil {
			return
		}
	}

	var allBatchIDs = make(map[common.Hash]struct{}, commonRPCAdmissionStoreStripeCount)
	for i := 0; i < commonRPCAdmissionStoreStripeCount; i++ {
		var id common.Hash
		id[0] = byte(i >> 4)
		id[1] = byte(i << 4)
		allBatchIDs[id] = struct{}{}
	}
	releaseBatches := lockCommonRPCAdmissionBatchIDs(allBatchIDs)
	defer releaseBatches()
	bodyKeys, nextBody, touchedBody, err := scanCommonRPCAdmissionPrefix(db, commonRPCAdmissionBatchDBPrefix, commonRPCAdmissionPersistentBatchPosition, now, prunePersistedCommonRPCAdmissionBatch)
	if err != nil {
		log.Warn("Failed to scan persisted common RPC admission batches", "err", err)
		return
	}
	if !touchedBody {
		return
	}
	batch := db.NewBatch()
	for _, key := range bodyKeys {
		if err := batch.Delete(key); err != nil {
			log.Warn("Failed to stage common RPC admission batch cleanup", "err", err)
			return
		}
	}
	if len(nextBody) == 0 {
		if err := batch.Delete(commonRPCAdmissionBatchGCCursor); err != nil {
			return
		}
	} else if err := batch.Put(commonRPCAdmissionBatchGCCursor, nextBody); err != nil {
		return
	}
	if err := batch.Write(); err != nil {
		log.Warn("Failed to clean persisted common RPC admissions", "err", err)
		return
	}
	commonRPCAdmissionPersistentBatchPosition = append(commonRPCAdmissionPersistentBatchPosition[:0], nextBody...)
}

func lockCommonRPCAdmissionStripes(stripes [commonRPCAdmissionStoreStripeCount]bool) func() {
	for i := 0; i < len(stripes); i++ {
		if stripes[i] {
			commonRPCAdmissionStoreLocks[i].Lock()
		}
	}
	return func() {
		for i := len(stripes) - 1; i >= 0; i-- {
			if stripes[i] {
				commonRPCAdmissionStoreLocks[i].Unlock()
			}
		}
	}
}

func lockCommonRPCAdmissionBatchIDs(ids map[common.Hash]struct{}) func() {
	var stripes [commonRPCAdmissionStoreStripeCount]bool
	for id := range ids {
		stripes[commonRPCAdmissionStripe(id)] = true
	}
	for i := 0; i < len(stripes); i++ {
		if stripes[i] {
			commonRPCAdmissionBatchLocks[i].Lock()
		}
	}
	return func() {
		for i := len(stripes) - 1; i >= 0; i-- {
			if stripes[i] {
				commonRPCAdmissionBatchLocks[i].Unlock()
			}
		}
	}
}

func copyCommonRPCAdmissionBatchEntry(entry *commonRPCAdmissionBatchEntry) *commonRPCAdmissionBatchEntry {
	if entry == nil {
		return nil
	}
	return &commonRPCAdmissionBatchEntry{
		batch: entry.batch, storedAt: entry.storedAt, updatedAt: entry.updatedAt,
		references: entry.references, unreferencedAt: entry.unreferencedAt,
	}
}

func validateCommonRPCAdmissionNetwork(batch *types.CommonTxAdmissionBatch, chainID *big.Int, genesisHash common.Hash) error {
	if chainID == nil || chainID.Sign() <= 0 || batch == nil || batch.ChainID == nil || batch.ChainID.Cmp(chainID) != 0 {
		return fmt.Errorf("%w: admission chain does not match the local chain", ErrInvalidCommonRPCAdmission)
	}
	if genesisHash == (common.Hash{}) || batch.GenesisHash != genesisHash {
		return fmt.Errorf("%w: admission genesis does not match the local genesis", ErrInvalidCommonRPCAdmission)
	}
	if err := types.VerifyCommonTxAdmissionSignature(batch); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCommonRPCAdmission, err)
	}
	return nil
}

// VerifyAndStoreCommonRPCAdmissionBatch verifies one untrusted certificate once
// and atomically stores all winner-index changes. Results align with TxHashes.
func VerifyAndStoreCommonRPCAdmissionBatch(batch *types.CommonTxAdmissionBatch, chainID *big.Int, genesisHash common.Hash) ([]CommonRPCAdmissionResult, error) {
	sealed := copyCommonRPCAdmissionBatch(batch)
	if err := validateCommonRPCAdmissionNetwork(sealed, chainID, genesisHash); err != nil {
		return nil, err
	}
	return storeVerifiedCommonRPCAdmissionBatch(sealed)
}

func storeVerifiedCommonRPCAdmissionBatch(candidate *types.CommonTxAdmissionBatch) ([]CommonRPCAdmissionResult, error) {
	results := make([]CommonRPCAdmissionResult, len(candidate.TxHashes))
	now := time.Now()
	maybeCleanupCommonRPCAdmissions(now, false)
	var stripes [commonRPCAdmissionStoreStripeCount]bool
	for _, txHash := range candidate.TxHashes {
		stripes[commonRPCAdmissionStripe(txHash)] = true
	}
	release := lockCommonRPCAdmissionStripes(stripes)
	defer release()

	planned := make([]*commonRPCAdmissionIndexEntry, len(candidate.TxHashes))
	changed := make([]bool, len(candidate.TxHashes))
	loaded := make([]bool, len(candidate.TxHashes))
	changedCount := 0
	newCount := int64(0)
	affectedBatchIDs := map[common.Hash]struct{}{candidate.AdmissionID: {}}
	for i, txHash := range candidate.TxHashes {
		if isFinalizedCommonRPCTransactionStrong(txHash) {
			results[i] = CommonRPCAdmissionResult{Batch: candidate, Item: uint16(i)}
			continue
		}
		current, exists := loadCommonRPCAdmissionIndexLocked(txHash, now)
		loaded[i] = exists
		if exists && !types.IsBetterCommonTxAdmission(candidate, current.batch, txHash) {
			planned[i] = current
			results[i] = CommonRPCAdmissionResult{Batch: current.batch, Item: current.item}
			continue
		}
		entry := &commonRPCAdmissionIndexEntry{batch: candidate, item: uint16(i), storedAt: now, updatedAt: now}
		if exists {
			if !current.storedAt.IsZero() {
				entry.storedAt = current.storedAt
			}
			affectedBatchIDs[current.batch.AdmissionID] = struct{}{}
		} else {
			newCount++
		}
		planned[i] = entry
		changed[i] = true
		changedCount++
		results[i] = CommonRPCAdmissionResult{Batch: candidate, Item: uint16(i), Updated: true, Inserted: !exists}
	}
	if changedCount == 0 {
		return results, nil
	}
	releaseBatches := lockCommonRPCAdmissionBatchIDs(affectedBatchIDs)
	defer releaseBatches()

	canonical := candidate
	body, bodyLoaded := loadPersistedCommonRPCAdmissionBatch(candidate.AdmissionID, now)
	if bodyLoaded {
		if !commonRPCAdmissionBatchesEqual(candidate, body.batch) {
			return nil, fmt.Errorf("%w: admission ID %s resolves to conflicting batch bodies", ErrInvalidCommonRPCAdmission, candidate.AdmissionID)
		}
		canonical = body.batch
	} else {
		body = &commonRPCAdmissionBatchEntry{batch: canonical, storedAt: now, updatedAt: now}
	}
	bodyUpdates := make(map[common.Hash]*commonRPCAdmissionBatchEntry, len(affectedBatchIDs))
	bodyUpdates[canonical.AdmissionID] = copyCommonRPCAdmissionBatchEntry(body)
	for id := range affectedBatchIDs {
		if id == canonical.AdmissionID {
			continue
		}
		entry, ok := loadPersistedCommonRPCAdmissionBatch(id, now)
		if !ok || entry == nil || entry.batch == nil {
			return nil, fmt.Errorf("common RPC admission body %s is missing for an indexed transaction", id)
		}
		bodyUpdates[id] = copyCommonRPCAdmissionBatchEntry(entry)
	}
	for i, update := range changed {
		if !update {
			continue
		}
		if loaded[i] {
			oldBody := bodyUpdates[planned[i].batch.AdmissionID]
			// planned currently points at the new batch; recover the old winner
			// while its tx stripe is held.
			oldWinner, exists := loadCommonRPCAdmissionIndexLocked(candidate.TxHashes[i], now)
			if !exists || oldWinner == nil || oldWinner.batch == nil {
				return nil, fmt.Errorf("common RPC admission index %s disappeared during winner replacement", candidate.TxHashes[i])
			}
			oldBody = bodyUpdates[oldWinner.batch.AdmissionID]
			if oldBody == nil || oldBody.references == 0 {
				return nil, fmt.Errorf("common RPC admission body %s has invalid reference count", oldWinner.batch.AdmissionID)
			}
			oldBody.references--
		}
		newBody := bodyUpdates[canonical.AdmissionID]
		if newBody.references == ^uint32(0) {
			return nil, fmt.Errorf("common RPC admission body %s reference count overflow", canonical.AdmissionID)
		}
		newBody.references++
		planned[i].batch = canonical
		results[i].Batch = canonical
	}
	for _, update := range bodyUpdates {
		update.updatedAt = now
		if update.references == 0 {
			if update.unreferencedAt.IsZero() {
				update.unreferencedAt = now
			}
		} else {
			update.unreferencedAt = time.Time{}
		}
	}
	if !reserveCommonRPCAdmissionEntries(newCount) {
		return nil, fmt.Errorf("%w: %d pending indexes already retained", ErrCommonRPCAdmissionCapacity, atomic.LoadInt64(&commonRPCAdmissionCount))
	}
	reserved := true
	defer func() {
		if reserved {
			releaseCommonRPCAdmissionEntries(newCount)
		}
	}()

	if db := currentCommonRPCAdmissionDatabase(); db != nil {
		writeBatch := db.NewBatch()
		for id, update := range bodyUpdates {
			raw, err := encodeCommonRPCAdmissionBatchEntry(update)
			if err != nil {
				return nil, err
			}
			if err := writeBatch.Put(commonRPCAdmissionBatchDBKey(id), raw); err != nil {
				return nil, err
			}
		}
		for i, update := range changed {
			if !update {
				continue
			}
			raw, err := encodeCommonRPCAdmissionIndexEntry(candidate.TxHashes[i], planned[i])
			if err != nil {
				return nil, err
			}
			if err := writeBatch.Put(commonRPCAdmissionIndexDBKey(candidate.TxHashes[i]), raw); err != nil {
				return nil, err
			}
		}
		if err := writeBatch.Write(); err != nil {
			return nil, fmt.Errorf("persist common RPC admission batch: %w", err)
		}
	}
	for id, update := range bodyUpdates {
		commonRPCAdmissionBatches.Store(id, update)
	}
	for i, update := range changed {
		if !update {
			continue
		}
		commonRPCAdmissionIndexes.Store(candidate.TxHashes[i], planned[i])
	}
	reserved = false
	return results, nil
}

// SignCommonRPCAdmissions signs and verifies one ordered micro-batch without
// publishing it to the process cache or admission database. This separation is
// the crash-ordering boundary used by ingress: the certificate can first be
// fsynced in the unified WAL, then materialized through
// VerifyAndStoreCommonRPCAdmissionBatch.
func SignCommonRPCAdmissions(txHashes []common.Hash, miner common.Address, chainID *big.Int, genesisHash common.Hash, keyBlockNumber, timestamp uint64) ([]CommonRPCAdmissionResult, error) {
	if len(txHashes) == 0 || len(txHashes) > types.MaxCommonTxAdmissionBatchItems {
		return nil, fmt.Errorf("invalid common RPC admission transaction count %d", len(txHashes))
	}
	if miner == (common.Address{}) || chainID == nil || chainID.Sign() <= 0 || genesisHash == (common.Hash{}) || timestamp == 0 {
		return nil, fmt.Errorf("invalid common RPC admission identity or boundary")
	}
	seen := make(map[common.Hash]struct{}, len(txHashes))
	for i, txHash := range txHashes {
		if txHash == (common.Hash{}) {
			return nil, fmt.Errorf("invalid common RPC admission transaction hash at %d", i)
		}
		if _, duplicate := seen[txHash]; duplicate {
			return nil, fmt.Errorf("duplicate common RPC admission transaction %s", txHash)
		}
		seen[txHash] = struct{}{}
	}
	batch := &types.CommonTxAdmissionBatch{
		ChainID: copyAdmissionChainID(chainID), GenesisHash: genesisHash, Miner: miner,
		KeyBlockNumber: keyBlockNumber, Timestamp: timestamp, TxHashes: append([]common.Hash(nil), txHashes...),
	}
	batch.TxRoot = types.DeriveCommonTxAdmissionTxRoot(batch.TxHashes)
	batch.AdmissionID = types.CommonTxAdmissionID(batch)
	if err := signCommonRPCAdmission(batch); err != nil {
		return nil, err
	}
	if batch.ChainID == nil || batch.ChainID.Cmp(chainID) != 0 || batch.GenesisHash != genesisHash || batch.Miner != miner ||
		batch.KeyBlockNumber != keyBlockNumber || batch.Timestamp != timestamp || len(batch.TxHashes) != len(txHashes) {
		return nil, fmt.Errorf("common RPC admission signer modified signed batch fields")
	}
	for i := range txHashes {
		if batch.TxHashes[i] != txHashes[i] {
			return nil, fmt.Errorf("common RPC admission signer modified transaction hashes")
		}
	}
	if err := types.VerifyCommonTxAdmissionSignature(batch); err != nil {
		return nil, err
	}
	sealed := copyCommonRPCAdmissionBatch(batch)
	results := make([]CommonRPCAdmissionResult, len(sealed.TxHashes))
	for index := range results {
		results[index] = CommonRPCAdmissionResult{Batch: sealed, Item: uint16(index)}
	}
	return results, nil
}

// SignAndRecordCommonRPCAdmissions retains the legacy single-call API for
// non-ingress callers. New durable ingress must call SignCommonRPCAdmissions,
// fsync its WAL intent, then call VerifyAndStoreCommonRPCAdmissionBatch.
func SignAndRecordCommonRPCAdmissions(txHashes []common.Hash, miner common.Address, chainID *big.Int, genesisHash common.Hash, keyBlockNumber, timestamp uint64) ([]CommonRPCAdmissionResult, error) {
	signed, err := SignCommonRPCAdmissions(txHashes, miner, chainID, genesisHash, keyBlockNumber, timestamp)
	if err != nil {
		return nil, err
	}
	if len(signed) == 0 || signed[0].Batch == nil {
		return nil, errors.New("common RPC admission signer returned no certificate")
	}
	return storeVerifiedCommonRPCAdmissionBatch(copyCommonRPCAdmissionBatch(signed[0].Batch))
}

// CommonRPCAdmissionForTransaction restores and returns the immutable winning
// certificate and item for txHash.
func CommonRPCAdmissionForTransaction(txHash common.Hash) (CommonRPCAdmissionResult, bool) {
	if txHash == (common.Hash{}) {
		return CommonRPCAdmissionResult{}, false
	}
	for {
		generation := commonRPCAdmissionFinalityGen.Load()
		entry, ok := loadCommonRPCAdmissionIndex(txHash, time.Now())
		if !ok || entry == nil || entry.batch == nil || entry.finalized.Load() {
			return CommonRPCAdmissionResult{}, false
		}
		if generation == commonRPCAdmissionFinalityGen.Load() && !entry.finalized.Load() {
			return CommonRPCAdmissionResult{Batch: entry.batch, Item: entry.item, entry: entry, finalityGeneration: generation}, true
		}
	}
}

func HasCommonRPCAdmission(txHash common.Hash) bool {
	_, ok := CommonRPCAdmissionForTransaction(txHash)
	return ok
}

// CommonRPCAdmissionFinalityGeneration returns the process-local epoch advanced
// when a finalized admission set is published. Proposal builders capture it and
// recheck it at their single publication point, closing the interval between
// cache tombstoning and canonical-head publication without a per-tx DB lookup.
func CommonRPCAdmissionFinalityGeneration() uint64 {
	return commonRPCAdmissionFinalityGen.Load()
}

type commonRPCAdmissionExpectedIndex struct {
	admissionID common.Hash
	item        uint16
}

// DropRejectedCommonRPCAdmissions compensates durable admission indexes that
// were created immediately before TxPool definitively rejected their
// transactions. It intentionally ignores winner replacements: removing a
// replacement could also erase evidence retained for an older accepted/outbox
// lifecycle. The caller must keep its exact-txHash submission lease held while
// checking that each transaction is absent from TxPool and invoking this
// function.
//
// Every deletion is conditional on the currently stored AdmissionID and item.
// Certificate reference updates and index deletes commit in one database batch;
// memory and the capacity counter change only after that commit succeeds.
func DropRejectedCommonRPCAdmissions(results []CommonRPCAdmissionResult) error {
	targets := make(map[common.Hash]commonRPCAdmissionExpectedIndex, len(results))
	var stripes [commonRPCAdmissionStoreStripeCount]bool
	for _, result := range results {
		if !result.Updated || !result.Inserted {
			continue
		}
		if result.Batch == nil || result.Batch.AdmissionID == (common.Hash{}) || int(result.Item) >= len(result.Batch.TxHashes) {
			return fmt.Errorf("%w: invalid rejected admission result", ErrInvalidCommonRPCAdmission)
		}
		hash := result.Batch.TxHashes[result.Item]
		if hash == (common.Hash{}) {
			return fmt.Errorf("%w: rejected admission has an empty transaction hash", ErrInvalidCommonRPCAdmission)
		}
		expected := commonRPCAdmissionExpectedIndex{admissionID: result.Batch.AdmissionID, item: result.Item}
		if previous, exists := targets[hash]; exists && previous != expected {
			return fmt.Errorf("%w: conflicting rejected admission results for %s", ErrInvalidCommonRPCAdmission, hash)
		}
		targets[hash] = expected
		stripes[commonRPCAdmissionStripe(hash)] = true
	}
	if len(targets) == 0 {
		return nil
	}

	releaseTx := lockCommonRPCAdmissionStripes(stripes)
	defer releaseTx()
	now := time.Now()
	current := make(map[common.Hash]*commonRPCAdmissionIndexEntry, len(targets))
	batchIDs := make(map[common.Hash]struct{})
	for hash, expected := range targets {
		entry, exists := loadCommonRPCAdmissionIndexForRemovalLocked(hash, now)
		if !exists || entry == nil || entry.batch == nil || entry.batch.AdmissionID != expected.admissionID || entry.item != expected.item {
			continue
		}
		current[hash] = entry
		batchIDs[entry.batch.AdmissionID] = struct{}{}
	}
	if len(current) == 0 {
		return nil
	}

	releaseBatches := lockCommonRPCAdmissionBatchIDs(batchIDs)
	defer releaseBatches()
	bodyUpdates := make(map[common.Hash]*commonRPCAdmissionBatchEntry, len(batchIDs))
	for id := range batchIDs {
		body, ok := loadPersistedCommonRPCAdmissionBatch(id, now)
		if !ok || body == nil || body.batch == nil {
			return fmt.Errorf("common RPC admission body %s is missing during rejected-index cleanup", id)
		}
		bodyUpdates[id] = copyCommonRPCAdmissionBatchEntry(body)
	}
	for hash, entry := range current {
		body := bodyUpdates[entry.batch.AdmissionID]
		if body == nil || body.references == 0 {
			return fmt.Errorf("common RPC admission body %s has invalid reference count while dropping rejected %s", entry.batch.AdmissionID, hash)
		}
		body.references--
		body.updatedAt = now
		if body.references == 0 {
			body.unreferencedAt = now
		}
	}

	if db := currentCommonRPCAdmissionDatabase(); db != nil {
		writeBatch := db.NewBatch()
		for id, body := range bodyUpdates {
			raw, err := encodeCommonRPCAdmissionBatchEntry(body)
			if err != nil {
				return err
			}
			if err := writeBatch.Put(commonRPCAdmissionBatchDBKey(id), raw); err != nil {
				return fmt.Errorf("stage rejected common RPC admission body %s: %w", id, err)
			}
		}
		for hash := range current {
			if err := writeBatch.Delete(commonRPCAdmissionIndexDBKey(hash)); err != nil {
				return fmt.Errorf("stage rejected common RPC admission index %s: %w", hash, err)
			}
		}
		if err := writeBatch.Write(); err != nil {
			return fmt.Errorf("commit rejected common RPC admission cleanup: %w", err)
		}
	}
	for id, body := range bodyUpdates {
		commonRPCAdmissionBatches.Store(id, body)
	}
	for hash := range current {
		commonRPCAdmissionIndexes.Delete(hash)
		decrementCommonRPCAdmissionCount()
	}
	return nil
}

func commonRPCAdmissionDurationSeconds(duration time.Duration) uint64 {
	if duration <= 0 {
		return 0
	}
	return uint64(duration / time.Second)
}

func commonRPCAdmissionAddSeconds(value, seconds uint64) uint64 {
	if ^uint64(0)-value < seconds {
		return ^uint64(0)
	}
	return value + seconds
}

func validateCommonRPCAdmissionForBlock(batch *types.CommonTxAdmissionBatch, keyBlockNumber, blockTimestamp uint64) error {
	if batch == nil {
		return fmt.Errorf("nil common RPC admission batch")
	}
	if batch.Timestamp == 0 || blockTimestamp == 0 {
		return fmt.Errorf("common RPC admission %s has invalid timestamp boundary", batch.AdmissionID)
	}
	if batch.Timestamp > commonRPCAdmissionAddSeconds(blockTimestamp, commonRPCAdmissionDurationSeconds(commonRPCAdmissionFutureClockSkew)) {
		return fmt.Errorf("common RPC admission %s is from the future: admission=%d block=%d", batch.AdmissionID, batch.Timestamp, blockTimestamp)
	}
	if batch.KeyBlockNumber > keyBlockNumber {
		return fmt.Errorf("common RPC admission %s is bound to future key block", batch.AdmissionID)
	}
	// An admission is durable ingress evidence, not a lease on a proposal
	// boundary. Once a genesis-authorized signer has admitted a transaction for
	// this chain, queueing, restart, or key-block progress must not silently
	// expire it before finalization. KeyBlockNumber and Timestamp remain signed
	// audit data; only evidence from the future is invalid at proposal time.
	return nil
}

func commonRPCAdmissionForBlockTransaction(tx *types.Transaction, config *params.ChainConfig, genesisHash common.Hash, keyBlockNumber, timestamp uint64, now time.Time) (CommonRPCAdmissionResult, error) {
	if tx == nil {
		return CommonRPCAdmissionResult{}, fmt.Errorf("nil transaction in common RPC admission set")
	}
	if config == nil || !config.FairHotstuff || config.ChainID == nil || config.ChainID.Sign() <= 0 || genesisHash == (common.Hash{}) {
		return CommonRPCAdmissionResult{}, fmt.Errorf("cannot select common RPC admission without a valid Fair HotStuff chain identity")
	}
	txHash := tx.Hash()
	for {
		generation := commonRPCAdmissionFinalityGen.Load()
		entry, ok := loadCommonRPCAdmissionIndex(txHash, now)
		if !ok || entry == nil || entry.batch == nil || int(entry.item) >= len(entry.batch.TxHashes) || entry.batch.TxHashes[entry.item] != txHash {
			return CommonRPCAdmissionResult{}, fmt.Errorf("Fair HotStuff transaction %s has no common RPC admission", txHash)
		}
		batch := entry.batch
		if batch.ChainID == nil || batch.ChainID.Cmp(config.ChainID) != 0 || batch.GenesisHash != genesisHash {
			return CommonRPCAdmissionResult{}, fmt.Errorf("common RPC admission for %s belongs to another chain genesis", txHash)
		}
		if !config.IsCommonRPCSigner(batch.Miner) {
			return CommonRPCAdmissionResult{}, fmt.Errorf("common RPC admission for %s signer %s is not genesis-authorized", txHash, batch.Miner)
		}
		if err := validateCommonRPCAdmissionForBlock(batch, keyBlockNumber, timestamp); err != nil {
			return CommonRPCAdmissionResult{}, err
		}
		if entry.finalized.Load() {
			return CommonRPCAdmissionResult{}, fmt.Errorf("Fair HotStuff transaction %s is already finalized", txHash)
		}
		if generation == commonRPCAdmissionFinalityGen.Load() && !entry.finalized.Load() {
			return CommonRPCAdmissionResult{Batch: batch, Item: entry.item, entry: entry, finalityGeneration: generation}, nil
		}
		// An unrelated finalization may advance the epoch while this admission
		// remains live. Retry the memory-only lookup so proposal filtering does
		// not spuriously discard the candidate.
	}
}

func HasCommonRPCAdmissionForBlock(tx *types.Transaction, config *params.ChainConfig, genesisHash common.Hash, keyBlockNumber, txBlockNumber, timestamp uint64) bool {
	_, err := CommonRPCAdmissionForBlockTransaction(tx, config, genesisHash, keyBlockNumber, txBlockNumber, timestamp)
	return err == nil
}

// CommonRPCAdmissionForBlockTransaction returns the already-verified winning
// certificate selection in one lookup. Block number is intentionally not part
// of the pre-admission certificate boundary.
func CommonRPCAdmissionForBlockTransaction(tx *types.Transaction, config *params.ChainConfig, genesisHash common.Hash, keyBlockNumber, txBlockNumber, timestamp uint64) (CommonRPCAdmissionResult, error) {
	_ = txBlockNumber
	return commonRPCAdmissionForBlockTransaction(tx, config, genesisHash, keyBlockNumber, timestamp, time.Now())
}

// BuildCommonTxAdmissions returns unique certificates in AdmissionID order and
// refs aligned with block transaction order. Failure is mandatory for missing,
// future-boundary, unauthorized, wrong-chain, or wrong-genesis evidence.
func BuildCommonTxAdmissions(txs types.Transactions, config *params.ChainConfig, genesisHash common.Hash, keyBlockNumber, txBlockNumber, timestamp uint64) ([]*types.CommonTxAdmissionBatch, []types.CommonTxAdmissionRef, error) {
	_ = txBlockNumber
	if config == nil || !config.FairHotstuff || config.ChainID == nil || config.ChainID.Sign() <= 0 || genesisHash == (common.Hash{}) {
		return nil, nil, fmt.Errorf("cannot build common RPC admissions without a valid Fair HotStuff chain identity")
	}
	now := time.Now()
	maybeCleanupCommonRPCAdmissions(now, false)
	selections := make([]CommonRPCAdmissionResult, len(txs))
	for i, tx := range txs {
		selection, err := commonRPCAdmissionForBlockTransaction(tx, config, genesisHash, keyBlockNumber, timestamp, now)
		if err != nil {
			return nil, nil, err
		}
		selections[i] = selection
	}
	return BuildCommonTxAdmissionsFromResults(txs, selections, config, genesisHash, keyBlockNumber, txBlockNumber, timestamp)
}

// BuildCommonTxAdmissionsFromResults builds block sidecars from the exact
// immutable winners already returned during proposal filtering. This removes a
// second admission/finality lookup for every selected transaction while still
// revalidating transaction alignment, chain identity, signer authorization,
// temporal boundaries and the entry's atomic finalization tombstone.
func BuildCommonTxAdmissionsFromResults(txs types.Transactions, selections []CommonRPCAdmissionResult, config *params.ChainConfig, genesisHash common.Hash, keyBlockNumber, txBlockNumber, timestamp uint64) ([]*types.CommonTxAdmissionBatch, []types.CommonTxAdmissionRef, error) {
	_ = txBlockNumber
	if config == nil || !config.FairHotstuff || config.ChainID == nil || config.ChainID.Sign() <= 0 || genesisHash == (common.Hash{}) {
		return nil, nil, fmt.Errorf("cannot build common RPC admissions without a valid Fair HotStuff chain identity")
	}
	if len(selections) != len(txs) {
		return nil, nil, fmt.Errorf("common RPC admission selection count %d does not match transaction count %d", len(selections), len(txs))
	}
	finalityGeneration := commonRPCAdmissionFinalityGen.Load()
	unique := make(map[common.Hash]*types.CommonTxAdmissionBatch)
	ids := make([]common.Hash, 0)
	for i, tx := range txs {
		selection := selections[i]
		if tx == nil || selection.Batch == nil || selection.entry == nil || selection.entry.batch != selection.Batch || selection.entry.item != selection.Item || selection.entry.finalized.Load() || selection.finalityGeneration != finalityGeneration {
			return nil, nil, fmt.Errorf("Fair HotStuff transaction %d has no reusable common RPC admission", i)
		}
		if int(selection.Item) >= len(selection.Batch.TxHashes) || selection.Batch.TxHashes[selection.Item] != tx.Hash() {
			return nil, nil, fmt.Errorf("common RPC admission selection %d does not match transaction %s", i, tx.Hash())
		}
		batch := selection.Batch
		if batch.ChainID == nil || batch.ChainID.Cmp(config.ChainID) != 0 || batch.GenesisHash != genesisHash {
			return nil, nil, fmt.Errorf("common RPC admission for %s belongs to another chain genesis", tx.Hash())
		}
		if !config.IsCommonRPCSigner(batch.Miner) {
			return nil, nil, fmt.Errorf("common RPC admission for %s signer %s is not genesis-authorized", tx.Hash(), batch.Miner)
		}
		if err := validateCommonRPCAdmissionForBlock(batch, keyBlockNumber, timestamp); err != nil {
			return nil, nil, err
		}
		id := batch.AdmissionID
		if _, exists := unique[id]; !exists {
			unique[id] = batch
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })
	if uint64(len(ids)) > uint64(^uint32(0))+1 {
		return nil, nil, fmt.Errorf("too many common RPC admission batches: %d", len(ids))
	}
	batches := make([]*types.CommonTxAdmissionBatch, len(ids))
	positions := make(map[common.Hash]uint32, len(ids))
	for i, id := range ids {
		batches[i] = unique[id]
		positions[id] = uint32(i)
	}
	refs := make([]types.CommonTxAdmissionRef, len(selections))
	for i, selection := range selections {
		if selection.entry.finalized.Load() || selection.finalityGeneration != commonRPCAdmissionFinalityGen.Load() {
			return nil, nil, fmt.Errorf("Fair HotStuff transaction %s finalized while building admissions", txs[i].Hash())
		}
		refs[i] = types.CommonTxAdmissionRef{Batch: positions[selection.Batch.AdmissionID], Item: selection.Item}
	}
	return batches, refs, nil
}

func commonRPCAdmissionHashesForRefs(batches []*types.CommonTxAdmissionBatch, refs []types.CommonTxAdmissionRef) ([]common.Hash, [commonRPCAdmissionStoreStripeCount]bool, error) {
	hashes := make([]common.Hash, 0, len(refs))
	seen := make(map[common.Hash]struct{}, len(refs))
	var stripes [commonRPCAdmissionStoreStripeCount]bool
	for i, ref := range refs {
		if int(ref.Batch) >= len(batches) || batches[ref.Batch] == nil || int(ref.Item) >= len(batches[ref.Batch].TxHashes) {
			return nil, stripes, fmt.Errorf("invalid common RPC admission reference at %d", i)
		}
		hash := batches[ref.Batch].TxHashes[ref.Item]
		if hash == (common.Hash{}) {
			return nil, stripes, fmt.Errorf("empty common RPC admission transaction at reference %d", i)
		}
		if _, duplicate := seen[hash]; duplicate {
			continue
		}
		seen[hash] = struct{}{}
		hashes = append(hashes, hash)
		stripes[commonRPCAdmissionStripe(hash)] = true
	}
	return hashes, stripes, nil
}

func stageFinalizedCommonRPCAdmissionDeletes(writer ethdb.KeyValueWriter, batches []*types.CommonTxAdmissionBatch, refs []types.CommonTxAdmissionRef) (release func(), forget func(), err error) {
	if len(refs) == 0 {
		return func() {}, func() {}, nil
	}
	if writer == nil {
		return nil, nil, fmt.Errorf("common RPC admission finalization writer is nil")
	}
	hashes, stripes, err := commonRPCAdmissionHashesForRefs(batches, refs)
	if err != nil {
		return nil, nil, err
	}
	return stageCommonRPCAdmissionIndexDeletes(writer, hashes, stripes)
}

func loadCommonRPCAdmissionIndexForRemovalLocked(txHash common.Hash, now time.Time) (*commonRPCAdmissionIndexEntry, bool) {
	if value, ok := commonRPCAdmissionIndexes.Load(txHash); ok {
		entry, valid := value.(*commonRPCAdmissionIndexEntry)
		if valid && entry != nil && entry.batch != nil {
			return entry, true
		}
	}
	return loadPersistedCommonRPCAdmissionIndexLocked(txHash, now)
}

// stageCommonRPCAdmissionIndexDeletes atomically removes transaction indexes
// and decrements their certificate-body references. The caller must invoke
// forget only after the writer has committed, and release on every path.
func stageCommonRPCAdmissionIndexDeletes(writer ethdb.KeyValueWriter, hashes []common.Hash, stripes [commonRPCAdmissionStoreStripeCount]bool) (release func(), forget func(), err error) {
	if writer == nil {
		return nil, nil, fmt.Errorf("common RPC admission removal writer is nil")
	}
	releaseTx := lockCommonRPCAdmissionStripes(stripes)
	now := time.Now()
	current := make(map[common.Hash]*commonRPCAdmissionIndexEntry, len(hashes))
	batchIDs := make(map[common.Hash]struct{})
	for _, hash := range hashes {
		entry, exists := loadCommonRPCAdmissionIndexForRemovalLocked(hash, now)
		if exists {
			current[hash] = entry
			batchIDs[entry.batch.AdmissionID] = struct{}{}
		}
	}
	releaseBatches := lockCommonRPCAdmissionBatchIDs(batchIDs)
	bodyUpdates := make(map[common.Hash]*commonRPCAdmissionBatchEntry, len(batchIDs))
	fail := func(err error) (func(), func(), error) {
		releaseBatches()
		releaseTx()
		return nil, nil, err
	}
	for id := range batchIDs {
		body, ok := loadPersistedCommonRPCAdmissionBatch(id, now)
		if !ok || body == nil || body.batch == nil {
			return fail(fmt.Errorf("common RPC admission body %s is missing during index removal", id))
		}
		bodyUpdates[id] = copyCommonRPCAdmissionBatchEntry(body)
	}
	for hash, entry := range current {
		body := bodyUpdates[entry.batch.AdmissionID]
		if body == nil || body.references == 0 {
			return fail(fmt.Errorf("common RPC admission body %s has invalid reference count while removing %s", entry.batch.AdmissionID, hash))
		}
		body.references--
		body.updatedAt = now
		if body.references == 0 {
			body.unreferencedAt = now
		}
	}
	for id, body := range bodyUpdates {
		raw, encodeErr := encodeCommonRPCAdmissionBatchEntry(body)
		if encodeErr != nil {
			return fail(encodeErr)
		}
		if putErr := writer.Put(commonRPCAdmissionBatchDBKey(id), raw); putErr != nil {
			return fail(fmt.Errorf("stage common RPC admission body reference update for %s: %w", id, putErr))
		}
	}
	for _, hash := range hashes {
		if deleteErr := writer.Delete(commonRPCAdmissionIndexDBKey(hash)); deleteErr != nil {
			return fail(fmt.Errorf("stage common RPC admission index deletion for %s: %w", hash, deleteErr))
		}
	}
	release = func() {
		releaseBatches()
		releaseTx()
	}
	forget = func() {
		// Publish finality before deleting map entries. Lock-free readers which
		// already loaded an entry pointer retain the atomic tombstone and cannot
		// return it after this canonical finalization boundary.
		for _, entry := range current {
			entry.finalized.Store(true)
		}
		// Invalidate every proposal-local selection from the previous head,
		// including a pointer to a winner which ingress replaced before this
		// finalization acquired its stripe. All current entries are tombstoned
		// before the new epoch becomes observable, so a reader cannot capture the
		// new epoch while still accepting an old current entry.
		commonRPCAdmissionFinalityGen.Add(1)
		for id, body := range bodyUpdates {
			commonRPCAdmissionBatches.Store(id, body)
		}
		for hash := range current {
			commonRPCAdmissionIndexes.Delete(hash)
			decrementCommonRPCAdmissionCount()
		}
	}
	return release, forget, nil
}
