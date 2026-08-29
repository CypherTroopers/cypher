package core

import (
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
	"github.com/cypherium/cypher/rlp"
)

const (
	commonRPCAdmissionTTL             = 30 * time.Minute
	commonRPCAdmissionCleanupInterval = time.Minute
	commonRPCAdmissionMaxEntries      = 1000000
	commonRPCAdmissionBoundaryGrace   = 2 * time.Minute
	commonRPCAdmissionFutureClockSkew = 30 * time.Second
)

type commonRPCAdmissionEntry struct {
	admission *types.CommonTxAdmission
	storedAt  time.Time
	updatedAt time.Time
}

type commonRPCAdmissionDiskEntry struct {
	Admission types.CommonTxAdmission
	StoredAt  uint64
	UpdatedAt uint64
}

var commonRPCAdmissionDBMu sync.RWMutex
var commonRPCAdmissionDB ethdb.KeyValueStore
var commonRPCAdmissionDBPrefix = []byte("common-rpc-admission-v1:")

// SetCommonRPCAdmissionDatabase installs the durable key-value store used for
// admission sidecars. The chain database is process-local and already follows
// the node's genesis lifecycle.
func SetCommonRPCAdmissionDatabase(db ethdb.KeyValueStore) {
	commonRPCAdmissionDBMu.Lock()
	commonRPCAdmissionDB = db
	commonRPCAdmissionDBMu.Unlock()
}

func currentCommonRPCAdmissionDatabase() ethdb.KeyValueStore {
	commonRPCAdmissionDBMu.RLock()
	db := commonRPCAdmissionDB
	commonRPCAdmissionDBMu.RUnlock()
	return db
}

func commonRPCAdmissionDBKey(txHash common.Hash) []byte {
	key := make([]byte, len(commonRPCAdmissionDBPrefix)+len(txHash))
	copy(key, commonRPCAdmissionDBPrefix)
	copy(key[len(commonRPCAdmissionDBPrefix):], txHash[:])
	return key
}

func persistCommonRPCAdmissionEntry(txHash common.Hash, entry *commonRPCAdmissionEntry) error {
	db := currentCommonRPCAdmissionDatabase()
	if db == nil {
		return nil
	}
	if entry == nil || entry.admission == nil || entry.admission.TxHash != txHash {
		return fmt.Errorf("invalid common RPC admission persistence entry for %s", txHash)
	}
	storedAt := entry.storedAt
	if storedAt.IsZero() {
		storedAt = time.Now()
	}
	updatedAt := entry.updatedAt
	if updatedAt.IsZero() {
		updatedAt = storedAt
	}
	encoded, err := rlp.EncodeToBytes(&commonRPCAdmissionDiskEntry{
		Admission: *copyCommonRPCAdmission(entry.admission),
		StoredAt:  uint64(storedAt.Unix()),
		UpdatedAt: uint64(updatedAt.Unix()),
	})
	if err != nil {
		return err
	}
	return db.Put(commonRPCAdmissionDBKey(txHash), encoded)
}

func deletePersistedCommonRPCAdmission(txHash common.Hash) {
	db := currentCommonRPCAdmissionDatabase()
	if db == nil {
		return
	}
	if err := db.Delete(commonRPCAdmissionDBKey(txHash)); err != nil {
		log.Debug("Failed to delete persisted common RPC admission", "tx", txHash, "err", err)
	}
}

func loadPersistedCommonRPCAdmissionEntry(txHash common.Hash, now time.Time) (*commonRPCAdmissionEntry, bool) {
	db := currentCommonRPCAdmissionDatabase()
	if db == nil {
		return nil, false
	}
	encoded, err := db.Get(commonRPCAdmissionDBKey(txHash))
	if err != nil || len(encoded) == 0 {
		return nil, false
	}
	var disk commonRPCAdmissionDiskEntry
	if err := rlp.DecodeBytes(encoded, &disk); err != nil || disk.Admission.TxHash != txHash {
		deletePersistedCommonRPCAdmission(txHash)
		return nil, false
	}
	if err := types.VerifyCommonTxAdmissionSignature(&disk.Admission); err != nil {
		deletePersistedCommonRPCAdmission(txHash)
		return nil, false
	}
	storedAtUnix := disk.StoredAt
	if storedAtUnix == 0 {
		storedAtUnix = disk.Admission.Timestamp
	}
	if storedAtUnix == 0 {
		storedAtUnix = uint64(now.Unix())
	}
	updatedAtUnix := disk.UpdatedAt
	if updatedAtUnix == 0 {
		updatedAtUnix = storedAtUnix
	}
	entry := &commonRPCAdmissionEntry{
		admission: copyCommonRPCAdmission(&disk.Admission),
		storedAt:  time.Unix(int64(storedAtUnix), 0),
		updatedAt: time.Unix(int64(updatedAtUnix), 0),
	}
	if commonRPCAdmissionEntryExpired(entry, now) {
		deletePersistedCommonRPCAdmission(txHash)
		return nil, false
	}
	actual, loaded := commonRPCAdmissions.LoadOrStore(txHash, entry)
	if loaded {
		existing, ok := actual.(*commonRPCAdmissionEntry)
		return existing, ok && existing != nil && existing.admission != nil
	}
	atomic.AddInt64(&commonRPCAdmissionCount, 1)
	return entry, true
}

var commonRPCAdmissions sync.Map // map[common.Hash]*commonRPCAdmissionEntry
var commonRPCAdmissionCount int64
var commonRPCAdmissionLastCleanup int64
var commonRPCAdmissionSigner atomic.Value         // func(*types.CommonTxAdmission) error
var commonRPCAdmissionRelay atomic.Value          // fallback func([]*types.CommonTxAdmission)
var commonRPCAdmissionDedicatedRelay atomic.Value // preferred func([]*types.CommonTxAdmission)

func copyCommonRPCAdmission(admission *types.CommonTxAdmission) *types.CommonTxAdmission {
	if admission == nil {
		return nil
	}
	cpy := *admission
	if admission.ChainID != nil {
		cpy.ChainID = new(big.Int).Set(admission.ChainID)
	}
	if len(admission.Signature) > 0 {
		cpy.Signature = make([]byte, len(admission.Signature))
		copy(cpy.Signature, admission.Signature)
	}
	return &cpy
}

func copyAdmissionChainID(chainID *big.Int) *big.Int {
	if chainID == nil {
		return nil
	}
	return new(big.Int).Set(chainID)
}

// SetCommonRPCAdmissionSigner installs the local ECDSA signer used to seal
// CommonTxAdmission records before they are committed into a block body or
// propagated to peers.
func SetCommonRPCAdmissionSigner(signer func(*types.CommonTxAdmission) error) {
	commonRPCAdmissionSigner.Store(signer)
}

// SetCommonRPCAdmissionRelay installs the fallback transport used to propagate
// signed local admissions. The preferred production path is the dedicated
// committee channel installed with SetCommonRPCAdmissionDedicatedRelay.
func SetCommonRPCAdmissionRelay(relay func([]*types.CommonTxAdmission)) {
	commonRPCAdmissionRelay.Store(relay)
}

// SetCommonRPCAdmissionDedicatedRelay installs the preferred dedicated committee
// transport used to propagate signed common RPC admissions. When installed, this
// relay is used instead of the generic eth/p2p fallback relay.
func SetCommonRPCAdmissionDedicatedRelay(relay func([]*types.CommonTxAdmission)) {
	commonRPCAdmissionDedicatedRelay.Store(relay)
}

func callCommonRPCAdmissionRelay(value interface{}, admissions []*types.CommonTxAdmission) bool {
	if value == nil {
		return false
	}
	relay, ok := value.(func([]*types.CommonTxAdmission))
	if !ok || relay == nil {
		return false
	}
	relay(admissions)
	return true
}

func relayCommonRPCAdmissions(admissions []*types.CommonTxAdmission) {
	if len(admissions) == 0 {
		return
	}
	if callCommonRPCAdmissionRelay(commonRPCAdmissionDedicatedRelay.Load(), admissions) {
		return
	}
	callCommonRPCAdmissionRelay(commonRPCAdmissionRelay.Load(), admissions)
}

// RelayCommonRPCAdmissions exposes the committee-wide admission relay to the
// common RPC and TxQUIC ingress paths. Delivery is idempotent by TxHash.
func RelayCommonRPCAdmissions(admissions []*types.CommonTxAdmission) {
	relayCommonRPCAdmissions(admissions)
}

func signCommonRPCAdmission(admission *types.CommonTxAdmission) error {
	value := commonRPCAdmissionSigner.Load()
	if value == nil {
		return fmt.Errorf("common RPC admission signer is not installed")
	}
	signer, ok := value.(func(*types.CommonTxAdmission) error)
	if !ok || signer == nil {
		return fmt.Errorf("common RPC admission signer has invalid type")
	}
	return signer(admission)
}

func commonRPCAdmissionEntryExpired(entry *commonRPCAdmissionEntry, now time.Time) bool {
	if entry == nil || entry.admission == nil {
		return true
	}
	return now.Sub(entry.updatedAt) > commonRPCAdmissionTTL
}

func maybeCleanupCommonRPCAdmissions(now time.Time, force bool) {
	last := atomic.LoadInt64(&commonRPCAdmissionLastCleanup)
	if !force && now.Unix()-last < int64(commonRPCAdmissionCleanupInterval/time.Second) && atomic.LoadInt64(&commonRPCAdmissionCount) <= commonRPCAdmissionMaxEntries {
		return
	}
	if !atomic.CompareAndSwapInt64(&commonRPCAdmissionLastCleanup, last, now.Unix()) && !force {
		return
	}
	cleanupCommonRPCAdmissions(now)
}

func cleanupCommonRPCAdmissions(now time.Time) {
	type candidate struct {
		hash     common.Hash
		storedAt time.Time
		value    interface{}
	}
	candidates := make([]candidate, 0)
	var total int64
	var removed int64

	commonRPCAdmissions.Range(func(key interface{}, value interface{}) bool {
		total++
		hash, hashOK := key.(common.Hash)
		entry, entryOK := value.(*commonRPCAdmissionEntry)
		if !hashOK || !entryOK || commonRPCAdmissionEntryExpired(entry, now) {
			if commonRPCAdmissions.CompareAndDelete(key, value) {
				removed++
				if hashOK {
					deletePersistedCommonRPCAdmission(hash)
				}
			}
			return true
		}
		candidates = append(candidates, candidate{hash: hash, storedAt: entry.storedAt, value: value})
		return true
	})

	remaining := total - removed
	if remaining > commonRPCAdmissionMaxEntries {
		sort.Slice(candidates, func(i, j int) bool {
			return candidates[i].storedAt.Before(candidates[j].storedAt)
		})
		overflow := int(remaining - commonRPCAdmissionMaxEntries)
		if overflow > len(candidates) {
			overflow = len(candidates)
		}
		for i := 0; i < overflow; i++ {
			if commonRPCAdmissions.CompareAndDelete(candidates[i].hash, candidates[i].value) {
				removed++
				deletePersistedCommonRPCAdmission(candidates[i].hash)
			}
		}
	}

	newCount := total - removed
	if newCount < 0 {
		newCount = 0
	}
	atomic.StoreInt64(&commonRPCAdmissionCount, newCount)
	if removed > 0 {
		log.Debug("Cleaned common RPC admissions", "removed", removed, "remaining", newCount)
	}
}

func loadCommonRPCAdmissionEntry(txHash common.Hash, now time.Time) (*commonRPCAdmissionEntry, bool) {
	value, ok := commonRPCAdmissions.Load(txHash)
	if !ok {
		return loadPersistedCommonRPCAdmissionEntry(txHash, now)
	}
	entry, ok := value.(*commonRPCAdmissionEntry)
	if !ok || commonRPCAdmissionEntryExpired(entry, now) {
		if commonRPCAdmissions.CompareAndDelete(txHash, value) {
			atomic.AddInt64(&commonRPCAdmissionCount, -1)
		}
		deletePersistedCommonRPCAdmission(txHash)
		return nil, false
	}
	return entry, true
}

// StoreCommonRPCAdmission verifies and stores a signed admission received from
// the local RPC path, the dedicated committee channel, or P2P. If multiple valid
// admissions exist for the same tx, the deterministic lowest winner hash is kept.
func StoreCommonRPCAdmission(admission *types.CommonTxAdmission) bool {
	if err := types.VerifyCommonTxAdmissionSignature(admission); err != nil {
		log.Warn("Rejected common RPC admission", "err", err)
		return false
	}
	return storeVerifiedCommonRPCAdmission(admission)
}

func storeVerifiedCommonRPCAdmission(admission *types.CommonTxAdmission) bool {
	now := time.Now()
	maybeCleanupCommonRPCAdmissions(now, false)

	sealed := copyCommonRPCAdmission(admission)
	replacement := &commonRPCAdmissionEntry{admission: sealed, storedAt: now, updatedAt: now}
	for {
		value, loaded := commonRPCAdmissions.LoadOrStore(sealed.TxHash, replacement)
		if !loaded {
			atomic.AddInt64(&commonRPCAdmissionCount, 1)
			if err := persistCommonRPCAdmissionEntry(sealed.TxHash, replacement); err != nil {
				log.Error("Failed to persist common RPC admission", "tx", sealed.TxHash, "err", err)
			}
			break
		}
		entry, _ := value.(*commonRPCAdmissionEntry)
		current := (*types.CommonTxAdmission)(nil)
		if entry != nil {
			current = entry.admission
		}
		if !types.IsBetterCommonTxAdmission(sealed, current) {
			if entry != nil {
				if err := persistCommonRPCAdmissionEntry(sealed.TxHash, entry); err != nil {
					log.Error("Failed to refresh persisted common RPC admission", "tx", sealed.TxHash, "err", err)
				}
			}
			return false
		}
		if entry != nil && !entry.storedAt.IsZero() {
			replacement.storedAt = entry.storedAt
		}
		if commonRPCAdmissions.CompareAndSwap(sealed.TxHash, value, replacement) {
			if err := persistCommonRPCAdmissionEntry(sealed.TxHash, replacement); err != nil {
				log.Error("Failed to persist replacement common RPC admission", "tx", sealed.TxHash, "err", err)
			}
			break
		}
	}
	if atomic.LoadInt64(&commonRPCAdmissionCount) > commonRPCAdmissionMaxEntries {
		maybeCleanupCommonRPCAdmissions(now, true)
	}
	return true
}

func commonRPCAdmissionDurationSeconds(d time.Duration) uint64 {
	if d <= 0 {
		return 0
	}
	return uint64(d / time.Second)
}

func commonRPCAdmissionAddSeconds(value uint64, seconds uint64) uint64 {
	if ^uint64(0)-value < seconds {
		return ^uint64(0)
	}
	return value + seconds
}

func validateCommonRPCAdmissionForBlock(admission *types.CommonTxAdmission, keyBlockNumber uint64, txBlockNumber uint64, blockTimestamp uint64) error {
	if admission == nil {
		return fmt.Errorf("nil common RPC admission")
	}
	if admission.TxBlockNumber != 0 {
		return fmt.Errorf("common RPC admission for %s has tx block number %d before finalization", admission.TxHash, admission.TxBlockNumber)
	}
	if admission.Timestamp == 0 {
		return fmt.Errorf("common RPC admission for %s has empty timestamp", admission.TxHash)
	}
	if blockTimestamp == 0 {
		return fmt.Errorf("common RPC admission for %s cannot be boundary-checked without block timestamp", admission.TxHash)
	}
	if admission.Timestamp > commonRPCAdmissionAddSeconds(blockTimestamp, commonRPCAdmissionDurationSeconds(commonRPCAdmissionFutureClockSkew)) {
		return fmt.Errorf("common RPC admission for %s is from the future: admission=%d block=%d", admission.TxHash, admission.Timestamp, blockTimestamp)
	}
	if admission.KeyBlockNumber == keyBlockNumber {
		return nil
	}
	if admission.KeyBlockNumber < keyBlockNumber && keyBlockNumber-admission.KeyBlockNumber == 1 {
		graceUntil := commonRPCAdmissionAddSeconds(admission.Timestamp, commonRPCAdmissionDurationSeconds(commonRPCAdmissionBoundaryGrace))
		if blockTimestamp <= graceUntil {
			return nil
		}
		return fmt.Errorf("common RPC admission for %s crossed key block boundary outside grace: admissionKey=%d blockKey=%d admissionTime=%d blockTime=%d grace=%s", admission.TxHash, admission.KeyBlockNumber, keyBlockNumber, admission.Timestamp, blockTimestamp, commonRPCAdmissionBoundaryGrace)
	}
	if admission.KeyBlockNumber > keyBlockNumber {
		return fmt.Errorf("common RPC admission for %s is bound to future key block: admissionKey=%d blockKey=%d", admission.TxHash, admission.KeyBlockNumber, keyBlockNumber)
	}
	return fmt.Errorf("common RPC admission for %s is bound to stale key block: admissionKey=%d blockKey=%d", admission.TxHash, admission.KeyBlockNumber, keyBlockNumber)
}

// SignAndRecordCommonRPCAdmission signs and stores a local common RPC tx
// admission. TxBlockNumber is intentionally zero here because the block proposer
// has not selected the tx block yet. The signed record is later carried unchanged
// in the block body and validated by signature recovery.
func SignAndRecordCommonRPCAdmission(txHash common.Hash, miner common.Address, chainID *big.Int, keyBlockNumber uint64, timestamp uint64) (*types.CommonTxAdmission, error) {
	if txHash == (common.Hash{}) || miner == (common.Address{}) {
		return nil, fmt.Errorf("invalid common RPC admission: tx=%s miner=%s", txHash, miner)
	}
	if chainID == nil || chainID.Sign() <= 0 {
		return nil, fmt.Errorf("invalid common RPC admission chain id for tx=%s miner=%s", txHash, miner)
	}
	admission := &types.CommonTxAdmission{
		ChainID:        copyAdmissionChainID(chainID),
		TxHash:         txHash,
		Miner:          miner,
		KeyBlockNumber: keyBlockNumber,
		TxBlockNumber:  0,
		Timestamp:      timestamp,
	}
	if err := signCommonRPCAdmission(admission); err != nil {
		return nil, err
	}
	if err := types.VerifyCommonTxAdmissionSignature(admission); err != nil {
		return nil, err
	}
	storeVerifiedCommonRPCAdmission(admission)
	entry, ok := loadCommonRPCAdmissionEntry(txHash, time.Now())
	if !ok {
		return nil, fmt.Errorf("common RPC admission was not retained for tx=%s", txHash)
	}
	if err := persistCommonRPCAdmissionEntry(txHash, entry); err != nil {
		return nil, fmt.Errorf("persist common RPC admission for tx=%s: %w", txHash, err)
	}
	return copyCommonRPCAdmission(admission), nil
}

// RecordCommonRPCAdmission records that a local common RPC miner accepted a tx,
// signs the admission when the local coinbase wallet is available, and relays the
// signed record to peers. It remains the stable entry point used by SendTx.
func RecordCommonRPCAdmission(txHash common.Hash, miner common.Address, chainID *big.Int) {
	if txHash == (common.Hash{}) || miner == (common.Address{}) {
		return
	}
	admission, err := SignAndRecordCommonRPCAdmission(txHash, miner, chainID, 0, uint64(time.Now().Unix()))
	if err != nil {
		log.Error("Failed to sign common RPC admission", "tx", txHash, "miner", miner, "err", err)
		return
	}
	relayCommonRPCAdmissions([]*types.CommonTxAdmission{admission})
}

// CommonRPCAdmissionMiner returns the local recorded common RPC miner for txHash.
func CommonRPCAdmissionMiner(txHash common.Hash) (common.Address, bool) {
	entry, ok := loadCommonRPCAdmissionEntry(txHash, time.Now())
	if !ok || entry.admission == nil || entry.admission.Miner == (common.Address{}) {
		return common.Address{}, false
	}
	return entry.admission.Miner, true
}

// CommonRPCAdmissionsForTransactions returns verified stored sidecars without
// applying block-boundary rules. It is used to re-relay journaled transactions
// after restart or peer reconnection.
func CommonRPCAdmissionsForTransactions(txs types.Transactions) []*types.CommonTxAdmission {
	now := time.Now()
	maybeCleanupCommonRPCAdmissions(now, false)
	admissions := make([]*types.CommonTxAdmission, 0, len(txs))
	for _, tx := range txs {
		if tx == nil {
			continue
		}
		entry, ok := loadCommonRPCAdmissionEntry(tx.Hash(), now)
		if !ok || entry.admission == nil {
			continue
		}
		admission := copyCommonRPCAdmission(entry.admission)
		if err := types.VerifyCommonTxAdmissionSignature(admission); err != nil {
			deletePersistedCommonRPCAdmission(tx.Hash())
			continue
		}
		admissions = append(admissions, admission)
	}
	return admissions
}

// BuildCommonTxAdmissions converts recorded tx admissions into signed block-body data.
func BuildCommonTxAdmissions(txs types.Transactions, keyBlockNumber uint64, txBlockNumber uint64, timestamp uint64) []*types.CommonTxAdmission {
	now := time.Now()
	maybeCleanupCommonRPCAdmissions(now, false)
	admissions := make([]*types.CommonTxAdmission, 0)
	for _, tx := range txs {
		if tx == nil {
			continue
		}
		txHash := tx.Hash()
		entry, ok := loadCommonRPCAdmissionEntry(txHash, now)
		if !ok || entry.admission == nil {
			continue
		}
		sealed := copyCommonRPCAdmission(entry.admission)
		if err := types.VerifyCommonTxAdmissionSignature(sealed); err != nil {
			log.Warn("Invalid common RPC admission signature", "tx", txHash, "miner", sealed.Miner, "err", err)
			continue
		}
		if err := validateCommonRPCAdmissionForBlock(sealed, keyBlockNumber, txBlockNumber, timestamp); err != nil {
			log.Debug("Skipping common RPC admission outside key block boundary", "tx", txHash, "miner", sealed.Miner, "err", err)
			continue
		}
		admissions = append(admissions, sealed)
	}
	return admissions
}

// DropCommonRPCAdmissions removes finalized tx admission records from memory.
func DropCommonRPCAdmissions(txs types.Transactions) {
	for _, tx := range txs {
		if tx == nil {
			continue
		}
		hash := tx.Hash()
		if _, loaded := commonRPCAdmissions.LoadAndDelete(hash); loaded {
			atomic.AddInt64(&commonRPCAdmissionCount, -1)
		}
		deletePersistedCommonRPCAdmission(hash)
	}
}
