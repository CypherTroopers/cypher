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
	"github.com/cypherium/cypher/log"
)

const (
	commonRPCAdmissionTTL             = 30 * time.Minute
	commonRPCAdmissionCleanupInterval = time.Minute
	commonRPCAdmissionMaxEntries      = 100000
)

type commonRPCAdmissionEntry struct {
	admission *types.CommonTxAdmission
	storedAt  time.Time
	updatedAt time.Time
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
	}
	candidates := make([]candidate, 0)
	var total int64
	var removed int64

	commonRPCAdmissions.Range(func(key interface{}, value interface{}) bool {
		total++
		hash, hashOK := key.(common.Hash)
		entry, entryOK := value.(*commonRPCAdmissionEntry)
		if !hashOK || !entryOK || commonRPCAdmissionEntryExpired(entry, now) {
			commonRPCAdmissions.Delete(key)
			removed++
			return true
		}
		candidates = append(candidates, candidate{hash: hash, storedAt: entry.storedAt})
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
			commonRPCAdmissions.Delete(candidates[i].hash)
			removed++
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
		return nil, false
	}
	entry, ok := value.(*commonRPCAdmissionEntry)
	if !ok || commonRPCAdmissionEntryExpired(entry, now) {
		commonRPCAdmissions.Delete(txHash)
		atomic.AddInt64(&commonRPCAdmissionCount, -1)
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
	now := time.Now()
	maybeCleanupCommonRPCAdmissions(now, false)

	sealed := copyCommonRPCAdmission(admission)
	value, ok := commonRPCAdmissions.Load(sealed.TxHash)
	if ok {
		entry, _ := value.(*commonRPCAdmissionEntry)
		current := (*types.CommonTxAdmission)(nil)
		if entry != nil {
			current = entry.admission
		}
		if !types.IsBetterCommonTxAdmission(sealed, current) {
			return false
		}
	} else {
		atomic.AddInt64(&commonRPCAdmissionCount, 1)
	}
	commonRPCAdmissions.Store(sealed.TxHash, &commonRPCAdmissionEntry{admission: sealed, storedAt: now, updatedAt: now})
	if atomic.LoadInt64(&commonRPCAdmissionCount) > commonRPCAdmissionMaxEntries {
		maybeCleanupCommonRPCAdmissions(now, true)
	}
	return true
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
	StoreCommonRPCAdmission(admission)
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
		admissions = append(admissions, sealed)
	}
	return admissions
}

// DropCommonRPCAdmissions removes finalized tx admission records from memory.
func DropCommonRPCAdmissions(txs types.Transactions) {
	for _, tx := range txs {
		if tx != nil {
			if _, loaded := commonRPCAdmissions.LoadAndDelete(tx.Hash()); loaded {
				atomic.AddInt64(&commonRPCAdmissionCount, -1)
			}
		}
	}
}
