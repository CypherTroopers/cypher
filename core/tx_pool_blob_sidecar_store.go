package core

import (
	"errors"
	"math"
	"sync"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

type blobSidecarStore struct {
	mu         sync.RWMutex
	sidecars   map[common.Hash]*types.BlobTxSidecar
	bytes      uint64
	maxBytes   uint64
	maxEntries uint64
}

var blobSidecarStores sync.Map

var ErrBlobSidecarStoreFull = errors.New("blob sidecar store capacity exceeded")

// blobSidecarMemoryBytes conservatively accounts the variable-sized data held
// by one defensive sidecar copy. The generic txpool accounting separately
// charges a second copy attached to the transaction object.
func blobSidecarMemoryBytes(sidecar *types.BlobTxSidecar) uint64 {
	if sidecar == nil {
		return 0
	}
	// Sidecar struct plus three slice headers. Each Blob element also owns a
	// slice header in addition to its byte backing.
	size := uint64(4 * 24)
	for _, blob := range sidecar.Blobs {
		if uint64(len(blob)) > math.MaxUint64-size {
			return math.MaxUint64
		}
		size += uint64(len(blob))
		if size > math.MaxUint64-24 {
			return math.MaxUint64
		}
		size += 24
	}
	commitmentBytes := uint64(len(sidecar.Commitments)) * uint64(len(types.KZGCommitment{}))
	proofBytes := uint64(len(sidecar.Proofs)) * uint64(len(types.KZGProof{}))
	if commitmentBytes > math.MaxUint64-size {
		return math.MaxUint64
	}
	size += commitmentBytes
	if proofBytes > math.MaxUint64-size {
		return math.MaxUint64
	}
	return size + proofBytes
}

func blobSidecarStoreLimits(pool *TxPool) (uint64, uint64) {
	globalSlots, globalQueue := DefaultTxPoolConfig.GlobalSlots, DefaultTxPoolConfig.GlobalQueue
	if pool != nil {
		if pool.config.GlobalSlots != 0 {
			globalSlots = pool.config.GlobalSlots
		}
		if pool.config.GlobalQueue != 0 {
			globalQueue = pool.config.GlobalQueue
		}
	}
	maxEntries := globalSlots
	if math.MaxUint64-maxEntries < globalQueue {
		maxEntries = math.MaxUint64
	} else {
		maxEntries += globalQueue
	}
	maxBytes := maxEntries
	if maxBytes > math.MaxUint64/txSlotSize {
		maxBytes = math.MaxUint64
	} else {
		maxBytes *= txSlotSize
	}
	return maxBytes, maxEntries
}

func dropBlobSidecarStore(pool *TxPool) {
	if pool != nil {
		blobSidecarStores.Delete(pool)
	}
}

func loadBlobSidecarStore(pool *TxPool) *blobSidecarStore {
	if pool == nil {
		return nil
	}
	store, ok := blobSidecarStores.Load(pool)
	if !ok {
		return nil
	}
	return store.(*blobSidecarStore)
}

func getBlobSidecarStore(pool *TxPool) *blobSidecarStore {
	if pool == nil {
		return nil
	}
	if store, ok := blobSidecarStores.Load(pool); ok {
		return store.(*blobSidecarStore)
	}
	maxBytes, maxEntries := blobSidecarStoreLimits(pool)
	store := &blobSidecarStore{
		sidecars:   make(map[common.Hash]*types.BlobTxSidecar),
		maxBytes:   maxBytes,
		maxEntries: maxEntries,
	}
	actual, _ := blobSidecarStores.LoadOrStore(pool, store)
	return actual.(*blobSidecarStore)
}

func (pool *TxPool) storeBlobSidecar(tx *types.Transaction, sidecar *types.BlobTxSidecar) error {
	store := getBlobSidecarStore(pool)
	if store == nil || tx == nil {
		return nil
	}
	if sidecar == nil {
		sidecar = tx.BlobSidecar()
	}
	if sidecar == nil {
		return types.ErrBlobSidecarMissing
	}
	copy := sidecar.Copy()
	copyBytes := blobSidecarMemoryBytes(copy)
	store.mu.Lock()
	defer store.mu.Unlock()
	hash := tx.Hash()
	old, exists := store.sidecars[hash]
	oldBytes := blobSidecarMemoryBytes(old)
	entries := uint64(len(store.sidecars))
	if !exists {
		entries++
	}
	if entries > store.maxEntries || copyBytes > store.maxBytes || store.bytes-oldBytes > store.maxBytes-copyBytes {
		return ErrBlobSidecarStoreFull
	}
	store.sidecars[hash] = copy
	store.bytes = store.bytes - oldBytes + copyBytes
	return nil
}

func (pool *TxPool) blobSidecarTxKnown(hash common.Hash) bool {
	if pool == nil || pool.all == nil {
		return true
	}
	return pool.Get(hash) != nil
}

func (pool *TxPool) getBlobSidecar(hash common.Hash, pruneStale bool) *types.BlobTxSidecar {
	store := loadBlobSidecarStore(pool)
	if store == nil {
		return nil
	}
	store.mu.RLock()
	sidecar := store.sidecars[hash]
	store.mu.RUnlock()
	if sidecar == nil {
		return nil
	}
	if pruneStale && !pool.blobSidecarTxKnown(hash) {
		pool.RemoveBlobSidecar(hash)
		return nil
	}
	return sidecar.Copy()
}

func (pool *TxPool) GetBlobSidecar(hash common.Hash) *types.BlobTxSidecar {
	return pool.getBlobSidecar(hash, true)
}

func (pool *TxPool) HasBlobSidecar(hash common.Hash) bool {
	return pool.GetBlobSidecar(hash) != nil
}

func (pool *TxPool) RemoveBlobSidecar(hash common.Hash) {
	store := loadBlobSidecarStore(pool)
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.bytes -= blobSidecarMemoryBytes(store.sidecars[hash])
	delete(store.sidecars, hash)
}

func (pool *TxPool) PruneBlobSidecars() int {
	store := loadBlobSidecarStore(pool)
	if store == nil || pool == nil || pool.all == nil {
		return 0
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	removed := 0
	for hash := range store.sidecars {
		if pool.Get(hash) == nil {
			store.bytes -= blobSidecarMemoryBytes(store.sidecars[hash])
			delete(store.sidecars, hash)
			removed++
		}
	}
	return removed
}
