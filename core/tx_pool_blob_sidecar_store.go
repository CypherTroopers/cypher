package core

import (
	"sync"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

type blobSidecarStore struct {
	mu       sync.RWMutex
	sidecars map[common.Hash]*types.BlobTxSidecar
}

var blobSidecarStores sync.Map

func getBlobSidecarStore(pool *TxPool) *blobSidecarStore {
	if pool == nil {
		return nil
	}
	if store, ok := blobSidecarStores.Load(pool); ok {
		return store.(*blobSidecarStore)
	}
	store := &blobSidecarStore{sidecars: make(map[common.Hash]*types.BlobTxSidecar)}
	actual, _ := blobSidecarStores.LoadOrStore(pool, store)
	return actual.(*blobSidecarStore)
}

func (pool *TxPool) storeBlobSidecar(tx *types.Transaction, sidecar *types.BlobTxSidecar) {
	store := getBlobSidecarStore(pool)
	if store == nil || tx == nil {
		return
	}
	if sidecar == nil {
		sidecar = tx.BlobSidecar()
	}
	if sidecar == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.sidecars[tx.Hash()] = sidecar
}

func (pool *TxPool) blobSidecarTxKnown(hash common.Hash) bool {
	if pool == nil || pool.all == nil {
		return true
	}
	return pool.Get(hash) != nil
}

func (pool *TxPool) getBlobSidecar(hash common.Hash, pruneStale bool) *types.BlobTxSidecar {
	store := getBlobSidecarStore(pool)
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
	return sidecar
}

func (pool *TxPool) GetBlobSidecar(hash common.Hash) *types.BlobTxSidecar {
	return pool.getBlobSidecar(hash, true)
}

func (pool *TxPool) HasBlobSidecar(hash common.Hash) bool {
	return pool.GetBlobSidecar(hash) != nil
}

func (pool *TxPool) RemoveBlobSidecar(hash common.Hash) {
	store := getBlobSidecarStore(pool)
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.sidecars, hash)
}

func (pool *TxPool) PruneBlobSidecars() int {
	store := getBlobSidecarStore(pool)
	if store == nil || pool == nil || pool.all == nil {
		return 0
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	removed := 0
	for hash := range store.sidecars {
		if pool.Get(hash) == nil {
			delete(store.sidecars, hash)
			removed++
		}
	}
	return removed
}
