package core

import (
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

// BlobSidecarsForTransactions returns the sidecars required by the supplied transactions.
// Non-blob transactions are ignored. Blob transactions without sidecars return
// ErrMissingBlobTxSidecar so callers can avoid building invalid Cancun blocks.
func (pool *TxPool) BlobSidecarsForTransactions(txs types.Transactions) (map[common.Hash]*types.BlobTxSidecar, error) {
	if len(txs) == 0 {
		return nil, nil
	}
	sidecars := make(map[common.Hash]*types.BlobTxSidecar)
	for _, tx := range txs {
		if tx == nil || tx.Type() != types.BlobTxType {
			continue
		}
		hash := tx.Hash()
		sidecar := pool.GetBlobSidecar(hash)
		if sidecar == nil {
			return nil, ErrMissingBlobTxSidecar
		}
		sidecars[hash] = sidecar
	}
	if len(sidecars) == 0 {
		return nil, nil
	}
	return sidecars, nil
}

// BlobBundlesForTransactions returns tx+sidecar bundles for blob transactions.
// The tx pointer is the original transaction from the supplied list, while the
// sidecar is fetched from the txpool store.
func (pool *TxPool) BlobBundlesForTransactions(txs types.Transactions) ([]*types.BlobTxWithSidecar, error) {
	if len(txs) == 0 {
		return nil, nil
	}
	bundles := make([]*types.BlobTxWithSidecar, 0)
	for _, tx := range txs {
		if tx == nil || tx.Type() != types.BlobTxType {
			continue
		}
		sidecar := pool.GetBlobSidecar(tx.Hash())
		if sidecar == nil {
			return nil, ErrMissingBlobTxSidecar
		}
		bundle, err := types.NewBlobTxWithSidecar(tx, sidecar)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, bundle)
	}
	if len(bundles) == 0 {
		return nil, nil
	}
	return bundles, nil
}
