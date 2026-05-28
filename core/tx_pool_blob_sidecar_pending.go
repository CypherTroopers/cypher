package core

import (
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

// PendingWithBlobSidecars returns pending transactions after dropping BlobTxs
// whose sidecar is not available in the txpool sidecar store.
func (pool *TxPool) PendingWithBlobSidecars() (map[common.Address]types.Transactions, error) {
	pending, err := pool.Pending()
	if err != nil {
		return nil, err
	}
	filtered := make(map[common.Address]types.Transactions, len(pending))
	for addr, txs := range pending {
		keep := pool.FilterTransactionsWithBlobSidecars(txs)
		if len(keep) > 0 {
			filtered[addr] = keep
		}
	}
	return filtered, nil
}

// ContentWithBlobSidecars returns pending and queued transactions after dropping
// BlobTxs whose sidecar is not available in the txpool sidecar store.
func (pool *TxPool) ContentWithBlobSidecars() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	pending, queued := pool.Content()
	filteredPending := make(map[common.Address]types.Transactions, len(pending))
	for addr, txs := range pending {
		keep := pool.FilterTransactionsWithBlobSidecars(txs)
		if len(keep) > 0 {
			filteredPending[addr] = keep
		}
	}
	filteredQueued := make(map[common.Address]types.Transactions, len(queued))
	for addr, txs := range queued {
		keep := pool.FilterTransactionsWithBlobSidecars(txs)
		if len(keep) > 0 {
			filteredQueued[addr] = keep
		}
	}
	return filteredPending, filteredQueued
}
