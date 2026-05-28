package core

import (
	"errors"

	"github.com/cypherium/cypher/core/types"
)

var ErrMissingBlobTxSidecar = errors.New("missing blob transaction sidecar")

func (pool *TxPool) ValidateBlobSidecarsForTransactions(txs types.Transactions) error {
	for _, tx := range txs {
		if tx == nil || tx.Type() != types.BlobTxType {
			continue
		}
		if pool.GetBlobSidecar(tx.Hash()) == nil {
			return ErrMissingBlobTxSidecar
		}
	}
	return nil
}

func (pool *TxPool) FilterTransactionsWithBlobSidecars(txs types.Transactions) types.Transactions {
	if len(txs) == 0 {
		return nil
	}
	filtered := make(types.Transactions, 0, len(txs))
	for _, tx := range txs {
		if tx == nil {
			continue
		}
		if tx.Type() == types.BlobTxType && pool.GetBlobSidecar(tx.Hash()) == nil {
			continue
		}
		filtered = append(filtered, tx)
	}
	return filtered
}
