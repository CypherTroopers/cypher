package core

import "github.com/cypherium/cypher/core/types"

// AttachBlobSidecarsToTransactions returns a transaction list where BlobTxs have
// their sidecars attached from the txpool store. Non-blob transactions are kept
// unchanged. Missing BlobTx sidecars return ErrMissingBlobTxSidecar.
func (pool *TxPool) AttachBlobSidecarsToTransactions(txs types.Transactions) (types.Transactions, error) {
	if len(txs) == 0 {
		return nil, nil
	}
	attached := make(types.Transactions, 0, len(txs))
	for _, tx := range txs {
		if tx == nil {
			continue
		}
		if tx.Type() != types.BlobTxType {
			attached = append(attached, tx)
			continue
		}
		sidecar := pool.GetBlobSidecar(tx.Hash())
		if sidecar == nil {
			return nil, ErrMissingBlobTxSidecar
		}
		attached = append(attached, tx.WithBlobSidecar(sidecar))
	}
	if len(attached) == 0 {
		return nil, nil
	}
	return attached, nil
}
