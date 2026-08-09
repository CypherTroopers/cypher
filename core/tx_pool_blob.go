package core

import (
	"math/big"

	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

// validateBlobTx performs txpool-level blob transaction validation. It is kept
// separate from validateTx so the modern Cancun path can be wired in with a
// small follow-up diff without disturbing legacy transaction validation.
func (pool *TxPool) validateBlobTx(tx *types.Transaction) error {
	if tx == nil || tx.Type() != types.BlobTxType {
		return nil
	}
	var (
		maxBlobs    int
		blobBaseFee *big.Int
	)
	if pool.chain != nil {
		if head := pool.chain.CurrentBlock(); head != nil && head.Header() != nil {
			header := head.Header()
			if pool.chainconfig != nil {
				maxBlobs = params.MaxBlobsPerTransaction(pool.chainconfig, header.Time)
			}
			blobBaseFee = params.CalcBlobBaseFeeAtTime(pool.chainconfig, header.Time, header.ExcessBlobGas)
		}
	}
	if maxBlobs == 0 && pool.chainconfig != nil {
		maxBlobs = params.MaxBlobsPerTransaction(pool.chainconfig, 0)
	}
	return tx.ValidateBlobTx(maxBlobs, blobBaseFee)
}
