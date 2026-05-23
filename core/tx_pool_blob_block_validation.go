package core

import (
	"errors"

	"github.com/cypherium/cypher/core/types"
)

var ErrMissingBlobSidecarForBlock = errors.New("missing blob sidecar for block blob transaction")

// ValidateBlobSidecarsForBlock validates that every BlobTx selected for a block
// has a sidecar available in the txpool sidecar store. If verifier is non-nil,
// it also runs the configured blob verifier before the block is assembled.
func (pool *TxPool) ValidateBlobSidecarsForBlock(txs types.Transactions, verifier types.BlobVerifier) error {
	for _, tx := range txs {
		if tx == nil || tx.Type() != types.BlobTxType {
			continue
		}
		sidecar := pool.GetBlobSidecar(tx.Hash())
		if sidecar == nil {
			return ErrMissingBlobSidecarForBlock
		}
		bundle := &types.BlobTxWithSidecar{Tx: tx, Sidecar: sidecar}
		if verifier != nil {
			if err := bundle.Verify(verifier); err != nil {
				return err
			}
		} else if err := bundle.Validate(); err != nil {
			return err
		}
	}
	return nil
}
