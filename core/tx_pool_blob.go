package core

import (
	"math/big"

	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

func (pool *TxPool) activeBlobSidecarVersion() byte {
	if pool == nil || pool.chainconfig == nil {
		return types.BlobSidecarVersion0
	}
	var number = new(big.Int)
	var timestamp uint64
	if pool.chain != nil {
		if head := pool.chain.CurrentBlock(); head != nil && head.Header() != nil {
			number = head.Number()
			timestamp = head.Time()
		}
	}
	return types.BlobSidecarVersionForOsaka(pool.chainconfig.IsOsaka(number, timestamp))
}

// ActiveBlobSidecarVersion exposes the fork-bound pooled sidecar format to
// authenticated ingress transports. It is derived from the same chain head
// used by TxPool admission.
func (pool *TxPool) ActiveBlobSidecarVersion() byte {
	return pool.activeBlobSidecarVersion()
}

// validateBlobTxEnvelope performs the inexpensive EIP-4844 execution-envelope
// checks before the KZG backend is invoked.
func (pool *TxPool) validateBlobTxEnvelope(tx *types.Transaction) error {
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

// validateBlobTx is the txpool admission gate for type-3 transactions. A bare
// signed execution envelope is insufficient: the complete sidecar must be
// attached and its proof must verify against the real KZG implementation.
func (pool *TxPool) validateBlobTx(tx *types.Transaction) error {
	if err := pool.validateBlobTxEnvelope(tx); err != nil {
		return err
	}
	if tx == nil || tx.Type() != types.BlobTxType {
		return nil
	}
	return tx.VerifyBlobSidecarVersion(tx.BlobSidecar(), pool.activeBlobSidecarVersion(), types.KZGBlobVerifier{})
}
