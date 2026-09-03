package core

import (
	"errors"

	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

var ErrBlobTxBeforeCancun = errors.New("blob transaction before Cancun")

func hasBlobTransactions(txs types.Transactions) bool {
	for _, tx := range txs {
		if tx != nil && tx.Type() == types.BlobTxType {
			return true
		}
	}
	return false
}

// ValidateBlockBlobSidecars verifies the BlobTx sidecars attached to a block's
// transactions. It intentionally leaves ColossusX consensus untouched and only
// validates the Cancun execution-layer BlobTx sidecar surface.
func ValidateBlockBlobSidecars(config *params.ChainConfig, header *types.Header, txs types.Transactions, verifier types.BlobVerifier) error {
	if config == nil || header == nil || header.Number == nil {
		return nil
	}
	if !hasBlobTransactions(txs) {
		return nil
	}
	modern := config.CypheriumModernForks(header.Number, header.Time)
	if !modern.IsCancun {
		return ErrBlobTxBeforeCancun
	}
	version := types.BlobSidecarVersionForOsaka(modern.IsOsaka)
	return types.VerifyBlobSidecarsForVersion(txs, version, verifier)
}

// ValidateBlockBlobExecution validates the block-level Cancun BlobTx execution
// surface in one place: blob gas accounting plus sidecar/KZG verification. The
// verifier is only required when the block contains BlobTxs.
func ValidateBlockBlobExecution(config *params.ChainConfig, header *types.Header, txs types.Transactions, verifier types.BlobVerifier) error {
	if err := ValidateBlockBlobBody(config, header, txs); err != nil {
		return err
	}
	return ValidateBlockBlobSidecars(config, header, txs, verifier)
}
