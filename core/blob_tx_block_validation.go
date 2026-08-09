package core

import (
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

// ValidateBlockBlobTransactions validates the Cancun BlobTx surface that is
// available in an execution block body. It intentionally does not require blob
// sidecars because sidecars are verified through the txpool/blob-sidecar path.
func ValidateBlockBlobTransactions(config *params.ChainConfig, header *types.Header, txs types.Transactions) error {
	if config == nil || header == nil || header.Number == nil {
		return nil
	}
	modern := config.CypheriumModernForks(header.Number, header.Time)
	maxBlobs := params.MaxBlobsPerTransaction(config, header.Time)
	blobBaseFee := params.CalcBlobBaseFeeAtTime(config, header.Time, header.ExcessBlobGas)
	for _, tx := range txs {
		if tx == nil || tx.Type() != types.BlobTxType {
			continue
		}
		if !modern.IsCancun {
			return ErrBlobTxBeforeCancun
		}
		if err := tx.ValidateBlobTx(maxBlobs, blobBaseFee); err != nil {
			return err
		}
		// ColossusX currently carries only the execution transaction in its block
		// and proposal wire formats. Until an authenticated sidecar path is wired
		// into proposal validation and full sync, fail closed instead of finalizing
		// a commitment whose blob bytes are unavailable to validators.
		return ErrBlobDAUnavailable
	}
	return nil
}

// ValidateBlockBlobBody validates the Cancun BlobTx execution block body
// surface without requiring blob sidecars. It combines blob gas accounting and
// BlobTx field validation for block import/body validation paths.
func ValidateBlockBlobBody(config *params.ChainConfig, header *types.Header, txs types.Transactions) error {
	if err := ValidateBlockBlobGas(config, header, txs); err != nil {
		return err
	}
	return ValidateBlockBlobTransactions(config, header, txs)
}
