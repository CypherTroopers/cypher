package core

import (
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

// ValidateBlockBlobTransactions validates every EIP-4844 execution envelope in
// a block. Data availability is checked separately by
// ValidateBlockBlobSidecars; keeping the two phases explicit lets callers run
// cheap field and fee checks before invoking the KZG backend.
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
	}
	return nil
}

// ValidateBlockBlobBody performs the inexpensive EIP-4844 execution-envelope
// checks. Consensus/import paths must additionally call
// ValidateBlockBlobExecution so a block cannot be accepted without its data.
func ValidateBlockBlobBody(config *params.ChainConfig, header *types.Header, txs types.Transactions) error {
	if err := ValidateBlockBlobGas(config, header, txs); err != nil {
		return err
	}
	return ValidateBlockBlobTransactions(config, header, txs)
}
