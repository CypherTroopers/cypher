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
	blobCfg := config.ActiveBlobConfig(header.Time)
	maxBlobs := 0
	if blobCfg != nil {
		maxBlobs = blobCfg.Max
	}
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

// ValidateBlockBlobBody validates the Cancun BlobTx execution block body
// surface without requiring blob sidecars. It combines blob gas accounting and
// BlobTx field validation for block import/body validation paths.
func ValidateBlockBlobBody(config *params.ChainConfig, header *types.Header, txs types.Transactions) error {
	if err := ValidateBlockBlobGas(config, header, txs); err != nil {
		return err
	}
	return ValidateBlockBlobTransactions(config, header, txs)
}
