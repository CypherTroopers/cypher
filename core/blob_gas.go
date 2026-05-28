package core

import (
	"errors"
	"fmt"

	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

var (
	ErrBlobGasUsedMismatch   = errors.New("blob gas used mismatch")
	ErrBlobGasUsedOverflow   = errors.New("blob gas used exceeds max blob gas per block")
	ErrExcessBlobGasMismatch = errors.New("excess blob gas mismatch")
)

// CalcBlobGasUsed returns the total EIP-4844 blob gas consumed by a block's
// transactions. Non-blob transactions contribute zero.
func CalcBlobGasUsed(txs types.Transactions) uint64 {
	var used uint64
	for _, tx := range txs {
		used += tx.BlobGas()
	}
	return used
}

// ValidateBlockBlobGas is a block-level scaffold for Cancun blob gas accounting.
// It validates header.BlobGasUsed against the transactions without changing
// ColossusX sealing or header verification flow.
func ValidateBlockBlobGas(config *params.ChainConfig, header *types.Header, txs types.Transactions) error {
	if config == nil || header == nil || header.Number == nil {
		return nil
	}
	modern := config.CypheriumModernForks(header.Number, header.Time)
	calculated := CalcBlobGasUsed(txs)
	if !modern.IsCancun {
		if calculated != 0 {
			return fmt.Errorf("%w: blob tx before Cancun", ErrBlobGasUsedMismatch)
		}
		if header.BlobGasUsed != 0 {
			return fmt.Errorf("%w: have %d want 0", ErrBlobGasUsedMismatch, header.BlobGasUsed)
		}
		return nil
	}
	if calculated != header.BlobGasUsed {
		return fmt.Errorf("%w: have %d want %d", ErrBlobGasUsedMismatch, header.BlobGasUsed, calculated)
	}
	blobCfg := config.ActiveBlobConfig(header.Time)
	maxBlobGas := params.MaxBlobGasPerBlock(blobCfg)
	if header.BlobGasUsed > maxBlobGas {
		return fmt.Errorf("%w: have %d max %d", ErrBlobGasUsedOverflow, header.BlobGasUsed, maxBlobGas)
	}
	return nil
}

// ValidateExcessBlobGas validates the child header's ExcessBlobGas against the
// parent header. This is intentionally independent from ColossusX sealing and
// only checks the modern EVM/Cancun accounting surface.
func ValidateExcessBlobGas(config *params.ChainConfig, parent, header *types.Header) error {
	if config == nil || parent == nil || header == nil || header.Number == nil {
		return nil
	}
	modern := config.CypheriumModernForks(header.Number, header.Time)
	if !modern.IsCancun {
		if header.ExcessBlobGas != 0 {
			return fmt.Errorf("%w: have %d want 0 before Cancun", ErrExcessBlobGasMismatch, header.ExcessBlobGas)
		}
		return nil
	}
	blobCfg := config.ActiveBlobConfig(header.Time)
	expected := params.CalcExcessBlobGas(parent.ExcessBlobGas, parent.BlobGasUsed, blobCfg)
	if header.ExcessBlobGas != expected {
		return fmt.Errorf("%w: have %d want %d", ErrExcessBlobGasMismatch, header.ExcessBlobGas, expected)
	}
	return nil
}
