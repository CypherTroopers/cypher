package core

import (
	"errors"
	"fmt"

	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

// NativeParallelBlockMode is the consensus execution lane selected by the
// genesis-native protocol for one block.
type NativeParallelBlockMode uint8

const (
	NativeParallelBlockModeNone NativeParallelBlockMode = iota
	NativeParallelBlockModeNative
	NativeParallelBlockModeEVM
)

var ErrNativeParallelLaneMismatch = errors.New("native parallel transaction lane mismatch")

// validateNativeTransactionTypeExecutionMode is the final low-level execution
// guard for NativeTxV1. Public RPC, TxPool and block-mode validation reject the
// same mismatch earlier, but direct state-transition and executor callers must
// not be able to bypass the genesis-committed EVM-only mode.
func validateNativeTransactionTypeExecutionMode(config *params.ChainConfig, txType uint8) error {
	if txType != types.NativeTxType {
		return nil
	}
	return ErrNativeTxDisabled
}

func validateNativeTransactionExecutionMode(config *params.ChainConfig, tx *types.Transaction) error {
	if tx == nil {
		return nil
	}
	return validateNativeTransactionTypeExecutionMode(config, tx.Type())
}

// NativeParallelBlockModeForType maps both transaction block lanes to canonical
// Ethereum transactions. NativeTxV1 is not part of the public consensus schema,
// even if an invalid in-memory config tries to set the retired strict flag.
func NativeParallelBlockModeForType(config *params.ChainConfig, blockType uint8) (NativeParallelBlockMode, error) {
	if config == nil || !config.NativeParallelEnabled() {
		return NativeParallelBlockModeEVM, nil
	}
	switch blockType {
	case types.Key_Block:
		return NativeParallelBlockModeNone, nil
	case types.FastTx_Block, types.SlowTx_Block:
		return NativeParallelBlockModeEVM, nil
	default:
		return NativeParallelBlockModeNone, fmt.Errorf("%w: unsupported block type %d", ErrNativeParallelLaneMismatch, blockType)
	}
}

// ValidateNativeParallelBlockMode rejects mixed transaction formats and any
// transaction placed in the wrong consensus lane. It deliberately does not
// constrain transaction types on non-native networks.
func ValidateNativeParallelBlockMode(config *params.ChainConfig, blockType uint8, transactions types.Transactions) (NativeParallelBlockMode, error) {
	mode, err := NativeParallelBlockModeForType(config, blockType)
	if err != nil {
		return mode, err
	}
	if config == nil || !config.NativeParallelEnabled() {
		return mode, nil
	}
	if mode == NativeParallelBlockModeNone {
		if len(transactions) != 0 {
			return mode, fmt.Errorf("%w: key block contains %d transactions", ErrNativeParallelLaneMismatch, len(transactions))
		}
		return mode, nil
	}
	for index, transaction := range transactions {
		if transaction == nil || !transaction.IsInitialized() {
			return mode, fmt.Errorf("%w: nil or uninitialized transaction at index %d", ErrNativeParallelLaneMismatch, index)
		}
		if transaction.Type() > types.SetCodeTxType {
			return mode, fmt.Errorf("%w: transaction %d unsupported type %#x in standard EVM lane", ErrNativeParallelLaneMismatch, index, transaction.Type())
		}
		isNative := transaction.Type() == types.NativeTxType
		switch mode {
		case NativeParallelBlockModeNative:
			if !isNative {
				return mode, fmt.Errorf("%w: transaction %d type %#x in NativeTxV1 lane", ErrNativeParallelLaneMismatch, index, transaction.Type())
			}
		case NativeParallelBlockModeEVM:
			if isNative {
				return mode, fmt.Errorf("%w: transaction %d NativeTxV1 in standard EVM lane", ErrNativeParallelLaneMismatch, index)
			}
			if size := uint64(transaction.Size()); size > config.NativeParallel.MaxTransactionBytes {
				return mode, fmt.Errorf("standard EVM transaction %d encoded size %d exceeds maximum %d", index, size, config.NativeParallel.MaxTransactionBytes)
			}
		}
	}
	return mode, nil
}
