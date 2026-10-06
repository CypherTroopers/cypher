package ethapi

import (
	"errors"
	"math/big"

	"github.com/cypherium/cypher/core/types"
)

var errNativeTransactionsDisabled = errors.New("native transactions disabled")

func nativeTransactionsEnabled(b Backend) bool {
	return b != nil && b.ChainConfig() != nil && b.ChainConfig().NativeParallel != nil
}

// nativeTransactionsRequired is permanently false at the public RPC boundary.
// NativeTxV1 remains available only to dormant low-level test helpers; genesis
// consensus accepts canonical Ethereum transaction types 0 through 4.
func nativeTransactionsRequired(Backend) bool {
	return false
}

// requestsNativeTransaction classifies requests before defaults and signing.
// Explicit type 0x05 or native-only fields bypass Ethereum nonce/gas defaults
// only so they reach the deterministic disabled-mode rejection.
func (args *SendTxArgs) requestsNativeTransaction(b Backend) bool {
	if args == nil {
		return false
	}
	return args.hasNativeFields() || (args.Type != nil && uint64(*args.Type) == types.NativeTxType)
}

func (args *SendTxArgs) hasNativeFields() bool {
	return args.Payer != nil || args.ReplaySequence != nil || args.RecentBlockHash != nil || args.RecentBlockNumber != nil ||
		args.ValidUntil != nil || args.NativeAccesses != nil || args.MaxFeePerCompute != nil ||
		args.MaxPriorityFeePerCompute != nil || args.ComputeLimit != nil || args.MemoryLimit != nil ||
		args.LogLimit != nil || args.OutputLimit != nil
}

func (args *SendTxArgs) feeWorkForValidation() uint64 {
	if args.ComputeLimit != nil {
		return uint64(*args.ComputeLimit)
	}
	if args.Gas != nil {
		return uint64(*args.Gas)
	}
	return 0
}

func nativeTransactionInput(args *SendTxArgs) []byte {
	if args.Input != nil {
		return *args.Input
	}
	if args.Data != nil {
		return *args.Data
	}
	return nil
}

func (args *SendTxArgs) toNativeTransaction(chainID *big.Int, input []byte) *types.Transaction {
	chainIDCopy := new(big.Int)
	if chainID != nil {
		chainIDCopy.Set(chainID)
	}
	return types.NewTx(&types.NativeTxV1{
		ChainID:               chainIDCopy,
		RecentBlockHash:       *args.RecentBlockHash,
		RecentBlockNumber:     uint64(*args.RecentBlockNumber),
		ValidUntil:            uint64(*args.ValidUntil),
		Payer:                 *args.Payer,
		ReplaySequence:        uint64(*args.ReplaySequence),
		To:                    *args.To,
		Value:                 (*big.Int)(args.Value),
		Data:                  input,
		MaxFeePerCompute:      (*big.Int)(args.MaxFeePerCompute),
		PriorityFeePerCompute: (*big.Int)(args.MaxPriorityFeePerCompute),
		ComputeLimit:          uint64(*args.ComputeLimit),
		MemoryLimit:           uint64(*args.MemoryLimit),
		LogLimit:              uint64(*args.LogLimit),
		OutputLimit:           uint64(*args.OutputLimit),
		Accesses:              *args.NativeAccesses,
		V:                     new(big.Int),
		R:                     new(big.Int),
		S:                     new(big.Int),
	})
}
