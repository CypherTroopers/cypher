package ethapi

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rpc"
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

func (args *SendTxArgs) setNativeDefaults(ctx context.Context, b Backend) error {
	if !nativeTransactionsRequired(b) {
		return errNativeTransactionsDisabled
	}
	config := b.ChainConfig()
	native := config.NativeParallel
	if err := native.Validate(); err != nil {
		return fmt.Errorf("invalid native parallel configuration: %w", err)
	}
	if config.ChainID == nil {
		return errors.New("native transaction chain ID is unavailable")
	}
	if args.Type == nil {
		txType := hexutil.Uint64(types.NativeTxType)
		args.Type = &txType
	} else if uint64(*args.Type) != types.NativeTxType {
		return fmt.Errorf("genesis-native chain requires transaction type %#x", types.NativeTxType)
	}

	// NativeTxV1 has one unambiguous field set. Accepting legacy aliases would
	// let clients believe they signed a value that is not present in the native
	// envelope.
	switch {
	case args.Nonce != nil:
		return errors.New("native transaction does not support nonce")
	case args.Gas != nil:
		return errors.New("native transaction uses computeLimit, not gas")
	case args.GasPrice != nil:
		return errors.New("native transaction uses compute fee fields, not gasPrice")
	case args.MaxFeePerGas != nil || args.MaxPriorityFeePerGas != nil:
		return errors.New("native transaction uses compute fee fields, not EIP-1559 gas fee aliases")
	case args.AccessList != nil:
		return errors.New("native transaction uses accesses, not accessList")
	case args.MaxFeePerBlobGas != nil || args.BlobVersionedHashes != nil || args.hasBlobSidecarFields():
		return errors.New("native transaction cannot contain blob fields")
	case args.AuthorizationList != nil:
		return errors.New("native transaction cannot contain authorizationList")
	}

	if args.Payer == nil {
		return errors.New("native transaction requires payer")
	}
	if *args.Payer != args.From {
		return errors.New("native transaction payer must equal from")
	}
	if args.ReplaySequence == nil {
		return errors.New("native transaction requires replaySequence")
	}
	if args.To == nil {
		return errors.New("native transaction requires an execution target")
	}
	if params.IsNativeReplayRegistryAddress(*args.To) {
		return errors.New("native transaction cannot target the reserved replay registry")
	}
	if args.RecentBlockHash == nil || *args.RecentBlockHash == (common.Hash{}) {
		return errors.New("native transaction requires a non-zero recentBlockHash")
	}
	if args.RecentBlockNumber == nil {
		return errors.New("native transaction requires recentBlockNumber")
	}
	if args.ValidUntil == nil {
		return errors.New("native transaction requires validUntil")
	}
	if args.NativeAccesses == nil {
		return errors.New("native transaction requires accesses")
	}
	if args.MaxFeePerCompute == nil || args.MaxPriorityFeePerCompute == nil {
		return errors.New("native transaction requires maxFeePerCompute and maxPriorityFeePerCompute")
	}
	if args.ComputeLimit == nil || args.MemoryLimit == nil || args.LogLimit == nil || args.OutputLimit == nil {
		return errors.New("native transaction requires computeLimit, memoryLimit, logLimit and outputLimit")
	}

	if uint64(len(*args.NativeAccesses)) > native.MaxAccessesPerTransaction {
		return fmt.Errorf("native transaction accesses %d exceed maximum %d", len(*args.NativeAccesses), native.MaxAccessesPerTransaction)
	}
	for _, access := range *args.NativeAccesses {
		if params.IsNativeReplayRegistryAddress(access.Resource.Address) {
			return errors.New("native transaction accesses the reserved replay registry")
		}
	}
	computeLimit := uint64(*args.ComputeLimit)
	memoryLimit := uint64(*args.MemoryLimit)
	logLimit := uint64(*args.LogLimit)
	outputLimit := uint64(*args.OutputLimit)
	if computeLimit == 0 || computeLimit > native.MaxComputePerTransaction {
		return fmt.Errorf("native computeLimit %d exceeds range 1..%d", computeLimit, native.MaxComputePerTransaction)
	}
	if memoryLimit == 0 || memoryLimit > native.MaxMemoryBytesPerTransaction {
		return fmt.Errorf("native memoryLimit %d exceeds range 1..%d", memoryLimit, native.MaxMemoryBytesPerTransaction)
	}
	if logLimit == 0 || logLimit > native.MaxLogBytesPerTransaction {
		return fmt.Errorf("native logLimit %d exceeds range 1..%d", logLimit, native.MaxLogBytesPerTransaction)
	}
	if outputLimit == 0 || outputLimit > native.MaxOutputBytesPerTransaction {
		return fmt.Errorf("native outputLimit %d exceeds range 1..%d", outputLimit, native.MaxOutputBytesPerTransaction)
	}
	maxFee := args.MaxFeePerCompute.ToInt()
	priorityFee := args.MaxPriorityFeePerCompute.ToInt()
	if maxFee.Sign() < 0 || priorityFee.Sign() < 0 {
		return errors.New("native compute fees cannot be negative")
	}
	if priorityFee.Cmp(maxFee) > 0 {
		return errors.New("maxFeePerCompute must be greater than or equal to maxPriorityFeePerCompute")
	}

	current := b.CurrentBlock()
	if current == nil {
		return errors.New("current block is unavailable for native replay validation")
	}
	head := current.Header()
	if head == nil || head.Number == nil || !head.Number.IsUint64() {
		return errors.New("current block number exceeds native replay range")
	}
	headNumber := head.Number.Uint64()
	if headNumber == math.MaxUint64 {
		return errors.New("current block number overflows next native proposal")
	}
	recentNumber := uint64(*args.RecentBlockNumber)
	validUntil := uint64(*args.ValidUntil)
	if recentNumber > math.MaxInt64 {
		return errors.New("recentBlockNumber exceeds RPC block-number range")
	}
	if recentNumber > headNumber {
		return fmt.Errorf("recentBlockNumber %d is ahead of canonical head %d", recentNumber, headNumber)
	}
	if headNumber-recentNumber >= native.ReplayWindowBlocks {
		return fmt.Errorf("recentBlockNumber %d is outside replay window %d at head %d", recentNumber, native.ReplayWindowBlocks, headNumber)
	}
	if validUntil <= headNumber {
		return fmt.Errorf("native transaction expires at %d before next block %d", validUntil, headNumber+1)
	}
	if validUntil < recentNumber || validUntil-recentNumber > native.ReplayWindowBlocks {
		return fmt.Errorf("native validity span exceeds replay window %d", native.ReplayWindowBlocks)
	}
	anchor, err := b.HeaderByNumber(ctx, rpc.BlockNumber(recentNumber))
	if err != nil {
		return fmt.Errorf("native replay anchor %d is unavailable: %w", recentNumber, err)
	}
	if anchor == nil || anchor.Hash() != *args.RecentBlockHash {
		return fmt.Errorf("recent block %d/%s is not canonical", recentNumber, args.RecentBlockHash.Hex())
	}
	if head.BaseFee != nil && maxFee.Cmp(head.BaseFee) < 0 {
		return errors.New("maxFeePerCompute is lower than current base fee")
	}

	tx := args.toNativeTransaction(config.ChainID, nativeTransactionInput(args))
	if err := tx.ValidateNativeManifest(); err != nil {
		return fmt.Errorf("native transaction manifest: %w", err)
	}
	nextNumber := new(big.Int).Add(head.Number, big.NewInt(1))
	rules := config.CypheriumRules(nextNumber, head.Time)
	intrinsic, err := core.IntrinsicGasWithRulesAndAuthorizations(tx.Data(), tx.AccessList(), nil, false, rules)
	if err != nil {
		return fmt.Errorf("native intrinsic compute: %w", err)
	}
	if computeLimit < intrinsic {
		return fmt.Errorf("native computeLimit %d is below intrinsic compute %d", computeLimit, intrinsic)
	}
	// Account for the largest secp256k1 signature encoding before asking the
	// wallet to sign. Otherwise an unsigned payload at the byte ceiling can pass
	// RPC validation and become oversized solely when V/R/S are attached.
	placeholderSignature := make([]byte, crypto.SignatureLength)
	placeholderSignature[0] = 1
	placeholderSignature[32] = 1
	placeholderSignature[64] = 1
	signedShape, err := tx.WithSignature(types.NewNativeSigner(config.ChainID), placeholderSignature)
	if err != nil {
		return err
	}
	wire, err := signedShape.MarshalBinary()
	if err != nil {
		return err
	}
	if uint64(len(wire)) > native.MaxTransactionBytes {
		return fmt.Errorf("native transaction bytes %d exceed maximum %d", len(wire), native.MaxTransactionBytes)
	}
	return nil
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
