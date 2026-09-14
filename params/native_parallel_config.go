package params

import (
	"errors"
	"fmt"

	"github.com/cypherium/cypher/common"
)

const (
	// EVMParallelIngressTargetTPS is an architecture sizing target, not a claim
	// about throughput on arbitrary hardware. Consensus and node-local queues
	// retain a five-second burst at this rate so dedicated machines can measure
	// the execution ceiling without hitting a legacy count gate first.
	EVMParallelIngressTargetTPS         = 200_000
	EVMParallelIngressBurstSeconds      = 5
	EVMParallelIngressBurstTransactions = EVMParallelIngressTargetTPS * EVMParallelIngressBurstSeconds
	NativeParallelHardMaxTransactions   = 1 << 20
	// rnet's genesis-native large-data class is bounded at 257 MiB including
	// framing. Keep the consensus body ceiling at 256 MiB so every configuration
	// accepted here is actually transportable by all validators.
	NativeParallelHardMaxBlockBytes = 256 * 1024 * 1024
	NativeParallelHardMaxAccesses   = 1 << 28
	NativeParallelHardMaxMemory     = 256 * 1024 * 1024
	// The production DAG retains receipts/logs until canonical block-order
	// finalization and reserves the remainder for one COW execution microbatch.
	// Keep this genesis-committed envelope below the process-wide 2 GiB lease so
	// DAG and serial fallback modes can never diverge on a local memory bound.
	NativeParallelExecutionMemoryBudget      = 2 << 30
	NativeReceiptMemoryReservePerTransaction = 512
	// Consensus planning bounds mirror core's compact streaming dependency
	// planner. A canonical NativeAccess RLP occupies at least 59 bytes, so the
	// block byte ceiling also bounds the otherwise larger configured access cap.
	NativeMinimumEncodedAccessBytes    = 59
	NativePlanningMemoryPerAccess      = 192
	NativePlanningMemoryPerTransaction = 128
	// EIP-2935 commits this many recent ancestor hashes in consensus state.
	// Native replay anchors and BLOCKHASH resolve their exact branch through it.
	NativeReplayHistoryWindow = 8191
	// Fair HotStuff attaches a bounded descendant finality proof after proposal
	// voting. Genesis block limits must reserve both the bounded proof and its
	// RLP/list growth or proposer subtraction would underflow.
	FairHotstuffMaxFinalityProofBytes     = 1024 * 1024
	FairHotstuffFinalityProofRLPOverhead  = 16
	FairHotstuffFinalityProofReserveBytes = FairHotstuffMaxFinalityProofBytes + FairHotstuffFinalityProofRLPOverhead
)

const (
	nativeReplayRegistryPrefix = 19
)

// NativeReplayRegistryAddress is one representative of the protocol-reserved
// replay metadata range. Native manifests and targets may not access any
// address with the 19-byte 0xff prefix.
var NativeReplayRegistryAddress = NativeReplayRegistryAddressForPayer(common.Address{})

// NativeReplayRegistryAddressForPayer selects one of 256 reserved storage
// accounts by the payer's first byte. The payer's complete address remains in
// each base/bitmap storage key, so sharding never truncates replay identity.
func NativeReplayRegistryAddressForPayer(payer common.Address) common.Address {
	var address common.Address
	for index := 0; index < nativeReplayRegistryPrefix; index++ {
		address[index] = 0xff
	}
	address[nativeReplayRegistryPrefix] = payer[0]
	return address
}

func IsNativeReplayRegistryAddress(address common.Address) bool {
	for index := 0; index < nativeReplayRegistryPrefix; index++ {
		if address[index] != 0xff {
			return false
		}
	}
	return true
}

// NativeParallelConfig contains consensus limits. Local queue depths and worker
// counts are intentionally absent: validators may tune those for their hardware
// without changing block validity.
type NativeParallelConfig struct {
	// RequireNativeTransactions is retained only for dormant low-level NativeTx
	// tests. Public ChainConfig JSON rejects it and CheckConfigForkOrder rejects
	// true programmatically.
	RequireNativeTransactions    bool   `json:"requireNativeTransactions"`
	MaxTransactionsPerBlock      uint64 `json:"maxTransactionsPerBlock"`
	MaxBlockBytes                uint64 `json:"maxBlockBytes"`
	MaxTransactionBytes          uint64 `json:"maxTransactionBytes"`
	MaxAccessesPerTransaction    uint64 `json:"maxAccessesPerTransaction"`
	MaxAccessesPerBlock          uint64 `json:"maxAccessesPerBlock"`
	MaxComputePerTransaction     uint64 `json:"maxComputePerTransaction"`
	MaxComputePerBlock           uint64 `json:"maxComputePerBlock"`
	MaxCriticalPathCompute       uint64 `json:"maxCriticalPathCompute"`
	MaxDependencyDepth           uint64 `json:"maxDependencyDepth"`
	MaxMemoryBytesPerTransaction uint64 `json:"maxMemoryBytesPerTransaction"`
	MaxLogBytesPerTransaction    uint64 `json:"maxLogBytesPerTransaction"`
	MaxLogBytesPerBlock          uint64 `json:"maxLogBytesPerBlock"`
	MaxReceiptBytesPerBlock      uint64 `json:"maxReceiptBytesPerBlock"`
	MaxOutputBytesPerTransaction uint64 `json:"maxOutputBytesPerTransaction"`
	ReplayWindowBlocks           uint64 `json:"replayWindowBlocks"`
}

// SolanaScaleEVMParallelConfig returns the high-capacity EVM genesis profile.
// These values are safety ceilings rather than expected block occupancy.
// Actual admission remains bounded by compute, critical-path and node-local
// queues. Public consensus accepts Ethereum transaction types 0-4.
func SolanaScaleEVMParallelConfig() *NativeParallelConfig {
	return &NativeParallelConfig{
		RequireNativeTransactions: false,
		// One million transactions retains a five-second safety envelope at the
		// 200k TPS architecture target. Compute, bytes, receipts and dependency
		// limits remain independent consensus bounds, so complex blocks reach
		// those limits before this count ceiling.
		MaxTransactionsPerBlock:   NativeParallelHardMaxTransactions,
		MaxBlockBytes:             256 * 1024 * 1024,
		MaxTransactionBytes:       1024 * 1024,
		MaxAccessesPerTransaction: 1024,
		// This permits two observed EVM resources for every transaction at the
		// one-million-transaction ceiling, or proportionally richer access sets
		// in smaller blocks. The dependency frontier is retained for the full
		// block and remains bounded by the 2 GiB execution envelope.
		MaxAccessesPerBlock:      2 * 1024 * 1024,
		MaxComputePerTransaction: 1 << 32,
		MaxComputePerBlock:       1 << 44,
		// Independent work may consume the full block budget. A dependency
		// chain is bounded by the number of minimum-intrinsic-gas transactions
		// that fit MaxCriticalPathCompute, so a Byzantine proposal cannot hide
		// a million-entry serial nonce chain inside the aggregate envelope.
		MaxCriticalPathCompute:       1 << 28,
		MaxDependencyDepth:           (1 << 28) / TxGas,
		MaxMemoryBytesPerTransaction: 64 * 1024 * 1024,
		MaxLogBytesPerTransaction:    256 * 1024,
		MaxLogBytesPerBlock:          64 * 1024 * 1024,
		MaxReceiptBytesPerBlock:      224 * 1024 * 1024,
		MaxOutputBytesPerTransaction: 1024 * 1024,
		ReplayWindowBlocks:           512,
	}
}

// SolanaScaleNativeParallelConfig retains the internal Go API name used by the
// dormant parallel executor. It returns the same EVM-only public profile.
func SolanaScaleNativeParallelConfig() *NativeParallelConfig {
	return SolanaScaleEVMParallelConfig()
}

func (c *NativeParallelConfig) Validate() error {
	if c == nil {
		return nil
	}
	if c.RequireNativeTransactions {
		return errors.New("evmParallel supports only Ethereum transaction types 0 through 4")
	}
	if c.MaxTransactionsPerBlock == 0 || c.MaxBlockBytes == 0 || c.MaxTransactionBytes == 0 ||
		c.MaxAccessesPerTransaction == 0 || c.MaxAccessesPerBlock == 0 ||
		c.MaxComputePerTransaction == 0 || c.MaxComputePerBlock == 0 || c.MaxCriticalPathCompute == 0 || c.MaxDependencyDepth == 0 ||
		c.MaxMemoryBytesPerTransaction == 0 || c.MaxLogBytesPerTransaction == 0 || c.MaxLogBytesPerBlock == 0 || c.MaxReceiptBytesPerBlock == 0 || c.MaxOutputBytesPerTransaction == 0 ||
		c.ReplayWindowBlocks == 0 {
		return errors.New("native parallel limits must all be non-zero")
	}
	if c.MaxTransactionBytes > c.MaxBlockBytes {
		return errors.New("native transaction byte limit exceeds block byte limit")
	}
	if c.MaxBlockBytes <= FairHotstuffFinalityProofReserveBytes {
		return fmt.Errorf("native block byte limit %d does not exceed Fair HotStuff finality-proof reserve %d", c.MaxBlockBytes, FairHotstuffFinalityProofReserveBytes)
	}
	if c.MaxAccessesPerTransaction > c.MaxAccessesPerBlock {
		return errors.New("native transaction access limit exceeds block access limit")
	}
	if c.MaxComputePerTransaction > c.MaxComputePerBlock {
		return errors.New("native transaction compute limit exceeds block compute limit")
	}
	if c.MaxCriticalPathCompute > c.MaxComputePerBlock {
		return errors.New("native critical-path compute exceeds block compute limit")
	}
	if c.MaxDependencyDepth > c.MaxTransactionsPerBlock {
		return errors.New("native dependency depth exceeds block transaction limit")
	}
	if c.MaxDependencyDepth > c.MaxCriticalPathCompute/TxGas {
		return errors.New("EVM dependency depth exceeds the minimum-gas critical-path limit")
	}
	if c.MaxLogBytesPerTransaction > c.MaxLogBytesPerBlock {
		return errors.New("native transaction log byte limit exceeds block log byte limit")
	}
	if c.MaxLogBytesPerBlock > c.MaxReceiptBytesPerBlock {
		return errors.New("native block log byte limit exceeds receipt byte limit")
	}
	if c.MaxReceiptBytesPerBlock > NativeParallelHardMaxBlockBytes {
		return fmt.Errorf("native receipt byte limit %d exceeds transportable maximum %d", c.MaxReceiptBytesPerBlock, NativeParallelHardMaxBlockBytes)
	}
	if c.MaxMemoryBytesPerTransaction > NativeParallelHardMaxMemory {
		return fmt.Errorf("native transaction memory limit %d exceeds implementation maximum %d", c.MaxMemoryBytesPerTransaction, NativeParallelHardMaxMemory)
	}
	if c.ReplayWindowBlocks > NativeReplayHistoryWindow {
		return fmt.Errorf("native replay window %d exceeds state-rooted history window %d", c.ReplayWindowBlocks, NativeReplayHistoryWindow)
	}
	if c.MaxTransactionsPerBlock > NativeParallelHardMaxTransactions {
		return fmt.Errorf("native transaction limit %d exceeds implementation maximum %d", c.MaxTransactionsPerBlock, NativeParallelHardMaxTransactions)
	}
	if c.MaxBlockBytes > NativeParallelHardMaxBlockBytes {
		return fmt.Errorf("native block byte limit %d exceeds implementation maximum %d", c.MaxBlockBytes, NativeParallelHardMaxBlockBytes)
	}
	if c.MaxAccessesPerBlock > NativeParallelHardMaxAccesses {
		return fmt.Errorf("native block access limit %d exceeds implementation maximum %d", c.MaxAccessesPerBlock, NativeParallelHardMaxAccesses)
	}
	effectiveAccesses := c.MaxAccessesPerBlock
	if effectiveAccesses > ^uint64(0)/NativePlanningMemoryPerAccess {
		return errors.New("native dependency planning memory overflows uint64")
	}
	planningMemory := effectiveAccesses * NativePlanningMemoryPerAccess
	if c.MaxTransactionsPerBlock > (^uint64(0)-planningMemory)/NativePlanningMemoryPerTransaction {
		return errors.New("native dependency transaction planning memory overflows uint64")
	}
	planningMemory += c.MaxTransactionsPerBlock * NativePlanningMemoryPerTransaction
	if planningMemory >= NativeParallelExecutionMemoryBudget {
		return fmt.Errorf("native dependency planning memory %d exceeds budget %d", planningMemory, NativeParallelExecutionMemoryBudget)
	}
	receiptReserve := c.MaxTransactionsPerBlock * NativeReceiptMemoryReservePerTransaction
	if c.MaxTransactionsPerBlock != 0 && receiptReserve/c.MaxTransactionsPerBlock != NativeReceiptMemoryReservePerTransaction {
		return errors.New("native retained receipt memory overflows uint64")
	}
	if receiptReserve >= NativeParallelExecutionMemoryBudget || c.MaxLogBytesPerBlock >= NativeParallelExecutionMemoryBudget-receiptReserve {
		return fmt.Errorf("native retained receipt/log memory %d+%d must remain below execution budget %d", receiptReserve, c.MaxLogBytesPerBlock, NativeParallelExecutionMemoryBudget)
	}
	retainedMemory := receiptReserve + c.MaxLogBytesPerBlock
	if planningMemory >= NativeParallelExecutionMemoryBudget-retainedMemory {
		return fmt.Errorf("combined dependency and retained result memory %d+%d must remain below execution budget %d", planningMemory, retainedMemory, NativeParallelExecutionMemoryBudget)
	}
	return nil
}

func (c *ChainConfig) NativeParallelEnabled() bool {
	return c != nil && c.NativeParallel != nil
}

// validateEVMParallelBlobMemory rejects a DA schedule whose defensive sidecar
// copies can consume the complete process execution budget by themselves.
// Block construction, immutable accessors, validation and proposal transport
// currently retain several copies; reserving at most 1/16 of the process
// envelope for the raw sidecar leaves headroom for those copies, EVM state,
// receipts and the encoded block body.
func (c *ChainConfig) validateEVMParallelBlobMemory() error {
	if !c.NativeParallelEnabled() {
		return nil
	}
	modern := c.ModernForkConfig()
	if modern == nil || modern.BlobSchedule == nil {
		return nil
	}
	limit := uint64(NativeParallelExecutionMemoryBudget / 16)
	if blockShare := c.NativeParallel.MaxBlockBytes / 4; blockShare < limit {
		limit = blockShare
	}
	for _, fork := range []struct {
		name          string
		config        *BlobConfig
		proofsPerBlob uint64
	}{
		{name: "cancun", config: modern.BlobSchedule.Cancun, proofsPerBlob: 1},
		{name: "prague", config: modern.BlobSchedule.Prague, proofsPerBlob: 1},
		{name: "osaka", config: modern.BlobSchedule.Osaka, proofsPerBlob: 128},
		{name: "bpo1", config: modern.BlobSchedule.BPO1, proofsPerBlob: 128},
		{name: "bpo2", config: modern.BlobSchedule.BPO2, proofsPerBlob: 128},
		{name: "bpo3", config: modern.BlobSchedule.BPO3, proofsPerBlob: 128},
		{name: "bpo4", config: modern.BlobSchedule.BPO4, proofsPerBlob: 128},
		{name: "bpo5", config: modern.BlobSchedule.BPO5, proofsPerBlob: 128},
	} {
		if fork.config == nil || fork.config.Max <= 0 {
			continue
		}
		// Every sidecar retains one 48-byte commitment per blob. Cancun and
		// Prague add one whole-blob proof; Osaka adds 128 EIP-7594 cell proofs.
		perBlob := BlobTxBlobBytes + 48 + 48*fork.proofsPerBlob
		if uint64(fork.config.Max) > limit/perBlob {
			return fmt.Errorf("%s blob schedule sidecar bytes exceed EVM parallel memory allowance %d", fork.name, limit)
		}
	}
	return nil
}

func (c *ChainConfig) EffectiveMaxBlockBytes() uint64 {
	if c.NativeParallelEnabled() {
		return c.NativeParallel.MaxBlockBytes
	}
	return MaxBlockSize
}

func (c *ChainConfig) EffectiveMaxTransactionBytes() uint64 {
	if c.NativeParallelEnabled() {
		return c.NativeParallel.MaxTransactionBytes
	}
	limitKiB := c.TransactionSizeLimit
	if limitKiB == 0 {
		limitKiB = 64
	}
	return limitKiB * 1024
}
