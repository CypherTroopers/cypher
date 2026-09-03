package params

import (
	"math/big"
	"math/bits"
)

const (
	BlobTxBlobGasPerBlob uint64 = 1 << 17
	BlobTxBlobBytes      uint64 = 1 << 17
	BlobTxMaxBlobs              = 6 // EIP-7594/Osaka per-transaction limit.
	MinBlobGasPrice      uint64 = 1
	BlobBaseCost         uint64 = 1 << 13 // EIP-7918 calldata-equivalent execution gas per blob.
)

var (
	minBlobGasPriceBig = new(big.Int).SetUint64(MinBlobGasPrice)
	// Blob fee caps and the BLOBBASEFEE opcode are uint256 values. One past
	// their representable range is a useful saturation sentinel: it rejects
	// every possible transaction fee cap while the opcode safely returns all
	// ones. Bounding the series also prevents malformed near-uint64 excess gas
	// from forcing trillions of FakeExponential iterations.
	maxBlobBaseFeeSentinel = new(big.Int).Lsh(big.NewInt(1), 256)
)

func (c *ChainConfig) ActiveBlobConfig(timestamp uint64) *BlobConfig {
	cfg := c.ModernForkConfig()
	if cfg == nil || cfg.BlobSchedule == nil {
		return DefaultCancunBlobConfig()
	}
	for _, fork := range []struct {
		at     *uint64
		config *BlobConfig
	}{
		{at: cfg.BPO5Time, config: cfg.BlobSchedule.BPO5},
		{at: cfg.BPO4Time, config: cfg.BlobSchedule.BPO4},
		{at: cfg.BPO3Time, config: cfg.BlobSchedule.BPO3},
		{at: cfg.BPO2Time, config: cfg.BlobSchedule.BPO2},
		{at: cfg.BPO1Time, config: cfg.BlobSchedule.BPO1},
	} {
		if isTimestampForked(fork.at, timestamp) && fork.config != nil {
			return fork.config
		}
	}
	if isTimestampForked(cfg.OsakaTime, timestamp) && cfg.BlobSchedule.Osaka != nil {
		return cfg.BlobSchedule.Osaka
	}
	if isTimestampForked(cfg.PragueTime, timestamp) && cfg.BlobSchedule.Prague != nil {
		return cfg.BlobSchedule.Prague
	}
	if isTimestampForked(cfg.CancunTime, timestamp) && cfg.BlobSchedule.Cancun != nil {
		return cfg.BlobSchedule.Cancun
	}
	return DefaultCancunBlobConfig()
}

func DefaultCancunBlobConfig() *BlobConfig {
	return &BlobConfig{Target: 3, Max: 6, BaseFeeUpdateFraction: 3338477}
}

func MaxBlobGasPerBlock(blobCfg *BlobConfig) uint64 {
	if blobCfg == nil || blobCfg.Max <= 0 {
		blobCfg = DefaultCancunBlobConfig()
	}
	return blobGasForCount(blobCfg.Max)
}

// MaxBlobsPerTransaction returns the fork-specific transaction limit. Before
// Osaka a transaction may consume the active block limit; Osaka separates the
// per-transaction cap (6) from the larger block-wide blob target/maximum.
func MaxBlobsPerTransaction(config *ChainConfig, timestamp uint64) int {
	maxBlobs := DefaultCancunBlobConfig().Max
	if config != nil {
		maxBlobs = config.ActiveBlobConfig(timestamp).Max
		modern := config.ModernForkConfig()
		if modern != nil && isTimestampForked(modern.OsakaTime, timestamp) && (maxBlobs == 0 || maxBlobs > BlobTxMaxBlobs) {
			maxBlobs = BlobTxMaxBlobs
		}
	}
	return maxBlobs
}

func TargetBlobGasPerBlock(blobCfg *BlobConfig) uint64 {
	if blobCfg == nil || blobCfg.Target <= 0 {
		blobCfg = DefaultCancunBlobConfig()
	}
	return blobGasForCount(blobCfg.Target)
}

func blobGasForCount(count int) uint64 {
	if count <= 0 {
		return 0
	}
	value := uint64(count)
	if value > ^uint64(0)/BlobTxBlobGasPerBlob {
		return ^uint64(0)
	}
	return value * BlobTxBlobGasPerBlob
}

func BlobBaseFeeUpdateFraction(blobCfg *BlobConfig) uint64 {
	if blobCfg == nil || blobCfg.BaseFeeUpdateFraction <= 0 {
		blobCfg = DefaultCancunBlobConfig()
	}
	return uint64(blobCfg.BaseFeeUpdateFraction)
}

func CalcExcessBlobGas(parentExcessBlobGas, parentBlobGasUsed uint64, blobCfg *BlobConfig) uint64 {
	return excessBlobGasAfterTarget(parentExcessBlobGas, parentBlobGasUsed, TargetBlobGasPerBlock(blobCfg))
}

// excessBlobGasAfterTarget computes max(a+b-target, 0) without permitting a
// malformed near-uint64 parent header to wrap into a small, apparently valid
// excess value. Results outside the header's uint64 domain saturate.
func excessBlobGasAfterTarget(a, b, target uint64) uint64 {
	sum, carry := bits.Add64(a, b, 0)
	if carry == 0 {
		if sum < target {
			return 0
		}
		return sum - target
	}
	// The mathematical sum is 2^64+sum. If subtracting target brings it back
	// into range, unsigned subtraction produces that exact value. Otherwise
	// the result cannot be represented by the header and is saturated.
	if sum < target {
		return 0 - (target - sum)
	}
	return ^uint64(0)
}

func saturatingAddUint64(a, b uint64) uint64 {
	result, carry := bits.Add64(a, b, 0)
	if carry != 0 {
		return ^uint64(0)
	}
	return result
}

// mulDivFloor computes floor(value*numerator/denominator). EIP-7918 always
// supplies numerator <= denominator, so the result is bounded by value even
// when the intermediate product needs 128 bits.
func mulDivFloor(value, numerator, denominator uint64) uint64 {
	if value == 0 || numerator == 0 || denominator == 0 {
		return 0
	}
	quotient, remainder := value/denominator, value%denominator
	hi, lo := bits.Mul64(remainder, numerator)
	remainderPart, _ := bits.Div64(hi, lo, denominator)
	return quotient*numerator + remainderPart
}

// CalcExcessBlobGasForFork calculates the child excess blob gas using the
// active execution fork. Osaka activates EIP-7918, which introduces a reserve
// price derived from the parent's execution base fee. Below that reserve the
// parent blob usage is scaled instead of subtracting the target, preventing
// the blob base fee from remaining below the calldata-equivalent price.
func CalcExcessBlobGasForFork(isOsaka bool, parentExcessBlobGas, parentBlobGasUsed uint64, parentBaseFee *big.Int, blobCfg *BlobConfig) uint64 {
	if !isOsaka || parentBaseFee == nil {
		return CalcExcessBlobGas(parentExcessBlobGas, parentBlobGasUsed, blobCfg)
	}
	if blobCfg == nil || blobCfg.Max <= 0 || blobCfg.Target <= 0 || blobCfg.Max < blobCfg.Target {
		blobCfg = DefaultCancunBlobConfig()
	}
	target := TargetBlobGasPerBlock(blobCfg)
	total, carry := bits.Add64(parentExcessBlobGas, parentBlobGasUsed, 0)
	if carry == 0 && total < target {
		return 0
	}
	// The EIP-7918 reserve is the execution-gas cost of one blob. Compare
	// prices in wei-per-blob to avoid rounding away the base fee.
	reservePrice := new(big.Int).Mul(new(big.Int).SetUint64(BlobBaseCost), parentBaseFee)
	blobPrice := new(big.Int).Mul(
		CalcBlobBaseFeeWithConfig(blobCfg, parentExcessBlobGas),
		new(big.Int).SetUint64(BlobTxBlobGasPerBlob),
	)
	if reservePrice.Cmp(blobPrice) > 0 {
		scaled := mulDivFloor(parentBlobGasUsed, uint64(blobCfg.Max-blobCfg.Target), uint64(blobCfg.Max))
		return saturatingAddUint64(parentExcessBlobGas, scaled)
	}
	return CalcExcessBlobGas(parentExcessBlobGas, parentBlobGasUsed, blobCfg)
}

func FakeExponential(factor, numerator, denominator *big.Int) *big.Int {
	if factor == nil || numerator == nil || denominator == nil || denominator.Sign() <= 0 {
		return new(big.Int).Set(minBlobGasPriceBig)
	}
	output := new(big.Int)
	accum := new(big.Int).Mul(factor, denominator)
	capScaled := new(big.Int).Mul(maxBlobBaseFeeSentinel, denominator)
	for i := int64(1); accum.Sign() > 0; i++ {
		output.Add(output, accum)
		if output.Cmp(capScaled) >= 0 {
			return new(big.Int).Set(maxBlobBaseFeeSentinel)
		}
		accum.Mul(accum, numerator)
		accum.Div(accum, denominator)
		accum.Div(accum, big.NewInt(i))
	}
	output.Div(output, denominator)
	if output.Cmp(minBlobGasPriceBig) < 0 {
		return new(big.Int).Set(minBlobGasPriceBig)
	}
	return output
}

func CalcBlobBaseFeeWithConfig(blobCfg *BlobConfig, excessBlobGas uint64) *big.Int {
	return FakeExponential(
		minBlobGasPriceBig,
		new(big.Int).SetUint64(excessBlobGas),
		new(big.Int).SetUint64(BlobBaseFeeUpdateFraction(blobCfg)),
	)
}

func CalcBlobBaseFeeAtTime(config *ChainConfig, timestamp uint64, excessBlobGas uint64) *big.Int {
	blobCfg := DefaultCancunBlobConfig()
	if config != nil {
		blobCfg = config.ActiveBlobConfig(timestamp)
	}
	return CalcBlobBaseFeeWithConfig(blobCfg, excessBlobGas)
}

func CalcBlobBaseFee(config *ChainConfig, excessBlobGas uint64) *big.Int {
	return CalcBlobBaseFeeAtTime(config, 0, excessBlobGas)
}
