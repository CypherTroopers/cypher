package params

import "math/big"

const (
	BlobTxBlobGasPerBlob uint64 = 1 << 17
	BlobTxMaxBlobs              = 6 // EIP-7594/Osaka per-transaction limit.
	MinBlobGasPrice      uint64 = 1
	BlobBaseCost         uint64 = 1 << 13 // EIP-7918 calldata-equivalent execution gas per blob.
)

var minBlobGasPriceBig = new(big.Int).SetUint64(MinBlobGasPrice)

func (c *ChainConfig) ActiveBlobConfig(timestamp uint64) *BlobConfig {
	cfg := c.ModernForkConfig()
	if cfg == nil || cfg.BlobSchedule == nil {
		return DefaultCancunBlobConfig()
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
	return uint64(blobCfg.Max) * BlobTxBlobGasPerBlob
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
	return uint64(blobCfg.Target) * BlobTxBlobGasPerBlob
}

func BlobBaseFeeUpdateFraction(blobCfg *BlobConfig) uint64 {
	if blobCfg == nil || blobCfg.BaseFeeUpdateFraction <= 0 {
		blobCfg = DefaultCancunBlobConfig()
	}
	return uint64(blobCfg.BaseFeeUpdateFraction)
}

func CalcExcessBlobGas(parentExcessBlobGas, parentBlobGasUsed uint64, blobCfg *BlobConfig) uint64 {
	target := TargetBlobGasPerBlock(blobCfg)
	if parentExcessBlobGas+parentBlobGasUsed < target {
		return 0
	}
	return parentExcessBlobGas + parentBlobGasUsed - target
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
	if parentExcessBlobGas < target && parentBlobGasUsed < target-parentExcessBlobGas {
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
		scaled := parentBlobGasUsed * uint64(blobCfg.Max-blobCfg.Target) / uint64(blobCfg.Max)
		return parentExcessBlobGas + scaled
	}
	return CalcExcessBlobGas(parentExcessBlobGas, parentBlobGasUsed, blobCfg)
}

func FakeExponential(factor, numerator, denominator *big.Int) *big.Int {
	if factor == nil || numerator == nil || denominator == nil || denominator.Sign() <= 0 {
		return new(big.Int).Set(minBlobGasPriceBig)
	}
	output := new(big.Int)
	accum := new(big.Int).Mul(factor, denominator)
	for i := int64(1); accum.Sign() > 0; i++ {
		output.Add(output, accum)
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
