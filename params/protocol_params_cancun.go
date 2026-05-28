package params

import "math/big"

const (
	BlobTxBlobGasPerBlob uint64 = 1 << 17
	MinBlobGasPrice      uint64 = 1
)

var minBlobGasPriceBig = new(big.Int).SetUint64(MinBlobGasPrice)

func (c *ChainConfig) ActiveBlobConfig(timestamp uint64) *BlobConfig {
	cfg := c.ModernForkConfig()
	if cfg == nil || cfg.BlobSchedule == nil {
		return DefaultCancunBlobConfig()
	}
	if c.IsOsaka(nil, timestamp) && cfg.BlobSchedule.Osaka != nil {
		return cfg.BlobSchedule.Osaka
	}
	if c.IsPrague(nil, timestamp) && cfg.BlobSchedule.Prague != nil {
		return cfg.BlobSchedule.Prague
	}
	if c.IsCancun(nil, timestamp) && cfg.BlobSchedule.Cancun != nil {
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
