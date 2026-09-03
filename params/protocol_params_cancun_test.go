package params

import (
	"math/big"
	"testing"
)

func TestCalcExcessBlobGas(t *testing.T) {
	cfg := DefaultCancunBlobConfig()
	target := TargetBlobGasPerBlock(cfg)

	tests := []struct {
		name         string
		parentExcess uint64
		parentUsed   uint64
		want         uint64
	}{
		{name: "below target", parentExcess: 0, parentUsed: target - 1, want: 0},
		{name: "at target", parentExcess: 0, parentUsed: target, want: 0},
		{name: "above target", parentExcess: 0, parentUsed: target + BlobTxBlobGasPerBlob, want: BlobTxBlobGasPerBlob},
		{name: "existing excess", parentExcess: BlobTxBlobGasPerBlob, parentUsed: target, want: BlobTxBlobGasPerBlob},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalcExcessBlobGas(tt.parentExcess, tt.parentUsed, cfg)
			if got != tt.want {
				t.Fatalf("CalcExcessBlobGas() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestCalcExcessBlobGasForForkEIP7918(t *testing.T) {
	cfg := DefaultCancunBlobConfig()
	used := TargetBlobGasPerBlock(cfg)
	baseFee := big.NewInt(1_000_000_000)

	if got := CalcExcessBlobGasForFork(false, 0, used, baseFee, cfg); got != 0 {
		t.Fatalf("pre-Osaka excess = %d, want 0", got)
	}
	want := used * uint64(cfg.Max-cfg.Target) / uint64(cfg.Max)
	if got := CalcExcessBlobGasForFork(true, 0, used, baseFee, cfg); got != want {
		t.Fatalf("Osaka reserve-price excess = %d, want %d", got, want)
	}
	if got := CalcExcessBlobGasForFork(true, 0, BlobTxBlobGasPerBlob, baseFee, cfg); got != 0 {
		t.Fatalf("Osaka below-target excess = %d, want 0", got)
	}
	if got := CalcExcessBlobGasForFork(true, 0, used, nil, cfg); got != 0 {
		t.Fatalf("nil parent base fee fallback = %d, want 0", got)
	}
}

func TestBlobGasScheduleDefaults(t *testing.T) {
	cfg := DefaultCancunBlobConfig()
	if got, want := TargetBlobGasPerBlock(cfg), uint64(cfg.Target)*BlobTxBlobGasPerBlob; got != want {
		t.Fatalf("target blob gas mismatch: got %d want %d", got, want)
	}
	if got, want := MaxBlobGasPerBlock(cfg), uint64(cfg.Max)*BlobTxBlobGasPerBlob; got != want {
		t.Fatalf("max blob gas mismatch: got %d want %d", got, want)
	}
	if got := BlobBaseFeeUpdateFraction(cfg); got == 0 {
		t.Fatalf("expected non-zero blob base fee update fraction")
	}
}

func TestActiveBlobConfigScheduleSwitches(t *testing.T) {
	cancunTime := uint64(10)
	pragueTime := uint64(20)
	osakaTime := uint64(30)
	bpo1Time := uint64(40)
	bpo3Time := uint64(50)
	cfg := &ChainConfig{}
	cfg.SetModernForkConfig(&ModernForkConfig{
		CancunTime: &cancunTime,
		PragueTime: &pragueTime,
		OsakaTime:  &osakaTime,
		BPO1Time:   &bpo1Time,
		BPO3Time:   &bpo3Time,
		BlobSchedule: &BlobScheduleConfig{
			Cancun: &BlobConfig{Target: 3, Max: 6, BaseFeeUpdateFraction: 3338477},
			Prague: &BlobConfig{Target: 4, Max: 8, BaseFeeUpdateFraction: 5000000},
			Osaka:  &BlobConfig{Target: 5, Max: 10, BaseFeeUpdateFraction: 7000000},
			BPO1:   &BlobConfig{Target: 7, Max: 14, BaseFeeUpdateFraction: 9000000},
			BPO3:   &BlobConfig{Target: 9, Max: 18, BaseFeeUpdateFraction: 11000000},
		},
	})

	if got := cfg.ActiveBlobConfig(10).Target; got != 3 {
		t.Fatalf("Cancun blob target = %d, want 3", got)
	}
	if got := cfg.ActiveBlobConfig(20).Target; got != 4 {
		t.Fatalf("Prague blob target = %d, want 4", got)
	}
	if got := cfg.ActiveBlobConfig(30).Target; got != 5 {
		t.Fatalf("Osaka blob target = %d, want 5", got)
	}
	if got := cfg.ActiveBlobConfig(40).Target; got != 7 {
		t.Fatalf("BPO1 blob target = %d, want 7", got)
	}
	if got := cfg.ActiveBlobConfig(50).Target; got != 9 {
		t.Fatalf("BPO3 blob target = %d, want 9", got)
	}
}

func TestBlobExcessArithmeticDoesNotWrap(t *testing.T) {
	target := TargetBlobGasPerBlock(DefaultCancunBlobConfig())
	maxUint64 := ^uint64(0)

	// max+1-target is representable even though the intermediate sum is not.
	want := maxUint64 - target + 1
	if got := CalcExcessBlobGas(maxUint64, 1, DefaultCancunBlobConfig()); got != want {
		t.Fatalf("overflowing intermediate = %d, want exact %d", got, want)
	}
	// The mathematical result no longer fits the header field and must never
	// wrap back to a small excess value.
	if got := CalcExcessBlobGas(maxUint64, target+1, DefaultCancunBlobConfig()); got != maxUint64 {
		t.Fatalf("out-of-range excess = %d, want saturation %d", got, maxUint64)
	}
	if got := mulDivFloor(maxUint64, 3, 6); got != maxUint64/2 {
		t.Fatalf("128-bit scaled usage = %d, want %d", got, maxUint64/2)
	}
	if got := CalcExcessBlobGasForFork(true, maxUint64, target, big.NewInt(1_000_000_000), DefaultCancunBlobConfig()); got != maxUint64 {
		t.Fatalf("EIP-7918 reserve branch wrapped to %d", got)
	}
	if got := CalcBlobBaseFeeWithConfig(DefaultCancunBlobConfig(), maxUint64); got.Cmp(maxBlobBaseFeeSentinel) != 0 {
		t.Fatalf("pathological blob base fee = %s, want uint256 overflow sentinel %s", got, maxBlobBaseFeeSentinel)
	}
}

func TestCalcBlobBaseFee(t *testing.T) {
	cfg := &ChainConfig{}
	zero := CalcBlobBaseFee(cfg, 0)
	if zero.Uint64() != MinBlobGasPrice {
		t.Fatalf("zero excess blob base fee = %s, want %d", zero, MinBlobGasPrice)
	}
	high := CalcBlobBaseFee(cfg, uint64(DefaultCancunBlobConfig().BaseFeeUpdateFraction*2))
	if high.Cmp(zero) <= 0 {
		t.Fatalf("expected blob base fee to increase: zero=%s high=%s", zero, high)
	}
}

func TestCalcBlobBaseFeeAtTimeUsesActiveSchedule(t *testing.T) {
	cancunTime := uint64(10)
	pragueTime := uint64(20)
	cfg := &ChainConfig{}
	cfg.SetModernForkConfig(&ModernForkConfig{
		CancunTime: &cancunTime,
		PragueTime: &pragueTime,
		BlobSchedule: &BlobScheduleConfig{
			Cancun: &BlobConfig{Target: 3, Max: 6, BaseFeeUpdateFraction: 100},
			Prague: &BlobConfig{Target: 3, Max: 6, BaseFeeUpdateFraction: 1000},
		},
	})

	excess := uint64(1000)
	cancunFee := CalcBlobBaseFeeAtTime(cfg, cancunTime, excess)
	pragueFee := CalcBlobBaseFeeAtTime(cfg, pragueTime, excess)
	if cancunFee.Cmp(pragueFee) <= 0 {
		t.Fatalf("expected lower update fraction to produce larger fee: cancun=%s prague=%s", cancunFee, pragueFee)
	}
}
