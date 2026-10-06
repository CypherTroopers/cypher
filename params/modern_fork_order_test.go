package params

import (
	"math/big"
	"testing"
)

func modernForkOrderConfig() *ChainConfig {
	zeroBlock := big.NewInt(0)
	return &ChainConfig{
		HomesteadBlock:      zeroBlock,
		EIP150Block:         zeroBlock,
		EIP155Block:         zeroBlock,
		EIP158Block:         zeroBlock,
		ByzantiumBlock:      zeroBlock,
		ConstantinopleBlock: zeroBlock,
		PetersburgBlock:     zeroBlock,
		IstanbulBlock:       zeroBlock,
	}
}

func validModernSchedule() *BlobScheduleConfig {
	return &BlobScheduleConfig{
		Cancun: &BlobConfig{Target: 3, Max: 6, BaseFeeUpdateFraction: 3338477},
		Prague: &BlobConfig{Target: 6, Max: 9, BaseFeeUpdateFraction: 5007716},
		Osaka:  &BlobConfig{Target: 6, Max: 9, BaseFeeUpdateFraction: 5007716},
	}
}

func validBPOBlobConfig() *BlobConfig {
	return &BlobConfig{Target: 10, Max: 15, BaseFeeUpdateFraction: 8346193}
}

func TestModernForkOrderAllowsAllForksAtGenesis(t *testing.T) {
	zero := uint64(0)
	cfg := modernForkOrderConfig()
	cfg.SetModernForkConfig(&ModernForkConfig{
		BerlinBlock:  big.NewInt(0),
		LondonBlock:  big.NewInt(0),
		ShanghaiTime: &zero,
		CancunTime:   &zero,
		PragueTime:   &zero,
		OsakaTime:    &zero,
		BlobSchedule: validModernSchedule(),
	})
	if err := cfg.CheckConfigForkOrder(); err != nil {
		t.Fatalf("all-at-genesis fork schedule rejected: %v", err)
	}
}

func TestModernForkOrderRejectsSkippedAndInvalidSchedules(t *testing.T) {
	zero, ten := uint64(0), uint64(10)
	for _, tc := range []struct {
		name   string
		modern *ModernForkConfig
	}{
		{name: "London without Berlin", modern: &ModernForkConfig{LondonBlock: big.NewInt(0)}},
		{name: "Shanghai without London", modern: &ModernForkConfig{ShanghaiTime: &zero}},
		{name: "Prague without Cancun", modern: &ModernForkConfig{ShanghaiTime: &zero, PragueTime: &ten}},
		{name: "timestamp regression", modern: &ModernForkConfig{ShanghaiTime: &ten, CancunTime: &zero, BlobSchedule: validModernSchedule()}},
		{name: "missing Prague blob config", modern: &ModernForkConfig{ShanghaiTime: &zero, CancunTime: &zero, PragueTime: &zero, BlobSchedule: &BlobScheduleConfig{Cancun: validModernSchedule().Cancun}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := modernForkOrderConfig()
			cfg.SetModernForkConfig(tc.modern)
			if err := cfg.CheckConfigForkOrder(); err == nil {
				t.Fatal("invalid modern fork schedule accepted")
			}
		})
	}
}

func TestModernForkOrderBPOValidation(t *testing.T) {
	zero, ten, twenty := uint64(0), uint64(10), uint64(20)
	for _, tc := range []struct {
		name    string
		modern  *ModernForkConfig
		wantErr bool
	}{
		{
			name: "BPO after Osaka",
			modern: &ModernForkConfig{
				BerlinBlock: big.NewInt(0), LondonBlock: big.NewInt(0),
				ShanghaiTime: &zero, CancunTime: &zero, PragueTime: &zero, OsakaTime: &zero, BPO1Time: &ten,
				BlobSchedule: func() *BlobScheduleConfig {
					schedule := validModernSchedule()
					schedule.BPO1 = validBPOBlobConfig()
					return schedule
				}(),
			},
		},
		{
			name: "optional earlier BPO slot",
			modern: &ModernForkConfig{
				BerlinBlock: big.NewInt(0), LondonBlock: big.NewInt(0),
				ShanghaiTime: &zero, CancunTime: &zero, PragueTime: &zero, OsakaTime: &zero, BPO3Time: &twenty,
				BlobSchedule: func() *BlobScheduleConfig {
					schedule := validModernSchedule()
					schedule.BPO3 = validBPOBlobConfig()
					return schedule
				}(),
			},
		},
		{
			name: "BPO without Osaka",
			modern: &ModernForkConfig{
				BerlinBlock: big.NewInt(0), LondonBlock: big.NewInt(0),
				ShanghaiTime: &zero, CancunTime: &zero, PragueTime: &zero, BPO1Time: &ten,
				BlobSchedule: func() *BlobScheduleConfig {
					schedule := validModernSchedule()
					schedule.BPO1 = validBPOBlobConfig()
					return schedule
				}(),
			},
			wantErr: true,
		},
		{
			name: "BPO timestamp regression",
			modern: &ModernForkConfig{
				BerlinBlock: big.NewInt(0), LondonBlock: big.NewInt(0),
				ShanghaiTime: &zero, CancunTime: &zero, PragueTime: &zero, OsakaTime: &twenty, BPO1Time: &ten,
				BlobSchedule: func() *BlobScheduleConfig {
					schedule := validModernSchedule()
					schedule.BPO1 = validBPOBlobConfig()
					return schedule
				}(),
			},
			wantErr: true,
		},
		{
			name: "missing BPO blob config",
			modern: &ModernForkConfig{
				BerlinBlock: big.NewInt(0), LondonBlock: big.NewInt(0),
				ShanghaiTime: &zero, CancunTime: &zero, PragueTime: &zero, OsakaTime: &zero, BPO1Time: &ten,
				BlobSchedule: validModernSchedule(),
			},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := modernForkOrderConfig()
			cfg.SetModernForkConfig(tc.modern)
			err := cfg.CheckConfigForkOrder()
			if tc.wantErr && err == nil {
				t.Fatal("invalid BPO schedule accepted")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("valid BPO schedule rejected: %v", err)
			}
		})
	}
}
