package core

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

func TestValidateExcessBlobGas(t *testing.T) {
	cancunTime := uint64(0)
	cfg := &params.ChainConfig{}
	cfg.SetModernForkConfig(&params.ModernForkConfig{BerlinBlock: big.NewInt(0), LondonBlock: big.NewInt(0), CancunTime: &cancunTime})
	blobCfg := cfg.ActiveBlobConfig(0)
	parent := &types.Header{
		Number:      big.NewInt(1),
		Time:        0,
		BlobGasUsed: params.TargetBlobGasPerBlock(blobCfg) + params.BlobTxBlobGasPerBlob,
	}
	header := &types.Header{Number: big.NewInt(2), Time: 0}
	header.ExcessBlobGas = params.CalcExcessBlobGas(parent.ExcessBlobGas, parent.BlobGasUsed, blobCfg)
	if err := ValidateExcessBlobGas(cfg, parent, header); err != nil {
		t.Fatalf("expected valid header, got %v", err)
	}
}

func TestValidateExcessBlobGasUsesChildBPOSchedule(t *testing.T) {
	zero, bpo1Time := uint64(0), uint64(10)
	osakaBlobs := &params.BlobConfig{Target: 3, Max: 6, BaseFeeUpdateFraction: 3338477}
	bpoBlobs := &params.BlobConfig{Target: 10, Max: 15, BaseFeeUpdateFraction: 8346193}
	cfg := &params.ChainConfig{}
	cfg.SetModernForkConfig(&params.ModernForkConfig{
		BerlinBlock: big.NewInt(0), LondonBlock: big.NewInt(0),
		ShanghaiTime: &zero, CancunTime: &zero, PragueTime: &zero, OsakaTime: &zero, BPO1Time: &bpo1Time,
		BlobSchedule: &params.BlobScheduleConfig{Cancun: osakaBlobs, Prague: osakaBlobs, Osaka: osakaBlobs, BPO1: bpoBlobs},
	})
	parent := &types.Header{
		Number:      big.NewInt(1),
		Time:        bpo1Time - 1,
		BlobGasUsed: params.TargetBlobGasPerBlock(bpoBlobs),
		BaseFee:     big.NewInt(1_000_000_000),
	}
	header := &types.Header{Number: big.NewInt(2), Time: bpo1Time}
	header.ExcessBlobGas = params.CalcExcessBlobGasForFork(true, parent.ExcessBlobGas, parent.BlobGasUsed, parent.BaseFee, bpoBlobs)
	if old := params.CalcExcessBlobGasForFork(true, parent.ExcessBlobGas, parent.BlobGasUsed, parent.BaseFee, osakaBlobs); old == header.ExcessBlobGas {
		t.Fatal("test schedules do not distinguish the BPO transition")
	}
	if err := ValidateExcessBlobGas(cfg, parent, header); err != nil {
		t.Fatalf("BPO boundary used the parent schedule: %v", err)
	}
}
