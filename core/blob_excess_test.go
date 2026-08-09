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
