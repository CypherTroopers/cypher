package core

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/params"
)

func modernCompatGenesis(osakaMax int) *Genesis {
	zero := uint64(0)
	config := &params.ChainConfig{
		ChainID:              big.NewInt(12367),
		TransactionSizeLimit: 32,
	}
	config.SetModernForkConfig(&params.ModernForkConfig{
		BerlinBlock:  big.NewInt(0),
		LondonBlock:  big.NewInt(0),
		ShanghaiTime: &zero,
		CancunTime:   &zero,
		PragueTime:   &zero,
		OsakaTime:    &zero,
		BlobSchedule: &params.BlobScheduleConfig{
			Cancun: &params.BlobConfig{Target: 3, Max: 6, BaseFeeUpdateFraction: 3338477},
			Prague: &params.BlobConfig{Target: 6, Max: 9, BaseFeeUpdateFraction: 5007716},
			Osaka:  &params.BlobConfig{Target: 6, Max: osakaMax, BaseFeeUpdateFraction: 5007716},
		},
	})
	return &Genesis{
		Config:     config,
		Difficulty: big.NewInt(1),
		GasLimit:   params.GenesisGasLimit,
		Alloc:      GenesisAlloc{},
	}
}

func TestSetupGenesisRejectsModernForkScheduleReplacementAfterHead(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	defer db.Close()

	genesis := modernCompatGenesis(9)
	_, stored, err := SetupGenesisBlock(db, genesis)
	if err != nil {
		t.Fatal(err)
	}
	replacement := modernCompatGenesis(12)
	if hash := replacement.ToBlock(nil).Hash(); hash != stored {
		t.Fatalf("test fixture changed genesis hash: have %s want %s", hash, stored)
	}

	// SetupGenesisBlock only needs the durable head-number marker for this
	// compatibility decision. The synthetic marker avoids constructing an
	// otherwise irrelevant execution block in this focused test.
	headHash := common.HexToHash("0x01")
	rawdb.WriteHeaderNumber(db, headHash, 1)
	rawdb.WriteHeadHeaderHash(db, headHash)
	if _, _, err := SetupGenesisBlock(db, replacement); err == nil {
		t.Fatal("past Osaka blob schedule was replaceable in a non-empty chain")
	}
	storedConfig := rawdb.ReadChainConfig(db, stored)
	if storedConfig == nil || storedConfig.ModernForkConfig().BlobSchedule.Osaka.Max != 9 {
		t.Fatal("failed replacement modified the stored modern fork schedule")
	}
}
