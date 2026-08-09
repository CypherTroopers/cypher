package reconfig

import (
	"errors"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

func cancunProposalTestConfig() *params.ChainConfig {
	cancunTime, shanghaiTime := uint64(0), uint64(0)
	cfg := &params.ChainConfig{ChainID: big.NewInt(12367)}
	cfg.SetModernForkConfig(&params.ModernForkConfig{
		BerlinBlock:  big.NewInt(0),
		LondonBlock:  big.NewInt(0),
		ShanghaiTime: &shanghaiTime,
		CancunTime:   &cancunTime,
		BlobSchedule: &params.BlobScheduleConfig{
			Cancun: &params.BlobConfig{Target: 3, Max: 6, BaseFeeUpdateFraction: 3338477},
		},
	})
	return cfg
}

func TestDeriveCancunHeaderFieldsFromParent(t *testing.T) {
	cfg := cancunProposalTestConfig()
	blobCfg := cfg.ActiveBlobConfig(1)
	parent := &types.Header{
		Number:        big.NewInt(1),
		Time:          0,
		ExcessBlobGas: params.TargetBlobGasPerBlock(blobCfg),
		BlobGasUsed:   params.BlobTxBlobGasPerBlob,
	}
	header := &types.Header{Number: big.NewInt(2), Time: 1, BlobGasUsed: 99, ExcessBlobGas: 99}

	deriveCancunHeaderFields(cfg, parent, header)

	if header.BlobGasUsed != 0 {
		t.Fatalf("new proposal blobGasUsed = %d, want 0 before body selection", header.BlobGasUsed)
	}
	wantExcess := params.CalcExcessBlobGas(parent.ExcessBlobGas, parent.BlobGasUsed, blobCfg)
	if header.ExcessBlobGas != wantExcess {
		t.Fatalf("new proposal excessBlobGas = %d, want %d", header.ExcessBlobGas, wantExcess)
	}
}

func TestCanIncludeBlobGasHonorsBlockLimit(t *testing.T) {
	cfg := cancunProposalTestConfig()
	header := &types.Header{Number: big.NewInt(1), Time: 0}
	maxBlobGas := params.MaxBlobGasPerBlock(cfg.ActiveBlobConfig(header.Time))
	tx := types.NewTx(&types.BlobTx{
		Gas:        21_000,
		BlobFeeCap: big.NewInt(1),
		BlobHashes: []common.Hash{{types.BlobCommitmentVersionKZG}},
	})

	header.BlobGasUsed = maxBlobGas - params.BlobTxBlobGasPerBlob
	if !canIncludeBlobGas(cfg, header, tx) {
		t.Fatal("expected one final blob to fit")
	}
	header.BlobGasUsed = maxBlobGas
	if canIncludeBlobGas(cfg, header, tx) {
		t.Fatal("expected blob transaction above block limit to be rejected")
	}
}

func TestProposalPrecheckRejectsBlobTxWithoutDA(t *testing.T) {
	zero := uint64(0)
	config := &params.ChainConfig{ChainID: big.NewInt(1)}
	config.SetModernForkConfig(&params.ModernForkConfig{
		BerlinBlock:  big.NewInt(0),
		LondonBlock:  big.NewInt(0),
		CancunTime:   &zero,
		BlobSchedule: &params.BlobScheduleConfig{Cancun: &params.BlobConfig{Target: 3, Max: 6, BaseFeeUpdateFraction: 3338477}},
	})
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	from := common.HexToAddress("0x100")
	to := common.HexToAddress("0x200")
	st.SetBalance(from, new(big.Int).Mul(big.NewInt(100), big.NewInt(params.Ether)))
	tx := types.NewTx(&types.BlobTx{
		ChainID:    big.NewInt(1),
		GasTipCap:  big.NewInt(1),
		GasFeeCap:  big.NewInt(params.FixedBaseFeePerGas + 1),
		Gas:        params.TxGas,
		To:         to,
		Value:      new(big.Int),
		BlobFeeCap: big.NewInt(1),
		BlobHashes: []common.Hash{{types.BlobCommitmentVersionKZG}},
		V:          new(big.Int),
		R:          big.NewInt(1),
		S:          big.NewInt(1),
	})
	header := &types.Header{Number: big.NewInt(1), Time: 0, GasLimit: 30_000_000, BaseFee: big.NewInt(params.FixedBaseFeePerGas)}
	if err := precheckTxForProposal(config, st, header, tx, from); !errors.Is(err, core.ErrBlobDAUnavailable) {
		t.Fatalf("error = %v, want %v", err, core.ErrBlobDAUnavailable)
	}
}

func TestOsakaProposalReservesBlockEncodingHeadroom(t *testing.T) {
	zero := uint64(0)
	cfg := &params.ChainConfig{}
	cfg.SetModernForkConfig(&params.ModernForkConfig{BerlinBlock: big.NewInt(0), LondonBlock: big.NewInt(0), OsakaTime: &zero})
	header := &types.Header{Number: big.NewInt(1), Time: 0}
	tx := types.NewTransaction(0, common.Address{}, big.NewInt(0), params.TxGas, big.NewInt(1), nil)
	env := &work{config: cfg, header: header, size: common.StorageSize(params.MaxBlockSize - uint64(osakaBlockSizeBuffer) - uint64(osakaPerTxBodySizeBuffer) - uint64(tx.Size()))}
	if env.txFitsBlockSize(tx) {
		t.Fatal("transaction at the reserved Osaka size boundary was accepted")
	}
	env.size--
	if !env.txFitsBlockSize(tx) {
		t.Fatal("transaction below the reserved Osaka size boundary was rejected")
	}
}
