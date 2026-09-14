package core

import (
	"errors"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

func blobBlockValidationHeader(txs types.Transactions, excessBlobGas uint64) *types.Header {
	return &types.Header{
		Number:        big.NewInt(1),
		Time:          0,
		ExcessBlobGas: excessBlobGas,
		BlobGasUsed:   CalcBlobGasUsed(txs),
	}
}

func TestValidateBlockBlobExecutionRejectsBlobTxWithoutDA(t *testing.T) {
	cfg := blobGasTestConfig(0)
	tx := newTxpoolBlobTx(t, []common.Hash{txpoolBlobTestHash(1)}, big.NewInt(2))
	txs := types.Transactions{tx}
	header := blobBlockValidationHeader(txs, 0)

	if err := ValidateBlockBlobBody(cfg, header, txs); err != nil {
		t.Fatalf("cheap execution-envelope validation failed: %v", err)
	}
	if err := ValidateBlockBlobExecution(cfg, header, txs, types.KZGBlobVerifier{}); !errors.Is(err, types.ErrBlobSidecarMissing) {
		t.Fatalf("error = %v, want %v", err, types.ErrBlobSidecarMissing)
	}
}

func TestValidateBlockBlobBodyRejectsBlobGasMismatch(t *testing.T) {
	cfg := blobGasTestConfig(0)
	tx := newTxpoolBlobTx(t, []common.Hash{txpoolBlobTestHash(1)}, big.NewInt(2))
	txs := types.Transactions{tx}
	header := blobBlockValidationHeader(txs, 0)
	header.BlobGasUsed = 0

	if err := ValidateBlockBlobBody(cfg, header, txs); !errors.Is(err, ErrBlobGasUsedMismatch) {
		t.Fatalf("expected blob gas mismatch, got %v", err)
	}
}

func TestValidateBlockBlobBodyRejectsInvalidBlobHashVersion(t *testing.T) {
	cfg := blobGasTestConfig(0)
	var invalid common.Hash
	invalid[0] = 0x02
	invalid[31] = 1
	tx := newTxpoolBlobTx(t, []common.Hash{invalid}, big.NewInt(2))
	txs := types.Transactions{tx}
	header := blobBlockValidationHeader(txs, 0)

	if err := ValidateBlockBlobBody(cfg, header, txs); !errors.Is(err, types.ErrBlobTxInvalidBlobHashVersion) {
		t.Fatalf("expected invalid blob hash version, got %v", err)
	}
}

func TestValidateBlockBlobBodyRejectsBlobFeeCapBelowBlobBaseFee(t *testing.T) {
	cfg := blobGasTestConfig(0)
	blobCfg := cfg.ActiveBlobConfig(0)
	excessBlobGas := params.BlobBaseFeeUpdateFraction(blobCfg) * 2
	blobBaseFee := params.CalcBlobBaseFeeAtTime(cfg, 0, excessBlobGas)
	if blobBaseFee.Cmp(big.NewInt(1)) <= 0 {
		t.Fatalf("test setup expected blob base fee > 1, got %s", blobBaseFee)
	}
	lowFeeCap := new(big.Int).Sub(blobBaseFee, big.NewInt(1))
	tx := newTxpoolBlobTx(t, []common.Hash{txpoolBlobTestHash(1)}, lowFeeCap)
	txs := types.Transactions{tx}
	header := blobBlockValidationHeader(txs, excessBlobGas)

	if err := ValidateBlockBlobBody(cfg, header, txs); !errors.Is(err, types.ErrBlobTxInvalidFeeCap) {
		t.Fatalf("expected invalid blob fee cap, got %v", err)
	}
}

func TestValidateBlockBlobBodyRejectsOsakaPerTransactionBlobLimit(t *testing.T) {
	zero := uint64(0)
	cfg := &params.ChainConfig{}
	cfg.SetModernForkConfig(&params.ModernForkConfig{
		BerlinBlock: big.NewInt(0),
		LondonBlock: big.NewInt(0),
		CancunTime:  &zero,
		PragueTime:  &zero,
		OsakaTime:   &zero,
		BlobSchedule: &params.BlobScheduleConfig{
			Cancun: &params.BlobConfig{Target: 3, Max: 6, BaseFeeUpdateFraction: 3338477},
			Prague: &params.BlobConfig{Target: 6, Max: 9, BaseFeeUpdateFraction: 5007716},
			Osaka:  &params.BlobConfig{Target: 6, Max: 9, BaseFeeUpdateFraction: 5007716},
		},
	})
	tx := blobGasTestTx(t, params.BlobTxMaxBlobs+1)
	header := blobBlockValidationHeader(types.Transactions{tx}, 0)
	if err := ValidateBlockBlobBody(cfg, header, types.Transactions{tx}); !errors.Is(err, types.ErrBlobTxTooManyBlobs) {
		t.Fatalf("error = %v, want %v", err, types.ErrBlobTxTooManyBlobs)
	}
}
