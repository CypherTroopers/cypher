package colossusX

import (
	"math/big"
	"strings"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

func modernHeaderTestConfig() *params.ChainConfig {
	cfg := &params.ChainConfig{
		ChainID:        big.NewInt(12367),
		HomesteadBlock: big.NewInt(0),
		EIP150Block:    big.NewInt(0),
		EIP155Block:    big.NewInt(0),
		EIP158Block:    big.NewInt(0),
		ByzantiumBlock: big.NewInt(0),
		IstanbulBlock:  big.NewInt(0),
	}
	cancunTime := uint64(10)
	cfg.SetModernForkConfig(&params.ModernForkConfig{
		BerlinBlock: big.NewInt(0),
		LondonBlock: big.NewInt(0),
		CancunTime:  &cancunTime,
		BlobSchedule: &params.BlobScheduleConfig{
			Cancun: &params.BlobConfig{Target: 3, Max: 6, BaseFeeUpdateFraction: 3338477},
		},
	})
	return cfg
}

func validModernHeader(number uint64, timestamp uint64) *types.Header {
	return &types.Header{
		Number:     new(big.Int).SetUint64(number),
		Time:       timestamp,
		GasLimit:   30_000_000,
		GasUsed:    1_000_000,
		Difficulty: big.NewInt(1),
		BaseFee:    big.NewInt(1_000_000_000),
	}
}

func requireHeaderErrContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error mismatch: got %q want contains %q", err.Error(), want)
	}
}

func TestVerifyModernHeaderFieldsAcceptsLondonAndCancunHeader(t *testing.T) {
	cfg := modernHeaderTestConfig()
	header := validModernHeader(1, 10)
	header.BlobGasUsed = params.BlobTxBlobGasPerBlob
	header.ExcessBlobGas = 0

	if err := verifyModernHeaderFields(cfg, header); err != nil {
		t.Fatalf("expected valid modern header, got %v", err)
	}
}

func TestVerifyModernHeaderFieldsRequiresLondonBaseFee(t *testing.T) {
	cfg := modernHeaderTestConfig()
	header := validModernHeader(1, 0)
	header.BaseFee = nil

	requireHeaderErrContains(t, verifyModernHeaderFields(cfg, header), "missing baseFeePerGas")
}

func TestVerifyModernHeaderFieldsRejectsCancunBlobGasBeforeFork(t *testing.T) {
	cfg := modernHeaderTestConfig()
	header := validModernHeader(1, 9)
	header.BlobGasUsed = params.BlobTxBlobGasPerBlob

	requireHeaderErrContains(t, verifyModernHeaderFields(cfg, header), "unexpected blobGasUsed before Cancun")
}

func TestVerifyModernHeaderFieldsRejectsBlobGasAboveGasUsed(t *testing.T) {
	cfg := modernHeaderTestConfig()
	header := validModernHeader(1, 10)
	header.GasUsed = 1
	header.BlobGasUsed = params.BlobTxBlobGasPerBlob

	requireHeaderErrContains(t, verifyModernHeaderFields(cfg, header), "invalid blobGasUsed")
}

func TestVerifyModernHeaderFieldsRejectsBlobGasMisalignment(t *testing.T) {
	cfg := modernHeaderTestConfig()
	header := validModernHeader(1, 10)
	header.BlobGasUsed = 1

	requireHeaderErrContains(t, verifyModernHeaderFields(cfg, header), "invalid blobGasUsed alignment")
}

func TestVerifyModernHeaderFieldsRejectsRequestsHashBeforePrague(t *testing.T) {
	cfg := modernHeaderTestConfig()
	header := validModernHeader(1, 10)
	header.RequestsHash = common.HexToHash("0x01")

	requireHeaderErrContains(t, verifyModernHeaderFields(cfg, header), "unexpected requestsHash before Prague")
}
