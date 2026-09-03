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
		BaseFee:    big.NewInt(params.FixedBaseFeePerGas),
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

func TestVerifyModernHeaderFieldsRequiresFixedLondonBaseFee(t *testing.T) {
	cfg := modernHeaderTestConfig()
	header := validModernHeader(1, 0)
	header.BaseFee.Add(header.BaseFee, big.NewInt(1))

	requireHeaderErrContains(t, verifyModernHeaderFields(cfg, header), "invalid baseFeePerGas")
}

func TestVerifyModernHeaderFieldsRejectsCancunBlobGasBeforeFork(t *testing.T) {
	cfg := modernHeaderTestConfig()
	header := validModernHeader(1, 9)
	header.BlobGasUsed = params.BlobTxBlobGasPerBlob

	requireHeaderErrContains(t, verifyModernHeaderFields(cfg, header), "unexpected blobGasUsed before Cancun")
}

func TestVerifyModernHeaderFieldsTreatsBlobGasAsIndependentFromExecutionGas(t *testing.T) {
	cfg := modernHeaderTestConfig()
	header := validModernHeader(1, 10)
	header.GasUsed = 1
	header.BlobGasUsed = params.BlobTxBlobGasPerBlob

	if err := verifyModernHeaderFields(cfg, header); err != nil {
		t.Fatalf("blob gas must not be compared with execution gas: %v", err)
	}
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

func TestVerifyModernHeaderFieldsRequiresExecutionOnlyShanghaiPragueRoots(t *testing.T) {
	zero := uint64(0)
	cfg := modernHeaderTestConfig()
	modern := cfg.ModernForkConfig()
	modern.ShanghaiTime = &zero
	modern.PragueTime = &zero
	cfg.SetModernForkConfig(modern)

	header := validModernHeader(1, 10)
	header.WithdrawalsHash = types.EmptyWithdrawalsHash
	header.RequestsHash = types.EmptyRequestsHash
	if err := verifyModernHeaderFields(cfg, header); err != nil {
		t.Fatalf("valid execution-only modern roots rejected: %v", err)
	}
	header.WithdrawalsHash = common.Hash{}
	requireHeaderErrContains(t, verifyModernHeaderFields(cfg, header), "withdrawalsRoot")
	header.WithdrawalsHash = types.EmptyWithdrawalsHash
	header.RequestsHash = common.Hash{}
	requireHeaderErrContains(t, verifyModernHeaderFields(cfg, header), "requestsHash")
}

func TestVerifyModernHeaderFieldsRejectsUnauthenticatedBeaconRoot(t *testing.T) {
	cfg := modernHeaderTestConfig()
	header := validModernHeader(1, 10)
	header.ParentBeaconRoot = common.HexToHash("0x01")
	requireHeaderErrContains(t, verifyModernHeaderFields(cfg, header), "unsupported by ColossusX")
}

func TestVerifyModernHeaderFieldsBindsPrevRandaoWithinKeyEpoch(t *testing.T) {
	zero := uint64(0)
	cfg := modernHeaderTestConfig()
	modern := cfg.ModernForkConfig()
	modern.ShanghaiTime = &zero
	cfg.SetModernForkConfig(modern)

	keyHash := common.HexToHash("0xcafe")
	parent := validModernHeader(1, 1)
	parent.WithdrawalsHash = types.EmptyWithdrawalsHash
	parent.BlockType = types.FastTx_Block
	parent.KeyHash = keyHash
	parent.MixDigest = common.HexToHash("0x1234")
	header := validModernHeader(2, 2)
	header.WithdrawalsHash = types.EmptyWithdrawalsHash
	header.BlockType = types.SlowTx_Block
	header.KeyHash = keyHash
	header.MixDigest = common.HexToHash("0x5678")

	requireHeaderErrContains(t, verifyModernHeaderFields(cfg, header, parent), "PREVRANDAO continuation")
	header.MixDigest = parent.MixDigest
	if err := verifyModernHeaderFields(cfg, header, parent); err != nil {
		t.Fatalf("matching PREVRANDAO continuation rejected: %v", err)
	}
	header.MixDigest = common.HexToHash("0x5678")
	header.BlockType = types.Key_Block
	if err := verifyModernHeaderFields(cfg, header, parent); err != nil {
		t.Fatalf("key-block carrier must be allowed to introduce PREVRANDAO: %v", err)
	}
}

func TestVerifyModernHeaderFieldsAllowsOldEpochChildOfKeyCarrier(t *testing.T) {
	zero := uint64(0)
	cfg := modernHeaderTestConfig()
	cfg.FairHotstuff = true
	modern := cfg.ModernForkConfig()
	modern.ShanghaiTime = &zero
	cfg.SetModernForkConfig(modern)

	oldKeyHash := common.HexToHash("0xcafe")
	parent := validModernHeader(1, 1)
	parent.WithdrawalsHash = types.EmptyWithdrawalsHash
	parent.BlockType = types.Key_Block
	parent.KeyHash = oldKeyHash
	parent.MixDigest = common.HexToHash("0x1111") // PREVRANDAO introduced by the carried key block.

	child := validModernHeader(2, 2)
	child.WithdrawalsHash = types.EmptyWithdrawalsHash
	child.BlockType = types.FastTx_Block
	child.KeyHash = oldKeyHash
	child.MixDigest = common.HexToHash("0x2222") // Still bound to the old signing epoch until the carrier commits.

	if err := verifyModernHeaderFields(cfg, child, parent); err != nil {
		t.Fatalf("old-epoch direct child of key-block carrier rejected: %v", err)
	}

	// The old-epoch child exception is specific to FHS two-chain finality. A
	// non-FHS chain has no canonical-key validation to authenticate this change.
	cfg.FairHotstuff = false
	requireHeaderErrContains(t, verifyModernHeaderFields(cfg, child, parent), "PREVRANDAO continuation")
}
