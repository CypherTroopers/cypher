package t8ntool

import (
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/cypherium/cypher/common"
	commonmath "github.com/cypherium/cypher/common/math"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/tests"
)

func TestApplyUsesModernEnvironmentAndPragueSystemCall(t *testing.T) {
	cfg, _, err := tests.GetChainConfig("Osaka")
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.HexToECDSA("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	from := crypto.PubkeyToAddress(key.PublicKey)
	contract := common.HexToAddress("0xc0de")
	parentHash := common.HexToHash("0x1234")
	blobHash := common.HexToHash("0x010000000000000000000000000000000000000000000000000000000000cafe")
	baseFee := big.NewInt(7)
	excessBlobGas := uint64(1_000_000)
	blobBaseFee := params.CalcBlobBaseFeeAtTime(cfg, 0, excessBlobGas)

	// BASEFEE -> slot 0, BLOBBASEFEE -> slot 1, BLOBHASH(0) -> slot 2,
	// PREVRANDAO (the post-merge meaning of opcode 0x44) -> slot 3.
	code := []byte{
		byte(vm.BASEFEE), byte(vm.PUSH1), 0, byte(vm.SSTORE),
		byte(vm.BLOBBASEFEE), byte(vm.PUSH1), 1, byte(vm.SSTORE),
		byte(vm.PUSH1), 0, byte(vm.BLOBHASH), byte(vm.PUSH1), 2, byte(vm.SSTORE),
		byte(vm.DIFFICULTY), byte(vm.PUSH1), 3, byte(vm.SSTORE),
		byte(vm.STOP),
	}
	random := big.NewInt(0x4242)
	pre := core.GenesisAlloc{
		from: {
			Balance: new(big.Int).Exp(big.NewInt(10), big.NewInt(30), nil),
		},
		contract: {
			Balance: new(big.Int),
			Code:    code,
		},
		params.HistoryStorageAddress: {
			Balance: new(big.Int),
			Nonce:   1,
			Code:    params.HistoryStorageCode,
		},
	}
	tx, err := types.SignTx(types.NewTx(&types.BlobTx{
		ChainID:    cfg.ChainID,
		Nonce:      0,
		GasTipCap:  big.NewInt(1),
		GasFeeCap:  big.NewInt(100),
		Gas:        200_000,
		To:         contract,
		Value:      new(big.Int),
		BlobFeeCap: new(big.Int).Add(blobBaseFee, big.NewInt(1)),
		BlobHashes: []common.Hash{blobHash},
	}), types.NewCancunSigner(cfg.ChainID), key)
	if err != nil {
		t.Fatal(err)
	}
	prestate := &Prestate{
		Pre: pre,
		Env: stEnv{
			Coinbase:      common.HexToAddress("0xc01a"),
			Random:        random,
			GasLimit:      1_000_000,
			Number:        1,
			Timestamp:     0,
			BaseFee:       baseFee,
			ExcessBlobGas: &excessBlobGas,
			BlockHashes: map[commonmath.HexOrDecimal64]common.Hash{
				0: parentHash,
			},
		},
	}
	statedb, result, err := prestate.Apply(vm.Config{}, cfg, types.Transactions{tx}, 0, func(int, common.Hash) (vm.Tracer, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rejected) != 0 {
		t.Fatalf("modern blob transaction rejected: %v", result.Rejected)
	}
	if result.BaseFee == nil || (*big.Int)(result.BaseFee).Cmp(baseFee) != 0 ||
		result.CurrentExcessBlobGas == nil || uint64(*result.CurrentExcessBlobGas) != excessBlobGas ||
		result.CurrentBlobGasUsed == nil || uint64(*result.CurrentBlobGasUsed) != params.BlobTxBlobGasPerBlob {
		t.Fatalf("modern execution result context is incomplete: %#v", result)
	}
	encodedResult, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encodedResult), `"receiptsRoot"`) || strings.Contains(string(encodedResult), `"receiptRoot"`) {
		t.Fatalf("non-standard t8n receipt-root field: %s", encodedResult)
	}
	checks := []struct {
		slot uint64
		want common.Hash
	}{
		{0, common.BigToHash(baseFee)},
		{1, common.BigToHash(blobBaseFee)},
		{2, blobHash},
		{3, common.BigToHash(random)},
	}
	for _, check := range checks {
		if got := statedb.GetState(contract, common.BigToHash(new(big.Int).SetUint64(check.slot))); got != check.want {
			t.Fatalf("contract slot %d = %s, want %s", check.slot, got, check.want)
		}
	}
	if got := statedb.GetState(params.HistoryStorageAddress, common.Hash{}); got != parentHash {
		t.Fatalf("EIP-2935 parent hash = %s, want %s", got, parentHash)
	}
}

func TestModernStEnvJSONRoundTrip(t *testing.T) {
	baseFee := big.NewInt(800_000_000)
	parentBaseFee := big.NewInt(799_000_000)
	random := big.NewInt(0x1234)
	excess := uint64(17)
	parentExcess := uint64(18)
	parentUsed := uint64(19)
	want := stEnv{
		Coinbase:            common.HexToAddress("0xc01a"),
		Random:              random,
		GasLimit:            30_000_000,
		Number:              7,
		Timestamp:           11,
		BaseFee:             baseFee,
		ParentBaseFee:       parentBaseFee,
		ParentTimestamp:     10,
		ExcessBlobGas:       &excess,
		ParentExcessBlobGas: &parentExcess,
		ParentBlobGasUsed:   &parentUsed,
	}
	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		`"currentRandom"`, `"currentBaseFee"`, `"parentBaseFee"`,
		`"parentTimestamp"`, `"currentExcessBlobGas"`,
		`"parentExcessBlobGas"`, `"parentBlobGasUsed"`,
	} {
		if !strings.Contains(string(encoded), field) {
			t.Fatalf("modern environment field %s missing from %s", field, encoded)
		}
	}
	var got stEnv
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if got.Difficulty != nil || got.Random.Cmp(random) != 0 || got.BaseFee.Cmp(baseFee) != 0 ||
		got.ParentBaseFee.Cmp(parentBaseFee) != 0 || got.ParentTimestamp != want.ParentTimestamp ||
		got.ExcessBlobGas == nil || *got.ExcessBlobGas != excess ||
		got.ParentExcessBlobGas == nil || *got.ParentExcessBlobGas != parentExcess ||
		got.ParentBlobGasUsed == nil || *got.ParentBlobGasUsed != parentUsed {
		t.Fatalf("modern environment round-trip mismatch: %#v", got)
	}
}

func TestApplyDerivesOsakaExcessBlobGasFromParent(t *testing.T) {
	cfg, _, err := tests.GetChainConfig("Osaka")
	if err != nil {
		t.Fatal(err)
	}
	parentExcess := uint64(2_000_000)
	parentUsed := params.BlobTxBlobGasPerBlob * 4
	parentBaseFee := big.NewInt(params.FixedBaseFeePerGas)
	wantExcess := params.CalcExcessBlobGasForFork(true, parentExcess, parentUsed, parentBaseFee, cfg.ActiveBlobConfig(0))
	prestate := &Prestate{Env: stEnv{
		Coinbase:            common.HexToAddress("0xc01a"),
		Random:              big.NewInt(1),
		GasLimit:            1_000_000,
		Number:              0,
		Timestamp:           0,
		BaseFee:             big.NewInt(params.FixedBaseFeePerGas),
		ParentBaseFee:       parentBaseFee,
		ParentExcessBlobGas: &parentExcess,
		ParentBlobGasUsed:   &parentUsed,
	}}
	_, result, err := prestate.Apply(vm.Config{}, cfg, nil, 0, func(int, common.Hash) (vm.Tracer, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.CurrentExcessBlobGas == nil || uint64(*result.CurrentExcessBlobGas) != wantExcess {
		t.Fatalf("derived excess blob gas = %v, want %d", result.CurrentExcessBlobGas, wantExcess)
	}
	if result.CurrentBlobGasUsed == nil || uint64(*result.CurrentBlobGasUsed) != 0 {
		t.Fatalf("blob gas used = %v, want 0", result.CurrentBlobGasUsed)
	}
}

func TestApplyRequiresPrevRandaoAfterShanghai(t *testing.T) {
	cfg, _, err := tests.GetChainConfig("Osaka")
	if err != nil {
		t.Fatal(err)
	}
	prestate := &Prestate{Env: stEnv{
		Coinbase:  common.HexToAddress("0xc01a"),
		GasLimit:  1_000_000,
		Timestamp: 0,
	}}
	_, _, err = prestate.Apply(vm.Config{}, cfg, nil, 0, func(int, common.Hash) (vm.Tracer, error) {
		return nil, nil
	})
	var numbered *NumberedError
	if !errors.As(err, &numbered) || numbered.Code() != ErrorVMConfig {
		t.Fatalf("missing currentRandom error = %v, want VM config error", err)
	}
	if !strings.Contains(err.Error(), "currentRandom is required") {
		t.Fatalf("missing currentRandom error = %v", err)
	}
}
