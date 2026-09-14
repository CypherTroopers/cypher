package vm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
	"reflect"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/params"
)

func TestModernPrecompileForkSets(t *testing.T) {
	if len(PrecompiledContractsBerlin) != 9 {
		t.Fatalf("Berlin precompile count = %d, want 9", len(PrecompiledContractsBerlin))
	}
	if len(PrecompiledContractsCancun) != 10 {
		t.Fatalf("Cancun precompile count = %d, want 10", len(PrecompiledContractsCancun))
	}
	if len(PrecompiledContractsPrague) != 17 {
		t.Fatalf("Prague precompile count = %d, want 17", len(PrecompiledContractsPrague))
	}
	if len(PrecompiledContractsOsaka) != 18 {
		t.Fatalf("Osaka precompile count = %d, want 18", len(PrecompiledContractsOsaka))
	}
	if _, ok := PrecompiledContractsCancun[common.BytesToAddress([]byte{0x0a})].(*kzgPointEvaluation); !ok {
		t.Fatal("Cancun address 0x0a is not the KZG point-evaluation precompile")
	}
	finalBLS := []any{
		&bls12381G1Add{}, &bls12381G1MultiExp{}, &bls12381G2Add{},
		&bls12381G2MultiExp{}, &bls12381Pairing{}, &bls12381MapG1{}, &bls12381MapG2{},
	}
	for i, want := range finalBLS {
		address := common.BytesToAddress([]byte{byte(0x0b + i)})
		got := PrecompiledContractsPrague[address]
		if got == nil {
			t.Fatalf("missing Prague BLS precompile at %#x", 0x0b+i)
		}
		if reflect.TypeOf(got) != reflect.TypeOf(want) {
			t.Fatalf("Prague precompile %#x has type %T, want %T", 0x0b+i, got, want)
		}
	}
	p256Address := common.BytesToAddress([]byte{0x01, 0x00})
	if _, ok := PrecompiledContractsOsaka[p256Address].(*p256Verify); !ok {
		t.Fatal("Osaka address 0x100 is not P256VERIFY")
	}
}

func modExpInput(baseLen, expLen, modLen uint64, base, exponent, modulus []byte) []byte {
	input := make([]byte, 96, 96+len(base)+len(exponent)+len(modulus))
	binary.BigEndian.PutUint64(input[24:32], baseLen)
	binary.BigEndian.PutUint64(input[56:64], expLen)
	binary.BigEndian.PutUint64(input[88:96], modLen)
	input = append(input, base...)
	input = append(input, exponent...)
	input = append(input, modulus...)
	return input
}

func TestModernModExpGasAndExecution(t *testing.T) {
	berlin := &modernBigModExp{}
	osaka := &modernBigModExp{eip7823: true, eip7883: true}

	small := modExpInput(1, 1, 1, []byte{2}, []byte{5}, []byte{13})
	if gas := berlin.RequiredGas(small); gas != 200 {
		t.Fatalf("Berlin minimum gas = %d, want 200", gas)
	}
	if gas := osaka.RequiredGas(small); gas != 500 {
		t.Fatalf("Osaka minimum gas = %d, want 500", gas)
	}
	result, err := osaka.Run(small)
	if err != nil {
		t.Fatalf("Osaka ModExp execution failed: %v", err)
	}
	if len(result) != 1 || result[0] != 6 {
		t.Fatalf("2**5 mod 13 = %x, want 06", result)
	}

	exponent := make([]byte, 32)
	for i := range exponent {
		exponent[i] = 0xff
	}
	vector := modExpInput(1, 32, 32, []byte{3}, exponent, make([]byte, 32))
	if gas := berlin.RequiredGas(vector); gas != 1360 {
		t.Fatalf("EIP-2565 vector gas = %d, want 1360", gas)
	}
	if gas := osaka.RequiredGas(vector); gas != 4080 {
		t.Fatalf("EIP-7883 vector gas = %d, want 4080", gas)
	}

	for name, tooLarge := range map[string][]byte{
		"base":     modExpInput(1025, 0, 0, nil, nil, nil),
		"exponent": modExpInput(0, 1025, 0, nil, nil, nil),
		"modulus":  modExpInput(0, 0, 1025, nil, nil, nil),
	} {
		t.Run("EIP-7823 "+name, func(t *testing.T) {
			if _, err := osaka.Run(tooLarge); !errors.Is(err, errModExpInputTooLarge) {
				t.Fatalf("oversized input error = %v, want %v", err, errModExpInputTooLarge)
			}
		})
	}
}

func TestEIP7823ExceptionalHaltConsumesAllGas(t *testing.T) {
	config := delegationTestConfig(true)
	zero := uint64(0)
	config.ModernForkConfig().OsakaTime = &zero
	evm := NewEVM(Context{
		CanTransfer: func(StateDB, common.Address, *big.Int) bool { return true },
		Transfer:    func(StateDB, common.Address, common.Address, *big.Int) {},
		BlockNumber: big.NewInt(0),
		Time:        big.NewInt(0),
	}, newDelegationStateDB(), config, Config{})
	_, remaining, err := evm.Call(
		AccountRef(common.HexToAddress("0xca11")),
		common.BytesToAddress([]byte{0x05}),
		modExpInput(1025, 0, 0, nil, nil, nil),
		1_000_000,
		new(big.Int),
	)
	if !errors.Is(err, errModExpInputTooLarge) {
		t.Fatalf("oversized MODEXP error = %v, want %v", err, errModExpInputTooLarge)
	}
	if remaining != 0 {
		t.Fatalf("oversized MODEXP remaining gas = %d, want exceptional halt", remaining)
	}
}

func TestKZGPointEvaluationValidation(t *testing.T) {
	precompile := &kzgPointEvaluation{}
	if gas := precompile.RequiredGas(nil); gas != params.BlobTxPointEvaluationPrecompileGas {
		t.Fatalf("KZG gas = %d, want %d", gas, params.BlobTxPointEvaluationPrecompileGas)
	}
	if _, err := precompile.Run(make([]byte, blobVerifyInputLength-1)); !errors.Is(err, errBlobVerifyInvalidInputLength) {
		t.Fatalf("short KZG input error = %v", err)
	}
	if _, err := precompile.Run(make([]byte, blobVerifyInputLength)); !errors.Is(err, errBlobVerifyMismatchedVersion) {
		t.Fatalf("zero KZG input error = %v, want version mismatch", err)
	}
}

func TestP256Verify(t *testing.T) {
	curve := elliptic.P256()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("cypherium-osaka-p256verify"))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	input := make([]byte, 160)
	copy(input[:32], digest[:])
	r.FillBytes(input[32:64])
	s.FillBytes(input[64:96])
	key.X.FillBytes(input[96:128])
	key.Y.FillBytes(input[128:160])

	precompile := &p256Verify{}
	if gas := precompile.RequiredGas(input); gas != params.P256VerifyGas {
		t.Fatalf("P256VERIFY gas = %d, want %d", gas, params.P256VerifyGas)
	}
	result, err := precompile.Run(input)
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != string(true32Byte) {
		t.Fatalf("valid P256 signature result = %x, want %x", result, true32Byte)
	}
	validInput := append([]byte(nil), input...)
	input[0] ^= 1
	result, err = precompile.Run(input)
	if err != nil || result != nil {
		t.Fatalf("invalid P256 signature returned %x, %v", result, err)
	}

	withField := func(offset int, value *big.Int) []byte {
		invalid := append([]byte(nil), validInput...)
		for i := offset; i < offset+32; i++ {
			invalid[i] = 0
		}
		if value != nil {
			value.FillBytes(invalid[offset : offset+32])
		}
		return invalid
	}
	invalidInputs := map[string][]byte{
		"short input":        validInput[:159],
		"zero r":             withField(32, nil),
		"zero s":             withField(64, nil),
		"r at group order":   withField(32, curve.Params().N),
		"s at group order":   withField(64, curve.Params().N),
		"x at field modulus": withField(96, curve.Params().P),
		"y at field modulus": withField(128, curve.Params().P),
	}
	infinity := append([]byte(nil), validInput...)
	clear(infinity[96:160])
	invalidInputs["point at infinity"] = infinity
	offCurve := append([]byte(nil), validInput...)
	clear(offCurve[96:160])
	offCurve[127], offCurve[159] = 1, 1
	invalidInputs["off-curve point"] = offCurve
	for name, invalid := range invalidInputs {
		t.Run(name, func(t *testing.T) {
			result, err := precompile.Run(invalid)
			if err != nil || result != nil {
				t.Fatalf("invalid P256 input returned %x, %v", result, err)
			}
		})
	}
}

func TestFinalBLSGasSchedule(t *testing.T) {
	if gas := (&bls12381G1Add{}).RequiredGas(nil); gas != 375 {
		t.Fatalf("G1ADD gas = %d, want 375", gas)
	}
	if gas := (&bls12381G2Add{}).RequiredGas(nil); gas != 600 {
		t.Fatalf("G2ADD gas = %d, want 600", gas)
	}
	if gas := (&bls12381Pairing{}).RequiredGas(nil); gas != 37700 {
		t.Fatalf("pairing base gas = %d, want 37700", gas)
	}
	if gas := (&bls12381G1MultiExp{}).RequiredGas(make([]byte, 160)); gas != 12000 {
		t.Fatalf("one-term G1MSM gas = %d, want 12000", gas)
	}
	if gas := (&bls12381G2MultiExp{}).RequiredGas(make([]byte, 288)); gas != 22500 {
		t.Fatalf("one-term G2MSM gas = %d, want 22500", gas)
	}
}
