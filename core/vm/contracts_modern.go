// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package vm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/cypherium/cypher/common"
	commonmath "github.com/cypherium/cypher/common/math"
	"github.com/cypherium/cypher/crypto/kzg4844"
	"github.com/cypherium/cypher/params"
)

// PrecompiledContractsBerlin contains the precompiles enabled from Berlin
// through Shanghai. ModExp uses the EIP-2565 gas schedule in this set.
var PrecompiledContractsBerlin = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{0x01}): &ecrecover{},
	common.BytesToAddress([]byte{0x02}): &sha256hash{},
	common.BytesToAddress([]byte{0x03}): &ripemd160hash{},
	common.BytesToAddress([]byte{0x04}): &dataCopy{},
	common.BytesToAddress([]byte{0x05}): &modernBigModExp{},
	common.BytesToAddress([]byte{0x06}): &bn256AddIstanbul{},
	common.BytesToAddress([]byte{0x07}): &bn256ScalarMulIstanbul{},
	common.BytesToAddress([]byte{0x08}): &bn256PairingIstanbul{},
	common.BytesToAddress([]byte{0x09}): &blake2F{},
}

// PrecompiledContractsCancun contains the Berlin set plus the EIP-4844 point
// evaluation precompile.
var PrecompiledContractsCancun = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{0x01}): &ecrecover{},
	common.BytesToAddress([]byte{0x02}): &sha256hash{},
	common.BytesToAddress([]byte{0x03}): &ripemd160hash{},
	common.BytesToAddress([]byte{0x04}): &dataCopy{},
	common.BytesToAddress([]byte{0x05}): &modernBigModExp{},
	common.BytesToAddress([]byte{0x06}): &bn256AddIstanbul{},
	common.BytesToAddress([]byte{0x07}): &bn256ScalarMulIstanbul{},
	common.BytesToAddress([]byte{0x08}): &bn256PairingIstanbul{},
	common.BytesToAddress([]byte{0x09}): &blake2F{},
	common.BytesToAddress([]byte{0x0a}): &kzgPointEvaluation{},
}

// PrecompiledContractsPrague contains the final EIP-2537 BLS12-381 address
// allocation. In particular, the standalone draft G1Mul/G2Mul contracts are
// not exposed.
var PrecompiledContractsPrague = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{0x01}): &ecrecover{},
	common.BytesToAddress([]byte{0x02}): &sha256hash{},
	common.BytesToAddress([]byte{0x03}): &ripemd160hash{},
	common.BytesToAddress([]byte{0x04}): &dataCopy{},
	common.BytesToAddress([]byte{0x05}): &modernBigModExp{},
	common.BytesToAddress([]byte{0x06}): &bn256AddIstanbul{},
	common.BytesToAddress([]byte{0x07}): &bn256ScalarMulIstanbul{},
	common.BytesToAddress([]byte{0x08}): &bn256PairingIstanbul{},
	common.BytesToAddress([]byte{0x09}): &blake2F{},
	common.BytesToAddress([]byte{0x0a}): &kzgPointEvaluation{},
	common.BytesToAddress([]byte{0x0b}): &bls12381G1Add{},
	common.BytesToAddress([]byte{0x0c}): &bls12381G1MultiExp{},
	common.BytesToAddress([]byte{0x0d}): &bls12381G2Add{},
	common.BytesToAddress([]byte{0x0e}): &bls12381G2MultiExp{},
	common.BytesToAddress([]byte{0x0f}): &bls12381Pairing{},
	common.BytesToAddress([]byte{0x10}): &bls12381MapG1{},
	common.BytesToAddress([]byte{0x11}): &bls12381MapG2{},
}

// PrecompiledContractsOsaka adds EIP-7951 P256VERIFY and switches ModExp to
// the EIP-7823 input cap and EIP-7883 gas schedule.
var PrecompiledContractsOsaka = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{0x01}):       &ecrecover{},
	common.BytesToAddress([]byte{0x02}):       &sha256hash{},
	common.BytesToAddress([]byte{0x03}):       &ripemd160hash{},
	common.BytesToAddress([]byte{0x04}):       &dataCopy{},
	common.BytesToAddress([]byte{0x05}):       &modernBigModExp{eip7823: true, eip7883: true},
	common.BytesToAddress([]byte{0x06}):       &bn256AddIstanbul{},
	common.BytesToAddress([]byte{0x07}):       &bn256ScalarMulIstanbul{},
	common.BytesToAddress([]byte{0x08}):       &bn256PairingIstanbul{},
	common.BytesToAddress([]byte{0x09}):       &blake2F{},
	common.BytesToAddress([]byte{0x0a}):       &kzgPointEvaluation{},
	common.BytesToAddress([]byte{0x0b}):       &bls12381G1Add{},
	common.BytesToAddress([]byte{0x0c}):       &bls12381G1MultiExp{},
	common.BytesToAddress([]byte{0x0d}):       &bls12381G2Add{},
	common.BytesToAddress([]byte{0x0e}):       &bls12381G2MultiExp{},
	common.BytesToAddress([]byte{0x0f}):       &bls12381Pairing{},
	common.BytesToAddress([]byte{0x10}):       &bls12381MapG1{},
	common.BytesToAddress([]byte{0x11}):       &bls12381MapG2{},
	common.BytesToAddress([]byte{0x01, 0x00}): &p256Verify{},
}

// modernBigModExp is the EIP-2565 ModExp contract. Osaka enables the optional
// EIP-7823 operand-size limit and EIP-7883 gas schedule.
type modernBigModExp struct {
	eip7823 bool
	eip7883 bool
}

var errModExpInputTooLarge = errors.New("one or more of base/exponent/modulus length exceeded 1024 bytes")

func modExpLengths(input []byte) (baseLen, expLen, modLen *big.Int) {
	return new(big.Int).SetBytes(getData(input, 0, 32)),
		new(big.Int).SetBytes(getData(input, 32, 32)),
		new(big.Int).SetBytes(getData(input, 64, 32))
}

func modExpPayload(input []byte) []byte {
	if len(input) > 96 {
		return input[96:]
	}
	return input[:0]
}

func modExpIterationCount(expLen, expHead *big.Int, multiplier uint64) *big.Int {
	count := new(big.Int)
	if expLen.Cmp(big32) > 0 {
		count.Sub(expLen, big32)
		count.Mul(count, new(big.Int).SetUint64(multiplier))
	}
	if bits := expHead.BitLen(); bits > 0 {
		count.Add(count, new(big.Int).SetUint64(uint64(bits-1)))
	}
	if count.Sign() == 0 {
		count.SetUint64(1)
	}
	return count
}

func berlinModExpComplexity(maxLen *big.Int) *big.Int {
	words := new(big.Int).Add(maxLen, big.NewInt(7))
	words.Div(words, big8)
	return words.Mul(words, words)
}

func osakaModExpComplexity(maxLen *big.Int) *big.Int {
	if maxLen.Cmp(big32) <= 0 {
		return big.NewInt(16)
	}
	complexity := berlinModExpComplexity(maxLen)
	return complexity.Mul(complexity, big.NewInt(2))
}

func modExpGasUint64(gas *big.Int) uint64 {
	if gas.Sign() < 0 || gas.BitLen() > 64 {
		return commonmath.MaxUint64
	}
	return gas.Uint64()
}

func (c *modernBigModExp) RequiredGas(input []byte) uint64 {
	baseLen, expLen, modLen := modExpLengths(input)
	payload := modExpPayload(input)

	expHead := new(big.Int)
	if baseLen.IsUint64() && uint64(len(payload)) > baseLen.Uint64() {
		headLen := uint64(32)
		if expLen.IsUint64() && expLen.Uint64() < headLen {
			headLen = expLen.Uint64()
		}
		expHead.SetBytes(getData(payload, baseLen.Uint64(), headLen))
	}
	maxLen := new(big.Int).Set(baseLen)
	if modLen.Cmp(maxLen) > 0 {
		maxLen.Set(modLen)
	}

	var gas *big.Int
	if c.eip7883 {
		gas = osakaModExpComplexity(maxLen)
		gas.Mul(gas, modExpIterationCount(expLen, expHead, 16))
		if gas.Cmp(big.NewInt(500)) < 0 {
			gas.SetUint64(500)
		}
	} else {
		gas = berlinModExpComplexity(maxLen)
		gas.Mul(gas, modExpIterationCount(expLen, expHead, 8))
		gas.Div(gas, big.NewInt(3))
		if gas.Cmp(big.NewInt(200)) < 0 {
			gas.SetUint64(200)
		}
	}
	return modExpGasUint64(gas)
}

func (c *modernBigModExp) Run(input []byte) ([]byte, error) {
	baseLenBig, expLenBig, modLenBig := modExpLengths(input)
	if c.eip7823 {
		limit := big.NewInt(1024)
		if baseLenBig.Cmp(limit) > 0 || expLenBig.Cmp(limit) > 0 || modLenBig.Cmp(limit) > 0 {
			return nil, errModExpInputTooLarge
		}
	}
	baseLen, expLen, modLen := baseLenBig.Uint64(), expLenBig.Uint64(), modLenBig.Uint64()
	payload := modExpPayload(input)
	if baseLen == 0 && modLen == 0 {
		return []byte{}, nil
	}
	base := new(big.Int).SetBytes(getData(payload, 0, baseLen))
	exponent := new(big.Int).SetBytes(getData(payload, baseLen, expLen))
	modulus := new(big.Int).SetBytes(getData(payload, baseLen+expLen, modLen))
	if modulus.Sign() == 0 {
		return common.LeftPadBytes(nil, int(modLen)), nil
	}
	return common.LeftPadBytes(base.Exp(base, exponent, modulus).Bytes(), int(modLen)), nil
}

// kzgPointEvaluation implements the EIP-4844 point-evaluation precompile.
type kzgPointEvaluation struct{}

const (
	blobVerifyInputLength          = 192
	blobCommitmentVersionKZG  byte = 0x01
	blobPrecompileReturnValue      = "000000000000000000000000000000000000000000000000000000000000100073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
)

var (
	errBlobVerifyInvalidInputLength = errors.New("invalid input length")
	errBlobVerifyMismatchedVersion  = errors.New("mismatched versioned hash")
	errBlobVerifyKZGProof           = errors.New("error verifying kzg proof")
)

func (c *kzgPointEvaluation) RequiredGas(input []byte) uint64 {
	return params.BlobTxPointEvaluationPrecompileGas
}

func (c *kzgPointEvaluation) Run(input []byte) ([]byte, error) {
	if len(input) != blobVerifyInputLength {
		return nil, errBlobVerifyInvalidInputLength
	}
	var (
		versionedHash common.Hash
		point         kzg4844.Point
		claim         kzg4844.Claim
		commitment    kzg4844.Commitment
		proof         kzg4844.Proof
	)
	copy(versionedHash[:], input[:32])
	copy(point[:], input[32:64])
	copy(claim[:], input[64:96])
	copy(commitment[:], input[96:144])
	copy(proof[:], input[144:192])
	if kzgToVersionedHash(commitment) != versionedHash {
		return nil, errBlobVerifyMismatchedVersion
	}
	if err := kzg4844.VerifyProof(commitment, point, claim, proof); err != nil {
		return nil, fmt.Errorf("%w: %v", errBlobVerifyKZGProof, err)
	}
	return common.Hex2Bytes(blobPrecompileReturnValue), nil
}

func kzgToVersionedHash(commitment kzg4844.Commitment) common.Hash {
	hash := sha256.Sum256(commitment[:])
	hash[0] = blobCommitmentVersionKZG
	return hash
}

// p256Verify implements the EIP-7951 P256VERIFY precompile.
type p256Verify struct{}

func (c *p256Verify) RequiredGas(input []byte) uint64 {
	return params.P256VerifyGas
}

func (c *p256Verify) Run(input []byte) ([]byte, error) {
	const p256VerifyInputLength = 160
	if len(input) != p256VerifyInputLength {
		return nil, nil
	}
	hash := input[:32]
	r := new(big.Int).SetBytes(input[32:64])
	s := new(big.Int).SetBytes(input[64:96])
	x := new(big.Int).SetBytes(input[96:128])
	y := new(big.Int).SetBytes(input[128:160])
	curve := elliptic.P256()
	if !curve.IsOnCurve(x, y) {
		return nil, nil
	}
	key := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	if !ecdsa.Verify(key, hash, r, s) {
		return nil, nil
	}
	return true32Byte, nil
}
