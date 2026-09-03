package vm

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cypherium/cypher/common"
)

func TestNativePrecompileRejectsOutputBeforeRun(t *testing.T) {
	input := make([]byte, 96)
	binary.BigEndian.PutUint64(input[88:96], 2<<20) // ModExp modulus/output length

	_, remaining, err := runPrecompiledContractWithLimits(
		&modernBigModExp{}, input, ^uint64(0), 64<<20, 1<<20,
	)
	if !errors.Is(err, ErrReturnDataLimitExceeded) {
		t.Fatalf("error = %v, want %v", err, ErrReturnDataLimitExceeded)
	}
	if remaining != 0 {
		t.Fatalf("remaining gas = %d, want exceptional halt", remaining)
	}
}

func TestNativePrecompileRejectsUnmeteredWorkMemory(t *testing.T) {
	input := make([]byte, 128)
	required, output, known := precompileResourceBounds(&ecrecover{}, input)
	if !known || output != 32 || required == 0 {
		t.Fatalf("unexpected resource bound: memory=%d output=%d known=%t", required, output, known)
	}
	_, _, err := runPrecompiledContractWithLimits(
		&ecrecover{}, input, ^uint64(0), required-1, output,
	)
	if !errors.Is(err, ErrMemoryLimitExceeded) {
		t.Fatalf("error = %v, want %v", err, ErrMemoryLimitExceeded)
	}
}

func TestLegacyPrecompileResourceLimitsRemainDisabled(t *testing.T) {
	input := make([]byte, 4096)
	output, _, err := RunPrecompiledContract(&dataCopy{}, input, ^uint64(0))
	if err != nil {
		t.Fatalf("legacy identity failed: %v", err)
	}
	if len(output) != len(input) {
		t.Fatalf("output length = %d, want %d", len(output), len(input))
	}
}

func TestAllActivePrecompilesHaveNativeResourceBounds(t *testing.T) {
	contractSets := []map[common.Address]PrecompiledContract{
		PrecompiledContractsHomestead,
		PrecompiledContractsByzantium,
		PrecompiledContractsIstanbul,
		PrecompiledContractsYoloV1,
		PrecompiledContractsBerlin,
		PrecompiledContractsCancun,
		PrecompiledContractsPrague,
		PrecompiledContractsOsaka,
	}
	for setIndex, contracts := range contractSets {
		for address, contract := range contracts {
			if _, _, known := precompileResourceBounds(contract, nil); !known {
				t.Fatalf("set %d precompile %s (%T) has no Native resource bound", setIndex, address, contract)
			}
		}
	}
}

func TestBLS12381PairingChargesMillerCoefficientHeap(t *testing.T) {
	const (
		pairs                   = uint64(4)
		pairInputBytes          = uint64(384)
		millerCoefficientsBytes = uint64(68 * 3 * 2 * 6 * 8)
	)
	memory, output, known := precompileResourceBounds(&bls12381Pairing{}, make([]byte, pairs*pairInputBytes))
	minimum := pairs*millerCoefficientsBytes + pairs*pairInputBytes
	if !known || output != 32 || memory < minimum {
		t.Fatalf("pairing bound memory/output/known = %d/%d/%t, want memory >= %d", memory, output, known, minimum)
	}

	// The largest multiple-of-384 payload inside the 1 MiB transaction limit
	// remains expressible by the genesis 64 MiB signed memory field.
	maxPairs := uint64((1 << 20) / pairInputBytes)
	memory, _, known = precompileResourceBounds(&bls12381Pairing{}, make([]byte, maxPairs*pairInputBytes))
	if !known || memory > 64<<20 {
		t.Fatalf("maximum pairing payload bound = %d bytes, want <= 64 MiB", memory)
	}
}

func TestNestedPrecompileAggregatesCallerMemory(t *testing.T) {
	input := make([]byte, 128)
	workMemory, output, known := precompileResourceBounds(&dataCopy{}, input)
	if !known || workMemory != 256 || output != 128 {
		t.Fatalf("identity resource bound = %d/%d/%t", workMemory, output, known)
	}
	// Nested calldata aliases one already-metered input image, leaving a
	// 128-byte incremental RETURNDATA charge.
	const liveMemory = uint64(100)
	if _, _, err := runPrecompiledContractWithUsage(
		&dataCopy{}, input, ^uint64(0), liveMemory+128, output, liveMemory, true,
	); err != nil {
		t.Fatalf("exact aggregate boundary failed: %v", err)
	}
	if _, _, err := runPrecompiledContractWithUsage(
		&dataCopy{}, input, ^uint64(0), liveMemory+127, output, liveMemory, true,
	); !errors.Is(err, ErrMemoryLimitExceeded) {
		t.Fatalf("aggregate overflow error = %v, want %v", err, ErrMemoryLimitExceeded)
	}
	// Top-level calldata has no parent linear-memory reservation and therefore
	// requires the complete input+output charge.
	if _, _, err := runPrecompiledContractWithUsage(
		&dataCopy{}, input, ^uint64(0), workMemory-1, output, 0, false,
	); !errors.Is(err, ErrMemoryLimitExceeded) {
		t.Fatalf("top-level charge error = %v, want %v", err, ErrMemoryLimitExceeded)
	}
}
