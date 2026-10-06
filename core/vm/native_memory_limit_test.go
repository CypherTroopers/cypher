package vm

import (
	"errors"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/params"
)

func TestInterpreterEnforcesNativeMemoryLimitBeforeAllocation(t *testing.T) {
	// MSTORE at offset 0x20 expands memory to 64 bytes.
	code := []byte{byte(PUSH1), 0x01, byte(PUSH1), 0x20, byte(MSTORE), byte(STOP)}
	evm := &EVM{chainRules: params.Rules{}}
	interpreter := NewEVMInterpreter(evm, Config{MaxMemoryBytes: 32})
	address := common.HexToAddress("0x1")
	contract := NewContract(AccountRef(address), AccountRef(address), new(big.Int), 100_000)
	contract.SetCallCode(&address, common.Hash{}, code)

	if _, err := interpreter.Run(contract, nil, false); !errors.Is(err, ErrMemoryLimitExceeded) {
		t.Fatalf("memory expansion error = %v, want %v", err, ErrMemoryLimitExceeded)
	}
}

func TestInterpreterMemoryLimitZeroPreservesLegacyBehavior(t *testing.T) {
	code := []byte{byte(PUSH1), 0x01, byte(PUSH1), 0x20, byte(MSTORE), byte(STOP)}
	evm := &EVM{chainRules: params.Rules{}}
	interpreter := NewEVMInterpreter(evm, Config{})
	address := common.HexToAddress("0x1")
	contract := NewContract(AccountRef(address), AccountRef(address), new(big.Int), 100_000)
	contract.SetCallCode(&address, common.Hash{}, code)
	if _, err := interpreter.Run(contract, nil, false); err != nil {
		t.Fatalf("legacy unlimited memory execution failed: %v", err)
	}
}

func TestInterpreterMemoryLimitIsSharedAcrossNestedFrames(t *testing.T) {
	const recurseOp = OpCode(0xaa)
	innerCode := []byte{byte(PUSH1), 0x01, byte(PUSH1), 0x00, byte(MSTORE), byte(STOP)}
	jumpTable := frontierInstructionSet
	jumpTable[recurseOp] = &operation{
		execute: func(_ *uint64, interpreter *EVMInterpreter, _ *callCtx) ([]byte, error) {
			address := common.HexToAddress("0x2")
			contract := NewContract(AccountRef(address), AccountRef(address), new(big.Int), 100_000)
			contract.SetCallCode(&address, common.Hash{}, innerCode)
			return interpreter.Run(contract, nil, false)
		},
		maxStack: 1024,
		halts:    true,
	}
	// The outer and inner frames each request 32 bytes. Each frame is below the
	// signed limit, but their simultaneously live aggregate is not.
	outerCode := []byte{byte(PUSH1), 0x01, byte(PUSH1), 0x00, byte(MSTORE), byte(recurseOp)}
	evm := &EVM{chainRules: params.Rules{}}
	interpreter := NewEVMInterpreter(evm, Config{MaxMemoryBytes: 32, JumpTable: jumpTable})
	address := common.HexToAddress("0x1")
	contract := NewContract(AccountRef(address), AccountRef(address), new(big.Int), 100_000)
	contract.SetCallCode(&address, common.Hash{}, outerCode)

	if _, err := interpreter.Run(contract, nil, false); !errors.Is(err, ErrMemoryLimitExceeded) {
		t.Fatalf("nested memory expansion error = %v, want %v", err, ErrMemoryLimitExceeded)
	}
	if interpreter.memoryUsed != 0 {
		t.Fatalf("nested execution leaked %d metered memory bytes", interpreter.memoryUsed)
	}
}

func TestInterpreterRejectsReturnDataBeforeCopy(t *testing.T) {
	// Store one word then return all 32 bytes. The signed output budget is
	// checked before Run can publish/copy the returned slice.
	code := []byte{
		byte(PUSH1), 0x01, byte(PUSH1), 0x00, byte(MSTORE),
		byte(PUSH1), 0x20, byte(PUSH1), 0x00, byte(RETURN),
	}
	evm := &EVM{chainRules: params.Rules{}}
	interpreter := NewEVMInterpreter(evm, Config{MaxMemoryBytes: 64, MaxReturnDataBytes: 31})
	address := common.HexToAddress("0x3")
	contract := NewContract(AccountRef(address), AccountRef(address), new(big.Int), 100_000)
	contract.SetCallCode(&address, common.Hash{}, code)
	if _, err := interpreter.Run(contract, nil, false); !errors.Is(err, ErrReturnDataLimitExceeded) {
		t.Fatalf("return data error = %v, want %v", err, ErrReturnDataLimitExceeded)
	}

	interpreter = NewEVMInterpreter(evm, Config{MaxMemoryBytes: 64, MaxReturnDataBytes: 32})
	if output, err := interpreter.Run(contract, nil, false); err != nil || len(output) != 32 {
		t.Fatalf("exact output boundary len/error = %d/%v", len(output), err)
	}
}

func TestMemoryResizeUsesAmortizedCapacity(t *testing.T) {
	memory := NewMemory()
	capacityChanges := 0
	previousCapacity := cap(memory.store)
	for size := uint64(32); size <= 1<<20; size += 32 {
		memory.Resize(size)
		if cap(memory.store) != previousCapacity {
			capacityChanges++
			previousCapacity = cap(memory.store)
		}
	}
	if memory.Len() != 1<<20 {
		t.Fatalf("memory len = %d, want %d", memory.Len(), 1<<20)
	}
	if capacityChanges > 16 {
		t.Fatalf("1 MiB incremental growth reallocated %d times", capacityChanges)
	}
}
