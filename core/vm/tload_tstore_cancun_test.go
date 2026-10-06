package vm

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
	"github.com/holiman/uint256"
)

func pushHash(st *Stack, h common.Hash) {
	v := new(uint256.Int)
	v.SetBytes(h.Bytes())
	st.push(v)
}

type transientStateDB struct {
	transient map[common.Address]map[common.Hash]common.Hash
}

func newTransientStateDB() *transientStateDB {
	return &transientStateDB{transient: make(map[common.Address]map[common.Hash]common.Hash)}
}

func (s *transientStateDB) GetTransientState(addr common.Address, key common.Hash) common.Hash {
	if slots := s.transient[addr]; slots != nil {
		return slots[key]
	}
	return common.Hash{}
}

func (s *transientStateDB) SetTransientState(addr common.Address, key, value common.Hash) {
	slots := s.transient[addr]
	if slots == nil {
		slots = make(map[common.Hash]common.Hash)
		s.transient[addr] = slots
	}
	slots[key] = value
}

func TestCancunHasTloadTstore(t *testing.T) {
	if cancunInstructionSet[TLOAD] == nil {
		t.Fatal("missing TLOAD in cancun jump table")
	}
	if cancunInstructionSet[TSTORE] == nil {
		t.Fatal("missing TSTORE in cancun jump table")
	}
	if shanghaiInstructionSet[TLOAD] != nil {
		t.Fatal("unexpected TLOAD in shanghai jump table")
	}
	if shanghaiInstructionSet[TSTORE] != nil {
		t.Fatal("unexpected TSTORE in shanghai jump table")
	}
}

func TestCancunOpcodeStringOverrides(t *testing.T) {
	if opCodeToString[TLOAD] != "TLOAD" {
		t.Fatalf("expected TLOAD string, got %q", opCodeToString[TLOAD])
	}
	if opCodeToString[TSTORE] != "TSTORE" {
		t.Fatalf("expected TSTORE string, got %q", opCodeToString[TSTORE])
	}
	if opCodeToString[MCOPY] != "MCOPY" {
		t.Fatalf("expected MCOPY string, got %q", opCodeToString[MCOPY])
	}
}

func TestMemoryMcopyExpandsForBothRanges(t *testing.T) {
	tests := []struct {
		name        string
		dst, src    uint64
		length      uint64
		wantMemSize uint64
	}{
		{name: "destination farther", dst: 96, src: 0, length: 32, wantMemSize: 128},
		{name: "source farther", dst: 0, src: 96, length: 32, wantMemSize: 128},
		{name: "zero length ignores offsets", dst: ^uint64(0), src: ^uint64(0), length: 0, wantMemSize: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stack := newstack()
			defer returnStack(stack)
			stack.push(uint256.NewInt(tt.length))
			stack.push(uint256.NewInt(tt.src))
			stack.push(uint256.NewInt(tt.dst))
			got, overflow := memoryMcopy(stack)
			if overflow {
				t.Fatal("unexpected memory size overflow")
			}
			if got != tt.wantMemSize {
				t.Fatalf("memoryMcopy() = %d, want %d", got, tt.wantMemSize)
			}
		})
	}
}

func TestMemoryMcopyRejectsWideSourceOffset(t *testing.T) {
	stack := newstack()
	defer returnStack(stack)
	wideSource := new(uint256.Int)
	wideSource.SetBytes(common.FromHex("0x10000000000000000"))
	stack.push(uint256.NewInt(1))
	stack.push(wideSource)
	stack.push(uint256.NewInt(0))
	if _, overflow := memoryMcopy(stack); !overflow {
		t.Fatal("expected overflow for source offset wider than uint64")
	}
}

func TestMcopyExecutionExpandsPartiallyOverlappingSource(t *testing.T) {
	// Copy [0x10, 0x30) into [0, 0x20). Expanding only the destination
	// would leave the source partially outside memory and used to panic in
	// Memory.GetCopy. EIP-5656 requires expansion through source+length.
	code := []byte{
		byte(PUSH1), 0x20,
		byte(PUSH1), 0x10,
		byte(PUSH1), 0x00,
		byte(MCOPY),
		byte(PUSH1), 0x20,
		byte(PUSH1), 0x00,
		byte(RETURN),
	}
	evm := &EVM{chainRules: params.Rules{IsCancun: true}}
	interpreter := NewEVMInterpreter(evm, Config{})
	addr := common.HexToAddress("0x1")
	contract := NewContract(AccountRef(addr), AccountRef(addr), new(big.Int), 100_000)
	contract.SetCallCode(&addr, common.Hash{}, code)

	output, err := interpreter.Run(contract, nil, false)
	if err != nil {
		t.Fatalf("MCOPY execution failed: %v", err)
	}
	if len(output) != 32 || !allZero(output) {
		t.Fatalf("MCOPY output = %x, want 32 zero bytes", output)
	}
}

func TestTloadDefaultZeroAndTstoreRoundTrip(t *testing.T) {
	st := newTransientStateDB()
	contract := NewContract(AccountRef(common.HexToAddress("0x1")), AccountRef(common.HexToAddress("0x1")), nil, 0)
	interpreter := &EVMInterpreter{evm: &EVM{StateDB: st}}
	stack := newstack()
	defer returnStack(stack)
	ctx := &callCtx{stack: stack, contract: contract}
	key := common.HexToHash("0x1")

	pushHash(stack, key)
	if _, err := opTload(nil, interpreter, ctx); err != nil {
		t.Fatalf("tload failed: %v", err)
	}
	if got := common.Hash(stack.peek().Bytes32()); got != (common.Hash{}) {
		t.Fatalf("expected zero, got %x", got)
	}

	pushHash(stack, common.HexToHash("0x99"))
	pushHash(stack, key)
	if _, err := opTstore(nil, interpreter, ctx); err != nil {
		t.Fatalf("tstore failed: %v", err)
	}
	pushHash(stack, key)
	if _, err := opTload(nil, interpreter, ctx); err != nil {
		t.Fatalf("tload failed: %v", err)
	}
	if got := common.Hash(stack.peek().Bytes32()); got != common.HexToHash("0x99") {
		t.Fatalf("expected 0x99, got %x", got)
	}
}

func TestTstoreWriteProtectionReadOnly(t *testing.T) {
	st := newTransientStateDB()
	contract := NewContract(AccountRef(common.HexToAddress("0x1")), AccountRef(common.HexToAddress("0x1")), nil, 0)
	interpreter := &EVMInterpreter{evm: &EVM{StateDB: st}, readOnly: true}
	stack := newstack()
	defer returnStack(stack)
	ctx := &callCtx{stack: stack, contract: contract}
	pushHash(stack, common.HexToHash("0x2"))
	pushHash(stack, common.HexToHash("0x1"))
	if _, err := opTstore(nil, interpreter, ctx); err != ErrWriteProtection {
		t.Fatalf("expected ErrWriteProtection, got %v", err)
	}
}

var _ StateDB = (*transientStateDB)(nil)

func (*transientStateDB) CreateAccount(common.Address)           {}
func (*transientStateDB) CreateContract(common.Address)          {}
func (*transientStateDB) CreatedContract(common.Address) bool    { return false }
func (*transientStateDB) SubBalance(common.Address, *big.Int)    {}
func (*transientStateDB) AddBalance(common.Address, *big.Int)    {}
func (*transientStateDB) GetBalance(common.Address) *big.Int     { return nil }
func (*transientStateDB) GetNonce(common.Address) uint64         { return 0 }
func (*transientStateDB) SetNonce(common.Address, uint64)        {}
func (*transientStateDB) GetCodeHash(common.Address) common.Hash { return common.Hash{} }
func (*transientStateDB) GetCode(common.Address) []byte          { return nil }
func (*transientStateDB) SetCode(common.Address, []byte)         {}
func (*transientStateDB) GetCodeSize(common.Address) int         { return 0 }
func (*transientStateDB) AddRefund(uint64)                       {}
func (*transientStateDB) SubRefund(uint64)                       {}
func (*transientStateDB) GetRefund() uint64                      { return 0 }
func (*transientStateDB) GetCommittedState(common.Address, common.Hash) common.Hash {
	return common.Hash{}
}
func (*transientStateDB) GetState(common.Address, common.Hash) common.Hash  { return common.Hash{} }
func (*transientStateDB) GetStorageRoot(common.Address) common.Hash         { return common.Hash{} }
func (*transientStateDB) SetState(common.Address, common.Hash, common.Hash) {}
func (*transientStateDB) Suicide(common.Address) bool                       { return false }
func (*transientStateDB) HasSuicided(common.Address) bool                   { return false }
func (*transientStateDB) Exist(common.Address) bool                         { return false }
func (*transientStateDB) Empty(common.Address) bool                         { return false }
func (*transientStateDB) RevertToSnapshot(int)                              {}
func (*transientStateDB) Snapshot() int                                     { return 0 }
func (*transientStateDB) AddLog(*types.Log)                                 {}
func (*transientStateDB) AddPreimage(common.Hash, []byte)                   {}
func (*transientStateDB) PrepareAccessList(common.Address, *common.Address, []common.Address, types.AccessList) {
}
func (*transientStateDB) AddAddressToAccessList(common.Address)           {}
func (*transientStateDB) AddSlotToAccessList(common.Address, common.Hash) {}
func (*transientStateDB) AddressInAccessList(common.Address) bool         { return false }
func (*transientStateDB) SlotInAccessList(common.Address, common.Hash) (bool, bool) {
	return false, false
}
func (*transientStateDB) ForEachStorage(common.Address, func(common.Hash, common.Hash) bool) error {
	return nil
}
