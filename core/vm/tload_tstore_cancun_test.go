package vm

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
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
