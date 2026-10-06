package vm

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
	"github.com/holiman/uint256"
)

type selfdestructStateDB struct {
	balance          map[common.Address]*big.Int
	suicided         map[common.Address]bool
	createdContracts map[common.Address]bool
}

func newSelfdestructStateDB() *selfdestructStateDB {
	return &selfdestructStateDB{balance: map[common.Address]*big.Int{}, suicided: map[common.Address]bool{}, createdContracts: map[common.Address]bool{}}
}

func (s *selfdestructStateDB) AddBalance(addr common.Address, amount *big.Int) {
	s.balance[addr] = new(big.Int).Add(s.GetBalance(addr), amount)
}
func (s *selfdestructStateDB) SubBalance(addr common.Address, amount *big.Int) {
	s.balance[addr] = new(big.Int).Sub(s.GetBalance(addr), amount)
}
func (s *selfdestructStateDB) GetBalance(addr common.Address) *big.Int {
	if b, ok := s.balance[addr]; ok {
		return new(big.Int).Set(b)
	}
	return new(big.Int)
}
func (s *selfdestructStateDB) Suicide(addr common.Address) bool {
	s.suicided[addr] = true
	s.balance[addr] = new(big.Int)
	return true
}
func (s *selfdestructStateDB) CreateContract(addr common.Address) { s.createdContracts[addr] = true }
func (s *selfdestructStateDB) CreatedContract(addr common.Address) bool {
	return s.createdContracts[addr]
}
func (*selfdestructStateDB) CreateAccount(common.Address)           {}
func (*selfdestructStateDB) GetNonce(common.Address) uint64         { return 0 }
func (*selfdestructStateDB) SetNonce(common.Address, uint64)        {}
func (*selfdestructStateDB) GetCodeHash(common.Address) common.Hash { return common.Hash{} }
func (*selfdestructStateDB) GetCode(common.Address) []byte          { return nil }
func (*selfdestructStateDB) SetCode(common.Address, []byte)         {}
func (*selfdestructStateDB) GetCodeSize(common.Address) int         { return 0 }
func (*selfdestructStateDB) AddRefund(uint64)                       {}
func (*selfdestructStateDB) SubRefund(uint64)                       {}
func (*selfdestructStateDB) GetRefund() uint64                      { return 0 }
func (*selfdestructStateDB) GetCommittedState(common.Address, common.Hash) common.Hash {
	return common.Hash{}
}
func (*selfdestructStateDB) GetState(common.Address, common.Hash) common.Hash  { return common.Hash{} }
func (*selfdestructStateDB) GetStorageRoot(common.Address) common.Hash         { return common.Hash{} }
func (*selfdestructStateDB) SetState(common.Address, common.Hash, common.Hash) {}
func (*selfdestructStateDB) HasSuicided(common.Address) bool                   { return false }
func (*selfdestructStateDB) Exist(common.Address) bool                         { return true }
func (*selfdestructStateDB) Empty(common.Address) bool                         { return false }
func (*selfdestructStateDB) RevertToSnapshot(int)                              {}
func (*selfdestructStateDB) Snapshot() int                                     { return 0 }
func (*selfdestructStateDB) AddLog(*types.Log)                                 {}
func (*selfdestructStateDB) AddPreimage(common.Hash, []byte)                   {}
func (*selfdestructStateDB) GetTransientState(common.Address, common.Hash) common.Hash {
	return common.Hash{}
}
func (*selfdestructStateDB) SetTransientState(common.Address, common.Hash, common.Hash) {}
func (*selfdestructStateDB) PrepareAccessList(common.Address, *common.Address, []common.Address, types.AccessList) {
}
func (*selfdestructStateDB) AddAddressToAccessList(common.Address)           {}
func (*selfdestructStateDB) AddSlotToAccessList(common.Address, common.Hash) {}
func (*selfdestructStateDB) AddressInAccessList(common.Address) bool         { return false }
func (*selfdestructStateDB) SlotInAccessList(common.Address, common.Hash) (addressOk bool, slotOk bool) {
	return false, false
}
func (*selfdestructStateDB) ForEachStorage(common.Address, func(common.Hash, common.Hash) bool) error {
	return nil
}

func TestSelfdestructCancunSemantics(t *testing.T) {
	contractAddr := common.HexToAddress("0x100")
	beneficiary := common.HexToAddress("0x200")
	cases := []struct {
		name          string
		isCancun      bool
		sameTxCreated bool
		wantSuicide   bool
	}{
		{"pre-cancun", false, false, true},
		{"cancun-existing-contract", true, false, false},
		{"cancun-same-tx-created", true, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newSelfdestructStateDB()
			st.balance[contractAddr] = big.NewInt(9)
			st.createdContracts[contractAddr] = tc.sameTxCreated
			evm := &EVM{StateDB: st, chainRules: params.Rules{IsCancun: tc.isCancun}}
			interpreter := &EVMInterpreter{evm: evm}
			contract := NewContract(AccountRef(contractAddr), AccountRef(contractAddr), big.NewInt(0), 0)
			stack := newstack()
			defer returnStack(stack)
			stack.push(new(uint256.Int).SetBytes(beneficiary.Bytes()))
			_, err := opSuicide(nil, interpreter, &callCtx{stack: stack, contract: contract})
			if err != nil {
				t.Fatalf("opSuicide error: %v", err)
			}
			if st.suicided[contractAddr] != tc.wantSuicide {
				t.Fatalf("suicide=%v want %v", st.suicided[contractAddr], tc.wantSuicide)
			}
			if got := st.GetBalance(beneficiary); got.Cmp(big.NewInt(9)) != 0 {
				t.Fatalf("beneficiary balance=%v want 9", got)
			}
			wantContract := big.NewInt(0)
			if got := st.GetBalance(contractAddr); got.Cmp(wantContract) != 0 {
				t.Fatalf("contract balance=%v want %v", got, wantContract)
			}
		})
	}
}

func TestSelfdestructCancunExistingContractNoBalanceMintWhenBeneficiarySelf(t *testing.T) {
	st := newSelfdestructStateDB()
	contractAddr := common.HexToAddress("0x100")
	st.balance[contractAddr] = big.NewInt(9)
	evm := &EVM{StateDB: st, chainRules: params.Rules{IsCancun: true}}
	interpreter := &EVMInterpreter{evm: evm}
	contract := NewContract(AccountRef(contractAddr), AccountRef(contractAddr), big.NewInt(0), 0)
	stack := newstack()
	defer returnStack(stack)
	stack.push(new(uint256.Int).SetBytes(contractAddr.Bytes()))
	_, err := opSuicide(nil, interpreter, &callCtx{stack: stack, contract: contract})
	if err != nil {
		t.Fatalf("opSuicide error: %v", err)
	}
	if st.suicided[contractAddr] {
		t.Fatal("expected no suicide for Cancun existing contract")
	}
	if got := st.GetBalance(contractAddr); got.Cmp(big.NewInt(9)) != 0 {
		t.Fatalf("self beneficiary should not mint balance; got %v want 9", got)
	}
}

func TestSelfdestructWriteProtectionReadOnly(t *testing.T) {
	st := newSelfdestructStateDB()
	contractAddr := common.HexToAddress("0x100")
	beneficiary := common.HexToAddress("0x200")
	st.balance[contractAddr] = big.NewInt(5)
	interpreter := &EVMInterpreter{
		evm:      &EVM{StateDB: st, chainRules: params.Rules{IsCancun: true}},
		readOnly: true,
	}
	contract := NewContract(AccountRef(contractAddr), AccountRef(contractAddr), big.NewInt(0), 0)
	stack := newstack()
	defer returnStack(stack)
	stack.push(new(uint256.Int).SetBytes(beneficiary.Bytes()))
	if _, err := opSuicide(nil, interpreter, &callCtx{stack: stack, contract: contract}); err != ErrWriteProtection {
		t.Fatalf("expected ErrWriteProtection, got %v", err)
	}
	if got := st.GetBalance(beneficiary); got.Sign() != 0 {
		t.Fatalf("beneficiary balance changed in readOnly context: %v", got)
	}
}
