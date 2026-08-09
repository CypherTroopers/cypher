package vm

import (
	"errors"
	"math"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/params"
	"github.com/holiman/uint256"
)

type refundGasStateDB struct {
	*selfdestructStateDB
	refund    uint64
	current   common.Hash
	original  common.Hash
	slotWarm  bool
	lastSlot  common.Hash
	lastOwner common.Address
}

func newRefundGasStateDB() *refundGasStateDB {
	return &refundGasStateDB{selfdestructStateDB: newSelfdestructStateDB()}
}

func (s *refundGasStateDB) AddRefund(gas uint64) { s.refund += gas }
func (s *refundGasStateDB) SubRefund(gas uint64) { s.refund -= gas }
func (s *refundGasStateDB) GetRefund() uint64    { return s.refund }
func (s *refundGasStateDB) GetState(common.Address, common.Hash) common.Hash {
	return s.current
}
func (s *refundGasStateDB) GetCommittedState(common.Address, common.Hash) common.Hash {
	return s.original
}
func (s *refundGasStateDB) SlotInAccessList(common.Address, common.Hash) (bool, bool) {
	return s.slotWarm, s.slotWarm
}
func (s *refundGasStateDB) AddSlotToAccessList(owner common.Address, slot common.Hash) {
	s.slotWarm = true
	s.lastOwner = owner
	s.lastSlot = slot
}

func TestCreateInitCodeWordGasEIP3860(t *testing.T) {
	stack := newstack()
	defer returnStack(stack)
	stack.push(new(uint256.Int).SetUint64(33)) // size (Back(2))
	stack.push(new(uint256.Int))               // offset
	stack.push(new(uint256.Int))               // value
	gas, err := gasCreateEIP3860(nil, nil, stack, NewMemory(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if want := uint64(2 * params.InitCodeWordGas); gas != want {
		t.Fatalf("CREATE initcode gas = %d, want %d", gas, want)
	}
	gas, err = gasCreate2EIP3860(nil, nil, stack, NewMemory(), 0)
	if err != nil {
		t.Fatal(err)
	}
	wantCreate2 := uint64(2 * (params.Sha3WordGas + params.InitCodeWordGas))
	if gas != wantCreate2 {
		t.Fatalf("CREATE2 initcode gas = %d, want %d", gas, wantCreate2)
	}
}

func TestCreateRejectsOversizedInitCodeAtShanghai(t *testing.T) {
	evm := &EVM{chainRules: params.Rules{IsShanghai: true}}
	code := make([]byte, params.MaxInitCodeSize+1)
	_, _, gas, err := evm.create(nil, &codeAndHash{code: code}, 100, new(big.Int), common.Address{})
	if err != ErrMaxInitCodeSizeExceeded {
		t.Fatalf("error = %v, want %v", err, ErrMaxInitCodeSizeExceeded)
	}
	if gas != 0 {
		t.Fatalf("remaining gas = %d, want 0", gas)
	}
}

func TestCreateOpcodesExceptionalHaltOnOversizedInitCode(t *testing.T) {
	for _, tc := range []struct {
		name    string
		gasFunc gasFunc
	}{
		{name: "CREATE", gasFunc: gasCreateEIP3860},
		{name: "CREATE2", gasFunc: gasCreate2EIP3860},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stack := newstack()
			defer returnStack(stack)
			stack.push(new(uint256.Int).SetUint64(params.MaxInitCodeSize + 1))
			stack.push(new(uint256.Int))
			stack.push(new(uint256.Int))
			if _, err := tc.gasFunc(nil, nil, stack, NewMemory(), 0); !errors.Is(err, ErrMaxInitCodeSizeExceeded) {
				t.Fatalf("error = %v, want %v", err, ErrMaxInitCodeSizeExceeded)
			}
		})
	}
}

func TestCreateRejectsEFPrefixAtLondon(t *testing.T) {
	// Initcode stores 0xef at memory[0] and returns it as one byte runtime code.
	initcode := common.FromHex("0x60ef60005360016000f3")
	for _, tc := range []struct {
		name    string
		london  bool
		wantErr error
	}{
		{name: "pre-London"},
		{name: "London", london: true, wantErr: ErrInvalidCode},
	} {
		t.Run(tc.name, func(t *testing.T) {
			statedb := newSelfdestructStateDB()
			evm := &EVM{
				Context: Context{
					CanTransfer: func(StateDB, common.Address, *big.Int) bool { return true },
					Transfer:    func(StateDB, common.Address, common.Address, *big.Int) {},
				},
				StateDB:    statedb,
				chainRules: params.Rules{IsHomestead: true, IsLondon: tc.london},
			}
			evm.interpreters = []Interpreter{NewEVMInterpreter(evm, Config{})}
			evm.interpreter = evm.interpreters[0]
			_, _, _, err := evm.create(AccountRef(common.HexToAddress("0x01")), &codeAndHash{code: initcode}, 100_000, new(big.Int), common.HexToAddress("0x02"))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

type createRulesStateDB struct {
	*selfdestructStateDB
	nonces       map[common.Address]uint64
	warm         map[common.Address]bool
	storageRoots map[common.Address]common.Hash
}

func newCreateRulesStateDB() *createRulesStateDB {
	return &createRulesStateDB{
		selfdestructStateDB: newSelfdestructStateDB(),
		nonces:              make(map[common.Address]uint64),
		warm:                make(map[common.Address]bool),
		storageRoots:        make(map[common.Address]common.Hash),
	}
}

func (s *createRulesStateDB) GetNonce(addr common.Address) uint64 { return s.nonces[addr] }
func (s *createRulesStateDB) SetNonce(addr common.Address, nonce uint64) {
	s.nonces[addr] = nonce
}
func (s *createRulesStateDB) AddAddressToAccessList(addr common.Address) { s.warm[addr] = true }
func (s *createRulesStateDB) AddressInAccessList(addr common.Address) bool {
	return s.warm[addr]
}
func (s *createRulesStateDB) GetStorageRoot(addr common.Address) common.Hash {
	return s.storageRoots[addr]
}

func TestCreateWarmsTargetBeforeCollisionAndRejectsNonceOverflow(t *testing.T) {
	caller := common.HexToAddress("0x01")
	target := common.HexToAddress("0x02")
	statedb := newCreateRulesStateDB()
	statedb.nonces[target] = 1 // Force a collision after target warming.
	evm := &EVM{
		Context: Context{
			CanTransfer: func(StateDB, common.Address, *big.Int) bool { return true },
			Transfer:    func(StateDB, common.Address, common.Address, *big.Int) {},
		},
		StateDB: statedb, chainRules: params.Rules{IsBerlin: true},
	}
	if _, _, _, err := evm.create(AccountRef(caller), &codeAndHash{}, 100, new(big.Int), target); !errors.Is(err, ErrContractAddressCollision) {
		t.Fatalf("collision error = %v, want %v", err, ErrContractAddressCollision)
	}
	if !statedb.AddressInAccessList(target) {
		t.Fatal("CREATE target was not warmed before collision check")
	}

	statedb = newCreateRulesStateDB()
	statedb.storageRoots[target] = common.HexToHash("0x1234")
	evm.StateDB = statedb
	if _, _, _, err := evm.create(AccountRef(caller), &codeAndHash{}, 100, new(big.Int), target); !errors.Is(err, ErrContractAddressCollision) {
		t.Fatalf("storage collision error = %v, want %v", err, ErrContractAddressCollision)
	}

	statedb = newCreateRulesStateDB()
	statedb.nonces[caller] = math.MaxUint64
	evm.StateDB = statedb
	if _, _, _, err := evm.create(AccountRef(caller), &codeAndHash{}, 100, new(big.Int), target); !errors.Is(err, ErrNonceUintOverflow) {
		t.Fatalf("nonce error = %v, want %v", err, ErrNonceUintOverflow)
	}
}

func TestColdCallAccessCostPrecedesEIP150Cap(t *testing.T) {
	const available = uint64(100_000)
	target := common.HexToAddress("0x1234")
	statedb := newDelegationStateDB()
	evm := &EVM{StateDB: statedb, chainRules: params.Rules{IsBerlin: true, IsEIP150: true}}
	contract := NewContract(AccountRef(common.HexToAddress("0x01")), AccountRef(common.HexToAddress("0x02")), new(big.Int), available)
	stack := newstack()
	defer returnStack(stack)
	// CALL stack, bottom to top: out-size, out-offset, in-size, in-offset,
	// value, address, requested gas.
	for i := 0; i < 5; i++ {
		stack.push(new(uint256.Int))
	}
	stack.push(new(uint256.Int).SetBytes(target[:]))
	stack.push(new(uint256.Int).SetUint64(math.MaxUint64))

	gas, err := gasCallEIP2929(evm, contract, stack, NewMemory(), 0)
	if err != nil {
		t.Fatal(err)
	}
	remainingBeforeCap := available - params.ColdAccountAccessCostEIP2929
	wantForwarded := remainingBeforeCap - remainingBeforeCap/64
	if evm.callGasTemp != wantForwarded {
		t.Fatalf("forwarded gas = %d, want %d", evm.callGasTemp, wantForwarded)
	}
	if want := wantForwarded + params.ColdAccountAccessCostEIP2929; gas != want {
		t.Fatalf("dynamic gas = %d, want %d", gas, want)
	}
	if contract.Gas != available {
		t.Fatalf("temporary access charge was not restored: gas = %d, want %d", contract.Gas, available)
	}
	if !statedb.AddressInAccessList(target) {
		t.Fatal("cold CALL target was not warmed")
	}
}

func TestSelfdestructRefundRemovedAtLondon(t *testing.T) {
	for _, tc := range []struct {
		name       string
		isLondon   bool
		wantRefund uint64
	}{
		{name: "pre-London", wantRefund: params.SelfdestructRefundGas},
		{name: "London", isLondon: true, wantRefund: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			statedb := newRefundGasStateDB()
			contractAddr := common.HexToAddress("0xc0de")
			statedb.balance[contractAddr] = big.NewInt(1)
			evm := &EVM{StateDB: statedb, chainRules: params.Rules{IsEIP150: true, IsLondon: tc.isLondon}}
			contract := NewContract(AccountRef(contractAddr), AccountRef(contractAddr), new(big.Int), 100000)
			stack := newstack()
			defer returnStack(stack)
			stack.push(new(uint256.Int).SetUint64(1))
			if _, err := gasSelfdestruct(evm, contract, stack, NewMemory(), 0); err != nil {
				t.Fatal(err)
			}
			if statedb.refund != tc.wantRefund {
				t.Fatalf("refund = %d, want %d", statedb.refund, tc.wantRefund)
			}
		})
	}
}

func TestSstoreClearRefundChangesAtLondon(t *testing.T) {
	nonzero := common.HexToHash("0x01")
	for _, tc := range []struct {
		name       string
		gasFunc    gasFunc
		wantRefund uint64
	}{
		{name: "Berlin", gasFunc: gasSStoreEIP2929, wantRefund: params.SstoreClearRefundEIP2200},
		{name: "London", gasFunc: gasSStoreEIP3529, wantRefund: params.SstoreClearsScheduleRefundEIP3529},
	} {
		t.Run(tc.name, func(t *testing.T) {
			statedb := newRefundGasStateDB()
			statedb.current = nonzero
			statedb.original = nonzero
			statedb.slotWarm = true
			contractAddr := common.HexToAddress("0xc0de")
			evm := &EVM{StateDB: statedb, chainRules: params.Rules{IsBerlin: true}}
			contract := NewContract(AccountRef(contractAddr), AccountRef(contractAddr), new(big.Int), 100000)
			stack := newstack()
			defer returnStack(stack)
			stack.push(new(uint256.Int))              // value
			stack.push(new(uint256.Int).SetUint64(1)) // slot
			gas, err := tc.gasFunc(evm, contract, stack, NewMemory(), 0)
			if err != nil {
				t.Fatal(err)
			}
			if want := params.SstoreCleanGasEIP2200 - params.ColdSloadCostEIP2929; gas != want {
				t.Fatalf("SSTORE gas = %d, want %d", gas, want)
			}
			if statedb.refund != tc.wantRefund {
				t.Fatalf("refund = %d, want %d", statedb.refund, tc.wantRefund)
			}
		})
	}
}
