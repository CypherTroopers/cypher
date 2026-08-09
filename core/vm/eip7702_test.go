package vm

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/params"
	"github.com/holiman/uint256"
)

type delegationStateDB struct {
	*selfdestructStateDB
	code       map[common.Address][]byte
	warm       map[common.Address]bool
	codeHashes map[common.Address]common.Hash
}

func newDelegationStateDB() *delegationStateDB {
	return &delegationStateDB{
		selfdestructStateDB: newSelfdestructStateDB(),
		code:                make(map[common.Address][]byte),
		warm:                make(map[common.Address]bool),
		codeHashes:          make(map[common.Address]common.Hash),
	}
}

func (s *delegationStateDB) GetCode(addr common.Address) []byte {
	return s.code[addr]
}

func (s *delegationStateDB) GetCodeHash(addr common.Address) common.Hash {
	if hash, ok := s.codeHashes[addr]; ok {
		return hash
	}
	return crypto.Keccak256Hash(s.code[addr])
}

func (s *delegationStateDB) GetCodeSize(addr common.Address) int { return len(s.code[addr]) }

func (s *delegationStateDB) SetCode(addr common.Address, code []byte) {
	s.code[addr] = common.CopyBytes(code)
}

func (s *delegationStateDB) PrepareAccessList(sender common.Address, dst *common.Address, precompiles []common.Address, list types.AccessList) {
	s.warm = make(map[common.Address]bool)
	s.warm[sender] = true
	if dst != nil {
		s.warm[*dst] = true
	}
	for _, addr := range precompiles {
		s.warm[addr] = true
	}
	for _, tuple := range list {
		s.warm[tuple.Address] = true
	}
}

func (s *delegationStateDB) AddAddressToAccessList(addr common.Address) { s.warm[addr] = true }
func (s *delegationStateDB) AddressInAccessList(addr common.Address) bool {
	return s.warm[addr]
}

func delegationTestConfig(prague bool) *params.ChainConfig {
	zeroBlock := big.NewInt(0)
	zeroTime := uint64(0)
	cfg := &params.ChainConfig{
		ChainID:         big.NewInt(1),
		HomesteadBlock:  zeroBlock,
		EIP150Block:     zeroBlock,
		EIP155Block:     zeroBlock,
		EIP158Block:     zeroBlock,
		ByzantiumBlock:  zeroBlock,
		PetersburgBlock: zeroBlock,
		IstanbulBlock:   zeroBlock,
	}
	modern := &params.ModernForkConfig{BerlinBlock: zeroBlock, LondonBlock: zeroBlock, ShanghaiTime: &zeroTime, CancunTime: &zeroTime}
	if prague {
		modern.PragueTime = &zeroTime
	}
	cfg.SetModernForkConfig(modern)
	return cfg
}

func TestEIP7702CallVariantsResolveOneDelegationLevel(t *testing.T) {
	caller := common.HexToAddress("0xca11")
	delegator := common.HexToAddress("0xde1e6a7e")
	target := common.HexToAddress("0x7a267e7")
	// Return a single 32-byte word containing 0x2a.
	targetCode := []byte{byte(PUSH1), 0x2a, byte(PUSH1), 0x00, byte(MSTORE), byte(PUSH1), 0x20, byte(PUSH1), 0x00, byte(RETURN)}
	want := make([]byte, 32)
	want[31] = 0x2a

	for _, tc := range []struct {
		name string
		call func(*EVM, *Contract) ([]byte, uint64, error)
	}{
		{name: "CALL", call: func(evm *EVM, _ *Contract) ([]byte, uint64, error) {
			return evm.Call(AccountRef(caller), delegator, nil, 100_000, new(big.Int))
		}},
		{name: "CALLCODE", call: func(evm *EVM, _ *Contract) ([]byte, uint64, error) {
			return evm.CallCode(AccountRef(caller), delegator, nil, 100_000, new(big.Int))
		}},
		{name: "DELEGATECALL", call: func(evm *EVM, parent *Contract) ([]byte, uint64, error) {
			return evm.DelegateCall(parent, delegator, nil, 100_000)
		}},
		{name: "STATICCALL", call: func(evm *EVM, _ *Contract) ([]byte, uint64, error) {
			return evm.StaticCall(AccountRef(caller), delegator, nil, 100_000)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			statedb := newDelegationStateDB()
			statedb.code[delegator] = types.AddressToDelegation(target)
			statedb.code[target] = targetCode
			evm := NewEVM(Context{
				CanTransfer: func(StateDB, common.Address, *big.Int) bool { return true },
				Transfer:    func(StateDB, common.Address, common.Address, *big.Int) {},
				BlockNumber: big.NewInt(0),
				Time:        big.NewInt(0),
			}, statedb, delegationTestConfig(true), Config{})
			parent := NewContract(AccountRef(caller), AccountRef(caller), new(big.Int), 100_000)
			got, _, err := tc.call(evm, parent)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("return = %x, want %x", got, want)
			}
		})
	}
}

func TestEIP7702CodeResolutionForkBoundaryAndSingleHop(t *testing.T) {
	delegator := common.HexToAddress("0xd1")
	target := common.HexToAddress("0xd2")
	secondTarget := common.HexToAddress("0xd3")
	statedb := newDelegationStateDB()
	statedb.code[delegator] = types.AddressToDelegation(target)
	statedb.code[target] = types.AddressToDelegation(secondTarget)
	statedb.code[secondTarget] = []byte{byte(STOP)}
	statedb.codeHashes[target] = common.HexToHash("0x42")

	pre := &EVM{StateDB: statedb, chainRules: params.Rules{}}
	if got := pre.resolveCode(delegator); !bytes.Equal(got, statedb.code[delegator]) {
		t.Fatalf("pre-Prague resolved code = %x", got)
	}
	prague := &EVM{StateDB: statedb, chainRules: params.Rules{IsPrague: true}}
	if got := prague.resolveCode(delegator); !bytes.Equal(got, statedb.code[target]) {
		t.Fatalf("Prague resolved code = %x, want first target code %x", got, statedb.code[target])
	}
	if got := prague.resolveCodeHash(delegator); got != statedb.codeHashes[target] {
		t.Fatalf("Prague resolved code hash = %s, want %s", got, statedb.codeHashes[target])
	}
}

func TestEIP7702CallGasWarmsDelegationTarget(t *testing.T) {
	delegator := common.HexToAddress("0xa1")
	target := common.HexToAddress("0xa2")
	makeStack := func() *Stack {
		stack := newstack()
		// CALL arguments from bottom to top: out-size, out-offset, in-size,
		// in-offset, value, address, gas.
		for i := 0; i < 5; i++ {
			stack.push(uint256.NewInt(0))
		}
		stack.push(new(uint256.Int).SetBytes(delegator.Bytes()))
		stack.push(uint256.NewInt(0))
		return stack
	}

	statedb := newDelegationStateDB()
	statedb.code[delegator] = types.AddressToDelegation(target)
	evm := &EVM{StateDB: statedb, chainRules: params.Rules{IsBerlin: true, IsPrague: true}}
	contract := NewContract(AccountRef(common.Address{}), AccountRef(common.Address{}), new(big.Int), 100_000)
	stack := makeStack()
	defer returnStack(stack)
	gas, err := pragueInstructionSet[CALL].dynamicGas(evm, contract, stack, NewMemory(), 0)
	if err != nil {
		t.Fatal(err)
	}
	want := uint64(2 * params.ColdAccountAccessCostEIP2929)
	if gas != want {
		t.Fatalf("Prague delegated CALL access gas = %d, want %d", gas, want)
	}
	if !statedb.AddressInAccessList(delegator) || !statedb.AddressInAccessList(target) {
		t.Fatal("delegator and target were not both warmed")
	}
	if contract.Gas != 100_000 {
		t.Fatalf("temporary access charge was not restored: gas = %d", contract.Gas)
	}
}
