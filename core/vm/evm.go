package vm

import (
	"errors"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/params"
	"github.com/holiman/uint256"
)

var emptyCodeHash = crypto.Keccak256Hash(nil)

type (
	CanTransferFunc func(StateDB, common.Address, *big.Int) bool
	TransferFunc    func(StateDB, common.Address, common.Address, *big.Int)
	GetHashFunc     func(uint64) common.Hash
)

func (evm *EVM) precompile(addr common.Address) (PrecompiledContract, bool) {
	var precompiles map[common.Address]PrecompiledContract
	switch {
	case evm.chainRules.IsYoloV1:
		precompiles = PrecompiledContractsYoloV1
	case evm.chainRules.IsIstanbul:
		precompiles = PrecompiledContractsIstanbul
	case evm.chainRules.IsByzantium:
		precompiles = PrecompiledContractsByzantium
	default:
		precompiles = PrecompiledContractsHomestead
	}
	p, ok := precompiles[addr]
	return p, ok
}

func run(evm *EVM, contract *Contract, input []byte, readOnly bool) ([]byte, error) {
	for _, interpreter := range evm.interpreters {
		if interpreter.CanRun(contract.Code) {
			if evm.interpreter != interpreter {
				defer func(i Interpreter) { evm.interpreter = i }(evm.interpreter)
				evm.interpreter = interpreter
			}
			return interpreter.Run(contract, input, readOnly)
		}
	}
	return nil, errors.New("no compatible interpreter")
}

type Context struct {
	CanTransfer CanTransferFunc
	Transfer    TransferFunc
	GetHash     GetHashFunc

	Origin   common.Address
	GasPrice *big.Int

	Coinbase    common.Address
	GasLimit    uint64
	BlockNumber *big.Int
	Time        *big.Int
	Difficulty  *big.Int
	BaseFee     *big.Int
	BlobBaseFee *big.Int
	BlobHashes  []common.Hash
}

type EVM struct {
	Context
	StateDB      StateDB
	depth        int
	chainConfig  *params.ChainConfig
	chainRules   params.Rules
	vmConfig     Config
	interpreters []Interpreter
	interpreter  Interpreter
	abort        int32
	callGasTemp  uint64
}

func NewEVM(ctx Context, statedb StateDB, chainConfig *params.ChainConfig, vmConfig Config) *EVM {
	timestamp := uint64(0)
	if ctx.Time != nil {
		timestamp = ctx.Time.Uint64()
	}
	evm := &EVM{
		Context:      ctx,
		StateDB:      statedb,
		vmConfig:     vmConfig,
		chainConfig:  chainConfig,
		chainRules:   chainConfig.CypheriumRules(ctx.BlockNumber, timestamp),
		interpreters: make([]Interpreter, 0, 1),
	}
	if chainConfig.IsEWASM(ctx.BlockNumber) {
		panic("No supported ewasm interpreter yet.")
	}
	evm.interpreters = append(evm.interpreters, NewEVMInterpreter(evm, vmConfig))
	evm.interpreter = evm.interpreters[0]
	return evm
}

func (evm *EVM) Cancel()                          { atomic.StoreInt32(&evm.abort, 1) }
func (evm *EVM) Cancelled() bool                  { return atomic.LoadInt32(&evm.abort) == 1 }
func (evm *EVM) Interpreter() Interpreter         { return evm.interpreter }
func (evm *EVM) ChainConfig() *params.ChainConfig { return evm.chainConfig }

func (evm *EVM) Call(caller ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) ([]byte, uint64, error) {
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, gas, nil
	}
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	if value.Sign() != 0 && !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, gas, ErrInsufficientBalance
	}
	snapshot := evm.StateDB.Snapshot()
	p, isPrecompile := evm.precompile(addr)
	if !evm.StateDB.Exist(addr) {
		if !isPrecompile && evm.chainRules.IsEIP158 && value.Sign() == 0 {
			if evm.vmConfig.Debug && evm.depth == 0 {
				evm.vmConfig.Tracer.CaptureStart(caller.Address(), addr, false, input, gas, value)
				evm.vmConfig.Tracer.CaptureEnd(nil, 0, 0, nil)
			}
			return nil, gas, nil
		}
		evm.StateDB.CreateAccount(addr)
	}
	evm.Transfer(evm.StateDB, caller.Address(), addr, value)
	var ret []byte
	var err error
	if evm.vmConfig.Debug && evm.depth == 0 {
		startGas, startTime := gas, time.Now()
		evm.vmConfig.Tracer.CaptureStart(caller.Address(), addr, false, input, gas, value)
		defer func() { evm.vmConfig.Tracer.CaptureEnd(ret, startGas-gas, time.Since(startTime), err) }()
	}
	if isPrecompile {
		ret, gas, err = RunPrecompiledContract(p, input, gas)
	} else if code := evm.StateDB.GetCode(addr); len(code) > 0 {
		addrCopy := addr
		contract := NewContract(caller, AccountRef(addrCopy), value, gas)
		contract.SetCallCode(&addrCopy, evm.StateDB.GetCodeHash(addrCopy), code)
		ret, err = run(evm, contract, input, false)
		gas = contract.Gas
	}
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			gas = 0
		}
	}
	return ret, gas, err
}

func (evm *EVM) CallCode(caller ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) ([]byte, uint64, error) {
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, gas, nil
	}
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	if !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, gas, ErrInsufficientBalance
	}
	snapshot := evm.StateDB.Snapshot()
	var ret []byte
	var err error
	if p, isPrecompile := evm.precompile(addr); isPrecompile {
		ret, gas, err = RunPrecompiledContract(p, input, gas)
	} else {
		addrCopy := addr
		contract := NewContract(caller, AccountRef(caller.Address()), value, gas)
		contract.SetCallCode(&addrCopy, evm.StateDB.GetCodeHash(addrCopy), evm.StateDB.GetCode(addrCopy))
		ret, err = run(evm, contract, input, false)
		gas = contract.Gas
	}
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			gas = 0
		}
	}
	return ret, gas, err
}

func (evm *EVM) DelegateCall(caller ContractRef, addr common.Address, input []byte, gas uint64) ([]byte, uint64, error) {
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, gas, nil
	}
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	snapshot := evm.StateDB.Snapshot()
	var ret []byte
	var err error
	if p, isPrecompile := evm.precompile(addr); isPrecompile {
		ret, gas, err = RunPrecompiledContract(p, input, gas)
	} else {
		addrCopy := addr
		contract := NewContract(caller, AccountRef(caller.Address()), nil, gas).AsDelegate()
		contract.SetCallCode(&addrCopy, evm.StateDB.GetCodeHash(addrCopy), evm.StateDB.GetCode(addrCopy))
		ret, err = run(evm, contract, input, false)
		gas = contract.Gas
	}
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			gas = 0
		}
	}
	return ret, gas, err
}

func (evm *EVM) StaticCall(caller ContractRef, addr common.Address, input []byte, gas uint64) ([]byte, uint64, error) {
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, gas, nil
	}
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	snapshot := evm.StateDB.Snapshot()
	evm.StateDB.AddBalance(addr, big0)
	var ret []byte
	var err error
	if p, isPrecompile := evm.precompile(addr); isPrecompile {
		ret, gas, err = RunPrecompiledContract(p, input, gas)
	} else {
		addrCopy := addr
		contract := NewContract(caller, AccountRef(addrCopy), new(big.Int), gas)
		contract.SetCallCode(&addrCopy, evm.StateDB.GetCodeHash(addrCopy), evm.StateDB.GetCode(addrCopy))
		ret, err = run(evm, contract, input, true)
		gas = contract.Gas
	}
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			gas = 0
		}
	}
	return ret, gas, err
}

type codeAndHash struct {
	code []byte
	hash common.Hash
}

func (c *codeAndHash) Hash() common.Hash {
	if c.hash == (common.Hash{}) {
		c.hash = crypto.Keccak256Hash(c.code)
	}
	return c.hash
}

func (evm *EVM) create(caller ContractRef, codeAndHash *codeAndHash, gas uint64, value *big.Int, address common.Address) ([]byte, common.Address, uint64, error) {
	if evm.depth > int(params.CallCreateDepth) {
		return nil, common.Address{}, gas, ErrDepth
	}
	if !evm.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, common.Address{}, gas, ErrInsufficientBalance
	}
	nonce := evm.StateDB.GetNonce(caller.Address())
	evm.StateDB.SetNonce(caller.Address(), nonce+1)
	contractHash := evm.StateDB.GetCodeHash(address)
	if evm.StateDB.GetNonce(address) != 0 || (contractHash != (common.Hash{}) && contractHash != emptyCodeHash) {
		return nil, common.Address{}, 0, ErrContractAddressCollision
	}
	snapshot := evm.StateDB.Snapshot()
	evm.StateDB.CreateAccount(address)
	evm.StateDB.CreateContract(address)
	if evm.chainRules.IsEIP158 {
		evm.StateDB.SetNonce(address, 1)
	}
	evm.Transfer(evm.StateDB, caller.Address(), address, value)
	contract := NewContract(caller, AccountRef(address), value, gas)
	contract.SetCodeOptionalHash(&address, codeAndHash)
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, address, gas, nil
	}
	if evm.vmConfig.Debug && evm.depth == 0 {
		evm.vmConfig.Tracer.CaptureStart(caller.Address(), address, true, codeAndHash.code, gas, value)
	}
	start := time.Now()
	ret, err := run(evm, contract, nil, false)

	maxCodeSize := params.MaxCodeSize
	if evm.chainConfig != nil && evm.Context.BlockNumber != nil {
		maxCodeSize = evm.chainConfig.GetMaxCodeSize(evm.Context.BlockNumber)
	}
	maxCodeSizeExceeded := evm.chainRules.IsEIP158 && len(ret) > maxCodeSize
	if err == nil && !maxCodeSizeExceeded {
		createDataGas := uint64(len(ret)) * params.CreateDataGas
		if contract.UseGas(createDataGas) {
			evm.StateDB.SetCode(address, ret)
		} else {
			err = ErrCodeStoreOutOfGas
		}
	}
	if maxCodeSizeExceeded || (err != nil && (evm.chainRules.IsHomestead || err != ErrCodeStoreOutOfGas)) {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}
	if maxCodeSizeExceeded && err == nil {
		err = ErrMaxCodeSizeExceeded
	}
	if evm.vmConfig.Debug && evm.depth == 0 {
		evm.vmConfig.Tracer.CaptureEnd(ret, gas-contract.Gas, time.Since(start), err)
	}
	return ret, address, contract.Gas, err
}

func (evm *EVM) Create(caller ContractRef, code []byte, gas uint64, value *big.Int) ([]byte, common.Address, uint64, error) {
	contractAddr := crypto.CreateAddress(caller.Address(), evm.StateDB.GetNonce(caller.Address()))
	ret, addr, left, err := evm.create(caller, &codeAndHash{code: code}, gas, value, contractAddr)
	return ret, addr, left, err
}

func (evm *EVM) Create2(caller ContractRef, code []byte, gas uint64, endowment *big.Int, salt *uint256.Int) ([]byte, common.Address, uint64, error) {
	codeAndHash := &codeAndHash{code: code}
	contractAddr := crypto.CreateAddress2(caller.Address(), common.Hash(salt.Bytes32()), codeAndHash.Hash().Bytes())
	return evm.create(caller, codeAndHash, gas, endowment, contractAddr)
}
