package vm

import (
	"github.com/cypherium/cypher/dex/settlement"
	"math/big"
)

func rejectNativeContext(gas uint64) ([]byte, uint64, error) {
	if gas < 5000 {
		return nil, 0, ErrOutOfGas
	}
	return []byte("DEX_NATIVE_CONTEXT"), gas - 5000, ErrExecutionReverted
}

func (evm *EVM) runNativeSettlement(caller ContractRef, input []byte, gas uint64, value *big.Int) ([]byte, uint64, error) {
	if evm.depth != 0 || caller.Address() != evm.Origin {
		return rejectNativeContext(gas)
	}
	cost := settlement.RequiredNativeGas(input)
	if gas < cost {
		return nil, 0, ErrOutOfGas
	}
	gas -= cost
	// The proof codecs have independent shape/allocation bounds. Charge a fixed
	// conservative native working-memory reserve as well as calldata here.
	if evm.vmConfig.MaxMemoryBytes != 0 && uint64(len(input))+4*1024*1024 > evm.vmConfig.MaxMemoryBytes {
		return nil, 0, ErrMemoryLimitExceeded
	}
	if evm.BlockNumber == nil || !evm.BlockNumber.IsUint64() {
		return []byte("DEX_NATIVE_BLOCK"), gas, ErrExecutionReverted
	}
	if evm.NativeGenesisConfig == nil {
		return []byte("DEX_NATIVE_CONTEXT"), gas, ErrExecutionReverted
	}
	// The historical configuration is detached from the legacy pointer-keyed
	// modern fork table while stored in the context. Register a private copy
	// only for this bounded execution and always release the table reference.
	genesisConfig := *evm.NativeGenesisConfig
	genesisConfig.SetModernForkConfig(evm.NativeGenesisForks)
	defer genesisConfig.SetModernForkConfig(nil)
	out, err := settlement.RunNative(evm.StateDB, &genesisConfig, settlement.NativeContext{Sender: caller.Address(), Nonce: evm.TransactionNonce, BlockNumber: evm.BlockNumber.Uint64(), Value: new(big.Int).Set(value), Genesis: evm.NativeGenesis, GenesisKeyHash: evm.NativeGenesisKeyHash, GetHash: evm.GetHash}, input)
	if err != nil { // Stable bounded semantic revert data; no allocation-dependent text.
		return []byte("DEX_NATIVE_REJECTED"), gas, ErrExecutionReverted
	}
	if evm.vmConfig.MaxReturnDataBytes != 0 && uint64(len(out)) > evm.vmConfig.MaxReturnDataBytes {
		return nil, 0, ErrReturnDataLimitExceeded
	}
	return out, gas, nil
}
