package core

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/params"
)

// ErrReservedNativeProtocolAddress marks any standard-EVM attempt to mutate
// the state-rooted NativeTxV1 replay registry. The violation is sticky across
// nested calls, so contract code cannot turn it into a catchable CALL failure.
var ErrReservedNativeProtocolAddress = errors.New("reserved native protocol address")

type protocolNamespaceGuard struct {
	vm.StateDB
	err error
}

func newProtocolNamespaceGuard(statedb vm.StateDB) *protocolNamespaceGuard {
	return &protocolNamespaceGuard{StateDB: statedb}
}

func (g *protocolNamespaceGuard) reject(operation string, address common.Address) bool {
	if !params.IsNativeReplayRegistryAddress(address) {
		return false
	}
	if g.err == nil {
		g.err = fmt.Errorf("%w: %s at %s", ErrReservedNativeProtocolAddress, operation, address)
	}
	return true
}

func (g *protocolNamespaceGuard) Error() error {
	if g == nil {
		return nil
	}
	return g.err
}

func (g *protocolNamespaceGuard) CreateAccount(address common.Address) {
	if !g.reject("create account", address) {
		g.StateDB.CreateAccount(address)
	}
}

func (g *protocolNamespaceGuard) CreateContract(address common.Address) {
	if !g.reject("create contract", address) {
		g.StateDB.CreateContract(address)
	}
}

func (g *protocolNamespaceGuard) SubBalance(address common.Address, amount *big.Int) {
	if !g.reject("subtract balance", address) {
		g.StateDB.SubBalance(address, amount)
	}
}

func (g *protocolNamespaceGuard) AddBalance(address common.Address, amount *big.Int) {
	if !g.reject("add balance", address) {
		g.StateDB.AddBalance(address, amount)
	}
}

func (g *protocolNamespaceGuard) SetNonce(address common.Address, nonce uint64) {
	if !g.reject("set nonce", address) {
		g.StateDB.SetNonce(address, nonce)
	}
}

func (g *protocolNamespaceGuard) SetCode(address common.Address, code []byte) {
	if !g.reject("set code", address) {
		g.StateDB.SetCode(address, code)
	}
}

func (g *protocolNamespaceGuard) SetState(address common.Address, key, value common.Hash) {
	if !g.reject("set storage", address) {
		g.StateDB.SetState(address, key, value)
	}
}

func (g *protocolNamespaceGuard) SetTransientState(address common.Address, key, value common.Hash) {
	if !g.reject("set transient storage", address) {
		g.StateDB.SetTransientState(address, key, value)
	}
}

func (g *protocolNamespaceGuard) Suicide(address common.Address) bool {
	if g.reject("selfdestruct", address) {
		return false
	}
	return g.StateDB.Suicide(address)
}
