// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"math"
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/params"
)

type StateTransition struct {
	gp              *GasPool
	msg             Message
	gas             uint64
	gasPrice        *big.Int
	gasFeeCap       *big.Int
	gasTipCap       *big.Int
	blobGasFeeCap   *big.Int
	blobGas         uint64
	effectiveGasTip *big.Int
	initialGas      uint64
	value           *big.Int
	data            []byte
	accessList      types.AccessList
	state           vm.StateDB
	evm             *vm.EVM
}

type Message interface {
	From() common.Address
	To() *common.Address
	GasPrice() *big.Int
	Gas() uint64
	Value() *big.Int
	Nonce() uint64
	CheckNonce() bool
	Data() []byte
}

type feeCapMessage interface {
	GasFeeCap() *big.Int
	GasTipCap() *big.Int
}

type blobFeeMessage interface {
	BlobGasFeeCap() *big.Int
	BlobGas() uint64
}

type accessListMessage interface {
	AccessList() types.AccessList
}

type ExecutionResult struct {
	UsedGas           uint64
	EffectiveGasPrice *big.Int
	Err               error
	ReturnData        []byte
}

func (result *ExecutionResult) Unwrap() error { return result.Err }
func (result *ExecutionResult) Failed() bool  { return result.Err != nil }
func (result *ExecutionResult) Return() []byte {
	if result.Err != nil {
		return nil
	}
	return common.CopyBytes(result.ReturnData)
}
func (result *ExecutionResult) Revert() []byte {
	if result.Err != vm.ErrExecutionReverted {
		return nil
	}
	return common.CopyBytes(result.ReturnData)
}

func parseIntrinsicGasArgs(args []interface{}) (types.AccessList, bool) {
	var accessList types.AccessList
	var contractCreation bool
	switch len(args) {
	case 1:
		contractCreation, _ = args[0].(bool)
	case 2:
		if list, ok := args[0].(types.AccessList); ok {
			accessList = list
		}
		contractCreation, _ = args[1].(bool)
	}
	return accessList, contractCreation
}

func IntrinsicGas(data []byte, args ...interface{}) (uint64, error) {
	accessList, contractCreation := parseIntrinsicGasArgs(args)
	var gas uint64
	if contractCreation {
		gas = params.TxGasContractCreation
	} else {
		gas = params.TxGas
	}
	if len(data) > 0 {
		var nz uint64
		for _, byt := range data {
			if byt != 0 {
				nz++
			}
		}
		nonZeroGas := params.TxDataNonZeroGasFrontier
		if (math.MaxUint64-gas)/nonZeroGas < nz {
			return 0, ErrGasUintOverflow
		}
		gas += nz * nonZeroGas
		z := uint64(len(data)) - nz
		if (math.MaxUint64-gas)/params.TxDataZeroGas < z {
			return 0, ErrGasUintOverflow
		}
		gas += z * params.TxDataZeroGas
	}
	if len(accessList) > 0 {
		if (math.MaxUint64-gas)/params.TxAccessListAddressGas < uint64(len(accessList)) {
			return 0, ErrGasUintOverflow
		}
		gas += uint64(len(accessList)) * params.TxAccessListAddressGas
		for _, tuple := range accessList {
			keys := uint64(len(tuple.StorageKeys))
			if keys == 0 {
				continue
			}
			if (math.MaxUint64-gas)/params.TxAccessListStorageKeyGas < keys {
				return 0, ErrGasUintOverflow
			}
			gas += keys * params.TxAccessListStorageKeyGas
		}
	}
	return gas, nil
}

func messageGasFeeCap(msg Message) *big.Int {
	if m, ok := msg.(feeCapMessage); ok {
		return new(big.Int).Set(m.GasFeeCap())
	}
	return new(big.Int).Set(msg.GasPrice())
}

func messageGasTipCap(msg Message) *big.Int {
	if m, ok := msg.(feeCapMessage); ok {
		return new(big.Int).Set(m.GasTipCap())
	}
	return new(big.Int).Set(msg.GasPrice())
}

func messageBlobGasFeeCap(msg Message) *big.Int {
	if m, ok := msg.(blobFeeMessage); ok {
		return new(big.Int).Set(m.BlobGasFeeCap())
	}
	return new(big.Int)
}

func messageBlobGas(msg Message) uint64 {
	if m, ok := msg.(blobFeeMessage); ok {
		return m.BlobGas()
	}
	return 0
}

func messageAccessList(msg Message) types.AccessList {
	if m, ok := msg.(accessListMessage); ok {
		return m.AccessList()
	}
	return nil
}

func calcEffectiveGasTip(gasFeeCap, gasTipCap, baseFee *big.Int) (*big.Int, error) {
	if gasFeeCap == nil {
		gasFeeCap = new(big.Int)
	}
	if gasTipCap == nil {
		gasTipCap = new(big.Int)
	}
	if gasTipCap.Cmp(gasFeeCap) > 0 {
		return nil, ErrGasTipAboveFeeCap
	}
	if baseFee == nil {
		return new(big.Int).Set(gasTipCap), nil
	}
	if gasFeeCap.Cmp(baseFee) < 0 {
		return nil, ErrGasFeeCapTooLow
	}
	tip := new(big.Int).Sub(gasFeeCap, baseFee)
	if tip.Cmp(gasTipCap) > 0 {
		tip.Set(gasTipCap)
	}
	return tip, nil
}

func calcEffectiveGasPrice(tip, baseFee *big.Int) *big.Int {
	price := new(big.Int)
	if tip != nil {
		price.Set(tip)
	}
	if baseFee != nil {
		price.Add(price, baseFee)
	}
	return price
}

func NewStateTransition(evm *vm.EVM, msg Message, gp *GasPool) *StateTransition {
	gasFeeCap := messageGasFeeCap(msg)
	gasTipCap := messageGasTipCap(msg)
	blobGasFeeCap := messageBlobGasFeeCap(msg)
	blobGas := messageBlobGas(msg)
	tip, err := calcEffectiveGasTip(gasFeeCap, gasTipCap, evm.Context.BaseFee)
	if err != nil {
		tip = new(big.Int)
	}
	return &StateTransition{
		gp:              gp,
		evm:             evm,
		msg:             msg,
		gasPrice:        calcEffectiveGasPrice(tip, evm.Context.BaseFee),
		gasFeeCap:       gasFeeCap,
		gasTipCap:       gasTipCap,
		blobGasFeeCap:   blobGasFeeCap,
		blobGas:         blobGas,
		effectiveGasTip: tip,
		value:           msg.Value(),
		data:            msg.Data(),
		accessList:      messageAccessList(msg),
		state:           evm.StateDB,
	}
}

func ApplyMessage(evm *vm.EVM, msg Message, gp *GasPool) (*ExecutionResult, error) {
	return NewStateTransition(evm, msg, gp).TransitionDb()
}

func (st *StateTransition) to() common.Address {
	if st.msg == nil || st.msg.To() == nil {
		return common.Address{}
	}
	return *st.msg.To()
}

func (st *StateTransition) blobGasCost() *big.Int {
	if st.blobGas == 0 {
		return new(big.Int)
	}
	return new(big.Int).Mul(new(big.Int).SetUint64(st.blobGas), st.blobGasFeeCap)
}

func (st *StateTransition) blobGasRefund() (*big.Int, error) {
	if st.blobGas == 0 {
		return new(big.Int), nil
	}
	blobBaseFee := st.evm.Context.BlobBaseFee
	if blobBaseFee == nil {
		blobBaseFee = new(big.Int)
	}
	if st.blobGasFeeCap.Cmp(blobBaseFee) < 0 {
		return nil, ErrBlobFeeCapTooLow
	}
	refundPerBlobGas := new(big.Int).Sub(st.blobGasFeeCap, blobBaseFee)
	return new(big.Int).Mul(new(big.Int).SetUint64(st.blobGas), refundPerBlobGas), nil
}

func (st *StateTransition) buyGas() error {
	mgval := new(big.Int).Mul(new(big.Int).SetUint64(st.msg.Gas()), st.gasFeeCap)
	mgval.Add(mgval, st.blobGasCost())
	if st.state.GetBalance(st.msg.From()).Cmp(mgval) < 0 {
		return ErrInsufficientFunds
	}
	if err := st.gp.SubGas(st.msg.Gas()); err != nil {
		return err
	}
	st.gas += st.msg.Gas()
	st.initialGas = st.msg.Gas()
	st.state.SubBalance(st.msg.From(), mgval)
	return nil
}

func (st *StateTransition) preCheck() error {
	if st.msg.CheckNonce() {
		nonce := st.state.GetNonce(st.msg.From())
		if nonce < st.msg.Nonce() {
			return ErrNonceTooHigh
		} else if nonce > st.msg.Nonce() {
			return ErrNonceTooLow
		}
	}
	tip, err := calcEffectiveGasTip(st.gasFeeCap, st.gasTipCap, st.evm.Context.BaseFee)
	if err != nil {
		return err
	}
	if _, err := st.blobGasRefund(); err != nil {
		return err
	}
	st.effectiveGasTip = tip
	st.gasPrice = calcEffectiveGasPrice(tip, st.evm.Context.BaseFee)
	return st.buyGas()
}

func (st *StateTransition) prepareAccessList(sender common.Address, to *common.Address) {
	st.state.PrepareAccessList(sender, to, nil, st.accessList)
}

func (st *StateTransition) TransitionDb() (*ExecutionResult, error) {
	if err := st.preCheck(); err != nil {
		return nil, err
	}
	msg := st.msg
	sender := vm.AccountRef(msg.From())
	contractCreation := msg.To() == nil
	st.prepareAccessList(msg.From(), msg.To())
	gas, err := IntrinsicGas(st.data, st.accessList, contractCreation)
	if err != nil {
		return nil, err
	}
	if st.gas < gas {
		return nil, ErrIntrinsicGas
	}
	st.gas -= gas
	if msg.Value().Sign() > 0 && !st.evm.CanTransfer(st.state, msg.From(), msg.Value()) {
		return nil, ErrInsufficientFundsForTransfer
	}
	var (
		ret   []byte
		vmerr error
	)
	if contractCreation {
		ret, _, st.gas, vmerr = st.evm.Create(sender, st.data, st.gas, st.value)
	} else {
		st.state.SetNonce(msg.From(), st.state.GetNonce(sender.Address())+1)
		ret, st.gas, vmerr = st.evm.Call(sender, st.to(), st.data, st.gas, st.value)
	}
	st.refundGas()
	// Do not credit gas fees to the tx block coinbase here. The protocol-level
	// common RPC settlement is handled after receipt gas usage is known:
	//   valid admission winner: actual fee / 5 paid to the common RPC miner
	//   remaining fee: burned by leaving it uncredited
	//   no valid admission: 100% burned
	return &ExecutionResult{UsedGas: st.gasUsed(), EffectiveGasPrice: new(big.Int).Set(st.gasPrice), Err: vmerr, ReturnData: ret}, nil
}

func (st *StateTransition) refundGas() {
	refund := st.gasUsed() / 2
	if refund > st.state.GetRefund() {
		refund = st.state.GetRefund()
	}
	st.gas += refund
	remaining := new(big.Int).Mul(new(big.Int).SetUint64(st.gas), st.gasFeeCap)
	st.state.AddBalance(st.msg.From(), remaining)
	if blobRefund, err := st.blobGasRefund(); err == nil && blobRefund.Sign() > 0 {
		st.state.AddBalance(st.msg.From(), blobRefund)
	}
	st.gp.AddGas(st.gas)
}

func (st *StateTransition) gasUsed() uint64 {
	return st.initialGas - st.gas
}
