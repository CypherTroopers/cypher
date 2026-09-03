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
	"fmt"
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
	txType          uint8
	authList        []types.SetCodeAuthorization
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

type typedMessage interface {
	Type() uint8
}

type setCodeMessage interface {
	SetCodeAuthorizations() []types.SetCodeAuthorization
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
	return IntrinsicGasWithRules(data, accessList, contractCreation, params.Rules{})
}

// IntrinsicGasWithRules computes transaction intrinsic gas under the supplied
// execution-layer fork rules. IntrinsicGas remains the legacy-compatible entry
// point for callers which do not have block context.
func IntrinsicGasWithRules(data []byte, accessList types.AccessList, contractCreation bool, rules params.Rules) (uint64, error) {
	return IntrinsicGasWithRulesAndAuthorizations(data, accessList, nil, contractCreation, rules)
}

// IntrinsicGasWithRulesAndAuthorizations adds the EIP-7702 up-front new-account
// charge for every authorization tuple. Existing authorizing accounts receive
// the protocol refund when a valid tuple is applied.
func IntrinsicGasWithRulesAndAuthorizations(data []byte, accessList types.AccessList, authList []types.SetCodeAuthorization, contractCreation bool, rules params.Rules) (uint64, error) {
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
		if rules.IsIstanbul {
			nonZeroGas = params.TxDataNonZeroGasEIP2028
		}
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
	if contractCreation && rules.IsShanghai {
		if len(data) > params.MaxInitCodeSize {
			return 0, ErrMaxInitCodeSizeExceeded
		}
		words := (uint64(len(data)) + 31) / 32
		if (math.MaxUint64-gas)/params.InitCodeWordGas < words {
			return 0, ErrGasUintOverflow
		}
		gas += words * params.InitCodeWordGas
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
	if len(authList) > 0 {
		authCount := uint64(len(authList))
		if (math.MaxUint64-gas)/params.CallNewAccountGas < authCount {
			return 0, ErrGasUintOverflow
		}
		gas += authCount * params.CallNewAccountGas
	}
	return gas, nil
}

// FloorDataGas returns the Prague EIP-7623 minimum gas charged for calldata.
// Zero bytes count as one token and non-zero bytes count as four tokens.
func FloorDataGas(data []byte) (uint64, error) {
	var nonZero uint64
	for _, b := range data {
		if b != 0 {
			nonZero++
		}
	}
	zero := uint64(len(data)) - nonZero
	if nonZero > math.MaxUint64/params.TxTokenPerNonZeroByte {
		return 0, ErrGasUintOverflow
	}
	tokens := nonZero * params.TxTokenPerNonZeroByte
	if math.MaxUint64-tokens < zero {
		return 0, ErrGasUintOverflow
	}
	tokens += zero
	if (math.MaxUint64-params.TxGas)/params.TxCostFloorPerToken < tokens {
		return 0, ErrGasUintOverflow
	}
	return params.TxGas + tokens*params.TxCostFloorPerToken, nil
}

func (st *StateTransition) rules() params.Rules {
	if st == nil || st.evm == nil || st.evm.ChainConfig() == nil {
		return params.Rules{}
	}
	timestamp := uint64(0)
	if st.evm.Context.Time != nil {
		timestamp = st.evm.Context.Time.Uint64()
	}
	return st.evm.ChainConfig().CypheriumRules(st.evm.Context.BlockNumber, timestamp)
}

// activePrecompileAddresses returns the fork's reserved precompile addresses
// for EIP-2929 warming. The sequential ranges match the Ethereum fork layout;
// Osaka additionally reserves P256VERIFY at 0x100.
func activePrecompileAddresses(rules params.Rules) []common.Address {
	last := byte(4)
	switch {
	case rules.IsOsaka, rules.IsPrague:
		last = 17
	case rules.IsCancun:
		last = 10
	case rules.IsYoloV1:
		last = 18
	case rules.IsIstanbul, rules.IsBerlin:
		last = 9
	case rules.IsByzantium:
		last = 8
	}
	addresses := make([]common.Address, 0, int(last)+1)
	for i := byte(1); i <= last; i++ {
		addresses = append(addresses, common.BytesToAddress([]byte{i}))
	}
	if rules.IsOsaka {
		addresses = append(addresses, common.BytesToAddress([]byte{0x01, 0x00}))
	}
	return addresses
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
		if cap := m.BlobGasFeeCap(); cap != nil {
			return new(big.Int).Set(cap)
		}
	}
	return new(big.Int)
}

func messageBlobGas(msg Message) uint64 {
	if m, ok := msg.(blobFeeMessage); ok {
		return m.BlobGas()
	}
	return 0
}

func messageBlobHashes(msg Message) []common.Hash {
	if m, ok := msg.(blobHashesMessage); ok {
		return m.BlobHashes()
	}
	return nil
}

func messageAccessList(msg Message) types.AccessList {
	if m, ok := msg.(accessListMessage); ok {
		return m.AccessList()
	}
	return nil
}

func messageType(msg Message) uint8 {
	if m, ok := msg.(typedMessage); ok {
		return m.Type()
	}
	return types.LegacyTxType
}

func messageSetCodeAuthorizations(msg Message) []types.SetCodeAuthorization {
	if m, ok := msg.(setCodeMessage); ok {
		return m.SetCodeAuthorizations()
	}
	return nil
}

// ValidateTxTypeForRules enforces the activation fork of every EIP-2718
// transaction envelope. Keeping this check shared prevents txpool admission,
// proposal construction and block execution from disagreeing at fork edges.
func ValidateTxTypeForRules(txType uint8, rules params.Rules) error {
	switch txType {
	case types.LegacyTxType:
		return nil
	case types.AccessListTxType:
		if rules.IsBerlin {
			return nil
		}
	case types.DynamicFeeTxType:
		if rules.IsLondon {
			return nil
		}
	case types.BlobTxType:
		if rules.IsCancun {
			return nil
		}
	case types.SetCodeTxType:
		if rules.IsPrague {
			return nil
		}
	case types.NativeTxType:
		// Type 5 is not part of the EVM transaction protocol. Keep this shared
		// trust-boundary check closed even when a caller has no ChainConfig; the
		// public network accepts only Ethereum transaction types 0 through 4.
		return ErrNativeTxDisabled
	}
	return ErrTxTypeNotSupported
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
		txType:          messageType(msg),
		authList:        messageSetCodeAuthorizations(msg),
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
	// The fee cap is a balance-availability bound, not the price charged. Debit
	// execution gas at the effective price and refund unused gas at that same
	// price. Blob gas retains the cap debit here and is reconciled to the blob
	// base fee in refundGasWithFloor.
	mgval := new(big.Int).Mul(new(big.Int).SetUint64(st.msg.Gas()), st.gasPrice)
	blobCap := st.blobGasCost()
	mgval.Add(mgval, blobCap)
	balanceCheck := new(big.Int).Mul(new(big.Int).SetUint64(st.msg.Gas()), st.gasFeeCap)
	balanceCheck.Add(balanceCheck, blobCap)
	if st.value != nil {
		balanceCheck.Add(balanceCheck, st.value)
	}
	if st.state.GetBalance(st.msg.From()).Cmp(balanceCheck) < 0 {
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
	if err := validateNativeTransactionTypeExecutionMode(st.evm.ChainConfig(), st.txType); err != nil {
		return err
	}
	rules := st.rules()
	transactionChecks := st.msg.CheckNonce()
	if err := ValidateTxTypeForRules(st.txType, rules); err != nil {
		return err
	}
	if st.txType == types.BlobTxType {
		hashes := messageBlobHashes(st.msg)
		if len(hashes) == 0 {
			return types.ErrBlobTxMissingBlobHashes
		}
		timestamp := uint64(0)
		if st.evm.Context.Time != nil {
			timestamp = st.evm.Context.Time.Uint64()
		}
		maxBlobs := params.MaxBlobsPerTransaction(st.evm.ChainConfig(), timestamp)
		if maxBlobs > 0 && len(hashes) > maxBlobs {
			return types.ErrBlobTxTooManyBlobs
		}
		for _, hash := range hashes {
			if hash[0] != types.BlobCommitmentVersionKZG {
				return types.ErrBlobTxInvalidBlobHashVersion
			}
		}
		if st.blobGasFeeCap == nil || st.blobGasFeeCap.Sign() <= 0 {
			return types.ErrBlobTxInvalidFeeCap
		}
		if uint64(len(hashes)) > math.MaxUint64/params.BlobTxBlobGasPerBlob ||
			st.blobGas != uint64(len(hashes))*params.BlobTxBlobGasPerBlob {
			return ErrBlobGasUsedMismatch
		}
	}
	if transactionChecks {
		if rules.IsOsaka && st.msg.Gas() > params.MaxTxGas {
			return ErrTxGasLimitExceeded
		}
	}
	if st.txType == types.SetCodeTxType {
		if st.msg.To() == nil {
			return ErrSetCodeTxCreate
		}
		if len(st.authList) == 0 {
			return ErrEmptyAuthList
		}
	}
	if transactionChecks {
		nonce := st.state.GetNonce(st.msg.From())
		if nonce < st.msg.Nonce() {
			return ErrNonceTooHigh
		} else if nonce > st.msg.Nonce() {
			return ErrNonceTooLow
		} else if nonce == math.MaxUint64 {
			return ErrNonceMax
		}
	}
	// NativeTxV1 deliberately omits an account nonce, but its fee payer still
	// follows the same EOA/delegated-account rule as a nonce-bearing sender.
	// Tying this check to CheckNonce would make pool admission stricter than
	// consensus execution and allow a Byzantine proposer to include a native
	// transaction from arbitrary contract code.
	if (transactionChecks || st.txType == types.NativeTxType) && rules.IsLondon {
		code := st.state.GetCode(st.msg.From())
		_, delegated := types.ParseDelegation(code)
		if len(code) != 0 && !(rules.IsPrague && delegated) {
			return ErrSenderNoEOA
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

func (st *StateTransition) prepareAccessList(sender common.Address, to *common.Address, rules params.Rules) {
	if !rules.IsBerlin {
		return
	}
	st.state.PrepareAccessList(sender, to, activePrecompileAddresses(rules), st.accessList)
	if rules.IsShanghai {
		st.state.AddAddressToAccessList(st.evm.Context.Coinbase)
	}
}

func (st *StateTransition) TransitionDb() (*ExecutionResult, error) {
	if err := st.preCheck(); err != nil {
		return nil, err
	}
	msg := st.msg
	sender := vm.AccountRef(msg.From())
	contractCreation := msg.To() == nil
	rules := st.rules()
	st.prepareAccessList(msg.From(), msg.To(), rules)
	var floorDataGas uint64
	if rules.IsPrague {
		var err error
		floorDataGas, err = FloorDataGas(st.data)
		if err != nil {
			return nil, err
		}
		if msg.Gas() < floorDataGas {
			return nil, ErrFloorDataGas
		}
	}
	gas, err := IntrinsicGasWithRulesAndAuthorizations(st.data, st.accessList, st.authList, contractCreation, rules)
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
		// NativeTxV1 has no account nonce. Its replay domain is the signed recent
		// block plus expiry window, so mutating an unrelated legacy account nonce
		// would make otherwise independent native transactions conflict.
		if st.txType != types.NativeTxType {
			st.state.SetNonce(msg.From(), st.state.GetNonce(sender.Address())+1)
		}
		if rules.IsPrague && st.txType == types.SetCodeTxType {
			for i := range st.authList {
				// Invalid tuples are ignored as required by EIP-7702. Stateless
				// list-shape errors were rejected in preCheck.
				_ = st.applyAuthorization(&st.authList[i])
			}
		}
		if rules.IsPrague {
			if target, ok := types.ParseDelegation(st.state.GetCode(st.to())); ok {
				st.state.AddAddressToAccessList(target)
			}
		}
		ret, st.gas, vmerr = st.evm.Call(sender, st.to(), st.data, st.gas, st.value)
	}
	st.refundGasWithFloor(floorDataGas)
	// Do not credit gas fees to the tx block coinbase here. The protocol-level
	// common RPC settlement is handled after receipt gas usage is known:
	//   valid admission winner: actual fee / 5 paid to the common RPC miner
	//   remaining fee: burned by leaving it uncredited
	//   no valid admission: 100% burned
	return &ExecutionResult{UsedGas: st.gasUsed(), EffectiveGasPrice: new(big.Int).Set(st.gasPrice), Err: vmerr, ReturnData: ret}, nil
}

// validateAuthorization validates one EIP-7702 tuple against the current
// chain and account state. The recovered authority is warmed even if its code
// or nonce check subsequently fails.
func (st *StateTransition) validateAuthorization(auth *types.SetCodeAuthorization) (common.Address, error) {
	var authority common.Address
	if auth == nil {
		return authority, ErrAuthorizationInvalidSignature
	}
	chainID := st.evm.ChainConfig().ChainID
	if auth.ChainID != nil && auth.ChainID.Sign() != 0 && (chainID == nil || auth.ChainID.Cmp(chainID) != 0) {
		return authority, ErrAuthorizationWrongChainID
	}
	if auth.Nonce == math.MaxUint64 {
		return authority, ErrAuthorizationNonceOverflow
	}
	var err error
	authority, err = auth.Authority()
	if err != nil {
		return authority, fmt.Errorf("%w: %v", ErrAuthorizationInvalidSignature, err)
	}
	st.state.AddAddressToAccessList(authority)
	code := st.state.GetCode(authority)
	if _, delegated := types.ParseDelegation(code); len(code) != 0 && !delegated {
		return authority, ErrAuthorizationDestinationHasCode
	}
	if st.state.GetNonce(authority) != auth.Nonce {
		return authority, ErrAuthorizationNonceMismatch
	}
	return authority, nil
}

// applyAuthorization installs or clears a one-level EIP-7702 delegation.
func (st *StateTransition) applyAuthorization(auth *types.SetCodeAuthorization) error {
	authority, err := st.validateAuthorization(auth)
	if err != nil {
		return err
	}
	if st.state.Exist(authority) {
		st.state.AddRefund(params.CallNewAccountGas - params.TxAuthTupleGas)
	}
	st.state.SetNonce(authority, auth.Nonce+1)
	if auth.Address == (common.Address{}) {
		st.state.SetCode(authority, nil)
		return nil
	}
	st.state.SetCode(authority, types.AddressToDelegation(auth.Address))
	return nil
}

func (st *StateTransition) refundGas() {
	st.refundGasWithFloor(0)
}

func (st *StateTransition) refundGasWithFloor(floorDataGas uint64) {
	refundQuotient := params.RefundQuotient
	if st.rules().IsLondon {
		refundQuotient = params.RefundQuotientEIP3529
	}
	refund := st.gasUsed() / refundQuotient
	if refund > st.state.GetRefund() {
		refund = st.state.GetRefund()
	}
	st.gas += refund
	if floorDataGas > 0 && st.gasUsed() < floorDataGas {
		st.gas = st.initialGas - floorDataGas
	}
	remaining := new(big.Int).Mul(new(big.Int).SetUint64(st.gas), st.gasPrice)
	st.state.AddBalance(st.msg.From(), remaining)
	if blobRefund, err := st.blobGasRefund(); err == nil && blobRefund.Sign() > 0 {
		st.state.AddBalance(st.msg.From(), blobRefund)
	}
	st.gp.AddGas(st.gas)
}

func (st *StateTransition) gasUsed() uint64 {
	return st.initialGas - st.gas
}
