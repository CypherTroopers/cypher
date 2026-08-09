package core

import (
	"errors"
	"math"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/params"
)

func modernExecutionTestConfig(prague, osaka bool) *params.ChainConfig {
	cfg := modernTestConfig(true, true, true)
	zero := uint64(0)
	modern := cfg.ModernForkConfig()
	modern.CancunTime = &zero
	if prague || osaka {
		modern.PragueTime = &zero
	}
	if osaka {
		modern.OsakaTime = &zero
	}
	return cfg
}

func signedSetCodeTestMessage(t *testing.T, keyHex string, auths []types.SetCodeAuthorization, gas uint64) types.Message {
	t.Helper()
	key, err := crypto.HexToECDSA(keyHex)
	if err != nil {
		t.Fatal(err)
	}
	tx := types.NewTx(&types.SetCodeTx{
		ChainID:   big.NewInt(1),
		GasTipCap: new(big.Int),
		GasFeeCap: new(big.Int),
		Gas:       gas,
		To:        common.HexToAddress("0x7702"),
		Value:     new(big.Int),
		AuthList:  auths,
	})
	tx, err = types.SignTx(tx, types.NewPragueSigner(big.NewInt(1)), key)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := tx.AsMessage(types.NewPragueSigner(big.NewInt(1)))
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestSetCodeForkGateAndAuthorizationApplication(t *testing.T) {
	authorityKey, err := crypto.HexToECDSA("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	if err != nil {
		t.Fatal(err)
	}
	authority := crypto.PubkeyToAddress(authorityKey.PublicKey)
	delegate := common.HexToAddress("0x123456")
	auth, err := types.SignSetCode(authorityKey, types.SetCodeAuthorization{ChainID: big.NewInt(1), Address: delegate})
	if err != nil {
		t.Fatal(err)
	}
	msg := signedSetCodeTestMessage(t, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", []types.SetCodeAuthorization{auth}, 100_000)

	preState := newModernTestState(t)
	preState.CreateAccount(msg.From())
	preEVM := vm.NewEVM(vm.Context{BlockNumber: big.NewInt(0), Time: big.NewInt(0)}, preState, modernExecutionTestConfig(false, false), vm.Config{})
	preTransition := NewStateTransition(preEVM, msg, new(GasPool).AddGas(msg.Gas()))
	if err := preTransition.preCheck(); !errors.Is(err, ErrTxTypeNotSupported) {
		t.Fatalf("pre-Prague set-code error = %v, want %v", err, ErrTxTypeNotSupported)
	}

	statedb := newModernTestState(t)
	statedb.CreateAccount(msg.From())
	statedb.CreateAccount(authority)
	evm := vm.NewEVM(vm.Context{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
		BlockNumber: big.NewInt(0),
		Time:        big.NewInt(0),
	}, statedb, modernExecutionTestConfig(true, false), vm.Config{})
	result, err := ApplyMessage(evm, msg, new(GasPool).AddGas(msg.Gas()))
	if err != nil {
		t.Fatal(err)
	}
	if result.Failed() {
		t.Fatalf("set-code execution failed: %v", result.Err)
	}
	if got := statedb.GetNonce(authority); got != 1 {
		t.Fatalf("authority nonce = %d, want 1", got)
	}
	if got := statedb.GetCode(authority); string(got) != string(types.AddressToDelegation(delegate)) {
		t.Fatalf("authority code = %x, want delegation %x", got, types.AddressToDelegation(delegate))
	}

	clear, err := types.SignSetCode(authorityKey, types.SetCodeAuthorization{ChainID: big.NewInt(1), Nonce: 1})
	if err != nil {
		t.Fatal(err)
	}
	transition := &StateTransition{state: statedb, evm: evm}
	if err := transition.applyAuthorization(&clear); err != nil {
		t.Fatal(err)
	}
	if got := statedb.GetCode(authority); len(got) != 0 {
		t.Fatalf("cleared authority still has code %x", got)
	}
}

func TestAuthorizationValidationWarmsAuthorityOnStateFailure(t *testing.T) {
	key, err := crypto.HexToECDSA("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	if err != nil {
		t.Fatal(err)
	}
	authority := crypto.PubkeyToAddress(key.PublicKey)
	auth, err := types.SignSetCode(key, types.SetCodeAuthorization{ChainID: big.NewInt(1), Address: common.HexToAddress("0xbeef"), Nonce: 1})
	if err != nil {
		t.Fatal(err)
	}
	statedb := newModernTestState(t)
	statedb.CreateAccount(authority)
	evm := vm.NewEVM(vm.Context{BlockNumber: big.NewInt(0), Time: big.NewInt(0)}, statedb, modernExecutionTestConfig(true, false), vm.Config{})
	transition := &StateTransition{state: statedb, evm: evm}
	if _, err := transition.validateAuthorization(&auth); !errors.Is(err, ErrAuthorizationNonceMismatch) {
		t.Fatalf("authorization error = %v, want %v", err, ErrAuthorizationNonceMismatch)
	}
	if !statedb.AddressInAccessList(authority) {
		t.Fatal("authority was not warmed before state validation failure")
	}
}

func TestPragueFloorDataGasForkBoundary(t *testing.T) {
	data := make([]byte, 100)
	for i := range data {
		data[i] = 1
	}
	floor, err := FloorDataGas(data)
	if err != nil {
		t.Fatal(err)
	}
	if want := params.TxGas + 100*params.TxTokenPerNonZeroByte*params.TxCostFloorPerToken; floor != want {
		t.Fatalf("floor data gas = %d, want %d", floor, want)
	}
	from := common.HexToAddress("0xf001")
	to := common.HexToAddress("0xf002")
	msg := types.NewMessage(from, &to, 0, new(big.Int), 50_000, new(big.Int), data, false)
	run := func(prague bool) uint64 {
		statedb := newModernTestState(t)
		statedb.CreateAccount(from)
		evm := vm.NewEVM(vm.Context{CanTransfer: CanTransfer, Transfer: Transfer, BlockNumber: big.NewInt(0), Time: big.NewInt(0)}, statedb, modernExecutionTestConfig(prague, false), vm.Config{})
		result, err := ApplyMessage(evm, msg, new(GasPool).AddGas(msg.Gas()))
		if err != nil {
			t.Fatal(err)
		}
		return result.UsedGas
	}
	prePrague := run(false)
	if prePrague >= floor {
		t.Fatalf("pre-Prague gas used = %d, expected below floor %d", prePrague, floor)
	}
	if prague := run(true); prague != floor {
		t.Fatalf("Prague gas used = %d, want floor %d", prague, floor)
	}
}

func TestOsakaTransactionGasCapBoundary(t *testing.T) {
	from := common.HexToAddress("0xca01")
	to := common.HexToAddress("0xca02")
	msg := types.NewMessage(from, &to, 0, new(big.Int), params.MaxTxGas+1, new(big.Int), nil, true)
	for _, tc := range []struct {
		name    string
		osaka   bool
		wantErr error
	}{
		{name: "pre-Osaka"},
		{name: "Osaka", osaka: true, wantErr: ErrTxGasLimitExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			statedb := newModernTestState(t)
			statedb.CreateAccount(from)
			evm := vm.NewEVM(vm.Context{BlockNumber: big.NewInt(0), Time: big.NewInt(0)}, statedb, modernExecutionTestConfig(true, tc.osaka), vm.Config{})
			transition := NewStateTransition(evm, msg, new(GasPool).AddGas(msg.Gas()))
			err := transition.preCheck()
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("preCheck error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestSenderCodeAndNonceForkRules(t *testing.T) {
	from := common.HexToAddress("0x3607")
	to := common.HexToAddress("0x01")
	newTransition := func(t *testing.T, cfg *params.ChainConfig, code []byte, nonce uint64) *StateTransition {
		t.Helper()
		statedb := newModernTestState(t)
		statedb.CreateAccount(from)
		statedb.SetCode(from, code)
		statedb.SetNonce(from, nonce)
		msg := types.NewMessage(from, &to, nonce, new(big.Int), 0, new(big.Int), nil, true)
		evm := vm.NewEVM(vm.Context{BlockNumber: big.NewInt(0), Time: big.NewInt(0)}, statedb, cfg, vm.Config{})
		return NewStateTransition(evm, msg, new(GasPool))
	}
	if err := newTransition(t, modernExecutionTestConfig(false, false), []byte{byte(vm.STOP)}, 0).preCheck(); !errors.Is(err, ErrSenderNoEOA) {
		t.Fatalf("contract sender error = %v, want %v", err, ErrSenderNoEOA)
	}
	delegation := types.AddressToDelegation(common.HexToAddress("0xbeef"))
	if err := newTransition(t, modernExecutionTestConfig(true, false), delegation, 0).preCheck(); err != nil {
		t.Fatalf("Prague delegated sender rejected: %v", err)
	}
	if err := newTransition(t, modernExecutionTestConfig(true, false), nil, math.MaxUint64).preCheck(); !errors.Is(err, ErrNonceMax) {
		t.Fatalf("max nonce error = %v, want %v", err, ErrNonceMax)
	}
}

func TestEVMContextUsesEffectiveDynamicGasPrice(t *testing.T) {
	from := common.HexToAddress("0xfee")
	author := common.Address{}
	msg := dynamicFeeAccountingMessage{
		shanghaiTestMessage: shanghaiTestMessage{from: from},
		value:               new(big.Int),
		feeCap:              big.NewInt(10),
		tipCap:              big.NewInt(2),
		gasPrice:            big.NewInt(10),
	}
	header := &types.Header{Number: big.NewInt(1), Time: 0, Difficulty: big.NewInt(1), BaseFee: big.NewInt(3)}
	ctx := NewEVMContextWithConfig(modernExecutionTestConfig(true, true), msg, header, nil, &author)
	if got, want := ctx.GasPrice, big.NewInt(5); got.Cmp(want) != 0 {
		t.Fatalf("GASPRICE context = %s, want %s", got, want)
	}
}

func TestTypedTransactionForkGates(t *testing.T) {
	tests := []struct {
		name   string
		txType uint8
		rules  params.Rules
		wantOK bool
	}{
		{"access-list before Berlin", types.AccessListTxType, params.Rules{}, false},
		{"access-list at Berlin", types.AccessListTxType, params.Rules{IsBerlin: true}, true},
		{"dynamic before London", types.DynamicFeeTxType, params.Rules{IsBerlin: true}, false},
		{"dynamic at London", types.DynamicFeeTxType, params.Rules{IsLondon: true}, true},
		{"blob before Cancun", types.BlobTxType, params.Rules{IsLondon: true}, false},
		{"blob at Cancun", types.BlobTxType, params.Rules{IsCancun: true}, true},
		{"set-code before Prague", types.SetCodeTxType, params.Rules{IsCancun: true}, false},
		{"set-code at Prague", types.SetCodeTxType, params.Rules{IsPrague: true}, true},
		{"unknown", 0x7f, params.Rules{IsPrague: true}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateTxTypeForRules(test.txType, test.rules)
			if (err == nil) != test.wantOK {
				t.Fatalf("error = %v, wantOK=%v", err, test.wantOK)
			}
		})
	}
}
