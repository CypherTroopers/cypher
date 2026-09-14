package core

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/params"
)

type shanghaiTestMessage struct{ from common.Address }

func (m shanghaiTestMessage) From() common.Address { return m.from }
func (shanghaiTestMessage) To() *common.Address    { return nil }
func (shanghaiTestMessage) GasPrice() *big.Int     { return new(big.Int) }
func (shanghaiTestMessage) Gas() uint64            { return 0 }
func (shanghaiTestMessage) Value() *big.Int        { return new(big.Int) }
func (shanghaiTestMessage) Nonce() uint64          { return 0 }
func (shanghaiTestMessage) CheckNonce() bool       { return false }
func (shanghaiTestMessage) Data() []byte           { return nil }

type dynamicFeeAccountingMessage struct {
	shanghaiTestMessage
	gas      uint64
	value    *big.Int
	feeCap   *big.Int
	tipCap   *big.Int
	gasPrice *big.Int
}

func (m dynamicFeeAccountingMessage) Gas() uint64         { return m.gas }
func (m dynamicFeeAccountingMessage) Value() *big.Int     { return new(big.Int).Set(m.value) }
func (m dynamicFeeAccountingMessage) GasPrice() *big.Int  { return new(big.Int).Set(m.gasPrice) }
func (m dynamicFeeAccountingMessage) GasFeeCap() *big.Int { return new(big.Int).Set(m.feeCap) }
func (m dynamicFeeAccountingMessage) GasTipCap() *big.Int { return new(big.Int).Set(m.tipCap) }

func modernTestConfig(berlin, london, shanghai bool) *params.ChainConfig {
	cfg := &params.ChainConfig{
		ChainID:         big.NewInt(1),
		HomesteadBlock:  big.NewInt(0),
		IstanbulBlock:   big.NewInt(0),
		ByzantiumBlock:  big.NewInt(0),
		PetersburgBlock: big.NewInt(0),
	}
	zeroBlock := big.NewInt(0)
	zeroTime := uint64(0)
	modern := new(params.ModernForkConfig)
	if berlin {
		modern.BerlinBlock = zeroBlock
	}
	if london {
		modern.LondonBlock = zeroBlock
	}
	if shanghai {
		modern.ShanghaiTime = &zeroTime
	}
	cfg.SetModernForkConfig(modern)
	return cfg
}

func newModernTestState(t *testing.T) *state.StateDB {
	t.Helper()
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestIntrinsicGasEIP2028ForkBoundary(t *testing.T) {
	data := []byte{0x01, 0x00}
	legacy, err := IntrinsicGasWithRules(data, nil, false, params.Rules{})
	if err != nil {
		t.Fatal(err)
	}
	if want := params.TxGas + params.TxDataNonZeroGasFrontier + params.TxDataZeroGas; legacy != want {
		t.Fatalf("legacy intrinsic gas = %d, want %d", legacy, want)
	}
	istanbul, err := IntrinsicGasWithRules(data, nil, false, params.Rules{IsIstanbul: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := params.TxGas + params.TxDataNonZeroGasEIP2028 + params.TxDataZeroGas; istanbul != want {
		t.Fatalf("Istanbul intrinsic gas = %d, want %d", istanbul, want)
	}
}

func TestIntrinsicGasEIP3860ForkBoundary(t *testing.T) {
	maxInitCode := make([]byte, params.MaxInitCodeSize)
	got, err := IntrinsicGasWithRules(maxInitCode, nil, true, params.Rules{IsIstanbul: true, IsShanghai: true})
	if err != nil {
		t.Fatal(err)
	}
	want := params.TxGasContractCreation + uint64(len(maxInitCode))*params.TxDataZeroGas +
		uint64(len(maxInitCode)/32)*params.InitCodeWordGas
	if got != want {
		t.Fatalf("Shanghai intrinsic gas = %d, want %d", got, want)
	}
	tooLarge := make([]byte, params.MaxInitCodeSize+1)
	if _, err := IntrinsicGasWithRules(tooLarge, nil, true, params.Rules{IsIstanbul: true}); err != nil {
		t.Fatalf("pre-Shanghai initcode rejected: %v", err)
	}
	if _, err := IntrinsicGasWithRules(tooLarge, nil, true, params.Rules{IsIstanbul: true, IsShanghai: true}); err != ErrMaxInitCodeSizeExceeded {
		t.Fatalf("Shanghai oversized initcode error = %v, want %v", err, ErrMaxInitCodeSizeExceeded)
	}
}

func TestShanghaiWarmsCoinbaseAndForkPrecompiles(t *testing.T) {
	coinbase := common.HexToAddress("0xc01")
	sender := common.HexToAddress("0x501")
	statedb := newModernTestState(t)
	cfg := modernTestConfig(true, true, true)
	evm := vm.NewEVM(vm.Context{BlockNumber: big.NewInt(0), Time: big.NewInt(0), Coinbase: coinbase}, statedb, cfg, vm.Config{})
	transition := &StateTransition{state: statedb, evm: evm}
	rules := transition.rules()
	transition.prepareAccessList(sender, nil, rules)
	if !statedb.AddressInAccessList(coinbase) {
		t.Fatal("Shanghai coinbase is not warm")
	}
	if !statedb.AddressInAccessList(common.BytesToAddress([]byte{9})) {
		t.Fatal("Istanbul precompile 0x09 is not warm")
	}

	preShanghaiState := newModernTestState(t)
	preShanghaiCfg := modernTestConfig(true, true, false)
	preShanghaiEVM := vm.NewEVM(vm.Context{BlockNumber: big.NewInt(0), Time: big.NewInt(0), Coinbase: coinbase}, preShanghaiState, preShanghaiCfg, vm.Config{})
	preShanghaiTransition := &StateTransition{state: preShanghaiState, evm: preShanghaiEVM}
	preShanghaiTransition.prepareAccessList(sender, nil, preShanghaiTransition.rules())
	if preShanghaiState.AddressInAccessList(coinbase) {
		t.Fatal("coinbase is warm before Shanghai")
	}
}

func TestBerlinActivePrecompilesIncludeAddressNine(t *testing.T) {
	addresses := activePrecompileAddresses(params.Rules{IsBerlin: true})
	want := common.BytesToAddress([]byte{9})
	for _, addr := range addresses {
		if addr == want {
			return
		}
	}
	t.Fatalf("Berlin active precompiles do not contain %s: %v", want, addresses)
}

func TestRefundQuotientChangesAtLondon(t *testing.T) {
	for _, tc := range []struct {
		name       string
		london     bool
		wantRefund uint64
	}{
		{name: "pre-London", wantRefund: 50},
		{name: "London", london: true, wantRefund: 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			from := common.HexToAddress("0xf00")
			statedb := newModernTestState(t)
			statedb.CreateAccount(from)
			statedb.AddRefund(100)
			cfg := modernTestConfig(true, tc.london, false)
			evm := vm.NewEVM(vm.Context{BlockNumber: big.NewInt(0), Time: big.NewInt(0)}, statedb, cfg, vm.Config{})
			transition := &StateTransition{
				gp:            new(GasPool),
				msg:           shanghaiTestMessage{from: from},
				gas:           0,
				initialGas:    100,
				gasFeeCap:     new(big.Int),
				gasPrice:      new(big.Int),
				blobGasFeeCap: new(big.Int),
				state:         statedb,
				evm:           evm,
			}
			transition.refundGas()
			if transition.gas != tc.wantRefund {
				t.Fatalf("refunded gas = %d, want %d", transition.gas, tc.wantRefund)
			}
		})
	}
}

func TestDynamicFeeChargesEffectivePriceNotFeeCap(t *testing.T) {
	from := common.HexToAddress("0xfee")
	statedb := newModernTestState(t)
	statedb.CreateAccount(from)
	initial := big.NewInt(1_000_000)
	statedb.AddBalance(from, initial)
	msg := dynamicFeeAccountingMessage{
		shanghaiTestMessage: shanghaiTestMessage{from: from},
		gas:                 100,
		value:               new(big.Int),
		feeCap:              big.NewInt(10),
		tipCap:              big.NewInt(2),
		gasPrice:            big.NewInt(10),
	}
	evm := vm.NewEVM(vm.Context{BlockNumber: big.NewInt(0), Time: big.NewInt(0), BaseFee: big.NewInt(3)}, statedb, modernTestConfig(true, true, false), vm.Config{})
	transition := NewStateTransition(evm, msg, new(GasPool).AddGas(msg.Gas()))
	if err := transition.preCheck(); err != nil {
		t.Fatal(err)
	}
	transition.gas = 40 // Simulate 60 gas consumed before refund.
	transition.refundGas()
	want := new(big.Int).Sub(initial, big.NewInt(60*5)) // effective price = base fee 3 + tip 2
	if got := statedb.GetBalance(from); got.Cmp(want) != 0 {
		t.Fatalf("balance = %s, want %s", got, want)
	}
}

func TestDynamicFeeBalanceCheckIncludesValueAtFeeCap(t *testing.T) {
	from := common.HexToAddress("0xbad")
	statedb := newModernTestState(t)
	statedb.CreateAccount(from)
	statedb.AddBalance(from, big.NewInt(1_000))
	msg := dynamicFeeAccountingMessage{
		shanghaiTestMessage: shanghaiTestMessage{from: from},
		gas:                 100,
		value:               big.NewInt(1),
		feeCap:              big.NewInt(10),
		tipCap:              big.NewInt(2),
		gasPrice:            big.NewInt(10),
	}
	evm := vm.NewEVM(vm.Context{BlockNumber: big.NewInt(0), Time: big.NewInt(0), BaseFee: big.NewInt(3)}, statedb, modernTestConfig(true, true, false), vm.Config{})
	transition := NewStateTransition(evm, msg, new(GasPool).AddGas(msg.Gas()))
	if err := transition.preCheck(); err != ErrInsufficientFunds {
		t.Fatalf("preCheck error = %v, want %v", err, ErrInsufficientFunds)
	}
}

func TestNativeAndContractTransactionsChargeActualExecutionGas(t *testing.T) {
	from := common.HexToAddress("0x1000000000000000000000000000000000000001")
	plainTo := common.HexToAddress("0x2000000000000000000000000000000000000002")
	contractTo := common.HexToAddress("0x3000000000000000000000000000000000000003")
	gasPrice := big.NewInt(params.FixedTransferGasPricePerGas)
	initial := new(big.Int).Mul(big.NewInt(10), big.NewInt(params.Ether))

	for _, tc := range []struct {
		name        string
		to          common.Address
		code        []byte
		wantGasUsed uint64
	}{
		{name: "plain-transfer", to: plainTo, wantGasUsed: params.TxGas},
		// PUSH1 1 PUSH1 0 SSTORE STOP ensures the EVM executes chargeable contract work.
		{name: "contract-call", to: contractTo, code: []byte{0x60, 0x01, 0x60, 0x00, 0x55, 0x00}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			statedb := newModernTestState(t)
			statedb.CreateAccount(from)
			statedb.AddBalance(from, new(big.Int).Set(initial))
			if len(tc.code) > 0 {
				statedb.SetCode(tc.to, tc.code)
			}
			cfg := modernTestConfig(true, true, true)
			evm := vm.NewEVM(vm.Context{
				CanTransfer: CanTransfer, Transfer: Transfer,
				BlockNumber: big.NewInt(0), Time: big.NewInt(0),
				GasPrice: new(big.Int).Set(gasPrice), BaseFee: big.NewInt(params.FixedBaseFeePerGas),
			}, statedb, cfg, vm.Config{})
			msg := types.NewMessageWithModernFields(
				types.LegacyTxType, from, &tc.to, 0, new(big.Int), 100_000,
				gasPrice, gasPrice, gasPrice, nil, nil, nil, nil, nil, false,
			)
			result, err := ApplyMessage(evm, msg, new(GasPool).AddGas(msg.Gas()))
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantGasUsed != 0 && result.UsedGas != tc.wantGasUsed {
				t.Fatalf("gas used = %d, want %d", result.UsedGas, tc.wantGasUsed)
			}
			if len(tc.code) > 0 && result.UsedGas <= params.TxGas {
				t.Fatalf("contract gas used = %d, want EVM execution above %d", result.UsedGas, params.TxGas)
			}
			wantBalance := new(big.Int).Sub(initial, new(big.Int).Mul(new(big.Int).SetUint64(result.UsedGas), gasPrice))
			if got := statedb.GetBalance(from); got.Cmp(wantBalance) != 0 {
				t.Fatalf("sender balance = %s, want actual gas charge %s", got, wantBalance)
			}
		})
	}
}
