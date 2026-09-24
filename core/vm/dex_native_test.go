package vm

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/params"
)

func TestDEXNativeRejectsAlternateCallContextsAndReservedCreation(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := *params.TestChainConfig
	cfg.DEXDevnet = &params.DEXDevnetConfig{Version: 2, ActivationBlock: 1, Custody: params.DEXSettlementAddress}
	sender := common.Address{1}
	st.AddBalance(sender, big.NewInt(100))
	st.SetNonce(params.DEXSettlementAddress, 1)
	ctx := Context{Origin: sender, BlockNumber: big.NewInt(1), Time: big.NewInt(1), CanTransfer: func(s StateDB, a common.Address, v *big.Int) bool { return s.GetBalance(a).Cmp(v) >= 0 }, Transfer: func(s StateDB, a, b common.Address, v *big.Int) { s.SubBalance(a, v); s.AddBalance(b, v) }}
	evm := NewEVM(ctx, st, &cfg, Config{})
	for name, call := range map[string]func() error{
		"callcode": func() error {
			_, _, err := evm.CallCode(AccountRef(sender), params.DEXSettlementAddress, nil, 10000, new(big.Int))
			return err
		},
		"delegatecall": func() error {
			_, _, err := evm.DelegateCall(AccountRef(sender), params.DEXSettlementAddress, nil, 10000)
			return err
		},
		"staticcall": func() error {
			_, _, err := evm.StaticCall(AccountRef(sender), params.DEXSettlementAddress, nil, 10000)
			return err
		},
		"internalcall": func() error {
			evm.depth = 1
			defer func() { evm.depth = 0 }()
			_, _, err := evm.Call(AccountRef(sender), params.DEXSettlementAddress, nil, 10000, big.NewInt(1))
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); err != ErrExecutionReverted {
				t.Fatal("context not rejected", err)
			}
			if st.GetBalance(sender).Cmp(big.NewInt(100)) != 0 || st.GetBalance(params.DEXSettlementAddress).Sign() != 0 {
				t.Fatal("context rejection leaked value")
			}
		})
	}
	// Even if a faulty/missing genesis account had nonce zero, the protocol
	// address is intrinsically reserved for both CREATE/CREATE2 targets.
	st.SetNonce(params.DEXSettlementAddress, 0)
	if _, _, _, err := evm.create(AccountRef(sender), &codeAndHash{code: []byte{0}}, 10000, new(big.Int), params.DEXSettlementAddress); err != ErrContractAddressCollision {
		t.Fatal("reserved create target", err)
	}
}
