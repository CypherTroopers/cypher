package core

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/settlement"
	"github.com/cypherium/cypher/params"
)

func TestDEXRollingGenesisSignedTXAndLocalOverride(t *testing.T) {
	legacy := newNativeTXVersionFixture(t, 0, 2)
	rolling := newNativeTXVersionFixture(t, 0, 3)
	if legacy.chain.genesis.Hash() == rolling.chain.genesis.Hash() {
		t.Fatal("rolling genesis did not authenticate the new version")
	}
	call, _ := (protocol.NativeCall{Operation: protocol.NativeDeposit}).Encode()
	for _, f := range []*nativeTXFixture{legacy, rolling} {
		tx := f.tx(t, 0, big.NewInt(123), 600000, call)
		r, err := f.apply(t, tx, vm.Config{})
		if err != nil || r == nil || r.Status != types.ReceiptStatusSuccessful || f.st.GetNonce(f.sender) != 1 || f.st.GetBalance(params.DEXSettlementAddress).Cmp(big.NewInt(123)) != 0 {
			t.Fatal("versioned normal transaction failed", r, err)
		}
		entry, err := settlement.ReadNativeEntry(f.st, params.DEXSettlementAddress, 0)
		if err != nil || entry.Genesis != protocol.Hash(f.chain.genesis.Hash()) || entry.Nonce != 0 || entry.Amount.Big().Cmp(big.NewInt(123)) != 0 {
			t.Fatal("versioned inbox identity", err)
		}
	}
	// A local config toggle cannot activate rolling rules on the old genesis.
	f := newNativeTXVersionFixture(t, 0, 2)
	f.config.DEXDevnet.Version = 3
	before := new(big.Int).Set(f.st.GetBalance(f.sender))
	if r, err := f.apply(t, f.tx(t, 0, big.NewInt(123), 600000, call), vm.Config{}); err == nil || r != nil {
		t.Fatal("local-only version override became a valid receipt", r, err)
	}
	if f.st.GetNonce(f.sender) != 0 || f.st.GetBalance(f.sender).Cmp(before) != 0 || f.st.GetBalance(params.DEXSettlementAddress).Sign() != 0 {
		t.Fatal("unauthenticated config changed funds")
	}
}
