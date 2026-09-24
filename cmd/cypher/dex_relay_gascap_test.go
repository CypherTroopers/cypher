package main

import (
	"context"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/relay"
	"github.com/cypherium/cypher/params"
)

func TestDEXRelaySignerUsesEffectiveGasCapWithoutChangingConfiguration(t *testing.T) {
	m, _ := relayCLIFixture(t)
	const configured = uint64(20_000_000)
	for i := range m.Payers {
		if m.Payers[i].Lane == "anchor" {
			m.Payers[i].GasLimit = configured
		}
	}
	c, err := m.config()
	if err != nil {
		t.Fatal(err)
	}
	s, err := loadRelayLocalSigner(m, c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	call, err := (protocol.NativeCall{Operation: protocol.NativeAnchorUpdate, Body: []byte{1}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	chainID := new(big.Int).SetUint64(c.Domain.ChainID)
	payer := c.Payers[relay.Anchor]
	for _, gas := range []uint64{params.MaxTxGas, configured, params.MaxTxGas - 1, params.MaxTxGas + 1} {
		tx := types.NewTransaction(9, c.Custody, new(big.Int), gas, c.GasPrice, call)
		signed, err := s.Sign(context.Background(), payer, tx, chainID)
		if gas == params.MaxTxGas {
			if err != nil {
				t.Fatal("canonical effective template rejected", err)
			}
			sender, err := types.Sender(types.NewEIP155Signer(chainID), signed)
			if err != nil || sender != payer || signed.Gas() != gas {
				t.Fatal("capped signature sender/gas mismatch", err)
			}
		} else if err == nil {
			t.Fatalf("noncanonical gas template %d signed", gas)
		}
	}
	if c.GasLimits[relay.Anchor] != configured || s.config.GasLimits[relay.Anchor] != configured {
		t.Fatal("effective transaction cap changed durable configuration")
	}
}
