package core

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/params"
)

type nativeGenesisConfigChain struct {
	nativeTXChain
	store *BlockChain
}

func (c nativeGenesisConfigChain) DEXGenesisConfig() (*params.ChainConfig, *params.ModernForkConfig) {
	return c.store.DEXGenesisConfig()
}

func TestDEXNativeImmutableGenesisConfigAndLocalFailure(t *testing.T) {
	for _, mode := range []string{"runtime-port", "missing-config", "corrupt-config", "activation-override", "disabled-override", "alias"} {
		t.Run(mode, func(t *testing.T) {
			f := newNativeTXFixture(t, 0)
			db := rawdb.NewMemoryDatabase()
			rawdb.WriteChainConfig(db, f.chain.genesis.Hash(), f.config)
			bc := &BlockChain{db: db, genesisBlock: f.chain.genesis}
			chain := nativeGenesisConfigChain{nativeTXChain: f.chain, store: bc}
			runtime := *f.config
			runtime.RnetPort = "49271"
			runtime.EnabledTPS = !runtime.EnabledTPS
			success := mode == "runtime-port" || mode == "alias"
			switch mode {
			case "missing-config":
				bc.db = rawdb.NewMemoryDatabase()
			case "corrupt-config":
				corrupt := *f.config
				corrupt.ChainID = new(big.Int).Add(f.config.ChainID, big.NewInt(1))
				rawdb.WriteChainConfig(db, f.chain.genesis.Hash(), &corrupt)
			case "activation-override":
				dex := *runtime.DEXDevnet
				dex.ActivationBlock++
				runtime.DEXDevnet = &dex
			case "disabled-override":
				runtime.DEXDevnet = nil
			case "alias":
				copy, _ := bc.DEXGenesisConfig()
				copy.ChainID.SetInt64(1)
				copy.DEXDevnet.Committee[0].Address = "mutated caller copy"
			}
			input, _ := (protocol.NativeCall{Operation: protocol.NativeDeposit}).Encode()
			tx := f.tx(t, 0, big.NewInt(5), 600000, input)
			before := new(big.Int).Set(f.st.GetBalance(f.sender))
			gp, used := new(GasPool).AddGas(f.header.GasLimit), uint64(0)
			f.st.Prepare(tx.Hash(), f.header.Hash(), 0)
			receipt, err := ApplyTransaction(&runtime, chain, nil, gp, f.st, f.header, tx, &used, vm.Config{})
			if success {
				if err != nil || receipt == nil || receipt.Status != types.ReceiptStatusSuccessful || len(receipt.Logs) != 1 || len(receipt.Logs[0].Data) != protocol.InboxEntrySize {
					t.Fatal("runtime settings changed native execution", receipt, err)
				}
				return
			}
			if err == nil || receipt != nil || used != 0 || gp.Gas() != f.header.GasLimit {
				t.Fatal("local authentication failure became a receipt", receipt, used, gp.Gas(), err)
			}
			if f.st.GetBalance(f.sender).Cmp(before) != 0 || f.st.GetNonce(f.sender) != 0 || f.st.GetBalance(params.DEXSettlementAddress).Sign() != 0 {
				t.Fatal("local authentication failure modified funds or nonce")
			}
		})
	}
}

func TestDEXNativeContextMissingChainDoesNotPanic(t *testing.T) {
	f := newNativeTXFixture(t, 0)
	input, _ := (protocol.NativeCall{Operation: protocol.NativeDeposit}).Encode()
	tx := f.tx(t, 0, big.NewInt(1), 600000, input)
	msg, err := tx.AsMessage(types.NewEIP155Signer(f.config.ChainID))
	if err != nil {
		t.Fatal(err)
	}
	ctx := NewEVMContextWithConfig(f.config, msg, f.header, nil, &f.sender)
	if ctx.NativeContextError == nil {
		t.Fatal("missing historical chain did not fail closed")
	}
}

func TestDEXNativeGenesisForkContextDoesNotRetainSideTable(t *testing.T) {
	f := newNativeTXFixture(t, 10000)
	db := rawdb.NewMemoryDatabase()
	rawdb.WriteChainConfig(db, f.chain.genesis.Hash(), f.config)
	bc := &BlockChain{db: db, genesisBlock: f.chain.genesis}
	stored, forks := bc.DEXGenesisConfig()
	if stored == nil || forks == nil || stored.ModernForkConfig() != nil {
		t.Fatal("genesis read retained pointer-keyed fork registration")
	}
	chain := nativeGenesisConfigChain{nativeTXChain: f.chain, store: bc}
	input, _ := (protocol.NativeCall{Operation: protocol.NativeDeposit}).Encode()
	tx := f.tx(t, 0, big.NewInt(1), 600000, input)
	msg, err := tx.AsMessage(types.NewEIP155Signer(f.config.ChainID))
	if err != nil {
		t.Fatal(err)
	}
	ctx := NewEVMContextWithConfig(f.config, msg, f.header, chain, &f.sender)
	if ctx.NativeContextError != nil || ctx.NativeGenesisForks == nil || ctx.NativeGenesisConfig.ModernForkConfig() != nil {
		t.Fatal("context failed authentication or retained fork registration", ctx.NativeContextError)
	}
	used := uint64(0)
	f.st.Prepare(tx.Hash(), f.header.Hash(), 0)
	receipt, err := ApplyTransaction(f.config, chain, nil, new(GasPool).AddGas(f.header.GasLimit), f.st, f.header, tx, &used, vm.Config{})
	if err != nil || receipt == nil || receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatal("detached modern forks changed native execution", receipt, err)
	}
}
