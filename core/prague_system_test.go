package core

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

func pragueSystemTestConfig() *params.ChainConfig {
	zero := uint64(0)
	config := &params.ChainConfig{ChainID: big.NewInt(12367)}
	config.SetModernForkConfig(&params.ModernForkConfig{
		BerlinBlock:  big.NewInt(0),
		LondonBlock:  big.NewInt(0),
		ShanghaiTime: &zero,
		CancunTime:   &zero,
		PragueTime:   &zero,
		BlobSchedule: &params.BlobScheduleConfig{
			Cancun: &params.BlobConfig{Target: 3, Max: 6, BaseFeeUpdateFraction: 3338477},
			Prague: &params.BlobConfig{Target: 6, Max: 9, BaseFeeUpdateFraction: 5007716},
		},
	})
	return config
}

func TestPragueGenesisInstallsHistoryStorageCode(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{Config: pragueSystemTestConfig(), Difficulty: big.NewInt(1), GasLimit: params.GenesisGasLimit}
	block := genesis.ToBlock(db)
	st, err := state.New(block.Root(), state.NewDatabase(db), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.GetCode(params.HistoryStorageAddress); !bytes.Equal(got, params.HistoryStorageCode) {
		t.Fatalf("history contract code mismatch: have %x want %x", got, params.HistoryStorageCode)
	}
	if got := st.GetNonce(params.HistoryStorageAddress); got != 1 {
		t.Fatalf("history contract nonce = %d, want 1", got)
	}
	for _, addr := range []common.Address{params.BeaconRootsAddress, params.WithdrawalRequestAddress, params.ConsolidationRequestAddress} {
		if got := st.GetNonce(addr); got != 1 {
			t.Fatalf("unsupported CL system contract %s nonce = %d, want 1", addr, got)
		}
		if got := st.GetCode(addr); !bytes.Equal(got, params.UnsupportedCLSystemCode) {
			t.Fatalf("unsupported CL system contract %s code = %x, want %x", addr, got, params.UnsupportedCLSystemCode)
		}
	}
}

func TestProcessParentBlockHashRejectsMissingCode(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	st, err := state.New(common.Hash{}, state.NewDatabase(db), nil)
	if err != nil {
		t.Fatal(err)
	}
	header := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1)}
	if err := ProcessParentBlockHash(pragueSystemTestConfig(), header, st); err == nil {
		t.Fatal("missing EIP-2935 predeploy was accepted")
	}
}

func TestProcessParentBlockHashEIP2935(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	st, err := state.New(common.Hash{}, state.NewDatabase(db), nil)
	if err != nil {
		t.Fatal(err)
	}
	st.SetCode(params.HistoryStorageAddress, params.HistoryStorageCode)
	parentHash := common.HexToHash("0x1234")
	header := &types.Header{
		Number:     big.NewInt(1),
		Time:       0,
		ParentHash: parentHash,
		Difficulty: big.NewInt(1),
		GasLimit:   params.GenesisGasLimit,
		BaseFee:    big.NewInt(params.FixedBaseFeePerGas),
	}
	if err := ProcessParentBlockHash(pragueSystemTestConfig(), header, st); err != nil {
		t.Fatal(err)
	}
	if got := st.GetState(params.HistoryStorageAddress, common.Hash{}); got != parentHash {
		t.Fatalf("history slot 0 = %s, want %s", got, parentHash)
	}
}
