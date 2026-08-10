package eth

import (
	"errors"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/params"
)

func TestSetupGenesisBlocksPropagatesKeyGenesisError(t *testing.T) {
	wantErr := errors.New("key genesis failed")
	txCalled := false
	_, _, err := setupGenesisBlocksWith(nil, nil, nil,
		func(ethdb.Database, *core.GenesisKey) (*params.ChainConfig, common.Hash, error) {
			return nil, common.Hash{}, wantErr
		},
		func(ethdb.Database, *core.Genesis) (*params.ChainConfig, common.Hash, error) {
			txCalled = true
			return nil, common.Hash{}, nil
		},
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if txCalled {
		t.Fatal("transaction genesis setup ran after key genesis failure")
	}
}

func TestSetupGenesisBlocksDoesNotMisapplyKeyCompatErrorToTxRewind(t *testing.T) {
	wantErr := &params.ConfigCompatError{What: "key fork", RewindTo: 3}
	txCalled := false
	_, _, err := setupGenesisBlocksWith(nil, nil, nil,
		func(ethdb.Database, *core.GenesisKey) (*params.ChainConfig, common.Hash, error) {
			return nil, common.Hash{}, wantErr
		},
		func(ethdb.Database, *core.Genesis) (*params.ChainConfig, common.Hash, error) {
			txCalled = true
			return nil, common.Hash{}, nil
		},
	)
	if err == nil {
		t.Fatal("key compatibility error was ignored")
	}
	if _, ok := err.(*params.ConfigCompatError); ok {
		t.Fatal("key compatibility error would be mistaken for a transaction-chain rewind")
	}
	var compat *params.ConfigCompatError
	if !errors.As(err, &compat) || compat != wantErr {
		t.Fatalf("wrapped compatibility error = %v, want %v", err, wantErr)
	}
	if txCalled {
		t.Fatal("transaction genesis setup ran after key compatibility failure")
	}
}

func TestSetupGenesisBlocksPropagatesTransactionGenesisError(t *testing.T) {
	wantErr := errors.New("transaction genesis failed")
	_, _, err := setupGenesisBlocksWith(nil, nil, nil,
		func(ethdb.Database, *core.GenesisKey) (*params.ChainConfig, common.Hash, error) {
			return nil, common.Hash{}, nil
		},
		func(ethdb.Database, *core.Genesis) (*params.ChainConfig, common.Hash, error) {
			return nil, common.Hash{}, wantErr
		},
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
}

func TestSetupGenesisBlocksPreservesTransactionCompatErrorForRewind(t *testing.T) {
	wantConfig := &params.ChainConfig{ChainID: big.NewInt(1337)}
	wantHash := common.HexToHash("0x1234")
	wantErr := &params.ConfigCompatError{What: "test fork", RewindTo: 7}
	config, hash, err := setupGenesisBlocksWith(nil, nil, nil,
		func(ethdb.Database, *core.GenesisKey) (*params.ChainConfig, common.Hash, error) {
			return nil, common.Hash{}, nil
		},
		func(ethdb.Database, *core.Genesis) (*params.ChainConfig, common.Hash, error) {
			return wantConfig, wantHash, wantErr
		},
	)
	if err != wantErr {
		t.Fatalf("error = %v, want compatibility error %v", err, wantErr)
	}
	if config != wantConfig {
		t.Fatalf("config = %p, want %p", config, wantConfig)
	}
	if hash != wantHash {
		t.Fatalf("hash = %s, want %s", hash, wantHash)
	}
}
