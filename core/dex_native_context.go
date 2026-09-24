package core

import (
	"errors"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/params"
)

// authenticateDEXGenesisConfig separates the two legacy node-local fields from
// consensus settings. Every other field must still equal the genesis-committed
// configuration; this is not permission to override activation or committees.
func authenticateDEXGenesisConfig(runtime, genesis *params.ChainConfig, headerCommitment common.Hash) error {
	if genesis == nil {
		return errors.New("DEX native genesis configuration unavailable")
	}
	if runtime == nil {
		return errors.New("DEX native runtime configuration unavailable")
	}
	if genesis.DEXDevnet == nil && runtime.DEXDevnet == nil {
		return nil
	}
	commitment, err := params.FairHotstuffGenesisCommitment(genesis)
	if err != nil || commitment != headerCommitment {
		return errors.New("DEX native stored genesis configuration authentication failed")
	}
	normalized := *runtime
	normalized.RnetPort, normalized.EnabledTPS = genesis.RnetPort, genesis.EnabledTPS
	normalized.SetModernForkConfig(runtime.ModernForkConfig())
	defer normalized.SetModernForkConfig(nil)
	actual, err := params.FairHotstuffGenesisCommitment(&normalized)
	if err != nil || actual != commitment {
		return errors.New("DEX native runtime consensus configuration differs from genesis")
	}
	return nil
}

// DEXGenesisConfig reads the configuration stored under the canonical genesis
// hash. eth.New applies node-local transport settings to its runtime config;
// those settings must never become the native settlement authentication root.
// ReadChainConfig decodes a fresh value, so callers cannot mutate the stored
// genesis configuration through an alias. Fork fields are returned separately:
// the legacy pointer-keyed fork table must not retain one config per transaction.
// Settlement verifies the commitment before using any field.
func (bc *BlockChain) DEXGenesisConfig() (*params.ChainConfig, *params.ModernForkConfig) {
	if bc == nil || bc.db == nil || bc.genesisBlock == nil {
		return nil, nil
	}
	config := rawdb.ReadChainConfig(bc.db, bc.genesisBlock.Hash())
	forks := config.ModernForkConfig()
	config.SetModernForkConfig(nil)
	return config, forks
}

// DEXGenesisKeyHash returns an immutable historical trust anchor. It never
// consults the current key committee/head and does not require a DEX worker.
func (bc *BlockChain) DEXGenesisKeyHash() common.Hash {
	if bc == nil || bc.keyBlockChain == nil {
		return common.Hash{}
	}
	header := bc.keyBlockChain.GetHeaderByNumber(0)
	if header == nil {
		return common.Hash{}
	}
	return header.Hash()
}
