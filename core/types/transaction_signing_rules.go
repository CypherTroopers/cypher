package types

import (
	"math/big"

	"github.com/cypherium/cypher/params"
)

// MakeSignerWithTimestamp returns the signer for a block number and timestamp.
// It keeps the existing MakeSigner behavior intact for legacy paths, while new
// execution-layer code can opt into timestamp-based modern forks.
func MakeSignerWithTimestamp(config *params.ChainConfig, blockNumber *big.Int, timestamp uint64) Signer {
	if config == nil {
		return FrontierSigner{}
	}
	switch {
	case config.IsPrague(blockNumber, timestamp):
		return NewPragueSigner(config.ChainID)
	case config.IsCancun(blockNumber, timestamp):
		return NewCancunSigner(config.ChainID)
	case config.IsLondon(blockNumber):
		return NewLondonSigner(config.ChainID)
	case config.IsBerlin(blockNumber):
		return NewEIP2930Signer(config.ChainID)
	default:
		return MakeSigner(config, blockNumber)
	}
}

// LatestSignerForChainID returns a chain-id aware signer that supports
// typed transaction signing/recovery while preserving legacy EIP-155 behavior.
func LatestSignerForChainID(chainID *big.Int) Signer {
	return NewLondonSigner(chainID)
}
