package colossusX

import (
	"fmt"
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

func verifyModernHeaderFields(config *params.ChainConfig, header *types.Header, parents ...*types.Header) error {
	if config == nil || header == nil || header.Number == nil {
		return nil
	}
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[0]
	}
	modern := config.CypheriumModernForks(header.Number, header.Time)
	if modern.IsShanghai {
		if header.WithdrawalsHash != types.EmptyWithdrawalsHash {
			return fmt.Errorf("invalid withdrawalsRoot for execution-only Shanghai block: have %s want %s", header.WithdrawalsHash, types.EmptyWithdrawalsHash)
		}
		// An ordinary transaction block that follows another ordinary block in
		// the same authenticated key epoch must inherit its PREVRANDAO carrier.
		// A Fair HotStuff key-block carrier is the transition exception: its
		// direct child is still certified by the old epoch while the carrier waits
		// for that child QC to reach two-chain finality. The FHS key-chain checks
		// bind the child's value to that old canonical key separately.
		if parent != nil && header.BlockType != types.Key_Block &&
			(!config.FairHotstuff || parent.BlockType != types.Key_Block) &&
			header.KeyHash == parent.KeyHash && header.MixDigest != parent.MixDigest {
			return fmt.Errorf("invalid PREVRANDAO continuation: have %s want %s", header.MixDigest, parent.MixDigest)
		}
	} else if header.WithdrawalsHash != (common.Hash{}) {
		return fmt.Errorf("unexpected withdrawalsRoot before Shanghai fork")
	}

	if modern.IsLondon {
		if header.BaseFee == nil {
			return fmt.Errorf("missing baseFeePerGas after London fork")
		}
		want := big.NewInt(params.FixedBaseFeePerGas)
		if header.BaseFee.Cmp(want) != 0 {
			return fmt.Errorf("invalid baseFeePerGas: have %v want %v", header.BaseFee, want)
		}
	} else if header.BaseFee != nil {
		return fmt.Errorf("unexpected baseFeePerGas before London fork")
	}

	if modern.IsCancun {
		if err := verifyCancunBlobHeaderFields(config, header, parent); err != nil {
			return err
		}
		// ColossusX has no Beacon consensus root source. Accepting an arbitrary
		// non-zero value would let a proposer mutate the EIP-4788 system state
		// without an authenticated consensus-layer commitment.
		if header.ParentBeaconRoot != (common.Hash{}) {
			return fmt.Errorf("non-zero parentBeaconBlockRoot is unsupported by ColossusX")
		}
	} else {
		if header.BlobGasUsed != 0 {
			return fmt.Errorf("unexpected blobGasUsed before Cancun fork")
		}
		if header.ExcessBlobGas != 0 {
			return fmt.Errorf("unexpected excessBlobGas before Cancun fork")
		}
		if header.ParentBeaconRoot != (common.Hash{}) {
			return fmt.Errorf("unexpected parentBeaconBlockRoot before Cancun fork")
		}
	}

	if modern.IsPrague {
		if header.RequestsHash != types.EmptyRequestsHash {
			return fmt.Errorf("invalid requestsHash for ColossusX Prague block: have %s want %s", header.RequestsHash, types.EmptyRequestsHash)
		}
	} else if header.RequestsHash != (common.Hash{}) {
		return fmt.Errorf("unexpected requestsHash before Prague fork")
	}
	return nil
}

func verifyCancunBlobHeaderFields(config *params.ChainConfig, header, parent *types.Header) error {
	blobCfg := config.ActiveBlobConfig(header.Time)
	maxBlobGas := params.MaxBlobGasPerBlock(blobCfg)
	if header.BlobGasUsed > maxBlobGas {
		return fmt.Errorf("invalid blobGasUsed: have %d, max %d", header.BlobGasUsed, maxBlobGas)
	}
	if header.BlobGasUsed%params.BlobTxBlobGasPerBlob != 0 {
		return fmt.Errorf("invalid blobGasUsed alignment: have %d, blobGasPerBlob %d", header.BlobGasUsed, params.BlobTxBlobGasPerBlob)
	}
	if parent != nil {
		expected := params.CalcExcessBlobGasForFork(
			config.IsOsaka(header.Number, header.Time),
			parent.ExcessBlobGas,
			parent.BlobGasUsed,
			parent.BaseFee,
			blobCfg,
		)
		if header.ExcessBlobGas != expected {
			return fmt.Errorf("invalid excessBlobGas: have %d, want %d", header.ExcessBlobGas, expected)
		}
	}
	blobBaseFee := params.CalcBlobBaseFeeAtTime(config, header.Time, header.ExcessBlobGas)
	if blobBaseFee == nil || blobBaseFee.Sign() <= 0 {
		return fmt.Errorf("invalid blobBaseFee scaffold result: %v", blobBaseFee)
	}
	return nil
}
