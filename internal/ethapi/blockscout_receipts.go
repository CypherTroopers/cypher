package ethapi

import (
	"context"
	"errors"
	"fmt"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/rpc"
)

// GetBlockReceipts returns receipts in transaction order. An unknown or pending
// block returns null; an existing empty block returns []. It reads the receipts
// once, rather than doing one transaction-index lookup per receipt.
func (s *PublicBlockChainAPI) GetBlockReceipts(ctx context.Context, ref rpc.BlockNumberOrHash) ([]map[string]interface{}, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var block *types.Block
	var err error
	if number, ok := ref.Number(); ok {
		if number == rpc.PendingBlockNumber {
			return nil, nil
		}
		block, err = s.b.BlockByNumber(ctx, number)
	} else if hash, ok := ref.Hash(); ok {
		block, err = s.b.BlockByHash(ctx, hash)
		if err == nil && block != nil && ref.RequireCanonical {
			var canonical *types.Header
			canonical, err = s.b.HeaderByNumber(ctx, rpc.BlockNumber(block.NumberU64()))
			if err == nil && (canonical == nil || canonical.Hash() != hash) {
				err = errors.New("hash is not currently canonical")
			}
		}
	} else {
		return nil, errors.New("block number or hash is required")
	}
	if err != nil || block == nil {
		return nil, err
	}
	txs := block.Transactions()
	result := make([]map[string]interface{}, len(txs))
	if len(txs) == 0 {
		return result, nil
	}
	receipts, err := s.b.GetReceipts(ctx, block.Hash())
	if err != nil {
		return nil, err
	}
	if len(receipts) != len(txs) {
		return nil, fmt.Errorf("receipt count mismatch for block %s: have %d want %d", block.Hash(), len(receipts), len(txs))
	}
	for i, tx := range txs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if receipts[i] == nil {
			return nil, fmt.Errorf("nil receipt at index %d", i)
		}
		if receipts[i].TxHash != (common.Hash{}) && receipts[i].TxHash != tx.Hash() {
			return nil, fmt.Errorf("receipt transaction hash mismatch at index %d", i)
		}
		result[i], err = marshalBlockscoutReceipt(s.b, block, tx, receipts[i], uint64(i))
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}
