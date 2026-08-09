package ethapi

import (
	"context"
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core/types"
)

type PublicTransactionReceiptAPI struct {
	b Backend
}

func NewPublicTransactionReceiptAPI(b Backend) *PublicTransactionReceiptAPI {
	return &PublicTransactionReceiptAPI{b: b}
}

func commonTxRewardForHash(block *types.Block, txHash common.Hash) *types.CommonTxReward {
	if block == nil {
		return nil
	}
	for _, reward := range block.CommonTxRewards() {
		if reward != nil && reward.TxHash == txHash {
			return reward
		}
	}
	return nil
}

func (s *PublicTransactionReceiptAPI) GetTransactionReceipt(ctx context.Context, hash common.Hash) (map[string]interface{}, error) {
	tx, blockHash, blockNumber, index, err := s.b.GetTransaction(ctx, hash)
	if err != nil {
		return nil, nil
	}
	receipts, err := s.b.GetReceipts(ctx, blockHash)
	if err != nil {
		return nil, err
	}
	if len(receipts) <= int(index) {
		return nil, nil
	}
	receipt := receipts[index]

	signer := rpcTransactionSigner(tx)
	from, _ := types.Sender(signer, tx)

	effectiveGasPrice := new(big.Int).Set(tx.GasPrice())
	var block *types.Block
	if loadedBlock, blockErr := s.b.BlockByHash(ctx, blockHash); blockErr == nil && loadedBlock != nil {
		block = loadedBlock
	}
	if isEIP1559Transaction(tx) {
		baseFee := fixedBaseFeePerGas()
		if block != nil {
			if headerBaseFee := block.Header().BaseFee; headerBaseFee != nil {
				baseFee = new(big.Int).Set(headerBaseFee)
			}
		}
		if tip, tipErr := tx.EffectiveGasTip(baseFee); tipErr == nil {
			effectiveGasPrice = new(big.Int).Add(new(big.Int).Set(baseFee), tip)
		}
	}

	fields := map[string]interface{}{
		"blockHash":         blockHash,
		"blockNumber":       hexutil.Uint64(blockNumber),
		"transactionHash":   hash,
		"transactionIndex":  hexutil.Uint64(index),
		"type":              hexutil.Uint64(tx.Type()),
		"effectiveGasPrice": (*hexutil.Big)(effectiveGasPrice),
		"from":              from,
		"to":                tx.To(),
		"gasUsed":           hexutil.Uint64(receipt.GasUsed),
		"cumulativeGasUsed": hexutil.Uint64(receipt.CumulativeGasUsed),
		"contractAddress":   nil,
		"logs":              receipt.Logs,
		"logsBloom":         receipt.Bloom,
	}

	fields["status"] = hexutil.Uint(receipt.Status)
	addBlobRPCReceiptFields(fields, s.b.ChainConfig(), block, tx)

	if reward := commonTxRewardForHash(block, hash); reward != nil {
		fields["commonTxApprover"] = reward.Approver
		if reward.ApproverReward != nil {
			fields["commonTxApproverReward"] = (*hexutil.Big)(reward.ApproverReward)
		}
		if reward.Burn != nil {
			fields["commonTxBurn"] = (*hexutil.Big)(reward.Burn)
		}
	}

	if receipt.Logs == nil {
		fields["logs"] = [][]*types.Log{}
	}
	if receipt.ContractAddress != (common.Address{}) {
		fields["contractAddress"] = receipt.ContractAddress
	}
	return fields, nil
}
