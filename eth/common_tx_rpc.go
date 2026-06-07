package eth

import (
	"context"
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core/types"
)

func addCommonRPCFields(fields map[string]interface{}, block *types.Block, hash common.Hash) {
	if fields == nil || block == nil {
		return
	}
	header := block.Header()
	fields["commonTxAdmissionRoot"] = header.CommonTxAdmissionRoot
	fields["commonTxRewardRoot"] = header.CommonTxRewardRoot

	for _, admission := range block.CommonTxAdmissions() {
		if admission == nil || admission.TxHash != hash {
			continue
		}
		fields["commonRpcMiner"] = admission.Miner
		if admission.ChainID != nil {
			fields["commonTxAdmissionChainId"] = (*hexutil.Big)(admission.ChainID)
		}
		fields["commonTxAdmissionKeyBlockNumber"] = hexutil.Uint64(admission.KeyBlockNumber)
		fields["commonTxAdmissionTxBlockNumber"] = hexutil.Uint64(admission.TxBlockNumber)
		fields["commonTxAdmissionTimestamp"] = hexutil.Uint64(admission.Timestamp)
		fields["commonTxAdmissionSignature"] = hexutil.Bytes(admission.Signature)
		break
	}
	for _, reward := range block.CommonTxRewards() {
		if reward == nil || reward.TxHash != hash {
			continue
		}
		fields["commonRpcMiner"] = reward.Miner
		if reward.Reward != nil {
			fields["commonRpcReward"] = (*hexutil.Big)(reward.Reward)
		}
		if reward.Burn != nil {
			fields["commonRpcBurn"] = (*hexutil.Big)(reward.Burn)
		}
		break
	}
}

func (api *PublicEthereumAPI) rpcTransactionFields(tx *types.Transaction, block *types.Block, blockHash common.Hash, blockNumber uint64, index uint64) map[string]interface{} {
	header := api.e.blockchain.CurrentHeader()
	if block != nil {
		header = block.Header()
	}
	signer := types.MakeSignerAutoJudgement(api.e.blockchain.Config(), header.Number, tx.V())
	from, _ := types.Sender(signer, tx)
	v, r, s := tx.RawSignatureValues()
	fields := map[string]interface{}{
		"transactionHash": tx.Hash(),
		"hash":            tx.Hash(),
		"nonce":           hexutil.Uint64(tx.Nonce()),
		"blockHash":       nil,
		"blockNumber":     nil,
		"transactionIndex": nil,
		"from":            from,
		"to":              tx.To(),
		"value":           (*hexutil.Big)(tx.Value()),
		"gas":             hexutil.Uint64(tx.Gas()),
		"gasPrice":        (*hexutil.Big)(tx.GasPrice()),
		"input":           hexutil.Bytes(tx.Data()),
		"type":            hexutil.Uint64(tx.Type()),
		"v":               (*hexutil.Big)(v),
		"r":               (*hexutil.Big)(r),
		"s":               (*hexutil.Big)(s),
	}
	if chainID := tx.ChainId(); chainID != nil && (tx.Type() != types.LegacyTxType || tx.Protected()) {
		fields["chainId"] = (*hexutil.Big)(new(big.Int).Set(chainID))
	}
	switch tx.Type() {
	case types.AccessListTxType:
		accessList := tx.AccessList()
		fields["accessList"] = accessList
	case types.DynamicFeeTxType:
		accessList := tx.AccessList()
		fields["accessList"] = accessList
		fields["maxFeePerGas"] = (*hexutil.Big)(tx.GasFeeCap())
		fields["maxPriorityFeePerGas"] = (*hexutil.Big)(tx.GasTipCap())
	case types.BlobTxType:
		accessList := tx.AccessList()
		fields["accessList"] = accessList
		fields["maxFeePerGas"] = (*hexutil.Big)(tx.GasFeeCap())
		fields["maxPriorityFeePerGas"] = (*hexutil.Big)(tx.GasTipCap())
		fields["maxFeePerBlobGas"] = (*hexutil.Big)(tx.BlobGasFeeCap())
		fields["blobVersionedHashes"] = tx.BlobHashes()
	}
	if block != nil && blockHash != (common.Hash{}) {
		fields["blockHash"] = blockHash
		fields["blockNumber"] = (*hexutil.Big)(new(big.Int).SetUint64(blockNumber))
		fields["transactionIndex"] = hexutil.Uint64(index)
		addCommonRPCFields(fields, block, tx.Hash())
	}
	return fields
}

// GetTransactionByHash returns the transaction for the given hash and appends
// Cypherium common RPC admission/reward fields when the tx is finalized.
func (api *PublicEthereumAPI) GetTransactionByHash(ctx context.Context, hash common.Hash) (map[string]interface{}, error) {
	tx, blockHash, blockNumber, index, err := api.e.APIBackend.GetTransaction(ctx, hash)
	if err != nil {
		return nil, err
	}
	if tx != nil {
		block := api.e.blockchain.GetBlock(blockHash, blockNumber)
		return api.rpcTransactionFields(tx, block, blockHash, blockNumber, index), nil
	}
	if tx := api.e.txPool.Get(hash); tx != nil {
		return api.rpcTransactionFields(tx, nil, common.Hash{}, 0, 0), nil
	}
	return nil, nil
}

// GetTransactionReceipt returns the transaction receipt for the given hash and
// appends Cypherium common RPC admission/reward fields.
func (api *PublicEthereumAPI) GetTransactionReceipt(ctx context.Context, hash common.Hash) (map[string]interface{}, error) {
	tx, blockHash, blockNumber, index, err := api.e.APIBackend.GetTransaction(ctx, hash)
	if err != nil {
		return nil, nil
	}
	if tx == nil || blockHash == (common.Hash{}) {
		return nil, nil
	}
	receipts, err := api.e.APIBackend.GetReceipts(ctx, blockHash)
	if err != nil {
		return nil, err
	}
	if len(receipts) <= int(index) {
		return nil, nil
	}
	receipt := receipts[index]
	block := api.e.blockchain.GetBlock(blockHash, blockNumber)
	if block == nil {
		return nil, nil
	}

	signer := types.MakeSignerAutoJudgement(api.e.blockchain.Config(), block.Header().Number, tx.V())
	from, _ := types.Sender(signer, tx)
	effectiveGasPrice := new(big.Int).Set(tx.GasPrice())
	if tx.Type() == types.DynamicFeeTxType {
		baseFee := fixedBaseFeePerGas()
		if headerBaseFee := block.Header().BaseFee; headerBaseFee != nil && headerBaseFee.Sign() > 0 {
			baseFee = new(big.Int).Set(headerBaseFee)
		}
		if tip, tipErr := tx.EffectiveGasTip(baseFee); tipErr == nil {
			effectiveGasPrice = new(big.Int).Add(new(big.Int).Set(baseFee), tip)
		}
	}

	fields := map[string]interface{}{
		"transactionHash":   hash,
		"blockHash":         blockHash,
		"blockNumber":       hexutil.Uint64(blockNumber),
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
		"status":            hexutil.Uint(receipt.Status),
	}
	if receipt.Logs == nil {
		fields["logs"] = [][]*types.Log{}
	}
	if receipt.ContractAddress != (common.Address{}) {
		fields["contractAddress"] = receipt.ContractAddress
	}
	addCommonRPCFields(fields, block, hash)
	return fields, nil
}
