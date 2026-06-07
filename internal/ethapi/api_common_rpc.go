package ethapi

import (
	"context"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/rpc"
)

type RPCCommonTxAdmission struct {
	ChainID        *hexutil.Big   `json:"chainId"`
	TxHash         common.Hash    `json:"txHash"`
	Miner          common.Address `json:"miner"`
	KeyBlockNumber hexutil.Uint64 `json:"keyBlockNumber"`
	TxBlockNumber  hexutil.Uint64 `json:"txBlockNumber"`
	Timestamp      hexutil.Uint64 `json:"timestamp"`
	Signature      hexutil.Bytes  `json:"signature"`
}

type RPCCommonTxReward struct {
	TxHash common.Hash    `json:"txHash"`
	Miner  common.Address `json:"miner"`
	Reward *hexutil.Big   `json:"reward"`
	Burn   *hexutil.Big   `json:"burn"`
}

type RPCCommonBlockInfo struct {
	Number                *hexutil.Big             `json:"number"`
	Hash                  common.Hash              `json:"hash"`
	CommonTxAdmissionRoot common.Hash              `json:"commonTxAdmissionRoot"`
	CommonTxRewardRoot    common.Hash              `json:"commonTxRewardRoot"`
	CommonTxAdmissions    []RPCCommonTxAdmission   `json:"commonTxAdmissions"`
	CommonTxRewards       []RPCCommonTxReward      `json:"commonTxRewards"`
}

func rpcCommonTxAdmission(admission *types.CommonTxAdmission) RPCCommonTxAdmission {
	result := RPCCommonTxAdmission{
		TxHash:         admission.TxHash,
		Miner:          admission.Miner,
		KeyBlockNumber: hexutil.Uint64(admission.KeyBlockNumber),
		TxBlockNumber:  hexutil.Uint64(admission.TxBlockNumber),
		Timestamp:      hexutil.Uint64(admission.Timestamp),
		Signature:      hexutil.Bytes(admission.Signature),
	}
	if admission.ChainID != nil {
		result.ChainID = (*hexutil.Big)(admission.ChainID)
	}
	return result
}

func rpcCommonTxReward(reward *types.CommonTxReward) RPCCommonTxReward {
	result := RPCCommonTxReward{
		TxHash: reward.TxHash,
		Miner:  reward.Miner,
	}
	if reward.Reward != nil {
		result.Reward = (*hexutil.Big)(reward.Reward)
	}
	if reward.Burn != nil {
		result.Burn = (*hexutil.Big)(reward.Burn)
	}
	return result
}

func rpcCommonBlockInfo(block *types.Block) *RPCCommonBlockInfo {
	if block == nil {
		return nil
	}
	header := block.Header()
	admissions := block.CommonTxAdmissions()
	rewards := block.CommonTxRewards()
	out := &RPCCommonBlockInfo{
		Number:                (*hexutil.Big)(header.Number),
		Hash:                  block.Hash(),
		CommonTxAdmissionRoot: header.CommonTxAdmissionRoot,
		CommonTxRewardRoot:    header.CommonTxRewardRoot,
		CommonTxAdmissions:    make([]RPCCommonTxAdmission, 0, len(admissions)),
		CommonTxRewards:       make([]RPCCommonTxReward, 0, len(rewards)),
	}
	for _, admission := range admissions {
		if admission != nil {
			out.CommonTxAdmissions = append(out.CommonTxAdmissions, rpcCommonTxAdmission(admission))
		}
	}
	for _, reward := range rewards {
		if reward != nil {
			out.CommonTxRewards = append(out.CommonTxRewards, rpcCommonTxReward(reward))
		}
	}
	return out
}

// GetBlockCommonInfoByNumber returns common RPC admission and reward/burn data
// committed in a tx block. This supplements eth_getBlockByNumber until the
// legacy block marshal output is extended with these custom fields.
func (s *PublicBlockChainAPI) GetBlockCommonInfoByNumber(ctx context.Context, number rpc.BlockNumber) (*RPCCommonBlockInfo, error) {
	block, err := s.b.BlockByNumber(ctx, number)
	if block == nil || err != nil {
		return nil, err
	}
	return rpcCommonBlockInfo(block), nil
}

// GetBlockCommonInfoByHash returns common RPC admission and reward/burn data
// committed in a tx block by block hash.
func (s *PublicBlockChainAPI) GetBlockCommonInfoByHash(ctx context.Context, hash common.Hash) (*RPCCommonBlockInfo, error) {
	block, err := s.b.BlockByHash(ctx, hash)
	if block == nil || err != nil {
		return nil, err
	}
	return rpcCommonBlockInfo(block), nil
}
