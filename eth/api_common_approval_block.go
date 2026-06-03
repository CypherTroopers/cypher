package eth

import (
	"context"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/internal/ethapi"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rpc"
)

// GetBlockByNumber overrides the generic eth block response with Cypherium's
// tx-block CommonApproval proof details. Keeping this in eth avoids replacing the
// large internal/ethapi/api.go file and exposes the data through the standard
// eth_getBlockByNumber / eth.getBlock path.
func (api *PublicEthereumAPI) GetBlockByNumber(ctx context.Context, number rpc.BlockNumber, fullTx bool) (map[string]interface{}, error) {
	block, err := api.e.APIBackend.BlockByNumber(ctx, number)
	if block != nil && err == nil {
		response, err := api.rpcMarshalBlockWithCommonApproval(ctx, block, true, fullTx)
		if err == nil && number == rpc.PendingBlockNumber {
			for _, field := range []string{"hash", "nonce", "miner"} {
				response[field] = nil
			}
		}
		return response, err
	}
	return nil, err
}

// GetBlockByHash overrides the generic eth block response with Cypherium's
// tx-block CommonApproval proof details. This affects eth_getBlockByHash.
func (api *PublicEthereumAPI) GetBlockByHash(ctx context.Context, hash common.Hash, fullTx bool) (map[string]interface{}, error) {
	block, err := api.e.APIBackend.BlockByHash(ctx, hash)
	if block != nil {
		return api.rpcMarshalBlockWithCommonApproval(ctx, block, true, fullTx)
	}
	return nil, err
}

func (api *PublicEthereumAPI) rpcMarshalBlockWithCommonApproval(ctx context.Context, block *types.Block, inclTx bool, fullTx bool) (map[string]interface{}, error) {
	fields, err := ethapi.RPCMarshalBlock(block, inclTx, fullTx)
	if err != nil {
		return nil, err
	}
	if keyblock, keyErr := api.e.APIBackend.KeyBlockByHash(ctx, block.KeyHash()); keyErr == nil && keyblock != nil {
		fields["miner"] = common.HexToAddress(keyblock.OutAddress(1))
	}
	addCommonApprovalRPCFields(fields, block, api.e.APIBackend.ChainConfig())
	if inclTx {
		fields["totalDifficulty"] = (*hexutil.Big)(api.e.APIBackend.GetTd(ctx, block.Hash()))
	}
	return fields, nil
}

func addCommonApprovalRPCFields(fields map[string]interface{}, block *types.Block, config *params.ChainConfig) {
	if fields == nil || block == nil {
		return
	}

	signInfo := block.SignInfo()
	if signInfo == nil {
		return
	}

	nodes := core.OrderedCommonCommittee(config)
	committeeMembers := make([]common.Address, 0, len(nodes))
	approvedMembers := make([]common.Address, 0, len(nodes))

	for i, node := range nodes {
		if node == nil {
			continue
		}

		memberAddress := common.HexToAddress(node.CoinBase)
		committeeMembers = append(committeeMembers, memberAddress)

		if len(signInfo.CommonApprovalExceptions) > i/8 {
			if (signInfo.CommonApprovalExceptions[i/8] & (1 << uint(i%8))) != 0 {
				approvedMembers = append(approvedMembers, memberAddress)
			}
		}
	}

	var commonLeaderAddress common.Address
	if len(nodes) > 0 && nodes[0] != nil {
		commonLeaderAddress = common.HexToAddress(nodes[0].CoinBase)
	}

	present := len(signInfo.CommonApprovalSignature) > 0 ||
		len(signInfo.CommonApprovalExceptions) > 0 ||
		signInfo.CommonApprovalViewID != (common.Hash{}) ||
		signInfo.CommonApprovalCommitteeHash != (common.Hash{})

	fields["commonApproval"] = map[string]interface{}{
		"present":                present,
		"signature":              hexutil.Bytes(signInfo.CommonApprovalSignature),
		"mask":                   hexutil.Bytes(signInfo.CommonApprovalExceptions),
		"viewId":                 signInfo.CommonApprovalViewID,
		"committeeHash":          signInfo.CommonApprovalCommitteeHash,
		"threshold":              core.CommonApprovalThreshold(config, len(nodes)),
		"commonLeaderAddress":    commonLeaderAddress,
		"commonCommitteeMembers": committeeMembers,
		"approvedMembers":        approvedMembers,
	}
}
