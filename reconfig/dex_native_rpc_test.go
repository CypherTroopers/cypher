package reconfig_test

import (
	"context"
	"errors"
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/settlement"
	"github.com/cypherium/cypher/internal/ethapi"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/rpc"
)

func (b *rewardReceiptBackend) StateAndHeaderByNumberOrHash(_ context.Context, ref rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	chain := b.backend.BlockChain()
	var block *types.Block
	if h, ok := ref.Hash(); ok {
		block = chain.GetBlockByHash(h)
	} else if n, ok := ref.Number(); ok {
		if n == rpc.LatestBlockNumber {
			block = chain.CurrentBlock()
		} else if n >= 0 {
			block = chain.GetBlockByNumber(uint64(n))
		}
	}
	if block == nil || chain.GetCanonicalHash(block.NumberU64()) != block.Hash() {
		return nil, nil, errors.New("canonical block unavailable")
	}
	s, err := chain.StateAt(block.Root())
	return s, block.Header(), err
}
func (a *rewardReceiptAPI) GetProof(ctx context.Context, address common.Address, keys []string, ref rpc.BlockNumberOrHash) (*ethapi.AccountResult, error) {
	return ethapi.NewPublicBlockChainAPI(a.backend).GetProof(ctx, address, keys, ref)
}
func (a *rewardReceiptAPI) GetBalance(ctx context.Context, address common.Address, ref rpc.BlockNumberOrHash) (*hexutil.Big, error) {
	return ethapi.NewPublicBlockChainAPI(a.backend).GetBalance(ctx, address, ref)
}

// The additional namespace serves only raw canonical data in the isolated
// harness. Consumers must independently verify its header/finality/MPT proofs.
type nativeFixtureAPI struct{ backend *rewardReceiptBackend }
type nativeProjection struct {
	Engine  engine.ProcessMetrics
	Header  *types.Header
	Status  settlement.Status
	Buckets map[settlement.Bucket]protocol.Amount
	Surplus protocol.Amount
	Balance *big.Int
	Entries []protocol.InboxEntry
}

func (a *nativeFixtureAPI) Block(height hexutil.Uint64) (hexutil.Bytes, error) {
	b := a.backend.backend.BlockChain().GetBlockByNumber(uint64(height))
	if b == nil {
		return nil, errors.New("canonical block missing")
	}
	return rlp.EncodeToBytes(b)
}
func (a *nativeFixtureAPI) Projection(ref rpc.BlockNumberOrHash) (nativeProjection, error) {
	s, h, err := a.backend.StateAndHeaderByNumberOrHash(context.Background(), ref)
	if err != nil {
		return nativeProjection{}, err
	}
	status, buckets, surplus, err := settlement.NativeStatus(s, params.DEXSettlementAddress)
	if err != nil {
		return nativeProjection{}, err
	}
	out := nativeProjection{Engine: engine.Metrics(), Header: h, Status: status, Buckets: buckets, Surplus: surplus, Balance: new(big.Int).Set(s.GetBalance(params.DEXSettlementAddress))}
	if status.Deposits > protocol.MaxDepositsPerCheckpoint {
		return out, errors.New("projection bound")
	}
	for i := uint64(0); i < status.Deposits; i++ {
		entry, err := settlement.ReadNativeEntry(s, params.DEXSettlementAddress, i)
		if err != nil {
			return out, err
		}
		out.Entries = append(out.Entries, entry)
	}
	return out, nil
}
