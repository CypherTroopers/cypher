package ethapi

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/cypherium/cypher/accounts"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/bloombits"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/eth/downloader"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rpc"
)

type londonAPITestBackend struct {
	headers map[uint64]*types.Header
	config  *params.ChainConfig
	price   *big.Int
	tip     *big.Int
}

func newLondonAPITestBackend() *londonAPITestBackend {
	config := &params.ChainConfig{
		ChainID:        big.NewInt(1337),
		HomesteadBlock: big.NewInt(0),
		EIP155Block:    big.NewInt(0),
	}
	config.SetModernForkConfig(&params.ModernForkConfig{
		BerlinBlock: big.NewInt(0),
		LondonBlock: big.NewInt(0),
	})
	return &londonAPITestBackend{
		headers: map[uint64]*types.Header{
			0: {Number: big.NewInt(0), GasLimit: 100, GasUsed: 25, BaseFee: big.NewInt(10)},
			1: {Number: big.NewInt(1), GasLimit: 100, GasUsed: 50, BaseFee: big.NewInt(11)},
			2: {Number: big.NewInt(2), GasLimit: 100, GasUsed: 75, BaseFee: big.NewInt(12)},
		},
		config: config,
		price:  big.NewInt(20),
		tip:    big.NewInt(2),
	}
}

func (b *londonAPITestBackend) latestHeader() *types.Header {
	var latest *types.Header
	for _, header := range b.headers {
		if latest == nil || header.Number.Cmp(latest.Number) > 0 {
			latest = header
		}
	}
	return latest
}

func (b *londonAPITestBackend) Downloader() *downloader.Downloader { return nil }
func (b *londonAPITestBackend) ProtocolVersion() int               { return 0 }
func (b *londonAPITestBackend) SuggestPrice(context.Context) (*big.Int, error) {
	return new(big.Int).Set(b.price), nil
}
func (b *londonAPITestBackend) SuggestGasTipCap(context.Context) (*big.Int, error) {
	return new(big.Int).Set(b.tip), nil
}
func (b *londonAPITestBackend) ChainDb() ethdb.Database            { return nil }
func (b *londonAPITestBackend) CandidatePool() *core.CandidatePool { return nil }
func (b *londonAPITestBackend) AccountManager() *accounts.Manager  { return nil }
func (b *londonAPITestBackend) ExtRPCEnabled() bool                { return false }
func (b *londonAPITestBackend) CallTimeOut() time.Duration         { return 0 }
func (b *londonAPITestBackend) RPCGasCap() uint64                  { return 0 }
func (b *londonAPITestBackend) RPCTxFeeCap() float64               { return 0 }
func (b *londonAPITestBackend) SetHead(uint64)                     {}
func (b *londonAPITestBackend) HeaderByNumber(_ context.Context, number rpc.BlockNumber) (*types.Header, error) {
	if number == rpc.LatestBlockNumber || number == rpc.PendingBlockNumber {
		return b.latestHeader(), nil
	}
	header := b.headers[uint64(number)]
	if header == nil {
		return nil, errors.New("header not found")
	}
	return header, nil
}
func (b *londonAPITestBackend) HeaderByHash(context.Context, common.Hash) (*types.Header, error) {
	return nil, nil
}
func (b *londonAPITestBackend) HeaderByNumberOrHash(context.Context, rpc.BlockNumberOrHash) (*types.Header, error) {
	return b.latestHeader(), nil
}
func (b *londonAPITestBackend) CurrentHeader() *types.Header { return b.latestHeader() }
func (b *londonAPITestBackend) CurrentBlock() *types.Block {
	return types.NewBlockWithHeader(b.latestHeader())
}
func (b *londonAPITestBackend) BlockByNumber(context.Context, rpc.BlockNumber) (*types.Block, error) {
	return nil, nil
}
func (b *londonAPITestBackend) BlockByHash(context.Context, common.Hash) (*types.Block, error) {
	return nil, nil
}
func (b *londonAPITestBackend) KeyBlockByNumber(context.Context, rpc.BlockNumber) (*types.KeyBlock, error) {
	return nil, nil
}
func (b *londonAPITestBackend) KeyBlockByHash(context.Context, common.Hash) (*types.KeyBlock, error) {
	return nil, nil
}
func (b *londonAPITestBackend) BlockByNumberOrHash(context.Context, rpc.BlockNumberOrHash) (*types.Block, error) {
	return nil, nil
}
func (b *londonAPITestBackend) KeyBlockNumber() uint64 { return 0 }
func (b *londonAPITestBackend) RescueCommittee(string) (*bftview.Committee, common.Hash, error) {
	return nil, common.Hash{}, nil
}
func (b *londonAPITestBackend) StateAndHeaderByNumber(context.Context, rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	return nil, nil, nil
}
func (b *londonAPITestBackend) StateAndHeaderByNumberOrHash(context.Context, rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	return nil, nil, nil
}
func (b *londonAPITestBackend) GetReceipts(context.Context, common.Hash) (types.Receipts, error) {
	return nil, nil
}
func (b *londonAPITestBackend) GetTd(context.Context, common.Hash) *big.Int { return nil }
func (b *londonAPITestBackend) GetEVM(context.Context, core.Message, *state.StateDB, *types.Header) (*vm.EVM, func() error, error) {
	return nil, func() error { return nil }, nil
}
func (b *londonAPITestBackend) SubscribeChainEvent(chan<- core.ChainEvent) event.Subscription {
	return nil
}
func (b *londonAPITestBackend) SubscribeChainHeadEvent(chan<- core.ChainHeadEvent) event.Subscription {
	return nil
}
func (b *londonAPITestBackend) SubscribeChainSideEvent(chan<- core.ChainSideEvent) event.Subscription {
	return nil
}
func (b *londonAPITestBackend) SendTx(context.Context, *types.Transaction, bool) error { return nil }
func (b *londonAPITestBackend) GetTransaction(context.Context, common.Hash) (*types.Transaction, common.Hash, uint64, uint64, error) {
	return nil, common.Hash{}, 0, 0, nil
}
func (b *londonAPITestBackend) GetPoolTransactions() (types.Transactions, error)  { return nil, nil }
func (b *londonAPITestBackend) GetPoolTransaction(common.Hash) *types.Transaction { return nil }
func (b *londonAPITestBackend) GetPoolNonce(context.Context, common.Address) (uint64, error) {
	return 0, nil
}
func (b *londonAPITestBackend) Stats() (int, int) { return 0, 0 }
func (b *londonAPITestBackend) TxPoolContent() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	return nil, nil
}
func (b *londonAPITestBackend) SubscribeNewTxsEvent(chan<- core.NewTxsEvent) event.Subscription {
	return nil
}
func (b *londonAPITestBackend) BloomStatus() (uint64, uint64) { return 0, 0 }
func (b *londonAPITestBackend) GetLogs(context.Context, common.Hash) ([][]*types.Log, error) {
	return nil, nil
}
func (b *londonAPITestBackend) ServiceFilter(context.Context, *bloombits.MatcherSession) {}
func (b *londonAPITestBackend) SubscribeLogsEvent(chan<- []*types.Log) event.Subscription {
	return nil
}
func (b *londonAPITestBackend) SubscribePendingLogsEvent(chan<- []*types.Log) event.Subscription {
	return nil
}
func (b *londonAPITestBackend) SubscribeRemovedLogsEvent(chan<- core.RemovedLogsEvent) event.Subscription {
	return nil
}
func (b *londonAPITestBackend) CommitteeMembers(context.Context, rpc.BlockNumber) ([]*common.Cnode, error) {
	return nil, nil
}
func (b *londonAPITestBackend) ChainConfig() *params.ChainConfig { return b.config }
func (b *londonAPITestBackend) Engine() consensus.Engine         { return nil }
func (b *londonAPITestBackend) GetKeyBlockChain() *core.KeyBlockChain {
	return nil
}

func TestMaxPriorityFeePerGasReturnsNonZero(t *testing.T) {
	api := NewPublicEthereumAPI(newLondonAPITestBackend())
	tip, err := api.MaxPriorityFeePerGas(context.Background())
	if err != nil {
		t.Fatalf("MaxPriorityFeePerGas failed: %v", err)
	}
	if tip == nil || tip.ToInt().Sign() <= 0 {
		t.Fatalf("tip must be non-zero: %v", tip)
	}
}

func TestFeeHistoryShape(t *testing.T) {
	api := NewPublicEthereumAPI(newLondonAPITestBackend())
	history, err := api.FeeHistory(context.Background(), hexutil.Uint64(2), rpc.LatestBlockNumber, []float64{10, 90})
	if err != nil {
		t.Fatalf("FeeHistory failed: %v", err)
	}
	if history.OldestBlock.ToInt().Uint64() != 1 {
		t.Fatalf("oldestBlock mismatch: got %v", history.OldestBlock)
	}
	if len(history.BaseFeePerGas) != 3 {
		t.Fatalf("baseFeePerGas length mismatch: got %d", len(history.BaseFeePerGas))
	}
	if len(history.GasUsedRatio) != 2 {
		t.Fatalf("gasUsedRatio length mismatch: got %d", len(history.GasUsedRatio))
	}
	if len(history.Reward) != 2 || len(history.Reward[0]) != 2 {
		t.Fatalf("reward shape mismatch: %#v", history.Reward)
	}
}

func TestRPCTransactionModernFields(t *testing.T) {
	to := common.HexToAddress("0x1111111111111111111111111111111111111111")
	accessList := types.AccessList{{Address: to, StorageKeys: []common.Hash{common.HexToHash("0x01")}}}
	dynamic := types.NewDynamicFeeTx(&types.DynamicFeeTx{
		ChainID:    big.NewInt(1337),
		Nonce:      1,
		GasTipCap:  big.NewInt(2),
		GasFeeCap:  big.NewInt(20),
		Gas:        21000,
		To:         &to,
		Value:      big.NewInt(1),
		AccessList: accessList,
		V:          big.NewInt(0),
		R:          big.NewInt(1),
		S:          big.NewInt(1),
	})
	rpcTx := newRPCTransaction(dynamic, common.Hash{}, 0, 0)
	if rpcTx.Type != hexutil.Uint64(types.DynamicFeeTxType) {
		t.Fatalf("type mismatch: got %d", rpcTx.Type)
	}
	if rpcTx.ChainID == nil || rpcTx.ChainID.ToInt().Cmp(big.NewInt(1337)) != 0 {
		t.Fatalf("chainId missing: %#v", rpcTx.ChainID)
	}
	if rpcTx.GasFeeCap == nil || rpcTx.GasFeeCap.ToInt().Cmp(big.NewInt(20)) != 0 {
		t.Fatalf("maxFeePerGas missing: %#v", rpcTx.GasFeeCap)
	}
	if rpcTx.GasTipCap == nil || rpcTx.GasTipCap.ToInt().Cmp(big.NewInt(2)) != 0 {
		t.Fatalf("maxPriorityFeePerGas missing: %#v", rpcTx.GasTipCap)
	}
	if rpcTx.GasPrice == nil || rpcTx.GasPrice.ToInt().Cmp(big.NewInt(20)) != 0 {
		t.Fatalf("gasPrice should preserve effective cap: %#v", rpcTx.GasPrice)
	}
	if rpcTx.Accesses == nil || len(*rpcTx.Accesses) != 1 {
		t.Fatalf("accessList missing: %#v", rpcTx.Accesses)
	}

	blobHash := common.HexToHash("0x02")
	blob := types.NewTx(&types.BlobTx{
		ChainID:    big.NewInt(1337),
		Nonce:      2,
		GasTipCap:  big.NewInt(3),
		GasFeeCap:  big.NewInt(30),
		Gas:        30000,
		To:         to,
		Value:      big.NewInt(2),
		AccessList: accessList,
		BlobFeeCap: big.NewInt(7),
		BlobHashes: []common.Hash{blobHash},
		V:          big.NewInt(0),
		R:          big.NewInt(1),
		S:          big.NewInt(1),
	})
	blobRPC := newRPCTransaction(blob, common.Hash{}, 0, 0)
	if blobRPC.Type != hexutil.Uint64(types.BlobTxType) {
		t.Fatalf("blob type mismatch: got %d", blobRPC.Type)
	}
	if blobRPC.BlobGasFeeCap == nil || blobRPC.BlobGasFeeCap.ToInt().Cmp(big.NewInt(7)) != 0 {
		t.Fatalf("maxFeePerBlobGas missing: %#v", blobRPC.BlobGasFeeCap)
	}
	if len(blobRPC.BlobVersionedHashes) != 1 || blobRPC.BlobVersionedHashes[0] != blobHash {
		t.Fatalf("blob hashes missing: %#v", blobRPC.BlobVersionedHashes)
	}
}

func TestSendTxArgsModernDefaultsAndToTransaction(t *testing.T) {
	backend := newLondonAPITestBackend()
	ctx := context.Background()
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	gas := hexutil.Uint64(21000)
	nonce := hexutil.Uint64(1)
	gasPrice := (*hexutil.Big)(big.NewInt(10))
	feeCap := (*hexutil.Big)(big.NewInt(20))
	tipCap := (*hexutil.Big)(big.NewInt(2))

	mixed := SendTxArgs{From: to, To: &to, Gas: &gas, Nonce: &nonce, GasPrice: gasPrice, MaxFeePerGas: feeCap}
	if err := mixed.setDefaults(ctx, backend); err == nil {
		t.Fatal("expected mixed gasPrice and maxFeePerGas to fail")
	}

	accessList := types.AccessList{{Address: to}}
	dynamic := SendTxArgs{
		From:                 to,
		To:                   &to,
		Gas:                  &gas,
		Nonce:                &nonce,
		MaxFeePerGas:         feeCap,
		MaxPriorityFeePerGas: tipCap,
		AccessList:           &accessList,
	}
	if err := dynamic.setDefaults(ctx, backend); err != nil {
		t.Fatalf("dynamic defaults failed: %v", err)
	}
	dynamicTx := dynamic.toTransaction(backend.config.ChainID)
	if dynamicTx.Type() != types.DynamicFeeTxType {
		t.Fatalf("expected dynamic tx, got type %d", dynamicTx.Type())
	}
	if len(dynamicTx.AccessList()) != 1 {
		t.Fatalf("dynamic accessList not preserved")
	}

	legacy := SendTxArgs{From: to, To: &to, Gas: &gas, Nonce: &nonce, GasPrice: gasPrice}
	if err := legacy.setDefaults(ctx, backend); err != nil {
		t.Fatalf("legacy defaults failed: %v", err)
	}
	legacyTx := legacy.toTransaction(backend.config.ChainID)
	if legacyTx.Type() != types.LegacyTxType {
		t.Fatalf("expected legacy tx, got type %d", legacyTx.Type())
	}
}
