package ethapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cypherium/cypher/accounts"
	"github.com/cypherium/cypher/accounts/keystore"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/bloombits"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/crypto"
	kzg "github.com/cypherium/cypher/crypto/kzg4844"
	"github.com/cypherium/cypher/eth/downloader"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/rpc"
)

type londonAPITestBackend struct {
	headers     map[uint64]*types.Header
	config      *params.ChainConfig
	price       *big.Int
	tip         *big.Int
	am          *accounts.Manager
	sendBatchFn func(types.Transactions) []error
}

type feePolicyTestBackend struct {
	*londonAPITestBackend
	state *state.StateDB
}

func newFeePolicyTestBackend(t *testing.T) *feePolicyTestBackend {
	t.Helper()
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	return &feePolicyTestBackend{londonAPITestBackend: newLondonAPITestBackend(), state: st}
}

func (b *feePolicyTestBackend) StateAndHeaderByNumberOrHash(context.Context, rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	return b.state.Copy(), b.latestHeader(), nil
}

func (b *feePolicyTestBackend) BlockByNumberOrHash(context.Context, rpc.BlockNumberOrHash) (*types.Block, error) {
	return types.NewBlockWithHeader(b.latestHeader()), nil
}

func (b *feePolicyTestBackend) GetEVM(_ context.Context, msg core.Message, st *state.StateDB, header *types.Header) (*vm.EVM, func() error, error) {
	ctx := vm.Context{
		CanTransfer: core.CanTransfer,
		Transfer:    core.Transfer,
		Origin:      msg.From(),
		GasPrice:    new(big.Int).Set(msg.GasPrice()),
		BlockNumber: new(big.Int).Set(header.Number),
		Time:        new(big.Int).SetUint64(header.Time),
		GasLimit:    header.GasLimit,
		BaseFee:     new(big.Int).Set(header.BaseFee),
		BlobBaseFee: new(big.Int),
	}
	return vm.NewEVM(ctx, st, b.config, vm.Config{}), func() error { return st.Error() }, nil
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
func (b *londonAPITestBackend) AccountManager() *accounts.Manager  { return b.am }
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
func (b *londonAPITestBackend) SendTxBatch(_ context.Context, txs types.Transactions) []error {
	if b.sendBatchFn != nil {
		return b.sendBatchFn(txs)
	}
	return make([]error, len(txs))
}
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

func TestRPCMarshalHeaderModernFields(t *testing.T) {
	header := &types.Header{
		Number:           big.NewInt(1),
		Difficulty:       big.NewInt(1),
		WithdrawalsHash:  common.HexToHash("0x01"),
		BlobGasUsed:      2,
		ExcessBlobGas:    3,
		ParentBeaconRoot: common.HexToHash("0x04"),
		RequestsHash:     common.HexToHash("0x05"),
	}
	fields := RPCMarshalHeader(header)
	checks := map[string]interface{}{
		"withdrawalsRoot":       header.WithdrawalsHash,
		"blobGasUsed":           hexutil.Uint64(2),
		"excessBlobGas":         hexutil.Uint64(3),
		"parentBeaconBlockRoot": header.ParentBeaconRoot,
		"requestsHash":          header.RequestsHash,
	}
	for name, want := range checks {
		if got := fields[name]; got != want {
			t.Fatalf("%s = %#v, want %#v", name, got, want)
		}
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
	if rpcTx.YParity == nil || uint64(*rpcTx.YParity) != 0 {
		t.Fatalf("dynamic-fee yParity missing: %#v", rpcTx.YParity)
	}

	accessListTx := types.NewTx(&types.AccessListTx{
		ChainID: big.NewInt(1337), Nonce: 1, GasPrice: big.NewInt(10), Gas: 21000,
		To: &to, Value: new(big.Int), AccessList: accessList,
		V: big.NewInt(1), R: big.NewInt(1), S: big.NewInt(1),
	})
	accessListRPC := newRPCTransaction(accessListTx, common.Hash{}, 0, 0)
	if accessListRPC.YParity == nil || uint64(*accessListRPC.YParity) != 1 {
		t.Fatalf("access-list yParity missing: %#v", accessListRPC.YParity)
	}
	legacyRPC := newRPCTransaction(types.NewTransaction(0, to, new(big.Int), 21000, big.NewInt(1), nil), common.Hash{}, 0, 0)
	if legacyRPC.YParity != nil {
		t.Fatalf("legacy transaction unexpectedly exposed yParity: %#v", legacyRPC.YParity)
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
	if blobRPC.YParity == nil || uint64(*blobRPC.YParity) != 0 {
		t.Fatalf("blob yParity missing: %#v", blobRPC.YParity)
	}

	auth := types.SetCodeAuthorization{
		ChainID: big.NewInt(1337), Address: to, Nonce: 3,
		V: big.NewInt(1), R: big.NewInt(2), S: big.NewInt(3),
	}
	setCode := types.NewTx(&types.SetCodeTx{
		ChainID: big.NewInt(1337), Nonce: 3, GasTipCap: big.NewInt(4), GasFeeCap: big.NewInt(40),
		Gas: 40000, To: to, Value: new(big.Int), AccessList: accessList,
		AuthList: []types.SetCodeAuthorization{auth}, V: big.NewInt(0), R: big.NewInt(1), S: big.NewInt(1),
	})
	setCodeRPC := newRPCTransaction(setCode, common.Hash{}, 0, 0)
	if setCodeRPC.Type != hexutil.Uint64(types.SetCodeTxType) || len(setCodeRPC.AuthorizationList) != 1 {
		t.Fatalf("set-code RPC fields missing: %#v", setCodeRPC)
	}
	if setCodeRPC.YParity == nil || uint64(*setCodeRPC.YParity) != 0 {
		t.Fatalf("set-code yParity missing: %#v", setCodeRPC.YParity)
	}
	setCodeRPC.AuthorizationList[0].Nonce = 99
	if setCode.SetCodeAuthorizations()[0].Nonce != 3 {
		t.Fatal("RPC authorizationList aliases transaction data")
	}

	for name, tx := range map[string]*types.Transaction{"dynamic": dynamic, "blob": blob, "set-code": setCode} {
		rpcTx := newRPCTransaction(tx, common.Hash{}, 0, 0)
		setRPCTransactionEffectiveGasPrice(rpcTx, tx, big.NewInt(10))
		want := new(big.Int).Add(big.NewInt(10), tx.GasTipCap())
		if rpcTx.GasPrice.ToInt().Cmp(want) != 0 {
			t.Fatalf("%s mined gasPrice = %v, want %v", name, rpcTx.GasPrice, want)
		}
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

	modernAccessList := types.AccessList{{Address: to}}
	blobType := hexutil.Uint64(types.BlobTxType)
	blobFeeCap := (*hexutil.Big)(big.NewInt(7))
	blob := SendTxArgs{
		From: to, To: &to, Gas: &gas, Nonce: &nonce, Type: &blobType,
		MaxFeePerGas: feeCap, MaxPriorityFeePerGas: tipCap, AccessList: &modernAccessList,
		MaxFeePerBlobGas: blobFeeCap, Blobs: []kzg.Blob{{}},
	}
	if err := blob.setDefaults(ctx, backend); err != nil {
		t.Fatalf("blob defaults failed: %v", err)
	}
	blobTx := blob.toTransaction(backend.config.ChainID)
	if blobTx.Type() != types.BlobTxType || blobTx.BlobGasFeeCap().Cmp(big.NewInt(7)) != 0 || len(blobTx.BlobHashes()) != 1 || blobTx.BlobSidecar() == nil {
		t.Fatalf("blob transaction fields missing: %#v", blobTx)
	}

	setCodeType := hexutil.Uint64(types.SetCodeTxType)
	auth := types.SetCodeAuthorization{
		ChainID: big.NewInt(1337), Address: to, Nonce: 0,
		V: big.NewInt(0), R: big.NewInt(1), S: big.NewInt(1),
	}
	setCode := SendTxArgs{
		From: to, To: &to, Gas: &gas, Nonce: &nonce, Type: &setCodeType,
		MaxFeePerGas: feeCap, MaxPriorityFeePerGas: tipCap, AccessList: &modernAccessList,
		AuthorizationList: []types.SetCodeAuthorization{auth},
	}
	if err := setCode.setDefaults(ctx, backend); err != nil {
		t.Fatalf("set-code defaults failed: %v", err)
	}
	setCodeTx := setCode.toTransaction(backend.config.ChainID)
	if setCodeTx.Type() != types.SetCodeTxType || len(setCodeTx.SetCodeAuthorizations()) != 1 {
		t.Fatalf("set-code transaction fields missing: %#v", setCodeTx)
	}
}

func TestNativeTransferDefaultFeeAndExecutionClassification(t *testing.T) {
	backend := newFeePolicyTestBackend(t)
	ctx := context.Background()
	from := common.HexToAddress("0x1000000000000000000000000000000000000001")
	to := common.HexToAddress("0x2000000000000000000000000000000000000002")

	args := SendTxArgs{From: from, To: &to}
	if err := args.setDefaults(ctx, backend); err != nil {
		t.Fatalf("plain transfer defaults failed: %v", err)
	}
	if args.Gas == nil || uint64(*args.Gas) != params.TxGas {
		t.Fatalf("plain transfer gas = %v, want %d", args.Gas, params.TxGas)
	}
	if args.GasPrice == nil || args.GasPrice.ToInt().Cmp(big.NewInt(params.FixedTransferGasPricePerGas)) != 0 {
		t.Fatalf("plain transfer gasPrice = %v, want %v", args.GasPrice, params.FixedTransferGasPricePerGas)
	}
	if tx := args.toTransaction(backend.config.ChainID); tx.Type() != types.LegacyTxType {
		t.Fatalf("plain transfer type = %d, want legacy", tx.Type())
	}
	wantFee := new(big.Int).Mul(new(big.Int).SetUint64(params.TxGas), big.NewInt(params.FixedTransferGasPricePerGas))
	gotFee := new(big.Int).Mul(new(big.Int).SetUint64(uint64(*args.Gas)), args.GasPrice.ToInt())
	if gotFee.Cmp(wantFee) != 0 || gotFee.Cmp(big.NewInt(21_000_000_000_000)) != 0 {
		t.Fatalf("plain transfer fee = %v, want 0.000021 native coin", gotFee)
	}

	blockRef := rpc.BlockNumberOrHashWithNumber(rpc.PendingBlockNumber)
	contract := common.HexToAddress("0x3000000000000000000000000000000000000003")
	backend.state.SetCode(contract, []byte{byte(vm.STOP)})
	for name, call := range map[string]CallArgs{
		"contract":   {To: &contract},
		"precompile": {To: func() *common.Address { a := common.BytesToAddress([]byte{1}); return &a }()},
		"set-code":   {To: &to, AuthorizationList: []types.SetCodeAuthorization{{ChainID: big.NewInt(1337), Address: to}}},
		"blob":       {To: &to, BlobVersionedHashes: []common.Hash{{types.BlobCommitmentVersionKZG}}},
	} {
		plain, err := isPlainValueTransferCall(ctx, backend, call, blockRef)
		if err != nil {
			t.Fatalf("%s classification failed: %v", name, err)
		}
		if plain {
			t.Fatalf("%s execution was incorrectly fixed to 21,000 gas", name)
		}
	}
}

func TestDynamicContractEstimateCapsGasByFeeCapAndBalance(t *testing.T) {
	backend := newFeePolicyTestBackend(t)
	header := backend.latestHeader()
	header.GasLimit = 1_000_000
	header.BaseFee = big.NewInt(10)
	from := common.HexToAddress("0x4000000000000000000000000000000000000004")
	contract := common.HexToAddress("0x5000000000000000000000000000000000000005")
	backend.state.CreateAccount(from)
	backend.state.AddBalance(from, big.NewInt(3_000_000)) // Funds at most 30,000 gas at feeCap=100.
	backend.state.SetCode(contract, []byte{byte(vm.STOP)})
	feeCap := (*hexutil.Big)(big.NewInt(100))
	tipCap := (*hexutil.Big)(big.NewInt(1))
	args := SendTxArgs{
		From: from, To: &contract,
		MaxFeePerGas: feeCap, MaxPriorityFeePerGas: tipCap,
	}
	if err := args.setDefaults(context.Background(), backend); err != nil {
		t.Fatalf("dynamic contract estimation failed: %v", err)
	}
	if args.Gas == nil || uint64(*args.Gas) < params.TxGas || uint64(*args.Gas) > 30_000 {
		t.Fatalf("estimated gas = %v, want fundable range [%d,30000]", args.Gas, params.TxGas)
	}
}

func TestCallArgsModernMessageFields(t *testing.T) {
	to := common.HexToAddress("0x3333333333333333333333333333333333333333")
	blobFeeCap := (*hexutil.Big)(big.NewInt(9))
	var blobHash common.Hash
	blobHash[0] = types.BlobCommitmentVersionKZG
	blobMsg := (&CallArgs{To: &to, MaxFeePerBlobGas: blobFeeCap, BlobVersionedHashes: []common.Hash{blobHash}}).ToMessage(100000)
	if blobMsg.Type() != types.BlobTxType || blobMsg.BlobGasFeeCap().Cmp(big.NewInt(9)) != 0 || len(blobMsg.BlobHashes()) != 1 {
		t.Fatalf("blob call message fields missing: type=%d fee=%v hashes=%v", blobMsg.Type(), blobMsg.BlobGasFeeCap(), blobMsg.BlobHashes())
	}
	auth := types.SetCodeAuthorization{ChainID: big.NewInt(1), Address: to, V: new(big.Int), R: big.NewInt(1), S: big.NewInt(1)}
	setCodeMsg := (&CallArgs{To: &to, AuthorizationList: []types.SetCodeAuthorization{auth}}).ToMessage(100000)
	if setCodeMsg.Type() != types.SetCodeTxType || len(setCodeMsg.SetCodeAuthorizations()) != 1 {
		t.Fatalf("set-code call message fields missing: type=%d auth=%v", setCodeMsg.Type(), setCodeMsg.SetCodeAuthorizations())
	}
}

func TestBlobRPCReceiptFields(t *testing.T) {
	to := common.Address{1}
	var blobHash common.Hash
	blobHash[0] = types.BlobCommitmentVersionKZG
	tx := types.NewTx(&types.BlobTx{ChainID: big.NewInt(1), To: to, GasTipCap: new(big.Int), GasFeeCap: big.NewInt(1), Value: new(big.Int), BlobFeeCap: big.NewInt(1), BlobHashes: []common.Hash{blobHash}})
	header := &types.Header{Number: big.NewInt(1), Time: 0, ExcessBlobGas: 123}
	fields := make(map[string]interface{})
	addBlobRPCReceiptFields(fields, newLondonAPITestBackend().config, types.NewBlockWithHeader(header), tx)
	if got := fields["blobGasUsed"]; got != hexutil.Uint64(params.BlobTxBlobGasPerBlob) {
		t.Fatalf("blobGasUsed = %#v", got)
	}
	if price, ok := fields["blobGasPrice"].(*hexutil.Big); !ok || price.ToInt().Sign() <= 0 {
		t.Fatalf("blobGasPrice = %#v", fields["blobGasPrice"])
	}
}

func TestUnpricedCallMessageUsesZeroFee(t *testing.T) {
	msg := (&CallArgs{}).ToMessage(100_000)
	if msg.GasPrice().Sign() != 0 || msg.GasFeeCap().Sign() != 0 || msg.GasTipCap().Sign() != 0 {
		t.Fatalf("unpriced call has non-zero fees: price=%v cap=%v tip=%v", msg.GasPrice(), msg.GasFeeCap(), msg.GasTipCap())
	}
	evm := &vm.EVM{Context: vm.Context{BaseFee: big.NewInt(7), BlobBaseFee: big.NewInt(11)}}
	lowerUnpricedCallFees(evm, msg)
	if evm.Context.BaseFee.Sign() != 0 || evm.Context.BlobBaseFee.Sign() != 0 {
		t.Fatalf("unpriced call fees were not lowered: base=%v blob=%v", evm.Context.BaseFee, evm.Context.BlobBaseFee)
	}
}
func signedRawTransactionsForTest(t *testing.T, count int) ([]hexutil.Bytes, types.Transactions) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	to := common.HexToAddress("0x1000000000000000000000000000000000000001")
	raw := make([]hexutil.Bytes, count)
	txs := make(types.Transactions, count)
	for i := 0; i < count; i++ {
		tx := types.NewTransaction(uint64(i), to, big.NewInt(1), 21_000, big.NewInt(20), nil)
		tx, err = types.SignTx(tx, types.NewEIP155Signer(big.NewInt(1337)), key)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := tx.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		raw[i] = encoded
		txs[i] = tx
	}
	return raw, txs
}

func signedIndependentRawTransactionsForTest(t *testing.T, count int) ([]hexutil.Bytes, types.Transactions) {
	t.Helper()
	to := common.HexToAddress("0x1000000000000000000000000000000000000001")
	raw := make([]hexutil.Bytes, count)
	txs := make(types.Transactions, count)
	for i := 0; i < count; i++ {
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		tx := types.NewTransaction(0, to, big.NewInt(int64(i+1)), 21_000, big.NewInt(20), nil)
		tx, err = types.SignTx(tx, types.NewEIP155Signer(big.NewInt(1337)), key)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := tx.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		raw[i] = encoded
		txs[i] = tx
	}
	return raw, txs
}

func signedRawTransactionMicroBatchesForTest(t *testing.T, count, batchSize int) ([]hexutil.Bytes, types.Transactions) {
	t.Helper()
	if batchSize <= 0 {
		t.Fatalf("invalid test batch size %d", batchSize)
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	to := common.HexToAddress("0x1000000000000000000000000000000000000001")
	raw := make([]hexutil.Bytes, count)
	txs := make(types.Transactions, count)
	for i := 0; i < count; i++ {
		if i > 0 && i%batchSize == 0 {
			key, err = crypto.GenerateKey()
			if err != nil {
				t.Fatal(err)
			}
		}
		tx := types.NewTransaction(uint64(i), to, big.NewInt(1), 21_000, big.NewInt(20), nil)
		tx, err = types.SignTx(tx, types.NewEIP155Signer(big.NewInt(1337)), key)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := tx.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		raw[i] = encoded
		txs[i] = tx
	}
	return raw, txs
}

func TestRawTransactionBurstEnvelopeAndWorkerScaling(t *testing.T) {
	if MaxRawTxRequestCount != params.NativeParallelHardMaxTransactions || singleRawTxDefaultQueueCountLimit < params.EVMParallelIngressBurstTransactions {
		t.Fatalf("raw transaction count envelope = request %d queue %d, want request %d and queue >= %d", MaxRawTxRequestCount, singleRawTxDefaultQueueCountLimit, params.NativeParallelHardMaxTransactions, params.EVMParallelIngressBurstTransactions)
	}
	if MaxRawTxRequestBytes != 60*1024*1024 {
		t.Fatalf("raw transaction request byte limit = %d, want 60 MiB", MaxRawTxRequestBytes)
	}
	if singleRawTxDefaultQueueBytesLimit < 128*1024*1024 {
		t.Fatalf("node-global raw transaction queue byte limit = %d, want at least 128 MiB", singleRawTxDefaultQueueBytesLimit)
	}
	for _, test := range []struct {
		cpus int
		want int
	}{
		{cpus: 1, want: rawTxBackendMinWorkers},
		{cpus: rawTxBackendMinWorkers, want: rawTxBackendMinWorkers},
		{cpus: 32, want: 32},
		{cpus: rawTxBackendMaxWorkers, want: rawTxBackendMaxWorkers},
		{cpus: rawTxBackendMaxWorkers * 2, want: rawTxBackendMaxWorkers},
	} {
		if got := rawTxBackendWorkersForCPU(test.cpus); got != test.want {
			t.Fatalf("backend workers for %d CPUs = %d, want %d", test.cpus, got, test.want)
		}
	}
}

func TestSendRawTransactionsRejectsStructuralLimitsWithoutBackendCall(t *testing.T) {
	backend := newLondonAPITestBackend()
	var calls int
	backend.sendBatchFn = func(txs types.Transactions) []error {
		calls++
		return make([]error, len(txs))
	}
	api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
	if _, err := api.SendRawTransactions(context.Background(), nil); err == nil {
		t.Fatal("expected empty batch error")
	}
	tooMany := make([]hexutil.Bytes, MaxRawTxRequestCount+1)
	if _, err := api.SendRawTransactions(context.Background(), tooMany); err == nil {
		t.Fatal("expected request count limit error")
	}
	tooLarge := []hexutil.Bytes{make([]byte, MaxRawTxRequestBytes+1)}
	if _, err := api.SendRawTransactions(context.Background(), tooLarge); err == nil {
		t.Fatal("expected request byte limit error")
	}
	if calls != 0 {
		t.Fatalf("backend calls = %d, want 0", calls)
	}
}

func TestSendRawTransactionsSubmitsOneAlignedBackendBatch(t *testing.T) {
	raw, signed := signedRawTransactionsForTest(t, 2)
	inputs := []hexutil.Bytes{raw[0], {0xff, 0x00}, raw[1]}
	backendErr := errors.New("injected backend rejection")
	backend := newLondonAPITestBackend()
	var calls int
	backend.sendBatchFn = func(txs types.Transactions) []error {
		calls++
		if len(txs) != 2 {
			t.Fatalf("backend transactions = %d, want 2", len(txs))
		}
		for i, tx := range txs {
			if tx.RouteHint() != types.TxRouteFast {
				t.Fatalf("transaction %d route = %d, want fast", i, tx.RouteHint())
			}
		}
		return []error{nil, backendErr}
	}
	api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
	results, err := api.SendRawTransactions(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("backend calls = %d, want 1", calls)
	}
	if len(results) != len(inputs) {
		t.Fatalf("results = %d, want %d", len(results), len(inputs))
	}
	if results[0].Hash == nil || *results[0].Hash != signed[0].Hash() || results[0].Error != "" {
		t.Fatalf("unexpected first result: %+v", results[0])
	}
	if results[1].Hash != nil || results[1].Error == "" {
		t.Fatalf("malformed transaction result = %+v", results[1])
	}
	if results[2].Hash == nil || *results[2].Hash != signed[1].Hash() || results[2].Error != backendErr.Error() {
		t.Fatalf("unexpected backend rejection result: %+v", results[2])
	}
}

func TestSendRawTransactionsDeduplicatesHashesAndFansOutResults(t *testing.T) {
	raw, signed := signedRawTransactionsForTest(t, 2)
	inputs := []hexutil.Bytes{raw[0], raw[0], raw[1], raw[1], raw[0]}
	backendErr := errors.New("injected unique transaction rejection")
	backend := newLondonAPITestBackend()
	var calls int
	backend.sendBatchFn = func(txs types.Transactions) []error {
		calls++
		if len(txs) != 2 {
			t.Fatalf("backend transactions = %d, want 2 unique transactions", len(txs))
		}
		if txs[0].Hash() != signed[0].Hash() || txs[1].Hash() != signed[1].Hash() {
			t.Fatalf("backend transaction order = [%s, %s], want [%s, %s]",
				txs[0].Hash(), txs[1].Hash(), signed[0].Hash(), signed[1].Hash())
		}
		return []error{nil, backendErr}
	}
	api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
	results, err := api.SendRawTransactions(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("backend calls = %d, want 1", calls)
	}
	if len(results) != len(inputs) {
		t.Fatalf("results = %d, want %d", len(results), len(inputs))
	}
	for _, index := range []int{0, 1, 4} {
		if results[index].Hash == nil || *results[index].Hash != signed[0].Hash() || results[index].Error != "" {
			t.Fatalf("idempotent duplicate result %d mismatch: %+v", index, results[index])
		}
	}
	for _, index := range []int{2, 3} {
		if results[index].Hash == nil || *results[index].Hash != signed[1].Hash() || results[index].Error != backendErr.Error() {
			t.Fatalf("rejected duplicate result %d mismatch: %+v", index, results[index])
		}
	}
}

func TestSendRawTransactionsAcceptsMaximumCountInOneBackendCall(t *testing.T) {
	raw, _ := signedRawTransactionsForTest(t, MaxRawTxBatchCount)
	backend := newLondonAPITestBackend()
	var calls, received int
	backend.sendBatchFn = func(txs types.Transactions) []error {
		calls++
		received = len(txs)
		return make([]error, len(txs))
	}
	api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
	results, err := api.SendRawTransactions(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != MaxRawTxBatchCount || calls != 1 || received != MaxRawTxBatchCount {
		t.Fatalf("batch mismatch: results=%d calls=%d received=%d", len(results), calls, received)
	}
}

func TestSendRawTransactionsSplitsBurstIntoBoundedMicroBatches(t *testing.T) {
	const tail = 17
	count := MaxRawTxBatchCount*2 + tail
	raw, signed := signedRawTransactionMicroBatchesForTest(t, count, MaxRawTxBatchCount)
	backend := newLondonAPITestBackend()
	backendErr := errors.New("injected reversed-batch rejection")
	batchDone := []chan struct{}{make(chan struct{}), make(chan struct{}), make(chan struct{})}
	seen := make([]int, count)
	var mu sync.Mutex
	var calls, received int
	completionOrder := make([]int, 0, len(batchDone))
	backend.sendBatchFn = func(txs types.Transactions) []error {
		if len(txs) == 0 || len(txs) > MaxRawTxBatchCount {
			t.Errorf("backend micro-batch size = %d", len(txs))
		}
		batchBytes := 0
		for _, tx := range txs {
			encoded, err := tx.MarshalBinary()
			if err != nil {
				t.Error(err)
				continue
			}
			batchBytes += len(encoded)
		}
		if batchBytes > MaxRawTxBatchBytes {
			t.Errorf("backend micro-batch bytes = %d, limit %d", batchBytes, MaxRawTxBatchBytes)
		}
		ordinal := int(txs[0].Nonce()) / MaxRawTxBatchCount
		if ordinal+1 < len(batchDone) {
			<-batchDone[ordinal+1]
		}
		backendResults := make([]error, len(txs))
		mu.Lock()
		calls++
		received += len(txs)
		completionOrder = append(completionOrder, ordinal)
		for index, tx := range txs {
			nonce := int(tx.Nonce())
			if nonce < 0 || nonce >= len(seen) {
				t.Errorf("backend nonce %d is outside request", nonce)
				continue
			}
			seen[nonce]++
			if nonce%257 == 0 {
				backendResults[index] = backendErr
			}
		}
		mu.Unlock()
		close(batchDone[ordinal])
		return backendResults
	}
	api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
	results, err := api.SendRawTransactions(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 3 || received != count || len(results) != count {
		t.Fatalf("burst mismatch: calls=%d received=%d results=%d", calls, received, len(results))
	}
	if fmt.Sprint(completionOrder) != "[2 1 0]" {
		t.Fatalf("backend completion order = %v, want reverse input order", completionOrder)
	}
	for index, result := range results {
		if seen[index] != 1 {
			t.Fatalf("transaction %d backend submissions = %d, want 1", index, seen[index])
		}
		wantError := ""
		if index%257 == 0 {
			wantError = backendErr.Error()
		}
		if result.Error != wantError || result.Hash == nil || *result.Hash != signed[index].Hash() {
			t.Fatalf("result %d mismatch: %+v", index, result)
		}
	}
}

func TestSendRawTransactionsSplitsBurstByEncodedBytes(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	to := common.HexToAddress("0x1000000000000000000000000000000000000001")
	data := make([]byte, MaxRawTxBatchBytes/2)
	raw := make([]hexutil.Bytes, 3)
	for index := range raw {
		tx := types.NewTransaction(uint64(index), to, big.NewInt(1), 10_000_000, big.NewInt(20), data)
		tx, err = types.SignTx(tx, types.NewEIP155Signer(big.NewInt(1337)), key)
		if err != nil {
			t.Fatal(err)
		}
		raw[index], err = tx.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if len(raw[index]) > MaxRawTxBatchBytes {
			t.Fatalf("test transaction exceeds per-item bound: %d", len(raw[index]))
		}
	}
	if len(raw[0])+len(raw[1]) <= MaxRawTxBatchBytes {
		t.Fatal("test transactions do not straddle the byte bound")
	}

	backend := newLondonAPITestBackend()
	var mu sync.Mutex
	var calls, received int
	backend.sendBatchFn = func(txs types.Transactions) []error {
		batchBytes := 0
		for _, tx := range txs {
			encoded, err := tx.MarshalBinary()
			if err != nil {
				t.Error(err)
				continue
			}
			batchBytes += len(encoded)
		}
		if batchBytes > MaxRawTxBatchBytes {
			t.Errorf("backend micro-batch bytes = %d, limit %d", batchBytes, MaxRawTxBatchBytes)
		}
		mu.Lock()
		calls++
		received += len(txs)
		mu.Unlock()
		return make([]error, len(txs))
	}
	api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
	results, err := api.SendRawTransactions(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 3 || received != len(raw) || len(results) != len(raw) {
		t.Fatalf("byte split mismatch: calls=%d received=%d results=%d", calls, received, len(results))
	}
}

func TestSendRawTransactionsAcceptsTwentyThousandAsMicroBatches(t *testing.T) {
	const count = 20_000
	raw, signed := signedRawTransactionMicroBatchesForTest(t, count, MaxRawTxBatchCount)
	backend := newLondonAPITestBackend()
	wantCalls := (count + MaxRawTxBatchCount - 1) / MaxRawTxBatchCount
	backendErr := errors.New("injected parallel backend rejection")
	started := make(chan struct{}, wantCalls)
	release := make(chan struct{})
	seen := make([]int, count)
	var mu sync.Mutex
	var calls, received, active, maxActive int
	backend.sendBatchFn = func(txs types.Transactions) []error {
		if len(txs) == 0 || len(txs) > MaxRawTxBatchCount {
			t.Errorf("backend micro-batch size = %d", len(txs))
		}
		batchBytes := 0
		backendResults := make([]error, len(txs))
		mu.Lock()
		calls++
		received += len(txs)
		active++
		if active > maxActive {
			maxActive = active
		}
		for index, tx := range txs {
			nonce := int(tx.Nonce())
			if nonce < 0 || nonce >= len(seen) {
				t.Errorf("backend nonce %d is outside request", nonce)
				continue
			}
			seen[nonce]++
			encoded, err := tx.MarshalBinary()
			if err != nil {
				t.Error(err)
			} else {
				batchBytes += len(encoded)
			}
			if nonce%997 == 0 {
				backendResults[index] = backendErr
			}
		}
		mu.Unlock()
		if batchBytes > MaxRawTxBatchBytes {
			t.Errorf("backend micro-batch bytes = %d, limit %d", batchBytes, MaxRawTxBatchBytes)
		}
		started <- struct{}{}
		<-release
		mu.Lock()
		active--
		mu.Unlock()
		return backendResults
	}
	api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
	wantActive := api.rawTxBackendWorkers
	if wantActive > wantCalls {
		wantActive = wantCalls
	}
	type rpcResult struct {
		results []RawTxResult
		err     error
	}
	finished := make(chan rpcResult, 1)
	go func() {
		results, err := api.SendRawTransactions(context.Background(), raw)
		finished <- rpcResult{results: results, err: err}
	}()
	for index := 0; index < wantActive; index++ {
		select {
		case <-started:
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d/%d backend workers started", index, wantActive)
		}
	}
	mu.Lock()
	if calls != wantActive || active != wantActive || maxActive != wantActive {
		t.Fatalf("initial backend concurrency calls=%d active=%d max=%d, want %d", calls, active, maxActive, wantActive)
	}
	mu.Unlock()
	close(release)
	response := <-finished
	if response.err != nil {
		t.Fatal(response.err)
	}
	results := response.results
	mu.Lock()
	defer mu.Unlock()
	if calls != wantCalls || received != count || maxActive > api.rawTxBackendWorkers || len(results) != count {
		t.Fatalf("20k burst mismatch: calls=%d/%d received=%d maxActive=%d results=%d", calls, wantCalls, received, maxActive, len(results))
	}
	for index, result := range results {
		if seen[index] != 1 {
			t.Fatalf("transaction %d backend submissions = %d, want 1", index, seen[index])
		}
		wantError := ""
		if index%997 == 0 {
			wantError = backendErr.Error()
		}
		if result.Error != wantError || result.Hash == nil || *result.Hash != signed[index].Hash() {
			t.Fatalf("result %d mismatch: %+v", index, result)
		}
	}
}

func TestSendRawTransactionsSerializesSenderAcrossMicroBatches(t *testing.T) {
	const count = MaxRawTxBatchCount + 1
	raw, signed := signedRawTransactionsForTest(t, count)
	backend := newLondonAPITestBackend()
	firstStarted := make(chan types.Transactions, 1)
	secondStarted := make(chan types.Transactions, 1)
	unexpected := make(chan types.Transactions, 1)
	releaseFirst := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseFirst) }) }
	backend.sendBatchFn = func(txs types.Transactions) []error {
		copyOfTxs := append(types.Transactions(nil), txs...)
		if len(txs) == MaxRawTxBatchCount && txs[0].Nonce() == 0 {
			firstStarted <- copyOfTxs
			<-releaseFirst
		} else if len(txs) == 1 && txs[0].Nonce() == MaxRawTxBatchCount {
			secondStarted <- copyOfTxs
		} else {
			unexpected <- copyOfTxs
		}
		return make([]error, len(txs))
	}
	api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
	type rpcResult struct {
		results []RawTxResult
		err     error
	}
	finished := make(chan rpcResult, 1)
	go func() {
		results, err := api.SendRawTransactions(context.Background(), raw)
		finished <- rpcResult{results: results, err: err}
	}()

	var first types.Transactions
	select {
	case first = <-firstStarted:
	case got := <-unexpected:
		release()
		t.Fatalf("unexpected first backend batch: %v", got)
	case <-time.After(10 * time.Second):
		release()
		t.Fatal("first same-sender micro-batch did not start")
	}
	for index, tx := range first {
		if tx.Hash() != signed[index].Hash() || tx.Nonce() != uint64(index) {
			release()
			t.Fatalf("first backend batch transaction %d = %s/%d, want %s/%d", index, tx.Hash(), tx.Nonce(), signed[index].Hash(), index)
		}
	}
	select {
	case second := <-secondStarted:
		release()
		<-finished
		t.Fatalf("same-sender successor %s started before predecessor completed", second[0].Hash())
	case got := <-unexpected:
		release()
		<-finished
		t.Fatalf("unexpected concurrent backend batch: %v", got)
	case <-time.After(100 * time.Millisecond):
	}

	release()
	select {
	case second := <-secondStarted:
		if len(second) != 1 || second[0].Hash() != signed[MaxRawTxBatchCount].Hash() || second[0].Nonce() != MaxRawTxBatchCount {
			t.Fatalf("second backend batch = %v, want nonce %d transaction %s", second, MaxRawTxBatchCount, signed[MaxRawTxBatchCount].Hash())
		}
	case got := <-unexpected:
		t.Fatalf("unexpected backend batch after predecessor release: %v", got)
	case <-time.After(10 * time.Second):
		t.Fatal("same-sender successor did not start after predecessor completed")
	}
	response := <-finished
	if response.err != nil {
		t.Fatal(response.err)
	}
	if len(response.results) != count {
		t.Fatalf("results = %d, want %d", len(response.results), count)
	}
	for index, result := range response.results {
		if result.Error != "" || result.Hash == nil || *result.Hash != signed[index].Hash() {
			t.Fatalf("result %d mismatch: %+v", index, result)
		}
	}
}

func TestRawTxIngressBackendPanicReleasesCapacityAndAlignsResults(t *testing.T) {
	const workerLimit = 4
	raw, signed := signedIndependentRawTransactionsForTest(t, workerLimit)
	backend := newLondonAPITestBackend()
	backend.sendBatchFn = func(types.Transactions) []error {
		panic("injected backend panic")
	}
	api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
	api.rawTxBackendWorkers = workerLimit
	results, err := api.SendRawTransactions(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(raw) {
		t.Fatalf("panic results = %d, want %d", len(results), len(raw))
	}
	for index, result := range results {
		if result.Hash == nil || *result.Hash != signed[index].Hash() || !strings.Contains(result.Error, "injected backend panic") {
			t.Fatalf("panic result %d mismatch: %+v", index, result)
		}
	}
	deadline := time.Now().Add(time.Second)
	for {
		api.singleRawTxMu.Lock()
		idle := api.singleRawTxPendingCount == 0 && api.singleRawTxPendingBytes == 0 &&
			len(api.rawTxIngressQueue) == 0 && api.rawTxIngressWorkers == 0 && api.rawTxIngressActiveJobs == 0 && len(api.rawTxActiveSenders) == 0
		api.singleRawTxMu.Unlock()
		if idle {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("backend panic did not release ingress capacity and sender ownership exactly once")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRawTxIngressSchedulerCapsConcurrencyAcrossBatchRequests(t *testing.T) {
	workerLimit := defaultRawTxBackendWorkers()
	batchesPerRequest := workerLimit + 1
	request, _ := signedRawTransactionMicroBatchesForTest(t, batchesPerRequest*MaxRawTxBatchCount, MaxRawTxBatchCount)

	backend := newLondonAPITestBackend()
	started := make(chan struct{}, batchesPerRequest*2)
	release := make(chan struct{})
	var mu sync.Mutex
	var calls, active, maxActive int
	backend.sendBatchFn = func(txs types.Transactions) []error {
		mu.Lock()
		calls++
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()
		started <- struct{}{}
		<-release
		mu.Lock()
		active--
		mu.Unlock()
		return make([]error, len(txs))
	}
	api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))

	type rpcResult struct {
		results []RawTxResult
		err     error
	}
	begin := make(chan struct{})
	finished := make(chan rpcResult, 2)
	for requestIndex := 0; requestIndex < 2; requestIndex++ {
		go func() {
			<-begin
			results, err := api.SendRawTransactions(context.Background(), request)
			finished <- rpcResult{results: results, err: err}
		}()
	}
	close(begin)
	for index := 0; index < workerLimit; index++ {
		select {
		case <-started:
		case <-time.After(10 * time.Second):
			close(release)
			t.Fatalf("only %d/%d global backend workers started", index, workerLimit)
		}
	}
	exceeded := false
	select {
	case <-started:
		exceeded = true
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	for requestIndex := 0; requestIndex < 2; requestIndex++ {
		response := <-finished
		if response.err != nil {
			t.Fatal(response.err)
		}
		if len(response.results) != len(request) {
			t.Fatalf("request %d results = %d, want %d", requestIndex, len(response.results), len(request))
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if exceeded || maxActive > workerLimit {
		t.Fatalf("node-global backend concurrency reached %d, limit %d", maxActive, workerLimit)
	}
	if calls != batchesPerRequest*2 {
		t.Fatalf("backend calls = %d, want %d", calls, batchesPerRequest*2)
	}
}

func TestRawTxIngressSchedulerBackpressureAlignsBatchResults(t *testing.T) {
	raw, _ := signedRawTransactionsForTest(t, 2)
	tests := []struct {
		name      string
		configure func(*PublicTransactionPoolAPI)
	}{
		{
			name: "count",
			configure: func(api *PublicTransactionPoolAPI) {
				api.singleRawTxQueueCountLimit = 1
			},
		},
		{
			name: "bytes",
			configure: func(api *PublicTransactionPoolAPI) {
				api.singleRawTxQueueBytesLimit = len(raw[0])
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := newLondonAPITestBackend()
			firstStarted := make(chan struct{})
			releaseFirst := make(chan struct{})
			var mu sync.Mutex
			calls := 0
			backend.sendBatchFn = func(txs types.Transactions) []error {
				mu.Lock()
				calls++
				call := calls
				mu.Unlock()
				if call == 1 {
					close(firstStarted)
					<-releaseFirst
				}
				return make([]error, len(txs))
			}
			api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
			test.configure(api)

			firstDone := make(chan error, 1)
			go func() {
				_, err := api.SendRawTransactions(context.Background(), raw[:1])
				firstDone <- err
			}()
			<-firstStarted
			results, err := api.SendRawTransactions(context.Background(), raw)
			if err != nil {
				close(releaseFirst)
				t.Fatal(err)
			}
			if len(results) != len(raw) {
				close(releaseFirst)
				t.Fatalf("backpressure results = %d, want %d", len(results), len(raw))
			}
			for index, result := range results {
				if result.Hash != nil || !strings.Contains(result.Error, "raw transaction ingress busy") {
					close(releaseFirst)
					t.Fatalf("backpressure result %d is not aligned busy rejection: %+v", index, result)
				}
			}
			mu.Lock()
			callsBeforeRelease := calls
			mu.Unlock()
			close(releaseFirst)
			if err := <-firstDone; err != nil {
				t.Fatalf("accepted request failed: %v", err)
			}
			if callsBeforeRelease != 1 {
				t.Fatalf("backend calls before release = %d, want 1", callsBeforeRelease)
			}
		})
	}
}

func TestRawTxIngressPendingCapacityIsSharedAcrossRPCMethods(t *testing.T) {
	raw, _ := signedRawTransactionsForTest(t, 2)
	tests := []struct {
		name          string
		startAccepted func(*PublicTransactionPoolAPI) <-chan error
		submitBlocked func(*PublicTransactionPoolAPI) error
	}{
		{
			name: "batch_blocks_single",
			startAccepted: func(api *PublicTransactionPoolAPI) <-chan error {
				done := make(chan error, 1)
				go func() {
					_, err := api.SendRawTransactions(context.Background(), raw[:1])
					done <- err
				}()
				return done
			},
			submitBlocked: func(api *PublicTransactionPoolAPI) error {
				_, err := api.SendRawTransaction(context.Background(), raw[1])
				return err
			},
		},
		{
			name: "single_blocks_batch",
			startAccepted: func(api *PublicTransactionPoolAPI) <-chan error {
				done := make(chan error, 1)
				go func() {
					_, err := api.SendRawTransaction(context.Background(), raw[0])
					done <- err
				}()
				return done
			},
			submitBlocked: func(api *PublicTransactionPoolAPI) error {
				results, err := api.SendRawTransactions(context.Background(), raw[1:])
				if err != nil {
					return err
				}
				if len(results) != 1 || results[0].Hash != nil || !strings.Contains(results[0].Error, "raw transaction ingress busy") {
					return fmt.Errorf("batch backpressure result mismatch: %+v", results)
				}
				return errors.New(results[0].Error)
			},
		},
		{
			name: "single_blocks_with_opts",
			startAccepted: func(api *PublicTransactionPoolAPI) <-chan error {
				done := make(chan error, 1)
				go func() {
					_, err := api.SendRawTransaction(context.Background(), raw[0])
					done <- err
				}()
				return done
			},
			submitBlocked: func(api *PublicTransactionPoolAPI) error {
				_, err := api.SendRawTransactionWithOpts(context.Background(), raw[1], SendTxOpts{UseSlowLane: true})
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := newLondonAPITestBackend()
			firstStarted := make(chan struct{})
			releaseFirst := make(chan struct{})
			var backendMu sync.Mutex
			backendCalls := 0
			backend.sendBatchFn = func(txs types.Transactions) []error {
				backendMu.Lock()
				backendCalls++
				call := backendCalls
				backendMu.Unlock()
				if call == 1 {
					close(firstStarted)
					<-releaseFirst
				}
				return make([]error, len(txs))
			}
			api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
			api.singleRawTxCoalesceDelay = 0
			api.singleRawTxQueueCountLimit = 1
			acceptedDone := test.startAccepted(api)
			<-firstStarted
			blockedErr := test.submitBlocked(api)
			if blockedErr == nil || !strings.Contains(blockedErr.Error(), "raw transaction ingress busy") {
				close(releaseFirst)
				t.Fatalf("cross-method backpressure error = %v", blockedErr)
			}
			close(releaseFirst)
			if err := <-acceptedDone; err != nil {
				t.Fatalf("accepted request failed: %v", err)
			}
		})
	}
}

func TestSendRawTransactionsCancellationReturnsWhileEnqueuedMicroBatchesFinish(t *testing.T) {
	const workerLimit = 2
	count := MaxRawTxBatchCount + 1
	raw, signed := signedRawTransactionMicroBatchesForTest(t, count, MaxRawTxBatchCount)
	backend := newLondonAPITestBackend()
	started := make(chan struct{}, workerLimit)
	release := make(chan struct{})
	var mu sync.Mutex
	var calls, active int
	backend.sendBatchFn = func(txs types.Transactions) []error {
		mu.Lock()
		calls++
		active++
		mu.Unlock()
		started <- struct{}{}
		<-release
		mu.Lock()
		active--
		mu.Unlock()
		return make([]error, len(txs))
	}
	api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
	api.rawTxBackendWorkers = workerLimit
	ctx, cancel := context.WithCancel(context.Background())
	type rpcResult struct {
		results []RawTxResult
		err     error
	}
	finished := make(chan rpcResult, 1)
	go func() {
		results, err := api.SendRawTransactions(ctx, raw)
		finished <- rpcResult{results: results, err: err}
	}()
	for index := 0; index < workerLimit; index++ {
		select {
		case <-started:
		case <-time.After(10 * time.Second):
			close(release)
			t.Fatalf("only %d/%d backend workers started", index, workerLimit)
		}
	}
	cancel()
	var response rpcResult
	select {
	case response = <-finished:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("cancelled request did not return while admitted backend work was blocked")
	}
	if response.err != nil {
		close(release)
		t.Fatal(response.err)
	}
	if len(response.results) != count {
		close(release)
		t.Fatalf("results=%d, want %d", len(response.results), count)
	}
	for index, result := range response.results {
		if result.Hash == nil || *result.Hash != signed[index].Hash() || result.Error != context.Canceled.Error() {
			close(release)
			t.Fatalf("cancelled admitted result %d mismatch: %+v", index, result)
		}
	}
	api.singleRawTxMu.Lock()
	pending, backendActive := api.singleRawTxPendingCount, api.rawTxIngressActiveJobs
	api.singleRawTxMu.Unlock()
	if pending != count || backendActive != workerLimit {
		close(release)
		t.Fatalf("node-owned work after return: pending=%d/%d active=%d/%d", pending, count, backendActive, workerLimit)
	}

	// Buffered completion delivery must not require an RPC waiter. The backend
	// jobs finish and refund the shared capacity after the cancelled call exits.
	close(release)
	deadline := time.Now().Add(time.Second)
	for {
		api.singleRawTxMu.Lock()
		idle := api.singleRawTxPendingCount == 0 && api.singleRawTxPendingBytes == 0 &&
			len(api.rawTxIngressQueue) == 0 && api.rawTxIngressWorkers == 0 && api.rawTxIngressActiveJobs == 0
		api.singleRawTxMu.Unlock()
		if idle {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cancelled node-owned work did not finish and release capacity")
		}
		time.Sleep(time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != workerLimit || active != 0 {
		t.Fatalf("backend calls=%d active=%d, want %d/0", calls, active, workerLimit)
	}
}

func TestRawTxIngressStopRejectsNewWorkAndDrainsAcceptedJob(t *testing.T) {
	raw, signed := signedRawTransactionsForTest(t, 2)
	backend := newLondonAPITestBackend()
	backendStarted := make(chan struct{}, 1)
	releaseBackend := make(chan struct{})
	var backendMu sync.Mutex
	backendCalls := 0
	backend.sendBatchFn = func(txs types.Transactions) []error {
		backendMu.Lock()
		backendCalls++
		backendMu.Unlock()
		backendStarted <- struct{}{}
		<-releaseBackend
		return make([]error, len(txs))
	}
	api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
	api.singleRawTxCoalesceDelay = 0

	type callResult struct {
		hash common.Hash
		err  error
	}
	acceptedDone := make(chan callResult, 1)
	go func() {
		hash, err := api.SendRawTransaction(context.Background(), raw[0])
		acceptedDone <- callResult{hash: hash, err: err}
	}()
	select {
	case <-backendStarted:
	case <-time.After(10 * time.Second):
		close(releaseBackend)
		t.Fatal("accepted backend job did not start")
	}

	const stopCallers = 16
	stopDone := make(chan struct{}, stopCallers)
	for caller := 0; caller < stopCallers; caller++ {
		go func() {
			api.Stop()
			stopDone <- struct{}{}
		}()
	}
	select {
	case <-stopDone:
		close(releaseBackend)
		t.Fatal("Stop returned before the accepted backend job completed")
	case <-time.After(50 * time.Millisecond):
	}

	if _, err := api.SendRawTransaction(context.Background(), raw[1]); !errors.Is(err, errRawTxIngressStopped) {
		close(releaseBackend)
		t.Fatalf("post-stop admission error = %v, want %v", err, errRawTxIngressStopped)
	}
	backendMu.Lock()
	callsBeforeRelease := backendCalls
	backendMu.Unlock()
	if callsBeforeRelease != 1 {
		close(releaseBackend)
		t.Fatalf("post-stop transaction reached backend: calls=%d", callsBeforeRelease)
	}

	close(releaseBackend)
	accepted := <-acceptedDone
	if accepted.err != nil || accepted.hash != signed[0].Hash() {
		t.Fatalf("accepted transaction result = %s/%v, want %s/nil", accepted.hash, accepted.err, signed[0].Hash())
	}
	for caller := 0; caller < stopCallers; caller++ {
		select {
		case <-stopDone:
		case <-time.After(time.Second):
			t.Fatalf("concurrent Stop caller %d did not join", caller)
		}
	}

	// An idempotent Stop after the completed drain must return immediately.
	stoppedAgain := make(chan struct{})
	go func() {
		api.Stop()
		close(stoppedAgain)
	}()
	select {
	case <-stoppedAgain:
	case <-time.After(time.Second):
		t.Fatal("idempotent Stop blocked after drain")
	}

	api.singleRawTxMu.Lock()
	idle := api.singleRawTxPendingCount == 0 && api.singleRawTxPendingBytes == 0 &&
		len(api.singleRawTxQueue) == 0 && len(api.rawTxIngressQueue) == 0 &&
		api.rawTxIngressWorkers == 0 && api.rawTxIngressActiveJobs == 0
	api.singleRawTxMu.Unlock()
	if !idle {
		t.Fatal("raw transaction scheduler retained work after Stop drain")
	}
}

func TestRawTxIngressStopDrainsDetachedCancelledBulk(t *testing.T) {
	const workerLimit = 2
	raw, _ := signedIndependentRawTransactionsForTest(t, workerLimit)
	backend := newLondonAPITestBackend()
	backendStarted := make(chan struct{}, workerLimit)
	releaseBackend := make(chan struct{})
	backend.sendBatchFn = func(txs types.Transactions) []error {
		backendStarted <- struct{}{}
		<-releaseBackend
		return make([]error, len(txs))
	}
	api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
	api.rawTxBackendWorkers = workerLimit

	ctx, cancel := context.WithCancel(context.Background())
	bulkDone := make(chan error, 1)
	go func() {
		_, err := api.SendRawTransactions(ctx, raw)
		bulkDone <- err
	}()
	for worker := 0; worker < workerLimit; worker++ {
		select {
		case <-backendStarted:
		case <-time.After(10 * time.Second):
			cancel()
			close(releaseBackend)
			t.Fatalf("only %d/%d detached bulk jobs started", worker, workerLimit)
		}
	}
	cancel()
	select {
	case err := <-bulkDone:
		if err != nil {
			close(releaseBackend)
			t.Fatalf("cancelled bulk returned top-level error: %v", err)
		}
	case <-time.After(time.Second):
		close(releaseBackend)
		t.Fatal("cancelled bulk did not return while node-owned jobs were blocked")
	}

	stopDone := make(chan struct{})
	go func() {
		api.Stop()
		close(stopDone)
	}()
	select {
	case <-stopDone:
		close(releaseBackend)
		t.Fatal("Stop returned before detached bulk jobs completed")
	case <-time.After(50 * time.Millisecond):
	}
	if _, err := api.SendRawTransactions(context.Background(), raw[:1]); !errors.Is(err, errRawTxIngressStopped) {
		close(releaseBackend)
		t.Fatalf("post-stop bulk error = %v, want %v", err, errRawTxIngressStopped)
	}

	close(releaseBackend)
	select {
	case <-stopDone:
	case <-time.After(time.Second):
		t.Fatal("Stop did not join detached bulk jobs")
	}
}

func TestRawTxIngressStopJoinsCancelledRequestDuringCoalesceDelay(t *testing.T) {
	raw, _ := signedRawTransactionsForTest(t, 1)
	backend := newLondonAPITestBackend()
	backendStarted := make(chan struct{}, 1)
	releaseBackend := make(chan struct{})
	backend.sendBatchFn = func(txs types.Transactions) []error {
		backendStarted <- struct{}{}
		<-releaseBackend
		return make([]error, len(txs))
	}
	api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
	api.singleRawTxCoalesceDelay = 100 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	requestDone := make(chan error, 1)
	go func() {
		_, err := api.SendRawTransaction(ctx, raw[0])
		requestDone <- err
	}()
	deadline := time.Now().Add(time.Second)
	for {
		api.singleRawTxMu.Lock()
		queued := api.singleRawTxPendingCount == 1 && api.singleRawTxWorkerRunning
		api.singleRawTxMu.Unlock()
		if queued {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			close(releaseBackend)
			t.Fatal("single request did not enter the coalescer")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-requestDone:
		if !errors.Is(err, context.Canceled) {
			close(releaseBackend)
			t.Fatalf("cancelled request error = %v, want %v", err, context.Canceled)
		}
	case <-time.After(time.Second):
		close(releaseBackend)
		t.Fatal("request cancellation waited for the coalescer delay")
	}

	stopDone := make(chan struct{})
	go func() {
		api.Stop()
		close(stopDone)
	}()
	select {
	case <-stopDone:
		close(releaseBackend)
		t.Fatal("Stop returned while accepted work remained in the coalescer")
	case <-time.After(20 * time.Millisecond):
	}
	select {
	case <-backendStarted:
	case <-time.After(time.Second):
		close(releaseBackend)
		t.Fatal("accepted request did not leave the coalescer during Stop drain")
	}
	select {
	case <-stopDone:
		close(releaseBackend)
		t.Fatal("Stop returned while the drained backend call remained active")
	case <-time.After(20 * time.Millisecond):
	}

	close(releaseBackend)
	select {
	case <-stopDone:
	case <-time.After(time.Second):
		t.Fatal("Stop did not join the coalescer and backend worker")
	}
}

func TestSendRawTransactionsBoundsUniqueSenderJobWindow(t *testing.T) {
	const workerLimit = 2
	count := (workerLimit*rawTxIngressOutstandingWaves + 1) * MaxRawTxBatchCount
	raw, signed := signedIndependentRawTransactionsForTest(t, count)
	backend := newLondonAPITestBackend()
	started := make(chan struct{}, workerLimit)
	release := make(chan struct{})
	var mu sync.Mutex
	calls := 0
	backend.sendBatchFn = func(txs types.Transactions) []error {
		mu.Lock()
		calls++
		mu.Unlock()
		started <- struct{}{}
		<-release
		return make([]error, len(txs))
	}
	api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
	api.rawTxBackendWorkers = workerLimit
	ctx, cancel := context.WithCancel(context.Background())
	type rpcResult struct {
		results []RawTxResult
		err     error
	}
	finished := make(chan rpcResult, 1)
	go func() {
		results, err := api.SendRawTransactions(ctx, raw)
		finished <- rpcResult{results: results, err: err}
	}()
	for index := 0; index < workerLimit; index++ {
		select {
		case <-started:
		case <-time.After(10 * time.Second):
			cancel()
			close(release)
			t.Fatalf("only %d/%d bounded-window workers started", index, workerLimit)
		}
	}

	wantJobs := workerLimit * rawTxIngressOutstandingWaves
	wantPending := rawTxIngressOutstandingWaves * MaxRawTxBatchCount
	deadline := time.Now().Add(10 * time.Second)
	for {
		api.singleRawTxMu.Lock()
		jobs := api.rawTxIngressActiveJobs + len(api.rawTxIngressQueue)
		pending := api.singleRawTxPendingCount
		api.singleRawTxMu.Unlock()
		if jobs == wantJobs && pending == wantPending {
			break
		}
		if jobs > wantJobs || pending > wantPending {
			cancel()
			close(release)
			t.Fatalf("per-request job window exceeded: jobs=%d/%d pending=%d/%d", jobs, wantJobs, pending, wantPending)
		}
		if time.Now().After(deadline) {
			cancel()
			close(release)
			t.Fatalf("bounded job window did not fill: jobs=%d/%d pending=%d/%d", jobs, wantJobs, pending, wantPending)
		}
		time.Sleep(time.Millisecond)
	}
	// The third unique-sender micro-batch is not materialized into another wave
	// of scheduler jobs while the first two waves are blocked.
	time.Sleep(20 * time.Millisecond)
	api.singleRawTxMu.Lock()
	jobs := api.rawTxIngressActiveJobs + len(api.rawTxIngressQueue)
	pending := api.singleRawTxPendingCount
	api.singleRawTxMu.Unlock()
	if jobs != wantJobs || pending != wantPending {
		cancel()
		close(release)
		t.Fatalf("per-request job window grew while blocked: jobs=%d/%d pending=%d/%d", jobs, wantJobs, pending, wantPending)
	}

	cancel()
	var response rpcResult
	select {
	case response = <-finished:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("bounded-window request did not return after cancellation")
	}
	if response.err != nil || len(response.results) != count {
		close(release)
		t.Fatalf("bounded-window response count=%d/%d err=%v", len(response.results), count, response.err)
	}
	for index, result := range response.results {
		if result.Error != context.Canceled.Error() {
			close(release)
			t.Fatalf("cancelled result %d error = %q", index, result.Error)
		}
		if index < wantPending {
			if result.Hash == nil || *result.Hash != signed[index].Hash() {
				close(release)
				t.Fatalf("admitted result %d hash mismatch: %+v", index, result)
			}
		} else if result.Hash != nil {
			close(release)
			t.Fatalf("unadmitted result %d unexpectedly has hash %s", index, *result.Hash)
		}
	}
	close(release)
	deadline = time.Now().Add(time.Second)
	for {
		api.singleRawTxMu.Lock()
		idle := api.singleRawTxPendingCount == 0 && len(api.rawTxIngressQueue) == 0 &&
			api.rawTxIngressWorkers == 0 && api.rawTxIngressActiveJobs == 0
		api.singleRawTxMu.Unlock()
		if idle {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("bounded-window node work did not drain after caller cancellation")
		}
		time.Sleep(time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != wantJobs {
		t.Fatalf("backend calls after cancellation = %d, want admitted jobs %d", calls, wantJobs)
	}
}

func TestSendRawTransactionsBusySenderDoesNotBlockIndependentGroups(t *testing.T) {
	const workerLimit = 4
	sameRaw, sameTxs := signedRawTransactionsForTest(t, 2)
	independentRaw, independentTxs := signedIndependentRawTransactionsForTest(t, workerLimit-1)
	request := []hexutil.Bytes{independentRaw[0], sameRaw[1], independentRaw[1], independentRaw[2]}
	wantErr := errors.New("injected independent rejection")

	backend := newLondonAPITestBackend()
	started := make(chan common.Hash, workerLimit+1)
	releaseHot := make(chan struct{})
	releaseIndependent := make(chan struct{})
	var mu sync.Mutex
	active, maxActive := 0, 0
	backend.sendBatchFn = func(txs types.Transactions) []error {
		if len(txs) != 1 {
			return []error{fmt.Errorf("backend batch size %d, want one sender group", len(txs))}
		}
		hash := txs[0].Hash()
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()
		started <- hash
		switch hash {
		case sameTxs[0].Hash():
			<-releaseHot
		case sameTxs[1].Hash():
		default:
			<-releaseIndependent
		}
		mu.Lock()
		active--
		mu.Unlock()
		if hash == independentTxs[1].Hash() {
			return []error{wantErr}
		}
		return []error{nil}
	}
	api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
	api.rawTxBackendWorkers = workerLimit

	type rpcResult struct {
		results []RawTxResult
		err     error
	}
	firstDone := make(chan rpcResult, 1)
	go func() {
		results, err := api.SendRawTransactions(context.Background(), sameRaw[:1])
		firstDone <- rpcResult{results: results, err: err}
	}()
	if hash := <-started; hash != sameTxs[0].Hash() {
		close(releaseHot)
		close(releaseIndependent)
		t.Fatalf("first backend transaction = %s, want hot predecessor %s", hash, sameTxs[0].Hash())
	}

	secondDone := make(chan rpcResult, 1)
	go func() {
		results, err := api.SendRawTransactions(context.Background(), request)
		secondDone <- rpcResult{results: results, err: err}
	}()
	seenIndependent := make(map[common.Hash]bool, len(independentTxs))
	for len(seenIndependent) < len(independentTxs) {
		select {
		case hash := <-started:
			if hash == sameTxs[1].Hash() {
				close(releaseHot)
				close(releaseIndependent)
				t.Fatal("same-sender successor bypassed its active predecessor")
			}
			seenIndependent[hash] = true
		case <-time.After(10 * time.Second):
			close(releaseHot)
			close(releaseIndependent)
			t.Fatalf("only %d/%d independent sender groups bypassed the busy sender", len(seenIndependent), len(independentTxs))
		}
	}
	for _, tx := range independentTxs {
		if !seenIndependent[tx.Hash()] {
			close(releaseHot)
			close(releaseIndependent)
			t.Fatalf("independent transaction %s did not reach a free backend lane", tx.Hash())
		}
	}
	mu.Lock()
	concurrency := maxActive
	mu.Unlock()
	if concurrency != workerLimit {
		close(releaseHot)
		close(releaseIndependent)
		t.Fatalf("backend concurrency = %d, want %d independent lanes", concurrency, workerLimit)
	}
	select {
	case hash := <-started:
		close(releaseHot)
		close(releaseIndependent)
		t.Fatalf("unexpected backend transaction before hot release: %s", hash)
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseIndependent)
	select {
	case hash := <-started:
		close(releaseHot)
		t.Fatalf("same-sender successor started while predecessor remained active: %s", hash)
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseHot)
	select {
	case hash := <-started:
		if hash != sameTxs[1].Hash() {
			t.Fatalf("backend after hot release = %s, want successor %s", hash, sameTxs[1].Hash())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("same-sender successor did not start after its predecessor finished")
	}

	first := <-firstDone
	if first.err != nil || len(first.results) != 1 || first.results[0].Hash == nil || *first.results[0].Hash != sameTxs[0].Hash() || first.results[0].Error != "" {
		t.Fatalf("hot predecessor result mismatch: results=%+v err=%v", first.results, first.err)
	}
	second := <-secondDone
	if second.err != nil || len(second.results) != len(request) {
		t.Fatalf("mixed request result count=%d/%d err=%v", len(second.results), len(request), second.err)
	}
	wantTxs := types.Transactions{independentTxs[0], sameTxs[1], independentTxs[1], independentTxs[2]}
	for index, result := range second.results {
		wantError := ""
		if wantTxs[index].Hash() == independentTxs[1].Hash() {
			wantError = wantErr.Error()
		}
		if result.Hash == nil || *result.Hash != wantTxs[index].Hash() || result.Error != wantError {
			t.Fatalf("mixed result %d mismatch: %+v", index, result)
		}
	}
}

func TestSendRawTransactionsAlreadyCancelledDoesNotEnqueue(t *testing.T) {
	raw, _ := signedRawTransactionsForTest(t, 3)
	backend := newLondonAPITestBackend()
	backendCalled := make(chan struct{}, 1)
	backend.sendBatchFn = func(txs types.Transactions) []error {
		backendCalled <- struct{}{}
		return make([]error, len(txs))
	}
	api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, err := api.SendRawTransactions(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(raw) {
		t.Fatalf("cancelled results = %d, want %d", len(results), len(raw))
	}
	for index, result := range results {
		if result.Hash != nil || result.Error != context.Canceled.Error() {
			t.Fatalf("cancelled result %d mismatch: %+v", index, result)
		}
	}
	select {
	case <-backendCalled:
		t.Fatal("already-cancelled batch reached backend")
	case <-time.After(20 * time.Millisecond):
	}
	api.singleRawTxMu.Lock()
	defer api.singleRawTxMu.Unlock()
	if api.singleRawTxPendingCount != 0 || api.singleRawTxPendingBytes != 0 || len(api.rawTxIngressQueue) != 0 || api.rawTxIngressWorkers != 0 {
		t.Fatalf("already-cancelled batch consumed ingress state: count=%d bytes=%d queued=%d workers=%d",
			api.singleRawTxPendingCount, api.singleRawTxPendingBytes, len(api.rawTxIngressQueue), api.rawTxIngressWorkers)
	}
}

func TestSendRawTransactionsRejectsOversizedItemWithoutRejectingNeighbors(t *testing.T) {
	raw, signed := signedRawTransactionsForTest(t, 2)
	inputs := []hexutil.Bytes{raw[0], make([]byte, MaxRawTxBatchBytes+1), raw[1]}
	backend := newLondonAPITestBackend()
	var mu sync.Mutex
	var calls, received int
	backend.sendBatchFn = func(txs types.Transactions) []error {
		mu.Lock()
		calls++
		received += len(txs)
		mu.Unlock()
		return make([]error, len(txs))
	}
	api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
	results, err := api.SendRawTransactions(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 2 || received != 2 {
		t.Fatalf("backend calls=%d received=%d, want 2/2", calls, received)
	}
	if results[0].Hash == nil || *results[0].Hash != signed[0].Hash() || results[0].Error != "" {
		t.Fatalf("first result mismatch: %+v", results[0])
	}
	if results[1].Hash != nil || results[1].Error == "" {
		t.Fatalf("oversized result mismatch: %+v", results[1])
	}
	if results[2].Hash == nil || *results[2].Hash != signed[1].Hash() || results[2].Error != "" {
		t.Fatalf("last result mismatch: %+v", results[2])
	}
}

func TestSendRawTransactionsHandlesBackendResultLengthMismatch(t *testing.T) {
	raw, _ := signedRawTransactionsForTest(t, 2)
	backend := newLondonAPITestBackend()
	backend.sendBatchFn = func(types.Transactions) []error { return []error{nil} }
	api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
	results, err := api.SendRawTransactions(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Error != "" || results[1].Error == "" {
		t.Fatalf("misaligned backend results were not isolated: %+v", results)
	}
}

func TestSendRawTransactionUsesBatchBackendAndPreservesError(t *testing.T) {
	raw, _ := signedRawTransactionsForTest(t, 1)
	want := errors.New("single batch failure")
	backend := newLondonAPITestBackend()
	var calls int
	backend.sendBatchFn = func(txs types.Transactions) []error {
		calls++
		return []error{want}
	}
	api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
	if _, err := api.SendRawTransaction(context.Background(), raw[0]); !errors.Is(err, want) {
		t.Fatalf("single transaction error = %v, want %v", err, want)
	}
	if calls != 1 {
		t.Fatalf("backend calls = %d, want 1", calls)
	}
}

func TestSendRawTransactionWithOptsUsesSharedIngressAndSlowRoute(t *testing.T) {
	raw, signed := signedRawTransactionsForTest(t, 1)
	backend := newLondonAPITestBackend()
	var calls int
	backend.sendBatchFn = func(txs types.Transactions) []error {
		calls++
		if len(txs) != 1 {
			t.Fatalf("backend transactions = %d, want 1", len(txs))
		}
		if got := txs[0].RouteHint(); got != types.TxRouteSlow {
			t.Fatalf("transaction route = %d, want slow", got)
		}
		return []error{nil}
	}
	api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
	api.singleRawTxCoalesceDelay = 0
	hash, err := api.SendRawTransactionWithOpts(context.Background(), raw[0], SendTxOpts{UseSlowLane: true})
	if err != nil {
		t.Fatal(err)
	}
	if hash != signed[0].Hash() || calls != 1 {
		t.Fatalf("with-opts result hash=%s/%s calls=%d, want one shared-ingress backend call", hash, signed[0].Hash(), calls)
	}

	oversized := make(hexutil.Bytes, MaxRawTxBatchBytes+1)
	if _, err := api.SendRawTransactionWithOpts(context.Background(), oversized, SendTxOpts{}); err == nil || !strings.Contains(err.Error(), "per-transaction limit") {
		t.Fatalf("oversized with-opts error = %v, want shared per-transaction limit", err)
	}
	if calls != 1 {
		t.Fatalf("oversized with-opts request reached backend: calls=%d", calls)
	}
}

func TestSendRawTransactionPreservesRealKZGPooledBlobSidecar(t *testing.T) {
	var blob kzg.Blob
	for offset, scalar := 0, byte(1); offset < len(blob); offset, scalar = offset+32, scalar+1 {
		// Keep every field element well below the BLS12-381 modulus.
		blob[offset+31] = scalar
		if scalar == 250 {
			scalar = 0
		}
	}
	commitment, err := kzg.BlobToCommitment(&blob)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := kzg.ComputeBlobProof(&blob, commitment)
	if err != nil {
		t.Fatal(err)
	}
	wireBlob := make(types.Blob, len(blob))
	copy(wireBlob, blob[:])
	var wireCommitment types.KZGCommitment
	copy(wireCommitment[:], commitment[:])
	var wireProof types.KZGProof
	copy(wireProof[:], proof[:])
	sidecar := &types.BlobTxSidecar{
		Blobs: []types.Blob{wireBlob}, Commitments: []types.KZGCommitment{wireCommitment}, Proofs: []types.KZGProof{wireProof},
	}

	backend := newLondonAPITestBackend()
	zeroTime := uint64(0)
	backend.config.ModernForkConfig().CancunTime = &zeroTime
	to := common.HexToAddress("0x4844000000000000000000000000000000000003")
	unsigned := types.NewTx(&types.BlobTx{
		ChainID: backend.config.ChainID, Nonce: 0, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(20),
		Gas: 100_000, To: to, Value: new(big.Int), BlobFeeCap: big.NewInt(2), BlobHashes: sidecar.BlobHashes(),
	}).WithBlobSidecar(sidecar)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := types.SignTx(unsigned, types.NewCancunSigner(backend.config.ChainID), key)
	if err != nil {
		t.Fatal(err)
	}
	pooled, err := signed.MarshalPooledBinary()
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := signed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(pooled, canonical) {
		t.Fatal("pooled type-3 wrapper did not include the sidecar")
	}

	backend.sendBatchFn = func(txs types.Transactions) []error {
		if len(txs) != 1 || txs[0].Type() != types.BlobTxType || txs[0].Hash() != signed.Hash() {
			t.Fatalf("backend transaction = %#v, want one type-3 transaction %s", txs, signed.Hash())
		}
		got := txs[0].BlobSidecar()
		if got == nil || len(got.Blobs) != 1 || !bytes.Equal(got.Blobs[0], sidecar.Blobs[0]) ||
			len(got.Commitments) != 1 || got.Commitments[0] != sidecar.Commitments[0] ||
			len(got.Proofs) != 1 || got.Proofs[0] != sidecar.Proofs[0] {
			t.Fatal("RPC decoder did not preserve the pooled type-3 sidecar through backend batching")
		}
		roundTrip, err := txs[0].MarshalPooledBinary()
		if err != nil || !bytes.Equal(roundTrip, pooled) {
			t.Fatalf("backend pooled envelope round trip mismatch: err=%v", err)
		}
		return []error{nil}
	}
	api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
	api.singleRawTxCoalesceDelay = 0
	hash, err := api.SendRawTransaction(context.Background(), pooled)
	if err != nil {
		t.Fatal(err)
	}
	if hash != signed.Hash() {
		t.Fatalf("submitted pooled blob hash = %s, want %s", hash, signed.Hash())
	}
}

func TestSendRawTransactionPipelinesAdaptiveIndependentSenderWaves(t *testing.T) {
	workerLimit := defaultRawTxBackendWorkers()
	firstRaw, firstTxs := signedIndependentRawTransactionsForTest(t, 1)
	secondRaw, secondTxs := signedIndependentRawTransactionsForTest(t, workerLimit-1)
	wantErr := errors.New("injected adaptive pipeline rejection")
	wantErrByHash := make(map[common.Hash]error, len(secondTxs))
	for index, tx := range secondTxs {
		if index%2 != 0 {
			wantErrByHash[tx.Hash()] = wantErr
		}
	}

	backend := newLondonAPITestBackend()
	backendStarted := make(chan types.Transactions, workerLimit)
	releaseBackend := make(chan struct{})
	backend.sendBatchFn = func(txs types.Transactions) []error {
		backendStarted <- append(types.Transactions(nil), txs...)
		<-releaseBackend
		results := make([]error, len(txs))
		for index, tx := range txs {
			results[index] = wantErrByHash[tx.Hash()]
		}
		return results
	}
	api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
	api.singleRawTxCoalesceDelay = 50 * time.Millisecond

	type callResult struct {
		index int
		hash  common.Hash
		err   error
	}
	firstDone := make(chan callResult, 1)
	go func() {
		hash, err := api.SendRawTransaction(context.Background(), firstRaw[0])
		firstDone <- callResult{hash: hash, err: err}
	}()
	firstBatch := <-backendStarted
	if len(firstBatch) != 1 || firstBatch[0].Hash() != firstTxs[0].Hash() {
		close(releaseBackend)
		t.Fatalf("first backend wave = %v, want transaction %s", firstBatch, firstTxs[0].Hash())
	}

	secondDone := make(chan callResult, len(secondRaw))
	startSecond := make(chan struct{})
	for index := range secondRaw {
		go func(index int) {
			<-startSecond
			hash, err := api.SendRawTransaction(context.Background(), secondRaw[index])
			secondDone <- callResult{index: index, hash: hash, err: err}
		}(index)
	}
	close(startSecond)

	allStarted := true
	startedBatches := []types.Transactions{firstBatch}
	timer := time.NewTimer(2 * time.Second)
	for len(startedBatches) < workerLimit {
		select {
		case batch := <-backendStarted:
			startedBatches = append(startedBatches, batch)
		case <-timer.C:
			allStarted = false
		}
		if !allStarted {
			break
		}
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	close(releaseBackend)

	firstResult := <-firstDone
	secondResults := make([]callResult, len(secondRaw))
	for range secondRaw {
		result := <-secondDone
		secondResults[result.index] = result
	}
	if !allStarted {
		t.Fatalf("backend calls started before releasing the first wave = %d, want %d", len(startedBatches), workerLimit)
	}
	for index, batch := range startedBatches {
		if len(batch) != 1 {
			t.Fatalf("adaptive backend batch %d size = %d, want 1 independent sender", index, len(batch))
		}
	}
	if firstResult.err != nil || firstResult.hash != firstTxs[0].Hash() {
		t.Fatalf("first result = %s/%v, want %s/nil", firstResult.hash, firstResult.err, firstTxs[0].Hash())
	}
	for index, result := range secondResults {
		if wantErrByHash[secondTxs[index].Hash()] != nil {
			if !errors.Is(result.err, wantErr) || result.hash != (common.Hash{}) {
				t.Fatalf("rejected result %d = %s/%v, want zero/%v", index, result.hash, result.err, wantErr)
			}
		} else if result.err != nil || result.hash != secondTxs[index].Hash() {
			t.Fatalf("accepted result %d = %s/%v, want %s/nil", index, result.hash, result.err, secondTxs[index].Hash())
		}
	}

	deadline := time.Now().Add(time.Second)
	for {
		api.singleRawTxMu.Lock()
		idle := !api.singleRawTxWorkerRunning && len(api.singleRawTxQueue) == 0 && len(api.rawTxIngressQueue) == 0 &&
			api.rawTxIngressWorkers == 0 && api.singleRawTxPendingCount == 0 && api.singleRawTxPendingBytes == 0
		api.singleRawTxMu.Unlock()
		if idle {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("adaptive pipeline did not release all pending capacity")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestSendRawTransactionPipelineSerializesSenderAcrossWaves(t *testing.T) {
	sameRaw, sameTxs := signedRawTransactionsForTest(t, 2)
	otherRaw, otherTxs := signedIndependentRawTransactionsForTest(t, 1)
	firstHash := sameTxs[0].Hash()
	nextHash := sameTxs[1].Hash()
	otherHash := otherTxs[0].Hash()

	backend := newLondonAPITestBackend()
	started := make(chan common.Hash, 3)
	releaseFirst := make(chan struct{})
	backend.sendBatchFn = func(txs types.Transactions) []error {
		if len(txs) != 1 {
			t.Fatalf("sender-order backend batch size = %d, want 1", len(txs))
		}
		hash := txs[0].Hash()
		started <- hash
		if hash == firstHash {
			<-releaseFirst
		}
		return []error{nil}
	}
	api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
	api.singleRawTxCoalesceDelay = 100 * time.Millisecond

	type callResult struct {
		hash common.Hash
		err  error
	}
	firstDone := make(chan callResult, 1)
	go func() {
		hash, err := api.SendRawTransaction(context.Background(), sameRaw[0])
		firstDone <- callResult{hash: hash, err: err}
	}()
	if hash := <-started; hash != firstHash {
		close(releaseFirst)
		t.Fatalf("first backend transaction = %s, want %s", hash, firstHash)
	}
	deadline := time.Now().Add(time.Second)
	for {
		api.singleRawTxMu.Lock()
		collectorIdle := !api.singleRawTxWorkerRunning
		api.singleRawTxMu.Unlock()
		if collectorIdle {
			break
		}
		if time.Now().After(deadline) {
			close(releaseFirst)
			t.Fatal("first-wave collector did not become idle")
		}
		time.Sleep(time.Millisecond)
	}

	nextDone := make(chan callResult, 2)
	startNext := make(chan struct{})
	for _, raw := range []hexutil.Bytes{sameRaw[1], otherRaw[0]} {
		raw := raw
		go func() {
			<-startNext
			hash, err := api.SendRawTransaction(context.Background(), raw)
			nextDone <- callResult{hash: hash, err: err}
		}()
	}
	close(startNext)
	if hash := <-started; hash != otherHash {
		close(releaseFirst)
		t.Fatalf("backend bypass while sender busy = %s, want independent %s", hash, otherHash)
	}
	select {
	case hash := <-started:
		close(releaseFirst)
		t.Fatalf("same-sender transaction %s started before predecessor completed", hash)
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseFirst)
	if hash := <-started; hash != nextHash {
		t.Fatalf("backend transaction after predecessor = %s, want %s", hash, nextHash)
	}

	firstResult := <-firstDone
	if firstResult.err != nil || firstResult.hash != firstHash {
		t.Fatalf("first sender result = %s/%v, want %s/nil", firstResult.hash, firstResult.err, firstHash)
	}
	seen := make(map[common.Hash]bool)
	for index := 0; index < 2; index++ {
		result := <-nextDone
		if result.err != nil {
			t.Fatalf("pipelined sender result failed: %v", result.err)
		}
		seen[result.hash] = true
	}
	if !seen[nextHash] || !seen[otherHash] {
		t.Fatalf("pipelined sender results = %v, want %s and %s", seen, nextHash, otherHash)
	}
}

func TestSendRawTransactionCoalescesConcurrentRequests(t *testing.T) {
	const count = MaxRawTxBatchCount + 1
	raw, signed := signedIndependentRawTransactionsForTest(t, count)
	wantBackendErr := errors.New("injected coalesced rejection")
	wantBackendErrByHash := make(map[common.Hash]bool, count)
	for index, tx := range signed {
		if index%17 == 0 {
			wantBackendErrByHash[tx.Hash()] = true
		}
	}
	backend := newLondonAPITestBackend()
	seen := make(map[common.Hash]int, count)
	backendStarted := make(chan struct{}, 2)
	releaseBackend := make(chan struct{})
	var backendMu sync.Mutex
	var backendCalls, received, largestBatch, active, maxActive int
	backend.sendBatchFn = func(txs types.Transactions) []error {
		backendMu.Lock()
		backendCalls++
		received += len(txs)
		active++
		if active > maxActive {
			maxActive = active
		}
		if len(txs) > largestBatch {
			largestBatch = len(txs)
		}
		results := make([]error, len(txs))
		for index, tx := range txs {
			seen[tx.Hash()]++
			if wantBackendErrByHash[tx.Hash()] {
				results[index] = wantBackendErr
			}
		}
		backendMu.Unlock()
		backendStarted <- struct{}{}
		<-releaseBackend
		backendMu.Lock()
		active--
		backendMu.Unlock()
		return results
	}
	api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
	// Production remains at 2ms; a wider deterministic test window separates
	// scheduler variance from the batching invariant exercised here.
	api.singleRawTxCoalesceDelay = time.Second

	start := make(chan struct{})
	errs := make([]error, count)
	hashes := make([]common.Hash, count)
	var callers sync.WaitGroup
	callers.Add(count)
	for index := range raw {
		go func(index int) {
			defer callers.Done()
			<-start
			hashes[index], errs[index] = api.SendRawTransaction(context.Background(), raw[index])
		}(index)
	}
	close(start)
	for index := 0; index < 2; index++ {
		select {
		case <-backendStarted:
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d/2 coalesced backend calls started", index)
		}
	}
	backendMu.Lock()
	if backendCalls != 2 || active != 2 || maxActive != 2 {
		t.Fatalf("coalesced backend concurrency calls=%d active=%d max=%d, want 2", backendCalls, active, maxActive)
	}
	backendMu.Unlock()
	close(releaseBackend)
	callers.Wait()

	backendMu.Lock()
	defer backendMu.Unlock()
	if backendCalls != 2 {
		t.Fatalf("backend calls = %d, want 2 bounded micro-batches", backendCalls)
	}
	if received != count || largestBatch > MaxRawTxBatchCount {
		t.Fatalf("backend received=%d largestBatch=%d, want %d and <=%d", received, largestBatch, count, MaxRawTxBatchCount)
	}
	for index, tx := range signed {
		if seen[tx.Hash()] != 1 {
			t.Fatalf("transaction %d backend submissions = %d, want 1", index, seen[tx.Hash()])
		}
		if wantBackendErrByHash[tx.Hash()] {
			if !errors.Is(errs[index], wantBackendErr) || hashes[index] != (common.Hash{}) {
				t.Fatalf("transaction %d rejection mismatch: hash=%s err=%v", index, hashes[index], errs[index])
			}
		} else if errs[index] != nil || hashes[index] != tx.Hash() {
			t.Fatalf("transaction %d result mismatch: hash=%s/%s err=%v", index, hashes[index], tx.Hash(), errs[index])
		}
	}
}

func TestSendRawTransactionCancellationDoesNotCancelAcceptedSubmission(t *testing.T) {
	raw, signed := signedRawTransactionsForTest(t, 2)
	backend := newLondonAPITestBackend()
	backendStarted := make(chan struct{})
	releaseBackend := make(chan struct{})
	backendDone := make(chan struct{})
	var backendCalls int
	backend.sendBatchFn = func(txs types.Transactions) []error {
		backendCalls++
		if len(txs) != 2 {
			t.Errorf("unexpected durable submission: %+v", txs)
		} else {
			got := map[common.Hash]bool{txs[0].Hash(): true, txs[1].Hash(): true}
			if !got[signed[0].Hash()] || !got[signed[1].Hash()] {
				t.Errorf("durable submission hashes do not match callers: %+v", txs)
			}
		}
		close(backendStarted)
		<-releaseBackend
		close(backendDone)
		return make([]error, len(txs))
	}
	api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
	api.singleRawTxCoalesceDelay = 100 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	canceledCallerDone := make(chan error, 1)
	continuingCallerDone := make(chan struct {
		hash common.Hash
		err  error
	}, 1)
	start := make(chan struct{})
	go func() {
		<-start
		_, err := api.SendRawTransaction(ctx, raw[0])
		canceledCallerDone <- err
	}()
	go func() {
		<-start
		hash, err := api.SendRawTransaction(context.Background(), raw[1])
		continuingCallerDone <- struct {
			hash common.Hash
			err  error
		}{hash: hash, err: err}
	}()
	close(start)
	<-backendStarted
	cancel()
	if err := <-canceledCallerDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled caller error = %v, want %v", err, context.Canceled)
	}
	close(releaseBackend)
	<-backendDone
	continuing := <-continuingCallerDone
	if continuing.err != nil || continuing.hash != signed[1].Hash() {
		t.Fatalf("uncanceled caller result = %s/%v, want %s/nil", continuing.hash, continuing.err, signed[1].Hash())
	}

	deadline := time.Now().Add(time.Second)
	for {
		api.singleRawTxMu.Lock()
		idle := !api.singleRawTxWorkerRunning && api.singleRawTxPendingCount == 0 && api.singleRawTxPendingBytes == 0
		api.singleRawTxMu.Unlock()
		if idle {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("single transaction worker did not become idle")
		}
		time.Sleep(time.Millisecond)
	}
	if backendCalls != 1 {
		t.Fatalf("backend calls = %d, want exactly one after caller cancellation", backendCalls)
	}
}

func TestSendRawTransactionAlreadyCancelledDoesNotEnqueue(t *testing.T) {
	raw, _ := signedRawTransactionsForTest(t, 1)
	backend := newLondonAPITestBackend()
	backendCalled := make(chan struct{}, 1)
	backend.sendBatchFn = func(txs types.Transactions) []error {
		backendCalled <- struct{}{}
		return make([]error, len(txs))
	}
	api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	hash, err := api.SendRawTransaction(ctx, raw[0])
	if !errors.Is(err, context.Canceled) || hash != (common.Hash{}) {
		t.Fatalf("already-cancelled submission = %s/%v, want zero/%v", hash, err, context.Canceled)
	}
	select {
	case <-backendCalled:
		t.Fatal("already-cancelled submission reached the backend")
	case <-time.After(20 * time.Millisecond):
	}
	api.singleRawTxMu.Lock()
	defer api.singleRawTxMu.Unlock()
	if api.singleRawTxWorkerRunning || len(api.singleRawTxQueue) != 0 || api.singleRawTxPendingCount != 0 || api.singleRawTxPendingBytes != 0 {
		t.Fatalf("already-cancelled submission consumed queue state: running=%t queued=%d count=%d bytes=%d",
			api.singleRawTxWorkerRunning, len(api.singleRawTxQueue), api.singleRawTxPendingCount, api.singleRawTxPendingBytes)
	}
}

func TestSendRawTransactionQueueBoundsIncludeInflightWork(t *testing.T) {
	raw, _ := signedRawTransactionsForTest(t, 2)
	tests := []struct {
		name      string
		configure func(*PublicTransactionPoolAPI)
		wantError string
	}{
		{
			name: "count",
			configure: func(api *PublicTransactionPoolAPI) {
				api.singleRawTxQueueCountLimit = 1
			},
			wantError: "queue count exceeds limit",
		},
		{
			name: "bytes",
			configure: func(api *PublicTransactionPoolAPI) {
				api.singleRawTxQueueCountLimit = 2
				api.singleRawTxQueueBytesLimit = len(raw[0]) + len(raw[1]) - 1
			},
			wantError: "queue bytes exceed limit",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := newLondonAPITestBackend()
			backendStarted := make(chan struct{})
			releaseBackend := make(chan struct{})
			var backendCalls int
			backend.sendBatchFn = func(txs types.Transactions) []error {
				backendCalls++
				close(backendStarted)
				<-releaseBackend
				return make([]error, len(txs))
			}
			api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
			api.singleRawTxCoalesceDelay = 0
			test.configure(api)

			firstDone := make(chan error, 1)
			go func() {
				_, err := api.SendRawTransaction(context.Background(), raw[0])
				firstDone <- err
			}()
			<-backendStarted
			if _, err := api.SendRawTransaction(context.Background(), raw[1]); err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("second request error = %v, want %q", err, test.wantError)
			}
			close(releaseBackend)
			if err := <-firstDone; err != nil {
				t.Fatalf("first request failed: %v", err)
			}
			if backendCalls != 1 {
				t.Fatalf("backend calls = %d, want 1", backendCalls)
			}
		})
	}
}

func TestSendRawTransactionsRejectsOversizedSignatureIntegerBeforeBackend(t *testing.T) {
	backend := newLondonAPITestBackend()
	var calls int
	backend.sendBatchFn = func(txs types.Transactions) []error {
		calls++
		return make([]error, len(txs))
	}
	to := common.HexToAddress("0x1000000000000000000000000000000000000001")
	oversizedV := new(big.Int).Lsh(big.NewInt(1), 1<<20)
	raw, err := rlp.EncodeToBytes([]interface{}{
		uint64(0), big.NewInt(1), uint64(21_000), to, big.NewInt(0), []byte(nil),
		oversizedV, big.NewInt(1), big.NewInt(1),
	})
	if err != nil {
		t.Fatal(err)
	}
	api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
	results, err := api.SendRawTransactions(context.Background(), []hexutil.Bytes{raw})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("backend calls = %d, want 0", calls)
	}
	if len(results) != 1 || results[0].Hash != nil || results[0].Error == "" {
		t.Fatalf("unexpected oversized-signature result: %+v", results)
	}
	if _, err := api.SendRawTransactionWithOpts(context.Background(), raw, SendTxOpts{}); !errors.Is(err, types.ErrTxIntegerOutOfRange) {
		t.Fatalf("with-opts oversized-signature error = %v, want cheap %v rejection", err, types.ErrTxIntegerOutOfRange)
	}
	if calls != 0 {
		t.Fatalf("with-opts oversized signature reached backend: calls=%d", calls)
	}
}

func TestPrivateSignTransactionReturnsCanonicalTypedEnvelope(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	const password = "typed-envelope-test"
	ks := keystore.NewKeyStore(t.TempDir(), keystore.LightScryptN, keystore.LightScryptP)
	account, err := ks.ImportECDSA(key, password)
	if err != nil {
		t.Fatal(err)
	}
	manager := accounts.NewManager(&accounts.Config{InsecureUnlockAllowed: true}, ks)
	t.Cleanup(func() { _ = manager.Close() })
	backend := newLondonAPITestBackend()
	backend.am = manager
	api := NewPrivateAccountAPI(backend, new(AddrLocker))

	to := common.HexToAddress("0x1000000000000000000000000000000000000001")
	txType := hexutil.Uint64(types.DynamicFeeTxType)
	nonce := hexutil.Uint64(0)
	gas := hexutil.Uint64(50_000)
	feeCap := (*hexutil.Big)(big.NewInt(20))
	tipCap := (*hexutil.Big)(big.NewInt(2))
	input := hexutil.Bytes{0x00}
	result, err := api.SignTransaction(context.Background(), SendTxArgs{
		From: account.Address, To: &to, Type: &txType, Nonce: &nonce, Gas: &gas,
		MaxFeePerGas: feeCap, MaxPriorityFeePerGas: tipCap, Input: &input,
	}, password)
	if err != nil {
		t.Fatal(err)
	}
	want, err := result.Tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.Raw, want) || len(result.Raw) == 0 || result.Raw[0] != types.DynamicFeeTxType {
		t.Fatalf("personal_signTransaction raw = %x, want canonical type-2 envelope %x", result.Raw, want)
	}
	var decoded types.Transaction
	if err := decoded.UnmarshalBinary(result.Raw); err != nil {
		t.Fatalf("canonical personal_signTransaction raw is not accepted by eth_sendRawTransaction decoder: %v", err)
	}
	if decoded.Hash() != result.Tx.Hash() {
		t.Fatalf("decoded hash = %s, want %s", decoded.Hash(), result.Tx.Hash())
	}
}
