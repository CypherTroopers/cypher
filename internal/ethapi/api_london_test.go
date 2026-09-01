package ethapi

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cypherium/cypher/accounts"
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
	var blobHash common.Hash
	blobHash[0] = types.BlobCommitmentVersionKZG
	blob := SendTxArgs{
		From: to, To: &to, Gas: &gas, Nonce: &nonce, Type: &blobType,
		MaxFeePerGas: feeCap, MaxPriorityFeePerGas: tipCap, AccessList: &modernAccessList,
		MaxFeePerBlobGas: blobFeeCap, BlobVersionedHashes: []common.Hash{blobHash},
	}
	if err := blob.setDefaults(ctx, backend); err != nil {
		t.Fatalf("blob defaults failed: %v", err)
	}
	blobTx := blob.toTransaction(backend.config.ChainID)
	if blobTx.Type() != types.BlobTxType || blobTx.BlobGasFeeCap().Cmp(big.NewInt(7)) != 0 || len(blobTx.BlobHashes()) != 1 {
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
	raw, signed := signedRawTransactionsForTest(t, count)
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
	raw, signed := signedRawTransactionsForTest(t, count)
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
	type rpcResult struct {
		results []RawTxResult
		err     error
	}
	finished := make(chan rpcResult, 1)
	go func() {
		results, err := api.SendRawTransactions(context.Background(), raw)
		finished <- rpcResult{results: results, err: err}
	}()
	for index := 0; index < rawTxBackendParallelism; index++ {
		select {
		case <-started:
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d/%d backend workers started", index, rawTxBackendParallelism)
		}
	}
	mu.Lock()
	if calls != rawTxBackendParallelism || active != rawTxBackendParallelism || maxActive != rawTxBackendParallelism {
		t.Fatalf("initial backend concurrency calls=%d active=%d max=%d, want %d", calls, active, maxActive, rawTxBackendParallelism)
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
	if calls != wantCalls || received != count || maxActive > rawTxBackendParallelism || len(results) != count {
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

func TestSendRawTransactionsCancellationStopsUnacceptedMicroBatches(t *testing.T) {
	const count = rawTxBackendParallelism*MaxRawTxBatchCount + 17
	raw, signed := signedRawTransactionsForTest(t, count)
	backend := newLondonAPITestBackend()
	started := make(chan struct{}, rawTxBackendParallelism+1)
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
	for index := 0; index < rawTxBackendParallelism; index++ {
		select {
		case <-started:
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d/%d backend workers started", index, rawTxBackendParallelism)
		}
	}
	cancel()
	// All workers are occupied, so the unbuffered ninth handoff must observe
	// cancellation rather than accepting more node-side durable work.
	select {
	case <-started:
		t.Fatal("backend accepted a micro-batch after request cancellation")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	response := <-finished
	if response.err != nil {
		t.Fatal(response.err)
	}
	mu.Lock()
	if calls != rawTxBackendParallelism || active != 0 {
		t.Fatalf("backend calls=%d active=%d, want %d/0", calls, active, rawTxBackendParallelism)
	}
	mu.Unlock()
	if len(response.results) != count {
		t.Fatalf("results=%d, want %d", len(response.results), count)
	}
	accepted := rawTxBackendParallelism * MaxRawTxBatchCount
	for index, result := range response.results {
		if index < accepted {
			if result.Hash == nil || *result.Hash != signed[index].Hash() || result.Error != "" {
				t.Fatalf("accepted result %d mismatch: %+v", index, result)
			}
			continue
		}
		if result.Hash != nil || result.Error != context.Canceled.Error() {
			t.Fatalf("unscheduled result %d mismatch: %+v", index, result)
		}
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

func TestSendRawTransactionCoalescesConcurrentRequests(t *testing.T) {
	const count = MaxRawTxBatchCount + 1
	raw, signed := signedRawTransactionsForTest(t, count)
	wantBackendErr := errors.New("injected coalesced rejection")
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
			if tx.Nonce()%17 == 0 {
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
		if tx.Nonce()%17 == 0 {
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
	if len(results) != 1 || results[0].Hash == nil || results[0].Error == "" {
		t.Fatalf("unexpected oversized-signature result: %+v", results)
	}
}
