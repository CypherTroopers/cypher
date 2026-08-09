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
	"github.com/cypherium/cypher/core/rawdb"
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
