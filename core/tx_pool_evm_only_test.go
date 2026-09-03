package core

import (
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/params"
)

// nativePoolTestTx exists only to construct retired type-5 inputs for negative
// boundary tests. No test in this file treats NativeTxV1 as valid consensus
// traffic.
func nativePoolTestTx(payer common.Address, priority int64, recentHash common.Hash, recent, validUntil uint64, tag byte) *types.Transaction {
	return types.NewTx(&types.NativeTxV1{
		ChainID:               big.NewInt(1),
		RecentBlockHash:       recentHash,
		RecentBlockNumber:     recent,
		ValidUntil:            validUntil,
		Payer:                 payer,
		ReplaySequence:        uint64(tag),
		To:                    payer,
		Value:                 new(big.Int),
		Data:                  []byte{tag},
		MaxFeePerCompute:      big.NewInt(1_000_000),
		PriorityFeePerCompute: big.NewInt(priority),
		ComputeLimit:          100_000,
		MemoryLimit:           1024,
		LogLimit:              1024,
		OutputLimit:           1024,
		Accesses: []types.NativeAccess{{
			Resource: types.NativeResource{Kind: types.NativeResourceAccount, Address: payer},
			Mode:     types.NativeAccessWrite,
		}},
		V: new(big.Int), R: new(big.Int), S: new(big.Int),
	})
}

func evmOnlyNativePoolTestConfig(t *testing.T) *params.ChainConfig {
	t.Helper()
	config := &params.ChainConfig{
		ChainID:        big.NewInt(1),
		FairHotstuff:   true,
		NativeParallel: params.SolanaScaleEVMParallelConfig(),
	}
	zero := uint64(0)
	config.SetModernForkConfig(&params.ModernForkConfig{
		BerlinBlock:  big.NewInt(0),
		LondonBlock:  big.NewInt(0),
		ShanghaiTime: &zero,
		CancunTime:   &zero,
		PragueTime:   &zero,
	})
	t.Cleanup(func() { config.SetModernForkConfig(nil) })
	return config
}

type evmPoolTestChain struct {
	mu     sync.RWMutex
	head   *types.Block
	blocks map[common.Hash]*types.Block
	state  *state.StateDB
}

func (c *evmPoolTestChain) CurrentBlock() *types.Block {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.head
}

func (c *evmPoolTestChain) GetBlock(hash common.Hash, number uint64) *types.Block {
	c.mu.RLock()
	defer c.mu.RUnlock()
	block := c.blocks[hash]
	if block == nil || block.NumberU64() != number {
		return nil
	}
	return block
}

func (c *evmPoolTestChain) StateAt(common.Hash) (*state.StateDB, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state.Copy(), nil
}

func (c *evmPoolTestChain) SubscribeChainHeadEvent(chan<- ChainHeadEvent) event.Subscription {
	return event.NewSubscription(func(quit <-chan struct{}) error {
		<-quit
		return nil
	})
}

func newNativePoolTestChain(t *testing.T, payer common.Address) (*evmPoolTestChain, []*types.Block) {
	t.Helper()
	statedb, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	statedb.SetBalance(payer, new(big.Int).Exp(big.NewInt(10), big.NewInt(30), nil))
	root, err := statedb.Commit(false)
	if err != nil {
		t.Fatal(err)
	}
	statedb, err = state.New(root, statedb.Database(), nil)
	if err != nil {
		t.Fatal(err)
	}
	chain := &evmPoolTestChain{blocks: make(map[common.Hash]*types.Block), state: statedb}
	blocks := make([]*types.Block, 6)
	parent := common.Hash{}
	for number := uint64(0); number < uint64(len(blocks)); number++ {
		header := &types.Header{
			ParentHash: parent,
			Number:     new(big.Int).SetUint64(number),
			Root:       root,
			GasLimit:   30_000_000,
			BaseFee:    big.NewInt(1),
			Extra:      []byte{byte(number)},
		}
		blocks[number] = types.NewBlockWithHeader(header)
		chain.blocks[blocks[number].Hash()] = blocks[number]
		parent = blocks[number].Hash()
	}
	chain.head = blocks[len(blocks)-1]
	return chain, blocks
}

func TestTxPoolEVMOnlyAcceptsTypesZeroOneTwoAndFourAndRejectsTypeFive(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	payer := crypto.PubkeyToAddress(key.PublicKey)
	chain, blocks := newNativePoolTestChain(t, payer)
	poolConfig := DefaultTxPoolConfig
	poolConfig.NoLocals = true
	poolConfig.Journal = ""
	poolConfig.PriceLimit = 1
	chainConfig := evmOnlyNativePoolTestConfig(t)
	pool := NewTxPool(poolConfig, chainConfig, chain)
	t.Cleanup(pool.Stop)

	sign := func(tx *types.Transaction, signer types.Signer) *types.Transaction {
		t.Helper()
		signed, signErr := types.SignTx(tx, signer, key)
		if signErr != nil {
			t.Fatal(signErr)
		}
		return signed
	}
	chainID := chainConfig.ChainID
	legacy := sign(types.NewTransaction(0, payer, new(big.Int), params.TxGas, big.NewInt(2), nil), types.NewEIP155Signer(chainID))
	accessList := sign(types.NewTx(&types.AccessListTx{
		ChainID: chainID, Nonce: 1, GasPrice: big.NewInt(2), Gas: params.TxGas,
		To: &payer, Value: new(big.Int),
	}), types.NewEIP2930Signer(chainID))
	dynamicFee := sign(types.NewTx(&types.DynamicFeeTx{
		ChainID: chainID, Nonce: 2, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2),
		Gas: params.TxGas, To: &payer, Value: new(big.Int),
	}), types.NewLondonSigner(chainID))
	authorization, err := types.SignSetCode(key, types.SetCodeAuthorization{
		ChainID: chainID,
		Address: common.HexToAddress("0x7702"),
	})
	if err != nil {
		t.Fatal(err)
	}
	setCode := sign(types.NewTx(&types.SetCodeTx{
		ChainID: chainID, Nonce: 3, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2),
		Gas: 100_000, To: payer, Value: new(big.Int), AuthList: []types.SetCodeAuthorization{authorization},
	}), types.NewPragueSigner(chainID))
	reservedAddress := sign(types.NewTransaction(4, params.NativeReplayRegistryAddress, new(big.Int), params.TxGas, big.NewInt(2), nil), types.NewEIP155Signer(chainID))
	slowLegacy := sign(types.NewTransaction(5, payer, new(big.Int), 400_000, big.NewInt(2), nil), types.NewEIP155Signer(chainID))
	standard := types.Transactions{legacy, accessList, dynamicFee, setCode, reservedAddress, slowLegacy}
	if errs := pool.AddRemotesSync(standard); len(errs) != len(standard) {
		t.Fatalf("EVM-only standard admission returned %d results, want %d: %v", len(errs), len(standard), errs)
	} else {
		for index, err := range errs {
			if err != nil {
				t.Fatalf("EVM-only type 0x%02x admission failed at index %d: %v", standard[index].Type(), index, err)
			}
			if pool.Get(standard[index].Hash()) == nil {
				t.Fatalf("accepted EVM-only type 0x%02x is absent from pool", standard[index].Type())
			}
		}
	}

	unsignedNative := nativePoolTestTx(payer, 3, blocks[5].Hash(), 5, 9, 7)
	native, err := types.SignTx(unsignedNative, types.NewNativeSigner(chainID), key)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.AddRemote(native); !errors.Is(err, ErrNativeTxDisabled) {
		t.Fatalf("EVM-only type-5 admission error = %v, want %v", err, ErrNativeTxDisabled)
	}
	if pool.Get(native.Hash()) != nil {
		t.Fatal("EVM-only pool retained rejected type-5 transaction")
	}

	limits := params.FairHotstuffEVMWorkLimitsForConfig(chainConfig)
	overAccess := sign(types.NewTx(&types.AccessListTx{
		ChainID: chainID, Nonce: 6, GasPrice: big.NewInt(2), Gas: 4_000_000,
		To: &payer, Value: new(big.Int), AccessList: make(types.AccessList, limits.AccessListAddressesPerTx+1),
	}), types.NewEIP2930Signer(chainID))
	overStorageKeys := sign(types.NewTx(&types.AccessListTx{
		ChainID: chainID, Nonce: 6, GasPrice: big.NewInt(2), Gas: 4_000_000,
		To: &payer, Value: new(big.Int), AccessList: types.AccessList{{StorageKeys: make([]common.Hash, limits.AccessListStorageKeysPerTx+1)}},
	}), types.NewEIP2930Signer(chainID))
	overAuthorizations := sign(types.NewTx(&types.SetCodeTx{
		ChainID: chainID, Nonce: 6, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2), Gas: 4_000_000,
		To: payer, Value: new(big.Int), AuthList: make([]types.SetCodeAuthorization, limits.SetCodeAuthorizationsPerTx+1),
	}), types.NewPragueSigner(chainID))
	unproposable := types.Transactions{overAccess, overStorageKeys, overAuthorizations}
	for _, tx := range unproposable {
		if err := pool.AddRemote(tx); !errors.Is(err, ErrFHSPerTransactionWorkLimit) {
			t.Fatalf("unproposable EVM type 0x%02x admission error = %v, want %v", tx.Type(), err, ErrFHSPerTransactionWorkLimit)
		}
		if pool.Get(tx.Hash()) != nil {
			t.Fatalf("pool retained unproposable EVM type 0x%02x", tx.Type())
		}
	}

	fastPending, slowPending, _ := pool.PendingClassStats()
	if fastPending != 5 || slowPending != 1 {
		t.Fatalf("EVM-only resource lane counts = fast %d slow %d, want 5/1", fastPending, slowPending)
	}
}
