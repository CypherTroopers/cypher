package core

import (
	"crypto/ecdsa"
	"math/big"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/params"
)

func signedPoolTx(t *testing.T, nonce uint64, key *ecdsa.PrivateKey) *types.Transaction {
	t.Helper()
	return signedPoolTxWithGasPrice(t, nonce, key, big.NewInt(1))
}

func signedPoolTxWithGasPrice(t *testing.T, nonce uint64, key *ecdsa.PrivateKey, gasPrice *big.Int) *types.Transaction {
	t.Helper()

	to := common.HexToAddress("0x1000000000000000000000000000000000000001")
	tx := types.NewTransaction(nonce, to, big.NewInt(0), 21000, gasPrice, nil)
	signed, err := types.SignTx(tx, types.NewEIP155Signer(big.NewInt(1)), key)
	if err != nil {
		t.Fatalf("failed to sign tx: %v", err)
	}
	return signed
}

type txPoolPriceTestChain struct {
	block *types.Block
}

func (c txPoolPriceTestChain) CurrentBlock() *types.Block                  { return c.block }
func (c txPoolPriceTestChain) GetBlock(common.Hash, uint64) *types.Block   { return nil }
func (c txPoolPriceTestChain) StateAt(common.Hash) (*state.StateDB, error) { return nil, nil }
func (c txPoolPriceTestChain) SubscribeChainHeadEvent(chan<- ChainHeadEvent) event.Subscription {
	return nil
}

func TestDefaultTxPoolPriceLimitIsOneGWei(t *testing.T) {
	if DefaultTxPoolConfig.PriceLimit != params.GWei {
		t.Fatalf("default txpool price limit mismatch: got %d want %d", DefaultTxPoolConfig.PriceLimit, uint64(params.GWei))
	}
}

func TestValidateTxAppliesPriceLimitToLocals(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	addr := crypto.PubkeyToAddress(key.PublicKey)
	statedb, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	statedb.SetBalance(addr, new(big.Int).Mul(big.NewInt(100), big.NewInt(params.Ether)))

	pool := &TxPool{
		chain:         txPoolPriceTestChain{block: types.NewBlockWithHeader(&types.Header{BaseFee: big.NewInt(1)})},
		chainconfig:   &params.ChainConfig{ChainID: big.NewInt(1)},
		signer:        types.NewEIP155Signer(big.NewInt(1)),
		currentState:  statedb,
		currentMaxGas: 30_000_000,
		gasPrice:      new(big.Int).SetUint64(DefaultTxPoolConfig.PriceLimit),
	}
	tx := signedPoolTxWithGasPrice(t, 0, key, big.NewInt(params.GWei-1))

	if err := pool.validateTx(tx, true); err != ErrUnderpriced {
		t.Fatalf("expected local tx below price limit to be underpriced, got %v", err)
	}
}

func TestPricedListCapAppliesPriceLimitToLocals(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	addr := crypto.PubkeyToAddress(key.PublicKey)
	underpriced := signedPoolTxWithGasPrice(t, 0, key, big.NewInt(params.GWei-1))

	all := newTxLookup()
	priced := newTxPricedList(all)
	locals := newAccountSet(types.NewEIP155Signer(big.NewInt(1)), addr)

	all.Add(underpriced, true)
	priced.Put(underpriced)

	dropped := priced.Cap(new(big.Int).SetUint64(DefaultTxPoolConfig.PriceLimit), locals)
	if len(dropped) != 1 || dropped[0].Hash() != underpriced.Hash() {
		t.Fatalf("expected local tx below price limit to be dropped, got %d", len(dropped))
	}
}

func TestTruncatePendingAppliesAccountSlotsToLocals(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	addr := crypto.PubkeyToAddress(key.PublicKey)

	pool := &TxPool{
		config:        TxPoolConfig{AccountSlots: 1, GlobalSlots: 2},
		pending:       map[common.Address]*txList{addr: newTxList(true)},
		locals:        newAccountSet(types.NewEIP155Signer(big.NewInt(1)), addr),
		all:           newTxLookup(),
		pendingNonces: &txNoncer{nonces: map[common.Address]uint64{addr: 3}},
	}
	pool.priced = newTxPricedList(pool.all)

	var txs types.Transactions
	for nonce := uint64(0); nonce < 3; nonce++ {
		tx := signedPoolTx(t, nonce, key)
		txs = append(txs, tx)
		pool.pending[addr].Add(tx, pool.config.PriceBump)
		pool.all.Add(tx, true)
		pool.priced.Put(tx)
	}

	pool.truncatePending()

	if got := pool.pending[addr].Len(); got != 2 {
		t.Fatalf("local pending account was not truncated: got %d txs, want 2", got)
	}
	if pool.all.Get(txs[2].Hash()) != nil {
		t.Fatalf("expected cap-exceeding local pending transaction to be removed")
	}
}

func TestEvictStaleTransactionsAppliesLifetimesToLocals(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	addr := crypto.PubkeyToAddress(key.PublicKey)

	pendingTx := signedPoolTx(t, 0, key)
	queuedTx := signedPoolTx(t, 1, key)
	now := time.Now()

	pool := &TxPool{
		config: TxPoolConfig{
			FastPendingLifetime: time.Second,
			FastQueuedLifetime:  time.Second,
		},
		signer:  types.NewEIP155Signer(big.NewInt(1)),
		pending: map[common.Address]*txList{addr: newTxList(true)},
		queue:   map[common.Address]*txList{addr: newTxList(false)},
		locals:        newAccountSet(types.NewEIP155Signer(big.NewInt(1)), addr),
		all:           newTxLookup(),
		pendingNonces: &txNoncer{nonces: map[common.Address]uint64{addr: 2}},
		seen: map[common.Hash]time.Time{
			pendingTx.Hash(): now.Add(-2 * time.Second),
			queuedTx.Hash():  now.Add(-2 * time.Second),
		},
	}
	pool.priced = newTxPricedList(pool.all)
	pool.pending[addr].Add(pendingTx, pool.config.PriceBump)
	pool.queue[addr].Add(queuedTx, pool.config.PriceBump)
	for _, tx := range []*types.Transaction{pendingTx, queuedTx} {
		pool.all.Add(tx, true)
		pool.priced.Put(tx)
	}

	pool.evictStaleTransactionsLocked(now)

	if pool.all.Get(pendingTx.Hash()) != nil {
		t.Fatalf("expected stale local pending transaction to be evicted")
	}
	if pool.all.Get(queuedTx.Hash()) != nil {
		t.Fatalf("expected stale local queued transaction to be evicted")
	}
}

func TestTruncateQueueAppliesGlobalQueueToLocals(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	addr := crypto.PubkeyToAddress(key.PublicKey)

	pool := &TxPool{
		config: TxPoolConfig{GlobalQueue: 2},
		signer: types.NewEIP155Signer(big.NewInt(1)),
		queue:  map[common.Address]*txList{addr: newTxList(false)},
		beats:  map[common.Address]time.Time{addr: time.Now()},
		locals: newAccountSet(types.NewEIP155Signer(big.NewInt(1)), addr),
		all:    newTxLookup(),
	}
	pool.priced = newTxPricedList(pool.all)

	var txs types.Transactions
	for nonce := uint64(0); nonce < 3; nonce++ {
		tx := signedPoolTx(t, nonce, key)
		txs = append(txs, tx)
		pool.queue[addr].Add(tx, pool.config.PriceBump)
		pool.all.Add(tx, true)
		pool.priced.Put(tx)
	}

	pool.truncateQueue()

	if got := pool.queue[addr].Len(); got != 2 {
		t.Fatalf("local queue was not truncated: got %d txs, want 2", got)
	}
	if pool.all.Get(txs[2].Hash()) != nil {
		t.Fatalf("expected cap-exceeding local queued transaction to be removed")
	}
}
