package core

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
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
	state *state.StateDB
}

func (c txPoolPriceTestChain) CurrentBlock() *types.Block                { return c.block }
func (c txPoolPriceTestChain) GetBlock(common.Hash, uint64) *types.Block { return nil }
func (c txPoolPriceTestChain) StateAt(common.Hash) (*state.StateDB, error) {
	if c.state == nil {
		return nil, nil
	}
	return c.state.Copy(), nil
}
func (c txPoolPriceTestChain) SubscribeChainHeadEvent(chan<- ChainHeadEvent) event.Subscription {
	return nil
}

type txPoolValidationSnapshotTestChain struct {
	block *types.Block
	db    state.Database

	stateAtEntered chan<- struct{}
	stateAtRelease <-chan struct{}
	stateAtOnce    sync.Once

	mu        sync.Mutex
	roots     []common.Hash
	snapshots map[*state.StateDB]struct{}
}

func (c *txPoolValidationSnapshotTestChain) CurrentBlock() *types.Block { return c.block }
func (c *txPoolValidationSnapshotTestChain) GetBlock(common.Hash, uint64) *types.Block {
	return nil
}
func (c *txPoolValidationSnapshotTestChain) StateAt(root common.Hash) (*state.StateDB, error) {
	if c.stateAtEntered != nil {
		c.stateAtOnce.Do(func() { c.stateAtEntered <- struct{}{} })
	}
	if c.stateAtRelease != nil {
		<-c.stateAtRelease
	}
	snapshot, err := state.New(root, c.db, nil)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.roots = append(c.roots, root)
	c.snapshots[snapshot] = struct{}{}
	c.mu.Unlock()
	return snapshot, nil
}

func (c *txPoolValidationSnapshotTestChain) SubscribeChainHeadEvent(chan<- ChainHeadEvent) event.Subscription {
	return nil
}

func TestValidateLocalsDoesNotHoldPoolLockWhileOpeningState(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr := crypto.PubkeyToAddress(key.PublicKey)
	db := state.NewDatabase(rawdb.NewMemoryDatabase())
	statedb, err := state.New(common.Hash{}, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	statedb.SetBalance(addr, new(big.Int).Mul(big.NewInt(100), big.NewInt(params.Ether)))
	root, err := statedb.Commit(false)
	if err != nil {
		t.Fatal(err)
	}
	currentState, err := state.New(root, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	header := &types.Header{Number: big.NewInt(0), Root: root, GasLimit: 30_000_000, BaseFee: big.NewInt(1)}
	stateAtEntered := make(chan struct{}, 1)
	stateAtRelease := make(chan struct{})
	chain := &txPoolValidationSnapshotTestChain{
		block:          types.NewBlockWithHeader(header),
		db:             db,
		snapshots:      make(map[*state.StateDB]struct{}),
		stateAtEntered: stateAtEntered,
		stateAtRelease: stateAtRelease,
	}
	config := DefaultTxPoolConfig
	config.NoLocals = false
	pool := &TxPool{
		config:           config,
		chainconfig:      &params.ChainConfig{ChainID: big.NewInt(1)},
		chain:            chain,
		gasPrice:         new(big.Int).SetUint64(params.GWei),
		signer:           types.NewEIP155Signer(big.NewInt(1)),
		currentState:     currentState,
		currentStateRoot: root,
		pendingNonces:    newTxNoncer(currentState),
		currentMaxGas:    header.GasLimit,
		locals:           newAccountSet(types.NewEIP155Signer(big.NewInt(1))),
		all:              newTxLookup(),
	}
	tx := signedPoolTxWithGasPrice(t, 0, key, big.NewInt(params.GWei))

	validationDone := make(chan []error, 1)
	go func() {
		validationDone <- pool.ValidateLocals(types.Transactions{tx})
	}()
	select {
	case <-stateAtEntered:
	case <-time.After(5 * time.Second):
		close(stateAtRelease)
		t.Fatal("ValidateLocals did not start opening its state snapshot")
	}

	lockAcquired := make(chan struct{})
	go func() {
		pool.mu.Lock()
		pool.mu.Unlock()
		close(lockAcquired)
	}()
	select {
	case <-lockAcquired:
		close(stateAtRelease)
	case <-time.After(time.Second):
		close(stateAtRelease)
		<-lockAcquired
		t.Fatal("ValidateLocals held pool.mu while StateAt was blocked")
	}
	if errs := <-validationDone; len(errs) != 1 || errs[0] != nil {
		t.Fatalf("ValidateLocals failed after state snapshot release: %v", errs)
	}
}

func (c *txPoolValidationSnapshotTestChain) validationSnapshots() ([]common.Hash, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]common.Hash(nil), c.roots...), len(c.snapshots)
}

func newTxPoolValidationTestPool(t *testing.T, chain *txPoolValidationSnapshotTestChain, root common.Hash, header *types.Header) *TxPool {
	t.Helper()
	currentState, err := state.New(root, chain.db, nil)
	if err != nil {
		t.Fatal(err)
	}
	config := DefaultTxPoolConfig
	config.NoLocals = false
	signer := types.NewEIP155Signer(big.NewInt(1))
	return &TxPool{
		config:                 config,
		chainconfig:            &params.ChainConfig{ChainID: big.NewInt(1)},
		chain:                  chain,
		gasPrice:               new(big.Int).SetUint64(params.GWei),
		signer:                 signer,
		currentState:           currentState,
		currentStateRoot:       root,
		currentStateHead:       types.CopyHeader(header),
		currentStateGeneration: 1,
		pendingNonces:          newTxNoncer(currentState),
		currentMaxGas:          header.GasLimit,
		locals:                 newAccountSet(signer),
		all:                    newTxLookup(),
	}
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

func TestValidateLocalsUsesIndependentStateSnapshots(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr := crypto.PubkeyToAddress(key.PublicKey)
	db := state.NewDatabase(rawdb.NewMemoryDatabase())
	statedb, err := state.New(common.Hash{}, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	statedb.SetBalance(addr, new(big.Int).Mul(big.NewInt(100), big.NewInt(params.Ether)))
	root, err := statedb.Commit(false)
	if err != nil {
		t.Fatal(err)
	}
	currentState, err := state.New(root, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	header := &types.Header{
		Number:   big.NewInt(0),
		Root:     root,
		GasLimit: 30_000_000,
		BaseFee:  big.NewInt(1),
	}
	chain := &txPoolValidationSnapshotTestChain{
		block:     types.NewBlockWithHeader(header),
		db:        db,
		snapshots: make(map[*state.StateDB]struct{}),
	}
	config := DefaultTxPoolConfig
	config.NoLocals = false
	pool := &TxPool{
		config:           config,
		chainconfig:      &params.ChainConfig{ChainID: big.NewInt(1)},
		chain:            chain,
		gasPrice:         new(big.Int).SetUint64(params.GWei),
		signer:           types.NewEIP155Signer(big.NewInt(1)),
		currentState:     currentState,
		currentStateRoot: root,
		pendingNonces:    newTxNoncer(currentState),
		currentMaxGas:    header.GasLimit,
		locals:           newAccountSet(types.NewEIP155Signer(big.NewInt(1))),
		all:              newTxLookup(),
	}
	tx := signedPoolTxWithGasPrice(t, 0, key, big.NewInt(params.GWei))

	const validators = 32
	start := make(chan struct{})
	results := make(chan error, validators)
	var wg sync.WaitGroup
	wg.Add(validators)
	for i := 0; i < validators; i++ {
		go func() {
			defer wg.Done()
			<-start
			errs := pool.ValidateLocals(types.Transactions{tx})
			if len(errs) != 1 {
				results <- errors.New("ValidateLocals returned an invalid result count")
				return
			}
			results <- errs[0]
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent preflight failed: %v", err)
		}
	}
	roots, snapshots := chain.validationSnapshots()
	if len(roots) != validators {
		t.Fatalf("StateAt calls = %d, want %d", len(roots), validators)
	}
	if snapshots != validators {
		t.Fatalf("independent state snapshots = %d, want %d", snapshots, validators)
	}
	for i, got := range roots {
		if got != root {
			t.Fatalf("StateAt root %d = %s, want %s", i, got, root)
		}
	}
}

func TestValidateLocalsDoesNotPopulatePendingNonceFallback(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr := crypto.PubkeyToAddress(key.PublicKey)
	db := state.NewDatabase(rawdb.NewMemoryDatabase())
	statedb, err := state.New(common.Hash{}, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	statedb.SetBalance(addr, new(big.Int).Mul(big.NewInt(100), big.NewInt(params.Ether)))
	root, err := statedb.Commit(false)
	if err != nil {
		t.Fatal(err)
	}
	header := &types.Header{Number: big.NewInt(0), Root: root, GasLimit: 30_000_000, BaseFee: big.NewInt(1)}
	chain := &txPoolValidationSnapshotTestChain{
		block:     types.NewBlockWithHeader(header),
		db:        db,
		snapshots: make(map[*state.StateDB]struct{}),
	}
	pool := newTxPoolValidationTestPool(t, chain, root, header)
	tx := signedPoolTxWithGasPrice(t, 0, key, big.NewInt(params.GWei))

	if _, ok := pool.pendingNonces.peek(addr); ok {
		t.Fatal("fresh pending noncer unexpectedly contains sender")
	}
	if errs := pool.ValidateLocals(types.Transactions{tx}); len(errs) != 1 || errs[0] != nil {
		t.Fatalf("ValidateLocals failed: %v", errs)
	}
	if nonce, ok := pool.pendingNonces.peek(addr); ok {
		t.Fatalf("preflight populated the shared pending nonce fallback: %d", nonce)
	}
}

func TestValidateLocalsUsesOneSnapshotPerSenderGroup(t *testing.T) {
	keys := make([]*ecdsa.PrivateKey, 2)
	db := state.NewDatabase(rawdb.NewMemoryDatabase())
	statedb, err := state.New(common.Hash{}, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range keys {
		keys[i], err = crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		addr := crypto.PubkeyToAddress(keys[i].PublicKey)
		statedb.SetBalance(addr, new(big.Int).Mul(big.NewInt(100), big.NewInt(params.Ether)))
	}
	root, err := statedb.Commit(false)
	if err != nil {
		t.Fatal(err)
	}
	header := &types.Header{Number: big.NewInt(0), Root: root, GasLimit: 30_000_000, BaseFee: big.NewInt(1)}
	chain := &txPoolValidationSnapshotTestChain{
		block:     types.NewBlockWithHeader(header),
		db:        db,
		snapshots: make(map[*state.StateDB]struct{}),
	}
	pool := newTxPoolValidationTestPool(t, chain, root, header)
	txs := types.Transactions{
		signedPoolTxWithGasPrice(t, 0, keys[0], big.NewInt(params.GWei)),
		signedPoolTxWithGasPrice(t, 0, keys[1], big.NewInt(params.GWei)),
		signedPoolTxWithGasPrice(t, 1, keys[0], big.NewInt(params.GWei)),
		signedPoolTxWithGasPrice(t, 1, keys[1], big.NewInt(params.GWei)),
	}

	for index, err := range pool.ValidateLocals(txs) {
		if err != nil {
			t.Fatalf("ValidateLocals result %d failed: %v", index, err)
		}
	}
	roots, snapshots := chain.validationSnapshots()
	if len(roots) != len(keys) || snapshots != len(keys) {
		t.Fatalf("state snapshots = %d calls/%d instances, want %d sender-owned instances", len(roots), snapshots, len(keys))
	}
	for index, got := range roots {
		if got != root {
			t.Fatalf("StateAt root %d = %s, want %s", index, got, root)
		}
	}
}

func TestValidateLocalsRetriesChangedHeadGeneration(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr := crypto.PubkeyToAddress(key.PublicKey)
	db := state.NewDatabase(rawdb.NewMemoryDatabase())
	firstState, err := state.New(common.Hash{}, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	firstState.SetBalance(addr, new(big.Int).Mul(big.NewInt(100), big.NewInt(params.Ether)))
	firstRoot, err := firstState.Commit(false)
	if err != nil {
		t.Fatal(err)
	}
	secondState, err := state.New(firstRoot, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	secondState.SetNonce(addr, 1)
	secondRoot, err := secondState.Commit(false)
	if err != nil {
		t.Fatal(err)
	}
	firstHeader := &types.Header{Number: big.NewInt(0), Root: firstRoot, GasLimit: 30_000_000, BaseFee: big.NewInt(1)}
	secondHeader := &types.Header{Number: big.NewInt(1), Root: secondRoot, GasLimit: 30_000_000, BaseFee: big.NewInt(1)}
	stateAtEntered := make(chan struct{}, 1)
	stateAtRelease := make(chan struct{})
	chain := &txPoolValidationSnapshotTestChain{
		block:          types.NewBlockWithHeader(firstHeader),
		db:             db,
		snapshots:      make(map[*state.StateDB]struct{}),
		stateAtEntered: stateAtEntered,
		stateAtRelease: stateAtRelease,
	}
	pool := newTxPoolValidationTestPool(t, chain, firstRoot, firstHeader)
	tx := signedPoolTxWithGasPrice(t, 0, key, big.NewInt(params.GWei))

	validationDone := make(chan []error, 1)
	go func() {
		validationDone <- pool.ValidateLocals(types.Transactions{tx})
	}()
	select {
	case <-stateAtEntered:
	case <-time.After(5 * time.Second):
		close(stateAtRelease)
		t.Fatal("ValidateLocals did not start opening the first state snapshot")
	}
	currentState, err := state.New(secondRoot, db, nil)
	if err != nil {
		close(stateAtRelease)
		t.Fatal(err)
	}
	pool.mu.Lock()
	pool.currentState = currentState
	pool.currentStateRoot = secondRoot
	pool.currentStateHead = types.CopyHeader(secondHeader)
	pool.currentStateGeneration++
	pool.pendingNonces = newTxNoncer(currentState)
	pool.currentMaxGas = secondHeader.GasLimit
	pool.mu.Unlock()
	close(stateAtRelease)

	results := <-validationDone
	if len(results) != 1 || !errors.Is(results[0], ErrNonceTooLow) {
		t.Fatalf("ValidateLocals used the stale head result: %v", results)
	}
	roots, _ := chain.validationSnapshots()
	if len(roots) != 2 || roots[0] != firstRoot || roots[1] != secondRoot {
		t.Fatalf("StateAt roots = %v, want [%s %s]", roots, firstRoot, secondRoot)
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

func TestEvictStaleTransactionsPreservesLocals(t *testing.T) {
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
		signer:        types.NewEIP155Signer(big.NewInt(1)),
		pending:       map[common.Address]*txList{addr: newTxList(true)},
		queue:         map[common.Address]*txList{addr: newTxList(false)},
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

	if pool.all.Get(pendingTx.Hash()) == nil {
		t.Fatalf("stale local pending transaction was evicted")
	}
	if pool.all.Get(queuedTx.Hash()) == nil {
		t.Fatalf("stale local queued transaction was evicted")
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

type countingJournalWriter struct {
	mu sync.Mutex
	bytes.Buffer
	writes int
}

func (w *countingJournalWriter) Write(payload []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes++
	return w.Buffer.Write(payload)
}

func (w *countingJournalWriter) Close() error { return nil }

func (w *countingJournalWriter) writeCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writes
}

func (w *countingJournalWriter) snapshot() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.Buffer.Bytes()...)
}

func decodeJournalTransactions(t *testing.T, payload []byte) types.Transactions {
	t.Helper()
	stream := rlp.NewStream(bytes.NewReader(payload), 0)
	var txs types.Transactions
	for {
		pooled, err := stream.Bytes()
		if err != nil {
			if err == io.EOF {
				return txs
			}
			t.Fatalf("decode journal record: %v", err)
		}
		tx := new(types.Transaction)
		if err := tx.UnmarshalBinary(pooled); err != nil {
			t.Fatalf("decode pooled journal transaction: %v", err)
		}
		txs = append(txs, tx)
	}
}

func TestTxJournalInsertBatchUsesSingleWrite(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	txs := make(types.Transactions, 0, txJournalBatchSize)
	for nonce := uint64(0); nonce < txJournalBatchSize; nonce++ {
		txs = append(txs, signedPoolTxWithGasPrice(t, nonce, key, big.NewInt(params.GWei)))
	}
	writer := new(countingJournalWriter)
	journal := &txJournal{writer: writer}
	if err := journal.insertBatch(txs); err != nil {
		t.Fatal(err)
	}
	if writer.writeCount() != 1 {
		t.Fatalf("journal writes = %d, want 1", writer.writeCount())
	}
	decoded := decodeJournalTransactions(t, writer.snapshot())
	if len(decoded) != len(txs) {
		t.Fatalf("decoded transactions = %d, want %d", len(decoded), len(txs))
	}
	for i := range txs {
		if decoded[i].Hash() != txs[i].Hash() {
			t.Fatalf("transaction %d hash mismatch", i)
		}
	}
}

func TestTxJournalRoundTripPreservesBlobSidecar(t *testing.T) {
	tx, wantSidecar := signedPoolBlobTx(t, 77, false)
	path := filepath.Join(t.TempDir(), "transactions.rlp")
	journal := newTxJournal(path)
	if err := journal.rotate(map[common.Address]types.Transactions{
		common.HexToAddress("0x1000000000000000000000000000000000000001"): {tx},
	}); err != nil {
		t.Fatal(err)
	}
	if err := journal.close(); err != nil {
		t.Fatal(err)
	}

	var restored types.Transactions
	restarted := newTxJournal(path)
	if err := restarted.load(func(txs []*types.Transaction) []error {
		restored = append(restored, txs...)
		return make([]error, len(txs))
	}); err != nil {
		t.Fatal(err)
	}
	if len(restored) != 1 {
		t.Fatalf("restored transactions = %d, want 1", len(restored))
	}
	if restored[0].Hash() != tx.Hash() {
		t.Fatalf("restored hash = %s, want %s", restored[0].Hash(), tx.Hash())
	}
	gotSidecar := restored[0].BlobSidecar()
	if gotSidecar == nil || len(gotSidecar.Blobs) != len(wantSidecar.Blobs) ||
		len(gotSidecar.Commitments) != len(wantSidecar.Commitments) || len(gotSidecar.Proofs) != len(wantSidecar.Proofs) {
		t.Fatal("restored type-3 transaction lost its pooled blob sidecar")
	}
	if !bytes.Equal(gotSidecar.Blobs[0], wantSidecar.Blobs[0]) ||
		gotSidecar.Commitments[0] != wantSidecar.Commitments[0] || gotSidecar.Proofs[0] != wantSidecar.Proofs[0] {
		t.Fatal("restored type-3 blob sidecar changed")
	}
}

func TestTxJournalRestoreBindsBlobSidecarToOsaka(t *testing.T) {
	for _, test := range []struct {
		name   string
		osaka  bool
		accept bool
	}{
		{name: "rejects Prague wrapper", osaka: false, accept: false},
		{name: "restores Osaka wrapper", osaka: true, accept: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx, _ := signedPoolBlobTx(t, 0, false)
			if test.osaka {
				tx = toOsakaBlobSidecar(t, tx)
			}
			path := filepath.Join(t.TempDir(), "transactions.rlp")
			journal := newTxJournal(path)
			if err := journal.rotate(map[common.Address]types.Transactions{common.Address{}: {tx}}); err != nil {
				t.Fatal(err)
			}
			if err := journal.close(); err != nil {
				t.Fatal(err)
			}

			key, err := crypto.HexToECDSA("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
			if err != nil {
				t.Fatal(err)
			}
			chain, _ := newNativePoolTestChain(t, crypto.PubkeyToAddress(key.PublicKey))
			chainConfig := evmOnlyNativePoolTestConfig(t)
			zero := uint64(0)
			chainConfig.ModernForkConfig().OsakaTime = &zero
			poolConfig := DefaultTxPoolConfig
			poolConfig.Journal = path
			poolConfig.PriceLimit = 1
			pool := NewTxPool(poolConfig, chainConfig, chain)
			t.Cleanup(pool.Stop)

			restored := pool.Get(tx.Hash())
			if !test.accept {
				if restored != nil {
					t.Fatal("Prague v0 sidecar was restored into an Osaka transaction pool")
				}
				return
			}
			if restored == nil || restored.BlobSidecar() == nil || restored.BlobSidecar().Version != types.BlobSidecarVersion1 {
				t.Fatal("Osaka v1 sidecar was not restored into the transaction pool")
			}
		})
	}
}

func TestTxJournalWriterCapsAsyncWritesAtBatchSize(t *testing.T) {
	txs := make(types.Transactions, txJournalBatchSize*2+1)
	to := common.HexToAddress("0x1000000000000000000000000000000000000001")
	for i := range txs {
		txs[i] = types.NewTransaction(uint64(i), to, big.NewInt(1), 21_000, big.NewInt(1), nil)
	}
	sink := new(countingJournalWriter)
	writer := newTxJournalWriter(&txJournal{writer: sink})
	if _, err := writer.enqueue(txs, false); err != nil {
		t.Fatal(err)
	}
	if err := writer.close(); err != nil {
		t.Fatal(err)
	}
	if got := sink.writeCount(); got != 3 {
		t.Fatalf("journal writes = %d, want 3 bounded chunks", got)
	}
	if decoded := decodeJournalTransactions(t, sink.snapshot()); len(decoded) != len(txs) {
		t.Fatalf("decoded transactions = %d, want %d", len(decoded), len(txs))
	}
}

func TestTxJournalWriterRejectsUnboundedQueuedBacklog(t *testing.T) {
	w := &txJournalWriter{
		notify:    make(chan struct{}, 1),
		maxQueued: 2,
	}
	tx := types.NewTransaction(1, common.Address{}, big.NewInt(0), 21_000, big.NewInt(1), nil)
	if err := w.send(txJournalCommand{kind: txJournalAppend, txs: types.Transactions{tx, tx}}); err != nil {
		t.Fatalf("fill bounded queue: %v", err)
	}
	if err := w.send(txJournalCommand{kind: txJournalAppend, txs: types.Transactions{tx}}); !errors.Is(err, errJournalQueueFull) {
		t.Fatalf("overflow error = %v, want %v", err, errJournalQueueFull)
	}
	if w.queued != 2 {
		t.Fatalf("queued transactions = %d, want 2", w.queued)
	}
}

func TestTxJournalWriterPreservesRotateOrdering(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr := crypto.PubkeyToAddress(key.PublicKey)
	a := signedPoolTxWithGasPrice(t, 0, key, big.NewInt(params.GWei))
	b := signedPoolTxWithGasPrice(t, 1, key, big.NewInt(params.GWei))
	c := signedPoolTxWithGasPrice(t, 2, key, big.NewInt(params.GWei))

	journal := newTxJournal(filepath.Join(t.TempDir(), "transactions.rlp"))
	if err := journal.rotate(map[common.Address]types.Transactions{addr: {a}}); err != nil {
		t.Fatal(err)
	}
	writer := newTxJournalWriter(journal)
	if _, err := writer.enqueue(types.Transactions{b}, false); err != nil {
		t.Fatal(err)
	}
	if err := writer.rotate(map[common.Address]types.Transactions{addr: {a, b}}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.enqueue(types.Transactions{c}, false); err != nil {
		t.Fatal(err)
	}
	if err := writer.close(); err != nil {
		t.Fatal(err)
	}

	payload, err := os.ReadFile(journal.path)
	if err != nil {
		t.Fatal(err)
	}
	decoded := decodeJournalTransactions(t, payload)
	want := types.Transactions{a, b, c}
	if len(decoded) != len(want) {
		t.Fatalf("decoded transactions = %d, want %d", len(decoded), len(want))
	}
	for i := range want {
		if decoded[i].Hash() != want[i].Hash() {
			t.Fatalf("transaction %d hash mismatch", i)
		}
	}
}

func TestAddLocalsAsyncBatchesJournalAndEvent(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr := crypto.PubkeyToAddress(key.PublicKey)
	remoteKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	remoteAddr := crypto.PubkeyToAddress(remoteKey.PublicKey)
	statedb, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	statedb.SetBalance(addr, new(big.Int).Mul(big.NewInt(100), big.NewInt(params.Ether)))
	statedb.SetBalance(remoteAddr, new(big.Int).Mul(big.NewInt(100), big.NewInt(params.Ether)))

	header := &types.Header{Number: big.NewInt(0), GasLimit: 30_000_000, BaseFee: big.NewInt(1)}
	config := DefaultTxPoolConfig
	config.NoLocals = false
	pool := &TxPool{
		config:          config,
		chainconfig:     &params.ChainConfig{ChainID: big.NewInt(1)},
		chain:           txPoolPriceTestChain{block: types.NewBlockWithHeader(header), state: statedb},
		gasPrice:        new(big.Int).SetUint64(params.GWei),
		signer:          types.NewEIP155Signer(big.NewInt(1)),
		currentState:    statedb,
		pendingNonces:   newTxNoncer(statedb),
		currentMaxGas:   header.GasLimit,
		locals:          newAccountSet(types.NewEIP155Signer(big.NewInt(1))),
		pending:         make(map[common.Address]*txList),
		queue:           make(map[common.Address]*txList),
		beats:           make(map[common.Address]time.Time),
		all:             newTxLookup(),
		seen:            make(map[common.Hash]time.Time),
		reqResetCh:      make(chan *txpoolResetRequest),
		reqPromoteCh:    make(chan *txpoolPromoteRequest),
		reorgShutdownCh: make(chan struct{}),
	}
	pool.priced = newTxPricedList(pool.all)

	journalSink := new(countingJournalWriter)
	pool.journal = &txJournal{writer: journalSink}
	pool.journalWriter = newTxJournalWriter(pool.journal)
	pool.wg.Add(1)
	go pool.scheduleReorgLoop()
	defer func() {
		close(pool.reorgShutdownCh)
		pool.wg.Wait()
		if err := pool.journalWriter.close(); err != nil {
			t.Errorf("close journal writer: %v", err)
		}
	}()

	events := make(chan NewTxsEvent, 1)
	sub := pool.txFeed.Subscribe(events)
	defer sub.Unsubscribe()
	txs := types.Transactions{
		signedPoolTxWithGasPrice(t, 0, key, big.NewInt(params.GWei)),
		signedPoolTxWithGasPrice(t, 1, key, big.NewInt(params.GWei)),
	}
	for i, err := range pool.ValidateLocals(txs) {
		if err != nil {
			t.Fatalf("preflight %d: %v", i, err)
		}
	}
	if pool.all.Count() != 0 || journalSink.writeCount() != 0 {
		t.Fatal("local preflight mutated the pool or journal")
	}
	for i, err := range pool.AddLocalsAsync(txs) {
		if err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	select {
	case event := <-events:
		if len(event.Txs) != len(txs) {
			t.Fatalf("event transactions = %d, want %d", len(event.Txs), len(txs))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for batched transaction event")
	}
	if !pool.locals.contains(addr) {
		t.Fatal("AddLocalsAsync did not preserve local account semantics")
	}
	deadline := time.Now().Add(time.Second)
	for journalSink.writeCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := journalSink.writeCount(); got != 1 {
		t.Fatalf("batched async journal writes = %d, want 1", got)
	}

	remoteTx := signedPoolTxWithGasPrice(t, 0, remoteKey, big.NewInt(params.GWei))
	if err := pool.AddRemotes(types.Transactions{remoteTx})[0]; err != nil {
		t.Fatalf("remote insert: %v", err)
	}
	writesBeforeUpgrade := journalSink.writeCount()
	if err := pool.AddLocals(types.Transactions{remoteTx})[0]; err != ErrAlreadyKnown {
		t.Fatalf("known local upgrade error = %v, want %v", err, ErrAlreadyKnown)
	}
	if !pool.locals.contains(remoteAddr) {
		t.Fatal("known remote transaction was not upgraded to local durability")
	}
	if got := journalSink.writeCount(); got <= writesBeforeUpgrade {
		t.Fatalf("known remote upgrade did not complete journal write: before=%d after=%d", writesBeforeUpgrade, got)
	}
}
