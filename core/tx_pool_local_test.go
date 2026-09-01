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
		tx := new(types.Transaction)
		if err := stream.Decode(tx); err != nil {
			if err == io.EOF {
				return txs
			}
			t.Fatalf("decode journal: %v", err)
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
		chain:           txPoolPriceTestChain{block: types.NewBlockWithHeader(header)},
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
