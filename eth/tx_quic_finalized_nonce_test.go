package eth

import (
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"math/big"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/ethdb/memorydb"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
	lru "github.com/hashicorp/golang-lru"
)

// The reader retains immutable, root-specific states. Every StateAt returns a
// separate Copy, including an independent trie, as the production reader does.
// A real trie wrapper makes GetNonce errors observable through StateDB.Error.
type finalizedNonceTestReader struct {
	mu       sync.RWMutex
	head     *types.Block
	states   map[common.Hash]*state.StateDB
	openErr  error
	openNil  bool
	opens    atomic.Int64
	reads    *finalizedNonceTestReads
	database state.Database
}

type finalizedNonceTestReads struct {
	mu      sync.Mutex
	counts  map[common.Address]int
	fail    common.Address
	failing bool
}

type finalizedNonceTestDatabase struct {
	state.Database
	reads *finalizedNonceTestReads
}

type finalizedNonceTestTrie struct {
	state.Trie
	reads *finalizedNonceTestReads
}

func (db *finalizedNonceTestDatabase) OpenTrie(root common.Hash) (state.Trie, error) {
	tr, err := db.Database.OpenTrie(root)
	if err != nil {
		return nil, err
	}
	return &finalizedNonceTestTrie{Trie: tr, reads: db.reads}, nil
}

func (db *finalizedNonceTestDatabase) CopyTrie(tr state.Trie) state.Trie {
	if wrapped, ok := tr.(*finalizedNonceTestTrie); ok {
		return &finalizedNonceTestTrie{Trie: db.Database.CopyTrie(wrapped.Trie), reads: wrapped.reads}
	}
	return db.Database.CopyTrie(tr)
}

func (tr *finalizedNonceTestTrie) TryGet(key []byte) ([]byte, error) {
	address := common.BytesToAddress(key)
	tr.reads.mu.Lock()
	tr.reads.counts[address]++
	fail := tr.reads.failing && tr.reads.fail == address
	tr.reads.mu.Unlock()
	if fail {
		return nil, errors.New("injected finalized account read failure")
	}
	return tr.Trie.TryGet(key)
}

func (reader *finalizedNonceTestReader) CurrentBlock() *types.Block {
	reader.mu.RLock()
	defer reader.mu.RUnlock()
	return reader.head
}

func (reader *finalizedNonceTestReader) StateAt(root common.Hash) (*state.StateDB, error) {
	reader.opens.Add(1)
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.openErr != nil || reader.openNil {
		return nil, reader.openErr
	}
	snapshot := reader.states[root]
	if snapshot == nil {
		return nil, errors.New("unknown finalized test state root")
	}
	return snapshot.Copy(), nil
}

func (reader *finalizedNonceTestReader) setHead(head *types.Block) {
	reader.mu.Lock()
	reader.head = head
	reader.mu.Unlock()
}

func (reader *finalizedNonceTestReader) resetCounts() {
	reader.opens.Store(0)
	reader.reads.mu.Lock()
	reader.reads.counts = make(map[common.Address]int)
	reader.reads.mu.Unlock()
}

func (reader *finalizedNonceTestReader) accountReads(address common.Address) int {
	reader.reads.mu.Lock()
	defer reader.reads.mu.Unlock()
	return reader.reads.counts[address]
}

func newFinalizedNonceTestReader(t testing.TB) *finalizedNonceTestReader {
	t.Helper()
	disk := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { _ = disk.Close() })
	reads := &finalizedNonceTestReads{counts: make(map[common.Address]int)}
	return &finalizedNonceTestReader{
		states: make(map[common.Hash]*state.StateDB), reads: reads,
		database: &finalizedNonceTestDatabase{Database: state.NewDatabase(disk), reads: reads},
	}
}

func (reader *finalizedNonceTestReader) addHead(t testing.TB, number uint64, nonces map[common.Address]uint64) *types.Block {
	t.Helper()
	// Commit real account data, then reopen it so the retained snapshot has no
	// preloaded state objects that could hide a requested trie-read failure.
	bare := reader.database.(*finalizedNonceTestDatabase).Database
	snapshot, err := state.New(common.Hash{}, bare, nil)
	if err != nil {
		t.Fatal(err)
	}
	for address, nonce := range nonces {
		snapshot.SetNonce(address, nonce)
		snapshot.SetBalance(address, big.NewInt(1))
	}
	root, err := snapshot.Commit(true)
	if err != nil {
		t.Fatal(err)
	}
	if err := bare.TrieDB().Commit(root, false, nil); err != nil {
		t.Fatal(err)
	}
	snapshot, err = state.New(root, reader.database, nil)
	if err != nil {
		t.Fatal(err)
	}
	head := types.NewBlockWithHeader(&types.Header{Number: new(big.Int).SetUint64(number), Root: root, GasLimit: 30_000_000})
	reader.mu.Lock()
	reader.states[root] = snapshot
	reader.head = head
	reader.mu.Unlock()
	return head
}

type finalizedNonceTestSigner struct {
	types.Signer
	calls atomic.Int64
}

func (signer *finalizedNonceTestSigner) Sender(tx *types.Transaction) (common.Address, error) {
	signer.calls.Add(1)
	return signer.Signer.Sender(tx)
}

func (signer *finalizedNonceTestSigner) Equal(other types.Signer) bool { return signer == other }

func finalizedNonceTestKey(t testing.TB, index uint64) *ecdsa.PrivateKey {
	t.Helper()
	var encoded [32]byte
	binary.BigEndian.PutUint64(encoded[24:], index+1)
	key, err := crypto.ToECDSA(encoded[:])
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func finalizedNonceTestTx(t testing.TB, key *ecdsa.PrivateKey, chainID *big.Int, nonce uint64) *types.Transaction {
	t.Helper()
	tx, err := types.SignTx(types.NewTransaction(nonce, common.HexToAddress("0x01"), big.NewInt(1), 21_000, big.NewInt(1), nil), types.NewEIP155Signer(chainID), key)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func finalizedNonceTestEncode(t testing.TB, txs types.Transactions) [][]byte {
	t.Helper()
	encoded := make([][]byte, len(txs))
	for i, tx := range txs {
		var err error
		if encoded[i], err = rlp.EncodeToBytes(tx); err != nil {
			t.Fatal(err)
		}
	}
	return encoded
}

func finalizedNonceTestDecode(t testing.TB, encoded [][]byte) types.Transactions {
	t.Helper()
	txs := make(types.Transactions, len(encoded))
	for i, raw := range encoded {
		txs[i] = new(types.Transaction)
		if err := rlp.DecodeBytes(raw, txs[i]); err != nil {
			t.Fatal(err)
		}
	}
	return txs
}

func finalizedNonceTestResult(t testing.TB, got, want []bool) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("obsolete = %v, want %v", got, want)
	}
}

func finalizedNonceTestCached(t testing.TB, reader *finalizedNonceTestReader, chainID *big.Int) (*txQUICFinalizedNonceLookup, *finalizedNonceTestSigner) {
	t.Helper()
	lookup := newTxQUICFinalizedNonceLookup(reader, chainID)
	if lookup.senders == nil || lookup.nonces == nil {
		t.Fatal("constructor did not enable bounded sender and finalized-nonce caches")
	}
	signer := &finalizedNonceTestSigner{Signer: lookup.signer}
	lookup.signer = signer
	return lookup, signer
}

func TestTxQUICFinalizedNonceLookupReusesDecodedTransactionsAndSenderNonce(t *testing.T) {
	reader := newFinalizedNonceTestReader(t)
	chainID := big.NewInt(1337)
	key := finalizedNonceTestKey(t, 0)
	address := crypto.PubkeyToAddress(key.PublicKey)
	reader.addHead(t, 10, map[common.Address]uint64{address: 5})
	// Keep this regression independent of cache internals: the uncached
	// constructor must fail on repeated recovery/read counts, not merely on
	// the presence of a cache field.
	lookup := newTxQUICFinalizedNonceLookup(reader, chainID)
	signer := &finalizedNonceTestSigner{Signer: lookup.signer}
	lookup.signer = signer
	encoded := finalizedNonceTestEncode(t, types.Transactions{finalizedNonceTestTx(t, key, chainID, 4), finalizedNonceTestTx(t, key, chainID, 5)})
	want := []bool{true, false}
	finalizedNonceTestResult(t, txQUICFinalizedNonceObsolete(reader, chainID, finalizedNonceTestDecode(t, encoded)), want)
	reader.resetCounts()
	for i := 0; i < 3; i++ {
		finalizedNonceTestResult(t, lookup.Lookup(finalizedNonceTestDecode(t, encoded)), want)
	}
	if signer.calls.Load() != 2 || reader.opens.Load() != 1 || reader.accountReads(address) != 1 {
		t.Fatalf("repeated decoded reads: recoveries=%d StateAt=%d account=%d, want 2/1/1", signer.calls.Load(), reader.opens.Load(), reader.accountReads(address))
	}
	// A new transaction from the same sender still needs signature recovery,
	// while its finalized nonce is reusable without opening another StateDB.
	finalizedNonceTestResult(t, lookup.Lookup(types.Transactions{finalizedNonceTestTx(t, key, chainID, 3)}), []bool{true})
	if signer.calls.Load() != 3 || reader.opens.Load() != 1 {
		t.Fatalf("new nonce recoveries=%d StateAt=%d, want 3/1", signer.calls.Load(), reader.opens.Load())
	}
}

func TestTxQUICFinalizedNonceLookupUsesExactHeadHash(t *testing.T) {
	reader := newFinalizedNonceTestReader(t)
	chainID := big.NewInt(1337)
	key := finalizedNonceTestKey(t, 0)
	address := crypto.PubkeyToAddress(key.PublicKey)
	headA := reader.addHead(t, 10, map[common.Address]uint64{address: 5})
	headB := reader.addHead(t, 10, map[common.Address]uint64{address: 2})
	headC := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(11), Root: headB.Root(), GasLimit: headB.GasLimit()})
	if headA.Hash() == headB.Hash() || headB.Hash() == headC.Hash() || headB.Root() != headC.Root() {
		t.Fatal("invalid distinct-head/same-root fixture")
	}
	lookup, signer := finalizedNonceTestCached(t, reader, chainID)
	encoded := finalizedNonceTestEncode(t, types.Transactions{finalizedNonceTestTx(t, key, chainID, 3)})
	reader.resetCounts()
	for _, test := range []struct {
		head *types.Block
		want bool
	}{{headA, true}, {headB, false}, {headC, false}, {headA, true}} {
		reader.setHead(test.head)
		finalizedNonceTestResult(t, lookup.Lookup(finalizedNonceTestDecode(t, encoded)), []bool{test.want})
	}
	if signer.calls.Load() != 1 || reader.opens.Load() != 3 {
		t.Fatalf("head changes recoveries=%d StateAt=%d, want 1/3", signer.calls.Load(), reader.opens.Load())
	}
	reader.setHead(nil)
	finalizedNonceTestResult(t, lookup.Lookup(finalizedNonceTestDecode(t, encoded)), []bool{false})
}

func TestTxQUICFinalizedNonceLookupReadFailurePublishesNoPartialNonce(t *testing.T) {
	for _, failure := range []string{"open error", "nil state", "account read error"} {
		t.Run(failure, func(t *testing.T) {
			reader := newFinalizedNonceTestReader(t)
			chainID := big.NewInt(1337)
			keys := []*ecdsa.PrivateKey{finalizedNonceTestKey(t, 0), finalizedNonceTestKey(t, 1), finalizedNonceTestKey(t, 2)}
			addresses := make([]common.Address, len(keys))
			nonces := make(map[common.Address]uint64)
			var txs types.Transactions
			for i, key := range keys {
				addresses[i] = crypto.PubkeyToAddress(key.PublicKey)
				nonces[addresses[i]] = 5
				txs = append(txs, finalizedNonceTestTx(t, key, chainID, 4))
			}
			reader.addHead(t, 10, nonces)
			lookup, _ := finalizedNonceTestCached(t, reader, chainID)
			encoded := finalizedNonceTestEncode(t, txs)
			finalizedNonceTestResult(t, lookup.Lookup(finalizedNonceTestDecode(t, encoded[:1])), []bool{true})
			reader.mu.Lock()
			reader.openNil = failure == "nil state"
			if failure == "open error" {
				reader.openErr = errors.New("injected StateAt failure")
			}
			reader.mu.Unlock()
			reader.reads.mu.Lock()
			reader.reads.fail, reader.reads.failing = addresses[2], failure == "account read error"
			reader.reads.mu.Unlock()
			// The first nonce is already cached; the second miss succeeds before
			// the third read fails. Neither cached nor fresh results may escape.
			finalizedNonceTestResult(t, lookup.Lookup(finalizedNonceTestDecode(t, encoded)), []bool{false, false, false})
			if lookup.nonces.Len() != 1 {
				t.Fatalf("nonce cache after failed batch = %d, want only the previously verified entry", lookup.nonces.Len())
			}
			reader.mu.Lock()
			reader.openErr, reader.openNil = nil, false
			reader.mu.Unlock()
			reader.reads.mu.Lock()
			reader.reads.failing = false
			reader.reads.mu.Unlock()
			finalizedNonceTestResult(t, lookup.Lookup(finalizedNonceTestDecode(t, encoded)), []bool{true, true, true})
			if reader.opens.Load() != 3 || lookup.nonces.Len() != 3 {
				t.Fatalf("retry StateAt=%d cached nonces=%d, want 3/3", reader.opens.Load(), lookup.nonces.Len())
			}
			if failure == "account read error" && (reader.accountReads(addresses[1]) != 2 || reader.accountReads(addresses[2]) != 2) {
				t.Fatal("failed snapshot's successful or failed reads were cached instead of retried")
			}
		})
	}
}

func TestTxQUICFinalizedNonceLookupRejectsInvalidAndCopiesChainID(t *testing.T) {
	reader := newFinalizedNonceTestReader(t)
	chainID := big.NewInt(1337)
	key := finalizedNonceTestKey(t, 0)
	reader.addHead(t, 10, map[common.Address]uint64{crypto.PubkeyToAddress(key.PublicKey): 5})
	lookup, signer := finalizedNonceTestCached(t, reader, chainID)
	valid := finalizedNonceTestTx(t, key, chainID, 4)
	foreign := finalizedNonceTestTx(t, key, big.NewInt(9999), 4)
	unsigned := types.NewTransaction(4, common.Address{}, big.NewInt(1), 21_000, big.NewInt(1), nil)
	outOfBounds := types.NewTransaction(4, common.Address{}, big.NewInt(1), 21_000, new(big.Int).Lsh(big.NewInt(1), 256), nil)
	chainID.SetInt64(9999)
	finalizedNonceTestResult(t, lookup.Lookup(types.Transactions{nil, new(types.Transaction), outOfBounds, unsigned, foreign, valid}), []bool{false, false, false, false, false, true})
	if lookup.senders.Len() != 1 || lookup.nonces.Len() != 1 {
		t.Fatalf("invalid transaction populated caches: senders=%d nonces=%d", lookup.senders.Len(), lookup.nonces.Len())
	}
	before := signer.calls.Load()
	finalizedNonceTestResult(t, lookup.Lookup(types.Transactions{unsigned, foreign}), []bool{false, false})
	if signer.calls.Load() != before+2 {
		t.Fatal("failed sender recoveries were cached")
	}
	for _, unavailable := range []*txQUICFinalizedNonceLookup{nil, newTxQUICFinalizedNonceLookup(nil, big.NewInt(1337)), newTxQUICFinalizedNonceLookup(reader, nil)} {
		finalizedNonceTestResult(t, unavailable.Lookup(types.Transactions{valid}), []bool{false})
	}
}

func TestTxQUICFinalizedNonceLookupEvictionAndUncachedMode(t *testing.T) {
	reader := newFinalizedNonceTestReader(t)
	chainID := big.NewInt(1337)
	nonces := make(map[common.Address]uint64)
	var txs types.Transactions
	for i := uint64(0); i < 7; i++ {
		key := finalizedNonceTestKey(t, i)
		nonces[crypto.PubkeyToAddress(key.PublicKey)] = 1
		txs = append(txs, finalizedNonceTestTx(t, key, chainID, 0))
	}
	reader.addHead(t, 10, nonces)
	lookup, signer := finalizedNonceTestCached(t, reader, chainID)
	lookup.senders, _ = lru.New(4)
	lookup.nonces, _ = lru.New(2)
	encoded := finalizedNonceTestEncode(t, txs)
	for i := range encoded {
		finalizedNonceTestResult(t, lookup.Lookup(finalizedNonceTestDecode(t, encoded[i:i+1])), []bool{true})
		if lookup.senders.Len() > 4 || lookup.nonces.Len() > 2 {
			t.Fatal("cache capacity exceeded")
		}
	}
	finalizedNonceTestResult(t, lookup.Lookup(finalizedNonceTestDecode(t, encoded[:1])), []bool{true})
	if signer.calls.Load() != 8 || reader.opens.Load() != 8 || lookup.senders.Len() != 4 || lookup.nonces.Len() != 2 {
		t.Fatalf("eviction recoveries=%d StateAt=%d caches=%d/%d, want 8/8/4/2", signer.calls.Load(), reader.opens.Load(), lookup.senders.Len(), lookup.nonces.Len())
	}
	lookup.senders, lookup.nonces = nil, nil
	signer.calls.Store(0)
	reader.resetCounts()
	for i := 0; i < 2; i++ {
		finalizedNonceTestResult(t, lookup.Lookup(finalizedNonceTestDecode(t, encoded[:1])), []bool{true})
	}
	if signer.calls.Load() != 2 || reader.opens.Load() != 2 {
		t.Fatalf("uncached recoveries=%d StateAt=%d, want 2/2", signer.calls.Load(), reader.opens.Load())
	}
}

func TestTxQUICFinalizedNonceLookupConcurrentHeads(t *testing.T) {
	reader := newFinalizedNonceTestReader(t)
	chainID := big.NewInt(1337)
	noncesA, noncesB := make(map[common.Address]uint64), make(map[common.Address]uint64)
	var txs types.Transactions
	wantA, wantB := make([]bool, 8), make([]bool, 8)
	for i := uint64(0); i < 8; i++ {
		key := finalizedNonceTestKey(t, i)
		address := crypto.PubkeyToAddress(key.PublicKey)
		if i%2 == 0 {
			noncesA[address], noncesB[address], wantA[i] = 2, 0, true
		} else {
			noncesA[address], noncesB[address], wantB[i] = 0, 2, true
		}
		txs = append(txs, finalizedNonceTestTx(t, key, chainID, 1))
	}
	headA, headB := reader.addHead(t, 10, noncesA), reader.addHead(t, 11, noncesB)
	lookup, _ := finalizedNonceTestCached(t, reader, chainID)
	encoded := finalizedNonceTestEncode(t, txs)
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 16; i++ {
				got := lookup.Lookup(finalizedNonceTestDecode(t, encoded))
				if !reflect.DeepEqual(got, wantA) && !reflect.DeepEqual(got, wantB) {
					t.Fatalf("batch mixes finalized heads: got %v, want all of %v or %v", got, wantA, wantB)
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 128; i++ {
			if i%2 == 0 {
				reader.setHead(headA)
			} else {
				reader.setHead(headB)
			}
		}
	}()
	wg.Wait()
}

func TestTxQUICFinalizedNonceLookupDoesNotBypassDurableCommitment(t *testing.T) {
	reader := newFinalizedNonceTestReader(t)
	chainID := big.NewInt(1337)
	key := finalizedNonceTestKey(t, 0)
	reader.addHead(t, 10, map[common.Address]uint64{crypto.PubkeyToAddress(key.PublicKey): 5})
	lookup, _ := finalizedNonceTestCached(t, reader, chainID)
	tx := finalizedNonceTestTx(t, key, chainID, 4)
	finalizedNonceTestResult(t, lookup.Lookup(types.Transactions{tx}), []bool{true})
	config := testTxQUICConfig()
	db := memorydb.New()
	store := NewTxQUICIngressStore(db, config)
	if err := store.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Stop)
	packet := testTxQUICPacket(t, config, common.HexToAddress("0x6050"), 1, tx)
	if _, err := store.StoreSync(context.Background(), packet, testTxQUICAck(t, packet, []int{0}, nil, nil)); err != nil {
		t.Fatal(err)
	}
	itemKey := txQUICIngressItemKey(packet.BatchID, 0)
	encoded, err := db.Get(itemKey)
	if err != nil {
		t.Fatal(err)
	}
	var record txQUICIngressItemRecord
	if err := rlp.DecodeBytes(encoded, &record); err != nil {
		t.Fatal(err)
	}
	// Corrupt an admission commitment without changing the transaction hash:
	// the sender cache would still hit if maintenance bypassed validation.
	record.Item.AdmissionIndex++
	if record.Item.Tx.Hash() != tx.Hash() || !lookup.senders.Contains(tx.Hash()) {
		t.Fatal("corruption fixture did not preserve the warmed cache key")
	}
	encoded, err = rlp.EncodeToBytes(&record)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Put(itemKey, encoded); err != nil {
		t.Fatal(err)
	}
	poolState, err := reader.StateAt(reader.CurrentBlock().Root())
	if err != nil {
		t.Fatal(err)
	}
	poolConfig := core.DefaultTxPoolConfig
	poolConfig.NoLocals, poolConfig.Journal = true, ""
	chainConfig := *params.TestChainConfig
	chainConfig.ChainID = new(big.Int).Set(chainID)
	pool := core.NewTxPool(poolConfig, &chainConfig, &testTxQUICPoolChain{block: reader.CurrentBlock(), state: poolState})
	t.Cleanup(pool.Stop)
	ingress := &TxQUICIngress{config: config, ctx: context.Background(), ingress: store, txpool: pool}
	lookupCalls := 0
	ingress.SetObsoleteTxLookup(func(txs types.Transactions) []bool {
		lookupCalls++
		return lookup.Lookup(txs)
	})
	if removed, err := ingress.maintainDurableIngressPage(); removed != 0 || err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("maintenance accepted a changed commitment with a warm cache: removed=%d err=%v", removed, err)
	}
	if lookupCalls != 0 {
		t.Fatal("maintenance consulted the cache before validating its durable item")
	}
}

// Every measured iteration decodes 512 fresh Transaction objects. Reusing the
// same objects would benchmark Transaction.from, hiding the repeated recovery
// performed when durable maintenance decodes its items on every pass.
func BenchmarkTxQUICFinalizedNonceLookup(b *testing.B) {
	const senders, txCount = 128, 512
	for _, mode := range []string{"uncached", "cached_cold", "cached_warm", "cached_new_head"} {
		b.Run(mode, func(b *testing.B) {
			reader := newFinalizedNonceTestReader(b)
			chainID := big.NewInt(1337)
			nonces := make(map[common.Address]uint64)
			keys := make([]*ecdsa.PrivateKey, senders)
			for i := range keys {
				keys[i] = finalizedNonceTestKey(b, uint64(i))
				nonces[crypto.PubkeyToAddress(keys[i].PublicKey)] = 2
			}
			head := reader.addHead(b, 10, nonces)
			txs, want := make(types.Transactions, txCount), make([]bool, txCount)
			for i := range txs {
				txs[i] = finalizedNonceTestTx(b, keys[i%senders], chainID, uint64(i/senders))
				want[i] = i/senders < 2
			}
			encoded := finalizedNonceTestEncode(b, txs)
			lookup := newTxQUICFinalizedNonceLookup(reader, chainID)
			if mode != "uncached" && (lookup.senders == nil || lookup.nonces == nil) {
				b.Fatal("constructor did not enable caches")
			}
			finalizedNonceTestResult(b, txQUICFinalizedNonceObsolete(reader, chainID, finalizedNonceTestDecode(b, encoded)), want)
			finalizedNonceTestResult(b, lookup.Lookup(finalizedNonceTestDecode(b, encoded)), want)
			reader.resetCounts()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if mode == "cached_cold" {
					// Include bounded-cache clearing cost in this cold-pass result.
					lookup.senders.Purge()
					lookup.nonces.Purge()
				} else if mode == "cached_new_head" {
					reader.setHead(types.NewBlockWithHeader(&types.Header{Number: new(big.Int).SetUint64(uint64(i + 11)), Root: head.Root(), GasLimit: head.GasLimit()}))
				}
				decoded := finalizedNonceTestDecode(b, encoded)
				var got []bool
				if mode == "uncached" {
					got = txQUICFinalizedNonceObsolete(reader, chainID, decoded)
				} else {
					got = lookup.Lookup(decoded)
				}
				for j := range want {
					if got[j] != want[j] {
						b.Fatalf("transaction %d obsolete=%t, want %t", j, got[j], want[j])
					}
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*txCount), "ns/tx")
			b.ReportMetric(float64(reader.opens.Load())/float64(b.N), "StateAt/op")
		})
	}
}
