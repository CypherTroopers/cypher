package core

import (
	"bytes"
	"fmt"
	"math/big"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/trie"
	lru "github.com/hashicorp/golang-lru"
)

func TestRLPStringEnvelopeSizeMatchesEncoder(t *testing.T) {
	for _, size := range []int{0, 1, 2, 55, 56, 255, 256, 4096} {
		payload := make([]byte, size)
		if size == 1 {
			payload[0] = 0x01
		}
		encoded, err := rlp.EncodeToBytes(payload)
		if err != nil {
			t.Fatalf("encode size %d: %v", size, err)
		}
		if got := rlpStringEnvelopeSize(payload); got != uint64(len(encoded)) {
			t.Fatalf("payload %d envelope = %d, want %d", size, got, len(encoded))
		}
	}
}

func TestEVMReceiptReusedEncodingPreservesListSize(t *testing.T) {
	receipts := types.Receipts{
		{Type: types.LegacyTxType, Status: types.ReceiptStatusSuccessful},
		{Type: types.AccessListTxType, Status: types.ReceiptStatusFailed},
		{Type: types.DynamicFeeTxType, Status: types.ReceiptStatusSuccessful},
		{Type: types.BlobTxType, Status: types.ReceiptStatusFailed},
		{Type: types.SetCodeTxType, Status: types.ReceiptStatusSuccessful, Logs: []*types.Log{{Data: make([]byte, 1024)}}},
	}
	var oldContent, reusedContent uint64
	for index, receipt := range receipts {
		wrapped, err := rlp.EncodeToBytes(receipt)
		if err != nil {
			t.Fatalf("encode wrapped receipt %d: %v", index, err)
		}
		leaf, err := receipt.MarshalBinary()
		if err != nil {
			t.Fatalf("encode receipt leaf %d: %v", index, err)
		}
		oldContent += uint64(len(wrapped))
		if receipt.Type == types.LegacyTxType {
			reusedContent += uint64(len(leaf))
		} else {
			reusedContent += rlpStringEnvelopeSize(leaf)
		}
	}
	if oldContent != reusedContent || rlp.ListSize(oldContent) != rlp.ListSize(reusedContent) {
		t.Fatalf("receipt list size changed: old=%d reused=%d", oldContent, reusedContent)
	}
}

func TestEVMValidateStateMixedReceiptBatches(t *testing.T) {
	config := evmOnlyNativeConfig()
	receipts := make(types.Receipts, 257)
	for index := range receipts {
		receiptType := uint8(index % (types.SetCodeTxType + 1))
		receipts[index] = &types.Receipt{Type: receiptType, Status: types.ReceiptStatusSuccessful}
	}
	statedb := newModernTestState(t)
	header := &types.Header{
		Number:      big.NewInt(0),
		Bloom:       types.CreateBloom(receipts),
		ReceiptHash: types.DeriveSha(receipts, new(trie.Trie)),
		Root:        statedb.IntermediateRoot(config.IsEIP158(big.NewInt(0))),
	}
	block := types.NewBlockWithHeader(header)
	validator := &BlockValidator{config: config}
	if err := validator.ValidateState(block, statedb, receipts, 0); err != nil {
		t.Fatalf("mixed typed receipt validation failed: %v", err)
	}
}

func newBodyRLPCacheFixture(t *testing.T, db ethdb.Database, limit uint64) *BlockChain {
	t.Helper()
	cache, err := lru.New(bodyCacheLimit)
	if err != nil {
		t.Fatal(err)
	}
	numbers, err := lru.New(numberCacheLimit)
	if err != nil {
		t.Fatal(err)
	}
	return &BlockChain{
		db: db, bodyRLPCache: cache, bodyRLPCacheLimit: limit,
		hc: &HeaderChain{chainDb: db, numberCache: numbers},
	}
}

func writeBodyRLPCacheFixture(t *testing.T, db ethdb.Database, nonce uint64, payload int) (common.Hash, rlp.RawValue) {
	t.Helper()
	tx := types.NewTransaction(nonce, common.Address{1}, big.NewInt(1), params.TxGas, big.NewInt(1), bytes.Repeat([]byte{0x42}, payload))
	block := types.NewBlock(&types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1)}, types.Transactions{tx}, nil, nil, new(trie.Trie))
	rawdb.WriteBlock(db, block)
	body := rawdb.ReadBodyRLP(db, block.Hash(), block.NumberU64())
	if len(body) == 0 || rawdb.ReadBlock(db, block.Hash(), block.NumberU64()) == nil {
		t.Fatal("fixture did not persist a readable block")
	}
	return block.Hash(), body
}

func bodyRLPCacheUsage(bc *BlockChain) (used uint64, retained uint64, entries int) {
	bc.bodyRLPCacheMu.Lock()
	defer bc.bodyRLPCacheMu.Unlock()
	for _, key := range bc.bodyRLPCache.Keys() {
		value, ok := bc.bodyRLPCache.Peek(key)
		if ok {
			retained += uint64(cap(value.(rlp.RawValue)))
		}
	}
	return bc.bodyRLPCacheBytes, retained, bc.bodyRLPCache.Len()
}

func TestBodyRLPCacheEvictionRestoresExactDurableBytes(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { db.Close() })
	var hashes [3]common.Hash
	var bodies [3]rlp.RawValue
	for index := range hashes {
		hashes[index], bodies[index] = writeBodyRLPCacheFixture(t, db, uint64(index+1), 256)
	}
	limit := uint64(2 * len(bodies[0]))
	bc := newBodyRLPCacheFixture(t, db, limit)
	for _, index := range []int{0, 1, 0, 2} {
		if got := bc.GetBodyRLP(hashes[index]); !bytes.Equal(got, bodies[index]) {
			t.Fatalf("body %d changed on database/cache retrieval", index)
		}
	}
	if bc.bodyRLPCache.Contains(hashes[1]) || !bc.bodyRLPCache.Contains(hashes[0]) || !bc.bodyRLPCache.Contains(hashes[2]) {
		t.Fatal("byte pressure did not evict the least recently used encoded body")
	}
	if used, retained, entries := bodyRLPCacheUsage(bc); used != retained || used > limit || entries != 2 {
		t.Fatalf("cache usage = %d accounted/%d retained/%d entries, limit %d", used, retained, entries, limit)
	}
	// A returned body can outlive its cache entry. Eviction releases only the
	// cache's reference; durable storage and active callers still own theirs.
	borrowed := bc.GetBodyRLP(hashes[0])
	if got := bc.GetBodyRLP(hashes[1]); !bytes.Equal(got, bodies[1]) {
		t.Fatal("evicted body did not restore its exact durable bytes")
	}
	if !bytes.Equal(borrowed, bodies[0]) || !bytes.Equal(rawdb.ReadBodyRLP(db, hashes[1], 1), bodies[1]) {
		t.Fatal("cache eviction changed a borrowed body or durable storage")
	}
	bc.purgeBodyRLPCache()
	if used, retained, entries := bodyRLPCacheUsage(bc); used != 0 || retained != 0 || entries != 0 {
		t.Fatalf("purged cache usage = %d/%d/%d", used, retained, entries)
	}
	if got := bc.GetBodyRLP(hashes[0]); !bytes.Equal(got, bodies[0]) {
		t.Fatal("purged cache could not restore a durable body")
	}
}

type bodyRLPCacheReadDatabase struct {
	ethdb.Database
	body       rlp.RawValue
	directBody rlp.RawValue
	capacity   int
	reads      atomic.Int64
	started    chan struct{}
	readReady  chan struct{}
	release    chan struct{}
	blockFirst sync.Once
}

func (db *bodyRLPCacheReadDatabase) Get(key []byte) ([]byte, error) {
	value, err := db.Database.Get(key)
	if err != nil || !bytes.Equal(value, db.body) {
		return value, err
	}
	db.reads.Add(1)
	if db.readReady != nil {
		db.readReady <- struct{}{}
	}
	if db.started != nil {
		db.blockFirst.Do(func() {
			close(db.started)
			<-db.release
		})
	}
	if db.directBody != nil {
		return db.directBody, nil
	}
	if db.capacity > cap(value) {
		backing := make([]byte, len(value), db.capacity)
		copy(backing, value)
		value = backing
	}
	return value, nil
}

func TestBodyRLPCacheOversizedBackingBypassesWithoutLosingBlock(t *testing.T) {
	for _, backingOnly := range []bool{false, true} {
		t.Run(fmt.Sprintf("excess backing=%t", backingOnly), func(t *testing.T) {
			db := rawdb.NewMemoryDatabase()
			t.Cleanup(func() { db.Close() })
			smallHash, small := writeBodyRLPCacheFixture(t, db, 1, 0)
			largeHash, large := writeBodyRLPCacheFixture(t, db, 2, 256)
			limit := uint64(len(large) - 1)
			capacity := 0
			if backingOnly {
				limit = uint64(len(large))
				capacity = len(large) + 1024
			}
			reads := &bodyRLPCacheReadDatabase{Database: db, body: large, capacity: capacity}
			bc := newBodyRLPCacheFixture(t, reads, limit)
			if got := bc.GetBodyRLP(smallHash); !bytes.Equal(got, small) {
				t.Fatal("small durable body changed")
			}
			for attempt := 0; attempt < 2; attempt++ {
				if got := bc.GetBodyRLP(largeHash); !bytes.Equal(got, large) {
					t.Fatal("oversized body was rejected or changed")
				}
				if bc.bodyRLPCache.Contains(largeHash) || !bc.bodyRLPCache.Contains(smallHash) {
					t.Fatal("oversized backing was cached or evicted a useful small body")
				}
			}
			if reads.reads.Load() != 2 || rawdb.ReadBlock(db, largeHash, 1) == nil {
				t.Fatal("cache bypass did not preserve normal durable block retrieval")
			}
			if used, retained, _ := bodyRLPCacheUsage(bc); used != retained || used > limit {
				t.Fatalf("oversized bypass usage = %d/%d, limit %d", used, retained, limit)
			}
		})
	}
}

func TestBodyRLPCacheCountLimitAndMissingBodies(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { db.Close() })
	bc := newBodyRLPCacheFixture(t, db, bodyRLPCacheMemory)
	if got := bc.GetBodyRLP(common.Hash{0xff}); got != nil {
		t.Fatal("unknown block returned a body")
	}
	header := &types.Header{Number: big.NewInt(2), Difficulty: big.NewInt(1)}
	rawdb.WriteHeader(db, header)
	if got := bc.GetBodyRLP(header.Hash()); got != nil {
		t.Fatal("header without a durable body returned data")
	}
	var oldest common.Hash
	for index := 0; index <= bodyCacheLimit; index++ {
		hash, body := writeBodyRLPCacheFixture(t, db, uint64(index+1), 0)
		if index == 0 {
			oldest = hash
		}
		if got := bc.GetBodyRLP(hash); !bytes.Equal(got, body) {
			t.Fatalf("body %d changed", index)
		}
	}
	if used, retained, entries := bodyRLPCacheUsage(bc); used != retained || entries != bodyCacheLimit || bc.bodyRLPCache.Contains(oldest) {
		t.Fatalf("count eviction usage = %d/%d/%d, oldest retained=%t", used, retained, entries, bc.bodyRLPCache.Contains(oldest))
	}
}

func TestBodyRLPCachePurgeDoesNotReinsertInflightRead(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { db.Close() })
	hash, body := writeBodyRLPCacheFixture(t, db, 1, 256)
	reads := &bodyRLPCacheReadDatabase{Database: db, body: body, started: make(chan struct{}), release: make(chan struct{})}
	bc := newBodyRLPCacheFixture(t, reads, uint64(len(body)))
	done := make(chan rlp.RawValue, 1)
	go func() { done <- bc.GetBodyRLP(hash) }()
	<-reads.started
	bc.purgeBodyRLPCache()
	close(reads.release)
	if got := <-done; !bytes.Equal(got, body) {
		t.Fatal("purge changed an active caller's durable body")
	}
	if used, retained, entries := bodyRLPCacheUsage(bc); used != 0 || retained != 0 || entries != 0 {
		t.Fatalf("pre-purge read repopulated the cache: %d/%d/%d", used, retained, entries)
	}
	if got := bc.GetBodyRLP(hash); !bytes.Equal(got, body) || reads.reads.Load() != 2 {
		t.Fatal("post-purge read did not restore the body from storage")
	}
}

func TestBodyRLPCacheConcurrentReadsAndPurge(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { db.Close() })
	var hashes [8]common.Hash
	var bodies [8]rlp.RawValue
	for index := range hashes {
		hashes[index], bodies[index] = writeBodyRLPCacheFixture(t, db, uint64(index+1), 256)
	}
	bc := newBodyRLPCacheFixture(t, db, uint64(3*len(bodies[0])))
	var workers sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			for attempt := 0; attempt < 64; attempt++ {
				index := (worker + attempt) % len(hashes)
				if got := bc.GetBodyRLP(hashes[index]); !bytes.Equal(got, bodies[index]) {
					t.Errorf("concurrent retrieval changed body %d", index)
					return
				}
				if used, retained, entries := bodyRLPCacheUsage(bc); used != retained || used > bc.bodyRLPCacheLimit || entries > bodyCacheLimit {
					t.Errorf("concurrent cache usage = %d/%d/%d", used, retained, entries)
					return
				}
			}
		}(worker)
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		for attempt := 0; attempt < 64; attempt++ {
			bc.purgeBodyRLPCache()
		}
	}()
	workers.Wait()
	bc.purgeBodyRLPCache()
	if used, retained, entries := bodyRLPCacheUsage(bc); used != 0 || retained != 0 || entries != 0 {
		t.Fatalf("final purge usage = %d/%d/%d", used, retained, entries)
	}
}

func TestBodyRLPCacheConcurrentMissesRetainOneBacking(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { db.Close() })
	hash, body := writeBodyRLPCacheFixture(t, db, 1, 256)
	reads := &bodyRLPCacheReadDatabase{
		Database: db, body: body, started: make(chan struct{}),
		readReady: make(chan struct{}, 2), release: make(chan struct{}),
	}
	bc := newBodyRLPCacheFixture(t, reads, uint64(len(body)))
	results := make(chan rlp.RawValue, 2)
	for caller := 0; caller < 2; caller++ {
		go func() { results <- bc.GetBodyRLP(hash) }()
	}
	// Hold both database results until both callers have missed the cache.
	<-reads.readReady
	<-reads.readReady
	close(reads.release)
	for caller := 0; caller < 2; caller++ {
		if got := <-results; !bytes.Equal(got, body) {
			t.Fatal("concurrent miss changed a caller's durable body")
		}
	}
	if used, retained, entries := bodyRLPCacheUsage(bc); used != uint64(len(body)) || retained != used || entries != 1 {
		t.Fatalf("duplicate miss retained/accounted more than one body: %d/%d/%d", used, retained, entries)
	}
	if got := bc.GetBodyRLP(hash); !bytes.Equal(got, body) || reads.reads.Load() != 2 {
		t.Fatal("duplicate misses did not leave one usable cached body")
	}
}

func TestBodyRLPCacheBudgetPreserves256MiBGenesisPolicy(t *testing.T) {
	config := &params.ChainConfig{NativeParallel: params.SolanaScaleNativeParallelConfig()}
	const maxBlockBytes = uint64(256 * 1024 * 1024)
	if config.EffectiveMaxBlockBytes() != maxBlockBytes {
		t.Fatal("genesis execution policy changed its 256 MiB block ceiling")
	}
	// Cache eligibility has no role in block validity. The metadata arithmetic
	// demonstrates why one valid maximum-sized body must bypass this cache,
	// without allocating it or retaining 128 such bodies in the fixture.
	if bodyRLPCacheMemory >= maxBlockBytes || uint64(bodyCacheLimit)*maxBlockBytes <= bodyRLPCacheMemory {
		t.Fatal("encoded-body cache budget does not bound maximum block retention")
	}
}

func TestBodyRLPCacheMaximumRawEnvelopeBypasses(t *testing.T) {
	if testing.Short() {
		t.Skip("run the maximum raw storage-envelope case separately from small fixtures")
	}
	config := &params.ChainConfig{NativeParallel: params.SolanaScaleNativeParallelConfig()}
	size := config.EffectiveMaxBlockBytes()
	if size != 256*1024*1024 {
		t.Fatalf("maximum storage-envelope fixture expects the current 256 MiB genesis block policy, got %d", size)
	}
	db := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { db.Close() })
	hash, marker := writeBodyRLPCacheFixture(t, db, 1, 0)
	// One backing array crosses the real GetBodyRLP/rawdb path. The database
	// wrapper substitutes it for a tiny stored marker to avoid extra copies.
	// This checks raw retrieval and cache bypass, not EVM block validity/import.
	body := make(rlp.RawValue, int(size))
	for index := range body {
		body[index] = 0x5a
	}
	body[0], body[len(body)/2], body[len(body)-1] = 0xf8, 0x42, 0xa5
	reads := &bodyRLPCacheReadDatabase{Database: db, body: marker, directBody: body}
	bc := newBodyRLPCacheFixture(t, reads, bodyRLPCacheMemory)
	for attempt := 0; attempt < 2; attempt++ {
		got := bc.GetBodyRLP(hash)
		if len(got) != len(body) || &got[0] != &body[0] || got[0] != 0xf8 || got[len(got)/2] != 0x42 || got[len(got)-1] != 0xa5 {
			t.Fatal("maximum raw storage envelope was rejected, copied, or changed")
		}
	}
	if reads.reads.Load() != 2 {
		t.Fatal("maximum envelope was retained instead of read from storage again")
	}
	if used, retained, entries := bodyRLPCacheUsage(bc); used != 0 || retained != 0 || entries != 0 {
		t.Fatalf("maximum envelope retained cache bytes: %d/%d/%d", used, retained, entries)
	}
}

func newReceiptCacheFixture(t *testing.T, db ethdb.Database, limit uint64) *BlockChain {
	t.Helper()
	cache, err := lru.New(receiptsCacheLimit)
	if err != nil {
		t.Fatal(err)
	}
	return &BlockChain{db: db, chainConfig: evmOnlyNativeConfig(), receiptsCache: cache, receiptsCacheLimit: limit}
}

func writeReceiptCacheFixture(t *testing.T, db ethdb.Database, nonce uint64, payload int) (*types.Block, types.Receipts) {
	t.Helper()
	config := evmOnlyNativeConfig()
	key, err := crypto.HexToECDSA("1111111111111111111111111111111111111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	creation, err := types.SignTx(types.NewContractCreation(nonce, new(big.Int), params.TxGas, big.NewInt(1), nil), types.LatestSignerForChainID(config.ChainID), key)
	if err != nil {
		t.Fatal(err)
	}
	to := common.Address{1}
	txs := types.Transactions{
		creation,
		types.NewTx(&types.AccessListTx{ChainID: config.ChainID, Nonce: nonce, To: &to, GasPrice: big.NewInt(1), Value: new(big.Int)}),
		types.NewTx(&types.DynamicFeeTx{ChainID: config.ChainID, Nonce: nonce, To: &to, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2), Value: new(big.Int)}),
		// This is a storage/receipt fixture, not blob execution validation. An
		// empty structural sidecar keeps the type-3 roundtrip small.
		types.NewTx(&types.BlobTx{ChainID: config.ChainID, Nonce: nonce, To: to, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2), BlobFeeCap: big.NewInt(1), Value: new(big.Int), Sidecar: &types.BlobTxSidecar{}}),
		types.NewTx(&types.SetCodeTx{ChainID: config.ChainID, Nonce: nonce, To: to, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2), Value: new(big.Int)}),
	}
	receipts := make(types.Receipts, len(txs))
	for index := range receipts {
		receipts[index] = &types.Receipt{
			Type: uint8(index), Status: uint64(index % 2), CumulativeGasUsed: uint64(index+1) * params.TxGas,
			Logs: []*types.Log{{Address: to, Topics: []common.Hash{{byte(index + 1)}}, Data: bytes.Repeat([]byte{byte(nonce)}, payload)}},
		}
		receipts[index].Bloom = types.CreateBloom(types.Receipts{receipts[index]})
	}
	block := types.NewBlock(&types.Header{Number: new(big.Int).SetUint64(nonce + 1), Difficulty: big.NewInt(1)}, txs, nil, receipts, new(trie.Trie))
	if err := receipts.DeriveFields(config, block.Hash(), block.NumberU64(), txs); err != nil {
		t.Fatal(err)
	}
	if receipts[0].ContractAddress != crypto.CreateAddress(crypto.PubkeyToAddress(key.PublicKey), nonce) || types.DeriveSha(receipts, new(trie.Trie)) != block.ReceiptHash() || types.CreateBloom(receipts) != block.Bloom() {
		t.Fatal("receipt fixture lost derived contract address, receipt root, or bloom")
	}
	if _, err := rlp.EncodeToBytes(block.Body()); err != nil {
		t.Fatalf("encode receipt fixture body: %v", err)
	}
	rawdb.WriteBlock(db, block)
	rawdb.WriteReceipts(db, block.Hash(), block.NumberU64(), receipts)
	decoded := rawdb.ReadReceipts(db, block.Hash(), block.NumberU64(), config)
	if !reflect.DeepEqual(decoded, receipts) {
		t.Fatal("durable fixture changed receipt types, consensus fields, or derived metadata")
	}
	return block, decoded
}

func receiptCacheUsage(bc *BlockChain) (used, retained uint64, entries int) {
	bc.receiptsCacheMu.Lock()
	defer bc.receiptsCacheMu.Unlock()
	for _, hash := range bc.receiptsCache.Keys() {
		value, _ := bc.receiptsCache.Peek(hash)
		weight, _ := receiptCacheWeight(value.(receiptCacheEntry).receipts, ^uint64(0))
		retained += weight
	}
	return bc.receiptsCacheBytes, retained, bc.receiptsCache.Len()
}

func TestReceiptCacheAccountsSpareBackingAndBigIntWords(t *testing.T) {
	receipt := &types.Receipt{BlockNumber: big.NewInt(1), Logs: []*types.Log{{Topics: []common.Hash{{1}}, Data: []byte{2}}}, PostState: []byte{3}}
	receipts := types.Receipts{receipt}
	base, fits := receiptCacheWeight(receipts, ^uint64(0))
	if !fits || base == 0 {
		t.Fatal("small receipt did not have a nonzero weight")
	}
	receipts = append(make(types.Receipts, 0, 4), receipt)
	receipt.PostState = make([]byte, 1, 8)
	receipt.Logs = append(make([]*types.Log, 0, 3), receipt.Logs[0])
	receipt.Logs[0].Topics = make([]common.Hash, 1, 5)
	receipt.Logs[0].Data = make([]byte, 1, 64)
	receipt.BlockNumber = new(big.Int).SetBits(make([]big.Word, 1, 9))
	receipt.BlockNumber.SetUint64(1)
	weight, fits := receiptCacheWeight(receipts, ^uint64(0))
	wantExtra := uint64((3+2)*unsafe.Sizeof((*types.Log)(nil)) + 7 + 4*common.HashLength + 63 + uintptr(cap(receipt.BlockNumber.Bits())-1)*unsafe.Sizeof(big.Word(0)))
	if !fits || weight != base+wantExtra {
		t.Fatalf("spare backing weight=%d, want %d", weight, base+wantExtra)
	}
	if exact, fits := receiptCacheWeight(receipts, weight); !fits || exact != weight {
		t.Fatal("exact accounted-byte boundary did not fit")
	}
	if _, fits := receiptCacheWeight(receipts, weight-1); fits {
		t.Fatal("one-byte-over-budget receipt fit")
	}
	if _, fits := receiptCacheWeight(receipts, 0); fits {
		t.Fatal("zero budget admitted nonempty receipts")
	}
}

func TestReceiptCacheEvictionAndPurgeRestoreFullyDerivedReceipts(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { db.Close() })
	var blocks [3]*types.Block
	var receipts [3]types.Receipts
	for index := range blocks {
		blocks[index], receipts[index] = writeReceiptCacheFixture(t, db, uint64(index+1), 32)
	}
	weight, _ := receiptCacheWeight(receipts[0], ^uint64(0))
	bc := newReceiptCacheFixture(t, db, 2*weight)
	for _, index := range []int{0, 1, 0, 2} {
		if got := bc.GetReceiptsByHash(blocks[index].Hash()); !reflect.DeepEqual(got, receipts[index]) {
			t.Fatalf("receipt batch %d changed", index)
		}
	}
	if bc.receiptsCache.Contains(blocks[1].Hash()) || !bc.receiptsCache.Contains(blocks[0].Hash()) || !bc.receiptsCache.Contains(blocks[2].Hash()) {
		t.Fatal("byte eviction did not remove the least recently used receipt batch")
	}
	borrowed := bc.GetReceiptsByHash(blocks[0].Hash())
	if got := bc.GetReceiptsByHash(blocks[1].Hash()); !reflect.DeepEqual(got, receipts[1]) || !reflect.DeepEqual(borrowed, receipts[0]) {
		t.Fatal("durable replay or borrowed receipts changed during eviction")
	}
	if used, retained, entries := receiptCacheUsage(bc); used != retained || used > 2*weight || entries != 2 {
		t.Fatalf("receipt cache usage=%d/%d/%d", used, retained, entries)
	}
	bc.purgeReceiptsCache()
	if used, retained, entries := receiptCacheUsage(bc); used != 0 || retained != 0 || entries != 0 {
		t.Fatalf("purge retained receipt cache usage=%d/%d/%d", used, retained, entries)
	}
	if got := bc.GetReceiptsByHash(blocks[0].Hash()); !reflect.DeepEqual(got, receipts[0]) {
		t.Fatal("purged receipts did not replay with all fields intact")
	}
}

func TestReceiptCacheOversizeAndZeroBudgetBypassDurably(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { db.Close() })
	smallBlock, small := writeReceiptCacheFixture(t, db, 1, 0)
	largeBlock, large := writeReceiptCacheFixture(t, db, 2, 1024)
	smallWeight, _ := receiptCacheWeight(small, ^uint64(0))
	for _, limit := range []uint64{0, smallWeight} {
		bc := newReceiptCacheFixture(t, db, limit)
		if got := bc.GetReceiptsByHash(smallBlock.Hash()); !reflect.DeepEqual(got, small) {
			t.Fatal("small receipt batch changed")
		}
		for attempt := 0; attempt < 2; attempt++ {
			if got := bc.GetReceiptsByHash(largeBlock.Hash()); !reflect.DeepEqual(got, large) {
				t.Fatal("oversized valid receipt batch was rejected or changed")
			}
		}
		if bc.receiptsCache.Contains(largeBlock.Hash()) || bc.receiptsCache.Contains(smallBlock.Hash()) != (limit != 0) {
			t.Fatal("oversized batch was retained or displaced the useful small batch")
		}
		if used, retained, _ := receiptCacheUsage(bc); used != retained || used > limit {
			t.Fatalf("bypass cache usage=%d/%d, limit=%d", used, retained, limit)
		}
	}
}

func TestReceiptCacheCountLimitAndMissingDurableData(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { db.Close() })
	bc := newReceiptCacheFixture(t, db, receiptsCacheMemory)
	if got := bc.GetReceiptsByHash(common.Hash{0xff}); got != nil {
		t.Fatal("unknown hash returned receipts")
	}
	block, _ := writeReceiptCacheFixture(t, db, 1, 0)
	rawdb.DeleteBody(db, block.Hash(), block.NumberU64())
	if got := bc.GetReceiptsByHash(block.Hash()); got != nil {
		t.Fatal("receipts without durable body were returned")
	}
	rawdb.WriteBlock(db, block)
	rawdb.DeleteReceipts(db, block.Hash(), block.NumberU64())
	if got := bc.GetReceiptsByHash(block.Hash()); got != nil {
		t.Fatal("body without durable receipts returned data")
	}
	var oldest common.Hash
	for index := 0; index <= receiptsCacheLimit; index++ {
		block, receipts := writeReceiptCacheFixture(t, db, uint64(index+2), 0)
		if index == 0 {
			oldest = block.Hash()
		}
		if got := bc.GetReceiptsByHash(block.Hash()); !reflect.DeepEqual(got, receipts) {
			t.Fatal("count-limit retrieval changed receipts")
		}
	}
	if used, retained, entries := receiptCacheUsage(bc); used != retained || used > receiptsCacheMemory || entries != receiptsCacheLimit || bc.receiptsCache.Contains(oldest) {
		t.Fatalf("count eviction usage=%d/%d/%d", used, retained, entries)
	}
}

func TestReceiptCachePurgeAndDuplicateInflightReads(t *testing.T) {
	for _, purge := range []bool{false, true} {
		t.Run(fmt.Sprintf("purge=%t", purge), func(t *testing.T) {
			db := rawdb.NewMemoryDatabase()
			t.Cleanup(func() { db.Close() })
			block, receipts := writeReceiptCacheFixture(t, db, 1, 32)
			// Reuse the blocking database wrapper with receipt RLP as its marker.
			marker := rawdb.ReadReceiptsRLP(db, block.Hash(), block.NumberU64())
			reads := &bodyRLPCacheReadDatabase{Database: db, body: marker, started: make(chan struct{}), readReady: make(chan struct{}, 2), release: make(chan struct{})}
			weight, _ := receiptCacheWeight(receipts, ^uint64(0))
			bc := newReceiptCacheFixture(t, reads, weight)
			results := make(chan types.Receipts, 2)
			for caller := 0; caller < 2; caller++ {
				go func() { results <- bc.GetReceiptsByHash(block.Hash()) }()
			}
			<-reads.readReady
			<-reads.readReady
			if purge {
				bc.purgeReceiptsCache()
			}
			close(reads.release)
			for caller := 0; caller < 2; caller++ {
				if got := <-results; !reflect.DeepEqual(got, receipts) {
					t.Fatal("inflight receipt read changed")
				}
			}
			wantEntries := 1
			if purge {
				wantEntries = 0
			}
			if used, retained, entries := receiptCacheUsage(bc); used != retained || used != uint64(wantEntries)*weight || entries != wantEntries {
				t.Fatalf("inflight receipt cache usage=%d/%d/%d, want %d entries", used, retained, entries, wantEntries)
			}
			if got := bc.GetReceiptsByHash(block.Hash()); !reflect.DeepEqual(got, receipts) || reads.reads.Load() != int64(2+1-wantEntries) {
				t.Fatal("post-inflight retrieval did not use expected durable/cache path")
			}
		})
	}
}

func TestReceiptCacheConcurrentReadsAndPurge(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { db.Close() })
	var blocks [4]*types.Block
	var receipts [4]types.Receipts
	for index := range blocks {
		blocks[index], receipts[index] = writeReceiptCacheFixture(t, db, uint64(index+1), 32)
	}
	weight, _ := receiptCacheWeight(receipts[0], ^uint64(0))
	bc := newReceiptCacheFixture(t, db, 2*weight)
	var workers sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			for attempt := 0; attempt < 16; attempt++ {
				index := (worker + attempt) % len(blocks)
				if got := bc.GetReceiptsByHash(blocks[index].Hash()); !reflect.DeepEqual(got, receipts[index]) {
					t.Error("concurrent retrieval changed receipt fields")
					return
				}
				if used, retained, entries := receiptCacheUsage(bc); used != retained || used > 2*weight || entries > receiptsCacheLimit {
					t.Errorf("concurrent receipt cache usage=%d/%d/%d", used, retained, entries)
					return
				}
			}
		}(worker)
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		for attempt := 0; attempt < 16; attempt++ {
			bc.purgeReceiptsCache()
		}
	}()
	workers.Wait()
	bc.purgeReceiptsCache()
	if used, retained, entries := receiptCacheUsage(bc); used != 0 || retained != 0 || entries != 0 {
		t.Fatalf("final receipt cache purge usage=%d/%d/%d", used, retained, entries)
	}
}
