package core

import (
	//	"bytes"

	"sync"
	"sync/atomic"

	"errors"
	"fmt"
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rlp"
	lru "github.com/hashicorp/golang-lru"
)

var (
	ErrNoKeyGenesis         = errors.New("Genesis not found in key block chain")
	ErrNoGenCommittee       = errors.New("Genesis not found in db")
	ErrNonCanonicalKeyBlock = errors.New("key block does not extend the canonical key head")
)

type KeyBlockChain struct {
	chainConfig *params.ChainConfig // Chain & network configuration
	db          ethdb.Database      // Low level persistent database to store final content in

	khc *KeyHeaderChain
	//chainFeed     event.Feed
	chainHeadFeed event.Feed
	scope         event.SubscriptionScope
	genesisBlock  *types.KeyBlock

	mu      sync.RWMutex // global mutex for locking chain operations
	chainmu sync.RWMutex // insertion lock
	procmu  sync.RWMutex // block processor lock

	currentBlock atomic.Value // Current head of the block chain

	blockCache    *lru.Cache // Cache for the most recent entire blocks
	blockRLPCache *lru.Cache // Cache for the most recent entire blocks in rlp format

	running int32 // running must be called atomically

	// procInterrupt must be atomically called
	procInterrupt int32          // interrupt signaler for block processing
	wg            sync.WaitGroup // chain processing wait group for shutting down

	engine consensus.Engine
	mux    *event.TypeMux

	candidatePool *CandidatePool

	backend Backend
}

// NewKeyBlockChain returns a fully initialised key block chain using information
// available in the database.
func NewKeyBlockChain(cph Backend, db ethdb.Database, cacheConfig *CacheConfig, chainConfig *params.ChainConfig, engine consensus.Engine, mux *event.TypeMux) (*KeyBlockChain, error) {
	blockCache, _ := lru.New(blockCacheLimit)
	blockRLPCache, _ := lru.New(bodyCacheLimit)

	kbc := &KeyBlockChain{
		chainConfig:   chainConfig,
		db:            db,
		blockCache:    blockCache,
		blockRLPCache: blockRLPCache,
		engine:        engine,
		mux:           mux,
		backend:       cph,
		candidatePool: cph.CandidatePool(),
	}

	var err error
	kbc.khc, err = NewKeyHeaderChain(db, chainConfig, kbc.getProcInterrupt)
	if err != nil {
		return nil, err
	}

	h := kbc.GetHeaderByNumber(0)
	if h == nil {
		return nil, ErrNoGenesis
	}
	committee0 := bftview.LoadMember(0, h.Hash(), false)
	if committee0 == nil {
		log.Info("NewKeyBlockChain committee0 nil")
		return nil, ErrNoGenCommittee
	}

	kbc.genesisBlock = kbc.GetBlockByNumber(0)
	if kbc.genesisBlock == nil {
		return nil, ErrNoKeyGenesis
	}

	if err := kbc.loadLastState(); err != nil {
		return nil, err
	}

	return kbc, nil
}

func (kbc *KeyBlockChain) Genesis() *types.KeyBlock {
	return kbc.genesisBlock
}
func (kbc *KeyBlockChain) getProcInterrupt() bool {
	return atomic.LoadInt32(&kbc.procInterrupt) == 1
}
func (kbc *KeyBlockChain) GetBlockByNumber(number uint64) *types.KeyBlock {
	hash := rawdb.ReadKeyBlockHash(kbc.db, number)
	if hash == (common.Hash{}) {
		return nil
	}
	return kbc.GetBlock(hash, number)
}

// GetBlockByHash retrieves a block from the database by hash, caching it if found.
func (kbc *KeyBlockChain) GetBlockByHash(hash common.Hash) *types.KeyBlock {
	number := kbc.khc.GetBlockNumber(hash)
	if number == nil {
		return nil
	}
	return kbc.GetBlock(hash, *number)
}
func (kbc *KeyBlockChain) HasBlock(hash common.Hash, number uint64) bool {
	if kbc.blockCache.Contains(hash) {
		return true
	}
	return rawdb.HasKeyBlockBody(kbc.db, hash, number)
}

// GetBlock retrieves a block from the database by hash and number,
// caching it if found.
func (kbc *KeyBlockChain) GetBlock(hash common.Hash, number uint64) *types.KeyBlock {
	// Short circuit if the block's already in the cache, retrieve otherwise
	if block, ok := kbc.blockCache.Get(hash); ok {
		return block.(*types.KeyBlock)
	}
	block := rawdb.ReadKeyBlock(kbc.db, hash, number)
	if block == nil {
		return nil
	}

	// Cache the found block for next time and return
	kbc.blockCache.Add(block.Hash(), block)
	return block
}

// GetTd retrieves a block's total difficulty in the canonical chain from the
// database by hash and number, caching it if found.
func (kbc *KeyBlockChain) GetTd(hash common.Hash, number uint64) *big.Int {
	return kbc.khc.GetTd(hash, number)
}
func (kbc *KeyBlockChain) CurrentBlock() *types.KeyBlock {
	return kbc.currentBlock.Load().(*types.KeyBlock)
}
func (kbc *KeyBlockChain) CurrentBlockN() uint64 {
	return kbc.CurrentBlock().NumberU64()
}
func (kbc *KeyBlockChain) CurrentBlockStore(block *types.KeyBlock) {
	kbc.currentBlock.Store(block)
}

// GetKeyHeaderByHash retrieves a block header from the database by hash, caching it if
// found.
func (kbc *KeyBlockChain) GetHeaderByHash(hash common.Hash) *types.KeyBlockHeader {
	return kbc.khc.GetHeaderByHash(hash)
}

// GetKeyHeaderByNumber retrieves a block header from the database by number,
// caching it (associated with its hash) if found.
func (kbc *KeyBlockChain) GetHeaderByNumber(number uint64) *types.KeyBlockHeader {
	return kbc.khc.GetHeaderByNumber(number)
}
func (kbc *KeyBlockChain) CurrentHeader() *types.KeyBlockHeader {
	return kbc.khc.CurrentHeader()
}
func (kbc *KeyBlockChain) GetHeader(hash common.Hash, number uint64) *types.KeyBlockHeader {
	return kbc.khc.GetHeader(hash, number)
}

// Reset purges the entire blockchain, restoring it to its genesis state.
func (kbc *KeyBlockChain) Reset() error {
	return kbc.ResetWithGenesisBlock(kbc.genesisBlock)
}

// ResetWithGenesisBlock purges the entire blockchain, restoring it to the
// specified genesis state.
func (kbc *KeyBlockChain) ResetWithGenesisBlock(genesis *types.KeyBlock) error {
	if genesis == nil {
		return ErrNoKeyGenesis
	}
	kbc.chainmu.Lock()
	defer kbc.chainmu.Unlock()
	var oldHead uint64
	if value := kbc.currentBlock.Load(); value != nil && value.(*types.KeyBlock) != nil {
		oldHead = value.(*types.KeyBlock).NumberU64()
	}
	batch := kbc.db.NewBatch()
	for number := genesis.NumberU64() + 1; number <= oldHead; number++ {
		rawdb.DeleteKeyBlockHash(batch, number)
	}
	kbc.stageCanonicalKeyBlock(batch, genesis)
	if err := batch.Write(); err != nil {
		return fmt.Errorf("failed to reset key block chain: %w", err)
	}
	kbc.genesisBlock = genesis.CopyMe()
	kbc.setCanonicalKeyBlock(genesis)
	if kbc.khc != nil {
		kbc.khc.SetGenesis(genesis.Header())
	}
	return nil
}

// loadLastState loads the last known chain state from the database. This method
// assumes that the chain manager mutex is held.
func (kbc *KeyBlockChain) loadLastState() error {
	// Restore the last known head block
	head := rawdb.ReadHeadKeyBlockHash(kbc.db)
	if head == (common.Hash{}) {
		// Corrupt or empty database, init from scratch
		log.Warn("Empty database, resetting chain")
		return kbc.Reset()
	}
	// Make sure the entire head block is available
	currentBlock := kbc.GetBlockByHash(head)
	if currentBlock == nil {
		// Corrupt or empty database, init from scratch
		log.Warn("Head block missing, resetting chain", "hash", head)
		return kbc.Reset()
	}

	// Everything seems to be fine, set as the head block
	kbc.currentBlock.Store(currentBlock)
	// Restore the last known head header
	currentHeader := currentBlock.Header()
	if head := rawdb.ReadHeadKeyHeaderHash(kbc.db); head != (common.Hash{}) {
		if header := kbc.GetHeaderByHash(head); header != nil {
			currentHeader = header
		}
	}
	kbc.khc.SetCurrentHeader(currentHeader)

	headerTd := kbc.GetTd(currentHeader.Hash(), currentHeader.Number.Uint64())
	blockTd := kbc.GetTd(currentBlock.Hash(), currentBlock.NumberU64())

	log.Info("Loaded most recent local keyblock header", "number", currentHeader.Number, "hash", currentHeader.Hash(), "td", headerTd)
	log.Info("Loaded most recent local full keyblock", "number", currentBlock.Number(), "hash", currentBlock.Hash(), "td", blockTd)

	return nil
}

// insert injects a new head keyblock into the current keyblock chain.
// Note, this function assumes that the `mu` mutex is held!
func (kbc *KeyBlockChain) insert(block *types.KeyBlock) error {
	if err := kbc.khc.WriteTd(block.Hash(), block.NumberU64(), block.Difficulty()); err != nil {
		return err
	}
	rawdb.WriteKeyBlock(kbc.db, block)
	rawdb.WriteKeyBlockHash(kbc.db, block.Hash(), block.NumberU64())
	rawdb.WriteHeadKeyBlockHash(kbc.db, block.Hash())

	kbc.currentBlock.Store(block)
	kbc.khc.SetCurrentHeader(block.Header())

	return nil
}

func (kbc *KeyBlockChain) InsertBlockFromData(data []byte) error {
	b := types.DecodeToKeyBlock(data)
	if b == nil {
		return fmt.Errorf("invalid encoded key block")
	}
	_, err := kbc.insert_Chain(types.KeyBlocks{b})
	if err != nil && kbc.candidatePool != nil {
		kbc.candidatePool.ClearObsolete(b.Number())
	}
	return err
}

// InsertChain attempts to insert the given batch of key blocks in to the keyblock
// chain. If an error is returned it will return the index number of the failing block
// as well an error describing what went wrong.
func (kbc *KeyBlockChain) insert_Chain(chain types.KeyBlocks) (int, error) {
	// Sanity check that we have something meaningful to import
	if len(chain) == 0 {
		return 0, nil
	}
	// Do a sanity check that the provided chain is actually ordered and linked
	for i := 1; i < len(chain); i++ {
		if chain[i].NumberU64() != chain[i-1].NumberU64()+1 || chain[i].ParentHash() != chain[i-1].Hash() {
			// Chain broke ancestry, log a messge (programming error) and skip insertion
			log.Error("Non contiguous key block insert", "number", chain[i].Number(), "hash", chain[i].Hash(),
				"parent", chain[i].ParentHash(), "prevnumber", chain[i-1].Number(), "prevhash", chain[i-1].Hash())

			return 0, fmt.Errorf("non contiguous insert: item %d is #%d [%x…], item %d is #%d [%x…] (parent [%x…])", i-1, chain[i-1].NumberU64(),
				chain[i-1].Hash().Bytes()[:4], i, chain[i].NumberU64(), chain[i].Hash().Bytes()[:4], chain[i].ParentHash().Bytes()[:4])
		}
	}
	// Pre-checks passed, start the full block imports
	kbc.wg.Add(1)
	defer kbc.wg.Done()

	kbc.chainmu.Lock()
	defer kbc.chainmu.Unlock()

	currentBlock := kbc.CurrentBlock()
	var lastBlock *types.KeyBlock

	// Iterate over the blocks and insert when the verifier permits
	for i, block := range chain {
		// If the chain is terminating, stop processing blocks
		if atomic.LoadInt32(&kbc.procInterrupt) == 1 {
			log.Debug("Premature abort during key blocks processing")
			break
		}

		err := kbc.ValidateKeyBlock(block)
		switch {
		case err == types.ErrKnownBlock:
			// The exact current head is an idempotent re-import. A known direct
			// child can be applied after a crash that persisted its body before
			// advancing the head. Any other known block is a sibling or stale
			// branch and must not replace the canonical key head.
			current := kbc.CurrentBlock()
			if current.Hash() == block.Hash() && current.NumberU64() == block.NumberU64() {
				continue
			}
			if block.NumberU64() != current.NumberU64()+1 || block.ParentHash() != current.Hash() {
				err = fmt.Errorf("%w: known block=%d/%s parent=%s head=%d/%s", ErrNonCanonicalKeyBlock,
					block.NumberU64(), block.Hash(), block.ParentHash(), current.NumberU64(), current.Hash())
				kbc.reportBlock(block, err)
				return i, err
			}

		case err != nil:
			kbc.reportBlock(block, err)
			return i, err

			continue
		}

		if err := kbc.insert(block); err != nil {
			return i, err
		}
		lastBlock = block
	}

	if lastBlock != nil && currentBlock.Hash() != lastBlock.Hash() {
		//go kbc.mux.Post(KeyChainHeadEvent{KeyBlock: lastBlock})
		//kbc.chainHeadFeed.Send(KeyChainHeadEvent{KeyBlock: lastBlock})
	}

	return 0, nil
}

func (kbc *KeyBlockChain) PostBlock(block *types.KeyBlock) {
	kbc.chainHeadFeed.Send(KeyChainHeadEvent{KeyBlock: block})
}

func (kbc *KeyBlockChain) reportBlock(block *types.KeyBlock, err error) {
	log.Warn(fmt.Sprintf(`
########## KEY BLOCK #########
Number: %v
Hash: 0x%x

Error: %v
##############################
`, block.Number(), block.Hash(), err))
}

// Stop stops the key blockchain service. If any imports are currently in progress
// it will abort them using the procInterrupt.
func (kbc *KeyBlockChain) Stop() {
	if !atomic.CompareAndSwapInt32(&kbc.running, 0, 1) {
		return
	}
	// Unsubscribe all subscriptions registered from blockchain
	kbc.scope.Close()
	atomic.StoreInt32(&kbc.procInterrupt, 1)

	kbc.wg.Wait()

	log.Info("key blockchain manager stopped")
}

func (kbc *KeyBlockChain) FinalizeKeyBlock(header *types.KeyBlockHeader) (*types.KeyBlock, error) {
	return types.NewKeyBlock(header), nil
}

// Config retrieves the blockchain's chain configuration.
func (kbc *KeyBlockChain) Config() *params.ChainConfig { return kbc.chainConfig }

func (kbc *KeyBlockChain) MockBlock(amount int64) {
	genKeyBlock := func(i int, parent *types.KeyBlock) *types.KeyBlock {
		b := types.NewKeyBlock(makeKeyHeader(nil, parent, kbc.engine))

		return b.CopyMe()
	}

	blocks := make([]*types.KeyBlock, 0, amount)
	parent := kbc.CurrentBlock()

	for i := 0; i < int(amount); i++ {
		block := genKeyBlock(1, parent)
		log.Trace("Mock key block", "number", block.NumberU64(), "parentNumber", parent.NumberU64())
		blocks = append(blocks, block)

		parent = block
	}

	log.Info("Mock key block", "amount", amount)

	kbc.insert_Chain(blocks)
}

// GetBlockRLPByHash retrieves a block in RLP encoding from the database by hash,
// caching it if found.
func (kbc *KeyBlockChain) GetBlockRLPByHash(hash common.Hash) rlp.RawValue {
	// Short circuit if the blocks's already in the cache, retrieve otherwise
	if cached, ok := kbc.blockRLPCache.Get(hash); ok {
		return cached.([]uint8)
	}
	number := kbc.khc.GetBlockNumber(hash)
	if number == nil {
		log.Trace("Get block number by hash returns err", "hash", hash.Hex())
		return nil
	}
	block := rawdb.ReadKeyBlock(kbc.db, hash, *number)
	if block == nil {
		log.Trace("Read key block returns error", "hash", hash.Hex(), "number", *number)
		return nil
	}

	rlpBlock, err := rlp.EncodeToBytes(block)
	if err == nil {
		kbc.blockRLPCache.Add(hash, rlpBlock)
		return rlpBlock
	} else {
		return nil
	}
}
func (kbc *KeyBlockChain) GetBlockRLPByNumber(number uint64) rlp.RawValue {
	hash := rawdb.ReadKeyBlockHash(kbc.db, number)
	if hash == (common.Hash{}) {
		return nil
	}

	return kbc.GetBlockRLPByHash(hash)
}
func (kbc *KeyBlockChain) EncodeBlockToBytes(hash common.Hash, block *types.KeyBlock) rlp.RawValue {
	// Short circuit if the blocks's already in the cache, retrieve otherwise
	if cached, ok := kbc.blockRLPCache.Get(hash); ok {
		return cached.([]uint8)
	}

	rlpBlock, err := rlp.EncodeToBytes(block)
	if err == nil {
		kbc.blockRLPCache.Add(hash, rlpBlock)
		return rlpBlock
	} else {
		return nil
	}
}

func (kbc *KeyBlockChain) ValidateKeyBlock(block *types.KeyBlock) error {
	if block == nil {
		return fmt.Errorf("%w: nil block", ErrNonCanonicalKeyBlock)
	}
	blockNumber := block.NumberU64()
	if kbc.HasBlock(block.Hash(), blockNumber) {
		return types.ErrKnownBlock
	}
	if blockNumber == 0 {
		return fmt.Errorf("%w: unexpected genesis block", ErrNonCanonicalKeyBlock)
	}
	if !kbc.HasBlock(block.ParentHash(), blockNumber-1) {
		return types.ErrUnknownAncestor
	}
	current := kbc.CurrentBlock()
	if blockNumber != current.NumberU64()+1 || block.ParentHash() != current.Hash() {
		return fmt.Errorf("%w: block=%d/%s parent=%s head=%d/%s", ErrNonCanonicalKeyBlock,
			blockNumber, block.Hash(), block.ParentHash(), current.NumberU64(), current.Hash())
	}
	return nil
}

// ValidateKeyBlockForCanonicalInsert is the preflight used by the transaction
// chain before it makes a key-carrying block canonical. A key transition must
// extend the exact current key head; a sibling at the same height must never
// replace it.
func (kbc *KeyBlockChain) ValidateKeyBlockForCanonicalInsert(block *types.KeyBlock) error {
	if block == nil {
		return fmt.Errorf("%w: nil block", ErrNonCanonicalKeyBlock)
	}
	if block.NumberU64() == 0 {
		return fmt.Errorf("%w: unexpected genesis block", ErrNonCanonicalKeyBlock)
	}
	current := kbc.CurrentBlock()
	if block.NumberU64() != current.NumberU64()+1 || block.ParentHash() != current.Hash() {
		return fmt.Errorf("%w: block=%d/%s parent=%s head=%d/%s", ErrNonCanonicalKeyBlock,
			block.NumberU64(), block.Hash(), block.ParentHash(), current.NumberU64(), current.Hash())
	}
	if !kbc.HasBlock(current.Hash(), current.NumberU64()) {
		return fmt.Errorf("%w: canonical parent %d/%s is missing", types.ErrUnknownAncestor,
			current.NumberU64(), current.Hash())
	}
	return nil
}

// stageCanonicalKeyBlock writes all durable key-head records into the caller's
// batch. The transaction-chain head and key-chain head therefore become visible
// atomically when both chains share the same database.
func (kbc *KeyBlockChain) stageCanonicalKeyBlock(batch ethdb.KeyValueWriter, block *types.KeyBlock) {
	rawdb.WriteTd(batch, block.Hash(), block.NumberU64(), block.Difficulty())
	rawdb.WriteKeyBlock(batch, block)
	rawdb.WriteKeyBlockHash(batch, block.Hash(), block.NumberU64())
	rawdb.WriteHeadKeyBlockHash(batch, block.Hash())
	rawdb.WriteHeadKeyHeaderHash(batch, block.Hash())
}

// setCanonicalKeyBlock updates in-memory key-chain markers after the shared
// transaction/key head batch has committed successfully.
func (kbc *KeyBlockChain) setCanonicalKeyBlock(block *types.KeyBlock) {
	block = block.CopyMe()
	if kbc.blockCache != nil {
		kbc.blockCache.Add(block.Hash(), block)
	}
	if kbc.khc != nil {
		header := block.Header()
		if kbc.khc.headerCache != nil {
			kbc.khc.headerCache.Add(block.Hash(), header)
		}
		if kbc.khc.numberCache != nil {
			kbc.khc.numberCache.Add(block.Hash(), block.NumberU64())
		}
		if kbc.khc.tdCache != nil {
			kbc.khc.tdCache.Add(block.Hash(), block.Difficulty())
		}
		kbc.khc.currentHeader.Store(header)
		kbc.khc.currentHeaderHash = block.Hash()
	}
	kbc.currentBlock.Store(block)
}

// SubscribeChainEvent registers a subscription of ChainEvent.
func (kbc *KeyBlockChain) SubscribeChainEvent(ch chan<- KeyChainHeadEvent) event.Subscription {
	return kbc.scope.Track(kbc.chainHeadFeed.Subscribe(ch))
}
func (kbc *KeyBlockChain) GetCommitteeByHash(hash common.Hash) []*common.Cnode {
	number := kbc.khc.GetBlockNumber(hash)
	if number == nil {
		return nil
	}
	header := kbc.khc.GetHeader(hash, *number)
	if header == nil {
		log.Warn("GetCommitteeByHash not found key block", "number", *number, "hash", hash)
		return nil
	}
	// A key-block height can have multiple historical hashes while the
	// canonical key chain is being reorganized. Resolve the committee by the
	// exact requested hash; looking it up again by number silently substitutes
	// the current canonical key block at that height and makes otherwise valid
	// historical FHS quorum certificates fail verification during sync.
	committee := bftview.LoadMember(*number, hash, false)
	if committee == nil {
		log.Warn("GetCommitteeByHash not found committee", "number", *number, "hash", hash)
		return nil
	}
	if committee.RlpHash() != header.CommitteeHash {
		log.Error("GetCommitteeByHash committee commitment mismatch", "number", *number, "hash", hash,
			"have", committee.RlpHash(), "want", header.CommitteeHash)
		return nil
	}
	return committee.List
}

// CurrentBlock retrieves the current committee of the canonical chain. The
// block is retrieved from the blockchain's internal cache.
func (kbc *KeyBlockChain) CurrentCommittee() []*common.Cnode {
	keyblock := kbc.CurrentBlock()
	c := bftview.LoadMember(keyblock.NumberU64(), keyblock.Hash(), false)
	if c != nil {
		return c.List
	}
	log.Warn("CurrentCommittee not found committee", "number", keyblock.NumberU64())
	return nil
}
func (kbc *KeyBlockChain) GetCommitteeByNumber(kNumber uint64) []*common.Cnode {
	blockSrc := kbc.GetBlockByNumber(kNumber)
	if blockSrc == nil {
		return nil
	}
	c := bftview.LoadMember(kNumber, blockSrc.Hash(), false)
	if c != nil {
		return c.List
	}
	log.Warn("GetCommitteeByNumber not found committee", "number", kNumber)
	return nil
}
