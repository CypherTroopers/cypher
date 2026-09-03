// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/prque"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/metrics"
	"github.com/cypherium/cypher/params"
)

const (
	chainHeadChanSize = 10
	// Charge retained transactions in 1 KiB units. The default two pending FHS
	// windows plus one queued window therefore have a 3 GiB charged-byte ceiling.
	// Blob transactions also charge both defensive sidecar copies below.
	txSlotSize = 1024
)

var (
	ErrAlreadyKnown          = errors.New("already known")
	ErrInvalidSender         = errors.New("invalid sender")
	ErrUnderpriced           = errors.New("transaction underpriced")
	ErrTxPoolOverflow        = errors.New("txpool is full")
	ErrReplaceUnderpriced    = errors.New("replacement transaction underpriced")
	ErrNonceTooFarInFuture   = errors.New("nonce too far in future")
	ErrGasLimit              = errors.New("exceeds block gas limit")
	ErrNegativeValue         = errors.New("negative value")
	ErrOversizedData         = errors.New("oversized data")
	ErrInvalidGasPrice       = errors.New("Gas price not 0")
	ErrEtherValueUnsupported = errors.New("ether value is not supported for private transactions")
	ErrNativeTxDisabled      = errors.New("native transaction type is disabled by genesis")
	ErrNativeReplayAnchor    = errors.New("invalid native transaction replay anchor")
	ErrNativeResourceLimit   = errors.New("native transaction resource limit exceeded")
)

var (
	evictionInterval    = time.Minute
	statsReportInterval = 8 * time.Second
	reqWaitTimeout      = 15 * time.Second
)

var (
	pendingDiscardMeter   = metrics.NewRegisteredMeter("txpool/pending/discard", nil)
	pendingReplaceMeter   = metrics.NewRegisteredMeter("txpool/pending/replace", nil)
	pendingRateLimitMeter = metrics.NewRegisteredMeter("txpool/pending/ratelimit", nil)
	pendingNofundsMeter   = metrics.NewRegisteredMeter("txpool/pending/nofunds", nil)

	queuedDiscardMeter   = metrics.NewRegisteredMeter("txpool/queued/discard", nil)
	queuedReplaceMeter   = metrics.NewRegisteredMeter("txpool/queued/replace", nil)
	queuedRateLimitMeter = metrics.NewRegisteredMeter("txpool/queued/ratelimit", nil)
	queuedNofundsMeter   = metrics.NewRegisteredMeter("txpool/queued/nofunds", nil)
	queuedEvictionMeter  = metrics.NewRegisteredMeter("txpool/queued/eviction", nil)

	knownTxMeter       = metrics.NewRegisteredMeter("txpool/known", nil)
	validTxMeter       = metrics.NewRegisteredMeter("txpool/valid", nil)
	invalidTxMeter     = metrics.NewRegisteredMeter("txpool/invalid", nil)
	underpricedTxMeter = metrics.NewRegisteredMeter("txpool/underpriced", nil)

	pendingGauge = metrics.NewRegisteredGauge("txpool/pending", nil)
	queuedGauge  = metrics.NewRegisteredGauge("txpool/queued", nil)
	localGauge   = metrics.NewRegisteredGauge("txpool/local", nil)
	slotsGauge   = metrics.NewRegisteredGauge("txpool/slots", nil)
)

type TxStatus uint

const (
	TxStatusUnknown TxStatus = iota
	TxStatusQueued
	TxStatusPending
	TxStatusIncluded
)

type TxLane uint8

const (
	TxLaneFast TxLane = iota
	TxLaneSlow
)

type TxResourceClass uint8

const (
	TxClassNative TxResourceClass = iota
	TxClassERC20
	TxClassSmallCall
	TxClassDex
	TxClassDeploy
	TxClassHeavy
	TxClassData
)

func (class TxResourceClass) String() string {
	switch class {
	case TxClassNative:
		return "native"
	case TxClassERC20:
		return "erc20"
	case TxClassSmallCall:
		return "small_call"
	case TxClassDex:
		return "dex"
	case TxClassDeploy:
		return "deploy"
	case TxClassHeavy:
		return "heavy"
	case TxClassData:
		return "data"
	default:
		return "unknown"
	}
}

type txReadyKey struct {
	lane  TxLane
	class TxResourceClass
}

const (
	// These are bounded fallbacks for callers which do not provide a request
	// limit. A genesis-configured FHS proposer supplies its two-window limit and
	// must not be clipped by these legacy defaults.
	fastPendingCandidateScanLimit = 2 * 262144
	slowPendingCandidateScanLimit = 2 * 262144
)

type pendingReadyIndex struct {
	version      uint64
	byKey        map[txReadyKey][]common.Address
	fastPending  int
	slowPending  int
	classPending map[TxResourceClass]int
}

var txClassFastSelectors = map[[4]byte]bool{
	{0xa9, 0x05, 0x9c, 0xbb}: true, // ERC20 transfer(address,uint256)
	{0x09, 0x5e, 0xa7, 0xb3}: true, // ERC20 approve(address,uint256)
}

var txClassDexSelectors = map[[4]byte]bool{
	{0x38, 0xed, 0x17, 0x39}: true, // swapExactTokensForTokens
	{0x7f, 0xf3, 0x6a, 0xb5}: true, // swapExactETHForTokens
	{0x18, 0xcb, 0xaf, 0xe5}: true, // swapExactTokensForETH
	{0x04, 0xe4, 0x5a, 0xaf}: true, // exactInputSingle
	{0xc0, 0x4b, 0x8d, 0x59}: true, // exactInput
	{0xac, 0x96, 0x50, 0xd8}: true, // multicall(bytes[])
}

func txMethodSelector(tx *types.Transaction) ([4]byte, bool) {
	var selector [4]byte
	if tx == nil || len(tx.Data()) < 4 {
		return selector, false
	}
	copy(selector[:], tx.Data()[:4])
	return selector, true
}

func ClassifyTxResource(tx *types.Transaction) TxResourceClass {
	if tx == nil {
		return TxClassHeavy
	}

	dataLen := len(tx.Data())

	// Contract creation / deployment path.
	if tx.To() == nil {
		if tx.Gas() > 3000000 || dataLen > 24*1024 {
			return TxClassHeavy
		}
		return TxClassDeploy
	}

	// Native transfer.
	if dataLen == 0 {
		return TxClassNative
	}

	// Very large calldata should be isolated from normal execution-heavy txs.
	if dataLen > 16*1024 {
		return TxClassData
	}
	if tx.Gas() > 1000000 {
		return TxClassHeavy
	}

	if selector, ok := txMethodSelector(tx); ok {
		if txClassDexSelectors[selector] {
			return TxClassDex
		}
		if txClassFastSelectors[selector] {
			return TxClassERC20
		}
	}

	// Small generic contract calls.
	if dataLen <= 256 && tx.Gas() <= 150000 {
		return TxClassSmallCall
	}
	if dataLen <= 1024 && tx.Gas() <= 300000 {
		return TxClassSmallCall
	}

	return TxClassHeavy
}

const (
	txLaneFastMaxDataBytes = 1024
	txLaneFastMaxGasPerTx  = uint64(300000)
)

func IsFastLaneEligible(tx *types.Transaction) bool {
	if tx == nil {
		return false
	}
	// RouteHint is local JSON-RPC metadata. It is neither part of the signed
	// transaction nor preserved by the canonical wire encoding, so using it
	// here would let different nodes assign the same transaction to different
	// proposal lanes. Derive the lane exclusively from signed transaction
	// fields instead.
	if tx.To() == nil {
		return false
	}
	if len(tx.Data()) > txLaneFastMaxDataBytes {
		return false
	}
	if tx.Gas() > txLaneFastMaxGasPerTx {
		return false
	}
	if len(tx.Data()) == 0 {
		return true
	}
	class := ClassifyTxResource(tx)
	return class == TxClassERC20 || class == TxClassSmallCall
}

type blockChain interface {
	CurrentBlock() *types.Block
	GetBlock(hash common.Hash, number uint64) *types.Block
	StateAt(root common.Hash) (*state.StateDB, error)
	SubscribeChainHeadEvent(ch chan<- ChainHeadEvent) event.Subscription
}

type TxPoolConfig struct {
	Locals    []common.Address
	NoLocals  bool
	Journal   string
	Rejournal time.Duration

	PriceLimit uint64
	PriceBump  uint64

	AccountSlots uint64
	GlobalSlots  uint64
	AccountQueue uint64
	GlobalQueue  uint64

	RemoteAccountWindow uint64
	LocalAccountWindow  uint64
	FastPendingLifetime time.Duration
	SlowPendingLifetime time.Duration
	FastQueuedLifetime  time.Duration
	SlowQueuedLifetime  time.Duration

	Lifetime time.Duration

	TransactionSizeLimit uint64
	MaxCodeSize          uint64
}

var DefaultTxPoolConfig = TxPoolConfig{
	Journal:   "transactions.rlp",
	Rejournal: time.Hour,

	PriceLimit: params.GWei,
	PriceBump:  10,

	// Retain the two executable windows needed by the Fair HotStuff proposer:
	// one window may already be present in the certified (not yet canonical)
	// parent and the second is the next proposal. Keep one additional queued
	// nonce window. These are 1 KiB memory-charge slots; larger transactions and
	// Blob sidecars consume proportionally more than one slot.
	AccountSlots: 32_768,
	GlobalSlots:  2 * params.NativeParallelHardMaxTransactions,
	AccountQueue: 32_768,
	GlobalQueue:  params.NativeParallelHardMaxTransactions,

	RemoteAccountWindow: 262_144,
	LocalAccountWindow:  262_144,
	FastPendingLifetime: 5 * time.Minute,
	SlowPendingLifetime: 10 * time.Minute,
	FastQueuedLifetime:  10 * time.Minute,
	SlowQueuedLifetime:  30 * time.Minute,

	Lifetime: 3 * time.Hour,

	TransactionSizeLimit: 64,
	MaxCodeSize:          24,
}

func (config *TxPoolConfig) sanitize() TxPoolConfig {
	conf := *config
	if conf.Rejournal < time.Second {
		log.Warn("Sanitizing invalid txpool journal time", "provided", conf.Rejournal, "updated", time.Second)
		conf.Rejournal = time.Second
	}
	if conf.PriceLimit < 1 {
		log.Warn("Sanitizing invalid txpool price limit", "provided", conf.PriceLimit, "updated", DefaultTxPoolConfig.PriceLimit)
		conf.PriceLimit = DefaultTxPoolConfig.PriceLimit
	}
	if conf.PriceBump < 1 {
		log.Warn("Sanitizing invalid txpool price bump", "provided", conf.PriceBump, "updated", DefaultTxPoolConfig.PriceBump)
		conf.PriceBump = DefaultTxPoolConfig.PriceBump
	}
	if conf.AccountSlots < 1 {
		log.Warn("Sanitizing invalid txpool account slots", "provided", conf.AccountSlots, "updated", DefaultTxPoolConfig.AccountSlots)
		conf.AccountSlots = DefaultTxPoolConfig.AccountSlots
	}
	if conf.GlobalSlots < 1 {
		log.Warn("Sanitizing invalid txpool global slots", "provided", conf.GlobalSlots, "updated", DefaultTxPoolConfig.GlobalSlots)
		conf.GlobalSlots = DefaultTxPoolConfig.GlobalSlots
	}
	if conf.AccountQueue < 1 {
		log.Warn("Sanitizing invalid txpool account queue", "provided", conf.AccountQueue, "updated", DefaultTxPoolConfig.AccountQueue)
		conf.AccountQueue = DefaultTxPoolConfig.AccountQueue
	}
	if conf.GlobalQueue < 1 {
		log.Warn("Sanitizing invalid txpool global queue", "provided", conf.GlobalQueue, "updated", DefaultTxPoolConfig.GlobalQueue)
		conf.GlobalQueue = DefaultTxPoolConfig.GlobalQueue
	}
	if conf.RemoteAccountWindow < 1 {
		log.Warn("Sanitizing invalid txpool remote account window", "provided", conf.RemoteAccountWindow, "updated", DefaultTxPoolConfig.RemoteAccountWindow)
		conf.RemoteAccountWindow = DefaultTxPoolConfig.RemoteAccountWindow
	}
	if conf.LocalAccountWindow < 1 {
		log.Warn("Sanitizing invalid txpool local account window", "provided", conf.LocalAccountWindow, "updated", DefaultTxPoolConfig.LocalAccountWindow)
		conf.LocalAccountWindow = DefaultTxPoolConfig.LocalAccountWindow
	}
	if conf.FastPendingLifetime < time.Second {
		log.Warn("Sanitizing invalid txpool fast pending lifetime", "provided", conf.FastPendingLifetime, "updated", DefaultTxPoolConfig.FastPendingLifetime)
		conf.FastPendingLifetime = DefaultTxPoolConfig.FastPendingLifetime
	}
	if conf.SlowPendingLifetime < time.Second {
		log.Warn("Sanitizing invalid txpool slow pending lifetime", "provided", conf.SlowPendingLifetime, "updated", DefaultTxPoolConfig.SlowPendingLifetime)
		conf.SlowPendingLifetime = DefaultTxPoolConfig.SlowPendingLifetime
	}
	if conf.FastQueuedLifetime < time.Second {
		log.Warn("Sanitizing invalid txpool fast queued lifetime", "provided", conf.FastQueuedLifetime, "updated", DefaultTxPoolConfig.FastQueuedLifetime)
		conf.FastQueuedLifetime = DefaultTxPoolConfig.FastQueuedLifetime
	}
	if conf.SlowQueuedLifetime < time.Second {
		log.Warn("Sanitizing invalid txpool slow queued lifetime", "provided", conf.SlowQueuedLifetime, "updated", DefaultTxPoolConfig.SlowQueuedLifetime)
		conf.SlowQueuedLifetime = DefaultTxPoolConfig.SlowQueuedLifetime
	}
	if conf.Lifetime < 1 {
		log.Warn("Sanitizing invalid txpool lifetime", "provided", conf.Lifetime, "updated", DefaultTxPoolConfig.Lifetime)
		conf.Lifetime = DefaultTxPoolConfig.Lifetime
	}
	return conf
}

type TxPool struct {
	config       TxPoolConfig
	chainconfig  *params.ChainConfig
	chain        blockChain
	gasPrice     *big.Int
	txFeed       event.Feed
	scope        event.SubscriptionScope
	signer       types.Signer
	nativeSigner types.Signer
	mu           sync.RWMutex

	istanbul bool

	currentState           *state.StateDB
	currentStateRoot       common.Hash
	currentStateHead       *types.Header
	currentStateGeneration uint64
	pendingNonces          *txNoncer
	currentMaxGas          uint64

	locals        *accountSet
	journal       *txJournal
	journalWriter *txJournalWriter

	pending map[common.Address]*txList
	queue   map[common.Address]*txList
	beats   map[common.Address]time.Time
	all     *txLookup
	priced  *txPricedList
	native  *nativeTxPool
	seen    map[common.Hash]time.Time

	// nativeCanonical is a bounded canonical hash ring derived from the
	// canonical head. Admission checks RecentBlockHash+RecentBlockNumber with
	// one map lookup instead of walking the chain for every transaction.
	nativeCanonical  map[uint64]common.Hash
	nativeHeadNumber uint64

	pendingIndexVersion    uint64
	pendingIndex           *pendingReadyIndex
	pendingCandidateCursor map[txReadyKey]int

	chainHeadCh       chan ChainHeadEvent
	chainHeadSub      event.Subscription
	reqResetCh        chan *txpoolResetRequest
	reqPromoteCh      chan *txpoolPromoteRequest
	reorgShutdownCh   chan struct{}
	wg                sync.WaitGroup
	changesSinceReorg int
}

type txpoolResetRequest struct {
	oldHead, newHead *types.Header
	reply            chan chan struct{}
}

type txpoolPromoteRequest struct {
	accounts *accountSet
	events   types.Transactions
	reply    chan chan struct{}
}

func NewTxPool(config TxPoolConfig, chainconfig *params.ChainConfig, chain blockChain) *TxPool {
	config = (&config).sanitize()
	log.Info("NewTxPool", "config", config)
	pool := &TxPool{
		config:          config,
		chainconfig:     chainconfig,
		chain:           chain,
		signer:          types.NewEIP155Signer(chainconfig.ChainID),
		nativeSigner:    types.NewNativeSigner(chainconfig.ChainID),
		pending:         make(map[common.Address]*txList),
		queue:           make(map[common.Address]*txList),
		beats:           make(map[common.Address]time.Time),
		all:             newTxLookup(),
		native:          newNativeTxPool(config, chainconfig),
		seen:            make(map[common.Hash]time.Time),
		nativeCanonical: make(map[uint64]common.Hash),
		chainHeadCh:     make(chan ChainHeadEvent, chainHeadChanSize),
		reqResetCh:      make(chan *txpoolResetRequest),
		reqPromoteCh:    make(chan *txpoolPromoteRequest),
		reorgShutdownCh: make(chan struct{}),
		gasPrice:        new(big.Int).SetUint64(config.PriceLimit),
	}
	pool.locals = newAccountSet(pool.signer)
	for _, addr := range config.Locals {
		log.Info("Setting new local account", "address", addr)
		pool.locals.add(addr)
	}
	pool.priced = newTxPricedList(pool.all)
	pool.Reset(nil, chain.CurrentBlock().Header())
	pool.wg.Add(1)
	go pool.scheduleReorgLoop()
	if !config.NoLocals && config.Journal != "" {
		pool.journal = newTxJournal(config.Journal)
		if err := pool.journal.load(pool.AddLocals); err != nil {
			log.Warn("Failed to load transaction journal", "err", err)
		}
		if err := pool.journal.rotate(pool.local()); err != nil {
			log.Warn("Failed to rotate transaction journal", "err", err)
		}
		pool.journalWriter = newTxJournalWriter(pool.journal)
	}
	pool.chainHeadSub = pool.chain.SubscribeChainHeadEvent(pool.chainHeadCh)
	pool.wg.Add(1)
	go pool.loop()
	return pool
}

func (pool *TxPool) loop() {
	defer pool.wg.Done()
	var (
		prevPending, prevQueued, prevStales int
		report                              = time.NewTicker(statsReportInterval)
		evict                               = time.NewTicker(evictionInterval)
		journal                             = time.NewTicker(pool.config.Rejournal)
		head                                = pool.chain.CurrentBlock()
	)
	defer report.Stop()
	defer evict.Stop()
	defer journal.Stop()
	for {
		select {
		case ev := <-pool.chainHeadCh:
			if ev.Block != nil {
				pool.requestReset(head.Header(), ev.Block.Header())
				head = ev.Block
			}
		case <-pool.chainHeadSub.Err():
			close(pool.reorgShutdownCh)
			return
		case <-report.C:
			pool.mu.RLock()
			pending, queued := pool.stats()
			pool.mu.RUnlock()
			stales := int(atomic.LoadInt64(&pool.priced.stales))
			if pending != prevPending || queued != prevQueued || stales != prevStales {
				log.Debug("Transaction pool status report", "executable", pending, "queued", queued, "stales", stales)
				prevPending, prevQueued, prevStales = pending, queued, stales
			}
		case <-evict.C:
			pool.mu.Lock()
			for addr := range pool.queue {
				if pool.locals.contains(addr) {
					continue
				}
				if time.Since(pool.beats[addr]) > pool.config.Lifetime {
					list := pool.queue[addr].Flatten()
					for _, tx := range list {
						pool.removeTx(tx.Hash(), true)
					}
					queuedEvictionMeter.Mark(int64(len(list)))
				}
			}
			pool.evictStaleTransactionsLocked(time.Now())
			pool.mu.Unlock()
		case <-journal.C:
			if pool.journalWriter != nil {
				pool.mu.Lock()
				all := pool.local()
				// Queue the rotation while pool.mu excludes new additions. This
				// orders the snapshot before every later append without holding the
				// pool lock during filesystem I/O.
				if err := pool.journalWriter.rotate(all); err != nil {
					log.Warn("Failed to queue local tx journal rotation", "err", err)
				}
				pool.mu.Unlock()
			}
		}
	}
}

func (pool *TxPool) Stop() {
	pool.scope.Close()
	pool.chainHeadSub.Unsubscribe()
	pool.wg.Wait()
	if pool.journalWriter != nil {
		if err := pool.journalWriter.close(); err != nil {
			log.Warn("Failed to close transaction journal writer", "err", err)
		}
	} else if pool.journal != nil {
		pool.journal.close()
	}
	dropBlobSidecarStore(pool)
	log.Info("Transaction pool stopped")
}

func (pool *TxPool) SubscribeNewTxsEvent(ch chan<- NewTxsEvent) event.Subscription {
	return pool.scope.Track(pool.txFeed.Subscribe(ch))
}

func (pool *TxPool) GasPrice() *big.Int {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	return new(big.Int).Set(pool.gasPrice)
}

func (pool *TxPool) SetGasPrice(price *big.Int) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	pool.gasPrice = price
	for _, tx := range pool.priced.Cap(price, pool.locals) {
		pool.removeTx(tx.Hash(), false)
	}
	pool.recordNativeRemovalsLocked(pool.native.removeUnderpriced(price), "below updated price threshold")
	log.Info("Transaction pool price threshold updated", "price", price)
}

func (pool *TxPool) currentBaseFee() *big.Int {
	block := pool.chain.CurrentBlock()
	if block == nil || block.Header() == nil || block.Header().BaseFee == nil || block.Header().BaseFee.Sign() == 0 {
		return big.NewInt(params.FixedBaseFeePerGas)
	}
	return new(big.Int).Set(block.Header().BaseFee)
}

func validate1559FeeCaps(tx *types.Transaction, baseFee *big.Int) error {
	if tx.GasFeeCap().BitLen() > 256 {
		return ErrFeeCapVeryHigh
	}
	if tx.GasTipCap().BitLen() > 256 {
		return ErrTipVeryHigh
	}
	if tx.GasTipCap().Cmp(tx.GasFeeCap()) > 0 {
		return ErrGasTipAboveFeeCap
	}
	if baseFee != nil && tx.GasFeeCap().Cmp(baseFee) < 0 {
		return ErrGasFeeCapTooLow
	}
	return nil
}

func (pool *TxPool) Nonce(addr common.Address) uint64 {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	return pool.pendingNonces.get(addr)
}

func (pool *TxPool) Stats() (int, int) {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	return pool.stats()
}

// PendingRevision returns an O(1) generation for the proposal-visible pending
// set. It changes whenever the pending index is invalidated, allowing proposal
// schedulers to remain quiescent after a no-work result without rescanning the
// entire pool merely to discover whether the same input is still present.
func (pool *TxPool) PendingRevision() uint64 {
	if pool == nil {
		return 0
	}
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	return pool.pendingIndexVersion
}

func (pool *TxPool) stats() (int, int) {
	pending := pool.native.count()
	for _, list := range pool.pending {
		pending += list.Len()
	}
	queued := 0
	for _, list := range pool.queue {
		queued += list.Len()
	}
	return pending, queued
}

func (pool *TxPool) Content() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	pending := make(map[common.Address]types.Transactions)
	for addr, list := range pool.pending {
		pending[addr] = list.Flatten()
	}
	for addr, txs := range pool.nativeByPayerLocked(false) {
		pending[addr] = append(pending[addr], txs...)
	}
	queued := make(map[common.Address]types.Transactions)
	for addr, list := range pool.queue {
		queued[addr] = list.Flatten()
	}
	return pending, queued
}

func (pool *TxPool) Pending() (map[common.Address]types.Transactions, error) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	pending := make(map[common.Address]types.Transactions)
	for addr, list := range pool.pending {
		pending[addr] = list.Flatten()
	}
	for addr, txs := range pool.nativeByPayerLocked(false) {
		pending[addr] = append(pending[addr], txs...)
	}
	return pending, nil
}

func (pool *TxPool) Locals() []common.Address {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	return pool.locals.flatten()
}

func (pool *TxPool) local() map[common.Address]types.Transactions {
	txs := make(map[common.Address]types.Transactions)
	for addr := range pool.locals.accounts {
		if pending := pool.pending[addr]; pending != nil {
			txs[addr] = append(txs[addr], pending.Flatten()...)
		}
		if queued := pool.queue[addr]; queued != nil {
			txs[addr] = append(txs[addr], queued.Flatten()...)
		}
	}
	for addr, native := range pool.native.localByPayer() {
		txs[addr] = append(txs[addr], native...)
	}
	return txs
}

// nativeByPayerLocked returns a deterministic native snapshot grouped by fee
// payer. The caller holds pool.mu; nativeTxPool uses its own lock so Get/Has
// remain race-safe without recursively acquiring pool.mu.
func (pool *TxPool) nativeByPayerLocked(localOnly bool) map[common.Address]types.Transactions {
	if localOnly {
		return pool.native.localByPayer()
	}
	grouped := make(map[common.Address]types.Transactions)
	for _, tx := range pool.native.snapshot() {
		grouped[tx.Payer()] = append(grouped[tx.Payer()], tx)
	}
	return grouped
}

func ClassifyTxLane(tx *types.Transaction) TxLane {
	if IsFastLaneEligible(tx) {
		return TxLaneFast
	}
	return TxLaneSlow
}

func (pool *TxPool) accountWindow(local bool) uint64 {
	if local {
		return pool.config.LocalAccountWindow
	}
	return pool.config.RemoteAccountWindow
}

func (pool *TxPool) txLifetime(lane TxLane, pending bool) time.Duration {
	if pending {
		if lane == TxLaneFast {
			return pool.config.FastPendingLifetime
		}
		return pool.config.SlowPendingLifetime
	}
	if lane == TxLaneFast {
		return pool.config.FastQueuedLifetime
	}
	return pool.config.SlowQueuedLifetime
}

func (pool *TxPool) noteSeen(hash common.Hash) {
	if _, ok := pool.seen[hash]; !ok {
		pool.seen[hash] = time.Now()
	}
}

func (pool *TxPool) markPendingIndexDirty() {
	pool.pendingIndexVersion++
}

func (pool *TxPool) rebuildPendingIndexLocked() {
	if pool.pendingIndex != nil && pool.pendingIndex.version == pool.pendingIndexVersion {
		return
	}

	idx := &pendingReadyIndex{
		version:      pool.pendingIndexVersion,
		byKey:        make(map[txReadyKey][]common.Address),
		classPending: make(map[TxResourceClass]int),
	}

	for addr, list := range pool.pending {
		if list == nil || list.Len() == 0 {
			continue
		}

		seenForAccount := make(map[txReadyKey]struct{})
		for _, tx := range list.txs.flatten() {
			lane := ClassifyTxLane(tx)
			class := ClassifyTxResource(tx)

			idx.classPending[class]++
			if lane == TxLaneFast {
				idx.fastPending++
			} else {
				idx.slowPending++
			}

			key := txReadyKey{lane: lane, class: class}
			if _, exists := seenForAccount[key]; exists {
				continue
			}
			idx.byKey[key] = append(idx.byKey[key], addr)
			seenForAccount[key] = struct{}{}
		}
	}

	pool.pendingIndex = idx
}

func pendingCandidateScanLimit(lane TxLane, requested int) int {
	// A positive limit is already bounded by the internal caller's consensus
	// configuration. Return it directly: multiplying or converting it again here
	// could overflow, and a legacy fixed ceiling would silently hide independent
	// accounts from a larger genesis-configured proposal window.
	if requested > 0 {
		return requested
	}
	if lane == TxLaneFast {
		return fastPendingCandidateScanLimit
	}
	return slowPendingCandidateScanLimit
}

func candidateClassQuota(totalLimit int, keyCount int) int {
	if totalLimit <= 0 || keyCount <= 0 {
		return 0
	}
	quota := totalLimit / keyCount
	if totalLimit%keyCount != 0 {
		quota++
	}
	if quota <= 0 {
		quota = 1
	}
	return quota
}

func (pool *TxPool) pendingCandidateKeysLocked(lane TxLane, classes []TxResourceClass) []txReadyKey {
	if pool.pendingIndex == nil {
		return nil
	}

	keys := make([]txReadyKey, 0)

	if len(classes) > 0 {
		for _, class := range classes {
			key := txReadyKey{lane: lane, class: class}
			if len(pool.pendingIndex.byKey[key]) > 0 {
				keys = append(keys, key)
			}
		}
		return keys
	}

	for key, addrs := range pool.pendingIndex.byKey {
		if key.lane == lane && len(addrs) > 0 {
			keys = append(keys, key)
		}
	}

	sort.Slice(keys, func(i, j int) bool {
		if keys[i].lane != keys[j].lane {
			return keys[i].lane < keys[j].lane
		}
		return keys[i].class < keys[j].class
	})

	return keys
}

func (pool *TxPool) appendRotatedCandidatesLocked(
	key txReadyKey,
	limit int,
	seen map[common.Address]struct{},
	candidates []common.Address,
) []common.Address {
	if pool.pendingIndex == nil {
		return candidates
	}

	addrs := pool.pendingIndex.byKey[key]
	if len(addrs) == 0 {
		if pool.pendingCandidateCursor != nil {
			delete(pool.pendingCandidateCursor, key)
		}
		return candidates
	}

	if pool.pendingCandidateCursor == nil {
		pool.pendingCandidateCursor = make(map[txReadyKey]int)
	}

	start := pool.pendingCandidateCursor[key]
	if start < 0 || start >= len(addrs) {
		start = 0
	}

	pickedForKey := 0
	scanned := 0

	for scanned < len(addrs) {
		if limit > 0 && len(candidates) >= limit {
			break
		}
		if limit > 0 && pickedForKey >= limit {
			break
		}

		idx := (start + scanned) % len(addrs)
		addr := addrs[idx]
		scanned++

		if _, ok := seen[addr]; ok {
			continue
		}

		seen[addr] = struct{}{}
		candidates = append(candidates, addr)
		pickedForKey++
	}

	if scanned > 0 {
		pool.pendingCandidateCursor[key] = (start + scanned) % len(addrs)
	}

	return candidates
}

func (pool *TxPool) pendingCandidateAddrsLocked(lane TxLane, classes []TxResourceClass, limit int) []common.Address {
	pool.rebuildPendingIndexLocked()

	if pool.pendingIndex == nil {
		return nil
	}

	keys := pool.pendingCandidateKeysLocked(lane, classes)
	if len(keys) == 0 {
		return nil
	}

	seen := make(map[common.Address]struct{})
	candidates := make([]common.Address, 0)
	if limit > 0 {
		// The request may be math.MaxInt in a defensive/internal call. Capacity
		// never needs to exceed the number of accounts actually retained, and this
		// clamp prevents a correct no-arithmetic limit from becoming a huge make.
		capacity := limit
		if capacity > len(pool.pending) {
			capacity = len(pool.pending)
		}
		candidates = make([]common.Address, 0, capacity)
	}

	// First pass: give each lane/class key a fair slice of the scan budget.
	// This prevents native from always consuming the entire fast-lane scan limit
	// before small_call gets a chance, and also helps dex/data/deploy/heavy fairness.
	perKeyLimit := candidateClassQuota(limit, len(keys))
	for _, key := range keys {
		if limit > 0 && len(candidates) >= limit {
			return candidates
		}
		candidates = pool.appendRotatedCandidatesLocked(key, perKeyLimit, seen, candidates)
	}

	// Second pass: if some classes had fewer accounts, fill the remaining budget
	// from all keys again using their advanced cursors.
	for _, key := range keys {
		if limit > 0 && len(candidates) >= limit {
			break
		}
		remaining := 0
		if limit > 0 {
			remaining = limit - len(candidates)
		}
		candidates = pool.appendRotatedCandidatesLocked(key, remaining, seen, candidates)
	}

	return candidates
}

func (pool *TxPool) PendingByLane(lane TxLane) (map[common.Address]types.Transactions, error) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	pending := make(map[common.Address]types.Transactions)
	for addr, list := range pool.pending {
		src := list.Flatten()
		dst := make(types.Transactions, 0, len(src))
		for _, tx := range src {
			if ClassifyTxLane(tx) != lane {
				break
			}
			dst = append(dst, tx)
		}
		if len(dst) > 0 {
			pending[addr] = dst
		}
	}
	return pending, nil
}

func (pool *TxPool) PendingByLaneAndClasses(lane TxLane, classes ...TxResourceClass) (map[common.Address]types.Transactions, error) {
	return pool.PendingByLaneAndClassesLimited(lane, 0, 0, 0, classes...)
}

func (pool *TxPool) PendingByLaneAndClassesLimited(lane TxLane, maxTx int, perAccountLimit int, gasTarget uint64, classes ...TxResourceClass) (map[common.Address]types.Transactions, error) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	allowed := make(map[TxResourceClass]bool, len(classes))
	for _, class := range classes {
		allowed[class] = true
	}
	useClassFilter := len(allowed) > 0

	candidateLimit := pendingCandidateScanLimit(lane, maxTx)
	candidates := pool.pendingCandidateAddrsLocked(lane, classes, candidateLimit)

	pending := make(map[common.Address]types.Transactions)
	remainingGas := gasTarget
	totalPicked := 0

	for _, addr := range candidates {
		list := pool.pending[addr]
		if list == nil || list.Len() == 0 {
			continue
		}

		src := list.txs.flatten()
		if len(src) == 0 {
			continue
		}

		dstCap := len(src)
		if perAccountLimit > 0 && dstCap > perAccountLimit {
			dstCap = perAccountLimit
		}
		if maxTx > 0 && dstCap > maxTx-totalPicked {
			dstCap = maxTx - totalPicked
		}
		if dstCap <= 0 {
			break
		}

		dst := make(types.Transactions, 0, dstCap)
		for _, tx := range src {
			if ClassifyTxLane(tx) != lane {
				break
			}
			if useClassFilter && !allowed[ClassifyTxResource(tx)] {
				continue
			}
			if gasTarget > 0 {
				if tx.Gas() > remainingGas {
					continue
				}
				remainingGas -= tx.Gas()
			}

			dst = append(dst, tx)
			totalPicked++

			if perAccountLimit > 0 && len(dst) >= perAccountLimit {
				break
			}
			if maxTx > 0 && totalPicked >= maxTx {
				break
			}
			if gasTarget > 0 && remainingGas == 0 {
				break
			}
		}

		if len(dst) > 0 {
			pending[addr] = dst
		}
		if maxTx > 0 && totalPicked >= maxTx {
			break
		}
		if gasTarget > 0 && remainingGas == 0 {
			break
		}
	}

	return pending, nil
}

func (pool *TxPool) PendingClassStats() (fastPending int, slowPending int, classPending map[TxResourceClass]int) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pool.rebuildPendingIndexLocked()

	classPending = make(map[TxResourceClass]int, len(pool.pendingIndex.classPending))
	for class, count := range pool.pendingIndex.classPending {
		classPending[class] = count
	}
	return pool.pendingIndex.fastPending, pool.pendingIndex.slowPending, classPending
}

func (pool *TxPool) evictStaleTransactionsLocked(now time.Time) {
	var evictedPending int
	var evictedQueued int
	for addr, list := range pool.pending {
		if pool.locals.contains(addr) {
			continue
		}
		for _, tx := range list.Flatten() {
			seenAt, ok := pool.seen[tx.Hash()]
			if !ok {
				pool.seen[tx.Hash()] = now
				continue
			}
			if now.Sub(seenAt) > pool.txLifetime(ClassifyTxLane(tx), true) {
				pool.removeTx(tx.Hash(), true)
				evictedPending++
			}
		}
	}
	for addr, list := range pool.queue {
		if pool.locals.contains(addr) {
			continue
		}
		for _, tx := range list.Flatten() {
			seenAt, ok := pool.seen[tx.Hash()]
			if !ok {
				pool.seen[tx.Hash()] = now
				continue
			}
			if now.Sub(seenAt) > pool.txLifetime(ClassifyTxLane(tx), false) {
				pool.removeTx(tx.Hash(), true)
				evictedQueued++
			}
		}
	}
	if evictedPending > 0 {
		log.Debug("Evicted stale pending transactions", "count", evictedPending)
	}
	if evictedQueued > 0 {
		queuedEvictionMeter.Mark(int64(evictedQueued))
		log.Debug("Evicted stale queued transactions", "count", evictedQueued)
	}
}

func (pool *TxPool) validateTx(tx *types.Transaction, local bool) error {
	return pool.validateTxWithState(tx, local, pool.currentState)
}

func (pool *TxPool) validateTxWithState(tx *types.Transaction, local bool, statedb *state.StateDB) error {
	return pool.validateTxWithStateAndBlobProof(tx, local, statedb, false)
}

// txPoolValidationView is an immutable copy of every head-dependent input used
// by EVM transaction admission. A preflight worker combines it with its own
// StateDB instance; no worker reads pool fields or shares StateDB caches.
type txPoolValidationView struct {
	stateRoot        common.Hash
	headGeneration   uint64
	chain            blockChain
	chainconfig      *params.ChainConfig
	signer           types.Signer
	rules            params.Rules
	maxTxBytes       uint64
	maxGas           uint64
	baseFee          *big.Int
	gasPrice         *big.Int
	remoteWindow     uint64
	localWindow      uint64
	pendingNonces    *txNoncer
	nonceOverrides   map[common.Address]uint64
	useNonceFallback bool
	maxBlobs         int
	blobBaseFee      *big.Int
	sidecarVersion   byte
}

// validationViewLocked snapshots admission policy at the StateDB generation
// selected by Reset/ResetHead. Callers either hold pool.mu or run in a context
// where the pool cannot concurrently reset (construction and focused tests).
func (pool *TxPool) validationViewLocked(needBlob bool) txPoolValidationView {
	view := txPoolValidationView{
		stateRoot:        pool.currentStateRoot,
		headGeneration:   pool.currentStateGeneration,
		chain:            pool.chain,
		chainconfig:      pool.chainconfig,
		signer:           pool.signer,
		maxGas:           pool.currentMaxGas,
		remoteWindow:     pool.config.RemoteAccountWindow,
		localWindow:      pool.config.LocalAccountWindow,
		pendingNonces:    pool.pendingNonces,
		useNonceFallback: true,
		baseFee:          big.NewInt(params.FixedBaseFeePerGas),
		gasPrice:         new(big.Int),
		sidecarVersion:   types.BlobSidecarVersion0,
	}
	if pool.gasPrice != nil {
		view.gasPrice.Set(pool.gasPrice)
	}
	if pool.chainconfig != nil {
		view.maxTxBytes = pool.chainconfig.EffectiveMaxTransactionBytes()
	} else {
		view.maxTxBytes = DefaultTxPoolConfig.TransactionSizeLimit * 1024
	}

	var head *types.Header
	if pool.currentStateHead != nil {
		// currentStateHead is a private deep copy replaced only while pool.mu is
		// write-locked. Reading it under the caller's lock needs no second copy.
		head = pool.currentStateHead
	} else if pool.chain != nil {
		if block := pool.chain.CurrentBlock(); block != nil && block.Header() != nil {
			head = block.Header()
		}
	}
	var (
		headNumber = new(big.Int)
		headTime   uint64
	)
	if head != nil {
		if head.Number != nil {
			headNumber.Set(head.Number)
			if pool.chainconfig != nil {
				nextNumber := new(big.Int).Add(head.Number, big.NewInt(1))
				view.rules = pool.chainconfig.CypheriumRules(nextNumber, head.Time)
			}
		}
		headTime = head.Time
		if head.BaseFee != nil && head.BaseFee.Sign() != 0 {
			view.baseFee.Set(head.BaseFee)
		}
		if needBlob {
			view.blobBaseFee = params.CalcBlobBaseFeeAtTime(pool.chainconfig, head.Time, head.ExcessBlobGas)
		}
	}
	if needBlob {
		view.maxBlobs = params.MaxBlobsPerTransaction(pool.chainconfig, headTime)
		if pool.chainconfig != nil {
			view.sidecarVersion = types.BlobSidecarVersionForOsaka(pool.chainconfig.IsOsaka(headNumber, headTime))
		}
	}
	return view
}

func (view txPoolValidationView) accountWindow(local bool) uint64 {
	if local {
		return view.localWindow
	}
	return view.remoteWindow
}

func (view txPoolValidationView) pendingNonce(addr common.Address, chainNonce uint64) uint64 {
	if view.pendingNonces == nil {
		return chainNonce
	}
	if view.useNonceFallback {
		if nonce := view.pendingNonces.get(addr); nonce > chainNonce {
			return nonce
		}
		return chainNonce
	}
	if nonce, ok := view.nonceOverrides[addr]; ok && nonce > chainNonce {
		return nonce
	}
	return chainNonce
}

func validateBlobTxWithView(tx *types.Transaction, view txPoolValidationView, blobProofVerified bool) error {
	if tx == nil || tx.Type() != types.BlobTxType {
		return nil
	}
	if err := tx.ValidateBlobTx(view.maxBlobs, view.blobBaseFee); err != nil {
		return err
	}
	if blobProofVerified {
		return tx.ValidateBlobSidecarVersion(tx.BlobSidecar(), view.sidecarVersion)
	}
	return tx.VerifyBlobSidecarVersion(tx.BlobSidecar(), view.sidecarVersion, types.KZGBlobVerifier{})
}

// validateFHSStandaloneTransactionWork rejects transactions which cannot fit an
// otherwise-empty Fair HotStuff block. Reusing the consensus meter keeps TxPool
// admission aligned with proposer and validator per-transaction list limits.
func validateFHSStandaloneTransactionWork(config *params.ChainConfig, tx *types.Transaction) error {
	if config == nil || !config.FairHotstuff {
		return nil
	}
	meter := NewFHSBlockWorkMeterForConfig(config)
	if config.NativeParallelEnabled() {
		meter = NewFHSEVMBlockWorkMeterForConfig(config)
	}
	return meter.AddTransaction(0, tx)
}

// validateTxWithStateAndBlobProof keeps expensive KZG work outside pool.mu for
// normal ingress. blobProofVerified may only be true for an immutable private
// copy verified by addTxs, or for transactions reinjected from an already
// validated canonical block. Envelope/sidecar shape checks are always repeated.
func (pool *TxPool) validateTxWithStateAndBlobProof(tx *types.Transaction, local bool, statedb *state.StateDB, blobProofVerified bool) error {
	needBlob := tx != nil && tx.IsInitialized() && tx.Type() == types.BlobTxType
	return pool.validateTxWithView(tx, local, statedb, blobProofVerified, pool.validationViewLocked(needBlob))
}

func (pool *TxPool) validateTxWithView(tx *types.Transaction, local bool, statedb *state.StateDB, blobProofVerified bool, view txPoolValidationView) error {
	if tx == nil || !tx.IsInitialized() {
		return ErrInvalidSender
	}
	if err := tx.ValidateIntegerBounds(); err != nil {
		return err
	}
	if tx.Type() == types.NativeTxType {
		return ErrNativeTxDisabled
	}
	if uint64(tx.Size()) > view.maxTxBytes {
		return ErrOversizedData
	}
	if tx.Value().Sign() < 0 {
		return ErrNegativeValue
	}
	rules := view.rules
	if rules.IsOsaka && tx.Gas() > params.MaxTxGas {
		return ErrTxGasLimitExceeded
	}
	if err := ValidateTxTypeForRules(tx.Type(), rules); err != nil {
		return err
	}
	if tx.Type() == types.SetCodeTxType {
		if tx.To() == nil {
			return ErrSetCodeTxCreate
		}
		if len(tx.SetCodeAuthorizations()) == 0 {
			return ErrEmptyAuthList
		}
	}
	if err := validateFHSStandaloneTransactionWork(view.chainconfig, tx); err != nil {
		return err
	}
	if view.maxGas < tx.Gas() {
		return ErrGasLimit
	}
	from, err := types.Sender(view.signer, tx)
	if err != nil {
		return ErrInvalidSender
	}
	if statedb == nil {
		return errors.New("txpool state snapshot is unavailable")
	}
	if rules.IsLondon {
		code := statedb.GetCode(from)
		_, delegated := types.ParseDelegation(code)
		if len(code) != 0 && !(rules.IsPrague && delegated) {
			return ErrSenderNoEOA
		}
	}
	if err := validate1559FeeCaps(tx, view.baseFee); err != nil {
		return err
	}
	if tx.GasPriceIntCmp(view.gasPrice) < 0 {
		return ErrUnderpriced
	}
	chainNonce := statedb.GetNonce(from)
	if chainNonce > tx.Nonce() {
		return ErrNonceTooLow
	}
	if chainNonce == math.MaxUint64 {
		return ErrNonceMax
	}
	baseNonce := view.pendingNonce(from, chainNonce)
	window := view.accountWindow(local)
	if tx.Nonce() > baseNonce && tx.Nonce()-baseNonce > window {
		return ErrNonceTooFarInFuture
	}
	if statedb.GetBalance(from).Cmp(tx.Cost()) < 0 {
		return ErrInsufficientFunds
	}
	if err := validateBlobTxWithView(tx, view, blobProofVerified); err != nil {
		return err
	}
	intrGas, err := IntrinsicGasWithRulesAndAuthorizations(tx.Data(), tx.AccessList(), tx.SetCodeAuthorizations(), tx.To() == nil, rules)
	if err != nil {
		return err
	}
	if tx.Gas() < intrGas {
		return ErrIntrinsicGas
	}
	if rules.IsPrague {
		floorDataGas, err := FloorDataGas(tx.Data())
		if err != nil {
			return err
		}
		if tx.Gas() < floorDataGas {
			return ErrFloorDataGas
		}
	}
	return nil
}

func (pool *TxPool) validateNativeTxWithState(tx *types.Transaction, statedb *state.StateDB) error {
	if pool.chainconfig == nil || !pool.chainconfig.NativeParallelEnabled() || !pool.chainconfig.NativeParallel.RequireNativeTransactions {
		return ErrNativeTxDisabled
	}
	if statedb == nil {
		return errors.New("native transaction state snapshot is unavailable")
	}
	native := pool.chainconfig.NativeParallel
	if uint64(tx.Size()) > native.MaxTransactionBytes {
		return ErrOversizedData
	}
	// Keep pool and block-envelope admission identical for signed manifests,
	// reserved state, and every declared resource ceiling.
	if err := validateNativeParallelEnvelope(pool.chainconfig, types.Transactions{tx}); err != nil {
		return fmt.Errorf("%w: %w", ErrNativeResourceLimit, err)
	}
	from, err := types.Sender(pool.nativeSigner, tx)
	if err != nil || from != tx.Payer() {
		return ErrInvalidSender
	}

	headNumber := pool.nativeHeadNumber
	if headNumber == math.MaxUint64 {
		return fmt.Errorf("%w: canonical head overflows proposal number", ErrNativeReplayAnchor)
	}
	recentNumber := tx.RecentBlockNumber()
	if recentNumber > headNumber {
		return fmt.Errorf("%w: recent block %d is ahead of canonical head %d", ErrNativeReplayAnchor, recentNumber, headNumber)
	}
	if headNumber-recentNumber >= native.ReplayWindowBlocks {
		return fmt.Errorf("%w: recent block %d is outside replay window %d at head %d", ErrNativeReplayAnchor, recentNumber, native.ReplayWindowBlocks, headNumber)
	}
	if tx.ValidUntil() <= headNumber {
		return fmt.Errorf("%w: transaction expires at %d before next block %d", ErrNativeReplayAnchor, tx.ValidUntil(), headNumber+1)
	}
	if tx.ValidUntil()-recentNumber > native.ReplayWindowBlocks {
		return fmt.Errorf("%w: validity span %d exceeds replay window %d", ErrNativeReplayAnchor, tx.ValidUntil()-recentNumber, native.ReplayWindowBlocks)
	}
	if canonical, ok := pool.nativeCanonical[recentNumber]; !ok || canonical != tx.RecentBlockHash() {
		return fmt.Errorf("%w: block %d/%s is not canonical", ErrNativeReplayAnchor, recentNumber, tx.RecentBlockHash())
	}
	if err := checkNativeReplaySequence(pool.chainconfig, statedb, tx); err != nil {
		return err
	}

	rules := params.Rules{}
	if head := pool.chain.CurrentBlock(); head != nil && head.Header() != nil {
		header := head.Header()
		rules = pool.chainconfig.CypheriumRules(new(big.Int).Add(header.Number, big.NewInt(1)), header.Time)
	}
	code := statedb.GetCode(from)
	_, delegated := types.ParseDelegation(code)
	if len(code) != 0 && !(rules.IsPrague && delegated) {
		return ErrSenderNoEOA
	}
	if err := validate1559FeeCaps(tx, pool.currentBaseFee()); err != nil {
		return err
	}
	if tx.GasPriceIntCmp(pool.gasPrice) < 0 {
		return ErrUnderpriced
	}
	if statedb.GetBalance(from).Cmp(tx.Cost()) < 0 {
		return ErrInsufficientFunds
	}
	// NativeTxV1 projects its signed resource manifest into the EVM access
	// list. Admission must charge exactly the same intrinsic work as the serial
	// reference executor; otherwise a transaction can enter the pool and later
	// make every proposal containing it consensus-invalid.
	intrinsic, err := IntrinsicGasWithRulesAndAuthorizations(tx.Data(), tx.AccessList(), nil, false, rules)
	if err != nil {
		return err
	}
	if tx.ComputeLimit() < intrinsic {
		return ErrIntrinsicGas
	}
	if rules.IsPrague {
		floorDataGas, err := FloorDataGas(tx.Data())
		if err != nil {
			return err
		}
		if tx.ComputeLimit() < floorDataGas {
			return ErrFloorDataGas
		}
	}
	return nil
}

func (pool *TxPool) add(tx *types.Transaction, local bool, blobProofVerified bool, view txPoolValidationView) (replaced bool, journal bool, event bool, err error) {
	if err := tx.ValidateIntegerBounds(); err != nil {
		return false, false, false, err
	}
	hash := tx.Hash()
	if pool.getTx(hash) != nil {
		log.Trace("Discarding already known transaction", "hash", hash)
		knownTxMeter.Mark(1)
		return false, false, false, ErrAlreadyKnown
	}
	isLocal := local || (tx.Type() == types.NativeTxType && pool.locals.contains(tx.Payer())) || (tx.Type() != types.NativeTxType && pool.locals.containsTx(tx))
	if err := pool.validateTxWithView(tx, isLocal, pool.currentState, blobProofVerified, view); err != nil {
		log.Trace("Discarding invalid transaction", "hash", hash, "err", err)
		invalidTxMeter.Mark(1)
		return false, false, false, err
	}
	if tx.Type() == types.NativeTxType {
		victims, err := pool.native.add(tx, isLocal, pool.currentState.GetBalance(tx.Payer()))
		if err != nil {
			return false, false, false, err
		}
		for _, victim := range victims {
			delete(pool.seen, victim.hash)
			pendingGauge.Dec(1)
			if victim.local {
				localGauge.Dec(1)
			}
			log.Trace("Evicted lower-priority native transaction", "hash", victim.hash, "priority", victim.priority)
		}
		if local && !pool.locals.contains(tx.Payer()) {
			pool.locals.add(tx.Payer())
			log.Info("Setting new native transaction payer local", "address", tx.Payer())
		}
		pool.noteSeen(hash)
		pool.markPendingIndexDirty()
		pendingGauge.Inc(1)
		if isLocal {
			localGauge.Inc(1)
		}
		log.Trace("Pooled native transaction", "hash", hash, "payer", tx.Payer(), "priority", tx.PriorityFeePerCompute(), "validUntil", tx.ValidUntil())
		return false, pool.journalWriter != nil && isLocal, true, nil
	}
	from, _ := types.Sender(pool.signer, tx)
	txSlots := numSlots(tx)
	poolSlots := saturatingAddUint64(pool.config.GlobalSlots, pool.config.GlobalQueue)
	if uint64(txSlots) > poolSlots {
		return false, false, false, ErrTxPoolOverflow
	}
	if uint64(pool.all.Slots()+txSlots) > poolSlots {
		if !isLocal && pool.priced.Underpriced(tx, pool.locals) {
			log.Trace("Discarding underpriced transaction", "hash", hash, "price", tx.GasPrice())
			underpricedTxMeter.Mark(1)
			return false, false, false, ErrUnderpriced
		}
		if pool.changesSinceReorg > int(pool.config.GlobalSlots/4) {
			return false, false, false, ErrTxPoolOverflow
		}
		poolSlotLimit := math.MaxInt
		if poolSlots <= uint64(math.MaxInt) {
			poolSlotLimit = int(poolSlots)
		}
		drop := pool.priced.Discard(pool.all.Slots()-poolSlotLimit+txSlots, pool.locals)
		pool.changesSinceReorg += len(drop)
		for _, tx := range drop {
			log.Trace("Discarding freshly underpriced transaction", "hash", tx.Hash(), "price", tx.GasPrice())
			underpricedTxMeter.Mark(1)
			pool.removeTx(tx.Hash(), false)
		}
		if uint64(pool.all.Slots()+txSlots) > poolSlots {
			return false, false, false, ErrTxPoolOverflow
		}
	}
	if list := pool.pending[from]; list != nil && list.Overlaps(tx) {
		inserted, old := list.Add(tx, pool.config.PriceBump)
		if !inserted {
			pendingDiscardMeter.Mark(1)
			return false, false, false, ErrReplaceUnderpriced
		}
		if old != nil {
			pool.all.Remove(old.Hash())
			pool.RemoveBlobSidecar(old.Hash())
			pool.priced.Removed(1)
			pendingReplaceMeter.Mark(1)
		}
		pool.all.Add(tx, isLocal)
		pool.priced.Put(tx)
		pool.noteSeen(hash)
		pool.markPendingIndexDirty()
		log.Trace("Pooled new executable transaction", "hash", hash, "from", from, "to", tx.To())
		pool.beats[from] = time.Now()
		return old != nil, pool.shouldJournalTx(from), true, nil
	}
	replaced, err = pool.enqueueTx(hash, tx, isLocal, true)
	if err != nil {
		return false, false, false, err
	}
	if local && !pool.locals.contains(from) {
		log.Info("Setting new local account", "address", from)
		pool.locals.add(from)
		pool.priced.Removed(pool.all.RemoteToLocals(pool.locals))
	}
	if isLocal {
		localGauge.Inc(1)
	}
	log.Trace("Pooled new future transaction", "hash", hash, "from", from, "to", tx.To(), "nonce", tx.Nonce())
	return replaced, pool.shouldJournalTx(from), false, nil
}

func (pool *TxPool) enqueueTx(hash common.Hash, tx *types.Transaction, local bool, addAll bool) (bool, error) {
	from, _ := types.Sender(pool.signer, tx)
	if pool.queue[from] == nil {
		pool.queue[from] = newTxList(false)
	}
	inserted, old := pool.queue[from].Add(tx, pool.config.PriceBump)
	if !inserted {
		queuedDiscardMeter.Mark(1)
		return false, ErrReplaceUnderpriced
	}
	if old != nil {
		pool.all.Remove(old.Hash())
		pool.RemoveBlobSidecar(old.Hash())
		pool.priced.Removed(1)
		queuedReplaceMeter.Mark(1)
	} else {
		queuedGauge.Inc(1)
	}
	if pool.all.Get(hash) == nil && !addAll {
		log.Error("Missing transaction in lookup set, please report the issue", "hash", hash)
	}
	if addAll {
		pool.all.Add(tx, local)
		pool.priced.Put(tx)
	}
	pool.noteSeen(hash)
	if _, exist := pool.beats[from]; !exist {
		pool.beats[from] = time.Now()
	}
	return old != nil, nil
}

func (pool *TxPool) shouldJournalTx(from common.Address) bool {
	return pool.journalWriter != nil && pool.locals.contains(from)
}

func (pool *TxPool) promoteTx(addr common.Address, hash common.Hash, tx *types.Transaction) bool {
	if pool.pending[addr] == nil {
		pool.pending[addr] = newTxList(true)
	}
	list := pool.pending[addr]
	inserted, old := list.Add(tx, pool.config.PriceBump)
	if !inserted {
		pool.all.Remove(hash)
		pool.RemoveBlobSidecar(hash)
		pool.priced.Removed(1)
		pendingDiscardMeter.Mark(1)
		return false
	}
	if old != nil {
		pool.all.Remove(old.Hash())
		pool.RemoveBlobSidecar(old.Hash())
		pool.priced.Removed(1)
		pendingReplaceMeter.Mark(1)
	} else {
		pendingGauge.Inc(1)
	}
	pool.pendingNonces.set(addr, tx.Nonce()+1)
	pool.beats[addr] = time.Now()
	pool.markPendingIndexDirty()
	return true
}

func (pool *TxPool) AddLocals(txs []*types.Transaction) []error {
	return pool.addTxs(txs, !pool.config.NoLocals, true)
}

// AddLocalsAsync validates and inserts a local transaction batch with normal
// local/journal semantics, but does not wait for the asynchronous promotion
// pass. Callers receive one result per input transaction.
func (pool *TxPool) AddLocalsAsync(txs []*types.Transaction) []error {
	return pool.addTxs(txs, !pool.config.NoLocals, false)
}

const validateLocalsHeadRetries = 2

type txPoolLocalPreflightSnapshot struct {
	view           txPoolValidationView
	localByDefault bool
	locals         map[common.Address]struct{}
}

func (pool *TxPool) localPreflightSnapshot(needBlob bool) txPoolLocalPreflightSnapshot {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	snapshot := txPoolLocalPreflightSnapshot{
		view:           pool.validationViewLocked(needBlob),
		localByDefault: !pool.config.NoLocals,
		locals:         make(map[common.Address]struct{}),
	}
	// Preflight already owns an independent StateDB at view.stateRoot. A cold
	// pending nonce must therefore fall back to that same StateDB, not the
	// txNoncer's mutable fallback copy.
	snapshot.view.useNonceFallback = false
	if pool.locals != nil {
		for addr := range pool.locals.accounts {
			snapshot.locals[addr] = struct{}{}
		}
	}
	return snapshot
}

func (pool *TxPool) preflightHeadUnchanged(view txPoolValidationView) bool {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	if pool.currentStateGeneration != view.headGeneration || pool.currentStateRoot != view.stateRoot || pool.pendingNonces != view.pendingNonces || pool.currentMaxGas != view.maxGas {
		return false
	}
	if pool.gasPrice == nil {
		return view.gasPrice.Sign() == 0
	}
	return pool.gasPrice.Cmp(view.gasPrice) == 0
}

// validateLocalsAtSnapshot validates sender groups in input order. Groups are
// distributed across bounded workers, each of which owns a distinct StateDB,
// so StateDB's read-populated caches are never concurrently shared.
func (pool *TxPool) validateLocalsAtSnapshot(txs []*types.Transaction, validate []int, snapshot txPoolLocalPreflightSnapshot, errs []error) {
	if len(validate) == 0 {
		return
	}
	view := snapshot.view
	if view.chain == nil {
		err := errors.New("txpool state snapshot unavailable: blockchain is unavailable")
		for _, index := range validate {
			errs[index] = err
		}
		return
	}

	// Recover senders under the same global CPU budget used by block and KZG
	// validation. The validation pass reuses the transaction sender cache.
	senders := make([]common.Address, len(txs))
	senderOK := make([]bool, len(txs))
	runBoundedParallelValidation(len(validate), func(offset int) {
		index := validate[offset]
		tx := txs[index]
		if tx.Type() == types.NativeTxType || view.signer == nil {
			return
		}
		from, err := types.Sender(view.signer, tx)
		if err == nil {
			senders[index] = from
			senderOK[index] = true
		}
	})
	uniqueSenders := make([]common.Address, 0, len(validate))
	seenSenders := make(map[common.Address]struct{}, len(validate))
	for _, index := range validate {
		if !senderOK[index] {
			continue
		}
		if _, seen := seenSenders[senders[index]]; seen {
			continue
		}
		seenSenders[senders[index]] = struct{}{}
		uniqueSenders = append(uniqueSenders, senders[index])
	}
	view.nonceOverrides = view.pendingNonces.snapshot(uniqueSenders)

	// A sender group is never split across workers. This keeps same-sender
	// validation in original input order while unrelated accounts run in
	// parallel. Invalid signatures share a serial miscellaneous group because
	// their final error still comes from the full ordered validation pipeline.
	groups := make([][]int, 0, len(validate))
	groupBySender := make(map[common.Address]int)
	miscGroup := -1
	for _, index := range validate {
		if senderOK[index] {
			group, ok := groupBySender[senders[index]]
			if !ok {
				group = len(groups)
				groupBySender[senders[index]] = group
				groups = append(groups, nil)
			}
			groups[group] = append(groups[group], index)
			continue
		}
		if miscGroup < 0 {
			miscGroup = len(groups)
			groups = append(groups, nil)
		}
		groups[miscGroup] = append(groups[miscGroup], index)
	}

	workers := len(groups)
	if budget := parallelValidationWorkerBudget(); workers > budget {
		workers = budget
	}
	shards := make([][]int, workers)
	for group := range groups {
		shard := group % workers
		shards[shard] = append(shards[shard], group)
	}
	snapshotErrs := make([]error, workers)
	runBoundedParallelValidationWithLimit(workers, workers, func(worker int) {
		validationState, err := view.chain.StateAt(view.stateRoot)
		if err != nil || validationState == nil {
			if err == nil {
				err = errors.New("state backend returned a nil snapshot")
			}
			snapshotErrs[worker] = fmt.Errorf("txpool state snapshot unavailable: %w", err)
			return
		}
		for _, group := range shards[worker] {
			for _, index := range groups[group] {
				local := snapshot.localByDefault
				if txs[index].Type() == types.NativeTxType {
					_, configuredLocal := snapshot.locals[txs[index].Payer()]
					local = local || configuredLocal
				} else if senderOK[index] {
					_, configuredLocal := snapshot.locals[senders[index]]
					local = local || configuredLocal
				}
				errs[index] = pool.validateTxWithView(txs[index], local, validationState, false, view)
			}
		}
	})
	for _, err := range snapshotErrs {
		if err == nil {
			continue
		}
		for _, index := range validate {
			errs[index] = err
		}
		return
	}
}

// ValidateLocals performs the state-dependent, non-mutating portion of local
// admission before an external durable sidecar is created. Results are aligned
// with txs; ErrAlreadyKnown is returned for an idempotent pool hit. The actual
// AddLocalsAsync call must still revalidate because the head or pool may change.
func (pool *TxPool) ValidateLocals(txs []*types.Transaction) []error {
	baseErrs := make([]error, len(txs))
	if pool == nil {
		for i := range baseErrs {
			baseErrs[i] = errors.New("transaction pool is unavailable")
		}
		return baseErrs
	}
	for i, tx := range txs {
		if tx == nil || !tx.IsInitialized() {
			baseErrs[i] = ErrInvalidSender
			continue
		}
		if err := tx.ValidateIntegerBounds(); err != nil {
			baseErrs[i] = err
		}
	}

	var latest []error
	for attempt := 0; attempt < validateLocalsHeadRetries; attempt++ {
		errs := append([]error(nil), baseErrs...)
		validate := make([]int, 0, len(txs))
		for i, tx := range txs {
			if errs[i] != nil {
				continue
			}
			if pool.getTx(tx.Hash()) != nil {
				errs[i] = ErrAlreadyKnown
				continue
			}
			validate = append(validate, i)
		}
		if len(validate) == 0 {
			return errs
		}

		needBlob := false
		for _, index := range validate {
			if txs[index].Type() == types.BlobTxType {
				needBlob = true
				break
			}
		}
		snapshot := pool.localPreflightSnapshot(needBlob)
		pool.validateLocalsAtSnapshot(txs, validate, snapshot, errs)
		latest = errs
		if pool.preflightHeadUnchanged(snapshot.view) {
			return errs
		}
	}
	// Continuous head movement can outrun a large preliminary batch. Return the
	// newest immutable-snapshot result instead of holding pool.mu indefinitely;
	// AddLocalsAsync performs the authoritative validation under pool.mu.
	return latest
}

func (pool *TxPool) AddLocal(tx *types.Transaction) error {
	errs := pool.AddLocals([]*types.Transaction{tx})
	return errs[0]
}

func (pool *TxPool) AddLocal0(tx *types.Transaction) error {
	errs := pool.addTxs([]*types.Transaction{tx}, false, false)
	return errs[0]
}

func (pool *TxPool) AddRemotes(txs []*types.Transaction) []error {
	return pool.addTxs(txs, false, false)
}

func (pool *TxPool) AddRemotesSync(txs []*types.Transaction) []error {
	return pool.addTxs(txs, false, true)
}

func (pool *TxPool) addRemoteSync(tx *types.Transaction) error {
	errs := pool.AddRemotesSync([]*types.Transaction{tx})
	return errs[0]
}

func (pool *TxPool) AddRemote(tx *types.Transaction) error {
	errs := pool.AddRemotes([]*types.Transaction{tx})
	return errs[0]
}

func (pool *TxPool) addTxs(txs []*types.Transaction, local, sync bool) []error {
	var (
		errs        = make([]error, len(txs))
		news        = make([]*types.Transaction, 0, len(txs))
		knownLocals = make([]*types.Transaction, 0)
	)
	for i, tx := range txs {
		if tx == nil || !tx.IsInitialized() {
			errs[i] = ErrInvalidSender
			invalidTxMeter.Mark(1)
			continue
		}
		if err := tx.ValidateIntegerBounds(); err != nil {
			errs[i] = err
			invalidTxMeter.Mark(1)
			continue
		}
		// Snapshot caller-owned Blob DA before verification. This private copy is
		// the exact data later admitted, closing mutation races while keeping KZG
		// work outside the global pool mutex so concurrent ingress can verify in
		// parallel.
		if tx.Type() == types.BlobTxType {
			tx = tx.WithBlobSidecar(tx.BlobSidecar())
		}
		if pool.getTx(tx.Hash()) != nil {
			errs[i] = ErrAlreadyKnown
			knownTxMeter.Mark(1)
			if local {
				knownLocals = append(knownLocals, tx)
			}
			continue
		}
		_, err := pool.sender(tx)
		if err != nil {
			errs[i] = ErrInvalidSender
			invalidTxMeter.Mark(1)
			continue
		}
		if tx.Type() == types.BlobTxType {
			if err := pool.validateBlobTxEnvelope(tx); err != nil {
				errs[i] = err
				invalidTxMeter.Mark(1)
				continue
			}
			poolSlots := saturatingAddUint64(pool.config.GlobalSlots, pool.config.GlobalQueue)
			if uint64(numSlots(tx)) > poolSlots {
				errs[i] = ErrTxPoolOverflow
				invalidTxMeter.Mark(1)
				continue
			}
			if err := tx.VerifyBlobSidecarVersion(tx.BlobSidecar(), pool.activeBlobSidecarVersion(), types.KZGBlobVerifier{}); err != nil {
				errs[i] = err
				invalidTxMeter.Mark(1)
				continue
			}
		}
		news = append(news, tx)
	}
	if len(news) == 0 && len(knownLocals) == 0 {
		return errs
	}
	pool.mu.Lock()
	knownJournalTxs := pool.localizeKnownTransactionsLocked(knownLocals)
	newErrs, dirtyAddrs, newJournalTxs, queuedEvents := pool.addTxsLocked(news, local, true)
	journalTxs := append(knownJournalTxs, newJournalTxs...)
	// Preserve append-before-rotate ordering by queueing the journal command
	// while pool.mu still excludes a rotation snapshot and later additions.
	journalDone := pool.queueJournalTxs(journalTxs, sync)
	pool.mu.Unlock()
	if journalDone != nil {
		<-journalDone
	}
	if len(news) == 0 {
		return errs
	}
	var nilSlot = 0
	for _, err := range newErrs {
		for errs[nilSlot] != nil {
			nilSlot++
		}
		errs[nilSlot] = err
		nilSlot++
	}
	done := pool.requestPromoteExecutables(dirtyAddrs, queuedEvents)
	if sync {
		<-done
	}
	return errs
}

// localizeKnownTransactionsLocked upgrades transactions first seen through a
// remote path when a trusted/local ingress later claims them. Without this,
// ErrAlreadyKnown could be ACKed while the only committee copy remained
// non-journaled and volatile. pool.mu must be held.
func (pool *TxPool) localizeKnownTransactionsLocked(txs types.Transactions) types.Transactions {
	newAccounts := make(map[common.Address]struct{})
	for _, requested := range txs {
		if requested == nil {
			continue
		}
		known := pool.getTx(requested.Hash())
		if known == nil {
			continue
		}
		from, err := pool.sender(known)
		if err != nil || pool.locals.contains(from) {
			continue
		}
		pool.locals.add(from)
		pool.native.markPayerLocal(from)
		newAccounts[from] = struct{}{}
		log.Info("Setting known transaction account local", "address", from)
	}
	journalTxs := make(types.Transactions, 0, len(txs))
	nativeLocals := pool.native.localByPayer()
	for addr := range newAccounts {
		if pending := pool.pending[addr]; pending != nil {
			journalTxs = append(journalTxs, pending.Flatten()...)
		}
		if queued := pool.queue[addr]; queued != nil {
			journalTxs = append(journalTxs, queued.Flatten()...)
		}
		journalTxs = append(journalTxs, nativeLocals[addr]...)
	}
	if len(journalTxs) > 0 {
		localGauge.Inc(int64(len(journalTxs)))
	}
	return journalTxs
}

func (pool *TxPool) addTxsLocked(txs []*types.Transaction, local, blobProofsVerified bool) ([]error, *accountSet, types.Transactions, types.Transactions) {
	dirty := newAccountSet(pool.signer)
	errs := make([]error, len(txs))
	journalTxs := make(types.Transactions, 0, len(txs))
	queuedEvents := make(types.Transactions, 0, len(txs))
	var validNative int64
	needBlob := false
	for _, tx := range txs {
		if tx != nil && tx.IsInitialized() && tx.Type() == types.BlobTxType {
			needBlob = true
			break
		}
	}
	view := pool.validationViewLocked(needBlob)
	for i, tx := range txs {
		replaced, journal, event, err := pool.add(tx, local, blobProofsVerified, view)
		errs[i] = err
		// Publish DA only after the execution transaction is present in the pool.
		// Failed admission therefore cannot leave a sidecar that later makes an
		// unrelated/bare envelope appear proposal-ready.
		if err == nil && tx.Type() == types.BlobTxType {
			if sidecarErr := pool.storeBlobSidecar(tx, tx.BlobSidecar()); sidecarErr != nil {
				pool.removeTx(tx.Hash(), true)
				err = sidecarErr
				errs[i] = sidecarErr
			}
		}
		if err == nil && !replaced && tx.Type() != types.NativeTxType {
			dirty.addTx(tx)
		}
		if err == nil && journal {
			journalTxs = append(journalTxs, tx)
		}
		if err == nil && event {
			queuedEvents = append(queuedEvents, tx)
		}
		if err == nil && tx.Type() == types.NativeTxType {
			validNative++
		}
	}
	validTxMeter.Mark(int64(len(dirty.accounts)) + validNative)
	return errs, dirty, journalTxs, queuedEvents
}

func (pool *TxPool) Status(hashes []common.Hash) []TxStatus {
	status := make([]TxStatus, len(hashes))
	for i, hash := range hashes {
		tx := pool.Get(hash)
		if tx == nil {
			continue
		}
		if tx.Type() == types.NativeTxType {
			status[i] = TxStatusPending
			continue
		}
		from, _ := types.Sender(pool.signer, tx)
		pool.mu.RLock()
		if txList := pool.pending[from]; txList != nil && txList.txs.items[tx.Nonce()] != nil {
			status[i] = TxStatusPending
		} else if txList := pool.queue[from]; txList != nil && txList.txs.items[tx.Nonce()] != nil {
			status[i] = TxStatusQueued
		}
		pool.mu.RUnlock()
	}
	return status
}

func (pool *TxPool) Get(hash common.Hash) *types.Transaction {
	return pool.getTx(hash)
}

func (pool *TxPool) Has(hash common.Hash) bool {
	return pool.getTx(hash) != nil
}

func (pool *TxPool) getTx(hash common.Hash) *types.Transaction {
	if pool == nil {
		return nil
	}
	if pool.all != nil {
		if tx := pool.all.Get(hash); tx != nil {
			return tx
		}
	}
	return pool.native.get(hash)
}

func (pool *TxPool) sender(tx *types.Transaction) (common.Address, error) {
	if tx != nil && tx.Type() == types.NativeTxType {
		if pool.nativeSigner == nil {
			return common.Address{}, ErrInvalidSender
		}
		return types.Sender(pool.nativeSigner, tx)
	}
	return types.Sender(pool.signer, tx)
}

func (pool *TxPool) removeTx(hash common.Hash, outofbound bool) {
	if native := pool.native.remove(hash); native != nil {
		pool.markPendingIndexDirty()
		delete(pool.seen, hash)
		pendingGauge.Dec(1)
		if native.local {
			localGauge.Dec(1)
		}
		return
	}
	tx := pool.all.Get(hash)
	if tx == nil {
		return
	}
	addr, _ := types.Sender(pool.signer, tx)
	pool.markPendingIndexDirty()
	pool.all.Remove(hash)
	pool.RemoveBlobSidecar(hash)
	delete(pool.seen, hash)
	if outofbound {
		pool.priced.Removed(1)
	}
	if pool.locals.contains(addr) {
		localGauge.Dec(1)
	}
	if pending := pool.pending[addr]; pending != nil {
		if removed, invalids := pending.Remove(tx); removed {
			if pending.Empty() {
				delete(pool.pending, addr)
			}
			for _, tx := range invalids {
				pool.enqueueTx(tx.Hash(), tx, false, false)
			}
			pool.pendingNonces.setIfLower(addr, tx.Nonce())
			pendingGauge.Dec(int64(1 + len(invalids)))
			return
		}
	}
	if future := pool.queue[addr]; future != nil {
		if removed, _ := future.Remove(tx); removed {
			queuedGauge.Dec(1)
		}
		if future.Empty() {
			delete(pool.queue, addr)
			delete(pool.beats, addr)
		}
	}
}

func (pool *TxPool) requestReset(oldHead *types.Header, newHead *types.Header) chan struct{} {
	reply := make(chan chan struct{}, 1)
	select {
	case pool.reqResetCh <- &txpoolResetRequest{oldHead: oldHead, newHead: newHead, reply: reply}:
	case <-pool.reorgShutdownCh:
		return pool.reorgShutdownCh
	case <-time.After(reqWaitTimeout):
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	select {
	case done := <-reply:
		return done
	case <-pool.reorgShutdownCh:
		return pool.reorgShutdownCh
	case <-time.After(reqWaitTimeout):
		ch := make(chan struct{})
		close(ch)
		return ch
	}
}

func (pool *TxPool) requestPromoteExecutables(set *accountSet, events types.Transactions) chan struct{} {
	reply := make(chan chan struct{}, 1)
	select {
	case pool.reqPromoteCh <- &txpoolPromoteRequest{accounts: set, events: events, reply: reply}:
	case <-pool.reorgShutdownCh:
		return pool.reorgShutdownCh
	case <-time.After(reqWaitTimeout):
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	select {
	case done := <-reply:
		return done
	case <-pool.reorgShutdownCh:
		return pool.reorgShutdownCh
	case <-time.After(reqWaitTimeout):
		ch := make(chan struct{})
		close(ch)
		return ch
	}
}

func (pool *TxPool) queueJournalTxs(txs types.Transactions, wait bool) <-chan struct{} {
	if pool.journalWriter == nil || len(txs) == 0 {
		return nil
	}
	done, err := pool.journalWriter.enqueue(txs, wait)
	if err != nil {
		log.Warn("Failed to queue local transaction journal batch", "transactions", len(txs), "err", err)
		return nil
	}
	return done
}

func (pool *TxPool) scheduleReorgLoop() {
	defer pool.wg.Done()
	var (
		curDone       chan struct{}
		nextDone      = make(chan struct{})
		launchNextRun bool
		reset         *txpoolResetRequest
		dirtyAccounts *accountSet
		queuedEvents  = make(map[common.Address]*txSortedMap)
		nativeEvents  = make(map[common.Hash]*types.Transaction)
	)
	for {
		if curDone == nil && launchNextRun {
			go pool.runReorg(nextDone, reset, dirtyAccounts, queuedEvents, nativeEvents)
			curDone, nextDone = nextDone, make(chan struct{})
			launchNextRun = false
			reset, dirtyAccounts = nil, nil
			queuedEvents = make(map[common.Address]*txSortedMap)
			nativeEvents = make(map[common.Hash]*types.Transaction)
		}
		select {
		case req := <-pool.reqResetCh:
			if reset == nil {
				reset = req
			} else {
				reset.newHead = req.newHead
			}
			launchNextRun = true
			req.reply <- nextDone
		case req := <-pool.reqPromoteCh:
			if dirtyAccounts == nil {
				dirtyAccounts = req.accounts
			} else {
				dirtyAccounts.merge(req.accounts)
			}
			pool.mergeQueuedTxEvents(queuedEvents, nativeEvents, req.events)
			launchNextRun = true
			req.reply <- nextDone
		case <-curDone:
			curDone = nil
		case <-pool.reorgShutdownCh:
			if curDone != nil {
				<-curDone
			}
			close(nextDone)
			return
		}
	}
}

func (pool *TxPool) mergeQueuedTxEvents(events map[common.Address]*txSortedMap, nativeEvents map[common.Hash]*types.Transaction, txs types.Transactions) {
	for _, tx := range txs {
		if tx == nil {
			continue
		}
		if tx.Type() == types.NativeTxType {
			nativeEvents[tx.Hash()] = tx
			continue
		}
		addr, err := types.Sender(pool.signer, tx)
		if err != nil {
			continue
		}
		if _, ok := events[addr]; !ok {
			events[addr] = newTxSortedMap()
		}
		events[addr].Put(tx)
	}
}

func (pool *TxPool) runReorg(done chan struct{}, reset *txpoolResetRequest, dirtyAccounts *accountSet, events map[common.Address]*txSortedMap, nativeEvents map[common.Hash]*types.Transaction) {
	defer close(done)
	var promoteAddrs []common.Address
	var resetJournal types.Transactions
	var resetEvents types.Transactions
	if dirtyAccounts != nil && reset == nil {
		promoteAddrs = dirtyAccounts.flatten()
	}
	pool.mu.Lock()
	if reset != nil {
		resetJournal, resetEvents = pool.Reset(reset.oldHead, reset.newHead)
		for addr := range events {
			events[addr].Forward(pool.pendingNonces.get(addr))
			if events[addr].Len() == 0 {
				delete(events, addr)
			}
		}
		promoteAddrs = make([]common.Address, 0, len(pool.queue))
		for addr := range pool.queue {
			promoteAddrs = append(promoteAddrs, addr)
		}
		for hash := range nativeEvents {
			if pool.native.get(hash) == nil {
				delete(nativeEvents, hash)
			}
		}
	}
	promoted := pool.promoteExecutables(promoteAddrs)
	if reset != nil {
		pool.demoteUnexecutables()
		nonces := make(map[common.Address]uint64, len(pool.pending))
		for addr, list := range pool.pending {
			highestPending := list.LastElement()
			nonces[addr] = highestPending.Nonce() + 1
		}
		pool.pendingNonces.setAll(nonces)
	}
	pool.truncatePending()
	pool.truncateQueue()
	pool.changesSinceReorg = 0
	pool.queueJournalTxs(resetJournal, false)
	pool.mu.Unlock()
	pool.mergeQueuedTxEvents(events, nativeEvents, append(resetEvents, promoted...))
	if len(events) > 0 || len(nativeEvents) > 0 {
		var txs []*types.Transaction
		for _, set := range events {
			txs = append(txs, set.Flatten()...)
		}
		nativeHashes := make([]common.Hash, 0, len(nativeEvents))
		for hash := range nativeEvents {
			nativeHashes = append(nativeHashes, hash)
		}
		sort.Slice(nativeHashes, func(i, j int) bool {
			return bytes.Compare(nativeHashes[i][:], nativeHashes[j][:]) < 0
		})
		for _, hash := range nativeHashes {
			txs = append(txs, nativeEvents[hash])
		}
		pool.txFeed.Send(NewTxsEvent{txs})
	}
}

func (pool *TxPool) Reset(oldHead, newHead *types.Header) (journalTxs types.Transactions, queuedEvents types.Transactions) {
	var reinject, included types.Transactions
	if oldHead != nil && oldHead.Hash() != newHead.ParentHash {
		oldNum := oldHead.Number.Uint64()
		newNum := newHead.Number.Uint64()
		if depth := uint64(math.Abs(float64(oldNum) - float64(newNum))); depth > 64 {
			log.Debug("Skipping deep transaction reorg", "depth", depth)
		} else {
			var discarded types.Transactions
			var (
				rem = pool.chain.GetBlock(oldHead.Hash(), oldHead.Number.Uint64())
				add = pool.chain.GetBlock(newHead.Hash(), newHead.Number.Uint64())
			)
			if rem == nil {
				if newNum < oldNum {
					log.Debug("Skipping transaction reset caused by setHead", "old", oldHead.Hash(), "oldnum", oldNum, "new", newHead.Hash(), "newnum", newNum)
				} else {
					log.Warn("Transaction pool reset with missing oldhead", "old", oldHead.Hash(), "oldnum", oldNum, "new", newHead.Hash(), "newnum", newNum)
				}
				return
			}
			for rem.NumberU64() > add.NumberU64() {
				discarded = append(discarded, rem.Transactions()...)
				if rem = pool.chain.GetBlock(rem.ParentHash(), rem.NumberU64()-1); rem == nil {
					log.Error("Unrooted old chain seen by tx pool", "block", oldHead.Number, "hash", oldHead.Hash())
					return
				}
			}
			for add.NumberU64() > rem.NumberU64() {
				included = append(included, add.Transactions()...)
				if add = pool.chain.GetBlock(add.ParentHash(), add.NumberU64()-1); add == nil {
					log.Error("Unrooted new chain seen by tx pool", "block", newHead.Number, "hash", newHead.Hash())
					return
				}
			}
			for rem.Hash() != add.Hash() {
				discarded = append(discarded, rem.Transactions()...)
				if rem = pool.chain.GetBlock(rem.ParentHash(), rem.NumberU64()-1); rem == nil {
					log.Error("Unrooted old chain seen by tx pool", "block", oldHead.Number, "hash", oldHead.Hash())
					return
				}
				included = append(included, add.Transactions()...)
				if add = pool.chain.GetBlock(add.ParentHash(), add.NumberU64()-1); add == nil {
					log.Error("Unrooted new chain seen by tx pool", "block", newHead.Number, "hash", newHead.Hash())
					return
				}
			}
			reinject = types.TxDifference(discarded, included)
		}
	}
	// Always include the new head body, including when deep-reorg reinjection is
	// intentionally skipped. Duplicate hashes are harmless and ensure a native
	// transaction consumed by the new canonical head cannot remain proposal-visible.
	if newHead != nil {
		if added := pool.chain.GetBlock(newHead.Hash(), newHead.Number.Uint64()); added != nil {
			included = append(included, added.Transactions()...)
		}
	}
	if newHead == nil {
		newHead = pool.chain.CurrentBlock().Header()
	}
	statedb, err := pool.chain.StateAt(newHead.Root)
	if err != nil {
		log.Error("Failed to reset txpool state", "err", err)
		return
	}
	pool.currentState = statedb
	pool.currentStateRoot = newHead.Root
	pool.currentStateHead = types.CopyHeader(newHead)
	pool.currentStateGeneration++
	pool.pendingNonces = newTxNoncer(statedb)
	pool.currentMaxGas = newHead.GasLimit
	pool.pruneNativeLocked(oldHead, newHead)
	includedNativePayers := make(map[common.Address]struct{})
	for _, tx := range included {
		if tx != nil && tx.Type() == types.NativeTxType {
			includedNativePayers[tx.Payer()] = struct{}{}
			pool.removeTx(tx.Hash(), false)
		}
	}
	pool.recordNativeRemovalsLocked(pool.native.removeReplaySequences(included), "payer replay sequence consumed at canonical head")
	pool.recordNativeRemovalsLocked(pool.native.removeUnfundedPayers(includedNativePayers, statedb.GetBalance), "payer balance changed at canonical head")
	log.Debug("Reinjecting stale transactions", "count", len(reinject))
	legacyReinject := make(types.Transactions, 0, len(reinject))
	for _, tx := range reinject {
		if tx != nil && tx.Type() != types.NativeTxType {
			legacyReinject = append(legacyReinject, tx)
		}
	}
	senderCacher.recover(pool.signer, legacyReinject)
	_, _, journalTxs, queuedEvents = pool.addTxsLocked(reinject, false, true)
	pool.markPendingIndexDirty()
	next := new(big.Int).Add(newHead.Number, big.NewInt(1))
	pool.istanbul = pool.chainconfig.IsIstanbul(next)
	return journalTxs, queuedEvents
}

func (pool *TxPool) ResetHead(newHead *types.Header) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	statedb, err := pool.chain.StateAt(newHead.Root)
	if err != nil {
		log.Error("Failed to reset txpool state", "err", err)
		return
	}
	pool.currentState = statedb
	pool.currentStateRoot = newHead.Root
	pool.currentStateHead = types.CopyHeader(newHead)
	pool.currentStateGeneration++
	pool.pendingNonces = newTxNoncer(statedb)
	pool.currentMaxGas = newHead.GasLimit
	pool.pruneNativeLocked(nil, newHead)
	if added := pool.chain.GetBlock(newHead.Hash(), newHead.Number.Uint64()); added != nil {
		addedTxs := added.Transactions()
		includedNativePayers := make(map[common.Address]struct{})
		for _, tx := range addedTxs {
			if tx != nil && tx.Type() == types.NativeTxType {
				includedNativePayers[tx.Payer()] = struct{}{}
				pool.removeTx(tx.Hash(), false)
			}
		}
		pool.recordNativeRemovalsLocked(pool.native.removeReplaySequences(addedTxs), "payer replay sequence consumed at canonical head")
		pool.recordNativeRemovalsLocked(pool.native.removeUnfundedPayers(includedNativePayers, statedb.GetBalance), "payer balance changed at canonical head")
	}
	accounts := make([]common.Address, 0, len(pool.queue))
	for addr := range pool.queue {
		accounts = append(accounts, addr)
	}
	promoted := pool.promoteExecutables(accounts)
	pool.demoteUnexecutables()
	pool.truncatePending()
	pool.truncateQueue()
	for addr, list := range pool.pending {
		highestPending := list.LastElement()
		pool.pendingNonces.set(addr, highestPending.Nonce()+1)
	}
	pool.markPendingIndexDirty()
	if len(promoted) > 0 {
		go pool.txFeed.Send(NewTxsEvent{promoted})
	}
}

func (pool *TxPool) promoteExecutables(accounts []common.Address) []*types.Transaction {
	var promoted []*types.Transaction
	for _, addr := range accounts {
		list := pool.queue[addr]
		if list == nil {
			continue
		}
		forwards := list.Forward(pool.currentState.GetNonce(addr))
		for _, tx := range forwards {
			hash := tx.Hash()
			pool.all.Remove(hash)
			pool.RemoveBlobSidecar(hash)
			delete(pool.seen, hash)
		}
		log.Trace("Removed old queued transactions", "count", len(forwards))
		drops, _ := list.Filter(pool.currentState.GetBalance(addr), pool.currentMaxGas)
		for _, tx := range drops {
			hash := tx.Hash()
			pool.all.Remove(hash)
			pool.RemoveBlobSidecar(hash)
			delete(pool.seen, hash)
		}
		log.Trace("Removed unpayable queued transactions", "count", len(drops))
		queuedNofundsMeter.Mark(int64(len(drops)))
		baseNonce := pool.currentState.GetNonce(addr)
		if pendingNonce := pool.pendingNonces.get(addr); pendingNonce > baseNonce {
			baseNonce = pendingNonce
		}
		windowDrops := list.FilterNonceAbove(baseNonce + pool.accountWindow(pool.locals.contains(addr)))
		for _, tx := range windowDrops {
			hash := tx.Hash()
			pool.all.Remove(hash)
			pool.RemoveBlobSidecar(hash)
			delete(pool.seen, hash)
			log.Trace("Removed too-far future queued transaction", "hash", hash)
		}
		log.Trace("Removed too-far future queued transactions", "count", len(windowDrops))
		readies := list.Ready(pool.pendingNonces.get(addr))
		for _, tx := range readies {
			hash := tx.Hash()
			if pool.promoteTx(addr, hash, tx) {
				promoted = append(promoted, tx)
			}
		}
		log.Trace("Promoted queued transactions", "count", len(promoted))
		queuedGauge.Dec(int64(len(readies)))
		caps := list.Cap(int(pool.config.AccountQueue))
		for _, tx := range caps {
			hash := tx.Hash()
			pool.all.Remove(hash)
			pool.RemoveBlobSidecar(hash)
			delete(pool.seen, hash)
			log.Trace("Removed cap-exceeding queued transaction", "hash", hash)
		}
		queuedRateLimitMeter.Mark(int64(len(caps)))
		pool.priced.Removed(len(forwards) + len(drops) + len(windowDrops) + len(caps))
		queuedGauge.Dec(int64(len(forwards) + len(drops) + len(windowDrops) + len(caps)))
		if pool.locals.contains(addr) {
			localGauge.Dec(int64(len(forwards) + len(drops) + len(windowDrops) + len(caps)))
		}
		if list.Empty() {
			delete(pool.queue, addr)
			delete(pool.beats, addr)
		}
	}
	return promoted
}

func (pool *TxPool) truncatePending() {
	pending := uint64(0)
	for _, list := range pool.pending {
		pending += uint64(list.Len())
	}
	if pending <= pool.config.GlobalSlots {
		return
	}
	pendingBeforeCap := pending
	spammers := prque.New(nil)
	for addr, list := range pool.pending {
		if uint64(list.Len()) > pool.config.AccountSlots {
			spammers.Push(addr, int64(list.Len()))
		}
	}
	offenders := []common.Address{}
	for pending > pool.config.GlobalSlots && !spammers.Empty() {
		offender, _ := spammers.Pop()
		offenders = append(offenders, offender.(common.Address))
		if len(offenders) > 1 {
			threshold := pool.pending[offender.(common.Address)].Len()
			for pending > pool.config.GlobalSlots && pool.pending[offenders[len(offenders)-2]].Len() > threshold {
				for i := 0; i < len(offenders)-1; i++ {
					list := pool.pending[offenders[i]]
					caps := list.Cap(list.Len() - 1)
					for _, tx := range caps {
						hash := tx.Hash()
						pool.all.Remove(hash)
						pool.RemoveBlobSidecar(hash)
						pool.pendingNonces.setIfLower(offenders[i], tx.Nonce())
						log.Trace("Removed fairness-exceeding pending transaction", "hash", hash)
					}
					pool.priced.Removed(len(caps))
					pendingGauge.Dec(int64(len(caps)))
					if pool.locals.contains(offenders[i]) {
						localGauge.Dec(int64(len(caps)))
					}
					pending--
				}
			}
		}
	}
	if pending > pool.config.GlobalSlots && len(offenders) > 0 {
		for pending > pool.config.GlobalSlots && uint64(pool.pending[offenders[len(offenders)-1]].Len()) > pool.config.AccountSlots {
			for _, addr := range offenders {
				list := pool.pending[addr]
				caps := list.Cap(list.Len() - 1)
				for _, tx := range caps {
					hash := tx.Hash()
					pool.all.Remove(hash)
					pool.RemoveBlobSidecar(hash)
					pool.pendingNonces.setIfLower(addr, tx.Nonce())
					log.Trace("Removed fairness-exceeding pending transaction", "hash", hash)
				}
				pool.priced.Removed(len(caps))
				pendingGauge.Dec(int64(len(caps)))
				if pool.locals.contains(addr) {
					localGauge.Dec(int64(len(caps)))
				}
				pending--
			}
		}
	}
	if pendingBeforeCap != pending {
		pool.markPendingIndexDirty()
	}
	pendingRateLimitMeter.Mark(int64(pendingBeforeCap - pending))
}

func (pool *TxPool) truncateQueue() {
	queued := uint64(0)
	for _, list := range pool.queue {
		queued += uint64(list.Len())
	}
	if queued <= pool.config.GlobalQueue {
		return
	}
	addresses := make(addressesByHeartbeat, 0, len(pool.queue))
	for addr := range pool.queue {
		addresses = append(addresses, addressByHeartbeat{addr, pool.beats[addr]})
	}
	sort.Sort(addresses)
	for drop := queued - pool.config.GlobalQueue; drop > 0 && len(addresses) > 0; {
		addr := addresses[len(addresses)-1]
		list := pool.queue[addr.address]
		addresses = addresses[:len(addresses)-1]
		if size := uint64(list.Len()); size <= drop {
			for _, tx := range list.Flatten() {
				pool.removeTx(tx.Hash(), true)
			}
			drop -= size
			queuedRateLimitMeter.Mark(int64(size))
			continue
		}
		txs := list.Flatten()
		for i := len(txs) - 1; i >= 0 && drop > 0; i-- {
			pool.removeTx(txs[i].Hash(), true)
			drop--
			queuedRateLimitMeter.Mark(1)
		}
	}
}

func (pool *TxPool) demoteUnexecutables() {
	for addr, list := range pool.pending {
		nonce := pool.currentState.GetNonce(addr)
		olds := list.Forward(nonce)
		for _, tx := range olds {
			hash := tx.Hash()
			pool.all.Remove(hash)
			pool.RemoveBlobSidecar(hash)
			log.Trace("Removed old pending transaction", "hash", hash)
		}
		drops, invalids := list.Filter(pool.currentState.GetBalance(addr), pool.currentMaxGas)
		for _, tx := range drops {
			hash := tx.Hash()
			log.Trace("Removed unpayable pending transaction", "hash", hash)
			pool.all.Remove(hash)
			pool.RemoveBlobSidecar(hash)
		}
		pendingNofundsMeter.Mark(int64(len(drops)))
		for _, tx := range invalids {
			hash := tx.Hash()
			log.Trace("Demoting pending transaction", "hash", hash)
			pool.enqueueTx(hash, tx, false, false)
		}
		pendingGauge.Dec(int64(len(olds) + len(drops) + len(invalids)))
		if pool.locals.contains(addr) {
			localGauge.Dec(int64(len(olds) + len(drops) + len(invalids)))
		}
		if list.Len() > 0 && list.txs.Get(nonce) == nil {
			gapped := list.Cap(0)
			for _, tx := range gapped {
				hash := tx.Hash()
				log.Error("Demoting invalidated transaction", "hash", hash)
				pool.enqueueTx(hash, tx, false, false)
			}
			pendingGauge.Dec(int64(len(gapped)))
			blockReorgInvalidatedTx.Mark(int64(len(gapped)))
		}
		if list.Empty() {
			delete(pool.pending, addr)
		}
	}
	pool.markPendingIndexDirty()
}

func (pool *TxPool) PendingCount() int {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	pending := pool.native.count()
	for _, list := range pool.pending {
		pending += list.Len()
	}
	return pending
}

func (pool *TxPool) RemoveBatch(txs types.Transactions) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	for _, tx := range txs {
		pool.removeTx(tx.Hash(), false)
	}
}

type addressByHeartbeat struct {
	address   common.Address
	heartbeat time.Time
}

type addressesByHeartbeat []addressByHeartbeat

func (a addressesByHeartbeat) Len() int           { return len(a) }
func (a addressesByHeartbeat) Less(i, j int) bool { return a[i].heartbeat.Before(a[j].heartbeat) }
func (a addressesByHeartbeat) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

type accountSet struct {
	accounts map[common.Address]struct{}
	signer   types.Signer
	cache    *[]common.Address
}

func newAccountSet(signer types.Signer, addrs ...common.Address) *accountSet {
	as := &accountSet{accounts: make(map[common.Address]struct{}), signer: signer}
	for _, addr := range addrs {
		as.add(addr)
	}
	return as
}

func (as *accountSet) contains(addr common.Address) bool {
	_, exist := as.accounts[addr]
	return exist
}

func (as *accountSet) empty() bool { return len(as.accounts) == 0 }

func (as *accountSet) containsTx(tx *types.Transaction) bool {
	if addr, err := types.Sender(as.signer, tx); err == nil {
		return as.contains(addr)
	}
	return false
}

func (as *accountSet) add(addr common.Address) {
	as.accounts[addr] = struct{}{}
	as.cache = nil
}

func (as *accountSet) addTx(tx *types.Transaction) {
	if addr, err := types.Sender(as.signer, tx); err == nil {
		as.add(addr)
	}
}

func (as *accountSet) flatten() []common.Address {
	if as.cache == nil {
		accounts := make([]common.Address, 0, len(as.accounts))
		for account := range as.accounts {
			accounts = append(accounts, account)
		}
		as.cache = &accounts
	}
	return *as.cache
}

func (as *accountSet) merge(other *accountSet) {
	for addr := range other.accounts {
		as.accounts[addr] = struct{}{}
	}
	as.cache = nil
}

type txLookup struct {
	slots       int
	lock        sync.RWMutex
	locals      map[common.Hash]*types.Transaction
	remotes     map[common.Hash]*types.Transaction
	slotsByHash map[common.Hash]int
}

func newTxLookup() *txLookup {
	return &txLookup{
		locals:      make(map[common.Hash]*types.Transaction),
		remotes:     make(map[common.Hash]*types.Transaction),
		slotsByHash: make(map[common.Hash]int),
	}
}

func (t *txLookup) Range(f func(hash common.Hash, tx *types.Transaction, local bool) bool, local bool, remote bool) {
	t.lock.RLock()
	defer t.lock.RUnlock()
	if local {
		for key, value := range t.locals {
			if !f(key, value, true) {
				return
			}
		}
	}
	if remote {
		for key, value := range t.remotes {
			if !f(key, value, false) {
				return
			}
		}
	}
}

func (t *txLookup) Get(hash common.Hash) *types.Transaction {
	t.lock.RLock()
	defer t.lock.RUnlock()
	if tx := t.locals[hash]; tx != nil {
		return tx
	}
	return t.remotes[hash]
}

func (t *txLookup) GetLocal(hash common.Hash) *types.Transaction {
	t.lock.RLock()
	defer t.lock.RUnlock()
	return t.locals[hash]
}

func (t *txLookup) GetRemote(hash common.Hash) *types.Transaction {
	t.lock.RLock()
	defer t.lock.RUnlock()
	return t.remotes[hash]
}

func (t *txLookup) Count() int {
	t.lock.RLock()
	defer t.lock.RUnlock()
	return len(t.locals) + len(t.remotes)
}

func (t *txLookup) LocalCount() int {
	t.lock.RLock()
	defer t.lock.RUnlock()
	return len(t.locals)
}

func (t *txLookup) RemoteCount() int {
	t.lock.RLock()
	defer t.lock.RUnlock()
	return len(t.remotes)
}

func (t *txLookup) Slots() int {
	t.lock.RLock()
	defer t.lock.RUnlock()
	return t.slots
}

func (t *txLookup) Add(tx *types.Transaction, local bool) {
	t.lock.Lock()
	defer t.lock.Unlock()
	hash := tx.Hash()
	charged := numSlots(tx)
	if old, exists := t.slotsByHash[hash]; exists {
		t.slots -= old
	}
	t.slots += charged
	t.slotsByHash[hash] = charged
	slotsGauge.Update(int64(t.slots))
	if local {
		t.locals[hash] = tx
	} else {
		t.remotes[hash] = tx
	}
}

func (t *txLookup) Remove(hash common.Hash) {
	t.lock.Lock()
	defer t.lock.Unlock()
	tx, ok := t.locals[hash]
	if !ok {
		tx, ok = t.remotes[hash]
	}
	if !ok {
		log.Error("No transaction found to be deleted", "hash", hash)
		return
	}
	charged, exists := t.slotsByHash[hash]
	if !exists {
		// Backward-compatible fallback for hand-built test lookups. Production
		// lookups always snapshot the charge at Add time, so mutation of an
		// exposed BlobSidecar pointer cannot corrupt quota accounting on Remove.
		charged = numSlots(tx)
	}
	t.slots -= charged
	delete(t.slotsByHash, hash)
	slotsGauge.Update(int64(t.slots))
	delete(t.locals, hash)
	delete(t.remotes, hash)
}

func (t *txLookup) RemoteToLocals(locals *accountSet) int {
	t.lock.Lock()
	defer t.lock.Unlock()
	var migrated int
	for hash, tx := range t.remotes {
		if locals.containsTx(tx) {
			t.locals[hash] = tx
			delete(t.remotes, hash)
			migrated++
		}
	}
	return migrated
}

func numSlots(tx *types.Transaction) int {
	if tx == nil {
		return 0
	}
	size := uint64(tx.Size())
	if tx.Type() == types.BlobTxType {
		// Admission retains one immutable sidecar on the transaction and another
		// defensive copy in the proposal sidecar store. Charge both so the
		// generic pool slot ceiling is also a hard blob-memory ceiling.
		sidecarBytes := blobSidecarMemoryBytes(tx.BlobSidecar())
		if sidecarBytes > (math.MaxUint64-size)/2 {
			return math.MaxInt
		}
		size += sidecarBytes * 2
	}
	if size > math.MaxUint64-(txSlotSize-1) {
		return math.MaxInt
	}
	slots := (size + txSlotSize - 1) / txSlotSize
	if slots > uint64(math.MaxInt) {
		return math.MaxInt
	}
	return int(slots)
}
