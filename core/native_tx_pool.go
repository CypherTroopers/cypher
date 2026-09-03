// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package core

import (
	"bytes"
	"container/heap"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
)

const nativePoolBlockBuffer = uint64(4)

// ErrNativeReplaySequenceReserved reports a payer/sequence identity that is
// already pending in the native pool. A distinct payer may use the same
// sequence; replay ordering is payer-scoped.
var ErrNativeReplaySequenceReserved = errors.New("native replay sequence is already reserved")

type nativeReplaySequenceKey struct {
	payer    common.Address
	sequence uint64
}

// nativePoolEntry is deliberately independent from txList and txPricedList.
// NativeTxV1 has no account nonce, so inserting it into either legacy data
// structure would make transactions from the same payer replace one another.
type nativePoolEntry struct {
	tx            *types.Transaction
	hash          common.Hash
	priority      *big.Int
	bytes         uint64
	local         bool
	index         int
	expiryIndex   int
	payerIndex    int
	proposalIndex int
}

type nativePriorityHeap []*nativePoolEntry

type nativeExpiryHeap []*nativePoolEntry

type nativePayerPriorityHeap []*nativePoolEntry

// nativeProposalHeap keeps the strongest proposal candidate at its root. It is
// separate from the local/remote eviction min-heaps: proposal snapshots need a
// global ordering, while eviction must preserve the local-transaction boundary.
type nativeProposalHeap []*nativePoolEntry

func (h nativePriorityHeap) Len() int { return len(h) }

// Less puts the globally worst transaction at the root: lower priority is
// worse, and for equal priority the lexicographically larger hash is worse.
// The inverse ordering is used by PendingNative for deterministic proposals.
func (h nativePriorityHeap) Less(i, j int) bool {
	return nativeRankCompare(h[i], h[j]) < 0
}

func (h nativePriorityHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *nativePriorityHeap) Push(value interface{}) {
	entry := value.(*nativePoolEntry)
	entry.index = len(*h)
	*h = append(*h, entry)
}

func (h *nativePriorityHeap) Pop() interface{} {
	old := *h
	last := len(old) - 1
	entry := old[last]
	old[last] = nil
	entry.index = -1
	*h = old[:last]
	return entry
}

func (h nativeExpiryHeap) Len() int { return len(h) }
func (h nativeExpiryHeap) Less(i, j int) bool {
	if h[i].tx.ValidUntil() != h[j].tx.ValidUntil() {
		return h[i].tx.ValidUntil() < h[j].tx.ValidUntil()
	}
	return bytes.Compare(h[i].hash[:], h[j].hash[:]) < 0
}
func (h nativeExpiryHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].expiryIndex = i
	h[j].expiryIndex = j
}
func (h *nativeExpiryHeap) Push(value interface{}) {
	entry := value.(*nativePoolEntry)
	entry.expiryIndex = len(*h)
	*h = append(*h, entry)
}
func (h *nativeExpiryHeap) Pop() interface{} {
	old := *h
	last := len(old) - 1
	entry := old[last]
	old[last] = nil
	entry.expiryIndex = -1
	*h = old[:last]
	return entry
}

func (h nativePayerPriorityHeap) Len() int { return len(h) }
func (h nativePayerPriorityHeap) Less(i, j int) bool {
	return nativeRankCompare(h[i], h[j]) < 0
}
func (h nativePayerPriorityHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].payerIndex = i
	h[j].payerIndex = j
}
func (h *nativePayerPriorityHeap) Push(value interface{}) {
	entry := value.(*nativePoolEntry)
	entry.payerIndex = len(*h)
	*h = append(*h, entry)
}
func (h *nativePayerPriorityHeap) Pop() interface{} {
	old := *h
	last := len(old) - 1
	entry := old[last]
	old[last] = nil
	entry.payerIndex = -1
	*h = old[:last]
	return entry
}

func (h nativeProposalHeap) Len() int { return len(h) }
func (h nativeProposalHeap) Less(i, j int) bool {
	return nativeRankCompare(h[i], h[j]) > 0
}
func (h nativeProposalHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].proposalIndex = i
	h[j].proposalIndex = j
}
func (h *nativeProposalHeap) Push(value interface{}) {
	entry := value.(*nativePoolEntry)
	entry.proposalIndex = len(*h)
	*h = append(*h, entry)
}
func (h *nativeProposalHeap) Pop() interface{} {
	old := *h
	last := len(old) - 1
	entry := old[last]
	old[last] = nil
	entry.proposalIndex = -1
	*h = old[:last]
	return entry
}

// nativeProposalFrontier traverses a max-heap without copying or mutating it.
// Popping one source index exposes only its two children, so selecting the top
// K entries uses O(K) auxiliary memory and O(K log K) comparisons.
type nativeProposalFrontier struct {
	source  nativeProposalHeap
	indexes []int
}

func (h nativeProposalFrontier) Len() int { return len(h.indexes) }
func (h nativeProposalFrontier) Less(i, j int) bool {
	return nativeRankCompare(h.source[h.indexes[i]], h.source[h.indexes[j]]) > 0
}
func (h nativeProposalFrontier) Swap(i, j int) {
	h.indexes[i], h.indexes[j] = h.indexes[j], h.indexes[i]
}
func (h *nativeProposalFrontier) Push(value interface{}) {
	h.indexes = append(h.indexes, value.(int))
}
func (h *nativeProposalFrontier) Pop() interface{} {
	last := len(h.indexes) - 1
	index := h.indexes[last]
	h.indexes = h.indexes[:last]
	return index
}

// nativeRankCompare returns a positive value when a is a better proposal
// candidate than b, zero when their rank is identical, and a negative value
// otherwise.
func nativeRankCompare(a, b *nativePoolEntry) int {
	if cmp := a.priority.Cmp(b.priority); cmp != 0 {
		return cmp
	}
	// For an equal fee, the smaller hash is the stronger deterministic rank.
	return -bytes.Compare(a.hash[:], b.hash[:])
}

type nativeTxPool struct {
	mu sync.RWMutex

	entries map[common.Hash]*nativePoolEntry
	// sequences prevents two distinct pending transactions from claiming the
	// same payer-scoped replay identity and entering one proposal.
	sequences map[nativeReplaySequenceKey]*nativePoolEntry
	locals    nativePriorityHeap
	remotes   nativePriorityHeap
	expiry    nativeExpiryHeap
	anchors   map[common.Hash]map[common.Hash]*nativePoolEntry
	// reservedCosts holds the sum of signed maximum fee+value commitments per
	// nonce-free payer. It prevents one account from filling the priority pool
	// with individually affordable transactions that cannot execute together.
	reservedCosts map[common.Address]*big.Int
	payers        map[common.Address]*nativePayerPriorityHeap
	proposal      nativeProposalHeap
	bytes         uint64

	maxCount int
	maxBytes uint64
}

func newNativeTxPool(config TxPoolConfig, chainConfig *params.ChainConfig) *nativeTxPool {
	pool := &nativeTxPool{
		entries:       make(map[common.Hash]*nativePoolEntry),
		sequences:     make(map[nativeReplaySequenceKey]*nativePoolEntry),
		anchors:       make(map[common.Hash]map[common.Hash]*nativePoolEntry),
		reservedCosts: make(map[common.Address]*big.Int),
		payers:        make(map[common.Address]*nativePayerPriorityHeap),
	}
	if chainConfig == nil || !chainConfig.NativeParallelEnabled() {
		return pool
	}
	native := chainConfig.NativeParallel
	globalBytes := saturatingMulUint64(saturatingAddUint64(config.GlobalSlots, config.GlobalQueue), txSlotSize)
	bufferedBytes := saturatingMulUint64(native.MaxBlockBytes, nativePoolBlockBuffer)
	pool.maxBytes = minPositiveUint64(globalBytes, bufferedBytes)

	bufferedCount := saturatingMulUint64(native.MaxTransactionsPerBlock, nativePoolBlockBuffer)
	pool.maxCount = saturatingUint64ToInt(bufferedCount)
	return pool
}

func saturatingMulUint64(a, b uint64) uint64 {
	if a != 0 && b > ^uint64(0)/a {
		return ^uint64(0)
	}
	return a * b
}

func saturatingAddUint64(a, b uint64) uint64 {
	if b > ^uint64(0)-a {
		return ^uint64(0)
	}
	return a + b
}

func saturatingUint64ToInt(value uint64) int {
	maxInt := uint64(^uint(0) >> 1)
	if value > maxInt {
		return int(maxInt)
	}
	return int(value)
}

func minPositiveUint64(a, b uint64) uint64 {
	if a <= 0 {
		return b
	}
	if b <= 0 || a < b {
		return a
	}
	return b
}

func (p *nativeTxPool) get(hash common.Hash) *types.Transaction {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if entry := p.entries[hash]; entry != nil {
		return entry.tx
	}
	return nil
}

func (p *nativeTxPool) count() int {
	if p == nil {
		return 0
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.entries)
}

func (p *nativeTxPool) add(tx *types.Transaction, local bool, payerBalance ...*big.Int) ([]*nativePoolEntry, error) {
	if p == nil || tx == nil || p.maxCount <= 0 || p.maxBytes == 0 {
		return nil, ErrTxPoolOverflow
	}
	entry := &nativePoolEntry{
		tx:            tx,
		hash:          tx.Hash(),
		priority:      tx.PriorityFeePerCompute(),
		bytes:         uint64(tx.Size()),
		local:         local,
		index:         -1,
		expiryIndex:   -1,
		payerIndex:    -1,
		proposalIndex: -1,
	}
	if entry.bytes > p.maxBytes {
		return nil, ErrTxPoolOverflow
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.entries[entry.hash] != nil {
		return nil, ErrAlreadyKnown
	}
	replayKey := nativeReplaySequenceKey{payer: tx.Payer(), sequence: tx.ReplaySequence()}
	if reserved := p.sequences[replayKey]; reserved != nil {
		return nil, fmt.Errorf("%w: payer %s sequence %d (transaction %s)", ErrNativeReplaySequenceReserved, replayKey.payer, replayKey.sequence, reserved.hash)
	}

	needCount := len(p.entries) + 1 - p.maxCount
	var needBytes uint64
	if totalBytes := saturatingAddUint64(p.bytes, entry.bytes); totalBytes > p.maxBytes {
		needBytes = totalBytes - p.maxBytes
	}
	if needCount < 0 {
		needCount = 0
	}

	var (
		victims    []*nativePoolEntry
		freedBytes uint64
	)
	if needCount > 0 || needBytes > 0 {
		// The heap root is already the globally worst entry. Pop only as many
		// roots as this admission needs instead of copying and sorting the entire
		// million-entry pool while holding its mutex. Until the admission is known
		// to succeed only the priority heaps are changed; all durable indexes stay
		// intact and the pops can be rolled back without observable mutation.
		popVictims := func(priority *nativePriorityHeap, force bool) {
			for (len(victims) < needCount || freedBytes < needBytes) && priority.Len() > 0 {
				candidate := (*priority)[0]
				if !force && nativeRankCompare(entry, candidate) <= 0 {
					break
				}
				victims = append(victims, heap.Pop(priority).(*nativePoolEntry))
				freedBytes = saturatingAddUint64(freedBytes, candidate.bytes)
			}
		}
		popVictims(&p.remotes, local)
		if local && (len(victims) < needCount || freedBytes < needBytes) {
			popVictims(&p.locals, false)
		}
		if len(victims) < needCount || freedBytes < needBytes {
			p.restorePriorityVictimsLocked(victims)
			return nil, ErrTxPoolOverflow
		}
	}
	if len(payerBalance) > 0 && payerBalance[0] != nil {
		reserved := new(big.Int)
		if current := p.reservedCosts[tx.Payer()]; current != nil {
			reserved.Set(current)
		}
		for _, victim := range victims {
			if victim.tx.Payer() == tx.Payer() {
				reserved.Sub(reserved, victim.tx.Cost())
			}
		}
		reserved.Add(reserved, tx.Cost())
		if reserved.Sign() < 0 || payerBalance[0].Cmp(reserved) < 0 {
			p.restorePriorityVictimsLocked(victims)
			return nil, ErrInsufficientFunds
		}
	}

	for _, victim := range victims {
		p.removePriorityPoppedEntryLocked(victim)
	}
	p.entries[entry.hash] = entry
	p.sequences[replayKey] = entry
	anchor := entry.tx.RecentBlockHash()
	if p.anchors[anchor] == nil {
		p.anchors[anchor] = make(map[common.Hash]*nativePoolEntry)
	}
	p.anchors[anchor][entry.hash] = entry
	p.addReservedCostLocked(entry)
	payer := entry.tx.Payer()
	if p.payers[payer] == nil {
		p.payers[payer] = new(nativePayerPriorityHeap)
	}
	heap.Push(p.payers[payer], entry)
	p.bytes = saturatingAddUint64(p.bytes, entry.bytes)
	if entry.local {
		heap.Push(&p.locals, entry)
	} else {
		heap.Push(&p.remotes, entry)
	}
	heap.Push(&p.expiry, entry)
	heap.Push(&p.proposal, entry)
	return victims, nil
}

func (p *nativeTxPool) restorePriorityVictimsLocked(victims []*nativePoolEntry) {
	for _, victim := range victims {
		if victim.local {
			heap.Push(&p.locals, victim)
		} else {
			heap.Push(&p.remotes, victim)
		}
	}
}

// removePriorityPoppedEntryLocked completes removal after the victim has
// already been detached from its priority heap during transactional admission.
func (p *nativeTxPool) removePriorityPoppedEntryLocked(entry *nativePoolEntry) {
	if entry == nil || entry.index != -1 || p.entries[entry.hash] != entry {
		return
	}
	heap.Remove(&p.expiry, entry.expiryIndex)
	p.removePayerIndexLocked(entry)
	p.removeProposalIndexLocked(entry)
	anchor := entry.tx.RecentBlockHash()
	delete(p.anchors[anchor], entry.hash)
	if len(p.anchors[anchor]) == 0 {
		delete(p.anchors, anchor)
	}
	delete(p.entries, entry.hash)
	delete(p.sequences, nativeReplaySequenceKey{payer: entry.tx.Payer(), sequence: entry.tx.ReplaySequence()})
	p.subtractReservedCostLocked(entry)
	p.bytes -= entry.bytes
}

func (p *nativeTxPool) removeProposalIndexLocked(entry *nativePoolEntry) {
	if entry == nil || entry.proposalIndex < 0 || entry.proposalIndex >= p.proposal.Len() || p.proposal[entry.proposalIndex] != entry {
		return
	}
	heap.Remove(&p.proposal, entry.proposalIndex)
}

func (p *nativeTxPool) removePayerIndexLocked(entry *nativePoolEntry) {
	if entry == nil || entry.tx == nil || entry.payerIndex < 0 {
		return
	}
	payer := entry.tx.Payer()
	priority := p.payers[payer]
	if priority == nil || entry.payerIndex >= priority.Len() || (*priority)[entry.payerIndex] != entry {
		return
	}
	heap.Remove(priority, entry.payerIndex)
	if priority.Len() == 0 {
		delete(p.payers, payer)
	}
}

func (p *nativeTxPool) addReservedCostLocked(entry *nativePoolEntry) {
	if entry == nil || entry.tx == nil {
		return
	}
	payer := entry.tx.Payer()
	if p.reservedCosts[payer] == nil {
		p.reservedCosts[payer] = new(big.Int)
	}
	p.reservedCosts[payer].Add(p.reservedCosts[payer], entry.tx.Cost())
}

func (p *nativeTxPool) subtractReservedCostLocked(entry *nativePoolEntry) {
	if entry == nil || entry.tx == nil {
		return
	}
	payer := entry.tx.Payer()
	reserved := p.reservedCosts[payer]
	if reserved == nil {
		return
	}
	reserved.Sub(reserved, entry.tx.Cost())
	if reserved.Sign() <= 0 {
		delete(p.reservedCosts, payer)
	}
}

func (p *nativeTxPool) remove(hash common.Hash) *nativePoolEntry {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	entry := p.entries[hash]
	if entry != nil {
		p.removeEntryLocked(entry)
	}
	return entry
}

// removeReplaySequences removes any pending transaction which conflicts with
// a payer/sequence identity consumed by newly canonical native transactions.
// The canonical transaction may have a different hash and may never have been
// present in this node's pool.
func (p *nativeTxPool) removeReplaySequences(txs types.Transactions) []*nativePoolEntry {
	if p == nil || len(txs) == 0 {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	removed := make([]*nativePoolEntry, 0)
	for _, tx := range txs {
		if tx == nil || tx.Type() != types.NativeTxType {
			continue
		}
		key := nativeReplaySequenceKey{payer: tx.Payer(), sequence: tx.ReplaySequence()}
		entry := p.sequences[key]
		if entry == nil {
			continue
		}
		p.removeEntryLocked(entry)
		removed = append(removed, entry)
	}
	return removed
}

func (p *nativeTxPool) removeEntryLocked(entry *nativePoolEntry) {
	if entry == nil || p.entries[entry.hash] != entry {
		return
	}
	if entry.local {
		heap.Remove(&p.locals, entry.index)
	} else {
		heap.Remove(&p.remotes, entry.index)
	}
	heap.Remove(&p.expiry, entry.expiryIndex)
	p.removePayerIndexLocked(entry)
	p.removeProposalIndexLocked(entry)
	anchor := entry.tx.RecentBlockHash()
	delete(p.anchors[anchor], entry.hash)
	if len(p.anchors[anchor]) == 0 {
		delete(p.anchors, anchor)
	}
	delete(p.entries, entry.hash)
	delete(p.sequences, nativeReplaySequenceKey{payer: entry.tx.Payer(), sequence: entry.tx.ReplaySequence()})
	p.subtractReservedCostLocked(entry)
	p.bytes -= entry.bytes
}

func (p *nativeTxPool) removeUnfundedPayers(payers map[common.Address]struct{}, balance func(common.Address) *big.Int) []*nativePoolEntry {
	if p == nil || len(payers) == 0 || balance == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var removed []*nativePoolEntry
	for payer := range payers {
		available := balance(payer)
		if available == nil {
			available = new(big.Int)
		}
		for reserved := p.reservedCosts[payer]; reserved != nil && reserved.Cmp(available) > 0; reserved = p.reservedCosts[payer] {
			priority := p.payers[payer]
			if priority == nil || priority.Len() == 0 {
				delete(p.reservedCosts, payer)
				break
			}
			victim := (*priority)[0]
			p.removeEntryLocked(victim)
			removed = append(removed, victim)
		}
	}
	return removed
}

func (p *nativeTxPool) removeExpired(head uint64) []*nativePoolEntry {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var removed []*nativePoolEntry
	for len(p.expiry) > 0 && p.expiry[0].tx.ValidUntil() <= head {
		entry := p.expiry[0]
		p.removeEntryLocked(entry)
		removed = append(removed, entry)
	}
	return removed
}

func (p *nativeTxPool) removeAnchored(hashes map[common.Hash]struct{}) []*nativePoolEntry {
	if p == nil || len(hashes) == 0 {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var removed []*nativePoolEntry
	for anchor := range hashes {
		for _, entry := range p.anchors[anchor] {
			removed = append(removed, entry)
		}
	}
	for _, entry := range removed {
		p.removeEntryLocked(entry)
	}
	return removed
}

func (p *nativeTxPool) removeUnderpriced(price *big.Int) []*nativePoolEntry {
	if p == nil || price == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var removed []*nativePoolEntry
	for _, entry := range p.entries {
		if entry.tx.MaxFeePerCompute().Cmp(price) < 0 {
			removed = append(removed, entry)
		}
	}
	for _, entry := range removed {
		p.removeEntryLocked(entry)
	}
	return removed
}

func (p *nativeTxPool) markPayerLocal(payer common.Address) int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var migrated int
	for _, entry := range p.entries {
		if entry.local || entry.tx.Payer() != payer {
			continue
		}
		heap.Remove(&p.remotes, entry.index)
		entry.local = true
		heap.Push(&p.locals, entry)
		migrated++
	}
	return migrated
}

func (p *nativeTxPool) snapshot(limits ...uint64) types.Transactions {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	count := p.proposal.Len()
	if len(limits) > 0 && limits[0] < uint64(count) {
		count = int(limits[0])
	}
	if count == 0 {
		p.mu.RUnlock()
		return nil
	}
	// Heap entries contain immutable transaction/ranking fields. Copy only the
	// pointer generation while holding the pool lock, then perform the O(K log K)
	// frontier walk without blocking ingress, eviction or canonical removal.
	// A transaction may be removed after this point just as it could immediately
	// after the former lock-scoped snapshot returned; proposal preflight remains
	// the authoritative eligibility check.
	source := append(nativeProposalHeap(nil), p.proposal...)
	p.mu.RUnlock()
	frontier := &nativeProposalFrontier{
		source:  source,
		indexes: make([]int, 0, count),
	}
	heap.Push(frontier, 0)
	txs := make(types.Transactions, 0, count)
	for len(txs) < count && frontier.Len() > 0 {
		index := heap.Pop(frontier).(int)
		txs = append(txs, source[index].tx)
		if len(txs) == count {
			break
		}
		if index < source.Len()/2 {
			left := index*2 + 1
			heap.Push(frontier, left)
			if right := left + 1; right < source.Len() {
				heap.Push(frontier, right)
			}
		}
	}
	return txs
}

func (p *nativeTxPool) localByPayer() map[common.Address]types.Transactions {
	result := make(map[common.Address]types.Transactions)
	if p == nil {
		return result
	}
	p.mu.RLock()
	for _, entry := range p.locals {
		result[entry.tx.Payer()] = append(result[entry.tx.Payer()], entry.tx)
	}
	p.mu.RUnlock()
	for payer := range result {
		txs := result[payer]
		sort.Slice(txs, func(i, j int) bool {
			left := &nativePoolEntry{hash: txs[i].Hash(), priority: txs[i].PriorityFeePerCompute()}
			right := &nativePoolEntry{hash: txs[j].Hash(), priority: txs[j].PriorityFeePerCompute()}
			return nativeRankCompare(left, right) > 0
		})
		result[payer] = txs
	}
	return result
}

// PendingNative returns a deterministic, immutable transaction slice ordered
// by descending priority fee and then ascending native transaction hash. With
// an optional limit it visits only the strongest K entries of the maintained
// proposal heap. Omitting the limit preserves the historical full snapshot.
func (pool *TxPool) PendingNative(limits ...uint64) types.Transactions {
	if pool == nil {
		return nil
	}
	return pool.native.snapshot(limits...)
}

// updateNativeCanonicalLocked advances the bounded canonical hash ring and
// returns hashes that ceased to be canonical (including hashes aged out of the
// replay window). The common extension path is O(1); initialization and a
// reorg rebuild at most ReplayWindowBlocks entries.
func (pool *TxPool) updateNativeCanonicalLocked(oldHead, newHead *types.Header) map[common.Hash]struct{} {
	invalidated := make(map[common.Hash]struct{})
	if pool == nil || pool.chainconfig == nil || !pool.chainconfig.NativeParallelEnabled() || newHead == nil || newHead.Number == nil {
		return invalidated
	}
	if pool.nativeCanonical == nil {
		pool.nativeCanonical = make(map[uint64]common.Hash)
	}
	oldCanonical := pool.nativeCanonical
	previous := make(map[uint64]common.Hash, len(oldCanonical))
	for number, hash := range oldCanonical {
		previous[number] = hash
	}
	window := pool.chainconfig.NativeParallel.ReplayWindowBlocks
	newNumber := newHead.Number.Uint64()
	newHash := newHead.Hash()
	linear := oldHead != nil && oldHead.Number != nil &&
		newNumber == oldHead.Number.Uint64()+1 && newHead.ParentHash == oldHead.Hash() &&
		oldCanonical[oldHead.Number.Uint64()] == oldHead.Hash()
	if linear {
		oldCanonical[newNumber] = newHash
		if newNumber >= window {
			delete(oldCanonical, newNumber-window)
		}
	} else {
		rebuilt := make(map[uint64]common.Hash, saturatingUint64ToInt(window))
		number, hash, parent := newNumber, newHash, newHead.ParentHash
		for retained := uint64(0); retained < window; retained++ {
			rebuilt[number] = hash
			if number == 0 {
				break
			}
			number--
			hash = parent
			block := pool.chain.GetBlock(hash, number)
			if block == nil {
				// The child header authenticates this immediate parent hash, so it
				// remains safe to retain even when older history is unavailable.
				rebuilt[number] = hash
				break
			}
			parent = block.ParentHash()
		}
		pool.nativeCanonical = rebuilt
	}
	for number, hash := range previous {
		if canonical, ok := pool.nativeCanonical[number]; !ok || canonical != hash {
			invalidated[hash] = struct{}{}
		}
	}
	pool.nativeHeadNumber = newNumber
	return invalidated
}

func (pool *TxPool) pruneNativeLocked(oldHead, newHead *types.Header) {
	invalidated := pool.updateNativeCanonicalLocked(oldHead, newHead)
	pool.recordNativeRemovalsLocked(pool.native.removeAnchored(invalidated), "non-canonical replay anchor")
	pool.recordNativeRemovalsLocked(pool.native.removeExpired(pool.nativeHeadNumber), "expired replay window")
}

func (pool *TxPool) recordNativeRemovalsLocked(entries []*nativePoolEntry, reason string) {
	if len(entries) == 0 {
		return
	}
	var locals int64
	for _, entry := range entries {
		delete(pool.seen, entry.hash)
		if entry.local {
			locals++
		}
	}
	pendingGauge.Dec(int64(len(entries)))
	if locals > 0 {
		localGauge.Dec(locals)
	}
	pool.markPendingIndexDirty()
	log.Debug("Removed native transactions", "count", len(entries), "reason", reason)
}
