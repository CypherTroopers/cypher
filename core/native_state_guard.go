package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"runtime"
	"sort"
	"sync"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
)

// ErrUndeclaredNativeStateAccess is a consensus-invalid native execution. The
// error is sticky and checked after the EVM returns, so contract code cannot
// catch an access-manifest violation as an ordinary CALL failure.
var ErrUndeclaredNativeStateAccess = errors.New("undeclared native state access")

// ErrNativeLogLimitExceeded is sticky for the lifetime of a NativeTxV1 EVM
// execution. Logs are rejected before they enter StateDB, preventing an
// ultimately-invalid transaction from retaining an unbounded log slice until
// the post-execution envelope check runs.
var ErrNativeLogLimitExceeded = errors.New("native transaction log limit exceeded")

// ErrNativeTransactionReplay reports a signed payer sequence which was already
// consumed, fell below the payer's canonical base, or was repeated in a block.
var ErrNativeTransactionReplay = errors.New("native transaction already consumed")

// ErrNativeReplaySequenceGap reports a sequence which cannot fit in the
// payer's 256-entry canonical sliding window after all lower sequences in the
// same block have been applied. It is consensus-invalid, not a local policy
// rejection.
var ErrNativeReplaySequenceGap = errors.New("native replay sequence has an unresolved gap")

// nativeEVMBlockHashWindow is the exact history range exposed by the EVM
// BLOCKHASH opcode. EIP-2935 retains a larger ring, but importing more than the
// opcode can address would add proposal work without changing semantics.
const nativeEVMBlockHashWindow = uint64(256)

// nativeLogObjectMemoryReserve covers the Go Log object, receipt/state slice
// pointers and allocator overhead not represented by its consensus RLP. A
// transaction's signed LogLimit is enforced against both exact wire bytes and
// this retained-memory charge, so many zero-data LOG opcodes cannot turn a
// small byte declaration into millions of heap objects.
const nativeLogObjectMemoryReserve = uint64(256)

// NativeReplayAnchorSet is an immutable, proposal-local view of every recent
// block hash which NativeTxV1 may legally sign. Building it once makes proposer
// filtering and validator rejection use the same rules without an ancestry
// walk per transaction.
type NativeReplayAnchorSet struct {
	proposalNumber uint64
	window         uint64
	ancestry       map[uint64]common.Hash
}

// PrepareNativeBlockHashes snapshots the EVM BLOCKHASH window from the
// state-rooted EIP-2935 ring. ProcessParentBlockHash must have run first so the
// immediate proposal parent is present. The resulting immutable view follows
// Copy and CopyDeclared branches and never depends on whether a certified
// HotStuff parent has reached the node-local canonical header database.
func PrepareNativeBlockHashes(config *params.ChainConfig, header *types.Header, statedb *state.StateDB) error {
	if config == nil || !config.NativeParallelEnabled() {
		return nil
	}
	if header == nil || header.Number == nil || statedb == nil {
		return errors.New("native BLOCKHASH view requires a header and parent-derived state")
	}
	if !header.Number.IsUint64() {
		return fmt.Errorf("native BLOCKHASH proposal number %s exceeds uint64", header.Number)
	}
	number := header.Number.Uint64()
	hashes := make(map[uint64]common.Hash, nativeEVMBlockHashWindow)
	oldest := uint64(0)
	if number > nativeEVMBlockHashWindow {
		oldest = number - nativeEVMBlockHashWindow
	}
	for ancestorNumber := oldest; ancestorNumber < number; ancestorNumber++ {
		historySlot := common.BigToHash(new(big.Int).SetUint64(ancestorNumber % params.NativeReplayHistoryWindow))
		ancestorHash := statedb.GetState(params.HistoryStorageAddress, historySlot)
		if ancestorHash == (common.Hash{}) {
			return fmt.Errorf("native BLOCKHASH history hash for block %d is unavailable", ancestorNumber)
		}
		hashes[ancestorNumber] = ancestorHash
	}
	statedb.SetNativeBlockHashes(hashes)
	return nil
}

// NewNativeReplayAnchorSet reads the exact parent branch from EIP-2935 history
// in the parent-derived StateDB. ProcessParentBlockHash must run first so the
// immediate proposal parent is present. This state-rooted source also works for
// certified HotStuff parents which are intentionally absent from the local
// canonical header index.
func NewNativeReplayAnchorSet(config *params.ChainConfig, statedb *state.StateDB, proposalNumber uint64) (*NativeReplayAnchorSet, error) {
	if config == nil || !config.NativeParallelEnabled() {
		return nil, errors.New("native replay anchors require the genesis-native configuration")
	}
	if !config.NativeParallel.RequireNativeTransactions {
		return nil, ErrNativeTxDisabled
	}
	window := config.NativeParallel.ReplayWindowBlocks
	if window == 0 || window > params.NativeReplayHistoryWindow {
		return nil, fmt.Errorf("native replay window %d is invalid", window)
	}
	anchors := &NativeReplayAnchorSet{
		proposalNumber: proposalNumber,
		window:         window,
		ancestry:       make(map[uint64]common.Hash, int(window)),
	}
	if proposalNumber == 0 {
		return anchors, nil
	}
	if statedb == nil {
		return nil, errors.New("native replay anchors require parent-derived state")
	}
	oldest := uint64(0)
	if proposalNumber > window {
		oldest = proposalNumber - window
	}
	ancestorNumber := proposalNumber - 1
	for {
		historySlot := common.BigToHash(new(big.Int).SetUint64(ancestorNumber % params.NativeReplayHistoryWindow))
		ancestorHash := statedb.GetState(params.HistoryStorageAddress, historySlot)
		if ancestorHash == (common.Hash{}) {
			return nil, fmt.Errorf("native replay history hash for block %d is unavailable", ancestorNumber)
		}
		anchors.ancestry[ancestorNumber] = ancestorHash
		if ancestorNumber == 0 || ancestorNumber == oldest {
			break
		}
		ancestorNumber--
	}
	return anchors, nil
}

// Validate checks one native transaction against this proposal's exact parent
// ancestry and signed validity interval.
func (a *NativeReplayAnchorSet) Validate(tx *types.Transaction) error {
	if a == nil {
		return errors.New("native replay anchor set is unavailable")
	}
	if tx == nil || tx.Type() != types.NativeTxType {
		return errors.New("native replay anchor validation requires NativeTxV1")
	}
	recentNumber := tx.RecentBlockNumber()
	if recentNumber >= a.proposalNumber {
		return fmt.Errorf("recent block %d is not before proposal block %d", recentNumber, a.proposalNumber)
	}
	if a.proposalNumber-1-recentNumber >= a.window {
		return fmt.Errorf("recent block %d is outside replay window %d at block %d", recentNumber, a.window, a.proposalNumber)
	}
	if tx.ValidUntil() < a.proposalNumber {
		return fmt.Errorf("expired at block %d before proposal block %d", tx.ValidUntil(), a.proposalNumber)
	}
	if tx.ValidUntil()-recentNumber > a.window {
		return fmt.Errorf("validity span %d exceeds replay window %d", tx.ValidUntil()-recentNumber, a.window)
	}
	if ancestor, ok := a.ancestry[recentNumber]; !ok || ancestor != tx.RecentBlockHash() {
		return fmt.Errorf("references a block outside proposal ancestry %d/%s", recentNumber, tx.RecentBlockHash())
	}
	return nil
}

// nativeReplaySequenceState is rooted in the account/storage trie. Base is the
// lowest not-yet-consumed sequence and bitmap bit N represents Base+N. The
// bitmap is kept normalized: bit zero is clear, except for the terminal
// MaxUint64 sequence which is represented by Base=MaxUint64, bit zero set.
type nativeReplaySequenceState struct {
	base   uint64
	bitmap [4]uint64
}

type nativeReplaySequenceEntry struct {
	payer    common.Address
	index    int
	sequence uint64
}

type nativeReplaySequenceChange struct {
	payer    common.Address
	registry common.Address
	before   nativeReplaySequenceState
	after    nativeReplaySequenceState
}

type nativeReplaySequenceGroup struct {
	start    int
	end      int
	minIndex int
}

type nativeReplaySequenceGroupResult struct {
	change nativeReplaySequenceChange
	err    error
}

// NativeReplaySequenceError identifies the canonical block index whose signed
// sequence made replay prevalidation fail. Proposal construction can remove the
// offending transaction and retry from a fresh parent state without guessing
// from an error string.
type NativeReplaySequenceError struct {
	Index    int
	Payer    common.Address
	Sequence uint64
	Err      error
}

func (e *NativeReplaySequenceError) Error() string {
	if e == nil {
		return "native replay sequence validation failed"
	}
	return fmt.Sprintf("native transaction %d payer %s sequence %d: %v", e.Index, e.Payer, e.Sequence, e.Err)
}

func (e *NativeReplaySequenceError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func nativeReplaySequenceRegistryAddress(payer common.Address) common.Address {
	return params.NativeReplayRegistryAddressForPayer(payer)
}

func nativeReplaySequenceSlots(payer common.Address) (baseSlot, bitmapSlot common.Hash) {
	baseSlot[0] = 1
	bitmapSlot[0] = 2
	copy(baseSlot[common.HashLength-common.AddressLength:], payer[:])
	copy(bitmapSlot[common.HashLength-common.AddressLength:], payer[:])
	return baseSlot, bitmapSlot
}

func nativeReplayBitmapFromHash(encoded common.Hash) (bitmap [4]uint64) {
	for word := 0; word < len(bitmap); word++ {
		offset := (len(bitmap) - 1 - word) * 8
		bitmap[word] = binary.BigEndian.Uint64(encoded[offset : offset+8])
	}
	return bitmap
}

func nativeReplayBitmapHash(bitmap [4]uint64) (encoded common.Hash) {
	for word := 0; word < len(bitmap); word++ {
		offset := (len(bitmap) - 1 - word) * 8
		binary.BigEndian.PutUint64(encoded[offset:offset+8], bitmap[word])
	}
	return encoded
}

func nativeReplayBaseHash(base uint64) (encoded common.Hash) {
	binary.BigEndian.PutUint64(encoded[common.HashLength-8:], base)
	return encoded
}

func (s *nativeReplaySequenceState) has(offset uint64) bool {
	return s.bitmap[offset/64]&(uint64(1)<<(offset%64)) != 0
}

func (s *nativeReplaySequenceState) set(offset uint64) {
	s.bitmap[offset/64] |= uint64(1) << (offset % 64)
}

func (s *nativeReplaySequenceState) shift() {
	for word := 0; word < len(s.bitmap)-1; word++ {
		s.bitmap[word] = s.bitmap[word]>>1 | s.bitmap[word+1]<<63
	}
	s.bitmap[len(s.bitmap)-1] >>= 1
}

func (s *nativeReplaySequenceState) consume(sequence uint64) error {
	if sequence < s.base {
		return fmt.Errorf("%w: sequence %d is below base %d", ErrNativeTransactionReplay, sequence, s.base)
	}
	offset := sequence - s.base
	if offset >= 256 {
		return fmt.Errorf("%w: sequence %d is %d ahead of base %d", ErrNativeReplaySequenceGap, sequence, offset, s.base)
	}
	if s.has(offset) {
		return fmt.Errorf("%w: sequence %d is already set at base %d", ErrNativeTransactionReplay, sequence, s.base)
	}
	s.set(offset)
	for s.has(0) {
		if s.base == math.MaxUint64 {
			// The terminal sequence has no representable successor. Keeping bit
			// zero set makes every future MaxUint64 attempt an exact replay.
			break
		}
		s.shift()
		s.base++
	}
	return nil
}

func validateNativeReplaySequenceState(value nativeReplaySequenceState) error {
	if value.base != math.MaxUint64 && value.has(0) {
		return errors.New("native replay sequence state is not base-normalized")
	}
	validBits := uint64(256)
	if value.base > math.MaxUint64-255 {
		validBits = math.MaxUint64 - value.base + 1
	}
	fullWords := validBits / 64
	remainder := validBits % 64
	if remainder != 0 {
		validMask := (uint64(1) << remainder) - 1
		if value.bitmap[fullWords]&^validMask != 0 {
			return errors.New("native replay bitmap represents a sequence above uint64")
		}
		fullWords++
	}
	for word := fullWords; word < uint64(len(value.bitmap)); word++ {
		if value.bitmap[word] != 0 {
			return errors.New("native replay bitmap represents a sequence above uint64")
		}
	}
	return nil
}

func readNativeReplaySequenceState(statedb *state.StateDB, payer common.Address) (nativeReplaySequenceState, error) {
	if statedb == nil {
		return nativeReplaySequenceState{}, errors.New("native replay sequence state is unavailable")
	}
	registry := nativeReplaySequenceRegistryAddress(payer)
	if !statedb.Exist(registry) {
		if err := statedb.Error(); err != nil {
			return nativeReplaySequenceState{}, fmt.Errorf("read native replay registry %s: %w", registry, err)
		}
		return nativeReplaySequenceState{}, nil
	}
	if nonce := statedb.GetNonce(registry); nonce != 1 {
		return nativeReplaySequenceState{}, fmt.Errorf("native replay registry %s has nonce %d, want 1", registry, nonce)
	}
	baseSlot, bitmapSlot := nativeReplaySequenceSlots(payer)
	baseHash, err := statedb.NativeProtocolState(registry, baseSlot)
	if err != nil {
		return nativeReplaySequenceState{}, fmt.Errorf("read native replay sequence for %s: %w", payer, err)
	}
	for _, value := range baseHash[:common.HashLength-8] {
		if value != 0 {
			return nativeReplaySequenceState{}, fmt.Errorf("native replay base for %s exceeds uint64", payer)
		}
	}
	value := nativeReplaySequenceState{
		base:   binary.BigEndian.Uint64(baseHash[common.HashLength-8:]),
		bitmap: [4]uint64{},
	}
	bitmapHash, err := statedb.NativeProtocolState(registry, bitmapSlot)
	if err != nil {
		return nativeReplaySequenceState{}, fmt.Errorf("read native replay bitmap for %s: %w", payer, err)
	}
	value.bitmap = nativeReplayBitmapFromHash(bitmapHash)
	if err := validateNativeReplaySequenceState(value); err != nil {
		return nativeReplaySequenceState{}, fmt.Errorf("invalid native replay state for %s: %w", payer, err)
	}
	return value, nil
}

func validateNativeReplaySequenceConfig(config *params.ChainConfig) error {
	if config == nil || !config.NativeParallelEnabled() {
		return errors.New("native replay sequence requires the genesis-native configuration")
	}
	if !config.NativeParallel.RequireNativeTransactions {
		return ErrNativeTxDisabled
	}
	window := config.NativeParallel.ReplayWindowBlocks
	if window == 0 || window > params.NativeReplayHistoryWindow {
		return fmt.Errorf("native replay window %d is invalid", window)
	}
	return nil
}

func checkNativeReplaySequence(config *params.ChainConfig, statedb *state.StateDB, tx *types.Transaction) error {
	if statedb == nil || tx == nil || tx.Type() != types.NativeTxType {
		return nil
	}
	if err := validateNativeReplaySequenceConfig(config); err != nil {
		return err
	}
	value, err := readNativeReplaySequenceState(statedb, tx.Payer())
	if err != nil {
		return err
	}
	return value.consume(tx.ReplaySequence())
}

func validateNativeReplaySequenceGroup(statedb *state.StateDB, entries []nativeReplaySequenceEntry, group nativeReplaySequenceGroup) nativeReplaySequenceGroupResult {
	if group.start < 0 || group.end <= group.start || group.end > len(entries) {
		return nativeReplaySequenceGroupResult{err: errors.New("invalid native replay payer group")}
	}
	payer := entries[group.start].payer
	before, err := readNativeReplaySequenceState(statedb, payer)
	if err != nil {
		entry := entries[group.start]
		return nativeReplaySequenceGroupResult{err: &NativeReplaySequenceError{
			Index: group.minIndex, Payer: payer, Sequence: entry.sequence, Err: err,
		}}
	}
	after := before
	for index := group.start; index < group.end; index++ {
		entry := entries[index]
		if err := after.consume(entry.sequence); err != nil {
			return nativeReplaySequenceGroupResult{err: &NativeReplaySequenceError{
				Index: entry.index, Payer: payer, Sequence: entry.sequence, Err: err,
			}}
		}
	}
	return nativeReplaySequenceGroupResult{change: nativeReplaySequenceChange{
		payer: payer, registry: nativeReplaySequenceRegistryAddress(payer), before: before, after: after,
	}}
}

func validateNativeReplaySequenceGroups(statedb *state.StateDB, entries []nativeReplaySequenceEntry, groups []nativeReplaySequenceGroup) ([]nativeReplaySequenceChange, error) {
	if len(groups) == 0 {
		return nil, nil
	}
	if err := statedb.Error(); err != nil {
		return nil, fmt.Errorf("native replay state is unavailable: %w", err)
	}
	results := make([]nativeReplaySequenceGroupResult, len(groups))
	workerCount := runtime.GOMAXPROCS(0)
	if workerCount < 1 {
		workerCount = 1
	}
	if workerCount > 64 {
		workerCount = 64
	}
	if workerCount > len(groups) {
		workerCount = len(groups)
	}
	if workerCount == 1 {
		for index, group := range groups {
			results[index] = validateNativeReplaySequenceGroup(statedb, entries, group)
		}
	} else {
		// StateDB lazily populates account/storage caches and is not safe for
		// concurrent reads. Give every bounded worker an independent trie/cache
		// view, then publish validated payer deltas serially below.
		views := make([]*state.StateDB, workerCount)
		views[0] = statedb
		for worker := 1; worker < workerCount; worker++ {
			views[worker] = statedb.Copy()
		}
		jobs := make(chan int, workerCount)
		var workers sync.WaitGroup
		workers.Add(workerCount)
		for worker := 0; worker < workerCount; worker++ {
			worker := worker
			go func() {
				defer workers.Done()
				for index := range jobs {
					results[index] = validateNativeReplaySequenceGroup(views[worker], entries, groups[index])
				}
			}()
		}
		for index := range groups {
			jobs <- index
		}
		close(jobs)
		workers.Wait()
	}

	// Multiple payer groups can fail independently. Always report the failure
	// with the lowest canonical transaction index, independent of worker timing.
	var selected *NativeReplaySequenceError
	for index, result := range results {
		if result.err == nil {
			continue
		}
		var replayErr *NativeReplaySequenceError
		if !errors.As(result.err, &replayErr) {
			replayErr = &NativeReplaySequenceError{Index: groups[index].minIndex, Payer: entries[groups[index].start].payer, Err: result.err}
		}
		if selected == nil || replayErr.Index < selected.Index {
			selected = replayErr
		}
	}
	if selected != nil {
		return nil, selected
	}
	changes := make([]nativeReplaySequenceChange, len(results))
	for index := range results {
		changes[index] = results[index].change
	}
	return changes, nil
}

// PrepareNativeReplaySequences validates a complete block against its parent
// state, then publishes at most two state writes per payer. Sequences are
// sorted within each payer domain, allowing an arbitrarily long contiguous run
// to advance through the fixed 256-bit window while rejecting duplicates, old
// values and gaps which remain 256 or more ahead after lower values advance.
// No state mutation occurs until every payer group has validated successfully.
func PrepareNativeReplaySequences(config *params.ChainConfig, statedb *state.StateDB, txs types.Transactions) error {
	if err := validateNativeReplaySequenceConfig(config); err != nil {
		return err
	}
	if statedb == nil {
		return errors.New("native replay sequence state is unavailable")
	}
	entries := make([]nativeReplaySequenceEntry, 0, len(txs))
	hashes := make([]common.Hash, 0, len(txs))
	for index, tx := range txs {
		if tx == nil || tx.Type() != types.NativeTxType {
			return &NativeReplaySequenceError{Index: index, Err: errors.New("replay prepass requires NativeTxV1")}
		}
		hash := tx.Hash()
		hashes = append(hashes, hash)
		entries = append(entries, nativeReplaySequenceEntry{
			payer: tx.Payer(), index: index, sequence: tx.ReplaySequence(),
		})
	}
	if statedb.NativeReplayTransactionsPrepared(hashes) {
		return nil
	}
	sort.Slice(entries, func(i, j int) bool {
		if order := bytes.Compare(entries[i].payer[:], entries[j].payer[:]); order != 0 {
			return order < 0
		}
		if entries[i].sequence != entries[j].sequence {
			return entries[i].sequence < entries[j].sequence
		}
		return entries[i].index < entries[j].index
	})
	payerCount := 0
	for index := range entries {
		if index == 0 || entries[index].payer != entries[index-1].payer {
			payerCount++
		}
	}
	groups := make([]nativeReplaySequenceGroup, 0, payerCount)
	for start := 0; start < len(entries); {
		payer := entries[start].payer
		end := start
		minIndex := entries[start].index
		for end < len(entries) && entries[end].payer == payer {
			if entries[end].index < minIndex {
				minIndex = entries[end].index
			}
			end++
		}
		groups = append(groups, nativeReplaySequenceGroup{start: start, end: end, minIndex: minIndex})
		start = end
	}
	changes, err := validateNativeReplaySequenceGroups(statedb, entries, groups)
	if err != nil {
		return err
	}

	for start := 0; start < len(changes); {
		registry := changes[start].registry
		end := start
		for end < len(changes) && changes[end].registry == registry {
			end++
		}
		mutations := make([]state.NativeProtocolStorageMutation, 0, (end-start)*2)
		for _, change := range changes[start:end] {
			baseSlot, bitmapSlot := nativeReplaySequenceSlots(change.payer)
			if change.after.base != change.before.base {
				mutations = append(mutations, state.NativeProtocolStorageMutation{
					Key: baseSlot, Before: nativeReplayBaseHash(change.before.base), After: nativeReplayBaseHash(change.after.base),
				})
			}
			if change.after.bitmap != change.before.bitmap {
				mutations = append(mutations, state.NativeProtocolStorageMutation{
					Key: bitmapSlot, Before: nativeReplayBitmapHash(change.before.bitmap), After: nativeReplayBitmapHash(change.after.bitmap),
				})
			}
		}
		if err := statedb.ApplyNativeProtocolStorageBatch(registry, 1, mutations); err != nil {
			return fmt.Errorf("publish native replay registry %s: %w", registry, err)
		}
		start = end
	}
	if err := statedb.Error(); err != nil {
		return fmt.Errorf("write native replay sequence state: %w", err)
	}
	statedb.SetNativeReplayTransactions(hashes)
	return nil
}

type nativeStateGuard struct {
	vm.StateDB
	accesses       map[types.NativeResource]types.NativeAccessMode
	logLimit       uint64
	logContentSize uint64
	logMemorySize  uint64
	err            error
}

func newNativeStateGuard(statedb vm.StateDB, accesses []types.NativeAccess, logLimit uint64) *nativeStateGuard {
	guard := &nativeStateGuard{
		StateDB:  statedb,
		accesses: make(map[types.NativeResource]types.NativeAccessMode, len(accesses)),
		logLimit: logLimit,
	}
	for _, access := range accesses {
		guard.accesses[access.Resource] = access.Mode
	}
	return guard
}

func newNativeStateGuardForTransaction(statedb vm.StateDB, tx *types.Transaction) *nativeStateGuard {
	if tx == nil {
		return newNativeStateGuard(statedb, nil, 0)
	}
	count := tx.NativeAccessCount()
	guard := &nativeStateGuard{
		StateDB:  statedb,
		accesses: make(map[types.NativeResource]types.NativeAccessMode, int(count)),
		logLimit: tx.LogLimit(),
	}
	for index := uint64(0); index < count; index++ {
		access, ok := tx.NativeAccessAt(index)
		if ok {
			guard.accesses[access.Resource] = access.Mode
		}
	}
	return guard
}

// nativeRLPStringSize returns the exact encoded size of an RLP byte string.
// Computing this directly avoids allocating a second copy of arbitrarily large
// LOG data merely to enforce the signed NativeTxV1 byte budget.
func nativeRLPStringSize(value []byte) uint64 {
	size := uint64(len(value))
	if size == 1 && value[0] < 0x80 {
		return 1
	}
	if size < 56 {
		return size + 1
	}
	lengthBytes := uint64(0)
	for encodedLength := size; encodedLength > 0; encodedLength >>= 8 {
		lengthBytes++
	}
	return size + 1 + lengthBytes
}

// nativeLogRLPSize matches types.Log.EncodeRLP exactly: the consensus fields
// are [address, topics, data], while derived block/transaction metadata is not
// encoded. The NativeTxV1 configuration bounds the practical values far below
// uint64 overflow; the explicit checks keep the guard total for malformed
// in-process callers as well.
func nativeLogRLPSize(entry *types.Log) (uint64, bool) {
	if entry == nil {
		return 0, false
	}
	const encodedAddressSize = uint64(21) // 0x94 followed by 20 address bytes
	const encodedTopicSize = uint64(33)   // 0xa0 followed by 32 hash bytes
	topicCount := uint64(len(entry.Topics))
	if topicCount > (^uint64(0)-9)/encodedTopicSize {
		return 0, false
	}
	topicContentSize := topicCount * encodedTopicSize
	encodedTopicsSize := rlp.ListSize(topicContentSize)
	encodedDataSize := nativeRLPStringSize(entry.Data)
	if encodedAddressSize > ^uint64(0)-encodedTopicsSize || encodedAddressSize+encodedTopicsSize > ^uint64(0)-encodedDataSize {
		return 0, false
	}
	contentSize := encodedAddressSize + encodedTopicsSize + encodedDataSize
	encodedSize := rlp.ListSize(contentSize)
	if encodedSize < contentSize {
		return 0, false
	}
	return encodedSize, true
}

// AddLog enforces the signed byte limit at the allocation boundary. The EVM
// StateDB interface cannot return an error, so a violation becomes sticky and
// is surfaced immediately after ApplyMessage. Further logs are discarded.
func (g *nativeStateGuard) AddLog(entry *types.Log) {
	if g == nil || g.StateDB == nil || g.err != nil {
		return
	}
	encodedSize, ok := nativeLogRLPSize(entry)
	if !ok || encodedSize > ^uint64(0)-g.logContentSize {
		g.err = fmt.Errorf("%w: invalid or overflowing log encoding", ErrNativeLogLimitExceeded)
		return
	}
	nextContentSize := g.logContentSize + encodedSize
	encodedListSize := rlp.ListSize(nextContentSize)
	if encodedListSize < nextContentSize || encodedListSize > g.logLimit {
		g.err = fmt.Errorf("%w: encoded bytes=%d limit=%d", ErrNativeLogLimitExceeded, encodedListSize, g.logLimit)
		return
	}
	if encodedSize > ^uint64(0)-nativeLogObjectMemoryReserve {
		g.err = fmt.Errorf("%w: overflowing retained-memory charge", ErrNativeLogLimitExceeded)
		return
	}
	entryMemorySize := encodedSize + nativeLogObjectMemoryReserve
	if entryMemorySize > ^uint64(0)-g.logMemorySize {
		g.err = fmt.Errorf("%w: overflowing aggregate retained-memory charge", ErrNativeLogLimitExceeded)
		return
	}
	nextMemorySize := g.logMemorySize + entryMemorySize
	if nextMemorySize > g.logLimit {
		g.err = fmt.Errorf("%w: retained bytes=%d limit=%d", ErrNativeLogLimitExceeded, nextMemorySize, g.logLimit)
		return
	}
	g.logContentSize = nextContentSize
	g.logMemorySize = nextMemorySize
	g.StateDB.AddLog(entry)
}

func (g *nativeStateGuard) Error() error {
	if g == nil {
		return nil
	}
	return g.err
}

func (g *nativeStateGuard) allow(operation string, resource types.NativeResource, write bool) bool {
	if g == nil || g.StateDB == nil {
		return false
	}
	mode, declared := g.accesses[resource]
	allowed := declared && (mode == types.NativeAccessWrite || (!write && mode == types.NativeAccessRead))
	if allowed {
		return true
	}
	if g.err == nil {
		access := "read"
		if write {
			access = "write"
		}
		g.err = fmt.Errorf("%w: operation=%s access=%s kind=%d address=%s slot=%s",
			ErrUndeclaredNativeStateAccess, operation, access, resource.Kind, resource.Address, resource.Slot)
	}
	return false
}

func nativeAccountResource(address common.Address) types.NativeResource {
	return types.NativeResource{Kind: types.NativeResourceAccount, Address: address}
}

func nativeStorageResource(address common.Address, slot common.Hash) types.NativeResource {
	return types.NativeResource{Kind: types.NativeResourceStorage, Address: address, Slot: slot}
}

func (g *nativeStateGuard) CreateAccount(address common.Address) {
	if !g.allow("CreateAccount", nativeAccountResource(address), true) {
		return
	}
	// Creating a provably absent value-transfer recipient cannot clear hidden
	// storage. Resetting an existing account can, so only the former is part of
	// NativeTxV1. Contract creation is rejected separately by CreateContract.
	if g.StateDB.Exist(address) {
		g.forbidStructuralAccountChange("CreateAccount", address)
		return
	}
	g.StateDB.CreateAccount(address)
}

func (g *nativeStateGuard) CreateContract(address common.Address) {
	g.forbidStructuralAccountChange("CreateContract", address)
}

// NativeTxV1 declares exact storage slots. Account creation and destruction
// can clear or replace an unbounded storage namespace, so they are intentionally
// reserved for a future system-program transaction type with an explicit
// whole-account resource. Treat the violation as sticky and consensus-invalid.
func (g *nativeStateGuard) forbidStructuralAccountChange(operation string, address common.Address) {
	if g == nil || g.err != nil {
		return
	}
	g.err = fmt.Errorf("%w: operation=%s access=write kind=%d address=%s: structural account changes are not supported by NativeTxV1",
		ErrUndeclaredNativeStateAccess, operation, types.NativeResourceAccount, address)
}

func (g *nativeStateGuard) CreatedContract(address common.Address) bool {
	return g.allow("CreatedContract", nativeAccountResource(address), false) && g.StateDB.CreatedContract(address)
}

func (g *nativeStateGuard) SubBalance(address common.Address, amount *big.Int) {
	if g.allow("SubBalance", nativeAccountResource(address), true) {
		g.StateDB.SubBalance(address, amount)
	}
}

func (g *nativeStateGuard) AddBalance(address common.Address, amount *big.Int) {
	// EVM.StaticCall performs AddBalance(address, 0) before executing the
	// callee. NativeTxV1 defines every zero-value balance addition as a pure
	// account read/no-op, including absent precompiles. Ethereum's legacy
	// EIP-161 touch-only artifact is not externally observable by supported
	// NativeTxV1 operations and would otherwise make every caller of one shared
	// precompile declare a write and serialize the entire DAG wave.
	if amount != nil && amount.Sign() == 0 {
		g.allow("AddBalanceZero", nativeAccountResource(address), false)
		return
	}
	if g.allow("AddBalance", nativeAccountResource(address), true) {
		g.StateDB.AddBalance(address, amount)
	}
}

func (g *nativeStateGuard) GetBalance(address common.Address) *big.Int {
	if !g.allow("GetBalance", nativeAccountResource(address), false) {
		return new(big.Int)
	}
	return g.StateDB.GetBalance(address)
}

func (g *nativeStateGuard) GetNonce(address common.Address) uint64 {
	if !g.allow("GetNonce", nativeAccountResource(address), false) {
		return 0
	}
	return g.StateDB.GetNonce(address)
}

func (g *nativeStateGuard) SetNonce(address common.Address, nonce uint64) {
	if g.allow("SetNonce", nativeAccountResource(address), true) {
		g.StateDB.SetNonce(address, nonce)
	}
}

func (g *nativeStateGuard) GetCodeHash(address common.Address) common.Hash {
	if !g.allow("GetCodeHash", nativeAccountResource(address), false) {
		return common.Hash{}
	}
	return g.StateDB.GetCodeHash(address)
}

func (g *nativeStateGuard) GetCode(address common.Address) []byte {
	if !g.allow("GetCode", nativeAccountResource(address), false) {
		return nil
	}
	return g.StateDB.GetCode(address)
}

func (g *nativeStateGuard) SetCode(address common.Address, code []byte) {
	if g.allow("SetCode", nativeAccountResource(address), true) {
		g.StateDB.SetCode(address, code)
	}
}

func (g *nativeStateGuard) GetCodeSize(address common.Address) int {
	if !g.allow("GetCodeSize", nativeAccountResource(address), false) {
		return 0
	}
	return g.StateDB.GetCodeSize(address)
}

func (g *nativeStateGuard) GetCommittedState(address common.Address, slot common.Hash) common.Hash {
	if !g.allow("GetCommittedState", nativeStorageResource(address, slot), false) {
		return common.Hash{}
	}
	return g.StateDB.GetCommittedState(address, slot)
}

func (g *nativeStateGuard) GetState(address common.Address, slot common.Hash) common.Hash {
	if !g.allow("GetState", nativeStorageResource(address, slot), false) {
		return common.Hash{}
	}
	return g.StateDB.GetState(address, slot)
}

func (g *nativeStateGuard) GetStorageRoot(address common.Address) common.Hash {
	// Reading a whole storage root depends on every slot and cannot be safely
	// represented by NativeTxV1's exact-slot manifest.
	if g.err == nil {
		g.err = fmt.Errorf("%w: operation=GetStorageRoot access=read kind=%d address=%s: whole-account storage root is not manifestable",
			ErrUndeclaredNativeStateAccess, types.NativeResourceStorage, address)
	}
	return common.Hash{}
}

func (g *nativeStateGuard) SetState(address common.Address, slot, value common.Hash) {
	if g.allow("SetState", nativeStorageResource(address, slot), true) {
		g.StateDB.SetState(address, slot, value)
	}
}

func (g *nativeStateGuard) GetTransientState(address common.Address, slot common.Hash) common.Hash {
	if !g.allow("GetTransientState", nativeStorageResource(address, slot), false) {
		return common.Hash{}
	}
	return g.StateDB.GetTransientState(address, slot)
}

func (g *nativeStateGuard) SetTransientState(address common.Address, slot, value common.Hash) {
	if g.allow("SetTransientState", nativeStorageResource(address, slot), true) {
		g.StateDB.SetTransientState(address, slot, value)
	}
}

func (g *nativeStateGuard) Suicide(address common.Address) bool {
	g.forbidStructuralAccountChange("Suicide", address)
	return false
}

func (g *nativeStateGuard) HasSuicided(address common.Address) bool {
	return g.allow("HasSuicided", nativeAccountResource(address), false) && g.StateDB.HasSuicided(address)
}

func (g *nativeStateGuard) Exist(address common.Address) bool {
	return g.allow("Exist", nativeAccountResource(address), false) && g.StateDB.Exist(address)
}

func (g *nativeStateGuard) Empty(address common.Address) bool {
	if !g.allow("Empty", nativeAccountResource(address), false) {
		return true
	}
	return g.StateDB.Empty(address)
}

func (g *nativeStateGuard) ForEachStorage(address common.Address, callback func(common.Hash, common.Hash) bool) error {
	if g.err == nil {
		g.err = fmt.Errorf("%w: operation=ForEachStorage access=read kind=%d address=%s: whole-account storage iteration is not manifestable",
			ErrUndeclaredNativeStateAccess, types.NativeResourceStorage, address)
	}
	return g.err
}
