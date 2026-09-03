package core

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/params"
)

// evmOptimisticMicroBatch bounds the number of complete EVM branches retained
// at once. Blocks may contain hundreds of thousands of transactions, but local
// memory stays proportional to this fixed window while independent windows are
// executed successively.
const evmOptimisticMicroBatch = 64

const (
	// Every code-loading operation after the transaction destination consumes at
	// least the warm-account opcode charge. A few implicit/EIP-7702 reads are
	// reserved separately below.
	evmRuntimeCodeLoadBase = uint64(4)
)

func saturatedMemoryProduct(count, amount uint64) uint64 {
	if count == 0 || amount == 0 {
		return 0
	}
	if count > nativeExecutionMemoryBudget/amount {
		return nativeExecutionMemoryBudget
	}
	return count * amount
}

// evmMaximumLiveMemoryFrames bounds simultaneously live interpreter memories.
// Each nested EVM call pays at least CallGasEIP150 and can forward at most
// 63/64 of the remainder. Using the transaction gas (including intrinsic gas)
// and ignoring every other opcode cost deliberately overestimates depth.
func evmMaximumLiveMemoryFrames(gas uint64, eip150 bool) uint64 {
	if !eip150 {
		// Before EIP-150, children could receive all remaining gas. The call-depth
		// protocol limit is therefore the only generally valid live-frame bound.
		return params.CallCreateDepth + 1
	}
	frames := uint64(1)
	available := gas
	for frames < params.CallCreateDepth+1 && available > params.CallGasEIP150 {
		available -= params.CallGasEIP150
		available -= available / 64
		frames++
	}
	return frames
}

func evmMemoryExpansionGas(words uint64) uint64 {
	// The configured protocol hard maximum is 256 MiB (2^23 words), so these
	// operations cannot overflow. Treat an out-of-contract caller
	// conservatively if that invariant is ever relaxed without this helper.
	if words != 0 && words > ^uint64(0)/words {
		return ^uint64(0)
	}
	square := words * words
	linear := saturatedMemoryProduct(words, params.MemoryGas)
	quadratic := square / params.QuadCoeffDiv
	if linear > ^uint64(0)-quadratic {
		return ^uint64(0)
	}
	return linear + quadratic
}

// evmMinimumAggregateMemoryGas is the least expansion gas capable of keeping
// totalWords live across at most frames call frames. The expansion schedule is
// discrete-convex, so balancing words across frames minimizes cost. This is
// the safe multi-frame counterpart to the familiar single-frame ~3 MiB bound
// at Osaka's MaxTxGas.
func evmMinimumAggregateMemoryGas(totalWords, frames uint64) uint64 {
	if totalWords == 0 {
		return 0
	}
	if frames == 0 {
		frames = 1
	}
	if frames > totalWords {
		frames = totalWords
	}
	base, remainder := totalWords/frames, totalWords%frames
	baseCost := evmMemoryExpansionGas(base)
	highCost := evmMemoryExpansionGas(base + 1)
	lowFrames := frames - remainder
	low := saturatedMemoryProduct(lowFrames, baseCost)
	high := saturatedMemoryProduct(remainder, highCost)
	if low >= nativeExecutionMemoryBudget || high >= nativeExecutionMemoryBudget || low > ^uint64(0)-high {
		return ^uint64(0)
	}
	return low + high
}

// evmGasBoundedLogicalMemory returns a rigorous aggregate live-memory upper
// bound derived from transaction gas and nested-call depth, capped by the
// genesis memory limit enforced by the interpreter itself.
func evmGasBoundedLogicalMemory(gas, configuredLimit uint64, eip150Active bool) uint64 {
	if configuredLimit == 0 || gas == 0 {
		return 0
	}
	if configuredLimit > params.NativeParallelHardMaxMemory {
		// Valid chain configurations cannot reach this case. Returning the full
		// value makes the caller's saturating reservation fail closed.
		return configuredLimit
	}
	maximumWords := configuredLimit / 32
	frames := evmMaximumLiveMemoryFrames(gas, eip150Active)
	low, high := uint64(0), maximumWords+1
	for low+1 < high {
		middle := low + (high-low)/2
		if evmMinimumAggregateMemoryGas(middle, frames) <= gas {
			low = middle
		} else {
			high = middle
		}
	}
	return low * 32
}

// evmRuntimeTransactionMemoryWeight is node-local scheduling policy. It uses
// only deterministic transaction/config values, but changing the estimate can
// affect concurrency only, never block validity or canonical results.
func evmRuntimeTransactionMemoryWeight(config *params.ChainConfig, header *types.Header, tx *types.Transaction) uint64 {
	if config == nil || config.NativeParallel == nil || tx == nil {
		return nativeExecutionMemoryBudget
	}
	limits := config.NativeParallel
	weight := nativeBranchBaseMemoryReserve
	eip150Active := header != nil && header.Number != nil && config.IsEIP150(header.Number)
	logicalMemory := evmGasBoundedLogicalMemory(tx.Gas(), limits.MaxMemoryBytesPerTransaction, eip150Active)
	// Memory.Resize doubles capacity. An active backing is below twice logical
	// size, and every uncollected prior geometric backing sums to less than the
	// active capacity, making the shared four-times factor a strict heap bound.
	weight = addScaledNativeMemoryWeight(weight, logicalMemory, nativeEVMMemoryPhysicalFactor)
	weight = addScaledNativeMemoryWeight(weight, limits.MaxOutputBytesPerTransaction, nativeOutputPhysicalFactor)
	weight = addNativeMemoryWeight(weight, limits.MaxLogBytesPerTransaction)
	weight = addNativeMemoryWeight(weight, uint64(tx.Size()))

	// A runtime resource can materialize an account object and a storage/journal
	// entry in the detached branch. Reserving both for every allowed resource is
	// intentionally conservative.
	accesses := limits.MaxAccessesPerTransaction
	weight = addNativeMemoryWeight(weight, saturatedMemoryProduct(accesses, nativeBranchAccountMemoryReserve))
	weight = addNativeMemoryWeight(weight, saturatedMemoryProduct(accesses, nativeBranchStorageMemoryReserve))

	// Already-loaded snapshot code is shared immutably. Previously unseen code
	// comes from the database cache into the branch, so reserve the maximum code
	// image for every code-bearing account that gas could possibly observe.
	codeLoads := evmRuntimeCodeLoadBase
	if tx.Gas() > (^uint64(0)-codeLoads)/params.WarmStorageReadCostEIP2929 {
		codeLoads = accesses
	} else {
		codeLoads += tx.Gas() / params.WarmStorageReadCostEIP2929
		if codeLoads > accesses {
			codeLoads = accesses
		}
	}
	maxCodeSize := params.MaxCodeSize
	if header != nil && header.Number != nil {
		maxCodeSize = config.GetMaxCodeSize(header.Number)
	}
	if maxCodeSize > 0 {
		weight = addNativeMemoryWeight(weight, saturatedMemoryProduct(codeLoads, uint64(maxCodeSize)))
	}
	return weight
}

func evmOptimisticMemoryBatchEnd(start int, weights []uint64) (int, uint64) {
	return evmOptimisticMemoryBatchEndWithin(start, weights, nativeExecutionMemoryBudget)
}

func evmOptimisticMemoryBatchEndWithin(start int, weights []uint64, capacity uint64) (int, uint64) {
	if start < 0 || start >= len(weights) || capacity == 0 {
		return start, 0
	}
	end, total := start, uint64(0)
	for end < len(weights) && end-start < evmOptimisticMicroBatch {
		weight := weights[end]
		if weight == 0 {
			weight = nativeBranchBaseMemoryReserve
		}
		if weight > capacity {
			break
		}
		if end > start && weight > capacity-total {
			break
		}
		total += weight
		end++
	}
	return end, total
}

// evmRuntimeRetainedMemoryWeight reserves the dependency frontiers and block
// outputs that coexist with every speculative microbatch. It uses the actual
// transaction count while conservatively assuming every transaction reaches
// its configured access and log limits.
func evmRuntimeRetainedMemoryWeight(config *params.ChainConfig, transactionCount int) uint64 {
	if config == nil || config.NativeParallel == nil || transactionCount <= 0 {
		return 0
	}
	limits := config.NativeParallel
	count := uint64(transactionCount)
	accesses := saturatedMemoryProduct(count, limits.MaxAccessesPerTransaction)
	if accesses > limits.MaxAccessesPerBlock {
		accesses = limits.MaxAccessesPerBlock
	}
	weight := saturatedMemoryProduct(accesses, uint64(params.NativePlanningMemoryPerAccess))
	weight = addNativeMemoryWeight(weight, saturatedMemoryProduct(count, uint64(params.NativePlanningMemoryPerTransaction)))
	weight = addNativeMemoryWeight(weight, saturatedMemoryProduct(count, uint64(params.NativeReceiptMemoryReservePerTransaction)))
	logBytes := saturatedMemoryProduct(count, limits.MaxLogBytesPerTransaction)
	if logBytes > limits.MaxLogBytesPerBlock {
		logBytes = limits.MaxLogBytesPerBlock
	}
	return addNativeMemoryWeight(weight, logBytes)
}

type evmMVCCResourceKind uint8

const (
	evmMVCCAccountResource evmMVCCResourceKind = iota + 1
	evmMVCCStorageResource
	evmMVCCStorageWildcardResource
	evmMVCCTemporaryStorageResource
)

var (
	ErrEVMRuntimeAccessLimitExceeded = errors.New("EVM runtime access limit exceeded")
	ErrEVMRuntimeWorkLimitExceeded   = errors.New("EVM runtime work limit exceeded")
)

// EVMExecutionInfrastructureError marks a local state/snapshot invariant
// failure for which dropping one candidate transaction is unsafe. In
// particular, proposer retry logic must abort on this type instead of treating
// it as a transaction-invalidity result.
type EVMExecutionInfrastructureError struct {
	Err error
}

func (e *EVMExecutionInfrastructureError) Error() string {
	if e == nil || e.Err == nil {
		return "standard EVM execution infrastructure failed"
	}
	return e.Err.Error()
}

func (e *EVMExecutionInfrastructureError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func markEVMExecutionInfrastructure(err error) error {
	if err == nil {
		return nil
	}
	var marked *EVMExecutionInfrastructureError
	if errors.As(err, &marked) {
		return err
	}
	return &EVMExecutionInfrastructureError{Err: err}
}

// EVMRuntimeWorkLimitError identifies the canonical transaction which crosses
// one genesis-committed standard-EVM execution bound. Proposers may remove that
// transaction and rebuild; validators retain the same typed cause while
// rejecting the candidate block.
type EVMRuntimeWorkLimitError struct {
	TransactionIndex int
	Dimension        string
	Observed         uint64
	Limit            uint64
}

func (e *EVMRuntimeWorkLimitError) Error() string {
	if e == nil {
		return ErrEVMRuntimeWorkLimitExceeded.Error()
	}
	return fmt.Sprintf("standard EVM transaction %d %s %d exceeds maximum %d", e.TransactionIndex, e.Dimension, e.Observed, e.Limit)
}

func (e *EVMRuntimeWorkLimitError) Unwrap() error {
	return ErrEVMRuntimeWorkLimitExceeded
}

func (e *EVMRuntimeWorkLimitError) Is(target error) bool {
	if target == ErrEVMRuntimeWorkLimitExceeded {
		return true
	}
	return target == ErrEVMRuntimeAccessLimitExceeded && e != nil &&
		(e.Dimension == "runtime accesses" || e.Dimension == "block runtime accesses")
}

// EVMTransactionExecutionError distinguishes a transaction-specific execution
// failure from microbatch snapshot/branch infrastructure failures. The cause is
// preserved for errors.Is/errors.As, including EVMRuntimeWorkLimitError.
type EVMTransactionExecutionError struct {
	TransactionIndex int
	Err              error
}

func (e *EVMTransactionExecutionError) Error() string {
	if e == nil || e.Err == nil {
		return "standard EVM transaction execution failed"
	}
	return fmt.Sprintf("standard EVM transaction %d: %v", e.TransactionIndex, e.Err)
}

func (e *EVMTransactionExecutionError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func evmTransactionExecutionError(index int, err error) error {
	if err == nil {
		return nil
	}
	var infrastructure *EVMExecutionInfrastructureError
	if errors.As(err, &infrastructure) {
		return err
	}
	return &EVMTransactionExecutionError{TransactionIndex: index, Err: err}
}

type evmMVCCResource struct {
	kind    evmMVCCResourceKind
	address common.Address
	slot    common.Hash
}

type evmMVCCAccessSet struct {
	reads  map[evmMVCCResource]struct{}
	writes map[evmMVCCResource]struct{}
}

// evmMVCCRecorder wraps the complete vm.StateDB boundary. It observes runtime
// accesses made by nonce/fee validation, EIP-7702 authorization processing and
// nested EVM calls, so safety never depends on an EIP-2930 access list being an
// exhaustive declaration (Ethereum does not require that property).
type evmMVCCRecorder struct {
	vm.StateDB
	reads       map[evmMVCCResource]struct{}
	writes      map[evmMVCCResource]struct{}
	seen        map[evmMVCCResource]struct{}
	maxAccesses uint64
	err         error

	// writeJournal and writeSnapshots mirror StateDB's execution snapshots for
	// persistent writes. Reads and seen resources deliberately survive a revert:
	// reverted code can still affect gas, return data and outer control flow, and
	// its work must still count towards the runtime access ceiling.
	writeJournal   []evmMVCCResource
	writeSnapshots map[int]int
}

func newEVMMVCCRecorder(statedb vm.StateDB) *evmMVCCRecorder {
	return &evmMVCCRecorder{
		StateDB: statedb,
		reads:   make(map[evmMVCCResource]struct{}),
		writes:  make(map[evmMVCCResource]struct{}),
		seen:    make(map[evmMVCCResource]struct{}),
	}
}

func (r *evmMVCCRecorder) setAccessLimit(limit uint64) {
	if r != nil {
		r.maxAccesses = limit
	}
}

func (r *evmMVCCRecorder) observe(resource evmMVCCResource, write bool) bool {
	if r == nil || r.err != nil {
		return false
	}
	if _, exists := r.seen[resource]; !exists {
		if r.maxAccesses != 0 && uint64(len(r.seen)) >= r.maxAccesses {
			r.err = fmt.Errorf("%w: observed=%d maximum=%d", ErrEVMRuntimeAccessLimitExceeded, len(r.seen)+1, r.maxAccesses)
			return false
		}
		r.seen[resource] = struct{}{}
	}
	if write {
		if _, exists := r.writes[resource]; !exists {
			r.writeJournal = append(r.writeJournal, resource)
		}
		r.writes[resource] = struct{}{}
	} else {
		r.reads[resource] = struct{}{}
	}
	return true
}

func (r *evmMVCCRecorder) Snapshot() int {
	id := r.StateDB.Snapshot()
	if r.writeSnapshots == nil {
		r.writeSnapshots = make(map[int]int)
	}
	r.writeSnapshots[id] = len(r.writeJournal)
	return id
}

func (r *evmMVCCRecorder) RevertToSnapshot(id int) {
	// Let the underlying StateDB validate and apply the revision first. If it
	// panics for an invalid id, the recorder must remain unchanged as well.
	r.StateDB.RevertToSnapshot(id)
	checkpoint, exists := r.writeSnapshots[id]
	if !exists {
		panic(fmt.Errorf("EVM MVCC recorder revision id %d cannot be reverted", id))
	}
	for index := len(r.writeJournal) - 1; index >= checkpoint; index-- {
		resource := r.writeJournal[index]
		delete(r.writes, resource)
		// Preserve a conservative dependency on the state observed while making
		// the reverted write. This prevents stale gas/control-flow results from
		// being merged while excluding the write from the canonical delta.
		r.reads[resource] = struct{}{}
	}
	r.writeJournal = r.writeJournal[:checkpoint]
	// StateDB invalidates this revision and every nested revision on revert.
	for revision := range r.writeSnapshots {
		if revision >= id {
			delete(r.writeSnapshots, revision)
		}
	}
}

func (r *evmMVCCRecorder) account(address common.Address, write bool) bool {
	return r.observe(evmMVCCResource{kind: evmMVCCAccountResource, address: address}, write)
}

func (r *evmMVCCRecorder) storage(address common.Address, slot common.Hash, write bool) bool {
	return r.observe(evmMVCCResource{kind: evmMVCCStorageResource, address: address, slot: slot}, write)
}

func (r *evmMVCCRecorder) temporaryStorage(address common.Address, slot common.Hash, write bool) bool {
	return r.observe(evmMVCCResource{kind: evmMVCCTemporaryStorageResource, address: address, slot: slot}, write)
}

func (r *evmMVCCRecorder) storageWildcard(address common.Address) bool {
	return r.observe(evmMVCCResource{kind: evmMVCCStorageWildcardResource, address: address}, false)
}

func (r *evmMVCCRecorder) Error() error {
	if r == nil {
		return nil
	}
	return r.err
}

func (r *evmMVCCRecorder) transactionError(index int, err error) error {
	if r != nil && errors.Is(err, ErrEVMRuntimeAccessLimitExceeded) {
		return &EVMRuntimeWorkLimitError{
			TransactionIndex: index,
			Dimension:        "runtime accesses",
			Observed:         uint64(len(r.seen)) + 1,
			Limit:            r.maxAccesses,
		}
	}
	return err
}

func (r *evmMVCCRecorder) accessSet() evmMVCCAccessSet {
	reads := make(map[evmMVCCResource]struct{}, len(r.reads))
	for resource := range r.reads {
		reads[resource] = struct{}{}
	}
	writes := make(map[evmMVCCResource]struct{}, len(r.writes))
	for resource := range r.writes {
		writes[resource] = struct{}{}
	}
	return evmMVCCAccessSet{reads: reads, writes: writes}
}

func (r *evmMVCCRecorder) observedAddresses() []common.Address {
	if r == nil {
		return nil
	}
	addresses := make([]common.Address, 0, len(r.seen))
	seen := make(map[common.Address]struct{}, len(r.seen))
	for resource := range r.seen {
		if _, duplicate := seen[resource.address]; duplicate {
			continue
		}
		seen[resource.address] = struct{}{}
		addresses = append(addresses, resource.address)
	}
	return addresses
}

func (r *evmMVCCRecorder) observedStorageSlots() map[common.Address][]common.Hash {
	if r == nil {
		return nil
	}
	slots := make(map[common.Address][]common.Hash)
	for resource := range r.seen {
		if resource.kind == evmMVCCStorageResource {
			slots[resource.address] = append(slots[resource.address], resource.slot)
		}
	}
	return slots
}

func (r *evmMVCCRecorder) CreateAccount(address common.Address) {
	if r.account(address, true) {
		r.StateDB.CreateAccount(address)
	}
}

func (r *evmMVCCRecorder) CreateContract(address common.Address) {
	if r.account(address, true) {
		r.StateDB.CreateContract(address)
	}
}

func (r *evmMVCCRecorder) CreatedContract(address common.Address) bool {
	if !r.account(address, false) {
		return false
	}
	return r.StateDB.CreatedContract(address)
}

func (r *evmMVCCRecorder) SubBalance(address common.Address, amount *big.Int) {
	if amount != nil && amount.Sign() == 0 {
		// StateDB.SubBalance is an unconditional no-op for zero value.
		if r != nil && r.err == nil {
			r.StateDB.SubBalance(address, amount)
		}
		return
	}
	if r.account(address, true) {
		r.StateDB.SubBalance(address, amount)
	}
}

func (r *evmMVCCRecorder) AddBalance(address common.Address, amount *big.Int) {
	if amount != nil && amount.Sign() == 0 {
		if !r.account(address, false) {
			return
		}
		// EIP-161 zero-value touches have a persistent effect only for an
		// already-existing empty account, which Finalise deletes. Missing and
		// non-empty accounts end the transaction unchanged, so treating every
		// zero transfer as a whole-account write would serialize all calls to a
		// shared contract and defeat slot-granular MVCC.
		persistentTouch := r.StateDB.Exist(address) && r.StateDB.Empty(address)
		if persistentTouch && !r.account(address, true) {
			return
		}
		r.StateDB.AddBalance(address, amount)
		return
	}
	if r.account(address, true) {
		r.StateDB.AddBalance(address, amount)
	}
}

func (r *evmMVCCRecorder) GetBalance(address common.Address) *big.Int {
	if !r.account(address, false) {
		return new(big.Int)
	}
	return r.StateDB.GetBalance(address)
}

func (r *evmMVCCRecorder) GetNonce(address common.Address) uint64 {
	if !r.account(address, false) {
		return 0
	}
	return r.StateDB.GetNonce(address)
}

func (r *evmMVCCRecorder) SetNonce(address common.Address, nonce uint64) {
	if r.account(address, true) {
		r.StateDB.SetNonce(address, nonce)
	}
}

func (r *evmMVCCRecorder) GetCodeHash(address common.Address) common.Hash {
	if !r.account(address, false) {
		return common.Hash{}
	}
	return r.StateDB.GetCodeHash(address)
}

func (r *evmMVCCRecorder) GetCode(address common.Address) []byte {
	if !r.account(address, false) {
		return nil
	}
	return r.StateDB.GetCode(address)
}

func (r *evmMVCCRecorder) SetCode(address common.Address, code []byte) {
	if r.account(address, true) {
		r.StateDB.SetCode(address, code)
	}
}

func (r *evmMVCCRecorder) GetCodeSize(address common.Address) int {
	if !r.account(address, false) {
		return 0
	}
	return r.StateDB.GetCodeSize(address)
}

func (r *evmMVCCRecorder) GetCommittedState(address common.Address, slot common.Hash) common.Hash {
	// Account existence and the exact storage cell are separate conflict
	// domains. Shared reads of immutable contract metadata do not serialize
	// independent ERC-20 balance slots, while account creation/deletion still
	// invalidates every storage observation through the account read.
	if !r.account(address, false) || !r.storage(address, slot, false) {
		return common.Hash{}
	}
	return r.StateDB.GetCommittedState(address, slot)
}

func (r *evmMVCCRecorder) GetState(address common.Address, slot common.Hash) common.Hash {
	if !r.account(address, false) || !r.storage(address, slot, false) {
		return common.Hash{}
	}
	return r.StateDB.GetState(address, slot)
}

func (r *evmMVCCRecorder) GetStorageRoot(address common.Address) common.Hash {
	if !r.account(address, false) || !r.storageWildcard(address) {
		return common.Hash{}
	}
	return r.StateDB.GetStorageRoot(address)
}

func (r *evmMVCCRecorder) SetState(address common.Address, slot, value common.Hash) {
	if !r.account(address, false) {
		return
	}
	create := false
	if !r.StateDB.Exist(address) {
		// Creating the state object changes account existence and must conflict
		// with every other observation of the same address.
		create = true
	}
	if (create && !r.account(address, true)) || !r.storage(address, slot, true) {
		return
	}
	r.StateDB.SetState(address, slot, value)
}

func (r *evmMVCCRecorder) GetTransientState(address common.Address, slot common.Hash) common.Hash {
	if !r.temporaryStorage(address, slot, false) {
		return common.Hash{}
	}
	return r.StateDB.GetTransientState(address, slot)
}

func (r *evmMVCCRecorder) SetTransientState(address common.Address, slot, value common.Hash) {
	if r.temporaryStorage(address, slot, true) {
		r.StateDB.SetTransientState(address, slot, value)
	}
}

func (r *evmMVCCRecorder) Suicide(address common.Address) bool {
	if !r.account(address, true) {
		return false
	}
	return r.StateDB.Suicide(address)
}

func (r *evmMVCCRecorder) HasSuicided(address common.Address) bool {
	if !r.account(address, false) {
		return false
	}
	return r.StateDB.HasSuicided(address)
}

func (r *evmMVCCRecorder) Exist(address common.Address) bool {
	if !r.account(address, false) {
		return false
	}
	return r.StateDB.Exist(address)
}

func (r *evmMVCCRecorder) Empty(address common.Address) bool {
	if !r.account(address, false) {
		return true
	}
	return r.StateDB.Empty(address)
}

func (r *evmMVCCRecorder) ForEachStorage(address common.Address, callback func(common.Hash, common.Hash) bool) error {
	if !r.account(address, false) || !r.storageWildcard(address) {
		return r.err
	}
	return r.StateDB.ForEachStorage(address, callback)
}

func (r *evmMVCCRecorder) AddRefund(gas uint64) {
	if r.err == nil {
		r.StateDB.AddRefund(gas)
	}
}

func (r *evmMVCCRecorder) SubRefund(gas uint64) {
	if r.err == nil {
		r.StateDB.SubRefund(gas)
	}
}

func (r *evmMVCCRecorder) GetRefund() uint64 {
	if r.err != nil {
		return 0
	}
	return r.StateDB.GetRefund()
}

func (r *evmMVCCRecorder) AddLog(entry *types.Log) {
	if r.err == nil {
		r.StateDB.AddLog(entry)
	}
}

func (r *evmMVCCRecorder) AddPreimage(hash common.Hash, preimage []byte) {
	if r.err == nil {
		r.StateDB.AddPreimage(hash, preimage)
	}
}

func (r *evmMVCCRecorder) PrepareAccessList(sender common.Address, destination *common.Address, precompiles []common.Address, list types.AccessList) {
	if r.err == nil {
		r.StateDB.PrepareAccessList(sender, destination, precompiles, list)
	}
}

func (r *evmMVCCRecorder) AddAddressToAccessList(address common.Address) {
	if r.account(address, false) {
		r.StateDB.AddAddressToAccessList(address)
	}
}

func (r *evmMVCCRecorder) AddSlotToAccessList(address common.Address, slot common.Hash) {
	if r.account(address, false) && r.storage(address, slot, false) {
		r.StateDB.AddSlotToAccessList(address, slot)
	}
}

func (r *evmMVCCRecorder) AddressInAccessList(address common.Address) bool {
	if !r.account(address, false) {
		return false
	}
	return r.StateDB.AddressInAccessList(address)
}

func (r *evmMVCCRecorder) SlotInAccessList(address common.Address, slot common.Hash) (bool, bool) {
	if !r.account(address, false) || !r.storage(address, slot, false) {
		return false, false
	}
	return r.StateDB.SlotInAccessList(address, slot)
}

type evmRuntimeAccessMeter struct {
	maxPerTransaction uint64
	maxPerBlock       uint64
	total             uint64
}

type evmRuntimePath struct {
	depth  uint64
	finish uint64
}

type evmRuntimeStorageKey struct {
	address common.Address
	slot    common.Hash
}

func maxEVMRuntimePath(left, right evmRuntimePath) evmRuntimePath {
	if right.depth > left.depth {
		left.depth = right.depth
	}
	if right.finish > left.finish {
		left.finish = right.finish
	}
	return left
}

// evmRuntimeDependencyIndex retains only canonical writer frontiers. Reads
// depend on prior conflicting writers; writes also depend on prior conflicting
// writers because the optimistic executor captures every earlier read before
// canonical publication. anyStorage makes whole-account dependencies O(1) even
// for contracts with many observed slots.
type evmRuntimeDependencyIndex struct {
	accounts   map[common.Address]evmRuntimePath
	storage    map[evmRuntimeStorageKey]evmRuntimePath
	wildcards  map[common.Address]evmRuntimePath
	anyStorage map[common.Address]evmRuntimePath
}

func newEVMRuntimeDependencyIndex() *evmRuntimeDependencyIndex {
	return &evmRuntimeDependencyIndex{
		accounts:   make(map[common.Address]evmRuntimePath),
		storage:    make(map[evmRuntimeStorageKey]evmRuntimePath),
		wildcards:  make(map[common.Address]evmRuntimePath),
		anyStorage: make(map[common.Address]evmRuntimePath),
	}
}

func (index *evmRuntimeDependencyIndex) predecessor(resource evmMVCCResource, write bool) evmRuntimePath {
	if index == nil || resource.kind == evmMVCCTemporaryStorageResource {
		return evmRuntimePath{}
	}
	predecessor := index.accounts[resource.address]
	switch resource.kind {
	case evmMVCCAccountResource:
		if write {
			predecessor = maxEVMRuntimePath(predecessor, index.anyStorage[resource.address])
		}
	case evmMVCCStorageResource:
		predecessor = maxEVMRuntimePath(predecessor, index.wildcards[resource.address])
		predecessor = maxEVMRuntimePath(predecessor, index.storage[evmRuntimeStorageKey{address: resource.address, slot: resource.slot}])
	case evmMVCCStorageWildcardResource:
		predecessor = maxEVMRuntimePath(predecessor, index.anyStorage[resource.address])
	}
	return predecessor
}

func (index *evmRuntimeDependencyIndex) publish(access evmMVCCAccessSet, sender common.Address, path evmRuntimePath) {
	if index == nil {
		return
	}
	accountWrites := make(map[common.Address]struct{})
	for resource := range access.writes {
		if resource.kind == evmMVCCAccountResource {
			accountWrites[resource.address] = struct{}{}
		}
	}
	// A standard transaction always persists its sender nonce/fee debit. Keep
	// this explicit so nonce-chain metering does not depend on recorder internals.
	accountWrites[sender] = struct{}{}
	for address := range accountWrites {
		index.accounts[address] = path
		// Older storage frontiers are transitively dominated by this account
		// path (which depended on anyStorage). Retaining flat entries avoids an
		// O(all slots) delete and, unlike one inner map per hostile address,
		// keeps allocation proportional to the configured access ceiling.
	}
	for resource := range access.writes {
		if _, dominated := accountWrites[resource.address]; dominated {
			continue
		}
		switch resource.kind {
		case evmMVCCStorageResource:
			index.storage[evmRuntimeStorageKey{address: resource.address, slot: resource.slot}] = path
			index.anyStorage[resource.address] = maxEVMRuntimePath(index.anyStorage[resource.address], path)
		case evmMVCCStorageWildcardResource:
			index.wildcards[resource.address] = path
			index.anyStorage[resource.address] = maxEVMRuntimePath(index.anyStorage[resource.address], path)
		}
	}
}

type evmRuntimeDependencyMeter struct {
	limits       *params.NativeParallelConfig
	frontiers    *evmRuntimeDependencyIndex
	totalCompute uint64
}

func newEVMRuntimeDependencyMeter(config *params.ChainConfig) *evmRuntimeDependencyMeter {
	if config == nil || !config.NativeParallelEnabled() || config.NativeParallel.RequireNativeTransactions {
		return nil
	}
	return &evmRuntimeDependencyMeter{limits: config.NativeParallel, frontiers: newEVMRuntimeDependencyIndex()}
}

func (m *evmRuntimeDependencyMeter) Add(index int, sender common.Address, access evmMVCCAccessSet, compute uint64) error {
	if m == nil || m.limits == nil {
		return nil
	}
	if compute == 0 || compute > m.limits.MaxComputePerTransaction {
		return &EVMRuntimeWorkLimitError{TransactionIndex: index, Dimension: "compute", Observed: compute, Limit: m.limits.MaxComputePerTransaction}
	}
	if m.totalCompute > m.limits.MaxComputePerBlock {
		return &EVMRuntimeWorkLimitError{TransactionIndex: index, Dimension: "block compute", Observed: m.totalCompute, Limit: m.limits.MaxComputePerBlock}
	}
	if compute > m.limits.MaxComputePerBlock-m.totalCompute {
		observed := ^uint64(0)
		if compute <= ^uint64(0)-m.totalCompute {
			observed = m.totalCompute + compute
		}
		return &EVMRuntimeWorkLimitError{TransactionIndex: index, Dimension: "block compute", Observed: observed, Limit: m.limits.MaxComputePerBlock}
	}

	predecessor := evmRuntimePath{}
	for resource := range access.reads {
		predecessor = maxEVMRuntimePath(predecessor, m.frontiers.predecessor(resource, false))
	}
	for resource := range access.writes {
		predecessor = maxEVMRuntimePath(predecessor, m.frontiers.predecessor(resource, true))
	}
	senderResource := evmMVCCResource{kind: evmMVCCAccountResource, address: sender}
	if _, recorded := access.writes[senderResource]; !recorded {
		predecessor = maxEVMRuntimePath(predecessor, m.frontiers.predecessor(senderResource, true))
	}
	depth := uint64(1)
	if predecessor.depth != 0 {
		if predecessor.depth == ^uint64(0) {
			return &EVMRuntimeWorkLimitError{TransactionIndex: index, Dimension: "dependency depth", Observed: predecessor.depth, Limit: m.limits.MaxDependencyDepth}
		}
		depth = predecessor.depth + 1
	}
	if depth > m.limits.MaxDependencyDepth {
		return &EVMRuntimeWorkLimitError{TransactionIndex: index, Dimension: "dependency depth", Observed: depth, Limit: m.limits.MaxDependencyDepth}
	}
	if compute > ^uint64(0)-predecessor.finish {
		return &EVMRuntimeWorkLimitError{TransactionIndex: index, Dimension: "critical path compute", Observed: ^uint64(0), Limit: m.limits.MaxCriticalPathCompute}
	}
	finish := predecessor.finish + compute
	if finish > m.limits.MaxCriticalPathCompute {
		return &EVMRuntimeWorkLimitError{TransactionIndex: index, Dimension: "critical path compute", Observed: finish, Limit: m.limits.MaxCriticalPathCompute}
	}
	m.totalCompute += compute
	m.frontiers.publish(access, sender, evmRuntimePath{depth: depth, finish: finish})
	return nil
}

type evmRuntimeWorkMeter struct {
	access     *evmRuntimeAccessMeter
	dependency *evmRuntimeDependencyMeter
}

func newEVMRuntimeWorkMeter(config *params.ChainConfig) *evmRuntimeWorkMeter {
	access := newEVMRuntimeAccessMeter(config)
	dependency := newEVMRuntimeDependencyMeter(config)
	if access == nil && dependency == nil {
		return nil
	}
	return &evmRuntimeWorkMeter{access: access, dependency: dependency}
}

func (m *evmRuntimeWorkMeter) Add(config *params.ChainConfig, header *types.Header, index int, tx *types.Transaction, receipt *types.Receipt, access evmMVCCAccessSet) error {
	if m == nil {
		return nil
	}
	if tx == nil || receipt == nil || header == nil {
		return markEVMExecutionInfrastructure(fmt.Errorf("standard EVM transaction %d runtime work is incomplete", index))
	}
	if err := m.access.Add(index, access); err != nil {
		return err
	}
	sender, err := types.Sender(types.MakeSignerAutoJudgement(config, header.Number, tx.V()), tx)
	if err != nil {
		return fmt.Errorf("recover standard EVM transaction %d sender for runtime work: %w", index, err)
	}
	return m.dependency.Add(index, sender, access, receipt.GasUsed)
}

func newEVMRuntimeAccessMeter(config *params.ChainConfig) *evmRuntimeAccessMeter {
	if config == nil || !config.NativeParallelEnabled() || config.NativeParallel.RequireNativeTransactions {
		return nil
	}
	return &evmRuntimeAccessMeter{
		maxPerTransaction: config.NativeParallel.MaxAccessesPerTransaction,
		maxPerBlock:       config.NativeParallel.MaxAccessesPerBlock,
	}
}

func (m *evmRuntimeAccessMeter) Add(index int, access evmMVCCAccessSet) error {
	if m == nil {
		return nil
	}
	count := uint64(len(access.reads))
	for resource := range access.writes {
		if _, read := access.reads[resource]; !read {
			count++
		}
	}
	if count > m.maxPerTransaction {
		return &EVMRuntimeWorkLimitError{TransactionIndex: index, Dimension: "runtime accesses", Observed: count, Limit: m.maxPerTransaction}
	}
	if m.total > m.maxPerBlock || count > m.maxPerBlock-m.total {
		observed := ^uint64(0)
		if count <= ^uint64(0)-m.total {
			observed = m.total + count
		}
		return &EVMRuntimeWorkLimitError{TransactionIndex: index, Dimension: "block runtime accesses", Observed: observed, Limit: m.maxPerBlock}
	}
	m.total += count
	return nil
}

type evmMVCCWriteIndex struct {
	accounts map[common.Address]struct{}
	storage  map[common.Address]map[common.Hash]struct{}
	wildcard map[common.Address]struct{}
}

func newEVMMVCCWriteIndex() *evmMVCCWriteIndex {
	return &evmMVCCWriteIndex{
		accounts: make(map[common.Address]struct{}),
		storage:  make(map[common.Address]map[common.Hash]struct{}),
		wildcard: make(map[common.Address]struct{}),
	}
}

func (index *evmMVCCWriteIndex) hasStorage(address common.Address) bool {
	return len(index.storage[address]) != 0
}

func (index *evmMVCCWriteIndex) conflictsRead(resource evmMVCCResource) bool {
	if _, changed := index.accounts[resource.address]; changed {
		return true
	}
	switch resource.kind {
	case evmMVCCAccountResource:
		// A storage-only update does not change code, nonce, balance or account
		// existence, so shared contract-code reads remain parallel.
		return false
	case evmMVCCStorageResource:
		if _, all := index.wildcard[resource.address]; all {
			return true
		}
		_, changed := index.storage[resource.address][resource.slot]
		return changed
	case evmMVCCStorageWildcardResource:
		return index.hasStorage(resource.address)
	default:
		return true
	}
}

func (index *evmMVCCWriteIndex) conflictsWrite(resource evmMVCCResource) bool {
	if _, changed := index.accounts[resource.address]; changed {
		return true
	}
	switch resource.kind {
	case evmMVCCAccountResource:
		// Whole-account replacement/deletion cannot be merged over a storage
		// update derived from the older account version.
		return index.hasStorage(resource.address) || index.hasWildcard(resource.address)
	case evmMVCCStorageResource:
		if _, all := index.wildcard[resource.address]; all {
			return true
		}
		_, changed := index.storage[resource.address][resource.slot]
		return changed
	case evmMVCCStorageWildcardResource:
		return index.hasStorage(resource.address) || index.hasWildcard(resource.address)
	default:
		return true
	}
}

func (index *evmMVCCWriteIndex) hasWildcard(address common.Address) bool {
	_, exists := index.wildcard[address]
	return exists
}

func (index *evmMVCCWriteIndex) conflicts(access evmMVCCAccessSet) bool {
	for resource := range access.reads {
		if index.conflictsRead(resource) {
			return true
		}
	}
	for resource := range access.writes {
		if index.conflictsWrite(resource) {
			return true
		}
	}
	return false
}

func (index *evmMVCCWriteIndex) add(access evmMVCCAccessSet) {
	for resource := range access.writes {
		switch resource.kind {
		case evmMVCCAccountResource:
			index.accounts[resource.address] = struct{}{}
		case evmMVCCStorageResource:
			if index.storage[resource.address] == nil {
				index.storage[resource.address] = make(map[common.Hash]struct{})
			}
			index.storage[resource.address][resource.slot] = struct{}{}
		case evmMVCCStorageWildcardResource:
			index.wildcard[resource.address] = struct{}{}
		}
	}
}

type evmMVCCResult struct {
	receipt *types.Receipt
	delta   nativeExecutionDelta
	access  evmMVCCAccessSet
	err     error
}

func captureEVMMVCCDelta(branch *state.StateDB, recorder *evmMVCCRecorder, receipt *types.Receipt) (nativeExecutionDelta, error) {
	if branch == nil || recorder == nil || receipt == nil {
		return nativeExecutionDelta{}, markEVMExecutionInfrastructure(fmt.Errorf("standard EVM MVCC execution produced an incomplete delta"))
	}
	delta := nativeExecutionDelta{}
	accountSet := make(map[common.Address]struct{})
	storageSet := make(map[common.Address]map[common.Hash]struct{})
	for resource := range recorder.writes {
		switch resource.kind {
		case evmMVCCAccountResource:
			accountSet[resource.address] = struct{}{}
		case evmMVCCStorageResource:
			if storageSet[resource.address] == nil {
				storageSet[resource.address] = make(map[common.Hash]struct{})
			}
			storageSet[resource.address][resource.slot] = struct{}{}
		}
	}
	accounts := make([]common.Address, 0, len(accountSet))
	for address := range accountSet {
		accounts = append(accounts, address)
	}
	sort.Slice(accounts, func(i, j int) bool { return bytes.Compare(accounts[i][:], accounts[j][:]) < 0 })
	for _, address := range accounts {
		account := nativeAccountDelta{address: address, exists: branch.Exist(address)}
		if account.exists {
			account.created = branch.CreatedContract(address)
			account.balance = new(big.Int).Set(branch.GetBalance(address))
			account.nonce = branch.GetNonce(address)
			account.code = common.CopyBytes(branch.GetCode(address))
		}
		delta.accounts = append(delta.accounts, account)
	}
	storageAddresses := make([]common.Address, 0, len(storageSet))
	for address := range storageSet {
		storageAddresses = append(storageAddresses, address)
	}
	sort.Slice(storageAddresses, func(i, j int) bool { return bytes.Compare(storageAddresses[i][:], storageAddresses[j][:]) < 0 })
	for _, address := range storageAddresses {
		slots := make([]common.Hash, 0, len(storageSet[address]))
		for slot := range storageSet[address] {
			slots = append(slots, slot)
		}
		sort.Slice(slots, func(i, j int) bool { return bytes.Compare(slots[i][:], slots[j][:]) < 0 })
		for _, slot := range slots {
			delta.storage = append(delta.storage, nativeStorageDelta{
				address: address,
				slot:    slot,
				value:   branch.GetState(address, slot),
			})
		}
	}
	for hash, preimage := range branch.Preimages() {
		delta.preimage = append(delta.preimage, nativePreimageDelta{hash: hash, preimage: common.CopyBytes(preimage)})
	}
	sort.Slice(delta.preimage, func(i, j int) bool {
		return bytes.Compare(delta.preimage[i].hash[:], delta.preimage[j].hash[:]) < 0
	})
	if err := branch.RuntimeMVCCError(recorder.observedAddresses()...); err != nil {
		return nativeExecutionDelta{}, markEVMExecutionInfrastructure(fmt.Errorf("capture standard EVM MVCC state: %w", err))
	}
	delta.logs = receipt.Logs
	receipt.Logs = nil
	for index, entry := range delta.logs {
		if entry == nil {
			return nativeExecutionDelta{}, markEVMExecutionInfrastructure(fmt.Errorf("standard EVM MVCC log %d is nil", index))
		}
	}
	return delta, nil
}

func executeEVMMVCCTransaction(config *params.ChainConfig, chain ChainContext, block *types.Block, branch *state.StateDB, tx *types.Transaction, index int, cfg vm.Config) evmMVCCResult {
	if branch == nil {
		return evmMVCCResult{err: markEVMExecutionInfrastructure(fmt.Errorf("standard EVM MVCC branch is unavailable"))}
	}
	defer branch.ReleaseRuntimeMVCCSnapshot()
	if block == nil {
		return evmMVCCResult{err: markEVMExecutionInfrastructure(fmt.Errorf("standard EVM MVCC block is unavailable"))}
	}
	if tx == nil {
		return evmMVCCResult{err: fmt.Errorf("standard EVM transaction is nil")}
	}
	branch.Prepare(tx.Hash(), block.Hash(), index)
	recorder := newEVMMVCCRecorder(branch)
	gasPool := new(GasPool).AddGas(block.GasLimit())
	var usedGas uint64
	receipt, err := applyTransactionWithEVMState(config, chain, nil, gasPool, branch, recorder, block.Header(), tx, &usedGas, cfg)
	access := recorder.accessSet()
	if stateErr := branch.RuntimeMVCCError(recorder.observedAddresses()...); stateErr != nil {
		return evmMVCCResult{access: access, err: markEVMExecutionInfrastructure(fmt.Errorf("execute standard EVM MVCC state: %w", stateErr))}
	}
	if err != nil {
		return evmMVCCResult{access: access, err: recorder.transactionError(index, err)}
	}
	delta, err := captureEVMMVCCDelta(branch, recorder, receipt)
	return evmMVCCResult{receipt: receipt, delta: delta, access: access, err: err}
}

func mergeEVMMVCCResult(statedb *state.StateDB, gp *GasPool, usedGas *uint64, block *types.Block, index int, tx *types.Transaction, result evmMVCCResult) (*types.Receipt, error) {
	if result.err != nil {
		return nil, result.err
	}
	if statedb == nil || gp == nil || usedGas == nil || block == nil || tx == nil || result.receipt == nil {
		return nil, markEVMExecutionInfrastructure(fmt.Errorf("standard EVM MVCC merge has incomplete context"))
	}
	if result.receipt.GasUsed > tx.Gas() {
		return nil, markEVMExecutionInfrastructure(fmt.Errorf("standard EVM receipt gas used %d exceeds transaction limit %d", result.receipt.GasUsed, tx.Gas()))
	}
	if err := gp.SubGas(tx.Gas()); err != nil {
		return nil, err
	}
	gp.AddGas(tx.Gas() - result.receipt.GasUsed)
	statedb.Prepare(tx.Hash(), block.Hash(), index)
	deletedAccounts := make(map[common.Address]struct{})
	for _, account := range result.delta.accounts {
		if !account.exists {
			deletedAccounts[account.address] = struct{}{}
			if statedb.Exist(account.address) {
				statedb.Suicide(account.address)
			}
			continue
		}
		if !statedb.Exist(account.address) {
			statedb.CreateAccount(account.address)
		}
		if account.created {
			statedb.CreateContract(account.address)
		}
		statedb.SetBalance(account.address, account.balance)
		statedb.SetNonce(account.address, account.nonce)
		statedb.SetCode(account.address, account.code)
	}
	for _, storage := range result.delta.storage {
		if _, deleted := deletedAccounts[storage.address]; deleted {
			continue
		}
		statedb.SetState(storage.address, storage.slot, storage.value)
	}
	for _, preimage := range result.delta.preimage {
		statedb.AddPreimage(preimage.hash, preimage.preimage)
	}
	for _, entry := range result.delta.logs {
		copyEntry := *entry
		copyEntry.Topics = append([]common.Hash(nil), entry.Topics...)
		copyEntry.Data = common.CopyBytes(entry.Data)
		statedb.AddLog(&copyEntry)
	}
	statedb.Finalise(true)
	*usedGas += result.receipt.GasUsed
	result.receipt.CumulativeGasUsed = *usedGas
	result.receipt.Logs = statedb.GetLogs(tx.Hash())
	result.receipt.Bloom = types.CreateBloom(types.Receipts{result.receipt})
	result.receipt.BlockHash = block.Hash()
	result.receipt.BlockNumber = new(big.Int).Set(block.Number())
	result.receipt.TransactionIndex = uint(index)
	return result.receipt, nil
}

func executeRecordedEVMSerial(config *params.ChainConfig, chain ChainContext, block *types.Block, statedb *state.StateDB, gp *GasPool, usedGas *uint64, tx *types.Transaction, index int, cfg vm.Config) (*types.Receipt, evmMVCCAccessSet, error) {
	statedb.Prepare(tx.Hash(), block.Hash(), index)
	recorder := newEVMMVCCRecorder(statedb)
	receipt, err := applyTransactionWithEVMState(config, chain, nil, gp, statedb, recorder, block.Header(), tx, usedGas, cfg)
	access := recorder.accessSet()
	if stateErr := statedb.RuntimeMVCCError(recorder.observedAddresses()...); stateErr != nil {
		return nil, access, markEVMExecutionInfrastructure(fmt.Errorf("execute standard EVM serial state: %w", stateErr))
	}
	if err == nil {
		if pruneErr := statedb.PruneRuntimeMVCCOrigins(recorder.observedStorageSlots()); pruneErr != nil {
			return nil, access, markEVMExecutionInfrastructure(fmt.Errorf("prune standard EVM serial state cache: %w", pruneErr))
		}
	}
	return receipt, access, recorder.transactionError(index, err)
}

func evmOptimisticParallelEnabled(config *params.ChainConfig, cfg vm.Config) bool {
	return config != nil && config.NativeParallelEnabled() && !config.NativeParallel.RequireNativeTransactions && nativeParallelVMConfigSupported(cfg)
}

// processEVMOptimistic executes standard Ethereum envelopes on isolated state
// versions, validates observed dependencies in canonical transaction order and
// re-executes only stale/conflicting results. A scheduling choice can therefore
// affect throughput but never the state root, receipt order or error returned
// by the serial Ethereum reference semantics.
func (p *StateProcessor) processEVMOptimistic(block *types.Block, statedb *state.StateDB, gp *GasPool, usedGas *uint64, cfg vm.Config, recordReceipt func(int, *types.Transaction, *types.Receipt) error) error {
	if p == nil || block == nil || statedb == nil || gp == nil || usedGas == nil || recordReceipt == nil {
		return fmt.Errorf("standard EVM optimistic executor has incomplete context")
	}
	txs := block.Transactions()
	transactionWeights := make([]uint64, len(txs))
	for index, tx := range txs {
		transactionWeights[index] = evmRuntimeTransactionMemoryWeight(p.config, block.Header(), tx)
	}
	retainedWeight := evmRuntimeRetainedMemoryWeight(p.config, len(txs))
	if retainedWeight >= nativeExecutionMemoryBudget {
		return markEVMExecutionInfrastructure(fmt.Errorf("standard EVM retained planning/result memory exceeds executor budget %d", nativeExecutionMemoryBudget))
	}
	batchCapacity := nativeExecutionMemoryBudget - retainedWeight
	var maximumBatchWeight uint64
	for start := 0; start < len(txs); {
		end, weight := evmOptimisticMemoryBatchEndWithin(start, transactionWeights, batchCapacity)
		if end <= start {
			return markEVMExecutionInfrastructure(fmt.Errorf("standard EVM memory scheduler cannot reserve transaction %d", start))
		}
		if weight > maximumBatchWeight {
			maximumBatchWeight = weight
		}
		start = end
	}
	// Reserve the process-wide execution envelope before taking any shared CPU
	// slot or creating a StateDB branch. This ordering cannot deadlock with the
	// Native DAG executor. The lease covers retained dependency/output objects
	// plus the largest speculative microbatch, so concurrent validation cannot
	// multiply either component beyond the shared execution-memory ceiling.
	memoryLease := nativeDAGMemoryLimiter.acquire(retainedWeight + maximumBatchWeight)
	defer nativeDAGMemoryLimiter.release(memoryLease)
	workMeter := newEVMRuntimeWorkMeter(p.config)
	for start := 0; start < len(txs); {
		end, _ := evmOptimisticMemoryBatchEndWithin(start, transactionWeights, batchCapacity)
		if end <= start {
			return markEVMExecutionInfrastructure(fmt.Errorf("standard EVM memory scheduler cannot advance at transaction %d", start))
		}
		workerLimit := end - start
		snapshot, err := statedb.PrepareRuntimeMVCCSnapshot(true)
		if err != nil {
			return fmt.Errorf("prepare standard EVM MVCC snapshot at transaction %d: %w", start, err)
		}
		branches := make([]*state.StateDB, end-start)
		branchErrors := make([]error, end-start)
		runBoundedParallelValidationWithLimit(len(branches), workerLimit, func(offset int) {
			branches[offset], branchErrors[offset] = snapshot.Branch()
		})
		for offset, branchErr := range branchErrors {
			if branchErr != nil {
				// Branch creation may fail after other offsets successfully borrowed
				// the snapshot seed table. Execution has not started yet, so release
				// every successful borrow exactly once before aborting the batch.
				for _, branch := range branches {
					if branch != nil {
						branch.ReleaseRuntimeMVCCSnapshot()
					}
				}
				return fmt.Errorf("create standard EVM MVCC branch for transaction %d: %w", start+offset, branchErr)
			}
		}
		results := make([]evmMVCCResult, end-start)
		runBoundedParallelValidationWithLimit(len(results), workerLimit, func(offset int) {
			index := start + offset
			results[offset] = executeEVMMVCCTransaction(p.config, p.bc, block, branches[offset], txs[index], index, cfg)
			// executeEVMMVCCTransaction has detached the branch from the shared
			// snapshot. Drop the remaining reference immediately so completed
			// workers do not retain account/code/storage caches until serial merge.
			branches[offset] = nil
		})
		priorWrites := newEVMMVCCWriteIndex()
		for offset, speculative := range results {
			index := start + offset
			tx := txs[index]
			conflict := priorWrites.conflicts(speculative.access)
			var receipt *types.Receipt
			if conflict {
				serialReceipt, serialAccess, serialErr := executeRecordedEVMSerial(p.config, p.bc, block, statedb, gp, usedGas, tx, index, cfg)
				if serialErr != nil {
					return evmTransactionExecutionError(index, fmt.Errorf("serial re-execution: %w", serialErr))
				}
				if err := workMeter.Add(p.config, block.Header(), index, tx, serialReceipt, serialAccess); err != nil {
					return evmTransactionExecutionError(index, err)
				}
				receipt = serialReceipt
				priorWrites.add(serialAccess)
			} else {
				if speculative.err != nil {
					return evmTransactionExecutionError(index, fmt.Errorf("speculative execution: %w", speculative.err))
				}
				if err := workMeter.Add(p.config, block.Header(), index, tx, speculative.receipt, speculative.access); err != nil {
					return evmTransactionExecutionError(index, err)
				}
				merged, mergeErr := mergeEVMMVCCResult(statedb, gp, usedGas, block, index, tx, speculative)
				if mergeErr != nil {
					return evmTransactionExecutionError(index, fmt.Errorf("merge: %w", mergeErr))
				}
				receipt = merged
				priorWrites.add(speculative.access)
			}
			if err := recordReceipt(index, tx, receipt); err != nil {
				return evmTransactionExecutionError(index, err)
			}
			results[offset] = evmMVCCResult{}
		}
		start = end
	}
	return nil
}
