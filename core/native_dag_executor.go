package core

import (
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"

	"github.com/cypherium/cypher/common"
	parallelstate "github.com/cypherium/cypher/core/parallel"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/params"
)

// nativeExecutionMicroBatch bounds speculative StateDB copies even when a
// conflict-free wave contains hundreds of thousands of transactions.
const nativeExecutionMicroBatch = 256

// Native logs are already measured as their RLP list. This reserve covers the
// typed receipt envelope, status, cumulative gas, bloom and list framing.
const nativeReceiptBytesPerTransactionReserve = uint64(params.NativeReceiptMemoryReservePerTransaction)

const nativeExecutionMemoryBudget = uint64(params.NativeParallelExecutionMemoryBudget)

const (
	// Planner.Resource/frontier map buckets, one projected access and schedule
	// bookkeeping are charged conservatively before any O(accesses) allocation.
	nativePlanningMemoryPerAccess      = uint64(params.NativePlanningMemoryPerAccess)
	nativePlanningMemoryPerTransaction = uint64(params.NativePlanningMemoryPerTransaction)
)

const (
	nativeBranchBaseMemoryReserve    = uint64(64 * 1024)
	nativeBranchAccountMemoryReserve = uint64(2 * 1024)
	nativeBranchStorageMemoryReserve = uint64(512)
	// Geometric EVM memory growth can transiently retain old+new backing arrays,
	// while call results coexist with a tight RETURNDATA copy. These local
	// scheduling factors bound physical heap even though consensus MemoryLimit
	// retains its stable logical-memory meaning.
	nativeEVMMemoryPhysicalFactor = uint64(4)
	nativeOutputPhysicalFactor    = uint64(2)
)

type nativeWeightedMemoryLimiter struct {
	mu        sync.Mutex
	condition *sync.Cond
	available uint64
	capacity  uint64
}

func newNativeWeightedMemoryLimiter(capacity uint64) *nativeWeightedMemoryLimiter {
	limiter := &nativeWeightedMemoryLimiter{available: capacity, capacity: capacity}
	limiter.condition = sync.NewCond(&limiter.mu)
	return limiter
}

func (l *nativeWeightedMemoryLimiter) acquire(requested uint64) uint64 {
	if requested == 0 {
		return 0
	}
	weight := requested
	if weight > l.capacity {
		weight = l.capacity
	}
	l.mu.Lock()
	for l.available < weight {
		l.condition.Wait()
	}
	l.available -= weight
	l.mu.Unlock()
	return weight
}

func (l *nativeWeightedMemoryLimiter) release(weight uint64) {
	if weight == 0 {
		return
	}
	l.mu.Lock()
	l.available += weight
	l.condition.Broadcast()
	l.mu.Unlock()
}

var nativeDAGMemoryLimiter = newNativeWeightedMemoryLimiter(nativeExecutionMemoryBudget)

func addNativeMemoryWeight(total, amount uint64) uint64 {
	if total >= nativeExecutionMemoryBudget || amount >= nativeExecutionMemoryBudget-total {
		return nativeExecutionMemoryBudget
	}
	return total + amount
}

func addScaledNativeMemoryWeight(total, amount, factor uint64) uint64 {
	for count := uint64(0); count < factor; count++ {
		total = addNativeMemoryWeight(total, amount)
	}
	return total
}

// nativeDAGTransactionMemoryWeight conservatively covers the memory that is
// outside the EVM's signed linear-memory limit: the transaction-local StateDB
// fork, declared account/code snapshots, exact storage slots, encoded logs,
// return data and the transaction itself. It is intentionally local policy;
// scheduling never changes consensus order or results.
func nativeDAGTransactionMemoryWeight(statedb *state.StateDB, tx *types.Transaction) uint64 {
	if tx == nil {
		return nativeBranchBaseMemoryReserve
	}
	weight := nativeBranchBaseMemoryReserve
	weight = addScaledNativeMemoryWeight(weight, tx.MemoryLimit(), nativeEVMMemoryPhysicalFactor)
	weight = addNativeMemoryWeight(weight, tx.LogLimit())
	weight = addScaledNativeMemoryWeight(weight, tx.OutputLimit(), nativeOutputPhysicalFactor)
	weight = addNativeMemoryWeight(weight, uint64(tx.Size()))
	accessCount := tx.NativeAccessCount()
	seenAccounts := make(map[common.Address]struct{}, int(accessCount))
	for accessIndex := uint64(0); accessIndex < accessCount; accessIndex++ {
		access, _ := tx.NativeAccessAt(accessIndex)
		if _, seen := seenAccounts[access.Resource.Address]; !seen {
			seenAccounts[access.Resource.Address] = struct{}{}
			weight = addNativeMemoryWeight(weight, nativeBranchAccountMemoryReserve)
			if statedb != nil {
				codeSize := statedb.GetCodeSize(access.Resource.Address)
				if codeSize > 0 {
					weight = addNativeMemoryWeight(weight, uint64(codeSize))
				}
			}
		}
		if access.Resource.Kind == types.NativeResourceStorage {
			weight = addNativeMemoryWeight(weight, nativeBranchStorageMemoryReserve)
		}
	}
	return weight
}

// nativeDAGRetainedMemoryWeight covers receipts and log objects retained until
// canonical receipt finalization at the end of the block. Full state deltas are
// discarded immediately after merge and are therefore charged to the current
// microbatch instead.
func nativeDAGRetainedMemoryWeight(txs types.Transactions) uint64 {
	var weight uint64
	for _, tx := range txs {
		weight = addNativeMemoryWeight(weight, nativePlanningMemoryPerTransaction)
		weight = addNativeMemoryWeight(weight, nativeReceiptBytesPerTransactionReserve)
		if tx != nil {
			// Log objects and their encoded-size validation buffer can coexist.
			weight = addNativeMemoryWeight(weight, tx.LogLimit())
		}
	}
	return weight
}

func nativeDAGPlanningMemoryWeight(txs types.Transactions) uint64 {
	var weight uint64
	for _, tx := range txs {
		weight = addNativeMemoryWeight(weight, nativePlanningMemoryPerTransaction)
		accesses := uint64(0)
		if tx != nil {
			accesses += tx.NativeAccessCount()
		}
		remaining := nativeExecutionMemoryBudget - weight
		if accesses > remaining/nativePlanningMemoryPerAccess {
			return nativeExecutionMemoryBudget
		}
		weight += accesses * nativePlanningMemoryPerAccess
	}
	return weight
}

func nativeDAGMicroBatchEnd(wave []int, start int, weights []uint64, capacity uint64) (int, uint64) {
	if start >= len(wave) || capacity == 0 {
		return start, 0
	}
	end, total := start, uint64(0)
	for end < len(wave) && end-start < nativeExecutionMicroBatch {
		index := wave[end]
		weight := nativeBranchBaseMemoryReserve
		if index >= 0 && index < len(weights) {
			weight = weights[index]
		}
		if weight > capacity {
			weight = capacity
		}
		if end > start && weight > capacity-total {
			break
		}
		total += weight
		end++
		if total == capacity {
			break
		}
	}
	return end, total
}

type nativeAccountDelta struct {
	address common.Address
	exists  bool
	created bool
	balance *big.Int
	nonce   uint64
	code    []byte
}

type nativeStorageDelta struct {
	address common.Address
	slot    common.Hash
	value   common.Hash
}

type nativePreimageDelta struct {
	hash     common.Hash
	preimage []byte
}

type nativeExecutionDelta struct {
	baseVersion uint64
	accounts    []nativeAccountDelta
	storage     []nativeStorageDelta
	preimage    []nativePreimageDelta
	logs        []*types.Log
}

type nativeDAGResult struct {
	receipt *types.Receipt
	delta   nativeExecutionDelta
	err     error
}

// NativeTransactionExecutionError identifies the canonical block index which
// made speculative native execution fail. Validators reject the block; a
// proposer may omit that candidate, rebuild the schedule, and retry from a
// fresh parent-state instance.
type NativeTransactionExecutionError struct {
	Index int
	Err   error
}

func (e *NativeTransactionExecutionError) Error() string {
	if e == nil {
		return "native transaction execution failed"
	}
	return fmt.Sprintf("native transaction %d: %v", e.Index, e.Err)
}

func (e *NativeTransactionExecutionError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func nativeExecutionLimits(config *params.ChainConfig) (parallelstate.Limits, error) {
	if config == nil || !config.NativeParallelEnabled() {
		return parallelstate.Limits{}, fmt.Errorf("native dependency scheduler is not enabled")
	}
	if !config.NativeParallel.RequireNativeTransactions {
		return parallelstate.Limits{}, ErrNativeTxDisabled
	}
	native := config.NativeParallel
	return parallelstate.Limits{
		Transactions:        native.MaxTransactionsPerBlock,
		AccessesPerTx:       native.MaxAccessesPerTransaction,
		AccessesPerBlock:    native.MaxAccessesPerBlock,
		ComputePerTx:        native.MaxComputePerTransaction,
		ComputePerBlock:     native.MaxComputePerBlock,
		CriticalPathCompute: native.MaxCriticalPathCompute,
		DependencyDepth:     native.MaxDependencyDepth,
	}, nil
}

func nativeExecutionProjection(config *params.NativeParallelConfig, tx *types.Transaction) (parallelstate.Transaction, error) {
	if config == nil || config.ReplayWindowBlocks == 0 || config.ReplayWindowBlocks > params.NativeReplayHistoryWindow {
		return parallelstate.Transaction{}, fmt.Errorf("dependency scheduler has invalid native replay configuration")
	}
	if tx == nil || tx.Type() != types.NativeTxType {
		return parallelstate.Transaction{}, fmt.Errorf("dependency scheduler requires NativeTxV1")
	}
	accessCount := tx.NativeAccessCount()
	projected := parallelstate.Transaction{
		Accesses: make([]parallelstate.Access, int(accessCount)),
		Compute:  tx.ComputeLimit(),
	}
	for accessIndex := uint64(0); accessIndex < accessCount; accessIndex++ {
		access, _ := tx.NativeAccessAt(accessIndex)
		projected.Accesses[accessIndex] = parallelstate.Access{
			Resource: parallelstate.Resource{
				Kind:    parallelstate.ResourceKind(access.Resource.Kind),
				Address: access.Resource.Address,
				Slot:    access.Resource.Slot,
			},
			Mode: parallelstate.AccessMode(access.Mode),
		}
	}
	return projected, nil
}

// validateNativeGasReservations makes the signed compute-limit sum a block
// reservation invariant. The DAG may merge independent waves in dependency
// order while the serial reference path runs canonical transaction order; if
// declared limits could overbook header.GasLimit, those two correct local
// execution choices could disagree on which transaction first fails GasPool
// reservation. Requiring the full signed sum to fit makes merge order
// irrelevant and matches proposer admission.
func validateNativeGasReservations(txs types.Transactions, gasLimit uint64) error {
	var reserved uint64
	for index, tx := range txs {
		if tx == nil {
			return fmt.Errorf("native transaction %d is nil", index)
		}
		compute := tx.Gas()
		if reserved > gasLimit || compute > gasLimit-reserved {
			return fmt.Errorf("native declared compute through transaction %d exceeds block gas limit %d", index, gasLimit)
		}
		reserved += compute
	}
	return nil
}

// NativeDependencyPlanner is the proposer-side incremental form of the exact
// scheduler validators derive from the final block. Rejected candidates do not
// mutate it, so priority-ordered selection can skip a hot resource without an
// O(n) schedule rebuild.
type NativeDependencyPlanner struct {
	planner      *parallelstate.Planner
	config       *params.NativeParallelConfig
	totalLog     uint64
	totalReceipt uint64
}

func NewNativeDependencyPlanner(config *params.ChainConfig) (*NativeDependencyPlanner, error) {
	limits, err := nativeExecutionLimits(config)
	if err != nil {
		return nil, err
	}
	return &NativeDependencyPlanner{planner: parallelstate.NewPlanner(limits), config: config.NativeParallel}, nil
}

func (p *NativeDependencyPlanner) TryAdd(tx *types.Transaction) error {
	if p == nil || p.planner == nil {
		return fmt.Errorf("native dependency planner is unavailable")
	}
	projected, err := nativeExecutionProjection(p.config, tx)
	if err != nil {
		return err
	}
	logBytes := tx.LogLimit()
	receiptBytes := logBytes + nativeReceiptBytesPerTransactionReserve
	if logBytes > p.config.MaxLogBytesPerBlock-p.totalLog {
		return fmt.Errorf("%w: native declared log bytes exceed block maximum %d", parallelstate.ErrWorkLimit, p.config.MaxLogBytesPerBlock)
	}
	if receiptBytes > p.config.MaxReceiptBytesPerBlock-p.totalReceipt {
		return fmt.Errorf("%w: native declared receipt bytes exceed block maximum %d", parallelstate.ErrWorkLimit, p.config.MaxReceiptBytesPerBlock)
	}
	if err := p.planner.TryAdd(projected); err != nil {
		return err
	}
	p.totalLog += logBytes
	p.totalReceipt += receiptBytes
	return nil
}

func validateNativeDeclaredResultEnvelope(config *params.ChainConfig, txs types.Transactions) error {
	if config == nil || !config.NativeParallelEnabled() {
		return nil
	}
	var totalLog, totalReceipt uint64
	for index, tx := range txs {
		if tx == nil || tx.Type() != types.NativeTxType {
			continue
		}
		logBytes := tx.LogLimit()
		if logBytes > config.NativeParallel.MaxLogBytesPerBlock-totalLog {
			return fmt.Errorf("native transaction %d makes declared log bytes exceed block maximum %d", index, config.NativeParallel.MaxLogBytesPerBlock)
		}
		receiptBytes := logBytes + nativeReceiptBytesPerTransactionReserve
		if receiptBytes > config.NativeParallel.MaxReceiptBytesPerBlock-totalReceipt {
			return fmt.Errorf("native transaction %d makes declared receipt bytes exceed block maximum %d", index, config.NativeParallel.MaxReceiptBytesPerBlock)
		}
		totalLog += logBytes
		totalReceipt += receiptBytes
	}
	return nil
}

func buildNativeExecutionSchedule(config *params.ChainConfig, txs types.Transactions) (*parallelstate.Schedule, error) {
	limits, err := nativeExecutionLimits(config)
	if err != nil {
		return nil, err
	}
	planningWeight := nativeDAGPlanningMemoryWeight(txs)
	if planningWeight >= nativeExecutionMemoryBudget {
		return nil, fmt.Errorf("native dependency plan memory exceeds budget %d", nativeExecutionMemoryBudget)
	}
	planningLease := nativeDAGMemoryLimiter.acquire(planningWeight)
	defer nativeDAGMemoryLimiter.release(planningLease)
	planner := parallelstate.NewPlanner(limits)
	for index, tx := range txs {
		projected, err := nativeExecutionProjection(config.NativeParallel, tx)
		if err != nil {
			return nil, fmt.Errorf("native dependency scheduler transaction %d: %w", index, err)
		}
		if err := planner.TryAdd(projected); err != nil {
			return nil, fmt.Errorf("native dependency scheduler transaction %d: %w", index, err)
		}
	}
	if err := validateNativeDeclaredResultEnvelope(config, txs); err != nil {
		return nil, err
	}
	return planner.TakeSchedule(), nil
}

func takeOrBuildNativeExecutionSchedule(config *params.ChainConfig, block *types.Block, handoff *nativeScheduleHandoff) (*parallelstate.Schedule, error) {
	if block == nil {
		return nil, fmt.Errorf("native dependency scheduler requires a block")
	}
	if handoff != nil {
		if schedule := handoff.take(config, block); schedule != nil {
			return schedule, nil
		}
	}
	return buildNativeExecutionSchedule(config, block.Transactions())
}

func nativeDeclaredAccountAddresses(config *params.ChainConfig, tx *types.Transaction) []common.Address {
	if tx == nil {
		return nil
	}
	accessCount := tx.NativeAccessCount()
	addresses := make([]common.Address, 0, int(accessCount)+1)
	seen := make(map[common.Address]struct{}, int(accessCount)+1)
	for accessIndex := uint64(0); accessIndex < accessCount; accessIndex++ {
		access, _ := tx.NativeAccessAt(accessIndex)
		address := access.Resource.Address
		if _, duplicate := seen[address]; duplicate {
			continue
		}
		seen[address] = struct{}{}
		addresses = append(addresses, address)
	}
	return addresses
}

func nativeDeclaredStorageSlots(config *params.ChainConfig, tx *types.Transaction) map[common.Address][]common.Hash {
	slots := make(map[common.Address][]common.Hash)
	if tx == nil {
		return slots
	}
	for accessIndex := uint64(0); accessIndex < tx.NativeAccessCount(); accessIndex++ {
		access, _ := tx.NativeAccessAt(accessIndex)
		if access.Resource.Kind == types.NativeResourceStorage {
			slots[access.Resource.Address] = append(slots[access.Resource.Address], access.Resource.Slot)
		}
	}
	return slots
}

func executeNativeDAGTransaction(config *params.ChainConfig, bc ChainContext, header *types.Header, blockHash common.Hash, branch *state.StateDB, tx *types.Transaction, index int, cfg vm.Config) nativeDAGResult {
	if branch == nil || tx == nil {
		return nativeDAGResult{err: fmt.Errorf("native MVCC branch is unavailable")}
	}
	branch.Prepare(tx.Hash(), blockHash, index)
	gasPool := new(GasPool).AddGas(tx.Gas())
	var usedGas uint64
	receipt, err := ApplyNativeTransactionReference(config, bc, nil, gasPool, branch, header, tx, &usedGas, cfg)
	if err != nil {
		return nativeDAGResult{err: err}
	}
	delta, err := captureNativeExecutionDelta(config, branch, tx, receipt)
	return nativeDAGResult{receipt: receipt, delta: delta, err: err}
}

func captureNativeExecutionDelta(config *params.ChainConfig, branch *state.StateDB, tx *types.Transaction, receipt *types.Receipt) (nativeExecutionDelta, error) {
	if branch == nil || tx == nil || receipt == nil {
		return nativeExecutionDelta{}, fmt.Errorf("native execution produced an incomplete delta")
	}
	delta := nativeExecutionDelta{baseVersion: branch.NativeMVCCVersion()}
	for accessIndex := uint64(0); accessIndex < tx.NativeAccessCount(); accessIndex++ {
		access, _ := tx.NativeAccessAt(accessIndex)
		if access.Mode != types.NativeAccessWrite {
			continue
		}
		switch access.Resource.Kind {
		case types.NativeResourceAccount:
			address := access.Resource.Address
			if !branch.NativeAccountChanged(address) {
				continue
			}
			account := nativeAccountDelta{address: address, exists: branch.Exist(address)}
			if account.exists {
				account.created = branch.CreatedContract(address)
				account.balance = new(big.Int).Set(branch.GetBalance(address))
				account.nonce = branch.GetNonce(address)
				account.code = common.CopyBytes(branch.GetCode(address))
			}
			delta.accounts = append(delta.accounts, account)
		case types.NativeResourceStorage:
			if !branch.NativeStorageChanged(access.Resource.Address, access.Resource.Slot) {
				continue
			}
			delta.storage = append(delta.storage, nativeStorageDelta{
				address: access.Resource.Address,
				slot:    access.Resource.Slot,
				value:   branch.GetState(access.Resource.Address, access.Resource.Slot),
			})
		default:
			return nativeExecutionDelta{}, fmt.Errorf("native delta contains resource kind %d", access.Resource.Kind)
		}
	}
	for hash, preimage := range branch.Preimages() {
		delta.preimage = append(delta.preimage, nativePreimageDelta{hash: hash, preimage: common.CopyBytes(preimage)})
	}
	sort.Slice(delta.preimage, func(i, j int) bool {
		return string(delta.preimage[i].hash[:]) < string(delta.preimage[j].hash[:])
	})
	// Transfer log ownership from the speculative receipt into the immutable
	// delta. The objects already belong exclusively to this StateDB branch;
	// deep-copying every topic/data slice would double retained block memory.
	delta.logs = receipt.Logs
	receipt.Logs = nil
	for index, entry := range delta.logs {
		if entry == nil {
			return nativeExecutionDelta{}, fmt.Errorf("native execution log %d is nil", index)
		}
	}
	return delta, nil
}

func mergeNativeExecutionDelta(statedb *state.StateDB, gp *GasPool, usedGas *uint64, block *types.Block, index int, tx *types.Transaction, result nativeDAGResult) (*types.Receipt, error) {
	if result.err != nil {
		return nil, result.err
	}
	if statedb == nil || gp == nil || usedGas == nil || block == nil || tx == nil || result.receipt == nil {
		return nil, fmt.Errorf("native execution merge has incomplete context")
	}
	if result.delta.baseVersion != statedb.NativeMVCCVersion() {
		return nil, fmt.Errorf("stale native MVCC delta base %d, current %d", result.delta.baseVersion, statedb.NativeMVCCVersion())
	}
	// Preserve the serial StateTransition gas-pool contract exactly: reserve
	// the transaction's complete signed compute limit before publishing any
	// state, then return only the unused portion. Subtracting GasUsed directly
	// would let a Byzantine block overbook the block gas pool whenever earlier
	// transactions happened to consume less than their declared limit.
	if result.receipt.GasUsed > tx.Gas() {
		return nil, fmt.Errorf("native receipt gas used %d exceeds transaction limit %d", result.receipt.GasUsed, tx.Gas())
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
			// Defensive serial equivalence for a future transaction version that
			// permits whole-account deletion. NativeTxV1 currently rejects the
			// operation before delta capture.
			continue
		}
		statedb.SetState(storage.address, storage.slot, storage.value)
	}
	for _, preimage := range result.delta.preimage {
		statedb.AddPreimage(preimage.hash, preimage.preimage)
	}
	*usedGas += result.receipt.GasUsed
	return result.receipt, nil
}

func finalizeNativeDAGReceipt(statedb *state.StateDB, block *types.Block, index int, tx *types.Transaction, result nativeDAGResult, cumulativeGas uint64) (*types.Receipt, error) {
	if statedb == nil || block == nil || tx == nil || result.receipt == nil {
		return nil, fmt.Errorf("native receipt finalization has incomplete context")
	}
	statedb.Prepare(tx.Hash(), block.Hash(), index)
	for _, entry := range result.delta.logs {
		copyEntry := *entry
		copyEntry.Topics = append([]common.Hash(nil), entry.Topics...)
		copyEntry.Data = common.CopyBytes(entry.Data)
		statedb.AddLog(&copyEntry)
	}
	result.receipt.CumulativeGasUsed = cumulativeGas
	result.receipt.Logs = statedb.GetLogs(tx.Hash())
	result.receipt.Bloom = types.CreateBloom(types.Receipts{result.receipt})
	result.receipt.BlockHash = block.Hash()
	result.receipt.BlockNumber = new(big.Int).Set(block.Number())
	result.receipt.TransactionIndex = uint(index)
	return result.receipt, nil
}

func (p *StateProcessor) processNativeDAG(block *types.Block, statedb *state.StateDB, gp *GasPool, usedGas *uint64, cfg vm.Config, recordReceipt func(int, *types.Transaction, *types.Receipt) error) error {
	if p == nil || block == nil || statedb == nil || gp == nil || usedGas == nil || recordReceipt == nil {
		return fmt.Errorf("native DAG executor has incomplete context")
	}
	if !statedb.NativeBlockHashesPrepared() {
		return fmt.Errorf("native DAG executor requires a prepared state-rooted BLOCKHASH view")
	}
	txs := block.Transactions()
	var handoff *nativeScheduleHandoff
	if p.bc != nil && p.bc.nativeSchedules != nil {
		handoff = p.bc.nativeSchedules
	}
	schedule, err := takeOrBuildNativeExecutionSchedule(p.config, block, handoff)
	if err != nil {
		return err
	}
	// Reserve one atomic block-level lease before creating any StateDB branch.
	// Acquiring per-worker leases after forks exist both leaves the forks
	// unaccounted and can deadlock concurrent validators through hold-and-wait.
	// The lease covers all receipts/logs retained to block finalization plus the
	// largest conservative microbatch; adversarial declarations merely reduce
	// batch width instead of escaping the shared process budget.
	retainedWeight := nativeDAGRetainedMemoryWeight(txs)
	if retainedWeight >= nativeExecutionMemoryBudget {
		return fmt.Errorf("native retained result memory exceeds executor budget %d", nativeExecutionMemoryBudget)
	}
	batchCapacity := nativeExecutionMemoryBudget - retainedWeight
	transactionWeights := make([]uint64, len(txs))
	for index, tx := range txs {
		transactionWeights[index] = nativeDAGTransactionMemoryWeight(statedb, tx)
	}
	var maximumBatchWeight uint64
	for _, wave := range schedule.Waves {
		for start := 0; start < len(wave); {
			end, weight := nativeDAGMicroBatchEnd(wave, start, transactionWeights, batchCapacity)
			if end == start {
				return fmt.Errorf("native memory scheduler cannot advance at wave offset %d", start)
			}
			if weight > maximumBatchWeight {
				maximumBatchWeight = weight
			}
			start = end
		}
	}
	blockMemoryWeight := retainedWeight + maximumBatchWeight
	memoryLease := nativeDAGMemoryLimiter.acquire(blockMemoryWeight)
	defer nativeDAGMemoryLimiter.release(memoryLease)

	initialUsedGas := *usedGas
	resultsByIndex := make([]nativeDAGResult, len(txs))
	receiptsByIndex := make(types.Receipts, len(txs))
	for _, wave := range schedule.Waves {
		for start := 0; start < len(wave); {
			end, _ := nativeDAGMicroBatchEnd(wave, start, transactionWeights, batchCapacity)
			indexes := wave[start:end]
			results := make([]nativeDAGResult, len(indexes))
			// Prefetch the union of declared resources once into an immutable MVCC
			// version. Branch objects are then assembled in parallel without lazy
			// reads or cache mutation on the shared block StateDB.
			branches := make([]*state.StateDB, len(indexes))
			declaredAccounts := make([][]common.Address, len(indexes))
			declaredSlots := make([]map[common.Address][]common.Hash, len(indexes))
			unionAccounts := make([]common.Address, 0)
			unionSlots := make(map[common.Address][]common.Hash)
			seenAccounts := make(map[common.Address]struct{})
			seenSlots := make(map[common.Address]map[common.Hash]struct{})
			for offset, index := range indexes {
				declaredAccounts[offset] = nativeDeclaredAccountAddresses(p.config, txs[index])
				declaredSlots[offset] = nativeDeclaredStorageSlots(p.config, txs[index])
				for _, address := range declaredAccounts[offset] {
					if _, seen := seenAccounts[address]; !seen {
						seenAccounts[address] = struct{}{}
						unionAccounts = append(unionAccounts, address)
					}
				}
				for address, slots := range declaredSlots[offset] {
					if seenSlots[address] == nil {
						seenSlots[address] = make(map[common.Hash]struct{}, len(slots))
					}
					for _, slot := range slots {
						if _, seen := seenSlots[address][slot]; seen {
							continue
						}
						seenSlots[address][slot] = struct{}{}
						unionSlots[address] = append(unionSlots[address], slot)
					}
				}
			}
			snapshot, err := statedb.PrepareNativeDeclaredSnapshot(unionAccounts, unionSlots)
			if err != nil {
				return fmt.Errorf("prepare native MVCC version %d: %w", statedb.NativeMVCCVersion(), err)
			}
			branchErrors := make([]error, len(indexes))
			runBoundedParallelValidation(len(indexes), func(offset int) {
				branches[offset], branchErrors[offset] = snapshot.Branch(declaredAccounts[offset], declaredSlots[offset])
			})
			for offset, err := range branchErrors {
				if err != nil {
					return fmt.Errorf("create native MVCC branch for transaction %d: %w", indexes[offset], err)
				}
			}
			runBoundedParallelValidation(len(indexes), func(offset int) {
				index := indexes[offset]
				results[offset] = executeNativeDAGTransaction(p.config, p.bc, block.Header(), block.Hash(), branches[offset], txs[index], index, cfg)
			})
			// Publish only after the entire microbatch executed successfully, then
			// merge in canonical transaction order independent of completion timing.
			for offset, result := range results {
				if result.err != nil {
					return &NativeTransactionExecutionError{Index: indexes[offset], Err: result.err}
				}
			}
			for offset, result := range results {
				index := indexes[offset]
				receipt, err := mergeNativeExecutionDelta(statedb, gp, usedGas, block, index, txs[index], result)
				if err != nil {
					return &NativeTransactionExecutionError{Index: index, Err: fmt.Errorf("merge: %w", err)}
				}
				// State/account/storage/preimage deltas have been published and are
				// no longer needed. Retain only the receipt and logs required for
				// canonical block-order finalization.
				resultsByIndex[index] = nativeDAGResult{
					receipt: result.receipt,
					delta:   nativeExecutionDelta{logs: result.delta.logs},
				}
				receiptsByIndex[index] = receipt
			}
			// Transactions in a microbatch have no conflicting declared writes.
			// Publish all deltas first, then perform the EIP-161/account finalisation
			// once at the same visibility boundary used to seed the next batch.
			// This preserves committed-state semantics between dependent batches
			// while removing one full journal/dirties scan per transaction.
			statedb.Finalise(true)
			if err := statedb.AdvanceNativeMVCCVersion(); err != nil {
				return err
			}
			start = end
		}
	}
	cumulativeGas := initialUsedGas
	for index, receipt := range receiptsByIndex {
		if receipt == nil {
			return fmt.Errorf("native dependency schedule omitted transaction %d", index)
		}
		cumulativeGas += receipt.GasUsed
		finalized, err := finalizeNativeDAGReceipt(statedb, block, index, txs[index], resultsByIndex[index], cumulativeGas)
		if err != nil {
			return err
		}
		if err := recordReceipt(index, txs[index], finalized); err != nil {
			return err
		}
		resultsByIndex[index] = nativeDAGResult{}
		receiptsByIndex[index] = nil
	}
	if cumulativeGas != *usedGas {
		return fmt.Errorf("native DAG gas accounting mismatch: block order=%d merged=%d", cumulativeGas, *usedGas)
	}
	return nil
}

// nativeParallelVMConfigSupported reports whether cfg can be shared by the
// speculative executors. Tracers and interpreter overrides may contain mutable
// process-local state, while ExtraEips is backed by a slice which the EVM may
// rewrite when it encounters an unsupported activation. Keep those modes on
// the canonical serial reference executor. This is deliberately the same
// conservative boundary used by the legacy native-transfer parallel lane.
func nativeParallelVMConfigSupported(cfg vm.Config) bool {
	return !cfg.Debug && cfg.Tracer == nil && !cfg.EnablePreimageRecording &&
		cfg.EVMInterpreter == "" && cfg.EWASMInterpreter == "" && len(cfg.ExtraEips) == 0
}

// processNativeReferenceSerial executes NativeTxV1 in canonical block order.
// It is the explicit fallback for VM configurations which cannot safely be
// shared across DAG workers.
func (p *StateProcessor) processNativeReferenceSerial(block *types.Block, statedb *state.StateDB, gp *GasPool, usedGas *uint64, cfg vm.Config, recordReceipt func(int, *types.Transaction, *types.Receipt) error) error {
	if p == nil || block == nil || statedb == nil || gp == nil || usedGas == nil || recordReceipt == nil {
		return fmt.Errorf("native serial reference executor has incomplete context")
	}
	for index, tx := range block.Transactions() {
		if tx == nil {
			return &NativeTransactionExecutionError{Index: index, Err: fmt.Errorf("nil NativeTxV1")}
		}
		statedb.Prepare(tx.Hash(), block.Hash(), index)
		receipt, err := ApplyNativeTransactionReference(p.config, p.bc, nil, gp, statedb, block.Header(), tx, usedGas, cfg)
		if err != nil {
			return &NativeTransactionExecutionError{Index: index, Err: err}
		}
		if err := recordReceipt(index, tx, receipt); err != nil {
			return err
		}
	}
	return nil
}

// processNativeTransactions is shared by proposal construction and block
// import, ensuring both sides make the same DAG-versus-reference decision.
func (p *StateProcessor) processNativeTransactions(block *types.Block, statedb *state.StateDB, gp *GasPool, usedGas *uint64, cfg vm.Config, recordReceipt func(int, *types.Transaction, *types.Receipt) error) error {
	if block == nil {
		return fmt.Errorf("native transaction executor requires a block")
	}
	if err := validateNativeGasReservations(block.Transactions(), block.GasLimit()); err != nil {
		return err
	}
	if err := PrepareNativeReplaySequences(p.config, statedb, block.Transactions()); err != nil {
		var replayErr *NativeReplaySequenceError
		if errors.As(err, &replayErr) {
			return &NativeTransactionExecutionError{Index: replayErr.Index, Err: replayErr}
		}
		return err
	}
	if nativeParallelVMConfigSupported(cfg) {
		return p.processNativeDAG(block, statedb, gp, usedGas, cfg, recordReceipt)
	}
	return p.processNativeReferenceSerial(block, statedb, gp, usedGas, cfg, recordReceipt)
}

// ExecuteNativeProposalTransactions is the proposer-side entry point for the
// same dependency DAG and serial reference executor used by validators. It
// mutates statedb on success. On error the caller must discard that speculative
// StateDB (earlier waves may already have been finalized); proposal builders
// naturally own a fresh parent-state instance per attempt.
func ExecuteNativeProposalTransactions(config *params.ChainConfig, bc *BlockChain, header *types.Header, txs types.Transactions, statedb *state.StateDB, cfg vm.Config) (types.Receipts, []*types.Log, uint64, error) {
	if config == nil || !config.NativeParallelEnabled() {
		return nil, nil, 0, fmt.Errorf("native proposal executor has incomplete context")
	}
	if !config.NativeParallel.RequireNativeTransactions {
		return nil, nil, 0, ErrNativeTxDisabled
	}
	if bc == nil || header == nil || header.Number == nil || statedb == nil {
		return nil, nil, 0, fmt.Errorf("native proposal executor has incomplete context")
	}
	if err := PrepareNativeBlockHashes(config, header, statedb); err != nil {
		return nil, nil, 0, err
	}
	block := types.NewBlockWithHeader(header).WithBody(txs, nil)
	processor := &StateProcessor{config: config, bc: bc}
	gp := new(GasPool).AddGas(header.GasLimit)
	usedGas := new(uint64)
	receipts := make(types.Receipts, 0, len(txs))
	logs := make([]*types.Log, 0)
	record := func(index int, tx *types.Transaction, receipt *types.Receipt) error {
		if index != len(receipts) || tx == nil || receipt == nil {
			return fmt.Errorf("native proposal receipt order mismatch at transaction %d", index)
		}
		receipts = append(receipts, receipt)
		logs = append(logs, receipt.Logs...)
		return nil
	}
	if err := processor.processNativeTransactions(block, statedb, gp, usedGas, cfg, record); err != nil {
		return nil, nil, 0, err
	}
	return receipts, logs, *usedGas, nil
}
