// Copyright 2015 The go-ethereum Authors
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

package eth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/cypherium/cypher/accounts"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/bloombits"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/eth/downloader"
	"github.com/cypherium/cypher/eth/gasprice"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/miner"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rpc"
)

// EthAPIBackend implements ethapi.Backend for full nodes
type EthAPIBackend struct {
	extRPCEnabled bool
	eth           *Ethereum
	gpo           *gasprice.Oracle

	// hex node id from node public key
	hexNodeId string

	// timeout value for call
	evmCallTimeOut time.Duration
}

// ChainConfig returns the active chain configuration.
func (b *EthAPIBackend) ChainConfig() *params.ChainConfig {
	return b.eth.blockchain.Config()
}

func (b *EthAPIBackend) CurrentBlock() *types.Block {
	return b.eth.blockchain.CurrentBlock()
}

func (b *EthAPIBackend) SetHead(number uint64) {
	b.eth.protocolManager.downloader.Cancel()
	b.eth.blockchain.SetHead(number)
}

func (b *EthAPIBackend) CommitteeMembers(ctx context.Context, blockNr rpc.BlockNumber) ([]*common.Cnode, error) {

	// Pending block is only known by the miner
	log.Info("CommitteeMembers call")
	if blockNr == rpc.PendingBlockNumber {
		return nil, errors.New("No pending block for Cypherium")
	}
	// Otherwise resolve and return the block
	if blockNr == rpc.LatestBlockNumber {
		return b.eth.keyBlockChain.CurrentCommittee(), nil
	}
	return b.eth.keyBlockChain.GetCommitteeByNumber(uint64(blockNr)), nil
}

func (b *EthAPIBackend) RescueCommittee(configPath string) (*bftview.Committee, common.Hash, error) {
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, common.Hash{}, fmt.Errorf("failed to read config file: %v", err)
	}

	var config bftview.RescueConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, common.Hash{}, fmt.Errorf("failed to parse config: %v", err)
	}

	log.Info("RescueCommittee, latetKeyNumber:%d, configNumber:%d", b.KeyBlockNumber(), config.KeyBlockNumber)
	currentKeyNumber := b.KeyBlockNumber()
	if currentKeyNumber != config.KeyBlockNumber {
		return nil, common.Hash{}, errors.New("not the newest keynumber")
	}

	keyblock := b.eth.keyBlockChain.GetBlockByNumber(config.KeyBlockNumber)
	if keyblock == nil {
		return nil, common.Hash{}, errors.New("key block not found")
	}
	committee := &bftview.Committee{List: config.Committee}
	return committee, keyblock.Hash(), nil
}

func (b *EthAPIBackend) HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error) {
	// Pending block is only known by the miner
	if number == rpc.PendingBlockNumber {
		block := b.eth.miner.PendingBlock()
		return block.Header(), nil
	}
	// Otherwise resolve and return the block
	if number == rpc.LatestBlockNumber {
		return b.eth.blockchain.CurrentBlock().Header(), nil
	}
	return b.eth.blockchain.GetHeaderByNumber(uint64(number)), nil
}

func (b *EthAPIBackend) HeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Header, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.HeaderByNumber(ctx, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		header := b.eth.blockchain.GetHeaderByHash(hash)
		if header == nil {
			return nil, errors.New("header for hash not found")
		}
		if blockNrOrHash.RequireCanonical && b.eth.blockchain.GetCanonicalHash(header.Number.Uint64()) != hash {
			return nil, errors.New("hash is not currently canonical")
		}
		return header, nil
	}
	return nil, errors.New("invalid arguments; neither block nor hash specified")
}

func (b *EthAPIBackend) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	return b.eth.blockchain.GetHeaderByHash(hash), nil
}

func (b *EthAPIBackend) BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Block, error) {
	// Pending block is only known by the miner
	if number == rpc.PendingBlockNumber {
		block := b.eth.miner.PendingBlock()
		return block, nil
	}
	if number == rpc.LatestBlockNumber {
		return b.eth.blockchain.CurrentBlock(), nil
	}
	return b.eth.blockchain.GetBlockByNumber(uint64(number)), nil
}

func (b *EthAPIBackend) KeyBlockByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.KeyBlock, error) {
	if blockNr == rpc.LatestBlockNumber {
		return b.eth.keyBlockChain.CurrentBlock(), nil
	}
	return b.eth.keyBlockChain.GetBlockByNumber(uint64(blockNr)), nil
}

func (b *EthAPIBackend) KeyBlockByHash(ctx context.Context, blockHash common.Hash) (*types.KeyBlock, error) {
	return b.eth.keyBlockChain.GetBlockByHash(blockHash), nil
}

func (b *EthAPIBackend) GetKeyBlockChain() *core.KeyBlockChain { return b.eth.keyBlockChain }
func (b *EthAPIBackend) MockKeyBlock(amount int64)             { b.eth.keyBlockChain.MockBlock(amount) }
func (b *EthAPIBackend) KeyBlockNumber() uint64                { return b.eth.keyBlockChain.CurrentBlockN() }

func (b *EthAPIBackend) BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	return b.eth.blockchain.GetBlockByHash(hash), nil
}

func (b *EthAPIBackend) BlockByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Block, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.BlockByNumber(ctx, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		header := b.eth.blockchain.GetHeaderByHash(hash)
		if header == nil {
			return nil, errors.New("header for hash not found")
		}
		if blockNrOrHash.RequireCanonical && b.eth.blockchain.GetCanonicalHash(header.Number.Uint64()) != hash {
			return nil, errors.New("hash is not currently canonical")
		}
		block := b.eth.blockchain.GetBlock(hash, header.Number.Uint64())
		if block == nil {
			return nil, errors.New("header found, but block body is missing")
		}
		return block, nil
	}
	return nil, errors.New("invalid arguments; neither block nor hash specified")
}

func (b *EthAPIBackend) StateAndHeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	if number == rpc.PendingBlockNumber {
		block, state := b.eth.miner.Pending()
		return state, block.Header(), nil
	}
	header, err := b.HeaderByNumber(ctx, number)
	if err != nil {
		return nil, nil, err
	}
	if header == nil {
		return nil, nil, errors.New("header not found")
	}
	stateDb, err := b.eth.BlockChain().StateAt(header.Root)
	return stateDb, header, err
}

func (b *EthAPIBackend) StateAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.StateAndHeaderByNumber(ctx, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		header, err := b.HeaderByHash(ctx, hash)
		if err != nil {
			return nil, nil, err
		}
		if header == nil {
			return nil, nil, errors.New("header for hash not found")
		}
		if blockNrOrHash.RequireCanonical && b.eth.blockchain.GetCanonicalHash(header.Number.Uint64()) != hash {
			return nil, nil, errors.New("hash is not currently canonical")
		}
		stateDb, err := b.eth.BlockChain().StateAt(header.Root)
		return stateDb, header, err
	}
	return nil, nil, errors.New("invalid arguments; neither block nor hash specified")
}

func (b *EthAPIBackend) GetReceipts(ctx context.Context, hash common.Hash) (types.Receipts, error) {
	return b.eth.blockchain.GetReceiptsByHash(hash), nil
}

func (b *EthAPIBackend) GetLogs(ctx context.Context, hash common.Hash) ([][]*types.Log, error) {
	receipts := b.eth.blockchain.GetReceiptsByHash(hash)
	if receipts == nil {
		return nil, nil
	}
	logs := make([][]*types.Log, len(receipts))
	for i, receipt := range receipts {
		logs[i] = receipt.Logs
	}
	return logs, nil
}

func (b *EthAPIBackend) GetTd(ctx context.Context, hash common.Hash) *big.Int {
	return b.eth.blockchain.GetTdByHash(hash)
}

func (b *EthAPIBackend) GetEVM(ctx context.Context, msg core.Message, state *state.StateDB, header *types.Header) (*vm.EVM, func() error, error) {
	vmError := func() error { return nil }
	context := core.NewEVMContextWithConfig(b.eth.blockchain.Config(), msg, header, b.eth.BlockChain(), nil)
	return vm.NewEVM(context, state, b.eth.blockchain.Config(), *b.eth.blockchain.GetVMConfig()), vmError, nil
}

func (b *EthAPIBackend) SubscribeRemovedLogsEvent(ch chan<- core.RemovedLogsEvent) event.Subscription {
	return b.eth.BlockChain().SubscribeRemovedLogsEvent(ch)
}
func (b *EthAPIBackend) SubscribePendingLogsEvent(ch chan<- []*types.Log) event.Subscription {
	return b.eth.SubscribePendingLogs(ch)
}
func (b *EthAPIBackend) SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription {
	return b.eth.BlockChain().SubscribeChainEvent(ch)
}
func (b *EthAPIBackend) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
	return b.eth.BlockChain().SubscribeChainHeadEvent(ch)
}
func (b *EthAPIBackend) SubscribeKeyChainHeadEvent(ch chan<- core.KeyChainHeadEvent) event.Subscription {
	return b.eth.KeyBlockChain().SubscribeChainEvent(ch)
}
func (b *EthAPIBackend) SubscribeChainSideEvent(ch chan<- core.ChainSideEvent) event.Subscription {
	return b.eth.BlockChain().SubscribeChainSideEvent(ch)
}
func (b *EthAPIBackend) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription {
	return b.eth.BlockChain().SubscribeLogsEvent(ch)
}

func (b *EthAPIBackend) shouldRecordCommonRPCAdmission() bool {
	if b == nil || b.eth == nil || b.ChainConfig() == nil {
		return false
	}
	miner := bftview.GetServerCoinBase()
	if miner == (common.Address{}) {
		return false
	}
	if b.ChainConfig().FairHotstuff && !b.ChainConfig().IsCommonRPCSigner(miner) {
		return false
	}
	if bftview.IamMember() >= 0 {
		return false
	}
	return true
}

func (b *EthAPIBackend) fairHotstuffRequiresCommonRPCAdmission() bool {
	return b != nil && b.eth != nil && b.ChainConfig() != nil && b.ChainConfig().FairHotstuff
}

func (b *EthAPIBackend) currentCommonRPCAdmissionKeyBlockNumber() (uint64, error) {
	if b == nil || b.eth == nil || b.eth.keyBlockChain == nil {
		return 0, fmt.Errorf("key block chain is not available")
	}
	currentKey := b.eth.keyBlockChain.CurrentBlock()
	if currentKey == nil {
		return 0, fmt.Errorf("current key block is not available")
	}
	return currentKey.NumberU64(), nil
}

type commonRPCBatchTxPool interface {
	AddLocals([]*types.Transaction) []error
	AddLocalsAsync([]*types.Transaction) []error
}

type commonRPCTxQUICTransport interface {
	enqueueVerifiedLocalTxsWithAdmissions(context.Context, []*types.Transaction, []core.CommonRPCAdmissionResult, *accounts.Manager) error
}

type commonRPCAdmissionTxPool interface {
	AddLocalsAsync([]*types.Transaction) []error
	Get(common.Hash) *types.Transaction
}

type commonRPCSubmissionLease struct {
	mu    sync.Mutex
	users uint32
}

var commonRPCSubmissionLeases = struct {
	sync.Mutex
	entries map[common.Hash]*commonRPCSubmissionLease
}{entries: make(map[common.Hash]*commonRPCSubmissionLease)}

// lockCommonRPCSubmissionHashes serializes only submissions which contain the
// same exact transaction hash. Registry ownership is ref-counted and released
// when the last holder/waiter leaves, so hostile unique hashes cannot grow it
// without bound. Full-hash ordering makes overlapping multi-hash batches
// deadlock-free while disjoint batches remain concurrent.
func lockCommonRPCSubmissionHashes(hashes []common.Hash) func() {
	unique := make(map[common.Hash]struct{}, len(hashes))
	ordered := make([]common.Hash, 0, len(hashes))
	for _, hash := range hashes {
		if hash == (common.Hash{}) {
			continue
		}
		if _, exists := unique[hash]; exists {
			continue
		}
		unique[hash] = struct{}{}
		ordered = append(ordered, hash)
	}
	sort.Slice(ordered, func(i, j int) bool { return bytes.Compare(ordered[i][:], ordered[j][:]) < 0 })
	leases := make([]*commonRPCSubmissionLease, len(ordered))
	commonRPCSubmissionLeases.Lock()
	for i, hash := range ordered {
		lease := commonRPCSubmissionLeases.entries[hash]
		if lease == nil {
			lease = new(commonRPCSubmissionLease)
			commonRPCSubmissionLeases.entries[hash] = lease
		}
		lease.users++
		leases[i] = lease
	}
	commonRPCSubmissionLeases.Unlock()
	for _, lease := range leases {
		lease.mu.Lock()
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			for i := len(leases) - 1; i >= 0; i-- {
				leases[i].mu.Unlock()
			}
			commonRPCSubmissionLeases.Lock()
			for i, hash := range ordered {
				lease := leases[i]
				if lease.users > 0 {
					lease.users--
				}
				if lease.users == 0 && commonRPCSubmissionLeases.entries[hash] == lease {
					delete(commonRPCSubmissionLeases.entries, hash)
				}
			}
			commonRPCSubmissionLeases.Unlock()
		})
	}
}

// addCommonRPCAdmittedTransactions crosses the admission-before-pool boundary
// while the caller holds exact-hash submission leases. Only a definitive pool
// rejection whose just-created index is still current and whose transaction is
// absent from the pool is eligible for compensating cleanup.
func addCommonRPCAdmittedTransactions(
	pool commonRPCAdmissionTxPool,
	txs types.Transactions,
	admissions []core.CommonRPCAdmissionResult,
	indexes []int,
	results []error,
) (types.Transactions, []core.CommonRPCAdmissionResult, []int, error) {
	if len(admissions) != len(txs) || len(indexes) != len(txs) {
		err := fmt.Errorf("common RPC admission/pool batch alignment mismatch: txs=%d admissions=%d indexes=%d", len(txs), len(admissions), len(indexes))
		for _, index := range indexes {
			if index >= 0 && index < len(results) {
				results[index] = err
			}
		}
		return nil, nil, nil, err
	}
	for i, tx := range txs {
		index := indexes[i]
		admission := admissions[i]
		if index < 0 || index >= len(results) || tx == nil || admission.Batch == nil || int(admission.Item) >= len(admission.Batch.TxHashes) || admission.Batch.TxHashes[admission.Item] != tx.Hash() {
			err := fmt.Errorf("invalid common RPC admission/pool batch item %d", i)
			for _, resultIndex := range indexes {
				if resultIndex >= 0 && resultIndex < len(results) {
					results[resultIndex] = err
				}
			}
			return nil, nil, nil, err
		}
	}
	poolResults := pool.AddLocalsAsync(txs)
	forwardTxs := make(types.Transactions, 0, len(txs))
	forwardAdmissions := make([]core.CommonRPCAdmissionResult, 0, len(txs))
	forwardIndexes := make([]int, 0, len(txs))
	rejectedAdmissions := make([]core.CommonRPCAdmissionResult, 0)
	for i, tx := range txs {
		index := indexes[i]
		if i >= len(poolResults) {
			results[index] = fmt.Errorf("transaction pool omitted batch result")
			continue
		}
		if poolResults[i] != nil && !errors.Is(poolResults[i], core.ErrAlreadyKnown) {
			results[index] = poolResults[i]
			if admissions[i].Updated && admissions[i].Inserted && pool.Get(tx.Hash()) == nil {
				rejectedAdmissions = append(rejectedAdmissions, admissions[i])
			}
			continue
		}
		forwardTxs = append(forwardTxs, tx)
		forwardAdmissions = append(forwardAdmissions, admissions[i])
		forwardIndexes = append(forwardIndexes, index)
	}
	cleanupErr := core.DropRejectedCommonRPCAdmissions(rejectedAdmissions)
	return forwardTxs, forwardAdmissions, forwardIndexes, cleanupErr
}

func addLocalTransactionBatch(pool commonRPCBatchTxPool, txs types.Transactions, async bool) []error {
	if pool == nil {
		errs := make([]error, len(txs))
		for i := range errs {
			errs[i] = fmt.Errorf("common RPC local transaction pool is unavailable")
		}
		return errs
	}
	if async {
		return pool.AddLocalsAsync(txs)
	}
	return pool.AddLocals(txs)
}

func forwardCommonRPCTransaction(
	_ context.Context,
	transport commonRPCTxQUICTransport,
	txs []*types.Transaction,
	admissions []core.CommonRPCAdmissionResult,
	am *accounts.Manager,
	enqueueTimeout time.Duration,
) error {
	if transport == nil {
		return fmt.Errorf("common RPC TxQUIC transport is unavailable")
	}
	var txHash common.Hash
	if len(txs) > 0 && txs[0] != nil {
		txHash = txs[0].Hash()
	}
	if enqueueTimeout <= 0 {
		enqueueTimeout = 15 * time.Second
	}
	enqueueCtx, cancel := context.WithTimeout(context.Background(), enqueueTimeout)
	err := transport.enqueueVerifiedLocalTxsWithAdmissions(enqueueCtx, txs, admissions, am)
	cancel()
	if err != nil {
		// The tx is already local, so a client retry is idempotent. Do not
		// report full ingress success until the durable outbox accepts it.
		return fmt.Errorf("transaction %s accepted locally but TxQUIC enqueue failed: %w", txHash, err)
	}
	return nil
}

func (b *EthAPIBackend) commonRPCGenesisHash() (common.Hash, error) {
	if b == nil || b.eth == nil || b.eth.blockchain == nil || b.eth.blockchain.Genesis() == nil {
		return common.Hash{}, fmt.Errorf("genesis block is not available")
	}
	hash := b.eth.blockchain.Genesis().Hash()
	if hash == (common.Hash{}) {
		return common.Hash{}, fmt.Errorf("genesis block has an empty hash")
	}
	return hash, nil
}

func (b *EthAPIBackend) SendTx(ctx context.Context, signedTx *types.Transaction, sync bool) error {
	recordAdmission := b.shouldRecordCommonRPCAdmission()
	if b.fairHotstuffRequiresCommonRPCAdmission() || recordAdmission {
		results := b.SendTxBatch(ctx, types.Transactions{signedTx})
		if len(results) != 1 {
			return fmt.Errorf("common RPC transaction batch omitted result")
		}
		return results[0]
	}

	var err error
	if sync {
		err = b.eth.txPool.AddLocal(signedTx)
	} else {
		err = b.eth.txPool.AddLocal0(signedTx)
	}
	if err != nil {
		return err
	}

	return nil
}

// SendTxBatch validates and inserts a transaction batch with one TxPool lock
// acquisition and, on a common Fair HotStuff bridge, one durable TxQUIC outbox
// write. Results are aligned with signedTxs.
func (b *EthAPIBackend) SendTxBatch(ctx context.Context, signedTxs types.Transactions) []error {
	results := make([]error, len(signedTxs))
	if len(signedTxs) == 0 {
		return results
	}
	if b == nil || b.eth == nil || b.eth.txPool == nil {
		for i := range results {
			results[i] = fmt.Errorf("transaction pool is unavailable")
		}
		return results
	}
	validTxs := make(types.Transactions, 0, len(signedTxs))
	validIndexes := make([]int, 0, len(signedTxs))
	for i, tx := range signedTxs {
		if tx == nil {
			results[i] = fmt.Errorf("nil transaction")
			continue
		}
		validTxs = append(validTxs, tx)
		validIndexes = append(validIndexes, i)
	}
	if len(validTxs) == 0 {
		return results
	}

	recordAdmission := b.shouldRecordCommonRPCAdmission()
	if b.fairHotstuffRequiresCommonRPCAdmission() && (!recordAdmission || b.eth.txQUICIngress == nil) {
		err := fmt.Errorf("Fair HotStuff transactions must be submitted through an admission-enabled common RPC node")
		for _, index := range validIndexes {
			results[index] = err
		}
		return results
	}
	if recordAdmission && b.eth.txQUICIngress != nil {
		return b.sendCommonRPCTransactionBatch(ctx, validTxs, validIndexes, results)
	}

	// TxQUIC accepts only transaction+admission-certificate units. Generic and
	// committee RPC endpoints therefore retain the synchronous local TxPool
	// durability boundary and never put a naked transaction on TxQUIC.
	poolResults := addLocalTransactionBatch(b.eth.txPool, validTxs, false)
	for i := range validTxs {
		index := validIndexes[i]
		if i >= len(poolResults) {
			results[index] = fmt.Errorf("transaction pool omitted batch result")
			continue
		}
		if poolResults[i] != nil {
			results[index] = poolResults[i]
		}
	}
	return results
}

func (b *EthAPIBackend) sendCommonRPCTransactionBatch(ctx context.Context, txs types.Transactions, indexes []int, results []error) []error {
	started := time.Now()
	var (
		keyBlockElapsed  time.Duration
		preflightElapsed time.Duration
		admissionElapsed time.Duration
		poolElapsed      time.Duration
		outboxElapsed    time.Duration
		eligibleCount    int
		admittedCount    int
		forwardedCount   int
	)
	defer func() {
		log.Debug("Processed common RPC transaction backend batch",
			"requested", len(txs), "eligible", eligibleCount, "admitted", admittedCount, "forwarded", forwardedCount,
			"keyBlock", keyBlockElapsed, "preflight", preflightElapsed, "admission", admissionElapsed,
			"txpool", poolElapsed, "outbox", outboxElapsed, "total", time.Since(started))
	}()
	keyBlockStarted := time.Now()
	keyBlockNumber, err := b.currentCommonRPCAdmissionKeyBlockNumber()
	keyBlockElapsed = time.Since(keyBlockStarted)
	if err != nil {
		for _, index := range indexes {
			results[index] = err
		}
		return results
	}
	genesisHash, err := b.commonRPCGenesisHash()
	if err != nil {
		for _, index := range indexes {
			results[index] = err
		}
		return results
	}
	preflightStarted := time.Now()
	preflightResults := b.eth.txPool.ValidateLocals(txs)
	preflightElapsed = time.Since(preflightStarted)
	eligibleTxs := make(types.Transactions, 0, len(txs))
	eligibleIndexes := make([]int, 0, len(txs))
	for i, tx := range txs {
		index := indexes[i]
		if i >= len(preflightResults) {
			results[index] = fmt.Errorf("transaction pool omitted preflight result")
			continue
		}
		if preflightResults[i] != nil && !errors.Is(preflightResults[i], core.ErrAlreadyKnown) {
			results[index] = preflightResults[i]
			continue
		}
		eligibleTxs = append(eligibleTxs, tx)
		eligibleIndexes = append(eligibleIndexes, index)
	}
	if len(eligibleTxs) == 0 {
		return results
	}
	eligibleCount = len(eligibleTxs)
	// Admissions are durable before AddLocalsAsync can append a transaction to
	// the journal. Pool mutations are never rolled back: replacements and
	// capacity evictions are not transactionally reversible, and an RPC/outbox
	// timeout is an ambiguous result that clients may safely retry.
	hashes := make([]common.Hash, len(eligibleTxs))
	for i, tx := range eligibleTxs {
		hashes[i] = tx.Hash()
	}
	releaseSubmissions := lockCommonRPCSubmissionHashes(hashes)
	defer releaseSubmissions()
	admissionStarted := time.Now()
	admissionResults, err := core.SignAndRecordCommonRPCAdmissions(
		hashes,
		bftview.GetServerCoinBase(),
		b.ChainConfig().ChainID,
		genesisHash,
		keyBlockNumber,
		uint64(time.Now().Unix()),
	)
	admissionElapsed = time.Since(admissionStarted)
	if err != nil {
		for _, index := range eligibleIndexes {
			results[index] = err
		}
		return results
	}
	admittedTxs := make(types.Transactions, 0, len(eligibleTxs))
	admittedAdmissions := make([]core.CommonRPCAdmissionResult, 0, len(eligibleTxs))
	admittedIndexes := make([]int, 0, len(eligibleTxs))
	for i, tx := range eligibleTxs {
		index := eligibleIndexes[i]
		if i >= len(admissionResults) {
			results[index] = fmt.Errorf("common RPC admission batch omitted result")
			continue
		}
		admission := admissionResults[i]
		if admission.Batch == nil || int(admission.Item) >= len(admission.Batch.TxHashes) || admission.Batch.TxHashes[admission.Item] != tx.Hash() {
			results[index] = fmt.Errorf("common RPC admission batch returned an invalid transaction reference")
			continue
		}
		admittedTxs = append(admittedTxs, tx)
		admittedAdmissions = append(admittedAdmissions, admission)
		admittedIndexes = append(admittedIndexes, index)
	}
	if len(admittedTxs) == 0 {
		return results
	}
	admittedCount = len(admittedTxs)
	poolStarted := time.Now()
	forwardTxs, forwardAdmissions, forwardIndexes, admissionPoolErr := addCommonRPCAdmittedTransactions(
		b.eth.txPool,
		admittedTxs,
		admittedAdmissions,
		admittedIndexes,
		results,
	)
	poolElapsed = time.Since(poolStarted)
	if admissionPoolErr != nil {
		// Boundary/cleanup failures deliberately retain admission state. A
		// compensating cleanup error must not mask the definitive TxPool result.
		log.Warn("Failed to finalize common RPC admission/pool boundary", "err", admissionPoolErr)
	}
	// Once TxPool acceptance or conservative retention is decided for every
	// hash, later outbox work cannot create an orphan admission and should not
	// block idempotent same-hash RPC retries.
	releaseSubmissions()
	if len(forwardTxs) == 0 {
		return results
	}
	forwardedCount = len(forwardTxs)
	outboxStarted := time.Now()
	err = forwardCommonRPCTransaction(ctx, b.eth.txQUICIngress, forwardTxs, forwardAdmissions, b.eth.accountManager, b.eth.txQUICIngress.config.ForwardTimeout)
	outboxElapsed = time.Since(outboxStarted)
	if err != nil {
		for _, index := range forwardIndexes {
			results[index] = err
		}
	}
	return results
}

func (b *EthAPIBackend) GetPoolTransactions() (types.Transactions, error) {
	pending, err := b.eth.txPool.Pending()
	if err != nil {
		return nil, err
	}
	var txs types.Transactions
	for _, batch := range pending {
		txs = append(txs, batch...)
	}
	return txs, nil
}
func (b *EthAPIBackend) GetPoolTransaction(hash common.Hash) *types.Transaction {
	return b.eth.txPool.Get(hash)
}
func (b *EthAPIBackend) GetTransaction(ctx context.Context, txHash common.Hash) (*types.Transaction, common.Hash, uint64, uint64, error) {
	tx, blockHash, blockNumber, index := rawdb.ReadTransaction(b.eth.ChainDb(), txHash)
	return tx, blockHash, blockNumber, index, nil
}
func (b *EthAPIBackend) GetPoolNonce(ctx context.Context, addr common.Address) (uint64, error) {
	return b.eth.txPool.Nonce(addr), nil
}
func (b *EthAPIBackend) Stats() (pending int, queued int) { return b.eth.txPool.Stats() }
func (b *EthAPIBackend) TxPoolContent() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	return b.eth.TxPool().Content()
}
func (b *EthAPIBackend) TxPool() *core.TxPool { return b.eth.TxPool() }
func (b *EthAPIBackend) SubscribeNewTxsEvent(ch chan<- core.NewTxsEvent) event.Subscription {
	return b.eth.TxPool().SubscribeNewTxsEvent(ch)
}
func (b *EthAPIBackend) Downloader() *downloader.Downloader { return b.eth.Downloader() }
func (b *EthAPIBackend) ProtocolVersion() int               { return b.eth.EthVersion() }
func (b *EthAPIBackend) SuggestPrice(ctx context.Context) (*big.Int, error) {
	return b.gpo.SuggestPrice(ctx)
}
func (b *EthAPIBackend) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	fallback := big.NewInt(params.GWei)
	price, err := b.gpo.SuggestPrice(ctx)
	if err != nil || price == nil || price.Sign() <= 0 {
		return fallback, nil
	}
	if head := b.CurrentHeader(); head != nil && head.BaseFee != nil {
		tip := new(big.Int).Sub(price, head.BaseFee)
		if tip.Sign() > 0 {
			return tip, nil
		}
	}
	return new(big.Int).Set(price), nil
}
func (b *EthAPIBackend) ChainDb() ethdb.Database           { return b.eth.ChainDb() }
func (b *EthAPIBackend) EventMux() *event.TypeMux          { return b.eth.EventMux() }
func (b *EthAPIBackend) AccountManager() *accounts.Manager { return b.eth.AccountManager() }
func (b *EthAPIBackend) ExtRPCEnabled() bool               { return b.extRPCEnabled }
func (b *EthAPIBackend) CallTimeOut() time.Duration        { return b.evmCallTimeOut }
func (b *EthAPIBackend) RPCGasCap() uint64                 { return b.eth.config.RPCGasCap }
func (b *EthAPIBackend) RPCTxFeeCap() float64              { return b.eth.config.RPCTxFeeCap }
func (b *EthAPIBackend) BloomStatus() (uint64, uint64) {
	sections, _, _ := b.eth.bloomIndexer.Sections()
	return params.BloomBitsBlocks, sections
}
func (b *EthAPIBackend) ServiceFilter(ctx context.Context, session *bloombits.MatcherSession) {
	for i := 0; i < bloomFilterThreads; i++ {
		go session.Multiplex(bloomRetrievalBatch, bloomRetrievalWait, b.eth.bloomRequests)
	}
}
func (b *EthAPIBackend) CandidatePool() *core.CandidatePool { return b.eth.CandidatePool() }
func (b *EthAPIBackend) Engine() consensus.Engine           { return b.eth.engine }
func (b *EthAPIBackend) CurrentHeader() *types.Header       { return b.eth.blockchain.CurrentHeader() }
func (b *EthAPIBackend) Miner() *miner.Miner                { return b.eth.Miner() }

//func (b *EthAPIBackend) StartMining(threads int) error {
//	return b.eth.StartMining(threads)
//}
