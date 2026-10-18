package core

import (
	"errors"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus/colossusX"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/params"
)

func TestExecuteEVMProposalTransactionsMatchesValidatorMVCC(t *testing.T) {
	config := evmMVCTestConfig()
	base := newModernTestState(t)
	block, txs := evmMVCCTestBlock(t, config, base, false, 32)
	prepareEVMOnlyHistory(base, block.Header())
	base.Finalise(true)

	engine := colossusX.NewFaker()
	defer engine.Close()
	chain := &BlockChain{chainConfig: config, engine: engine}

	proposalState := base.Copy()
	proposalReceipts, proposalLogs, proposalGas, err := ExecuteEVMProposalTransactions(config, chain, block.Header(), txs, proposalState, vm.Config{})
	if err != nil {
		t.Fatalf("proposal execution: %v", err)
	}

	validatorState := base.Copy()
	if err := PrepareNativeBlockHashes(config, block.Header(), validatorState); err != nil {
		t.Fatal(err)
	}
	validatorGasPool := new(GasPool).AddGas(block.GasLimit())
	var validatorGas uint64
	validatorReceipts := make(types.Receipts, 0, len(txs))
	validatorLogs := make([]*types.Log, 0)
	processor := &StateProcessor{config: config, bc: chain}
	err = processor.processEVMOptimistic(block, validatorState, validatorGasPool, &validatorGas, vm.Config{}, func(index int, tx *types.Transaction, receipt *types.Receipt) error {
		validatorReceipts = append(validatorReceipts, receipt)
		validatorLogs = append(validatorLogs, receipt.Logs...)
		return nil
	})
	if err != nil {
		t.Fatalf("validator execution: %v", err)
	}

	proposalRoot := proposalState.IntermediateRoot(true)
	validatorRoot := validatorState.IntermediateRoot(true)
	if proposalRoot != validatorRoot || proposalGas != validatorGas || !reflect.DeepEqual(proposalReceipts, validatorReceipts) || !reflect.DeepEqual(proposalLogs, validatorLogs) {
		t.Fatalf("proposal/validator mismatch: root=%s/%s gas=%d/%d receipts=%t logs=%t",
			proposalRoot, validatorRoot, proposalGas, validatorGas,
			reflect.DeepEqual(proposalReceipts, validatorReceipts), reflect.DeepEqual(proposalLogs, validatorLogs))
	}
}

func TestExecuteEVMProposalTransactionsUsesSerialOracleForDebugVM(t *testing.T) {
	config := evmMVCTestConfig()
	base := newModernTestState(t)
	block, txs := evmMVCCTestBlock(t, config, base, true, 8)
	prepareEVMOnlyHistory(base, block.Header())
	base.Finalise(true)
	engine := colossusX.NewFaker()
	defer engine.Close()
	chain := &BlockChain{chainConfig: config, engine: engine}

	parallelState := base.Copy()
	parallelReceipts, _, parallelGas, err := ExecuteEVMProposalTransactions(config, chain, block.Header(), txs, parallelState, vm.Config{EnablePreimageRecording: true})
	if err != nil {
		t.Fatalf("serial proposal fallback: %v", err)
	}

	referenceState := base.Copy()
	if err := PrepareNativeBlockHashes(config, block.Header(), referenceState); err != nil {
		t.Fatal(err)
	}
	referencePool := new(GasPool).AddGas(block.GasLimit())
	var referenceGas uint64
	referenceReceipts := make(types.Receipts, 0, len(txs))
	for index, tx := range txs {
		referenceState.Prepare(tx.Hash(), block.Hash(), index)
		receipt, err := ApplyTransaction(config, chain, nil, referencePool, referenceState, block.Header(), tx, &referenceGas, vm.Config{EnablePreimageRecording: true})
		if err != nil {
			t.Fatalf("reference transaction %d: %v", index, err)
		}
		referenceReceipts = append(referenceReceipts, receipt)
	}
	if parallelState.IntermediateRoot(true) != referenceState.IntermediateRoot(true) || parallelGas != referenceGas || !reflect.DeepEqual(parallelReceipts, referenceReceipts) {
		t.Fatal("unsupported VM configuration did not match the serial oracle")
	}
}

func TestExecuteEVMProposalTransactionsSupportsTypesZeroThroughFourAndPreservesBlobSidecar(t *testing.T) {
	config := evmMVCTestConfig()
	base := newModernTestState(t)
	to := common.HexToAddress("0x7000000000000000000000000000000000000007")
	signer := types.LatestSignerForChainID(config.ChainID)
	keys := []string{
		"1111111111111111111111111111111111111111111111111111111111111111",
		"2222222222222222222222222222222222222222222222222222222222222222",
		"3333333333333333333333333333333333333333333333333333333333333333",
		"4444444444444444444444444444444444444444444444444444444444444444",
	}
	unsigned := []*types.Transaction{
		types.NewTransaction(0, to, new(big.Int), params.TxGas, big.NewInt(params.FixedTransferGasPricePerGas), nil),
		types.NewTx(&types.AccessListTx{ChainID: config.ChainID, GasPrice: big.NewInt(params.FixedTransferGasPricePerGas), Gas: params.TxGas, To: &to, Value: new(big.Int)}),
		types.NewTx(&types.DynamicFeeTx{ChainID: config.ChainID, GasTipCap: big.NewInt(1), GasFeeCap: new(big.Int).Add(big.NewInt(params.FixedBaseFeePerGas), big.NewInt(1)), Gas: params.TxGas, To: &to, Value: new(big.Int)}),
	}
	txs := make(types.Transactions, 0, 5)
	for index, transaction := range unsigned {
		key, err := crypto.HexToECDSA(keys[index])
		if err != nil {
			t.Fatal(err)
		}
		signed, err := types.SignTx(transaction, signer, key)
		if err != nil {
			t.Fatal(err)
		}
		base.SetBalance(crypto.PubkeyToAddress(key.PublicKey), new(big.Int).Exp(big.NewInt(10), big.NewInt(24), nil))
		txs = append(txs, signed)
	}
	_, sidecar := signedPoolBlobTx(t, 0, false)
	blobKey, err := crypto.HexToECDSA("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	blobUnsigned := types.NewTx(&types.BlobTx{
		ChainID: config.ChainID, GasTipCap: big.NewInt(1), GasFeeCap: new(big.Int).Add(big.NewInt(params.FixedBaseFeePerGas), big.NewInt(1)),
		Gas: params.TxGas, To: to, Value: new(big.Int), BlobFeeCap: big.NewInt(2), BlobHashes: sidecar.BlobHashes(),
	})
	blobTx, err := types.SignTx(blobUnsigned, signer, blobKey)
	if err != nil {
		t.Fatal(err)
	}
	blobTx = toOsakaBlobSidecar(t, blobTx.WithBlobSidecar(sidecar))
	sidecar = blobTx.BlobSidecar()
	blobSender, err := types.Sender(signer, blobTx)
	if err != nil {
		t.Fatal(err)
	}
	base.SetBalance(blobSender, new(big.Int).Exp(big.NewInt(10), big.NewInt(24), nil))
	txs = append(txs, blobTx)

	authorityKey, err := crypto.HexToECDSA("5555555555555555555555555555555555555555555555555555555555555555")
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := types.SignSetCode(authorityKey, types.SetCodeAuthorization{ChainID: config.ChainID, Address: to})
	if err != nil {
		t.Fatal(err)
	}
	setCodeKey, err := crypto.HexToECDSA(keys[3])
	if err != nil {
		t.Fatal(err)
	}
	setCodeUnsigned := types.NewTx(&types.SetCodeTx{
		ChainID: config.ChainID, GasTipCap: big.NewInt(11), GasFeeCap: new(big.Int).Add(big.NewInt(params.FixedBaseFeePerGas), big.NewInt(1)),
		Gas: 100_000, To: to, Value: new(big.Int), AuthList: []types.SetCodeAuthorization{authorization},
	})
	setCodeTx, err := types.SignTx(setCodeUnsigned, signer, setCodeKey)
	if err != nil {
		t.Fatal(err)
	}
	base.SetBalance(crypto.PubkeyToAddress(setCodeKey.PublicKey), new(big.Int).Exp(big.NewInt(10), big.NewInt(24), nil))
	txs = append(txs, setCodeTx)

	header := &types.Header{
		ParentHash: common.HexToHash("0xa004"), Coinbase: common.HexToAddress("0x9000000000000000000000000000000000000009"),
		Number: big.NewInt(1), Difficulty: big.NewInt(1), GasLimit: 500_000, Time: 1,
		BaseFee: big.NewInt(params.FixedBaseFeePerGas), BlockType: types.SlowTx_Block, BlobGasUsed: blobTx.BlobGas(),
	}
	prepareEVMOnlyHistory(base, header)
	base.Finalise(true)
	engine := colossusX.NewFaker()
	defer engine.Close()
	chain := &BlockChain{chainConfig: config, engine: engine}
	receipts, _, _, err := ExecuteEVMProposalTransactions(config, chain, header, txs, base, vm.Config{})
	if err != nil {
		t.Fatalf("mixed standard EVM proposal: %v", err)
	}
	if len(receipts) != 5 {
		t.Fatalf("receipt count = %d, want 5", len(receipts))
	}
	for index, wantType := range []uint8{types.LegacyTxType, types.AccessListTxType, types.DynamicFeeTxType, types.BlobTxType, types.SetCodeTxType} {
		if receipts[index].Type != wantType {
			t.Fatalf("receipt %d type = %#x, want %#x", index, receipts[index].Type, wantType)
		}
	}
	if got := txs[3].BlobSidecar(); got == nil || len(got.Blobs) != len(sidecar.Blobs) || got.Blobs[0][31] != sidecar.Blobs[0][31] {
		t.Fatal("proposal execution detached or mutated the authenticated blob sidecar")
	}
}

type evmProposalExecutionCounter struct {
	*vm.StructLogger
	starts       int
	slotsAtStart []int
}

func (c *evmProposalExecutionCounter) CaptureStart(from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) error {
	c.starts++
	c.slotsAtStart = append(c.slotsAtStart, len(parallelValidationSlots))
	return c.StructLogger.CaptureStart(from, to, create, input, gas, value)
}

func signedEVMFilteringTransaction(t *testing.T, config *params.ChainConfig, base *state.StateDB, target common.Address, gas uint64, data []byte) (*types.Transaction, common.Address) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	unsigned := types.NewTx(&types.DynamicFeeTx{
		ChainID: config.ChainID, GasTipCap: big.NewInt(2), GasFeeCap: new(big.Int).Add(big.NewInt(params.FixedBaseFeePerGas), big.NewInt(2)),
		Gas: gas, To: &target, Value: new(big.Int), Data: data,
	})
	tx, err := types.SignTx(unsigned, types.LatestSignerForChainID(config.ChainID), key)
	if err != nil {
		t.Fatal(err)
	}
	sender := crypto.PubkeyToAddress(key.PublicKey)
	base.SetBalance(sender, new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil))
	return tx, sender
}

func TestFilterEVMProposalTransactionsVisitsManyFailuresOnce(t *testing.T) {
	config := evmMVCTestConfig()
	base := newModernTestState(t)
	block, txs := evmMVCCTestBlock(t, config, base, false, 65)
	good, _ := signedEVMFilteringTransaction(t, config, base, common.HexToAddress("0xf001"), params.TxGas, nil)
	txs = append(txs, good)
	header := block.Header()
	header.GasLimit += good.Gas()
	prepareEVMOnlyHistory(base, header)
	base.Finalise(true)
	config.NativeParallel.MaxComputePerTransaction = params.TxGas
	config.NativeParallel.MaxLogBytesPerTransaction = 1
	config.NativeParallel.MaxLogBytesPerBlock = 1
	engine := colossusX.NewFaker()
	defer engine.Close()
	chain := &BlockChain{chainConfig: config, engine: engine}
	counter := &evmProposalExecutionCounter{StructLogger: vm.NewStructLogger(nil)}
	filteredState := base.Copy()
	selected, rejected, err := FilterEVMProposalTransactions(config, chain, header, txs, filteredState, vm.Config{Debug: true, Tracer: counter})
	if err != nil {
		t.Fatalf("filter many failures: %v", err)
	}
	if len(selected) != 1 || selected[0].Hash() != good.Hash() || len(rejected) != 65 || counter.starts != len(txs) {
		t.Fatalf("filter selected=%d rejected=%d executions=%d, want 1/65/%d", len(selected), len(rejected), counter.starts, len(txs))
	}
	for index, rejection := range rejected {
		var limit *EVMRuntimeWorkLimitError
		if rejection.TransactionIndex != index || !errors.As(rejection, &limit) || limit.Dimension != "compute" {
			t.Fatalf("rejection %d = %v, want per-transaction compute limit", index, rejection)
		}
	}
	reference := base.Copy()
	if _, _, _, err := ExecuteEVMProposalTransactions(config, chain, header, selected, reference, vm.Config{}); err != nil {
		t.Fatal(err)
	}
	if filteredState.IntermediateRoot(true) != reference.IntermediateRoot(true) {
		t.Fatal("rejected runtime transactions leaked fees, nonce or storage into filtered state")
	}
}

func TestFilterEVMProposalTransactionsWaitsForSharedCPUSlot(t *testing.T) {
	config := evmMVCTestConfig()
	base := newModernTestState(t)
	block, txs := evmMVCCTestBlock(t, config, base, false, 1)
	prepareEVMOnlyHistory(base, block.Header())
	base.Finalise(true)
	engine := colossusX.NewFaker()
	defer engine.Close()
	chain := &BlockChain{chainConfig: config, engine: engine}

	synctest.Test(t, func(t *testing.T) {
		originalSlots := parallelValidationSlots
		parallelValidationSlots = make(chan struct{}, 2)
		defer func() { parallelValidationSlots = originalSlots }()
		parallelValidationSlots <- struct{}{}
		parallelValidationSlots <- struct{}{}
		counter := &evmProposalExecutionCounter{StructLogger: vm.NewStructLogger(&vm.LogConfig{Limit: 1})}
		var selected types.Transactions
		var rejected []*EVMTransactionExecutionError
		var err error
		done := make(chan struct{})
		go func() {
			selected, rejected, err = FilterEVMProposalTransactions(config, chain, block.Header(), txs, base.Copy(), vm.Config{Debug: true, Tracer: counter})
			close(done)
		}()
		// Wait until the filter is durably blocked, with no clock-based guess
		// about whether its goroutine has reached the shared CPU acquisition.
		synctest.Wait()
		if counter.starts != 0 {
			t.Errorf("filter entered %d EVM transactions with every shared CPU slot occupied", counter.starts)
		}
		select {
		case <-done:
			t.Error("filter completed while every shared CPU slot was occupied")
		default:
		}
		<-parallelValidationSlots
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("filter did not finish after a shared CPU slot became available")
		}
		if err != nil || len(selected) != 1 || len(rejected) != 0 || counter.starts != 1 || !reflect.DeepEqual(counter.slotsAtStart, []int{2}) || len(parallelValidationSlots) != 1 {
			t.Fatalf("resumed filter selected=%d rejected=%d executions=%d occupied slots=%d err=%v, want 1/0/1/1/nil", len(selected), len(rejected), counter.starts, len(parallelValidationSlots), err)
		}
		<-parallelValidationSlots
	})
}

func TestEVMSerialExecutorsWaitForSharedMemoryAndRelease(t *testing.T) {
	for _, entry := range []string{"proposal", "processor"} {
		for _, mode := range []string{"single", "debug", "custom_eips", "oversized_estimate"} {
			for _, failure := range []bool{false, true} {
				name := entry + "/" + mode + "/success"
				if failure {
					name = entry + "/" + mode + "/nonce_error"
				}
				t.Run(name, func(t *testing.T) {
					config := evmMVCTestConfig()
					config.FairHotstuff = false // Import needs no committee or admission fixture.
					if mode == "oversized_estimate" {
						// An estimate must serialize local execution without creating a
						// new consensus rejection. No large output buffer is allocated.
						config.NativeParallel.MaxOutputBytesPerTransaction = nativeExecutionMemoryBudget
					}
					count := 1
					if mode == "debug" || mode == "custom_eips" {
						count = 2
					}
					base := newModernTestState(t)
					block, txs := evmMVCCTestBlock(t, config, base, false, count)
					prepareEVMOnlyHistory(base, block.Header())
					sender, err := types.Sender(types.LatestSignerForChainID(config.ChainID), txs[0])
					if err != nil {
						t.Fatal(err)
					}
					if failure {
						base.SetNonce(sender, 1)
					}
					base.Finalise(true)
					engine := colossusX.NewFaker()
					defer engine.Close()
					chain := &BlockChain{chainConfig: config, engine: engine}
					processor := NewStateProcessor(config, chain, engine)
					run := func(statedb *state.StateDB) (types.Receipts, []*types.Log, uint64, error) {
						var cfg vm.Config
						switch mode {
						case "debug":
							cfg = vm.Config{Debug: true, Tracer: vm.NewStructLogger(&vm.LogConfig{Limit: 1})}
						case "custom_eips":
							cfg.ExtraEips = []int{1344}
						}
						if entry == "processor" {
							return processor.Process(block, statedb, cfg)
						}
						return ExecuteEVMProposalTransactions(config, chain, block.Header(), txs, statedb, cfg)
					}
					reference := base.Copy()
					wantReceipts, wantLogs, wantGas, wantErr := run(reference)
					if failure != errors.Is(wantErr, ErrNonceTooLow) || !failure && wantErr != nil {
						t.Fatalf("reference execution error = %v", wantErr)
					}
					wantRoot := reference.IntermediateRoot(true)
					statedb := base.Copy()
					synctest.Test(t, func(t *testing.T) {
						original := nativeDAGMemoryLimiter
						limiter := newNativeWeightedMemoryLimiter(3)
						nativeDAGMemoryLimiter = limiter
						defer func() { nativeDAGMemoryLimiter = original }()
						held := limiter.acquire(3)
						var receipts types.Receipts
						var logs []*types.Log
						var usedGas uint64
						var executionErr error
						done := make(chan struct{})
						go func() {
							receipts, logs, usedGas, executionErr = run(statedb)
							close(done)
						}()
						synctest.Wait()
						select {
						case <-done:
							t.Error("serial execution finished while the shared memory lease was exhausted")
						default:
						}
						if got := statedb.GetNonce(sender); got != base.GetNonce(sender) {
							t.Errorf("serial execution mutated sender nonce before acquiring memory: %d", got)
						}
						limiter.release(1)
						synctest.Wait()
						select {
						case <-done:
							t.Error("serial execution entered without its complete memory lease")
						default:
						}
						limiter.release(held - 1)
						synctest.Wait()
						select {
						case <-done:
						default:
							t.Fatal("serial execution did not resume after memory became available")
						}
						if failure != errors.Is(executionErr, ErrNonceTooLow) || !failure && executionErr != nil {
							t.Fatalf("resumed execution error = %v, want %v", executionErr, wantErr)
						}
						if usedGas != wantGas || !reflect.DeepEqual(receipts, wantReceipts) || !reflect.DeepEqual(logs, wantLogs) || statedb.IntermediateRoot(true) != wantRoot {
							t.Fatal("memory scheduling changed serial state, receipts, logs, or gas")
						}
						if limiter.available != limiter.capacity {
							t.Fatalf("serial execution leaked memory lease: available=%d capacity=%d", limiter.available, limiter.capacity)
						}
					})
				})
			}
		}
	}
}

func TestEVMSerialMemoryLeaseReservesRetainedAndLargestTransaction(t *testing.T) {
	config := evmMVCTestConfig()
	config.NativeParallel.MaxMemoryBytesPerTransaction = 128
	config.NativeParallel.MaxAccessesPerTransaction = 1
	config.NativeParallel.MaxAccessesPerBlock = 2
	config.NativeParallel.MaxOutputBytesPerTransaction = 1
	config.NativeParallel.MaxLogBytesPerTransaction = 1
	config.NativeParallel.MaxLogBytesPerBlock = 2
	header := &types.Header{Number: big.NewInt(1)}
	txs := types.Transactions{
		types.NewTransaction(0, common.Address{1}, new(big.Int), params.TxGas, big.NewInt(1), nil),
		types.NewTransaction(0, common.Address{2}, new(big.Int), 100_000, big.NewInt(1), nil),
	}
	first := evmRuntimeTransactionMemoryWeight(config, header, txs[0])
	largest := evmRuntimeTransactionMemoryWeight(config, header, txs[1])
	retained := evmRuntimeRetainedMemoryWeight(config, len(txs))
	if largest <= first || retained == 0 || retained+largest > 128*1024 {
		t.Fatalf("invalid small reservation fixture: first=%d largest=%d retained=%d", first, largest, retained)
	}
	original := nativeDAGMemoryLimiter
	defer func() { nativeDAGMemoryLimiter = original }()
	nativeDAGMemoryLimiter = newNativeWeightedMemoryLimiter(retained + largest)
	limiter, lease := acquireEVMSerialMemoryLease(config, header, txs)
	if lease != retained+largest || limiter.available != 0 {
		t.Fatalf("serial lease=%d available=%d, want retained %d plus largest %d", lease, limiter.available, retained, largest)
	}
	// Replacing the injected global must not change the returned lease owner.
	nativeDAGMemoryLimiter = newNativeWeightedMemoryLimiter(7)
	limiter.release(lease)
	if limiter.available != limiter.capacity || nativeDAGMemoryLimiter.available != 7 {
		t.Fatal("serial memory lease was released to the wrong limiter")
	}
	config.NativeParallel.MaxOutputBytesPerTransaction = ^uint64(0)
	limiter, lease = acquireEVMSerialMemoryLease(config, header, txs)
	if lease != 7 || limiter.available != 0 {
		t.Fatalf("saturating estimate lease=%d available=%d, want exclusive seven-unit lease", lease, limiter.available)
	}
	limiter.release(lease)
}

func TestEVMSerialMemoryLeaseSkipsEmptyAndOtherProfiles(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		original := nativeDAGMemoryLimiter
		limiter := newNativeWeightedMemoryLimiter(3)
		nativeDAGMemoryLimiter = limiter
		defer func() { nativeDAGMemoryLimiter = original }()
		held := limiter.acquire(3)
		legacy := evmMVCTestConfig()
		legacy.NativeParallel = nil
		native := evmMVCTestConfig()
		native.NativeParallel.RequireNativeTransactions = true
		config := evmMVCTestConfig()
		txs := types.Transactions{types.NewTransaction(0, common.Address{1}, new(big.Int), params.TxGas, big.NewInt(1), nil)}
		done := make(chan struct{})
		go func() {
			for _, profile := range []*params.ChainConfig{nil, legacy, native} {
				owner, lease := acquireEVMSerialMemoryLease(profile, &types.Header{Number: big.NewInt(1)}, txs)
				owner.release(lease)
			}
			owner, lease := acquireEVMSerialMemoryLease(config, &types.Header{Number: big.NewInt(1)}, nil)
			owner.release(lease)
			close(done)
		}()
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Error("empty or unrelated execution profile waited for the standard EVM lease")
		}
		if limiter.available != 0 {
			t.Error("skipped serial execution changed the occupied memory budget")
		}
		limiter.release(held)
		synctest.Wait()
		<-done
	})
}

type evmProposalPublicationDatabase struct {
	state.Database
	publications int
}

func (d *evmProposalPublicationDatabase) OpenTrie(root common.Hash) (state.Trie, error) {
	accountTrie, err := d.Database.OpenTrie(root)
	if err != nil {
		return nil, err
	}
	return &evmProposalPublicationTrie{Trie: accountTrie, publications: &d.publications}, nil
}

func (d *evmProposalPublicationDatabase) CopyTrie(accountTrie state.Trie) state.Trie {
	if counted, ok := accountTrie.(*evmProposalPublicationTrie); ok {
		accountTrie = counted.Trie
	}
	// Count only the canonical StateDB's account-trie publications, excluding
	// its immutable snapshot and isolated worker copies.
	return d.Database.CopyTrie(accountTrie)
}

type evmProposalPublicationTrie struct {
	state.Trie
	publications *int
}

func (t *evmProposalPublicationTrie) Hash() common.Hash {
	*t.publications++
	return t.Trie.Hash()
}

func TestFilterEVMProposalTransactionsReusesSnapshotAcrossRejections(t *testing.T) {
	for _, test := range []struct {
		name         string
		logSizes     []uint64
		publications int
	}{
		{"all rejected", []uint64{64, 64, 64, 64}, 1},
		{"last accepted", []uint64{64, 64, 64, 32}, 1},
		{"mixed with trailing rejections", []uint64{32, 64, 64, 32, 64, 64}, 3},
		{"mixed with last accepted", []uint64{32, 64, 64, 32}, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := evmMVCTestConfig()
			base := newModernTestState(t)
			contract := common.HexToAddress("0xfa01")
			// Increment slot zero and log its new value. Calldata determines
			// log length, so rejected candidates also change state before metering.
			base.SetCode(contract, []byte{0x60, 0x00, 0x54, 0x60, 0x01, 0x01, 0x60, 0x00, 0x55, 0x60, 0x00, 0x54, 0x60, 0x00, 0x52, 0x60, 0x00, 0x35, 0x60, 0x00, 0xa0, 0x00})
			base.SetNonce(contract, 1)
			txs := make(types.Transactions, len(test.logSizes))
			wantSelected := make(types.Transactions, 0, len(txs))
			var rejectedIndices []int
			senders := make([]common.Address, len(txs))
			for index, size := range test.logSizes {
				key, err := crypto.ToECDSA(common.LeftPadBytes(big.NewInt(int64(index+1)).Bytes(), 32))
				if err != nil {
					t.Fatal(err)
				}
				senders[index] = crypto.PubkeyToAddress(key.PublicKey)
				base.SetBalance(senders[index], new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil))
				txs[index], err = types.SignTx(types.NewTx(&types.DynamicFeeTx{
					ChainID: config.ChainID, GasTipCap: big.NewInt(2), GasFeeCap: new(big.Int).Add(big.NewInt(params.FixedBaseFeePerGas), big.NewInt(2)),
					Gas: 100_000, To: &contract, Value: new(big.Int), Data: common.LeftPadBytes(new(big.Int).SetUint64(size).Bytes(), 32),
				}), types.LatestSignerForChainID(config.ChainID), key)
				if err != nil {
					t.Fatal(err)
				}
				if size == 32 {
					wantSelected = append(wantSelected, txs[index])
				} else {
					rejectedIndices = append(rejectedIndices, index)
				}
			}
			_, retainedLogBytes, err := consensusLogMeasurements([]*types.Log{{Address: contract, Data: make([]byte, 32)}})
			if err != nil {
				t.Fatal(err)
			}
			config.NativeParallel.MaxLogBytesPerTransaction = retainedLogBytes
			config.NativeParallel.MaxLogBytesPerBlock = retainedLogBytes * uint64(len(txs))
			if err := config.NativeParallel.Validate(); err != nil {
				t.Fatal(err)
			}
			header := &types.Header{ParentHash: common.HexToHash("0xfa02"), Coinbase: common.HexToAddress("0xfa03"), Number: big.NewInt(1), Difficulty: big.NewInt(1), GasLimit: uint64(len(txs)) * 100_000, Time: 1, BaseFee: big.NewInt(params.FixedBaseFeePerGas)}
			root, err := base.Commit(true)
			if err != nil {
				t.Fatal(err)
			}
			database := &evmProposalPublicationDatabase{Database: base.Database()}
			filtered, err := state.New(root, database, nil)
			if err != nil {
				t.Fatal(err)
			}
			// Leave the system history update pending so the first counted
			// publication must include it before any candidate executes.
			prepareEVMOnlyHistory(filtered, header)
			engine := colossusX.NewFaker()
			defer engine.Close()
			chain := &BlockChain{chainConfig: config, engine: engine}
			counter := &evmProposalExecutionCounter{StructLogger: vm.NewStructLogger(&vm.LogConfig{Limit: 1})}
			selected, rejected, err := FilterEVMProposalTransactions(config, chain, header, txs, filtered, vm.Config{Debug: true, Tracer: counter})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(selected, wantSelected) || len(rejected) != len(rejectedIndices) {
				t.Fatalf("selected=%v rejected=%v, want selected=%v rejected indices=%v", selected, rejected, wantSelected, rejectedIndices)
			}
			for index, rejection := range rejected {
				if rejection.TransactionIndex != rejectedIndices[index] || !strings.Contains(rejection.Err.Error(), "log") {
					t.Fatalf("rejection %d = %v, want log rejection at candidate %d", index, rejection, rejectedIndices[index])
				}
			}
			if database.publications != test.publications || counter.starts != len(txs) {
				t.Errorf("canonical trie publications=%d executions=%d, want %d/%d", database.publications, counter.starts, test.publications, len(txs))
			}
			reference := base.Copy()
			prepareEVMOnlyHistory(reference, header)
			if err := PrepareNativeBlockHashes(config, header, reference); err != nil {
				t.Fatal(err)
			}
			gasPool := new(GasPool).AddGas(header.GasLimit)
			var wantGas uint64
			wantReceipts := make(types.Receipts, 0, len(wantSelected))
			wantLogs := make([]*types.Log, 0, len(wantSelected))
			for index, tx := range wantSelected {
				reference.Prepare(tx.Hash(), header.Hash(), index)
				receipt, err := ApplyTransaction(config, chain, nil, gasPool, reference, header, tx, &wantGas, vm.Config{})
				if err != nil {
					t.Fatal(err)
				}
				wantReceipts = append(wantReceipts, receipt)
				wantLogs = append(wantLogs, receipt.Logs...)
				if len(receipt.Logs) != 1 || new(big.Int).SetBytes(receipt.Logs[0].Data).Uint64() != uint64(index+1) || !reflect.DeepEqual(filtered.GetLogs(tx.Hash()), receipt.Logs) {
					t.Fatalf("accepted transaction %d did not observe its canonical storage/log prefix", index)
				}
			}
			for index, sender := range senders {
				if filtered.GetNonce(sender) != reference.GetNonce(sender) || filtered.GetBalance(sender).Cmp(reference.GetBalance(sender)) != 0 || (test.logSizes[index] == 64 && len(filtered.GetLogs(txs[index].Hash())) != 0) {
					t.Fatalf("candidate %d leaked or lost nonce, gas debit or logs", index)
				}
			}
			wantRoot := reference.IntermediateRoot(true)
			if filtered.IntermediateRoot(true) != wantRoot {
				t.Fatal("filter state differs from sequential selected-body execution")
			}
			replay := base.Copy()
			prepareEVMOnlyHistory(replay, header)
			receipts, logs, gas, err := ExecuteEVMProposalTransactions(config, chain, header, selected, replay, vm.Config{})
			if err != nil {
				t.Fatal(err)
			}
			if replay.IntermediateRoot(true) != wantRoot || gas != wantGas || !reflect.DeepEqual(receipts, wantReceipts) || !reflect.DeepEqual(logs, wantLogs) {
				t.Fatalf("selected-body replay differs from sequential state, receipts, gas or logs: gas=%d/%d", gas, wantGas)
			}
		})
	}
}

func TestFilterEVMProposalTransactionsRestoresAccessAndOutputAfterDependencyRejection(t *testing.T) {
	config := evmMVCTestConfig()
	base := newModernTestState(t)
	block, txs := evmMVCCTestBlock(t, config, base, true, 2)
	good, _ := signedEVMFilteringTransaction(t, config, base, common.HexToAddress("0x8000000000000000000000000000000000000080"), 100_000, evmMVCCStorageCallData(99, 1000))
	txs = append(txs, good)
	header := block.Header()
	header.GasLimit += good.Gas()
	prepareEVMOnlyHistory(base, header)
	base.Finalise(true)
	engine := colossusX.NewFaker()
	defer engine.Close()
	chain := &BlockChain{chainConfig: config, engine: engine}
	var acceptedAccesses uint64
	for _, tx := range (types.Transactions{txs[0], good}) {
		snapshot, err := base.Copy().PrepareRuntimeMVCCSnapshot(true)
		if err != nil {
			t.Fatal(err)
		}
		branch, err := snapshot.Branch()
		if err != nil {
			t.Fatal(err)
		}
		result := executeEVMMVCCTransaction(config, chain, block, branch, tx, 0, vm.Config{})
		if result.err != nil {
			t.Fatal(result.err)
		}
		meter := newEVMRuntimeAccessMeter(config)
		if err := meter.Add(0, result.access); err != nil {
			t.Fatal(err)
		}
		acceptedAccesses += meter.total
	}
	config.NativeParallel.MaxDependencyDepth = 1
	config.NativeParallel.MaxAccessesPerTransaction = acceptedAccesses
	config.NativeParallel.MaxAccessesPerBlock = acceptedAccesses
	config.NativeParallel.MaxLogBytesPerTransaction = 1
	config.NativeParallel.MaxLogBytesPerBlock = 2
	if err := config.NativeParallel.Validate(); err != nil {
		t.Fatalf("dependency filtering config: %v", err)
	}
	filteredState := base.Copy()
	selected, rejected, err := FilterEVMProposalTransactions(config, chain, header, txs, filteredState, vm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	var limit *EVMRuntimeWorkLimitError
	if len(selected) != 2 || selected[0].Hash() != txs[0].Hash() || selected[1].Hash() != good.Hash() || len(rejected) != 1 || !errors.As(rejected[0], &limit) || limit.Dimension != "dependency depth" {
		t.Fatalf("dependency filtering selected=%v rejected=%v, want prefix/suffix and depth rejection", selected, rejected)
	}
	reference := base.Copy()
	if _, _, _, err := ExecuteEVMProposalTransactions(config, chain, header, selected, reference, vm.Config{}); err != nil {
		t.Fatal(err)
	}
	if filteredState.IntermediateRoot(true) != reference.IntermediateRoot(true) {
		t.Fatal("dependency-rejected transaction changed canonical state")
	}
}

func TestFilterEVMProposalTransactionsRestoresBlockOutputBudget(t *testing.T) {
	for _, dimension := range []string{"logs", "receipts"} {
		t.Run(dimension, func(t *testing.T) {
			config := evmMVCTestConfig()
			base := newModernTestState(t)
			contract := common.HexToAddress("0xf003")
			// Store persistent state and emit a log before output metering.
			logSize := byte(64)
			if dimension == "receipts" {
				logSize = 0
			}
			base.SetCode(contract, []byte{0x60, 0x01, 0x60, 0x00, 0x55, 0x60, logSize, 0x60, 0x00, 0xa0, 0x00})
			base.SetNonce(contract, 1)
			first, _ := signedEVMFilteringTransaction(t, config, base, contract, 100_000, nil)
			overflow, overflowSender := signedEVMFilteringTransaction(t, config, base, contract, 100_000, nil)
			good, _ := signedEVMFilteringTransaction(t, config, base, common.HexToAddress("0xf004"), params.TxGas, nil)
			header := &types.Header{ParentHash: common.HexToHash("0xf005"), Coinbase: common.HexToAddress("0xf006"), Number: big.NewInt(1), Difficulty: big.NewInt(1), GasLimit: first.Gas() + overflow.Gas() + good.Gas(), Time: 1, BaseFee: big.NewInt(params.FixedBaseFeePerGas)}
			prepareEVMOnlyHistory(base, header)
			base.Finalise(true)
			engine := colossusX.NewFaker()
			defer engine.Close()
			chain := &BlockChain{chainConfig: config, engine: engine}
			reference := base.Copy()
			wantReceipts, _, _, err := ExecuteEVMProposalTransactions(config, chain, header, types.Transactions{first, good}, reference, vm.Config{})
			if err != nil {
				t.Fatal(err)
			}
			if dimension == "logs" {
				measured, err := measureExecutionOutput(wantReceipts[0])
				if err != nil {
					t.Fatal(err)
				}
				config.NativeParallel.MaxLogBytesPerTransaction = measured.logRetained
				config.NativeParallel.MaxLogBytesPerBlock = measured.logRetained
			} else {
				var content uint64
				for _, receipt := range wantReceipts {
					measured, err := measureExecutionOutput(receipt)
					if err != nil {
						t.Fatal(err)
					}
					content += measured.receiptEntry
				}
				config.NativeParallel.MaxReceiptBytesPerBlock = rlpListSizeChecked(content)
				config.NativeParallel.MaxLogBytesPerTransaction = config.NativeParallel.MaxReceiptBytesPerBlock
				config.NativeParallel.MaxLogBytesPerBlock = config.NativeParallel.MaxReceiptBytesPerBlock
			}
			if err := config.NativeParallel.Validate(); err != nil {
				t.Fatalf("output filtering config: %v", err)
			}
			filteredState := base.Copy()
			selected, rejected, err := FilterEVMProposalTransactions(config, chain, header, types.Transactions{first, overflow, good}, filteredState, vm.Config{})
			if err != nil {
				t.Fatal(err)
			}
			if len(selected) != 2 || selected[0].Hash() != first.Hash() || selected[1].Hash() != good.Hash() || len(rejected) != 1 || rejected[0].TransactionIndex != 1 {
				t.Fatalf("%s filtering selected=%v rejected=%v, want prefix and independent suffix", dimension, selected, rejected)
			}
			wantDimension := "log bytes"
			if dimension == "receipts" {
				wantDimension = "receipt bytes"
			}
			if !strings.Contains(rejected[0].Err.Error(), wantDimension) {
				t.Fatalf("output rejection = %v, want %s", rejected[0], wantDimension)
			}
			if filteredState.GetNonce(overflowSender) != 0 || len(filteredState.GetLogs(overflow.Hash())) != 0 || filteredState.GetBalance(overflowSender).Cmp(base.GetBalance(overflowSender)) != 0 {
				t.Fatal("block-output rejection leaked nonce, logs or fee debit")
			}
			if filteredState.IntermediateRoot(true) != reference.IntermediateRoot(true) {
				t.Fatal("block-output rejection leaked persistent state")
			}
			if _, _, _, err := ExecuteEVMProposalTransactions(config, chain, header, selected, base.Copy(), vm.Config{}); err != nil {
				t.Fatalf("selected body exceeds canonical output budget: %v", err)
			}
		})
	}
}

func TestFilterEVMProposalTransactionsSkipsRejectedSenderNonceSuffix(t *testing.T) {
	config := evmMVCTestConfig()
	base := newModernTestState(t)
	block, txs := evmMVCCTestBlock(t, config, base, true, 3)
	good, _ := signedEVMFilteringTransaction(t, config, base, common.HexToAddress("0xf007"), params.TxGas, nil)
	txs = append(txs, good)
	header := block.Header()
	header.GasLimit += good.Gas()
	prepareEVMOnlyHistory(base, header)
	base.Finalise(true)
	config.NativeParallel.MaxComputePerTransaction = params.TxGas
	engine := colossusX.NewFaker()
	defer engine.Close()
	chain := &BlockChain{chainConfig: config, engine: engine}
	counter := &evmProposalExecutionCounter{StructLogger: vm.NewStructLogger(nil)}
	selected, rejected, err := FilterEVMProposalTransactions(config, chain, header, txs, base, vm.Config{Debug: true, Tracer: counter})
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 1 || selected[0].Hash() != good.Hash() || len(rejected) != 1 || counter.starts != 2 {
		t.Fatalf("nonce suffix filtering selected=%v rejected=%v executions=%d, want independent TX/one rejection/two executions", selected, rejected, counter.starts)
	}
	sender, err := types.Sender(types.LatestSignerForChainID(config.ChainID), txs[0])
	if err != nil {
		t.Fatal(err)
	}
	if base.GetNonce(sender) != 0 {
		t.Fatal("rejected sender nonce suffix changed state")
	}
}

type evmProposalCodeReadFailure struct {
	state.Database
	cause error
}

func (d *evmProposalCodeReadFailure) ContractCode(common.Hash, common.Hash) ([]byte, error) {
	return nil, d.cause
}

func TestFilterEVMProposalTransactionsAbortsOnStateReadFailure(t *testing.T) {
	config := evmMVCTestConfig()
	base := newModernTestState(t)
	block, txs := evmMVCCTestBlock(t, config, base, false, 1)
	prepareEVMOnlyHistory(base, block.Header())
	root, err := base.Commit(true)
	if err != nil {
		t.Fatal(err)
	}
	readFailure := errors.New("injected proposal code read failure")
	broken, err := state.New(root, &evmProposalCodeReadFailure{Database: base.Database(), cause: readFailure}, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine := colossusX.NewFaker()
	defer engine.Close()
	chain := &BlockChain{chainConfig: config, engine: engine}
	selected, rejected, err := FilterEVMProposalTransactions(config, chain, block.Header(), txs, broken, vm.Config{})
	var infrastructure *EVMExecutionInfrastructureError
	if !errors.As(err, &infrastructure) || !strings.Contains(err.Error(), readFailure.Error()) || len(selected) != 0 || len(rejected) != 0 {
		t.Fatalf("state read failure selected=%v rejected=%v err=%v, want infrastructure abort", selected, rejected, err)
	}
}
