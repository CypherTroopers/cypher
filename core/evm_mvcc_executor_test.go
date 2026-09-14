package core

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus/colossusX"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/params"
)

func evmMVCTestConfig() *params.ChainConfig {
	config := stateProcessorOsakaTestConfig()
	config.NativeParallel = params.SolanaScaleNativeParallelConfig()
	config.NativeParallel.RequireNativeTransactions = false
	return config
}

func evmMVCCStorageCallData(slot, value uint64) []byte {
	data := make([]byte, 64)
	new(big.Int).SetUint64(slot).FillBytes(data[:32])
	new(big.Int).SetUint64(value).FillBytes(data[32:])
	return data
}

func evmMVCCTestBlock(t *testing.T, config *params.ChainConfig, base *state.StateDB, sameSender bool, count int) (*types.Block, types.Transactions) {
	t.Helper()
	contract := common.HexToAddress("0x8000000000000000000000000000000000000080")
	// CALLDATALOAD(32), CALLDATALOAD(0), SSTORE, STOP. Different calldata
	// keys exercise slot-granular conflict detection inside one contract.
	base.SetCode(contract, []byte{0x60, 0x20, 0x35, 0x60, 0x00, 0x35, 0x55, 0x00})
	base.SetNonce(contract, 1)

	// Use concrete ECDSA keys below. The intentionally small helper keeps the
	// transaction construction identical for independent and nonce-chain cases.
	var senderKey = func() *ecdsa.PrivateKey {
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		return key
	}()

	txs := make(types.Transactions, count)
	signer := types.LatestSignerForChainID(config.ChainID)
	for index := range txs {
		key := senderKey
		nonce := uint64(index)
		if !sameSender {
			key = func() *ecdsa.PrivateKey {
				generated, err := crypto.GenerateKey()
				if err != nil {
					t.Fatal(err)
				}
				return generated
			}()
			nonce = 0
		}
		from := crypto.PubkeyToAddress(key.PublicKey)
		base.SetBalance(from, new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil))
		unsigned := types.NewTx(&types.DynamicFeeTx{
			ChainID:   config.ChainID,
			Nonce:     nonce,
			GasTipCap: big.NewInt(2),
			GasFeeCap: new(big.Int).Add(
				big.NewInt(params.FixedBaseFeePerGas), big.NewInt(2),
			),
			Gas:   100_000,
			To:    &contract,
			Value: new(big.Int),
			Data:  evmMVCCStorageCallData(uint64(index+1), uint64(index+100)),
		})
		signed, err := types.SignTx(unsigned, signer, key)
		if err != nil {
			t.Fatal(err)
		}
		txs[index] = signed
	}
	base.Finalise(true)
	header := &types.Header{
		ParentHash: common.HexToHash("0xabc1"),
		Coinbase:   common.HexToAddress("0x9000000000000000000000000000000000000009"),
		Number:     big.NewInt(1),
		Difficulty: big.NewInt(1),
		GasLimit:   uint64(count) * 100_000,
		Time:       1,
		BaseFee:    big.NewInt(params.FixedBaseFeePerGas),
	}
	return types.NewBlockWithHeader(header).WithBody(txs, nil), txs
}

func compareEVMOptimisticWithSerial(t *testing.T, sameSender bool, count int) {
	t.Helper()
	config := evmMVCTestConfig()
	base := newModernTestState(t)
	block, txs := evmMVCCTestBlock(t, config, base, sameSender, count)
	engine := colossusX.NewFaker()
	defer engine.Close()
	chain := &BlockChain{chainConfig: config, engine: engine}
	processor := NewStateProcessor(config, chain, engine)

	parallelState := base.Copy()
	parallelGas := new(GasPool).AddGas(block.GasLimit())
	var parallelUsed uint64
	parallelReceipts := make(types.Receipts, 0, len(txs))
	err := processor.processEVMOptimistic(block, parallelState, parallelGas, &parallelUsed, vm.Config{}, func(_ int, _ *types.Transaction, receipt *types.Receipt) error {
		parallelReceipts = append(parallelReceipts, receipt)
		return nil
	})
	if err != nil {
		t.Fatalf("optimistic execution: %v", err)
	}

	serialState := base.Copy()
	serialGas := new(GasPool).AddGas(block.GasLimit())
	var serialUsed uint64
	serialReceipts := make(types.Receipts, 0, len(txs))
	for index, tx := range txs {
		serialState.Prepare(tx.Hash(), block.Hash(), index)
		receipt, err := ApplyTransaction(config, chain, nil, serialGas, serialState, block.Header(), tx, &serialUsed, vm.Config{})
		if err != nil {
			t.Fatalf("serial transaction %d: %v", index, err)
		}
		serialReceipts = append(serialReceipts, receipt)
	}
	parallelRoot := parallelState.IntermediateRoot(true)
	serialRoot := serialState.IntermediateRoot(true)
	if parallelRoot != serialRoot || parallelUsed != serialUsed || parallelGas.Gas() != serialGas.Gas() || !reflect.DeepEqual(parallelReceipts, serialReceipts) {
		t.Fatalf("optimistic/serial mismatch: root=%s/%s gas=%d/%d remaining=%d/%d receiptsEqual=%t",
			parallelRoot, serialRoot, parallelUsed, serialUsed, parallelGas.Gas(), serialGas.Gas(), reflect.DeepEqual(parallelReceipts, serialReceipts))
	}
}

func TestEVMOptimisticMVCCMatchesSerialForIndependentContractSlots(t *testing.T) {
	compareEVMOptimisticWithSerial(t, false, 16)
}

func TestEVMOptimisticMVCCReexecutesNonceDependencies(t *testing.T) {
	// Transactions after index zero initially observe the old sender nonce and
	// fail speculatively. The sender write from the preceding canonical result
	// makes those failures stale, so each is re-executed and must match serial.
	compareEVMOptimisticWithSerial(t, true, 16)
}

func TestEVMOptimisticMVCCMatchesSerialAcrossMemoryWindows(t *testing.T) {
	compareEVMOptimisticWithSerial(t, false, 130)
}

func TestEVMOptimisticMVCCMatchesSerialForEnvelopeTypesZeroThroughFour(t *testing.T) {
	config := evmMVCTestConfig()
	base := newModernTestState(t)
	signer := types.LatestSignerForChainID(config.ChainID)
	txs := make(types.Transactions, 0, 5)
	gasLimit := uint64(0)
	for txType := uint8(types.LegacyTxType); txType <= types.SetCodeTxType; txType++ {
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		sender := crypto.PubkeyToAddress(key.PublicKey)
		base.SetBalance(sender, new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil))
		to := common.BigToAddress(new(big.Int).SetUint64(uint64(0x9000) + uint64(txType)))
		gas := uint64(params.TxGas)
		var unsigned *types.Transaction
		switch txType {
		case types.LegacyTxType:
			unsigned = types.NewTransaction(0, to, big.NewInt(int64(txType+1)), gas, big.NewInt(params.FixedTransferGasPricePerGas), nil)
		case types.AccessListTxType:
			unsigned = types.NewTx(&types.AccessListTx{
				ChainID: config.ChainID, GasPrice: big.NewInt(params.FixedTransferGasPricePerGas), Gas: gas,
				To: &to, Value: big.NewInt(int64(txType + 1)),
			})
		case types.DynamicFeeTxType:
			unsigned = types.NewTx(&types.DynamicFeeTx{
				ChainID: config.ChainID, GasTipCap: big.NewInt(2), GasFeeCap: new(big.Int).Add(big.NewInt(params.FixedBaseFeePerGas), big.NewInt(2)), Gas: gas,
				To: &to, Value: big.NewInt(int64(txType + 1)),
			})
		case types.BlobTxType:
			var blobHash common.Hash
			blobHash[0] = types.BlobCommitmentVersionKZG
			blobHash[len(blobHash)-1] = 1
			unsigned = types.NewTx(&types.BlobTx{
				ChainID: config.ChainID, GasTipCap: big.NewInt(2), GasFeeCap: new(big.Int).Add(big.NewInt(params.FixedBaseFeePerGas), big.NewInt(2)), Gas: gas,
				To: to, Value: big.NewInt(int64(txType + 1)), BlobFeeCap: big.NewInt(2), BlobHashes: []common.Hash{blobHash},
			})
		case types.SetCodeTxType:
			gas = 100_000
			authorityKey, err := crypto.GenerateKey()
			if err != nil {
				t.Fatal(err)
			}
			authorization, err := types.SignSetCode(authorityKey, types.SetCodeAuthorization{
				ChainID: config.ChainID,
				Address: common.HexToAddress("0x7702000000000000000000000000000000000001"),
			})
			if err != nil {
				t.Fatal(err)
			}
			unsigned = types.NewTx(&types.SetCodeTx{
				ChainID: config.ChainID, GasTipCap: big.NewInt(2), GasFeeCap: new(big.Int).Add(big.NewInt(params.FixedBaseFeePerGas), big.NewInt(2)), Gas: gas,
				To: to, Value: big.NewInt(int64(txType + 1)), AuthList: []types.SetCodeAuthorization{authorization},
			})
		}
		signed, err := types.SignTx(unsigned, signer, key)
		if err != nil {
			t.Fatal(err)
		}
		txs = append(txs, signed)
		gasLimit += gas
	}
	base.Finalise(true)
	header := &types.Header{
		ParentHash: common.HexToHash("0xabc5"), Coinbase: common.HexToAddress("0x9000000000000000000000000000000000000009"),
		Number: big.NewInt(1), Difficulty: big.NewInt(1), GasLimit: gasLimit, Time: 1,
		BaseFee: big.NewInt(params.FixedBaseFeePerGas), BlobGasUsed: params.BlobTxBlobGasPerBlob,
	}
	block := types.NewBlockWithHeader(header).WithBody(txs, nil)
	engine := colossusX.NewFaker()
	defer engine.Close()
	chain := &BlockChain{chainConfig: config, engine: engine}
	processor := NewStateProcessor(config, chain, engine)

	parallelState := base.Copy()
	parallelGas := new(GasPool).AddGas(block.GasLimit())
	var parallelUsed uint64
	parallelReceipts := make(types.Receipts, 0, len(txs))
	if err := processor.processEVMOptimistic(block, parallelState, parallelGas, &parallelUsed, vm.Config{}, func(_ int, _ *types.Transaction, receipt *types.Receipt) error {
		parallelReceipts = append(parallelReceipts, receipt)
		return nil
	}); err != nil {
		t.Fatalf("optimistic mixed-envelope execution: %v", err)
	}

	serialState := base.Copy()
	serialGas := new(GasPool).AddGas(block.GasLimit())
	var serialUsed uint64
	serialReceipts := make(types.Receipts, 0, len(txs))
	for index, tx := range txs {
		serialState.Prepare(tx.Hash(), block.Hash(), index)
		receipt, err := ApplyTransaction(config, chain, nil, serialGas, serialState, header, tx, &serialUsed, vm.Config{})
		if err != nil {
			t.Fatalf("serial mixed-envelope transaction %d/type %d: %v", index, tx.Type(), err)
		}
		serialReceipts = append(serialReceipts, receipt)
	}
	parallelRoot := parallelState.IntermediateRoot(true)
	serialRoot := serialState.IntermediateRoot(true)
	if parallelRoot != serialRoot || parallelUsed != serialUsed || parallelGas.Gas() != serialGas.Gas() || !reflect.DeepEqual(parallelReceipts, serialReceipts) {
		t.Fatalf("mixed-envelope optimistic/serial mismatch: root=%s/%s gas=%d/%d remaining=%d/%d receiptsEqual=%t",
			parallelRoot, serialRoot, parallelUsed, serialUsed, parallelGas.Gas(), serialGas.Gas(), reflect.DeepEqual(parallelReceipts, serialReceipts))
	}
	for index, receipt := range parallelReceipts {
		if receipt.Type != uint8(index) {
			t.Fatalf("receipt %d type = %d, want %d", index, receipt.Type, index)
		}
	}
}

func TestEVMOptimisticMVCCDiscardsRevertedAccountWrites(t *testing.T) {
	config := evmMVCTestConfig()
	database := state.NewDatabase(rawdb.NewMemoryDatabase())
	initial, err := state.New(common.Hash{}, database, nil)
	if err != nil {
		t.Fatal(err)
	}
	emptyAccount := common.HexToAddress("0x7000000000000000000000000000000000000007")
	contract := common.HexToAddress("0x8000000000000000000000000000000000000008")
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sender := crypto.PubkeyToAddress(key.PublicKey)
	initial.CreateAccount(emptyAccount)
	initial.SetCode(contract, revertedStaticCallCode(emptyAccount))
	initial.SetNonce(contract, 1)
	initial.SetBalance(sender, new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil))
	root, err := initial.Commit(false)
	if err != nil {
		t.Fatal(err)
	}
	base, err := state.New(root, database, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !base.Exist(emptyAccount) || !base.Empty(emptyAccount) {
		t.Fatal("test fixture did not retain the committed empty account")
	}

	unsigned := types.NewTx(&types.DynamicFeeTx{
		ChainID:   config.ChainID,
		Nonce:     0,
		GasTipCap: big.NewInt(2),
		GasFeeCap: new(big.Int).Add(big.NewInt(params.FixedBaseFeePerGas), big.NewInt(2)),
		Gas:       100_000,
		To:        &contract,
		Value:     new(big.Int),
	})
	tx, err := types.SignTx(unsigned, types.LatestSignerForChainID(config.ChainID), key)
	if err != nil {
		t.Fatal(err)
	}
	header := &types.Header{
		ParentHash: common.HexToHash("0xabc2"),
		Coinbase:   common.HexToAddress("0x9000000000000000000000000000000000000009"),
		Number:     big.NewInt(1),
		Difficulty: big.NewInt(1),
		GasLimit:   tx.Gas(),
		Time:       1,
		BaseFee:    big.NewInt(params.FixedBaseFeePerGas),
	}
	block := types.NewBlockWithHeader(header).WithBody(types.Transactions{tx}, nil)
	engine := colossusX.NewFaker()
	defer engine.Close()
	chain := &BlockChain{chainConfig: config, engine: engine}
	processor := NewStateProcessor(config, chain, engine)

	parallelState := base.Copy()
	parallelGas := new(GasPool).AddGas(block.GasLimit())
	var parallelUsed uint64
	var parallelReceipt *types.Receipt
	err = processor.processEVMOptimistic(block, parallelState, parallelGas, &parallelUsed, vm.Config{}, func(_ int, _ *types.Transaction, receipt *types.Receipt) error {
		parallelReceipt = receipt
		return nil
	})
	if err != nil {
		t.Fatalf("optimistic execution: %v", err)
	}

	serialState := base.Copy()
	serialGas := new(GasPool).AddGas(block.GasLimit())
	var serialUsed uint64
	serialState.Prepare(tx.Hash(), block.Hash(), 0)
	serialReceipt, err := ApplyTransaction(config, chain, nil, serialGas, serialState, header, tx, &serialUsed, vm.Config{})
	if err != nil {
		t.Fatalf("serial execution: %v", err)
	}
	parallelRoot := parallelState.IntermediateRoot(true)
	serialRoot := serialState.IntermediateRoot(true)
	if parallelRoot != serialRoot || parallelState.Exist(emptyAccount) != serialState.Exist(emptyAccount) || !reflect.DeepEqual(parallelReceipt, serialReceipt) {
		t.Fatalf("reverted write changed optimistic state: root=%s/%s emptyExists=%t/%t receiptsEqual=%t",
			parallelRoot, serialRoot, parallelState.Exist(emptyAccount), serialState.Exist(emptyAccount), reflect.DeepEqual(parallelReceipt, serialReceipt))
	}
}

func revertedStaticCallCode(target common.Address) []byte {
	// STATICCALL(target), discard its success flag, then REVERT the outer call.
	code := []byte{0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x73}
	code = append(code, target[:]...)
	return append(code, 0x61, 0xff, 0xff, 0xfa, 0x50, 0x60, 0x00, 0x60, 0x00, 0xfd)
}

func TestEVMMVCCRecorderRevertRestoresWritesButRetainsObservedWork(t *testing.T) {
	statedb := newModernTestState(t)
	persistent := common.HexToAddress("0x11")
	reverted := common.HexToAddress("0x12")
	readOnly := common.HexToAddress("0x13")
	overLimit := common.HexToAddress("0x14")
	recorder := newEVMMVCCRecorder(statedb)
	recorder.setAccessLimit(3)

	recorder.SetNonce(persistent, 1)
	snapshot := recorder.Snapshot()
	recorder.SetNonce(reverted, 1)
	recorder.GetBalance(readOnly)
	recorder.RevertToSnapshot(snapshot)

	account := func(address common.Address) evmMVCCResource {
		return evmMVCCResource{kind: evmMVCCAccountResource, address: address}
	}
	if _, exists := recorder.writes[account(persistent)]; !exists {
		t.Fatal("write made before the snapshot was discarded")
	}
	if _, exists := recorder.writes[account(reverted)]; exists {
		t.Fatal("reverted write remained publishable")
	}
	if _, exists := recorder.reads[account(reverted)]; !exists {
		t.Fatal("reverted write did not retain a conservative dependency")
	}
	if _, exists := recorder.reads[account(readOnly)]; !exists {
		t.Fatal("reverted execution read was discarded")
	}
	if got := len(recorder.seen); got != 3 {
		t.Fatalf("observed work after revert = %d, want 3", got)
	}
	if statedb.Exist(reverted) {
		t.Fatal("underlying StateDB write was not reverted")
	}
	recorder.GetNonce(overLimit)
	if !errors.Is(recorder.Error(), ErrEVMRuntimeAccessLimitExceeded) {
		t.Fatalf("access error = %v, want %v", recorder.Error(), ErrEVMRuntimeAccessLimitExceeded)
	}
}

func TestEVMMVCCRecorderClassifiesZeroBalanceTouches(t *testing.T) {
	statedb := newModernTestState(t)
	nonEmpty := common.HexToAddress("0x15")
	empty := common.HexToAddress("0x16")
	missing := common.HexToAddress("0x17")
	statedb.SetNonce(nonEmpty, 1)
	statedb.CreateAccount(empty)
	recorder := newEVMMVCCRecorder(statedb)
	recorder.AddBalance(nonEmpty, new(big.Int))
	recorder.AddBalance(empty, new(big.Int))
	recorder.AddBalance(missing, new(big.Int))
	recorder.SubBalance(common.HexToAddress("0x18"), new(big.Int))

	resource := func(address common.Address) evmMVCCResource {
		return evmMVCCResource{kind: evmMVCCAccountResource, address: address}
	}
	if _, write := recorder.writes[resource(nonEmpty)]; write {
		t.Fatal("zero balance add made a non-empty contract a whole-account writer")
	}
	if _, read := recorder.reads[resource(nonEmpty)]; !read {
		t.Fatal("zero balance add did not observe the non-empty account")
	}
	if _, write := recorder.writes[resource(empty)]; !write {
		t.Fatal("EIP-161 empty-account touch was not recorded as a write")
	}
	if _, write := recorder.writes[resource(missing)]; write {
		t.Fatal("ephemeral zero touch of a missing account was recorded as persistent")
	}
	if got := len(recorder.seen); got != 3 {
		t.Fatalf("zero balance access count = %d, want 3", got)
	}
}

func TestEVMRuntimeDependencyMeterBoundsCanonicalChains(t *testing.T) {
	config := evmMVCTestConfig()
	config.NativeParallel.MaxComputePerTransaction = 100
	config.NativeParallel.MaxComputePerBlock = 1_000
	config.NativeParallel.MaxCriticalPathCompute = 1_000
	config.NativeParallel.MaxDependencyDepth = 2
	contract := common.HexToAddress("0x21")
	slot := common.HexToHash("0x01")
	storage := evmMVCCResource{kind: evmMVCCStorageResource, address: contract, slot: slot}
	write := evmMVCCAccessSet{writes: map[evmMVCCResource]struct{}{storage: {}}}

	meter := newEVMRuntimeDependencyMeter(config)
	if err := meter.Add(0, common.HexToAddress("0x31"), write, 10); err != nil {
		t.Fatal(err)
	}
	if err := meter.Add(1, common.HexToAddress("0x32"), write, 10); err != nil {
		t.Fatal(err)
	}
	err := meter.Add(2, common.HexToAddress("0x33"), write, 10)
	var limitError *EVMRuntimeWorkLimitError
	if !errors.As(err, &limitError) || limitError.TransactionIndex != 2 || limitError.Dimension != "dependency depth" || limitError.Observed != 3 {
		t.Fatalf("depth error = %#v, want transaction 2 depth 3", err)
	}

	// A reverted write is represented as a read: it depends on the prior writer
	// but does not become a new writer frontier for the following transaction.
	meter = newEVMRuntimeDependencyMeter(config)
	if err := meter.Add(0, common.HexToAddress("0x41"), write, 10); err != nil {
		t.Fatal(err)
	}
	revertedWrite := evmMVCCAccessSet{reads: map[evmMVCCResource]struct{}{storage: {}}}
	if err := meter.Add(1, common.HexToAddress("0x42"), revertedWrite, 10); err != nil {
		t.Fatal(err)
	}
	if err := meter.Add(2, common.HexToAddress("0x43"), revertedWrite, 10); err != nil {
		t.Fatalf("reverted write extended the writer chain: %v", err)
	}

	// Disjoint resources remain at depth one, while the explicit sender frontier
	// serializes same-sender nonce/fee updates even if a recorder were incomplete.
	config.NativeParallel.MaxCriticalPathCompute = 10
	meter = newEVMRuntimeDependencyMeter(config)
	otherSlot := evmMVCCResource{kind: evmMVCCStorageResource, address: contract, slot: common.HexToHash("0x02")}
	if err := meter.Add(0, common.HexToAddress("0x51"), write, 10); err != nil {
		t.Fatal(err)
	}
	if err := meter.Add(1, common.HexToAddress("0x52"), evmMVCCAccessSet{writes: map[evmMVCCResource]struct{}{otherSlot: {}}}, 10); err != nil {
		t.Fatalf("disjoint slot inherited a critical path: %v", err)
	}
	meter = newEVMRuntimeDependencyMeter(config)
	sender := common.HexToAddress("0x53")
	if err := meter.Add(0, sender, evmMVCCAccessSet{}, 10); err != nil {
		t.Fatal(err)
	}
	err = meter.Add(1, sender, evmMVCCAccessSet{}, 10)
	if !errors.As(err, &limitError) || limitError.Dimension != "critical path compute" || limitError.Observed != 20 {
		t.Fatalf("sender critical-path error = %#v, want compute 20", err)
	}
}

func TestEVMRuntimeMetersRejectArithmeticOverflow(t *testing.T) {
	config := evmMVCTestConfig()
	config.NativeParallel.MaxComputePerTransaction = ^uint64(0)
	config.NativeParallel.MaxComputePerBlock = ^uint64(0)
	config.NativeParallel.MaxCriticalPathCompute = ^uint64(0)
	config.NativeParallel.MaxDependencyDepth = ^uint64(0)
	sender := common.HexToAddress("0x61")

	blockMeter := newEVMRuntimeDependencyMeter(config)
	blockMeter.totalCompute = ^uint64(0) - 5
	err := blockMeter.Add(4, sender, evmMVCCAccessSet{}, 10)
	var limitError *EVMRuntimeWorkLimitError
	if !errors.As(err, &limitError) || limitError.Dimension != "block compute" || limitError.Observed != ^uint64(0) {
		t.Fatalf("block compute overflow error = %#v", err)
	}

	pathMeter := newEVMRuntimeDependencyMeter(config)
	pathMeter.frontiers.accounts[sender] = evmRuntimePath{depth: 1, finish: ^uint64(0) - 5}
	err = pathMeter.Add(5, sender, evmMVCCAccessSet{}, 10)
	if !errors.As(err, &limitError) || limitError.Dimension != "critical path compute" || limitError.Observed != ^uint64(0) {
		t.Fatalf("critical path overflow error = %#v", err)
	}

	accessMeter := &evmRuntimeAccessMeter{maxPerTransaction: ^uint64(0), maxPerBlock: ^uint64(0), total: ^uint64(0) - 1}
	first := evmMVCCResource{kind: evmMVCCAccountResource, address: common.HexToAddress("0x62")}
	second := evmMVCCResource{kind: evmMVCCAccountResource, address: common.HexToAddress("0x63")}
	err = accessMeter.Add(6, evmMVCCAccessSet{reads: map[evmMVCCResource]struct{}{first: {}, second: {}}})
	if !errors.As(err, &limitError) || limitError.Dimension != "block runtime accesses" || limitError.Observed != ^uint64(0) {
		t.Fatalf("block access overflow error = %#v", err)
	}
}

func TestEVMOptimisticMVCCChargesCanonicalDependencyOnce(t *testing.T) {
	run := func(limit uint64) error {
		config := evmMVCTestConfig()
		config.NativeParallel.MaxDependencyDepth = limit
		base := newModernTestState(t)
		block, _ := evmMVCCTestBlock(t, config, base, true, 16)
		engine := colossusX.NewFaker()
		defer engine.Close()
		chain := &BlockChain{chainConfig: config, engine: engine}
		processor := NewStateProcessor(config, chain, engine)
		statedb := base.Copy()
		gasPool := new(GasPool).AddGas(block.GasLimit())
		var usedGas uint64
		return processor.processEVMOptimistic(block, statedb, gasPool, &usedGas, vm.Config{}, func(int, *types.Transaction, *types.Receipt) error { return nil })
	}
	if err := run(16); err != nil {
		t.Fatalf("exact canonical dependency boundary rejected: %v", err)
	}
	err := run(15)
	var executionError *EVMTransactionExecutionError
	var limitError *EVMRuntimeWorkLimitError
	if !errors.As(err, &executionError) || !errors.As(err, &limitError) {
		t.Fatalf("dependency limit did not retain typed causes: %v", err)
	}
	if executionError.TransactionIndex != 15 || limitError.TransactionIndex != 15 || limitError.Dimension != "dependency depth" || limitError.Observed != 16 {
		t.Fatalf("dependency limit error = %#v / %#v, want transaction 15 depth 16", executionError, limitError)
	}
}

func TestEVMRuntimeMemorySchedulingUsesNestedGasBound(t *testing.T) {
	configured := uint64(64 * 1024 * 1024)
	logical := evmGasBoundedLogicalMemory(params.MaxTxGas, configured, true)
	// A single-frame inversion is about 3 MiB, but nested calls can keep many
	// separately metered memories live. The scheduler must not use that unsafe
	// single-frame estimate for its process-wide reservation.
	if logical <= 3*1024*1024 {
		t.Fatalf("nested logical memory bound = %d, want more than single-frame 3 MiB", logical)
	}
	if logical > configured {
		t.Fatalf("nested logical memory bound = %d, exceeds configured limit %d", logical, configured)
	}
	if preEIP150 := evmGasBoundedLogicalMemory(params.MaxTxGas, configured, false); preEIP150 < logical || preEIP150 > configured {
		t.Fatalf("pre-EIP-150 memory bound = %d, want range [%d,%d]", preEIP150, logical, configured)
	}
	if got := evmGasBoundedLogicalMemory(0, configured, true); got != 0 {
		t.Fatalf("zero-gas memory bound = %d, want 0", got)
	}
}

func TestEVMRuntimeMemoryBatchesStayWithinProcessLease(t *testing.T) {
	config := evmMVCTestConfig()
	header := &types.Header{Number: big.NewInt(1)}
	makeTx := func(gas uint64) *types.Transaction {
		to := common.HexToAddress("0x81")
		return types.NewTransaction(0, to, new(big.Int), gas, big.NewInt(1), nil)
	}
	lowWeight := evmRuntimeTransactionMemoryWeight(config, header, makeTx(params.TxGas))
	highWeight := evmRuntimeTransactionMemoryWeight(config, header, makeTx(params.MaxTxGas))
	if lowWeight == 0 || lowWeight >= highWeight || highWeight > nativeExecutionMemoryBudget {
		t.Fatalf("unexpected EVM weights low=%d high=%d budget=%d", lowWeight, highWeight, nativeExecutionMemoryBudget)
	}
	weights := make([]uint64, evmOptimisticMicroBatch+3)
	for index := range weights {
		if index%2 == 0 {
			weights[index] = highWeight
		} else {
			weights[index] = lowWeight
		}
	}
	for start := 0; start < len(weights); {
		end, reserved := evmOptimisticMemoryBatchEnd(start, weights)
		if end <= start {
			t.Fatalf("memory scheduler did not advance at %d", start)
		}
		if end-start > evmOptimisticMicroBatch || reserved == 0 || reserved > nativeExecutionMemoryBudget {
			t.Fatalf("invalid memory batch [%d,%d) reserve=%d", start, end, reserved)
		}
		var exact uint64
		for _, weight := range weights[start:end] {
			exact += weight
		}
		if exact != reserved {
			t.Fatalf("memory batch [%d,%d) reserve=%d, exact=%d", start, end, reserved, exact)
		}
		start = end
	}

	end, reserved := evmOptimisticMemoryBatchEnd(0, []uint64{nativeExecutionMemoryBudget, 1})
	if end != 1 || reserved != nativeExecutionMemoryBudget {
		t.Fatalf("full-budget transaction batch = [%d] reserve=%d", end, reserved)
	}
}

func TestEVMRuntimeMemoryLeaseReservesPlanningAndResults(t *testing.T) {
	limits := params.SolanaScaleEVMParallelConfig()
	config := &params.ChainConfig{
		NativeParallel: limits,
		EIP150Block:    big.NewInt(0),
		MaxCodeSizeConfig: []params.MaxCodeConfigStruct{{
			Block: big.NewInt(0),
			Size:  128,
		}},
	}
	retained := evmRuntimeRetainedMemoryWeight(config, int(limits.MaxTransactionsPerBlock))
	if retained == 0 || retained >= nativeExecutionMemoryBudget {
		t.Fatalf("retained EVM reserve = %d, budget %d", retained, nativeExecutionMemoryBudget)
	}
	capacity := nativeExecutionMemoryBudget - retained
	to := common.HexToAddress("0x81")
	maxGasTx := types.NewTransaction(0, to, new(big.Int), params.MaxTxGas, big.NewInt(1), nil)
	weight := evmRuntimeTransactionMemoryWeight(config, &types.Header{Number: big.NewInt(1)}, maxGasTx)
	if weight == 0 || weight > capacity {
		t.Fatalf("maximum-gas transaction weight %d does not fit residual batch capacity %d", weight, capacity)
	}
	end, batch := evmOptimisticMemoryBatchEndWithin(0, []uint64{weight, weight}, capacity)
	if end == 0 || batch > capacity || retained+batch > nativeExecutionMemoryBudget {
		t.Fatalf("retained=%d batch=%d end=%d exceeds budget=%d", retained, batch, end, nativeExecutionMemoryBudget)
	}
	if end, batch := evmOptimisticMemoryBatchEndWithin(0, []uint64{capacity + 1}, capacity); end != 0 || batch != 0 {
		t.Fatalf("overweight transaction was scheduled: end=%d batch=%d capacity=%d", end, batch, capacity)
	}
}

func TestEVMTransactionErrorClassifierPreservesInfrastructureAbort(t *testing.T) {
	stateFailure := errors.New("state trie read failed")
	infrastructure := markEVMExecutionInfrastructure(stateFailure)
	classified := evmTransactionExecutionError(7, fmt.Errorf("execute: %w", infrastructure))
	var transactionError *EVMTransactionExecutionError
	var infrastructureError *EVMExecutionInfrastructureError
	if errors.As(classified, &transactionError) {
		t.Fatalf("infrastructure failure was classified as droppable transaction: %v", classified)
	}
	if !errors.As(classified, &infrastructureError) || !errors.Is(classified, stateFailure) {
		t.Fatalf("infrastructure cause was not preserved: %v", classified)
	}

	candidate := evmTransactionExecutionError(7, errors.New("nonce too low"))
	if !errors.As(candidate, &transactionError) || transactionError.TransactionIndex != 7 {
		t.Fatalf("candidate error was not indexed: %v", candidate)
	}
}

func TestEVMMVCCStorageConflictsRemainSlotGranular(t *testing.T) {
	address := common.HexToAddress("0x1234")
	first := evmMVCCAccessSet{writes: map[evmMVCCResource]struct{}{
		{kind: evmMVCCStorageResource, address: address, slot: common.HexToHash("0x01")}: {},
	}}
	index := newEVMMVCCWriteIndex()
	index.add(first)
	independent := evmMVCCAccessSet{
		reads: map[evmMVCCResource]struct{}{
			{kind: evmMVCCAccountResource, address: address}:                                 {},
			{kind: evmMVCCStorageResource, address: address, slot: common.HexToHash("0x02")}: {},
		},
		writes: map[evmMVCCResource]struct{}{
			{kind: evmMVCCStorageResource, address: address, slot: common.HexToHash("0x02")}: {},
		},
	}
	if index.conflicts(independent) {
		t.Fatal("independent storage slots were serialized")
	}
	dependent := evmMVCCAccessSet{reads: map[evmMVCCResource]struct{}{
		{kind: evmMVCCStorageResource, address: address, slot: common.HexToHash("0x01")}: {},
	}}
	if !index.conflicts(dependent) {
		t.Fatal("same-slot dependency was not detected")
	}
}
