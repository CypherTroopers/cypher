package core

import (
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus/colossusX"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/trie"
)

func TestEVMResourceGuardRejectsLogBeforeStateDBRetention(t *testing.T) {
	statedb := newModernTestState(t)
	txHash := common.HexToHash("0xe001")
	statedb.Prepare(txHash, common.Hash{}, 0)
	guard := newEVMResourceGuard(statedb, 128)
	guard.AddLog(&types.Log{Data: make([]byte, 4096)})
	if !errors.Is(guard.Error(), ErrEVMLogLimitExceeded) {
		t.Fatalf("oversized log error = %v, want %v", guard.Error(), ErrEVMLogLimitExceeded)
	}
	if got := len(statedb.GetLogs(txHash)); got != 0 {
		t.Fatalf("oversized EVM log was retained; count=%d", got)
	}
}

func TestEVMOnlyApplyTransactionEnforcesLogLimitAndRollsBack(t *testing.T) {
	config := evmOnlyNativeConfig()
	config.NativeParallel.MaxLogBytesPerTransaction = 128
	contract := common.HexToAddress("0xe002")
	// PUSH2(256), PUSH1(0), LOG0, STOP emits 256 zero bytes.
	code := []byte{byte(vm.PUSH2), 0x01, 0x00, byte(vm.PUSH1), 0x00, byte(vm.LOG0), byte(vm.STOP)}
	unsigned := types.NewTransaction(0, contract, new(big.Int), 100_000, big.NewInt(params.FixedTransferGasPricePerGas), nil)
	tx, sender := signEVMOnlyLegacyTransaction(t, config, "2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", unsigned)
	statedb := newEVMOnlyTestState(t)
	initialBalance := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	statedb.SetBalance(sender, initialBalance)
	statedb.SetCode(contract, code)
	statedb.Finalise(true)
	statedb.Prepare(tx.Hash(), common.Hash{}, 0)
	header := &types.Header{
		Number: big.NewInt(1), Difficulty: big.NewInt(1), GasLimit: tx.Gas(), Time: 1,
		BaseFee: big.NewInt(params.FixedBaseFeePerGas),
	}
	gasPool := new(GasPool).AddGas(header.GasLimit)
	var usedGas uint64
	author := common.Address{}
	if _, err := ApplyTransaction(config, nil, &author, gasPool, statedb, header, tx, &usedGas, vm.Config{}); !errors.Is(err, ErrEVMLogLimitExceeded) {
		t.Fatalf("standard EVM log limit error = %v, want %v", err, ErrEVMLogLimitExceeded)
	}
	if got := len(statedb.GetLogs(tx.Hash())); got != 0 {
		t.Fatalf("rejected standard transaction retained %d logs", got)
	}
	if got := statedb.GetNonce(sender); got != 0 {
		t.Fatalf("rejected standard transaction retained nonce %d", got)
	}
	if got := statedb.GetBalance(sender); got.Cmp(initialBalance) != 0 {
		t.Fatalf("rejected standard transaction retained fee debit: %s", got)
	}
	if gasPool.Gas() != header.GasLimit {
		t.Fatalf("rejected standard transaction gas pool = %d, want %d", gasPool.Gas(), header.GasLimit)
	}
}

func TestBlockExecutionOutputMeterExactBoundaries(t *testing.T) {
	receipt := &types.Receipt{
		Type:   types.DynamicFeeTxType,
		Status: types.ReceiptStatusSuccessful,
		Logs: []*types.Log{{
			Address: common.HexToAddress("0xe003"),
			Topics:  []common.Hash{common.HexToHash("0x01")},
			Data:    []byte("bounded output"),
		}},
	}
	measured, err := measureExecutionOutput(receipt)
	if err != nil {
		t.Fatal(err)
	}
	encodedList, err := rlp.EncodeToBytes(types.Receipts{receipt})
	if err != nil {
		t.Fatal(err)
	}
	if got := rlpListSizeChecked(measured.receiptEntry); got != uint64(len(encodedList)) {
		t.Fatalf("receipt list size = %d, want %d", got, len(encodedList))
	}

	config := evmOnlyNativeConfig()
	config.NativeParallel.MaxLogBytesPerTransaction = measured.logRetained
	config.NativeParallel.MaxLogBytesPerBlock = measured.logRetained
	config.NativeParallel.MaxReceiptBytesPerBlock = uint64(len(encodedList))
	meter := newBlockExecutionOutputMeter(config)
	if err := meter.AddMeasured(0, measured); err != nil {
		t.Fatalf("exact output boundaries rejected: %v", err)
	}
	if err := meter.AddMeasured(1, measured); err == nil || !strings.Contains(err.Error(), "log bytes") {
		t.Fatalf("aggregate log overflow error = %v", err)
	}

	config = evmOnlyNativeConfig()
	config.NativeParallel.MaxLogBytesPerTransaction = measured.logRetained - 1
	if err := newBlockExecutionOutputMeter(config).AddMeasured(0, measured); err == nil || !strings.Contains(err.Error(), "per-transaction") {
		t.Fatalf("per-transaction log overflow error = %v", err)
	}

	config = evmOnlyNativeConfig()
	config.NativeParallel.MaxReceiptBytesPerBlock = uint64(len(encodedList)) - 1
	if err := newBlockExecutionOutputMeter(config).AddMeasured(0, measured); err == nil || !strings.Contains(err.Error(), "receipt bytes") {
		t.Fatalf("outer receipt-list overflow error = %v", err)
	}
}

func TestBlockExecutionOutputMeterChargesRetainedLogObjects(t *testing.T) {
	receipt := &types.Receipt{Status: types.ReceiptStatusSuccessful, Logs: []*types.Log{{}}}
	measured, err := measureExecutionOutput(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if measured.logRetained <= measured.logList {
		t.Fatalf("retained charge %d does not exceed wire charge %d", measured.logRetained, measured.logList)
	}
	config := evmOnlyNativeConfig()
	config.NativeParallel.MaxLogBytesPerTransaction = measured.logRetained
	config.NativeParallel.MaxLogBytesPerBlock = measured.logRetained + measured.logList
	meter := newBlockExecutionOutputMeter(config)
	if err := meter.AddMeasured(0, measured); err != nil {
		t.Fatalf("first retained log charge rejected: %v", err)
	}
	if err := meter.AddMeasured(1, measured); err == nil || !strings.Contains(err.Error(), "retained log bytes") {
		t.Fatalf("retained object aggregate error = %v", err)
	}
}

func TestEVMMVCCRecorderStopsStateReadsAtRuntimeAccessLimit(t *testing.T) {
	statedb := newModernTestState(t)
	address := common.HexToAddress("0xe004")
	firstSlot := common.HexToHash("0x01")
	secondSlot := common.HexToHash("0x02")
	statedb.SetState(address, firstSlot, common.HexToHash("0x11"))
	statedb.SetState(address, secondSlot, common.HexToHash("0x22"))
	recorder := newEVMMVCCRecorder(statedb)
	recorder.setAccessLimit(2) // account plus one exact storage slot
	if got := recorder.GetState(address, firstSlot); got != common.HexToHash("0x11") {
		t.Fatalf("first bounded storage read = %s", got)
	}
	if got := recorder.GetState(address, secondSlot); got != (common.Hash{}) {
		t.Fatalf("over-limit storage read reached StateDB: %s", got)
	}
	if !errors.Is(recorder.Error(), ErrEVMRuntimeAccessLimitExceeded) {
		t.Fatalf("runtime access error = %v, want %v", recorder.Error(), ErrEVMRuntimeAccessLimitExceeded)
	}
	recorder.SetState(address, firstSlot, common.HexToHash("0xff"))
	if got := statedb.GetState(address, firstSlot); got != common.HexToHash("0x11") {
		t.Fatalf("sticky runtime limit allowed a state write: %s", got)
	}
}

func TestEVMRuntimeAccessMeterUsesCanonicalPerTransactionUnion(t *testing.T) {
	config := evmOnlyNativeConfig()
	config.NativeParallel.MaxAccessesPerTransaction = 2
	config.NativeParallel.MaxAccessesPerBlock = 3
	meter := newEVMRuntimeAccessMeter(config)
	account := evmMVCCResource{kind: evmMVCCAccountResource, address: common.HexToAddress("0xe005")}
	storage := evmMVCCResource{kind: evmMVCCStorageResource, address: account.address, slot: common.HexToHash("0x01")}
	access := evmMVCCAccessSet{
		reads:  map[evmMVCCResource]struct{}{account: {}, storage: {}},
		writes: map[evmMVCCResource]struct{}{account: {}}, // read+write is one resource
	}
	if err := meter.Add(0, access); err != nil {
		t.Fatalf("first canonical access set rejected: %v", err)
	}
	err := meter.Add(1, access)
	var limitError *EVMRuntimeWorkLimitError
	if !errors.As(err, &limitError) || limitError.TransactionIndex != 1 || limitError.Dimension != "block runtime accesses" || limitError.Observed != 4 || limitError.Limit != 3 {
		t.Fatalf("aggregate canonical access error = %#v, want transaction 1 accesses 4/3", err)
	}
}

func TestEVMOnlyProcessRejectsCanonicalRuntimeAccessAggregate(t *testing.T) {
	config := evmOnlyNativeConfig()
	config.NativeParallel.MaxAccessesPerTransaction = 3
	config.NativeParallel.MaxAccessesPerBlock = 5
	key := "4123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	firstUnsigned := types.NewTransaction(0, common.HexToAddress("0xe006"), big.NewInt(1), params.TxGas, big.NewInt(params.FixedTransferGasPricePerGas), nil)
	secondUnsigned := types.NewTransaction(1, common.HexToAddress("0xe007"), big.NewInt(1), params.TxGas, big.NewInt(params.FixedTransferGasPricePerGas), nil)
	first, sender := signEVMOnlyLegacyTransaction(t, config, key, firstUnsigned)
	second, _ := signEVMOnlyLegacyTransaction(t, config, key, secondUnsigned)
	statedb := newEVMOnlyTestState(t)
	statedb.SetBalance(sender, new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	header := &types.Header{
		ParentHash: common.HexToHash("0xe008"), Number: big.NewInt(1), Difficulty: big.NewInt(1),
		GasLimit: 2 * params.TxGas, Time: 1, BaseFee: big.NewInt(params.FixedBaseFeePerGas), BlockType: types.FastTx_Block,
	}
	prepareEVMOnlyHistory(statedb, header)
	statedb.Finalise(true)
	block := types.NewBlock(header, types.Transactions{first, second}, nil, nil, new(trie.Trie))
	engine := colossusX.NewFaker()
	defer engine.Close()
	chain := &BlockChain{chainConfig: config, engine: engine}
	_, _, _, err := NewStateProcessor(config, chain, engine).Process(block, statedb, vm.Config{})
	var limitError *EVMRuntimeWorkLimitError
	if !errors.As(err, &limitError) || limitError.TransactionIndex != 1 || limitError.Dimension != "block runtime accesses" || limitError.Observed != 6 || limitError.Limit != 5 {
		t.Fatalf("canonical runtime access aggregate error = %#v, want transaction 1 accesses 6/5", err)
	}
}
