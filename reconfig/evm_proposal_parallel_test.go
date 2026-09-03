package reconfig

import (
	"errors"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus/colossusX"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/params"
)

func evmProposalParallelTestConfig(t *testing.T) *params.ChainConfig {
	t.Helper()
	zeroBlock := big.NewInt(0)
	zeroTime := uint64(0)
	native := params.SolanaScaleNativeParallelConfig()
	native.RequireNativeTransactions = false
	config := &params.ChainConfig{
		ChainID:             big.NewInt(9191),
		FairHotstuff:        true,
		FairHotstuffSeed:    common.HexToHash("0x9191"),
		CommonRPCSigners:    []common.Address{common.HexToAddress("0x9191")},
		HomesteadBlock:      zeroBlock,
		EIP150Block:         zeroBlock,
		EIP155Block:         zeroBlock,
		EIP158Block:         zeroBlock,
		ByzantiumBlock:      zeroBlock,
		ConstantinopleBlock: zeroBlock,
		PetersburgBlock:     zeroBlock,
		IstanbulBlock:       zeroBlock,
		NativeParallel:      native,
	}
	config.SetModernForkConfig(&params.ModernForkConfig{
		BerlinBlock: zeroBlock, LondonBlock: zeroBlock, ShanghaiTime: &zeroTime,
		CancunTime: &zeroTime, PragueTime: &zeroTime, OsakaTime: &zeroTime,
	})
	t.Cleanup(func() { config.SetModernForkConfig(nil) })
	return config
}

func evmProposalParallelState(t *testing.T, parentHash common.Hash) *state.StateDB {
	t.Helper()
	statedb, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	statedb.SetNonce(params.HistoryStorageAddress, 1)
	statedb.SetCode(params.HistoryStorageAddress, params.HistoryStorageCode)
	statedb.SetState(params.HistoryStorageAddress, common.Hash{}, parentHash)
	return statedb
}

func evmProposalParallelChain(t *testing.T, config *params.ChainConfig) *core.BlockChain {
	t.Helper()
	chainConfig := *params.TestChainConfig
	chainConfig.ChainID = new(big.Int).Set(config.ChainID)
	database := rawdb.NewMemoryDatabase()
	genesis := &core.Genesis{Config: &chainConfig, Difficulty: big.NewInt(1), GasLimit: 30_000_000}
	if _, err := genesis.Commit(database); err != nil {
		t.Fatal(err)
	}
	engine := colossusX.NewFaker()
	chain, err := core.NewBlockChain(database, nil, &chainConfig, engine, vm.Config{}, nil, nil, nil)
	if err != nil {
		engine.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		chain.Stop()
		engine.Close()
	})
	return chain
}

func signedEVMProposalTx(t *testing.T, config *params.ChainConfig, keyHex string, nonce, feeCap, tipCap uint64, to common.Address) (*types.Transaction, common.Address) {
	t.Helper()
	key, err := crypto.HexToECDSA(keyHex)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := types.NewTx(&types.DynamicFeeTx{
		ChainID: config.ChainID, Nonce: nonce,
		GasTipCap: new(big.Int).SetUint64(tipCap), GasFeeCap: new(big.Int).SetUint64(feeCap),
		Gas: params.TxGas, To: &to, Value: big.NewInt(1),
	})
	signed, err := types.SignTx(unsigned, types.LatestSignerForChainID(config.ChainID), key)
	if err != nil {
		t.Fatal(err)
	}
	return signed, crypto.PubkeyToAddress(key.PublicKey)
}

func evmProposalParallelWork(config *params.ChainConfig, statedb *state.StateDB, parentHash common.Hash, gasLimit uint64) *work {
	header := &types.Header{
		ParentHash: parentHash, Number: big.NewInt(1), Difficulty: big.NewInt(1),
		GasLimit: gasLimit, Time: 1, BaseFee: big.NewInt(1), BlockType: types.SlowTx_Block,
	}
	return &work{
		config: config, publicState: statedb, header: header,
		maxTxCount: uint64(1024), gasTarget: gasLimit, blockType: types.SlowTx_Block,
		size: header.Size(),
	}
}

func TestEVMProposalMVCCCommitMatchesSerialReference(t *testing.T) {
	config := evmProposalParallelTestConfig(t)
	chain := evmProposalParallelChain(t, config)
	parentHash := common.HexToHash("0x9191")
	base := evmProposalParallelState(t, parentHash)
	to := common.HexToAddress("0x7000000000000000000000000000000000000007")
	keys := []string{
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		"1111111111111111111111111111111111111111111111111111111111111111",
		"2222222222222222222222222222222222222222222222222222222222222222",
	}
	addressTxs := make(map[common.Address]types.Transactions, len(keys))
	for index, key := range keys {
		tx, sender := signedEVMProposalTx(t, config, key, 0, uint64(100-index), 1, to)
		base.SetBalance(sender, new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
		addressTxs[sender] = types.Transactions{tx}
	}
	base.Finalise(true)
	serialState := base.Copy()
	work := evmProposalParallelWork(config, base.Copy(), parentHash, uint64(len(keys))*params.TxGas)
	cursor := types.NewTransactionsByPriceAndNonce(config, work.header.Number, addressTxs)
	committed, receipts, _, failed, err := work.commitTransactions(cursor, chain)
	if err != nil {
		t.Fatalf("parallel proposal commit: %v", err)
	}
	if len(committed) != len(keys) || len(receipts) != len(keys) || len(failed) != 0 {
		t.Fatalf("parallel proposal result: committed=%d receipts=%d failed=%d", len(committed), len(receipts), len(failed))
	}

	if err := core.PrepareNativeBlockHashes(config, work.header, serialState); err != nil {
		t.Fatal(err)
	}
	serialGasPool := new(core.GasPool).AddGas(work.header.GasLimit)
	var serialGas uint64
	for index, tx := range committed {
		serialState.Prepare(tx.Hash(), common.Hash{}, index)
		if _, err := core.ApplyTransaction(config, chain, nil, serialGasPool, serialState, work.header, tx, &serialGas, vm.Config{}); err != nil {
			t.Fatalf("serial transaction %d: %v", index, err)
		}
	}
	parallelRoot := work.publicState.IntermediateRoot(true)
	serialRoot := serialState.IntermediateRoot(true)
	if parallelRoot != serialRoot || work.header.GasUsed != serialGas {
		t.Fatalf("parallel proposal differs from serial: root=%s/%s gas=%d/%d",
			parallelRoot, serialRoot, work.header.GasUsed, serialGas)
	}
}

func TestEVMProposalMVCCRetryRetainsIndependentSenders(t *testing.T) {
	config := evmProposalParallelTestConfig(t)
	chain := evmProposalParallelChain(t, config)
	parentHash := common.HexToHash("0x9292")
	base := evmProposalParallelState(t, parentHash)
	to := common.HexToAddress("0x8000000000000000000000000000000000000008")
	first, firstSender := signedEVMProposalTx(t, config, "3333333333333333333333333333333333333333333333333333333333333333", 0, 30, 1, to)
	// tipCap > feeCap passes the cheap proposal precheck but is rejected by
	// canonical state transition validation, forcing a clean MVCC retry.
	invalid, invalidSender := signedEVMProposalTx(t, config, "4444444444444444444444444444444444444444444444444444444444444444", 0, 40, 41, to)
	last, lastSender := signedEVMProposalTx(t, config, "5555555555555555555555555555555555555555555555555555555555555555", 0, 10, 1, to)
	for _, sender := range []common.Address{firstSender, invalidSender, lastSender} {
		base.SetBalance(sender, new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	}
	base.Finalise(true)
	work := evmProposalParallelWork(config, base, parentHash, 3*params.TxGas)
	cursor := types.NewTransactionsByPriceAndNonce(config, work.header.Number, map[common.Address]types.Transactions{
		firstSender:   {first},
		invalidSender: {invalid},
		lastSender:    {last},
	})
	committed, receipts, _, failed, err := work.commitTransactions(cursor, chain)
	if err != nil {
		t.Fatalf("MVCC retry commit: %v", err)
	}
	if len(committed) != 2 || committed[0].Hash() != first.Hash() || committed[1].Hash() != last.Hash() {
		t.Fatalf("MVCC retry dropped/reordered independent senders: %v", committed)
	}
	if len(receipts) != 2 || len(failed) != 0 {
		t.Fatalf("MVCC retry receipts=%d failed=%d, want 2/0", len(receipts), len(failed))
	}
	if work.publicState.GetNonce(firstSender) != 1 || work.publicState.GetNonce(lastSender) != 1 || work.publicState.GetNonce(invalidSender) != 0 {
		t.Fatalf("MVCC retry nonce state = first:%d invalid:%d last:%d",
			work.publicState.GetNonce(firstSender), work.publicState.GetNonce(invalidSender), work.publicState.GetNonce(lastSender))
	}
}

func TestEVMProposalRuntimeDepthOverflowUsesBoundedValidPrefix(t *testing.T) {
	config := evmProposalParallelTestConfig(t)
	config.NativeParallel.MaxDependencyDepth = 1
	parentHash := common.HexToHash("0x9393")
	base := evmProposalParallelState(t, parentHash)
	chain := evmProposalParallelChain(t, config)
	to := common.HexToAddress("0x9000000000000000000000000000000000000009")
	independentTo := common.HexToAddress("0xa00000000000000000000000000000000000000a")
	invalid, invalidSender := signedEVMProposalTx(t, config, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 0, 40, 41, to)
	first, sender := signedEVMProposalTx(t, config, "6666666666666666666666666666666666666666666666666666666666666666", 0, 30, 1, to)
	dependent, dependentSender := signedEVMProposalTx(t, config, "6666666666666666666666666666666666666666666666666666666666666666", 1, 29, 1, to)
	independent, independentSender := signedEVMProposalTx(t, config, "7777777777777777777777777777777777777777777777777777777777777777", 0, 10, 1, independentTo)
	if dependentSender != sender {
		t.Fatal("nonce chain test transactions recovered different senders")
	}
	for _, account := range []common.Address{invalidSender, sender, independentSender} {
		base.SetBalance(account, new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	}
	base.Finalise(true)
	work := evmProposalParallelWork(config, base, parentHash, 4*params.TxGas)

	// The shared validator/proposer executor identifies the exact canonical
	// transaction crossing the genesis-committed dependency-depth bound.
	_, _, _, executeErr := core.ExecuteEVMProposalTransactions(config, chain, work.header, types.Transactions{first, dependent, independent}, base.Copy(), vm.Config{})
	var txErr *core.EVMTransactionExecutionError
	var workErr *core.EVMRuntimeWorkLimitError
	if !errors.As(executeErr, &txErr) || txErr.TransactionIndex != 1 || !errors.As(executeErr, &workErr) || workErr.Dimension != "dependency depth" {
		t.Fatalf("runtime depth error = %v, want transaction 1 dependency depth", executeErr)
	}

	// The higher-priced invalid sender consumes attempt one. Attempt two reaches
	// the dependency overflow, and the fixed final attempt executes only the
	// already-validated prefix. The independent suffix is postponed, not rescanned.
	cursor := types.NewTransactionsByPriceAndNonce(config, work.header.Number, map[common.Address]types.Transactions{
		invalidSender:     {invalid},
		sender:            {first, dependent},
		independentSender: {independent},
	})
	committed, receipts, _, failed, err := work.commitTransactions(cursor, chain)
	if err != nil {
		t.Fatalf("depth-limited proposal: %v", err)
	}
	if len(committed) != 1 || committed[0].Hash() != first.Hash() {
		t.Fatalf("depth retry selected %v, want the canonical valid prefix", committed)
	}
	if len(receipts) != 1 || len(failed) != 0 {
		t.Fatalf("depth retry receipts=%d failed=%d, want 1/0", len(receipts), len(failed))
	}
	if work.publicState.GetNonce(invalidSender) != 0 || work.publicState.GetNonce(sender) != 1 || work.publicState.GetNonce(independentSender) != 0 {
		t.Fatalf("depth retry nonce state = invalid:%d dependent sender:%d independent:%d",
			work.publicState.GetNonce(invalidSender), work.publicState.GetNonce(sender), work.publicState.GetNonce(independentSender))
	}
}

func TestEVMProposalOutputLimitRetryRevertsPartialStateAndKeepsSmallOutput(t *testing.T) {
	config := evmProposalParallelTestConfig(t)
	// An empty log list costs one RLP byte. A transaction which emits any log
	// crosses this block bound, while the independent plain transfer still fits.
	config.NativeParallel.MaxLogBytesPerTransaction = 1
	config.NativeParallel.MaxLogBytesPerBlock = 1
	if err := config.NativeParallel.Validate(); err != nil {
		t.Fatalf("output-limit test config: %v", err)
	}
	parentHash := common.HexToHash("0x9494")
	base := evmProposalParallelState(t, parentHash)
	chain := evmProposalParallelChain(t, config)
	logContract := common.HexToAddress("0xb00000000000000000000000000000000000000b")
	transferTarget := common.HexToAddress("0xc00000000000000000000000000000000000000c")
	// PUSH1(64), PUSH1(0), LOG0, STOP.
	base.SetCode(logContract, []byte{0x60, 0x40, 0x60, 0x00, 0xa0, 0x00})
	base.SetNonce(logContract, 1)
	sign := func(keyHex string, feeCap, gas uint64, target common.Address, value int64) (*types.Transaction, common.Address) {
		key, err := crypto.HexToECDSA(keyHex)
		if err != nil {
			t.Fatal(err)
		}
		unsigned := types.NewTx(&types.DynamicFeeTx{
			ChainID: config.ChainID, GasTipCap: big.NewInt(1), GasFeeCap: new(big.Int).SetUint64(feeCap),
			Gas: gas, To: &target, Value: big.NewInt(value),
		})
		tx, err := types.SignTx(unsigned, types.LatestSignerForChainID(config.ChainID), key)
		if err != nil {
			t.Fatal(err)
		}
		return tx, crypto.PubkeyToAddress(key.PublicKey)
	}
	overflow, overflowSender := sign("8888888888888888888888888888888888888888888888888888888888888888", 30, 100_000, logContract, 0)
	small, smallSender := sign("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 10, params.TxGas, transferTarget, 1)
	for _, account := range []common.Address{overflowSender, smallSender} {
		base.SetBalance(account, new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	}
	base.Finalise(true)
	headerGas := overflow.Gas() + small.Gas()
	work := evmProposalParallelWork(config, base, parentHash, headerGas)

	cursor := types.NewTransactionsByPriceAndNonce(config, work.header.Number, map[common.Address]types.Transactions{
		overflowSender: {overflow},
		smallSender:    {small},
	})
	committed, receipts, _, failed, err := work.commitTransactions(cursor, chain)
	if err != nil {
		t.Fatalf("output-limited proposal: %v", err)
	}
	if len(committed) != 1 || committed[0].Hash() != small.Hash() {
		t.Fatalf("output retry selected %v, want only the small-output independent tx", committed)
	}
	if len(receipts) != 1 || len(failed) != 0 {
		t.Fatalf("output retry receipts=%d failed=%d, want 1/0", len(receipts), len(failed))
	}
	if work.publicState.GetNonce(overflowSender) != 0 || work.publicState.GetNonce(smallSender) != 1 {
		t.Fatalf("output retry did not discard failed speculative state: overflow=%d small=%d",
			work.publicState.GetNonce(overflowSender), work.publicState.GetNonce(smallSender))
	}
}

func TestEVMProposalExecutionAttemptLimitIsFixed(t *testing.T) {
	if evmProposalMaxExecutionAttempts != 3 {
		t.Fatalf("proposal execution attempt bound = %d, want 3", evmProposalMaxExecutionAttempts)
	}
}
