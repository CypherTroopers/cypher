package core

import (
	"errors"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus/colossusX"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/trie"
)

func evmOnlyNativeConfig() *params.ChainConfig {
	zeroBlock := big.NewInt(0)
	zeroTime := uint64(0)
	config := &params.ChainConfig{
		ChainID:             big.NewInt(1),
		HomesteadBlock:      zeroBlock,
		EIP150Block:         zeroBlock,
		EIP155Block:         zeroBlock,
		EIP158Block:         zeroBlock,
		ByzantiumBlock:      zeroBlock,
		ConstantinopleBlock: zeroBlock,
		PetersburgBlock:     zeroBlock,
		IstanbulBlock:       zeroBlock,
	}
	config.SetModernForkConfig(&params.ModernForkConfig{
		BerlinBlock: zeroBlock, LondonBlock: zeroBlock, ShanghaiTime: &zeroTime,
	})
	config.NativeParallel = params.SolanaScaleNativeParallelConfig()
	config.NativeParallel.RequireNativeTransactions = false
	return config
}

func strictNativeConfig() *params.ChainConfig {
	config := evmOnlyNativeConfig()
	config.NativeParallel = params.SolanaScaleNativeParallelConfig()
	config.NativeParallel.RequireNativeTransactions = true
	return config
}

func newEVMOnlyTestState(t *testing.T) *state.StateDB {
	t.Helper()
	statedb, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	return statedb
}

func evmOnlyBlobHash(index byte) common.Hash {
	var hash common.Hash
	hash[0] = types.BlobCommitmentVersionKZG
	hash[len(hash)-1] = index
	return hash
}

func allEVMTransactionTypes(config *params.ChainConfig) types.Transactions {
	to := common.HexToAddress("0x1001")
	return types.Transactions{
		types.NewTransaction(0, to, new(big.Int), params.TxGas, big.NewInt(1), nil),
		types.NewTx(&types.AccessListTx{
			ChainID: config.ChainID, GasPrice: big.NewInt(1), Gas: params.TxGas,
			To: &to, Value: new(big.Int),
		}),
		types.NewTx(&types.DynamicFeeTx{
			ChainID: config.ChainID, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(1), Gas: params.TxGas,
			To: &to, Value: new(big.Int),
		}),
		types.NewTx(&types.BlobTx{
			ChainID: config.ChainID, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(1), Gas: params.TxGas,
			To: to, Value: new(big.Int), BlobFeeCap: big.NewInt(1), BlobHashes: []common.Hash{evmOnlyBlobHash(1)},
		}),
		types.NewTx(&types.SetCodeTx{
			ChainID: config.ChainID, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(1), Gas: params.TxGas,
			To: to, Value: new(big.Int),
		}),
	}
}

func minimalNativeModeTransaction(config *params.ChainConfig) *types.Transaction {
	return types.NewTx(&types.NativeTxV1{
		ChainID: config.ChainID, Value: new(big.Int), MaxFeePerCompute: big.NewInt(1),
		PriorityFeePerCompute: new(big.Int), V: new(big.Int), R: new(big.Int), S: new(big.Int),
	})
}

func TestEVMOnlyGenesisModeAcceptsTypesZeroThroughFourInBothLanes(t *testing.T) {
	config := evmOnlyNativeConfig()
	for _, blockType := range []uint8{types.FastTx_Block, types.SlowTx_Block} {
		for _, tx := range allEVMTransactionTypes(config) {
			mode, err := ValidateNativeParallelBlockMode(config, blockType, types.Transactions{tx})
			if err != nil {
				t.Fatalf("block type %d rejected EVM transaction type %#x: %v", blockType, tx.Type(), err)
			}
			if mode != NativeParallelBlockModeEVM {
				t.Fatalf("block type %d transaction type %#x selected mode %d", blockType, tx.Type(), mode)
			}
		}
		if _, err := ValidateNativeParallelBlockMode(config, blockType, types.Transactions{minimalNativeModeTransaction(config)}); !errors.Is(err, ErrNativeParallelLaneMismatch) {
			t.Fatalf("block type %d NativeTxV1 error = %v, want lane mismatch", blockType, err)
		}
	}
}

func TestEVMOnlyDirectNativeAPIsRejectBeforeExecution(t *testing.T) {
	config := evmOnlyNativeConfig()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	payer := crypto.PubkeyToAddress(key.PublicKey)
	native, err := types.SignTx(
		nativePoolTestTx(payer, 1, common.HexToHash("0x01"), 0, 1, 0),
		types.NewNativeSigner(config.ChainID),
		key,
	)
	if err != nil {
		t.Fatal(err)
	}
	newFundedState := func() *state.StateDB {
		statedb := newEVMOnlyTestState(t)
		statedb.SetBalance(payer, new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
		return statedb
	}

	if _, err := NewNativeReplayAnchorSet(config, nil, 0); !errors.Is(err, ErrNativeTxDisabled) {
		t.Fatalf("EVM-only replay anchor error = %v, want %v", err, ErrNativeTxDisabled)
	}
	statedb := newFundedState()
	rootBefore := statedb.IntermediateRoot(false)
	if err := PrepareNativeReplaySequences(config, statedb, types.Transactions{native}); !errors.Is(err, ErrNativeTxDisabled) {
		t.Fatalf("EVM-only replay prepass error = %v, want %v", err, ErrNativeTxDisabled)
	}
	if rootAfter := statedb.IntermediateRoot(false); rootAfter != rootBefore {
		t.Fatalf("disabled replay prepass mutated state: root %s -> %s", rootBefore, rootAfter)
	}
	if _, err := NewNativeDependencyPlanner(config); !errors.Is(err, ErrNativeTxDisabled) {
		t.Fatalf("EVM-only dependency planner error = %v, want %v", err, ErrNativeTxDisabled)
	}

	header := &types.Header{Number: big.NewInt(0), GasLimit: native.Gas(), BaseFee: big.NewInt(1)}
	gasPool := new(GasPool).AddGas(header.GasLimit)
	usedGas := uint64(0)
	statedb = newFundedState()
	if _, err := ApplyTransaction(config, nil, nil, gasPool, statedb, header, native, &usedGas, vm.Config{}); !errors.Is(err, ErrNativeTxDisabled) {
		t.Fatalf("EVM-only direct ApplyTransaction error = %v, want %v", err, ErrNativeTxDisabled)
	}
	if _, err := ApplyNativeTransactionReference(config, nil, nil, gasPool, statedb, header, native, &usedGas, vm.Config{}); !errors.Is(err, ErrNativeTxDisabled) {
		t.Fatalf("EVM-only native reference error = %v, want %v", err, ErrNativeTxDisabled)
	}
	if _, _, _, err := ExecuteNativeProposalTransactions(config, nil, header, types.Transactions{native}, statedb, vm.Config{}); !errors.Is(err, ErrNativeTxDisabled) {
		t.Fatalf("EVM-only proposal executor error = %v, want %v", err, ErrNativeTxDisabled)
	}
	message := types.NewMessageWithModernFields(
		types.NativeTxType, payer, &payer, 0, new(big.Int), params.TxGas,
		big.NewInt(1), big.NewInt(1), big.NewInt(1), nil, nil, nil, nil, nil, false,
	)
	evm := vm.NewEVM(vm.Context{
		CanTransfer: CanTransfer, Transfer: Transfer, BlockNumber: big.NewInt(0),
		Time: new(big.Int), GasLimit: params.TxGas, BaseFee: big.NewInt(1),
	}, statedb, config, vm.Config{})
	if _, err := ApplyMessage(evm, message, new(GasPool).AddGas(params.TxGas)); !errors.Is(err, ErrNativeTxDisabled) {
		t.Fatalf("EVM-only direct ApplyMessage error = %v, want %v", err, ErrNativeTxDisabled)
	}

	pool := &TxPool{chainconfig: config, nativeSigner: types.NewNativeSigner(config.ChainID)}
	if err := pool.validateNativeTxWithState(native, statedb); !errors.Is(err, ErrNativeTxDisabled) {
		t.Fatalf("EVM-only direct native pool validation error = %v, want %v", err, ErrNativeTxDisabled)
	}
}

func TestEVMOnlyExecutionModeGuardLeavesTypesZeroThroughFourEnabled(t *testing.T) {
	config := evmOnlyNativeConfig()
	for _, tx := range allEVMTransactionTypes(config) {
		if err := validateNativeTransactionTypeExecutionMode(config, tx.Type()); err != nil {
			t.Fatalf("EVM-only transaction-type guard rejected standard type %#x: %v", tx.Type(), err)
		}
		if err := validateNativeTransactionExecutionMode(config, tx); err != nil {
			t.Fatalf("EVM-only execution mode rejected standard type %#x: %v", tx.Type(), err)
		}
	}
}

func TestRetiredStrictFlagCannotReenableNativeBlockLanes(t *testing.T) {
	config := strictNativeConfig()
	nativeTx := minimalNativeModeTransaction(config)
	legacyTx := types.NewTransaction(0, common.Address{1}, new(big.Int), params.TxGas, big.NewInt(1), nil)
	if err := config.NativeParallel.Validate(); err == nil {
		t.Fatal("retired strict NativeTx profile unexpectedly validated")
	}
	for _, blockType := range []uint8{types.FastTx_Block, types.SlowTx_Block} {
		if mode, err := ValidateNativeParallelBlockMode(config, blockType, types.Transactions{nativeTx}); !errors.Is(err, ErrNativeParallelLaneMismatch) || mode != NativeParallelBlockModeEVM {
			t.Fatalf("retired strict flag enabled NativeTxV1 for block type %d: mode=%d err=%v", blockType, mode, err)
		}
		if mode, err := ValidateNativeParallelBlockMode(config, blockType, types.Transactions{legacyTx}); err != nil || mode != NativeParallelBlockModeEVM {
			t.Fatalf("retired strict flag rejected legacy type 0 for block type %d: mode=%d err=%v", blockType, mode, err)
		}
	}
}

func TestEVMOnlyBlobLaneStillFailsClosedWithoutDA(t *testing.T) {
	config := evmOnlyNativeConfig()
	zeroTime := uint64(0)
	modern := config.ModernForkConfig()
	modern.CancunTime = &zeroTime
	to := common.HexToAddress("0x1001")
	tx := types.NewTx(&types.BlobTx{
		ChainID: config.ChainID, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(10), Gas: params.TxGas,
		To: to, Value: new(big.Int), BlobFeeCap: big.NewInt(1), BlobHashes: []common.Hash{evmOnlyBlobHash(1)},
		V: new(big.Int), R: big.NewInt(1), S: big.NewInt(1),
	})
	header := &types.Header{Number: big.NewInt(1), Time: 0, BlockType: types.FastTx_Block}
	header.BlobGasUsed = CalcBlobGasUsed(types.Transactions{tx})
	if _, err := ValidateNativeParallelBlockMode(config, header.BlockType, types.Transactions{tx}); err != nil {
		t.Fatalf("blob transaction was not classified as EVM lane work: %v", err)
	}
	if err := ValidateBlockBlobExecution(config, header, types.Transactions{tx}, types.KZGBlobVerifier{}); !errors.Is(err, types.ErrBlobSidecarMissing) {
		t.Fatalf("blob body error = %v, want unavailable authenticated DA", err)
	}
}

func prepareEVMOnlyHistory(statedb *state.StateDB, header *types.Header) {
	if statedb == nil || header == nil || header.Number == nil || header.Number.Sign() <= 0 {
		return
	}
	parentNumber := header.Number.Uint64() - 1
	slot := common.BigToHash(new(big.Int).SetUint64(parentNumber % params.NativeReplayHistoryWindow))
	statedb.SetNonce(params.HistoryStorageAddress, 1)
	statedb.SetCode(params.HistoryStorageAddress, params.HistoryStorageCode)
	statedb.SetState(params.HistoryStorageAddress, slot, header.ParentHash)
}

func signEVMOnlyLegacyTransaction(t *testing.T, config *params.ChainConfig, keyHex string, tx *types.Transaction) (*types.Transaction, common.Address) {
	t.Helper()
	key, err := crypto.HexToECDSA(keyHex)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := types.SignTx(tx, types.NewEIP155Signer(config.ChainID), key)
	if err != nil {
		t.Fatal(err)
	}
	return signed, crypto.PubkeyToAddress(key.PublicKey)
}

func TestEVMOnlyStateProcessorExecutesStandardContractCreation(t *testing.T) {
	config := evmOnlyNativeConfig()
	// Copy the trailing STOP byte into memory and return it as one-byte runtime
	// code, ensuring the created contract is non-empty under EIP-161.
	initCode := []byte{0x60, 0x01, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, 0x01, 0x60, 0x00, 0xf3, 0x00}
	unsigned := types.NewContractCreation(0, new(big.Int), 100_000, big.NewInt(params.FixedTransferGasPricePerGas), initCode)
	tx, sender := signEVMOnlyLegacyTransaction(t, config, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", unsigned)
	statedb := newEVMOnlyTestState(t)
	statedb.SetBalance(sender, new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	header := &types.Header{
		ParentHash: common.HexToHash("0xabc1"), Number: big.NewInt(1), Difficulty: big.NewInt(1),
		GasLimit: tx.Gas(), Time: 1, BaseFee: big.NewInt(params.FixedBaseFeePerGas), BlockType: types.SlowTx_Block,
	}
	prepareEVMOnlyHistory(statedb, header)
	statedb.Finalise(true)
	block := types.NewBlock(header, types.Transactions{tx}, nil, nil, new(trie.Trie))
	engine := colossusX.NewFaker()
	defer engine.Close()
	chain := &BlockChain{chainConfig: config, engine: engine}
	processor := NewStateProcessor(config, chain, engine)
	receipts, _, usedGas, err := processor.Process(block, statedb, vm.Config{})
	if err != nil {
		t.Fatalf("standard contract creation failed: %v", err)
	}
	if len(receipts) != 1 || receipts[0] == nil || receipts[0].ContractAddress != crypto.CreateAddress(sender, 0) {
		t.Fatalf("contract creation receipt = %+v", receipts)
	}
	if usedGas == 0 || !statedb.Exist(receipts[0].ContractAddress) {
		t.Fatalf("contract was not created: gas=%d address=%s", usedGas, receipts[0].ContractAddress)
	}
}

func TestEVMOnlyStateProcessorUsesStateRootedBlockHash(t *testing.T) {
	config := evmOnlyNativeConfig()
	target := common.HexToAddress("0x2001")
	// PUSH1(0), BLOCKHASH, PUSH1(0), SSTORE, STOP.
	code := []byte{byte(vm.PUSH1), 0, byte(vm.BLOCKHASH), byte(vm.PUSH1), 0, byte(vm.SSTORE), byte(vm.STOP)}
	unsigned := types.NewTransaction(0, target, new(big.Int), 100_000, big.NewInt(params.FixedTransferGasPricePerGas), nil)
	tx, sender := signEVMOnlyLegacyTransaction(t, config, "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", unsigned)
	statedb := newEVMOnlyTestState(t)
	statedb.SetBalance(sender, new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	statedb.SetCode(target, code)
	header := &types.Header{
		ParentHash: common.HexToHash("0xcafe"), Number: big.NewInt(1), Difficulty: big.NewInt(1),
		GasLimit: tx.Gas(), Time: 1, BaseFee: big.NewInt(params.FixedBaseFeePerGas), BlockType: types.FastTx_Block,
	}
	prepareEVMOnlyHistory(statedb, header)
	statedb.Finalise(true)
	block := types.NewBlock(header, types.Transactions{tx}, nil, nil, new(trie.Trie))
	engine := colossusX.NewFaker()
	defer engine.Close()
	chain := &BlockChain{chainConfig: config, engine: engine}
	if _, _, _, err := NewStateProcessor(config, chain, engine).Process(block, statedb, vm.Config{}); err != nil {
		t.Fatalf("BLOCKHASH transaction failed: %v", err)
	}
	if got := statedb.GetState(target, common.Hash{}); got != header.ParentHash {
		t.Fatalf("BLOCKHASH read %s, want certified parent %s", got, header.ParentHash)
	}
}

func TestEVMOnlyReservedPrefixIsOrdinaryAddress(t *testing.T) {
	config := evmOnlyNativeConfig()
	reserved := params.NativeReplayRegistryAddressForPayer(common.Address{0x42})
	unsigned := types.NewTransaction(0, reserved, big.NewInt(7), params.TxGas, big.NewInt(params.FixedTransferGasPricePerGas), nil)
	tx, sender := signEVMOnlyLegacyTransaction(t, config, "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", unsigned)
	statedb := newEVMOnlyTestState(t)
	statedb.SetBalance(sender, new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	statedb.Finalise(true)
	header := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1), GasLimit: params.TxGas, Time: 1, BaseFee: big.NewInt(params.FixedBaseFeePerGas)}
	statedb.Prepare(tx.Hash(), common.Hash{}, 0)
	gasPool := new(GasPool).AddGas(header.GasLimit)
	var usedGas uint64
	author := common.Address{}
	if _, err := ApplyTransaction(config, nil, &author, gasPool, statedb, header, tx, &usedGas, vm.Config{}); err != nil {
		t.Fatalf("reserved-prefix EVM transfer failed: %v", err)
	}
	if got := statedb.GetBalance(reserved); got.Cmp(big.NewInt(7)) != 0 {
		t.Fatalf("reserved-prefix balance = %v, want 7", got)
	}
}

func TestStrictNativeProtocolGuardRollsBackDirectAndInternalMutation(t *testing.T) {
	config := strictNativeConfig()
	reserved := params.NativeReplayRegistryAddressForPayer(common.Address{0x42})
	contract := common.HexToAddress("0x3001")
	callCode := []byte{
		byte(vm.PUSH1), 0, byte(vm.PUSH1), 0, byte(vm.PUSH1), 0, byte(vm.PUSH1), 0,
		byte(vm.PUSH1), 1, byte(vm.PUSH20),
	}
	callCode = append(callCode, reserved[:]...)
	callCode = append(callCode, byte(vm.GAS), byte(vm.CALL), byte(vm.POP), byte(vm.STOP))

	tests := []struct {
		name  string
		to    common.Address
		value *big.Int
		gas   uint64
		setup func(*state.StateDB)
	}{
		{name: "direct", to: reserved, value: big.NewInt(1), gas: params.TxGas},
		{name: "internal", to: contract, value: new(big.Int), gas: 120_000, setup: func(statedb *state.StateDB) {
			statedb.SetCode(contract, callCode)
			statedb.SetBalance(contract, big.NewInt(10))
		}},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statedb := newEVMOnlyTestState(t)
			statedb.SetNonce(reserved, 1)
			if test.setup != nil {
				test.setup(statedb)
			}
			unsigned := types.NewTransaction(0, test.to, test.value, test.gas, big.NewInt(params.FixedTransferGasPricePerGas), nil)
			keyHex := []string{
				"2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				"3123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			}[index]
			tx, sender := signEVMOnlyLegacyTransaction(t, config, keyHex, unsigned)
			initialSenderBalance := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
			statedb.SetBalance(sender, initialSenderBalance)
			statedb.Finalise(true)
			beforeRoot := statedb.IntermediateRoot(true)
			statedb.Prepare(tx.Hash(), common.Hash{}, 0)
			gasPool := new(GasPool).AddGas(test.gas)
			var usedGas uint64
			author := common.Address{}
			receipt, err := ApplyTransaction(config, nil, &author, gasPool, statedb, &types.Header{
				Number: big.NewInt(1), Difficulty: big.NewInt(1), GasLimit: test.gas, Time: 1, BaseFee: big.NewInt(params.FixedBaseFeePerGas),
			}, tx, &usedGas, vm.Config{})
			if !errors.Is(err, ErrReservedNativeProtocolAddress) {
				t.Fatalf("guard error = %v receipt=%+v code=%x contractBalance=%v reservedBalance=%v", err, receipt, statedb.GetCode(contract), statedb.GetBalance(contract), statedb.GetBalance(reserved))
			}
			if usedGas != 0 || gasPool.Gas() != test.gas {
				t.Fatalf("failed transaction leaked gas accounting: used=%d remaining=%d", usedGas, gasPool.Gas())
			}
			if statedb.GetNonce(sender) != 0 || statedb.GetBalance(sender).Cmp(initialSenderBalance) != 0 || statedb.GetNonce(reserved) != 1 || statedb.GetBalance(reserved).Sign() != 0 {
				t.Fatal("failed reserved mutation poisoned account state")
			}
			if test.name == "internal" && statedb.GetBalance(contract).Cmp(big.NewInt(10)) != 0 {
				t.Fatal("failed internal mutation leaked contract balance")
			}
			if got := statedb.IntermediateRoot(true); got != beforeRoot {
				t.Fatalf("failed mutation state root = %s, want %s", got, beforeRoot)
			}
		})
	}
}

func TestReplayRegistryGenesisAccountsOnlyExistInStrictNativeMode(t *testing.T) {
	for _, test := range []struct {
		name   string
		config *params.ChainConfig
		exist  bool
	}{
		{name: "evm-only", config: evmOnlyNativeConfig(), exist: false},
		{name: "strict-native", config: strictNativeConfig(), exist: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			database := rawdb.NewMemoryDatabase()
			genesis := &Genesis{Config: test.config, Difficulty: big.NewInt(1)}
			block := genesis.ToBlock(database)
			statedb, err := state.New(block.Root(), state.NewDatabase(database), nil)
			if err != nil {
				t.Fatal(err)
			}
			for shard := 0; shard < 256; shard++ {
				var payer common.Address
				payer[0] = byte(shard)
				address := params.NativeReplayRegistryAddressForPayer(payer)
				if got := statedb.Exist(address); got != test.exist {
					t.Fatalf("shard %d existence = %t, want %t", shard, got, test.exist)
				}
				if test.exist && (statedb.GetNonce(address) != 1 || len(statedb.GetCode(address)) != 0 || statedb.GetBalance(address).Sign() != 0) {
					t.Fatalf("shard %d has non-canonical protocol account", shard)
				}
			}
		})
	}
}

func TestReservedGenesisAllocIsOrdinaryOnlyInEVMMode(t *testing.T) {
	reserved := params.NativeReplayRegistryAddressForPayer(common.Address{0x7f})
	allocation := GenesisAlloc{reserved: {Balance: big.NewInt(9)}}
	database := rawdb.NewMemoryDatabase()
	block := (&Genesis{Config: evmOnlyNativeConfig(), Difficulty: big.NewInt(1), Alloc: allocation}).ToBlock(database)
	statedb, err := state.New(block.Root(), state.NewDatabase(database), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := statedb.GetBalance(reserved); got.Cmp(big.NewInt(9)) != 0 {
		t.Fatalf("EVM-only reserved-prefix genesis balance = %v, want 9", got)
	}
	if address, found := firstReservedNativeGenesisAccount(allocation); !found || address != reserved {
		t.Fatalf("strict-native reserved allocation detector = %s/%t", address, found)
	}
}
