package core

import (
	"bytes"
	"crypto/ecdsa"
	"math"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus/colossusX"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/params"
)

func TestCommonRPCRewardIsAppliedOnlyAfterTransactionExecution(t *testing.T) {
	approver := common.HexToAddress("0x1000000000000000000000000000000000000001")
	tx := types.NewTransaction(0, common.HexToAddress("0x2000000000000000000000000000000000000002"), new(big.Int), params.TxGas, big.NewInt(params.FixedTransferGasPricePerGas), nil)
	actualFee := new(big.Int).Mul(new(big.Int).SetUint64(params.TxGas), big.NewInt(params.FixedTransferGasPricePerGas))
	wantReward := new(big.Int).Div(new(big.Int).Set(actualFee), big.NewInt(5))
	reward := &types.CommonTxReward{
		TxHash: tx.Hash(), Approver: approver,
		ApproverReward: new(big.Int).Set(wantReward),
		Burn:           new(big.Int).Sub(actualFee, wantReward),
	}
	statedb := newModernTestState(t)
	if err := validateCommonRPCReward(reward, approver, tx, params.TxGas, big.NewInt(params.FixedBaseFeePerGas)); err != nil {
		t.Fatal(err)
	}
	if got := statedb.GetBalance(approver); got.Sign() != 0 {
		t.Fatalf("validation mutated approver balance before all tx execution: %v", got)
	}
	applyCommonRPCRewards(statedb, []*types.CommonTxReward{reward})
	if got := statedb.GetBalance(approver); got.Cmp(wantReward) != 0 {
		t.Fatalf("settled approver reward = %v, want %v", got, wantReward)
	}
}

func stateProcessorTestAdmissionBatch(t *testing.T, key *ecdsa.PrivateKey, chainID *big.Int, genesisHash common.Hash, keyBlockNumber, timestamp uint64, txHashes []common.Hash) *types.CommonTxAdmissionBatch {
	t.Helper()
	batch := &types.CommonTxAdmissionBatch{
		ChainID:        new(big.Int).Set(chainID),
		GenesisHash:    genesisHash,
		Miner:          crypto.PubkeyToAddress(key.PublicKey),
		KeyBlockNumber: keyBlockNumber,
		Timestamp:      timestamp,
		TxHashes:       append([]common.Hash(nil), txHashes...),
	}
	batch.TxRoot = types.DeriveCommonTxAdmissionTxRoot(batch.TxHashes)
	batch.AdmissionID = types.CommonTxAdmissionID(batch)
	var err error
	batch.Signature, err = crypto.Sign(types.CommonTxAdmissionSigningHash(batch).Bytes(), key)
	if err != nil {
		t.Fatal(err)
	}
	return batch
}

func cloneStateProcessorTestAdmissionBatch(batch *types.CommonTxAdmissionBatch) *types.CommonTxAdmissionBatch {
	if batch == nil {
		return nil
	}
	clone := *batch
	if batch.ChainID != nil {
		clone.ChainID = new(big.Int).Set(batch.ChainID)
	}
	clone.TxHashes = append([]common.Hash(nil), batch.TxHashes...)
	clone.Signature = append([]byte(nil), batch.Signature...)
	return &clone
}

func resealStateProcessorTestAdmissionBatch(t *testing.T, batch *types.CommonTxAdmissionBatch, key *ecdsa.PrivateKey) {
	t.Helper()
	batch.Miner = crypto.PubkeyToAddress(key.PublicKey)
	batch.TxRoot = types.DeriveCommonTxAdmissionTxRoot(batch.TxHashes)
	batch.AdmissionID = types.CommonTxAdmissionID(batch)
	var err error
	batch.Signature, err = crypto.Sign(types.CommonTxAdmissionSigningHash(batch).Bytes(), key)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCommonTxAdmissionBatchConsensusValidation(t *testing.T) {
	config := modernTestConfig(true, true, true)
	config.FairHotstuff = true
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	miner := crypto.PubkeyToAddress(key.PublicKey)
	config.CommonRPCSigners = []common.Address{miner}
	genesisHash := common.Hash{0xaa}
	const keyBlockNumber = uint64(7)
	const blockTimestamp = uint64(100)

	txs := make(types.Transactions, types.MaxCommonTxAdmissionBatchItems)
	hashes := make([]common.Hash, len(txs))
	refs := make([]types.CommonTxAdmissionRef, len(txs))
	for index := range txs {
		txs[index] = types.NewTransaction(uint64(index), common.Address{1}, big.NewInt(int64(index+1)), params.TxGas, big.NewInt(1), nil)
		hashes[index] = txs[index].Hash()
		refs[index] = types.CommonTxAdmissionRef{Batch: 0, Item: uint16(index)}
	}
	valid := stateProcessorTestAdmissionBatch(t, key, config.ChainID, genesisHash, keyBlockNumber, blockTimestamp, hashes)
	miners, err := buildCommonAdmissionApprovers(config, []*types.CommonTxAdmissionBatch{valid}, refs, txs, genesisHash, keyBlockNumber, blockTimestamp)
	if err != nil {
		t.Fatalf("valid 512-item admission batch rejected: %v", err)
	}
	if len(miners) != len(txs) {
		t.Fatalf("approver count = %d, want %d", len(miners), len(txs))
	}
	for index, got := range miners {
		if got != miner {
			t.Fatalf("approver %d = %s, want %s", index, got, miner)
		}
	}

	t.Run("513 items", func(t *testing.T) {
		tooLarge := cloneStateProcessorTestAdmissionBatch(valid)
		tooLarge.TxHashes = append(tooLarge.TxHashes, common.Hash{0xff})
		resealStateProcessorTestAdmissionBatch(t, tooLarge, key)
		if _, err := validateCommonTxAdmissionLayout(config, []*types.CommonTxAdmissionBatch{tooLarge}, refs, txs, genesisHash); err == nil || !strings.Contains(err.Error(), "invalid transaction count 513") {
			t.Fatalf("513-item batch error = %v", err)
		}
	})

	t.Run("past key block remains valid until finalization", func(t *testing.T) {
		batch := cloneStateProcessorTestAdmissionBatch(valid)
		batch.KeyBlockNumber = keyBlockNumber - 2
		resealStateProcessorTestAdmissionBatch(t, batch, key)
		miners, err := buildCommonAdmissionApprovers(config, []*types.CommonTxAdmissionBatch{batch}, refs, txs, genesisHash, keyBlockNumber, blockTimestamp)
		if err != nil {
			t.Fatalf("durable past-key admission rejected: %v", err)
		}
		if len(miners) != len(txs) || miners[0] != miner {
			t.Fatalf("past-key admission approvers = %v, want %s", miners, miner)
		}
	})

	tests := []struct {
		name string
		want string
		run  func() error
	}{
		{
			name: "wrong chain", want: "chain id",
			run: func() error {
				batch := cloneStateProcessorTestAdmissionBatch(valid)
				batch.ChainID = new(big.Int).Add(config.ChainID, big.NewInt(1))
				resealStateProcessorTestAdmissionBatch(t, batch, key)
				_, err := buildCommonAdmissionApprovers(config, []*types.CommonTxAdmissionBatch{batch}, refs, txs, genesisHash, keyBlockNumber, blockTimestamp)
				return err
			},
		},
		{
			name: "wrong genesis", want: "genesis hash",
			run: func() error {
				batch := cloneStateProcessorTestAdmissionBatch(valid)
				batch.GenesisHash = common.Hash{0xbb}
				resealStateProcessorTestAdmissionBatch(t, batch, key)
				_, err := buildCommonAdmissionApprovers(config, []*types.CommonTxAdmissionBatch{batch}, refs, txs, genesisHash, keyBlockNumber, blockTimestamp)
				return err
			},
		},
		{
			name: "future timestamp", want: "from the future",
			run: func() error {
				batch := cloneStateProcessorTestAdmissionBatch(valid)
				batch.Timestamp = blockTimestamp + 31
				resealStateProcessorTestAdmissionBatch(t, batch, key)
				_, err := buildCommonAdmissionApprovers(config, []*types.CommonTxAdmissionBatch{batch}, refs, txs, genesisHash, keyBlockNumber, blockTimestamp)
				return err
			},
		},
		{
			name: "unauthorized miner", want: "genesis-authorized",
			run: func() error {
				unauthorizedKey, err := crypto.GenerateKey()
				if err != nil {
					t.Fatal(err)
				}
				batch := cloneStateProcessorTestAdmissionBatch(valid)
				resealStateProcessorTestAdmissionBatch(t, batch, unauthorizedKey)
				_, err = buildCommonAdmissionApprovers(config, []*types.CommonTxAdmissionBatch{batch}, refs, txs, genesisHash, keyBlockNumber, blockTimestamp)
				return err
			},
		},
		{
			name: "tampered signature",
			run: func() error {
				batch := cloneStateProcessorTestAdmissionBatch(valid)
				batch.Signature[0] ^= 0x01
				_, err := buildCommonAdmissionApprovers(config, []*types.CommonTxAdmissionBatch{batch}, refs, txs, genesisHash, keyBlockNumber, blockTimestamp)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(); err == nil || test.want != "" && !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestCommonTxAdmissionReferenceConsensusValidation(t *testing.T) {
	config := modernTestConfig(true, true, true)
	config.FairHotstuff = true
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	miner := crypto.PubkeyToAddress(key.PublicKey)
	config.CommonRPCSigners = []common.Address{miner}
	genesisHash := common.Hash{0xaa}
	txA := types.NewTransaction(0, common.Address{1}, big.NewInt(1), params.TxGas, big.NewInt(1), nil)
	txB := types.NewTransaction(1, common.Address{2}, big.NewInt(2), params.TxGas, big.NewInt(1), nil)
	batchA := stateProcessorTestAdmissionBatch(t, key, config.ChainID, genesisHash, 7, 100, []common.Hash{txA.Hash()})
	batchB := stateProcessorTestAdmissionBatch(t, key, config.ChainID, genesisHash, 7, 100, []common.Hash{txB.Hash()})
	batches := []*types.CommonTxAdmissionBatch{batchA, batchB}
	if bytes.Compare(batches[0].AdmissionID[:], batches[1].AdmissionID[:]) > 0 {
		batches[0], batches[1] = batches[1], batches[0]
	}
	batchFor := func(hash common.Hash) uint16 {
		for index, batch := range batches {
			if batch.TxHashes[0] == hash {
				return uint16(index)
			}
		}
		t.Fatalf("missing batch for %s", hash)
		return 0
	}
	refs := []types.CommonTxAdmissionRef{{Batch: batchFor(txA.Hash()), Item: 0}, {Batch: batchFor(txB.Hash()), Item: 0}}
	if _, err := validateCommonTxAdmissionLayout(config, batches, refs, types.Transactions{txA, txB}, genesisHash); err != nil {
		t.Fatalf("valid sorted partial-batch selection rejected: %v", err)
	}

	reversed := []*types.CommonTxAdmissionBatch{batches[1], batches[0]}
	if _, err := validateCommonTxAdmissionLayout(config, reversed, refs, types.Transactions{txA, txB}, genesisHash); err == nil || !strings.Contains(err.Error(), "ascending") {
		t.Fatalf("unsorted batch error = %v", err)
	}
	if _, err := validateCommonTxAdmissionLayout(config, batches, refs[:1], types.Transactions{txA}, genesisHash); err == nil || !strings.Contains(err.Error(), "unreferenced") {
		t.Fatalf("unreferenced batch error = %v", err)
	}
	if _, err := validateCommonTxAdmissionLayout(config, []*types.CommonTxAdmissionBatch{batchA}, []types.CommonTxAdmissionRef{{Batch: 0, Item: 0}}, types.Transactions{txB}, genesisHash); err == nil || !strings.Contains(err.Error(), "transaction mismatch") {
		t.Fatalf("reference/hash mismatch error = %v", err)
	}
	if _, err := validateCommonTxAdmissionLayout(config, []*types.CommonTxAdmissionBatch{batchA}, []types.CommonTxAdmissionRef{{Batch: 0, Item: 0}, {Batch: 0, Item: 0}}, types.Transactions{txA, txA}, genesisHash); err == nil || !strings.Contains(err.Error(), "duplicates batch 0 item 0") {
		t.Fatalf("duplicate reference error = %v", err)
	}
	duplicate := []*types.CommonTxAdmissionBatch{batchA, cloneStateProcessorTestAdmissionBatch(batchA)}
	if _, err := validateCommonTxAdmissionLayout(config, duplicate, []types.CommonTxAdmissionRef{{Batch: 0, Item: 0}}, types.Transactions{txA}, genesisHash); err == nil || !strings.Contains(err.Error(), "duplicates admission id") {
		t.Fatalf("duplicate certificate error = %v", err)
	}

	actualFee := new(big.Int).Mul(new(big.Int).SetUint64(params.TxGas), big.NewInt(params.FixedTransferGasPricePerGas))
	approverReward := new(big.Int).Div(new(big.Int).Set(actualFee), big.NewInt(5))
	reward := &types.CommonTxReward{
		TxHash: txA.Hash(), Approver: common.Address{9}, ApproverReward: approverReward,
		Burn: new(big.Int).Sub(actualFee, approverReward),
	}
	if err := validateCommonRPCReward(reward, batchA.Miner, txA, params.TxGas, big.NewInt(params.FixedBaseFeePerGas)); err == nil || !strings.Contains(err.Error(), "approver") {
		t.Fatalf("reward approver substitution error = %v", err)
	}
}

func TestStateProcessorRejectsFHSAdmissionAndRewardOmissionBeforeExecution(t *testing.T) {
	config := modernTestConfig(true, true, true)
	config.FairHotstuff = true
	tx := types.NewTransaction(
		0,
		common.HexToAddress("0x2000000000000000000000000000000000000002"),
		big.NewInt(1),
		params.TxGas,
		big.NewInt(params.FixedTransferGasPricePerGas),
		nil,
	)
	block := types.NewBlockWithHeader(&types.Header{
		Number: big.NewInt(1), Difficulty: big.NewInt(1), BlockType: types.FastTx_Block,
		GasLimit: params.TxGas, BaseFee: big.NewInt(params.FixedBaseFeePerGas),
	}).WithBody(types.Transactions{tx}, nil)

	processor := &StateProcessor{config: config}
	if _, _, _, err := processor.Process(block, newModernTestState(t), vm.Config{}); err == nil || !strings.Contains(err.Error(), "admission reference count") {
		t.Fatalf("missing Fair HotStuff admission/reward rejection = %v", err)
	}
}

func TestStateProcessorParallelNativeMatchesSerial(t *testing.T) {
	config := modernTestConfig(true, true, true)
	base := newModernTestState(t)
	txs := make(types.Transactions, 64)
	for index := range txs {
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		from := crypto.PubkeyToAddress(key.PublicKey)
		to := common.BigToAddress(new(big.Int).SetUint64(uint64(10_000 + index)))
		base.SetBalance(from, new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
		base.SetBalance(to, big.NewInt(100))
		var unsigned *types.Transaction
		switch index % 3 {
		case 0:
			unsigned = types.NewTransaction(0, to, big.NewInt(int64(index+1)), params.TxGas,
				big.NewInt(params.FixedTransferGasPricePerGas), nil)
		case 1:
			unsigned = types.NewTx(&types.AccessListTx{
				ChainID: config.ChainID, Nonce: 0, GasPrice: big.NewInt(params.FixedTransferGasPricePerGas),
				Gas: params.TxGas, To: &to, Value: big.NewInt(int64(index + 1)),
			})
		default:
			unsigned = types.NewTx(&types.DynamicFeeTx{
				ChainID: config.ChainID, Nonce: 0, GasTipCap: big.NewInt(2),
				GasFeeCap: new(big.Int).Add(big.NewInt(params.FixedBaseFeePerGas), big.NewInt(2)),
				Gas:       params.TxGas, To: &to, Value: big.NewInt(int64(index + 1)),
			})
		}
		txs[index], err = types.SignTx(unsigned, types.LatestSignerForChainID(config.ChainID), key)
		if err != nil {
			t.Fatal(err)
		}
	}
	base.Finalise(true)
	header := &types.Header{
		ParentHash: common.HexToHash("0x100"), Number: big.NewInt(1), Difficulty: big.NewInt(1),
		GasLimit: uint64(len(txs)) * params.TxGas, Time: 1,
		BaseFee: big.NewInt(params.FixedBaseFeePerGas),
	}
	block := types.NewBlockWithHeader(header).WithBody(txs, nil)
	processor := &StateProcessor{config: config}
	rules := config.CypheriumRules(header.Number, header.Time)
	author := header.Coinbase

	serialState := base.Copy()
	serialGas := new(GasPool).AddGas(header.GasLimit)
	var serialUsed uint64
	serialReceipts := make(types.Receipts, 0, len(txs))
	for index, tx := range txs {
		serialState.Prepare(tx.Hash(), block.Hash(), index)
		receipt, err := ApplyTransaction(config, (*BlockChain)(nil), &author, serialGas, serialState, header, tx, &serialUsed, vm.Config{EnablePreimageRecording: true})
		if err != nil {
			t.Fatalf("serial tx %d: %v", index, err)
		}
		serialReceipts = append(serialReceipts, receipt)
	}
	serialRoot := serialState.IntermediateRoot(true)

	for _, workerCount := range []int{1, 2, 4, maxParallelNativeBatch} {
		executor := newNativeTransferExecutor(block, workerCount)
		for attempt := 0; attempt < 2; attempt++ {
			parallelState := base.Copy()
			parallelGas := new(GasPool).AddGas(header.GasLimit)
			jobs := processor.collectParallelNativeJobs(txs, 0, block, parallelState, parallelGas, vm.Config{}, rules)
			if len(jobs) != len(txs) {
				t.Fatalf("workers=%d parallel jobs = %d, want %d", workerCount, len(jobs), len(txs))
			}
			results := executor.execute(jobs)
			var parallelUsed uint64
			parallelReceipts := make(types.Receipts, 0, len(txs))
			for index := range jobs {
				receipt, err := mergeParallelNativeResult(parallelState, parallelGas, &parallelUsed, block, header, rules, jobs[index], results[index])
				if err != nil {
					t.Fatalf("workers=%d parallel tx %d: %v", workerCount, index, err)
				}
				parallelReceipts = append(parallelReceipts, receipt)
			}
			parallelRoot := parallelState.IntermediateRoot(true)
			if parallelRoot != serialRoot || parallelUsed != serialUsed || parallelGas.Gas() != serialGas.Gas() || !reflect.DeepEqual(parallelReceipts, serialReceipts) {
				t.Fatalf("workers=%d parallel result mismatch: root=%s/%s gas=%d/%d remaining=%d/%d receiptsEqual=%t",
					workerCount, parallelRoot, serialRoot, parallelUsed, serialUsed, parallelGas.Gas(), serialGas.Gas(), reflect.DeepEqual(parallelReceipts, serialReceipts))
			}
		}
		executor.close()
	}
}

func TestNativeTransferFastPathMatchesSerialNonceChain(t *testing.T) {
	config := modernTestConfig(true, true, true)
	zeroTime := uint64(0)
	modern := config.ModernForkConfig()
	modern.CancunTime = &zeroTime
	modern.PragueTime = &zeroTime
	modern.OsakaTime = &zeroTime
	base := newModernTestState(t)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	from := crypto.PubkeyToAddress(key.PublicKey)
	base.SetBalance(from, new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil))

	const txCount = 64
	txs := make(types.Transactions, txCount)
	signer := types.LatestSignerForChainID(config.ChainID)
	for index := range txs {
		to := common.BigToAddress(new(big.Int).SetUint64(uint64(20_000 + index)))
		base.SetBalance(to, big.NewInt(int64(index+1)))
		unsigned := types.NewTx(&types.DynamicFeeTx{
			ChainID: config.ChainID, Nonce: uint64(index), GasTipCap: big.NewInt(3),
			GasFeeCap: new(big.Int).Add(big.NewInt(params.FixedBaseFeePerGas), big.NewInt(3)),
			Gas:       params.TxGas, To: &to, Value: big.NewInt(int64(index + 1)),
		})
		txs[index], err = types.SignTx(unsigned, signer, key)
		if err != nil {
			t.Fatal(err)
		}
	}
	base.Finalise(true)
	header := &types.Header{
		ParentHash: common.HexToHash("0x400"), Number: big.NewInt(1), Difficulty: big.NewInt(1),
		GasLimit: txCount * params.TxGas, Time: 1, BaseFee: big.NewInt(params.FixedBaseFeePerGas),
	}
	block := types.NewBlockWithHeader(header).WithBody(txs, nil)
	author := header.Coinbase
	probeState := base.Copy()
	probeState.Prepare(txs[0].Hash(), block.Hash(), 0)
	probeMessage, err := txs[0].AsMessage(types.MakeSignerAutoJudgement(config, header.Number, txs[0].V()))
	if err != nil {
		t.Fatal(err)
	}
	probeGas := new(GasPool).AddGas(header.GasLimit)
	var probeUsed uint64
	if _, handled, probeErr := tryApplyNativeTransfer(config, probeGas, probeState, header, txs[0], probeMessage, &probeUsed, vm.Config{}); probeErr != nil || !handled {
		t.Fatalf("eligible native transfer handled=%t err=%v", handled, probeErr)
	}

	execute := func(name string, cfg vm.Config) (*state.StateDB, types.Receipts, uint64, uint64) {
		t.Helper()
		st := base.Copy()
		gas := new(GasPool).AddGas(header.GasLimit)
		var used uint64
		receipts := make(types.Receipts, 0, len(txs))
		for index, tx := range txs {
			st.Prepare(tx.Hash(), block.Hash(), index)
			receipt, applyErr := ApplyTransaction(config, (*BlockChain)(nil), &author, gas, st, header, tx, &used, cfg)
			if applyErr != nil {
				t.Fatalf("%s tx %d: %v", name, index, applyErr)
			}
			receipts = append(receipts, receipt)
		}
		return st, receipts, used, gas.Gas()
	}

	fastState, fastReceipts, fastUsed, fastRemaining := execute("fast", vm.Config{})
	serialState, serialReceipts, serialUsed, serialRemaining := execute("serial", vm.Config{EnablePreimageRecording: true})
	fastRoot := fastState.IntermediateRoot(true)
	serialRoot := serialState.IntermediateRoot(true)
	if fastRoot != serialRoot || fastUsed != serialUsed || fastRemaining != serialRemaining || !reflect.DeepEqual(fastReceipts, serialReceipts) {
		t.Fatalf("nonce-chain fast path mismatch: root=%s/%s gas=%d/%d remaining=%d/%d receiptsEqual=%t",
			fastRoot, serialRoot, fastUsed, serialUsed, fastRemaining, serialRemaining, reflect.DeepEqual(fastReceipts, serialReceipts))
	}
}

func TestParallelNativeCandidateRejectsSharedOrStatefulTransfers(t *testing.T) {
	config := modernTestConfig(true, true, true)
	statedb := newModernTestState(t)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	from := crypto.PubkeyToAddress(key.PublicKey)
	to := common.HexToAddress("0x2000")
	statedb.SetBalance(from, new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	statedb.SetBalance(to, big.NewInt(1))
	statedb.Finalise(true)
	signer := types.NewEIP155Signer(config.ChainID)
	sign := func(gas uint64, value *big.Int, data []byte, recipient common.Address) *types.Transaction {
		tx, err := types.SignTx(types.NewTransaction(0, recipient, value, gas, big.NewInt(params.FixedTransferGasPricePerGas), data), signer, key)
		if err != nil {
			t.Fatal(err)
		}
		return tx
	}
	rules := config.CypheriumRules(big.NewInt(1), 1)
	precompiles := make(map[common.Address]struct{})
	for _, address := range activePrecompileAddresses(rules) {
		precompiles[address] = struct{}{}
	}
	tests := []struct {
		name string
		tx   *types.Transaction
	}{
		{"zero value", sign(params.TxGas, new(big.Int), nil, to)},
		{"calldata", sign(params.TxGas+params.TxDataNonZeroGasEIP2028, big.NewInt(1), []byte{1}, to)},
		{"non-exact gas", sign(params.TxGas+1, big.NewInt(1), nil, to)},
		{"self transfer", sign(params.TxGas, big.NewInt(1), nil, from)},
		{"new recipient", sign(params.TxGas, big.NewInt(1), nil, common.HexToAddress("0x3000"))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, ok := parallelNativeTransferCandidate(test.tx, config, big.NewInt(1), statedb, rules, precompiles); ok {
				t.Fatal("unsafe transfer entered the parallel lane")
			}
		})
	}
	statedb.SetNonce(from, math.MaxUint64)
	maxNonce := types.NewTransaction(math.MaxUint64, to, big.NewInt(1), params.TxGas, big.NewInt(params.FixedTransferGasPricePerGas), nil)
	maxNonce, err = types.SignTx(maxNonce, signer, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := parallelNativeTransferCandidate(maxNonce, config, big.NewInt(1), statedb, rules, precompiles); ok {
		t.Fatal("max nonce transfer entered the parallel lane")
	}
}

func stateProcessorOsakaTestConfig() *params.ChainConfig {
	config := modernTestConfig(true, true, true)
	zeroTime := uint64(0)
	modern := config.ModernForkConfig()
	modern.CancunTime = &zeroTime
	modern.PragueTime = &zeroTime
	modern.OsakaTime = &zeroTime
	return config
}

func TestStateProcessorParallelSerialParallelMatchesSerial(t *testing.T) {
	config := stateProcessorOsakaTestConfig()
	base := newModernTestState(t)
	baseFee := big.NewInt(params.FixedBaseFeePerGas)
	osakaPrecompile := common.BytesToAddress([]byte{0x01, 0x00})
	txs := make(types.Transactions, 6)
	for index := range txs {
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		from := crypto.PubkeyToAddress(key.PublicKey)
		to := common.BigToAddress(new(big.Int).SetUint64(uint64(30_000 + index)))
		recipientBalance := big.NewInt(int64(index + 1))
		if index == 3 {
			to = osakaPrecompile
			recipientBalance = big.NewInt(1)
		}
		base.SetBalance(to, recipientBalance)
		value := big.NewInt(int64(index + 1))
		var unsigned *types.Transaction
		switch {
		case index < 2:
			unsigned = types.NewTx(&types.DynamicFeeTx{
				ChainID: config.ChainID, GasTipCap: new(big.Int), GasFeeCap: new(big.Int).Set(baseFee),
				Gas: params.TxGas, To: &to, Value: value,
			})
		case index == 2:
			unsigned = types.NewTx(&types.AccessListTx{
				ChainID: config.ChainID, GasPrice: big.NewInt(params.FixedTransferGasPricePerGas),
				Gas: params.TxGas + params.TxAccessListAddressGas, To: &to, Value: value,
				AccessList: types.AccessList{{Address: common.HexToAddress("0x8000000000000000000000000000000000000008")}},
			})
		default:
			unsigned = types.NewTransaction(0, to, value, params.TxGas, big.NewInt(params.FixedTransferGasPricePerGas), nil)
		}
		tx, err := types.SignTx(unsigned, types.LatestSignerForChainID(config.ChainID), key)
		if err != nil {
			t.Fatal(err)
		}
		txs[index] = tx
		if index < 2 {
			// Exercise the exact dynamic-fee balance boundary in the first
			// parallel wave: fee cap equals base fee and tip is zero.
			base.SetBalance(from, tx.Cost())
		} else {
			base.SetBalance(from, new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
		}
	}
	base.SetNonce(params.HistoryStorageAddress, 1)
	base.SetCode(params.HistoryStorageAddress, params.HistoryStorageCode)
	base.Finalise(true)
	middleGas := params.TxGas + params.TxAccessListAddressGas
	header := &types.Header{
		ParentHash: common.HexToHash("0x900"), Coinbase: common.HexToAddress("0x9000000000000000000000000000000000000009"),
		Number: big.NewInt(1), Difficulty: big.NewInt(1), GasLimit: 5*params.TxGas + middleGas,
		Time: 1, BaseFee: baseFee,
	}
	block := types.NewBlockWithHeader(header).WithBody(txs, nil)
	rules := config.CypheriumRules(header.Number, header.Time)
	processor := &StateProcessor{config: config}
	probeGas := new(GasPool).AddGas(header.GasLimit)
	if jobs := processor.collectParallelNativeJobs(txs, 0, block, base, probeGas, vm.Config{}, rules); len(jobs) != 2 {
		t.Fatalf("first parallel wave = %d jobs, want 2", len(jobs))
	}
	if _, _, ok := parallelNativeTransferCandidate(txs[2], config, header.Number, base, rules, nil); ok {
		t.Fatal("access-list transaction entered the native parallel lane")
	}
	if _, _, ok := parallelNativeTransferCandidate(txs[3], config, header.Number, base, rules, nil); ok {
		t.Fatal("Osaka P256VERIFY precompile transaction entered the native parallel lane")
	}
	if jobs := processor.collectParallelNativeJobs(txs, 4, block, base, probeGas, vm.Config{}, rules); len(jobs) != 2 {
		t.Fatalf("second parallel wave = %d jobs, want 2", len(jobs))
	}

	engine := colossusX.NewFaker()
	defer engine.Close()
	chain := &BlockChain{chainConfig: config, engine: engine}
	processor = NewStateProcessor(config, chain, engine)
	parallelState := base.Copy()
	parallelReceipts, parallelLogs, parallelUsed, err := processor.Process(block, parallelState, vm.Config{})
	if err != nil {
		t.Fatalf("parallel process: %v", err)
	}
	serialState := base.Copy()
	serialReceipts, serialLogs, serialUsed, err := processor.Process(block, serialState, vm.Config{EnablePreimageRecording: true})
	if err != nil {
		t.Fatalf("serial process: %v", err)
	}
	if parallelReceipts[2].GasUsed != middleGas || parallelReceipts[2].Status != types.ReceiptStatusSuccessful {
		t.Fatalf("access-list receipt = gas %d status %d, want gas %d success", parallelReceipts[2].GasUsed, parallelReceipts[2].Status, middleGas)
	}
	if parallelReceipts[3].GasUsed != params.TxGas || parallelReceipts[3].Status != types.ReceiptStatusFailed {
		t.Fatalf("Osaka precompile receipt = gas %d status %d, want gas %d failed", parallelReceipts[3].GasUsed, parallelReceipts[3].Status, params.TxGas)
	}
	if got := parallelState.GetBalance(osakaPrecompile); got.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("failed Osaka precompile call changed recipient balance to %v", got)
	}
	parallelRoot := parallelState.IntermediateRoot(true)
	serialRoot := serialState.IntermediateRoot(true)
	if parallelRoot != serialRoot || parallelUsed != serialUsed || !reflect.DeepEqual(parallelReceipts, serialReceipts) || !reflect.DeepEqual(parallelLogs, serialLogs) {
		t.Fatalf("parallel-serial-parallel mismatch: root=%s/%s gas=%d/%d receiptsEqual=%t logsEqual=%t",
			parallelRoot, serialRoot, parallelUsed, serialUsed, reflect.DeepEqual(parallelReceipts, serialReceipts), reflect.DeepEqual(parallelLogs, serialLogs))
	}
}
