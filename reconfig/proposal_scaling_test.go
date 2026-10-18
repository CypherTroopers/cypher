package reconfig

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

func TestProposalTransactionBodyWeightMatchesCanonicalItems(t *testing.T) {
	to := common.Address{1}
	for _, dataBytes := range []int{0, 55, 56, 255, 256} {
		tx := types.NewDynamicFeeTx(&types.DynamicFeeTx{
			ChainID: big.NewInt(1), GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2),
			Gas: params.TxGas, To: &to, Value: new(big.Int), Data: make([]byte, dataBytes),
			V: new(big.Int), R: big.NewInt(1), S: big.NewInt(1),
		})
		encoded, err := rlp.EncodeToBytes(tx)
		if err != nil {
			t.Fatal(err)
		}
		if got := proposalTransactionBodyWeight(tx); got != uint64(len(encoded)) {
			t.Fatalf("typed payload %d: selected bytes = %d, canonical bytes = %d", dataBytes, got, len(encoded))
		}
	}
	for _, version := range []byte{types.BlobSidecarVersion0, types.BlobSidecarVersion1} {
		proofCount := 1
		if version == types.BlobSidecarVersion1 {
			proofCount = types.BlobCellProofsPerBlob
		}
		sidecar := types.NewBlobTxSidecar(version, []types.Blob{make([]byte, 131072)}, make([]types.KZGCommitment, 1), make([]types.KZGProof, proofCount))
		tx := types.NewTx(&types.BlobTx{
			ChainID: big.NewInt(1), GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2),
			Gas: params.TxGas, To: to, Value: new(big.Int), BlobFeeCap: big.NewInt(1),
			BlobHashes: sidecar.BlobHashes(), V: new(big.Int), R: big.NewInt(1), S: big.NewInt(1),
		}).WithBlobSidecar(sidecar)
		transactionBytes, err := rlp.EncodeToBytes(tx)
		if err != nil {
			t.Fatal(err)
		}
		sidecarBytes, err := rlp.EncodeToBytes(sidecar)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := proposalTransactionBodyWeight(tx), uint64(len(transactionBytes)+len(sidecarBytes)); got != want {
			t.Fatalf("blob version %d: selected bytes = %d, canonical bytes = %d", version, got, want)
		}
		header := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1), GasLimit: 1_000_000}
		size, err := newProposalBodySize(header, nil, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		addition, ok := size.nextTransaction(tx, 128)
		if !ok {
			t.Fatalf("blob version %d accounting failed", version)
		}
		size.install(addition)
		assertProposalSizeMatchesCanonical(t, header, size, types.Transactions{tx}, nil)
	}
}

func proposalSizeTestTransaction(nonce uint64, dataBytes int) *types.Transaction {
	return types.NewTransaction(nonce, common.Address{1}, new(big.Int), 50_000, big.NewInt(128), make([]byte, dataBytes))
}

func proposalSizeTestBatch(id uint64, txs types.Transactions) *types.CommonTxAdmissionBatch {
	hashes := make([]common.Hash, len(txs))
	for index, tx := range txs {
		hashes[index] = tx.Hash()
	}
	return &types.CommonTxAdmissionBatch{
		Version: types.CommonRPCVersionV2, ChainID: big.NewInt(1), GenesisHash: common.Hash{1},
		AdmissionID: common.BigToHash(new(big.Int).SetUint64(id)), TxRoot: types.DeriveCommonTxAdmissionTxRoot(hashes),
		Miner: common.Address{2}, RewardRecipient: common.Address{3}, KeyBlockNumber: math.MaxUint64,
		Timestamp: math.MaxUint64, TxHashes: hashes, Signature: make([]byte, 65),
	}
}

// This oracle encodes the complete selected body only in tests. Production
// accounting visits each transaction once and each newly adopted certificate once.
func assertProposalSizeMatchesCanonical(t *testing.T, header *types.Header, size *proposalBodySize, txs types.Transactions, gasUsed []uint64) *types.Block {
	t.Helper()
	actualHeader := types.CopyHeader(header)
	actualHeader.GasUsed = size.gasUsed
	actualHeader.BlobGasUsed = size.blobGasUsed
	block := types.NewBlockWithHeader(actualHeader).WithBody(txs, nil)
	if size.admissions != nil {
		unique := make(map[common.Hash]*types.CommonTxAdmissionBatch)
		for _, tx := range txs {
			batch := size.admissions[tx.Hash()].Batch
			unique[batch.AdmissionID] = batch
		}
		ids := make([]common.Hash, 0, len(unique))
		for id := range unique {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })
		batches := make([]*types.CommonTxAdmissionBatch, len(ids))
		positions := make(map[common.Hash]uint32, len(ids))
		for index, id := range ids {
			batches[index] = unique[id]
			positions[id] = uint32(index)
		}
		refs := make([]types.CommonTxAdmissionRef, len(txs))
		receipts := make(types.Receipts, len(txs))
		for index, tx := range txs {
			selection := size.admissions[tx.Hash()]
			refs[index] = types.CommonTxAdmissionRef{Batch: positions[selection.Batch.AdmissionID], Item: selection.Item}
			receipts[index] = &types.Receipt{GasUsed: gasUsed[index]}
		}
		rewards, err := buildCommonTxRewards(txs, receipts, batches, refs, header.BaseFee)
		if err != nil {
			t.Fatal(err)
		}
		block.AttachCommonTxData(batches, refs, rewards)
	}
	encoded := block.EncodeToBytes()
	if got := size.encodedSize(false); got != uint64(len(encoded)) {
		t.Fatalf("selected %d transactions: incremental bytes = %d, canonical bytes = %d", len(txs), got, len(encoded))
	}
	return block
}

func TestProposalBodySizePartialCertificateAndActualReward(t *testing.T) {
	header := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1), GasLimit: 1_000_000, BaseFee: big.NewInt(1)}
	txs := make(types.Transactions, types.MaxCommonTxAdmissionBatchItems)
	for index := range txs {
		txs[index] = proposalSizeTestTransaction(uint64(index), index%57)
	}
	batch := proposalSizeTestBatch(1, txs)
	admissions := make(map[common.Hash]core.CommonRPCAdmissionResult, len(txs))
	for index, tx := range txs {
		admissions[tx.Hash()] = core.CommonRPCAdmissionResult{Batch: batch, Item: uint16(index)}
	}
	config := &params.ChainConfig{FairHotstuff: true, NativeParallel: params.SolanaScaleNativeParallelConfig()}
	size, err := newProposalBodySize(header, config, admissions, 0)
	if err != nil {
		t.Fatal(err)
	}
	var adopted types.Transactions
	var gas []uint64
	for _, item := range []int{0, 127, 128, 255, 256, 511} {
		bound, ok := size.nextTransaction(txs[item], txs[item].Gas())
		if !ok {
			t.Fatal("reward upper bound failed")
		}
		addition, ok := size.nextTransaction(txs[item], uint64(item))
		if !ok || addition.next.encodedSize(false) > bound.next.encodedSize(false) {
			t.Fatal("actual receipt exceeded declared-gas reward bound")
		}
		size.install(addition)
		adopted = append(adopted, txs[item])
		gas = append(gas, uint64(item))
		assertProposalSizeMatchesCanonical(t, header, size, adopted, gas)
		if size.batchBytes != size.batchSizes[0] || size.batchCount != 1 {
			t.Fatal("partial adoption omitted or duplicated the complete signed certificate")
		}
	}
	block := assertProposalSizeMatchesCanonical(t, header, size, adopted, gas)
	validatorMeter := core.NewFHSEVMBlockWorkMeterForConfig(config)
	for index, tx := range adopted {
		if err := validatorMeter.AddTransaction(index, tx); err != nil {
			t.Fatal(err)
		}
	}
	if err := validatorMeter.AddCommonSidecars(block.CommonTxAdmissionBatches(), block.CommonTxAdmissionRefs(), block.CommonTxRewards()); err != nil {
		t.Fatalf("selected subset exceeds final consensus sidecar meter: %v", err)
	}
	beforeMeter := *size.workMeter
	tooMuchGas := types.NewTransaction(999, common.Address{1}, new(big.Int), params.FairHotstuffEVMWorkLimitsForConfig(config).DeclaredGas+1, big.NewInt(1), nil)
	if _, ok := size.nextTransaction(tooMuchGas, 0); ok || *size.workMeter != beforeMeter {
		t.Fatal("rejected trial transaction consumed accepted sidecar work")
	}
	clone := size.copy()
	addition, ok := clone.nextTransaction(txs[1], 1)
	if !ok {
		t.Fatal("clone candidate failed")
	}
	clone.install(addition)
	if size.batchRefs[0] != uint64(len(adopted)) {
		t.Fatal("speculative copy mutated accepted certificate accounting")
	}
	size.txBytes = math.MaxUint64
	if _, ok := size.nextTransaction(txs[1], 1); ok {
		t.Fatal("overflowing proposal byte counter accepted a candidate")
	}
}

func TestProposalBodySizePreservesRewardPayloadSubquota(t *testing.T) {
	config := &params.ChainConfig{FairHotstuff: true, NativeParallel: params.SolanaScaleNativeParallelConfig()}
	config.NativeParallel.MaxBlockBytes = 8 * 1024 * 1024
	config.NativeParallel.MaxTransactionBytes = 1024 * 1024
	header := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1), GasLimit: 1_000_000_000}
	limits := params.FairHotstuffEVMWorkLimitsForConfig(config)
	txs := make(types.Transactions, limits.CommonTxRewardPayloadBytes/73+2)
	admissions := make(map[common.Hash]core.CommonRPCAdmissionResult, len(txs))
	for index := range txs {
		txs[index] = proposalSizeTestTransaction(uint64(index), 0)
	}
	for first := 0; first < len(txs); first += types.MaxCommonTxAdmissionBatchItems {
		end := first + types.MaxCommonTxAdmissionBatchItems
		if end > len(txs) {
			end = len(txs)
		}
		batch := proposalSizeTestBatch(uint64(first+1), txs[first:end])
		for index := first; index < end; index++ {
			admissions[txs[index].Hash()] = core.CommonRPCAdmissionResult{Batch: batch, Item: uint16(index - first)}
		}
	}
	size, err := newProposalBodySize(header, config, admissions, 0)
	if err != nil {
		t.Fatal(err)
	}
	var gas []uint64
	for _, tx := range txs {
		before := *size.workMeter
		addition, ok := size.nextTransaction(tx, tx.Gas())
		if !ok {
			if *size.workMeter != before {
				t.Fatal("reward payload rejection consumed the accepted work meter")
			}
			break
		}
		size.install(addition)
		gas = append(gas, tx.Gas())
	}
	if len(gas) == 0 || len(gas) == len(txs) {
		t.Fatalf("reward subquota selected %d/%d candidates", len(gas), len(txs))
	}
	if size.encodedSize(true) > config.EffectiveMaxBlockBytes() {
		t.Fatal("byte ceiling bound before the isolated reward payload subquota")
	}
	block := assertProposalSizeMatchesCanonical(t, header, size, txs[:len(gas)], gas)
	validatorMeter := core.NewFHSEVMBlockWorkMeterForConfig(config)
	for index, tx := range txs[:len(gas)] {
		if err := validatorMeter.AddTransaction(index, tx); err != nil {
			t.Fatal(err)
		}
	}
	if err := validatorMeter.AddCommonSidecars(block.CommonTxAdmissionBatches(), block.CommonTxAdmissionRefs(), block.CommonTxRewards()); err != nil {
		t.Fatalf("accepted byte-bounded subset exceeds final sidecar meter: %v", err)
	}
}

func TestProposalByteTrialPreservesPermanentWorkFailureCleanup(t *testing.T) {
	for _, serial := range []bool{false, true} {
		t.Run(fmt.Sprintf("serial=%t", serial), func(t *testing.T) {
			config := evmProposalParallelTestConfig(t)
			config.NativeParallel.MaxAccessesPerTransaction = 1
			header := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1), GasLimit: 1_000_000}
			statedb := evmProposalParallelState(t, common.Hash{})
			env := &work{config: config, header: header, publicState: statedb, fhsWorkMeter: core.NewFHSEVMBlockWorkMeterForConfig(config)}
			to := common.Address{1}
			tx := types.NewTx(&types.AccessListTx{
				ChainID: config.ChainID, To: &to, Gas: params.TxGas, GasPrice: big.NewInt(1), Value: new(big.Int),
				AccessList: types.AccessList{{Address: common.Address{2}}, {Address: common.Address{3}}},
				V:          new(big.Int), R: big.NewInt(1), S: big.NewInt(1),
			})
			key, err := crypto.GenerateKey()
			if err != nil {
				t.Fatal(err)
			}
			tx, err = types.SignTx(tx, types.NewLondonSigner(config.ChainID), key)
			if err != nil {
				t.Fatal(err)
			}
			cursor := types.NewTransactionsByPriceAndNonce(config, header.Number, map[common.Address]types.Transactions{crypto.PubkeyToAddress(key.PublicKey): {tx}})
			var failed types.Transactions
			if serial {
				var err error
				_, _, _, failed, err = env.commitTransactionsSerial(cursor, nil)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				failed = env.selectEVMProposalTransactions(cursor).failed
			}
			if len(failed) != 1 || failed[0].Hash() != tx.Hash() {
				t.Fatal("byte trial swallowed permanent work-limit cleanup")
			}
		})
	}
}

func TestProposalBodySizeSortedReferenceWidthGrowth(t *testing.T) {
	header := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1), GasLimit: 100_000_000}
	const batchCount = 260
	batches := make([]types.Transactions, batchCount)
	admissions := make(map[common.Hash]core.CommonRPCAdmissionResult, 2*batchCount)
	for index := range batches {
		batches[index] = types.Transactions{proposalSizeTestTransaction(uint64(2*index), index%57), proposalSizeTestTransaction(uint64(2*index+1), index%57)}
		batch := proposalSizeTestBatch(uint64(index+1), batches[index])
		for item, tx := range batches[index] {
			admissions[tx.Hash()] = core.CommonRPCAdmissionResult{Batch: batch, Item: uint16(item)}
		}
	}
	size, err := newProposalBodySize(header, nil, admissions, 0)
	if err != nil {
		t.Fatal(err)
	}
	var adopted types.Transactions
	var gas []uint64
	for index := len(batches) - 1; index >= 0; index-- {
		for _, tx := range batches[index] {
			addition, ok := size.nextTransaction(tx, 128)
			if !ok {
				t.Fatal("candidate rejected")
			}
			size.install(addition)
			adopted = append(adopted, tx)
			gas = append(gas, 128)
		}
		if size.batchCount <= 3 || size.batchCount >= 126 && size.batchCount <= 130 || size.batchCount >= 254 {
			assertProposalSizeMatchesCanonical(t, header, size, adopted, gas)
		}
	}
	// A retry can retain an arbitrary successful subset. Starting from the
	// parent snapshot removes unused certificates and renumbers remaining refs.
	subset, err := newProposalBodySize(header, nil, admissions, 0)
	if err != nil {
		t.Fatal(err)
	}
	addition, _ := subset.nextTransaction(batches[100][1], 127)
	subset.install(addition)
	assertProposalSizeMatchesCanonical(t, header, subset, batches[100][1:], []uint64{127})
}

func TestProposalBodySizeCanonicalListBoundariesAndFinality(t *testing.T) {
	for _, length := range []int{0, 1, 55, 56, 255, 256, 65535, 65536} {
		encoded, err := rlp.EncodeToBytes([][]byte{make([]byte, length)})
		if err != nil {
			t.Fatal(err)
		}
		if got := proposalListSize(proposalByteStringSize(make([]byte, length))); got != uint64(len(encoded)) {
			t.Fatalf("list boundary %d: incremental bytes %d, canonical bytes %d", length, got, len(encoded))
		}
	}
	header := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1), GasLimit: 1_000_000}
	config := &params.ChainConfig{FairHotstuff: true, GenCommittee: params.GenesisCommittee{0: {Address: strings.Repeat("l", 56)}}}
	size, err := newProposalBodySize(header, config, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	tx := proposalSizeTestTransaction(0, 256)
	addition, _ := size.nextTransaction(tx, 128)
	size.install(addition)
	block := assertProposalSizeMatchesCanonical(t, header, size, types.Transactions{tx}, nil)
	unsigned := block.EncodeToBytes()
	block.SetFHSSignature(make([]byte, 96), make([]byte, 13), common.Hash{1}, strings.Repeat("l", 56), math.MaxUint64, common.Hash{2}, common.Hash{3})
	if err := block.SetFHSFinalityProof(make([]byte, types.MaxFHSFinalityProofSize)); err != nil {
		t.Fatal(err)
	}
	if got, want := size.encodedSize(true), uint64(len(block.EncodeToBytes())); got != want {
		t.Fatalf("finality and QC bound = %d, canonical maximum = %d", got, want)
	}
	actualHeader := types.CopyHeader(header)
	actualHeader.GasUsed = size.gasUsed
	if got, err := proposalFinalizedSize(actualHeader, unsigned, config, 0); err != nil || got != size.encodedSize(true) {
		t.Fatalf("final canonical check = %d, error %v, want %d", got, err, size.encodedSize(true))
	}
}

func TestHighBacklogProposalIsChunked(t *testing.T) {
	if got := blockMaxTxCount(types.FastTx_Block); got != 16384 {
		t.Fatalf("fast proposal tx limit = %d, want 16384", got)
	}
	if got := blockMaxTxCount(types.SlowTx_Block); got != 16384 {
		t.Fatalf("slow proposal tx limit = %d, want 16384", got)
	}
	if got := blockProposalLimit(types.FastTx_Block, 250000); got != 512 {
		t.Fatalf("high-backlog per-account limit = %d, want 512", got)
	}
	if got := blockProposalLimit(types.SlowTx_Block, 250000); got != 512 {
		t.Fatalf("high-backlog slow per-account limit = %d, want 512", got)
	}
	const singleSenderBurst = 20000
	if blocks := (singleSenderBurst + fastPerAccountTierLarge - 1) / fastPerAccountTierLarge; blocks != 40 {
		t.Fatalf("%d sequential transactions require %d bounded proposals, want 40", singleSenderBurst, blocks)
	}
	const submitted = 250000
	blocks := (submitted + int(fastBlockMaxTxCount) - 1) / int(fastBlockMaxTxCount)
	if blocks != 16 {
		t.Fatalf("%d transactions require %d proposal chunks, want 16", submitted, blocks)
	}
}

func TestGenesisNativeProposalUsesRaisedConsensusCeilings(t *testing.T) {
	config := &params.ChainConfig{NativeParallel: params.SolanaScaleNativeParallelConfig()}
	if got := blockMaxTxCountForConfig(config, types.FastTx_Block); got != config.NativeParallel.MaxTransactionsPerBlock {
		t.Fatalf("native block transaction limit = %d, want %d", got, config.NativeParallel.MaxTransactionsPerBlock)
	}
	if got := proposalByteLimit(config, types.FastTx_Block); got != config.NativeParallel.MaxBlockBytes {
		t.Fatalf("native proposal byte limit = %d, want %d", got, config.NativeParallel.MaxBlockBytes)
	}
	serialLimit := params.FairHotstuffEVMWorkLimitsForConfig(config).TransactionsPerSender
	if got := blockProposalLimitForConfig(config, types.FastTx_Block, 1_000_000); uint64(got) != serialLimit {
		t.Fatalf("EVM per-sender proposal limit = %d, want %d", got, serialLimit)
	}
	maxTx, perAccount := proposalPoolScanLimitsForConfig(config, types.FastTx_Block, 1_000_000, false)
	if uint64(maxTx) != config.NativeParallel.MaxTransactionsPerBlock {
		t.Fatalf("native proposal scan limit = %d, want %d", maxTx, config.NativeParallel.MaxTransactionsPerBlock)
	}
	if uint64(perAccount) != serialLimit {
		t.Fatalf("EVM proposal per-account scan limit = %d, want %d", perAccount, serialLimit)
	}
	maxTx, perAccount = proposalPoolScanLimitsForConfig(config, types.FastTx_Block, 1_000_000, true)
	if uint64(maxTx) != 2*config.NativeParallel.MaxTransactionsPerBlock || uint64(perAccount) != 2*serialLimit {
		t.Fatalf("two-chain EVM proposal scan limits = %d/%d, want %d/%d", maxTx, perAccount, 2*config.NativeParallel.MaxTransactionsPerBlock, 2*serialLimit)
	}
}

func TestEVMOnlyProposalRoutesBothResourceLanesToStandardEVM(t *testing.T) {
	strict := &params.ChainConfig{NativeParallel: params.SolanaScaleNativeParallelConfig()}
	evmOnly := strict
	if !isEVMOnlyProposalMode(evmOnly) {
		t.Fatal("EVM-only genesis did not select the EVM work limits and meter")
	}
	retired := *evmOnly.NativeParallel
	retired.RequireNativeTransactions = true
	invalid := &params.ChainConfig{NativeParallel: &retired}
	if !isEVMOnlyProposalMode(invalid) {
		t.Fatal("retired strict flag disabled EVM-only proposal limits")
	}

	wantLimit := params.FairHotstuffEVMWorkLimitsForConfig(evmOnly).Transactions
	for _, blockType := range []uint8{types.FastTx_Block, types.SlowTx_Block} {
		if got := blockMaxTxCountForConfig(evmOnly, blockType); got != wantLimit {
			t.Fatalf("EVM-only %s scan limit = %d, want %d", readableTxBlockType(blockType), got, wantLimit)
		}
	}
	wantClasses := map[uint8][]core.TxResourceClass{
		types.FastTx_Block: {core.TxClassNative, core.TxClassERC20, core.TxClassSmallCall},
		types.SlowTx_Block: {core.TxClassDex, core.TxClassDeploy, core.TxClassHeavy, core.TxClassData, core.TxClassNative, core.TxClassERC20, core.TxClassSmallCall},
	}
	for blockType, want := range wantClasses {
		got := pendingClassesForBlockType(blockType)
		if len(got) != len(want) {
			t.Fatalf("EVM-only %s resource classes = %v, want %v", readableTxBlockType(blockType), got, want)
		}
		for index := range want {
			if got[index] != want[index] {
				t.Fatalf("EVM-only %s resource classes = %v, want %v", readableTxBlockType(blockType), got, want)
			}
		}
	}
}

func TestEVMOnlyProposalResourceClassesUseConfiguredBlockCeiling(t *testing.T) {
	config := &params.ChainConfig{NativeParallel: params.SolanaScaleNativeParallelConfig()}
	config.NativeParallel.RequireNativeTransactions = false
	const gasTarget = uint64(9_000_000)
	budget := newTxResourceBudgetForConfig(config, types.SlowTx_Block, gasTarget, backlogEmergencyDrainPendingThreshold)
	wantTx := config.NativeParallel.MaxTransactionsPerBlock
	for _, class := range []core.TxResourceClass{core.TxClassDeploy, core.TxClassHeavy, core.TxClassData, core.TxClassDex} {
		if got := budget.txCaps[class]; got != wantTx {
			t.Fatalf("class %s transaction cap = %d, want %d", class, got, wantTx)
		}
		if got := budget.gasCaps[class]; got != gasTarget {
			t.Fatalf("class %s gas cap = %d, want %d", class, got, gasTarget)
		}
	}
}

func TestSlowProposalClassesRetainSignedNativeAndERC20Transactions(t *testing.T) {
	config := proposalBlobTestConfig(t)
	key, err := crypto.HexToECDSA("0000000000000000000000000000000000000000000000000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	oversizedERC20 := make([]byte, 1025)
	copy(oversizedERC20, []byte{0xa9, 0x05, 0x9c, 0xbb})
	for _, test := range []struct {
		name  string
		gas   uint64
		data  []byte
		class core.TxResourceClass
	}{
		{"native above fast gas", 300_001, nil, core.TxClassNative},
		{"erc20 above fast gas", 300_001, []byte{0xa9, 0x05, 0x9c, 0xbb}, core.TxClassERC20},
		{"erc20 above fast calldata", 100_000, oversizedERC20, core.TxClassERC20},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx, err := types.SignTx(types.NewTransaction(0, common.Address{9}, new(big.Int), test.gas, big.NewInt(2), test.data), types.NewEIP155Signer(config.ChainID), key)
			if err != nil {
				t.Fatal(err)
			}
			if core.ClassifyTxLane(tx) != core.TxLaneSlow || core.ClassifyTxResource(tx) != test.class {
				t.Fatalf("signed transaction lane/class = %d/%s, want slow/%s", core.ClassifyTxLane(tx), core.ClassifyTxResource(tx), test.class)
			}
			next, err := types.SignTx(types.NewTransaction(1, common.Address{9}, new(big.Int), 100_000, big.NewInt(2), []byte{0x38, 0xed, 0x17, 0x39}), types.NewEIP155Signer(config.ChainID), key)
			if err != nil {
				t.Fatal(err)
			}
			pool, _, sender := newProposalBlobTxPool(t, config, tx)
			if errs := pool.AddRemotesSync(types.Transactions{tx, next}); len(errs) != 2 || errs[0] != nil || errs[1] != nil {
				t.Fatalf("signed standard transaction admission: %v", errs)
			}
			fast, err := pool.PendingByLaneAndClassesLimited(core.TxLaneFast, 10, 10, 1_000_000, pendingClassesForBlockType(types.FastTx_Block)...)
			if err != nil || len(fast) != 0 {
				t.Fatalf("slow transaction selected by fast query: %v, %v", fast, err)
			}
			slow, err := pool.PendingByLaneAndClassesLimited(core.TxLaneSlow, 10, 10, 1_000_000, pendingClassesForBlockType(types.SlowTx_Block)...)
			if err != nil {
				t.Fatal(err)
			}
			if got := slow[sender]; len(got) != 2 || got[0].Hash() != tx.Hash() || got[1].Hash() != next.Hash() {
				t.Fatalf("slow proposal query lost accepted %s/dex nonce prefix: %v", test.class, got)
			}
		})
	}
}

func TestFHSAdmissionBatchLimitPreservesDeterministicNoncePrefixes(t *testing.T) {
	firstAddress := common.Address{1}
	secondAddress := common.Address{2}
	to := common.Address{9}
	first := types.Transactions{
		types.NewTransaction(0, to, new(big.Int), params.TxGas, big.NewInt(1), nil),
		types.NewTransaction(1, to, new(big.Int), params.TxGas, big.NewInt(1), nil),
		types.NewTransaction(2, to, new(big.Int), params.TxGas, big.NewInt(1), nil),
	}
	second := types.Transactions{
		types.NewTransaction(3, to, new(big.Int), params.TxGas, big.NewInt(1), nil),
		types.NewTransaction(4, to, new(big.Int), params.TxGas, big.NewInt(1), nil),
	}
	batchA, batchB, batchC := common.Hash{0xa}, common.Hash{0xb}, common.Hash{0xc}
	batchByTx := map[common.Hash]common.Hash{
		first[0].Hash():  batchA,
		first[1].Hash():  batchA,
		first[2].Hash():  batchB,
		second[0].Hash(): batchC,
		second[1].Hash(): batchA,
	}
	// Insert addresses in reverse order to ensure map iteration cannot decide
	// which certificate consumes the bound.
	got := limitFHSAdmissionBatchPrefixes(AddressTxes{secondAddress: second, firstAddress: first}, 2, func(tx *types.Transaction) (common.Hash, bool) {
		id, ok := batchByTx[tx.Hash()]
		return id, ok
	})
	if len(got[firstAddress]) != 2 {
		t.Fatalf("first sender prefix length = %d, want 2", len(got[firstAddress]))
	}
	if len(got[secondAddress]) != len(second) {
		t.Fatalf("higher-yield second sender prefix length = %d, want %d", len(got[secondAddress]), len(second))
	}

	delete(batchByTx, first[1].Hash())
	got = limitFHSAdmissionBatchPrefixes(AddressTxes{firstAddress: first}, 2, func(tx *types.Transaction) (common.Hash, bool) {
		id, ok := batchByTx[tx.Hash()]
		return id, ok
	})
	if len(got[firstAddress]) != 1 {
		t.Fatalf("sender suffix survived missing earlier admission: got prefix %d, want 1", len(got[firstAddress]))
	}
}

// Keep the original greedy selector as an independent compatibility oracle.
// visits counts transaction positions inspected by its repeated scoring scans.
func referenceFHSAdmissionBatchPrefixes(addrTxes AddressTxes, maxBatches int, admissionBatch func(*types.Transaction) (common.Hash, bool)) (AddressTxes, int) {
	filtered := make(AddressTxes, len(addrTxes))
	if maxBatches <= 0 || admissionBatch == nil {
		return filtered, 0
	}
	addresses := make([]common.Address, 0, len(addrTxes))
	for address := range addrTxes {
		addresses = append(addresses, address)
	}
	sort.Slice(addresses, func(i, j int) bool { return bytes.Compare(addresses[i][:], addresses[j][:]) < 0 })
	idsBySender := make(map[common.Address][]common.Hash, len(addresses))
	for _, address := range addresses {
		for _, tx := range addrTxes[address] {
			id, ok := admissionBatch(tx)
			if !ok || id == (common.Hash{}) {
				break
			}
			idsBySender[address] = append(idsBySender[address], id)
		}
	}
	selected := make(map[common.Hash]struct{})
	visits := 0
	for len(selected) < maxBatches {
		scores := make(map[common.Hash]int)
		for _, address := range addresses {
			ids := idsBySender[address]
			frontier := 0
			for frontier < len(ids) {
				visits++
				if _, ok := selected[ids[frontier]]; !ok {
					break
				}
				frontier++
			}
			if frontier == len(ids) {
				continue
			}
			candidate := ids[frontier]
			for _, id := range ids[frontier:] {
				visits++
				if id != candidate {
					if _, ok := selected[id]; !ok {
						break
					}
				}
				scores[candidate]++
			}
		}
		var best common.Hash
		bestScore := 0
		for id, score := range scores {
			if score > bestScore || score == bestScore && score > 0 && (best == (common.Hash{}) || bytes.Compare(id[:], best[:]) < 0) {
				best, bestScore = id, score
			}
		}
		if bestScore == 0 {
			break
		}
		selected[best] = struct{}{}
	}
	for _, address := range addresses {
		count := 0
		for _, id := range idsBySender[address] {
			if _, ok := selected[id]; !ok {
				break
			}
			count++
		}
		if count > 0 {
			filtered[address] = addrTxes[address][:count]
		}
	}
	return filtered, visits
}

func assertFHSAdmissionPrefixesEqual(t *testing.T, got, want AddressTxes) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("selected sender count = %d, want %d", len(got), len(want))
	}
	for address, txs := range want {
		if len(got[address]) != len(txs) {
			t.Fatalf("sender %s prefix length = %d, want %d", address, len(got[address]), len(txs))
		}
		for index, tx := range txs {
			if got[address][index] != tx {
				t.Fatalf("sender %s changed transaction at prefix index %d", address, index)
			}
		}
	}
}

func TestFHSAdmissionBatchLimitMatchesOriginalGreedy(t *testing.T) {
	rng := rand.New(rand.NewSource(230819))
	type admission struct {
		id common.Hash
		ok bool
	}
	for scenario := 0; scenario < 120; scenario++ {
		batchCount := 1 + rng.Intn(12)
		ids := make([]common.Hash, batchCount)
		for index := range ids {
			_, _ = rng.Read(ids[index][:])
		}
		addresses := make([]common.Address, rng.Intn(9))
		txsBySender := make([]types.Transactions, len(addresses))
		admissions := make(map[*types.Transaction]admission)
		for sender := range addresses {
			addresses[sender] = common.Address{byte(sender + 1)}
			txs := make(types.Transactions, rng.Intn(41))
			stop := rng.Intn(len(txs) + 1)
			for index := range txs {
				txs[index] = types.NewTransaction(uint64(index), addresses[sender], new(big.Int), params.TxGas, big.NewInt(1), nil)
				item := admission{id: ids[rng.Intn(batchCount)], ok: true}
				if scenario%3 != 0 && index == stop {
					if scenario%3 == 1 {
						item.ok = false
					} else {
						item.id = common.Hash{}
					}
				}
				admissions[txs[index]] = item
			}
			txsBySender[sender] = txs
		}
		for _, cap := range []int{-1, 0, 1, batchCount / 2, batchCount - 1, batchCount, batchCount + 1} {
			for permutation := 0; permutation < 3; permutation++ {
				t.Run(fmt.Sprintf("case%d/cap%d/order%d", scenario, cap, permutation), func(t *testing.T) {
					input := make(AddressTxes, len(addresses))
					for _, sender := range rng.Perm(len(addresses)) {
						input[addresses[sender]] = txsBySender[sender]
					}
					var gotLookups, wantLookups []*types.Transaction
					lookup := func(trace *[]*types.Transaction) func(*types.Transaction) (common.Hash, bool) {
						return func(tx *types.Transaction) (common.Hash, bool) {
							*trace = append(*trace, tx)
							item := admissions[tx]
							return item.id, item.ok
						}
					}
					want, _ := referenceFHSAdmissionBatchPrefixes(input, cap, lookup(&wantLookups))
					got := limitFHSAdmissionBatchPrefixes(input, cap, lookup(&gotLookups))
					assertFHSAdmissionPrefixesEqual(t, got, want)
					if len(gotLookups) != len(wantLookups) {
						t.Fatalf("admission lookups = %d, want %d", len(gotLookups), len(wantLookups))
					}
					for index, tx := range wantLookups {
						if gotLookups[index] != tx {
							t.Fatalf("admission lookup order changed at %d", index)
						}
					}
					selectedIDs := make(map[common.Hash]struct{})
					for _, txs := range got {
						for _, tx := range txs {
							selectedIDs[admissions[tx].id] = struct{}{}
						}
					}
					if len(selectedIDs) > 0 && len(selectedIDs) > cap {
						t.Fatalf("selected %d certificates with cap %d", len(selectedIDs), cap)
					}
				})
			}
		}
	}
}

func TestFHSAdmissionBatchLimitUsesAdmissionIDTieBreak(t *testing.T) {
	first, second := common.Address{1}, common.Address{2}
	txA, txB := proposalSizeTestTransaction(0, 0), proposalSizeTestTransaction(1, 0)
	input := AddressTxes{first: {txA}, second: {txB}}
	got := limitFHSAdmissionBatchPrefixes(input, 1, func(tx *types.Transaction) (common.Hash, bool) {
		if tx == txA {
			return common.Hash{2}, true
		}
		return common.Hash{1}, true
	})
	assertFHSAdmissionPrefixesEqual(t, got, AddressTxes{second: {txB}})
	if got := limitFHSAdmissionBatchPrefixes(input, 1, nil); len(got) != 0 {
		t.Fatal("nil admission lookup selected transactions")
	}
}

func TestFHSAdmissionBatchLimitNonbindingWorkBound(t *testing.T) {
	for _, count := range []int{512, 1024} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			address := common.Address{1}
			txs := make(types.Transactions, count)
			ids := make(map[*types.Transaction]common.Hash, count)
			for index := range txs {
				txs[index] = proposalSizeTestTransaction(uint64(index), 0)
				ids[txs[index]] = common.BigToHash(big.NewInt(int64(index + 1)))
			}
			input := AddressTxes{address: txs}
			lookup := func(tx *types.Transaction) (common.Hash, bool) { return ids[tx], true }
			want, visits := referenceFHSAdmissionBatchPrefixes(input, count, lookup)
			if expected := count*(count+1)/2 + 2*count - 1; visits != expected {
				t.Fatalf("original greedy scoring visits = %d, want %d", visits, expected)
			}
			// Count coverage of this test separately to verify that production's
			// greedy scoring loop is never entered. Callback counts alone cannot
			// detect rescoring because the original selector caches admissions too.
			for _, cap := range []int{count, count + 1} {
				lookups := 0
				got := limitFHSAdmissionBatchPrefixes(input, cap, func(tx *types.Transaction) (common.Hash, bool) {
					lookups++
					return lookup(tx)
				})
				assertFHSAdmissionPrefixesEqual(t, got, want)
				if lookups != count {
					t.Fatalf("admission lookups = %d, want %d", lookups, count)
				}
			}
			t.Logf("original greedy scoring visits: %d for %d transactions", visits, count)
		})
	}
}

func TestFHSAdmissionBatchLimitNonbindingLargeCap(t *testing.T) {
	input := AddressTxes{common.Address{1}: {proposalSizeTestTransaction(0, 0)}}
	got := limitFHSAdmissionBatchPrefixes(input, math.MaxInt, func(*types.Transaction) (common.Hash, bool) {
		return common.Hash{1}, true
	})
	assertFHSAdmissionPrefixesEqual(t, got, input)
}

// These deterministic fixtures measure local selection work, not chain TPS.
// Repeated IDs deliberately appear beyond intervening certificates.
func saturatedAdmissionPrefixFixture(shape string, count int) (AddressTxes, map[*types.Transaction]common.Hash, int) {
	input := make(AddressTxes)
	ids := make(map[*types.Transaction]common.Hash)
	senderCount, senderLength := 1, count
	if shape == "wide" {
		senderCount, senderLength = count/4, 4
	}
	for sender := 0; sender < senderCount; sender++ {
		address := common.BigToAddress(big.NewInt(int64(sender + 1)))
		var txs types.Transactions
		for item := 0; item < senderLength; item++ {
			tx := proposalSizeTestTransaction(uint64(len(txs)), 0)
			txs = append(txs, tx)
			ids[tx] = common.BigToHash(big.NewInt(int64(sender*senderLength + item + 1)))
			if shape == "repeated" && item > 0 {
				tx = proposalSizeTestTransaction(uint64(len(txs)), 0)
				txs = append(txs, tx)
				ids[tx] = common.BigToHash(big.NewInt(1))
			}
		}
		input[address] = txs
	}
	return input, ids, count / 2
}

func BenchmarkFHSAdmissionBatchPrefixesSaturated(b *testing.B) {
	for _, shape := range []string{"chain", "wide", "repeated"} {
		for _, count := range []int{512, 1024} {
			b.Run(fmt.Sprintf("%s/%d", shape, count), func(b *testing.B) {
				input, ids, cap := saturatedAdmissionPrefixFixture(shape, count)
				lookup := func(tx *types.Transaction) (common.Hash, bool) { return ids[tx], true }
				b.ReportAllocs()
				b.ResetTimer()
				for iteration := 0; iteration < b.N; iteration++ {
					_ = limitFHSAdmissionBatchPrefixes(input, cap, lookup)
				}
			})
		}
	}
}

func TestFHSAdmissionBatchLimitDependencyChangesMatchOriginalGreedy(t *testing.T) {
	for _, fixture := range []struct {
		name    string
		senders [][]uint64
	}{
		{"repeated-bridge", [][]uint64{{1, 2, 1, 3, 1, 4, 1, 5, 1}}},
		{"shared-blockers", [][]uint64{{5, 1, 5, 2, 5, 3, 5, 4, 5}, {6, 1, 6, 2, 6, 3, 6, 4, 6}, {1, 1, 2, 2, 3, 3, 4, 4}}},
		{"shared-candidates", [][]uint64{{1, 2, 1, 3, 1}, {1, 3, 1, 2, 1}, {2, 3, 2}, {3, 2, 3}}},
		{"changing-ties", [][]uint64{{4, 1, 4, 3}, {1, 2, 1, 3}, {2, 2, 3}, {3, 3, 5}}},
		{"exhausted-lookahead", [][]uint64{{1, 2, 1}, {2, 2, 2, 2}}},
		{"empty-and-terminal", [][]uint64{nil, {3, 1}, {1, 1, 2}, {4}}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			input := make(AddressTxes)
			ids := make(map[*types.Transaction]common.Hash)
			distinct := make(map[uint64]struct{})
			for sender, sequence := range fixture.senders {
				address := common.BigToAddress(big.NewInt(int64(sender + 1)))
				for nonce, id := range sequence {
					tx := proposalSizeTestTransaction(uint64(nonce), 0)
					input[address] = append(input[address], tx)
					ids[tx] = common.BigToHash(new(big.Int).SetUint64(id))
					distinct[id] = struct{}{}
				}
			}
			for cap := -1; cap <= len(distinct)+1; cap++ {
				var gotCalls, wantCalls []*types.Transaction
				lookup := func(calls *[]*types.Transaction) func(*types.Transaction) (common.Hash, bool) {
					return func(tx *types.Transaction) (common.Hash, bool) {
						*calls = append(*calls, tx)
						return ids[tx], true
					}
				}
				want, _ := referenceFHSAdmissionBatchPrefixes(input, cap, lookup(&wantCalls))
				got := limitFHSAdmissionBatchPrefixes(input, cap, lookup(&gotCalls))
				assertFHSAdmissionPrefixesEqual(t, got, want)
				if len(gotCalls) != len(wantCalls) {
					t.Fatalf("cap %d: admission lookup count = %d, want %d", cap, len(gotCalls), len(wantCalls))
				}
				for index := range wantCalls {
					if gotCalls[index] != wantCalls[index] {
						t.Fatalf("cap %d: admission lookup order changed at %d", cap, index)
					}
				}
			}
		})
	}
}

func TestFHSAdmissionBatchLimitExhaustiveSmallPrefixes(t *testing.T) {
	// Every pair of sequences up to length four over three certificate IDs:
	// 121 * 121 pairs exercise cycles, shared blockers, and score/hash ties.
	sequences := []types.Transactions{nil}
	ids := make(map[*types.Transaction]common.Hash)
	var extend func(types.Transactions)
	extend = func(prefix types.Transactions) {
		if len(prefix) == 4 {
			return
		}
		for id := byte(1); id <= 3; id++ {
			tx := proposalSizeTestTransaction(uint64(len(prefix)), 0)
			ids[tx] = common.Hash{id}
			sequence := append(append(types.Transactions(nil), prefix...), tx)
			sequences = append(sequences, sequence)
			extend(sequence)
		}
	}
	extend(nil)
	lookup := func(tx *types.Transaction) (common.Hash, bool) { return ids[tx], true }
	for first, left := range sequences {
		for second, right := range sequences {
			input := AddressTxes{common.Address{1}: left, common.Address{2}: right}
			for cap := 0; cap <= 4; cap++ {
				want, _ := referenceFHSAdmissionBatchPrefixes(input, cap, lookup)
				got := limitFHSAdmissionBatchPrefixes(input, cap, lookup)
				if len(got[common.Address{1}]) != len(want[common.Address{1}]) || len(got[common.Address{2}]) != len(want[common.Address{2}]) {
					t.Fatalf("sequences %d/%d cap %d: got prefix lengths %d/%d, want %d/%d", first, second, cap,
						len(got[common.Address{1}]), len(got[common.Address{2}]), len(want[common.Address{1}]), len(want[common.Address{2}]))
				}
				assertFHSAdmissionPrefixesEqual(t, got, want)
			}
		}
	}
}

func TestFHSAdmissionBatchLimitSaturatedScaling(t *testing.T) {
	for _, shape := range []string{"chain", "wide", "repeated"} {
		for _, count := range []int{512, 1024} {
			t.Run(fmt.Sprintf("%s/%d", shape, count), func(t *testing.T) {
				input, ids, cap := saturatedAdmissionPrefixFixture(shape, count)
				lookups := 0
				lookup := func(tx *types.Transaction) (common.Hash, bool) { return ids[tx], true }
				want, visits := referenceFHSAdmissionBatchPrefixes(input, cap, lookup)
				got := limitFHSAdmissionBatchPrefixes(input, cap, func(tx *types.Transaction) (common.Hash, bool) {
					lookups++
					return lookup(tx)
				})
				assertFHSAdmissionPrefixesEqual(t, got, want)
				if lookups != len(ids) {
					t.Fatalf("admission lookups = %d, want %d", lookups, len(ids))
				}
				t.Logf("synthetic selector: %d transactions, cap %d, original scoring visits %d", len(ids), cap, visits)
			})
		}
	}
}

func TestProposalSenderUsesProposalForkSigner(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	chainID := big.NewInt(1337)
	config := *params.TestChainConfig
	config.ChainID = new(big.Int).Set(chainID)
	config.EIP155Block = big.NewInt(10)
	config.SetModernForkConfig(&params.ModernForkConfig{
		BerlinBlock: big.NewInt(10),
		LondonBlock: big.NewInt(10),
	})
	defer config.SetModernForkConfig(nil)

	to := common.HexToAddress("0x5555555555555555555555555555555555555555")
	tx, err := types.SignTx(types.NewDynamicFeeTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     0,
		GasTipCap: big.NewInt(2),
		GasFeeCap: big.NewInt(20),
		Gas:       21_000,
		To:        &to,
		Value:     big.NewInt(1),
	}), types.NewLondonSigner(chainID), key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := proposalTransactionSender(&config, big.NewInt(9), tx); err == nil {
		t.Fatal("typed transaction unexpectedly recovered with the pre-London parent signer")
	}
	from, err := proposalTransactionSender(&config, big.NewInt(10), tx)
	if err != nil {
		t.Fatalf("typed transaction rejected at proposal fork height: %v", err)
	}
	if want := crypto.PubkeyToAddress(key.PublicKey); from != want {
		t.Fatalf("proposal sender = %s, want %s", from, want)
	}
}

func TestFHSPipelineScansPastCertifiedSenderWindow(t *testing.T) {
	maxTx, perAccount := proposalPoolScanLimits(types.FastTx_Block, 20_000, true)
	if maxTx != 2*params.MaxTxCountPerBlock || perAccount != 2*params.MaxTxCountPerSenderPerBlock {
		t.Fatalf("FHS scan limits = %d/%d, want %d/%d", maxTx, perAccount, 2*params.MaxTxCountPerBlock, 2*params.MaxTxCountPerSenderPerBlock)
	}
	maxTx, perAccount = proposalPoolScanLimits(types.FastTx_Block, 20_000, false)
	if maxTx != params.MaxTxCountPerBlock || perAccount != params.MaxTxCountPerSenderPerBlock {
		t.Fatalf("non-FHS scan limits = %d/%d, want %d/%d", maxTx, perAccount, params.MaxTxCountPerBlock, params.MaxTxCountPerSenderPerBlock)
	}

	address := common.Address{1}
	txs := make(types.Transactions, 2*params.MaxTxCountPerSenderPerBlock)
	for index := range txs {
		txs[index] = types.NewTransaction(uint64(index), address, new(big.Int), 21_000, big.NewInt(1), nil)
	}
	chain := newProposedChain()
	now := time.Now()
	chain.recordProposedTransactions(txs[:params.MaxTxCountPerSenderPerBlock], now)
	available := chain.withoutProposedTxes(AddressTxes{address: txs}, now)
	available = limitAddressTxes(available, params.MaxTxCountPerSenderPerBlock)
	got := available[address]
	if len(got) != params.MaxTxCountPerSenderPerBlock || got[0].Nonce() != params.MaxTxCountPerSenderPerBlock || got[len(got)-1].Nonce() != 2*params.MaxTxCountPerSenderPerBlock-1 {
		t.Fatalf("next certified sender window = len %d nonces %d..%d", len(got), got[0].Nonce(), got[len(got)-1].Nonce())
	}
}

func TestFHSPipelineScansPastCertifiedGasWindow(t *testing.T) {
	const blockGasTarget = uint64(1_000_000)
	if got := proposalPoolScanGasTarget(blockGasTarget, true); got != 2*blockGasTarget {
		t.Fatalf("FHS scan gas target = %d, want %d", got, 2*blockGasTarget)
	}
	if got := proposalPoolScanGasTarget(blockGasTarget, false); got != blockGasTarget {
		t.Fatalf("non-FHS scan gas target = %d, want %d", got, blockGasTarget)
	}
	if got := proposalPoolScanGasTarget(math.MaxUint64, true); got != math.MaxUint64 {
		t.Fatalf("overflowing FHS scan gas target = %d, want saturation", got)
	}
}

func TestFHSProposalUsesConsensusWorkMeterBoundary(t *testing.T) {
	limits := params.FairHotstuffWorkLimits()
	env := &work{fhsWorkMeter: core.NewFHSBlockWorkMeter()}
	atLimit := types.NewTransaction(0, common.Address{1}, new(big.Int), limits.DeclaredGas, big.NewInt(1), nil)
	next, err := env.nextFHSWorkMeter(0, atLimit)
	if err != nil {
		t.Fatalf("proposal rejected exact declared-gas consensus boundary: %v", err)
	}
	env.fhsWorkMeter = next // mirrors installation after successful execution
	if _, err := env.nextFHSWorkMeter(1, types.NewTransaction(1, common.Address{1}, new(big.Int), 1, big.NewInt(1), nil)); err == nil || !strings.Contains(err.Error(), "declared gas") {
		t.Fatalf("proposal accepted transaction beyond declared-gas consensus boundary: %v", err)
	}

	// Failed execution does not install its speculative meter snapshot.
	env = &work{fhsWorkMeter: core.NewFHSBlockWorkMeter()}
	if _, err := env.nextFHSWorkMeter(0, atLimit); err != nil {
		t.Fatal(err)
	}
	if _, err := env.nextFHSWorkMeter(0, atLimit); err != nil {
		t.Fatalf("uncommitted candidate consumed proposal work budget: %v", err)
	}

	// Non-FHS proposal construction remains outside these consensus rules.
	if next, err := (&work{}).nextFHSWorkMeter(0, atLimit); err != nil || next != nil {
		t.Fatalf("non-FHS work meter result = (%v,%v), want (nil,nil)", next, err)
	}
}

func TestFHSProposalMetersFinalRewardSidecar(t *testing.T) {
	tx := types.NewTransaction(0, common.Address{1}, new(big.Int), params.TxGas, big.NewInt(1), nil)
	seed := func(t *testing.T) *core.FHSBlockWorkMeter {
		t.Helper()
		env := &work{fhsWorkMeter: core.NewFHSBlockWorkMeter()}
		next, err := env.nextFHSWorkMeter(0, tx)
		if err != nil {
			t.Fatal(err)
		}
		return next
	}
	txHash := tx.Hash()
	approver := common.Address{2}
	admission := &types.CommonTxAdmissionBatch{Version: types.CommonRPCVersionV2, RewardRecipient: common.HexToAddress("0x43"), ChainID: big.NewInt(1), GenesisHash: common.Hash{1}, Miner: approver, Timestamp: 1, TxHashes: []common.Hash{txHash}, Signature: make([]byte, 65)}
	admission.TxRoot = types.DeriveCommonTxAdmissionTxRoot(admission.TxHashes)
	admission.AdmissionID = types.CommonTxAdmissionID(admission)
	refs := []types.CommonTxAdmissionRef{{Batch: 0, Item: 0}}
	reward := &types.CommonTxReward{Version: types.CommonRPCVersionV2, RewardRecipient: common.HexToAddress("0x43"), TxHash: txHash, Approver: approver, ApproverReward: big.NewInt(1), Burn: big.NewInt(1)}
	if err := addFHSProposalSidecarWork(seed(t), []*types.CommonTxAdmissionBatch{admission}, refs, []*types.CommonTxReward{reward}); err != nil {
		t.Fatalf("normal final proposal sidecars rejected: %v", err)
	}

	huge := &types.CommonTxReward{
		Version:         types.CommonRPCVersionV2,
		RewardRecipient: common.HexToAddress("0x43"),
		TxHash:          txHash,
		Approver:        approver,
		ApproverReward:  new(big.Int).Lsh(big.NewInt(1), uint(params.MaxFHSCommonTxRewardBytesPerReward*8)),
		Burn:            new(big.Int),
	}
	if err := addFHSProposalSidecarWork(seed(t), []*types.CommonTxAdmissionBatch{admission}, refs, []*types.CommonTxReward{huge}); err == nil || !strings.Contains(err.Error(), "reward 0 payload exceeds per-entry maximum") {
		t.Fatalf("proposal accepted oversized final reward sidecar: %v", err)
	}
	if err := addFHSProposalSidecarWork(seed(t), []*types.CommonTxAdmissionBatch{admission}, refs, []*types.CommonTxReward{reward, reward}); err == nil || !strings.Contains(err.Error(), "does not match admission reference count") {
		t.Fatalf("proposal accepted unrelated final rewards: %v", err)
	}
}

func TestFailedOnlyProposalRemainsPublishableForCleanup(t *testing.T) {
	// The build condition is intentionally expressed here at its boundary: a
	// failed-only selection must not take the ordinary no-work early return,
	// otherwise publication-gated failed transaction removal is unreachable.
	for _, test := range []struct {
		name          string
		txCount       int
		failedCount   int
		allowFinality bool
		wantNoWork    bool
	}{
		{name: "no work", wantNoWork: true},
		{name: "failed only", failedCount: 1},
		{name: "transaction", txCount: 1},
		{name: "finality child", allowFinality: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			gotNoWork := proposalHasNoPublishableWork(test.txCount, test.failedCount, test.allowFinality)
			if gotNoWork != test.wantNoWork {
				t.Fatalf("no-work decision = %t, want %t", gotNoWork, test.wantNoWork)
			}
		})
	}
}

func TestProposalNoWorkLaneSelectionAndRetryPolicy(t *testing.T) {
	realPrimary := errors.New("primary execution failure")
	realFallback := errors.New("fallback execution failure")
	wrappedNoWork := fmt.Errorf("lane empty: %w", errProposalNoWork)

	for _, test := range []struct {
		name     string
		primary  error
		fallback error
		want     error
	}{
		{name: "both empty", primary: errProposalNoWork, fallback: wrappedNoWork, want: errProposalNoWork},
		{name: "primary empty fallback failed", primary: errProposalNoWork, fallback: realFallback, want: realFallback},
		{name: "primary failed fallback empty", primary: realPrimary, fallback: errProposalNoWork, want: realPrimary},
		{name: "both failed preserves fallback", primary: realPrimary, fallback: realFallback, want: realFallback},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := proposalLaneBuildError(test.primary, test.fallback)
			if !errors.Is(got, test.want) {
				t.Fatalf("selected lane error = %v, want %v", got, test.want)
			}
		})
	}

	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "success"},
		{name: "empty", err: errProposalNoWork},
		{name: "wrapped empty", err: wrappedNoWork},
		{name: "stale view", err: hotstuff.ErrOldState},
		{name: "real failure", err: realPrimary, want: true},
	} {
		t.Run("retry "+test.name, func(t *testing.T) {
			if got := shouldRetryFHSProposalBuild(test.err); got != test.want {
				t.Fatalf("retry decision for %v = %t, want %t", test.err, got, test.want)
			}
		})
	}
}

func TestProposedTransactionExpiryWakesWithoutMaintenanceScan(t *testing.T) {
	chain := newProposedChain()
	start := time.Unix(1_800_000_000, 0)
	address := common.Address{1}
	tx := types.NewTransaction(0, address, new(big.Int), params.TxGas, big.NewInt(1), nil)
	chain.recordProposedTransactions(types.Transactions{tx}, start)
	wantExpiry := start.Add(proposedTxTTL)
	if chain.nextProposedExpiry != wantExpiry {
		t.Fatalf("next proposed expiry = %s, want %s", chain.nextProposedExpiry, wantExpiry)
	}

	atBoundary := AddressTxes{address: types.Transactions{tx}}
	if got := chain.withoutProposedTxes(atBoundary, wantExpiry); len(got) != 0 {
		t.Fatal("proposed transaction expired before its strict TTL boundary")
	}
	revision := chain.revision
	afterExpiry := AddressTxes{address: types.Transactions{tx}}
	if got := chain.withoutProposedTxes(afterExpiry, wantExpiry.Add(time.Nanosecond)); len(got[address]) != 1 {
		t.Fatal("expired proposed transaction remained excluded")
	}
	if chain.revision != revision+1 || !chain.nextProposedExpiry.IsZero() {
		t.Fatalf("expired exclusion state = revision %d expiry %s, want revision %d and zero expiry",
			chain.revision, chain.nextProposedExpiry, revision+1)
	}
}

func TestCertifiedProposedTransactionRemainsExcludedUntilCommit(t *testing.T) {
	chain := newProposedChain()
	start := time.Unix(1_800_000_000, 0)
	address := common.Address{2}
	tx := types.NewTransaction(0, address, new(big.Int), params.TxGas, big.NewInt(1), nil)
	block := types.NewBlockWithHeader(&types.Header{
		Number: big.NewInt(1), Difficulty: big.NewInt(1),
	}).WithBody(types.Transactions{tx}, nil)

	chain.head = block
	chain.recordProposedTransactions(block.Transactions(), start)
	if chain.nextProposedExpiry.IsZero() {
		t.Fatal("speculative transaction has no expiry")
	}
	revision := chain.revision
	chain.adoptCertified(block)
	if chain.revision != revision+1 {
		t.Fatalf("certification revision = %d, want %d", chain.revision, revision+1)
	}
	if len(chain.proposedTxes) != 0 || len(chain.certifiedTxes) != 1 || !chain.nextProposedExpiry.IsZero() {
		t.Fatalf("certified exclusion state = proposed %d certified %d expiry %s",
			len(chain.proposedTxes), len(chain.certifiedTxes), chain.nextProposedExpiry)
	}
	afterOldTTL := AddressTxes{address: types.Transactions{tx}}
	if got := chain.withoutProposedTxes(afterOldTTL, start.Add(1000*proposedTxTTL)); len(got) != 0 {
		t.Fatal("certified transaction expired before commit")
	}

	chain.markCommitted(block)
	if len(chain.certifiedTxes) != 0 {
		t.Fatal("committed transaction remained in certified exclusion set")
	}
	afterCommit := AddressTxes{address: types.Transactions{tx}}
	if got := chain.withoutProposedTxes(afterCommit, start.Add(1000*proposedTxTTL)); len(got[address]) != 1 {
		t.Fatal("committed transaction remained excluded")
	}
}

func TestProposalNoWorkWatermarkQuiescesIdenticalMaintenanceInputs(t *testing.T) {
	for _, fairHotstuff := range []bool{false, true} {
		mode := "legacy"
		if fairHotstuff {
			mode = "fhs"
		}
		t.Run(mode, func(t *testing.T) {
			proposedExpiry := time.Unix(1_900_000_000, 0)
			base := proposalWorkStamp{
				fairHotstuff:      fairHotstuff,
				poolRevision:      11,
				candidateRevision: 7,
				proposedRevision:  9,
				proposedExpiry:    proposedExpiry,
				parentNumber:      20,
				parentHash:        common.HexToHash("0x20"),
				keyNumber:         3,
				keyHash:           common.HexToHash("0x30"),
				view: bftview.View{
					TxNumber: 20, TxHash: common.HexToHash("0x20"),
					KeyNumber: 3, KeyHash: common.HexToHash("0x30"),
					CommitteeHash: common.HexToHash("0xc0"), LeaderIndex: 2,
					NoDone: true, Round: 4, ViewNumber: 21,
				},
				proposalView:     21,
				proposalViewID:   common.HexToHash("0x2100"),
				proposalLeaderID: "leader",
			}
			service := new(Service)
			if !service.rememberProposalNoWorkIfCurrent(base, base, true) {
				t.Fatal("failed to install exact no-work watermark")
			}
			if !service.proposalNoWorkMatchesCurrent(base, base, true) {
				t.Fatal("identical maintenance input did not remain quiescent")
			}
			if proposalNoWorkExpiryElapsed(base, proposedExpiry) {
				t.Fatal("proposed exclusion expired at the cleanup boundary")
			}
			if !proposalNoWorkExpiryElapsed(base, proposedExpiry.Add(time.Nanosecond)) {
				t.Fatal("expired proposed exclusion did not wake maintenance")
			}

			mutations := []struct {
				name   string
				mutate func(*proposalWorkStamp)
			}{
				{name: "txpool revision", mutate: func(s *proposalWorkStamp) { s.poolRevision++ }},
				{name: "candidate revision", mutate: func(s *proposalWorkStamp) { s.candidateRevision++ }},
				{name: "proposed exclusion revision", mutate: func(s *proposalWorkStamp) { s.proposedRevision++ }},
				{name: "proposed exclusion expiry", mutate: func(s *proposalWorkStamp) { s.proposedExpiry = s.proposedExpiry.Add(time.Millisecond) }},
				{name: "parent", mutate: func(s *proposalWorkStamp) { s.parentNumber++; s.parentHash = common.HexToHash("0x21") }},
				{name: "key head", mutate: func(s *proposalWorkStamp) { s.keyNumber++; s.keyHash = common.HexToHash("0x31") }},
				{name: "view", mutate: func(s *proposalWorkStamp) { s.view.ViewNumber++ }},
				{name: "finality", mutate: func(s *proposalWorkStamp) { s.finality = !s.finality }},
				{name: "key interval", mutate: func(s *proposalWorkStamp) {
					s.keyblockReady = !s.keyblockReady
					s.keyblockPending = s.keyblockReady
				}},
				{name: "proposal view", mutate: func(s *proposalWorkStamp) { s.proposalView++; s.proposalViewID = common.HexToHash("0x2200") }},
				{name: "proposal leader", mutate: func(s *proposalWorkStamp) { s.proposalLeaderID = "next-leader" }},
			}
			for _, mutation := range mutations {
				t.Run(mutation.name, func(t *testing.T) {
					service.clearProposalNoWork()
					if !service.rememberProposalNoWorkIfCurrent(base, base, true) {
						t.Fatal("failed to reinstall no-work watermark")
					}
					current := base
					mutation.mutate(&current)
					if service.proposalNoWorkMatchesCurrent(base, current, true) {
						t.Fatal("changed proposal input remained quiescent")
					}
					service.muProposalNoWork.Lock()
					marker := service.proposalNoWork
					service.muProposalNoWork.Unlock()
					if marker != nil {
						t.Fatal("changed proposal input did not clear no-work watermark")
					}
				})
			}

			// Crossing the keyblock interval is real work while the current view is
			// still in tx mode, so it must not install a suppressing marker.
			intervalReady := base
			intervalReady.keyblockReady = true
			intervalReady.keyblockPending = true
			if service.rememberProposalNoWorkIfCurrent(intervalReady, intervalReady, true) {
				t.Fatal("pending keyblock trigger installed a no-work watermark")
			}
			service.muProposalNoWork.Lock()
			pendingMarker := service.proposalNoWork
			service.muProposalNoWork.Unlock()
			if pendingMarker != nil {
				t.Fatal("pending keyblock trigger left a no-work watermark")
			}

			// Local proposal-mode changes cannot suppress a due fixed keyblock.
			afterKeyWake := intervalReady
			afterKeyWake.view.NoDone = false
			if service.rememberProposalNoWorkIfCurrent(afterKeyWake, afterKeyWake, true) {
				t.Fatal("keyblock wake installed a no-work watermark")
			}

			// A new canonical key head resets the interval and may quiesce normally.
			afterKeyCommit := afterKeyWake
			afterKeyCommit.keyNumber++
			afterKeyCommit.keyHash = common.HexToHash("0x31")
			afterKeyCommit.keyblockReady = false
			afterKeyCommit.keyblockPending = false
			if !service.rememberProposalNoWorkIfCurrent(afterKeyCommit, afterKeyCommit, true) {
				t.Fatal("failed to install post-keyblock-commit watermark")
			}
			if !service.proposalNoWorkMatchesCurrent(afterKeyCommit, afterKeyCommit, true) {
				t.Fatal("post-keyblock-commit no-work state did not quiesce")
			}

			// A stale concurrent comparison must not erase a newer bounded marker.
			newer := afterKeyCommit
			newer.poolRevision++
			if !service.rememberProposalNoWorkIfCurrent(newer, newer, true) {
				t.Fatal("failed to replace bounded watermark")
			}
			if service.proposalNoWorkMatchesCurrent(afterKeyCommit, afterKeyCommit, true) {
				t.Fatal("stale comparison matched newer watermark")
			}
			service.muProposalNoWork.Lock()
			kept := service.proposalNoWork != nil && *service.proposalNoWork == newer
			service.muProposalNoWork.Unlock()
			if !kept {
				t.Fatal("stale comparison erased newer watermark")
			}
		})
	}
}

func TestProposalBodyWaitTimeoutScalesWithBody(t *testing.T) {
	if got := proposalBodyWaitTimeoutForConfig(nil, 0); got != 2*time.Second {
		t.Fatalf("empty body timeout = %s, want 2s", got)
	}
	if got := proposalBodyWaitTimeoutForConfig(nil, 16*1024*1024); got != 10*time.Second {
		t.Fatalf("16MiB body timeout = %s, want 10s", got)
	}
	if got := proposalBodyWaitTimeoutForConfig(nil, 256*1024*1024); got != 30*time.Second {
		t.Fatalf("large body timeout = %s, want 30s cap", got)
	}
}

func TestProposalGenerationRejectsStaleConstruction(t *testing.T) {
	parent := types.NewBlockWithHeader(&types.Header{
		Number: big.NewInt(9), Root: common.HexToHash("0x900"), Difficulty: big.NewInt(1),
	})
	keyBlock := types.NewKeyBlock(&types.KeyBlockHeader{
		Number: big.NewInt(3), Difficulty: big.NewInt(1),
	})
	chain := newProposedChain()
	chain.clear(parent)
	generation := proposalGeneration{
		proposedRevision:            chain.revision,
		admissionFinalityGeneration: 7,
		parentHash:                  parent.Hash(),
		parentRoot:                  parent.Root(),
		parentNumber:                parent.NumberU64(),
		keyHash:                     keyBlock.Hash(),
		keyNumber:                   keyBlock.NumberU64(),
	}
	if !generation.matches(chain.revision, 7, parent, keyBlock) {
		t.Fatal("fresh proposal generation was rejected")
	}
	if generation.matches(chain.revision, 8, parent, keyBlock) {
		t.Fatal("proposal generation survived an admission-finality publication")
	}

	child := types.NewBlockWithHeader(&types.Header{
		ParentHash: parent.Hash(), Number: big.NewInt(10), Root: common.HexToHash("0x901"), Difficulty: big.NewInt(1),
	})
	chain.extend(child)
	if generation.matches(chain.revision, 7, parent, keyBlock) {
		t.Fatal("proposal generation survived a concurrent proposed-chain update")
	}
	if generation.matches(generation.proposedRevision, 7, child, keyBlock) {
		t.Fatal("proposal generation survived a parent change")
	}
	nextKeyBlock := types.NewKeyBlock(&types.KeyBlockHeader{
		Number: big.NewInt(4), Difficulty: big.NewInt(1),
	})
	if generation.matches(generation.proposedRevision, 7, parent, nextKeyBlock) {
		t.Fatal("proposal generation survived a key-committee change")
	}
}

func proposalBuildRequestForTest(view uint64) *hotstuff.FHSProposalBuildRequest {
	state := []byte{byte(view), 0xa5}
	return &hotstuff.FHSProposalBuildRequest{
		Key: hotstuff.FHSProposalBuildKey{
			RequestID:          view,
			ViewNumber:         view,
			ViewID:             common.BigToHash(new(big.Int).SetUint64(view)),
			LeaderID:           "leader",
			CurrentStateDigest: hotstuff.StateDigest(state),
		},
		CurrentState: state,
	}
}

func TestProposalBuildSchedulerKeepsOnlyLatestWaitingView(t *testing.T) {
	service := &Service{
		runningState:                 1,
		proposalBuildJobs:            make(chan *proposalBuildJob, proposalBuildQueueCapacity),
		proposalBuildResults:         make(chan *hotstuff.FHSProposalBuildResult, proposalBuildWorkers+1),
		proposalValidationGeneration: 1,
	}
	at := time.Unix(1_800_000_000, 0)
	service.recordTxProposalPublication(types.FastTx_Block, at)
	serviceState := service.txLaneService
	first := proposalBuildRequestForTest(11)
	if err := service.ScheduleFHSProposalBuild(first); err != nil {
		t.Fatal(err)
	}
	firstJob := <-service.proposalBuildJobs // simulate the first non-interruptible worker starting
	second := proposalBuildRequestForTest(12)
	if err := service.ScheduleFHSProposalBuild(second); err != nil {
		t.Fatal(err)
	}
	secondJob := <-service.proposalBuildJobs
	service.proposalBuildJobs <- secondJob // leave it waiting so the next request must replace it
	third := proposalBuildRequestForTest(13)
	if err := service.ScheduleFHSProposalBuild(third); err != nil {
		t.Fatal(err)
	}
	select {
	case <-firstJob.ctx.Done():
	default:
		t.Fatal("superseded running proposal construction was not cancelled")
	}
	select {
	case <-secondJob.ctx.Done():
	default:
		t.Fatal("superseded queued proposal construction was not cancelled")
	}
	if len(service.proposalBuildJobs) != 1 || service.activeProposalBuild == nil || service.activeProposalBuild.key != third.Key {
		t.Fatalf("latest-wins scheduler state: queued=%d active=%#v", len(service.proposalBuildJobs), service.activeProposalBuild)
	}
	if proposalBuildWorkers != 2 || cap(service.proposalBuildJobs) != 1 {
		t.Fatalf("proposal construction bounds = workers %d queue %d, want 2/1", proposalBuildWorkers, cap(service.proposalBuildJobs))
	}
	if service.txLaneService != serviceState || service.lastFastBlockTime != at || !service.lastSlowBlockTime.IsZero() {
		t.Fatal("queued or cancelled construction consumed publication service")
	}
}

func TestEpochTransitionGateRejectsBuildsUntilSyncCommitFinishes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	service := &Service{
		runningState:                 1,
		proposalValidationGeneration: 1,
		proposalBuildJobs:            make(chan *proposalBuildJob, 1),
		activeProposalBuild:          &proposalBuildControl{cancel: cancel},
	}
	service.invalidateProposalBuildsForEpochTransition()
	if atomic.LoadInt32(&service.fhsEpochTransition) == 0 || service.proposalValidationGeneration != 2 || service.activeProposalBuild != nil {
		t.Fatal("epoch transition did not invalidate the old proposal generation")
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("epoch transition did not cancel the active proposal worker")
	}
	request := proposalBuildRequestForTest(12)
	if err := service.ScheduleFHSProposalBuild(request); !errors.Is(err, hotstuff.ErrOldState) {
		t.Fatalf("build scheduled between before-hook and canonical key mutation: %v", err)
	}
	if err := service.acquireFHSValidationPublication(fhsValidationPublicationSyncTransition); err != nil {
		t.Fatal(err)
	}
	service.finishFHSFinalizedSyncKeyCommit(nil, core.FHSFinalizedSyncPreCommitFailed)
	if atomic.LoadInt32(&service.fhsEpochTransition) != 0 {
		t.Fatal("failed sync commit did not release the epoch transition gate")
	}
	if err := service.ScheduleFHSProposalBuild(request); err != nil {
		t.Fatalf("build did not resume after sync commit cleanup: %v", err)
	}
}

func TestSyncEpochTransitionFailsFastBehindLivePublication(t *testing.T) {
	service := &Service{runningState: 1}
	if err := service.acquireFHSValidationPublication(fhsValidationPublicationHighQC); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	acquired, err := service.beforeFHSFinalizedSyncKeyCommit(nil, nil)
	if acquired {
		t.Fatal("contended sync transition claimed the live publication barrier")
	}
	if !errors.Is(err, errFHSValidationPublicationBusy) {
		t.Fatalf("contended sync transition error = %v, want %v", err, errFHSValidationPublicationBusy)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("contended sync transition waited behind live publication for %s", elapsed)
	}
	if atomic.LoadInt32(&service.fhsValidationPublicationOwner) != int32(fhsValidationPublicationHighQC) {
		t.Fatal("contended sync transition changed the live publication owner")
	}
	waitStarted := make(chan struct{})
	waitReturned := make(chan struct{})
	go func() {
		close(waitStarted)
		service.waitFHSValidationPublication()
		close(waitReturned)
	}()
	<-waitStarted
	select {
	case <-waitReturned:
		t.Fatal("publication wait returned before the live owner released the barrier")
	case <-time.After(20 * time.Millisecond):
	}
	if !service.releaseFHSValidationPublication(fhsValidationPublicationHighQC) {
		t.Fatal("failed to release live publication after contention test")
	}
	select {
	case <-waitReturned:
	case <-time.After(time.Second):
		t.Fatal("publication wait did not return after live owner release")
	}
	if err := service.tryAcquireFHSValidationPublication(fhsValidationPublicationSyncTransition); err != nil {
		t.Fatalf("sync transition did not acquire after live publication released: %v", err)
	}
	if atomic.LoadInt32(&service.fhsValidationPublicationOwner) != int32(fhsValidationPublicationSyncTransition) {
		t.Fatal("retry did not install the sync transition publication owner")
	}
	if !service.releaseFHSValidationPublication(fhsValidationPublicationSyncTransition) {
		t.Fatal("failed to release sync publication after successful retry")
	}
}

func TestEpochTransitionPostCanonicalFailureStaysFailClosed(t *testing.T) {
	service := &Service{
		runningState:                 1,
		proposalValidationGeneration: 1,
		fhsEpochTransition:           1,
	}
	if err := service.acquireFHSValidationPublication(fhsValidationPublicationSyncTransition); err != nil {
		t.Fatal(err)
	}
	service.finishFHSFinalizedSyncKeyCommit(nil, core.FHSFinalizedSyncCanonicalAfterFailed)
	if atomic.LoadInt32(&service.runningState) != 0 {
		t.Fatal("post-canonical lifecycle failure left consensus running")
	}
	if atomic.LoadInt32(&service.fhsEpochTransition) == 0 {
		t.Fatal("post-canonical lifecycle failure reopened the epoch transition gate")
	}
	if atomic.LoadUint64(&service.proposalValidationGeneration) != 2 {
		t.Fatal("post-canonical lifecycle failure did not invalidate in-flight work")
	}
}

func TestEpochTransitionSuccessfulCommitReopensGate(t *testing.T) {
	service := &Service{
		runningState:                 1,
		proposalValidationGeneration: 1,
		fhsEpochTransition:           1,
	}
	if err := service.acquireFHSValidationPublication(fhsValidationPublicationSyncTransition); err != nil {
		t.Fatal(err)
	}
	service.finishFHSFinalizedSyncKeyCommit(nil, core.FHSFinalizedSyncCompleted)
	if atomic.LoadInt32(&service.runningState) != 1 {
		t.Fatal("successful lifecycle completion stopped consensus")
	}
	if atomic.LoadInt32(&service.fhsEpochTransition) != 0 {
		t.Fatal("successful lifecycle completion did not reopen the epoch transition gate")
	}
}

func proposalValidationPublicationFixture() (*Service, *hotstuff.FHSProposalValidationResult) {
	viewID := common.HexToHash("0x200")
	parentHash := common.HexToHash("0x100")
	block := types.NewBlockWithHeader(&types.Header{
		ParentHash: parentHash,
		Number:     big.NewInt(1),
		Difficulty: big.NewInt(1),
	})
	ref := &types.HotstuffProposalRef{
		Version:    types.HotstuffProposalRefVersion,
		ChainID:    1,
		Number:     block.NumberU64(),
		ViewNumber: 2,
		ViewID:     viewID,
		LeaderID:   "leader",
		BlockHash:  block.Hash(),
		ParentHash: parentHash,
		BodyHash:   common.HexToHash("0x300"),
		BodySize:   1,
		ExtraHash:  types.HotstuffProposalExtraHash(nil),
	}
	key := hotstuff.FHSProposalValidationKey{
		RequestID: 1, ViewNumber: ref.ViewNumber, ViewID: ref.ViewID,
		LeaderID: ref.LeaderID, ProposalID: ref.ProposalID(),
	}
	output := &proposalValidationOutput{
		ref: ref,
		verified: &core.VerifiedProposal{
			ProposalID: key.ProposalID, ViewNumber: ref.ViewNumber, ViewID: ref.ViewID, LeaderID: ref.LeaderID,
			Block: block, ParentHash: parentHash, ParentNumber: 0,
		},
		serviceGeneration:    1,
		validationGeneration: 1,
	}
	service := &Service{
		runningState:                 1,
		proposalValidationGeneration: 1,
		activeProposalValidation:     &proposalValidationControl{key: key, generation: 1},
		proposalBodies:               make(map[common.Hash]*proposalBodyMsg),
		verifiedProposalByID:         make(map[common.Hash]*core.VerifiedProposal),
		fhsCertifiedByID:             make(map[common.Hash]*fhsCertifiedProposal),
		pacetMakerTimer:              &paceMakerTimer{},
	}
	return service, &hotstuff.FHSProposalValidationResult{Key: key, ApplicationData: output}
}

func TestFHSProposalValidationApplyTransfersPublicationBarrier(t *testing.T) {
	service, result := proposalValidationPublicationFixture()
	if err := service.ApplyFHSProposalValidation(result); err != nil {
		t.Fatalf("apply verified proposal: %v", err)
	}
	if service.muFHSValidationPublication.TryLock() {
		service.muFHSValidationPublication.Unlock()
		t.Fatal("sync transition entered between validation Apply and manager vote completion")
	}
	service.FinishFHSProposalValidation(result)
	if !service.muFHSValidationPublication.TryLock() {
		t.Fatal("validation publication barrier remained locked after manager Finish")
	}
	service.muFHSValidationPublication.Unlock()
}

func TestFHSProposalValidationApplyFailureReleasesPublicationBarrier(t *testing.T) {
	service, result := proposalValidationPublicationFixture()
	output := result.ApplicationData.(*proposalValidationOutput)
	output.serviceGeneration++
	if err := service.ApplyFHSProposalValidation(result); !errors.Is(err, hotstuff.ErrOldState) {
		t.Fatalf("stale proposal validation error = %v, want %v", err, hotstuff.ErrOldState)
	}
	if !service.muFHSValidationPublication.TryLock() {
		t.Fatal("failed proposal validation retained the publication barrier")
	}
	service.muFHSValidationPublication.Unlock()
}

func TestFHSHighQCFinishReleasesOnlyExactPublication(t *testing.T) {
	service := new(Service)
	result := &hotstuff.FHSHighQCValidationResult{Key: hotstuff.FHSHighQCValidationKey{RequestID: 1}}
	other := &hotstuff.FHSHighQCValidationResult{Key: result.Key}
	if err := service.acquireFHSValidationPublication(fhsValidationPublicationHighQC); err != nil {
		t.Fatal(err)
	}
	service.activeHighQCValidationPublish = result
	service.FinishFHSHighQCValidation(other)
	if service.muFHSValidationPublication.TryLock() {
		service.muFHSValidationPublication.Unlock()
		t.Fatal("mismatched HighQC result released the publication barrier")
	}
	service.FinishFHSHighQCValidation(result)
	if !service.muFHSValidationPublication.TryLock() {
		t.Fatal("exact HighQC manager completion did not release the publication barrier")
	}
	service.muFHSValidationPublication.Unlock()
}

func TestFHSHighQCApplyFailureReleasesPublicationBarrier(t *testing.T) {
	key := hotstuff.FHSHighQCValidationKey{RequestID: 1, TargetView: 2, QCID: common.HexToHash("0x1")}
	service := &Service{proposalValidationGeneration: 1}
	result := &hotstuff.FHSHighQCValidationResult{
		Key: key,
		ApplicationData: &fhsHighQCValidationOutput{
			key: key, serviceGeneration: 1,
		},
	}
	if err := service.ApplyFHSHighQCValidation(result); !errors.Is(err, hotstuff.ErrOldState) {
		t.Fatalf("stopped HighQC validation error = %v, want %v", err, hotstuff.ErrOldState)
	}
	if !service.muFHSValidationPublication.TryLock() {
		t.Fatal("failed HighQC validation retained the publication barrier")
	}
	service.muFHSValidationPublication.Unlock()
}

func TestProposalCadenceConcurrentWorkerReadAndPublish(t *testing.T) {
	service := &Service{chainConfig: &params.ChainConfig{FairHotstuff: true, FairHotstuffSlotMillis: 250}}
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(2)
		go func(offset int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				now := time.Unix(0, int64(offset*1000+i+1))
				lane := uint8(types.FastTx_Block)
				if i%2 != 0 {
					lane = types.SlowTx_Block
				}
				service.recordTxProposalPublication(lane, now)
			}
		}(worker)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				service.shouldEmitFastBlock(time.Now())
				service.shouldEmitSlowBlock(time.Now(), i)
				service.chooseTxBlockTypeForPending(time.Now(), 100, 8192)
			}
		}()
	}
	wg.Wait()
}

func TestStoppedServiceWriteAndBroadcastFailClosed(t *testing.T) {
	service := &Service{}
	msg := &hotstuff.HotstuffMessage{Code: hotstuff.MsgTryPropose}
	if err := service.Write("self", msg); !errors.Is(err, types.ErrNotRunning) {
		t.Fatalf("stopped Write error = %v, want %v", err, types.ErrNotRunning)
	}
	errs := service.Broadcast(msg)
	if len(errs) != 1 || !errors.Is(errs[0], types.ErrNotRunning) {
		t.Fatalf("stopped Broadcast errors = %v, want %v", errs, types.ErrNotRunning)
	}
}

func proposalBuildApplyFixture(key hotstuff.FHSProposalBuildKey) (*Service, *proposalBuildOutput, *hotstuff.FHSProposalBuildResult) {
	body := &proposalBodyMsg{ProposalID: common.HexToHash("0x11"), BodyHash: common.HexToHash("0x12"), BodySize: 1}
	manifest := &proposalBodyMsg{ProposalID: body.ProposalID, BodyHash: body.BodyHash, BodySize: 1, Type: proposalBodyMsgManifest}
	output := &proposalBuildOutput{
		stagedHotstuffProposal: stagedHotstuffProposal{proposalRef: []byte{0x01}, body: body, manifest: manifest},
		key:                    key,
		serviceGeneration:      1,
		constructionGeneration: 7,
	}
	service := &Service{
		runningState:                 1,
		proposalValidationGeneration: 1,
		activeProposalBuild:          &proposalBuildControl{key: key, generation: 7},
		proposalManifestSlots:        make(chan struct{}, 1),
		proposalManifestJobs:         make(chan *proposalManifestDispatch, 1),
		proposalFailedTxSlots:        make(chan struct{}, 1),
		proposalFailedTxJobs:         make(chan *proposalFailedTxCleanup, 1),
	}
	result := &hotstuff.FHSProposalBuildResult{Key: key, TProposal: []byte{0x01}, ApplicationData: output}
	return service, output, result
}

func TestProposalBuildTimeoutOnlyViewAdvancePublishesNothing(t *testing.T) {
	request := proposalBuildRequestForTest(12)
	service, output, result := proposalBuildApplyFixture(request.Key)
	service.currentView.ViewNumber = 10 // request targets 12; exact next view is 11
	service.replicaView = &service.currentView

	db := rawdb.NewMemoryDatabase()
	bftview.SetCommitteeConfig(db, nil, nil)
	committee := &bftview.Committee{List: []*common.Cnode{{Address: "127.0.0.1:1", Public: "01"}}}
	keyBlock := types.NewKeyBlock(&types.KeyBlockHeader{
		Number: big.NewInt(2), Difficulty: big.NewInt(1), CommitteeHash: committee.RlpHash(),
	})
	output.keyCandidate = &keyProposalCandidate{}
	output.keyBlock = keyBlock
	output.committee = committee

	err := service.ApplyFHSProposalBuild(result)
	if !errors.Is(err, hotstuff.ErrOldState) {
		t.Fatalf("timeout-stale Apply error = %v, want %v", err, hotstuff.ErrOldState)
	}
	if len(service.proposalManifestJobs) != 0 || len(service.proposalManifestSlots) != 0 ||
		bftview.LoadMember(keyBlock.NumberU64(), keyBlock.Hash(), true) != nil {
		t.Fatal("timeout-stale result dispatched a manifest or stored a committee")
	}

	txService, txOutput, txResult := proposalBuildApplyFixture(request.Key)
	txService.currentView.ViewNumber = 10
	txService.replicaView = &txService.currentView
	txOutput.txCandidate = &txProposalCandidate{
		failedTxes: types.Transactions{types.NewTransaction(0, common.HexToAddress("0x1"), big.NewInt(1), 21_000, big.NewInt(1), nil)},
	}
	if err := txService.ApplyFHSProposalBuild(txResult); !errors.Is(err, hotstuff.ErrOldState) {
		t.Fatalf("timeout-stale tx Apply error = %v, want %v", err, hotstuff.ErrOldState)
	}
	if len(txService.proposalManifestJobs) != 0 || len(txService.proposalManifestSlots) != 0 ||
		len(txService.proposalFailedTxJobs) != 0 || len(txService.proposalFailedTxSlots) != 0 {
		t.Fatal("timeout-stale tx result published proposed-chain maintenance, manifest, or failed-TX GC")
	}
}

func TestProposalBuildQueueSaturationFailsBeforePublication(t *testing.T) {
	request := proposalBuildRequestForTest(11)
	service, output, result := proposalBuildApplyFixture(request.Key)
	output.txCandidate = &txProposalCandidate{}
	service.proposalManifestSlots <- struct{}{} // reserve the sole slot for earlier accepted work

	err := service.ApplyFHSProposalBuild(result)
	if err == nil || err.Error() != "proposal manifest dispatch queue saturated" {
		t.Fatalf("saturated Apply error = %v", err)
	}
	if len(service.proposalManifestJobs) != 0 || len(service.proposalManifestSlots) != 1 {
		t.Fatal("queue saturation consumed a reservation or published a manifest")
	}
}

func TestProposalBuildStopInvalidatesCompletionBeforePublication(t *testing.T) {
	request := proposalBuildRequestForTest(11)
	service, output, result := proposalBuildApplyFixture(request.Key)
	output.txCandidate = &txProposalCandidate{}
	service.setRunState(0)
	if err := service.ApplyFHSProposalBuild(result); !errors.Is(err, hotstuff.ErrOldState) {
		t.Fatalf("stopped construction Apply error = %v, want %v", err, hotstuff.ErrOldState)
	}
	if service.activeProposalBuild != nil || len(service.proposalManifestJobs) != 0 || len(service.proposalFailedTxJobs) != 0 {
		t.Fatal("stopped construction remained active or published maintenance")
	}
}

func TestProposalBuildPublicationBarrierLinearizesStop(t *testing.T) {
	service := &Service{
		runningState:                 1,
		proposalValidationGeneration: 1,
		proposalBuildJobs:            make(chan *proposalBuildJob, 1),
	}
	output := &proposalBuildOutput{publicationLocksHeld: true}
	result := &hotstuff.FHSProposalBuildResult{ApplicationData: output}
	service.muProposalBuild.Lock()
	service.muCurrentView.Lock()

	started := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		close(started)
		service.setRunState(0)
		close(stopped)
	}()
	<-started
	select {
	case <-stopped:
		t.Fatal("Stop crossed the Apply-to-Broadcast publication barrier")
	case <-time.After(20 * time.Millisecond):
	}
	service.FinishFHSProposalBuild(result)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Stop did not complete after proposal publication finished")
	}
	if service.runningState != 0 || output.publicationLocksHeld {
		t.Fatal("publication barrier did not release into the stopped generation")
	}
}

func TestProposalManifestDispatcherDropsPriorLifecycleGeneration(t *testing.T) {
	service := &Service{
		runningState:                 1,
		proposalValidationGeneration: 2,
		proposalManifestSlots:        make(chan struct{}, 1),
		proposalManifestJobs:         make(chan *proposalManifestDispatch, 1),
	}
	service.proposalManifestSlots <- struct{}{}
	go service.proposalManifestDispatchWorker()
	service.proposalManifestJobs <- &proposalManifestDispatch{
		body:              &proposalBodyMsg{ProposalID: common.HexToHash("0x1")},
		destinations:      []string{"would-panic-without-generation-check"},
		serviceGeneration: 1,
	}
	deadline := time.After(time.Second)
	for len(service.proposalManifestSlots) != 0 {
		select {
		case <-deadline:
			t.Fatal("stale manifest dispatch reservation was not released")
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func TestProposalFailedTxCleanupRunsExactlyOnceForAcceptedGeneration(t *testing.T) {
	called := make(chan types.Transactions, 1)
	service := &Service{
		runningState:                 1,
		proposalValidationGeneration: 3,
		proposalFailedTxSlots:        make(chan struct{}, 1),
		proposalFailedTxJobs:         make(chan *proposalFailedTxCleanup, 1),
		removeFailedProposalTxs: func(txs types.Transactions) {
			called <- append(types.Transactions(nil), txs...)
		},
	}
	txs := types.Transactions{types.NewTransaction(0, common.HexToAddress("0x1"), big.NewInt(1), 21_000, big.NewInt(1), nil)}
	service.proposalFailedTxSlots <- struct{}{}
	go service.proposalFailedTxCleanupWorker()
	service.proposalFailedTxJobs <- &proposalFailedTxCleanup{txs: txs, serviceGeneration: 3}
	select {
	case got := <-called:
		if len(got) != 1 || got[0].Hash() != txs[0].Hash() {
			t.Fatalf("failed-TX cleanup payload = %v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("accepted failed-TX cleanup did not run")
	}
	select {
	case duplicate := <-called:
		t.Fatalf("failed-TX cleanup ran more than once: %v", duplicate)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestSlotLaneServiceBoundsBuildableBacklogs(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	for _, test := range []struct {
		name       string
		fast, slow int
		wantFast   int
	}{
		{"balanced", 100, 100, 12},
		{"fast twice slow", 200, 100, 16},
		{"generic perp fast", 350_000, 150_000, 18},
		{"recognized slow perp", 100_000, 400_000, 6},
		{"emergency slow still serves fast", 1, 8192, 6},
		{"extreme fast still serves slow", math.MaxInt, 1, 18},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &Service{chainConfig: &params.ChainConfig{FairHotstuff: true, FairHotstuffSlotMillis: 250},
				lastFastBlockTime: start, lastSlowBlockTime: start}
			var sequence []uint8
			fastCount := 0
			for proposal := 0; proposal < 24; proposal++ {
				now := start.Add(time.Duration(proposal+1) * time.Millisecond)
				lane := service.chooseTxBlockTypeForPending(now, test.fast, test.slow)
				// Both modeled lanes are continuously buildable. Only successful
				// publication charges the service, exactly as Apply does below.
				service.recordTxProposalPublication(lane, now)
				sequence = append(sequence, lane)
				if lane == types.FastTx_Block {
					fastCount++
				}
				if len(sequence) >= 4 {
					window := sequence[len(sequence)-4:]
					allSame := true
					for _, observed := range window[1:] {
						allSame = allSame && observed == window[0]
					}
					if allSame {
						t.Fatalf("four published proposals omitted a buildable lane: %v", sequence)
					}
				}
			}
			if fastCount != test.wantFast {
				t.Fatalf("successful fast/slow services = %d/%d, want %d/%d; sequence=%v",
					fastCount, 24-fastCount, test.wantFast, 24-test.wantFast, sequence)
			}
		})
	}
}

func TestSlotLaneServiceAgingAndLegacyCadence(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, test := range []struct {
		name               string
		fast, slow         int
		fastTime, slowTime time.Time
		service            txLaneService
		want               uint8
	}{
		{"slow age beats fast preference", 1000, 1, now, now.Add(-txLaneServiceAge), txLaneService{}, types.SlowTx_Block},
		{"fast age beats slow preference", 1, 1000, now.Add(-txLaneServiceAge), now, txLaneService{}, types.FastTx_Block},
		{"slow below age retains preference", 1000, 1, now, now.Add(-txLaneServiceAge + time.Nanosecond), txLaneService{}, types.FastTx_Block},
		{"never served fast", 1, 1000, time.Time{}, now, txLaneService{}, types.FastTx_Block},
		{"never served slow", 1000, 1, now, time.Time{}, txLaneService{}, types.SlowTx_Block},
		{"oldest fast", 1, 1000, now.Add(-2 * txLaneServiceAge), now.Add(-txLaneServiceAge), txLaneService{}, types.FastTx_Block},
		{"bound beats age", 1000, 1, now.Add(-2 * txLaneServiceAge), now.Add(-txLaneServiceAge), txLaneService{types.FastTx_Block, 3}, types.SlowTx_Block},
		{"fast only", 1, 0, now, time.Time{}, txLaneService{types.FastTx_Block, 3}, types.FastTx_Block},
		{"slow only", 0, 1, time.Time{}, now, txLaneService{types.SlowTx_Block, 3}, types.SlowTx_Block},
		{"both empty retains fallback", 0, 0, now, now, txLaneService{}, types.FastTx_Block},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &Service{chainConfig: &params.ChainConfig{FairHotstuff: true, FairHotstuffSlotMillis: 250},
				lastFastBlockTime: test.fastTime, lastSlowBlockTime: test.slowTime, txLaneService: test.service}
			for attempt := 0; attempt < 8; attempt++ {
				if got := service.chooseTxBlockTypeForPending(now, test.fast, test.slow); got != test.want {
					t.Fatalf("lane = %s, want %s", readableTxBlockType(got), readableTxBlockType(test.want))
				}
			}
			if service.lastFastBlockTime != test.fastTime || service.lastSlowBlockTime != test.slowTime || service.txLaneService != test.service {
				t.Fatal("choosing a lane charged publication service or reset age")
			}
		})
	}
	// The legacy emergency policy and fast-first normal cadence are retained
	// for omission/zero; a clock field without FHS also does not enable fairness.
	for _, config := range []*params.ChainConfig{nil, {FairHotstuff: true}, {FairHotstuffSlotMillis: 250}} {
		service := &Service{chainConfig: config, lastFastBlockTime: now.Add(-time.Second), lastSlowBlockTime: now,
			txLaneService: txLaneService{types.SlowTx_Block, 3}}
		if got := service.chooseTxBlockTypeForPending(now, 1, 8192); got != types.SlowTx_Block {
			t.Fatalf("legacy emergency lane = %s", readableTxBlockType(got))
		}
		if got := service.chooseTxBlockTypeForPending(now, 100, 100); got != types.FastTx_Block {
			t.Fatalf("legacy normal lane = %s", readableTxBlockType(got))
		}
	}
}

func slotLanePublicationFixture(t *testing.T, lane uint8) (*Service, *proposalBuildOutput, *hotstuff.FHSProposalBuildResult) {
	t.Helper()
	txs, keyBlock := newPrevRandaoProposalFixture(t)
	parent := txs.bc.CurrentBlock()
	view := bftview.View{ViewNumber: 10, TxNumber: parent.NumberU64(), TxHash: parent.Hash(),
		KeyNumber: keyBlock.NumberU64(), KeyHash: keyBlock.Hash(), CommitteeHash: keyBlock.CommitteeHash()}
	key := hotstuff.FHSProposalBuildKey{RequestID: 1, ViewNumber: 11,
		CurrentStateDigest: hotstuff.StateDigest(view.EncodeConsensusToBytes()), LeaderID: bftview.GetNodeID("validator", "")}
	service, output, result := proposalBuildApplyFixture(key)
	service.chainConfig = &params.ChainConfig{FairHotstuff: true, FairHotstuffSlotMillis: 250}
	service.currentView, service.replicaView = view, &view
	service.txService, service.bc, service.kbc = txs, txs.bc, txs.kbc
	service.netService = &netService{serverID: key.LeaderID}
	block := types.NewBlockWithHeader(&types.Header{ParentHash: parent.Hash(), Number: big.NewInt(1),
		Difficulty: big.NewInt(1), BlockType: lane, KeyHash: keyBlock.Hash()})
	output.txCandidate = &txProposalCandidate{block: block, encoded: block.EncodeToBytes(), blockType: lane,
		generation: proposalGeneration{proposedRevision: txs.proposedChain.revision,
			admissionFinalityGeneration: core.CommonRPCAdmissionFinalityGeneration(),
			parentHash:                  parent.Hash(), parentRoot: parent.Root(), parentNumber: parent.NumberU64(),
			keyHash: keyBlock.Hash(), keyNumber: keyBlock.NumberU64()}}
	output.blockType = lane
	return service, output, result
}

func TestSlotLaneServiceChargesActualSuccessfulPublication(t *testing.T) {
	service, output, result := slotLanePublicationFixture(t, types.SlowTx_Block)
	before := time.Now()
	service.lastSlowBlockTime = before
	service.recordTxProposalPublication(types.FastTx_Block, before)
	// The preferred lane can be empty, stale or otherwise unbuildable; the
	// unchanged builder may return a slow fallback candidate. Charge that lane.
	if got := service.chooseTxBlockTypeForPending(before, 100, 1); got != types.FastTx_Block {
		t.Fatal("fast backlog did not receive the primary preference")
	}
	if err := service.ApplyFHSProposalBuild(result); err != nil {
		t.Fatalf("actual candidate publication failed: %v", err)
	}
	service.FinishFHSProposalBuild(result)
	if service.txService.proposedChain.head != output.txCandidate.block || len(service.proposalManifestJobs) != 1 {
		t.Fatal("successful Apply did not publish the candidate and dispatch its manifest")
	}
	if service.lastFastBlockTime != before || service.lastSlowBlockTime.Before(before) ||
		service.txLaneService != (txLaneService{types.SlowTx_Block, 1}) {
		t.Fatal("publication charged the preferred lane instead of the actual candidate")
	}
	state, fastTime, slowTime := service.txLaneService, service.lastFastBlockTime, service.lastSlowBlockTime
	service.FinishFHSProposalBuild(result)
	if service.txLaneService != state || service.lastFastBlockTime != fastTime || service.lastSlowBlockTime != slowTime {
		t.Fatal("duplicate Finish charged a second service")
	}
}

func TestSlotLaneServiceRejectsUnpublishedWorkerResults(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Service, *proposalBuildOutput, *hotstuff.FHSProposalBuildResult)
	}{
		{"no work", func(_ *Service, _ *proposalBuildOutput, r *hotstuff.FHSProposalBuildResult) {
			r.Err = errProposalNoWork
		}},
		{"execution error", func(_ *Service, _ *proposalBuildOutput, r *hotstuff.FHSProposalBuildResult) {
			r.Err = errors.New("execution failed")
		}},
		{"cancelled", func(_ *Service, _ *proposalBuildOutput, r *hotstuff.FHSProposalBuildResult) { r.Err = context.Canceled }},
		{"old construction", func(s *Service, _ *proposalBuildOutput, _ *hotstuff.FHSProposalBuildResult) {
			s.activeProposalBuild.generation++
		}},
		{"old service", func(s *Service, _ *proposalBuildOutput, _ *hotstuff.FHSProposalBuildResult) {
			s.proposalValidationGeneration++
		}},
		{"old view", func(s *Service, _ *proposalBuildOutput, _ *hotstuff.FHSProposalBuildResult) {
			s.currentView.ViewNumber++
		}},
		{"old transaction generation", func(_ *Service, o *proposalBuildOutput, _ *hotstuff.FHSProposalBuildResult) {
			o.txCandidate.generation.proposedRevision++
		}},
		{"manifest full", func(s *Service, _ *proposalBuildOutput, _ *hotstuff.FHSProposalBuildResult) {
			s.proposalManifestSlots <- struct{}{}
		}},
		{"stopped", func(s *Service, _ *proposalBuildOutput, _ *hotstuff.FHSProposalBuildResult) { s.setRunState(0) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, output, result := slotLanePublicationFixture(t, types.SlowTx_Block)
			at := time.Unix(1_800_000_000, 0)
			service.recordTxProposalPublication(types.FastTx_Block, at)
			state := service.txLaneService
			test.mutate(service, output, result)
			if err := service.ApplyFHSProposalBuild(result); err == nil {
				service.FinishFHSProposalBuild(result)
				t.Fatal("invalid worker result published")
			}
			if service.txLaneService != state || service.lastFastBlockTime != at || !service.lastSlowBlockTime.IsZero() ||
				len(service.proposalManifestJobs) != 0 || service.txService.proposedChain.head == output.txCandidate.block {
				t.Fatal("unpublished worker result consumed a service opportunity")
			}
		})
	}
}

func TestSlotLaneFallbackDoesNotCreditUnbuiltLane(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	service := &Service{chainConfig: &params.ChainConfig{FairHotstuff: true, FairHotstuffSlotMillis: 250},
		lastFastBlockTime: now, lastSlowBlockTime: now}
	for fallback := 0; fallback < 6; fallback++ {
		service.recordTxProposalPublication(types.FastTx_Block, now)
	}
	if service.txLaneService.consecutive != txLaneMaxConsecutive {
		t.Fatal("fallback service counter did not saturate")
	}
	for attempt := 0; attempt < 4; attempt++ {
		if got := service.chooseTxBlockTypeForPending(now, 1000, 1); got != types.SlowTx_Block {
			t.Fatal("repeated fast fallback spent the slow lane's next primary opportunity")
		}
	}
	service.recordTxProposalPublication(types.SlowTx_Block, now)
	if service.txLaneService != (txLaneService{types.SlowTx_Block, 1}) {
		t.Fatal("the first buildable slow publication did not reset bounded preference")
	}
}

func TestSlotLaneResearchProfileSelectsAndExecutesTwentySignedTransactions(t *testing.T) {
	for _, heavyPerp := range []bool{false, true} {
		name := "generic250kPerpSmallCall"
		if heavyPerp {
			name = "perpHeavyCalldata"
		}
		t.Run(name, func(t *testing.T) {
			config := evmProposalParallelTestConfig(t)
			config.NativeParallel = params.FHS250msResearchEVMParallelConfig()
			config.FairHotstuffSlotMillis, config.FixedCommittee = 250, true
			config.MaxCodeSize = 128
			zeroTime := uint64(0)
			config.SetModernForkConfig(&params.ModernForkConfig{
				BerlinBlock: big.NewInt(0), LondonBlock: big.NewInt(0),
				ShanghaiTime: &zeroTime, CancunTime: &zeroTime, PragueTime: &zeroTime, OsakaTime: &zeroTime,
				BlobSchedule: &params.BlobScheduleConfig{
					Cancun: &params.BlobConfig{Target: 192, Max: 288, BaseFeeUpdateFraction: 213662528},
					Prague: &params.BlobConfig{Target: 192, Max: 288, BaseFeeUpdateFraction: 160246912},
					Osaka:  &params.BlobConfig{Target: 192, Max: 288, BaseFeeUpdateFraction: 160246912},
				},
			})
			committee := newFHSEpochTestFixture(t).committee
			config.GenCommittee = make(params.GenesisCommittee, len(committee.List))
			for index, member := range committee.List {
				config.GenCommittee[index] = *member
			}
			if err := config.CheckConfigForkOrder(); err != nil {
				t.Fatalf("research fixture configuration: %v", err)
			}
			parentHash := common.HexToHash("0x19191")
			base := evmProposalParallelState(t, parentHash)
			base.SetCode(common.Address{10}, common.FromHex("0x600160005500"))
			base.SetCode(common.Address{11}, common.FromHex("0x600260005500"))
			var txs types.Transactions
			senders := make([]common.Address, 3)
			for index := 0; index < 20; index++ {
				// Twenty percent ordinary, thirty percent known DEX selector,
				// fifty percent perp-like generic calls. Calldata, rather than the
				// application label, decides whether the 250k calls are slow.
				gas, to, data, class, lane := uint64(params.TxGas), common.Address{9}, []byte(nil), core.TxClassNative, core.TxLaneFast
				account, nonce := 0, uint64(index)
				if index >= 4 && index < 10 {
					gas, to, data, class, lane = 150_000, common.Address{10}, []byte{0x38, 0xed, 0x17, 0x39}, core.TxClassDex, core.TxLaneSlow
					account, nonce = 1, uint64(index-4)
				} else if index >= 10 {
					gas, to, data, class = 250_000, common.Address{11}, []byte{0xde, 0xad, 0xbe, 0xef}, core.TxClassSmallCall
					account, nonce = 2, uint64(index-10)
					if heavyPerp {
						data, class, lane = make([]byte, 1025), core.TxClassHeavy, core.TxLaneSlow
					}
				}
				key, err := crypto.HexToECDSA(fmt.Sprintf("%064x", account+1))
				if err != nil {
					t.Fatal(err)
				}
				senders[account] = crypto.PubkeyToAddress(key.PublicKey)
				base.SetBalance(senders[account], new(big.Int).Exp(big.NewInt(10), big.NewInt(30), nil))
				tx, err := types.SignTx(types.NewTransaction(nonce, to, new(big.Int), gas, big.NewInt(2), data),
					types.NewEIP155Signer(config.ChainID), key)
				if err != nil {
					t.Fatal(err)
				}
				if gotLane, gotClass := core.ClassifyTxLane(tx), core.ClassifyTxResource(tx); gotLane != lane || gotClass != class {
					t.Fatalf("signed transaction %d lane/class = %d/%s, want %d/%s", index, gotLane, gotClass, lane, class)
				}
				txs = append(txs, tx)
			}
			base.Finalise(true)
			poolChain := &proposalBlobPoolChain{state: base, head: types.NewBlockWithHeader(&types.Header{
				Number: big.NewInt(0), Root: base.IntermediateRoot(true), GasLimit: 30_000_000, BaseFee: big.NewInt(1),
			})}
			poolConfig := core.DefaultTxPoolConfig
			poolConfig.NoLocals, poolConfig.Journal, poolConfig.PriceLimit = true, "", 1
			pool := core.NewTxPool(poolConfig, config, poolChain)
			t.Cleanup(pool.Stop)
			for index, err := range pool.AddRemotesSync(txs) {
				if err != nil {
					t.Fatalf("signed transaction %d pool admission: %v", index, err)
				}
			}
			service := &Service{chainConfig: config, txPool: pool}
			fast, slow := service.lanePendingCounts()
			wantFast, wantSlow := 14, 6
			if heavyPerp {
				wantFast, wantSlow = 4, 16
			}
			if fast != wantFast || slow != wantSlow {
				t.Fatalf("actual TxPool fast/slow pending = %d/%d, want %d/%d", fast, slow, wantFast, wantSlow)
			}
			now := time.Now()
			service.lastFastBlockTime, service.lastSlowBlockTime = now, now
			preferred, _ := boundedTxLanePreference(fast, slow)
			if got := service.chooseTxBlockType(); got != preferred {
				t.Fatalf("actual pending scheduler lane = %s, want %s", readableTxBlockType(got), readableTxBlockType(preferred))
			}
			chain := evmProposalParallelChain(t, config)
			selector := &txService{config: config, txPool: pool, bc: chain}
			totalCommitted := 0
			for _, blockType := range []uint8{types.FastTx_Block, types.SlowTx_Block} {
				selected, err := selector.loadPendingAddressTxes(blockType)
				if err != nil {
					t.Fatal(err)
				}
				wantCount := wantFast
				if blockType == types.SlowTx_Block {
					wantCount = wantSlow
				}
				selectedCount := 0
				expectedNonces := make(map[common.Address]uint64, len(selected))
				for sender, accountTxs := range selected {
					expectedNonces[sender] = uint64(len(accountTxs))
					selectedCount += len(accountTxs)
					for _, tx := range accountTxs {
						if (core.ClassifyTxLane(tx) == core.TxLaneFast) != (blockType == types.FastTx_Block) {
							t.Fatal("actual lane selector mixed fast and slow nonce prefixes")
						}
					}
				}
				if selectedCount != wantCount {
					t.Fatalf("actual %s selector count = %d, want %d", readableTxBlockType(blockType), selectedCount, wantCount)
				}
				// Execute each lane from the same funded parent as two independent
				// proposal candidates. This is a small local EVM fixture, without
				// consensus publication, admissions or a throughput measurement.
				work := evmProposalParallelWork(config, base.Copy(), parentHash, 10_000_000)
				work.blockType, work.header.BlockType = blockType, blockType
				work.header.SetFHSSlot(4)
				work.maxTxCount = blockMaxTxCountForConfig(config, blockType)
				if work.maxTxCount != 175_000 {
					t.Fatalf("research proposer count cap = %d, want 175000", work.maxTxCount)
				}
				cursor := types.NewTransactionsByPriceAndNonce(config, work.header.Number, selected)
				committed, receipts, _, failed, err := work.commitTransactions(cursor, chain)
				if err != nil || len(committed) != wantCount || len(receipts) != wantCount || len(failed) != 0 {
					t.Fatalf("actual %s EVM result: committed=%d receipts=%d failed=%d err=%v", readableTxBlockType(blockType), len(committed), len(receipts), len(failed), err)
				}
				totalCommitted += len(committed)
				for sender, expectedNonce := range expectedNonces {
					if work.publicState.GetNonce(sender) != expectedNonce {
						t.Fatalf("small %s proposal sender %s nonce = %d, want %d", readableTxBlockType(blockType), sender.Hex(),
							work.publicState.GetNonce(sender), expectedNonce)
					}
				}
				if expectedNonces[senders[1]] > 0 && work.publicState.GetState(common.Address{10}, common.Hash{}) != common.HexToHash("0x1") {
					t.Fatal("small DEX-selector contract calls did not execute")
				}
				if expectedNonces[senders[2]] > 0 && work.publicState.GetState(common.Address{11}, common.Hash{}) != common.HexToHash("0x2") {
					t.Fatal("small perp-like contract calls did not execute")
				}
				for _, receipt := range receipts {
					if receipt.Status != types.ReceiptStatusSuccessful {
						t.Fatal("small mixed proposal included a reverted contract call")
					}
				}
			}
			if totalCommitted != 20 {
				t.Fatalf("two lane candidates executed %d transactions, want 20", totalCommitted)
			}
		})
	}
}
