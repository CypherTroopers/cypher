package core

import (
	"errors"
	"math"
	"math/big"
	"strings"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/params"
)

func TestValidateOsakaBlockSize(t *testing.T) {
	osaka := uint64(1)
	config := new(params.ChainConfig)
	config.SetModernForkConfig(&params.ModernForkConfig{BerlinBlock: big.NewInt(0), LondonBlock: big.NewInt(0), OsakaTime: &osaka})

	oversized := types.NewBlockWithHeader(&types.Header{
		Number:     big.NewInt(1),
		Time:       osaka,
		Difficulty: big.NewInt(1),
		Extra:      make([]byte, params.MaxBlockSize),
	})
	if err := validateOsakaBlockSize(config, oversized); err == nil {
		t.Fatal("oversized Osaka block accepted")
	}

	preFork := types.NewBlockWithHeader(&types.Header{
		Number:     big.NewInt(1),
		Time:       osaka - 1,
		Difficulty: big.NewInt(1),
		Extra:      make([]byte, params.MaxBlockSize),
	})
	if err := validateOsakaBlockSize(config, preFork); err != nil {
		t.Fatalf("pre-Osaka block rejected: %v", err)
	}
}

func TestValidateOsakaBlockSizeUsesGenesisNativeLimit(t *testing.T) {
	osaka := uint64(0)
	config := &params.ChainConfig{NativeParallel: params.SolanaScaleNativeParallelConfig()}
	config.SetModernForkConfig(&params.ModernForkConfig{BerlinBlock: big.NewInt(0), LondonBlock: big.NewInt(0), OsakaTime: &osaka})

	block := types.NewBlockWithHeader(&types.Header{
		Number:     big.NewInt(1),
		Time:       osaka,
		Difficulty: big.NewInt(1),
		Extra:      make([]byte, params.MaxBlockSize+1024),
	})
	if err := validateOsakaBlockSize(config, block); err != nil {
		t.Fatalf("native block above legacy 8 MiB ceiling rejected: %v", err)
	}
}

func TestValidateOsakaBlockSizeIncludesFinalityProof(t *testing.T) {
	osaka := uint64(0)
	config := new(params.ChainConfig)
	config.SetModernForkConfig(&params.ModernForkConfig{BerlinBlock: big.NewInt(0), LondonBlock: big.NewInt(0), OsakaTime: &osaka})

	block := types.NewBlockWithHeader(&types.Header{
		Number:     big.NewInt(1),
		Time:       osaka,
		Difficulty: big.NewInt(1),
		Extra:      make([]byte, params.MaxBlockSize-4096),
	})
	if err := validateOsakaBlockSize(config, block); err != nil {
		t.Fatalf("block without finality proof should fit: %v", err)
	}
	if err := block.SetFHSFinalityProof(make([]byte, 8192)); err != nil {
		t.Fatalf("attach finality proof: %v", err)
	}
	if err := validateOsakaBlockSize(config, block); err == nil {
		t.Fatal("finality proof was not included in Osaka block-size validation")
	}
}

func TestValidateOsakaBlockSizeReservesFHSFinalityProofBeforeVote(t *testing.T) {
	osaka := uint64(0)
	config := &params.ChainConfig{FairHotstuff: true}
	config.SetModernForkConfig(&params.ModernForkConfig{BerlinBlock: big.NewInt(0), LondonBlock: big.NewInt(0), OsakaTime: &osaka})

	block := types.NewBlockWithHeader(&types.Header{
		Number:     big.NewInt(1),
		Time:       osaka,
		Difficulty: big.NewInt(1),
		Extra:      make([]byte, params.MaxBlockSize-types.MaxFHSFinalityProofSize),
	})
	if err := validateOsakaBlockSize(config, block); err == nil {
		t.Fatal("proofless Fair HotStuff proposal consumed the finality-proof reserve")
	}
}

func TestValidateBodyRejectsPrematureFHSFinalityProof(t *testing.T) {
	osaka := uint64(0)
	config := &params.ChainConfig{FairHotstuff: true}
	config.SetModernForkConfig(&params.ModernForkConfig{
		BerlinBlock: big.NewInt(0), LondonBlock: big.NewInt(0), OsakaTime: &osaka,
	})
	block := types.NewBlockWithHeader(&types.Header{
		Number: big.NewInt(1), Time: osaka, Difficulty: big.NewInt(1),
	})
	if err := block.SetFHSFinalityProof([]byte{1}); err != nil {
		t.Fatal(err)
	}
	validator := &BlockValidator{config: config}
	if err := validator.ValidateBodyWithHotstuffParent(block); err == nil {
		t.Fatal("live proposal with placeholder finality proof was accepted")
	}
	if err := validator.ValidateBodyRevalidatingKnown(block, true); err == nil {
		t.Fatal("known live proposal with placeholder finality proof was accepted")
	}
}

func TestFHSCommonRPCSidecarCoverageIsConsensusMandatory(t *testing.T) {
	config := &params.ChainConfig{ChainID: big.NewInt(1), FairHotstuff: true, CommonRPCSigners: []common.Address{{2}}}
	tx := types.NewTransaction(0, common.Address{1}, big.NewInt(1), params.TxGas, big.NewInt(1), nil)
	newBlock := func(blockType uint8) *types.Block {
		return types.NewBlockWithHeader(&types.Header{
			Number: big.NewInt(1), Difficulty: big.NewInt(1), BlockType: blockType,
		}).WithBody(types.Transactions{tx}, nil)
	}
	admission := osakaTestCommonAdmissionBatch(config.ChainID, common.Hash{9}, common.Address{2}, []common.Hash{tx.Hash()})
	refs := []types.CommonTxAdmissionRef{{Batch: 0, Item: 0}}
	reward := &types.CommonTxReward{
		TxHash: tx.Hash(), Approver: admission.Miner, ApproverReward: new(big.Int), Burn: new(big.Int),
	}

	missingAdmission := newBlock(types.FastTx_Block)
	if err := validateFHSCommonRPCSidecarCoverage(config, missingAdmission); err == nil || !strings.Contains(err.Error(), "admission reference count") {
		t.Fatalf("missing admission error = %v", err)
	}
	missingReward := newBlock(types.FastTx_Block)
	missingReward.AttachCommonTxData([]*types.CommonTxAdmissionBatch{admission}, refs, nil)
	if err := validateFHSCommonRPCSidecarCoverage(config, missingReward); err == nil || !strings.Contains(err.Error(), "reward count") {
		t.Fatalf("missing reward error = %v", err)
	}
	complete := newBlock(types.SlowTx_Block)
	complete.AttachCommonTxData([]*types.CommonTxAdmissionBatch{admission}, refs, []*types.CommonTxReward{reward})
	if err := validateFHSCommonRPCSidecarCoverage(config, complete); err != nil {
		t.Fatalf("complete sidecars rejected: %v", err)
	}
	unauthorizedAdmission := *admission
	unauthorizedAdmission.Miner = common.Address{3}
	unauthorizedAdmission.AdmissionID = types.CommonTxAdmissionID(&unauthorizedAdmission)
	unauthorizedReward := *reward
	unauthorizedReward.Approver = unauthorizedAdmission.Miner
	redirected := newBlock(types.FastTx_Block)
	redirected.AttachCommonTxData([]*types.CommonTxAdmissionBatch{&unauthorizedAdmission}, refs, []*types.CommonTxReward{&unauthorizedReward})
	if err := validateFHSCommonRPCSidecarCoverage(config, redirected); err == nil || !strings.Contains(err.Error(), "genesis-authorized") {
		t.Fatalf("unauthorized reward redirect error = %v", err)
	}

	keyBlock := newBlock(types.Key_Block)
	keyBlock.AttachCommonTxData([]*types.CommonTxAdmissionBatch{admission}, refs, []*types.CommonTxReward{reward})
	if err := validateFHSCommonRPCSidecarCoverage(config, keyBlock); err == nil || !strings.Contains(err.Error(), "key block") {
		t.Fatalf("key block payload error = %v", err)
	}
	emptyKeyBlock := types.NewBlockWithHeader(&types.Header{
		Number: big.NewInt(1), Difficulty: big.NewInt(1), BlockType: types.Key_Block,
	})
	if err := validateFHSCommonRPCSidecarCoverage(config, emptyKeyBlock); err != nil {
		t.Fatalf("empty key block rejected: %v", err)
	}
	if err := validateFHSCommonRPCSidecarCoverage(config, newBlock(99)); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown block type error = %v", err)
	}
}

func osakaTestCommonAdmissionBatch(chainID *big.Int, genesisHash common.Hash, miner common.Address, txHashes []common.Hash) *types.CommonTxAdmissionBatch {
	batch := &types.CommonTxAdmissionBatch{
		ChainID:        new(big.Int).Set(chainID),
		GenesisHash:    genesisHash,
		Miner:          miner,
		KeyBlockNumber: 1,
		Timestamp:      1,
		TxHashes:       append([]common.Hash(nil), txHashes...),
		Signature:      make([]byte, crypto.SignatureLength),
	}
	batch.TxRoot = types.DeriveCommonTxAdmissionTxRoot(batch.TxHashes)
	batch.AdmissionID = types.CommonTxAdmissionID(batch)
	return batch
}

func TestValidateFHSBlockWorkBoundsSerialSender(t *testing.T) {
	config := *params.AllcolossusXProtocolChanges
	config.FairHotstuff = true
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := types.SignTx(
		types.NewTransaction(0, common.Address{1}, new(big.Int), params.TxGas, big.NewInt(params.FixedTransferGasPricePerGas), nil),
		types.LatestSignerForChainID(config.ChainID), key,
	)
	if err != nil {
		t.Fatal(err)
	}
	header := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1)}
	allowed := make(types.Transactions, params.MaxTxCountPerSenderPerBlock)
	for index := range allowed {
		allowed[index] = tx
	}
	if err := validateFHSSenderWork(&config, types.NewBlockWithHeader(header).WithBody(allowed, nil)); err != nil {
		t.Fatalf("maximum per-sender work rejected: %v", err)
	}
	over := append(append(types.Transactions(nil), allowed...), tx)
	if err := validateFHSSenderWork(&config, types.NewBlockWithHeader(header).WithBody(over, nil)); err == nil {
		t.Fatal("over-limit serial sender work accepted")
	}

	tooMany := make(types.Transactions, params.MaxTxCountPerBlock+1)
	if err := validateFHSBlockWork(&config, types.NewBlockWithHeader(header).WithBody(tooMany, nil)); err == nil {
		t.Fatal("over-limit global transaction work accepted")
	}
}

func TestValidateFHSEVMCapacityProfileDoesNotRetainLegacySenderCap(t *testing.T) {
	config := *params.AllcolossusXProtocolChanges
	config.FairHotstuff = true
	config.NativeParallel = params.SolanaScaleNativeParallelConfig()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := types.SignTx(
		types.NewTransaction(0, common.Address{1}, new(big.Int), params.TxGas, big.NewInt(params.FixedTransferGasPricePerGas), nil),
		types.LatestSignerForChainID(config.ChainID), key,
	)
	if err != nil {
		t.Fatal(err)
	}
	serialLimit := params.FairHotstuffEVMWorkLimitsForConfig(&config).TransactionsPerSender
	if serialLimit != config.NativeParallel.MaxDependencyDepth {
		t.Fatalf("EVM serial sender limit = %d, want configured dependency depth %d", serialLimit, config.NativeParallel.MaxDependencyDepth)
	}
	header := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1), BlockType: types.FastTx_Block}
	allowed := make(types.Transactions, serialLimit)
	for index := range allowed {
		allowed[index] = tx
	}
	if err := validateFHSSenderWork(&config, types.NewBlockWithHeader(header).WithBody(allowed, nil)); err != nil {
		t.Fatalf("EVM capacity profile retained the legacy %d-transaction sender cap: %v", params.MaxTxCountPerSenderPerBlock, err)
	}
	over := append(append(types.Transactions(nil), allowed...), tx)
	if err := validateFHSSenderWork(&config, types.NewBlockWithHeader(header).WithBody(over, nil)); err == nil {
		t.Fatalf("EVM capacity profile accepted %d transactions from one serial sender, want maximum %d", len(over), serialLimit)
	}
}

func TestValidateFHSBlockWorkAcceptsFullSimpleTransferBlock(t *testing.T) {
	config := *params.AllcolossusXProtocolChanges
	config.FairHotstuff = true
	header := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1)}
	txs := make(types.Transactions, 0, params.MaxTxCountPerBlock)
	for account := 0; account < params.MaxTxCountPerBlock/params.MaxTxCountPerSenderPerBlock; account++ {
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		tx, err := types.SignTx(
			types.NewTransaction(0, common.Address{1}, new(big.Int), params.TxGas, big.NewInt(params.FixedTransferGasPricePerGas), nil),
			types.LatestSignerForChainID(config.ChainID), key,
		)
		if err != nil {
			t.Fatal(err)
		}
		for count := 0; count < params.MaxTxCountPerSenderPerBlock; count++ {
			txs = append(txs, tx)
		}
	}
	if len(txs) != params.MaxTxCountPerBlock {
		t.Fatalf("simple transfer fixture count = %d, want %d", len(txs), params.MaxTxCountPerBlock)
	}
	if err := validateFHSSenderWork(&config, types.NewBlockWithHeader(header).WithBody(txs, nil)); err != nil {
		t.Fatalf("full simple-transfer work envelope rejected: %v", err)
	}
}

func TestFHSFullSimpleTransferSidecarsFitOsakaEnvelope(t *testing.T) {
	config := *params.AllcolossusXProtocolChanges
	config.FairHotstuff = true
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := types.SignTx(
		types.NewTransaction(0, common.Address{1}, new(big.Int), params.TxGas, big.NewInt(params.FixedTransferGasPricePerGas), nil),
		types.LatestSignerForChainID(config.ChainID), key,
	)
	if err != nil {
		t.Fatal(err)
	}
	miner := crypto.PubkeyToAddress(key.PublicKey)
	actualFee := new(big.Int).Mul(new(big.Int).SetUint64(params.TxGas), big.NewInt(params.FixedTransferGasPricePerGas))
	approverReward := new(big.Int).Div(new(big.Int).Set(actualFee), big.NewInt(5))
	txs := make(types.Transactions, params.MaxTxCountPerBlock)
	batches := make([]*types.CommonTxAdmissionBatch, 0, params.MaxTxCountPerBlock/types.MaxCommonTxAdmissionBatchItems)
	refs := make([]types.CommonTxAdmissionRef, params.MaxTxCountPerBlock)
	rewards := make([]*types.CommonTxReward, params.MaxTxCountPerBlock)
	for start := 0; start < len(txs); start += types.MaxCommonTxAdmissionBatchItems {
		end := start + types.MaxCommonTxAdmissionBatchItems
		if end > len(txs) {
			end = len(txs)
		}
		hashes := make([]common.Hash, end-start)
		for index := start; index < end; index++ {
			txHash := common.BigToHash(new(big.Int).SetUint64(uint64(index + 1)))
			txs[index] = tx
			hashes[index-start] = txHash
			refs[index] = types.CommonTxAdmissionRef{Batch: uint32(len(batches)), Item: uint16(index - start)}
			rewards[index] = &types.CommonTxReward{
				TxHash: txHash, Approver: miner, ApproverReward: approverReward, Burn: new(big.Int).Sub(actualFee, approverReward),
			}
		}
		batches = append(batches, osakaTestCommonAdmissionBatch(config.ChainID, common.Hash{9}, miner, hashes))
	}
	block := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1)}).WithBody(txs, nil)
	block.AttachCommonTxData(batches, refs, rewards)
	if err := validateFHSBlockWorkEnvelope(&config, block); err != nil {
		t.Fatalf("full normal admission/reward work envelope rejected: %v", err)
	}
	const proofRLPOverhead = uint64(16)
	limit := uint64(params.MaxBlockSize-types.MaxFHSFinalityProofSize) - proofRLPOverhead
	if size := uint64(block.Size()); size > limit {
		t.Fatalf("full normal admission/reward block size = %d, exceeds Osaka proposal envelope %d", size, limit)
	}
}

func TestFHSBlockWorkMeterBoundariesAndOverflow(t *testing.T) {
	limits := params.FairHotstuffWorkLimits()
	if total, ok := params.AddFHSWork(math.MaxUint64-1, 1, math.MaxUint64); !ok || total != math.MaxUint64 {
		t.Fatalf("exact uint64 boundary = (%d,%t), want (%d,true)", total, ok, uint64(math.MaxUint64))
	}
	if total, ok := params.AddFHSWork(math.MaxUint64, 1, math.MaxUint64); ok || total != math.MaxUint64 {
		t.Fatalf("overflowing uint64 accumulation = (%d,%t), want (%d,false)", total, ok, uint64(math.MaxUint64))
	}

	t.Run("declared gas", func(t *testing.T) {
		meter := NewFHSBlockWorkMeter()
		atLimit := types.NewTransaction(0, common.Address{1}, new(big.Int), limits.DeclaredGas, big.NewInt(1), nil)
		if err := meter.AddTransaction(0, atLimit); err != nil {
			t.Fatalf("exact declared-gas boundary rejected: %v", err)
		}
		if err := meter.AddTransaction(1, types.NewTransaction(1, common.Address{1}, new(big.Int), 1, big.NewInt(1), nil)); err == nil || !strings.Contains(err.Error(), "transaction 1 makes declared gas") {
			t.Fatalf("over-limit declared gas error = %v", err)
		}
	})

	t.Run("uninitialized transaction", func(t *testing.T) {
		if err := NewFHSBlockWorkMeter().AddTransaction(0, new(types.Transaction)); err == nil || !strings.Contains(err.Error(), "transaction 0 is nil or uninitialized") {
			t.Fatalf("uninitialized transaction error = %v", err)
		}
	})

	t.Run("per transaction lists", func(t *testing.T) {
		to := common.Address{1}
		tests := []struct {
			name string
			tx   *types.Transaction
		}{
			{
				name: "authorizations",
				tx: types.NewTx(&types.SetCodeTx{
					ChainID: big.NewInt(1), GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(1), Gas: params.TxGas,
					To: to, Value: new(big.Int), AuthList: make([]types.SetCodeAuthorization, limits.SetCodeAuthorizationsPerTx+1),
				}),
			},
			{
				name: "addresses",
				tx: types.NewTx(&types.AccessListTx{
					ChainID: big.NewInt(1), GasPrice: big.NewInt(1), Gas: params.TxGas, To: &to, Value: new(big.Int),
					AccessList: make(types.AccessList, limits.AccessListAddressesPerTx+1),
				}),
			},
			{
				name: "storage keys",
				tx: types.NewTx(&types.AccessListTx{
					ChainID: big.NewInt(1), GasPrice: big.NewInt(1), Gas: params.TxGas, To: &to, Value: new(big.Int),
					AccessList: types.AccessList{{StorageKeys: make([]common.Hash, limits.AccessListStorageKeysPerTx+1)}},
				}),
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				err := NewFHSBlockWorkMeter().AddTransaction(0, test.tx)
				if !errors.Is(err, ErrFHSPerTransactionWorkLimit) {
					t.Fatalf("per-transaction work error = %v, want %v", err, ErrFHSPerTransactionWorkLimit)
				}
			})
		}
	})

	t.Run("aggregate access lists", func(t *testing.T) {
		to := common.Address{1}
		addressTx := types.NewTx(&types.AccessListTx{
			ChainID: big.NewInt(1), GasPrice: big.NewInt(1), Gas: 1, To: &to, Value: new(big.Int),
			AccessList: make(types.AccessList, limits.AccessListAddressesPerTx),
		})
		meter := NewFHSBlockWorkMeter()
		for index := uint64(0); index < limits.AccessListAddresses/limits.AccessListAddressesPerTx; index++ {
			if err := meter.AddTransaction(int(index), addressTx); err != nil {
				t.Fatalf("exact aggregate address boundary rejected at %d: %v", index, err)
			}
		}
		oneAddress := types.NewTx(&types.AccessListTx{
			ChainID: big.NewInt(1), GasPrice: big.NewInt(1), Gas: 1, To: &to, Value: new(big.Int), AccessList: make(types.AccessList, 1),
		})
		if err := meter.AddTransaction(999, oneAddress); err == nil || !strings.Contains(err.Error(), "access-list address count") {
			t.Fatalf("over-limit aggregate addresses error = %v", err)
		}

		storageTx := types.NewTx(&types.AccessListTx{
			ChainID: big.NewInt(1), GasPrice: big.NewInt(1), Gas: 1, To: &to, Value: new(big.Int),
			AccessList: types.AccessList{{StorageKeys: make([]common.Hash, limits.AccessListStorageKeysPerTx)}},
		})
		meter = NewFHSBlockWorkMeter()
		for index := uint64(0); index < limits.AccessListStorageKeys/limits.AccessListStorageKeysPerTx; index++ {
			if err := meter.AddTransaction(int(index), storageTx); err != nil {
				t.Fatalf("exact aggregate storage-key boundary rejected at %d: %v", index, err)
			}
		}
		oneKey := types.NewTx(&types.AccessListTx{
			ChainID: big.NewInt(1), GasPrice: big.NewInt(1), Gas: 1, To: &to, Value: new(big.Int),
			AccessList: types.AccessList{{StorageKeys: make([]common.Hash, 1)}},
		})
		if err := meter.AddTransaction(999, oneKey); err == nil || !strings.Contains(err.Error(), "access-list storage-key count") {
			t.Fatalf("over-limit aggregate storage keys error = %v", err)
		}
	})

	t.Run("authorization and signature operations", func(t *testing.T) {
		to := common.Address{1}
		authTx := types.NewTx(&types.SetCodeTx{
			ChainID: big.NewInt(1), GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(1), Gas: params.TxGas,
			To: to, Value: new(big.Int), AuthList: make([]types.SetCodeAuthorization, 1),
		})
		meter := NewFHSBlockWorkMeter()
		for index := uint64(0); index < limits.SetCodeAuthorizations; index++ {
			if err := meter.AddTransaction(int(index), authTx); err != nil {
				t.Fatalf("signature boundary transaction %d rejected: %v", index, err)
			}
		}
		simpleTx := types.NewTransaction(0, to, new(big.Int), params.TxGas, big.NewInt(1), nil)
		for index := limits.SetCodeAuthorizations; index < limits.Transactions; index++ {
			if err := meter.AddTransaction(int(index), simpleTx); err != nil {
				t.Fatalf("signature boundary simple transaction %d rejected: %v", index, err)
			}
		}
		if want := limits.Transactions + limits.SetCodeAuthorizations + limits.CommonTxAdmissionBatches; limits.SignatureOperations != want {
			t.Fatalf("signature-operation ceiling = %d, want constituent maximum %d", limits.SignatureOperations, want)
		}
		batch := osakaTestCommonAdmissionBatch(big.NewInt(1), common.Hash{9}, common.Address{2}, []common.Hash{{1}})
		beforeSignatures := meter.signatureOperations
		if err := meter.AddAdmissionBatch(0, batch); err != nil {
			t.Fatalf("one batch admission rejected: %v", err)
		}
		if got := meter.signatureOperations - beforeSignatures; got != 1 {
			t.Fatalf("one 512-capable batch used %d signature operations, want 1", got)
		}
		maxAmount := new(big.Int).Lsh(big.NewInt(1), 255) // 32-byte magnitude
		reward := &types.CommonTxReward{ApproverReward: maxAmount, Burn: maxAmount}
		for index := uint64(0); index < limits.CommonTxRewards; index++ {
			if err := meter.AddReward(int(index), reward); err != nil {
				t.Fatalf("normal maximum reward sidecar %d rejected: %v", index, err)
			}
		}
		full := NewFHSBlockWorkMeter()
		full.commonTxAdmissionBatches = limits.CommonTxAdmissionBatches
		if err := full.AddAdmissionBatch(int(limits.CommonTxAdmissionBatches), batch); err == nil || !strings.Contains(err.Error(), "batch count") {
			t.Fatalf("over-limit admission batch error = %v", err)
		}
		if err := meter.AddReward(int(limits.CommonTxRewards), reward); err == nil || !strings.Contains(err.Error(), "reward count") {
			t.Fatalf("over-limit reward count error = %v", err)
		}

		maxAuthTx := types.NewTx(&types.SetCodeTx{
			ChainID: big.NewInt(1), GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(1), Gas: 1,
			To: to, Value: new(big.Int), AuthList: make([]types.SetCodeAuthorization, limits.SetCodeAuthorizationsPerTx),
		})
		meter = NewFHSBlockWorkMeter()
		for index := uint64(0); index < limits.SetCodeAuthorizations/limits.SetCodeAuthorizationsPerTx; index++ {
			if err := meter.AddTransaction(int(index), maxAuthTx); err != nil {
				t.Fatalf("exact authorization boundary rejected at %d: %v", index, err)
			}
		}
		if err := meter.AddTransaction(999, authTx); err == nil || !strings.Contains(err.Error(), "EIP-7702 authorization count") {
			t.Fatalf("over-limit authorization error = %v", err)
		}
	})

	t.Run("admission payload bytes", func(t *testing.T) {
		batch := osakaTestCommonAdmissionBatch(big.NewInt(1), common.Hash{9}, common.Address{2}, []common.Hash{{1}})
		oversized := *batch
		oversized.Signature = make([]byte, limits.CommonTxAdmissionBytesPerBatch)
		if err := NewFHSBlockWorkMeter().AddAdmissionBatch(0, &oversized); err == nil || !strings.Contains(err.Error(), "per-batch maximum") {
			t.Fatalf("over-limit admission batch payload error = %v", err)
		}

		meter := NewFHSBlockWorkMeter()
		meter.commonTxAdmissionBytes = limits.CommonTxAdmissionPayloadBytes
		if err := meter.AddAdmissionBatch(0, batch); err == nil || !strings.Contains(err.Error(), "admission payload bytes") {
			t.Fatalf("over-limit aggregate admission payload error = %v", err)
		}
	})

	t.Run("reward count relations", func(t *testing.T) {
		tx := types.NewTransaction(0, common.Address{1}, new(big.Int), 1, big.NewInt(1), nil)
		reward := &types.CommonTxReward{ApproverReward: big.NewInt(1), Burn: big.NewInt(1)}

		meter := NewFHSBlockWorkMeter()
		if err := meter.AddTransaction(0, tx); err != nil {
			t.Fatal(err)
		}
		if err := meter.AddTransaction(1, tx); err != nil {
			t.Fatal(err)
		}
		if err := meter.AddReward(0, reward); err != nil {
			t.Fatal(err)
		}
		if err := meter.AddReward(1, reward); err != nil {
			t.Fatalf("second transaction reward rejected: %v", err)
		}
		if err := meter.AddReward(2, reward); err == nil || !strings.Contains(err.Error(), "exceed transaction count") {
			t.Fatalf("unrelated reward error = %v, want transaction-count relation", err)
		}

		meter = NewFHSBlockWorkMeter()
		if err := meter.AddTransaction(0, tx); err != nil {
			t.Fatal(err)
		}
		if err := meter.AddReward(0, reward); err != nil {
			t.Fatal(err)
		}
		if err := meter.AddReward(1, reward); err == nil || !strings.Contains(err.Error(), "exceed transaction count") {
			t.Fatalf("unrelated reward error = %v, want transaction-count relation", err)
		}
	})

	t.Run("reward payload bytes", func(t *testing.T) {
		// 52 fixed bytes + a 77-byte reward + a zero-byte burn = 129.
		const entryBytes = uint64(129)
		amount := new(big.Int).Lsh(big.NewInt(1), 8*76)
		reward := &types.CommonTxReward{ApproverReward: amount, Burn: new(big.Int)}
		count := limits.CommonTxRewardPayloadBytes / entryBytes
		needed := count + 1
		meter := NewFHSBlockWorkMeter()
		tx := types.NewTransaction(0, common.Address{1}, new(big.Int), 1, big.NewInt(1), nil)
		for index := uint64(0); index < needed; index++ {
			if err := meter.AddTransaction(int(index), tx); err != nil {
				t.Fatalf("reward payload transaction %d rejected: %v", index, err)
			}
		}
		for index := uint64(0); index < count; index++ {
			if err := meter.AddReward(int(index), reward); err != nil {
				t.Fatalf("reward payload boundary rejected at %d: %v", index, err)
			}
		}
		if err := meter.AddReward(int(count), reward); err == nil || !strings.Contains(err.Error(), "reward payload bytes") {
			t.Fatalf("over-limit reward payload error = %v", err)
		}

		huge := &types.CommonTxReward{
			ApproverReward: new(big.Int).Lsh(big.NewInt(1), uint(limits.CommonTxRewardBytesPerEntry*8)),
			Burn:           new(big.Int),
		}
		if err := NewFHSBlockWorkMeter().AddReward(0, huge); err == nil || !strings.Contains(err.Error(), "per-entry maximum") {
			t.Fatalf("huge reward big.Int error = %v", err)
		}
	})
}

func TestValidateFHSBlockWorkReturnsCheapOrderedErrorBeforeCrypto(t *testing.T) {
	config := *params.AllcolossusXProtocolChanges
	config.FairHotstuff = true
	to := common.Address{1}
	invalidSender := types.NewTransaction(0, to, new(big.Int), params.TxGas, big.NewInt(1), nil)
	overLimit := types.NewTx(&types.SetCodeTx{
		ChainID: big.NewInt(1), GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(1), Gas: params.TxGas,
		To: to, Value: new(big.Int), AuthList: make([]types.SetCodeAuthorization, params.MaxFHSSetCodeAuthorizationsPerTransaction+1),
	})
	block := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1)}).WithBody(types.Transactions{invalidSender, overLimit, nil}, nil)
	err := validateFHSBlockWork(&config, block)
	if err == nil || !strings.Contains(err.Error(), "transaction 1 EIP-7702 authorization count") {
		t.Fatalf("ordered cheap work error = %v, want transaction 1 authorization error before sender recovery", err)
	}

	// The production body path must run the same cheap envelope before even a
	// deliberately wrong transaction root, and therefore before sender crypto
	// or EVM execution.
	header := block.Header0()
	header.BaseFee = big.NewInt(params.FixedBaseFeePerGas)
	err = (&BlockValidator{config: &config}).ValidateBodyForHotstuffSync(block, true)
	if err == nil || !strings.Contains(err.Error(), "transaction 1 EIP-7702 authorization count") {
		t.Fatalf("body validation ordering error = %v, want cheap work error before root/crypto", err)
	}
}

func TestValidateFHSBlockWorkRejectsUnrelatedRewardSidecar(t *testing.T) {
	config := *params.AllcolossusXProtocolChanges
	config.FairHotstuff = true
	tx := types.NewTransaction(0, common.Address{1}, new(big.Int), params.TxGas, big.NewInt(1), nil)
	admission := osakaTestCommonAdmissionBatch(config.ChainID, common.Hash{9}, common.Address{2}, []common.Hash{tx.Hash()})
	refs := []types.CommonTxAdmissionRef{{Batch: 0, Item: 0}}
	rewards := make([]*types.CommonTxReward, 64)
	for index := range rewards {
		rewards[index] = &types.CommonTxReward{ApproverReward: big.NewInt(1), Burn: big.NewInt(1)}
	}
	block := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1)}).WithBody(types.Transactions{tx}, nil)
	block.AttachCommonTxData([]*types.CommonTxAdmissionBatch{admission}, refs, rewards)
	err := validateFHSBlockWorkEnvelope(&config, block)
	if err == nil || !strings.Contains(err.Error(), "reward count 64 does not match admission reference count 1") {
		t.Fatalf("unrelated reward sidecar error = %v", err)
	}
}

func TestFHSCommonSidecarSetEqualityBeforeEVM(t *testing.T) {
	seed := func(t *testing.T) *FHSBlockWorkMeter {
		t.Helper()
		meter := NewFHSBlockWorkMeter()
		tx := types.NewTransaction(0, common.Address{1}, new(big.Int), 1, big.NewInt(1), nil)
		for index := 0; index < 2; index++ {
			if err := meter.AddTransaction(index, tx); err != nil {
				t.Fatal(err)
			}
		}
		return meter
	}
	hashA, hashB, hashC := common.Hash{1}, common.Hash{2}, common.Hash{3}
	approverA, approverB := common.Address{1}, common.Address{2}
	reward := func(hash common.Hash, approver common.Address) *types.CommonTxReward {
		return &types.CommonTxReward{TxHash: hash, Approver: approver, ApproverReward: big.NewInt(1), Burn: big.NewInt(1)}
	}
	batches := []*types.CommonTxAdmissionBatch{
		osakaTestCommonAdmissionBatch(big.NewInt(1), common.Hash{9}, approverA, []common.Hash{hashA}),
		osakaTestCommonAdmissionBatch(big.NewInt(1), common.Hash{9}, approverB, []common.Hash{hashB}),
	}
	refs := []types.CommonTxAdmissionRef{{Batch: 0, Item: 0}, {Batch: 1, Item: 0}}

	// StateProcessor indexes these sidecars by TxHash, so reversed reward order
	// is valid as long as the set and approvers are identical.
	if err := seed(t).AddCommonSidecars(batches, refs, []*types.CommonTxReward{reward(hashB, approverB), reward(hashA, approverA)}); err != nil {
		t.Fatalf("reordered but equal reward set rejected: %v", err)
	}
	if err := seed(t).AddCommonSidecars(batches, refs, []*types.CommonTxReward{reward(hashA, approverA)}); err == nil || !strings.Contains(err.Error(), "reward count 1 does not match admission reference count 2") {
		t.Fatalf("missing terminal reward error = %v", err)
	}
	if err := seed(t).AddCommonSidecars(batches, refs, []*types.CommonTxReward{reward(hashA, approverA), reward(hashC, approverB)}); err == nil || !strings.Contains(err.Error(), "no matching admission reference") {
		t.Fatalf("mismatched reward hash set error = %v", err)
	}
	if err := seed(t).AddCommonSidecars(batches, refs, []*types.CommonTxReward{reward(hashA, approverB), reward(hashB, approverB)}); err == nil || !strings.Contains(err.Error(), "does not match admission batch miner") {
		t.Fatalf("mismatched reward approver error = %v", err)
	}
	if err := seed(t).AddCommonSidecars(batches, []types.CommonTxAdmissionRef{{Batch: 0, Item: 0}, {Batch: 0, Item: 0}}, []*types.CommonTxReward{reward(hashA, approverA), reward(hashB, approverB)}); err == nil || !strings.Contains(err.Error(), "duplicates batch 0 item 0") {
		t.Fatalf("duplicate admission reference error = %v", err)
	}
	unusedBatches := []*types.CommonTxAdmissionBatch{
		osakaTestCommonAdmissionBatch(big.NewInt(1), common.Hash{9}, approverA, []common.Hash{hashA, hashB}),
		osakaTestCommonAdmissionBatch(big.NewInt(1), common.Hash{9}, approverB, []common.Hash{hashC}),
	}
	if err := seed(t).AddCommonSidecars(unusedBatches, []types.CommonTxAdmissionRef{{Batch: 0, Item: 0}, {Batch: 0, Item: 1}}, []*types.CommonTxReward{reward(hashA, approverA), reward(hashB, approverA)}); err == nil || !strings.Contains(err.Error(), "unreferenced") {
		t.Fatalf("unreferenced admission batch error = %v", err)
	}
}

func TestValidateFHSBlockWorkRejectsHugeRewardBeforeRoot(t *testing.T) {
	config := *params.AllcolossusXProtocolChanges
	config.FairHotstuff = true
	tx := types.NewTransaction(0, common.Address{1}, new(big.Int), params.TxGas, big.NewInt(1), nil)
	txHash := tx.Hash()
	approver := common.Address{2}
	admission := osakaTestCommonAdmissionBatch(config.ChainID, common.Hash{9}, approver, []common.Hash{txHash})
	refs := []types.CommonTxAdmissionRef{{Batch: 0, Item: 0}}
	huge := &types.CommonTxReward{
		TxHash:         txHash,
		Approver:       approver,
		ApproverReward: new(big.Int).Lsh(big.NewInt(1), uint(params.MaxFHSCommonTxRewardBytesPerReward*8)),
		Burn:           new(big.Int),
	}
	block := types.NewBlockWithHeader(&types.Header{
		Number: big.NewInt(1), Difficulty: big.NewInt(1), BaseFee: big.NewInt(params.FixedBaseFeePerGas),
	}).WithBody(types.Transactions{tx}, nil)
	block.AttachCommonTxData([]*types.CommonTxAdmissionBatch{admission}, refs, []*types.CommonTxReward{huge})
	block.Header0().CommonTxRewardRoot = common.Hash{} // force a later root mismatch
	err := (&BlockValidator{config: &config}).ValidateBodyForHotstuffSync(block, true)
	if err == nil || !strings.Contains(err.Error(), "reward 0 payload exceeds per-entry maximum") {
		t.Fatalf("huge reward ordering error = %v, want cheap payload rejection before root", err)
	}

	missing := types.NewBlockWithHeader(&types.Header{
		Number: big.NewInt(1), Difficulty: big.NewInt(1), BaseFee: big.NewInt(params.FixedBaseFeePerGas),
	}).WithBody(types.Transactions{tx}, nil)
	missing.AttachCommonTxData([]*types.CommonTxAdmissionBatch{admission}, refs, nil)
	err = (&BlockValidator{config: &config}).ValidateBodyForHotstuffSync(missing, true)
	if err == nil || !strings.Contains(err.Error(), "reward count 0 does not match admission reference count 1") {
		t.Fatalf("missing reward ordering error = %v, want count equality rejection before root", err)
	}
}
