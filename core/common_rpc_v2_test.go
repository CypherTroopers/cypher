package core

import (
	"crypto/ecdsa"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus/colossusX"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
	lru "github.com/hashicorp/golang-lru"
)

func v2ExecutionFixture(t *testing.T) (*StateProcessor, *types.Block, *state.StateDB, *ecdsa.PrivateKey, common.Address) {
	t.Helper()
	config := modernTestConfig(true, true, true)
	config.FairHotstuff = true
	genesis := types.NewBlockWithHeader(&types.Header{Number: new(big.Int), Difficulty: big.NewInt(1)})
	keyBlock := types.NewKeyBlock(&types.KeyBlockHeader{Number: new(big.Int), Difficulty: big.NewInt(1)})
	base := newModernTestState(t)
	operatorKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	operator := crypto.PubkeyToAddress(operatorKey.PublicKey)
	recipient := common.HexToAddress("0xb321") // No key or account manager exists for B.
	base.SetBalance(operator, big.NewInt(77))
	base.SetBalance(recipient, big.NewInt(123))
	base.SetCode(recipient, []byte{0x60, 0x00, 0x60, 0x00, 0xfd}) // A payout must never execute B's reverting code.
	txs := make(types.Transactions, 4)
	hashes := make([]common.Hash, len(txs))
	for i := range txs {
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		base.SetBalance(crypto.PubkeyToAddress(key.PublicKey), big.NewInt(1_000_000_000_000_000_000))
		to := common.BigToAddress(big.NewInt(int64(0x4000 + i)))
		base.SetBalance(to, big.NewInt(11))
		txs[i], err = types.SignTx(types.NewTransaction(0, to, big.NewInt(7), params.TxGas, big.NewInt(params.FixedTransferGasPricePerGas), nil), types.LatestSignerForChainID(config.ChainID), key)
		if err != nil {
			t.Fatal(err)
		}
		hashes[i] = txs[i].Hash()
	}
	batch := stateProcessorTestAdmissionBatch(t, operatorKey, config.ChainID, genesis.Hash(), 0, 100, hashes)
	batch.Version, batch.RewardRecipient = 2, recipient
	resealStateProcessorTestAdmissionBatch(t, batch, operatorKey)
	refs := make([]types.CommonTxAdmissionRef, len(txs))
	rewards := make([]*types.CommonTxReward, len(txs))
	fee := new(big.Int).Mul(big.NewInt(int64(params.TxGas)), big.NewInt(params.FixedTransferGasPricePerGas))
	reward := new(big.Int).Div(new(big.Int).Set(fee), big.NewInt(5))
	for i, tx := range txs {
		refs[i].Item = uint16(i)
		rewards[i] = &types.CommonTxReward{TxHash: tx.Hash(), Approver: operator, Version: 2, RewardRecipient: recipient, ApproverReward: new(big.Int).Set(reward), Burn: new(big.Int).Sub(fee, reward)}
	}
	block := types.NewBlockWithHeader(&types.Header{ParentHash: genesis.Hash(), Number: big.NewInt(1), Difficulty: big.NewInt(1), BlockType: types.FastTx_Block, KeyHash: keyBlock.Hash(), Time: 100, Coinbase: common.HexToAddress("0xc001"), GasLimit: uint64(len(txs)) * params.TxGas, BaseFee: big.NewInt(params.FixedBaseFeePerGas)}).WithBody(txs, nil)
	block.AttachCommonTxData([]*types.CommonTxAdmissionBatch{batch}, refs, rewards)
	keyCache, _ := lru.New(1)
	keyCache.Add(keyBlock.Hash(), keyBlock)
	numberCache, _ := lru.New(1)
	numberCache.Add(keyBlock.Hash(), uint64(0))
	engine := colossusX.NewFaker()
	t.Cleanup(func() { engine.Close() })
	chain := &BlockChain{chainConfig: config, genesisBlock: genesis, engine: engine, keyBlockChain: &KeyBlockChain{blockCache: keyCache, khc: &KeyHeaderChain{numberCache: numberCache}}, validatedFHSSidecars: newFHSSidecarHandoff()}
	base.Finalise(true)
	return NewStateProcessor(config, chain, engine), block, base, operatorKey, recipient
}

func TestCommonRPCV2DirectPayoutSerialParallelAndImportedBlock(t *testing.T) {
	processor, block, base, key, recipient := v2ExecutionFixture(t)
	operator := crypto.PubkeyToAddress(key.PublicKey)
	jobs := processor.collectParallelNativeJobs(block.Transactions(), 0, block, base.Copy(), new(GasPool).AddGas(block.GasLimit()), vm.Config{}, processor.config.CypheriumRules(block.Number(), block.Time()))
	if len(jobs) != len(block.Transactions()) {
		t.Fatalf("parallel execution not exercised: %d jobs", len(jobs))
	}
	serial := base.Copy()
	serialReceipts, _, serialGas, err := processor.Process(block, serial, vm.Config{EnablePreimageRecording: true})
	if err != nil {
		t.Fatal(err)
	}
	parallel := base.Copy()
	parallelReceipts, _, parallelGas, err := processor.Process(block, parallel, vm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if serial.IntermediateRoot(true) != parallel.IntermediateRoot(true) || serialGas != parallelGas || !reflect.DeepEqual(serialReceipts, parallelReceipts) {
		t.Fatal("V2 serial/parallel roots, gas or receipts differ")
	}
	var rewardTotal, burnTotal big.Int
	for _, r := range block.CommonTxRewards() {
		rewardTotal.Add(&rewardTotal, r.ApproverReward)
		burnTotal.Add(&burnTotal, r.Burn)
	}
	if got := serial.GetBalance(recipient); got.Cmp(new(big.Int).Add(big.NewInt(123), &rewardTotal)) != 0 {
		t.Fatalf("B payout=%s expected existing balance plus %s", got, &rewardTotal)
	}
	if got := serial.GetBalance(operator); got.Cmp(big.NewInt(77)) != 0 {
		t.Fatal("Common TX reward was paid to signing account A")
	}
	feeTotal := new(big.Int).Mul(new(big.Int).SetUint64(serialGas), big.NewInt(params.FixedTransferGasPricePerGas))
	if new(big.Int).Add(&rewardTotal, &burnTotal).Cmp(feeTotal) != 0 {
		t.Fatal("reward plus burn changed total fee")
	}
	if !reflect.DeepEqual(serial.GetCode(recipient), base.GetCode(recipient)) {
		t.Fatal("reward payout executed recipient contract")
	}
	wire, err := rlp.EncodeToBytes(block)
	if err != nil {
		t.Fatal(err)
	}
	var imported types.Block
	if err := rlp.DecodeBytes(wire, &imported); err != nil {
		t.Fatal(err)
	}
	context := fhsSidecarValidationContext{genesisHash: processor.bc.genesisBlock.Hash(), keyBlockNumber: 0}
	validated, err := buildValidatedFHSSidecarLayout(processor.config, &imported, context)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAndPublishValidatedFHSSidecars(processor.config, &imported, context, validated, processor.bc.validatedFHSSidecars); err != nil {
		t.Fatal(err)
	}
	synced := base.Copy()
	syncedReceipts, _, _, err := processor.Process(&imported, synced, vm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if synced.IntermediateRoot(true) != serial.IntermediateRoot(true) || !reflect.DeepEqual(syncedReceipts, serialReceipts) {
		t.Fatal("import/cache execution disagrees with proposal execution")
	}
}

func TestCommonRPCV2LaterTransactionCannotSpendEarlierReward(t *testing.T) {
	processor, block, base, operatorKey, _ := v2ExecutionFixture(t)
	// B signs this transaction outside the node. Its initial funds are one unit
	// short of gas, but the first transaction's reward would cover that gap if
	// rewards were incorrectly credited before the block finished execution.
	externalBKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	b := crypto.PubkeyToAddress(externalBKey.PublicKey)
	fee := new(big.Int).Mul(big.NewInt(int64(params.TxGas)), big.NewInt(params.FixedTransferGasPricePerGas))
	initial := new(big.Int).Sub(new(big.Int).Set(fee), big.NewInt(1))
	base.SetBalance(b, initial)
	base.Finalise(true)
	spend, err := types.SignTx(types.NewTransaction(0, common.HexToAddress("0x9000"), new(big.Int), params.TxGas, big.NewInt(params.FixedTransferGasPricePerGas), nil), types.LatestSignerForChainID(processor.config.ChainID), externalBKey)
	if err != nil {
		t.Fatal(err)
	}
	txs := types.Transactions{block.Transactions()[0], spend}
	batch := block.CommonTxAdmissionBatches()[0]
	batch.TxHashes = []common.Hash{txs[0].Hash(), spend.Hash()}
	batch.RewardRecipient = b
	resealStateProcessorTestAdmissionBatch(t, batch, operatorKey)
	rewardAmount := new(big.Int).Div(new(big.Int).Set(fee), big.NewInt(5))
	rewards := make([]*types.CommonTxReward, len(txs))
	for i, tx := range txs {
		rewards[i] = &types.CommonTxReward{TxHash: tx.Hash(), Approver: batch.Miner, Version: 2, RewardRecipient: b, ApproverReward: new(big.Int).Set(rewardAmount), Burn: new(big.Int).Sub(fee, rewardAmount)}
	}
	block = block.WithBody(txs, nil)
	block.AttachCommonTxData([]*types.CommonTxAdmissionBatch{batch}, []types.CommonTxAdmissionRef{{Item: 0}, {Item: 1}}, rewards)
	if _, _, _, err := processor.Process(block, base, vm.Config{}); err == nil || !strings.Contains(err.Error(), "insufficient funds") {
		t.Fatalf("later transaction spent an earlier reward: %v", err)
	}
	if base.GetBalance(b).Cmp(initial) != 0 {
		t.Fatal("failed block credited Common reward before all transactions completed")
	}
}

func TestCommonRPCV2RewardTamperingRejectedWithAndWithoutHandoff(t *testing.T) {
	for _, cached := range []bool{false, true} {
		for _, mutation := range []string{"reward-recipient", "reward-version", "admission-recipient-and-id", "admission-signer", "missing", "duplicate"} {
			t.Run(mutation+map[bool]string{false: "/uncached", true: "/cached"}[cached], func(t *testing.T) {
				processor, block, base, _, _ := v2ExecutionFixture(t)
				context := fhsSidecarValidationContext{genesisHash: processor.bc.genesisBlock.Hash()}
				if cached {
					validated, err := buildValidatedFHSSidecarLayout(processor.config, block, context)
					if err != nil {
						t.Fatal(err)
					}
					if err := verifyAndPublishValidatedFHSSidecars(processor.config, block, context, validated, processor.bc.validatedFHSSidecars); err != nil {
						t.Fatal(err)
					}
				}
				body := block.Body()
				switch mutation {
				case "reward-recipient":
					body.CommonTxRewards[0].RewardRecipient[0] ^= 1
				case "reward-version":
					body.CommonTxRewards[0].Version = 0
					body.CommonTxRewards[0].RewardRecipient = common.Address{}
				case "admission-recipient-and-id":
					b := body.CommonTxAdmissionBatches[0]
					b.RewardRecipient[0] ^= 1
					b.AdmissionID = types.CommonTxAdmissionID(b)
					for _, r := range body.CommonTxRewards {
						r.RewardRecipient = b.RewardRecipient
					}
				case "admission-signer":
					body.CommonTxAdmissionBatches[0].Miner[0] ^= 1
				case "missing":
					body.CommonTxRewards = body.CommonTxRewards[1:]
				case "duplicate":
					body.CommonTxRewards[1] = body.CommonTxRewards[0]
				}
				block.AttachCommonTxData(body.CommonTxAdmissionBatches, body.CommonTxAdmissionRefs, body.CommonTxRewards)
				if _, _, _, err := processor.Process(block, base.Copy(), vm.Config{}); err == nil {
					t.Fatal("tampered sidecar reached valid execution")
				}
			})
		}
	}
}

func TestCommonRPCV2MandatoryFromFirstBlockAndRestoresRecipient(t *testing.T) {
	db, miner, chainID, genesis, _ := resetAdmissionTestState(t)
	t.Cleanup(func() { SetCommonRPCAdmissionSigner(nil); SetCommonRPCAdmissionDatabase(nil) })
	now := uint64(time.Now().Unix())
	tx := testTransaction(902)
	b := common.HexToAddress("0xb123")
	config := &params.ChainConfig{FairHotstuff: true, ChainID: chainID}
	for _, invalid := range []common.Address{{}, miner} {
		if _, err := SignCommonRPCAdmissions([]common.Hash{tx.Hash()}, miner, chainID, genesis, 0, now, invalid); err == nil {
			t.Fatal("admission signed without distinct recipient at genesis")
		}
	}
	signed, err := SignAndRecordCommonRPCAdmissions([]common.Hash{tx.Hash()}, miner, chainID, genesis, 0, now, b)
	if err != nil {
		t.Fatal(err)
	}
	for _, height := range []uint64{1, 2, 100} {
		if _, err := CommonRPCAdmissionForBlockTransaction(tx, config, genesis, 0, height, now); err != nil {
			t.Fatalf("valid recipient proof rejected at block %d: %v", height, err)
		}
	}
	SetCommonRPCAdmissionDatabase(db)
	restored, ok := CommonRPCAdmissionForTransaction(tx.Hash())
	if !ok || restored.Batch.RewardRecipient != b || restored.Batch.AdmissionID != signed[0].Batch.AdmissionID {
		t.Fatal("restart lost mandatory reward recipient")
	}
	legacy := copyCommonRPCAdmissionBatch(restored.Batch)
	legacy.Version = 0
	legacy.RewardRecipient = common.Address{}
	if _, err := VerifyAndStoreCommonRPCAdmissionBatch(legacy, chainID, genesis); err == nil {
		t.Fatal("legacy recipient-less proof accepted")
	}
}

func TestCommonRPCV2SignerCannotChangeRecipientAfterSnapshot(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	SetCommonRPCAdmissionSigner(func(batch *types.CommonTxAdmissionBatch) error {
		batch.RewardRecipient[0] ^= 1
		batch.AdmissionID = types.CommonTxAdmissionID(batch)
		var err error
		batch.Signature, err = crypto.Sign(types.CommonTxAdmissionSigningHash(batch).Bytes(), key)
		return err
	})
	t.Cleanup(func() { SetCommonRPCAdmissionSigner(nil) })
	_, err = SignCommonRPCAdmissions([]common.Hash{common.HexToHash("0x123")}, crypto.PubkeyToAddress(key.PublicKey), big.NewInt(99), common.HexToHash("0x987"), 1, 1, common.HexToAddress("0xb123"))
	if err == nil || !strings.Contains(err.Error(), "modified signed batch fields") {
		t.Fatalf("signer changed fixed recipient: %v", err)
	}
}

func TestCommonRPCV2TrustedSelectionRejectsRecipientAndIDMutation(t *testing.T) {
	_, miner, chainID, genesis, _ := resetAdmissionTestState(t)
	t.Cleanup(func() { SetCommonRPCAdmissionSigner(nil); SetCommonRPCAdmissionDatabase(nil) })
	now := uint64(time.Now().Unix())
	tx := testTransaction(997)
	if _, err := SignAndRecordCommonRPCAdmissions([]common.Hash{tx.Hash()}, miner, chainID, genesis, 1, now, common.HexToAddress("0xb123")); err != nil {
		t.Fatal(err)
	}
	config := &params.ChainConfig{ChainID: chainID, FairHotstuff: true}
	selection, err := CommonRPCAdmissionForBlockTransaction(tx, config, genesis, 1, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	selection.Batch.RewardRecipient[0] ^= 1
	selection.Batch.AdmissionID = types.CommonTxAdmissionID(selection.Batch)
	if _, _, err := BuildCommonTxAdmissionsFromResults(types.Transactions{tx}, []CommonRPCAdmissionResult{selection}, config, genesis, 1, 1, now); err == nil || !strings.Contains(err.Error(), "modified after validation") {
		t.Fatalf("trusted proof mutation accepted: %v", err)
	}
}
