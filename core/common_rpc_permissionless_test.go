package core

import (
	"math/big"
	"testing"

	lru "github.com/hashicorp/golang-lru"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus/colossusX"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/params"
)

func TestCommonRPCIndependentOperatorsReceiveExecutionRewards(t *testing.T) {
	config := modernTestConfig(true, true, true)
	config.FairHotstuff = true
	genesis := types.NewBlockWithHeader(&types.Header{Number: new(big.Int), Difficulty: big.NewInt(1)})
	keyBlock := types.NewKeyBlock(&types.KeyBlockHeader{Number: new(big.Int), Difficulty: big.NewInt(1)})
	genesisHash := genesis.Hash()
	db := rawdb.NewMemoryDatabase()
	defer db.Close()
	SetCommonRPCAdmissionDatabase(db)
	SetCommonRPCAdmissionFinalizedLookup(nil)
	t.Cleanup(func() {
		SetCommonRPCAdmissionDatabase(nil)
		SetCommonRPCAdmissionFinalizedLookup(nil)
	})

	state := newModernTestState(t)
	senderKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sender := crypto.PubkeyToAddress(senderKey.PublicKey)
	initialBalance := big.NewInt(1_000_000_000_000_000_000)
	state.SetBalance(sender, initialBalance)
	const timestamp = uint64(100)
	const transferValue = int64(7)
	// Each ordinary transfer costs 21,000 gas at the protocol's fixed price.
	fee := new(big.Int).Mul(big.NewInt(21_000), big.NewInt(params.FixedTransferGasPricePerGas))
	rewardAmount := new(big.Int).Div(new(big.Int).Set(fee), big.NewInt(5))
	burnAmount := new(big.Int).Sub(new(big.Int).Set(fee), rewardAmount)
	txs := make(types.Transactions, 2)
	operators := make([]common.Address, len(txs))
	recipients := []common.Address{common.HexToAddress("0x2001"), common.HexToAddress("0x2002")}
	rewards := make([]*types.CommonTxReward, len(txs))
	selections := make([]CommonRPCAdmissionResult, len(txs))
	for index := range txs {
		// Operator keys are generated after the chain identity is established;
		// neither operator is registered in chain configuration or genesis.
		operatorKey, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		operators[index] = crypto.PubkeyToAddress(operatorKey.PublicKey)
		txs[index], err = types.SignTx(types.NewTransaction(uint64(index), recipients[index], big.NewInt(transferValue), params.TxGas, big.NewInt(params.FixedTransferGasPricePerGas), nil), types.LatestSignerForChainID(config.ChainID), senderKey)
		if err != nil {
			t.Fatal(err)
		}
		certificate := stateProcessorTestAdmissionBatch(t, operatorKey, config.ChainID, genesisHash, keyBlock.NumberU64(), timestamp, []common.Hash{txs[index].Hash()})
		if _, err := VerifyAndStoreCommonRPCAdmissionBatch(certificate, config.ChainID, genesisHash); err != nil {
			t.Fatalf("operator %d admission: %v", index, err)
		}
		selections[index], err = CommonRPCAdmissionForBlockTransaction(txs[index], config, genesisHash, keyBlock.NumberU64(), 1, timestamp)
		if err != nil {
			t.Fatalf("operator %d proposal selection: %v", index, err)
		}
		if selections[index].Batch.Miner != operators[index] {
			t.Fatalf("operator %d admission attributed to %s", index, selections[index].Batch.Miner)
		}
		rewards[index] = &types.CommonTxReward{
			TxHash: txs[index].Hash(), Approver: operators[index],
			ApproverReward: new(big.Int).Set(rewardAmount), Burn: new(big.Int).Set(burnAmount),
		}
	}
	batches, refs, err := BuildCommonTxAdmissionsFromResults(txs, selections, config, genesisHash, keyBlock.NumberU64(), 1, timestamp)
	if err != nil {
		t.Fatalf("build proposal admissions: %v", err)
	}
	block := types.NewBlockWithHeader(&types.Header{
		ParentHash: genesisHash, Number: big.NewInt(1), Difficulty: big.NewInt(1),
		BlockType: types.FastTx_Block, KeyHash: keyBlock.Hash(), Time: timestamp,
		Coinbase: common.HexToAddress("0xc001"), GasLimit: 2 * params.TxGas,
		BaseFee: big.NewInt(params.FixedBaseFeePerGas),
	}).WithBody(txs, nil)
	block.AttachCommonTxData(batches, refs, rewards)
	keyCache, _ := lru.New(1)
	keyCache.Add(keyBlock.Hash(), keyBlock)
	numberCache, _ := lru.New(1)
	numberCache.Add(keyBlock.Hash(), keyBlock.NumberU64())
	engine := colossusX.NewFaker()
	defer engine.Close()
	chain := &BlockChain{
		chainConfig: config, genesisBlock: genesis, engine: engine,
		keyBlockChain: &KeyBlockChain{blockCache: keyCache, khc: &KeyHeaderChain{numberCache: numberCache}},
	}
	// Block import must validate the proof from the block, independent of the
	// proposal node's local admission index.
	SetCommonRPCAdmissionDatabase(nil)
	processor := NewStateProcessor(config, chain, engine)
	receipts, _, gasUsed, err := processor.Process(block, state, vm.Config{})
	if err != nil {
		t.Fatalf("execute independently admitted transactions: %v", err)
	}
	if len(receipts) != len(txs) || gasUsed != 2*params.TxGas {
		t.Fatalf("execution receipts=%d gas=%d, want 2 receipts and %d gas", len(receipts), gasUsed, 2*params.TxGas)
	}
	for index, operator := range operators {
		if receipts[index].Status != types.ReceiptStatusSuccessful || receipts[index].GasUsed != params.TxGas {
			t.Fatalf("operator %d transaction receipt: %+v", index, receipts[index])
		}
		if got := state.GetBalance(operator); got.Cmp(rewardAmount) != 0 {
			t.Fatalf("operator %d reward balance = %v, want 20%% fee = %v", index, got, rewardAmount)
		}
		if got := state.GetBalance(recipients[index]); got.Cmp(big.NewInt(transferValue)) != 0 {
			t.Fatalf("recipient %d balance = %v, want %d", index, got, transferValue)
		}
	}
	wantSender := new(big.Int).Sub(new(big.Int).Set(initialBalance), new(big.Int).Mul(big.NewInt(2), new(big.Int).Add(new(big.Int).Set(fee), big.NewInt(transferValue))))
	if got := state.GetBalance(sender); got.Cmp(wantSender) != 0 || state.GetNonce(sender) != 2 {
		t.Fatalf("sender balance=%v nonce=%d, want balance=%v nonce=2", got, state.GetNonce(sender), wantSender)
	}
}
