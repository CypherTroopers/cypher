package core

import (
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

type fhsPrevRandaoTestKeys struct {
	byHash   map[common.Hash]*types.KeyBlock
	byNumber map[uint64]*types.KeyBlock
}

func (keys *fhsPrevRandaoTestKeys) GetBlockByHash(hash common.Hash) *types.KeyBlock {
	return keys.byHash[hash]
}

func (keys *fhsPrevRandaoTestKeys) GetBlockByNumber(number uint64) *types.KeyBlock {
	return keys.byNumber[number]
}

func fhsPrevRandaoTestConfig(shanghai uint64) *params.ChainConfig {
	config := &params.ChainConfig{ChainID: big.NewInt(1), FairHotstuff: true}
	config.SetModernForkConfig(&params.ModernForkConfig{LondonBlock: big.NewInt(0), ShanghaiTime: &shanghai})
	return config
}

func fhsPrevRandaoTestKey(number uint64, parent, mix common.Hash) *types.KeyBlock {
	return types.NewKeyBlock(&types.KeyBlockHeader{
		ParentHash: parent,
		Difficulty: big.NewInt(1),
		Number:     new(big.Int).SetUint64(number),
		Time:       number + 1,
		BlockType:  types.TimeReconfig,
		MixDigest:  mix,
	})
}

func fhsPrevRandaoTestBlock(blockType uint8, keyHash, mix common.Hash) *types.Block {
	return types.NewBlockWithHeader(&types.Header{
		Number:     big.NewInt(1),
		Difficulty: big.NewInt(1),
		Time:       1,
		BlockType:  blockType,
		KeyHash:    keyHash,
		MixDigest:  mix,
	})
}

func TestValidateFHSPrevRandaoBindsOrdinaryBlockToCanonicalKey(t *testing.T) {
	config := fhsPrevRandaoTestConfig(0)
	key := fhsPrevRandaoTestKey(7, common.HexToHash("0x70"), common.HexToHash("0x7711"))
	keys := &fhsPrevRandaoTestKeys{
		byHash:   map[common.Hash]*types.KeyBlock{key.Hash(): key},
		byNumber: map[uint64]*types.KeyBlock{key.NumberU64(): key},
	}
	block := fhsPrevRandaoTestBlock(types.FastTx_Block, key.Hash(), key.MixDigest())
	if err := validateFHSPrevRandao(config, block, keys); err != nil {
		t.Fatalf("canonical PREVRANDAO rejected: %v", err)
	}

	tampered := fhsPrevRandaoTestBlock(types.FastTx_Block, key.Hash(), common.HexToHash("0xdead"))
	if err := validateFHSPrevRandao(config, tampered, keys); err == nil || !strings.Contains(err.Error(), "PREVRANDAO mismatch") {
		t.Fatalf("tampered PREVRANDAO error = %v", err)
	}

	sibling := fhsPrevRandaoTestKey(key.NumberU64(), key.ParentHash(), common.HexToHash("0x7722"))
	keys.byHash[sibling.Hash()] = sibling
	nonCanonical := fhsPrevRandaoTestBlock(types.SlowTx_Block, sibling.Hash(), sibling.MixDigest())
	if err := validateFHSPrevRandao(config, nonCanonical, keys); err == nil || !strings.Contains(err.Error(), "not canonical") {
		t.Fatalf("non-canonical key error = %v", err)
	}
}

func TestValidateFHSPrevRandaoBindsKeyCarrierToEmbeddedKeyBlock(t *testing.T) {
	config := fhsPrevRandaoTestConfig(0)
	parent := common.HexToHash("0x8011")
	key := fhsPrevRandaoTestKey(8, parent, common.HexToHash("0x8822"))
	carrier := fhsPrevRandaoTestBlock(types.Key_Block, parent, key.MixDigest())
	carrier.SetKeyblock(key)
	if err := validateFHSPrevRandao(config, carrier, nil); err != nil {
		t.Fatalf("valid key carrier PREVRANDAO rejected: %v", err)
	}

	tampered := fhsPrevRandaoTestBlock(types.Key_Block, parent, common.HexToHash("0xdead"))
	tampered.SetKeyblock(key)
	if err := validateFHSPrevRandao(config, tampered, nil); err == nil || !strings.Contains(err.Error(), "key carrier mismatch") {
		t.Fatalf("tampered carrier PREVRANDAO error = %v", err)
	}

	wrongParent := fhsPrevRandaoTestBlock(types.Key_Block, common.HexToHash("0xbad"), key.MixDigest())
	wrongParent.SetKeyblock(key)
	if err := validateFHSPrevRandao(config, wrongParent, nil); err == nil || !strings.Contains(err.Error(), "parent mismatch") {
		t.Fatalf("carrier parent error = %v", err)
	}
}

func TestValidateFHSPrevRandaoActivatesWithShanghai(t *testing.T) {
	config := fhsPrevRandaoTestConfig(2)
	block := fhsPrevRandaoTestBlock(types.FastTx_Block, common.Hash{}, common.HexToHash("0xdead"))
	if err := validateFHSPrevRandao(config, block, nil); err != nil {
		t.Fatalf("pre-Shanghai DIFFICULTY block was subject to PREVRANDAO binding: %v", err)
	}
}

func TestPrevRandaoIsIdenticalAcrossSerialMVCCAndProposalExecution(t *testing.T) {
	config := evmMVCTestConfig()
	base := newModernTestState(t)
	contract := common.HexToAddress("0x4399000000000000000000000000000000000044")
	// PREVRANDAO, PUSH1(0), SSTORE, STOP. Two senders target the same slot so
	// the optimistic executor accepts one detached result and serially
	// re-executes the conflicting result in canonical order.
	base.SetCode(contract, []byte{byte(vm.DIFFICULTY), byte(vm.PUSH1), 0, byte(vm.SSTORE), byte(vm.STOP)})
	base.SetNonce(contract, 1)

	header := &types.Header{
		ParentHash: common.HexToHash("0x4399"),
		Coinbase:   common.HexToAddress("0x9000000000000000000000000000000000000009"),
		Number:     big.NewInt(1),
		Difficulty: big.NewInt(7),
		GasLimit:   300_000,
		Time:       1,
		BaseFee:    big.NewInt(params.FixedBaseFeePerGas),
		MixDigest:  common.HexToHash("0xabcdef4399"),
		BlockType:  types.SlowTx_Block,
	}
	signer := types.LatestSignerForChainID(config.ChainID)
	keys := []string{
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	txs := make(types.Transactions, len(keys))
	for index, keyHex := range keys {
		key, err := crypto.HexToECDSA(keyHex)
		if err != nil {
			t.Fatal(err)
		}
		base.SetBalance(crypto.PubkeyToAddress(key.PublicKey), new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil))
		unsigned := types.NewTx(&types.DynamicFeeTx{
			ChainID:   config.ChainID,
			GasTipCap: big.NewInt(1),
			GasFeeCap: new(big.Int).Add(big.NewInt(params.FixedBaseFeePerGas), big.NewInt(1)),
			Gas:       100_000,
			To:        &contract,
			Value:     new(big.Int),
		})
		txs[index], err = types.SignTx(unsigned, signer, key)
		if err != nil {
			t.Fatal(err)
		}
	}
	prepareEVMOnlyHistory(base, header)
	base.Finalise(true)
	block := types.NewBlockWithHeader(header).WithBody(txs, nil)
	engine := colossusX.NewFaker()
	defer engine.Close()
	chain := &BlockChain{chainConfig: config, engine: engine}

	runSerial := func(statedb *state.StateDB) (types.Receipts, uint64) {
		gasPool := new(GasPool).AddGas(block.GasLimit())
		var usedGas uint64
		receipts := make(types.Receipts, 0, len(txs))
		for index, tx := range txs {
			statedb.Prepare(tx.Hash(), block.Hash(), index)
			receipt, err := ApplyTransaction(config, chain, nil, gasPool, statedb, header, tx, &usedGas, vm.Config{})
			if err != nil {
				t.Fatalf("serial transaction %d: %v", index, err)
			}
			receipts = append(receipts, receipt)
		}
		return receipts, usedGas
	}

	serialState := base.Copy()
	serialReceipts, serialGas := runSerial(serialState)

	mvccState := base.Copy()
	mvccPool := new(GasPool).AddGas(block.GasLimit())
	var mvccGas uint64
	mvccReceipts := make(types.Receipts, 0, len(txs))
	processor := NewStateProcessor(config, chain, engine)
	if err := processor.processEVMOptimistic(block, mvccState, mvccPool, &mvccGas, vm.Config{}, func(_ int, _ *types.Transaction, receipt *types.Receipt) error {
		mvccReceipts = append(mvccReceipts, receipt)
		return nil
	}); err != nil {
		t.Fatalf("MVCC execution: %v", err)
	}

	proposalState := base.Copy()
	proposalReceipts, _, proposalGas, err := ExecuteEVMProposalTransactions(config, chain, header, txs, proposalState, vm.Config{})
	if err != nil {
		t.Fatalf("proposal execution: %v", err)
	}
	want := header.MixDigest
	for name, statedb := range map[string]*state.StateDB{
		"serial": serialState, "MVCC": mvccState, "proposal": proposalState,
	} {
		if got := statedb.GetState(contract, common.Hash{}); got != want {
			t.Fatalf("%s PREVRANDAO result = %s, want %s", name, got, want)
		}
	}
	if serialGas != mvccGas || serialGas != proposalGas ||
		!reflect.DeepEqual(serialReceipts, mvccReceipts) || !reflect.DeepEqual(serialReceipts, proposalReceipts) ||
		serialState.IntermediateRoot(true) != mvccState.IntermediateRoot(true) || serialState.IntermediateRoot(true) != proposalState.IntermediateRoot(true) {
		t.Fatal("PREVRANDAO execution diverged between serial, MVCC and proposer paths")
	}
}
