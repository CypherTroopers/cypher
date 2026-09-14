package reconfig

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus/colossusX"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
)

func newPrevRandaoProposalFixture(t *testing.T) (*txService, *types.KeyBlock) {
	t.Helper()

	db := rawdb.NewMemoryDatabase()
	config := *params.TestChainConfig
	config.ChainID = big.NewInt(73_039)
	config.FairHotstuff = false
	zeroBlock := big.NewInt(0)
	zeroTime := uint64(0)
	config.SetModernForkConfig(&params.ModernForkConfig{
		BerlinBlock:  zeroBlock,
		LondonBlock:  zeroBlock,
		ShanghaiTime: &zeroTime,
	})

	keyBlock := types.NewKeyBlock(&types.KeyBlockHeader{
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(0),
		Time:       1,
		BlockType:  types.Initialization,
		MixDigest:  common.HexToHash("0x73a0"),
	})
	committee := &bftview.Committee{List: []*common.Cnode{{Address: "validator"}}}
	keyBlock.SetCommitteeHash(committee.RlpHash())
	rawdb.WriteKeyBlock(db, keyBlock)
	rawdb.WriteKeyBlockHash(db, keyBlock.Hash(), keyBlock.NumberU64())
	rawdb.WriteHeadKeyBlockHash(db, keyBlock.Hash())
	rawdb.WriteHeadKeyHeaderHash(db, keyBlock.Hash())
	rawdb.WriteTd(db, keyBlock.Hash(), keyBlock.NumberU64(), keyBlock.Difficulty())
	bftview.SetCommitteeConfig(db, nil, nil)
	if !bftview.WriteCommittee(keyBlock.NumberU64(), keyBlock.Hash(), committee) {
		t.Fatal("write key-block committee")
	}
	kbc, err := core.NewKeyBlockChain(&fhsEpochTestBackend{}, db, nil, &config, nil, new(event.TypeMux))
	if err != nil {
		t.Fatalf("create key block chain: %v", err)
	}

	genesis := (&core.Genesis{
		Config:     &config,
		Difficulty: big.NewInt(1),
		GasLimit:   30_000_000,
		Timestamp:  1,
	}).MustCommit(db)
	engine := colossusX.NewFaker()
	bc, err := core.NewBlockChain(db, nil, &config, engine, vm.Config{}, nil, nil, kbc)
	if err != nil {
		kbc.Stop()
		engine.Close()
		t.Fatalf("create transaction block chain: %v", err)
	}
	t.Cleanup(func() {
		bc.Stop()
		kbc.Stop()
		engine.Close()
		config.SetModernForkConfig(nil)
		db.Close()
	})

	proposed := newProposedChain()
	proposed.clear(genesis)
	return &txService{bc: bc, kbc: kbc, config: &config, proposedChain: proposed}, keyBlock
}

func TestCaptureProposalGenerationBindsPrevRandaoBeforeExecution(t *testing.T) {
	service, keyBlock := newPrevRandaoProposalFixture(t)
	parent := service.bc.CurrentBlock()
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     new(big.Int).Add(parent.Number(), common.Big1),
		Difficulty: big.NewInt(1),
		Time:       parent.Time() + 1,
		BlockType:  types.SlowTx_Block,
		MixDigest:  common.HexToHash("0xdead"),
	}
	work := &work{header: header}

	service.mu.Lock()
	generation, err := service.captureProposalGeneration(work)
	service.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if header.KeyHash != generation.keyHash || header.KeyHash != keyBlock.Hash() {
		t.Fatalf("proposal key context = %s, want captured key block %s", header.KeyHash, keyBlock.Hash())
	}
	if header.MixDigest != keyBlock.MixDigest() {
		t.Fatalf("proposal PREVRANDAO = %s, want captured key-block mix digest %s", header.MixDigest, keyBlock.MixDigest())
	}
}

func prevRandaoValidationConfig(t *testing.T) *params.ChainConfig {
	t.Helper()
	zeroBlock := big.NewInt(0)
	zeroTime := uint64(0)
	config := &params.ChainConfig{ChainID: big.NewInt(73_040)}
	config.SetModernForkConfig(&params.ModernForkConfig{
		BerlinBlock:  zeroBlock,
		LondonBlock:  zeroBlock,
		ShanghaiTime: &zeroTime,
	})
	t.Cleanup(func() { config.SetModernForkConfig(nil) })
	return config
}

func TestVerifyHotstuffProposalPrevRandaoRejectsProposerValue(t *testing.T) {
	config := prevRandaoValidationConfig(t)
	keyBlock := types.NewKeyBlock(&types.KeyBlockHeader{
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(4),
		MixDigest:  common.HexToHash("0x4400"),
	})
	header := &types.Header{
		Number:     big.NewInt(9),
		Difficulty: big.NewInt(1),
		Time:       1,
		BlockType:  types.FastTx_Block,
		KeyHash:    keyBlock.Hash(),
		MixDigest:  keyBlock.MixDigest(),
	}
	if err := verifyHotstuffProposalPrevRandao(config, types.NewBlockWithHeader(header), keyBlock); err != nil {
		t.Fatalf("valid key-bound PREVRANDAO rejected: %v", err)
	}

	tampered := types.CopyHeader(header)
	tampered.MixDigest = common.HexToHash("0x4401")
	if err := verifyHotstuffProposalPrevRandao(config, types.NewBlockWithHeader(tampered), keyBlock); err == nil {
		t.Fatal("proposer-controlled PREVRANDAO was accepted")
	}

	wrongKey := types.CopyHeader(header)
	wrongKey.KeyHash = common.HexToHash("0x4402")
	if err := verifyHotstuffProposalPrevRandao(config, types.NewBlockWithHeader(wrongKey), keyBlock); err == nil {
		t.Fatal("PREVRANDAO resolved through a different KeyHash was accepted")
	}
}

func TestVerifyHotstuffKeyCarrierBindsOuterPrevRandao(t *testing.T) {
	config := prevRandaoValidationConfig(t)
	currentKey := types.NewKeyBlock(&types.KeyBlockHeader{
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(4),
		MixDigest:  common.HexToHash("0x4500"),
	})
	carriedKey := types.NewKeyBlock(&types.KeyBlockHeader{
		ParentHash: currentKey.Hash(),
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(5),
		MixDigest:  common.HexToHash("0x4501"),
	})
	header := &types.Header{
		Number:     big.NewInt(9),
		Difficulty: big.NewInt(1),
		Time:       1,
		BlockType:  types.Key_Block,
		KeyHash:    currentKey.Hash(),
		MixDigest:  carriedKey.MixDigest(),
	}
	carrier := types.NewBlockWithHeader(header)
	carrier.SetKeyblock(carriedKey)
	if err := verifyHotstuffProposalPrevRandao(config, carrier, currentKey); err != nil {
		t.Fatalf("valid key-block PREVRANDAO carrier rejected: %v", err)
	}

	tamperedHeader := types.CopyHeader(header)
	tamperedHeader.MixDigest = common.HexToHash("0x4502")
	tampered := types.NewBlockWithHeader(tamperedHeader)
	tampered.SetKeyblock(carriedKey)
	if err := verifyHotstuffProposalPrevRandao(config, tampered, currentKey); err == nil {
		t.Fatal("key-block carrier with mismatched outer PREVRANDAO was accepted")
	}

	wrongParentHeader := types.CopyHeader(header)
	wrongParentHeader.KeyHash = common.HexToHash("0x4503")
	wrongParent := types.NewBlockWithHeader(wrongParentHeader)
	wrongParent.SetKeyblock(carriedKey)
	if err := verifyHotstuffProposalPrevRandao(config, wrongParent, currentKey); err == nil {
		t.Fatal("key-block carrier with mismatched outer key parent was accepted")
	}

	missingPayload := types.NewBlockWithHeader(header)
	if err := verifyHotstuffProposalPrevRandao(config, missingPayload, currentKey); err == nil {
		t.Fatal("key-block PREVRANDAO carrier without embedded key block was accepted")
	}
}
