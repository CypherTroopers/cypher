// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package reconfig

import (
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/consensus/colossusX"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
)

type a02RegressionBackend struct {
	bc     *core.BlockChain
	kbc    *core.KeyBlockChain
	cp     *core.CandidatePool
	engine consensus.Engine
}

func (backend *a02RegressionBackend) BlockChain() *core.BlockChain       { return backend.bc }
func (backend *a02RegressionBackend) KeyBlockChain() *core.KeyBlockChain { return backend.kbc }
func (backend *a02RegressionBackend) CandidatePool() *core.CandidatePool { return backend.cp }
func (backend *a02RegressionBackend) Engine() consensus.Engine           { return backend.engine }

func a02RegressionPublicKey(t *testing.T) string {
	t.Helper()
	var secret bls.SecretKey
	secret.SetByCSPRNG()
	return secret.GetPublicKey().SerializeToHexStr()
}

func a02RegressionChainConfig() *params.ChainConfig {
	config := *params.TestChainConfig
	config.FairHotstuff = false
	config.FixedCommittee = false
	config.FixedLeader = false
	return &config
}

func TestVerifyKeyBlockKnownBlockRejectsAlternateBodyAndUnsafeDynamicRecovery(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	mux := new(event.TypeMux)
	backend := &a02RegressionBackend{}
	now := uint64(time.Now().Unix())
	memberPublic := a02RegressionPublicKey(t)
	candidatePublic := a02RegressionPublicKey(t)
	memberCoinbase := (common.Address{0x11}).Hex()
	candidateCoinbase := (common.Address{0x22}).Hex()
	committee := &bftview.Committee{List: []*common.Cnode{{
		Address:  "127.0.0.1:30303",
		CoinBase: memberCoinbase,
		Public:   memberPublic,
	}}}
	genesis := types.NewKeyBlock(&types.KeyBlockHeader{
		Difficulty:    big.NewInt(1),
		Number:        big.NewInt(0),
		Time:          now - uint64(params.KeyBlockMinInterval/time.Second),
		BlockType:     types.Initialization,
		CommitteeHash: committee.RlpHash(),
	})
	known := types.NewKeyBlock(&types.KeyBlockHeader{
		ParentHash:    genesis.Hash(),
		Difficulty:    big.NewInt(1),
		Number:        big.NewInt(1),
		Time:          now,
		BlockType:     types.PowReconfig,
		CommitteeHash: committee.RlpHash(),
		T_Number:      7,
	}).WithBody(candidatePublic, candidateCoinbase, memberPublic, memberCoinbase, memberPublic, memberCoinbase)
	for number, block := range []*types.KeyBlock{genesis, known} {
		rawdb.WriteKeyBlock(db, block)
		rawdb.WriteKeyBlockHash(db, block.Hash(), block.NumberU64())
		rawdb.WriteTd(db, block.Hash(), block.NumberU64(), big.NewInt(int64(number+1)))
	}
	rawdb.WriteHeadKeyBlockHash(db, known.Hash())
	rawdb.WriteHeadKeyHeaderHash(db, known.Hash())

	bftview.SetCommitteeConfig(db, nil, nil)
	if !bftview.WriteCommittee(genesis.NumberU64(), genesis.Hash(), committee) {
		t.Fatal("store genesis committee")
	}
	kbc, err := core.NewKeyBlockChain(backend, db, nil, a02RegressionChainConfig(), nil, mux)
	if err != nil {
		t.Fatalf("create key block chain: %v", err)
	}
	backend.kbc = kbc
	bftview.SetCommitteeConfig(db, kbc, nil)
	t.Cleanup(func() {
		mux.Stop()
		kbc.Stop()
		bftview.SetCommitteeConfig(nil, nil, nil)
		db.Close()
	})

	candidate := types.NewCandidate(
		genesis.Hash(),
		big.NewInt(1),
		known.NumberU64(),
		known.T_Number(),
		nil,
		net.ParseIP("127.0.0.2"),
		candidatePublic,
		candidateCoinbase,
		30304,
	)
	candidate.KeyCandidate.Time = known.Time()
	keyS := &keyService{kbc: kbc}

	alternate := known.WithBody(
		known.InPubKey(),
		known.InAddress(),
		known.OutPubKey(),
		(common.Address{0x33}).Hex(),
		known.LeaderPubKey(),
		known.LeaderAddress(),
	)
	if alternate.Hash() != known.Hash() {
		t.Fatal("test requires the legacy header-only key block hash")
	}
	if err := keyS.verifyKeyBlock(alternate, candidate, known.T_Number()); err == nil ||
		!strings.Contains(err.Error(), "known key block body mismatch") {
		t.Fatalf("alternate body error = %v, want known-body mismatch", err)
	}

	if member := bftview.LoadMember(known.NumberU64(), known.Hash(), true); member != nil {
		t.Fatal("test precondition violated: dynamic committee unexpectedly exists")
	}
	if err := keyS.verifyKeyBlock(known.CopyMe(), candidate, known.T_Number()); err == nil ||
		!strings.Contains(err.Error(), "cannot reconstruct known dynamic committee without committed endpoint evidence") {
		t.Fatalf("missing dynamic committee error = %v, want fail-closed recovery", err)
	}
}

func TestCandidateCacheSurvivesEmptyRefreshButClearsAfterTxHeadRewind(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	mux := new(event.TypeMux)
	engine := colossusX.NewFaker()
	backend := &a02RegressionBackend{engine: engine}
	config := a02RegressionChainConfig()
	memberPublic := a02RegressionPublicKey(t)
	candidatePublic := a02RegressionPublicKey(t)
	memberCoinbase := (common.Address{0x41}).Hex()
	candidateCoinbase := (common.Address{0x42}).Hex()
	committee := &bftview.Committee{List: []*common.Cnode{{
		Address:  "127.0.0.1:30303",
		CoinBase: memberCoinbase,
		Public:   memberPublic,
	}}}
	now := uint64(time.Now().Unix())
	keyGenesis := types.NewKeyBlock(&types.KeyBlockHeader{
		Difficulty:    big.NewInt(1),
		Number:        big.NewInt(0),
		Time:          now - uint64(params.KeyBlockMinInterval/time.Second),
		BlockType:     types.Initialization,
		CommitteeHash: committee.RlpHash(),
	})
	rawdb.WriteKeyBlock(db, keyGenesis)
	rawdb.WriteKeyBlockHash(db, keyGenesis.Hash(), keyGenesis.NumberU64())
	rawdb.WriteTd(db, keyGenesis.Hash(), keyGenesis.NumberU64(), keyGenesis.Difficulty())
	rawdb.WriteHeadKeyBlockHash(db, keyGenesis.Hash())
	rawdb.WriteHeadKeyHeaderHash(db, keyGenesis.Hash())
	bftview.SetCommitteeConfig(db, nil, nil)
	if !bftview.WriteCommittee(keyGenesis.NumberU64(), keyGenesis.Hash(), committee) {
		t.Fatal("store candidate fixture committee")
	}
	kbc, err := core.NewKeyBlockChain(backend, db, nil, config, engine, mux)
	if err != nil {
		t.Fatalf("create key block chain: %v", err)
	}
	backend.kbc = kbc
	bftview.SetCommitteeConfig(db, kbc, nil)

	txGenesis, err := (&core.Genesis{
		Config:     config,
		Difficulty: new(big.Int).Set(params.GenesisDifficulty),
		GasLimit:   params.GenesisGasLimit,
	}).Commit(db)
	if err != nil {
		t.Fatalf("commit transaction genesis: %v", err)
	}
	blocks, receipts := core.GenerateChain(config, txGenesis, engine, db, 3, nil)
	totalDifficulty := txGenesis.Difficulty()
	for index, block := range blocks {
		totalDifficulty = new(big.Int).Add(totalDifficulty, block.Difficulty())
		rawdb.WriteTd(db, block.Hash(), block.NumberU64(), totalDifficulty)
		rawdb.WriteBlock(db, block)
		rawdb.WriteReceipts(db, block.Hash(), block.NumberU64(), receipts[index])
		rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
	}
	lastBlock := blocks[len(blocks)-1]
	rawdb.WriteHeadBlockHash(db, lastBlock.Hash())
	rawdb.WriteHeadFastBlockHash(db, lastBlock.Hash())
	rawdb.WriteHeadHeaderHash(db, lastBlock.Hash())
	bc, err := core.NewBlockChain(db, nil, config, engine, vm.Config{}, nil, nil, kbc)
	if err != nil {
		t.Fatalf("create transaction block chain: %v", err)
	}
	backend.bc = bc
	cp := core.NewCandidatePool(backend, mux, db)
	backend.cp = cp
	cp.CheckMinerPort = func(string, uint64, uint64) {}
	t.Cleanup(func() {
		mux.Stop()
		bc.Stop()
		kbc.Stop()
		_ = engine.Close()
		bftview.SetCommitteeConfig(nil, nil, nil)
		db.Close()
	})

	candidate := types.NewCandidate(
		keyGenesis.Hash(),
		nil,
		keyGenesis.NumberU64()+1,
		bc.CurrentBlockN(),
		nil,
		net.ParseIP("127.0.0.2"),
		candidatePublic,
		candidateCoinbase,
		30304,
	)
	candidate.KeyCandidate.Time = keyGenesis.Time() + uint64(params.KeyBlockMinInterval/time.Second)
	if err := engine.PrepareCandidate(kbc, candidate, len(committee.List)); err != nil {
		t.Fatalf("prepare candidate: %v", err)
	}
	if err := cp.ValidateCandidate(candidate); err != nil {
		t.Fatalf("candidate fixture is not valid: %v", err)
	}

	keyS := &keyService{
		candidatepool: cp,
		bc:            bc,
		kbc:           kbc,
		engine:        engine,
		config:        config,
	}
	if contents := cp.Content(); len(contents) != 0 {
		t.Fatalf("NewView cache test requires an empty pool, have %d candidates", len(contents))
	}
	keyS.setBestCandidate([]*types.Candidate{candidate})
	if cached := keyS.getBestCandidate(true); cached != candidate {
		t.Fatalf("valid NewView-only winner was not retained across empty refresh: got %p want %p", cached, candidate)
	}

	if err := cp.AddRemote(candidate, false); err != nil {
		t.Fatalf("add candidate through public remote path: %v", err)
	}
	cp.CheckMinerMsgAck(net.JoinHostPort(net.IP(candidate.IP).String(), "30304"), bc.CurrentBlockN(), kbc.CurrentBlockN())
	if !cp.FoundCandidate(candidate.KeyCandidate.Number, candidate.KeyCandidate.ParentHash, candidate.PubKey) {
		t.Fatal("valid candidate was not found before transaction-head rewind")
	}

	if err := bc.SetHead(1); err != nil {
		t.Fatalf("rewind transaction head: %v", err)
	}
	if got := bc.CurrentBlockN(); got != 1 {
		t.Fatalf("transaction head after rewind = %d, want 1", got)
	}
	if cached := keyS.getBestCandidate(false); cached != nil {
		t.Fatalf("tx-head-invalid cached candidate survived rewind: %v", cached.Hash())
	}
	if cp.FoundCandidate(candidate.KeyCandidate.Number, candidate.KeyCandidate.ParentHash, candidate.PubKey) {
		t.Fatal("stale high-T candidate still suppressed fresh work after transaction-head rewind")
	}
}
