package core

import (
	"errors"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	lru "github.com/hashicorp/golang-lru"
)

type fhsCanonicalHeadTestValidator struct{}

func (*fhsCanonicalHeadTestValidator) ValidateBody(*types.Block) error { return nil }
func (*fhsCanonicalHeadTestValidator) ValidateBodyWithHotstuffParent(*types.Block) error {
	return nil
}
func (*fhsCanonicalHeadTestValidator) ValidateState(*types.Block, *state.StateDB, types.Receipts, uint64) error {
	return nil
}
func (*fhsCanonicalHeadTestValidator) VerifySignature(*types.Block) error { return nil }
func (*fhsCanonicalHeadTestValidator) VerifyFHS2ChainCommitProof(*types.Block, *hotstuff.SignedState) error {
	return nil
}

func TestGetCommitteeByHashUsesExactHistoricalKeyBlock(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	defer db.Close()

	historicalCommittee := &bftview.Committee{List: []*common.Cnode{{
		Address:  "historical:1",
		CoinBase: "historical",
		Public:   "historical-public-key",
	}}}
	canonicalCommittee := &bftview.Committee{List: []*common.Cnode{{
		Address:  "canonical:1",
		CoinBase: "canonical",
		Public:   "canonical-public-key",
	}}}
	historical := &types.KeyBlockHeader{
		Difficulty:    big.NewInt(1),
		Number:        big.NewInt(2),
		Time:          1,
		CommitteeHash: historicalCommittee.RlpHash(),
	}
	canonical := types.CopyKeyBlockHeader(historical)
	canonical.Time = 2
	canonical.CommitteeHash = canonicalCommittee.RlpHash()
	historicalHash := historical.Hash()
	canonicalHash := canonical.Hash()

	rawdb.WriteKeyHeader(db, historical)
	rawdb.WriteKeyHeader(db, canonical)
	rawdb.WriteKeyBlockHash(db, canonicalHash, 2)

	bftview.SetCommitteeConfig(db, nil, nil)
	if !bftview.WriteCommittee(2, historicalHash, historicalCommittee) {
		t.Fatal("failed to store historical committee")
	}
	if !bftview.WriteCommittee(2, canonicalHash, canonicalCommittee) {
		t.Fatal("failed to store canonical committee")
	}

	numberCache, err := lru.New(headerCacheLimit)
	if err != nil {
		t.Fatal(err)
	}
	headerCache, err := lru.New(headerCacheLimit)
	if err != nil {
		t.Fatal(err)
	}
	blockCache, err := lru.New(blockCacheLimit)
	if err != nil {
		t.Fatal(err)
	}
	kbc := &KeyBlockChain{
		db:         db,
		blockCache: blockCache,
		khc: &KeyHeaderChain{
			chainDb:     db,
			headerCache: headerCache,
			numberCache: numberCache,
		},
	}

	got := kbc.GetCommitteeByHash(historicalHash)
	if len(got) != 1 || got[0].Public != historicalCommittee.List[0].Public {
		t.Fatalf("resolved wrong committee for historical hash: %#v", got)
	}
}

func TestCandidateProposalRevisionTracksOnlyVisibleChanges(t *testing.T) {
	lookup := newCandidateLookup(nil)
	candidate := types.NewCandidate(common.HexToHash("0xc1"), big.NewInt(1), 2, 10, nil, nil, "candidate-public", "candidate-coinbase", 1)

	if got := lookup.Revision(); got != 0 {
		t.Fatalf("initial candidate revision = %d, want 0", got)
	}
	if exists := lookup.Add(candidate); exists {
		t.Fatal("new candidate reported as duplicate")
	}
	if got := lookup.Revision(); got != 1 {
		t.Fatalf("candidate revision after add = %d, want 1", got)
	}
	if exists := lookup.Add(candidate); !exists {
		t.Fatal("duplicate candidate reported as new")
	}
	if got := lookup.Revision(); got != 1 {
		t.Fatalf("duplicate add advanced candidate revision to %d", got)
	}
	lookup.ClearObsolete(big.NewInt(1))
	if got := lookup.Revision(); got != 1 {
		t.Fatalf("no-op obsolete clear advanced candidate revision to %d", got)
	}
	lookup.ClearObsolete(big.NewInt(2))
	if got := lookup.Revision(); got != 2 {
		t.Fatalf("visible candidate removal revision = %d, want 2", got)
	}
}

func TestCanonicalKeyBlockValidationRejectsSibling(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	defer db.Close()

	parent := types.NewKeyBlock(&types.KeyBlockHeader{
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(1),
		Time:       1,
	})
	current := types.NewKeyBlock(&types.KeyBlockHeader{
		ParentHash: parent.Hash(),
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(2),
		Time:       2,
	})
	sibling := types.NewKeyBlock(&types.KeyBlockHeader{
		ParentHash: parent.Hash(),
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(2),
		Time:       3,
		T_Number:   9,
	})
	child := types.NewKeyBlock(&types.KeyBlockHeader{
		ParentHash: current.Hash(),
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(3),
		Time:       4,
	})
	rawdb.WriteKeyBlock(db, parent)
	rawdb.WriteKeyBlock(db, current)

	blockCache, err := lru.New(blockCacheLimit)
	if err != nil {
		t.Fatal(err)
	}
	kbc := &KeyBlockChain{db: db, blockCache: blockCache}
	kbc.currentBlock.Store(current)

	if err := kbc.ValidateKeyBlockForCanonicalInsert(sibling); !errors.Is(err, ErrNonCanonicalKeyBlock) {
		t.Fatalf("competing sibling was not rejected: %v", err)
	}
	if err := kbc.ValidateKeyBlockForCanonicalInsert(current); !errors.Is(err, ErrNonCanonicalKeyBlock) {
		t.Fatalf("duplicate current key block was not rejected: %v", err)
	}
	if err := kbc.ValidateKeyBlockForCanonicalInsert(child); err != nil {
		t.Fatalf("direct canonical child was rejected: %v", err)
	}

	bc := &BlockChain{chainConfig: &params.ChainConfig{FairHotstuff: true}, keyBlockChain: kbc}
	txBlock := types.NewBlockWithHeader(&types.Header{
		Number:     big.NewInt(10),
		Difficulty: big.NewInt(1),
		BlockType:  types.Key_Block,
		KeyHash:    sibling.ParentHash(),
	})
	txBlock.SetKeyblock(sibling)
	if err := bc.validateEmbeddedKeyBlockForCanonicalInsert(txBlock); !errors.Is(err, ErrNonCanonicalKeyBlock) {
		t.Fatalf("transaction-chain preflight accepted sibling key block: %v", err)
	}
}

func TestFHSCanonicalHeadStagesTransactionAndKeyHeadTogether(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	defer db.Close()

	keyGenesis := types.NewKeyBlock(&types.KeyBlockHeader{
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(0),
		Time:       1,
	})
	keyChild := types.NewKeyBlock(&types.KeyBlockHeader{
		ParentHash: keyGenesis.Hash(),
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(1),
		Time:       2,
	})
	rawdb.WriteKeyBlock(db, keyGenesis)
	rawdb.WriteKeyBlockHash(db, keyGenesis.Hash(), 0)
	rawdb.WriteHeadKeyBlockHash(db, keyGenesis.Hash())

	keyCache, err := lru.New(blockCacheLimit)
	if err != nil {
		t.Fatal(err)
	}
	kbc := &KeyBlockChain{db: db, blockCache: keyCache}
	kbc.currentBlock.Store(keyGenesis)

	txGenesis := types.NewBlockWithHeader(&types.Header{
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(0),
		BlockType:  types.FastTx_Block,
	})
	txKey := types.NewBlockWithHeader(&types.Header{
		ParentHash: txGenesis.Hash(),
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(1),
		BlockType:  types.Key_Block,
		KeyHash:    keyGenesis.Hash(),
	})
	txKey.SetKeyblock(keyChild)
	// Avoid exercising HeaderChain cache maintenance in this focused test;
	// writeHeadBlock must still atomically move both durable head markers.
	rawdb.WriteCanonicalHash(db, txKey.Hash(), txKey.NumberU64())

	bc := &BlockChain{
		chainConfig:   &params.ChainConfig{FairHotstuff: true},
		db:            db,
		keyBlockChain: kbc,
		validator:     &fhsCanonicalHeadTestValidator{},
	}
	bc.currentBlock.Store(txGenesis)
	proof, err := encodeFHSFinalityProof(&hotstuff.SignedState{
		State: []byte{1}, Sign: []byte{1}, Mask: []byte{1},
		ViewID: common.HexToHash("0x1"), LeaderID: "leader", Number: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := txKey.SetFHSFinalityProof(proof); err != nil {
		t.Fatal(err)
	}
	if err := bc.writeHeadBlock(txKey); err != nil {
		t.Fatalf("write canonical FHS head: %v", err)
	}
	if got := rawdb.ReadHeadBlockHash(db); got != txKey.Hash() {
		t.Fatalf("transaction head mismatch: have %s want %s", got, txKey.Hash())
	}
	if got := rawdb.ReadHeadKeyBlockHash(db); got != keyChild.Hash() {
		t.Fatalf("key head mismatch: have %s want %s", got, keyChild.Hash())
	}
	if got := kbc.CurrentBlock(); got.Hash() != keyChild.Hash() {
		t.Fatalf("in-memory key head mismatch: have %s want %s", got.Hash(), keyChild.Hash())
	}
}

func TestFHSStartupRejectsSiblingKeyHistory(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	defer db.Close()
	bftview.SetCommitteeConfig(db, nil, nil)

	keyGenesis := types.NewKeyBlock(&types.KeyBlockHeader{
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(0),
		Time:       1,
	})
	committee := &bftview.Committee{List: []*common.Cnode{{
		Address: "validator:1",
		Public:  "validator-public-key",
	}}}
	keyGenesis.SetCommitteeHash(committee.RlpHash())
	keyChild := types.NewKeyBlock(&types.KeyBlockHeader{
		ParentHash:    keyGenesis.Hash(),
		Difficulty:    big.NewInt(1),
		Number:        big.NewInt(1),
		Time:          2,
		CommitteeHash: committee.RlpHash(),
	})
	rawdb.WriteKeyBlock(db, keyGenesis)
	rawdb.WriteKeyBlock(db, keyChild)
	rawdb.WriteKeyBlockHash(db, keyGenesis.Hash(), 0)
	rawdb.WriteKeyBlockHash(db, keyChild.Hash(), 1)
	rawdb.WriteHeadKeyBlockHash(db, keyChild.Hash())
	if !bftview.WriteCommittee(0, keyGenesis.Hash(), committee) {
		t.Fatal("failed to store genesis committee")
	}
	if !bftview.WriteCommittee(1, keyChild.Hash(), committee) {
		t.Fatal("failed to store child committee")
	}

	keyBlockCache, _ := lru.New(blockCacheLimit)
	headerCache, _ := lru.New(headerCacheLimit)
	numberCache, _ := lru.New(headerCacheLimit)
	kbc := &KeyBlockChain{
		db:           db,
		genesisBlock: keyGenesis,
		blockCache:   keyBlockCache,
		khc: &KeyHeaderChain{
			chainDb:     db,
			headerCache: headerCache,
			numberCache: numberCache,
		},
	}
	kbc.currentBlock.Store(keyChild)

	txGenesis := types.NewBlockWithHeader(&types.Header{
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(0),
		BlockType:  types.FastTx_Block,
	})
	txChild := types.NewBlockWithHeader(&types.Header{
		ParentHash: txGenesis.Hash(),
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(1),
		BlockType:  types.Key_Block,
		KeyHash:    keyGenesis.Hash(),
	})
	txChild.SetKeyblock(keyChild)
	// The key carrier is certified by the old committee. Fast HotStuff may
	// already have certified a child with that same old key before the carrier
	// commits, so the canonical history must allow the old key to drain once.
	txOldKeyChild := types.NewBlockWithHeader(&types.Header{
		ParentHash: txChild.Hash(),
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(2),
		BlockType:  types.FastTx_Block,
		KeyHash:    keyGenesis.Hash(),
	})
	txActivatedChild := types.NewBlockWithHeader(&types.Header{
		ParentHash: txOldKeyChild.Hash(),
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(3),
		BlockType:  types.FastTx_Block,
		KeyHash:    keyChild.Hash(),
	})
	for _, block := range []*types.Block{txGenesis, txChild, txOldKeyChild, txActivatedChild} {
		rawdb.WriteBlock(db, block)
		rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
	}
	txBlockCache, _ := lru.New(blockCacheLimit)
	bc := &BlockChain{
		chainConfig:   &params.ChainConfig{FairHotstuff: true},
		db:            db,
		blockCache:    txBlockCache,
		keyBlockChain: kbc,
		genesisBlock:  txGenesis,
	}
	bc.currentBlock.Store(txChild)
	if err := bc.validateFHSCanonicalExtension(txOldKeyChild); err != nil {
		t.Fatalf("runtime validation rejected a pipelined child signed by the old committee: %v", err)
	}
	bc.currentBlock.Store(txOldKeyChild)
	txExpiredOldKeyChild := types.NewBlockWithHeader(&types.Header{
		ParentHash: txOldKeyChild.Hash(),
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(3),
		BlockType:  types.FastTx_Block,
		KeyHash:    keyGenesis.Hash(),
	})
	if err := bc.validateFHSCanonicalExtension(txExpiredOldKeyChild); err == nil {
		t.Fatal("runtime validation accepted an old signing key beyond the two-chain drain window")
	}
	if err := bc.validateFHSCanonicalExtension(txActivatedChild); err != nil {
		t.Fatalf("runtime validation rejected activation of the latest committee: %v", err)
	}
	bc.currentBlock.Store(txActivatedChild)
	if err := bc.validateFHSCanonicalKeyHistory(); err != nil {
		t.Fatalf("valid canonical key history was rejected: %v", err)
	}
	if err := bc.reconcileFHSCanonicalKeyState(txGenesis); err != nil {
		t.Fatalf("rewind canonical key state to genesis: %v", err)
	}
	if got := kbc.CurrentBlock(); got.Hash() != keyGenesis.Hash() {
		t.Fatalf("rewound in-memory key head mismatch: have %s want %s", got.Hash(), keyGenesis.Hash())
	}
	if got := rawdb.ReadKeyBlockHash(db, keyChild.NumberU64()); got != (common.Hash{}) {
		t.Fatalf("rewind retained a canonical child mapping: %s", got)
	}
	if got := rawdb.ReadKeyBlock(db, keyChild.Hash(), keyChild.NumberU64()); got == nil {
		t.Fatal("rewind deleted historical key block data needed for QC verification")
	}
	if err := bc.reconcileFHSCanonicalKeyState(txActivatedChild); err != nil {
		t.Fatalf("restore canonical key state from transaction ancestry: %v", err)
	}
	if got := kbc.CurrentBlock(); got.Hash() != keyChild.Hash() {
		t.Fatalf("restored in-memory key head mismatch: have %s want %s", got.Hash(), keyChild.Hash())
	}
	if got := rawdb.ReadKeyBlockHash(db, keyChild.NumberU64()); got != keyChild.Hash() {
		t.Fatalf("restored canonical child mapping mismatch: have %s want %s", got, keyChild.Hash())
	}

	txRollback := types.NewBlockWithHeader(&types.Header{
		ParentHash: txActivatedChild.Hash(),
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(4),
		BlockType:  types.FastTx_Block,
		KeyHash:    keyGenesis.Hash(),
	})
	if err := bc.validateFHSCanonicalExtension(txRollback); err == nil {
		t.Fatal("runtime validation accepted a rollback to the old signing key")
	}

	keySibling := types.NewKeyBlock(&types.KeyBlockHeader{
		ParentHash:    keyGenesis.Hash(),
		Difficulty:    big.NewInt(1),
		Number:        big.NewInt(1),
		Time:          3,
		CommitteeHash: committee.RlpHash(),
		T_Number:      4,
	})
	txSibling := types.NewBlockWithHeader(&types.Header{
		ParentHash: txActivatedChild.Hash(),
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(5),
		BlockType:  types.Key_Block,
		KeyHash:    keyChild.Hash(),
	})
	txSibling.SetKeyblock(keySibling)
	rawdb.WriteBlock(db, txSibling)
	rawdb.WriteCanonicalHash(db, txSibling.Hash(), txSibling.NumberU64())
	bc.currentBlock.Store(txSibling)
	if err := bc.validateFHSCanonicalKeyHistory(); err == nil {
		t.Fatal("startup validation accepted same-height sibling key blocks")
	}
}
