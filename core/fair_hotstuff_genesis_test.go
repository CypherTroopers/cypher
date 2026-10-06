package core

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/params"
)

func testFairHotstuffGenesis() *Genesis {
	seed := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	publicKeys := []string{
		"3912d236e16d97b70244a6c3f0693c8ff855bca8771b521bb3af948f0c682a15a8ca1a90265f7db37dacd2621e389c1cc8526eca9efd31a66e6ce6debdb1560b",
		"e79f42fc639c2bb3fb489641d4643aed30f3095948283362a11f35074175081632e251cad8e718bbbfa22ce58720968a092ae9d326df681ccc9efb1828ab380a",
		"c5248a6fdfe58a4b442293c84dcb2d08d2d6c6cdaf2cd42732723ca238b0c2198f9e047170bef68af6b690327b6bbab8af258eba20db0679ddc897f0ea108388",
		"e1f5313fea570fbef1013335a91afc186a35aca491a08bcaedc3566c18beac1f969ee7303de787b2861c5bc4a874b2887bd027f2562b9807bac7c171098a308b",
	}
	committee := make(params.GenesisCommittee, 4)
	for index := 0; index < 4; index++ {
		committee[index] = common.Cnode{
			Address:  fmt.Sprintf("127.0.0.1:%d", 7100+index),
			CoinBase: fmt.Sprintf("%040x", index+1),
			Public:   publicKeys[index],
		}
	}
	config := &params.ChainConfig{
		ChainID:              big.NewInt(10101919),
		FairHotstuff:         true,
		FairHotstuffSeed:     seed,
		GenCommittee:         committee,
		TransactionSizeLimit: DefaultTxPoolConfig.TransactionSizeLimit,
	}
	commitment, err := params.FairHotstuffGenesisCommitment(config)
	if err != nil {
		panic(err)
	}
	return &Genesis{
		Config:     config,
		GasLimit:   params.GenesisGasLimit,
		Difficulty: big.NewInt(1),
		Mixhash:    commitment,
		Alloc:      GenesisAlloc{},
	}
}

func TestSetupGenesisRejectsFairHotstuffSeedReplacement(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := testFairHotstuffGenesis()
	_, stored, err := SetupGenesisBlock(db, genesis)
	if err != nil {
		t.Fatal(err)
	}

	replacement := *genesis
	replacementConfig := *genesis.Config
	replacementConfig.FairHotstuffSeed = common.HexToHash("0xabcdef")
	replacement.Config = &replacementConfig
	// The full config is committed to the header, so either the genesis hash or
	// the stored commitment guard must reject this replacement.
	if _, _, err := SetupGenesisBlock(db, &replacement); err == nil {
		t.Fatal("genesis-committed Fair HotStuff seed was replaceable in an existing DB")
	}

	storedConfig := rawdb.ReadChainConfig(db, stored)
	storedConfig.FairHotstuffSeed = common.HexToHash("0xdeadbeef")
	rawdb.WriteChainConfig(db, stored, storedConfig)
	if _, _, err := SetupGenesisBlock(db, nil); err == nil {
		t.Fatal("stored Fair HotStuff config inconsistent with genesis mixHash was accepted")
	}
}

func TestSetupGenesisRejectsFairHotstuffCommitteeReplacement(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := testFairHotstuffGenesis()
	_, stored, err := SetupGenesisBlock(db, genesis)
	if err != nil {
		t.Fatal(err)
	}
	storedConfig := rawdb.ReadChainConfig(db, stored)
	node := storedConfig.GenCommittee[0]
	node.Address = "127.0.0.1:9999"
	storedConfig.GenCommittee[0] = node
	rawdb.WriteChainConfig(db, stored, storedConfig)
	if _, _, err := SetupGenesisBlock(db, nil); err == nil {
		t.Fatal("stored Fair HotStuff committee inconsistent with genesis commitment was accepted")
	}
}

func TestSetupGenesisRejectsFairHotstuffActivationChange(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := testFairHotstuffGenesis()
	if _, _, err := SetupGenesisBlock(db, genesis); err != nil {
		t.Fatal(err)
	}
	replacement := *genesis
	replacementConfig := *genesis.Config
	replacementConfig.FairHotstuff = false
	replacementConfig.FairHotstuffSeed = common.Hash{}
	replacement.Config = &replacementConfig
	if _, _, err := SetupGenesisBlock(db, &replacement); err == nil {
		t.Fatal("Fair HotStuff activation was changeable after genesis")
	}
}

func TestSetupGenesisRejectsMissingStoredFairHotstuffConfig(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := testFairHotstuffGenesis()
	_, stored, err := SetupGenesisBlock(db, genesis)
	if err != nil {
		t.Fatal(err)
	}

	// ChainConfig is consensus-critical but stored separately from the header.
	// A damaged DB must not silently fall back to a default configuration.
	key := append([]byte("ethereum-config-"), stored.Bytes()...)
	if err := db.Delete(key); err != nil {
		t.Fatal(err)
	}
	if _, _, err := SetupGenesisBlock(db, nil); err == nil {
		t.Fatal("missing stored Fair HotStuff chain config was accepted")
	}
}
