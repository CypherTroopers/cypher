package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
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

func slotGenesis(t *testing.T) *Genesis {
	t.Helper()
	genesis := testFairHotstuffGenesis()
	genesis.Config.FairHotstuffSlotMillis = params.FairHotstuffSlotDurationMillis
	header := new(types.Header)
	header.SetFHSSlot(1_700_000_000 * params.FairHotstuffSlotsPerSecond)
	genesis.Timestamp, genesis.ExtraData = header.Time, string(header.Extra)
	commitment, err := params.FairHotstuffGenesisCommitment(genesis.Config)
	if err != nil {
		t.Fatal(err)
	}
	genesis.Mixhash = commitment
	return genesis
}

func TestSetupGenesisFairHotstuffSlotRoundTrip(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := slotGenesis(t)
	// This slot includes non-UTF-8 bytes. Its public genesis representation must
	// use hex and retain the exact envelope before deriving the genesis hash.
	encoded, err := json.Marshal(genesis)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"extraData":"0x46485301`)) {
		t.Fatal("slot genesis did not encode its binary Extra as hex")
	}
	var decoded Genesis
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { decoded.Config.SetModernForkConfig(nil) })
	if decoded.ExtraData != genesis.ExtraData || decoded.ToBlock(nil).Hash() != genesis.ToBlock(nil).Hash() {
		t.Fatal("slot genesis JSON changed its exact envelope or hash")
	}
	genesis = &decoded
	_, hash, err := SetupGenesisBlock(db, genesis)
	if err != nil {
		t.Fatal(err)
	}
	stored := rawdb.ReadHeader(db, hash, 0)
	slot, err := stored.FHSSlot()
	if err != nil || slot != genesis.Timestamp*params.FairHotstuffSlotsPerSecond {
		t.Fatalf("stored genesis slot=%d, error=%v", slot, err)
	}
	config, reopened, err := SetupGenesisBlock(db, nil)
	if err != nil || reopened != hash || !config.FairHotstuffSlotEnabled() {
		t.Fatalf("reopened genesis hash=%s, config=%v, error=%v", reopened, config, err)
	}
	// The stored header commits the slot mode even at height zero. Neither
	// removing it nor changing the interval is a data-directory migration.
	for _, millis := range []uint64{0, 500} {
		config := rawdb.ReadChainConfig(db, hash)
		config.FairHotstuffSlotMillis = millis
		rawdb.WriteChainConfig(db, hash, config)
		if _, _, err := SetupGenesisBlock(db, nil); err == nil {
			t.Fatalf("stored slot interval was replaceable with %d", millis)
		}
	}
}

func TestSetupGenesisFairHotstuffSlotRejectsInvalidEnvelope(t *testing.T) {
	for _, name := range []string{"missing", "wrong-prefix", "trailing", "timestamp-mismatch", "fractional-genesis"} {
		t.Run(name, func(t *testing.T) {
			genesis := slotGenesis(t)
			switch name {
			case "missing":
				genesis.ExtraData = ""
			case "wrong-prefix":
				extra := []byte(genesis.ExtraData)
				extra[0] ^= 1
				genesis.ExtraData = string(extra)
			case "trailing":
				genesis.ExtraData += "x"
			case "timestamp-mismatch":
				genesis.Timestamp++
			case "fractional-genesis":
				header := new(types.Header)
				header.SetFHSSlot(genesis.Timestamp*params.FairHotstuffSlotsPerSecond + 1)
				genesis.ExtraData = string(header.Extra)
			}
			db := rawdb.NewMemoryDatabase()
			if _, err := genesis.Commit(db); err == nil {
				t.Fatal("invalid slot genesis was committed")
			}
			if rawdb.ReadCanonicalHash(db, 0) != (common.Hash{}) {
				t.Fatal("invalid slot genesis wrote a canonical block")
			}
		})
	}
	// Other profiles retain arbitrary genesis Extra and their original hash.
	legacy := testFairHotstuffGenesis()
	legacy.ExtraData = "legacy genesis extra"
	if _, err := legacy.Commit(rawdb.NewMemoryDatabase()); err != nil {
		t.Fatalf("legacy genesis Extra rejected: %v", err)
	}
	encoded, err := json.Marshal(legacy)
	if err != nil || !bytes.Contains(encoded, []byte(`"extraData":"legacy genesis extra"`)) {
		t.Fatalf("legacy genesis JSON string convention changed: %s, error=%v", encoded, err)
	}
	var decoded Genesis
	if err := json.Unmarshal(encoded, &decoded); err != nil || decoded.ExtraData != legacy.ExtraData {
		t.Fatalf("legacy genesis Extra round trip changed: %q, error=%v", decoded.ExtraData, err)
	}
	t.Cleanup(func() { decoded.Config.SetModernForkConfig(nil) })
}

func distributedFairHotstuffGenesis(t *testing.T) ([]byte, *Genesis) {
	t.Helper()
	encoded, err := os.ReadFile("../genesis.json")
	if err != nil {
		t.Fatal(err)
	}
	var genesis Genesis
	if err := json.Unmarshal(encoded, &genesis); err != nil {
		t.Fatal(err)
	}
	if genesis.Config == nil {
		t.Fatal("distributed genesis has no config")
	}
	t.Cleanup(func() { genesis.Config.SetModernForkConfig(nil) })
	return encoded, &genesis
}

func TestDistributedFairHotstuffGenesisActivation(t *testing.T) {
	_, genesis := distributedFairHotstuffGenesis(t)
	config := genesis.Config
	if err := config.CheckConfigForkOrder(); err != nil {
		t.Fatalf("distributed genesis config: %v", err)
	}
	if err := config.IsValid(); err != nil {
		t.Fatalf("distributed genesis transaction/code limits: %v", err)
	}
	if !config.FairHotstuffSlotEnabled() || !config.FixedCommittee {
		t.Fatalf("distributed genesis must enable the fixed-committee 250ms clock: slotMillis=%d, fixedCommittee=%t", config.FairHotstuffSlotMillis, config.FixedCommittee)
	}
	profile := params.FHS250msResearchEVMParallelConfig()
	if config.NativeParallel == nil || *config.NativeParallel != *profile {
		t.Fatalf("distributed genesis evmParallel=%+v, want %+v", config.NativeParallel, profile)
	}
	commitment, err := params.FairHotstuffGenesisCommitment(config)
	if err != nil {
		t.Fatal(err)
	}
	if genesis.Mixhash != commitment {
		t.Fatalf("distributed genesis mixHash=%s, want %s", genesis.Mixhash, commitment)
	}
	header := genesis.ToBlock(nil).Header()
	slot, err := header.FHSSlot()
	if err != nil || slot != genesis.Timestamp*params.FairHotstuffSlotsPerSecond || header.Time != genesis.Timestamp {
		t.Fatalf("distributed genesis slot=%d, timestamp=%d, want Unix second %d, error=%v", slot, header.Time, genesis.Timestamp, err)
	}
	encoded, err := json.Marshal(genesis)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"extraData":"0x46485301`)) {
		t.Fatal("distributed slot genesis must retain the canonical hex envelope")
	}
}

func TestDistributedFairHotstuffGenesisNetworkPins(t *testing.T) {
	_, genesis := distributedFairHotstuffGenesis(t)
	if genesis.Config.ChainID == nil {
		t.Fatal("distributed genesis has no chain ID")
	}
	hash := genesis.ToBlock(nil).Hash()
	for _, path := range []string{
		"../config/browser-relay/common-mine.json",
		"../config/lightnode/public.json",
		"../browser-llm-lab/relay/config.json",
	} {
		t.Run(path, func(t *testing.T) {
			encoded, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var config struct {
				Network struct {
					ChainID     uint64      `json:"chainId"`
					GenesisHash common.Hash `json:"genesisHash"`
				} `json:"network"`
			}
			if err := json.Unmarshal(encoded, &config); err != nil {
				t.Fatal(err)
			}
			if config.Network.ChainID != genesis.Config.ChainID.Uint64() || config.Network.GenesisHash != hash {
				t.Fatalf("network pin chainId=%d, genesisHash=%s, want chainId=%s, genesisHash=%s", config.Network.ChainID, config.Network.GenesisHash, genesis.Config.ChainID, hash)
			}
		})
	}
}

func TestSetupDistributedFairHotstuffGenesis(t *testing.T) {
	encoded, genesis := distributedFairHotstuffGenesis(t)
	// The CLI decodes the same file into both genesis types and initializes
	// their separate headers and configurations in one database, key first.
	var keyGenesis GenesisKey
	if err := json.Unmarshal(encoded, &keyGenesis); err != nil {
		t.Fatal(err)
	}
	if keyGenesis.Config == nil {
		t.Fatal("distributed key genesis has no config")
	}
	t.Cleanup(func() { keyGenesis.Config.SetModernForkConfig(nil) })
	wantConfig, err := json.Marshal(genesis.Config)
	if err != nil {
		t.Fatal(err)
	}
	checkConfig := func(config *params.ChainConfig) {
		t.Helper()
		if config == nil {
			t.Fatal("missing stored genesis config")
		}
		t.Cleanup(func() { config.SetModernForkConfig(nil) })
		got, err := json.Marshal(config)
		if err != nil || !bytes.Equal(got, wantConfig) {
			t.Fatalf("genesis config readback changed: have %s, want %s, error=%v", got, wantConfig, err)
		}
	}
	checkConfig(keyGenesis.Config)
	db := rawdb.NewMemoryDatabase()
	t.Cleanup(func() {
		bftview.SetCommitteeConfig(nil, nil, nil)
		db.Close()
	})
	keyConfig, keyHash, err := SetupGenesisKeyBlock(db, &keyGenesis)
	if err != nil {
		t.Fatal(err)
	}
	checkConfig(keyConfig)
	config, hash, err := SetupGenesisBlock(db, genesis)
	if err != nil {
		t.Fatal(err)
	}
	checkConfig(config)
	checkConfig(rawdb.ReadChainConfig(db, keyHash))
	checkConfig(rawdb.ReadChainConfig(db, hash))
	keyHeader := rawdb.ReadKeyHeader(db, keyHash, 0)
	header := rawdb.ReadHeader(db, hash, 0)
	if keyHeader == nil || header == nil {
		t.Fatal("missing stored key or transaction genesis header")
	}
	if keyHeader.Hash() != keyHash || header.Hash() != hash {
		t.Fatal("stored genesis header hashes changed")
	}
	if keyHeader.Time != genesis.Timestamp || keyHeader.MixDigest != genesis.Mixhash {
		t.Fatal("key genesis changed the shared Unix-second timestamp or commitment")
	}
	if header.Time != genesis.Timestamp || !bytes.Equal(header.Extra, []byte(genesis.ExtraData)) || header.MixDigest != genesis.Mixhash || hash != genesis.ToBlock(nil).Hash() {
		t.Fatal("stored transaction genesis changed its timestamp, envelope, commitment or hash")
	}
	if rawdb.ReadKeyBlockHash(db, 0) != keyHash || rawdb.ReadHeadKeyHeaderHash(db) != keyHash || rawdb.ReadHeadKeyBlockHash(db) != keyHash || rawdb.ReadCanonicalHash(db, 0) != hash || rawdb.ReadHeadHeaderHash(db) != hash || rawdb.ReadHeadBlockHash(db) != hash {
		t.Fatal("shared database did not retain both canonical genesis heads")
	}
	// Exercise both the normal stored-config reopen path and repeated CLI init.
	for _, supplied := range []bool{false, true} {
		var txInput *Genesis
		var keyInput *GenesisKey
		if supplied {
			txInput, keyInput = genesis, &keyGenesis
		}
		keyConfig, reopenedKey, err := SetupGenesisKeyBlock(db, keyInput)
		if err != nil || reopenedKey != keyHash {
			t.Fatalf("reopen key genesis supplied=%t: hash=%s, error=%v", supplied, reopenedKey, err)
		}
		checkConfig(keyConfig)
		config, reopened, err := SetupGenesisBlock(db, txInput)
		if err != nil || reopened != hash {
			t.Fatalf("reopen transaction genesis supplied=%t: hash=%s, error=%v", supplied, reopened, err)
		}
		checkConfig(config)
	}
}

func TestSetupDistributedFairHotstuffGenesisRejectsCapacityChange(t *testing.T) {
	_, genesis := distributedFairHotstuffGenesis(t)
	if genesis.Config.NativeParallel == nil {
		t.Fatal("distributed genesis has no capacity profile")
	}
	db := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { db.Close() })
	_, hash, err := SetupGenesisBlock(db, genesis)
	if err != nil {
		t.Fatal(err)
	}
	genesis.Config.NativeParallel.MaxTransactionsPerBlock--
	if err := genesis.Config.CheckConfigForkOrder(); err != nil {
		t.Fatalf("capacity mutation must remain valid before testing its commitment: %v", err)
	}
	fresh := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { fresh.Close() })
	if _, _, err := SetupGenesisBlock(fresh, genesis); err == nil {
		t.Fatal("changed capacity with a stale genesis commitment was accepted")
	}
	if rawdb.ReadCanonicalHash(fresh, 0) != (common.Hash{}) {
		t.Fatal("stale genesis commitment wrote a canonical block")
	}
	genesis.Mixhash, err = params.FairHotstuffGenesisCommitment(genesis.Config)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := SetupGenesisBlock(db, genesis); err == nil {
		t.Fatal("changed capacity with a new commitment replaced an initialized genesis")
	}
	stored := rawdb.ReadChainConfig(db, hash)
	if stored == nil {
		t.Fatal("rejected replacement lost the original genesis config")
	}
	t.Cleanup(func() { stored.SetModernForkConfig(nil) })
	if stored.NativeParallel == nil || *stored.NativeParallel != *params.FHS250msResearchEVMParallelConfig() {
		t.Fatal("rejected replacement changed the stored capacity profile")
	}
}
