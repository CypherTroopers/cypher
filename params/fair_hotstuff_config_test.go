package params

import (
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
)

func testFairHotstuffConfig() *ChainConfig {
	publicKeys := []string{
		"3912d236e16d97b70244a6c3f0693c8ff855bca8771b521bb3af948f0c682a15a8ca1a90265f7db37dacd2621e389c1cc8526eca9efd31a66e6ce6debdb1560b",
		"e79f42fc639c2bb3fb489641d4643aed30f3095948283362a11f35074175081632e251cad8e718bbbfa22ce58720968a092ae9d326df681ccc9efb1828ab380a",
		"c5248a6fdfe58a4b442293c84dcb2d08d2d6c6cdaf2cd42732723ca238b0c2198f9e047170bef68af6b690327b6bbab8af258eba20db0679ddc897f0ea108388",
		"e1f5313fea570fbef1013335a91afc186a35aca491a08bcaedc3566c18beac1f969ee7303de787b2861c5bc4a874b2887bd027f2562b9807bac7c171098a308b",
		"48a16b06d3771797644cce84d1bb0bfba9525ff6b19fab48cb29f7b108a8971a35630a7c0355fe69f95263faaf48a4ed515028b20e7bc6b306448cddeb3ea61e",
		"0ea28b3fad0c3ef992e8d51fa2e0b158c0ba1101629e4516f999f66c672222257d3d4b0e20024fdcc1d09100c2d040c006cd32dbb7ccb416c7dc5a03af9c8d02",
		"bbf99348f4f81b296d0fceeb3d7f1b25ad4d3f50eb44baffa80a290d1a56a0177394455ce8d8a69452b453e5de5568df58f68077d57e7ff54df0aa4ade7d0e14",
	}
	committee := make(GenesisCommittee, 7)
	for index := 0; index < 7; index++ {
		committee[index] = common.Cnode{
			Address:  fmt.Sprintf("127.0.0.1:%d", 7100+index),
			CoinBase: fmt.Sprintf("%040x", index+1),
			Public:   publicKeys[index],
		}
	}
	return &ChainConfig{
		ChainID:             bigInt(10101919),
		FairHotstuff:        true,
		FairHotstuffSeed:    common.HexToHash("0xacb7b49e23815caf94dc47bcf81dab93cc986cf9ab04e243efcbc204c6a2a627"),
		GenCommittee:        committee,
		HomesteadBlock:      bigInt(0),
		EIP150Block:         bigInt(0),
		EIP155Block:         bigInt(0),
		EIP158Block:         bigInt(0),
		ByzantiumBlock:      bigInt(0),
		ConstantinopleBlock: bigInt(0),
		PetersburgBlock:     bigInt(0),
		IstanbulBlock:       bigInt(0),
	}
}

func bigInt(value int64) *big.Int { return big.NewInt(value) }

func TestFairHotstuffConfigRequiresSeedAndThreeFPlusOne(t *testing.T) {
	config := testFairHotstuffConfig()
	if err := config.CheckConfigForkOrder(); err != nil {
		t.Fatal(err)
	}
	config.FairHotstuffSeed = common.Hash{}
	if err := config.CheckConfigForkOrder(); err == nil {
		t.Fatal("zero Fair HotStuff seed accepted")
	}
	config = testFairHotstuffConfig()
	delete(config.GenCommittee, 6)
	if err := config.CheckConfigForkOrder(); err == nil {
		t.Fatal("six-node Fair HotStuff committee accepted")
	}
	config = testFairHotstuffConfig()
	config.GenCommittee = make(GenesisCommittee, MaxFairHotstuffCommitteeSize+3)
	if err := config.CheckConfigForkOrder(); err == nil {
		t.Fatal("oversized Fair HotStuff committee accepted")
	}
}

func TestFairHotstuffConfigRejectsInvalidChainAndCommitteeKeys(t *testing.T) {
	config := testFairHotstuffConfig()
	config.ChainID = big.NewInt(0)
	if err := config.CheckConfigForkOrder(); err == nil {
		t.Fatal("zero Fair HotStuff chain ID accepted")
	}

	for _, public := range []string{"not-hex", "01", fmt.Sprintf("%0128x", 0)} {
		config = testFairHotstuffConfig()
		node := config.GenCommittee[0]
		node.Public = public
		config.GenCommittee[0] = node
		if err := config.CheckConfigForkOrder(); err == nil {
			t.Fatalf("invalid Fair HotStuff public key %q accepted", public)
		}
	}
}

func TestFairHotstuffConfigForbidsTransportDowngrade(t *testing.T) {
	config := testFairHotstuffConfig()
	if fallback := config.EffectiveRnetFallbackTransport(); fallback != "none" {
		t.Fatalf("default Fair HotStuff fallback = %q, want none", fallback)
	}
	config.RnetFallbackTransport = "tcp"
	if err := config.CheckConfigForkOrder(); err == nil {
		t.Fatal("Fair HotStuff accepted unauthenticated TCP fallback")
	}
	config = testFairHotstuffConfig()
	config.RnetTransport = "tcp"
	if err := config.CheckConfigForkOrder(); err == nil {
		t.Fatal("Fair HotStuff accepted unauthenticated TCP transport")
	}
}

func TestFairHotstuffSeedJSONRoundTrip(t *testing.T) {
	config := testFairHotstuffConfig()
	config.RnetTransport = "quic"
	config.RnetFallbackTransport = "none"
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ChainConfig
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.FairHotstuffSeed != config.FairHotstuffSeed {
		t.Fatalf("seed round trip = %s, want %s", decoded.FairHotstuffSeed, config.FairHotstuffSeed)
	}
	if decoded.RnetTransport != config.RnetTransport || decoded.RnetFallbackTransport != config.RnetFallbackTransport {
		t.Fatalf("transport policy did not survive JSON round trip: %#v", decoded)
	}
}

func TestFairHotstuffGenesisCommitmentBindsConsensusConfiguration(t *testing.T) {
	base := testFairHotstuffConfig()
	want, err := FairHotstuffGenesisCommitment(base)
	if err != nil {
		t.Fatal(err)
	}
	explicitDefaults := *base
	explicitDefaults.RnetTransport = "quic"
	explicitDefaults.RnetFallbackTransport = "none"
	if got, err := FairHotstuffGenesisCommitment(&explicitDefaults); err != nil || got != want {
		t.Fatalf("semantic transport defaults are not canonical: got %s err %v want %s", got, err, want)
	}
	mutations := []*ChainConfig{}
	chainChanged := *base
	chainChanged.ChainID = big.NewInt(base.ChainID.Int64() + 1)
	mutations = append(mutations, &chainChanged)
	committeeChanged := *base
	committeeChanged.GenCommittee = make(GenesisCommittee, len(base.GenCommittee))
	for index, node := range base.GenCommittee {
		committeeChanged.GenCommittee[index] = node
	}
	node := committeeChanged.GenCommittee[0]
	node.Address = "127.0.0.1:9999"
	committeeChanged.GenCommittee[0] = node
	mutations = append(mutations, &committeeChanged)
	transportChanged := *base
	transportChanged.RnetFallbackTransport = "tcp"
	mutations = append(mutations, &transportChanged)
	for index, mutation := range mutations {
		got, err := FairHotstuffGenesisCommitment(mutation)
		if err != nil {
			t.Fatalf("mutation %d: %v", index, err)
		}
		if got == want {
			t.Fatalf("mutation %d did not change the genesis config commitment", index)
		}
	}
}
