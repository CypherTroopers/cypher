package replication

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/rewards"
	"github.com/cypherium/cypher/dex/transport"
	"github.com/cypherium/cypher/reconfig/bftview"
)

func TestContinuousDutiesAreFiniteAndDistinctFromLegacyList(t *testing.T) {
	members, peers, recipients := make([]*common.Cnode, 7), make([]transport.Peer, 7), make([][20]byte, 7)
	var keys [7]bls.SecretKey
	for i := range keys {
		if err := keys[i].SetDecString(fmt.Sprint(i + 740)); err != nil {
			t.Fatal(err)
		}
		recipients[i][19] = byte(i + 1)
		members[i] = &common.Cnode{Address: fmt.Sprintf("replication-unit-%d", i), Public: keys[i].GetPublicKey().SerializeToHexStr(), CoinBase: common.Address(recipients[i]).Hex()}
		peers[i] = transport.Peer{ID: members[i].Address, BLSPublic: members[i].Public, RewardRecipient: recipients[i]}
	}
	domain := protocol.Domain{Version: 1, ChainID: 91, Genesis: protocol.Hash{1}, DEXID: protocol.Hash{2}, Epoch: 1, Committee: protocol.Hash((&bftview.Committee{List: members}).RlpHash())}
	registry, err := rewards.NewRegistry(domain, members, recipients)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := rewards.OpenCollector(filepath.Join(t.TempDir(), "collector"), registry, 0, &keys[0])
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Shutdown()
	cfg := Config{Index: 0, Peers: peers, Registry: registry, Collector: collector, Continuous: true, MaxHeight: consensus.MaxOperatingHeight}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, height := range []uint64{1, 64, 128, 129, 256, 320, consensus.MaxOperatingHeight} {
		if !c.eligible(height) {
			t.Fatal("continuous duty absent", height)
		}
	}
	if c.eligible(0) || c.eligible(consensus.MaxOperatingHeight+1) {
		t.Fatal("unbounded duty policy")
	}
	cfg.Heights = []uint64{1}
	if _, err := New(cfg); err == nil {
		t.Fatal("mixed receipt policy accepted")
	}
	cfg.Continuous = false
	legacy, err := New(cfg)
	if err != nil || !legacy.eligible(1) || legacy.eligible(129) {
		t.Fatal("legacy fixture reinterpreted", err)
	}
	cfg.Continuous = true
	cfg.Heights = nil
	cfg.MaxHeight = consensus.MaxOperatingHeight + 1
	if _, err := New(cfg); err == nil {
		t.Fatal("unbounded continuous lifetime")
	}
}
