package main

import (
	"github.com/cypherium/cypher/eth"
	"testing"
)

func TestCommonRelayOperatorExamplesDecode(t *testing.T) {
	for _, role := range []string{"common", "gateway", "committee"} {
		t.Run(role, func(t *testing.T) {
			cfg := gethConfig{Eth: eth.DefaultConfig, Node: defaultNodeConfig()}
			if err := loadConfig("../../docs/common-relay/examples/"+role+".toml", &cfg); err != nil {
				t.Fatal(err)
			}
			if !cfg.Node.P2P.ReservedPeerMode || cfg.Node.P2P.MaxPeers != len(cfg.Node.P2P.ReservedNodes)+cfg.Node.P2P.MaxPublicPeers {
				t.Fatal("reservation budget lost")
			}
			if role != "committee" && (!cfg.Eth.Relay.Enabled || cfg.Eth.Relay.Timeout.Seconds() != 15) {
				t.Fatal("relay config not decoded")
			}
			if (role == "gateway") != cfg.Eth.Relay.Gateway {
				t.Fatal("gateway opt-in lost")
			}
			if !cfg.Eth.TxQUIC.AutoRole {
				t.Fatal("verified miner identity auto-role selection disabled")
			}
			if cfg.Eth.TxQUIC.CommitteePublicKey != "" {
				t.Fatal("example still requires a separate committee identity hint")
			}
		})
	}
}
