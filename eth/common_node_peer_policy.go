package eth

import (
	"net"
	"strings"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/p2p/enode"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
)

func commonNodeRole(chainConfig *params.ChainConfig, configuredCoinbase common.Address) bool {
	if chainConfig == nil || !(chainConfig.FixedCommittee || chainConfig.FixedLeader) || len(chainConfig.GenCommittee) == 0 {
		return false
	}
	coinbase := bftview.GetServerCoinBase()
	if coinbase == (common.Address{}) {
		coinbase = configuredCoinbase
	}
	if coinbase == (common.Address{}) {
		return false
	}
	return bftview.IamMember() < 0
}

func committeeAddressHost(address string) (string, bool) {
	// GenCommittee.Address stores the rnet/KCP endpoint. Its port is the rnet UDP
	// port, not the eth/p2p TCP port. The eth/p2p fallback peer policy can only
	// use the host safely until validator identity based matching is added.
	host, _, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil || host == "" {
		return "", false
	}
	return host, true
}

func sameHost(a string, b string) bool {
	if a == "" || b == "" {
		return false
	}
	ipA := net.ParseIP(a)
	ipB := net.ParseIP(b)
	if ipA != nil && ipB != nil {
		return ipA.Equal(ipB)
	}
	return strings.EqualFold(a, b)
}

func fixedCommitteePeerAllowed(chainConfig *params.ChainConfig, node *enode.Node) bool {
	if chainConfig == nil || node == nil {
		return false
	}
	ip := node.IP()
	if ip == nil {
		return false
	}
	nodeHost := ip.String()
	for _, member := range chainConfig.GenCommittee {
		host, ok := committeeAddressHost(member.Address)
		if !ok {
			continue
		}
		if sameHost(nodeHost, host) {
			return true
		}
	}
	return false
}

func (eth *Ethereum) commonNodePeerAllowed(node *enode.Node) bool {
	if eth == nil || eth.config == nil {
		return true
	}
	chainConfig := eth.blockchain.Config()
	if !commonNodeRole(chainConfig, eth.config.Miner.Etherbase) {
		return true
	}
	return fixedCommitteePeerAllowed(chainConfig, node)
}
