package eth

import (
	"net"
	"strconv"
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

func committeeAddressHostPort(address string) (string, int, bool) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil || host == "" || portText == "" {
		return "", 0, false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 {
		return "", 0, false
	}
	return host, port, true
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
	nodeTCP := node.TCP()
	if nodeTCP <= 0 {
		return false
	}
	for _, member := range chainConfig.GenCommittee {
		host, port, ok := committeeAddressHostPort(member.Address)
		if !ok {
			continue
		}
		if sameHost(nodeHost, host) && nodeTCP == port {
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
