package eth

import (
	"github.com/cypherium/cypher/common"
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
