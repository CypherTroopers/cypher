package bftview

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

type identityMembershipTestChain struct {
	block     *types.KeyBlock
	committee []*common.Cnode
}

func (chain *identityMembershipTestChain) CurrentBlock() *types.KeyBlock { return chain.block }

func (chain *identityMembershipTestChain) CurrentBlockN() uint64 {
	return chain.block.NumberU64()
}

func (chain *identityMembershipTestChain) GetBlockByHash(hash common.Hash) *types.KeyBlock {
	if chain.block.Hash() == hash {
		return chain.block
	}
	return nil
}

func (chain *identityMembershipTestChain) CurrentCommittee() []*common.Cnode {
	return chain.committee
}

func TestIamMemberCacheTracksServerPublicKey(t *testing.T) {
	chain := &identityMembershipTestChain{
		block: types.NewKeyBlock(&types.KeyBlockHeader{
			Number:     big.NewInt(7),
			Difficulty: big.NewInt(1),
		}),
		committee: []*common.Cnode{
			{Address: "192.0.2.1:7102", Public: "validator-a"},
			{Address: "192.0.2.2:7102", Public: "validator-b"},
		},
	}
	SetCommitteeConfig(nil, chain, nil)
	t.Cleanup(func() {
		SetServerInfo("", "")
		SetCommitteeConfig(nil, nil, nil)
	})

	SetServerInfo(chain.committee[0].Address, chain.committee[0].Public)
	if index := IamMember(); index != 0 {
		t.Fatalf("first validator membership = %d, want 0", index)
	}
	SetServerInfo("192.0.2.100:8998", "common-miner")
	if index := IamMember(); index != -1 {
		t.Fatalf("same-height common-miner membership reused cache index %d", index)
	}
	SetServerInfo(chain.committee[1].Address, chain.committee[1].Public)
	if index := IamMember(); index != 1 {
		t.Fatalf("same-height second validator membership = %d, want 1", index)
	}
}
