package reconfig

import (
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

func TestCommonApprovalRewardsUseKeyBlockActiveCommittee(t *testing.T) {
	bootstrap := common.Cnode{
		Address:  "bootstrap-address",
		CoinBase: "0x0000000000000000000000000000000000000001",
		Public:   "bootstrap-public",
	}
	dynamic := common.Cnode{
		Address:  "dynamic-address",
		CoinBase: "0x0000000000000000000000000000000000000002",
		Public:   "dynamic-public",
	}
	config := &params.ChainConfig{
		CommonApprovalEnabled: true,
		CommonCommittee: params.GenesisCommittee{
			core.CommonApprovalBootstrapIndex: bootstrap,
		},
	}
	keyblock := types.NewKeyBlock(&types.KeyBlockHeader{
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(1),
	})
	keyblock.SetActiveCommonCommittee([]types.CommonApprovalCommitteeMember{
		{Address: bootstrap.Address, CoinBase: bootstrap.CoinBase, Public: bootstrap.Public},
		{Address: dynamic.Address, CoinBase: dynamic.CoinBase, Public: dynamic.Public},
	})
	activeNodes := core.OrderedCommonCommitteeForKeyBlock(config, keyblock)
	activeHash := core.CommonApprovalCommitteeHashFromNodes(activeNodes)
	if activeHash == core.CommonApprovalCommitteeHash(config) {
		t.Fatal("test requires the active committee hash to differ from the config fallback")
	}

	block := types.NewBlockWithHeader(&types.Header{
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(1),
		BlockType:  types.FastTx_Block,
		KeyHash:    keyblock.Hash(),
		SignInfo: types.SignInfo{
			CommonApprovalSignature:     []byte{1},
			CommonApprovalExceptions:    []byte{0x03},
			CommonApprovalCommitteeHash: activeHash,
		},
	})

	got := commonApprovalRewardsForBlock(config, block, keyblock)
	want := []types.CommonApprovalReward{
		{CoinBase: common.HexToAddress(bootstrap.CoinBase).Hex(), SignedTxBlocks: 1},
		{CoinBase: common.HexToAddress(dynamic.CoinBase).Hex(), SignedTxBlocks: 1},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected rewards: have=%v want=%v", got, want)
	}
}

func TestCommonApprovalRewardsHonorActiveCommitteeSignerMask(t *testing.T) {
	bootstrap := common.Cnode{
		Address:  "bootstrap-address",
		CoinBase: "0x0000000000000000000000000000000000000011",
		Public:   "bootstrap-public",
	}
	dynamic := common.Cnode{
		Address:  "dynamic-address",
		CoinBase: "0x0000000000000000000000000000000000000012",
		Public:   "dynamic-public",
	}
	config := &params.ChainConfig{
		CommonApprovalEnabled: true,
		CommonCommittee: params.GenesisCommittee{
			core.CommonApprovalBootstrapIndex: bootstrap,
		},
	}
	keyblock := types.NewKeyBlock(&types.KeyBlockHeader{Difficulty: big.NewInt(1), Number: big.NewInt(1)})
	keyblock.SetActiveCommonCommittee([]types.CommonApprovalCommitteeMember{
		{Address: bootstrap.Address, CoinBase: bootstrap.CoinBase, Public: bootstrap.Public},
		{Address: dynamic.Address, CoinBase: dynamic.CoinBase, Public: dynamic.Public},
	})
	activeHash := core.CommonApprovalCommitteeHashForKeyBlock(config, keyblock)
	block := types.NewBlockWithHeader(&types.Header{
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(1),
		BlockType:  types.FastTx_Block,
		SignInfo: types.SignInfo{
			CommonApprovalSignature:     []byte{1},
			CommonApprovalExceptions:    []byte{0x02},
			CommonApprovalCommitteeHash: activeHash,
		},
	})

	got := commonApprovalRewardsForBlock(config, block, keyblock)
	want := []types.CommonApprovalReward{{CoinBase: common.HexToAddress(dynamic.CoinBase).Hex(), SignedTxBlocks: 1}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected rewards: have=%v want=%v", got, want)
	}
}

func TestCommonApprovalRewardsSupportMaximumCommitteeSize(t *testing.T) {
	const signerMask = byte(0x7f) // indexes 0 through 6: one leader and six committee members

	committee := make([]types.CommonApprovalCommitteeMember, 0, core.CommonApprovalMaxCommitteeSize)
	configCommittee := make(params.GenesisCommittee)
	want := make([]types.CommonApprovalReward, 0, core.CommonApprovalMaxCommitteeSize)
	for i := 0; i < core.CommonApprovalMaxCommitteeSize; i++ {
		node := common.Cnode{
			Address:  fmt.Sprintf("common-address-%d", i),
			CoinBase: fmt.Sprintf("0x%040x", i+1),
			Public:   fmt.Sprintf("common-public-%d", i),
		}
		if i == core.CommonApprovalBootstrapIndex {
			configCommittee[i] = node
		}
		committee = append(committee, types.CommonApprovalCommitteeMember{
			Address:  node.Address,
			CoinBase: node.CoinBase,
			Public:   node.Public,
		})
		want = append(want, types.CommonApprovalReward{
			CoinBase:       common.HexToAddress(node.CoinBase).Hex(),
			SignedTxBlocks: 1,
		})
	}
	config := &params.ChainConfig{
		CommonApprovalEnabled: true,
		CommonCommittee:       configCommittee,
	}
	keyblock := types.NewKeyBlock(&types.KeyBlockHeader{Difficulty: big.NewInt(1), Number: big.NewInt(1)})
	keyblock.SetActiveCommonCommittee(committee)
	activeHash := core.CommonApprovalCommitteeHashForKeyBlock(config, keyblock)
	if activeHash == core.CommonApprovalCommitteeHash(config) {
		t.Fatal("test requires six dynamic members outside the config fallback")
	}
	block := types.NewBlockWithHeader(&types.Header{
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(1),
		BlockType:  types.FastTx_Block,
		KeyHash:    keyblock.Hash(),
		SignInfo: types.SignInfo{
			CommonApprovalSignature:     []byte{1},
			CommonApprovalExceptions:    []byte{signerMask},
			CommonApprovalCommitteeHash: activeHash,
		},
	})

	got := commonApprovalRewardsForBlock(config, block, keyblock)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected maximum-committee rewards: have=%v want=%v", got, want)
	}
}
