package core

import (
	"fmt"
	"sort"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

// OrderedCommonCommittee returns the common approval committee in deterministic
// genesis-index order. It is deliberately separate from GenCommittee: the fixed
// validator committee remains the finality layer, while CommonCommittee is the
// tx-block approval layer.
func OrderedCommonCommittee(config *params.ChainConfig) []*common.Cnode {
	if config == nil || len(config.CommonCommittee) == 0 {
		return nil
	}
	keys := make([]int, 0, len(config.CommonCommittee))
	for k := range config.CommonCommittee {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	nodes := make([]*common.Cnode, 0, len(keys))
	for _, k := range keys {
		node := config.CommonCommittee[k]
		nodes = append(nodes, &node)
	}
	return nodes
}

func CommonApprovalCommitteeHash(config *params.ChainConfig) common.Hash {
	return (&bftview.Committee{List: OrderedCommonCommittee(config)}).RlpHash()
}

func CommonApprovalRequired(config *params.ChainConfig, block *types.Block) bool {
	if config == nil || block == nil || !config.CommonApprovalEnabled {
		return false
	}
	// Key blocks are still governed by the fixed validator committee. Common
	// approval is only required for transaction blocks.
	return block.BlockType() != types.Key_Block
}

func CommonApprovalThreshold(config *params.ChainConfig, committeeSize int) int {
	if committeeSize <= 0 {
		return 0
	}
	threshold := hotstuff.CalcThreshold(committeeSize)
	if config != nil && config.CommonApprovalThreshold > 0 {
		threshold = int(config.CommonApprovalThreshold)
	}
	if threshold < 1 {
		threshold = 1
	}
	if threshold > committeeSize {
		threshold = committeeSize
	}
	return threshold
}

func CommonApprovalPublicKeys(nodes []*common.Cnode) ([]*bls.PublicKey, error) {
	pubs := make([]*bls.PublicKey, 0, len(nodes))
	for i, node := range nodes {
		if node == nil || node.Public == "" {
			return nil, fmt.Errorf("common approval committee member %d has empty public key", i)
		}
		pub := bftview.StrToBlsPubKey(node.Public)
		if pub == nil {
			return nil, fmt.Errorf("common approval committee member %d has invalid BLS public key", i)
		}
		pubs = append(pubs, pub)
	}
	return pubs, nil
}

func VerifyCommonApproval(config *params.ChainConfig, block *types.Block) error {
	if !CommonApprovalRequired(config, block) {
		return nil
	}
	nodes := OrderedCommonCommittee(config)
	if len(nodes) == 0 {
		return fmt.Errorf("common approval enabled but commonCommittee is empty")
	}
	pubs, err := CommonApprovalPublicKeys(nodes)
	if err != nil {
		return err
	}

	si := block.SignInfo()
	if si == nil || len(si.CommonApprovalSignature) == 0 || len(si.CommonApprovalExceptions) == 0 {
		return fmt.Errorf("common approval signature is empty")
	}
	if si.CommonApprovalViewID == (common.Hash{}) || si.CommonApprovalLeaderID == "" {
		return fmt.Errorf("common approval context is empty")
	}
	committeeHash := CommonApprovalCommitteeHash(config)
	if si.CommonApprovalCommitteeHash != committeeHash {
		return fmt.Errorf("common approval committee hash mismatch: have %s want %s", si.CommonApprovalCommitteeHash.Hex(), committeeHash.Hex())
	}

	payload := block.CopyNoSignInfo().EncodeToBytes()
	if payload == nil {
		return types.ErrEncodeRLP
	}
	threshold := CommonApprovalThreshold(config, len(pubs))
	chainID := uint64(0)
	if config.ChainID != nil {
		chainID = config.ChainID.Uint64()
	}
	if !hotstuff.VerifySignatureWithContext(si.CommonApprovalSignature, si.CommonApprovalExceptions, payload, pubs, threshold, chainID, hotstuff.MsgVotePrepare, si.CommonApprovalViewID, si.CommonApprovalLeaderID) {
		return fmt.Errorf("invalid common approval signature")
	}
	return nil
}
