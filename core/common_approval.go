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

const (
	// CommonApprovalBootstrapIndex is the genesis commonCommittee member that must
	// always stay active as the network's last-resort tx-block approver. Even when
	// dynamic common committee selection is added later, this member is preserved.
	CommonApprovalBootstrapIndex = 0

	// CommonApprovalMinCommitteeSize allows the network to start with a single
	// common miner right after launch. When more common miners are selected, the
	// threshold automatically follows HotStuff's 2f+1 style calculation.
	CommonApprovalMinCommitteeSize = 1

	// CommonApprovalMaxCommitteeSize keeps the active common approval HotStuff set
	// small enough for low-latency tx-block approval. The wider common-miner pool
	// can be larger, but only up to seven nodes should be active approvers at once.
	CommonApprovalMaxCommitteeSize = 7
)

// BootstrapCommonApprover returns genesistest.json commonCommittee[0]. This node
// is the permanent safety approver: it must stay in the active common committee
// and remains the fallback when no dynamic common miners are eligible.
func BootstrapCommonApprover(config *params.ChainConfig) (*common.Cnode, bool) {
	if config == nil || len(config.CommonCommittee) == 0 {
		return nil, false
	}
	node, ok := config.CommonCommittee[CommonApprovalBootstrapIndex]
	if !ok {
		return nil, false
	}
	return &node, true
}

// OrderedCommonCommittee returns the active common approval committee in
// deterministic genesis-index order. It is deliberately separate from
// GenCommittee: the fixed validator committee remains the finality layer, while
// CommonCommittee is the tx-block approval layer.
//
// Safety rule: commonCommittee[0] from genesistest.json is always included first.
// If dynamic committee selection is added later and produces no eligible common
// miners, this bootstrap node alone remains the active committee/leader.
func OrderedCommonCommittee(config *params.ChainConfig) []*common.Cnode {
	if config == nil || len(config.CommonCommittee) == 0 {
		return nil
	}

	nodes := make([]*common.Cnode, 0, len(config.CommonCommittee))
	included := make(map[int]struct{})

	if bootstrap, ok := BootstrapCommonApprover(config); ok && bootstrap != nil {
		nodes = append(nodes, bootstrap)
		included[CommonApprovalBootstrapIndex] = struct{}{}
	}

	keys := make([]int, 0, len(config.CommonCommittee))
	for k := range config.CommonCommittee {
		if _, ok := included[k]; ok {
			continue
		}
		keys = append(keys, k)
	}
	sort.Ints(keys)

	for _, k := range keys {
		if len(nodes) >= CommonApprovalMaxCommitteeSize {
			break
		}
		node := config.CommonCommittee[k]
		nodes = append(nodes, &node)
	}
	return nodes
}

func ValidateCommonApprovalCommittee(config *params.ChainConfig) error {
	if config == nil || !config.CommonApprovalEnabled {
		return nil
	}
	if _, ok := BootstrapCommonApprover(config); !ok {
		return fmt.Errorf("common approval enabled but bootstrap commonCommittee[%d] is missing", CommonApprovalBootstrapIndex)
	}
	size := len(OrderedCommonCommittee(config))
	if size < CommonApprovalMinCommitteeSize {
		return fmt.Errorf("common approval enabled but commonCommittee has %d active member(s), minimum is %d", size, CommonApprovalMinCommitteeSize)
	}
	if size > CommonApprovalMaxCommitteeSize {
		return fmt.Errorf("common approval commonCommittee has %d active member(s), maximum active size is %d", size, CommonApprovalMaxCommitteeSize)
	}
	return nil
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
	if committeeSize > CommonApprovalMaxCommitteeSize {
		committeeSize = CommonApprovalMaxCommitteeSize
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

// CommonApprovalBootstrapSigned checks whether the permanent bootstrap approver
// signed the CommonApprovalQC. Since OrderedCommonCommittee always places
// genesis commonCommittee[0] at active index 0, mask bit 0 is the bootstrap
// safety approver.
func CommonApprovalBootstrapSigned(mask []byte) bool {
	return len(mask) > 0 && (mask[0]&0x01) != 0
}

// CommonApprovalEffectiveThreshold returns the normal committee threshold unless
// the permanent bootstrap approver signed. In that emergency/safety path, the
// bootstrap signature alone is enough to make a tx block progress on testnet.
func CommonApprovalEffectiveThreshold(config *params.ChainConfig, committeeSize int, mask []byte) int {
	if CommonApprovalBootstrapSigned(mask) {
		return 1
	}
	return CommonApprovalThreshold(config, committeeSize)
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
	if err := ValidateCommonApprovalCommittee(config); err != nil {
		return err
	}
	nodes := OrderedCommonCommittee(config)
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
	threshold := CommonApprovalEffectiveThreshold(config, len(pubs), si.CommonApprovalExceptions)
	chainID := uint64(0)
	if config.ChainID != nil {
		chainID = config.ChainID.Uint64()
	}
	if !hotstuff.VerifySignatureWithContext(si.CommonApprovalSignature, si.CommonApprovalExceptions, payload, pubs, threshold, chainID, hotstuff.MsgVotePrepare, si.CommonApprovalViewID, si.CommonApprovalLeaderID) {
		return fmt.Errorf("invalid common approval signature")
	}
	return nil
}
