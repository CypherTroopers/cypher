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

func normalizeCommonApprovalNode(node *common.Cnode) *common.Cnode {
	if node == nil {
		return nil
	}
	return &common.Cnode{
		Address:  node.Address,
		CoinBase: common.HexToAddress(node.CoinBase).Hex(),
		Public:   node.Public,
	}
}

func normalizeCommonApprovalNodes(nodes []*common.Cnode) []*common.Cnode {
	normalized := make([]*common.Cnode, 0, len(nodes))
	for _, node := range nodes {
		normalized = append(normalized, normalizeCommonApprovalNode(node))
	}
	return normalized
}

func commonApprovalCommitteeHashFromNodes(nodes []*common.Cnode) common.Hash {
	return (&bftview.Committee{List: normalizeCommonApprovalNodes(nodes)}).RlpHash()
}

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
	return normalizeCommonApprovalNode(&node), true
}

// OrderedCommonCommittee returns the genesis/config fallback common approval
// committee in deterministic genesis-index order. The production active committee
// path is OrderedCommonCommitteeForKeyBlock: it reads the KeyBlock-recorded
// ActiveCommonCommittee so all nodes use chain data instead of local observation.
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
		nodes = append(nodes, normalizeCommonApprovalNode(&node))
	}
	return nodes
}

func commonApprovalNodesFromKeyBlock(config *params.ChainConfig, keyblock *types.KeyBlock) ([]*common.Cnode, bool) {
	if keyblock == nil {
		return nil, false
	}
	members := keyblock.ActiveCommonCommittee()
	if len(members) == 0 {
		return nil, false
	}
	nodes := make([]*common.Cnode, 0, len(members))
	for _, member := range members {
		if member.Address == "" || member.CoinBase == "" || member.Public == "" {
			return nil, false
		}
		node := normalizeCommonApprovalNode(&common.Cnode{
			Address:  member.Address,
			CoinBase: member.CoinBase,
			Public:   member.Public,
		})
		nodes = append(nodes, node)
	}
	if err := ValidateCommonApprovalNodes(config, nodes); err != nil {
		return nil, false
	}
	return nodes, true
}

// OrderedCommonCommitteeForKeyBlock returns the committee that must be used for
// tx-block CommonApproval under keyblock.Hash(). If the KeyBlock does not contain
// ActiveCommonCommittee (for genesis or pre-upgrade data), it falls back to the
// genesis/config commonCommittee. New production KeyBlocks should always carry
// ActiveCommonCommittee.
func OrderedCommonCommitteeForKeyBlock(config *params.ChainConfig, keyblock *types.KeyBlock) []*common.Cnode {
	if nodes, ok := commonApprovalNodesFromKeyBlock(config, keyblock); ok {
		return nodes
	}
	return OrderedCommonCommittee(config)
}

func ValidateCommonApprovalNodes(config *params.ChainConfig, nodes []*common.Cnode) error {
	if config == nil || !config.CommonApprovalEnabled {
		return nil
	}
	nodes = normalizeCommonApprovalNodes(nodes)
	if len(nodes) < CommonApprovalMinCommitteeSize {
		return fmt.Errorf("common approval enabled but active committee has %d member(s), minimum is %d", len(nodes), CommonApprovalMinCommitteeSize)
	}
	if len(nodes) > CommonApprovalMaxCommitteeSize {
		return fmt.Errorf("common approval active committee has %d member(s), maximum active size is %d", len(nodes), CommonApprovalMaxCommitteeSize)
	}
	bootstrap, ok := BootstrapCommonApprover(config)
	if !ok || bootstrap == nil {
		return fmt.Errorf("common approval enabled but bootstrap commonCommittee[%d] is missing", CommonApprovalBootstrapIndex)
	}
	if nodes[0] == nil || nodes[0].Address != bootstrap.Address || common.HexToAddress(nodes[0].CoinBase) != common.HexToAddress(bootstrap.CoinBase) || nodes[0].Public != bootstrap.Public {
		return fmt.Errorf("common approval bootstrap member mismatch")
	}
	seenPublic := make(map[string]struct{})
	seenCoinbase := make(map[common.Address]struct{})
	for i, node := range nodes {
		if node == nil || node.Address == "" || node.CoinBase == "" || node.Public == "" {
			return fmt.Errorf("common approval committee member %d is invalid", i)
		}
		if _, ok := seenPublic[node.Public]; ok {
			return fmt.Errorf("common approval committee member %d duplicate public key", i)
		}
		coinbase := common.HexToAddress(node.CoinBase)
		if _, ok := seenCoinbase[coinbase]; ok {
			return fmt.Errorf("common approval committee member %d duplicate coinbase", i)
		}
		seenPublic[node.Public] = struct{}{}
		seenCoinbase[coinbase] = struct{}{}
	}
	return nil
}

func ValidateCommonApprovalCommittee(config *params.ChainConfig) error {
	return ValidateCommonApprovalNodes(config, OrderedCommonCommittee(config))
}

func ValidateCommonApprovalCommitteeForKeyBlock(config *params.ChainConfig, keyblock *types.KeyBlock) error {
	return ValidateCommonApprovalNodes(config, OrderedCommonCommitteeForKeyBlock(config, keyblock))
}

func CommonApprovalCommitteeHash(config *params.ChainConfig) common.Hash {
	return commonApprovalCommitteeHashFromNodes(OrderedCommonCommittee(config))
}

func CommonApprovalCommitteeHashForKeyBlock(config *params.ChainConfig, keyblock *types.KeyBlock) common.Hash {
	return commonApprovalCommitteeHashFromNodes(OrderedCommonCommitteeForKeyBlock(config, keyblock))
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
// signed the CommonApprovalQC. Since active common committees always place
// genesis commonCommittee[0] at index 0, mask bit 0 is the bootstrap safety
// approver.
func CommonApprovalBootstrapSigned(mask []byte) bool {
	return len(mask) > 0 && (mask[0]&0x01) != 0
}

// CommonApprovalEffectiveThreshold returns the normal committee threshold unless
// the permanent bootstrap approver signed. In that emergency/safety path, the
// bootstrap signature alone is enough to make a tx block progress.
func CommonApprovalEffectiveThreshold(config *params.ChainConfig, committeeSize int, mask []byte) int {
	if CommonApprovalBootstrapSigned(mask) {
		return 1
	}
	return CommonApprovalThreshold(config, committeeSize)
}

func CommonApprovalPublicKeys(nodes []*common.Cnode) ([]*bls.PublicKey, error) {
	nodes = normalizeCommonApprovalNodes(nodes)
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
	return VerifyCommonApprovalForKeyBlock(config, block, nil)
}

func VerifyCommonApprovalForKeyBlock(config *params.ChainConfig, block *types.Block, keyblock *types.KeyBlock) error {
	if !CommonApprovalRequired(config, block) {
		return nil
	}
	nodes := OrderedCommonCommitteeForKeyBlock(config, keyblock)
	if err := ValidateCommonApprovalNodes(config, nodes); err != nil {
		return err
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
	committeeHash := commonApprovalCommitteeHashFromNodes(nodes)
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
