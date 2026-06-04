package reconfig

import (
	"fmt"
	"net"
	"sort"
	"strconv"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
)

const commonApprovalCandidateLookbackKeyBlocks uint64 = 3

func commonNodeToApprovalMember(node *common.Cnode) types.CommonApprovalCommitteeMember {
	if node == nil {
		return types.CommonApprovalCommitteeMember{}
	}
	return types.CommonApprovalCommitteeMember{
		Address:  node.Address,
		CoinBase: common.HexToAddress(node.CoinBase).Hex(),
		Public:   node.Public,
	}
}

func commonMinerRecordToApprovalMember(rec core.CommonMinerRecord) types.CommonApprovalCommitteeMember {
	return types.CommonApprovalCommitteeMember{
		Address:  rec.Address,
		CoinBase: common.HexToAddress(rec.CoinBase).Hex(),
		Public:   rec.Public,
	}
}

func commonMinerCandidateToApprovalMember(candidate *types.Candidate) types.CommonApprovalCommitteeMember {
	if candidate == nil || candidate.PubKey == "" || candidate.Coinbase == "" || candidate.Port <= 0 {
		return types.CommonApprovalCommitteeMember{}
	}
	ip := net.IP(candidate.IP).String()
	if ip == "" || ip == "<nil>" {
		return types.CommonApprovalCommitteeMember{}
	}
	return types.CommonApprovalCommitteeMember{
		Address:  ip + ":" + strconv.Itoa(candidate.Port),
		CoinBase: common.HexToAddress(candidate.Coinbase).Hex(),
		Public:   candidate.PubKey,
	}
}

func validApprovalMember(m types.CommonApprovalCommitteeMember) bool {
	return m.Address != "" && m.CoinBase != "" && m.Public != ""
}

func (keyS *keyService) buildActiveCommonCommitteeSummary() ([]types.CommonApprovalCommitteeMember, error) {
	if keyS == nil || keyS.config == nil {
		return nil, fmt.Errorf("active common committee build failed: missing chain config")
	}
	bootstrap, ok := core.BootstrapCommonApprover(keyS.config)
	if !ok || bootstrap == nil {
		return nil, fmt.Errorf("active common committee build failed: missing bootstrap commonCommittee[%d]", core.CommonApprovalBootstrapIndex)
	}

	committee := make([]types.CommonApprovalCommitteeMember, 0, core.CommonApprovalMaxCommitteeSize)
	seenPublic := make(map[string]struct{})
	seenCoinbase := make(map[string]struct{})

	add := func(member types.CommonApprovalCommitteeMember) {
		if len(committee) >= core.CommonApprovalMaxCommitteeSize || !validApprovalMember(member) {
			return
		}
		member.CoinBase = common.HexToAddress(member.CoinBase).Hex()
		if _, ok := seenPublic[member.Public]; ok {
			return
		}
		if _, ok := seenCoinbase[member.CoinBase]; ok {
			return
		}
		seenPublic[member.Public] = struct{}{}
		seenCoinbase[member.CoinBase] = struct{}{}
		committee = append(committee, member)
	}

	add(commonNodeToApprovalMember(bootstrap))

	if keyS.candidatepool == nil || keyS.kbc == nil {
		return committee, keyS.verifyActiveCommonCommitteeMembers(committee)
	}
	currentKey := keyS.kbc.CurrentBlockN()

	// First source: ACK-backed common miner registry. This is the strongest
	// evidence path because it means the validator received CheckMinerPort ACK
	// for the submitted PoW candidate's rnet address.
	records := keyS.candidatepool.CommonMinerSnapshot()
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].LastSeenKey != records[j].LastSeenKey {
			return records[i].LastSeenKey > records[j].LastSeenKey
		}
		if records[i].PowSubmitCount != records[j].PowSubmitCount {
			return records[i].PowSubmitCount > records[j].PowSubmitCount
		}
		if records[i].ReachableAckCount != records[j].ReachableAckCount {
			return records[i].ReachableAckCount > records[j].ReachableAckCount
		}
		return records[i].Public < records[j].Public
	})
	for _, rec := range records {
		if len(committee) >= core.CommonApprovalMaxCommitteeSize {
			break
		}
		if rec.LastSeenKey+commonApprovalCandidateLookbackKeyBlocks < currentKey {
			continue
		}
		if rec.PowSubmitCount == 0 || rec.ReachableAckCount == 0 {
			continue
		}
		add(commonMinerRecordToApprovalMember(rec))
	}

	// Second source: current candidate pool content. CandidatePool.Content()
	// exposes PoW candidates that passed into the active candidate pool. This
	// covers restart/upgrade cases where the candidate pool already contains a
	// valid external common miner candidate but the in-memory ACK registry was
	// empty when the KeyBlock was generated.
	candidates := keyS.candidatepool.Content()
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i] == nil || candidates[i].KeyCandidate == nil {
			return false
		}
		if candidates[j] == nil || candidates[j].KeyCandidate == nil {
			return true
		}
		if candidates[i].KeyCandidate.Number.Uint64() != candidates[j].KeyCandidate.Number.Uint64() {
			return candidates[i].KeyCandidate.Number.Uint64() > candidates[j].KeyCandidate.Number.Uint64()
		}
		return candidates[i].PubKey < candidates[j].PubKey
	})
	for _, candidate := range candidates {
		if len(committee) >= core.CommonApprovalMaxCommitteeSize {
			break
		}
		if candidate == nil || candidate.KeyCandidate == nil {
			continue
		}
		candidateKey := candidate.KeyCandidate.Number.Uint64()
		if candidateKey+commonApprovalCandidateLookbackKeyBlocks < currentKey {
			continue
		}
		add(commonMinerCandidateToApprovalMember(candidate))
	}

	return committee, keyS.verifyActiveCommonCommitteeMembers(committee)
}

func (keyS *keyService) verifyActiveCommonCommitteeSummary(keyblock *types.KeyBlock) error {
	if keyblock == nil {
		return fmt.Errorf("active common committee verify failed: nil keyblock")
	}
	return keyS.verifyActiveCommonCommitteeMembers(keyblock.ActiveCommonCommittee())
}

func (keyS *keyService) verifyActiveCommonCommitteeMembers(committee []types.CommonApprovalCommitteeMember) error {
	if len(committee) == 0 {
		return fmt.Errorf("active common committee is empty")
	}
	if len(committee) > core.CommonApprovalMaxCommitteeSize {
		return fmt.Errorf("active common committee too large: have %d max %d", len(committee), core.CommonApprovalMaxCommitteeSize)
	}
	bootstrap, ok := core.BootstrapCommonApprover(keyS.config)
	if !ok || bootstrap == nil {
		return fmt.Errorf("active common committee verify failed: missing bootstrap commonCommittee[%d]", core.CommonApprovalBootstrapIndex)
	}
	wantBootstrap := commonNodeToApprovalMember(bootstrap)
	if committee[0].Address != wantBootstrap.Address || common.HexToAddress(committee[0].CoinBase) != common.HexToAddress(wantBootstrap.CoinBase) || committee[0].Public != wantBootstrap.Public {
		return fmt.Errorf("active common committee verify failed: bootstrap member mismatch")
	}
	seenPublic := make(map[string]struct{})
	seenCoinbase := make(map[common.Address]struct{})
	for i, member := range committee {
		if !validApprovalMember(member) {
			return fmt.Errorf("active common committee member %d is invalid", i)
		}
		if _, ok := seenPublic[member.Public]; ok {
			return fmt.Errorf("active common committee member %d duplicate public key", i)
		}
		coinbase := common.HexToAddress(member.CoinBase)
		if _, ok := seenCoinbase[coinbase]; ok {
			return fmt.Errorf("active common committee member %d duplicate coinbase", i)
		}
		seenPublic[member.Public] = struct{}{}
		seenCoinbase[coinbase] = struct{}{}
	}
	return nil
}
