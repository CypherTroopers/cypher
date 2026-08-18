package reconfig

import (
	"context"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rpc"
)

type PublicReconfigAPI struct {
	reconfig *ReconfigBackend
}

type PublicFHSStatus struct {
	Enabled             bool          `json:"enabled"`
	Role                string        `json:"role"`
	LocalCommitteeIndex int           `json:"localCommitteeIndex"`
	CurrentView         uint64        `json:"currentView"`
	ProposalView        uint64        `json:"proposalView"`
	TxNumber            uint64        `json:"txNumber"`
	KeyNumber           uint64        `json:"keyNumber"`
	KeyHash             common.Hash   `json:"keyHash"`
	CommitteeHash       common.Hash   `json:"committeeHash"`
	LeaderIndex         uint          `json:"leaderIndex"`
	LeaderID            string        `json:"leaderId"`
	Leader              *common.Cnode `json:"leader"`
	Error               string        `json:"error,omitempty"`
}

func NewPublicReconfigAPI(reconfig *ReconfigBackend) *PublicReconfigAPI {
	return &PublicReconfigAPI{reconfig}
}

func (s *PublicReconfigAPI) Role() string {
	i := bftview.IamMember()
	if i < 0 {
		return "I'm common node."
	}
	_, leaderIndex, ok := s.currentLeader()
	if ok && uint(i) == leaderIndex {
		return "I'm leader."
	}
	return "I'm committee member."
}

func (s *PublicReconfigAPI) Leader() *common.Cnode {
	leader, _, ok := s.currentLeader()
	if !ok || leader == nil {
		return nil
	}
	copy := *leader
	return &copy
}

func (s *PublicReconfigAPI) currentLeader() (*common.Cnode, uint, bool) {
	if s == nil || s.reconfig == nil || s.reconfig.service == nil {
		return nil, 0, false
	}
	if s.reconfig.service.fairHotstuffEnabled() {
		route, err := s.reconfig.CurrentFHSRoute()
		if err != nil || route == nil || route.Leader == nil {
			return nil, 0, false
		}
		return route.Leader, route.LeaderIndex, true
	}
	view := s.reconfig.service.GetCurrentView()
	mb := bftview.GetCurrentMember()
	if view == nil || mb == nil || view.LeaderIndex >= uint(len(mb.List)) || mb.List[view.LeaderIndex] == nil {
		return nil, 0, false
	}
	return mb.List[view.LeaderIndex], view.LeaderIndex, true
}

// FhsStatus exposes the exact dynamic route used by Fair HotStuff. The RPC
// method name is reconfig_fhsStatus.
func (s *PublicReconfigAPI) FhsStatus() *PublicFHSStatus {
	status := &PublicFHSStatus{LocalCommitteeIndex: bftview.IamMember()}
	if s == nil || s.reconfig == nil || s.reconfig.service == nil || !s.reconfig.service.fairHotstuffEnabled() {
		return status
	}
	status.Enabled = true
	route, err := s.reconfig.CurrentFHSRoute()
	if err != nil {
		status.Error = err.Error()
		return status
	}
	status.CurrentView = route.CurrentView
	status.ProposalView = route.ProposalView
	status.TxNumber = route.TxNumber
	status.KeyNumber = route.KeyNumber
	status.KeyHash = route.KeyHash
	status.CommitteeHash = route.CommitteeHash
	status.LeaderIndex = route.LeaderIndex
	status.LeaderID = route.LeaderID
	status.Leader = route.Leader
	switch {
	case status.LocalCommitteeIndex < 0:
		status.Role = "common"
	case uint(status.LocalCommitteeIndex) == route.LeaderIndex:
		status.Role = "leader"
	default:
		status.Role = "committee"
	}
	return status
}
func (s *PublicReconfigAPI) RoleList() []*common.Cnode {
	mb := bftview.GetCurrentMember()
	if mb != nil {
		return mb.List
	}
	return nil
}

func (s *PublicReconfigAPI) Id(enodeId string) string {
	coinbase := bftview.GetServerCoinBase()
	return bftview.GetServerInfo(bftview.PublicKey) + "\n" + coinbase.String()
}

func (s *PublicReconfigAPI) Members(ctx context.Context, blockNr rpc.BlockNumber) ([]*common.Cnode, error) {
	if blockNr == rpc.LatestBlockNumber {
		return s.reconfig.KeyBlockChain().CurrentCommittee(), nil
	}
	return s.reconfig.KeyBlockChain().GetCommitteeByNumber(uint64(blockNr)), nil
}

func (s *PublicReconfigAPI) Exceptions(ctx context.Context, blockNr rpc.BlockNumber) []string {
	return s.reconfig.Exceptions(int64(blockNr))
}

func (s *PublicReconfigAPI) takePartInBlocks(ctx context.Context, addr common.Address, blockNr rpc.BlockNumber) []string {
	return s.reconfig.service.TakePartInBlocks(addr, int64(blockNr))
}
