package reconfig

import (
	"strings"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/reconfig/bftview"
)

func TestVerifyKeyBlockLeaderIndexUsesPrepareView(t *testing.T) {
	prepareView := &bftview.View{LeaderIndex: 2}
	if err := verifyKeyBlockLeaderIndex(prepareView, 2); err != nil {
		t.Fatalf("matching authenticated Prepare leader rejected: %v", err)
	}

	err := verifyKeyBlockLeaderIndex(prepareView, 0)
	if err == nil || !strings.Contains(err.Error(), "leaderindex(2)") {
		t.Fatalf("mismatch error = %v, want authenticated Prepare leader index 2", err)
	}
	if err := verifyKeyBlockLeaderIndex(nil, 2); err == nil {
		t.Fatal("nil Prepare view was accepted")
	}
}

func TestVerifyKeyBlockLeaderUsesAuthenticatedViewCommittee(t *testing.T) {
	committee := &bftview.Committee{List: []*common.Cnode{
		{Public: "member-0"},
		{Public: "member-1"},
		{Public: "member-2"},
	}}
	prepareView := &bftview.View{LeaderIndex: 2}

	if err := verifyKeyBlockLeaderForCommittee(prepareView, committee, "member-2"); err != nil {
		t.Fatalf("authenticated Prepare leader rejected: %v", err)
	}
	if err := verifyKeyBlockLeaderForCommittee(prepareView, committee, "member-0"); err == nil {
		t.Fatal("leader from stale local index 0 was accepted")
	}
	if err := verifyKeyBlockLeaderForCommittee(prepareView, committee, "not-a-member"); err == nil {
		t.Fatal("non-member leader was accepted")
	}
}
