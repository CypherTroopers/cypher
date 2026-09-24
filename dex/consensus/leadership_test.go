package consensus

import (
	"errors"
	"testing"
)

func TestLeadershipUsesRecoveredAuthenticatedFHSView(t *testing.T) {
	n := newNetwork(t, 3)
	if _, err := n.nodes[0].Leadership(); err == nil {
		t.Fatal("unstarted consensus advertised active leadership")
	}
	n.start(t)
	for i, a := range n.nodes {
		state, err := a.Leadership()
		if err != nil || state.View != 4 || state.LeaderIndex != 3 || state.SelfIndex != uint8(i) || state.Active != (i == 3) || state.LeaderID != n.nodes[3].Self() {
			t.Fatalf("node %d leadership %+v: %v", i, state, err)
		}
	}
	a := n.nodes[3]
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Leadership(); err == nil {
		t.Fatal("closed actor advertised leadership")
	}
	restored, err := Open(n.configs[3])
	if err != nil {
		t.Fatal(err)
	}
	n.nodes[3] = restored
	restored.SetTransport(n.send)
	if _, err := restored.Leadership(); err == nil {
		t.Fatal("recovered but unstarted actor advertised leadership")
	}
	if err = restored.Start(); err != nil {
		t.Fatal(err)
	}
	state, err := restored.Leadership()
	if err != nil || state.View != 4 || !state.Active {
		t.Fatalf("cold recovery lost authenticated leadership: %+v %v", state, err)
	}
	restored.fatal = errors.New("injected storage failure")
	if _, err := restored.Leadership(); err == nil {
		t.Fatal("failed actor advertised submission eligibility")
	}
}
