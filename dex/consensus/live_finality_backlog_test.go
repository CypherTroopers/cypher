package consensus

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

// This is a reproducer for a known LIVE liveness failure, not a test claiming
// that prolonged view gaps recover. Real managers form seven-member QCs and
// timeout certificates. No QC, timeout watermark, or finalized state is forged.
// The workload ceiling models a producer with no next action before timeout.
func TestLiveFinalityBacklogBeyondProofBoundFailsClosed(t *testing.T) {
	n := newNetwork(t, 2)
	for _, a := range n.nodes {
		a.config.MaxHeight = 1
	}
	n.start(t)
	for height := uint64(2); height <= checkpoint.MaxDescendants+1; height++ {
		// Let the empty next view really time out before admitting more work.
		for _, a := range n.nodes[:5] {
			if err := a.Timeout(); !benign(err) {
				t.Fatal(err)
			}
		}
		pumpFinalityBacklog(t, n, false)
		for i, a := range n.nodes {
			a.config.MaxHeight = height
			n.configs[i].MaxHeight = height
			if err := a.NotifyIngress(); !benign(err) {
				t.Fatal(err)
			}
		}
		pumpFinalityBacklog(t, n, false)
		for i, a := range n.nodes {
			if a.CertifiedHeight() != height || a.FinalizedHeight() != 0 || a.HighestCertified().Number != 2*height-1 {
				t.Fatalf("node%d height%d: certified%d finalized%d view%d", i, height, a.CertifiedHeight(), a.FinalizedHeight(), a.HighestCertified().Number)
			}
		}
	}

	// Admit a child immediately in the ready next view. The genuine final
	// edge is consecutive, but its oldest ancestor now needs nine descendants.
	for i, a := range n.nodes {
		a.config.MaxHeight = checkpoint.MaxDescendants + 2
		n.configs[i].MaxHeight = a.config.MaxHeight
		if err := a.NotifyIngress(); !benign(err) {
			t.Fatal(err)
		}
	}
	proofErrors := pumpFinalityBacklog(t, n, true)
	if proofErrors == 0 {
		t.Fatal("expected known finality proof-cap liveness failure")
	}
	for i, a := range n.nodes {
		if a.CertifiedHeight() != checkpoint.MaxDescendants+1 || a.FinalizedHeight() != 0 {
			t.Fatalf("node%d published partial finality after rejected proof", i)
		}
		if _, _, err := a.FinalizedCheckpoint(1); err == nil {
			t.Fatal("unfinalized oldest checkpoint was exposed as finalized")
		}
		safety := hotstuff.CloneFHSSafetyState(a.disk.Safety)
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
		restarted, err := Open(n.configs[i])
		if err != nil {
			t.Fatal(err)
		}
		n.nodes[i] = restarted
		if restarted.FinalizedHeight() != 0 || restarted.CertifiedHeight() != checkpoint.MaxDescendants+1 || !reflect.DeepEqual(safety, restarted.disk.Safety) {
			t.Fatal("same-WAL restart changed finality, highest QC, vote, lock or timeout safety")
		}
	}
	t.Logf("KNOWN LIVE LIVENESS FAILURE reproduced: 9 certified gapped heights; genuine height10/view18 child rejected by unchanged %d-descendant cap; finality stays0; safety survives same-WAL restart; this test PASS is fail-closed coverage, not LIVE recovery PASS", checkpoint.MaxDescendants)
}

func pumpFinalityBacklog(t *testing.T, n *network, allowProofFailure bool) int {
	t.Helper()
	proofErrors := 0
	check := func(err error) {
		t.Helper()
		if benign(err) {
			return
		}
		if allowProofFailure && strings.Contains(err.Error(), "finality requires target and bounded descendants") {
			proofErrors++
			return
		}
		t.Fatal(err)
	}
	for step := 0; step < 20000; step++ {
		progress := false
		for _, a := range n.nodes {
			did, err := a.Advance()
			check(err)
			progress = progress || did
		}
		if len(n.queue) > 0 {
			d := n.queue[0]
			n.queue = n.queue[1:]
			progress = true
			for _, a := range n.nodes {
				if a.Self() == d.to {
					err := a.Handle(d.message)
					// Old timeout votes can remain in transport after a real TC
					// advanced this recipient. The existing protocol rejects them.
					// Do not reinterpret a future/current timeout or proposal error.
					if !(d.message.Code == hotstuff.MsgTimeout && d.message.Number < a.CurrentN() && errors.Is(err, hotstuff.ErrViewIdNotMatch)) {
						check(err)
					}
					break
				}
			}
		}
		if !progress {
			return proofErrors
		}
	}
	t.Fatal("reproducer did not quiesce within bounded work")
	return 0
}
